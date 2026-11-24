//! The native E01 extraction walk of `rapidtriage/core/e01_native.py` (`_recover_priority_paths`,
//! `_walk_ntfs_dir`, `_sweep_deleted_mft_records`, `_dump_ntfs_record`) over [`crate::ntfs`]:
//! same visiting order, output paths, counters, caps and error accounting.

use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::ntfs::{Media, Ntfs, Record};

const CHUNK: i128 = 8 << 20;
const MAX_DEPTH: u32 = 64;
const MAX_CONSECUTIVE_MISSING: u64 = 100_000;
// `_mft_record_count` asks the boot sector for `clusters_per_file_record`, which dissect's
// BOOT_SECTOR does not have; the AttributeError leaves its divisor at 1024 on every volume.
const RECORD_COUNT_DIVISOR: i128 = 1024;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub files: i128,
    pub bytes: i128,
    pub errors: i128,
    pub depth_skips: i128,
    pub truncated: i128,
    pub deleted_files: i128,
    pub deleted_read_errors: i128,
    pub alias_skips: i128,
    pub file_limit: i128,
}

impl Stats {
    pub fn pairs(&self) -> [(&'static str, i128); 9] {
        [
            ("files", self.files),
            ("bytes", self.bytes),
            ("errors", self.errors),
            ("depth_skips", self.depth_skips),
            ("truncated", self.truncated),
            ("deleted_files", self.deleted_files),
            ("deleted_read_errors", self.deleted_read_errors),
            ("alias_skips", self.alias_skips),
            ("file_limit", self.file_limit),
        ]
    }
}

pub type ProgressFn<'a> = Box<dyn FnMut(&Stats) -> Result<(), String> + 'a>;

pub struct Options<'a> {
    pub extract_dir: PathBuf,
    pub limit: i128,
    pub include_deleted: bool,
    pub priority_paths: Vec<String>,
    /// Called with the running stats every `progress_every` progress points (and never fails
    /// silently: an `Err` aborts the run so the caller can fall back to the Python engine).
    pub progress: ProgressFn<'a>,
    pub progress_every: u64,
}

/// What a Python `try` around the call site would see.
enum Raised {
    /// An exception the surrounding `except Exception` counts (mkdir failure in `_dump_ntfs_record`).
    Counted,
    /// Abort the run (progress callback failure).
    Fatal(String),
}

/// `_safe_component`.
pub fn safe_component(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if "<>:\"/\\|?*".contains(c) || (c as u32) < 0x20 {
                '_'
            } else {
                c
            }
        })
        .collect();
    let trimmed = cleaned.trim_end_matches([' ', '.']);
    let chosen = if trimmed.is_empty() { "_" } else { trimmed };
    chosen.chars().take(180).collect()
}

pub struct Walker<'a, M: Media> {
    ntfs: &'a Ntfs<M>,
    pub stats: Stats,
    done: HashSet<u64>,
    progress: ProgressFn<'a>,
    progress_every: u64,
    pending: u64,
}

impl<'a, M: Media> Walker<'a, M> {
    fn on_progress(&mut self) -> Result<(), Raised> {
        self.pending += 1;
        if self.pending >= self.progress_every {
            self.flush_progress()?;
        }
        Ok(())
    }

    fn flush_progress(&mut self) -> Result<(), Raised> {
        self.pending = 0;
        (self.progress)(&self.stats).map_err(Raised::Fatal)
    }

    /// `_dump_ntfs_record`.
    fn dump(&mut self, record: &Record, out_path: &Path) -> Result<(), Raised> {
        let size = match self.ntfs.data_size(record) {
            Ok(size) => size,
            Err(_) => {
                self.stats.errors += 1;
                return Ok(());
            }
        };
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent).map_err(|_| Raised::Counted)?;
        }
        let stream = match self.ntfs.data_stream(record) {
            Ok(stream) => stream,
            Err(_) => {
                self.stats.errors += 1;
                return Ok(());
            }
        };
        let mut remaining = size;
        let copied = (|| -> Result<(), String> {
            let mut file = fs::File::create(out_path).map_err(|e| e.to_string())?;
            let mut pos: i128 = 0;
            while remaining > 0 {
                let want = CHUNK.min(remaining);
                let chunk = stream.read(&mut self.ntfs.vol.borrow_mut(), pos, want)?;
                pos += want.min(stream.size - pos).max(0);
                if chunk.is_empty() {
                    break;
                }
                file.write_all(&chunk).map_err(|e| e.to_string())?;
                remaining -= chunk.len() as i128;
            }
            file.flush().map_err(|e| e.to_string())
        })();
        if copied.is_err() {
            self.stats.errors += 1;
            let _ = fs::remove_file(out_path);
            return Ok(());
        }
        self.stats.files += 1;
        self.stats.bytes += size - remaining.max(0);
        Ok(())
    }

    /// `_walk_ntfs_dir`.
    fn walk_dir(&mut self, node: &Record, out_dir: &Path, depth: u32) -> Result<(), String> {
        if depth > MAX_DEPTH {
            self.stats.depth_skips += 1;
            return Ok(());
        }
        let listed = self.ntfs.listdir(node, true).and_then(|preferred| {
            let all = self.ntfs.listdir(node, false)?;
            Ok((preferred, all))
        });
        let (preferred, all) = match listed {
            Ok(names) => names,
            Err(_) => {
                self.stats.errors += 1;
                return Ok(());
            }
        };
        let preferred_set: HashSet<&String> = preferred.iter().collect();
        let dos_only: Vec<String> = all
            .iter()
            .filter(|n| !preferred_set.contains(n))
            .cloned()
            .collect();
        let mut seen_segments: HashSet<u64> = HashSet::new();
        for name in preferred.iter().chain(dos_only.iter()) {
            if name == "." || name == ".." {
                continue;
            }
            let record = match self.ntfs.get_path(node, name) {
                Ok(record) => record,
                Err(_) => {
                    self.stats.errors += 1;
                    continue;
                }
            };
            let segment = record.segment;
            if !seen_segments.insert(segment) {
                self.stats.alias_skips += 1;
                continue;
            }
            let target = out_dir.join(safe_component(name));
            let outcome = (|| -> Result<(), Raised> {
                if record.is_dir() {
                    self.walk_dir(&record, &target, depth + 1)
                        .map_err(Raised::Fatal)?;
                } else {
                    if self.done.contains(&segment) {
                        return Ok(());
                    }
                    if self.stats.files >= self.stats.file_limit {
                        self.stats.truncated += 1;
                        return self.on_progress();
                    }
                    self.dump(&record, &target)?;
                    self.done.insert(segment);
                    self.on_progress()?;
                }
                Ok(())
            })();
            match outcome {
                Ok(()) => {}
                Err(Raised::Counted) => self.stats.errors += 1,
                Err(Raised::Fatal(message)) => return Err(message),
            }
        }
        Ok(())
    }

    /// `_priority_targets`.
    fn priority_targets(&self, root: Record, pattern: &str) -> Vec<(String, Record)> {
        let mut found: Vec<(String, Record)> = vec![(String::new(), root)];
        for part in pattern.split('/') {
            let mut next = Vec::new();
            for (rel, node) in &found {
                let names = if part == "*" {
                    match self.ntfs.listdir(node, true) {
                        Ok(names) => names
                            .into_iter()
                            .filter(|n| n != "." && n != "..")
                            .collect(),
                        Err(_) => continue,
                    }
                } else {
                    vec![part.to_string()]
                };
                for name in names {
                    let Ok(child) = self.ntfs.get_path(node, &name) else {
                        continue;
                    };
                    if part == "*" && !child.is_dir() {
                        continue;
                    }
                    let path = if rel.is_empty() {
                        name
                    } else {
                        format!("{rel}/{name}")
                    };
                    next.push((path, child));
                }
            }
            found = next;
        }
        found
    }

    /// `_recover_priority_paths`.
    fn recover_priority(&mut self, extract_dir: &Path, patterns: &[String]) -> Result<(), String> {
        for pattern in patterns {
            let root = match self.ntfs.mft_record(5) {
                Ok(root) => root,
                Err(message) => return Err(format!("root record unreadable: {message}")),
            };
            for (rel, record) in self.priority_targets(root, pattern) {
                let target = rel.split('/').fold(extract_dir.to_path_buf(), |acc, part| {
                    acc.join(safe_component(part))
                });
                let outcome = (|| -> Result<(), Raised> {
                    if record.is_dir() {
                        self.walk_dir(&record, &target, 0).map_err(Raised::Fatal)?;
                    } else {
                        let segment = record.segment;
                        if self.done.contains(&segment) {
                            return Ok(());
                        }
                        if self.stats.files >= self.stats.file_limit {
                            self.stats.truncated += 1;
                            return Ok(());
                        }
                        self.dump(&record, &target)?;
                        self.done.insert(segment);
                        self.on_progress()?;
                    }
                    Ok(())
                })();
                match outcome {
                    Ok(()) => {}
                    Err(Raised::Counted) => self.stats.errors += 1,
                    Err(Raised::Fatal(message)) => return Err(message),
                }
            }
        }
        Ok(())
    }

    /// `_sweep_deleted_mft_records`.
    fn sweep_deleted(&mut self, extract_dir: &Path) -> Result<(), String> {
        let total = self.ntfs.mft_size().div_euclid(RECORD_COUNT_DIVISOR).max(0) as u64;
        let deleted_dir = extract_dir.join("_deleted_mft");
        let mut consecutive_missing: u64 = 0;
        for index in 0..total {
            let record = match self.ntfs.mft_record(index) {
                Ok(record) => record,
                Err(_) => {
                    consecutive_missing += 1;
                    if consecutive_missing > MAX_CONSECUTIVE_MISSING && index > 16 {
                        break;
                    }
                    continue;
                }
            };
            consecutive_missing = 0;
            if record.is_dir() || record.flags & 0x01 != 0 {
                continue;
            }
            let filename = match self.ntfs.filename(&record) {
                Ok(Some(name)) if !name.is_empty() => name,
                Ok(_) => format!("record-{index}"),
                Err(_) => continue,
            };
            if self.stats.deleted_files + self.stats.deleted_read_errors >= self.stats.file_limit {
                self.stats.truncated += 1;
                self.on_progress().map_err(fatal_message)?;
                continue;
            }
            let target = deleted_dir.join(format!("{index}-{}", safe_component(&filename)));
            let before = self.stats.errors;
            match self.dump(&record, &target) {
                Ok(()) => {}
                Err(Raised::Counted) => {
                    return Err(format!(
                        "cannot create {} for a deleted record",
                        deleted_dir.display()
                    ));
                }
                Err(Raised::Fatal(message)) => return Err(message),
            }
            if self.stats.errors != before {
                self.stats.deleted_read_errors += 1;
            } else {
                self.stats.deleted_files += 1;
            }
            self.on_progress().map_err(fatal_message)?;
        }
        Ok(())
    }
}

fn fatal_message(raised: Raised) -> String {
    match raised {
        Raised::Fatal(message) => message,
        Raised::Counted => "unexpected counted error".into(),
    }
}

/// The body of `extract_e01_native` after `NTFS(reader)`: priority paths, the full tree walk,
/// then (optionally) the deleted-record sweep. `Err` means the run must not be trusted.
pub fn extract<M: Media>(ntfs: &Ntfs<M>, options: Options<'_>) -> Result<Stats, String> {
    let mut walker = Walker {
        ntfs,
        stats: Stats {
            file_limit: options.limit,
            ..Stats::default()
        },
        done: HashSet::new(),
        progress: options.progress,
        progress_every: options.progress_every.max(1),
        pending: 0,
    };
    let root = ntfs
        .mft_record(5)
        .map_err(|m| format!("root record unreadable: {m}"))?;
    walker.recover_priority(&options.extract_dir, &options.priority_paths)?;
    walker.walk_dir(&root, &options.extract_dir, 0)?;
    if options.include_deleted {
        walker.sweep_deleted(&options.extract_dir)?;
    }
    walker.flush_progress().map_err(fatal_message)?;
    Ok(walker.stats)
}

#[cfg(test)]
mod tests {
    use super::safe_component;

    #[test]
    fn safe_component_matches_python() {
        assert_eq!(safe_component("weird:name?.txt"), "weird_name_.txt");
        assert_eq!(safe_component("trailing dot. "), "trailing dot");
        assert_eq!(safe_component(".."), "_");
        assert_eq!(safe_component("a\u{1}b"), "a_b");
        assert_eq!(safe_component(&"가".repeat(200)).chars().count(), 180);
    }
}
