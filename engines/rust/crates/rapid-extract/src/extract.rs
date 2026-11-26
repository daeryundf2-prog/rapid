//! The native E01 extraction walk of `rapidtriage/core/e01_native.py` (`_recover_priority_paths`,
//! `_walk_ntfs_dir`, `_sweep_deleted_mft_records`, `_dump_ntfs_record`) over [`crate::ntfs`]:
//! same visiting order, output paths, counters, caps and error accounting.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::names::{
    opened_id, path_id, target_id, Collision, FileId, OutputNames, DELETED_DIR, ROOT,
};
use crate::ntfs::{DirectReader, Media, Ntfs, Record, RecordTimes, Stream, VolRead};

const CHUNK: i128 = 8 << 20;
const MAX_DEPTH: u32 = 64;
const MAX_CONSECUTIVE_MISSING: u64 = 100_000;
// `_mft_record_count` asks the boot sector for `clusters_per_file_record`, which dissect's
// BOOT_SECTOR does not have; the AttributeError leaves its divisor at 1024 on every volume.
const RECORD_COUNT_DIVISOR: i128 = 1024;
// `ExtractSpaceGuard`: free space is re-read after this many files or bytes.
const SPACE_CHECK_EVERY_FILES: u64 = 256;
const SPACE_CHECK_EVERY_BYTES: i128 = 1 << 30;
// Headroom over the reserve (Python's estimate may lag the drive by up to one re-read interval),
// and the allocation unit each file is rounded up to.
const SPACE_MARGIN: i128 = SPACE_CHECK_EVERY_BYTES;
const SPACE_BLOCK: i128 = 4096;
/// Prefix of the error returned when the output drive nears its free-space reserve.
pub const SPACE_RESERVE_ERROR: &str = "free-space-reserve";

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
    pub name_collision_renames: i128,
    pub name_collisions_unresolved: i128,
    pub time_restore_skips: i128,
    pub file_limit: i128,
}

impl Stats {
    pub fn pairs(&self) -> [(&'static str, i128); 12] {
        [
            ("files", self.files),
            ("bytes", self.bytes),
            ("errors", self.errors),
            ("depth_skips", self.depth_skips),
            ("truncated", self.truncated),
            ("deleted_files", self.deleted_files),
            ("deleted_read_errors", self.deleted_read_errors),
            ("alias_skips", self.alias_skips),
            ("name_collision_renames", self.name_collision_renames),
            (
                "name_collisions_unresolved",
                self.name_collisions_unresolved,
            ),
            ("time_restore_skips", self.time_restore_skips),
            ("file_limit", self.file_limit),
        ]
    }
}

pub type ProgressFn<'a> = Box<dyn FnMut(&Stats) -> Result<(), String> + 'a>;

/// The output drive's free-space reserve (`ExtractSpaceGuard` of `e01_native.py`). The Rust engine
/// never skips files for space: when a file would bring the drive within `min_free` (plus
/// [`SPACE_MARGIN`]), or the drive drops below it while copying, `extract` returns an error starting
/// with [`SPACE_RESERVE_ERROR`] so the caller reruns the image on the Python engine, whose guard
/// decides which files are written.
#[derive(Clone)]
pub struct SpaceReserve {
    /// Free bytes when extraction started; negative = unknown (not guarded, as in Python).
    pub free_at_start: i128,
    pub min_free: i128,
    /// Re-reads the drive's free bytes (negative = unreadable).
    pub probe: Arc<dyn Fn() -> i128 + Send + Sync>,
}

struct SpaceState {
    reserve: SpaceReserve,
    /// Estimated free bytes above `min_free + SPACE_MARGIN`.
    left: i128,
    files: u64,
    bytes: i128,
}

pub struct Options<'a> {
    pub extract_dir: PathBuf,
    pub limit: i128,
    pub include_deleted: bool,
    pub priority_paths: Vec<String>,
    /// Called with the running stats every `progress_every` progress points (and never fails
    /// silently: an `Err` aborts the run so the caller can fall back to the Python engine).
    pub progress: ProgressFn<'a>,
    pub progress_every: u64,
    /// Worker threads for copying file data; 1 copies inline during the walk (no speculation).
    pub threads: usize,
    pub space: Option<SpaceReserve>,
}

/// A deferred file copy of the planning walk (`_dump_ntfs_record` past its checks), keyed by
/// (target, record). The directories it needs are [`OutputNames::dirs`].
struct Job {
    key: JobKey,
    stream: Stream,
    size: i128,
    times: Option<RecordTimes>,
}

type JobKey = (PathBuf, u64);

/// One step of a priority path: (name, MFT segment, sequence).
type Link = (String, u64, u16);

/// How a deferred copy went; a second planning walk replays these in walk order.
#[derive(Clone, Copy)]
enum JobOutcome {
    /// Bytes written, and whether the file got the record's times (`_restore_record_times`).
    Copied(i128, bool),
    ReadFailed,
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
    if cfg!(windows) && is_windows_device_name(chosen) {
        return format!("_{chosen}").chars().take(180).collect();
    }
    chosen.chars().take(180).collect()
}

/// `_is_windows_device_name`: Win32 opens the device, not a file in the output folder, for
/// `CON`, `nul.txt`, `COM1 .log`, ... (the name before the first dot, trailing spaces ignored).
pub fn is_windows_device_name(name: &str) -> bool {
    let stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end_matches(' ')
        .to_uppercase();
    if matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }
    let mut chars = stem.chars();
    let prefix: String = chars.by_ref().take(3).collect();
    let digit = chars.next();
    (prefix == "COM" || prefix == "LPT")
        && digit.is_some_and(|d| "0123456789\u{b9}\u{b2}\u{b3}".contains(d))
        && chars.next().is_none()
}

pub struct Walker<'a, M: Media> {
    ntfs: &'a Ntfs<M>,
    pub stats: Stats,
    done: HashSet<u64>,
    progress: ProgressFn<'a>,
    progress_every: u64,
    pending: u64,
    plan: Option<Vec<Job>>,
    known: HashMap<JobKey, JobOutcome>,
    space: Option<SpaceState>,
    names: OutputNames,
}

impl<'a, M: Media> Walker<'a, M> {
    /// `ExtractSpaceGuard.allows`, except that a file the reserve cannot take aborts the run. A
    /// planning walk writes nothing, so it only counts down the estimate from the start value.
    fn reserve_space(&mut self, size: i128) -> Result<(), String> {
        let planning = self.plan.is_some();
        let Some(space) = self.space.as_mut() else {
            return Ok(());
        };
        let need = (size.max(0) + SPACE_BLOCK - 1) / SPACE_BLOCK * SPACE_BLOCK;
        if !planning
            && (space.files >= SPACE_CHECK_EVERY_FILES
                || space.bytes >= SPACE_CHECK_EVERY_BYTES
                || space.left < need)
        {
            let free = (space.reserve.probe)();
            if free >= 0 {
                space.left = free - space.reserve.min_free - SPACE_MARGIN;
            }
            space.files = 0;
            space.bytes = 0;
        }
        if space.left < need {
            return Err(format!(
                "{SPACE_RESERVE_ERROR}: writing {size} more bytes would bring the output drive within \
                 {} bytes (plus a {SPACE_MARGIN}-byte margin) of its free-space reserve",
                space.reserve.min_free
            ));
        }
        space.files += 1;
        space.bytes += need;
        space.left -= need;
        Ok(())
    }

    fn on_progress(&mut self) -> Result<(), Raised> {
        if self.plan.is_some() {
            return Ok(());
        }
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
    fn dump(&mut self, record: &Record, entry: usize) -> Result<(), Raised> {
        let size = match self.ntfs.data_size(record) {
            Ok(size) => size,
            Err(_) => {
                self.stats.errors += 1;
                return Ok(());
            }
        };
        self.reserve_space(size).map_err(Raised::Fatal)?;
        let parent = self
            .names
            .directory(
                self.names.parent(entry),
                &mut self.stats.name_collision_renames,
            )
            .map_err(|_| Raised::Counted)?;
        let Some(parent) = parent else {
            self.names
                .unresolved(entry, &mut self.stats.name_collisions_unresolved);
            self.stats.errors += 1;
            return Ok(());
        };
        check_output_path(&parent.join(self.names.base(entry))).map_err(Raised::Fatal)?;
        let stream = match self.ntfs.data_stream(record) {
            Ok(stream) => stream,
            Err(_) => {
                self.stats.errors += 1;
                return Ok(());
            }
        };
        let times = self.ntfs.record_times(record);
        if self.plan.is_some() {
            let planned =
                self.names
                    .plan_file(entry, &parent, &mut self.stats.name_collision_renames);
            let Some(path) = planned else {
                self.names
                    .unresolved(entry, &mut self.stats.name_collisions_unresolved);
                self.stats.errors += 1;
                return Ok(());
            };
            let key: JobKey = (path, record.segment);
            // Not run yet: planned as copied, with the times restored when the record has them.
            match self.known.get(&key).copied() {
                None => {
                    self.stats.files += 1;
                    self.stats.time_restore_skips += i128::from(times.is_none());
                }
                Some(JobOutcome::Copied(bytes, restored)) => {
                    self.stats.files += 1;
                    self.stats.bytes += bytes;
                    self.stats.time_restore_skips += i128::from(!restored);
                }
                Some(JobOutcome::ReadFailed) => self.stats.errors += 1,
            }
            if let Some(plan) = self.plan.as_mut() {
                plan.push(Job {
                    key,
                    stream,
                    size,
                    times,
                });
            }
            return Ok(());
        }
        let created =
            self.names
                .create_file(entry, &parent, &mut self.stats.name_collision_renames);
        let copied = match created {
            Ok(Some(mut file)) => {
                copy_into(&stream, size, &mut file, &mut *self.ntfs.vol.borrow_mut())
                    .map(|copied| (copied, restore_times(&file, times)))
            }
            Ok(None) => {
                self.names
                    .unresolved(entry, &mut self.stats.name_collisions_unresolved);
                self.stats.errors += 1;
                return Ok(());
            }
            Err(error) => Err(error.to_string()),
        };
        match copied {
            Ok((copied, restored)) => {
                self.stats.time_restore_skips += i128::from(!restored);
                self.stats.files += 1;
                self.stats.bytes += copied;
            }
            Err(_) => {
                self.stats.errors += 1;
                self.names.discard(entry);
            }
        }
        Ok(())
    }

    /// `_walk_ntfs_dir`. `done` holds the segments the priority pass recovered; only that pass
    /// records into it (`record_done`), so the full walk recovers every path of a hard-linked file.
    fn walk_dir(
        &mut self,
        node: &Record,
        out_dir: usize,
        depth: u32,
        limit: i128,
        record_done: bool,
    ) -> Result<(), String> {
        if depth > MAX_DEPTH {
            self.stats.depth_skips += 1;
            return Ok(());
        }
        // Win32/POSIX entries first, deduplicated on the record segment: each record is extracted
        // once under its long name (a DOS 8.3 alias counted in alias_skips), and records that
        // only have a DOS name are still recovered. Each entry is followed by its own reference.
        let (preferred, dos) = match self.ntfs.directory_entries(node) {
            Ok(entries) => entries,
            Err(_) => {
                self.stats.errors += 1;
                return Ok(());
            }
        };
        let mut seen_segments: HashSet<u64> = HashSet::new();
        for listed in preferred.iter().chain(dos.iter()) {
            self.ntfs.check_refused()?;
            let name = &listed.name;
            if name == "." || name == ".." {
                continue;
            }
            let record = match self.ntfs.mft_record(listed.segment) {
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
            let base = safe_component(name);
            let target = self
                .names
                .child(out_dir, base, record.segment, record.sequence, name);
            let outcome = (|| -> Result<(), Raised> {
                if record.is_dir() {
                    self.walk_dir(&record, target, depth + 1, limit, record_done)
                        .map_err(Raised::Fatal)?;
                } else {
                    if self.done.contains(&segment) {
                        return Ok(());
                    }
                    if self.stats.files >= limit {
                        self.stats.truncated += 1;
                        return self.on_progress();
                    }
                    self.dump(&record, target)?;
                    if record_done {
                        self.done.insert(segment);
                    }
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

    /// `_priority_targets`: below `root`, for one pattern, each target record with the chain of
    /// (name, MFT segment, sequence) that leads to it. A named part is looked up case-insensitively,
    /// as Windows resolves it; `*` follows every Win32/POSIX entry by its MFT reference.
    fn priority_targets(&self, root: Record, pattern: &str) -> Vec<(Vec<Link>, Record)> {
        let mut found: Vec<(Vec<Link>, Record)> = vec![(Vec::new(), root)];
        for part in pattern.split('/') {
            let mut next = Vec::new();
            for (chain, node) in &found {
                let children: Vec<(String, Option<u64>)> = if part == "*" {
                    match self.ntfs.directory_entries(node) {
                        Ok((preferred, _)) => preferred
                            .into_iter()
                            .filter(|e| e.name != "." && e.name != "..")
                            .map(|e| (e.name, Some(e.segment)))
                            .collect(),
                        Err(_) => continue,
                    }
                } else {
                    vec![(part.to_string(), None)]
                };
                for (name, segment) in children {
                    let resolved = match segment {
                        Some(segment) => self.ntfs.mft_record(segment),
                        None => self.ntfs.get_path(node, &name),
                    };
                    let Ok(child) = resolved else {
                        continue;
                    };
                    if part == "*" && !child.is_dir() {
                        continue;
                    }
                    let mut longer = chain.clone();
                    longer.push((name, child.segment, child.sequence));
                    next.push((longer, child));
                }
            }
            found = next;
        }
        found
    }

    /// `_recover_priority_paths`: exempt from the file cap (the files count toward it, so the tree
    /// walk gets what is left); only the free-space reserve stops them.
    fn recover_priority(&mut self, patterns: &[String]) -> Result<(), String> {
        for pattern in patterns {
            let root = match self.ntfs.mft_record(5) {
                Ok(root) => root,
                Err(message) => return Err(format!("root record unreadable: {message}")),
            };
            for (chain, record) in self.priority_targets(root, pattern) {
                self.ntfs.check_refused()?;
                let mut target = ROOT;
                for (name, segment, sequence) in &chain {
                    target =
                        self.names
                            .child(target, safe_component(name), *segment, *sequence, name);
                }
                let record = &record;
                let outcome = (|| -> Result<(), Raised> {
                    if record.is_dir() {
                        self.walk_dir(record, target, 0, i128::MAX, true)
                            .map_err(Raised::Fatal)?;
                    } else {
                        let segment = record.segment;
                        if self.done.contains(&segment) {
                            return Ok(());
                        }
                        self.dump(record, target)?;
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
        let deleted_dir = extract_dir.join(crate::names::DELETED_SWEEP_DIR);
        let mut consecutive_missing: u64 = 0;
        for index in 0..total {
            self.ntfs.check_refused()?;
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
            let base = format!("{index}-{}", safe_component(&filename));
            let target = self.names.child(
                DELETED_DIR,
                base,
                record.segment,
                record.sequence,
                &filename,
            );
            let (before_files, before_errors) = (self.stats.files, self.stats.errors);
            match self.dump(&record, target) {
                Ok(()) => {}
                Err(Raised::Counted) => {
                    return Err(format!(
                        "cannot create {} for a deleted record",
                        deleted_dir.display()
                    ));
                }
                Err(Raised::Fatal(message)) => return Err(message),
            }
            if self.stats.files != before_files {
                self.stats.deleted_files += 1;
            } else if self.stats.errors != before_errors {
                self.stats.deleted_read_errors += 1;
            }
            self.on_progress().map_err(fatal_message)?;
        }
        Ok(())
    }
}

/// Runs `body`, turning a panic into `Err("rapid-extract panicked: ...")`. pyo3 would raise a panic
/// as `pyo3_runtime.PanicException`, a `BaseException` an `except Exception` fallback lets
/// through; as an error the image is redone on the Python engine and the reason recorded.
pub fn catch_panic<T>(body: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)).unwrap_or_else(|payload| {
        let text = payload
            .downcast_ref::<&str>()
            .map(|text| (*text).to_string())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_default();
        Err(format!("rapid-extract panicked: {text}"))
    })
}

fn fatal_message(raised: Raised) -> String {
    match raised {
        Raised::Fatal(message) => message,
        Raised::Counted => "unexpected counted error".into(),
    }
}

/// The read/write loop of `_dump_ntfs_record` into the opened target: bytes counted as
/// `size - max(remaining, 0)`.
fn copy_into<V: VolRead>(
    stream: &Stream,
    size: i128,
    file: &mut fs::File,
    vol: &mut V,
) -> Result<i128, String> {
    let mut remaining = size;
    let mut pos: i128 = 0;
    while remaining > 0 {
        let want = CHUNK.min(remaining);
        let chunk = stream.read(vol, pos, want)?;
        pos += want.min(stream.size - pos).max(0);
        if chunk.is_empty() {
            break;
        }
        file.write_all(&chunk).map_err(|e| e.to_string())?;
        remaining -= chunk.len() as i128;
    }
    file.flush().map_err(|e| e.to_string())?;
    Ok(size - remaining.max(0))
}

/// `_restore_record_times` on the written file: false (counted in `time_restore_skips`) when the
/// record has no restorable times or the output drive refuses them.
fn restore_times(file: &fs::File, times: Option<RecordTimes>) -> bool {
    times
        .and_then(|times| times.file_times())
        .is_some_and(|times| file.set_times(times).is_ok())
}

/// Fails the run (the Python engine then redoes the image) for an output path Python would not
/// write the way Rust does: on Windows without the system-wide long-path opt-in, Python's
/// `open`/`mkdir` fail from `MAX_PATH` (directories from 248 characters) where Rust's std
/// silently writes through a `\\?\` path.
#[cfg(windows)]
fn check_output_path(path: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    // raw-dylib: no import library needed for this ntdll export (Windows 10 1607+).
    #[link(name = "ntdll", kind = "raw-dylib")]
    extern "system" {
        fn RtlAreLongPathsEnabled() -> u8;
    }
    const SHORTEST_UNSUPPORTED: usize = 248;
    let full = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    if full.as_os_str().encode_wide().count() < SHORTEST_UNSUPPORTED {
        return Ok(());
    }
    // SAFETY: takes no arguments and only reads the process's long-path setting.
    if unsafe { RtlAreLongPathsEnabled() } != 0 {
        return Ok(());
    }
    Err(format!(
        "windows-long-path: {} is longer than this system supports without long paths",
        full.display()
    ))
}

#[cfg(not(windows))]
fn check_output_path(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn fold_key(path: &Path) -> String {
    path.to_string_lossy().to_lowercase()
}

/// A file one copy unit wrote; `ok` is the outcome of its last copy.
struct Owned {
    path: PathBuf,
    id: FileId,
    ok: bool,
}

/// One planned copy on a worker, with the effects the sequential walk would have: a failed copy is
/// gone before the next job of the unit writes the same file (the sequential walk removes it, and
/// the name is free again). Failed files stay on disk until every worker is done, so no other unit
/// can create the same file unnoticed in the meantime. `Err` (the walk must run sequentially) when
/// the target reaches a file or directory another target reached (names the output drive folds
/// together, which the sequential walk renames), or creating it fails other than on what was in
/// the output folder before the run.
fn copy_job<V: VolRead>(
    job: &Job,
    owned: &mut Vec<Owned>,
    claims: &Mutex<HashMap<FileId, PathBuf>>,
    existing: &HashSet<PathBuf>,
    reader: &mut V,
) -> Result<JobOutcome, String> {
    let target: &Path = &job.key.0;
    let collision = |why: String| format!("output path collision at {}: {why}", target.display());
    if owned.iter().any(|o| !o.ok) {
        if let Ok(id) = path_id(target) {
            if let Some(at) = owned.iter().position(|o| !o.ok && o.id == id) {
                let failed = owned.remove(at);
                fs::remove_file(&failed.path).map_err(|e| collision(e.to_string()))?;
                if let Ok(mut claims) = claims.lock() {
                    claims.remove(&failed.id);
                }
            }
        }
    }
    let mut file = match fs::File::create(target) {
        Ok(file) => file,
        Err(_) if existing.contains(target) => {
            // In the output folder before the run (a directory, say): the walk fails on it alike.
            let _ = fs::remove_file(target);
            return Ok(JobOutcome::ReadFailed);
        }
        Err(error) => return Err(collision(error.to_string())),
    };
    let id = opened_id(&file, target).map_err(|e| collision(e.to_string()))?;
    {
        let mut claims = claims
            .lock()
            .map_err(|_| collision("claims poisoned".into()))?;
        match claims.get(&id) {
            Some(other) if other != target => {
                return Err(collision("another target reached the same file".into()));
            }
            Some(_) => {}
            None => {
                // `FileId` is `Copy` on Unix only (a `PathBuf` elsewhere).
                #[allow(clippy::clone_on_copy)]
                claims.insert(id.clone(), target.to_path_buf());
            }
        }
    }
    let slot = match owned.iter().position(|o| o.id == id) {
        Some(slot) => slot,
        None => {
            owned.push(Owned {
                path: target.to_path_buf(),
                id,
                ok: false,
            });
            owned.len() - 1
        }
    };
    let copied = copy_into(&job.stream, job.size, &mut file, reader);
    owned[slot].ok = copied.is_ok();
    Ok(match copied {
        Ok(n) => JobOutcome::Copied(n, restore_times(&file, job.times)),
        Err(_) => JobOutcome::ReadFailed,
    })
}

/// What the parallel copies did: each job's outcome, or why they cannot stand in for the
/// sequential walk (an output path collision).
type Executed = Result<Vec<JobOutcome>, String>;

/// Run the planned side effects on `threads` workers. Directories (`dirs`, the plan's
/// [`OutputNames::dirs`]) are created first, in walk order, so each keeps the spelling the
/// sequential walk gives it; two of them that the output drive folds into one folder are a
/// collision. Jobs whose targets fold to the same path stay in walk order on one worker; units
/// start in image order. Two targets reaching the same file (names the output file system folds
/// together, a file where another target needs a directory) are detected, and the walk then runs
/// sequentially, which renames the later one. With a `space` reserve the drive is re-read while
/// copying, and the copies stop with an error once the bytes still to write no longer fit above
/// the reserve (another writer took the space the plan counted on).
#[allow(clippy::too_many_arguments)]
fn execute<M: Media>(
    ntfs: &Ntfs<M>,
    dirs: &[PathBuf],
    jobs: &[Job],
    threads: usize,
    stats: &Stats,
    progress: &mut ProgressFn<'_>,
    space: Option<&SpaceReserve>,
    existing: &HashSet<PathBuf>,
) -> Result<Executed, String> {
    let mut folders: HashMap<FileId, &Path> = HashMap::new();
    for dir in dirs {
        let made = fs::create_dir_all(dir).and_then(|()| target_id(dir));
        let reason = match made {
            Err(error) => Some(error.to_string()),
            Ok(id) => folders
                .insert(id, dir)
                .map(|other| format!("the folder of {} too", other.display())),
        };
        if let Some(reason) = reason {
            return Ok(Err(format!(
                "output path collision at {}: {reason}",
                dir.display()
            )));
        }
    }
    let mut units: Vec<Vec<usize>> = Vec::new();
    let mut unit_of: HashMap<String, usize> = HashMap::new();
    for (index, job) in jobs.iter().enumerate() {
        let unit = *unit_of.entry(fold_key(&job.key.0)).or_insert_with(|| {
            units.push(Vec::new());
            units.len() - 1
        });
        units[unit].push(index);
    }
    units.sort_by_cached_key(|unit| jobs[unit[0]].stream.first_lcn());
    let vol = ntfs.vol.borrow();
    let direct = vol.direct();
    let next = AtomicUsize::new(0);
    let copied_files = AtomicUsize::new(0);
    let bytes = AtomicI64::new(0);
    let abort = AtomicBool::new(false);
    let planned_bytes: i128 = jobs.iter().map(|job| job.size.max(0)).sum();
    let results: Mutex<Vec<(usize, JobOutcome)>> = Mutex::new(Vec::new());
    let written: Mutex<Vec<Owned>> = Mutex::new(Vec::new());
    let claims: Mutex<HashMap<FileId, PathBuf>> = Mutex::new(HashMap::new());
    // (collision, fatal) reasons from the workers.
    let stopped: Mutex<(Option<String>, Option<String>)> = Mutex::new((None, None));
    let stop = |collision: Option<String>, fatal: Option<String>| {
        abort.store(true, Ordering::Relaxed);
        if let Ok(mut reasons) = stopped.lock() {
            reasons.0 = reasons.0.take().or(collision);
            reasons.1 = reasons.1.take().or(fatal);
        }
    };
    std::thread::scope(|scope| -> Result<(), String> {
        let workers: Vec<_> = (0..threads.max(1))
            .map(|_| {
                scope.spawn(|| {
                    let mut reader = DirectReader {
                        media: direct.media,
                        base: direct.base,
                        size: direct.size,
                        refused: None,
                    };
                    let mut local = Vec::new();
                    let mut mine = Vec::new();
                    'units: loop {
                        let unit = next.fetch_add(1, Ordering::Relaxed);
                        if unit >= units.len() || abort.load(Ordering::Relaxed) {
                            break;
                        }
                        let mut owned = Vec::new();
                        for &index in &units[unit] {
                            if abort.load(Ordering::Relaxed) {
                                break 'units;
                            }
                            let job = &jobs[index];
                            let outcome = copy_job(job, &mut owned, &claims, existing, &mut reader);
                            if let Some(message) = reader.refused.take() {
                                stop(None, Some(message));
                                break 'units;
                            }
                            match outcome {
                                Ok(outcome) => {
                                    if let JobOutcome::Copied(n, _) = outcome {
                                        bytes.fetch_add(n as i64, Ordering::Relaxed);
                                        copied_files.fetch_add(1, Ordering::Relaxed);
                                    }
                                    local.push((index, outcome));
                                }
                                Err(reason) => {
                                    stop(Some(reason), None);
                                    break 'units;
                                }
                            }
                        }
                        mine.extend(owned);
                    }
                    if let Ok(mut all) = results.lock() {
                        all.extend(local);
                    }
                    if let Ok(mut all) = written.lock() {
                        all.extend(mine);
                    }
                })
            })
            .collect();
        while workers.iter().any(|w| !w.is_finished()) {
            let mut snapshot = stats.clone();
            snapshot.files = copied_files.load(Ordering::Relaxed) as i128;
            snapshot.bytes = bytes.load(Ordering::Relaxed) as i128;
            let checked = progress(&snapshot).and_then(|()| match space {
                Some(space) if space.free_at_start >= 0 => {
                    let free = (space.probe)();
                    let still_to_write = planned_bytes - snapshot.bytes;
                    if free >= 0 && free - still_to_write < space.min_free {
                        Err(format!(
                            "{SPACE_RESERVE_ERROR}: the output drive has {free} bytes free with \
                             {still_to_write} still to write, below its {}-byte reserve",
                            space.min_free
                        ))
                    } else {
                        Ok(())
                    }
                }
                _ => Ok(()),
            });
            if let Err(message) = checked {
                stop(None, Some(message));
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        for worker in workers {
            worker
                .join()
                .map_err(|_| "copy worker panicked".to_string())?;
        }
        Ok(())
    })?;
    let (collision, fatal) = stopped
        .into_inner()
        .map_err(|_| "copy stop reasons poisoned".to_string())?;
    if let Some(message) = fatal {
        return Err(message);
    }
    if let Some(reason) = collision {
        return Ok(Err(reason));
    }
    // The sequential walk removes a file whose copy failed; every unit is done with them now.
    for file in written
        .into_inner()
        .map_err(|_| "copy results poisoned".to_string())?
    {
        if !file.ok {
            let _ = fs::remove_file(&file.path);
        }
    }
    let mut outcomes: Vec<Option<JobOutcome>> = vec![None; jobs.len()];
    for (index, outcome) in results
        .into_inner()
        .map_err(|_| "copy results poisoned".to_string())?
    {
        outcomes[index] = Some(outcome);
    }
    outcomes
        .into_iter()
        .collect::<Option<Vec<JobOutcome>>>()
        .map(Ok)
        .ok_or_else(|| "a planned copy never ran".to_string())
}

/// Every path under `dir` (symlinks not followed); empty when `dir` does not exist.
fn snapshot(dir: &Path) -> HashSet<PathBuf> {
    let mut seen = HashSet::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        let Ok(entries) = fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                pending.push(path.clone());
            }
            seen.insert(path);
        }
    }
    seen
}

/// Remove everything under `dir` that `before` (a [`snapshot`]) does not list, at any depth.
fn discard_new_paths(dir: &Path, before: &HashSet<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_dir = entry.file_type().is_ok_and(|kind| kind.is_dir());
        if before.contains(&path) {
            if is_dir {
                discard_new_paths(&path, before);
            }
        } else if is_dir {
            let _ = fs::remove_dir_all(&path);
        } else {
            let _ = fs::remove_file(&path);
        }
    }
}

fn new_walker<'a, M: Media>(
    ntfs: &'a Ntfs<M>,
    progress: ProgressFn<'a>,
    planning: bool,
    limit: i128,
    every: u64,
    space: Option<&SpaceReserve>,
    names: OutputNames,
) -> Walker<'a, M> {
    Walker {
        ntfs,
        stats: Stats {
            file_limit: limit,
            ..Stats::default()
        },
        done: HashSet::new(),
        progress,
        progress_every: every.max(1),
        pending: 0,
        plan: planning.then(Vec::new),
        known: HashMap::new(),
        space: space
            .filter(|reserve| reserve.free_at_start >= 0)
            .map(|reserve| SpaceState {
                left: reserve.free_at_start - reserve.min_free - SPACE_MARGIN,
                reserve: reserve.clone(),
                files: 0,
                bytes: 0,
            }),
        names,
    }
}

fn walk_all<M: Media>(
    walker: &mut Walker<'_, M>,
    ntfs: &Ntfs<M>,
    options: &Options<'_>,
) -> Result<(), String> {
    let root = ntfs
        .mft_record(5)
        .map_err(|m| format!("root record unreadable: {m}"))?;
    walker.recover_priority(&options.priority_paths)?;
    let limit = walker.stats.file_limit;
    walker.walk_dir(&root, ROOT, 0, limit, false)?;
    if options.include_deleted {
        walker.sweep_deleted(&options.extract_dir)?;
    }
    // A read refused late in the walk (the last directory's listing, say) still fails the run.
    ntfs.check_refused()
}

/// What one `extract` call did, besides the stats.
pub struct Outcome {
    pub stats: Stats,
    /// Records written under a tagged name or not at all because their name was taken
    /// (`output_name_collisions`, the first [`crate::names::REPORT_LIMIT`]).
    pub collisions: Vec<Collision>,
    pub walk_seconds: f64,
    pub copy_seconds: f64,
    /// Why the parallel plan could not be used, which made the walk run again sequentially (exact
    /// Python order of effects); `None` when no rerun happened.
    pub rerun_reason: Option<String>,
}

/// The body of `extract_e01_native` after `NTFS(reader)`: priority paths, the full tree walk,
/// then (optionally) the deleted-record sweep. `Err` means the run must not be trusted.
///
/// With `threads > 1` a first walk plans every side effect assuming each copy succeeds; the
/// copies then run in parallel and each one's outcome is recorded. If any failed, a second walk
/// replays the recorded outcomes in walk order, which yields exactly the sequential counters as
/// long as it plans the same side effects. Only when a failure moved a decision (a cap boundary,
/// say) or two planned names meet on the output drive does the walk run again sequentially,
/// after removing everything written.
pub fn extract<'a, M: Media>(
    ntfs: &'a Ntfs<M>,
    mut options: Options<'a>,
) -> Result<Outcome, String> {
    let (options_limit, options_every) = (options.limit, options.progress_every);
    let space = options.space.clone();
    let (extract_dir, include_deleted) = (options.extract_dir.clone(), options.include_deleted);
    let fresh = |progress: ProgressFn<'a>, planning: bool, known: HashMap<JobKey, JobOutcome>| {
        let mut walker = new_walker(
            ntfs,
            progress,
            planning,
            options_limit,
            options_every,
            space.as_ref(),
            OutputNames::new(&extract_dir, include_deleted, planning),
        );
        walker.known = known;
        walker
    };
    let started = Instant::now();
    let mut rerun_reason = None;
    if options.threads > 1 {
        let before = snapshot(&options.extract_dir);
        let progress = std::mem::replace(&mut options.progress, Box::new(|_| Ok(())));
        let mut planner = fresh(progress, true, HashMap::new());
        walk_all(&mut planner, ntfs, &options)?;
        let jobs = planner.plan.take().unwrap_or_default();
        let walk_seconds = started.elapsed().as_secs_f64();
        let copying = Instant::now();
        let executed = execute(
            ntfs,
            &planner.names.dirs,
            &jobs,
            options.threads,
            &planner.stats,
            &mut planner.progress,
            space.as_ref(),
            &before,
        )?;
        let mut progress = std::mem::replace(&mut planner.progress, Box::new(|_| Ok(())));
        match executed {
            Err(collision) => rerun_reason = Some(collision),
            Ok(outcomes) => {
                if outcomes
                    .iter()
                    .all(|outcome| matches!(outcome, JobOutcome::Copied(..)))
                {
                    planner.stats.bytes = outcomes
                        .iter()
                        .map(|o| {
                            if let JobOutcome::Copied(n, _) = o {
                                *n
                            } else {
                                0
                            }
                        })
                        .sum();
                    // Every planned file was written: the skips are the copies that kept their
                    // extraction time (the plan only counted records without times).
                    planner.stats.time_restore_skips = outcomes
                        .iter()
                        .filter(|o| matches!(o, JobOutcome::Copied(_, false)))
                        .count() as i128;
                    planner.plan = None;
                    planner.progress = progress;
                    planner.flush_progress().map_err(fatal_message)?;
                    return Ok(Outcome {
                        stats: planner.stats,
                        collisions: planner.names.report,
                        walk_seconds,
                        copy_seconds: copying.elapsed().as_secs_f64(),
                        rerun_reason: None,
                    });
                }
                let known: HashMap<JobKey, JobOutcome> = jobs
                    .iter()
                    .zip(&outcomes)
                    .map(|(job, outcome)| (job.key.clone(), *outcome))
                    .collect();
                let unique = known.len() == jobs.len();
                let mut replay = fresh(progress, true, known);
                let replayed = if unique {
                    walk_all(&mut replay, ntfs, &options)
                } else {
                    Err("duplicate job keys".into())
                };
                let same_plan = replayed.is_ok()
                    && replay.names.dirs == planner.names.dirs
                    && replay.plan.as_ref().is_some_and(|again| {
                        again.len() == jobs.len()
                            && again.iter().zip(&jobs).all(|(a, b)| a.key == b.key)
                    });
                if same_plan {
                    replay.plan = None;
                    replay.flush_progress().map_err(fatal_message)?;
                    return Ok(Outcome {
                        stats: replay.stats,
                        collisions: replay.names.report,
                        walk_seconds,
                        copy_seconds: copying.elapsed().as_secs_f64(),
                        rerun_reason: None,
                    });
                }
                rerun_reason = Some(match replayed {
                    Err(message) => message,
                    Ok(()) => "a failed copy changed the walk's later decisions".to_string(),
                });
                progress = replay.progress;
            }
        }
        discard_new_paths(&options.extract_dir, &before);
        options.progress = progress;
    }
    let sequential = Instant::now();
    let progress = std::mem::replace(&mut options.progress, Box::new(|_| Ok(())));
    let mut walker = fresh(progress, false, HashMap::new());
    walk_all(&mut walker, ntfs, &options)?;
    walker.flush_progress().map_err(fatal_message)?;
    Ok(Outcome {
        stats: walker.stats,
        collisions: walker.names.report,
        walk_seconds: sequential.elapsed().as_secs_f64(),
        copy_seconds: 0.0,
        rerun_reason,
    })
}

#[cfg(test)]
mod tests {
    use super::{catch_panic, discard_new_paths, is_windows_device_name, safe_component, snapshot};
    use std::fs;

    #[test]
    fn panics_become_errors() {
        let caught = catch_panic::<()>(|| panic!("index {} out of range", 7));
        assert_eq!(
            caught,
            Err("rapid-extract panicked: index 7 out of range".into())
        );
        assert_eq!(catch_panic(|| Ok::<_, String>(3)), Ok(3));
    }

    #[test]
    fn safe_component_matches_python() {
        assert_eq!(safe_component("weird:name?.txt"), "weird_name_.txt");
        assert_eq!(safe_component("trailing dot. "), "trailing dot");
        assert_eq!(safe_component(".."), "_");
        assert_eq!(safe_component("a\u{1}b"), "a_b");
        assert_eq!(safe_component(&"가".repeat(200)).chars().count(), 180);
        let device = if cfg!(windows) { "_CON.txt" } else { "CON.txt" };
        assert_eq!(safe_component("CON.txt"), device);
    }

    #[test]
    fn windows_device_names_match_python() {
        for name in [
            "CON",
            "con.txt",
            "Nul",
            "COM1.log",
            "lpt9 .txt",
            "COM\u{b9}",
            "CONIN$",
        ] {
            assert!(is_windows_device_name(name), "{name}");
        }
        for name in ["CONSOLE", "COM10", "xCON", "aux_", "COM", "LPT0x.txt"] {
            assert!(!is_windows_device_name(name), "{name}");
        }
    }

    #[test]
    fn discard_removes_new_paths_at_any_depth() {
        let root =
            std::env::temp_dir().join(format!("rapid-extract-discard-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("kept/inner")).unwrap();
        fs::write(root.join("kept/old.txt"), b"old").unwrap();
        let before = snapshot(&root);
        fs::write(root.join("kept/new.txt"), b"new").unwrap();
        fs::create_dir_all(root.join("kept/inner/fresh")).unwrap();
        fs::write(root.join("kept/inner/fresh/f"), b"f").unwrap();
        fs::create_dir_all(root.join("top")).unwrap();
        discard_new_paths(&root, &before);
        assert_eq!(snapshot(&root), before);
        fs::remove_dir_all(&root).unwrap();
    }
}
