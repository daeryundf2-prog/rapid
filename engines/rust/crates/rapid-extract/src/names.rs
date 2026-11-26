//! `_OutputNames` of `rapidtriage/core/e01_native.py`: every recovered record gets its own output
//! file or directory. Each one is an (output directory, MFT record) pair; when its name is taken
//! (two records whose names `safe_component` makes equal, or that the output drive folds together:
//! case, Unicode normalization, 8.3 aliases), the later record in walk order gets a tagged name
//! (`tagged_name`) instead of overwriting or merging into the first. A name is taken when another
//! record was given the same path in this run, or when the drive resolves the path to a file or
//! directory written for another record (checked before writing). A planning walk has no drive to
//! ask; the parallel copy checks that no two planned paths meet on the drive.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Name of the deleted-record sweep folder below the extraction root.
pub const DELETED_SWEEP_DIR: &str = "_deleted_mft";
/// Names one record tries (the plain name, then tagged ones) before it is reported unresolved.
const ATTEMPTS: usize = 32;
/// Entries kept in the collision report; the stats count every collision.
pub const REPORT_LIMIT: usize = 1000;
/// Index of the extraction root in [`OutputNames`].
pub const ROOT: usize = 0;
/// Index of the deleted-record sweep folder in [`OutputNames`].
pub const DELETED_DIR: usize = 1;

/// A file on the output drive: (device, inode) on Unix; elsewhere the canonical path, which
/// Windows resolves from the opened file (the stored spelling of every component).
#[cfg(unix)]
pub type FileId = (u64, u64);
#[cfg(not(unix))]
pub type FileId = PathBuf;

/// The identity of `path` itself (symlinks not followed).
#[cfg(unix)]
pub fn path_id(path: &Path) -> io::Result<FileId> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::symlink_metadata(path)?;
    Ok((meta.dev(), meta.ino()))
}

#[cfg(not(unix))]
pub fn path_id(path: &Path) -> io::Result<FileId> {
    fs::canonicalize(path)
}

/// The identity of what `path` resolves to (symlinks followed).
#[cfg(unix)]
pub fn target_id(path: &Path) -> io::Result<FileId> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::metadata(path)?;
    Ok((meta.dev(), meta.ino()))
}

#[cfg(not(unix))]
pub fn target_id(path: &Path) -> io::Result<FileId> {
    fs::canonicalize(path)
}

#[cfg(unix)]
pub fn opened_id(file: &fs::File, _path: &Path) -> io::Result<FileId> {
    use std::os::unix::fs::MetadataExt;
    let meta = file.metadata()?;
    Ok((meta.dev(), meta.ino()))
}

#[cfg(not(unix))]
pub fn opened_id(_file: &fs::File, path: &Path) -> io::Result<FileId> {
    fs::canonicalize(path)
}

/// `_file_identity`: `None` where the drive reports none (inode 0).
#[cfg(unix)]
fn known(id: io::Result<FileId>) -> Option<FileId> {
    id.ok().filter(|id| id.1 != 0)
}

#[cfg(not(unix))]
fn known(id: io::Result<FileId>) -> Option<FileId> {
    id.ok()
}

/// `_tagged_name`: `base`, then `<stem>~mft<segment>[-<attempt>]<extension>` within 180
/// characters; the extension (up to 16 characters) is kept so parsers that select files by suffix
/// still see it.
pub fn tagged_name(base: &str, segment: Option<u64>, attempt: usize) -> String {
    if attempt == 0 {
        return base.to_string();
    }
    let mut tag = match segment {
        Some(segment) => format!("~mft{segment}"),
        None => "~mft".to_string(),
    };
    if attempt > 1 {
        tag.push_str(&format!("-{attempt}"));
    }
    let chars: Vec<char> = base.chars().collect();
    let extension = match chars.iter().rposition(|&c| c == '.') {
        Some(dot) if dot > 0 && chars.len() - dot <= 16 => chars.len() - dot,
        _ => 0,
    };
    let stem_end = chars.len() - extension;
    let keep = 180usize
        .saturating_sub(tag.chars().count() + extension)
        .max(1);
    let stem: String = chars[..stem_end].iter().take(keep).collect();
    let suffix: String = chars[stem_end..].iter().collect();
    format!("{stem}{tag}{suffix}")
}

/// One entry of the collision report (`output_name_collisions`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Collision {
    /// `renamed` (written under a tagged name) or `unresolved` (not written).
    pub status: &'static str,
    /// `file` or `directory`.
    pub kind: &'static str,
    /// Relative to the extraction root, `/`-separated; `None` when unresolved.
    pub output_path: Option<String>,
    pub source_name: String,
    /// Volume path of the record (`None` for deleted records, which have no directory).
    pub source_path: Option<String>,
    pub mft_segment: Option<u64>,
    pub mft_sequence: Option<u16>,
}

/// `_OutputEntry`: one recovered file or directory.
struct Entry {
    parent: Option<usize>,
    base: String,
    segment: Option<u64>,
    sequence: Option<u16>,
    source_name: String,
    source_path: Option<String>,
    path: Option<PathBuf>,
    identity: Option<FileId>,
    /// Entries below this directory, by MFT segment.
    children: HashMap<u64, usize>,
}

/// `_OutputNames`. Counters go to the caller's `renamed` / `unresolved` stats.
pub struct OutputNames {
    entries: Vec<Entry>,
    /// No drive: names are only checked against each other (the parallel copy's plan).
    planning: bool,
    root_made: bool,
    paths: HashMap<PathBuf, usize>,
    live: HashMap<FileId, usize>,
    /// Directories handed out, in walk order (the root first).
    pub dirs: Vec<PathBuf>,
    pub report: Vec<Collision>,
}

impl OutputNames {
    pub fn new(root: &Path, reserve_deleted_dir: bool, planning: bool) -> Self {
        let entry = |parent, base: &str, source_path: Option<String>| Entry {
            parent,
            base: base.to_string(),
            segment: None,
            sequence: None,
            source_name: base.to_string(),
            source_path,
            path: None,
            identity: None,
            children: HashMap::new(),
        };
        let mut root_entry = entry(None, "", Some(String::new()));
        root_entry.path = Some(root.to_path_buf());
        let mut names = OutputNames {
            entries: vec![root_entry, entry(Some(ROOT), DELETED_SWEEP_DIR, None)],
            planning,
            root_made: false,
            paths: HashMap::new(),
            live: HashMap::new(),
            dirs: Vec::new(),
            report: Vec::new(),
        };
        if reserve_deleted_dir {
            names
                .paths
                .insert(root.join(DELETED_SWEEP_DIR), DELETED_DIR);
        }
        names
    }

    /// `_OutputEntry.child`: the entry of MFT record `segment` below directory `parent` (one per
    /// record, whatever name reached it).
    pub fn child(
        &mut self,
        parent: usize,
        base: String,
        segment: u64,
        sequence: u16,
        source_name: &str,
    ) -> usize {
        if let Some(&found) = self.entries[parent].children.get(&segment) {
            return found;
        }
        let source_path = self.entries[parent].source_path.as_ref().map(|path| {
            if path.is_empty() {
                source_name.to_string()
            } else {
                format!("{path}/{source_name}")
            }
        });
        let id = self.entries.len();
        self.entries.push(Entry {
            parent: Some(parent),
            base,
            segment: Some(segment),
            sequence: Some(sequence),
            source_name: source_name.to_string(),
            source_path,
            path: None,
            identity: None,
            children: HashMap::new(),
        });
        self.entries[parent].children.insert(segment, id);
        id
    }

    pub fn parent(&self, id: usize) -> usize {
        self.entries[id].parent.unwrap_or(ROOT)
    }

    pub fn base(&self, id: usize) -> &str {
        &self.entries[id].base
    }

    fn taken(&mut self, path: &Path, id: usize) -> bool {
        if *self.paths.entry(path.to_path_buf()).or_insert(id) != id {
            return true;
        }
        if self.planning {
            return false;
        }
        match known(path_id(path)) {
            Some(identity) => self.live.get(&identity).is_some_and(|&owner| owner != id),
            None => false,
        }
    }

    fn claim(
        &mut self,
        id: usize,
        path: &Path,
        identity: Option<FileId>,
        kind: &'static str,
        attempt: usize,
        renamed: &mut i128,
    ) -> bool {
        if let Some(identity) = &identity {
            if self.live.get(identity).is_some_and(|&owner| owner != id) {
                return false;
            }
            // `FileId` is `Copy` on Unix only (a `PathBuf` elsewhere).
            #[allow(clippy::clone_on_copy)]
            self.live.insert(identity.clone(), id);
        }
        self.entries[id].path = Some(path.to_path_buf());
        self.entries[id].identity = identity;
        if attempt > 0 {
            *renamed += 1;
            self.record(id, kind, "renamed", Some(path));
        }
        true
    }

    fn record(&mut self, id: usize, kind: &'static str, status: &'static str, path: Option<&Path>) {
        if self.report.len() >= REPORT_LIMIT {
            return;
        }
        let root = self.entries[ROOT].path.clone().unwrap_or_default();
        let output_path = path.map(|path| {
            path.strip_prefix(&root)
                .unwrap_or(path)
                .components()
                .map(|part| part.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/")
        });
        let entry = &self.entries[id];
        self.report.push(Collision {
            status,
            kind,
            output_path,
            source_name: entry.source_name.clone(),
            source_path: entry.source_path.clone(),
            mft_segment: entry.segment,
            mft_sequence: entry.sequence,
        });
    }

    /// File entry `id` was not written: no name was left for it or for its directory.
    pub fn unresolved(&mut self, id: usize, unresolved: &mut i128) {
        *unresolved += 1;
        self.record(id, "file", "unresolved", None);
    }

    /// `_OutputNames.directory`: entry `id`'s output directory, created with its parents (not when
    /// planning); `Ok(None)` when no name is left. `Err` is a creation failure (a file in the
    /// folder before the run, say) the caller counts.
    pub fn directory(&mut self, id: usize, renamed: &mut i128) -> io::Result<Option<PathBuf>> {
        let Some(parent) = self.entries[id].parent else {
            let root = self.entries[id].path.clone().unwrap_or_default();
            if !self.root_made {
                if !self.planning {
                    fs::create_dir_all(&root)?;
                }
                self.root_made = true;
                self.dirs.push(root.clone());
            }
            return Ok(Some(root));
        };
        if let Some(path) = &self.entries[id].path {
            return Ok(Some(path.clone()));
        }
        let Some(parent_path) = self.directory(parent, renamed)? else {
            return Ok(None);
        };
        for attempt in 0..ATTEMPTS {
            let name = tagged_name(&self.entries[id].base, self.entries[id].segment, attempt);
            let path = parent_path.join(name);
            if self.taken(&path, id) {
                continue;
            }
            let identity = if self.planning {
                None
            } else {
                match fs::create_dir(&path) {
                    Ok(()) => {}
                    // `mkdir(exist_ok=True)`: an existing directory (symlinks followed) is fine.
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists && path.is_dir() => {
                    }
                    Err(error) => return Err(error),
                }
                known(target_id(&path))
            };
            if self.claim(id, &path, identity, "directory", attempt, renamed) {
                self.dirs.push(path.clone());
                return Ok(Some(path));
            }
        }
        Ok(None)
    }

    /// The path planned for file entry `id` in `parent` (no drive); `None` when no name is left.
    pub fn plan_file(&mut self, id: usize, parent: &Path, renamed: &mut i128) -> Option<PathBuf> {
        for attempt in 0..ATTEMPTS {
            let path = parent.join(tagged_name(
                &self.entries[id].base,
                self.entries[id].segment,
                attempt,
            ));
            if !self.taken(&path, id) && self.claim(id, &path, None, "file", attempt, renamed) {
                return Some(path);
            }
        }
        None
    }

    /// `_OutputNames.create_file`: file entry `id`'s output file in `parent`, opened for writing
    /// and emptied; `Ok(None)` when no name is left. An `Err` leaves the entry at the name that
    /// could not be opened (see [`OutputNames::discard`]).
    pub fn create_file(
        &mut self,
        id: usize,
        parent: &Path,
        renamed: &mut i128,
    ) -> io::Result<Option<fs::File>> {
        for attempt in 0..ATTEMPTS {
            let path = parent.join(tagged_name(
                &self.entries[id].base,
                self.entries[id].segment,
                attempt,
            ));
            if self.taken(&path, id) {
                continue;
            }
            self.entries[id].path = Some(path.clone());
            // Not truncated before the check: the path may reach another record's file.
            let file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)?;
            let identity = known(opened_id(&file, &path));
            if self.claim(id, &path, identity, "file", attempt, renamed) {
                file.set_len(0)?;
                return Ok(Some(file));
            }
        }
        Ok(None)
    }

    /// `_OutputNames.discard`: remove file entry `id`'s file after a failed copy; its name stays
    /// taken.
    pub fn discard(&mut self, id: usize) {
        if let Some(identity) = self.entries[id].identity.take() {
            self.live.remove(&identity);
        }
        if let Some(path) = &self.entries[id].path {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::tagged_name;

    #[test]
    fn tagged_names_match_python() {
        assert_eq!(tagged_name("report.pdf", Some(42), 0), "report.pdf");
        assert_eq!(tagged_name("report.pdf", Some(42), 1), "report~mft42.pdf");
        assert_eq!(tagged_name("report.pdf", Some(42), 3), "report~mft42-3.pdf");
        assert_eq!(tagged_name(".profile", Some(7), 1), ".profile~mft7");
        assert_eq!(
            tagged_name("a.verylongextension1", Some(7), 1),
            "a.verylongextension1~mft7"
        );
        assert_eq!(tagged_name("_deleted_mft", None, 1), "_deleted_mft~mft");
        let long = "p".repeat(180);
        let tagged = tagged_name(&long, Some(205), 1);
        assert_eq!(tagged, format!("{}~mft205", "p".repeat(173)));
        let korean = format!("{}.hwp", "가".repeat(178));
        assert_eq!(
            tagged_name(&korean, Some(9), 2),
            format!("{}~mft9-2.hwp", "가".repeat(180 - 7 - 4))
        );
    }
}
