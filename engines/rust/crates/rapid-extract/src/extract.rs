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

use crate::ntfs::{DirectReader, Media, Ntfs, Record, Stream, VolRead};

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

/// A deferred `_dump_ntfs_record` side effect of the planning walk, keyed by (target, record).
enum Job {
    /// `out_path.parent.mkdir(...)` for a record whose stream then failed to open.
    Mkdir { key: JobKey, dir: PathBuf },
    Copy {
        key: JobKey,
        stream: Stream,
        size: i128,
    },
}

type JobKey = (PathBuf, u64);

/// How a deferred side effect went; a second planning walk replays these in walk order.
#[derive(Clone, Copy)]
enum JobOutcome {
    Copied(i128),
    ReadFailed,
    MkdirFailed,
}

impl Job {
    fn key(&self) -> &JobKey {
        match self {
            Job::Mkdir { key, .. } | Job::Copy { key, .. } => key,
        }
    }
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
    plan: Option<Vec<Job>>,
    known: HashMap<JobKey, JobOutcome>,
    space: Option<SpaceState>,
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
    fn dump(&mut self, record: &Record, out_path: &Path) -> Result<(), Raised> {
        let size = match self.ntfs.data_size(record) {
            Ok(size) => size,
            Err(_) => {
                self.stats.errors += 1;
                return Ok(());
            }
        };
        self.reserve_space(size).map_err(Raised::Fatal)?;
        if let Some(plan) = self.plan.as_mut() {
            let key: JobKey = (out_path.to_path_buf(), record.segment);
            let outcome = self.known.get(&key).copied();
            match self.ntfs.data_stream(record) {
                Ok(stream) => {
                    plan.push(Job::Copy { key, stream, size });
                    match outcome {
                        None => self.stats.files += 1,
                        Some(JobOutcome::Copied(bytes)) => {
                            self.stats.files += 1;
                            self.stats.bytes += bytes;
                        }
                        Some(JobOutcome::ReadFailed) => self.stats.errors += 1,
                        Some(JobOutcome::MkdirFailed) => return Err(Raised::Counted),
                    }
                }
                Err(_) => {
                    let dir = out_path.parent().map(Path::to_path_buf).unwrap_or_default();
                    plan.push(Job::Mkdir { key, dir });
                    if let Some(JobOutcome::MkdirFailed) = outcome {
                        return Err(Raised::Counted);
                    }
                    self.stats.errors += 1;
                }
            }
            return Ok(());
        }
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
        match copy_stream(&stream, size, out_path, &mut *self.ntfs.vol.borrow_mut()) {
            Ok(copied) => {
                self.stats.files += 1;
                self.stats.bytes += copied;
            }
            Err(_) => {
                self.stats.errors += 1;
                let _ = fs::remove_file(out_path);
            }
        }
        Ok(())
    }

    /// `_walk_ntfs_dir`. `done` holds the segments the priority pass recovered; only that pass
    /// records into it (`record_done`), so the full walk recovers every path of a hard-linked file.
    fn walk_dir(
        &mut self,
        node: &Record,
        out_dir: &Path,
        depth: u32,
        limit: i128,
        record_done: bool,
    ) -> Result<(), String> {
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
                    self.walk_dir(&record, &target, depth + 1, limit, record_done)
                        .map_err(Raised::Fatal)?;
                } else {
                    if self.done.contains(&segment) {
                        return Ok(());
                    }
                    if self.stats.files >= limit {
                        self.stats.truncated += 1;
                        return self.on_progress();
                    }
                    self.dump(&record, &target)?;
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

    /// `_recover_priority_paths`: exempt from the file cap (the files count toward it, so the tree
    /// walk gets what is left); only the free-space reserve stops them.
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
                        self.walk_dir(&record, &target, 0, i128::MAX, true)
                            .map_err(Raised::Fatal)?;
                    } else {
                        let segment = record.segment;
                        if self.done.contains(&segment) {
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
            let (before_files, before_errors) = (self.stats.files, self.stats.errors);
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

fn fatal_message(raised: Raised) -> String {
    match raised {
        Raised::Fatal(message) => message,
        Raised::Counted => "unexpected counted error".into(),
    }
}

/// The read/write loop of `_dump_ntfs_record`: bytes counted as `size - max(remaining, 0)`.
fn copy_stream<V: VolRead>(
    stream: &Stream,
    size: i128,
    out_path: &Path,
    vol: &mut V,
) -> Result<i128, String> {
    let mut remaining = size;
    let mut file = fs::File::create(out_path).map_err(|e| e.to_string())?;
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

fn fold_key(path: &Path) -> String {
    path.to_string_lossy().to_lowercase()
}

/// Run the planned side effects on `threads` workers and return each job's outcome. Jobs whose
/// targets fold to the same path stay in walk order on one worker (a later failure removes the
/// file an earlier job wrote, as in Python); units start in image order. With a `space` reserve
/// the drive is re-read while copying, and the copies stop with an error once the bytes still to
/// write no longer fit above the reserve (another writer took the space the plan counted on).
fn execute<M: Media>(
    ntfs: &Ntfs<M>,
    jobs: &[Job],
    threads: usize,
    stats: &Stats,
    progress: &mut ProgressFn<'_>,
    space: Option<&SpaceReserve>,
) -> Result<Vec<JobOutcome>, String> {
    let mut outcomes: Vec<Option<JobOutcome>> = vec![None; jobs.len()];
    let mut units: Vec<Vec<usize>> = Vec::new();
    let mut unit_of: HashMap<String, usize> = HashMap::new();
    for (index, job) in jobs.iter().enumerate() {
        match job {
            Job::Mkdir { dir, .. } => {
                outcomes[index] = Some(match fs::create_dir_all(dir) {
                    Ok(()) => JobOutcome::Copied(0),
                    Err(_) => JobOutcome::MkdirFailed,
                });
            }
            Job::Copy { key, .. } => {
                let unit = *unit_of.entry(fold_key(&key.0)).or_insert_with(|| {
                    units.push(Vec::new());
                    units.len() - 1
                });
                units[unit].push(index);
            }
        }
    }
    let start_of = |unit: &Vec<usize>| match &jobs[unit[0]] {
        Job::Copy { stream, .. } => stream.first_lcn(),
        Job::Mkdir { .. } => -1,
    };
    units.sort_by_cached_key(|unit| start_of(unit));
    let vol = ntfs.vol.borrow();
    let direct = vol.direct();
    let next = AtomicUsize::new(0);
    let copied_files = AtomicUsize::new(0);
    let bytes = AtomicI64::new(0);
    let abort = AtomicBool::new(false);
    let planned_bytes: i128 = jobs
        .iter()
        .map(|job| match job {
            Job::Copy { size, .. } => (*size).max(0),
            Job::Mkdir { .. } => 0,
        })
        .sum();
    let results: Mutex<Vec<(usize, JobOutcome)>> = Mutex::new(Vec::new());
    std::thread::scope(|scope| -> Result<(), String> {
        let workers: Vec<_> = (0..threads.max(1))
            .map(|_| {
                scope.spawn(|| {
                    let mut reader = DirectReader {
                        media: direct.media,
                        base: direct.base,
                        size: direct.size,
                    };
                    let mut local = Vec::new();
                    loop {
                        let unit = next.fetch_add(1, Ordering::Relaxed);
                        if unit >= units.len() || abort.load(Ordering::Relaxed) {
                            break;
                        }
                        for &index in &units[unit] {
                            if abort.load(Ordering::Relaxed) {
                                break;
                            }
                            let Job::Copy { key, stream, size } = &jobs[index] else {
                                continue;
                            };
                            let target = &key.0;
                            let created = target.parent().map(fs::create_dir_all).unwrap_or(Ok(()));
                            let outcome = match created {
                                Err(_) => JobOutcome::MkdirFailed,
                                Ok(()) => match copy_stream(stream, *size, target, &mut reader) {
                                    Ok(n) => {
                                        bytes.fetch_add(n as i64, Ordering::Relaxed);
                                        copied_files.fetch_add(1, Ordering::Relaxed);
                                        JobOutcome::Copied(n)
                                    }
                                    Err(_) => {
                                        let _ = fs::remove_file(target);
                                        JobOutcome::ReadFailed
                                    }
                                },
                            };
                            local.push((index, outcome));
                        }
                    }
                    if let Ok(mut all) = results.lock() {
                        all.extend(local);
                    }
                })
            })
            .collect();
        let mut failure: Option<String> = None;
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
                abort.store(true, Ordering::Relaxed);
                failure = Some(message);
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        for worker in workers {
            worker
                .join()
                .map_err(|_| "copy worker panicked".to_string())?;
        }
        failure.map_or(Ok(()), Err)
    })?;
    for (index, outcome) in results
        .into_inner()
        .map_err(|_| "copy results poisoned".to_string())?
    {
        outcomes[index] = Some(outcome);
    }
    outcomes
        .into_iter()
        .map(|o| o.ok_or_else(|| "a planned copy never ran".to_string()))
        .collect()
}

fn top_level_entries(dir: &Path) -> HashSet<PathBuf> {
    fs::read_dir(dir)
        .map(|it| it.filter_map(|e| e.ok().map(|e| e.path())).collect())
        .unwrap_or_default()
}

fn discard_new_entries(dir: &Path, before: &HashSet<PathBuf>) {
    for entry in top_level_entries(dir).difference(before) {
        if entry.is_dir() {
            let _ = fs::remove_dir_all(entry);
        } else {
            let _ = fs::remove_file(entry);
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
    walker.recover_priority(&options.extract_dir, &options.priority_paths)?;
    let limit = walker.stats.file_limit;
    walker.walk_dir(&root, &options.extract_dir, 0, limit, false)?;
    if options.include_deleted {
        walker.sweep_deleted(&options.extract_dir)?;
    }
    Ok(())
}

/// What one `extract` call did, besides the stats.
pub struct Outcome {
    pub stats: Stats,
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
/// say) does the walk run again sequentially, after removing everything written.
pub fn extract<'a, M: Media>(
    ntfs: &'a Ntfs<M>,
    mut options: Options<'a>,
) -> Result<Outcome, String> {
    let (options_limit, options_every) = (options.limit, options.progress_every);
    let space = options.space.clone();
    let fresh = |progress: ProgressFn<'a>, planning: bool, known: HashMap<JobKey, JobOutcome>| {
        let mut walker = new_walker(
            ntfs,
            progress,
            planning,
            options_limit,
            options_every,
            space.as_ref(),
        );
        walker.known = known;
        walker
    };
    let started = Instant::now();
    let mut rerun_reason = None;
    if options.threads > 1 {
        let before = top_level_entries(&options.extract_dir);
        let progress = std::mem::replace(&mut options.progress, Box::new(|_| Ok(())));
        let mut planner = fresh(progress, true, HashMap::new());
        walk_all(&mut planner, ntfs, &options)?;
        let jobs = planner.plan.take().unwrap_or_default();
        let walk_seconds = started.elapsed().as_secs_f64();
        let copying = Instant::now();
        let outcomes = execute(
            ntfs,
            &jobs,
            options.threads,
            &planner.stats,
            &mut planner.progress,
            space.as_ref(),
        )?;
        if outcomes.iter().all(|o| matches!(o, JobOutcome::Copied(_))) {
            planner.stats.bytes = outcomes
                .iter()
                .map(|o| if let JobOutcome::Copied(n) = o { *n } else { 0 })
                .sum();
            planner.plan = None;
            planner.flush_progress().map_err(fatal_message)?;
            return Ok(Outcome {
                stats: planner.stats,
                walk_seconds,
                copy_seconds: copying.elapsed().as_secs_f64(),
                rerun_reason: None,
            });
        }
        let mut known: HashMap<JobKey, JobOutcome> = HashMap::with_capacity(jobs.len());
        for (job, outcome) in jobs.iter().zip(&outcomes) {
            known.insert(job.key().clone(), *outcome);
        }
        let unique = known.len() == jobs.len();
        let progress = std::mem::replace(&mut planner.progress, Box::new(|_| Ok(())));
        let mut replay = fresh(progress, true, known);
        let replayed = if unique {
            walk_all(&mut replay, ntfs, &options)
        } else {
            Err("duplicate job keys".into())
        };
        let same_plan = replayed.is_ok()
            && replay.plan.as_ref().is_some_and(|again| {
                again.len() == jobs.len()
                    && again.iter().zip(&jobs).all(|(a, b)| a.key() == b.key())
            });
        if same_plan {
            replay.plan = None;
            replay.flush_progress().map_err(fatal_message)?;
            return Ok(Outcome {
                stats: replay.stats,
                walk_seconds,
                copy_seconds: copying.elapsed().as_secs_f64(),
                rerun_reason: None,
            });
        }
        rerun_reason = Some(match replayed {
            Err(message) => message,
            Ok(()) => "a failed copy changed the walk's later decisions".to_string(),
        });
        discard_new_entries(&options.extract_dir, &before);
        options.progress = replay.progress;
    }
    let sequential = Instant::now();
    let progress = std::mem::replace(&mut options.progress, Box::new(|_| Ok(())));
    let mut walker = fresh(progress, false, HashMap::new());
    walk_all(&mut walker, ntfs, &options)?;
    walker.flush_progress().map_err(fatal_message)?;
    Ok(Outcome {
        stats: walker.stats,
        walk_seconds: sequential.elapsed().as_secs_f64(),
        copy_seconds: 0.0,
        rerun_reason,
    })
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
