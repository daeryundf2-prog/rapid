// PyO3 0.22's `#[pyfunction]` expansion converts `PyErr` into itself (clippy::useless_conversion).
#![allow(clippy::useless_conversion)]

use std::fs::File;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

use crate::ewf::EwfImage;
use crate::extract::{catch_panic, extract, Options, Outcome, SpaceReserve, Stats};
use crate::ntfs::{Media, Ntfs, Res, Volume};

/// A Python object with `seek(offset)` / `read(n)` (a pyewf handle or `RawMediaHandle`). Calls
/// are serialised: pyewf releases the GIL inside `read`, and one libewf handle must not see
/// interleaved seek/read pairs from copy workers.
struct PyMedia {
    handle: Py<PyAny>,
    lock: Mutex<()>,
}

impl Media for PyMedia {
    fn read_at(&self, offset: u64, len: usize) -> Res<Vec<u8>> {
        let _serial = self
            .lock
            .lock()
            .map_err(|_| "media lock poisoned".to_string())?;
        Python::with_gil(|py| {
            let handle = self.handle.bind(py);
            handle
                .call_method1("seek", (offset,))
                .map_err(|e| e.to_string())?;
            let data = handle
                .call_method1("read", (len,))
                .map_err(|e| e.to_string())?;
            let bytes = data.downcast::<PyBytes>().map_err(|e| e.to_string())?;
            Ok(bytes.as_bytes().to_vec())
        })
    }
}

fn pread(file: &File, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.read_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        file.seek_read(buf, offset)
    }
}

/// Media reads served in Rust when the container is understood, else by the Python handle.
enum Source {
    Ewf(EwfImage),
    Raw(File, u64),
    Python,
}

struct AnyMedia {
    source: Source,
    python: PyMedia,
    python_reads: AtomicU64,
}

impl AnyMedia {
    fn label(&self) -> &'static str {
        match self.source {
            Source::Ewf(_) => "rust-ewf",
            Source::Raw(..) => "raw-file",
            Source::Python => "python-handle",
        }
    }
}

impl Media for AnyMedia {
    fn read_at(&self, offset: u64, len: usize) -> Res<Vec<u8>> {
        let served = match &self.source {
            Source::Ewf(image) => image.read_at(offset, len).ok(),
            Source::Raw(file, size) => {
                let want = (len as u64).min(size.saturating_sub(offset)) as usize;
                let mut buf = vec![0u8; want];
                let mut done = 0;
                let mut ok = true;
                while done < want {
                    match pread(file, offset + done as u64, &mut buf[done..]) {
                        Ok(0) => break,
                        Ok(n) => done += n,
                        Err(_) => {
                            ok = false;
                            break;
                        }
                    }
                }
                buf.truncate(done);
                ok.then_some(buf)
            }
            Source::Python => None,
        };
        match served {
            Some(data) => Ok(data),
            None => {
                self.python_reads.fetch_add(1, Ordering::Relaxed);
                self.python.read_at(offset, len)
            }
        }
    }
}

fn pick_source(segments: &[PathBuf], media_size: u64, reader: &str, threads: usize) -> Source {
    if reader == "python" || segments.is_empty() {
        return Source::Python;
    }
    if let Ok(image) = EwfImage::open(segments, threads) {
        if image.media_size() == media_size {
            return Source::Ewf(image);
        }
        return Source::Python;
    }
    if let [path] = segments {
        if let Ok(file) = File::open(path) {
            let mut magic = [0u8; 3];
            let is_ewf = pread(&file, 0, &mut magic)
                .map(|n| n == 3 && &magic == b"EVF")
                .unwrap_or(true);
            if !is_ewf
                && file
                    .metadata()
                    .map(|m| m.len() == media_size)
                    .unwrap_or(false)
            {
                return Source::Raw(file, media_size);
            }
        }
    }
    Source::Python
}

fn stats_dict<'py>(py: Python<'py>, stats: &Stats) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new_bound(py);
    for (key, value) in stats.pairs() {
        dict.set_item(key, i64::try_from(value).unwrap_or(i64::MAX))?;
    }
    Ok(dict)
}

/// Run the priority pass, the tree walk and (optionally) the deleted sweep on the NTFS volume at
/// `base` (`size` bytes) of the media, writing under `extract_dir`. Media bytes come from the Rust
/// EWF reader (or the raw file) when `segments` are understood and `reader` is not "python", else
/// from `handle`; any read the Rust reader cannot serve goes to `handle`. Returns
/// `{"stats": <extract_e01_native stats>, "media_reader": str, "python_reads": int,
/// "walk_seconds": float, "copy_seconds": float, "sequential_rerun": bool}`.
/// `free_at_start` / `min_free_bytes` / `free_space` (a callable returning the output drive's free
/// bytes, negative when unreadable) are `ExtractSpaceGuard`'s start value, reserve and probe; a
/// negative `free_at_start` or no `free_space` leaves the run unguarded. Raises a `RuntimeError`
/// starting with `free-space-reserve` when the reserve would be reached.
#[pyfunction]
#[pyo3(signature = (handle, base, size, extract_dir, limit, include_deleted, priority_paths, progress=None, progress_every=256, segments=Vec::new(), media_size=0, threads=1, reader="auto", free_at_start=-1, min_free_bytes=0, free_space=None))]
#[allow(clippy::too_many_arguments)]
fn extract_tree(
    py: Python<'_>,
    handle: Py<PyAny>,
    base: u64,
    size: u64,
    extract_dir: PathBuf,
    limit: i64,
    include_deleted: bool,
    priority_paths: Vec<String>,
    progress: Option<Py<PyAny>>,
    progress_every: u64,
    segments: Vec<PathBuf>,
    media_size: u64,
    threads: usize,
    reader: &str,
    free_at_start: i64,
    min_free_bytes: i64,
    free_space: Option<Py<PyAny>>,
) -> PyResult<Py<PyDict>> {
    let reader = reader.to_string();
    let space = free_space.map(|probe| SpaceReserve {
        free_at_start: free_at_start.into(),
        min_free: min_free_bytes.into(),
        probe: Arc::new(move || {
            Python::with_gil(|py| {
                probe
                    .call0(py)
                    .and_then(|free| free.extract::<i64>(py))
                    .map_or(-1, i128::from)
            })
        }),
    });
    let outcome = py.allow_threads(move || {
        catch_panic(move || {
            let media = AnyMedia {
                source: pick_source(&segments, media_size, &reader, threads),
                python: PyMedia {
                    handle,
                    lock: Mutex::new(()),
                },
                python_reads: AtomicU64::new(0),
            };
            let ntfs = Ntfs::open(Volume::new(media, base, size))?;
            let callback = move |stats: &Stats| -> Result<(), String> {
                let Some(progress) = progress.as_ref() else {
                    return Ok(());
                };
                Python::with_gil(|py| {
                    let dict = stats_dict(py, stats).map_err(|e| e.to_string())?;
                    progress
                        .call1(py, (dict,))
                        .map(|_| ())
                        .map_err(|e| e.to_string())
                })
            };
            let outcome = extract(
                &ntfs,
                Options {
                    extract_dir,
                    limit: limit as i128,
                    include_deleted,
                    priority_paths,
                    progress: Box::new(callback),
                    progress_every,
                    threads,
                    space,
                },
            )?;
            let vol = ntfs.vol.borrow();
            let media = vol.media();
            Ok::<_, String>((
                outcome,
                media.label(),
                media.python_reads.load(Ordering::Relaxed),
            ))
        })
    });
    match outcome {
        Ok((
            Outcome {
                stats,
                walk_seconds,
                copy_seconds,
                rerun_reason,
            },
            label,
            python_reads,
        )) => {
            let dict = PyDict::new_bound(py);
            dict.set_item("stats", stats_dict(py, &stats)?)?;
            dict.set_item("walk_seconds", walk_seconds)?;
            dict.set_item("copy_seconds", copy_seconds)?;
            dict.set_item("rerun_reason", rerun_reason)?;
            dict.set_item("media_reader", label)?;
            dict.set_item("python_reads", python_reads)?;
            Ok(dict.unbind())
        }
        Err(message) => Err(PyRuntimeError::new_err(message)),
    }
}

/// Read `length` media bytes at `offset` with the Rust EWF reader (tests compare it with pyewf;
/// `threads` > 1 decodes the chunks of one read in parallel).
#[pyfunction]
#[pyo3(signature = (segments, offset, length, threads=1))]
fn ewf_read(
    py: Python<'_>,
    segments: Vec<PathBuf>,
    offset: u64,
    length: usize,
    threads: usize,
) -> PyResult<Py<PyBytes>> {
    let data = py
        .allow_threads(|| {
            catch_panic(|| {
                EwfImage::open(&segments, threads).and_then(|image| image.read_at(offset, length))
            })
        })
        .map_err(PyRuntimeError::new_err)?;
    Ok(PyBytes::new_bound(py, &data).unbind())
}

/// Crate version; rapidtriage.core.e01_extract_engine refuses a build whose version differs from
/// E01_EXTRACT_NATIVE_VERSION (a stale extension left in rapidtriage/native).
#[pyfunction]
fn engine_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[pymodule]
fn rapid_extract_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("ABI_VERSION", crate::ABI_VERSION)?;
    m.add_function(wrap_pyfunction!(engine_version, m)?)?;
    m.add_function(wrap_pyfunction!(extract_tree, m)?)?;
    m.add_function(wrap_pyfunction!(ewf_read, m)?)?;
    Ok(())
}
