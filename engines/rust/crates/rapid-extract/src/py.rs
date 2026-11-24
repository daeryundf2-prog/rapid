// PyO3 0.22's `#[pyfunction]` expansion converts `PyErr` into itself (clippy::useless_conversion).
#![allow(clippy::useless_conversion)]

use std::path::PathBuf;

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

use crate::extract::{extract, Options, Stats};
use crate::ntfs::{Media, Ntfs, Res, Volume};

/// A Python object with `seek(offset)` / `read(n)` (a pyewf handle or `RawMediaHandle`).
struct PyMedia {
    handle: Py<PyAny>,
}

impl Media for PyMedia {
    fn read_at(&mut self, offset: u64, len: usize) -> Res<Vec<u8>> {
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

fn stats_dict<'py>(py: Python<'py>, stats: &Stats) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new_bound(py);
    for (key, value) in stats.pairs() {
        dict.set_item(key, i64::try_from(value).unwrap_or(i64::MAX))?;
    }
    Ok(dict)
}

/// Run the priority pass, the tree walk and (optionally) the deleted sweep on the NTFS volume at
/// `base` (`size` bytes) of `handle`, writing under `extract_dir`. Returns the stats dict of
/// `extract_e01_native`; `progress(stats)` is called every `progress_every` recovered entries.
#[pyfunction]
#[pyo3(signature = (handle, base, size, extract_dir, limit, include_deleted, priority_paths, progress=None, progress_every=256))]
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
) -> PyResult<Py<PyDict>> {
    let outcome = py.allow_threads(move || {
        let ntfs = Ntfs::open(Volume::new(PyMedia { handle }, base, size))?;
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
        extract(
            &ntfs,
            Options {
                extract_dir,
                limit: limit as i128,
                include_deleted,
                priority_paths,
                progress: Box::new(callback),
                progress_every,
            },
        )
    });
    match outcome {
        Ok(stats) => Ok(stats_dict(py, &stats)?.unbind()),
        Err(message) => Err(PyRuntimeError::new_err(message)),
    }
}

#[pymodule]
fn rapid_extract_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("ABI_VERSION", crate::ABI_VERSION)?;
    m.add_function(wrap_pyfunction!(extract_tree, m)?)?;
    Ok(())
}
