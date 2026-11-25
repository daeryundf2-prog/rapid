// PyO3 bindings: the `rapid_ntfs_native` extension module. Build with
// `--features python`; scripts/build-rapid-ntfs.py stages the cdylib where
// rapidtriage.core.ntfs_native imports it.
// pyo3 0.22's #[pyfunction] expansion trips clippy::useless_conversion on
// `PyResult` returns (fixed upstream in pyo3 0.23).
#![allow(clippy::useless_conversion)]

use std::collections::HashMap;

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyString};

use crate::value::Value;
use crate::{mft, usn};

struct Converter<'py> {
    py: Python<'py>,
    keys: HashMap<&'static str, Bound<'py, PyString>>,
}

impl<'py> Converter<'py> {
    fn new(py: Python<'py>) -> Self {
        Self {
            py,
            keys: HashMap::new(),
        }
    }

    fn key(&mut self, key: &'static str) -> Bound<'py, PyString> {
        let py = self.py;
        self.keys
            .entry(key)
            .or_insert_with(|| PyString::intern_bound(py, key))
            .clone()
    }

    fn convert(&mut self, value: Value) -> PyResult<PyObject> {
        let py = self.py;
        Ok(match value {
            Value::None => py.None(),
            Value::Bool(v) => v.into_py(py),
            Value::Int(v) => match i64::try_from(v) {
                Ok(small) => small.into_py(py),
                Err(_) => v.into_py(py),
            },
            Value::U128(v) => match u64::try_from(v) {
                Ok(small) => small.into_py(py),
                Err(_) => v.into_py(py),
            },
            Value::Float(v) => v.into_py(py),
            Value::Str(v) => v.into_py(py),
            Value::List(items) => {
                let converted = items
                    .into_iter()
                    .map(|item| self.convert(item))
                    .collect::<PyResult<Vec<_>>>()?;
                PyList::new_bound(py, converted).into_any().unbind()
            }
            Value::Dict(items) => {
                let dict = PyDict::new_bound(py);
                for (key, item) in items {
                    let key = self.key(key);
                    dict.set_item(key, self.convert(item)?)?;
                }
                dict.into_any().unbind()
            }
        })
    }
}

/// Rust port of filesystem.parse_mft_record_headers (fields per docs/architecture/rapid-ntfs.md).
#[pyfunction]
fn parse_mft_record_headers(py: Python<'_>, blob: &[u8]) -> PyResult<PyObject> {
    let records = py.allow_threads(|| mft::parse_mft_record_headers(blob));
    Converter::new(py).convert(Value::List(records))
}

/// Rust port of filesystem.parse_usn_record_scan (fields per docs/architecture/rapid-ntfs.md).
#[pyfunction]
#[pyo3(signature = (blob, *, record_limit = usn::USN_RECORD_SCAN_LIMIT, start_offset = 0, max_scan_bytes = None))]
fn parse_usn_record_scan(
    py: Python<'_>,
    blob: &[u8],
    record_limit: i64,
    start_offset: i64,
    max_scan_bytes: Option<i64>,
) -> PyResult<PyObject> {
    let scan = py.allow_threads(|| {
        usn::parse_usn_record_scan(blob, record_limit, start_offset, max_scan_bytes)
    });
    Converter::new(py).convert(scan)
}

#[pyfunction]
fn mft_volume_record_size(blob: &[u8]) -> Option<usize> {
    mft::mft_volume_record_size(blob)
}

#[pyfunction]
fn engine_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[pymodule]
fn rapid_ntfs_native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(parse_mft_record_headers, module)?)?;
    module.add_function(wrap_pyfunction!(parse_usn_record_scan, module)?)?;
    module.add_function(wrap_pyfunction!(mft_volume_record_size, module)?)?;
    module.add_function(wrap_pyfunction!(engine_version, module)?)?;
    Ok(())
}
