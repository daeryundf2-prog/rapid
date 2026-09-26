// PyO3 bindings for rapidcore — the `rapidcore_native` extension module (R4-1).
// Build with `--features python`; the produced cdylib is renamed to
// rapidcore_native.pyd/.so for import from rapidtriage.core.native_accel.

use crate::evtx;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use std::path::Path;

/// Scan an EVTX file's chunk/record headers. Returns a JSON string matching
/// the EvtxScanResult shape consumed by rapidtriage.core.native_accel.
#[pyfunction]
#[pyo3(signature = (path, max_records = 100_000))]
fn scan_evtx(path: &str, max_records: usize) -> PyResult<String> {
    let result = evtx::scan_evtx(Path::new(path), max_records).map_err(PyValueError::new_err)?;
    serde_json::to_string(&result).map_err(|err| PyValueError::new_err(err.to_string()))
}

/// Extension identity for engine reporting.
#[pyfunction]
fn engine_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[pymodule]
fn rapidcore_native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(scan_evtx, module)?)?;
    module.add_function(wrap_pyfunction!(engine_version, module)?)?;
    Ok(())
}
