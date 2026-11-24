// PyO3 bindings for rapidcore — the `rapidcore_native` extension module (R4-1).
// Build with `--features python`; the produced cdylib is renamed to
// rapidcore_native.pyd/.so for import from rapidtriage.core.native_accel.
// pyo3 0.22's `#[pyfunction]` expansion trips clippy's useless_conversion on
// every `PyResult` return; the lint is about generated code, not ours.
#![allow(clippy::useless_conversion)]

use crate::evtx;
use crate::evtx_binxml::{self, ChunkDecoder, DecodeError, DecodedRecord, Raw};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyString, PyTuple};
use pyo3::{intern, IntoPy};
use std::borrow::Cow;
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

/// Python decoder version this native decoder reproduces.
#[pyfunction]
fn evtx_decoder_version() -> &'static str {
    evtx_binxml::DECODER_VERSION
}

fn raw_to_py(py: Python<'_>, raw: &Raw) -> PyObject {
    match raw {
        // `Text` never reaches system_raw (extraction stores the owned string).
        Raw::None | Raw::Nested(_) | Raw::Text => py.None(),
        Raw::Int(number) => number.into_py(py),
        Raw::UInt(number) => number.into_py(py),
        Raw::Float(number) => number.into_py(py),
        Raw::Bool(flag) => flag.into_py(py),
        Raw::Str(text) => text.into_py(py),
        Raw::List(items) => PyList::new_bound(py, items).into_any().unbind(),
    }
}

/// Known value-type names (`Cow::Borrowed`) are interned; built names are not.
#[allow(clippy::ptr_arg)] // the Borrowed/Owned distinction is the point
fn type_name_to_py<'py>(py: Python<'py>, name: &Cow<'static, str>) -> Bound<'py, PyString> {
    match name {
        Cow::Borrowed(text) => PyString::intern_bound(py, text),
        Cow::Owned(text) => PyString::new_bound(py, text),
    }
}

fn decoded_to_py<'py>(py: Python<'py>, decoded: &DecodedRecord) -> PyResult<Bound<'py, PyDict>> {
    let system_fields = PyDict::new_bound(py);
    for (key, text) in &decoded.system_fields {
        system_fields.set_item(*key, text)?;
    }
    let system_raw = PyDict::new_bound(py);
    for (key, raw) in &decoded.system_raw {
        system_raw.set_item(*key, raw_to_py(py, raw))?;
    }
    // `event_data` (name -> value) and the sequence share the same str objects.
    let event_data = PyDict::new_bound(py);
    let sequence = PyList::empty_bound(py);
    for (index, item) in decoded.event_data_sequence.iter().enumerate() {
        let name = PyString::new_bound(py, &item.name);
        let text = PyString::new_bound(py, &item.value);
        event_data.set_item(&name, &text)?;
        let entry = PyDict::new_bound(py);
        entry.set_item(intern!(py, "index"), index)?;
        entry.set_item(intern!(py, "name"), name)?;
        entry.set_item(intern!(py, "value"), text)?;
        entry.set_item(intern!(py, "path"), &item.path)?;
        entry.set_item(
            intern!(py, "section"),
            PyString::intern_bound(py, item.section),
        )?;
        entry.set_item(
            intern!(py, "value_type"),
            type_name_to_py(py, &item.value_type),
        )?;
        entry.set_item(
            intern!(py, "confidence"),
            intern!(py, "binxml-template-decoded"),
        )?;
        sequence.append(entry)?;
    }
    let out = PyDict::new_bound(py);
    out.set_item(intern!(py, "system_fields"), system_fields)?;
    out.set_item(intern!(py, "system_raw"), system_raw)?;
    out.set_item(intern!(py, "event_data"), event_data)?;
    out.set_item(intern!(py, "event_data_sequence"), sequence)?;
    out.set_item(intern!(py, "event_data_source"), decoded.event_data_source)?;
    out.set_item(intern!(py, "root_name"), &decoded.root_name)?;
    out.set_item(intern!(py, "template_offsets"), &decoded.template_offsets)?;
    out.set_item(
        intern!(py, "substitution_count"),
        decoded.substitution_count,
    )?;
    if let Some(xml) = &decoded.rendered_xml {
        out.set_item(intern!(py, "rendered_xml"), xml)?;
    }
    Ok(out)
}

/// Native counterpart of the Python `EvtxChunkDecoder` (one 64 KiB chunk).
///
/// `decode_record` returns `(status, payload)`: 0 = decoded dict,
/// 1 = `EvtxDecodeError` message, 2 = `IndexError` message,
/// 3 = unsupported here (reason) — decode the chunk with Python instead.
#[pyclass(unsendable, module = "rapidcore_native")]
struct EvtxChunkDecoder {
    inner: ChunkDecoder,
    render_xml: bool,
}

#[pymethods]
impl EvtxChunkDecoder {
    #[new]
    #[pyo3(signature = (chunk, render_xml = true))]
    fn new(chunk: &[u8], render_xml: bool) -> Self {
        Self {
            inner: ChunkDecoder::new(chunk.to_vec()),
            render_xml,
        }
    }

    #[getter]
    fn template_parse_count(&self) -> u64 {
        self.inner.template_parse_count
    }

    fn decode_record(
        &mut self,
        py: Python<'_>,
        record_offset: i64,
        record_size: i64,
    ) -> PyResult<(u8, PyObject)> {
        Ok(
            match self
                .inner
                .decode_record(record_offset, record_size, self.render_xml)
            {
                Ok(decoded) => (0, decoded_to_py(py, &decoded)?.into_any().unbind()),
                Err(DecodeError::Decode(message)) => (1, message.into_py(py)),
                Err(DecodeError::Index(message)) => (2, message.into_py(py)),
                Err(DecodeError::Unsupported(reason)) => (3, reason.into_py(py)),
            },
        )
    }
}
/// Nesting below this is handed to the Python walker (`redact_tree`).
const REDACT_MAX_DEPTH: u32 = 200;
/// `redact_recovery_passwords` only scans strings this long (code points).
const RECOVERY_PASSWORD_MIN_CHARS: usize = 48;

/// Python's `RECOVERY_PASSWORD_LOOSE` (`\d{6}(?:[-\s‐-―−]?\d{6}){7}`) matches 48
/// digits with at most one separator between them. This scan counts digits
/// (`char::is_numeric`, a superset of `\d`) over runs where every non-digit is a
/// single character between digits and is not a letter (a superset of the
/// separator class), so it never skips a string the regex could match.
fn may_hold_recovery_password(text: &Bound<'_, PyString>) -> bool {
    let Ok(value) = text.to_str() else {
        // Lone surrogates: let Python decide.
        return true;
    };
    let mut digits = 0usize;
    let mut after_digit = false;
    for character in value.chars() {
        if character.is_numeric() {
            digits += 1;
            if digits >= RECOVERY_PASSWORD_MIN_CHARS {
                return true;
            }
            after_digit = true;
        } else if character.is_alphabetic() || !after_digit {
            digits = 0;
            after_digit = false;
        } else {
            after_digit = false;
        }
    }
    false
}

/// `None` when `value` is unchanged (the caller keeps the same object).
fn redact_walk(
    value: &Bound<'_, PyAny>,
    redact_text: &Bound<'_, PyAny>,
    redact_tree: &Bound<'_, PyAny>,
    depth: u32,
) -> PyResult<Option<PyObject>> {
    let py = value.py();
    let replaced = |out: Bound<'_, PyAny>| -> Option<PyObject> {
        if out.is(value) {
            None
        } else {
            Some(out.unbind())
        }
    };
    if let Ok(text) = value.downcast::<PyString>() {
        if text.len()? >= RECOVERY_PASSWORD_MIN_CHARS && may_hold_recovery_password(text) {
            return Ok(replaced(redact_text.call1((text,))?));
        }
        return Ok(None);
    }
    let container = value.is_instance_of::<PyDict>()
        || value.is_instance_of::<PyList>()
        || value.is_instance_of::<PyTuple>();
    if !container {
        return Ok(None);
    }
    if depth >= REDACT_MAX_DEPTH {
        return Ok(replaced(redact_tree.call1((value,))?));
    }
    if let Ok(dict) = value.downcast::<PyDict>() {
        // Copy only once something changed (most rows hold no recovery password).
        let mut out: Option<Bound<'_, PyDict>> = None;
        for (index, (key, item)) in dict.iter().enumerate() {
            let new = redact_walk(&item, redact_text, redact_tree, depth + 1)?;
            if let Some(fresh) = &out {
                fresh.set_item(key, new.unwrap_or_else(|| item.unbind()))?;
            } else if let Some(new) = new {
                let fresh = PyDict::new_bound(py);
                for (old_key, old_item) in dict.iter().take(index) {
                    fresh.set_item(old_key, old_item)?;
                }
                fresh.set_item(key, new)?;
                out = Some(fresh);
            }
        }
        return Ok(out.map(|fresh| fresh.into_any().unbind()));
    }
    let items: Vec<Bound<'_, PyAny>> = if let Ok(list) = value.downcast::<PyList>() {
        list.iter().collect()
    } else {
        value.downcast::<PyTuple>()?.iter().collect()
    };
    let mut out: Option<Vec<PyObject>> = None;
    for (index, item) in items.iter().enumerate() {
        let new = redact_walk(item, redact_text, redact_tree, depth + 1)?;
        if let Some(fresh) = &mut out {
            fresh.push(new.unwrap_or_else(|| item.clone().unbind()));
        } else if let Some(new) = new {
            let mut fresh: Vec<PyObject> = items[..index]
                .iter()
                .map(|old| old.clone().unbind())
                .collect();
            fresh.push(new);
            out = Some(fresh);
        }
    }
    let Some(fresh) = out else {
        return Ok(None);
    };
    Ok(Some(if value.is_instance_of::<PyList>() {
        PyList::new_bound(py, fresh).into_any().unbind()
    } else {
        PyTuple::new_bound(py, fresh).into_any().unbind()
    }))
}

/// Native walk of `antiforensics.redact_recovery_passwords_in`: same result and
/// the same object back when nothing changed. Every string that could hold a
/// recovery password is passed to `redact_text` (the Python
/// `redact_recovery_passwords`), so masking stays the Python implementation's.
#[pyfunction]
fn redact_recovery_passwords_in(
    value: &Bound<'_, PyAny>,
    redact_text: &Bound<'_, PyAny>,
    redact_tree: &Bound<'_, PyAny>,
) -> PyResult<PyObject> {
    Ok(redact_walk(value, redact_text, redact_tree, 0)?.unwrap_or_else(|| value.clone().unbind()))
}

#[pymodule]
fn rapidcore_native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(scan_evtx, module)?)?;
    module.add_function(wrap_pyfunction!(engine_version, module)?)?;
    module.add_function(wrap_pyfunction!(evtx_decoder_version, module)?)?;
    module.add_function(wrap_pyfunction!(redact_recovery_passwords_in, module)?)?;
    module.add_class::<EvtxChunkDecoder>()?;
    Ok(())
}
