// Triage projection of eventlog event rows for the opt-in EVTX engine:
// `rapidtriage.artifacts.windows.eventlog.triage_eventlog_details` in Rust.
// `project` returns the dict the Python function returns (same keys, order,
// values and types) or `None` when Python must run: any value the port cannot
// reproduce exactly (Mapping/str/list subclasses, other custom objects in
// containers it inspects, lone surrogates in text it filters) or any error.
#![allow(clippy::useless_conversion)]

use crate::py_json::{encode_json, JsonStyle};
use crate::py_rows::{kind, rich_eq, Fallback, Kernel, Kind};
use pyo3::ffi;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyString, PyTuple};
use std::collections::HashSet;

/// `json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)`.
const EVENT_DATA_JSON: JsonStyle<'static> = JsonStyle {
    item_separator: ", ",
    key_separator: ": ",
    sort_keys: true,
};

/// C0 controls removed from triage text (`_TRIAGE_CONTROL_CHARS_RE`): keeps TAB, LF, CR.
fn is_removed_control(byte: u8) -> bool {
    matches!(byte, 0x00..=0x08 | 0x0b | 0x0c | 0x0e..=0x1f | 0x7f)
}

/// `str(value or "")`.
fn text_or_empty<'py>(py: Python<'py>, value: Option<Bound<'py, PyAny>>) -> Kernel<Bound<'py, PyString>> {
    text_or(py, value, "")
}

/// `str(value or default)`.
fn text_or<'py>(py: Python<'py>, value: Option<Bound<'py, PyAny>>, default: &str) -> Kernel<Bound<'py, PyString>> {
    match value {
        Some(value) if value.is_truthy()? => {
            if kind(&value) == Kind::Str {
                value.downcast_into::<PyString>().map_err(|_| Fallback)
            } else {
                Ok(value.str()?)
            }
        }
        _ => Ok(PyString::new_bound(py, default)),
    }
}

/// Code-point length of a `str`.
fn str_len(text: &Bound<'_, PyString>) -> Kernel<usize> {
    Ok(text.len()?)
}

/// `text[:limit]` (code points).
fn str_prefix<'py>(text: &Bound<'py, PyString>, limit: usize) -> Kernel<Bound<'py, PyString>> {
    let end = ffi::Py_ssize_t::try_from(limit).map_err(|_| Fallback)?;
    // SAFETY: `text` is a live `str`; PyUnicode_Substring returns a new reference or NULL with an exception set.
    let slice = unsafe { Bound::from_owned_ptr_or_err(text.py(), ffi::PyUnicode_Substring(text.as_ptr(), 0, end))? };
    slice.downcast_into::<PyString>().map_err(|_| Fallback)
}

/// `_bounded_text(value, limit)` on `text = str(value or "")`.
fn bounded_text<'py>(text: Bound<'py, PyString>, limit: usize) -> Kernel<(Bound<'py, PyString>, bool)> {
    let raw = text.to_str()?;
    let text = if raw.bytes().any(is_removed_control) {
        let kept: String = raw.chars().filter(|character| !(character.is_ascii() && is_removed_control(*character as u8))).collect();
        PyString::new_bound(text.py(), &kept)
    } else {
        text
    };
    if str_len(&text)? <= limit {
        return Ok((text, false));
    }
    Ok((str_prefix(&text, limit)?, true))
}

/// `value not in (None, "", [], {})` is False for these values.
fn is_empty_pivot(value: &Bound<'_, PyAny>) -> Kernel<bool> {
    Ok(match kind(value) {
        Kind::None => true,
        Kind::Str | Kind::List | Kind::Dict => value.len()? == 0,
        Kind::Int | Kind::Bool | Kind::Float | Kind::Tuple => false,
        Kind::Other => return Err(Fallback),
    })
}

/// `value if isinstance(value, Mapping) else None` (an empty dict stands in for `{}`).
fn as_mapping<'py>(value: Option<Bound<'py, PyAny>>) -> Kernel<Option<Bound<'py, PyDict>>> {
    match value {
        None => Ok(None),
        Some(value) => match kind(&value) {
            Kind::Dict => Ok(Some(value.downcast_into::<PyDict>().map_err(|_| Fallback)?)),
            Kind::Other => Err(Fallback),
            _ => Ok(None),
        },
    }
}

fn mapping_get<'py>(mapping: &Option<Bound<'py, PyDict>>, key: &str) -> Kernel<Option<Bound<'py, PyAny>>> {
    match mapping {
        Some(mapping) => Ok(mapping.get_item(key)?),
        None => Ok(None),
    }
}

/// Items of `value or []` for a list/tuple; other truthy values go to Python.
fn sequence_items<'py>(value: Option<Bound<'py, PyAny>>) -> Kernel<Vec<Bound<'py, PyAny>>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if !value.is_truthy()? {
        return Ok(Vec::new());
    }
    match kind(&value) {
        Kind::List => Ok(value.downcast::<PyList>()?.iter().collect()),
        Kind::Tuple => Ok(value.downcast::<PyTuple>()?.iter().collect()),
        _ => Err(Fallback),
    }
}

/// `slim[key] = items` then `cap_list_field(slim, key, limit)`: the list keeps
/// its position, the markers follow it.
fn cap_list(slim: &Bound<'_, PyDict>, key: &str, items: Vec<Bound<'_, PyAny>>, limit: usize) -> Kernel<()> {
    let py = slim.py();
    let total = items.len();
    slim.set_item(key, PyList::new_bound(py, &items[..total.min(limit)]))?;
    if total > limit {
        slim.set_item(format!("{key}_total"), total)?;
        slim.set_item(format!("{key}_truncated"), true)?;
    }
    Ok(())
}

#[pyclass(frozen, module = "rapidcore_native")]
struct EventlogTriageProjector {
    identity_keys: Vec<Py<PyString>>,
    pivot_keys: Vec<Py<PyString>>,
    payload_pivot_keys: HashSet<String>,
    payload_event_data_keys: HashSet<String>,
    text_max_chars: usize,
    payload_max_chars: usize,
    event_data_max_items: usize,
    string_max_items: usize,
    string_max_chars: usize,
    file_header_size: i64,
    chunk_size: i64,
    native_parser: Py<PyString>,
    record_projection: Py<PyDict>,
    int_text: PyObject,
    str_type: PyObject,
}

impl EventlogTriageProjector {
    fn project_kernel<'py>(&self, details: &Bound<'py, PyAny>) -> Kernel<Bound<'py, PyDict>> {
        let py = details.py();
        if kind(details) != Kind::Dict {
            return Err(Fallback);
        }
        let details = details.downcast::<PyDict>()?;
        let slim = PyDict::new_bound(py);
        for key in &self.identity_keys {
            if let Some(value) = details.get_item(key.bind(py))? {
                slim.set_item(key.bind(py), value)?;
            }
        }
        for key in &self.pivot_keys {
            if let Some(value) = details.get_item(key.bind(py))? {
                if !is_empty_pivot(&value)? {
                    slim.set_item(key.bind(py), value)?;
                }
            }
        }
        let kept: Vec<(Bound<'py, PyAny>, Bound<'py, PyAny>)> = slim.iter().collect();
        for (key, value) in kept {
            match kind(&value) {
                Kind::Str => {}
                Kind::Other if value.is_instance_of::<PyString>() => return Err(Fallback),
                _ => continue,
            }
            let key_text = key.downcast::<PyString>()?.to_str()?;
            let limit = if self.payload_pivot_keys.contains(key_text) {
                self.payload_max_chars
            } else {
                self.text_max_chars
            };
            let text = value.downcast::<PyString>()?;
            if str_len(text)? > limit {
                slim.set_item(&key, str_prefix(text, limit)?)?;
                slim.set_item(format!("{key_text}_truncated"), true)?;
            }
        }
        let raw_preview = text_or_empty(py, details.get_item("raw_preview")?)?;
        let command_line = text_or_empty(py, details.get_item("command_line")?)?;
        if str_len(&command_line)? > 0 && !rich_eq(&command_line, &raw_preview)? {
            let (text, cut) = bounded_text(command_line, self.payload_max_chars)?;
            slim.set_item("command_line", text)?;
            if cut {
                slim.set_item("command_line_truncated", true)?;
            }
        }
        if let Some(rule) = as_mapping(details.get_item("rule")?)? {
            let titled = match rule.get_item("title")? {
                Some(title) if title.is_truthy()? => true,
                _ => matches!(rule.get_item("id")?, Some(id) if id.is_truthy()?),
            };
            if titled {
                slim.set_item("rule", rule.copy()?)?;
            }
        }
        let (message, cut) = bounded_text(text_or_empty(py, details.get_item("event_message")?)?, self.text_max_chars)?;
        if str_len(&message)? > 0 {
            slim.set_item("event_message", message)?;
            if cut {
                slim.set_item("event_message_truncated", true)?;
            }
        }
        if let Some(items) = details.get_item("event_data_items")? {
            match kind(&items) {
                Kind::List if !items.downcast::<PyList>()?.is_empty() => {
                    let mut projected = Vec::new();
                    for item in items.downcast::<PyList>()?.iter() {
                        let Some(item) = as_mapping(Some(item))? else {
                            continue;
                        };
                        let entry = PyDict::new_bound(py);
                        entry.set_item("name", text_or_empty(py, item.get_item("name")?)?)?;
                        let (value, _) = bounded_text(text_or_empty(py, item.get_item("value")?)?, self.text_max_chars)?;
                        entry.set_item("value", value)?;
                        projected.push(entry.into_any());
                    }
                    cap_list(&slim, "event_data_items", projected, self.event_data_max_items)?;
                }
                Kind::Other if items.is_instance_of::<PyList>() => return Err(Fallback),
                _ => {}
            }
        }
        let is_native = match details.get_item("parser")? {
            Some(parser) => parser.eq(self.native_parser.bind(py))?,
            None => false,
        };
        let event_data = as_mapping(details.get_item(if is_native { "binxml_event_data_fields" } else { "data" })?)?;
        match &event_data {
            Some(data) if !data.is_empty() => self.bounded_event_data(&slim, data)?,
            _ if is_native => {
                let binxml = as_mapping(details.get_item("evtx_binxml")?)?;
                let mut values = Vec::new();
                for item in sequence_items(mapping_get(&binxml, "value_fields")?)? {
                    let Some(item) = as_mapping(Some(item))? else {
                        continue;
                    };
                    let path = text_or_empty(py, item.get_item("element_path")?)?;
                    if path.to_str()?.starts_with("Event/System") {
                        continue;
                    }
                    let text = text_or_empty(py, item.get_item("text")?)?;
                    if str_len(&text)? > 0 {
                        values.push(text);
                    }
                }
                if !values.is_empty() {
                    let mut bounded = Vec::with_capacity(values.len());
                    for value in values {
                        bounded.push(bounded_text(value, self.text_max_chars)?.0.into_any());
                    }
                    cap_list(&slim, "event_data_values", bounded, self.event_data_max_items)?;
                } else {
                    let mut strings = Vec::new();
                    for item in sequence_items(details.get_item("extracted_strings")?)? {
                        let text = item.str()?;
                        if str_len(&text)? > 0 {
                            strings.push(bounded_text(text, self.string_max_chars)?.0.into_any());
                        }
                    }
                    if !strings.is_empty() {
                        cap_list(&slim, "extracted_strings", strings, self.string_max_items)?;
                    }
                }
            }
            _ => {}
        }
        if is_native {
            self.native_status(details, &slim)?;
        }
        let projection = PyDict::new_bound(py);
        for (key, value) in self.record_projection.bind(py).iter() {
            if kind(&value) == Kind::List {
                projection.set_item(key, PyList::new_bound(py, value.downcast::<PyList>()?.iter()))?;
            } else {
                projection.set_item(key, value)?;
            }
        }
        slim.set_item("record_projection", projection)?;
        Ok(slim)
    }

    /// `_bounded_event_data(data)` and the `event_data*` keys it sets.
    fn bounded_event_data(&self, slim: &Bound<'_, PyDict>, data: &Bound<'_, PyDict>) -> Kernel<()> {
        let py = slim.py();
        let mut truncated = data.len() > self.event_data_max_items;
        let mut cut_fields: Vec<Bound<'_, PyString>> = Vec::new();
        let bounded = PyDict::new_bound(py);
        let str_type = self.str_type.bind(py);
        for (key, value) in data.iter().take(self.event_data_max_items) {
            let value = match kind(&value) {
                Kind::Dict | Kind::List => {
                    let mut out = String::new();
                    encode_json(&mut out, &value, Some(str_type), &EVENT_DATA_JSON, 0)?;
                    PyString::new_bound(py, &out).into_any()
                }
                Kind::Other => return Err(Fallback),
                _ => value,
            };
            let key_text = key.str()?;
            let value = if kind(&value) == Kind::Str {
                let key_str = key_text.to_str()?;
                let lowered = if key_str.is_ascii() {
                    key_str.to_ascii_lowercase()
                } else {
                    key_text.call_method0("lower")?.downcast::<PyString>()?.to_str()?.to_owned()
                };
                let limit = if self.payload_event_data_keys.contains(&lowered) {
                    self.payload_max_chars
                } else {
                    self.text_max_chars
                };
                let (text, cut) = bounded_text(value.downcast_into::<PyString>().map_err(|_| Fallback)?, limit)?;
                if cut {
                    truncated = true;
                    cut_fields.push(key_text.clone());
                }
                text.into_any()
            } else {
                value
            };
            bounded.set_item(key_text, value)?;
        }
        slim.set_item("event_data", bounded)?;
        if truncated {
            slim.set_item("event_data_truncated", true)?;
        }
        if !cut_fields.is_empty() {
            slim.set_item("event_data_truncated_fields", PyList::new_bound(py, cut_fields))?;
        }
        Ok(())
    }

    /// The native-record status codes and chunk index.
    fn native_status(&self, details: &Bound<'_, PyDict>, slim: &Bound<'_, PyDict>) -> Kernel<()> {
        let py = slim.py();
        let integrity = as_mapping(details.get_item("evtx_record_integrity")?)?;
        let sequence = as_mapping(details.get_item("evtx_record_sequence")?)?;
        let indicators = as_mapping(details.get_item("native_indicators")?)?;
        let chunk_context = as_mapping(details.get_item("evtx_chunk_context")?)?;
        let report_grade = as_mapping(details.get_item("evtx_report_grade_assessment")?)?;
        let chunk_offset: Option<i64> = match mapping_get(&chunk_context, "chunk_offset")? {
            None => None,
            Some(value) => match kind(&value) {
                Kind::None | Kind::Bool => None,
                Kind::Int => {
                    let number: i64 = value.extract().map_err(|_| Fallback)?;
                    (number != 0).then_some(number)
                }
                _ => {
                    let parsed = self.int_text.bind(py).call1((value,))?;
                    if parsed.is_none() {
                        None
                    } else {
                        Some(parsed.extract().map_err(|_| Fallback)?)
                    }
                }
            },
        };
        let trailing_valid = match mapping_get(&integrity, "trailing_size_valid")? {
            Some(value) => value.is_truthy()?,
            None => false,
        };
        slim.set_item(
            "evtx_integrity_status",
            if trailing_valid { "trailing-size-valid" } else { "trailing-size-unverified" },
        )?;
        slim.set_item("evtx_sequence_status", text_or(py, mapping_get(&sequence, "status")?, "unknown")?)?;
        slim.set_item(
            "evtx_channel_hint_source",
            text_or(py, mapping_get(&indicators, "channel_hint_source")?, "unknown")?,
        )?;
        slim.set_item(
            "evtx_chunk_boundary_status",
            text_or(py, mapping_get(&chunk_context, "chunk_boundary_status")?, "unknown")?,
        )?;
        slim.set_item("evtx_report_grade_status", text_or(py, mapping_get(&report_grade, "status")?, "unknown")?)?;
        if let Some(offset) = chunk_offset {
            if offset >= self.file_header_size {
                slim.set_item("evtx_chunk_index", (offset - self.file_header_size) / self.chunk_size)?;
            }
        }
        Ok(())
    }
}

#[pymethods]
impl EventlogTriageProjector {
    #[new]
    #[pyo3(signature = (
        *,
        identity_keys,
        pivot_keys,
        payload_pivot_keys,
        payload_event_data_keys,
        text_max_chars,
        payload_max_chars,
        event_data_max_items,
        string_max_items,
        string_max_chars,
        file_header_size,
        chunk_size,
        native_parser,
        record_projection,
        int_text,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: Python<'_>,
        identity_keys: Vec<Bound<'_, PyString>>,
        pivot_keys: Vec<Bound<'_, PyString>>,
        payload_pivot_keys: HashSet<String>,
        payload_event_data_keys: HashSet<String>,
        text_max_chars: usize,
        payload_max_chars: usize,
        event_data_max_items: usize,
        string_max_items: usize,
        string_max_chars: usize,
        file_header_size: i64,
        chunk_size: i64,
        native_parser: Bound<'_, PyString>,
        record_projection: Bound<'_, PyDict>,
        int_text: PyObject,
    ) -> PyResult<Self> {
        if chunk_size <= 0 {
            return Err(pyo3::exceptions::PyValueError::new_err("chunk_size must be positive"));
        }
        Ok(Self {
            identity_keys: identity_keys.into_iter().map(Bound::unbind).collect(),
            pivot_keys: pivot_keys.into_iter().map(Bound::unbind).collect(),
            payload_pivot_keys,
            payload_event_data_keys,
            text_max_chars,
            payload_max_chars,
            event_data_max_items,
            string_max_items,
            string_max_chars,
            file_header_size,
            chunk_size,
            native_parser: native_parser.unbind(),
            record_projection: record_projection.unbind(),
            int_text,
            str_type: py.get_type_bound::<PyString>().into_any().unbind(),
        })
    }

    /// `triage_eventlog_details(details)`, or `None` when Python must run.
    fn project<'py>(&self, details: &Bound<'py, PyAny>) -> Option<Bound<'py, PyDict>> {
        self.project_kernel(details).ok()
    }
}

pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<EventlogTriageProjector>()?;
    Ok(())
}
