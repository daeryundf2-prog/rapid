// Row kernels of the opt-in EVTX engine (`evtx_engine=rust`): the hot parts of
// `rapidtriage.core.artifact_profiles` (template folding, residue stripping,
// profile expansion). Each kernel reproduces its Python counterpart exactly on
// "plain" trees (exact dict/list/str/int/float/bool/None, as `json.loads`
// returns) and reports anything else so the caller runs the Python
// implementation instead.
#![allow(clippy::useless_conversion)]

use pyo3::ffi;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyList, PyLong, PyString, PyTuple};

/// Nesting below this goes to the Python implementation (which also owns
/// `RecursionError` and circular-reference behaviour).
pub(crate) const MAX_DEPTH: u32 = 200;

/// The value left the plain shape (or a Python call failed): run the Python
/// implementation, which reproduces the result or the exception.
pub(crate) struct Fallback;

pub(crate) type Kernel<T> = Result<T, Fallback>;

impl From<PyErr> for Fallback {
    fn from(_: PyErr) -> Self {
        Fallback
    }
}

impl From<pyo3::DowncastError<'_, '_>> for Fallback {
    fn from(_: pyo3::DowncastError<'_, '_>) -> Self {
        Fallback
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Str,
    Dict,
    List,
    Int,
    None,
    Bool,
    Float,
    Tuple,
    Other,
}

pub(crate) fn kind(value: &Bound<'_, PyAny>) -> Kind {
    if value.is_exact_instance_of::<PyString>() {
        Kind::Str
    } else if value.is_exact_instance_of::<PyDict>() {
        Kind::Dict
    } else if value.is_exact_instance_of::<PyList>() {
        Kind::List
    } else if value.is_exact_instance_of::<PyLong>() {
        Kind::Int
    } else if value.is_none() {
        Kind::None
    } else if value.is_exact_instance_of::<PyBool>() {
        Kind::Bool
    } else if value.is_exact_instance_of::<PyFloat>() {
        Kind::Float
    } else if value.is_exact_instance_of::<PyTuple>() {
        Kind::Tuple
    } else {
        Kind::Other
    }
}

/// `left == right` for two exact `str` or two exact `int` objects.
pub(crate) fn rich_eq(left: &Bound<'_, PyAny>, right: &Bound<'_, PyAny>) -> Kernel<bool> {
    // SAFETY: both pointers are live borrowed references held by the GIL.
    match unsafe { ffi::PyObject_RichCompareBool(left.as_ptr(), right.as_ptr(), ffi::Py_EQ) } {
        1 => Ok(true),
        0 => Ok(false),
        _ => Err(PyErr::fetch(left.py()).into()),
    }
}

pub(crate) fn float_value(value: &Bound<'_, PyAny>) -> f64 {
    // SAFETY: called only for exact `float` objects.
    unsafe { ffi::PyFloat_AS_DOUBLE(value.as_ptr()) }
}

// ---------------------------------------------------------------------------
// artifact_profiles: _same / _common / _residue / _merge
// ---------------------------------------------------------------------------

/// `artifact_profiles._same(value, template)`: scalars compare type-strict
/// (`True != 1`, `1 != 1.0`, NaN never equal); containers by identity, else
/// `==` plus canonical-JSON identity (`nested_same`).
fn same(value: &Bound<'_, PyAny>, template: &Bound<'_, PyAny>) -> Kernel<bool> {
    let template_kind = kind(template);
    match template_kind {
        Kind::Dict | Kind::List => {
            if value.is(template) {
                Ok(true)
            } else {
                nested_same(value, template, 0)
            }
        }
        Kind::Other | Kind::Tuple => Err(Fallback),
        _ => {
            if kind(value) != template_kind {
                return Ok(false);
            }
            match template_kind {
                Kind::Str | Kind::Int => rich_eq(value, template),
                Kind::Float => Ok(float_value(value) == float_value(template)),
                Kind::Bool => Ok(value.is(template)),
                _ => Ok(true),
            }
        }
    }
}

/// `a == b and canonical(a) == canonical(b)` below a container: `==` has the
/// identity shortcut, the canonical form tells bool/int/float and -0.0/0.0
/// apart, and dict key order is irrelevant to both.
fn nested_same(value: &Bound<'_, PyAny>, template: &Bound<'_, PyAny>, depth: u32) -> Kernel<bool> {
    if value.is(template) {
        return Ok(true);
    }
    if depth >= MAX_DEPTH {
        return Err(Fallback);
    }
    let (value_kind, template_kind) = (kind(value), kind(template));
    if matches!(value_kind, Kind::Other | Kind::Tuple) || matches!(template_kind, Kind::Other | Kind::Tuple) {
        return Err(Fallback);
    }
    if value_kind != template_kind {
        return Ok(false);
    }
    match template_kind {
        Kind::Str | Kind::Int => rich_eq(value, template),
        Kind::Float => {
            let (left, right) = (float_value(value), float_value(template));
            Ok(left == right && left.to_bits() == right.to_bits())
        }
        Kind::Bool => Ok(false),
        Kind::None => Ok(true),
        Kind::Dict => {
            let (value, template) = (value.downcast::<PyDict>()?, template.downcast::<PyDict>()?);
            if value.len() != template.len() {
                return Ok(false);
            }
            for (key, item) in template.iter() {
                if kind(&key) != Kind::Str {
                    // Canonical JSON renders non-str keys as strings (True -> "true").
                    return Err(Fallback);
                }
                match value.get_item(&key)? {
                    Some(other) => {
                        if !nested_same(&other, &item, depth + 1)? {
                            return Ok(false);
                        }
                    }
                    None => return Ok(false),
                }
            }
            Ok(true)
        }
        Kind::List => {
            let (value, template) = (value.downcast::<PyList>()?, template.downcast::<PyList>()?);
            if value.len() != template.len() {
                return Ok(false);
            }
            for (left, right) in value.iter().zip(template.iter()) {
                if !nested_same(&left, &right, depth + 1)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        Kind::Tuple | Kind::Other => Err(Fallback),
    }
}

fn all_dicts(list: &Bound<'_, PyList>) -> Kernel<bool> {
    for item in list.iter() {
        match kind(&item) {
            Kind::Dict => {}
            Kind::Other => return Err(Fallback),
            _ => return Ok(false),
        }
    }
    Ok(true)
}

/// `artifact_profiles._common(left, right)`: `None` when nothing is shared;
/// the same `left` object when nothing changed.
fn common<'py>(left: &Bound<'py, PyAny>, right: &Bound<'py, PyAny>, depth: u32) -> Kernel<Option<Bound<'py, PyAny>>> {
    if depth >= MAX_DEPTH {
        return Err(Fallback);
    }
    if same(right, left)? {
        return Ok(Some(left.clone()));
    }
    let (left_kind, right_kind) = (kind(left), kind(right));
    if left_kind == Kind::Other || right_kind == Kind::Other {
        return Err(Fallback);
    }
    let py = left.py();
    if left_kind == Kind::Dict && right_kind == Kind::Dict {
        let (left_dict, right_dict) = (left.downcast::<PyDict>()?, right.downcast::<PyDict>()?);
        let template = PyDict::new_bound(py);
        let mut unchanged = true;
        for (key, value) in left_dict.iter() {
            if let Some(other) = right_dict.get_item(&key)? {
                if let Some(child) = common(&value, &other, depth + 1)? {
                    unchanged = unchanged && child.is(&value);
                    template.set_item(key, child)?;
                    continue;
                }
            }
            unchanged = false;
        }
        if unchanged {
            return Ok(Some(left.clone()));
        }
        return Ok((!template.is_empty()).then(|| template.into_any()));
    }
    if left_kind == Kind::List && right_kind == Kind::List {
        let (left_list, right_list) = (left.downcast::<PyList>()?, right.downcast::<PyList>()?);
        if left_list.is_empty() || left_list.len() != right_list.len() || !all_dicts(left_list)? || !all_dicts(right_list)? {
            return Ok(None);
        }
        let mut items: Vec<Bound<'py, PyAny>> = Vec::with_capacity(left_list.len());
        let mut any_hoisted = false;
        let mut unchanged = true;
        for (left_item, right_item) in left_list.iter().zip(right_list.iter()) {
            match common(&left_item, &right_item, depth + 1)? {
                Some(child) => {
                    any_hoisted = true;
                    unchanged = unchanged && child.is(&left_item);
                    items.push(child);
                }
                None => {
                    unchanged = unchanged && left_item.downcast::<PyDict>()?.is_empty();
                    items.push(PyDict::new_bound(py).into_any());
                }
            }
        }
        if !any_hoisted {
            return Ok(None);
        }
        if unchanged {
            return Ok(Some(left.clone()));
        }
        return Ok(Some(PyList::new_bound(py, items).into_any()));
    }
    Ok(None)
}

/// `artifact_profiles._residue(value, template)`: `None` stands for `_MISSING`.
fn residue<'py>(value: &Bound<'py, PyAny>, template: &Bound<'py, PyAny>, depth: u32) -> Kernel<Option<Bound<'py, PyAny>>> {
    if depth >= MAX_DEPTH {
        return Err(Fallback);
    }
    if same(value, template)? {
        return Ok(None);
    }
    let (value_kind, template_kind) = (kind(value), kind(template));
    if value_kind == Kind::Other || template_kind == Kind::Other {
        return Err(Fallback);
    }
    let py = value.py();
    if value_kind == Kind::Dict && template_kind == Kind::Dict {
        let (value_dict, template_dict) = (value.downcast::<PyDict>()?, template.downcast::<PyDict>()?);
        let out = PyDict::new_bound(py);
        for (key, item) in value_dict.iter() {
            match template_dict.get_item(&key)? {
                Some(part) => {
                    if let Some(child) = residue(&item, &part, depth + 1)? {
                        out.set_item(key, child)?;
                    }
                }
                None => out.set_item(key, item)?,
            }
        }
        return Ok((!out.is_empty()).then(|| out.into_any()));
    }
    if value_kind == Kind::List && template_kind == Kind::List {
        let (value_list, template_list) = (value.downcast::<PyList>()?, template.downcast::<PyList>()?);
        if value_list.len() == template_list.len() {
            let mut items: Vec<Option<Bound<'py, PyAny>>> = Vec::with_capacity(value_list.len());
            for (item, part) in value_list.iter().zip(template_list.iter()) {
                items.push(residue(&item, &part, depth + 1)?);
            }
            if items.iter().all(Option::is_none) {
                return Ok(None);
            }
            let items: Vec<Bound<'py, PyAny>> = items
                .into_iter()
                .map(|item| item.unwrap_or_else(|| PyDict::new_bound(py).into_any()))
                .collect();
            return Ok(Some(PyList::new_bound(py, items).into_any()));
        }
    }
    Ok(Some(value.clone()))
}

/// `_TemplateTracker.observe` for the details templates. Folds `details` into
/// `templates` (key -> running template, `missing` before the first value) and
/// returns True, or returns False without touching `templates` when the
/// Python implementation must run.
#[pyfunction]
fn profile_observe_details(templates: &Bound<'_, PyDict>, details: &Bound<'_, PyAny>, missing: &Bound<'_, PyAny>) -> bool {
    observe_details(templates, details, missing).is_ok()
}

fn observe_details(templates: &Bound<'_, PyDict>, details: &Bound<'_, PyAny>, missing: &Bound<'_, PyAny>) -> Kernel<()> {
    if kind(details) != Kind::Dict || !templates.is_exact_instance_of::<PyDict>() {
        return Err(Fallback);
    }
    let details = details.downcast::<PyDict>()?;
    let mut updates = Vec::with_capacity(templates.len());
    for (key, current) in templates.iter() {
        let update = match details.get_item(&key)? {
            None => None,
            Some(value) if current.is(missing) => Some(value),
            Some(value) => common(&current, &value, 0)?,
        };
        updates.push((key, current, update));
    }
    for (key, current, update) in updates {
        match update {
            None => templates.del_item(key)?,
            Some(template) => {
                if !template.is(&current) {
                    templates.set_item(key, template)?;
                }
            }
        }
    }
    Ok(())
}

/// `_common(left, right)` -> `(hoisted, template)`, or `None` when the Python
/// implementation must run.
#[pyfunction]
fn profile_common<'py>(left: &Bound<'py, PyAny>, right: &Bound<'py, PyAny>) -> Option<(bool, PyObject)> {
    let py = left.py();
    match common(left, right, 0) {
        Ok(Some(template)) => Some((true, template.unbind())),
        Ok(None) => Some((false, py.None())),
        Err(Fallback) => None,
    }
}

/// `_strip_level(row, level)`; returns False without touching `row` when the
/// Python implementation must run.
#[pyfunction]
fn profile_strip_level(row: &Bound<'_, PyAny>, level: &Bound<'_, PyAny>) -> bool {
    strip_level(row, level).is_ok()
}

fn strip_level(row: &Bound<'_, PyAny>, level: &Bound<'_, PyAny>) -> Kernel<()> {
    if kind(row) != Kind::Dict || kind(level) != Kind::Dict {
        return Err(Fallback);
    }
    let (row, level) = (row.downcast::<PyDict>()?, level.downcast::<PyDict>()?);
    let py = row.py();
    let mut detail_updates = Vec::new();
    let details = row.get_item("details")?;
    let templates = level.get_item("details")?;
    if let (Some(details), Some(templates)) = (&details, &templates) {
        match (kind(details), kind(templates)) {
            (Kind::Other, _) | (_, Kind::Other) => return Err(Fallback),
            (Kind::Dict, Kind::Dict) => {
                let (details, templates) = (details.downcast::<PyDict>()?, templates.downcast::<PyDict>()?);
                for (key, template) in templates.iter() {
                    if let Some(value) = details.get_item(&key)? {
                        detail_updates.push((key, residue(&value, &template, 0)?));
                    }
                }
            }
            _ => {}
        }
    }
    let mut envelope_update = None;
    if let Some(envelope_template) = level.get_item("artifact_record")? {
        if !envelope_template.is_none() {
            if let Some(envelope) = row.get_item("artifact_record")? {
                match kind(&envelope) {
                    Kind::Other => return Err(Fallback),
                    Kind::Dict => {
                        envelope_update = Some(
                            residue(&envelope, &envelope_template, 0)?.unwrap_or_else(|| PyDict::new_bound(py).into_any()),
                        );
                    }
                    _ => {}
                }
            }
        }
    }
    if let Some(details) = details {
        let details = details.downcast::<PyDict>()?;
        for (key, update) in detail_updates {
            match update {
                None => details.del_item(key)?,
                Some(value) => details.set_item(key, value)?,
            }
        }
    }
    if let Some(envelope) = envelope_update {
        row.set_item("artifact_record", envelope)?;
    }
    Ok(())
}

/// `_merge(template, residue, copy_template=False)`; `missing` is `_MISSING`
/// and nodes outside the plain shape go to `python_merge` (the same call in
/// Python), which is exact because `_merge` only looks at one node at a time.
#[pyfunction]
fn profile_merge<'py>(
    template: &Bound<'py, PyAny>,
    residue: &Bound<'py, PyAny>,
    missing: &Bound<'py, PyAny>,
    python_merge: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    merge(template, residue, missing, python_merge, 0)
}

fn merge<'py>(
    template: &Bound<'py, PyAny>,
    residue: &Bound<'py, PyAny>,
    missing: &Bound<'py, PyAny>,
    python_merge: &Bound<'py, PyAny>,
    depth: u32,
) -> PyResult<Bound<'py, PyAny>> {
    if residue.is(missing) {
        return Ok(template.clone());
    }
    let (template_kind, residue_kind) = (kind(template), kind(residue));
    if depth >= MAX_DEPTH || template_kind == Kind::Other || residue_kind == Kind::Other {
        return python_merge.call1((template, residue));
    }
    let py = template.py();
    if template_kind == Kind::Dict && residue_kind == Kind::Dict {
        let (template, residue) = (template.downcast::<PyDict>()?, residue.downcast::<PyDict>()?);
        let merged = PyDict::new_bound(py);
        for (key, value) in template.iter() {
            match residue.get_item(&key)? {
                Some(part) => merged.set_item(&key, merge(&value, &part, missing, python_merge, depth + 1)?)?,
                None => merged.set_item(&key, value)?,
            }
        }
        for (key, value) in residue.iter() {
            if !template.contains(&key)? {
                merged.set_item(key, value)?;
            }
        }
        return Ok(merged.into_any());
    }
    if template_kind == Kind::List && residue_kind == Kind::List {
        let (template, residue) = (template.downcast::<PyList>()?, residue.downcast::<PyList>()?);
        if template.len() == residue.len() {
            let mut items = Vec::with_capacity(template.len());
            for (item, part) in template.iter().zip(residue.iter()) {
                items.push(merge(&item, &part, missing, python_merge, depth + 1)?);
            }
            return Ok(PyList::new_bound(py, items).into_any());
        }
    }
    Ok(residue.clone())
}

pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(profile_observe_details, module)?)?;
    module.add_function(wrap_pyfunction!(profile_common, module)?)?;
    module.add_function(wrap_pyfunction!(profile_strip_level, module)?)?;
    module.add_function(wrap_pyfunction!(profile_merge, module)?)?;
    Ok(())
}
