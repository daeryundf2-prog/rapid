// `json.dumps(..., ensure_ascii=False)` for rows of the opt-in EVTX engine
// (`rapidtriage.core.artifacts._dump_row`): byte-identical text on plain values
// (Python float `repr`, NaN/Infinity, big ints, `default=` for other objects),
// `None` whenever the Python encoder must run instead (subclasses of the
// encoder's built-in kinds, non-str keys, lone surrogates, deep nesting, any
// error), which then produces the same text or raises the same exception.
#![allow(clippy::useless_conversion)]

use crate::evtx_binxml::python_float_repr;
use crate::py_rows::{float_value, kind, Fallback, Kernel, Kind, MAX_DEPTH};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyFloat, PyList, PyLong, PyString, PyTuple};

pub(crate) struct JsonStyle<'a> {
    pub item_separator: &'a str,
    pub key_separator: &'a str,
    pub sort_keys: bool,
}

pub(crate) const COMPACT: JsonStyle<'static> = JsonStyle {
    item_separator: ",",
    key_separator: ":",
    sort_keys: false,
};

/// `json.dumps` string escaping with `ensure_ascii=False`.
pub(crate) fn push_json_string(out: &mut String, text: &str) {
    out.push('"');
    let mut start = 0;
    for (index, byte) in text.bytes().enumerate() {
        let escape = match byte {
            b'"' => "\\\"",
            b'\\' => "\\\\",
            b'\n' => "\\n",
            b'\r' => "\\r",
            b'\t' => "\\t",
            0x08 => "\\b",
            0x0c => "\\f",
            0x00..=0x1f => "",
            _ => continue,
        };
        out.push_str(&text[start..index]);
        if escape.is_empty() {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            out.push_str("\\u00");
            out.push(HEX[usize::from(byte >> 4)] as char);
            out.push(HEX[usize::from(byte & 0x0f)] as char);
        } else {
            out.push_str(escape);
        }
        start = index + 1;
    }
    out.push_str(&text[start..]);
    out.push('"');
}

/// `float.__repr__` as the json encoder writes it (`allow_nan=True`).
pub(crate) fn push_json_float(out: &mut String, number: f64) {
    if number.is_nan() {
        out.push_str("NaN");
    } else if number.is_infinite() {
        out.push_str(if number > 0.0 {
            "Infinity"
        } else {
            "-Infinity"
        });
    } else {
        out.push_str(&python_float_repr(number));
    }
}

pub(crate) fn push_json_int(out: &mut String, value: &Bound<'_, PyAny>) -> Kernel<()> {
    if let Ok(number) = value.extract::<i64>() {
        use std::fmt::Write;
        // Writing into a String cannot fail.
        let _ = write!(out, "{number}");
    } else {
        // Big ints: `int.__repr__`, including its max-str-digits ValueError.
        out.push_str(value.str()?.to_str()?);
    }
    Ok(())
}

/// True for values the json encoder treats as one of its built-in kinds
/// (subclasses included): those never reach `default=`.
fn encoder_builtin_subclass(value: &Bound<'_, PyAny>) -> bool {
    value.is_instance_of::<PyString>()
        || value.is_instance_of::<PyLong>()
        || value.is_instance_of::<PyFloat>()
        || value.is_instance_of::<PyList>()
        || value.is_instance_of::<PyTuple>()
        || value.is_instance_of::<PyDict>()
}

/// `json.dumps(value, ensure_ascii=False, ...)` into `out`. `default` is the
/// `default=` callback (called for objects outside the encoder's kinds).
/// Subclasses of the built-in kinds, non-str keys, lone surrogates and deep
/// nesting go back to Python.
pub(crate) fn encode_json(
    out: &mut String,
    value: &Bound<'_, PyAny>,
    default: Option<&Bound<'_, PyAny>>,
    style: &JsonStyle<'_>,
    depth: u32,
) -> Kernel<()> {
    if depth >= MAX_DEPTH {
        return Err(Fallback);
    }
    match kind(value) {
        Kind::Str => push_json_string(out, value.downcast::<PyString>()?.to_str()?),
        Kind::None => out.push_str("null"),
        Kind::Bool => out.push_str(if value.is_truthy()? { "true" } else { "false" }),
        Kind::Int => push_json_int(out, value)?,
        Kind::Float => push_json_float(out, float_value(value)),
        Kind::List => {
            let list = value.downcast::<PyList>()?;
            out.push('[');
            for (index, item) in list.iter().enumerate() {
                if index > 0 {
                    out.push_str(style.item_separator);
                }
                encode_json(out, &item, default, style, depth + 1)?;
            }
            out.push(']');
        }
        Kind::Tuple => {
            let tuple = value.downcast::<PyTuple>()?;
            out.push('[');
            for (index, item) in tuple.iter().enumerate() {
                if index > 0 {
                    out.push_str(style.item_separator);
                }
                encode_json(out, &item, default, style, depth + 1)?;
            }
            out.push(']');
        }
        Kind::Dict => {
            let dict = value.downcast::<PyDict>()?;
            out.push('{');
            if style.sort_keys {
                let mut items: Vec<(String, Bound<'_, PyAny>)> = Vec::with_capacity(dict.len());
                for (key, item) in dict.iter() {
                    if kind(&key) != Kind::Str {
                        return Err(Fallback);
                    }
                    items.push((key.downcast::<PyString>()?.to_str()?.to_owned(), item));
                }
                // UTF-8 byte order is code point order (Python's str ordering).
                items.sort_by(|left, right| left.0.cmp(&right.0));
                for (index, (key, item)) in items.iter().enumerate() {
                    if index > 0 {
                        out.push_str(style.item_separator);
                    }
                    push_json_string(out, key);
                    out.push_str(style.key_separator);
                    encode_json(out, item, default, style, depth + 1)?;
                }
            } else {
                for (index, (key, item)) in dict.iter().enumerate() {
                    if kind(&key) != Kind::Str {
                        return Err(Fallback);
                    }
                    if index > 0 {
                        out.push_str(style.item_separator);
                    }
                    push_json_string(out, key.downcast::<PyString>()?.to_str()?);
                    out.push_str(style.key_separator);
                    encode_json(out, &item, default, style, depth + 1)?;
                }
            }
            out.push('}');
        }
        Kind::Other => {
            let Some(default) = default else {
                return Err(Fallback);
            };
            if encoder_builtin_subclass(value) {
                return Err(Fallback);
            }
            let converted = default.call1((value,))?;
            encode_json(out, &converted, Some(default), style, depth + 1)?;
        }
    }
    Ok(())
}

/// `json.dumps(row, ensure_ascii=False, separators=(",", ":"), default=default)`,
/// or `None` when the Python encoder must run (same text or same exception).
#[pyfunction]
fn dump_json_row<'py>(
    row: &Bound<'py, PyAny>,
    default: &Bound<'py, PyAny>,
) -> Option<Bound<'py, PyString>> {
    let mut out = String::with_capacity(4096);
    encode_json(&mut out, row, Some(default), &COMPACT, 0).ok()?;
    Some(PyString::new_bound(row.py(), &out))
}

pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(dump_json_row, module)?)?;
    Ok(())
}
