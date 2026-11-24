//! PyO3 bindings: the `rapid_registry_native` extension module.
//!
//! `RegistryReader` reads the same buffer (``mmap`` or ``bytes``) the Python
//! `NativeRegistryHive` holds, with the geometry Python computed for it, and records walk errors
//! straight into that hive's `errors` Counter in the order the Python reader would.

// PyO3 0.22's `#[pymethods]` expansion converts `PyErr` into itself (clippy::useless_conversion).
#![allow(clippy::useless_conversion)]

use pyo3::buffer::PyBuffer;
use pyo3::exceptions::PyValueError;
use pyo3::intern;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyString, PyTuple};

use crate::hive::{ErrorJournal, Geometry, Hive, Key, KeyWalk, Value, ValueData, WalkEntry};
use crate::scan::{self, FreeCellKind};
use crate::text;

#[pyclass(name = "NativeRegistryKey", module = "rapid_registry_native", frozen)]
pub struct PyKey {
    #[pyo3(get)]
    offset: u32,
    name: Py<PyString>,
    name_encoding: &'static str,
    #[pyo3(get)]
    flags: u16,
    #[pyo3(get)]
    last_written_filetime: u64,
    #[pyo3(get)]
    parent_offset: u32,
    #[pyo3(get)]
    subkey_count: u32,
    #[pyo3(get)]
    subkey_list_offset: u32,
    #[pyo3(get)]
    value_count: u32,
    #[pyo3(get)]
    value_list_offset: u32,
    #[pyo3(get)]
    allocated: bool,
}

#[pymethods]
impl PyKey {
    #[getter]
    fn name(&self, py: Python<'_>) -> Py<PyString> {
        self.name.clone_ref(py)
    }

    #[getter]
    fn name_encoding<'py>(&self, py: Python<'py>) -> Bound<'py, PyString> {
        PyString::intern_bound(py, self.name_encoding)
    }

    #[getter]
    fn last_written_at(&self) -> String {
        text::filetime_to_iso_ticks(self.last_written_filetime)
    }

    fn __repr__(&self, py: Python<'_>) -> String {
        format!(
            "NativeRegistryKey(offset={}, name={:?})",
            self.offset,
            self.name.bind(py).to_string()
        )
    }
}

#[pyclass(name = "NativeRegistryValue", module = "rapid_registry_native", frozen)]
pub struct PyValue {
    #[pyo3(get)]
    offset: u32,
    name: Py<PyString>,
    name_encoding: &'static str,
    #[pyo3(get)]
    value_type: u32,
    #[pyo3(get)]
    data_size: u32,
    #[pyo3(get)]
    data_offset: u32,
    #[pyo3(get)]
    inline: bool,
    #[pyo3(get)]
    flags: u16,
    #[pyo3(get)]
    allocated: bool,
}

#[pymethods]
impl PyValue {
    #[getter]
    fn name(&self, py: Python<'_>) -> Py<PyString> {
        self.name.clone_ref(py)
    }

    #[getter]
    fn name_encoding<'py>(&self, py: Python<'py>) -> Bound<'py, PyString> {
        PyString::intern_bound(py, self.name_encoding)
    }

    fn __repr__(&self, py: Python<'_>) -> String {
        format!(
            "NativeRegistryValue(offset={}, name={:?})",
            self.offset,
            self.name.bind(py).to_string()
        )
    }
}

impl PyValue {
    /// Core value for data reads (which never look at the name).
    fn core(&self) -> Value {
        Value {
            offset: self.offset,
            name: String::new(),
            name_encoding: self.name_encoding,
            value_type: self.value_type,
            data_size: self.data_size,
            data_offset: self.data_offset,
            inline: self.inline,
            flags: self.flags,
            allocated: self.allocated,
        }
    }
}

fn py_key(py: Python<'_>, key: Key) -> PyResult<Py<PyKey>> {
    Py::new(
        py,
        PyKey {
            offset: key.offset,
            name: PyString::new_bound(py, &key.name).unbind(),
            name_encoding: key.name_encoding,
            flags: key.flags,
            last_written_filetime: key.last_written_filetime,
            parent_offset: key.parent_offset,
            subkey_count: key.subkey_count,
            subkey_list_offset: key.subkey_list_offset,
            value_count: key.value_count,
            value_list_offset: key.value_list_offset,
            allocated: key.allocated,
        },
    )
}

fn py_value(py: Python<'_>, value: Value) -> PyResult<Py<PyValue>> {
    Py::new(
        py,
        PyValue {
            offset: value.offset,
            name: PyString::new_bound(py, &value.name).unbind(),
            name_encoding: value.name_encoding,
            value_type: value.value_type,
            data_size: value.data_size,
            data_offset: value.data_offset,
            inline: value.inline,
            flags: value.flags,
            allocated: value.allocated,
        },
    )
}

fn value_data_object(py: Python<'_>, data: ValueData) -> PyObject {
    match data {
        ValueData::Text(text) => text.into_py(py),
        ValueData::MultiText(items) => PyList::new_bound(py, items).into_any().unbind(),
        ValueData::Integer(number) => number.into_py(py),
        ValueData::Bytes(raw) => PyBytes::new_bound(py, &raw).into_any().unbind(),
    }
}

/// `str(name).casefold() == wanted_folded`: ASCII names fold in Rust, others through Python's
/// own `str.casefold` so the Unicode tables match the running interpreter exactly.
fn folded_equals(py: Python<'_>, name: &str, wanted_folded: &str) -> PyResult<bool> {
    if name.is_ascii() {
        return Ok(name.len() == wanted_folded.len()
            && name
                .bytes()
                .zip(wanted_folded.bytes())
                .all(|(left, right)| left.to_ascii_lowercase() == right));
    }
    let folded: String = PyString::new_bound(py, name)
        .call_method0(intern!(py, "casefold"))?
        .extract()?;
    Ok(folded == wanted_folded)
}

/// A Python int offset past `u32` can only fail `_cell`'s alignment or bounds check.
fn narrow_offset(relative_offset: u64, journal: &mut ErrorJournal) -> Option<u32> {
    match u32::try_from(relative_offset) {
        Ok(offset) => Some(offset),
        Err(_) if !relative_offset.is_multiple_of(8) => {
            journal.push("misaligned-cell-offset");
            None
        }
        Err(_) => {
            journal.push("cell-offset-out-of-bounds");
            None
        }
    }
}

fn casefold(py: Python<'_>, name: &Bound<'_, PyString>) -> PyResult<String> {
    name.call_method0(intern!(py, "casefold"))?.extract()
}

struct PyEntry {
    parts: Py<PyTuple>,
    key: Py<PyKey>,
    offset: u32,
    subkey_count: u32,
    subkey_list_offset: u32,
}

impl WalkEntry for PyEntry {
    fn offset(&self) -> u32 {
        self.offset
    }
    fn subkey_count(&self) -> u32 {
        self.subkey_count
    }
    fn subkey_list_offset(&self) -> u32 {
        self.subkey_list_offset
    }
}

/// Cell reader over a Python buffer. Methods mirror `NativeRegistryHive`.
#[pyclass(name = "RegistryReader", module = "rapid_registry_native")]
pub struct PyReader {
    buffer: Option<PyBuffer<u8>>,
    geometry: Geometry,
    errors: Py<PyDict>,
}

impl PyReader {
    fn data(&self) -> PyResult<&[u8]> {
        let buffer = self
            .buffer
            .as_ref()
            .ok_or_else(|| PyValueError::new_err("registry reader is closed"))?;
        let length = buffer.len_bytes();
        if length == 0 {
            return Ok(&[]);
        }
        // SAFETY: the exporter keeps the C-contiguous buffer alive and unresized while the
        // `PyBuffer` is held; the slice cannot outlive `&self`, which owns that `PyBuffer`.
        Ok(unsafe { std::slice::from_raw_parts(buffer.buf_ptr() as *const u8, length) })
    }

    fn hive(&self) -> PyResult<Hive<'_>> {
        Ok(Hive::new(self.data()?, self.geometry))
    }

    /// Apply journaled walk errors to the hive's `errors` Counter (`errors[key] += 1`).
    fn flush(&self, py: Python<'_>, journal: ErrorJournal) -> PyResult<()> {
        if journal.is_empty() {
            return Ok(());
        }
        let errors = self.errors.bind(py);
        for name in journal {
            let current: u64 = match errors.get_item(name)? {
                Some(count) => count.extract()?,
                None => 0,
            };
            errors.set_item(name, current + 1)?;
        }
        Ok(())
    }

    fn keys_to_list(py: Python<'_>, keys: Vec<Key>) -> PyResult<Py<PyList>> {
        let items = keys
            .into_iter()
            .map(|key| py_key(py, key))
            .collect::<PyResult<Vec<_>>>()?;
        Ok(PyList::new_bound(py, items).unbind())
    }

    fn values_to_list(py: Python<'_>, values: Vec<Value>) -> PyResult<Py<PyList>> {
        let items = values
            .into_iter()
            .map(|value| py_value(py, value))
            .collect::<PyResult<Vec<_>>>()?;
        Ok(PyList::new_bound(py, items).unbind())
    }

    fn find_subkey(
        &self,
        py: Python<'_>,
        hive: &Hive<'_>,
        subkey_count: u32,
        subkey_list_offset: u32,
        wanted_folded: &str,
        journal: &mut ErrorJournal,
    ) -> PyResult<Option<Key>> {
        for child in hive.subkeys_of(subkey_count, subkey_list_offset, journal) {
            if folded_equals(py, &child.name, wanted_folded)? {
                return Ok(Some(child));
            }
        }
        Ok(None)
    }
}

#[pymethods]
impl PyReader {
    #[new]
    fn new(
        data: &Bound<'_, PyAny>,
        errors: Bound<'_, PyDict>,
        hbin_end: usize,
        minor_version: u32,
        root_cell_offset: u32,
    ) -> PyResult<Self> {
        let buffer = PyBuffer::<u8>::get_bound(data)?;
        if !buffer.is_c_contiguous() {
            return Err(PyValueError::new_err("hive buffer must be C-contiguous"));
        }
        if hbin_end > buffer.len_bytes() {
            return Err(PyValueError::new_err("hbin_end beyond the hive buffer"));
        }
        Ok(Self {
            buffer: Some(buffer),
            geometry: Geometry {
                hbin_end,
                minor_version,
                root_cell_offset,
            },
            errors: errors.unbind(),
        })
    }

    /// Release the buffer so the owner can close its ``mmap``.
    fn close(&mut self, py: Python<'_>) {
        if let Some(buffer) = self.buffer.take() {
            buffer.release(py);
        }
    }

    fn key_at(&self, py: Python<'_>, relative_offset: u64) -> PyResult<Option<Py<PyKey>>> {
        let mut journal = ErrorJournal::new();
        let hive = self.hive()?;
        let key = narrow_offset(relative_offset, &mut journal)
            .and_then(|offset| hive.key_at(offset, &mut journal));
        self.flush(py, journal)?;
        key.map(|key| py_key(py, key)).transpose()
    }

    fn subkeys(&self, py: Python<'_>, key: &Bound<'_, PyKey>) -> PyResult<Py<PyList>> {
        let key = key.get();
        let mut journal = ErrorJournal::new();
        let children =
            self.hive()?
                .subkeys_of(key.subkey_count, key.subkey_list_offset, &mut journal);
        self.flush(py, journal)?;
        Self::keys_to_list(py, children)
    }

    fn subkey(
        &self,
        py: Python<'_>,
        key: &Bound<'_, PyKey>,
        name: &Bound<'_, PyString>,
    ) -> PyResult<Option<Py<PyKey>>> {
        let wanted = casefold(py, name)?;
        let key = key.get();
        let mut journal = ErrorJournal::new();
        let found = self.find_subkey(
            py,
            &self.hive()?,
            key.subkey_count,
            key.subkey_list_offset,
            &wanted,
            &mut journal,
        );
        self.flush(py, journal)?;
        found?.map(|child| py_key(py, child)).transpose()
    }

    /// `open_key(relative_path, start)`; the caller resolves ``start or self.root``.
    #[pyo3(signature = (relative_path, start))]
    fn open_key(
        &self,
        py: Python<'_>,
        relative_path: &str,
        start: Option<Py<PyKey>>,
    ) -> PyResult<Option<Py<PyKey>>> {
        let parts: Vec<&str> = relative_path
            .split(['\\', '/'])
            .filter(|part| !part.is_empty())
            .collect();
        let Some(start) = start else {
            return Ok(None);
        };
        if parts.is_empty() {
            return Ok(Some(start));
        }
        let hive = self.hive()?;
        let mut journal = ErrorJournal::new();
        let (mut count, mut list) = {
            let key = start.get();
            (key.subkey_count, key.subkey_list_offset)
        };
        let mut current: Option<Key> = None;
        let mut outcome = Ok(());
        for part in parts {
            let wanted = match casefold(py, &PyString::new_bound(py, part)) {
                Ok(wanted) => wanted,
                Err(error) => {
                    outcome = Err(error);
                    break;
                }
            };
            match self.find_subkey(py, &hive, count, list, &wanted, &mut journal) {
                Ok(Some(child)) => {
                    count = child.subkey_count;
                    list = child.subkey_list_offset;
                    current = Some(child);
                }
                Ok(None) => {
                    current = None;
                    break;
                }
                Err(error) => {
                    outcome = Err(error);
                    break;
                }
            }
        }
        self.flush(py, journal)?;
        outcome?;
        current.map(|key| py_key(py, key)).transpose()
    }

    /// `iter_keys(start, components)`; the caller resolves ``start or self.root``.
    fn iter_keys(
        slf: &Bound<'_, Self>,
        start: Py<PyKey>,
        components: Py<PyTuple>,
    ) -> PyResult<PyKeyWalk> {
        let (offset, subkey_count, subkey_list_offset) = {
            let key = start.get();
            (key.offset, key.subkey_count, key.subkey_list_offset)
        };
        Ok(PyKeyWalk {
            reader: slf.clone().unbind(),
            walk: KeyWalk::new(PyEntry {
                parts: components,
                key: start,
                offset,
                subkey_count,
                subkey_list_offset,
            }),
        })
    }

    fn values(&self, py: Python<'_>, key: &Bound<'_, PyKey>) -> PyResult<Py<PyList>> {
        let key = key.get();
        let mut journal = ErrorJournal::new();
        let values = self
            .hive()?
            .values_of(key.value_count, key.value_list_offset, &mut journal);
        self.flush(py, journal)?;
        Self::values_to_list(py, values)
    }

    fn value_at(&self, py: Python<'_>, relative_offset: u64) -> PyResult<Option<Py<PyValue>>> {
        let mut journal = ErrorJournal::new();
        let hive = self.hive()?;
        let value = narrow_offset(relative_offset, &mut journal)
            .and_then(|offset| hive.value_at(offset, &mut journal));
        self.flush(py, journal)?;
        value.map(|value| py_value(py, value)).transpose()
    }

    fn value(
        &self,
        py: Python<'_>,
        key: &Bound<'_, PyKey>,
        name: &Bound<'_, PyString>,
    ) -> PyResult<Option<Py<PyValue>>> {
        let wanted = casefold(py, name)?;
        let key = key.get();
        let mut journal = ErrorJournal::new();
        let values = self
            .hive()?
            .values_of(key.value_count, key.value_list_offset, &mut journal);
        self.flush(py, journal)?;
        for value in values {
            if folded_equals(py, &value.name, &wanted)? {
                return py_value(py, value).map(Some);
            }
        }
        Ok(None)
    }

    fn cell_allocated(&self, relative_offset: u64) -> PyResult<Option<bool>> {
        let hive = self.hive()?;
        Ok(u32::try_from(relative_offset)
            .ok()
            .and_then(|offset| hive.cell_allocated(offset)))
    }

    fn value_data_allocated(&self, value: &Bound<'_, PyValue>) -> PyResult<Option<bool>> {
        Ok(self.hive()?.value_data_allocated(&value.get().core()))
    }

    fn value_bytes<'py>(
        &self,
        py: Python<'py>,
        value: &Bound<'py, PyValue>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let mut journal = ErrorJournal::new();
        let raw = self.hive()?.value_bytes(&value.get().core(), &mut journal);
        self.flush(py, journal)?;
        Ok(PyBytes::new_bound(py, &raw))
    }

    fn value_data(&self, py: Python<'_>, value: &Bound<'_, PyValue>) -> PyResult<PyObject> {
        let mut journal = ErrorJournal::new();
        let data = self.hive()?.value_data(&value.get().core(), &mut journal);
        self.flush(py, journal)?;
        Ok(value_data_object(py, data))
    }

    /// ``[(name, value_data(value)) for value in values(key)]`` — the `values_dict` items.
    fn value_items(&self, py: Python<'_>, key: &Bound<'_, PyKey>) -> PyResult<Py<PyList>> {
        let key = key.get();
        let hive = self.hive()?;
        let mut journal = ErrorJournal::new();
        let values = hive.values_of(key.value_count, key.value_list_offset, &mut journal);
        let mut items: Vec<PyObject> = Vec::with_capacity(values.len());
        for value in values {
            let data = hive.value_data(&value, &mut journal);
            items.push((value.name, value_data_object(py, data)).into_py(py));
        }
        self.flush(py, journal)?;
        Ok(PyList::new_bound(py, items).unbind())
    }

    /// `iter_registry_free_cell_candidates`: (candidate dicts, allocator stats dict).
    fn free_cell_candidates<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<(Bound<'py, PyList>, Bound<'py, PyDict>)> {
        let (cells, stats) = scan::free_cell_candidates(&self.hive()?);
        let candidates = PyList::empty_bound(py);
        for cell in cells {
            let row = PyDict::new_bound(py);
            match &cell.kind {
                FreeCellKind::Key(key) => {
                    row.set_item("cell_kind", "key-node")?;
                    row.set_item("cell_signature", "nk")?;
                    row.set_item("cell_offset", cell.cell_offset)?;
                    row.set_item("cell_size", cell.cell_size)?;
                    row.set_item("allocation_status", "free-or-deleted-candidate")?;
                    row.set_item("flags", key.flags)?;
                    row.set_item("name", &key.name)?;
                    row.set_item("name_encoding", key.name_encoding)?;
                    row.set_item("last_written_at", &key.last_written_at)?;
                    row.set_item(
                        "parent_cell_offset",
                        scan::relative_to_file_offset(key.parent_cell_relative_offset),
                    )?;
                    row.set_item(
                        "parent_cell_relative_offset",
                        key.parent_cell_relative_offset,
                    )?;
                    row.set_item(
                        "subkey_count",
                        u64::from(key.stable_subkey_count) + u64::from(key.volatile_subkey_count),
                    )?;
                    row.set_item("stable_subkey_count", key.stable_subkey_count)?;
                    row.set_item("volatile_subkey_count", key.volatile_subkey_count)?;
                    row.set_item("stable_subkey_list_offset", 0)?;
                    row.set_item("volatile_subkey_list_offset", 0)?;
                    row.set_item("value_count", key.value_count)?;
                    row.set_item(
                        "value_list_offset",
                        scan::relative_to_file_offset(key.value_list_relative_offset),
                    )?;
                    row.set_item("value_list_relative_offset", key.value_list_relative_offset)?;
                }
                FreeCellKind::Value(value) => {
                    let inline = value.data_raw_size & 0x8000_0000 != 0;
                    row.set_item("cell_kind", "value")?;
                    row.set_item("cell_signature", "vk")?;
                    row.set_item("cell_offset", cell.cell_offset)?;
                    row.set_item("cell_size", cell.cell_size)?;
                    row.set_item("allocation_status", "free-or-deleted-candidate")?;
                    row.set_item("flags", value.flags)?;
                    row.set_item("name", &value.name)?;
                    row.set_item("name_encoding", value.name_encoding)?;
                    row.set_item("value_type", text::value_type_name(value.value_type))?;
                    row.set_item("value_data_size", value.data_raw_size & 0x7FFF_FFFF)?;
                    row.set_item(
                        "value_data_offset",
                        if inline {
                            u64::from(value.data_relative_offset)
                        } else {
                            scan::relative_to_file_offset(value.data_relative_offset)
                        },
                    )?;
                    row.set_item("value_data_relative_offset", value.data_relative_offset)?;
                    row.set_item("value_data_inline", inline)?;
                    row.set_item("value_data_raw_size", value.data_raw_size)?;
                }
            }
            row.set_item(
                "cell_relative_offset",
                cell.cell_offset - crate::hive::HIVE_BIN_BASE_OFFSET as u64,
            )?;
            row.set_item("cell_scan_method", "hbin-walk")?;
            row.set_item("hbin_offset", cell.hbin_offset)?;
            row.set_item("cell_index", cell.cell_index)?;
            candidates.append(row)?;
        }
        let counters = PyDict::new_bound(py);
        for (name, count) in stats.0 {
            counters.set_item(name, count)?;
        }
        Ok((candidates, counters))
    }

    /// `extract_utf16le_strings(bytes(data[:scan_end]))`.
    #[pyo3(signature = (scan_end, min_chars = 4, max_strings = 250))]
    fn utf16le_strings(
        &self,
        scan_end: usize,
        min_chars: usize,
        max_strings: usize,
    ) -> PyResult<Vec<String>> {
        let data = self.data()?;
        Ok(scan::utf16le_strings(
            &data[..scan_end.min(data.len())],
            min_chars,
            max_strings,
        ))
    }
}

/// Iterator returned by `RegistryReader.iter_keys`: yields (components tuple, key).
#[pyclass(module = "rapid_registry_native")]
pub struct PyKeyWalk {
    reader: Py<PyReader>,
    walk: KeyWalk<PyEntry>,
}

#[pymethods]
impl PyKeyWalk {
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(&mut self, py: Python<'_>) -> PyResult<Option<(Py<PyTuple>, Py<PyKey>)>> {
        let reader = self.reader.bind(py).borrow();
        let hive = reader.hive()?;
        let mut journal = ErrorJournal::new();
        let mut failure: Option<PyErr> = None;
        let next = self.walk.next_entry(&hive, &mut journal, |parent, key| {
            let parent_parts = parent.parts.bind(py);
            let name = PyString::new_bound(py, &key.name);
            let mut items: Vec<Bound<'_, PyAny>> = parent_parts.iter().collect();
            items.push(name.into_any());
            let parts = PyTuple::new_bound(py, items);
            let (offset, subkey_count, subkey_list_offset) =
                (key.offset, key.subkey_count, key.subkey_list_offset);
            let key = match py_key(py, key) {
                Ok(key) => key,
                Err(error) => {
                    failure.get_or_insert(error);
                    Py::clone_ref(&parent.key, py)
                }
            };
            PyEntry {
                parts: parts.unbind(),
                key,
                offset,
                subkey_count,
                subkey_list_offset,
            }
        });
        let next = next.map(|entry| (entry.parts.clone_ref(py), entry.key.clone_ref(py)));
        reader.flush(py, journal)?;
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(next)
    }
}

/// `bytes.decode("utf-16-le", errors="replace")` — exported for parity tests.
#[pyfunction]
fn decode_utf16le_replace(raw: &[u8]) -> String {
    text::decode_utf16le(raw, true)
}

/// `filetime_to_iso_ticks` — exported for parity tests.
#[pyfunction]
fn filetime_to_iso_ticks(ticks: u64) -> String {
    text::filetime_to_iso_ticks(ticks)
}

#[pymodule]
fn rapid_registry_native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("ABI_VERSION", crate::ABI_VERSION)?;
    module.add("__version__", env!("CARGO_PKG_VERSION"))?;
    module.add_class::<PyReader>()?;
    module.add_class::<PyKey>()?;
    module.add_class::<PyValue>()?;
    module.add_class::<PyKeyWalk>()?;
    module.add_function(wrap_pyfunction!(decode_utf16le_replace, module)?)?;
    module.add_function(wrap_pyfunction!(filetime_to_iso_ticks, module)?)?;
    Ok(())
}
