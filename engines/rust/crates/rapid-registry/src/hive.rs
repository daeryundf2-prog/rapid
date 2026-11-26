//! Read-only regf cell reader: a line-for-line port of `NativeRegistryHive` in
//! `rapidtriage/artifacts/windows/registry.py`.
//!
//! Every read keeps the Python semantics: byte slices past the end of the data are short (and
//! read as the little-endian value of the bytes that exist), cell bounds are checked against the
//! readable hive-bin end, and every structural problem is appended to an error journal under the
//! same counter key, in the same order, as the Python reader's `errors` Counter.

use std::collections::HashSet;

use crate::text;

pub const HIVE_BIN_BASE_OFFSET: usize = 4096;
pub const BIG_DATA_SEGMENT_SIZE: usize = 16344;
const KEY_COMP_NAME: u16 = 0x0020;
const VALUE_COMP_NAME: u16 = 0x0001;
const MAX_SUBKEY_LIST_DEPTH: usize = 8;

/// Ordered walk-error events (one entry per Python `errors[key] += 1`).
pub type ErrorJournal = Vec<&'static str>;

/// `bytes[offset:offset + width]` read as a little-endian integer (short slices read short).
pub fn read_le(data: &[u8], offset: usize, width: usize) -> u64 {
    if offset >= data.len() {
        return 0;
    }
    let end = offset.saturating_add(width).min(data.len());
    data[offset..end]
        .iter()
        .rev()
        .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte))
}

fn slice(data: &[u8], start: usize, end: usize) -> &[u8] {
    let start = start.min(data.len());
    &data[start..end.clamp(start, data.len())]
}

fn signature_is(data: &[u8], offset: usize, signature: &[u8; 2]) -> bool {
    offset.checked_add(2).and_then(|end| data.get(offset..end)) == Some(signature.as_slice())
}

/// Hive geometry the Python reader derives from the base block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    pub hbin_end: usize,
    pub minor_version: u32,
    pub root_cell_offset: u32,
}

impl Geometry {
    /// `NativeRegistryHive.__init__`: header fields from the first 4096 bytes (0 when absent).
    pub fn from_data(data: &[u8]) -> Self {
        let header = &data[..data.len().min(HIVE_BIN_BASE_OFFSET)];
        let field = |offset: usize| -> u32 {
            if offset + 4 > header.len() {
                0
            } else {
                read_le(header, offset, 4) as u32
            }
        };
        let hbin_size = field(40) as usize;
        let hbin_end = if hbin_size != 0 {
            data.len().min(HIVE_BIN_BASE_OFFSET + hbin_size)
        } else {
            data.len()
        };
        Self {
            hbin_end,
            minor_version: field(24),
            root_cell_offset: field(36),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    pub offset: u32,
    pub name: String,
    pub name_encoding: &'static str,
    pub flags: u16,
    pub last_written_filetime: u64,
    pub parent_offset: u32,
    pub subkey_count: u32,
    pub subkey_list_offset: u32,
    pub value_count: u32,
    pub value_list_offset: u32,
    pub allocated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Value {
    pub offset: u32,
    pub name: String,
    pub name_encoding: &'static str,
    pub value_type: u32,
    pub data_size: u32,
    pub data_offset: u32,
    pub inline: bool,
    pub flags: u16,
    pub allocated: bool,
}

/// Decoded value data, as `decode_registry_value_data` returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueData {
    Text(String),
    MultiText(Vec<String>),
    /// Unsigned integer of up to 8 bytes (DWORD, big-endian DWORD, QWORD).
    Integer(u64),
    Bytes(Vec<u8>),
}

pub fn decode_value_data(value_type: u32, raw: Vec<u8>) -> ValueData {
    match value_type {
        1 | 2 | 6 => ValueData::Text(text::decode_registry_sz(&raw)),
        7 => ValueData::MultiText(text::decode_registry_multi_sz(&raw)),
        4 => ValueData::Integer(read_le(&raw, 0, 4)),
        5 => ValueData::Integer(
            raw.iter()
                .take(4)
                .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte)),
        ),
        11 => ValueData::Integer(read_le(&raw, 0, 8)),
        _ => ValueData::Bytes(raw),
    }
}

/// A borrowed view of one hive plus the geometry `NativeRegistryHive` computed for it.
#[derive(Debug, Clone, Copy)]
pub struct Hive<'a> {
    pub data: &'a [u8],
    pub geometry: Geometry,
}

impl<'a> Hive<'a> {
    pub fn new(data: &'a [u8], geometry: Geometry) -> Self {
        Self { data, geometry }
    }

    fn u16_at(&self, offset: usize) -> u16 {
        read_le(self.data, offset, 2) as u16
    }

    fn u32_at(&self, offset: usize) -> u32 {
        read_le(self.data, offset, 4) as u32
    }

    fn u64_at(&self, offset: usize) -> u64 {
        read_le(self.data, offset, 8)
    }

    /// `_cell`: (data_start, data_length, allocated) of a referenced cell.
    pub fn cell(
        &self,
        relative_offset: u32,
        errors: &mut ErrorJournal,
    ) -> Option<(usize, usize, bool)> {
        if relative_offset == 0 || relative_offset == u32::MAX {
            return None;
        }
        if !relative_offset.is_multiple_of(8) {
            errors.push("misaligned-cell-offset");
            return None;
        }
        let offset = HIVE_BIN_BASE_OFFSET + relative_offset as usize;
        let hbin_end = self.geometry.hbin_end;
        if offset + 8 > hbin_end {
            errors.push("cell-offset-out-of-bounds");
            return None;
        }
        let raw_size = read_le(self.data, offset, 4) as u32 as i32;
        let size = i64::from(raw_size).unsigned_abs() as usize;
        if size < 8 || offset + size > hbin_end {
            errors.push("cell-size-invalid");
            return None;
        }
        if raw_size > 0 {
            errors.push("free-cell-referenced");
        }
        Some((offset + 4, size - 4, raw_size < 0))
    }

    pub fn key_at(&self, relative_offset: u32, errors: &mut ErrorJournal) -> Option<Key> {
        let (start, length, allocated) = self.cell(relative_offset, errors)?;
        if length < 76 || !signature_is(self.data, start, b"nk") {
            errors.push("nk-signature-mismatch");
            return None;
        }
        let flags = self.u16_at(start + 2);
        let name_length = usize::from(self.u16_at(start + 72));
        let raw_name = slice(
            self.data,
            start + 76,
            start + 76 + name_length.min(length - 76),
        );
        let (name, name_encoding) = text::decode_native_name(raw_name, flags & KEY_COMP_NAME != 0);
        Some(Key {
            offset: relative_offset,
            name,
            name_encoding,
            flags,
            last_written_filetime: self.u64_at(start + 4),
            parent_offset: self.u32_at(start + 16),
            subkey_count: self.u32_at(start + 20),
            subkey_list_offset: self.u32_at(start + 28),
            value_count: self.u32_at(start + 36),
            value_list_offset: self.u32_at(start + 40),
            allocated,
        })
    }

    fn subkey_offsets(
        &self,
        list_offset: u32,
        depth: usize,
        offsets: &mut Vec<u32>,
        errors: &mut ErrorJournal,
    ) {
        if depth > MAX_SUBKEY_LIST_DEPTH {
            errors.push("subkey-list-depth-exceeded");
            return;
        }
        let Some((start, length, _allocated)) = self.cell(list_offset, errors) else {
            return;
        };
        let count = usize::from(self.u16_at(start + 2));
        if signature_is(self.data, start, b"lf") || signature_is(self.data, start, b"lh") {
            for index in 0..count.min((length - 4) / 8) {
                offsets.push(self.u32_at(start + 4 + index * 8));
            }
        } else if signature_is(self.data, start, b"li") {
            for index in 0..count.min((length - 4) / 4) {
                offsets.push(self.u32_at(start + 4 + index * 4));
            }
        } else if signature_is(self.data, start, b"ri") {
            for index in 0..count.min((length - 4) / 4) {
                let nested = self.u32_at(start + 4 + index * 4);
                self.subkey_offsets(nested, depth + 1, offsets, errors);
            }
        } else {
            errors.push("subkey-list-signature-unknown");
        }
    }

    pub fn subkeys(&self, key: &Key, errors: &mut ErrorJournal) -> Vec<Key> {
        self.subkeys_of(key.subkey_count, key.subkey_list_offset, errors)
    }

    /// `subkeys` for a key known only by its subkey count and subkey-list offset.
    pub fn subkeys_of(
        &self,
        subkey_count: u32,
        subkey_list_offset: u32,
        errors: &mut ErrorJournal,
    ) -> Vec<Key> {
        if subkey_count == 0 {
            return Vec::new();
        }
        let mut offsets = Vec::new();
        self.subkey_offsets(subkey_list_offset, 0, &mut offsets, errors);
        let children: Vec<Key> = offsets
            .into_iter()
            .filter_map(|offset| self.key_at(offset, errors))
            .collect();
        if children.len() != subkey_count as usize {
            errors.push("subkey-count-mismatch");
        }
        children
    }

    pub fn values(&self, key: &Key, errors: &mut ErrorJournal) -> Vec<Value> {
        self.values_of(key.value_count, key.value_list_offset, errors)
    }

    /// `values` for a key known only by its value count and value-list offset.
    pub fn values_of(
        &self,
        value_count: u32,
        value_list_offset: u32,
        errors: &mut ErrorJournal,
    ) -> Vec<Value> {
        if value_count == 0 {
            return Vec::new();
        }
        let Some((start, length, _allocated)) = self.cell(value_list_offset, errors) else {
            return Vec::new();
        };
        let count = (value_count as usize).min(length / 4);
        (0..count)
            .filter_map(|index| self.value_at(self.u32_at(start + index * 4), errors))
            .collect()
    }

    pub fn value_at(&self, relative_offset: u32, errors: &mut ErrorJournal) -> Option<Value> {
        let (start, length, allocated) = self.cell(relative_offset, errors)?;
        if length < 20 || !signature_is(self.data, start, b"vk") {
            errors.push("vk-signature-mismatch");
            return None;
        }
        let name_length = usize::from(self.u16_at(start + 2));
        let raw_size = self.u32_at(start + 4);
        let flags = self.u16_at(start + 16);
        let raw_name = slice(
            self.data,
            start + 20,
            start + 20 + name_length.min(length - 20),
        );
        let (name, name_encoding) =
            text::decode_native_name(raw_name, flags & VALUE_COMP_NAME != 0);
        Some(Value {
            offset: relative_offset,
            name,
            name_encoding,
            value_type: self.u32_at(start + 12),
            data_size: raw_size & 0x7FFF_FFFF,
            data_offset: self.u32_at(start + 8),
            inline: raw_size & 0x8000_0000 != 0,
            flags,
            allocated,
        })
    }

    /// `cell_allocated`: a read-only probe that records no errors.
    pub fn cell_allocated(&self, relative_offset: u32) -> Option<bool> {
        if relative_offset == 0 || relative_offset == u32::MAX || !relative_offset.is_multiple_of(8)
        {
            return None;
        }
        let offset = HIVE_BIN_BASE_OFFSET + relative_offset as usize;
        let hbin_end = self.geometry.hbin_end;
        if offset + 8 > hbin_end {
            return None;
        }
        let raw_size = read_le(self.data, offset, 4) as u32 as i32;
        let size = i64::from(raw_size).unsigned_abs() as usize;
        if size < 8 || offset + size > hbin_end {
            return None;
        }
        Some(raw_size < 0)
    }

    fn is_big_data(&self, size: usize, start: usize) -> bool {
        size > BIG_DATA_SEGMENT_SIZE
            && self.geometry.minor_version >= 4
            && signature_is(self.data, start, b"db")
    }

    /// `value_data_allocated`: data cell, big-data list and segments must all be allocated.
    pub fn value_data_allocated(&self, value: &Value) -> Option<bool> {
        let size = value.data_size as usize;
        if value.inline || size == 0 {
            return None;
        }
        let state = self.cell_allocated(value.data_offset);
        if state != Some(true) {
            return state;
        }
        let start = HIVE_BIN_BASE_OFFSET + value.data_offset as usize + 4;
        if self.is_big_data(size, start) {
            let list_offset = self.u32_at(start + 4);
            let list_state = self.cell_allocated(list_offset);
            if list_state != Some(true) {
                return list_state;
            }
            let list_start = HIVE_BIN_BASE_OFFSET + list_offset as usize + 4;
            for index in 0..usize::from(self.u16_at(start + 2)) {
                let segment = self.cell_allocated(self.u32_at(list_start + index * 4));
                if segment != Some(true) {
                    return segment;
                }
            }
        }
        Some(true)
    }

    /// `value_bytes`: inline data, one data cell, or the concatenated big-data segments.
    pub fn value_bytes(&self, value: &Value, errors: &mut ErrorJournal) -> Vec<u8> {
        let size = value.data_size as usize;
        if value.inline {
            return value.data_offset.to_le_bytes()[..size.min(4)].to_vec();
        }
        if size == 0 {
            return Vec::new();
        }
        let Some((start, length, _allocated)) = self.cell(value.data_offset, errors) else {
            return Vec::new();
        };
        if self.is_big_data(size, start) {
            let segment_count = usize::from(self.u16_at(start + 2));
            let Some((list_start, list_length, _)) = self.cell(self.u32_at(start + 4), errors)
            else {
                return Vec::new();
            };
            let mut joined = Vec::with_capacity(size);
            let mut remaining = size;
            for index in 0..segment_count.min(list_length / 4) {
                let Some((segment_start, segment_length, _)) =
                    self.cell(self.u32_at(list_start + index * 4), errors)
                else {
                    errors.push("big-data-segment-missing");
                    break;
                };
                let take = remaining.min(segment_length).min(BIG_DATA_SEGMENT_SIZE);
                joined.extend_from_slice(slice(self.data, segment_start, segment_start + take));
                remaining -= take;
                if remaining == 0 {
                    break;
                }
            }
            return joined;
        }
        slice(self.data, start, start + size.min(length)).to_vec()
    }

    pub fn value_data(&self, value: &Value, errors: &mut ErrorJournal) -> ValueData {
        decode_value_data(value.value_type, self.value_bytes(value, errors))
    }
}

/// What [`KeyWalk`] needs to know about one stack entry.
pub trait WalkEntry {
    fn offset(&self) -> u32;
    fn subkey_count(&self) -> u32;
    fn subkey_list_offset(&self) -> u32;
}

impl WalkEntry for (Vec<String>, Key) {
    fn offset(&self) -> u32 {
        self.1.offset
    }
    fn subkey_count(&self) -> u32 {
        self.1.subkey_count
    }
    fn subkey_list_offset(&self) -> u32 {
        self.1.subkey_list_offset
    }
}

/// `iter_keys`: depth-first walk over entries such as (root-relative name components, key).
///
/// Children of the entry returned last are expanded on the following call, exactly when the
/// Python generator resumes, so the error journal interleaves with caller reads the same way.
pub struct KeyWalk<T> {
    stack: Vec<T>,
    visited: HashSet<u32>,
    pending: Option<T>,
}

impl<T: WalkEntry> KeyWalk<T> {
    pub fn new(start: T) -> Self {
        Self {
            stack: vec![start],
            visited: HashSet::new(),
            pending: None,
        }
    }

    /// Next entry; `child` builds a child entry from its parent entry and the child key.
    pub fn next_entry(
        &mut self,
        hive: &Hive<'_>,
        errors: &mut ErrorJournal,
        mut child: impl FnMut(&T, Key) -> T,
    ) -> Option<&T> {
        if let Some(parent) = self.pending.take() {
            let children =
                hive.subkeys_of(parent.subkey_count(), parent.subkey_list_offset(), errors);
            for key in children.into_iter().rev() {
                self.stack.push(child(&parent, key));
            }
        }
        while let Some(entry) = self.stack.pop() {
            if !self.visited.insert(entry.offset()) {
                errors.push("key-cycle-skipped");
                continue;
            }
            return Some(self.pending.insert(entry));
        }
        None
    }
}

/// Child entry for the plain-Rust walk: parent components plus the child's name.
pub fn child_components(parent: &(Vec<String>, Key), key: Key) -> (Vec<String>, Key) {
    let mut parts = parent.0.clone();
    parts.push(key.name.clone());
    (parts, key)
}
