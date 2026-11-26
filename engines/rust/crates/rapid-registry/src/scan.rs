//! Whole-hive scans: the hbin/cell allocator walk behind `iter_registry_free_cell_candidates`
//! and the bounded UTF-16LE string pivot behind `extract_utf16le_strings`.

use std::collections::HashSet;

use crate::hive::{read_le, Hive, HIVE_BIN_BASE_OFFSET};
use crate::text;

const HBIN_HEADER_SIZE: usize = 32;
const HBIN_ALIGNMENT: usize = 4096;
const KEY_COMP_NAME: u16 = 0x0020;
const VALUE_COMP_NAME: u16 = 0x0001;

/// Insertion-ordered counter mirroring a Python `Counter` built with `+=`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OrderedCounter(pub Vec<(&'static str, u64)>);

impl OrderedCounter {
    pub fn add(&mut self, key: &'static str, amount: u64) {
        match self.0.iter_mut().find(|(name, _)| *name == key) {
            Some((_, count)) => *count += amount,
            None => self.0.push((key, amount)),
        }
    }

    pub fn get(&self, key: &str) -> u64 {
        self.0
            .iter()
            .find(|(name, _)| *name == key)
            .map_or(0, |(_, count)| *count)
    }
}

/// `registry_relative_to_file_offset`.
pub fn relative_to_file_offset(relative: u32) -> u64 {
    if relative == 0 || relative == u32::MAX {
        0
    } else {
        HIVE_BIN_BASE_OFFSET as u64 + u64::from(relative)
    }
}

/// Fields of a free nk cell candidate (`parse_registry_nk_cell` plus the walk's additions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreeKeyCell {
    pub flags: u16,
    pub name: String,
    pub name_encoding: &'static str,
    pub last_written_at: String,
    pub parent_cell_relative_offset: u32,
    pub stable_subkey_count: u32,
    pub volatile_subkey_count: u32,
    pub value_count: u32,
    pub value_list_relative_offset: u32,
}

/// Fields of a free vk cell candidate (`parse_registry_vk_cell`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreeValueCell {
    pub flags: u16,
    pub name: String,
    pub name_encoding: &'static str,
    pub value_type: u32,
    pub data_raw_size: u32,
    pub data_relative_offset: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FreeCellKind {
    Key(FreeKeyCell),
    Value(FreeValueCell),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreeCell {
    pub cell_offset: u64,
    pub cell_size: u64,
    pub hbin_offset: u64,
    pub cell_index: u64,
    pub kind: FreeCellKind,
}

/// `read_u16`/`read_u32`/`read_u64` of the cell helpers: 0 unless the whole field is present.
fn field(blob: &[u8], offset: usize, width: usize) -> u64 {
    if offset + width > blob.len() {
        0
    } else {
        read_le(blob, offset, width)
    }
}

fn name_bytes(blob: &[u8], name_start: usize, name_length: usize, cell_size: usize) -> &[u8] {
    let name_end = (name_start + name_length).min(cell_size);
    if name_end <= name_start || name_start >= blob.len() {
        return &[];
    }
    &blob[name_start..name_end.min(blob.len())]
}

fn parse_nk(blob: &[u8], cell_size: usize) -> Option<FreeKeyCell> {
    let flags = field(blob, 6, 2) as u16;
    let last_written_at = text::filetime_to_iso_ticks(field(blob, 8, 8));
    let name_length = field(blob, 4 + 0x48, 2) as usize;
    let (name, name_encoding) = text::decode_cell_name(
        name_bytes(blob, 4 + 0x4C, name_length, cell_size),
        flags & KEY_COMP_NAME != 0,
    );
    if !text::is_plausible_cell_name(&name) && last_written_at.is_empty() {
        return None;
    }
    Some(FreeKeyCell {
        flags,
        name,
        name_encoding,
        last_written_at,
        parent_cell_relative_offset: field(blob, 4 + 0x10, 4) as u32,
        stable_subkey_count: field(blob, 4 + 0x14, 4) as u32,
        volatile_subkey_count: field(blob, 4 + 0x18, 4) as u32,
        value_count: field(blob, 4 + 0x24, 4) as u32,
        value_list_relative_offset: field(blob, 4 + 0x28, 4) as u32,
    })
}

fn parse_vk(blob: &[u8], cell_size: usize) -> Option<FreeValueCell> {
    let name_length = field(blob, 6, 2) as usize;
    let flags = field(blob, 20, 2) as u16;
    let (name, name_encoding) = text::decode_cell_name(
        name_bytes(blob, 24, name_length, cell_size),
        flags & VALUE_COMP_NAME != 0,
    );
    if !text::is_plausible_cell_name(&name) {
        return None;
    }
    Some(FreeValueCell {
        flags,
        name,
        name_encoding,
        value_type: field(blob, 16, 4) as u32,
        data_raw_size: field(blob, 8, 4) as u32,
        data_relative_offset: field(blob, 12, 4) as u32,
    })
}

/// `iter_registry_free_cell_candidates`: walk every hbin up to the readable hive-bin end,
/// counting allocator state and returning free nk/vk cells (no cap).
pub fn free_cell_candidates(hive: &Hive<'_>) -> (Vec<FreeCell>, OrderedCounter) {
    let data = hive.data;
    let end = hive.geometry.hbin_end as u64;
    let mut candidates = Vec::new();
    let mut stats = OrderedCounter::default();
    let mut offset = HIVE_BIN_BASE_OFFSET as u64;
    while offset + HBIN_HEADER_SIZE as u64 <= end {
        let bin = offset as usize;
        if &data[bin..bin + 4] != b"hbin" {
            stats.add("hbin-signature-gap", 1);
            offset += HBIN_ALIGNMENT as u64;
            continue;
        }
        let hbin_size = read_le(data, bin + 8, 4);
        if hbin_size < HBIN_ALIGNMENT as u64 || !hbin_size.is_multiple_of(HBIN_ALIGNMENT as u64) {
            stats.add("hbin-size-invalid", 1);
            offset += HBIN_ALIGNMENT as u64;
            continue;
        }
        stats.add("hbin_count", 1);
        let hbin_end = end.min(offset + hbin_size) as usize;
        stats.add("hbin_walked_bytes", hbin_end as u64 - offset);
        let mut cursor = bin + HBIN_HEADER_SIZE;
        while cursor + 8 <= hbin_end {
            let raw_size = read_le(data, cursor, 4) as u32 as i32;
            let size = i64::from(raw_size).unsigned_abs() as usize;
            if size < 8 || cursor + size > hbin_end {
                stats.add("cell-walk-break", 1);
                break;
            }
            let signature = &data[cursor + 4..cursor + 6];
            let free = raw_size > 0;
            if signature == b"nk" {
                stats.add(if free { "free_nk" } else { "allocated_nk" }, 1);
            } else if signature == b"vk" {
                stats.add(if free { "free_vk" } else { "allocated_vk" }, 1);
            }
            if free && (signature == b"nk" || signature == b"vk") {
                let cell = &data[cursor..cursor + size];
                let kind = if signature == b"nk" {
                    parse_nk(cell, size).map(FreeCellKind::Key)
                } else {
                    parse_vk(cell, size).map(FreeCellKind::Value)
                };
                if let Some(kind) = kind {
                    candidates.push(FreeCell {
                        cell_offset: cursor as u64,
                        cell_size: size as u64,
                        hbin_offset: offset,
                        cell_index: candidates.len() as u64,
                        kind,
                    });
                }
            }
            cursor += size + (8 - size % 8) % 8;
        }
        offset += hbin_size;
    }
    (candidates, stats)
}

fn printable_unit(unit: u16) -> bool {
    matches!(unit, 9 | 10 | 13 | 32..=0xD7FF | 0xE000..=0xFFFD)
}

/// `extract_utf16le_strings(blob)`: printable UTF-16LE runs at both byte alignments, stripped,
/// at least `min_chars` long, de-duplicated, stopping at `max_strings`.
pub fn utf16le_strings(blob: &[u8], min_chars: usize, max_strings: usize) -> Vec<String> {
    let mut strings: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut accept = |run: &[u8], strings: &mut Vec<String>| -> bool {
        let text = text::decode_utf16le_stripped(run);
        if text.chars().count() >= min_chars && !seen.contains(&text) {
            seen.insert(text.clone());
            strings.push(text);
            return strings.len() >= max_strings;
        }
        false
    };
    for alignment in 0..2 {
        let mut start: Option<usize> = None;
        let mut cursor = alignment;
        while cursor + 1 < blob.len() {
            let unit = u16::from_le_bytes([blob[cursor], blob[cursor + 1]]);
            if printable_unit(unit) {
                start.get_or_insert(cursor);
            } else if let Some(begin) = start.take() {
                if accept(&blob[begin..cursor], &mut strings) {
                    return strings;
                }
            }
            cursor += 2;
        }
        if let Some(begin) = start {
            if accept(&blob[begin..cursor.min(blob.len())], &mut strings) {
                return strings;
            }
        }
    }
    strings
}
