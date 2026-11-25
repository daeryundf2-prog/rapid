use crate::bytes::{int_from_u128, u16_at, u32_at, u64_at, utf16_ignore, utf16_strict};
use crate::dict;
use crate::filetime::filetime_to_iso;
use crate::flags::{
    flag_names, unknown_flag_mask, NTFS_FILE_ATTRIBUTE_NAMES, USN_REASON_FLAGS,
    USN_SOURCE_INFO_FLAGS,
};
use crate::value::Value;

pub const USN_RECORD_SCAN_LIMIT: i64 = 5000;
const LARGE_RECORD_THRESHOLD: usize = 512;
const V4_EXTENT_PREVIEW_LIMIT: usize = 64;

struct Layout {
    minimum_length: usize,
    parent_reference_offset: usize,
    reference_size: usize,
    usn_offset: usize,
    timestamp_offset: usize,
    reason_offset: usize,
    source_info_offset: usize,
    security_id_offset: usize,
    file_attributes_offset: usize,
    name_length_offset: usize,
    name_offset_offset: usize,
}

const V2: Layout = Layout {
    minimum_length: 60,
    parent_reference_offset: 16,
    reference_size: 8,
    usn_offset: 24,
    timestamp_offset: 32,
    reason_offset: 40,
    source_info_offset: 44,
    security_id_offset: 48,
    file_attributes_offset: 52,
    name_length_offset: 56,
    name_offset_offset: 58,
};

const V3: Layout = Layout {
    minimum_length: 76,
    parent_reference_offset: 24,
    reference_size: 16,
    usn_offset: 40,
    timestamp_offset: 48,
    reason_offset: 56,
    source_info_offset: 60,
    security_id_offset: 64,
    file_attributes_offset: 68,
    name_length_offset: 72,
    name_offset_offset: 74,
};

fn reason_string(reason: u64, names: &[String]) -> String {
    if names.is_empty() {
        format!("0x{reason:08x}")
    } else {
        names.join("|")
    }
}

fn rename_hint(names: &[String]) -> &'static str {
    let has_old = names.iter().any(|name| name == "RENAME_OLD_NAME");
    let has_new = names.iter().any(|name| name == "RENAME_NEW_NAME");
    match (has_old, has_new) {
        (true, true) => "rename-old-and-new",
        (true, false) => "rename-old-name",
        (false, true) => "rename-new-name",
        (false, false) => "",
    }
}

fn size_class(length: usize) -> &'static str {
    if length >= LARGE_RECORD_THRESHOLD {
        "large"
    } else {
        "standard"
    }
}

fn reference_value(value: u128, size: usize) -> Value {
    if size == 8 {
        Value::from(value as u64)
    } else {
        Value::U128(value)
    }
}

fn decode_reference(value: u128, size: usize) -> Value {
    if size == 8 {
        let value = value as u64;
        dict! {
            "format" => "mft-reference-64",
            "record_number" => value & 0x0000_FFFF_FFFF_FFFF,
            "sequence_number" => (value >> 48) & 0xFFFF,
        }
    } else {
        dict! { "format" => "file-id-128", "hex" => format!("{value:032x}") }
    }
}

struct Parsed {
    value: Value,
    next_cursor: usize,
    record_length: usize,
    timestamp: String,
}

fn parse_usn_v4_record(record: &[u8], offset: usize) -> Option<Parsed> {
    let length = u32_at(record, 0) as usize;
    if length < 64 {
        return None;
    }
    let end = offset + length;
    let reason = u32_at(record, 48);
    let source_info = u32_at(record, 52);
    let extent_count = u16_at(record, 60);
    let extent_size = u16_at(record, 62);
    let table = 64usize;
    let expected_bytes = extent_count * extent_size;
    let bounds_valid = extent_size >= 16
        && table + expected_bytes <= length
        && extent_count <= V4_EXTENT_PREVIEW_LIMIT;
    let mut extents = Vec::new();
    if extent_size >= 16 {
        for index in 0..extent_count.min(V4_EXTENT_PREVIEW_LIMIT) {
            let extent = table + index * extent_size;
            if extent + 16 > length {
                break;
            }
            extents.push(dict! {
                "extent_index" => index,
                "source_offset" => offset + extent,
                "file_offset" => u64_at(record, extent),
                "byte_length" => u64_at(record, extent + 8),
            });
        }
    }
    let names = flag_names(reason, USN_REASON_FLAGS);
    let unknown_reason = unknown_flag_mask(reason, USN_REASON_FLAGS);
    let mut warnings: Vec<&str> = Vec::new();
    if !length.is_multiple_of(8) {
        warnings.push("record-length-not-8-byte-aligned");
    }
    if extent_size < 16 {
        warnings.push("v4-extent-size-too-small");
    }
    if table + expected_bytes > length {
        warnings.push("v4-extents-overrun-record");
    }
    if extent_count > V4_EXTENT_PREVIEW_LIMIT {
        warnings.push("v4-extent-preview-limit-reached");
    }
    if reason != 0 && names.is_empty() {
        warnings.push("unknown-reason-flags");
    }
    if unknown_reason != 0 {
        warnings.push("reason-has-unknown-bits");
    }
    if reason == 0 {
        warnings.push("empty-reason");
    }
    let status = if warnings.is_empty() {
        "valid"
    } else {
        "valid-with-warnings"
    };
    let payload = (table + extents.len() * extent_size) as i64;
    let extent_total = extents.len();
    let file_reference = int_from_u128(record, 8, 16);
    let parent_reference = int_from_u128(record, 24, 16);
    let value = dict! {
        "record_offset" => offset,
        "record_cursor" => offset,
        "next_record_cursor" => end,
        "record_end_offset" => end,
        "record_length" => length,
        "record_payload_bytes" => payload,
        "record_padding_bytes" => (length as i64 - payload).max(0),
        "record_size_class" => size_class(length),
        "major_version" => 4u64,
        "minor_version" => u16_at(record, 6),
        "file_reference_number" => Value::U128(file_reference),
        "parent_file_reference_number" => Value::U128(parent_reference),
        "file_reference_number_decoded" => decode_reference(file_reference, 16),
        "parent_file_reference_number_decoded" => decode_reference(parent_reference, 16),
        "usn" => u64_at(record, 40),
        "timestamp" => "",
        "timestamp_filetime" => 0u64,
        "reason" => reason_string(reason, &names),
        "reason_raw" => reason,
        "reason_flags" => names.clone(),
        "unknown_reason_mask" => unknown_reason,
        "source_info" => source_info,
        "source_info_flags" => flag_names(source_info, USN_SOURCE_INFO_FLAGS),
        "unknown_source_info_mask" => unknown_flag_mask(source_info, USN_SOURCE_INFO_FLAGS),
        "security_id" => 0u64,
        "file_attributes" => 0u64,
        "file_attribute_names" => Vec::<String>::new(),
        "unknown_file_attribute_mask" => 0u64,
        "file_name_length" => 0u64,
        "file_name_offset" => 0u64,
        "file_name_character_count" => 0u64,
        "file_name_decode_status" => "not-present-usn-v4",
        "file_name" => "",
        "deleted_hint" => names.iter().any(|name| name == "FILE_DELETE"),
        "rename_hint" => rename_hint(&names),
        "v4_remaining_extents" => u32_at(record, 56),
        "v4_extent_count" => extent_count,
        "v4_extent_size" => extent_size,
        "v4_extent_preview_limit" => V4_EXTENT_PREVIEW_LIMIT,
        "v4_extents" => Value::List(extents),
        "validation_status" => status,
        "validation_warnings" => warnings.iter().map(|w| w.to_string()).collect::<Vec<_>>(),
        "validation_checks" => dict! {
            "record_length_aligned" => length.is_multiple_of(8),
            "record_cursor_progresses" => end > offset,
            "filename_bounds_valid" => true,
            "filename_utf16_valid" => true,
            "filetime_plausible" => true,
            "version_supported" => true,
            "v4_extent_bounds_valid" => bounds_valid,
            "v4_extent_count_matches" => extent_total == extent_count.min(V4_EXTENT_PREVIEW_LIMIT),
            "v4_no_filename_by_design" => true,
            "known_reason_bits_only" => unknown_reason == 0,
            "large_record" => length >= LARGE_RECORD_THRESHOLD,
        },
        "parser_confidence" => if status == "valid" { 0.82 } else { 0.68 },
    };
    Some(Parsed {
        value,
        next_cursor: end,
        record_length: length,
        timestamp: String::new(),
    })
}

/// `parse_usn_record_at` of filesystem.py.
fn parse_usn_record_at(blob: &[u8], offset: usize) -> Option<Parsed> {
    let length = u32_at(blob, offset) as usize;
    let major = u16_at(blob, offset + 4);
    if !(60..=65536).contains(&length) || offset + length > blob.len() || !(2..=4).contains(&major)
    {
        return None;
    }
    let record = &blob[offset..offset + length];
    if major == 4 {
        return parse_usn_v4_record(record, offset);
    }
    let layout = if major == 2 { &V2 } else { &V3 };
    if length < layout.minimum_length {
        return None;
    }
    let name_length = u16_at(record, layout.name_length_offset);
    let name_offset = u16_at(record, layout.name_offset_offset);
    if name_offset < layout.minimum_length || name_length == 0 || name_offset + name_length > length
    {
        return None;
    }
    let filetime = u64_at(record, layout.timestamp_offset);
    let timestamp = filetime_to_iso(filetime);
    let reason = u32_at(record, layout.reason_offset);
    let source_info = u32_at(record, layout.source_info_offset);
    let file_attributes = u32_at(record, layout.file_attributes_offset);
    let names = flag_names(reason, USN_REASON_FLAGS);
    let unknown_reason = unknown_flag_mask(reason, USN_REASON_FLAGS);
    let name_blob = &record[name_offset..name_offset + name_length];
    let (file_name, decode_status) = match utf16_strict(name_blob) {
        Some(name) => (name, "valid"),
        None => (utf16_ignore(name_blob), "invalid-utf16"),
    };
    let mut warnings: Vec<&str> = Vec::new();
    if !(2..=3).contains(&major) {
        warnings.push("unsupported-usn-record-version");
    }
    if !length.is_multiple_of(8) {
        warnings.push("record-length-not-8-byte-aligned");
    }
    if !name_length.is_multiple_of(2) {
        warnings.push("filename-length-not-utf16-even");
    }
    if !name_offset.is_multiple_of(2) {
        warnings.push("filename-offset-not-utf16-even");
    }
    if timestamp.is_empty() {
        warnings.push("invalid-filetime");
    }
    if reason != 0 && names.is_empty() {
        warnings.push("unknown-reason-flags");
    }
    if unknown_reason != 0 {
        warnings.push("reason-has-unknown-bits");
    }
    if reason == 0 {
        warnings.push("empty-reason");
    }
    if decode_status != "valid" {
        warnings.push("filename-invalid-utf16");
    }
    let status = if warnings.is_empty() {
        "valid"
    } else {
        "valid-with-warnings"
    };
    let file_reference = int_from_u128(record, 8, layout.reference_size);
    let parent_reference = int_from_u128(
        record,
        layout.parent_reference_offset,
        layout.reference_size,
    );
    let end = offset + length;
    let payload = name_offset + name_length;
    let character_count = file_name.chars().count();
    let value = dict! {
        "record_offset" => offset,
        "record_cursor" => offset,
        "next_record_cursor" => end,
        "record_end_offset" => end,
        "record_length" => length,
        "record_payload_bytes" => payload,
        "record_padding_bytes" => length.saturating_sub(payload),
        "record_size_class" => size_class(length),
        "major_version" => major,
        "minor_version" => u16_at(record, 6),
        "file_reference_number" => reference_value(file_reference, layout.reference_size),
        "parent_file_reference_number" => reference_value(parent_reference, layout.reference_size),
        "file_reference_number_decoded" => decode_reference(file_reference, layout.reference_size),
        "parent_file_reference_number_decoded" => decode_reference(parent_reference, layout.reference_size),
        "usn" => u64_at(record, layout.usn_offset),
        "timestamp" => timestamp.as_str(),
        "timestamp_filetime" => filetime,
        "reason" => reason_string(reason, &names),
        "reason_raw" => reason,
        "reason_flags" => names.clone(),
        "unknown_reason_mask" => unknown_reason,
        "source_info" => source_info,
        "source_info_flags" => flag_names(source_info, USN_SOURCE_INFO_FLAGS),
        "unknown_source_info_mask" => unknown_flag_mask(source_info, USN_SOURCE_INFO_FLAGS),
        "security_id" => u32_at(record, layout.security_id_offset),
        "file_attributes" => file_attributes,
        "file_attribute_names" => flag_names(file_attributes, NTFS_FILE_ATTRIBUTE_NAMES),
        "unknown_file_attribute_mask" => unknown_flag_mask(file_attributes, NTFS_FILE_ATTRIBUTE_NAMES),
        "file_name_length" => name_length,
        "file_name_offset" => name_offset,
        "file_name_character_count" => character_count,
        "file_name_decode_status" => decode_status,
        "file_name" => file_name,
        "deleted_hint" => names.iter().any(|name| name == "FILE_DELETE"),
        "rename_hint" => rename_hint(&names),
        "validation_status" => status,
        "validation_warnings" => warnings.iter().map(|w| w.to_string()).collect::<Vec<_>>(),
        "validation_checks" => dict! {
            "record_length_aligned" => length.is_multiple_of(8),
            "record_cursor_progresses" => end > offset,
            "filename_bounds_valid" => name_offset >= layout.minimum_length && name_offset + name_length <= length,
            "filename_utf16_valid" => decode_status == "valid",
            "filetime_plausible" => !timestamp.is_empty(),
            "version_supported" => (2..=3).contains(&major),
            "known_reason_bits_only" => unknown_reason == 0,
            "large_record" => length >= LARGE_RECORD_THRESHOLD,
        },
        "parser_confidence" => if status == "valid" { 0.85 } else { 0.7 },
    };
    Some(Parsed {
        value,
        next_cursor: end,
        record_length: length,
        timestamp,
    })
}

/// `parse_usn_record_scan` of filesystem.py without `cursor_window_profile`.
pub fn parse_usn_record_scan(
    blob: &[u8],
    record_limit: i64,
    start_offset: i64,
    max_scan_bytes: Option<i64>,
) -> Value {
    let start = (start_offset.max(0) as u64).min(blob.len() as u64) as usize;
    let stop = match max_scan_bytes {
        Some(limit) => blob.len().min(start.saturating_add(limit.max(0) as usize)),
        None => blob.len(),
    };
    let mut records: Vec<Parsed> = Vec::new();
    let mut offset = start;
    let mut skipped: u64 = 0;
    let mut partial = false;
    while offset + 60 <= stop {
        let Some(record) = parse_usn_record_at(blob, offset) else {
            skipped += 1;
            if blob[offset] == 0 {
                let gap_end = blob[offset..stop]
                    .iter()
                    .position(|byte| *byte != 0)
                    .map_or(stop, |position| offset + position);
                if gap_end - offset >= 4 {
                    skipped += (gap_end - offset - 4) as u64;
                    offset = gap_end - 3;
                    continue;
                }
            }
            offset += 1;
            continue;
        };
        if record.next_cursor > stop {
            partial = true;
            break;
        }
        offset = record.next_cursor;
        records.push(record);
        if records.len() as i64 >= record_limit {
            break;
        }
    }
    let mut timestamps: Vec<&str> = records
        .iter()
        .map(|record| record.timestamp.as_str())
        .filter(|timestamp| !timestamp.is_empty())
        .collect();
    timestamps.sort_unstable();
    let resumable = partial || offset + 60 <= blob.len();
    let next_available = !records.is_empty() && resumable;
    let first_offset = records.first().map(|record| {
        record
            .value
            .get("record_offset")
            .cloned()
            .unwrap_or(Value::None)
    });
    let last_offset = records.last().map(|record| {
        record
            .value
            .get("record_offset")
            .cloned()
            .unwrap_or(Value::None)
    });
    let first_offset_number = first_offset.as_ref().and_then(Value::as_int);
    let large = records
        .iter()
        .filter(|record| record.record_length >= LARGE_RECORD_THRESHOLD)
        .count();
    let largest = records
        .iter()
        .map(|record| record.record_length)
        .max()
        .unwrap_or(0);
    let record_count = records.len() as i64;
    let timestamp_range = dict! {
        "earliest" => timestamps.first().copied().unwrap_or(""),
        "latest" => timestamps.last().copied().unwrap_or(""),
    };
    let next_cursor = if next_available {
        Value::from(offset)
    } else {
        Value::None
    };
    dict! {
        "records" => Value::List(records.into_iter().map(|record| record.value).collect()),
        "scan_start_offset" => start,
        "scan_end_offset" => blob.len(),
        "scan_stop_offset" => stop,
        "scan_window_bytes" => stop.saturating_sub(start),
        "max_scan_bytes" => max_scan_bytes,
        "last_scanned_offset" => offset,
        "first_record_offset" => first_offset.unwrap_or(Value::None),
        "last_record_offset" => last_offset.unwrap_or(Value::None),
        "next_cursor_offset" => next_cursor.clone(),
        "resume_start_offset" => next_cursor,
        "next_cursor_available" => next_available,
        "record_limit" => record_limit,
        "record_limit_reached" => record_count >= record_limit && resumable,
        "partial_record_at_scan_end" => partial,
        "skipped_bytes_before_records" => match first_offset_number {
            Some(first) => Value::Int(first - start as i128),
            None => Value::from(skipped),
        },
        "skipped_bytes_during_scan" => skipped,
        "trailing_unparsed_bytes" => blob.len().saturating_sub(offset),
        "trailing_unparsed_window_bytes" => stop.saturating_sub(offset),
        "large_record_count" => large,
        "largest_record_length" => largest,
        "timestamp_range" => timestamp_range,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v2(name: &str, reason: u32, frn: u64, parent: u64, usn: u64, filetime: u64) -> Vec<u8> {
        let encoded: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let length = (60 + encoded.len() + 7) & !7;
        let mut record = vec![0u8; length];
        record[0..4].copy_from_slice(&(length as u32).to_le_bytes());
        record[4..6].copy_from_slice(&2u16.to_le_bytes());
        record[8..16].copy_from_slice(&frn.to_le_bytes());
        record[16..24].copy_from_slice(&parent.to_le_bytes());
        record[24..32].copy_from_slice(&usn.to_le_bytes());
        record[32..40].copy_from_slice(&filetime.to_le_bytes());
        record[40..44].copy_from_slice(&reason.to_le_bytes());
        record[56..58].copy_from_slice(&(encoded.len() as u16).to_le_bytes());
        record[58..60].copy_from_slice(&60u16.to_le_bytes());
        record[60..60 + encoded.len()].copy_from_slice(&encoded);
        record
    }

    #[test]
    fn rename_pair_decodes_names_references_and_ticks() {
        let parent = (4u64 << 48) | 11;
        let mut blob = v2(
            "old.txt",
            0x1000,
            (3u64 << 48) | 42,
            parent,
            8,
            133_485_408_000_000_007,
        );
        blob.extend(vec![0u8; 64]);
        blob.extend(v2(
            "new.txt",
            0x2000,
            (3u64 << 48) | 42,
            parent,
            9,
            133_485_408_000_000_009,
        ));
        let scan = parse_usn_record_scan(&blob, USN_RECORD_SCAN_LIMIT, 0, None);
        let Some(Value::List(records)) = scan.get("records") else {
            panic!("records missing");
        };
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0].get("rename_hint").and_then(Value::as_str),
            Some("rename-old-name")
        );
        assert_eq!(
            records[1].get("file_name").and_then(Value::as_str),
            Some("new.txt")
        );
        assert_eq!(
            records[1].get("timestamp_filetime"),
            Some(&Value::Int(133_485_408_000_000_009))
        );
        let parent_decoded = records[0]
            .get("parent_file_reference_number_decoded")
            .unwrap();
        assert_eq!(parent_decoded.get("record_number"), Some(&Value::Int(11)));
        assert_eq!(parent_decoded.get("sequence_number"), Some(&Value::Int(4)));
    }

    #[test]
    fn window_limit_marks_partial_record() {
        let record = v2("a.txt", 0x100, 1, 5, 1, 1);
        let mut blob = record.clone();
        blob.extend(&record);
        let scan = parse_usn_record_scan(
            &blob,
            USN_RECORD_SCAN_LIMIT,
            0,
            Some(record.len() as i64 + 60),
        );
        assert_eq!(
            scan.get("partial_record_at_scan_end"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            scan.get("last_scanned_offset"),
            Some(&Value::Int(record.len() as i128))
        );
    }
}
