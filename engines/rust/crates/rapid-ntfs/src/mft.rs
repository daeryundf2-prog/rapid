use std::borrow::Cow;

use crate::bytes::{find, hex, int_from, u16_at, u32_at, u64_at, utf16_ignore};
use crate::dict;
use crate::filetime::{filetime_to_iso, FILETIME_OUT_OF_RANGE_ISO};
use crate::flags::{
    attribute_type_name, file_name_namespace, flag_names, NTFS_FILE_ATTRIBUTE_NAMES,
};
use crate::value::Value;

pub const MFT_RECORD_SCAN_LIMIT: usize = 5000;
const SECTOR_SIZE: usize = 512;
const RUNLIST_PREVIEW_BYTE_LIMIT: usize = 256;
const RUNLIST_PREVIEW_RUN_LIMIT: usize = 64;
const PLAUSIBLE_RECORD_SIZES: [usize; 3] = [1024, 2048, 4096];
const TIMESTAMP_FIELDS: [&str; 4] = [
    "created_at",
    "modified_at",
    "mft_modified_at",
    "accessed_at",
];

fn align8(value: usize) -> usize {
    (value + 7) & !7
}

fn split_mft_reference(value: u64) -> Value {
    dict! {
        "record_number" => value & 0x0000_FFFF_FFFF_FFFF,
        "sequence_number" => (value >> 48) & 0xFFFF,
    }
}

/// `mft_volume_record_size`: the record size voted for by records whose own geometry agrees.
pub fn mft_volume_record_size(blob: &[u8]) -> Option<usize> {
    let mut votes = [0usize; 3];
    let mut offset = 0;
    let mut seen = 0;
    while seen < 5000 {
        let Some(hit) = find(blob, b"FILE", offset) else {
            break;
        };
        offset = hit;
        if offset + 48 <= blob.len() {
            seen += 1;
            let allocated = u32_at(blob, offset + 0x1C) as usize;
            if let Some(index) = PLAUSIBLE_RECORD_SIZES
                .iter()
                .position(|size| *size == allocated)
            {
                if offset % allocated == 0 && offset + allocated <= blob.len() {
                    let header_agrees = u16_at(blob, offset + 0x04) < 0x30
                        || u32_at(blob, offset + 0x2C) == (offset / allocated) as u64;
                    if header_agrees {
                        votes[index] += 1;
                    }
                }
            }
        }
        offset += 4;
    }
    (0..3)
        .filter(|index| votes[*index] > 0)
        .max_by_key(|index| (votes[*index], PLAUSIBLE_RECORD_SIZES[*index]))
        .map(|index| PLAUSIBLE_RECORD_SIZES[index])
}

struct SequenceValidation {
    status: &'static str,
    warnings: Vec<String>,
    value: Value,
}

fn validate_mft_update_sequence(record: &[u8]) -> SequenceValidation {
    let usa_offset = u16_at(record, 0x04);
    let usa_count = u16_at(record, 0x06);
    let early = |status: &'static str, warning: &str| SequenceValidation {
        status,
        warnings: vec![warning.to_string()],
        value: dict! {
            "status" => status,
            "warnings" => vec![warning.to_string()],
            "update_sequence_offset" => usa_offset,
            "update_sequence_count" => usa_count,
        },
    };
    if usa_offset == 0 || usa_count == 0 {
        return early("missing", "missing-update-sequence-array");
    }
    if usa_offset + usa_count * 2 > record.len() {
        return early("invalid", "update-sequence-array-out-of-bounds");
    }
    let mut warnings = Vec::new();
    let sector_count = record.len() / SECTOR_SIZE;
    if sector_count != 0 && usa_count != sector_count + 1 {
        warnings.push("update-sequence-count-sector-mismatch".to_string());
    }
    let sequence_number = &record[usa_offset..usa_offset + 2];
    let mut repaired = 0usize;
    for sector_index in 1..usa_count {
        let trailer = sector_index * SECTOR_SIZE - 2;
        if trailer + 2 > record.len() {
            warnings.push(format!("sector-trailer-out-of-bounds:{sector_index}"));
            continue;
        }
        if &record[trailer..trailer + 2] != sequence_number {
            warnings.push(format!(
                "sector-trailer-update-sequence-mismatch:{sector_index}"
            ));
            continue;
        }
        repaired += 1;
    }
    let status = if warnings.is_empty() {
        "valid"
    } else {
        "valid-with-warnings"
    };
    SequenceValidation {
        status,
        warnings: warnings.clone(),
        value: dict! {
            "status" => status,
            "warnings" => warnings,
            "update_sequence_offset" => usa_offset,
            "update_sequence_count" => usa_count,
            "update_sequence_number" => hex(sequence_number),
            "sector_size" => SECTOR_SIZE,
            "sector_count" => sector_count,
            "repaired_sector_trailer_count" => repaired,
        },
    }
}

/// `apply_mft_update_sequence_fixup` without the two `record_sha256_*` keys.
fn apply_mft_update_sequence_fixup(record: &[u8]) -> (Cow<'_, [u8]>, bool, Value) {
    let usa_offset = u16_at(record, 0x04);
    let usa_count = u16_at(record, 0x06);
    let sector_count = record.len() / SECTOR_SIZE;
    let profile =
        |status: &str, applied: bool, number: String, restored: usize, warnings: Vec<String>| {
            dict! {
                "profile_version" => "mft-usa-fixup-application-v1",
                "status" => status,
                "applied" => applied,
                "sector_size" => SECTOR_SIZE,
                "sector_count" => sector_count,
                "update_sequence_offset" => usa_offset,
                "update_sequence_count" => usa_count,
                "update_sequence_number" => number,
                "restored_sector_trailer_count" => restored,
                "warnings" => warnings,
            }
        };
    let mut warnings = Vec::new();
    if usa_offset == 0 || usa_count == 0 {
        warnings.push("missing-update-sequence-array".to_string());
    }
    if usa_offset + usa_count * 2 > record.len() {
        warnings.push("update-sequence-array-out-of-bounds".to_string());
    }
    if sector_count == 0 {
        warnings.push("record-smaller-than-sector".to_string());
    }
    if usa_count != sector_count + 1 {
        warnings.push("update-sequence-count-sector-mismatch".to_string());
    }
    if !warnings.is_empty() {
        let value = profile("not-applied-invalid-usa", false, String::new(), 0, warnings);
        return (Cow::Borrowed(record), false, value);
    }
    let sequence_number = &record[usa_offset..usa_offset + 2];
    let mut repaired = record.to_vec();
    let mut restored = 0usize;
    for sector_index in 1..usa_count {
        let trailer = sector_index * SECTOR_SIZE - 2;
        if trailer + 2 > record.len() {
            warnings.push(format!("sector-trailer-out-of-bounds:{sector_index}"));
            break;
        }
        if &record[trailer..trailer + 2] != sequence_number {
            warnings.push(format!(
                "sector-trailer-update-sequence-mismatch:{sector_index}"
            ));
            break;
        }
        let replacement = usa_offset + sector_index * 2;
        repaired[trailer..trailer + 2].copy_from_slice(&record[replacement..replacement + 2]);
        restored += 1;
    }
    let number = hex(sequence_number);
    if !warnings.is_empty() {
        let value = profile("not-applied-trailer-mismatch", false, number, 0, warnings);
        return (Cow::Borrowed(record), false, value);
    }
    let value = profile("applied", true, number, restored, Vec::new());
    (Cow::Owned(repaired), true, value)
}

fn timestamps(value: &[u8], base: usize) -> ([u64; 4], [String; 4]) {
    let ticks = [0, 8, 16, 24].map(|delta| u64_at(value, base + delta));
    (ticks, ticks.map(filetime_to_iso))
}

fn timestamp_dicts(ticks: &[u64; 4], texts: &[String; 4]) -> (Value, Value) {
    let text = Value::Dict(
        TIMESTAMP_FIELDS
            .iter()
            .zip(texts)
            .map(|(name, text)| (*name, Value::from(text.as_str())))
            .collect(),
    );
    let raw = Value::Dict(
        TIMESTAMP_FIELDS
            .iter()
            .zip(ticks)
            .map(|(name, tick)| (*name, Value::from(*tick)))
            .collect(),
    );
    (text, raw)
}

/// `parse_standard_information`, plus `timestamps_filetime` (raw 100 ns ticks; Rust only).
fn parse_standard_information(value: &[u8]) -> (Value, [String; 4]) {
    let (ticks, texts) = timestamps(value, 0);
    let (text, raw) = timestamp_dicts(&ticks, &texts);
    let file_attributes = if value.len() >= 36 {
        u32_at(value, 32)
    } else {
        0
    };
    let out_of_range: Vec<&str> = TIMESTAMP_FIELDS
        .iter()
        .zip(&texts)
        .filter(|(_, text)| *text == FILETIME_OUT_OF_RANGE_ISO)
        .map(|(name, _)| *name)
        .collect();
    let mut items = vec![("timestamps", text), ("timestamps_filetime", raw)];
    if !out_of_range.is_empty() {
        items.push((
            "timestamps_out_of_range",
            Value::from(
                out_of_range
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>(),
            ),
        ));
    }
    items.push(("file_attributes", Value::from(file_attributes)));
    items.push((
        "file_attribute_names",
        Value::from(flag_names(file_attributes, NTFS_FILE_ATTRIBUTE_NAMES)),
    ));
    (Value::Dict(items), texts)
}

/// `parse_file_name_attribute`, plus `timestamps_filetime` (raw 100 ns ticks; Rust only).
fn parse_file_name_attribute(value: &[u8]) -> (Value, [String; 4]) {
    let parent_reference_raw = u64_at(value, 0);
    let name_length = int_from(value, 64, 1) as usize;
    let namespace = int_from(value, 65, 1);
    let name_end = 66 + name_length * 2;
    let name = if name_end <= value.len() {
        utf16_ignore(&value[66..name_end])
    } else {
        String::new()
    };
    let file_attributes = u32_at(value, 56);
    let (ticks, texts) = timestamps(value, 8);
    let (text, raw) = timestamp_dicts(&ticks, &texts);
    let parsed = dict! {
        "parent_reference" => split_mft_reference(parent_reference_raw),
        "parent_reference_raw" => parent_reference_raw,
        "timestamps" => text,
        "timestamps_filetime" => raw,
        "allocated_size" => u64_at(value, 40),
        "real_size" => u64_at(value, 48),
        "file_attributes" => file_attributes,
        "file_attribute_names" => flag_names(file_attributes, NTFS_FILE_ATTRIBUTE_NAMES),
        "name_length" => name_length,
        "namespace" => file_name_namespace(namespace),
        "file_name" => name,
    };
    (parsed, texts)
}

fn parse_attribute_list_attribute(value: &[u8]) -> Value {
    let mut entries = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut offset = 0usize;
    while offset + 26 <= value.len() && entries.len() < 256 {
        let attribute_type = u32_at(value, offset);
        let entry_length = u16_at(value, offset + 4);
        let name_length = int_from(value, offset + 6, 1) as usize;
        let name_offset = int_from(value, offset + 7, 1) as usize;
        if attribute_type == 0 || entry_length == 0 {
            break;
        }
        if entry_length < 26 {
            warnings.push(format!("invalid-attribute-list-entry-length:{offset}"));
            break;
        }
        if offset + entry_length > value.len() {
            warnings.push(format!("attribute-list-entry-overruns-value:{offset}"));
            break;
        }
        let name_start = offset + name_offset;
        let name_end = name_start + name_length * 2;
        let name = if name_length != 0 && name_end <= offset + entry_length {
            utf16_ignore(&value[name_start..name_end])
        } else {
            String::new()
        };
        let extension_reference_raw = u64_at(value, offset + 16);
        entries.push(dict! {
            "entry_index" => entries.len(),
            "entry_offset" => offset,
            "attribute_type" => attribute_type,
            "attribute_type_name" => attribute_type_name(attribute_type),
            "entry_length" => entry_length,
            "name" => name,
            "lowest_vcn" => u64_at(value, offset + 8),
            "extension_reference_raw" => extension_reference_raw,
            "extension_reference_decoded" => split_mft_reference(extension_reference_raw),
            "attribute_id" => u16_at(value, offset + 24),
            "requires_extension_record_resolution" => extension_reference_raw != 0,
        });
        offset += align8(entry_length);
    }
    if entries.len() >= 256 {
        warnings.push("attribute-list-entry-limit-reached".to_string());
    }
    let status = match (entries.is_empty(), warnings.is_empty()) {
        (false, true) => "decoded",
        (false, false) => "decoded-with-warnings",
        (true, _) => "empty",
    };
    let count = entries.len();
    dict! {
        "status" => status,
        "entries" => Value::List(entries),
        "entry_count" => count,
        "warnings" => warnings,
        "resolved" => false,
        "resolution_status" => "extension-record-resolution-not-implemented",
    }
}

fn signed_le(blob: &[u8]) -> i128 {
    if blob.is_empty() {
        return 0;
    }
    let unsigned = blob
        .iter()
        .rev()
        .fold(0i128, |acc, byte| (acc << 8) | i128::from(*byte));
    let bits = blob.len() * 8;
    if blob[blob.len() - 1] & 0x80 != 0 {
        unsigned - (1i128 << bits)
    } else {
        unsigned
    }
}

struct Runlist {
    status: &'static str,
    runs: Vec<Value>,
    warnings: Vec<String>,
    terminator_offset: Option<usize>,
    consumed_bytes: usize,
    preview_bytes: usize,
}

/// `decode_mft_runlist` without `preview_sha256`.
fn decode_mft_runlist(blob: &[u8]) -> Runlist {
    let preview = &blob[..blob.len().min(RUNLIST_PREVIEW_BYTE_LIMIT)];
    let mut runs = Vec::new();
    let mut warnings = Vec::new();
    let mut offset = 0usize;
    let mut absolute_lcn: i128 = 0;
    let mut terminator_offset = None;
    while offset < preview.len() && runs.len() < RUNLIST_PREVIEW_RUN_LIMIT {
        let header = preview[offset];
        if header == 0 {
            terminator_offset = Some(offset);
            offset += 1;
            break;
        }
        let length_size = usize::from(header & 0x0F);
        let lcn_delta_size = usize::from((header >> 4) & 0x0F);
        let value_offset = offset + 1;
        let value_end = value_offset + length_size + lcn_delta_size;
        if length_size == 0 {
            warnings.push(format!("missing-run-length-field:{offset}"));
            break;
        }
        if length_size > 8 || lcn_delta_size > 8 {
            warnings.push(format!("oversized-run-field:{offset}"));
            break;
        }
        if value_end > preview.len() {
            warnings.push(format!("run-overruns-preview:{offset}"));
            break;
        }
        let cluster_count = int_from(preview, value_offset, length_size);
        let sparse = lcn_delta_size == 0;
        let lcn_delta = if sparse {
            0
        } else {
            signed_le(&preview[value_offset + length_size..value_end])
        };
        if !sparse {
            absolute_lcn += lcn_delta;
        }
        if cluster_count == 0 {
            warnings.push(format!("zero-cluster-run:{offset}"));
        }
        if !sparse && absolute_lcn < 0 {
            warnings.push(format!("negative-absolute-lcn:{offset}"));
        }
        runs.push(dict! {
            "run_index" => runs.len(),
            "header_offset" => offset,
            "header_byte" => header,
            "length_field_size" => length_size,
            "lcn_delta_field_size" => lcn_delta_size,
            "cluster_count" => cluster_count,
            "lcn_delta" => lcn_delta,
            "absolute_lcn" => if sparse { None } else { Some(absolute_lcn) },
            "sparse" => sparse,
            "valid" => cluster_count > 0 && (sparse || absolute_lcn >= 0),
        });
        offset = value_end;
    }
    if runs.len() >= RUNLIST_PREVIEW_RUN_LIMIT && terminator_offset.is_none() {
        warnings.push("run-limit-reached".to_string());
    }
    if terminator_offset.is_none() && offset >= preview.len() && !preview.is_empty() {
        warnings.push("runlist-terminator-not-seen-in-preview".to_string());
    }
    let status = if preview.is_empty() {
        "missing"
    } else if !runs.is_empty() && warnings.is_empty() {
        "decoded-preview"
    } else if !runs.is_empty() {
        "decoded-preview-with-warnings"
    } else {
        "invalid-preview"
    };
    Runlist {
        status,
        runs,
        warnings,
        terminator_offset,
        consumed_bytes: offset,
        preview_bytes: preview.len(),
    }
}

enum Decoded {
    None,
    StandardInformation(Value, [String; 4]),
    AttributeList(Vec<Value>),
    FileName(Value, [String; 4]),
    Data(Value, DataFacts),
}

#[derive(Clone, Copy, Default)]
struct DataFacts {
    nonresident: bool,
    has_runlist_preview: bool,
    decoded_preview: bool,
}

/// `parse_mft_attribute`, minus resident `$DATA` hashes and `runlist_decode.preview_sha256`.
fn parse_mft_attribute(
    attribute: &[u8],
    record_relative_offset: usize,
) -> (Value, String, Decoded) {
    let attribute_type = u32_at(attribute, 0);
    let length = u32_at(attribute, 4);
    let nonresident = int_from(attribute, 8, 1) != 0;
    let name_length = int_from(attribute, 9, 1) as usize;
    let name_offset = u16_at(attribute, 10);
    let name = if name_length != 0 && name_offset + name_length * 2 <= attribute.len() {
        utf16_ignore(&attribute[name_offset..name_offset + name_length * 2])
    } else {
        String::new()
    };
    let type_name = attribute_type_name(attribute_type);
    let mut items: Vec<(&'static str, Value)> = vec![
        ("record_relative_offset", record_relative_offset.into()),
        ("attribute_type", attribute_type.into()),
        ("attribute_type_name", type_name.as_str().into()),
        ("length", length.into()),
        ("nonresident", nonresident.into()),
        ("name", name.into()),
        ("flags", u16_at(attribute, 12).into()),
        ("attribute_id", u16_at(attribute, 14).into()),
    ];
    if nonresident {
        let runlist_offset = u16_at(attribute, 32);
        let runlist_blob: &[u8] = if runlist_offset < attribute.len() {
            &attribute[runlist_offset
                ..attribute
                    .len()
                    .min(runlist_offset + RUNLIST_PREVIEW_BYTE_LIMIT)]
        } else {
            &[]
        };
        let runlist = decode_mft_runlist(runlist_blob);
        let run_values = Value::List(runlist.runs.clone());
        let runlist_decode = dict! {
            "status" => runlist.status,
            "runs" => run_values.clone(),
            "run_count" => runlist.runs.len(),
            "warnings" => runlist.warnings.clone(),
            "terminator_offset" => runlist.terminator_offset,
            "consumed_bytes" => runlist.consumed_bytes,
            "preview_bytes" => runlist.preview_bytes,
        };
        items.push((
            "nonresident_metadata",
            dict! {
                "lowest_vcn" => u64_at(attribute, 16),
                "highest_vcn" => u64_at(attribute, 24),
                "runlist_offset" => runlist_offset,
                "compression_unit" => u16_at(attribute, 34),
                "allocated_size" => u64_at(attribute, 40),
                "real_size" => u64_at(attribute, 48),
                "initialized_size" => u64_at(attribute, 56),
                "data_runs_preview" => hex(&runlist_blob[..runlist_blob.len().min(32)]),
                "runlist_decode_status" => runlist.status,
                "runlist_decode" => runlist_decode,
            },
        ));
        let mut decoded = Decoded::None;
        if attribute_type == 0x80 {
            let data = dict! {
                "resident" => false,
                "allocated_size" => u64_at(attribute, 40),
                "real_size" => u64_at(attribute, 48),
                "initialized_size" => u64_at(attribute, 56),
                "runlist_offset" => runlist_offset,
                "runlist_preview" => run_values,
                "runlist_decode_status" => runlist.status,
                "runlist_warning_count" => runlist.warnings.len(),
                "runlist_consumed_bytes" => runlist.consumed_bytes,
                "runlist_preview_bytes" => runlist.preview_bytes,
                "runlist_terminator_offset" => runlist.terminator_offset,
            };
            items.push(("data", data.clone()));
            let facts = DataFacts {
                nonresident: true,
                has_runlist_preview: !runlist.runs.is_empty(),
                decoded_preview: runlist.status.starts_with("decoded-preview"),
            };
            decoded = Decoded::Data(data, facts);
        }
        return (Value::Dict(items), type_name, decoded);
    }

    let value_length = u32_at(attribute, 16) as usize;
    let value_offset = u16_at(attribute, 20);
    let value: &[u8] = if value_offset + value_length <= attribute.len() {
        &attribute[value_offset..value_offset + value_length]
    } else {
        &[]
    };
    items.push((
        "resident_metadata",
        dict! {
            "value_length" => value_length,
            "value_offset" => value_offset,
            "indexed_flag" => int_from(attribute, 22, 1),
        },
    ));
    let decoded = match attribute_type {
        0x10 => {
            let (parsed, texts) = parse_standard_information(value);
            items.push(("standard_information", parsed.clone()));
            Decoded::StandardInformation(parsed, texts)
        }
        0x20 => {
            let parsed = parse_attribute_list_attribute(value);
            let entries = match parsed.get("entries") {
                Some(Value::List(entries)) => entries.clone(),
                _ => Vec::new(),
            };
            items.push(("attribute_list", parsed));
            Decoded::AttributeList(entries)
        }
        0x30 => {
            let (parsed, texts) = parse_file_name_attribute(value);
            items.push(("file_name", parsed.clone()));
            Decoded::FileName(parsed, texts)
        }
        0x80 => {
            let data = dict! {
                "resident" => true,
                "resident_size" => value_length,
                "runlist_decode_status" => "resident-data-no-runlist",
            };
            items.push(("data", data.clone()));
            Decoded::Data(data, DataFacts::default())
        }
        _ => Decoded::None,
    };
    (Value::Dict(items), type_name, decoded)
}

#[derive(Default)]
struct Attributes {
    attributes: Vec<Value>,
    attribute_types: Vec<String>,
    attribute_list_entries: Vec<Value>,
    standard_information: Option<(Value, [String; 4])>,
    file_name_entries: Vec<(Value, [String; 4])>,
    data_attributes: Vec<(Value, DataFacts)>,
    end_marker_seen: bool,
    warnings: Vec<String>,
}

fn parse_mft_attributes(
    record: &[u8],
    first_attribute_offset: usize,
    used_size: usize,
) -> Attributes {
    let mut parsed = Attributes::default();
    let limit = if first_attribute_offset < used_size && used_size <= record.len() {
        used_size
    } else {
        record.len()
    };
    let mut offset = first_attribute_offset;
    let mut seen = 0;
    while offset + 8 <= limit && seen < 256 {
        let attribute_type = u32_at(record, offset);
        if attribute_type == 0xFFFF_FFFF {
            parsed.end_marker_seen = true;
            break;
        }
        let length = u32_at(record, offset + 4) as usize;
        if length < 24 {
            parsed
                .warnings
                .push(format!("invalid-attribute-length:{offset}"));
            break;
        }
        if offset + length > limit {
            parsed
                .warnings
                .push(format!("attribute-overruns-record:{offset}"));
            break;
        }
        let (attribute, type_name, decoded) =
            parse_mft_attribute(&record[offset..offset + length], offset);
        parsed.attributes.push(attribute);
        parsed.attribute_types.push(type_name);
        match decoded {
            Decoded::StandardInformation(value, texts) => {
                parsed.standard_information = Some((value, texts))
            }
            Decoded::AttributeList(entries) => parsed.attribute_list_entries.extend(entries),
            Decoded::FileName(value, texts) => parsed.file_name_entries.push((value, texts)),
            Decoded::Data(value, facts) => parsed.data_attributes.push((value, facts)),
            Decoded::None => {}
        }
        offset += align8(length);
        seen += 1;
    }
    if seen >= 256 {
        parsed
            .warnings
            .push("attribute-iteration-limit-reached".to_string());
    }
    parsed
}

struct TimestampValidation {
    status: &'static str,
    timestamp_count: usize,
    invalid_sources: Vec<String>,
    value: Value,
}

fn mft_timestamp_validation(attributes: &Attributes) -> TimestampValidation {
    let mut sources: Vec<(String, String)> = Vec::new();
    let mut invalid: Vec<String> = Vec::new();
    let mut collect = |prefix: &str, texts: &[String; 4]| {
        for (name, text) in TIMESTAMP_FIELDS.iter().zip(texts) {
            let source = format!("{prefix}.{name}");
            if text.is_empty() {
                invalid.push(source);
            } else {
                sources.push((source, text.clone()));
            }
        }
    };
    if let Some((_, texts)) = &attributes.standard_information {
        collect("$STANDARD_INFORMATION", texts);
    }
    for (index, (_, texts)) in attributes.file_name_entries.iter().enumerate() {
        collect(&format!("$FILE_NAME[{index}]"), texts);
    }
    let status = match (sources.is_empty(), invalid.is_empty()) {
        (false, true) => "valid",
        (false, false) => "valid-with-warnings",
        (true, _) => "missing",
    };
    let mut values: Vec<&str> = sources.iter().map(|(_, value)| value.as_str()).collect();
    values.sort_unstable();
    values.dedup();
    let invalid_capped: Vec<String> = invalid.iter().take(32).cloned().collect();
    let value = dict! {
        "status" => status,
        "timestamp_count" => sources.len(),
        "sources" => Value::List(
            sources
                .iter()
                .take(32)
                .map(|(source, value)| dict! { "source" => source.as_str(), "value" => value.as_str() })
                .collect(),
        ),
        "invalid_sources" => invalid_capped.clone(),
        "earliest" => values.first().copied().unwrap_or(""),
        "latest" => values.last().copied().unwrap_or(""),
    };
    TimestampValidation {
        status,
        timestamp_count: sources.len(),
        invalid_sources: invalid_capped,
        value,
    }
}

fn mft_validation_warnings(
    record: &[u8],
    first_attribute_offset: usize,
    used_size: u64,
    allocated_size: u64,
    sequence: &SequenceValidation,
    attributes: &Attributes,
    timestamps: &TimestampValidation,
) -> Vec<String> {
    let mut warnings = Vec::new();
    if record.len() < 4 || &record[..4] != b"FILE" {
        warnings.push("invalid-file-record-magic".to_string());
    }
    if first_attribute_offset < 0x30 || first_attribute_offset >= record.len() {
        warnings.push("first-attribute-offset-out-of-range".to_string());
    }
    if !first_attribute_offset.is_multiple_of(8) {
        warnings.push("first-attribute-offset-not-8-byte-aligned".to_string());
    }
    if used_size != 0 && allocated_size != 0 && used_size > allocated_size {
        warnings.push("used-size-exceeds-allocated-size".to_string());
    }
    if sequence.status != "valid" {
        if sequence.warnings.is_empty() {
            warnings.push("sequence-validation-not-valid".to_string());
        } else {
            warnings.extend(sequence.warnings.iter().cloned());
        }
    }
    if !attributes.end_marker_seen {
        warnings.push("attribute-end-marker-not-seen".to_string());
    }
    warnings.extend(attributes.warnings.iter().cloned());
    if attributes.standard_information.is_none() {
        warnings.push("missing-standard-information-attribute".to_string());
    }
    if attributes.file_name_entries.is_empty() {
        warnings.push("missing-file-name-attribute".to_string());
    }
    if timestamps.status != "valid" {
        if timestamps.invalid_sources.is_empty() {
            warnings.push("timestamp-validation-not-valid".to_string());
        } else {
            warnings.extend(timestamps.invalid_sources.iter().cloned());
        }
    }
    warnings
}

fn mft_parser_confidence(
    validation_status: &str,
    attributes: &Attributes,
    sequence_status: &str,
) -> f64 {
    let mut confidence = 0.55;
    if attributes.standard_information.is_some() {
        confidence += 0.1;
    }
    if !attributes.file_name_entries.is_empty() {
        confidence += 0.1;
    }
    if !attributes.data_attributes.is_empty() {
        confidence += 0.05;
    }
    if sequence_status == "valid" {
        confidence += 0.1;
    }
    if validation_status == "valid" {
        confidence += 0.05;
    }
    f64::min(confidence, 0.9)
}

fn parse_record(blob: &[u8], offset: usize, volume_record_size: Option<usize>) -> Value {
    let flags = u16_at(blob, offset + 0x16);
    let allocated_size = u32_at(blob, offset + 0x1C);
    let own_geometry_ok =
        (48..=4096).contains(&allocated_size) && offset + allocated_size as usize <= blob.len();
    let mut geometry_issues: Vec<String> = Vec::new();
    let record_size;
    let record_number_source;
    if let Some(volume_size) = volume_record_size {
        record_size = volume_size;
        record_number_source = "record-offset-divided-by-volume-record-size";
        if allocated_size != volume_size as u64 {
            geometry_issues.push(format!(
                "allocated-size-{allocated_size}-disagrees-with-volume-record-size-{volume_size}"
            ));
        }
        if !offset.is_multiple_of(volume_size) {
            geometry_issues.push("record-offset-not-slot-aligned".to_string());
        }
    } else {
        let plausible_size = PLAUSIBLE_RECORD_SIZES.contains(&(allocated_size as usize));
        record_size = if own_geometry_ok || plausible_size {
            allocated_size as usize
        } else {
            1024
        };
        record_number_source = "record-offset-divided-by-record-size";
        if !(48..=4096).contains(&allocated_size) {
            geometry_issues.push(format!("allocated-size-invalid-{allocated_size}"));
        }
    }
    if offset + record_size > blob.len() {
        geometry_issues.push(format!(
            "record-truncated-{}-of-{record_size}-bytes",
            blob.len() - offset
        ));
    }
    let record = &blob[offset..blob.len().min(offset + record_size)];
    let first_attribute_offset = u16_at(blob, offset + 0x14);
    let used_size = u32_at(blob, offset + 0x18);
    let sequence = validate_mft_update_sequence(record);
    let (repaired, usa_applied, usa_value) = apply_mft_update_sequence_fixup(record);
    let attributes = parse_mft_attributes(&repaired, first_attribute_offset, used_size as usize);
    let timestamps = mft_timestamp_validation(&attributes);
    let mut validation_warnings = mft_validation_warnings(
        &repaired,
        first_attribute_offset,
        used_size,
        allocated_size,
        &sequence,
        &attributes,
        &timestamps,
    );
    validation_warnings.extend(geometry_issues.iter().cloned());
    let validation_status = if validation_warnings.is_empty() {
        "valid"
    } else {
        "valid-with-warnings"
    };
    let record_number = (offset / record_size) as u64;
    let header_record_number = if u16_at(blob, offset + 0x04) >= 0x30 {
        Some(u32_at(blob, offset + 0x2C))
    } else {
        None
    };
    let header_agrees = header_record_number == Some(record_number);
    let record_number_trusted = match volume_record_size {
        Some(size) => {
            (header_record_number.is_none() || header_agrees)
                && (geometry_issues.is_empty() || (offset.is_multiple_of(size) && header_agrees))
        }
        None => geometry_issues.is_empty() && header_agrees,
    };
    let data_facts: Vec<DataFacts> = attributes
        .data_attributes
        .iter()
        .map(|(_, facts)| *facts)
        .collect();
    let validation_checks = dict! {
        "magic_valid" => record.len() >= 4 && &record[..4] == b"FILE",
        "sequence_fixup_valid" => sequence.status == "valid",
        "usa_fixup_applied" => usa_applied,
        "has_standard_information_attribute" => attributes.standard_information.is_some(),
        "has_file_name_attribute" => !attributes.file_name_entries.is_empty(),
        "has_data_attribute" => !attributes.data_attributes.is_empty(),
        "has_attribute_list_attribute" => !attributes.attribute_list_entries.is_empty()
            || attributes.attribute_types.iter().any(|name| name == "$ATTRIBUTE_LIST"),
        "has_nonresident_data_attribute" => data_facts.iter().any(|facts| facts.nonresident),
        "has_nonresident_runlist_preview" => data_facts.iter().any(|facts| facts.has_runlist_preview),
        "has_decoded_nonresident_runlist" => data_facts.iter().any(|facts| facts.decoded_preview),
        "attribute_end_marker_seen" => attributes.end_marker_seen,
        "timestamp_fields_present" => timestamps.timestamp_count != 0,
    };
    let parser_confidence = mft_parser_confidence(validation_status, &attributes, sequence.status);
    dict! {
        "record_offset" => offset,
        "record_number_candidate" => record_number,
        "record_number_source" => record_number_source,
        "record_number_trusted" => record_number_trusted,
        "record_geometry_status" => if geometry_issues.is_empty() { "consistent" } else { "damaged" },
        "record_geometry_issues" => geometry_issues,
        "record_size_used_for_slot" => record_size,
        "record_number_header" => header_record_number,
        "record_number_header_mismatch" => header_record_number.is_some_and(|header| header != record_number),
        "sequence_number" => u16_at(blob, offset + 0x10),
        "hard_link_count" => u16_at(blob, offset + 0x12),
        "first_attribute_offset" => first_attribute_offset,
        "flags" => flags,
        "in_use" => flags & 0x01 != 0,
        "directory" => flags & 0x02 != 0,
        "used_size" => used_size,
        "allocated_size" => allocated_size,
        "base_file_reference" => u64_at(blob, offset + 0x20),
        "sequence_validation" => sequence.value,
        "usa_fixup_application" => usa_value,
        "attribute_count" => attributes.attributes.len(),
        "attribute_types" => attributes.attribute_types,
        "attributes" => Value::List(attributes.attributes),
        "attribute_list_entries" => Value::List(attributes.attribute_list_entries),
        "standard_information" => attributes
            .standard_information
            .map_or_else(|| Value::Dict(Vec::new()), |(value, _)| value),
        "file_name_entries" => Value::List(attributes.file_name_entries.into_iter().map(|(value, _)| value).collect()),
        "data_attributes" => Value::List(attributes.data_attributes.into_iter().map(|(value, _)| value).collect()),
        "timestamp_validation" => timestamps.value,
        "validation_status" => validation_status,
        "validation_warnings" => validation_warnings,
        "validation_checks" => validation_checks,
        "parser_confidence" => parser_confidence,
        "path_candidates" => path_candidates(record),
    }
}

/// `extract_utf16_strings(blob)` of filesystem.py: runs of >= 4 printable-ASCII UTF-16 units.
fn extract_utf16_strings(blob: &[u8]) -> Vec<String> {
    const LIMIT: usize = 250;
    let mut strings: Vec<String> = Vec::new();
    let mut current = String::new();
    let flush = |current: &mut String, strings: &mut Vec<String>| -> bool {
        if current.len() >= 4 {
            let trimmed = current.trim_matches(' ');
            if !trimmed.is_empty() && !strings.iter().any(|seen| seen == trimmed) {
                strings.push(trimmed.to_string());
                if strings.len() >= LIMIT {
                    return true;
                }
            }
        }
        current.clear();
        false
    };
    for pair in blob.as_chunks::<2>().0 {
        let unit = u16::from_le_bytes(*pair);
        if (32..=126).contains(&unit) {
            current.push(char::from(unit as u8));
            continue;
        }
        if flush(&mut current, &mut strings) {
            return strings;
        }
    }
    flush(&mut current, &mut strings);
    strings
}

/// Length of a `WINDOWS_PATH_RE` match starting at `start` (ASCII text only):
/// `(?i)(?:[a-z]:\\|\\\\|\\device\\)[^\x00\r\n\t"'<>|]{4,260}`.
fn windows_path_match(text: &[u8], start: usize) -> Option<usize> {
    let rest = &text[start..];
    let prefixes = [
        rest.len() >= 3 && rest[0].is_ascii_alphabetic() && rest[1] == b':' && rest[2] == b'\\',
        rest.len() >= 2 && rest[0] == b'\\' && rest[1] == b'\\',
        rest.len() >= 8 && rest[..8].eq_ignore_ascii_case(b"\\device\\"),
    ];
    for (prefix_length, matched) in [3usize, 2, 8].into_iter().zip(prefixes) {
        if !matched {
            continue;
        }
        let body = rest[prefix_length..]
            .iter()
            .take(260)
            .take_while(|byte| !b"\x00\r\n\t\"'<>|".contains(byte))
            .count();
        if body >= 4 {
            return Some(prefix_length + body);
        }
    }
    None
}

/// `extract_path_candidates(extract_utf16_strings(record))[:10]` of filesystem.py.
fn path_candidates(record: &[u8]) -> Vec<String> {
    let mut candidates: Vec<String> = Vec::new();
    for value in extract_utf16_strings(record) {
        let text = value.as_bytes();
        let mut position = 0;
        while position < text.len() {
            match windows_path_match(text, position) {
                Some(length) => {
                    let candidate = value[position..position + length]
                        .trim_end_matches(['.', ',', ')', ';', ']']);
                    if !candidates.iter().any(|seen| seen == candidate) {
                        candidates.push(candidate.to_string());
                    }
                    position += length;
                }
                None => position += 1,
            }
        }
    }
    candidates.truncate(10);
    candidates
}

/// `parse_mft_record_headers` of filesystem.py (main after PR #33): every `FILE`
/// hit with a 48-byte header, at most 5000 records. The attribute-list
/// resolution pass is not ported (see the crate docs).
pub fn parse_mft_record_headers(blob: &[u8]) -> Vec<Value> {
    let volume_record_size = mft_volume_record_size(blob);
    let mut records = Vec::new();
    let mut offset = 0;
    while let Some(hit) = find(blob, b"FILE", offset) {
        offset = hit;
        if offset + 48 <= blob.len() {
            records.push(parse_record(blob, offset, volume_record_size));
        }
        offset += 4;
        if records.len() >= MFT_RECORD_SCAN_LIMIT {
            break;
        }
    }
    records
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(blob: &mut [u8], offset: usize, value: u64, size: usize) {
        blob[offset..offset + size].copy_from_slice(&value.to_le_bytes()[..size]);
    }

    fn record(number: u32, sequence: u16, size: usize) -> Vec<u8> {
        let mut blob = vec![0u8; size];
        blob[..4].copy_from_slice(b"FILE");
        let sectors = size / SECTOR_SIZE;
        put(&mut blob, 0x04, 0x30, 2);
        put(&mut blob, 0x06, (sectors + 1) as u64, 2);
        put(&mut blob, 0x10, u64::from(sequence), 2);
        put(&mut blob, 0x12, 1, 2);
        put(&mut blob, 0x14, 0x38, 2);
        put(&mut blob, 0x16, 0x01, 2);
        put(&mut blob, 0x1C, size as u64, 4);
        put(&mut blob, 0x2C, u64::from(number), 4);
        let mut offset = 0x38;
        let mut si = vec![0u8; 24 + 48];
        put(&mut si, 0, 0x10, 4);
        put(&mut si, 4, 72, 4);
        put(&mut si, 16, 48, 4);
        put(&mut si, 20, 24, 2);
        put(&mut si, 24, 133_485_408_001_234_567, 8);
        blob[offset..offset + si.len()].copy_from_slice(&si);
        offset += si.len();
        put(&mut blob, offset, 0xFFFF_FFFF, 4);
        put(&mut blob, 0x18, (offset + 8) as u64, 4);
        put(&mut blob, 0x30, 0x0007, 2);
        for sector in 1..=sectors {
            let trailer = sector * SECTOR_SIZE - 2;
            let original = [blob[trailer], blob[trailer + 1]];
            blob[0x30 + sector * 2..0x30 + sector * 2 + 2].copy_from_slice(&original);
            put(&mut blob, trailer, 0x0007, 2);
        }
        blob
    }

    #[test]
    fn slot_geometry_and_fixup_follow_the_volume_stride() {
        let mut blob = record(0, 1, 1024);
        blob.extend(record(1, 5, 1024));
        let records = parse_mft_record_headers(&blob);
        assert_eq!(records.len(), 2);
        let second = &records[1];
        assert_eq!(second.get("record_number_candidate"), Some(&Value::Int(1)));
        assert_eq!(second.get("sequence_number"), Some(&Value::Int(5)));
        assert_eq!(
            second.get("record_number_trusted"),
            Some(&Value::Bool(true))
        );
        let fixup = second.get("usa_fixup_application").unwrap();
        assert_eq!(fixup.get("status").and_then(Value::as_str), Some("applied"));
        let si = second.get("standard_information").unwrap();
        let raw = si.get("timestamps_filetime").unwrap();
        assert_eq!(
            raw.get("created_at"),
            Some(&Value::Int(133_485_408_001_234_567))
        );
    }

    #[test]
    fn trailer_mismatch_leaves_fixup_unapplied() {
        let mut blob = record(0, 1, 1024);
        put(&mut blob, 1022, 0x1234, 2);
        let records = parse_mft_record_headers(&blob);
        let fixup = records[0].get("usa_fixup_application").unwrap();
        assert_eq!(
            fixup.get("status").and_then(Value::as_str),
            Some("not-applied-trailer-mismatch")
        );
        assert_eq!(
            records[0].get("validation_status").and_then(Value::as_str),
            Some("valid-with-warnings")
        );
    }

    #[test]
    fn runlist_decodes_signed_deltas_and_sparse_runs() {
        let decoded =
            decode_mft_runlist(&[0x21, 0x10, 0x00, 0x01, 0x11, 0x05, 0xFF, 0x01, 0x04, 0x00]);
        assert_eq!(decoded.status, "decoded-preview");
        assert_eq!(decoded.runs.len(), 3);
        assert_eq!(decoded.runs[1].get("absolute_lcn"), Some(&Value::Int(255)));
        assert_eq!(decoded.runs[2].get("absolute_lcn"), Some(&Value::None));
        assert_eq!(decoded.terminator_offset, Some(9));
    }
}
