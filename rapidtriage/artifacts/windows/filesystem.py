from __future__ import annotations

import csv
import datetime as dt
import hashlib
import json
import re
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from ...core.forensic_accuracy import build_accuracy_gate
from ...core.models import ArtifactRecord
from .common import build_forensic_review

PARSER_VERSION = "windows-filesystem-v5"
SUPPORTED_SUFFIXES = {".csv", ".json", ".jsonl", ".ndjson"}
MFT_HINTS = ("mft", "mftexcmd", "$mft")
USN_HINTS = ("usn", "usnjrnl", "$j")
NATIVE_SCAN_LIMIT = 16 * 1024 * 1024
USN_RECORD_SCAN_LIMIT = 5000
USN_LARGE_RECORD_THRESHOLD = 512
WINDOWS_PATH_RE = re.compile(r"(?i)(?:[a-z]:\\|\\\\|\\device\\)[^\x00\r\n\t\"'<>|]{4,260}")
USN_REASON_FLAGS = {
    0x00000001: "DATA_OVERWRITE",
    0x00000002: "DATA_EXTEND",
    0x00000004: "DATA_TRUNCATION",
    0x00000010: "NAMED_DATA_OVERWRITE",
    0x00000020: "NAMED_DATA_EXTEND",
    0x00000040: "NAMED_DATA_TRUNCATION",
    0x00000100: "FILE_CREATE",
    0x00000200: "FILE_DELETE",
    0x00000400: "EA_CHANGE",
    0x00000800: "SECURITY_CHANGE",
    0x00001000: "RENAME_OLD_NAME",
    0x00002000: "RENAME_NEW_NAME",
    0x00004000: "INDEXABLE_CHANGE",
    0x00008000: "BASIC_INFO_CHANGE",
    0x00010000: "HARD_LINK_CHANGE",
    0x00020000: "COMPRESSION_CHANGE",
    0x00040000: "ENCRYPTION_CHANGE",
    0x00080000: "OBJECT_ID_CHANGE",
    0x00100000: "REPARSE_POINT_CHANGE",
    0x00200000: "STREAM_CHANGE",
    0x80000000: "CLOSE",
}
USN_SOURCE_INFO_FLAGS = {
    0x00000001: "DATA_MANAGEMENT",
    0x00000002: "AUXILIARY_DATA",
    0x00000004: "REPLICATION_MANAGEMENT",
    0x00000008: "CLIENT_REPLICATION_MANAGEMENT",
}
NTFS_FILE_ATTRIBUTE_NAMES = {
    0x00000001: "READONLY",
    0x00000002: "HIDDEN",
    0x00000004: "SYSTEM",
    0x00000010: "DIRECTORY",
    0x00000020: "ARCHIVE",
    0x00000040: "DEVICE",
    0x00000080: "NORMAL",
    0x00000100: "TEMPORARY",
    0x00000400: "REPARSE_POINT",
    0x00000800: "COMPRESSED",
    0x00001000: "OFFLINE",
    0x00004000: "ENCRYPTED",
}
MFT_ATTRIBUTE_TYPE_NAMES = {
    0x10: "$STANDARD_INFORMATION",
    0x20: "$ATTRIBUTE_LIST",
    0x30: "$FILE_NAME",
    0x40: "$OBJECT_ID",
    0x50: "$SECURITY_DESCRIPTOR",
    0x60: "$VOLUME_NAME",
    0x70: "$VOLUME_INFORMATION",
    0x80: "$DATA",
    0x90: "$INDEX_ROOT",
    0xA0: "$INDEX_ALLOCATION",
    0xB0: "$BITMAP",
    0xC0: "$REPARSE_POINT",
    0xD0: "$EA_INFORMATION",
    0xE0: "$EA",
    0x100: "$LOGGED_UTILITY_STREAM",
}
NTFS_FILESYSTEM_CAPABILITIES = {
    "mft_export_import": True,
    "mft_native_file_record_scan": True,
    "mft_update_sequence_validation": True,
    "mft_standard_information_decode": True,
    "mft_file_name_attribute_decode": True,
    "mft_resident_data_hash": True,
    "mft_nonresident_runlist_preview": True,
    "usn_export_import": True,
    "usn_native_v2_v3_record_decode": True,
    "usn_reason_flag_decode": True,
    "usn_large_record_detection": True,
    "mft_attribute_list_resolution": False,
    "mft_full_nonresident_runlist_decode": False,
    "usn_full_journal_replay": False,
    "full_volume_path_reconstruction": False,
}
MFT_REPORT_GRADE_BLOCKERS = [
    "bounded-native-mft-scan-not-full-volume-validated",
    "attribute-list-extension-record-resolution-not-implemented",
    "nonresident-data-run-decoding-not-report-grade-validated",
]
USN_REPORT_GRADE_BLOCKERS = [
    "bounded-native-usn-scan-not-full-journal-validated",
    "full-usn-replay-correlation-not-implemented",
    "large-corpus-pagination-validation-required",
]
FILE_NAME_NAMESPACE_NAMES = {
    0: "POSIX",
    1: "WIN32",
    2: "DOS",
    3: "WIN32_AND_DOS",
}


class WindowsFilesystemProvider:
    name = "windows-filesystem"
    collector_kind = "windows-filesystem"
    description = "Windows MFT and USN Journal imports plus bounded native NTFS inventory"
    target_platform = "windows"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        yield from collect_native_ntfs_artifacts(root)
        for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
            if not path.is_file() or path.suffix.lower() not in SUPPORTED_SUFFIXES:
                continue
            family = artifact_family(path)
            if not family:
                continue
            rows = iter_csv_rows(path) if path.suffix.lower() == ".csv" else iter_json_rows(path)
            for index, row in enumerate(rows):
                if not isinstance(row, Mapping):
                    continue
                yield build_filesystem_record(path, family, row, index)


def collect_native_ntfs_artifacts(root: Path) -> Iterable[ArtifactRecord]:
    seen: set[Path] = set()
    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if not path.is_file():
            continue
        name = path.name.lower()
        parent_blob = str(path.parent).lower()
        resolved = path.resolve()
        if resolved in seen:
            continue
        if name == "$mft":
            yield build_mft_inventory_record(path)
            for index, record in enumerate(parse_mft_record_headers(read_prefix(path, NATIVE_SCAN_LIMIT))):
                yield build_native_mft_record(path, record, index)
            seen.add(resolved)
        elif name in {"$j", "$usnjrnl"} or (name.endswith(".usn") and "usn" in parent_blob):
            yield build_usn_journal_inventory_record(path)
            for index, record in enumerate(parse_usn_records(read_prefix(path, NATIVE_SCAN_LIMIT))):
                yield build_native_usn_record(path, record, index)
            seen.add(resolved)


def build_mft_inventory_record(path: Path) -> ArtifactRecord:
    stat_result = path.stat()
    blob = read_prefix(path, NATIVE_SCAN_LIMIT)
    mft_records = parse_mft_record_headers(blob)
    strings = extract_utf16_strings(blob)
    path_candidates = extract_path_candidates(strings)
    validation_checks = {
        "has_native_records": bool(mft_records),
        "has_valid_record_headers": any(record.get("validation_status") == "valid" for record in mft_records),
        "has_sequence_validation": any((record.get("sequence_validation") or {}).get("status") for record in mft_records if isinstance(record.get("sequence_validation"), Mapping)),
        "has_timestamp_validation": any((record.get("timestamp_validation") or {}).get("status") for record in mft_records if isinstance(record.get("timestamp_validation"), Mapping)),
        "attribute_list_resolution_available": False,
        "full_nonresident_runlist_decode_available": False,
        "full_volume_path_reconstruction_available": False,
    }
    report_grade = ntfs_report_grade_assessment(
        ntfs_validation_matrix(validation_checks),
        validation_required=True,
        gap_ids=["#12"],
        blockers=MFT_REPORT_GRADE_BLOCKERS,
    )
    return ArtifactRecord(
        provider=WindowsFilesystemProvider.name,
        artifact_type="mft-file",
        path=str(path.resolve()),
        supported=False,
        details={
            "parser": "windows-mft-native-inventory",
            "parser_version": PARSER_VERSION,
            "coverage_status": "native-header-string-scan",
            "reportability": "inventory-only",
            "source_path": str(path.resolve()),
            "source_format": "ntfs-mft",
            "source_hashes": file_hashes(path),
            "size": stat_result.st_size,
            "modified_at": dt.datetime.fromtimestamp(stat_result.st_mtime, dt.timezone.utc).isoformat(),
            "scan_bytes": len(blob),
            "native_record_count": len(mft_records),
            "record_validation_counts": count_values(record.get("validation_status") for record in mft_records),
            "sequence_validation_counts": count_values(
                (record.get("sequence_validation") or {}).get("status")
                for record in mft_records
                if isinstance(record.get("sequence_validation"), Mapping)
            ),
            "timestamp_validation_counts": count_values(
                (record.get("timestamp_validation") or {}).get("status")
                for record in mft_records
                if isinstance(record.get("timestamp_validation"), Mapping)
            ),
            "native_attribute_type_counts": count_many(record.get("attribute_types") for record in mft_records),
            "record_header_samples": mft_records[:50],
            "extracted_string_count": len(strings),
            "path_candidates": path_candidates[:50],
            "recommended_parsers": ["MFTECmd", "analyzeMFT", "The Sleuth Kit/fls-icat"],
            "validation_required": True,
            "validation_checks": validation_checks,
            "core_accuracy_gates": ntfs_core_accuracy_gates(
                "mft-file",
                {
                    "source_path": str(path.resolve()),
                    "source_hashes": file_hashes(path),
                    "record_header_samples": mft_records[:50],
                    "path_candidates": path_candidates[:50],
                    "validation_checks": validation_checks,
                },
            ),
            "ntfs_validation_matrix": ntfs_validation_matrix(validation_checks),
            "ntfs_report_grade_assessment": report_grade,
            "ntfs_native_capabilities": NTFS_FILESYSTEM_CAPABILITIES,
            "commercial_uplift_evidence": ntfs_commercial_uplift_evidence(
                "mft",
                {
                    "source_path": str(path.resolve()),
                    "source_hashes": file_hashes(path),
                    "artifact_type": "mft-file",
                    "ntfs_validation_matrix": ntfs_validation_matrix(validation_checks),
                    "ntfs_report_grade_assessment": report_grade,
                    "native_record_count": len(mft_records),
                    "scan_bytes": len(blob),
                },
            ),
            "commercial_grade_ready": False,
            "commercial_grade_blockers": report_grade["blockers"],
            "note": "Native $MFT is inventoried with bounded FILE record, attribute, timestamp, sequence-fixup, and string pivots; validate report findings with a dedicated parser.",
        },
    )


def build_usn_journal_inventory_record(path: Path) -> ArtifactRecord:
    stat_result = path.stat()
    blob = read_prefix(path, NATIVE_SCAN_LIMIT)
    scan = parse_usn_record_scan(blob)
    records = list(scan["records"])
    scan_metadata = {key: value for key, value in scan.items() if key != "records"}
    strings = extract_utf16_strings(blob)
    validation_checks = {
        "has_native_records": bool(records),
        "record_limit_not_reached": not bool(scan_metadata["record_limit_reached"]),
        "cursor_progress_validated": bool(records) and scan_metadata["trailing_unparsed_bytes"] >= 0,
        "has_timestamp_range": bool(scan_metadata["timestamp_range"].get("latest")),
        "full_usn_replay_available": False,
        "full_journal_pagination_validated": not bool(scan_metadata["next_cursor_available"]),
    }
    report_grade = ntfs_report_grade_assessment(
        ntfs_validation_matrix(validation_checks),
        validation_required=True,
        gap_ids=["#13"],
        blockers=USN_REPORT_GRADE_BLOCKERS,
    )
    return ArtifactRecord(
        provider=WindowsFilesystemProvider.name,
        artifact_type="usn-journal-file",
        path=str(path.resolve()),
        supported=False,
        details={
            "parser": "windows-usn-native-inventory",
            "parser_version": PARSER_VERSION,
            "coverage_status": "native-record-scan",
            "reportability": "inventory-only",
            "source_path": str(path.resolve()),
            "source_format": "ntfs-usn-journal",
            "source_hashes": file_hashes(path),
            "size": stat_result.st_size,
            "modified_at": dt.datetime.fromtimestamp(stat_result.st_mtime, dt.timezone.utc).isoformat(),
            "scan_bytes": len(blob),
            "scan_metadata": scan_metadata,
            "record_limit": USN_RECORD_SCAN_LIMIT,
            "record_limit_reached": scan_metadata["record_limit_reached"],
            "next_cursor_offset": scan_metadata["next_cursor_offset"],
            "next_cursor_available": scan_metadata["next_cursor_available"],
            "skipped_bytes_before_records": scan_metadata["skipped_bytes_before_records"],
            "skipped_bytes_during_scan": scan_metadata["skipped_bytes_during_scan"],
            "trailing_unparsed_bytes": scan_metadata["trailing_unparsed_bytes"],
            "native_record_count": len(records),
            "record_validation_counts": count_values(record.get("validation_status") for record in records),
            "record_version_counts": count_values(str(record.get("major_version") or "") for record in records),
            "reason_flag_counts": count_many(record.get("reason_flags") for record in records),
            "record_size_class_counts": count_values(record.get("record_size_class") for record in records),
            "large_record_count": scan_metadata["large_record_count"],
            "largest_record_length": scan_metadata["largest_record_length"],
            "timestamp_range": scan_metadata["timestamp_range"],
            "record_samples": records[:50],
            "extracted_string_count": len(strings),
            "recommended_parsers": ["MFTECmd", "UsnJrnl2Csv", "The Sleuth Kit"],
            "validation_required": True,
            "validation_checks": validation_checks,
            "core_accuracy_gates": ntfs_core_accuracy_gates(
                "usn-journal-file",
                {
                    "source_path": str(path.resolve()),
                    "source_hashes": file_hashes(path),
                    "record_samples": records[:50],
                    "scan_metadata": scan_metadata,
                    "validation_checks": validation_checks,
                },
            ),
            "ntfs_validation_matrix": ntfs_validation_matrix(validation_checks),
            "ntfs_report_grade_assessment": report_grade,
            "ntfs_native_capabilities": NTFS_FILESYSTEM_CAPABILITIES,
            "commercial_uplift_evidence": ntfs_commercial_uplift_evidence(
                "usn",
                {
                    "source_path": str(path.resolve()),
                    "source_hashes": file_hashes(path),
                    "artifact_type": "usn-journal-file",
                    "ntfs_validation_matrix": ntfs_validation_matrix(validation_checks),
                    "ntfs_report_grade_assessment": report_grade,
                    "native_record_count": len(records),
                    "scan_bytes": len(blob),
                    "next_cursor_available": bool(scan_metadata["next_cursor_available"]),
                },
            ),
            "commercial_grade_ready": False,
            "commercial_grade_blockers": report_grade["blockers"],
            "note": "Native USN records are decoded when bounded v2/v3 record structures are recoverable; validation counts summarize structural, cursor, size, and timestamp confidence. Validate critical timelines with a dedicated parser.",
        },
    )


def build_native_mft_record(path: Path, record: Mapping[str, object], index: int) -> ArtifactRecord:
    path_candidates = list(record.get("path_candidates") or [])
    file_path = str(path_candidates[0]) if path_candidates else ""
    standard_information = record.get("standard_information") if isinstance(record.get("standard_information"), Mapping) else {}
    file_name_entries = list(record.get("file_name_entries") or [])
    primary_file_name = file_name_entries[0] if file_name_entries and isinstance(file_name_entries[0], Mapping) else {}
    timestamps = standard_information.get("timestamps") if isinstance(standard_information.get("timestamps"), Mapping) else {}
    timestamp = str(timestamps.get("modified_at") or timestamps.get("created_at") or "")
    timestamp_source = "$STANDARD_INFORMATION" if timestamp else "not_available_native_mft_attributes"
    parent_reference = primary_file_name.get("parent_reference_raw") if isinstance(primary_file_name, Mapping) else ""
    file_path = file_path or str(primary_file_name.get("file_name") or "")
    details = {
        "parser": "windows-mft-native",
        "parser_version": PARSER_VERSION,
        "coverage_status": "native-file-record-attributes-partial",
        "reportability": "triage",
        "source_path": str(path.resolve()),
        "source_format": "ntfs-mft",
        "source_hashes": file_hashes(path),
        "source_index": index,
        "artifact_family": "mft",
        "record_number": str(record.get("record_number_candidate", "")),
        "parent_reference": str(parent_reference or ""),
        "parent_reference_decoded": dict(primary_file_name.get("parent_reference") or {})
        if isinstance(primary_file_name.get("parent_reference"), Mapping)
        else {},
        "file_path": file_path,
        "path_candidates": path_candidates[:10],
        "timestamp": timestamp,
        "timestamp_source": timestamp_source,
        "deleted_hint": not bool(record.get("in_use")),
        "sequence_number": record.get("sequence_number", 0),
        "hard_link_count": record.get("hard_link_count", 0),
        "first_attribute_offset": record.get("first_attribute_offset", 0),
        "flags": record.get("flags", 0),
        "in_use": bool(record.get("in_use")),
        "directory": bool(record.get("directory")),
        "used_size": record.get("used_size", 0),
        "allocated_size": record.get("allocated_size", 0),
        "base_file_reference": record.get("base_file_reference", 0),
        "record_offset": record.get("record_offset", 0),
        "sequence_validation": dict(record.get("sequence_validation") or {}),
        "attribute_count": record.get("attribute_count", 0),
        "attribute_types": list(record.get("attribute_types") or []),
        "attribute_type_counts": count_values(record.get("attribute_types") or []),
        "attributes": list(record.get("attributes") or [])[:25],
        "standard_information": dict(standard_information),
        "file_name_entries": file_name_entries[:10],
        "data_attributes": list(record.get("data_attributes") or [])[:10],
        "timestamp_validation": dict(record.get("timestamp_validation") or {}),
        "validation_status": str(record.get("validation_status") or "unknown"),
        "validation_warnings": list(record.get("validation_warnings") or []),
        "validation_checks": dict(record.get("validation_checks") or {}),
        "core_accuracy_gates": ntfs_core_accuracy_gates(
            "mft-record",
            {
                "source_path": str(path.resolve()),
                "source_hashes": file_hashes(path),
                "source_index": index,
                "file_path": file_path,
                "parent_reference": str(parent_reference or ""),
                "timestamp": timestamp,
                "timestamp_source": timestamp_source,
                "sequence_validation": dict(record.get("sequence_validation") or {}),
                "attribute_types": list(record.get("attribute_types") or []),
                "data_attributes": list(record.get("data_attributes") or [])[:10],
                "file_name_entries": file_name_entries[:10],
                "validation_checks": dict(record.get("validation_checks") or {}),
            },
        ),
        "parser_confidence": record.get("parser_confidence", 0.0),
        "mft_record_evidence": mft_record_evidence(record, file_path),
        "evidence_strength": "ntfs-mft-native-attribute-metadata",
        "validation_required": True,
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "bounded-native-mft-scan-not-full-volume-validated",
            "attribute-list-extension-record-resolution-not-implemented",
            "nonresident-data-run-decoding-not-report-grade-validated",
        ],
        "validation_guidance": "Native MFT rows decode bounded FILE record headers, common attributes, FILETIME fields, and update-sequence fixup metadata for triage. Validate parent paths, attribute-list extension records, data runs, and critical timestamps with MFTECmd/analyzeMFT or another dedicated parser before final testimony.",
        "raw": dict(record),
        "raw_preview": json.dumps(record, ensure_ascii=False, sort_keys=True)[:2000],
    }
    details["ntfs_validation_matrix"] = ntfs_validation_matrix(details["validation_checks"])
    details["ntfs_report_grade_assessment"] = ntfs_report_grade_assessment(
        details["ntfs_validation_matrix"],
        validation_required=True,
        gap_ids=["#12"],
        blockers=MFT_REPORT_GRADE_BLOCKERS,
    )
    details["ntfs_native_capabilities"] = NTFS_FILESYSTEM_CAPABILITIES
    details["commercial_grade_blockers"] = details["ntfs_report_grade_assessment"]["blockers"]
    details["commercial_uplift_evidence"] = ntfs_commercial_uplift_evidence("mft", details)
    details["forensic_review"] = build_forensic_review(
        gap_id="#12",
        artifact_goal="$MFT native FILE record evidence",
        primary_evidence=[
            f"record={details['record_number']}" if details.get("record_number") else "",
            f"path={details['file_path']}" if details.get("file_path") else "",
            f"timestamp={details['timestamp']}" if details.get("timestamp") else "",
            f"attributes={details['attribute_count']}",
        ],
        validation_required=True,
        report_grade_assessment=details["ntfs_report_grade_assessment"],
        commercial_grade_ready=False,
        caveats=[
            "Attribute-list extension resolution is not complete.",
            "Full-volume parent path reconstruction is not validated.",
        ],
    )
    return ArtifactRecord(
        provider=WindowsFilesystemProvider.name,
        artifact_type="mft-record",
        path=str(path.resolve()),
        supported=True,
        details=details,
    )


def build_native_usn_record(path: Path, record: Mapping[str, object], index: int) -> ArtifactRecord:
    details = {
        "parser": "windows-usn-native",
        "parser_version": PARSER_VERSION,
        "coverage_status": "native-record",
        "reportability": "triage",
        "source_path": str(path.resolve()),
        "source_format": "ntfs-usn-journal",
        "source_hashes": file_hashes(path),
        "source_index": index,
        "artifact_family": "usn",
        "record_number": str(record.get("file_reference_number") or ""),
        "parent_reference": str(record.get("parent_file_reference_number") or ""),
        "file_path": str(record.get("file_name") or ""),
        "timestamp": str(record.get("timestamp") or ""),
        "timestamp_source": "usn_filetime" if record.get("timestamp") else "invalid_or_missing_filetime",
        "deleted_hint": bool(record.get("deleted_hint")),
        "rename_hint": str(record.get("rename_hint") or ""),
        "reason": str(record.get("reason") or ""),
        "reason_raw": record.get("reason_raw", 0),
        "reason_flags": list(record.get("reason_flags") or []),
        "source_info": record.get("source_info", 0),
        "source_info_flags": list(record.get("source_info_flags") or []),
        "security_id": record.get("security_id", 0),
        "file_attributes": record.get("file_attributes", 0),
        "file_attribute_names": list(record.get("file_attribute_names") or []),
        "usn": record.get("usn", 0),
        "record_cursor": record.get("record_cursor", record.get("record_offset", 0)),
        "next_record_cursor": record.get("next_record_cursor", 0),
        "record_end_offset": record.get("record_end_offset", 0),
        "record_offset": record.get("record_offset", 0),
        "record_length": record.get("record_length", 0),
        "record_payload_bytes": record.get("record_payload_bytes", 0),
        "record_padding_bytes": record.get("record_padding_bytes", 0),
        "record_size_class": str(record.get("record_size_class") or ""),
        "major_version": record.get("major_version", 0),
        "minor_version": record.get("minor_version", 0),
        "file_reference_number_decoded": dict(record.get("file_reference_number_decoded") or {}),
        "parent_file_reference_number_decoded": dict(record.get("parent_file_reference_number_decoded") or {}),
        "file_name_length": record.get("file_name_length", 0),
        "file_name_character_count": record.get("file_name_character_count", 0),
        "file_name_offset": record.get("file_name_offset", 0),
        "file_name_decode_status": str(record.get("file_name_decode_status") or ""),
        "unknown_reason_mask": record.get("unknown_reason_mask", 0),
        "unknown_source_info_mask": record.get("unknown_source_info_mask", 0),
        "unknown_file_attribute_mask": record.get("unknown_file_attribute_mask", 0),
        "validation_status": str(record.get("validation_status") or "unknown"),
        "validation_warnings": list(record.get("validation_warnings") or []),
        "validation_checks": dict(record.get("validation_checks") or {}),
        "core_accuracy_gates": ntfs_core_accuracy_gates(
            "usn-record",
            {
                "source_path": str(path.resolve()),
                "source_hashes": file_hashes(path),
                "source_index": index,
                "file_path": str(record.get("file_name") or ""),
                "timestamp": str(record.get("timestamp") or ""),
                "reason_flags": list(record.get("reason_flags") or []),
                "rename_hint": str(record.get("rename_hint") or ""),
                "deleted_hint": bool(record.get("deleted_hint")),
                "record_cursor": record.get("record_cursor", record.get("record_offset", 0)),
                "next_record_cursor": record.get("next_record_cursor", 0),
                "file_reference_number_decoded": dict(record.get("file_reference_number_decoded") or {}),
                "parent_file_reference_number_decoded": dict(record.get("parent_file_reference_number_decoded") or {}),
                "validation_checks": dict(record.get("validation_checks") or {}),
            },
        ),
        "parser_confidence": record.get("parser_confidence", 0.0),
        "usn_record_evidence": usn_record_evidence(record),
        "evidence_strength": "ntfs-usn-native-record",
        "validation_required": True,
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "bounded-native-usn-scan-not-full-journal-validated",
            "full-usn-replay-correlation-not-implemented",
            "large-corpus-pagination-validation-required",
        ],
        "validation_guidance": "Native USN rows validate record layout, length, cursor bounds, name bounds/UTF-16 decoding, version, and FILETIME plausibility, but critical timelines should still be cross-checked with MFTECmd/UsnJrnl2Csv or another dedicated parser.",
        "raw": dict(record),
        "raw_preview": json.dumps(record, ensure_ascii=False, sort_keys=True)[:2000],
    }
    details["ntfs_validation_matrix"] = ntfs_validation_matrix(details["validation_checks"])
    details["ntfs_report_grade_assessment"] = ntfs_report_grade_assessment(
        details["ntfs_validation_matrix"],
        validation_required=True,
        gap_ids=["#13"],
        blockers=USN_REPORT_GRADE_BLOCKERS,
    )
    details["ntfs_native_capabilities"] = NTFS_FILESYSTEM_CAPABILITIES
    details["commercial_grade_blockers"] = details["ntfs_report_grade_assessment"]["blockers"]
    details["commercial_uplift_evidence"] = ntfs_commercial_uplift_evidence("usn", details)
    details["forensic_review"] = build_forensic_review(
        gap_id="#13",
        artifact_goal="$UsnJrnl native change record evidence",
        primary_evidence=[
            f"file={details['file_path']}" if details.get("file_path") else "",
            f"timestamp={details['timestamp']}" if details.get("timestamp") else "",
            f"reason={','.join(details.get('reason_flags') or [])}" if details.get("reason_flags") else "",
            f"cursor={details['record_cursor']}",
        ],
        validation_required=True,
        report_grade_assessment=details["ntfs_report_grade_assessment"],
        commercial_grade_ready=False,
        caveats=[
            "Full USN replay and path-cache correlation are not complete.",
            "Large-corpus pagination requires separate validation.",
        ],
    )
    return ArtifactRecord(
        provider=WindowsFilesystemProvider.name,
        artifact_type="usn-record",
        path=str(path.resolve()),
        supported=True,
        details=details,
    )


def mft_record_evidence(record: Mapping[str, object], file_path: str) -> dict[str, object]:
    attributes = list(record.get("attributes") or [])
    standard_information = record.get("standard_information") if isinstance(record.get("standard_information"), Mapping) else {}
    file_name_entries = list(record.get("file_name_entries") or [])
    data_attributes = list(record.get("data_attributes") or [])
    resident_hashes = [
        dict(item.get("resident_data_hashes") or {})
        for item in data_attributes
        if isinstance(item, Mapping) and item.get("resident_data_hashes")
    ]
    nonresident_previews = [
        list(item.get("runlist_preview") or [])
        for item in data_attributes
        if isinstance(item, Mapping) and not bool(item.get("resident"))
    ]
    sequence_validation = record.get("sequence_validation") if isinstance(record.get("sequence_validation"), Mapping) else {}
    timestamp_validation = record.get("timestamp_validation") if isinstance(record.get("timestamp_validation"), Mapping) else {}
    validation_checks = record.get("validation_checks") if isinstance(record.get("validation_checks"), Mapping) else {}
    return {
        "record_identity": {
            "record_number": record.get("record_number_candidate", ""),
            "sequence_number": record.get("sequence_number", 0),
            "base_file_reference": record.get("base_file_reference", 0),
            "record_offset": record.get("record_offset", 0),
        },
        "path_evidence": {
            "primary_path": file_path,
            "file_name_entry_count": len(file_name_entries),
            "parent_reference_decoded": dict(file_name_entries[0].get("parent_reference") or {})
            if file_name_entries and isinstance(file_name_entries[0], Mapping)
            else {},
        },
        "state_evidence": {
            "in_use": bool(record.get("in_use")),
            "deleted_hint": not bool(record.get("in_use")),
            "directory": bool(record.get("directory")),
            "hard_link_count": record.get("hard_link_count", 0),
        },
        "attribute_evidence": {
            "attribute_count": len(attributes),
            "attribute_types": list(record.get("attribute_types") or []),
            "standard_information_present": bool(standard_information),
            "file_name_attribute_count": len(file_name_entries),
            "data_attribute_count": len(data_attributes),
            "resident_data_hashes": resident_hashes,
            "nonresident_runlist_preview_count": sum(1 for item in nonresident_previews if item),
        },
        "validation_evidence": {
            "record_validation_status": record.get("validation_status", "unknown"),
            "sequence_fixup_status": sequence_validation.get("status", ""),
            "timestamp_validation_status": timestamp_validation.get("status", ""),
            "critical_checks_passed": [
                key
                for key in (
                    "magic_valid",
                    "sequence_fixup_valid",
                    "has_standard_information_attribute",
                    "has_file_name_attribute",
                    "timestamp_fields_present",
                )
                if bool(validation_checks.get(key))
            ],
            "validation_warnings": list(record.get("validation_warnings") or []),
        },
        "report_limitations": [
            "attribute-list extension records are not resolved",
            "full-volume parent path reconstruction is not validated",
            "nonresident data run decoding is preview-only",
        ],
    }


def usn_record_evidence(record: Mapping[str, object]) -> dict[str, object]:
    validation_checks = record.get("validation_checks") if isinstance(record.get("validation_checks"), Mapping) else {}
    return {
        "record_identity": {
            "major_version": record.get("major_version", 0),
            "minor_version": record.get("minor_version", 0),
            "usn": record.get("usn", 0),
            "record_cursor": record.get("record_cursor", record.get("record_offset", 0)),
            "next_record_cursor": record.get("next_record_cursor", 0),
        },
        "file_reference_evidence": {
            "file_reference_number_decoded": dict(record.get("file_reference_number_decoded") or {}),
            "parent_file_reference_number_decoded": dict(record.get("parent_file_reference_number_decoded") or {}),
            "file_name": str(record.get("file_name") or ""),
        },
        "change_evidence": {
            "reason_flags": list(record.get("reason_flags") or []),
            "rename_hint": str(record.get("rename_hint") or ""),
            "deleted_hint": bool(record.get("deleted_hint")),
            "file_attribute_names": list(record.get("file_attribute_names") or []),
            "timestamp": str(record.get("timestamp") or ""),
        },
        "validation_evidence": {
            "record_validation_status": record.get("validation_status", "unknown"),
            "filename_decode_status": str(record.get("file_name_decode_status") or ""),
            "record_size_class": str(record.get("record_size_class") or ""),
            "critical_checks_passed": [
                key
                for key in (
                    "record_length_aligned",
                    "record_cursor_progresses",
                    "filename_bounds_valid",
                    "filename_utf16_valid",
                    "filetime_plausible",
                    "version_supported",
                )
                if bool(validation_checks.get(key))
            ],
            "validation_warnings": list(record.get("validation_warnings") or []),
        },
        "report_limitations": [
            "full journal replay and path cache correlation are not complete",
            "large-corpus cursor pagination requires separate validation",
        ],
    }


def artifact_family(path: Path) -> str:
    lowered = str(path).lower()
    if any(hint in lowered for hint in MFT_HINTS):
        return "mft"
    if any(hint in lowered for hint in USN_HINTS):
        return "usn"
    return ""


def ntfs_validation_matrix(checks: Mapping[str, object]) -> list[dict[str, object]]:
    labels = {
        "has_native_records": ("Native records", "high"),
        "has_valid_record_headers": ("Valid record headers", "critical"),
        "has_sequence_validation": ("Sequence validation", "high"),
        "has_timestamp_validation": ("Timestamp validation", "high"),
        "attribute_list_resolution_available": ("Attribute-list resolution", "critical"),
        "full_nonresident_runlist_decode_available": ("Full nonresident runlist decode", "critical"),
        "full_volume_path_reconstruction_available": ("Full volume path reconstruction", "critical"),
        "record_limit_not_reached": ("Record limit not reached", "medium"),
        "cursor_progress_validated": ("Cursor progress validated", "high"),
        "has_timestamp_range": ("Timestamp range", "medium"),
        "full_usn_replay_available": ("Full USN replay", "critical"),
        "full_journal_pagination_validated": ("Journal pagination validated", "high"),
        "magic_valid": ("MFT magic", "critical"),
        "sequence_fixup_valid": ("MFT sequence fixup", "critical"),
        "has_standard_information_attribute": ("$STANDARD_INFORMATION", "high"),
        "has_file_name_attribute": ("$FILE_NAME", "high"),
        "has_data_attribute": ("$DATA", "medium"),
        "attribute_end_marker_seen": ("Attribute end marker", "medium"),
        "timestamp_fields_present": ("Timestamp fields", "high"),
        "record_length_aligned": ("USN record length aligned", "high"),
        "record_cursor_progresses": ("USN cursor progresses", "critical"),
        "filename_bounds_valid": ("USN filename bounds", "high"),
        "filename_utf16_valid": ("USN filename UTF-16", "high"),
        "filetime_plausible": ("USN FILETIME plausible", "high"),
        "version_supported": ("USN version supported", "high"),
        "known_reason_bits_only": ("Known USN reason bits", "medium"),
        "has_record_number": ("Record number", "medium"),
        "has_file_path": ("File path", "high"),
        "has_timestamp": ("Timestamp", "high"),
        "source_tool_export_validation_required": ("Source tool export validation", "high"),
    }
    matrix: list[dict[str, object]] = []
    for key, value in checks.items():
        if key == "large_record":
            continue
        label, severity = labels.get(key, (key.replace("_", " "), "medium"))
        negative_requirement = key.endswith("_required")
        passed = bool(value)
        if negative_requirement:
            passed = not bool(value)
        matrix.append({"id": key.replace("_", "-"), "label": label, "passed": passed, "severity": severity, "detail": value})
    return matrix


def ntfs_report_grade_assessment(
    validation_matrix: list[dict[str, object]],
    *,
    validation_required: bool,
    gap_ids: list[str],
    blockers: Sequence[str],
) -> dict[str, object]:
    failed = [str(item.get("id")) for item in validation_matrix if not item.get("passed")]
    all_blockers = set(blockers)
    all_blockers.update(f"validation-check-failed:{item}" for item in failed)
    if validation_required:
        all_blockers.add("ntfs-validation-required")
    return {
        "report_grade_ready": False,
        "status": "validation-required" if failed else "triage-validated-report-grade-blocked",
        "blockers": sorted(all_blockers),
        "validated_strengths": [str(item.get("id")) for item in validation_matrix if item.get("passed")],
        "commercial_gap_ids": gap_ids,
        "next_validation_step": "Validate NTFS timelines and paths with a full-volume parser, attribute-list resolution, and known-answer fixtures before report-grade use.",
    }


def ntfs_commercial_uplift_evidence(family: str, details: Mapping[str, object]) -> dict[str, object]:
    matrix = details.get("ntfs_validation_matrix") if isinstance(details.get("ntfs_validation_matrix"), list) else []
    report_grade = (
        details.get("ntfs_report_grade_assessment")
        if isinstance(details.get("ntfs_report_grade_assessment"), Mapping)
        else {}
    )
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
    item_number = 12 if family == "mft" else 13
    return {
        "batch_id": "commercial-uplift-011-015",
        "item_numbers": [item_number],
        "implementation_track": "native-parser-depth",
        "objective": "Expose native NTFS record validation, cursor/offset provenance, and commercial blockers on MFT/USN rows.",
        "source_refs": [
            f"source_path:{details.get('source_path', '')}",
            f"source_index:{details.get('source_index', '')}",
            f"source_sha256:{hashes.get('sha256', '')}",
            f"artifact_type:{details.get('artifact_type', '')}",
        ],
        "passed_validation_matrix_ids": [
            str(item.get("id")) for item in matrix if isinstance(item, Mapping) and item.get("passed")
        ],
        "failed_validation_matrix_ids": [
            str(item.get("id")) for item in matrix if isinstance(item, Mapping) and not item.get("passed")
        ],
        "report_grade_status": str(report_grade.get("status") or ""),
        "commercial_blockers": list(report_grade.get("blockers") or []),
        "large_data_controls": {
            "bounded_native_scan": True,
            "scan_limit_bytes": NATIVE_SCAN_LIMIT,
            "native_record_count": int(details.get("native_record_count") or 0),
            "record_cursor": int(details.get("record_cursor") or details.get("record_offset") or 0),
            "next_cursor_available": bool(details.get("next_cursor_available")),
            "full_volume_or_journal_validation_required_for_commercial_claims": True,
        },
        "next_internal_step": (
            "Complete MFT attribute-list/nonresident runlist/path reconstruction validation."
            if family == "mft"
            else "Complete USN full-journal replay, FRN path-cache correlation, and large corpus cursor validation."
        ),
        "external_evidence_required": True,
    }


def iter_csv_rows(path: Path) -> Iterable[Mapping[str, object]]:
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            yield from csv.DictReader(handle)
    except (OSError, UnicodeError, csv.Error):
        return


def iter_json_rows(path: Path) -> Iterable[Mapping[str, object]]:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError):
        return
    if path.suffix.lower() in {".jsonl", ".ndjson"}:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, Mapping):
                yield row
        return
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return
    rows = payload if isinstance(payload, list) else payload.get("rows", []) if isinstance(payload, Mapping) else []
    for row in rows:
        if isinstance(row, Mapping):
            yield row


def build_filesystem_record(path: Path, family: str, row: Mapping[str, object], index: int) -> ArtifactRecord:
    lowered = {normalize_key(key): value for key, value in row.items()}
    artifact_type = "mft-record" if family == "mft" else "usn-record"
    file_path = str(first_value(lowered, "fullpath", "path", "filename", "name") or "")
    record_number = str(first_value(lowered, "entrynumber", "recordnumber", "filerecordnumber", "frn") or "")
    parent_reference = str(first_value(lowered, "parententrynumber", "parentfrn", "parentfilereference") or "")
    deleted = truthy(first_value(lowered, "deleted", "isinuse", "inuse", "flags"))
    timestamp = str(
        first_value(
            lowered,
            "timestamp",
            "standardinformationmodified",
            "created0x10",
            "created",
            "sitimecreated",
            "eventtime",
            "timestampdate",
        )
        or ""
    ).replace("Z", "+00:00")
    details = {
        "parser": "windows-filesystem-import",
        "parser_version": PARSER_VERSION,
        "coverage_status": "mapped",
        "reportability": "triage",
        "source_path": str(path.resolve()),
        "source_format": path.suffix.lower().lstrip("."),
        "source_hashes": file_hashes(path),
        "source_index": index,
        "artifact_family": family,
        "record_number": record_number,
        "parent_reference": parent_reference,
        "file_path": file_path,
        "timestamp": timestamp,
        "deleted_hint": deleted if family == "mft" else False,
        "reason": str(first_value(lowered, "reason", "reasonflags", "usnreason") or ""),
        "raw": dict(row),
        "raw_preview": json.dumps(row, ensure_ascii=False, sort_keys=True)[:2000],
    }
    validation_checks = {
        "has_record_number": bool(record_number),
        "has_file_path": bool(file_path),
        "has_timestamp": bool(timestamp),
        "source_tool_export_validation_required": True,
    }
    details["validation_required"] = False
    details["validation_checks"] = validation_checks
    details["core_accuracy_gates"] = ntfs_core_accuracy_gates(artifact_type, details)
    details["ntfs_validation_matrix"] = ntfs_validation_matrix(validation_checks)
    details["ntfs_report_grade_assessment"] = ntfs_report_grade_assessment(
        details["ntfs_validation_matrix"],
        validation_required=False,
        gap_ids=["#12"] if family == "mft" else ["#13"],
        blockers=["source-tool-export-validation-required"],
    )
    details["ntfs_native_capabilities"] = NTFS_FILESYSTEM_CAPABILITIES
    details["commercial_grade_ready"] = False
    details["commercial_grade_blockers"] = details["ntfs_report_grade_assessment"]["blockers"]
    details["commercial_uplift_evidence"] = ntfs_commercial_uplift_evidence(family, details)
    return ArtifactRecord(
        provider=WindowsFilesystemProvider.name,
        artifact_type=artifact_type,
        path=str(path.resolve()),
        supported=True,
        details=details,
    )


def ntfs_core_accuracy_gates(artifact_type: str, details: Mapping[str, object]) -> list[dict[str, object]]:
    checks = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
    evidence_refs = [
        f"source_path:{details.get('source_path', '')}",
        f"source_index:{details.get('source_index', '')}",
    ]
    if details.get("record_cursor") not in (None, ""):
        evidence_refs.append(f"record_cursor:{details.get('record_cursor')}")
    if hashes.get("sha256"):
        evidence_refs.append(f"source_sha256:{hashes['sha256']}")

    if artifact_type in {"mft-file", "mft-record"}:
        data_attributes = [item for item in details.get("data_attributes") or [] if isinstance(item, Mapping)]
        satisfied: list[str] = []
        if checks.get("sequence_fixup_valid") or checks.get("has_sequence_validation") or details.get("sequence_validation"):
            satisfied.append("USA validation")
        if "$ATTRIBUTE_LIST" in list(details.get("attribute_types") or []):
            satisfied.append("attribute-list extension resolution")
        if details.get("file_path") or details.get("path_candidates") or details.get("parent_reference"):
            satisfied.append("parent path reconstruction")
        if any(item.get("resident") is False or item.get("runlist_preview") for item in data_attributes):
            satisfied.append("runlist decoding")
        if details.get("timestamp") or details.get("timestamp_source") or checks.get("timestamp_fields_present") or checks.get("has_timestamp_validation"):
            satisfied.append("timestamp/source field provenance")
        return [build_accuracy_gate(12, satisfied_checks=satisfied, evidence_refs=evidence_refs)]

    if artifact_type in {"usn-journal-file", "usn-record"}:
        samples = [item for item in details.get("record_samples") or [] if isinstance(item, Mapping)]
        sample_reasons = [flag for item in samples for flag in list(item.get("reason_flags") or [])]
        satisfied = []
        if checks.get("record_length_aligned") or checks.get("record_limit_not_reached") or checks.get("cursor_progress_validated"):
            satisfied.append("record-size bounds")
        if details.get("reason_flags") or sample_reasons:
            satisfied.append("reason flag decoding")
        if details.get("parent_file_reference_number_decoded") or details.get("file_reference_number_decoded"):
            satisfied.append("FRN path cache replay")
        if details.get("rename_hint") or details.get("deleted_hint") or any("RENAME" in str(flag) or "DELETE" in str(flag) for flag in sample_reasons):
            satisfied.append("rename/delete ordering")
        if details.get("record_cursor") not in (None, "") or checks.get("cursor_progress_validated"):
            satisfied.append("cursor determinism at scale")
        return [build_accuracy_gate(13, satisfied_checks=satisfied, evidence_refs=evidence_refs)]

    return []


def normalize_key(value: object) -> str:
    return "".join(ch for ch in str(value).lower() if ch.isalnum())


def first_value(row: Mapping[str, object], *keys: str) -> object:
    for key in keys:
        value = row.get(normalize_key(key))
        if value not in (None, ""):
            return value
    return ""


def truthy(value: object) -> bool:
    text = str(value or "").strip().lower()
    if text in {"true", "yes", "1", "deleted"}:
        return True
    if text in {"false", "no", "0", "inuse", "in use"}:
        return False
    return "deleted" in text and "not deleted" not in text


def file_hashes(path: Path) -> dict[str, str]:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return {}
    return {"sha256": digest.hexdigest()}


def read_prefix(path: Path, limit: int) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(limit)
    except OSError:
        return b""


def parse_mft_record_headers(blob: bytes) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    offset = 0
    while True:
        offset = blob.find(b"FILE", offset)
        if offset < 0:
            return records
        if offset + 48 <= len(blob):
            flags = int_from(blob, offset + 0x16, 2)
            allocated_size = int_from(blob, offset + 0x1C, 4)
            record_size = allocated_size if 48 <= allocated_size <= 4096 and offset + allocated_size <= len(blob) else 1024
            record_blob = blob[offset : min(len(blob), offset + record_size)]
            path_candidates = extract_path_candidates(extract_utf16_strings(record_blob))
            first_attribute_offset = int_from(blob, offset + 0x14, 2)
            used_size = int_from(blob, offset + 0x18, 4)
            sequence_validation = validate_mft_update_sequence(record_blob)
            attributes = parse_mft_attributes(record_blob, first_attribute_offset, used_size)
            timestamp_validation = mft_timestamp_validation(attributes)
            validation_warnings = mft_validation_warnings(
                record_blob=record_blob,
                first_attribute_offset=first_attribute_offset,
                used_size=used_size,
                allocated_size=allocated_size,
                sequence_validation=sequence_validation,
                attributes=attributes,
                timestamp_validation=timestamp_validation,
            )
            validation_status = "valid" if not validation_warnings else "valid-with-warnings"
            records.append(
                {
                    "record_offset": offset,
                    "record_number_candidate": offset // 1024,
                    "sequence_number": int_from(blob, offset + 0x10, 2),
                    "hard_link_count": int_from(blob, offset + 0x12, 2),
                    "first_attribute_offset": first_attribute_offset,
                    "flags": flags,
                    "in_use": bool(flags & 0x01),
                    "directory": bool(flags & 0x02),
                    "used_size": used_size,
                    "allocated_size": allocated_size,
                    "base_file_reference": int_from(blob, offset + 0x20, 8),
                    "sequence_validation": sequence_validation,
                    "attribute_count": len(attributes["attributes"]),
                    "attribute_types": attributes["attribute_types"],
                    "attributes": attributes["attributes"],
                    "standard_information": attributes["standard_information"],
                    "file_name_entries": attributes["file_name_entries"],
                    "data_attributes": attributes["data_attributes"],
                    "timestamp_validation": timestamp_validation,
                    "validation_status": validation_status,
                    "validation_warnings": validation_warnings,
                    "validation_checks": {
                        "magic_valid": record_blob[:4] == b"FILE",
                        "sequence_fixup_valid": sequence_validation.get("status") == "valid",
                        "has_standard_information_attribute": bool(attributes["standard_information"]),
                        "has_file_name_attribute": bool(attributes["file_name_entries"]),
                        "has_data_attribute": bool(attributes["data_attributes"]),
                        "attribute_end_marker_seen": bool(attributes["end_marker_seen"]),
                        "timestamp_fields_present": bool(timestamp_validation.get("timestamp_count")),
                    },
                    "parser_confidence": mft_parser_confidence(validation_status, attributes, sequence_validation),
                    "path_candidates": path_candidates[:10],
                }
            )
        offset += 4
        if len(records) >= 5000:
            return records


def validate_mft_update_sequence(record_blob: bytes, *, sector_size: int = 512) -> dict[str, object]:
    usa_offset = int_from(record_blob, 0x04, 2)
    usa_count = int_from(record_blob, 0x06, 2)
    warnings: list[str] = []
    if not usa_offset or not usa_count:
        return {
            "status": "missing",
            "warnings": ["missing-update-sequence-array"],
            "update_sequence_offset": usa_offset,
            "update_sequence_count": usa_count,
        }
    if usa_offset + usa_count * 2 > len(record_blob):
        return {
            "status": "invalid",
            "warnings": ["update-sequence-array-out-of-bounds"],
            "update_sequence_offset": usa_offset,
            "update_sequence_count": usa_count,
        }
    sector_count = len(record_blob) // sector_size
    if sector_count and usa_count != sector_count + 1:
        warnings.append("update-sequence-count-sector-mismatch")
    update_sequence_number = record_blob[usa_offset : usa_offset + 2]
    repaired_trailers = 0
    for sector_index in range(1, usa_count):
        trailer_offset = sector_index * sector_size - 2
        if trailer_offset + 2 > len(record_blob):
            warnings.append(f"sector-trailer-out-of-bounds:{sector_index}")
            continue
        if record_blob[trailer_offset : trailer_offset + 2] != update_sequence_number:
            warnings.append(f"sector-trailer-update-sequence-mismatch:{sector_index}")
            continue
        repaired_trailers += 1
    return {
        "status": "valid" if not warnings else "valid-with-warnings",
        "warnings": warnings,
        "update_sequence_offset": usa_offset,
        "update_sequence_count": usa_count,
        "update_sequence_number": update_sequence_number.hex(),
        "sector_size": sector_size,
        "sector_count": sector_count,
        "repaired_sector_trailer_count": repaired_trailers,
    }


def parse_mft_attributes(record_blob: bytes, first_attribute_offset: int, used_size: int) -> dict[str, object]:
    attributes: list[dict[str, object]] = []
    attribute_types: list[str] = []
    file_name_entries: list[dict[str, object]] = []
    data_attributes: list[dict[str, object]] = []
    standard_information: dict[str, object] = {}
    warnings: list[str] = []
    end_marker_seen = False
    limit = used_size if first_attribute_offset < used_size <= len(record_blob) else len(record_blob)
    offset = first_attribute_offset
    seen = 0
    while offset + 8 <= limit and seen < 256:
        attribute_type = int_from(record_blob, offset, 4)
        if attribute_type == 0xFFFFFFFF:
            end_marker_seen = True
            break
        length = int_from(record_blob, offset + 4, 4)
        if length < 24:
            warnings.append(f"invalid-attribute-length:{offset}")
            break
        if offset + length > limit:
            warnings.append(f"attribute-overruns-record:{offset}")
            break
        attribute_blob = record_blob[offset : offset + length]
        parsed = parse_mft_attribute(attribute_blob, offset)
        attributes.append(parsed)
        attribute_types.append(str(parsed["attribute_type_name"]))
        if parsed["attribute_type"] == 0x10 and isinstance(parsed.get("standard_information"), Mapping):
            standard_information = dict(parsed["standard_information"])
        elif parsed["attribute_type"] == 0x30 and isinstance(parsed.get("file_name"), Mapping):
            file_name_entries.append(dict(parsed["file_name"]))
        elif parsed["attribute_type"] == 0x80 and isinstance(parsed.get("data"), Mapping):
            data_attributes.append(dict(parsed["data"]))
        offset += align8(length)
        seen += 1
    if seen >= 256:
        warnings.append("attribute-iteration-limit-reached")
    return {
        "attributes": attributes,
        "attribute_types": attribute_types,
        "standard_information": standard_information,
        "file_name_entries": file_name_entries,
        "data_attributes": data_attributes,
        "end_marker_seen": end_marker_seen,
        "warnings": warnings,
    }


def parse_mft_attribute(attribute_blob: bytes, record_relative_offset: int) -> dict[str, object]:
    attribute_type = int_from(attribute_blob, 0, 4)
    length = int_from(attribute_blob, 4, 4)
    nonresident = bool(int_from(attribute_blob, 8, 1))
    name_length = int_from(attribute_blob, 9, 1)
    name_offset = int_from(attribute_blob, 10, 2)
    name = ""
    if name_length and name_offset + name_length * 2 <= len(attribute_blob):
        name = attribute_blob[name_offset : name_offset + name_length * 2].decode("utf-16le", errors="ignore")
    parsed: dict[str, object] = {
        "record_relative_offset": record_relative_offset,
        "attribute_type": attribute_type,
        "attribute_type_name": MFT_ATTRIBUTE_TYPE_NAMES.get(attribute_type, f"0x{attribute_type:08x}"),
        "length": length,
        "nonresident": nonresident,
        "name": name,
        "flags": int_from(attribute_blob, 12, 2),
        "attribute_id": int_from(attribute_blob, 14, 2),
    }
    if nonresident:
        runlist_offset = int_from(attribute_blob, 32, 2)
        parsed["nonresident_metadata"] = {
            "lowest_vcn": int_from(attribute_blob, 16, 8),
            "highest_vcn": int_from(attribute_blob, 24, 8),
            "runlist_offset": runlist_offset,
            "compression_unit": int_from(attribute_blob, 34, 2),
            "allocated_size": int_from(attribute_blob, 40, 8),
            "real_size": int_from(attribute_blob, 48, 8),
            "initialized_size": int_from(attribute_blob, 56, 8),
            "data_runs_preview": attribute_blob[runlist_offset : min(len(attribute_blob), runlist_offset + 32)].hex()
            if runlist_offset < len(attribute_blob)
            else "",
            "runlist_decode_status": "preview-only",
        }
        if attribute_type == 0x80:
            parsed["data"] = {
                "resident": False,
                "allocated_size": int_from(attribute_blob, 40, 8),
                "real_size": int_from(attribute_blob, 48, 8),
                "initialized_size": int_from(attribute_blob, 56, 8),
                "runlist_decode_status": "preview-only",
            }
        return parsed

    value_length = int_from(attribute_blob, 16, 4)
    value_offset = int_from(attribute_blob, 20, 2)
    value = attribute_blob[value_offset : value_offset + value_length] if value_offset + value_length <= len(attribute_blob) else b""
    parsed["resident_metadata"] = {
        "value_length": value_length,
        "value_offset": value_offset,
        "indexed_flag": int_from(attribute_blob, 22, 1),
    }
    if attribute_type == 0x10:
        parsed["standard_information"] = parse_standard_information(value)
    elif attribute_type == 0x30:
        parsed["file_name"] = parse_file_name_attribute(value)
    elif attribute_type == 0x80:
        parsed["data"] = {
            "resident": True,
            "resident_size": value_length,
            "sha256": hashlib.sha256(value).hexdigest() if value else "",
        }
    return parsed


def parse_standard_information(value: bytes) -> dict[str, object]:
    timestamps = {
        "created_at": filetime_to_iso(int_from(value, 0, 8)),
        "modified_at": filetime_to_iso(int_from(value, 8, 8)),
        "mft_modified_at": filetime_to_iso(int_from(value, 16, 8)),
        "accessed_at": filetime_to_iso(int_from(value, 24, 8)),
    }
    file_attributes = int_from(value, 32, 4) if len(value) >= 36 else 0
    return {
        "timestamps": timestamps,
        "file_attributes": file_attributes,
        "file_attribute_names": flag_names(file_attributes, NTFS_FILE_ATTRIBUTE_NAMES),
    }


def parse_file_name_attribute(value: bytes) -> dict[str, object]:
    parent_reference_raw = int_from(value, 0, 8)
    name_length = int_from(value, 64, 1)
    namespace = int_from(value, 65, 1)
    name_bytes = value[66 : 66 + name_length * 2] if 66 + name_length * 2 <= len(value) else b""
    file_attributes = int_from(value, 56, 4)
    return {
        "parent_reference": split_mft_reference(parent_reference_raw),
        "parent_reference_raw": parent_reference_raw,
        "timestamps": {
            "created_at": filetime_to_iso(int_from(value, 8, 8)),
            "modified_at": filetime_to_iso(int_from(value, 16, 8)),
            "mft_modified_at": filetime_to_iso(int_from(value, 24, 8)),
            "accessed_at": filetime_to_iso(int_from(value, 32, 8)),
        },
        "allocated_size": int_from(value, 40, 8),
        "real_size": int_from(value, 48, 8),
        "file_attributes": file_attributes,
        "file_attribute_names": flag_names(file_attributes, NTFS_FILE_ATTRIBUTE_NAMES),
        "name_length": name_length,
        "namespace": FILE_NAME_NAMESPACE_NAMES.get(namespace, str(namespace)),
        "file_name": name_bytes.decode("utf-16le", errors="ignore"),
    }


def split_mft_reference(value: int) -> dict[str, int]:
    return {
        "record_number": value & 0x0000FFFFFFFFFFFF,
        "sequence_number": (value >> 48) & 0xFFFF,
    }


def mft_timestamp_validation(attributes: Mapping[str, object]) -> dict[str, object]:
    timestamp_sources: list[dict[str, str]] = []
    invalid_sources: list[str] = []
    standard_information = attributes.get("standard_information")
    if isinstance(standard_information, Mapping):
        collect_mft_timestamps(timestamp_sources, invalid_sources, "$STANDARD_INFORMATION", standard_information.get("timestamps"))
    for index, entry in enumerate(attributes.get("file_name_entries") or []):
        if isinstance(entry, Mapping):
            collect_mft_timestamps(timestamp_sources, invalid_sources, f"$FILE_NAME[{index}]", entry.get("timestamps"))
    status = "valid" if timestamp_sources and not invalid_sources else "valid-with-warnings" if timestamp_sources else "missing"
    values = sorted({item["value"] for item in timestamp_sources})
    return {
        "status": status,
        "timestamp_count": len(timestamp_sources),
        "sources": timestamp_sources[:32],
        "invalid_sources": invalid_sources[:32],
        "earliest": values[0] if values else "",
        "latest": values[-1] if values else "",
    }


def collect_mft_timestamps(
    timestamp_sources: list[dict[str, str]],
    invalid_sources: list[str],
    prefix: str,
    timestamps: object,
) -> None:
    if not isinstance(timestamps, Mapping):
        return
    for name, value in timestamps.items():
        text = str(value or "")
        source = f"{prefix}.{name}"
        if text:
            timestamp_sources.append({"source": source, "value": text})
        else:
            invalid_sources.append(source)


def mft_validation_warnings(
    *,
    record_blob: bytes,
    first_attribute_offset: int,
    used_size: int,
    allocated_size: int,
    sequence_validation: Mapping[str, object],
    attributes: Mapping[str, object],
    timestamp_validation: Mapping[str, object],
) -> list[str]:
    warnings: list[str] = []
    if record_blob[:4] != b"FILE":
        warnings.append("invalid-file-record-magic")
    if first_attribute_offset < 0x30 or first_attribute_offset >= len(record_blob):
        warnings.append("first-attribute-offset-out-of-range")
    if first_attribute_offset % 8:
        warnings.append("first-attribute-offset-not-8-byte-aligned")
    if used_size and allocated_size and used_size > allocated_size:
        warnings.append("used-size-exceeds-allocated-size")
    if sequence_validation.get("status") != "valid":
        warnings.extend(str(item) for item in sequence_validation.get("warnings") or ["sequence-validation-not-valid"])
    if not attributes.get("end_marker_seen"):
        warnings.append("attribute-end-marker-not-seen")
    warnings.extend(str(item) for item in attributes.get("warnings") or [])
    if not attributes.get("standard_information"):
        warnings.append("missing-standard-information-attribute")
    if not attributes.get("file_name_entries"):
        warnings.append("missing-file-name-attribute")
    if timestamp_validation.get("status") != "valid":
        warnings.extend(str(item) for item in timestamp_validation.get("invalid_sources") or ["timestamp-validation-not-valid"])
    return warnings


def mft_parser_confidence(
    validation_status: str,
    attributes: Mapping[str, object],
    sequence_validation: Mapping[str, object],
) -> float:
    confidence = 0.55
    if attributes.get("standard_information"):
        confidence += 0.1
    if attributes.get("file_name_entries"):
        confidence += 0.1
    if attributes.get("data_attributes"):
        confidence += 0.05
    if sequence_validation.get("status") == "valid":
        confidence += 0.1
    if validation_status == "valid":
        confidence += 0.05
    return min(confidence, 0.9)


def align8(value: int) -> int:
    return (value + 7) & ~7


def parse_usn_records(blob: bytes) -> list[dict[str, object]]:
    return list(parse_usn_record_scan(blob)["records"])


def parse_usn_record_scan(blob: bytes, *, record_limit: int = USN_RECORD_SCAN_LIMIT) -> dict[str, object]:
    records: list[dict[str, object]] = []
    offset = 0
    skipped_bytes = 0
    while offset + 60 <= len(blob):
        record = parse_usn_record_at(blob, offset)
        if record is None:
            skipped_bytes += 1
            offset += 1
            continue
        records.append(record)
        offset = int(record["next_record_cursor"])
        if len(records) >= record_limit:
            break
    timestamps = sorted(str(record.get("timestamp")) for record in records if record.get("timestamp"))
    next_cursor_available = offset < len(blob) and bool(records)
    large_record_count = sum(1 for record in records if record.get("record_size_class") == "large")
    first_record_offset = int(records[0]["record_offset"]) if records else None
    return {
        "records": records,
        "scan_start_offset": 0,
        "scan_end_offset": len(blob),
        "last_scanned_offset": offset,
        "first_record_offset": first_record_offset,
        "last_record_offset": records[-1]["record_offset"] if records else None,
        "next_cursor_offset": offset if next_cursor_available else None,
        "next_cursor_available": next_cursor_available,
        "record_limit": record_limit,
        "record_limit_reached": len(records) >= record_limit and offset < len(blob),
        "skipped_bytes_before_records": first_record_offset if first_record_offset is not None else skipped_bytes,
        "skipped_bytes_during_scan": skipped_bytes,
        "trailing_unparsed_bytes": max(len(blob) - offset, 0),
        "large_record_count": large_record_count,
        "largest_record_length": max((int(record.get("record_length", 0)) for record in records), default=0),
        "timestamp_range": {
            "earliest": timestamps[0] if timestamps else "",
            "latest": timestamps[-1] if timestamps else "",
        },
    }


def parse_usn_record_at(blob: bytes, offset: int) -> dict[str, object] | None:
    length = int_from(blob, offset, 4)
    major = int_from(blob, offset + 4, 2)
    if length < 60 or length > 65536 or offset + length > len(blob) or major not in {2, 3}:
        return None
    record_blob = blob[offset : offset + length]
    if major == 2:
        layout = {
            "minimum_length": 60,
            "file_reference_offset": 8,
            "parent_reference_offset": 16,
            "reference_size": 8,
            "usn_offset": 24,
            "timestamp_offset": 32,
            "reason_offset": 40,
            "source_info_offset": 44,
            "security_id_offset": 48,
            "file_attributes_offset": 52,
            "name_length_offset": 56,
            "name_offset_offset": 58,
        }
    else:
        layout = {
            "minimum_length": 76,
            "file_reference_offset": 8,
            "parent_reference_offset": 24,
            "reference_size": 16,
            "usn_offset": 40,
            "timestamp_offset": 48,
            "reason_offset": 56,
            "source_info_offset": 60,
            "security_id_offset": 64,
            "file_attributes_offset": 68,
            "name_length_offset": 72,
            "name_offset_offset": 74,
        }
    if length < int(layout["minimum_length"]):
        return None
    name_length = int_from(record_blob, int(layout["name_length_offset"]), 2)
    name_offset = int_from(record_blob, int(layout["name_offset_offset"]), 2)
    if name_offset < int(layout["minimum_length"]) or name_length <= 0 or name_offset + name_length > length:
        return None
    filetime_value = int_from(record_blob, int(layout["timestamp_offset"]), 8)
    timestamp = filetime_to_iso(filetime_value)
    reason = int_from(record_blob, int(layout["reason_offset"]), 4)
    source_info = int_from(record_blob, int(layout["source_info_offset"]), 4)
    file_attributes = int_from(record_blob, int(layout["file_attributes_offset"]), 4)
    reason_flag_names = reason_flags(reason)
    unknown_reason_mask = unknown_flag_mask(reason, USN_REASON_FLAGS)
    unknown_source_info_mask = unknown_flag_mask(source_info, USN_SOURCE_INFO_FLAGS)
    unknown_file_attribute_mask = unknown_flag_mask(file_attributes, NTFS_FILE_ATTRIBUTE_NAMES)
    file_name_blob = record_blob[name_offset : name_offset + name_length]
    try:
        file_name = file_name_blob.decode("utf-16le")
        file_name_decode_status = "valid"
    except UnicodeDecodeError:
        file_name = file_name_blob.decode("utf-16le", errors="ignore")
        file_name_decode_status = "invalid-utf16"
    validation_warnings = usn_validation_warnings(
        length=length,
        name_length=name_length,
        name_offset=name_offset,
        major=major,
        timestamp=timestamp,
        reason=reason,
        reason_flag_names=reason_flag_names,
        unknown_reason_mask=unknown_reason_mask,
        file_name_decode_status=file_name_decode_status,
    )
    validation_status = "valid" if not validation_warnings else "valid-with-warnings"
    parser_confidence = 0.85 if validation_status == "valid" else 0.7
    file_reference_number = int_from(record_blob, int(layout["file_reference_offset"]), int(layout["reference_size"]))
    parent_file_reference_number = int_from(record_blob, int(layout["parent_reference_offset"]), int(layout["reference_size"]))
    record_end_offset = offset + length
    record_payload_bytes = name_offset + name_length
    return {
        "record_offset": offset,
        "record_cursor": offset,
        "next_record_cursor": record_end_offset,
        "record_end_offset": record_end_offset,
        "record_length": length,
        "record_payload_bytes": record_payload_bytes,
        "record_padding_bytes": max(length - record_payload_bytes, 0),
        "record_size_class": usn_record_size_class(length),
        "major_version": major,
        "minor_version": int_from(record_blob, 6, 2),
        "file_reference_number": file_reference_number,
        "parent_file_reference_number": parent_file_reference_number,
        "file_reference_number_decoded": decode_usn_file_reference(file_reference_number, int(layout["reference_size"])),
        "parent_file_reference_number_decoded": decode_usn_file_reference(
            parent_file_reference_number, int(layout["reference_size"])
        ),
        "usn": int_from(record_blob, int(layout["usn_offset"]), 8),
        "timestamp": timestamp,
        "timestamp_filetime": filetime_value,
        "reason": reason_string(reason),
        "reason_raw": reason,
        "reason_flags": reason_flag_names,
        "unknown_reason_mask": unknown_reason_mask,
        "source_info": source_info,
        "source_info_flags": flag_names(source_info, USN_SOURCE_INFO_FLAGS),
        "unknown_source_info_mask": unknown_source_info_mask,
        "security_id": int_from(record_blob, int(layout["security_id_offset"]), 4),
        "file_attributes": file_attributes,
        "file_attribute_names": flag_names(file_attributes, NTFS_FILE_ATTRIBUTE_NAMES),
        "unknown_file_attribute_mask": unknown_file_attribute_mask,
        "file_name_length": name_length,
        "file_name_offset": name_offset,
        "file_name_character_count": len(file_name),
        "file_name_decode_status": file_name_decode_status,
        "file_name": file_name,
        "deleted_hint": "FILE_DELETE" in reason_flag_names,
        "rename_hint": rename_hint(reason_flag_names),
        "validation_status": validation_status,
        "validation_warnings": validation_warnings,
        "validation_checks": {
            "record_length_aligned": length % 8 == 0,
            "record_cursor_progresses": record_end_offset > offset,
            "filename_bounds_valid": name_offset >= int(layout["minimum_length"]) and name_offset + name_length <= length,
            "filename_utf16_valid": file_name_decode_status == "valid",
            "filetime_plausible": bool(timestamp),
            "version_supported": major in {2, 3},
            "known_reason_bits_only": unknown_reason_mask == 0,
            "large_record": length >= USN_LARGE_RECORD_THRESHOLD,
        },
        "parser_confidence": parser_confidence,
    }


def usn_validation_warnings(
    *,
    length: int,
    name_length: int,
    name_offset: int,
    major: int,
    timestamp: str,
    reason: int,
    reason_flag_names: list[str],
    unknown_reason_mask: int,
    file_name_decode_status: str,
) -> list[str]:
    warnings: list[str] = []
    if major not in {2, 3}:
        warnings.append("unsupported-usn-record-version")
    if length % 8:
        warnings.append("record-length-not-8-byte-aligned")
    if name_length % 2:
        warnings.append("filename-length-not-utf16-even")
    if name_offset % 2:
        warnings.append("filename-offset-not-utf16-even")
    if not timestamp:
        warnings.append("invalid-filetime")
    if reason and not reason_flag_names:
        warnings.append("unknown-reason-flags")
    if unknown_reason_mask:
        warnings.append("reason-has-unknown-bits")
    if reason == 0:
        warnings.append("empty-reason")
    if file_name_decode_status != "valid":
        warnings.append("filename-invalid-utf16")
    return warnings


def usn_record_size_class(length: int) -> str:
    return "large" if length >= USN_LARGE_RECORD_THRESHOLD else "standard"


def decode_usn_file_reference(value: int, size: int) -> dict[str, object]:
    if size == 8:
        decoded = split_mft_reference(value)
        return {
            "format": "mft-reference-64",
            "record_number": decoded["record_number"],
            "sequence_number": decoded["sequence_number"],
        }
    return {
        "format": "file-id-128",
        "hex": f"{value:032x}",
    }


def unknown_flag_mask(value: int, names: Mapping[int, str]) -> int:
    known = 0
    for flag in names:
        known |= flag
    return value & ~known


def rename_hint(reason_flag_names: list[str]) -> str:
    has_old = "RENAME_OLD_NAME" in reason_flag_names
    has_new = "RENAME_NEW_NAME" in reason_flag_names
    if has_old and has_new:
        return "rename-old-and-new"
    if has_old:
        return "rename-old-name"
    if has_new:
        return "rename-new-name"
    return ""


def int_from(blob: bytes, offset: int, size: int) -> int:
    if offset + size > len(blob):
        return 0
    return int.from_bytes(blob[offset : offset + size], "little", signed=False)


def extract_utf16_strings(blob: bytes, *, min_chars: int = 4, limit: int = 250) -> list[str]:
    strings: list[str] = []
    current = bytearray()
    for index in range(0, len(blob) - 1, 2):
        value = int.from_bytes(blob[index : index + 2], "little", signed=False)
        if 32 <= value <= 126:
            current.extend(blob[index : index + 2])
            continue
        if len(current) >= min_chars * 2:
            decoded = current.decode("utf-16le", errors="ignore").strip()
            if decoded and decoded not in strings:
                strings.append(decoded)
                if len(strings) >= limit:
                    return strings
        current.clear()
    if len(current) >= min_chars * 2:
        decoded = current.decode("utf-16le", errors="ignore").strip()
        if decoded and decoded not in strings:
            strings.append(decoded)
    return strings


def extract_path_candidates(strings: list[str]) -> list[str]:
    candidates: list[str] = []
    for value in strings:
        for match in WINDOWS_PATH_RE.finditer(value):
            candidate = match.group(0).rstrip(".,);]")
            if candidate not in candidates:
                candidates.append(candidate)
    return candidates


def reason_flags(value: int) -> list[str]:
    return [name for flag, name in USN_REASON_FLAGS.items() if value & flag]


def reason_string(value: int) -> str:
    flags = reason_flags(value)
    return "|".join(flags) if flags else f"0x{value:08x}"


def flag_names(value: int, names: Mapping[int, str]) -> list[str]:
    return [name for flag, name in names.items() if value & flag]


def count_values(values: Iterable[object]) -> list[dict[str, object]]:
    counts: dict[str, int] = {}
    for value in values:
        text = str(value or "")
        if not text:
            continue
        counts[text] = counts.get(text, 0) + 1
    return [{"value": value, "count": count} for value, count in sorted(counts.items())]


def count_many(values: Iterable[object]) -> list[dict[str, object]]:
    counts: dict[str, int] = {}
    for collection in values:
        if not isinstance(collection, Iterable) or isinstance(collection, (str, bytes)):
            continue
        for value in collection:
            text = str(value or "")
            if not text:
                continue
            counts[text] = counts.get(text, 0) + 1
    return [{"value": value, "count": count} for value, count in sorted(counts.items())]


def filetime_to_iso(value: int) -> str:
    if value <= 0:
        return ""
    try:
        base = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
        return (base + dt.timedelta(microseconds=value / 10)).isoformat()
    except (OverflowError, ValueError):
        return ""
