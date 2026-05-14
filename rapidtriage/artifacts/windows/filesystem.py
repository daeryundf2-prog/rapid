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

PARSER_VERSION = "windows-filesystem-v7"
SUPPORTED_SUFFIXES = {".csv", ".json", ".jsonl", ".ndjson"}
MFT_HINTS = ("mft", "mftexcmd", "$mft")
USN_HINTS = ("usn", "usnjrnl", "$j")
NATIVE_SCAN_LIMIT = 16 * 1024 * 1024
NTFS_LOGFILE_SCAN_LIMIT = 8 * 1024 * 1024
NTFS_LOGFILE_SIGNATURES = {
    "restart_page": b"RSTR",
    "log_record_page": b"RCRD",
    "checkpoint_page": b"CHKD",
}
SIGNATURE_SCAN_LIMIT = 4096
SIGNATURE_SCAN_FILE_LIMIT = 5000
USN_RECORD_SCAN_LIMIT = 5000
USN_LARGE_RECORD_THRESHOLD = 512
USN_V4_EXTENT_PREVIEW_LIMIT = 64
MFT_RUNLIST_PREVIEW_BYTE_LIMIT = 256
MFT_RUNLIST_PREVIEW_RUN_LIMIT = 64
WINDOWS_PATH_RE = re.compile(r"(?i)(?:[a-z]:\\|\\\\|\\device\\)[^\x00\r\n\t\"'<>|]{4,260}")
FILE_SIGNATURES: tuple[dict[str, object], ...] = (
    {"kind": "windows-pe", "signature": b"MZ", "expected_extensions": {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx"}},
    {"kind": "pdf", "signature": b"%PDF", "expected_extensions": {".pdf"}},
    {"kind": "png", "signature": b"\x89PNG\r\n\x1a\n", "expected_extensions": {".png"}},
    {"kind": "jpeg", "signature": b"\xff\xd8\xff", "expected_extensions": {".jpg", ".jpeg", ".jpe"}},
    {"kind": "gif", "signature": (b"GIF87a", b"GIF89a"), "expected_extensions": {".gif"}},
    {"kind": "zip-ooxml", "signature": b"PK\x03\x04", "expected_extensions": {".zip", ".docx", ".xlsx", ".pptx", ".jar", ".odt", ".ods", ".odp"}},
    {"kind": "ole-cfb", "signature": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "expected_extensions": {".doc", ".xls", ".ppt", ".msg", ".msi"}},
    {"kind": "rar", "signature": (b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00"), "expected_extensions": {".rar"}},
    {"kind": "7zip", "signature": b"7z\xbc\xaf\x27\x1c", "expected_extensions": {".7z"}},
    {"kind": "sqlite", "signature": b"SQLite format 3\x00", "expected_extensions": {".sqlite", ".sqlite3", ".db"}},
)
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
    "mft_bounded_parent_path_cache": True,
    "mft_resident_data_hash": True,
    "mft_nonresident_runlist_preview": True,
    "usn_export_import": True,
    "usn_native_v2_v3_record_decode": True,
    "usn_native_v4_extent_record_decode": True,
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
    "mft-trusted-record-diff-required",
]
USN_REPORT_GRADE_BLOCKERS = [
    "bounded-native-usn-scan-not-full-journal-validated",
    "full-usn-replay-correlation-not-implemented",
    "large-corpus-pagination-validation-required",
    "usn-trusted-timeline-diff-required",
]
MFT_TRUSTED_TOOLS = {"mftecmd", "tsk", "sleuthkit", "fls", "istat", "velociraptor"}
USN_TRUSTED_TOOLS = {"mftecmd", "usnjrnl2csv", "usnparser", "velociraptor", "tsk", "sleuthkit"}
QC_PREP_NTFS_ITEM_NUMBERS = {
    "mft": 27,
    "usn": 28,
}
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
        yield from collect_ntfs_logfile_artifacts(root)
        yield from collect_recycle_bin_artifacts(root)
        yield from collect_signature_mismatch_artifacts(root)
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


def collect_recycle_bin_artifacts(root: Path) -> Iterable[ArtifactRecord]:
    recycle_roots = [path for path in root.rglob("$Recycle.Bin") if path.is_dir()]
    for recycle_root in sorted(recycle_roots, key=lambda item: str(item).lower()):
        for metadata_path in sorted(recycle_root.rglob("$I*"), key=lambda item: str(item).lower()):
            if not metadata_path.is_file():
                continue
            parsed = parse_recycle_bin_i_file(metadata_path)
            suffix = metadata_path.name[2:]
            payload_candidates = [
                metadata_path.with_name(f"$R{suffix}"),
                metadata_path.with_name(f"$R{suffix}{metadata_path.suffix}"),
            ]
            paired_payload = next((candidate for candidate in payload_candidates if candidate.is_file()), None)
            stat_result = metadata_path.stat()
            yield ArtifactRecord(
                provider=WindowsFilesystemProvider.name,
                artifact_type="recycle-bin-entry",
                path=str(metadata_path.resolve()),
                supported=True,
                details={
                    "parser": "windows-recycle-bin",
                    "parser_version": PARSER_VERSION,
                    "coverage_status": "i-r-pair-mapped" if paired_payload else "i-file-only",
                    "reportability": "triage",
                    "source_path": str(metadata_path.resolve()),
                    "source_format": "recycle-bin-i-file",
                    "source_hashes": file_hashes(metadata_path),
                    "source_size": stat_result.st_size,
                    "modified_at": dt.datetime.fromtimestamp(stat_result.st_mtime, dt.timezone.utc).isoformat(),
                    "recycle_id": suffix,
                    "sid_hint": metadata_path.parent.name,
                    "original_path": parsed.get("original_path", ""),
                    "deleted_at": parsed.get("deleted_at", ""),
                    "deleted_file_size": parsed.get("deleted_file_size", 0),
                    "format_version": parsed.get("format_version", 0),
                    "paired_payload_path": str(paired_payload.resolve()) if paired_payload else "",
                    "paired_payload_hashes": file_hashes(paired_payload) if paired_payload else {},
                    "validation_required": True,
                    "validation_guidance": "Recycle Bin $I metadata is mapped to the sibling $R payload when present; validate high-value deletion timelines with MFT/USN and shell activity.",
                    "risk_flags": ["deleted-file-recycle-bin"],
                    "commercial_grade_ready": False,
                    "commercial_grade_blockers": [
                        "recycle-bin-known-answer-fixture-required",
                        "mft-usn-delete-correlation-required",
                    ],
                },
            )


def parse_recycle_bin_i_file(path: Path) -> dict[str, object]:
    blob = read_prefix(path, 4096)
    if len(blob) < 24:
        return {"format_version": 0, "deleted_file_size": 0, "deleted_at": "", "original_path": ""}
    version = int.from_bytes(blob[0:8], "little", signed=False)
    deleted_file_size = int.from_bytes(blob[8:16], "little", signed=False)
    deleted_at = filetime_to_iso(int.from_bytes(blob[16:24], "little", signed=False))
    original_path = decode_recycle_original_path(blob)
    return {
        "format_version": version,
        "deleted_file_size": deleted_file_size,
        "deleted_at": deleted_at,
        "original_path": original_path,
    }


def decode_recycle_original_path(blob: bytes) -> str:
    candidates = []
    if len(blob) >= 28:
        name_len = int.from_bytes(blob[24:28], "little", signed=False)
        if 0 < name_len < 2048 and 28 + name_len * 2 <= len(blob):
            candidates.append(blob[28 : 28 + name_len * 2])
    candidates.append(blob[24:])
    for candidate in candidates:
        text = candidate.decode("utf-16le", errors="ignore").split("\x00", 1)[0].strip()
        if text:
            return text
    return ""


def collect_signature_mismatch_artifacts(root: Path) -> Iterable[ArtifactRecord]:
    scanned = 0
    for path in sorted((item for item in root.rglob("*") if item.is_file()), key=lambda item: str(item).lower()):
        if path.name.startswith("$I") or path.name.startswith("$R"):
            continue
        scanned += 1
        if scanned > SIGNATURE_SCAN_FILE_LIMIT:
            break
        detected = detect_file_signature(read_prefix(path, SIGNATURE_SCAN_LIMIT))
        if not detected:
            continue
        expected_extensions = set(detected["expected_extensions"])
        actual_extension = path.suffix.lower()
        if actual_extension in expected_extensions:
            continue
        stat_result = path.stat()
        yield ArtifactRecord(
            provider=WindowsFilesystemProvider.name,
            artifact_type="file-signature-mismatch",
            path=str(path.resolve()),
            supported=True,
            details={
                "parser": "windows-file-signature-mismatch",
                "parser_version": PARSER_VERSION,
                "coverage_status": "bounded-magic-header-check",
                "reportability": "triage",
                "source_path": str(path.resolve()),
                "source_format": "filesystem-file",
                "source_hashes": file_hashes(path),
                "source_size": stat_result.st_size,
                "modified_at": dt.datetime.fromtimestamp(stat_result.st_mtime, dt.timezone.utc).isoformat(),
                "actual_extension": actual_extension,
                "detected_signature_kind": detected["kind"],
                "signature_hex": detected["signature_hex"],
                "expected_extensions": sorted(expected_extensions),
                "risk_flags": ["signature-extension-mismatch"],
                "validation_required": True,
                "validation_guidance": "Magic-header mismatch is a triage lead. Validate with a full file-type parser and user/action timeline before reporting concealment intent.",
                "commercial_grade_ready": False,
                "commercial_grade_blockers": [
                    "full-file-type-parser-validation-required",
                    "false-positive-extension-policy-required",
                ],
            },
        )


def detect_file_signature(blob: bytes) -> dict[str, object] | None:
    for entry in FILE_SIGNATURES:
        signatures = entry["signature"]
        signature_list = signatures if isinstance(signatures, tuple) else (signatures,)
        for signature in signature_list:
            if blob.startswith(signature):
                return {
                    "kind": entry["kind"],
                    "signature_hex": signature.hex(),
                    "expected_extensions": entry["expected_extensions"],
                }
    return None


def collect_native_ntfs_artifacts(root: Path) -> Iterable[ArtifactRecord]:
    seen: set[Path] = set()
    candidate_paths = sorted((path for path in root.rglob("*") if path.is_file()), key=lambda item: str(item).lower())
    mft_records_by_path: dict[Path, list[dict[str, object]]] = {}
    mft_path_caches_by_volume: dict[Path, dict[int, dict[str, object]]] = {}
    for path in candidate_paths:
        if is_native_mft_path(path):
            resolved = path.resolve()
            mft_records = parse_mft_record_headers(read_prefix(path, NATIVE_SCAN_LIMIT))
            mft_records_by_path[resolved] = mft_records
            mft_path_caches_by_volume[resolved.parent] = build_mft_bounded_path_cache(mft_records)
    for path in candidate_paths:
        if not path.is_file():
            continue
        name = path.name.lower()
        resolved = path.resolve()
        if resolved in seen:
            continue
        if is_native_mft_path(path):
            yield build_mft_inventory_record(path)
            mft_records = mft_records_by_path.get(resolved) or parse_mft_record_headers(read_prefix(path, NATIVE_SCAN_LIMIT))
            bounded_path_cache = mft_path_caches_by_volume.get(resolved.parent) or build_mft_bounded_path_cache(mft_records)
            for index, record in enumerate(mft_records):
                yield build_native_mft_record(path, record, index, bounded_path_cache)
            seen.add(resolved)
        elif is_native_usn_path(path):
            bounded_path_cache = nearest_mft_path_cache(path, mft_path_caches_by_volume)
            yield build_usn_journal_inventory_record(path, bounded_path_cache)
            for index, record in enumerate(parse_usn_records(read_prefix(path, NATIVE_SCAN_LIMIT))):
                yield build_native_usn_record(path, record, index, bounded_path_cache)
            seen.add(resolved)


def collect_ntfs_logfile_artifacts(root: Path) -> Iterable[ArtifactRecord]:
    for path in sorted((item for item in root.rglob("*") if item.is_file()), key=lambda item: str(item).lower()):
        if not is_native_logfile_path(path):
            continue
        yield build_ntfs_logfile_inventory_record(path)


def is_native_mft_path(path: Path) -> bool:
    return path.name.lower() == "$mft"


def is_native_usn_path(path: Path) -> bool:
    name = path.name.lower()
    parent_blob = str(path.parent).lower()
    return name in {"$j", "$usnjrnl"} or (name.endswith(".usn") and "usn" in parent_blob)


def is_native_logfile_path(path: Path) -> bool:
    return path.name.lower() == "$logfile"


def build_ntfs_logfile_inventory_record(path: Path) -> ArtifactRecord:
    stat_result = path.stat()
    blob = read_prefix(path, NTFS_LOGFILE_SCAN_LIMIT)
    signature_scan = ntfs_logfile_signature_scan(blob)
    strings = extract_mixed_strings(blob)
    path_candidates = extract_path_candidates(strings)
    has_log_signatures = bool(signature_scan["signature_counts"])
    validation_checks = {
        "source_file_readable": bool(blob),
        "has_logfile_name": is_native_logfile_path(path),
        "has_ntfs_log_signatures": has_log_signatures,
        "bounded_scan_completed": len(blob) <= NTFS_LOGFILE_SCAN_LIMIT,
        "transaction_redo_undo_decoded": False,
        "trusted_logfile_parser_diff_available": False,
    }
    return ArtifactRecord(
        provider=WindowsFilesystemProvider.name,
        artifact_type="ntfs-logfile-transaction-candidate",
        path=str(path.resolve()),
        supported=True,
        details={
            "parser": "windows-ntfs-logfile-bounded-inventory",
            "parser_version": PARSER_VERSION,
            "coverage_status": "ntfs-logfile-signature-and-string-pivot",
            "reportability": "triage",
            "source_path": str(path.resolve()),
            "source_format": "ntfs-logfile",
            "source_hashes": file_hashes(path),
            "size": stat_result.st_size,
            "modified_at": dt.datetime.fromtimestamp(stat_result.st_mtime, dt.timezone.utc).isoformat(),
            "timestamp": dt.datetime.fromtimestamp(stat_result.st_mtime, dt.timezone.utc).isoformat(),
            "timestamp_source": "ntfs_logfile_modified_at",
            "scan_bytes": len(blob),
            "signature_counts": signature_scan["signature_counts"],
            "signature_offsets": signature_scan["signature_offsets"],
            "path_candidates": path_candidates[:50],
            "string_samples": strings[:50],
            "risk_flags": ["ntfs-logfile-present"] + (["ntfs-logfile-signatures-present"] if has_log_signatures else []),
            "validation_required": True,
            "validation_checks": validation_checks,
            "validation_guidance": (
                "$LogFile is currently exposed as a bounded transaction candidate. Validate create/rename/delete "
                "claims with a full redo/undo decoder and correlate with $MFT/$UsnJrnl before report-grade use."
            ),
            "commercial_grade_ready": False,
            "commercial_grade_blockers": [
                "ntfs-logfile-redo-undo-decoder-not-implemented",
                "mft-usn-logfile-timeline-correlation-required",
                "trusted-logfile-parser-diff-required",
            ],
            "recommended_parsers": ["LogFileParser", "MFTECmd", "The Sleuth Kit"],
        },
    )


def ntfs_logfile_signature_scan(blob: bytes) -> dict[str, object]:
    signature_offsets: dict[str, list[int]] = {}
    for label, signature in NTFS_LOGFILE_SIGNATURES.items():
        offsets: list[int] = []
        cursor = 0
        while len(offsets) < 50:
            found = blob.find(signature, cursor)
            if found < 0:
                break
            offsets.append(found)
            cursor = found + 1
        if offsets:
            signature_offsets[label] = offsets
    return {
        "signature_counts": [{"value": key, "count": len(value)} for key, value in sorted(signature_offsets.items())],
        "signature_offsets": signature_offsets,
    }


def nearest_mft_path_cache(
    path: Path,
    caches_by_volume: Mapping[Path, Mapping[int, Mapping[str, object]]],
) -> Mapping[int, Mapping[str, object]]:
    resolved = path.resolve()
    best_root: Path | None = None
    best_cache: Mapping[int, Mapping[str, object]] = {}
    for volume_root, cache in caches_by_volume.items():
        try:
            resolved.relative_to(volume_root)
        except ValueError:
            continue
        if best_root is None or len(str(volume_root)) > len(str(best_root)):
            best_root = volume_root
            best_cache = cache
    return best_cache


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
            "mft_full_parser_profile": mft_full_parser_profile(
                artifact_scope="inventory",
                details={
                    "source_path": str(path.resolve()),
                    "source_hashes": file_hashes(path),
                    "native_record_count": len(mft_records),
                    "scan_bytes": len(blob),
                    "record_validation_counts": count_values(record.get("validation_status") for record in mft_records),
                    "native_attribute_type_counts": count_many(record.get("attribute_types") for record in mft_records),
                    "path_candidates": path_candidates[:50],
                    "validation_checks": validation_checks,
                    "ntfs_report_grade_assessment": report_grade,
                },
            ),
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


def build_usn_journal_inventory_record(
    path: Path,
    mft_path_cache: Mapping[int, Mapping[str, object]] | None = None,
) -> ArtifactRecord:
    stat_result = path.stat()
    blob = read_prefix(path, NATIVE_SCAN_LIMIT)
    scan = parse_usn_record_scan(blob)
    records = list(scan["records"])
    scan_metadata = {key: value for key, value in scan.items() if key != "records"}
    replay_inventory = usn_replay_inventory_profile(records, scan_metadata, mft_path_cache or {})
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
            "usn_replay_inventory_profile": replay_inventory,
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
            "usn_journal_replay_profile": usn_journal_replay_profile(
                artifact_scope="inventory",
                details={
                    "source_path": str(path.resolve()),
                    "source_hashes": file_hashes(path),
                    "scan_metadata": scan_metadata,
                    "native_record_count": len(records),
                    "reason_flag_counts": count_many(record.get("reason_flags") for record in records),
                    "usn_replay_inventory_profile": replay_inventory,
                    "timestamp_range": scan_metadata["timestamp_range"],
                    "record_limit_reached": scan_metadata["record_limit_reached"],
                    "next_cursor_available": scan_metadata["next_cursor_available"],
                    "validation_checks": validation_checks,
                    "ntfs_report_grade_assessment": report_grade,
                },
            ),
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
            "note": "Native USN records are decoded when bounded v2/v3 filename records or v4 extent records are recoverable; validation counts summarize structural, cursor, size, and timestamp confidence where the format provides it. Validate critical timelines with a dedicated parser.",
        },
    )


def build_native_mft_record(
    path: Path,
    record: Mapping[str, object],
    index: int,
    bounded_path_cache: Mapping[int, Mapping[str, object]] | None = None,
) -> ArtifactRecord:
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
    record_number_int = int(record.get("record_number_candidate") or 0)
    bounded_parent_path = dict((bounded_path_cache or {}).get(record_number_int) or {})
    if not file_path and bounded_parent_path.get("path"):
        file_path = str(bounded_parent_path.get("path"))
    timestamp_stomping = mft_timestamp_stomping_analysis(standard_information, file_name_entries)
    risk_flags = list(timestamp_stomping.get("risk_flags") or [])
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
        "attribute_list_entries": list(record.get("attribute_list_entries") or [])[:25],
        "standard_information": dict(standard_information),
        "file_name_entries": file_name_entries[:10],
        "data_attributes": list(record.get("data_attributes") or [])[:10],
        "timestamp_validation": dict(record.get("timestamp_validation") or {}),
        "timestamp_stomping_analysis": timestamp_stomping,
        "time_stomping_suspected": bool(timestamp_stomping.get("suspected")),
        "risk_flags": risk_flags,
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
                "attribute_list_entries": list(record.get("attribute_list_entries") or [])[:25],
                "data_attributes": list(record.get("data_attributes") or [])[:10],
                "file_name_entries": file_name_entries[:10],
                "validation_checks": dict(record.get("validation_checks") or {}),
            },
        ),
        "parser_confidence": record.get("parser_confidence", 0.0),
        "mft_record_evidence": mft_record_evidence(record, file_path),
        "mft_bounded_parent_path": bounded_parent_path,
        "mft_path_reconstruction_profile": mft_path_reconstruction_profile(record, file_path, bounded_parent_path),
        "mft_attribute_list_profile": mft_attribute_list_profile(record),
        "mft_data_run_summary": mft_data_run_summary(record),
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
    details["ntfs_report_citation_manifest"] = ntfs_report_citation_manifest("mft", details)
    details["ntfs_report_citation_manifest_hash"] = details["ntfs_report_citation_manifest"]["manifest_sha256"]
    details["source_viewer_locator"] = ntfs_record_source_viewer_locator("mft", details)
    details["ntfs_record_locator_profile"] = details["source_viewer_locator"]
    details["ntfs_native_capabilities"] = NTFS_FILESYSTEM_CAPABILITIES
    details["mft_full_parser_profile"] = mft_full_parser_profile("record", details)
    details["mft_parser_depth_manifest"] = mft_parser_depth_manifest(details)
    details["mft_parser_depth_manifest_hash"] = details["mft_parser_depth_manifest"]["manifest_sha256"]
    details["ntfs_native_depth_readiness_profile"] = ntfs_native_depth_readiness_profile("mft", "record", details)
    details["commercial_grade_blockers"] = details["ntfs_report_grade_assessment"]["blockers"]
    details["commercial_uplift_evidence"] = ntfs_commercial_uplift_evidence("mft", details)
    details["ntfs_analyst_review_profile"] = ntfs_analyst_review_profile("mft", "record", details)
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


def build_native_usn_record(
    path: Path,
    record: Mapping[str, object],
    index: int,
    mft_path_cache: Mapping[int, Mapping[str, object]] | None = None,
) -> ArtifactRecord:
    bounded_mft_path = usn_bounded_mft_path_correlation(record, mft_path_cache or {})
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
        "usn_bounded_mft_path": bounded_mft_path,
        "usn_replay_transition_profile": usn_replay_transition_profile(record, bounded_mft_path),
        "usn_cursor_pagination_profile": usn_cursor_pagination_profile(record),
        "evidence_strength": "ntfs-usn-native-record",
        "validation_required": True,
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "bounded-native-usn-scan-not-full-journal-validated",
            "full-usn-replay-correlation-not-implemented",
            "large-corpus-pagination-validation-required",
        ],
        "validation_guidance": "Native USN rows validate record layout, length, cursor bounds, name bounds/UTF-16 decoding for v2/v3, v4 extent bounds/counts where present, version, and FILETIME plausibility where the format provides it. Critical timelines should still be cross-checked with MFTECmd/UsnJrnl2Csv or another dedicated parser.",
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
    details["ntfs_report_citation_manifest"] = ntfs_report_citation_manifest("usn", details)
    details["ntfs_report_citation_manifest_hash"] = details["ntfs_report_citation_manifest"]["manifest_sha256"]
    details["source_viewer_locator"] = ntfs_record_source_viewer_locator("usn", details)
    details["ntfs_record_locator_profile"] = details["source_viewer_locator"]
    details["ntfs_native_capabilities"] = NTFS_FILESYSTEM_CAPABILITIES
    details["usn_journal_replay_profile"] = usn_journal_replay_profile("record", details)
    details["usn_timeline_depth_manifest"] = usn_timeline_depth_manifest(details)
    details["usn_timeline_depth_manifest_hash"] = details["usn_timeline_depth_manifest"]["manifest_sha256"]
    details["ntfs_native_depth_readiness_profile"] = ntfs_native_depth_readiness_profile("usn", "record", details)
    details["commercial_grade_blockers"] = details["ntfs_report_grade_assessment"]["blockers"]
    details["commercial_uplift_evidence"] = ntfs_commercial_uplift_evidence("usn", details)
    details["ntfs_analyst_review_profile"] = ntfs_analyst_review_profile("usn", "record", details)
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
    attribute_list_entries = list(record.get("attribute_list_entries") or [])
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
    nonresident_runlist_evidence = [
        {
            "runlist_decode_status": str(item.get("runlist_decode_status") or ""),
            "runlist_warning_count": int(item.get("runlist_warning_count") or 0),
            "run_count": len(list(item.get("runlist_preview") or [])),
            "runs": list(item.get("runlist_preview") or [])[:10],
            "preview_bytes": int(item.get("runlist_preview_bytes") or 0),
            "consumed_bytes": int(item.get("runlist_consumed_bytes") or 0),
            "terminator_offset": item.get("runlist_terminator_offset"),
        }
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
            "attribute_list_entry_count": len(attribute_list_entries),
            "attribute_list_evidence": attribute_list_entries[:10],
            "data_attribute_count": len(data_attributes),
            "resident_data_hashes": resident_hashes,
            "nonresident_runlist_preview_count": sum(1 for item in nonresident_previews if item),
            "nonresident_runlist_evidence": nonresident_runlist_evidence,
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


def build_mft_bounded_path_cache(records: Sequence[Mapping[str, object]]) -> dict[int, dict[str, object]]:
    nodes: dict[int, dict[str, object]] = {}
    for record in records:
        record_number = int(record.get("record_number_candidate") or 0)
        if record_number < 0:
            continue
        file_name_entry = mft_preferred_file_name_entry(record)
        parent_reference = (
            file_name_entry.get("parent_reference")
            if isinstance(file_name_entry.get("parent_reference"), Mapping)
            else {}
        )
        name = str(file_name_entry.get("file_name") or "")
        if not name:
            path_candidates = [str(item) for item in record.get("path_candidates") or [] if item]
            name = path_candidates[0].rsplit("\\", 1)[-1].rsplit("/", 1)[-1] if path_candidates else ""
        nodes[record_number] = {
            "record_number": record_number,
            "sequence_number": int(record.get("sequence_number") or 0),
            "name": name,
            "parent_record_number": parent_reference.get("record_number", ""),
            "parent_sequence_number": parent_reference.get("sequence_number", ""),
            "namespace": str(file_name_entry.get("namespace") or ""),
            "directory": bool(record.get("directory")),
            "in_use": bool(record.get("in_use")),
        }

    cache: dict[int, dict[str, object]] = {}
    for record_number in sorted(nodes):
        cache[record_number] = resolve_mft_bounded_path(record_number, nodes)
    return cache


def mft_bounded_path_cache_profile(
    mft_path_cache: Mapping[int, Mapping[str, object]],
) -> dict[str, object]:
    entries = [entry for entry in mft_path_cache.values() if isinstance(entry, Mapping)]
    complete_entries = [entry for entry in entries if bool(entry.get("complete_within_bounded_scan"))]
    partial_entries = [entry for entry in entries if not bool(entry.get("complete_within_bounded_scan"))]
    warning_count = sum(len(entry.get("warnings") or []) for entry in entries)
    max_depth = max((int(entry.get("depth") or 0) for entry in entries), default=0)
    return {
        "profile_version": "mft-bounded-path-cache-profile-v1",
        "cache_entry_count": len(entries),
        "complete_path_count": len(complete_entries),
        "partial_path_count": len(partial_entries),
        "complete_path_ratio": round(len(complete_entries) / len(entries), 6) if entries else 0,
        "status_counts": count_values(str(entry.get("status") or "unknown") for entry in entries),
        "warning_count": warning_count,
        "max_chain_depth": max_depth,
        "sample_complete_paths": [
            str(entry.get("path") or "")
            for entry in complete_entries[:10]
            if entry.get("path")
        ],
        "sample_partial_paths": [
            {
                "record_number": entry.get("record_number", ""),
                "path": str(entry.get("path") or ""),
                "status": str(entry.get("status") or ""),
                "warnings": list(entry.get("warnings") or [])[:3],
            }
            for entry in partial_entries[:10]
        ],
        "commercial_grade_ready": False,
        "reportability": "bounded-mft-path-cache-quality-profile",
        "blockers": [
            "mft-full-volume-parent-cache-required",
            "mft-hardlink-namespace-selection-validation-required",
            "mft-trusted-path-diff-required",
        ],
    }


def mft_preferred_file_name_entry(record: Mapping[str, object]) -> dict[str, object]:
    entries = [item for item in record.get("file_name_entries") or [] if isinstance(item, Mapping)]
    if not entries:
        return {}
    namespace_rank = {"WIN32": 0, "WIN32_AND_DOS": 1, "POSIX": 2, "DOS": 3}
    return dict(
        sorted(
            entries,
            key=lambda item: (
                namespace_rank.get(str(item.get("namespace") or ""), 9),
                len(str(item.get("file_name") or "")),
            ),
        )[0]
    )


def resolve_mft_bounded_path(record_number: int, nodes: Mapping[int, Mapping[str, object]]) -> dict[str, object]:
    chain: list[Mapping[str, object]] = []
    visited: set[int] = set()
    current = record_number
    status = "reconstructed-bounded-parent-cache"
    warnings: list[str] = []
    max_depth = 128
    while len(chain) < max_depth:
        if current in visited:
            status = "partial-cycle-detected"
            warnings.append(f"cycle-at-record:{current}")
            break
        node = nodes.get(current)
        if not node:
            status = "partial-parent-outside-bounded-scan"
            warnings.append(f"missing-record:{current}")
            break
        visited.add(current)
        chain.append(node)
        parent_value = node.get("parent_record_number")
        parent_number = int(parent_value) if isinstance(parent_value, int) or str(parent_value).isdigit() else -1
        if parent_number < 0:
            status = "partial-parent-reference-missing"
            break
        if parent_number == current:
            break
        parent_node = nodes.get(parent_number)
        if not parent_node:
            status = "partial-parent-outside-bounded-scan"
            warnings.append(f"parent-not-in-cache:{parent_number}")
            break
        expected_sequence = node.get("parent_sequence_number")
        actual_sequence = parent_node.get("sequence_number")
        if expected_sequence not in ("", None) and int(expected_sequence or 0) != int(actual_sequence or 0):
            status = "partial-parent-sequence-mismatch"
            warnings.append(f"parent-sequence-mismatch:{parent_number}")
            break
        current = parent_number
    else:
        status = "partial-depth-limit-reached"
        warnings.append(f"depth-limit:{max_depth}")

    ordered = list(reversed(chain))
    parts = [str(item.get("name") or "") for item in ordered if str(item.get("name") or "") not in {"", "."}]
    path = "\\" + "\\".join(parts) if parts else str(chain[0].get("name") or "") if chain else ""
    return {
        "profile_version": "mft-bounded-parent-path-v1",
        "status": status,
        "path": path,
        "record_number": record_number,
        "depth": len(chain),
        "complete_within_bounded_scan": status == "reconstructed-bounded-parent-cache",
        "chain": [
            {
                "record_number": item.get("record_number", ""),
                "sequence_number": item.get("sequence_number", ""),
                "name": item.get("name", ""),
                "namespace": item.get("namespace", ""),
                "parent_record_number": item.get("parent_record_number", ""),
                "parent_sequence_number": item.get("parent_sequence_number", ""),
            }
            for item in chain
        ],
        "warnings": warnings,
        "reportability": "bounded-scan-path-candidate",
        "commercial_grade_ready": False,
        "blockers": [
            "mft-full-volume-parent-cache-required",
            "mft-hardlink-namespace-selection-validation-required",
            "mft-trusted-path-diff-required",
        ],
    }


def mft_path_reconstruction_profile(
    record: Mapping[str, object],
    file_path: str,
    bounded_parent_path: Mapping[str, object] | None = None,
) -> dict[str, object]:
    file_name_entries = [item for item in record.get("file_name_entries") or [] if isinstance(item, Mapping)]
    primary = file_name_entries[0] if file_name_entries else {}
    parent_reference = primary.get("parent_reference") if isinstance(primary.get("parent_reference"), Mapping) else {}
    path_candidates = [str(item) for item in record.get("path_candidates") or [] if item]
    best_name = str(primary.get("file_name") or file_path or "")
    bounded_path = bounded_parent_path if isinstance(bounded_parent_path, Mapping) else {}
    has_full_path_string = any(("\\" in item or "/" in item) and best_name and best_name.lower() in item.lower() for item in path_candidates)
    confidence = (
        "bounded-scan-parent-cache"
        if bounded_path.get("complete_within_bounded_scan")
        else "full-path-string-candidate"
        if has_full_path_string
        else "filename-plus-parent-reference-only"
    )
    return {
        "profile_version": "mft-path-reconstruction-v1",
        "record_number": record.get("record_number_candidate", ""),
        "sequence_number": record.get("sequence_number", 0),
        "best_available_path": str(bounded_path.get("path") or file_path or best_name),
        "best_file_name": best_name,
        "path_candidates": path_candidates[:10],
        "file_name_entry_count": len(file_name_entries),
        "parent_reference_decoded": dict(parent_reference),
        "parent_record_number": parent_reference.get("record_number", ""),
        "parent_sequence_number": parent_reference.get("sequence_number", ""),
        "source_mode": confidence,
        "full_volume_path_cache_used": False,
        "bounded_parent_cache_used": bool(bounded_path),
        "bounded_parent_path": dict(bounded_path),
        "commercial_grade_ready": False,
        "blockers": [
            "mft-full-volume-parent-cache-required",
            "mft-hardlink-and-namespace-selection-validation-required",
            "mft-trusted-path-diff-required",
        ],
        "safe_report_wording": (
            "Path candidate reconstructed from records available within the bounded native $MFT scan; validate against a full-volume path cache before report-grade use."
            if bounded_path.get("complete_within_bounded_scan")
            else
            "Full path candidate recovered from record-local strings; validate with full-volume MFT path cache."
            if has_full_path_string
            else "Filename and parent FRN decoded from $FILE_NAME; full path not reconstructed from a volume-wide cache."
        ),
    }


def mft_attribute_list_profile(record: Mapping[str, object]) -> dict[str, object]:
    attribute_types = list(record.get("attribute_types") or [])
    entries = [item for item in record.get("attribute_list_entries") or [] if isinstance(item, Mapping)]
    present = "$ATTRIBUTE_LIST" in attribute_types or bool(entries)
    return {
        "profile_version": "mft-attribute-list-v1",
        "present": present,
        "entry_count": len(entries),
        "entries": entries[:25],
        "resolved": False,
        "resolution_status": (
            "extension-record-resolution-not-implemented"
            if present
            else "not-present-in-record"
        ),
        "extension_record_references": [
            dict(item.get("extension_reference_decoded") or {})
            for item in entries
            if item.get("extension_reference_decoded")
        ][:25],
        "commercial_grade_ready": False,
        "blockers": ["mft-attribute-list-extension-record-resolution-required"] if present else [],
    }


def mft_data_run_summary(record: Mapping[str, object]) -> dict[str, object]:
    data_attributes = [item for item in record.get("data_attributes") or [] if isinstance(item, Mapping)]
    nonresident = [item for item in data_attributes if item.get("resident") is False]
    decoded_runs: list[Mapping[str, object]] = []
    warning_count = 0
    for item in nonresident:
        runs = [run for run in item.get("runlist_preview") or [] if isinstance(run, Mapping)]
        decoded_runs.extend(runs)
        warning_count += int(item.get("runlist_warning_count") or 0)
    first_lcn = next((run.get("absolute_lcn") for run in decoded_runs if run.get("absolute_lcn") is not None), None)
    return {
        "profile_version": "mft-data-run-summary-v1",
        "data_attribute_count": len(data_attributes),
        "nonresident_data_attribute_count": len(nonresident),
        "resident_data_attribute_count": len(data_attributes) - len(nonresident),
        "preview_run_count": len(decoded_runs),
        "sparse_preview_run_count": sum(1 for run in decoded_runs if bool(run.get("sparse"))),
        "preview_cluster_count": sum(int(run.get("cluster_count") or 0) for run in decoded_runs),
        "first_preview_lcn": first_lcn,
        "decode_statuses": count_values(str(item.get("runlist_decode_status") or "") for item in nonresident),
        "warning_count": warning_count,
        "preview_limited": bool(nonresident),
        "commercial_grade_ready": False,
        "blockers": ["mft-full-nonresident-runlist-validation-required"] if nonresident else [],
    }


def mft_parser_depth_manifest(details: Mapping[str, object]) -> dict[str, object]:
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
    validation_checks = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    sequence_validation = (
        details.get("sequence_validation")
        if isinstance(details.get("sequence_validation"), Mapping)
        else {}
    )
    report_grade = (
        details.get("ntfs_report_grade_assessment")
        if isinstance(details.get("ntfs_report_grade_assessment"), Mapping)
        else {}
    )
    full_profile = (
        details.get("mft_full_parser_profile")
        if isinstance(details.get("mft_full_parser_profile"), Mapping)
        else {}
    )
    path_profile = (
        details.get("mft_path_reconstruction_profile")
        if isinstance(details.get("mft_path_reconstruction_profile"), Mapping)
        else {}
    )
    attribute_list_profile = (
        details.get("mft_attribute_list_profile")
        if isinstance(details.get("mft_attribute_list_profile"), Mapping)
        else {}
    )
    data_run_summary = (
        details.get("mft_data_run_summary")
        if isinstance(details.get("mft_data_run_summary"), Mapping)
        else {}
    )
    file_name_entries = [
        item for item in details.get("file_name_entries") or [] if isinstance(item, Mapping)
    ]
    data_attributes = [
        item for item in details.get("data_attributes") or [] if isinstance(item, Mapping)
    ]
    attribute_types = [str(item) for item in details.get("attribute_types") or []]
    nonresident_data = [item for item in data_attributes if item.get("resident") is False]
    resident_data = [item for item in data_attributes if item.get("resident") is not False]
    reportability = ntfs_reportability_decision("mft", report_grade, details)
    source = {
        "source_path": str(details.get("source_path") or ""),
        "source_sha256": str(hashes.get("sha256") or ""),
        "source_format": str(details.get("source_format") or ""),
        "source_index": details.get("source_index", ""),
        "record_offset": details.get("record_offset", ""),
    }
    record_identity = {
        "record_number": str(details.get("record_number") or ""),
        "sequence_number": details.get("sequence_number", ""),
        "in_use": bool(details.get("in_use")),
        "directory": bool(details.get("directory")),
        "file_path": str(details.get("file_path") or ""),
        "file_names": [str(item.get("file_name") or "") for item in file_name_entries if item.get("file_name")][:10],
        "parent_references": [
            dict(item.get("parent_reference") or {})
            for item in file_name_entries
            if isinstance(item.get("parent_reference"), Mapping)
        ][:10],
        "path_candidates": list(details.get("path_candidates") or [])[:10],
    }
    manifest_payload = {
        "manifest_version": "mft-parser-depth-manifest-v1",
        "parser_version": PARSER_VERSION,
        "commercial_batch_id": "commercial-uplift-011-015",
        "item_number": 12,
        "gap_id": "#12",
        "artifact_type": "mft-record",
        "source": source,
        "record_identity": record_identity,
        "record_identity_hash": ntfs_stable_sha256(record_identity),
        "usa_validation": {
            "magic_valid": bool(validation_checks.get("magic_valid")),
            "sequence_fixup_valid": bool(validation_checks.get("sequence_fixup_valid")),
            "sequence_validation_status": str(sequence_validation.get("status") or details.get("validation_status") or "unknown"),
            "update_sequence_offset": sequence_validation.get("update_sequence_offset", ""),
            "update_sequence_count": sequence_validation.get("update_sequence_count", ""),
            "repaired_sector_trailer_count": sequence_validation.get("repaired_sector_trailer_count", 0),
            "warnings": list(sequence_validation.get("warnings") or [])[:25],
        },
        "attribute_decoding": {
            "attribute_count": int(details.get("attribute_count") or 0),
            "attribute_types": attribute_types,
            "has_standard_information": "$STANDARD_INFORMATION" in attribute_types
            or bool(validation_checks.get("has_standard_information_attribute")),
            "has_file_name": "$FILE_NAME" in attribute_types
            or bool(validation_checks.get("has_file_name_attribute")),
            "has_data": "$DATA" in attribute_types
            or bool(validation_checks.get("has_data_attribute")),
            "has_attribute_list": bool(attribute_list_profile.get("present")),
            "attribute_list_entry_count": int(attribute_list_profile.get("entry_count") or 0),
            "attribute_list_resolution_available": bool(NTFS_FILESYSTEM_CAPABILITIES["mft_attribute_list_resolution"]),
            "attribute_list_resolution_status": str(attribute_list_profile.get("resolution_status") or ""),
            "attribute_list_blockers": list(attribute_list_profile.get("blockers") or []),
        },
        "data_run_decoding": {
            "data_attribute_count": int(data_run_summary.get("data_attribute_count") or len(data_attributes)),
            "resident_data_attribute_count": int(data_run_summary.get("resident_data_attribute_count") or len(resident_data)),
            "nonresident_data_attribute_count": int(data_run_summary.get("nonresident_data_attribute_count") or len(nonresident_data)),
            "runlist_preview_count": int(data_run_summary.get("preview_run_count") or 0),
            "sparse_preview_run_count": int(data_run_summary.get("sparse_preview_run_count") or 0),
            "preview_cluster_count": int(data_run_summary.get("preview_cluster_count") or 0),
            "decode_statuses": dict(data_run_summary.get("decode_statuses") or {}),
            "full_nonresident_runlist_decode_available": bool(NTFS_FILESYSTEM_CAPABILITIES["mft_full_nonresident_runlist_decode"]),
            "report_grade_blockers": list(data_run_summary.get("blockers") or []),
        },
        "path_reconstruction": {
            "best_available_path": str(path_profile.get("best_available_path") or details.get("file_path") or ""),
            "parent_record_number": path_profile.get("parent_record_number", ""),
            "parent_sequence_number": path_profile.get("parent_sequence_number", ""),
            "source_mode": str(path_profile.get("source_mode") or "unknown"),
            "bounded_parent_cache_used": bool(path_profile.get("bounded_parent_cache_used")),
            "full_volume_path_cache_used": bool(path_profile.get("full_volume_path_cache_used")),
            "full_volume_path_reconstruction_complete": bool(NTFS_FILESYSTEM_CAPABILITIES["full_volume_path_reconstruction"]),
            "safe_report_wording": str(path_profile.get("safe_report_wording") or ""),
            "blockers": list(path_profile.get("blockers") or []),
        },
        "decoded_components": dict(full_profile.get("decoded_components") or {}),
        "citation_refs": [
            {
                "kind": "mft-record-header",
                "record_number": str(details.get("record_number") or ""),
                "record_offset": details.get("record_offset", ""),
            },
            {
                "kind": "mft-usa-validation",
                "status": str(sequence_validation.get("status") or details.get("validation_status") or "unknown"),
            },
            {
                "kind": "mft-attribute-list",
                "present": bool(attribute_list_profile.get("present")),
                "resolution_status": str(attribute_list_profile.get("resolution_status") or ""),
            },
            {
                "kind": "mft-data-run-preview",
                "runlist_preview_count": int(data_run_summary.get("preview_run_count") or 0),
                "full_decode_available": bool(NTFS_FILESYSTEM_CAPABILITIES["mft_full_nonresident_runlist_decode"]),
            },
            {
                "kind": "mft-parent-path-reconstruction",
                "source_mode": str(path_profile.get("source_mode") or "unknown"),
                "full_volume_path_reconstruction_complete": bool(NTFS_FILESYSTEM_CAPABILITIES["full_volume_path_reconstruction"]),
            },
        ],
        "reportability": {
            "allowed_use": reportability["allowed_use"],
            "decision": reportability["decision"],
            "report_grade_ready": bool(report_grade.get("report_grade_ready")),
            "commercial_grade_ready": False,
            "full_path_complete": False,
            "file_content_complete": False,
            "blockers": reportability["blockers"],
        },
        "required_before_commercial_grade": [
            "resolve ATTRIBUTE_LIST extension records and merge base/extension attributes",
            "fully decode and validate nonresident runlists over physical cluster ranges",
            "reconstruct paths from a full-volume FRN cache with hardlink namespace handling",
            "diff record identity, timestamps, paths, and data-run facts against trusted tool output",
        ],
    }
    manifest_payload["manifest_sha256"] = ntfs_stable_sha256(manifest_payload)
    return manifest_payload


def usn_timeline_depth_manifest(details: Mapping[str, object]) -> dict[str, object]:
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
    validation_checks = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    report_grade = (
        details.get("ntfs_report_grade_assessment")
        if isinstance(details.get("ntfs_report_grade_assessment"), Mapping)
        else {}
    )
    replay_profile = (
        details.get("usn_journal_replay_profile")
        if isinstance(details.get("usn_journal_replay_profile"), Mapping)
        else {}
    )
    transition_profile = (
        details.get("usn_replay_transition_profile")
        if isinstance(details.get("usn_replay_transition_profile"), Mapping)
        else {}
    )
    cursor_profile = (
        details.get("usn_cursor_pagination_profile")
        if isinstance(details.get("usn_cursor_pagination_profile"), Mapping)
        else {}
    )
    bounded_path = (
        details.get("usn_bounded_mft_path")
        if isinstance(details.get("usn_bounded_mft_path"), Mapping)
        else {}
    )
    reportability = ntfs_reportability_decision("usn", report_grade, details)
    source = {
        "source_path": str(details.get("source_path") or ""),
        "source_sha256": str(hashes.get("sha256") or ""),
        "source_format": str(details.get("source_format") or ""),
        "source_index": details.get("source_index", ""),
        "record_cursor": details.get("record_cursor", ""),
        "next_record_cursor": details.get("next_record_cursor", ""),
    }
    record_identity = {
        "usn": details.get("usn", ""),
        "file_reference_number": str(details.get("record_number") or ""),
        "parent_reference": str(details.get("parent_reference") or ""),
        "file_name": str(details.get("file_path") or ""),
        "timestamp": str(details.get("timestamp") or ""),
        "major_version": details.get("major_version", ""),
        "minor_version": details.get("minor_version", ""),
    }
    manifest_payload = {
        "manifest_version": "usn-timeline-depth-manifest-v1",
        "parser_version": PARSER_VERSION,
        "commercial_batch_id": "commercial-uplift-011-015",
        "item_number": 13,
        "gap_id": "#13",
        "artifact_type": "usn-record",
        "source": source,
        "record_identity": record_identity,
        "record_identity_hash": ntfs_stable_sha256(record_identity),
        "record_layout_validation": {
            "validation_status": str(details.get("validation_status") or "unknown"),
            "record_length": details.get("record_length", ""),
            "record_payload_bytes": details.get("record_payload_bytes", ""),
            "record_padding_bytes": details.get("record_padding_bytes", ""),
            "record_cursor_progresses": bool(validation_checks.get("record_cursor_progresses")),
            "record_length_aligned": bool(validation_checks.get("record_length_aligned")),
            "version_supported": bool(validation_checks.get("version_supported")),
            "filename_utf16_valid": bool(validation_checks.get("filename_utf16_valid")),
            "large_record": bool(validation_checks.get("large_record")),
            "warnings": list(details.get("validation_warnings") or [])[:25],
        },
        "change_semantics": {
            "reason_flags": list(details.get("reason_flags") or []),
            "source_info_flags": list(details.get("source_info_flags") or []),
            "file_attribute_names": list(details.get("file_attribute_names") or []),
            "deleted_hint": bool(details.get("deleted_hint")),
            "rename_hint": str(details.get("rename_hint") or ""),
            "transition_class": str(transition_profile.get("transition_class") or ""),
            "requires_previous_state": bool(transition_profile.get("requires_previous_state")),
            "standalone_timeline_fact": False,
        },
        "path_correlation": {
            "status": str(bounded_path.get("status") or ""),
            "path_candidate": str(bounded_path.get("path_candidate") or ""),
            "path_source": str(bounded_path.get("path_source") or ""),
            "file_reference_cache_hit": bool(bounded_path.get("file_reference_cache_hit")),
            "parent_reference_cache_hit": bool(bounded_path.get("parent_reference_cache_hit")),
            "complete_within_bounded_mft_cache": bool(bounded_path.get("complete_within_bounded_mft_cache")),
            "full_frn_path_cache_replay_done": bool(NTFS_FILESYSTEM_CAPABILITIES["usn_full_journal_replay"]),
            "blockers": list(bounded_path.get("blockers") or []),
        },
        "cursor_pagination": {
            "record_cursor": details.get("record_cursor", ""),
            "next_record_cursor": details.get("next_record_cursor", ""),
            "record_end_offset": details.get("record_end_offset", ""),
            "safe_for_cursor_api": bool(cursor_profile.get("safe_for_cursor_api")),
            "cursor_progress_validated": bool(validation_checks.get("record_cursor_progresses")),
            "large_journal_pagination_validated": False,
            "record_limit": USN_RECORD_SCAN_LIMIT,
            "scan_limit_bytes": NATIVE_SCAN_LIMIT,
            "blockers": list(cursor_profile.get("blockers") or []),
        },
        "replay_state": {
            "decoded_components": dict(replay_profile.get("decoded_components") or {}),
            "full_journal_replay_available": bool(NTFS_FILESYSTEM_CAPABILITIES["usn_full_journal_replay"]),
            "complete_journal_ordering_validated": False,
            "rename_delete_replay_validated": False,
            "trusted_timeline_diff_status": trusted_ntfs_diff_status("usn", details),
            "blockers": [
                "usn-frn-path-cache-replay-required",
                "usn-complete-journal-ordering-required",
                "usn-large-journal-pagination-validation-required",
                "usn-trusted-timeline-diff-required",
            ],
        },
        "citation_refs": [
            {
                "kind": "usn-record-cursor",
                "record_cursor": details.get("record_cursor", ""),
                "next_record_cursor": details.get("next_record_cursor", ""),
                "usn": details.get("usn", ""),
            },
            {
                "kind": "usn-reason-flags",
                "reason_flags": list(details.get("reason_flags") or []),
                "reason_raw": details.get("reason_raw", 0),
            },
            {
                "kind": "usn-frn-parent-reference",
                "file_reference_number": str(details.get("record_number") or ""),
                "parent_reference": str(details.get("parent_reference") or ""),
            },
            {
                "kind": "usn-bounded-path-correlation",
                "status": str(bounded_path.get("status") or ""),
                "path_candidate": str(bounded_path.get("path_candidate") or ""),
            },
            {
                "kind": "usn-replay-validation-state",
                "full_journal_replay_available": bool(NTFS_FILESYSTEM_CAPABILITIES["usn_full_journal_replay"]),
                "trusted_timeline_diff_status": trusted_ntfs_diff_status("usn", details),
            },
        ],
        "reportability": {
            "allowed_use": reportability["allowed_use"],
            "decision": reportability["decision"],
            "report_grade_ready": bool(report_grade.get("report_grade_ready")),
            "commercial_grade_ready": False,
            "full_timeline_replayed": False,
            "blockers": reportability["blockers"],
        },
        "required_before_commercial_grade": [
            "build a complete FRN path cache from full-volume MFT records",
            "replay the complete USN journal in cursor/USN order",
            "validate rename/delete state transitions against known-answer replay rows",
            "prove cursor pagination determinism on multi-million-record journals",
            "diff critical timeline facts against MFTECmd/UsnJrnl2Csv/TSK output",
        ],
    }
    manifest_payload["manifest_sha256"] = ntfs_stable_sha256(manifest_payload)
    return manifest_payload


def usn_record_number_from_record(record: Mapping[str, object], decoded_key: str, raw_key: str) -> int | None:
    decoded = record.get(decoded_key) if isinstance(record.get(decoded_key), Mapping) else {}
    value = decoded.get("record_number") if isinstance(decoded, Mapping) else None
    if value not in (None, ""):
        return int(value)
    raw_value = record.get(raw_key)
    if raw_value in (None, ""):
        return None
    raw_int = int(raw_value)
    return raw_int & 0x0000FFFFFFFFFFFF if raw_int > 0x0000FFFFFFFFFFFF else raw_int


def usn_bounded_mft_path_correlation(
    record: Mapping[str, object],
    mft_path_cache: Mapping[int, Mapping[str, object]],
) -> dict[str, object]:
    frn = usn_record_number_from_record(record, "file_reference_number_decoded", "file_reference_number")
    parent_frn = usn_record_number_from_record(record, "parent_file_reference_number_decoded", "parent_file_reference_number")
    file_name = str(record.get("file_name") or "")
    current = mft_path_cache.get(frn) if frn is not None else None
    parent = mft_path_cache.get(parent_frn) if parent_frn is not None else None
    path_candidate = ""
    source = "none"
    status = "no-mft-path-cache-attached" if not mft_path_cache else "no-matching-frn-in-bounded-mft-cache"
    if isinstance(current, Mapping) and current.get("path"):
        path_candidate = str(current.get("path") or "")
        source = "file-reference-cache"
        status = "matched-file-reference-cache"
    elif isinstance(parent, Mapping) and parent.get("path") and file_name:
        parent_path = str(parent.get("path") or "").rstrip("\\")
        path_candidate = f"{parent_path}\\{file_name}" if parent_path else file_name
        source = "parent-reference-cache-plus-usn-name"
        status = "combined-parent-cache-and-usn-name"
    elif isinstance(parent, Mapping) and parent.get("path"):
        path_candidate = str(parent.get("path") or "")
        source = "parent-reference-cache-only"
        status = "partial-parent-cache-only"
    return {
        "profile_version": "usn-bounded-mft-path-correlation-v1",
        "status": status,
        "file_reference_number": frn if frn is not None else "",
        "parent_file_reference_number": parent_frn if parent_frn is not None else "",
        "file_name": file_name,
        "path_candidate": path_candidate,
        "path_source": source,
        "file_reference_cache_hit": isinstance(current, Mapping),
        "parent_reference_cache_hit": isinstance(parent, Mapping),
        "cache_entry_count": len(mft_path_cache),
        "complete_within_bounded_mft_cache": status in {
            "matched-file-reference-cache",
            "combined-parent-cache-and-usn-name",
        },
        "current_mft_path": dict(current or {}),
        "parent_mft_path": dict(parent or {}),
        "commercial_grade_ready": False,
        "reportability": "bounded-mft-cache-usn-path-candidate",
        "blockers": [
            "usn-full-frn-path-cache-required",
            "usn-complete-journal-ordering-required",
            "usn-trusted-timeline-diff-required",
        ],
    }


def usn_parent_name_path_candidate(
    record: Mapping[str, object],
    mft_path_cache: Mapping[int, Mapping[str, object]],
) -> dict[str, object]:
    parent_frn = usn_record_number_from_record(record, "parent_file_reference_number_decoded", "parent_file_reference_number")
    parent = mft_path_cache.get(parent_frn) if parent_frn is not None else None
    file_name = str(record.get("file_name") or "")
    parent_path = str(parent.get("path") or "") if isinstance(parent, Mapping) else ""
    path_candidate = ""
    status = "no-parent-frn-path-cache-match"
    if parent_path and file_name:
        stripped_parent = parent_path.rstrip("\\")
        path_candidate = f"{stripped_parent}\\{file_name}" if stripped_parent else file_name
        status = "parent-cache-plus-usn-name"
    elif parent_path:
        path_candidate = parent_path
        status = "parent-cache-only"
    return {
        "profile_version": "usn-parent-name-path-candidate-v1",
        "status": status,
        "parent_file_reference_number": parent_frn if parent_frn is not None else "",
        "file_name": file_name,
        "path_candidate": path_candidate,
        "parent_mft_path": dict(parent or {}),
        "cache_entry_count": len(mft_path_cache),
        "commercial_grade_ready": False,
        "reportability": "bounded-parent-cache-usn-name-path-candidate",
        "blockers": [
            "usn-full-frn-path-cache-required",
            "usn-complete-journal-ordering-required",
            "usn-trusted-timeline-diff-required",
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
            "v4_extent_evidence": {
                "extent_count": int(record.get("v4_extent_count") or 0),
                "remaining_extents": int(record.get("v4_remaining_extents") or 0),
                "extent_size": int(record.get("v4_extent_size") or 0),
                "extents": list(record.get("v4_extents") or [])[:10],
            }
            if int(record.get("major_version") or 0) == 4
            else {},
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


def usn_replay_transition_profile(
    record: Mapping[str, object],
    bounded_mft_path: Mapping[str, object] | None = None,
) -> dict[str, object]:
    reason_flags = set(str(item) for item in record.get("reason_flags") or [])
    bounded_path = bounded_mft_path if isinstance(bounded_mft_path, Mapping) else {}
    transition = "metadata-change"
    if "RENAME_OLD_NAME" in reason_flags:
        transition = "rename-old-name"
    elif "RENAME_NEW_NAME" in reason_flags:
        transition = "rename-new-name"
    elif "FILE_DELETE" in reason_flags:
        transition = "delete"
    elif "FILE_CREATE" in reason_flags:
        transition = "create"
    return {
        "profile_version": "usn-replay-transition-v1",
        "transition_class": transition,
        "replay_order_key": {
            "usn": record.get("usn", 0),
            "timestamp": str(record.get("timestamp") or ""),
            "record_cursor": record.get("record_cursor", record.get("record_offset", 0)),
        },
        "file_reference_number_decoded": dict(record.get("file_reference_number_decoded") or {}),
        "parent_file_reference_number_decoded": dict(record.get("parent_file_reference_number_decoded") or {}),
        "file_name": str(record.get("file_name") or ""),
        "bounded_mft_path": dict(bounded_path),
        "path_candidate": str(bounded_path.get("path_candidate") or ""),
        "path_cache_effect": (
            "remove-current-name-after-delete"
            if transition == "delete"
            else "pending-rename-pair-required"
            if transition.startswith("rename-")
            else "add-or-update-current-name"
            if transition == "create"
            else "no-path-cache-mutation-by-itself"
        ),
        "requires_previous_state": transition in {"delete", "rename-old-name", "rename-new-name"},
        "full_journal_context_required": True,
        "commercial_grade_ready": False,
        "blockers": [
            "usn-full-frn-path-cache-required",
            "usn-complete-journal-ordering-required",
            "usn-rename-pair-validation-required",
        ],
    }


def usn_cursor_pagination_profile(record: Mapping[str, object]) -> dict[str, object]:
    cursor = int(record.get("record_cursor", record.get("record_offset", 0)) or 0)
    next_cursor = int(record.get("next_record_cursor", 0) or 0)
    length = int(record.get("record_length", 0) or 0)
    return {
        "profile_version": "usn-cursor-pagination-v1",
        "record_cursor": cursor,
        "next_record_cursor": next_cursor,
        "record_length": length,
        "cursor_progresses": next_cursor > cursor,
        "expected_next_cursor": cursor + length if length else None,
        "cursor_matches_record_length": bool(length and next_cursor == cursor + length),
        "safe_for_cursor_api": next_cursor > cursor and bool(length),
        "commercial_grade_ready": False,
        "blockers": ["usn-large-journal-cursor-determinism-required"],
    }


def usn_replay_inventory_profile(
    records: Sequence[Mapping[str, object]],
    scan_metadata: Mapping[str, object],
    mft_path_cache: Mapping[int, Mapping[str, object]] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    path_cache = mft_path_cache or {}
    transition_counts = count_values(
        usn_replay_transition_profile(record)["transition_class"] for record in records
    )
    rename_old = sum(1 for record in records if "RENAME_OLD_NAME" in set(record.get("reason_flags") or []))
    rename_new = sum(1 for record in records if "RENAME_NEW_NAME" in set(record.get("reason_flags") or []))
    bounded_replay_preview = usn_bounded_mft_replay_preview(records, path_cache)
    rename_pair_preview = usn_rename_pair_preview(records, path_cache)
    delete_lifecycle_preview = usn_delete_lifecycle_preview(records, path_cache)
    state_replay_preview = usn_bounded_state_replay_preview(records, path_cache)
    path_cache_profile = mft_bounded_path_cache_profile(path_cache)
    path_reliability_profile = usn_path_reliability_profile(
        records=records,
        bounded_replay_preview=bounded_replay_preview,
        path_cache_profile=path_cache_profile,
    )
    state_validation_profile = usn_state_replay_validation_profile(
        state_replay_preview=state_replay_preview,
        trusted_diff=trusted_diff,
        path_reliability_profile=path_reliability_profile,
    )
    timeline_review_candidates = usn_timeline_review_candidates(
        rename_pair_preview=rename_pair_preview,
        delete_lifecycle_preview=delete_lifecycle_preview,
    )
    return {
        "profile_version": "usn-replay-inventory-v1",
        "native_record_count": len(records),
        "transition_counts": transition_counts,
        "rename_old_count": rename_old,
        "rename_new_count": rename_new,
        "rename_pair_balance": "balanced-in-scan" if rename_old == rename_new else "requires-full-journal-context",
        "delete_count": sum(1 for record in records if "FILE_DELETE" in set(record.get("reason_flags") or [])),
        "create_count": sum(1 for record in records if "FILE_CREATE" in set(record.get("reason_flags") or [])),
        "cursor_window": {
            "first_record_offset": scan_metadata.get("first_record_offset"),
            "last_record_offset": scan_metadata.get("last_record_offset"),
            "next_cursor_offset": scan_metadata.get("next_cursor_offset"),
            "next_cursor_available": bool(scan_metadata.get("next_cursor_available")),
            "record_limit_reached": bool(scan_metadata.get("record_limit_reached")),
        },
        "bounded_mft_replay_preview": bounded_replay_preview,
        "mft_bounded_path_cache_profile": path_cache_profile,
        "usn_path_reliability_profile": path_reliability_profile,
        "usn_state_replay_validation_profile": state_validation_profile,
        "rename_pair_preview": rename_pair_preview,
        "delete_lifecycle_preview": delete_lifecycle_preview,
        "bounded_state_replay_preview": state_replay_preview,
        "timeline_review_candidates": timeline_review_candidates,
        "timeline_review_candidate_count": len(timeline_review_candidates),
        "full_frn_path_cache_replay_done": False,
        "commercial_grade_ready": False,
        "blockers": [
            "usn-full-frn-path-cache-required",
            "usn-complete-journal-ordering-required",
            "usn-large-journal-pagination-proof-required",
        ],
    }


def usn_bounded_state_replay_preview(
    records: Sequence[Mapping[str, object]],
    mft_path_cache: Mapping[int, Mapping[str, object]] | None = None,
) -> dict[str, object]:
    state: dict[int, str] = {
        int(record_number): str(entry.get("path") or "")
        for record_number, entry in (mft_path_cache or {}).items()
        if isinstance(record_number, int) and isinstance(entry, Mapping) and entry.get("path")
    }
    pending_renames: dict[int, dict[str, object]] = {}
    transitions: list[dict[str, object]] = []
    sorted_records = sorted(records, key=usn_replay_sort_key)

    for record in sorted_records:
        frn = usn_record_number_from_record(record, "file_reference_number_decoded", "file_reference_number")
        if frn is None:
            continue
        flags = set(str(item) for item in record.get("reason_flags") or [])
        parent_name_path = usn_parent_name_path_candidate(record, mft_path_cache or {})
        event_path = str(parent_name_path.get("path_candidate") or state.get(frn) or "")
        base = {
            "file_reference_number": frn,
            "file_name": str(record.get("file_name") or ""),
            "timestamp": str(record.get("timestamp") or ""),
            "usn": record.get("usn", ""),
            "record_cursor": record.get("record_cursor", record.get("record_offset", "")),
            "reason_flags": list(record.get("reason_flags") or []),
            "reportability": "bounded-usn-state-replay-transition",
            "validation_required": True,
            "blockers": [
                "usn-full-frn-path-cache-required",
                "usn-complete-journal-ordering-required",
                "usn-trusted-state-replay-diff-required",
            ],
        }
        if "FILE_CREATE" in flags:
            previous_path = state.get(frn, "")
            if event_path:
                state[frn] = event_path
            transitions.append(
                {
                    **base,
                    "transition": "create",
                    "previous_path": previous_path,
                    "new_path": event_path,
                    "path_candidate": event_path,
                    "timeline_type": "usn-state-create",
                    "event_label": "USN state create",
                    "state_effect": "set-current-path",
                    "confidence": "high" if event_path else "medium",
                }
            )
        if "RENAME_OLD_NAME" in flags:
            previous_path = event_path or state.get(frn, "")
            pending_renames[frn] = {**base, "old_path": previous_path}
            transitions.append(
                {
                    **base,
                    "transition": "rename-old-name",
                    "previous_path": previous_path,
                    "new_path": "",
                    "path_candidate": previous_path,
                    "timeline_type": "usn-state-rename-old-name",
                    "event_label": "USN state rename old name",
                    "state_effect": "pending-rename-old-name",
                    "confidence": "high" if previous_path else "medium",
                }
            )
        if "RENAME_NEW_NAME" in flags:
            pending = pending_renames.pop(frn, {})
            previous_path = str(pending.get("old_path") or state.get(frn) or "")
            new_path = event_path
            if new_path:
                state[frn] = new_path
            transitions.append(
                {
                    **base,
                    "transition": "rename-new-name",
                    "previous_path": previous_path,
                    "new_path": new_path,
                    "path_candidate": new_path,
                    "timeline_type": "usn-state-rename-new-name",
                    "event_label": "USN state rename new name",
                    "state_effect": "update-current-path",
                    "paired_old_record_cursor": pending.get("record_cursor", ""),
                    "confidence": "high" if previous_path and new_path else "medium",
                }
            )
        if "FILE_DELETE" in flags:
            previous_path = state.get(frn) or event_path
            if frn in state:
                del state[frn]
            transitions.append(
                {
                    **base,
                    "transition": "delete",
                    "previous_path": previous_path,
                    "new_path": "",
                    "path_candidate": previous_path,
                    "timeline_type": "usn-state-delete",
                    "event_label": "USN state delete",
                    "state_effect": "remove-current-path",
                    "confidence": "high" if previous_path else "medium",
                }
            )

    return {
        "profile_version": "usn-bounded-state-replay-preview-v1",
        "input_record_count": len(records),
        "sorted_record_count": len(sorted_records),
        "initial_path_state_count": len(mft_path_cache or {}),
        "final_path_state_count": len(state),
        "transition_count": len(transitions),
        "transition_counts": count_values(str(item.get("transition") or "") for item in transitions),
        "pending_rename_count": len(pending_renames),
        "transitions": transitions[:50],
        "sample_limit": 50,
        "complete_journal_replay": False,
        "commercial_grade_ready": False,
        "reportability": "bounded-usn-state-replay-preview",
        "blockers": [
            "usn-full-frn-path-cache-required",
            "usn-complete-journal-ordering-required",
            "usn-large-journal-pagination-proof-required",
            "usn-trusted-state-replay-diff-required",
        ],
    }


def usn_replay_sort_key(record: Mapping[str, object]) -> tuple[int, int, str]:
    try:
        usn = int(record.get("usn") or 0)
    except (TypeError, ValueError):
        usn = 0
    try:
        cursor = int(record.get("record_cursor", record.get("record_offset", 0)) or 0)
    except (TypeError, ValueError):
        cursor = 0
    return (usn, cursor, str(record.get("file_name") or ""))


def usn_timeline_review_candidates(
    *,
    rename_pair_preview: Mapping[str, object],
    delete_lifecycle_preview: Mapping[str, object],
) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    for index, pair in enumerate(rename_pair_preview.get("pairs") or []):
        if not isinstance(pair, Mapping):
            continue
        if pair.get("old_timestamp"):
            candidates.append(
                usn_timeline_candidate(
                    event_type="usn-rename-old-name",
                    timestamp=str(pair.get("old_timestamp") or ""),
                    label=f"USN rename old name: {pair.get('old_name') or ''}",
                    source=pair,
                    source_index=index,
                    cursor_key="old_record_cursor",
                    path_key="old_path_candidate",
                    name_key="old_name",
                )
            )
        if pair.get("new_timestamp"):
            candidates.append(
                usn_timeline_candidate(
                    event_type="usn-rename-new-name",
                    timestamp=str(pair.get("new_timestamp") or ""),
                    label=f"USN rename new name: {pair.get('new_name') or ''}",
                    source=pair,
                    source_index=index,
                    cursor_key="new_record_cursor",
                    path_key="new_path_candidate",
                    name_key="new_name",
                )
            )
    for index, item in enumerate(delete_lifecycle_preview.get("candidates") or []):
        if not isinstance(item, Mapping):
            continue
        if item.get("create_timestamp"):
            candidates.append(
                usn_timeline_candidate(
                    event_type="usn-file-create",
                    timestamp=str(item.get("create_timestamp") or ""),
                    label=f"USN file create: {item.get('file_name') or ''}",
                    source=item,
                    source_index=index,
                    cursor_key="create_record_cursor",
                    path_key="create_path_candidate",
                    name_key="file_name",
                )
            )
        if item.get("delete_timestamp"):
            candidates.append(
                usn_timeline_candidate(
                    event_type="usn-file-delete",
                    timestamp=str(item.get("delete_timestamp") or ""),
                    label=f"USN file delete: {item.get('file_name') or ''}",
                    source=item,
                    source_index=index,
                    cursor_key="delete_record_cursor",
                    path_key="delete_path_candidate",
                    name_key="file_name",
                )
            )
    return candidates[:50]


def usn_timeline_candidate(
    *,
    event_type: str,
    timestamp: str,
    label: str,
    source: Mapping[str, object],
    source_index: int,
    cursor_key: str,
    path_key: str,
    name_key: str,
) -> dict[str, object]:
    return {
        "timestamp": timestamp,
        "timeline_type": event_type,
        "event_label": label.strip(),
        "file_name": str(source.get(name_key) or ""),
        "path_candidate": str(source.get(path_key) or ""),
        "record_cursor": source.get(cursor_key, ""),
        "file_reference_number": source.get("file_reference_number", ""),
        "confidence": str(source.get("confidence") or ""),
        "source_index": source_index,
        "reportability": "bounded-usn-timeline-review-candidate",
        "validation_required": True,
        "blockers": [
            "usn-complete-journal-ordering-required",
            "usn-trusted-timeline-diff-required",
        ],
    }


def usn_delete_lifecycle_preview(
    records: Sequence[Mapping[str, object]],
    mft_path_cache: Mapping[int, Mapping[str, object]] | None = None,
) -> dict[str, object]:
    create_records: list[Mapping[str, object]] = []
    delete_records: list[Mapping[str, object]] = []
    for record in records:
        flags = set(str(item) for item in record.get("reason_flags") or [])
        if "FILE_CREATE" in flags:
            create_records.append(record)
        if "FILE_DELETE" in flags:
            delete_records.append(record)

    create_by_frn: dict[int, list[Mapping[str, object]]] = {}
    for record in create_records:
        frn = usn_record_number_from_record(record, "file_reference_number_decoded", "file_reference_number")
        if frn is None:
            continue
        create_by_frn.setdefault(frn, []).append(record)

    candidates: list[dict[str, object]] = []
    unmatched_delete_count = 0
    for delete_record in delete_records:
        frn = usn_record_number_from_record(delete_record, "file_reference_number_decoded", "file_reference_number")
        delete_usn = int(delete_record.get("usn") or 0)
        matching_create: Mapping[str, object] | None = None
        if frn is not None:
            for create_record in reversed(create_by_frn.get(frn, [])):
                create_usn = int(create_record.get("usn") or 0)
                if not delete_usn or not create_usn or create_usn <= delete_usn:
                    matching_create = create_record
                    break
        if matching_create is None:
            unmatched_delete_count += 1
        delete_correlation = usn_bounded_mft_path_correlation(delete_record, mft_path_cache or {})
        create_correlation = usn_bounded_mft_path_correlation(matching_create, mft_path_cache or {}) if matching_create else {}
        file_name = str(delete_record.get("file_name") or (matching_create.get("file_name") if matching_create else "") or "")
        candidates.append(
            {
                "lifecycle_status": "create-delete-paired-within-bounded-window" if matching_create else "delete-without-prior-create-in-window",
                "confidence": "high" if matching_create and frn is not None else "medium" if frn is not None else "low",
                "file_reference_number": frn if frn is not None else "",
                "file_name": file_name,
                "create_usn": matching_create.get("usn", "") if matching_create else "",
                "delete_usn": delete_record.get("usn", ""),
                "create_record_cursor": matching_create.get("record_cursor", matching_create.get("record_offset", "")) if matching_create else "",
                "delete_record_cursor": delete_record.get("record_cursor", delete_record.get("record_offset", "")),
                "create_timestamp": str(matching_create.get("timestamp") or "") if matching_create else "",
                "delete_timestamp": str(delete_record.get("timestamp") or ""),
                "create_path_candidate": str(create_correlation.get("path_candidate") or ""),
                "delete_path_candidate": str(delete_correlation.get("path_candidate") or ""),
                "delete_reason_flags": list(delete_record.get("reason_flags") or []),
                "reportability": "bounded-delete-lifecycle-candidate",
            }
        )

    return {
        "profile_version": "usn-delete-lifecycle-preview-v1",
        "create_count": len(create_records),
        "delete_count": len(delete_records),
        "candidate_lifecycle_count": len(candidates),
        "paired_create_delete_count": sum(1 for item in candidates if item["lifecycle_status"] == "create-delete-paired-within-bounded-window"),
        "delete_without_prior_create_count": unmatched_delete_count,
        "candidates": candidates[:25],
        "sample_limit": 25,
        "complete_journal_replay": False,
        "commercial_grade_ready": False,
        "blockers": [
            "usn-complete-journal-ordering-required",
            "usn-delete-state-machine-validation-required",
            "usn-trusted-delete-diff-required",
        ],
    }


def usn_rename_pair_preview(
    records: Sequence[Mapping[str, object]],
    mft_path_cache: Mapping[int, Mapping[str, object]] | None = None,
) -> dict[str, object]:
    old_records: list[Mapping[str, object]] = []
    new_records: list[Mapping[str, object]] = []
    for record in records:
        flags = set(str(item) for item in record.get("reason_flags") or [])
        if "RENAME_OLD_NAME" in flags:
            old_records.append(record)
        if "RENAME_NEW_NAME" in flags:
            new_records.append(record)

    pairs: list[dict[str, object]] = []
    unmatched_old: list[Mapping[str, object]] = []
    used_new_indexes: set[int] = set()
    for old_record in old_records:
        old_frn = usn_record_number_from_record(old_record, "file_reference_number_decoded", "file_reference_number")
        old_parent = usn_record_number_from_record(old_record, "parent_file_reference_number_decoded", "parent_file_reference_number")
        old_usn = int(old_record.get("usn") or 0)
        best_index = -1
        best_new: Mapping[str, object] | None = None
        for index, new_record in enumerate(new_records):
            if index in used_new_indexes:
                continue
            new_frn = usn_record_number_from_record(new_record, "file_reference_number_decoded", "file_reference_number")
            if old_frn is not None and new_frn is not None and old_frn != new_frn:
                continue
            new_usn = int(new_record.get("usn") or 0)
            if old_usn and new_usn and new_usn < old_usn:
                continue
            best_index = index
            best_new = new_record
            break
        if best_new is None:
            unmatched_old.append(old_record)
            continue
        used_new_indexes.add(best_index)
        new_parent = usn_record_number_from_record(best_new, "parent_file_reference_number_decoded", "parent_file_reference_number")
        old_correlation = usn_bounded_mft_path_correlation(old_record, mft_path_cache or {})
        new_correlation = usn_bounded_mft_path_correlation(best_new, mft_path_cache or {})
        old_name_path = usn_parent_name_path_candidate(old_record, mft_path_cache or {})
        new_name_path = usn_parent_name_path_candidate(best_new, mft_path_cache or {})
        old_name = str(old_record.get("file_name") or "")
        new_name = str(best_new.get("file_name") or "")
        same_parent = old_parent not in (None, "") and new_parent not in (None, "") and old_parent == new_parent
        confidence = "high" if same_parent and old_frn is not None else "medium" if old_frn is not None else "low"
        pairs.append(
            {
                "pair_status": "candidate-paired-within-bounded-window",
                "confidence": confidence,
                "file_reference_number": old_frn if old_frn is not None else "",
                "old_parent_file_reference_number": old_parent if old_parent is not None else "",
                "new_parent_file_reference_number": new_parent if new_parent is not None else "",
                "same_parent_reference": same_parent,
                "old_name": old_name,
                "new_name": new_name,
                "old_path_candidate": str(old_name_path.get("path_candidate") or old_correlation.get("path_candidate") or ""),
                "new_path_candidate": str(new_name_path.get("path_candidate") or new_correlation.get("path_candidate") or ""),
                "old_path_candidate_source": str(old_name_path.get("status") or old_correlation.get("status") or ""),
                "new_path_candidate_source": str(new_name_path.get("status") or new_correlation.get("status") or ""),
                "old_frn_path_correlation": dict(old_correlation),
                "new_frn_path_correlation": dict(new_correlation),
                "old_usn": old_record.get("usn", ""),
                "new_usn": best_new.get("usn", ""),
                "old_record_cursor": old_record.get("record_cursor", old_record.get("record_offset", "")),
                "new_record_cursor": best_new.get("record_cursor", best_new.get("record_offset", "")),
                "old_timestamp": str(old_record.get("timestamp") or ""),
                "new_timestamp": str(best_new.get("timestamp") or ""),
                "reportability": "bounded-rename-pair-candidate",
            }
        )

    unmatched_new = [
        record for index, record in enumerate(new_records) if index not in used_new_indexes
    ]
    return {
        "profile_version": "usn-rename-pair-preview-v1",
        "rename_old_count": len(old_records),
        "rename_new_count": len(new_records),
        "candidate_pair_count": len(pairs),
        "unmatched_old_count": len(unmatched_old),
        "unmatched_new_count": len(unmatched_new),
        "pair_balance": "balanced-in-bounded-window" if len(unmatched_old) == 0 and len(unmatched_new) == 0 else "requires-full-journal-context",
        "pairs": pairs[:25],
        "sample_limit": 25,
        "complete_journal_replay": False,
        "commercial_grade_ready": False,
        "blockers": [
            "usn-complete-journal-ordering-required",
            "usn-rename-state-machine-validation-required",
            "usn-trusted-rename-diff-required",
        ],
    }


def usn_bounded_mft_replay_preview(
    records: Sequence[Mapping[str, object]],
    mft_path_cache: Mapping[int, Mapping[str, object]],
) -> dict[str, object]:
    correlations = [usn_bounded_mft_path_correlation(record, mft_path_cache) for record in records]
    matched = [item for item in correlations if item.get("path_candidate")]
    samples: list[dict[str, object]] = []
    for record, correlation in zip(records, correlations):
        if not correlation.get("path_candidate"):
            continue
        transition = usn_replay_transition_profile(record, correlation)
        samples.append(
            {
                "usn": record.get("usn", ""),
                "record_cursor": record.get("record_cursor", record.get("record_offset", "")),
                "timestamp": str(record.get("timestamp") or ""),
                "transition_class": transition["transition_class"],
                "reason_flags": list(record.get("reason_flags") or []),
                "file_reference_number": correlation.get("file_reference_number", ""),
                "parent_file_reference_number": correlation.get("parent_file_reference_number", ""),
                "file_name": str(record.get("file_name") or ""),
                "path_candidate": str(correlation.get("path_candidate") or ""),
                "path_source": str(correlation.get("path_source") or ""),
                "correlation_status": str(correlation.get("status") or ""),
            }
        )
    return {
        "profile_version": "usn-bounded-mft-replay-preview-v1",
        "cache_entry_count": len(mft_path_cache),
        "record_count": len(records),
        "correlated_record_count": len(matched),
        "uncorrelated_record_count": max(0, len(records) - len(matched)),
        "file_reference_cache_hit_count": sum(1 for item in correlations if item.get("file_reference_cache_hit")),
        "parent_reference_cache_hit_count": sum(1 for item in correlations if item.get("parent_reference_cache_hit")),
        "correlation_status_counts": count_values(str(item.get("status") or "") for item in correlations),
        "correlated_transition_counts": count_values(str(item.get("transition_class") or "") for item in samples),
        "path_samples": samples[:25],
        "sample_limit": 25,
        "complete_journal_replay": False,
        "reportability": "bounded-mft-cache-usn-review-preview",
        "commercial_grade_ready": False,
        "blockers": [
            "usn-full-frn-path-cache-required",
            "usn-complete-journal-ordering-required",
            "usn-rename-delete-state-machine-validation-required",
            "usn-large-journal-pagination-proof-required",
        ],
    }


def usn_path_reliability_profile(
    *,
    records: Sequence[Mapping[str, object]],
    bounded_replay_preview: Mapping[str, object],
    path_cache_profile: Mapping[str, object],
) -> dict[str, object]:
    record_count = len(records)
    correlated_count = int(bounded_replay_preview.get("correlated_record_count") or 0)
    cache_entry_count = int(path_cache_profile.get("cache_entry_count") or 0)
    cache_complete_ratio = float(path_cache_profile.get("complete_path_ratio") or 0)
    warning_count = int(path_cache_profile.get("warning_count") or 0)
    correlation_ratio = round(correlated_count / record_count, 6) if record_count else 0
    if not record_count:
        reliability = "no-usn-records"
    elif correlation_ratio >= 0.8 and cache_complete_ratio >= 0.8 and warning_count == 0:
        reliability = "high-bounded-review-confidence"
    elif correlation_ratio >= 0.5 and cache_complete_ratio >= 0.5:
        reliability = "medium-bounded-review-confidence"
    elif correlated_count > 0:
        reliability = "low-bounded-review-confidence"
    else:
        reliability = "no-path-correlation"
    return {
        "profile_version": "usn-path-reliability-profile-v1",
        "record_count": record_count,
        "correlated_record_count": correlated_count,
        "correlation_ratio": correlation_ratio,
        "mft_cache_entry_count": cache_entry_count,
        "mft_cache_complete_path_ratio": cache_complete_ratio,
        "mft_cache_warning_count": warning_count,
        "reliability": reliability,
        "review_priority": (
            "review-correlated-paths-first"
            if reliability in {"high-bounded-review-confidence", "medium-bounded-review-confidence"}
            else "treat-paths-as-low-confidence-pivots"
            if correlated_count > 0
            else "review-usn-records-without-path-assumption"
        ),
        "safe_report_wording": (
            "Bounded MFT cache supplied strong review pivots for most scanned USN records; validate with full-volume FRN cache and trusted parser diff before report-grade use."
            if reliability == "high-bounded-review-confidence"
            else "Bounded MFT cache supplied partial review pivots; do not report paths as complete without full-volume FRN cache validation."
            if correlated_count > 0
            else "No reliable bounded MFT path correlation was available for this USN scan window."
        ),
        "commercial_grade_ready": False,
        "reportability": "bounded-usn-path-reliability-assessment",
        "blockers": [
            "usn-full-frn-path-cache-required",
            "mft-trusted-path-diff-required",
            "usn-trusted-state-replay-diff-required",
        ],
    }


def usn_state_replay_validation_profile(
    *,
    state_replay_preview: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None = None,
    state_replay_diff: Mapping[str, object] | None = None,
    path_reliability_profile: Mapping[str, object] | None = None,
) -> dict[str, object]:
    diff = trusted_diff if isinstance(trusted_diff, Mapping) else {}
    replay_diff = state_replay_diff if isinstance(state_replay_diff, Mapping) else {}
    reliability = path_reliability_profile if isinstance(path_reliability_profile, Mapping) else {}
    transition_count = int(state_replay_preview.get("transition_count") or 0)
    record_level_passed = diff.get("status") == "pass"
    has_transitions = transition_count > 0
    reliability_label = str(reliability.get("reliability") or "")
    replay_validated = replay_diff.get("status") == "pass"
    blockers = []
    if not record_level_passed:
        blockers.append("usn-trusted-timeline-diff-required")
    if has_transitions and not replay_validated:
        blockers.append("usn-trusted-state-replay-diff-required")
    elif not has_transitions:
        blockers.append("usn-state-replay-transition-corpus-required")
    if reliability_label in {"low-bounded-review-confidence", "no-path-correlation", ""}:
        blockers.append("usn-path-reliability-validation-required")
    return {
        "profile_version": "usn-state-replay-validation-profile-v1",
        "record_level_trusted_diff_passed": record_level_passed,
        "state_replay_diff_passed": replay_validated,
        "trusted_tool": str(diff.get("trusted_tool") or ""),
        "trusted_tool_recognized": bool(diff.get("trusted_tool_recognized")),
        "trusted_diff_status": str(diff.get("status") or "not-attached"),
        "trusted_diff_matched_count": int(diff.get("matched_count") or 0),
        "state_replay_diff_status": str(replay_diff.get("status") or "not-attached"),
        "state_replay_diff_matched_count": int(replay_diff.get("matched_count") or 0),
        "state_replay_trusted_tool": str(replay_diff.get("trusted_tool") or ""),
        "transition_count": transition_count,
        "path_reliability": reliability_label,
        "validation_status": (
            "record-and-state-replay-diffs-passed"
            if record_level_passed and replay_validated
            else
            "record-level-diff-passed-state-replay-validation-required"
            if record_level_passed and has_transitions
            else "trusted-diff-and-state-replay-validation-required"
        ),
        "commercial_grade_ready": record_level_passed and replay_validated and reliability_label not in {"low-bounded-review-confidence", "no-path-correlation", ""},
        "reportability": "usn-state-replay-validation-gate",
        "blockers": blockers,
        "safe_report_wording": (
            "USN record-level and state replay diffs passed against trusted validation rows; still preserve source hashes and full-corpus scope limits in reports."
            if record_level_passed and replay_validated
            else
            "USN records matched a trusted parser export, but the derived state replay remains a bounded review aid until a state-machine replay diff is attached."
            if record_level_passed
            else "USN state replay has not been validated against a trusted parser export or state-machine replay corpus."
        ),
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
        "has_attribute_list_attribute": ("$ATTRIBUTE_LIST detected", "medium"),
        "has_nonresident_data_attribute": ("Nonresident $DATA attribute", "medium"),
        "has_nonresident_runlist_preview": ("Nonresident runlist preview", "medium"),
        "has_decoded_nonresident_runlist": ("Decoded nonresident runlist preview", "high"),
        "attribute_end_marker_seen": ("Attribute end marker", "medium"),
        "timestamp_fields_present": ("Timestamp fields", "high"),
        "record_length_aligned": ("USN record length aligned", "high"),
        "record_cursor_progresses": ("USN cursor progresses", "critical"),
        "filename_bounds_valid": ("USN filename bounds", "high"),
        "filename_utf16_valid": ("USN filename UTF-16", "high"),
        "filetime_plausible": ("USN FILETIME plausible", "high"),
        "version_supported": ("USN version supported", "high"),
        "v4_extent_bounds_valid": ("USN v4 extent bounds", "high"),
        "v4_extent_count_matches": ("USN v4 extent count", "medium"),
        "v4_no_filename_by_design": ("USN v4 has no filename by design", "medium"),
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


def ntfs_report_citation_manifest(family: str, details: Mapping[str, object]) -> dict[str, object]:
    matrix = details.get("ntfs_validation_matrix") if isinstance(details.get("ntfs_validation_matrix"), list) else []
    report_grade = (
        details.get("ntfs_report_grade_assessment")
        if isinstance(details.get("ntfs_report_grade_assessment"), Mapping)
        else {}
    )
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
    artifact_type = "mft-record" if family == "mft" else "usn-record"
    row_identity = ntfs_row_identity(family, details)
    citation_refs: list[dict[str, object]] = [
        {
            "kind": "ntfs-source-file",
            "source_path": str(details.get("source_path") or ""),
            "source_sha256": str(hashes.get("sha256") or ""),
            "source_format": str(details.get("source_format") or ""),
            "viewer_locator": {
                "viewer": "ntfs-source",
                "artifact_family": family,
                "source_path": str(details.get("source_path") or ""),
            },
        }
    ]
    if family == "mft":
        citation_refs.extend(ntfs_mft_citation_refs(details))
    else:
        citation_refs.extend(ntfs_usn_citation_refs(details))

    validation_passed = [
        str(item.get("id"))
        for item in matrix
        if isinstance(item, Mapping) and bool(item.get("passed"))
    ]
    validation_failed = [
        str(item.get("id"))
        for item in matrix
        if isinstance(item, Mapping) and not bool(item.get("passed"))
    ]
    reportability = ntfs_reportability_decision(family, report_grade, details)
    manifest_payload = {
        "manifest_version": "ntfs-report-citation-manifest-v1",
        "parser_version": PARSER_VERSION,
        "artifact_family": family,
        "artifact_type": artifact_type,
        "source_path": str(details.get("source_path") or ""),
        "source_sha256": str(hashes.get("sha256") or ""),
        "source_index": details.get("source_index", ""),
        "row_identity": row_identity,
        "row_identity_hash": ntfs_stable_sha256(row_identity),
        "citation_refs": citation_refs,
        "citation_ref_count": len(citation_refs),
        "validation_summary": {
            "passed_ids": validation_passed,
            "failed_ids": validation_failed,
            "validation_required": bool(details.get("validation_required", True)),
            "validation_status": str(details.get("validation_status") or ""),
        },
        "reportability": {
            "allowed_use": reportability["allowed_use"],
            "decision": reportability["decision"],
            "report_grade_ready": bool(report_grade.get("report_grade_ready")),
            "commercial_grade_ready": False,
            "blockers": reportability["blockers"],
        },
        "viewer_entrypoints": ntfs_viewer_entrypoints(family, details),
    }
    manifest_payload["manifest_sha256"] = ntfs_stable_sha256(manifest_payload)
    return manifest_payload


def ntfs_row_identity(family: str, details: Mapping[str, object]) -> dict[str, object]:
    if family == "mft":
        return {
            "record_number": str(details.get("record_number") or ""),
            "record_offset": details.get("record_offset", ""),
            "sequence_number": details.get("sequence_number", ""),
            "parent_reference": str(details.get("parent_reference") or ""),
            "file_path": str(details.get("file_path") or ""),
        }
    return {
        "usn": details.get("usn", ""),
        "record_cursor": details.get("record_cursor", ""),
        "next_record_cursor": details.get("next_record_cursor", ""),
        "record_length": details.get("record_length", ""),
        "file_reference_number": str(details.get("record_number") or ""),
        "parent_reference": str(details.get("parent_reference") or ""),
        "file_path": str(details.get("file_path") or ""),
    }


def ntfs_record_source_viewer_locator(family: str, details: Mapping[str, object]) -> dict[str, object]:
    source_hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
    report_grade = (
        details.get("ntfs_report_grade_assessment")
        if isinstance(details.get("ntfs_report_grade_assessment"), Mapping)
        else {}
    )
    base_payload: dict[str, object] = {
        "profile_version": "ntfs-record-source-viewer-locator-v1",
        "qc_prep_item": 9,
        "artifact_family": family,
        "source_path": str(details.get("source_path") or ""),
        "source_format": str(details.get("source_format") or ""),
        "source_sha256": str(source_hashes.get("sha256") or ""),
        "source_index": details.get("source_index", ""),
        "file_path": str(details.get("file_path") or ""),
        "timestamp": str(details.get("timestamp") or ""),
        "validation_required": bool(details.get("validation_required", True)),
        "validation_warnings": list(details.get("validation_warnings") or []),
        "commercial_grade_ready": bool(details.get("commercial_grade_ready")),
        "commercial_grade_blockers": list(
            report_grade.get("blockers")
            if isinstance(report_grade.get("blockers"), list)
            else details.get("commercial_grade_blockers") or []
        ),
        "report_citation_manifest_hash": str(details.get("ntfs_report_citation_manifest_hash") or ""),
        "required_before_report": [
            "source_sha256",
            "record offset/cursor",
            "decoded FRN identity",
            "path confidence",
            "trusted parser diff for report-grade claims",
        ],
    }
    if family == "mft":
        path_profile = (
            details.get("mft_path_reconstruction_profile")
            if isinstance(details.get("mft_path_reconstruction_profile"), Mapping)
            else {}
        )
        parent_decoded = (
            details.get("parent_reference_decoded")
            if isinstance(details.get("parent_reference_decoded"), Mapping)
            else {}
        )
        payload = {
            **base_payload,
            "viewer": "ntfs-mft-record",
            "record_locator_type": "mft-file-record",
            "record_number": str(details.get("record_number") or ""),
            "frn": str(details.get("record_number") or ""),
            "frn_record_number": details.get("record_number", ""),
            "parent_frn": str(details.get("parent_reference") or ""),
            "parent_frn_record_number": parent_decoded.get("record_number", ""),
            "parent_sequence": parent_decoded.get("sequence_number", ""),
            "sequence": details.get("sequence_number", ""),
            "usn": "",
            "reason_flags": [],
            "record_offset": details.get("record_offset", ""),
            "record_cursor": "",
            "next_record_cursor": "",
            "path_confidence": str(path_profile.get("source_mode") or ""),
            "path_candidate": str(path_profile.get("best_available_path") or details.get("file_path") or ""),
            "source_citation": (
                f"$MFT record {details.get('record_number', '')} "
                f"seq {details.get('sequence_number', '')} "
                f"offset {details.get('record_offset', '')} "
                f"path {details.get('file_path', '')}"
            ).strip(),
            "viewer_actions": [
                {
                    "label": "Open raw MFT record",
                    "viewer": "hex",
                    "byte_offset": details.get("record_offset", ""),
                },
                {
                    "label": "Inspect decoded MFT attributes",
                    "viewer": "mft-attributes",
                    "record_number": str(details.get("record_number") or ""),
                },
            ],
        }
    else:
        file_ref_decoded = (
            details.get("file_reference_number_decoded")
            if isinstance(details.get("file_reference_number_decoded"), Mapping)
            else {}
        )
        parent_ref_decoded = (
            details.get("parent_file_reference_number_decoded")
            if isinstance(details.get("parent_file_reference_number_decoded"), Mapping)
            else {}
        )
        bounded_path = (
            details.get("usn_bounded_mft_path") if isinstance(details.get("usn_bounded_mft_path"), Mapping) else {}
        )
        payload = {
            **base_payload,
            "viewer": "ntfs-usn-record",
            "record_locator_type": "usn-change-record",
            "record_number": str(details.get("record_number") or ""),
            "frn": str(details.get("record_number") or ""),
            "frn_record_number": file_ref_decoded.get("record_number", ""),
            "parent_frn": str(details.get("parent_reference") or ""),
            "parent_frn_record_number": parent_ref_decoded.get("record_number", ""),
            "parent_sequence": parent_ref_decoded.get("sequence_number", ""),
            "sequence": file_ref_decoded.get("sequence_number", ""),
            "usn": details.get("usn", ""),
            "reason_flags": list(details.get("reason_flags") or []),
            "record_offset": details.get("record_offset", ""),
            "record_cursor": details.get("record_cursor", ""),
            "next_record_cursor": details.get("next_record_cursor", ""),
            "path_confidence": str(bounded_path.get("status") or "usn-file-name-only"),
            "path_candidate": str(bounded_path.get("path_candidate") or details.get("file_path") or ""),
            "source_citation": (
                f"USN {details.get('usn', '')} "
                f"FRN {details.get('record_number', '')} "
                f"parent {details.get('parent_reference', '')} "
                f"cursor {details.get('record_cursor', '')} "
                f"reason {','.join(str(item) for item in details.get('reason_flags') or [])} "
                f"path {details.get('file_path', '')}"
            ).strip(),
            "viewer_actions": [
                {
                    "label": "Open raw USN record",
                    "viewer": "hex",
                    "byte_offset": details.get("record_cursor", ""),
                },
                {
                    "label": "Inspect reason and FRN decode",
                    "viewer": "usn-record",
                    "usn": details.get("usn", ""),
                },
            ],
        }
    payload["locator_sha256"] = ntfs_stable_sha256(payload)
    return payload


def ntfs_mft_citation_refs(details: Mapping[str, object]) -> list[dict[str, object]]:
    refs: list[dict[str, object]] = [
        {
            "kind": "mft-record-offset",
            "record_number": str(details.get("record_number") or ""),
            "record_offset": details.get("record_offset", ""),
            "sequence_number": details.get("sequence_number", ""),
            "viewer_locator": {
                "viewer": "mft-record-offset",
                "record_number": str(details.get("record_number") or ""),
                "byte_offset": details.get("record_offset", ""),
            },
        }
    ]
    file_name_entries = [item for item in details.get("file_name_entries") or [] if isinstance(item, Mapping)]
    if details.get("file_path") or file_name_entries:
        refs.append(
            {
                "kind": "mft-file-name-attribute",
                "file_path": str(details.get("file_path") or ""),
                "parent_reference": str(details.get("parent_reference") or ""),
                "file_name_entry_count": len(file_name_entries),
                "path_hash": ntfs_stable_sha256(
                    {
                        "file_path": str(details.get("file_path") or ""),
                        "file_name_entries": file_name_entries[:5],
                    }
                ),
                "viewer_locator": {
                    "viewer": "mft-file-name",
                    "record_number": str(details.get("record_number") or ""),
                    "attribute": "$FILE_NAME",
                },
            }
        )
    data_attributes = [item for item in details.get("data_attributes") or [] if isinstance(item, Mapping)]
    if data_attributes:
        first_data = data_attributes[0]
        refs.append(
            {
                "kind": "mft-data-attribute",
                "data_attribute_count": len(data_attributes),
                "resident": bool(first_data.get("resident")),
                "runlist_decode_status": str(first_data.get("runlist_decode_status") or ""),
                "resident_data_hashes": first_data.get("resident_data_hashes", {}),
                "viewer_locator": {
                    "viewer": "mft-data-attribute",
                    "record_number": str(details.get("record_number") or ""),
                    "attribute": "$DATA",
                },
            }
        )
    attribute_list_entries = [item for item in details.get("attribute_list_entries") or [] if isinstance(item, Mapping)]
    if attribute_list_entries:
        refs.append(
            {
                "kind": "mft-attribute-list",
                "attribute_list_entry_count": len(attribute_list_entries),
                "extension_resolution_status": "detected-not-resolved",
                "viewer_locator": {
                    "viewer": "mft-attribute-list",
                    "record_number": str(details.get("record_number") or ""),
                    "attribute": "$ATTRIBUTE_LIST",
                },
            }
        )
    return refs


def ntfs_usn_citation_refs(details: Mapping[str, object]) -> list[dict[str, object]]:
    refs: list[dict[str, object]] = [
        {
            "kind": "usn-record-cursor",
            "usn": details.get("usn", ""),
            "record_cursor": details.get("record_cursor", ""),
            "next_record_cursor": details.get("next_record_cursor", ""),
            "record_length": details.get("record_length", ""),
            "viewer_locator": {
                "viewer": "usn-record-cursor",
                "byte_offset": details.get("record_cursor", ""),
                "usn": details.get("usn", ""),
            },
        }
    ]
    if details.get("reason_flags"):
        refs.append(
            {
                "kind": "usn-reason-flags",
                "reason_flags": list(details.get("reason_flags") or []),
                "reason_raw": details.get("reason_raw", 0),
                "viewer_locator": {
                    "viewer": "usn-reason",
                    "byte_offset": details.get("record_cursor", ""),
                },
            }
        )
    if details.get("rename_hint") or details.get("deleted_hint"):
        refs.append(
            {
                "kind": "usn-rename-delete-timeline-hint",
                "rename_hint": str(details.get("rename_hint") or ""),
                "deleted_hint": bool(details.get("deleted_hint")),
                "file_reference_number": str(details.get("record_number") or ""),
                "parent_reference": str(details.get("parent_reference") or ""),
                "viewer_locator": {
                    "viewer": "usn-transition",
                    "byte_offset": details.get("record_cursor", ""),
                    "timestamp": str(details.get("timestamp") or ""),
                },
            }
        )
    bounded_path = details.get("usn_bounded_mft_path") if isinstance(details.get("usn_bounded_mft_path"), Mapping) else {}
    if bounded_path.get("path_candidate"):
        refs.append(
            {
                "kind": "usn-bounded-mft-path-candidate",
                "path_candidate": str(bounded_path.get("path_candidate") or ""),
                "path_source": str(bounded_path.get("path_source") or ""),
                "file_reference_number": bounded_path.get("file_reference_number", ""),
                "parent_file_reference_number": bounded_path.get("parent_file_reference_number", ""),
                "viewer_locator": {
                    "viewer": "usn-mft-path-correlation",
                    "byte_offset": details.get("record_cursor", ""),
                    "usn": details.get("usn", ""),
                },
            }
        )
    raw = details.get("raw") if isinstance(details.get("raw"), Mapping) else {}
    v4_extents = list(raw.get("v4_extents") or [])
    if v4_extents:
        refs.append(
            {
                "kind": "usn-v4-extent-preview",
                "v4_extent_count": len(v4_extents),
                "v4_extents_preview": v4_extents[:USN_V4_EXTENT_PREVIEW_LIMIT],
                "viewer_locator": {
                    "viewer": "usn-v4-extents",
                    "byte_offset": details.get("record_cursor", ""),
                },
            }
        )
    return refs


def ntfs_viewer_entrypoints(family: str, details: Mapping[str, object]) -> list[dict[str, object]]:
    if family == "mft":
        return [
            {
                "label": "Open raw MFT record",
                "viewer": "hex",
                "source_path": str(details.get("source_path") or ""),
                "byte_offset": details.get("record_offset", ""),
            },
            {
                "label": "Inspect decoded MFT attributes",
                "viewer": "mft-attributes",
                "record_number": str(details.get("record_number") or ""),
            },
        ]
    return [
        {
            "label": "Open raw USN record",
            "viewer": "hex",
            "source_path": str(details.get("source_path") or ""),
            "byte_offset": details.get("record_cursor", ""),
        },
        {
            "label": "Inspect USN timeline transition",
            "viewer": "usn-transition",
            "usn": details.get("usn", ""),
            "file_reference_number": str(details.get("record_number") or ""),
        },
    ]


def ntfs_stable_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def ntfs_commercial_uplift_evidence(family: str, details: Mapping[str, object]) -> dict[str, object]:
    matrix = details.get("ntfs_validation_matrix") if isinstance(details.get("ntfs_validation_matrix"), list) else []
    report_grade = (
        details.get("ntfs_report_grade_assessment")
        if isinstance(details.get("ntfs_report_grade_assessment"), Mapping)
        else {}
    )
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
    item_number = 12 if family == "mft" else 13
    trusted_diff_key = "mft_trusted_diff" if family == "mft" else "usn_trusted_diff"
    trusted_diff = (
        details.get(trusted_diff_key)
        if isinstance(details.get(trusted_diff_key), Mapping)
        else {"status": "not-attached"}
    )
    reportability_decision = ntfs_reportability_decision(family, report_grade, details)
    return {
        "batch_id": "commercial-uplift-011-015",
        "item_numbers": [item_number],
        "qc_prep_item_numbers": [QC_PREP_NTFS_ITEM_NUMBERS[family]],
        "implementation_track": "native-parser-depth",
        "objective": "Expose native NTFS record validation, cursor/offset provenance, and commercial blockers on #12-#13 / QC-prep #27-#28 MFT/USN rows.",
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
        "reportability_decision": reportability_decision,
        "commercial_blockers": list(report_grade.get("blockers") or []),
        trusted_diff_key: trusted_diff,
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


def ntfs_reportability_decision(
    family: str,
    report_grade: Mapping[str, object],
    details: Mapping[str, object],
) -> dict[str, object]:
    blockers = set(str(item) for item in report_grade.get("blockers") or [])
    if family == "mft":
        decision = "do-not-report-full-path-or-file-content-as-complete"
        allowed_use = "mft-record-structure-and-timestamp-pivot"
        blockers.add("mft-attribute-list-and-nonresident-runlist-validation-required")
        blockers.add("mft-full-volume-parent-path-diff-required")
        required = [
            "attribute-list extension records resolved",
            "nonresident data runs decoded and independently checked",
            "parent path reconstruction diffed against full-volume parser",
            "record offset, sequence number, and source hash preserved in citation",
        ]
    else:
        decision = "do-not-report-full-timeline-as-replayed"
        allowed_use = "usn-change-record-triage-pivot"
        blockers.add("usn-frn-path-cache-replay-required")
        blockers.add("usn-large-journal-pagination-validation-required")
        required = [
            "FRN path cache replay completed",
            "rename/delete ordering validated over the full journal",
            "large-journal pagination and cursor determinism proven",
            "record cursor, USN, source hash, and parser version preserved in citation",
        ]
    return {
        "profile_version": "ntfs-reportability-decision-v1",
        "commercial_gap_id": "#12" if family == "mft" else "#13",
        "qc_prep_item_number": QC_PREP_NTFS_ITEM_NUMBERS[family],
        "decision": decision,
        "allowed_use": allowed_use,
        "blockers": sorted(blockers),
        "source_location_available": bool(details.get("record_offset") not in (None, "") or details.get("record_cursor") not in (None, "")),
        "required_before_report": required,
    }


def ntfs_native_depth_readiness_profile(
    family: str,
    artifact_scope: str,
    details: Mapping[str, object],
) -> dict[str, object]:
    """Summarize native NTFS parser depth without overstating report-grade readiness."""

    report_grade = (
        details.get("ntfs_report_grade_assessment")
        if isinstance(details.get("ntfs_report_grade_assessment"), Mapping)
        else {}
    )
    validation_checks = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    matrix = details.get("ntfs_validation_matrix") if isinstance(details.get("ntfs_validation_matrix"), list) else []
    passed_ids = [str(item.get("id")) for item in matrix if isinstance(item, Mapping) and item.get("passed")]
    failed_ids = [str(item.get("id")) for item in matrix if isinstance(item, Mapping) and not item.get("passed")]
    source_hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
    decoded_components = (
        mft_depth_components(details, validation_checks)
        if family == "mft"
        else usn_depth_components(details, validation_checks)
    )
    component_count = len(decoded_components)
    decoded_count = sum(1 for value in decoded_components.values() if value)
    depth_score = round(decoded_count / component_count, 3) if component_count else 0.0
    blockers = sorted(
        set(str(item) for item in report_grade.get("blockers") or [])
        | (set(MFT_REPORT_GRADE_BLOCKERS) if family == "mft" else set(USN_REPORT_GRADE_BLOCKERS))
    )
    return {
        "profile_version": "ntfs-native-depth-readiness-v1",
        "parser_version": PARSER_VERSION,
        "family": family,
        "artifact_scope": artifact_scope,
        "commercial_grade_ready": False,
        "report_grade_ready": bool(report_grade.get("report_grade_ready")),
        "status": "triage-depth-improved-report-grade-blocked",
        "depth_score": depth_score,
        "decoded_component_count": decoded_count,
        "total_component_count": component_count,
        "decoded_components": decoded_components,
        "validation_summary": {
            "passed_ids": passed_ids,
            "failed_ids": failed_ids,
            "validation_required": bool(details.get("validation_required", True)),
            "trusted_diff_status": trusted_ntfs_diff_status(family, details),
        },
        "large_data_controls": {
            "bounded_native_scan": str(details.get("source_format") or "").startswith("ntfs-"),
            "scan_limit_bytes": NATIVE_SCAN_LIMIT,
            "record_limit": USN_RECORD_SCAN_LIMIT if family == "usn" else None,
            "source_index": details.get("source_index", ""),
            "record_cursor": details.get("record_cursor", details.get("record_offset", "")),
            "next_cursor_available": bool(details.get("next_cursor_available")),
            "case_db_indexable": True,
        },
        "source_citation_requirements": [
            "source_path",
            "source_sha256",
            "parser_version",
            "record_offset_or_cursor",
            "record_number_or_usn",
            "validation_status",
        ],
        "source_provenance": {
            "source_path": str(details.get("source_path") or ""),
            "source_sha256": str(source_hashes.get("sha256") or ""),
            "record_offset": details.get("record_offset", ""),
            "record_cursor": details.get("record_cursor", ""),
            "record_number": details.get("record_number", ""),
            "usn": details.get("usn", ""),
        },
        "blockers": blockers,
        "next_internal_actions": (
            [
                "Resolve ATTRIBUTE_LIST base/extension records.",
                "Validate nonresident data runs against cluster-level known-answer fixtures.",
                "Build full-volume parent path cache and diff paths against MFTECmd/analyzeMFT.",
            ]
            if family == "mft"
            else [
                "Replay USN with FRN path cache from MFT rows.",
                "Validate rename/delete ordering over the complete journal.",
                "Prove cursor pagination determinism on multi-million-record journals.",
            ]
        ),
        "analyst_warning": (
            "Use this MFT row as a native structure/timestamp pivot only until attribute-list, runlist, "
            "and full parent-path validation are attached."
            if family == "mft"
            else "Use this USN row as a native change-record pivot only until full-journal replay and "
            "trusted timeline diff evidence are attached."
        ),
    }


def mft_depth_components(details: Mapping[str, object], validation_checks: Mapping[str, object]) -> dict[str, bool]:
    data_attributes = [item for item in details.get("data_attributes") or [] if isinstance(item, Mapping)]
    path_profile = details.get("mft_path_reconstruction_profile") if isinstance(details.get("mft_path_reconstruction_profile"), Mapping) else {}
    return {
        "file_record_header": bool(validation_checks.get("magic_valid") or details.get("record_number")),
        "usa_sequence_fixup": bool(validation_checks.get("sequence_fixup_valid") or details.get("sequence_validation")),
        "standard_information": "$STANDARD_INFORMATION" in list(details.get("attribute_types") or []),
        "file_name_attribute": "$FILE_NAME" in list(details.get("attribute_types") or []),
        "parent_reference_decode": bool(path_profile.get("parent_record_number") not in (None, "")),
        "bounded_parent_path_cache": bool(path_profile.get("bounded_parent_cache_used")),
        "data_attribute": "$DATA" in list(details.get("attribute_types") or []),
        "resident_data_hash": any(item.get("resident_data_hashes") for item in data_attributes),
        "nonresident_runlist_preview": any(item.get("runlist_preview") for item in data_attributes),
        "attribute_list_detect": "$ATTRIBUTE_LIST" in list(details.get("attribute_types") or []),
        "attribute_list_resolution": bool(NTFS_FILESYSTEM_CAPABILITIES["mft_attribute_list_resolution"]),
        "full_parent_path_reconstruction": bool(NTFS_FILESYSTEM_CAPABILITIES["full_volume_path_reconstruction"]),
    }


def usn_depth_components(details: Mapping[str, object], validation_checks: Mapping[str, object]) -> dict[str, bool]:
    bounded_path = details.get("usn_bounded_mft_path") if isinstance(details.get("usn_bounded_mft_path"), Mapping) else {}
    return {
        "record_header": bool(validation_checks.get("record_length_aligned") or details.get("record_length")),
        "cursor_progression": bool(validation_checks.get("record_cursor_progresses") or details.get("record_cursor") not in (None, "")),
        "v2_v3_filename_decode": bool(validation_checks.get("filename_utf16_valid") or details.get("file_path")),
        "v4_extent_preview": bool((details.get("usn_record_evidence") or {}).get("change_evidence", {}).get("v4_extent_evidence"))
        if isinstance(details.get("usn_record_evidence"), Mapping)
        else False,
        "reason_flags": bool(details.get("reason_flags")),
        "file_attribute_flags": bool(details.get("file_attribute_names")),
        "frn_parent_refs": bool(details.get("file_reference_number_decoded") or details.get("parent_file_reference_number_decoded")),
        "bounded_mft_path_correlation": bool(bounded_path.get("path_candidate")),
        "rename_delete_hints": bool(details.get("rename_hint") or details.get("deleted_hint")),
        "full_frn_path_cache_replay": bool(NTFS_FILESYSTEM_CAPABILITIES["usn_full_journal_replay"]),
    }


def trusted_ntfs_diff_status(family: str, details: Mapping[str, object]) -> str:
    key = "mft_trusted_diff" if family == "mft" else "usn_trusted_diff"
    trusted_diff = details.get(key) if isinstance(details.get(key), Mapping) else {}
    return str(trusted_diff.get("status") or "not-attached")


def ntfs_analyst_review_profile(family: str, artifact_scope: str, details: Mapping[str, object]) -> dict[str, object]:
    report_grade = (
        details.get("ntfs_report_grade_assessment")
        if isinstance(details.get("ntfs_report_grade_assessment"), Mapping)
        else {}
    )
    validation_checks = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    if family == "mft":
        catalog = {
            "severity": "high",
            "summary": "$MFT FILE record pivot; validates record structure and timestamps but not full-volume path/content completeness.",
            "evidence_interpretation": "NTFS file record metadata, attributes, timestamps, and bounded path candidates",
            "not_proof_of": ["complete file content recovery", "full path reconstruction without volume-wide parent cache", "attribute-list extension resolution"],
            "primary_pivots": ["record_number", "file_path", "parent_reference", "timestamp", "record_offset"],
            "correlation_targets": ["USN", "File content hash", "Directory listing", "Windows Search", "JumpList/ShellBags"],
            "analyst_questions": [
                "Does a trusted MFT parser confirm the same record, parent, and timestamps?",
                "Is the displayed path from a full parent cache or only a bounded candidate?",
                "Do USN and application artifacts explain create/modify/delete activity?",
            ],
            "risk_tags": ["filesystem-record", "path-validation-required"],
        }
        blockers = set(MFT_REPORT_GRADE_BLOCKERS)
    else:
        catalog = {
            "severity": "high",
            "summary": "$UsnJrnl change record pivot; validates record layout and reason flags but not a complete replayed timeline.",
            "evidence_interpretation": "NTFS change journal record with cursor, FRN, reason flags, timestamp, and bounded path correlation",
            "not_proof_of": ["complete timeline replay", "full FRN path-cache history", "user intent"],
            "primary_pivots": ["usn", "record_number", "parent_reference", "file_path", "timestamp", "reason_flags", "record_cursor"],
            "correlation_targets": ["MFT", "Timeline", "File content hash", "Windows Search", "Execution artifacts"],
            "analyst_questions": [
                "Does UsnJrnl2Csv/MFTECmd confirm this record and cursor?",
                "Is the path reconstructed from a reliable MFT cache or just the event filename?",
                "Does rename/delete replay pass a known-answer or trusted transition diff?",
            ],
            "risk_tags": ["journal-record", "timeline-validation-required"],
        }
        blockers = set(USN_REPORT_GRADE_BLOCKERS)
    source_values: dict[str, object] = {}
    for pivot in catalog["primary_pivots"]:
        value = details.get(pivot)
        if value not in ("", None, [], {}):
            source_values[pivot] = bounded_ntfs_review_value(value)
    failed_checks = sorted(str(key) for key, value in validation_checks.items() if not bool(value))
    blockers |= set(str(item) for item in report_grade.get("blockers", []) if str(item))
    blockers.add("mft-trusted-parser-diff-required" if family == "mft" else "usn-trusted-parser-diff-required")
    return {
        "profile_version": "ntfs-analyst-review-profile-v1",
        "family": family,
        "artifact_scope": artifact_scope,
        "severity": catalog["severity"],
        "summary": catalog["summary"],
        "evidence_interpretation": catalog["evidence_interpretation"],
        "not_proof_of": catalog["not_proof_of"],
        "analyst_questions": catalog["analyst_questions"],
        "primary_pivots": catalog["primary_pivots"],
        "source_field_values": source_values,
        "correlation_targets": catalog["correlation_targets"],
        "risk_tags": sorted(catalog["risk_tags"]),
        "validation_required": bool(report_grade.get("status") != "report-grade-ready" or failed_checks),
        "failed_validation_checks": failed_checks,
        "report_grade_ready": bool(report_grade.get("report_grade_ready")),
        "commercial_blockers": sorted(blockers),
        "report_guidance": (
            "Use this NTFS row as a file-system review pivot. Report final path, content, or timeline conclusions only "
            "after trusted parser diff, full-volume/path-cache validation, and source citation checks."
        ),
    }


def bounded_ntfs_review_value(value: object) -> object:
    if isinstance(value, str):
        return value[:1000]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    try:
        text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return str(value)[:1000]
    if len(text) <= 2000:
        return value
    return {"truncated_json_preview": text[:2000], "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}


def mft_full_parser_profile(artifact_scope: str, details: Mapping[str, object]) -> dict[str, object]:
    validation_checks = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    report_grade = (
        details.get("ntfs_report_grade_assessment")
        if isinstance(details.get("ntfs_report_grade_assessment"), Mapping)
        else {}
    )
    attribute_types = list(details.get("attribute_types") or [])
    native_counts = list(details.get("native_attribute_type_counts") or [])
    attribute_list_profile = (
        details.get("mft_attribute_list_profile")
        if isinstance(details.get("mft_attribute_list_profile"), Mapping)
        else {}
    )
    path_profile = (
        details.get("mft_path_reconstruction_profile")
        if isinstance(details.get("mft_path_reconstruction_profile"), Mapping)
        else {}
    )
    data_run_summary = (
        details.get("mft_data_run_summary")
        if isinstance(details.get("mft_data_run_summary"), Mapping)
        else {}
    )
    attribute_type_names = sorted(
        set(str(item) for item in attribute_types)
        | {str(item.get("value")) for item in native_counts if isinstance(item, Mapping) and item.get("value")}
    )
    return {
        "profile_version": "mft-full-parser-readiness-v1",
        "commercial_batch_id": "commercial-uplift-011-015",
        "item_number": 12,
        "qc_prep_item_number": QC_PREP_NTFS_ITEM_NUMBERS["mft"],
        "qc_prep_item_goal": (
            "Complete MFT attribute-list, runlist, resident/nonresident data, "
            "parent path reconstruction, and deleted-state validation."
        ),
        "artifact_scope": artifact_scope,
        "qc_prep_contract": {
            "implemented": [
                "native FILE record header and USA sequence fixup validation",
                "STANDARD_INFORMATION and FILE_NAME attribute decoding",
                "resident data hashing and nonresident runlist preview",
                "bounded parent path cache and source locator/citation",
                "trusted MFTECmd/analyzeMFT-style record diff helper",
            ],
            "usable_outputs": ["mft-file", "mft-record"],
            "validated_by_current_tests": [
                "native MFT fixture record decode",
                "attribute list detection without false resolution claim",
                "nonresident runlist preview decode",
                "trusted MFT diff pass and mismatch blocking",
            ],
            "not_report_grade_until": [
                "ATTRIBUTE_LIST extension records are resolved",
                "nonresident runlists are fully decoded and cluster ranges validated",
                "full-volume FRN parent path reconstruction is complete",
                "deleted-state/path/timestamp rows pass trusted parser diffs",
            ],
        },
        "current_decode_level": (
            "native-file-record-attributes-partial"
            if str(details.get("source_format") or "") == "ntfs-mft"
            else "trusted-tool-export-row"
        ),
        "decoded_components": {
            "file_record_header": bool(validation_checks.get("magic_valid") or validation_checks.get("has_native_records") or details.get("record_number")),
            "usa_sequence_fixup": bool(validation_checks.get("sequence_fixup_valid") or validation_checks.get("has_sequence_validation")),
            "standard_information": "$STANDARD_INFORMATION" in attribute_type_names or bool(validation_checks.get("has_standard_information_attribute")),
            "file_name_attributes": "$FILE_NAME" in attribute_type_names or bool(validation_checks.get("has_file_name_attribute")),
            "parent_reference_decode": bool(path_profile.get("parent_record_number") not in (None, "")),
            "bounded_parent_path_cache": bool(path_profile.get("bounded_parent_cache_used")),
            "resident_data_hashing": any(isinstance(item, Mapping) and item.get("resident") for item in list(details.get("data_attributes") or [])),
            "nonresident_runlist_preview": any(
                isinstance(item, Mapping) and (item.get("resident") is False or item.get("runlist_preview"))
                for item in list(details.get("data_attributes") or [])
            ),
            "attribute_list_detect": bool(attribute_list_profile.get("present")),
            "attribute_list_resolution": bool(NTFS_FILESYSTEM_CAPABILITIES["mft_attribute_list_resolution"]),
            "full_parent_path_reconstruction": bool(NTFS_FILESYSTEM_CAPABILITIES["full_volume_path_reconstruction"]),
        },
        "path_reconstruction_profile": path_profile,
        "attribute_list_profile": attribute_list_profile,
        "data_run_summary": data_run_summary,
        "source_provenance": {
            "source_path": str(details.get("source_path") or ""),
            "source_sha256": (details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}).get("sha256", ""),
            "record_offset": details.get("record_offset", ""),
            "record_number": details.get("record_number", ""),
            "native_record_count": details.get("native_record_count", 0),
            "scan_bytes": details.get("scan_bytes", 0),
        },
        "reportability_decision": ntfs_reportability_decision("mft", report_grade, details),
        "required_before_report": [
            "resolve ATTRIBUTE_LIST extension records and merge base/extension attributes",
            "fully decode nonresident runlists and validate physical cluster ranges",
            "reconstruct parent paths using a full-volume FRN cache",
            "diff record identity/path/timestamps against MFTECmd/analyzeMFT/TSK known-answer output",
        ],
        "large_data_controls": {
            "bounded_native_scan": str(details.get("source_format") or "") == "ntfs-mft",
            "scan_limit_bytes": NATIVE_SCAN_LIMIT,
            "record_level_rows": artifact_scope in {"record", "trusted-export-row"},
            "safe_for_case_db_indexing": True,
        },
        "report_grade_ready": bool(report_grade.get("report_grade_ready")),
        "commercial_grade_ready": False,
        "commercial_grade_blockers": sorted(
            set(report_grade.get("blockers") or [])
            | {
                "mft-attribute-list-extension-resolution-required",
                "mft-full-nonresident-runlist-validation-required",
                "mft-full-volume-path-cache-required",
            }
        ),
    }


def usn_journal_replay_profile(artifact_scope: str, details: Mapping[str, object]) -> dict[str, object]:
    validation_checks = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    report_grade = (
        details.get("ntfs_report_grade_assessment")
        if isinstance(details.get("ntfs_report_grade_assessment"), Mapping)
        else {}
    )
    scan_metadata = details.get("scan_metadata") if isinstance(details.get("scan_metadata"), Mapping) else {}
    transition_profile = (
        details.get("usn_replay_transition_profile")
        if isinstance(details.get("usn_replay_transition_profile"), Mapping)
        else {}
    )
    cursor_profile = (
        details.get("usn_cursor_pagination_profile")
        if isinstance(details.get("usn_cursor_pagination_profile"), Mapping)
        else {}
    )
    inventory_profile = (
        details.get("usn_replay_inventory_profile")
        if isinstance(details.get("usn_replay_inventory_profile"), Mapping)
        else {}
    )
    bounded_path = details.get("usn_bounded_mft_path") if isinstance(details.get("usn_bounded_mft_path"), Mapping) else {}
    return {
        "profile_version": "usn-journal-replay-readiness-v1",
        "commercial_batch_id": "commercial-uplift-011-015",
        "item_number": 14,
        "qc_prep_item_number": QC_PREP_NTFS_ITEM_NUMBERS["usn"],
        "qc_prep_item_goal": (
            "Complete USN v2/v3/v4 replay, FRN path cache, rename/delete reconstruction, "
            "and large-journal cursor handling."
        ),
        "artifact_scope": artifact_scope,
        "qc_prep_contract": {
            "implemented": [
                "native USN v2/v3 record scan and v4 extent preview",
                "reason/source/file-attribute flag decoding",
                "record cursor pagination and next-cursor metadata",
                "bounded MFT path correlation and rename/delete transition previews",
                "trusted UsnJrnl2Csv/MFTECmd-style row and state-replay diff helpers",
            ],
            "usable_outputs": ["usn-journal-file", "usn-record"],
            "validated_by_current_tests": [
                "native USN fixture decode with cursor metadata",
                "v4 extent record preservation",
                "bounded state replay preview",
                "trusted USN diff pass and reason mismatch blocking",
            ],
            "not_report_grade_until": [
                "complete journal replay is performed with a full FRN path cache",
                "rename/delete/create lifecycle is validated against known-answer transitions",
                "large-journal cursor behavior is stress tested",
                "trusted timeline and state-replay diffs are attached for the case evidence",
            ],
        },
        "current_decode_level": (
            "native-v2-v3-record-scan"
            if str(details.get("source_format") or "") == "ntfs-usn-journal"
            else "trusted-tool-export-row"
        ),
        "decoded_components": {
            "v2_v3_records": bool(validation_checks.get("version_supported") or validation_checks.get("has_native_records")),
            "reason_flags": bool(details.get("reason_flags") or details.get("reason_flag_counts")),
            "frn_parent_refs": bool(details.get("file_reference_number_decoded") or details.get("parent_file_reference_number_decoded")),
            "bounded_mft_path_correlation": bool(bounded_path.get("path_candidate")),
            "rename_delete_hints": bool(details.get("rename_hint") or details.get("deleted_hint") or details.get("reason_flag_counts")),
            "cursor_pagination": bool(details.get("record_cursor") not in (None, "") or validation_checks.get("cursor_progress_validated")),
            "full_frn_path_cache_replay": bool(NTFS_FILESYSTEM_CAPABILITIES["usn_full_journal_replay"]),
        },
        "transition_profile": transition_profile,
        "cursor_pagination_profile": cursor_profile,
        "bounded_mft_path_correlation": bounded_path,
        "inventory_replay_profile": inventory_profile,
        "source_provenance": {
            "source_path": str(details.get("source_path") or ""),
            "source_sha256": (details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}).get("sha256", ""),
            "record_cursor": details.get("record_cursor", ""),
            "next_record_cursor": details.get("next_record_cursor", ""),
            "next_cursor_available": details.get("next_cursor_available", scan_metadata.get("next_cursor_available", False)),
            "native_record_count": details.get("native_record_count", 0),
            "timestamp_range": details.get("timestamp_range", scan_metadata.get("timestamp_range", {})),
        },
        "reportability_decision": ntfs_reportability_decision("usn", report_grade, details),
        "required_before_report": [
            "build FRN-to-path cache from MFT and replay USN changes in order",
            "validate rename/delete transitions across the complete journal, not just sampled rows",
            "prove pagination/cursor determinism on large journals",
            "diff critical timeline rows against MFTECmd/UsnJrnl2Csv/TSK known-answer output",
        ],
        "large_data_controls": {
            "bounded_native_scan": str(details.get("source_format") or "") == "ntfs-usn-journal",
            "scan_limit_bytes": NATIVE_SCAN_LIMIT,
            "record_limit": USN_RECORD_SCAN_LIMIT,
            "record_limit_reached": bool(details.get("record_limit_reached", scan_metadata.get("record_limit_reached", False))),
            "safe_for_case_db_indexing": True,
        },
        "report_grade_ready": bool(report_grade.get("report_grade_ready")),
        "commercial_grade_ready": False,
        "commercial_grade_blockers": sorted(
            set(report_grade.get("blockers") or [])
            | {
                "usn-frn-path-cache-replay-required",
                "usn-full-journal-pagination-validation-required",
                "usn-trusted-timeline-diff-required",
            }
        ),
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
    if family == "mft":
        details["mft_full_parser_profile"] = mft_full_parser_profile("trusted-export-row", details)
    else:
        details["usn_journal_replay_profile"] = usn_journal_replay_profile("trusted-export-row", details)
    details["ntfs_native_depth_readiness_profile"] = ntfs_native_depth_readiness_profile(
        family,
        "trusted-export-row",
        details,
    )
    details["commercial_grade_ready"] = False
    details["commercial_grade_blockers"] = details["ntfs_report_grade_assessment"]["blockers"]
    details["commercial_uplift_evidence"] = ntfs_commercial_uplift_evidence(family, details)
    details["ntfs_analyst_review_profile"] = ntfs_analyst_review_profile(family, "trusted-export-row", details)
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
        trusted_diff = (
            details.get("mft_trusted_diff")
            if isinstance(details.get("mft_trusted_diff"), Mapping)
            else {}
        )
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
        if trusted_diff.get("status") == "pass":
            satisfied.append("trusted MFT parser record diff pass")
        return [build_accuracy_gate(12, satisfied_checks=satisfied, evidence_refs=evidence_refs)]

    if artifact_type in {"usn-journal-file", "usn-record"}:
        trusted_diff = (
            details.get("usn_trusted_diff")
            if isinstance(details.get("usn_trusted_diff"), Mapping)
            else {}
        )
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
        if trusted_diff.get("status") == "pass":
            satisfied.append("trusted USN parser timeline diff pass")
        return [build_accuracy_gate(13, satisfied_checks=satisfied, evidence_refs=evidence_refs)]

    return []


def normalize_key(value: object) -> str:
    return "".join(ch for ch in str(value).lower() if ch.isalnum())


def build_mft_trusted_diff(
    rapid_rows: Sequence[Mapping[str, object]],
    trusted_rows: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str,
) -> dict[str, object]:
    return build_ntfs_trusted_diff(
        index_mft_rows(rapid_rows),
        index_mft_rows(trusted_rows),
        trusted_tool=trusted_tool,
        recognized_tools=MFT_TRUSTED_TOOLS,
        mode="mft-trusted-record-diff-v1",
        blocker="mft-trusted-record-diff-required",
        key_label="file_reference",
    )


def build_usn_trusted_diff(
    rapid_rows: Sequence[Mapping[str, object]],
    trusted_rows: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str,
) -> dict[str, object]:
    return build_ntfs_trusted_diff(
        index_usn_rows(rapid_rows),
        index_usn_rows(trusted_rows),
        trusted_tool=trusted_tool,
        recognized_tools=USN_TRUSTED_TOOLS,
        mode="usn-trusted-timeline-diff-v1",
        blocker="usn-trusted-timeline-diff-required",
        key_label="usn_key",
    )


def build_usn_state_replay_trusted_diff(
    rapid_rows: Sequence[Mapping[str, object]],
    trusted_rows: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str,
) -> dict[str, object]:
    return build_ntfs_trusted_diff(
        index_usn_state_replay_rows(rapid_rows),
        index_usn_state_replay_rows(trusted_rows),
        trusted_tool=trusted_tool,
        recognized_tools=USN_TRUSTED_TOOLS | {"state-replay-fixture", "known-answer-state-replay"},
        mode="usn-trusted-state-replay-diff-v1",
        blocker="usn-trusted-state-replay-diff-required",
        key_label="state_replay_key",
    )


def index_mft_rows(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        payload = mft_diff_row_payload(row)
        evidence = payload.get("mft_record_evidence") if isinstance(payload.get("mft_record_evidence"), Mapping) else {}
        identity = evidence.get("record_identity") if isinstance(evidence.get("record_identity"), Mapping) else {}
        path_evidence = evidence.get("path_evidence") if isinstance(evidence.get("path_evidence"), Mapping) else {}
        attribute_evidence = evidence.get("attribute_evidence") if isinstance(evidence.get("attribute_evidence"), Mapping) else {}
        data_attribute = first_mapping(payload.get("data_attributes"))

        record_number = normalized_int_text(
            first_present(
                first_value(payload, "entry_number", "record_number", "file_record_number", "frn", "entrynumber"),
                first_value(identity, "record_number", "file_record_number"),
            )
        )
        sequence_number = normalized_int_text(
            first_present(
                first_value(payload, "sequence_number", "sequence", "seq"),
                first_value(identity, "sequence_number", "sequence"),
            )
        )
        parent_reference = normalized_int_text(
            first_present(
                first_value(payload, "parent_record_number", "parent_reference", "parent_frn", "parent_entry_number", "parent_file_reference"),
                first_value(path_evidence, "parent_record_number", "parent_reference", "parent_entry_number"),
            )
        )
        path = normalized_diff_value(
            first_present(
                first_value(payload, "file_path", "full_path", "path", "filename", "name", "fullpath"),
                first_value(path_evidence, "primary_path", "file_path", "path"),
            )
        )
        attribute_types = normalized_diff_list(
            first_present(
                first_value(payload, "attribute_types", "attributes", "attribute_type_names", "attribute_list"),
                first_value(attribute_evidence, "attribute_types", "attributes", "attribute_type_names"),
            )
        )
        runlist_status = normalized_diff_value(
            first_present(
                first_value(payload, "runlist_decode_status", "data_run_status", "data_runs_status", "runlist_status"),
                first_value(data_attribute, "runlist_decode_status", "data_run_status", "runlist_status"),
            )
        )
        resident_sha256 = normalized_diff_value(
            first_present(
                first_value(payload, "resident_sha256", "resident_data_sha256", "resident_data_hash", "sha256"),
                first_value(data_attribute, "resident_sha256", "resident_data_sha256", "sha256"),
            )
        )
        record_offset = normalized_int_text(
            first_present(
                first_value(payload, "record_offset", "source_offset", "offset", "byte_offset"),
                first_value(identity, "record_offset", "source_offset", "offset"),
            )
        )
        key = mft_diff_key(record_number=record_number, path=path, record_offset=record_offset)
        if not key:
            continue
        indexed[key] = {
            "record_number": record_number,
            "sequence_number": sequence_number,
            "parent_reference": parent_reference,
            "file_path": path,
            "timestamp": normalized_diff_value(
                first_value(
                    payload,
                    "timestamp",
                    "modified_at",
                    "created_at",
                    "si_time_created",
                    "created0x10",
                    "fn_time_created",
                    "standard_information_modified",
                )
            ),
            "deleted": normalized_deleted_state(payload),
            "attribute_types": attribute_types,
            "record_offset": record_offset,
            "runlist_decode_status": runlist_status,
            "resident_data_sha256": resident_sha256,
        }
    return indexed


def mft_diff_row_payload(row: Mapping[str, object]) -> Mapping[str, object]:
    details = row.get("details")
    if not isinstance(details, Mapping):
        return row
    payload = dict(details)
    for key, value in row.items():
        if key == "details":
            continue
        payload.setdefault(key, value)
    return payload


def mft_diff_key(*, record_number: str, path: str, record_offset: str) -> str:
    if record_number and path:
        return f"{record_number}|{path}"
    if record_number:
        return record_number
    if path and record_offset:
        return f"{path}|{record_offset}"
    return path or record_offset


def first_present(*values: object) -> object:
    for value in values:
        if value not in (None, ""):
            return value
    return ""


def first_mapping(value: object) -> Mapping[str, object]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            if isinstance(item, Mapping):
                return item
    if isinstance(value, Mapping):
        return value
    return {}


def normalized_diff_list(value: object) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, str):
        parts = [part.strip() for part in re.split(r"[,;|]", value) if part.strip()]
    elif isinstance(value, Sequence):
        parts = [str(item).strip() for item in value if str(item).strip()]
    else:
        parts = [str(value).strip()]
    return "|".join(sorted({normalized_diff_value(part) for part in parts if part}))


def normalized_int_text(value: object) -> str:
    if value in (None, ""):
        return ""
    text = str(value).strip()
    if not text:
        return ""
    try:
        return str(int(text, 0))
    except ValueError:
        return normalized_diff_value(text)


def normalized_deleted_state(row: Mapping[str, object]) -> str:
    deleted_value = first_value(row, "deleted_hint", "deleted", "is_deleted", "isdeleted")
    if deleted_value not in (None, ""):
        return normalize_bool_text(deleted_value)
    in_use_value = first_value(row, "in_use", "inuse", "isinuse", "allocated", "isallocated")
    if in_use_value in (None, ""):
        return ""
    state = normalize_bool_text(in_use_value)
    if state == "true":
        return "false"
    if state == "false":
        return "true"
    return state


def normalize_bool_text(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    text = normalized_diff_value(value)
    if text in {"1", "yes", "y", "deleted", "true"}:
        return "true"
    if text in {"0", "no", "n", "active", "present", "allocated", "inuse", "in use", "false"}:
        return "false"
    return text


def index_usn_rows(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        payload = usn_diff_row_payload(row)
        evidence = payload.get("usn_record_evidence") if isinstance(payload.get("usn_record_evidence"), Mapping) else {}
        identity = evidence.get("record_identity") if isinstance(evidence.get("record_identity"), Mapping) else {}
        file_reference = evidence.get("file_reference_evidence") if isinstance(evidence.get("file_reference_evidence"), Mapping) else {}
        change = evidence.get("change_evidence") if isinstance(evidence.get("change_evidence"), Mapping) else {}
        v4_extent_evidence = change.get("v4_extent_evidence") if isinstance(change.get("v4_extent_evidence"), Mapping) else {}

        usn = normalized_int_text(first_present(first_value(payload, "usn", "usn_number"), first_value(identity, "usn", "usn_number")))
        frn = normalized_int_text(
            first_present(
                first_value(payload, "file_reference_number", "frn", "file_reference", "filereference"),
                first_value(file_reference, "file_reference_number", "frn", "file_reference"),
            )
        )
        parent_reference = normalized_int_text(
            first_present(
                first_value(payload, "parent_file_reference_number", "parent_frn", "parent_reference", "parentfilereference"),
                first_value(file_reference, "parent_file_reference_number", "parent_frn", "parent_reference"),
            )
        )
        name = normalized_diff_value(
            first_present(
                first_value(payload, "file_name", "filename", "name", "file_path", "path"),
                first_value(file_reference, "file_name", "filename", "name", "file_path", "path"),
            )
        )
        record_cursor = normalized_int_text(
            first_present(
                first_value(payload, "record_cursor", "record_offset", "offset", "byte_offset"),
                first_value(identity, "record_cursor", "record_offset", "offset"),
            )
        )
        key = usn_diff_key(usn=usn, frn=frn, name=name, record_cursor=record_cursor)
        if not key:
            continue
        indexed[key] = {
            "usn": usn,
            "file_reference_number": frn,
            "parent_reference": parent_reference,
            "file_name": name,
            "reason": normalized_diff_list(
                first_present(
                    first_value(payload, "reason", "reason_flags", "usn_reason", "reasonflags"),
                    first_value(change, "reason", "reason_flags", "usn_reason", "reasonflags"),
                )
            ),
            "timestamp": normalized_diff_value(first_value(payload, "timestamp", "event_time", "time_created")),
            "major_version": normalized_int_text(first_present(first_value(payload, "major_version", "major"), first_value(identity, "major_version", "major"))),
            "source_info": normalized_diff_list(
                first_present(
                    first_value(payload, "source_info_flags", "source_info", "sourceinfo"),
                    first_value(change, "source_info_flags", "source_info", "sourceinfo"),
                )
            ),
            "file_attributes": normalized_diff_list(
                first_present(
                    first_value(payload, "file_attribute_names", "file_attributes", "attributes"),
                    first_value(change, "file_attribute_names", "file_attributes", "attributes"),
                )
            ),
            "record_cursor": record_cursor,
            "v4_extent_count": normalized_int_text(
                first_present(
                    first_value(payload, "v4_extent_count", "extent_count", "extentcount"),
                    first_value(v4_extent_evidence, "extent_count", "v4_extent_count", "extentcount"),
                )
            ),
        }
    return indexed


def index_usn_state_replay_rows(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        for transition in iter_usn_state_replay_rows(row):
            frn = normalized_int_text(first_value(transition, "file_reference_number", "frn", "file_reference"))
            cursor = normalized_int_text(first_value(transition, "record_cursor", "record_offset", "offset", "byte_offset"))
            usn = normalized_int_text(first_value(transition, "usn", "usn_number"))
            transition_name = normalized_diff_value(first_value(transition, "transition", "transition_type", "state_transition"))
            timestamp = normalized_diff_value(first_value(transition, "timestamp", "event_time", "time_created"))
            previous_path = normalized_diff_value(first_value(transition, "previous_path", "old_path", "source_path"))
            new_path = normalized_diff_value(first_value(transition, "new_path", "path_candidate", "target_path"))
            file_name = normalized_diff_value(first_value(transition, "file_name", "filename", "name"))
            key = usn_state_replay_diff_key(
                usn=usn,
                cursor=cursor,
                frn=frn,
                transition=transition_name,
                previous_path=previous_path,
                new_path=new_path,
                file_name=file_name,
            )
            if not key:
                continue
            indexed[key] = {
                "usn": usn,
                "record_cursor": cursor,
                "file_reference_number": frn,
                "transition": transition_name,
                "timestamp": timestamp,
                "previous_path": previous_path,
                "new_path": new_path,
                "file_name": file_name,
                "state_effect": normalized_diff_value(first_value(transition, "state_effect", "effect")),
            }
    return indexed


def iter_usn_state_replay_rows(row: Mapping[str, object]) -> Iterable[Mapping[str, object]]:
    payload = usn_diff_row_payload(row)
    replay = (
        payload.get("usn_replay_inventory_profile")
        if isinstance(payload.get("usn_replay_inventory_profile"), Mapping)
        else {}
    )
    state_preview = (
        replay.get("bounded_state_replay_preview")
        if isinstance(replay.get("bounded_state_replay_preview"), Mapping)
        else payload.get("bounded_state_replay_preview")
        if isinstance(payload.get("bounded_state_replay_preview"), Mapping)
        else {}
    )
    transitions = state_preview.get("transitions") if isinstance(state_preview, Mapping) else None
    if isinstance(transitions, Sequence) and not isinstance(transitions, (str, bytes, bytearray)):
        for transition in transitions:
            if isinstance(transition, Mapping):
                yield transition
        return
    if first_value(payload, "transition", "transition_type", "state_transition"):
        yield payload


def usn_state_replay_diff_key(
    *,
    usn: str,
    cursor: str,
    frn: str,
    transition: str,
    previous_path: str,
    new_path: str,
    file_name: str,
) -> str:
    if usn and frn and transition:
        return f"{usn}|{frn}|{transition}"
    if cursor and frn and transition:
        return f"{cursor}|{frn}|{transition}"
    if transition and (previous_path or new_path):
        return "|".join(item for item in (transition, previous_path, new_path) if item)
    return "|".join(item for item in (frn, transition, file_name, cursor) if item)


def usn_diff_row_payload(row: Mapping[str, object]) -> Mapping[str, object]:
    details = row.get("details")
    if not isinstance(details, Mapping):
        return row
    payload = dict(details)
    for key, value in row.items():
        if key == "details":
            continue
        payload.setdefault(key, value)
    return payload


def usn_diff_key(*, usn: str, frn: str, name: str, record_cursor: str) -> str:
    if usn and frn and name:
        return f"{usn}|{frn}|{name}"
    if usn and frn:
        return f"{usn}|{frn}"
    if record_cursor and frn:
        return f"{record_cursor}|{frn}"
    return "|".join(item for item in (usn, frn, name, record_cursor) if item)


def build_ntfs_trusted_diff(
    rapid_index: Mapping[str, Mapping[str, str]],
    trusted_index: Mapping[str, Mapping[str, str]],
    *,
    trusted_tool: str,
    recognized_tools: set[str],
    mode: str,
    blocker: str,
    key_label: str,
) -> dict[str, object]:
    recognized_names = {item.replace(" ", "").lower() for item in recognized_tools}
    recognized = trusted_tool.strip().lower().replace(" ", "") in recognized_names
    common = sorted(set(rapid_index) & set(trusted_index))
    missing = sorted(set(rapid_index) - set(trusted_index))
    extra = sorted(set(trusted_index) - set(rapid_index))
    mismatches: list[dict[str, object]] = []
    for key in common:
        for field, rapid_value in rapid_index[key].items():
            trusted_value = trusted_index[key].get(field, "")
            if rapid_value and trusted_value and rapid_value != trusted_value:
                mismatches.append(
                    {
                        key_label: key,
                        "field": field,
                        "rapid_value": rapid_value,
                        "trusted_value": trusted_value,
                    }
                )
                break
    status = "pass" if recognized and common and not missing and not extra and not mismatches else "diffs-present"
    return {
        "mode": mode,
        "status": status,
        "trusted_tool": trusted_tool,
        "trusted_tool_recognized": recognized,
        "rapid_indexed_count": len(rapid_index),
        "trusted_indexed_count": len(trusted_index),
        "matched_count": len(common) - len(mismatches),
        "mismatch_count": len(mismatches),
        "missing_in_trusted_count": len(missing),
        "extra_in_trusted_count": len(extra),
        "mismatches": mismatches[:25],
        "missing_in_trusted_sample": missing[:25],
        "extra_in_trusted_sample": extra[:25],
        "commercial_grade_evidence": status == "pass",
        "reportability_decision": {
            "decision": "trusted-diff-passed" if status == "pass" else "do-not-use-native-output-as-final",
            "blockers": [] if status == "pass" else [blocker],
        },
    }


def normalized_diff_value(value: object) -> str:
    return " ".join(str(value or "").strip().lower().replace("\\", "/").split())


def first_value(row: Mapping[str, object], *keys: str) -> object:
    normalized = {normalize_key(key): value for key, value in row.items()}
    for key in keys:
        value = normalized.get(normalize_key(key))
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
                    "attribute_list_entries": attributes["attribute_list_entries"],
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
                        "has_attribute_list_attribute": bool(attributes["attribute_list_entries"])
                        or "$ATTRIBUTE_LIST" in attributes["attribute_types"],
                        "has_nonresident_data_attribute": any(
                            isinstance(item, Mapping) and item.get("resident") is False
                            for item in attributes["data_attributes"]
                        ),
                        "has_nonresident_runlist_preview": any(
                            isinstance(item, Mapping) and bool(item.get("runlist_preview"))
                            for item in attributes["data_attributes"]
                        ),
                        "has_decoded_nonresident_runlist": any(
                            isinstance(item, Mapping)
                            and str(item.get("runlist_decode_status") or "").startswith("decoded-preview")
                            for item in attributes["data_attributes"]
                        ),
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
    attribute_list_entries: list[dict[str, object]] = []
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
        elif parsed["attribute_type"] == 0x20 and isinstance(parsed.get("attribute_list"), Mapping):
            attribute_list_entries.extend(list(parsed["attribute_list"].get("entries") or []))
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
        "attribute_list_entries": attribute_list_entries,
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
        runlist_blob = (
            attribute_blob[runlist_offset : min(len(attribute_blob), runlist_offset + MFT_RUNLIST_PREVIEW_BYTE_LIMIT)]
            if runlist_offset < len(attribute_blob)
            else b""
        )
        runlist_decode = decode_mft_runlist(runlist_blob)
        parsed["nonresident_metadata"] = {
            "lowest_vcn": int_from(attribute_blob, 16, 8),
            "highest_vcn": int_from(attribute_blob, 24, 8),
            "runlist_offset": runlist_offset,
            "compression_unit": int_from(attribute_blob, 34, 2),
            "allocated_size": int_from(attribute_blob, 40, 8),
            "real_size": int_from(attribute_blob, 48, 8),
            "initialized_size": int_from(attribute_blob, 56, 8),
            "data_runs_preview": runlist_blob[:32].hex(),
            "runlist_decode_status": runlist_decode["status"],
            "runlist_decode": runlist_decode,
        }
        if attribute_type == 0x80:
            parsed["data"] = {
                "resident": False,
                "allocated_size": int_from(attribute_blob, 40, 8),
                "real_size": int_from(attribute_blob, 48, 8),
                "initialized_size": int_from(attribute_blob, 56, 8),
                "runlist_offset": runlist_offset,
                "runlist_preview": list(runlist_decode["runs"]),
                "runlist_decode_status": runlist_decode["status"],
                "runlist_warning_count": len(runlist_decode["warnings"]),
                "runlist_consumed_bytes": runlist_decode["consumed_bytes"],
                "runlist_preview_bytes": runlist_decode["preview_bytes"],
                "runlist_terminator_offset": runlist_decode["terminator_offset"],
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
    elif attribute_type == 0x20:
        parsed["attribute_list"] = parse_attribute_list_attribute(value)
    elif attribute_type == 0x30:
        parsed["file_name"] = parse_file_name_attribute(value)
    elif attribute_type == 0x80:
        sha256 = hashlib.sha256(value).hexdigest() if value else ""
        parsed["data"] = {
            "resident": True,
            "resident_size": value_length,
            "sha256": sha256,
            "resident_data_hashes": {"sha256": sha256} if sha256 else {},
            "runlist_decode_status": "resident-data-no-runlist",
        }
    return parsed


def parse_attribute_list_attribute(value: bytes) -> dict[str, object]:
    entries: list[dict[str, object]] = []
    warnings: list[str] = []
    offset = 0
    while offset + 26 <= len(value) and len(entries) < 256:
        attribute_type = int_from(value, offset, 4)
        entry_length = int_from(value, offset + 4, 2)
        name_length = int_from(value, offset + 6, 1)
        name_offset = int_from(value, offset + 7, 1)
        if attribute_type == 0 or entry_length == 0:
            break
        if entry_length < 26:
            warnings.append(f"invalid-attribute-list-entry-length:{offset}")
            break
        if offset + entry_length > len(value):
            warnings.append(f"attribute-list-entry-overruns-value:{offset}")
            break
        name = ""
        absolute_name_offset = offset + name_offset
        absolute_name_end = absolute_name_offset + name_length * 2
        if name_length and absolute_name_end <= offset + entry_length:
            name = value[absolute_name_offset:absolute_name_end].decode("utf-16le", errors="ignore")
        extension_reference_raw = int_from(value, offset + 16, 8)
        entries.append(
            {
                "entry_index": len(entries),
                "entry_offset": offset,
                "attribute_type": attribute_type,
                "attribute_type_name": MFT_ATTRIBUTE_TYPE_NAMES.get(attribute_type, f"0x{attribute_type:08x}"),
                "entry_length": entry_length,
                "name": name,
                "lowest_vcn": int_from(value, offset + 8, 8),
                "extension_reference_raw": extension_reference_raw,
                "extension_reference_decoded": split_mft_reference(extension_reference_raw),
                "attribute_id": int_from(value, offset + 24, 2),
                "requires_extension_record_resolution": bool(extension_reference_raw),
            }
        )
        offset += align8(entry_length)
    if len(entries) >= 256:
        warnings.append("attribute-list-entry-limit-reached")
    return {
        "status": "decoded" if entries and not warnings else "decoded-with-warnings" if entries else "empty",
        "entries": entries,
        "entry_count": len(entries),
        "warnings": warnings,
        "resolved": False,
        "resolution_status": "extension-record-resolution-not-implemented",
    }


def decode_mft_runlist(
    blob: bytes,
    *,
    run_limit: int = MFT_RUNLIST_PREVIEW_RUN_LIMIT,
) -> dict[str, object]:
    runs: list[dict[str, object]] = []
    warnings: list[str] = []
    offset = 0
    absolute_lcn = 0
    terminator_offset: int | None = None
    preview = blob[:MFT_RUNLIST_PREVIEW_BYTE_LIMIT]
    while offset < len(preview) and len(runs) < run_limit:
        header = preview[offset]
        if header == 0:
            terminator_offset = offset
            offset += 1
            break
        length_size = header & 0x0F
        lcn_delta_size = (header >> 4) & 0x0F
        value_offset = offset + 1
        value_end = value_offset + length_size + lcn_delta_size
        if length_size == 0:
            warnings.append(f"missing-run-length-field:{offset}")
            break
        if length_size > 8 or lcn_delta_size > 8:
            warnings.append(f"oversized-run-field:{offset}")
            break
        if value_end > len(preview):
            warnings.append(f"run-overruns-preview:{offset}")
            break
        cluster_count = int.from_bytes(preview[value_offset : value_offset + length_size], "little", signed=False)
        delta_blob = preview[value_offset + length_size : value_end]
        sparse = lcn_delta_size == 0
        lcn_delta = 0 if sparse else int.from_bytes(delta_blob, "little", signed=True)
        if not sparse:
            absolute_lcn += lcn_delta
        if cluster_count == 0:
            warnings.append(f"zero-cluster-run:{offset}")
        if not sparse and absolute_lcn < 0:
            warnings.append(f"negative-absolute-lcn:{offset}")
        runs.append(
            {
                "run_index": len(runs),
                "header_offset": offset,
                "header_byte": header,
                "length_field_size": length_size,
                "lcn_delta_field_size": lcn_delta_size,
                "cluster_count": cluster_count,
                "lcn_delta": lcn_delta,
                "absolute_lcn": None if sparse else absolute_lcn,
                "sparse": sparse,
                "valid": cluster_count > 0 and (sparse or absolute_lcn >= 0),
            }
        )
        offset = value_end
    if len(runs) >= run_limit and terminator_offset is None:
        warnings.append("run-limit-reached")
    if terminator_offset is None and offset >= len(preview) and preview:
        warnings.append("runlist-terminator-not-seen-in-preview")
    if not preview:
        status = "missing"
    elif runs and not warnings:
        status = "decoded-preview"
    elif runs:
        status = "decoded-preview-with-warnings"
    else:
        status = "invalid-preview"
    return {
        "status": status,
        "runs": runs,
        "run_count": len(runs),
        "warnings": warnings,
        "terminator_offset": terminator_offset,
        "consumed_bytes": offset,
        "preview_bytes": len(preview),
        "preview_sha256": hashlib.sha256(preview).hexdigest() if preview else "",
    }


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


MFT_TIMESTAMP_STOMPING_FIELDS = ("created_at", "modified_at", "mft_modified_at", "accessed_at")


def mft_timestamp_stomping_analysis(
    standard_information: Mapping[str, object],
    file_name_entries: Sequence[object],
) -> dict[str, object]:
    """Compare NTFS $STANDARD_INFORMATION and $FILE_NAME times as a triage anti-forensics signal."""

    si_timestamps = (
        standard_information.get("timestamps") if isinstance(standard_information.get("timestamps"), Mapping) else {}
    )
    file_name_samples: list[dict[str, object]] = []
    mismatches: list[dict[str, object]] = []
    for index, entry in enumerate(file_name_entries[:10]):
        if not isinstance(entry, Mapping):
            continue
        fn_timestamps = entry.get("timestamps") if isinstance(entry.get("timestamps"), Mapping) else {}
        sample = {
            "index": index,
            "file_name": str(entry.get("file_name") or ""),
            "namespace": str(entry.get("namespace") or ""),
            "timestamps": dict(fn_timestamps),
        }
        file_name_samples.append(sample)
        for field in MFT_TIMESTAMP_STOMPING_FIELDS:
            si_value = str(si_timestamps.get(field) or "")
            fn_value = str(fn_timestamps.get(field) or "")
            if si_value and fn_value and si_value != fn_value:
                mismatches.append(
                    {
                        "field": field,
                        "standard_information": si_value,
                        "file_name": fn_value,
                        "file_name_index": index,
                        "file_name_value": sample["file_name"],
                        "file_name_namespace": sample["namespace"],
                    }
                )
    suspected = bool(mismatches)
    coverage_status = (
        "sia-fna-mismatch-detected"
        if suspected
        else "sia-fna-compared"
        if si_timestamps and file_name_samples
        else "insufficient-sia-fna-timestamps"
    )
    risk_flags = ["mft-sia-fna-timestamp-mismatch", "time-stomping-suspected"] if suspected else []
    return {
        "profile_version": "mft-timestamp-stomping-analysis-v1",
        "coverage_status": coverage_status,
        "suspected": suspected,
        "mismatch_count": len(mismatches),
        "mismatches": mismatches[:50],
        "standard_information_timestamps": dict(si_timestamps),
        "file_name_timestamp_samples": file_name_samples,
        "risk_flags": risk_flags,
        "validation_required": suspected,
        "reportability": "triage",
        "not_proof_of": [
            "intentional timestamp manipulation without corroborating timeline evidence",
            "file content creation time",
        ],
        "correlation_targets": ["$UsnJrnl", "$LogFile", "Prefetch", "LNK", "JumpList"],
        "validation_guidance": "Treat $STANDARD_INFORMATION/$FILE_NAME timestamp divergence as an anti-forensics lead. Corroborate with USN, $LogFile, execution artifacts, and trusted tools before final reporting.",
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "usn-logfile-execution-artifact-correlation-required",
            "trusted-mft-parser-diff-required",
        ],
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
    if length < 60 or length > 65536 or offset + length > len(blob) or major not in {2, 3, 4}:
        return None
    record_blob = blob[offset : offset + length]
    if major == 4:
        return parse_usn_v4_record(record_blob, offset)
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


def parse_usn_v4_record(record_blob: bytes, offset: int) -> dict[str, object] | None:
    length = int_from(record_blob, 0, 4)
    if length < 64:
        return None
    record_end_offset = offset + length
    reason = int_from(record_blob, 48, 4)
    source_info = int_from(record_blob, 52, 4)
    remaining_extents = int_from(record_blob, 56, 4)
    extent_count = int_from(record_blob, 60, 2)
    extent_size = int_from(record_blob, 62, 2)
    extent_table_offset = 64
    expected_extent_bytes = extent_count * extent_size
    extent_bounds_valid = (
        extent_size >= 16
        and extent_table_offset + expected_extent_bytes <= length
        and extent_count <= USN_V4_EXTENT_PREVIEW_LIMIT
    )
    extents: list[dict[str, object]] = []
    if extent_size >= 16:
        for extent_index in range(min(extent_count, USN_V4_EXTENT_PREVIEW_LIMIT)):
            extent_offset = extent_table_offset + extent_index * extent_size
            if extent_offset + 16 > length:
                break
            extents.append(
                {
                    "extent_index": extent_index,
                    "source_offset": offset + extent_offset,
                    "file_offset": int_from(record_blob, extent_offset, 8),
                    "byte_length": int_from(record_blob, extent_offset + 8, 8),
                }
            )
    reason_flag_names = reason_flags(reason)
    unknown_reason_mask = unknown_flag_mask(reason, USN_REASON_FLAGS)
    unknown_source_info_mask = unknown_flag_mask(source_info, USN_SOURCE_INFO_FLAGS)
    validation_warnings: list[str] = []
    if length % 8:
        validation_warnings.append("record-length-not-8-byte-aligned")
    if extent_size < 16:
        validation_warnings.append("v4-extent-size-too-small")
    if extent_table_offset + expected_extent_bytes > length:
        validation_warnings.append("v4-extents-overrun-record")
    if extent_count > USN_V4_EXTENT_PREVIEW_LIMIT:
        validation_warnings.append("v4-extent-preview-limit-reached")
    if reason and not reason_flag_names:
        validation_warnings.append("unknown-reason-flags")
    if unknown_reason_mask:
        validation_warnings.append("reason-has-unknown-bits")
    if reason == 0:
        validation_warnings.append("empty-reason")
    validation_status = "valid" if not validation_warnings else "valid-with-warnings"
    return {
        "record_offset": offset,
        "record_cursor": offset,
        "next_record_cursor": record_end_offset,
        "record_end_offset": record_end_offset,
        "record_length": length,
        "record_payload_bytes": extent_table_offset + len(extents) * extent_size,
        "record_padding_bytes": max(length - (extent_table_offset + len(extents) * extent_size), 0),
        "record_size_class": usn_record_size_class(length),
        "major_version": 4,
        "minor_version": int_from(record_blob, 6, 2),
        "file_reference_number": int_from(record_blob, 8, 16),
        "parent_file_reference_number": int_from(record_blob, 24, 16),
        "file_reference_number_decoded": decode_usn_file_reference(int_from(record_blob, 8, 16), 16),
        "parent_file_reference_number_decoded": decode_usn_file_reference(int_from(record_blob, 24, 16), 16),
        "usn": int_from(record_blob, 40, 8),
        "timestamp": "",
        "timestamp_filetime": 0,
        "reason": reason_string(reason),
        "reason_raw": reason,
        "reason_flags": reason_flag_names,
        "unknown_reason_mask": unknown_reason_mask,
        "source_info": source_info,
        "source_info_flags": flag_names(source_info, USN_SOURCE_INFO_FLAGS),
        "unknown_source_info_mask": unknown_source_info_mask,
        "security_id": 0,
        "file_attributes": 0,
        "file_attribute_names": [],
        "unknown_file_attribute_mask": 0,
        "file_name_length": 0,
        "file_name_offset": 0,
        "file_name_character_count": 0,
        "file_name_decode_status": "not-present-usn-v4",
        "file_name": "",
        "deleted_hint": "FILE_DELETE" in reason_flag_names,
        "rename_hint": rename_hint(reason_flag_names),
        "v4_remaining_extents": remaining_extents,
        "v4_extent_count": extent_count,
        "v4_extent_size": extent_size,
        "v4_extent_preview_limit": USN_V4_EXTENT_PREVIEW_LIMIT,
        "v4_extents": extents,
        "validation_status": validation_status,
        "validation_warnings": validation_warnings,
        "validation_checks": {
            "record_length_aligned": length % 8 == 0,
            "record_cursor_progresses": record_end_offset > offset,
            "filename_bounds_valid": True,
            "filename_utf16_valid": True,
            "filetime_plausible": True,
            "version_supported": True,
            "v4_extent_bounds_valid": extent_bounds_valid,
            "v4_extent_count_matches": len(extents) == min(extent_count, USN_V4_EXTENT_PREVIEW_LIMIT),
            "v4_no_filename_by_design": True,
            "known_reason_bits_only": unknown_reason_mask == 0,
            "large_record": length >= USN_LARGE_RECORD_THRESHOLD,
        },
        "parser_confidence": 0.82 if validation_status == "valid" else 0.68,
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


def extract_mixed_strings(blob: bytes, *, limit: int = 250) -> list[str]:
    strings: list[str] = []
    seen: set[str] = set()
    for value in [*extract_ascii_strings(blob), *extract_utf16_strings(blob)]:
        cleaned = " ".join(value.split()).strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        strings.append(cleaned)
        if len(strings) >= limit:
            break
    return strings


def extract_ascii_strings(blob: bytes, *, min_chars: int = 5, limit: int = 250) -> list[str]:
    strings: list[str] = []
    current = bytearray()
    for byte in blob:
        if 32 <= byte <= 126:
            current.append(byte)
            continue
        if len(current) >= min_chars:
            decoded = current.decode("ascii", errors="ignore").strip()
            if decoded and decoded not in strings:
                strings.append(decoded)
                if len(strings) >= limit:
                    return strings
        current.clear()
    if len(current) >= min_chars:
        decoded = current.decode("ascii", errors="ignore").strip()
        if decoded and decoded not in strings:
            strings.append(decoded)
    return strings


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
