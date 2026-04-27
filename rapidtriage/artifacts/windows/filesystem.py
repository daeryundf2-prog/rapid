from __future__ import annotations

import csv
import datetime as dt
import hashlib
import json
import re
from pathlib import Path
from typing import Iterable, Mapping

from ...core.models import ArtifactRecord

PARSER_VERSION = "windows-filesystem-v4"
SUPPORTED_SUFFIXES = {".csv", ".json", ".jsonl", ".ndjson"}
MFT_HINTS = ("mft", "mftexcmd", "$mft")
USN_HINTS = ("usn", "usnjrnl", "$j")
NATIVE_SCAN_LIMIT = 16 * 1024 * 1024
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
            "record_header_samples": mft_records[:50],
            "extracted_string_count": len(strings),
            "path_candidates": path_candidates[:50],
            "recommended_parsers": ["MFTECmd", "analyzeMFT", "The Sleuth Kit/fls-icat"],
            "note": "Native $MFT is inventoried with bounded record-header and string pivots; use a dedicated parser for full attribute decoding.",
        },
    )


def build_usn_journal_inventory_record(path: Path) -> ArtifactRecord:
    stat_result = path.stat()
    blob = read_prefix(path, NATIVE_SCAN_LIMIT)
    records = parse_usn_records(blob)
    strings = extract_utf16_strings(blob)
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
            "native_record_count": len(records),
            "record_validation_counts": count_values(record.get("validation_status") for record in records),
            "record_version_counts": count_values(str(record.get("major_version") or "") for record in records),
            "reason_flag_counts": count_many(record.get("reason_flags") for record in records),
            "record_samples": records[:50],
            "extracted_string_count": len(strings),
            "recommended_parsers": ["MFTECmd", "UsnJrnl2Csv", "The Sleuth Kit"],
            "note": "Native USN records are decoded when bounded v2/v3 record structures are recoverable; validation counts summarize structural and timestamp confidence. Validate critical timelines with a dedicated parser.",
        },
    )


def build_native_mft_record(path: Path, record: Mapping[str, object], index: int) -> ArtifactRecord:
    path_candidates = list(record.get("path_candidates") or [])
    file_path = str(path_candidates[0]) if path_candidates else ""
    details = {
        "parser": "windows-mft-native",
        "parser_version": PARSER_VERSION,
        "coverage_status": "native-file-record-header",
        "reportability": "triage",
        "source_path": str(path.resolve()),
        "source_format": "ntfs-mft",
        "source_hashes": file_hashes(path),
        "source_index": index,
        "artifact_family": "mft",
        "record_number": str(record.get("record_number_candidate", "")),
        "parent_reference": "",
        "file_path": file_path,
        "path_candidates": path_candidates[:10],
        "timestamp": "",
        "timestamp_source": "not_available_native_header_scan",
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
        "parser_confidence": 0.55,
        "evidence_strength": "ntfs-mft-file-record-header",
        "validation_required": True,
        "validation_guidance": "Native MFT rows decode bounded FILE record headers and nearby path strings only; validate full attributes, parent paths, and timestamps with MFTECmd/analyzeMFT before final testimony.",
        "raw": dict(record),
        "raw_preview": json.dumps(record, ensure_ascii=False, sort_keys=True)[:2000],
    }
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
        "record_offset": record.get("record_offset", 0),
        "record_length": record.get("record_length", 0),
        "major_version": record.get("major_version", 0),
        "minor_version": record.get("minor_version", 0),
        "validation_status": str(record.get("validation_status") or "unknown"),
        "validation_warnings": list(record.get("validation_warnings") or []),
        "parser_confidence": record.get("parser_confidence", 0.0),
        "evidence_strength": "ntfs-usn-native-record",
        "validation_required": True,
        "validation_guidance": "Native USN rows validate record layout, length, name bounds, version, and FILETIME plausibility, but critical timelines should still be cross-checked with MFTECmd/UsnJrnl2Csv or another dedicated parser.",
        "raw": dict(record),
        "raw_preview": json.dumps(record, ensure_ascii=False, sort_keys=True)[:2000],
    }
    return ArtifactRecord(
        provider=WindowsFilesystemProvider.name,
        artifact_type="usn-record",
        path=str(path.resolve()),
        supported=True,
        details=details,
    )


def artifact_family(path: Path) -> str:
    lowered = str(path).lower()
    if any(hint in lowered for hint in MFT_HINTS):
        return "mft"
    if any(hint in lowered for hint in USN_HINTS):
        return "usn"
    return ""


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
    return ArtifactRecord(
        provider=WindowsFilesystemProvider.name,
        artifact_type=artifact_type,
        path=str(path.resolve()),
        supported=True,
        details=details,
    )


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
            records.append(
                {
                    "record_offset": offset,
                    "record_number_candidate": offset // 1024,
                    "sequence_number": int_from(blob, offset + 0x10, 2),
                    "hard_link_count": int_from(blob, offset + 0x12, 2),
                    "first_attribute_offset": int_from(blob, offset + 0x14, 2),
                    "flags": flags,
                    "in_use": bool(flags & 0x01),
                    "directory": bool(flags & 0x02),
                    "used_size": int_from(blob, offset + 0x18, 4),
                    "allocated_size": allocated_size,
                    "base_file_reference": int_from(blob, offset + 0x20, 8),
                    "path_candidates": path_candidates[:10],
                }
            )
        offset += 4
        if len(records) >= 5000:
            return records


def parse_usn_records(blob: bytes) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    offset = 0
    while offset + 60 <= len(blob):
        record = parse_usn_record_at(blob, offset)
        if record is None:
            offset += 1
            continue
        records.append(record)
        offset += int(record["record_length"])
        if len(records) >= 5000:
            return records
    return records


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
    validation_warnings = usn_validation_warnings(
        length=length,
        name_length=name_length,
        name_offset=name_offset,
        major=major,
        timestamp=timestamp,
        reason=reason,
        reason_flag_names=reason_flag_names,
    )
    validation_status = "valid" if not validation_warnings else "valid-with-warnings"
    parser_confidence = 0.85 if validation_status == "valid" else 0.7
    return {
        "record_offset": offset,
        "record_length": length,
        "major_version": major,
        "minor_version": int_from(record_blob, 6, 2),
        "file_reference_number": int_from(record_blob, int(layout["file_reference_offset"]), int(layout["reference_size"])),
        "parent_file_reference_number": int_from(record_blob, int(layout["parent_reference_offset"]), int(layout["reference_size"])),
        "usn": int_from(record_blob, int(layout["usn_offset"]), 8),
        "timestamp": timestamp,
        "timestamp_filetime": filetime_value,
        "reason": reason_string(reason),
        "reason_raw": reason,
        "reason_flags": reason_flag_names,
        "source_info": source_info,
        "source_info_flags": flag_names(source_info, USN_SOURCE_INFO_FLAGS),
        "security_id": int_from(record_blob, int(layout["security_id_offset"]), 4),
        "file_attributes": file_attributes,
        "file_attribute_names": flag_names(file_attributes, NTFS_FILE_ATTRIBUTE_NAMES),
        "file_name_length": name_length,
        "file_name_offset": name_offset,
        "file_name": record_blob[name_offset : name_offset + name_length].decode("utf-16le", errors="ignore"),
        "deleted_hint": "FILE_DELETE" in reason_flag_names,
        "rename_hint": rename_hint(reason_flag_names),
        "validation_status": validation_status,
        "validation_warnings": validation_warnings,
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
    if reason == 0:
        warnings.append("empty-reason")
    return warnings


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
