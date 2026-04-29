from __future__ import annotations

import csv
import hashlib
import json
import re
from collections import Counter
from pathlib import Path, PureWindowsPath
from typing import Iterable, Mapping, Sequence

from ...core.models import ArtifactRecord
from .ese import build_ese_string_pivots, probe_ese_database

PARSER_VERSION = "windows-search-index-import-v5"
SEARCH_EDB_PATH = ("ProgramData", "Microsoft", "Search", "Data", "Applications", "Windows", "Windows.edb")
SUPPORTED_EXPORT_SUFFIXES = {".csv", ".json", ".jsonl", ".ndjson"}
EXPORT_HINTS = ("windows.edb", "windows-search", "searchindex", "search-index", "edbexport", "winsearch")
WINDOWS_SEARCH_EDB_BLOCKERS = [
    "native-ese-catalog-decoding-required",
    "windows-search-table-schema-decoding-required",
    "row-level-path-url-content-decoding-required",
    "row-level-timestamp-and-deleted-state-validation-required",
]
WINDOWS_SEARCH_CAPABILITIES = {
    "csv_json_export_import": True,
    "ese_header_probe": True,
    "native_string_pivots": True,
    "table_family_marker_detection": True,
    "content_candidate_string_scan": True,
    "native_ese_catalog_decode": False,
    "native_table_schema_decode": False,
    "native_row_level_decode": False,
    "native_deleted_state_decode": False,
    "native_timestamp_decode": False,
}
WINDOWS_SEARCH_TABLE_MARKERS = {
    "gather-path": ("systemindex_gthrpth", "gthrpth", "scope", "crawl", "file:"),
    "gather-record": ("systemindex_gthr", "workid", "documentid", "docid", "itemurl"),
    "property-store": (
        "systemindex_propertystore",
        "system.itempathdisplay",
        "system.filename",
        "system.size",
        "system.datemodified",
    ),
    "content-index": ("system.search.contents", "contents", "inverted", "phrase"),
    "deleted-state": ("isdeleted", "deleted", "tombstone", "status", "crawlstatus"),
}


class WindowsSearchIndexProvider:
    name = "windows-search-index"
    collector_kind = "windows-search-index"
    description = "Windows Search index EDB inventory and CSV/JSON export imports"
    target_platform = "windows"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        records: list[ArtifactRecord] = []
        seen: set[Path] = set()
        edb_path = root.joinpath(*SEARCH_EDB_PATH)
        if edb_path.is_file():
            inventory = build_edb_inventory_record(edb_path)
            records.append(inventory)
            records.extend(build_edb_pivot_records(edb_path, inventory.details))
            records.extend(build_edb_table_candidate_records(edb_path, inventory.details))
            seen.add(edb_path.resolve())

        for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
            if not path.is_file():
                continue
            resolved = path.resolve()
            if resolved in seen:
                continue
            lowered = str(path.relative_to(root)).lower()
            if path.name.lower() == "windows.edb":
                inventory = build_edb_inventory_record(path)
                records.append(inventory)
                records.extend(build_edb_pivot_records(path, inventory.details))
                records.extend(build_edb_table_candidate_records(path, inventory.details))
                seen.add(resolved)
                continue
            if path.suffix.lower() not in SUPPORTED_EXPORT_SUFFIXES or not any(hint in lowered for hint in EXPORT_HINTS):
                continue
            rows = iter_csv_rows(path) if path.suffix.lower() == ".csv" else iter_json_rows(path)
            source_hashes = file_hashes(path)
            for index, row in enumerate(rows):
                records.append(build_search_index_entry(path, row, index, source_hashes))

        yield from records
        summary = build_search_index_summary(root, records)
        if summary is not None:
            yield summary


def build_edb_inventory_record(path: Path) -> ArtifactRecord:
    stat_result = path.stat()
    ese_header = probe_ese_database(path)
    pivots = build_ese_string_pivots(path)
    content_candidates = build_search_content_candidates(pivots)
    table_families = detect_search_table_families(pivots)
    coverage_status = "ese-header-string-scan" if ese_header.get("header_readable") else "detected"
    validation_checks = {
        "ese_header_readable": bool(ese_header.get("header_readable")),
        "ese_signature_valid": bool(ese_header.get("signature_valid")),
        "has_path_pivots": bool(pivots.get("path_candidates")),
        "has_url_pivots": bool(pivots.get("url_candidates")),
        "has_content_candidates": bool(content_candidates),
        "has_table_family_candidates": bool(table_families),
        "ese_catalog_decoded": False,
        "row_level_decoding_available": False,
        "timestamps_decoded_from_native_rows": False,
        "deleted_state_decoded_from_native_rows": False,
        "requires_windows_search_parser": True,
    }
    report_grade = search_index_report_grade_assessment(
        search_index_validation_matrix(validation_checks),
        validation_required=True,
        extra_blockers=WINDOWS_SEARCH_EDB_BLOCKERS,
    )
    return ArtifactRecord(
        provider=WindowsSearchIndexProvider.name,
        artifact_type="windows-search-edb-file",
        path=str(path.resolve()),
        supported=False,
        details={
            "parser": "windows-search-edb-inventory",
            "parser_version": PARSER_VERSION,
            "coverage_status": coverage_status,
            "reportability": "inventory-only",
            "source_path": str(path.resolve()),
            "source_format": "ese-edb",
            "source_hashes": file_hashes(path),
            "size": stat_result.st_size,
            "modified_at": stat_result.st_mtime,
            "ese_header": ese_header,
            "parser_confidence": 0.65 if ese_header.get("signature_valid") else 0.35,
            "evidence_strength": "search-index-database-presence",
            **pivots,
            "content_candidates": content_candidates,
            "native_candidate_metadata": {
                "path_candidate_count": len(pivots.get("path_candidates") or []),
                "url_candidate_count": len(pivots.get("url_candidates") or []),
                "content_candidate_count": len(content_candidates),
                "table_candidate_families": table_families,
                "table_candidate_count": len(table_families),
                "string_scan_bytes": int(pivots.get("string_scan_bytes") or 0),
            },
            "native_validation": {
                "header_signature_valid": bool(ese_header.get("signature_valid")),
                "page_size_detected": int(ese_header.get("page_size") or 0),
                "bounded_string_scan_only": True,
                "ese_catalog_decoded": False,
                "row_level_decoding_available": False,
                "path_url_content_candidates_only": True,
                "timestamps_decoded_from_native_rows": False,
                "deleted_state_decoded_from_native_rows": False,
            },
            "validation_required": True,
            "validation_checks": validation_checks,
            "search_index_validation_matrix": search_index_validation_matrix(validation_checks),
            "search_index_report_grade_assessment": report_grade,
            "search_index_native_capabilities": WINDOWS_SEARCH_CAPABILITIES,
            "commercial_grade_ready": False,
            "commercial_grade_blockers": report_grade["blockers"],
            "recommended_parsers": ["WinSearchDBAnalyzer", "ESEDatabaseView", "libesedb/esedbexport"],
            "note": "Windows.edb is inventoried directly with bounded ESE header/string/table candidate pivots; export CSV/JSON rows with a trusted ESE/Search parser for full table, timestamp, and deleted-state decoding.",
        },
    )


def build_edb_pivot_records(path: Path, inventory_details: Mapping[str, object]) -> list[ArtifactRecord]:
    source_hashes = file_hashes(path)
    candidates: list[tuple[str, str]] = []
    for value in inventory_details.get("path_candidates") or []:
        candidates.append(("path", str(value)))
    for value in inventory_details.get("url_candidates") or []:
        candidates.append(("url", str(value)))
    for value in inventory_details.get("content_candidates") or []:
        candidates.append(("content", str(value)))
    for value in inventory_details.get("suspicious_strings") or []:
        candidates.append(("string", str(value)))

    records: list[ArtifactRecord] = []
    seen: set[tuple[str, str]] = set()
    for index, (candidate_kind, candidate_value) in enumerate(candidates):
        key = (candidate_kind, candidate_value)
        if key in seen:
            continue
        seen.add(key)
        item_path = candidate_value if candidate_kind == "path" else ""
        url = candidate_value if candidate_kind == "url" else first_url(candidate_value)
        file_name = filename_from_path(item_path) if item_path else ""
        risk_flags = []
        if url:
            risk_flags.append("search-index-url-pivot")
        if candidate_kind == "content":
            risk_flags.append("search-index-content-pivot")
        if any(term in candidate_value.lower() for term in ("powershell", "cmd.exe", "rundll32", "regsvr32", "wmic", "certutil")):
            risk_flags.append("search-index-suspicious-text-pivot")
        validation_checks = {
            "candidate_kind": candidate_kind,
            "has_candidate_value": bool(candidate_value),
            "has_path_or_url": bool(item_path or url),
            "row_level_decoding_available": False,
            "requires_windows_search_parser": True,
        }
        report_grade = search_index_report_grade_assessment(
            search_index_validation_matrix(validation_checks),
            validation_required=True,
            extra_blockers=WINDOWS_SEARCH_EDB_BLOCKERS,
        )
        records.append(
            ArtifactRecord(
                provider=WindowsSearchIndexProvider.name,
                artifact_type="windows-search-edb-pivot",
                path=str(path.resolve()),
                supported=True,
                details={
                    "parser": "windows-search-edb-string-pivot",
                    "parser_version": PARSER_VERSION,
                    "coverage_status": "native-ese-string-pivot",
                    "reportability": "triage",
                    "source_path": str(path.resolve()),
                    "source_format": "ese-edb",
                    "source_hashes": source_hashes,
                    "source_index": index,
                    "candidate_kind": candidate_kind,
                    "candidate_value": candidate_value,
                    "item_path": item_path,
                    "file_name": file_name,
                    "extension": extension_from_name(file_name or item_path),
                    "url": url,
                    "title": "",
                    "content_snippet": candidate_value[:1000],
                    "parser_confidence": 0.4,
                    "evidence_strength": "search-index-string-pivot",
                    "validation_required": True,
                    "validation_guidance": "Windows.edb native string pivots identify indexed paths/URLs/text present in the database; validate full table fields and timestamps with a dedicated Windows Search EDB parser.",
                    "validation_checks": validation_checks,
                    "search_index_validation_matrix": search_index_validation_matrix(validation_checks),
                    "search_index_report_grade_assessment": report_grade,
                    "search_index_native_capabilities": WINDOWS_SEARCH_CAPABILITIES,
                    "commercial_grade_ready": False,
                    "commercial_grade_blockers": report_grade["blockers"],
                    "risk_flags": sorted(set(risk_flags)),
                    "risk_score": min(100, len(set(risk_flags)) * 20),
                    "raw_preview": candidate_value[:2000],
                },
            )
        )
    return records


def build_edb_table_candidate_records(path: Path, inventory_details: Mapping[str, object]) -> list[ArtifactRecord]:
    strings = [str(value) for value in inventory_details.get("extracted_strings") or []]
    lowered_blob = "\n".join(strings).lower()
    source_hashes = file_hashes(path)
    records: list[ArtifactRecord] = []
    ese_header = dict(inventory_details.get("ese_header") or {})
    native_metadata = dict(inventory_details.get("native_candidate_metadata") or {})
    for index, (table_family, markers) in enumerate(WINDOWS_SEARCH_TABLE_MARKERS.items()):
        matched = sorted({marker for marker in markers if marker in lowered_blob})
        if not matched:
            continue
        validation_checks = {
            "table_family_marker_count": len(matched),
            "ese_signature_valid": bool(ese_header.get("signature_valid")),
            "page_size_detected": int(ese_header.get("page_size") or 0),
            "ese_catalog_decoded": False,
            "row_level_decoding_available": False,
            "timestamps_decoded_from_native_rows": False,
            "deleted_state_decoded_from_native_rows": False,
            "requires_windows_search_parser": True,
        }
        report_grade = search_index_report_grade_assessment(
            search_index_validation_matrix(validation_checks),
            validation_required=True,
            extra_blockers=WINDOWS_SEARCH_EDB_BLOCKERS,
        )
        records.append(
            ArtifactRecord(
                provider=WindowsSearchIndexProvider.name,
                artifact_type="windows-search-edb-table-candidate",
                path=str(path.resolve()),
                supported=True,
                details={
                    "parser": "windows-search-edb-table-candidate",
                    "parser_version": PARSER_VERSION,
                    "coverage_status": "native-ese-table-string-candidate",
                    "reportability": "triage",
                    "source_path": str(path.resolve()),
                    "source_format": "ese-edb",
                    "source_hashes": source_hashes,
                    "source_index": index,
                    "table_family": table_family,
                    "matched_markers": matched,
                    "matched_marker_count": len(matched),
                    "candidate_metadata": native_metadata,
                    "parser_confidence": 0.38 + min(0.24, len(matched) * 0.06),
                    "evidence_strength": "windows-search-table-presence-candidate",
                    "validation_required": True,
                    "validation_guidance": "This row identifies likely Windows Search table families from native ESE strings only; validate rows, paths, content, timestamps, and deleted/index state with a full Windows Search EDB parser.",
                    "validation_checks": validation_checks,
                    "search_index_validation_matrix": search_index_validation_matrix(validation_checks),
                    "search_index_report_grade_assessment": report_grade,
                    "search_index_native_capabilities": WINDOWS_SEARCH_CAPABILITIES,
                    "commercial_grade_ready": False,
                    "commercial_grade_blockers": report_grade["blockers"],
                    "risk_flags": [f"windows-search-table:{table_family}"],
                    "risk_score": 20,
                    "raw_preview": " ".join(strings[:20])[:2000],
                },
            )
        )
    return records


def build_search_index_entry(
    path: Path,
    row: Mapping[str, object],
    index: int,
    source_hashes: Mapping[str, str],
) -> ArtifactRecord:
    lowered = {normalize_key(key): value for key, value in row.items()}
    item_path = str(
        first_value(
            lowered,
            "System.ItemPathDisplay",
            "ItemPathDisplay",
            "ItemPath",
            "Path",
            "FilePath",
            "URL",
        )
        or ""
    )
    title = str(first_value(lowered, "System.Title", "Title", "Subject", "DisplayName") or "")
    file_name = str(first_value(lowered, "System.FileName", "FileName", "Name") or "") or filename_from_path(item_path)
    content = str(first_value(lowered, "System.Search.Contents", "Contents", "Content", "Text", "Snippet") or "")
    validation_checks = {
        "has_item_path": bool(item_path),
        "has_file_name": bool(file_name),
        "has_content": bool(content),
        "has_timestamp": bool(
            first_value(lowered, "System.DateCreated", "DateCreated", "Created", "CreationTime")
            or first_value(lowered, "System.DateModified", "DateModified", "Modified", "LastModified")
            or first_value(lowered, "System.DateAccessed", "DateAccessed", "Accessed", "LastAccessed")
        ),
        "source_tool_export_validation_required": True,
    }
    report_grade = search_index_report_grade_assessment(
        search_index_validation_matrix(validation_checks),
        validation_required=False,
        extra_blockers=["source-tool-export-validation-required"],
    )
    details = {
        "parser": "windows-search-index-import",
        "parser_version": PARSER_VERSION,
        "coverage_status": "mapped",
        "reportability": "triage",
        "source_path": str(path.resolve()),
        "source_format": path.suffix.lower().lstrip("."),
        "source_hashes": dict(source_hashes),
        "source_index": index,
        "entry_id": str(first_value(lowered, "DocID", "DocumentID", "EntryID", "ID") or ""),
        "item_path": item_path,
        "file_name": file_name,
        "extension": extension_from_name(file_name or item_path),
        "url": str(first_value(lowered, "URL", "System.ItemUrl", "ItemUrl") or ""),
        "title": title,
        "author": str(first_value(lowered, "System.Author", "Author") or ""),
        "content_snippet": content[:1000],
        "created_at": normalize_timestamp(first_value(lowered, "System.DateCreated", "DateCreated", "Created", "CreationTime")),
        "modified_at": normalize_timestamp(first_value(lowered, "System.DateModified", "DateModified", "Modified", "LastModified")),
        "accessed_at": normalize_timestamp(first_value(lowered, "System.DateAccessed", "DateAccessed", "Accessed", "LastAccessed")),
        "size": str(first_value(lowered, "System.Size", "Size", "FileSize") or ""),
        "store": str(first_value(lowered, "Store", "Catalog", "Scope") or ""),
        "validation_required": False,
        "validation_checks": validation_checks,
        "search_index_validation_matrix": search_index_validation_matrix(validation_checks),
        "search_index_report_grade_assessment": report_grade,
        "search_index_native_capabilities": WINDOWS_SEARCH_CAPABILITIES,
        "commercial_grade_ready": False,
        "commercial_grade_blockers": report_grade["blockers"],
        "raw": dict(row),
        "raw_preview": json.dumps(row, ensure_ascii=False, sort_keys=True)[:2000],
    }
    return ArtifactRecord(
        provider=WindowsSearchIndexProvider.name,
        artifact_type="windows-search-index-entry",
        path=str(path.resolve()),
        supported=True,
        details=details,
    )


def build_search_index_summary(root: Path, records: Sequence[ArtifactRecord]) -> ArtifactRecord | None:
    entries = [record for record in records if record.artifact_type == "windows-search-index-entry"]
    edb_files = [record for record in records if record.artifact_type == "windows-search-edb-file"]
    edb_pivots = [record for record in records if record.artifact_type == "windows-search-edb-pivot"]
    edb_table_candidates = [record for record in records if record.artifact_type == "windows-search-edb-table-candidate"]
    if not entries and not edb_files and not edb_pivots and not edb_table_candidates:
        return None
    extension_counts: Counter[str] = Counter()
    source_files: set[str] = set()
    for record in entries:
        details = record.details
        extension = str(details.get("extension") or "")
        if extension:
            extension_counts[extension] += 1
        source_path = str(details.get("source_path") or record.path)
        source_files.add(source_path)
    for record in edb_pivots:
        details = record.details
        source_path = str(details.get("source_path") or record.path)
        source_files.add(source_path)
    table_family_counts: Counter[str] = Counter()
    for record in edb_table_candidates:
        details = record.details
        source_path = str(details.get("source_path") or record.path)
        source_files.add(source_path)
        table_family = str(details.get("table_family") or "")
        if table_family:
            table_family_counts[table_family] += 1
    edb_inventory = []
    edb_string_hit_count = 0
    for record in edb_files:
        details = record.details
        source_path = str(details.get("source_path") or record.path)
        source_files.add(source_path)
        hit_count = int(details.get("extracted_string_count") or 0)
        edb_string_hit_count += hit_count
        edb_inventory.append(
            {
                "source_path": source_path,
                "signature_valid": bool(dict(details.get("ese_header") or {}).get("signature_valid")),
                "extracted_string_count": hit_count,
                "native_candidate_metadata": dict(details.get("native_candidate_metadata") or {}),
                "commercial_grade_ready": bool(details.get("commercial_grade_ready")),
                "risk_flags": list(details.get("risk_flags") or [])[:10],
            }
        )
    return ArtifactRecord(
        provider=WindowsSearchIndexProvider.name,
        artifact_type="windows-search-index-summary",
        path=str(root.resolve()),
        supported=True,
        details={
            "parser": "windows-search-index-summary",
            "parser_version": PARSER_VERSION,
            "coverage_status": "summarized",
            "reportability": "triage",
            "source_path": str(root.resolve()),
            "entry_count": len(entries),
            "inventory_count": len(edb_files),
            "edb_pivot_count": len(edb_pivots),
            "edb_table_candidate_count": len(edb_table_candidates),
            "source_files": sorted(source_files),
            "extension_counts": [{"value": value, "count": count} for value, count in extension_counts.most_common(25)],
            "table_family_counts": [
                {"value": value, "count": count} for value, count in table_family_counts.most_common(25)
            ],
            "edb_string_hit_count": edb_string_hit_count,
            "edb_inventory": edb_inventory,
            "commercial_grade_ready": False,
            "commercial_grade_blockers": WINDOWS_SEARCH_EDB_BLOCKERS if edb_files else [],
        },
    )


def build_search_content_candidates(pivots: Mapping[str, object], *, limit: int = 50) -> list[str]:
    path_values = {str(value) for value in pivots.get("path_candidates") or []}
    url_values = {str(value) for value in pivots.get("url_candidates") or []}
    candidates: list[str] = []
    seen: set[str] = set()
    for value in pivots.get("extracted_strings") or []:
        text = str(value).strip()
        lowered = text.lower()
        if not text or text in path_values or text in url_values:
            continue
        if first_url(text) or re.search(r"(?i)(?:[a-z]:\\|\\\\)", text):
            continue
        if any(marker in lowered for markers in WINDOWS_SEARCH_TABLE_MARKERS.values() for marker in markers):
            continue
        if len(text) < 20 or " " not in text:
            continue
        if text in seen:
            continue
        seen.add(text)
        candidates.append(text[:1000])
        if len(candidates) >= limit:
            break
    return candidates


def search_index_validation_matrix(checks: Mapping[str, object]) -> list[dict[str, object]]:
    labels = {
        "ese_header_readable": ("ESE header readable", "critical"),
        "ese_signature_valid": ("ESE signature valid", "critical"),
        "has_path_pivots": ("Path pivots", "medium"),
        "has_url_pivots": ("URL pivots", "medium"),
        "has_content_candidates": ("Content candidates", "medium"),
        "has_table_family_candidates": ("Table family candidates", "medium"),
        "has_candidate_value": ("Candidate value", "medium"),
        "has_path_or_url": ("Path or URL", "medium"),
        "has_item_path": ("Item path", "high"),
        "has_file_name": ("File name", "medium"),
        "has_content": ("Content", "medium"),
        "has_timestamp": ("Timestamp", "high"),
        "ese_catalog_decoded": ("ESE catalog decoded", "critical"),
        "row_level_decoding_available": ("Row-level decoding", "critical"),
        "timestamps_decoded_from_native_rows": ("Native row timestamps", "high"),
        "deleted_state_decoded_from_native_rows": ("Native deleted state", "high"),
        "requires_windows_search_parser": ("Windows Search parser validation", "critical"),
        "source_tool_export_validation_required": ("Source tool export validation", "high"),
    }
    matrix: list[dict[str, object]] = []
    for key, value in checks.items():
        if key in {"candidate_kind", "page_size_detected", "table_family_marker_count"}:
            continue
        label, severity = labels.get(key, (key.replace("_", " "), "medium"))
        negative_requirement = key.startswith("requires_") or key.endswith("_required")
        passed = bool(value)
        if negative_requirement:
            passed = not bool(value)
        matrix.append({"id": key.replace("_", "-"), "label": label, "passed": passed, "severity": severity, "detail": value})
    return matrix


def search_index_report_grade_assessment(
    validation_matrix: Sequence[Mapping[str, object]],
    *,
    validation_required: bool,
    extra_blockers: Sequence[str],
) -> dict[str, object]:
    failed = [str(item.get("id")) for item in validation_matrix if isinstance(item, Mapping) and not item.get("passed")]
    blockers = set(WINDOWS_SEARCH_EDB_BLOCKERS)
    blockers.update(f"validation-check-failed:{item}" for item in failed)
    blockers.update(str(item) for item in extra_blockers if str(item))
    if validation_required:
        blockers.add("windows-search-validation-required")
    return {
        "report_grade_ready": False,
        "status": "validation-required" if failed else "triage-validated-report-grade-blocked",
        "blockers": sorted(blockers),
        "validated_strengths": [str(item.get("id")) for item in validation_matrix if isinstance(item, Mapping) and item.get("passed")],
        "commercial_gap_ids": ["#11"],
        "next_validation_step": "Validate Windows.edb paths, content, timestamps, and deleted/index state with a full ESE/Search parser before report-grade use.",
    }


def detect_search_table_families(pivots: Mapping[str, object]) -> list[str]:
    strings = [str(value) for value in pivots.get("extracted_strings") or []]
    lowered_blob = "\n".join(strings).lower()
    return [
        table_family
        for table_family, markers in WINDOWS_SEARCH_TABLE_MARKERS.items()
        if any(marker in lowered_blob for marker in markers)
    ]


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


def normalize_key(value: object) -> str:
    return "".join(ch for ch in str(value).lower() if ch.isalnum())


def first_value(row: Mapping[str, object], *keys: str) -> object:
    for key in keys:
        value = row.get(normalize_key(key))
        if value not in (None, ""):
            return value
    return ""


def normalize_timestamp(value: object) -> str:
    return str(value or "").strip().replace("Z", "+00:00")


def filename_from_path(value: str) -> str:
    if not value:
        return ""
    return PureWindowsPath(value).name


def extension_from_name(value: str) -> str:
    suffix = PureWindowsPath(value).suffix.lower()
    return suffix if suffix else ""


def first_url(value: str) -> str:
    match = re.search(r"(?i)https?://[^\s\x00\"'<>]{4,300}", value)
    return match.group(0).rstrip(".,);]") if match else ""


def file_hashes(path: Path) -> dict[str, str]:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return {}
    return {"sha256": digest.hexdigest()}
