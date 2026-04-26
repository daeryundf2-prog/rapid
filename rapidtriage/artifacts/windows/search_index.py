from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from pathlib import Path, PureWindowsPath
from typing import Iterable, Mapping, Sequence

from ...core.models import ArtifactRecord
from .ese import build_ese_string_pivots, probe_ese_database

PARSER_VERSION = "windows-search-index-import-v2"
SEARCH_EDB_PATH = ("ProgramData", "Microsoft", "Search", "Data", "Applications", "Windows", "Windows.edb")
SUPPORTED_EXPORT_SUFFIXES = {".csv", ".json", ".jsonl", ".ndjson"}
EXPORT_HINTS = ("windows.edb", "windows-search", "searchindex", "search-index", "edbexport", "winsearch")


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
            records.append(build_edb_inventory_record(edb_path))
            seen.add(edb_path.resolve())

        for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
            if not path.is_file():
                continue
            resolved = path.resolve()
            if resolved in seen:
                continue
            lowered = str(path.relative_to(root)).lower()
            if path.name.lower() == "windows.edb":
                records.append(build_edb_inventory_record(path))
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
    coverage_status = "ese-header-string-scan" if ese_header.get("header_readable") else "detected"
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
            "recommended_parsers": ["WinSearchDBAnalyzer", "ESEDatabaseView", "libesedb/esedbexport"],
            "note": "Windows.edb is inventoried directly with bounded ESE header/string pivots; export CSV/JSON rows with a trusted ESE/Search parser for full table decoding.",
        },
    )


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
    if not entries and not edb_files:
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
            "source_files": sorted(source_files),
            "extension_counts": [{"value": value, "count": count} for value, count in extension_counts.most_common(25)],
            "edb_string_hit_count": edb_string_hit_count,
            "edb_inventory": edb_inventory,
        },
    )


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


def file_hashes(path: Path) -> dict[str, str]:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return {}
    return {"sha256": digest.hexdigest()}
