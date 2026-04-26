from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from typing import Iterable, Mapping

from ...core.models import ArtifactRecord

PARSER_VERSION = "windows-filesystem-import-v1"
SUPPORTED_SUFFIXES = {".csv", ".json", ".jsonl", ".ndjson"}
MFT_HINTS = ("mft", "mftexcmd", "$mft")
USN_HINTS = ("usn", "usnjrnl", "$j")


class WindowsFilesystemProvider:
    name = "windows-filesystem"
    collector_kind = "windows-filesystem"
    description = "Windows MFT and USN Journal CSV/JSON/JSONL imports"
    target_platform = "windows"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
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
