"""Read-only helpers behind the console 접수 dashboard (plan §9 X1/X2/X17).

* case notes — examiner name + case summary stored as JSON next to the run
  outputs (``<output_dir>/rapidtriage-case-notes.json``);
* evidence source — image name/size and the partition rows the image stage
  recorded (``rapidtriage-e01.json`` ``partition_selection.partition_browser_rows``);
* export history — case report formats, reviewer bundle, submission manifest,
  validation package and row extracts already written under the output dir.

Nothing here parses evidence or changes recovery behaviour; it only reads
files the run (or earlier console actions) already produced.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from fastapi import HTTPException

from ...core.case_report import case_report_export_paths
from ...core.jobs import RunJob, RunJobStore, read_output_json, run_output_dir
from ...core.run.profiles import RUN_PROFILES
from .helpers import (
    default_case_report_path,
    default_reviewer_bundle_dir_path,
    default_run_validation_package_path,
    default_submission_manifest_path,
    get_output_path,
    job_output_dir,
)

CASE_NOTES_FILE_NAME = "rapidtriage-case-notes.json"
CASE_NOTES_PROFILE = "rapidtriage-case-notes-v1"
IMAGE_OUTPUT_NAMES = ("e01", "disk_image", "virtual_disk", "archive_image")
EXTRACT_NAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
EXPORT_HISTORY_MAX = 200


# --- case notes -------------------------------------------------------------


def case_notes_path(output_dir: Path) -> Path:
    return output_dir / CASE_NOTES_FILE_NAME


def read_case_notes(output_dir: Path | None) -> dict[str, Any]:
    """Stored notes, or empty strings when the file is missing/unreadable."""
    empty: dict[str, Any] = {"examiner": "", "summary": "", "updated_at": None, "exists": False}
    if output_dir is None:
        return empty
    path = case_notes_path(output_dir)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return empty
    if not isinstance(payload, dict):
        return empty
    return {
        "examiner": str(payload.get("examiner") or ""),
        "summary": str(payload.get("summary") or ""),
        "updated_at": payload.get("updated_at"),
        "exists": True,
    }


def write_case_notes(output_dir: Path, *, examiner: str, summary: str) -> dict[str, Any]:
    payload = {
        "profile_version": CASE_NOTES_PROFILE,
        "examiner": examiner,
        "summary": summary,
        "updated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    path = case_notes_path(output_dir)
    temp = path.with_name(f"{path.name}.tmp")
    temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(path)
    return {**payload, "exists": True}


def notes_output_dir(job: RunJob) -> Path:
    output_dir = job_output_dir(job)
    if output_dir is None:
        raise HTTPException(status_code=409, detail="run has no output directory yet")
    return output_dir


def apply_case_notes_to_report_metadata(metadata: dict[str, Any], output_dir: Path | None) -> dict[str, Any]:
    """Fill empty report fields from the case notes (explicit request values win)."""
    notes = read_case_notes(output_dir)
    if not metadata.get("investigator") and notes["examiner"]:
        metadata["investigator"] = notes["examiner"]
    if not metadata.get("scope") and notes["summary"]:
        metadata["scope"] = notes["summary"]
    return metadata


# --- evidence source --------------------------------------------------------


def _int_or_none(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _integrity_size(integrity: object) -> int | None:
    if isinstance(integrity, Mapping):
        return _int_or_none(integrity.get("size"))
    if isinstance(integrity, list):
        sizes = [_int_or_none(item.get("size")) for item in integrity if isinstance(item, Mapping)]
        known = [size for size in sizes if size is not None]
        return sum(known) if known else None
    return None


def _partition_rows(payload: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    selection = payload.get("partition_selection")
    if isinstance(selection, Mapping) and isinstance(selection.get("partition_browser_rows"), list):
        rows = selection["partition_browser_rows"]
        if rows:
            return [row for row in rows if isinstance(row, Mapping)]
    browser = payload.get("partition_browser")
    if isinstance(browser, Mapping) and isinstance(browser.get("rows"), list) and browser["rows"]:
        return [row for row in browser["rows"] if isinstance(row, Mapping)]
    table = payload.get("partition_table")
    return [row for row in table if isinstance(row, Mapping)] if isinstance(table, list) else []


def _normalize_partitions(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    selection = payload.get("partition_selection") if isinstance(payload.get("partition_selection"), Mapping) else {}
    selected_sector = _int_or_none(selection.get("selected_start_sector"))
    if selected_sector is None:
        selected_sector = _int_or_none(payload.get("partition_start_sector"))
    partitions: list[dict[str, Any]] = []
    for index, row in enumerate(_partition_rows(payload), start=1):
        start = _int_or_none(row.get("start_sector"))
        partitions.append(
            {
                "number": _int_or_none(row.get("partition_number")) or _int_or_none(row.get("slot")) or index,
                "description": str(row.get("description") or ""),
                "filesystem": str(row.get("filesystem_guess") or "unknown"),
                "size_bytes": _int_or_none(row.get("size_bytes")),
                "start_sector": start,
                "byte_offset": _int_or_none(row.get("byte_offset")),
                "selected": bool(row.get("selected_for_recovery"))
                or (selected_sector is not None and start == selected_sector),
                "recommended": bool(row.get("recommended_for_recovery")),
            }
        )
    return partitions


def build_evidence_source(store: RunJobStore, run_id: str, job: RunJob) -> dict[str, Any]:
    request = job.request
    root = str(getattr(request, "root", "") or "")
    source: dict[str, Any] = {
        "path": root,
        "name": Path(root).name if root else run_id,
        "kind": "folder",
        "image_output": None,
        "size_bytes": None,
        "partitions": [],
        "selected_partition": None,
    }
    try:
        root_path = Path(root).expanduser()
        if root and root_path.is_file():
            source["kind"] = "file"
            source["size_bytes"] = root_path.stat().st_size
    except OSError:
        pass
    outputs = job.summary.get("outputs") if isinstance(job.summary, Mapping) else None
    if not isinstance(outputs, Mapping):
        return source
    for name in IMAGE_OUTPUT_NAMES:
        if name not in outputs:
            continue
        try:
            payload = read_output_json(get_output_path(store, run_id, name))
        except (HTTPException, OSError, json.JSONDecodeError):
            continue
        if not isinstance(payload, Mapping):
            continue
        source["kind"] = "image"
        source["image_output"] = name
        source_path = str(payload.get("source_path") or root)
        source["path"] = source_path
        source["name"] = Path(source_path).name or source["name"]
        size = _integrity_size(payload.get("source_integrity"))
        if size is not None:
            source["size_bytes"] = size
        partitions = _normalize_partitions(payload)
        source["partitions"] = partitions
        source["selected_partition"] = next(
            (partition["number"] for partition in partitions if partition["selected"]), None
        )
        break
    return source


# --- export history ---------------------------------------------------------


def _iso_mtime(path: Path) -> str | None:
    try:
        return dt.datetime.fromtimestamp(path.stat().st_mtime, tz=dt.timezone.utc).isoformat()
    except OSError:
        return None


def _file_entry(path: Path, *, kind: str, label: str, download_url: str, status: str = "완료") -> dict[str, Any]:
    return {
        "name": path.name,
        "type": kind,
        "label": label,
        "created_at": _iso_mtime(path),
        "size": path.stat().st_size if path.is_file() else None,
        "status": status,
        "download_url": download_url,
    }


def build_export_history(store: RunJobStore, run_id: str, job: RunJob) -> list[dict[str, Any]]:
    if job.summary is None:
        return []
    base = f"/api/runs/{run_id}"
    entries: list[dict[str, Any]] = []
    try:
        report_path = default_case_report_path(store, run_id)
        for format_name, path in case_report_export_paths(report_path).items():
            if format_name == "manifest" or not path.is_file():
                continue
            entries.append(
                _file_entry(
                    path,
                    kind="case-report",
                    label=f"보고서 ({format_name.upper()})",
                    download_url=f"{base}/case-report/file/{format_name}",
                )
            )
        bundle_zip = default_reviewer_bundle_dir_path(store, run_id).with_suffix(".zip")
        if bundle_zip.is_file():
            entries.append(
                _file_entry(bundle_zip, kind="reviewer-bundle", label="리뷰어 번들", download_url=f"{base}/reviewer-bundle/file")
            )
        manifest = default_submission_manifest_path(store, run_id)
        if manifest.is_file():
            entries.append(
                _file_entry(
                    manifest,
                    kind="submission-manifest",
                    label="제출 매니페스트",
                    download_url=f"{base}/submission-manifest/file",
                )
            )
        package = default_run_validation_package_path(store, run_id)
        if package.is_file():
            entries.append(
                _file_entry(package, kind="validation-package", label="검증 패키지", download_url=f"{base}/validation-package/file")
            )
    except HTTPException:
        pass
    try:
        extract_root = run_output_dir(job.summary) / "extract"
    except RuntimeError:
        extract_root = None
    if extract_root is not None and extract_root.is_dir():
        for folder in sorted(extract_root.iterdir()):
            if not folder.is_dir() or not EXTRACT_NAME_PATTERN.fullmatch(folder.name):
                continue
            archive = extract_root / f"{folder.name}.zip"
            extracted = None
            try:
                manifest_payload = json.loads((folder / "rapidtriage-extract-manifest.json").read_text(encoding="utf-8"))
                summary = manifest_payload.get("summary") if isinstance(manifest_payload, dict) else None
                if isinstance(summary, dict):
                    extracted = _int_or_none(summary.get("extracted_count"))
            except (OSError, json.JSONDecodeError):
                pass
            entries.append(
                {
                    "name": f"{folder.name}.zip",
                    "type": "extract",
                    "label": "선택 추출",
                    "created_at": _iso_mtime(folder),
                    "size": archive.stat().st_size if archive.is_file() else None,
                    "status": "zip 준비됨" if archive.is_file() else "zip 미생성",
                    "item_count": extracted,
                    "download_url": f"{base}/extract/{folder.name}/file",
                }
            )
    entries.sort(key=lambda entry: entry.get("created_at") or "", reverse=True)
    return entries[:EXPORT_HISTORY_MAX]


# --- aggregate --------------------------------------------------------------


def build_run_dashboard(store: RunJobStore, run_id: str, job: RunJob) -> dict[str, Any]:
    mode = str(getattr(job.request, "mode", "") or "")
    profile = RUN_PROFILES.get(mode)
    return {
        "command": "run-dashboard",
        "run_id": run_id,
        "completed": job.summary is not None,
        "profile": {
            "mode": mode,
            "description": profile.description if profile else "",
            "keywords": list(profile.keywords) if profile else [],
        },
        "evidence_source": build_evidence_source(store, run_id, job),
        "exports": build_export_history(store, run_id, job),
    }
