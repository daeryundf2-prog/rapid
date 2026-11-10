"""Run review payload for report/bundle exports (E01 QA D2).

The console writes marks and tags into the run's case DB (``review_mark``),
while the submission manifest, case report and reviewer bundle historically
read only the bookmark JSON (``rapidtriage-case.json``) written by
``POST /bookmarks``. A run reviewed only in the console therefore had no case
JSON, and the reviewer bundle answered 404 although the report gate counted
the marks as report candidates.

:func:`load_run_review_payload` merges both stores into one case payload:
the bookmark JSON (when present) plus one bookmark per active case DB mark,
carrying the mark's status, tags, note and include-in-report flag. Nothing is
written back to either store.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from pathlib import Path

from ...core.case import build_case_summary
from ...core.jobs import RunJobStore, run_output_dir
from .helpers import default_case_path, get_job
from .run_review import canonical_run_case, review_map_entries
from .runops import load_case_payload_or_empty

CASE_DB_BOOKMARK_PREFIX = "case-db:"
MAX_CASE_DB_MARKS = 5000


def _summary_dir(summary: Mapping[str, object]) -> Path | None:
    try:
        return run_output_dir(summary)
    except RuntimeError:
        return None


def _resolve_mark_path(raw: str, summary: Mapping[str, object]) -> str:
    """Absolute on-disk path for a mark's path when it can be resolved, else the raw value."""
    if not raw:
        return ""
    candidate = Path(raw)
    if candidate.is_absolute():
        return raw
    roots: list[str] = []
    source = summary.get("source")
    if isinstance(source, Mapping):
        roots.extend(str(source.get(key) or "") for key in ("analysis_root", "stage_dir"))
    roots.extend(str(summary.get(key) or "") for key in ("root", "scan_scope_root"))
    for root in roots:
        if root and (Path(root) / candidate).is_file():
            return str((Path(root) / candidate).resolve())
    return raw


def case_db_mark_bookmarks(summary: Mapping[str, object], run_id: str) -> list[dict[str, object]]:
    """Active case DB review marks of the run, shaped as case-JSON bookmarks."""
    database_path, case_id = canonical_run_case(summary, run_id)
    if not database_path.is_file():
        return []
    outputs = summary.get("outputs")
    try:
        connection = sqlite3.connect(f"{database_path.as_uri()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            entries, _truncated = review_map_entries(
                connection,
                case_id,
                outputs if isinstance(outputs, Mapping) else {},
                limit=MAX_CASE_DB_MARKS,
                output_dir=_summary_dir(summary),
            )
        finally:
            connection.close()
    except sqlite3.Error:
        return []
    bookmarks: list[dict[str, object]] = []
    for entry in entries:
        citation_id = str(entry.get("citation_id") or "")
        target_type = str(entry.get("target_type") or "")
        target_id = str(entry.get("target_id") or "")
        path = _resolve_mark_path(str(entry.get("path") or ""), summary)
        title = str(entry.get("title") or "") or (Path(path).name if path else f"{target_type} {target_id}")
        updated_at = str(entry.get("updated_at") or "")
        bookmarks.append(
            {
                "bookmark_id": f"{CASE_DB_BOOKMARK_PREFIX}{citation_id or f'{target_type}/{target_id}'}",
                "created_at": updated_at,
                "updated_at": updated_at,
                "summary": title,
                "tags": [str(tag) for tag in entry.get("tags") or []],
                "note": str(entry.get("note") or ""),
                "review": {
                    "status": str(entry.get("status") or "unreviewed"),
                    "include_in_report": bool(entry.get("include_in_report")),
                    "reviewed_at": updated_at or None,
                },
                "review_history": [],
                "reference": {
                    "source_command": "case-db",
                    "case_id": case_id,
                    "citation_id": citation_id,
                    "target_type": target_type,
                    "target_id": target_id,
                    "collection": str(entry.get("collection") or ""),
                    "kind": str(entry.get("kind") or ""),
                    "locator": str(entry.get("locator") or ""),
                },
                "snapshot": {
                    "path": path,
                    "timestamp": str(entry.get("timestamp") or ""),
                    "summary": title,
                },
            }
        )
    return bookmarks


def load_run_review_payload(store: RunJobStore, run_id: str) -> dict[str, object]:
    """Bookmark JSON + active case DB marks of a finished run as one case payload."""
    job = get_job(store, run_id)
    summary = job.summary or {}
    payload = load_case_payload_or_empty(default_case_path(store, run_id))
    existing = payload.get("bookmarks")
    bookmarks = [item for item in existing if isinstance(item, Mapping)] if isinstance(existing, list) else []
    known = {str(item.get("bookmark_id") or "") for item in bookmarks}
    added = [item for item in case_db_mark_bookmarks(summary, run_id) if item["bookmark_id"] not in known]
    if not added:
        return payload
    merged = dict(payload)
    merged["bookmarks"] = [*bookmarks, *added]
    merged["summary"] = build_case_summary(merged["bookmarks"])
    return merged
