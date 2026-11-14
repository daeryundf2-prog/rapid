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

R8 RI-02: :func:`report_candidate_count` is the one count of report candidates
(``GET /review-counts``); it applies :func:`~rapidtriage.core.report_candidates.is_report_candidate`
to exactly the bookmarks :func:`load_run_review_payload` hands the case report, the submission
manifest and the reviewer bundle (same merge, same 5,000-mark cap, same order), so all of them
agree. Caps and an unreadable case DB are reported (``review_scope`` / ``truncated`` / ``error``),
never dropped silently.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from fastapi import HTTPException

from ...core.case import build_case_summary
from ...core.jobs import RunJobStore, run_output_dir
from ...core.report_candidates import is_report_candidate
from .helpers import default_case_path, get_job
from .run_review import (
    ACTIVE_MARK_ORDER_SQL,
    ACTIVE_MARK_SQL,
    canonical_run_case,
    read_only_sqlite_uri,
    review_map_entries,
)
from .runops import load_case_payload_or_empty

CASE_DB_BOOKMARK_PREFIX = "case-db:"
MAX_CASE_DB_MARKS = 5000
CASE_DB_UNREADABLE = "CASE_DB_UNREADABLE"
CASE_JSON_UNREADABLE = "CASE_JSON_UNREADABLE"


@dataclass
class CaseDbMarks:
    """Active case DB marks as bookmarks (or bare ids + flags), with the cap and read error."""

    bookmarks: list[dict[str, object]] = field(default_factory=list)
    truncated: bool = False
    total: int = 0
    error: str | None = None


def case_db_bookmark_id(citation_id: str, target_type: str, target_id: str) -> str:
    return f"{CASE_DB_BOOKMARK_PREFIX}{citation_id or f'{target_type}/{target_id}'}"


def _open_ro(database_path: Path) -> sqlite3.Connection:
    # ``immutable`` in a read-only folder: a plain ``mode=ro`` open of a WAL case DB creates
    # ``-wal`` / ``-shm`` next to it (T-348: the histogram tree read wrote them).
    connection = sqlite3.connect(read_only_sqlite_uri(database_path), uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def _active_mark_total(connection: sqlite3.Connection, case_id: str) -> int:
    row = connection.execute(f"SELECT COUNT(*) FROM review_mark WHERE case_id = ? AND {ACTIVE_MARK_SQL}", (case_id,)).fetchone()
    return int(row[0]) if row is not None else 0


def case_db_mark_flags(summary: Mapping[str, object], run_id: str) -> CaseDbMarks:
    """Bookmark id + include flag of the marks :func:`case_db_mark_bookmarks` returns (one query,
    same filter / order / cap — the cheap form for counting)."""
    database_path, case_id = canonical_run_case(summary, run_id)
    if not database_path.is_file():
        return CaseDbMarks()
    try:
        connection = _open_ro(database_path)
        try:
            rows = connection.execute(
                "SELECT citation_id, target_type, target_id, include_in_report FROM review_mark "
                f"WHERE case_id = ? AND {ACTIVE_MARK_SQL} {ACTIVE_MARK_ORDER_SQL} LIMIT ?",
                (case_id, MAX_CASE_DB_MARKS + 1),
            ).fetchall()
            truncated = len(rows) > MAX_CASE_DB_MARKS
            total = _active_mark_total(connection, case_id) if truncated else min(len(rows), MAX_CASE_DB_MARKS)
        finally:
            connection.close()
    except sqlite3.Error as exc:
        return CaseDbMarks(error=str(exc))
    marks = [
        {
            "bookmark_id": case_db_bookmark_id(str(row[0] or ""), str(row[1]), str(row[2])),
            "review": {"include_in_report": bool(row[3])},
            # Same citation fields as :func:`read_case_db_marks` so the dedup key is the same.
            "reference": {"citation_id": str(row[0] or ""), "target_type": str(row[1]), "target_id": str(row[2])},
        }
        for row in rows[:MAX_CASE_DB_MARKS]
    ]
    return CaseDbMarks(bookmarks=marks, truncated=truncated, total=total)


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


def _mark_preview(entry: Mapping[str, object]) -> str:
    """The cited row's preview text. A file record's "preview" is its path (``case_db.review``),
    which is not content and may be the analysis PC's path, so it is not used as a preview."""
    preview = str(entry.get("preview") or "").strip()
    if not preview or preview == str(entry.get("path") or "").strip():
        return ""
    return preview


def case_db_mark_bookmarks(summary: Mapping[str, object], run_id: str) -> list[dict[str, object]]:
    """Active case DB review marks of the run, shaped as case-JSON bookmarks."""
    return read_case_db_marks(summary, run_id).bookmarks


def read_case_db_marks(summary: Mapping[str, object], run_id: str) -> CaseDbMarks:
    """:func:`case_db_mark_bookmarks` with the 5,000-mark cap and a read error kept."""
    database_path, case_id = canonical_run_case(summary, run_id)
    if not database_path.is_file():
        return CaseDbMarks()
    outputs = summary.get("outputs")
    total = 0
    try:
        connection = _open_ro(database_path)
        try:
            entries, truncated = review_map_entries(
                connection,
                case_id,
                outputs if isinstance(outputs, Mapping) else {},
                limit=MAX_CASE_DB_MARKS,
                output_dir=_summary_dir(summary),
            )
            total = _active_mark_total(connection, case_id) if truncated else len(entries)
        finally:
            connection.close()
    except sqlite3.Error as exc:
        return CaseDbMarks(error=str(exc))
    bookmarks: list[dict[str, object]] = []
    for entry in entries:
        citation_id = str(entry.get("citation_id") or "")
        target_type = str(entry.get("target_type") or "")
        target_id = str(entry.get("target_id") or "")
        path = _resolve_mark_path(str(entry.get("path") or ""), summary)
        title = str(entry.get("title") or "") or (Path(path).name if path else f"{target_type} {target_id}")
        updated_at = str(entry.get("updated_at") or "")
        reviewer = str(entry.get("reviewer") or "")
        preview = _mark_preview(entry)
        bookmarks.append(
            {
                "bookmark_id": case_db_bookmark_id(citation_id, target_type, target_id),
                "created_at": updated_at,
                "updated_at": updated_at,
                "summary": title,
                "tags": [str(tag) for tag in entry.get("tags") or []],
                "note": str(entry.get("note") or ""),
                "review": {
                    "status": str(entry.get("status") or "unreviewed"),
                    "include_in_report": bool(entry.get("include_in_report")),
                    "reviewed_at": updated_at or None,
                    "reviewer": reviewer,
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
                    # The cited row's own content (``build_row_info`` prefers it; "" = none, never
                    # the title again).
                    "preview": preview,
                },
            }
        )
    return CaseDbMarks(bookmarks=bookmarks, truncated=truncated, total=total)


def _json_bookmarks(payload: Mapping[str, object]) -> list[Mapping[str, object]]:
    existing = payload.get("bookmarks")
    return [item for item in existing if isinstance(item, Mapping)] if isinstance(existing, list) else []


def review_citation_keys(bookmark: Mapping[str, object]) -> set[str]:
    """Dedup keys of one review item (R8 T-025): its citation, not the store's own bookmark id.

    ``reference.citation_id`` (the case DB mark's citation) and ``reference.target_type/target_id``
    (the cited target) when the item carries them; empty when it carries neither (then only the
    bookmark id can match)."""
    reference = bookmark.get("reference")
    if not isinstance(reference, Mapping):
        return set()
    keys: set[str] = set()
    citation_id = str(reference.get("citation_id") or "").strip()
    if citation_id:
        keys.add(f"citation:{citation_id}")
    target_type = str(reference.get("target_type") or "").strip()
    target_id = str(reference.get("target_id") or "").strip()
    if target_type and target_id:
        keys.add(f"target:{target_type}/{target_id}")
    return keys


def merge_review_bookmarks(
    json_bookmarks: list[Mapping[str, object]], marks: list[dict[str, object]]
) -> list[Mapping[str, object]]:
    """Bookmark JSON first, then every case DB mark the JSON does not already hold.

    A mark is the same item as a JSON bookmark when both carry the same citation id or cited
    target (:func:`review_citation_keys`), or the same bookmark id (a snapshot of an earlier
    merge) — so an item present in both stores under different bookmark ids counts once."""
    known_ids = {str(item.get("bookmark_id") or "") for item in json_bookmarks}
    known_citations: set[str] = set()
    for item in json_bookmarks:
        known_citations |= review_citation_keys(item)
    return [
        *json_bookmarks,
        *(
            item
            for item in marks
            if item["bookmark_id"] not in known_ids and not (review_citation_keys(item) & known_citations)
        ),
    ]


def review_scope(marks: CaseDbMarks) -> dict[str, object] | None:
    """``review_scope`` of the merged payload: the mark cap / read error that limited it."""
    if not marks.truncated and marks.error is None:
        return None
    return {
        "case_db_marks_truncated": marks.truncated,
        "case_db_marks_total": marks.total,
        "case_db_mark_limit": MAX_CASE_DB_MARKS,
        "case_db_error": marks.error,
    }


def load_run_review_payload(store: RunJobStore, run_id: str) -> dict[str, object]:
    """Bookmark JSON + active case DB marks of a finished run as one case payload."""
    job = get_job(store, run_id)
    summary = job.summary or {}
    payload = load_case_payload_or_empty(default_case_path(store, run_id))
    bookmarks = _json_bookmarks(payload)
    marks = read_case_db_marks(summary, run_id)
    merged_bookmarks = merge_review_bookmarks(bookmarks, marks.bookmarks)
    scope = review_scope(marks)
    if len(merged_bookmarks) == len(bookmarks) and scope is None:
        return payload
    merged = dict(payload)
    merged["bookmarks"] = merged_bookmarks
    merged["summary"] = build_case_summary(merged["bookmarks"])
    if scope is not None:
        merged["review_scope"] = scope
    return merged


def report_candidate_count(store: RunJobStore, run_id: str) -> dict[str, object]:
    """The report-candidate count every surface shows (R8 RI-02).

    ``count`` = bookmarks of :func:`load_run_review_payload` that pass ``is_report_candidate``
    (computed from the same merge without building the full mark payload). ``case_db`` /
    ``case_json`` split it by store; ``truncated`` says the 5,000-mark cap left marks out
    (``case_db_marks_total`` = every active mark); ``error`` (``count`` = ``None``) when a review
    store cannot be read."""
    job = get_job(store, run_id)
    summary = job.summary or {}
    error: dict[str, str] | None = None
    try:
        bookmarks = _json_bookmarks(load_case_payload_or_empty(default_case_path(store, run_id)))
    except HTTPException as exc:
        bookmarks = []
        error = {"code": CASE_JSON_UNREADABLE, "message": f"검토 목록 파일(rapidtriage-case.json)을 읽지 못했습니다: {exc.detail}"}
    marks = case_db_mark_flags(summary, run_id)
    if marks.error is not None:
        error = {"code": CASE_DB_UNREADABLE, "message": f"케이스 DB를 읽지 못했습니다: {marks.error}"}
    candidates = [item for item in merge_review_bookmarks(bookmarks, marks.bookmarks) if is_report_candidate(item)]
    from_db = sum(1 for item in candidates if str(item.get("bookmark_id") or "").startswith(CASE_DB_BOOKMARK_PREFIX))
    return {
        "count": None if error else len(candidates),
        "case_db": from_db,
        "case_json": len(candidates) - from_db,
        "truncated": marks.truncated,
        "case_db_marks_total": marks.total,
        "case_db_mark_limit": MAX_CASE_DB_MARKS,
        "error": error,
    }
