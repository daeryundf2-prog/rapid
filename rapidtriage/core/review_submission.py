"""Case-DB review marks as case bookmarks for the run's submission.

A run's review decisions live in two stores: case-JSON bookmarks
(``rapidtriage-case.json``, ``/bookmarks``) and case-DB review marks
(``review_mark`` in ``rapidtriage-case.db``, the V2 review board). The
submission (manifest, case report, reviewer bundle) reads one case payload:
:func:`review_mark_bookmarks` turns every active mark of the run's case into a
bookmark of the same shape -- the cited output row, its row digest and
snapshot -- so a mark flagged for the report reaches every submission output.
A mark whose row cannot be cited keeps a bookmark with
``reference.case_db.unresolved_reason``; the manifest lists it as missing and
the report and bundle stop on it instead of leaving it out.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from pathlib import Path

from .case import (
    CaseBookmarkError,
    build_bookmark_snapshot,
    build_case_summary,
    build_review_state,
    load_source_payload,
    normalize_tags,
    upsert_bookmark,
)
from .case_db.review import load_review_target_match
from .case_db.run_locator import ACTIVE_MARK_SQL, RunLocatorIndex, location_source

# Why a mark has no citable output row (``reference.case_db.unresolved_reason``).
MARK_ROW_NOT_FOUND = "review-mark-row-not-found"
MARK_NOT_CITABLE = "review-mark-not-citable"
MARK_SOURCE_UNREADABLE = "review-mark-source-unreadable"


def review_mark_bookmarks(
    database: Path,
    case_id: str,
    outputs: Mapping[str, object],
    *,
    output_dir: Path,
) -> list[dict[str, object]]:
    """Every active review mark of ``case_id`` as a case bookmark (oldest first).

    ``outputs`` is the run summary's output map; only outputs under
    ``output_dir`` are read."""
    if not database.is_file():
        return []
    output_root = output_dir.expanduser().resolve()
    try:
        connection = sqlite3.connect(f"{database.expanduser().resolve().as_uri()}?mode=ro", uri=True)
    except sqlite3.Error:
        return []
    try:
        try:
            rows = connection.execute(
                "SELECT citation_id, target_type, target_id, status, tags_json, note, include_in_report, "
                "reviewer, created_at, updated_at "
                f"FROM review_mark WHERE case_id = ? AND {ACTIVE_MARK_SQL} ORDER BY id",
                (case_id,),
            ).fetchall()
        except sqlite3.Error:
            return []  # a case DB without review tables has no marks
        index = RunLocatorIndex(connection, case_id, outputs, output_dir=output_root)
        sources: dict[Path, dict[str, object]] = {}
        bookmarks: list[dict[str, object]] = []
        for row in rows:
            citation_id, target_type, target_id = str(row[0]), str(row[1]), str(row[2])
            try:
                tags = normalize_tags(json.loads(str(row[4] or "[]")))
            except json.JSONDecodeError:
                tags = []
            mark = {
                "citation_id": citation_id,
                "status": str(row[3] or "unreviewed"),
                "tags": tags,
                "note": str(row[5] or ""),
                "include_in_report": bool(row[6]),
                "created_at": str(row[8] or ""),
                "updated_at": str(row[9] or ""),
            }
            case_db = {
                "database": str(database),
                "case_id": case_id,
                "citation_id": citation_id,
                "target_type": target_type,
                "target_id": target_id,
                "reviewer": str(row[7] or ""),
            }
            location = index.locate(target_type, target_id)
            source = location_source(location) if location is not None else None
            reason = MARK_ROW_NOT_FOUND if location is None else MARK_NOT_CITABLE if source is None else ""
            bookmark = None
            if source is not None:
                output_name, pointer = source
                case_db["locator"] = dict(location or {})
                try:
                    bookmark = _mark_bookmark(mark, _output_file(outputs, output_name, output_root), pointer, sources)
                except (OSError, CaseBookmarkError) as exc:
                    reason = MARK_SOURCE_UNREADABLE
                    case_db["unresolved_detail"] = str(exc)
            if bookmark is None:
                match = load_review_target_match(connection, case_id, target_type=target_type, target_id=target_id)
                bookmark = _unresolved_bookmark(mark, match)
                case_db["unresolved_reason"] = reason
            bookmark["reference"]["case_db"] = case_db
            bookmarks.append(bookmark)
        return bookmarks
    finally:
        connection.close()


def with_review_marks(case_payload: Mapping[str, object], marks: list[dict[str, object]]) -> dict[str, object]:
    """``case_payload`` plus the case-DB mark bookmarks, with the summary recounted."""
    existing = case_payload.get("bookmarks")
    bookmarks = [*(existing if isinstance(existing, list) else []), *marks]
    return {**case_payload, "bookmarks": bookmarks, "summary": build_case_summary(bookmarks)}


def _output_file(outputs: Mapping[str, object], output_name: str, output_root: Path) -> Path:
    raw = outputs.get(output_name)
    if not raw:
        raise FileNotFoundError(f"run output {output_name!r} is not recorded")
    path = Path(str(raw)).expanduser().resolve()
    if not path.is_relative_to(output_root):
        raise PermissionError(f"run output is outside output_dir: {path}")
    return path


def _mark_bookmark(
    mark: Mapping[str, object],
    source_path: Path,
    pointer: str,
    sources: dict[Path, dict[str, object]],
) -> dict[str, object]:
    if source_path not in sources:
        sources[source_path] = load_source_payload(source_path)
    # One payload per mark: two marks on rows of equal content stay two bookmarks.
    holder: dict[str, object] = {"bookmarks": []}
    upsert_bookmark(
        holder,
        source_path=source_path,
        source_payload=sources[source_path],
        source_pointer=pointer,
        bookmark_id=str(mark["citation_id"]),
        tags=list(mark["tags"]),  # type: ignore[arg-type]
        remove_tags=[],
        note=str(mark["note"]),
        review_status=str(mark["status"]),
        include_in_report=bool(mark["include_in_report"]),
    )
    bookmark = holder["bookmarks"][0]  # type: ignore[index]
    bookmark["created_at"] = mark["created_at"] or bookmark["created_at"]
    bookmark["updated_at"] = mark["updated_at"] or bookmark["updated_at"]
    return bookmark


def _unresolved_bookmark(mark: Mapping[str, object], match: Mapping[str, object] | None) -> dict[str, object]:
    title = str((match or {}).get("title") or "")
    path = str((match or {}).get("path") or "")
    summary = title or path or f"검토 표시 {mark['citation_id']}"
    status = str(mark["status"])
    return {
        "bookmark_id": str(mark["citation_id"]),
        "created_at": str(mark["created_at"]),
        "updated_at": str(mark["updated_at"]),
        "summary": summary,
        "tags": list(mark["tags"]),  # type: ignore[call-overload]
        "note": str(mark["note"]),
        "review": build_review_state(
            status=status,
            include_in_report=bool(mark["include_in_report"]),
            reviewed_at=str(mark["updated_at"]) or None,
        ),
        "review_history": [],
        "reference": {
            "command": "",
            "file": "",
            "pointer": "",
            "root": None,
            "stable_key": str(mark["citation_id"]),
        },
        "snapshot": build_bookmark_snapshot(
            source_path=None,
            source_hash=None,
            source_timestamp=str((match or {}).get("timestamp") or "") or None,
            artifact_key=None,
            summary=summary,
        ),
    }
