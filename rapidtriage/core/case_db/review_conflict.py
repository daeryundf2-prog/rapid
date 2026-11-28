"""Optimistic concurrency of review marks (design review F14).

A console write may carry, per target, the ``updated_at`` of the mark it last
read (``expected_updated_at``; ``""`` = "I saw no mark"). When the stored mark
changed since, the write is refused with the current mark instead of silently
overwriting another examiner's decision. A batch is all-or-nothing: every
expectation is checked inside the write transaction before anything is written.
Writes without an expectation behave as before.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Mapping

from .base import CaseDatabaseError

__all__ = [
    "ACTIVE_MARK_SQL",
    "EXPECTED_UPDATED_AT_KEY",
    "ReviewConflictError",
    "review_conflicts",
]

# A mark toggled back to its defaults (status ``unreviewed``, no note/tags,
# not in the report, unverified) is "cleared": the row stays in ``review_mark``
# (``review_mark_history`` keeps the audit trail) but the review board and the
# review tallies leave it out.
ACTIVE_MARK_SQL = (
    "NOT (status = 'unreviewed' AND include_in_report = 0 AND COALESCE(note, '') = '' "
    "AND COALESCE(tags_json, '[]') IN ('[]', '') "
    "AND COALESCE(verification_status, 'unverified') IN ('unverified', ''))"
)

EXPECTED_UPDATED_AT_KEY = "expected_updated_at"
# Run-output locator keys echoed back in a conflict so the console finds its row.
_LOCATOR_KEYS = ("collection", "kind", "locator")


class ReviewConflictError(CaseDatabaseError):
    """The stored mark of one or more targets changed since the client read it; nothing was written."""

    def __init__(self, conflicts: list[dict[str, object]]) -> None:
        self.conflicts = conflicts
        super().__init__(
            f"다른 판정이 먼저 저장되어 아무것도 바꾸지 않았습니다(충돌 {len(conflicts)}건). "
            "현재 판정을 확인한 뒤 다시 저장하세요."
        )


def _current_mark(connection: sqlite3.Connection, case_id: str, target_type: str, target_id: str) -> dict[str, object]:
    """The stored mark as a conflict shows it; ``expected_updated_at`` is what the client should send next."""
    row = connection.execute(
        "SELECT status, include_in_report, note, tags_json, reviewer, updated_at, "
        f"{ACTIVE_MARK_SQL} AS active FROM review_mark "
        "WHERE case_id = ? AND target_type = ? AND target_id = ? LIMIT 1",
        (case_id, target_type, target_id),
    ).fetchone()
    if row is None:
        return {
            "exists": False,
            "status": "unreviewed",
            "include_in_report": False,
            "note": "",
            "tags": [],
            "reviewer": "",
            "updated_at": "",
            EXPECTED_UPDATED_AT_KEY: "",
        }
    try:
        tags = json.loads(str(row["tags_json"] or "[]"))
    except json.JSONDecodeError:
        tags = []
    active = bool(row["active"])
    updated_at = str(row["updated_at"] or "")
    return {
        # A cleared mark is "no mark" for the board (it is not in the review map), so its token is "".
        "exists": active,
        "status": str(row["status"] or "unreviewed"),
        "include_in_report": bool(row["include_in_report"]),
        "note": str(row["note"] or ""),
        "tags": [str(tag) for tag in tags] if isinstance(tags, list) else [],
        "reviewer": str(row["reviewer"] or ""),
        "updated_at": updated_at,
        EXPECTED_UPDATED_AT_KEY: updated_at if active else "",
    }


def review_conflicts(
    connection: sqlite3.Connection,
    case_id: str,
    targets: Iterable[Mapping[str, object]],
) -> list[dict[str, object]]:
    """Targets whose ``expected_updated_at`` no longer matches the stored mark (targets without one never conflict)."""
    conflicts: list[dict[str, object]] = []
    for target in targets:
        expected = target.get(EXPECTED_UPDATED_AT_KEY)
        if expected is None:
            continue
        target_type = str(target.get("target_type") or "")
        target_id = str(target.get("target_id") or "")
        current = _current_mark(connection, case_id, target_type, target_id)
        if current[EXPECTED_UPDATED_AT_KEY] == str(expected):
            continue
        conflict: dict[str, object] = {
            "target_type": target_type,
            "target_id": target_id,
            EXPECTED_UPDATED_AT_KEY: str(expected),
            "current": current,
        }
        for key in _LOCATOR_KEYS:
            if target.get(key) is not None:
                conflict[key] = str(target[key])
        conflicts.append(conflict)
    return conflicts
