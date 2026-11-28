"""Optimistic concurrency of review marks (design review F14).

Every mark has a version token: its newest ``review_mark_history`` version (a
per-target counter every write bumps inside the write transaction), or ``0``
when there is no mark or the mark is cleared. A console write may carry, per
target, the token of the mark the examiner saw (``expected_version``; ``0`` =
"I saw no mark"). When the stored mark changed since, the write is refused with
the current mark and what changed, instead of silently overwriting another
examiner's decision. A batch is all-or-nothing: every expectation is checked
inside the write transaction before anything is written. Writes without an
expectation behave as before.

``expected_updated_at`` (the mark's ``updated_at`` text, ``""`` = no mark) is
still accepted from older clients; the counter is preferred because two writes
within one clock tick share an ``updated_at`` (review P3-1).
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Mapping

from .base import CaseDatabaseError
from .review_verdict import verdict_select_sql

__all__ = [
    "ACTIVE_MARK_SQL",
    "EXPECTATION_KEYS",
    "EXPECTED_UPDATED_AT_KEY",
    "EXPECTED_VERSION_KEY",
    "ReviewConflictError",
    "mark_version",
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

EXPECTED_VERSION_KEY = "expected_version"
EXPECTED_UPDATED_AT_KEY = "expected_updated_at"
# The keys a write target carries its expectation in (the version first).
EXPECTATION_KEYS = (EXPECTED_VERSION_KEY, EXPECTED_UPDATED_AT_KEY)
# Run-output locator keys echoed back in a conflict so the console finds its row.
_LOCATOR_KEYS = ("collection", "kind", "locator")
# History versions a conflict lists (newest first).
_CHANGES_LIMIT = 20
_HISTORY_VERSION_SQL = (
    "(SELECT COALESCE(MAX(h.version), 0) FROM review_mark_history h WHERE h.case_id = review_mark.case_id "
    "AND h.target_type = review_mark.target_type AND h.target_id = review_mark.target_id)"
)


class ReviewConflictError(CaseDatabaseError):
    """The stored mark of one or more targets changed since the client read it; nothing was written."""

    def __init__(self, conflicts: list[dict[str, object]]) -> None:
        self.conflicts = conflicts
        super().__init__(
            f"다른 판정이 먼저 저장되어 아무것도 바꾸지 않았습니다(충돌 {len(conflicts)}건). "
            "현재 판정을 확인한 뒤 다시 저장하세요."
        )


def _expected_version(value: object) -> int:
    """An ``expected_version`` as sent (int or digit string); anything else is a 400."""
    if isinstance(value, bool):
        raise CaseDatabaseError("expected_version must be a non-negative integer")
    if isinstance(value, int) and value >= 0:
        return value
    text = str(value).strip()
    if text.isdigit():
        return int(text)
    raise CaseDatabaseError("expected_version must be a non-negative integer")


def _mark_row(connection: sqlite3.Connection, case_id: str, target_type: str, target_id: str) -> sqlite3.Row | None:
    return connection.execute(
        "SELECT status, include_in_report, note, tags_json, reviewer, updated_at, "
        f"{verdict_select_sql(connection)}, {_HISTORY_VERSION_SQL} AS history_version, "
        f"{ACTIVE_MARK_SQL} AS active FROM review_mark "
        "WHERE case_id = ? AND target_type = ? AND target_id = ? LIMIT 1",
        (case_id, target_type, target_id),
    ).fetchone()


def mark_version(connection: sqlite3.Connection, case_id: str, target_type: str, target_id: str) -> int:
    """The mark's version token: its newest history version, ``0`` for no mark or a cleared one."""
    row = _mark_row(connection, case_id, target_type, target_id)
    return int(row["history_version"] or 0) if row is not None and row["active"] else 0


def _current_mark(connection: sqlite3.Connection, case_id: str, target_type: str, target_id: str) -> dict[str, object]:
    """The stored mark as a conflict shows it; ``version`` / ``expected_updated_at`` are what to send next."""
    row = _mark_row(connection, case_id, target_type, target_id)
    if row is None:
        return {
            "exists": False,
            "status": "unreviewed",
            "include_in_report": False,
            "note": "",
            "tags": [],
            "reviewer": "",
            "updated_at": "",
            "status_by": "",
            "status_at": "",
            "version": 0,
            EXPECTED_UPDATED_AT_KEY: "",
        }
    try:
        tags = json.loads(str(row["tags_json"] or "[]"))
    except json.JSONDecodeError:
        tags = []
    active = bool(row["active"])
    updated_at = str(row["updated_at"] or "")
    return {
        # A cleared mark is "no mark" for the board (it is not in the review map), so its token is 0 / "".
        "exists": active,
        "status": str(row["status"] or "unreviewed"),
        "include_in_report": bool(row["include_in_report"]),
        "note": str(row["note"] or ""),
        "tags": [str(tag) for tag in tags] if isinstance(tags, list) else [],
        "reviewer": str(row["reviewer"] or ""),
        "updated_at": updated_at,
        "status_by": str(row["status_by"] or ""),
        "status_at": str(row["status_at"] or ""),
        "version": int(row["history_version"] or 0) if active else 0,
        EXPECTED_UPDATED_AT_KEY: updated_at if active else "",
    }


def _snapshot_active(snapshot: Mapping[str, object]) -> bool:
    """``ACTIVE_MARK_SQL`` over a history ``current_json`` snapshot."""
    return not (
        str(snapshot.get("status") or "unreviewed") == "unreviewed"
        and not snapshot.get("include_in_report")
        and not str(snapshot.get("note") or "")
        and not snapshot.get("tags")
        and str(snapshot.get("verification_status") or "unverified") in ("unverified", "")
    )


def _changes_since(
    connection: sqlite3.Connection,
    case_id: str,
    target_type: str,
    target_id: str,
    after_version: int | None,
) -> list[dict[str, object]]:
    """History versions after ``after_version``, newest first: who, when, which fields (review P3-4).

    ``0`` ("no mark seen") lists the versions since the mark was last cleared; ``None``
    (an ``expected_updated_at`` the history does not know) lists nothing.
    """
    if after_version is None:
        return []
    rows = connection.execute(
        "SELECT version, actor, changed_at, changed_fields_json, current_json FROM review_mark_history "
        "WHERE case_id = ? AND target_type = ? AND target_id = ? AND version > ? ORDER BY version DESC LIMIT ?",
        (case_id, target_type, target_id, after_version, _CHANGES_LIMIT),
    ).fetchall()
    changes: list[dict[str, object]] = []
    for row in rows:
        try:
            fields = json.loads(str(row["changed_fields_json"] or "[]"))
            snapshot = json.loads(str(row["current_json"] or "{}"))
        except json.JSONDecodeError:
            fields, snapshot = [], {}
        if after_version == 0 and isinstance(snapshot, Mapping) and not _snapshot_active(snapshot):
            break
        changes.append(
            {
                "version": int(row["version"]),
                "actor": str(row["actor"] or ""),
                "changed_at": str(row["changed_at"] or ""),
                # Every write re-stamps ``reviewer``; it is who wrote, not what changed.
                "fields": [str(field) for field in fields if field != "reviewer"] if isinstance(fields, list) else [],
            }
        )
    return changes


def _version_at(connection: sqlite3.Connection, case_id: str, target_type: str, target_id: str, at: str) -> int | None:
    """The history version an old client's ``expected_updated_at`` names (``""`` = no mark = 0)."""
    if not at:
        return 0
    row = connection.execute(
        "SELECT MAX(version) FROM review_mark_history WHERE case_id = ? AND target_type = ? AND target_id = ? "
        "AND changed_at = ?",
        (case_id, target_type, target_id, at),
    ).fetchone()
    return int(row[0]) if row is not None and row[0] is not None else None


def review_conflicts(
    connection: sqlite3.Connection,
    case_id: str,
    targets: Iterable[Mapping[str, object]],
) -> list[dict[str, object]]:
    """Targets whose expectation no longer matches the stored mark (targets without one never conflict).

    ``expected_version`` is compared with the version token; without it, ``expected_updated_at``
    with the mark's ``updated_at`` (older clients).
    """
    conflicts: list[dict[str, object]] = []
    for target in targets:
        raw_version = target.get(EXPECTED_VERSION_KEY)
        expected_at = target.get(EXPECTED_UPDATED_AT_KEY)
        if raw_version is None and expected_at is None:
            continue
        target_type = str(target.get("target_type") or "")
        target_id = str(target.get("target_id") or "")
        current = _current_mark(connection, case_id, target_type, target_id)
        conflict: dict[str, object] = {"target_type": target_type, "target_id": target_id}
        if raw_version is not None:
            expected_version = _expected_version(raw_version)
            if current["version"] == expected_version:
                continue
            conflict[EXPECTED_VERSION_KEY] = expected_version
            seen: int | None = expected_version
        else:
            if current[EXPECTED_UPDATED_AT_KEY] == str(expected_at):
                continue
            conflict[EXPECTED_UPDATED_AT_KEY] = str(expected_at)
            seen = _version_at(connection, case_id, target_type, target_id, str(expected_at))
        current["changes"] = _changes_since(connection, case_id, target_type, target_id, seen)
        conflict["current"] = current
        for key in _LOCATOR_KEYS:
            if target.get(key) is not None:
                conflict[key] = str(target[key])
        conflicts.append(conflict)
    return conflicts
