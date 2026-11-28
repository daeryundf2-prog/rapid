"""Who set a review mark's verdict, and when (design review P2-1).

``review_mark.reviewer`` / ``updated_at`` name the *last writer* of any field: a
note, a tag or the report flag moves them too. The review board's 판정자 /
판정 시각 and the conflict prompt need the person who set the current verdict
(``status``), so the mark keeps it apart:

* ``review_mark.status_by`` -- the actor of the last write that changed ``status``;
* ``review_mark.status_at`` -- that write's time.

A first write that creates a mark with no verdict (``unreviewed``: a note or a
tag only) sets neither. Migration (first apply on a DB without the columns):
both are filled from ``review_mark_history`` -- the newest version whose
``changed_fields`` names ``status`` under the same rule. Marks with no such
history keep ``""``. Registered as a schema extension, idempotent.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping

from .schema import register_schema_extension

__all__ = [
    "VERDICT_COLUMNS",
    "ensure_review_verdict_columns",
    "verdict_changed",
    "verdict_select_sql",
]

VERDICT_COLUMNS = ("status_by", "status_at")


def verdict_changed(previous: Mapping[str, object], current_status: str) -> bool:
    """True when a write sets the verdict: ``status`` changed, except a new mark created without one."""
    if not previous:
        return current_status != "unreviewed"
    return previous.get("status") != current_status


def _history_sql(column: str, mark: str) -> str:
    """``column`` (``actor`` / ``changed_at``) of the newest history version that set the mark's verdict."""
    return (
        f"COALESCE((SELECT h.{column} FROM review_mark_history h "
        f"WHERE h.case_id = {mark}.case_id AND h.target_type = {mark}.target_type AND h.target_id = {mark}.target_id "
        "AND EXISTS (SELECT 1 FROM json_each(CASE WHEN json_valid(h.changed_fields_json) "
        "THEN h.changed_fields_json ELSE '[]' END) AS f WHERE f.value = 'status') "
        "AND NOT ((CASE WHEN json_valid(h.previous_json) THEN json_extract(h.previous_json, '$.status') END) IS NULL "
        "AND (CASE WHEN json_valid(h.current_json) THEN json_extract(h.current_json, '$.status') END) = 'unreviewed') "
        "ORDER BY h.version DESC LIMIT 1), '')"
    )


def _has_verdict_columns(connection: sqlite3.Connection) -> bool:
    columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(review_mark)")}
    return set(VERDICT_COLUMNS) <= columns


def verdict_select_sql(connection: sqlite3.Connection, mark: str = "review_mark") -> str:
    """``status_by, status_at`` of ``mark``; a read-only DB not migrated yet derives them from the history."""
    if _has_verdict_columns(connection):
        return f"{mark}.status_by, {mark}.status_at"
    return f"{_history_sql('actor', mark)} AS status_by, {_history_sql('changed_at', mark)} AS status_at"


def ensure_review_verdict_columns(connection: sqlite3.Connection) -> None:
    """Add ``status_by`` / ``status_at`` and fill them from the history (cheap once applied)."""
    if _has_verdict_columns(connection):
        return
    for column in VERDICT_COLUMNS:
        try:
            connection.execute(f"ALTER TABLE review_mark ADD COLUMN {column} TEXT NOT NULL DEFAULT ''")
        except sqlite3.OperationalError as exc:
            # Another connection added it between the check and the ALTER (concurrent first open).
            if "duplicate column" not in str(exc).lower():
                raise
    # Only rows never filled, so it is safe after a lost race too.
    connection.execute(
        f"UPDATE review_mark SET status_by = {_history_sql('actor', 'review_mark')}, "
        f"status_at = {_history_sql('changed_at', 'review_mark')} WHERE status_at = ''"
    )


register_schema_extension(ensure_review_verdict_columns)
