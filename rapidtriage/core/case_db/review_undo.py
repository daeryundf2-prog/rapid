"""Undo writes in the review history (design viewer-keys re-review P2).

The console's Z puts a row back to the review state it had before a verdict. The write is
an ordinary mark write: the stored mark's ``reviewer`` / ``status_by`` / ``status_at`` become
the examiner who pressed Z and that time (forensic rule: the actor is whoever wrote). So the
history still says what happened, a Z write carries, per target, ``undo_of_version`` -- the
history version of the verdict it undoes -- and its ``review_mark_history`` row records:

* ``kind`` -- ``"undo"`` (``""`` for every other write);
* ``undone_version`` -- that version;
* ``undone_reviewer`` -- the actor of that version (``""`` when the version is unknown).

Schema extension (idempotent): the columns are added to existing DBs; older rows keep the
defaults (no backfill: an undo was not recorded before). A read-only DB not migrated yet
reads as if every row were an ordinary write.
"""

from __future__ import annotations

import sqlite3

from .base import CaseDatabaseError
from .review_conflict import EXPECTATION_KEYS
from .schema import register_schema_extension

__all__ = [
    "TARGET_CARRIED_KEYS",
    "UNDO_KIND",
    "UNDO_OF_VERSION_KEY",
    "ensure_review_undo_columns",
    "history_undo_select_sql",
    "undo_detail",
    "verdict_undo",
]

UNDO_OF_VERSION_KEY = "undo_of_version"
UNDO_KIND = "undo"
# Per-target keys a batch request carries through locator resolution to the write.
TARGET_CARRIED_KEYS = (*EXPECTATION_KEYS, UNDO_OF_VERSION_KEY)

_COLUMNS = (
    ("kind", "TEXT NOT NULL DEFAULT ''"),
    ("undone_version", "INTEGER"),
    ("undone_reviewer", "TEXT NOT NULL DEFAULT ''"),
)


def _history_columns(connection: sqlite3.Connection) -> set[str]:
    return {str(row[1]) for row in connection.execute("PRAGMA table_info(review_mark_history)")}


def ensure_review_undo_columns(connection: sqlite3.Connection) -> None:
    """Add ``kind`` / ``undone_version`` / ``undone_reviewer`` to ``review_mark_history``."""
    present = _history_columns(connection)
    if not present:
        return
    for column, definition in _COLUMNS:
        if column in present:
            continue
        try:
            connection.execute(f"ALTER TABLE review_mark_history ADD COLUMN {column} {definition}")
        except sqlite3.OperationalError as exc:
            # Another connection added it between the check and the ALTER (concurrent first open).
            if "duplicate column" not in str(exc).lower():
                raise


def history_undo_select_sql(connection: sqlite3.Connection) -> str:
    """``kind, undone_version, undone_reviewer`` of a history row (defaults before the migration)."""
    if {name for name, _ in _COLUMNS} <= _history_columns(connection):
        return "kind, undone_version, undone_reviewer"
    return "'' AS kind, NULL AS undone_version, '' AS undone_reviewer"


def undo_detail(
    connection: sqlite3.Connection, case_id: str, target_type: str, target_id: str, raw: object
) -> dict[str, object] | None:
    """The undo record of a target's ``undo_of_version`` (``None`` when the write is no undo)."""
    if raw is None or raw == "":
        return None
    if isinstance(raw, bool) or not (
        (isinstance(raw, int) and raw >= 1) or (isinstance(raw, str) and raw.isdigit() and int(raw) >= 1)
    ):
        raise CaseDatabaseError("undo_of_version must be a positive integer")
    version = int(raw)
    row = connection.execute(
        "SELECT actor FROM review_mark_history WHERE case_id = ? AND target_type = ? AND target_id = ? "
        "AND version = ? LIMIT 1",
        (case_id, target_type, target_id, version),
    ).fetchone()
    return {"kind": UNDO_KIND, "undone_version": version, "undone_reviewer": str(row[0] or "") if row else ""}


register_schema_extension(ensure_review_undo_columns)


def verdict_undo(
    connection: sqlite3.Connection, case_id: str, target_type: str, target_id: str
) -> dict[str, object] | None:
    """``{undone_version, undone_reviewer}`` when the mark's current verdict was set by a Z write.

    The verdict-setting write is the newest history version whose changed fields name ``status``
    (the review board's 판정자 tooltip says "되돌림 (원래 판정: lee v3)"); ``None`` otherwise.
    """
    if not {name for name, _ in _COLUMNS} <= _history_columns(connection):
        return None
    row = connection.execute(
        "SELECT kind, undone_version, undone_reviewer FROM review_mark_history "
        "WHERE case_id = ? AND target_type = ? AND target_id = ? AND changed_fields_json LIKE '%\"status\"%' "
        "ORDER BY version DESC LIMIT 1",
        (case_id, target_type, target_id),
    ).fetchone()
    if row is None or str(row[0] or "") != UNDO_KIND or row[1] is None:
        return None
    return {"undone_version": int(row[1]), "undone_reviewer": str(row[2] or "")}