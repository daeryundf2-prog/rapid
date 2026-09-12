"""Schema bootstrap and inspection helpers."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

from .base import (
    CaseDatabaseError,
)
from .constants import (
    SCHEMA_SQL,
    SCHEMA_VERSION,
)

__all__ = [
    "apply_schema",
    "assert_supported_existing_schema_version",
    "ensure_case_exists",
    "ensure_column",
    "get_schema_version",
    "list_tables",
    "table_columns",
]

def apply_schema(connection: sqlite3.Connection) -> None:
    current_version = get_schema_version(connection)
    if current_version not in (0, SCHEMA_VERSION):
        raise CaseDatabaseError(f"unsupported case DB schema version: {current_version}")
    connection.executescript(SCHEMA_SQL)
    ensure_column(connection, "review_mark", "assignee", "TEXT NOT NULL DEFAULT ''")
    ensure_column(connection, "review_mark", "priority", "TEXT NOT NULL DEFAULT 'normal'")
    ensure_column(connection, "review_mark", "due_at", "TEXT NOT NULL DEFAULT ''")
    ensure_column(connection, "review_mark", "source_citation_package_json", "TEXT NOT NULL DEFAULT '{}'")
    connection.execute(
        """
        INSERT INTO schema_info (key, value)
        VALUES ('schema_version', ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """,
        (str(SCHEMA_VERSION),),
    )


def assert_supported_existing_schema_version(path: Path) -> None:
    if not path.exists():
        return
    try:
        uri = f"file:{path}?mode=ro"
        # sqlite3.Connection's context manager commits instead of closing;
        # use closing() so the read-only handle does not keep case.db locked
        # (which breaks temp-dir cleanup on Windows).
        with closing(sqlite3.connect(uri, uri=True)) as connection:
            connection.row_factory = sqlite3.Row
            table_count_row = connection.execute(
                "SELECT count(*) AS count FROM sqlite_master WHERE type = 'table'"
            ).fetchone()
            table_count = int(table_count_row["count"]) if table_count_row is not None else 0
            if not table_count:
                return
            has_schema_info = connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'schema_info'"
            ).fetchone()
            if has_schema_info is None:
                raise CaseDatabaseError("unsupported case DB schema version: unversioned database")
            version = connection.execute("SELECT value FROM schema_info WHERE key = 'schema_version'").fetchone()
            current_version = int(version["value"]) if version is not None else 0
    except sqlite3.DatabaseError as exc:
        raise CaseDatabaseError(f"unsupported case DB file: {exc}") from exc
    if current_version not in (0, SCHEMA_VERSION):
        raise CaseDatabaseError(f"unsupported case DB schema version: {current_version}")


def ensure_column(connection: sqlite3.Connection, table_name: str, column_name: str, definition: str) -> None:
    columns = {str(row["name"]) for row in connection.execute(f"PRAGMA table_info({table_name})")}
    if column_name not in columns:
        connection.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}")


def get_schema_version(connection: sqlite3.Connection) -> int:
    row = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'schema_info'"
    ).fetchone()
    if row is None:
        return 0
    version = connection.execute("SELECT value FROM schema_info WHERE key = 'schema_version'").fetchone()
    return int(version["value"]) if version is not None else 0


def list_tables(connection: sqlite3.Connection) -> list[str]:
    rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    return [str(row["name"]) for row in rows]


def table_columns(connection: sqlite3.Connection, table_name: str) -> list[str]:
    return [str(row["name"]) for row in connection.execute(f"PRAGMA table_info({table_name})")]


def ensure_case_exists(connection: sqlite3.Connection, case_id: str) -> None:
    if connection.execute("SELECT 1 FROM case_record WHERE case_id = ?", (case_id,)).fetchone() is None:
        raise CaseDatabaseError(f"case not found: {case_id}")
