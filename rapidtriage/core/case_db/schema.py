"""Schema bootstrap and inspection helpers."""

from __future__ import annotations

import json
import sqlite3
import zlib
from collections.abc import Mapping
from contextlib import closing
from pathlib import Path

from ..textnorm import normalize_nfc
from .base import (
    CaseDatabaseError,
)
from .constants import (
    ARTIFACT_FTS_SOURCE_VIEW,
    SCHEMA_SQL,
    SCHEMA_SQL_COMPRESSED_ARTIFACTS,
    SCHEMA_VERSION,
)
from .intake import apply_intake_schema

__all__ = [
    "ARTIFACT_DATA_CODEC_NONE",
    "ARTIFACT_DATA_CODEC_ZLIB",
    "ARTIFACT_DATA_ZLIB_LEVEL",
    "DOCUMENT_TRIGRAM_TABLE",
    "apply_schema",
    "artifact_data_select_sql",
    "artifact_fts_is_external",
    "artifact_row_data_json",
    "assert_supported_existing_schema_version",
    "decode_artifact_data",
    "document_trigram_available",
    "encode_artifact_data",
    "ensure_case_exists",
    "ensure_column",
    "ensure_document_trigram_index",
    "get_schema_version",
    "insert_document_trigram_row",
    "list_tables",
    "register_case_db_functions",
    "sqlite_supports_trigram",
    "table_columns",
]

REVIEW_MARK_MIGRATION_COLUMNS = ("assignee", "priority", "due_at", "source_citation_package_json")


def apply_schema(connection: sqlite3.Connection, *, compressed_artifacts: bool = False) -> None:
    """Create or migrate the case DB schema.

    ``compressed_artifacts`` only matters for a DB without tables yet (the
    run persist step's fresh, disposable DB): it is then created with the
    compressed artifact layout (``SCHEMA_SQL_COMPRESSED_ARTIFACTS``). An
    existing DB keeps the artifact layout it was created with.
    """
    current_version = get_schema_version(connection)
    if current_version not in (0, SCHEMA_VERSION):
        raise CaseDatabaseError(f"unsupported case DB schema version: {current_version}")
    if current_version == SCHEMA_VERSION:
        review_mark_columns = {
            str(row["name"]) for row in connection.execute("PRAGMA table_info(review_mark)")
        }
        artifact_columns = {str(row["name"]) for row in connection.execute("PRAGMA table_info(artifact)")}
        if set(REVIEW_MARK_MIGRATION_COLUMNS) <= review_mark_columns and set(ARTIFACT_DATA_COLUMNS) <= artifact_columns:
            # Current schema: no writes (read-only/ACL-locked run DBs keep opening). The case
            # intake columns/tables are migrated by the workspace DB (ensure_intake_schema).
            return
    fresh = current_version == 0 and not connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'artifact'"
    ).fetchone()
    connection.executescript(SCHEMA_SQL_COMPRESSED_ARTIFACTS if compressed_artifacts and fresh else SCHEMA_SQL)
    ensure_column(connection, "artifact", "data_blob", "BLOB")
    ensure_column(connection, "artifact", "data_codec", "TEXT NOT NULL DEFAULT ''")
    ensure_document_trigram_index(connection)
    ensure_column(connection, "review_mark", "assignee", "TEXT NOT NULL DEFAULT ''")
    ensure_column(connection, "review_mark", "priority", "TEXT NOT NULL DEFAULT 'normal'")
    ensure_column(connection, "review_mark", "due_at", "TEXT NOT NULL DEFAULT ''")
    ensure_column(connection, "review_mark", "source_citation_package_json", "TEXT NOT NULL DEFAULT '{}'")
    apply_intake_schema(connection)
    connection.execute(
        """
        INSERT INTO schema_info (key, value)
        VALUES ('schema_version', ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """,
        (str(SCHEMA_VERSION),),
    )


DOCUMENT_TRIGRAM_TABLE = "indexed_document_trigram"

# --- compressed artifact data (parser-quality r2) ---------------------------
#
# A compressed artifact row stores its data_json text zlib-compressed in
# ``data_blob`` with ``data_codec = 'zlib'``; ``data_json`` then holds only
# the ``source_locator`` stub, so SQL json_extract(data_json,
# '$.source_locator...') lookups keep working without decoding. Every
# reader of the full data goes through artifact_row_data_json() (Python) or
# rt_artifact_data() (SQL), selected with artifact_data_select_sql().
ARTIFACT_DATA_CODEC_NONE = ""
ARTIFACT_DATA_CODEC_ZLIB = "zlib"
ARTIFACT_DATA_ZLIB_LEVEL = 1
ARTIFACT_DATA_COLUMNS = ("data_blob", "data_codec")
ARTIFACT_DATA_LOCATOR_KEY = "source_locator"


def encode_artifact_data(data_json: str, *, locator: Mapping[str, object] | None = None) -> tuple[str, bytes, str]:
    """``(data_json stub, data_blob, data_codec)`` for a compressed artifact row."""
    stub = (
        json.dumps({ARTIFACT_DATA_LOCATOR_KEY: dict(locator)}, ensure_ascii=False, sort_keys=True)
        if locator
        else "{}"
    )
    return stub, zlib.compress(data_json.encode("utf-8"), ARTIFACT_DATA_ZLIB_LEVEL), ARTIFACT_DATA_CODEC_ZLIB


def decode_artifact_data(data_json: object, data_blob: object = None, data_codec: object = "") -> str:
    """The artifact row's full data_json text, whatever the storage codec."""
    if data_codec == ARTIFACT_DATA_CODEC_ZLIB and data_blob is not None:
        return zlib.decompress(bytes(data_blob)).decode("utf-8")
    if data_codec:
        raise CaseDatabaseError(f"unsupported artifact data codec: {data_codec}")
    return "" if data_json is None else str(data_json)


def artifact_row_data_json(row: Mapping[str, object] | sqlite3.Row) -> str:
    """Full data_json of a fetched artifact row (``sqlite3.Row`` or mapping).

    Rows selected without the codec columns (legacy DBs, or queries that
    did not use artifact_data_select_sql) return ``data_json`` unchanged.
    """
    keys = row.keys()
    if "data_codec" in keys and "data_blob" in keys:
        return decode_artifact_data(row["data_json"], row["data_blob"], row["data_codec"])
    return "" if row["data_json"] is None else str(row["data_json"])


def artifact_data_select_sql(connection: sqlite3.Connection, alias: str = "") -> str:
    """SELECT-list fragment for artifact data: ``data_json, data_blob, data_codec``.

    Older DBs opened read-only (no codec columns yet) get NULL/'' stand-ins,
    so artifact_row_data_json() works on every case DB.
    """
    prefix = f"{alias}." if alias else ""
    columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(artifact)")}
    if set(ARTIFACT_DATA_COLUMNS) <= columns:
        return f"{prefix}data_json AS data_json, {prefix}data_blob AS data_blob, {prefix}data_codec AS data_codec"
    return f"{prefix}data_json AS data_json, NULL AS data_blob, '' AS data_codec"


def _sql_nfc(value: object) -> object:
    return normalize_nfc(value) if isinstance(value, str) else value


def _sql_artifact_data(data_json: object, data_blob: object, data_codec: object) -> str:
    return decode_artifact_data(data_json, data_blob, data_codec or "")


def _sql_artifact_fts_text(data_json: object, data_blob: object, data_codec: object) -> str:
    return normalize_nfc(decode_artifact_data(data_json, data_blob, data_codec or ""))


def register_case_db_functions(connection: sqlite3.Connection) -> None:
    """SQL functions of the compressed artifact layout (view, triggers, readers).

    ``rt_artifact_data(data_json, data_blob, data_codec)`` -> full data_json;
    ``rt_artifact_fts_text(...)`` -> the same in NFC (what artifact_fts
    indexes); ``rt_nfc(text)`` -> NFC text.
    """
    connection.create_function("rt_nfc", 1, _sql_nfc, deterministic=True)
    connection.create_function("rt_artifact_data", 3, _sql_artifact_data, deterministic=True)
    connection.create_function("rt_artifact_fts_text", 3, _sql_artifact_fts_text, deterministic=True)


def artifact_fts_is_external(connection: sqlite3.Connection) -> bool:
    """True when artifact_fts is the external-content index (compressed layout)."""
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'artifact_fts'"
    ).fetchone()
    return row is not None and ARTIFACT_FTS_SOURCE_VIEW in str(row[0] or "")


def sqlite_supports_trigram() -> bool:
    """FTS5 ``trigram`` tokenizer ships with SQLite 3.34.0+."""
    return sqlite3.sqlite_version_info >= (3, 34, 0)


def ensure_document_trigram_index(connection: sqlite3.Connection) -> bool:
    """Create the substring (trigram) index over indexed_document when supported.

    unicode61 splits on whitespace, so Korean words with particles
    ("계약서를") never match "계약서"; the trigram table matches any
    substring of 3+ characters. It complements (does not replace)
    ``indexed_document_fts``: 1-2 character queries still use unicode61
    prefix terms.
    """
    if not sqlite_supports_trigram():
        return False
    try:
        connection.execute(
            f"CREATE VIRTUAL TABLE IF NOT EXISTS {DOCUMENT_TRIGRAM_TABLE} USING fts5("
            "title, body, content='indexed_document', content_rowid='id', tokenize='trigram')"
        )
    except sqlite3.OperationalError:
        return False
    return True


def document_trigram_available(connection: sqlite3.Connection) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (DOCUMENT_TRIGRAM_TABLE,)
    ).fetchone()
    return row is not None


def insert_document_trigram_row(connection: sqlite3.Connection, rowid: int, title: str, body: str) -> None:
    if document_trigram_available(connection):
        connection.execute(
            f"INSERT INTO {DOCUMENT_TRIGRAM_TABLE}(rowid, title, body) VALUES (?, ?, ?)",
            (rowid, title, body),
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
