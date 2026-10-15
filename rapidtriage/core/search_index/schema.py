"""Search index schema (plan §3.0) and connection helpers.

Deviations from the plan text (documented in docs/plans/search-2026-10-13.md §3.0):

* ``search_text`` is one FTS5 column ``text`` (external content
  ``search_doc.text``) holding ``title\\npath\\nbody``; ``detail=none`` keeps
  the trigram index small. Substring search uses ``LIKE`` (the trigram index
  serves it, SQLite re-checks every candidate), never ``MATCH`` phrases.
* Rows that repeat a source row for another timestamp (``ts_kind``) keep
  ``text`` NULL and point at the primary row through ``group_id``; only the
  primary row is in the FTS index (results collapse by ``group_id``).
* The database is written with ``journal_mode=DELETE`` (one file, read with
  ``mode=ro``; WAL would need a writable ``-shm`` next to a read-only open).
  Readers wait up to ``READ_BUSY_MS`` for a commit's lock; an incremental
  writer waits up to ``WRITE_BUSY_MS`` for readers (longer than a query's
  budget + grace).
* ``path2``/``path2_fold``: the row's target path (LNK/Jump List target,
  Prefetch executable, Amcache/ShimCache/BAM executable, download target);
  ``path:``/``under:`` match ``path_fold`` or ``path2_fold``.
* ``truncated``: 1 when any value, list or the row text was cut at a cap
  (counted per field in ``summary.skipped`` / ``summary.skipped_fields``).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

INDEX_FILE_NAME = "rapidtriage-search.db"
BUILDING_SUFFIX = ".building"
INDEX_VERSION = "search-index-v2"
# Bump when the flattening rules change: an index of an older rule set is stale.
FLATTEN_VERSION = "flatten-v2"

TOKENIZER_TRIGRAM = "trigram"
TOKENIZER_FALLBACK = "unicode61"
# One query's wall-clock budget and the grace after it (engine); index swaps and
# incremental commits wait longer than both for readers to let go.
QUERY_BUDGET_SECONDS = 15.0
QUERY_GRACE_SECONDS = 3.0
READ_BUSY_MS = 5000
WRITE_BUSY_MS = 25_000

SCHEMA_TABLES = """
CREATE TABLE IF NOT EXISTS search_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS search_doc (
    doc_id INTEGER PRIMARY KEY,
    group_id INTEGER NOT NULL,
    collection TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT '',
    locator TEXT NOT NULL,
    analysis_id TEXT NOT NULL DEFAULT '',
    domain TEXT NOT NULL DEFAULT '',
    artifact_type TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '',
    path_fold TEXT NOT NULL DEFAULT '',
    path2 TEXT NOT NULL DEFAULT '',
    path2_fold TEXT NOT NULL DEFAULT '',
    ext TEXT NOT NULL DEFAULT '',
    size INTEGER,
    ts INTEGER,
    ts_kind TEXT NOT NULL DEFAULT '',
    ts_family TEXT NOT NULL DEFAULT '',
    ts_labels TEXT NOT NULL DEFAULT '',
    actor TEXT NOT NULL DEFAULT '',
    actor_sid TEXT NOT NULL DEFAULT '',
    computer TEXT NOT NULL DEFAULT '',
    md5 TEXT NOT NULL DEFAULT '',
    sha1 TEXT NOT NULL DEFAULT '',
    sha256 TEXT NOT NULL DEFAULT '',
    text TEXT,
    fields_json TEXT NOT NULL DEFAULT '{}',
    deleted INTEGER NOT NULL DEFAULT 0,
    sig_mismatch INTEGER NOT NULL DEFAULT 0,
    in_archive INTEGER NOT NULL DEFAULT 0,
    pii_count INTEGER NOT NULL DEFAULT 0,
    truncated INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS search_field (
    doc_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    value_fold TEXT NOT NULL DEFAULT '',
    value_int INTEGER
);
CREATE TABLE IF NOT EXISTS search_hash (
    algorithm TEXT NOT NULL,
    value TEXT NOT NULL,
    doc_id INTEGER NOT NULL
);
-- S3 (위치/미디어): created now so the schema is stable; filled in S3.
CREATE TABLE IF NOT EXISTS search_geo (
    doc_id INTEGER NOT NULL,
    lat REAL,
    lon REAL,
    make TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
    taken_ts INTEGER,
    phash INTEGER
);
-- S2 (신원·PII): PII rows keep value_fold empty and only an HMAC.
CREATE TABLE IF NOT EXISTS search_ident (
    doc_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    value_fold TEXT NOT NULL DEFAULT '',
    masked TEXT NOT NULL DEFAULT '',
    hmac TEXT NOT NULL DEFAULT ''
);
"""

SCHEMA_INDEXES = """
CREATE INDEX IF NOT EXISTS search_doc_ts ON search_doc(ts);
CREATE INDEX IF NOT EXISTS search_doc_domain_ts ON search_doc(domain, ts);
CREATE INDEX IF NOT EXISTS search_doc_path_fold ON search_doc(path_fold);
CREATE INDEX IF NOT EXISTS search_doc_path2_fold ON search_doc(path2_fold);
CREATE INDEX IF NOT EXISTS search_doc_actor ON search_doc(actor);
CREATE INDEX IF NOT EXISTS search_doc_computer ON search_doc(computer);
CREATE INDEX IF NOT EXISTS search_doc_artifact_type ON search_doc(artifact_type);
CREATE INDEX IF NOT EXISTS search_doc_analysis_id ON search_doc(analysis_id);
CREATE INDEX IF NOT EXISTS search_doc_group ON search_doc(group_id);
CREATE INDEX IF NOT EXISTS search_doc_locator ON search_doc(locator, collection, kind);
CREATE INDEX IF NOT EXISTS search_field_name_value ON search_field(name, value_fold);
CREATE INDEX IF NOT EXISTS search_field_name_int ON search_field(name, value_int);
CREATE INDEX IF NOT EXISTS search_field_doc ON search_field(doc_id);
CREATE INDEX IF NOT EXISTS search_hash_value ON search_hash(algorithm, value);
CREATE INDEX IF NOT EXISTS search_hash_doc ON search_hash(doc_id);
"""


def index_path_for(output_dir: Path | str) -> Path:
    return Path(output_dir) / INDEX_FILE_NAME


def sqlite_version_tuple() -> tuple[int, ...]:
    return tuple(int(part) for part in sqlite3.sqlite_version.split(".")[:3])


def detect_tokenizer() -> str:
    """``trigram`` when this SQLite has it (>= 3.34 with FTS5), else ``unicode61``."""
    if sqlite_version_tuple() < (3, 34, 0):
        return TOKENIZER_FALLBACK
    probe = sqlite3.connect(":memory:")
    try:
        probe.execute("CREATE VIRTUAL TABLE probe USING fts5(x, tokenize='trigram', detail=none)")
    except sqlite3.Error:
        return TOKENIZER_FALLBACK
    finally:
        probe.close()
    return TOKENIZER_TRIGRAM


def fts_sql(tokenizer: str) -> str:
    if tokenizer == TOKENIZER_TRIGRAM:
        options = "tokenize='trigram', detail=none"
    else:
        options = "tokenize='unicode61 remove_diacritics 0'"
    # Identifiers are constants: the tokenizer is one of two literals above.
    return f"CREATE VIRTUAL TABLE IF NOT EXISTS search_text USING fts5(text, content='search_doc', content_rowid='doc_id', {options})"


def create_schema(connection: sqlite3.Connection, tokenizer: str, *, with_indexes: bool) -> None:
    connection.executescript(SCHEMA_TABLES)
    connection.execute(fts_sql(tokenizer))
    if with_indexes:
        connection.executescript(SCHEMA_INDEXES)


def create_indexes(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA_INDEXES)


def open_read_only(path: Path) -> sqlite3.Connection:
    """Read-only connection (``mode=ro``); ``uri=True`` so hash sets can be ATTACHed read-only too."""
    connection = sqlite3.connect(
        f"{Path(path).resolve().as_uri()}?mode=ro", uri=True, check_same_thread=False, timeout=READ_BUSY_MS / 1000
    )
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA temp_store = MEMORY")
        connection.execute("PRAGMA cache_size = -65536")
    except sqlite3.Error:
        connection.close()  # never leave a handle on a corrupt file (Windows could not replace it)
        raise
    return connection


def open_writable(path: Path, *, bulk: bool) -> sqlite3.Connection:
    """``bulk``: a fresh ``.building`` file; otherwise an in-place update that waits for readers."""
    connection = sqlite3.connect(str(path), check_same_thread=False, timeout=WRITE_BUSY_MS / 1000)
    connection.row_factory = sqlite3.Row
    if bulk:
        # A fresh .building file: a crash leaves a file the next build deletes.
        connection.execute("PRAGMA journal_mode = OFF")
        connection.execute("PRAGMA synchronous = OFF")
    else:
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("PRAGMA synchronous = NORMAL")
    connection.execute("PRAGMA temp_store = MEMORY")
    connection.execute("PRAGMA cache_size = -262144")
    return connection


def read_meta(connection: sqlite3.Connection) -> dict[str, str]:
    try:
        return {str(row[0]): str(row[1]) for row in connection.execute("SELECT key, value FROM search_meta")}
    except sqlite3.Error:
        return {}


def write_meta(connection: sqlite3.Connection, values: dict[str, object]) -> None:
    connection.executemany(
        "INSERT INTO search_meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [(key, value if isinstance(value, str) else _json(value)) for key, value in values.items()],
    )


def _json(value: object) -> str:
    import json

    return json.dumps(value, ensure_ascii=False, sort_keys=True)
