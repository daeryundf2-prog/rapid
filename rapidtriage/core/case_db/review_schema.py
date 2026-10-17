"""Review-tool tables of the case DB (AXIOM adoption E3, plan §3.3).

Kept apart from ``constants.SCHEMA_SQL`` and registered as a schema
extension (``schema.register_schema_extension``) so it applies on every
``apply_schema`` call, new and existing databases alike:

* ``case_tag`` -- user and system review tags of a case: name (unique per
  case among live tags, case-insensitive), one of the eight ``tag-1``..``tag-8``
  colour tokens, an optional shortcut digit 1-9 (unique per case among live
  tags), description, author and time; deletion is soft (``deleted_at``).
* ``histogram_baseline`` -- saved per-category counts of a run, compared
  later by ``GET /api/runs/{id}/histogram?compare=<id>``.
* ``review_mark.tag_ids_json`` -- the mark's tags as ``case_tag`` ids, the
  canonical link. ``review_mark.tags_json`` keeps the tag *names* in the
  same order as a denormalised mirror: the search filter (``tag:``), reports,
  bundles, the review history diff and the CLI read names, and a rename or a
  delete rewrites both columns in one transaction.

Migration (first apply on a DB without ``tag_ids_json``): every string tag
already on a mark becomes a ``case_tag`` row (``북마크`` and ``우선순위 1``..``5``
as system tags) and the mark gets its id list. Idempotent.
"""

from __future__ import annotations

import json
import sqlite3
import unicodedata
from collections.abc import Iterable, Sequence

from .base import CaseDatabaseError, now_iso
from .schema import register_schema_extension

__all__ = [
    "BOOKMARK_TAG_NAME",
    "COLOR_TOKENS",
    "COLOR_TOKEN_LABELS",
    "PRIORITY_TAG_NAMES",
    "REVIEW_SCHEMA_SQL",
    "SYSTEM_TAGS",
    "TAG_NAME_MAX",
    "ReviewToolError",
    "apply_review_schema",
    "ensure_system_tags",
    "live_tag_rows",
    "migrate_string_tags",
    "next_color_token",
    "normalize_tag_name",
    "resolve_tag_names",
    "sync_review_mark_tag_ids",
    "tag_names_for_ids",
]

COLOR_TOKENS: tuple[str, ...] = tuple(f"tag-{n}" for n in range(1, 9))
COLOR_TOKEN_LABELS: dict[str, str] = {
    "tag-1": "빨강",
    "tag-2": "주황",
    "tag-3": "초록",
    "tag-4": "청록",
    "tag-5": "파랑",
    "tag-6": "보라",
    "tag-7": "자주",
    "tag-8": "회갈색",
}
TAG_NAME_MAX = 60
TAG_DESCRIPTION_MAX = 500
BOOKMARK_TAG_NAME = "북마크"
PRIORITY_TAG_NAMES: tuple[str, ...] = tuple(f"우선순위 {n}" for n in range(1, 6))
# name -> (colour token, shortcut). System tags keep the console's existing keys
# (B = 북마크 command, 1-5 = 우선순위 n) as their default bindings; their name
# cannot change and they cannot be deleted, but colour/shortcut/description can.
SYSTEM_TAGS: dict[str, tuple[str, int | None]] = {
    BOOKMARK_TAG_NAME: ("tag-3", None),
    **{name: (COLOR_TOKENS[index], index + 1) for index, name in enumerate(PRIORITY_TAG_NAMES)},
}


class ReviewToolError(CaseDatabaseError):
    """A Korean, user-facing review-tool error with an HTTP status hint."""

    def __init__(self, message: str, *, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


REVIEW_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS case_tag (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    name TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'user',
    color_token TEXT NOT NULL DEFAULT 'tag-5',
    shortcut INTEGER,
    description TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deleted_at TEXT NOT NULL DEFAULT '',
    deleted_by TEXT NOT NULL DEFAULT '',
    CHECK (kind IN ('user', 'system')),
    CHECK (shortcut IS NULL OR shortcut BETWEEN 1 AND 9),
    FOREIGN KEY (case_id) REFERENCES case_record(case_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_case_tag_live_name
    ON case_tag(case_id, name COLLATE NOCASE) WHERE deleted_at = '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_case_tag_live_shortcut
    ON case_tag(case_id, shortcut) WHERE deleted_at = '' AND shortcut IS NOT NULL;

CREATE TABLE IF NOT EXISTS histogram_baseline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    name TEXT NOT NULL,
    run_id TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    counts_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(case_id, name),
    FOREIGN KEY (case_id) REFERENCES case_record(case_id) ON DELETE CASCADE
);
"""


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")}


def apply_review_schema(connection: sqlite3.Connection) -> None:
    """Create the review-tool tables and migrate string tags (cheap when already applied)."""
    present = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('case_tag', 'histogram_baseline')"
        )
    }
    if len(present) < 2:
        connection.executescript(REVIEW_SCHEMA_SQL)
    if "tag_ids_json" not in _columns(connection, "review_mark"):
        # NULL = not migrated yet; migrate_string_tags fills every row.
        connection.execute("ALTER TABLE review_mark ADD COLUMN tag_ids_json TEXT")
        migrate_string_tags(connection)


def normalize_tag_name(value: object) -> str:
    """NFC, trimmed, inner whitespace collapsed; Korean error when empty/too long/control chars."""
    text = unicodedata.normalize("NFC", str(value or ""))
    text = " ".join(text.split())
    if not text:
        raise ReviewToolError("태그 이름을 입력하세요.", status=422)
    if len(text) > TAG_NAME_MAX:
        raise ReviewToolError(f"태그 이름은 {TAG_NAME_MAX}자 이하여야 합니다.", status=422)
    if any(unicodedata.category(ch).startswith("C") for ch in text):
        raise ReviewToolError("태그 이름에 제어 문자를 쓸 수 없습니다.", status=422)
    return text


def live_tag_rows(connection: sqlite3.Connection, case_id: str) -> list[sqlite3.Row]:
    return connection.execute(
        "SELECT * FROM case_tag WHERE case_id = ? AND deleted_at = '' ORDER BY id", (case_id,)
    ).fetchall()


def next_color_token(connection: sqlite3.Connection, case_id: str) -> str:
    """The least-used colour token among the case's live tags (ties: token order)."""
    used = dict.fromkeys(COLOR_TOKENS, 0)
    for row in connection.execute(
        "SELECT color_token, COUNT(*) FROM case_tag WHERE case_id = ? AND deleted_at = '' GROUP BY color_token",
        (case_id,),
    ):
        if str(row[0]) in used:
            used[str(row[0])] = int(row[1])
    return min(COLOR_TOKENS, key=lambda token: (used[token], COLOR_TOKENS.index(token)))


def _insert_tag(
    connection: sqlite3.Connection,
    case_id: str,
    name: str,
    *,
    actor: str,
    timestamp: str,
) -> int:
    """Insert a tag named ``name``: a system tag when the name is one, else a user tag."""
    system = SYSTEM_TAGS.get(name)
    if system is not None:
        color, shortcut = system
        taken = shortcut is not None and connection.execute(
            "SELECT 1 FROM case_tag WHERE case_id = ? AND deleted_at = '' AND shortcut = ?", (case_id, shortcut)
        ).fetchone()
        cursor = connection.execute(
            "INSERT INTO case_tag (case_id, name, kind, color_token, shortcut, description, created_by, created_at, updated_at) "
            "VALUES (?, ?, 'system', ?, ?, ?, ?, ?, ?)",
            (
                case_id,
                name,
                color,
                None if taken else shortcut,
                "기본 태그",
                "system",
                timestamp,
                timestamp,
            ),
        )
    else:
        cursor = connection.execute(
            "INSERT INTO case_tag (case_id, name, kind, color_token, shortcut, description, created_by, created_at, updated_at) "
            "VALUES (?, ?, 'user', ?, NULL, '', ?, ?, ?)",
            (case_id, name, next_color_token(connection, case_id), actor or "local-user", timestamp, timestamp),
        )
    return int(cursor.lastrowid or 0)


def ensure_system_tags(connection: sqlite3.Connection, case_id: str) -> None:
    """Create the missing system tags (북마크, 우선순위 1-5) of a case."""
    live = {str(row["name"]).casefold() for row in live_tag_rows(connection, case_id)}
    timestamp = now_iso()
    for name in SYSTEM_TAGS:
        if name.casefold() not in live:
            _insert_tag(connection, case_id, name, actor="system", timestamp=timestamp)


def resolve_tag_names(
    connection: sqlite3.Connection,
    case_id: str,
    names: Iterable[str],
    *,
    actor: str = "",
) -> list[int]:
    """Tag names -> live ``case_tag`` ids, creating a tag for an unknown name."""
    ids: list[int] = []
    timestamp = ""
    for raw in names:
        try:
            name = normalize_tag_name(raw)
        except ReviewToolError:
            continue
        row = connection.execute(
            "SELECT id FROM case_tag WHERE case_id = ? AND deleted_at = '' AND name = ? COLLATE NOCASE",
            (case_id, name),
        ).fetchone()
        if row is None:
            timestamp = timestamp or now_iso()
            tag_id = _insert_tag(connection, case_id, name, actor=actor, timestamp=timestamp)
        else:
            tag_id = int(row[0])
        if tag_id not in ids:
            ids.append(tag_id)
    return ids


def sync_review_mark_tag_ids(
    connection: sqlite3.Connection,
    case_id: str,
    citation_id: str,
    names: Sequence[str],
    *,
    actor: str = "",
) -> list[int]:
    """Keep ``tag_ids_json`` in step with a mark whose ``tags_json`` names were just written."""
    apply_review_schema(connection)
    ids = resolve_tag_names(connection, case_id, names, actor=actor)
    connection.execute(
        "UPDATE review_mark SET tag_ids_json = ?, tags_json = ? WHERE citation_id = ?",
        (json.dumps(ids), json.dumps(tag_names_for_ids(connection, ids), ensure_ascii=False), citation_id),
    )
    return ids


def tag_names_for_ids(connection: sqlite3.Connection, ids: Sequence[int]) -> list[str]:
    """Canonical names of tag ids, in the given order (unknown ids dropped)."""
    if not ids:
        return []
    placeholders = ", ".join("?" for _ in ids)
    names = {
        int(row[0]): str(row[1])
        for row in connection.execute(f"SELECT id, name FROM case_tag WHERE id IN ({placeholders})", tuple(ids))
    }
    return [names[tag_id] for tag_id in ids if tag_id in names]


def _mark_tag_names(raw: object) -> list[str]:
    try:
        value = json.loads(str(raw or "[]"))
    except json.JSONDecodeError:
        return []
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


def migrate_string_tags(connection: sqlite3.Connection) -> int:
    """String tags on marks -> ``case_tag`` rows + ``tag_ids_json``. Returns migrated marks."""
    migrated = 0
    rows = connection.execute(
        "SELECT id, case_id, tags_json, reviewer FROM review_mark WHERE tag_ids_json IS NULL"
    ).fetchall()
    for row in rows:
        names = _mark_tag_names(row[2])
        ids = resolve_tag_names(connection, str(row[1]), names, actor=str(row[3] or "") or "migration")
        connection.execute(
            "UPDATE review_mark SET tag_ids_json = ?, tags_json = ? WHERE id = ?",
            (json.dumps(ids), json.dumps(tag_names_for_ids(connection, ids), ensure_ascii=False), int(row[0])),
        )
        migrated += 1
    return migrated


register_schema_extension(apply_review_schema)
