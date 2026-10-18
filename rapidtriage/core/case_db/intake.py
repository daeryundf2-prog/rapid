"""Case intake (AXIOM adoption E1): case info, evidence list, notes, processing snapshots.

A *workspace* case DB (``rapidtriage-cases.db`` next to the run job state)
holds the examiner's cases: ``case_record`` (plus ``case_number``,
``case_type``, ``requester``), ``evidence_source`` rows the examiner adds
(plus ``evidence_number`` and the hash-verification columns), ``case_note``
(author, soft delete, append-only ``case_note_history``) and
``processing_snapshot`` (the run options fixed when a run of an evidence item
starts). Every column/table here is additive: ``apply_intake_schema`` runs from
``apply_schema`` on every case DB and migrates an existing DB in place.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from collections.abc import Callable, Iterable, Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass

from .base import CaseDatabaseError, normalize_identifier, now_iso
from .constants import CITATION_KIND_PREFIXES, CITATION_WIDTH

LOGGER = logging.getLogger(__name__)

__all__ = [
    "CASE_INTAKE_COLUMNS",
    "EVIDENCE_INTAKE_COLUMNS",
    "EVIDENCE_TYPES",
    "HASH_STATUS_LABELS",
    "CaseConflictError",
    "CaseIntake",
    "CaseNotFoundError",
    "apply_intake_schema",
    "ensure_intake_schema",
    "same_local_path",
]

CASE_INTAKE_COLUMNS = (
    ("case_record", "case_number", "TEXT NOT NULL DEFAULT ''"),
    ("case_record", "case_type", "TEXT NOT NULL DEFAULT ''"),
    ("case_record", "requester", "TEXT NOT NULL DEFAULT ''"),
)
EVIDENCE_INTAKE_COLUMNS = (
    ("evidence_source", "evidence_number", "TEXT NOT NULL DEFAULT ''"),
    ("evidence_source", "hash_verify", "INTEGER NOT NULL DEFAULT 0"),
    ("evidence_source", "hash_expected", "TEXT NOT NULL DEFAULT ''"),
    ("evidence_source", "hash_status", "TEXT NOT NULL DEFAULT ''"),
    ("evidence_source", "hash_message", "TEXT NOT NULL DEFAULT ''"),
)

# One statement per blank-line-separated block (apply_intake_schema executes them one by one).
INTAKE_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS case_note (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    author TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deleted_at TEXT,
    deleted_by TEXT NOT NULL DEFAULT '',
    text TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES case_record(case_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_case_note_case ON case_note(case_id, created_at);

CREATE TABLE IF NOT EXISTS case_note_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    note_id INTEGER NOT NULL,
    case_id TEXT NOT NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT '',
    at TEXT NOT NULL,
    text TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_case_note_history_case ON case_note_history(case_id, id);

CREATE TRIGGER IF NOT EXISTS case_note_history_no_update
BEFORE UPDATE ON case_note_history
BEGIN
    SELECT RAISE(ABORT, 'case_note_history is append-only');
END;

CREATE TRIGGER IF NOT EXISTS case_note_history_no_delete
BEFORE DELETE ON case_note_history
BEGIN
    SELECT RAISE(ABORT, 'case_note_history is append-only');
END;

CREATE TABLE IF NOT EXISTS processing_snapshot (
    run_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    evidence_citation_id TEXT NOT NULL DEFAULT '',
    captured_at TEXT NOT NULL,
    snapshot_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (case_id) REFERENCES case_record(case_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_processing_snapshot_case ON processing_snapshot(case_id, captured_at);

CREATE UNIQUE INDEX IF NOT EXISTS idx_case_record_case_number
    ON case_record(case_number) WHERE case_number <> '';

CREATE UNIQUE INDEX IF NOT EXISTS idx_evidence_source_number
    ON evidence_source(case_id, evidence_number) WHERE evidence_number <> '';
"""

#: Unique indexes that can fail on a legacy DB that already holds duplicates (created separately so
#: such a DB still opens; the API pre-checks inside ``BEGIN IMMEDIATE`` keep new rows unique).
#: ``lower()`` folds ASCII only, the same fold the pre-check uses.
CASE_NUMBER_NOCASE_INDEX = "idx_case_record_case_number_nocase"
CITATION_PREFIX_INDEX = "idx_case_record_citation_prefix"
INTAKE_UNIQUE_INDEXES = (
    (CASE_NUMBER_NOCASE_INDEX,
     f"CREATE UNIQUE INDEX IF NOT EXISTS {CASE_NUMBER_NOCASE_INDEX} "
     "ON case_record(lower(case_number)) WHERE case_number <> ''"),
    (CITATION_PREFIX_INDEX,
     f"CREATE UNIQUE INDEX IF NOT EXISTS {CITATION_PREFIX_INDEX} ON case_record(citation_prefix)"),
)
INTAKE_TRIGGERS = ("case_note_history_no_update", "case_note_history_no_delete")

#: Evidence kinds the intake wizard offers (AXIOM: image / folder / export / mobile).
EVIDENCE_TYPES = ("e01", "folder", "export", "mobile")

HASH_STATUS_LABELS = {
    "not-requested": "해시 검증 안 함",
    "not-applicable": "해당 없음 (폴더)",
    "hashing": "해시 계산 중",
    "computed": "해시 계산 완료 (기대값 없음)",
    "matched": "해시 일치",
    "mismatched": "해시 불일치",
    "failed": "해시 계산 실패",
    "interrupted": "해시 계산 중단됨 (서버 재시작)",
}

CASE_FIELDS = ("case_number", "name", "case_type", "examiner", "requester", "organization", "description", "status")


class CaseNotFoundError(CaseDatabaseError):
    """A case, evidence item or note does not exist (API 404)."""


class CaseConflictError(CaseDatabaseError):
    """The request conflicts with stored state (API 409)."""


def _ensure_column(connection: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def apply_intake_schema(connection: sqlite3.Connection) -> None:
    """Add the intake columns and tables (idempotent; existing DBs migrate in place)."""
    for table, column, definition in (*CASE_INTAKE_COLUMNS, *EVIDENCE_INTAKE_COLUMNS):
        _ensure_column(connection, table, column, definition)
    # One execute() per statement (blank-line separated), not executescript(): executescript
    # commits first, and apply_schema's fast path counts DDL replays (hardening follow-ups).
    for statement in INTAKE_SCHEMA_SQL.strip().split("\n\n"):
        connection.execute(statement)
    for name, statement in INTAKE_UNIQUE_INDEXES:
        try:
            connection.execute(statement)
        except sqlite3.IntegrityError as exc:
            LOGGER.warning("case DB keeps duplicate rows; unique index %s not created: %s", name, exc)


def intake_schema_present(connection: sqlite3.Connection) -> bool:
    """True when every intake column and table already exists (cheap check for apply_schema)."""
    for table in ("case_record", "evidence_source"):
        columns = {str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")}
        wanted = {c for t, c, _ in (*CASE_INTAKE_COLUMNS, *EVIDENCE_INTAKE_COLUMNS) if t == table}
        if not wanted <= columns:
            return False
    names = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN "
            "('case_note', 'case_note_history', 'processing_snapshot')"
        )
    }
    if len(names) != 3:
        return False
    objects = {
        str(row[0])
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type IN ('index', 'trigger')")
    }
    return {name for name, _ in INTAKE_UNIQUE_INDEXES} <= objects and set(INTAKE_TRIGGERS) <= objects


def ensure_intake_schema(connection: sqlite3.Connection) -> bool:
    """Migrate an existing (current-version) case DB to the intake layout; True when it wrote.

    ``apply_schema`` adds the intake layout only when it replays DDL anyway (fresh or migrating
    DBs); its current-schema fast path stays write-free so read-only run DBs keep opening. The
    workspace case DB calls this once when it is opened.
    """
    if intake_schema_present(connection):
        return False
    apply_intake_schema(connection)
    return True


def same_local_path(left: str, right: str) -> bool:
    """Path equality as Windows sees it (``D:/x`` == ``d:\\X``), without touching the disk."""
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(os.path.abspath(right))


def _begin_immediate(connection: sqlite3.Connection) -> None:
    """Take the write lock now (not at the first write) so a read-then-write stays consistent."""
    if not connection.in_transaction:
        connection.execute("BEGIN IMMEDIATE")


def case_integrity_conflict(exc: sqlite3.IntegrityError, case_number: str) -> CaseConflictError:
    """A unique index caught what the pre-check could not (legacy rows / another writer)."""
    text = str(exc)
    if "citation_prefix" in text or CITATION_PREFIX_INDEX in text or "audit_event" in text:
        return CaseConflictError("인용 ID 접두가 다른 케이스와 겹쳐 케이스를 저장하지 못했습니다. 다시 시도하세요")
    if "case_number" in text:
        return CaseConflictError(f"같은 사건 번호의 케이스가 이미 있습니다 (대소문자 무시): {case_number}")
    return CaseConflictError(f"케이스를 저장하지 못했습니다 (중복): {text}")


def _row_dict(row: sqlite3.Row | None) -> dict[str, object]:
    return {key: row[key] for key in row.keys()} if row is not None else {}


def _next_citation(connection: sqlite3.Connection, case_id: str, kind: str) -> str:
    prefix = CITATION_KIND_PREFIXES[kind]
    case = connection.execute("SELECT citation_prefix FROM case_record WHERE case_id = ?", (case_id,)).fetchone()
    if case is None:
        raise CaseNotFoundError("케이스를 찾을 수 없습니다")
    connection.execute(
        "INSERT INTO citation_sequence (case_id, kind, next_value) VALUES (?, ?, 1) "
        "ON CONFLICT(case_id, kind) DO NOTHING",
        (case_id, kind),
    )
    value = int(
        connection.execute(
            "SELECT next_value FROM citation_sequence WHERE case_id = ? AND kind = ?", (case_id, kind)
        ).fetchone()[0]
    )
    connection.execute(
        "UPDATE citation_sequence SET next_value = ? WHERE case_id = ? AND kind = ?", (value + 1, case_id, kind)
    )
    return f"{case['citation_prefix']}-{prefix}-{value:0{CITATION_WIDTH}d}"


def _audit(
    connection: sqlite3.Connection,
    case_id: str,
    action: str,
    *,
    target_type: str,
    target_id: str,
    actor: str,
    params: Mapping[str, object] | None = None,
) -> None:
    timestamp = now_iso()
    connection.execute(
        """
        INSERT INTO audit_event (
            citation_id, case_id, actor, action, target_type, target_id,
            timestamp, tool_name, tool_version, params_json, result, error
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, 'rapidtriage', '', ?, 'ok', '')
        """,
        (
            _next_citation(connection, case_id, "audit"),
            case_id,
            actor or "local-user",
            action,
            target_type,
            target_id,
            timestamp,
            json.dumps(dict(params or {}), ensure_ascii=False, sort_keys=True),
        ),
    )
    connection.execute("UPDATE case_record SET updated_at = ? WHERE case_id = ?", (timestamp, case_id))


@dataclass
class CaseIntake:
    """Intake operations over one (workspace) case DB connection factory.

    ``connect`` is a context manager yielding a ``sqlite3.Connection`` with
    ``row_factory = sqlite3.Row`` that commits on success (``CaseDatabase.connect``).
    """

    connect: Callable[[], AbstractContextManager[sqlite3.Connection]]

    # --- cases ---------------------------------------------------------------

    def _case_row(self, connection: sqlite3.Connection, case_id: str) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM case_record WHERE case_id = ?", (case_id,)).fetchone()
        if row is None:
            raise CaseNotFoundError("케이스를 찾을 수 없습니다")
        return row

    @staticmethod
    def _case_payload(row: sqlite3.Row) -> dict[str, object]:
        data = _row_dict(row)
        return {
            "case_id": data["case_id"],
            "case_number": data.get("case_number") or "",
            "name": data.get("name") or "",
            "case_type": data.get("case_type") or "",
            "examiner": data.get("examiner") or "",
            "requester": data.get("requester") or "",
            "organization": data.get("organization") or "",
            "description": data.get("description") or "",
            "case_root": data.get("case_root") or "",
            "citation_prefix": data.get("citation_prefix") or "",
            "status": data.get("status") or "open",
            "created_at": data.get("created_at"),
            "updated_at": data.get("updated_at"),
        }

    def _unique_prefix(self, connection: sqlite3.Connection, case_number: str) -> str:
        base = normalize_identifier(case_number.upper(), fallback="CASE")[:36]
        used = {str(row[0]) for row in connection.execute("SELECT citation_prefix FROM case_record")}
        candidate = base
        index = 2
        while candidate in used:
            candidate = f"{base}-{index}"
            index += 1
        return candidate

    def create_case(self, *, case_id: str, fields: Mapping[str, str], case_root: str, actor: str) -> dict[str, object]:
        case_number = str(fields.get("case_number") or "").strip()
        timestamp = now_iso()
        with self.connect() as connection:
            # Pre-check, prefix choice and insert in one write transaction: concurrent creates
            # serialize here instead of both passing the pre-check (unique indexes back it up).
            _begin_immediate(connection)
            if connection.execute(
                "SELECT 1 FROM case_record WHERE lower(case_number) = lower(?)", (case_number,)
            ).fetchone():
                raise CaseConflictError(f"같은 사건 번호의 케이스가 이미 있습니다: {case_number}")
            try:
                connection.execute(
                    """
                    INSERT INTO case_record (
                        case_id, name, description, examiner, organization, case_root,
                        citation_prefix, status, created_at, updated_at,
                        case_number, case_type, requester
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?)
                    """,
                    (
                        case_id,
                        str(fields.get("name") or "").strip() or case_number,
                        str(fields.get("description") or "").strip(),
                        str(fields.get("examiner") or "").strip(),
                        str(fields.get("organization") or "").strip(),
                        case_root,
                        self._unique_prefix(connection, case_number),
                        timestamp,
                        timestamp,
                        case_number,
                        str(fields.get("case_type") or "").strip(),
                        str(fields.get("requester") or "").strip(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise case_integrity_conflict(exc, case_number) from exc
            _audit(connection, case_id, "case.created", target_type="case", target_id=case_id, actor=actor,
                   params={"case_number": case_number})
            return self._case_payload(self._case_row(connection, case_id))

    def list_cases(self) -> list[dict[str, object]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM case_record WHERE case_number <> '' ORDER BY updated_at DESC, case_id"
            ).fetchall()
            return [self._case_payload(row) for row in rows]

    def get_case(self, case_id: str) -> dict[str, object]:
        with self.connect() as connection:
            return self._case_payload(self._case_row(connection, case_id))

    def update_case(self, case_id: str, changes: Mapping[str, str], *, actor: str) -> dict[str, object]:
        updates = {key: str(value).strip() for key, value in changes.items() if key in CASE_FIELDS}
        with self.connect() as connection:
            _begin_immediate(connection)
            before = self._case_payload(self._case_row(connection, case_id))
            if "name" in updates and not updates["name"]:
                # 사건명 is never blank: an emptied name falls back to the case number (as on create).
                updates["name"] = updates.get("case_number") or str(before["case_number"])
            number = updates.get("case_number")
            if number is not None and number != before["case_number"]:
                clash = connection.execute(
                    "SELECT 1 FROM case_record WHERE lower(case_number) = lower(?) AND case_id <> ?",
                    (number, case_id),
                ).fetchone()
                if clash:
                    raise CaseConflictError(f"같은 사건 번호의 케이스가 이미 있습니다: {number}")
            changed = {key: value for key, value in updates.items() if before.get(key) != value}
            if changed:
                assignments = ", ".join(f"{key} = ?" for key in changed)
                try:
                    connection.execute(
                        f"UPDATE case_record SET {assignments}, updated_at = ? WHERE case_id = ?",
                        (*changed.values(), now_iso(), case_id),
                    )
                except sqlite3.IntegrityError as exc:
                    raise case_integrity_conflict(exc, str(number or before["case_number"])) from exc
                _audit(
                    connection, case_id, "case.updated", target_type="case", target_id=case_id, actor=actor,
                    params={"changed": sorted(changed), "previous": {key: before.get(key) for key in changed}},
                )
            return self._case_payload(self._case_row(connection, case_id))

    # --- evidence ------------------------------------------------------------

    @staticmethod
    def _evidence_payload(row: sqlite3.Row) -> dict[str, object]:
        data = _row_dict(row)
        status = str(data.get("hash_status") or "not-requested")
        return {
            "citation_id": data["citation_id"],
            "case_id": data["case_id"],
            "evidence_number": data.get("evidence_number") or "",
            "display_name": data.get("display_name") or "",
            "source_type": data.get("source_type") or "",
            "path": data.get("original_path") or "",
            "size_bytes": data.get("size_bytes"),
            "hash_verify": bool(data.get("hash_verify")),
            "hash_expected": data.get("hash_expected") or "",
            "hash_status": status,
            "hash_status_label": HASH_STATUS_LABELS.get(status, status),
            "hash_message": data.get("hash_message") or "",
            "hashes": {
                key: data.get(f"hash_{key}")
                for key in ("md5", "sha1", "sha256")
                if data.get(f"hash_{key}")
            },
            "added_at": data.get("added_at"),
        }

    def add_evidence(
        self,
        case_id: str,
        *,
        evidence_number: str,
        display_name: str,
        source_type: str,
        path: str,
        size_bytes: int | None,
        hash_verify: bool,
        hash_expected: str,
        hash_status: str,
        hash_message: str,
        actor: str,
    ) -> dict[str, object]:
        with self.connect() as connection:
            self._case_row(connection, case_id)
            clash = connection.execute(
                "SELECT 1 FROM evidence_source WHERE case_id = ? AND evidence_number = ?", (case_id, evidence_number)
            ).fetchone()
            if clash:
                raise CaseConflictError(f"같은 증거 번호가 이미 있습니다: {evidence_number}")
            for number, existing in connection.execute(
                "SELECT evidence_number, original_path FROM evidence_source WHERE case_id = ?", (case_id,)
            ):
                if existing and same_local_path(str(existing), path):
                    raise CaseConflictError(f"같은 경로의 증거가 이미 있습니다: 증거 {number}")
            citation_id = _next_citation(connection, case_id, "evidence")
            connection.execute(
                """
                INSERT INTO evidence_source (
                    citation_id, case_id, display_name, source_type, original_path, staged_path,
                    size_bytes, detected_format, adapter_name, adapter_version, status, added_at,
                    evidence_number, hash_verify, hash_expected, hash_status, hash_message
                )
                VALUES (?, ?, ?, ?, ?, '', ?, ?, 'case-intake', '1', 'registered', ?, ?, ?, ?, ?, ?)
                """,
                (
                    citation_id,
                    case_id,
                    display_name,
                    source_type,
                    path,
                    size_bytes,
                    source_type,
                    now_iso(),
                    evidence_number,
                    1 if hash_verify else 0,
                    hash_expected,
                    hash_status,
                    hash_message,
                ),
            )
            _audit(
                connection, case_id, "evidence.added", target_type="evidence_source", target_id=citation_id,
                actor=actor, params={"evidence_number": evidence_number, "source_type": source_type, "path": path,
                                     "hash_verify": hash_verify},
            )
            return self._evidence_payload(
                connection.execute("SELECT * FROM evidence_source WHERE citation_id = ?", (citation_id,)).fetchone()
            )

    def list_evidence(self, case_id: str) -> list[dict[str, object]]:
        with self.connect() as connection:
            self._case_row(connection, case_id)
            rows = connection.execute(
                "SELECT * FROM evidence_source WHERE case_id = ? ORDER BY id", (case_id,)
            ).fetchall()
            return [self._evidence_payload(row) for row in rows]

    def get_evidence(self, case_id: str, citation_id: str) -> dict[str, object]:
        with self.connect() as connection:
            self._case_row(connection, case_id)
            row = connection.execute(
                "SELECT * FROM evidence_source WHERE case_id = ? AND citation_id = ?", (case_id, citation_id)
            ).fetchone()
            if row is None:
                raise CaseNotFoundError("증거를 찾을 수 없습니다")
            return self._evidence_payload(row)

    def find_evidence_by_path(self, case_id: str, path: str) -> dict[str, object] | None:
        with self.connect() as connection:
            for row in connection.execute("SELECT * FROM evidence_source WHERE case_id = ? ORDER BY id", (case_id,)):
                if row["original_path"] and same_local_path(str(row["original_path"]), path):
                    return self._evidence_payload(row)
            return None

    def set_evidence_hash(
        self, citation_id: str, *, status: str, message: str = "", digests: Mapping[str, str] | None = None
    ) -> None:
        digests = digests or {}
        with self.connect() as connection:
            row = connection.execute(
                "SELECT case_id FROM evidence_source WHERE citation_id = ?", (citation_id,)
            ).fetchone()
            if row is None:
                return
            connection.execute(
                """
                UPDATE evidence_source
                SET hash_status = ?, hash_message = ?,
                    hash_md5 = COALESCE(?, hash_md5), hash_sha1 = COALESCE(?, hash_sha1),
                    hash_sha256 = COALESCE(?, hash_sha256)
                WHERE citation_id = ?
                """,
                (status, message, digests.get("md5"), digests.get("sha1"), digests.get("sha256"), citation_id),
            )
            if status not in ("hashing",):
                _audit(
                    connection, str(row[0]), "evidence.hash", target_type="evidence_source", target_id=citation_id,
                    actor="rapidtriage", params={"status": status, "message": message, **dict(digests)},
                )

    def mark_interrupted_hashes(self, started_before: str) -> list[str]:
        """``hashing`` rows saved before ``started_before`` have no worker any more: store ``interrupted``."""
        message = "서버가 다시 시작되어 해시 계산이 끊겼습니다. 다시 계산하세요"
        with self.connect() as connection:
            _begin_immediate(connection)
            rows = connection.execute(
                "SELECT citation_id, case_id FROM evidence_source WHERE hash_status = 'hashing' AND added_at < ?",
                (started_before,),
            ).fetchall()
            for citation_id, case_id in rows:
                connection.execute(
                    "UPDATE evidence_source SET hash_status = 'interrupted', hash_message = ? WHERE citation_id = ?",
                    (message, citation_id),
                )
                _audit(
                    connection, str(case_id), "evidence.hash", target_type="evidence_source",
                    target_id=str(citation_id), actor="rapidtriage",
                    params={"status": "interrupted", "message": message},
                )
        return [str(row[0]) for row in rows]

    def restart_hash(self, case_id: str, citation_id: str, *, actor: str) -> dict[str, object]:
        """Mark an evidence row ``hashing`` again (re-hash); the caller starts the worker."""
        with self.connect() as connection:
            _begin_immediate(connection)
            self._case_row(connection, case_id)
            row = connection.execute(
                "SELECT * FROM evidence_source WHERE case_id = ? AND citation_id = ?", (case_id, citation_id)
            ).fetchone()
            if row is None:
                raise CaseNotFoundError("증거를 찾을 수 없습니다")
            if row["hash_status"] == "hashing":
                raise CaseConflictError("이미 해시를 계산하고 있습니다")
            expected = str(row["hash_expected"] or "")
            connection.execute(
                "UPDATE evidence_source SET hash_verify = 1, hash_status = 'hashing', hash_message = ? "
                "WHERE citation_id = ?",
                ("다시 계산 중" + (" (기대값과 비교)" if expected else ""), citation_id),
            )
            _audit(
                connection, case_id, "evidence.hash.restart", target_type="evidence_source", target_id=citation_id,
                actor=actor, params={"previous_status": row["hash_status"]},
            )
            return self._evidence_payload(
                connection.execute("SELECT * FROM evidence_source WHERE citation_id = ?", (citation_id,)).fetchone()
            )

    # --- processing snapshots -----------------------------------------------

    def save_snapshot(
        self,
        *,
        run_id: str,
        case_id: str,
        evidence_citation_id: str,
        snapshot: Mapping[str, object],
        actor: str,
        action: str = "run.created",
        audit_params: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        captured_at = str(snapshot.get("captured_at") or now_iso())
        with self.connect() as connection:
            self._case_row(connection, case_id)
            existing = connection.execute(
                "SELECT case_id FROM processing_snapshot WHERE run_id = ?", (run_id,)
            ).fetchone()
            if existing is not None:
                raise CaseConflictError("이미 케이스에 연결된 런입니다")
            connection.execute(
                "INSERT INTO processing_snapshot (run_id, case_id, evidence_citation_id, captured_at, snapshot_json) "
                "VALUES (?, ?, ?, ?, ?)",
                (run_id, case_id, evidence_citation_id, captured_at,
                 json.dumps(dict(snapshot), ensure_ascii=False, sort_keys=True)),
            )
            _audit(
                connection, case_id, action, target_type="run", target_id=run_id, actor=actor,
                params={"evidence_citation_id": evidence_citation_id, **dict(audit_params or {})},
            )
        return {"run_id": run_id, "case_id": case_id, "evidence_citation_id": evidence_citation_id,
                "captured_at": captured_at, "snapshot": dict(snapshot)}

    @staticmethod
    def _snapshot_payload(row: sqlite3.Row) -> dict[str, object]:
        try:
            snapshot = json.loads(str(row["snapshot_json"] or "{}"))
        except json.JSONDecodeError:
            snapshot = {}
        return {
            "run_id": row["run_id"],
            "case_id": row["case_id"],
            "evidence_citation_id": row["evidence_citation_id"],
            "captured_at": row["captured_at"],
            "snapshot": snapshot if isinstance(snapshot, dict) else {},
        }

    def get_snapshot(self, run_id: str) -> dict[str, object] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM processing_snapshot WHERE run_id = ?", (run_id,)).fetchone()
            return self._snapshot_payload(row) if row is not None else None

    def list_snapshots(self, case_id: str | None = None) -> list[dict[str, object]]:
        with self.connect() as connection:
            if case_id is None:
                rows = connection.execute("SELECT * FROM processing_snapshot ORDER BY captured_at").fetchall()
            else:
                self._case_row(connection, case_id)
                rows = connection.execute(
                    "SELECT * FROM processing_snapshot WHERE case_id = ? ORDER BY captured_at", (case_id,)
                ).fetchall()
            return [self._snapshot_payload(row) for row in rows]

    # --- notes ---------------------------------------------------------------

    @staticmethod
    def _note_payload(row: sqlite3.Row) -> dict[str, object]:
        return {
            "id": int(row["id"]),
            "case_id": row["case_id"],
            "author": row["author"] or "",
            "text": row["text"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "deleted_at": row["deleted_at"],
            "deleted_by": row["deleted_by"] or "",
        }

    def add_note(self, case_id: str, *, text: str, author: str) -> dict[str, object]:
        timestamp = now_iso()
        with self.connect() as connection:
            self._case_row(connection, case_id)
            cursor = connection.execute(
                "INSERT INTO case_note (case_id, author, created_at, updated_at, text) VALUES (?, ?, ?, ?, ?)",
                (case_id, author, timestamp, timestamp, text),
            )
            note_id = int(cursor.lastrowid)
            connection.execute(
                "INSERT INTO case_note_history (note_id, case_id, action, actor, at, text) "
                "VALUES (?, ?, 'created', ?, ?, ?)",
                (note_id, case_id, author, timestamp, text),
            )
            _audit(connection, case_id, "note.created", target_type="case_note", target_id=str(note_id),
                   actor=author)
            return self._note_payload(
                connection.execute("SELECT * FROM case_note WHERE id = ?", (note_id,)).fetchone()
            )

    def delete_note(self, case_id: str, note_id: int, *, actor: str) -> dict[str, object]:
        timestamp = now_iso()
        with self.connect() as connection:
            self._case_row(connection, case_id)
            row = connection.execute(
                "SELECT * FROM case_note WHERE id = ? AND case_id = ?", (note_id, case_id)
            ).fetchone()
            if row is None:
                raise CaseNotFoundError("메모를 찾을 수 없습니다")
            if row["deleted_at"]:
                raise CaseConflictError("이미 삭제된 메모입니다")
            connection.execute(
                "UPDATE case_note SET deleted_at = ?, deleted_by = ?, updated_at = ? WHERE id = ?",
                (timestamp, actor, timestamp, note_id),
            )
            connection.execute(
                "INSERT INTO case_note_history (note_id, case_id, action, actor, at, text) "
                "VALUES (?, ?, 'deleted', ?, ?, ?)",
                (note_id, case_id, actor, timestamp, row["text"]),
            )
            _audit(connection, case_id, "note.deleted", target_type="case_note", target_id=str(note_id),
                   actor=actor)
            return self._note_payload(
                connection.execute("SELECT * FROM case_note WHERE id = ?", (note_id,)).fetchone()
            )

    def list_notes(self, case_id: str, *, include_deleted: bool = False) -> dict[str, object]:
        with self.connect() as connection:
            self._case_row(connection, case_id)
            rows = connection.execute(
                "SELECT * FROM case_note WHERE case_id = ? ORDER BY created_at DESC, id DESC", (case_id,)
            ).fetchall()
            history = connection.execute(
                "SELECT * FROM case_note_history WHERE case_id = ? ORDER BY id DESC LIMIT 500", (case_id,)
            ).fetchall()
        notes = [self._note_payload(row) for row in rows]
        active = [note for note in notes if not note["deleted_at"]]
        return {
            "notes": notes if include_deleted else active,
            "count": len(active),
            "deleted_count": len(notes) - len(active),
            "history": [
                {
                    "id": int(row["id"]),
                    "note_id": int(row["note_id"]),
                    "action": row["action"],
                    "actor": row["actor"] or "",
                    "at": row["at"],
                    "text": row["text"],
                }
                for row in history
            ],
        }

    # --- counts --------------------------------------------------------------

    def case_counts(self, case_ids: Iterable[str]) -> dict[str, dict[str, int]]:
        ids = list(case_ids)
        counts = {case_id: {"evidence_count": 0, "run_count": 0, "note_count": 0} for case_id in ids}
        if not ids:
            return counts
        marks = ",".join("?" for _ in ids)
        with self.connect() as connection:
            for table, key, extra in (
                ("evidence_source", "evidence_count", ""),
                ("processing_snapshot", "run_count", ""),
                ("case_note", "note_count", " AND deleted_at IS NULL"),
            ):
                for case_id, count in connection.execute(
                    f"SELECT case_id, COUNT(*) FROM {table} WHERE case_id IN ({marks}){extra} GROUP BY case_id", ids
                ):
                    counts[str(case_id)][key] = int(count)
        return counts
