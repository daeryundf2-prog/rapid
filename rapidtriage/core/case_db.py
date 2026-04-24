from __future__ import annotations

import datetime as dt
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

from .docs import extract_text
from .search import SearchError, load_run_summary
from .submission import compute_hashes


SCHEMA_VERSION = 1
CITATION_WIDTH = 6
CITATION_KIND_PREFIXES = {
    "evidence": "EVID",
    "file": "FILE",
    "artifact": "ART",
    "event": "EVT",
    "report": "RPT",
    "review": "REV",
    "audit": "AUD",
    "job": "JOB",
    "hash": "HASH",
    "indexed_document": "IDX",
}


class CaseDatabaseError(ValueError):
    """Raised when a case database operation is invalid."""


@dataclass(frozen=True)
class CaseRecord:
    case_id: str
    name: str
    description: str
    examiner: str
    organization: str
    case_root: str
    citation_prefix: str
    status: str
    created_at: str
    updated_at: str

    def to_dict(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "name": self.name,
            "description": self.description,
            "examiner": self.examiner,
            "organization": self.organization,
            "case_root": self.case_root,
            "citation_prefix": self.citation_prefix,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def normalize_identifier(value: str, *, fallback: str) -> str:
    normalized = "".join(ch if ch.isalnum() or ch in ("-", "_") else "-" for ch in value.strip())
    normalized = "-".join(part for part in normalized.split("-") if part)
    return normalized or fallback


def default_citation_prefix(case_id: str) -> str:
    normalized = normalize_identifier(case_id.upper(), fallback="CASE")
    return normalized[:40]


class CaseDatabase:
    def __init__(self, path: Path):
        self.path = path.expanduser().resolve()

    def connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize(self) -> dict[str, object]:
        with self.connect() as connection:
            apply_schema(connection)
            return {
                "path": str(self.path),
                "schema_version": get_schema_version(connection),
                "tables": list_tables(connection),
            }

    def schema_version(self) -> int:
        with self.connect() as connection:
            return get_schema_version(connection)

    def create_case(
        self,
        *,
        case_id: str,
        name: Optional[str] = None,
        description: str = "",
        examiner: str = "",
        organization: str = "",
        case_root: Optional[Path] = None,
        citation_prefix: Optional[str] = None,
        status: str = "open",
    ) -> CaseRecord:
        normalized_case_id = normalize_identifier(case_id, fallback="case")
        timestamp = now_iso()
        record = CaseRecord(
            case_id=normalized_case_id,
            name=(name or normalized_case_id).strip(),
            description=description.strip(),
            examiner=examiner.strip(),
            organization=organization.strip(),
            case_root=str(case_root.expanduser().resolve()) if case_root else "",
            citation_prefix=(citation_prefix or default_citation_prefix(normalized_case_id)).strip(),
            status=status.strip() or "open",
            created_at=timestamp,
            updated_at=timestamp,
        )
        with self.connect() as connection:
            apply_schema(connection)
            try:
                connection.execute(
                    """
                    INSERT INTO case_record (
                        case_id, name, description, examiner, organization,
                        case_root, citation_prefix, status, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.case_id,
                        record.name,
                        record.description,
                        record.examiner,
                        record.organization,
                        record.case_root,
                        record.citation_prefix,
                        record.status,
                        record.created_at,
                        record.updated_at,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise CaseDatabaseError(f"case already exists: {record.case_id}") from exc
        return record

    def get_case(self, case_id: str) -> CaseRecord:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM case_record WHERE case_id = ?", (case_id,)).fetchone()
        if row is None:
            raise CaseDatabaseError(f"case not found: {case_id}")
        return case_record_from_row(row)

    def list_cases(self) -> list[CaseRecord]:
        with self.connect() as connection:
            rows = connection.execute("SELECT * FROM case_record ORDER BY updated_at DESC, case_id ASC").fetchall()
        return [case_record_from_row(row) for row in rows]

    def next_citation_id(self, case_id: str, kind: str) -> str:
        with self.connect() as connection:
            apply_schema(connection)
            return next_citation_id_for_connection(connection, case_id, kind)

    def add_audit_event(
        self,
        *,
        case_id: str,
        action: str,
        target_type: str = "",
        target_id: str = "",
        actor: str = "local-user",
        tool_name: str = "rapidtriage",
        tool_version: str = "",
        params_json: str = "{}",
        result: str = "ok",
        error: str = "",
    ) -> str:
        with self.connect() as connection:
            citation_id = next_citation_id_for_connection(connection, case_id, "audit")
            timestamp = now_iso()
            connection.execute(
                """
                INSERT INTO audit_event (
                    citation_id, case_id, actor, action, target_type, target_id,
                    timestamp, tool_name, tool_version, params_json, result, error
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    citation_id,
                    case_id,
                    actor,
                    action,
                    target_type,
                    target_id,
                    timestamp,
                    tool_name,
                    tool_version,
                    params_json,
                    result,
                    error,
                ),
            )
            connection.execute(
                "UPDATE case_record SET updated_at = ? WHERE case_id = ?",
                (timestamp, case_id),
            )
        return citation_id

    def import_run_output(
        self,
        run_summary: Mapping[str, object] | Path,
        *,
        case_id: str,
        case_name: Optional[str] = None,
    ) -> dict[str, object]:
        summary = load_run_summary(run_summary)
        outputs = summary.get("outputs")
        if not isinstance(outputs, Mapping):
            raise CaseDatabaseError("run summary does not include outputs")
        source = summary.get("source")
        source_payload = source if isinstance(source, Mapping) else {}
        root = Path(str(summary.get("root") or source_payload.get("analysis_root") or "")).expanduser()
        case_root = root.resolve() if str(root) else None

        with self.connect() as connection:
            apply_schema(connection)
            case_row = connection.execute("SELECT case_id FROM case_record WHERE case_id = ?", (case_id,)).fetchone()
        if case_row is None:
            self.create_case(case_id=case_id, name=case_name, case_root=case_root)

        evidence_source_id = self._insert_evidence_source(case_id, summary)
        counts = {
            "evidence_source_count": 1,
            "file_record_count": self._import_files(case_id, evidence_source_id, outputs),
            "indexed_document_count": self._import_docs(case_id, evidence_source_id, outputs),
            "artifact_count": self._import_artifacts(case_id, evidence_source_id, outputs),
            "event_count": self._import_timeline(case_id, evidence_source_id, outputs),
        }
        audit_id = self.add_audit_event(
            case_id=case_id,
            action="run.imported",
            target_type="run-summary",
            target_id=str(summary.get("outputs", {}).get("summary") or ""),
            params_json=json.dumps({"counts": counts}, ensure_ascii=False, sort_keys=True),
        )
        return {
            "case_id": case_id,
            "audit_citation_id": audit_id,
            "summary": counts,
        }

    def search_case(
        self,
        *,
        case_id: str,
        keywords: Iterable[str],
        limit: int = 100,
        sources: Iterable[str] | None = None,
        verification_status: str | None = None,
    ) -> dict[str, object]:
        normalized_keywords = [keyword.strip() for keyword in keywords if keyword.strip()]
        if not normalized_keywords:
            raise CaseDatabaseError("at least one keyword is required")
        normalized_case_id = normalize_identifier(case_id, fallback="case")
        source_filter = {source.strip() for source in (sources or []) if source.strip()}
        with self.connect() as connection:
            apply_schema(connection)
            if connection.execute("SELECT 1 FROM case_record WHERE case_id = ?", (normalized_case_id,)).fetchone() is None:
                raise CaseDatabaseError(f"case not found: {normalized_case_id}")
            matches: list[dict[str, object]] = []
            matches.extend(search_indexed_documents(connection, normalized_case_id, normalized_keywords, limit))
            matches.extend(search_file_records(connection, normalized_case_id, normalized_keywords, limit))
            matches.extend(search_artifacts(connection, normalized_case_id, normalized_keywords, limit))
            matches.extend(search_events(connection, normalized_case_id, normalized_keywords, limit))
            matches = attach_review_marks(connection, normalized_case_id, matches)
            if source_filter:
                matches = [match for match in matches if str(match.get("source") or "") in source_filter]
            if verification_status:
                matches = [
                    match
                    for match in matches
                    if str((match.get("review") or {}).get("verification_status") or "unverified") == verification_status
                ]
            if limit:
                matches = matches[:limit]

        source_counts: dict[str, int] = {}
        keyword_counts: dict[str, int] = {keyword.lower(): 0 for keyword in normalized_keywords}
        for match in matches:
            source = str(match.get("source") or "unknown")
            source_counts[source] = source_counts.get(source, 0) + 1
            for keyword in match.get("matched_keywords", []):
                keyword_counts[str(keyword).lower()] = keyword_counts.get(str(keyword).lower(), 0) + 1
        return {
            "command": "case-search",
            "generated_at": now_iso(),
            "database": str(self.path),
            "case_id": normalized_case_id,
            "keywords": normalized_keywords,
            "options": {
                "limit": limit,
                "sources": sorted(source_filter),
                "verification_status": verification_status,
            },
            "summary": {
                "match_count": len(matches),
                "source_counts": source_counts,
                "keyword_counts": keyword_counts,
            },
            "matches": matches,
        }

    def mark_review(
        self,
        *,
        case_id: str,
        target_type: str,
        target_id: str,
        status: str = "unreviewed",
        verification_status: str = "unverified",
        tags: Iterable[str] | None = None,
        note: str = "",
        include_in_report: bool = False,
        reviewer: str = "",
    ) -> dict[str, object]:
        normalized_case_id = normalize_identifier(case_id, fallback="case")
        normalized_tags = normalize_tags(tags or [])
        timestamp = now_iso()
        with self.connect() as connection:
            apply_schema(connection)
            if connection.execute("SELECT 1 FROM case_record WHERE case_id = ?", (normalized_case_id,)).fetchone() is None:
                raise CaseDatabaseError(f"case not found: {normalized_case_id}")
            existing = connection.execute(
                """
                SELECT * FROM review_mark
                WHERE case_id = ? AND target_type = ? AND target_id = ?
                LIMIT 1
                """,
                (normalized_case_id, target_type, target_id),
            ).fetchone()
            tags_json = json.dumps(normalized_tags, ensure_ascii=False)
            if existing is None:
                citation_id = next_citation_id_for_connection(connection, normalized_case_id, "review")
                connection.execute(
                    """
                    INSERT INTO review_mark (
                        citation_id, case_id, target_type, target_id, status,
                        verification_status, tags_json, note, include_in_report,
                        reviewer, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        citation_id,
                        normalized_case_id,
                        target_type,
                        target_id,
                        status,
                        verification_status,
                        tags_json,
                        note,
                        1 if include_in_report else 0,
                        reviewer,
                        timestamp,
                        timestamp,
                    ),
                )
            else:
                citation_id = str(existing["citation_id"])
                connection.execute(
                    """
                    UPDATE review_mark
                    SET status = ?, verification_status = ?, tags_json = ?, note = ?,
                        include_in_report = ?, reviewer = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        status,
                        verification_status,
                        tags_json,
                        note,
                        1 if include_in_report else 0,
                        reviewer,
                        timestamp,
                        existing["id"],
                    ),
                )
            connection.execute(
                """
                INSERT INTO audit_event (
                    citation_id, case_id, actor, action, target_type, target_id,
                    timestamp, tool_name, tool_version, params_json, result, error
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    next_citation_id_for_connection(connection, normalized_case_id, "audit"),
                    normalized_case_id,
                    reviewer or "local-user",
                    "review.marked",
                    target_type,
                    target_id,
                    timestamp,
                    "rapidtriage",
                    "",
                    json.dumps(
                        {
                            "status": status,
                            "verification_status": verification_status,
                            "tags": normalized_tags,
                            "include_in_report": include_in_report,
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                    "ok",
                    "",
                ),
            )
        return self.get_review_mark(normalized_case_id, target_type=target_type, target_id=target_id)

    def get_review_mark(self, case_id: str, *, target_type: str, target_id: str) -> dict[str, object]:
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM review_mark
                WHERE case_id = ? AND target_type = ? AND target_id = ?
                LIMIT 1
                """,
                (case_id, target_type, target_id),
            ).fetchone()
        if row is None:
            raise CaseDatabaseError(f"review mark not found: {target_type}:{target_id}")
        return review_mark_to_dict(row)

    def list_review_marks(self, case_id: str) -> list[dict[str, object]]:
        normalized_case_id = normalize_identifier(case_id, fallback="case")
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM review_mark WHERE case_id = ? ORDER BY updated_at DESC, id DESC",
                (normalized_case_id,),
            ).fetchall()
        return [review_mark_to_dict(row) for row in rows]

    def _insert_evidence_source(self, case_id: str, summary: Mapping[str, object]) -> int:
        source = summary.get("source")
        source_payload = source if isinstance(source, Mapping) else {}
        source_path = str(source_payload.get("source_path") or summary.get("root") or "")
        analysis_root = str(source_payload.get("analysis_root") or summary.get("root") or "")
        timestamp = now_iso()
        size = path_size(source_path)
        hashes = hash_existing_file(source_path)
        with self.connect() as connection:
            citation_id = next_citation_id_for_connection(connection, case_id, "evidence")
            cursor = connection.execute(
                """
                INSERT INTO evidence_source (
                    citation_id, case_id, display_name, source_type, original_path, staged_path,
                    size_bytes, hash_md5, hash_sha1, hash_sha256, detected_format,
                    adapter_name, adapter_version, status, added_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    citation_id,
                    case_id,
                    Path(source_path).name if source_path else str(summary.get("mode") or "run-output"),
                    str(source_payload.get("type") or "run-output"),
                    source_path,
                    analysis_root,
                    size,
                    hashes.get("md5"),
                    hashes.get("sha1"),
                    hashes.get("sha256"),
                    str(source_payload.get("type") or ""),
                    "run-output-import",
                    "1",
                    "imported",
                    timestamp,
                ),
            )
            return int(cursor.lastrowid)

    def _import_files(self, case_id: str, evidence_source_id: int, outputs: Mapping[str, object]) -> int:
        payload = read_output(outputs, "files")
        rows = payload.get("candidates") if isinstance(payload, Mapping) else None
        if not isinstance(rows, list):
            return 0
        count = 0
        with self.connect() as connection:
            for row in rows:
                if not isinstance(row, Mapping):
                    continue
                path = str(row.get("path") or "")
                hashes = hash_existing_file(path)
                connection.execute(
                    """
                    INSERT INTO file_record (
                        citation_id, case_id, evidence_source_id, path, normalized_path, extension,
                        size_bytes, modified_at, hash_md5, hash_sha1, hash_sha256,
                        is_deleted, is_recovered
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        next_citation_id_for_connection(connection, case_id, "file"),
                        case_id,
                        evidence_source_id,
                        path,
                        normalize_path_for_db(path),
                        str(row.get("extension") or ""),
                        optional_int(row.get("size")),
                        optional_str(row.get("modified_at")),
                        hashes.get("md5"),
                        hashes.get("sha1"),
                        hashes.get("sha256"),
                        1 if "recycle" in path.lower() or "deleted" in path.lower() else 0,
                        1 if "recycle" in path.lower() or "deleted" in path.lower() else 0,
                    ),
                )
                count += 1
        return count

    def _import_docs(self, case_id: str, evidence_source_id: int, outputs: Mapping[str, object]) -> int:
        payload = read_output(outputs, "docs")
        rows = payload.get("candidates") if isinstance(payload, Mapping) else None
        if not isinstance(rows, list):
            return 0
        count = 0
        with self.connect() as connection:
            for row in rows:
                if not isinstance(row, Mapping):
                    continue
                path = Path(str(row.get("path") or ""))
                kind = str(row.get("kind") or "")
                body = safe_extract_text(path, kind)
                title = path.name
                cursor = connection.execute(
                    """
                    INSERT INTO indexed_document (
                        citation_id, case_id, evidence_source_id, source_type, field_name,
                        title, body, language, indexed_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        next_citation_id_for_connection(connection, case_id, "indexed_document"),
                        case_id,
                        evidence_source_id,
                        "document",
                        kind,
                        title,
                        body,
                        "",
                        now_iso(),
                    ),
                )
                connection.execute(
                    "INSERT INTO indexed_document_fts(rowid, title, body) VALUES (?, ?, ?)",
                    (int(cursor.lastrowid), title, body),
                )
                count += 1
        return count

    def _import_artifacts(self, case_id: str, evidence_source_id: int, outputs: Mapping[str, object]) -> int:
        count = 0
        with self.connect() as connection:
            for output_name, raw_path in sorted(outputs.items()):
                name = str(output_name)
                if not name.startswith("artifacts_"):
                    continue
                payload = read_json_path(Path(str(raw_path)))
                rows = payload.get("artifacts") if isinstance(payload, Mapping) else None
                if not isinstance(rows, list):
                    continue
                for row in rows:
                    if not isinstance(row, Mapping):
                        continue
                    artifact_type = str(row.get("artifact_type") or name.removeprefix("artifacts_"))
                    summary = artifact_summary(row)
                    connection.execute(
                        """
                        INSERT INTO artifact (
                            citation_id, case_id, evidence_source_id, artifact_type, parser_name,
                            parser_version, title, summary, data_json, confidence, created_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            next_citation_id_for_connection(connection, case_id, "artifact"),
                            case_id,
                            evidence_source_id,
                            artifact_type,
                            str(row.get("provider") or name),
                            "",
                            artifact_type,
                            summary,
                            json.dumps(dict(row), ensure_ascii=False, sort_keys=True),
                            None,
                            now_iso(),
                        ),
                    )
                    count += 1
        return count

    def _import_timeline(self, case_id: str, evidence_source_id: int, outputs: Mapping[str, object]) -> int:
        payload = read_output(outputs, "timeline")
        rows = payload.get("events") if isinstance(payload, Mapping) else None
        if not isinstance(rows, list):
            return 0
        count = 0
        with self.connect() as connection:
            for row in rows:
                if not isinstance(row, Mapping):
                    continue
                timestamp = str(row.get("timestamp") or "")
                if not timestamp:
                    continue
                connection.execute(
                    """
                    INSERT INTO event (
                        citation_id, case_id, evidence_source_id, event_type, timestamp,
                        timestamp_kind, action, target, description, source, confidence
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        next_citation_id_for_connection(connection, case_id, "event"),
                        case_id,
                        evidence_source_id,
                        str(row.get("event_type") or ""),
                        timestamp,
                        str(row.get("timestamp_kind") or ""),
                        str(row.get("event_type") or ""),
                        str(row.get("path") or ""),
                        str(row.get("summary") or ""),
                        str(row.get("source") or ""),
                        None,
                    ),
                )
                count += 1
        return count


def next_citation_id_for_connection(connection: sqlite3.Connection, case_id: str, kind: str) -> str:
    normalized_kind = kind.strip().lower()
    prefix = CITATION_KIND_PREFIXES.get(normalized_kind)
    if prefix is None:
        supported = ", ".join(sorted(CITATION_KIND_PREFIXES))
        raise CaseDatabaseError(f"unsupported citation kind: {kind} (supported: {supported})")
    case = connection.execute(
        "SELECT citation_prefix FROM case_record WHERE case_id = ?",
        (case_id,),
    ).fetchone()
    if case is None:
        raise CaseDatabaseError(f"case not found: {case_id}")
    connection.execute(
        """
        INSERT INTO citation_sequence (case_id, kind, next_value)
        VALUES (?, ?, 1)
        ON CONFLICT(case_id, kind) DO NOTHING
        """,
        (case_id, normalized_kind),
    )
    row = connection.execute(
        "SELECT next_value FROM citation_sequence WHERE case_id = ? AND kind = ?",
        (case_id, normalized_kind),
    ).fetchone()
    value = int(row["next_value"])
    connection.execute(
        "UPDATE citation_sequence SET next_value = ? WHERE case_id = ? AND kind = ?",
        (value + 1, case_id, normalized_kind),
    )
    return f"{case['citation_prefix']}-{prefix}-{value:0{CITATION_WIDTH}d}"


def open_case_database(path: Path) -> CaseDatabase:
    database = CaseDatabase(path)
    database.initialize()
    return database


def case_record_from_row(row: sqlite3.Row) -> CaseRecord:
    return CaseRecord(
        case_id=str(row["case_id"]),
        name=str(row["name"]),
        description=str(row["description"]),
        examiner=str(row["examiner"]),
        organization=str(row["organization"]),
        case_root=str(row["case_root"]),
        citation_prefix=str(row["citation_prefix"]),
        status=str(row["status"]),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
    )


def apply_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA_SQL)
    current_version = get_schema_version(connection)
    if current_version not in (0, SCHEMA_VERSION):
        raise CaseDatabaseError(f"unsupported case DB schema version: {current_version}")
    connection.execute(
        """
        INSERT INTO schema_info (key, value)
        VALUES ('schema_version', ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """,
        (str(SCHEMA_VERSION),),
    )


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


def require_tables(connection: sqlite3.Connection, table_names: Iterable[str]) -> None:
    existing = set(list_tables(connection))
    missing = sorted(set(table_names) - existing)
    if missing:
        raise CaseDatabaseError(f"case DB is missing required tables: {', '.join(missing)}")


def row_to_dict(row: Mapping[str, object]) -> dict[str, object]:
    return {key: row[key] for key in row.keys()}


def read_output(outputs: Mapping[str, object], name: str) -> dict[str, object]:
    raw_path = outputs.get(name)
    if not raw_path:
        return {}
    return read_json_path(Path(str(raw_path)))


def read_json_path(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.expanduser().resolve().read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def safe_extract_text(path: Path, kind: str) -> str:
    try:
        return extract_text(path, kind)
    except Exception:
        return ""


def hash_existing_file(path: str) -> dict[str, str]:
    if not path:
        return {}
    resolved = Path(path).expanduser()
    try:
        if not resolved.is_file():
            return {}
        return compute_hashes(resolved)
    except OSError:
        return {}


def path_size(path: str) -> int | None:
    if not path:
        return None
    try:
        resolved = Path(path).expanduser()
        return resolved.stat().st_size if resolved.is_file() else None
    except OSError:
        return None


def normalize_path_for_db(path: str) -> str:
    return path.replace("\\", "/").lower()


def optional_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def optional_str(value: Any) -> str | None:
    return str(value) if value not in (None, "") else None


def artifact_summary(row: Mapping[str, object]) -> str:
    details = row.get("details")
    details_payload = details if isinstance(details, Mapping) else {}
    for key in ("url", "source_url", "target_path", "entry_name", "summary"):
        value = details_payload.get(key) or row.get(key)
        if value:
            return str(value)
    return str(row.get("path") or row.get("artifact_type") or "artifact")


def search_indexed_documents(
    connection: sqlite3.Connection,
    case_id: str,
    keywords: list[str],
    limit: int,
) -> list[dict[str, object]]:
    query = build_fts_query(keywords)
    rows = connection.execute(
        """
        SELECT
            indexed_document.citation_id,
            indexed_document.id,
            indexed_document.source_type,
            indexed_document.field_name,
            indexed_document.title,
            snippet(indexed_document_fts, 1, '[', ']', ' ... ', 16) AS snippet
        FROM indexed_document_fts
        JOIN indexed_document ON indexed_document_fts.rowid = indexed_document.id
        WHERE indexed_document.case_id = ?
          AND indexed_document_fts MATCH ?
        ORDER BY rank
        LIMIT ?
        """,
        (case_id, query, limit or -1),
    ).fetchall()
    return [
        {
            "source": "documents",
            "citation_id": str(row["citation_id"]),
            "target_type": "indexed_document",
            "target_id": str(row["id"]),
            "title": str(row["title"]),
            "kind": str(row["field_name"]),
            "matched_keywords": matched_keywords(str(row["snippet"]), keywords),
            "preview": str(row["snippet"]),
        }
        for row in rows
    ]


def attach_review_marks(
    connection: sqlite3.Connection,
    case_id: str,
    matches: list[dict[str, object]],
) -> list[dict[str, object]]:
    if not matches:
        return matches
    rows = connection.execute(
        "SELECT * FROM review_mark WHERE case_id = ?",
        (case_id,),
    ).fetchall()
    review_by_target = {
        (str(row["target_type"]), str(row["target_id"])): review_mark_to_dict(row)
        for row in rows
    }
    output = []
    for match in matches:
        copied = dict(match)
        review = review_by_target.get((str(match.get("target_type")), str(match.get("target_id"))))
        if review is not None:
            copied["review"] = review
        else:
            copied["review"] = {
                "status": "unreviewed",
                "verification_status": "unverified",
                "include_in_report": False,
                "tags": [],
            }
        output.append(copied)
    return output


def search_file_records(
    connection: sqlite3.Connection,
    case_id: str,
    keywords: list[str],
    limit: int,
) -> list[dict[str, object]]:
    rows = connection.execute(
        """
        SELECT citation_id, id, path, extension, size_bytes, modified_at
        FROM file_record
        WHERE case_id = ?
        ORDER BY id ASC
        """,
        (case_id,),
    ).fetchall()
    matches = []
    for row in rows:
        haystack = " ".join(
            str(row[key] or "")
            for key in ("path", "extension", "size_bytes", "modified_at")
        )
        hits = matched_keywords(haystack, keywords)
        if not hits:
            continue
        matches.append(
            {
                "source": "files",
                "citation_id": str(row["citation_id"]),
                "target_type": "file_record",
                "target_id": str(row["id"]),
                "title": Path(str(row["path"])).name,
                "kind": str(row["extension"] or ""),
                "path": str(row["path"]),
                "matched_keywords": hits,
                "preview": str(row["path"]),
            }
        )
        if limit and len(matches) >= limit:
            break
    return matches


def search_artifacts(
    connection: sqlite3.Connection,
    case_id: str,
    keywords: list[str],
    limit: int,
) -> list[dict[str, object]]:
    rows = connection.execute(
        """
        SELECT citation_id, id, artifact_type, title, summary, data_json
        FROM artifact
        WHERE case_id = ?
        ORDER BY id ASC
        """,
        (case_id,),
    ).fetchall()
    matches = []
    for row in rows:
        haystack = " ".join(str(row[key] or "") for key in ("artifact_type", "title", "summary", "data_json"))
        hits = matched_keywords(haystack, keywords)
        if not hits:
            continue
        matches.append(
            {
                "source": "artifacts",
                "citation_id": str(row["citation_id"]),
                "target_type": "artifact",
                "target_id": str(row["id"]),
                "title": str(row["title"] or row["artifact_type"]),
                "kind": str(row["artifact_type"]),
                "matched_keywords": hits,
                "preview": str(row["summary"] or row["artifact_type"]),
            }
        )
        if limit and len(matches) >= limit:
            break
    return matches


def search_events(
    connection: sqlite3.Connection,
    case_id: str,
    keywords: list[str],
    limit: int,
) -> list[dict[str, object]]:
    rows = connection.execute(
        """
        SELECT citation_id, id, event_type, timestamp, target, description, source
        FROM event
        WHERE case_id = ?
        ORDER BY timestamp ASC, id ASC
        """,
        (case_id,),
    ).fetchall()
    matches = []
    for row in rows:
        haystack = " ".join(str(row[key] or "") for key in ("event_type", "timestamp", "target", "description", "source"))
        hits = matched_keywords(haystack, keywords)
        if not hits:
            continue
        matches.append(
            {
                "source": "timeline",
                "citation_id": str(row["citation_id"]),
                "target_type": "event",
                "target_id": str(row["id"]),
                "title": str(row["description"] or row["event_type"]),
                "kind": str(row["event_type"]),
                "timestamp": str(row["timestamp"]),
                "path": str(row["target"] or ""),
                "matched_keywords": hits,
                "preview": str(row["description"] or row["target"] or row["event_type"]),
            }
        )
        if limit and len(matches) >= limit:
            break
    return matches


def build_fts_query(keywords: list[str]) -> str:
    return " OR ".join(quote_fts_token(keyword) for keyword in keywords)


def quote_fts_token(keyword: str) -> str:
    escaped = keyword.replace('"', '""')
    return f'"{escaped}"'


def matched_keywords(text: str, keywords: Iterable[str]) -> list[str]:
    haystack = text.lower()
    return [keyword for keyword in keywords if keyword.lower() in haystack]


def normalize_tags(tags: Iterable[str]) -> list[str]:
    normalized = []
    seen = set()
    for item in tags:
        tag = str(item).strip()
        if not tag or tag in seen:
            continue
        seen.add(tag)
        normalized.append(tag)
    return normalized


def review_mark_to_dict(row: sqlite3.Row) -> dict[str, object]:
    try:
        tags = json.loads(str(row["tags_json"] or "[]"))
    except json.JSONDecodeError:
        tags = []
    return {
        "citation_id": str(row["citation_id"]),
        "case_id": str(row["case_id"]),
        "target_type": str(row["target_type"]),
        "target_id": str(row["target_id"]),
        "status": str(row["status"]),
        "verification_status": str(row["verification_status"]),
        "tags": tags if isinstance(tags, list) else [],
        "note": str(row["note"] or ""),
        "include_in_report": bool(row["include_in_report"]),
        "reviewer": str(row["reviewer"] or ""),
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
    }


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_info (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS case_record (
    case_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    examiner TEXT NOT NULL DEFAULT '',
    organization TEXT NOT NULL DEFAULT '',
    case_root TEXT NOT NULL DEFAULT '',
    citation_prefix TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS citation_sequence (
    case_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    next_value INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (case_id, kind),
    FOREIGN KEY (case_id) REFERENCES case_record(case_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS evidence_source (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    citation_id TEXT NOT NULL UNIQUE,
    case_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    source_type TEXT NOT NULL,
    original_path TEXT NOT NULL,
    staged_path TEXT NOT NULL DEFAULT '',
    size_bytes INTEGER,
    hash_md5 TEXT,
    hash_sha1 TEXT,
    hash_sha256 TEXT,
    detected_format TEXT NOT NULL DEFAULT '',
    adapter_name TEXT NOT NULL DEFAULT '',
    adapter_version TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    added_at TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES case_record(case_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS file_record (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    citation_id TEXT NOT NULL UNIQUE,
    case_id TEXT NOT NULL,
    evidence_source_id INTEGER,
    path TEXT NOT NULL,
    normalized_path TEXT NOT NULL DEFAULT '',
    extension TEXT NOT NULL DEFAULT '',
    mime_type TEXT NOT NULL DEFAULT '',
    size_bytes INTEGER,
    created_at TEXT,
    modified_at TEXT,
    accessed_at TEXT,
    changed_at TEXT,
    hash_md5 TEXT,
    hash_sha1 TEXT,
    hash_sha256 TEXT,
    is_deleted INTEGER NOT NULL DEFAULT 0,
    is_recovered INTEGER NOT NULL DEFAULT 0,
    source_offset INTEGER,
    parent_id INTEGER,
    FOREIGN KEY (case_id) REFERENCES case_record(case_id) ON DELETE CASCADE,
    FOREIGN KEY (evidence_source_id) REFERENCES evidence_source(id) ON DELETE SET NULL,
    FOREIGN KEY (parent_id) REFERENCES file_record(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS hash_record (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    citation_id TEXT NOT NULL UNIQUE,
    case_id TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    hash_scope TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    value TEXT NOT NULL,
    calculated_at TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES case_record(case_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS artifact (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    citation_id TEXT NOT NULL UNIQUE,
    case_id TEXT NOT NULL,
    evidence_source_id INTEGER,
    file_record_id INTEGER,
    artifact_type TEXT NOT NULL,
    parser_name TEXT NOT NULL,
    parser_version TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    data_json TEXT NOT NULL DEFAULT '{}',
    confidence REAL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES case_record(case_id) ON DELETE CASCADE,
    FOREIGN KEY (evidence_source_id) REFERENCES evidence_source(id) ON DELETE SET NULL,
    FOREIGN KEY (file_record_id) REFERENCES file_record(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS event (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    citation_id TEXT NOT NULL UNIQUE,
    case_id TEXT NOT NULL,
    evidence_source_id INTEGER,
    artifact_id INTEGER,
    file_record_id INTEGER,
    event_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    timestamp_kind TEXT NOT NULL DEFAULT '',
    timezone TEXT NOT NULL DEFAULT '',
    actor TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL DEFAULT '',
    target TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    confidence REAL,
    FOREIGN KEY (case_id) REFERENCES case_record(case_id) ON DELETE CASCADE,
    FOREIGN KEY (evidence_source_id) REFERENCES evidence_source(id) ON DELETE SET NULL,
    FOREIGN KEY (artifact_id) REFERENCES artifact(id) ON DELETE SET NULL,
    FOREIGN KEY (file_record_id) REFERENCES file_record(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS indexed_document (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    citation_id TEXT NOT NULL UNIQUE,
    case_id TEXT NOT NULL,
    evidence_source_id INTEGER,
    file_record_id INTEGER,
    artifact_id INTEGER,
    source_type TEXT NOT NULL,
    field_name TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL DEFAULT '',
    language TEXT NOT NULL DEFAULT '',
    ocr_confidence REAL,
    indexed_at TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES case_record(case_id) ON DELETE CASCADE,
    FOREIGN KEY (evidence_source_id) REFERENCES evidence_source(id) ON DELETE SET NULL,
    FOREIGN KEY (file_record_id) REFERENCES file_record(id) ON DELETE SET NULL,
    FOREIGN KEY (artifact_id) REFERENCES artifact(id) ON DELETE SET NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS indexed_document_fts USING fts5(
    title,
    body,
    content='indexed_document',
    content_rowid='id'
);

CREATE TABLE IF NOT EXISTS review_mark (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    citation_id TEXT NOT NULL UNIQUE,
    case_id TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'unreviewed',
    verification_status TEXT NOT NULL DEFAULT 'unverified',
    tags_json TEXT NOT NULL DEFAULT '[]',
    note TEXT NOT NULL DEFAULT '',
    include_in_report INTEGER NOT NULL DEFAULT 0,
    reviewer TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES case_record(case_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_event (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    citation_id TEXT NOT NULL UNIQUE,
    case_id TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT '',
    target_id TEXT NOT NULL DEFAULT '',
    timestamp TEXT NOT NULL,
    tool_name TEXT NOT NULL DEFAULT '',
    tool_version TEXT NOT NULL DEFAULT '',
    params_json TEXT NOT NULL DEFAULT '{}',
    result TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (case_id) REFERENCES case_record(case_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS report_item (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    citation_id TEXT NOT NULL UNIQUE,
    case_id TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    section TEXT NOT NULL,
    title TEXT NOT NULL DEFAULT '',
    narrative TEXT NOT NULL DEFAULT '',
    order_index INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES case_record(case_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS job (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    citation_id TEXT NOT NULL UNIQUE,
    case_id TEXT NOT NULL,
    job_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    params_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES case_record(case_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS job_step (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL,
    step_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    retry_count INTEGER NOT NULL DEFAULT 0,
    started_at TEXT,
    completed_at TEXT,
    error TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (job_id) REFERENCES job(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_evidence_source_case ON evidence_source(case_id);
CREATE INDEX IF NOT EXISTS idx_file_record_case_path ON file_record(case_id, normalized_path);
CREATE INDEX IF NOT EXISTS idx_hash_record_case_scope ON hash_record(case_id, hash_scope, algorithm);
CREATE INDEX IF NOT EXISTS idx_artifact_case_type ON artifact(case_id, artifact_type);
CREATE INDEX IF NOT EXISTS idx_event_case_time ON event(case_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_indexed_document_case_source ON indexed_document(case_id, source_type);
CREATE INDEX IF NOT EXISTS idx_review_mark_case_status ON review_mark(case_id, status, verification_status);
CREATE INDEX IF NOT EXISTS idx_audit_event_case_time ON audit_event(case_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_report_item_case_section ON report_item(case_id, section, order_index);
CREATE INDEX IF NOT EXISTS idx_job_case_status ON job(case_id, status);
"""
