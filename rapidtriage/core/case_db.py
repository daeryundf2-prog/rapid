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
    "search": "SRCH",
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

    def case_storage_summary(self, case_id: str) -> dict[str, object]:
        normalized_case_id = normalize_identifier(case_id, fallback="case")
        with self.connect() as connection:
            apply_schema(connection)
            case_row = connection.execute(
                "SELECT case_id FROM case_record WHERE case_id = ?",
                (normalized_case_id,),
            ).fetchone()
            counts = {
                "evidence_source_count": count_rows(connection, "evidence_source", normalized_case_id),
                "file_record_count": count_rows(connection, "file_record", normalized_case_id),
                "indexed_document_count": count_rows(connection, "indexed_document", normalized_case_id),
                "artifact_count": count_rows(connection, "artifact", normalized_case_id),
                "event_count": count_rows(connection, "event", normalized_case_id),
                "review_mark_count": count_rows(connection, "review_mark", normalized_case_id),
                "saved_search_count": count_rows(connection, "saved_search", normalized_case_id),
            }
        return {
            "case_id": normalized_case_id,
            "exists": case_row is not None,
            "summary": counts,
        }

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
            "indicator_count": self._import_indicators(case_id, evidence_source_id, outputs),
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

    def import_vsc_compare(
        self,
        vsc_compare_json: Mapping[str, object] | Path,
        *,
        case_id: str,
        case_name: Optional[str] = None,
    ) -> dict[str, object]:
        payload = read_json_path(vsc_compare_json) if isinstance(vsc_compare_json, Path) else dict(vsc_compare_json)
        if str(payload.get("tool") or "") != "rapidtriage-vsc-compare":
            raise CaseDatabaseError("VSC compare JSON must come from rapidtriage vsc-compare")
        normalized_case_id = normalize_identifier(case_id, fallback="case")
        current_root = Path(str(payload.get("current_root") or "")).expanduser()
        case_root = current_root.resolve() if str(current_root) else None

        with self.connect() as connection:
            apply_schema(connection)
            case_row = connection.execute("SELECT case_id FROM case_record WHERE case_id = ?", (normalized_case_id,)).fetchone()
        if case_row is None:
            self.create_case(case_id=normalized_case_id, name=case_name, case_root=case_root)

        source_payload = {
            "source": {
                "source_path": str(vsc_compare_json) if isinstance(vsc_compare_json, Path) else str(payload.get("current_root") or ""),
                "analysis_root": str(payload.get("current_root") or ""),
                "type": "vsc-compare",
            },
            "mode": "vsc-compare",
            "root": str(payload.get("current_root") or ""),
        }
        evidence_source_id = self._insert_evidence_source(normalized_case_id, source_payload)
        artifact_count = self._import_vsc_artifacts(normalized_case_id, evidence_source_id, payload)
        audit_id = self.add_audit_event(
            case_id=normalized_case_id,
            action="vsc-compare.imported",
            target_type="vsc-compare",
            target_id=str(vsc_compare_json) if isinstance(vsc_compare_json, Path) else "",
            params_json=json.dumps({"artifact_count": artifact_count}, ensure_ascii=False, sort_keys=True),
        )
        return {
            "case_id": normalized_case_id,
            "audit_citation_id": audit_id,
            "summary": {
                "evidence_source_count": 1,
                "artifact_count": artifact_count,
            },
        }

    def search_case(
        self,
        *,
        case_id: str,
        keywords: Iterable[str],
        limit: int = 100,
        sources: Iterable[str] | None = None,
        metadata_filters: Iterable[str] | None = None,
        review_status: str | None = None,
        verification_status: str | None = None,
    ) -> dict[str, object]:
        normalized_keywords = [keyword.strip() for keyword in keywords if keyword.strip()]
        if not normalized_keywords:
            raise CaseDatabaseError("at least one keyword is required")
        normalized_case_id = normalize_identifier(case_id, fallback="case")
        source_filter = {source.strip() for source in (sources or []) if source.strip()}
        metadata_filter = parse_metadata_filters(metadata_filters or [])
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
            if metadata_filter:
                matches = [match for match in matches if metadata_matches(match.get("metadata"), metadata_filter)]
            if review_status:
                matches = [
                    match
                    for match in matches
                    if str((match.get("review") or {}).get("status") or "unreviewed") == review_status
                ]
            if verification_status:
                matches = [
                    match
                    for match in matches
                    if str((match.get("review") or {}).get("verification_status") or "unverified") == verification_status
                ]
            matches = enrich_case_search_matches(matches, normalized_keywords)
            if limit:
                matches = matches[:limit]

        source_counts: dict[str, int] = {}
        keyword_counts: dict[str, int] = {keyword.lower(): 0 for keyword in normalized_keywords}
        priority_counts: dict[str, int] = {}
        for match in matches:
            source = str(match.get("source") or "unknown")
            source_counts[source] = source_counts.get(source, 0) + 1
            priority_level = str((match.get("review_priority") or {}).get("level") or "low")
            priority_counts[priority_level] = priority_counts.get(priority_level, 0) + 1
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
                "metadata": dict(metadata_filter),
                "review_status": review_status,
                "verification_status": verification_status,
            },
            "summary": {
                "match_count": len(matches),
                "source_counts": source_counts,
                "keyword_counts": keyword_counts,
                "priority_counts": priority_counts,
            },
            "matches": matches,
        }

    def save_search(
        self,
        *,
        case_id: str,
        name: str,
        keywords: Iterable[str],
        sources: Iterable[str] | None = None,
        metadata_filters: Iterable[str] | None = None,
        review_status: str | None = None,
        verification_status: str | None = None,
        limit: int = 100,
        created_by: str = "",
    ) -> dict[str, object]:
        normalized_case_id = normalize_identifier(case_id, fallback="case")
        normalized_keywords = [keyword.strip() for keyword in keywords if keyword.strip()]
        if not normalized_keywords:
            raise CaseDatabaseError("at least one keyword is required")
        normalized_name = name.strip()
        if not normalized_name:
            raise CaseDatabaseError("saved search name is required")
        timestamp = now_iso()
        filters = {
            "keywords": normalized_keywords,
            "sources": [source.strip() for source in (sources or []) if source.strip()],
            "metadata": dict(parse_metadata_filters(metadata_filters or [])),
            "review_status": review_status,
            "verification_status": verification_status,
            "limit": limit,
        }
        with self.connect() as connection:
            apply_schema(connection)
            if connection.execute("SELECT 1 FROM case_record WHERE case_id = ?", (normalized_case_id,)).fetchone() is None:
                raise CaseDatabaseError(f"case not found: {normalized_case_id}")
            row = connection.execute(
                """
                SELECT id, citation_id, created_at FROM saved_search
                WHERE case_id = ? AND name = ?
                LIMIT 1
                """,
                (normalized_case_id, normalized_name),
            ).fetchone()
            if row is None:
                citation_id = next_citation_id_for_connection(connection, normalized_case_id, "search")
                connection.execute(
                    """
                    INSERT INTO saved_search (
                        citation_id, case_id, name, keywords_json, filters_json,
                        created_by, created_at, updated_at, last_run_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        citation_id,
                        normalized_case_id,
                        normalized_name,
                        json.dumps(normalized_keywords, ensure_ascii=False),
                        json.dumps(filters, ensure_ascii=False, sort_keys=True),
                        created_by,
                        timestamp,
                        timestamp,
                        timestamp,
                    ),
                )
            else:
                citation_id = str(row["citation_id"])
                connection.execute(
                    """
                    UPDATE saved_search
                    SET keywords_json = ?, filters_json = ?, created_by = ?,
                        updated_at = ?, last_run_at = ?
                    WHERE id = ?
                    """,
                    (
                        json.dumps(normalized_keywords, ensure_ascii=False),
                        json.dumps(filters, ensure_ascii=False, sort_keys=True),
                        created_by,
                        timestamp,
                        timestamp,
                        row["id"],
                    ),
                )
            connection.execute(
                "UPDATE case_record SET updated_at = ? WHERE case_id = ?",
                (timestamp, normalized_case_id),
            )
        return self.get_saved_search(normalized_case_id, name=normalized_name)

    def list_saved_searches(self, case_id: str) -> list[dict[str, object]]:
        normalized_case_id = normalize_identifier(case_id, fallback="case")
        with self.connect() as connection:
            apply_schema(connection)
            rows = connection.execute(
                "SELECT * FROM saved_search WHERE case_id = ? ORDER BY updated_at DESC, name ASC",
                (normalized_case_id,),
            ).fetchall()
        return [saved_search_to_dict(row) for row in rows]

    def get_saved_search(self, case_id: str, *, name: str) -> dict[str, object]:
        normalized_case_id = normalize_identifier(case_id, fallback="case")
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM saved_search
                WHERE case_id = ? AND name = ?
                LIMIT 1
                """,
                (normalized_case_id, name),
            ).fetchone()
        if row is None:
            raise CaseDatabaseError(f"saved search not found: {name}")
        return saved_search_to_dict(row)

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

    def mark_reviews_batch(
        self,
        *,
        case_id: str,
        targets: Iterable[Mapping[str, object]],
        status: str = "unreviewed",
        verification_status: str = "unverified",
        tags: Iterable[str] | None = None,
        note: str = "",
        include_in_report: bool = False,
        reviewer: str = "",
    ) -> dict[str, object]:
        marks: list[dict[str, object]] = []
        for target in targets:
            target_type = str(target.get("target_type") or "").strip()
            target_id = str(target.get("target_id") or "").strip()
            if not target_type or not target_id:
                raise CaseDatabaseError("every batch target requires target_type and target_id")
            marks.append(
                self.mark_review(
                    case_id=case_id,
                    target_type=target_type,
                    target_id=target_id,
                    status=status,
                    verification_status=verification_status,
                    tags=tags or [],
                    note=note,
                    include_in_report=include_in_report,
                    reviewer=reviewer,
                )
            )
        return {
            "command": "case-review-batch",
            "generated_at": now_iso(),
            "database": str(self.path),
            "case_id": normalize_identifier(case_id, fallback="case"),
            "updated_count": len(marks),
            "marks": marks,
        }

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
                    details = artifact_details(row)
                    title = artifact_title(row)
                    summary = artifact_summary(row)
                    cursor = connection.execute(
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
                            str(details.get("parser") or row.get("provider") or name),
                            str(details.get("parser_version") or ""),
                            title,
                            summary,
                            json.dumps(dict(row), ensure_ascii=False, sort_keys=True),
                            None,
                            now_iso(),
                        ),
                    )
                    connection.execute(
                        "INSERT INTO artifact_fts(rowid, title, summary, metadata) VALUES (?, ?, ?, ?)",
                        (int(cursor.lastrowid), title, summary, artifact_index_text(row)),
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

    def _import_indicators(self, case_id: str, evidence_source_id: int, outputs: Mapping[str, object]) -> int:
        payload = read_output(outputs, "indicators")
        rows = payload.get("indicators") if isinstance(payload, Mapping) else None
        if not isinstance(rows, list):
            return 0
        count = 0
        with self.connect() as connection:
            for index, row in enumerate(rows):
                if not isinstance(row, Mapping):
                    continue
                artifact = indicator_artifact_row(row, index=index)
                details = artifact_details(artifact)
                title = artifact_title(artifact)
                summary = artifact_summary(artifact)
                cursor = connection.execute(
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
                        str(artifact.get("artifact_type") or "indicator"),
                        str(details.get("parser") or "rapidtriage-indicators"),
                        str(details.get("parser_version") or "1"),
                        title,
                        summary,
                        json.dumps(artifact, ensure_ascii=False, sort_keys=True),
                        None,
                        now_iso(),
                    ),
                )
                connection.execute(
                    "INSERT INTO artifact_fts(rowid, title, summary, metadata) VALUES (?, ?, ?, ?)",
                    (int(cursor.lastrowid), title, summary, artifact_index_text(artifact)),
                )
                count += 1
        return count

    def _import_vsc_artifacts(self, case_id: str, evidence_source_id: int, payload: Mapping[str, object]) -> int:
        comparisons = payload.get("comparisons")
        if not isinstance(comparisons, list):
            return 0
        count = 0
        with self.connect() as connection:
            for comparison in comparisons:
                if not isinstance(comparison, Mapping):
                    continue
                snapshot_label = str(comparison.get("snapshot_label") or "")
                snapshot_root = str(comparison.get("snapshot_root") or "")
                records = comparison.get("records")
                if not isinstance(records, list):
                    continue
                for index, record in enumerate(records):
                    if not isinstance(record, Mapping):
                        continue
                    artifact = vsc_artifact_row(record, snapshot_label=snapshot_label, snapshot_root=snapshot_root, index=index)
                    details = artifact_details(artifact)
                    title = artifact_title(artifact)
                    summary = artifact_summary(artifact)
                    cursor = connection.execute(
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
                            str(artifact.get("artifact_type") or "vsc-change"),
                            str(details.get("parser") or "rapidtriage-vsc-compare"),
                            str(details.get("parser_version") or "1"),
                            title,
                            summary,
                            json.dumps(artifact, ensure_ascii=False, sort_keys=True),
                            None,
                            now_iso(),
                        ),
                    )
                    connection.execute(
                        "INSERT INTO artifact_fts(rowid, title, summary, metadata) VALUES (?, ?, ?, ?)",
                        (int(cursor.lastrowid), title, summary, artifact_index_text(artifact)),
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


def count_rows(connection: sqlite3.Connection, table_name: str, case_id: str) -> int:
    row = connection.execute(f"SELECT COUNT(*) AS count FROM {table_name} WHERE case_id = ?", (case_id,)).fetchone()
    return int(row["count"]) if row is not None else 0


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


def parse_metadata_filters(filters: Iterable[str]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for item in filters:
        text = str(item or "").strip()
        if not text:
            continue
        if "=" not in text:
            raise CaseDatabaseError(f"metadata filter must be KEY=VALUE: {text}")
        key, value = text.split("=", 1)
        key = key.strip()
        if not key:
            raise CaseDatabaseError(f"metadata filter key is empty: {text}")
        parsed[key] = value.strip()
    return parsed


def metadata_matches(metadata: object, filters: Mapping[str, str]) -> bool:
    if not isinstance(metadata, Mapping):
        return False
    for key, expected in filters.items():
        value = metadata.get(key)
        if isinstance(value, list):
            haystack = " ".join(str(item) for item in value)
        else:
            haystack = str(value or "")
        if expected.lower() not in haystack.lower():
            return False
    return True


def artifact_details(row: Mapping[str, object]) -> Mapping[str, object]:
    details = row.get("details")
    return details if isinstance(details, Mapping) else {}


def artifact_summary(row: Mapping[str, object]) -> str:
    details_payload = artifact_details(row)
    indicator_value = details_payload.get("indicator_value")
    if indicator_value:
        return " ".join(
            str(part)
            for part in (
                details_payload.get("indicator_type"),
                indicator_value,
                details_payload.get("classification"),
            )
            if part
        )
    event_id = details_payload.get("event_id")
    if event_id:
        parts = [
            f"event_id={event_id}",
            str(details_payload.get("event_category") or ""),
            field_label("user", details_payload.get("user_name") or details_payload.get("target_user_name")),
            field_label("ip", details_payload.get("source_ip")),
            field_label("cmd", details_payload.get("command_line") or details_payload.get("script_block_text")),
        ]
        summary = " ".join(part for part in parts if part)
        if summary:
            return summary

    for key in (
        "relative_path",
        "current_path",
        "snapshot_path",
        "command_line",
        "script_block_text",
        "file_path",
        "executable_path",
        "data_url",
        "origin_url",
        "url",
        "source_url",
        "target_path",
        "label",
        "program",
        "home_path",
        "entry_name",
        "service_name",
        "process_name",
        "summary",
    ):
        value = details_payload.get(key) or row.get(key)
        if value:
            return str(value)
    nested = artifact_nested_preview(details_payload)
    if nested:
        return nested
    return str(row.get("path") or row.get("artifact_type") or "artifact")


def artifact_title(row: Mapping[str, object]) -> str:
    artifact_type = str(row.get("artifact_type") or "artifact")
    details = artifact_details(row)
    indicator_value = details.get("indicator_value")
    if indicator_value:
        return f"{artifact_type}: {compact_text(str(indicator_value), 80)}"
    event_id = details.get("event_id")
    if event_id:
        category = details.get("event_category") or "event"
        return f"{artifact_type} {event_id} {category}"
    if "browser" in artifact_type:
        nested = artifact_nested_preview(details)
        if nested:
            return f"{artifact_type}: {compact_text(nested, 80)}"
    for key in (
        "relative_path",
        "current_path",
        "snapshot_path",
        "command_line",
        "file_path",
        "executable_path",
        "data_url",
        "origin_url",
        "label",
        "program",
        "entry_name",
        "source_path",
    ):
        value = details.get(key)
        if value:
            return f"{artifact_type}: {compact_text(str(value), 80)}"
    nested = artifact_nested_preview(details)
    if nested:
        return f"{artifact_type}: {compact_text(nested, 80)}"
    return artifact_type


def artifact_source_path(row: Mapping[str, object]) -> str:
    details = artifact_details(row)
    for value in (
        row.get("path"),
        details.get("source_path"),
        details.get("current_path"),
        details.get("snapshot_path"),
        details.get("target_path"),
        details.get("file_path"),
        details.get("source_path"),
    ):
        if value:
            return str(value)
    return ""


def artifact_search_metadata(row: Mapping[str, object]) -> dict[str, object]:
    details = artifact_details(row)
    keys = (
        "parser",
        "parser_version",
        "coverage_status",
        "reportability",
        "status",
        "relative_path",
        "snapshot_label",
        "snapshot_path",
        "current_path",
        "snapshot_modified_at",
        "current_modified_at",
        "snapshot_sha256",
        "current_sha256",
        "event_id",
        "event_category",
        "event_family",
        "event_tags",
        "event_description",
        "channel",
        "channel_family",
        "computer",
        "user_name",
        "subject_user_name",
        "target_user_name",
        "target_domain_name",
        "logon_type",
        "source_ip",
        "source_port",
        "destination_ip",
        "destination_hostname",
        "destination_port",
        "service_name",
        "service_file_name",
        "process_name",
        "new_process_name",
        "parent_process_name",
        "parent_command_line",
        "command_line",
        "script_block_text",
        "query_name",
        "target_object",
        "image_loaded",
        "task_name",
        "workstation_name",
        "logon_process_name",
        "authentication_package_name",
        "status_code",
        "failure_reason",
        "share_name",
        "relative_target_name",
        "triage_recommendation",
        "matched_fields",
        "false_positive_note",
        "file_path",
        "executable_path",
        "reason",
        "timestamp",
        "risk_score",
        "risk_flags",
        "evidence_strength",
        "user",
        "browser",
        "profile",
        "history_count",
        "download_count",
        "internet_usage_count",
        "ai_usage_count",
        "ai_conversation_candidate_count",
        "question_count",
        "answer_count",
        "ai_service",
        "domain",
        "query_hint",
        "prompt_hint",
        "first_seen_at",
        "last_seen_at",
        "ai_service_counts",
        "internet_category_counts",
        "top_domains",
        "agent_name",
        "data_url",
        "origin_url",
        "sender_name",
        "home_path",
        "label",
        "program",
        "program_arguments",
        "run_at_load",
        "modified_at",
        "indicator_type",
        "indicator_value",
        "classification",
        "count",
        "source_hashes",
        "record_hashes",
        "source_path",
        "source_format",
        "source_index",
        "record_offset",
        "file_offset",
        "raw_record_preview",
        "extraction_method",
        "parser_confidence",
        "matched_rules",
    )
    metadata = {key: details[key] for key in keys if details.get(key) not in (None, "", [])}
    nested = artifact_nested_preview(details)
    if nested:
        metadata["preview_value"] = nested
    return metadata


def artifact_index_text(row: Mapping[str, object]) -> str:
    details = artifact_details(row)
    searchable = {
        "artifact_type": row.get("artifact_type"),
        "provider": row.get("provider"),
        "path": row.get("path"),
        "details": details,
        "metadata": artifact_search_metadata(row),
    }
    return json.dumps(searchable, ensure_ascii=False, sort_keys=True)


def artifact_nested_preview(details: Mapping[str, object]) -> str:
    for key in ("conversation_candidates", "ai_conversation_candidates", "ai_usage", "internet_usage", "downloads", "history"):
        rows = details.get(key)
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            for value_key in ("text", "ai_service", "query_hint", "prompt_hint", "source_url", "url", "target_path", "title", "domain"):
                value = row.get(value_key)
                if value:
                    return str(value)
    return ""


def vsc_artifact_row(
    record: Mapping[str, object],
    *,
    snapshot_label: str,
    snapshot_root: str,
    index: int,
) -> dict[str, object]:
    status = str(record.get("status") or "change")
    relative_path = str(record.get("relative_path") or "")
    snapshot = record.get("snapshot") if isinstance(record.get("snapshot"), Mapping) else {}
    current = record.get("current") if isinstance(record.get("current"), Mapping) else {}
    snapshot_path = str(snapshot.get("path") or "") if isinstance(snapshot, Mapping) else ""
    current_path = str(current.get("path") or "") if isinstance(current, Mapping) else ""
    review_path = current_path or snapshot_path or relative_path
    details = {
        "parser": "rapidtriage-vsc-compare-import",
        "parser_version": "1",
        "coverage_status": "mapped",
        "reportability": "triage",
        "source_format": "vsc-compare-json",
        "source_index": index,
        "status": status,
        "relative_path": relative_path,
        "snapshot_label": snapshot_label,
        "snapshot_root": snapshot_root,
        "snapshot_path": snapshot_path,
        "current_path": current_path,
        "snapshot_size": snapshot.get("size") if isinstance(snapshot, Mapping) else None,
        "current_size": current.get("size") if isinstance(current, Mapping) else None,
        "snapshot_modified_at": snapshot.get("modified_at") if isinstance(snapshot, Mapping) else "",
        "current_modified_at": current.get("modified_at") if isinstance(current, Mapping) else "",
        "snapshot_sha256": snapshot.get("sha256") if isinstance(snapshot, Mapping) else "",
        "current_sha256": current.get("sha256") if isinstance(current, Mapping) else "",
        "evidence_strength": "snapshot-file-delta",
        "raw": dict(record),
    }
    return {
        "provider": "rapidtriage-vsc-compare",
        "artifact_type": f"vsc-{status}-file",
        "path": review_path,
        "supported": True,
        "details": details,
    }


def indicator_artifact_row(row: Mapping[str, object], *, index: int) -> dict[str, object]:
    indicator_type = str(row.get("type") or "indicator")
    indicator_value = str(row.get("value") or "")
    sources = row.get("sources") if isinstance(row.get("sources"), list) else []
    first_source = sources[0] if sources and isinstance(sources[0], Mapping) else {}
    source_path = str(first_source.get("path") or first_source.get("source_path") or "")
    output_path = str(first_source.get("output_path") or "")
    details = {
        "parser": "rapidtriage-indicators",
        "parser_version": "1",
        "coverage_status": "run-output-summary",
        "reportability": "triage",
        "source_format": "rapidtriage-indicators-json",
        "source_index": index,
        "source_path": source_path,
        "output_path": output_path,
        "indicator_type": indicator_type,
        "indicator_value": indicator_value,
        "count": optional_int(row.get("count")) or 0,
        "classification": str(row.get("classification") or ""),
        "risk_flags": list(row.get("risk_flags", [])) if isinstance(row.get("risk_flags"), list) else [],
        "matched_rules": list(row.get("matched_rules", [])) if isinstance(row.get("matched_rules"), list) else [],
        "sources": sources,
        "evidence_strength": "indicator-pivot",
        "raw": dict(row),
    }
    return {
        "provider": "rapidtriage-indicators",
        "artifact_type": f"indicator-{indicator_type}",
        "path": source_path or output_path,
        "supported": True,
        "details": details,
    }


def parse_json_object(value: object) -> dict[str, object]:
    if isinstance(value, Mapping):
        return dict(value)
    try:
        payload = json.loads(str(value or "{}"))
    except json.JSONDecodeError:
        return {}
    return dict(payload) if isinstance(payload, Mapping) else {}


def field_label(name: str, value: object) -> str:
    return f"{name}={value}" if value not in (None, "") else ""


def compact_text(value: str, limit: int) -> str:
    text = " ".join(value.split())
    return text if len(text) <= limit else f"{text[: limit - 1]}..."


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


def enrich_case_search_matches(matches: list[dict[str, object]], keywords: list[str]) -> list[dict[str, object]]:
    enriched = []
    for index, match in enumerate(matches):
        copied = dict(match)
        copied["source_reference"] = build_source_reference(copied)
        copied["review_priority"] = build_review_priority(copied, keywords)
        copied["_result_order"] = index
        enriched.append(copied)
    enriched.sort(key=case_search_priority_sort_key)
    for match in enriched:
        match.pop("_result_order", None)
    return enriched


def case_search_priority_sort_key(match: Mapping[str, object]) -> tuple[int, int]:
    priority = match.get("review_priority") if isinstance(match.get("review_priority"), Mapping) else {}
    score = optional_int(priority.get("score")) or 0
    order = optional_int(match.get("_result_order")) or 0
    return (-score, order)


def build_source_reference(match: Mapping[str, object]) -> dict[str, object]:
    metadata = match.get("metadata") if isinstance(match.get("metadata"), Mapping) else {}
    source_hashes = metadata.get("source_hashes") if isinstance(metadata.get("source_hashes"), Mapping) else {}
    record_hashes = metadata.get("record_hashes") if isinstance(metadata.get("record_hashes"), Mapping) else {}
    reference = {
        "citation_id": str(match.get("citation_id") or ""),
        "target_type": str(match.get("target_type") or ""),
        "target_id": str(match.get("target_id") or ""),
        "path": str(metadata.get("source_path") or match.get("path") or ""),
        "source_format": str(metadata.get("source_format") or ""),
        "parser": str(metadata.get("parser") or ""),
        "parser_version": str(metadata.get("parser_version") or ""),
        "parser_confidence": metadata.get("parser_confidence"),
        "source_index": metadata.get("source_index"),
        "record_offset": metadata.get("record_offset") or metadata.get("file_offset"),
        "source_hashes": dict(source_hashes),
        "record_hashes": dict(record_hashes),
        "evidence_strength": str(metadata.get("evidence_strength") or ""),
        "reportability": str(metadata.get("reportability") or ""),
        "coverage_status": str(metadata.get("coverage_status") or ""),
    }
    return {
        key: value
        for key, value in reference.items()
        if value not in (None, "", {}, [])
    }


def build_review_priority(match: Mapping[str, object], keywords: list[str]) -> dict[str, object]:
    metadata = match.get("metadata") if isinstance(match.get("metadata"), Mapping) else {}
    source = str(match.get("source") or "")
    kind = str(match.get("kind") or "")
    title_preview = " ".join(str(match.get(key) or "") for key in ("title", "preview", "path")).lower()
    score = 0
    reasons: list[str] = []

    risk_score = optional_int(metadata.get("risk_score"))
    if risk_score:
        score += min(100, risk_score)
        reasons.append(f"parser risk score {risk_score}")
    risk_flags = metadata.get("risk_flags") if isinstance(metadata.get("risk_flags"), list) else []
    if risk_flags:
        score += min(30, len(risk_flags) * 10)
        reasons.append(f"{len(risk_flags)} risk flag(s)")
    matched_rules = metadata.get("matched_rules") if isinstance(metadata.get("matched_rules"), list) else []
    if matched_rules:
        score += min(30, len(matched_rules) * 15)
        reasons.append(f"{len(matched_rules)} matched rule(s)")
    if source == "indicators":
        score += 25
        reasons.append("IOC/indicator pivot")
    if source == "artifacts" and any(token in kind for token in ("eventlog", "powershell", "wmi", "prefetch", "registry-run", "rdp")):
        score += 20
        reasons.append("high-value Windows artifact")
    if any(token in title_preview for token in ("password", "credential", "token", "secret", "powershell", "rundll32", "wmic", "bitlocker")):
        score += 15
        reasons.append("high-value keyword context")
    if metadata.get("ai_service") or metadata.get("ai_conversation_candidate_count"):
        score += 12
        reasons.append("AI-service activity context")
    if metadata.get("source_hashes") or metadata.get("record_hashes"):
        reasons.append("hash-backed source reference")
    if metadata.get("parser_confidence") not in (None, ""):
        reasons.append("parser confidence available")

    score = max(0, min(100, score))
    if score >= 70:
        level = "high"
        recommended_action = "verify source, preserve hash context, and consider report inclusion"
    elif score >= 35:
        level = "medium"
        recommended_action = "review source preview and classify relevance"
    else:
        level = "low"
        recommended_action = "triage when higher-priority hits are cleared"
    return {
        "score": score,
        "level": level,
        "reasons": reasons[:6],
        "recommended_action": recommended_action,
    }


def search_file_records(
    connection: sqlite3.Connection,
    case_id: str,
    keywords: list[str],
    limit: int,
) -> list[dict[str, object]]:
    rows = connection.execute(
        """
        SELECT citation_id, id, path, extension, size_bytes, modified_at, hash_md5, hash_sha1, hash_sha256
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
                "metadata": {
                    "size_bytes": optional_int(row["size_bytes"]),
                    "modified_at": optional_str(row["modified_at"]),
                    "source_hashes": {
                        key: str(row[column])
                        for key, column in (("md5", "hash_md5"), ("sha1", "hash_sha1"), ("sha256", "hash_sha256"))
                        if row[column]
                    },
                },
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
    if artifact_fts_has_rows(connection, case_id):
        fts_matches = search_artifacts_fts(connection, case_id, keywords, limit)
        scan_matches = search_artifacts_scan(connection, case_id, keywords, limit)
        return dedupe_matches([*fts_matches, *scan_matches], limit=limit)
    return search_artifacts_scan(connection, case_id, keywords, limit)


def search_artifacts_scan(
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
        artifact_row = parse_json_object(row["data_json"])
        metadata = artifact_search_metadata(artifact_row)
        matches.append(
            {
                "source": artifact_match_source(str(row["artifact_type"])),
                "citation_id": str(row["citation_id"]),
                "target_type": "artifact",
                "target_id": str(row["id"]),
                "title": str(row["title"] or row["artifact_type"]),
                "kind": str(row["artifact_type"]),
                "path": artifact_source_path(artifact_row),
                "matched_keywords": hits,
                "preview": str(row["summary"] or row["artifact_type"]),
                "metadata": metadata,
            }
        )
        if limit and len(matches) >= limit:
            break
    return matches


def artifact_match_source(artifact_type: str) -> str:
    return "indicators" if artifact_type.startswith("indicator-") else "artifacts"


def dedupe_matches(matches: list[dict[str, object]], *, limit: int) -> list[dict[str, object]]:
    output = []
    seen: set[tuple[str, str]] = set()
    for match in matches:
        key = (str(match.get("target_type") or ""), str(match.get("target_id") or ""))
        if key in seen:
            continue
        seen.add(key)
        output.append(match)
        if limit and len(output) >= limit:
            break
    return output


def artifact_fts_has_rows(connection: sqlite3.Connection, case_id: str) -> bool:
    try:
        row = connection.execute(
            """
            SELECT 1
            FROM artifact_fts
            JOIN artifact ON artifact_fts.rowid = artifact.id
            WHERE artifact.case_id = ?
            LIMIT 1
            """,
            (case_id,),
        ).fetchone()
    except sqlite3.OperationalError:
        return False
    return row is not None


def search_artifacts_fts(
    connection: sqlite3.Connection,
    case_id: str,
    keywords: list[str],
    limit: int,
) -> list[dict[str, object]]:
    query = build_fts_query(keywords)
    try:
        rows = connection.execute(
            """
            SELECT
                artifact.citation_id,
                artifact.id,
                artifact.artifact_type,
                artifact.title,
                artifact.summary,
                artifact.data_json,
                snippet(artifact_fts, 2, '[', ']', ' ... ', 18) AS snippet
            FROM artifact_fts
            JOIN artifact ON artifact_fts.rowid = artifact.id
            WHERE artifact.case_id = ?
              AND artifact_fts MATCH ?
            ORDER BY rank
            LIMIT ?
            """,
            (case_id, query, limit or -1),
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    matches = []
    for row in rows:
        artifact_row = parse_json_object(row["data_json"])
        metadata = artifact_search_metadata(artifact_row)
        preview = str(row["summary"] or row["snippet"] or row["artifact_type"])
        matches.append(
            {
                "source": artifact_match_source(str(row["artifact_type"])),
                "citation_id": str(row["citation_id"]),
                "target_type": "artifact",
                "target_id": str(row["id"]),
                "title": str(row["title"] or row["artifact_type"]),
                "kind": str(row["artifact_type"]),
                "path": artifact_source_path(artifact_row),
                "matched_keywords": matched_keywords(f"{row['title']} {row['summary']} {row['snippet']}", keywords),
                "preview": preview,
                "metadata": metadata,
            }
        )
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


def saved_search_to_dict(row: sqlite3.Row) -> dict[str, object]:
    try:
        keywords = json.loads(str(row["keywords_json"] or "[]"))
    except json.JSONDecodeError:
        keywords = []
    try:
        filters = json.loads(str(row["filters_json"] or "{}"))
    except json.JSONDecodeError:
        filters = {}
    return {
        "citation_id": str(row["citation_id"]),
        "case_id": str(row["case_id"]),
        "name": str(row["name"]),
        "keywords": keywords if isinstance(keywords, list) else [],
        "filters": filters if isinstance(filters, dict) else {},
        "created_by": str(row["created_by"] or ""),
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
        "last_run_at": str(row["last_run_at"] or ""),
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

CREATE VIRTUAL TABLE IF NOT EXISTS artifact_fts USING fts5(
    title,
    summary,
    metadata,
    content='artifact',
    content_rowid='id'
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

CREATE TABLE IF NOT EXISTS saved_search (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    citation_id TEXT NOT NULL UNIQUE,
    case_id TEXT NOT NULL,
    name TEXT NOT NULL,
    keywords_json TEXT NOT NULL DEFAULT '[]',
    filters_json TEXT NOT NULL DEFAULT '{}',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_run_at TEXT NOT NULL DEFAULT '',
    UNIQUE(case_id, name),
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
CREATE INDEX IF NOT EXISTS idx_saved_search_case_name ON saved_search(case_id, name);
CREATE INDEX IF NOT EXISTS idx_audit_event_case_time ON audit_event(case_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_report_item_case_section ON report_item(case_id, section, order_index);
CREATE INDEX IF NOT EXISTS idx_job_case_status ON job(case_id, status);
"""
