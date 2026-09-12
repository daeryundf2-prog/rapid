"""SQLite-backed case database."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path

from ..artifact_store import read_jsonl_artifacts, validate_artifact_record
from ..review_reporting_controls import build_review_reporting_contract
from ..search import load_run_summary
from ..submission_qc_controls import build_submission_qc_contract
from .base import (
    CaseDatabaseError,
    CaseRecord,
    default_citation_prefix,
    normalize_identifier,
    now_iso,
)
from .constants import (
    ACQUISITION_HASH_GAP_ID,
    CASE_SEARCH_CURSOR_VERSION,
    CHAIN_OF_CUSTODY_GAP_ID,
    CITATION_KIND_PREFIXES,
    CITATION_WIDTH,
    CLOCK_SKEW_ANALYSIS_GAP_ID,
    COURT_EXHIBIT_EXPORT_GAP_ID,
    EVIDENCE_CONTAMINATION_WARNING_GAP_ID,
    IMMUTABLE_AUDIT_GAP_ID,
    LEGAL_LIMITATION_GAP_ID,
    PARSER_CONFIDENCE_GAP_ID,
    REPORT_REPRODUCIBILITY_GAP_ID,
    REVIEW_TARGET_TABLES,
    SOURCE_PROVENANCE_GAP_ID,
    TIMEZONE_NORMALIZATION_GAP_ID,
    VALIDATION_WARNING_UX_GAP_ID,
    WRITE_BLOCKER_ACQUISITION_METADATA_GAP_ID,
)
from .fts import (
    case_db_fts_optimization_assessment,
    case_db_search_index_health,
    rebuild_case_db_search_indexes,
)
from .helpers import (
    artifact_details,
    artifact_summary,
    artifact_title,
    count_rows,
    hash_existing_file,
    indicator_artifact_row,
    ioc_scanner_artifact_row,
    metadata_matches,
    normalize_path_for_db,
    optional_float,
    optional_int,
    optional_str,
    parse_metadata_filters,
    path_size,
    read_json_path,
    read_output,
    safe_extract_text,
    vsc_artifact_row,
    worker_artifact_row,
    worker_record_index_text,
)
from .integrity import (
    build_acquisition_hash_workflow,
    build_acquisition_metadata_record,
    build_audit_integrity_chain,
    build_clock_skew_analysis,
    build_custody_workflow,
    build_evidence_contamination_warnings,
    build_report_reproducibility_manifest,
    build_timezone_validation,
)
from .reporting import (
    attach_report_citation_profile,
    attach_report_warning_display_profile,
    build_case_db_report_generation_package,
    build_court_exhibit_package_manifest,
    build_evidence_selection_version_history,
    build_functional_reporting_profiles,
    build_report_citation_index,
    build_report_citation_manager,
    build_report_citation_workflow_summary,
    build_report_quality_matrix,
    build_report_warning_display_summary,
    build_review_export_item,
)
from .review import (
    acquisition_metadata_to_dict,
    build_case_search_review_workflow_summary,
    normalize_review_priority,
    normalize_source_citation_package,
    normalize_tags,
    review_mark_to_dict,
    saved_search_to_dict,
    source_citation_package_hash,
)
from .schema import (
    apply_schema,
    assert_supported_existing_schema_version,
    ensure_case_exists,
    get_schema_version,
    list_tables,
)
from .search import (
    attach_review_marks,
    build_case_search_execution_plan,
    build_case_search_result_window_manifest,
    case_document_extraction_errors,
    case_search_cursor_scope,
    case_search_reportability_decision,
    case_search_scan_candidate_limit,
    case_search_source_requested,
    decode_case_search_cursor,
    encode_case_search_cursor,
    enrich_case_search_matches,
    search_artifacts,
    search_events,
    search_file_records,
    search_indexed_documents,
)
from .trusted_diffs import (
    build_forensic_integrity_matrix,
)

__all__ = [
    "CaseDatabase",
    "case_record_from_row",
    "insert_review_history",
    "next_citation_id_for_connection",
    "open_case_database",
    "review_changed_fields",
]

class CaseDatabase:
    def __init__(self, path: Path):
        self.path = path.expanduser().resolve()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA temp_store = MEMORY")
        connection.execute("PRAGMA cache_size = -65536")
        try:
            connection.execute("PRAGMA journal_mode = WAL")
        except sqlite3.DatabaseError:
            pass
        try:
            yield connection
            try:
                connection.execute("PRAGMA optimize")
            except sqlite3.DatabaseError:
                pass
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> dict[str, object]:
        assert_supported_existing_schema_version(self.path)
        with self.connect() as connection:
            apply_schema(connection)
            return {
                "path": str(self.path),
                "schema_version": get_schema_version(connection),
                "tables": list_tables(connection),
                "large_sqlite_fts_optimization": case_db_fts_optimization_assessment(connection),
            }

    def search_index_health(self, case_id: str) -> dict[str, object]:
        normalized_case_id = normalize_identifier(case_id, fallback="case")
        with self.connect() as connection:
            apply_schema(connection)
            ensure_case_exists(connection, normalized_case_id)
            return case_db_search_index_health(connection, normalized_case_id)

    def rebuild_search_indexes(self, case_id: str) -> dict[str, object]:
        normalized_case_id = normalize_identifier(case_id, fallback="case")
        with self.connect() as connection:
            apply_schema(connection)
            ensure_case_exists(connection, normalized_case_id)
            payload = rebuild_case_db_search_indexes(connection, normalized_case_id)
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
                    "local-user",
                    "search-index.rebuilt",
                    "case",
                    normalized_case_id,
                    now_iso(),
                    "rapidtriage",
                    "",
                    json.dumps(
                        {
                            "before_status": payload["before"]["status"],
                            "after_status": payload["after"]["status"],
                            "actions": payload["actions"],
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                    "ok" if payload["after"]["status"] == "healthy" else "partial",
                    "",
                ),
            )
            return payload

    def schema_version(self) -> int:
        with self.connect() as connection:
            return get_schema_version(connection)

    def create_case(
        self,
        *,
        case_id: str,
        name: str | None = None,
        description: str = "",
        examiner: str = "",
        organization: str = "",
        case_root: Path | None = None,
        citation_prefix: str | None = None,
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
        case_name: str | None = None,
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
        case_name: str | None = None,
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

    def import_worker_jsonl(
        self,
        worker_jsonl: Path,
        *,
        case_id: str,
        case_name: str | None = None,
    ) -> dict[str, object]:
        jsonl_path = worker_jsonl.expanduser().resolve()
        normalized_case_id = normalize_identifier(case_id, fallback="case")
        with self.connect() as connection:
            apply_schema(connection)
            case_row = connection.execute(
                "SELECT case_id FROM case_record WHERE case_id = ?",
                (normalized_case_id,),
            ).fetchone()
        if case_row is None:
            self.create_case(case_id=normalized_case_id, name=case_name, case_root=jsonl_path.parent)

        source_payload = {
            "source": {
                "source_path": str(jsonl_path),
                "analysis_root": str(jsonl_path.parent),
                "type": "worker-jsonl",
            },
            "mode": "worker-jsonl",
            "root": str(jsonl_path.parent),
        }
        evidence_source_id = self._insert_evidence_source(normalized_case_id, source_payload)
        counts = self._import_worker_jsonl_records(normalized_case_id, evidence_source_id, jsonl_path)
        audit_id = self.add_audit_event(
            case_id=normalized_case_id,
            action="worker-jsonl.imported",
            target_type="worker-jsonl",
            target_id=str(jsonl_path),
            params_json=json.dumps({"counts": counts}, ensure_ascii=False, sort_keys=True),
        )
        return {
            "case_id": normalized_case_id,
            "audit_citation_id": audit_id,
            "summary": {
                "evidence_source_count": 1,
                **counts,
            },
        }

    def search_case(
        self,
        *,
        case_id: str,
        keywords: Iterable[str],
        limit: int = 100,
        cursor: str = "",
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
        cursor_scope = case_search_cursor_scope(
            case_id=normalized_case_id,
            keywords=normalized_keywords,
            sources=source_filter,
            metadata_filter=metadata_filter,
            review_status=review_status,
            verification_status=verification_status,
        )
        page_offset = decode_case_search_cursor(cursor, expected_scope=cursor_scope) if cursor else 0
        page_size = max(0, int(limit))
        retrieval_limit = page_offset + page_size + 1 if page_size else 0
        query_limit = retrieval_limit or limit
        scan_candidate_limit = case_search_scan_candidate_limit(query_limit)
        with self.connect() as connection:
            apply_schema(connection)
            if connection.execute("SELECT 1 FROM case_record WHERE case_id = ?", (normalized_case_id,)).fetchone() is None:
                raise CaseDatabaseError(f"case not found: {normalized_case_id}")
            large_case_search_plan = build_case_search_execution_plan(
                connection,
                normalized_case_id,
                source_filter=source_filter,
                limit=limit,
                cursor_offset=page_offset,
                retrieval_limit=retrieval_limit,
                scan_candidate_limit=scan_candidate_limit,
            )
            matches: list[dict[str, object]] = []
            document_errors: list[dict[str, object]] = []
            if case_search_source_requested(source_filter, "documents"):
                matches.extend(search_indexed_documents(connection, normalized_case_id, normalized_keywords, query_limit))
                document_errors = case_document_extraction_errors(connection, normalized_case_id)
            if case_search_source_requested(source_filter, "files"):
                matches.extend(search_file_records(connection, normalized_case_id, normalized_keywords, query_limit, scan_candidate_limit))
            if case_search_source_requested(source_filter, "artifacts", "indicators"):
                matches.extend(search_artifacts(connection, normalized_case_id, normalized_keywords, query_limit, scan_candidate_limit))
            if case_search_source_requested(source_filter, "timeline"):
                matches.extend(search_events(connection, normalized_case_id, normalized_keywords, query_limit, scan_candidate_limit))
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
            total_returnable_count = len(matches)
            has_more = False
            next_cursor = ""
            if page_size:
                has_more = total_returnable_count > page_offset + page_size
                matches = matches[page_offset : page_offset + page_size]
                if has_more:
                    next_cursor = encode_case_search_cursor(offset=page_offset + page_size, scope=cursor_scope)

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
        review_workflow_summary = build_case_search_review_workflow_summary(
            matches,
            review_status_filter=review_status,
            verification_status_filter=verification_status,
        )
        result_window_manifest = build_case_search_result_window_manifest(
            case_id=normalized_case_id,
            keywords=normalized_keywords,
            source_filter=source_filter,
            metadata_filter=metadata_filter,
            review_status=review_status,
            verification_status=verification_status,
            cursor_scope=cursor_scope,
            page_offset=page_offset,
            page_size=page_size,
            retrieval_limit=retrieval_limit,
            scan_candidate_limit=scan_candidate_limit,
            total_returnable_count=total_returnable_count,
            returned_matches=matches,
            source_counts=source_counts,
            keyword_counts=keyword_counts,
            priority_counts=priority_counts,
            has_more=has_more,
            next_cursor=next_cursor,
            large_case_search_plan=large_case_search_plan,
            review_workflow_summary=review_workflow_summary,
        )
        reportability_decision = case_search_reportability_decision(
            result_window_manifest=result_window_manifest,
            large_case_search_plan=large_case_search_plan,
            returned_matches=matches,
        )
        return {
            "command": "case-search",
            "generated_at": now_iso(),
            "database": str(self.path),
            "case_id": normalized_case_id,
            "keywords": normalized_keywords,
            "options": {
                "limit": limit,
                "cursor": cursor,
                "page_offset": page_offset,
                "page_size": page_size,
                "retrieval_limit": retrieval_limit,
                "cursor_scope_hash": cursor_scope,
                "sources": sorted(source_filter),
                "metadata": dict(metadata_filter),
                "review_status": review_status,
                "verification_status": verification_status,
                "scan_candidate_limit": scan_candidate_limit,
            },
            "summary": {
                "match_count": len(matches),
                "returned_count": len(matches),
                "total_returnable_count": total_returnable_count,
                "has_more": has_more,
                "next_cursor": next_cursor,
                "source_counts": source_counts,
                "keyword_counts": keyword_counts,
                "priority_counts": priority_counts,
                "document_error_count": len(document_errors),
                "search_index_health_status": str(
                    (large_case_search_plan.get("search_index_health") or {}).get("status") or "unknown"
                )
                if isinstance(large_case_search_plan.get("search_index_health"), Mapping)
                else "unknown",
                "search_index_missing_rows": int(
                    ((large_case_search_plan.get("search_index_health") or {}).get("summary") or {}).get(
                        "missing_index_rows",
                        0,
                    )
                )
                if isinstance((large_case_search_plan.get("search_index_health") or {}).get("summary"), Mapping)
                else 0,
                "cursor_api": {
                    "profile_version": CASE_SEARCH_CURSOR_VERSION,
                    "offset": page_offset,
                    "page_size": page_size,
                    "has_more": has_more,
                    "next_cursor": next_cursor,
                    "scope_hash": cursor_scope,
                    "stable_scope_fields": [
                        "case_id",
                        "keywords",
                        "sources",
                        "metadata",
                        "review_status",
                        "verification_status",
                    ],
                    "commercial_gap_ids": ["#78", "#79"],
                },
                "case_search_result_window_manifest_hash": result_window_manifest["manifest_hash"],
            },
            "documents": {
                "errors": document_errors,
            },
            "large_case_search_plan": large_case_search_plan,
            "review_workflow_summary": review_workflow_summary,
            "case_search_result_window_manifest": result_window_manifest,
            "reportability_decision": reportability_decision,
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
        status: str | None = None,
        verification_status: str | None = None,
        tags: Iterable[str] | None = None,
        note: str | None = None,
        include_in_report: bool | None = None,
        reviewer: str | None = None,
        assignee: str | None = None,
        priority: str | None = None,
        due_at: str | None = None,
        source_citation_package: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        normalized_case_id = normalize_identifier(case_id, fallback="case")
        timestamp = now_iso()
        with self.connect() as connection:
            apply_schema(connection)
            if connection.execute("SELECT 1 FROM case_record WHERE case_id = ?", (normalized_case_id,)).fetchone() is None:
                raise CaseDatabaseError(f"case not found: {normalized_case_id}")
            target_missing = connection.execute(
                f"SELECT 1 FROM {REVIEW_TARGET_TABLES[target_type]} WHERE id = ? LIMIT 1",
                (target_id,),
            ).fetchone() is None if target_type in REVIEW_TARGET_TABLES else False
            if target_missing:
                raise CaseDatabaseError(
                    f"review target not found: {target_type}:{target_id} in case {normalized_case_id}; "
                    "run 'rapidtriage case-search' to find the exact target id before marking a review"
                )
            existing = connection.execute(
                """
                SELECT * FROM review_mark
                WHERE case_id = ? AND target_type = ? AND target_id = ?
                LIMIT 1
                """,
                (normalized_case_id, target_type, target_id),
            ).fetchone()
            previous_review = review_mark_to_dict(existing) if existing is not None else {}
            effective_status = str(status if status is not None else previous_review.get("status", "unreviewed"))
            effective_verification = str(
                verification_status
                if verification_status is not None
                else previous_review.get("verification_status", "unverified")
            )
            effective_tags = normalize_tags(
                tags if tags is not None else previous_review.get("tags", [])
            )
            effective_note = str(note if note is not None else previous_review.get("note", ""))
            effective_include = bool(
                include_in_report
                if include_in_report is not None
                else previous_review.get("include_in_report", False)
            )
            effective_reviewer = str(reviewer if reviewer is not None else previous_review.get("reviewer", ""))
            effective_assignee = str(assignee if assignee is not None else previous_review.get("assignee", ""))
            effective_priority = normalize_review_priority(
                str(priority if priority is not None else previous_review.get("priority", "normal"))
            )
            effective_due_at = str(due_at if due_at is not None else previous_review.get("due_at", ""))
            effective_source_citation_package = normalize_source_citation_package(
                source_citation_package
                if source_citation_package is not None
                else previous_review.get("source_citation_package", {})
            )
            tags_json = json.dumps(effective_tags, ensure_ascii=False)
            source_citation_package_json = json.dumps(
                effective_source_citation_package,
                ensure_ascii=False,
                sort_keys=True,
            )
            if existing is None:
                citation_id = next_citation_id_for_connection(connection, normalized_case_id, "review")
                connection.execute(
                    """
                    INSERT INTO review_mark (
                        citation_id, case_id, target_type, target_id, status,
                        verification_status, tags_json, note, include_in_report,
                        reviewer, assignee, priority, due_at, source_citation_package_json,
                        created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        citation_id,
                        normalized_case_id,
                        target_type,
                        target_id,
                        effective_status,
                        effective_verification,
                        tags_json,
                        effective_note,
                        1 if effective_include else 0,
                        effective_reviewer,
                        effective_assignee,
                        effective_priority,
                        effective_due_at,
                        source_citation_package_json,
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
                        include_in_report = ?, reviewer = ?, assignee = ?, priority = ?,
                        due_at = ?, source_citation_package_json = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        effective_status,
                        effective_verification,
                        tags_json,
                        effective_note,
                        1 if effective_include else 0,
                        effective_reviewer,
                        effective_assignee,
                        effective_priority,
                        effective_due_at,
                        source_citation_package_json,
                        timestamp,
                        existing["id"],
                    ),
                )
            current_review = {
                "citation_id": citation_id,
                "case_id": normalized_case_id,
                "target_type": target_type,
                "target_id": target_id,
                "status": effective_status,
                "verification_status": effective_verification,
                "tags": effective_tags,
                "note": effective_note,
                "include_in_report": effective_include,
                "reviewer": effective_reviewer,
                "assignee": effective_assignee,
                "priority": effective_priority,
                "due_at": effective_due_at,
                "source_citation_package": effective_source_citation_package,
                "source_citation_package_hash": source_citation_package_hash(effective_source_citation_package),
                "updated_at": timestamp,
            }
            insert_review_history(
                connection,
                case_id=normalized_case_id,
                review_citation_id=citation_id,
                target_type=target_type,
                target_id=target_id,
                previous_review=previous_review,
                current_review=current_review,
                actor=effective_reviewer or "local-user",
                changed_at=timestamp,
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
                    effective_reviewer or "local-user",
                    "review.marked",
                    target_type,
                    target_id,
                    timestamp,
                    "rapidtriage",
                    "",
                    json.dumps(
                        {
                            "status": effective_status,
                            "verification_status": effective_verification,
                            "tags": effective_tags,
                            "include_in_report": effective_include,
                            "assignee": effective_assignee,
                            "priority": effective_priority,
                            "due_at": effective_due_at,
                            "source_citation_package_hash": source_citation_package_hash(effective_source_citation_package),
                            "source_citation_package_attached": bool(effective_source_citation_package),
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
        status: str | None = None,
        verification_status: str | None = None,
        tags: Iterable[str] | None = None,
        note: str | None = None,
        include_in_report: bool | None = None,
        reviewer: str | None = None,
        assignee: str | None = None,
        priority: str | None = None,
        due_at: str | None = None,
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
                    assignee=assignee,
                    priority=priority,
                    due_at=due_at,
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

    def record_acquisition_metadata(
        self,
        *,
        case_id: str,
        evidence_source_citation_id: str = "",
        operator: str = "",
        acquisition_started_at: str = "",
        acquisition_completed_at: str = "",
        source_identifier: str = "",
        write_blocker: str = "",
        acquisition_tool: str = "",
        acquisition_tool_version: str = "",
        whole_source_sha256: str = "",
        notes: str = "",
    ) -> dict[str, object]:
        normalized_case_id = normalize_identifier(case_id, fallback="case")
        timestamp = now_iso()
        with self.connect() as connection:
            apply_schema(connection)
            case = connection.execute(
                "SELECT case_id FROM case_record WHERE case_id = ?",
                (normalized_case_id,),
            ).fetchone()
            if case is None:
                raise CaseDatabaseError(f"case not found: {normalized_case_id}")
            normalized_evidence_citation = evidence_source_citation_id.strip()
            if normalized_evidence_citation:
                evidence = connection.execute(
                    """
                    SELECT citation_id FROM evidence_source
                    WHERE case_id = ? AND citation_id = ?
                    LIMIT 1
                    """,
                    (normalized_case_id, normalized_evidence_citation),
                ).fetchone()
                if evidence is None:
                    raise CaseDatabaseError(f"evidence source not found: {normalized_evidence_citation}")
            citation_id = next_citation_id_for_connection(connection, normalized_case_id, "acquisition")
            connection.execute(
                """
                INSERT INTO acquisition_metadata (
                    citation_id, case_id, evidence_source_citation_id, operator,
                    acquisition_started_at, acquisition_completed_at, source_identifier,
                    write_blocker, acquisition_tool, acquisition_tool_version,
                    whole_source_sha256, notes, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    citation_id,
                    normalized_case_id,
                    normalized_evidence_citation,
                    operator.strip(),
                    acquisition_started_at.strip(),
                    acquisition_completed_at.strip(),
                    source_identifier.strip(),
                    write_blocker.strip(),
                    acquisition_tool.strip(),
                    acquisition_tool_version.strip(),
                    whole_source_sha256.strip().lower(),
                    notes.strip(),
                    timestamp,
                ),
            )
            audit_citation_id = next_citation_id_for_connection(connection, normalized_case_id, "audit")
            connection.execute(
                """
                INSERT INTO audit_event (
                    citation_id, case_id, actor, action, target_type, target_id,
                    timestamp, tool_name, tool_version, params_json, result, error
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    audit_citation_id,
                    normalized_case_id,
                    operator.strip() or "local-user",
                    "acquisition.metadata.recorded",
                    "acquisition_metadata",
                    citation_id,
                    timestamp,
                    "rapidtriage",
                    "",
                    json.dumps(
                        {
                            "evidence_source_citation_id": normalized_evidence_citation,
                            "source_identifier": source_identifier.strip(),
                            "write_blocker_recorded": bool(write_blocker.strip()),
                            "whole_source_sha256_recorded": bool(whole_source_sha256.strip()),
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                    "ok",
                    "",
                ),
            )
            connection.execute(
                "UPDATE case_record SET updated_at = ? WHERE case_id = ?",
                (timestamp, normalized_case_id),
            )
            row = connection.execute(
                "SELECT * FROM acquisition_metadata WHERE citation_id = ?",
                (citation_id,),
            ).fetchone()
        return acquisition_metadata_to_dict(row)

    def list_acquisition_metadata(self, case_id: str) -> list[dict[str, object]]:
        normalized_case_id = normalize_identifier(case_id, fallback="case")
        with self.connect() as connection:
            apply_schema(connection)
            rows = connection.execute(
                """
                SELECT * FROM acquisition_metadata
                WHERE case_id = ?
                ORDER BY created_at DESC, id DESC
                """,
                (normalized_case_id,),
            ).fetchall()
        return [acquisition_metadata_to_dict(row) for row in rows]

    def export_reviewed_items(
        self,
        *,
        case_id: str,
        include_all: bool = False,
        max_items: int = 500,
    ) -> dict[str, object]:
        normalized_case_id = normalize_identifier(case_id, fallback="case")
        bounded_limit = max(1, min(int(max_items or 500), 5000))
        with self.connect() as connection:
            apply_schema(connection)
            case = connection.execute(
                "SELECT * FROM case_record WHERE case_id = ?",
                (normalized_case_id,),
            ).fetchone()
            if case is None:
                raise CaseDatabaseError(f"case not found: {normalized_case_id}")
            review_rows = connection.execute(
                """
                SELECT *
                FROM review_mark
                WHERE case_id = ?
                  AND (? OR include_in_report = 1)
                ORDER BY include_in_report DESC, updated_at DESC, id DESC
                LIMIT ?
                """,
                (normalized_case_id, 1 if include_all else 0, bounded_limit),
            ).fetchall()
            items = [
                build_review_export_item(connection, normalized_case_id, review_mark_to_dict(row))
                for row in review_rows
            ]
            items = [attach_report_citation_profile(item) for item in items]
            items = [attach_report_warning_display_profile(item) for item in items]
            custody_workflow = build_custody_workflow(connection, normalized_case_id)
            acquisition_hash_workflow = build_acquisition_hash_workflow(connection, normalized_case_id)
            audit_integrity = build_audit_integrity_chain(connection, normalized_case_id)
            acquisition_metadata = build_acquisition_metadata_record(connection, normalized_case_id)
            timezone_validation = build_timezone_validation(connection, normalized_case_id)
            clock_skew_analysis = build_clock_skew_analysis(connection, normalized_case_id)
            contamination_warnings = build_evidence_contamination_warnings(connection, normalized_case_id)
        status_counts: dict[str, int] = {}
        verification_counts: dict[str, int] = {}
        for item in items:
            review = item.get("review") if isinstance(item.get("review"), Mapping) else {}
            status = str(review.get("status") or "unreviewed")
            verification = str(review.get("verification_status") or "unverified")
            status_counts[status] = status_counts.get(status, 0) + 1
            verification_counts[verification] = verification_counts.get(verification, 0) + 1
        validation_warning_count = sum(
            len(assessment.get("warnings") or [])
            for item in items
            for assessment in [item.get("validation_assessment") if isinstance(item.get("validation_assessment"), Mapping) else {}]
        )
        warning_ux_summary = build_report_warning_display_summary(items)
        legal_limitation_count = sum(
            len(item.get("legal_limitations") or [])
            for item in items
            if isinstance(item.get("legal_limitations"), list)
        )
        citation_index = build_report_citation_index(items)
        report_citation_summary = build_report_citation_workflow_summary(items)
        report_generation_package = build_case_db_report_generation_package(
            case_id=normalized_case_id,
            items=items,
            citation_index=citation_index,
            status_counts=status_counts,
            verification_counts=verification_counts,
        )
        reproducibility = build_report_reproducibility_manifest(items, citation_index)
        forensic_integrity_matrix = build_forensic_integrity_matrix(
            custody_workflow=custody_workflow,
            acquisition_hash_workflow=acquisition_hash_workflow,
            audit_integrity=audit_integrity,
            reproducibility=reproducibility,
            items=items,
        )
        court_exhibit_package = build_court_exhibit_package_manifest(
            case_id=normalized_case_id,
            items=items,
            citation_index=citation_index,
            report_generation_package=report_generation_package,
            custody_workflow=custody_workflow,
            acquisition_hash_workflow=acquisition_hash_workflow,
            audit_integrity=audit_integrity,
            reproducibility=reproducibility,
        )
        report_quality_matrix = build_report_quality_matrix(
            items=items,
            court_exhibit_package=court_exhibit_package,
        )
        functional_profiles = build_functional_reporting_profiles(
            items=items,
            citation_index=citation_index,
            validation_warning_count=validation_warning_count,
            legal_limitation_count=legal_limitation_count,
            report_generation_package=report_generation_package,
            court_exhibit_package=court_exhibit_package,
        )
        summary = {
            "exported_item_count": len(items),
            "review_status_counts": status_counts,
            "verification_status_counts": verification_counts,
            "review_workflow_gap_ids": ["#51"],
            "review_assignment_enabled": True,
            "functional_priority_gap_ids": ["#21", "#22", "#23", "#24"],
            "functional_priority_status": functional_profiles["status"],
            "report_citation_gap_ids": ["#64"],
            "evidence_selection_gap_ids": ["#65"],
            "forensic_integrity_gap_ids": [
                CHAIN_OF_CUSTODY_GAP_ID,
                ACQUISITION_HASH_GAP_ID,
                IMMUTABLE_AUDIT_GAP_ID,
                REPORT_REPRODUCIBILITY_GAP_ID,
                SOURCE_PROVENANCE_GAP_ID,
                WRITE_BLOCKER_ACQUISITION_METADATA_GAP_ID,
                TIMEZONE_NORMALIZATION_GAP_ID,
                CLOCK_SKEW_ANALYSIS_GAP_ID,
                EVIDENCE_CONTAMINATION_WARNING_GAP_ID,
            ],
            "parser_confidence_gap_ids": [PARSER_CONFIDENCE_GAP_ID],
            "validation_warning_ux_gap_ids": [VALIDATION_WARNING_UX_GAP_ID],
            "legal_limitation_gap_ids": [LEGAL_LIMITATION_GAP_ID],
            "report_quality_gap_ids": [
                PARSER_CONFIDENCE_GAP_ID,
                VALIDATION_WARNING_UX_GAP_ID,
                LEGAL_LIMITATION_GAP_ID,
                COURT_EXHIBIT_EXPORT_GAP_ID,
            ],
            "acquisition_metadata_gap_ids": [WRITE_BLOCKER_ACQUISITION_METADATA_GAP_ID],
            "timezone_validation_gap_ids": [TIMEZONE_NORMALIZATION_GAP_ID],
            "clock_skew_gap_ids": [CLOCK_SKEW_ANALYSIS_GAP_ID],
            "contamination_warning_gap_ids": [EVIDENCE_CONTAMINATION_WARNING_GAP_ID],
            "citation_count": len(citation_index),
            "report_citation_profile_summary": report_citation_summary,
            "report_citation_ready_count": report_citation_summary["ready_for_report_export_count"],
            "report_citation_blocker_count": report_citation_summary["blocker_count"],
            "report_generation_manifest_hash": report_generation_package["manifest"]["manifest_hash"],
            "report_generation_hash_bundle_sha256": report_generation_package["hash_bundle_sha256"],
            "court_exhibit_manifest_hash": court_exhibit_package["manifest"]["manifest_hash"],
            "court_exhibit_package_hash": court_exhibit_package["package_hash"],
            "court_exhibit_count": court_exhibit_package["manifest"]["exhibit_count"],
            "report_quality_matrix_hash": report_quality_matrix["matrix_hash"],
            "forensic_integrity_matrix_hash": forensic_integrity_matrix["matrix_hash"],
            "custody_event_count": custody_workflow["summary"]["custody_event_count"],
            "acquisition_hash_count": acquisition_hash_workflow["summary"]["hash_count"],
            "audit_chain_event_count": audit_integrity["summary"]["event_count"],
            "validation_warning_count": validation_warning_count,
            "warning_ux_summary": warning_ux_summary,
            "warning_ux_profile_count": warning_ux_summary["profile_count"],
            "legal_limitation_count": legal_limitation_count,
            "acquisition_metadata_missing_count": acquisition_metadata["summary"]["missing_required_field_count"],
            "timezone_missing_count": timezone_validation["summary"]["missing_timezone_count"],
            "clock_skew_warning_count": clock_skew_analysis["summary"]["warning_count"],
            "contamination_warning_count": contamination_warnings["summary"]["warning_count"],
        }
        history_rows = [
            history
            for item in items
            if isinstance(item.get("review_history"), list)
            for history in item.get("review_history", [])
            if isinstance(history, Mapping)
        ]
        review_reporting_qc_contract = build_review_reporting_contract(
            review_marks=[
                item.get("review") if isinstance(item.get("review"), Mapping) else {}
                for item in items
            ],
            citation_index=citation_index,
            history_rows=history_rows,
        )
        submission_qc_contract = build_submission_qc_contract(
            court_exhibit_package=court_exhibit_package,
            custody_workflow=custody_workflow,
            acquisition_metadata=acquisition_metadata,
            audit_integrity=audit_integrity,
            report_generation_package=report_generation_package,
            items=items,
        )
        summary["review_reporting_qc_gap_ids"] = ["#61", "#62", "#63", "#64", "#65"]
        summary["review_reporting_qc_contract_hash"] = review_reporting_qc_contract["contract_hash"]
        summary["submission_qc_gap_ids"] = ["#66", "#67", "#68", "#69", "#70"]
        summary["submission_qc_contract_hash"] = submission_qc_contract["contract_hash"]
        return {
            "command": "case-db-report-export",
            "generated_at": now_iso(),
            "database": str(self.path),
            "case": case_record_from_row(case).to_dict(),
            "options": {
                "include_all": include_all,
                "max_items": bounded_limit,
            },
            "summary": summary,
            "citation_index": citation_index,
            "functional_reporting_profiles": functional_profiles,
            "report_generation_package": report_generation_package,
            "court_exhibit_package": court_exhibit_package,
            "report_quality_matrix": report_quality_matrix,
            "report_citation_manager": build_report_citation_manager(citation_index),
            "evidence_selection_version_history": build_evidence_selection_version_history(items),
            "review_reporting_qc_contract": review_reporting_qc_contract,
            "submission_qc_contract": submission_qc_contract,
            "custody_workflow": custody_workflow,
            "acquisition_hash_workflow": acquisition_hash_workflow,
            "audit_integrity": audit_integrity,
            "reproducibility": reproducibility,
            "forensic_integrity_matrix": forensic_integrity_matrix,
            "acquisition_metadata": acquisition_metadata,
            "timezone_validation": timezone_validation,
            "clock_skew_analysis": clock_skew_analysis,
            "contamination_warnings": contamination_warnings,
            "items": items,
        }

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
                body, extraction_error = safe_extract_text(path, kind)
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
                if extraction_error:
                    connection.execute(
                        """
                        INSERT INTO audit_event (
                            citation_id, case_id, actor, action, target_type, target_id,
                            timestamp, tool_name, tool_version, params_json, result, error
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            next_citation_id_for_connection(connection, case_id, "audit"),
                            case_id,
                            "case-db-import",
                            "document-text-extraction",
                            "indexed_document",
                            str(cursor.lastrowid),
                            now_iso(),
                            "rapidtriage",
                            "",
                            json.dumps({"path": str(path), "kind": kind}, ensure_ascii=False, sort_keys=True),
                            "failed",
                            extraction_error,
                        ),
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
                            str(details.get("parser") or row.get("provider") or name),
                            str(details.get("parser_version") or ""),
                            title,
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

    def _import_indicators(self, case_id: str, evidence_source_id: int, outputs: Mapping[str, object]) -> int:
        payload = read_output(outputs, "indicators")
        indicator_rows = payload.get("indicators") if isinstance(payload, Mapping) else None
        scanner_rows = payload.get("ioc_scanner_hits") if isinstance(payload, Mapping) else None
        if not isinstance(indicator_rows, list) and not isinstance(scanner_rows, list):
            return 0
        count = 0
        with self.connect() as connection:
            for index, row in enumerate(indicator_rows if isinstance(indicator_rows, list) else []):
                if not isinstance(row, Mapping):
                    continue
                artifact = indicator_artifact_row(row, index=index)
                details = artifact_details(artifact)
                title = artifact_title(artifact)
                summary = artifact_summary(artifact)
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
                count += 1
            for index, row in enumerate(scanner_rows if isinstance(scanner_rows, list) else []):
                if not isinstance(row, Mapping):
                    continue
                artifact = ioc_scanner_artifact_row(row, index=index)
                details = artifact_details(artifact)
                title = artifact_title(artifact)
                summary = artifact_summary(artifact)
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
                        str(artifact.get("artifact_type") or "indicator-ioc-scanner-hit"),
                        str(details.get("parser") or "rapidtriage-indicators"),
                        str(details.get("parser_version") or "1"),
                        title,
                        summary,
                        json.dumps(artifact, ensure_ascii=False, sort_keys=True),
                        None,
                        now_iso(),
                    ),
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
                    count += 1
        return count

    def _import_worker_jsonl_records(self, case_id: str, evidence_source_id: int, jsonl_path: Path) -> dict[str, int]:
        artifact_count = 0
        indexed_document_count = 0
        rejected_count = 0
        with self.connect() as connection:
            for index, record in enumerate(read_jsonl_artifacts(jsonl_path), start=1):
                validation_errors = validate_artifact_record(record)
                if validation_errors:
                    rejected_count += 1
                    continue
                artifact = worker_artifact_row(record, source_jsonl=str(jsonl_path), index=index)
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
                        str(artifact.get("artifact_type") or "worker-artifact"),
                        str(record.get("parser") or "rapid-worker"),
                        str(record.get("parser_version") or ""),
                        title,
                        summary,
                        json.dumps(artifact, ensure_ascii=False, sort_keys=True),
                        optional_float(record.get("confidence")),
                        now_iso(),
                    ),
                )
                artifact_id = int(cursor.lastrowid)
                index_body = worker_record_index_text(artifact)
                doc_cursor = connection.execute(
                    """
                    INSERT INTO indexed_document (
                        citation_id, case_id, evidence_source_id, artifact_id, source_type,
                        field_name, title, body, language, indexed_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        next_citation_id_for_connection(connection, case_id, "indexed_document"),
                        case_id,
                        evidence_source_id,
                        artifact_id,
                        "worker-artifact",
                        str(record.get("artifact_type") or ""),
                        title,
                        index_body,
                        "",
                        now_iso(),
                    ),
                )
                connection.execute(
                    "INSERT INTO indexed_document_fts(rowid, title, body) VALUES (?, ?, ?)",
                    (int(doc_cursor.lastrowid), title, index_body),
                )
                artifact_count += 1
                indexed_document_count += 1
        return {
            "artifact_count": artifact_count,
            "indexed_document_count": indexed_document_count,
            "rejected_count": rejected_count,
        }


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


def insert_review_history(
    connection: sqlite3.Connection,
    *,
    case_id: str,
    review_citation_id: str,
    target_type: str,
    target_id: str,
    previous_review: Mapping[str, object],
    current_review: Mapping[str, object],
    actor: str,
    changed_at: str,
) -> None:
    row = connection.execute(
        """
        SELECT COALESCE(MAX(version), 0) AS version
        FROM review_mark_history
        WHERE case_id = ? AND target_type = ? AND target_id = ?
        """,
        (case_id, target_type, target_id),
    ).fetchone()
    version = int(row["version"] or 0) + 1 if row is not None else 1
    changed_fields = review_changed_fields(previous_review, current_review)
    connection.execute(
        """
        INSERT INTO review_mark_history (
            case_id, review_citation_id, target_type, target_id, version,
            changed_at, actor, changed_fields_json, previous_json, current_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            case_id,
            review_citation_id,
            target_type,
            target_id,
            version,
            changed_at,
            actor,
            json.dumps(changed_fields, ensure_ascii=False, sort_keys=True),
            json.dumps(previous_review, ensure_ascii=False, sort_keys=True),
            json.dumps(current_review, ensure_ascii=False, sort_keys=True),
        ),
    )


def review_changed_fields(previous_review: Mapping[str, object], current_review: Mapping[str, object]) -> list[str]:
    tracked = (
        "status",
        "verification_status",
        "tags",
        "note",
        "include_in_report",
        "reviewer",
        "assignee",
        "priority",
        "due_at",
        "source_citation_package",
    )
    return [
        field
        for field in tracked
        if previous_review.get(field) != current_review.get(field)
    ]


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
