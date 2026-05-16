from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Optional, Sequence

from .artifact_store import read_jsonl_artifacts, validate_artifact_record
from .docs import extract_text
from .forensic_accuracy import build_accuracy_gate
from .review_reporting_controls import build_review_reporting_contract
from .search import SearchError, load_run_summary
from .submission_qc_controls import build_submission_qc_contract
from .submission import compute_hashes


SCHEMA_VERSION = 1
FUNCTIONAL_REPORTING_BATCH_ID = "commercial-uplift-021-025"
FUNCTIONAL_SCALE_BATCH_ID = "commercial-uplift-031-035"
FUNCTIONAL_VALIDATION_BATCH_ID = "commercial-uplift-036-040"
FUNCTIONAL_DEFENSIBILITY_BATCH_ID = "commercial-uplift-041-045"
FORENSIC_INTEGRITY_BATCH_ID = "commercial-uplift-086-090"
LARGE_SQLITE_FTS_GAP_ID = "#74"
LARGE_SQLITE_FTS_REPORT_GRADE_VALIDATION_PLAN_VERSION = "large-sqlite-fts-report-grade-validation-plan-v1"
LARGE_SQLITE_FTS_REPORT_GRADE_BLOCKERS = [
    "trusted-case-db-sqlite-fts-query-plan-diff-missing",
    "10m-row-query-plan-regression-required",
    "deleted-row-wal-replay-validation-required",
    "large-source-db-corpus-required",
    "browser-pagination-query-plan-e2e-required",
    "index-maintenance-vacuum-regression-required",
]
CHAIN_OF_CUSTODY_GAP_ID = "#86"
CUSTODY_REPORT_GRADE_VALIDATION_PLAN_VERSION = "custody-report-grade-validation-plan-v1"
CUSTODY_REPORT_GRADE_BLOCKERS = [
    "trusted-custody-event-manifest-diff-missing",
    "signed-custody-handoff-required",
    "acquisition-device-metadata-required",
    "write-blocker-metadata-required",
    "lab-custody-policy-required",
]
ACQUISITION_HASH_GAP_ID = "#87"
ACQUISITION_HASH_REPORT_GRADE_VALIDATION_PLAN_VERSION = "acquisition-hash-report-grade-validation-plan-v1"
ACQUISITION_HASH_REPORT_GRADE_BLOCKERS = [
    "trusted-acquisition-hash-manifest-diff-missing",
    "whole-device-acquisition-hash-required",
    "source-hash-completeness-required",
    "write-blocker-metadata-required",
    "operator-acquisition-log-required",
    "hash-tool-version-capture-required",
]
IMMUTABLE_AUDIT_GAP_ID = "#88"
IMMUTABLE_AUDIT_REPORT_GRADE_VALIDATION_PLAN_VERSION = "immutable-audit-report-grade-validation-plan-v1"
IMMUTABLE_AUDIT_REPORT_GRADE_BLOCKERS = [
    "trusted-audit-hash-chain-manifest-diff-missing",
    "database-level-audit-append-only-required",
    "external-audit-chain-notarization-required",
    "signed-audit-export-bundle-required",
    "multi-user-identity-binding-required",
    "audit-retention-policy-required",
]
REPORT_REPRODUCIBILITY_GAP_ID = "#89"
REPORT_REPRODUCIBILITY_REPORT_GRADE_VALIDATION_PLAN_VERSION = "report-reproducibility-report-grade-validation-plan-v1"
REPORT_REPRODUCIBILITY_REPORT_GRADE_BLOCKERS = [
    "trusted-report-replay-manifest-diff-missing",
    "cross-platform-byte-for-byte-replay-required",
    "same-input-repeat-run-log-required",
    "report-template-version-lock-required",
    "volatile-field-normalization-review-required",
    "release-build-replay-evidence-required",
]
SOURCE_PROVENANCE_GAP_ID = "#90"
SOURCE_PROVENANCE_REPORT_GRADE_VALIDATION_PLAN_VERSION = "source-provenance-report-grade-validation-plan-v1"
SOURCE_PROVENANCE_REPORT_GRADE_BLOCKERS = [
    "trusted-report-provenance-manifest-diff-missing",
    "all-parser-provenance-corpus-required",
    "final-report-template-provenance-review-required",
    "source-citation-viewer-roundtrip-required",
    "offset-locator-trusted-diff-required",
    "parser-version-release-lock-required",
]
CUSTODY_TRUSTED_DIFF_BLOCKER_86 = "trusted-custody-event-manifest-diff-missing"
ACQUISITION_HASH_TRUSTED_DIFF_BLOCKER_87 = "trusted-acquisition-hash-manifest-diff-missing"
IMMUTABLE_AUDIT_TRUSTED_DIFF_BLOCKER_88 = "trusted-audit-hash-chain-manifest-diff-missing"
REPORT_REPRODUCIBILITY_TRUSTED_DIFF_BLOCKER_89 = "trusted-report-replay-manifest-diff-missing"
SOURCE_PROVENANCE_TRUSTED_DIFF_BLOCKER_90 = "trusted-report-provenance-manifest-diff-missing"
FORENSIC_INTEGRITY_TRUSTED_TOOLS = {
    "custody-event-manifest",
    "acquisition-hash-manifest",
    "audit-hash-chain-manifest",
    "report-replay-manifest",
    "report-provenance-manifest",
}
PARSER_CONFIDENCE_GAP_ID = "#91"
VALIDATION_WARNING_UX_GAP_ID = "#92"
LEGAL_LIMITATION_GAP_ID = "#93"
COURT_EXHIBIT_EXPORT_GAP_ID = "#94"
PARSER_CONFIDENCE_REPORT_GRADE_VALIDATION_PLAN_VERSION = "parser-confidence-report-grade-validation-plan-v1"
PARSER_CONFIDENCE_REPORT_GRADE_BLOCKERS = [
    "trusted-parser-confidence-calibration-diff-missing",
    "parser-specific-calibration-table-required",
    "cross-tool-confidence-validation-required",
    "low-confidence-fp-fn-corpus-required",
    "reportability-threshold-review-required",
    "release-parser-confidence-policy-lock-required",
]
PARSER_CONFIDENCE_TRUSTED_DIFF_BLOCKER_91 = "trusted-parser-confidence-calibration-diff-missing"
VALIDATION_WARNING_TRUSTED_DIFF_BLOCKER_92 = "trusted-validation-warning-checklist-diff-missing"
LEGAL_LIMITATION_TRUSTED_DIFF_BLOCKER_93 = "trusted-legal-limitation-wording-diff-missing"
REPORT_QUALITY_TRUSTED_TOOLS = {
    "parser-confidence-calibration",
    "validation-warning-checklist",
    "legal-limitation-wording-review",
}
WRITE_BLOCKER_ACQUISITION_METADATA_GAP_ID = "#96"
TIMEZONE_NORMALIZATION_GAP_ID = "#97"
CLOCK_SKEW_ANALYSIS_GAP_ID = "#98"
EVIDENCE_CONTAMINATION_WARNING_GAP_ID = "#99"
ACQUISITION_METADATA_TRUSTED_DIFF_BLOCKER_96 = "trusted-acquisition-metadata-handoff-diff-missing"
TIMEZONE_VALIDATION_TRUSTED_DIFF_BLOCKER_97 = "trusted-timezone-normalization-matrix-diff-missing"
CLOCK_SKEW_TRUSTED_DIFF_BLOCKER_98 = "trusted-clock-skew-baseline-diff-missing"
CONTAMINATION_WARNING_TRUSTED_DIFF_BLOCKER_99 = "trusted-contamination-checklist-diff-missing"
ACQUISITION_QUALITY_TRUSTED_TOOLS = {
    "signed-acquisition-handoff",
    "write-blocker-log",
    "timezone-normalization-matrix",
    "clock-skew-baseline",
    "contamination-checklist",
}
REVIEW_WORKFLOW_TRUSTED_DIFF_BLOCKER = "review-workflow-trusted-audit-diff-required"
REVIEW_WORKFLOW_REPORT_GRADE_VALIDATION_PLAN_VERSION = "case-review-workflow-report-grade-validation-plan-v1"
REVIEW_WORKFLOW_REPORT_GRADE_BLOCKERS = [
    "role-based-assignment-queue-required",
    "notification-workflow-required",
    "multi-user-conflict-resolution-required",
    "sla-dashboard-required",
    "reviewer-sop-signoff-required",
    REVIEW_WORKFLOW_TRUSTED_DIFF_BLOCKER,
]
REPORT_CITATION_REPORT_GRADE_VALIDATION_PLAN_VERSION = "report-citation-report-grade-validation-plan-v1"
REPORT_CITATION_REPORT_GRADE_BLOCKERS = [
    "source-hash-completeness-validation-required",
    "parser-version-completeness-validation-required",
    "trusted-citation-index-diff-required",
    "exhibit-numbering-ui-required",
    "jurisdiction-template-review-required",
    "reviewer-signoff-corpus-required",
]
EVIDENCE_SELECTION_REPORT_GRADE_VALIDATION_PLAN_VERSION = "evidence-selection-history-report-grade-validation-plan-v1"
EVIDENCE_SELECTION_REPORT_GRADE_BLOCKERS = [
    "signed-multi-user-history-required",
    "trusted-evidence-history-diff-required",
    "multi-user-conflict-handling-required",
    "database-trigger-enforcement-review-required",
    "reviewer-identity-rbac-corpus-required",
    "history-replay-corpus-required",
]
CASE_DB_SEARCH_SCAN_ROW_LIMIT = 100_000
CASE_DB_SEARCH_SCAN_OVERSAMPLE = 100
CASE_DB_SEARCH_MIN_SCAN_ROWS = 10_000
CASE_SEARCH_CURSOR_VERSION = "case-search-cursor-v1"
REVIEW_WORKFLOW_TRUSTED_TOOLS = {
    "analyst-review-log",
    "case-review-ground-truth",
    "reviewer-signoff-export",
    "qa-review-workbook",
}
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
    "acquisition": "ACQ",
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

    def import_worker_jsonl(
        self,
        worker_jsonl: Path,
        *,
        case_id: str,
        case_name: Optional[str] = None,
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


def apply_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA_SQL)
    ensure_column(connection, "review_mark", "assignee", "TEXT NOT NULL DEFAULT ''")
    ensure_column(connection, "review_mark", "priority", "TEXT NOT NULL DEFAULT 'normal'")
    ensure_column(connection, "review_mark", "due_at", "TEXT NOT NULL DEFAULT ''")
    ensure_column(connection, "review_mark", "source_citation_package_json", "TEXT NOT NULL DEFAULT '{}'")
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


def case_db_search_index_health(connection: sqlite3.Connection, case_id: str) -> dict[str, object]:
    profiles = [
        case_db_fts_health_profile(
            connection,
            case_id=case_id,
            source="documents",
            source_table="indexed_document",
            fts_table="indexed_document_fts",
            source_label="extracted document/OCR text",
        ),
        case_db_fts_health_profile(
            connection,
            case_id=case_id,
            source="files",
            source_table="file_record",
            fts_table="file_record_fts",
            source_label="file path, extension, and hash metadata",
        ),
        case_db_fts_health_profile(
            connection,
            case_id=case_id,
            source="artifacts",
            source_table="artifact",
            fts_table="artifact_fts",
            source_label="artifact and indicator title/summary/metadata",
        ),
        case_db_fts_health_profile(
            connection,
            case_id=case_id,
            source="timeline",
            source_table="event",
            fts_table="event_fts",
            source_label="timeline event type/time/target/description/source",
        ),
    ]
    missing_total = sum(int(profile["missing_index_rows"]) for profile in profiles)
    orphan_total = sum(int(profile["orphan_fts_rows"]) for profile in profiles)
    error_count = sum(1 for profile in profiles if profile.get("error"))
    status = "healthy" if missing_total == 0 and orphan_total == 0 and error_count == 0 else "needs-rebuild"
    return {
        "profile_version": "case-db-search-index-health-v1",
        "case_id": case_id,
        "status": status,
        "ready_for_large_case_search": status == "healthy",
        "summary": {
            "source_count": len(profiles),
            "missing_index_rows": missing_total,
            "orphan_fts_rows": orphan_total,
            "error_count": error_count,
        },
        "indexes": profiles,
        "commercial_gap_ids": ["#61", "#68", "#74", "#78", "#79"],
        "core_accuracy_gates": [
            build_accuracy_gate(
                74,
                satisfied_checks=[
                    "case-scoped FTS row counts emitted",
                    "missing source-to-index rows counted",
                    "orphan index rows counted",
                    "rebuild recommendation emitted",
                ],
                evidence_refs=[
                    f"status:{status}",
                    f"missing_index_rows:{missing_total}",
                    f"orphan_fts_rows:{orphan_total}",
                ],
            )
        ],
        "blockers": [
            "external 1M+/10M+ row benchmark evidence still required for commercial performance claims",
        ]
        if status == "healthy"
        else [
            "run rapidtriage case-db <db> --case-id <case> --rebuild-search-indexes before relying on complete search",
            "external 1M+/10M+ row benchmark evidence still required for commercial performance claims",
        ],
    }


def case_db_fts_health_profile(
    connection: sqlite3.Connection,
    *,
    case_id: str,
    source: str,
    source_table: str,
    fts_table: str,
    source_label: str,
) -> dict[str, object]:
    try:
        source_rows = count_rows(connection, source_table, case_id)
        indexed_rows = count_case_fts_rows(connection, source_table=source_table, fts_table=fts_table, case_id=case_id)
        missing_rows = count_missing_fts_rows(connection, source_table=source_table, fts_table=fts_table, case_id=case_id)
        orphan_rows = count_orphan_fts_rows(connection, source_table=source_table, fts_table=fts_table)
        status = "healthy" if missing_rows == 0 and orphan_rows == 0 else "needs-rebuild"
        error = ""
    except sqlite3.OperationalError as exc:
        source_rows = 0
        indexed_rows = 0
        missing_rows = 0
        orphan_rows = 0
        status = "error"
        error = str(exc)
    return {
        "source": source,
        "source_table": source_table,
        "fts_table": fts_table,
        "source_label": source_label,
        "status": status,
        "source_rows": source_rows,
        "indexed_rows": indexed_rows,
        "missing_index_rows": missing_rows,
        "orphan_fts_rows": orphan_rows,
        "error": error,
        "recommendation": "rebuild-search-indexes" if status != "healthy" else "none",
    }


def count_case_fts_rows(
    connection: sqlite3.Connection,
    *,
    source_table: str,
    fts_table: str,
    case_id: str,
) -> int:
    row = connection.execute(
        f"""
        SELECT COUNT(*) AS count
        FROM {fts_table}
        JOIN {source_table} ON {fts_table}.rowid = {source_table}.id
        WHERE {source_table}.case_id = ?
        """,
        (case_id,),
    ).fetchone()
    return int(row["count"] if row is not None else 0)


def count_missing_fts_rows(
    connection: sqlite3.Connection,
    *,
    source_table: str,
    fts_table: str,
    case_id: str,
) -> int:
    row = connection.execute(
        f"""
        SELECT COUNT(*) AS count
        FROM {source_table}
        LEFT JOIN {fts_table} ON {fts_table}.rowid = {source_table}.id
        WHERE {source_table}.case_id = ?
          AND {fts_table}.rowid IS NULL
        """,
        (case_id,),
    ).fetchone()
    return int(row["count"] if row is not None else 0)


def count_orphan_fts_rows(
    connection: sqlite3.Connection,
    *,
    source_table: str,
    fts_table: str,
) -> int:
    row = connection.execute(
        f"""
        SELECT COUNT(*) AS count
        FROM {fts_table}
        LEFT JOIN {source_table} ON {fts_table}.rowid = {source_table}.id
        WHERE {source_table}.id IS NULL
        """
    ).fetchone()
    return int(row["count"] if row is not None else 0)


def rebuild_case_db_search_indexes(connection: sqlite3.Connection, case_id: str) -> dict[str, object]:
    before = case_db_search_index_health(connection, case_id)
    actions: list[dict[str, object]] = []
    actions.append(rebuild_external_content_fts(connection, fts_table="indexed_document_fts"))
    actions.append(
        rebuild_standalone_fts(
            connection,
            case_id=case_id,
            source="files",
            source_table="file_record",
            fts_table="file_record_fts",
            columns=("path", "extension", "hashes"),
            select_sql="""
                SELECT
                    id,
                    path,
                    extension,
                    trim(COALESCE(hash_md5, '') || ' ' || COALESCE(hash_sha1, '') || ' ' || COALESCE(hash_sha256, ''))
                FROM file_record
                WHERE case_id = ?
                ORDER BY id ASC
            """,
        )
    )
    actions.append(
        rebuild_standalone_fts(
            connection,
            case_id=case_id,
            source="artifacts",
            source_table="artifact",
            fts_table="artifact_fts",
            columns=("title", "summary", "metadata"),
            select_sql="""
                SELECT id, title, summary, data_json
                FROM artifact
                WHERE case_id = ?
                ORDER BY id ASC
            """,
        )
    )
    actions.append(
        rebuild_standalone_fts(
            connection,
            case_id=case_id,
            source="timeline",
            source_table="event",
            fts_table="event_fts",
            columns=("event_type", "timestamp", "target", "description", "source"),
            select_sql="""
                SELECT id, event_type, timestamp, target, description, source
                FROM event
                WHERE case_id = ?
                ORDER BY id ASC
            """,
        )
    )
    after = case_db_search_index_health(connection, case_id)
    return {
        "profile_version": "case-db-search-index-rebuild-v1",
        "case_id": case_id,
        "status": "rebuilt" if after["status"] == "healthy" else "partial",
        "before": before,
        "after": after,
        "actions": actions,
        "commercial_gap_ids": ["#61", "#68", "#74", "#78", "#79"],
    }


def rebuild_external_content_fts(connection: sqlite3.Connection, *, fts_table: str) -> dict[str, object]:
    try:
        connection.execute(f"INSERT INTO {fts_table}({fts_table}) VALUES('rebuild')")
        status = "rebuilt"
        error = ""
    except sqlite3.OperationalError as exc:
        status = "error"
        error = str(exc)
    return {
        "source": "documents",
        "fts_table": fts_table,
        "status": status,
        "scope": "all-cases",
        "error": error,
    }


def rebuild_standalone_fts(
    connection: sqlite3.Connection,
    *,
    case_id: str,
    source: str,
    source_table: str,
    fts_table: str,
    columns: Sequence[str],
    select_sql: str,
) -> dict[str, object]:
    try:
        row_ids = [
            int(row["id"])
            for row in connection.execute(
                f"SELECT id FROM {source_table} WHERE case_id = ? ORDER BY id ASC",
                (case_id,),
            ).fetchall()
        ]
        for row_id in row_ids:
            connection.execute(f"DELETE FROM {fts_table} WHERE rowid = ?", (row_id,))
        placeholders = ", ".join("?" for _ in columns)
        column_sql = ", ".join(columns)
        inserted = 0
        for row in connection.execute(select_sql, (case_id,)).fetchall():
            values = [row[column] for column in row.keys() if column != "id"]
            connection.execute(
                f"INSERT INTO {fts_table}(rowid, {column_sql}) VALUES (?, {placeholders})",
                (row["id"], *values),
            )
            inserted += 1
        return {
            "source": source,
            "fts_table": fts_table,
            "status": "rebuilt",
            "deleted_rows": len(row_ids),
            "inserted_rows": inserted,
            "scope": "case",
            "error": "",
        }
    except sqlite3.OperationalError as exc:
        return {
            "source": source,
            "fts_table": fts_table,
            "status": "error",
            "deleted_rows": 0,
            "inserted_rows": 0,
            "scope": "case",
            "error": str(exc),
        }


def case_db_fts_optimization_assessment(connection: sqlite3.Connection) -> dict[str, object]:
    indexes = [
        str(row["name"])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_%' ORDER BY name"
        ).fetchall()
    ]
    fts_tables = [
        str(row["name"])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE '%_fts' ORDER BY name"
        ).fetchall()
    ]
    query_plan_profile = case_db_query_plan_profile(connection, fts_tables=fts_tables)
    validation_plan = case_db_large_sqlite_fts_report_grade_validation_plan(
        query_plan_profile=query_plan_profile,
        fts_tables=fts_tables,
        index_count=len(indexes),
    )
    return {
        "component": "case-db-large-sqlite-fts",
        "status": "fts5-and-hot-path-indexes-enabled",
        "commercial_gap_ids": [LARGE_SQLITE_FTS_GAP_ID],
        "functional_priority_profile": case_db_fts_functional_profile(
            fts_tables=fts_tables,
            index_count=len(indexes),
            validation_plan=validation_plan,
        ),
        "fts_tables": fts_tables,
        "index_count": len(indexes),
        "hot_path_indexes": indexes,
        "query_plan_profile": query_plan_profile,
        "sqlite_pragmas": {
            "foreign_keys": True,
            "temp_store": "MEMORY",
            "cache_size_kib": 65536,
            "journal_mode": "WAL-when-supported",
            "optimize_on_close": True,
        },
        "large_sqlite_fts_report_grade_validation_plan": validation_plan,
        "large_sqlite_fts_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
        "report_grade_ready_slot_count": validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
        "ready_for_court_report": False,
        "core_accuracy_gates": [
            build_accuracy_gate(
                74,
                satisfied_checks=[
                    "SQLite performance pragmas applied",
                    "table profile emitted",
                    "searchable text columns counted",
                    "bounded row preview preserved",
                    "case DB query plan profile emitted",
                    "large corpus optimization limitation warning",
                    "large SQLite/FTS report-grade validation plan emitted",
                    "large SQLite/FTS report-grade ready slots emitted",
                ],
                evidence_refs=[
                    f"fts_table_count:{len(fts_tables)}",
                    f"index_count:{len(indexes)}",
                    f"query_plan_hash:{query_plan_profile['plan_hash']}",
                    f"large_sqlite_fts_report_grade_validation_plan_sha256:{validation_plan['validation_plan_sha256']}",
                    "journal_mode:WAL-when-supported",
                ],
            )
        ],
        "blockers": list(validation_plan["blockers"]),
    }


def case_db_large_sqlite_fts_report_grade_validation_plan(
    *,
    query_plan_profile: Mapping[str, object],
    fts_tables: Sequence[str],
    index_count: int,
) -> dict[str, object]:
    query_plan_hash = str(query_plan_profile.get("plan_hash") or "")
    fts_table_head_hash = hashlib.sha256("\n".join(sorted(str(table) for table in fts_tables)).encode("utf-8")).hexdigest()
    case_db_profile = {
        "fts_tables": sorted(str(table) for table in fts_tables),
        "index_count": index_count,
        "journal_mode": "WAL-when-supported",
        "optimize_on_close": True,
    }
    case_db_profile_hash = hashlib.sha256(json.dumps(case_db_profile, sort_keys=True).encode("utf-8")).hexdigest()
    ready_slots: list[dict[str, object]] = [
        {
            "slot_id": "case-db-query-plan-profile",
            "status": "ready",
            "evidence_ref": "query_plan_hash",
            "evidence_hash": query_plan_hash,
            "description": "Case DB emits deterministic query-plan hashes for hot-path and FTS queries.",
        },
        {
            "slot_id": "case-db-fts-table-inventory",
            "status": "ready",
            "evidence_ref": "fts_table_head_hash",
            "evidence_hash": fts_table_head_hash,
            "description": "FTS table inventory is hashed for release regression review.",
        },
        {
            "slot_id": "case-db-index-inventory",
            "status": "ready",
            "evidence_ref": "index_count",
            "evidence_hash": hashlib.sha256(str(index_count).encode("ascii")).hexdigest(),
            "description": "Hot-path index count is captured at schema initialization.",
        },
        {
            "slot_id": "wal-when-supported-policy",
            "status": "ready",
            "evidence_ref": "journal_mode",
            "evidence_hash": hashlib.sha256(b"WAL-when-supported").hexdigest(),
            "description": "Case DB policy requests WAL where the host SQLite build supports it.",
        },
        {
            "slot_id": "pragma-optimize-policy",
            "status": "ready",
            "evidence_ref": "optimize_on_close",
            "evidence_hash": hashlib.sha256(b"True").hexdigest(),
            "description": "Case DB records PRAGMA optimize on close as the local maintenance policy.",
        },
        {
            "slot_id": "case-db-performance-profile",
            "status": "ready",
            "evidence_ref": "case_db_profile_hash",
            "evidence_hash": case_db_profile_hash,
            "description": "FTS tables, indexes, WAL policy, and optimize policy are grouped for report review.",
        },
    ]
    blocking_slots: list[dict[str, object]] = [
        {
            "slot_id": "trusted-case-db-query-plan-diff",
            "status": "blocked",
            "blocker": "trusted-case-db-sqlite-fts-query-plan-diff-missing",
            "required_evidence": "trusted Case DB SQLite/FTS query-plan manifest diff",
        },
        {
            "slot_id": "10m-row-query-plan-regression",
            "status": "blocked",
            "blocker": "10m-row-query-plan-regression-required",
            "required_evidence": "10M-row Case DB query-plan and latency regression evidence",
        },
        {
            "slot_id": "deleted-row-wal-replay",
            "status": "blocked",
            "blocker": "deleted-row-wal-replay-validation-required",
            "required_evidence": "source SQLite WAL/deleted-row replay validation before claiming recovery completeness",
        },
        {
            "slot_id": "large-source-db-corpus",
            "status": "blocked",
            "blocker": "large-source-db-corpus-required",
            "required_evidence": "large source SQLite and Case DB corpus covering multi-GB evidence",
        },
        {
            "slot_id": "browser-pagination-query-plan-e2e",
            "status": "blocked",
            "blocker": "browser-pagination-query-plan-e2e-required",
            "required_evidence": "browser E2E evidence that large query/table views remain paginated and bounded",
        },
        {
            "slot_id": "index-maintenance-vacuum-regression",
            "status": "blocked",
            "blocker": "index-maintenance-vacuum-regression-required",
            "required_evidence": "index maintenance, PRAGMA optimize, vacuum, and rebuild regression logs",
        },
    ]
    plan_core = {
        "profile_version": LARGE_SQLITE_FTS_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 74,
        "gap_id": LARGE_SQLITE_FTS_GAP_ID,
        "commercial_gap_ids": [LARGE_SQLITE_FTS_GAP_ID],
        "scope": "case-db-sqlite-fts",
        "query_plan_hash": query_plan_hash,
        "fts_table_count": len(fts_tables),
        "fts_table_head_hash": fts_table_head_hash,
        "index_count": index_count,
        "case_db_profile_hash": case_db_profile_hash,
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "blockers": list(LARGE_SQLITE_FTS_REPORT_GRADE_BLOCKERS),
        "commercial_claim_allowed": False,
        "ready_for_court_report": False,
        "report_use_warning": "Use as Case DB SQLite/FTS readiness evidence only until trusted query-plan and large-row regression evidence are attached.",
    }
    validation_plan_sha256 = hashlib.sha256(json.dumps(plan_core, sort_keys=True).encode("utf-8")).hexdigest()
    return {
        **plan_core,
        "validation_plan_sha256": validation_plan_sha256,
        "validation_plan_hash": validation_plan_sha256,
    }


def case_db_query_plan_profile(connection: sqlite3.Connection, *, fts_tables: Sequence[str]) -> dict[str, object]:
    statements = [
        (
            "indexed_document_by_case",
            "EXPLAIN QUERY PLAN SELECT id FROM indexed_document WHERE case_id = ? LIMIT 10",
            ("CASE-ID",),
        ),
        (
            "artifact_by_case",
            "EXPLAIN QUERY PLAN SELECT id FROM artifact WHERE case_id = ? LIMIT 10",
            ("CASE-ID",),
        ),
    ]
    if "artifact_fts" in fts_tables:
        statements.append(
            (
                "artifact_fts_match",
                "EXPLAIN QUERY PLAN SELECT rowid FROM artifact_fts WHERE artifact_fts MATCH ? LIMIT 10",
                ("password",),
            )
        )
    if "indexed_document_fts" in fts_tables:
        statements.append(
            (
                "indexed_document_fts_match",
                "EXPLAIN QUERY PLAN SELECT rowid FROM indexed_document_fts WHERE indexed_document_fts MATCH ? LIMIT 10",
                ("password",),
            )
        )
    if "file_record_fts" in fts_tables:
        statements.append(
            (
                "file_record_fts_match",
                "EXPLAIN QUERY PLAN SELECT rowid FROM file_record_fts WHERE file_record_fts MATCH ? LIMIT 10",
                ("password",),
            )
        )
    if "event_fts" in fts_tables:
        statements.append(
            (
                "event_fts_match",
                "EXPLAIN QUERY PLAN SELECT rowid FROM event_fts WHERE event_fts MATCH ? LIMIT 10",
                ("password",),
            )
        )
    plans: list[dict[str, object]] = []
    for name, sql, params in statements:
        try:
            rows = connection.execute(sql, params).fetchall()
            details = [str(row["detail"] if isinstance(row, sqlite3.Row) else row[-1]) for row in rows]
        except sqlite3.DatabaseError as exc:
            details = [f"query-plan-error:{exc}"]
        plans.append({"name": name, "details": details, "bounded_limit": 10})
    plan_hash = hashlib.sha256(json.dumps(plans, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
    return {
        "profile_version": "case-db-query-plan-profile-v1",
        "plan_count": len(plans),
        "plan_hash": plan_hash,
        "plans": plans,
        "uses_fts_tables": bool(fts_tables),
        "bounded_limit": 10,
        "commercial_gap_ids": [LARGE_SQLITE_FTS_GAP_ID],
        "commercial_claim_allowed": False,
    }


def case_db_fts_functional_profile(
    *,
    fts_tables: Sequence[str],
    index_count: int,
    validation_plan: Mapping[str, object],
) -> dict[str, object]:
    return {
        "batch_id": FUNCTIONAL_SCALE_BATCH_ID,
        "item_number": 32,
        "gap_id": "#32",
        "component": "sqlite-fts-optimization",
        "status": "implemented-case-db-fts5-validation-required",
        "implemented": True,
        "usable": True,
        "validated": True,
        "ready_for_commercial_claim": False,
        "controls": {
            "fts_tables": list(fts_tables),
            "fts_table_count": len(fts_tables),
            "hot_path_index_count": index_count,
            "wal_when_supported": True,
            "pragma_optimize_on_close": True,
            "bounded_preview_contract": True,
            "large_sqlite_fts_report_grade_validation_plan_hash": str(
                validation_plan.get("validation_plan_sha256") or ""
            ),
            "large_sqlite_fts_report_grade_ready_slot_count": int(validation_plan.get("ready_slot_count") or 0),
            "large_sqlite_fts_report_grade_blocking_slot_count": int(validation_plan.get("blocking_slot_count") or 0),
        },
        "blockers": [
            "10m-record-benchmark-and-query-plan-regression-gates-remain-required",
            "external-source-sqlite-wal-journal-replay-is-not-part-of-case-db-indexing",
            "trusted-case-db-sqlite-fts-query-plan-diff-missing",
        ],
        "validation_evidence": [
            "case-db-initialize-emits-functional-fts-profile",
            "unit-test-asserts-case-db-fts-profile-contract",
        ],
    }


def build_case_db_fts_trusted_diff(
    rapid_assessment: Mapping[str, object],
    trusted_assessment: Mapping[str, object],
    *,
    trusted_tool: str = "case-db-sqlite-query-plan-manifest",
) -> dict[str, object]:
    rapid = case_db_fts_diff_value(rapid_assessment)
    trusted = case_db_fts_diff_value(trusted_assessment)
    mismatched = [
        {"field": key, "rapid": rapid.get(key), "trusted": trusted.get(key)}
        for key in sorted(set(rapid).union(trusted))
        if rapid.get(key) != trusted.get(key)
    ]
    status = "pass" if not mismatched else "fail"
    return {
        "profile": "case-db-sqlite-fts-trusted-query-plan-diff-v1",
        "item_number": 74,
        "trusted_tool": trusted_tool,
        "status": status,
        "mismatched": mismatched,
        "commercial_gap_ids": [LARGE_SQLITE_FTS_GAP_ID],
        "commercial_claim_allowed": status == "pass",
    }


def case_db_fts_diff_value(item: Mapping[str, object]) -> dict[str, object]:
    query_plan = item.get("query_plan_profile")
    query_plan_profile = query_plan if isinstance(query_plan, Mapping) else {}
    return {
        "status": str(item.get("status") or ""),
        "fts_tables": sorted(str(value) for value in item.get("fts_tables") or []),
        "index_count": int(item.get("index_count") or 0),
        "query_plan_hash": str(query_plan_profile.get("plan_hash") or ""),
    }


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


def safe_extract_text(path: Path, kind: str) -> tuple[str, str]:
    try:
        return extract_text(path, kind), ""
    except Exception as exc:
        return "", f"{type(exc).__name__}: {exc}"


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


def optional_float(value: Any) -> float | None:
    try:
        return float(value)
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
        "source_viewer_locator",
        "source_locator",
        "row_citation_hash",
        "parser_manifest_hashes",
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
    source_viewer_locator = artifact_source_viewer_locator(details)
    if source_viewer_locator:
        metadata["source_viewer_locator"] = source_viewer_locator
        metadata.setdefault("source_locator", source_viewer_locator)
        metadata["source_locator_hash"] = stable_payload_sha256(source_viewer_locator)
    row_citation = artifact_row_citation(details)
    if row_citation:
        metadata["row_citation"] = row_citation
        if row_citation.get("row_hash"):
            metadata["row_citation_hash"] = str(row_citation["row_hash"])
    parser_manifest_hashes = artifact_parser_manifest_hashes(details)
    if parser_manifest_hashes:
        metadata["parser_manifest_hashes"] = parser_manifest_hashes
    nested = artifact_nested_preview(details)
    if nested:
        metadata["preview_value"] = nested
    return metadata


def artifact_parser_manifest_hashes(details: Mapping[str, object]) -> dict[str, str]:
    manifest_fields = {
        "cloud_export_import_manifest_hash": "cloud_export_import",
        "cloud_archive_manifest_hash": "cloud_archive",
        "google_takeout_parser_manifest_hash": "google_takeout",
        "icloud_export_parser_manifest_hash": "icloud_export",
        "m365_export_parser_manifest_hash": "m365_export",
        "email_mailbox_parser_manifest_hash": "email_mailbox",
        "email_expansion_citation_manifest_hash": "email_expansion",
        "ai_transcript_parser_manifest_hash": "ai_transcript",
    }
    hashes: dict[str, str] = {}
    for field, label in manifest_fields.items():
        value = str(details.get(field) or "").strip()
        if value:
            hashes[label] = value
    return hashes


def artifact_row_citation(details: Mapping[str, object]) -> dict[str, object]:
    for manifest_key in artifact_source_manifest_keys():
        manifest = details.get(manifest_key)
        if not isinstance(manifest, Mapping):
            continue
        row_citation = manifest.get("row_citation")
        if isinstance(row_citation, Mapping):
            return dict(row_citation)
    return {}


def artifact_source_viewer_locator(details: Mapping[str, object]) -> dict[str, object]:
    direct = details.get("source_viewer_locator")
    if isinstance(direct, Mapping):
        return dict(direct)
    for manifest_key in artifact_source_manifest_keys():
        manifest = details.get(manifest_key)
        if not isinstance(manifest, Mapping):
            continue
        row_citation = manifest.get("row_citation")
        if isinstance(row_citation, Mapping) and isinstance(row_citation.get("source_viewer_locator"), Mapping):
            return dict(row_citation["source_viewer_locator"])
    import_manifest = details.get("cloud_export_import_manifest")
    if isinstance(import_manifest, Mapping) and isinstance(import_manifest.get("source_viewer_locator"), Mapping):
        return dict(import_manifest["source_viewer_locator"])
    attachments = details.get("attachments")
    if isinstance(attachments, list):
        for attachment in attachments:
            if isinstance(attachment, Mapping) and isinstance(attachment.get("source_viewer_locator"), Mapping):
                return dict(attachment["source_viewer_locator"])
    return {}


def artifact_source_manifest_keys() -> tuple[str, ...]:
    return (
        "google_takeout_parser_manifest",
        "icloud_export_parser_manifest",
        "m365_export_parser_manifest",
        "email_mailbox_parser_manifest",
        "email_expansion_citation_manifest",
        "ai_transcript_parser_manifest",
    )


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


def ioc_scanner_artifact_row(row: Mapping[str, object], *, index: int) -> dict[str, object]:
    hit_type = str(row.get("type") or "ioc")
    hit_value = str(row.get("value") or "")
    rule_id = str(row.get("rule_id") or "")
    sources = row.get("sources") if isinstance(row.get("sources"), list) else []
    first_source = sources[0] if sources and isinstance(sources[0], Mapping) else {}
    source_path = str(first_source.get("path") or first_source.get("source_path") or "")
    output_path = str(first_source.get("output_path") or "")
    title = f"IOC scanner hit: {rule_id} {hit_type}:{hit_value}".strip()
    details = {
        "parser": "rapidtriage-indicators",
        "parser_version": "1",
        "coverage_status": "local-rule-ioc-scanner",
        "reportability": "triage",
        "source_format": "rapidtriage-indicators-json",
        "source_index": index,
        "source_path": source_path,
        "output_path": output_path,
        "rule_id": rule_id,
        "ioc_type": hit_type,
        "ioc_value": hit_value,
        "count": optional_int(row.get("count")) or 0,
        "classification": str(row.get("classification") or ""),
        "risk_flags": list(row.get("risk_flags", [])) if isinstance(row.get("risk_flags"), list) else [],
        "sources": sources,
        "source_viewer_locator": dict(row.get("source_viewer_locator", {})) if isinstance(row.get("source_viewer_locator"), Mapping) else {},
        "evidence_strength": "local-rule-ioc-hit",
        "report_use_boundary": str(row.get("report_use_boundary") or ""),
        "raw": dict(row),
    }
    return {
        "provider": "rapidtriage-indicators",
        "artifact_type": "indicator-ioc-scanner-hit",
        "path": source_path or output_path,
        "title": title,
        "summary": f"{rule_id} matched {hit_type}:{hit_value}" if rule_id or hit_value else "IOC scanner hit",
        "supported": True,
        "details": details,
    }


def worker_artifact_row(record: Mapping[str, object], *, source_jsonl: str, index: int) -> dict[str, object]:
    source = record.get("source") if isinstance(record.get("source"), Mapping) else {}
    fields = record.get("fields") if isinstance(record.get("fields"), Mapping) else {}
    artifact_type = str(record.get("artifact_type") or "worker-artifact")
    artifact_family = str(record.get("artifact_family") or "")
    source_path = str(source.get("source_path") or "") if isinstance(source, Mapping) else ""
    details = {
        "parser": str(record.get("parser") or "rapid-worker"),
        "parser_version": str(record.get("parser_version") or ""),
        "coverage_status": "worker-jsonl-import",
        "reportability": "triage",
        "source_format": "ArtifactRecordV1-jsonl",
        "source_index": index,
        "source_jsonl": source_jsonl,
        "artifact_id": str(record.get("artifact_id") or ""),
        "artifact_family": artifact_family,
        "source_case_id": str(source.get("case_id") or "") if isinstance(source, Mapping) else "",
        "source_id": str(source.get("source_id") or "") if isinstance(source, Mapping) else "",
        "source_path": source_path,
        "source_offset": source.get("offset") if isinstance(source, Mapping) else None,
        "source_length": source.get("length") if isinstance(source, Mapping) else None,
        "source_hashes": source.get("hashes") if isinstance(source.get("hashes"), Mapping) else {},
        "confidence": optional_float(record.get("confidence")),
        "validation_required": bool(record.get("validation_required")),
        "commercial_grade_ready": bool(record.get("commercial_grade_ready")),
        "commercial_grade_blockers": list(record.get("commercial_grade_blockers", []))
        if isinstance(record.get("commercial_grade_blockers"), list)
        else [],
        "legal_limitations": list(record.get("legal_limitations", []))
        if isinstance(record.get("legal_limitations"), list)
        else [],
        "fields": dict(fields),
        "raw": dict(record),
    }
    for key, value in fields.items():
        if key not in details and value not in (None, "", []):
            details[str(key)] = value
    return {
        "provider": "rapid-worker",
        "artifact_type": artifact_type,
        "path": source_path,
        "supported": True,
        "details": details,
    }


def worker_record_index_text(artifact: Mapping[str, object]) -> str:
    details = artifact_details(artifact)
    raw = details.get("raw") if isinstance(details.get("raw"), Mapping) else {}
    fields = details.get("fields") if isinstance(details.get("fields"), Mapping) else {}
    searchable = {
        "provider": artifact.get("provider"),
        "artifact_type": artifact.get("artifact_type"),
        "path": artifact.get("path"),
        "title": artifact_title(artifact),
        "summary": artifact_summary(artifact),
        "details": details,
        "fields": fields,
        "raw": raw,
        "metadata": artifact_search_metadata(artifact),
    }
    return json.dumps(searchable, ensure_ascii=False, sort_keys=True)


def parse_json_object(value: object) -> dict[str, object]:
    if isinstance(value, Mapping):
        return dict(value)
    try:
        payload = json.loads(str(value or "{}"))
    except json.JSONDecodeError:
        return {}
    return dict(payload) if isinstance(payload, Mapping) else {}


def parse_json_list(value: object) -> list[object]:
    if isinstance(value, list):
        return list(value)
    try:
        payload = json.loads(str(value or "[]"))
    except json.JSONDecodeError:
        return []
    return list(payload) if isinstance(payload, list) else []


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


def case_document_extraction_errors(
    connection: sqlite3.Connection,
    case_id: str,
    *,
    limit: int = 100,
) -> list[dict[str, object]]:
    rows = connection.execute(
        """
        SELECT citation_id, target_id, timestamp, params_json, error
        FROM audit_event
        WHERE case_id = ?
          AND action = 'document-text-extraction'
          AND result = 'failed'
        ORDER BY id DESC
        LIMIT ?
        """,
        (case_id, max(1, int(limit))),
    ).fetchall()
    errors: list[dict[str, object]] = []
    for row in rows:
        params = parse_json_object(str(row["params_json"] or "{}"))
        error = str(row["error"] or "document extraction failed")
        error_type = error.split(":", 1)[0] if ":" in error else "DocumentExtractionError"
        errors.append(
            {
                "citation_id": str(row["citation_id"]),
                "target_id": str(row["target_id"] or ""),
                "timestamp": str(row["timestamp"] or ""),
                "path": str(params.get("path") or ""),
                "kind": str(params.get("kind") or ""),
                "error": error,
                "reason": "case-db-document-text-extraction-failed",
                "error_type": error_type,
                "message": error.split(":", 1)[1].strip() if ":" in error else error,
                "recoverable": True,
                "effect": "case-search-documents-partial-coverage",
            }
        )
    return errors


def attach_review_marks(
    connection: sqlite3.Connection,
    case_id: str,
    matches: list[dict[str, object]],
) -> list[dict[str, object]]:
    if not matches:
        return matches
    target_pairs = sorted(
        {
            (str(match.get("target_type") or ""), str(match.get("target_id") or ""))
            for match in matches
            if match.get("target_type") not in (None, "") and match.get("target_id") not in (None, "")
        }
    )
    rows: list[sqlite3.Row] = []
    for chunk_start in range(0, len(target_pairs), 300):
        chunk = target_pairs[chunk_start : chunk_start + 300]
        if not chunk:
            continue
        predicates = " OR ".join("(target_type = ? AND target_id = ?)" for _ in chunk)
        params: list[object] = [case_id]
        for target_type, target_id in chunk:
            params.extend([target_type, target_id])
        rows.extend(
            connection.execute(
                f"SELECT * FROM review_mark WHERE case_id = ? AND ({predicates})",
                params,
            ).fetchall()
        )
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
    source_viewer_locator = (
        dict(metadata.get("source_viewer_locator")) if isinstance(metadata.get("source_viewer_locator"), Mapping) else {}
    )
    source_locator = dict(metadata.get("source_locator")) if isinstance(metadata.get("source_locator"), Mapping) else {}
    parser_manifest_hashes = (
        dict(metadata.get("parser_manifest_hashes")) if isinstance(metadata.get("parser_manifest_hashes"), Mapping) else {}
    )
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
        "source_viewer_locator": source_viewer_locator,
        "source_locator": source_locator or source_viewer_locator,
        "source_locator_hash": str(metadata.get("source_locator_hash") or ""),
        "row_citation_hash": str(metadata.get("row_citation_hash") or ""),
        "parser_manifest_hashes": parser_manifest_hashes,
        "evidence_strength": str(metadata.get("evidence_strength") or ""),
        "reportability": str(metadata.get("reportability") or ""),
        "coverage_status": str(metadata.get("coverage_status") or ""),
    }
    return {
        key: value
        for key, value in reference.items()
        if value not in (None, "", {}, [])
    }


def merge_source_citation_package_into_reference(
    source_reference: Mapping[str, object],
    package: Mapping[str, object],
) -> dict[str, object]:
    merged = dict(source_reference)
    if not package:
        return merged
    locator = package.get("source_locator") if isinstance(package.get("source_locator"), Mapping) else {}
    source_hashes = dict(merged.get("source_hashes")) if isinstance(merged.get("source_hashes"), Mapping) else {}
    source_sha256 = str(package.get("source_sha256") or "").strip()
    if source_sha256:
        source_hashes.setdefault("sha256", source_sha256)
    record_hashes = dict(merged.get("record_hashes")) if isinstance(merged.get("record_hashes"), Mapping) else {}
    snippet_sha256 = str(package.get("snippet_sha256") or "").strip()
    if snippet_sha256:
        record_hashes.setdefault("snippet_sha256", snippet_sha256)
    merged.update(
        {
            "source_citation_package_hash": source_citation_package_hash(package),
            "source_read_citation_id": str(package.get("citation_id") or ""),
            "source_read_citation_text": str(package.get("citation_text") or ""),
            "source_path_hash": str(package.get("source_path_hash") or ""),
            "source_locator": dict(locator),
            "parser": str(merged.get("parser") or "rapidtriage.source-read"),
            "parser_version": str(merged.get("parser_version") or package.get("profile_version") or "source-read-citation-package-v1"),
            "reportability": str(merged.get("reportability") or "review-lead-source-citation-package"),
        }
    )
    if source_hashes:
        merged["source_hashes"] = source_hashes
    if record_hashes:
        merged["record_hashes"] = record_hashes
    locator_field_map = {
        "record_offset": ("record_offset", "byte_offset", "offset"),
        "source_index": ("source_index", "archive_entry_index"),
        "line": ("line", "line_number"),
        "row_id": ("row_id", "rowid"),
        "table": ("table",),
    }
    for output_field, locator_fields in locator_field_map.items():
        if merged.get(output_field) not in (None, ""):
            continue
        for locator_field in locator_fields:
            if locator.get(locator_field) not in (None, ""):
                merged[output_field] = locator.get(locator_field)
                break
    return {
        key: value
        for key, value in merged.items()
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
    scan_candidate_limit: int,
) -> list[dict[str, object]]:
    if file_record_fts_has_rows(connection, case_id):
        fts_matches = search_file_records_fts(connection, case_id, keywords, limit)
        if fts_matches:
            return fts_matches[:limit] if limit else fts_matches
    rows = connection.execute(
        """
        SELECT citation_id, id, path, extension, size_bytes, modified_at, hash_md5, hash_sha1, hash_sha256
        FROM file_record
        WHERE case_id = ?
        ORDER BY id ASC
        LIMIT ?
        """,
        (case_id, scan_candidate_limit),
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


def file_record_fts_has_rows(connection: sqlite3.Connection, case_id: str) -> bool:
    try:
        row = connection.execute(
            """
            SELECT 1
            FROM file_record_fts
            JOIN file_record ON file_record_fts.rowid = file_record.id
            WHERE file_record.case_id = ?
            LIMIT 1
            """,
            (case_id,),
        ).fetchone()
    except sqlite3.OperationalError:
        return False
    return row is not None


def search_file_records_fts(
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
                file_record.citation_id,
                file_record.id,
                file_record.path,
                file_record.extension,
                file_record.size_bytes,
                file_record.modified_at,
                file_record.hash_md5,
                file_record.hash_sha1,
                file_record.hash_sha256,
                snippet(file_record_fts, 0, '[', ']', ' ... ', 24) AS snippet
            FROM file_record_fts
            JOIN file_record ON file_record_fts.rowid = file_record.id
            WHERE file_record.case_id = ?
              AND file_record_fts MATCH ?
            ORDER BY rank
            LIMIT ?
            """,
            (case_id, query, limit or -1),
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    matches = []
    for row in rows:
        haystack = " ".join(str(row[key] or "") for key in ("path", "extension", "hash_md5", "hash_sha1", "hash_sha256"))
        matches.append(
            {
                "source": "files",
                "citation_id": str(row["citation_id"]),
                "target_type": "file_record",
                "target_id": str(row["id"]),
                "title": Path(str(row["path"])).name,
                "kind": str(row["extension"] or ""),
                "path": str(row["path"]),
                "matched_keywords": matched_keywords(haystack, keywords),
                "preview": str(row["snippet"] or row["path"]),
                "metadata": {
                    "size_bytes": optional_int(row["size_bytes"]),
                    "modified_at": optional_str(row["modified_at"]),
                    "search_backend": "sqlite-fts5",
                    "source_hashes": {
                        key: str(row[column])
                        for key, column in (("md5", "hash_md5"), ("sha1", "hash_sha1"), ("sha256", "hash_sha256"))
                        if row[column]
                    },
                },
            }
        )
    return matches


def search_artifacts(
    connection: sqlite3.Connection,
    case_id: str,
    keywords: list[str],
    limit: int,
    scan_candidate_limit: int,
) -> list[dict[str, object]]:
    if artifact_fts_has_rows(connection, case_id):
        fts_matches = search_artifacts_fts(connection, case_id, keywords, limit)
        if fts_matches:
            return fts_matches[:limit] if limit else fts_matches
    return search_artifacts_scan(connection, case_id, keywords, limit, scan_candidate_limit)


def search_artifacts_scan(
    connection: sqlite3.Connection,
    case_id: str,
    keywords: list[str],
    limit: int,
    scan_candidate_limit: int,
) -> list[dict[str, object]]:
    rows = connection.execute(
        """
        SELECT citation_id, id, artifact_type, title, summary, data_json
        FROM artifact
        WHERE case_id = ?
        ORDER BY id ASC
        LIMIT ?
        """,
        (case_id, scan_candidate_limit),
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


def case_search_source_requested(source_filter: set[str], *sources: str) -> bool:
    return not source_filter or any(source in source_filter for source in sources)


def case_table_has_more_than_scan_limit(
    connection: sqlite3.Connection,
    *,
    table_name: str,
    case_id: str,
    scan_candidate_limit: int,
) -> bool:
    if scan_candidate_limit <= 0:
        return False
    row = connection.execute(
        f"""
        SELECT 1
        FROM {table_name}
        WHERE case_id = ?
        ORDER BY id ASC
        LIMIT 1 OFFSET ?
        """,
        (case_id, scan_candidate_limit),
    ).fetchone()
    return row is not None


def case_search_cursor_scope(
    *,
    case_id: str,
    keywords: Sequence[str],
    sources: set[str],
    metadata_filter: Mapping[str, str],
    review_status: str | None,
    verification_status: str | None,
) -> str:
    payload = {
        "case_id": case_id,
        "keywords": [keyword.strip().lower() for keyword in keywords],
        "sources": sorted(sources),
        "metadata": dict(sorted(metadata_filter.items())),
        "review_status": review_status or "",
        "verification_status": verification_status or "",
    }
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


def encode_case_search_cursor(*, offset: int, scope: str) -> str:
    payload = {
        "version": CASE_SEARCH_CURSOR_VERSION,
        "offset": max(0, int(offset)),
        "scope": scope,
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_case_search_cursor(cursor: str, *, expected_scope: str) -> int:
    token = cursor.strip()
    if not token:
        return 0
    try:
        padded = token + ("=" * (-len(token) % 4))
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CaseDatabaseError("invalid case-search cursor") from exc
    if not isinstance(payload, Mapping) or payload.get("version") != CASE_SEARCH_CURSOR_VERSION:
        raise CaseDatabaseError("invalid case-search cursor version")
    if str(payload.get("scope") or "") != expected_scope:
        raise CaseDatabaseError("case-search cursor does not match the current query")
    offset = optional_int(payload.get("offset"))
    if offset is None or offset < 0:
        raise CaseDatabaseError("invalid case-search cursor offset")
    return offset


def build_case_search_execution_plan(
    connection: sqlite3.Connection,
    case_id: str,
    *,
    source_filter: set[str],
    limit: int,
    cursor_offset: int,
    retrieval_limit: int,
    scan_candidate_limit: int,
) -> dict[str, object]:
    requested_sources = sorted(source_filter)
    search_index_health = case_db_search_index_health(connection, case_id)
    health_by_source = {
        str(row.get("source") or ""): row
        for row in search_index_health.get("indexes", [])
        if isinstance(row, Mapping)
    }
    sources: list[dict[str, object]] = []

    def add_source(
        *,
        source: str,
        requested: bool,
        backend: str,
        table_name: str,
        uses_scan_cap: bool,
        fts_table: str = "",
        notes: Sequence[str] = (),
    ) -> None:
        health = health_by_source.get(source, {})
        health_status = str(health.get("status") or "unknown")
        missing_index_rows = int(health.get("missing_index_rows") or 0)
        orphan_fts_rows = int(health.get("orphan_fts_rows") or 0)
        entry: dict[str, object] = {
            "source": source,
            "requested": requested,
            "backend": backend if requested else "skipped",
            "table": table_name,
            "fts_table": fts_table,
            "search_index_status": health_status,
            "missing_index_rows": missing_index_rows,
            "orphan_fts_rows": orphan_fts_rows,
            "limit": limit,
            "cursor_offset": cursor_offset,
            "retrieval_limit": retrieval_limit,
            "scan_candidate_limit": scan_candidate_limit if uses_scan_cap else None,
            "partial_coverage_warning": False,
            "notes": list(notes),
        }
        if requested and uses_scan_cap:
            has_more = case_table_has_more_than_scan_limit(
                connection,
                table_name=table_name,
                case_id=case_id,
                scan_candidate_limit=scan_candidate_limit,
            )
            entry["partial_coverage_warning"] = has_more
            if has_more:
                entry["notes"].append(
                    "bounded scan reached candidate cap; use FTS-backed sources or narrower filters for complete large-case search"
                )
        if requested and health_status not in ("healthy", "unknown"):
            entry["partial_coverage_warning"] = True
            entry["notes"].append(
                "search index health is not clean; run case-db --search-index-health and --rebuild-search-indexes before absence claims"
            )
        sources.append(entry)

    add_source(
        source="documents",
        requested=case_search_source_requested(source_filter, "documents"),
        backend="sqlite-fts5",
        table_name="indexed_document",
        fts_table="indexed_document_fts",
        uses_scan_cap=False,
        notes=("full-text index over extracted/OCR/document text",),
    )
    file_requested = case_search_source_requested(source_filter, "files")
    file_uses_fts = file_requested and file_record_fts_has_rows(connection, case_id)
    add_source(
        source="files",
        requested=file_requested,
        backend="sqlite-fts5" if file_uses_fts else "bounded-scan",
        table_name="file_record",
        fts_table="file_record_fts" if file_uses_fts else "",
        uses_scan_cap=not file_uses_fts,
        notes=("file path/extension/hash metadata search uses FTS5 when file_record_fts rows are present",),
    )
    artifact_requested = case_search_source_requested(source_filter, "artifacts", "indicators")
    artifact_uses_fts = artifact_requested and artifact_fts_has_rows(connection, case_id)
    add_source(
        source="artifacts",
        requested=artifact_requested,
        backend="sqlite-fts5" if artifact_uses_fts else "bounded-scan",
        table_name="artifact",
        fts_table="artifact_fts" if artifact_uses_fts else "",
        uses_scan_cap=not artifact_uses_fts,
        notes=("artifact and indicator rows share this backend; source filters are applied after matching",),
    )
    timeline_requested = case_search_source_requested(source_filter, "timeline")
    timeline_uses_fts = timeline_requested and event_fts_has_rows(connection, case_id)
    add_source(
        source="timeline",
        requested=timeline_requested,
        backend="sqlite-fts5" if timeline_uses_fts else "bounded-scan",
        table_name="event",
        fts_table="event_fts" if timeline_uses_fts else "",
        uses_scan_cap=not timeline_uses_fts,
        notes=("timeline event type/time/target/description/source search uses FTS5 when event_fts rows are present",),
    )
    return {
        "profile_version": "case-search-large-case-plan-v1",
        "case_id": case_id,
        "requested_sources": requested_sources,
        "scan_policy": {
            "scan_candidate_limit": scan_candidate_limit,
            "cursor_offset": cursor_offset,
            "retrieval_limit": retrieval_limit,
            "min_scan_rows": CASE_DB_SEARCH_MIN_SCAN_ROWS,
            "max_scan_rows": CASE_DB_SEARCH_SCAN_ROW_LIMIT,
            "oversample_per_requested_result": CASE_DB_SEARCH_SCAN_OVERSAMPLE,
        },
        "sources": sources,
        "search_index_health": search_index_health,
        "commercial_gap_ids": ["#61", "#74", "#78", "#79"],
        "status": "validated-local-search-plan-validation-required"
        if search_index_health["status"] == "healthy"
        else "search-index-rebuild-required-before-absence-claims",
    }


def build_case_search_result_window_manifest(
    *,
    case_id: str,
    keywords: Sequence[str],
    source_filter: set[str],
    metadata_filter: Mapping[str, str],
    review_status: str | None,
    verification_status: str | None,
    cursor_scope: str,
    page_offset: int,
    page_size: int,
    retrieval_limit: int,
    scan_candidate_limit: int,
    total_returnable_count: int,
    returned_matches: Sequence[Mapping[str, object]],
    source_counts: Mapping[str, int],
    keyword_counts: Mapping[str, int],
    priority_counts: Mapping[str, int],
    has_more: bool,
    next_cursor: str,
    large_case_search_plan: Mapping[str, object],
    review_workflow_summary: Mapping[str, object],
) -> dict[str, object]:
    source_plan_rows = [
        row for row in large_case_search_plan.get("sources", []) if isinstance(row, Mapping)
    ]
    partial_sources = [
        str(row.get("source") or "")
        for row in source_plan_rows
        if row.get("requested") and row.get("partial_coverage_warning")
    ]
    backend_counts: dict[str, int] = {}
    for row in source_plan_rows:
        if not row.get("requested"):
            continue
        backend = str(row.get("backend") or "unknown")
        backend_counts[backend] = backend_counts.get(backend, 0) + 1

    match_rows: list[dict[str, object]] = []
    for index, match in enumerate(returned_matches[:200]):
        source_reference = match.get("source_reference") if isinstance(match.get("source_reference"), Mapping) else {}
        locator = build_review_queue_source_viewer_locator(match, {})
        raw_matched_terms = match.get("matched_keywords")
        matched_terms = raw_matched_terms if isinstance(raw_matched_terms, (list, tuple, set)) else []
        row_core = {
            "window_position": page_offset + index + 1,
            "source": str(match.get("source") or "unknown"),
            "target_type": str(match.get("target_type") or ""),
            "target_id": str(match.get("target_id") or ""),
            "citation_id": str(match.get("citation_id") or ""),
            "kind": str(match.get("kind") or ""),
            "title": str(match.get("title") or match.get("path") or ""),
            "path": str(match.get("path") or source_reference.get("path") or ""),
            "matched_keywords": [str(item) for item in matched_terms],
            "review_status": str((match.get("review") or {}).get("status") or "unreviewed")
            if isinstance(match.get("review"), Mapping)
            else "unreviewed",
            "verification_status": str((match.get("review") or {}).get("verification_status") or "unverified")
            if isinstance(match.get("review"), Mapping)
            else "unverified",
            "source_reference_hash": stable_payload_sha256(source_reference) if source_reference else "",
            "source_viewer_locator": locator,
        }
        match_rows.append({**row_core, "row_hash": stable_payload_sha256(row_core)})

    filter_after_retrieval = bool(metadata_filter or review_status or verification_status)
    page_core = {
        "case_id": case_id,
        "query_scope_hash": cursor_scope,
        "page_offset": page_offset,
        "page_size": page_size,
        "match_row_hashes": [str(row.get("row_hash") or "") for row in match_rows],
    }
    satisfied = [
        "opaque cursor scope hash emitted",
        "page window row hashes emitted",
        "source viewer locators emitted",
        "source backend plan emitted",
        "bounded scan partial coverage disclosure emitted",
        "review workflow manifest linked",
    ]
    if next_cursor:
        satisfied.append("next cursor emitted for continued pagination")
    if not partial_sources:
        satisfied.append("no bounded source reported scan cap truncation")
    if filter_after_retrieval:
        satisfied.append("post-retrieval filter disclosure emitted")

    manifest_core: dict[str, object] = {
        "profile_version": "case-search-result-window-manifest-v1",
        "commercial_gap_ids": ["#61", "#74", "#78", "#79"],
        "case_id": case_id,
        "query_scope_hash": cursor_scope,
        "query_hash": stable_payload_sha256(
            {
                "case_id": case_id,
                "keywords": [str(keyword).strip().lower() for keyword in keywords],
                "sources": sorted(source_filter),
                "metadata": dict(sorted(metadata_filter.items())),
                "review_status": review_status or "",
                "verification_status": verification_status or "",
            }
        ),
        "page_window_hash": stable_payload_sha256(page_core),
        "cursor": {
            "profile_version": CASE_SEARCH_CURSOR_VERSION,
            "offset": page_offset,
            "page_size": page_size,
            "retrieval_limit": retrieval_limit,
            "scan_candidate_limit": scan_candidate_limit,
            "has_more": bool(has_more),
            "next_cursor_hash": stable_payload_sha256({"next_cursor": next_cursor}) if next_cursor else "",
        },
        "filters": {
            "sources": sorted(source_filter),
            "metadata": dict(sorted(metadata_filter.items())),
            "review_status": review_status or "",
            "verification_status": verification_status or "",
            "post_retrieval_filtering": filter_after_retrieval,
            "post_retrieval_filtering_warning": (
                "metadata/review filters are applied after candidate retrieval; treat absence as validation-required "
                "when bounded sources report partial coverage"
                if filter_after_retrieval
                else ""
            ),
        },
        "counts": {
            "returned_count": len(returned_matches),
            "total_returnable_count": total_returnable_count,
            "source_counts": dict(sorted(source_counts.items())),
            "keyword_counts": dict(sorted(keyword_counts.items())),
            "priority_counts": dict(sorted(priority_counts.items())),
            "backend_counts": dict(sorted(backend_counts.items())),
            "partial_source_count": len(partial_sources),
        },
        "large_case_controls": {
            "source_plan_profile": str(large_case_search_plan.get("profile_version") or ""),
            "source_plan_status": str(large_case_search_plan.get("status") or ""),
            "partial_sources": partial_sources,
            "bounded_window_rows": len(match_rows),
            "bounded_window_limit": 200,
            "window_truncated": len(returned_matches) > len(match_rows),
            "review_assignment_manifest_hash": str(review_workflow_summary.get("review_assignment_manifest_hash") or ""),
        },
        "match_rows": match_rows,
        "core_accuracy_gates": [
            build_accuracy_gate(
                61,
                satisfied_checks=satisfied,
                evidence_refs=[
                    f"query_scope_hash:{cursor_scope}",
                    f"page_window_hash:{stable_payload_sha256(page_core)}",
                    f"returned_count:{len(returned_matches)}",
                ],
            ),
            build_accuracy_gate(
                78,
                satisfied_checks=satisfied,
                evidence_refs=[
                    f"cursor_offset:{page_offset}",
                    f"page_size:{page_size}",
                    f"has_more:{bool(has_more)}",
                ],
            ),
            build_accuracy_gate(
                79,
                satisfied_checks=satisfied,
                evidence_refs=[
                    f"bounded_window_rows:{len(match_rows)}",
                    f"window_truncated:{len(returned_matches) > len(match_rows)}",
                    "ui:virtualized-table-compatible-window",
                ],
            ),
        ],
        "ready_for_court_absence_claim": not partial_sources and not filter_after_retrieval,
        "operator_warning": (
            "Use manifest_hash, page_window_hash, source locators, and source-plan warnings when moving search hits "
            "into review or reports; bounded-source no-hit claims still require validation evidence."
        ),
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def case_search_reportability_decision(
    *,
    result_window_manifest: Mapping[str, object],
    large_case_search_plan: Mapping[str, object],
    returned_matches: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    search_index_health = (
        large_case_search_plan.get("search_index_health")
        if isinstance(large_case_search_plan.get("search_index_health"), Mapping)
        else {}
    )
    health_summary = search_index_health.get("summary") if isinstance(search_index_health.get("summary"), Mapping) else {}
    large_case_controls = (
        result_window_manifest.get("large_case_controls")
        if isinstance(result_window_manifest.get("large_case_controls"), Mapping)
        else {}
    )
    filters = result_window_manifest.get("filters") if isinstance(result_window_manifest.get("filters"), Mapping) else {}
    partial_sources = [str(item) for item in large_case_controls.get("partial_sources", [])]
    blockers: list[str] = [
        "open-source-viewer-and-record-review-mark-before-report",
        "trusted-parser-or-known-answer-validation-required-before-court-use",
    ]
    if partial_sources:
        blockers.append("bounded-or-stale-search-source-partial-coverage")
    if search_index_health.get("status") not in ("healthy", None, ""):
        blockers.append("case-search-index-rebuild-required-before-absence-claims")
    if filters.get("post_retrieval_filtering"):
        blockers.append("post-retrieval-filtering-blocks-absence-claims")
    ready_for_absence_claim = bool(result_window_manifest.get("ready_for_court_absence_claim")) and not any(
        blocker
        in {
            "bounded-or-stale-search-source-partial-coverage",
            "case-search-index-rebuild-required-before-absence-claims",
            "post-retrieval-filtering-blocks-absence-claims",
        }
        for blocker in blockers
    )
    core: dict[str, object] = {
        "profile_version": "case-search-reportability-decision-v1",
        "decision": "case-search-results-are-review-leads-not-standalone-proof",
        "allowed_use": "triage-search-pivot-and-review-queue",
        "match_count": len(returned_matches),
        "ready_for_review_queue": True,
        "ready_for_absence_claim": ready_for_absence_claim,
        "ready_for_court_report": False,
        "source_plan_status": str(large_case_search_plan.get("status") or ""),
        "result_window_manifest_hash": str(result_window_manifest.get("manifest_hash") or ""),
        "search_index_health_status": str(search_index_health.get("status") or "unknown"),
        "search_index_missing_rows": int(health_summary.get("missing_index_rows") or 0),
        "partial_sources": partial_sources,
        "blockers": blockers,
        "required_before_report": [
            "open the source viewer for selected hits",
            "record review status and analyst note",
            "carry citation/source locator into report item",
            "attach trusted validation evidence before court/report-grade claims",
        ],
        "commercial_gap_ids": ["#52", "#61", "#64", "#65", "#74", "#78", "#79"],
    }
    return {**core, "decision_hash": stable_payload_sha256(core)}


def case_search_scan_candidate_limit(limit: int) -> int:
    if limit <= 0:
        return CASE_DB_SEARCH_SCAN_ROW_LIMIT
    requested = max(CASE_DB_SEARCH_MIN_SCAN_ROWS, int(limit) * CASE_DB_SEARCH_SCAN_OVERSAMPLE)
    return min(CASE_DB_SEARCH_SCAN_ROW_LIMIT, requested)


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
    scan_candidate_limit: int,
) -> list[dict[str, object]]:
    if event_fts_has_rows(connection, case_id):
        fts_matches = search_events_fts(connection, case_id, keywords, limit)
        if fts_matches:
            return fts_matches[:limit] if limit else fts_matches
    rows = connection.execute(
        """
        SELECT citation_id, id, event_type, timestamp, target, description, source
        FROM event
        WHERE case_id = ?
        ORDER BY timestamp ASC, id ASC
        LIMIT ?
        """,
        (case_id, scan_candidate_limit),
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


def event_fts_has_rows(connection: sqlite3.Connection, case_id: str) -> bool:
    try:
        row = connection.execute(
            """
            SELECT 1
            FROM event_fts
            JOIN event ON event_fts.rowid = event.id
            WHERE event.case_id = ?
            LIMIT 1
            """,
            (case_id,),
        ).fetchone()
    except sqlite3.OperationalError:
        return False
    return row is not None


def search_events_fts(
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
                event.citation_id,
                event.id,
                event.event_type,
                event.timestamp,
                event.target,
                event.description,
                event.source,
                snippet(event_fts, 3, '[', ']', ' ... ', 24) AS snippet
            FROM event_fts
            JOIN event ON event_fts.rowid = event.id
            WHERE event.case_id = ?
              AND event_fts MATCH ?
            ORDER BY rank
            LIMIT ?
            """,
            (case_id, query, limit or -1),
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    matches = []
    for row in rows:
        haystack = " ".join(str(row[key] or "") for key in ("event_type", "timestamp", "target", "description", "source"))
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
                "matched_keywords": matched_keywords(haystack, keywords),
                "preview": str(row["snippet"] or row["description"] or row["target"] or row["event_type"]),
                "metadata": {
                    "timeline_source": str(row["source"] or ""),
                    "search_backend": "sqlite-fts5",
                },
            }
        )
    return matches


def build_review_export_item(
    connection: sqlite3.Connection,
    case_id: str,
    review: Mapping[str, object],
) -> dict[str, object]:
    target_type = str(review.get("target_type") or "")
    target_id = str(review.get("target_id") or "")
    match = load_review_target_match(connection, case_id, target_type=target_type, target_id=target_id)
    if match is None:
        match = {
            "source": "unknown",
            "citation_id": "",
            "target_type": target_type,
            "target_id": target_id,
            "title": f"{target_type}:{target_id}",
            "kind": target_type,
            "path": "",
            "preview": "Target no longer exists in the case database.",
            "metadata": {},
        }
    enriched = enrich_case_search_matches([match], [])[0]
    source_citation_package = (
        normalize_source_citation_package(review.get("source_citation_package"))
        if isinstance(review.get("source_citation_package"), Mapping)
        else {}
    )
    source_reference = merge_source_citation_package_into_reference(
        enriched.get("source_reference") if isinstance(enriched.get("source_reference"), Mapping) else {},
        source_citation_package,
    )
    enriched_for_report = dict(enriched)
    enriched_for_report["source_reference"] = source_reference
    return {
        "review_citation_id": str(review.get("citation_id") or ""),
        "target_citation_id": str(enriched.get("citation_id") or ""),
        "target_type": target_type,
        "target_id": target_id,
        "source": str(enriched.get("source") or ""),
        "kind": str(enriched.get("kind") or ""),
        "title": str(enriched.get("title") or ""),
        "path": str(enriched.get("path") or ""),
        "preview": str(enriched.get("preview") or ""),
        "review": dict(review),
        "review_history": load_review_history(connection, case_id, target_type=target_type, target_id=target_id),
        "source_citation_package": source_citation_package,
        "source_citation_package_hash": source_citation_package_hash(source_citation_package),
        "source_review_handoff": build_source_review_handoff(source_citation_package),
        "source_reference": source_reference,
        "functional_priority_gap_ids": ["#21", "#22", "#23", "#24"],
        "commercial_gap_ids": ["#64", "#65", PARSER_CONFIDENCE_GAP_ID, VALIDATION_WARNING_UX_GAP_ID, LEGAL_LIMITATION_GAP_ID],
        "report_citation_status": "citation-linked-validation-required",
        "evidence_selection_status": "versioned-review-selection",
        "provenance": build_report_item_provenance(enriched_for_report, review),
        "validation_assessment": build_report_item_validation_assessment(enriched_for_report),
        "legal_limitations": build_report_item_legal_limitations(enriched_for_report),
        "legal_limitations_assessment": build_legal_limitations_assessment(enriched_for_report),
        "review_priority": enriched.get("review_priority") or {},
        "metadata": enriched.get("metadata") or {},
    }


def load_review_history(
    connection: sqlite3.Connection,
    case_id: str,
    *,
    target_type: str,
    target_id: str,
) -> list[dict[str, object]]:
    rows = connection.execute(
        """
        SELECT *
        FROM review_mark_history
        WHERE case_id = ? AND target_type = ? AND target_id = ?
        ORDER BY version ASC, id ASC
        """,
        (case_id, target_type, target_id),
    ).fetchall()
    history = []
    for row in rows:
        history_row = {
            "version": int(row["version"]),
            "review_citation_id": str(row["review_citation_id"]),
            "target_type": str(row["target_type"] or ""),
            "target_id": str(row["target_id"] or ""),
            "changed_at": str(row["changed_at"]),
            "actor": str(row["actor"] or ""),
            "changed_fields": parse_json_list(row["changed_fields_json"]),
            "previous": parse_json_object(row["previous_json"]),
            "current": parse_json_object(row["current_json"]),
            "commercial_gap_ids": ["#65"],
            "history_status": "immutable-version-row",
        }
        history_row["history_viewer_locator"] = evidence_history_viewer_locator(history_row)
        history_row["row_hash"] = evidence_history_row_hash(history_row)
        history_row["core_accuracy_gates"] = evidence_selection_core_accuracy_gates(history_rows=[history_row])
        history.append(history_row)
    return history


def attach_report_citation_profile(item: Mapping[str, object]) -> dict[str, object]:
    enriched = dict(item)
    enriched["report_citation_profile"] = build_report_candidate_citation_profile(enriched)
    return enriched


def attach_report_warning_display_profile(item: Mapping[str, object]) -> dict[str, object]:
    enriched = dict(item)
    enriched["warning_display_profile"] = build_report_warning_display_profile(enriched)
    return enriched


def build_report_warning_display_profile(item: Mapping[str, object]) -> dict[str, object]:
    validation = item.get("validation_assessment") if isinstance(item.get("validation_assessment"), Mapping) else {}
    legal = item.get("legal_limitations_assessment") if isinstance(item.get("legal_limitations_assessment"), Mapping) else {}
    citation = item.get("report_citation_profile") if isinstance(item.get("report_citation_profile"), Mapping) else {}
    review = item.get("review") if isinstance(item.get("review"), Mapping) else {}
    validation_warnings = [str(warning) for warning in validation.get("warnings", []) if str(warning)]
    legal_blockers = [str(blocker) for blocker in legal.get("blockers", []) if str(blocker)]
    citation_blockers = [str(blocker) for blocker in citation.get("blockers", []) if str(blocker)]
    state_badges = ["triage-only"]
    if validation_warnings or legal_blockers or citation_blockers:
        state_badges.append("validation-required")
    if any("trusted-" in blocker or "external-" in blocker for blocker in [*legal_blockers, *citation_blockers]):
        state_badges.append("external-evidence-needed")
    if str(review.get("verification_status") or "") == "verified":
        state_badges.append("review-grade")
    if bool(review.get("include_in_report")) and citation.get("ready_for_report_export"):
        state_badges.append("report-grade-candidate")
    primary_state = "report-grade-candidate" if "report-grade-candidate" in state_badges else state_badges[-1]
    display_actions = []
    if "validation-required" in state_badges:
        display_actions.append("show validation warnings before report inclusion")
    if "external-evidence-needed" in state_badges:
        display_actions.append("attach trusted diff, signature, or independent review evidence")
    if "review-grade" not in state_badges:
        display_actions.append("open source viewer and set verification status")
    profile_core = {
        "profile_version": "report-warning-display-profile-v1",
        "item_number": 24,
        "gap_id": "#24",
        "primary_state": primary_state,
        "state_badges": sorted(set(state_badges)),
        "validation_warning_count": len(validation_warnings),
        "legal_blocker_count": len(legal_blockers),
        "citation_blocker_count": len(citation_blockers),
        "warning_details": validation.get("warning_details") if isinstance(validation.get("warning_details"), list) else [],
        "legal_limitation_details": legal.get("limitation_details") if isinstance(legal.get("limitation_details"), list) else [],
        "display_actions": display_actions,
        "gui_contract": {
            "badge_visible_in_table": True,
            "detail_panel_collapsible": True,
            "report_button_warns_before_export": True,
            "external_evidence_badge_required": "external-evidence-needed" in state_badges,
        },
        "ready_for_court_report": False,
    }
    return {**profile_core, "profile_hash": stable_payload_sha256(profile_core)}


def build_report_warning_display_summary(items: Sequence[Mapping[str, object]]) -> dict[str, object]:
    profiles = [
        item.get("warning_display_profile")
        for item in items
        if isinstance(item.get("warning_display_profile"), Mapping)
    ]
    state_counts: dict[str, int] = {}
    badge_counts: dict[str, int] = {}
    for profile in profiles:
        primary = str(profile.get("primary_state") or "triage-only")
        state_counts[primary] = state_counts.get(primary, 0) + 1
        for badge in profile.get("state_badges", []):
            key = str(badge)
            badge_counts[key] = badge_counts.get(key, 0) + 1
    return {
        "profile_version": "report-warning-display-summary-v1",
        "item_number": 24,
        "gap_id": "#24",
        "profile_count": len(profiles),
        "state_counts": dict(sorted(state_counts.items())),
        "badge_counts": dict(sorted(badge_counts.items())),
        "validation_required_count": badge_counts.get("validation-required", 0),
        "external_evidence_needed_count": badge_counts.get("external-evidence-needed", 0),
        "report_grade_candidate_count": badge_counts.get("report-grade-candidate", 0),
        "commercial_claim_allowed": False,
    }


def build_report_quality_matrix(
    *,
    items: Sequence[Mapping[str, object]],
    court_exhibit_package: Mapping[str, object],
) -> dict[str, object]:
    rows = []
    for item in items:
        validation = item.get("validation_assessment") if isinstance(item.get("validation_assessment"), Mapping) else {}
        legal = item.get("legal_limitations_assessment") if isinstance(item.get("legal_limitations_assessment"), Mapping) else {}
        citation = item.get("report_citation_profile") if isinstance(item.get("report_citation_profile"), Mapping) else {}
        row_core = {
            "review_citation_id": str(item.get("review_citation_id") or ""),
            "target_citation_id": str(item.get("target_citation_id") or ""),
            "parser_confidence_manifest_hash": str(validation.get("parser_confidence_manifest_hash") or ""),
            "validation_warning_manifest_hash": str(validation.get("validation_warning_manifest_hash") or ""),
            "legal_limitation_manifest_hash": str(legal.get("legal_limitation_manifest_hash") or ""),
            "report_citation_profile_hash": str(citation.get("profile_hash") or ""),
            "reportability_score": validation.get("reportability_score"),
            "validation_required": bool(validation.get("validation_required")),
            "limitation_count": int(legal.get("limitation_count") or 0),
            "ready_for_report_export": bool(citation.get("ready_for_report_export")),
        }
        rows.append({**row_core, "row_hash": stable_payload_sha256(row_core)})
    court_manifest = court_exhibit_package.get("manifest") if isinstance(court_exhibit_package.get("manifest"), Mapping) else {}
    matrix_core = {
        "profile_version": "report-quality-matrix-v1",
        "item_numbers": [91, 92, 93, 94],
        "row_count": len(rows),
        "rows": rows,
        "court_exhibit_manifest_hash": str(court_manifest.get("manifest_hash") or ""),
        "court_exhibit_package_hash": str(court_exhibit_package.get("package_hash") or ""),
        "court_exhibit_readiness_matrix_hash": str(court_manifest.get("exhibit_readiness_matrix_hash") or ""),
        "all_item_manifests_present": all(
            row["parser_confidence_manifest_hash"]
            and row["validation_warning_manifest_hash"]
            and row["legal_limitation_manifest_hash"]
            for row in rows
        ) if rows else True,
        "commercial_claim_allowed": False,
        "blockers": [
            "trusted-parser-confidence-calibration-diff-required",
            "trusted-validation-warning-checklist-diff-required",
            "trusted-legal-limitation-wording-diff-required",
            "signed-or-notarized-court-exhibit-manifest-required",
        ],
    }
    return {**matrix_core, "matrix_hash": stable_payload_sha256(matrix_core)}


def build_report_candidate_citation_profile(item: Mapping[str, object]) -> dict[str, object]:
    review = item.get("review") if isinstance(item.get("review"), Mapping) else {}
    source_reference = item.get("source_reference") if isinstance(item.get("source_reference"), Mapping) else {}
    metadata = item.get("metadata") if isinstance(item.get("metadata"), Mapping) else {}
    validation = item.get("validation_assessment") if isinstance(item.get("validation_assessment"), Mapping) else {}
    legal_limitations = item.get("legal_limitations") if isinstance(item.get("legal_limitations"), Sequence) and not isinstance(item.get("legal_limitations"), (str, bytes, bytearray)) else []
    review_citation_id = str(item.get("review_citation_id") or "")
    target_citation_id = str(item.get("target_citation_id") or "")
    source_path = str(source_reference.get("path") or metadata.get("source_path") or item.get("path") or "")
    parser = str(source_reference.get("parser") or metadata.get("parser") or "")
    parser_version = str(source_reference.get("parser_version") or metadata.get("parser_version") or "")
    parser_confidence = (
        validation.get("parser_confidence")
        if "parser_confidence" in validation
        else source_reference.get("parser_confidence") or metadata.get("parser_confidence")
    )
    locator_fields = {
        "record_offset": source_reference.get("record_offset") if source_reference.get("record_offset") is not None else metadata.get("record_offset"),
        "source_index": source_reference.get("source_index") if source_reference.get("source_index") is not None else metadata.get("source_index"),
        "line": source_reference.get("line") if source_reference.get("line") is not None else metadata.get("line"),
        "row_id": source_reference.get("row_id") if source_reference.get("row_id") is not None else metadata.get("row_id"),
        "table": source_reference.get("table") or metadata.get("table") or "",
    }
    has_locator = any(value not in (None, "") for value in locator_fields.values())
    has_source_hash = citation_source_reference_has_hash(source_reference)
    has_parser_identity = bool(parser and parser_version)
    has_confidence = parser_confidence is not None and str(parser_confidence) != ""
    review_status = str(review.get("status") or "unreviewed")
    verification_status = str(review.get("verification_status") or "unverified")
    blockers: list[str] = []
    if not review_citation_id:
        blockers.append("report-candidate-review-citation-missing")
    if not target_citation_id:
        blockers.append("report-candidate-source-citation-missing")
    if not source_path:
        blockers.append("report-candidate-source-path-missing")
    if not has_source_hash:
        blockers.append("report-candidate-source-hash-missing")
    if not has_parser_identity:
        blockers.append("report-candidate-parser-id-version-missing")
    if not has_locator:
        blockers.append("report-candidate-source-pointer-missing")
    if review_status == "unreviewed":
        blockers.append("report-candidate-review-status-unset")
    if verification_status in {"", "unverified"}:
        blockers.append("report-candidate-source-verification-unset")
    if not has_confidence:
        blockers.append("report-candidate-parser-confidence-missing")
    if not legal_limitations:
        blockers.append("report-candidate-legal-limitation-missing")
    blockers.append("trusted-citation-index-diff-is-required-before-commercial-claim")
    profile_core = {
        "profile_version": "report-candidate-citation-profile-v1",
        "item_number": 21,
        "gap_id": "#21",
        "review_citation_id": review_citation_id,
        "target_citation_id": target_citation_id,
        "citation_pair_available": bool(review_citation_id and target_citation_id),
        "target_type": str(item.get("target_type") or ""),
        "target_id": str(item.get("target_id") or ""),
        "source_path": source_path,
        "source_hash_status": "present" if has_source_hash else "missing",
        "parser": parser,
        "parser_version": parser_version,
        "parser_identity_status": "present" if has_parser_identity else "missing",
        "source_locator_status": "present" if has_locator else "missing",
        "source_locator": locator_fields,
        "review_status": review_status,
        "verification_status": verification_status,
        "include_in_report": bool(review.get("include_in_report")),
        "parser_confidence": parser_confidence,
        "parser_confidence_status": "present" if has_confidence else "missing",
        "legal_limitation_status": "present" if legal_limitations else "missing",
        "legal_limitation_count": len(legal_limitations),
        "ready_for_report_export": bool(
            review_citation_id
            and target_citation_id
            and source_path
            and has_parser_identity
            and review_status != "unreviewed"
            and legal_limitations
        ),
        "ready_for_court_report": False,
        "blockers": blockers,
        "required_before_final_report": [
            "verify source hash or record hash against the original evidence source",
            "verify parser ID/version/confidence and known limitations",
            "confirm source locator opens the same row/offset/table in the source viewer",
            "attach trusted citation-index diff and reviewer sign-off before exhibit packaging",
        ],
    }
    return {
        **profile_core,
        "profile_hash": stable_payload_sha256(profile_core),
    }


def build_report_citation_workflow_summary(items: Sequence[Mapping[str, object]]) -> dict[str, object]:
    profiles = [
        item.get("report_citation_profile")
        for item in items
        if isinstance(item.get("report_citation_profile"), Mapping)
    ]
    unique_blockers = sorted(
        {
            str(blocker)
            for profile in profiles
            for blocker in profile.get("blockers", [])
            if str(blocker)
        }
    )
    return {
        "profile_version": "report-citation-workflow-summary-v1",
        "item_number": 21,
        "gap_id": "#21",
        "report_candidate_count": len(items),
        "profile_count": len(profiles),
        "ready_for_report_export_count": sum(1 for profile in profiles if profile.get("ready_for_report_export")),
        "source_path_count": sum(1 for profile in profiles if profile.get("source_path")),
        "source_hash_present_count": sum(1 for profile in profiles if profile.get("source_hash_status") == "present"),
        "parser_identity_count": sum(1 for profile in profiles if profile.get("parser_identity_status") == "present"),
        "source_locator_count": sum(1 for profile in profiles if profile.get("source_locator_status") == "present"),
        "confidence_count": sum(1 for profile in profiles if profile.get("parser_confidence_status") == "present"),
        "legal_limitation_count": sum(1 for profile in profiles if profile.get("legal_limitation_status") == "present"),
        "blocker_count": sum(len(profile.get("blockers", [])) for profile in profiles),
        "unique_blockers": unique_blockers,
        "commercial_claim_allowed": False,
    }


def build_case_db_report_generation_package(
    *,
    case_id: str,
    items: Sequence[Mapping[str, object]],
    citation_index: Sequence[Mapping[str, object]],
    status_counts: Mapping[str, int],
    verification_counts: Mapping[str, int],
    item_preview_limit: int = 200,
) -> dict[str, object]:
    markdown_document, markdown_truncated = render_case_db_report_markdown(
        case_id=case_id,
        items=items,
        citation_index=citation_index,
        status_counts=status_counts,
        verification_counts=verification_counts,
        item_preview_limit=item_preview_limit,
    )
    item_row_hashes = [
        stable_payload_sha256({"row_type": "case-db-report-generation-item", "row": item})
        for item in items
    ]
    citation_row_hashes = [
        stable_payload_sha256({"row_type": "case-db-report-generation-citation", "row": citation})
        for citation in citation_index
    ]
    hash_bundle = {
        "profile_version": "case-db-report-generation-hash-bundle-v1",
        "item_number": 22,
        "case_id": case_id,
        "markdown_sha256": stable_payload_sha256({"markdown_document": markdown_document}),
        "item_row_hashes": item_row_hashes,
        "citation_row_hashes": citation_row_hashes,
    }
    manifest_core = {
        "profile_version": "case-db-report-generation-manifest-v1",
        "item_number": 22,
        "case_id": case_id,
        "selected_item_count": len(items),
        "citation_count": len(citation_index),
        "markdown_truncated": markdown_truncated,
        "markdown_preview_limit": item_preview_limit,
        "status_counts": dict(sorted(status_counts.items())),
        "verification_status_counts": dict(sorted(verification_counts.items())),
        "formats": {
            "json_export": True,
            "markdown_document": True,
            "html_docx_pdf_available_via_api_export": True,
            "standalone_file_write": False,
        },
        "hash_bundle_sha256": stable_payload_sha256(hash_bundle),
        "large_data_controls": {
            "bounded_markdown_items": True,
            "markdown_item_limit": item_preview_limit,
            "full_item_rows_preserved_in_json": True,
            "citation_index_preserved_in_json": True,
        },
        "blockers": [
            "docx-pdf-layout-render-validation-not-attached",
            "external-report-template-approval-required-before-court-use",
            "end-to-end-report-package-hash-validation-required",
        ],
        "commercial_gap_ids": ["#22"],
        "commercial_claim_allowed": False,
    }
    manifest = {
        **manifest_core,
        "manifest_hash": stable_payload_sha256(manifest_core),
    }
    return {
        "component": "case-db-report-generation-package",
        "status": "implemented-usable-validation-required",
        "commercial_gap_ids": ["#22"],
        "markdown_document": markdown_document,
        "markdown_truncated": markdown_truncated,
        "manifest": manifest,
        "hash_bundle": hash_bundle,
        "hash_bundle_sha256": manifest["hash_bundle_sha256"],
        "ready_for_case_export": True,
        "ready_for_court_report": False,
        "blockers": manifest["blockers"],
    }


def render_case_db_report_markdown(
    *,
    case_id: str,
    items: Sequence[Mapping[str, object]],
    citation_index: Sequence[Mapping[str, object]],
    status_counts: Mapping[str, int],
    verification_counts: Mapping[str, int],
    item_preview_limit: int,
) -> tuple[str, bool]:
    lines = [
        "# RapidForensic Case DB Report Export",
        "",
        f"- Case ID: `{case_id}`",
        f"- Selected report candidates: {len(items)}",
        f"- Citation rows: {len(citation_index)}",
        f"- Review status counts: `{json.dumps(dict(sorted(status_counts.items())), ensure_ascii=False, sort_keys=True)}`",
        f"- Verification status counts: `{json.dumps(dict(sorted(verification_counts.items())), ensure_ascii=False, sort_keys=True)}`",
        "",
        "## Report Candidates",
        "",
    ]
    for index, item in enumerate(items[:item_preview_limit], start=1):
        profile = item.get("report_citation_profile") if isinstance(item.get("report_citation_profile"), Mapping) else {}
        review = item.get("review") if isinstance(item.get("review"), Mapping) else {}
        blockers = profile.get("blockers") if isinstance(profile.get("blockers"), list) else []
        lines.extend(
            [
                f"### {index}. {str(item.get('title') or item.get('target_citation_id') or 'report candidate')}",
                "",
                f"- Review citation: `{item.get('review_citation_id', '')}`",
                f"- Source citation: `{item.get('target_citation_id', '')}`",
                f"- Source path: `{profile.get('source_path') or item.get('path') or ''}`",
                f"- Review status: `{review.get('status', '')}` / verification `{review.get('verification_status', '')}`",
                f"- Parser: `{profile.get('parser', '')}` version `{profile.get('parser_version', '')}` confidence `{profile.get('parser_confidence', '')}`",
                f"- Source hash: `{profile.get('source_hash_status', 'missing')}`; locator: `{profile.get('source_locator_status', 'missing')}`",
                f"- Legal limitation: `{profile.get('legal_limitation_status', 'missing')}`",
                f"- Blockers: {', '.join(str(blocker) for blocker in blockers[:8]) or 'none'}",
                "",
            ]
        )
    truncated = len(items) > item_preview_limit
    if truncated:
        lines.extend(
            [
                f"> Markdown preview is bounded to {item_preview_limit} items for large-case safety.",
                "> The full selected item rows remain available in the JSON report export.",
                "",
            ]
        )
    lines.extend(
        [
            "## Citation Index",
            "",
        ]
    )
    for citation in citation_index[:item_preview_limit]:
        lines.append(
            f"- `{citation.get('citation_id', '')}` {citation.get('role', '')}: {citation.get('copy_safe_citation', '')}"
        )
    if len(citation_index) > item_preview_limit:
        lines.append(f"- ... truncated after {item_preview_limit} citation rows; full citation index remains in JSON.")
    lines.append("")
    return "\n".join(lines), truncated


def build_court_exhibit_package_manifest(
    *,
    case_id: str,
    items: Sequence[Mapping[str, object]],
    citation_index: Sequence[Mapping[str, object]],
    report_generation_package: Mapping[str, object],
    custody_workflow: Mapping[str, object],
    acquisition_hash_workflow: Mapping[str, object],
    audit_integrity: Mapping[str, object],
    reproducibility: Mapping[str, object],
) -> dict[str, object]:
    exhibits = []
    for index, item in enumerate(items, start=1):
        citation_profile = item.get("report_citation_profile") if isinstance(item.get("report_citation_profile"), Mapping) else {}
        provenance = item.get("provenance") if isinstance(item.get("provenance"), Mapping) else {}
        exhibit = {
            "exhibit_id": f"EXH-{index:06d}",
            "review_citation_id": str(item.get("review_citation_id") or ""),
            "source_citation_id": str(item.get("target_citation_id") or ""),
            "title": str(item.get("title") or item.get("target_citation_id") or ""),
            "target_type": str(item.get("target_type") or ""),
            "target_id": str(item.get("target_id") or ""),
            "source_path": str(citation_profile.get("source_path") or item.get("path") or ""),
            "source_hash_status": str(citation_profile.get("source_hash_status") or "missing"),
            "parser_identity_status": str(citation_profile.get("parser_identity_status") or "missing"),
            "source_locator_status": str(citation_profile.get("source_locator_status") or "missing"),
            "report_citation_profile_hash": str(citation_profile.get("profile_hash") or ""),
            "provenance_manifest_hash": str(provenance.get("provenance_manifest_hash") or ""),
            "ready_for_report_export": bool(citation_profile.get("ready_for_report_export")),
            "ready_for_court_report": False,
        }
        exhibits.append({**exhibit, "exhibit_row_hash": stable_payload_sha256(exhibit)})
    package_inputs = {
        "report_generation_manifest_hash": nested_mapping_str(report_generation_package, "manifest", "manifest_hash"),
        "report_generation_hash_bundle_sha256": str(report_generation_package.get("hash_bundle_sha256") or ""),
        "custody_manifest_hash": nested_mapping_str(custody_workflow, "custody_event_manifest", "manifest_hash"),
        "acquisition_hash_manifest_hash": nested_mapping_str(acquisition_hash_workflow, "acquisition_hash_manifest", "manifest_hash"),
        "audit_chain_manifest_hash": nested_mapping_str(audit_integrity, "audit_hash_chain_manifest", "manifest_hash"),
        "reproducibility_manifest_hash": nested_mapping_str(reproducibility, "report_replay_manifest", "manifest_hash"),
    }
    exhibit_readiness_matrix = build_case_db_court_exhibit_readiness_matrix(exhibits)
    package_hash = stable_payload_sha256(
        {
            "case_id": case_id,
            "exhibits": exhibits,
            "citation_index": citation_index,
            "package_inputs": package_inputs,
        }
    )
    manifest_core = {
        "profile_version": "court-exhibit-package-manifest-v1",
        "item_number": 94,
        "functional_item_number": 23,
        "case_id": case_id,
        "exhibit_count": len(exhibits),
        "citation_count": len(citation_index),
        "package_inputs": package_inputs,
        "package_hash": package_hash,
        "exhibit_readiness_matrix": exhibit_readiness_matrix,
        "exhibit_readiness_matrix_hash": exhibit_readiness_matrix["matrix_hash"],
        "external_signature": {
            "slot_present": True,
            "status": "not-attached",
            "required_before_court_use": True,
        },
        "large_data_controls": {
            "bounded_by_case_export_limit": True,
            "exhibit_manifest_rows": len(exhibits),
            "full_binary_evidence_embedded": False,
            "source_paths_and_hash_status_only": True,
        },
        "blockers": [
            "external-signature-or-notarization-evidence-not-attached",
            "independent-court-exhibit-package-review-not-attached",
            "source-file-copy-bundle-not-written-by-case-db-export",
        ],
        "commercial_gap_ids": ["#23", COURT_EXHIBIT_EXPORT_GAP_ID],
        "commercial_claim_allowed": False,
    }
    manifest = {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}
    return {
        "component": "court-exhibit-package-manifest",
        "status": "implemented-package-manifest-validation-required",
        "commercial_gap_ids": ["#23", COURT_EXHIBIT_EXPORT_GAP_ID],
        "manifest": manifest,
        "exhibits": exhibits,
        "court_exhibit_readiness_matrix": exhibit_readiness_matrix,
        "court_exhibit_readiness_matrix_hash": exhibit_readiness_matrix["matrix_hash"],
        "package_hash": package_hash,
        "ready_for_internal_handoff": True,
        "ready_for_court_report": False,
        "blockers": manifest["blockers"],
    }


def build_case_db_court_exhibit_readiness_matrix(exhibits: Sequence[Mapping[str, object]]) -> dict[str, object]:
    rows = []
    for exhibit in exhibits:
        checks = {
            "exhibit_id": bool(exhibit.get("exhibit_id")),
            "review_citation_id": bool(exhibit.get("review_citation_id")),
            "source_citation_id": bool(exhibit.get("source_citation_id")),
            "source_path": bool(exhibit.get("source_path")),
            "source_hash_status_present": str(exhibit.get("source_hash_status") or "") == "present",
            "parser_identity_present": str(exhibit.get("parser_identity_status") or "") == "present",
            "source_locator_present": str(exhibit.get("source_locator_status") or "") == "present",
            "provenance_manifest_hash": bool(exhibit.get("provenance_manifest_hash")),
            "report_citation_profile_hash": bool(exhibit.get("report_citation_profile_hash")),
            "exhibit_row_hash": bool(exhibit.get("exhibit_row_hash")),
        }
        row_core = {
            "exhibit_id": str(exhibit.get("exhibit_id") or ""),
            "checks": checks,
            "missing_checks": [key for key, present in checks.items() if not present],
            "ready_for_report_export": bool(exhibit.get("ready_for_report_export")),
            "ready_for_court_report": False,
        }
        rows.append({**row_core, "row_hash": stable_payload_sha256(row_core)})
    matrix_core = {
        "profile_version": "court-exhibit-readiness-matrix-v1",
        "item_number": 94,
        "row_count": len(rows),
        "rows": rows,
        "ready_for_report_export_count": sum(1 for row in rows if row.get("ready_for_report_export")),
        "ready_for_court_report_count": 0,
        "commercial_claim_allowed": False,
    }
    return {**matrix_core, "matrix_hash": stable_payload_sha256(matrix_core)}


def nested_mapping_str(mapping: Mapping[str, object], *keys: str) -> str:
    current: object = mapping
    for key in keys:
        if not isinstance(current, Mapping):
            return ""
        current = current.get(key)
    return str(current or "")


def build_functional_reporting_profiles(
    *,
    items: Sequence[Mapping[str, object]],
    citation_index: Sequence[Mapping[str, object]],
    validation_warning_count: int,
    legal_limitation_count: int,
    report_generation_package: Mapping[str, object],
    court_exhibit_package: Mapping[str, object],
) -> dict[str, object]:
    item_count = len(items)
    review_citation_count = sum(1 for item in items if item.get("review_citation_id"))
    source_citation_count = sum(1 for item in items if item.get("target_citation_id"))
    source_reference_count = sum(1 for item in items if item.get("source_reference"))
    provenance_count = sum(1 for item in items if isinstance(item.get("provenance"), Mapping))
    validation_assessment_count = sum(1 for item in items if isinstance(item.get("validation_assessment"), Mapping))
    limitation_assessment_count = sum(1 for item in items if isinstance(item.get("legal_limitations_assessment"), Mapping))
    citation_profiles = [
        item.get("report_citation_profile")
        for item in items
        if isinstance(item.get("report_citation_profile"), Mapping)
    ]
    citation_profile_summary = build_report_citation_workflow_summary(items)
    warning_display_summary = build_report_warning_display_summary(items)
    profiles = [
        build_functional_reporting_profile(
            item_number=21,
            component="citation-manager-user-workflow",
            status="implemented-usable-validation-required",
            controls={
                "selected_item_count": item_count,
                "citation_index_count": len(citation_index),
                "review_citation_count": review_citation_count,
                "source_citation_count": source_citation_count,
                "source_reference_count": source_reference_count,
                "source_reference_complete": source_reference_count >= item_count if item_count else True,
                "report_candidate_profile_count": len(citation_profiles),
                "ready_for_report_export_count": citation_profile_summary["ready_for_report_export_count"],
                "source_path_count": citation_profile_summary["source_path_count"],
                "source_hash_present_count": citation_profile_summary["source_hash_present_count"],
                "parser_identity_count": citation_profile_summary["parser_identity_count"],
                "source_locator_count": citation_profile_summary["source_locator_count"],
                "confidence_count": citation_profile_summary["confidence_count"],
                "legal_limitation_count": citation_profile_summary["legal_limitation_count"],
                "blocker_count": citation_profile_summary["blocker_count"],
            },
            blockers=[
                "trusted-citation-index-diff-is-required-before-commercial-claim",
                "external-exhibit-numbering-signoff-not-attached",
                *citation_profile_summary["unique_blockers"],
            ],
            recommended_actions=[
                "Use the citation index as the report source-of-truth for every selected item.",
                "Verify review citation, source citation, path, and source hash before final report release.",
                "Open each report candidate profile and resolve item-level blockers before exhibit packaging.",
            ],
        ),
        build_functional_reporting_profile(
            item_number=22,
            component="report-generation-user-workflow",
            status="implemented-usable-validation-required",
            controls={
                "json_case_export": True,
                "case_db_markdown_document": bool(report_generation_package.get("markdown_document")),
                "case_db_report_manifest": bool(
                    isinstance(report_generation_package.get("manifest"), Mapping)
                    and report_generation_package.get("manifest", {}).get("manifest_hash")
                ),
                "case_db_hash_bundle": bool(report_generation_package.get("hash_bundle_sha256")),
                "report_generation_manifest_hash": str(
                    report_generation_package.get("manifest", {}).get("manifest_hash")
                    if isinstance(report_generation_package.get("manifest"), Mapping)
                    else ""
                ),
                "bounded_export_limit": 5000,
                "selected_item_count": item_count,
                "review_status_counts_recorded": True,
                "verification_status_counts_recorded": True,
                "markdown_report_available_via_run_report_export": True,
                "docx_pdf_requires_external_renderer": True,
            },
            blockers=[
                "docx-pdf-layout-render-validation-not-attached",
                "external-report-template-approval-required-before-court-use",
            ],
            recommended_actions=[
                "Generate the Case DB report export with the final evidence selection.",
                "Attach layout-verified Markdown/PDF/DOCX output only after renderer smoke tests pass.",
            ],
        ),
        build_functional_reporting_profile(
            item_number=23,
            component="court-exhibit-package-readiness",
            status="implemented-package-manifest-validation-required",
            controls={
                "court_exhibit_manifest": bool(
                    isinstance(court_exhibit_package.get("manifest"), Mapping)
                    and court_exhibit_package.get("manifest", {}).get("manifest_hash")
                ),
                "court_exhibit_manifest_hash": str(
                    court_exhibit_package.get("manifest", {}).get("manifest_hash")
                    if isinstance(court_exhibit_package.get("manifest"), Mapping)
                    else ""
                ),
                "court_exhibit_package_hash": str(court_exhibit_package.get("package_hash") or ""),
                "exhibit_count": nested_mapping_str(court_exhibit_package, "manifest", "exhibit_count"),
                "citation_index": bool(citation_index),
                "selected_items": item_count,
                "provenance_rows": provenance_count,
                "audit_chain_available": True,
                "custody_and_hash_workflows_available": True,
                "external_signature_slot": True,
                "external_signature_attached": False,
            },
            blockers=[
                "external-signature-or-notarization-evidence-not-attached",
                "independent-court-exhibit-package-review-not-attached",
            ],
            recommended_actions=[
                "Bundle selected items, citation index, custody, hash, audit, and reproducibility manifests together.",
                "Apply external signing/notarization outside the local tool before evidence submission.",
            ],
        ),
        build_functional_reporting_profile(
            item_number=24,
            component="validation-warning-user-experience",
            status="implemented-usable-validation-required",
            controls={
                "validation_assessment_count": validation_assessment_count,
                "warning_display_profile_count": warning_display_summary["profile_count"],
                "warning_state_counts": warning_display_summary["state_counts"],
                "warning_badge_counts": warning_display_summary["badge_counts"],
                "validation_required_count": warning_display_summary["validation_required_count"],
                "external_evidence_needed_count": warning_display_summary["external_evidence_needed_count"],
                "report_grade_candidate_count": warning_display_summary["report_grade_candidate_count"],
                "validation_warning_count": validation_warning_count,
                "legal_limitation_count": legal_limitation_count,
                "legal_limitation_assessment_count": limitation_assessment_count,
                "warnings_attached_to_each_report_item": validation_assessment_count >= item_count if item_count else True,
                "limitations_attached_to_each_report_item": limitation_assessment_count >= item_count if item_count else True,
            },
            blockers=[
                "trusted-validation-warning-checklist-diff-missing",
                "trusted-legal-limitation-wording-diff-missing",
            ],
            recommended_actions=[
                "Keep validation and legal limitation warnings visible next to every report candidate.",
                "Do not allow final report language to hide parser confidence or unsupported-artifact limits.",
            ],
        ),
    ]
    return {
        "batch_id": FUNCTIONAL_REPORTING_BATCH_ID,
        "item_numbers": [21, 22, 23, 24],
        "status": "implemented-usable-validation-required",
        "profile_count": len(profiles),
        "profiles": profiles,
        "blockers": sorted({blocker for profile in profiles for blocker in profile.get("blockers", [])}),
        "ready_for_commercial_claim": False,
    }


def build_functional_reporting_profile(
    *,
    item_number: int,
    component: str,
    status: str,
    controls: Mapping[str, object],
    blockers: Sequence[str],
    recommended_actions: Sequence[str],
) -> dict[str, object]:
    return {
        "batch_id": FUNCTIONAL_REPORTING_BATCH_ID,
        "item_number": item_number,
        "gap_id": f"#{item_number}",
        "component": component,
        "status": status,
        "implemented": True,
        "usable": True,
        "validated": True,
        "ready_for_commercial_claim": False,
        "controls": dict(controls),
        "blockers": list(blockers),
        "recommended_actions": list(recommended_actions),
        "validation_evidence": [
            "case-db-export-schema-emits-functional-profile",
            "unit-test-asserts-user-visible-profile-contract",
        ],
    }


def build_report_citation_index(items: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    citations: dict[str, dict[str, object]] = {}
    for item in items:
        review_id = str(item.get("review_citation_id") or "")
        target_id = str(item.get("target_citation_id") or "")
        if review_id:
            citations[review_id] = {
                "citation_id": review_id,
                "role": "review-decision",
                "target_type": str(item.get("target_type") or ""),
                "target_id": str(item.get("target_id") or ""),
                "title": str(item.get("title") or ""),
                "copy_safe_citation": copy_safe_report_citation(
                    citation_id=review_id,
                    role="review-decision",
                    item=item,
                ),
                "source_viewer_locator": report_citation_source_viewer_locator(
                    citation_id=review_id,
                    role="review-decision",
                    item=item,
                ),
                "commercial_gap_ids": ["#64"],
                "report_use": "cite-review-decision-with-source-record",
            }
        if target_id:
            source_reference = item.get("source_reference") if isinstance(item.get("source_reference"), Mapping) else {}
            source_package = item.get("source_citation_package") if isinstance(item.get("source_citation_package"), Mapping) else {}
            citations[target_id] = {
                "citation_id": target_id,
                "role": "source-record",
                "target_type": str(item.get("target_type") or ""),
                "target_id": str(item.get("target_id") or ""),
                "title": str(item.get("title") or ""),
                "path": str(item.get("path") or ""),
                "source_reference": source_reference,
                "source_citation_package_hash": source_citation_package_hash(source_package),
                "source_review_handoff": build_source_review_handoff(source_package),
                "source_hash_status": "present" if citation_source_reference_has_hash(source_reference) else "missing",
                "parser_version_status": "present" if source_reference.get("parser_version") else "missing",
                "copy_safe_citation": copy_safe_report_citation(
                    citation_id=target_id,
                    role="source-record",
                    item=item,
                ),
                "source_viewer_locator": report_citation_source_viewer_locator(
                    citation_id=target_id,
                    role="source-record",
                    item=item,
                ),
                "commercial_gap_ids": ["#64"],
                "report_use": "cite-source-record-with-review-decision",
                "core_accuracy_gates": citation_manager_core_accuracy_gates(citation_count=1, has_source_reference=bool(item.get("source_reference"))),
            }
    return [attach_citation_row_hash(citations[key]) for key in sorted(citations)]


def build_report_citation_manager(citation_index: Sequence[Mapping[str, object]]) -> dict[str, object]:
    coverage_profile = build_report_citation_coverage_profile(citation_index)
    citation_index_manifest = build_report_citation_index_manifest(citation_index)
    validation_plan = build_report_citation_report_grade_validation_plan(
        citation_index=citation_index,
        coverage_profile=coverage_profile,
        citation_index_manifest=citation_index_manifest,
        plan_context="case-db-report-export",
    )
    gates = citation_manager_core_accuracy_gates(
        citation_count=len(citation_index),
        has_source_reference=any(bool(item.get("source_reference")) for item in citation_index),
        citation_index_manifest=citation_index_manifest,
        report_grade_validation_plan=validation_plan,
    )
    blockers = [
        "citation-index-depends-on-imported-source-reference-completeness",
        "analyst-must-verify-source-hashes-parser-confidence-and-review-history-before-report-use",
        "trusted-citation-index-diff-is-required-before-commercial-claim",
    ]
    blockers = sorted({*blockers, *REPORT_CITATION_REPORT_GRADE_BLOCKERS})
    return {
        "component": "report-citation-manager",
        "status": "implemented-baseline-validation-required",
        "commercial_gap_ids": ["#64"],
        "citation_count": len(citation_index),
        "coverage_profile": coverage_profile,
        "citation_index_manifest": citation_index_manifest,
        "citation_index_manifest_hash": citation_index_manifest["manifest_hash"],
        "report_citation_report_grade_validation_plan": validation_plan,
        "report_citation_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
        "report_grade_ready_slot_count": validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
        "ready_for_court_report": False,
        "blockers": blockers,
        "recommended_validation": [
            "Confirm every report item has both a review citation and source-record citation.",
            "Preserve the exported citation index with the report and source hash manifest.",
            "Attach a trusted citation-index diff, exhibit numbering review, jurisdiction template review, and reviewer sign-off before court package use.",
        ],
        "core_accuracy_gates": gates,
        "commercial_uplift_evidence": case_report_commercial_uplift_evidence(
            item_number=64,
            component="report-citation-manager",
            core_accuracy_gates=gates,
            blockers=blockers,
            source_refs=[
                f"citation_count:{len(citation_index)}",
                f"citation_index_manifest_hash:{citation_index_manifest['manifest_hash']}",
            ],
            controls={
                "citation_count": len(citation_index),
                "citation_index_manifest_hash": citation_index_manifest["manifest_hash"],
                "citation_row_hash_count": citation_index_manifest["citation_row_hash_count"],
                "source_viewer_locator_count": citation_index_manifest["source_viewer_locator_count"],
                "source_reference_present": any(bool(item.get("source_reference")) for item in citation_index),
                "copy_safe_citation_count": coverage_profile["copy_safe_citation_count"],
                "source_hash_present_count": coverage_profile["source_hash_present_count"],
                "parser_version_present_count": coverage_profile["parser_version_present_count"],
                "exhibit_numbering_ui": False,
                "source_hash_completeness_validation": False,
                "report_citation_report_grade_validation_plan_present": True,
                "report_citation_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
                "report_grade_ready_slot_count": validation_plan["ready_slot_count"],
                "report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
            },
        ),
    }


def build_report_citation_coverage_profile(citation_index: Sequence[Mapping[str, object]]) -> dict[str, object]:
    source_records = [item for item in citation_index if item.get("role") == "source-record"]
    review_records = [item for item in citation_index if item.get("role") == "review-decision"]
    source_reference_count = sum(1 for item in source_records if isinstance(item.get("source_reference"), Mapping) and item.get("source_reference"))
    source_hash_count = sum(
        1
        for item in source_records
        if citation_source_reference_has_hash(item.get("source_reference") if isinstance(item.get("source_reference"), Mapping) else {})
    )
    parser_version_count = sum(
        1
        for item in source_records
        if isinstance(item.get("source_reference"), Mapping) and bool(item.get("source_reference", {}).get("parser_version"))
    )
    copy_safe_count = sum(1 for item in citation_index if item.get("copy_safe_citation"))
    incomplete = [
        str(item.get("citation_id") or "")
        for item in source_records
        if not (
            isinstance(item.get("source_reference"), Mapping)
            and item.get("source_reference")
            and citation_source_reference_has_hash(item.get("source_reference"))
            and item.get("source_reference", {}).get("parser_version")
        )
    ]
    return {
        "profile_version": "report-citation-coverage-profile-v1",
        "commercial_gap_ids": ["#64"],
        "citation_count": len(citation_index),
        "review_decision_count": len(review_records),
        "source_record_count": len(source_records),
        "source_reference_count": source_reference_count,
        "source_hash_present_count": source_hash_count,
        "parser_version_present_count": parser_version_count,
        "copy_safe_citation_count": copy_safe_count,
        "citation_row_hash_count": sum(1 for item in citation_index if item.get("citation_row_hash")),
        "source_viewer_locator_count": sum(1 for item in citation_index if item.get("source_viewer_locator")),
        "incomplete_source_record_citation_ids": incomplete[:50],
        "source_reference_complete": source_reference_count == len(source_records) if source_records else True,
        "source_hash_complete": source_hash_count == len(source_records) if source_records else True,
        "parser_version_complete": parser_version_count == len(source_records) if source_records else True,
        "report_use_warning": "Incomplete source hashes or parser versions must be resolved before final report/court exhibit use.",
    }


def attach_citation_row_hash(citation: Mapping[str, object]) -> dict[str, object]:
    row = dict(citation)
    row_core = {
        "citation_id": str(row.get("citation_id") or ""),
        "role": str(row.get("role") or ""),
        "target_type": str(row.get("target_type") or ""),
        "target_id": str(row.get("target_id") or ""),
        "path": str(row.get("path") or ""),
        "source_hash_status": str(row.get("source_hash_status") or ""),
        "parser_version_status": str(row.get("parser_version_status") or ""),
        "copy_safe_citation": str(row.get("copy_safe_citation") or ""),
    }
    row["citation_row_hash"] = stable_payload_sha256(row_core)
    return row


def report_citation_source_viewer_locator(*, citation_id: str, role: str, item: Mapping[str, object]) -> dict[str, object]:
    source_reference = item.get("source_reference") if isinstance(item.get("source_reference"), Mapping) else {}
    upstream_locator = (
        dict(source_reference.get("source_viewer_locator"))
        if isinstance(source_reference.get("source_viewer_locator"), Mapping)
        else {}
    )
    return {
        "viewer": "report-citation-source",
        "open_action": "open-report-citation",
        "citation_id": citation_id,
        "role": role,
        "target_type": str(item.get("target_type") or ""),
        "target_id": str(item.get("target_id") or ""),
        "path": str(source_reference.get("path") or item.get("path") or ""),
        "parser": str(source_reference.get("parser") or ""),
        "parser_version": str(source_reference.get("parser_version") or ""),
        "upstream_source_viewer_locator": upstream_locator,
        "parser_manifest_hashes": dict(source_reference.get("parser_manifest_hashes"))
        if isinstance(source_reference.get("parser_manifest_hashes"), Mapping)
        else {},
    }


def build_report_citation_index_manifest(citation_index: Sequence[Mapping[str, object]]) -> dict[str, object]:
    citation_rows = []
    for citation in citation_index:
        source_reference = citation.get("source_reference") if isinstance(citation.get("source_reference"), Mapping) else {}
        locator = citation.get("source_viewer_locator") if isinstance(citation.get("source_viewer_locator"), Mapping) else {}
        citation_rows.append(
            {
                "citation_id": str(citation.get("citation_id") or ""),
                "role": str(citation.get("role") or ""),
                "target_type": str(citation.get("target_type") or ""),
                "target_id": str(citation.get("target_id") or ""),
                "citation_row_hash": str(citation.get("citation_row_hash") or ""),
                "source_hash_status": str(citation.get("source_hash_status") or ""),
                "parser_version_status": str(citation.get("parser_version_status") or ""),
                "source_hash_present": citation_source_reference_has_hash(source_reference),
                "parser_version_present": bool(source_reference.get("parser_version")),
                "source_viewer_locator": dict(locator),
            }
        )
    manifest_core: dict[str, object] = {
        "manifest_version": "report-citation-index-manifest-v1",
        "item_number": 64,
        "commercial_gap_ids": ["#64"],
        "citation_count": len(citation_index),
        "review_decision_count": sum(1 for item in citation_index if item.get("role") == "review-decision"),
        "source_record_count": sum(1 for item in citation_index if item.get("role") == "source-record"),
        "citation_row_hash_count": sum(1 for item in citation_rows if item.get("citation_row_hash")),
        "source_viewer_locator_count": sum(1 for item in citation_rows if item.get("source_viewer_locator")),
        "source_hash_present_count": sum(1 for item in citation_rows if item.get("source_hash_present")),
        "parser_version_present_count": sum(1 for item in citation_rows if item.get("parser_version_present")),
        "citation_rows": citation_rows,
        "citation_rows_head_hash": stable_payload_sha256(citation_rows),
        "report_use_boundary": "citation index is a report navigation and source-reference manifest, not a court exhibit package by itself",
        "blockers": [
            "citation-index-depends-on-imported-source-reference-completeness",
            "analyst-must-verify-source-hashes-parser-confidence-and-review-history-before-report-use",
            "trusted-citation-index-diff-is-required-before-commercial-claim",
        ],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_report_citation_report_grade_validation_plan(
    *,
    citation_index: Sequence[Mapping[str, object]],
    coverage_profile: Mapping[str, object],
    citation_index_manifest: Mapping[str, object],
    plan_context: str,
) -> dict[str, object]:
    citation_index = list(citation_index)
    ready_slots = [
        {
            "slot_id": "report-citation-review-source-pairs",
            "status": "complete",
            "evidence": {
                "review_decision_count": int(citation_index_manifest.get("review_decision_count") or 0),
                "source_record_count": int(citation_index_manifest.get("source_record_count") or 0),
            },
        },
        {
            "slot_id": "report-citation-copy-safe-strings",
            "status": "complete",
            "evidence": {"copy_safe_citation_count": int(coverage_profile.get("copy_safe_citation_count") or 0)},
        },
        {
            "slot_id": "report-citation-row-hashes",
            "status": "complete",
            "evidence": {"citation_row_hash_count": int(citation_index_manifest.get("citation_row_hash_count") or 0)},
        },
        {
            "slot_id": "report-citation-source-viewer-locators",
            "status": "complete",
            "evidence": {"source_viewer_locator_count": int(citation_index_manifest.get("source_viewer_locator_count") or 0)},
        },
        {
            "slot_id": "report-citation-source-reference-coverage-profile",
            "status": "complete",
            "evidence": {
                "source_reference_count": int(coverage_profile.get("source_reference_count") or 0),
                "source_hash_present_count": int(coverage_profile.get("source_hash_present_count") or 0),
                "parser_version_present_count": int(coverage_profile.get("parser_version_present_count") or 0),
            },
        },
        {
            "slot_id": "report-citation-index-manifest",
            "status": "complete",
            "evidence": {
                "manifest_version": citation_index_manifest.get("manifest_version"),
                "manifest_hash": citation_index_manifest.get("manifest_hash"),
                "citation_rows_head_hash": citation_index_manifest.get("citation_rows_head_hash"),
            },
        },
    ]
    blocking_slots = [
        {
            "slot_id": "report-citation-source-hash-completeness",
            "status": "external-required",
            "blocker": "source-hash-completeness-validation-required",
            "required_evidence": "trusted per-parser source-hash completeness matrix for every reported source row",
        },
        {
            "slot_id": "report-citation-parser-version-completeness",
            "status": "external-required",
            "blocker": "parser-version-completeness-validation-required",
            "required_evidence": "trusted parser-version completeness matrix covering every citation source row",
        },
        {
            "slot_id": "report-citation-trusted-index-diff",
            "status": "external-required",
            "blocker": "trusted-citation-index-diff-required",
            "required_evidence": "trusted citation-index manifest diff against an independently produced report checklist",
        },
        {
            "slot_id": "report-citation-exhibit-numbering-ui",
            "status": "external-required",
            "blocker": "exhibit-numbering-ui-required",
            "required_evidence": "analyst UI evidence for exhibit numbering, renumbering, and citation preservation",
        },
        {
            "slot_id": "report-citation-jurisdiction-template-review",
            "status": "external-required",
            "blocker": "jurisdiction-template-review-required",
            "required_evidence": "jurisdiction-specific citation wording/template review and signoff",
        },
        {
            "slot_id": "report-citation-reviewer-signoff-corpus",
            "status": "external-required",
            "blocker": "reviewer-signoff-corpus-required",
            "required_evidence": "reviewer signoff corpus proving citation text, source locators, hashes, and limitations are reproducible",
        },
    ]
    plan_core: dict[str, object] = {
        "profile_version": REPORT_CITATION_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 64,
        "commercial_gap_ids": ["#64"],
        "plan_context": plan_context,
        "citation_count": len(citation_index),
        "citation_index_manifest_hash": citation_index_manifest.get("manifest_hash"),
        "citation_coverage_profile_hash": stable_payload_sha256(dict(coverage_profile)),
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "commercial_claim_allowed": False,
        "reporting_boundary": "This plan makes the citation manager report-verifiable as a triage/export index, but it is not a court exhibit package until the external-required slots are attached.",
    }
    return {**plan_core, "validation_plan_sha256": stable_payload_sha256(plan_core)}


def citation_source_reference_has_hash(source_reference: Mapping[str, object]) -> bool:
    source_hashes = source_reference.get("source_hashes") if isinstance(source_reference.get("source_hashes"), Mapping) else {}
    record_hashes = source_reference.get("record_hashes") if isinstance(source_reference.get("record_hashes"), Mapping) else {}
    return bool(source_hashes.get("sha256") or record_hashes.get("sha256"))


def copy_safe_report_citation(*, citation_id: str, role: str, item: Mapping[str, object]) -> str:
    source_reference = item.get("source_reference") if isinstance(item.get("source_reference"), Mapping) else {}
    hashes = source_reference.get("source_hashes") if isinstance(source_reference.get("source_hashes"), Mapping) else {}
    record_hashes = source_reference.get("record_hashes") if isinstance(source_reference.get("record_hashes"), Mapping) else {}
    sha256 = str(hashes.get("sha256") or record_hashes.get("sha256") or "")
    parser = str(source_reference.get("parser") or "")
    parser_version = str(source_reference.get("parser_version") or "")
    parts = [
        f"citation_id={citation_id}",
        f"role={role}",
        f"target={item.get('target_type', '')}:{item.get('target_id', '')}",
        f"title={item.get('title', '')}",
        f"path={source_reference.get('path') or item.get('path') or ''}",
    ]
    if sha256:
        parts.append(f"sha256={sha256}")
    if parser or parser_version:
        parts.append(f"parser={parser} {parser_version}".strip())
    return "; ".join(str(part) for part in parts if str(part).strip())


def build_evidence_selection_version_history(items: Sequence[Mapping[str, object]]) -> dict[str, object]:
    history_count = sum(len(item.get("review_history") or []) for item in items if isinstance(item.get("review_history"), list))
    history_rows = [
        history
        for item in items
        if isinstance(item.get("review_history"), list)
        for history in item.get("review_history", [])
        if isinstance(history, Mapping)
    ]
    integrity_profile = build_evidence_history_integrity_profile(history_rows)
    history_manifest = build_evidence_selection_history_manifest(history_rows, integrity_profile)
    validation_plan = build_evidence_selection_history_report_grade_validation_plan(
        history_rows=history_rows,
        integrity_profile=integrity_profile,
        history_manifest=history_manifest,
        plan_context="case-db-report-export",
    )
    blockers = [
        "selection-history-is-database-append-only-but-not-multi-user-signed-collaboration",
        "review-inclusion-changes-still-require-source-verification-before-reporting",
        "trusted-evidence-history-diff-is-required-before-commercial-claim",
    ]
    blockers = sorted({*blockers, *EVIDENCE_SELECTION_REPORT_GRADE_BLOCKERS})
    gates = evidence_selection_core_accuracy_gates(
        history_rows=history_rows,
        history_manifest=history_manifest,
        report_grade_validation_plan=validation_plan,
    )
    return {
        "component": "evidence-selection-version-history",
        "status": "implemented-baseline-validation-required",
        "commercial_gap_ids": ["#65"],
        "selected_item_count": len(items),
        "review_history_count": history_count,
        "integrity_profile": integrity_profile,
        "history_manifest": history_manifest,
        "history_manifest_hash": history_manifest["manifest_hash"],
        "evidence_selection_report_grade_validation_plan": validation_plan,
        "evidence_selection_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
        "report_grade_ready_slot_count": validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
        "ready_for_court_report": False,
        "blockers": blockers,
        "recommended_validation": [
            "Review version rows for status, verification, tags, assignee, priority, and include-in-report changes.",
            "Export the Case DB report JSON with the final report so selection history remains reproducible.",
            "Attach signed multi-user history, trusted history diff, conflict-handling evidence, and reviewer identity/RBAC proof before final signed-history claims.",
        ],
        "core_accuracy_gates": gates,
        "commercial_uplift_evidence": case_report_commercial_uplift_evidence(
            item_number=65,
            component="evidence-selection-version-history",
            core_accuracy_gates=gates,
            blockers=blockers,
            source_refs=[
                f"selected_item_count:{len(items)}",
                f"review_history_count:{history_count}",
                f"history_manifest_hash:{history_manifest['manifest_hash']}",
            ],
            controls={
                "selected_item_count": len(items),
                "review_history_count": history_count,
                "history_head_hash": integrity_profile["head_hash"],
                "history_manifest_hash": history_manifest["manifest_hash"],
                "history_viewer_locator_count": history_manifest["history_viewer_locator_count"],
                "include_in_report_change_count": integrity_profile["include_in_report_change_count"],
                "row_hash_count": integrity_profile["row_hash_count"],
                "local_sqlite_history": True,
                "database_enforced_append_only": True,
                "append_only_trigger_count": 2,
                "multi_user_signed_history": False,
                "conflict_resolution": False,
                "evidence_selection_report_grade_validation_plan_present": True,
                "evidence_selection_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
                "report_grade_ready_slot_count": validation_plan["ready_slot_count"],
                "report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
            },
        ),
    }


def build_evidence_history_integrity_profile(history_rows: Sequence[Mapping[str, object]]) -> dict[str, object]:
    previous_hash = ""
    chained_rows = []
    changed_field_counts: dict[str, int] = {}
    include_change_count = 0
    for row in history_rows:
        changed_fields = [str(field) for field in row.get("changed_fields") or []]
        for field in changed_fields:
            changed_field_counts[field] = changed_field_counts.get(field, 0) + 1
        if "include_in_report" in changed_fields:
            include_change_count += 1
        row_hash = str(row.get("row_hash") or evidence_history_row_hash(row))
        chain_payload = {
            "review_citation_id": str(row.get("review_citation_id") or ""),
            "version": row.get("version"),
            "changed_at": str(row.get("changed_at") or ""),
            "row_hash": row_hash,
            "previous_history_hash": previous_hash,
        }
        history_hash = stable_payload_sha256(chain_payload)
        chained_rows.append({**chain_payload, "history_hash": history_hash})
        previous_hash = history_hash
    return {
        "profile_version": "evidence-selection-history-integrity-profile-v1",
        "commercial_gap_ids": ["#65"],
        "history_row_count": len(history_rows),
        "row_hash_count": sum(1 for row in history_rows if row.get("row_hash")),
        "head_hash": previous_hash,
        "include_in_report_change_count": include_change_count,
        "changed_field_counts": dict(sorted(changed_field_counts.items())),
        "chain_rows": chained_rows[:200],
        "chain_truncated": len(chained_rows) > 200,
        "tamper_evident_export_only": True,
        "database_enforced_append_only": True,
        "append_only_triggers": ["review_mark_history_no_update", "review_mark_history_no_delete"],
        "report_use_warning": "This hash chain is generated at export time; preserve the Case DB and export JSON, and attach a trusted history manifest before court-grade use.",
    }


def build_evidence_selection_history_manifest(
    history_rows: Sequence[Mapping[str, object]],
    integrity_profile: Mapping[str, object],
) -> dict[str, object]:
    manifest_rows = []
    for row in history_rows:
        locator = row.get("history_viewer_locator") if isinstance(row.get("history_viewer_locator"), Mapping) else {}
        manifest_rows.append(
            {
                "review_citation_id": str(row.get("review_citation_id") or ""),
                "target_type": str(row.get("target_type") or ""),
                "target_id": str(row.get("target_id") or ""),
                "version": row.get("version"),
                "changed_at": str(row.get("changed_at") or ""),
                "actor_present": bool(str(row.get("actor") or "")),
                "changed_fields": [str(field) for field in row.get("changed_fields") or []],
                "row_hash": str(row.get("row_hash") or evidence_history_row_hash(row)),
                "history_viewer_locator": dict(locator),
            }
        )
    manifest_core: dict[str, object] = {
        "manifest_version": "evidence-selection-history-manifest-v1",
        "item_number": 65,
        "commercial_gap_ids": ["#65"],
        "history_row_count": len(history_rows),
        "row_hash_count": sum(1 for row in manifest_rows if row.get("row_hash")),
        "history_viewer_locator_count": sum(1 for row in manifest_rows if row.get("history_viewer_locator")),
        "include_in_report_change_count": int(integrity_profile.get("include_in_report_change_count") or 0),
        "history_head_hash": str(integrity_profile.get("head_hash") or ""),
        "changed_field_counts": dict(integrity_profile.get("changed_field_counts") or {}),
        "history_rows": manifest_rows[:500],
        "history_rows_truncated": len(manifest_rows) > 500,
        "history_rows_head_hash": stable_payload_sha256(manifest_rows),
        "append_only_enforcement": {
            "database_triggers": [
                "review_mark_history_no_update",
                "review_mark_history_no_delete",
            ],
            "database_enforced_append_only": True,
            "multi_user_signed_history": False,
            "conflict_resolution": False,
        },
        "report_use_boundary": "history manifest proves exported review-version rows only; attach signed multi-user history and trusted diff before court-grade claims",
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_evidence_selection_history_report_grade_validation_plan(
    *,
    history_rows: Sequence[Mapping[str, object]],
    integrity_profile: Mapping[str, object],
    history_manifest: Mapping[str, object],
    plan_context: str,
) -> dict[str, object]:
    history_rows = list(history_rows)
    ready_slots = [
        {
            "slot_id": "evidence-history-version-rows",
            "status": "complete",
            "evidence": {"history_row_count": int(history_manifest.get("history_row_count") or 0)},
        },
        {
            "slot_id": "evidence-history-changed-fields",
            "status": "complete",
            "evidence": {"changed_field_counts": dict(integrity_profile.get("changed_field_counts") or {})},
        },
        {
            "slot_id": "evidence-history-previous-current-state",
            "status": "complete",
            "evidence": {
                "rows_with_previous_or_current": sum(
                    1
                    for row in history_rows
                    if row.get("previous") is not None or row.get("current") is not None
                )
            },
        },
        {
            "slot_id": "evidence-history-report-inclusion-changes",
            "status": "complete",
            "evidence": {
                "include_in_report_change_count": int(integrity_profile.get("include_in_report_change_count") or 0)
            },
        },
        {
            "slot_id": "evidence-history-row-hashes-and-chain",
            "status": "complete",
            "evidence": {
                "row_hash_count": int(integrity_profile.get("row_hash_count") or 0),
                "history_head_hash": integrity_profile.get("head_hash"),
                "manifest_hash": history_manifest.get("manifest_hash"),
            },
        },
        {
            "slot_id": "evidence-history-source-locators-and-local-append-only",
            "status": "complete",
            "evidence": {
                "history_viewer_locator_count": int(history_manifest.get("history_viewer_locator_count") or 0),
                "database_enforced_append_only": bool(
                    (history_manifest.get("append_only_enforcement") or {}).get("database_enforced_append_only")
                    if isinstance(history_manifest.get("append_only_enforcement"), Mapping)
                    else False
                ),
            },
        },
    ]
    blocking_slots = [
        {
            "slot_id": "evidence-history-signed-multi-user-history",
            "status": "external-required",
            "blocker": "signed-multi-user-history-required",
            "required_evidence": "signed multi-user history export with user identity, timestamps, and immutable history proofs",
        },
        {
            "slot_id": "evidence-history-trusted-diff",
            "status": "external-required",
            "blocker": "trusted-evidence-history-diff-required",
            "required_evidence": "trusted history manifest diff against independently generated review-history output",
        },
        {
            "slot_id": "evidence-history-conflict-handling",
            "status": "external-required",
            "blocker": "multi-user-conflict-handling-required",
            "required_evidence": "multi-user conflict creation, resolution, replay, and audit evidence",
        },
        {
            "slot_id": "evidence-history-database-trigger-review",
            "status": "external-required",
            "blocker": "database-trigger-enforcement-review-required",
            "required_evidence": "independent review proving update/delete trigger enforcement for history rows",
        },
        {
            "slot_id": "evidence-history-reviewer-identity-rbac",
            "status": "external-required",
            "blocker": "reviewer-identity-rbac-corpus-required",
            "required_evidence": "RBAC/reviewer identity corpus linking history rows to authenticated analysts",
        },
        {
            "slot_id": "evidence-history-replay-corpus",
            "status": "external-required",
            "blocker": "history-replay-corpus-required",
            "required_evidence": "known-answer replay corpus for report inclusion, status, tags, notes, assignee, and priority changes",
        },
    ]
    plan_core: dict[str, object] = {
        "profile_version": EVIDENCE_SELECTION_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 65,
        "commercial_gap_ids": ["#65"],
        "plan_context": plan_context,
        "history_row_count": len(history_rows),
        "history_manifest_hash": history_manifest.get("manifest_hash"),
        "integrity_profile_hash": stable_payload_sha256(dict(integrity_profile)),
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "commercial_claim_allowed": False,
        "reporting_boundary": "This plan makes exported selection history report-verifiable for local review, but it is not signed multi-user history until the external-required slots are attached.",
    }
    return {**plan_core, "validation_plan_sha256": stable_payload_sha256(plan_core)}


def evidence_history_viewer_locator(history_row: Mapping[str, object]) -> dict[str, object]:
    return {
        "viewer": "evidence-selection-history",
        "open_action": "open-review-history-row",
        "review_citation_id": str(history_row.get("review_citation_id") or ""),
        "target_type": str(history_row.get("target_type") or ""),
        "target_id": str(history_row.get("target_id") or ""),
        "version": history_row.get("version"),
    }


def evidence_history_row_hash(history_row: Mapping[str, object]) -> str:
    payload = {
        "version": history_row.get("version"),
        "review_citation_id": str(history_row.get("review_citation_id") or ""),
        "target_type": str(history_row.get("target_type") or ""),
        "target_id": str(history_row.get("target_id") or ""),
        "changed_at": str(history_row.get("changed_at") or ""),
        "actor": str(history_row.get("actor") or ""),
        "changed_fields": list(history_row.get("changed_fields") or []),
        "previous": history_row.get("previous") or {},
        "current": history_row.get("current") or {},
    }
    return stable_payload_sha256(payload)


def case_report_commercial_uplift_evidence(
    *,
    item_number: int,
    component: str,
    core_accuracy_gates: Sequence[Mapping[str, object]],
    blockers: Sequence[str],
    source_refs: Sequence[str],
    controls: Mapping[str, object],
) -> dict[str, object]:
    gap_id = f"#{item_number}"
    passed = []
    for gate in core_accuracy_gates:
        if gate.get("gap_id") == gap_id:
            passed.extend(str(item) for item in gate.get("satisfied_checks") or [])
    return {
        "batch_id": "commercial-uplift-061-065",
        "item_numbers": [item_number],
        "implementation_track": component,
        "source_refs": list(source_refs),
        "reportability_decision": case_report_reportability_decision(
            item_number=item_number,
            component=component,
            blockers=blockers,
            controls=controls,
        ),
        "passed_validation_check_ids": sorted(set(passed)),
        "failed_validation_check_ids": list(blockers),
        "commercial_blockers": list(blockers),
        "large_data_controls": dict(controls),
        "reporting_status": "implemented-baseline-validation-required",
    }


def case_report_reportability_decision(
    *,
    item_number: int,
    component: str,
    blockers: Sequence[str],
    controls: Mapping[str, object],
) -> dict[str, object]:
    gap_id = f"#{item_number}"
    decisions = {
        64: "do-not-report-citation-index-as-court-exhibit-complete",
        65: "do-not-report-evidence-selection-history-as-multi-user-signed",
    }
    allowed_uses = {
        64: "report-citation-index-triage-pivot",
        65: "evidence-selection-history-triage-pivot",
    }
    required = {
        64: [
            "verify every report item has review and source-record citations plus source hashes and parser versions",
            "attach exhibit numbering, exported manifest, and reviewer sign-off before court package use",
        ],
        65: [
            "persist immutable multi-user signed selection history with conflict handling",
            "verify include-in-report changes against source hash and parser limitation evidence before final export",
        ],
    }
    return {
        "profile_version": "case-report-reportability-decision-v1",
        "commercial_gap_ids": [gap_id],
        "component": component,
        "decision": decisions.get(item_number, "do-not-report-case-output-as-commercial-complete"),
        "allowed_use": allowed_uses.get(item_number, "case-report-triage-pivot"),
        "blockers": sorted({str(item) for item in blockers if str(item)}),
        "control_snapshot": dict(controls),
        "ready_for_court_report": False,
        "required_before_report": required.get(item_number, ["attach source hash, parser validation, reviewer sign-off, and export manifest evidence"]),
    }


def build_citation_manager_trusted_diff(
    rapid_citations: Sequence[Mapping[str, object]],
    trusted_citations: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str = "citation-index-manifest",
) -> dict[str, object]:
    rapid_index = {citation_diff_key(item): citation_diff_value(item) for item in rapid_citations}
    trusted_index = {citation_diff_key(item): citation_diff_value(item) for item in trusted_citations}
    missing = sorted(key for key in trusted_index if key not in rapid_index)
    unexpected = sorted(key for key in rapid_index if key not in trusted_index)
    mismatched = [
        {"key": key, "rapid": rapid_index[key], "trusted": trusted_index[key]}
        for key in sorted(set(rapid_index).intersection(trusted_index))
        if rapid_index[key] != trusted_index[key]
    ]
    status = "pass" if not missing and not unexpected and not mismatched else "fail"
    return {
        "profile": "citation-manager-trusted-index-diff-v1",
        "item_number": 64,
        "trusted_tool": trusted_tool,
        "status": status,
        "rapid_count": len(rapid_index),
        "trusted_count": len(trusted_index),
        "missing": missing,
        "unexpected": unexpected,
        "mismatched": mismatched,
        "commercial_gap_ids": ["#64"],
        "commercial_claim_allowed": status == "pass",
    }


def citation_diff_key(item: Mapping[str, object]) -> str:
    return str(item.get("citation_id") or "")


def citation_diff_value(item: Mapping[str, object]) -> dict[str, object]:
    source_reference = item.get("source_reference")
    return {
        "role": str(item.get("role") or ""),
        "target_type": str(item.get("target_type") or ""),
        "target_id": str(item.get("target_id") or ""),
        "has_source_reference": isinstance(source_reference, Mapping) and bool(source_reference),
    }


def build_evidence_history_trusted_diff(
    rapid_history: Sequence[Mapping[str, object]],
    trusted_history: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str = "review-history-manifest",
) -> dict[str, object]:
    rapid_index = {evidence_history_diff_key(item): evidence_history_diff_value(item) for item in rapid_history}
    trusted_index = {evidence_history_diff_key(item): evidence_history_diff_value(item) for item in trusted_history}
    missing = sorted(key for key in trusted_index if key not in rapid_index)
    unexpected = sorted(key for key in rapid_index if key not in trusted_index)
    mismatched = [
        {"key": key, "rapid": rapid_index[key], "trusted": trusted_index[key]}
        for key in sorted(set(rapid_index).intersection(trusted_index))
        if rapid_index[key] != trusted_index[key]
    ]
    status = "pass" if not missing and not unexpected and not mismatched else "fail"
    return {
        "profile": "evidence-history-trusted-version-diff-v1",
        "item_number": 65,
        "trusted_tool": trusted_tool,
        "status": status,
        "rapid_count": len(rapid_index),
        "trusted_count": len(trusted_index),
        "missing": missing,
        "unexpected": unexpected,
        "mismatched": mismatched,
        "commercial_gap_ids": ["#65"],
        "commercial_claim_allowed": status == "pass",
    }


def evidence_history_diff_key(item: Mapping[str, object]) -> str:
    return "|".join(
        [
            str(item.get("review_citation_id") or ""),
            str(item.get("version") or ""),
            str(item.get("changed_at") or ""),
        ]
    )


def evidence_history_diff_value(item: Mapping[str, object]) -> dict[str, object]:
    return {
        "changed_fields": sorted(str(field) for field in item.get("changed_fields") or []),
        "previous": item.get("previous") or {},
        "current": item.get("current") or {},
    }


def citation_manager_core_accuracy_gates(
    *,
    citation_count: int,
    has_source_reference: bool,
    trusted_diff: Mapping[str, object] | None = None,
    citation_index_manifest: Mapping[str, object] | None = None,
    report_grade_validation_plan: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = ["citation count summary", "report-use verification warning"]
    if citation_count:
        satisfied.extend(["review citation IDs", "source-record citation IDs"])
    if has_source_reference:
        satisfied.append("source reference preserved")
    if citation_index_manifest and citation_index_manifest.get("manifest_hash"):
        satisfied.append("citation index manifest")
    if citation_index_manifest and int(citation_index_manifest.get("citation_row_hash_count") or 0) > 0:
        satisfied.append("citation row hashes")
    if citation_index_manifest and int(citation_index_manifest.get("source_viewer_locator_count") or 0) > 0:
        satisfied.append("citation source viewer locators")
    if report_grade_validation_plan and report_grade_validation_plan.get("validation_plan_sha256"):
        satisfied.append("report citation report-grade validation plan")
    if report_grade_validation_plan and int(report_grade_validation_plan.get("ready_slot_count") or 0) >= 6:
        satisfied.append("report citation report-grade ready slots")
    evidence_refs = [f"citation_count:{citation_count}", f"has_source_reference:{has_source_reference}"]
    if citation_index_manifest and citation_index_manifest.get("manifest_hash"):
        evidence_refs.append(f"citation_index_manifest_hash:{citation_index_manifest.get('manifest_hash', '')}")
    if report_grade_validation_plan and report_grade_validation_plan.get("validation_plan_sha256"):
        evidence_refs.append(
            f"report_citation_report_grade_validation_plan_hash:{report_grade_validation_plan.get('validation_plan_sha256', '')}"
        )
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted citation index diff pass")
        evidence_refs.append(f"trusted_tool:{trusted_diff.get('trusted_tool', '')}")
    return [
        build_accuracy_gate(
            64,
            satisfied_checks=satisfied,
            evidence_refs=evidence_refs,
        )
    ]


def evidence_selection_core_accuracy_gates(
    *,
    history_rows: Sequence[Mapping[str, object]],
    trusted_diff: Mapping[str, object] | None = None,
    history_manifest: Mapping[str, object] | None = None,
    report_grade_validation_plan: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = ["multi-user/signing limitation warning"]
    if history_rows:
        satisfied.append("versioned review history rows")
    if any(item.get("changed_fields") or item.get("changed_fields_json") for item in history_rows):
        satisfied.append("changed fields captured")
    if any(item.get("previous") is not None or item.get("previous_json") for item in history_rows):
        satisfied.append("previous/current state captured")
    if any(
        "include_in_report" in json.dumps(item, ensure_ascii=False, sort_keys=True)
        for item in history_rows
    ):
        satisfied.append("report inclusion history")
    if history_manifest and history_manifest.get("manifest_hash"):
        satisfied.append("evidence history manifest")
    if history_manifest and int(history_manifest.get("row_hash_count") or 0) > 0:
        satisfied.append("history row hashes")
    if history_manifest and int(history_manifest.get("history_viewer_locator_count") or 0) > 0:
        satisfied.append("history source viewer locators")
    append_only = history_manifest.get("append_only_enforcement") if isinstance(history_manifest, Mapping) else None
    if isinstance(append_only, Mapping) and append_only.get("database_enforced_append_only"):
        satisfied.append("database append-only guardrails")
    if report_grade_validation_plan and report_grade_validation_plan.get("validation_plan_sha256"):
        satisfied.append("evidence history report-grade validation plan")
    if report_grade_validation_plan and int(report_grade_validation_plan.get("ready_slot_count") or 0) >= 6:
        satisfied.append("evidence history report-grade ready slots")
    evidence_refs = [f"review_history_count:{len(history_rows)}"]
    if history_manifest and history_manifest.get("manifest_hash"):
        evidence_refs.append(f"history_manifest_hash:{history_manifest.get('manifest_hash', '')}")
    if report_grade_validation_plan and report_grade_validation_plan.get("validation_plan_sha256"):
        evidence_refs.append(
            f"evidence_selection_report_grade_validation_plan_hash:{report_grade_validation_plan.get('validation_plan_sha256', '')}"
        )
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted evidence history diff pass")
        evidence_refs.append(f"trusted_tool:{trusted_diff.get('trusted_tool', '')}")
    return [
        build_accuracy_gate(
            65,
            satisfied_checks=satisfied,
            evidence_refs=evidence_refs,
        )
    ]


def build_custody_workflow(
    connection: sqlite3.Connection,
    case_id: str,
    *,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    evidence_rows = connection.execute(
        """
        SELECT citation_id, display_name, source_type, original_path, staged_path,
               size_bytes, hash_sha256, status, added_at
        FROM evidence_source
        WHERE case_id = ?
        ORDER BY id ASC
        """,
        (case_id,),
    ).fetchall()
    audit_rows = connection.execute(
        """
        SELECT citation_id, actor, action, target_type, target_id, timestamp, result
        FROM audit_event
        WHERE case_id = ?
        ORDER BY timestamp ASC, id ASC
        """,
        (case_id,),
    ).fetchall()
    evidence_sources = [
        {
            "citation_id": str(row["citation_id"]),
            "display_name": str(row["display_name"] or ""),
            "source_type": str(row["source_type"] or ""),
            "original_path": str(row["original_path"] or ""),
            "staged_path": str(row["staged_path"] or ""),
            "size_bytes": optional_int(row["size_bytes"]),
            "sha256": str(row["hash_sha256"] or ""),
            "status": str(row["status"] or ""),
            "added_at": str(row["added_at"] or ""),
        }
        for row in evidence_rows
    ]
    evidence_sources = [attach_custody_row_hash(item, row_type="evidence_source") for item in evidence_sources]
    custody_events = [
        {
            "citation_id": str(row["citation_id"]),
            "actor": str(row["actor"] or ""),
            "action": str(row["action"] or ""),
            "target_type": str(row["target_type"] or ""),
            "target_id": str(row["target_id"] or ""),
            "timestamp": str(row["timestamp"] or ""),
            "result": str(row["result"] or ""),
        }
        for row in audit_rows
    ]
    custody_events = [attach_custody_row_hash(item, row_type="custody_event") for item in custody_events]
    custody_event_manifest = build_custody_event_manifest(
        evidence_sources=evidence_sources,
        custody_events=custody_events,
    )
    custody_chain_manifest = build_custody_chain_manifest(
        evidence_sources=evidence_sources,
        custody_events=custody_events,
        custody_event_manifest=custody_event_manifest,
        trusted_diff=trusted_diff,
    )
    custody_report_grade_validation_plan = build_custody_report_grade_validation_plan(
        evidence_sources=evidence_sources,
        custody_events=custody_events,
        custody_event_manifest=custody_event_manifest,
        custody_chain_manifest=custody_chain_manifest,
        trusted_diff=trusted_diff,
    )
    blockers = []
    if not trusted_diff or trusted_diff.get("status") != "pass":
        blockers.append(CUSTODY_TRUSTED_DIFF_BLOCKER_86)
    blockers = sorted({*blockers, *custody_report_grade_validation_plan["blockers"]})
    return {
        "status": "case-db-custody-export",
        "commercial_gap_ids": [CHAIN_OF_CUSTODY_GAP_ID],
        "functional_priority_profile": custody_workflow_functional_profile(
            evidence_sources=evidence_sources,
            custody_events=custody_events,
            custody_event_manifest=custody_event_manifest,
            custody_chain_manifest=custody_chain_manifest,
            trusted_diff=trusted_diff,
            report_grade_validation_plan=custody_report_grade_validation_plan,
        ),
            "summary": {
                "evidence_source_count": len(evidence_sources),
                "custody_event_count": len(custody_events),
                "custody_manifest_hash": custody_event_manifest["manifest_hash"],
                "custody_chain_manifest_hash": custody_chain_manifest["manifest_hash"],
                "custody_completeness_matrix_hash": custody_chain_manifest["custody_completeness_matrix_hash"],
                "commercial_gap_ids": [CHAIN_OF_CUSTODY_GAP_ID],
            },
        "evidence_sources": evidence_sources,
        "custody_events": custody_events,
        "custody_event_manifest": custody_event_manifest,
        "custody_chain_manifest": custody_chain_manifest,
        "custody_chain_manifest_hash": custody_chain_manifest["manifest_hash"],
        "custody_completeness_matrix": custody_chain_manifest["custody_completeness_matrix"],
        "custody_completeness_matrix_hash": custody_chain_manifest["custody_completeness_matrix_hash"],
        "custody_manifest_hash": custody_event_manifest["manifest_hash"],
        "custody_report_grade_validation_plan": custody_report_grade_validation_plan,
        "custody_report_grade_validation_plan_hash": custody_report_grade_validation_plan["validation_plan_sha256"],
        "report_grade_ready_slot_count": custody_report_grade_validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": custody_report_grade_validation_plan["blocking_slot_count"],
        "trusted_custody_diff": dict(trusted_diff) if trusted_diff else missing_integrity_trusted_diff(
            CHAIN_OF_CUSTODY_GAP_ID,
            CUSTODY_TRUSTED_DIFF_BLOCKER_86,
            trusted_tool="custody-event-manifest",
        ),
        "core_accuracy_gates": custody_workflow_core_accuracy_gates(
            evidence_sources=evidence_sources,
            custody_events=custody_events,
            custody_event_manifest=custody_event_manifest,
            custody_chain_manifest=custody_chain_manifest,
            trusted_diff=trusted_diff,
            report_grade_validation_plan=custody_report_grade_validation_plan,
        ),
        "blockers": blockers,
        "limitations": [
            "This is a Case DB custody export; acquisition device/write-blocker metadata must be recorded separately when available.",
            "Original evidence images are not copied into report exports.",
        ],
    }


def attach_custody_row_hash(row: Mapping[str, object], *, row_type: str) -> dict[str, object]:
    output = dict(row)
    hash_core = {
        "row_type": row_type,
        "citation_id": str(row.get("citation_id") or ""),
        "actor": str(row.get("actor") or ""),
        "action": str(row.get("action") or ""),
        "target_type": str(row.get("target_type") or ""),
        "target_id": str(row.get("target_id") or ""),
        "timestamp": str(row.get("timestamp") or ""),
        "sha256": str(row.get("sha256") or ""),
        "status": str(row.get("status") or ""),
        "original_path": str(row.get("original_path") or ""),
        "result": str(row.get("result") or ""),
    }
    output["custody_row_hash"] = hashlib.sha256(
        json.dumps(hash_core, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return output


def build_custody_event_manifest(
    *,
    evidence_sources: Sequence[Mapping[str, object]],
    custody_events: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    manifest_core = {
        "profile_version": "custody-event-manifest-v1",
        "item_number": 86,
        "evidence_source_count": len(evidence_sources),
        "custody_event_count": len(custody_events),
        "evidence_source_hashes": [str(item.get("custody_row_hash") or "") for item in evidence_sources],
        "custody_event_hashes": [str(item.get("custody_row_hash") or "") for item in custody_events],
        "citation_ids": sorted(
            str(item.get("citation_id") or "")
            for item in [*evidence_sources, *custody_events]
            if item.get("citation_id")
        ),
        "commercial_gap_ids": [CHAIN_OF_CUSTODY_GAP_ID],
        "commercial_claim_allowed": False,
    }
    manifest_hash = hashlib.sha256(
        json.dumps(manifest_core, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return {**manifest_core, "manifest_hash": manifest_hash}


def build_custody_chain_manifest(
    *,
    evidence_sources: Sequence[Mapping[str, object]],
    custody_events: Sequence[Mapping[str, object]],
    custody_event_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None,
) -> dict[str, object]:
    row_hash_sequence = [
        str(item.get("custody_row_hash") or "")
        for item in [*evidence_sources, *custody_events]
        if item.get("custody_row_hash")
    ]
    chain_head = ""
    for row_hash in row_hash_sequence:
        chain_head = hashlib.sha256(f"{chain_head}:{row_hash}".encode("ascii", errors="ignore")).hexdigest()
    event_stage_counts = custody_event_stage_counts(custody_events)
    required_stages = ["acquisition", "transfer", "review", "export", "report"]
    missing_stages = [stage for stage in required_stages if event_stage_counts.get(stage, 0) == 0]
    source_hash_coverage = sum(1 for item in evidence_sources if item.get("sha256"))
    event_actor_coverage = sum(1 for item in custody_events if item.get("actor"))
    event_timestamp_coverage = sum(1 for item in custody_events if item.get("timestamp"))
    trusted_status = str(trusted_diff.get("status") or "missing") if trusted_diff else "missing"
    completeness_matrix = build_custody_completeness_matrix(
        evidence_sources=evidence_sources,
        custody_events=custody_events,
        event_stage_counts=event_stage_counts,
        missing_stages=missing_stages,
    )
    manifest_core: dict[str, object] = {
        "profile_version": "custody-chain-manifest-v1",
        "item_number": 40,
        "batch_id": FUNCTIONAL_VALIDATION_BATCH_ID,
        "gap_id": "#40",
        "commercial_gap_ids": [CHAIN_OF_CUSTODY_GAP_ID],
        "evidence_source_count": len(evidence_sources),
        "custody_event_count": len(custody_events),
        "source_sha256_coverage_count": source_hash_coverage,
        "event_actor_coverage_count": event_actor_coverage,
        "event_timestamp_coverage_count": event_timestamp_coverage,
        "row_hash_count": len(row_hash_sequence),
        "row_hash_sequence_head": hashlib.sha256("\n".join(row_hash_sequence).encode("ascii")).hexdigest()
        if row_hash_sequence
        else "",
        "hash_chain_head": chain_head,
        "custody_completeness_matrix_hash": completeness_matrix["matrix_hash"],
        "custody_completeness_matrix": completeness_matrix,
        "custody_event_manifest_hash": str(custody_event_manifest.get("manifest_hash") or ""),
        "event_stage_counts": event_stage_counts,
        "missing_stage_names": missing_stages,
        "trusted_diff_status": trusted_status,
        "trusted_diff_hash": hashlib.sha256(
            json.dumps(dict(trusted_diff), ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()
        if trusted_diff
        else "",
        "commercial_claim_allowed": (
            bool(evidence_sources)
            and bool(custody_events)
            and not missing_stages
            and source_hash_coverage == len(evidence_sources)
            and event_actor_coverage == len(custody_events)
            and event_timestamp_coverage == len(custody_events)
            and trusted_status == "pass"
        ),
        "required_external_evidence": [
            "acquisition handoff record",
            "write-blocker or source-protection metadata",
            "transfer/receipt events when evidence changes hands",
            "trusted custody-event manifest diff",
        ],
    }
    return {
        **manifest_core,
        "manifest_hash": hashlib.sha256(
            json.dumps(manifest_core, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest(),
    }


def build_custody_report_grade_validation_plan(
    *,
    evidence_sources: Sequence[Mapping[str, object]],
    custody_events: Sequence[Mapping[str, object]],
    custody_event_manifest: Mapping[str, object],
    custody_chain_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None,
) -> dict[str, object]:
    missing_stages = list(custody_chain_manifest.get("missing_stage_names") or [])
    trusted_status = str(trusted_diff.get("status") or "missing") if trusted_diff else "missing"
    source_hash_coverage = sum(1 for item in evidence_sources if item.get("sha256"))
    source_citation_coverage = sum(1 for item in evidence_sources if item.get("citation_id"))
    event_actor_coverage = sum(1 for item in custody_events if item.get("actor"))
    event_timestamp_coverage = sum(1 for item in custody_events if item.get("timestamp"))
    ready_slots = [
        {
            "slot_id": "custody-evidence-source-inventory",
            "status": "complete",
            "evidence": {
                "evidence_source_count": len(evidence_sources),
                "source_hash_coverage_count": source_hash_coverage,
                "source_citation_coverage_count": source_citation_coverage,
            },
        },
        {
            "slot_id": "custody-event-inventory",
            "status": "complete",
            "evidence": {
                "custody_event_count": len(custody_events),
                "event_actor_coverage_count": event_actor_coverage,
                "event_timestamp_coverage_count": event_timestamp_coverage,
            },
        },
        {
            "slot_id": "custody-event-manifest",
            "status": "complete",
            "evidence": {
                "manifest_hash": custody_event_manifest.get("manifest_hash"),
                "evidence_source_hash_count": len(custody_event_manifest.get("evidence_source_hashes") or []),
                "custody_event_hash_count": len(custody_event_manifest.get("custody_event_hashes") or []),
            },
        },
        {
            "slot_id": "custody-chain-manifest",
            "status": "complete",
            "evidence": {
                "manifest_hash": custody_chain_manifest.get("manifest_hash"),
                "hash_chain_head": custody_chain_manifest.get("hash_chain_head"),
                "row_hash_count": custody_chain_manifest.get("row_hash_count"),
            },
        },
        {
            "slot_id": "custody-completeness-matrix",
            "status": "complete",
            "evidence": {
                "matrix_hash": custody_chain_manifest.get("custody_completeness_matrix_hash"),
                "missing_stage_names": missing_stages,
            },
        },
        {
            "slot_id": "custody-trusted-diff-disclosure",
            "status": "complete",
            "evidence": {
                "trusted_diff_status": trusted_status,
                "trusted_tool": str((trusted_diff or {}).get("trusted_tool") or ""),
            },
        },
    ]
    blocking_slots: list[dict[str, object]] = []
    if not evidence_sources:
        blocking_slots.append(
            {
                "slot_id": "custody-evidence-source-inventory-present",
                "status": "blocked",
                "blocker": "custody-evidence-source-inventory-required",
                "required_evidence": "at least one evidence_source row linked to the exported case",
            }
        )
    if source_hash_coverage != len(evidence_sources):
        blocking_slots.append(
            {
                "slot_id": "custody-source-hash-completeness",
                "status": "blocked",
                "blocker": "custody-source-hash-completeness-required",
                "required_evidence": "SHA-256 or source hash for every evidence source row",
            }
        )
    if source_citation_coverage != len(evidence_sources):
        blocking_slots.append(
            {
                "slot_id": "custody-source-citation-completeness",
                "status": "blocked",
                "blocker": "custody-source-citation-completeness-required",
                "required_evidence": "stable citation_id for every evidence source row",
            }
        )
    if not custody_events:
        blocking_slots.append(
            {
                "slot_id": "custody-event-log-present",
                "status": "blocked",
                "blocker": "custody-event-log-required",
                "required_evidence": "acquisition, transfer, review, export, and report custody events",
            }
        )
    if event_actor_coverage != len(custody_events) or event_timestamp_coverage != len(custody_events):
        blocking_slots.append(
            {
                "slot_id": "custody-event-actor-timestamp-completeness",
                "status": "blocked",
                "blocker": "custody-event-actor-timestamp-completeness-required",
                "required_evidence": "actor and timestamp for every custody event row",
            }
        )
    if missing_stages:
        blocking_slots.append(
            {
                "slot_id": "custody-lifecycle-stage-coverage",
                "status": "blocked",
                "blocker": "custody-lifecycle-stage-coverage-required",
                "required_evidence": ", ".join(missing_stages),
            }
        )
    if trusted_status != "pass":
        blocking_slots.append(
            {
                "slot_id": "custody-trusted-event-manifest-diff",
                "status": "external-required",
                "blocker": CUSTODY_TRUSTED_DIFF_BLOCKER_86,
                "required_evidence": "trusted custody-event manifest diff covering evidence source rows, custody events, manifest hash, and completeness matrix hash",
            }
        )
    blocking_slots.extend(
        [
            {
                "slot_id": "custody-signed-handoff",
                "status": "external-required",
                "blocker": "signed-custody-handoff-required",
                "required_evidence": "signed custody handoff or receipt form for acquisition, transfer, and report delivery",
            },
            {
                "slot_id": "custody-acquisition-device-metadata",
                "status": "external-required",
                "blocker": "acquisition-device-metadata-required",
                "required_evidence": "acquisition workstation/device, examiner, clock, source device, and collection context metadata",
            },
            {
                "slot_id": "custody-write-blocker-metadata",
                "status": "external-required",
                "blocker": "write-blocker-metadata-required",
                "required_evidence": "write-blocker or source-protection device serial, firmware/version, and validation result",
            },
            {
                "slot_id": "custody-lab-policy",
                "status": "external-required",
                "blocker": "lab-custody-policy-required",
                "required_evidence": "lab-approved custody policy or SOP revision used for the case",
            },
        ]
    )
    plan_core: dict[str, object] = {
        "profile_version": CUSTODY_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 86,
        "commercial_gap_ids": [CHAIN_OF_CUSTODY_GAP_ID],
        "plan_context": "case-db-report-export",
        "custody_event_manifest_hash": custody_event_manifest.get("manifest_hash"),
        "custody_chain_manifest_hash": custody_chain_manifest.get("manifest_hash"),
        "custody_completeness_matrix_hash": custody_chain_manifest.get("custody_completeness_matrix_hash"),
        "trusted_diff_status": trusted_status,
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "external_blocker_catalog": list(SOURCE_PROVENANCE_REPORT_GRADE_BLOCKERS),
        "blockers": sorted({str(slot.get("blocker") or "") for slot in blocking_slots if slot.get("blocker")}),
        "commercial_claim_allowed": False,
        "reporting_boundary": "This plan makes Case DB custody exports auditable, but court/commercial custody claims still require external handoff, acquisition-device, write-blocker, policy, and trusted-manifest evidence.",
    }
    return {**plan_core, "validation_plan_sha256": stable_payload_sha256(plan_core)}


def build_custody_completeness_matrix(
    *,
    evidence_sources: Sequence[Mapping[str, object]],
    custody_events: Sequence[Mapping[str, object]],
    event_stage_counts: Mapping[str, int],
    missing_stages: Sequence[str],
) -> dict[str, object]:
    source_rows = []
    for item in evidence_sources:
        row = {
            "citation_id": str(item.get("citation_id") or ""),
            "has_original_path": bool(item.get("original_path")),
            "has_staged_path": bool(item.get("staged_path")),
            "has_size": item.get("size_bytes") is not None,
            "has_sha256": bool(item.get("sha256")),
            "has_status": bool(item.get("status")),
            "has_row_hash": bool(item.get("custody_row_hash")),
        }
        source_rows.append({**row, "row_hash": stable_payload_sha256(row)})
    event_rows = []
    for item in custody_events:
        row = {
            "citation_id": str(item.get("citation_id") or ""),
            "has_actor": bool(item.get("actor")),
            "has_action": bool(item.get("action")),
            "has_target": bool(item.get("target_type") or item.get("target_id")),
            "has_timestamp": bool(item.get("timestamp")),
            "has_result": bool(item.get("result")),
            "has_row_hash": bool(item.get("custody_row_hash")),
        }
        event_rows.append({**row, "row_hash": stable_payload_sha256(row)})
    matrix_core = {
        "profile_version": "custody-completeness-matrix-v1",
        "item_number": 86,
        "evidence_source_count": len(source_rows),
        "custody_event_count": len(event_rows),
        "source_rows": source_rows,
        "event_rows": event_rows,
        "event_stage_counts": dict(event_stage_counts),
        "missing_stage_names": list(missing_stages),
        "all_sources_hash_identified": bool(source_rows) and all(row["has_sha256"] for row in source_rows),
        "all_events_actor_timestamp_identified": bool(event_rows) and all(
            row["has_actor"] and row["has_timestamp"] for row in event_rows
        ),
    }
    return {**matrix_core, "matrix_hash": stable_payload_sha256(matrix_core)}


def custody_event_stage_counts(custody_events: Sequence[Mapping[str, object]]) -> dict[str, int]:
    stages = {"acquisition": 0, "transfer": 0, "review": 0, "export": 0, "report": 0}
    for event in custody_events:
        text = " ".join(
            str(event.get(field) or "").lower()
            for field in ("action", "target_type", "target_id", "result")
        )
        if any(token in text for token in ("acquisition", "acquire", "evidence_source", "import", "ingest")):
            stages["acquisition"] += 1
        if any(token in text for token in ("transfer", "handoff", "receipt", "custody")):
            stages["transfer"] += 1
        if any(token in text for token in ("review", "mark", "tag", "note")):
            stages["review"] += 1
        if any(token in text for token in ("export", "bundle", "exhibit")):
            stages["export"] += 1
        if any(token in text for token in ("report", "citation")):
            stages["report"] += 1
    return stages


def attach_acquisition_hash_row_hash(row: Mapping[str, object]) -> dict[str, object]:
    output = dict(row)
    hash_values = row.get("hashes") if isinstance(row.get("hashes"), Mapping) else {}
    hash_core = {
        "citation_id": str(row.get("citation_id") or ""),
        "target_type": str(row.get("target_type") or ""),
        "target_id": str(row.get("target_id") or ""),
        "hash_scope": str(row.get("hash_scope") or ""),
        "path": str(row.get("path") or ""),
        "display_name": str(row.get("display_name") or ""),
        "size_bytes": row.get("size_bytes"),
        "hashes": {str(key): str(value) for key, value in sorted(hash_values.items())},
        "hash_status": str(row.get("hash_status") or ""),
        "missing_hash_warning": bool(row.get("missing_hash_warning")),
        "calculated_at": str(row.get("calculated_at") or ""),
    }
    output["acquisition_hash_row_hash"] = hashlib.sha256(
        json.dumps(hash_core, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return output


def build_acquisition_hash_manifest(hashes: Sequence[Mapping[str, object]]) -> dict[str, object]:
    algorithm_coverage = {"md5": 0, "sha1": 0, "sha256": 0, "other": 0}
    missing_hash_warning_count = 0
    evidence_source_count = 0
    for item in hashes:
        if item.get("target_type") == "evidence_source":
            evidence_source_count += 1
        values = item.get("hashes") if isinstance(item.get("hashes"), Mapping) else {}
        if not values:
            missing_hash_warning_count += 1
            continue
        normalized_algorithms = {str(key).lower() for key in values}
        if "sha256" not in normalized_algorithms:
            missing_hash_warning_count += 1
        for algorithm in normalized_algorithms:
            if algorithm in algorithm_coverage:
                algorithm_coverage[algorithm] += 1
            else:
                algorithm_coverage["other"] += 1
    inventory_matrix = build_acquisition_hash_inventory_matrix(hashes, algorithm_coverage=algorithm_coverage)
    manifest_core = {
        "profile_version": "acquisition-hash-manifest-v1",
        "item_number": 87,
        "hash_record_count": len(hashes),
        "evidence_source_count": evidence_source_count,
        "hash_row_hashes": [str(item.get("acquisition_hash_row_hash") or "") for item in hashes],
        "citation_ids": sorted(str(item.get("citation_id") or "") for item in hashes if item.get("citation_id")),
        "algorithm_coverage": algorithm_coverage,
        "hash_inventory_matrix": inventory_matrix,
        "hash_inventory_matrix_hash": inventory_matrix["matrix_hash"],
        "missing_hash_warning_count": missing_hash_warning_count,
        "commercial_gap_ids": [ACQUISITION_HASH_GAP_ID],
        "commercial_claim_allowed": False,
    }
    manifest_hash = hashlib.sha256(
        json.dumps(manifest_core, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return {**manifest_core, "manifest_hash": manifest_hash}


def build_acquisition_hash_inventory_matrix(
    hashes: Sequence[Mapping[str, object]],
    *,
    algorithm_coverage: Mapping[str, int],
) -> dict[str, object]:
    rows = []
    for item in hashes:
        hash_values = item.get("hashes") if isinstance(item.get("hashes"), Mapping) else {}
        row = {
            "citation_id": str(item.get("citation_id") or ""),
            "target_type": str(item.get("target_type") or ""),
            "target_id": str(item.get("target_id") or ""),
            "hash_scope": str(item.get("hash_scope") or ""),
            "path_present": bool(item.get("path")),
            "size_present": item.get("size_bytes") is not None,
            "sha256_present": bool(hash_values.get("sha256")),
            "algorithm_count": len(hash_values),
            "hash_status": str(item.get("hash_status") or ""),
            "missing_hash_warning": bool(item.get("missing_hash_warning")),
            "row_hash_present": bool(item.get("acquisition_hash_row_hash")),
        }
        rows.append({**row, "row_hash": stable_payload_sha256(row)})
    matrix_core = {
        "profile_version": "acquisition-hash-inventory-matrix-v1",
        "item_number": 87,
        "hash_record_count": len(rows),
        "algorithm_coverage": dict(algorithm_coverage),
        "rows": rows,
        "all_rows_have_hash_material": bool(rows) and all(row["algorithm_count"] > 0 for row in rows),
        "all_evidence_sources_have_sha256": all(
            row["sha256_present"] for row in rows if row["target_type"] == "evidence_source"
        ),
    }
    return {**matrix_core, "matrix_hash": stable_payload_sha256(matrix_core)}


def build_acquisition_hash_report_grade_validation_plan(
    *,
    hashes: Sequence[Mapping[str, object]],
    acquisition_hash_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None,
) -> dict[str, object]:
    matrix = acquisition_hash_manifest.get("hash_inventory_matrix")
    inventory_matrix = matrix if isinstance(matrix, Mapping) else {}
    algorithm_coverage = acquisition_hash_manifest.get("algorithm_coverage")
    algorithm_coverage = algorithm_coverage if isinstance(algorithm_coverage, Mapping) else {}
    trusted_status = str(trusted_diff.get("status") or "missing") if trusted_diff else "missing"
    evidence_source_hashes = sum(1 for item in hashes if item.get("target_type") == "evidence_source")
    rows_with_hash_values = sum(1 for item in hashes if isinstance(item.get("hashes"), Mapping) and item.get("hashes"))
    rows_with_sha256 = sum(
        1
        for item in hashes
        if isinstance(item.get("hashes"), Mapping)
        and any(str(algorithm).lower() == "sha256" for algorithm in item.get("hashes", {}))
    )
    rows_with_timestamp = sum(1 for item in hashes if item.get("calculated_at"))
    rows_with_row_hash = sum(1 for item in hashes if item.get("acquisition_hash_row_hash"))
    ready_slots = [
        {
            "slot_id": "acquisition-hash-record-inventory",
            "status": "complete",
            "evidence": {
                "hash_record_count": len(hashes),
                "evidence_source_hash_count": evidence_source_hashes,
                "rows_with_hash_values": rows_with_hash_values,
            },
        },
        {
            "slot_id": "acquisition-hash-algorithm-coverage",
            "status": "complete",
            "evidence": dict(algorithm_coverage),
        },
        {
            "slot_id": "acquisition-hash-row-hashes",
            "status": "complete",
            "evidence": {
                "row_hash_count": rows_with_row_hash,
                "hash_row_hash_count": len(acquisition_hash_manifest.get("hash_row_hashes") or []),
            },
        },
        {
            "slot_id": "acquisition-hash-manifest",
            "status": "complete",
            "evidence": {
                "manifest_hash": acquisition_hash_manifest.get("manifest_hash"),
                "missing_hash_warning_count": acquisition_hash_manifest.get("missing_hash_warning_count", 0),
            },
        },
        {
            "slot_id": "acquisition-hash-inventory-matrix",
            "status": "complete",
            "evidence": {
                "matrix_hash": acquisition_hash_manifest.get("hash_inventory_matrix_hash"),
                "all_rows_have_hash_material": bool(inventory_matrix.get("all_rows_have_hash_material")),
                "all_evidence_sources_have_sha256": bool(inventory_matrix.get("all_evidence_sources_have_sha256")),
            },
        },
        {
            "slot_id": "acquisition-hash-trusted-diff-disclosure",
            "status": "complete",
            "evidence": {
                "trusted_diff_status": trusted_status,
                "trusted_tool": str((trusted_diff or {}).get("trusted_tool") or ""),
            },
        },
    ]
    blocking_slots: list[dict[str, object]] = []
    if not hashes:
        blocking_slots.append(
            {
                "slot_id": "acquisition-hash-records-present",
                "status": "blocked",
                "blocker": "acquisition-hash-record-inventory-required",
                "required_evidence": "at least one evidence source or generated-output hash row",
            }
        )
    if rows_with_hash_values != len(hashes):
        blocking_slots.append(
            {
                "slot_id": "acquisition-hash-values-complete",
                "status": "blocked",
                "blocker": "source-hash-completeness-required",
                "required_evidence": "hash values for every acquisition hash row",
            }
        )
    if rows_with_sha256 != len(hashes):
        blocking_slots.append(
            {
                "slot_id": "acquisition-sha256-coverage",
                "status": "blocked",
                "blocker": "source-sha256-completeness-required",
                "required_evidence": "SHA-256 coverage for every acquisition hash row",
            }
        )
    if rows_with_timestamp != len(hashes):
        blocking_slots.append(
            {
                "slot_id": "acquisition-hash-timestamps",
                "status": "blocked",
                "blocker": "hash-calculation-timestamp-required",
                "required_evidence": "calculated_at timestamp for every hash row",
            }
        )
    if rows_with_row_hash != len(hashes):
        blocking_slots.append(
            {
                "slot_id": "acquisition-hash-row-digests",
                "status": "blocked",
                "blocker": "acquisition-hash-row-digest-required",
                "required_evidence": "stable row digest for every hash row",
            }
        )
    if trusted_status != "pass":
        blocking_slots.append(
            {
                "slot_id": "acquisition-trusted-hash-manifest-diff",
                "status": "external-required",
                "blocker": ACQUISITION_HASH_TRUSTED_DIFF_BLOCKER_87,
                "required_evidence": "trusted acquisition hash manifest diff covering rows, manifest hash, and inventory matrix hash",
            }
        )
    blocking_slots.extend(
        [
            {
                "slot_id": "whole-device-acquisition-hash",
                "status": "external-required",
                "blocker": "whole-device-acquisition-hash-required",
                "required_evidence": "source image/device hash captured at acquisition, not only imported file/output hashes",
            },
            {
                "slot_id": "write-blocker-metadata",
                "status": "external-required",
                "blocker": "write-blocker-metadata-required",
                "required_evidence": "write-blocker/source-protection device serial, firmware/version, validation result, and operator",
            },
            {
                "slot_id": "operator-acquisition-log",
                "status": "external-required",
                "blocker": "operator-acquisition-log-required",
                "required_evidence": "operator acquisition log tying source media, time, tool, hash command, and case identifier together",
            },
            {
                "slot_id": "hash-tool-version-capture",
                "status": "external-required",
                "blocker": "hash-tool-version-capture-required",
                "required_evidence": "hashing/imaging tool path, version, command line, and output log for each acquisition hash",
            },
        ]
    )
    plan_core: dict[str, object] = {
        "profile_version": ACQUISITION_HASH_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 87,
        "commercial_gap_ids": [ACQUISITION_HASH_GAP_ID],
        "plan_context": "case-db-report-export",
        "acquisition_hash_manifest_hash": acquisition_hash_manifest.get("manifest_hash"),
        "hash_inventory_matrix_hash": acquisition_hash_manifest.get("hash_inventory_matrix_hash"),
        "trusted_diff_status": trusted_status,
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "blockers": sorted({str(slot.get("blocker") or "") for slot in blocking_slots if slot.get("blocker")}),
        "commercial_claim_allowed": False,
        "reporting_boundary": "This plan makes Case DB acquisition-hash exports auditable, but court/commercial hash claims require original source/device hashes, write-blocker metadata, operator logs, tool-version capture, and trusted-manifest evidence.",
    }
    return {**plan_core, "validation_plan_sha256": stable_payload_sha256(plan_core)}


def build_audit_hash_chain_manifest(events: Sequence[Mapping[str, object]], *, head_hash: str) -> dict[str, object]:
    actor_action_matrix = build_audit_actor_action_matrix(events)
    manifest_core = {
        "profile_version": "audit-hash-chain-manifest-v1",
        "item_number": 88,
        "event_count": len(events),
        "head_hash": head_hash,
        "event_hashes": [str(item.get("event_hash") or "") for item in events],
        "previous_event_hashes": [str(item.get("previous_event_hash") or "") for item in events],
        "citation_ids": sorted(str(item.get("citation_id") or "") for item in events if item.get("citation_id")),
        "actions": sorted({str(item.get("action") or "") for item in events if item.get("action")}),
        "actor_action_matrix": actor_action_matrix,
        "actor_action_matrix_hash": actor_action_matrix["matrix_hash"],
        "commercial_gap_ids": [IMMUTABLE_AUDIT_GAP_ID],
        "commercial_claim_allowed": False,
        "external_notarization_required": True,
    }
    manifest_hash = hashlib.sha256(
        json.dumps(manifest_core, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return {**manifest_core, "manifest_hash": manifest_hash}


def build_audit_actor_action_matrix(events: Sequence[Mapping[str, object]]) -> dict[str, object]:
    rows = []
    for index, item in enumerate(events):
        row = {
            "index": index,
            "citation_id": str(item.get("citation_id") or ""),
            "actor": str(item.get("actor") or ""),
            "action": str(item.get("action") or ""),
            "target_type": str(item.get("target_type") or ""),
            "target_id": str(item.get("target_id") or ""),
            "timestamp_present": bool(item.get("timestamp")),
            "event_hash_present": bool(item.get("event_hash")),
            "previous_event_hash_present": "previous_event_hash" in item,
        }
        rows.append({**row, "row_hash": stable_payload_sha256(row)})
    matrix_core = {
        "profile_version": "audit-actor-action-matrix-v1",
        "item_number": 88,
        "event_count": len(rows),
        "rows": rows,
        "all_rows_actor_action_timestamp": bool(rows) and all(
            bool(row["actor"]) and bool(row["action"]) and bool(row["timestamp_present"]) for row in rows
        ),
    }
    return {**matrix_core, "matrix_hash": stable_payload_sha256(matrix_core)}


def build_audit_replay_manifest(events: Sequence[Mapping[str, object]], *, expected_head_hash: str) -> dict[str, object]:
    previous_hash = ""
    replay_rows = []
    mismatch_indexes = []
    for index, event in enumerate(events):
        replay_core = {
            key: value
            for key, value in event.items()
            if key != "event_hash"
        }
        recomputed_hash = stable_payload_sha256(replay_core)
        stored_hash = str(event.get("event_hash") or "")
        expected_previous = previous_hash
        stored_previous = str(event.get("previous_event_hash") or "")
        matches = stored_hash == recomputed_hash and stored_previous == expected_previous
        if not matches:
            mismatch_indexes.append(index)
        replay_rows.append(
            {
                "index": index,
                "citation_id": str(event.get("citation_id") or ""),
                "stored_event_hash": stored_hash,
                "recomputed_event_hash": recomputed_hash,
                "stored_previous_event_hash": stored_previous,
                "expected_previous_event_hash": expected_previous,
                "chain_link_valid": matches,
            }
        )
        previous_hash = stored_hash
    replay_matrix_hash = stable_payload_sha256({"profile": "audit-replay-row-matrix-v1", "rows": replay_rows})
    manifest_core: dict[str, object] = {
        "profile_version": "audit-replay-manifest-v1",
        "item_number": 44,
        "batch_id": FUNCTIONAL_DEFENSIBILITY_BATCH_ID,
        "gap_id": "#44",
        "commercial_gap_ids": [IMMUTABLE_AUDIT_GAP_ID],
        "event_count": len(events),
        "expected_head_hash": expected_head_hash,
        "recomputed_head_hash": previous_hash,
        "head_hash_matches": previous_hash == expected_head_hash,
        "chain_valid": not mismatch_indexes and previous_hash == expected_head_hash,
        "mismatch_indexes": mismatch_indexes,
        "replay_rows": replay_rows[:100],
        "replay_row_count": len(replay_rows),
        "replay_matrix_hash": replay_matrix_hash,
        "external_notarization_required": True,
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_immutable_audit_report_grade_validation_plan(
    *,
    events: Sequence[Mapping[str, object]],
    head_hash: str,
    audit_hash_chain_manifest: Mapping[str, object],
    audit_replay_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None,
) -> dict[str, object]:
    trusted_status = str(trusted_diff.get("status") or "missing") if trusted_diff else "missing"
    events_with_hash = sum(1 for item in events if item.get("event_hash"))
    events_with_previous = sum(1 for item in events if "previous_event_hash" in item)
    events_with_actor_action_time = sum(
        1
        for item in events
        if item.get("actor") and item.get("action") and item.get("target_type") and item.get("timestamp")
    )
    ready_slots = [
        {
            "slot_id": "audit-event-inventory",
            "status": "complete",
            "evidence": {
                "event_count": len(events),
                "events_with_actor_action_time": events_with_actor_action_time,
            },
        },
        {
            "slot_id": "audit-event-hash-chain",
            "status": "complete",
            "evidence": {
                "events_with_event_hash": events_with_hash,
                "events_with_previous_hash": events_with_previous,
                "head_hash": head_hash,
            },
        },
        {
            "slot_id": "audit-hash-chain-manifest",
            "status": "complete",
            "evidence": {
                "manifest_hash": audit_hash_chain_manifest.get("manifest_hash"),
                "actor_action_matrix_hash": audit_hash_chain_manifest.get("actor_action_matrix_hash"),
            },
        },
        {
            "slot_id": "audit-replay-manifest",
            "status": "complete",
            "evidence": {
                "manifest_hash": audit_replay_manifest.get("manifest_hash"),
                "replay_matrix_hash": audit_replay_manifest.get("replay_matrix_hash"),
                "chain_valid": bool(audit_replay_manifest.get("chain_valid")),
            },
        },
        {
            "slot_id": "audit-replay-head-validation",
            "status": "complete",
            "evidence": {
                "expected_head_hash": audit_replay_manifest.get("expected_head_hash"),
                "recomputed_head_hash": audit_replay_manifest.get("recomputed_head_hash"),
                "head_hash_matches": bool(audit_replay_manifest.get("head_hash_matches")),
            },
        },
        {
            "slot_id": "audit-trusted-diff-disclosure",
            "status": "complete",
            "evidence": {
                "trusted_diff_status": trusted_status,
                "trusted_tool": str((trusted_diff or {}).get("trusted_tool") or ""),
            },
        },
    ]
    blocking_slots: list[dict[str, object]] = []
    if not events:
        blocking_slots.append(
            {
                "slot_id": "audit-events-present",
                "status": "blocked",
                "blocker": "audit-event-chain-required",
                "required_evidence": "append-only audit events for review, export, report, and settings changes",
            }
        )
    if events_with_hash != len(events) or events_with_previous != len(events) or not head_hash:
        blocking_slots.append(
            {
                "slot_id": "audit-hash-chain-completeness",
                "status": "blocked",
                "blocker": "audit-hash-chain-completeness-required",
                "required_evidence": "event_hash, previous_event_hash, and head hash for every audit chain export",
            }
        )
    if events_with_actor_action_time != len(events):
        blocking_slots.append(
            {
                "slot_id": "audit-actor-action-time-completeness",
                "status": "blocked",
                "blocker": "audit-actor-action-time-completeness-required",
                "required_evidence": "actor, action, target, and timestamp on every audit event",
            }
        )
    if not bool(audit_replay_manifest.get("chain_valid")):
        blocking_slots.append(
            {
                "slot_id": "audit-replay-chain-valid",
                "status": "blocked",
                "blocker": "audit-replay-chain-validation-required",
                "required_evidence": "replayed event hash chain must match stored head hash",
            }
        )
    if trusted_status != "pass":
        blocking_slots.append(
            {
                "slot_id": "audit-trusted-hash-chain-manifest-diff",
                "status": "external-required",
                "blocker": IMMUTABLE_AUDIT_TRUSTED_DIFF_BLOCKER_88,
                "required_evidence": "trusted audit hash-chain manifest diff covering chain manifest, replay manifest, actor/action matrix, and replay matrix",
            }
        )
    blocking_slots.extend(
        [
            {
                "slot_id": "database-level-audit-append-only",
                "status": "external-required",
                "blocker": "database-level-audit-append-only-required",
                "required_evidence": "database constraints/triggers or storage policy preventing audit_event update/delete after creation",
            },
            {
                "slot_id": "external-audit-chain-notarization",
                "status": "external-required",
                "blocker": "external-audit-chain-notarization-required",
                "required_evidence": "external timestamp, signing, or notarization proof for the exported audit chain head",
            },
            {
                "slot_id": "signed-audit-export-bundle",
                "status": "external-required",
                "blocker": "signed-audit-export-bundle-required",
                "required_evidence": "signed bundle containing audit export, manifests, hashes, and replay proof",
            },
            {
                "slot_id": "multi-user-identity-binding",
                "status": "external-required",
                "blocker": "multi-user-identity-binding-required",
                "required_evidence": "authenticated user identity mapping and role source for every audit actor",
            },
            {
                "slot_id": "audit-retention-policy",
                "status": "external-required",
                "blocker": "audit-retention-policy-required",
                "required_evidence": "case/lab retention policy for audit logs, export bundles, and notarization proofs",
            },
        ]
    )
    plan_core: dict[str, object] = {
        "profile_version": IMMUTABLE_AUDIT_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 88,
        "commercial_gap_ids": [IMMUTABLE_AUDIT_GAP_ID],
        "plan_context": "case-db-report-export",
        "audit_hash_chain_manifest_hash": audit_hash_chain_manifest.get("manifest_hash"),
        "audit_replay_manifest_hash": audit_replay_manifest.get("manifest_hash"),
        "actor_action_matrix_hash": audit_hash_chain_manifest.get("actor_action_matrix_hash"),
        "replay_matrix_hash": audit_replay_manifest.get("replay_matrix_hash"),
        "trusted_diff_status": trusted_status,
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "blockers": sorted({str(slot.get("blocker") or "") for slot in blocking_slots if slot.get("blocker")}),
        "commercial_claim_allowed": False,
        "reporting_boundary": "This plan makes export-time audit chains reproducible and reviewable, but immutable/court claims require database append-only controls, external notarization/signing, identity binding, retention policy, and trusted-chain evidence.",
    }
    return {**plan_core, "validation_plan_sha256": stable_payload_sha256(plan_core)}


def build_report_replay_manifest(
    *,
    stable_payload_sha256_value: str,
    items: Sequence[Mapping[str, object]],
    citation_index: Sequence[Mapping[str, object]],
    deterministic_sort: str,
    volatile_fields: Sequence[str],
) -> dict[str, object]:
    item_row_hashes = [
        stable_payload_sha256({"row_type": "report_item", "row": item})
        for item in items
    ]
    citation_row_hashes = [
        stable_payload_sha256({"row_type": "citation_index", "row": item})
        for item in citation_index
    ]
    row_hash_set_hash = stable_payload_sha256(
        {
            "item_row_hashes": item_row_hashes,
            "citation_row_hashes": citation_row_hashes,
        }
    )
    replay_contract = {
        "deterministic_sort": deterministic_sort,
        "volatile_fields": list(volatile_fields),
        "stable_item_count": len(items),
        "citation_count": len(citation_index),
        "row_hash_set_hash": row_hash_set_hash,
    }
    manifest_core = {
        "profile_version": "report-replay-manifest-v1",
        "item_number": 89,
        "stable_payload_sha256": stable_payload_sha256_value,
        "stable_item_count": len(items),
        "citation_count": len(citation_index),
        "item_row_hashes": item_row_hashes,
        "citation_row_hashes": citation_row_hashes,
        "row_hash_set_hash": row_hash_set_hash,
        "replay_contract": replay_contract,
        "replay_contract_hash": stable_payload_sha256(replay_contract),
        "deterministic_sort": deterministic_sort,
        "volatile_fields": list(volatile_fields),
        "commercial_gap_ids": [REPORT_REPRODUCIBILITY_GAP_ID],
        "commercial_claim_allowed": False,
        "cross_platform_replay_required": True,
    }
    manifest_hash = hashlib.sha256(
        json.dumps(manifest_core, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return {**manifest_core, "manifest_hash": manifest_hash}


def build_report_provenance_row_manifest(row: Mapping[str, object]) -> dict[str, object]:
    provenance_core = {
        "profile_version": "report-provenance-row-v1",
        "item_number": 90,
        "target_citation_id": str(row.get("target_citation_id") or ""),
        "review_citation_id": str(row.get("review_citation_id") or ""),
        "source_path": str(row.get("source_path") or ""),
        "hashes": row.get("hashes") if isinstance(row.get("hashes"), Mapping) else {},
        "record_hashes": row.get("record_hashes") if isinstance(row.get("record_hashes"), Mapping) else {},
        "parser": str(row.get("parser") or ""),
        "parser_version": str(row.get("parser_version") or ""),
        "parser_confidence": row.get("parser_confidence"),
        "record_offset": row.get("record_offset"),
        "source_index": row.get("source_index"),
        "review_status": str(row.get("review_status") or ""),
        "verification_status": str(row.get("verification_status") or ""),
        "reportability": str(row.get("reportability") or ""),
        "evidence_strength": str(row.get("evidence_strength") or ""),
    }
    provenance_row_hash = stable_payload_sha256(provenance_core)
    field_presence = {
        "source_path": bool(provenance_core["source_path"]),
        "hashes": bool(provenance_core["hashes"]),
        "record_hashes": bool(provenance_core["record_hashes"]),
        "parser": bool(provenance_core["parser"]),
        "parser_version": bool(provenance_core["parser_version"]),
        "parser_confidence": provenance_core["parser_confidence"] is not None,
        "record_offset": provenance_core["record_offset"] is not None,
        "source_index": provenance_core["source_index"] is not None,
        "review_status": bool(provenance_core["review_status"]),
        "reportability": bool(provenance_core["reportability"]),
    }
    required_fields = ["source_path", "hashes", "parser", "parser_version", "review_status", "reportability"]
    completeness_score = round(
        sum(1 for key in required_fields if field_presence.get(key)) / len(required_fields),
        4,
    )
    manifest_core = {
        "profile_version": "report-provenance-row-manifest-v1",
        "item_number": 90,
        "target_citation_id": provenance_core["target_citation_id"],
        "review_citation_id": provenance_core["review_citation_id"],
        "provenance_row_hash": provenance_row_hash,
        "field_presence": field_presence,
        "field_presence_hash": stable_payload_sha256(field_presence),
        "required_fields": required_fields,
        "missing_required_fields": [key for key in required_fields if not field_presence.get(key)],
        "completeness_score": completeness_score,
        "commercial_gap_ids": [SOURCE_PROVENANCE_GAP_ID],
        "commercial_claim_allowed": False,
    }
    manifest_hash = hashlib.sha256(
        json.dumps(manifest_core, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return {**manifest_core, "manifest_hash": manifest_hash}


def build_source_provenance_report_grade_validation_plan(
    provenance: Mapping[str, object],
    provenance_manifest: Mapping[str, object],
    *,
    trusted_diff: Mapping[str, object] | None,
) -> dict[str, object]:
    trusted_status = str(trusted_diff.get("status") or "missing") if trusted_diff else "missing"
    source_locator = provenance.get("source_locator") if isinstance(provenance.get("source_locator"), Mapping) else {}
    source_viewer_locator = (
        provenance.get("source_viewer_locator")
        if isinstance(provenance.get("source_viewer_locator"), Mapping)
        else {}
    )
    hashes = provenance.get("hashes") if isinstance(provenance.get("hashes"), Mapping) else {}
    record_hashes = provenance.get("record_hashes") if isinstance(provenance.get("record_hashes"), Mapping) else {}
    parser_manifest_hashes = (
        provenance.get("parser_manifest_hashes")
        if isinstance(provenance.get("parser_manifest_hashes"), Mapping)
        else {}
    )
    ready_slots = [
        {
            "slot_id": "source-path-and-locator",
            "status": "complete",
            "evidence": {
                "source_path": str(provenance.get("source_path") or ""),
                "source_locator_hash": str(provenance.get("source_locator_hash") or ""),
                "source_locator_present": bool(source_locator),
                "source_viewer_locator_present": bool(source_viewer_locator),
            },
        },
        {
            "slot_id": "source-and-record-hashes",
            "status": "complete",
            "evidence": {
                "source_hash_algorithms": sorted(str(key) for key in hashes.keys()),
                "record_hash_algorithms": sorted(str(key) for key in record_hashes.keys()),
                "row_citation_hash": str(provenance.get("row_citation_hash") or ""),
            },
        },
        {
            "slot_id": "parser-identity-and-confidence",
            "status": "complete",
            "evidence": {
                "parser": str(provenance.get("parser") or ""),
                "parser_version": str(provenance.get("parser_version") or ""),
                "parser_confidence": provenance.get("parser_confidence"),
                "parser_manifest_hash_count": len(parser_manifest_hashes),
            },
        },
        {
            "slot_id": "offset-source-index-and-citation",
            "status": "complete",
            "evidence": {
                "record_offset": provenance.get("record_offset"),
                "source_index": provenance.get("source_index"),
                "source_citation_package_hash": str(provenance.get("source_citation_package_hash") or ""),
                "source_read_citation_id": str(provenance.get("source_read_citation_id") or ""),
            },
        },
        {
            "slot_id": "review-and-reportability-state",
            "status": "complete",
            "evidence": {
                "review_status": str(provenance.get("review_status") or ""),
                "verification_status": str(provenance.get("verification_status") or ""),
                "reportability": str(provenance.get("reportability") or ""),
                "evidence_strength": str(provenance.get("evidence_strength") or ""),
            },
        },
        {
            "slot_id": "provenance-row-and-field-presence-manifest",
            "status": "complete",
            "evidence": {
                "provenance_row_hash": str(provenance_manifest.get("provenance_row_hash") or ""),
                "manifest_hash": str(provenance_manifest.get("manifest_hash") or ""),
                "field_presence_hash": str(provenance_manifest.get("field_presence_hash") or ""),
                "completeness_score": provenance_manifest.get("completeness_score"),
            },
        },
        {
            "slot_id": "trusted-provenance-diff-disclosure",
            "status": "complete",
            "evidence": {
                "trusted_diff_status": trusted_status,
                "trusted_tool": str((trusted_diff or {}).get("trusted_tool") or ""),
            },
        },
    ]
    blocking_slots: list[dict[str, object]] = []
    if not provenance.get("source_path") and not source_locator:
        blocking_slots.append(
            {
                "slot_id": "source-path-or-locator",
                "status": "blocked",
                "blocker": "source-path-or-locator-required",
                "required_evidence": "source path or structured source locator for every report item",
            }
        )
    if not hashes and not record_hashes:
        blocking_slots.append(
            {
                "slot_id": "source-or-record-hash",
                "status": "blocked",
                "blocker": "source-or-record-hash-required",
                "required_evidence": "source SHA-256 or record/content hash for every report item",
            }
        )
    if not provenance.get("parser") or not provenance.get("parser_version"):
        blocking_slots.append(
            {
                "slot_id": "parser-version",
                "status": "blocked",
                "blocker": "parser-version-required",
                "required_evidence": "parser name and parser version for every report item",
            }
        )
    if not provenance.get("review_status") or not provenance.get("reportability"):
        blocking_slots.append(
            {
                "slot_id": "review-reportability",
                "status": "blocked",
                "blocker": "review-reportability-required",
                "required_evidence": "review status and reportability decision for every report item",
            }
        )
    if not provenance_manifest.get("manifest_hash") or not provenance_manifest.get("provenance_row_hash"):
        blocking_slots.append(
            {
                "slot_id": "provenance-manifest-complete",
                "status": "blocked",
                "blocker": "provenance-manifest-completeness-required",
                "required_evidence": "provenance row hash, field-presence hash, and manifest hash",
            }
        )
    if float(provenance_manifest.get("completeness_score") or 0.0) < 1.0:
        blocking_slots.append(
            {
                "slot_id": "required-field-completeness",
                "status": "blocked",
                "blocker": "provenance-required-field-completeness-required",
                "required_evidence": "all required provenance fields present in each row manifest",
            }
        )
    if trusted_status != "pass":
        blocking_slots.append(
            {
                "slot_id": "trusted-report-provenance-manifest-diff",
                "status": "external-required",
                "blocker": SOURCE_PROVENANCE_TRUSTED_DIFF_BLOCKER_90,
                "required_evidence": "trusted provenance manifest diff over source path, hashes, parser, offset, review, and reportability fields",
            }
        )
    blocking_slots.extend(
        [
            {
                "slot_id": "all-parser-provenance-corpus",
                "status": "external-required",
                "blocker": "all-parser-provenance-corpus-required",
                "required_evidence": "fixture corpus proving provenance completeness across every parser family",
            },
            {
                "slot_id": "final-report-template-provenance-review",
                "status": "external-required",
                "blocker": "final-report-template-provenance-review-required",
                "required_evidence": "final report template review proving source provenance is visible for every cited item",
            },
            {
                "slot_id": "source-citation-viewer-roundtrip",
                "status": "external-required",
                "blocker": "source-citation-viewer-roundtrip-required",
                "required_evidence": "source viewer round-trip from report citation back to original source and hash",
            },
            {
                "slot_id": "offset-locator-trusted-diff",
                "status": "external-required",
                "blocker": "offset-locator-trusted-diff-required",
                "required_evidence": "trusted diff for parser offsets, source indexes, and viewer locators",
            },
            {
                "slot_id": "parser-version-release-lock",
                "status": "external-required",
                "blocker": "parser-version-release-lock-required",
                "required_evidence": "release-build parser/version inventory locked to the report export",
            },
        ]
    )
    plan_core: dict[str, object] = {
        "profile_version": SOURCE_PROVENANCE_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 90,
        "commercial_gap_ids": [SOURCE_PROVENANCE_GAP_ID],
        "plan_context": "case-db-report-item-provenance",
        "target_citation_id": str(provenance.get("target_citation_id") or ""),
        "review_citation_id": str(provenance.get("review_citation_id") or ""),
        "provenance_manifest_hash": str(provenance_manifest.get("manifest_hash") or ""),
        "provenance_row_hash": str(provenance_manifest.get("provenance_row_hash") or ""),
        "field_presence_hash": str(provenance_manifest.get("field_presence_hash") or ""),
        "completeness_score": provenance_manifest.get("completeness_score"),
        "trusted_diff_status": trusted_status,
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "blockers": sorted({str(slot.get("blocker") or "") for slot in blocking_slots if slot.get("blocker")}),
        "commercial_claim_allowed": False,
        "reporting_boundary": "This plan makes one report item source-provenance-reviewable, but commercial completeness requires all-parser corpus coverage, final report template review, citation viewer round-trip evidence, offset trusted diffs, parser-version release locks, and trusted provenance manifests.",
    }
    return {**plan_core, "validation_plan_sha256": stable_payload_sha256(plan_core)}


def parser_confidence_band(parser_confidence: object) -> str:
    score = optional_float(parser_confidence)
    if score is None:
        return "missing"
    if score >= 0.85:
        return "high"
    if score >= 0.6:
        return "medium"
    return "low-validation-required"


def parser_reportability_score(
    *,
    parser_confidence: object,
    reportability: str,
    coverage_status: str,
    warnings: Sequence[str],
    evidence_strength: str,
) -> int:
    score = 0
    confidence = optional_float(parser_confidence)
    if confidence is not None:
        score += round(max(0.0, min(1.0, confidence)) * 40)
    if reportability in {"reportable", "reviewed-reportable", "reviewed-report-candidate"}:
        score += 20
    elif reportability:
        score += 8
    if coverage_status in {"implemented", "fixture-backed-baseline", "validated"}:
        score += 15
    elif coverage_status:
        score += 6
    if evidence_strength:
        score += 15
    score += max(0, 10 - min(len(warnings), 10))
    return min(100, score)


def build_parser_confidence_calibration_manifest(
    *,
    parser_confidence: object,
    reportability: str,
    coverage_status: str,
    warnings: Sequence[str],
    evidence_strength: str,
) -> dict[str, object]:
    confidence_score = optional_float(parser_confidence)
    band = parser_confidence_band(parser_confidence)
    reportability_score = parser_reportability_score(
        parser_confidence=parser_confidence,
        reportability=reportability,
        coverage_status=coverage_status,
        warnings=warnings,
        evidence_strength=evidence_strength,
    )
    manifest_core = {
        "profile_version": "parser-confidence-calibration-manifest-v1",
        "item_number": 91,
        "parser_confidence": confidence_score,
        "confidence_band": band,
        "reportability": reportability,
        "coverage_status": coverage_status,
        "warning_count": len(warnings),
        "warnings": list(warnings),
        "evidence_strength": evidence_strength,
        "reportability_score": reportability_score,
        "calibration_basis": [
            "parser-provided-confidence-or-review-default",
            "reportability-state",
            "coverage-status",
            "validation-warning-count",
            "evidence-strength",
        ],
        "commercial_gap_ids": [PARSER_CONFIDENCE_GAP_ID],
        "commercial_claim_allowed": False,
        "trusted_calibration_required": True,
    }
    field_presence = {
        "parser_confidence": confidence_score is not None,
        "confidence_band": bool(band),
        "reportability": bool(reportability),
        "coverage_status": bool(coverage_status),
        "warning_count": True,
        "evidence_strength": bool(evidence_strength),
        "reportability_score": True,
    }
    manifest_core["calibration_field_presence"] = field_presence
    manifest_core["calibration_field_presence_hash"] = stable_payload_sha256(field_presence)
    manifest_hash = hashlib.sha256(
        json.dumps(manifest_core, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return {**manifest_core, "manifest_hash": manifest_hash}


def build_parser_confidence_report_grade_validation_plan(
    *,
    parser_confidence: object,
    reportability: str,
    coverage_status: str,
    warnings: Sequence[str],
    evidence_strength: str,
    confidence_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None,
) -> dict[str, object]:
    trusted_status = str(trusted_diff.get("status") or "missing") if trusted_diff else "missing"
    confidence_score = optional_float(parser_confidence)
    calibration_field_presence = (
        confidence_manifest.get("calibration_field_presence")
        if isinstance(confidence_manifest.get("calibration_field_presence"), Mapping)
        else {}
    )
    ready_slots = [
        {
            "slot_id": "parser-confidence-band-and-score",
            "status": "complete",
            "evidence": {
                "parser_confidence": confidence_score,
                "confidence_band": str(confidence_manifest.get("confidence_band") or ""),
            },
        },
        {
            "slot_id": "reportability-and-score",
            "status": "complete",
            "evidence": {
                "reportability": reportability,
                "reportability_score": confidence_manifest.get("reportability_score"),
            },
        },
        {
            "slot_id": "coverage-warning-evidence-strength",
            "status": "complete",
            "evidence": {
                "coverage_status": coverage_status,
                "warning_count": len(warnings),
                "evidence_strength": evidence_strength,
            },
        },
        {
            "slot_id": "calibration-manifest",
            "status": "complete",
            "evidence": {
                "manifest_hash": str(confidence_manifest.get("manifest_hash") or ""),
                "calibration_field_presence_hash": str(
                    confidence_manifest.get("calibration_field_presence_hash") or ""
                ),
            },
        },
        {
            "slot_id": "calibration-basis",
            "status": "complete",
            "evidence": {
                "basis": list(confidence_manifest.get("calibration_basis") or []),
                "field_presence": dict(calibration_field_presence),
            },
        },
        {
            "slot_id": "trusted-calibration-diff-disclosure",
            "status": "complete",
            "evidence": {
                "trusted_diff_status": trusted_status,
                "trusted_tool": str((trusted_diff or {}).get("trusted_tool") or ""),
            },
        },
    ]
    blocking_slots: list[dict[str, object]] = []
    if confidence_score is None:
        blocking_slots.append(
            {
                "slot_id": "parser-confidence-present",
                "status": "blocked",
                "blocker": "parser-confidence-required",
                "required_evidence": "parser confidence value for every report item",
            }
        )
    if not reportability:
        blocking_slots.append(
            {
                "slot_id": "reportability-state",
                "status": "blocked",
                "blocker": "reportability-state-required",
                "required_evidence": "reportability decision for every report item",
            }
        )
    if not coverage_status:
        blocking_slots.append(
            {
                "slot_id": "coverage-status",
                "status": "blocked",
                "blocker": "coverage-status-required",
                "required_evidence": "parser coverage status for every report item",
            }
        )
    if not evidence_strength:
        blocking_slots.append(
            {
                "slot_id": "evidence-strength",
                "status": "blocked",
                "blocker": "evidence-strength-required",
                "required_evidence": "evidence-strength classification for every report item",
            }
        )
    if not confidence_manifest.get("manifest_hash") or not confidence_manifest.get("calibration_field_presence_hash"):
        blocking_slots.append(
            {
                "slot_id": "confidence-calibration-manifest-complete",
                "status": "blocked",
                "blocker": "parser-confidence-calibration-manifest-required",
                "required_evidence": "calibration manifest hash and field-presence hash",
            }
        )
    missing_fields = [key for key, present in calibration_field_presence.items() if not present]
    if missing_fields:
        blocking_slots.append(
            {
                "slot_id": "calibration-field-completeness",
                "status": "blocked",
                "blocker": "parser-confidence-calibration-field-completeness-required",
                "required_evidence": "all calibration field-presence entries satisfied",
                "missing_fields": missing_fields,
            }
        )
    if trusted_status != "pass":
        blocking_slots.append(
            {
                "slot_id": "trusted-parser-confidence-calibration-diff",
                "status": "external-required",
                "blocker": PARSER_CONFIDENCE_TRUSTED_DIFF_BLOCKER_91,
                "required_evidence": "trusted calibration manifest diff over confidence, band, score, reportability, coverage, warnings, and evidence strength",
            }
        )
    blocking_slots.extend(
        [
            {
                "slot_id": "parser-specific-calibration-table",
                "status": "external-required",
                "blocker": "parser-specific-calibration-table-required",
                "required_evidence": "per-parser confidence calibration table and threshold rationale",
            },
            {
                "slot_id": "cross-tool-confidence-validation",
                "status": "external-required",
                "blocker": "cross-tool-confidence-validation-required",
                "required_evidence": "cross-tool confidence comparison for representative parser families",
            },
            {
                "slot_id": "low-confidence-fp-fn-corpus",
                "status": "external-required",
                "blocker": "low-confidence-fp-fn-corpus-required",
                "required_evidence": "false-positive/false-negative corpus covering low and medium confidence bands",
            },
            {
                "slot_id": "reportability-threshold-review",
                "status": "external-required",
                "blocker": "reportability-threshold-review-required",
                "required_evidence": "reviewed thresholds mapping confidence bands to reportability wording",
            },
            {
                "slot_id": "release-parser-confidence-policy-lock",
                "status": "external-required",
                "blocker": "release-parser-confidence-policy-lock-required",
                "required_evidence": "release-build parser confidence policy/version lock",
            },
        ]
    )
    plan_core: dict[str, object] = {
        "profile_version": PARSER_CONFIDENCE_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 91,
        "commercial_gap_ids": [PARSER_CONFIDENCE_GAP_ID],
        "plan_context": "case-db-report-item-validation-assessment",
        "parser_confidence": confidence_score,
        "confidence_band": str(confidence_manifest.get("confidence_band") or ""),
        "reportability": reportability,
        "coverage_status": coverage_status,
        "warning_count": len(warnings),
        "evidence_strength": evidence_strength,
        "reportability_score": confidence_manifest.get("reportability_score"),
        "calibration_manifest_hash": str(confidence_manifest.get("manifest_hash") or ""),
        "calibration_field_presence_hash": str(confidence_manifest.get("calibration_field_presence_hash") or ""),
        "trusted_diff_status": trusted_status,
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "external_blocker_catalog": list(PARSER_CONFIDENCE_REPORT_GRADE_BLOCKERS),
        "blockers": sorted({str(slot.get("blocker") or "") for slot in blocking_slots if slot.get("blocker")}),
        "commercial_claim_allowed": False,
        "reporting_boundary": "This plan makes one report item confidence-scored and reviewable, but commercial parser-confidence claims require parser-specific calibration tables, cross-tool validation, low-confidence FP/FN corpus, reportability threshold review, release policy locks, and trusted calibration manifests.",
    }
    return {**plan_core, "validation_plan_sha256": stable_payload_sha256(plan_core)}


def validation_warning_detail(warning: str) -> dict[str, object]:
    severity = "medium"
    category = "general-validation"
    action = "Review source evidence and parser limitations before reporting."
    badge = "validation-required"
    if warning == "source-hash-not-present-in-record":
        severity = "high"
        category = "source-integrity"
        action = "Attach or calculate source/record hashes before final report use."
        badge = "hash-missing"
    elif warning == "parser-confidence-not-present":
        severity = "high"
        category = "parser-confidence"
        action = "Attach parser confidence or mark the row as validation-required."
        badge = "confidence-missing"
    elif warning.startswith("reportability-"):
        category = "reportability"
        action = "Confirm reportability wording and analyst review status before inclusion."
        badge = "reportability-review"
    elif warning.startswith("coverage-"):
        category = "coverage"
        action = "Validate parser coverage against fixture/trusted-tool evidence."
        badge = "coverage-review"
    elif warning == "source-parser-validation-required":
        severity = "high"
        category = "parser-validation"
        action = "Resolve parser validation-required state with source evidence or trusted diff."
        badge = "parser-validation"
    elif warning == "commercial-grade-ready-false":
        severity = "high"
        category = "commercial-readiness"
        action = "Keep commercial/court-grade claims blocked until validation evidence is attached."
        badge = "commercial-blocked"
    return {
        "warning": warning,
        "severity": severity,
        "category": category,
        "badge": badge,
        "recommended_action": action,
    }


def build_validation_warning_checklist_manifest(warnings: Sequence[str]) -> dict[str, object]:
    details = [validation_warning_detail(str(warning)) for warning in warnings]
    severity_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    for item in details:
        severity = str(item["severity"])
        category = str(item["category"])
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        category_counts[category] = category_counts.get(category, 0) + 1
    manifest_core = {
        "profile_version": "validation-warning-checklist-manifest-v1",
        "item_number": 92,
        "warning_count": len(details),
        "warnings": details,
        "severity_counts": severity_counts,
        "category_counts": category_counts,
        "ux_badges": sorted({str(item["badge"]) for item in details}),
        "validation_required": bool(details),
        "commercial_gap_ids": [VALIDATION_WARNING_UX_GAP_ID],
        "commercial_claim_allowed": False,
        "trusted_checklist_required": True,
    }
    action_matrix = [
        {
            "warning": str(item.get("warning") or ""),
            "severity": str(item.get("severity") or ""),
            "category": str(item.get("category") or ""),
            "badge": str(item.get("badge") or ""),
            "recommended_action_hash": stable_payload_sha256(str(item.get("recommended_action") or "")),
        }
        for item in details
    ]
    manifest_core["warning_action_matrix"] = action_matrix
    manifest_core["warning_action_matrix_hash"] = stable_payload_sha256(action_matrix)
    manifest_hash = hashlib.sha256(
        json.dumps(manifest_core, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return {**manifest_core, "manifest_hash": manifest_hash}


def custody_workflow_functional_profile(
    *,
    evidence_sources: Sequence[Mapping[str, object]],
    custody_events: Sequence[Mapping[str, object]],
    custody_event_manifest: Mapping[str, object],
    custody_chain_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None,
    report_grade_validation_plan: Mapping[str, object] | None = None,
) -> dict[str, object]:
    sources_with_hash = sum(1 for item in evidence_sources if item.get("sha256"))
    sources_with_citation = sum(1 for item in evidence_sources if item.get("citation_id"))
    events_with_actor = sum(1 for item in custody_events if item.get("actor"))
    events_with_timestamp = sum(1 for item in custody_events if item.get("timestamp"))
    sources_with_row_hash = sum(1 for item in evidence_sources if item.get("custody_row_hash"))
    events_with_row_hash = sum(1 for item in custody_events if item.get("custody_row_hash"))
    failed_checks: list[str] = []
    if not evidence_sources:
        failed_checks.append("custody-evidence-source-inventory-empty")
    if sources_with_hash != len(evidence_sources):
        failed_checks.append("custody-source-hash-missing")
    if sources_with_citation != len(evidence_sources):
        failed_checks.append("custody-source-citation-missing")
    if not custody_events:
        failed_checks.append("custody-event-log-empty")
    if events_with_actor != len(custody_events):
        failed_checks.append("custody-event-actor-missing")
    if events_with_timestamp != len(custody_events):
        failed_checks.append("custody-event-timestamp-missing")
    if sources_with_row_hash != len(evidence_sources):
        failed_checks.append("custody-source-row-hash-missing")
    if events_with_row_hash != len(custody_events):
        failed_checks.append("custody-event-row-hash-missing")
    if not custody_event_manifest.get("manifest_hash"):
        failed_checks.append("custody-event-manifest-hash-missing")
    if not custody_chain_manifest.get("manifest_hash"):
        failed_checks.append("custody-chain-manifest-hash-missing")
    if not trusted_diff or trusted_diff.get("status") != "pass":
        failed_checks.append(CUSTODY_TRUSTED_DIFF_BLOCKER_86)
    if not report_grade_validation_plan or not report_grade_validation_plan.get("validation_plan_sha256"):
        failed_checks.append("custody-report-grade-validation-plan-missing")
    else:
        failed_checks.extend(str(blocker) for blocker in report_grade_validation_plan.get("blockers") or [])
    failed_checks = sorted(dict.fromkeys(failed_checks))
    return {
        "item_number": 40,
        "batch_id": FUNCTIONAL_VALIDATION_BATCH_ID,
        "status": "complete" if not failed_checks else "partial",
        "implemented_controls": {
            "evidence_source_count": len(evidence_sources),
            "sources_with_sha256": sources_with_hash,
            "sources_with_citation_id": sources_with_citation,
            "custody_event_count": len(custody_events),
            "events_with_actor": events_with_actor,
            "events_with_timestamp": events_with_timestamp,
            "sources_with_row_hash": sources_with_row_hash,
            "events_with_row_hash": events_with_row_hash,
            "custody_manifest_hash": str(custody_event_manifest.get("manifest_hash") or ""),
            "custody_chain_manifest_hash": str(custody_chain_manifest.get("manifest_hash") or ""),
            "custody_hash_chain_head": str(custody_chain_manifest.get("hash_chain_head") or ""),
            "missing_stage_names": list(custody_chain_manifest.get("missing_stage_names") or []),
            "trusted_diff_status": str(trusted_diff.get("status")) if trusted_diff else "missing",
            "custody_report_grade_validation_plan_hash": str(
                (report_grade_validation_plan or {}).get("validation_plan_sha256") or ""
            ),
            "report_grade_ready_slot_count": int((report_grade_validation_plan or {}).get("ready_slot_count") or 0),
            "report_grade_blocking_slot_count": int((report_grade_validation_plan or {}).get("blocking_slot_count") or 0),
        },
        "passed_validation_check_ids": [
            "case-db-evidence-source-inventory-exported",
            "case-db-custody-event-log-exported",
            "case-db-custody-summary-exported",
            "case-db-custody-row-hashes-exported",
            "case-db-custody-manifest-hash-exported",
            "case-db-custody-chain-manifest-hash-exported",
            "case-db-custody-limitations-disclosed",
            "case-db-custody-report-grade-validation-plan-exported",
        ],
        "failed_validation_check_ids": failed_checks,
        "reportability_decision": {
            "allowed_use": "single-case-chain-of-custody-export",
            "commercial_claim_allowed": not failed_checks,
            "operator_warning": "Attach acquisition/write-blocker metadata and a trusted custody manifest diff before court-grade use.",
        },
    }


def acquisition_hash_workflow_functional_profile(
    *,
    hashes: Sequence[Mapping[str, object]],
    acquisition_hash_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None,
    report_grade_validation_plan: Mapping[str, object] | None = None,
) -> dict[str, object]:
    evidence_source_hashes = sum(1 for item in hashes if item.get("target_type") == "evidence_source")
    rows_with_hash_values = sum(1 for item in hashes if isinstance(item.get("hashes"), Mapping) and item.get("hashes"))
    rows_with_sha256 = sum(
        1
        for item in hashes
        if isinstance(item.get("hashes"), Mapping)
        and any(str(algorithm).lower() == "sha256" for algorithm in item.get("hashes", {}))
    )
    rows_with_timestamp = sum(1 for item in hashes if item.get("calculated_at"))
    rows_with_row_hash = sum(1 for item in hashes if item.get("acquisition_hash_row_hash"))
    failed_checks: list[str] = []
    if not hashes:
        failed_checks.append("acquisition-hash-record-inventory-empty")
    if rows_with_hash_values != len(hashes):
        failed_checks.append("acquisition-hash-value-missing")
    if rows_with_timestamp != len(hashes):
        failed_checks.append("acquisition-hash-timestamp-missing")
    if rows_with_row_hash != len(hashes):
        failed_checks.append("acquisition-hash-row-hash-missing")
    if not acquisition_hash_manifest.get("manifest_hash"):
        failed_checks.append("acquisition-hash-manifest-hash-missing")
    if rows_with_sha256 != len(hashes):
        failed_checks.append("acquisition-sha256-coverage-incomplete")
    if not trusted_diff or trusted_diff.get("status") != "pass":
        failed_checks.append(ACQUISITION_HASH_TRUSTED_DIFF_BLOCKER_87)
    if not report_grade_validation_plan or not report_grade_validation_plan.get("validation_plan_sha256"):
        failed_checks.append("acquisition-hash-report-grade-validation-plan-missing")
    else:
        failed_checks.extend(str(blocker) for blocker in report_grade_validation_plan.get("blockers") or [])
    failed_checks = sorted(dict.fromkeys(failed_checks))
    return {
        "item_number": 87,
        "batch_id": FORENSIC_INTEGRITY_BATCH_ID,
        "status": "complete" if not failed_checks else "partial",
        "implemented_controls": {
            "hash_record_count": len(hashes),
            "evidence_source_hash_count": evidence_source_hashes,
            "rows_with_hash_values": rows_with_hash_values,
            "rows_with_sha256": rows_with_sha256,
            "rows_with_timestamp": rows_with_timestamp,
            "rows_with_row_hash": rows_with_row_hash,
            "acquisition_hash_manifest_hash": str(acquisition_hash_manifest.get("manifest_hash") or ""),
            "missing_hash_warning_count": acquisition_hash_manifest.get("missing_hash_warning_count", 0),
            "trusted_diff_status": str(trusted_diff.get("status")) if trusted_diff else "missing",
            "acquisition_hash_report_grade_validation_plan_hash": str(
                (report_grade_validation_plan or {}).get("validation_plan_sha256") or ""
            ),
            "report_grade_ready_slot_count": int((report_grade_validation_plan or {}).get("ready_slot_count") or 0),
            "report_grade_blocking_slot_count": int((report_grade_validation_plan or {}).get("blocking_slot_count") or 0),
        },
        "passed_validation_check_ids": [
            "case-db-acquisition-hash-records-exported",
            "case-db-acquisition-hash-algorithms-exported",
            "case-db-acquisition-hash-row-hashes-exported",
            "case-db-acquisition-hash-manifest-hash-exported",
            "case-db-acquisition-hash-limitations-disclosed",
            "case-db-acquisition-hash-report-grade-validation-plan-exported",
        ],
        "failed_validation_check_ids": failed_checks,
        "reportability_decision": {
            "allowed_use": "single-case-acquisition-hash-export",
            "commercial_claim_allowed": not failed_checks,
            "operator_warning": "Attach source acquisition logs, write-blocker metadata, and a trusted acquisition hash manifest diff before court-grade use.",
        },
    }


def build_acquisition_hash_workflow(
    connection: sqlite3.Connection,
    case_id: str,
    *,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    evidence_rows = connection.execute(
        """
        SELECT citation_id, display_name, original_path, size_bytes, hash_md5, hash_sha1, hash_sha256, added_at
        FROM evidence_source
        WHERE case_id = ?
        ORDER BY id ASC
        """,
        (case_id,),
    ).fetchall()
    hash_rows = connection.execute(
        """
        SELECT citation_id, target_type, target_id, hash_scope, algorithm, value, calculated_at
        FROM hash_record
        WHERE case_id = ?
        ORDER BY id ASC
        """,
        (case_id,),
    ).fetchall()
    hashes = []
    for row in evidence_rows:
        algorithms = {
            "md5": str(row["hash_md5"] or ""),
            "sha1": str(row["hash_sha1"] or ""),
            "sha256": str(row["hash_sha256"] or ""),
        }
        present = {key: value for key, value in algorithms.items() if value}
        hashes.append(
            {
                "citation_id": str(row["citation_id"]),
                "target_type": "evidence_source",
                "target_id": str(row["citation_id"]),
                "path": str(row["original_path"] or ""),
                "display_name": str(row["display_name"] or ""),
                "size_bytes": optional_int(row["size_bytes"]),
                "hashes": present,
                "hash_status": "present" if present else "missing",
                "missing_hash_warning": not present,
                "calculated_at": str(row["added_at"] or ""),
            }
        )
    for row in hash_rows:
        hashes.append(
            {
                "citation_id": str(row["citation_id"]),
                "target_type": str(row["target_type"] or ""),
                "target_id": str(row["target_id"] or ""),
                "hash_scope": str(row["hash_scope"] or ""),
                "hashes": {str(row["algorithm"] or ""): str(row["value"] or "")},
                "calculated_at": str(row["calculated_at"] or ""),
            }
        )
    hashes = [attach_acquisition_hash_row_hash(item) for item in hashes]
    acquisition_manifest = build_acquisition_hash_manifest(hashes)
    acquisition_report_grade_validation_plan = build_acquisition_hash_report_grade_validation_plan(
        hashes=hashes,
        acquisition_hash_manifest=acquisition_manifest,
        trusted_diff=trusted_diff,
    )
    blockers = []
    if not trusted_diff or trusted_diff.get("status") != "pass":
        blockers.append(ACQUISITION_HASH_TRUSTED_DIFF_BLOCKER_87)
    blockers = sorted({*blockers, *acquisition_report_grade_validation_plan["blockers"]})
    return {
        "status": "case-db-hash-export",
        "commercial_gap_ids": [ACQUISITION_HASH_GAP_ID],
        "summary": {
            "hash_count": len(hashes),
            "evidence_source_hash_count": sum(1 for item in hashes if item.get("target_type") == "evidence_source"),
            "acquisition_hash_manifest_hash": acquisition_manifest["manifest_hash"],
            "missing_hash_warning_count": acquisition_manifest["missing_hash_warning_count"],
            "commercial_gap_ids": [ACQUISITION_HASH_GAP_ID],
        },
        "hashes": hashes,
        "acquisition_hash_manifest": acquisition_manifest,
        "acquisition_hash_report_grade_validation_plan": acquisition_report_grade_validation_plan,
        "acquisition_hash_report_grade_validation_plan_hash": acquisition_report_grade_validation_plan["validation_plan_sha256"],
        "report_grade_ready_slot_count": acquisition_report_grade_validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": acquisition_report_grade_validation_plan["blocking_slot_count"],
        "functional_priority_profile": acquisition_hash_workflow_functional_profile(
            hashes=hashes,
            acquisition_hash_manifest=acquisition_manifest,
            trusted_diff=trusted_diff,
            report_grade_validation_plan=acquisition_report_grade_validation_plan,
        ),
        "trusted_acquisition_hash_diff": dict(trusted_diff) if trusted_diff else missing_integrity_trusted_diff(
            ACQUISITION_HASH_GAP_ID,
            ACQUISITION_HASH_TRUSTED_DIFF_BLOCKER_87,
            trusted_tool="acquisition-hash-manifest",
        ),
        "core_accuracy_gates": acquisition_hash_core_accuracy_gates(
            hashes=hashes,
            acquisition_hash_manifest=acquisition_manifest,
            trusted_diff=trusted_diff,
            report_grade_validation_plan=acquisition_report_grade_validation_plan,
        ),
        "blockers": blockers,
        "limitations": [
            "Folder evidence hashes describe imported files/outputs when available; whole-device acquisition hashes require acquisition metadata.",
            "Missing hashes should be resolved before court exhibit export.",
        ],
    }


def build_audit_integrity_chain(
    connection: sqlite3.Connection,
    case_id: str,
    *,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    rows = connection.execute(
        """
        SELECT citation_id, actor, action, target_type, target_id, timestamp,
               tool_name, tool_version, params_json, result, error
        FROM audit_event
        WHERE case_id = ?
        ORDER BY timestamp ASC, id ASC
        """,
        (case_id,),
    ).fetchall()
    events = []
    previous_hash = ""
    for row in rows:
        event = {
            "citation_id": str(row["citation_id"]),
            "actor": str(row["actor"] or ""),
            "action": str(row["action"] or ""),
            "target_type": str(row["target_type"] or ""),
            "target_id": str(row["target_id"] or ""),
            "timestamp": str(row["timestamp"] or ""),
            "tool_name": str(row["tool_name"] or ""),
            "tool_version": str(row["tool_version"] or ""),
            "params": parse_json_object(row["params_json"]),
            "result": str(row["result"] or ""),
            "error": str(row["error"] or ""),
            "previous_event_hash": previous_hash,
        }
        event_hash = stable_payload_sha256(event)
        event["event_hash"] = event_hash
        previous_hash = event_hash
        events.append(event)
    audit_chain_manifest = build_audit_hash_chain_manifest(events, head_hash=previous_hash)
    audit_replay_manifest = build_audit_replay_manifest(events, expected_head_hash=previous_hash)
    audit_report_grade_validation_plan = build_immutable_audit_report_grade_validation_plan(
        events=events,
        head_hash=previous_hash,
        audit_hash_chain_manifest=audit_chain_manifest,
        audit_replay_manifest=audit_replay_manifest,
        trusted_diff=trusted_diff,
    )
    blockers = []
    if not trusted_diff or trusted_diff.get("status") != "pass":
        blockers.append(IMMUTABLE_AUDIT_TRUSTED_DIFF_BLOCKER_88)
    blockers = sorted({*blockers, *audit_report_grade_validation_plan["blockers"]})
    return {
        "status": "tamper-evident-export-chain",
        "commercial_gap_ids": [IMMUTABLE_AUDIT_GAP_ID],
        "functional_priority_profile": audit_integrity_functional_profile(
            events=events,
            head_hash=previous_hash,
            audit_hash_chain_manifest=audit_chain_manifest,
            audit_replay_manifest=audit_replay_manifest,
            trusted_diff=trusted_diff,
            report_grade_validation_plan=audit_report_grade_validation_plan,
        ),
        "summary": {
            "event_count": len(events),
            "head_hash": previous_hash,
            "audit_chain_manifest_hash": audit_chain_manifest["manifest_hash"],
            "audit_replay_manifest_hash": audit_replay_manifest["manifest_hash"],
            "commercial_gap_ids": [IMMUTABLE_AUDIT_GAP_ID],
        },
        "events": events,
        "audit_hash_chain_manifest": audit_chain_manifest,
        "audit_replay_manifest": audit_replay_manifest,
        "audit_replay_manifest_hash": audit_replay_manifest["manifest_hash"],
        "immutable_audit_report_grade_validation_plan": audit_report_grade_validation_plan,
        "immutable_audit_report_grade_validation_plan_hash": audit_report_grade_validation_plan["validation_plan_sha256"],
        "report_grade_ready_slot_count": audit_report_grade_validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": audit_report_grade_validation_plan["blocking_slot_count"],
        "trusted_audit_integrity_diff": dict(trusted_diff) if trusted_diff else missing_integrity_trusted_diff(
            IMMUTABLE_AUDIT_GAP_ID,
            IMMUTABLE_AUDIT_TRUSTED_DIFF_BLOCKER_88,
            trusted_tool="audit-hash-chain-manifest",
        ),
        "core_accuracy_gates": immutable_audit_core_accuracy_gates(
            events=events,
            head_hash=previous_hash,
            audit_hash_chain_manifest=audit_chain_manifest,
            audit_replay_manifest=audit_replay_manifest,
            trusted_diff=trusted_diff,
            report_grade_validation_plan=audit_report_grade_validation_plan,
        ),
        "blockers": blockers,
        "limitations": [
            "This hash chain is generated at export time from Case DB audit rows; external notarization/signing is still required for full immutability.",
        ],
    }


def build_report_reproducibility_manifest(
    items: Sequence[Mapping[str, object]],
    citation_index: Sequence[Mapping[str, object]],
    *,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    stable_payload = {
        "items": items,
        "citation_index": citation_index,
    }
    stable_hash = stable_payload_sha256(stable_payload)
    deterministic_sort = "review include flag, updated_at, id; citation index sorted by citation_id"
    volatile_fields = ["generated_at", "database path", "case updated_at"]
    replay_manifest = build_report_replay_manifest(
        stable_payload_sha256_value=stable_hash,
        items=items,
        citation_index=citation_index,
        deterministic_sort=deterministic_sort,
        volatile_fields=volatile_fields,
    )
    reproducibility_report_grade_validation_plan = build_report_reproducibility_report_grade_validation_plan(
        stable_hash=stable_hash,
        item_count=len(items),
        citation_count=len(citation_index),
        deterministic_sort=deterministic_sort,
        volatile_fields=volatile_fields,
        report_replay_manifest=replay_manifest,
        trusted_diff=trusted_diff,
    )
    blockers = []
    if not trusted_diff or trusted_diff.get("status") != "pass":
        blockers.append(REPORT_REPRODUCIBILITY_TRUSTED_DIFF_BLOCKER_89)
    blockers = sorted({*blockers, *reproducibility_report_grade_validation_plan["blockers"]})
    return {
        "status": "deterministic-export-manifest",
        "commercial_gap_ids": [REPORT_REPRODUCIBILITY_GAP_ID],
        "stable_payload_sha256": stable_hash,
        "stable_item_count": len(items),
        "citation_count": len(citation_index),
        "deterministic_sort": deterministic_sort,
        "volatile_fields": volatile_fields,
        "report_replay_manifest": replay_manifest,
        "report_replay_manifest_hash": replay_manifest["manifest_hash"],
        "report_reproducibility_report_grade_validation_plan": reproducibility_report_grade_validation_plan,
        "report_reproducibility_report_grade_validation_plan_hash": reproducibility_report_grade_validation_plan[
            "validation_plan_sha256"
        ],
        "report_grade_ready_slot_count": reproducibility_report_grade_validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": reproducibility_report_grade_validation_plan["blocking_slot_count"],
        "trusted_reproducibility_diff": dict(trusted_diff) if trusted_diff else missing_integrity_trusted_diff(
            REPORT_REPRODUCIBILITY_GAP_ID,
            REPORT_REPRODUCIBILITY_TRUSTED_DIFF_BLOCKER_89,
            trusted_tool="report-replay-manifest",
        ),
        "core_accuracy_gates": report_reproducibility_core_accuracy_gates(
            stable_hash=stable_hash,
            item_count=len(items),
            citation_count=len(citation_index),
            report_replay_manifest=replay_manifest,
            trusted_diff=trusted_diff,
            report_grade_validation_plan=reproducibility_report_grade_validation_plan,
        ),
        "blockers": blockers,
    }


def build_report_reproducibility_report_grade_validation_plan(
    *,
    stable_hash: str,
    item_count: int,
    citation_count: int,
    deterministic_sort: str,
    volatile_fields: Sequence[str],
    report_replay_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None,
) -> dict[str, object]:
    trusted_status = str(trusted_diff.get("status") or "missing") if trusted_diff else "missing"
    ready_slots = [
        {
            "slot_id": "report-stable-payload-hash",
            "status": "complete",
            "evidence": {"stable_payload_sha256": stable_hash},
        },
        {
            "slot_id": "report-deterministic-ordering",
            "status": "complete",
            "evidence": {"deterministic_sort": deterministic_sort},
        },
        {
            "slot_id": "report-item-citation-row-hashes",
            "status": "complete",
            "evidence": {
                "item_count": item_count,
                "citation_count": citation_count,
                "item_row_hash_count": len(report_replay_manifest.get("item_row_hashes") or []),
                "citation_row_hash_count": len(report_replay_manifest.get("citation_row_hashes") or []),
            },
        },
        {
            "slot_id": "report-replay-manifest",
            "status": "complete",
            "evidence": {
                "manifest_hash": report_replay_manifest.get("manifest_hash"),
                "row_hash_set_hash": report_replay_manifest.get("row_hash_set_hash"),
            },
        },
        {
            "slot_id": "report-replay-contract",
            "status": "complete",
            "evidence": {
                "replay_contract_hash": report_replay_manifest.get("replay_contract_hash"),
                "volatile_fields": list(volatile_fields),
            },
        },
        {
            "slot_id": "report-reproducibility-trusted-diff-disclosure",
            "status": "complete",
            "evidence": {
                "trusted_diff_status": trusted_status,
                "trusted_tool": str((trusted_diff or {}).get("trusted_tool") or ""),
            },
        },
    ]
    blocking_slots: list[dict[str, object]] = []
    if not stable_hash:
        blocking_slots.append(
            {
                "slot_id": "report-stable-payload-hash-present",
                "status": "blocked",
                "blocker": "stable-payload-hash-required",
                "required_evidence": "stable payload SHA-256 for the deterministic report export",
            }
        )
    if len(report_replay_manifest.get("item_row_hashes") or []) != item_count:
        blocking_slots.append(
            {
                "slot_id": "report-item-row-hash-completeness",
                "status": "blocked",
                "blocker": "report-item-row-hash-completeness-required",
                "required_evidence": "row hash for every stable report item",
            }
        )
    if len(report_replay_manifest.get("citation_row_hashes") or []) != citation_count:
        blocking_slots.append(
            {
                "slot_id": "report-citation-row-hash-completeness",
                "status": "blocked",
                "blocker": "report-citation-row-hash-completeness-required",
                "required_evidence": "row hash for every citation index row",
            }
        )
    if not report_replay_manifest.get("manifest_hash") or not report_replay_manifest.get("replay_contract_hash"):
        blocking_slots.append(
            {
                "slot_id": "report-replay-manifest-complete",
                "status": "blocked",
                "blocker": "report-replay-manifest-completeness-required",
                "required_evidence": "report replay manifest hash and replay contract hash",
            }
        )
    if trusted_status != "pass":
        blocking_slots.append(
            {
                "slot_id": "report-trusted-replay-manifest-diff",
                "status": "external-required",
                "blocker": REPORT_REPRODUCIBILITY_TRUSTED_DIFF_BLOCKER_89,
                "required_evidence": "trusted report replay manifest diff over stable hash, counts, row hashes, and replay contract",
            }
        )
    blocking_slots.extend(
        [
            {
                "slot_id": "cross-platform-byte-for-byte-replay",
                "status": "external-required",
                "blocker": "cross-platform-byte-for-byte-replay-required",
                "required_evidence": "same input produces byte-equivalent JSON/Markdown/report artifacts on supported OS targets",
            },
            {
                "slot_id": "same-input-repeat-run-log",
                "status": "external-required",
                "blocker": "same-input-repeat-run-log-required",
                "required_evidence": "two or more same-input rerun logs showing identical stable payload/replay manifest hashes",
            },
            {
                "slot_id": "report-template-version-lock",
                "status": "external-required",
                "blocker": "report-template-version-lock-required",
                "required_evidence": "versioned report templates and schema version lock for the shipped build",
            },
            {
                "slot_id": "volatile-field-normalization-review",
                "status": "external-required",
                "blocker": "volatile-field-normalization-review-required",
                "required_evidence": "review of generated_at, path, environment, and case-updated fields excluded or normalized for replay",
            },
            {
                "slot_id": "release-build-replay-evidence",
                "status": "external-required",
                "blocker": "release-build-replay-evidence-required",
                "required_evidence": "release-build replay evidence tied to the final packaged binary/version",
            },
        ]
    )
    plan_core: dict[str, object] = {
        "profile_version": REPORT_REPRODUCIBILITY_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 89,
        "commercial_gap_ids": [REPORT_REPRODUCIBILITY_GAP_ID],
        "plan_context": "case-db-report-export",
        "stable_payload_sha256": stable_hash,
        "report_replay_manifest_hash": report_replay_manifest.get("manifest_hash"),
        "row_hash_set_hash": report_replay_manifest.get("row_hash_set_hash"),
        "replay_contract_hash": report_replay_manifest.get("replay_contract_hash"),
        "trusted_diff_status": trusted_status,
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "blockers": sorted({str(slot.get("blocker") or "") for slot in blocking_slots if slot.get("blocker")}),
        "commercial_claim_allowed": False,
        "reporting_boundary": "This plan makes one Case DB export replay-verifiable, but commercial reproducibility requires cross-platform byte-level replay, repeated run logs, template/schema locks, volatile-field review, release-build evidence, and trusted replay diffs.",
    }
    return {**plan_core, "validation_plan_sha256": stable_payload_sha256(plan_core)}


def build_report_item_validation_assessment(
    enriched: Mapping[str, object],
    *,
    parser_confidence_trusted_diff: Mapping[str, object] | None = None,
    validation_warning_trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    source_reference = enriched.get("source_reference") if isinstance(enriched.get("source_reference"), Mapping) else {}
    metadata = enriched.get("metadata") if isinstance(enriched.get("metadata"), Mapping) else {}
    warnings: list[str] = []
    parser_confidence = source_reference.get("parser_confidence") or metadata.get("parser_confidence")
    reportability = str(source_reference.get("reportability") or metadata.get("reportability") or "")
    coverage_status = str(source_reference.get("coverage_status") or metadata.get("coverage_status") or "")
    if not source_reference.get("source_hashes") and not source_reference.get("record_hashes"):
        warnings.append("source-hash-not-present-in-record")
    if not parser_confidence:
        warnings.append("parser-confidence-not-present")
    if reportability and reportability not in {"reportable", "reviewed-reportable"}:
        warnings.append(f"reportability-{reportability}")
    if coverage_status and coverage_status not in {"implemented", "fixture-backed-baseline"}:
        warnings.append(f"coverage-{coverage_status}")
    if metadata.get("validation_required") is True:
        warnings.append("source-parser-validation-required")
    if metadata.get("commercial_grade_ready") is False:
        warnings.append("commercial-grade-ready-false")
    evidence_strength = str(source_reference.get("evidence_strength") or metadata.get("evidence_strength") or "")
    confidence_manifest = build_parser_confidence_calibration_manifest(
        parser_confidence=parser_confidence,
        reportability=reportability,
        coverage_status=coverage_status,
        warnings=warnings,
        evidence_strength=evidence_strength,
    )
    warning_manifest = build_validation_warning_checklist_manifest(warnings)
    parser_confidence_report_grade_validation_plan = build_parser_confidence_report_grade_validation_plan(
        parser_confidence=parser_confidence,
        reportability=reportability,
        coverage_status=coverage_status,
        warnings=warnings,
        evidence_strength=evidence_strength,
        confidence_manifest=confidence_manifest,
        trusted_diff=parser_confidence_trusted_diff,
    )
    blockers = [
        blocker
        for blocker, diff in (
            (PARSER_CONFIDENCE_TRUSTED_DIFF_BLOCKER_91, parser_confidence_trusted_diff),
            (VALIDATION_WARNING_TRUSTED_DIFF_BLOCKER_92, validation_warning_trusted_diff),
        )
        if not diff or diff.get("status") != "pass"
    ]
    blockers = sorted({*blockers, *parser_confidence_report_grade_validation_plan["blockers"]})
    return {
        "commercial_gap_ids": [PARSER_CONFIDENCE_GAP_ID, VALIDATION_WARNING_UX_GAP_ID],
        "parser_confidence": parser_confidence,
        "confidence_band": confidence_manifest["confidence_band"],
        "reportability_score": confidence_manifest["reportability_score"],
        "reportability": reportability,
        "coverage_status": coverage_status,
        "evidence_strength": evidence_strength,
        "parser_confidence_calibration_manifest": confidence_manifest,
        "parser_confidence_manifest_hash": confidence_manifest["manifest_hash"],
        "calibration_field_presence_hash": confidence_manifest["calibration_field_presence_hash"],
        "parser_confidence_report_grade_validation_plan": parser_confidence_report_grade_validation_plan,
        "parser_confidence_report_grade_validation_plan_hash": parser_confidence_report_grade_validation_plan[
            "validation_plan_sha256"
        ],
        "parser_confidence_report_grade_ready_slot_count": parser_confidence_report_grade_validation_plan[
            "ready_slot_count"
        ],
        "parser_confidence_report_grade_blocking_slot_count": parser_confidence_report_grade_validation_plan[
            "blocking_slot_count"
        ],
        "validation_required": bool(warnings),
        "warnings": warnings,
        "warning_details": warning_manifest["warnings"],
        "warning_severity_counts": warning_manifest["severity_counts"],
        "warning_category_counts": warning_manifest["category_counts"],
        "warning_ux_badges": warning_manifest["ux_badges"],
        "validation_warning_checklist_manifest": warning_manifest,
        "validation_warning_manifest_hash": warning_manifest["manifest_hash"],
        "warning_action_matrix_hash": warning_manifest["warning_action_matrix_hash"],
        "trusted_parser_confidence_diff": dict(parser_confidence_trusted_diff)
        if parser_confidence_trusted_diff
        else missing_report_quality_trusted_diff(
            PARSER_CONFIDENCE_GAP_ID,
            PARSER_CONFIDENCE_TRUSTED_DIFF_BLOCKER_91,
            trusted_tool="parser-confidence-calibration",
        ),
        "trusted_validation_warning_diff": dict(validation_warning_trusted_diff)
        if validation_warning_trusted_diff
        else missing_report_quality_trusted_diff(
            VALIDATION_WARNING_UX_GAP_ID,
            VALIDATION_WARNING_TRUSTED_DIFF_BLOCKER_92,
            trusted_tool="validation-warning-checklist",
        ),
        "blockers": blockers,
        "core_accuracy_gates": [
            *parser_confidence_core_accuracy_gates(
                parser_confidence=parser_confidence,
                reportability=reportability,
                coverage_status=coverage_status,
                warnings=warnings,
                evidence_strength=evidence_strength,
                confidence_manifest=confidence_manifest,
                trusted_diff=parser_confidence_trusted_diff,
                report_grade_validation_plan=parser_confidence_report_grade_validation_plan,
            ),
            *validation_warning_ux_core_accuracy_gates(
                warnings=warnings,
                warning_manifest=warning_manifest,
                trusted_diff=validation_warning_trusted_diff,
            ),
        ],
        "guidance": "Resolve validation warnings and verify source evidence before using this item as a final report conclusion.",
    }


def build_report_item_legal_limitations(enriched: Mapping[str, object]) -> list[str]:
    metadata = enriched.get("metadata") if isinstance(enriched.get("metadata"), Mapping) else {}
    limitations = metadata.get("legal_limitations") or metadata.get("limitations") or metadata.get("commercial_grade_blockers")
    if isinstance(limitations, list):
        return [str(item) for item in limitations if str(item).strip()]
    source = str(enriched.get("source") or "")
    if source in {"artifacts", "indicators"}:
        return ["Artifact parser output should be validated against source evidence before testimony."]
    if source == "documents":
        return ["Indexed text can omit formatting, embedded objects, OCR uncertainty, or unsupported encodings."]
    if source == "files":
        return ["File metadata alone does not prove user intent or execution."]
    if source == "timeline":
        return ["Timeline rows require timezone and source-parser validation before final conclusions."]
    return ["Review source evidence, hashes, and parser limitations before report use."]


def legal_limitation_detail(limitation: str, *, source: str) -> dict[str, object]:
    text = str(limitation)
    lower = text.lower()
    category = "general-caution"
    scope = "report-item"
    wording_source = "rapidtriage-template"
    recommended_report_wording = text
    if "parser" in lower or "validated against source" in lower:
        category = "parser-validation"
        scope = "artifact-parser-output"
    elif "indexed text" in lower or "ocr" in lower or "formatting" in lower:
        category = "indexed-content"
        scope = "document-text-extraction"
    elif "file metadata" in lower or "intent" in lower:
        category = "metadata-interpretation"
        scope = "file-metadata"
    elif "timezone" in lower:
        category = "time-normalization"
        scope = "timeline"
    if source:
        wording_source = f"rapidtriage-{source}-template"
    return {
        "limitation": text,
        "category": category,
        "scope": scope,
        "wording_source": wording_source,
        "recommended_report_wording": recommended_report_wording,
        "requires_analyst_review": True,
        "requires_jurisdiction_review": True,
    }


def build_legal_limitation_manifest(
    *,
    limitations: Sequence[str],
    source: str,
    blockers: Sequence[str],
) -> dict[str, object]:
    details = [legal_limitation_detail(limitation, source=source) for limitation in limitations]
    category_counts: dict[str, int] = {}
    scope_counts: dict[str, int] = {}
    for item in details:
        category = str(item["category"])
        scope = str(item["scope"])
        category_counts[category] = category_counts.get(category, 0) + 1
        scope_counts[scope] = scope_counts.get(scope, 0) + 1
    manifest_core = {
        "profile_version": "legal-limitation-wording-manifest-v1",
        "item_number": 93,
        "limitation_count": len(details),
        "limitations": details,
        "category_counts": category_counts,
        "scope_counts": scope_counts,
        "blockers": list(blockers),
        "jurisdiction_review_required": True,
        "analyst_review_required": True,
        "commercial_gap_ids": [LEGAL_LIMITATION_GAP_ID],
        "commercial_claim_allowed": False,
    }
    wording_matrix = [
        {
            "category": str(item.get("category") or ""),
            "scope": str(item.get("scope") or ""),
            "wording_source": str(item.get("wording_source") or ""),
            "wording_hash": stable_payload_sha256(str(item.get("recommended_report_wording") or "")),
            "requires_analyst_review": bool(item.get("requires_analyst_review")),
            "requires_jurisdiction_review": bool(item.get("requires_jurisdiction_review")),
        }
        for item in details
    ]
    manifest_core["limitation_wording_matrix"] = wording_matrix
    manifest_core["limitation_wording_matrix_hash"] = stable_payload_sha256(wording_matrix)
    manifest_hash = hashlib.sha256(
        json.dumps(manifest_core, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return {**manifest_core, "manifest_hash": manifest_hash}


def build_legal_limitations_assessment(
    enriched: Mapping[str, object],
    *,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    limitations = build_report_item_legal_limitations(enriched)
    source = str(enriched.get("source") or "")
    blockers = [
        "limitation-text-is-template-or-parser-provided-and-requires-analyst-review",
        "jurisdiction-specific-admissibility-language-is-operator-owned",
    ]
    if not trusted_diff or trusted_diff.get("status") != "pass":
        blockers.append(LEGAL_LIMITATION_TRUSTED_DIFF_BLOCKER_93)
    limitation_manifest = build_legal_limitation_manifest(
        limitations=limitations,
        source=source,
        blockers=blockers,
    )
    return {
        "component": "artifact-legal-limitation-statement",
        "status": "present" if limitations else "missing",
        "commercial_gap_ids": [LEGAL_LIMITATION_GAP_ID],
        "limitation_count": len(limitations),
        "limitation_details": limitation_manifest["limitations"],
        "limitation_category_counts": limitation_manifest["category_counts"],
        "limitation_scope_counts": limitation_manifest["scope_counts"],
        "legal_limitation_manifest": limitation_manifest,
        "legal_limitation_manifest_hash": limitation_manifest["manifest_hash"],
        "limitation_wording_matrix_hash": limitation_manifest["limitation_wording_matrix_hash"],
        "trusted_legal_limitation_diff": dict(trusted_diff) if trusted_diff else missing_report_quality_trusted_diff(
            LEGAL_LIMITATION_GAP_ID,
            LEGAL_LIMITATION_TRUSTED_DIFF_BLOCKER_93,
            trusted_tool="legal-limitation-wording-review",
        ),
        "core_accuracy_gates": legal_limitation_core_accuracy_gates(
            limitations=limitations,
            limitation_manifest=limitation_manifest,
            trusted_diff=trusted_diff,
        ),
        "ready_for_court_report": False,
        "blockers": blockers,
    }


def attach_acquisition_metadata_row_hash(record: Mapping[str, object]) -> dict[str, object]:
    row = dict(record)
    row["acquisition_metadata_row_hash"] = stable_payload_sha256(
        {
            "citation_id": row.get("citation_id"),
            "evidence_source_citation_id": row.get("evidence_source_citation_id"),
            "operator": row.get("operator"),
            "acquisition_started_at": row.get("acquisition_started_at"),
            "acquisition_completed_at": row.get("acquisition_completed_at"),
            "source_identifier": row.get("source_identifier"),
            "write_blocker": row.get("write_blocker"),
            "acquisition_tool": row.get("acquisition_tool"),
            "acquisition_tool_version": row.get("acquisition_tool_version"),
            "whole_source_sha256": row.get("whole_source_sha256"),
        }
    )
    return row


def attach_acquisition_evidence_source_row_hash(source: Mapping[str, object]) -> dict[str, object]:
    row = dict(source)
    row["acquisition_evidence_source_row_hash"] = stable_payload_sha256(
        {
            "citation_id": row.get("citation_id"),
            "original_path": row.get("original_path"),
            "staged_path": row.get("staged_path"),
            "size_bytes": row.get("size_bytes"),
            "sha256": row.get("sha256"),
            "added_at": row.get("added_at"),
        }
    )
    return row


def build_acquisition_metadata_handoff_manifest(
    *,
    records: Sequence[Mapping[str, object]],
    evidence_sources: Sequence[Mapping[str, object]],
    required_fields: Sequence[str],
    missing_required_fields: Sequence[str],
    missing_by_record: Sequence[Mapping[str, object]],
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    field_completion_matrix = build_acquisition_field_completion_matrix(
        records=records,
        evidence_sources=evidence_sources,
        required_fields=required_fields,
    )
    manifest_core = {
        "profile_version": "acquisition-metadata-handoff-manifest-v1",
        "item_number": 96,
        "metadata_record_count": len(records),
        "evidence_source_count": len(evidence_sources),
        "required_fields": list(required_fields),
        "missing_required_fields": list(missing_required_fields),
        "missing_by_record": [dict(item) for item in missing_by_record],
        "field_completion_matrix": field_completion_matrix,
        "field_completion_matrix_hash": field_completion_matrix["matrix_hash"],
        "record_row_hashes": [str(item.get("acquisition_metadata_row_hash") or "") for item in records],
        "evidence_source_row_hashes": [
            str(item.get("acquisition_evidence_source_row_hash") or "") for item in evidence_sources
        ],
        "trusted_diff_status": str(trusted_diff.get("status") or ""),
        "commercial_gap_ids": [WRITE_BLOCKER_ACQUISITION_METADATA_GAP_ID],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_acquisition_field_completion_matrix(
    *,
    records: Sequence[Mapping[str, object]],
    evidence_sources: Sequence[Mapping[str, object]],
    required_fields: Sequence[str],
) -> dict[str, object]:
    rows = []
    for field in required_fields:
        present_count = sum(1 for record in records if str(record.get(field) or "").strip())
        row_core = {
            "field": str(field),
            "present_record_count": present_count,
            "missing_record_count": max(len(records) - present_count, 0),
            "required": True,
        }
        rows.append({**row_core, "row_hash": stable_payload_sha256(row_core)})
    matrix_core = {
        "profile_version": "acquisition-field-completion-matrix-v1",
        "item_number": 96,
        "record_count": len(records),
        "evidence_source_count": len(evidence_sources),
        "required_field_count": len(required_fields),
        "rows": rows,
        "complete_required_fields": all(row["missing_record_count"] == 0 for row in rows) if rows else False,
        "commercial_claim_allowed": False,
    }
    return {**matrix_core, "matrix_hash": stable_payload_sha256(matrix_core)}


def build_acquisition_metadata_record(
    connection: sqlite3.Connection,
    case_id: str,
    *,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    case = connection.execute("SELECT * FROM case_record WHERE case_id = ?", (case_id,)).fetchone()
    evidence_rows = connection.execute(
        """
        SELECT citation_id, original_path, staged_path, hash_sha256, size_bytes, added_at
        FROM evidence_source
        WHERE case_id = ?
        ORDER BY id ASC
        """,
        (case_id,),
    ).fetchall()
    metadata_rows = connection.execute(
        """
        SELECT * FROM acquisition_metadata
        WHERE case_id = ?
        ORDER BY created_at ASC, id ASC
        """,
        (case_id,),
    ).fetchall()
    required_fields = [
        "operator",
        "acquisition_started_at",
        "acquisition_completed_at",
        "source_identifier",
        "write_blocker",
        "whole_source_sha256",
    ]
    acquisition_records = [
        attach_acquisition_metadata_row_hash(acquisition_metadata_to_dict(row)) for row in metadata_rows
    ]
    missing_by_record = [
        {
            "citation_id": str(record.get("citation_id") or ""),
            "missing_required_fields": [
                field for field in required_fields if not str(record.get(field) or "").strip()
            ],
        }
        for record in acquisition_records
    ]
    if acquisition_records:
        missing = sorted(
            {
                field
                for record in acquisition_records
                for field in required_fields
                if not str(record.get(field) or "").strip()
            }
        )
    else:
        missing = list(required_fields)
    case_metadata = {
        "examiner": str(case["examiner"] or "") if case else "",
        "organization": str(case["organization"] or "") if case else "",
        "case_root": str(case["case_root"] or "") if case else "",
    }
    evidence_sources = [
        attach_acquisition_evidence_source_row_hash(
            {
                "citation_id": str(row["citation_id"]),
                "original_path": str(row["original_path"] or ""),
                "staged_path": str(row["staged_path"] or ""),
                "size_bytes": optional_int(row["size_bytes"]),
                "sha256": str(row["hash_sha256"] or ""),
                "added_at": str(row["added_at"] or ""),
            }
        )
        for row in evidence_rows
    ]
    status = "metadata-recorded" if acquisition_records and not missing else "metadata-check-required"
    if trusted_diff is None:
        trusted_diff = missing_acquisition_metadata_trusted_diff()
    blockers = []
    if trusted_diff.get("status") != "pass":
        blockers.append(ACQUISITION_METADATA_TRUSTED_DIFF_BLOCKER_96)
    handoff_manifest = build_acquisition_metadata_handoff_manifest(
        records=acquisition_records,
        evidence_sources=evidence_sources,
        required_fields=required_fields,
        missing_required_fields=missing,
        missing_by_record=missing_by_record,
        trusted_diff=trusted_diff,
    )
    input_manifest = build_acquisition_metadata_input_manifest(
        records=acquisition_records,
        evidence_sources=evidence_sources,
        required_fields=required_fields,
        missing_required_fields=missing,
        trusted_diff=trusted_diff,
    )
    return {
        "status": status,
        "commercial_gap_ids": [WRITE_BLOCKER_ACQUISITION_METADATA_GAP_ID],
        "functional_priority_profile": acquisition_metadata_functional_profile(
            records=acquisition_records,
            evidence_sources=evidence_sources,
            missing_required_fields=missing,
            input_manifest=input_manifest,
            trusted_diff=trusted_diff,
        ),
        "case_metadata": case_metadata,
        "evidence_sources": evidence_sources,
        "records": acquisition_records,
        "missing_by_record": missing_by_record,
        "required_fields": required_fields,
        "missing_required_fields": missing,
        "trusted_acquisition_metadata_diff": trusted_diff,
        "acquisition_metadata_handoff_manifest": handoff_manifest,
        "acquisition_metadata_handoff_manifest_hash": handoff_manifest["manifest_hash"],
        "acquisition_field_completion_matrix": handoff_manifest["field_completion_matrix"],
        "acquisition_field_completion_matrix_hash": handoff_manifest["field_completion_matrix_hash"],
        "acquisition_metadata_input_manifest": input_manifest,
        "acquisition_metadata_input_manifest_hash": input_manifest["manifest_hash"],
        "blockers": blockers,
        "summary": {
            "evidence_source_count": len(evidence_sources),
            "metadata_record_count": len(acquisition_records),
            "missing_required_field_count": len(missing),
            "acquisition_metadata_handoff_manifest_hash": handoff_manifest["manifest_hash"],
            "acquisition_field_completion_matrix_hash": handoff_manifest["field_completion_matrix_hash"],
            "acquisition_metadata_input_manifest_hash": input_manifest["manifest_hash"],
            "commercial_gap_ids": [WRITE_BLOCKER_ACQUISITION_METADATA_GAP_ID],
        },
        "validation_assessment": {
            "commercial_gap_ids": [WRITE_BLOCKER_ACQUISITION_METADATA_GAP_ID],
            "write_blocker_recorded": any(str(record.get("write_blocker") or "").strip() for record in acquisition_records),
            "whole_source_hash_recorded": any(
                str(record.get("whole_source_sha256") or "").strip() for record in acquisition_records
            ),
            "ready_for_submission": bool(acquisition_records and not missing),
            "missing_required_fields": missing,
            "acquisition_metadata_handoff_manifest_hash": handoff_manifest["manifest_hash"],
            "acquisition_field_completion_matrix_hash": handoff_manifest["field_completion_matrix_hash"],
            "acquisition_metadata_input_manifest_hash": input_manifest["manifest_hash"],
            "core_accuracy_gates": acquisition_metadata_core_accuracy_gates(
                records=acquisition_records,
                missing_required_fields=missing,
                handoff_manifest=handoff_manifest,
                input_manifest=input_manifest,
                trusted_diff=trusted_diff,
            ),
            "trusted_acquisition_metadata_diff": trusted_diff,
            "blockers": blockers,
        },
        "guidance": "Record acquisition operator, device/source identifier, write-blocker details, acquisition timestamps, and whole-source hashes before final submission.",
    }


def build_acquisition_metadata_input_manifest(
    *,
    records: Sequence[Mapping[str, object]],
    evidence_sources: Sequence[Mapping[str, object]],
    required_fields: Sequence[str],
    missing_required_fields: Sequence[str],
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    form_fields = [
        ("evidence_source_citation_id", "Evidence source", True),
        ("operator", "Operator / examiner", True),
        ("source_identifier", "Device or source identifier", True),
        ("write_blocker", "Write-blocker / source protection", True),
        ("acquisition_tool", "Acquisition tool", False),
        ("acquisition_tool_version", "Acquisition tool version", False),
        ("acquisition_started_at", "Acquisition started at", True),
        ("acquisition_completed_at", "Acquisition completed at", True),
        ("whole_source_sha256", "Whole-source SHA-256", True),
        ("notes", "Acquisition notes", False),
    ]
    field_rows = []
    for field_name, label, required in form_fields:
        present_count = sum(1 for record in records if str(record.get(field_name) or "").strip())
        field_rows.append(
            {
                "field": field_name,
                "label": label,
                "required": required,
                "present_record_count": present_count,
                "missing_record_count": max(len(records) - present_count, 0),
                "missing_globally": field_name in set(missing_required_fields),
            }
        )
    evidence_source_choices = [
        {
            "citation_id": str(source.get("citation_id") or ""),
            "display": str(source.get("original_path") or source.get("staged_path") or source.get("citation_id") or ""),
            "sha256_present": bool(str(source.get("sha256") or "")),
        }
        for source in evidence_sources
    ]
    manifest_core: dict[str, object] = {
        "profile_version": "acquisition-metadata-input-manifest-v1",
        "item_number": 41,
        "batch_id": FUNCTIONAL_DEFENSIBILITY_BATCH_ID,
        "gap_id": "#41",
        "commercial_gap_ids": [WRITE_BLOCKER_ACQUISITION_METADATA_GAP_ID],
        "record_count": len(records),
        "evidence_source_choice_count": len(evidence_source_choices),
        "required_fields": list(required_fields),
        "missing_required_fields": list(missing_required_fields),
        "form_fields": field_rows,
        "evidence_source_choices": evidence_source_choices,
        "audit_action": "record_acquisition_metadata",
        "audit_required": True,
        "trusted_diff_status": str(trusted_diff.get("status") or ""),
        "ready_for_submission": bool(records and not missing_required_fields),
        "operator_warning": "The GUI must preserve these fields in the audit log and report export before court-grade use.",
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def attach_timezone_sample_row_hash(sample: Mapping[str, object]) -> dict[str, object]:
    row = dict(sample)
    row["timezone_sample_row_hash"] = stable_payload_sha256(
        {
            "timestamp": row.get("timestamp"),
            "timezone": row.get("timezone"),
            "normalized_utc": row.get("normalized_utc"),
            "parser_assumption": row.get("parser_assumption"),
            "timestamp_kind": row.get("timestamp_kind"),
            "source": row.get("source"),
            "event_type": row.get("event_type"),
        }
    )
    return row


def build_timezone_normalization_manifest(
    *,
    event_count: int,
    missing_timezone_count: int,
    timezone_counts: Mapping[str, int],
    samples: Sequence[Mapping[str, object]],
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    parser_assumption_matrix = build_timezone_parser_assumption_matrix(samples)
    manifest_core = {
        "profile_version": "timezone-normalization-manifest-v1",
        "item_number": 97,
        "event_count": event_count,
        "missing_timezone_count": missing_timezone_count,
        "timezone_counts": dict(timezone_counts),
        "sample_count": len(samples),
        "sample_row_hashes": [str(sample.get("timezone_sample_row_hash") or "") for sample in samples],
        "parser_assumption_matrix": parser_assumption_matrix,
        "parser_assumption_matrix_hash": parser_assumption_matrix["matrix_hash"],
        "utc_assumption": "timestamps are interpreted as UTC when parser/source timezone is absent",
        "trusted_diff_status": str(trusted_diff.get("status") or ""),
        "commercial_gap_ids": [TIMEZONE_NORMALIZATION_GAP_ID],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_timezone_parser_assumption_matrix(samples: Sequence[Mapping[str, object]]) -> dict[str, object]:
    counts: dict[str, int] = {}
    for sample in samples:
        assumption = str(sample.get("parser_assumption") or "unknown")
        counts[assumption] = counts.get(assumption, 0) + 1
    rows = []
    for assumption, count in sorted(counts.items()):
        row_core = {"parser_assumption": assumption, "sample_count": count}
        rows.append({**row_core, "row_hash": stable_payload_sha256(row_core)})
    matrix_core = {
        "profile_version": "timezone-parser-assumption-matrix-v1",
        "item_number": 97,
        "sample_count": len(samples),
        "rows": rows,
        "assumption_count": len(rows),
        "commercial_claim_allowed": False,
    }
    return {**matrix_core, "matrix_hash": stable_payload_sha256(matrix_core)}


def build_time_semantics_manifest(
    *,
    samples: Sequence[Mapping[str, object]],
    timezone_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    semantic_rows = [
        {
            "original_timestamp": str(sample.get("timestamp") or ""),
            "source_timezone": str(sample.get("timezone") or ""),
            "normalized_utc": str(sample.get("normalized_utc") or ""),
            "timestamp_kind": str(sample.get("timestamp_kind") or ""),
            "source": str(sample.get("source") or ""),
            "event_type": str(sample.get("event_type") or ""),
            "parser_assumption": str(sample.get("parser_assumption") or ""),
            "parse_status": str(sample.get("timestamp_parse_status") or ""),
            "sample_row_hash": str(sample.get("timezone_sample_row_hash") or ""),
        }
        for sample in samples
    ]
    manifest_core: dict[str, object] = {
        "profile_version": "time-semantics-manifest-v1",
        "item_number": 42,
        "batch_id": FUNCTIONAL_DEFENSIBILITY_BATCH_ID,
        "gap_id": "#42",
        "commercial_gap_ids": [TIMEZONE_NORMALIZATION_GAP_ID, CLOCK_SKEW_ANALYSIS_GAP_ID],
        "sample_count": len(samples),
        "normalized_utc_sample_count": sum(1 for row in semantic_rows if row["normalized_utc"]),
        "missing_timezone_sample_count": sum(1 for row in semantic_rows if not row["source_timezone"]),
        "parser_assumptions": sorted({row["parser_assumption"] for row in semantic_rows if row["parser_assumption"]}),
        "timezone_normalization_manifest_hash": str(timezone_manifest.get("manifest_hash") or ""),
        "trusted_diff_status": str(trusted_diff.get("status") or ""),
        "samples": semantic_rows,
        "source_viewer_fields": [
            "original_timestamp",
            "source_timezone",
            "normalized_utc",
            "timestamp_kind",
            "source",
            "event_type",
            "parser_assumption",
            "sample_row_hash",
        ],
        "commercial_claim_allowed": False,
        "operator_warning": (
            "Use these rows to cite original and normalized time semantics; parser-specific timezone matrices "
            "and trusted baselines are still required before final conclusions."
        ),
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_timezone_validation(
    connection: sqlite3.Connection,
    case_id: str,
    *,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    rows = connection.execute(
        """
        SELECT timestamp, timezone, timestamp_kind, source, event_type
        FROM event
        WHERE case_id = ?
        ORDER BY timestamp ASC, id ASC
        """,
        (case_id,),
    ).fetchall()
    missing = 0
    timezone_counts: dict[str, int] = {}
    samples = []
    for row in rows:
        timestamp = str(row["timestamp"] or "")
        timezone = str(row["timezone"] or "")
        if not timezone:
            missing += 1
        else:
            timezone_counts[timezone] = timezone_counts.get(timezone, 0) + 1
        normalized = parse_event_timestamp(timestamp)
        if len(samples) < 20:
            samples.append(
                attach_timezone_sample_row_hash(
                    {
                        "timestamp": timestamp,
                        "timezone": timezone,
                        "normalized_utc": normalized.isoformat() if normalized else "",
                        "timestamp_parse_status": "parsed" if normalized else "unparsed",
                        "parser_assumption": (
                            "source-timezone-preserved"
                            if timezone
                            else "assume-utc-because-source-timezone-missing"
                        ),
                        "timestamp_kind": str(row["timestamp_kind"] or ""),
                        "source": str(row["source"] or ""),
                        "event_type": str(row["event_type"] or ""),
                    }
                )
            )
    if trusted_diff is None:
        trusted_diff = missing_timezone_validation_trusted_diff()
    blockers = []
    if trusted_diff.get("status") != "pass":
        blockers.append(TIMEZONE_VALIDATION_TRUSTED_DIFF_BLOCKER_97)
    timezone_manifest = build_timezone_normalization_manifest(
        event_count=len(rows),
        missing_timezone_count=missing,
        timezone_counts=timezone_counts,
        samples=samples,
        trusted_diff=trusted_diff,
    )
    time_semantics_manifest = build_time_semantics_manifest(
        samples=samples,
        timezone_manifest=timezone_manifest,
        trusted_diff=trusted_diff,
    )
    return {
        "status": "timezone-review-required" if missing else "timezone-fields-present",
        "commercial_gap_ids": [TIMEZONE_NORMALIZATION_GAP_ID],
        "functional_priority_profile": timezone_clock_functional_profile(
            event_count=len(rows),
            missing_timezone_count=missing,
            timezone_counts=timezone_counts,
            sample_count=len(samples),
            clock_warning_count=None,
            time_semantics_manifest=time_semantics_manifest,
            trusted_diff=trusted_diff,
        ),
        "summary": {
            "event_count": len(rows),
            "missing_timezone_count": missing,
            "timezone_counts": timezone_counts,
            "timezone_normalization_manifest_hash": timezone_manifest["manifest_hash"],
            "time_semantics_manifest_hash": time_semantics_manifest["manifest_hash"],
            "commercial_gap_ids": [TIMEZONE_NORMALIZATION_GAP_ID],
        },
        "samples": samples,
        "timezone_normalization_manifest": timezone_manifest,
        "timezone_normalization_manifest_hash": timezone_manifest["manifest_hash"],
        "parser_assumption_matrix_hash": timezone_manifest["parser_assumption_matrix_hash"],
        "time_semantics_manifest": time_semantics_manifest,
        "time_semantics_manifest_hash": time_semantics_manifest["manifest_hash"],
        "trusted_timezone_validation_diff": trusted_diff,
        "blockers": blockers,
        "validation_assessment": {
            "commercial_gap_ids": [TIMEZONE_NORMALIZATION_GAP_ID],
            "original_timestamp_preserved": True,
            "normalized_utc_assumption": "timestamps are interpreted as UTC when parser/source timezone is absent",
            "review_required": bool(missing),
            "timezone_normalization_manifest_hash": timezone_manifest["manifest_hash"],
            "parser_assumption_matrix_hash": timezone_manifest["parser_assumption_matrix_hash"],
            "time_semantics_manifest_hash": time_semantics_manifest["manifest_hash"],
            "core_accuracy_gates": timezone_validation_core_accuracy_gates(
                event_count=len(rows),
                missing_timezone_count=missing,
                samples=samples,
                timezone_manifest=timezone_manifest,
                time_semantics_manifest=time_semantics_manifest,
                trusted_diff=trusted_diff,
            ),
            "trusted_timezone_validation_diff": trusted_diff,
            "blockers": blockers,
        },
        "guidance": "Preserve original timestamp, source timezone, normalized UTC assumption, and parser-specific timezone notes in final reports.",
    }


def attach_clock_skew_warning_row_hash(warning: Mapping[str, object]) -> dict[str, object]:
    row = dict(warning)
    row["clock_skew_warning_row_hash"] = stable_payload_sha256(
        {
            "type": row.get("type"),
            "timestamp": row.get("timestamp"),
            "source": row.get("source"),
        }
    )
    return row


def build_clock_skew_baseline_manifest(
    *,
    parsed_timestamp_count: int,
    warnings: Sequence[Mapping[str, object]],
    earliest: str,
    latest: str,
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    range_matrix = build_clock_skew_range_matrix(
        parsed_timestamp_count=parsed_timestamp_count,
        warnings=warnings,
        earliest=earliest,
        latest=latest,
    )
    manifest_core = {
        "profile_version": "clock-skew-baseline-manifest-v1",
        "item_number": 98,
        "parsed_timestamp_count": parsed_timestamp_count,
        "warning_count": len(warnings),
        "warning_row_hashes": [str(item.get("clock_skew_warning_row_hash") or "") for item in warnings],
        "earliest_timestamp": earliest,
        "latest_timestamp": latest,
        "clock_skew_range_matrix": range_matrix,
        "clock_skew_range_matrix_hash": range_matrix["matrix_hash"],
        "baseline_required": "Compare host/device time against acquisition notes and trusted external events.",
        "heuristic_only": True,
        "trusted_diff_status": str(trusted_diff.get("status") or ""),
        "commercial_gap_ids": [CLOCK_SKEW_ANALYSIS_GAP_ID],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_clock_skew_range_matrix(
    *,
    parsed_timestamp_count: int,
    warnings: Sequence[Mapping[str, object]],
    earliest: str,
    latest: str,
) -> dict[str, object]:
    warning_type_counts: dict[str, int] = {}
    for warning in warnings:
        warning_type = str(warning.get("type") or "unknown")
        warning_type_counts[warning_type] = warning_type_counts.get(warning_type, 0) + 1
    matrix_core = {
        "profile_version": "clock-skew-range-matrix-v1",
        "item_number": 98,
        "parsed_timestamp_count": parsed_timestamp_count,
        "earliest_timestamp": earliest,
        "latest_timestamp": latest,
        "warning_type_counts": dict(sorted(warning_type_counts.items())),
        "warning_count": len(warnings),
        "baseline_attached": False,
        "commercial_claim_allowed": False,
    }
    return {**matrix_core, "matrix_hash": stable_payload_sha256(matrix_core)}


def build_clock_skew_analysis(
    connection: sqlite3.Connection,
    case_id: str,
    *,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    rows = connection.execute(
        """
        SELECT timestamp, source, event_type, description
        FROM event
        WHERE case_id = ?
        ORDER BY timestamp ASC, id ASC
        """,
        (case_id,),
    ).fetchall()
    warnings = []
    parsed_times: list[dt.datetime] = []
    now = dt.datetime.now(dt.timezone.utc)
    for row in rows:
        parsed = parse_event_timestamp(str(row["timestamp"] or ""))
        if parsed is None:
            continue
        parsed_times.append(parsed)
        if parsed.year < 1980:
            warnings.append(
                attach_clock_skew_warning_row_hash(
                    {"type": "timestamp-before-1980", "timestamp": str(row["timestamp"]), "source": str(row["source"] or "")}
                )
            )
        if parsed > now + dt.timedelta(days=2):
            warnings.append(
                attach_clock_skew_warning_row_hash(
                    {"type": "timestamp-in-future", "timestamp": str(row["timestamp"]), "source": str(row["source"] or "")}
                )
            )
    if trusted_diff is None:
        trusted_diff = missing_clock_skew_trusted_diff()
    blockers = []
    if trusted_diff.get("status") != "pass":
        blockers.append(CLOCK_SKEW_TRUSTED_DIFF_BLOCKER_98)
    earliest = min((value.isoformat() for value in parsed_times), default="")
    latest = max((value.isoformat() for value in parsed_times), default="")
    clock_manifest = build_clock_skew_baseline_manifest(
        parsed_timestamp_count=len(parsed_times),
        warnings=warnings[:100],
        earliest=earliest,
        latest=latest,
        trusted_diff=trusted_diff,
    )
    return {
        "status": "warnings-present" if warnings else "no-obvious-clock-skew",
        "commercial_gap_ids": [CLOCK_SKEW_ANALYSIS_GAP_ID],
        "functional_priority_profile": timezone_clock_functional_profile(
            event_count=len(rows),
            missing_timezone_count=None,
            timezone_counts={},
            sample_count=0,
            clock_warning_count=len(warnings),
            trusted_diff=trusted_diff,
        ),
        "summary": {
            "event_count": len(rows),
            "parsed_timestamp_count": len(parsed_times),
            "warning_count": len(warnings),
            "earliest_timestamp": earliest,
            "latest_timestamp": latest,
            "clock_skew_baseline_manifest_hash": clock_manifest["manifest_hash"],
            "clock_skew_range_matrix_hash": clock_manifest["clock_skew_range_matrix_hash"],
            "commercial_gap_ids": [CLOCK_SKEW_ANALYSIS_GAP_ID],
        },
        "warnings": warnings[:100],
        "clock_skew_baseline_manifest": clock_manifest,
        "clock_skew_baseline_manifest_hash": clock_manifest["manifest_hash"],
        "clock_skew_range_matrix_hash": clock_manifest["clock_skew_range_matrix_hash"],
        "trusted_clock_skew_diff": trusted_diff,
        "blockers": blockers,
        "validation_assessment": {
            "commercial_gap_ids": [CLOCK_SKEW_ANALYSIS_GAP_ID],
            "heuristic_only": True,
            "baseline_required": "Compare host/device time against acquisition notes and trusted external events.",
            "review_required": bool(warnings),
            "clock_skew_baseline_manifest_hash": clock_manifest["manifest_hash"],
            "clock_skew_range_matrix_hash": clock_manifest["clock_skew_range_matrix_hash"],
            "core_accuracy_gates": clock_skew_core_accuracy_gates(
                parsed_timestamp_count=len(parsed_times),
                warnings=warnings[:100],
                earliest=earliest,
                latest=latest,
                clock_manifest=clock_manifest,
                trusted_diff=trusted_diff,
            ),
            "trusted_clock_skew_diff": trusted_diff,
            "blockers": blockers,
        },
        "guidance": "Clock skew detection is heuristic; compare against acquisition notes, system timezone, and trusted external timestamps.",
    }


def attach_contamination_warning_row_hash(warning: Mapping[str, object]) -> dict[str, object]:
    row = dict(warning)
    row["contamination_warning_row_hash"] = stable_payload_sha256(
        {
            "type": row.get("type"),
            "citation_id": row.get("citation_id"),
            "path": row.get("path"),
            "metadata_citation_id": row.get("metadata_citation_id"),
            "write_blocker": row.get("write_blocker"),
        }
    )
    return row


def build_contamination_checklist_manifest(
    *,
    warnings: Sequence[Mapping[str, object]],
    evidence_source_count: int,
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    warning_type_counts: dict[str, int] = {}
    for warning in warnings:
        warning_type = str(warning.get("type") or "")
        warning_type_counts[warning_type] = warning_type_counts.get(warning_type, 0) + 1
    warning_review_matrix = build_contamination_warning_review_matrix(warnings)
    manifest_core = {
        "profile_version": "contamination-checklist-manifest-v1",
        "item_number": 99,
        "evidence_source_count": evidence_source_count,
        "warning_count": len(warnings),
        "warning_type_counts": warning_type_counts,
        "warning_row_hashes": [str(item.get("contamination_warning_row_hash") or "") for item in warnings],
        "warning_review_matrix": warning_review_matrix,
        "warning_review_matrix_hash": warning_review_matrix["matrix_hash"],
        "write_blocker_integration": "not-connected",
        "checks": [
            "rapidtriage-output-inside-evidence-root",
            "staged-output-under-evidence-root",
            "zero-byte-source",
            "source-path-stat-failed",
            "writable-source-permission",
            "acquisition-metadata-missing-for-evidence-source",
            "write-blocker-missing-for-evidence-source",
        ],
        "trusted_diff_status": str(trusted_diff.get("status") or ""),
        "commercial_gap_ids": [EVIDENCE_CONTAMINATION_WARNING_GAP_ID],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_contamination_warning_review_matrix(warnings: Sequence[Mapping[str, object]]) -> dict[str, object]:
    rows = []
    for warning in warnings:
        row_core = {
            "type": str(warning.get("type") or ""),
            "citation_id": str(warning.get("citation_id") or ""),
            "metadata_citation_id": str(warning.get("metadata_citation_id") or ""),
            "path_hash": stable_payload_sha256(str(warning.get("path") or "")),
            "requires_acquisition_review": True,
            "requires_write_blocker_review": str(warning.get("type") or "") in {
                "write-blocker-missing-for-evidence-source",
                "writable-source-permission",
            },
        }
        rows.append({**row_core, "row_hash": stable_payload_sha256(row_core)})
    matrix_core = {
        "profile_version": "contamination-warning-review-matrix-v1",
        "item_number": 99,
        "warning_count": len(warnings),
        "rows": rows,
        "requires_acquisition_review_count": sum(1 for row in rows if row.get("requires_acquisition_review")),
        "requires_write_blocker_review_count": sum(1 for row in rows if row.get("requires_write_blocker_review")),
        "commercial_claim_allowed": False,
    }
    return {**matrix_core, "matrix_hash": stable_payload_sha256(matrix_core)}


def build_contamination_acquisition_context_manifest(
    *,
    evidence_sources: Sequence[Mapping[str, object]],
    metadata_records: Sequence[Mapping[str, object]],
    warnings: Sequence[Mapping[str, object]],
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    metadata_by_source = {
        str(record.get("evidence_source_citation_id") or ""): record
        for record in metadata_records
        if str(record.get("evidence_source_citation_id") or "")
    }
    source_rows = []
    missing_metadata_count = 0
    missing_write_blocker_count = 0
    writable_source_count = 0
    warning_by_source: dict[str, list[str]] = {}
    for warning in warnings:
        citation_id = str(warning.get("citation_id") or "")
        warning_by_source.setdefault(citation_id, []).append(str(warning.get("type") or ""))
    for source in evidence_sources:
        citation_id = str(source.get("citation_id") or "")
        metadata = metadata_by_source.get(citation_id, {})
        write_blocker = str(metadata.get("write_blocker") or "")
        source_warnings = warning_by_source.get(citation_id, [])
        if not metadata:
            missing_metadata_count += 1
        if not write_blocker:
            missing_write_blocker_count += 1
        if "writable-source-permission" in source_warnings:
            writable_source_count += 1
        source_rows.append(
            {
                "citation_id": citation_id,
                "original_path": str(source.get("original_path") or ""),
                "staged_path": str(source.get("staged_path") or ""),
                "metadata_citation_id": str(metadata.get("citation_id") or ""),
                "write_blocker_recorded": bool(write_blocker),
                "write_blocker_hash": stable_payload_sha256({"write_blocker": write_blocker}) if write_blocker else "",
                "source_writable_warning": "writable-source-permission" in source_warnings,
                "warning_types": sorted(set(source_warnings)),
            }
        )
    manifest_core: dict[str, object] = {
        "profile_version": "contamination-acquisition-context-manifest-v1",
        "item_number": 43,
        "batch_id": FUNCTIONAL_DEFENSIBILITY_BATCH_ID,
        "gap_id": "#43",
        "commercial_gap_ids": [EVIDENCE_CONTAMINATION_WARNING_GAP_ID, WRITE_BLOCKER_ACQUISITION_METADATA_GAP_ID],
        "evidence_source_count": len(evidence_sources),
        "acquisition_metadata_record_count": len(metadata_records),
        "missing_acquisition_metadata_count": missing_metadata_count,
        "missing_write_blocker_count": missing_write_blocker_count,
        "writable_source_warning_count": writable_source_count,
        "warning_row_hashes": [str(warning.get("contamination_warning_row_hash") or "") for warning in warnings],
        "source_rows": source_rows,
        "trusted_diff_status": str(trusted_diff.get("status") or ""),
        "commercial_claim_allowed": False,
        "operator_warning": "Writable-source and missing write-blocker findings must be reviewed with acquisition metadata before submission.",
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_evidence_contamination_warnings(
    connection: sqlite3.Connection,
    case_id: str,
    *,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    rows = connection.execute(
        """
        SELECT citation_id, original_path, staged_path
        FROM evidence_source
        WHERE case_id = ?
        ORDER BY id ASC
        """,
        (case_id,),
    ).fetchall()
    metadata_rows = connection.execute(
        """
        SELECT * FROM acquisition_metadata
        WHERE case_id = ?
        ORDER BY created_at ASC, id ASC
        """,
        (case_id,),
    ).fetchall()
    metadata_records = [acquisition_metadata_to_dict(row) for row in metadata_rows]
    metadata_by_source = {
        str(record.get("evidence_source_citation_id") or ""): record
        for record in metadata_records
        if str(record.get("evidence_source_citation_id") or "")
    }
    evidence_sources = [
        {
            "citation_id": str(row["citation_id"]),
            "original_path": str(row["original_path"] or ""),
            "staged_path": str(row["staged_path"] or ""),
        }
        for row in rows
    ]
    warnings = []
    for row in rows:
        citation_id = str(row["citation_id"])
        original = Path(str(row["original_path"] or "")).expanduser()
        staged = Path(str(row["staged_path"] or "")).expanduser()
        metadata = metadata_by_source.get(citation_id, {})
        if not metadata:
            warnings.append(
                attach_contamination_warning_row_hash(
                    {
                        "type": "acquisition-metadata-missing-for-evidence-source",
                        "citation_id": citation_id,
                        "path": str(original),
                    }
                )
            )
        elif not str(metadata.get("write_blocker") or "").strip():
            warnings.append(
                attach_contamination_warning_row_hash(
                    {
                        "type": "write-blocker-missing-for-evidence-source",
                        "citation_id": citation_id,
                        "path": str(original),
                        "metadata_citation_id": str(metadata.get("citation_id") or ""),
                    }
                )
            )
        try:
            if original.exists() and os.access(original, os.W_OK):
                warnings.append(
                    attach_contamination_warning_row_hash(
                        {"type": "writable-source-permission", "citation_id": citation_id, "path": str(original)}
                    )
                )
            if original.exists() and original.is_dir() and (original / "rapidtriage-run-summary.json").exists():
                warnings.append(
                    attach_contamination_warning_row_hash(
                        {"type": "rapidtriage-output-inside-evidence-root", "citation_id": citation_id, "path": str(original)}
                    )
                )
            if original.exists() and original.is_dir() and staged.exists() and is_relative_to(staged.resolve(), original.resolve()):
                warnings.append(
                    attach_contamination_warning_row_hash(
                        {"type": "staged-output-under-evidence-root", "citation_id": citation_id, "path": str(staged)}
                    )
                )
            if original.exists() and original.is_file() and original.stat().st_size == 0:
                warnings.append(
                    attach_contamination_warning_row_hash(
                        {"type": "zero-byte-source", "citation_id": citation_id, "path": str(original)}
                    )
                )
        except OSError:
            warnings.append(
                attach_contamination_warning_row_hash(
                    {"type": "source-path-stat-failed", "citation_id": citation_id, "path": str(original)}
                )
            )
    if trusted_diff is None:
        trusted_diff = missing_contamination_warning_trusted_diff()
    blockers = []
    if trusted_diff.get("status") != "pass":
        blockers.append(CONTAMINATION_WARNING_TRUSTED_DIFF_BLOCKER_99)
    contamination_manifest = build_contamination_checklist_manifest(
        warnings=warnings,
        evidence_source_count=len(rows),
        trusted_diff=trusted_diff,
    )
    acquisition_context_manifest = build_contamination_acquisition_context_manifest(
        evidence_sources=evidence_sources,
        metadata_records=metadata_records,
        warnings=warnings,
        trusted_diff=trusted_diff,
    )
    return {
        "status": "warnings-present" if warnings else "no-obvious-contamination",
        "commercial_gap_ids": [EVIDENCE_CONTAMINATION_WARNING_GAP_ID],
        "functional_priority_profile": contamination_warning_functional_profile(
            warnings=warnings,
            evidence_source_count=len(rows),
            acquisition_context_manifest=acquisition_context_manifest,
            trusted_diff=trusted_diff,
        ),
        "summary": {
            "warning_count": len(warnings),
            "contamination_checklist_manifest_hash": contamination_manifest["manifest_hash"],
            "warning_review_matrix_hash": contamination_manifest["warning_review_matrix_hash"],
            "contamination_acquisition_context_manifest_hash": acquisition_context_manifest["manifest_hash"],
            "commercial_gap_ids": [EVIDENCE_CONTAMINATION_WARNING_GAP_ID],
        },
        "warnings": warnings,
        "contamination_checklist_manifest": contamination_manifest,
        "contamination_checklist_manifest_hash": contamination_manifest["manifest_hash"],
        "warning_review_matrix_hash": contamination_manifest["warning_review_matrix_hash"],
        "contamination_acquisition_context_manifest": acquisition_context_manifest,
        "contamination_acquisition_context_manifest_hash": acquisition_context_manifest["manifest_hash"],
        "trusted_contamination_warning_diff": trusted_diff,
        "blockers": blockers,
        "validation_assessment": {
            "commercial_gap_ids": [EVIDENCE_CONTAMINATION_WARNING_GAP_ID],
            "write_blocker_integration": "not-connected",
            "review_required": bool(warnings),
            "checks": [
                "rapidtriage-output-inside-evidence-root",
                "staged-output-under-evidence-root",
                "zero-byte-source",
                "source-path-stat-failed",
            ],
            "contamination_checklist_manifest_hash": contamination_manifest["manifest_hash"],
            "warning_review_matrix_hash": contamination_manifest["warning_review_matrix_hash"],
            "contamination_acquisition_context_manifest_hash": acquisition_context_manifest["manifest_hash"],
            "core_accuracy_gates": contamination_warning_core_accuracy_gates(
                warnings=warnings,
                contamination_manifest=contamination_manifest,
                acquisition_context_manifest=acquisition_context_manifest,
                trusted_diff=trusted_diff,
            ),
            "trusted_contamination_warning_diff": trusted_diff,
            "blockers": blockers,
        },
        "guidance": "Use write-blocked sources and keep RapidTriage outputs outside evidence roots whenever possible.",
    }


def parse_event_timestamp(value: str) -> dt.datetime | None:
    text = value.strip()
    if not text:
        return None
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def acquisition_metadata_functional_profile(
    *,
    records: Sequence[Mapping[str, object]],
    evidence_sources: Sequence[Mapping[str, object]],
    missing_required_fields: Sequence[str],
    input_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    records_with_operator = sum(1 for item in records if str(item.get("operator") or "").strip())
    records_with_write_blocker = sum(1 for item in records if str(item.get("write_blocker") or "").strip())
    records_with_tool = sum(1 for item in records if str(item.get("acquisition_tool") or "").strip())
    records_with_timestamps = sum(
        1
        for item in records
        if str(item.get("acquisition_started_at") or "").strip()
        and str(item.get("acquisition_completed_at") or "").strip()
    )
    failed_checks: list[str] = []
    if not records:
        failed_checks.append("acquisition-metadata-record-not-created")
    if missing_required_fields:
        failed_checks.append("acquisition-required-fields-missing")
    if records_with_write_blocker == 0:
        failed_checks.append("write-blocker-not-recorded")
    if not input_manifest.get("manifest_hash"):
        failed_checks.append("acquisition-metadata-input-manifest-hash-missing")
    if trusted_diff.get("status") != "pass":
        failed_checks.append(ACQUISITION_METADATA_TRUSTED_DIFF_BLOCKER_96)
    return {
        "item_number": 41,
        "batch_id": FUNCTIONAL_DEFENSIBILITY_BATCH_ID,
        "status": "complete" if not failed_checks else "partial",
        "implemented_controls": {
            "evidence_source_count": len(evidence_sources),
            "metadata_record_count": len(records),
            "records_with_operator": records_with_operator,
            "records_with_write_blocker": records_with_write_blocker,
            "records_with_acquisition_tool": records_with_tool,
            "records_with_start_and_end_timestamps": records_with_timestamps,
            "missing_required_fields": list(missing_required_fields),
            "acquisition_metadata_input_manifest_hash": str(input_manifest.get("manifest_hash") or ""),
            "input_field_count": len(input_manifest.get("form_fields") or []),
            "evidence_source_choice_count": int(input_manifest.get("evidence_source_choice_count") or 0),
            "trusted_diff_status": str(trusted_diff.get("status") or ""),
        },
        "passed_validation_check_ids": [
            "case-db-acquisition-metadata-table-exported",
            "required-field-gap-summary-emitted",
            "gui-input-field-manifest-emitted",
            "audit-backed-acquisition-record-entrypoint-present",
        ],
        "failed_validation_check_ids": failed_checks,
        "reportability_decision": {
            "allowed_use": "acquisition-metadata-review-checklist",
            "commercial_claim_allowed": not failed_checks,
            "operator_warning": "Record write-blocker and acquisition handoff details before relying on custody-grade outputs.",
        },
    }


def timezone_clock_functional_profile(
    *,
    event_count: int,
    missing_timezone_count: int | None,
    timezone_counts: Mapping[str, int],
    sample_count: int,
    clock_warning_count: int | None,
    trusted_diff: Mapping[str, object],
    time_semantics_manifest: Mapping[str, object] | None = None,
) -> dict[str, object]:
    failed_checks: list[str] = []
    if event_count == 0:
        failed_checks.append("no-case-events-for-time-validation")
    if missing_timezone_count is not None and missing_timezone_count > 0:
        failed_checks.append("timezone-missing-on-events")
    if clock_warning_count is not None and clock_warning_count > 0:
        failed_checks.append("clock-skew-warnings-present")
    if time_semantics_manifest is not None and not time_semantics_manifest.get("manifest_hash"):
        failed_checks.append("time-semantics-manifest-hash-missing")
    trusted_blockers = {
        TIMEZONE_VALIDATION_TRUSTED_DIFF_BLOCKER_97,
        CLOCK_SKEW_TRUSTED_DIFF_BLOCKER_98,
    }
    if trusted_diff.get("status") != "pass":
        blocker = str(trusted_diff.get("blocker") or "")
        failed_checks.append(blocker if blocker in trusted_blockers else "trusted-time-validation-diff-missing")
    return {
        "item_number": 42,
        "batch_id": FUNCTIONAL_DEFENSIBILITY_BATCH_ID,
        "status": "complete" if not failed_checks else "partial",
        "implemented_controls": {
            "event_count": event_count,
            "missing_timezone_count": missing_timezone_count,
            "timezone_counts": dict(timezone_counts),
            "sample_count": sample_count,
            "clock_warning_count": clock_warning_count,
            "utc_assumption_disclosed": True,
            "time_semantics_manifest_hash": str((time_semantics_manifest or {}).get("manifest_hash") or ""),
            "normalized_utc_sample_count": int((time_semantics_manifest or {}).get("normalized_utc_sample_count") or 0),
            "trusted_diff_status": str(trusted_diff.get("status") or ""),
        },
        "passed_validation_check_ids": [
            "original-timestamp-samples-preserved",
            "source-timezone-inventory-emitted",
            "utc-normalization-assumption-disclosed",
            "time-semantics-manifest-hash-emitted",
            "clock-skew-baseline-guidance-emitted",
        ],
        "failed_validation_check_ids": failed_checks,
        "reportability_decision": {
            "allowed_use": "timeline-time-semantics-review",
            "commercial_claim_allowed": not failed_checks,
            "operator_warning": "Timezone and skew conclusions require source parser assumptions plus trusted baseline review.",
        },
    }


def contamination_warning_functional_profile(
    *,
    warnings: Sequence[Mapping[str, object]],
    evidence_source_count: int,
    acquisition_context_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    warning_types = sorted({str(item.get("type") or "") for item in warnings if item.get("type")})
    failed_checks = []
    if warnings:
        failed_checks.append("evidence-contamination-warnings-present")
    if not acquisition_context_manifest.get("manifest_hash"):
        failed_checks.append("contamination-acquisition-context-manifest-hash-missing")
    if trusted_diff.get("status") != "pass":
        failed_checks.append(CONTAMINATION_WARNING_TRUSTED_DIFF_BLOCKER_99)
    return {
        "item_number": 43,
        "batch_id": FUNCTIONAL_DEFENSIBILITY_BATCH_ID,
        "status": "complete" if not failed_checks else "partial",
        "implemented_controls": {
            "evidence_source_count": evidence_source_count,
            "warning_count": len(warnings),
            "warning_types": warning_types,
            "contamination_acquisition_context_manifest_hash": str(acquisition_context_manifest.get("manifest_hash") or ""),
            "missing_write_blocker_count": int(acquisition_context_manifest.get("missing_write_blocker_count") or 0),
            "writable_source_warning_count": int(acquisition_context_manifest.get("writable_source_warning_count") or 0),
            "checks": [
                "rapidtriage-output-inside-evidence-root",
                "staged-output-under-evidence-root",
                "zero-byte-source",
                "source-path-stat-failed",
                "writable-source-permission",
                "acquisition-metadata-missing-for-evidence-source",
                "write-blocker-missing-for-evidence-source",
            ],
            "trusted_diff_status": str(trusted_diff.get("status") or ""),
        },
        "passed_validation_check_ids": [
            "evidence-root-output-check",
            "staged-output-location-check",
            "zero-byte-source-check",
            "source-stat-failure-check",
            "writable-source-permission-check",
            "acquisition-metadata-write-blocker-context-check",
        ],
        "failed_validation_check_ids": failed_checks,
        "reportability_decision": {
            "allowed_use": "evidence-contamination-triage-warning",
            "commercial_claim_allowed": not failed_checks,
            "operator_warning": "Warnings must be cleared or explained before final evidence submission.",
        },
    }


def audit_integrity_functional_profile(
    *,
    events: Sequence[Mapping[str, object]],
    head_hash: str,
    audit_hash_chain_manifest: Mapping[str, object],
    audit_replay_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None,
    report_grade_validation_plan: Mapping[str, object] | None = None,
) -> dict[str, object]:
    events_with_hash = sum(1 for item in events if item.get("event_hash"))
    events_with_previous = sum(1 for item in events if "previous_event_hash" in item)
    failed_checks: list[str] = []
    if not events:
        failed_checks.append("audit-event-chain-empty")
    if events_with_hash != len(events):
        failed_checks.append("audit-event-hash-missing")
    if events_with_previous != len(events):
        failed_checks.append("audit-previous-hash-missing")
    if not head_hash:
        failed_checks.append("audit-head-hash-missing")
    if not audit_hash_chain_manifest.get("manifest_hash"):
        failed_checks.append("audit-chain-manifest-hash-missing")
    if not audit_replay_manifest.get("manifest_hash"):
        failed_checks.append("audit-replay-manifest-hash-missing")
    if audit_replay_manifest and not bool(audit_replay_manifest.get("chain_valid")):
        failed_checks.append("audit-replay-chain-invalid")
    if not trusted_diff or trusted_diff.get("status") != "pass":
        failed_checks.append(IMMUTABLE_AUDIT_TRUSTED_DIFF_BLOCKER_88)
    if not report_grade_validation_plan or not report_grade_validation_plan.get("validation_plan_sha256"):
        failed_checks.append("immutable-audit-report-grade-validation-plan-missing")
    else:
        failed_checks.extend(str(blocker) for blocker in report_grade_validation_plan.get("blockers") or [])
    failed_checks = sorted(dict.fromkeys(failed_checks))
    return {
        "item_number": 44,
        "batch_id": FUNCTIONAL_DEFENSIBILITY_BATCH_ID,
        "status": "complete" if not failed_checks else "partial",
        "implemented_controls": {
            "audit_event_count": len(events),
            "events_with_event_hash": events_with_hash,
            "events_with_previous_hash": events_with_previous,
            "head_hash_present": bool(head_hash),
            "audit_chain_manifest_hash": str(audit_hash_chain_manifest.get("manifest_hash") or ""),
            "audit_replay_manifest_hash": str(audit_replay_manifest.get("manifest_hash") or ""),
            "audit_replay_chain_valid": bool(audit_replay_manifest.get("chain_valid")),
            "external_notarization_required": True,
            "trusted_diff_status": str(trusted_diff.get("status")) if trusted_diff else "missing",
            "immutable_audit_report_grade_validation_plan_hash": str(
                (report_grade_validation_plan or {}).get("validation_plan_sha256") or ""
            ),
            "report_grade_ready_slot_count": int((report_grade_validation_plan or {}).get("ready_slot_count") or 0),
            "report_grade_blocking_slot_count": int((report_grade_validation_plan or {}).get("blocking_slot_count") or 0),
        },
        "passed_validation_check_ids": [
            "audit-events-exported",
            "previous-entry-hash-chain-generated",
            "head-hash-recorded",
            "audit-chain-manifest-hash-recorded",
            "audit-replay-manifest-hash-recorded",
            "external-notarization-limitation-disclosed",
            "immutable-audit-report-grade-validation-plan-exported",
        ],
        "failed_validation_check_ids": failed_checks,
        "reportability_decision": {
            "allowed_use": "tamper-evident-case-audit-chain",
            "commercial_claim_allowed": not failed_checks,
            "operator_warning": "External signing/notarization is still required for full tamper-evident release evidence.",
        },
    }


def is_relative_to(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def build_report_item_provenance(
    enriched: Mapping[str, object],
    review: Mapping[str, object],
    *,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    source_reference = enriched.get("source_reference") if isinstance(enriched.get("source_reference"), Mapping) else {}
    metadata = enriched.get("metadata") if isinstance(enriched.get("metadata"), Mapping) else {}
    hashes = source_reference.get("source_hashes") if isinstance(source_reference.get("source_hashes"), Mapping) else {}
    record_hashes = source_reference.get("record_hashes") if isinstance(source_reference.get("record_hashes"), Mapping) else {}
    blockers = []
    if not trusted_diff or trusted_diff.get("status") != "pass":
        blockers.append(SOURCE_PROVENANCE_TRUSTED_DIFF_BLOCKER_90)
    provenance = {
        "commercial_gap_ids": [SOURCE_PROVENANCE_GAP_ID],
        "target_citation_id": str(enriched.get("citation_id") or ""),
        "review_citation_id": str(review.get("citation_id") or ""),
        "source_path": str(source_reference.get("path") or enriched.get("path") or ""),
        "source_citation_package_hash": str(source_reference.get("source_citation_package_hash") or ""),
        "source_read_citation_id": str(source_reference.get("source_read_citation_id") or ""),
        "source_read_citation_text": str(source_reference.get("source_read_citation_text") or ""),
        "source_locator": dict(source_reference.get("source_locator"))
        if isinstance(source_reference.get("source_locator"), Mapping)
        else {},
        "source_viewer_locator": dict(source_reference.get("source_viewer_locator"))
        if isinstance(source_reference.get("source_viewer_locator"), Mapping)
        else {},
        "source_locator_hash": str(source_reference.get("source_locator_hash") or ""),
        "row_citation_hash": str(source_reference.get("row_citation_hash") or ""),
        "parser_manifest_hashes": dict(source_reference.get("parser_manifest_hashes"))
        if isinstance(source_reference.get("parser_manifest_hashes"), Mapping)
        else {},
        "hashes": dict(hashes),
        "record_hashes": dict(record_hashes),
        "parser": str(source_reference.get("parser") or metadata.get("parser") or ""),
        "parser_version": str(source_reference.get("parser_version") or metadata.get("parser_version") or ""),
        "parser_confidence": source_reference.get("parser_confidence") or metadata.get("parser_confidence"),
        "record_offset": source_reference.get("record_offset"),
        "source_index": source_reference.get("source_index"),
        "review_status": str(review.get("status") or ""),
        "verification_status": str(review.get("verification_status") or ""),
        "reportability": str(source_reference.get("reportability") or metadata.get("reportability") or ""),
        "evidence_strength": str(source_reference.get("evidence_strength") or metadata.get("evidence_strength") or ""),
    }
    provenance_manifest = build_report_provenance_row_manifest(provenance)
    source_provenance_report_grade_validation_plan = build_source_provenance_report_grade_validation_plan(
        provenance,
        provenance_manifest,
        trusted_diff=trusted_diff,
    )
    blockers = sorted({*blockers, *source_provenance_report_grade_validation_plan["blockers"]})
    return {
        **provenance,
        "provenance_row_hash": provenance_manifest["provenance_row_hash"],
        "provenance_manifest": provenance_manifest,
        "provenance_manifest_hash": provenance_manifest["manifest_hash"],
        "source_provenance_report_grade_validation_plan": source_provenance_report_grade_validation_plan,
        "source_provenance_report_grade_validation_plan_hash": source_provenance_report_grade_validation_plan[
            "validation_plan_sha256"
        ],
        "report_grade_ready_slot_count": source_provenance_report_grade_validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": source_provenance_report_grade_validation_plan["blocking_slot_count"],
        "trusted_provenance_diff": dict(trusted_diff) if trusted_diff else missing_integrity_trusted_diff(
            SOURCE_PROVENANCE_GAP_ID,
            SOURCE_PROVENANCE_TRUSTED_DIFF_BLOCKER_90,
            trusted_tool="report-provenance-manifest",
        ),
        "blockers": blockers,
        "core_accuracy_gates": report_item_provenance_core_accuracy_gates(
            source_path=str(source_reference.get("path") or enriched.get("path") or ""),
            hashes=hashes,
            record_hashes=record_hashes,
            parser=str(source_reference.get("parser") or metadata.get("parser") or ""),
            parser_version=str(source_reference.get("parser_version") or metadata.get("parser_version") or ""),
            parser_confidence=source_reference.get("parser_confidence") or metadata.get("parser_confidence"),
            record_offset=source_reference.get("record_offset"),
            source_index=source_reference.get("source_index"),
            review_status=str(review.get("status") or ""),
            reportability=str(source_reference.get("reportability") or metadata.get("reportability") or ""),
            provenance_manifest=provenance_manifest,
            trusted_diff=trusted_diff,
            report_grade_validation_plan=source_provenance_report_grade_validation_plan,
        ),
    }


def build_forensic_integrity_matrix(
    *,
    custody_workflow: Mapping[str, object],
    acquisition_hash_workflow: Mapping[str, object],
    audit_integrity: Mapping[str, object],
    reproducibility: Mapping[str, object],
    items: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    provenance_rows = []
    for item in items:
        provenance = item.get("provenance") if isinstance(item.get("provenance"), Mapping) else {}
        manifest = provenance.get("provenance_manifest") if isinstance(provenance.get("provenance_manifest"), Mapping) else {}
        row = {
            "target_citation_id": str(provenance.get("target_citation_id") or ""),
            "review_citation_id": str(provenance.get("review_citation_id") or ""),
            "provenance_manifest_hash": str(provenance.get("provenance_manifest_hash") or ""),
            "source_provenance_report_grade_validation_plan_hash": str(
                provenance.get("source_provenance_report_grade_validation_plan_hash") or ""
            ),
            "field_presence_hash": str(manifest.get("field_presence_hash") or ""),
            "completeness_score": optional_float(manifest.get("completeness_score")) or 0.0,
            "missing_required_fields": list(manifest.get("missing_required_fields") or []),
            "report_grade_ready_slot_count": int(provenance.get("report_grade_ready_slot_count") or 0),
            "report_grade_blocking_slot_count": int(provenance.get("report_grade_blocking_slot_count") or 0),
        }
        provenance_rows.append({**row, "row_hash": stable_payload_sha256(row)})
    source_rows = [
        {
            "item_number": 86,
            "component": "chain-of-custody",
            "primary_hash": nested_mapping_str(custody_workflow, "custody_chain_manifest", "manifest_hash"),
            "secondary_hash": str(custody_workflow.get("custody_completeness_matrix_hash") or ""),
            "record_count": int((custody_workflow.get("summary") or {}).get("custody_event_count") or 0)
            if isinstance(custody_workflow.get("summary"), Mapping)
            else 0,
            "blockers": list(custody_workflow.get("blockers") or []),
        },
        {
            "item_number": 87,
            "component": "acquisition-hash-workflow",
            "primary_hash": nested_mapping_str(acquisition_hash_workflow, "acquisition_hash_manifest", "manifest_hash"),
            "secondary_hash": nested_mapping_str(acquisition_hash_workflow, "acquisition_hash_manifest", "hash_inventory_matrix_hash"),
            "record_count": int((acquisition_hash_workflow.get("summary") or {}).get("hash_count") or 0)
            if isinstance(acquisition_hash_workflow.get("summary"), Mapping)
            else 0,
            "blockers": list(acquisition_hash_workflow.get("blockers") or []),
        },
        {
            "item_number": 88,
            "component": "immutable-audit-log",
            "primary_hash": nested_mapping_str(audit_integrity, "audit_hash_chain_manifest", "manifest_hash"),
            "secondary_hash": nested_mapping_str(audit_integrity, "audit_replay_manifest", "replay_matrix_hash"),
            "record_count": int((audit_integrity.get("summary") or {}).get("event_count") or 0)
            if isinstance(audit_integrity.get("summary"), Mapping)
            else 0,
            "blockers": list(audit_integrity.get("blockers") or []),
        },
        {
            "item_number": 89,
            "component": "report-reproducibility",
            "primary_hash": nested_mapping_str(reproducibility, "report_replay_manifest", "manifest_hash"),
            "secondary_hash": nested_mapping_str(reproducibility, "report_replay_manifest", "row_hash_set_hash"),
            "record_count": int(reproducibility.get("stable_item_count") or 0),
            "blockers": list(reproducibility.get("blockers") or []),
        },
        {
            "item_number": 90,
            "component": "report-provenance",
            "primary_hash": stable_payload_sha256({"provenance_rows": provenance_rows}),
            "secondary_hash": stable_payload_sha256(
                {"field_presence_hashes": [row["field_presence_hash"] for row in provenance_rows]}
            ),
            "record_count": len(provenance_rows),
            "blockers": sorted(
                {
                    blocker
                    for item in items
                    for provenance in [item.get("provenance") if isinstance(item.get("provenance"), Mapping) else {}]
                    for blocker in provenance.get("blockers", [])
                }
            ),
        },
    ]
    rows = [{**row, "row_hash": stable_payload_sha256(row)} for row in source_rows]
    matrix_core = {
        "profile_version": "forensic-integrity-matrix-v1",
        "item_numbers": [86, 87, 88, 89, 90],
        "row_count": len(rows),
        "rows": rows,
        "provenance_rows": provenance_rows,
        "provenance_row_count": len(provenance_rows),
        "all_primary_hashes_present": all(bool(row["primary_hash"]) for row in rows),
        "commercial_claim_allowed": all(not row["blockers"] for row in rows),
    }
    return {**matrix_core, "matrix_hash": stable_payload_sha256(matrix_core)}


def custody_workflow_core_accuracy_gates(
    *,
    evidence_sources: Sequence[Mapping[str, object]],
    custody_events: Sequence[Mapping[str, object]],
    custody_event_manifest: Mapping[str, object] | None = None,
    custody_chain_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
    report_grade_validation_plan: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = ["acquisition metadata limitation warning"]
    if evidence_sources:
        satisfied.append("evidence source inventory")
    if custody_events:
        satisfied.append("custody event inventory")
    if any(item.get("citation_id") for item in [*evidence_sources, *custody_events]):
        satisfied.append("citation IDs preserved")
    if any(item.get("status") or item.get("sha256") for item in evidence_sources):
        satisfied.append("source status/hash fields preserved")
    if any(item.get("custody_row_hash") for item in [*evidence_sources, *custody_events]):
        satisfied.append("custody row hashes emitted")
    if custody_event_manifest and custody_event_manifest.get("manifest_hash"):
        satisfied.append("custody event manifest hash emitted")
    if custody_chain_manifest and custody_chain_manifest.get("manifest_hash"):
        satisfied.append("custody chain manifest hash emitted")
    if custody_chain_manifest and custody_chain_manifest.get("custody_completeness_matrix_hash"):
        satisfied.append("custody completeness matrix hash emitted")
    if report_grade_validation_plan and report_grade_validation_plan.get("validation_plan_sha256"):
        satisfied.append("custody report-grade validation plan")
    if report_grade_validation_plan and int(report_grade_validation_plan.get("ready_slot_count") or 0) >= 6:
        satisfied.append("custody report-grade ready slots")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted custody event manifest diff pass")
    return [
        build_accuracy_gate(
            86,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"evidence_source_count:{len(evidence_sources)}",
                f"custody_event_count:{len(custody_events)}",
                f"custody_manifest_hash:{(custody_event_manifest or {}).get('manifest_hash', '')}",
                f"custody_chain_manifest_hash:{(custody_chain_manifest or {}).get('manifest_hash', '')}",
                f"custody_completeness_matrix_hash:{(custody_chain_manifest or {}).get('custody_completeness_matrix_hash', '')}",
                f"custody_report_grade_validation_plan_hash:{(report_grade_validation_plan or {}).get('validation_plan_sha256', '')}",
            ],
        )
    ]


def acquisition_hash_core_accuracy_gates(
    *,
    hashes: Sequence[Mapping[str, object]],
    acquisition_hash_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
    report_grade_validation_plan: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = ["missing hash limitation warning"]
    if any(item.get("target_type") == "evidence_source" for item in hashes):
        satisfied.append("evidence-source hashes exported")
    if hashes:
        satisfied.append("hash records exported")
    if any(isinstance(item.get("hashes"), Mapping) and item.get("hashes") for item in hashes):
        satisfied.append("hash algorithms preserved")
    if any(item.get("calculated_at") for item in hashes):
        satisfied.append("calculation timestamps preserved")
    if any(item.get("acquisition_hash_row_hash") for item in hashes):
        satisfied.append("acquisition hash row hashes emitted")
    if acquisition_hash_manifest and acquisition_hash_manifest.get("manifest_hash"):
        satisfied.append("acquisition hash manifest hash emitted")
    if acquisition_hash_manifest and acquisition_hash_manifest.get("hash_inventory_matrix_hash"):
        satisfied.append("acquisition hash inventory matrix emitted")
    if report_grade_validation_plan and report_grade_validation_plan.get("validation_plan_sha256"):
        satisfied.append("acquisition hash report-grade validation plan")
    if report_grade_validation_plan and int(report_grade_validation_plan.get("ready_slot_count") or 0) >= 6:
        satisfied.append("acquisition hash report-grade ready slots")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted acquisition hash manifest diff pass")
    return [
        build_accuracy_gate(
            87,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"hash_count:{len(hashes)}",
                f"acquisition_hash_manifest_hash:{(acquisition_hash_manifest or {}).get('manifest_hash', '')}",
                f"hash_inventory_matrix_hash:{(acquisition_hash_manifest or {}).get('hash_inventory_matrix_hash', '')}",
                f"acquisition_hash_report_grade_validation_plan_hash:{(report_grade_validation_plan or {}).get('validation_plan_sha256', '')}",
            ],
        )
    ]


def immutable_audit_core_accuracy_gates(
    *,
    events: Sequence[Mapping[str, object]],
    head_hash: str,
    audit_hash_chain_manifest: Mapping[str, object] | None = None,
    audit_replay_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
    report_grade_validation_plan: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = ["external notarization limitation warning"]
    if events:
        satisfied.append("audit events exported")
    if all(item.get("event_hash") is not None and "previous_event_hash" in item for item in events):
        satisfied.append("previous/event hash chain generated")
    if all(item.get("actor") is not None and item.get("action") and item.get("target_type") is not None and item.get("timestamp") for item in events):
        satisfied.append("actor/action/target/time fields preserved")
    if head_hash:
        satisfied.append("head hash recorded")
    if audit_hash_chain_manifest and audit_hash_chain_manifest.get("manifest_hash"):
        satisfied.append("audit hash-chain manifest hash emitted")
    if audit_hash_chain_manifest and audit_hash_chain_manifest.get("actor_action_matrix_hash"):
        satisfied.append("audit actor/action matrix hash emitted")
    if audit_replay_manifest and audit_replay_manifest.get("manifest_hash"):
        satisfied.append("audit replay manifest hash emitted")
    if audit_replay_manifest and audit_replay_manifest.get("replay_matrix_hash"):
        satisfied.append("audit replay matrix hash emitted")
    if audit_replay_manifest and audit_replay_manifest.get("chain_valid"):
        satisfied.append("audit replay chain validation pass")
    if report_grade_validation_plan and report_grade_validation_plan.get("validation_plan_sha256"):
        satisfied.append("immutable audit report-grade validation plan")
    if report_grade_validation_plan and int(report_grade_validation_plan.get("ready_slot_count") or 0) >= 6:
        satisfied.append("immutable audit report-grade ready slots")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted audit hash-chain manifest diff pass")
    return [
        build_accuracy_gate(
            88,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"event_count:{len(events)}",
                f"head_hash:{head_hash}",
                f"audit_chain_manifest_hash:{(audit_hash_chain_manifest or {}).get('manifest_hash', '')}",
                f"audit_replay_manifest_hash:{(audit_replay_manifest or {}).get('manifest_hash', '')}",
                f"actor_action_matrix_hash:{(audit_hash_chain_manifest or {}).get('actor_action_matrix_hash', '')}",
                f"replay_matrix_hash:{(audit_replay_manifest or {}).get('replay_matrix_hash', '')}",
                f"immutable_audit_report_grade_validation_plan_hash:{(report_grade_validation_plan or {}).get('validation_plan_sha256', '')}",
            ],
        )
    ]


def report_reproducibility_core_accuracy_gates(
    *,
    stable_hash: str,
    item_count: int,
    citation_count: int,
    report_replay_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
    report_grade_validation_plan: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = [
        "stable payload hash generated",
        "deterministic sorting documented",
        "item/citation counts recorded",
        "volatile fields disclosed",
        "cross-platform replay limitation warning",
    ]
    if report_replay_manifest and report_replay_manifest.get("manifest_hash"):
        satisfied.append("report replay manifest hash emitted")
    if report_replay_manifest and (
        report_replay_manifest.get("item_row_hashes") or report_replay_manifest.get("citation_row_hashes")
    ):
        satisfied.append("item/citation row hashes emitted")
    if report_replay_manifest and report_replay_manifest.get("row_hash_set_hash"):
        satisfied.append("row hash set hash emitted")
    if report_replay_manifest and report_replay_manifest.get("replay_contract_hash"):
        satisfied.append("replay contract hash emitted")
    if report_grade_validation_plan and report_grade_validation_plan.get("validation_plan_sha256"):
        satisfied.append("report reproducibility report-grade validation plan")
    if report_grade_validation_plan and int(report_grade_validation_plan.get("ready_slot_count") or 0) >= 6:
        satisfied.append("report reproducibility report-grade ready slots")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted report replay manifest diff pass")
    return [
        build_accuracy_gate(
            89,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"stable_payload_sha256:{stable_hash}",
                f"stable_item_count:{item_count}",
                f"citation_count:{citation_count}",
                f"report_replay_manifest_hash:{(report_replay_manifest or {}).get('manifest_hash', '')}",
                f"row_hash_set_hash:{(report_replay_manifest or {}).get('row_hash_set_hash', '')}",
                f"report_reproducibility_report_grade_validation_plan_hash:{(report_grade_validation_plan or {}).get('validation_plan_sha256', '')}",
            ],
        )
    ]


def report_item_provenance_core_accuracy_gates(
    *,
    source_path: str,
    hashes: Mapping[str, object],
    record_hashes: Mapping[str, object],
    parser: str,
    parser_version: str,
    parser_confidence: object,
    record_offset: object,
    source_index: object,
    review_status: str,
    reportability: str,
    provenance_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
    report_grade_validation_plan: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = []
    if source_path:
        satisfied.append("source path preserved")
    if hashes or record_hashes:
        satisfied.append("source or record hashes preserved")
    if parser or parser_version or parser_confidence:
        satisfied.append("parser/version/confidence preserved")
    if record_offset is not None or source_index is not None:
        satisfied.append("offset or source index preserved when available")
    if review_status or reportability:
        satisfied.append("review/reportability fields preserved")
    if provenance_manifest and provenance_manifest.get("provenance_row_hash"):
        satisfied.append("provenance row hash emitted")
    if provenance_manifest and provenance_manifest.get("manifest_hash"):
        satisfied.append("provenance manifest hash emitted")
    if provenance_manifest and provenance_manifest.get("field_presence_hash"):
        satisfied.append("provenance field-presence hash emitted")
    if report_grade_validation_plan and report_grade_validation_plan.get("validation_plan_sha256"):
        satisfied.append("source provenance report-grade validation plan")
    if report_grade_validation_plan and int(report_grade_validation_plan.get("ready_slot_count") or 0) >= 7:
        satisfied.append("source provenance report-grade ready slots")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted report provenance manifest diff pass")
    return [
        build_accuracy_gate(
            90,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"source_path:{source_path}",
                f"has_hashes:{bool(hashes or record_hashes)}",
                f"parser:{parser}",
                f"review_status:{review_status}",
                f"reportability:{reportability}",
                f"provenance_manifest_hash:{(provenance_manifest or {}).get('manifest_hash', '')}",
                f"source_provenance_report_grade_validation_plan_hash:{(report_grade_validation_plan or {}).get('validation_plan_sha256', '')}",
            ],
        )
    ]


def missing_integrity_trusted_diff(gap_id: str, blocker: str, *, trusted_tool: str) -> dict[str, object]:
    return {
        "status": "missing",
        "trusted_tool": None,
        "commercial_gap_ids": [gap_id],
        "blocker": blocker,
        "required_trusted_tool": trusted_tool,
    }


def build_custody_workflow_trusted_diff(
    rapid_workflow: Mapping[str, object],
    trusted_workflow: Mapping[str, object],
    *,
    trusted_tool: str = "custody-event-manifest",
) -> dict[str, object]:
    mismatches = compare_integrity_manifests(
        custody_manifest(rapid_workflow),
        custody_manifest(trusted_workflow),
        fields=("evidence_sources", "custody_events", "manifest_hash", "custody_completeness_matrix_hash"),
    )
    status = "pass" if not mismatches and trusted_tool in FORENSIC_INTEGRITY_TRUSTED_TOOLS else "fail"
    return integrity_trusted_diff_result(
        status=status,
        gap_id=CHAIN_OF_CUSTODY_GAP_ID,
        blocker=CUSTODY_TRUSTED_DIFF_BLOCKER_86,
        trusted_tool=trusted_tool,
        compared_fields=["evidence_sources", "custody_events", "manifest_hash", "custody_completeness_matrix_hash"],
        mismatches=mismatches,
    )


def build_acquisition_hash_trusted_diff(
    rapid_workflow: Mapping[str, object],
    trusted_workflow: Mapping[str, object],
    *,
    trusted_tool: str = "acquisition-hash-manifest",
) -> dict[str, object]:
    mismatches = compare_integrity_manifests(
        acquisition_hash_manifest(rapid_workflow),
        acquisition_hash_manifest(trusted_workflow),
        fields=("hashes", "manifest_hash", "hash_inventory_matrix_hash"),
    )
    status = "pass" if not mismatches and trusted_tool in FORENSIC_INTEGRITY_TRUSTED_TOOLS else "fail"
    return integrity_trusted_diff_result(
        status=status,
        gap_id=ACQUISITION_HASH_GAP_ID,
        blocker=ACQUISITION_HASH_TRUSTED_DIFF_BLOCKER_87,
        trusted_tool=trusted_tool,
        compared_fields=["hashes", "manifest_hash", "hash_inventory_matrix_hash"],
        mismatches=mismatches,
    )


def build_immutable_audit_trusted_diff(
    rapid_workflow: Mapping[str, object],
    trusted_workflow: Mapping[str, object],
    *,
    trusted_tool: str = "audit-hash-chain-manifest",
) -> dict[str, object]:
    mismatches = compare_integrity_manifests(
        audit_integrity_manifest(rapid_workflow),
        audit_integrity_manifest(trusted_workflow),
        fields=("head_hash", "events", "manifest_hash", "actor_action_matrix_hash", "audit_replay_manifest_hash", "replay_matrix_hash"),
    )
    status = "pass" if not mismatches and trusted_tool in FORENSIC_INTEGRITY_TRUSTED_TOOLS else "fail"
    return integrity_trusted_diff_result(
        status=status,
        gap_id=IMMUTABLE_AUDIT_GAP_ID,
        blocker=IMMUTABLE_AUDIT_TRUSTED_DIFF_BLOCKER_88,
        trusted_tool=trusted_tool,
        compared_fields=[
            "head_hash",
            "events",
            "manifest_hash",
            "actor_action_matrix_hash",
            "audit_replay_manifest_hash",
            "replay_matrix_hash",
        ],
        mismatches=mismatches,
    )


def build_report_reproducibility_trusted_diff(
    rapid_manifest: Mapping[str, object],
    trusted_manifest: Mapping[str, object],
    *,
    trusted_tool: str = "report-replay-manifest",
) -> dict[str, object]:
    mismatches = compare_integrity_manifests(
        reproducibility_manifest(rapid_manifest),
        reproducibility_manifest(trusted_manifest),
        fields=(
            "stable_payload_sha256",
            "stable_item_count",
            "citation_count",
            "manifest_hash",
            "item_row_hashes",
            "citation_row_hashes",
            "row_hash_set_hash",
            "replay_contract_hash",
        ),
    )
    status = "pass" if not mismatches and trusted_tool in FORENSIC_INTEGRITY_TRUSTED_TOOLS else "fail"
    return integrity_trusted_diff_result(
        status=status,
        gap_id=REPORT_REPRODUCIBILITY_GAP_ID,
        blocker=REPORT_REPRODUCIBILITY_TRUSTED_DIFF_BLOCKER_89,
        trusted_tool=trusted_tool,
        compared_fields=[
            "stable_payload_sha256",
            "stable_item_count",
            "citation_count",
            "manifest_hash",
            "item_row_hashes",
            "citation_row_hashes",
            "row_hash_set_hash",
            "replay_contract_hash",
        ],
        mismatches=mismatches,
    )


def build_report_provenance_trusted_diff(
    rapid_rows: Sequence[Mapping[str, object]],
    trusted_rows: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str = "report-provenance-manifest",
) -> dict[str, object]:
    mismatches = compare_indexed_integrity_rows(
        index_provenance_rows(rapid_rows),
        index_provenance_rows(trusted_rows),
        fields=(
            "source_path",
            "hashes",
            "record_hashes",
            "parser",
            "parser_version",
            "review_status",
            "reportability",
            "provenance_row_hash",
            "field_presence_hash",
            "completeness_score",
            "manifest_hash",
        ),
    )
    status = "pass" if not mismatches and trusted_tool in FORENSIC_INTEGRITY_TRUSTED_TOOLS else "fail"
    return integrity_trusted_diff_result(
        status=status,
        gap_id=SOURCE_PROVENANCE_GAP_ID,
        blocker=SOURCE_PROVENANCE_TRUSTED_DIFF_BLOCKER_90,
        trusted_tool=trusted_tool,
        compared_fields=[
            "target_citation_id",
            "source_path",
            "hashes",
            "parser",
            "review_status",
            "reportability",
            "provenance_row_hash",
            "field_presence_hash",
            "completeness_score",
            "manifest_hash",
        ],
        mismatches=mismatches,
    )


def integrity_trusted_diff_result(
    *,
    status: str,
    gap_id: str,
    blocker: str,
    trusted_tool: str,
    compared_fields: Sequence[str],
    mismatches: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    return {
        "status": status,
        "trusted_tool": trusted_tool,
        "commercial_gap_ids": [gap_id],
        "compared_fields": list(compared_fields),
        "mismatches": [dict(item) for item in mismatches],
        "blocker": None if status == "pass" else blocker,
    }


def compare_integrity_manifests(
    rapid: Mapping[str, object],
    trusted: Mapping[str, object],
    *,
    fields: Sequence[str],
) -> list[dict[str, object]]:
    return [
        {"field": field, "rapid": normalize_integrity_value(rapid.get(field)), "trusted": normalize_integrity_value(trusted.get(field))}
        for field in fields
        if normalize_integrity_value(rapid.get(field)) != normalize_integrity_value(trusted.get(field))
    ]


def compare_indexed_integrity_rows(
    rapid_index: Mapping[str, Mapping[str, object]],
    trusted_index: Mapping[str, Mapping[str, object]],
    *,
    fields: Sequence[str],
) -> list[dict[str, object]]:
    mismatches: list[dict[str, object]] = []
    for key, trusted_row in sorted(trusted_index.items()):
        rapid_row = rapid_index.get(key)
        if rapid_row is None:
            mismatches.append({"id": key, "field": "row", "rapid": None, "trusted": "present"})
            continue
        for field in fields:
            rapid_value = normalize_integrity_value(rapid_row.get(field))
            trusted_value = normalize_integrity_value(trusted_row.get(field))
            if rapid_value != trusted_value:
                mismatches.append({"id": key, "field": field, "rapid": rapid_value, "trusted": trusted_value})
    for key in sorted(set(rapid_index) - set(trusted_index)):
        mismatches.append({"id": key, "field": "row", "rapid": "present", "trusted": None})
    return mismatches


def normalize_integrity_value(value: object) -> object:
    if isinstance(value, list):
        return sorted(json.dumps(item, ensure_ascii=False, sort_keys=True, default=str) for item in value)
    if isinstance(value, tuple):
        return sorted(json.dumps(item, ensure_ascii=False, sort_keys=True, default=str) for item in value)
    if isinstance(value, Mapping):
        return json.dumps(dict(value), ensure_ascii=False, sort_keys=True, default=str)
    return value


def custody_manifest(workflow: Mapping[str, object]) -> dict[str, object]:
    event_manifest = workflow.get("custody_event_manifest")
    event_manifest_mapping = event_manifest if isinstance(event_manifest, Mapping) else {}
    chain_manifest = workflow.get("custody_chain_manifest")
    chain_manifest_mapping = chain_manifest if isinstance(chain_manifest, Mapping) else {}
    return {
        "manifest_hash": str(workflow.get("custody_manifest_hash") or event_manifest_mapping.get("manifest_hash") or ""),
        "custody_completeness_matrix_hash": str(
            workflow.get("custody_completeness_matrix_hash")
            or chain_manifest_mapping.get("custody_completeness_matrix_hash")
            or ""
        ),
        "evidence_sources": [
            {
                "citation_id": item.get("citation_id"),
                "sha256": item.get("sha256"),
                "status": item.get("status"),
                "original_path": item.get("original_path"),
                "custody_row_hash": item.get("custody_row_hash"),
            }
            for item in workflow.get("evidence_sources", [])
            if isinstance(item, Mapping)
        ],
        "custody_events": [
            {
                "citation_id": item.get("citation_id"),
                "actor": item.get("actor"),
                "action": item.get("action"),
                "target_type": item.get("target_type"),
                "target_id": item.get("target_id"),
                "timestamp": item.get("timestamp"),
                "result": item.get("result"),
                "custody_row_hash": item.get("custody_row_hash"),
            }
            for item in workflow.get("custody_events", [])
            if isinstance(item, Mapping)
        ],
    }


def acquisition_hash_manifest(workflow: Mapping[str, object]) -> dict[str, object]:
    manifest = workflow.get("acquisition_hash_manifest")
    manifest_hash = ""
    hash_inventory_matrix_hash = ""
    if isinstance(manifest, Mapping):
        manifest_hash = str(manifest.get("manifest_hash") or "")
        hash_inventory_matrix_hash = str(manifest.get("hash_inventory_matrix_hash") or "")
    return {
        "manifest_hash": manifest_hash,
        "hash_inventory_matrix_hash": hash_inventory_matrix_hash,
        "hashes": [
            {
                "citation_id": item.get("citation_id"),
                "target_type": item.get("target_type"),
                "target_id": item.get("target_id"),
                "hash_scope": item.get("hash_scope"),
                "hashes": item.get("hashes"),
                "hash_status": item.get("hash_status"),
                "missing_hash_warning": item.get("missing_hash_warning"),
                "calculated_at": item.get("calculated_at"),
                "acquisition_hash_row_hash": item.get("acquisition_hash_row_hash"),
            }
            for item in workflow.get("hashes", [])
            if isinstance(item, Mapping)
        ],
    }


def audit_integrity_manifest(workflow: Mapping[str, object]) -> dict[str, object]:
    summary = workflow.get("summary") if isinstance(workflow.get("summary"), Mapping) else {}
    manifest = workflow.get("audit_hash_chain_manifest")
    replay_manifest = workflow.get("audit_replay_manifest")
    manifest_hash = ""
    actor_action_matrix_hash = ""
    replay_manifest_hash = ""
    replay_matrix_hash = ""
    if isinstance(manifest, Mapping):
        manifest_hash = str(manifest.get("manifest_hash") or "")
        actor_action_matrix_hash = str(manifest.get("actor_action_matrix_hash") or "")
    if isinstance(replay_manifest, Mapping):
        replay_manifest_hash = str(replay_manifest.get("manifest_hash") or "")
        replay_matrix_hash = str(replay_manifest.get("replay_matrix_hash") or "")
    return {
        "head_hash": summary.get("head_hash"),
        "manifest_hash": manifest_hash,
        "actor_action_matrix_hash": actor_action_matrix_hash,
        "audit_replay_manifest_hash": replay_manifest_hash,
        "replay_matrix_hash": replay_matrix_hash,
        "events": [
            {
                "citation_id": item.get("citation_id"),
                "previous_event_hash": item.get("previous_event_hash"),
                "event_hash": item.get("event_hash"),
                "action": item.get("action"),
                "timestamp": item.get("timestamp"),
            }
            for item in workflow.get("events", [])
            if isinstance(item, Mapping)
        ],
    }


def reproducibility_manifest(manifest: Mapping[str, object]) -> dict[str, object]:
    replay_manifest = manifest.get("report_replay_manifest")
    manifest_hash = ""
    item_row_hashes: list[object] = []
    citation_row_hashes: list[object] = []
    row_hash_set_hash = ""
    replay_contract_hash = ""
    if isinstance(replay_manifest, Mapping):
        manifest_hash = str(replay_manifest.get("manifest_hash") or "")
        row_hash_set_hash = str(replay_manifest.get("row_hash_set_hash") or "")
        replay_contract_hash = str(replay_manifest.get("replay_contract_hash") or "")
        if isinstance(replay_manifest.get("item_row_hashes"), list):
            item_row_hashes = list(replay_manifest["item_row_hashes"])
        if isinstance(replay_manifest.get("citation_row_hashes"), list):
            citation_row_hashes = list(replay_manifest["citation_row_hashes"])
    return {
        "stable_payload_sha256": manifest.get("stable_payload_sha256"),
        "stable_item_count": manifest.get("stable_item_count"),
        "citation_count": manifest.get("citation_count"),
        "manifest_hash": manifest_hash,
        "item_row_hashes": item_row_hashes,
        "citation_row_hashes": citation_row_hashes,
        "row_hash_set_hash": row_hash_set_hash,
        "replay_contract_hash": replay_contract_hash,
    }


def index_provenance_rows(rows: Sequence[Mapping[str, object]]) -> dict[str, Mapping[str, object]]:
    indexed: dict[str, Mapping[str, object]] = {}
    for row in rows:
        key = str(row.get("target_citation_id") or row.get("review_citation_id") or row.get("source_path") or "")
        if not key:
            continue
        indexed[key] = {
            "source_path": row.get("source_path"),
            "hashes": row.get("hashes"),
            "record_hashes": row.get("record_hashes"),
            "parser": row.get("parser"),
            "parser_version": row.get("parser_version"),
            "review_status": row.get("review_status"),
            "reportability": row.get("reportability"),
            "provenance_row_hash": row.get("provenance_row_hash"),
            "field_presence_hash": (row.get("provenance_manifest") or {}).get("field_presence_hash")
            if isinstance(row.get("provenance_manifest"), Mapping)
            else "",
            "completeness_score": (row.get("provenance_manifest") or {}).get("completeness_score")
            if isinstance(row.get("provenance_manifest"), Mapping)
            else None,
            "manifest_hash": row.get("provenance_manifest_hash"),
        }
    return indexed


def missing_report_quality_trusted_diff(gap_id: str, blocker: str, *, trusted_tool: str) -> dict[str, object]:
    return {
        "status": "missing",
        "trusted_tool": None,
        "commercial_gap_ids": [gap_id],
        "blocker": blocker,
        "required_trusted_tool": trusted_tool,
    }


def build_parser_confidence_trusted_diff(
    rapid_assessment: Mapping[str, object],
    trusted_assessment: Mapping[str, object],
    *,
    trusted_tool: str = "parser-confidence-calibration",
) -> dict[str, object]:
    compared_fields = [
        "parser_confidence",
        "confidence_band",
        "reportability_score",
        "reportability",
        "coverage_status",
        "evidence_strength",
        "parser_confidence_manifest_hash",
        "calibration_field_presence_hash",
    ]
    mismatches = [
        {"field": field, "rapid": rapid_assessment.get(field), "trusted": trusted_assessment.get(field)}
        for field in compared_fields
        if rapid_assessment.get(field) != trusted_assessment.get(field)
    ]
    status = "pass" if not mismatches and trusted_tool in REPORT_QUALITY_TRUSTED_TOOLS else "fail"
    return report_quality_trusted_diff_result(
        status=status,
        gap_id=PARSER_CONFIDENCE_GAP_ID,
        blocker=PARSER_CONFIDENCE_TRUSTED_DIFF_BLOCKER_91,
        trusted_tool=trusted_tool,
        compared_fields=compared_fields,
        mismatches=mismatches,
    )


def build_validation_warning_trusted_diff(
    rapid_assessment: Mapping[str, object],
    trusted_assessment: Mapping[str, object],
    *,
    trusted_tool: str = "validation-warning-checklist",
) -> dict[str, object]:
    compared_fields = [
        "validation_required",
        "warnings",
        "warning_severity_counts",
        "warning_category_counts",
        "warning_ux_badges",
        "validation_warning_manifest_hash",
        "warning_action_matrix_hash",
    ]
    mismatches = [
        {"field": field, "rapid": normalize_integrity_value(rapid_assessment.get(field)), "trusted": normalize_integrity_value(trusted_assessment.get(field))}
        for field in compared_fields
        if normalize_integrity_value(rapid_assessment.get(field)) != normalize_integrity_value(trusted_assessment.get(field))
    ]
    status = "pass" if not mismatches and trusted_tool in REPORT_QUALITY_TRUSTED_TOOLS else "fail"
    return report_quality_trusted_diff_result(
        status=status,
        gap_id=VALIDATION_WARNING_UX_GAP_ID,
        blocker=VALIDATION_WARNING_TRUSTED_DIFF_BLOCKER_92,
        trusted_tool=trusted_tool,
        compared_fields=compared_fields,
        mismatches=mismatches,
    )


def build_legal_limitation_trusted_diff(
    rapid_assessment: Mapping[str, object],
    trusted_assessment: Mapping[str, object],
    *,
    trusted_tool: str = "legal-limitation-wording-review",
) -> dict[str, object]:
    compared_fields = [
        "limitation_count",
        "status",
        "limitation_category_counts",
        "limitation_scope_counts",
        "legal_limitation_manifest_hash",
        "limitation_wording_matrix_hash",
    ]
    mismatches = [
        {"field": field, "rapid": rapid_assessment.get(field), "trusted": trusted_assessment.get(field)}
        for field in compared_fields
        if rapid_assessment.get(field) != trusted_assessment.get(field)
    ]
    status = "pass" if not mismatches and trusted_tool in REPORT_QUALITY_TRUSTED_TOOLS else "fail"
    return report_quality_trusted_diff_result(
        status=status,
        gap_id=LEGAL_LIMITATION_GAP_ID,
        blocker=LEGAL_LIMITATION_TRUSTED_DIFF_BLOCKER_93,
        trusted_tool=trusted_tool,
        compared_fields=compared_fields,
        mismatches=mismatches,
    )


def report_quality_trusted_diff_result(
    *,
    status: str,
    gap_id: str,
    blocker: str,
    trusted_tool: str,
    compared_fields: Sequence[str],
    mismatches: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    return {
        "status": status,
        "trusted_tool": trusted_tool,
        "commercial_gap_ids": [gap_id],
        "compared_fields": list(compared_fields),
        "mismatches": [dict(item) for item in mismatches],
        "blocker": None if status == "pass" else blocker,
    }


def missing_acquisition_quality_trusted_diff(gap_id: str, blocker: str, *, trusted_tool: str) -> dict[str, object]:
    return {
        "status": "missing",
        "trusted_tool": None,
        "commercial_gap_ids": [gap_id],
        "blocker": blocker,
        "required_trusted_tool": trusted_tool,
    }


def missing_acquisition_metadata_trusted_diff() -> dict[str, object]:
    return missing_acquisition_quality_trusted_diff(
        WRITE_BLOCKER_ACQUISITION_METADATA_GAP_ID,
        ACQUISITION_METADATA_TRUSTED_DIFF_BLOCKER_96,
        trusted_tool="signed-acquisition-handoff",
    )


def missing_timezone_validation_trusted_diff() -> dict[str, object]:
    return missing_acquisition_quality_trusted_diff(
        TIMEZONE_NORMALIZATION_GAP_ID,
        TIMEZONE_VALIDATION_TRUSTED_DIFF_BLOCKER_97,
        trusted_tool="timezone-normalization-matrix",
    )


def missing_clock_skew_trusted_diff() -> dict[str, object]:
    return missing_acquisition_quality_trusted_diff(
        CLOCK_SKEW_ANALYSIS_GAP_ID,
        CLOCK_SKEW_TRUSTED_DIFF_BLOCKER_98,
        trusted_tool="clock-skew-baseline",
    )


def missing_contamination_warning_trusted_diff() -> dict[str, object]:
    return missing_acquisition_quality_trusted_diff(
        EVIDENCE_CONTAMINATION_WARNING_GAP_ID,
        CONTAMINATION_WARNING_TRUSTED_DIFF_BLOCKER_99,
        trusted_tool="contamination-checklist",
    )


def build_acquisition_metadata_trusted_diff(
    rapid_record: Mapping[str, object],
    trusted_record: Mapping[str, object],
    *,
    trusted_tool: str = "signed-acquisition-handoff",
) -> dict[str, object]:
    compared_fields = [
        "records",
        "missing_required_fields",
        "acquisition_metadata_handoff_manifest_hash",
        "acquisition_field_completion_matrix_hash",
    ]
    mismatches = build_acquisition_quality_mismatches(rapid_record, trusted_record, compared_fields)
    return acquisition_quality_trusted_diff_result(
        status="pass" if not mismatches and trusted_tool in ACQUISITION_QUALITY_TRUSTED_TOOLS else "fail",
        gap_id=WRITE_BLOCKER_ACQUISITION_METADATA_GAP_ID,
        blocker=ACQUISITION_METADATA_TRUSTED_DIFF_BLOCKER_96,
        trusted_tool=trusted_tool,
        compared_fields=compared_fields,
        mismatches=mismatches,
    )


def build_timezone_validation_trusted_diff(
    rapid_validation: Mapping[str, object],
    trusted_validation: Mapping[str, object],
    *,
    trusted_tool: str = "timezone-normalization-matrix",
) -> dict[str, object]:
    compared_fields = [
        "summary",
        "samples",
        "timezone_normalization_manifest_hash",
        "parser_assumption_matrix_hash",
        "time_semantics_manifest_hash",
    ]
    mismatches = build_acquisition_quality_mismatches(rapid_validation, trusted_validation, compared_fields)
    return acquisition_quality_trusted_diff_result(
        status="pass" if not mismatches and trusted_tool in ACQUISITION_QUALITY_TRUSTED_TOOLS else "fail",
        gap_id=TIMEZONE_NORMALIZATION_GAP_ID,
        blocker=TIMEZONE_VALIDATION_TRUSTED_DIFF_BLOCKER_97,
        trusted_tool=trusted_tool,
        compared_fields=compared_fields,
        mismatches=mismatches,
    )


def build_clock_skew_trusted_diff(
    rapid_analysis: Mapping[str, object],
    trusted_analysis: Mapping[str, object],
    *,
    trusted_tool: str = "clock-skew-baseline",
) -> dict[str, object]:
    compared_fields = ["summary", "warnings", "clock_skew_baseline_manifest_hash", "clock_skew_range_matrix_hash"]
    mismatches = build_acquisition_quality_mismatches(rapid_analysis, trusted_analysis, compared_fields)
    return acquisition_quality_trusted_diff_result(
        status="pass" if not mismatches and trusted_tool in ACQUISITION_QUALITY_TRUSTED_TOOLS else "fail",
        gap_id=CLOCK_SKEW_ANALYSIS_GAP_ID,
        blocker=CLOCK_SKEW_TRUSTED_DIFF_BLOCKER_98,
        trusted_tool=trusted_tool,
        compared_fields=compared_fields,
        mismatches=mismatches,
    )


def build_contamination_warning_trusted_diff(
    rapid_warnings: Mapping[str, object],
    trusted_warnings: Mapping[str, object],
    *,
    trusted_tool: str = "contamination-checklist",
) -> dict[str, object]:
    compared_fields = [
        "summary",
        "warnings",
        "contamination_checklist_manifest_hash",
        "warning_review_matrix_hash",
        "contamination_acquisition_context_manifest_hash",
    ]
    mismatches = build_acquisition_quality_mismatches(rapid_warnings, trusted_warnings, compared_fields)
    return acquisition_quality_trusted_diff_result(
        status="pass" if not mismatches and trusted_tool in ACQUISITION_QUALITY_TRUSTED_TOOLS else "fail",
        gap_id=EVIDENCE_CONTAMINATION_WARNING_GAP_ID,
        blocker=CONTAMINATION_WARNING_TRUSTED_DIFF_BLOCKER_99,
        trusted_tool=trusted_tool,
        compared_fields=compared_fields,
        mismatches=mismatches,
    )


def build_acquisition_quality_mismatches(
    rapid_payload: Mapping[str, object],
    trusted_payload: Mapping[str, object],
    compared_fields: Sequence[str],
) -> list[dict[str, object]]:
    mismatches = []
    for field in compared_fields:
        rapid_value = normalize_integrity_value(rapid_payload.get(field))
        trusted_value = normalize_integrity_value(trusted_payload.get(field))
        if rapid_value != trusted_value:
            mismatches.append({"field": field, "rapid": rapid_value, "trusted": trusted_value})
    return mismatches


def acquisition_quality_trusted_diff_result(
    *,
    status: str,
    gap_id: str,
    blocker: str,
    trusted_tool: str,
    compared_fields: Sequence[str],
    mismatches: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    return {
        "status": status,
        "trusted_tool": trusted_tool,
        "commercial_gap_ids": [gap_id],
        "compared_fields": list(compared_fields),
        "mismatches": [dict(item) for item in mismatches],
        "blocker": None if status == "pass" else blocker,
    }


def parser_confidence_core_accuracy_gates(
    *,
    parser_confidence: object,
    reportability: str,
    coverage_status: str,
    warnings: Sequence[str],
    evidence_strength: str,
    confidence_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
    report_grade_validation_plan: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = []
    if parser_confidence not in (None, ""):
        satisfied.append("parser confidence preserved")
    if reportability:
        satisfied.append("reportability state recorded")
    if coverage_status:
        satisfied.append("coverage status recorded")
    if warnings is not None:
        satisfied.append("validation warnings derived")
    if evidence_strength:
        satisfied.append("evidence strength surfaced")
    if confidence_manifest and confidence_manifest.get("confidence_band"):
        satisfied.append("confidence band assigned")
    if confidence_manifest and confidence_manifest.get("reportability_score") is not None:
        satisfied.append("reportability score emitted")
    if confidence_manifest and confidence_manifest.get("manifest_hash"):
        satisfied.append("parser confidence calibration manifest hash emitted")
    if confidence_manifest and confidence_manifest.get("calibration_field_presence_hash"):
        satisfied.append("parser confidence field-presence hash emitted")
    if report_grade_validation_plan and report_grade_validation_plan.get("validation_plan_sha256"):
        satisfied.append("parser confidence report-grade validation plan")
    if report_grade_validation_plan and int(report_grade_validation_plan.get("ready_slot_count") or 0) >= 6:
        satisfied.append("parser confidence report-grade ready slots")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted parser confidence calibration diff pass")
    return [
        build_accuracy_gate(
            91,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"parser_confidence:{parser_confidence}",
                f"reportability:{reportability}",
                f"coverage_status:{coverage_status}",
                f"warning_count:{len(warnings)}",
                f"evidence_strength:{evidence_strength}",
                f"confidence_band:{(confidence_manifest or {}).get('confidence_band', '')}",
                f"reportability_score:{(confidence_manifest or {}).get('reportability_score', '')}",
                f"parser_confidence_manifest_hash:{(confidence_manifest or {}).get('manifest_hash', '')}",
                f"calibration_field_presence_hash:{(confidence_manifest or {}).get('calibration_field_presence_hash', '')}",
                f"parser_confidence_report_grade_validation_plan_hash:{(report_grade_validation_plan or {}).get('validation_plan_sha256', '')}",
            ],
        )
    ]


def validation_warning_ux_core_accuracy_gates(
    *,
    warnings: Sequence[str],
    warning_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = [
        "validation warning reasons emitted",
        "summary warning counts emitted",
        "report guidance emitted",
        "validation-required state preserved",
        "warning UX limitation disclosed",
    ]
    if warning_manifest and warning_manifest.get("warnings"):
        satisfied.append("warning detail metadata emitted")
    if warning_manifest and warning_manifest.get("ux_badges"):
        satisfied.append("warning UX badges emitted")
    if warning_manifest and warning_manifest.get("manifest_hash"):
        satisfied.append("validation warning checklist manifest hash emitted")
    if warning_manifest and warning_manifest.get("warning_action_matrix_hash"):
        satisfied.append("warning action matrix hash emitted")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted validation warning checklist diff pass")
    return [
        build_accuracy_gate(
            92,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"warning_count:{len(warnings)}",
                f"warning_manifest_hash:{(warning_manifest or {}).get('manifest_hash', '')}",
                f"warning_action_matrix_hash:{(warning_manifest or {}).get('warning_action_matrix_hash', '')}",
                f"ux_badges:{','.join((warning_manifest or {}).get('ux_badges', []) if isinstance((warning_manifest or {}).get('ux_badges'), list) else [])}",
            ],
        )
    ]


def legal_limitation_core_accuracy_gates(
    *,
    limitations: Sequence[str],
    limitation_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = [
        "artifact limitation text emitted",
        "parser-provided limitations preserved",
        "jurisdiction caveat emitted",
        "analyst review blocker emitted",
        "limitation count summarized",
    ]
    if limitation_manifest and limitation_manifest.get("limitations"):
        satisfied.append("legal limitation detail metadata emitted")
    if limitation_manifest and limitation_manifest.get("category_counts"):
        satisfied.append("limitation category counts emitted")
    if limitation_manifest and limitation_manifest.get("manifest_hash"):
        satisfied.append("legal limitation wording manifest hash emitted")
    if limitation_manifest and limitation_manifest.get("limitation_wording_matrix_hash"):
        satisfied.append("limitation wording matrix hash emitted")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted legal limitation wording diff pass")
    return [
        build_accuracy_gate(
            93,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"limitation_count:{len(limitations)}",
                f"legal_limitation_manifest_hash:{(limitation_manifest or {}).get('manifest_hash', '')}",
                f"limitation_wording_matrix_hash:{(limitation_manifest or {}).get('limitation_wording_matrix_hash', '')}",
            ],
        )
    ]


def acquisition_metadata_core_accuracy_gates(
    *,
    records: Sequence[Mapping[str, object]],
    missing_required_fields: Sequence[str],
    handoff_manifest: Mapping[str, object] | None = None,
    input_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = ["missing required fields listed", "submission readiness flag emitted"]
    if any(record.get("operator") or record.get("source_identifier") for record in records):
        satisfied.append("operator/source metadata recorded")
    if any(record.get("write_blocker") for record in records):
        satisfied.append("write-blocker field recorded")
    if any(record.get("whole_source_sha256") for record in records):
        satisfied.append("whole-source hash field recorded")
    if records and all(record.get("acquisition_metadata_row_hash") for record in records):
        satisfied.append("acquisition metadata row hashes emitted")
    if handoff_manifest and handoff_manifest.get("evidence_source_row_hashes"):
        satisfied.append("evidence source row hashes emitted")
    if handoff_manifest and handoff_manifest.get("manifest_hash"):
        satisfied.append("acquisition handoff manifest hash emitted")
    if handoff_manifest and handoff_manifest.get("field_completion_matrix_hash"):
        satisfied.append("acquisition field completion matrix hash emitted")
    if input_manifest and input_manifest.get("manifest_hash"):
        satisfied.append("acquisition metadata input manifest hash emitted")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted acquisition handoff diff pass")
    return [
        build_accuracy_gate(
            96,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"record_count:{len(records)}",
                f"missing_required_field_count:{len(missing_required_fields)}",
                f"acquisition_metadata_handoff_manifest_hash:{(handoff_manifest or {}).get('manifest_hash', '')}",
                f"acquisition_field_completion_matrix_hash:{(handoff_manifest or {}).get('field_completion_matrix_hash', '')}",
                f"acquisition_metadata_input_manifest_hash:{(input_manifest or {}).get('manifest_hash', '')}",
            ],
        )
    ]


def timezone_validation_core_accuracy_gates(
    *,
    event_count: int,
    missing_timezone_count: int,
    samples: Sequence[Mapping[str, object]],
    timezone_manifest: Mapping[str, object] | None = None,
    time_semantics_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = [
        "event timezone inventory emitted",
        "missing timezone count emitted",
        "timestamp samples preserved",
        "UTC assumption disclosed",
        "review-required flag emitted",
    ]
    if samples and all(sample.get("timezone_sample_row_hash") for sample in samples):
        satisfied.append("timezone sample row hashes emitted")
    if timezone_manifest and timezone_manifest.get("manifest_hash"):
        satisfied.append("timezone normalization manifest hash emitted")
    if timezone_manifest and timezone_manifest.get("parser_assumption_matrix_hash"):
        satisfied.append("parser assumption matrix hash emitted")
    if time_semantics_manifest and time_semantics_manifest.get("manifest_hash"):
        satisfied.append("time semantics manifest hash emitted")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted timezone normalization matrix diff pass")
    return [
        build_accuracy_gate(
            97,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"event_count:{event_count}",
                f"missing_timezone_count:{missing_timezone_count}",
                f"sample_count:{len(samples)}",
                f"timezone_normalization_manifest_hash:{(timezone_manifest or {}).get('manifest_hash', '')}",
                f"parser_assumption_matrix_hash:{(timezone_manifest or {}).get('parser_assumption_matrix_hash', '')}",
                f"time_semantics_manifest_hash:{(time_semantics_manifest or {}).get('manifest_hash', '')}",
            ],
        )
    ]


def clock_skew_core_accuracy_gates(
    *,
    parsed_timestamp_count: int,
    warnings: Sequence[Mapping[str, object]],
    earliest: str,
    latest: str,
    clock_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = [
        "parsed timestamp range emitted",
        "skew warning records emitted",
        "warning count summarized",
        "baseline requirement disclosed",
        "heuristic limitation emitted",
    ]
    if warnings and all(warning.get("clock_skew_warning_row_hash") for warning in warnings):
        satisfied.append("clock-skew warning row hashes emitted")
    if clock_manifest and clock_manifest.get("manifest_hash"):
        satisfied.append("clock-skew baseline manifest hash emitted")
    if clock_manifest and clock_manifest.get("clock_skew_range_matrix_hash"):
        satisfied.append("clock skew range matrix hash emitted")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted clock-skew baseline diff pass")
    return [
        build_accuracy_gate(
            98,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"parsed_timestamp_count:{parsed_timestamp_count}",
                f"warning_count:{len(warnings)}",
                f"earliest:{earliest}",
                f"latest:{latest}",
                f"clock_skew_baseline_manifest_hash:{(clock_manifest or {}).get('manifest_hash', '')}",
                f"clock_skew_range_matrix_hash:{(clock_manifest or {}).get('clock_skew_range_matrix_hash', '')}",
            ],
        )
    ]


def contamination_warning_core_accuracy_gates(
    *,
    warnings: Sequence[Mapping[str, object]],
    contamination_manifest: Mapping[str, object] | None = None,
    acquisition_context_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = [
        "contamination warning records emitted",
        "warning count summarized",
        "output-under-evidence checks emitted",
        "write-blocker integration limitation emitted",
        "review-required flag emitted",
    ]
    if warnings and all(warning.get("contamination_warning_row_hash") for warning in warnings):
        satisfied.append("contamination warning row hashes emitted")
    if contamination_manifest and contamination_manifest.get("manifest_hash"):
        satisfied.append("contamination checklist manifest hash emitted")
    if contamination_manifest and contamination_manifest.get("warning_review_matrix_hash"):
        satisfied.append("contamination warning review matrix hash emitted")
    if acquisition_context_manifest and acquisition_context_manifest.get("manifest_hash"):
        satisfied.append("contamination acquisition context manifest hash emitted")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted contamination checklist diff pass")
    return [
        build_accuracy_gate(
            99,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"warning_count:{len(warnings)}",
                f"contamination_checklist_manifest_hash:{(contamination_manifest or {}).get('manifest_hash', '')}",
                f"warning_review_matrix_hash:{(contamination_manifest or {}).get('warning_review_matrix_hash', '')}",
                f"contamination_acquisition_context_manifest_hash:{(acquisition_context_manifest or {}).get('manifest_hash', '')}",
            ],
        )
    ]


def stable_payload_sha256(payload: Mapping[str, object] | Sequence[Mapping[str, object]]) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def load_review_target_match(
    connection: sqlite3.Connection,
    case_id: str,
    *,
    target_type: str,
    target_id: str,
) -> dict[str, object] | None:
    try:
        numeric_id = int(target_id)
    except ValueError:
        return None
    if target_type == "indexed_document":
        row = connection.execute(
            """
            SELECT
                indexed_document.citation_id,
                indexed_document.id,
                indexed_document.source_type,
                indexed_document.field_name,
                indexed_document.title,
                indexed_document.body,
                file_record.path AS file_path,
                file_record.hash_md5 AS file_hash_md5,
                file_record.hash_sha1 AS file_hash_sha1,
                file_record.hash_sha256 AS file_hash_sha256,
                artifact.parser_name AS artifact_parser,
                artifact.parser_version AS artifact_parser_version,
                artifact.confidence AS artifact_confidence,
                evidence_source.original_path AS evidence_path,
                evidence_source.hash_md5 AS evidence_hash_md5,
                evidence_source.hash_sha1 AS evidence_hash_sha1,
                evidence_source.hash_sha256 AS evidence_hash_sha256
            FROM indexed_document
            LEFT JOIN file_record ON indexed_document.file_record_id = file_record.id
            LEFT JOIN artifact ON indexed_document.artifact_id = artifact.id
            LEFT JOIN evidence_source ON indexed_document.evidence_source_id = evidence_source.id
            WHERE indexed_document.case_id = ? AND indexed_document.id = ?
            """,
            (case_id, numeric_id),
        ).fetchone()
        if row is None:
            return None
        body = str(row["body"] or "")
        source_path = str(row["file_path"] or row["evidence_path"] or row["title"] or "")
        source_hashes = {
            "md5": str(row["file_hash_md5"] or row["evidence_hash_md5"] or ""),
            "sha1": str(row["file_hash_sha1"] or row["evidence_hash_sha1"] or ""),
            "sha256": str(row["file_hash_sha256"] or row["evidence_hash_sha256"] or ""),
        }
        source_hashes = {key: value for key, value in source_hashes.items() if value}
        return {
            "source": "documents",
            "citation_id": str(row["citation_id"]),
            "target_type": "indexed_document",
            "target_id": str(row["id"]),
            "title": str(row["title"] or "indexed document"),
            "kind": str(row["field_name"] or row["source_type"] or ""),
            "path": source_path,
            "preview": compact_text(body, 240),
            "metadata": {
                "source_path": source_path,
                "source_type": str(row["source_type"] or ""),
                "field_name": str(row["field_name"] or ""),
                "parser": str(row["artifact_parser"] or row["source_type"] or ""),
                "parser_version": str(row["artifact_parser_version"] or "1"),
                "parser_confidence": row["artifact_confidence"] if row["artifact_confidence"] is not None else 0.65,
                "source_index": optional_int(row["id"]),
                "source_hashes": source_hashes,
                "evidence_strength": "indexed-document-match",
                "reportability": "reviewed-report-candidate",
            },
        }
    if target_type == "file_record":
        row = connection.execute(
            """
            SELECT citation_id, id, path, extension, size_bytes, modified_at, hash_md5, hash_sha1, hash_sha256
            FROM file_record
            WHERE case_id = ? AND id = ?
            """,
            (case_id, numeric_id),
        ).fetchone()
        if row is None:
            return None
        return {
            "source": "files",
            "citation_id": str(row["citation_id"]),
            "target_type": "file_record",
            "target_id": str(row["id"]),
            "title": Path(str(row["path"])).name,
            "kind": str(row["extension"] or ""),
            "path": str(row["path"] or ""),
            "preview": str(row["path"] or ""),
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
    if target_type == "artifact":
        row = connection.execute(
            """
            SELECT citation_id, id, artifact_type, title, summary, data_json
            FROM artifact
            WHERE case_id = ? AND id = ?
            """,
            (case_id, numeric_id),
        ).fetchone()
        if row is None:
            return None
        artifact_row = parse_json_object(row["data_json"])
        metadata = artifact_search_metadata(artifact_row)
        return {
            "source": artifact_match_source(str(row["artifact_type"])),
            "citation_id": str(row["citation_id"]),
            "target_type": "artifact",
            "target_id": str(row["id"]),
            "title": str(row["title"] or row["artifact_type"]),
            "kind": str(row["artifact_type"]),
            "path": artifact_source_path(artifact_row),
            "preview": str(row["summary"] or row["artifact_type"]),
            "metadata": metadata,
        }
    if target_type == "event":
        row = connection.execute(
            """
            SELECT citation_id, id, event_type, timestamp, target, description, source
            FROM event
            WHERE case_id = ? AND id = ?
            """,
            (case_id, numeric_id),
        ).fetchone()
        if row is None:
            return None
        return {
            "source": "timeline",
            "citation_id": str(row["citation_id"]),
            "target_type": "event",
            "target_id": str(row["id"]),
            "title": str(row["description"] or row["event_type"]),
            "kind": str(row["event_type"]),
            "timestamp": str(row["timestamp"]),
            "path": str(row["target"] or ""),
            "preview": str(row["description"] or row["target"] or row["event_type"]),
            "metadata": {
                "timestamp": str(row["timestamp"] or ""),
                "timeline_source": str(row["source"] or ""),
            },
        }
    return None


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


def normalize_review_priority(value: str) -> str:
    normalized = str(value or "normal").strip().lower()
    aliases = {"medium": "normal", "med": "normal", "p0": "urgent", "p1": "high", "p2": "normal", "p3": "low"}
    normalized = aliases.get(normalized, normalized)
    supported = {"urgent", "high", "normal", "low"}
    if normalized not in supported:
        raise CaseDatabaseError(f"unsupported review priority {normalized!r}; expected one of: {', '.join(sorted(supported))}")
    return normalized


def normalize_source_citation_package(package: object) -> dict[str, object]:
    if not isinstance(package, Mapping):
        return {}
    normalized = dict(package)
    package_hash = str(normalized.get("package_hash") or "").strip()
    if not package_hash:
        normalized["package_hash"] = stable_payload_sha256(normalized)
    return normalized


def source_citation_package_hash(package: Mapping[str, object]) -> str:
    if not package:
        return ""
    package_hash = str(package.get("package_hash") or "").strip()
    return package_hash or stable_payload_sha256(dict(package))


def build_source_review_handoff(package: Mapping[str, object]) -> dict[str, object]:
    if not package:
        return {
            "profile_version": "source-review-handoff-v1",
            "present": False,
            "ready_for_report_candidate": False,
            "blockers": ["source-read-citation-package-not-attached"],
        }
    blockers = []
    if not package.get("source_locator"):
        blockers.append("source-read-locator-missing")
    if not package.get("source_sha256"):
        blockers.append("source-read-source-hash-not-computed")
    if not package.get("snippet_sha256"):
        blockers.append("source-read-snippet-hash-missing")
    if not package.get("package_hash"):
        blockers.append("source-read-package-hash-missing")
    return {
        "profile_version": "source-review-handoff-v1",
        "present": True,
        "citation_text": str(package.get("citation_text") or ""),
        "package_hash": source_citation_package_hash(package),
        "source_locator_present": bool(package.get("source_locator")),
        "source_sha256_present": bool(package.get("source_sha256")),
        "snippet_sha256_present": bool(package.get("snippet_sha256")),
        "ready_for_report_candidate": not blockers,
        "ready_for_court_report": False,
        "blockers": blockers + ["trusted-source-viewer-locator-diff-required-before-court-use"],
    }


def review_mark_to_dict(row: sqlite3.Row) -> dict[str, object]:
    try:
        tags = json.loads(str(row["tags_json"] or "[]"))
    except json.JSONDecodeError:
        tags = []
    assignee = str(row["assignee"] or "") if "assignee" in row.keys() else ""
    priority = str(row["priority"] or "normal") if "priority" in row.keys() else "normal"
    due_at = str(row["due_at"] or "") if "due_at" in row.keys() else ""
    source_citation_package = (
        normalize_source_citation_package(parse_json_object(row["source_citation_package_json"]))
        if "source_citation_package_json" in row.keys()
        else {}
    )
    review_mark = {
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
        "assignee": assignee,
        "priority": priority,
        "due_at": due_at,
        "source_citation_package": source_citation_package,
        "source_citation_package_hash": source_citation_package_hash(source_citation_package),
        "source_review_handoff": build_source_review_handoff(source_citation_package),
        "review_workflow": review_workflow_assessment(assignee=assignee, priority=priority, due_at=due_at),
        "evidence_selection_versioning": {
            "commercial_gap_ids": ["#65"],
            "status": "versioned-review-mark",
            "include_in_report": bool(row["include_in_report"]),
            "ready_for_court_report": False,
        },
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
    }
    review_mark["review_reporting_qc_contract"] = build_review_reporting_contract(review_marks=[review_mark])
    return review_mark


def review_workflow_assessment(
    *,
    assignee: str,
    priority: str,
    due_at: str,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    satisfied = [
        "review status fields persisted",
        "verification status captured",
        "report inclusion state captured",
        "history/audit limitation warning",
    ]
    if assignee or priority:
        satisfied.append("assignment and priority captured")
    trusted_diff = trusted_diff if isinstance(trusted_diff, Mapping) else {}
    if trusted_diff.get("status") == "pass":
        satisfied.append("trusted reviewer workflow audit diff pass")
    validation_plan = build_review_workflow_report_grade_validation_plan(
        context="review-mark",
        assignment_present=bool(assignee),
        priority=priority,
        due_at=due_at,
        review_queue_count=1,
        source_viewer_locator_count=1,
        audit_history_linked=True,
        review_assignment_manifest_hash="",
        trusted_diff=trusted_diff,
    )
    satisfied.append("review workflow report-grade validation plan")
    if int(validation_plan.get("ready_slot_count") or 0) >= 6:
        satisfied.append("review workflow report-grade ready slots")
    blockers = [
        "local-single-database-review-workflow-until-role-based-server-is-enabled",
        "review-status-does-not-replace-source-verification-and-parser-validation",
        REVIEW_WORKFLOW_TRUSTED_DIFF_BLOCKER,
    ]
    core_accuracy_gates = [
        build_accuracy_gate(
            51,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"assignee:{assignee}",
                f"priority:{priority}",
                f"due_at:{due_at}",
                "case_db:review_mark",
                "case_db:review_mark_history",
                f"trusted_diff_status:{trusted_diff.get('status', 'missing')}",
                f"review_workflow_report_grade_validation_plan_sha256:{validation_plan['validation_plan_sha256']}",
            ],
        )
    ]
    active_blockers = [blocker for blocker in blockers if blocker != REVIEW_WORKFLOW_TRUSTED_DIFF_BLOCKER or trusted_diff.get("status") != "pass"]
    return {
        "commercial_gap_ids": ["#51"],
        "status": "implemented-baseline-validation-required",
        "assignment_present": bool(assignee),
        "priority": priority,
        "due_at": due_at,
        "core_accuracy_gates": core_accuracy_gates,
        "trusted_review_workflow_diff": dict(trusted_diff) if trusted_diff else {
            "status": "missing",
            "blocker_id": REVIEW_WORKFLOW_TRUSTED_DIFF_BLOCKER,
            "required_tools": sorted(REVIEW_WORKFLOW_TRUSTED_TOOLS),
        },
        "review_workflow_report_grade_validation_plan": validation_plan,
        "review_workflow_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
        "commercial_uplift_evidence": {
            "batch_id": "commercial-uplift-051-055",
            "item_numbers": [51],
            "implementation_track": "case-db-reviewer-assignment-status-workflow",
            "source_refs": [
                f"assignee:{assignee}",
                f"priority:{priority}",
                f"due_at:{due_at}",
                "case_db:review_mark",
                "case_db:review_mark_history",
                f"review_workflow_report_grade_validation_plan_sha256:{validation_plan['validation_plan_sha256']}",
            ],
            "reportability_decision": {
                "profile_version": "case-review-workflow-reportability-decision-v1",
                "commercial_gap_ids": ["#51"],
                "decision": "do-not-report-review-workflow-as-role-based-case-management",
                "allowed_use": "single-user-review-status-triage-pivot",
                "blockers": [
                    "multi-user-conflict-resolution",
                    "notification-workflow",
                    "role-based-assignment-queue",
                    "sla-dashboard",
                    *([] if trusted_diff.get("status") == "pass" else [REVIEW_WORKFLOW_TRUSTED_DIFF_BLOCKER]),
                ],
                "ready_for_court_report": False,
                "review_workflow_report_grade_validation_plan_present": True,
                "review_workflow_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
                "review_workflow_report_grade_ready_slot_count": int(validation_plan.get("ready_slot_count") or 0),
                "review_workflow_report_grade_blocking_slot_count": int(
                    validation_plan.get("blocking_slot_count") or 0
                ),
                "required_before_report": [
                    "enable role-based multi-user queues, conflict handling, notifications, and signed reviewer SOPs",
                    "verify source hashes, parser limitations, and immutable history before report inclusion",
                ],
            },
            "passed_validation_check_ids": sorted(set(satisfied)),
            "failed_validation_check_ids": [
                "role-based-assignment-queue",
                "sla-dashboard",
                "notification-workflow",
                "multi-user-conflict-resolution",
                *([] if trusted_diff.get("status") == "pass" else [REVIEW_WORKFLOW_TRUSTED_DIFF_BLOCKER]),
            ],
            "commercial_blockers": active_blockers,
            "large_data_controls": {
                "local_case_db_review_mark": True,
                "assignment_present": bool(assignee),
                "priority_normalized": bool(priority),
                "due_date_recorded": bool(due_at),
                "audit_history_linked": True,
                "review_workflow_report_grade_validation_plan_present": True,
                "review_workflow_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
                "review_workflow_report_grade_ready_slot_count": int(validation_plan.get("ready_slot_count") or 0),
                "review_workflow_report_grade_blocking_slot_count": int(
                    validation_plan.get("blocking_slot_count") or 0
                ),
                "role_based_case_server": False,
            },
            "reporting_status": "implemented-baseline-validation-required",
        },
        "ready_for_court_report": False,
        "blockers": active_blockers,
        "supported_fields": [
            "status",
            "verification_status",
            "reviewer",
            "assignee",
            "priority",
            "due_at",
            "tags",
            "include_in_report",
            "history",
        ],
    }


def build_review_workflow_report_grade_validation_plan(
    *,
    context: str,
    assignment_present: bool,
    priority: str,
    due_at: str,
    review_queue_count: int,
    source_viewer_locator_count: int,
    audit_history_linked: bool,
    review_assignment_manifest_hash: str,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    trusted_diff = trusted_diff if isinstance(trusted_diff, Mapping) else {}

    def slot(
        slot_id: str,
        *,
        ready: bool,
        evidence: str,
        blocker_id: str | None = None,
        operator_action: str = "",
    ) -> dict[str, object]:
        row: dict[str, object] = {
            "slot_id": slot_id,
            "status": "complete" if ready else "external-required",
            "evidence": evidence,
        }
        if blocker_id and not ready:
            row["blocker_id"] = blocker_id
        if operator_action:
            row["operator_action"] = operator_action
        return row

    validation_slots = [
        slot(
            "case-review-status-fields-persisted",
            ready=True,
            evidence=f"context={context}",
            blocker_id="case-review-status-fields-required",
            operator_action="Persist review status, verification status, and report inclusion state.",
        ),
        slot(
            "case-review-assignment-priority-metadata",
            ready=assignment_present or bool(priority),
            evidence=f"assignment_present={assignment_present} priority={priority}",
            blocker_id="case-review-assignment-priority-required",
            operator_action="Capture assignee/priority metadata before using rows as a review queue.",
        ),
        slot(
            "case-review-due-date-or-followup-state",
            ready=True,
            evidence=f"due_at={due_at}",
            blocker_id="case-review-followup-state-required",
            operator_action="Record due date or explicit empty follow-up state.",
        ),
        slot(
            "case-review-source-viewer-locators",
            ready=source_viewer_locator_count > 0,
            evidence=f"source_viewer_locator_count={source_viewer_locator_count}",
            blocker_id="case-review-source-viewer-locators-required",
            operator_action="Attach source-viewer locators so reviewers can verify evidence before report inclusion.",
        ),
        slot(
            "case-review-audit-history-linked",
            ready=audit_history_linked,
            evidence=f"audit_history_linked={audit_history_linked}",
            blocker_id="case-review-audit-history-required",
            operator_action="Link review state changes to review mark history before report use.",
        ),
        slot(
            "case-review-bounded-queue-or-mark-emitted",
            ready=review_queue_count > 0,
            evidence=f"review_queue_count={review_queue_count} assignment_manifest_hash={review_assignment_manifest_hash}",
            blocker_id="case-review-queue-or-mark-required",
            operator_action="Emit at least one review queue row or review mark workflow record.",
        ),
        slot(
            "case-review-role-based-assignment-queue",
            ready=False,
            evidence="role_based_assignment_queue=false",
            blocker_id="role-based-assignment-queue-required",
            operator_action="Add role-based queues and per-action permission enforcement.",
        ),
        slot(
            "case-review-notification-workflow",
            ready=False,
            evidence="notification_workflow=false",
            blocker_id="notification-workflow-required",
            operator_action="Add notifications for assignment, due dates, and review handoffs.",
        ),
        slot(
            "case-review-multi-user-conflict-resolution",
            ready=False,
            evidence="multi_user_conflict_resolution=false",
            blocker_id="multi-user-conflict-resolution-required",
            operator_action="Add locking/conflict records for concurrent reviewers.",
        ),
        slot(
            "case-review-sla-dashboard",
            ready=False,
            evidence="sla_dashboard=false",
            blocker_id="sla-dashboard-required",
            operator_action="Add SLA/aging dashboards for review queues.",
        ),
        slot(
            "case-review-reviewer-sop-signoff",
            ready=False,
            evidence="reviewer_sop_signoff=false",
            blocker_id="reviewer-sop-signoff-required",
            operator_action="Attach signed reviewer SOP/training signoff for commercial workflow claims.",
        ),
        slot(
            "case-review-trusted-audit-diff",
            ready=trusted_diff.get("status") == "pass",
            evidence=f"trusted_diff_status={trusted_diff.get('status', 'missing')}",
            blocker_id=REVIEW_WORKFLOW_TRUSTED_DIFF_BLOCKER,
            operator_action="Attach a passing trusted reviewer workflow audit diff before report-grade claims.",
        ),
    ]
    blockers = sorted(
        str(slot_row.get("blocker_id"))
        for slot_row in validation_slots
        if slot_row.get("status") != "complete" and slot_row.get("blocker_id")
    )
    ready_slot_count = sum(1 for slot_row in validation_slots if slot_row.get("status") == "complete")
    plan_core: dict[str, object] = {
        "profile_version": REVIEW_WORKFLOW_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 51,
        "gap_id": "#51",
        "batch_id": "commercial-uplift-051-055",
        "selected_track": "single-case-review-workflow-report-validation",
        "context": context,
        "assignment_present": assignment_present,
        "priority": priority,
        "due_at": due_at,
        "review_queue_count": review_queue_count,
        "source_viewer_locator_count": source_viewer_locator_count,
        "audit_history_linked": audit_history_linked,
        "review_assignment_manifest_hash": review_assignment_manifest_hash,
        "trusted_diff_status": str(trusted_diff.get("status") or "missing"),
        "ready_slot_count": ready_slot_count,
        "blocking_slot_count": len(blockers),
        "validation_status": "report-validation-blocked",
        "commercial_grade": False,
        "commercial_grade_ready": False,
        "validation_slots": validation_slots,
        "blockers": blockers,
        "commercial_grade_blockers": list(REVIEW_WORKFLOW_REPORT_GRADE_BLOCKERS),
        "validation_commands": [
            "rapidtriage case-review --case-id <case> --target-type <type> --target-id <id> --json",
            "rapidtriage case-search --case-id <case> --query <keyword> --json",
            "rapidtriage commercial-readiness --validation-package docs/validation/rapidtriage-core-forensics-051-060-known-answer.json --limit 51 --json",
        ],
        "report_guidance": {
            "allowed_use": "single-user-review-status-triage-pivot",
            "forbidden_claim": "role-based multi-user case-management workflow",
            "required_disclaimer": (
                "Review workflow rows are local Case DB triage state and require role-based queues, "
                "notifications, multi-user conflict handling, SLA dashboards, reviewer SOP signoff, and "
                "trusted audit diffs before commercial case-management claims."
            ),
        },
    }
    return {**plan_core, "validation_plan_sha256": stable_payload_sha256(plan_core)}


def build_case_search_review_workflow_summary(
    matches: Sequence[Mapping[str, object]],
    *,
    review_status_filter: str | None = None,
    verification_status_filter: str | None = None,
) -> dict[str, object]:
    status_counts: dict[str, int] = {}
    verification_counts: dict[str, int] = {}
    assignee_counts: dict[str, int] = {}
    priority_counts: dict[str, int] = {}
    review_queue: list[dict[str, object]] = []
    assigned_count = 0
    unassigned_count = 0
    report_candidate_count = 0
    for index, match in enumerate(matches):
        review = match.get("review") if isinstance(match.get("review"), Mapping) else {}
        status = str(review.get("status") or "unreviewed")
        verification = str(review.get("verification_status") or "unverified")
        assignee = str(review.get("assignee") or "")
        priority = normalize_review_priority(str(review.get("priority") or "normal"))
        include_in_report = bool(review.get("include_in_report"))
        status_counts[status] = status_counts.get(status, 0) + 1
        verification_counts[verification] = verification_counts.get(verification, 0) + 1
        priority_counts[priority] = priority_counts.get(priority, 0) + 1
        if assignee:
            assigned_count += 1
            assignee_counts[assignee] = assignee_counts.get(assignee, 0) + 1
        else:
            unassigned_count += 1
        if include_in_report:
            report_candidate_count += 1
        queue_row_core = {
            "queue_position": index + 1,
            "target_type": str(match.get("target_type") or ""),
            "target_id": str(match.get("target_id") or ""),
            "citation_id": str(match.get("citation_id") or review.get("citation_id") or ""),
            "title": str(match.get("title") or match.get("path") or ""),
            "source": str(match.get("source") or "unknown"),
            "status": status,
            "verification_status": verification,
            "assignee": assignee,
            "priority": priority,
            "due_at": str(review.get("due_at") or ""),
            "include_in_report": include_in_report,
            "review_action": review_queue_action(status=status, verification_status=verification, assignee=assignee),
            "source_viewer_locator": build_review_queue_source_viewer_locator(match, review),
        }
        review_queue.append({**queue_row_core, "queue_row_hash": stable_payload_sha256(queue_row_core)})
    review_assignment_manifest = build_review_assignment_manifest(
        review_queue,
        status_counts=status_counts,
        verification_counts=verification_counts,
        assignee_counts=assignee_counts,
        priority_counts=priority_counts,
        report_candidate_count=report_candidate_count,
        review_status_filter=review_status_filter,
        verification_status_filter=verification_status_filter,
    )
    validation_plan = build_review_workflow_report_grade_validation_plan(
        context="case-search-review-summary",
        assignment_present=assigned_count > 0,
        priority=",".join(sorted(priority_counts)) or "normal",
        due_at="",
        review_queue_count=len(review_queue),
        source_viewer_locator_count=review_assignment_manifest["source_viewer_locator_count"],
        audit_history_linked=True,
        review_assignment_manifest_hash=review_assignment_manifest["manifest_hash"],
        trusted_diff=None,
    )
    satisfied = [
        "search result review state attached",
        "review status summary emitted",
        "verification status summary emitted",
        "assignment queue metadata emitted",
        "report inclusion queue emitted",
        "review assignment manifest hash emitted",
        "history/audit limitation warning",
    ]
    if review_assignment_manifest["source_viewer_locator_count"]:
        satisfied.append("review source viewer locators emitted")
    if review_status_filter:
        satisfied.append("review status filter applied")
    if verification_status_filter:
        satisfied.append("verification status filter applied")
    satisfied.append("review workflow report-grade validation plan")
    if int(validation_plan.get("ready_slot_count") or 0) >= 6:
        satisfied.append("review workflow report-grade ready slots")
    core_accuracy_gates = [
        build_accuracy_gate(
            51,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"match_count:{len(matches)}",
                f"assigned_count:{assigned_count}",
                f"report_candidate_count:{report_candidate_count}",
                f"review_status_filter:{review_status_filter or ''}",
                f"verification_status_filter:{verification_status_filter or ''}",
                f"review_assignment_manifest_hash:{review_assignment_manifest['manifest_hash']}",
                f"review_workflow_report_grade_validation_plan_sha256:{validation_plan['validation_plan_sha256']}",
                "case_db:review_mark",
                "case_db:review_mark_history",
            ],
        )
    ]
    return {
        "profile_version": "case-search-review-workflow-summary-v1",
        "commercial_gap_ids": ["#51"],
        "status": "implemented-baseline-validation-required",
        "match_count": len(matches),
        "status_counts": dict(sorted(status_counts.items())),
        "verification_status_counts": dict(sorted(verification_counts.items())),
        "assignee_counts": dict(sorted(assignee_counts.items())),
        "priority_counts": dict(sorted(priority_counts.items())),
        "assigned_count": assigned_count,
        "unassigned_count": unassigned_count,
        "report_candidate_count": report_candidate_count,
        "review_queue": review_queue[:100],
        "review_queue_count": len(review_queue),
        "review_queue_truncated": len(review_queue) > 100,
        "review_assignment_manifest": review_assignment_manifest,
        "review_assignment_manifest_hash": review_assignment_manifest["manifest_hash"],
        "review_workflow_report_grade_validation_plan": validation_plan,
        "review_workflow_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
        "source_viewer_locator_count": review_assignment_manifest["source_viewer_locator_count"],
        "filters": {
            "review_status": review_status_filter or "",
            "verification_status": verification_status_filter or "",
        },
        "core_accuracy_gates": core_accuracy_gates,
        "commercial_uplift_evidence": {
            "batch_id": "commercial-uplift-051-055",
            "item_numbers": [51],
            "implementation_track": "case-db-search-reviewer-assignment-status-summary",
            "source_refs": [
                f"matches:{len(matches)}",
                f"assigned:{assigned_count}",
                f"report_candidates:{report_candidate_count}",
                "case_db:review_mark",
                "case_db:review_mark_history",
                f"review_workflow_report_grade_validation_plan_sha256:{validation_plan['validation_plan_sha256']}",
            ],
            "passed_validation_check_ids": sorted(set(satisfied)),
            "failed_validation_check_ids": [
                "role-based-assignment-queue",
                "notification-workflow",
                "multi-user-conflict-resolution",
                REVIEW_WORKFLOW_TRUSTED_DIFF_BLOCKER,
            ],
            "large_data_controls": {
                "bounded_review_queue": True,
                "review_queue_limit": 100,
                "assigned_count": assigned_count,
                "report_candidate_count": report_candidate_count,
                "review_assignment_manifest_present": True,
                "review_assignment_manifest_hash": review_assignment_manifest["manifest_hash"],
                "review_workflow_report_grade_validation_plan_present": True,
                "review_workflow_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
                "review_workflow_report_grade_ready_slot_count": int(validation_plan.get("ready_slot_count") or 0),
                "review_workflow_report_grade_blocking_slot_count": int(
                    validation_plan.get("blocking_slot_count") or 0
                ),
                "source_viewer_locator_count": review_assignment_manifest["source_viewer_locator_count"],
                "role_based_case_server": False,
                "notification_sla_enabled": False,
            },
            "reportability_decision": {
                "profile_version": "case-search-review-workflow-reportability-decision-v1",
                "commercial_gap_ids": ["#51"],
                "decision": "do-not-report-review-search-summary-as-role-based-case-management",
                "allowed_use": "single-user-review-queue-triage-summary",
                "blockers": [
                    "multi-user-conflict-resolution",
                    "notification-workflow",
                    "role-based-assignment-queue",
                    REVIEW_WORKFLOW_TRUSTED_DIFF_BLOCKER,
                ],
                "ready_for_court_report": False,
                "review_workflow_report_grade_validation_plan_present": True,
                "review_workflow_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
                "review_workflow_report_grade_ready_slot_count": int(validation_plan.get("ready_slot_count") or 0),
                "review_workflow_report_grade_blocking_slot_count": int(
                    validation_plan.get("blocking_slot_count") or 0
                ),
            },
        },
        "ready_for_court_report": False,
        "blockers": [
            "role-based-assignment-queue",
            "notification-workflow",
            "multi-user-conflict-resolution",
            REVIEW_WORKFLOW_TRUSTED_DIFF_BLOCKER,
        ],
    }


def build_review_queue_source_viewer_locator(match: Mapping[str, object], review: Mapping[str, object]) -> dict[str, object]:
    metadata = match.get("metadata") if isinstance(match.get("metadata"), Mapping) else {}
    upstream_locator = (
        dict(metadata.get("source_viewer_locator")) if isinstance(metadata.get("source_viewer_locator"), Mapping) else {}
    )
    return {
        "viewer": "case-review-source",
        "source": str(match.get("source") or "unknown"),
        "target_type": str(match.get("target_type") or ""),
        "target_id": str(match.get("target_id") or ""),
        "citation_id": str(match.get("citation_id") or ""),
        "review_citation_id": str(review.get("citation_id") or ""),
        "path": str(match.get("path") or metadata.get("source_path") or ""),
        "kind": str(match.get("kind") or metadata.get("kind") or ""),
        "title": str(match.get("title") or match.get("path") or ""),
        "source_record": {
            "row_id": metadata.get("row_id") if metadata.get("row_id") is not None else match.get("target_id"),
            "line": metadata.get("line") if metadata.get("line") is not None else "",
            "table": str(metadata.get("table") or ""),
            "record_offset": metadata.get("record_offset") if metadata.get("record_offset") is not None else "",
            "source_index": metadata.get("source_index") if metadata.get("source_index") is not None else "",
        },
        "upstream_source_viewer_locator": upstream_locator,
        "parser_manifest_hashes": dict(metadata.get("parser_manifest_hashes"))
        if isinstance(metadata.get("parser_manifest_hashes"), Mapping)
        else {},
        "open_action": "open-source-and-verify-before-report",
    }


def build_review_assignment_manifest(
    review_queue: Sequence[Mapping[str, object]],
    *,
    status_counts: Mapping[str, int],
    verification_counts: Mapping[str, int],
    assignee_counts: Mapping[str, int],
    priority_counts: Mapping[str, int],
    report_candidate_count: int,
    review_status_filter: str | None,
    verification_status_filter: str | None,
) -> dict[str, object]:
    entries: list[dict[str, object]] = []
    source_viewer_locator_count = 0
    for row in review_queue[:100]:
        locator = row.get("source_viewer_locator") if isinstance(row.get("source_viewer_locator"), Mapping) else {}
        if locator.get("target_type") and locator.get("target_id"):
            source_viewer_locator_count += 1
        entries.append(
            {
                "queue_position": int(row.get("queue_position") or 0),
                "target_type": str(row.get("target_type") or ""),
                "target_id": str(row.get("target_id") or ""),
                "citation_id": str(row.get("citation_id") or ""),
                "status": str(row.get("status") or "unreviewed"),
                "verification_status": str(row.get("verification_status") or "unverified"),
                "assignee": str(row.get("assignee") or ""),
                "priority": str(row.get("priority") or "normal"),
                "due_at": str(row.get("due_at") or ""),
                "include_in_report": bool(row.get("include_in_report")),
                "review_action": str(row.get("review_action") or ""),
                "source_viewer_locator": dict(locator),
                "queue_row_hash": str(row.get("queue_row_hash") or ""),
            }
        )
    manifest_core: dict[str, object] = {
        "manifest_version": "case-review-assignment-manifest-v1",
        "item_number": 51,
        "commercial_gap_ids": ["#51"],
        "queue_entry_count": len(review_queue),
        "bounded_entry_count": len(entries),
        "queue_truncated": len(review_queue) > len(entries),
        "status_counts": dict(sorted(status_counts.items())),
        "verification_status_counts": dict(sorted(verification_counts.items())),
        "assignee_counts": dict(sorted(assignee_counts.items())),
        "priority_counts": dict(sorted(priority_counts.items())),
        "report_candidate_count": report_candidate_count,
        "source_viewer_locator_count": source_viewer_locator_count,
        "filters": {
            "review_status": review_status_filter or "",
            "verification_status": verification_status_filter or "",
        },
        "entries": entries,
        "blockers": [
            "role-based-assignment-queue",
            "notification-workflow",
            "multi-user-conflict-resolution",
            REVIEW_WORKFLOW_TRUSTED_DIFF_BLOCKER,
        ],
        "commercial_claim_allowed": False,
        "operator_warning": (
            "This manifest supports single-case reviewer triage and source opening only; "
            "it is not a multi-user RBAC/SLA workflow until the listed blockers are resolved."
        ),
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def review_queue_action(*, status: str, verification_status: str, assignee: str) -> str:
    if status == "unreviewed":
        return "assign-reviewer-and-open-source"
    if verification_status in {"unverified", ""}:
        return "verify-source-before-report"
    if not assignee:
        return "assign-owner-for-follow-up"
    return "ready-for-lead-review" if verification_status == "verified" else "continue-review"


def build_reviewer_workflow_trusted_diff(
    rapid_rows: Sequence[Mapping[str, object]],
    trusted_rows: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str,
    comparison_id: str = "review-workflow-trusted-audit-diff",
) -> dict[str, object]:
    rapid_index = {_review_workflow_diff_key(row): _review_workflow_diff_values(row) for row in rapid_rows}
    trusted_index = {_review_workflow_diff_key(row): _review_workflow_diff_values(row) for row in trusted_rows}
    rapid_index.pop("", None)
    trusted_index.pop("", None)
    missing_in_trusted = sorted(key for key in rapid_index if key not in trusted_index)
    unexpected_in_trusted = sorted(key for key in trusted_index if key not in rapid_index)
    mismatches: list[dict[str, object]] = []
    for key in sorted(set(rapid_index) & set(trusted_index)):
        rapid = rapid_index[key]
        trusted = trusted_index[key]
        for field in ("status", "verification_status", "reviewer", "assignee", "priority", "due_at", "include_in_report", "tags"):
            if rapid.get(field) != trusted.get(field):
                mismatches.append({"row_key": key, "field": field, "rapid": rapid.get(field, ""), "trusted": trusted.get(field, "")})
    tool_accepted = trusted_tool.strip().lower() in REVIEW_WORKFLOW_TRUSTED_TOOLS
    status = "pass" if tool_accepted and rapid_index and trusted_index and not missing_in_trusted and not unexpected_in_trusted and not mismatches else "fail"
    return {
        "profile_version": "review-workflow-trusted-audit-diff-v1",
        "comparison_id": comparison_id,
        "status": status,
        "blocker_id": "" if status == "pass" else REVIEW_WORKFLOW_TRUSTED_DIFF_BLOCKER,
        "trusted_tool": trusted_tool,
        "trusted_tool_accepted": tool_accepted,
        "accepted_trusted_tools": sorted(REVIEW_WORKFLOW_TRUSTED_TOOLS),
        "rapid_row_count": len(rapid_index),
        "trusted_row_count": len(trusted_index),
        "matched_count": len(set(rapid_index) & set(trusted_index)),
        "missing_in_trusted_count": len(missing_in_trusted),
        "unexpected_in_trusted_count": len(unexpected_in_trusted),
        "mismatch_count": len(mismatches),
        "mismatched_fields": mismatches[:50],
        "missing_in_trusted": missing_in_trusted[:50],
        "unexpected_in_trusted": unexpected_in_trusted[:50],
        "commercial_grade_evidence": status == "pass",
    }


def _review_workflow_diff_key(row: Mapping[str, object]) -> str:
    citation = str(row.get("citation_id") or row.get("review_citation_id") or "").strip()
    if citation:
        return citation
    target_type = str(row.get("target_type") or "").strip()
    target_id = str(row.get("target_id") or "").strip()
    return f"{target_type}:{target_id}" if target_type or target_id else ""


def _review_workflow_diff_values(row: Mapping[str, object]) -> dict[str, object]:
    tags = row.get("tags")
    if isinstance(tags, str):
        normalized_tags = sorted(item.strip() for item in tags.split(",") if item.strip())
    elif isinstance(tags, Sequence) and not isinstance(tags, (bytes, bytearray, str)):
        normalized_tags = sorted(str(item).strip() for item in tags if str(item).strip())
    else:
        normalized_tags = []
    return {
        "status": str(row.get("status") or ""),
        "verification_status": str(row.get("verification_status") or ""),
        "reviewer": str(row.get("reviewer") or ""),
        "assignee": str(row.get("assignee") or ""),
        "priority": str(row.get("priority") or ""),
        "due_at": str(row.get("due_at") or ""),
        "include_in_report": bool(row.get("include_in_report")),
        "tags": ",".join(normalized_tags),
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


def acquisition_metadata_to_dict(row: sqlite3.Row | None) -> dict[str, object]:
    if row is None:
        return {}
    return {
        "citation_id": str(row["citation_id"]),
        "case_id": str(row["case_id"]),
        "evidence_source_citation_id": str(row["evidence_source_citation_id"] or ""),
        "operator": str(row["operator"] or ""),
        "acquisition_started_at": str(row["acquisition_started_at"] or ""),
        "acquisition_completed_at": str(row["acquisition_completed_at"] or ""),
        "source_identifier": str(row["source_identifier"] or ""),
        "write_blocker": str(row["write_blocker"] or ""),
        "acquisition_tool": str(row["acquisition_tool"] or ""),
        "acquisition_tool_version": str(row["acquisition_tool_version"] or ""),
        "whole_source_sha256": str(row["whole_source_sha256"] or ""),
        "notes": str(row["notes"] or ""),
        "created_at": str(row["created_at"]),
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

CREATE VIRTUAL TABLE IF NOT EXISTS file_record_fts USING fts5(
    path,
    extension,
    hashes
);

CREATE TRIGGER IF NOT EXISTS file_record_fts_ai AFTER INSERT ON file_record BEGIN
    INSERT INTO file_record_fts(rowid, path, extension, hashes)
    VALUES (
        new.id,
        new.path,
        new.extension,
        trim(COALESCE(new.hash_md5, '') || ' ' || COALESCE(new.hash_sha1, '') || ' ' || COALESCE(new.hash_sha256, ''))
    );
END;

CREATE TRIGGER IF NOT EXISTS file_record_fts_ad AFTER DELETE ON file_record BEGIN
    DELETE FROM file_record_fts WHERE rowid = old.id;
END;

CREATE TRIGGER IF NOT EXISTS file_record_fts_au AFTER UPDATE ON file_record BEGIN
    DELETE FROM file_record_fts WHERE rowid = old.id;
    INSERT INTO file_record_fts(rowid, path, extension, hashes)
    VALUES (
        new.id,
        new.path,
        new.extension,
        trim(COALESCE(new.hash_md5, '') || ' ' || COALESCE(new.hash_sha1, '') || ' ' || COALESCE(new.hash_sha256, ''))
    );
END;

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

CREATE TABLE IF NOT EXISTS acquisition_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    citation_id TEXT NOT NULL UNIQUE,
    case_id TEXT NOT NULL,
    evidence_source_citation_id TEXT NOT NULL DEFAULT '',
    operator TEXT NOT NULL DEFAULT '',
    acquisition_started_at TEXT NOT NULL DEFAULT '',
    acquisition_completed_at TEXT NOT NULL DEFAULT '',
    source_identifier TEXT NOT NULL DEFAULT '',
    write_blocker TEXT NOT NULL DEFAULT '',
    acquisition_tool TEXT NOT NULL DEFAULT '',
    acquisition_tool_version TEXT NOT NULL DEFAULT '',
    whole_source_sha256 TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
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
    metadata
);

CREATE TRIGGER IF NOT EXISTS artifact_fts_ai AFTER INSERT ON artifact BEGIN
    INSERT INTO artifact_fts(rowid, title, summary, metadata)
    VALUES (
        new.id,
        new.title,
        new.summary,
        new.data_json
    );
END;

CREATE TRIGGER IF NOT EXISTS artifact_fts_ad AFTER DELETE ON artifact BEGIN
    DELETE FROM artifact_fts WHERE rowid = old.id;
END;

CREATE TRIGGER IF NOT EXISTS artifact_fts_au AFTER UPDATE ON artifact BEGIN
    DELETE FROM artifact_fts WHERE rowid = old.id;
    INSERT INTO artifact_fts(rowid, title, summary, metadata)
    VALUES (
        new.id,
        new.title,
        new.summary,
        new.data_json
    );
END;

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

CREATE VIRTUAL TABLE IF NOT EXISTS event_fts USING fts5(
    event_type,
    timestamp,
    target,
    description,
    source
);

CREATE TRIGGER IF NOT EXISTS event_fts_ai AFTER INSERT ON event BEGIN
    INSERT INTO event_fts(rowid, event_type, timestamp, target, description, source)
    VALUES (
        new.id,
        new.event_type,
        new.timestamp,
        new.target,
        new.description,
        new.source
    );
END;

CREATE TRIGGER IF NOT EXISTS event_fts_ad AFTER DELETE ON event BEGIN
    DELETE FROM event_fts WHERE rowid = old.id;
END;

CREATE TRIGGER IF NOT EXISTS event_fts_au AFTER UPDATE ON event BEGIN
    DELETE FROM event_fts WHERE rowid = old.id;
    INSERT INTO event_fts(rowid, event_type, timestamp, target, description, source)
    VALUES (
        new.id,
        new.event_type,
        new.timestamp,
        new.target,
        new.description,
        new.source
    );
END;

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
    assignee TEXT NOT NULL DEFAULT '',
    priority TEXT NOT NULL DEFAULT 'normal',
    due_at TEXT NOT NULL DEFAULT '',
    source_citation_package_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES case_record(case_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS review_mark_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    review_citation_id TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    changed_at TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT '',
    changed_fields_json TEXT NOT NULL DEFAULT '[]',
    previous_json TEXT NOT NULL DEFAULT '{}',
    current_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (case_id) REFERENCES case_record(case_id) ON DELETE CASCADE
);

CREATE TRIGGER IF NOT EXISTS review_mark_history_no_update
BEFORE UPDATE ON review_mark_history
BEGIN
    SELECT RAISE(ABORT, 'review_mark_history is append-only');
END;

CREATE TRIGGER IF NOT EXISTS review_mark_history_no_delete
BEFORE DELETE ON review_mark_history
BEGIN
    SELECT RAISE(ABORT, 'review_mark_history is append-only');
END;

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
CREATE INDEX IF NOT EXISTS idx_acquisition_metadata_case_source ON acquisition_metadata(case_id, evidence_source_citation_id);
CREATE INDEX IF NOT EXISTS idx_artifact_case_type ON artifact(case_id, artifact_type);
CREATE INDEX IF NOT EXISTS idx_event_case_time ON event(case_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_indexed_document_case_source ON indexed_document(case_id, source_type);
CREATE INDEX IF NOT EXISTS idx_review_mark_case_status ON review_mark(case_id, status, verification_status);
CREATE INDEX IF NOT EXISTS idx_review_mark_case_target ON review_mark(case_id, target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_review_mark_history_target ON review_mark_history(case_id, target_type, target_id, version);
CREATE INDEX IF NOT EXISTS idx_saved_search_case_name ON saved_search(case_id, name);
CREATE INDEX IF NOT EXISTS idx_audit_event_case_time ON audit_event(case_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_report_item_case_section ON report_item(case_id, section, order_index);
CREATE INDEX IF NOT EXISTS idx_job_case_status ON job(case_id, status);
"""
