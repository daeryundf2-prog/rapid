"""Case DB constants and schema SQL."""

from __future__ import annotations

__all__ = [
    "ACQUISITION_HASH_GAP_ID",
    "ACQUISITION_HASH_REPORT_GRADE_BLOCKERS",
    "ACQUISITION_HASH_REPORT_GRADE_VALIDATION_PLAN_VERSION",
    "ACQUISITION_HASH_TRUSTED_DIFF_BLOCKER_87",
    "ACQUISITION_METADATA_REPORT_GRADE_BLOCKERS",
    "ACQUISITION_METADATA_REPORT_GRADE_VALIDATION_PLAN_VERSION",
    "ACQUISITION_METADATA_TRUSTED_DIFF_BLOCKER_96",
    "ACQUISITION_QUALITY_TRUSTED_TOOLS",
    "CASE_DB_SEARCH_MIN_SCAN_ROWS",
    "CASE_DB_SEARCH_SCAN_OVERSAMPLE",
    "CASE_DB_SEARCH_SCAN_ROW_LIMIT",
    "CASE_SEARCH_CURSOR_VERSION",
    "CHAIN_OF_CUSTODY_GAP_ID",
    "CITATION_KIND_PREFIXES",
    "CITATION_WIDTH",
    "CLOCK_SKEW_ANALYSIS_GAP_ID",
    "CLOCK_SKEW_REPORT_GRADE_BLOCKERS",
    "CLOCK_SKEW_REPORT_GRADE_VALIDATION_PLAN_VERSION",
    "CLOCK_SKEW_TRUSTED_DIFF_BLOCKER_98",
    "CONTAMINATION_WARNING_REPORT_GRADE_BLOCKERS",
    "CONTAMINATION_WARNING_REPORT_GRADE_VALIDATION_PLAN_VERSION",
    "CONTAMINATION_WARNING_TRUSTED_DIFF_BLOCKER_99",
    "COURT_EXHIBIT_EXPORT_GAP_ID",
    "CUSTODY_REPORT_GRADE_BLOCKERS",
    "CUSTODY_REPORT_GRADE_VALIDATION_PLAN_VERSION",
    "CUSTODY_TRUSTED_DIFF_BLOCKER_86",
    "EVIDENCE_CONTAMINATION_WARNING_GAP_ID",
    "EVIDENCE_SELECTION_REPORT_GRADE_BLOCKERS",
    "EVIDENCE_SELECTION_REPORT_GRADE_VALIDATION_PLAN_VERSION",
    "FORENSIC_INTEGRITY_BATCH_ID",
    "FORENSIC_INTEGRITY_TRUSTED_TOOLS",
    "FUNCTIONAL_DEFENSIBILITY_BATCH_ID",
    "FUNCTIONAL_REPORTING_BATCH_ID",
    "FUNCTIONAL_SCALE_BATCH_ID",
    "FUNCTIONAL_VALIDATION_BATCH_ID",
    "IMMUTABLE_AUDIT_GAP_ID",
    "IMMUTABLE_AUDIT_REPORT_GRADE_BLOCKERS",
    "IMMUTABLE_AUDIT_REPORT_GRADE_VALIDATION_PLAN_VERSION",
    "IMMUTABLE_AUDIT_TRUSTED_DIFF_BLOCKER_88",
    "LARGE_SQLITE_FTS_GAP_ID",
    "LARGE_SQLITE_FTS_REPORT_GRADE_BLOCKERS",
    "LARGE_SQLITE_FTS_REPORT_GRADE_VALIDATION_PLAN_VERSION",
    "LEGAL_LIMITATION_GAP_ID",
    "LEGAL_LIMITATION_REPORT_GRADE_BLOCKERS",
    "LEGAL_LIMITATION_REPORT_GRADE_VALIDATION_PLAN_VERSION",
    "LEGAL_LIMITATION_TRUSTED_DIFF_BLOCKER_93",
    "PARSER_CONFIDENCE_GAP_ID",
    "PARSER_CONFIDENCE_REPORT_GRADE_BLOCKERS",
    "PARSER_CONFIDENCE_REPORT_GRADE_VALIDATION_PLAN_VERSION",
    "PARSER_CONFIDENCE_TRUSTED_DIFF_BLOCKER_91",
    "REPORT_CITATION_REPORT_GRADE_BLOCKERS",
    "REPORT_CITATION_REPORT_GRADE_VALIDATION_PLAN_VERSION",
    "REPORT_QUALITY_TRUSTED_TOOLS",
    "REPORT_REPRODUCIBILITY_GAP_ID",
    "REPORT_REPRODUCIBILITY_REPORT_GRADE_BLOCKERS",
    "REPORT_REPRODUCIBILITY_REPORT_GRADE_VALIDATION_PLAN_VERSION",
    "REPORT_REPRODUCIBILITY_TRUSTED_DIFF_BLOCKER_89",
    "REVIEW_TARGET_TABLES",
    "REVIEW_WORKFLOW_REPORT_GRADE_BLOCKERS",
    "REVIEW_WORKFLOW_REPORT_GRADE_VALIDATION_PLAN_VERSION",
    "REVIEW_WORKFLOW_TRUSTED_DIFF_BLOCKER",
    "REVIEW_WORKFLOW_TRUSTED_TOOLS",
    "SCHEMA_SQL",
    "SCHEMA_VERSION",
    "SOURCE_PROVENANCE_GAP_ID",
    "SOURCE_PROVENANCE_REPORT_GRADE_BLOCKERS",
    "SOURCE_PROVENANCE_REPORT_GRADE_VALIDATION_PLAN_VERSION",
    "SOURCE_PROVENANCE_TRUSTED_DIFF_BLOCKER_90",
    "TIMEZONE_NORMALIZATION_GAP_ID",
    "TIMEZONE_REPORT_GRADE_BLOCKERS",
    "TIMEZONE_REPORT_GRADE_VALIDATION_PLAN_VERSION",
    "TIMEZONE_VALIDATION_TRUSTED_DIFF_BLOCKER_97",
    "VALIDATION_WARNING_REPORT_GRADE_BLOCKERS",
    "VALIDATION_WARNING_REPORT_GRADE_VALIDATION_PLAN_VERSION",
    "VALIDATION_WARNING_TRUSTED_DIFF_BLOCKER_92",
    "VALIDATION_WARNING_UX_GAP_ID",
    "WRITE_BLOCKER_ACQUISITION_METADATA_GAP_ID",
]

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


VALIDATION_WARNING_REPORT_GRADE_VALIDATION_PLAN_VERSION = "validation-warning-report-grade-validation-plan-v1"


VALIDATION_WARNING_REPORT_GRADE_BLOCKERS = [
    "trusted-validation-warning-checklist-diff-missing",
    "all-table-warning-badge-coverage-required",
    "warning-ux-e2e-required",
    "report-template-warning-rendering-review-required",
    "warning-action-playbook-review-required",
    "accessibility-warning-badge-review-required",
]


VALIDATION_WARNING_TRUSTED_DIFF_BLOCKER_92 = "trusted-validation-warning-checklist-diff-missing"


LEGAL_LIMITATION_TRUSTED_DIFF_BLOCKER_93 = "trusted-legal-limitation-wording-diff-missing"


LEGAL_LIMITATION_REPORT_GRADE_VALIDATION_PLAN_VERSION = "legal-limitation-report-grade-validation-plan-v1"


LEGAL_LIMITATION_REPORT_GRADE_BLOCKERS = [
    "trusted-legal-limitation-wording-diff-missing",
    "jurisdiction-approved-wording-required",
    "formal-legal-review-signoff-required",
    "artifact-family-limitation-corpus-required",
    "report-template-limitation-rendering-review-required",
    "analyst-limitation-acknowledgement-required",
]


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


ACQUISITION_METADATA_REPORT_GRADE_VALIDATION_PLAN_VERSION = "acquisition-metadata-report-grade-validation-plan-v1"


ACQUISITION_METADATA_REPORT_GRADE_BLOCKERS = [
    "trusted-acquisition-metadata-handoff-diff-missing",
    "acquisition-required-fields-missing",
    "write-blocker-device-log-required",
    "signed-acquisition-handoff-required",
    "original-acquisition-notes-required",
    "whole-source-hash-verification-log-required",
    "acquisition-tool-version-linkage-required",
    "source-read-only-policy-signoff-required",
]


TIMEZONE_VALIDATION_TRUSTED_DIFF_BLOCKER_97 = "trusted-timezone-normalization-matrix-diff-missing"


TIMEZONE_REPORT_GRADE_VALIDATION_PLAN_VERSION = "timezone-normalization-report-grade-validation-plan-v1"


TIMEZONE_REPORT_GRADE_BLOCKERS = [
    "trusted-timezone-normalization-matrix-diff-missing",
    "source-timezone-completeness-required",
    "parser-timezone-assumption-matrix-required",
    "multi-source-timezone-reconciliation-required",
    "timezone-known-answer-corpus-required",
    "daylight-saving-edge-case-corpus-required",
    "source-clock-baseline-required",
]


CLOCK_SKEW_TRUSTED_DIFF_BLOCKER_98 = "trusted-clock-skew-baseline-diff-missing"


CLOCK_SKEW_REPORT_GRADE_VALIDATION_PLAN_VERSION = "clock-skew-report-grade-validation-plan-v1"


CLOCK_SKEW_REPORT_GRADE_BLOCKERS = [
    "trusted-clock-skew-baseline-diff-missing",
    "host-device-clock-baseline-required",
    "multi-device-skew-model-required",
    "trusted-external-timestamp-comparison-required",
    "acquisition-time-baseline-required",
    "timezone-normalization-linkage-required",
    "clock-skew-known-answer-corpus-required",
]


CONTAMINATION_WARNING_TRUSTED_DIFF_BLOCKER_99 = "trusted-contamination-checklist-diff-missing"


CONTAMINATION_WARNING_REPORT_GRADE_VALIDATION_PLAN_VERSION = "contamination-warning-report-grade-validation-plan-v1"


CONTAMINATION_WARNING_REPORT_GRADE_BLOCKERS = [
    "trusted-contamination-checklist-diff-missing",
    "acquisition-time-mtime-baseline-required",
    "write-blocker-integration-required",
    "source-read-only-proof-required",
    "output-path-policy-enforcement-required",
    "contamination-known-answer-corpus-required",
    "reviewer-signoff-workflow-required",
]


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


REVIEW_TARGET_TABLES = {
    "artifact": "artifact",
    "event": "event",
    "file_record": "file_record",
    "indexed_document": "indexed_document",
    "hash": "hash_record",
    "evidence_source": "evidence_source",
    "job": "job",
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

CREATE TRIGGER IF NOT EXISTS audit_event_no_update
BEFORE UPDATE ON audit_event
BEGIN
    SELECT RAISE(ABORT, 'audit_event is append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_event_no_delete
BEFORE DELETE ON audit_event
BEGIN
    SELECT RAISE(ABORT, 'audit_event is append-only');
END;

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
