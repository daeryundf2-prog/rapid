"""Run-mode constants, gap IDs, and report-grade blocker lists."""

from __future__ import annotations

from ..extract import SUPPORTED_DOC_KINDS

__all__ = [
    "CHECKPOINT_RESUME_GAP_ID",
    "CHECKPOINT_RESUME_REPORT_GRADE_BLOCKERS",
    "CHECKPOINT_RESUME_REPORT_GRADE_VALIDATION_PLAN_VERSION",
    "CHECKPOINT_TRUSTED_DIFF_BLOCKER_70",
    "CROSS_PLATFORM_SYSTEM_ARTIFACT_KINDS",
    "DEFAULT_INCREMENTAL_HASH_MAX_BYTES",
    "FUNCTIONAL_LARGE_DATA_BATCH_ID",
    "GENERAL_FORENSIC_ARTIFACT_KINDS",
    "IMPLEMENTED_RUN_MODES",
    "INCREMENTAL_INDEXING_GAP_ID",
    "INCREMENTAL_INDEXING_REPORT_GRADE_BLOCKERS",
    "INCREMENTAL_INDEXING_REPORT_GRADE_VALIDATION_PLAN_VERSION",
    "INCREMENTAL_TRUSTED_DIFF_BLOCKER_68",
    "LARGE_SQLITE_FTS_GAP_ID",
    "LARGE_SQLITE_FTS_REPORT_GRADE_BLOCKERS",
    "LARGE_SQLITE_FTS_REPORT_GRADE_VALIDATION_PLAN_VERSION",
    "LARGE_SQLITE_FTS_TRUSTED_DIFF_BLOCKER_74",
    "MEMORY_CAP_ENV",
    "MEMORY_CAP_GAP_ID",
    "MEMORY_CAP_REPORT_GRADE_BLOCKERS",
    "MEMORY_CAP_REPORT_GRADE_VALIDATION_PLAN_VERSION",
    "MEMORY_CAP_TRUSTED_DIFF_BLOCKER_72",
    "PARALLEL_PARSER_SCHEDULER_GAP_ID",
    "PARSER_CRASH_ISOLATION_GAP_ID",
    "PARSER_CRASH_REPORT_GRADE_BLOCKERS",
    "PARSER_CRASH_REPORT_GRADE_VALIDATION_PLAN_VERSION",
    "PARSER_CRASH_TRUSTED_DIFF_BLOCKER_71",
    "PERFORMANCE_BATCH_ID",
    "PREVIEW_SANDBOX_GAP_ID",
    "PREVIEW_SANDBOX_REPORT_GRADE_BLOCKERS",
    "PREVIEW_SANDBOX_REPORT_GRADE_VALIDATION_PLAN_VERSION",
    "PREVIEW_SANDBOX_TRUSTED_DIFF_BLOCKER_73",
    "RUNTIME_DEFENSIBILITY_BATCH_ID",
    "RUN_DOC_EXTRACT_KINDS",
    "SCHEDULER_REPORT_GRADE_BLOCKERS",
    "SCHEDULER_REPORT_GRADE_VALIDATION_PLAN_VERSION",
    "SCHEDULER_TRUSTED_DIFF_BLOCKER_75",
    "SUPPORTED_RUN_MODES",
    "WINDOWS_FORENSIC_ARTIFACT_KINDS",
]


SUPPORTED_RUN_MODES: tuple[str, ...] = ("seizure", "fraud", "hacking", "recovery")
IMPLEMENTED_RUN_MODES = set(SUPPORTED_RUN_MODES)
RUN_DOC_EXTRACT_KINDS = SUPPORTED_DOC_KINDS
GENERAL_FORENSIC_ARTIFACT_KINDS = (
    "browser",
    "recent-files",
    "email",
    "cloud-export",
    "mobile-export",
    "kakaotalk-macos",
    "kakaotalk-windows",
    "android-apk",
    "media-image",
    "generic-documents",
    "memory-volatility",
    "synthetic-media",
)
WINDOWS_FORENSIC_ARTIFACT_KINDS = (
    "windows-os-account",
    "eventlog",
    "windows-search-index",
    "windows-remote-access",
    "windows-execution",
    "windows-registry",
    "windows-shellbags",
    "windows-prefetch",
    "windows-filesystem",
    "windows-system",
)
CROSS_PLATFORM_SYSTEM_ARTIFACT_KINDS = (
    "linux-system",
    "macos-system",
)
PARSER_CRASH_ISOLATION_GAP_ID = "#71"
MEMORY_CAP_GAP_ID = "#72"
PREVIEW_SANDBOX_GAP_ID = "#73"
LARGE_SQLITE_FTS_GAP_ID = "#74"
INCREMENTAL_INDEXING_GAP_ID = "#68"
CHECKPOINT_RESUME_GAP_ID = "#70"
PARALLEL_PARSER_SCHEDULER_GAP_ID = "#75"
MEMORY_CAP_ENV = "RAPIDTRIAGE_MEMORY_CAP_BYTES"
PERFORMANCE_BATCH_ID = "commercial-uplift-066-070"
FUNCTIONAL_LARGE_DATA_BATCH_ID = "commercial-uplift-026-030"
RUNTIME_DEFENSIBILITY_BATCH_ID = "commercial-uplift-071-075"
INCREMENTAL_TRUSTED_DIFF_BLOCKER_68 = "trusted-incremental-reuse-manifest-diff-missing"
INCREMENTAL_INDEXING_REPORT_GRADE_VALIDATION_PLAN_VERSION = "incremental-indexing-report-grade-validation-plan-v1"
INCREMENTAL_INDEXING_REPORT_GRADE_BLOCKERS = [
    "full-large-file-content-hash-delta-required",
    "row-level-stage-delta-reindex-required",
    "trusted-incremental-reuse-manifest-required",
    "multi-million-file-replay-validation-required",
    "case-db-stage-dedup-validation-required",
    "cross-platform-fingerprint-semantics-required",
]
CHECKPOINT_TRUSTED_DIFF_BLOCKER_70 = "trusted-checkpoint-resume-manifest-diff-missing"
CHECKPOINT_RESUME_REPORT_GRADE_VALIDATION_PLAN_VERSION = "checkpoint-resume-report-grade-validation-plan-v1"
CHECKPOINT_RESUME_REPORT_GRADE_BLOCKERS = [
    "mid-parser-checkpointing-required",
    "failed-stage-partial-resume-validation-required",
    "trusted-checkpoint-resume-manifest-required",
    "long-running-case-replay-validation-required",
    "partial-output-cleanup-validation-required",
    "case-db-resume-dedup-validation-required",
]
PARSER_CRASH_TRUSTED_DIFF_BLOCKER_71 = "trusted-parser-crash-corpus-diff-missing"
PARSER_CRASH_REPORT_GRADE_VALIDATION_PLAN_VERSION = "parser-crash-report-grade-validation-plan-v1"
PARSER_CRASH_REPORT_GRADE_BLOCKERS = [
    "native-process-sandboxing-required",
    "trusted-parser-crash-corpus-required",
    "corrupt-input-fuzz-crash-corpus-required",
    "subprocess-crash-boundary-validation-required",
    "long-running-corrupt-evidence-replay-required",
    "cross-platform-parser-isolation-validation-required",
]
MEMORY_CAP_TRUSTED_DIFF_BLOCKER_72 = "trusted-memory-cap-rss-diff-missing"
MEMORY_CAP_REPORT_GRADE_VALIDATION_PLAN_VERSION = "memory-cap-report-grade-validation-plan-v1"
MEMORY_CAP_REPORT_GRADE_BLOCKERS = [
    "hard-os-memory-limit-required",
    "per-parser-live-rss-telemetry-required",
    "trusted-memory-cap-rss-manifest-required",
    "platform-specific-rss-validation-required",
    "large-case-rss-graph-required",
    "allocation-level-enforcement-validation-required",
]
PREVIEW_SANDBOX_TRUSTED_DIFF_BLOCKER_73 = "trusted-preview-no-exec-diff-missing"
PREVIEW_SANDBOX_REPORT_GRADE_VALIDATION_PLAN_VERSION = "preview-sandbox-report-grade-validation-plan-v1"
PREVIEW_SANDBOX_REPORT_GRADE_BLOCKERS = [
    "os-level-renderer-sandbox-required",
    PREVIEW_SANDBOX_TRUSTED_DIFF_BLOCKER_73,
    "browser-renderer-exploit-corpus-required",
    "malicious-active-content-corpus-required",
    "risky-codec-macro-external-sandbox-required",
    "browser-e2e-preview-sandbox-required",
]
LARGE_SQLITE_FTS_TRUSTED_DIFF_BLOCKER_74 = "trusted-large-sqlite-fts-query-plan-diff-missing"
LARGE_SQLITE_FTS_REPORT_GRADE_VALIDATION_PLAN_VERSION = "large-sqlite-fts-report-grade-validation-plan-v1"
LARGE_SQLITE_FTS_REPORT_GRADE_BLOCKERS = [
    "trusted-large-sqlite-fts-query-plan-manifest-required",
    "10m-row-query-plan-regression-required",
    "deleted-row-wal-replay-validation-required",
    "large-source-db-corpus-required",
    "browser-pagination-query-plan-e2e-required",
    "index-maintenance-vacuum-regression-required",
]
SCHEDULER_TRUSTED_DIFF_BLOCKER_75 = "trusted-parser-scheduler-manifest-diff-missing"
SCHEDULER_REPORT_GRADE_VALIDATION_PLAN_VERSION = "parser-scheduler-report-grade-validation-plan-v1"
SCHEDULER_REPORT_GRADE_BLOCKERS = [
    SCHEDULER_TRUSTED_DIFF_BLOCKER_75,
    "distributed-priority-scheduler-required",
    "live-worker-telemetry-stream-required",
    "tb-scale-fairness-backpressure-validation-required",
    "cross-platform-worker-quota-validation-required",
    "priority-starvation-regression-required",
]
DEFAULT_INCREMENTAL_HASH_MAX_BYTES = 16 * 1024 * 1024
