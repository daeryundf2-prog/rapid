from __future__ import annotations
import base64
import binascii
import contextlib
import datetime as dt
import email
import hashlib
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import struct
import wave
from collections.abc import Mapping, MutableMapping, Sequence
from email import policy
from pathlib import Path
from typing import Any
from urllib.parse import quote
from xml.etree import ElementTree as ET
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from ...core.audit import audit_path_for, write_audit_record
from ...core.bundle import BundleError, build_submission_bundle
from ...core.case import (
    CaseBookmarkError,
    create_or_update_case_payload,
    load_case_payload,
    save_case_payload,
)
from ...core.case_catalog import CaseCatalog, CaseCatalogError, default_case_catalog_path
from ...core.case_db import CaseDatabaseError, open_case_database
from ...core.case_report import (
    build_case_report_markdown,
    case_report_export_paths,
    write_case_report_exports,
)
from ...core.collect_plan import (
    CollectPlanError,
    build_collect_plan,
    supported_collect_profiles,
)
from ...core.columnar_store import query_columnar_artifact_records
from ...core.commercial_readiness import (
    CommercialReadinessError,
    build_commercial_readiness_report,
)
from ...core.crash import (
    export_crash_report_bundle,
    list_crash_reports,
    read_crash_report,
    write_crash_report,
)
from ...core.docs import SUPPORTED_DOC_EXTS, TEXT_EXTS, extract_text, query_docs_index
from ...core.doctor import run_doctor
from ...core.enterprise import build_enterprise_policy
from ...core.evidence import identify_evidence, supported_evidence_formats
from ...core.files import DEFAULT_KNOWN_GOOD_MAX_HASH_BYTES
from ...core.forensic_accuracy import build_accuracy_gate
from ...core.hash_cache import hash_cache_assessment
from ...core.indicators import (
    IndicatorSummaryError,
    build_indicator_ti_enrichment_package,
)
from ...core.jobs import (
    RunJobStore,
    RunRequest,
    default_job_store,
    is_relative_to,
    run_output_dir,
)
from ...core.keyword_packs import (
    KeywordPackError,
    keyword_pack_library_assessment,
    keyword_pack_selection_profile,
    list_keyword_packs,
    resolve_keyword_packs,
)
from ...core.large_case_controls import build_source_search_full_cursor_contract
from ...core.ocr_queue import (
    OcrQueueError,
    build_ocr_queue,
    build_ocr_queue_report_grade_validation_plan,
)
from ...core.run import RunModeError
from ...core.safe_xml import UnsafeXmlError, safe_xml_fromstring
from ...core.sample_case import DEFAULT_SAMPLE_MODE, SampleCaseError, run_sample_workflow
from ...core.search import SearchError, run_unified_search
from ...core.source_paths import (
    candidate_source_paths,
    source_path_resolution_diagnostics,
)
from ...core.source_reader import (
    SourceReadError,
    build_source_locator,
    parse_archived_source_request,
)
from ...core.source_reader import (
    build_archived_source_preview as build_archived_source_read_preview,
)
from ...core.sqlite_wal import SqliteWalPreviewError, build_sqlite_wal_preview
from ...core.submission import build_submission_manifest, compute_hashes
from ...core.visible_capabilities import build_visible_capability_response



DEFAULT_INTERNAL_VALIDATION_PACKAGE = (
    Path(__file__).resolve().parents[3]
    / "docs"
    / "validation"
    / "rapidtriage-core-forensics-001-120-known-answer.json"
)


SQLITE_PREVIEW_EXTS = {".sqlite", ".sqlite3", ".db", ".db3"}


SQLITE_HEADER = b"SQLite format 3\x00"


SQLITE_PREVIEW_TABLE_LIMIT = 8


SQLITE_PREVIEW_ROW_LIMIT = 10


SQLITE_PREVIEW_COLUMN_LIMIT = 12


SQLITE_TABLE_PAGE_MAX_ROWS = 500


SQLITE_SOURCE_SEARCH_ROW_SCAN_LIMIT = 100_000


SQLITE_WAL_HEADER_SIZE = 32


SQLITE_WAL_FRAME_HEADER_SIZE = 24


SQLITE_WAL_MAGIC_VALUES = {0x377F0682: "big-endian", 0x377F0683: "little-endian"}


STRUCTURED_PREVIEW_MAX_BYTES = 5 * 1024 * 1024


JSON_PREVIEW_ITEM_LIMIT = 50


XML_PREVIEW_NODE_LIMIT = 80


EMAIL_PREVIEW_MESSAGE_LIMIT = 10


EMAIL_BODY_PREVIEW_CHARS = 4000


EMAIL_ATTACHMENT_EXPORT_MAX_BYTES = 256 * 1024


EMAIL_PREVIEW_MAX_BYTES = 25 * 1024 * 1024


EMAIL_PREVIEW_MESSAGE_MAX_BYTES = 5 * 1024 * 1024


DOCUMENT_PREVIEW_MAX_BYTES = 25 * 1024 * 1024


IMAGE_GALLERY_MAX_ITEMS = 200


IMAGE_GALLERY_DEFAULT_LIMIT = 50


SOURCE_OCR_QUEUE_DEFAULT_MAX_ITEMS = 200


SOURCE_OCR_TRANSLATION_MAX_CHARS = 8000


VIRTUAL_TABLE_ROW_LIMIT = 300


HEX_PREVIEW_MAX_BYTES = 4096


HEX_PREVIEW_ROW_WIDTH = 16


HEX_RANGE_EXPORT_MAX_BYTES = 64 * 1024


MAX_SOURCE_SEARCH_ARCHIVE_TEXT_CHARS = 2_000_000


MEDIA_TRANSCRIPT_PREVIEW_CHARS = 8000


MEDIA_TRANSCRIPT_SUFFIXES = (".srt", ".vtt", ".txt", ".transcript.txt", ".ocr.txt")


MEDIA_CUE_EXPORT_MAX_CHARS = 4000


SOURCE_VIEWER_VERSION = "2"


FUNCTIONAL_UI_BATCH_ID = "commercial-uplift-021-025"


FUNCTIONAL_SCALE_BATCH_ID = "commercial-uplift-031-035"


VIEWER_WORKFLOW_GAP_IDS = {
    "review": "#51",
    "compare": "#52",
    "hex": "#53",
    "sqlite": "#54",
    "email": "#55",
    "gallery": "#56",
    "media": "#57",
    "ocr_queue": "#58",
    "korean_ocr": "#59",
    "preview_sandbox": "#73",
    "sqlite_performance": "#74",
    "hash_cache": "#76",
    "pagination": "#78",
    "ui_virtualization": "#79",
}


STAGE10_VIEWER_ITEM_BY_FAMILY = {
    "sqlite-table-preview": 54,
    "email-thread-preview": 55,
    "image-gallery-preview": 56,
    "media-preview": 57,
}


STAGE10_CAPABILITY_SPECS: tuple[dict[str, object], ...] = (
    {
        "item_number": 51,
        "label": "reviewer workflow",
        "primary_families": ("document-text-preview",),
        "route_template": None,
        "evidence_refs": ("review_workflow", "case-db:review_mark", "case-db:review_mark_history"),
        "blockers": ("role-based-review-queue-not-enabled", "trusted-review-audit-diff-required"),
    },
    {
        "item_number": 52,
        "label": "A/B/C compare",
        "primary_families": (),
        "route_template": None,
        "evidence_refs": ("compare_workflow", "command:compare"),
        "blockers": ("semantic-binary-table-visual-diff-required", "trusted-expected-diff-required"),
    },
    {
        "item_number": 53,
        "label": "raw/hex viewer",
        "primary_families": ("text-or-hex-preview",),
        "route_template": "/api/runs/{run_id}/source-preview?path={quoted_path}",
        "evidence_refs": ("hex.hex_preview_manifest", "hex.range_citation_profile"),
        "blockers": ("trusted-offset-manifest-required",),
    },
    {
        "item_number": 54,
        "label": "SQLite/table viewer",
        "primary_families": ("sqlite-table-preview",),
        "route_template": "/api/runs/{run_id}/source-sqlite-table?path={quoted_path}",
        "evidence_refs": ("sqlite.sqlite_preview_manifest", "sqlite.table_page_profile"),
        "blockers": ("deleted-row-wal-validation-required", "trusted-sqlite-query-schema-diff-required"),
    },
    {
        "item_number": 55,
        "label": "email conversation viewer",
        "primary_families": ("email-thread-preview",),
        "route_template": "/api/runs/{run_id}/source-email-attachment?path={quoted_path}",
        "evidence_refs": ("email.email_conversation_manifest", "email.attachment_package_profile"),
        "blockers": ("native-pst-ost-msg-validation-required", "trusted-mail-thread-export-required"),
    },
    {
        "item_number": 56,
        "label": "image gallery review",
        "primary_families": ("image-gallery-preview",),
        "route_template": "/api/runs/{run_id}/source-image-gallery?path={quoted_path}",
        "evidence_refs": ("image.gallery_page_profile", "image.image_gallery_manifest"),
        "blockers": ("large-gallery-browser-e2e-required", "trusted-image-manifest-required"),
    },
    {
        "item_number": 57,
        "label": "video/audio transcript viewer",
        "primary_families": ("media-preview",),
        "route_template": "/api/runs/{run_id}/source-media-cue?path={quoted_path}",
        "evidence_refs": ("media.transcript_sidecars", "media.cue_package_profile"),
        "blockers": ("safe-playback-asr-alignment-corpus-required", "trusted-transcript-cue-diff-required"),
    },
    {
        "item_number": 58,
        "label": "OCR queue",
        "primary_families": ("image-gallery-preview",),
        "route_template": "/api/runs/{run_id}/source-ocr-queue?path={quoted_path}",
        "evidence_refs": ("image.ocr_queue_profile", "ocr_queue.core_accuracy_gates"),
        "blockers": ("native-ocr-engine-log-required", "trusted-ocr-sidecar-diff-required"),
    },
    {
        "item_number": 59,
        "label": "Korean OCR/translation review",
        "primary_families": ("image-gallery-preview",),
        "route_template": "/api/runs/{run_id}/source-ocr-translation?path={quoted_path}",
        "evidence_refs": ("image.ocr_translation_profile", "source-ocr-translation-review-manifest"),
        "blockers": ("korean-ocr-calibration-corpus-required", "certified-translation-review-required"),
    },
    {
        "item_number": 60,
        "label": "search hit dedup review",
        "primary_families": (),
        "route_template": None,
        "evidence_refs": ("analysis_analyst_review_profile.dedup_review", "search-analysis.duplicate_groups"),
        "blockers": ("persistent-suppression-workflow-required", "trusted-duplicate-manifest-required"),
    },
)


RUN_VIEWER_WORKFLOW_VALIDATION_VERSION = "run-viewer-workflow-validation-v1"


RUN_VIEWER_WORKFLOW_CANDIDATE_LIMIT = 80


RUN_VIEWER_WORKFLOW_SUPPLEMENTAL_SCAN_LIMIT = 300


RUN_VIEWER_WORKFLOW_REQUIRED_ROUTES = (
    "source-preview",
    "source-hex-range",
    "source-sqlite-table",
    "source-email-attachment",
    "source-image-gallery",
    "source-media-cue",
    "source-ocr-queue",
    "source-ocr-translation",
)


RUN_VIEWER_WORKFLOW_FAMILY_PRIORITY = {
    "sqlite-table-preview": 0,
    "email-thread-preview": 1,
    "image-gallery-preview": 2,
    "media-preview": 3,
    "document-text-preview": 4,
    "text-or-hex-preview": 5,
    "json-structured-preview": 6,
    "xml-structured-preview": 7,
}


HEX_VIEWER_TRUSTED_DIFF_BLOCKER = "hex-viewer-trusted-offset-manifest-required"


HEX_VIEWER_TRUSTED_TOOLS = {"known-byte-offset-manifest", "hex-editor-ground-truth", "source-byte-citation-package"}


HEX_VIEWER_REPORT_GRADE_VALIDATION_PLAN_VERSION = "hex-viewer-report-grade-validation-plan-v1"


HEX_VIEWER_REPORT_GRADE_BLOCKERS = [
    "interactive-jump-to-offset-ui-not-implemented",
    "copy-safe-byte-selection-ui-not-implemented",
    "hex-viewer-trusted-offset-manifest-required",
    "full-file-inline-hash-for-large-source-required",
    "sector-partition-aware-navigation-not-implemented",
    "external-byte-citation-package-validation-required",
]


SQLITE_VIEWER_TRUSTED_DIFF_BLOCKER = "sqlite-viewer-trusted-query-schema-diff-required"


SQLITE_VIEWER_TRUSTED_TOOLS = {"sqlite3-cli-oracle", "db-browser-export", "known-answer-sqlite-manifest"}


SQLITE_VIEWER_REPORT_GRADE_VALIDATION_PLAN_VERSION = "sqlite-viewer-report-grade-validation-plan-v1"


SQLITE_VIEWER_REPORT_GRADE_BLOCKERS = [
    "sqlite-pagination-browser-e2e-required",
    "sqlite-deleted-row-and-wal-recovery-required",
    "sqlite-viewer-trusted-query-schema-diff-required",
    "sqlite-export-selected-rows-workflow-required",
    "sqlite-fts-ranking-and-virtual-table-review-required",
    "sqlite-large-database-corpus-required",
]


EMAIL_VIEWER_TRUSTED_DIFF_BLOCKER = "email-viewer-trusted-thread-export-required"


EMAIL_VIEWER_TRUSTED_TOOLS = {"mail-client-thread-export", "eml-ground-truth", "mbox-ground-truth", "vendor-mailbox-export"}


EMAIL_VIEWER_REPORT_GRADE_VALIDATION_PLAN_VERSION = "email-viewer-report-grade-validation-plan-v1"


EMAIL_VIEWER_REPORT_GRADE_BLOCKERS = [
    "native-pst-ost-msg-conversation-view-required",
    "deleted-mailbox-item-recovery-required",
    "native-mailbox-attachment-extraction-required",
    "message-id-graph-validation-required",
    "email-viewer-trusted-thread-export-required",
    "mailbox-corpus-validation-required",
]


IMAGE_GALLERY_TRUSTED_DIFF_BLOCKER = "image-gallery-trusted-manifest-diff-required"


IMAGE_GALLERY_REPORT_GRADE_VALIDATION_PLAN_VERSION = "image-gallery-report-grade-validation-plan-v1"


IMAGE_GALLERY_REPORT_GRADE_BLOCKERS = [
    "dedicated-virtualized-gallery-ui-required",
    "persistent-gallery-tags-required",
    "ml-visual-similarity-clustering-required",
    "sensitive-deepfake-classifier-validation-required",
    IMAGE_GALLERY_TRUSTED_DIFF_BLOCKER,
    "selected-image-report-export-required",
]


MEDIA_TRANSCRIPT_TRUSTED_DIFF_BLOCKER = "media-transcript-trusted-cue-diff-required"


MEDIA_TRANSCRIPT_TRUSTED_TOOLS = {"transcript-cue-manifest", "asr-alignment-export", "manual-playback-review"}


MEDIA_TRANSCRIPT_REPORT_GRADE_VALIDATION_PLAN_VERSION = "media-transcript-report-grade-validation-plan-v1"


MEDIA_TRANSCRIPT_REPORT_GRADE_BLOCKERS = [
    "safe-playback-sandbox-required",
    "asr-execution-or-alignment-required",
    "waveform-thumbnail-preview-required",
    MEDIA_TRANSCRIPT_TRUSTED_DIFF_BLOCKER,
    "transcript-alignment-corpus-required",
    "selected-cue-report-export-integration-required",
]


PREVIEW_SANDBOX_TRUSTED_DIFF_BLOCKER = "preview-sandbox-trusted-no-exec-manifest-required"


PREVIEW_SANDBOX_TRUSTED_TOOLS = {"no-exec-preview-manifest", "browser-sandbox-review", "active-content-test-corpus"}


PREVIEW_SANDBOX_REPORT_GRADE_VALIDATION_PLAN_VERSION = "preview-sandbox-report-grade-validation-plan-v1"


PREVIEW_SANDBOX_REPORT_GRADE_BLOCKERS = [
    "os-level-renderer-sandbox-required",
    PREVIEW_SANDBOX_TRUSTED_DIFF_BLOCKER,
    "browser-renderer-exploit-corpus-required",
    "malicious-active-content-corpus-required",
    "risky-codec-macro-external-sandbox-required",
    "browser-e2e-preview-sandbox-required",
]


SQLITE_FTS_TRUSTED_DIFF_BLOCKER = "large-sqlite-fts-trusted-query-plan-diff-required"


SQLITE_FTS_TRUSTED_TOOLS = {"sqlite-query-plan-manifest", "large-db-profile-oracle", "fts-benchmark-manifest"}


LARGE_SQLITE_FTS_REPORT_GRADE_VALIDATION_PLAN_VERSION = "large-sqlite-fts-report-grade-validation-plan-v1"


LARGE_SQLITE_FTS_REPORT_GRADE_BLOCKERS = [
    SQLITE_FTS_TRUSTED_DIFF_BLOCKER,
    "10m-row-query-plan-regression-required",
    "deleted-row-wal-replay-validation-required",
    "large-source-db-corpus-required",
    "browser-pagination-query-plan-e2e-required",
    "index-maintenance-vacuum-regression-required",
]


PAGINATION_TRUSTED_DIFF_BLOCKER_78 = "trusted-pagination-cursor-manifest-diff-missing"


PAGINATION_TRUSTED_TOOLS = {"pagination-cursor-manifest", "api-pagination-oracle", "known-answer-page-window-export"}


PAGINATION_CURSOR_REPORT_GRADE_VALIDATION_PLAN_VERSION = "pagination-cursor-report-grade-validation-plan-v1"


PAGINATION_CURSOR_REPORT_GRADE_BLOCKERS = [
    "snapshot-isolated-database-cursors-required",
    PAGINATION_TRUSTED_DIFF_BLOCKER_78,
    "endpoint-wide-pagination-compatibility-required",
    "cursor-invalidation-replay-validation-required",
    "large-case-page-latency-validation-required",
    "cross-client-cursor-compatibility-required",
]


UI_VIRTUALIZATION_TRUSTED_DIFF_BLOCKER_79 = "trusted-ui-virtualization-manifest-diff-missing"


UI_VIRTUALIZATION_TRUSTED_TOOLS = {"ui-virtualization-manifest", "browser-e2e-row-window-export", "large-table-render-oracle"}


UI_VIRTUALIZATION_REPORT_GRADE_VALIDATION_PLAN_VERSION = "ui-virtualization-report-grade-validation-plan-v1"


UI_VIRTUALIZATION_REPORT_GRADE_BLOCKERS = [
    UI_VIRTUALIZATION_TRUSTED_DIFF_BLOCKER_79,
    "true-recycling-virtual-scroller-required",
    "persisted-viewport-restoration-required",
    "browser-e2e-100k-row-window-validation-required",
    "browser-memory-profile-required",
    "cross-client-virtualization-compatibility-required",
]


WORKBENCH_SMOKE_CONTRACT_VERSION = "single-case-workbench-smoke-v1"


BROWSER_E2E_PERFORMANCE_CONTRACT_VERSION = "browser-e2e-performance-contract-v1"


WORKBENCH_SMOKE_SELECTORS = {
    "shell": "[data-testid='workbench-shell']",
    "sample_run": "[data-testid='sample-run-button']",
    "evidence_root": "[data-testid='evidence-root-input']",
    "evidence_support": "[data-testid='evidence-support-button']",
    "run_submit": "[data-testid='run-submit-button']",
    "run_list": "[data-testid='run-list']",
    "detail_panel": "[data-testid='detail-panel']",
    "case_hero": "[data-testid='case-hero']",
    "artifact_validation_summary": "[data-testid='artifact-validation-summary']",
    "global_search": "[data-testid='global-case-search']",
    "search_view": ".forensic-view-mode[data-tab='search']",
    "search_tab": "[data-testid='tab-search']",
    "source_viewer": "[data-testid='source-viewer']",
    "source_verification": "[data-testid='source-verification-trail']",
    "viewer_review": "[data-testid='viewer-review-form']",
    "review_view": ".forensic-view-mode[data-tab='review']",
    "report_view": ".forensic-view-mode[data-tab='report']",
    "report_tab": "[data-testid='tab-report']",
}


LOCAL_API_HOSTS = {"127.0.0.1", "localhost", "::1", "testserver"}


MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
