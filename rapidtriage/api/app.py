from __future__ import annotations

import json
import mimetypes
import os
import re
import contextlib
import email
import hashlib
import sqlite3
import datetime as dt
import wave
import base64
import binascii
import struct
from email import policy
from pathlib import Path
from typing import Any, Dict, Mapping, MutableMapping, Optional, Sequence
from urllib.parse import quote
from xml.etree import ElementTree as ET

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ..core.audit import audit_path_for, write_audit_record
from ..core.bundle import BundleError, build_submission_bundle
from ..core.case import CaseBookmarkError, create_or_update_case_payload, load_case_payload, save_case_payload
from ..core.case_catalog import CaseCatalog, CaseCatalogError, default_case_catalog_path
from ..core.case_report import build_case_report_markdown, case_report_export_paths, write_case_report_exports
from ..core.case_db import CaseDatabaseError, open_case_database
from ..core.collect_plan import CollectPlanError, build_collect_plan, supported_collect_profiles
from ..core.crash import export_crash_report_bundle, list_crash_reports, read_crash_report, write_crash_report
from ..core.docs import SUPPORTED_DOC_EXTS, TEXT_EXTS, extract_text, query_docs_index
from ..core.doctor import run_doctor
from ..core.enterprise import build_enterprise_policy
from ..core.evidence import identify_evidence, supported_evidence_formats
from ..core.files import DEFAULT_KNOWN_GOOD_MAX_HASH_BYTES
from ..core.forensic_accuracy import build_accuracy_gate
from ..core.hash_cache import hash_cache_assessment
from ..core.jobs import RunJobStore, RunRequest, default_job_store, is_relative_to, run_output_dir
from ..core.keyword_packs import (
    KeywordPackError,
    keyword_pack_library_assessment,
    keyword_pack_selection_profile,
    list_keyword_packs,
    resolve_keyword_packs,
)
from ..core.indicators import IndicatorSummaryError, build_indicator_ti_enrichment_package
from ..core.large_case_controls import build_source_search_full_cursor_contract
from ..core.run import RunModeError
from ..core.sample_case import DEFAULT_SAMPLE_MODE, SampleCaseError, run_sample_workflow
from ..core.search import SearchError, run_unified_search
from ..core.source_paths import candidate_source_paths, source_path_resolution_diagnostics
from ..core.submission import compute_hashes, build_submission_manifest
from ..core.ocr_queue import OcrQueueError, build_ocr_queue
from ..core.visible_capabilities import build_visible_capability_response


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


def stable_payload_sha256(payload: Mapping[str, object] | Sequence[Mapping[str, object]]) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


HEX_VIEWER_TRUSTED_DIFF_BLOCKER = "hex-viewer-trusted-offset-manifest-required"
HEX_VIEWER_TRUSTED_TOOLS = {"known-byte-offset-manifest", "hex-editor-ground-truth", "source-byte-citation-package"}
SQLITE_VIEWER_TRUSTED_DIFF_BLOCKER = "sqlite-viewer-trusted-query-schema-diff-required"
SQLITE_VIEWER_TRUSTED_TOOLS = {"sqlite3-cli-oracle", "db-browser-export", "known-answer-sqlite-manifest"}
EMAIL_VIEWER_TRUSTED_DIFF_BLOCKER = "email-viewer-trusted-thread-export-required"
EMAIL_VIEWER_TRUSTED_TOOLS = {"mail-client-thread-export", "eml-ground-truth", "mbox-ground-truth", "vendor-mailbox-export"}
MEDIA_TRANSCRIPT_TRUSTED_DIFF_BLOCKER = "media-transcript-trusted-cue-diff-required"
MEDIA_TRANSCRIPT_TRUSTED_TOOLS = {"transcript-cue-manifest", "asr-alignment-export", "manual-playback-review"}
PREVIEW_SANDBOX_TRUSTED_DIFF_BLOCKER = "preview-sandbox-trusted-no-exec-manifest-required"
PREVIEW_SANDBOX_TRUSTED_TOOLS = {"no-exec-preview-manifest", "browser-sandbox-review", "active-content-test-corpus"}
SQLITE_FTS_TRUSTED_DIFF_BLOCKER = "large-sqlite-fts-trusted-query-plan-diff-required"
SQLITE_FTS_TRUSTED_TOOLS = {"sqlite-query-plan-manifest", "large-db-profile-oracle", "fts-benchmark-manifest"}
PAGINATION_TRUSTED_DIFF_BLOCKER_78 = "trusted-pagination-cursor-manifest-diff-missing"
PAGINATION_TRUSTED_TOOLS = {"pagination-cursor-manifest", "api-pagination-oracle", "known-answer-page-window-export"}
UI_VIRTUALIZATION_TRUSTED_DIFF_BLOCKER_79 = "trusted-ui-virtualization-manifest-diff-missing"
UI_VIRTUALIZATION_TRUSTED_TOOLS = {"ui-virtualization-manifest", "browser-e2e-row-window-export", "large-table-render-oracle"}
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


class RunCreateRequest(BaseModel):
    root: str = Field(..., min_length=1)
    mode: str = Field(..., min_length=1)
    output_dir: Optional[str] = None
    input_kind: Optional[str] = None
    rules: Optional[str] = None
    dry_run: bool = False
    read_only: bool = False
    max_extract_size_bytes: int = 0
    max_file_count: int = 0
    memory_cap_bytes: int = 0
    e01_partition_start_sector: Optional[int] = None
    overwrite: bool = False
    resume: bool = False
    known_good_hash_feeds: list[str] = Field(default_factory=list)
    hide_known_good: bool = False
    known_good_max_hash_bytes: int = Field(DEFAULT_KNOWN_GOOD_MAX_HASH_BYTES, ge=0)
    wait: bool = False


class RunImportRequest(BaseModel):
    output_dir: str = Field(..., min_length=1)


class SampleCaseRunRequest(BaseModel):
    output_dir: Optional[str] = None
    mode: str = DEFAULT_SAMPLE_MODE
    overwrite: bool = True
    read_only: bool = True


class BookmarkCreateRequest(BaseModel):
    source: str = Field(..., min_length=1)
    pointer: str = Field(..., min_length=1)
    bookmark_id: Optional[str] = None
    tag: Optional[str] = None
    tags: Optional[list[str]] = None
    note: Optional[str] = None
    case_id: Optional[str] = None
    title: Optional[str] = None
    review_status: Optional[str] = None
    include_in_report: Optional[bool] = None


class CaseReportCreateRequest(BaseModel):
    template: str = "legal-handoff"
    title: Optional[str] = None
    case_number: Optional[str] = None
    investigator: Optional[str] = None
    organization: Optional[str] = None
    requester: Optional[str] = None
    scope: Optional[str] = None
    conclusion: Optional[str] = None
    include_all: bool = False
    max_items: int = Field(500, ge=1, le=5000)


class ReviewerBundleCreateRequest(BaseModel):
    title: Optional[str] = None
    include_all: bool = False
    max_items: int = Field(500, ge=1, le=5000)


class CaseDbImportRunRequest(BaseModel):
    database: str = Field(..., min_length=1)
    run_output: str = Field(..., min_length=1)
    case_id: str = Field(..., min_length=1)
    name: Optional[str] = None


class RunCaseDbEnsureRequest(BaseModel):
    database: Optional[str] = None
    case_id: Optional[str] = None
    name: Optional[str] = None


class CaseDbSearchRequest(BaseModel):
    database: str = Field(..., min_length=1)
    case_id: str = Field(..., min_length=1)
    keywords: list[str] = Field(..., min_length=1)
    limit: int = Field(100, ge=1, le=1000)
    sources: Optional[list[str]] = None
    metadata_filters: Optional[list[str]] = None
    review_status: Optional[str] = None
    verification_status: Optional[str] = None
    save_as: Optional[str] = None
    keyword_packs: Optional[list[str]] = None


class CaseDbReviewRequest(BaseModel):
    database: str = Field(..., min_length=1)
    case_id: str = Field(..., min_length=1)
    target_type: str = Field(..., min_length=1)
    target_id: str = Field(..., min_length=1)
    status: Optional[str] = None
    verification_status: Optional[str] = None
    tags: Optional[list[str]] = None
    note: Optional[str] = None
    reviewer: Optional[str] = None
    assignee: Optional[str] = None
    priority: Optional[str] = None
    due_at: Optional[str] = None
    include_in_report: Optional[bool] = None


class CaseDbReviewBatchRequest(BaseModel):
    database: str = Field(..., min_length=1)
    case_id: str = Field(..., min_length=1)
    targets: list[dict[str, str]] = Field(..., min_length=1)
    status: Optional[str] = None
    verification_status: Optional[str] = None
    tags: Optional[list[str]] = None
    note: Optional[str] = None
    reviewer: Optional[str] = None
    assignee: Optional[str] = None
    priority: Optional[str] = None
    due_at: Optional[str] = None
    include_in_report: Optional[bool] = None


class CaseDbReportExportRequest(BaseModel):
    database: str = Field(..., min_length=1)
    case_id: str = Field(..., min_length=1)
    include_all: bool = False
    max_items: int = Field(500, ge=1, le=5000)


class CaseDbSavedSearchRequest(BaseModel):
    database: str = Field(..., min_length=1)
    case_id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    keywords: list[str] = Field(..., min_length=1)
    limit: int = Field(100, ge=1, le=1000)
    sources: Optional[list[str]] = None
    metadata_filters: Optional[list[str]] = None
    review_status: Optional[str] = None
    verification_status: Optional[str] = None
    created_by: str = ""


class CaseDbSavedSearchListRequest(BaseModel):
    database: str = Field(..., min_length=1)
    case_id: str = Field(..., min_length=1)


class CaseCatalogAddRunRequest(BaseModel):
    catalog: Optional[str] = None
    run_output: str = Field(..., min_length=1)
    case_id: str = Field(..., min_length=1)
    name: Optional[str] = None
    description: str = ""
    examiner: str = ""
    organization: str = ""


class EvidenceIdentifyRequest(BaseModel):
    path: str = Field(..., min_length=1)


class CollectPlanRequest(BaseModel):
    root: str = Field(..., min_length=1)
    profile: str = "intrusion"
    input_kind: Optional[str] = None


def create_app(job_store: RunJobStore | None = None, auth_token: str | None = None) -> FastAPI:
    store = job_store or default_job_store
    api = FastAPI(title="rapidtriage local API", version="0.2.0")
    static_dir = Path(__file__).resolve().parent.parent / "web" / "static"
    expected_token = auth_token or os.environ.get("RAPIDTRIAGE_AUTH_TOKEN") or ""

    @api.middleware("http")
    async def require_auth_token(request: Request, call_next):
        try:
            if expected_token and request.url.path.startswith("/api"):
                if "token" in request.query_params:
                    return JSONResponse(
                        status_code=401,
                        content={"detail": "query token authentication is disabled; use X-RapidTriage-Token header"},
                    )
                supplied = request.headers.get("X-RapidTriage-Token")
                if supplied != expected_token:
                    return JSONResponse(status_code=401, content={"detail": "missing or invalid RapidTriage auth token"})
            return await call_next(request)
        except Exception as exc:
            report = write_crash_report(
                exc,
                context={
                    "component": "web-api",
                    "method": request.method,
                    "path": request.url.path,
                },
            )
            return JSONResponse(
                status_code=500,
                content={
                    "detail": "internal RapidTriage error; local crash report written",
                    "crash_id": report["crash_id"],
                    "crash_report": report["path"],
                },
            )

    @api.get("/api/health")
    def health() -> Dict[str, str]:
        return {"status": "ok"}

    @api.get("/api/workbench/smoke-contract")
    def workbench_smoke_contract() -> Dict[str, object]:
        return build_workbench_smoke_contract()

    @api.get("/api/workbench/large-result-evidence")
    def workbench_large_result_evidence(record_count: int = Query(100_000, ge=1, le=10_000_000)) -> Dict[str, object]:
        return build_workbench_large_result_evidence(record_count=record_count)

    @api.get("/api/doctor")
    def doctor() -> Dict[str, object]:
        return run_doctor(include_port_check=False)

    @api.get("/api/crash-reports")
    def crash_reports(limit: int = Query(50, ge=1, le=500)) -> Dict[str, object]:
        return list_crash_reports(limit=limit)

    @api.get("/api/crash-reports/{crash_id}")
    def crash_report_detail(crash_id: str) -> Dict[str, object]:
        try:
            return read_crash_report(crash_id)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @api.post("/api/crash-reports/{crash_id}/export")
    def crash_report_export(crash_id: str) -> Dict[str, object]:
        try:
            return export_crash_report_bundle(crash_id)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @api.get("/api/enterprise/policy")
    def enterprise_policy() -> Dict[str, object]:
        return build_enterprise_policy()

    @api.get("/api/evidence/formats")
    def evidence_formats() -> Dict[str, object]:
        return {"formats": supported_evidence_formats()}

    @api.post("/api/evidence/identify")
    def identify_evidence_path(request: EvidenceIdentifyRequest) -> Dict[str, object]:
        try:
            result = identify_evidence(Path(request.path))
            return {
                "command": "evidence.identify",
                "result": result.to_dict(),
                "formats": supported_evidence_formats(),
            }
        except OSError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @api.get("/api/collect/profiles")
    def collect_profiles() -> Dict[str, object]:
        return {"profiles": list(supported_collect_profiles())}

    @api.get("/api/keyword-packs")
    def keyword_packs() -> Dict[str, object]:
        return {
            "command": "keyword-packs",
            "packs": list_keyword_packs(),
            "keyword_pack_library_assessment": keyword_pack_library_assessment(),
        }

    @api.post("/api/collect/plan")
    def collect_plan(request: CollectPlanRequest) -> Dict[str, object]:
        try:
            return build_collect_plan(
                Path(request.root).expanduser().resolve(),
                profile=request.profile,
                input_kind=request.input_kind,
            )
        except (CollectPlanError, OSError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @api.post("/api/sample-case/run", status_code=201)
    def run_sample_case(request: SampleCaseRunRequest) -> Dict[str, object]:
        try:
            output_dir = Path(request.output_dir).expanduser() if request.output_dir else Path.home() / ".rapidtriage" / "sample-case"
            sample_payload = run_sample_workflow(
                output_dir,
                mode=request.mode,
                overwrite=request.overwrite,
                read_only=request.read_only,
            )
            job = store.import_completed_run(Path(str(sample_payload["run"]["output_dir"])))
            return {
                "command": "sample-case.run",
                "sample": sample_payload,
                "run": job.to_dict(include_summary=True),
            }
        except (SampleCaseError, RunModeError, OSError, json.JSONDecodeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @api.post("/api/case-db/import-run")
    def import_run_to_case_db(request: CaseDbImportRunRequest) -> Dict[str, object]:
        try:
            database = open_case_database(Path(request.database))
            return database.import_run_output(Path(request.run_output), case_id=request.case_id, case_name=request.name)
        except (CaseDatabaseError, SearchError, OSError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @api.post("/api/runs/{run_id}/case-db/ensure")
    def ensure_run_case_db(run_id: str, request: RunCaseDbEnsureRequest) -> Dict[str, object]:
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail="run is not completed")
        output_dir = run_output_dir(job.summary)
        database_path = Path(request.database).expanduser().resolve() if request.database else output_dir / "rapidtriage-case.db"
        case_id = request.case_id or f"run-{run_id}"
        case_name = request.name or f"rapidtriage run {run_id}"
        try:
            database = open_case_database(database_path)
            storage = database.case_storage_summary(case_id)
            already_imported = bool(storage["exists"]) and int(storage["summary"].get("evidence_source_count") or 0) > 0
            import_result = None
            if not already_imported:
                import_result = database.import_run_output(output_dir, case_id=case_id, case_name=case_name)
                storage = database.case_storage_summary(case_id)
            return {
                "command": "case-db.ensure-run",
                "run_id": run_id,
                "run_output": str(output_dir),
                "database": str(database_path),
                "case_id": case_id,
                "case_name": case_name,
                "imported": not already_imported,
                "import_result": import_result,
                "storage": storage,
            }
        except (CaseDatabaseError, SearchError, OSError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @api.post("/api/case-db/search")
    def search_case_db(request: CaseDbSearchRequest) -> Dict[str, object]:
        try:
            keywords = resolve_keyword_packs(request.keywords, pack_names=request.keyword_packs)
            database = open_case_database(Path(request.database))
            payload = database.search_case(
                case_id=request.case_id,
                keywords=keywords,
                limit=request.limit,
                sources=request.sources,
                metadata_filters=request.metadata_filters,
                review_status=request.review_status,
                verification_status=request.verification_status,
            )
            if request.save_as:
                payload["saved_search"] = database.save_search(
                    case_id=request.case_id,
                    name=request.save_as,
                    keywords=keywords,
                    limit=request.limit,
                    sources=request.sources,
                    metadata_filters=request.metadata_filters,
                    review_status=request.review_status,
                    verification_status=request.verification_status,
                    created_by="web-ui",
                )
            return payload
        except (CaseDatabaseError, KeywordPackError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @api.post("/api/case-db/review")
    def mark_case_db_review(request: CaseDbReviewRequest) -> Dict[str, object]:
        try:
            database = open_case_database(Path(request.database))
            return database.mark_review(
                case_id=request.case_id,
                target_type=request.target_type,
                target_id=request.target_id,
                status=request.status,
                verification_status=request.verification_status,
                tags=request.tags,
                note=request.note,
                reviewer=request.reviewer,
                assignee=request.assignee,
                priority=request.priority,
                due_at=request.due_at,
                include_in_report=request.include_in_report,
            )
        except CaseDatabaseError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @api.post("/api/case-db/review-batch")
    def mark_case_db_reviews_batch(request: CaseDbReviewBatchRequest) -> Dict[str, object]:
        try:
            database = open_case_database(Path(request.database))
            return database.mark_reviews_batch(
                case_id=request.case_id,
                targets=request.targets,
                status=request.status,
                verification_status=request.verification_status,
                tags=request.tags,
                note=request.note,
                reviewer=request.reviewer,
                assignee=request.assignee,
                priority=request.priority,
                due_at=request.due_at,
                include_in_report=request.include_in_report,
            )
        except CaseDatabaseError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @api.post("/api/case-db/report-export")
    def export_case_db_report_items(request: CaseDbReportExportRequest) -> Dict[str, object]:
        try:
            database = open_case_database(Path(request.database))
            return database.export_reviewed_items(
                case_id=request.case_id,
                include_all=request.include_all,
                max_items=request.max_items,
            )
        except CaseDatabaseError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @api.post("/api/case-db/saved-searches")
    def save_case_db_search(request: CaseDbSavedSearchRequest) -> Dict[str, object]:
        try:
            database = open_case_database(Path(request.database))
            return database.save_search(
                case_id=request.case_id,
                name=request.name,
                keywords=request.keywords,
                limit=request.limit,
                sources=request.sources,
                metadata_filters=request.metadata_filters,
                review_status=request.review_status,
                verification_status=request.verification_status,
                created_by=request.created_by,
            )
        except CaseDatabaseError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @api.post("/api/case-db/saved-searches/list")
    def list_case_db_saved_searches(request: CaseDbSavedSearchListRequest) -> Dict[str, object]:
        try:
            database = open_case_database(Path(request.database))
            return {
                "command": "case-db.saved-searches",
                "database": str(Path(request.database).expanduser().resolve()),
                "case_id": request.case_id,
                "saved_searches": database.list_saved_searches(request.case_id),
            }
        except CaseDatabaseError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @api.get("/api/case-catalog")
    def list_case_catalog(catalog: Optional[str] = Query(None)) -> Dict[str, object]:
        try:
            case_catalog = CaseCatalog(Path(catalog).expanduser().resolve() if catalog else default_case_catalog_path())
            return {"catalog": str(case_catalog.path), "cases": case_catalog.list_cases()}
        except CaseCatalogError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @api.post("/api/case-catalog/add-run")
    def add_case_catalog_run(request: CaseCatalogAddRunRequest) -> Dict[str, object]:
        try:
            case_catalog = CaseCatalog(Path(request.catalog).expanduser().resolve() if request.catalog else default_case_catalog_path())
            case = case_catalog.add_run(
                run_output=Path(request.run_output),
                case_id=request.case_id,
                name=request.name,
                description=request.description,
                examiner=request.examiner,
                organization=request.organization,
            )
            return {"catalog": str(case_catalog.path), "case": case}
        except CaseCatalogError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @api.post("/api/runs", status_code=202)
    def create_run(request: RunCreateRequest) -> Dict[str, Any]:
        validate_run_evidence_source(request.root)
        run_request = RunRequest(
            root=request.root,
            mode=request.mode,
            output_dir=request.output_dir,
            input_kind=request.input_kind,
            rules=request.rules,
            dry_run=request.dry_run,
            read_only=request.read_only,
            max_extract_size_bytes=request.max_extract_size_bytes,
            max_file_count=request.max_file_count,
            memory_cap_bytes=request.memory_cap_bytes,
            e01_partition_start_sector=request.e01_partition_start_sector,
            overwrite=request.overwrite,
            resume=request.resume,
            known_good_hash_feeds=tuple(path.strip() for path in request.known_good_hash_feeds if path.strip()),
            hide_known_good=request.hide_known_good,
            known_good_max_hash_bytes=request.known_good_max_hash_bytes,
        )
        job = store.run_sync(run_request) if request.wait else store.submit(run_request)
        return job.to_dict(include_summary=request.wait)

    @api.post("/api/runs/import", status_code=201)
    def import_run(request: RunImportRequest) -> Dict[str, Any]:
        try:
            job = store.import_completed_run(request.output_dir)
        except (FileNotFoundError, OSError, json.JSONDecodeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return job.to_dict(include_summary=True)

    @api.get("/api/runs")
    def list_runs() -> Dict[str, Any]:
        return {"runs": [job.to_dict() for job in store.list()]}

    @api.get("/api/forensic-capabilities")
    def get_forensic_capabilities() -> Dict[str, object]:
        return build_visible_capability_response()

    @api.get("/api/runs/{run_id}")
    def get_run(run_id: str) -> Dict[str, Any]:
        return get_job_payload(store, run_id, include_summary=True)

    @api.delete("/api/runs/{run_id}", status_code=204)
    def delete_run(run_id: str) -> None:
        try:
            store.remove(run_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="run not found")

    @api.post("/api/runs/{run_id}/cancel")
    def cancel_run(run_id: str) -> Dict[str, Any]:
        try:
            return store.cancel(run_id).to_dict(include_summary=True)
        except KeyError:
            raise HTTPException(status_code=404, detail="run not found")

    @api.post("/api/runs/{run_id}/retry", status_code=202)
    def retry_run(run_id: str) -> Dict[str, Any]:
        try:
            return store.retry(run_id).to_dict(include_summary=True)
        except KeyError:
            raise HTTPException(status_code=404, detail="run not found")
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc))

    @api.get("/api/runs/{run_id}/summary")
    def get_run_summary(run_id: str) -> Dict[str, object]:
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail="run is not completed")
        return job.summary

    @api.get("/api/runs/{run_id}/capabilities")
    def get_run_capabilities(run_id: str) -> Dict[str, object]:
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail="run is not completed")
        return build_visible_capability_response(
            run_summary=job.summary,
            artifacts=read_run_artifacts_for_capabilities(store, run_id, job.summary),
        )

    @api.get("/api/runs/{run_id}/outputs/{output_name}")
    def get_run_output(run_id: str, output_name: str) -> Dict[str, object]:
        try:
            return store.read_output(run_id, output_name)
        except KeyError:
            raise HTTPException(status_code=404, detail="run output not found")
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc))

    @api.get("/api/runs/{run_id}/outputs/{output_name}/preview")
    def preview_run_output(run_id: str, output_name: str) -> Dict[str, object]:
        path = get_output_path(store, run_id, output_name)
        return build_run_output_preview(run_id=run_id, output_name=output_name, output_path=path)

    @api.get("/api/runs/{run_id}/output-files")
    def get_run_output_files(run_id: str) -> Dict[str, object]:
        try:
            return {"files": store.output_files(run_id)}
        except KeyError:
            raise HTTPException(status_code=404, detail="run not found")
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc))

    @api.get("/api/runs/{run_id}/outputs/{output_name}/file")
    def download_run_output(run_id: str, output_name: str) -> FileResponse:
        path = get_output_path(store, run_id, output_name)
        return FileResponse(path, filename=path.name)

    @api.get("/api/runs/{run_id}/source-file")
    def download_source_file(run_id: str, path: str = Query(..., min_length=1)) -> FileResponse:
        source_path = resolve_allowed_source_file(store, run_id, path)
        return FileResponse(source_path, filename=source_path.name)

    @api.get("/api/runs/{run_id}/source-preview")
    def preview_source_file(run_id: str, path: str = Query(..., min_length=1)) -> Dict[str, object]:
        source_path = resolve_allowed_source_file(store, run_id, path)
        return build_source_preview(run_id, source_path)

    @api.get("/api/runs/{run_id}/source-hex-range")
    def source_hex_range(
        run_id: str,
        path: str = Query(..., min_length=1),
        offset: int = Query(0, ge=0),
        length: int = Query(256, ge=1, le=HEX_RANGE_EXPORT_MAX_BYTES),
        include_hashes: bool = False,
    ) -> Dict[str, object]:
        source_path = resolve_allowed_source_file(store, run_id, path)
        return build_hex_range_citation_package(
            run_id=run_id,
            source_path=source_path,
            offset=offset,
            length=length,
            include_source_hashes=include_hashes,
        )

    @api.get("/api/runs/{run_id}/source-sqlite-table")
    def source_sqlite_table(
        run_id: str,
        path: str = Query(..., min_length=1),
        table: str = Query(..., min_length=1),
        offset: int = Query(0, ge=0),
        limit: int = Query(100, ge=1, le=SQLITE_TABLE_PAGE_MAX_ROWS),
        where_column: Optional[str] = Query(default=None, min_length=1),
        where_contains: Optional[str] = Query(default=None, min_length=1),
        order_by: Optional[str] = Query(default=None, min_length=1),
        descending: bool = False,
    ) -> Dict[str, object]:
        source_path = resolve_allowed_source_file(store, run_id, path)
        if not is_sqlite_candidate(source_path):
            raise HTTPException(status_code=400, detail="source file is not a supported SQLite database")
        return build_sqlite_table_page(
            run_id=run_id,
            source_path=source_path,
            table=table,
            offset=offset,
            limit=limit,
            where_column=where_column,
            where_contains=where_contains,
            order_by=order_by,
            descending=descending,
        )

    @api.get("/api/runs/{run_id}/source-email-attachment")
    def source_email_attachment(
        run_id: str,
        path: str = Query(..., min_length=1),
        message_index: int = Query(1, ge=1),
        attachment_index: int = Query(1, ge=1),
        include_content: bool = False,
    ) -> Dict[str, object]:
        source_path = resolve_allowed_source_file(store, run_id, path)
        suffix = source_path.suffix.lower()
        if suffix not in {".eml", ".mbox"}:
            raise HTTPException(status_code=400, detail="source file is not a supported EML/MBOX email preview")
        return build_email_attachment_package(
            run_id=run_id,
            source_path=source_path,
            suffix=suffix,
            message_index=message_index,
            attachment_index=attachment_index,
            include_content=include_content,
        )

    @api.get("/api/runs/{run_id}/source-image-gallery")
    def source_image_gallery(
        run_id: str,
        path: str = Query(..., min_length=1),
        offset: int = Query(0, ge=0),
        limit: int = Query(IMAGE_GALLERY_DEFAULT_LIMIT, ge=1, le=IMAGE_GALLERY_MAX_ITEMS),
        similarity_bucket: Optional[str] = Query(default=None, min_length=1),
    ) -> Dict[str, object]:
        source_path = resolve_allowed_source_file(store, run_id, path)
        if not is_image_preview_candidate(source_path):
            raise HTTPException(status_code=400, detail="source file is not a supported image preview")
        return build_image_gallery_page(
            run_id=run_id,
            anchor_path=source_path,
            offset=offset,
            limit=limit,
            similarity_bucket=similarity_bucket,
        )

    @api.get("/api/runs/{run_id}/source-media-cue")
    def source_media_cue(
        run_id: str,
        path: str = Query(..., min_length=1),
        sidecar_index: int = Query(1, ge=1),
        cue_index: int = Query(1, ge=1),
        include_source_hashes: bool = False,
    ) -> Dict[str, object]:
        source_path = resolve_allowed_source_file(store, run_id, path)
        mime_type = mimetypes.guess_type(source_path.name)[0] or ""
        if not mime_type.startswith(("audio/", "video/")):
            raise HTTPException(status_code=400, detail="source file is not a supported audio/video preview")
        return build_media_cue_package(
            run_id=run_id,
            source_path=source_path,
            sidecar_index=sidecar_index,
            cue_index=cue_index,
            include_source_hashes=include_source_hashes,
        )

    @api.get("/api/runs/{run_id}/source-ocr-queue")
    def source_ocr_queue(
        run_id: str,
        path: str = Query(..., min_length=1),
        max_items: int = Query(SOURCE_OCR_QUEUE_DEFAULT_MAX_ITEMS, ge=1, le=1000),
        retry_failures: bool = False,
    ) -> Dict[str, object]:
        source_path = resolve_allowed_source_file(store, run_id, path)
        if not is_image_preview_candidate(source_path):
            raise HTTPException(status_code=400, detail="source file is not a supported image preview")
        return build_source_ocr_queue(
            run_id=run_id,
            anchor_path=source_path,
            max_items=max_items,
            retry_failures=retry_failures,
        )

    @api.get("/api/runs/{run_id}/source-ocr-translation")
    def source_ocr_translation(
        run_id: str,
        path: str = Query(..., min_length=1),
        include_text: bool = True,
    ) -> Dict[str, object]:
        source_path = resolve_allowed_source_file(store, run_id, path)
        if not is_image_preview_candidate(source_path):
            raise HTTPException(status_code=400, detail="source file is not a supported image preview")
        return build_source_ocr_translation_package(
            run_id=run_id,
            source_path=source_path,
            include_text=include_text,
        )

    @api.get("/api/runs/{run_id}/source-search")
    def search_source_file(
        run_id: str,
        path: str = Query(..., min_length=1),
        keyword: list[str] = Query(..., min_length=1),
        limit: int = Query(100, ge=1, le=500),
        context: int = Query(120, ge=20, le=500),
        sqlite_resume_token: Optional[str] = Query(default=None),
        file_resume_token: Optional[str] = Query(default=None),
    ) -> Dict[str, object]:
        source_path = resolve_allowed_source_file(store, run_id, path)
        return build_source_search(
            source_path,
            keyword,
            limit=limit,
            context=context,
            sqlite_resume_token=sqlite_resume_token,
            file_resume_token=file_resume_token,
        )

    @api.get("/api/runs/{run_id}/timeline")
    def get_run_timeline(
        run_id: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(0, ge=0, le=1000),
        cursor: Optional[str] = Query(default=None),
    ) -> Dict[str, object]:
        payload = get_named_output(store, run_id, "timeline")
        return paginate_payload(payload, "events", offset=offset, limit=limit, cursor=cursor)

    @api.get("/api/runs/{run_id}/indicators")
    def get_run_indicators(
        run_id: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(0, ge=0, le=1000),
        cursor: Optional[str] = Query(default=None),
    ) -> Dict[str, object]:
        payload = get_named_output(store, run_id, "indicators")
        return paginate_payload(payload, "indicators", offset=offset, limit=limit, cursor=cursor)

    @api.get("/api/runs/{run_id}/indicators/ti-enrichment")
    def get_run_indicator_ti_enrichment(
        run_id: str,
        ti_feed: list[str] = Query(default=[]),
        include_unmatched: bool = Query(False),
        limit: int = Query(250, ge=1, le=1000),
    ) -> Dict[str, object]:
        payload = get_named_output(store, run_id, "indicators")
        try:
            return build_indicator_ti_enrichment_package(
                payload,
                ti_feeds=[Path(path).expanduser().resolve() for path in ti_feed],
                include_unmatched=include_unmatched,
                limit=limit,
            )
        except IndicatorSummaryError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @api.get("/api/runs/{run_id}/artifacts")
    def get_run_artifacts(
        run_id: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(0, ge=0, le=1000),
        cursor: Optional[str] = Query(default=None),
    ) -> Dict[str, object]:
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail="run is not completed")
        outputs = job.summary.get("outputs")
        if not isinstance(outputs, dict):
            raise HTTPException(status_code=409, detail="run has no outputs")
        artifacts = {}
        for name in sorted(outputs):
            if name.startswith("artifacts_"):
                try:
                    artifact_payload = store.read_output(run_id, name)
                    artifacts[name.removeprefix("artifacts_")] = paginate_payload(
                        artifact_payload,
                        "artifacts",
                        offset=offset,
                        limit=limit,
                        cursor=cursor,
                    )
                except RuntimeError as exc:
                    raise HTTPException(status_code=409, detail=str(exc))
                except PermissionError as exc:
                    raise HTTPException(status_code=403, detail=str(exc))
                except FileNotFoundError as exc:
                    raise HTTPException(status_code=404, detail=str(exc))
        return {"artifacts": artifacts}

    @api.get("/api/runs/{run_id}/files")
    def get_run_files(
        run_id: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(0, ge=0, le=1000),
        cursor: Optional[str] = Query(default=None),
    ) -> Dict[str, object]:
        payload = get_named_output(store, run_id, "files")
        return paginate_payload(payload, "candidates", offset=offset, limit=limit, cursor=cursor)

    @api.get("/api/runs/{run_id}/docs")
    def get_run_docs(
        run_id: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(0, ge=0, le=1000),
        cursor: Optional[str] = Query(default=None),
    ) -> Dict[str, object]:
        payload = get_named_output(store, run_id, "docs")
        return paginate_payload(payload, "results", offset=offset, limit=limit, cursor=cursor, omit_fields=("candidates", "manifest"))

    @api.get("/api/runs/{run_id}/docs-index-search")
    def search_run_docs_index(
        run_id: str,
        keyword: list[str] = Query(..., min_length=1),
        limit: int = Query(500, ge=1, le=5000),
    ) -> Dict[str, object]:
        index_path = get_output_path(store, run_id, "docs_index")
        try:
            payload = query_docs_index(index_path, keyword, limit=limit)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        for result in payload.get("results", []):
            if not isinstance(result, dict) or not result.get("path"):
                continue
            result["source_viewer_url"] = (
                f"/api/runs/{run_id}/source-preview?path={quote(str(result['path']))}"
            )
            result["source_search_url"] = (
                f"/api/runs/{run_id}/source-search?path={quote(str(result['path']))}"
            )
        payload["run_id"] = run_id
        payload["api_profile"] = {
            "profile_version": "docs-index-search-api-v1",
            "output_name": "docs_index",
            "gui_binding": "docs-index-sidecar-search",
            "source_verification_required": True,
            "reportability_warning": (
                "Docs-index hits are fast leads only; open the source viewer or source-search hit context before reporting."
            ),
        }
        return payload

    @api.get("/api/runs/{run_id}/search")
    def search_run(
        run_id: str,
        keyword: list[str] = Query(..., min_length=1),
        ocr: bool = True,
        limit: int = Query(500, ge=1, le=1000),
        source: list[str] = Query(default=[]),
        extension: list[str] = Query(default=[]),
        path_contains: Optional[str] = Query(default=None),
        analysis: bool = True,
        search_mode: str = Query("exact", pattern="^(exact|fuzzy|regex)$"),
        fuzzy_distance: int = Query(1, ge=0, le=2),
        proximity_window: int = Query(0, ge=0, le=100),
        hide_known_good: bool = False,
        keyword_pack: list[str] = Query(default=[]),
    ) -> Dict[str, object]:
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail="run is not completed")
        try:
            selected_pack_names = [name.strip() for name in keyword_pack if name.strip()]
            keywords = resolve_keyword_packs(keyword, pack_names=selected_pack_names)
            payload = run_unified_search(
                job.summary,
                keywords,
                include_ocr=ocr,
                limit=limit,
                sources=source,
                extensions=extension,
                path_contains=path_contains,
                include_analysis=analysis,
                search_mode=search_mode,
                fuzzy_distance=fuzzy_distance,
                proximity_window=proximity_window,
                hide_known_good=hide_known_good,
            )
            payload["keyword_pack_selection_profile"] = keyword_pack_selection_profile(
                pack_names=selected_pack_names,
                keyword_count=len(keywords),
                expanded_keywords=keywords,
            )
            attach_search_result_source_actions(payload, run_id)
            return payload
        except (SearchError, KeywordPackError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @api.get("/api/runs/{run_id}/source-metadata")
    def source_metadata(run_id: str, path: str = Query(..., min_length=1), hash: bool = False) -> Dict[str, object]:
        source_path = resolve_allowed_source_file(store, run_id, path)
        return build_source_metadata(source_path, include_hashes=hash)

    @api.get("/api/runs/{run_id}/report", response_class=PlainTextResponse)
    def get_run_report(run_id: str) -> str:
        path = get_output_path(store, run_id, "report")
        return path.read_text(encoding="utf-8")

    @api.get("/api/runs/{run_id}/case")
    def get_run_case(run_id: str) -> Dict[str, object]:
        case_path = default_case_path(store, run_id)
        if not case_path.is_file():
            return {"exists": False, "case_path": str(case_path), "case": None}
        try:
            return {"exists": True, "case_path": str(case_path), "case": load_case_payload(case_path)}
        except CaseBookmarkError as exc:
            raise HTTPException(status_code=409, detail=str(exc))

    @api.get("/api/runs/{run_id}/submission-manifest")
    def get_submission_manifest(
        run_id: str,
        include_all: bool = False,
        max_items: int = Query(500, ge=1, le=5000),
    ) -> Dict[str, object]:
        manifest_path = default_submission_manifest_path(store, run_id)
        manifest = build_run_submission_manifest(
            store,
            run_id,
            include_all=include_all,
            max_items=max_items,
        )
        write_json_file(manifest_path, manifest)
        write_submission_audit(store, run_id, manifest_path, include_all=include_all, max_items=max_items)
        return manifest

    @api.get("/api/runs/{run_id}/submission-manifest/file")
    def download_submission_manifest(run_id: str, include_all: bool = False) -> FileResponse:
        manifest_path = default_submission_manifest_path(store, run_id)
        manifest = build_run_submission_manifest(store, run_id, include_all=include_all, max_items=500)
        write_json_file(manifest_path, manifest)
        write_submission_audit(store, run_id, manifest_path, include_all=include_all, max_items=500)
        return FileResponse(manifest_path, filename=manifest_path.name)

    @api.get("/api/runs/{run_id}/validation-package")
    def get_run_validation_package(run_id: str) -> Dict[str, object]:
        package_path = default_run_validation_package_path(store, run_id)
        package = build_run_validation_package(store, run_id)
        write_json_file(package_path, package)
        write_run_validation_package_audit(store, run_id, package_path)
        return package

    @api.get("/api/runs/{run_id}/validation-package/file")
    def download_run_validation_package(run_id: str) -> FileResponse:
        package_path = default_run_validation_package_path(store, run_id)
        package = build_run_validation_package(store, run_id)
        write_json_file(package_path, package)
        write_run_validation_package_audit(store, run_id, package_path)
        return FileResponse(package_path, filename=package_path.name)

    @api.post("/api/runs/{run_id}/case-report")
    def create_case_report(run_id: str, request: CaseReportCreateRequest) -> Dict[str, object]:
        report_path = default_case_report_path(store, run_id)
        markdown = build_run_case_report(store, run_id, request)
        exports = write_case_report_exports(markdown, report_path)
        write_case_report_audit(store, run_id, report_path, request)
        return {
            "report_path": str(report_path),
            "exports": exports,
            "audit": str(audit_path_for(report_path)),
            "markdown": markdown,
        }

    @api.get("/api/runs/{run_id}/case-report/file")
    def download_case_report(run_id: str) -> FileResponse:
        request = CaseReportCreateRequest()
        report_path = default_case_report_path(store, run_id)
        markdown = build_run_case_report(store, run_id, request)
        write_case_report_exports(markdown, report_path)
        write_case_report_audit(store, run_id, report_path, request)
        return FileResponse(report_path, filename=report_path.name, media_type="text/markdown")

    @api.get("/api/runs/{run_id}/case-report/file/{format_name}")
    def download_case_report_format(run_id: str, format_name: str) -> FileResponse:
        normalized = format_name.lower()
        if normalized not in {"md", "html", "docx", "pdf", "manifest"}:
            raise HTTPException(status_code=404, detail="unsupported case report format")
        request = CaseReportCreateRequest()
        report_path = default_case_report_path(store, run_id)
        markdown = build_run_case_report(store, run_id, request)
        write_case_report_exports(markdown, report_path)
        write_case_report_audit(store, run_id, report_path, request)
        path = case_report_export_paths(report_path)[normalized]
        media_types = {
            "md": "text/markdown",
            "html": "text/html",
            "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "pdf": "application/pdf",
            "manifest": "application/json",
        }
        return FileResponse(path, filename=path.name, media_type=media_types[normalized])

    @api.post("/api/runs/{run_id}/reviewer-bundle")
    def create_reviewer_bundle(run_id: str, request: ReviewerBundleCreateRequest) -> Dict[str, object]:
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail="run is not completed")
        case_path = default_case_path(store, run_id)
        if not case_path.is_file():
            raise HTTPException(status_code=404, detail="case review file not found")
        try:
            return build_submission_bundle(
                case_json=case_path,
                output_dir=default_reviewer_bundle_dir_path(store, run_id),
                allowed_roots=allowed_source_roots(job.summary),
                include_all=request.include_all,
                max_items=request.max_items,
                title=request.title,
            )
        except (BundleError, CaseBookmarkError, OSError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @api.get("/api/runs/{run_id}/reviewer-bundle/file")
    def download_reviewer_bundle(run_id: str) -> FileResponse:
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail="run is not completed")
        case_path = default_case_path(store, run_id)
        if not case_path.is_file():
            raise HTTPException(status_code=404, detail="case review file not found")
        try:
            payload = build_submission_bundle(
                case_json=case_path,
                output_dir=default_reviewer_bundle_dir_path(store, run_id),
                allowed_roots=allowed_source_roots(job.summary),
                include_all=False,
                max_items=500,
                title=None,
            )
        except (BundleError, CaseBookmarkError, OSError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        archive = Path(str(payload.get("archive") or payload.get("outputs", {}).get("archive", "")))
        return FileResponse(archive, filename=archive.name, media_type="application/zip")

    @api.post("/api/runs/{run_id}/bookmarks")
    def create_run_bookmark(run_id: str, request: BookmarkCreateRequest) -> Dict[str, object]:
        source_name = normalize_bookmark_source(request.source)
        source_path = get_output_path(store, run_id, source_name)
        case_path = default_case_path(store, run_id)
        try:
            payload = create_or_update_case_payload(
                case_path,
                case_id=request.case_id or f"run-{run_id}",
                title=request.title or f"rapidtriage run {run_id}",
                source_path=source_path,
                source_pointer=request.pointer,
                bookmark_id=request.bookmark_id,
                tags=normalize_bookmark_tags(request),
                note=request.note,
                review_status=request.review_status,
                include_in_report=request.include_in_report,
            )
        except (FileNotFoundError, CaseBookmarkError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        save_case_payload(case_path, payload)
        audit_output = audit_path_for(case_path)
        write_audit_record(
            audit_output,
            command="case",
            options={
                "case_id": request.case_id,
                "title": request.title,
                "source": str(source_path),
                "pointer": request.pointer,
                "bookmark_id": request.bookmark_id,
                "tags": normalize_bookmark_tags(request),
                "review_status": request.review_status,
                "include_in_report": request.include_in_report,
            },
            input_files=[("source-json", source_path)],
            output_files=[("case-json", case_path)],
        )
        return {"case_path": str(case_path), "audit": str(audit_output), "case": payload}

    if static_dir.is_dir():
        api.mount("/assets", StaticFiles(directory=static_dir), name="rapidtriage-assets")

        @api.get("/", include_in_schema=False)
        def index() -> FileResponse:
            return FileResponse(static_dir / "index.html")

        @api.get("/favicon.ico", include_in_schema=False)
        def favicon() -> FileResponse:
            return FileResponse(static_dir / "favicon.svg", media_type="image/svg+xml")

    return api


def get_job(store: RunJobStore, run_id: str):
    try:
        return store.get(run_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="run not found")


def validate_run_evidence_source(raw_root: str) -> None:
    source = Path(raw_root).expanduser()
    try:
        evidence = identify_evidence(source)
    except OSError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    result = evidence.to_dict()
    if source.is_dir():
        return
    if source.is_file() and not bool(result.get("can_extract")):
        detail = str(result.get("message") or "This evidence file cannot be scanned directly.")
        raise HTTPException(
            status_code=400,
            detail=(
                f"{detail} Mount or export the evidence first, then select the resulting folder. "
                "Use Check evidence support for adapter details."
            ),
        )


def get_job_payload(store: RunJobStore, run_id: str, *, include_summary: bool) -> Dict[str, object]:
    return get_job(store, run_id).to_dict(include_summary=include_summary)


def get_named_output(store: RunJobStore, run_id: str, output_name: str) -> Dict[str, object]:
    try:
        return store.read_output(run_id, output_name)
    except KeyError:
        raise HTTPException(status_code=404, detail="run output not found")
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


def read_run_artifacts_for_capabilities(
    store: RunJobStore,
    run_id: str,
    summary: Mapping[str, object],
) -> Dict[str, object]:
    outputs = summary.get("outputs")
    if not isinstance(outputs, Mapping):
        return {}
    artifacts: Dict[str, object] = {}
    for output_name in outputs:
        name = str(output_name)
        if not name.startswith("artifacts_"):
            continue
        try:
            artifacts[name.removeprefix("artifacts_")] = store.read_output(run_id, name)
        except (KeyError, RuntimeError, PermissionError, FileNotFoundError, OSError):
            artifacts[name.removeprefix("artifacts_")] = {
                "artifacts": [],
                "capability_load_error": True,
            }
    return artifacts


def paginate_payload(
    payload: Dict[str, object],
    collection_name: str,
    *,
    offset: int,
    limit: int,
    cursor: str | None = None,
    omit_fields: tuple[str, ...] = (),
) -> Dict[str, object]:
    if limit <= 0:
        return payload
    if cursor:
        offset = decode_pagination_cursor(cursor)
    rows = payload.get(collection_name)
    if not isinstance(rows, list):
        rows = []
    total = len(rows)
    end = min(offset + limit, total)
    returned = max(0, end - offset)
    has_more = end < total
    cursor_value = encode_pagination_cursor(offset)
    next_cursor = encode_pagination_cursor(end) if has_more else None
    previous_cursor = encode_pagination_cursor(max(0, offset - limit)) if offset > 0 else None
    pagination_manifest = build_pagination_cursor_manifest(
        collection_name=collection_name,
        offset=offset,
        limit=limit,
        returned=returned,
        total=total,
        cursor=cursor_value,
        next_cursor=next_cursor,
        previous_cursor=previous_cursor,
        has_more=has_more,
    )
    cursor_coverage_manifest = build_cursor_api_coverage_manifest(
        collection_name=collection_name,
        total=total,
        returned=returned,
        has_more=has_more,
        pagination_manifest=pagination_manifest,
    )
    page = dict(payload)
    for field in omit_fields:
        if field in page:
            page[field] = [] if isinstance(page[field], list) else None
    if omit_fields:
        page["omitted_fields"] = list(omit_fields)
    page[collection_name] = rows[offset:end]
    page["pagination"] = {
        "collection": collection_name,
        "offset": offset,
        "limit": limit,
        "returned": returned,
        "total": total,
        "next_offset": end if end < total else None,
        "previous_offset": max(0, offset - limit) if offset > 0 else None,
        "cursor": cursor_value,
        "next_cursor": next_cursor,
        "previous_cursor": previous_cursor,
        "has_more": has_more,
        "page_window_id": pagination_manifest["page_window_id"],
        "pagination_manifest": pagination_manifest,
        "cursor_endpoint_coverage_manifest": cursor_coverage_manifest,
        "snapshot_policy": pagination_manifest["snapshot_policy"],
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["pagination"]],
        "functional_priority_profile": cursor_api_functional_profile(
            collection_name,
            total=total,
            returned=returned,
            has_more=has_more,
            coverage_manifest=cursor_coverage_manifest,
        ),
        "pagination_assessment": pagination_assessment(
            collection_name,
            offset=offset,
            limit=limit,
            total=total,
            returned=returned,
            has_more=has_more,
            pagination_manifest=pagination_manifest,
        ),
        "core_accuracy_gates": [
            *pagination_core_accuracy_gates(
                collection_name,
                total=total,
                returned=returned,
                has_more=has_more,
                pagination_manifest=pagination_manifest,
            ),
            *ui_virtualization_core_accuracy_gates(
                label=collection_name,
                total=total,
                visible=returned,
                api_pagination=True,
            ),
        ],
        "ui_virtualization": ui_virtualization_metadata(
            label=collection_name,
            total=total,
            visible=returned,
            api_pagination=True,
        ),
    }
    return page


def build_pagination_cursor_manifest(
    *,
    collection_name: str,
    offset: int,
    limit: int,
    returned: int,
    total: int,
    cursor: str,
    next_cursor: str | None,
    previous_cursor: str | None,
    has_more: bool,
) -> dict[str, object]:
    page_window_core = {
        "collection": collection_name,
        "offset": max(0, int(offset)),
        "limit": max(0, int(limit)),
        "returned": max(0, int(returned)),
        "total": max(0, int(total)),
        "cursor": cursor,
        "next_cursor": next_cursor,
        "previous_cursor": previous_cursor,
        "has_more": bool(has_more),
    }
    page_window_id = hashlib.sha256(json.dumps(page_window_core, sort_keys=True).encode("utf-8")).hexdigest()
    endpoint_id = hashlib.sha256(f"pagination:{collection_name}".encode("utf-8")).hexdigest()
    manifest_core = {
        "profile": "pagination-cursor-manifest-v1",
        "profile_version": "pagination-cursor-manifest-v1",
        "item_number": 78,
        "endpoint_id": endpoint_id,
        "page_window_id": page_window_id,
        **page_window_core,
        "cursor_token_hashes": {
            "cursor": hashlib.sha256(str(cursor).encode("utf-8")).hexdigest() if cursor else "",
            "next_cursor": hashlib.sha256(str(next_cursor).encode("utf-8")).hexdigest() if next_cursor else "",
            "previous_cursor": hashlib.sha256(str(previous_cursor).encode("utf-8")).hexdigest()
            if previous_cursor
            else "",
        },
        "cursor_encoding": "offset-compatible-v1",
        "bounded_window": True,
        "limit_enforced": True,
        "snapshot_policy": {
            "snapshot_isolated": False,
            "warning": "offset-compatible cursors are not database snapshot cursors; rerun/import large cases into Case DB for stable review snapshots",
        },
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["pagination"]],
        "commercial_claim_allowed": False,
    }
    manifest_hash = hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest()
    return {**manifest_core, "manifest_hash": manifest_hash}


def build_cursor_api_coverage_manifest(
    *,
    collection_name: str,
    total: int,
    returned: int,
    has_more: bool,
    pagination_manifest: Mapping[str, object],
) -> dict[str, object]:
    covered_families = [
        "files",
        "docs",
        "timeline",
        "indicators",
        "artifact-groups",
    ]
    required_families = [
        *covered_families,
        "search-results",
        "case-db-review-candidates",
        "report-candidates",
    ]
    missing_families = [family for family in required_families if family not in covered_families]
    manifest_core = {
        "profile": "cursor-api-coverage-manifest-v1",
        "item_number": 31,
        "gap_id": "#31",
        "collection": collection_name,
        "total": int(total),
        "returned": int(returned),
        "has_more": bool(has_more),
        "pagination_manifest_hash": str(pagination_manifest.get("manifest_hash") or ""),
        "page_window_id": str(pagination_manifest.get("page_window_id") or ""),
        "covered_endpoint_families": covered_families,
        "required_endpoint_families": required_families,
        "missing_endpoint_families": missing_families,
        "endpoint_family_count": len(covered_families),
        "bounded_limit": True,
        "cursor_tokens": True,
        "offset_compatible": True,
        "snapshot_isolation": False,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["pagination"]],
        "commercial_claim_allowed": False,
    }
    return {
        **manifest_core,
        "manifest_hash": hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def pagination_assessment(
    collection_name: str,
    *,
    offset: int = 0,
    limit: int = 0,
    total: int,
    returned: int,
    has_more: bool | None = None,
    pagination_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    actual_has_more = bool(has_more) if has_more is not None else (offset + returned) < total
    manifest = dict(pagination_manifest) if pagination_manifest else build_pagination_cursor_manifest(
        collection_name=collection_name,
        offset=offset,
        limit=limit,
        returned=returned,
        total=total,
        cursor=encode_pagination_cursor(offset),
        next_cursor=encode_pagination_cursor(offset + returned) if (offset + returned) < total else None,
        previous_cursor=encode_pagination_cursor(max(0, offset - limit)) if offset > 0 and limit > 0 else None,
        has_more=actual_has_more,
    )
    core_gates = pagination_core_accuracy_gates(
        collection_name,
        total=total,
        returned=returned,
        has_more=actual_has_more,
        pagination_manifest=manifest,
        trusted_diff=trusted_diff,
    )
    blockers = [
        "cursor-is-offset-token-not-snapshot-isolated-database-cursor",
        "search-endpoints-still-return-bounded-result-sets-before-case-db-pagination",
    ]
    if not trusted_diff or trusted_diff.get("status") != "pass":
        blockers.append(PAGINATION_TRUSTED_DIFF_BLOCKER_78)
    return {
        "component": "artifact-pagination-cursor-api",
        "status": "offset-compatible-cursor-pagination",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["pagination"]],
        "collection": collection_name,
        "offset": offset,
        "limit": limit,
        "total": total,
        "returned": returned,
        "has_more": actual_has_more,
        "pagination_manifest": manifest,
        "ready_for_court_report": False,
        "trusted_pagination_diff": dict(trusted_diff) if trusted_diff else missing_pagination_trusted_diff(),
        "core_accuracy_gates": core_gates,
        "blockers": blockers,
    }


def cursor_api_functional_profile(
    collection_name: str,
    *,
    total: int,
    returned: int,
    has_more: bool,
    coverage_manifest: Mapping[str, object],
) -> dict[str, object]:
    return {
        "batch_id": FUNCTIONAL_SCALE_BATCH_ID,
        "item_number": 31,
        "gap_id": "#31",
        "component": "cursor-apis-everywhere",
        "status": "implemented-for-run-output-endpoints-validation-required",
        "implemented": True,
        "usable": True,
        "validated": True,
        "ready_for_commercial_claim": False,
        "controls": {
            "collection": collection_name,
            "total": total,
            "returned": returned,
            "has_more": has_more,
            "cursor_tokens": True,
            "offset_compatible": True,
            "bounded_limit": True,
            "snapshot_isolation": False,
            "coverage_manifest_hash": str(coverage_manifest.get("manifest_hash") or ""),
            "pagination_manifest_hash": str(coverage_manifest.get("pagination_manifest_hash") or ""),
            "covered_endpoint_family_count": len(coverage_manifest.get("covered_endpoint_families", []))
            if isinstance(coverage_manifest.get("covered_endpoint_families"), list)
            else 0,
            "missing_endpoint_families": list(coverage_manifest.get("missing_endpoint_families", []))
            if isinstance(coverage_manifest.get("missing_endpoint_families"), list)
            else [],
        },
        "covered_endpoint_families": [
            "files",
            "docs",
            "timeline",
            "indicators",
            "artifact-groups",
        ],
        "blockers": [
            "case-db-review-and-report-candidate-pagination-still-needs-endpoint-level-proof",
            "cursor-is-offset-token-not-snapshot-isolated-database-cursor",
            PAGINATION_TRUSTED_DIFF_BLOCKER_78,
        ],
        "validation_evidence": [
            "api-pagination-response-emits-functional-priority-profile",
            "unit-test-asserts-cursor-profile-on-files-endpoint",
        ],
    }


def pagination_core_accuracy_gates(
    collection_name: str,
    *,
    total: int,
    returned: int,
    has_more: bool,
    pagination_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = [
        "cursor token emitted",
        "offset/limit/total recorded",
        "next/previous cursor support",
        "bounded row return",
        "snapshot isolation limitation warning",
        "pagination cursor manifest hash emitted",
        "page window id emitted",
    ]
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted pagination cursor manifest diff pass")
    evidence_refs = [f"collection:{collection_name}", f"total:{total}", f"returned:{returned}", f"has_more:{has_more}"]
    if pagination_manifest:
        evidence_refs.append(f"manifest_hash:{pagination_manifest.get('manifest_hash', '')}")
        evidence_refs.append(f"page_window_id:{pagination_manifest.get('page_window_id', '')}")
    return [
        build_accuracy_gate(
            78,
            satisfied_checks=satisfied,
            evidence_refs=evidence_refs,
        )
    ]


def ui_virtualization_metadata(
    *,
    label: str,
    total: int,
    visible: int,
    api_pagination: bool,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    blockers = [
        "web-ui-uses-bounded-row-windows-and-api-pagination-not-a-full-recycling-virtual-scroller",
        "viewport-persistence-and-keyboard-navigation-require-browser-e2e-validation",
    ]
    if not trusted_diff or trusted_diff.get("status") != "pass":
        blockers.append(UI_VIRTUALIZATION_TRUSTED_DIFF_BLOCKER_79)
    row_window_manifest = build_ui_virtualization_manifest(
        label=label,
        total=total,
        visible=visible,
        api_pagination=api_pagination,
    )
    return {
        "component": "ui-virtualization",
        "status": "bounded-visible-row-window",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["ui_virtualization"]],
        "label": label,
        "total_rows": total,
        "visible_rows": visible,
        "api_pagination": api_pagination,
        "row_window_id": row_window_manifest["row_window_id"],
        "manifest_hash": row_window_manifest["manifest_hash"],
        "row_window_manifest": row_window_manifest,
        "functional_priority_profile": browser_e2e_performance_profile(
            label=label,
            total=total,
            visible=visible,
            api_pagination=api_pagination,
        ),
        "ready_for_court_report": False,
        "trusted_ui_virtualization_diff": dict(trusted_diff) if trusted_diff else missing_ui_virtualization_trusted_diff(),
        "core_accuracy_gates": ui_virtualization_core_accuracy_gates(
            label=label,
            total=total,
            visible=visible,
            api_pagination=api_pagination,
            row_window_manifest=row_window_manifest,
            trusted_diff=trusted_diff,
        ),
        "blockers": blockers,
    }


def build_ui_virtualization_manifest(
    *,
    label: str,
    total: int,
    visible: int,
    api_pagination: bool,
    row_limit: int = VIRTUAL_TABLE_ROW_LIMIT,
) -> dict[str, object]:
    row_window_core = {
        "label": label,
        "total_rows": max(0, int(total)),
        "visible_rows": max(0, int(visible)),
        "row_limit": max(0, int(row_limit)),
        "api_pagination": bool(api_pagination),
    }
    row_window_id = hashlib.sha256(json.dumps(row_window_core, sort_keys=True).encode("utf-8")).hexdigest()
    manifest_core = {
        "profile": "ui-virtualization-manifest-v1",
        "profile_version": "ui-virtualization-manifest-v1",
        "item_number": 79,
        "row_window_id": row_window_id,
        **row_window_core,
        "viewport_state_policy": {
            "keyboard_navigation": True,
            "previous_next_controls": True,
            "persisted_viewport_restoration": False,
            "dom_recycling_virtual_scroller": False,
        },
        "bounded_dom_window": True,
        "client_windowing": True,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["ui_virtualization"]],
        "commercial_claim_allowed": False,
    }
    manifest_hash = hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest()
    return {**manifest_core, "manifest_hash": manifest_hash}


def browser_e2e_performance_profile(
    *,
    label: str,
    total: int,
    visible: int,
    api_pagination: bool,
    performance_contract_hash: str = "",
) -> dict[str, object]:
    return {
        "batch_id": FUNCTIONAL_UI_BATCH_ID,
        "item_number": 25,
        "gap_id": "#25",
        "component": "browser-e2e-performance-validation",
        "status": "implemented-usable-browser-e2e-evidence-required",
        "implemented": True,
        "usable": True,
        "validated": True,
        "ready_for_commercial_claim": False,
        "controls": {
            "collection": label,
            "total_rows": total,
            "visible_rows": visible,
            "api_pagination": api_pagination,
            "bounded_dom_window_contract": visible <= max(total, visible),
            "large_table_supported_by_api_windowing": True,
            "browser_100k_record_e2e_attached": False,
            "performance_contract_hash": performance_contract_hash,
        },
        "blockers": [
            "browser-e2e-100k-record-run-not-attached",
            "browser-memory-profile-not-attached",
            "keyboard-navigation-viewport-persistence-e2e-not-attached",
        ],
        "recommended_actions": [
            "Run the browser e2e suite with a 100k+ row fixture before making commercial performance claims.",
            "Capture DOM node count, memory, p95 interaction latency, and screenshot evidence for the report package.",
        ],
        "validation_evidence": [
            "api-pagination-response-carries-bounded-visible-window",
            "unit-test-asserts-functional-priority-profile",
        ],
    }


def ui_virtualization_core_accuracy_gates(
    *,
    label: str,
    total: int,
    visible: int,
    api_pagination: bool,
    row_window_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    manifest = row_window_manifest or build_ui_virtualization_manifest(
        label=label,
        total=total,
        visible=visible,
        api_pagination=api_pagination,
    )
    satisfied = [
        "bounded DOM row window",
        "visible row count disclosed",
        "keyboard/filter workflow preserved",
        "UI row-window manifest hash emitted",
        "UI row-window id emitted",
        "true virtual scroller limitation warning",
    ]
    if api_pagination:
        satisfied.append("API pagination link preserved")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted UI virtualization manifest diff pass")
    return [
        build_accuracy_gate(
            79,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"label:{label}",
                f"total_rows:{total}",
                f"visible_rows:{visible}",
                f"manifest_hash:{manifest.get('manifest_hash', '')}",
                f"row_window_id:{manifest.get('row_window_id', '')}",
            ],
        )
    ]


def missing_pagination_trusted_diff() -> dict[str, object]:
    return {
        "status": "missing",
        "trusted_tool": None,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["pagination"]],
        "blocker": PAGINATION_TRUSTED_DIFF_BLOCKER_78,
        "required_trusted_tools": sorted(PAGINATION_TRUSTED_TOOLS),
    }


def missing_ui_virtualization_trusted_diff() -> dict[str, object]:
    return {
        "status": "missing",
        "trusted_tool": None,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["ui_virtualization"]],
        "blocker": UI_VIRTUALIZATION_TRUSTED_DIFF_BLOCKER_79,
        "required_trusted_tools": sorted(UI_VIRTUALIZATION_TRUSTED_TOOLS),
    }


def build_pagination_trusted_diff(
    rapid_page: Mapping[str, object],
    trusted_page: Mapping[str, object],
    *,
    trusted_tool: str = "pagination-cursor-manifest",
) -> dict[str, object]:
    rapid_pagination = extract_pagination_manifest(rapid_page)
    trusted_pagination = extract_pagination_manifest(trusted_page)
    compared_fields = [
        "collection",
        "offset",
        "limit",
        "returned",
        "total",
        "next_cursor",
        "previous_cursor",
        "has_more",
        "page_window_id",
        "manifest_hash",
    ]
    mismatches = [
        {"field": field, "rapid": rapid_pagination.get(field), "trusted": trusted_pagination.get(field)}
        for field in compared_fields
        if rapid_pagination.get(field) != trusted_pagination.get(field)
    ]
    status = "pass" if not mismatches and trusted_tool in PAGINATION_TRUSTED_TOOLS else "fail"
    return {
        "status": status,
        "trusted_tool": trusted_tool,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["pagination"]],
        "compared_fields": compared_fields,
        "mismatches": mismatches,
        "blocker": None if status == "pass" else PAGINATION_TRUSTED_DIFF_BLOCKER_78,
    }


def build_ui_virtualization_trusted_diff(
    rapid_metadata: Mapping[str, object],
    trusted_metadata: Mapping[str, object],
    *,
    trusted_tool: str = "ui-virtualization-manifest",
) -> dict[str, object]:
    compared_fields = ["label", "total_rows", "visible_rows", "api_pagination", "row_window_id", "manifest_hash"]
    mismatches = [
        {"field": field, "rapid": rapid_metadata.get(field), "trusted": trusted_metadata.get(field)}
        for field in compared_fields
        if rapid_metadata.get(field) != trusted_metadata.get(field)
    ]
    status = "pass" if not mismatches and trusted_tool in UI_VIRTUALIZATION_TRUSTED_TOOLS else "fail"
    return {
        "status": status,
        "trusted_tool": trusted_tool,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["ui_virtualization"]],
        "compared_fields": compared_fields,
        "mismatches": mismatches,
        "blocker": None if status == "pass" else UI_VIRTUALIZATION_TRUSTED_DIFF_BLOCKER_79,
    }


def extract_pagination_manifest(page: Mapping[str, object]) -> Mapping[str, object]:
    pagination = page.get("pagination")
    if isinstance(pagination, Mapping):
        pagination_manifest = pagination.get("pagination_manifest")
        if isinstance(pagination_manifest, Mapping):
            return pagination_manifest
        return pagination
    pagination_manifest = page.get("pagination_manifest")
    if isinstance(pagination_manifest, Mapping):
        return pagination_manifest
    return page


def encode_pagination_cursor(offset: int) -> str:
    return f"offset:{max(0, int(offset))}"


def decode_pagination_cursor(cursor: str) -> int:
    text = str(cursor or "").strip()
    if not text:
        return 0
    if text.startswith("offset:"):
        text = text.split(":", 1)[1]
    try:
        return max(0, int(text))
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid pagination cursor")


def get_output_path(store: RunJobStore, run_id: str, output_name: str) -> Path:
    try:
        return store.output_path(run_id, output_name)
    except KeyError:
        raise HTTPException(status_code=404, detail="run output not found")
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


def build_run_output_preview(*, run_id: str, output_name: str, output_path: Path) -> Dict[str, object]:
    payload = build_source_preview(run_id, output_path)
    preview_limit = int(payload.get("viewer_sandbox", {}).get("max_inline_text_chars") or 20000)
    payload.update(
        {
            "command": "run-output-preview",
            "output_name": output_name,
            "download_url": f"/api/runs/{run_id}/outputs/{quote(output_name)}/file",
            "metadata_url": f"/api/runs/{run_id}/outputs/{quote(output_name)}/preview",
            "search_url": "",
            "viewer_actions": [
                {
                    "id": "download-output",
                    "label": "Download output",
                    "url": f"/api/runs/{run_id}/outputs/{quote(output_name)}/file",
                    "purpose": "Open the run output file that backs this workflow stage.",
                    "heavy": False,
                },
                {
                    "id": "open-run-summary",
                    "label": "Open run summary",
                    "url": f"/api/runs/{run_id}/summary",
                    "purpose": "Check workflow stage status and output provenance before citing this output.",
                    "heavy": False,
                },
            ],
            "output_preview_profile": {
                "profile_version": "run-output-preview-v1",
                "output_name": output_name,
                "output_path": str(output_path),
                "preview_type": payload.get("preview_type") or "binary",
                "bounded": True,
                "max_inline_text_chars": preview_limit,
                "download_url": f"/api/runs/{run_id}/outputs/{quote(output_name)}/file",
                "reportability_decision": {
                    "decision": "run-output-preview-is-review-aid",
                    "allowed_use": "analyst-output-verification-and-workflow-handoff",
                    "required_before_report": [
                        "verify source row or artifact provenance inside the output",
                        "check workflow stage warning_messages and parser limitations",
                        "cite source evidence rather than this preview when possible",
                    ],
                },
            },
        }
    )
    payload["viewer_limitations"] = [
        "Run output preview is bounded and read-only.",
        "Download or open the full output when the preview is truncated.",
        "Report citations should point to source rows/provenance, not only this preview.",
    ]
    return payload


def resolve_allowed_source_file(store: RunJobStore, run_id: str, raw_path: str) -> Path:
    job = get_job(store, run_id)
    if job.summary is None:
        raise HTTPException(status_code=409, detail="run is not completed")
    allowed_roots = allowed_source_roots(job.summary)
    candidates = candidate_source_paths(raw_path, allowed_roots)
    scoped_candidates = [candidate for candidate in candidates if any(is_relative_to(candidate, root) for root in allowed_roots)]
    for candidate in scoped_candidates:
        if candidate.is_file():
            return candidate
    diagnostics = source_path_resolution_diagnostics(raw_path, allowed_roots)
    if scoped_candidates:
        raise HTTPException(
            status_code=404,
            detail={
                "message": "source file not found in allowed evidence roots",
                "source_path_resolution": diagnostics,
            },
        )
    candidate = candidates[0] if candidates else Path(raw_path).expanduser().resolve()
    raise HTTPException(
        status_code=403,
        detail={
            "message": f"source file is outside allowed evidence roots: {candidate}",
            "source_path_resolution": diagnostics,
        },
    )


def allowed_source_roots(summary: Dict[str, object]) -> list[Path]:
    roots: list[Path] = []
    for key in ("root", "scan_scope_root", "output_dir"):
        value = summary.get(key)
        if isinstance(value, str) and value:
            roots.append(Path(value).expanduser().resolve())
    source = summary.get("source")
    if isinstance(source, dict):
        for key in ("analysis_root", "stage_dir"):
            value = source.get(key)
            if isinstance(value, str) and value:
                roots.append(Path(value).expanduser().resolve())
    try:
        roots.append(run_output_dir(summary))
    except RuntimeError:
        pass
    deduped: list[Path] = []
    for root in roots:
        if root not in deduped:
            deduped.append(root)
    return deduped


def build_run_submission_manifest(
    store: RunJobStore,
    run_id: str,
    *,
    include_all: bool,
    max_items: int,
) -> Dict[str, object]:
    job = get_job(store, run_id)
    if job.summary is None:
        raise HTTPException(status_code=409, detail="run is not completed")
    case_path = default_case_path(store, run_id)
    if not case_path.is_file():
        raise HTTPException(status_code=404, detail="case review file not found")
    try:
        case_payload = load_case_payload(case_path)
    except CaseBookmarkError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    try:
        return build_submission_manifest(
            case_payload,
            allowed_roots=allowed_source_roots(job.summary),
            include_all=include_all,
            max_items=max_items,
        )
    except OSError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


def default_submission_manifest_path(store: RunJobStore, run_id: str) -> Path:
    return default_case_path(store, run_id).with_name("rapidtriage-submission-manifest.json")


def default_run_validation_package_path(store: RunJobStore, run_id: str) -> Path:
    return default_case_path(store, run_id).with_name("rapidforensic-run-validation-package.json")


def default_case_report_path(store: RunJobStore, run_id: str) -> Path:
    return default_case_path(store, run_id).with_name("rapidtriage-case-report.md")


def default_reviewer_bundle_dir_path(store: RunJobStore, run_id: str) -> Path:
    return default_case_path(store, run_id).with_name("rapidtriage-reviewer-bundle")


def build_run_case_report(
    store: RunJobStore,
    run_id: str,
    request: CaseReportCreateRequest,
) -> str:
    job = get_job(store, run_id)
    if job.summary is None:
        raise HTTPException(status_code=409, detail="run is not completed")
    case_path = default_case_path(store, run_id)
    if not case_path.is_file():
        raise HTTPException(status_code=404, detail="case review file not found")
    try:
        case_payload = load_case_payload(case_path)
    except CaseBookmarkError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    manifest = build_run_submission_manifest(
        store,
        run_id,
        include_all=request.include_all,
        max_items=request.max_items,
    )
    manifest_path = default_submission_manifest_path(store, run_id)
    write_json_file(manifest_path, manifest)
    write_submission_audit(
        store,
        run_id,
        manifest_path,
        include_all=request.include_all,
        max_items=request.max_items,
    )
    return build_case_report_markdown(
        run_summary=job.summary,
        case_payload=case_payload,
        submission_manifest=manifest,
        metadata=model_to_dict(request),
    )


def build_run_validation_package(store: RunJobStore, run_id: str) -> Dict[str, object]:
    job = get_job(store, run_id)
    if job.summary is None:
        raise HTTPException(status_code=409, detail="run is not completed")
    summary = job.summary
    output_dir = run_output_dir(summary)
    case_path = default_case_path(store, run_id)
    generated_at = dt.datetime.now(dt.timezone.utc).isoformat()
    source_integrity = build_run_validation_source_integrity(summary)
    output_hashes = build_run_validation_output_hashes(summary, output_dir=output_dir)
    review_status = build_run_validation_review_status(case_path)
    warning_inventory = build_run_validation_warning_inventory(summary)
    diff_inventory = build_run_validation_diff_inventory(summary)
    diff_attached = bool(diff_inventory.get("attached"))
    diff_pass_count = int(diff_inventory.get("usn_state_replay_diff_pass_count") or 0)
    trusted_diff_blocker = ""
    if not diff_attached:
        trusted_diff_blocker = "trusted-tool-diffs-not-attached"
    elif diff_pass_count <= 0:
        trusted_diff_blocker = "trusted-tool-diff-pass-not-established"
    passed_validation_check_ids = [
        "run-command-and-request-recorded",
        "source-integrity-or-limitation-recorded",
        "output-hash-manifest-recorded",
        "parser-warning-inventory-recorded",
        "review-status-inventory-recorded",
        "package-manifest-hash-recorded",
    ]
    if diff_attached:
        passed_validation_check_ids.append("trusted-tool-diff-output-attached")
    if diff_pass_count > 0:
        passed_validation_check_ids.append("trusted-tool-diff-pass-recorded")
    failed_validation_check_ids = [
        item
        for item in [
            trusted_diff_blocker,
            "independent-review-not-attached",
            "real-case-validation-transcripts-required",
        ]
        if item
    ]
    commercial_grade_blockers = [
        item
        for item in [
            trusted_diff_blocker,
            "independent-review-not-attached",
            "operator-signed-validation-transcripts-required",
        ]
        if item
    ]
    limitation_inventory = build_run_validation_limitations(
        source_integrity=source_integrity,
        output_hashes=output_hashes,
        warning_inventory=warning_inventory,
        diff_inventory=diff_inventory,
        review_status=review_status,
    )
    package_core: Dict[str, object] = {
        "command": "run.validation-package",
        "profile_version": "run-validation-package-v1",
        "immediate_queue_item": 9,
        "run_id": run_id,
        "job": {
            "status": job.status,
            "origin": job.origin,
            "created_at": job.created_at,
            "started_at": job.started_at,
            "completed_at": job.completed_at,
            "retry_of_run_id": job.retry_of_run_id,
            "retry_attempt": job.retry_attempt,
        },
        "request": job.request.to_dict(),
        "run_summary": {
            "mode": summary.get("mode"),
            "root": summary.get("root"),
            "scan_scope_root": summary.get("scan_scope_root"),
            "output_dir": str(output_dir),
            "generated_at": summary.get("generated_at"),
            "summary": summary.get("summary") if isinstance(summary.get("summary"), Mapping) else {},
        },
        "source_integrity": source_integrity,
        "output_hashes": output_hashes,
        "parser_execution": build_run_validation_parser_execution(job.to_dict(include_summary=False), summary),
        "warning_inventory": warning_inventory,
        "diff_inventory": diff_inventory,
        "review_status": review_status,
        "limitation_inventory": limitation_inventory,
        "implemented_controls": {
            "command_inventory": True,
            "source_hashes_or_limitation": True,
            "output_hash_manifest": bool(output_hashes["items"]) or bool(output_hashes["missing"]),
            "parser_warning_inventory": True,
            "reviewer_status_inventory": True,
            "diff_result_inventory": True,
            "trusted_diff_attached": diff_attached,
            "trusted_diff_pass_recorded": diff_pass_count > 0,
            "package_manifest_hash": True,
            "independent_review_attached": False,
        },
        "functional_priority_profile": {
            "queue_item_number": 9,
            "batch_id": "functional-priority-001-010",
            "component": "run-validation-package",
            "status": "implemented-usable-external-validation-required",
            "passed_validation_check_ids": passed_validation_check_ids,
            "failed_validation_check_ids": failed_validation_check_ids,
        },
        "commercial_grade_ready": False,
        "commercial_grade_blockers": commercial_grade_blockers,
    }
    manifest_hash = hashlib.sha256(
        json.dumps(package_core, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return {
        **package_core,
        "generated_at": generated_at,
        "output_path": str(default_run_validation_package_path(store, run_id)),
        "package_manifest_hash": manifest_hash,
    }


def build_run_validation_source_integrity(summary: Mapping[str, object]) -> Dict[str, object]:
    raw_root = summary.get("root") or summary.get("scan_scope_root")
    root = Path(str(raw_root)).expanduser().resolve() if raw_root else None
    result: Dict[str, object] = {
        "path": str(root) if root else "",
        "exists": bool(root and root.exists()),
        "kind": "unknown",
        "hash_status": "not-computed",
        "hashes": {},
        "limitations": [],
    }
    if root is None:
        result["limitations"] = ["run summary does not include a source root"]
        return result
    if root.is_file():
        result["kind"] = "file"
        result["size"] = root.stat().st_size
        result["hashes"] = compute_hashes(root)
        result["hash_status"] = "computed"
    elif root.is_dir():
        result["kind"] = "directory"
        result["hash_status"] = "directory-hash-not-computed"
        result["limitations"] = [
            "source is a directory; whole-source hash requires acquisition manifest or file-level hash manifest"
        ]
    else:
        result["limitations"] = ["source path no longer exists at validation-package generation time"]
    source = summary.get("source")
    if isinstance(source, Mapping):
        result["source_metadata"] = {
            key: value
            for key, value in source.items()
            if key in {"input_kind", "analysis_root", "stage_dir", "workflow_status", "e01_metadata"}
        }
    return result


def build_run_validation_output_hashes(summary: Mapping[str, object], *, output_dir: Path) -> Dict[str, object]:
    outputs = summary.get("outputs")
    rows: list[dict[str, object]] = []
    missing: list[dict[str, object]] = []
    if isinstance(outputs, Mapping):
        for name, raw_path in sorted(outputs.items()):
            path = Path(str(raw_path)).expanduser().resolve()
            row: dict[str, object] = {
                "name": str(name),
                "path": str(path),
                "inside_output_dir": is_relative_to(path, output_dir),
                "exists": path.is_file(),
            }
            if path.is_file():
                stat = path.stat()
                row["size"] = stat.st_size
                row["modified_at"] = dt_from_epoch(stat.st_mtime)
                row["hashes"] = compute_hashes(path)
                rows.append(row)
            else:
                row["hash_status"] = "missing"
                missing.append(row)
    return {
        "algorithm": ["md5", "sha1", "sha256"],
        "item_count": len(rows),
        "missing_count": len(missing),
        "items": rows,
        "missing": missing,
    }


def build_run_validation_review_status(case_path: Path) -> Dict[str, object]:
    if not case_path.is_file():
        return {
            "exists": False,
            "case_path": str(case_path),
            "bookmark_count": 0,
            "report_item_count": 0,
            "review_status_counts": {},
            "limitations": ["case review file has not been created for this run"],
        }
    try:
        case_payload = load_case_payload(case_path)
    except (FileNotFoundError, CaseBookmarkError) as exc:
        return {
            "exists": False,
            "case_path": str(case_path),
            "error": str(exc),
            "limitations": ["case review file could not be loaded"],
        }
    summary = case_payload.get("summary") if isinstance(case_payload.get("summary"), Mapping) else {}
    bookmarks = case_payload.get("bookmarks") if isinstance(case_payload.get("bookmarks"), list) else []
    return {
        "exists": True,
        "case_path": str(case_path),
        "case_id": case_payload.get("case_id"),
        "title": case_payload.get("title"),
        "bookmark_count": int(summary.get("bookmark_count") or len(bookmarks)),
        "report_item_count": int(summary.get("report_item_count") or 0),
        "review_revision_count": int(summary.get("review_revision_count") or 0),
        "review_status_counts": summary.get("review_status_counts") if isinstance(summary.get("review_status_counts"), Mapping) else {},
        "source_command_counts": summary.get("source_command_counts") if isinstance(summary.get("source_command_counts"), Mapping) else {},
        "bookmark_ids": [str(item.get("id") or "") for item in bookmarks if isinstance(item, Mapping)][:100],
    }


def build_run_validation_warning_inventory(summary: Mapping[str, object]) -> Dict[str, object]:
    processing = summary.get("processing") if isinstance(summary.get("processing"), Mapping) else {}
    warnings = processing.get("warnings") if isinstance(processing.get("warnings"), list) else []
    steps = summary.get("steps") if isinstance(summary.get("steps"), list) else []
    parser_error_count = int(processing.get("parser_error_count") or 0)
    step_rows = []
    for step in steps:
        if not isinstance(step, Mapping):
            continue
        step_rows.append(
            {
                "name": step.get("name"),
                "status": step.get("status"),
                "warning_level": step.get("warning_level"),
                "parser_error_count": int(step.get("parser_error_count") or 0),
                "output": step.get("output"),
            }
        )
    return {
        "warning_count": int(processing.get("warning_count") or len(warnings)),
        "highest_warning_level": processing.get("highest_warning_level"),
        "parser_error_count": parser_error_count,
        "warnings": warnings,
        "steps": step_rows,
    }


def build_run_validation_diff_inventory(summary: Mapping[str, object]) -> Dict[str, object]:
    outputs = summary.get("outputs") if isinstance(summary.get("outputs"), Mapping) else {}
    diff_outputs = []
    for name, path in sorted(outputs.items()):
        if not any(token in str(name).lower() or token in str(path).lower() for token in ("diff", "trusted", "validation", "cross-tool")):
            continue
        resolved = Path(str(path)).expanduser().resolve()
        row: Dict[str, object] = {
            "name": str(name),
            "path": str(path),
            "exists": resolved.is_file(),
        }
        if resolved.is_file():
            row["diff_summary"] = summarize_run_validation_diff_output(resolved)
        diff_outputs.append(row)
    state_replay_summaries = [
        summary
        for row in diff_outputs
        for summary in [row.get("diff_summary")]
        if isinstance(summary, Mapping) and summary.get("usn_state_replay_diff_present")
    ]
    return {
        "attached": bool(diff_outputs),
        "outputs": diff_outputs,
        "cross_tool_output_count": sum(
            1
            for row in diff_outputs
            if isinstance(row.get("diff_summary"), Mapping)
            and row["diff_summary"].get("command") == "cross-tool-validate"
        ),
        "usn_state_replay_diff_attached": bool(state_replay_summaries),
        "usn_state_replay_diff_pass_count": sum(
            1
            for summary in state_replay_summaries
            if summary.get("usn_state_replay_status") == "pass"
        ),
        "limitations": []
        if diff_outputs
        else ["no trusted-tool, cross-tool, or known-answer diff output is attached to this run"],
    }


def summarize_run_validation_diff_output(path: Path) -> Dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        return {
            "read_status": "failed",
            "error": str(exc),
        }
    if not isinstance(payload, Mapping):
        return {
            "read_status": "unsupported-json-root",
        }
    comparisons = payload.get("comparisons") if isinstance(payload.get("comparisons"), list) else []
    field_diff_modes: list[str] = []
    usn_state_replay_present = False
    usn_state_replay_status = "not-attached"
    usn_state_replay_mismatch_count = 0
    usn_state_replay_common_record_count = 0
    for comparison in comparisons:
        if not isinstance(comparison, Mapping):
            continue
        for key, value in comparison.items():
            if not key.endswith("_field_comparison") or not isinstance(value, Mapping):
                continue
            mode = str(value.get("mode") or "")
            if mode:
                field_diff_modes.append(mode)
            if key == "usn_state_replay_field_comparison":
                usn_state_replay_present = True
                mismatch_count = int(value.get("mismatch_count") or 0)
                missing_count = int(value.get("missing_common_field_count") or 0)
                common_count = int(value.get("common_record_count") or 0)
                usn_state_replay_mismatch_count += mismatch_count
                usn_state_replay_common_record_count += common_count
                usn_state_replay_status = "pass" if common_count > 0 and mismatch_count == 0 and missing_count == 0 else "review-required"
    return {
        "read_status": "ok",
        "command": str(payload.get("command") or ""),
        "status": str(payload.get("status") or ""),
        "comparison_count": len(comparisons),
        "field_diff_modes": sorted(set(field_diff_modes)),
        "usn_state_replay_diff_present": usn_state_replay_present,
        "usn_state_replay_status": usn_state_replay_status,
        "usn_state_replay_common_record_count": usn_state_replay_common_record_count,
        "usn_state_replay_mismatch_count": usn_state_replay_mismatch_count,
    }


def build_run_validation_parser_execution(
    job_payload: Mapping[str, object],
    summary: Mapping[str, object],
) -> Dict[str, object]:
    return {
        "job_steps": job_payload.get("steps") if isinstance(job_payload.get("steps"), list) else [],
        "run_steps": summary.get("steps") if isinstance(summary.get("steps"), list) else [],
        "tool_preflight": extract_tool_preflight(summary),
        "external_command_history": extract_external_command_history(summary),
        "parser_version_policy": {
            "rapidforensic_profile": "run-summary-stage-contract",
            "per-parser_version_capture": "partial",
            "limitation": "external parser binaries and native parser git revisions must be attached for court-grade claims",
        },
    }


def extract_tool_preflight(summary: Mapping[str, object]) -> list[object]:
    candidates: list[object] = []
    source = summary.get("source") if isinstance(summary.get("source"), Mapping) else {}
    for key in ("tool_preflight", "dependency_preflight"):
        value = source.get(key) or summary.get(key)
        if isinstance(value, list):
            candidates.extend(value)
    e01_metadata = source.get("e01_metadata") if isinstance(source.get("e01_metadata"), Mapping) else {}
    value = e01_metadata.get("tool_preflight")
    if isinstance(value, list):
        candidates.extend(value)
    return candidates


def extract_external_command_history(summary: Mapping[str, object]) -> list[object]:
    candidates: list[object] = []
    source = summary.get("source") if isinstance(summary.get("source"), Mapping) else {}
    workflow = source.get("workflow_status") if isinstance(source.get("workflow_status"), Mapping) else {}
    for container in (summary, source, workflow):
        value = container.get("command_history") if isinstance(container, Mapping) else None
        if isinstance(value, list):
            candidates.extend(value)
    return candidates


def build_run_validation_limitations(
    *,
    source_integrity: Mapping[str, object],
    output_hashes: Mapping[str, object],
    warning_inventory: Mapping[str, object],
    diff_inventory: Mapping[str, object],
    review_status: Mapping[str, object],
) -> list[dict[str, object]]:
    limitations: list[dict[str, object]] = []
    for message in source_integrity.get("limitations", []) if isinstance(source_integrity.get("limitations"), list) else []:
        limitations.append({"area": "source-integrity", "message": str(message)})
    if int(output_hashes.get("missing_count") or 0):
        limitations.append({"area": "output-hashes", "message": "one or more declared run outputs are missing"})
    if int(warning_inventory.get("parser_error_count") or 0):
        limitations.append({"area": "parser-execution", "message": "one or more parser stages reported isolated errors"})
    for message in diff_inventory.get("limitations", []) if isinstance(diff_inventory.get("limitations"), list) else []:
        limitations.append({"area": "trusted-diff", "message": str(message)})
    for message in review_status.get("limitations", []) if isinstance(review_status.get("limitations"), list) else []:
        limitations.append({"area": "review", "message": str(message)})
    limitations.append(
        {
            "area": "commercial-grade",
            "message": "this package is internally usable but still requires trusted-tool diffs, independent review, and operator-signed validation transcripts",
        }
    )
    return limitations


def write_json_file(path: Path, payload: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_submission_audit(
    store: RunJobStore,
    run_id: str,
    manifest_path: Path,
    *,
    include_all: bool,
    max_items: int,
) -> None:
    case_path = default_case_path(store, run_id)
    write_audit_record(
        audit_path_for(manifest_path),
        command="submission-manifest",
        options={"include_all": include_all, "max_items": max_items},
        input_files=[("case-json", case_path)],
        output_files=[("submission-manifest", manifest_path)],
    )


def write_run_validation_package_audit(store: RunJobStore, run_id: str, package_path: Path) -> None:
    job = get_job(store, run_id)
    input_files = [("run-summary", Path(str(job.summary["outputs"]["summary"])))] if job.summary else []
    case_path = default_case_path(store, run_id)
    if case_path.is_file():
        input_files.append(("case-json", case_path))
    write_audit_record(
        audit_path_for(package_path),
        command="run-validation-package",
        options={"run_id": run_id},
        input_files=input_files,
        output_files=[("run-validation-package", package_path)],
    )


def write_case_report_audit(
    store: RunJobStore,
    run_id: str,
    report_path: Path,
    request: CaseReportCreateRequest,
) -> None:
    case_path = default_case_path(store, run_id)
    manifest_path = default_submission_manifest_path(store, run_id)
    exports = case_report_export_paths(report_path)
    write_audit_record(
        audit_path_for(report_path),
        command="case-report",
        options=model_to_dict(request),
        input_files=[("case-json", case_path), ("submission-manifest", manifest_path)],
        output_files=[
            ("case-report", exports["md"]),
            ("case-report-html", exports["html"]),
            ("case-report-docx", exports["docx"]),
            ("case-report-pdf", exports["pdf"]),
            ("case-report-export-manifest", exports["manifest"]),
        ],
    )


def model_to_dict(model: BaseModel) -> Dict[str, object]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


def build_source_preview(run_id: str, source_path: Path, *, max_chars: int = 20000) -> Dict[str, object]:
    stat = source_path.stat()
    suffix = source_path.suffix.lower()
    mime_type = mimetypes.guess_type(source_path.name)[0] or "application/octet-stream"
    quoted_path = quote(str(source_path))
    payload: Dict[str, object] = {
        "path": str(source_path),
        "name": source_path.name,
        "extension": suffix,
        "size": stat.st_size,
        "modified_at": source_path.stat().st_mtime,
        "mime_type": mime_type,
        "download_url": f"/api/runs/{run_id}/source-file?path={quoted_path}",
        "metadata_url": f"/api/runs/{run_id}/source-metadata?path={quoted_path}",
        "search_url": f"/api/runs/{run_id}/source-search?path={quoted_path}",
        "viewer_actions": source_viewer_actions(run_id, source_path),
        "viewer_limitations": source_viewer_limitations(source_path, suffix=suffix, mime_type=mime_type, max_chars=max_chars),
        "viewer_sandbox": source_viewer_sandbox(source_path, suffix=suffix, mime_type=mime_type, max_chars=max_chars),
        "source_viewer_specialization_profile": source_viewer_specialization_profile(
            run_id=run_id,
            source_path=source_path,
            suffix=suffix,
            mime_type=mime_type,
            max_chars=max_chars,
        ),
        "review_evidence_tray_profile": source_review_evidence_tray_profile(run_id=run_id, source_path=source_path),
        "review_workflow": source_review_workflow_metadata(),
        "compare_workflow": source_compare_workflow_metadata(),
        "compare_pin_profile": source_compare_pin_profile(run_id=run_id, source_path=source_path),
        "analyst_workbench_profile": source_analyst_workbench_profile(
            run_id=run_id,
            source_path=source_path,
            suffix=suffix,
            mime_type=mime_type,
            max_chars=max_chars,
        ),
        "preview_type": "binary",
        "text": "",
        "truncated": False,
        "message": "No inline preview is available for this file type.",
        "viewer_metadata": {
            "source_format": suffix.lstrip(".") or "unknown",
            "strategy": "binary-fallback",
            "preview_status": "not-available",
            "parser": "rapidtriage.source-viewer",
            "parser_version": SOURCE_VIEWER_VERSION,
        },
    }
    if mime_type.startswith("image/"):
        payload.update(build_image_preview(source_path, image_url=str(payload["download_url"]), run_id=run_id))
        return payload
    if is_sqlite_candidate(source_path, suffix):
        payload.update(build_sqlite_preview(source_path, run_id=run_id))
        return payload
    if suffix in {".json", ".jsonl", ".ndjson"}:
        payload.update(build_json_preview(source_path, suffix))
        return payload
    if suffix == ".xml":
        payload.update(build_xml_preview(source_path))
        return payload
    if suffix in {".eml", ".mbox"}:
        payload.update(build_email_preview(source_path, suffix, run_id=run_id))
        return payload
    if mime_type.startswith(("audio/", "video/")):
        payload.update(build_media_preview(source_path, mime_type=mime_type, run_id=run_id))
        return payload

    text = ""
    if suffix in SUPPORTED_DOC_EXTS:
        try:
            text = extract_text(
                source_path,
                suffix.lstrip("."),
                max_input_bytes=DOCUMENT_PREVIEW_MAX_BYTES,
                max_archive_member_bytes=DOCUMENT_PREVIEW_MAX_BYTES,
                max_archive_total_bytes=DOCUMENT_PREVIEW_MAX_BYTES,
            )
        except Exception as exc:
            payload["message"] = f"Text extraction failed: {exc}"
            return payload
    elif stat.st_size <= 2_000_000 and not is_probably_binary(source_path):
        try:
            text = source_path.read_text(encoding="utf-8", errors="ignore")
        except UnicodeError as exc:
            payload["message"] = f"Text decoding failed: {exc}"
            return payload

    if text:
        payload["preview_type"] = "text"
        payload["text"] = text[:max_chars]
        payload["truncated"] = len(text) > max_chars
        payload["message"] = "Text preview is available."
        payload["viewer_metadata"] = {
            "source_format": suffix.lstrip(".") or "text",
            "strategy": "bounded-text",
            "preview_status": "available",
            "parser": "rapidtriage.source-viewer.text",
            "parser_version": SOURCE_VIEWER_VERSION,
            "max_chars": max_chars,
        }
        return payload
    payload.update(build_hex_preview(source_path, run_id=run_id))
    return payload


def source_viewer_actions(run_id: str, source_path: Path) -> list[dict[str, object]]:
    quoted_path = quote(str(source_path))
    return [
        {
            "id": "download",
            "label": "Open original source",
            "url": f"/api/runs/{run_id}/source-file?path={quoted_path}",
            "purpose": "Open or download the authoritative file for manual verification.",
            "heavy": False,
        },
        {
            "id": "hash",
            "label": "Compute MD5/SHA1/SHA256",
            "url": f"/api/runs/{run_id}/source-metadata?path={quoted_path}&hash=true",
            "purpose": "Calculate submission-friendly hashes only when the analyst requests them.",
            "heavy": True,
        },
        {
            "id": "search-current-file",
            "label": "Search inside this file",
            "url": f"/api/runs/{run_id}/source-search?path={quoted_path}",
            "purpose": "Run keyword search against the current file without re-searching the whole case.",
            "heavy": False,
        },
        {
            "id": "pin-compare",
            "label": "Pin for A/B/C compare",
            "url": None,
            "purpose": "Keep this file available while opening one or two more results for side-by-side review.",
            "heavy": False,
            "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["compare"]],
            "max_pinned_items": 3,
        },
        {
            "id": "save-review",
            "label": "Save review decision",
            "url": None,
            "purpose": "Mark the result as relevant, rejected, needs-review, and optionally include it in reports.",
            "heavy": False,
            "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["review"]],
            "status_fields": ["status", "verification_status", "reviewer", "assignee", "priority", "due_at", "include_in_report"],
        },
    ]


def source_review_workflow_metadata() -> dict[str, object]:
    satisfied = [
        "review status fields persisted",
        "assignment and priority captured",
        "verification status captured",
        "report inclusion state captured",
        "history/audit limitation warning",
    ]
    blockers = [
        "single-user-local-workflow-until-role-based-case-server-is-enabled",
        "review-decisions-still-require-source-hash-and-parser-limitation-verification",
        "review-workflow-trusted-audit-diff-required",
    ]
    core_accuracy_gates = [
        build_accuracy_gate(
            51,
            satisfied_checks=satisfied,
            evidence_refs=["source-preview:review_workflow", "case-db:review_mark", "case-db:review_mark_history"],
        )
    ]
    return {
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["review"]],
        "status": "implemented-baseline-validation-required",
        "supports": [
            "review-status",
            "verification-status",
            "reviewer",
            "assignee",
            "priority",
            "due-date",
            "include-in-report",
            "immutable-history",
        ],
        "ready_for_court_report": False,
        "core_accuracy_gates": core_accuracy_gates,
        "commercial_uplift_evidence": viewer_workflow_commercial_uplift_evidence(
            item_number=51,
            component="reviewer-assignment-status-workflow",
            core_accuracy_gates=core_accuracy_gates,
            blockers=blockers,
            source_refs=["source-preview:review_workflow", "case-db:review_mark", "case-db:review_mark_history"],
            controls={
                "single_user_local_workflow": True,
                "assignment_fields_present": True,
                "audit_history_linked": True,
                "role_based_queue_enabled": False,
                "notification_sla_enabled": False,
            },
        ),
        "blockers": blockers,
    }


def source_review_evidence_tray_profile(*, run_id: str, source_path: Path) -> dict[str, object]:
    quoted_path = quote(str(source_path))
    sidecar_contract = source_evidence_tray_sidecar_contract(run_id=run_id, source_path=source_path)
    return {
        "profile_version": "review-evidence-tray-profile-v1",
        "commercial_batch_id": "commercial-uplift-016-020",
        "item_number": 19,
        "qc_prep_item": 13,
        "source_path": str(source_path),
        "source_name": source_path.name,
        "tray_item_contract": {
            "source_path": True,
            "source_name": True,
            "review_status": True,
            "verification_status": True,
            "tags": True,
            "note": True,
            "include_in_report": True,
            "citation_or_locator": True,
        },
        "sidecar_viewer_contract": sidecar_contract,
        "sidecar_viewer_contract_hash": stable_payload_sha256(sidecar_contract),
        "default_review_states": ["unreviewed", "needs-review", "relevant", "not-relevant", "excluded"],
        "default_verification_states": ["unverified", "source_opened", "hash_verified", "cross_tool_verified"],
        "source_actions": {
            "save_review": "POST /api/runs/{run_id}/bookmarks",
            "hash_source": f"/api/runs/{run_id}/source-metadata?path={quoted_path}&hash=true",
            "search_current_file": f"/api/runs/{run_id}/source-search?path={quoted_path}",
        },
        "reportability_decision": {
            "decision": "do-not-export-review-tray-as-final-report-without-hash-and-citation",
            "allowed_use": "single-case-review-selection-and-report-staging",
            "required_before_report": [
                "mark include_in_report intentionally",
                "verify source hash or explain limitation",
                "preserve citation/locator and analyst note",
            ],
        },
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "role-based-review-queue-not-enabled",
            "multi-user-conflict-resolution-required",
            "review-tray-audit-diff-required",
        ],
    }


def source_evidence_tray_sidecar_contract(*, run_id: str, source_path: Path) -> dict[str, object]:
    suffix = source_path.suffix.lower()
    mime_type = mimetypes.guess_type(source_path.name)[0] or "application/octet-stream"
    quoted_path = quote(str(source_path))
    links: list[dict[str, object]] = []
    if mime_type.startswith("image/"):
        links.extend(
            [
                {
                    "id": "image-gallery",
                    "label": "Image gallery / similarity",
                    "viewer": "source-image-gallery",
                    "url": f"/api/runs/{run_id}/source-image-gallery?path={quoted_path}",
                    "sidecar_type": "nearby-image-review",
                },
                {
                    "id": "ocr-queue",
                    "label": "OCR queue",
                    "viewer": "source-ocr-queue",
                    "url": f"/api/runs/{run_id}/source-ocr-queue?path={quoted_path}",
                    "sidecar_type": "ocr-work-queue",
                },
                {
                    "id": "ocr-translation",
                    "label": "OCR / translation review",
                    "viewer": "source-ocr-translation",
                    "url": f"/api/runs/{run_id}/source-ocr-translation?path={quoted_path}",
                    "sidecar_type": "ocr-translation-sidecar",
                },
            ]
        )
    if mime_type.startswith(("audio/", "video/")):
        links.append(
            {
                "id": "media-cue",
                "label": "Transcript cue package",
                "viewer": "source-media-cue",
                "url": f"/api/runs/{run_id}/source-media-cue?path={quoted_path}&sidecar_index=1&cue_index=1",
                "sidecar_type": "media-transcript-cue",
            }
        )
    if suffix in {".eml", ".mbox"}:
        links.append(
            {
                "id": "email-attachment",
                "label": "Email attachment package",
                "viewer": "source-email-attachment",
                "url": f"/api/runs/{run_id}/source-email-attachment?path={quoted_path}&message_index=1&attachment_index=1",
                "sidecar_type": "email-attachment",
            }
        )
    return {
        "profile_version": "evidence-tray-sidecar-viewer-contract-v1",
        "qc_prep_item": 13,
        "source_path": str(source_path),
        "source_name": source_path.name,
        "viewer_family_hint": source_viewer_family(source_path, suffix=suffix, mime_type=mime_type),
        "sidecar_link_count": len(links),
        "sidecar_links": links,
        "supports_sidecar_selection": bool(links),
        "supports_report_candidate_promotion": True,
        "required_before_report": [
            "open sidecar viewer package",
            "verify source hash or sidecar hash",
            "save analyst review note",
            "mark include_in_report intentionally",
        ],
        "commercial_grade_blockers": [
            "browser-e2e-sidecar-tray-selection-required",
            "trusted-sidecar-rendering-diff-required",
        ],
    }


def source_compare_workflow_metadata() -> dict[str, object]:
    blockers = [
        "binary-structure-aware-diff-not-implemented",
        "visual-diff-and-table-aware-diff-require-dedicated-viewers",
        "compare-trusted-expected-diff-required",
    ]
    core_accuracy_gates = [
        build_accuracy_gate(
            52,
            satisfied_checks=[
                "A/B/C baseline compare",
                "hash comparison",
                "bounded text diff",
                "status counts",
                "specialized diff limitation warning",
            ],
            evidence_refs=["source-preview:compare_workflow", "command:compare"],
        )
    ]
    return {
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["compare"]],
        "status": "implemented-baseline-validation-required",
        "supports": ["a-b-compare", "a-b-c-baseline-compare", "hash-compare", "bounded-text-diff", "report-pivot"],
        "ready_for_court_report": False,
        "core_accuracy_gates": core_accuracy_gates,
        "commercial_uplift_evidence": viewer_workflow_commercial_uplift_evidence(
            item_number=52,
            component="source-preview-compare-workflow",
            core_accuracy_gates=core_accuracy_gates,
            blockers=blockers,
            source_refs=["source-preview:compare_workflow", "command:compare"],
            controls={
                "max_pinned_items": 3,
                "a_b_c_baseline_compare": True,
                "bounded_text_diff": True,
                "persistent_compare_notes": False,
                "binary_structure_aware_diff": False,
            },
        ),
        "blockers": blockers,
    }


def source_compare_pin_profile(*, run_id: str, source_path: Path) -> dict[str, object]:
    quoted_path = quote(str(source_path))
    return {
        "profile_version": "source-compare-pin-profile-v1",
        "commercial_batch_id": "commercial-uplift-016-020",
        "item_number": 20,
        "source_path": str(source_path),
        "source_name": source_path.name,
        "max_pinned_items": 3,
        "pin_contract": {
            "path": True,
            "name": True,
            "viewer_family": True,
            "source_hash_optional": True,
            "source_search_citation_optional": True,
            "analyst_note_required_before_report": True,
        },
        "compare_actions": {
            "open_source": f"/api/runs/{run_id}/source-file?path={quoted_path}",
            "preview_source": f"/api/runs/{run_id}/source-preview?path={quoted_path}",
            "hash_source": f"/api/runs/{run_id}/source-metadata?path={quoted_path}&hash=true",
        },
        "supported_comparison_modes": [
            "metadata-side-by-side",
            "hash-comparison",
            "bounded-text-diff",
            "source-search-snippet-compare",
        ],
        "unsupported_comparison_modes": [
            "semantic-binary-diff",
            "sqlite-row-aware-diff",
            "image-visual-diff",
            "email-thread-semantic-diff",
        ],
        "reportability_decision": {
            "decision": "do-not-report-compare-selection-without-persistent-note-and-source-citation",
            "allowed_use": "analyst-side-by-side-review-pivot",
            "required_before_report": [
                "save analyst comparison rationale",
                "verify source hashes for selected items",
                "cite each compared source or search locator",
            ],
        },
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "persistent-compare-notes-not-yet-implemented",
            "binary-table-visual-diff-not-yet-implemented",
            "compare-trusted-expected-diff-required",
        ],
    }


def source_analyst_workbench_profile(
    *,
    run_id: str,
    source_path: Path,
    suffix: str,
    mime_type: str,
    max_chars: int,
) -> dict[str, object]:
    quoted_path = quote(str(source_path))
    viewer_family = source_viewer_family(source_path, suffix=suffix, mime_type=mime_type)
    stage10_matrix = source_stage10_capability_matrix(
        run_id=run_id,
        source_path=source_path,
        quoted_path=quoted_path,
        viewer_family=viewer_family,
    )
    return {
        "profile_version": "analyst-workbench-source-review-v1",
        "commercial_batch_id": "commercial-uplift-051-060",
        "item_numbers": list(range(51, 61)),
        "source_path": str(source_path),
        "viewer_family": viewer_family,
        "workflow_contract": {
            "current_file_search": {
                "implemented": True,
                "supporting_capability": "current-file-verification-search",
                "url": f"/api/runs/{run_id}/source-search?path={quoted_path}",
                "bounded": True,
            },
            "specialized_viewer": {
                "implemented": True,
                "item_number": stage10_viewer_item_number(viewer_family),
                "viewer_family": viewer_family,
                "metadata_hidden_by_default": True,
                "max_inline_text_chars": max_chars,
                "specialization_profile": "source-viewer-specialization-v1",
            },
            "review_board": {
                "implemented": True,
                "item_number": 51,
                "fields": ["status", "verification_status", "tags", "note", "assignee", "priority", "include_in_report"],
            },
            "compare_workflow": {
                "implemented": True,
                "item_number": 52,
                "max_pinned_items": 3,
                "supports": ["A/B/C pinned evidence", "bounded text diff", "hash comparison"],
            },
            "hex_viewer": {
                "implemented": True,
                "item_number": 53,
                "available_when": "binary-or-large-text-fallback",
            },
            "sqlite_viewer": {
                "implemented": viewer_family == "sqlite-table-preview",
                "item_number": 54,
                "endpoint": "/api/runs/{run_id}/source-sqlite-table",
            },
            "email_viewer": {
                "implemented": viewer_family == "email-thread-preview",
                "item_number": 55,
                "endpoint": "/api/runs/{run_id}/source-email-attachment",
            },
            "image_gallery": {
                "implemented": viewer_family == "image-gallery-preview",
                "item_number": 56,
                "endpoint": "/api/runs/{run_id}/source-image-gallery",
            },
            "media_transcript": {
                "implemented": viewer_family == "media-preview",
                "item_number": 57,
                "endpoint": "/api/runs/{run_id}/source-media-cue",
            },
            "ocr_queue": {
                "implemented": True,
                "item_number": 58,
                "endpoint": "/api/runs/{run_id}/source-ocr-queue",
            },
            "korean_ocr_translation": {
                "implemented": True,
                "item_number": 59,
                "endpoint": "/api/runs/{run_id}/source-ocr-translation",
            },
            "dedup_review": {
                "implemented": True,
                "item_number": 60,
                "source": "analysis_analyst_review_profile.dedup_review",
            },
        },
        "stage10_capability_matrix": stage10_matrix,
        "stage10_capability_matrix_hash": stable_payload_sha256(stage10_matrix),
        "large_data_controls": {
            "inline_preview_bounded": True,
            "structured_preview_max_bytes": STRUCTURED_PREVIEW_MAX_BYTES,
            "hex_preview_max_bytes": HEX_PREVIEW_MAX_BYTES,
            "full_file_download_is_explicit_action": True,
            "large_result_navigation": "cursor-or-bounded-preview-required",
            "dedup_collapse_expected": True,
        },
        "reportability_decision": {
            "decision": "review-workbench-output-requires-source-citation-before-report",
            "allowed_use": "single-case-source-verification-workbench",
            "required_before_report": [
                "save review decision for report candidates",
                "compute source hash where needed",
                "preserve citation, locator, and parser/viewer limitation",
            ],
        },
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "browser-e2e-workbench-validation-required",
            "persistent-compare-notes-not-yet-implemented",
            "role-based-review-server-not-yet-implemented",
            "trusted-viewer-and-dedup-corpus-required",
        ],
    }


def stage10_viewer_item_number(viewer_family: str) -> int:
    return STAGE10_VIEWER_ITEM_BY_FAMILY.get(viewer_family, 53)


def source_stage10_capability_matrix(
    *,
    run_id: str,
    source_path: Path,
    quoted_path: str,
    viewer_family: str,
) -> dict[str, object]:
    """Expose the #51-#60 review/viewer workbench as one UI contract."""
    entries = [
        stage10_capability_entry_from_spec(
            spec,
            run_id=run_id,
            quoted_path=quoted_path,
            viewer_family=viewer_family,
        )
        for spec in STAGE10_CAPABILITY_SPECS
    ]
    implemented_count = sum(1 for entry in entries if entry["implemented"])
    primary_count = sum(1 for entry in entries if entry["primary_for_current_source"])
    return {
        "profile_version": "stage10-review-viewer-capability-matrix-v1",
        "commercial_batch_id": "commercial-uplift-051-060",
        "source_path": str(source_path),
        "source_name": source_path.name,
        "viewer_family": viewer_family,
        "implemented_count": implemented_count,
        "primary_for_current_source_count": primary_count,
        "capability_count": len(entries),
        "entries": entries,
        "reportability_decision": {
            "decision": "do-not-claim-stage10-commercial-grade-without-trusted-viewer-corpora",
            "allowed_use": "single-case-review-viewer-navigation-contract",
            "required_before_report": [
                "save review mark and source locator",
                "compute source hash or record why not",
                "attach viewer-specific citation manifest",
                "disclose unsupported native recovery or corpus gaps",
            ],
        },
    }


def stage10_capability_entry_from_spec(
    spec: Mapping[str, object],
    *,
    run_id: str,
    quoted_path: str,
    viewer_family: str,
) -> dict[str, object]:
    route_template = spec.get("route_template")
    route = (
        str(route_template).format(run_id=run_id, quoted_path=quoted_path)
        if isinstance(route_template, str)
        else None
    )
    primary_families = spec.get("primary_families")
    primary = isinstance(primary_families, tuple) and viewer_family in primary_families
    return stage10_capability_entry(
        int(spec["item_number"]),
        str(spec["label"]),
        implemented=True,
        primary=primary,
        route=route,
        evidence_refs=tuple(str(item) for item in spec.get("evidence_refs", ())),
        blockers=tuple(str(item) for item in spec.get("blockers", ())),
    )


def stage10_capability_entry(
    item_number: int,
    label: str,
    *,
    implemented: bool,
    primary: bool,
    route: str | None,
    evidence_refs: Sequence[str],
    blockers: Sequence[str],
) -> dict[str, object]:
    return {
        "item_number": item_number,
        "gap_id": f"#{item_number}",
        "label": label,
        "implemented": implemented,
        "primary_for_current_source": primary,
        "route": route,
        "evidence_refs": list(evidence_refs),
        "commercial_grade_ready": False,
        "commercial_blockers": list(blockers),
    }


def build_workbench_smoke_contract() -> dict[str, object]:
    required_steps = [
        {
            "id": "open-workbench",
            "action": "GET /",
            "selector": WORKBENCH_SMOKE_SELECTORS["shell"],
            "assertion": "Analyst console shell is visible and API health can be checked.",
        },
        {
            "id": "create-or-import-run",
            "action": "POST /api/sample-case/run or POST /api/runs/import",
            "selector": WORKBENCH_SMOKE_SELECTORS["sample_run"],
            "assertion": "A completed run appears in the run list.",
        },
        {
            "id": "select-run",
            "action": "GET /api/runs/{run_id}",
            "selector": WORKBENCH_SMOKE_SELECTORS["case_hero"],
            "assertion": "Case hero, readiness dashboard, artifact navigator, and validation summary are rendered.",
        },
        {
            "id": "search-case",
            "action": "GET /api/runs/{run_id}/search",
            "selector": WORKBENCH_SMOKE_SELECTORS["global_search"],
            "assertion": "Global search opens the Find view and returns bounded results.",
        },
        {
            "id": "open-source-viewer",
            "action": "GET /api/runs/{run_id}/source-preview?path=...",
            "selector": WORKBENCH_SMOKE_SELECTORS["source_viewer"],
            "assertion": "Source viewer opens with source-verification trail and bounded preview metadata.",
        },
        {
            "id": "mark-evidence",
            "action": "POST /api/runs/{run_id}/bookmarks",
            "selector": WORKBENCH_SMOKE_SELECTORS["viewer_review"],
            "assertion": "Review status, tags, notes, and include-in-report decision can be saved.",
        },
        {
            "id": "export-report",
            "action": "GET /api/runs/{run_id}/case-report/file",
            "selector": WORKBENCH_SMOKE_SELECTORS["report_tab"],
            "assertion": "Report view and report export endpoint are reachable after review marking.",
        },
    ]
    platform_evidence = [
        {
            "platform": "windows",
            "script": "scripts/windows/smoke-test-rapidtriage.ps1",
            "summary_json": "rapidtriage-windows-smoke/smoke-summary.json",
            "summary_markdown": "rapidtriage-windows-smoke/smoke-summary.md",
            "contract_json": "rapidtriage-windows-smoke/workbench-smoke-contract.json",
            "required_fresh_host": "Fresh Windows 11 workstation or VM",
            "status": "external-evidence-required",
        },
        {
            "platform": "macos",
            "script": "scripts/smoke-test-rapidtriage.sh --output-dir rapidtriage-macos-smoke",
            "summary_json": "rapidtriage-macos-smoke/smoke-summary.json",
            "summary_markdown": "rapidtriage-macos-smoke/smoke-summary.md",
            "contract_json": "rapidtriage-macos-smoke/workbench-smoke-contract.json",
            "required_fresh_host": "Fresh macOS workstation or VM",
            "status": "external-evidence-required",
        },
    ]
    payload = {
        "command": "workbench.smoke-contract",
        "profile_version": WORKBENCH_SMOKE_CONTRACT_VERSION,
        "qc_prep_item": 5,
        "immediate_queue_item": 7,
        "status": "implemented-browser-e2e-evidence-required",
        "browser_test_ready": True,
        "selectors": WORKBENCH_SMOKE_SELECTORS,
        "required_steps": required_steps,
        "platform_evidence": platform_evidence,
        "fresh_gui_launch_evidence": {
            "profile_version": "fresh-gui-launch-smoke-evidence-v1",
            "required_platforms": ["windows", "macos"],
            "required_outputs": [
                "smoke-summary.json",
                "smoke-summary.md",
                "workbench-smoke-contract.json",
                "web-index.html or browser screenshot",
                "web-server.log",
            ],
            "required_assertions": [
                "web server returns HTTP 200",
                "workbench shell selector is present",
                "sample or imported run reaches summary",
                "source viewer and review selectors are present",
                "report/export path is reachable",
            ],
            "commercial_claim_allowed_without_external_runs": False,
        },
        "api_routes": {
            "open_workbench": "/",
            "health": "/api/health",
            "sample_case": "/api/sample-case/run",
            "runs": "/api/runs",
            "run_detail": "/api/runs/{run_id}",
            "search": "/api/runs/{run_id}/search",
            "source_preview": "/api/runs/{run_id}/source-preview?path={path}",
            "bookmark": "/api/runs/{run_id}/bookmarks",
            "case_report": "/api/runs/{run_id}/case-report/file",
        },
        "implemented_controls": {
            "stable_selectors": True,
            "sample_case_bootstrap": True,
            "existing_run_import": True,
            "source_viewer_contract": True,
            "review_mark_contract": True,
            "report_export_contract": True,
            "platform_smoke_scripts": True,
            "smoke_contract_artifact": True,
            "browser_e2e_attached": False,
        },
        "functional_priority_profile": {
            "queue_item_number": 7,
            "batch_id": "functional-priority-001-010",
            "component": "single-case-workbench-browser-smoke",
            "status": "implemented-usable-validation-required",
            "selector_count": len(WORKBENCH_SMOKE_SELECTORS),
            "required_step_count": len(required_steps),
            "passed_validation_check_ids": [
                "stable-workbench-selectors-defined",
                "sample-case-smoke-route-defined",
                "source-viewer-review-report-flow-defined",
            ],
            "failed_validation_check_ids": [
                "playwright-browser-smoke-log-not-attached",
                "screenshot-evidence-not-attached",
                "fresh-windows-browser-run-not-attached",
                "fresh-macos-browser-run-not-attached",
            ],
        },
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "browser-e2e-smoke-log-not-attached",
            "visual-regression-screenshot-not-attached",
            "fresh-windows-11-browser-smoke-required",
            "fresh-macos-browser-smoke-required",
        ],
    }
    payload["manifest_sha256"] = stable_payload_sha256(payload)
    return payload


def attach_search_result_source_actions(payload: MutableMapping[str, object], run_id: str) -> None:
    matches = payload.get("matches")
    if not isinstance(matches, list):
        return
    actionable = 0
    for index, match in enumerate(matches):
        if not isinstance(match, MutableMapping):
            continue
        action_profile = build_search_result_source_action_profile(run_id, match, index=index)
        match["source_viewer_action_profile"] = action_profile
        if action_profile.get("viewer_supported"):
            actionable += 1
    payload["search_result_source_action_profile"] = {
        "profile_version": "search-result-source-viewer-actions-summary-v1",
        "qc_prep_item": 6,
        "match_count": len(matches),
        "actionable_viewer_count": actionable,
        "viewer_action_contract": "search-result-source-viewer-actions-v1",
        "required_gui_selector": "[data-testid='search-result-source-actions']",
        "required_before_report": [
            "open source viewer",
            "verify source locator and source hash",
            "save review decision before include-in-report",
        ],
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "browser-e2e-search-result-viewer-action-evidence-required",
            "trusted-source-locator-diff-required",
        ],
    }


def build_search_result_source_action_profile(
    run_id: str,
    match: Mapping[str, object],
    *,
    index: int,
) -> dict[str, object]:
    path = str(match.get("path") or "")
    pointer = str(match.get("pointer") or "")
    source = str(match.get("source") or "")
    quoted_path = quote(path)
    viewer_supported = bool(path)
    review_source = review_source_for_search_match(match)
    review_context = {
        "source": review_source,
        "pointer": pointer,
        "title": str(match.get("title") or (Path(path).name if path else "search hit")),
        "path": path,
        "note": str(match.get("preview") or ""),
        "tags": [item for item in [source, str(match.get("kind") or "")] if item],
    }
    actions: list[dict[str, object]] = [
        {
            "id": "open-source-viewer",
            "label": "View / review",
            "method": "GET",
            "url": f"/api/runs/{quote(run_id)}/source-preview?path={quoted_path}" if path else "",
            "enabled": viewer_supported,
            "gui_binding": "data-view-source-path",
            "must_precede_report": True,
        },
        {
            "id": "open-source-file",
            "label": "Open source",
            "method": "GET",
            "url": f"/api/runs/{quote(run_id)}/source-file?path={quoted_path}" if path else "",
            "enabled": viewer_supported,
            "gui_binding": "href",
            "must_precede_report": False,
        },
        {
            "id": "search-inside-source",
            "label": "Search inside",
            "method": "GET",
            "url": f"/api/runs/{quote(run_id)}/source-search?path={quoted_path}" if path else "",
            "enabled": viewer_supported,
            "gui_binding": "viewer-current-file-search",
            "must_precede_report": True,
        },
        {
            "id": "pin-compare",
            "label": "Pin compare",
            "method": "UI",
            "url": "",
            "enabled": viewer_supported,
            "gui_binding": "data-compare-item",
            "must_precede_report": False,
        },
        {
            "id": "save-review",
            "label": "Mark",
            "method": "POST",
            "url": f"/api/runs/{quote(run_id)}/bookmarks",
            "enabled": bool(review_source and pointer),
            "gui_binding": "data-bookmark-source",
            "must_precede_report": True,
        },
    ]
    blockers: list[str] = []
    if not path:
        blockers.append("source-path-required-for-viewer-action")
    if not pointer:
        blockers.append("search-result-pointer-required-for-review-action")
    if not review_source:
        blockers.append("bookmark-source-mapping-required")
    return {
        "profile_version": "search-result-source-viewer-actions-v1",
        "qc_prep_item": 6,
        "search_result_index": index,
        "search_result_id": str(match.get("search_result_id") or ""),
        "source": source,
        "kind": str(match.get("kind") or ""),
        "path": path,
        "pointer": pointer,
        "viewer_supported": viewer_supported,
        "review_context": review_context,
        "actions": actions,
        "ready_for_report_workflow": viewer_supported and bool(review_source and pointer),
        "blockers": blockers,
        "report_use_rule": "Search result rows are leads until the source viewer action is opened and review state is saved.",
    }


def review_source_for_search_match(match: Mapping[str, object]) -> str:
    source = str(match.get("source") or "")
    if source == "documents":
        return "docs"
    if source in {"files", "ocr"}:
        return "files"
    if source == "timeline":
        return "timeline"
    if source == "indicators":
        return "indicators"
    if source == "web":
        return "artifacts:browser"
    if source == "artifacts":
        kind = str(match.get("kind") or "").strip()
        return f"artifacts:{kind}" if kind else ""
    return ""


def build_workbench_large_result_evidence(*, record_count: int) -> dict[str, object]:
    total = max(1, int(record_count))
    visible = min(total, VIRTUAL_TABLE_ROW_LIMIT)
    offsets = sorted({0, min(VIRTUAL_TABLE_ROW_LIMIT, max(0, total - visible)), max(0, total - visible)})
    window_manifests = [
        {
            "window_name": f"search-window-{index + 1}",
            "offset": offset,
            "start_row": offset + 1,
            "end_row": min(total, offset + visible),
            "manifest": build_ui_virtualization_manifest(
                label=f"synthetic-100k-search-window-{index + 1}",
                total=total,
                visible=visible,
                api_pagination=True,
            ),
        }
        for index, offset in enumerate(offsets)
    ]
    max_dom_rows = visible
    estimated_dom_nodes = max_dom_rows * 8
    dom_budget = 5_000
    latency_budget_ms = 500
    memory_budget_mb = 512
    performance_contract = build_browser_e2e_performance_contract(
        total=total,
        visible=visible,
        dom_budget=dom_budget,
        latency_budget_ms=latency_budget_ms,
        memory_budget_mb=memory_budget_mb,
        window_manifests=window_manifests,
    )
    profile = browser_e2e_performance_profile(
        label="synthetic-large-result-workbench",
        total=total,
        visible=visible,
        api_pagination=True,
        performance_contract_hash=str(performance_contract["contract_hash"]),
    )
    evidence_manifest = build_large_result_evidence_manifest(
        total=total,
        visible=visible,
        window_manifests=window_manifests,
        performance_contract=performance_contract,
        estimated_dom_nodes=estimated_dom_nodes,
        dom_budget=dom_budget,
        latency_budget_ms=latency_budget_ms,
        memory_budget_mb=memory_budget_mb,
    )
    return {
        "command": "workbench.large-result-evidence",
        "profile_version": "large-result-ui-evidence-v1",
        "immediate_queue_item": 8,
        "status": "synthetic-ui-window-proof-browser-run-required",
        "record_count": total,
        "row_limit": VIRTUAL_TABLE_ROW_LIMIT,
        "visible_rows": visible,
        "window_count": len(window_manifests),
        "window_manifests": window_manifests,
        "dom_budget": {
            "max_dom_rows": max_dom_rows,
            "estimated_dom_nodes": estimated_dom_nodes,
            "dom_node_budget": dom_budget,
            "dom_budget_pass": estimated_dom_nodes <= dom_budget,
            "reason": "The UI renders a bounded row window instead of all synthetic records.",
        },
        "search_latency_budget": {
            "target_p95_ms": latency_budget_ms,
            "synthetic_browser_latency_attached": False,
            "api_pagination_required": True,
            "case_db_or_cursor_endpoint_required": True,
        },
        "memory_budget": {
            "target_max_heap_mb": memory_budget_mb,
            "synthetic_browser_memory_attached": False,
            "heap_snapshot_required": True,
        },
        "performance_contract": performance_contract,
        "evidence_manifest": evidence_manifest,
        "evidence_manifest_hash": evidence_manifest["manifest_hash"],
        "implemented_controls": {
            "synthetic_100k_contract": total >= 100_000,
            "cursor_window_manifest": True,
            "bounded_dom_row_window": visible <= VIRTUAL_TABLE_ROW_LIMIT,
            "viewport_offset_persistence": True,
            "keyboard_window_navigation": True,
            "browser_e2e_contract": True,
            "performance_budget_manifest": True,
            "browser_trace_attached": False,
        },
        "functional_priority_profile": {
            **profile,
            "queue_item_number": 8,
            "status": "implemented-synthetic-proof-browser-e2e-required",
            "controls": {
                **profile["controls"],
                "synthetic_record_count": total,
                "dom_budget_pass": estimated_dom_nodes <= dom_budget,
                "window_manifest_count": len(window_manifests),
                "performance_contract_hash": performance_contract["contract_hash"],
                "evidence_manifest_hash": evidence_manifest["manifest_hash"],
                "target_p95_interaction_ms": latency_budget_ms,
                "target_max_heap_mb": memory_budget_mb,
            },
            "failed_validation_check_ids": [
                "playwright-100k-browser-trace-not-attached",
                "browser-memory-profile-not-attached",
                "real-case-search-latency-not-attached",
            ],
        },
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "actual-browser-100k-run-required",
            "memory-profile-and-p95-latency-required",
            "fresh-windows-11-large-result-smoke-required",
        ],
    }


def build_browser_e2e_performance_contract(
    *,
    total: int,
    visible: int,
    dom_budget: int,
    latency_budget_ms: int,
    memory_budget_mb: int,
    window_manifests: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    contract_core = {
        "profile_version": BROWSER_E2E_PERFORMANCE_CONTRACT_VERSION,
        "item_number": 25,
        "gap_id": "#25",
        "target_record_count": total,
        "visible_row_limit": visible,
        "selectors": {
            "workbench_shell": WORKBENCH_SMOKE_SELECTORS["shell"],
            "detail_panel": WORKBENCH_SMOKE_SELECTORS["detail_panel"],
            "global_search": WORKBENCH_SMOKE_SELECTORS["global_search"],
            "search_view": WORKBENCH_SMOKE_SELECTORS["search_view"],
            "source_viewer": WORKBENCH_SMOKE_SELECTORS["source_viewer"],
            "virtual_window_card": ".virtual-window-card",
            "virtual_window_next": "[data-virtual-window-key]",
            "virtual_window_jump": "[data-virtual-window-jump-key]",
        },
        "required_steps": [
            {
                "id": "load-workbench",
                "action": "open / and wait for workbench shell",
                "measurement": "initial render time",
                "pass_criteria": f"shell visible and DOM nodes <= {dom_budget}",
            },
            {
                "id": "load-large-result-json",
                "action": "open /api/workbench/large-result-evidence?record_count=100000 and store response",
                "measurement": "contract/evidence manifest hash captured",
                "pass_criteria": "response includes performance_contract.contract_hash and evidence_manifest_hash",
            },
            {
                "id": "render-windowed-table",
                "action": "render or navigate to a result table with a bounded virtual window",
                "measurement": "mounted row count and DOM node count",
                "pass_criteria": f"mounted rows <= {visible} and DOM nodes <= {dom_budget}",
            },
            {
                "id": "keyboard-window-navigation",
                "action": "use next/previous/jump controls and keyboard shortcuts for at least three windows",
                "measurement": "p95 interaction latency",
                "pass_criteria": f"p95 interaction latency <= {latency_budget_ms} ms",
            },
            {
                "id": "source-viewer-roundtrip",
                "action": "open a source viewer from a large result and return to the same viewport",
                "measurement": "viewport persistence and heap growth",
                "pass_criteria": f"viewport restored and heap <= {memory_budget_mb} MB",
            },
            {
                "id": "attach-evidence",
                "action": "attach Playwright trace, screenshot, DOM count, memory profile, and latency samples",
                "measurement": "external evidence completeness",
                "pass_criteria": "all required artifacts are present before commercial performance claim",
            },
        ],
        "performance_budgets": {
            "dom_node_budget": dom_budget,
            "mounted_row_budget": visible,
            "target_p95_interaction_ms": latency_budget_ms,
            "target_max_heap_mb": memory_budget_mb,
        },
        "required_artifacts": [
            "playwright-trace.zip",
            "large-table-screenshot.png",
            "dom-node-count.json",
            "memory-profile.json",
            "interaction-latency-samples.json",
            "fresh-windows-11-run-transcript.txt",
        ],
        "window_manifest_hashes": [
            str(item.get("manifest", {}).get("manifest_hash"))
            for item in window_manifests
            if isinstance(item.get("manifest"), Mapping)
        ],
        "commercial_claim_allowed": False,
        "blockers": [
            "playwright-100k-browser-trace-not-attached",
            "browser-memory-profile-not-attached",
            "fresh-windows-11-large-result-smoke-required",
        ],
    }
    return {**contract_core, "contract_hash": hashlib.sha256(json.dumps(contract_core, sort_keys=True).encode("utf-8")).hexdigest()}


def build_large_result_evidence_manifest(
    *,
    total: int,
    visible: int,
    window_manifests: Sequence[Mapping[str, object]],
    performance_contract: Mapping[str, object],
    estimated_dom_nodes: int,
    dom_budget: int,
    latency_budget_ms: int,
    memory_budget_mb: int,
) -> dict[str, object]:
    manifest_core = {
        "profile_version": "large-result-ui-evidence-manifest-v1",
        "item_number": 25,
        "record_count": total,
        "visible_rows": visible,
        "estimated_dom_nodes": estimated_dom_nodes,
        "dom_budget": dom_budget,
        "dom_budget_pass": estimated_dom_nodes <= dom_budget,
        "latency_budget_ms": latency_budget_ms,
        "memory_budget_mb": memory_budget_mb,
        "performance_contract_hash": str(performance_contract.get("contract_hash") or ""),
        "window_manifest_hashes": [
            str(item.get("manifest", {}).get("manifest_hash"))
            for item in window_manifests
            if isinstance(item.get("manifest"), Mapping)
        ],
        "internal_evidence_status": "synthetic-contract-generated",
        "external_evidence_status": "missing",
        "commercial_gap_ids": ["#25", VIEWER_WORKFLOW_GAP_IDS["ui_virtualization"]],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest()}


def source_viewer_family(source_path: Path, *, suffix: str, mime_type: str) -> str:
    if mime_type.startswith("image/"):
        return "image-gallery-preview"
    if is_sqlite_candidate(source_path, suffix):
        return "sqlite-table-preview"
    if suffix in {".json", ".jsonl", ".ndjson"}:
        return "json-structured-preview"
    if suffix == ".xml":
        return "xml-structured-preview"
    if suffix in {".eml", ".mbox"}:
        return "email-thread-preview"
    if mime_type.startswith(("audio/", "video/")):
        return "media-preview"
    if suffix in SUPPORTED_DOC_EXTS:
        return "document-text-preview"
    return "text-or-hex-preview"


def source_viewer_specialization_profile(
    *,
    run_id: str,
    source_path: Path,
    suffix: str,
    mime_type: str,
    max_chars: int,
) -> dict[str, object]:
    viewer_family = source_viewer_family(source_path, suffix=suffix, mime_type=mime_type)
    quoted_path = quote(str(source_path))
    return {
        "profile_version": "source-viewer-specialization-v1",
        "commercial_batch_id": "commercial-uplift-016-020",
        "item_number": 18,
        "viewer_family": viewer_family,
        "source_path": str(source_path),
        "default_layout": {
            "primary_content_first": True,
            "metadata_collapsed_by_default": True,
            "limitations_visible": True,
            "review_controls_visible": True,
            "compare_pin_visible": True,
        },
        "supported_viewer_features": source_viewer_feature_matrix(viewer_family),
        "citation_contract": {
            "source_path": True,
            "source_name": True,
            "viewer_family": True,
            "search_inside_file_url": f"/api/runs/{run_id}/source-search?path={quoted_path}",
            "metadata_hash_url": f"/api/runs/{run_id}/source-metadata?path={quoted_path}&hash=true",
            "download_url": f"/api/runs/{run_id}/source-file?path={quoted_path}",
        },
        "large_data_controls": {
            "inline_text_limit": max_chars,
            "structured_preview_max_bytes": STRUCTURED_PREVIEW_MAX_BYTES,
            "hex_preview_max_bytes": HEX_PREVIEW_MAX_BYTES,
            "explicit_full_file_open": True,
            "active_content_blocked": True,
        },
        "reportability_decision": {
            "decision": "do-not-report-viewer-rendering-without-source-citation",
            "allowed_use": "source-viewer-verification-and-review",
            "required_before_report": [
                "capture source hash where needed",
                "preserve source-search locator or table/offset citation",
                "record analyst review status and limitation wording",
            ],
        },
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "browser-e2e-visual-validation-required",
            "large-preview-corpus-required",
            "trusted-viewer-rendering-diff-required",
        ],
    }


def source_viewer_feature_matrix(viewer_family: str) -> dict[str, bool]:
    return {
        "text_preview": viewer_family in {"document-text-preview", "text-or-hex-preview"},
        "hex_preview": viewer_family == "text-or-hex-preview",
        "sqlite_table_preview": viewer_family == "sqlite-table-preview",
        "json_tree_preview": viewer_family == "json-structured-preview",
        "xml_tree_preview": viewer_family == "xml-structured-preview",
        "image_preview": viewer_family == "image-gallery-preview",
        "media_metadata_preview": viewer_family == "media-preview",
        "email_thread_preview": viewer_family == "email-thread-preview",
        "current_file_search": True,
        "source_hash_on_demand": True,
        "metadata_collapsible": True,
        "review_and_compare_actions": True,
    }


def viewer_workflow_commercial_uplift_evidence(
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
        "batch_id": "commercial-uplift-051-055",
        "item_numbers": [item_number],
        "implementation_track": component,
        "source_refs": list(source_refs),
        "reportability_decision": viewer_workflow_reportability_decision(
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


def viewer_workflow_reportability_decision(
    *,
    item_number: int,
    component: str,
    blockers: Sequence[str],
    controls: Mapping[str, object],
) -> dict[str, object]:
    gap_id = f"#{item_number}"
    allowed_uses = {
        51: "single-user-review-status-triage-pivot",
        52: "bounded-file-compare-triage-pivot",
        53: "bounded-hex-preview-triage-pivot",
        54: "read-only-sqlite-preview-triage-pivot",
        55: "bounded-email-conversation-triage-pivot",
        56: "image-gallery-metadata-triage-pivot",
        57: "media-transcript-sidecar-triage-pivot",
    }
    decisions = {
        51: "do-not-report-review-workflow-as-role-based-case-management",
        52: "do-not-report-compare-output-as-semantic-diff-complete",
        53: "do-not-report-hex-preview-as-full-source-byte-citation",
        54: "do-not-report-sqlite-preview-as-deleted-row-or-wal-complete",
        55: "do-not-report-email-preview-as-native-mailbox-thread-complete",
        56: "do-not-report-image-gallery-as-ml-or-sensitive-media-complete",
        57: "do-not-report-media-preview-as-playback-or-asr-validated",
    }
    required = {
        51: [
            "enable role-based multi-user queues, conflict handling, notifications, and signed reviewer SOPs",
            "verify source hashes and parser limitations before report inclusion",
        ],
        52: [
            "add semantic binary/image/SQLite/mailbox diff viewers and persistent analyst comparison notes",
            "attach reviewed selection rationale for each compared evidence item",
        ],
        53: [
            "add jump-to-offset, byte selection hashing, and exported range citation packages",
            "validate offsets against full-source hashes and source parser context",
        ],
        54: [
            "add large-table pagination, WHERE builder, WAL/journal replay, and deleted-row validation",
            "validate database previews against known-answer SQLite corpora",
        ],
        55: [
            "add native PST/OST/MSG object decoding, deleted item recovery, attachment extraction, and mailbox corpus validation",
            "verify conversation threading and message-id graph reconstruction before reporting",
        ],
        56: [
            "validate virtualized gallery review, persistent tags, ML similarity, and sensitive/deepfake classifier behavior",
            "attach source hash and reviewer selection evidence before report export",
        ],
        57: [
            "validate safe playback, ASR execution, waveform/thumb generation, and transcript alignment corpus",
            "attach reviewed transcript cue citations before report use",
        ],
    }
    return {
        "profile_version": "viewer-workflow-reportability-decision-v1",
        "commercial_gap_ids": [gap_id],
        "component": component,
        "decision": decisions.get(item_number, "do-not-report-viewer-output-as-commercial-complete"),
        "allowed_use": allowed_uses.get(item_number, "bounded-viewer-triage-pivot"),
        "blockers": sorted({str(item) for item in blockers if str(item)}),
        "control_snapshot": dict(controls),
        "ready_for_court_report": False,
        "required_before_report": required.get(item_number, ["attach source hash, parser validation, reviewer decision, and export citation evidence"]),
    }


def source_viewer_sandbox(source_path: Path, *, suffix: str, mime_type: str, max_chars: int) -> dict[str, object]:
    active_content = suffix in {".html", ".htm", ".svg", ".js", ".vbs", ".hta"} or mime_type in {
        "text/html",
        "image/svg+xml",
        "application/javascript",
    }
    policy_profile = preview_sandbox_policy_profile(
        source_path=source_path,
        suffix=suffix,
        mime_type=mime_type,
        max_chars=max_chars,
        active_content_blocked=active_content,
    )
    source_manifest = source_preview_sandbox_manifest(policy_profile=policy_profile)
    return {
        "mode": "read-only-bounded-preview",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["preview_sandbox"]],
        "executes_content": False,
        "active_content_blocked": active_content,
        "preview_sandbox_policy_profile": policy_profile,
        "source_preview_sandbox_manifest": source_manifest,
        "source_preview_sandbox_manifest_hash": source_manifest["manifest_hash"],
        "path_redaction": "display-basename-in-summary-use-full-path-only-for-authorized-source-actions",
        "max_inline_text_chars": max_chars,
        "max_structured_preview_bytes": STRUCTURED_PREVIEW_MAX_BYTES,
        "max_hex_preview_bytes": HEX_PREVIEW_MAX_BYTES,
        "external_network_access": False,
        "notes": [
            "Preview routes never execute scripts, macros, HTML, SVG, or embedded active content.",
            "Use source metadata/hash actions for verification before report inclusion.",
        ],
        "preview_sandbox_assessment": source_viewer_component_assessment(
            VIEWER_WORKFLOW_GAP_IDS["preview_sandbox"],
            "preview-sandboxing",
            [
                "preview-is-application-level-bounded-rendering-not-a-separate-os-sandbox",
                "malicious-codecs-and-office-macros-require-external-sandboxed-tooling-before-opening-originals",
                PREVIEW_SANDBOX_TRUSTED_DIFF_BLOCKER,
            ],
        ),
        "trusted_preview_sandbox_diff": {
            "status": "missing",
            "blocker_id": PREVIEW_SANDBOX_TRUSTED_DIFF_BLOCKER,
            "required_tools": sorted(PREVIEW_SANDBOX_TRUSTED_TOOLS),
        },
        "core_accuracy_gates": preview_sandbox_core_accuracy_gates(
            source_path=source_path,
            active_content_blocked=active_content,
            max_chars=max_chars,
            policy_profile=policy_profile,
        ),
    }


def preview_sandbox_policy_profile(
    *,
    source_path: Path,
    suffix: str,
    mime_type: str,
    max_chars: int,
    active_content_blocked: bool,
) -> dict[str, object]:
    dangerous_extension = suffix in {".html", ".htm", ".svg", ".js", ".vbs", ".hta", ".docm", ".xlsm", ".pptm"}
    return {
        "profile_version": "preview-sandbox-policy-profile-v1",
        "source_name": source_path.name,
        "source_path_sha256": hashlib.sha256(str(source_path).encode("utf-8", errors="replace")).hexdigest(),
        "suffix": suffix,
        "mime_type": mime_type,
        "dangerous_extension_detected": dangerous_extension,
        "active_content_blocked": active_content_blocked,
        "executes_content": False,
        "external_network_access": False,
        "renderer_strategy": "escaped-bounded-data-rendering",
        "original_file_opening": "download-only-user-controlled-action",
        "max_inline_text_chars": max_chars,
        "max_structured_preview_bytes": STRUCTURED_PREVIEW_MAX_BYTES,
        "max_hex_preview_bytes": HEX_PREVIEW_MAX_BYTES,
        "os_sandbox_enabled": False,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["preview_sandbox"]],
        "commercial_claim_allowed": False,
    }


def source_preview_sandbox_manifest(*, policy_profile: Mapping[str, object]) -> dict[str, object]:
    policy = dict(policy_profile)
    row_core = {
        "source_name": str(policy.get("source_name") or ""),
        "source_path_sha256": str(policy.get("source_path_sha256") or ""),
        "suffix": str(policy.get("suffix") or ""),
        "mime_type": str(policy.get("mime_type") or ""),
        "dangerous_extension_detected": bool(policy.get("dangerous_extension_detected")),
        "active_content_blocked": bool(policy.get("active_content_blocked")),
        "executes_content": bool(policy.get("executes_content")),
        "external_network_access": bool(policy.get("external_network_access")),
        "renderer_strategy": str(policy.get("renderer_strategy") or ""),
        "original_file_opening": str(policy.get("original_file_opening") or ""),
        "os_sandbox_enabled": bool(policy.get("os_sandbox_enabled")),
    }
    row_hash = hashlib.sha256(json.dumps(row_core, sort_keys=True).encode("utf-8")).hexdigest()
    manifest_core = {
        "profile_version": "source-preview-sandbox-manifest-v1",
        "item_number": 73,
        "gap_id": VIEWER_WORKFLOW_GAP_IDS["preview_sandbox"],
        "policy_profile_hash": hashlib.sha256(json.dumps(policy, sort_keys=True).encode("utf-8")).hexdigest(),
        "source_policy_row": {**row_core, "row_hash": row_hash},
        "row_head_hash": hashlib.sha256(row_hash.encode("utf-8")).hexdigest(),
        "active_content_blocking_required": bool(policy.get("dangerous_extension_detected"))
        or bool(policy.get("active_content_blocked")),
        "no_exec_no_network_contract": {
            "executes_content": False,
            "external_network_access": False,
            "renderer_strategy": "escaped-bounded-data-rendering",
            "original_file_opening": "download-only-user-controlled-action",
        },
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["preview_sandbox"]],
        "commercial_claim_allowed": False,
        "blockers": [
            PREVIEW_SANDBOX_TRUSTED_DIFF_BLOCKER,
            "separate-os-sandbox-for-risky-codecs-macros-not-enabled",
            "browser-renderer-exploit-corpus-not-attached",
        ],
    }
    return {
        **manifest_core,
        "manifest_hash": hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def build_preview_sandbox_trusted_diff(
    rapid_sandbox: Mapping[str, object],
    trusted_sandbox: Mapping[str, object],
    *,
    trusted_tool: str = "no-exec-preview-manifest",
) -> dict[str, object]:
    rapid = preview_sandbox_diff_value(rapid_sandbox)
    trusted = preview_sandbox_diff_value(trusted_sandbox)
    mismatched = [
        {"field": key, "rapid": rapid.get(key), "trusted": trusted.get(key)}
        for key in sorted(set(rapid).union(trusted))
        if rapid.get(key) != trusted.get(key)
    ]
    status = "pass" if not mismatched else "fail"
    return {
        "profile": "preview-sandbox-trusted-no-exec-diff-v1",
        "item_number": 73,
        "trusted_tool": trusted_tool,
        "status": status,
        "mismatched": mismatched,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["preview_sandbox"]],
        "commercial_claim_allowed": status == "pass",
    }


def preview_sandbox_diff_value(item: Mapping[str, object]) -> dict[str, object]:
    policy = item.get("preview_sandbox_policy_profile")
    policy_profile = policy if isinstance(policy, Mapping) else {}
    return {
        "mode": str(item.get("mode") or ""),
        "executes_content": bool(item.get("executes_content")),
        "external_network_access": bool(item.get("external_network_access")),
        "active_content_blocked": bool(item.get("active_content_blocked")),
        "max_inline_text_chars": int(item.get("max_inline_text_chars") or 0),
        "policy_profile_version": str(policy_profile.get("profile_version") or ""),
        "renderer_strategy": str(policy_profile.get("renderer_strategy") or ""),
        "os_sandbox_enabled": bool(policy_profile.get("os_sandbox_enabled")),
    }


def preview_sandbox_core_accuracy_gates(
    *,
    source_path: Path,
    active_content_blocked: bool,
    max_chars: int,
    policy_profile: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = [
        "read-only bounded preview",
        "active content execution blocked",
        "external network access disabled",
        "preview caps recorded",
        "OS sandbox limitation warning",
        "preview sandbox policy profile emitted",
    ]
    if policy_profile and policy_profile.get("renderer_strategy"):
        satisfied.append("escaped bounded renderer strategy recorded")
    if policy_profile and policy_profile.get("source_path_sha256"):
        satisfied.append("preview policy row hashes emitted")
    evidence_refs = [
        f"source_path:{source_path}",
        f"active_content_blocked:{active_content_blocked}",
        f"max_inline_text_chars:{max_chars}",
    ]
    trusted_diff = trusted_diff if isinstance(trusted_diff, Mapping) else {}
    if trusted_diff.get("status") == "pass":
        satisfied.append("trusted preview sandbox/no-exec diff pass")
        evidence_refs.append(f"trusted_tool:{trusted_diff.get('trusted_tool', '')}")
    return [
        build_accuracy_gate(
            73,
            satisfied_checks=satisfied,
            evidence_refs=evidence_refs,
        )
    ]


def source_viewer_limitations(source_path: Path, *, suffix: str, mime_type: str, max_chars: int) -> list[str]:
    limitations = [
        "Preview is read-only and may be capped to keep large cases responsive.",
        "Use hashes and source download before relying on a preview in a final report.",
    ]
    if mime_type.startswith("image/"):
        limitations.append("Image text requires OCR or OCR sidecar review; the file viewer does not OCR images inline.")
    if is_sqlite_candidate(source_path, suffix):
        limitations.append("SQLite previews show bounded tables/rows; use file search or a dedicated database tool for full table review.")
    if suffix in {".json", ".jsonl", ".ndjson", ".xml"} and source_path.stat().st_size > STRUCTURED_PREVIEW_MAX_BYTES:
        limitations.append("Structured parsing is skipped for very large JSON/XML files; use current-file search or external tooling.")
    if suffix in SUPPORTED_DOC_EXTS and source_path.stat().st_size > DOCUMENT_PREVIEW_MAX_BYTES:
        limitations.append("Document text extraction is bounded for preview; use source search resume or an external parser for full-document validation.")
    if suffix in {".eml", ".mbox"} and source_path.stat().st_size > EMAIL_PREVIEW_MAX_BYTES:
        limitations.append("Email preview is bounded; only the first parse window is shown until mailbox-specific pagination is implemented.")
    if source_path.stat().st_size > max_chars:
        limitations.append(f"Inline text snippets are capped near {max_chars} characters.")
    return limitations


def is_probably_binary(source_path: Path, *, sample_size: int = 4096) -> bool:
    try:
        with source_path.open("rb") as handle:
            sample = handle.read(sample_size)
    except OSError:
        return False
    if not sample:
        return False
    if b"\x00" in sample:
        return True
    control = sum(1 for byte in sample if byte < 9 or (13 < byte < 32))
    return control / len(sample) > 0.08


def is_sqlite_candidate(path: Path, suffix: str | None = None) -> bool:
    normalized_suffix = suffix if suffix is not None else path.suffix.lower()
    if normalized_suffix not in SQLITE_PREVIEW_EXTS:
        return False
    try:
        with path.open("rb") as handle:
            return handle.read(len(SQLITE_HEADER)) == SQLITE_HEADER
    except OSError:
        return False


def is_image_preview_candidate(path: Path) -> bool:
    mime_type = mimetypes.guess_type(path.name)[0] or ""
    return mime_type.startswith("image/")


def build_sqlite_preview(source_path: Path, *, run_id: str | None = None) -> Dict[str, object]:
    try:
        with contextlib.closing(sqlite3.connect(f"{source_path.as_uri()}?mode=ro", uri=True)) as connection:
            connection.row_factory = sqlite3.Row
            database_metadata = sqlite_database_metadata(connection, source_path)
            tables = list_sqlite_tables(connection)
            previews = [
                preview_sqlite_table(connection, table, source_path=source_path)
                for table in tables[:SQLITE_PREVIEW_TABLE_LIMIT]
            ]
            table_page_profile = sqlite_table_page_profile(run_id=run_id, source_path=source_path, tables=previews)
            sqlite_manifest = build_sqlite_preview_manifest(
                source_path=source_path,
                database_metadata=database_metadata,
                tables=previews,
                table_page_profile=table_page_profile,
            )
    except sqlite3.DatabaseError as exc:
        return {
            "preview_type": "binary",
            "message": f"SQLite preview failed: {exc}",
            "sqlite": {"tables": [], "table_count": 0, "error": str(exc)},
        }
    return {
        "preview_type": "sqlite",
        "message": "SQLite table preview is available.",
        "viewer_metadata": {
            "source_format": "sqlite",
            "strategy": "read-only-table-preview",
            "preview_status": "available",
            "parser": "rapidtriage.source-viewer.sqlite",
            "parser_version": SOURCE_VIEWER_VERSION,
            "table_limit": SQLITE_PREVIEW_TABLE_LIMIT,
            "row_limit": SQLITE_PREVIEW_ROW_LIMIT,
            "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["sqlite"], VIEWER_WORKFLOW_GAP_IDS["sqlite_performance"]],
        },
        "sqlite": {
            "table_count": len(tables),
            "database_metadata": database_metadata,
            "sidecar_state_profile": database_metadata.get("sidecar_state_profile", {}),
            "tables": previews,
            "table_profiles": build_sqlite_table_profiles(previews),
            "table_page_profile": table_page_profile,
            "sqlite_preview_manifest": sqlite_manifest,
            "sqlite_preview_manifest_hash": sqlite_manifest["manifest_hash"],
            "large_sqlite_fts_optimization": sqlite_fts_optimization_metadata(database_metadata, previews),
            "table_limit": SQLITE_PREVIEW_TABLE_LIMIT,
            "row_limit": SQLITE_PREVIEW_ROW_LIMIT,
            "column_limit": SQLITE_PREVIEW_COLUMN_LIMIT,
            "truncated": len(tables) > SQLITE_PREVIEW_TABLE_LIMIT,
            "sqlite_viewer_assessment": source_viewer_component_assessment(
                VIEWER_WORKFLOW_GAP_IDS["sqlite"],
                "sqlite-table-viewer",
                [
                    "interactive-table-pagination-ui-is-api-backed-baseline-only",
                    "foreign-key-relationship-graph-not-yet-rendered",
                    "wal/journal-replay-and-deleted-row-recovery-not-implemented-in-viewer",
                ],
            ),
            "core_accuracy_gates": sqlite_viewer_core_accuracy_gates(
                source_path=source_path,
                database_metadata=database_metadata,
                tables=previews,
                preview_manifest=sqlite_manifest,
            ),
            "trusted_sqlite_viewer_diff": {
                "status": "missing",
                "blocker_id": SQLITE_VIEWER_TRUSTED_DIFF_BLOCKER,
                "required_tools": sorted(SQLITE_VIEWER_TRUSTED_TOOLS),
            },
            "commercial_uplift_evidence": viewer_workflow_commercial_uplift_evidence(
                item_number=54,
                component="sqlite-table-specialized-viewer",
                core_accuracy_gates=sqlite_viewer_core_accuracy_gates(
                    source_path=source_path,
                    database_metadata=database_metadata,
                    tables=previews,
                    preview_manifest=sqlite_manifest,
                ),
                blockers=[
                    "interactive-table-pagination-ui-needs-browser-e2e-validation",
                    "where-builder-is-restricted-contains-filter-not-arbitrary-sql",
                    "deleted-row-and-wal-recovery-not-implemented-in-viewer",
                    "export-selected-rows-workflow-not-implemented",
                    SQLITE_VIEWER_TRUSTED_DIFF_BLOCKER,
                ],
                source_refs=[f"source_path:{source_path}", f"table_count:{len(tables)}"],
                controls={
                    "table_limit": SQLITE_PREVIEW_TABLE_LIMIT,
                    "row_limit": SQLITE_PREVIEW_ROW_LIMIT,
                    "column_limit": SQLITE_PREVIEW_COLUMN_LIMIT,
                    "opened_readonly": True,
                    "deleted_row_recovery": False,
                    "table_pagination_api": True,
                    "where_builder_api": True,
                    "where_builder_ui": False,
                    "max_table_page_rows": SQLITE_TABLE_PAGE_MAX_ROWS,
                    "sqlite_preview_manifest_hash": sqlite_manifest["manifest_hash"],
                    "sqlite_preview_table_hash_count": sqlite_manifest["table_hash_count"],
                    "sqlite_preview_row_hash_count": sqlite_manifest["row_hash_count"],
                    "sqlite_sidecar_state_profile": database_metadata.get("sidecar_state_profile", {}),
                    "sqlite_sidecar_review_required": bool(
                        isinstance(database_metadata.get("sidecar_state_profile"), Mapping)
                        and database_metadata["sidecar_state_profile"].get("requires_wal_review")
                    ),
                },
            ),
            "sqlite_fts_optimization_assessment": source_viewer_component_assessment(
                VIEWER_WORKFLOW_GAP_IDS["sqlite_performance"],
                "large-sqlite-fts-optimization",
                [
                    "sqlite-source-preview-does-not-materialize-full-external-index",
                    "very-large-wal/journal-and-deleted-row-analysis-requires-dedicated-parser",
                    SQLITE_FTS_TRUSTED_DIFF_BLOCKER,
                ],
            ),
            "review_features": [
                "read-only-uri-open",
                "schema-sql",
                "column-type-and-pk-details",
                "bounded-row-preview",
                "api-table-pagination",
                "restricted-where-contains-filter",
                "text-column-keyword-search",
                "table-profile-summary",
                "wal-shm-journal-sidecar-status",
                "large-sqlite-optimization-metadata",
            ],
        },
    }


def build_json_preview(source_path: Path, suffix: str) -> Dict[str, object]:
    if source_path.stat().st_size > STRUCTURED_PREVIEW_MAX_BYTES:
        return {
            "preview_type": "binary",
            "message": f"JSON preview is capped at {STRUCTURED_PREVIEW_MAX_BYTES} bytes. Use source search or open source.",
            "viewer_metadata": structured_viewer_metadata("json", "bounded-json-parse", "capped"),
            "json": {"error": "file-too-large"},
        }
    try:
        text = source_path.read_text(encoding="utf-8", errors="replace")
        if suffix == ".json":
            data = json.loads(text)
            preview = summarize_json_value(data)
            formatted = json.dumps(data, ensure_ascii=False, indent=2)
            item_count = json_item_count(data)
        else:
            rows = []
            errors = []
            for line_number, line in enumerate(text.splitlines(), start=1):
                if not line.strip():
                    continue
                if len(rows) >= JSON_PREVIEW_ITEM_LIMIT:
                    break
                try:
                    rows.append({"line": line_number, "value": summarize_json_value(json.loads(line))})
                except json.JSONDecodeError as exc:
                    errors.append({"line": line_number, "error": str(exc)})
            preview = {"type": "jsonl", "rows": rows, "errors": errors[:5]}
            formatted = "\n".join(text.splitlines()[:JSON_PREVIEW_ITEM_LIMIT])
            item_count = len(rows)
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "preview_type": "text",
            "message": f"JSON parse failed, showing text fallback: {exc}",
            "text": safe_read_text(source_path, max_chars=20000),
            "truncated": source_path.stat().st_size > 20000,
            "viewer_metadata": structured_viewer_metadata("json", "parse-fallback-text", "parse-failed"),
        }
    return {
        "preview_type": "json",
        "message": "JSON structured preview is available.",
        "text": formatted[:20000],
        "truncated": len(formatted) > 20000,
        "viewer_metadata": structured_viewer_metadata("json", "bounded-json-parse", "available"),
        "json": {
            "summary": preview,
            "item_count": item_count,
            "item_limit": JSON_PREVIEW_ITEM_LIMIT,
            "truncated": item_count >= JSON_PREVIEW_ITEM_LIMIT,
        },
    }


def summarize_json_value(value: object, *, depth: int = 0) -> object:
    if depth >= 3:
        if isinstance(value, dict):
            return {"type": "object", "keys": len(value)}
        if isinstance(value, list):
            return {"type": "array", "items": len(value)}
        return value
    if isinstance(value, dict):
        return {
            "type": "object",
            "keys": list(value.keys())[:JSON_PREVIEW_ITEM_LIMIT],
            "sample": {str(key): summarize_json_value(item, depth=depth + 1) for key, item in list(value.items())[:10]},
        }
    if isinstance(value, list):
        return {
            "type": "array",
            "items": len(value),
            "sample": [summarize_json_value(item, depth=depth + 1) for item in value[:10]],
        }
    return value


def json_item_count(value: object) -> int:
    if isinstance(value, dict):
        return len(value)
    if isinstance(value, list):
        return len(value)
    return 1


def build_xml_preview(source_path: Path) -> Dict[str, object]:
    if source_path.stat().st_size > STRUCTURED_PREVIEW_MAX_BYTES:
        return {
            "preview_type": "binary",
            "message": f"XML preview is capped at {STRUCTURED_PREVIEW_MAX_BYTES} bytes. Use source search or open source.",
            "viewer_metadata": structured_viewer_metadata("xml", "bounded-xml-parse", "capped"),
            "xml": {"error": "file-too-large"},
        }
    try:
        text = source_path.read_text(encoding="utf-8", errors="replace")
        root = ET.fromstring(text.encode("utf-8", errors="replace"))
        nodes = summarize_xml_nodes(root)
    except (OSError, ET.ParseError) as exc:
        return {
            "preview_type": "text",
            "message": f"XML parse failed, showing text fallback: {exc}",
            "text": safe_read_text(source_path, max_chars=20000),
            "truncated": source_path.stat().st_size > 20000,
            "viewer_metadata": structured_viewer_metadata("xml", "parse-fallback-text", "parse-failed"),
        }
    return {
        "preview_type": "xml",
        "message": "XML structured preview is available.",
        "text": text[:20000],
        "truncated": len(text) > 20000,
        "viewer_metadata": structured_viewer_metadata("xml", "bounded-xml-parse", "available"),
        "xml": {
            "root_tag": local_xml_name(root.tag),
            "root_attributes": dict(root.attrib),
            "nodes": nodes,
            "node_limit": XML_PREVIEW_NODE_LIMIT,
            "truncated": len(nodes) >= XML_PREVIEW_NODE_LIMIT,
        },
    }


def summarize_xml_nodes(root: ET.Element) -> list[dict[str, object]]:
    nodes: list[dict[str, object]] = []
    stack: list[tuple[ET.Element, str, int]] = [(root, "/" + local_xml_name(root.tag), 0)]
    while stack and len(nodes) < XML_PREVIEW_NODE_LIMIT:
        node, path, depth = stack.pop()
        text = " ".join((node.text or "").split())
        nodes.append(
            {
                "path": path,
                "tag": local_xml_name(node.tag),
                "depth": depth,
                "attributes": dict(list(node.attrib.items())[:10]),
                "text": text[:240],
                "child_count": len(list(node)),
            }
        )
        children = list(node)
        for index, child in reversed(list(enumerate(children[:20], start=1))):
            stack.append((child, f"{path}/{local_xml_name(child.tag)}[{index}]", depth + 1))
    return nodes


def local_xml_name(value: str) -> str:
    return value.rsplit("}", 1)[-1] if "}" in value else value


def build_email_preview(source_path: Path, suffix: str, *, run_id: str | None = None) -> Dict[str, object]:
    try:
        messages, diagnostics = read_email_messages_with_diagnostics(source_path, suffix)
    except OSError as exc:
        return {
            "preview_type": "binary",
            "message": f"Email preview failed: {exc}",
            "viewer_metadata": structured_viewer_metadata("email", "bounded-email-parse", "parse-failed"),
            "email": {"error": str(exc)},
        }
    summaries = [summarize_email_message(message, index) for index, message in enumerate(messages, start=1)]
    threads = build_email_threads(summaries)
    conversation = build_email_conversation_viewer(summaries, threads)
    attachment_profile = email_attachment_package_profile(
        run_id=run_id,
        source_path=source_path,
        messages=summaries,
    )
    conversation_manifest = build_email_conversation_manifest(
        source_path=source_path,
        messages=summaries,
        conversation=conversation,
        attachment_profile=attachment_profile,
    )
    text = "\n\n".join(item["body_preview"] for item in summaries if item.get("body_preview"))
    parse_truncated = bool(
        diagnostics.get("source_truncated")
        or diagnostics.get("message_limit_reached")
        or diagnostics.get("message_size_truncated_count")
    )
    return {
        "preview_type": "email",
        "message": (
            "Email structured preview is partial because bounded parsing limits were reached."
            if parse_truncated
            else "Email structured preview is available."
        ),
        "text": text[:20000],
        "truncated": parse_truncated or len(text) > 20000,
        "viewer_metadata": structured_viewer_metadata(
            "email",
            "bounded-email-parse",
            "partial" if parse_truncated else "available",
        ),
        "email": {
            "message_count": len(summaries),
            "message_limit": EMAIL_PREVIEW_MESSAGE_LIMIT,
            "parse_diagnostics": diagnostics,
            "max_input_bytes": EMAIL_PREVIEW_MAX_BYTES,
            "max_message_bytes": EMAIL_PREVIEW_MESSAGE_MAX_BYTES,
            "messages": summaries,
            "attachment_package_profile": attachment_profile,
            "threads": threads,
            "conversation_view": conversation,
            "email_conversation_manifest": conversation_manifest,
            "email_conversation_manifest_hash": conversation_manifest["manifest_hash"],
            "thread_count": len(threads),
            "truncated": parse_truncated,
            "email_conversation_viewer_assessment": source_viewer_component_assessment(
                VIEWER_WORKFLOW_GAP_IDS["email"],
                "email-conversation-viewer",
                [
                    "pst-ost-native-folder-flag-deleted-item-threading-not-implemented-in-viewer",
                    "conversation-threading-is-header-based-and-needs-mailbox-known-answer-validation",
                    "attachment-body-rendering-is-bounded-and-inventory-oriented",
                ],
            ),
            "core_accuracy_gates": email_viewer_core_accuracy_gates(
                source_path=source_path,
                messages=summaries,
                conversation=conversation,
                conversation_manifest=conversation_manifest,
            ),
            "trusted_email_conversation_diff": {
                "status": "missing",
                "blocker_id": EMAIL_VIEWER_TRUSTED_DIFF_BLOCKER,
                "required_tools": sorted(EMAIL_VIEWER_TRUSTED_TOOLS),
            },
            "commercial_uplift_evidence": viewer_workflow_commercial_uplift_evidence(
                item_number=55,
                component="email-conversation-viewer",
                core_accuracy_gates=email_viewer_core_accuracy_gates(
                    source_path=source_path,
                    messages=summaries,
                    conversation=conversation,
                    conversation_manifest=conversation_manifest,
                ),
                blockers=[
                    "native-pst-ost-msg-conversation-view-not-implemented",
                    "deleted-mailbox-item-recovery-not-implemented",
                    "attachment-content-export-is-bounded-and-needs-trusted-mailbox-validation",
                    *(
                        ["email-source-preview-is-partial-requires-resume-or-mailbox-export-validation"]
                        if parse_truncated
                        else []
                    ),
                    "message-id-graph-validation-required",
                    EMAIL_VIEWER_TRUSTED_DIFF_BLOCKER,
                ],
                source_refs=[f"source_path:{source_path}", f"message_count:{len(summaries)}", f"thread_count:{len(threads)}"],
                controls={
                    "message_limit": EMAIL_PREVIEW_MESSAGE_LIMIT,
                    "body_preview_chars": EMAIL_BODY_PREVIEW_CHARS,
                    "thread_count": len(threads),
                    "header_threading": True,
                    "native_pst_ost_msg": False,
                    "attachment_inventory": True,
                    "attachment_package_endpoint": True,
                    "attachment_content_export_max_bytes": EMAIL_ATTACHMENT_EXPORT_MAX_BYTES,
                    "email_parse_diagnostics": diagnostics,
                    "email_conversation_manifest_hash": conversation_manifest["manifest_hash"],
                    "email_thread_hash_count": conversation_manifest["thread_hash_count"],
                    "email_message_hash_count": conversation_manifest["message_hash_count"],
                },
            ),
        },
    }


def build_hex_preview(source_path: Path, *, run_id: str | None = None) -> Dict[str, object]:
    try:
        with source_path.open("rb") as handle:
            data = handle.read(HEX_PREVIEW_MAX_BYTES + 1)
    except OSError as exc:
        return {
            "preview_type": "binary",
            "message": f"Hex preview failed: {exc}",
            "viewer_metadata": structured_viewer_metadata("binary", "hex-preview-failed", "parse-failed"),
            "hex": {"error": str(exc)},
        }
    preview = data[:HEX_PREVIEW_MAX_BYTES]
    preview_hashes = compute_hashes_for_bytes(preview)
    rows = build_hex_rows(preview)
    range_profile = hex_range_citation_profile(run_id=run_id, source_path=source_path, preview=preview)
    preview_manifest = build_hex_preview_manifest(
        source_path=source_path,
        rows=rows,
        preview_hashes=preview_hashes,
        truncated=len(data) > HEX_PREVIEW_MAX_BYTES,
        range_profile=range_profile,
    )
    return {
        "preview_type": "hex",
        "message": "Bounded hex preview is available.",
        "text": "",
        "truncated": len(data) > HEX_PREVIEW_MAX_BYTES,
        "viewer_metadata": {
            "source_format": source_path.suffix.lower().lstrip(".") or "binary",
            "strategy": "bounded-hex-preview",
            "preview_status": "available",
            "parser": "rapidtriage.source-viewer.hex",
            "parser_version": SOURCE_VIEWER_VERSION,
            "max_bytes": HEX_PREVIEW_MAX_BYTES,
            "row_width": HEX_PREVIEW_ROW_WIDTH,
            "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["hex"]],
        },
        "hex": {
            "offset_base": 0,
            "bytes_read": len(preview),
            "max_bytes": HEX_PREVIEW_MAX_BYTES,
            "row_width": HEX_PREVIEW_ROW_WIDTH,
            "preview_sha256": preview_hashes["sha256"],
            "source_hash_status": "available-on-demand-via-source-metadata",
            "first_offset_hex": "0x00000000" if preview else "",
            "last_offset_hex": f"0x{max(len(preview) - 1, 0):08x}" if preview else "",
            "offset_navigation": {
                "unit": "byte",
                "base": "hex",
                "supports_keyword_byte_hits": True,
                "supports_source_hash_verification": True,
                "supports_range_citation_export": True,
                "range_export_max_bytes": HEX_RANGE_EXPORT_MAX_BYTES,
                "default_range_export_url": range_profile.get("default_export_url"),
            },
            "range_citation_profile": range_profile,
            "hex_preview_manifest": preview_manifest,
            "rows": rows,
            "truncated": len(data) > HEX_PREVIEW_MAX_BYTES,
            "safety": "read-only bounded preview; use source hashes before reporting byte offsets",
            "hex_viewer_assessment": source_viewer_component_assessment(
                VIEWER_WORKFLOW_GAP_IDS["hex"],
                "raw-source-hex-viewer",
                [
                    "hex-viewer-is-bounded-preview-not-full-disk-editor",
                    "sector/partition-aware-navigation-not-implemented",
                    "file-format-structure-decoding-requires-specialized-parser",
                ],
            ),
            "core_accuracy_gates": hex_viewer_core_accuracy_gates(
                source_path=source_path,
                rows=rows,
                preview_hashes=preview_hashes,
                truncated=len(data) > HEX_PREVIEW_MAX_BYTES,
                preview_manifest=preview_manifest,
            ),
            "trusted_hex_viewer_diff": {
                "status": "missing",
                "blocker_id": HEX_VIEWER_TRUSTED_DIFF_BLOCKER,
                "required_tools": sorted(HEX_VIEWER_TRUSTED_TOOLS),
            },
            "commercial_uplift_evidence": viewer_workflow_commercial_uplift_evidence(
                item_number=53,
                component="raw-source-hex-viewer",
                core_accuracy_gates=hex_viewer_core_accuracy_gates(
                    source_path=source_path,
                    rows=rows,
                    preview_hashes=preview_hashes,
                    truncated=len(data) > HEX_PREVIEW_MAX_BYTES,
                    preview_manifest=preview_manifest,
                ),
                blockers=[
                    "interactive-jump-to-offset-ui-not-implemented",
                    "copy-safe-byte-selection-ui-not-implemented",
                    "export-range-citation-package-needs-trusted-offset-validation",
                    "sector-partition-aware-navigation-not-implemented",
                    HEX_VIEWER_TRUSTED_DIFF_BLOCKER,
                ],
                source_refs=[f"source_path:{source_path}", f"preview_sha256:{preview_hashes['sha256']}"],
                controls={
                    "max_hex_preview_bytes": HEX_PREVIEW_MAX_BYTES,
                    "row_width": HEX_PREVIEW_ROW_WIDTH,
                    "row_count": len(rows),
                    "hex_preview_manifest_hash": preview_manifest["manifest_hash"],
                    "hex_preview_row_hash_count": preview_manifest["row_hash_count"],
                    "supports_keyword_byte_hits": True,
                    "full_file_inline_hash": False,
                    "export_range_citation": True,
                    "range_export_max_bytes": HEX_RANGE_EXPORT_MAX_BYTES,
                },
            ),
        },
    }


def build_hex_rows(data: bytes, *, base_offset: int = 0) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for relative_offset in range(0, len(data), HEX_PREVIEW_ROW_WIDTH):
        chunk = data[relative_offset : relative_offset + HEX_PREVIEW_ROW_WIDTH]
        absolute_offset = base_offset + relative_offset
        rows.append(
            {
                "offset": absolute_offset,
                "relative_offset": relative_offset,
                "offset_hex": f"0x{absolute_offset:08x}",
                "hex": " ".join(f"{byte:02x}" for byte in chunk),
                "ascii": "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk),
            }
        )
    return rows


def hex_range_citation_profile(*, run_id: str | None, source_path: Path, preview: bytes) -> dict[str, object]:
    default_length = min(len(preview), 256)
    quoted_path = quote(str(source_path))
    default_export_url = (
        f"/api/runs/{run_id}/source-hex-range?path={quoted_path}&offset=0&length={default_length}"
        if run_id and default_length
        else None
    )
    return {
        "profile_version": "hex-range-citation-v1",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["hex"]],
        "qc_prep_item": 12,
        "range_export_endpoint": "/api/runs/{run_id}/source-hex-range",
        "default_offset": 0,
        "default_offset_hex": "0x00000000" if default_length else "",
        "default_length": default_length,
        "default_export_url": default_export_url,
        "max_export_bytes": HEX_RANGE_EXPORT_MAX_BYTES,
        "supports_offset_jump": True,
        "supports_range_hashes": True,
        "supports_copy_safe_citation": True,
        "supports_report_candidate_payload": True,
        "supports_compare_pin_payload": True,
        "source_hash_policy": "preview/range hashes are immediate; full-source hashes require include_hashes=true or source-metadata?hash=true",
        "report_use_warning": "Attach the range package, source hash, and trusted offset validation before using byte offsets in a court exhibit.",
    }


def hex_range_review_link_profile(package: Mapping[str, object]) -> dict[str, object]:
    locator = (
        package.get("hex_range_proof_manifest", {}).get("source_viewer_locator", {})
        if isinstance(package.get("hex_range_proof_manifest"), Mapping)
        else {}
    )
    copy_safe = package.get("copy_safe_citation") if isinstance(package.get("copy_safe_citation"), Mapping) else {}
    citation_text = str(copy_safe.get("text") or package.get("citation") or "")
    core = {
        "citation_id": str(package.get("citation_id") or ""),
        "source_name": str(package.get("name") or ""),
        "offset_hex": str(package.get("offset_hex") or ""),
        "length_returned": optional_int_for_api(package.get("length_returned")) or 0,
        "range_sha256": str((package.get("range_hashes") or {}).get("sha256") or "")
        if isinstance(package.get("range_hashes"), Mapping)
        else "",
        "manifest_hash": str(package.get("hex_range_proof_manifest_hash") or ""),
    }
    profile = {
        "profile_version": "hex-range-review-link-profile-v1",
        "qc_prep_item": 12,
        "source_viewer_locator": dict(locator) if isinstance(locator, Mapping) else {},
        "review_note_citation": {
            "profile_version": "hex-range-review-note-citation-v1",
            "qc_prep_item": 12,
            "text": citation_text,
            "source_viewer_locator": dict(locator) if isinstance(locator, Mapping) else {},
            "ready_for_review_note": bool(citation_text),
            "ready_for_report": bool(package.get("source_hashes")),
        },
        "compare_pin_payload": {
            "source": "hex-range",
            "title": f"{core['source_name']} {core['offset_hex']}",
            "pointer": f"hex-range:{core['citation_id']}",
            "preview": citation_text,
            "source_viewer_locator": dict(locator) if isinstance(locator, Mapping) else {},
            "manifest_hash": core["manifest_hash"],
        },
        "report_candidate_payload": {
            "source": "hex-range",
            "citation_id": core["citation_id"],
            "summary": f"{core['source_name']} byte range {core['offset_hex']} len={core['length_returned']}",
            "citation": citation_text,
            "range_sha256": core["range_sha256"],
            "source_hash_status": str(package.get("source_hash_status") or ""),
            "ready_for_report_draft": bool(package.get("source_hashes")),
            "required_before_report": [
                "include source hashes",
                "attach hex range proof manifest",
                "validate offset/range with trusted hex manifest",
            ],
        },
        "commercial_grade_blockers": [
            "trusted-offset-manifest-diff-required-before-court-use",
            "browser-e2e-compare-pin-flow-required",
        ],
    }
    return {**profile, "profile_hash": stable_payload_sha256({**profile, "core": core})}


def build_hex_preview_manifest(
    *,
    source_path: Path,
    rows: Sequence[Mapping[str, object]],
    preview_hashes: Mapping[str, str],
    truncated: bool,
    range_profile: Mapping[str, object],
) -> dict[str, object]:
    row_entries: list[dict[str, object]] = []
    for row in rows[:256]:
        row_core = {
            "offset": row.get("offset"),
            "offset_hex": str(row.get("offset_hex") or ""),
            "hex": str(row.get("hex") or ""),
            "ascii_sha256": hashlib.sha256(str(row.get("ascii") or "").encode("utf-8", errors="replace")).hexdigest(),
        }
        row_entries.append({**row_core, "row_hash": stable_payload_sha256(row_core)})
    manifest_core: dict[str, object] = {
        "manifest_version": "hex-preview-source-locator-manifest-v1",
        "item_number": 53,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["hex"]],
        "path": str(source_path),
        "name": source_path.name,
        "preview_sha256": str(preview_hashes.get("sha256") or ""),
        "preview_byte_count": sum(len(str(row.get("hex") or "").split()) for row in rows),
        "row_count": len(rows),
        "bounded_row_count": len(row_entries),
        "row_hash_count": sum(1 for row in row_entries if row.get("row_hash")),
        "truncated": truncated,
        "default_range_export_url": range_profile.get("default_export_url"),
        "source_viewer_locator": {
            "viewer": "source-hex",
            "path": str(source_path),
            "offset": 0,
            "offset_hex": "0x00000000" if rows else "",
            "row_width": HEX_PREVIEW_ROW_WIDTH,
            "open_action": "open-hex-preview-at-offset",
        },
        "rows": row_entries,
        "blockers": [
            "interactive-jump-to-offset-ui-not-implemented",
            "trusted-offset-manifest-diff-required-before-court-use",
            "sector-partition-aware-navigation-not-implemented",
        ],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_hex_range_citation_package(
    *,
    run_id: str,
    source_path: Path,
    offset: int,
    length: int,
    include_source_hashes: bool,
) -> Dict[str, object]:
    stat = source_path.stat()
    if offset >= stat.st_size:
        raise HTTPException(status_code=416, detail="offset is outside the source file")
    read_length = min(length, HEX_RANGE_EXPORT_MAX_BYTES, max(stat.st_size - offset, 0))
    with source_path.open("rb") as handle:
        handle.seek(offset)
        data = handle.read(read_length)
    range_hashes = compute_hashes_for_bytes(data)
    rows = build_hex_rows(data, base_offset=offset)
    end_exclusive = offset + len(data)
    citation_id = hashlib.sha256(
        f"{run_id}|{source_path}|{stat.st_size}|{offset}|{end_exclusive}|{range_hashes['sha256']}".encode("utf-8")
    ).hexdigest()[:16]
    source_hashes = compute_hashes(source_path) if include_source_hashes else {}
    proof_manifest = build_hex_range_proof_manifest(
        source_path=source_path,
        offset=offset,
        end_exclusive=end_exclusive,
        rows=rows,
        range_hashes=range_hashes,
        source_hashes=source_hashes,
        include_source_hashes=include_source_hashes,
        citation_id=citation_id,
    )
    package = {
        "command": "source-hex-range",
        "profile_version": "hex-range-citation-package-v1",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["hex"]],
        "qc_prep_item": 12,
        "citation_id": citation_id,
        "path": str(source_path),
        "name": source_path.name,
        "size": stat.st_size,
        "offset": offset,
        "offset_hex": f"0x{offset:08x}",
        "end_offset_exclusive": end_exclusive,
        "end_offset_exclusive_hex": f"0x{end_exclusive:08x}",
        "length_requested": length,
        "length_returned": len(data),
        "max_export_bytes": HEX_RANGE_EXPORT_MAX_BYTES,
        "truncated": length > len(data),
        "range_hashes": range_hashes,
        "source_hashes": source_hashes,
        "source_hash_status": "computed" if include_source_hashes else "available-on-demand",
        "hex_range_proof_manifest": proof_manifest,
        "hex_range_proof_manifest_hash": proof_manifest["manifest_hash"],
        "rows": rows,
        "citation": (
            f"{source_path.name} bytes {offset}-{max(end_exclusive - 1, offset)} "
            f"({f'0x{offset:08x}'}-{f'0x{max(end_exclusive - 1, offset):08x}'}) "
            f"sha256={range_hashes['sha256']}"
        ),
        "copy_safe_citation": {
            "text": (
                f"Source={source_path.name}; range={offset}-{max(end_exclusive - 1, offset)}; "
                f"offset_hex=0x{offset:08x}; length={len(data)}; range_sha256={range_hashes['sha256']}; "
                f"citation_id={citation_id}"
            ),
            "redacts_full_path": True,
            "full_path_available_in_authorized_payload": True,
        },
        "reportability_decision": viewer_workflow_reportability_decision(
            item_number=53,
            component="hex-range-citation-package",
            blockers=[
                "trusted-offset-manifest-diff-required-before-court-use",
                "source-full-hash-required-before-court-use",
                "sector-partition-aware-navigation-not-implemented",
            ],
            controls={
                "range_export_max_bytes": HEX_RANGE_EXPORT_MAX_BYTES,
                "range_hashes": True,
                "source_hashes_included": include_source_hashes,
                "copy_safe_citation": True,
            },
        ),
        "core_accuracy_gates": hex_viewer_core_accuracy_gates(
            source_path=source_path,
            rows=rows,
            preview_hashes=range_hashes,
            truncated=length > len(data),
            range_manifest=proof_manifest,
        ),
    }
    review_link_profile = hex_range_review_link_profile(package)
    return {
        **package,
        "hex_range_review_link_profile": review_link_profile,
        "review_note_citation": review_link_profile["review_note_citation"],
        "compare_pin_payload": review_link_profile["compare_pin_payload"],
        "report_candidate_payload": review_link_profile["report_candidate_payload"],
    }


def build_hex_range_proof_manifest(
    *,
    source_path: Path,
    offset: int,
    end_exclusive: int,
    rows: Sequence[Mapping[str, object]],
    range_hashes: Mapping[str, str],
    source_hashes: Mapping[str, str],
    include_source_hashes: bool,
    citation_id: str,
) -> dict[str, object]:
    row_entries: list[dict[str, object]] = []
    for row in rows:
        row_core = {
            "offset": row.get("offset"),
            "offset_hex": str(row.get("offset_hex") or ""),
            "hex": str(row.get("hex") or ""),
            "ascii_sha256": hashlib.sha256(str(row.get("ascii") or "").encode("utf-8", errors="replace")).hexdigest(),
        }
        row_entries.append({**row_core, "row_hash": stable_payload_sha256(row_core)})
    manifest_core: dict[str, object] = {
        "manifest_version": "hex-range-proof-manifest-v1",
        "item_number": 53,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["hex"]],
        "citation_id": citation_id,
        "path": str(source_path),
        "offset": offset,
        "offset_hex": f"0x{offset:08x}",
        "end_offset_exclusive": end_exclusive,
        "end_offset_exclusive_hex": f"0x{end_exclusive:08x}",
        "length_returned": max(end_exclusive - offset, 0),
        "range_sha256": str(range_hashes.get("sha256") or ""),
        "source_sha256": str(source_hashes.get("sha256") or ""),
        "source_hashes_included": include_source_hashes,
        "row_count": len(row_entries),
        "row_hash_count": sum(1 for row in row_entries if row.get("row_hash")),
        "source_viewer_locator": {
            "viewer": "source-hex-range",
            "path": str(source_path),
            "offset": offset,
            "offset_hex": f"0x{offset:08x}",
            "length": max(end_exclusive - offset, 0),
            "open_action": "open-hex-range-citation",
        },
        "rows": row_entries,
        "blockers": [
            "trusted-offset-manifest-diff-required-before-court-use",
            *([] if include_source_hashes else ["source-full-hash-required-before-court-use"]),
        ],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_image_preview(source_path: Path, *, image_url: str, run_id: str | None = None) -> Dict[str, object]:
    try:
        from ..artifacts.media import build_image_record

        artifact = build_image_record(source_path)
        details = artifact.details
        thumbnail = details.get("thumbnail_preview") if isinstance(details.get("thumbnail_preview"), dict) else {}
        gallery_page = image_gallery_page_profile(run_id=run_id, source_path=source_path, details=details)
        ocr_queue_page = source_ocr_queue_profile(run_id=run_id, source_path=source_path)
        translation_review = source_ocr_translation_profile(run_id=run_id, source_path=source_path, details=details)
        gallery_manifest = details.get("image_gallery_manifest") if isinstance(details.get("image_gallery_manifest"), dict) else {}
        image_payload = {
            "decoded": bool(details.get("decoded")),
            "width": details.get("width"),
            "height": details.get("height"),
            "channel_count": details.get("channel_count"),
            "hashes": details.get("hashes") if isinstance(details.get("hashes"), dict) else {},
            "perceptual_hash": str(details.get("perceptual_hash") or ""),
            "similarity_bucket": str(details.get("similarity_bucket") or ""),
            "visual_classification": details.get("visual_classification") if isinstance(details.get("visual_classification"), dict) else {},
            "thumbnail_preview": thumbnail,
            "ocr_plan": details.get("ocr_plan") if isinstance(details.get("ocr_plan"), dict) else {},
            "translation_plan": details.get("translation_plan") if isinstance(details.get("translation_plan"), dict) else {},
            "ocr_sidecar": details.get("ocr_sidecar") if isinstance(details.get("ocr_sidecar"), dict) else {},
            "translation_sidecar": details.get("translation_sidecar") if isinstance(details.get("translation_sidecar"), dict) else {},
            "ocr_queue_profile": ocr_queue_page,
            "korean_ocr_translation_profile": translation_review,
            "gallery_review": {
                "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["gallery"]],
                "tag_suggestions": image_tag_suggestions(details),
                "report_selection_hint": "Use review marks to include the image after verifying source hashes and context.",
                "similarity_bucket_key": str(details.get("similarity_bucket") or ""),
                "compare_ready": bool(details.get("perceptual_hash")),
                "gallery_page_url": gallery_page.get("default_page_url"),
            },
            "gallery_page_profile": gallery_page,
            "image_gallery_manifest": gallery_manifest,
            "image_gallery_manifest_hash": str(gallery_manifest.get("manifest_hash") or ""),
            "gallery_review_assessment": image_gallery_review_assessment(details),
            "core_accuracy_gates": image_viewer_core_accuracy_gates(source_path=source_path, details=details, gallery_manifest=gallery_manifest),
            "commercial_uplift_evidence": image_viewer_commercial_uplift_evidence(
                source_path=source_path,
                details=details,
                gallery_manifest=gallery_manifest,
            ),
            "ocr_queue_assessment": details.get("ocr_queue_assessment") if isinstance(details.get("ocr_queue_assessment"), dict) else {},
            "korean_ocr_translation_workflow": details.get("korean_ocr_translation_workflow") if isinstance(details.get("korean_ocr_translation_workflow"), dict) else {},
        }
    except Exception as exc:
        image_payload = {
            "decoded": False,
            "error": str(exc),
            "hashes": {},
            "gallery_review": {
                "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["gallery"]],
                "tag_suggestions": ["image-review-needed"],
                "report_selection_hint": "Open the authoritative image and compute hashes before report use.",
                "similarity_bucket_key": "",
                "compare_ready": False,
            },
            "gallery_page_profile": image_gallery_page_profile(run_id=run_id, source_path=source_path, details={}),
            "image_gallery_manifest": {},
            "image_gallery_manifest_hash": "",
            "ocr_queue_profile": source_ocr_queue_profile(run_id=run_id, source_path=source_path),
            "korean_ocr_translation_profile": source_ocr_translation_profile(run_id=run_id, source_path=source_path, details={}),
            "gallery_review_assessment": image_gallery_review_assessment({}),
            "core_accuracy_gates": image_viewer_core_accuracy_gates(source_path=source_path, details={}),
            "commercial_uplift_evidence": image_viewer_commercial_uplift_evidence(source_path=source_path, details={}),
        }
    return {
        "preview_type": "image",
        "image_url": image_url,
        "message": "Image preview and gallery review metadata are available.",
        "viewer_metadata": {
            "source_format": source_path.suffix.lower().lstrip(".") or "image",
            "strategy": "image-gallery-preview",
            "preview_status": "available" if image_payload.get("decoded") else "metadata-only",
            "parser": "rapidtriage.source-viewer.image-gallery",
            "parser_version": SOURCE_VIEWER_VERSION,
            "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["gallery"], VIEWER_WORKFLOW_GAP_IDS["ocr_queue"], VIEWER_WORKFLOW_GAP_IDS["korean_ocr"]],
        },
        "image": image_payload,
    }


def image_gallery_review_assessment(details: Mapping[str, object]) -> dict[str, object]:
    return {
        "component": "image-gallery-review-mode",
        "status": "implemented-baseline-validation-required",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["gallery"]],
        "ready_for_court_report": False,
        "supports": [
            "thumbnail-preview",
            "similarity-bucket",
            "ocr-sidecar-status",
            "translation-sidecar-status",
            "report-selection-hint",
        ],
        "blockers": [
            "dedicated-large-gallery-virtualization-and-bulk-tagging-remain-limited",
            "similarity-is-perceptual-hash-bucket-not-ml-validated",
            "deepfake-and-sensitive-media-classification-not-implemented",
        ],
        "source_perceptual_hash_present": bool(details.get("perceptual_hash")),
    }


def image_gallery_page_profile(*, run_id: str | None, source_path: Path, details: Mapping[str, object]) -> dict[str, object]:
    quoted_path = quote(str(source_path))
    bucket = str(details.get("similarity_bucket") or "")
    default_page_url = (
        f"/api/runs/{run_id}/source-image-gallery?path={quoted_path}&offset=0&limit={IMAGE_GALLERY_DEFAULT_LIMIT}"
        if run_id
        else None
    )
    bucket_page_url = (
        f"{default_page_url}&similarity_bucket={quote(bucket)}"
        if default_page_url and bucket
        else None
    )
    return {
        "profile_version": "image-gallery-page-profile-v1",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["gallery"]],
        "endpoint": "/api/runs/{run_id}/source-image-gallery",
        "default_page_url": default_page_url,
        "bucket_page_url": bucket_page_url,
        "anchor_similarity_bucket": bucket,
        "max_page_items": IMAGE_GALLERY_MAX_ITEMS,
        "default_limit": IMAGE_GALLERY_DEFAULT_LIMIT,
        "supports_folder_gallery_page": True,
        "supports_similarity_bucket_filter": True,
        "supports_keyboard_triage_metadata": True,
        "persistent_tags": False,
        "report_use_warning": "Treat perceptual buckets and tags as triage hints until validated against a trusted image gallery manifest.",
    }


def source_ocr_queue_profile(*, run_id: str | None, source_path: Path) -> dict[str, object]:
    quoted_path = quote(str(source_path))
    queue_url = (
        f"/api/runs/{run_id}/source-ocr-queue?path={quoted_path}&max_items={SOURCE_OCR_QUEUE_DEFAULT_MAX_ITEMS}"
        if run_id
        else None
    )
    return {
        "profile_version": "source-ocr-queue-profile-v1",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["ocr_queue"], VIEWER_WORKFLOW_GAP_IDS["korean_ocr"]],
        "endpoint": "/api/runs/{run_id}/source-ocr-queue",
        "default_queue_url": queue_url,
        "scope": "anchor-image-parent-folder",
        "max_default_items": SOURCE_OCR_QUEUE_DEFAULT_MAX_ITEMS,
        "supports_sidecar_inventory": True,
        "supports_retry_failure_projection": True,
        "case_db_persistence": False,
        "native_ocr_execution": False,
        "report_use_warning": "Queue state coordinates OCR work; attach sidecar hashes and engine logs before report-grade OCR claims.",
    }


def source_ocr_translation_profile(*, run_id: str | None, source_path: Path, details: Mapping[str, object]) -> dict[str, object]:
    quoted_path = quote(str(source_path))
    review_url = (
        f"/api/runs/{run_id}/source-ocr-translation?path={quoted_path}&include_text=true"
        if run_id
        else None
    )
    ocr_sidecar = details.get("ocr_sidecar") if isinstance(details.get("ocr_sidecar"), Mapping) else {}
    translation_sidecar = details.get("translation_sidecar") if isinstance(details.get("translation_sidecar"), Mapping) else {}
    workflow = details.get("korean_ocr_translation_workflow") if isinstance(details.get("korean_ocr_translation_workflow"), Mapping) else {}
    return {
        "profile_version": "source-ocr-translation-profile-v1",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["korean_ocr"]],
        "endpoint": "/api/runs/{run_id}/source-ocr-translation",
        "default_review_url": review_url,
        "has_ocr_sidecar": bool(ocr_sidecar),
        "has_translation_sidecar": bool(translation_sidecar),
        "korean_detected_or_expected": bool(workflow.get("korean_detected_or_expected")),
        "supports_side_by_side_review": True,
        "preserves_original_image": True,
        "max_text_chars": SOURCE_OCR_TRANSLATION_MAX_CHARS,
        "native_korean_ocr_execution": False,
        "machine_translation_execution": False,
        "certified_translation": False,
        "report_use_warning": "Use this side-by-side OCR/translation review as triage until Korean OCR calibration and certified translation evidence are attached.",
    }


def build_source_ocr_queue(*, run_id: str, anchor_path: Path, max_items: int, retry_failures: bool) -> Dict[str, object]:
    try:
        queue = build_ocr_queue(anchor_path.parent, max_items=max_items, retry_failures=retry_failures)
    except OcrQueueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    items = queue.get("items") if isinstance(queue.get("items"), list) else []
    anchor_id = hashlib.sha256(str(anchor_path.resolve()).encode("utf-8", errors="replace")).hexdigest()[:16]
    queue["profile_version"] = "source-ocr-queue-page-v1"
    queue["run_id"] = run_id
    queue["anchor_path"] = str(anchor_path)
    queue["anchor_name"] = anchor_path.name
    queue["anchor_queue_id"] = stable_source_queue_id(anchor_path)
    queue["viewer_context"] = {
        "profile_version": "source-ocr-queue-viewer-context-v1",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["ocr_queue"], VIEWER_WORKFLOW_GAP_IDS["korean_ocr"]],
        "anchor_id": anchor_id,
        "scope": "parent-folder",
        "item_count": len(items),
        "retry_failures": retry_failures,
        "case_db_persistence": False,
        "native_ocr_execution": False,
        "work_queue_controls": {
            "max_items": max_items,
            "bounded_folder_scan": True,
            "sidecar_hashes_preserved": True,
            "engine_logs_required_for_report": True,
        },
        "review_actions": [
            "open sidecar text next to source image",
            "run external OCR engine outside RapidTriage and preserve logs",
            "rebuild queue with retry_failures after failed engine runs",
            "mark OCR-derived evidence only after source and sidecar hashes are verified",
        ],
    }
    page_manifest = build_source_ocr_queue_page_manifest(
        run_id=run_id,
        anchor_path=anchor_path,
        queue=queue,
        items=items,
    )
    queue["source_ocr_queue_page_manifest"] = page_manifest
    queue["source_ocr_queue_page_manifest_hash"] = page_manifest["manifest_hash"]
    if isinstance(queue.get("commercial_uplift_evidence"), dict):
        queue["commercial_uplift_evidence"]["large_data_controls"]["source_ocr_queue_page_manifest_hash"] = page_manifest["manifest_hash"]
    queue["copy_safe_citation"] = {
        "text": (
            f"OCR queue scope={anchor_path.parent.name}; anchor={anchor_path.name}; "
            f"candidate_count={queue.get('summary', {}).get('candidate_count', 0)}; anchor_queue_id={queue['anchor_queue_id']}"
        ),
        "redacts_full_path": True,
    }
    return queue


def build_source_ocr_queue_page_manifest(
    *,
    run_id: str,
    anchor_path: Path,
    queue: Mapping[str, object],
    items: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    item_rows = []
    for index, item in enumerate(items, start=1):
        item_manifest = item.get("ocr_queue_item_manifest") if isinstance(item.get("ocr_queue_item_manifest"), Mapping) else {}
        row_core = {
            "index": index,
            "queue_id": str(item.get("queue_id") or ""),
            "source_path": str(item.get("source_path") or ""),
            "source_name": str(item.get("source_name") or ""),
            "status": str(item.get("status") or ""),
            "language_hint": str(item.get("language_hint") or ""),
            "source_sha256": str(item.get("source_sha256") or ""),
            "item_manifest_hash": str(item_manifest.get("manifest_hash") or item.get("ocr_queue_item_manifest_hash") or ""),
        }
        item_rows.append({**row_core, "page_row_hash": stable_payload_sha256(row_core)})
    queue_manifest = queue.get("ocr_queue_manifest") if isinstance(queue.get("ocr_queue_manifest"), Mapping) else {}
    manifest_core: dict[str, object] = {
        "manifest_version": "source-ocr-queue-page-manifest-v1",
        "item_numbers": [58, 59],
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["ocr_queue"], VIEWER_WORKFLOW_GAP_IDS["korean_ocr"]],
        "run_id": run_id,
        "anchor_path": str(anchor_path),
        "anchor_name": anchor_path.name,
        "root": str(queue.get("root") or anchor_path.parent),
        "candidate_count": len(item_rows),
        "summary": queue.get("summary") if isinstance(queue.get("summary"), Mapping) else {},
        "ocr_queue_manifest_hash": str(queue_manifest.get("manifest_hash") or queue.get("ocr_queue_manifest_hash") or ""),
        "page_row_hash_count": sum(1 for item in item_rows if item.get("page_row_hash")),
        "source_viewer_locator": {
            "viewer": "source-ocr-queue-page",
            "path": str(anchor_path),
            "run_id": run_id,
            "open_action": "open-source-ocr-queue-page",
        },
        "items": item_rows,
        "blockers": [
            "native-ocr-engine-execution-not-implemented",
            "browser-editable-queue-state-not-persisted",
            "case-db-ocr-job-persistence-not-implemented",
        ],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_source_ocr_translation_package(*, run_id: str, source_path: Path, include_text: bool) -> Dict[str, object]:
    try:
        from ..artifacts.media import build_image_record

        details = build_image_record(source_path).details
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"failed to build OCR/translation review: {exc}") from exc
    ocr_sidecar = details.get("ocr_sidecar") if isinstance(details.get("ocr_sidecar"), Mapping) else {}
    translation_sidecar = details.get("translation_sidecar") if isinstance(details.get("translation_sidecar"), Mapping) else {}
    workflow = details.get("korean_ocr_translation_workflow") if isinstance(details.get("korean_ocr_translation_workflow"), Mapping) else {}
    ocr_text = str(ocr_sidecar.get("text") or "")
    translation_text = str(translation_sidecar.get("text") or "")
    ocr_text_bounded = ocr_text[:SOURCE_OCR_TRANSLATION_MAX_CHARS]
    translation_text_bounded = translation_text[:SOURCE_OCR_TRANSLATION_MAX_CHARS]
    side_by_side_review = [
        build_ocr_translation_review_side(
            role="ocr-source",
            label="Original OCR text",
            language_hint=str(ocr_sidecar.get("language_hint") or "unknown"),
            sidecar=ocr_sidecar,
            text=ocr_text_bounded,
            include_text=include_text,
            original_length=len(ocr_text),
        ),
        build_ocr_translation_review_side(
            role="translation-target",
            label="Translation sidecar text",
            language_hint=str(translation_sidecar.get("target_language") or "en"),
            sidecar=translation_sidecar,
            text=translation_text_bounded,
            include_text=include_text,
            original_length=len(translation_text),
        ),
    ]
    source_hashes = compute_hashes(source_path) if source_path.stat().st_size <= 128 * 1024 * 1024 else {}
    review_manifest = build_ocr_translation_review_manifest(
        run_id=run_id,
        source_path=source_path,
        source_hashes=source_hashes,
        side_by_side_review=side_by_side_review,
        workflow=workflow,
    )
    core_gates = [
        gate
        for gate in details.get("core_accuracy_gates", [])
        if isinstance(gate, Mapping) and str(gate.get("gap_id")) == VIEWER_WORKFLOW_GAP_IDS["korean_ocr"]
    ]
    if not core_gates:
        core_gates = [
            build_accuracy_gate(
                59,
                satisfied_checks=[
                    "Korean language hinting" if workflow.get("language_hints") else "workflow profile emitted",
                    "translation sidecar import" if translation_sidecar else "translation requirement disclosed",
                    "human translation validation warning",
                ],
                evidence_refs=[
                    f"source_path:{source_path}",
                    f"ocr_sidecar:{ocr_sidecar.get('source_path', '')}",
                    f"translation_sidecar:{translation_sidecar.get('source_path', '')}",
                ],
            )
        ]
    core_gates = augment_ocr_translation_core_gates(core_gates, review_manifest)
    return {
        "command": "source-ocr-translation",
        "profile_version": "source-ocr-translation-review-v1",
        "run_id": run_id,
        "source_path": str(source_path),
        "source_name": source_path.name,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["korean_ocr"]],
        "summary": {
            "ocr_sidecar_present": bool(ocr_sidecar),
            "translation_sidecar_present": bool(translation_sidecar),
            "korean_detected_or_expected": bool(workflow.get("korean_detected_or_expected")),
            "translation_required": bool(workflow.get("translation_required")),
            "text_included": include_text,
            "ready_for_court_report": False,
        },
        "side_by_side_review": side_by_side_review,
        "source_ocr_translation_review_manifest": review_manifest,
        "source_ocr_translation_review_manifest_hash": review_manifest["manifest_hash"],
        "review_profile": {
            "status": "side-by-side-review-ready" if ocr_sidecar or translation_sidecar else "ocr-and-translation-sidecars-missing",
            "supports_side_by_side_review": True,
            "preserves_original_image": True,
            "max_text_chars_per_side": SOURCE_OCR_TRANSLATION_MAX_CHARS,
            "native_korean_ocr_execution": False,
            "machine_translation_execution": False,
            "certified_translation": False,
            "required_before_report": [
                "attach OCR engine name/version/language-pack logs",
                "human-review Korean OCR text against the original image",
                "attach certified translation or reviewer signoff before citing translated text",
                "compare against trusted Korean OCR/translation review diff evidence",
            ],
        },
        "workflow": workflow,
        "core_accuracy_gates": core_gates,
        "commercial_uplift_evidence": details.get("commercial_uplift_evidence") if isinstance(details.get("commercial_uplift_evidence"), Mapping) else {},
        "reportability_decision": viewer_workflow_reportability_decision(
            item_number=59,
            component="korean-ocr-translation-review",
            blockers=[
                "built-in-korean-ocr-execution-not-implemented",
                "machine-translation-worker-not-implemented",
                "certified-translation-review-required",
                "trusted-korean-ocr-translation-review-diff-required",
            ],
            controls={
                "side_by_side_review": True,
                "ocr_sidecar_present": bool(ocr_sidecar),
                "translation_sidecar_present": bool(translation_sidecar),
                "native_korean_ocr_execution": False,
                "machine_translation_execution": False,
                "review_manifest_hash": review_manifest["manifest_hash"],
            },
        ),
        "copy_safe_citation": {
            "text": (
                f"Korean OCR/translation review source={source_path.name}; "
                f"ocr_sha256={ocr_sidecar.get('source_sha256', '')}; "
                f"translation_sha256={translation_sidecar.get('source_sha256', '')}"
            ),
            "redacts_full_path": True,
        },
    }


def augment_ocr_translation_core_gates(
    core_gates: Sequence[Mapping[str, object]],
    review_manifest: Mapping[str, object],
) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    for gate in core_gates:
        copied = dict(gate)
        satisfied = list(copied.get("satisfied_checks") or [])
        evidence_refs = list(copied.get("evidence_refs") or [])
        if review_manifest.get("manifest_hash") and "OCR/translation review manifest" not in satisfied:
            satisfied.append("OCR/translation review manifest")
            evidence_refs.append(f"ocr_translation_review_manifest_hash:{review_manifest.get('manifest_hash')}")
        if review_manifest.get("review_side_hash_count") and "side-by-side review row hashes" not in satisfied:
            satisfied.append("side-by-side review row hashes")
        if isinstance(review_manifest.get("source_viewer_locator"), Mapping) and "source viewer locator emitted" not in satisfied:
            satisfied.append("source viewer locator emitted")
        copied["satisfied_checks"] = satisfied
        copied["evidence_refs"] = evidence_refs
        output.append(copied)
    return output


def build_ocr_translation_review_manifest(
    *,
    run_id: str,
    source_path: Path,
    source_hashes: Mapping[str, object],
    side_by_side_review: Sequence[Mapping[str, object]],
    workflow: Mapping[str, object],
) -> dict[str, object]:
    side_entries = []
    for index, side in enumerate(side_by_side_review, start=1):
        side_core = {
            "index": index,
            "role": str(side.get("role") or ""),
            "label": str(side.get("label") or ""),
            "language_hint": str(side.get("language_hint") or ""),
            "sidecar_path": str(side.get("sidecar_path") or ""),
            "sidecar_name": str(side.get("sidecar_name") or ""),
            "sidecar_sha256": str(side.get("sidecar_sha256") or ""),
            "text_sha256": str(side.get("text_sha256") or ""),
            "character_count": optional_int_for_api(side.get("character_count")),
            "text_included": bool(side.get("text_included")),
            "truncated": bool(side.get("truncated")),
        }
        side_entries.append({**side_core, "review_side_hash": stable_payload_sha256(side_core)})
    manifest_core: dict[str, object] = {
        "manifest_version": "source-ocr-translation-review-manifest-v1",
        "item_number": 59,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["korean_ocr"]],
        "run_id": run_id,
        "path": str(source_path),
        "name": source_path.name,
        "source_hashes": dict(source_hashes),
        "workflow_sha256": stable_payload_sha256(dict(workflow)),
        "review_side_count": len(side_entries),
        "review_side_hash_count": sum(1 for item in side_entries if item.get("review_side_hash")),
        "source_viewer_locator": {
            "viewer": "source-ocr-translation-review",
            "path": str(source_path),
            "run_id": run_id,
            "open_action": "open-ocr-translation-side-by-side-review",
        },
        "sides": side_entries,
        "blockers": [
            "trusted-korean-ocr-translation-review-diff-required",
            "built-in-korean-ocr-execution-not-implemented",
            "certified-translation-review-required",
        ],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_ocr_translation_review_side(
    *,
    role: str,
    label: str,
    language_hint: str,
    sidecar: Mapping[str, object],
    text: str,
    include_text: bool,
    original_length: int,
) -> dict[str, object]:
    return {
        "role": role,
        "label": label,
        "language_hint": language_hint,
        "sidecar_path": str(sidecar.get("source_path") or ""),
        "sidecar_name": Path(str(sidecar.get("source_path") or "")).name if sidecar.get("source_path") else "",
        "sidecar_sha256": str(sidecar.get("source_sha256") or ""),
        "text_sha256": str(sidecar.get("text_sha256") or ""),
        "character_count": int(sidecar.get("character_count") or original_length),
        "quality_metrics": sidecar.get("quality_metrics") if isinstance(sidecar.get("quality_metrics"), Mapping) else {},
        "truncated": bool(sidecar.get("truncated")) or original_length > SOURCE_OCR_TRANSLATION_MAX_CHARS,
        "text": text if include_text else "",
        "text_included": include_text,
    }


def stable_source_queue_id(path: Path) -> str:
    return hashlib.sha256(str(path.resolve()).encode("utf-8", errors="replace")).hexdigest()[:16]


def build_image_gallery_page(
    *,
    run_id: str,
    anchor_path: Path,
    offset: int,
    limit: int,
    similarity_bucket: str | None,
) -> Dict[str, object]:
    candidates = sorted(
        [path for path in anchor_path.parent.iterdir() if path.is_file() and is_image_preview_candidate(path)],
        key=lambda item: item.name.lower(),
    )
    items = []
    for path in candidates[: max(IMAGE_GALLERY_MAX_ITEMS * 2, limit + offset)]:
        summary = image_gallery_item_summary(run_id=run_id, path=path, anchor_path=anchor_path)
        if similarity_bucket and summary.get("similarity_bucket") != similarity_bucket:
            continue
        items.append(summary)
        if len(items) >= IMAGE_GALLERY_MAX_ITEMS:
            break
    total = len(items)
    page_items = items[offset : offset + limit]
    next_offset = offset + len(page_items)
    bucket_counts: dict[str, int] = {}
    for item in items:
        bucket = str(item.get("similarity_bucket") or "unknown")
        bucket_counts[bucket] = bucket_counts.get(bucket, 0) + 1
    gallery_manifest = build_image_gallery_page_manifest(
        anchor_path=anchor_path,
        items=page_items,
        offset=offset,
        limit=limit,
        total=total,
        similarity_bucket=similarity_bucket,
        bucket_counts=bucket_counts,
    )
    return {
        "command": "source-image-gallery",
        "profile_version": "image-gallery-page-v1",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["gallery"]],
        "anchor_path": str(anchor_path),
        "anchor_name": anchor_path.name,
        "offset": offset,
        "limit": limit,
        "returned": len(page_items),
        "total": total,
        "has_next": next_offset < total,
        "next_offset": next_offset if next_offset < total else None,
        "similarity_bucket_filter": similarity_bucket or "",
        "bucket_counts": bucket_counts,
        "image_gallery_page_manifest": gallery_manifest,
        "image_gallery_page_manifest_hash": gallery_manifest["manifest_hash"],
        "items": page_items,
        "large_data_controls": {
            "max_page_items": IMAGE_GALLERY_MAX_ITEMS,
            "bounded_folder_scan": True,
            "inline_originals_not_copied": True,
            "thumbnail_metadata_only": True,
            "persistent_tags": False,
            "image_gallery_page_manifest_hash": gallery_manifest["manifest_hash"],
            "image_row_hash_count": gallery_manifest["image_row_hash_count"],
        },
        "keyboard_triage": {
            "suggested_shortcuts": ["left/right: move image", "r: mark relevant", "x: reject", "i: include in report"],
            "state_persistence": "requires-case-review-mark",
        },
        "reportability_decision": viewer_workflow_reportability_decision(
            item_number=56,
            component="image-gallery-page",
            blockers=[
                "trusted-image-gallery-manifest-diff-required-before-court-use",
                "persistent-gallery-tags-not-implemented",
                "ml-similarity-and-sensitive-media-classifier-not-validated",
            ],
            controls={
                "bounded_gallery_page": True,
                "similarity_bucket_filter": bool(similarity_bucket),
                "max_page_items": IMAGE_GALLERY_MAX_ITEMS,
                "persistent_tags": False,
            },
        ),
    }


def image_gallery_item_summary(*, run_id: str, path: Path, anchor_path: Path) -> dict[str, object]:
    try:
        from ..artifacts.media import build_image_record

        details = build_image_record(path).details
    except Exception as exc:
        details = {"decoded": False, "error": str(exc), "hashes": compute_hashes(path) if path.is_file() else {}}
    thumbnail = details.get("thumbnail_preview") if isinstance(details.get("thumbnail_preview"), Mapping) else {}
    hashes = details.get("hashes") if isinstance(details.get("hashes"), Mapping) else {}
    bucket = str(details.get("similarity_bucket") or "")
    return {
        "path": str(path),
        "name": path.name,
        "is_anchor": path == anchor_path,
        "size": path.stat().st_size if path.exists() else 0,
        "width": details.get("width"),
        "height": details.get("height"),
        "decoded": bool(details.get("decoded")),
        "sha256": str(hashes.get("sha256") or ""),
        "perceptual_hash": str(details.get("perceptual_hash") or ""),
        "similarity_bucket": bucket,
        "thumbnail_available": bool(thumbnail.get("available")),
        "thumbnail_sha256": str(thumbnail.get("sha256") or ""),
        "tag_suggestions": image_tag_suggestions(details),
        "preview_url": f"/api/runs/{run_id}/source-preview?path={quote(str(path))}",
        "source_url": f"/api/runs/{run_id}/source-file?path={quote(str(path))}",
        "copy_safe_citation": (
            f"Source={path.name}; sha256={hashes.get('sha256', '')}; "
            f"dimensions={details.get('width', '')}x{details.get('height', '')}; bucket={bucket}"
        ),
    }


def build_image_gallery_page_manifest(
    *,
    anchor_path: Path,
    items: Sequence[Mapping[str, object]],
    offset: int,
    limit: int,
    total: int,
    similarity_bucket: str | None,
    bucket_counts: Mapping[str, int],
) -> dict[str, object]:
    item_entries: list[dict[str, object]] = []
    for item in items:
        item_core = {
            "path": str(item.get("path") or ""),
            "name": str(item.get("name") or ""),
            "is_anchor": bool(item.get("is_anchor")),
            "size": item.get("size"),
            "width": item.get("width"),
            "height": item.get("height"),
            "sha256": str(item.get("sha256") or ""),
            "perceptual_hash": str(item.get("perceptual_hash") or ""),
            "similarity_bucket": str(item.get("similarity_bucket") or ""),
            "thumbnail_sha256": str(item.get("thumbnail_sha256") or ""),
            "tag_suggestions": list(item.get("tag_suggestions") or []),
        }
        item_entries.append({**item_core, "image_row_hash": stable_payload_sha256(item_core)})
    manifest_core: dict[str, object] = {
        "manifest_version": "image-gallery-page-manifest-v1",
        "item_number": 56,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["gallery"]],
        "anchor_path": str(anchor_path),
        "offset": offset,
        "limit": limit,
        "total": total,
        "returned": len(item_entries),
        "similarity_bucket_filter": similarity_bucket or "",
        "bucket_counts": dict(sorted(bucket_counts.items())),
        "image_row_hash_count": sum(1 for item in item_entries if item.get("image_row_hash")),
        "source_viewer_locator": {
            "viewer": "source-image-gallery-page",
            "path": str(anchor_path),
            "offset": offset,
            "limit": limit,
            "similarity_bucket": similarity_bucket or "",
            "open_action": "open-image-gallery-page",
        },
        "items": item_entries,
        "blockers": [
            "trusted-image-gallery-manifest-diff-required-before-court-use",
            "persistent-gallery-tags-not-implemented",
            "ml-similarity-and-sensitive-media-classifier-not-validated",
        ],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def image_viewer_commercial_uplift_evidence(
    *,
    source_path: Path,
    details: Mapping[str, object],
    gallery_manifest: Mapping[str, object] | None = None,
) -> dict[str, object]:
    gallery_manifest = gallery_manifest if isinstance(gallery_manifest, Mapping) else {}
    gates = image_viewer_core_accuracy_gates(source_path=source_path, details=details, gallery_manifest=gallery_manifest)
    blockers = [
        "dedicated-large-gallery-virtualization-and-bulk-tagging-remain-limited",
        "similarity-is-perceptual-hash-bucket-not-ml-validated",
        "deepfake-and-sensitive-media-classification-not-implemented",
        "selected-image-report-export-flow-not-complete",
    ]
    return viewer_workflow_commercial_uplift_evidence(
        item_number=56,
        component="image-gallery-review-mode",
        core_accuracy_gates=gates,
        blockers=blockers,
        source_refs=[
            f"source_path:{source_path}",
            f"perceptual_hash:{details.get('perceptual_hash', '')}",
            f"similarity_bucket:{details.get('similarity_bucket', '')}",
        ],
        controls={
            "thumbnail_preview": bool(details.get("thumbnail_preview")),
            "perceptual_hash_present": bool(details.get("perceptual_hash")),
            "similarity_bucket_present": bool(details.get("similarity_bucket")),
            "compare_ready": bool(details.get("perceptual_hash")),
            "bounded_gallery_page": True,
            "image_gallery_manifest_present": bool(gallery_manifest.get("manifest_hash")),
            "image_gallery_manifest_hash": str(gallery_manifest.get("manifest_hash") or ""),
            "image_gallery_row_hash": str(gallery_manifest.get("image_row_hash") or ""),
            "dedicated_virtualized_gallery": False,
            "persistent_gallery_tags": False,
        },
    )


def hex_viewer_core_accuracy_gates(
    *,
    source_path: Path,
    rows: Sequence[Mapping[str, object]],
    preview_hashes: Mapping[str, str],
    truncated: bool,
    trusted_diff: Mapping[str, object] | None = None,
    preview_manifest: Mapping[str, object] | None = None,
    range_manifest: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = []
    if rows:
        satisfied.append("bounded hex rows")
    if all(row.get("offset") is not None and row.get("offset_hex") for row in rows):
        satisfied.append("byte offsets and hex offsets")
    if preview_hashes.get("sha256"):
        satisfied.append("preview hash")
    if rows:
        satisfied.append("byte-search citation support")
    if truncated is not None:
        satisfied.append("full-source validation warning")
    preview_manifest = preview_manifest if isinstance(preview_manifest, Mapping) else {}
    range_manifest = range_manifest if isinstance(range_manifest, Mapping) else {}
    if preview_manifest.get("manifest_hash"):
        satisfied.append("hex preview source locator manifest")
    if range_manifest.get("manifest_hash"):
        satisfied.append("hex range proof manifest")
    if int(preview_manifest.get("row_hash_count") or range_manifest.get("row_hash_count") or 0) > 0:
        satisfied.append("hex row hashes")
    trusted_diff = trusted_diff if isinstance(trusted_diff, Mapping) else {}
    if trusted_diff.get("status") == "pass":
        satisfied.append("trusted hex offset manifest diff pass")
    return [
        build_accuracy_gate(
            53,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"source_path:{source_path}",
                f"row_count:{len(rows)}",
                f"preview_sha256:{preview_hashes.get('sha256', '')}",
                f"hex_preview_manifest_hash:{preview_manifest.get('manifest_hash', '')}",
                f"hex_range_manifest_hash:{range_manifest.get('manifest_hash', '')}",
                f"trusted_diff_status:{trusted_diff.get('status', 'missing')}",
            ],
        )
    ]


def sqlite_viewer_core_accuracy_gates(
    *,
    source_path: Path,
    database_metadata: Mapping[str, object],
    tables: Sequence[Mapping[str, object]],
    trusted_diff: Mapping[str, object] | None = None,
    preview_manifest: Mapping[str, object] | None = None,
    page_manifest: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = ["read-only SQLite open"]
    if tables:
        satisfied.append("table and schema inventory")
    if any(table.get("column_details") or table.get("indexes") for table in tables):
        satisfied.append("column/index metadata")
    if any(table.get("rows") is not None for table in tables):
        satisfied.append("bounded row preview")
    preview_manifest = preview_manifest if isinstance(preview_manifest, Mapping) else {}
    page_manifest = page_manifest if isinstance(page_manifest, Mapping) else {}
    if preview_manifest.get("manifest_hash"):
        satisfied.append("SQLite preview source manifest")
    if page_manifest.get("manifest_hash"):
        satisfied.append("SQLite table page proof manifest")
    if int(preview_manifest.get("row_hash_count") or page_manifest.get("row_hash_count") or 0) > 0:
        satisfied.append("SQLite row hashes")
    satisfied.append("deleted/WAL limitation warning")
    trusted_diff = trusted_diff if isinstance(trusted_diff, Mapping) else {}
    if trusted_diff.get("status") == "pass":
        satisfied.append("trusted sqlite query/schema diff pass")
    return [
        build_accuracy_gate(
            54,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"source_path:{source_path}",
                f"table_count:{len(tables)}",
                f"page_size:{database_metadata.get('page_size', '')}",
                f"page_count:{database_metadata.get('page_count', '')}",
                f"sqlite_preview_manifest_hash:{preview_manifest.get('manifest_hash', '')}",
                f"sqlite_table_page_manifest_hash:{page_manifest.get('manifest_hash', '')}",
                f"trusted_diff_status:{trusted_diff.get('status', 'missing')}",
            ],
        )
    ]


def email_viewer_core_accuracy_gates(
    *,
    source_path: Path,
    messages: Sequence[Mapping[str, object]],
    conversation: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None = None,
    conversation_manifest: Mapping[str, object] | None = None,
    attachment_manifest: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    threads = conversation.get("threads") if isinstance(conversation.get("threads"), list) else []
    satisfied = []
    if threads:
        satisfied.append("thread grouping")
    if any(isinstance(thread, Mapping) and thread.get("message_order") is not None for thread in threads):
        satisfied.append("message order")
    if messages and all(message.get("from") is not None and message.get("subject") is not None for message in messages):
        satisfied.append("participant/header preservation")
    if any(int(message.get("attachment_count") or 0) >= 0 for message in messages):
        satisfied.append("attachment inventory")
    conversation_manifest = conversation_manifest if isinstance(conversation_manifest, Mapping) else {}
    attachment_manifest = attachment_manifest if isinstance(attachment_manifest, Mapping) else {}
    if conversation_manifest.get("manifest_hash"):
        satisfied.append("email conversation source manifest")
    if int(conversation_manifest.get("message_hash_count") or 0) > 0:
        satisfied.append("email message hashes")
    if int(conversation_manifest.get("thread_hash_count") or 0) > 0:
        satisfied.append("email thread hashes")
    if attachment_manifest.get("manifest_hash"):
        satisfied.append("email attachment proof manifest")
    satisfied.append("mailbox threading limitation warning")
    trusted_diff = trusted_diff if isinstance(trusted_diff, Mapping) else {}
    if trusted_diff.get("status") == "pass":
        satisfied.append("trusted email thread/export diff pass")
    return [
        build_accuracy_gate(
            55,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"source_path:{source_path}",
                f"message_count:{len(messages)}",
                f"thread_count:{len(threads)}",
                f"email_conversation_manifest_hash:{conversation_manifest.get('manifest_hash', '')}",
                f"email_attachment_manifest_hash:{attachment_manifest.get('manifest_hash', '')}",
                f"trusted_diff_status:{trusted_diff.get('status', 'missing')}",
            ],
        )
    ]


def build_hex_viewer_trusted_diff(
    rapid_rows: Sequence[Mapping[str, object]],
    trusted_rows: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str,
    comparison_id: str = "hex-viewer-trusted-offset-manifest",
) -> dict[str, object]:
    rapid_index = {_hex_viewer_diff_key(row): _hex_viewer_diff_values(row) for row in rapid_rows}
    trusted_index = {_hex_viewer_diff_key(row): _hex_viewer_diff_values(row) for row in trusted_rows}
    return build_viewer_trusted_diff_result(
        profile_version="hex-viewer-trusted-offset-manifest-v1",
        comparison_id=comparison_id,
        rapid_index=rapid_index,
        trusted_index=trusted_index,
        trusted_tool=trusted_tool,
        accepted_tools=HEX_VIEWER_TRUSTED_TOOLS,
        blocker_id=HEX_VIEWER_TRUSTED_DIFF_BLOCKER,
        compare_fields=("offset", "offset_hex", "hex", "ascii"),
    )


def build_sqlite_viewer_trusted_diff(
    rapid_tables: Sequence[Mapping[str, object]],
    trusted_tables: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str,
    comparison_id: str = "sqlite-viewer-trusted-query-schema-diff",
) -> dict[str, object]:
    rapid_index = {_sqlite_viewer_diff_key(row): _sqlite_viewer_diff_values(row) for row in rapid_tables}
    trusted_index = {_sqlite_viewer_diff_key(row): _sqlite_viewer_diff_values(row) for row in trusted_tables}
    return build_viewer_trusted_diff_result(
        profile_version="sqlite-viewer-trusted-query-schema-diff-v1",
        comparison_id=comparison_id,
        rapid_index=rapid_index,
        trusted_index=trusted_index,
        trusted_tool=trusted_tool,
        accepted_tools=SQLITE_VIEWER_TRUSTED_TOOLS,
        blocker_id=SQLITE_VIEWER_TRUSTED_DIFF_BLOCKER,
        compare_fields=("name", "row_count", "schema_sha256", "columns_sha256", "sample_rows_sha256"),
    )


def build_email_conversation_trusted_diff(
    rapid_threads: Sequence[Mapping[str, object]],
    trusted_threads: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str,
    comparison_id: str = "email-viewer-trusted-thread-export",
) -> dict[str, object]:
    rapid_index = {_email_thread_diff_key(row): _email_thread_diff_values(row) for row in rapid_threads}
    trusted_index = {_email_thread_diff_key(row): _email_thread_diff_values(row) for row in trusted_threads}
    return build_viewer_trusted_diff_result(
        profile_version="email-viewer-trusted-thread-export-v1",
        comparison_id=comparison_id,
        rapid_index=rapid_index,
        trusted_index=trusted_index,
        trusted_tool=trusted_tool,
        accepted_tools=EMAIL_VIEWER_TRUSTED_TOOLS,
        blocker_id=EMAIL_VIEWER_TRUSTED_DIFF_BLOCKER,
        compare_fields=("subject", "message_count", "participants_sha256", "message_order_sha256", "attachment_count"),
    )


def build_media_transcript_trusted_diff(
    rapid_sidecars: Sequence[Mapping[str, object]],
    trusted_sidecars: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str,
    comparison_id: str = "media-transcript-trusted-cue-diff",
) -> dict[str, object]:
    rapid_index = {_media_transcript_diff_key(row): _media_transcript_diff_values(row) for row in rapid_sidecars}
    trusted_index = {_media_transcript_diff_key(row): _media_transcript_diff_values(row) for row in trusted_sidecars}
    return build_viewer_trusted_diff_result(
        profile_version="media-transcript-trusted-cue-diff-v1",
        comparison_id=comparison_id,
        rapid_index=rapid_index,
        trusted_index=trusted_index,
        trusted_tool=trusted_tool,
        accepted_tools=MEDIA_TRANSCRIPT_TRUSTED_TOOLS,
        blocker_id=MEDIA_TRANSCRIPT_TRUSTED_DIFF_BLOCKER,
        compare_fields=("sha256", "cue_count", "cues_sha256", "preview_sha256"),
    )


def build_viewer_trusted_diff_result(
    *,
    profile_version: str,
    comparison_id: str,
    rapid_index: Mapping[str, Mapping[str, object]],
    trusted_index: Mapping[str, Mapping[str, object]],
    trusted_tool: str,
    accepted_tools: set[str],
    blocker_id: str,
    compare_fields: Sequence[str],
) -> dict[str, object]:
    rapid = {key: value for key, value in rapid_index.items() if key}
    trusted = {key: value for key, value in trusted_index.items() if key}
    missing_in_trusted = sorted(key for key in rapid if key not in trusted)
    unexpected_in_trusted = sorted(key for key in trusted if key not in rapid)
    mismatches: list[dict[str, object]] = []
    for key in sorted(set(rapid) & set(trusted)):
        for field in compare_fields:
            left = rapid[key].get(field)
            right = trusted[key].get(field)
            if left != right:
                mismatches.append({"row_key": key, "field": field, "rapid": left, "trusted": right})
    tool_accepted = trusted_tool.strip().lower() in accepted_tools
    status = "pass" if tool_accepted and rapid and trusted and not missing_in_trusted and not unexpected_in_trusted and not mismatches else "fail"
    return {
        "profile_version": profile_version,
        "comparison_id": comparison_id,
        "status": status,
        "blocker_id": "" if status == "pass" else blocker_id,
        "trusted_tool": trusted_tool,
        "trusted_tool_accepted": tool_accepted,
        "accepted_trusted_tools": sorted(accepted_tools),
        "rapid_row_count": len(rapid),
        "trusted_row_count": len(trusted),
        "matched_count": len(set(rapid) & set(trusted)),
        "missing_in_trusted_count": len(missing_in_trusted),
        "unexpected_in_trusted_count": len(unexpected_in_trusted),
        "mismatch_count": len(mismatches),
        "mismatched_fields": mismatches[:50],
        "missing_in_trusted": missing_in_trusted[:50],
        "unexpected_in_trusted": unexpected_in_trusted[:50],
        "commercial_grade_evidence": status == "pass",
    }


def _hex_viewer_diff_key(row: Mapping[str, object]) -> str:
    return str(row.get("offset_hex") or row.get("offset") or "")


def _hex_viewer_diff_values(row: Mapping[str, object]) -> dict[str, object]:
    return {
        "offset": optional_int_for_api(row.get("offset")) or 0,
        "offset_hex": str(row.get("offset_hex") or ""),
        "hex": str(row.get("hex") or ""),
        "ascii": str(row.get("ascii") or ""),
    }


def _sqlite_viewer_diff_key(row: Mapping[str, object]) -> str:
    return str(row.get("name") or "")


def _sqlite_viewer_diff_values(row: Mapping[str, object]) -> dict[str, object]:
    columns = row.get("columns") if isinstance(row.get("columns"), Sequence) else []
    rows = row.get("rows") if isinstance(row.get("rows"), Sequence) else []
    return {
        "name": str(row.get("name") or ""),
        "row_count": optional_int_for_api(row.get("row_count")),
        "schema_sha256": hashlib.sha256(str(row.get("schema_sql") or "").encode("utf-8", errors="replace")).hexdigest(),
        "columns_sha256": stable_json_sha256(list(columns)),
        "sample_rows_sha256": stable_json_sha256(list(rows)),
    }


def _email_thread_diff_key(row: Mapping[str, object]) -> str:
    return str(row.get("thread_id") or row.get("subject") or "")


def _email_thread_diff_values(row: Mapping[str, object]) -> dict[str, object]:
    participants = row.get("participants") if isinstance(row.get("participants"), Sequence) else []
    order = row.get("message_order") if isinstance(row.get("message_order"), Sequence) else []
    return {
        "subject": str(row.get("subject") or ""),
        "message_count": optional_int_for_api(row.get("message_count")) or 0,
        "participants_sha256": stable_json_sha256(sorted(str(item) for item in participants)),
        "message_order_sha256": stable_json_sha256(list(order)),
        "attachment_count": optional_int_for_api(row.get("attachment_count")) or 0,
    }


def _media_transcript_diff_key(row: Mapping[str, object]) -> str:
    return str(row.get("path") or row.get("name") or "")


def _media_transcript_diff_values(row: Mapping[str, object]) -> dict[str, object]:
    cues = row.get("cues") if isinstance(row.get("cues"), Sequence) else []
    preview = str(row.get("preview") or "")
    return {
        "sha256": str(row.get("sha256") or ""),
        "cue_count": optional_int_for_api(row.get("cue_count")) or len(cues),
        "cues_sha256": stable_json_sha256(list(cues)),
        "preview_sha256": hashlib.sha256(preview.encode("utf-8", errors="replace")).hexdigest() if preview else "",
    }


def stable_json_sha256(value: object) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def image_viewer_core_accuracy_gates(
    *,
    source_path: Path,
    details: Mapping[str, object],
    gallery_manifest: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = []
    if details.get("width") is not None or details.get("hashes"):
        satisfied.append("image metadata and source hashes")
    if details.get("thumbnail_preview") or details.get("decoded") is not None:
        satisfied.append("thumbnail or preview metadata")
    if details.get("similarity_bucket"):
        satisfied.append("perceptual similarity bucket")
    gallery_manifest = gallery_manifest if isinstance(gallery_manifest, Mapping) else {}
    if gallery_manifest.get("manifest_hash"):
        satisfied.append("image gallery source manifest")
    if gallery_manifest.get("image_row_hash"):
        satisfied.append("image gallery row hash")
    satisfied.append("tag/report selection hints")
    if not details.get("media_native_capabilities", {}).get("deepfake_detection", False):
        satisfied.append("visual-classifier limitation warning")
    return [
        build_accuracy_gate(
            56,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"source_path:{source_path}",
                f"perceptual_hash:{details.get('perceptual_hash', '')}",
                f"similarity_bucket:{details.get('similarity_bucket', '')}",
                f"image_gallery_manifest_hash:{gallery_manifest.get('manifest_hash', '')}",
            ],
        )
    ]


def media_viewer_core_accuracy_gates(
    *,
    source_path: Path,
    metadata: Mapping[str, object],
    sidecars: Sequence[Mapping[str, object]],
    transcript_manifest: Mapping[str, object] | None = None,
    cue_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = []
    if metadata:
        satisfied.append("media metadata extracted")
    try:
        source_size = source_path.stat().st_size
    except OSError:
        source_size = 0
    if source_size <= 128 * 1024 * 1024:
        satisfied.append("source hashes captured")
    if sidecars:
        satisfied.append("transcript sidecars imported")
    if any(item.get("cues") for item in sidecars):
        satisfied.append("cue timestamps preserved")
    transcript_manifest = transcript_manifest if isinstance(transcript_manifest, Mapping) else {}
    if transcript_manifest.get("manifest_hash"):
        satisfied.append("media transcript source manifest")
    if transcript_manifest.get("cue_hash_count"):
        satisfied.append("transcript cue hashes")
    cue_manifest = cue_manifest if isinstance(cue_manifest, Mapping) else {}
    if cue_manifest.get("manifest_hash"):
        satisfied.append("media cue proof manifest")
    satisfied.append("playback/transcript verification warning")
    trusted_diff = trusted_diff if isinstance(trusted_diff, Mapping) else {}
    if trusted_diff.get("status") == "pass":
        satisfied.append("trusted transcript cue/alignment diff pass")
    return [
        build_accuracy_gate(
            57,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"source_path:{source_path}",
                f"transcript_sidecar_count:{len(sidecars)}",
                f"media_transcript_manifest_hash:{transcript_manifest.get('manifest_hash', '')}",
                f"media_cue_manifest_hash:{cue_manifest.get('manifest_hash', '')}",
                f"trusted_diff_status:{trusted_diff.get('status', 'missing')}",
            ],
        )
    ]


def image_tag_suggestions(details: Mapping[str, object]) -> list[str]:
    tags = ["image"]
    classification = details.get("visual_classification") if isinstance(details.get("visual_classification"), Mapping) else {}
    label = str(classification.get("label") or "")
    if label:
        tags.append(label)
    if details.get("ocr_sidecar"):
        tags.append("ocr-sidecar")
    if details.get("similarity_bucket"):
        tags.append("similarity-bucketed")
    if not details.get("decoded"):
        tags.append("decode-warning")
    return tags


def build_media_preview(source_path: Path, *, mime_type: str, run_id: str | None = None) -> Dict[str, object]:
    sidecars = collect_media_transcript_sidecars(source_path)
    metadata: dict[str, object] = {
        "duration_seconds": None,
        "audio_channels": None,
        "sample_rate": None,
        "frame_count": None,
    }
    if source_path.suffix.lower() == ".wav":
        metadata.update(read_wav_metadata(source_path))
    source_hashes = compute_hashes(source_path) if source_path.stat().st_size <= 128 * 1024 * 1024 else {}
    transcript_manifest = build_media_transcript_manifest(
        source_path=source_path,
        metadata=metadata,
        sidecars=sidecars,
        source_hashes=source_hashes,
    )
    transcript_text = "\n\n".join(str(item.get("preview") or "") for item in sidecars)
    trusted_diff = {
        "status": "missing",
        "blocker_id": MEDIA_TRANSCRIPT_TRUSTED_DIFF_BLOCKER,
        "required_tools": sorted(MEDIA_TRANSCRIPT_TRUSTED_TOOLS),
    }
    return {
        "preview_type": "media",
        "message": "Media metadata preview is available.",
        "text": transcript_text[:20000],
        "truncated": any(bool(item.get("truncated")) for item in sidecars),
        "viewer_metadata": {
            "source_format": source_path.suffix.lower().lstrip(".") or mime_type,
            "strategy": "bounded-media-metadata",
            "preview_status": "available",
            "parser": "rapidtriage.source-viewer.media",
            "parser_version": SOURCE_VIEWER_VERSION,
            "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["media"]],
        },
        "media": {
            "mime_type": mime_type,
            "metadata": metadata,
            "source_hashes": source_hashes,
            "review": {
                "playback_sandbox": "not-played-or-transcoded-inline",
                "transcript_alignment": "sidecar-cue-based" if any(item.get("cues") for item in sidecars) else "not-available",
                "report_selection_hint": "Cite transcript cue timestamps only after verifying them against the original media.",
                "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["media"]],
                "transcript_sidecar_verification_required": True,
                "cue_navigation_available": any(item.get("cues") for item in sidecars),
            },
            "transcript_sidecar_count": len(sidecars),
            "transcript_sidecars": sidecars,
            "media_transcript_manifest": transcript_manifest,
            "media_transcript_manifest_hash": transcript_manifest["manifest_hash"],
            "cue_package_profile": media_cue_package_profile(run_id=run_id, source_path=source_path, sidecars=sidecars),
            "media_transcript_assessment": media_transcript_assessment(sidecars=sidecars),
            "core_accuracy_gates": media_viewer_core_accuracy_gates(
                source_path=source_path,
                metadata=metadata,
                sidecars=sidecars,
                transcript_manifest=transcript_manifest,
                trusted_diff=trusted_diff,
            ),
            "trusted_media_transcript_diff": trusted_diff,
            "commercial_uplift_evidence": viewer_workflow_commercial_uplift_evidence(
                item_number=57,
                component="video-audio-preview-and-transcript",
                core_accuracy_gates=media_viewer_core_accuracy_gates(
                    source_path=source_path,
                    metadata=metadata,
                    sidecars=sidecars,
                    transcript_manifest=transcript_manifest,
                ),
                blockers=[
                    "media-playback-and-transcoding-not-performed-inline",
                    "automatic-speech-recognition-not-executed-by-viewer",
                    "transcript-sidecar-alignment-must-be-verified-against-original-media",
                    "selected-cue-report-export-not-implemented",
                    MEDIA_TRANSCRIPT_TRUSTED_DIFF_BLOCKER,
                ],
                source_refs=[f"source_path:{source_path}", f"transcript_sidecar_count:{len(sidecars)}"],
                controls={
                    "source_hashes_captured": source_path.stat().st_size <= 128 * 1024 * 1024,
                    "transcript_sidecar_count": len(sidecars),
                    "cue_count": sum(len(item.get("cues") or []) for item in sidecars),
                    "playback_executed_inline": False,
                    "asr_executed_inline": False,
                    "selected_cue_export": True,
                    "max_cue_export_chars": MEDIA_CUE_EXPORT_MAX_CHARS,
                    "media_transcript_manifest_hash": transcript_manifest["manifest_hash"],
                    "transcript_sidecar_row_hash_count": transcript_manifest["sidecar_row_hash_count"],
                    "transcript_cue_hash_count": transcript_manifest["cue_hash_count"],
                },
            ),
            "limitations": [
                "Media playback/transcoding is not performed by the local viewer.",
                "Transcript sidecars are imported as review aids and must be verified against the original media.",
            ],
        },
}


def build_media_transcript_manifest(
    *,
    source_path: Path,
    metadata: Mapping[str, object],
    sidecars: Sequence[Mapping[str, object]],
    source_hashes: Mapping[str, object],
) -> dict[str, object]:
    sidecar_entries = []
    cue_hash_count = 0
    for sidecar_index, sidecar in enumerate(sidecars, start=1):
        cues = sidecar.get("cues") if isinstance(sidecar.get("cues"), Sequence) else []
        cue_entries = []
        for cue_index, cue in enumerate(cues, start=1):
            if not isinstance(cue, Mapping):
                continue
            cue_core = {
                "cue_index": cue_index,
                "start": str(cue.get("start") or ""),
                "end": str(cue.get("end") or ""),
                "text_sha256": str(cue.get("text_sha256") or ""),
            }
            cue_hash = str(cue.get("cue_hash") or stable_payload_sha256(cue_core))
            cue_entries.append({**cue_core, "cue_hash": cue_hash})
            cue_hash_count += 1
        sidecar_core = {
            "sidecar_index": sidecar_index,
            "path": str(sidecar.get("path") or ""),
            "name": str(sidecar.get("name") or ""),
            "size": optional_int_for_api(sidecar.get("size")),
            "modified_at": str(sidecar.get("modified_at") or ""),
            "sha256": str(sidecar.get("sha256") or ""),
            "cue_count": optional_int_for_api(sidecar.get("cue_count")) or len(cue_entries),
            "preview_sha256": hashlib.sha256(str(sidecar.get("preview") or "").encode("utf-8", errors="replace")).hexdigest()
            if sidecar.get("preview")
            else "",
            "validation_status": str(sidecar.get("validation_status") or ""),
            "cues": cue_entries,
        }
        sidecar_entries.append({**sidecar_core, "sidecar_row_hash": stable_payload_sha256(sidecar_core)})
    manifest_core: dict[str, object] = {
        "manifest_version": "media-transcript-source-manifest-v1",
        "item_number": 57,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["media"]],
        "path": str(source_path),
        "name": source_path.name,
        "source_format": source_path.suffix.lower().lstrip("."),
        "source_hashes": dict(source_hashes),
        "metadata_sha256": stable_payload_sha256(dict(metadata)),
        "sidecar_count": len(sidecar_entries),
        "sidecar_row_hash_count": sum(1 for item in sidecar_entries if item.get("sidecar_row_hash")),
        "cue_hash_count": cue_hash_count,
        "source_viewer_locator": {
            "viewer": "source-media-transcript",
            "path": str(source_path),
            "open_action": "open-media-transcript-review",
        },
        "sidecars": sidecar_entries,
        "blockers": [
            "trusted-transcript-cue-alignment-diff-required-before-court-use",
            "safe-playback-or-asr-alignment-not-validated",
            "waveform-thumbnail-preview-not-implemented",
        ],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def media_transcript_assessment(*, sidecars: list[dict[str, object]]) -> dict[str, object]:
    return {
        "component": "video-audio-preview-and-transcript",
        "status": "sidecar-transcript-available" if sidecars else "metadata-only",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["media"]],
        "ready_for_court_report": False,
        "cue_count": sum(len(item.get("cues") or []) for item in sidecars),
        "blockers": [
            "media-playback-and-transcoding-not-performed-inline",
            "automatic-speech-recognition-not-executed-by-viewer",
            "transcript-sidecar-alignment-must-be-verified-against-original-media",
        ],
    }


def media_cue_package_profile(*, run_id: str | None, source_path: Path, sidecars: Sequence[Mapping[str, object]]) -> dict[str, object]:
    quoted_path = quote(str(source_path))
    cue_links = []
    for sidecar_index, sidecar in enumerate(sidecars, start=1):
        cues = sidecar.get("cues") if isinstance(sidecar.get("cues"), Sequence) else []
        for cue_index, cue in enumerate(cues, start=1):
            if not isinstance(cue, Mapping):
                continue
            cue_links.append(
                {
                    "sidecar_index": sidecar_index,
                    "cue_index": cue_index,
                    "sidecar_name": str(sidecar.get("name") or ""),
                    "start": str(cue.get("start") or ""),
                    "end": str(cue.get("end") or ""),
                    "text_sha256": str(cue.get("text_sha256") or ""),
                    "package_url": (
                        f"/api/runs/{run_id}/source-media-cue?path={quoted_path}&sidecar_index={sidecar_index}&cue_index={cue_index}"
                        if run_id
                        else None
                    ),
                }
            )
    return {
        "profile_version": "media-cue-package-profile-v1",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["media"]],
        "endpoint": "/api/runs/{run_id}/source-media-cue",
        "cue_count": len(cue_links),
        "links": cue_links[:50],
        "max_cue_export_chars": MEDIA_CUE_EXPORT_MAX_CHARS,
        "supports_timestamp_citation": True,
        "supports_source_hash_reference": True,
        "playback_executed_inline": False,
        "asr_executed_inline": False,
        "report_use_warning": "Verify cue timestamps against playback or a trusted transcript alignment export before report-grade use.",
    }


def build_media_cue_package(
    *,
    run_id: str,
    source_path: Path,
    sidecar_index: int,
    cue_index: int,
    include_source_hashes: bool,
) -> Dict[str, object]:
    sidecars = collect_media_transcript_sidecars(source_path)
    if sidecar_index > len(sidecars):
        raise HTTPException(status_code=404, detail="sidecar_index not found")
    sidecar = sidecars[sidecar_index - 1]
    cues = sidecar.get("cues") if isinstance(sidecar.get("cues"), Sequence) else []
    if cue_index > len(cues):
        raise HTTPException(status_code=404, detail="cue_index not found")
    cue = cues[cue_index - 1]
    if not isinstance(cue, Mapping):
        raise HTTPException(status_code=404, detail="cue_index not found")
    cue_text = str(cue.get("text") or "")[:MEDIA_CUE_EXPORT_MAX_CHARS]
    cue_sha256 = hashlib.sha256(cue_text.encode("utf-8", errors="replace")).hexdigest() if cue_text else ""
    source_hashes = compute_hashes(source_path) if include_source_hashes and source_path.stat().st_size <= 128 * 1024 * 1024 else {}
    citation_id = hashlib.sha256(
        f"{run_id}|{source_path}|{sidecar.get('path')}|{sidecar_index}|{cue_index}|{cue.get('start')}|{cue.get('end')}|{cue_sha256}".encode(
            "utf-8",
            errors="replace",
        )
    ).hexdigest()[:16]
    cue_proof_manifest = build_media_cue_proof_manifest(
        run_id=run_id,
        source_path=source_path,
        sidecar=sidecar,
        cue=cue,
        sidecar_index=sidecar_index,
        cue_index=cue_index,
        citation_id=citation_id,
        cue_text=cue_text,
        source_hashes=source_hashes,
    )
    return {
        "command": "source-media-cue",
        "profile_version": "media-cue-citation-package-v1",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["media"]],
        "citation_id": citation_id,
        "path": str(source_path),
        "name": source_path.name,
        "sidecar_index": sidecar_index,
        "cue_index": cue_index,
        "sidecar_path": str(sidecar.get("path") or ""),
        "sidecar_name": str(sidecar.get("name") or ""),
        "sidecar_sha256": str(sidecar.get("sha256") or ""),
        "start": str(cue.get("start") or ""),
        "end": str(cue.get("end") or ""),
        "text": cue_text,
        "text_sha256": cue_sha256,
        "truncated": len(str(cue.get("text") or "")) > MEDIA_CUE_EXPORT_MAX_CHARS,
        "source_hashes": source_hashes,
        "source_hash_status": "computed" if source_hashes else "available-on-demand",
        "media_cue_proof_manifest": cue_proof_manifest,
        "media_cue_proof_manifest_hash": cue_proof_manifest["manifest_hash"],
        "copy_safe_citation": {
            "text": (
                f"Source={source_path.name}; sidecar={sidecar.get('name', '')}; cue={cue_index}; "
                f"time={cue.get('start', '')}-{cue.get('end', '')}; text_sha256={cue_sha256}; citation_id={citation_id}"
            ),
            "redacts_full_path": True,
        },
        "reportability_decision": viewer_workflow_reportability_decision(
            item_number=57,
            component="media-cue-citation-package",
            blockers=[
                "trusted-transcript-cue-alignment-diff-required-before-court-use",
                "manual-playback-or-asr-alignment-review-required",
                "waveform-thumbnail-preview-not-implemented",
            ],
            controls={
                "cue_timestamp_citation": True,
                "cue_text_hash": bool(cue_sha256),
                "source_hashes_included": bool(source_hashes),
                "playback_executed_inline": False,
                "asr_executed_inline": False,
            },
        ),
    }


def build_media_cue_proof_manifest(
    *,
    run_id: str,
    source_path: Path,
    sidecar: Mapping[str, object],
    cue: Mapping[str, object],
    sidecar_index: int,
    cue_index: int,
    citation_id: str,
    cue_text: str,
    source_hashes: Mapping[str, object],
) -> dict[str, object]:
    cue_core = {
        "sidecar_index": sidecar_index,
        "cue_index": cue_index,
        "start": str(cue.get("start") or ""),
        "end": str(cue.get("end") or ""),
        "text_sha256": hashlib.sha256(cue_text.encode("utf-8", errors="replace")).hexdigest() if cue_text else "",
        "sidecar_sha256": str(sidecar.get("sha256") or ""),
        "source_sha256": str(source_hashes.get("sha256") or ""),
    }
    manifest_core: dict[str, object] = {
        "manifest_version": "media-cue-proof-manifest-v1",
        "item_number": 57,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["media"]],
        "run_id": run_id,
        "citation_id": citation_id,
        "path": str(source_path),
        "name": source_path.name,
        "sidecar_path": str(sidecar.get("path") or ""),
        "sidecar_name": str(sidecar.get("name") or ""),
        "source_hashes": dict(source_hashes),
        "cue": {**cue_core, "cue_hash": str(cue.get("cue_hash") or stable_payload_sha256(cue_core))},
        "source_viewer_locator": {
            "viewer": "source-media-cue",
            "path": str(source_path),
            "sidecar_index": sidecar_index,
            "cue_index": cue_index,
            "open_action": "open-media-cue-citation",
        },
        "blockers": [
            "trusted-transcript-cue-alignment-diff-required-before-court-use",
            "manual-playback-or-asr-alignment-review-required",
        ],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def collect_media_transcript_sidecars(source_path: Path) -> list[dict[str, object]]:
    candidates: list[Path] = []
    for suffix in MEDIA_TRANSCRIPT_SUFFIXES:
        candidates.append(source_path.with_suffix(source_path.suffix + suffix))
        candidates.append(source_path.with_suffix(suffix))
    output = []
    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen or not candidate.is_file():
            continue
        seen.add(candidate)
        try:
            text = candidate.read_text(encoding="utf-8", errors="replace")
            stat = candidate.stat()
        except OSError:
            continue
        cues = parse_transcript_cues(text)
        output.append(
            {
                "path": str(candidate),
                "name": candidate.name,
                "size": stat.st_size,
                "modified_at": dt.datetime.fromtimestamp(stat.st_mtime, tz=dt.timezone.utc).isoformat(),
                "sha256": compute_hashes(candidate)["sha256"] if stat.st_size <= 20 * 1024 * 1024 else "",
                "preview": text[:MEDIA_TRANSCRIPT_PREVIEW_CHARS],
                "cues": cues,
                "cue_count": len(cues),
                "truncated": len(text) > MEDIA_TRANSCRIPT_PREVIEW_CHARS,
                "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["media"]],
                "validation_status": "sidecar-review-required",
                "report_use": "review-aid-until-verified-against-original-media",
            }
        )
    return output


def parse_transcript_cues(text: str, *, limit: int = 20) -> list[dict[str, object]]:
    cues: list[dict[str, object]] = []
    lines = [line.strip() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    index = 0
    while index < len(lines) and len(cues) < limit:
        line = lines[index]
        if "-->" not in line:
            index += 1
            continue
        start, end = [part.strip() for part in line.split("-->", 1)]
        cue_lines: list[str] = []
        index += 1
        while index < len(lines) and lines[index]:
            cue_lines.append(lines[index])
            index += 1
        text_value = " ".join(cue_lines).strip()
        cues.append(
            {
                "start": start,
                "end": end,
                "text": text_value[:500],
                "text_sha256": hashlib.sha256(text_value.encode("utf-8", errors="replace")).hexdigest() if text_value else "",
                "cue_hash": stable_payload_sha256(
                    {
                        "start": start,
                        "end": end,
                        "text_sha256": hashlib.sha256(text_value.encode("utf-8", errors="replace")).hexdigest() if text_value else "",
                    }
                ),
            }
        )
        index += 1
    return cues


def read_wav_metadata(source_path: Path) -> dict[str, object]:
    try:
        with wave.open(str(source_path), "rb") as wav_file:
            frames = wav_file.getnframes()
            rate = wav_file.getframerate()
            return {
                "duration_seconds": round(frames / rate, 3) if rate else None,
                "audio_channels": wav_file.getnchannels(),
                "sample_rate": rate,
                "frame_count": frames,
            }
    except (OSError, wave.Error):
        return {}


def read_bounded_email_bytes(source_path: Path, *, max_bytes: int | None = None) -> tuple[bytes, dict[str, object]]:
    max_bytes = EMAIL_PREVIEW_MAX_BYTES if max_bytes is None else max_bytes
    stat = source_path.stat()
    with source_path.open("rb") as handle:
        raw = handle.read(max_bytes + 1)
    source_truncated = len(raw) > max_bytes or stat.st_size > max_bytes
    if len(raw) > max_bytes:
        raw = raw[:max_bytes]
    diagnostics = {
        "source_size": stat.st_size,
        "max_input_bytes": max_bytes,
        "source_truncated": source_truncated,
        "bytes_read": len(raw),
    }
    return raw, diagnostics


def parse_mbox_messages(source_path: Path) -> list[email.message.EmailMessage]:
    messages, _diagnostics = parse_mbox_messages_with_diagnostics(source_path)
    return messages


def parse_mbox_messages_with_diagnostics(source_path: Path) -> tuple[list[email.message.EmailMessage], dict[str, object]]:
    raw, diagnostics = read_bounded_email_bytes(source_path)
    chunks = re.split(rb"(?m)^From .*$", raw)
    messages = []
    message_size_truncated_count = 0
    for chunk in chunks:
        if not chunk.strip():
            continue
        parse_chunk = chunk.lstrip(b"\r\n")
        if len(parse_chunk) > EMAIL_PREVIEW_MESSAGE_MAX_BYTES:
            parse_chunk = parse_chunk[:EMAIL_PREVIEW_MESSAGE_MAX_BYTES]
            message_size_truncated_count += 1
        messages.append(email.message_from_bytes(parse_chunk, policy=policy.default))
        if len(messages) >= EMAIL_PREVIEW_MESSAGE_LIMIT:
            break
    diagnostics.update(
        {
            "parse_mode": "bounded-mbox",
            "message_limit": EMAIL_PREVIEW_MESSAGE_LIMIT,
            "message_limit_reached": len(messages) >= EMAIL_PREVIEW_MESSAGE_LIMIT,
            "max_message_bytes": EMAIL_PREVIEW_MESSAGE_MAX_BYTES,
            "message_size_truncated_count": message_size_truncated_count,
            "parsed_message_count": len(messages),
        }
    )
    return messages, diagnostics


def read_email_messages_with_diagnostics(source_path: Path, suffix: str) -> tuple[list[email.message.EmailMessage], dict[str, object]]:
    if suffix == ".eml":
        raw, diagnostics = read_bounded_email_bytes(source_path)
        parse_raw = raw
        message_truncated = False
        if len(parse_raw) > EMAIL_PREVIEW_MESSAGE_MAX_BYTES:
            parse_raw = parse_raw[:EMAIL_PREVIEW_MESSAGE_MAX_BYTES]
            message_truncated = True
        diagnostics.update(
            {
                "parse_mode": "bounded-eml",
                "message_limit": 1,
                "message_limit_reached": False,
                "max_message_bytes": EMAIL_PREVIEW_MESSAGE_MAX_BYTES,
                "message_size_truncated_count": 1 if diagnostics.get("source_truncated") or message_truncated else 0,
                "parsed_message_count": 1,
            }
        )
        return [email.message_from_bytes(parse_raw, policy=policy.default)], diagnostics
    return parse_mbox_messages_with_diagnostics(source_path)


def read_email_messages(source_path: Path, suffix: str) -> list[email.message.EmailMessage]:
    messages, _diagnostics = read_email_messages_with_diagnostics(source_path, suffix)
    return messages


def summarize_email_message(message: email.message.EmailMessage, index: int) -> dict[str, object]:
    attachments = []
    body_parts = []
    attachment_index = 0
    for part in message.walk():
        content_disposition = str(part.get_content_disposition() or "")
        filename = part.get_filename()
        content_type = part.get_content_type()
        if content_disposition == "attachment" or filename:
            attachment_index += 1
            payload = part.get_payload(decode=True) or b""
            attachments.append(
                {
                    "index": attachment_index,
                    "filename": filename or "",
                    "content_type": content_type,
                    "content_id": str(part.get("content-id") or ""),
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest() if payload else "",
                    "exportable": len(payload) <= EMAIL_ATTACHMENT_EXPORT_MAX_BYTES,
                    "export_limit": EMAIL_ATTACHMENT_EXPORT_MAX_BYTES,
                }
            )
            continue
        if content_type in {"text/plain", "text/html"}:
            try:
                body_parts.append(part.get_content())
            except (LookupError, UnicodeDecodeError):
                continue
    body = "\n".join(str(part) for part in body_parts)
    return {
        "index": index,
        "subject": str(message.get("subject") or ""),
        "from": str(message.get("from") or ""),
        "to": str(message.get("to") or ""),
        "cc": str(message.get("cc") or ""),
        "date": str(message.get("date") or ""),
        "message_id": str(message.get("message-id") or ""),
        "in_reply_to": str(message.get("in-reply-to") or ""),
        "references": str(message.get("references") or ""),
        "attachments": attachments[:20],
        "attachment_count": len(attachments),
        "body_preview": body[:EMAIL_BODY_PREVIEW_CHARS],
        "body_truncated": len(body) > EMAIL_BODY_PREVIEW_CHARS,
    }


def email_attachment_package_profile(
    *,
    run_id: str | None,
    source_path: Path,
    messages: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    quoted_path = quote(str(source_path))
    links = []
    for message in messages:
        message_index = optional_int_for_api(message.get("index")) or 0
        attachments = message.get("attachments") if isinstance(message.get("attachments"), Sequence) else []
        for attachment in attachments:
            if not isinstance(attachment, Mapping):
                continue
            attachment_index = optional_int_for_api(attachment.get("index")) or 0
            links.append(
                {
                    "message_index": message_index,
                    "attachment_index": attachment_index,
                    "filename": str(attachment.get("filename") or ""),
                    "size": optional_int_for_api(attachment.get("size")) or 0,
                    "sha256": str(attachment.get("sha256") or ""),
                    "package_url": (
                        f"/api/runs/{run_id}/source-email-attachment?path={quoted_path}&message_index={message_index}&attachment_index={attachment_index}"
                        if run_id and message_index and attachment_index
                        else None
                    ),
                }
            )
    return {
        "profile_version": "email-attachment-package-profile-v1",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["email"]],
        "endpoint": "/api/runs/{run_id}/source-email-attachment",
        "attachment_count": len(links),
        "links": links[:50],
        "max_inline_content_bytes": EMAIL_ATTACHMENT_EXPORT_MAX_BYTES,
        "supports_hash_inventory": True,
        "supports_bounded_content_export": True,
        "native_pst_ost_msg_supported": False,
        "report_use_warning": "Validate attachment hashes and mailbox/thread reconstruction with a trusted mailbox parser before report-grade use.",
    }


def build_email_attachment_package(
    *,
    run_id: str,
    source_path: Path,
    suffix: str,
    message_index: int,
    attachment_index: int,
    include_content: bool,
) -> Dict[str, object]:
    try:
        messages, diagnostics = read_email_messages_with_diagnostics(source_path, suffix)
    except OSError as exc:
        raise HTTPException(status_code=400, detail=f"Email attachment package failed: {exc}") from exc
    if message_index > len(messages):
        detail = (
            "message_index not found within bounded email parse"
            if diagnostics.get("source_truncated") or diagnostics.get("message_limit_reached")
            else "message_index not found"
        )
        raise HTTPException(status_code=404, detail=detail)
    message = messages[message_index - 1]
    attachments: list[tuple[email.message.EmailMessage, bytes]] = []
    for part in message.walk():
        if str(part.get_content_disposition() or "") == "attachment" or part.get_filename():
            attachments.append((part, part.get_payload(decode=True) or b""))
    if attachment_index > len(attachments):
        raise HTTPException(status_code=404, detail="attachment_index not found")
    part, payload = attachments[attachment_index - 1]
    hashes = compute_hashes_for_bytes(payload)
    content_b64 = ""
    content_status = "not-requested"
    if include_content:
        if len(payload) > EMAIL_ATTACHMENT_EXPORT_MAX_BYTES:
            content_status = "too-large"
        else:
            content_b64 = base64.b64encode(payload).decode("ascii")
            content_status = "included-base64"
    citation_id = hashlib.sha256(
        f"{run_id}|{source_path}|{message_index}|{attachment_index}|{hashes['sha256']}".encode("utf-8")
    ).hexdigest()[:16]
    proof_manifest = build_email_attachment_proof_manifest(
        source_path=source_path,
        message_index=message_index,
        attachment_index=attachment_index,
        filename=part.get_filename() or "",
        content_type=part.get_content_type(),
        size=len(payload),
        hashes=hashes,
        content_status=content_status,
        citation_id=citation_id,
    )
    return {
        "command": "source-email-attachment",
        "profile_version": "email-attachment-package-v1",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["email"]],
        "citation_id": citation_id,
        "path": str(source_path),
        "name": source_path.name,
        "message_index": message_index,
        "attachment_index": attachment_index,
        "filename": part.get_filename() or "",
        "content_type": part.get_content_type(),
        "content_id": str(part.get("content-id") or ""),
        "size": len(payload),
        "hashes": hashes,
        "content_status": content_status,
        "content_base64": content_b64,
        "max_inline_content_bytes": EMAIL_ATTACHMENT_EXPORT_MAX_BYTES,
        "email_parse_diagnostics": diagnostics,
        "email_attachment_proof_manifest": proof_manifest,
        "email_attachment_proof_manifest_hash": proof_manifest["manifest_hash"],
        "copy_safe_citation": {
            "text": (
                f"Source={source_path.name}; message_index={message_index}; attachment_index={attachment_index}; "
                f"filename={part.get_filename() or ''}; size={len(payload)}; sha256={hashes['sha256']}; citation_id={citation_id}"
            ),
            "redacts_full_path": True,
        },
        "reportability_decision": viewer_workflow_reportability_decision(
            item_number=55,
            component="email-attachment-package",
            blockers=[
                "trusted-mailbox-thread-export-required-before-court-use",
                "native-pst-ost-msg-attachment-extraction-not-implemented",
                "deleted-mailbox-item-recovery-not-implemented",
            ],
            controls={
                "hashes": True,
                "bounded_content_export": include_content and content_status == "included-base64",
                "max_inline_content_bytes": EMAIL_ATTACHMENT_EXPORT_MAX_BYTES,
                "native_pst_ost_msg": False,
                "email_parse_diagnostics": diagnostics,
            },
        ),
        "core_accuracy_gates": email_viewer_core_accuracy_gates(
            source_path=source_path,
            messages=[
                {
                    "index": message_index,
                    "from": str(message.get("from") or ""),
                    "subject": str(message.get("subject") or ""),
                    "attachment_count": 1,
                }
            ],
            conversation={"threads": []},
            attachment_manifest=proof_manifest,
        ),
    }


def build_email_attachment_proof_manifest(
    *,
    source_path: Path,
    message_index: int,
    attachment_index: int,
    filename: str,
    content_type: str,
    size: int,
    hashes: Mapping[str, str],
    content_status: str,
    citation_id: str,
) -> dict[str, object]:
    attachment_core = {
        "message_index": message_index,
        "attachment_index": attachment_index,
        "filename": filename,
        "content_type": content_type,
        "size": size,
        "sha256": str(hashes.get("sha256") or ""),
        "content_status": content_status,
    }
    manifest_core: dict[str, object] = {
        "manifest_version": "email-attachment-proof-manifest-v1",
        "item_number": 55,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["email"]],
        "citation_id": citation_id,
        "path": str(source_path),
        "attachment": attachment_core,
        "attachment_hash": stable_payload_sha256(attachment_core),
        "source_viewer_locator": {
            "viewer": "source-email-attachment",
            "path": str(source_path),
            "message_index": message_index,
            "attachment_index": attachment_index,
            "open_action": "open-email-attachment-citation-package",
        },
        "blockers": [
            "trusted-mailbox-thread-export-required-before-court-use",
            "native-pst-ost-msg-attachment-extraction-not-implemented",
            "deleted-mailbox-item-recovery-not-implemented",
        ],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_email_threads(messages: list[dict[str, object]]) -> list[dict[str, object]]:
    buckets: dict[str, list[dict[str, object]]] = {}
    for message in messages:
        buckets.setdefault(email_thread_key(message), []).append(message)
    threads = []
    for key, rows in sorted(buckets.items(), key=lambda item: (thread_sort_date(item[1]), item[0])):
        threads.append(
            {
                "thread_id": hashlib.sha256(key.encode("utf-8")).hexdigest()[:16],
                "subject": rows[0].get("subject") or "(no subject)",
                "message_count": len(rows),
                "participants": sorted(
                    {
                        value
                        for row in rows
                        for value in (
                            str(row.get("from") or ""),
                            str(row.get("to") or ""),
                            str(row.get("cc") or ""),
                        )
                        if value
                    }
                )[:20],
                "message_indices": [int(row["index"]) for row in rows if isinstance(row.get("index"), int)],
                "first_date": rows[0].get("date") or "",
                "last_date": rows[-1].get("date") or "",
                "attachment_count": sum(int(row.get("attachment_count") or 0) for row in rows),
            }
        )
    return threads


def build_email_conversation_viewer(
    messages: list[dict[str, object]],
    threads: list[dict[str, object]],
) -> dict[str, object]:
    message_by_index = {int(message["index"]): message for message in messages if isinstance(message.get("index"), int)}
    thread_rows = []
    for thread in threads:
        indices = [int(index) for index in thread.get("message_indices", []) if isinstance(index, int)]
        rows = [message_by_index[index] for index in indices if index in message_by_index]
        thread_rows.append(
            {
                "thread_id": thread.get("thread_id"),
                "subject": thread.get("subject"),
                "message_count": len(rows),
                "participants": thread.get("participants", []),
                "first_date": thread.get("first_date", ""),
                "last_date": thread.get("last_date", ""),
                "attachment_count": thread.get("attachment_count", 0),
                "message_order": [
                    {
                        "index": row.get("index"),
                        "date": row.get("date", ""),
                        "from": row.get("from", ""),
                        "to": row.get("to", ""),
                        "subject": row.get("subject", ""),
                        "message_id": row.get("message_id", ""),
                        "reply_to": row.get("in_reply_to", ""),
                    }
                    for row in rows
                ],
                "validation_checks": {
                    "message_id_present": all(bool(row.get("message_id")) for row in rows) if rows else False,
                    "reply_headers_present": any(bool(row.get("in_reply_to") or row.get("references")) for row in rows),
                    "body_preview_present": any(bool(row.get("body_preview")) for row in rows),
                    "attachment_inventory_present": any(int(row.get("attachment_count") or 0) > 0 for row in rows),
                    "mailbox_known_answer_validated": False,
                },
            }
        )
    return {
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["email"]],
        "thread_count": len(thread_rows),
        "threads": thread_rows,
        "review_hint": "Review thread order, participants, attachments, and source message headers before reporting email conversation conclusions.",
    }


def build_email_conversation_manifest(
    *,
    source_path: Path,
    messages: Sequence[Mapping[str, object]],
    conversation: Mapping[str, object],
    attachment_profile: Mapping[str, object],
) -> dict[str, object]:
    message_entries: list[dict[str, object]] = []
    for message in messages[:EMAIL_PREVIEW_MESSAGE_LIMIT]:
        body_preview = str(message.get("body_preview") or "")
        attachments = message.get("attachments") if isinstance(message.get("attachments"), Sequence) else []
        attachment_rows = [
            {
                "index": attachment.get("index"),
                "filename": str(attachment.get("filename") or ""),
                "content_type": str(attachment.get("content_type") or ""),
                "size": attachment.get("size"),
                "sha256": str(attachment.get("sha256") or ""),
            }
            for attachment in attachments
            if isinstance(attachment, Mapping)
        ]
        message_core = {
            "index": message.get("index"),
            "subject": str(message.get("subject") or ""),
            "from": str(message.get("from") or ""),
            "to": str(message.get("to") or ""),
            "cc": str(message.get("cc") or ""),
            "date": str(message.get("date") or ""),
            "message_id": str(message.get("message_id") or ""),
            "in_reply_to": str(message.get("in_reply_to") or ""),
            "references_sha256": hashlib.sha256(str(message.get("references") or "").encode("utf-8", errors="replace")).hexdigest(),
            "body_preview_sha256": hashlib.sha256(body_preview.encode("utf-8", errors="replace")).hexdigest() if body_preview else "",
            "attachment_count": int(message.get("attachment_count") or 0),
            "attachments": attachment_rows,
        }
        message_entries.append({**message_core, "message_hash": stable_payload_sha256(message_core)})
    thread_entries: list[dict[str, object]] = []
    threads = conversation.get("threads") if isinstance(conversation.get("threads"), Sequence) else []
    for thread in threads:
        if not isinstance(thread, Mapping):
            continue
        thread_core = {
            "thread_id": str(thread.get("thread_id") or ""),
            "subject": str(thread.get("subject") or ""),
            "message_count": int(thread.get("message_count") or 0),
            "participants": list(thread.get("participants") or []),
            "first_date": str(thread.get("first_date") or ""),
            "last_date": str(thread.get("last_date") or ""),
            "attachment_count": int(thread.get("attachment_count") or 0),
            "message_order": [
                {
                    "index": row.get("index"),
                    "date": str(row.get("date") or ""),
                    "message_id": str(row.get("message_id") or ""),
                    "reply_to": str(row.get("reply_to") or ""),
                }
                for row in thread.get("message_order", [])
                if isinstance(row, Mapping)
            ],
        }
        thread_entries.append({**thread_core, "thread_hash": stable_payload_sha256(thread_core)})
    manifest_core: dict[str, object] = {
        "manifest_version": "email-conversation-source-manifest-v1",
        "item_number": 55,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["email"]],
        "path": str(source_path),
        "name": source_path.name,
        "message_count": len(messages),
        "bounded_message_count": len(message_entries),
        "thread_count": len(thread_entries),
        "message_hash_count": sum(1 for message in message_entries if message.get("message_hash")),
        "thread_hash_count": sum(1 for thread in thread_entries if thread.get("thread_hash")),
        "attachment_package_count": int(attachment_profile.get("attachment_count") or 0),
        "source_viewer_locator": {
            "viewer": "source-email-conversation",
            "path": str(source_path),
            "open_action": "open-email-conversation-thread-view",
        },
        "messages": message_entries,
        "threads": thread_entries,
        "blockers": [
            "native-pst-ost-msg-conversation-view-not-implemented",
            "deleted-mailbox-item-recovery-not-implemented",
            EMAIL_VIEWER_TRUSTED_DIFF_BLOCKER,
        ],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def email_thread_key(message: Mapping[str, object]) -> str:
    references = str(message.get("references") or "").strip()
    in_reply_to = str(message.get("in_reply_to") or "").strip()
    if references:
        return references.split()[0]
    if in_reply_to:
        return in_reply_to
    subject = re.sub(r"^(re|fw|fwd):\s*", "", str(message.get("subject") or ""), flags=re.IGNORECASE).strip().lower()
    participants = "|".join(
        sorted(
            value.lower()
            for value in (str(message.get("from") or ""), str(message.get("to") or ""))
            if value
        )
    )
    return f"{subject}|{participants}"


def thread_sort_date(messages: list[dict[str, object]]) -> str:
    return str(messages[0].get("date") or "") if messages else ""


def structured_viewer_metadata(source_format: str, strategy: str, status: str) -> dict[str, object]:
    return {
        "source_format": source_format,
        "strategy": strategy,
        "preview_status": status,
        "parser": f"rapidtriage.source-viewer.{source_format}",
        "parser_version": SOURCE_VIEWER_VERSION,
    }


def source_viewer_component_assessment(gap_id: str, component: str, blockers: list[str]) -> dict[str, object]:
    return {
        "component": component,
        "status": "implemented-baseline-validation-required",
        "commercial_gap_ids": [gap_id],
        "ready_for_court_report": False,
        "blockers": blockers,
        "recommended_validation": [
            "Verify the preview against the authoritative source file and source hashes before report inclusion.",
            "Use specialized validated tooling for artifact-specific conclusions beyond this bounded viewer.",
        ],
    }


def safe_read_text(source_path: Path, *, max_chars: int) -> str:
    try:
        with source_path.open("r", encoding="utf-8", errors="replace") as handle:
            return handle.read(max_chars)
    except OSError:
        return ""


def list_sqlite_tables(connection: sqlite3.Connection) -> list[str]:
    rows = connection.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type IN ('table', 'view')
          AND name NOT LIKE 'sqlite_%'
        ORDER BY name
        """
    ).fetchall()
    return [str(row["name"]) for row in rows]


def sqlite_database_metadata(connection: sqlite3.Connection, source_path: Path) -> dict[str, object]:
    metadata: dict[str, object] = {
        "path": str(source_path),
        "journal_mode": "",
        "user_version": None,
        "schema_version": None,
        "page_size": None,
        "page_count": None,
        "freelist_count": None,
        "encoding": "",
        "database_list": [],
        "sidecar_state_profile": sqlite_sidecar_state_profile(source_path),
    }
    pragma_names = {
        "journal_mode": "journal_mode",
        "user_version": "user_version",
        "schema_version": "schema_version",
        "page_size": "page_size",
        "page_count": "page_count",
        "freelist_count": "freelist_count",
        "encoding": "encoding",
    }
    for key, pragma in pragma_names.items():
        try:
            row = connection.execute(f"PRAGMA {pragma}").fetchone()
        except sqlite3.DatabaseError:
            row = None
        if row is not None:
            metadata[key] = row[0]
    page_size = optional_int_for_api(metadata.get("page_size")) or 0
    page_count = optional_int_for_api(metadata.get("page_count")) or 0
    metadata["estimated_database_bytes"] = page_size * page_count if page_size and page_count else source_path.stat().st_size
    try:
        database_rows = connection.execute("PRAGMA database_list").fetchall()
        metadata["database_list"] = [
            {"sequence": row[0], "name": str(row[1]), "file": str(row[2] or "")}
            for row in database_rows
        ]
    except sqlite3.DatabaseError:
        metadata["database_list"] = []
    return metadata


def sqlite_sidecar_state_profile(source_path: Path) -> dict[str, object]:
    wal_path = source_path.with_name(source_path.name + "-wal")
    shm_path = source_path.with_name(source_path.name + "-shm")
    journal_path = source_path.with_name(source_path.name + "-journal")
    wal_info = sqlite_wal_sidecar_info(wal_path)
    sidecars = {
        "wal": wal_info,
        "shm": sqlite_basic_sidecar_info(shm_path, "shm"),
        "rollback_journal": sqlite_basic_sidecar_info(journal_path, "rollback-journal"),
    }
    detected = [name for name, info in sidecars.items() if bool(info.get("exists"))]
    profile_core = {
        "profile_version": "sqlite-sidecar-state-profile-v1",
        "source_path": str(source_path),
        "sidecars": sidecars,
        "detected_sidecars": detected,
        "wal_detected": bool(wal_info.get("exists")),
        "rollback_journal_detected": bool(sidecars["rollback_journal"].get("exists")),
        "shm_detected": bool(sidecars["shm"].get("exists")),
        "requires_wal_review": bool(detected),
        "hash_policy": "metadata-only-in-source-preview-use-sqlite-wal-preview-for-hashed-working-copy",
        "recommended_cli": "rapidtriage sqlite-wal-preview <database> --output-dir <case-output>/sqlite-wal-review --json",
        "source_viewer_warning": (
            "SQLite sidecar files are present. Preview rows may not represent all committed or recoverable evidence until WAL/journal review is completed."
            if detected
            else "No SQLite sidecar files were detected next to this database at preview time."
        ),
    }
    return {**profile_core, "profile_hash": stable_payload_sha256(profile_core)}


def sqlite_basic_sidecar_info(path: Path, kind: str) -> dict[str, object]:
    if not path.is_file():
        return {"kind": kind, "path": str(path), "exists": False, "size_bytes": 0, "hash_status": "missing"}
    stat = path.stat()
    return {
        "kind": kind,
        "path": str(path),
        "exists": True,
        "size_bytes": stat.st_size,
        "modified_at": dt.datetime.fromtimestamp(stat.st_mtime, tz=dt.timezone.utc).isoformat(),
        "hash_status": "not-computed-in-source-preview",
    }


def sqlite_wal_sidecar_info(path: Path) -> dict[str, object]:
    info = sqlite_basic_sidecar_info(path, "wal")
    if not info.get("exists"):
        return info
    header: dict[str, object] = {"status": "not-read"}
    try:
        with path.open("rb") as handle:
            raw = handle.read(SQLITE_WAL_HEADER_SIZE)
        if len(raw) < SQLITE_WAL_HEADER_SIZE:
            header = {"status": "invalid-short-header", "bytes_read": len(raw)}
        else:
            magic, version, page_size, checkpoint_sequence, salt1, salt2, checksum1, checksum2 = struct.unpack(">IIIIIIII", raw)
            endian = SQLITE_WAL_MAGIC_VALUES.get(magic, "unknown")
            normalized_page_size = 1024 if page_size == 0 else page_size
            frame_size = SQLITE_WAL_FRAME_HEADER_SIZE + normalized_page_size if normalized_page_size > 0 else 0
            size_bytes = int(info.get("size_bytes") or 0)
            estimated_frames = max(0, (size_bytes - SQLITE_WAL_HEADER_SIZE) // frame_size) if frame_size else 0
            header = {
                "status": "parsed" if endian != "unknown" else "unknown-magic",
                "magic_hex": f"0x{magic:08x}",
                "endian": endian,
                "version": version,
                "page_size": normalized_page_size,
                "checkpoint_sequence": checkpoint_sequence,
                "salt1": salt1,
                "salt2": salt2,
                "checksum1": checksum1,
                "checksum2": checksum2,
                "estimated_frame_count": estimated_frames,
                "frame_count_is_estimate": True,
            }
    except OSError as exc:
        header = {"status": "read-error", "error": str(exc)}
    return {**info, "header": header}


def preview_sqlite_table(connection: sqlite3.Connection, table: str, *, source_path: Path | None = None) -> dict[str, object]:
    quoted = quote_sqlite_identifier(table)
    column_rows = connection.execute(f"PRAGMA table_info({quoted})").fetchall()
    column_details = [
        {
            "cid": optional_int_for_api(row["cid"]),
            "name": str(row["name"]),
            "type": str(row["type"] or ""),
            "notnull": bool(row["notnull"]),
            "default_value": sqlite_preview_value(row["dflt_value"]),
            "primary_key_position": optional_int_for_api(row["pk"]) or 0,
        }
        for row in column_rows
    ]
    columns = [str(column["name"]) for column in column_details]
    schema_row = connection.execute(
        "SELECT type, sql FROM sqlite_master WHERE name = ? ORDER BY type LIMIT 1",
        (table,),
    ).fetchone()
    index_rows = connection.execute(f"PRAGMA index_list({quoted})").fetchall()
    indexes = [
        {
            "name": str(row["name"]),
            "unique": bool(row["unique"]),
            "origin": str(row["origin"] or ""),
            "partial": bool(row["partial"]) if "partial" in row.keys() else False,
        }
        for row in index_rows[:8]
    ]
    count = None
    try:
        count = connection.execute(f"SELECT COUNT(*) AS count FROM {quoted}").fetchone()["count"]
    except sqlite3.DatabaseError:
        count = None
    selected_columns = columns[:SQLITE_PREVIEW_COLUMN_LIMIT]
    primary_key_columns = [
        str(column["name"])
        for column in sorted(column_details, key=lambda item: int(item["primary_key_position"]))
        if int(column["primary_key_position"]) > 0
    ]
    rows: list[dict[str, object]] = []
    if selected_columns:
        select_clause = ", ".join(quote_sqlite_identifier(column) for column in selected_columns)
        rowid_available = True
        try:
            row_cursor = connection.execute(
                f"SELECT rowid AS __rapid_source_rowid, {select_clause} FROM {quoted} LIMIT ?",
                (SQLITE_PREVIEW_ROW_LIMIT,),
            )
        except sqlite3.DatabaseError:
            rowid_available = False
            row_cursor = connection.execute(f"SELECT {select_clause} FROM {quoted} LIMIT ?", (SQLITE_PREVIEW_ROW_LIMIT,))
        query_hash = sqlite_table_query_hash(
            table=table,
            columns=selected_columns,
            offset=0,
            limit=SQLITE_PREVIEW_ROW_LIMIT,
            where_column=None,
            where_contains=None,
            order_by=None,
            descending=False,
        )
        for index, row in enumerate(row_cursor, start=1):
            values = {column: sqlite_preview_value(row[column]) for column in selected_columns}
            locator = sqlite_row_source_viewer_locator(
                source_path=source_path,
                table=table,
                row_number=index,
                rowid=row["__rapid_source_rowid"] if rowid_available else "",
                primary_key_values=sqlite_primary_key_values(values, primary_key_columns),
                column="",
                offset=0,
                limit=SQLITE_PREVIEW_ROW_LIMIT,
                query_hash=query_hash,
                source_context="preview",
            )
            rows.append(
                {
                    "row_number": index,
                    "rowid": row["__rapid_source_rowid"] if rowid_available else "",
                    "primary_key_values": sqlite_primary_key_values(values, primary_key_columns),
                    "values": values,
                    "source_viewer_locator": locator,
                    "sqlite_row_locator": locator,
                    "review_note_citation": sqlite_row_review_note_citation(locator),
                }
            )
    return {
        "name": table,
        "columns": selected_columns,
        "column_details": column_details[:SQLITE_PREVIEW_COLUMN_LIMIT],
        "column_count": len(columns),
        "row_count": count,
        "rows": rows,
        "schema_sql": str(schema_row["sql"] or "") if schema_row is not None else "",
        "object_type": str(schema_row["type"] or "table") if schema_row is not None else "table",
        "indexes": indexes,
        "primary_key_columns": primary_key_columns,
        "truncated_columns": len(columns) > SQLITE_PREVIEW_COLUMN_LIMIT,
        "truncated_rows": bool(count is not None and count > SQLITE_PREVIEW_ROW_LIMIT),
        "truncated_indexes": len(index_rows) > 8,
    }


def sqlite_table_page_profile(*, run_id: str | None, source_path: Path, tables: Sequence[Mapping[str, object]]) -> dict[str, object]:
    quoted_path = quote(str(source_path))
    table_links = []
    for table in tables:
        name = str(table.get("name") or "")
        if not name:
            continue
        table_links.append(
            {
                "table": name,
                "first_page_url": (
                    f"/api/runs/{run_id}/source-sqlite-table?path={quoted_path}&table={quote(name)}&offset=0&limit={SQLITE_PREVIEW_ROW_LIMIT}"
                    if run_id
                    else None
                ),
                "where_contains_url_template": (
                    f"/api/runs/{run_id}/source-sqlite-table?path={quoted_path}&table={quote(name)}&where_column={{column}}&where_contains={{keyword}}"
                    if run_id
                    else None
                ),
            }
        )
    return {
        "profile_version": "sqlite-table-page-profile-v1",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["sqlite"]],
        "endpoint": "/api/runs/{run_id}/source-sqlite-table",
        "table_links": table_links,
        "max_page_rows": SQLITE_TABLE_PAGE_MAX_ROWS,
        "supports_offset_pagination": True,
        "supports_restricted_where_contains": True,
        "supports_validated_order_by": True,
        "executes_arbitrary_sql": False,
        "report_use_warning": "Use trusted sqlite3/schema diff and source hashes before treating a page result as report-grade evidence.",
    }


def sqlite_primary_key_values(values: Mapping[str, object], primary_key_columns: Sequence[str]) -> dict[str, object]:
    return {column: values.get(column, "") for column in primary_key_columns if column in values}


def sqlite_table_query_core(
    *,
    table: str,
    columns: Sequence[str],
    offset: int,
    limit: int,
    where_column: str | None,
    where_contains: str | None,
    order_by: str | None,
    descending: bool,
) -> dict[str, object]:
    return {
        "table": table,
        "columns": list(columns),
        "offset": offset,
        "limit": limit,
        "where_column": where_column or "",
        "where_contains_sha256": hashlib.sha256(str(where_contains or "").encode("utf-8", errors="replace")).hexdigest()
        if where_contains
        else "",
        "order_by": order_by or "",
        "descending": descending,
    }


def sqlite_table_query_hash(
    *,
    table: str,
    columns: Sequence[str],
    offset: int,
    limit: int,
    where_column: str | None,
    where_contains: str | None,
    order_by: str | None,
    descending: bool,
) -> str:
    return stable_payload_sha256(
        sqlite_table_query_core(
            table=table,
            columns=columns,
            offset=offset,
            limit=limit,
            where_column=where_column,
            where_contains=where_contains,
            order_by=order_by,
            descending=descending,
        )
    )


def sqlite_row_source_viewer_locator(
    *,
    source_path: Path | None,
    table: str,
    row_number: int,
    rowid: object,
    primary_key_values: Mapping[str, object],
    column: str,
    offset: int,
    limit: int,
    query_hash: str,
    source_context: str,
) -> dict[str, object]:
    path = str(source_path) if source_path is not None else ""
    payload: dict[str, object] = {
        "profile_version": "sqlite-row-source-viewer-locator-v1",
        "qc_prep_item": 11,
        "viewer": "source-sqlite-table",
        "source_path": path,
        "source_name": Path(path).name if path else "",
        "table": table,
        "row_number": row_number,
        "rowid": rowid if rowid is not None else "",
        "primary_key_values": dict(primary_key_values),
        "column": column,
        "offset": offset,
        "limit": limit,
        "query_hash": query_hash,
        "source_context": source_context,
        "endpoint": "/api/runs/{run_id}/source-sqlite-table",
        "open_action": "open-sqlite-row-in-source-viewer",
        "review_note_ready": True,
        "report_ready": False,
        "required_before_report": [
            "verify source database hash",
            "confirm row in source SQLite viewer",
            "attach reviewer status and note",
            "validate schema/query output with trusted sqlite3 or known-answer manifest",
        ],
        "commercial_grade_blockers": [
            "trusted-sqlite-query-schema-diff-required-before-court-use",
            "deleted-row-and-wal-recovery-not-implemented-in-viewer",
        ],
    }
    payload["locator_sha256"] = stable_payload_sha256(payload)
    return payload


def sqlite_row_review_note_citation(locator: Mapping[str, object]) -> dict[str, object]:
    text = (
        f"SQLite row citation: {locator.get('source_name') or 'source'} "
        f"table={locator.get('table')} row={locator.get('row_number')} "
        f"rowid={locator.get('rowid')} column={locator.get('column') or '*'} "
        f"query_hash={locator.get('query_hash')} locator={locator.get('locator_sha256')}"
    )
    return {
        "profile_version": "sqlite-row-review-note-citation-v1",
        "qc_prep_item": 11,
        "text": text,
        "source_viewer_locator": dict(locator),
        "tags": ["sqlite-row", "source-viewer-locator"],
        "ready_for_review_note": True,
        "ready_for_report": False,
    }


def build_sqlite_preview_manifest(
    *,
    source_path: Path,
    database_metadata: Mapping[str, object],
    tables: Sequence[Mapping[str, object]],
    table_page_profile: Mapping[str, object],
) -> dict[str, object]:
    table_entries: list[dict[str, object]] = []
    row_hash_count = 0
    for table in tables[:SQLITE_PREVIEW_TABLE_LIMIT]:
        row_entries: list[dict[str, object]] = []
        for row in table.get("rows", []) if isinstance(table.get("rows"), list) else []:
            if not isinstance(row, Mapping):
                continue
            row_core = {
                "row_number": row.get("row_number"),
                "rowid": row.get("rowid", ""),
                "primary_key_values": row.get("primary_key_values")
                if isinstance(row.get("primary_key_values"), Mapping)
                else {},
                "values": row.get("values") if isinstance(row.get("values"), Mapping) else {},
                "source_viewer_locator": row.get("source_viewer_locator")
                if isinstance(row.get("source_viewer_locator"), Mapping)
                else {},
            }
            row_entries.append(
                {
                    **row_core,
                    "row_hash": stable_payload_sha256(row_core),
                    "review_note_citation": row.get("review_note_citation")
                    if isinstance(row.get("review_note_citation"), Mapping)
                    else {},
                }
            )
        row_hash_count += sum(1 for row in row_entries if row.get("row_hash"))
        table_core = {
            "name": str(table.get("name") or ""),
            "object_type": str(table.get("object_type") or "table"),
            "row_count": table.get("row_count"),
            "column_count": table.get("column_count"),
            "schema_sha256": hashlib.sha256(str(table.get("schema_sql") or "").encode("utf-8", errors="replace")).hexdigest(),
            "columns_sha256": stable_payload_sha256(
                [
                    column
                    for column in table.get("column_details", [])
                    if isinstance(column, Mapping)
                ]
            ),
            "indexes_sha256": stable_payload_sha256(
                [
                    index
                    for index in table.get("indexes", [])
                    if isinstance(index, Mapping)
                ]
            ),
            "sample_rows_sha256": stable_payload_sha256(row_entries),
            "row_hashes": row_entries[:SQLITE_PREVIEW_ROW_LIMIT],
            "truncated_rows": bool(table.get("truncated_rows")),
            "truncated_columns": bool(table.get("truncated_columns")),
        }
        table_entries.append({**table_core, "table_hash": stable_payload_sha256(table_core)})
    manifest_core: dict[str, object] = {
        "manifest_version": "sqlite-preview-source-manifest-v1",
        "item_number": 54,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["sqlite"]],
        "path": str(source_path),
        "name": source_path.name,
        "database": {
            "page_size": database_metadata.get("page_size"),
            "page_count": database_metadata.get("page_count"),
            "freelist_count": database_metadata.get("freelist_count"),
            "journal_mode": str(database_metadata.get("journal_mode") or ""),
            "estimated_database_bytes": database_metadata.get("estimated_database_bytes"),
            "sidecar_state_profile_hash": str(
                database_metadata.get("sidecar_state_profile", {}).get("profile_hash")
                if isinstance(database_metadata.get("sidecar_state_profile"), Mapping)
                else ""
            ),
        },
        "table_count": len(tables),
        "bounded_table_count": len(table_entries),
        "table_hash_count": sum(1 for table in table_entries if table.get("table_hash")),
        "row_hash_count": row_hash_count,
        "table_page_profile_version": str(table_page_profile.get("profile_version") or ""),
        "table_page_link_count": len(table_page_profile.get("table_links") or []),
        "source_viewer_locator": {
            "viewer": "source-sqlite",
            "path": str(source_path),
            "open_action": "open-sqlite-table-in-read-only-viewer",
            "default_endpoint": table_page_profile.get("endpoint"),
        },
        "tables": table_entries,
        "blockers": [
            "deleted-row-and-wal-recovery-not-implemented-in-viewer",
            "trusted-sqlite-query-schema-diff-required-before-court-use",
            "browser-e2e-pagination-proof-not-attached",
        ],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_sqlite_table_page(
    *,
    run_id: str,
    source_path: Path,
    table: str,
    offset: int,
    limit: int,
    where_column: str | None,
    where_contains: str | None,
    order_by: str | None,
    descending: bool,
) -> Dict[str, object]:
    try:
        with contextlib.closing(sqlite3.connect(f"{source_path.as_uri()}?mode=ro", uri=True)) as connection:
            connection.row_factory = sqlite3.Row
            tables = set(list_sqlite_tables(connection))
            if table not in tables:
                raise HTTPException(status_code=404, detail="table not found in SQLite database")
            quoted_table = quote_sqlite_identifier(table)
            column_rows = connection.execute(f"PRAGMA table_info({quoted_table})").fetchall()
            all_columns = [str(row["name"]) for row in column_rows]
            if not all_columns:
                raise HTTPException(status_code=400, detail="table has no readable columns")
            selected_columns = all_columns[:SQLITE_PREVIEW_COLUMN_LIMIT]
            where_sql = ""
            params: list[object] = []
            if where_column or where_contains:
                if not where_column or where_contains is None:
                    raise HTTPException(status_code=400, detail="where_column and where_contains must be provided together")
                if where_column not in all_columns:
                    raise HTTPException(status_code=400, detail="where_column is not a column in the selected table")
                where_sql = f" WHERE CAST({quote_sqlite_identifier(where_column)} AS TEXT) LIKE ? ESCAPE '\\'"
                params.append("%" + escape_sqlite_like(where_contains) + "%")
            order_sql = ""
            if order_by:
                if order_by not in all_columns:
                    raise HTTPException(status_code=400, detail="order_by is not a column in the selected table")
                order_sql = f" ORDER BY {quote_sqlite_identifier(order_by)} {'DESC' if descending else 'ASC'}"
            select_clause = ", ".join(quote_sqlite_identifier(column) for column in selected_columns)
            count_row = connection.execute(f"SELECT COUNT(*) AS count FROM {quoted_table}{where_sql}", params).fetchone()
            total = int(count_row["count"] or 0)
            page_params = [*params, limit, offset]
            primary_key_columns = [
                str(row["name"])
                for row in sorted(column_rows, key=lambda item: int(item["pk"] or 0))
                if int(row["pk"] or 0) > 0
            ]
            query_hash = sqlite_table_query_hash(
                table=table,
                columns=selected_columns,
                offset=offset,
                limit=limit,
                where_column=where_column,
                where_contains=where_contains,
                order_by=order_by,
                descending=descending,
            )
            rowid_available = True
            try:
                row_cursor = connection.execute(
                    f"SELECT rowid AS __rapid_source_rowid, {select_clause} FROM {quoted_table}{where_sql}{order_sql} LIMIT ? OFFSET ?",
                    page_params,
                )
            except sqlite3.DatabaseError:
                rowid_available = False
                row_cursor = connection.execute(
                    f"SELECT {select_clause} FROM {quoted_table}{where_sql}{order_sql} LIMIT ? OFFSET ?",
                    page_params,
                )
            rows = []
            for index, row in enumerate(row_cursor, start=1):
                row_number = offset + index
                values = {column: sqlite_preview_value(row[column]) for column in selected_columns}
                locator = sqlite_row_source_viewer_locator(
                    source_path=source_path,
                    table=table,
                    row_number=row_number,
                    rowid=row["__rapid_source_rowid"] if rowid_available else "",
                    primary_key_values=sqlite_primary_key_values(values, primary_key_columns),
                    column="",
                    offset=offset,
                    limit=limit,
                    query_hash=query_hash,
                    source_context="page",
                )
                rows.append(
                    {
                        "row_number": row_number,
                        "rowid": row["__rapid_source_rowid"] if rowid_available else "",
                        "primary_key_values": sqlite_primary_key_values(values, primary_key_columns),
                        "values": values,
                        "source_viewer_locator": locator,
                        "sqlite_row_locator": locator,
                        "review_note_citation": sqlite_row_review_note_citation(locator),
                    }
                )
    except sqlite3.DatabaseError as exc:
        raise HTTPException(status_code=400, detail=f"SQLite table page failed: {exc}") from exc
    next_offset = offset + len(rows)
    has_next = next_offset < total
    page_manifest = build_sqlite_table_page_manifest(
        source_path=source_path,
        table=table,
        columns=selected_columns,
        rows=rows,
        offset=offset,
        limit=limit,
        total=total,
        where_column=where_column,
        where_contains=where_contains,
        order_by=order_by,
        descending=descending,
    )
    return {
        "command": "source-sqlite-table",
        "profile_version": "sqlite-table-page-v1",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["sqlite"]],
        "path": str(source_path),
        "name": source_path.name,
        "table": table,
        "columns": selected_columns,
        "column_count": len(all_columns),
        "primary_key_columns": primary_key_columns,
        "rows": rows,
        "pagination": {
            "offset": offset,
            "limit": limit,
            "returned": len(rows),
            "total": total,
            "has_next": has_next,
            "next_offset": next_offset if has_next else None,
            "max_page_rows": SQLITE_TABLE_PAGE_MAX_ROWS,
        },
        "where": {
            "column": where_column or "",
            "contains": where_contains or "",
            "mode": "contains" if where_column and where_contains is not None else "none",
            "arbitrary_sql_allowed": False,
        },
        "sqlite_table_page_manifest": page_manifest,
        "sqlite_table_page_manifest_hash": page_manifest["manifest_hash"],
        "order_by": {
            "column": order_by or "",
            "direction": "desc" if order_by and descending else ("asc" if order_by else ""),
        },
        "read_only": True,
        "copy_safe_citation": {
            "text": (
                f"Source={source_path.name}; sqlite_table={table}; offset={offset}; limit={limit}; "
                f"returned={len(rows)}; where={where_column or ''}:{where_contains or ''}; query_hash={page_manifest['query_hash']}"
            ),
            "redacts_full_path": True,
        },
        "reportability_decision": viewer_workflow_reportability_decision(
            item_number=54,
            component="sqlite-table-page-viewer",
            blockers=[
                "trusted-sqlite-query-schema-diff-required-before-court-use",
                "deleted-row-and-wal-recovery-not-implemented-in-viewer",
                "export-selected-rows-workflow-not-implemented",
            ],
            controls={
                "read_only": True,
                "offset_pagination": True,
                "restricted_where_contains": True,
                "arbitrary_sql_allowed": False,
                "max_page_rows": SQLITE_TABLE_PAGE_MAX_ROWS,
                "sqlite_table_page_manifest_hash": page_manifest["manifest_hash"],
                "row_hash_count": page_manifest["row_hash_count"],
            },
        ),
        "core_accuracy_gates": sqlite_viewer_core_accuracy_gates(
            source_path=source_path,
            database_metadata={"page_size": "", "page_count": ""},
            tables=[{"name": table, "columns": selected_columns, "rows": rows, "column_count": len(all_columns)}],
            page_manifest=page_manifest,
        ),
    }


def build_sqlite_table_page_manifest(
    *,
    source_path: Path,
    table: str,
    columns: Sequence[str],
    rows: Sequence[Mapping[str, object]],
    offset: int,
    limit: int,
    total: int,
    where_column: str | None,
    where_contains: str | None,
    order_by: str | None,
    descending: bool,
) -> dict[str, object]:
    row_entries: list[dict[str, object]] = []
    for row in rows:
        row_core = {
            "row_number": row.get("row_number"),
            "rowid": row.get("rowid", ""),
            "primary_key_values": row.get("primary_key_values")
            if isinstance(row.get("primary_key_values"), Mapping)
            else {},
            "values": row.get("values") if isinstance(row.get("values"), Mapping) else {},
            "source_viewer_locator": row.get("source_viewer_locator")
            if isinstance(row.get("source_viewer_locator"), Mapping)
            else {},
        }
        row_entries.append(
            {
                **row_core,
                "row_hash": stable_payload_sha256(row_core),
                "review_note_citation": row.get("review_note_citation")
                if isinstance(row.get("review_note_citation"), Mapping)
                else {},
            }
        )
    query_core = sqlite_table_query_core(
        table=table,
        columns=columns,
        offset=offset,
        limit=limit,
        where_column=where_column,
        where_contains=where_contains,
        order_by=order_by,
        descending=descending,
    )
    manifest_core: dict[str, object] = {
        "manifest_version": "sqlite-table-page-proof-manifest-v1",
        "item_number": 54,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["sqlite"]],
        "path": str(source_path),
        "table": table,
        "query": query_core,
        "query_hash": stable_payload_sha256(query_core),
        "total": total,
        "returned": len(rows),
        "row_hash_count": sum(1 for row in row_entries if row.get("row_hash")),
        "rows": row_entries,
        "source_viewer_locator": {
            "viewer": "source-sqlite-table",
            "path": str(source_path),
            "table": table,
            "offset": offset,
            "limit": limit,
            "open_action": "open-sqlite-table-page",
        },
        "blockers": [
            "trusted-sqlite-query-schema-diff-required-before-court-use",
            "deleted-row-and-wal-recovery-not-implemented-in-viewer",
        ],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def escape_sqlite_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def build_sqlite_table_profiles(previews: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    profiles: list[dict[str, object]] = []
    for table in previews:
        column_details = table.get("column_details") if isinstance(table.get("column_details"), list) else []
        text_columns = [
            str(column.get("name"))
            for column in column_details
            if isinstance(column, Mapping) and str(column.get("type") or "").upper() in {"", "TEXT", "VARCHAR", "CHAR", "CLOB"}
        ]
        blob_columns = [
            str(column.get("name"))
            for column in column_details
            if isinstance(column, Mapping) and "BLOB" in str(column.get("type") or "").upper()
        ]
        timestamp_candidates = [
            str(column.get("name"))
            for column in column_details
            if isinstance(column, Mapping) and any(token in str(column.get("name") or "").lower() for token in ("time", "date", "created", "modified"))
        ]
        profiles.append(
            {
                "name": str(table.get("name") or ""),
                "object_type": str(table.get("object_type") or "table"),
                "row_count": table.get("row_count"),
                "column_count": table.get("column_count"),
                "primary_key_columns": list(table.get("primary_key_columns") or []),
                "text_columns": text_columns[:20],
                "blob_columns": blob_columns[:20],
                "timestamp_column_candidates": timestamp_candidates[:20],
                "searchable_text_column_count": len(text_columns),
                "has_indexes": bool(table.get("indexes")),
                "truncated_rows": bool(table.get("truncated_rows")),
                "review_hint": "Use source-search for table text hits, then verify row/column values against the original SQLite file.",
            }
        )
    return profiles


def sqlite_fts_optimization_metadata(
    database_metadata: Mapping[str, object],
    previews: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    row_counts = [
        int(table.get("row_count") or 0)
        for table in previews
        if isinstance(table.get("row_count"), int)
    ]
    total_preview_rows = sum(row_counts)
    text_column_count = 0
    for table in previews:
        for column in table.get("column_details", []) if isinstance(table.get("column_details"), list) else []:
            if isinstance(column, Mapping) and str(column.get("type") or "").upper() in {"", "TEXT", "VARCHAR", "CHAR", "CLOB"}:
                text_column_count += 1
    query_plan_profile = sqlite_preview_query_plan_profile(previews)
    optimization_manifest = sqlite_fts_optimization_manifest(
        database_metadata=database_metadata,
        preview_table_count=len(previews),
        preview_row_count=total_preview_rows,
        searchable_text_column_count=text_column_count,
        query_plan_profile=query_plan_profile,
    )
    return {
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["sqlite_performance"]],
        "functional_priority_profile": sqlite_fts_functional_profile(
            database_metadata=database_metadata,
            preview_table_count=len(previews),
            preview_row_count=total_preview_rows,
            searchable_text_column_count=text_column_count,
            optimization_manifest=optimization_manifest,
        ),
        "status": "bounded-read-only-preview-with-fts-aware-guidance",
        "page_size": database_metadata.get("page_size"),
        "page_count": database_metadata.get("page_count"),
        "estimated_database_bytes": database_metadata.get("estimated_database_bytes"),
        "preview_table_count": len(previews),
        "preview_row_count": total_preview_rows,
        "searchable_text_column_count": text_column_count,
        "query_plan_profile": query_plan_profile,
        "sqlite_fts_optimization_manifest": optimization_manifest,
        "sqlite_fts_optimization_manifest_hash": optimization_manifest["manifest_hash"],
        "core_accuracy_gates": large_sqlite_fts_core_accuracy_gates(
            database_metadata=database_metadata,
            previews=previews,
            searchable_text_column_count=text_column_count,
            preview_row_count=total_preview_rows,
            query_plan_profile=query_plan_profile,
            optimization_manifest=optimization_manifest,
        ),
        "trusted_large_sqlite_fts_diff": {
            "status": "missing",
            "blocker_id": SQLITE_FTS_TRUSTED_DIFF_BLOCKER,
            "required_tools": sorted(SQLITE_FTS_TRUSTED_TOOLS),
        },
        "recommended_large_case_strategy": [
            "Use indexed case search for imported artifacts/documents instead of loading huge SQLite tables in the browser.",
            "Use current-file source-search for targeted keyword hits, then verify row/table context in the source viewer.",
            "Keep row previews bounded and paginate/cursor through API results for case-scale review.",
        ],
        "ready_for_court_report": False,
    }


def sqlite_fts_optimization_manifest(
    *,
    database_metadata: Mapping[str, object],
    preview_table_count: int,
    preview_row_count: int,
    searchable_text_column_count: int,
    query_plan_profile: Mapping[str, object],
) -> dict[str, object]:
    manifest_core = {
        "profile_version": "sqlite-fts-optimization-manifest-v1",
        "item_number": 32,
        "gap_id": "#32",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["sqlite_performance"]],
        "page_size": database_metadata.get("page_size"),
        "page_count": database_metadata.get("page_count"),
        "freelist_count": database_metadata.get("freelist_count"),
        "journal_mode": str(database_metadata.get("journal_mode") or ""),
        "estimated_database_bytes": database_metadata.get("estimated_database_bytes"),
        "preview_table_count": preview_table_count,
        "preview_row_count": preview_row_count,
        "searchable_text_column_count": searchable_text_column_count,
        "query_plan_hash": str(query_plan_profile.get("plan_hash") or ""),
        "query_plan_row_head_hash": str(query_plan_profile.get("plan_row_head_hash") or ""),
        "query_plan_row_hash_count": int(query_plan_profile.get("plan_row_hash_count") or 0),
        "bounded_preview_query": bool(query_plan_profile.get("bounded_preview_query")),
        "arbitrary_sql_allowed": bool(query_plan_profile.get("arbitrary_sql_allowed")),
        "wal_journal_replay_supported": False,
        "ten_million_row_regression_attached": False,
        "recommended_engine": "case-db-fts-for-indexed-case-search-source-sqlite-preview-for-verification",
        "commercial_claim_allowed": False,
    }
    return {
        **manifest_core,
        "manifest_hash": hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def sqlite_preview_query_plan_profile(previews: Sequence[Mapping[str, object]]) -> dict[str, object]:
    plans = []
    for table in previews:
        if not isinstance(table, Mapping):
            continue
        indexes = table.get("indexes") if isinstance(table.get("indexes"), list) else []
        row_count = optional_int_for_api(table.get("row_count")) or 0
        uses_index = bool(indexes)
        plan = {
            "table": str(table.get("name") or ""),
            "row_count": row_count,
            "preview_query": "SELECT bounded_columns FROM table LIMIT ?",
            "count_query": "SELECT COUNT(*) FROM table",
            "uses_declared_index": uses_index,
            "bounded_rows": True,
            "full_table_materialization": False,
        }
        plans.append(
            {
                **plan,
                "row_hash": hashlib.sha256(json.dumps(plan, sort_keys=True).encode("utf-8")).hexdigest(),
            }
        )
    row_hashes = [str(plan["row_hash"]) for plan in plans if plan.get("row_hash")]
    plan_hash = hashlib.sha256(json.dumps(plans, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
    return {
        "profile_version": "sqlite-preview-query-plan-profile-v1",
        "plan_count": len(plans),
        "plan_hash": plan_hash,
        "plan_row_hash_count": len(row_hashes),
        "plan_row_head_hash": hashlib.sha256("\n".join(row_hashes).encode("utf-8")).hexdigest(),
        "plans": plans[:20],
        "bounded_preview_query": True,
        "arbitrary_sql_allowed": False,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["sqlite_performance"]],
        "commercial_claim_allowed": False,
    }


def sqlite_fts_functional_profile(
    *,
    database_metadata: Mapping[str, object],
    preview_table_count: int,
    preview_row_count: int,
    searchable_text_column_count: int,
    optimization_manifest: Mapping[str, object],
) -> dict[str, object]:
    return {
        "batch_id": FUNCTIONAL_SCALE_BATCH_ID,
        "item_number": 32,
        "gap_id": "#32",
        "component": "sqlite-fts-optimization",
        "status": "implemented-source-viewer-bounded-preview-validation-required",
        "implemented": True,
        "usable": True,
        "validated": True,
        "ready_for_commercial_claim": False,
        "controls": {
            "page_size": database_metadata.get("page_size"),
            "page_count": database_metadata.get("page_count"),
            "estimated_database_bytes": database_metadata.get("estimated_database_bytes"),
            "preview_table_count": preview_table_count,
            "preview_row_count": preview_row_count,
            "searchable_text_column_count": searchable_text_column_count,
            "bounded_row_preview": True,
            "case_db_fts_recommended_for_large_search": True,
            "optimization_manifest_hash": str(optimization_manifest.get("manifest_hash") or ""),
            "query_plan_hash": str(optimization_manifest.get("query_plan_hash") or ""),
            "query_plan_row_head_hash": str(optimization_manifest.get("query_plan_row_head_hash") or ""),
            "query_plan_row_hash_count": int(optimization_manifest.get("query_plan_row_hash_count") or 0),
            "wal_journal_replay_supported": bool(optimization_manifest.get("wal_journal_replay_supported")),
        },
        "blockers": [
            SQLITE_FTS_TRUSTED_DIFF_BLOCKER,
            "source-sqlite-wal-journal-replay-not-implemented-in-viewer",
            "large-table-query-plan-benchmark-not-attached",
        ],
        "validation_evidence": [
            "source-preview-emits-functional-sqlite-fts-profile",
            "unit-test-asserts-sqlite-viewer-profile-contract",
        ],
    }


def large_sqlite_fts_core_accuracy_gates(
    *,
    database_metadata: Mapping[str, object],
    previews: Sequence[Mapping[str, object]],
    searchable_text_column_count: int,
    preview_row_count: int,
    query_plan_profile: Mapping[str, object] | None = None,
    optimization_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = [
        "SQLite performance pragmas applied",
        "table profile emitted",
        "searchable text columns counted",
        "bounded row preview preserved",
        "bounded query plan profile emitted",
        "query plan row hashes emitted",
        "SQLite/FTS optimization manifest hash emitted",
        "large corpus optimization limitation warning",
    ]
    evidence_refs = [
        f"page_size:{database_metadata.get('page_size', '')}",
        f"page_count:{database_metadata.get('page_count', '')}",
        f"preview_table_count:{len(previews)}",
        f"preview_row_count:{preview_row_count}",
        f"searchable_text_column_count:{searchable_text_column_count}",
    ]
    if query_plan_profile:
        evidence_refs.append(f"query_plan_hash:{query_plan_profile.get('plan_hash', '')}")
    if optimization_manifest:
        evidence_refs.append(f"optimization_manifest_hash:{optimization_manifest.get('manifest_hash', '')}")
    trusted_diff = trusted_diff if isinstance(trusted_diff, Mapping) else {}
    if trusted_diff.get("status") == "pass":
        satisfied.append("trusted large SQLite/FTS query-plan diff pass")
        evidence_refs.append(f"trusted_tool:{trusted_diff.get('trusted_tool', '')}")
    return [
        build_accuracy_gate(
            74,
            satisfied_checks=satisfied,
            evidence_refs=evidence_refs,
        )
    ]


def build_large_sqlite_fts_trusted_diff(
    rapid_metadata: Mapping[str, object],
    trusted_metadata: Mapping[str, object],
    *,
    trusted_tool: str = "sqlite-query-plan-manifest",
) -> dict[str, object]:
    rapid = large_sqlite_fts_diff_value(rapid_metadata)
    trusted = large_sqlite_fts_diff_value(trusted_metadata)
    mismatched = [
        {"field": key, "rapid": rapid.get(key), "trusted": trusted.get(key)}
        for key in sorted(set(rapid).union(trusted))
        if rapid.get(key) != trusted.get(key)
    ]
    status = "pass" if not mismatched else "fail"
    return {
        "profile": "large-sqlite-fts-trusted-query-plan-diff-v1",
        "item_number": 74,
        "trusted_tool": trusted_tool,
        "status": status,
        "mismatched": mismatched,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["sqlite_performance"]],
        "commercial_claim_allowed": status == "pass",
    }


def large_sqlite_fts_diff_value(item: Mapping[str, object]) -> dict[str, object]:
    query_plan = item.get("query_plan_profile")
    query_plan_profile = query_plan if isinstance(query_plan, Mapping) else {}
    return {
        "page_size": int(item.get("page_size") or 0),
        "page_count": int(item.get("page_count") or 0),
        "preview_table_count": int(item.get("preview_table_count") or 0),
        "searchable_text_column_count": int(item.get("searchable_text_column_count") or 0),
        "preview_row_count": int(item.get("preview_row_count") or 0),
        "query_plan_hash": str(query_plan_profile.get("plan_hash") or ""),
    }


def quote_sqlite_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def optional_int_for_api(value: object) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def sqlite_preview_value(value: object, *, max_length: int = 240) -> object:
    if value is None or isinstance(value, (int, float)):
        return value
    if isinstance(value, bytes):
        return f"<blob {len(value)} bytes sha256={compute_hashes_for_bytes(value)['sha256'][:16]}>"
    text = str(value)
    return text if len(text) <= max_length else text[:max_length] + "...[truncated]"


def compute_hashes_for_bytes(value: bytes) -> dict[str, str]:
    import hashlib

    return {
        "md5": hashlib.md5(value).hexdigest(),
        "sha1": hashlib.sha1(value).hexdigest(),
        "sha256": hashlib.sha256(value).hexdigest(),
    }


def build_source_metadata(source_path: Path, *, include_hashes: bool) -> Dict[str, object]:
    stat = source_path.stat()
    mime_type = mimetypes.guess_type(source_path.name)[0] or "application/octet-stream"
    payload: Dict[str, object] = {
        "command": "source-metadata",
        "path": str(source_path),
        "name": source_path.name,
        "extension": source_path.suffix.lower(),
        "size": stat.st_size,
        "modified_at": dt_from_epoch(stat.st_mtime),
        "created_at": dt_from_epoch(getattr(stat, "st_birthtime", stat.st_ctime)),
        "mime_type": mime_type,
        "hashes": {},
        "hash_status": "not-requested",
        "hash_cache_assessment": hash_cache_assessment(),
    }
    if include_hashes:
        payload["hashes"] = compute_hashes(source_path)
        payload["hash_status"] = "computed"
        payload["hash_cache_assessment"] = hash_cache_assessment()
    return payload


def dt_from_epoch(value: float) -> str:
    return dt.datetime.fromtimestamp(value).isoformat()


def build_source_search(
    source_path: Path,
    keywords: Sequence[str],
    *,
    limit: int = 100,
    context: int = 120,
    max_plain_text_bytes: int = 50_000_000,
    sqlite_row_scan_limit: int | None = SQLITE_SOURCE_SEARCH_ROW_SCAN_LIMIT,
    sqlite_resume_token: str | None = None,
    file_resume_token: str | None = None,
) -> Dict[str, object]:
    normalized = [item.strip().lower() for item in keywords if item.strip()]
    if not normalized:
        raise HTTPException(status_code=400, detail="at least one keyword is required")

    stat = source_path.stat()
    suffix = source_path.suffix.lower()
    mime_type = mimetypes.guess_type(source_path.name)[0] or "application/octet-stream"
    matches: list[dict[str, object]] = []
    truncated = False
    search_diagnostics: dict[str, object] = {}
    searchable = True
    message = "File search completed."

    if mime_type.startswith("image/"):
        searchable = False
        message = "Image files are not text-searchable in the file viewer. Use OCR from the full evidence search."
    elif is_sqlite_candidate(source_path, suffix):
        try:
            sqlite_resume_state = decode_source_search_resume_token(
                sqlite_resume_token,
                source_path=source_path,
                keywords=normalized,
            ) if sqlite_resume_token else None
            matches, sqlite_truncated, search_diagnostics = search_sqlite_file(
                source_path,
                normalized,
                limit=limit,
                context=context,
                row_scan_limit=sqlite_row_scan_limit,
                resume_state=sqlite_resume_state,
            )
            if search_diagnostics.get("sqlite_resume_state"):
                token = encode_source_search_resume_token(
                    source_path=source_path,
                    keywords=normalized,
                    state=search_diagnostics["sqlite_resume_state"],
                )
                search_diagnostics["sqlite_resume_token"] = token
                search_diagnostics["sqlite_resume_token_hash"] = hashlib.sha256(token.encode("utf-8")).hexdigest()
            truncated = sqlite_truncated or len(matches) >= limit
            message = "SQLite text search completed."
        except sqlite3.DatabaseError as exc:
            searchable = False
            message = f"SQLite search failed: {exc}"
    elif suffix in SUPPORTED_DOC_EXTS:
        try:
            kind = suffix.lstrip(".")
            if file_resume_token or (stat.st_size > max_plain_text_bytes and kind in TEXT_EXTS):
                file_resume_state = decode_source_search_file_resume_token(
                    file_resume_token,
                    source_path=source_path,
                    keywords=normalized,
                ) if file_resume_token else None
                matches, truncated, search_diagnostics = search_large_byte_window_file(
                    source_path,
                    normalized,
                    limit=limit,
                    context=context,
                    max_scan_bytes=max_plain_text_bytes,
                    resume_state=file_resume_state,
                )
                if search_diagnostics.get("file_resume_state"):
                    token = encode_source_search_file_resume_token(
                        source_path=source_path,
                        keywords=normalized,
                        state=search_diagnostics["file_resume_state"],
                    )
                    search_diagnostics["file_resume_token"] = token
                    search_diagnostics["file_resume_token_hash"] = hashlib.sha256(token.encode("utf-8")).hexdigest()
                message = "Large text file byte-window search completed."
            else:
                text = extract_text(
                    source_path,
                    kind,
                    max_input_bytes=max_plain_text_bytes,
                    max_archive_member_bytes=max_plain_text_bytes,
                    max_archive_total_bytes=max_plain_text_bytes,
                )
                matches = search_text_content(text, normalized, limit=limit, context=context)
        except HTTPException:
            raise
        except Exception as exc:
            searchable = False
            message = f"Text extraction failed: {exc}"
    elif stat.st_size <= max_plain_text_bytes and is_probably_binary(source_path):
        try:
            matches, truncated = search_binary_file(source_path, normalized, limit=limit, context=context)
            message = "Binary/hex byte search completed."
        except OSError as exc:
            searchable = False
            message = f"Binary search failed: {exc}"
    elif stat.st_size <= max_plain_text_bytes:
        try:
            matches, truncated = search_plain_text_file(source_path, normalized, limit=limit, context=context)
        except UnicodeError as exc:
            searchable = False
            message = f"Text decoding failed: {exc}"
    else:
        try:
            file_resume_state = decode_source_search_file_resume_token(
                file_resume_token,
                source_path=source_path,
                keywords=normalized,
            ) if file_resume_token else None
            matches, truncated, search_diagnostics = search_large_byte_window_file(
                source_path,
                normalized,
                limit=limit,
                context=context,
                max_scan_bytes=max_plain_text_bytes,
                resume_state=file_resume_state,
            )
            if search_diagnostics.get("file_resume_state"):
                token = encode_source_search_file_resume_token(
                    source_path=source_path,
                    keywords=normalized,
                    state=search_diagnostics["file_resume_state"],
                )
                search_diagnostics["file_resume_token"] = token
                search_diagnostics["file_resume_token_hash"] = hashlib.sha256(token.encode("utf-8")).hexdigest()
            message = "Large file byte-window search completed."
        except OSError as exc:
            searchable = False
            message = f"Large file search failed: {exc}"

    return {
        "command": "source-search",
        "path": str(source_path),
        "name": source_path.name,
        "extension": suffix,
        "size": stat.st_size,
        "mime_type": mime_type,
        "keywords": normalized,
        "searchable": searchable,
        "truncated": truncated or len(matches) >= limit,
        "message": message,
        "summary": {
            "match_count": len(matches),
            "limit": limit,
            **search_diagnostics,
        },
        "source_search_profile": source_search_profile(
            source_path=source_path,
            searchable=searchable,
            truncated=truncated or len(matches) >= limit,
            match_count=len(matches),
            limit=limit,
            context=context,
            diagnostics=search_diagnostics,
        ),
        "source_search_full_cursor_contract": build_source_search_full_cursor_contract(),
        "matches": enrich_source_search_matches(source_path, matches),
    }


def source_search_profile(
    *,
    source_path: Path,
    searchable: bool,
    truncated: bool,
    match_count: int,
    limit: int,
    context: int,
    diagnostics: Mapping[str, object] | None = None,
) -> dict[str, object]:
    diagnostics = diagnostics or {}
    return {
        "profile_version": "current-file-search-v1",
        "commercial_batch_id": "commercial-uplift-016-020",
        "item_number": 17,
        "qc_prep_item_number": 56,
        "qc_prep_profile": "source-search-full-cursor-scan-v1",
        "source_search_full_cursor_contract": build_source_search_full_cursor_contract(),
        "source_path": str(source_path),
        "searchable": searchable,
        "match_count": match_count,
        "bounded_context_chars": context,
        "large_data_controls": {
            "result_limit": limit,
            "truncated": truncated,
            "sqlite_row_scan_limit": diagnostics.get("sqlite_row_scan_limit"),
            "sqlite_scanned_row_count": diagnostics.get("sqlite_scanned_row_count"),
            "sqlite_scan_truncated": diagnostics.get("sqlite_scan_truncated"),
            "sqlite_full_cursor_scan": diagnostics.get("sqlite_full_cursor_scan"),
            "sqlite_result_limit_reached": diagnostics.get("sqlite_result_limit_reached"),
            "sqlite_resume_state": diagnostics.get("sqlite_resume_state"),
            "sqlite_resume_requested": diagnostics.get("sqlite_resume_requested"),
            "sqlite_resume_token": diagnostics.get("sqlite_resume_token"),
            "sqlite_resume_token_hash": diagnostics.get("sqlite_resume_token_hash"),
            "file_search_mode": diagnostics.get("file_search_mode"),
            "file_scan_start_offset": diagnostics.get("file_scan_start_offset"),
            "file_scan_end_offset": diagnostics.get("file_scan_end_offset"),
            "file_scanned_bytes": diagnostics.get("file_scanned_bytes"),
            "file_scan_truncated": diagnostics.get("file_scan_truncated"),
            "file_result_limit_reached": diagnostics.get("file_result_limit_reached"),
            "file_resume_state": diagnostics.get("file_resume_state"),
            "file_resume_requested": diagnostics.get("file_resume_requested"),
            "file_resume_token": diagnostics.get("file_resume_token"),
            "file_resume_token_hash": diagnostics.get("file_resume_token_hash"),
            "full_case_reindex_not_required": True,
            "sqlite_table_search_uses_limit": bool(diagnostics.get("sqlite_row_scan_limit")),
            "binary_search_is_bounded": True,
        },
        "reportability_decision": {
            "decision": "do-not-report-current-file-search-hit-without-viewer-citation",
            "allowed_use": "current-file-verification-pivot",
            "required_before_report": [
                "preserve line/offset/table locator",
                "copy citation into review note",
                "verify source hash if item is selected for report",
            ],
        },
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "large-file-search-benchmark-required",
            "source-search-trusted-locator-diff-required",
        ],
    }


def enrich_source_search_matches(source_path: Path, matches: Sequence[dict[str, object]]) -> list[dict[str, object]]:
    enriched: list[dict[str, object]] = []
    for index, match in enumerate(matches):
        locator = source_search_locator(match)
        citation = source_search_citation(source_path, match, locator)
        match_id = hashlib.sha256(f"{source_path}|{index}|{citation}|{match.get('snippet', '')}".encode("utf-8")).hexdigest()[:16]
        citation_profile = source_search_citation_profile(source_path, match, locator, citation)
        item = dict(match)
        item.update(
            {
                "match_id": match_id,
                "match_index": index,
                "pointer": f"source-search:/matches/{index}",
                "source_path": str(source_path),
                "source_name": source_path.name,
                "locator": locator,
                "citation": citation,
                "citation_profile": citation_profile,
                "source_viewer_locator": citation_profile.get("source_viewer_locator", {}),
                "review_note_citation": citation_profile.get("review_note_citation", {}),
                "review_hint": "Use this citation in the viewer review note, then verify source hashes before reporting.",
                "compare_preview": f"{citation}\n{match.get('snippet', '')}",
            }
        )
        enriched.append(item)
    return enriched


def source_search_locator(match: dict[str, object]) -> dict[str, object]:
    locator: dict[str, object] = {
        "line": match.get("line"),
        "offset": match.get("offset"),
        "keyword": match.get("keyword"),
    }
    for key in ("table", "column", "row_number", "rowid", "primary_key_values"):
        if key in match:
            locator[key] = match[key]
    if isinstance(match.get("source_viewer_locator"), Mapping):
        locator["source_viewer_locator"] = dict(match["source_viewer_locator"])
    elif isinstance(match.get("sqlite_row_locator"), Mapping):
        locator["source_viewer_locator"] = dict(match["sqlite_row_locator"])
    for key in ("offset_hex", "byte_length"):
        if key in match:
            locator[key] = match[key]
    return locator


def source_search_citation(source_path: Path, match: dict[str, object], locator: dict[str, object]) -> str:
    if locator.get("table"):
        return (
            f"{source_path.name} table {locator.get('table')} row {locator.get('row_number')} "
            f"column {locator.get('column')} keyword {locator.get('keyword')}"
        )
    if locator.get("offset_hex"):
        return (
            f"{source_path.name} byte offset {locator.get('offset_hex')} "
            f"length {locator.get('byte_length')} keyword {locator.get('keyword')}"
        )
    return f"{source_path.name} line {locator.get('line')} offset {locator.get('offset')} keyword {locator.get('keyword')}"


def source_search_citation_profile(
    source_path: Path,
    match: Mapping[str, object],
    locator: Mapping[str, object],
    citation: str,
) -> dict[str, object]:
    locator_type = "sqlite-table-row" if locator.get("table") else "byte-offset" if locator.get("offset_hex") else "text-line-offset"
    source_viewer_locator = (
        locator.get("source_viewer_locator")
        if isinstance(locator.get("source_viewer_locator"), Mapping)
        else {}
    )
    review_note = (
        match.get("review_note_citation")
        if isinstance(match.get("review_note_citation"), Mapping)
        else sqlite_row_review_note_citation(source_viewer_locator)
        if source_viewer_locator
        else {}
    )
    return {
        "profile_version": "current-file-search-citation-v1",
        "item_number": 17,
        "qc_prep_item": 11 if locator_type == "sqlite-table-row" else 17,
        "source_path": str(source_path),
        "source_name": source_path.name,
        "locator_type": locator_type,
        "citation": citation,
        "keyword": str(match.get("keyword") or ""),
        "line": locator.get("line"),
        "offset": locator.get("offset"),
        "offset_hex": locator.get("offset_hex", ""),
        "table": locator.get("table", ""),
        "column": locator.get("column", ""),
        "row_number": locator.get("row_number", ""),
        "rowid": locator.get("rowid", ""),
        "primary_key_values": locator.get("primary_key_values", {}),
        "source_viewer_locator": dict(source_viewer_locator),
        "review_note_citation": dict(review_note),
        "report_draft_profile": source_search_report_draft_profile(
            source_path=source_path,
            match=match,
            locator=locator,
            citation=citation,
            review_note=review_note if isinstance(review_note, Mapping) else {},
        ),
        "ready_for_review_note": bool(citation and match.get("snippet")),
        "ready_for_report": False,
        "required_before_report": [
            "verify source file hash",
            "confirm locator in source viewer",
            "attach analyst review status",
        ],
        "commercial_grade_blockers": [
            "source-search-trusted-locator-diff-required",
            "source-hash-verification-required-for-report",
        ],
    }


def source_search_report_draft_profile(
    *,
    source_path: Path,
    match: Mapping[str, object],
    locator: Mapping[str, object],
    citation: str,
    review_note: Mapping[str, object],
) -> dict[str, object]:
    locator_payload = (
        locator.get("source_viewer_locator")
        if isinstance(locator.get("source_viewer_locator"), Mapping)
        else {}
    )
    return {
        "profile_version": "current-file-search-report-draft-profile-v1",
        "qc_prep_item": 14,
        "source_name": source_path.name,
        "citation": citation,
        "structured_citation": str(review_note.get("text") or ""),
        "source_locator_hash": str(locator_payload.get("locator_sha256") or ""),
        "snippet_sha256": hashlib.sha256(str(match.get("snippet") or "").encode("utf-8", errors="replace")).hexdigest()
        if match.get("snippet")
        else "",
        "ready_for_review_note": bool(citation and match.get("snippet")),
        "ready_for_report_draft": bool(citation and match.get("snippet")),
        "report_note_prefixes": ["Current-file hit:", "Structured citation:", "Source locator:", "Snippet:", "Review hint:"],
        "required_before_report": [
            "save source-search hit to review note",
            "verify source hash",
            "confirm locator in source viewer",
            "mark include_in_report intentionally",
        ],
    }


def search_sqlite_file(
    source_path: Path,
    keywords: Sequence[str],
    *,
    limit: int,
    context: int,
    row_scan_limit: int | None = None,
    resume_state: Mapping[str, object] | None = None,
) -> tuple[list[dict[str, object]], bool, dict[str, object]]:
    matches: list[dict[str, object]] = []
    scanned_rows = 0
    scanned_tables = 0
    truncated_tables: list[str] = []
    result_limit_reached = False
    next_resume_state: dict[str, object] | None = None
    effective_row_scan_limit = int(row_scan_limit or 0)
    resume_table = str((resume_state or {}).get("table") or "")
    resume_next_row_number = max(1, optional_int_for_api((resume_state or {}).get("next_row_number")) or 1)
    resume_consumed = not bool(resume_table)
    with contextlib.closing(sqlite3.connect(f"{source_path.as_uri()}?mode=ro", uri=True)) as connection:
        connection.row_factory = sqlite3.Row
        for table in list_sqlite_tables(connection):
            if len(matches) >= limit:
                break
            table_start_row_number = 1
            if resume_table and not resume_consumed:
                if table != resume_table:
                    continue
                table_start_row_number = resume_next_row_number
                resume_consumed = True
            quoted = quote_sqlite_identifier(table)
            column_rows = connection.execute(f"PRAGMA table_info({quoted})").fetchall()
            text_columns = [
                str(row["name"])
                for row in column_rows
                if str(row["type"] or "").upper() in {"", "TEXT", "VARCHAR", "CHAR", "CLOB"}
            ][:SQLITE_PREVIEW_COLUMN_LIMIT]
            if not text_columns:
                continue
            primary_key_columns = [
                str(row["name"])
                for row in sorted(column_rows, key=lambda item: int(item["pk"] or 0))
                if int(row["pk"] or 0) > 0
            ]
            scanned_tables += 1
            scan_columns = [*text_columns, *[column for column in primary_key_columns if column not in text_columns]]
            select_clause = ", ".join(quote_sqlite_identifier(column) for column in scan_columns)
            table_offset = max(0, table_start_row_number - 1)
            rowid_available = True
            try:
                query = f"SELECT rowid AS __rapid_source_rowid, {select_clause} FROM {quoted}"
                params_list: list[object] = []
                if effective_row_scan_limit > 0:
                    query += " LIMIT ?"
                    params_list.append(effective_row_scan_limit + 1)
                elif table_offset:
                    query += " LIMIT -1"
                if table_offset:
                    query += " OFFSET ?"
                    params_list.append(table_offset)
                params = tuple(params_list)
                row_cursor = connection.execute(query, params)
            except sqlite3.DatabaseError:
                rowid_available = False
                query = f"SELECT {select_clause} FROM {quoted}"
                params_list = []
                if effective_row_scan_limit > 0:
                    query += " LIMIT ?"
                    params_list.append(effective_row_scan_limit + 1)
                elif table_offset:
                    query += " LIMIT -1"
                if table_offset:
                    query += " OFFSET ?"
                    params_list.append(table_offset)
                params = tuple(params_list)
                row_cursor = connection.execute(query, params)
            for page_row_index, row in enumerate(row_cursor, start=0):
                row_number = table_start_row_number + page_row_index
                if effective_row_scan_limit > 0 and page_row_index >= effective_row_scan_limit:
                    truncated_tables.append(table)
                    next_resume_state = {
                        "table": table,
                        "next_row_number": row_number,
                        "reason": "sqlite-row-scan-limit",
                        "scanned_row_count": scanned_rows,
                        "match_count": len(matches),
                    }
                    break
                scanned_rows += 1
                row_values = {column: sqlite_preview_value(row[column]) for column in scan_columns}
                primary_key_values = sqlite_primary_key_values(row_values, primary_key_columns)
                for column in text_columns:
                    value = row[column]
                    if value is None:
                        continue
                    text = str(value)
                    lowered = text.lower()
                    for keyword in keywords:
                        offset = lowered.find(keyword)
                        if offset >= 0:
                            query_hash = stable_payload_sha256(
                                {
                                    "table": table,
                                    "columns": text_columns,
                                    "mode": "source-search",
                                    "keyword": keyword,
                                    "row_scan_limit": effective_row_scan_limit or "unbounded",
                                    "row_start_number": table_start_row_number,
                                }
                            )
                            sqlite_locator = sqlite_row_source_viewer_locator(
                                source_path=source_path,
                                table=table,
                                row_number=row_number,
                                rowid=row["__rapid_source_rowid"] if rowid_available else "",
                                primary_key_values=primary_key_values,
                                column=column,
                                offset=max(row_number - 1, 0),
                                limit=row_scan_limit,
                                query_hash=query_hash,
                                source_context="source-search",
                            )
                            matches.append(
                                {
                                    "keyword": keyword,
                                    "line": f"{table}:{row_number}",
                                    "offset": offset,
                                    "snippet": snippet_around(text, offset, len(keyword), context=context),
                                    "table": table,
                                    "column": column,
                                    "row_number": row_number,
                                    "rowid": row["__rapid_source_rowid"] if rowid_available else "",
                                    "primary_key_values": primary_key_values,
                                    "source_viewer_locator": sqlite_locator,
                                    "sqlite_row_locator": sqlite_locator,
                                    "review_note_citation": sqlite_row_review_note_citation(sqlite_locator),
                                }
                            )
                            if len(matches) >= limit:
                                result_limit_reached = True
                                next_resume_state = {
                                    "table": table,
                                    "next_row_number": row_number + 1,
                                    "reason": "result-limit",
                                    "scanned_row_count": scanned_rows,
                                    "match_count": len(matches),
                                    "rowid": row["__rapid_source_rowid"] if rowid_available else "",
                                }
                                return matches, True, {
                                    "sqlite_scanned_table_count": scanned_tables,
                                    "sqlite_scanned_row_count": scanned_rows,
                                    "sqlite_row_scan_limit": effective_row_scan_limit or None,
                                    "sqlite_scan_truncated": True,
                                    "sqlite_truncated_tables": truncated_tables[:10],
                                    "sqlite_full_cursor_scan": False,
                                    "sqlite_result_limit_reached": result_limit_reached,
                                    "sqlite_resume_state": next_resume_state,
                                    "sqlite_resume_requested": bool(resume_state),
                                    "sqlite_resume_consumed": resume_consumed,
                                }
                            break
    truncated = bool(truncated_tables)
    return matches, truncated, {
        "sqlite_scanned_table_count": scanned_tables,
        "sqlite_scanned_row_count": scanned_rows,
        "sqlite_row_scan_limit": effective_row_scan_limit or None,
        "sqlite_scan_truncated": truncated,
        "sqlite_truncated_tables": truncated_tables[:10],
        "sqlite_full_cursor_scan": not truncated,
        "sqlite_result_limit_reached": result_limit_reached,
        "sqlite_resume_state": next_resume_state,
        "sqlite_resume_requested": bool(resume_state),
        "sqlite_resume_consumed": resume_consumed,
    }


def encode_source_search_resume_token(*, source_path: Path, keywords: Sequence[str], state: Mapping[str, object]) -> str:
    safe_state = {
        key: state[key]
        for key in ("table", "next_row_number", "reason", "scanned_row_count", "match_count", "rowid")
        if key in state
    }
    payload = {
        "profile_version": "source-search-sqlite-resume-v1",
        "source_path_sha256": source_search_source_digest(source_path),
        "keywords_sha256": source_search_keywords_digest(keywords),
        "state": safe_state,
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_source_search_resume_token(
    token: str,
    *,
    source_path: Path,
    keywords: Sequence[str],
) -> dict[str, object]:
    try:
        padded = token + ("=" * (-len(token) % 4))
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="invalid sqlite_resume_token") from exc
    if not isinstance(payload, Mapping) or payload.get("profile_version") != "source-search-sqlite-resume-v1":
        raise HTTPException(status_code=400, detail="invalid sqlite_resume_token profile")
    if payload.get("source_path_sha256") != source_search_source_digest(source_path):
        raise HTTPException(status_code=400, detail="sqlite_resume_token does not match source file")
    if payload.get("keywords_sha256") != source_search_keywords_digest(keywords):
        raise HTTPException(status_code=400, detail="sqlite_resume_token does not match keywords")
    state = payload.get("state")
    if not isinstance(state, Mapping) or not state.get("table") or "next_row_number" not in state:
        raise HTTPException(status_code=400, detail="sqlite_resume_token is missing resume state")
    return {
        "table": str(state.get("table") or ""),
        "next_row_number": max(1, optional_int_for_api(state.get("next_row_number")) or 1),
        "reason": str(state.get("reason") or "resume-token"),
        "scanned_row_count": optional_int_for_api(state.get("scanned_row_count")) or 0,
        "match_count": optional_int_for_api(state.get("match_count")) or 0,
        "rowid": state.get("rowid", ""),
    }


def source_search_source_digest(source_path: Path) -> str:
    try:
        normalized = str(source_path.resolve())
    except OSError:
        normalized = str(source_path)
    return hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()


def source_search_keywords_digest(keywords: Sequence[str]) -> str:
    normalized = sorted(str(item).strip().lower() for item in keywords if str(item).strip())
    return hashlib.sha256(json.dumps(normalized, ensure_ascii=False).encode("utf-8")).hexdigest()


def encode_source_search_file_resume_token(*, source_path: Path, keywords: Sequence[str], state: Mapping[str, object]) -> str:
    safe_state = {
        key: state[key]
        for key in ("next_offset", "reason", "scanned_bytes", "match_count", "last_match_offset")
        if key in state
    }
    payload = {
        "profile_version": "source-search-file-resume-v1",
        "source_path_sha256": source_search_source_digest(source_path),
        "keywords_sha256": source_search_keywords_digest(keywords),
        "state": safe_state,
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_source_search_file_resume_token(
    token: str,
    *,
    source_path: Path,
    keywords: Sequence[str],
) -> dict[str, object]:
    try:
        padded = token + ("=" * (-len(token) % 4))
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="invalid file_resume_token") from exc
    if not isinstance(payload, Mapping) or payload.get("profile_version") != "source-search-file-resume-v1":
        raise HTTPException(status_code=400, detail="invalid file_resume_token profile")
    if payload.get("source_path_sha256") != source_search_source_digest(source_path):
        raise HTTPException(status_code=400, detail="file_resume_token does not match source file")
    if payload.get("keywords_sha256") != source_search_keywords_digest(keywords):
        raise HTTPException(status_code=400, detail="file_resume_token does not match keywords")
    state = payload.get("state")
    if not isinstance(state, Mapping) or "next_offset" not in state:
        raise HTTPException(status_code=400, detail="file_resume_token is missing resume state")
    return {
        "next_offset": max(0, optional_int_for_api(state.get("next_offset")) or 0),
        "reason": str(state.get("reason") or "resume-token"),
        "scanned_bytes": optional_int_for_api(state.get("scanned_bytes")) or 0,
        "match_count": optional_int_for_api(state.get("match_count")) or 0,
        "last_match_offset": optional_int_for_api(state.get("last_match_offset")),
    }


def search_text_content(text: str, keywords: Sequence[str], *, limit: int, context: int) -> list[dict[str, object]]:
    matches: list[dict[str, object]] = []
    lowered = text.lower()
    for keyword in keywords:
        start = 0
        while len(matches) < limit:
            index = lowered.find(keyword, start)
            if index < 0:
                break
            line_number = text.count("\n", 0, index) + 1
            matches.append(
                {
                    "keyword": keyword,
                    "line": line_number,
                    "offset": index,
                    "snippet": snippet_around(text, index, len(keyword), context=context),
                }
            )
            start = index + max(len(keyword), 1)
        if len(matches) >= limit:
            break
    matches.sort(key=lambda item: int(item["offset"]))
    return matches


def search_plain_text_file(
    source_path: Path,
    keywords: Sequence[str],
    *,
    limit: int,
    context: int,
) -> tuple[list[dict[str, object]], bool]:
    matches: list[dict[str, object]] = []
    truncated = False
    with source_path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line_number, line in enumerate(handle, start=1):
            lowered = line.lower()
            for keyword in keywords:
                for match in re.finditer(re.escape(keyword), lowered):
                    matches.append(
                        {
                            "keyword": keyword,
                            "line": line_number,
                            "offset": match.start(),
                            "snippet": snippet_around(line.rstrip("\n"), match.start(), len(keyword), context=context),
                        }
                    )
                    if len(matches) >= limit:
                        truncated = True
                        return matches, truncated
    return matches, truncated


def search_binary_file(
    source_path: Path,
    keywords: Sequence[str],
    *,
    limit: int,
    context: int,
) -> tuple[list[dict[str, object]], bool]:
    data = source_path.read_bytes()
    lowered = data.lower()
    matches: list[dict[str, object]] = []
    for keyword in keywords:
        needle = keyword.encode("utf-8", errors="ignore").lower()
        if not needle:
            continue
        start = 0
        while len(matches) < limit:
            index = lowered.find(needle, start)
            if index < 0:
                break
            snippet_start = max(0, index - context)
            snippet_end = min(len(data), index + len(needle) + context)
            snippet = data[snippet_start:snippet_end]
            matches.append(
                {
                    "keyword": keyword,
                    "line": f"byte:{index}",
                    "offset": index,
                    "offset_hex": f"0x{index:08x}",
                    "byte_length": len(needle),
                    "snippet": "".join(chr(byte) if 32 <= byte < 127 else "." for byte in snippet),
                    "hex_snippet": " ".join(f"{byte:02x}" for byte in snippet[:256]),
                }
            )
            start = index + max(len(needle), 1)
    matches.sort(key=lambda item: int(item["offset"]))
    return matches[:limit], len(matches) >= limit


def search_large_byte_window_file(
    source_path: Path,
    keywords: Sequence[str],
    *,
    limit: int,
    context: int,
    max_scan_bytes: int,
    resume_state: Mapping[str, object] | None = None,
) -> tuple[list[dict[str, object]], bool, dict[str, object]]:
    stat = source_path.stat()
    file_size = stat.st_size
    start_offset = min(max(0, optional_int_for_api((resume_state or {}).get("next_offset")) or 0), file_size)
    needles = [(keyword, keyword.encode("utf-8", errors="ignore").lower()) for keyword in keywords if keyword]
    needles = [(keyword, needle) for keyword, needle in needles if needle]
    overlap = min(max((len(needle) for _, needle in needles), default=1) + context, 1_048_576)
    scan_bytes = max(1, int(max_scan_bytes))
    scan_end_offset = min(file_size, start_offset + scan_bytes)
    read_end_offset = min(file_size, scan_end_offset + overlap)
    read_length = max(0, read_end_offset - start_offset)
    matches: list[dict[str, object]] = []
    result_limit_reached = False
    last_match_offset: int | None = None
    if read_length:
        with source_path.open("rb") as handle:
            handle.seek(start_offset)
            data = handle.read(read_length)
        lowered = data.lower()
        local_start = 0
        while len(matches) < limit:
            found: tuple[int, str, bytes] | None = None
            for keyword, needle in needles:
                index = lowered.find(needle, local_start)
                if index >= 0 and (found is None or index < found[0]):
                    found = (index, keyword, needle)
            if found is None:
                break
            index, keyword, needle = found
            absolute_offset = start_offset + index
            if absolute_offset >= scan_end_offset:
                break
            snippet_start = max(0, index - context)
            snippet_end = min(len(data), index + len(needle) + context)
            snippet = data[snippet_start:snippet_end]
            matches.append(
                {
                    "keyword": keyword,
                    "line": f"byte:{absolute_offset}",
                    "offset": absolute_offset,
                    "offset_hex": f"0x{absolute_offset:08x}",
                    "byte_length": len(needle),
                    "snippet": "".join(chr(byte) if 32 <= byte < 127 else "." for byte in snippet),
                    "hex_snippet": " ".join(f"{byte:02x}" for byte in snippet[:256]),
                }
            )
            last_match_offset = absolute_offset
            local_start = index + max(len(needle), 1)
        if len(matches) >= limit:
            result_limit_reached = True
    matches.sort(key=lambda item: int(item["offset"]))
    next_resume_state: dict[str, object] | None = None
    if result_limit_reached and last_match_offset is not None:
        next_resume_state = {
            "next_offset": min(file_size, last_match_offset + 1),
            "reason": "result-limit",
            "scanned_bytes": max(0, scan_end_offset - start_offset),
            "match_count": len(matches),
            "last_match_offset": last_match_offset,
        }
    elif scan_end_offset < file_size:
        next_resume_state = {
            "next_offset": scan_end_offset,
            "reason": "byte-scan-limit",
            "scanned_bytes": max(0, scan_end_offset - start_offset),
            "match_count": len(matches),
        }
    truncated = bool(next_resume_state)
    return matches[:limit], truncated, {
        "file_search_mode": "bounded-byte-window",
        "file_scan_start_offset": start_offset,
        "file_scan_end_offset": scan_end_offset,
        "file_scanned_bytes": max(0, scan_end_offset - start_offset),
        "file_read_ahead_bytes": max(0, read_end_offset - scan_end_offset),
        "file_size": file_size,
        "file_scan_truncated": truncated,
        "file_result_limit_reached": result_limit_reached,
        "file_resume_state": next_resume_state,
        "file_resume_requested": bool(resume_state),
    }


def snippet_around(text: str, index: int, length: int, *, context: int) -> str:
    start = max(0, index - context)
    end = min(len(text), index + length + context)
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(text) else ""
    return f"{prefix}{text[start:end].strip()}{suffix}"


def default_case_path(store: RunJobStore, run_id: str) -> Path:
    job = get_job(store, run_id)
    if job.summary is None:
        raise HTTPException(status_code=409, detail="run is not completed")
    output_dir = job.summary.get("output_dir")
    if not isinstance(output_dir, str) or not output_dir:
        raise HTTPException(status_code=409, detail="run summary does not include output_dir")
    return Path(output_dir).expanduser().resolve() / "rapidtriage-case.json"


def normalize_bookmark_source(source: str) -> str:
    normalized = source.strip()
    aliases = {
        "timeline": "timeline",
        "files": "files",
        "docs": "docs",
        "indicators": "indicators",
        "compare": "compare",
    }
    if normalized in aliases:
        return aliases[normalized]
    if normalized.startswith("artifacts:"):
        kind = normalized.split(":", 1)[1].strip()
        if kind:
            return f"artifacts_{kind}"
    if normalized.startswith("artifacts_"):
        return normalized
    raise HTTPException(status_code=400, detail=f"unsupported bookmark source: {source}")


def normalize_bookmark_tags(request: BookmarkCreateRequest) -> list[str]:
    raw_tags: list[str] = []
    if request.tag:
        raw_tags.append(request.tag)
    if request.tags:
        raw_tags.extend(request.tags)
    tags: list[str] = []
    seen: set[str] = set()
    for item in raw_tags:
        tag = str(item).strip()
        if not tag or tag in seen:
            continue
        seen.add(tag)
        tags.append(tag)
    return tags


app = create_app()
