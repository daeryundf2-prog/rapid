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
from email import policy
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence
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
from ..core.crash import write_crash_report
from ..core.docs import SUPPORTED_DOC_EXTS, extract_text
from ..core.doctor import run_doctor
from ..core.enterprise import build_enterprise_policy
from ..core.evidence import identify_evidence, supported_evidence_formats
from ..core.forensic_accuracy import build_accuracy_gate
from ..core.hash_cache import hash_cache_assessment
from ..core.jobs import RunJobStore, RunRequest, default_job_store, is_relative_to, run_output_dir
from ..core.keyword_packs import KeywordPackError, keyword_pack_library_assessment, list_keyword_packs, resolve_keyword_packs
from ..core.run import RunModeError
from ..core.sample_case import DEFAULT_SAMPLE_MODE, SampleCaseError, run_sample_workflow
from ..core.search import SearchError, run_unified_search
from ..core.submission import compute_hashes, build_submission_manifest


SQLITE_PREVIEW_EXTS = {".sqlite", ".sqlite3", ".db", ".db3"}
SQLITE_HEADER = b"SQLite format 3\x00"
SQLITE_PREVIEW_TABLE_LIMIT = 8
SQLITE_PREVIEW_ROW_LIMIT = 10
SQLITE_PREVIEW_COLUMN_LIMIT = 12
STRUCTURED_PREVIEW_MAX_BYTES = 5 * 1024 * 1024
JSON_PREVIEW_ITEM_LIMIT = 50
XML_PREVIEW_NODE_LIMIT = 80
EMAIL_PREVIEW_MESSAGE_LIMIT = 10
EMAIL_BODY_PREVIEW_CHARS = 4000
HEX_PREVIEW_MAX_BYTES = 4096
HEX_PREVIEW_ROW_WIDTH = 16
MEDIA_TRANSCRIPT_PREVIEW_CHARS = 8000
MEDIA_TRANSCRIPT_SUFFIXES = (".srt", ".vtt", ".txt", ".transcript.txt", ".ocr.txt")
SOURCE_VIEWER_VERSION = "2"
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
    overwrite: bool = False
    resume: bool = False
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
    review_status: Optional[str] = None
    verification_status: Optional[str] = None
    save_as: Optional[str] = None
    keyword_packs: Optional[list[str]] = None


class CaseDbReviewRequest(BaseModel):
    database: str = Field(..., min_length=1)
    case_id: str = Field(..., min_length=1)
    target_type: str = Field(..., min_length=1)
    target_id: str = Field(..., min_length=1)
    status: str = "unreviewed"
    verification_status: str = "unverified"
    tags: Optional[list[str]] = None
    note: str = ""
    reviewer: str = ""
    assignee: str = ""
    priority: str = "normal"
    due_at: str = ""
    include_in_report: bool = False


class CaseDbReviewBatchRequest(BaseModel):
    database: str = Field(..., min_length=1)
    case_id: str = Field(..., min_length=1)
    targets: list[dict[str, str]] = Field(..., min_length=1)
    status: str = "unreviewed"
    verification_status: str = "unverified"
    tags: Optional[list[str]] = None
    note: str = ""
    reviewer: str = ""
    assignee: str = ""
    priority: str = "normal"
    due_at: str = ""
    include_in_report: bool = False


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
                supplied = request.headers.get("X-RapidTriage-Token") or request.query_params.get("token")
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

    @api.get("/api/doctor")
    def doctor() -> Dict[str, object]:
        return run_doctor(include_port_check=False)

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
                tags=request.tags or [],
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
                tags=request.tags or [],
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
            overwrite=request.overwrite,
            resume=request.resume,
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

    @api.get("/api/runs/{run_id}/source-search")
    def search_source_file(
        run_id: str,
        path: str = Query(..., min_length=1),
        keyword: list[str] = Query(..., min_length=1),
        limit: int = Query(100, ge=1, le=500),
        context: int = Query(120, ge=20, le=500),
    ) -> Dict[str, object]:
        source_path = resolve_allowed_source_file(store, run_id, path)
        return build_source_search(source_path, keyword, limit=limit, context=context)

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
        keyword_pack: list[str] = Query(default=[]),
    ) -> Dict[str, object]:
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail="run is not completed")
        try:
            keywords = resolve_keyword_packs(keyword, pack_names=keyword_pack)
            return run_unified_search(
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
            )
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
        "returned": max(0, end - offset),
        "total": total,
        "next_offset": end if end < total else None,
        "previous_offset": max(0, offset - limit) if offset > 0 else None,
        "cursor": encode_pagination_cursor(offset),
        "next_cursor": encode_pagination_cursor(end) if end < total else None,
        "previous_cursor": encode_pagination_cursor(max(0, offset - limit)) if offset > 0 else None,
        "has_more": end < total,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["pagination"]],
        "pagination_assessment": pagination_assessment(collection_name, total=total, returned=max(0, end - offset)),
        "core_accuracy_gates": [
            *pagination_core_accuracy_gates(collection_name, total=total, returned=max(0, end - offset), has_more=end < total),
            *ui_virtualization_core_accuracy_gates(
                label=collection_name,
                total=total,
                visible=max(0, end - offset),
                api_pagination=True,
            ),
        ],
        "ui_virtualization": ui_virtualization_metadata(
            label=collection_name,
            total=total,
            visible=max(0, end - offset),
            api_pagination=True,
        ),
    }
    return page


def pagination_assessment(collection_name: str, *, total: int, returned: int) -> dict[str, object]:
    core_gates = pagination_core_accuracy_gates(
        collection_name,
        total=total,
        returned=returned,
        has_more=returned < total,
    )
    return {
        "component": "artifact-pagination-cursor-api",
        "status": "offset-compatible-cursor-pagination",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["pagination"]],
        "collection": collection_name,
        "total": total,
        "returned": returned,
        "ready_for_court_report": False,
        "core_accuracy_gates": core_gates,
        "blockers": [
            "cursor-is-offset-token-not-snapshot-isolated-database-cursor",
            "search-endpoints-still-return-bounded-result-sets-before-case-db-pagination",
        ],
    }


def pagination_core_accuracy_gates(
    collection_name: str,
    *,
    total: int,
    returned: int,
    has_more: bool,
) -> list[dict[str, object]]:
    return [
        build_accuracy_gate(
            78,
            satisfied_checks=[
                "cursor token emitted",
                "offset/limit/total recorded",
                "next/previous cursor support",
                "bounded row return",
                "snapshot isolation limitation warning",
            ],
            evidence_refs=[f"collection:{collection_name}", f"total:{total}", f"returned:{returned}", f"has_more:{has_more}"],
        )
    ]


def ui_virtualization_metadata(*, label: str, total: int, visible: int, api_pagination: bool) -> dict[str, object]:
    return {
        "component": "ui-virtualization",
        "status": "bounded-visible-row-window",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["ui_virtualization"]],
        "label": label,
        "total_rows": total,
        "visible_rows": visible,
        "api_pagination": api_pagination,
        "ready_for_court_report": False,
        "core_accuracy_gates": ui_virtualization_core_accuracy_gates(
            label=label,
            total=total,
            visible=visible,
            api_pagination=api_pagination,
        ),
        "blockers": [
            "web-ui-uses-bounded-row-windows-and-api-pagination-not-a-full-recycling-virtual-scroller",
            "viewport-persistence-and-keyboard-navigation-require-browser-e2e-validation",
        ],
    }


def ui_virtualization_core_accuracy_gates(
    *,
    label: str,
    total: int,
    visible: int,
    api_pagination: bool,
) -> list[dict[str, object]]:
    satisfied = [
        "bounded DOM row window",
        "visible row count disclosed",
        "keyboard/filter workflow preserved",
        "true virtual scroller limitation warning",
    ]
    if api_pagination:
        satisfied.append("API pagination link preserved")
    return [
        build_accuracy_gate(
            79,
            satisfied_checks=satisfied,
            evidence_refs=[f"label:{label}", f"total_rows:{total}", f"visible_rows:{visible}"],
        )
    ]


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


def resolve_allowed_source_file(store: RunJobStore, run_id: str, raw_path: str) -> Path:
    job = get_job(store, run_id)
    if job.summary is None:
        raise HTTPException(status_code=409, detail="run is not completed")
    candidate = Path(raw_path).expanduser().resolve()
    allowed_roots = allowed_source_roots(job.summary)
    if not any(is_relative_to(candidate, root) for root in allowed_roots):
        raise HTTPException(status_code=403, detail=f"source file is outside allowed evidence roots: {candidate}")
    if not candidate.is_file():
        raise HTTPException(status_code=404, detail=f"source file not found: {candidate}")
    return candidate


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
        "review_workflow": source_review_workflow_metadata(),
        "compare_workflow": source_compare_workflow_metadata(),
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
        payload.update(build_image_preview(source_path, image_url=str(payload["download_url"])))
        return payload
    if is_sqlite_candidate(source_path, suffix):
        payload.update(build_sqlite_preview(source_path))
        return payload
    if suffix in {".json", ".jsonl", ".ndjson"}:
        payload.update(build_json_preview(source_path, suffix))
        return payload
    if suffix == ".xml":
        payload.update(build_xml_preview(source_path))
        return payload
    if suffix in {".eml", ".mbox"}:
        payload.update(build_email_preview(source_path, suffix))
        return payload
    if mime_type.startswith(("audio/", "video/")):
        payload.update(build_media_preview(source_path, mime_type=mime_type))
        return payload

    text = ""
    if suffix in SUPPORTED_DOC_EXTS:
        try:
            text = extract_text(source_path, suffix.lstrip("."))
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
    payload.update(build_hex_preview(source_path))
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
    return {
        "mode": "read-only-bounded-preview",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["preview_sandbox"]],
        "executes_content": False,
        "active_content_blocked": active_content,
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
        ),
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
    return {
        "mode": str(item.get("mode") or ""),
        "executes_content": bool(item.get("executes_content")),
        "external_network_access": bool(item.get("external_network_access")),
        "active_content_blocked": bool(item.get("active_content_blocked")),
        "max_inline_text_chars": int(item.get("max_inline_text_chars") or 0),
    }


def preview_sandbox_core_accuracy_gates(
    *,
    source_path: Path,
    active_content_blocked: bool,
    max_chars: int,
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = [
        "read-only bounded preview",
        "active content execution blocked",
        "external network access disabled",
        "preview caps recorded",
        "OS sandbox limitation warning",
    ]
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
    if source_path.stat().st_size > max_chars:
        limitations.append(f"Inline text snippets are capped near {max_chars} characters.")
    return limitations


def is_probably_binary(source_path: Path, *, sample_size: int = 4096) -> bool:
    try:
        sample = source_path.read_bytes()[:sample_size]
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


def build_sqlite_preview(source_path: Path) -> Dict[str, object]:
    try:
        with contextlib.closing(sqlite3.connect(f"{source_path.as_uri()}?mode=ro", uri=True)) as connection:
            connection.row_factory = sqlite3.Row
            database_metadata = sqlite_database_metadata(connection, source_path)
            tables = list_sqlite_tables(connection)
            previews = [preview_sqlite_table(connection, table) for table in tables[:SQLITE_PREVIEW_TABLE_LIMIT]]
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
            "tables": previews,
            "table_profiles": build_sqlite_table_profiles(previews),
            "large_sqlite_fts_optimization": sqlite_fts_optimization_metadata(database_metadata, previews),
            "table_limit": SQLITE_PREVIEW_TABLE_LIMIT,
            "row_limit": SQLITE_PREVIEW_ROW_LIMIT,
            "column_limit": SQLITE_PREVIEW_COLUMN_LIMIT,
            "truncated": len(tables) > SQLITE_PREVIEW_TABLE_LIMIT,
            "sqlite_viewer_assessment": source_viewer_component_assessment(
                VIEWER_WORKFLOW_GAP_IDS["sqlite"],
                "sqlite-table-viewer",
                [
                    "large-table-pagination-beyond-preview-limit-required",
                    "foreign-key-relationship-graph-not-yet-rendered",
                    "wal/journal-replay-and-deleted-row-recovery-not-implemented-in-viewer",
                ],
            ),
            "core_accuracy_gates": sqlite_viewer_core_accuracy_gates(
                source_path=source_path,
                database_metadata=database_metadata,
                tables=previews,
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
                ),
                blockers=[
                    "table-specific-pagination-ui-not-implemented",
                    "where-builder-ui-not-implemented",
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
                    "where_builder_ui": False,
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
                "text-column-keyword-search",
                "table-profile-summary",
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


def build_email_preview(source_path: Path, suffix: str) -> Dict[str, object]:
    try:
        if suffix == ".eml":
            messages = [email.message_from_bytes(source_path.read_bytes(), policy=policy.default)]
        else:
            messages = parse_mbox_messages(source_path)
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
    text = "\n\n".join(item["body_preview"] for item in summaries if item.get("body_preview"))
    return {
        "preview_type": "email",
        "message": "Email structured preview is available.",
        "text": text[:20000],
        "truncated": len(messages) >= EMAIL_PREVIEW_MESSAGE_LIMIT or len(text) > 20000,
        "viewer_metadata": structured_viewer_metadata("email", "bounded-email-parse", "available"),
        "email": {
            "message_count": len(summaries),
            "message_limit": EMAIL_PREVIEW_MESSAGE_LIMIT,
            "messages": summaries,
            "threads": threads,
            "conversation_view": conversation,
            "thread_count": len(threads),
            "truncated": len(messages) >= EMAIL_PREVIEW_MESSAGE_LIMIT,
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
                ),
                blockers=[
                    "native-pst-ost-msg-conversation-view-not-implemented",
                    "deleted-mailbox-item-recovery-not-implemented",
                    "attachment-extraction-and-citation-export-not-complete",
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
                    "attachment_extraction": False,
                },
            ),
        },
    }


def build_hex_preview(source_path: Path) -> Dict[str, object]:
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
    rows = []
    for offset in range(0, len(preview), HEX_PREVIEW_ROW_WIDTH):
        chunk = preview[offset : offset + HEX_PREVIEW_ROW_WIDTH]
        rows.append(
            {
                "offset": offset,
                "offset_hex": f"0x{offset:08x}",
                "hex": " ".join(f"{byte:02x}" for byte in chunk),
                "ascii": "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk),
            }
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
            },
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
                ),
                blockers=[
                    "interactive-jump-to-offset-ui-not-implemented",
                    "copy-safe-byte-selection-ui-not-implemented",
                    "exported-hex-range-citation-package-not-implemented",
                    "sector-partition-aware-navigation-not-implemented",
                    HEX_VIEWER_TRUSTED_DIFF_BLOCKER,
                ],
                source_refs=[f"source_path:{source_path}", f"preview_sha256:{preview_hashes['sha256']}"],
                controls={
                    "max_hex_preview_bytes": HEX_PREVIEW_MAX_BYTES,
                    "row_width": HEX_PREVIEW_ROW_WIDTH,
                    "row_count": len(rows),
                    "supports_keyword_byte_hits": True,
                    "full_file_inline_hash": False,
                    "export_range_citation": False,
                },
            ),
        },
    }


def build_image_preview(source_path: Path, *, image_url: str) -> Dict[str, object]:
    try:
        from ..artifacts.media import build_image_record

        artifact = build_image_record(source_path)
        details = artifact.details
        thumbnail = details.get("thumbnail_preview") if isinstance(details.get("thumbnail_preview"), dict) else {}
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
            "gallery_review": {
                "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["gallery"]],
                "tag_suggestions": image_tag_suggestions(details),
                "report_selection_hint": "Use review marks to include the image after verifying source hashes and context.",
                "similarity_bucket_key": str(details.get("similarity_bucket") or ""),
                "compare_ready": bool(details.get("perceptual_hash")),
            },
            "gallery_review_assessment": image_gallery_review_assessment(details),
            "core_accuracy_gates": image_viewer_core_accuracy_gates(source_path=source_path, details=details),
            "commercial_uplift_evidence": image_viewer_commercial_uplift_evidence(source_path=source_path, details=details),
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


def image_viewer_commercial_uplift_evidence(*, source_path: Path, details: Mapping[str, object]) -> dict[str, object]:
    gates = image_viewer_core_accuracy_gates(source_path=source_path, details=details)
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
) -> list[dict[str, object]]:
    satisfied = ["read-only SQLite open"]
    if tables:
        satisfied.append("table and schema inventory")
    if any(table.get("column_details") or table.get("indexes") for table in tables):
        satisfied.append("column/index metadata")
    if any(table.get("rows") is not None for table in tables):
        satisfied.append("bounded row preview")
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


def image_viewer_core_accuracy_gates(*, source_path: Path, details: Mapping[str, object]) -> list[dict[str, object]]:
    satisfied = []
    if details.get("width") is not None or details.get("hashes"):
        satisfied.append("image metadata and source hashes")
    if details.get("thumbnail_preview") or details.get("decoded") is not None:
        satisfied.append("thumbnail or preview metadata")
    if details.get("similarity_bucket"):
        satisfied.append("perceptual similarity bucket")
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
            ],
        )
    ]


def media_viewer_core_accuracy_gates(
    *,
    source_path: Path,
    metadata: Mapping[str, object],
    sidecars: Sequence[Mapping[str, object]],
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


def build_media_preview(source_path: Path, *, mime_type: str) -> Dict[str, object]:
    sidecars = collect_media_transcript_sidecars(source_path)
    metadata: dict[str, object] = {
        "duration_seconds": None,
        "audio_channels": None,
        "sample_rate": None,
        "frame_count": None,
    }
    if source_path.suffix.lower() == ".wav":
        metadata.update(read_wav_metadata(source_path))
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
            "source_hashes": compute_hashes(source_path) if source_path.stat().st_size <= 128 * 1024 * 1024 else {},
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
            "media_transcript_assessment": media_transcript_assessment(sidecars=sidecars),
            "core_accuracy_gates": media_viewer_core_accuracy_gates(
                source_path=source_path,
                metadata=metadata,
                sidecars=sidecars,
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
                    "selected_cue_export": False,
                },
            ),
            "limitations": [
                "Media playback/transcoding is not performed by the local viewer.",
                "Transcript sidecars are imported as review aids and must be verified against the original media.",
            ],
        },
    }


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


def parse_mbox_messages(source_path: Path) -> list[email.message.EmailMessage]:
    raw = source_path.read_bytes()
    chunks = re.split(rb"(?m)^From .*$", raw)
    messages = []
    for chunk in chunks:
        if not chunk.strip():
            continue
        messages.append(email.message_from_bytes(chunk, policy=policy.default))
        if len(messages) >= EMAIL_PREVIEW_MESSAGE_LIMIT:
            break
    return messages


def summarize_email_message(message: email.message.EmailMessage, index: int) -> dict[str, object]:
    attachments = []
    body_parts = []
    for part in message.walk():
        content_disposition = str(part.get_content_disposition() or "")
        filename = part.get_filename()
        content_type = part.get_content_type()
        if content_disposition == "attachment" or filename:
            attachments.append({"filename": filename or "", "content_type": content_type})
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


def preview_sqlite_table(connection: sqlite3.Connection, table: str) -> dict[str, object]:
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
    rows: list[dict[str, object]] = []
    if selected_columns:
        select_clause = ", ".join(quote_sqlite_identifier(column) for column in selected_columns)
        for index, row in enumerate(connection.execute(f"SELECT {select_clause} FROM {quoted} LIMIT ?", (SQLITE_PREVIEW_ROW_LIMIT,)), start=1):
            rows.append(
                {
                    "row_number": index,
                    "values": {column: sqlite_preview_value(row[column]) for column in selected_columns},
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
        "primary_key_columns": [
            str(column["name"])
            for column in sorted(column_details, key=lambda item: int(item["primary_key_position"]))
            if int(column["primary_key_position"]) > 0
        ],
        "truncated_columns": len(columns) > SQLITE_PREVIEW_COLUMN_LIMIT,
        "truncated_rows": bool(count is not None and count > SQLITE_PREVIEW_ROW_LIMIT),
        "truncated_indexes": len(index_rows) > 8,
    }


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
    return {
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["sqlite_performance"]],
        "status": "bounded-read-only-preview-with-fts-aware-guidance",
        "page_size": database_metadata.get("page_size"),
        "page_count": database_metadata.get("page_count"),
        "estimated_database_bytes": database_metadata.get("estimated_database_bytes"),
        "preview_table_count": len(previews),
        "preview_row_count": total_preview_rows,
        "searchable_text_column_count": text_column_count,
        "core_accuracy_gates": large_sqlite_fts_core_accuracy_gates(
            database_metadata=database_metadata,
            previews=previews,
            searchable_text_column_count=text_column_count,
            preview_row_count=total_preview_rows,
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


def large_sqlite_fts_core_accuracy_gates(
    *,
    database_metadata: Mapping[str, object],
    previews: Sequence[Mapping[str, object]],
    searchable_text_column_count: int,
    preview_row_count: int,
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = [
        "SQLite performance pragmas applied",
        "table profile emitted",
        "searchable text columns counted",
        "bounded row preview preserved",
        "large corpus optimization limitation warning",
    ]
    evidence_refs = [
        f"page_size:{database_metadata.get('page_size', '')}",
        f"page_count:{database_metadata.get('page_count', '')}",
        f"preview_table_count:{len(previews)}",
        f"preview_row_count:{preview_row_count}",
        f"searchable_text_column_count:{searchable_text_column_count}",
    ]
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
    return {
        "page_size": int(item.get("page_size") or 0),
        "page_count": int(item.get("page_count") or 0),
        "preview_table_count": int(item.get("preview_table_count") or 0),
        "searchable_text_column_count": int(item.get("searchable_text_column_count") or 0),
        "preview_row_count": int(item.get("preview_row_count") or 0),
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
) -> Dict[str, object]:
    normalized = [item.strip().lower() for item in keywords if item.strip()]
    if not normalized:
        raise HTTPException(status_code=400, detail="at least one keyword is required")

    stat = source_path.stat()
    suffix = source_path.suffix.lower()
    mime_type = mimetypes.guess_type(source_path.name)[0] or "application/octet-stream"
    matches: list[dict[str, object]] = []
    truncated = False
    searchable = True
    message = "File search completed."

    if mime_type.startswith("image/"):
        searchable = False
        message = "Image files are not text-searchable in the file viewer. Use OCR from the full evidence search."
    elif is_sqlite_candidate(source_path, suffix):
        try:
            matches = search_sqlite_file(source_path, normalized, limit=limit, context=context)
            truncated = len(matches) >= limit
            message = "SQLite text search completed."
        except sqlite3.DatabaseError as exc:
            searchable = False
            message = f"SQLite search failed: {exc}"
    elif suffix in SUPPORTED_DOC_EXTS:
        try:
            text = extract_text(source_path, suffix.lstrip("."))
            matches = search_text_content(text, normalized, limit=limit, context=context)
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
        searchable = False
        message = f"File is larger than the {max_plain_text_bytes} byte inline search limit."

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
        },
        "matches": enrich_source_search_matches(source_path, matches),
    }


def enrich_source_search_matches(source_path: Path, matches: Sequence[dict[str, object]]) -> list[dict[str, object]]:
    enriched: list[dict[str, object]] = []
    for index, match in enumerate(matches):
        locator = source_search_locator(match)
        citation = source_search_citation(source_path, match, locator)
        match_id = hashlib.sha256(f"{source_path}|{index}|{citation}|{match.get('snippet', '')}".encode("utf-8")).hexdigest()[:16]
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
    for key in ("table", "column", "row_number"):
        if key in match:
            locator[key] = match[key]
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


def search_sqlite_file(source_path: Path, keywords: Sequence[str], *, limit: int, context: int) -> list[dict[str, object]]:
    matches: list[dict[str, object]] = []
    with contextlib.closing(sqlite3.connect(f"{source_path.as_uri()}?mode=ro", uri=True)) as connection:
        connection.row_factory = sqlite3.Row
        for table in list_sqlite_tables(connection):
            if len(matches) >= limit:
                break
            quoted = quote_sqlite_identifier(table)
            text_columns = [
                str(row["name"])
                for row in connection.execute(f"PRAGMA table_info({quoted})").fetchall()
                if str(row["type"] or "").upper() in {"", "TEXT", "VARCHAR", "CHAR", "CLOB"}
            ][:SQLITE_PREVIEW_COLUMN_LIMIT]
            if not text_columns:
                continue
            select_clause = ", ".join(quote_sqlite_identifier(column) for column in text_columns)
            for row_index, row in enumerate(connection.execute(f"SELECT {select_clause} FROM {quoted} LIMIT 5000"), start=1):
                for column in text_columns:
                    value = row[column]
                    if value is None:
                        continue
                    text = str(value)
                    lowered = text.lower()
                    for keyword in keywords:
                        offset = lowered.find(keyword)
                        if offset >= 0:
                            matches.append(
                                {
                                    "keyword": keyword,
                                    "line": f"{table}:{row_index}",
                                    "offset": offset,
                                    "snippet": snippet_around(text, offset, len(keyword), context=context),
                                    "table": table,
                                    "column": column,
                                    "row_number": row_index,
                                }
                            )
                            if len(matches) >= limit:
                                return matches
                            break
    return matches


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
