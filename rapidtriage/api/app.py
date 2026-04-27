from __future__ import annotations

import json
import mimetypes
import os
import re
import datetime as dt
from pathlib import Path
from typing import Any, Dict, Optional, Sequence
from urllib.parse import quote

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ..core.audit import audit_path_for, write_audit_record
from ..core.case import CaseBookmarkError, create_or_update_case_payload, load_case_payload, save_case_payload
from ..core.case_catalog import CaseCatalog, CaseCatalogError, default_case_catalog_path
from ..core.case_report import build_case_report_markdown, case_report_export_paths, write_case_report_exports
from ..core.case_db import CaseDatabaseError, open_case_database
from ..core.collect_plan import CollectPlanError, build_collect_plan, supported_collect_profiles
from ..core.docs import SUPPORTED_DOC_EXTS, extract_text
from ..core.doctor import run_doctor
from ..core.evidence import identify_evidence, supported_evidence_formats
from ..core.jobs import RunJobStore, RunRequest, default_job_store, is_relative_to, run_output_dir
from ..core.run import RunModeError
from ..core.sample_case import DEFAULT_SAMPLE_MODE, SampleCaseError, run_sample_workflow
from ..core.search import SearchError, run_unified_search
from ..core.submission import compute_hashes, build_submission_manifest


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
    overwrite: bool = False
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
        if expected_token and request.url.path.startswith("/api"):
            supplied = request.headers.get("X-RapidTriage-Token") or request.query_params.get("token")
            if supplied != expected_token:
                return JSONResponse(status_code=401, content={"detail": "missing or invalid RapidTriage auth token"})
        return await call_next(request)

    @api.get("/api/health")
    def health() -> Dict[str, str]:
        return {"status": "ok"}

    @api.get("/api/doctor")
    def doctor() -> Dict[str, object]:
        return run_doctor(include_port_check=False)

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
            database = open_case_database(Path(request.database))
            payload = database.search_case(
                case_id=request.case_id,
                keywords=request.keywords,
                limit=request.limit,
                sources=request.sources,
                review_status=request.review_status,
                verification_status=request.verification_status,
            )
            if request.save_as:
                payload["saved_search"] = database.save_search(
                    case_id=request.case_id,
                    name=request.save_as,
                    keywords=request.keywords,
                    limit=request.limit,
                    sources=request.sources,
                    review_status=request.review_status,
                    verification_status=request.verification_status,
                    created_by="web-ui",
                )
            return payload
        except CaseDatabaseError as exc:
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
            overwrite=request.overwrite,
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
    ) -> Dict[str, object]:
        payload = get_named_output(store, run_id, "timeline")
        return paginate_payload(payload, "events", offset=offset, limit=limit)

    @api.get("/api/runs/{run_id}/indicators")
    def get_run_indicators(
        run_id: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(0, ge=0, le=1000),
    ) -> Dict[str, object]:
        payload = get_named_output(store, run_id, "indicators")
        return paginate_payload(payload, "indicators", offset=offset, limit=limit)

    @api.get("/api/runs/{run_id}/artifacts")
    def get_run_artifacts(
        run_id: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(0, ge=0, le=1000),
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
    ) -> Dict[str, object]:
        payload = get_named_output(store, run_id, "files")
        return paginate_payload(payload, "candidates", offset=offset, limit=limit)

    @api.get("/api/runs/{run_id}/docs")
    def get_run_docs(
        run_id: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(0, ge=0, le=1000),
    ) -> Dict[str, object]:
        payload = get_named_output(store, run_id, "docs")
        return paginate_payload(payload, "results", offset=offset, limit=limit, omit_fields=("candidates", "manifest"))

    @api.get("/api/runs/{run_id}/search")
    def search_run(
        run_id: str,
        keyword: list[str] = Query(..., min_length=1),
        ocr: bool = True,
        limit: int = Query(500, ge=1, le=1000),
        source: list[str] = Query(default=[]),
        extension: list[str] = Query(default=[]),
        path_contains: Optional[str] = Query(default=None),
    ) -> Dict[str, object]:
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail="run is not completed")
        try:
            return run_unified_search(
                job.summary,
                keyword,
                include_ocr=ocr,
                limit=limit,
                sources=source,
                extensions=extension,
                path_contains=path_contains,
            )
        except SearchError as exc:
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
    omit_fields: tuple[str, ...] = (),
) -> Dict[str, object]:
    if limit <= 0:
        return payload
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
        "has_more": end < total,
    }
    return page


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
        "preview_type": "binary",
        "text": "",
        "truncated": False,
        "message": "No inline preview is available for this file type.",
    }
    if mime_type.startswith("image/"):
        payload["preview_type"] = "image"
        payload["image_url"] = payload["download_url"]
        payload["message"] = "Image preview is available."
        return payload

    text = ""
    if suffix in SUPPORTED_DOC_EXTS:
        try:
            text = extract_text(source_path, suffix.lstrip("."))
        except Exception as exc:
            payload["message"] = f"Text extraction failed: {exc}"
            return payload
    elif stat.st_size <= 2_000_000:
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
    return payload


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
    }
    if include_hashes:
        payload["hashes"] = compute_hashes(source_path)
        payload["hash_status"] = "computed"
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
    elif suffix in SUPPORTED_DOC_EXTS:
        try:
            text = extract_text(source_path, suffix.lstrip("."))
            matches = search_text_content(text, normalized, limit=limit, context=context)
        except Exception as exc:
            searchable = False
            message = f"Text extraction failed: {exc}"
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
        "matches": matches,
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
