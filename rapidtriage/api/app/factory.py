from __future__ import annotations

import json
import mimetypes
import os
import secrets
import sqlite3
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from urllib.parse import quote

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from ...core.audit import audit_path_for, write_audit_record
from ...core.bundle import BundleError, build_submission_bundle
from ...core.case import (
    CaseBookmarkError,
    create_or_update_case_payload,
    load_case_payload,
    save_case_payload,
)
from ...core.case_catalog import (
    CaseCatalog,
    CaseCatalogError,
    default_case_catalog_path,
)
from ...core.case_db import CaseDatabaseError, open_case_database
from ...core.case_report import (
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
from ...core.docs import query_docs_index
from ...core.doctor import run_doctor
from ...core.enterprise import build_enterprise_policy
from ...core.evidence import identify_evidence, supported_evidence_formats
from ...core.indicators import (
    IndicatorSummaryError,
    build_indicator_ti_enrichment_package,
)
from ...core.jobs import (
    RunJobStore,
    RunRequest,
    default_job_store,
    run_output_dir,
)
from ...core.keyword_packs import (
    KeywordPackError,
    keyword_pack_library_assessment,
    keyword_pack_selection_profile,
    list_keyword_packs,
    resolve_keyword_packs,
)
from ...core.run import RunModeError
from ...core.sample_case import (
    SampleCaseError,
    run_sample_workflow,
)
from ...core.search import SearchError, run_unified_search
from ...core.sqlite_wal import SqliteWalPreviewError, build_sqlite_wal_preview
from ...core.visible_capabilities import build_visible_capability_response
from .constants import (
    HEX_RANGE_EXPORT_MAX_BYTES,
    IMAGE_GALLERY_DEFAULT_LIMIT,
    IMAGE_GALLERY_MAX_ITEMS,
    MUTATING_METHODS,
    SOURCE_OCR_QUEUE_DEFAULT_MAX_ITEMS,
    SQLITE_TABLE_PAGE_MAX_ROWS,
)
from .email import (
    build_email_attachment_package,
)
from .helpers import (
    allowed_api_hosts,
    allowed_source_roots,
    default_case_path,
    default_case_report_path,
    default_reviewer_bundle_dir_path,
    default_run_validation_package_path,
    default_submission_manifest_path,
    get_job,
    get_job_payload,
    get_named_output,
    get_output_path,
    is_image_preview_candidate,
    is_sqlite_candidate,
    parse_source_preview_archive_request,
    read_run_artifacts_for_capabilities,
    request_host,
    resolve_allowed_source_file,
    resolve_case_db_path,
    truthy_env,
    validate_run_evidence_source,
)
from .hex import (
    build_hex_range_citation_package,
)
from .image import (
    build_image_gallery_page,
    build_source_ocr_queue,
    build_source_ocr_translation_package,
)
from .media import (
    build_media_cue_package,
)
from .models import (
    BookmarkCreateRequest,
    CaseCatalogAddRunRequest,
    CaseDbImportRunRequest,
    CaseDbReportExportRequest,
    CaseDbReviewBatchRequest,
    CaseDbReviewRequest,
    CaseDbSavedSearchListRequest,
    CaseDbSavedSearchRequest,
    CaseDbSearchRequest,
    CaseReportCreateRequest,
    CollectPlanRequest,
    EvidenceIdentifyRequest,
    ReviewerBundleCreateRequest,
    RunCaseDbEnsureRequest,
    RunCreateRequest,
    RunImportRequest,
    SampleCaseRunRequest,
)
from .pagination import (
    paginate_payload,
)
from .previews import (
    write_json_file,
)
from .runops import (
    attach_search_result_source_actions,
    build_archived_source_api_preview,
    build_archived_source_search,
    build_commercial_readiness_api_payload,
    build_run_case_report,
    build_run_output_preview,
    build_run_submission_manifest,
    build_run_validation_package,
    build_run_viewer_workflow_validation,
    build_search_result_source_action_profile,
    build_source_metadata,
    build_source_preview,
    build_source_search,
    write_case_report_audit,
    write_run_validation_package_audit,
    write_submission_audit,
)
from .search import (
    normalize_bookmark_source,
    normalize_bookmark_tags,
)
from .sqlite import (
    build_sqlite_table_page,
)
from .viewer_core import (
    build_workbench_large_result_evidence,
    build_workbench_smoke_contract,
    resolve_commercial_readiness_validation_package,
)


def create_app(
    job_store: RunJobStore | None = None,
    auth_token: str | None = None,
    require_auth: bool | None = None,
    case_db_roots: Iterable[str | Path] | None = None,
) -> FastAPI:
    store = job_store or default_job_store
    api = FastAPI(title="rapidtriage local API", version="0.2.0")
    static_dir = Path(__file__).resolve().parent.parent.parent / "web" / "static"
    auth_disabled = truthy_env("RAPIDTRIAGE_DISABLE_AUTH") or require_auth is False
    configured_token = auth_token or os.environ.get("RAPIDTRIAGE_AUTH_TOKEN") or ""
    expected_token = "" if auth_disabled else configured_token or secrets.token_urlsafe(32)
    api.state.auth_required = bool(expected_token)
    api.state.auth_token = expected_token
    configured_case_db_roots = frozenset(case_db_roots or ())
    api.state.case_db_roots = configured_case_db_roots

    def open_request_case_database(raw_path: str | Path):
        database_path = resolve_case_db_path(store, raw_path, configured_case_db_roots)
        return open_case_database(database_path)

    @api.middleware("http")
    async def require_auth_token(request: Request, call_next):
        try:
            if request.url.path.startswith("/api"):
                host = request_host(request.headers.get("host"))
                allowed_hosts = allowed_api_hosts()
                if host and host not in allowed_hosts:
                    return JSONResponse(status_code=403, content={"detail": "RapidTriage API host is not allowed"})
                origin = request.headers.get("origin")
                if origin and request.method.upper() in MUTATING_METHODS:
                    origin_host = request_host(origin.split("//", 1)[-1])
                    if origin_host and origin_host not in allowed_hosts:
                        return JSONResponse(status_code=403, content={"detail": "RapidTriage API origin is not allowed"})
            if expected_token and request.url.path.startswith("/api"):
                if "token" in request.query_params:
                    return JSONResponse(
                        status_code=401,
                        content={"detail": "query token authentication is disabled; use X-RapidTriage-Token header"},
                    )
                supplied = request.headers.get("X-RapidTriage-Token")
                if supplied is None or not secrets.compare_digest(supplied, expected_token):
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
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @api.get("/api/workbench/smoke-contract")
    def workbench_smoke_contract() -> dict[str, object]:
        return build_workbench_smoke_contract()

    @api.get("/api/workbench/large-result-evidence")
    def workbench_large_result_evidence(record_count: int = Query(100_000, ge=1, le=10_000_000)) -> dict[str, object]:
        return build_workbench_large_result_evidence(record_count=record_count)

    @api.get("/api/commercial-readiness")
    def commercial_readiness(
        next_gate: str = Query("commercial_grade", min_length=1, max_length=64),
        limit: int = Query(8, ge=1, le=50),
        validation_package: str | None = Query(default=None, max_length=4096),
        mac_first_evidence: str | None = Query(default=None, max_length=4096),
        include_internal_validation: bool = Query(False),
    ) -> dict[str, object]:
        try:
            validation_package_path = resolve_commercial_readiness_validation_package(
                validation_package,
                include_internal_validation=include_internal_validation,
            )
            mac_first_evidence_paths = [Path(mac_first_evidence).expanduser().resolve()] if mac_first_evidence else []
            report = build_commercial_readiness_report(
                validation_package_path=validation_package_path,
                mac_first_evidence_paths=mac_first_evidence_paths,
                uplift_targets=limit,
                uplift_batch_size=5,
            )
        except CommercialReadinessError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return build_commercial_readiness_api_payload(
            report,
            next_gate=next_gate,
            limit=limit,
            validation_package_path=validation_package_path,
            include_internal_validation=include_internal_validation,
        )

    @api.get("/api/doctor")
    def doctor() -> dict[str, object]:
        return run_doctor(include_port_check=False)

    @api.get("/api/crash-reports")
    def crash_reports(limit: int = Query(50, ge=1, le=500)) -> dict[str, object]:
        return list_crash_reports(limit=limit)

    @api.get("/api/crash-reports/{crash_id}")
    def crash_report_detail(crash_id: str) -> dict[str, object]:
        try:
            return read_crash_report(crash_id)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @api.post("/api/crash-reports/{crash_id}/export")
    def crash_report_export(crash_id: str) -> dict[str, object]:
        try:
            return export_crash_report_bundle(crash_id)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @api.get("/api/enterprise/policy")
    def enterprise_policy() -> dict[str, object]:
        return build_enterprise_policy()

    @api.get("/api/evidence/formats")
    def evidence_formats() -> dict[str, object]:
        return {"formats": supported_evidence_formats()}

    @api.post("/api/evidence/identify")
    def identify_evidence_path(request: EvidenceIdentifyRequest) -> dict[str, object]:
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
    def collect_profiles() -> dict[str, object]:
        return {"profiles": list(supported_collect_profiles())}

    @api.get("/api/keyword-packs")
    def keyword_packs() -> dict[str, object]:
        return {
            "command": "keyword-packs",
            "packs": list_keyword_packs(),
            "keyword_pack_library_assessment": keyword_pack_library_assessment(),
        }

    @api.post("/api/collect/plan")
    def collect_plan(request: CollectPlanRequest) -> dict[str, object]:
        try:
            return build_collect_plan(
                Path(request.root).expanduser().resolve(),
                profile=request.profile,
                input_kind=request.input_kind,
            )
        except (CollectPlanError, OSError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @api.post("/api/sample-case/run", status_code=201)
    def run_sample_case(request: SampleCaseRunRequest) -> dict[str, object]:
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
    def import_run_to_case_db(request: CaseDbImportRunRequest) -> dict[str, object]:
        try:
            database = open_request_case_database(request.database)
            return database.import_run_output(Path(request.run_output), case_id=request.case_id, case_name=request.name)
        except (CaseDatabaseError, SearchError, OSError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @api.post("/api/runs/{run_id}/case-db/ensure")
    def ensure_run_case_db(run_id: str, request: RunCaseDbEnsureRequest) -> dict[str, object]:
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail="run is not completed")
        output_dir = run_output_dir(job.summary)
        database_path = Path(request.database).expanduser().resolve() if request.database else output_dir / "rapidtriage-case.db"
        case_id = request.case_id or f"run-{run_id}"
        case_name = request.name or f"rapidtriage run {run_id}"
        try:
            database = open_request_case_database(database_path)
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
    def search_case_db(request: CaseDbSearchRequest) -> dict[str, object]:
        try:
            keywords = resolve_keyword_packs(request.keywords, pack_names=request.keyword_packs)
            database = open_request_case_database(request.database)
            payload = database.search_case(
                case_id=request.case_id,
                keywords=keywords,
                limit=request.limit,
                cursor=request.cursor or "",
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
    def mark_case_db_review(request: CaseDbReviewRequest) -> dict[str, object]:
        try:
            database = open_request_case_database(request.database)
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
    def mark_case_db_reviews_batch(request: CaseDbReviewBatchRequest) -> dict[str, object]:
        try:
            database = open_request_case_database(request.database)
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
    def export_case_db_report_items(request: CaseDbReportExportRequest) -> dict[str, object]:
        try:
            database = open_request_case_database(request.database)
            return database.export_reviewed_items(
                case_id=request.case_id,
                include_all=request.include_all,
                max_items=request.max_items,
            )
        except CaseDatabaseError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @api.post("/api/case-db/saved-searches")
    def save_case_db_search(request: CaseDbSavedSearchRequest) -> dict[str, object]:
        try:
            database = open_request_case_database(request.database)
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
    def list_case_db_saved_searches(request: CaseDbSavedSearchListRequest) -> dict[str, object]:
        try:
            database = open_request_case_database(request.database)
            return {
                "command": "case-db.saved-searches",
                "database": str(Path(request.database).expanduser().resolve()),
                "case_id": request.case_id,
                "saved_searches": database.list_saved_searches(request.case_id),
            }
        except CaseDatabaseError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @api.get("/api/case-catalog")
    def list_case_catalog(catalog: str | None = Query(None)) -> dict[str, object]:
        try:
            case_catalog = CaseCatalog(Path(catalog).expanduser().resolve() if catalog else default_case_catalog_path())
            return {"catalog": str(case_catalog.path), "cases": case_catalog.list_cases()}
        except CaseCatalogError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @api.post("/api/case-catalog/add-run")
    def add_case_catalog_run(request: CaseCatalogAddRunRequest) -> dict[str, object]:
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
    def create_run(request: RunCreateRequest) -> dict[str, Any]:
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
    def import_run(request: RunImportRequest) -> dict[str, Any]:
        try:
            job = store.import_completed_run(request.output_dir)
        except (FileNotFoundError, OSError, json.JSONDecodeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return job.to_dict(include_summary=True)

    @api.get("/api/runs")
    def list_runs() -> dict[str, Any]:
        return {"runs": [job.to_dict() for job in store.list()]}

    @api.get("/api/forensic-capabilities")
    def get_forensic_capabilities() -> dict[str, object]:
        return build_visible_capability_response()

    @api.get("/api/runs/{run_id}")
    def get_run(run_id: str) -> dict[str, Any]:
        return get_job_payload(store, run_id, include_summary=True)

    @api.delete("/api/runs/{run_id}", status_code=204)
    def delete_run(run_id: str) -> None:
        try:
            store.remove(run_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="run not found")

    @api.post("/api/runs/{run_id}/cancel")
    def cancel_run(run_id: str) -> dict[str, Any]:
        try:
            return store.cancel(run_id).to_dict(include_summary=True)
        except KeyError:
            raise HTTPException(status_code=404, detail="run not found")

    @api.post("/api/runs/{run_id}/retry", status_code=202)
    def retry_run(run_id: str) -> dict[str, Any]:
        try:
            return store.retry(run_id).to_dict(include_summary=True)
        except KeyError:
            raise HTTPException(status_code=404, detail="run not found")
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc))

    @api.get("/api/runs/{run_id}/summary")
    def get_run_summary(run_id: str) -> dict[str, object]:
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail="run is not completed")
        return job.summary

    @api.get("/api/runs/{run_id}/capabilities")
    def get_run_capabilities(run_id: str) -> dict[str, object]:
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail="run is not completed")
        return build_visible_capability_response(
            run_summary=job.summary,
            artifacts=read_run_artifacts_for_capabilities(store, run_id, job.summary),
        )

    @api.get("/api/runs/{run_id}/viewer-workflow-validation")
    def get_run_viewer_workflow_validation(run_id: str) -> dict[str, object]:
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail="run is not completed")
        return build_run_viewer_workflow_validation(store, run_id, job.summary)

    @api.get("/api/runs/{run_id}/outputs/{output_name}")
    def get_run_output(run_id: str, output_name: str) -> dict[str, object]:
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
    def preview_run_output(run_id: str, output_name: str) -> dict[str, object]:
        path = get_output_path(store, run_id, output_name)
        return build_run_output_preview(run_id=run_id, output_name=output_name, output_path=path)

    @api.get("/api/runs/{run_id}/output-files")
    def get_run_output_files(run_id: str) -> dict[str, object]:
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
    def preview_source_file(run_id: str, path: str = Query(..., min_length=1)) -> dict[str, object]:
        archive_request = parse_source_preview_archive_request(path)
        if archive_request:
            source_path = resolve_allowed_source_file(store, run_id, archive_request["archive_path"])
            return build_archived_source_api_preview(run_id, source_path, archive_request["entry_name"])
        source_path = resolve_allowed_source_file(store, run_id, path)
        return build_source_preview(run_id, source_path)

    @api.get("/api/runs/{run_id}/source-hex-range")
    def source_hex_range(
        run_id: str,
        path: str = Query(..., min_length=1),
        offset: int = Query(0, ge=0),
        length: int = Query(256, ge=1, le=HEX_RANGE_EXPORT_MAX_BYTES),
        include_hashes: bool = False,
    ) -> dict[str, object]:
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
        where_column: str | None = Query(default=None, min_length=1),
        where_contains: str | None = Query(default=None, min_length=1),
        order_by: str | None = Query(default=None, min_length=1),
        descending: bool = False,
    ) -> dict[str, object]:
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

    @api.get("/api/runs/{run_id}/source-sqlite-wal-preview")
    def source_sqlite_wal_preview(
        run_id: str,
        path: str = Query(..., min_length=1),
        max_frames: int = Query(20, ge=1, le=100),
    ) -> dict[str, object]:
        source_path = resolve_allowed_source_file(store, run_id, path)
        if not is_sqlite_candidate(source_path):
            raise HTTPException(status_code=400, detail="source file is not a supported SQLite database")
        try:
            payload = build_sqlite_wal_preview(database_path=source_path, output_dir=None, max_frames=max_frames)
        except (SqliteWalPreviewError, OSError, sqlite3.DatabaseError) as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        payload["api_profile"] = {
            "profile_version": "source-sqlite-wal-preview-api-v1",
            "gui_binding": "sqlite-sidecar-preview",
            "source_path": str(source_path),
            "max_frames": max_frames,
            "reportability_warning": (
                "WAL preview rows are recovery leads; validate with a trusted SQLite recovery tool before reporting."
            ),
        }
        return payload

    @api.get("/api/runs/{run_id}/source-email-attachment")
    def source_email_attachment(
        run_id: str,
        path: str = Query(..., min_length=1),
        message_index: int = Query(1, ge=1),
        attachment_index: int = Query(1, ge=1),
        include_content: bool = False,
    ) -> dict[str, object]:
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
        similarity_bucket: str | None = Query(default=None, min_length=1),
    ) -> dict[str, object]:
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
    ) -> dict[str, object]:
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
    ) -> dict[str, object]:
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
    ) -> dict[str, object]:
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
        sqlite_resume_token: str | None = Query(default=None),
        file_resume_token: str | None = Query(default=None),
    ) -> dict[str, object]:
        archive_request = parse_source_preview_archive_request(path)
        if archive_request:
            source_path = resolve_allowed_source_file(store, run_id, archive_request["archive_path"])
            return build_archived_source_search(
                source_path,
                archive_request["entry_name"],
                keyword,
                limit=limit,
                context=context,
                sqlite_resume_token=sqlite_resume_token,
                file_resume_token=file_resume_token,
            )
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
        cursor: str | None = Query(default=None),
    ) -> dict[str, object]:
        payload = get_named_output(store, run_id, "timeline")
        return paginate_payload(payload, "events", offset=offset, limit=limit, cursor=cursor)

    @api.get("/api/runs/{run_id}/indicators")
    def get_run_indicators(
        run_id: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(0, ge=0, le=1000),
        cursor: str | None = Query(default=None),
    ) -> dict[str, object]:
        payload = get_named_output(store, run_id, "indicators")
        return paginate_payload(payload, "indicators", offset=offset, limit=limit, cursor=cursor)

    @api.get("/api/runs/{run_id}/indicators/ti-enrichment")
    def get_run_indicator_ti_enrichment(
        run_id: str,
        ti_feed: list[str] = Query(default=[]),
        include_unmatched: bool = Query(False),
        limit: int = Query(250, ge=1, le=1000),
    ) -> dict[str, object]:
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
        cursor: str | None = Query(default=None),
    ) -> dict[str, object]:
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

    @api.get("/api/runs/{run_id}/columnar-artifacts")
    def get_run_columnar_artifacts(
        run_id: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(200, ge=1, le=1000),
        artifact_family: str | None = Query(default=None),
        artifact_type: str | None = Query(default=None),
        keyword: str | None = Query(default=None),
    ) -> dict[str, object]:
        """Query the opt-in columnar sidecar Parquet with bounded pagination.

        Serves the run's ``columnar_artifacts`` output through DuckDB with
        parameterized family/type/keyword filters. When the sidecar was not
        produced (no ``--columnar-store``) the endpoint 404s on the missing
        output; when duckdb is not installed it returns 200 with
        ``status=skipped`` so callers fall back to the JSONL/JSON outputs.
        """
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail="run is not completed")
        try:
            path = get_output_path(store, run_id, "columnar_artifacts")
        except HTTPException as exc:
            if exc.status_code == 404:
                raise HTTPException(
                    status_code=404,
                    detail=(
                        "run output not found: columnar_artifacts; "
                        "rerun 'rapidtriage run --columnar-store' to produce the sidecar"
                    ),
                ) from exc
            raise
        return query_columnar_artifact_records(
            parquet_path=path,
            offset=offset,
            limit=limit,
            artifact_family=artifact_family,
            artifact_type=artifact_type,
            keyword=keyword,
        )

    @api.get("/api/runs/{run_id}/files")
    def get_run_files(
        run_id: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(0, ge=0, le=1000),
        cursor: str | None = Query(default=None),
    ) -> dict[str, object]:
        payload = get_named_output(store, run_id, "files")
        return paginate_payload(payload, "candidates", offset=offset, limit=limit, cursor=cursor)

    @api.get("/api/runs/{run_id}/docs")
    def get_run_docs(
        run_id: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(0, ge=0, le=1000),
        cursor: str | None = Query(default=None),
    ) -> dict[str, object]:
        payload = get_named_output(store, run_id, "docs")
        return paginate_payload(payload, "results", offset=offset, limit=limit, cursor=cursor, omit_fields=("candidates", "manifest"))

    @api.get("/api/runs/{run_id}/docs-index-search")
    def search_run_docs_index(
        run_id: str,
        keyword: list[str] = Query(..., min_length=1),
        limit: int = Query(500, ge=1, le=5000),
    ) -> dict[str, object]:
        index_path = get_output_path(store, run_id, "docs_index")
        try:
            payload = query_docs_index(index_path, keyword, limit=limit)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        query_terms = [
            str(term)
            for term in ((payload.get("query") or {}).get("terms") if isinstance(payload.get("query"), dict) else keyword)
            if str(term).strip()
        ]
        keyword_query = "".join(f"&keyword={quote(term)}" for term in query_terms)
        for index, result in enumerate(payload.get("results", [])):
            if not isinstance(result, dict) or not result.get("path"):
                continue
            result["pointer"] = str(result.get("source_locator") or f"docs-index:/results/{index}")
            result["source"] = "docs-index"
            result["matched_keywords"] = [
                item["term"]
                for item in result.get("matched_terms", [])
                if isinstance(item, dict) and item.get("term")
            ]
            matched_term_text = ", ".join(
                f"{item.get('term')}:{item.get('count')}"
                for item in result.get("matched_terms", [])
                if isinstance(item, dict) and item.get("term")
            )
            review_note_text = (
                f"Docs-index hit: {result.get('source_locator')} path={result.get('path')}\n"
                f"Matched terms: {matched_term_text or ', '.join(query_terms)}\n"
                f"Result hash: {result.get('result_hash') or ''}\n"
                "Review hint: open source viewer and current-file source-search before report inclusion"
            )
            result["review_note_citation"] = {
                "profile_version": "docs-index-review-note-citation-v1",
                "source_locator": result.get("source_locator"),
                "result_hash": result.get("result_hash"),
                "text": review_note_text,
                "ready_for_review_note": True,
                "report_use_rule": "Docs-index hits are leads until source-search confirms hit context in the original source.",
            }
            result["source_viewer_url"] = (
                f"/api/runs/{run_id}/source-preview?path={quote(str(result['path']))}"
            )
            result["source_search_url"] = (
                f"/api/runs/{run_id}/source-search?path={quote(str(result['path']))}{keyword_query}"
            )
            result["source_viewer_action_profile"] = build_search_result_source_action_profile(
                run_id,
                {
                    "path": result.get("path"),
                    "pointer": result.get("pointer"),
                    "source": "docs-index",
                    "kind": result.get("kind") or "docs-index",
                    "title": Path(str(result.get("path") or "")).name,
                    "preview": review_note_text,
                    "matched_keywords": result.get("matched_keywords") or query_terms,
                    "search_result_id": result.get("result_hash") or result.get("source_locator") or "",
                },
                index=index,
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
        path_contains: str | None = Query(default=None),
        analysis: bool = True,
        search_mode: str = Query("exact", pattern="^(exact|fuzzy|regex)$"),
        fuzzy_distance: int = Query(1, ge=0, le=2),
        proximity_window: int = Query(0, ge=0, le=100),
        hide_known_good: bool = False,
        keyword_pack: list[str] = Query(default=[]),
    ) -> dict[str, object]:
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
    def source_metadata(run_id: str, path: str = Query(..., min_length=1), hash: bool = False) -> dict[str, object]:
        source_path = resolve_allowed_source_file(store, run_id, path)
        return build_source_metadata(source_path, include_hashes=hash)

    @api.get("/api/runs/{run_id}/report", response_class=PlainTextResponse)
    def get_run_report(run_id: str) -> str:
        path = get_output_path(store, run_id, "report")
        return path.read_text(encoding="utf-8")

    @api.get("/api/runs/{run_id}/case")
    def get_run_case(run_id: str) -> dict[str, object]:
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
    ) -> dict[str, object]:
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
    def get_run_validation_package(run_id: str) -> dict[str, object]:
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
    def create_case_report(run_id: str, request: CaseReportCreateRequest) -> dict[str, object]:
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
    def create_reviewer_bundle(run_id: str, request: ReviewerBundleCreateRequest) -> dict[str, object]:
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
    def create_run_bookmark(run_id: str, request: BookmarkCreateRequest) -> dict[str, object]:
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


app = create_app()
