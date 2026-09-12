"""Case-database, case-catalog, and sample-case API routes."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query

from ...core.case_catalog import (
    CaseCatalog,
    CaseCatalogError,
    default_case_catalog_path,
)
from ...core.case_db import (
    CaseDatabase,
    CaseDatabaseError,
)
from ...core.jobs import (
    RunJobStore,
    run_output_dir,
)
from ...core.keyword_packs import (
    KeywordPackError,
    resolve_keyword_packs,
)
from ...core.run import RunModeError
from ...core.sample_case import (
    SampleCaseError,
    run_sample_workflow,
)
from ...core.search import (
    SearchError,
)
from .helpers import (
    get_job,
)
from .models import (
    CaseCatalogAddRunRequest,
    CaseDbImportRunRequest,
    CaseDbReportExportRequest,
    CaseDbReviewBatchRequest,
    CaseDbReviewRequest,
    CaseDbSavedSearchListRequest,
    CaseDbSavedSearchRequest,
    CaseDbSearchRequest,
    RunCaseDbEnsureRequest,
    SampleCaseRunRequest,
)


def build_case_db_router(
    store: RunJobStore,
    open_request_case_database: Callable[[str | Path], CaseDatabase],
) -> APIRouter:
    router = APIRouter()

    @router.post("/api/sample-case/run", status_code=201)
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


    @router.post("/api/case-db/import-run")
    def import_run_to_case_db(request: CaseDbImportRunRequest) -> dict[str, object]:
        try:
            database = open_request_case_database(request.database)
            return database.import_run_output(Path(request.run_output), case_id=request.case_id, case_name=request.name)
        except (CaseDatabaseError, SearchError, OSError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))


    @router.post("/api/runs/{run_id}/case-db/ensure")
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


    @router.post("/api/case-db/search")
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


    @router.post("/api/case-db/review")
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


    @router.post("/api/case-db/review-batch")
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


    @router.post("/api/case-db/report-export")
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


    @router.post("/api/case-db/saved-searches")
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


    @router.post("/api/case-db/saved-searches/list")
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


    @router.get("/api/case-catalog")
    def list_case_catalog(catalog: str | None = Query(None)) -> dict[str, object]:
        try:
            case_catalog = CaseCatalog(Path(catalog).expanduser().resolve() if catalog else default_case_catalog_path())
            return {"catalog": str(case_catalog.path), "cases": case_catalog.list_cases()}
        except CaseCatalogError as exc:
            raise HTTPException(status_code=400, detail=str(exc))


    @router.post("/api/case-catalog/add-run")
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

    return router
