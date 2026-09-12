"""Run case, bookmark, and report-deliverable API routes."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import (
    FileResponse,
)

from ...core.audit import audit_path_for, write_audit_record
from ...core.bundle import BundleError, build_submission_bundle
from ...core.case import (
    CaseBookmarkError,
    create_or_update_case_payload,
    load_case_payload,
    save_case_payload,
)
from ...core.case_report import (
    case_report_export_paths,
    write_case_report_exports,
)
from ...core.jobs import RunJobStore
from .helpers import (
    allowed_source_roots,
    default_case_path,
    default_case_report_path,
    default_reviewer_bundle_dir_path,
    default_run_validation_package_path,
    default_submission_manifest_path,
    get_job,
    get_output_path,
)
from .models import (
    BookmarkCreateRequest,
    CaseReportCreateRequest,
    ReviewerBundleCreateRequest,
)
from .previews import (
    write_json_file,
)
from .runops import (
    build_run_case_report,
    build_run_submission_manifest,
    build_run_validation_package,
    write_case_report_audit,
    write_run_validation_package_audit,
    write_submission_audit,
)
from .search import (
    normalize_bookmark_source,
    normalize_bookmark_tags,
)


def build_reports_router(
    store: RunJobStore,
) -> APIRouter:
    router = APIRouter()

    @router.get("/api/runs/{run_id}/case")
    def get_run_case(run_id: str) -> dict[str, object]:
        case_path = default_case_path(store, run_id)
        if not case_path.is_file():
            return {"exists": False, "case_path": str(case_path), "case": None}
        try:
            return {"exists": True, "case_path": str(case_path), "case": load_case_payload(case_path)}
        except CaseBookmarkError as exc:
            raise HTTPException(status_code=409, detail=str(exc))


    @router.get("/api/runs/{run_id}/submission-manifest")
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


    @router.get("/api/runs/{run_id}/submission-manifest/file")
    def download_submission_manifest(run_id: str, include_all: bool = False) -> FileResponse:
        manifest_path = default_submission_manifest_path(store, run_id)
        manifest = build_run_submission_manifest(store, run_id, include_all=include_all, max_items=500)
        write_json_file(manifest_path, manifest)
        write_submission_audit(store, run_id, manifest_path, include_all=include_all, max_items=500)
        return FileResponse(manifest_path, filename=manifest_path.name)


    @router.get("/api/runs/{run_id}/validation-package")
    def get_run_validation_package(run_id: str) -> dict[str, object]:
        package_path = default_run_validation_package_path(store, run_id)
        package = build_run_validation_package(store, run_id)
        write_json_file(package_path, package)
        write_run_validation_package_audit(store, run_id, package_path)
        return package


    @router.get("/api/runs/{run_id}/validation-package/file")
    def download_run_validation_package(run_id: str) -> FileResponse:
        package_path = default_run_validation_package_path(store, run_id)
        package = build_run_validation_package(store, run_id)
        write_json_file(package_path, package)
        write_run_validation_package_audit(store, run_id, package_path)
        return FileResponse(package_path, filename=package_path.name)


    @router.post("/api/runs/{run_id}/case-report")
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


    @router.get("/api/runs/{run_id}/case-report/file")
    def download_case_report(run_id: str) -> FileResponse:
        request = CaseReportCreateRequest()
        report_path = default_case_report_path(store, run_id)
        markdown = build_run_case_report(store, run_id, request)
        write_case_report_exports(markdown, report_path)
        write_case_report_audit(store, run_id, report_path, request)
        return FileResponse(report_path, filename=report_path.name, media_type="text/markdown")


    @router.get("/api/runs/{run_id}/case-report/file/{format_name}")
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


    @router.post("/api/runs/{run_id}/reviewer-bundle")
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


    @router.get("/api/runs/{run_id}/reviewer-bundle/file")
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


    @router.post("/api/runs/{run_id}/bookmarks")
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

    return router
