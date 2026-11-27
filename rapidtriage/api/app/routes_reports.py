"""Run case, bookmark, and report-deliverable API routes."""

from __future__ import annotations

import time
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import (
    FileResponse,
)

from ...core import telemetry
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
    run_not_finished_message,
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
    load_run_review_payload,
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
    def create_case_report(
        run_id: str, request: CaseReportCreateRequest, http_request: Request
    ) -> dict[str, object]:
        started = time.perf_counter()
        snapshot = (
            http_request.app.state.case_workspace.intake.get_snapshot(run_id) if telemetry.is_recording() else None
        )
        case_id = str(snapshot["case_id"]) if snapshot is not None else None
        # One generation writes md, html, docx and pdf together: recorded once as ``md``.
        props: dict[str, object] = {"format": "md", "status": "error"}
        try:
            report_path = default_case_report_path(store, run_id)
            draft = build_run_case_report(store, run_id, request)
            exports = write_case_report_exports(draft.markdown, report_path)
            write_case_report_audit(store, run_id, report_path, request)
            props.update(status="ok", tagged_row_count=draft.tagged_rows)
        finally:
            props["duration_ms"] = int((time.perf_counter() - started) * 1000)
            telemetry.record("case_report_created", props, run_id=run_id, case_id=case_id)
        return {
            "report_path": str(report_path),
            "exports": exports,
            "audit": str(audit_path_for(report_path)),
            "markdown": draft.markdown,
        }


    @router.get("/api/runs/{run_id}/case-report/file")
    def download_case_report(run_id: str) -> FileResponse:
        report_path = default_case_report_path(store, run_id)
        if not report_path.is_file():
            request = CaseReportCreateRequest()
            write_case_report_exports(build_run_case_report(store, run_id, request).markdown, report_path)
            write_case_report_audit(store, run_id, report_path, request)
        return FileResponse(report_path, filename=report_path.name, media_type="text/markdown")


    @router.get("/api/runs/{run_id}/case-report/file/{format_name}")
    def download_case_report_format(run_id: str, format_name: str) -> FileResponse:
        normalized = format_name.lower()
        if normalized not in {"md", "html", "docx", "pdf", "manifest"}:
            raise HTTPException(status_code=404, detail="unsupported case report format")
        report_path = default_case_report_path(store, run_id)
        if not report_path.is_file():
            request = CaseReportCreateRequest()
            write_case_report_exports(build_run_case_report(store, run_id, request).markdown, report_path)
            write_case_report_audit(store, run_id, report_path, request)
        path = case_report_export_paths(report_path)[normalized]
        if not path.is_file():
            # Export missing for an existing report (e.g. written before the
            # export set changed) — re-export from the stored markdown so the
            # template the author chose is preserved instead of regenerated
            # with default settings.
            write_case_report_exports(report_path.read_text(encoding="utf-8"), report_path)
        media_types = {
            "md": "text/markdown",
            "html": "text/html",
            "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "pdf": "application/pdf",
            "manifest": "application/json",
        }
        return FileResponse(path, filename=path.name, media_type=media_types[normalized])


    def _build_reviewer_bundle(run_id: str, *, include_all: bool, max_items: int, title: str | None) -> dict[str, object]:
        """Reviewer bundle of the run's review payload (case JSON + case-DB review marks).

        409 with the reason when nothing is marked for the report or a marked
        item cannot be carried (the Korean list names each one)."""
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail=run_not_finished_message(job))
        case_payload = load_run_review_payload(store, run_id)
        if not include_all and not any(
            isinstance(item, dict) and isinstance(item.get("review"), dict) and item["review"].get("include_in_report")
            for item in case_payload.get("bookmarks") or []
        ):
            raise HTTPException(
                status_code=409,
                detail="보고서 포함으로 지정된 검토 항목이 없어 리뷰어 번들을 만들지 않았습니다. 항목을 북마크하거나 검토 표시에서 보고서 포함을 지정하세요.",
            )
        try:
            return build_submission_bundle(
                case_json=default_case_path(store, run_id),
                case_payload=case_payload,
                output_dir=default_reviewer_bundle_dir_path(store, run_id),
                allowed_roots=allowed_source_roots(job.summary),
                include_all=include_all,
                max_items=max_items,
                title=title,
            )
        except BundleError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        except (CaseBookmarkError, OSError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))


    @router.post("/api/runs/{run_id}/reviewer-bundle")
    def create_reviewer_bundle(run_id: str, request: ReviewerBundleCreateRequest) -> dict[str, object]:
        return _build_reviewer_bundle(
            run_id, include_all=request.include_all, max_items=request.max_items, title=request.title
        )


    @router.get("/api/runs/{run_id}/reviewer-bundle/file")
    def download_reviewer_bundle(run_id: str) -> FileResponse:
        payload = _build_reviewer_bundle(run_id, include_all=False, max_items=500, title=None)
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
                remove_tags=[str(item).strip() for item in (request.remove_tags or []) if str(item).strip()] or None,
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
