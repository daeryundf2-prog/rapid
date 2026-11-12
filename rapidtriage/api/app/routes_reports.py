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
from .review_payload import load_run_review_payload
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

REVIEWER_BUNDLE_CASE_SNAPSHOT = "rapidtriage-reviewer-bundle.review-case.json"
REVIEWER_BUNDLE_EMPTY_MESSAGE = (
    "리뷰어 번들에 넣을 검토 항목이 없습니다. 행에 검토 상태나 태그를 표시한 뒤 다시 내보내세요."
)

# ``POST /case-report`` export formats, in the order its ``written`` list names them.
CASE_REPORT_FORMATS = ("md", "html", "docx", "pdf", "manifest")

#: ``detail.code`` of a download GET whose file no export POST has written yet (R8 RI-07 / T-030).
EXPORT_NOT_WRITTEN = "EXPORT_NOT_WRITTEN"


def saved_export(path: Path, label: str) -> Path:
    """The saved export at ``path`` — GETs never build or write one (404 until a POST wrote it)."""
    if not path.is_file():
        raise HTTPException(
            status_code=404,
            detail={"code": EXPORT_NOT_WRITTEN, "message": f"저장된 {label}이(가) 없습니다. 먼저 내보내기를 실행하세요"},
        )
    return path


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
        """The manifest built in memory — nothing written (``POST`` writes it with its audit).
        ``summary.truncated`` / ``max_items_skipped_count`` name candidates ``max_items`` left out."""
        return build_run_submission_manifest(store, run_id, include_all=include_all, max_items=max_items)


    @router.post("/api/runs/{run_id}/submission-manifest")
    def create_submission_manifest(
        run_id: str,
        include_all: bool = False,
        max_items: int = Query(500, ge=1, le=5000),
    ) -> dict[str, object]:
        """Write the submission manifest (+ one audit record) into the run folder once per request.

        Like ``POST /validation-package``: the response names every file written (``written``)
        and a read-only ``download_url`` (``GET /submission-manifest/saved``) so the console can
        show and open the saved manifest without building and writing it again (R7 S1 re-review
        R-4). No GET writes (R8): ``GET /submission-manifest`` builds in memory, ``/file`` and
        ``/saved`` return this saved file.
        """
        manifest_path = default_submission_manifest_path(store, run_id)
        manifest = build_run_submission_manifest(store, run_id, include_all=include_all, max_items=max_items)
        write_json_file(manifest_path, manifest)
        write_submission_audit(store, run_id, manifest_path, include_all=include_all, max_items=max_items)
        audit_path = audit_path_for(manifest_path)
        return {
            "command": "run.submission-manifest.write",
            "run_id": run_id,
            "manifest_path": str(manifest_path),
            "audit": str(audit_path),
            "written": [str(manifest_path), str(audit_path)],
            "download_url": f"/api/runs/{run_id}/submission-manifest/saved",
            "manifest": manifest,
        }


    @router.get("/api/runs/{run_id}/submission-manifest/saved")
    def open_saved_submission_manifest(run_id: str) -> FileResponse:
        """The manifest the last export wrote, read-only (404 until one was written)."""
        manifest_path = saved_export(default_submission_manifest_path(store, run_id), "제출 매니페스트")
        return FileResponse(manifest_path, filename=manifest_path.name, media_type="application/json")


    @router.get("/api/runs/{run_id}/submission-manifest/file")
    def download_submission_manifest(run_id: str) -> FileResponse:
        """The saved manifest (written by ``POST /submission-manifest``); 404 before one exists."""
        manifest_path = saved_export(default_submission_manifest_path(store, run_id), "제출 매니페스트")
        return FileResponse(manifest_path, filename=manifest_path.name)


    @router.get("/api/runs/{run_id}/validation-package")
    def get_run_validation_package(run_id: str) -> dict[str, object]:
        """The validation package built in memory — nothing written (``POST`` writes it)."""
        return build_run_validation_package(store, run_id)


    @router.post("/api/runs/{run_id}/validation-package")
    def create_run_validation_package(run_id: str) -> dict[str, object]:
        """Write the run's validation package (+ audit) into the run folder on an explicit request.

        The console's export dialog confirms first and then calls this; the response names every
        file written (``written``) and a read-only ``download_url`` for the saved package, so the
        completion toast can show the path and open it without writing again.
        """
        package_path = default_run_validation_package_path(store, run_id)
        package = build_run_validation_package(store, run_id)
        write_json_file(package_path, package)
        write_run_validation_package_audit(store, run_id, package_path)
        audit_path = audit_path_for(package_path)
        return {
            "command": "run.validation-package.write",
            "run_id": run_id,
            "package_path": str(package_path),
            "audit": str(audit_path),
            "written": [str(package_path), str(audit_path)],
            "download_url": f"/api/runs/{run_id}/validation-package/saved",
            "package": package,
        }


    @router.get("/api/runs/{run_id}/validation-package/saved")
    def open_saved_run_validation_package(run_id: str) -> FileResponse:
        """The package the last export wrote, read-only (404 until one was written)."""
        package_path = saved_export(default_run_validation_package_path(store, run_id), "검증 패키지")
        return FileResponse(package_path, filename=package_path.name, media_type="application/json")


    @router.get("/api/runs/{run_id}/validation-package/file")
    def download_run_validation_package(run_id: str) -> FileResponse:
        """The saved package (written by ``POST /validation-package``); 404 before one exists."""
        package_path = saved_export(default_run_validation_package_path(store, run_id), "검증 패키지")
        return FileResponse(package_path, filename=package_path.name)


    @router.post("/api/runs/{run_id}/case-report")
    def create_case_report(run_id: str, request: CaseReportCreateRequest) -> dict[str, object]:
        report_path = default_case_report_path(store, run_id)
        markdown = build_run_case_report(store, run_id, request)
        exports = write_case_report_exports(markdown, report_path)
        write_case_report_audit(store, run_id, report_path, request)
        audit_path = audit_path_for(report_path)
        # Every file this request wrote (R7 S1 re-review R-4): md, html, docx, pdf, export manifest, audit.
        formats = [name for name in CASE_REPORT_FORMATS if name in exports]
        return {
            "report_path": str(report_path),
            "exports": exports,
            "audit": str(audit_path),
            "written": [*(exports[name] for name in formats), str(audit_path)],
            "written_files": [
                *({"format": name, "path": exports[name], "download_url": f"/api/runs/{run_id}/case-report/file/{name}"} for name in formats),
                {"format": "audit", "path": str(audit_path), "download_url": None},
            ],
            "markdown": markdown,
        }


    @router.get("/api/runs/{run_id}/case-report/file")
    def download_case_report(run_id: str) -> FileResponse:
        """The saved report markdown (written by ``POST /case-report``); 404 before one exists."""
        report_path = saved_export(default_case_report_path(store, run_id), "보고서")
        return FileResponse(report_path, filename=report_path.name, media_type="text/markdown")


    @router.get("/api/runs/{run_id}/case-report/file/{format_name}")
    def download_case_report_format(run_id: str, format_name: str) -> FileResponse:
        normalized = format_name.lower()
        if normalized not in {"md", "html", "docx", "pdf", "manifest"}:
            raise HTTPException(status_code=404, detail="unsupported case report format")
        # Saved exports only (R8): an export missing from an older report set is written again by
        # ``POST /case-report``, never by this GET.
        report_path = saved_export(default_case_report_path(store, run_id), "보고서")
        path = saved_export(case_report_export_paths(report_path)[normalized], f"보고서({normalized.upper()})")
        media_types = {
            "md": "text/markdown",
            "html": "text/html",
            "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "pdf": "application/pdf",
            "manifest": "application/json",
        }
        return FileResponse(path, filename=path.name, media_type=media_types[normalized])


    def _reviewer_bundle_case_json(store: RunJobStore, run_id: str) -> Path:
        """Snapshot of the run's review (bookmark JSON + case DB marks) for the bundle.

        Console marks/tags live in the case DB, not in ``rapidtriage-case.json``
        (E01 QA D2), so the bundle reads a merged snapshot written beside the
        bundle folder. Neither review store is modified.
        """
        payload = load_run_review_payload(store, run_id)
        if not payload.get("bookmarks"):
            raise HTTPException(status_code=404, detail=REVIEWER_BUNDLE_EMPTY_MESSAGE)
        snapshot = default_reviewer_bundle_dir_path(store, run_id).with_name(REVIEWER_BUNDLE_CASE_SNAPSHOT)
        try:
            save_case_payload(snapshot, payload)
        except OSError as exc:
            raise HTTPException(status_code=400, detail=f"리뷰어 번들 검토 목록을 쓰지 못했습니다: {exc}")
        return snapshot

    @router.post("/api/runs/{run_id}/reviewer-bundle")
    def create_reviewer_bundle(run_id: str, request: ReviewerBundleCreateRequest) -> dict[str, object]:
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail=run_not_finished_message(job))
        case_path = _reviewer_bundle_case_json(store, run_id)
        try:
            return build_submission_bundle(
                case_json=case_path,
                output_dir=default_reviewer_bundle_dir_path(store, run_id),
                allowed_roots=allowed_source_roots(job.summary),
                include_all=request.include_all,
                max_items=request.max_items,
                title=request.title,
                run_summary=job.summary,
            )
        except (BundleError, CaseBookmarkError, OSError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))


    @router.get("/api/runs/{run_id}/reviewer-bundle/file")
    def download_reviewer_bundle(run_id: str) -> FileResponse:
        """The saved bundle archive (written by ``POST /reviewer-bundle``); 404 before one exists.

        It used to rebuild the bundle and rewrite its review snapshot on every download (R8)."""
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail=run_not_finished_message(job))
        archive = saved_export(default_reviewer_bundle_dir_path(store, run_id).with_suffix(".zip"), "리뷰어 번들")
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
