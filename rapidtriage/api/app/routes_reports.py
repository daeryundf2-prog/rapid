"""Run case, bookmark, and report-deliverable API routes."""

from __future__ import annotations

import json
import threading
import weakref
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import (
    FileResponse,
    Response,
)

from ...core.audit import audit_path_for, keep_previous_version, write_audit_record
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
    resolve_request_reviewer,
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

#: Bookmark writes load, change and save ``rapidtriage-case.json``: one at a time, so two
#: examiners editing at once never drop each other's change (one server process).
CASE_JSON_WRITE_LOCK = threading.Lock()
#: One run's report and reviewer-bundle generation (which first moves or copies the current
#: deliverable into its history folder) runs one at a time: two examiners generating at once
#: would otherwise move the folder the other is writing (one server process). Other runs are not
#: blocked; a lock lives while a request holds it.
_RUN_DELIVERABLE_LOCKS: weakref.WeakValueDictionary[str, threading.Lock] = weakref.WeakValueDictionary()
_RUN_DELIVERABLE_LOCKS_GUARD = threading.Lock()
#: Earlier deliverables are kept here (one ``<UTC time>/`` folder per replaced version).
CASE_REPORT_HISTORY_DIR = "rapidtriage-case-report-history"
REVIEWER_BUNDLE_HISTORY_DIR = "rapidtriage-reviewer-bundle-history"


def recorded_actor() -> str:
    """Who a report, bundle or bookmark write is recorded under (the server's actor, GAP-5)."""
    return resolve_request_reviewer(None) or "local-user"


def run_deliverable_lock(run_id: str) -> threading.Lock:
    """The lock serializing ``run_id``'s case report and reviewer bundle writes."""
    with _RUN_DELIVERABLE_LOCKS_GUARD:
        lock = _RUN_DELIVERABLE_LOCKS.get(run_id)
        if lock is None:
            lock = threading.Lock()
            _RUN_DELIVERABLE_LOCKS[run_id] = lock
        return lock


def recorded_report_author(export_manifest: Path) -> str | None:
    """``generated_by`` of an existing case report export manifest (``None`` when absent)."""
    try:
        manifest = json.loads(export_manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    author = manifest.get("generated_by") if isinstance(manifest, dict) else None
    return author if isinstance(author, str) and author else None


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
        generated_by = recorded_actor()
        with run_deliverable_lock(run_id):
            markdown = build_run_case_report(store, run_id, request)
            # The report it replaces (with its audit record naming its author) stays as a version.
            previous = keep_previous_version(
                [*case_report_export_paths(report_path).values(), audit_path_for(report_path)],
                report_path.with_name(CASE_REPORT_HISTORY_DIR),
            )
            exports = write_case_report_exports(markdown, report_path, generated_by=generated_by)
            write_case_report_audit(store, run_id, report_path, request, generated_by=generated_by)
        return {
            "report_path": str(report_path),
            "exports": exports,
            "audit": str(audit_path_for(report_path)),
            "generated_by": generated_by,
            "previous_version": str(previous) if previous else None,
            "markdown": markdown,
        }


    def _ensure_case_report(run_id: str, report_path: Path) -> None:
        """Generate the run's case report with default settings when none exists yet
        (the caller holds :func:`run_deliverable_lock`)."""
        if not report_path.is_file():
            request = CaseReportCreateRequest()
            markdown = build_run_case_report(store, run_id, request)
            write_case_report_exports(markdown, report_path, generated_by=recorded_actor())
            write_case_report_audit(store, run_id, report_path, request, generated_by=recorded_actor())


    @router.get("/api/runs/{run_id}/case-report/file")
    def download_case_report(run_id: str) -> FileResponse:
        report_path = default_case_report_path(store, run_id)
        with run_deliverable_lock(run_id):
            _ensure_case_report(run_id, report_path)
        return FileResponse(report_path, filename=report_path.name, media_type="text/markdown")


    @router.get("/api/runs/{run_id}/case-report/file/{format_name}")
    def download_case_report_format(run_id: str, format_name: str) -> FileResponse:
        normalized = format_name.lower()
        if normalized not in {"md", "html", "docx", "pdf", "manifest"}:
            raise HTTPException(status_code=404, detail="unsupported case report format")
        report_path = default_case_report_path(store, run_id)
        export_paths = case_report_export_paths(report_path)
        path = export_paths[normalized]
        with run_deliverable_lock(run_id):
            _ensure_case_report(run_id, report_path)
            if not path.is_file():
                # Export missing for an existing report (e.g. written before the
                # export set changed) — re-export from the stored markdown so the
                # template the author chose is preserved instead of regenerated
                # with default settings. The report's author stays its author: a
                # download never records the downloader as ``generated_by``.
                write_case_report_exports(
                    report_path.read_text(encoding="utf-8"),
                    report_path,
                    generated_by=recorded_report_author(export_paths["manifest"]),
                )
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

        The caller holds :func:`run_deliverable_lock`. 409 with the reason when nothing is
        marked for the report or a marked item cannot be carried (the Korean list names each
        one). The server's actor is recorded as ``generated_by``; a bundle it replaces moves
        to the history folder."""
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
        bundle_dir = default_reviewer_bundle_dir_path(store, run_id)
        try:
            return build_submission_bundle(
                case_json=default_case_path(store, run_id),
                case_payload=case_payload,
                output_dir=bundle_dir,
                allowed_roots=allowed_source_roots(job.summary),
                include_all=include_all,
                max_items=max_items,
                title=title,
                generated_by=recorded_actor(),
                history_dir=bundle_dir.with_name(REVIEWER_BUNDLE_HISTORY_DIR),
            )
        except BundleError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        except (CaseBookmarkError, OSError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))


    @router.post("/api/runs/{run_id}/reviewer-bundle")
    def create_reviewer_bundle(run_id: str, request: ReviewerBundleCreateRequest) -> dict[str, object]:
        get_job(store, run_id)
        with run_deliverable_lock(run_id):
            return _build_reviewer_bundle(
                run_id, include_all=request.include_all, max_items=request.max_items, title=request.title
            )


    @router.get("/api/runs/{run_id}/reviewer-bundle/file")
    def download_reviewer_bundle(run_id: str) -> Response:
        """The bundle the last ``POST …/reviewer-bundle`` built; built here only when none exists
        (a download is not a new version in the history folder). The archive is read under the
        run's lock, so a bundle generated meanwhile never moves it away mid-download."""
        archive = default_reviewer_bundle_dir_path(store, run_id).with_suffix(".zip")
        with run_deliverable_lock(run_id):
            if not archive.is_file():
                payload = _build_reviewer_bundle(run_id, include_all=False, max_items=500, title=None)
                archive = Path(str(payload.get("archive") or payload.get("outputs", {}).get("archive", "")))
            content = archive.read_bytes()
        return Response(
            content,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{archive.name}"'},
        )


    @router.post("/api/runs/{run_id}/bookmarks")
    def create_run_bookmark(run_id: str, request: BookmarkCreateRequest) -> dict[str, object]:
        source_name = normalize_bookmark_source(request.source)
        source_path = get_output_path(store, run_id, source_name)
        case_path = default_case_path(store, run_id)
        actor = recorded_actor()
        with CASE_JSON_WRITE_LOCK:
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
                    actor=actor,
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
                    "actor": actor,
                },
                input_files=[("source-json", source_path)],
                output_files=[("case-json", case_path)],
            )
        return {"case_path": str(case_path), "audit": str(audit_output), "case": payload}

    return router
