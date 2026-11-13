"""Case-database, case-catalog, and sample-case API routes."""

from __future__ import annotations

import json
import sqlite3
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
from ...core.case_db.base import normalize_identifier
from ...core.case_db.review import saved_search_to_dict
from ...core.case_db.write_lock import (
    CaseDatabaseBatchPartialError,
    CaseDatabaseLockedError,
    case_db_batch_partial_detail,
    case_db_locked_detail,
)
from ...core.jobs import (
    RunJobStore,
    run_output_dir,
)
from ...core.keyword_packs import (
    KeywordPackError,
    resolve_keyword_packs,
)
from ...core.output_guard import (
    OutputInsideEvidenceError,
    canonical_path,
    check_output_outside_evidence,
)
from ...core.run import RunModeError
from ...core.sample_case import (
    SAMPLE_DIR_HAS_OTHER_FILES,
    SAMPLE_DIR_NOT_EMPTY,
    SAMPLE_DIR_NOT_SAMPLE,
    SampleCaseError,
    run_sample_workflow,
    sample_case_root,
)
from ...core.search import (
    SearchError,
)
from .helpers import (
    get_job,
    resolve_request_actor,
    run_not_finished_message,
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
from .review_payload import CASE_DB_UNREADABLE, report_candidate_count
from .routes_review_tools import apply_review_tag_batch
from .run_review import (
    ACTIVE_MARK_SQL,
    RunLocatorIndex,
    canonical_run_case,
    read_only_sqlite_uri,
    review_map_entries,
    split_batch_targets,
)

#: ``detail.code`` of a sample folder outside the server's sample root (stable).
PATH_OUTSIDE_ALLOWED_ROOT = "PATH_OUTSIDE_ALLOWED_ROOT"
SAMPLE_CONFLICT_CODES = frozenset({SAMPLE_DIR_NOT_EMPTY, SAMPLE_DIR_NOT_SAMPLE, SAMPLE_DIR_HAS_OTHER_FILES})


def _known_evidence_paths(store: RunJobStore) -> list[str]:
    paths: list[str] = []
    for job in store.list():
        if job.request is not None and job.request.root:
            paths.append(str(job.request.root))
        root = (job.summary or {}).get("root")
        if isinstance(root, str) and root:
            paths.append(root)
    return paths


def sample_request_output_dir(store: RunJobStore, raw: str | None) -> Path:
    """The practice-sample folder of ``POST /api/sample-case/run`` (R8 RI-04).

    The server chooses the parent (:func:`~rapidtriage.core.sample_case.sample_case_root`,
    ``~/.rapidtriage``): a request may name a folder under it, never anywhere else (403). The folder
    must not overlap the evidence of any run the server knows (``core/output_guard``, 422)."""
    allowed = sample_case_root()
    target = (Path(raw).expanduser() if raw else allowed / "sample-case").resolve()
    if target == allowed or not target.is_relative_to(allowed):
        raise HTTPException(
            status_code=403,
            detail={
                "code": PATH_OUTSIDE_ALLOWED_ROOT,
                "message": f"샘플 폴더는 서버의 샘플 위치({allowed}) 아래에만 만들 수 있습니다: {target}",
            },
        )
    try:
        # A previous sample's own synthetic evidence (``<target>/evidence``) is replaced, not guarded.
        own = canonical_path(target / "evidence")
        check_output_outside_evidence(
            target, [path for path in _known_evidence_paths(store) if canonical_path(path) != own]
        )
    except OutputInsideEvidenceError as exc:
        raise HTTPException(status_code=422, detail=exc.to_detail()) from exc
    return target


def _summary_output_dir(summary: dict[str, object]) -> Path | None:
    try:
        return run_output_dir(summary)
    except RuntimeError:
        return None


def read_only_saved_searches(database_path: Path, case_id: str) -> list[dict[str, object]]:
    """Saved searches of a case read through a ``mode=ro`` connection (none without a DB file or
    before the table exists): a read-only run folder or server never has its case DB written."""
    if not database_path.is_file():
        return []
    try:
        connection = sqlite3.connect(read_only_sqlite_uri(database_path), uri=True)
    except sqlite3.Error as exc:
        raise HTTPException(status_code=400, detail=f"케이스 DB를 열 수 없습니다: {exc}") from exc
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            "SELECT * FROM saved_search WHERE case_id = ? ORDER BY updated_at DESC, name ASC",
            (normalize_identifier(case_id, fallback="case"),),
        ).fetchall()
    except sqlite3.OperationalError:
        return []  # an older DB without the table: nothing saved
    finally:
        connection.close()
    return [saved_search_to_dict(row) for row in rows]


def build_case_db_router(
    store: RunJobStore,
    open_request_case_database: Callable[[str | Path], CaseDatabase],
    resolve_request_catalog_path: Callable[[str | Path], Path],
    read_only_case_db_path: Callable[[str | Path], Path | None] | None = None,
) -> APIRouter:
    router = APIRouter()

    @router.post("/api/sample-case/run", status_code=201)
    def run_sample_case(request: SampleCaseRunRequest) -> dict[str, object]:
        output_dir = sample_request_output_dir(store, request.output_dir)
        try:
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
        except SampleCaseError as exc:
            status = 409 if exc.code in SAMPLE_CONFLICT_CODES else 400
            raise HTTPException(status_code=status, detail={"code": exc.code, "message": str(exc)})
        except (RunModeError, OSError, json.JSONDecodeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))


    @router.get("/api/runs/{run_id}/review-counts")
    def run_review_counts(run_id: str) -> dict[str, object]:
        """Read-only review tallies for the console tree and the report gate.

        Reads the run's canonical case DB (``rapidtriage-case.db``; the
        persisted run case, or ``run-<run_id>`` from ``/case-db/ensure``) and
        the case-review JSON without creating either.
        """
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail=run_not_finished_message(job))
        output_dir = run_output_dir(job.summary)
        database_path, case_id = canonical_run_case(job.summary, run_id)
        by_status: dict[str, int] = {}
        db_include = 0
        cleared = 0
        db_error: str | None = None
        db_exists = database_path.is_file()
        if db_exists:
            try:
                connection = sqlite3.connect(f"{database_path.as_uri()}?mode=ro", uri=True)
                try:
                    # Cleared marks (back to defaults) stay in the DB for the audit
                    # trail but are not review items: counted apart, never in by_status.
                    for status, include, active, count in connection.execute(
                        f"SELECT status, include_in_report, {ACTIVE_MARK_SQL} AS active, COUNT(*) FROM review_mark "
                        "WHERE case_id = ? GROUP BY status, include_in_report, active",
                        (case_id,),
                    ):
                        if not active:
                            cleared += int(count)
                            continue
                        by_status[str(status)] = by_status.get(str(status), 0) + int(count)
                        if include:
                            db_include += int(count)
                finally:
                    connection.close()
            except sqlite3.Error as exc:
                # R8 T-025: an unreadable case DB is ``null`` + ``error``, never a silent 0.
                db_error = str(exc)
        bookmarks = 0
        case_json = output_dir / "rapidtriage-case.json"
        if case_json.is_file():
            try:
                payload = json.loads(case_json.read_text(encoding="utf-8"))
                items = payload.get("bookmarks") if isinstance(payload, dict) else None
                if isinstance(items, list):
                    bookmarks = len(items)
            except (OSError, json.JSONDecodeError):
                pass
        # R8 RI-02: the one count the case report, manifest and reviewer bundle use.
        candidates = report_candidate_count(store, run_id)
        if db_error is not None and candidates["error"] is None:
            candidates = {
                **candidates,
                "count": None,
                "error": {"code": CASE_DB_UNREADABLE, "message": f"케이스 DB를 읽지 못했습니다: {db_error}"},
            }
        return {
            "command": "case-db.review-counts",
            "run_id": run_id,
            "database": str(database_path),
            "case_id": case_id,
            "exists": db_exists,
            "by_status": None if db_error is not None else by_status,
            "cleared": None if db_error is not None else cleared,
            "include_in_report": None if db_error is not None else db_include,
            "case_json": {"bookmarks": bookmarks, "include_in_report": candidates["case_json"]},
            # ``null`` with ``error`` when a review store cannot be read (never a silent 0).
            "report_candidates": candidates["count"],
            "report_candidates_detail": candidates,
            "truncated": candidates["truncated"],
            "error": candidates["error"],
        }


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
            raise HTTPException(status_code=409, detail=run_not_finished_message(job))
        output_dir = run_output_dir(job.summary)
        default_database, default_case_id = canonical_run_case(job.summary, run_id)
        database_path = Path(request.database).expanduser().resolve() if request.database else default_database
        case_id = request.case_id or (default_case_id if not request.database else f"run-{run_id}")
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
            reviewer, actor_source = resolve_request_actor(request.reviewer)
            return database.mark_review(
                case_id=request.case_id,
                target_type=request.target_type,
                target_id=request.target_id,
                status=request.status,
                verification_status=request.verification_status,
                tags=request.tags,
                note=request.note,
                reviewer=reviewer,
                actor_source=actor_source,
                assignee=request.assignee,
                priority=request.priority,
                due_at=request.due_at,
                include_in_report=request.include_in_report,
            )
        except CaseDatabaseError as exc:
            raise HTTPException(status_code=400, detail=str(exc))


    def _resolve_run_locators(
        database: CaseDatabase,
        case_id: str,
        run_id: str | None,
        located: list[dict[str, str]],
    ) -> list[dict[str, str]]:
        """``{collection, kind?, locator}`` targets -> case-DB ``{target_type, target_id}``."""
        if not run_id:
            raise HTTPException(status_code=400, detail="로케이터 대상에는 run_id가 필요합니다")
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail=run_not_finished_message(job))
        outputs = job.summary.get("outputs")
        resolved: list[dict[str, str]] = []
        unresolved: list[str] = []
        with database.connect() as connection:
            index = RunLocatorIndex(
                connection,
                case_id,
                outputs if isinstance(outputs, dict) else {},
                output_dir=_summary_output_dir(job.summary),
            )
            for target in located:
                collection = target.get("collection") or target.get("source") or ""
                locator = target.get("locator") or target.get("pointer") or ""
                hit = index.resolve(collection, locator, target.get("kind") or "")
                if hit is None:
                    unresolved.append(f"{collection}:{target.get('kind') or ''}:{locator}")
                else:
                    resolved.append({"target_type": hit[0], "target_id": hit[1]})
        if unresolved:
            raise HTTPException(
                status_code=400,
                detail=f"케이스 DB에 이 런 로케이터에 해당하는 행이 없습니다: {', '.join(unresolved[:10])}",
            )
        return resolved


    @router.get("/api/runs/{run_id}/review-map")
    def run_review_map(run_id: str, limit: int = Query(5000, ge=1, le=50000)) -> dict[str, object]:
        """Every review mark of the run's canonical case with its run-output locator.

        Read-only (never creates the DB). The console overlays ``status``/
        ``tags``/``note`` on grid rows by ``collection|kind|locator`` and lists
        the marks on the review board.
        """
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail=run_not_finished_message(job))
        database_path, case_id = canonical_run_case(job.summary, run_id)
        payload: dict[str, object] = {
            "command": "case-db.review-map",
            "run_id": run_id,
            "database": str(database_path),
            "case_id": case_id,
            "exists": database_path.is_file(),
            "marks": [],
            "truncated": False,
        }
        if not database_path.is_file():
            return payload
        outputs = job.summary.get("outputs")
        try:
            connection = sqlite3.connect(f"{database_path.as_uri()}?mode=ro", uri=True)
            connection.row_factory = sqlite3.Row
            try:
                marks, truncated = review_map_entries(
                    connection,
                    case_id,
                    outputs if isinstance(outputs, dict) else {},
                    limit=limit,
                    output_dir=_summary_output_dir(job.summary),
                )
            finally:
                connection.close()
        except sqlite3.Error as exc:
            payload["error"] = str(exc)
            return payload
        payload["marks"] = marks
        payload["truncated"] = truncated
        return payload


    def _mark_preserving_tags(
        database: CaseDatabase,
        request: CaseDbReviewBatchRequest,
        targets: list[dict[str, str]],
    ) -> dict[str, object]:
        """Console marks: omitted ``tags`` keep the row's tags; ``add_tags`` merges.

        The merge with the row's current tags happens inside the case DB's write transaction
        (``add_tags`` of :meth:`CaseDatabase.mark_reviews_batch`), so a tag added by another window
        between our read and our write is never lost (R8 T-131 review P1-7); the batch is all or nothing.
        """
        reviewer, actor_source = resolve_request_actor(request.reviewer)
        marks = database.mark_reviews_batch(
            case_id=request.case_id,
            targets=targets,
            status=request.status,
            verification_status=request.verification_status,
            tags=request.tags,
            add_tags=request.add_tags,
            keep_omitted_tags=True,
            note=request.note,
            reviewer=reviewer,
            actor_source=actor_source,
            assignee=request.assignee,
            priority=request.priority,
            due_at=request.due_at,
            include_in_report=request.include_in_report,
        )["marks"]
        return {
            "command": "case-review-batch",
            "database": str(database.path),
            "case_id": request.case_id,
            "run_id": request.run_id,
            "updated_count": len(marks),
            "targets": targets,
            "marks": marks,
        }


    @router.post("/api/case-db/review-batch")
    def mark_case_db_reviews_batch(request: CaseDbReviewBatchRequest) -> dict[str, object]:
        try:
            database = open_request_case_database(request.database)
            targets, located = split_batch_targets(request.targets)
            if located:
                targets.extend(_resolve_run_locators(database, request.case_id, request.run_id, located))
            if request.tag_ids or request.remove_tag_ids or request.propagate_by_hash:
                return apply_review_tag_batch(database, request, targets)
            if request.run_id or request.add_tags:
                return _mark_preserving_tags(database, request, targets)
            reviewer, actor_source = resolve_request_actor(request.reviewer)
            return database.mark_reviews_batch(
                case_id=request.case_id,
                targets=targets,
                status=request.status,
                verification_status=request.verification_status,
                tags=request.tags,
                note=request.note,
                reviewer=reviewer,
                actor_source=actor_source,
                assignee=request.assignee,
                priority=request.priority,
                due_at=request.due_at,
                include_in_report=request.include_in_report,
            )
        except CaseDatabaseLockedError as exc:
            raise HTTPException(status_code=409, detail=case_db_locked_detail(exc)) from exc
        except CaseDatabaseBatchPartialError as exc:
            raise HTTPException(status_code=409, detail=case_db_batch_partial_detail(exc)) from exc
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
            read_only_path = read_only_case_db_path(request.database) if read_only_case_db_path else None
            if read_only_path is not None:
                # A read-only run folder / server: read through ``mode=ro``, never initialise it.
                saved_searches = read_only_saved_searches(read_only_path, request.case_id)
            else:
                saved_searches = open_request_case_database(request.database).list_saved_searches(request.case_id)
            return {
                "command": "case-db.saved-searches",
                "database": str(Path(request.database).expanduser().resolve()),
                "case_id": request.case_id,
                "saved_searches": saved_searches,
            }
        except CaseDatabaseError as exc:
            raise HTTPException(status_code=400, detail=str(exc))


    @router.get("/api/case-catalog")
    def list_case_catalog(catalog: str | None = Query(None)) -> dict[str, object]:
        try:
            catalog_path = resolve_request_catalog_path(catalog) if catalog else default_case_catalog_path()
            case_catalog = CaseCatalog(catalog_path)
            return {"catalog": str(case_catalog.path), "cases": case_catalog.list_cases()}
        except CaseCatalogError as exc:
            raise HTTPException(status_code=400, detail=str(exc))


    @router.post("/api/case-catalog/add-run")
    def add_case_catalog_run(request: CaseCatalogAddRunRequest) -> dict[str, object]:
        try:
            catalog_path = resolve_request_catalog_path(request.catalog) if request.catalog else default_case_catalog_path()
            case_catalog = CaseCatalog(catalog_path)
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
