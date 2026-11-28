"""Case-database, case-catalog, and sample-case API routes."""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query

from ...core.case_catalog import (
    CaseCatalog,
    CaseCatalogError,
    default_case_catalog_path,
)
from ...core.case_db import (
    ACTIVE_MARK_SQL,
    EXPECTED_UPDATED_AT_KEY,
    CaseDatabase,
    CaseDatabaseError,
    ReviewConflictError,
)
from ...core.case_db.run_locator import (
    RunLocatorIndex,
    canonical_run_case,
)
from ...core.jobs import (
    RunJobStore,
    run_output_dir,
)
from ...core.keyword_packs import (
    KeywordPackError,
    resolve_keyword_packs,
)
from ...core.local_paths import ANALYSIS_OUTPUT_ROOTS_ENV, configured_root_entries
from ...core.run import RunModeError
from ...core.sample_case import (
    DEFAULT_SAMPLE_DIR,
    SampleCaseError,
    run_sample_workflow,
)
from ...core.search import (
    SearchError,
)
from .case_workspace import checked_output_path
from .helpers import (
    get_job,
    resolve_request_reviewer,
    run_not_finished_message,
    server_actor,
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
from .routes_review_tools import apply_review_tag_batch
from .run_review import (
    review_conflict_http_error,
    review_map_entries,
    split_batch_targets,
)


def _summary_output_dir(summary: dict[str, object]) -> Path | None:
    try:
        return run_output_dir(summary)
    except RuntimeError:
        return None


def resolve_run_locator_targets(
    located: Iterable[Mapping[str, str]],
    resolve: Callable[[str, str, str], tuple[str, str] | None],
) -> list[dict[str, str]]:
    """``{collection, kind?, locator}`` targets -> ``{target_type, target_id}`` by ``resolve``
    (``RunLocatorIndex.resolve``); any unresolved one is a 400 naming the first ten. The resolved
    target keeps its locator (the answer's ``targets`` tell the console which row became which
    mark) and its ``expected_updated_at`` (F14)."""
    resolved: list[dict[str, str]] = []
    unresolved: list[str] = []
    for target in located:
        collection = target.get("collection") or target.get("source") or ""
        locator = target.get("locator") or target.get("pointer") or ""
        kind = target.get("kind") or ""
        hit = resolve(collection, locator, kind)
        if hit is None:
            unresolved.append(f"{collection}:{kind}:{locator}")
            continue
        entry = {"target_type": hit[0], "target_id": hit[1], "collection": collection, "kind": kind, "locator": locator}
        expected = target.get(EXPECTED_UPDATED_AT_KEY)
        if expected is not None:
            entry[EXPECTED_UPDATED_AT_KEY] = expected
        resolved.append(entry)
    if unresolved:
        raise HTTPException(
            status_code=400,
            detail=f"케이스 DB에 이 런 로케이터에 해당하는 행이 없습니다: {', '.join(unresolved[:10])}",
        )
    return resolved


def build_case_db_router(
    store: RunJobStore,
    open_request_case_database: Callable[[str | Path], CaseDatabase],
    resolve_request_catalog_path: Callable[[str | Path], Path],
) -> APIRouter:
    router = APIRouter()

    @router.post("/api/sample-case/run", status_code=201)
    def run_sample_case(request: SampleCaseRunRequest) -> dict[str, object]:
        # The sample folder is output: under the output roots, never in evidence
        # (422). With the output roots set the default is the first one's sample
        # folder. ``overwrite`` only ever replaces an earlier sample folder.
        output_roots = configured_root_entries(ANALYSIS_OUTPUT_ROOTS_ENV)
        if request.output_dir:
            output_dir = Path(checked_output_path(request.output_dir, label="샘플 출력 폴더"))
        elif output_roots:
            output_dir = Path(checked_output_path(os.path.join(output_roots[0], DEFAULT_SAMPLE_DIR), label="샘플 출력 폴더"))
        else:
            output_dir = Path.home() / ".rapidtriage" / "sample-case"
        try:
            sample_payload = run_sample_workflow(
                output_dir,
                mode=request.mode,
                overwrite=request.overwrite,
                read_only=request.read_only,
            )
            job = store.import_completed_run(Path(str(sample_payload["run"]["output_dir"])), owner=server_actor())
            return {
                "command": "sample-case.run",
                "sample": sample_payload,
                "run": job.to_dict(include_summary=True),
            }
        except (SampleCaseError, RunModeError, OSError, json.JSONDecodeError, ValueError) as exc:
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
            except sqlite3.Error:
                by_status = {}
                db_include = 0
                cleared = 0
        bookmarks = 0
        bookmarks_in_report = 0
        case_json = output_dir / "rapidtriage-case.json"
        if case_json.is_file():
            try:
                payload = json.loads(case_json.read_text(encoding="utf-8"))
                items = payload.get("bookmarks") if isinstance(payload, dict) else None
                if isinstance(items, list):
                    bookmarks = len(items)
                    bookmarks_in_report = sum(
                        1 for item in items if isinstance(item, dict) and item.get("include_in_report")
                    )
            except (OSError, json.JSONDecodeError):
                pass
        return {
            "command": "case-db.review-counts",
            "run_id": run_id,
            "database": str(database_path),
            "case_id": case_id,
            "exists": db_exists,
            "by_status": by_status,
            "cleared": cleared,
            "include_in_report": db_include,
            "case_json": {"bookmarks": bookmarks, "include_in_report": bookmarks_in_report},
            "report_candidates": db_include + bookmarks_in_report,
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
                    created_by=resolve_request_reviewer(None) or "web-ui",
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
                reviewer=resolve_request_reviewer(request.reviewer),
                assignee=request.assignee,
                priority=request.priority,
                due_at=request.due_at,
                include_in_report=request.include_in_report,
                expected_updated_at=request.expected_updated_at,
            )
        except ReviewConflictError as exc:
            raise review_conflict_http_error(exc) from exc
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
        with database.connect() as connection:
            index = RunLocatorIndex(
                connection,
                case_id,
                outputs if isinstance(outputs, dict) else {},
                output_dir=_summary_output_dir(job.summary),
            )
            return resolve_run_locator_targets(located, index.resolve)


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

        The merge happens inside the batch's write transaction, so concurrent
        ``add_tags`` on one row keep every tag (R4); a conflict writes nothing (F14).
        """
        result = database.mark_reviews_batch(
            case_id=request.case_id,
            targets=targets,
            status=request.status,
            verification_status=request.verification_status,
            tags=request.tags,
            add_tags=request.add_tags,
            keep_tags=True,
            note=request.note,
            reviewer=resolve_request_reviewer(request.reviewer),
            assignee=request.assignee,
            priority=request.priority,
            due_at=request.due_at,
            include_in_report=request.include_in_report,
        )
        return {
            "command": "case-review-batch",
            "database": str(database.path),
            "case_id": request.case_id,
            "run_id": request.run_id,
            "updated_count": result["updated_count"],
            "targets": targets,
            "marks": result["marks"],
        }


    @router.post("/api/case-db/review-batch")
    def mark_case_db_reviews_batch(request: CaseDbReviewBatchRequest) -> dict[str, object]:
        """Marks on every target in one transaction. A target may carry ``expected_updated_at``
        (the mark's ``updated_at`` from the review map, ``""`` = no mark): when any stored mark
        changed since, the answer is 409 with every conflict and nothing is written (F14)."""
        try:
            database = open_request_case_database(request.database)
            targets, located = split_batch_targets(request.targets)
            if located:
                targets.extend(_resolve_run_locators(database, request.case_id, request.run_id, located))
            if request.tag_ids or request.remove_tag_ids or request.propagate_by_hash:
                return apply_review_tag_batch(database, request, targets)
            if request.run_id or request.add_tags:
                return _mark_preserving_tags(database, request, targets)
            return database.mark_reviews_batch(
                case_id=request.case_id,
                targets=targets,
                status=request.status,
                verification_status=request.verification_status,
                tags=request.tags,
                note=request.note,
                reviewer=resolve_request_reviewer(request.reviewer),
                assignee=request.assignee,
                priority=request.priority,
                due_at=request.due_at,
                include_in_report=request.include_in_report,
            )
        except ReviewConflictError as exc:
            raise review_conflict_http_error(exc) from exc
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
                created_by=resolve_request_reviewer(request.created_by) or "",
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
