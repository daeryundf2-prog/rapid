"""Run lifecycle and run-output browsing API routes."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import (
    FileResponse,
    PlainTextResponse,
)

from ...core.columnar_store import query_columnar_artifact_records
from ...core.indicators import (
    IndicatorSummaryError,
    build_indicator_ti_enrichment_package,
)
from ...core.jobs import (
    RunJobStore,
    RunRequest,
)
from ...core.visible_capabilities import build_visible_capability_response
from .helpers import (
    default_case_path,
    enrich_summary_counts,
    get_job,
    get_job_payload,
    get_named_output,
    get_output_path,
    read_run_artifacts_for_capabilities,
    run_progress_payload,
    validate_run_evidence_source,
)
from .models import (
    RunCreateRequest,
    RunImportRequest,
)
from .pagination import (
    paginate_artifact_output,
    paginate_payload,
)
from .runops import (
    build_run_output_preview,
    build_run_viewer_workflow_validation,
)
from .timeline_hist import build_timeline_histogram
from .tree import build_run_issues, build_run_tree

ACTIVE_RUN_STATUSES = frozenset({"queued", "running"})


def compact_run_progress(progress: Mapping[str, object] | None) -> dict[str, object] | None:
    """Stage, provider counts, and running provider kinds from run progress."""
    if not isinstance(progress, Mapping):
        return None
    running = progress.get("running") if isinstance(progress.get("running"), list) else []
    return {
        "status": progress.get("status"),
        "stage": progress.get("stage"),
        "completed_count": progress.get("completed_count"),
        "total_count": progress.get("total_count"),
        "error_count": progress.get("error_count"),
        "running": [
            str(item.get("kind")) if isinstance(item, Mapping) else str(item)
            for item in running
        ],
        "updated_at": progress.get("updated_at"),
    }


CAPABILITY_RESPONSE_CACHE_MAX_ENTRIES = 16
_CAPABILITY_RESPONSE_CACHE: dict[tuple[object, ...], dict[str, object]] = {}


def capability_response_cache_key(run_id: str, summary: Mapping[str, object]) -> tuple[object, ...]:
    """Run id plus (path, mtime_ns, size) of every artifacts output and the summary JSON."""
    outputs = summary.get("outputs") if isinstance(summary.get("outputs"), Mapping) else {}
    stamps: list[tuple[str, int, int]] = []
    for name in sorted(outputs):
        if not (str(name).startswith("artifacts_") or name == "summary"):
            continue
        path = Path(str(outputs[name]))
        try:
            stat = path.stat()
            stamps.append((str(path), stat.st_mtime_ns, stat.st_size))
        except OSError:
            stamps.append((str(path), -1, -1))
    return (run_id, tuple(stamps))


def build_runs_router(
    store: RunJobStore,
) -> APIRouter:
    router = APIRouter()

    @router.post("/api/runs", status_code=202)
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
            extract=request.extract,
            known_good_hash_feeds=tuple(path.strip() for path in request.known_good_hash_feeds if path.strip()),
            hide_known_good=request.hide_known_good,
            known_good_max_hash_bytes=request.known_good_max_hash_bytes,
        )
        job = store.run_sync(run_request) if request.wait else store.submit(run_request)
        return job.to_dict(include_summary=request.wait)


    @router.post("/api/runs/import", status_code=201)
    def import_run(request: RunImportRequest) -> dict[str, Any]:
        try:
            job = store.import_completed_run(request.output_dir)
        except (FileNotFoundError, OSError, json.JSONDecodeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return job.to_dict(include_summary=True)


    @router.get("/api/runs")
    def list_runs() -> dict[str, Any]:
        runs = []
        for job in store.list():
            row = job.to_dict()
            if job.status in ACTIVE_RUN_STATUSES:
                # Compact live progress for the run card (full payload on
                # GET /api/runs/{run_id}); finished runs skip the file read.
                row["progress"] = compact_run_progress(run_progress_payload(job))
            runs.append(row)
        return {"runs": runs}


    @router.get("/api/runs/{run_id}")
    def get_run(run_id: str) -> dict[str, Any]:
        payload = get_job_payload(store, run_id, include_summary=True)
        # Live per-provider progress (rapidtriage-run-progress.json); null
        # until the run has written it.
        payload["progress"] = run_progress_payload(get_job(store, run_id))
        return payload


    @router.delete("/api/runs/{run_id}", status_code=204)
    def delete_run(run_id: str) -> None:
        try:
            store.remove(run_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="run not found")


    @router.post("/api/runs/{run_id}/cancel")
    def cancel_run(run_id: str) -> dict[str, Any]:
        try:
            return store.cancel(run_id).to_dict(include_summary=True)
        except KeyError:
            raise HTTPException(status_code=404, detail="run not found")


    @router.post("/api/runs/{run_id}/retry", status_code=202)
    def retry_run(run_id: str) -> dict[str, Any]:
        try:
            return store.retry(run_id).to_dict(include_summary=True)
        except KeyError:
            raise HTTPException(status_code=404, detail="run not found")
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc))


    @router.get("/api/runs/{run_id}/summary")
    def get_run_summary(run_id: str) -> dict[str, object]:
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail="run is not completed")
        try:
            case_path = default_case_path(store, run_id)
        except HTTPException:
            case_path = None
        return enrich_summary_counts(job.summary, case_path=case_path)


    @router.get("/api/runs/{run_id}/capabilities")
    def get_run_capabilities(run_id: str) -> dict[str, object]:
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail="run is not completed")
        # Completed run outputs are immutable; reuse the response until any
        # artifacts output (or the summary) changes on disk.
        cache_key = capability_response_cache_key(run_id, job.summary)
        cached = _CAPABILITY_RESPONSE_CACHE.get(cache_key)
        if cached is not None:
            return cached
        response = build_visible_capability_response(
            run_summary=job.summary,
            artifacts=read_run_artifacts_for_capabilities(store, run_id, job.summary),
        )
        if len(_CAPABILITY_RESPONSE_CACHE) >= CAPABILITY_RESPONSE_CACHE_MAX_ENTRIES:
            _CAPABILITY_RESPONSE_CACHE.pop(next(iter(_CAPABILITY_RESPONSE_CACHE)))
        _CAPABILITY_RESPONSE_CACHE[cache_key] = response
        return response


    @router.get("/api/runs/{run_id}/viewer-workflow-validation")
    def get_run_viewer_workflow_validation(run_id: str) -> dict[str, object]:
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail="run is not completed")
        return build_run_viewer_workflow_validation(store, run_id, job.summary)


    @router.get("/api/runs/{run_id}/outputs/{output_name}")
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


    @router.get("/api/runs/{run_id}/outputs/{output_name}/preview")
    def preview_run_output(run_id: str, output_name: str) -> dict[str, object]:
        path = get_output_path(store, run_id, output_name)
        return build_run_output_preview(run_id=run_id, output_name=output_name, output_path=path)


    @router.get("/api/runs/{run_id}/output-files")
    def get_run_output_files(run_id: str) -> dict[str, object]:
        try:
            return {"files": store.output_files(run_id)}
        except KeyError:
            raise HTTPException(status_code=404, detail="run not found")
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc))


    @router.get("/api/runs/{run_id}/outputs/{output_name}/file")
    def download_run_output(run_id: str, output_name: str) -> FileResponse:
        path = get_output_path(store, run_id, output_name)
        return FileResponse(path, filename=path.name)


    @router.get("/api/runs/{run_id}/tree")
    def get_run_tree(run_id: str) -> dict[str, object]:
        return build_run_tree(store, run_id)


    @router.get("/api/runs/{run_id}/issues")
    def get_run_issues(run_id: str) -> dict[str, object]:
        return build_run_issues(store, run_id)


    @router.get("/api/runs/{run_id}/timeline")
    def get_run_timeline(
        run_id: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(0, ge=0, le=1000),
        cursor: str | None = Query(default=None),
    ) -> dict[str, object]:
        payload = get_named_output(store, run_id, "timeline")
        return paginate_payload(payload, "events", offset=offset, limit=limit, cursor=cursor)


    @router.get("/api/runs/{run_id}/timeline-histogram")
    def get_run_timeline_histogram(run_id: str) -> dict[str, object]:
        payload = get_named_output(store, run_id, "timeline")
        return build_timeline_histogram(payload)


    @router.get("/api/runs/{run_id}/indicators")
    def get_run_indicators(
        run_id: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(0, ge=0, le=1000),
        cursor: str | None = Query(default=None),
    ) -> dict[str, object]:
        payload = get_named_output(store, run_id, "indicators")
        return paginate_payload(payload, "indicators", offset=offset, limit=limit, cursor=cursor)


    @router.get("/api/runs/{run_id}/indicators/ti-enrichment")
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


    @router.get("/api/runs/{run_id}/artifacts")
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
                    artifacts[name.removeprefix("artifacts_")] = paginate_artifact_output(
                        artifact_payload,
                        payload_path=get_output_path(store, run_id, name),
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


    @router.get("/api/runs/{run_id}/columnar-artifacts")
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


    @router.get("/api/runs/{run_id}/files")
    def get_run_files(
        run_id: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(0, ge=0, le=1000),
        cursor: str | None = Query(default=None),
    ) -> dict[str, object]:
        payload = get_named_output(store, run_id, "files")
        return paginate_payload(payload, "candidates", offset=offset, limit=limit, cursor=cursor)


    @router.get("/api/runs/{run_id}/docs")
    def get_run_docs(
        run_id: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(0, ge=0, le=1000),
        cursor: str | None = Query(default=None),
    ) -> dict[str, object]:
        payload = get_named_output(store, run_id, "docs")
        return paginate_payload(payload, "results", offset=offset, limit=limit, cursor=cursor, omit_fields=("candidates", "manifest"))


    @router.get("/api/runs/{run_id}/report", response_class=PlainTextResponse)
    def get_run_report(run_id: str) -> str:
        path = get_output_path(store, run_id, "report")
        return path.read_text(encoding="utf-8")

    return router
