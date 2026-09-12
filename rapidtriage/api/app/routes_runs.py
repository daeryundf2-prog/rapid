"""Run lifecycle and run-output browsing API routes."""

from __future__ import annotations

import json
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
    get_job,
    get_job_payload,
    get_named_output,
    get_output_path,
    read_run_artifacts_for_capabilities,
    validate_run_evidence_source,
)
from .models import (
    RunCreateRequest,
    RunImportRequest,
)
from .pagination import (
    paginate_payload,
)
from .runops import (
    build_run_output_preview,
    build_run_viewer_workflow_validation,
)


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
        return {"runs": [job.to_dict() for job in store.list()]}


    @router.get("/api/runs/{run_id}")
    def get_run(run_id: str) -> dict[str, Any]:
        return get_job_payload(store, run_id, include_summary=True)


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
        return job.summary


    @router.get("/api/runs/{run_id}/capabilities")
    def get_run_capabilities(run_id: str) -> dict[str, object]:
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail="run is not completed")
        return build_visible_capability_response(
            run_summary=job.summary,
            artifacts=read_run_artifacts_for_capabilities(store, run_id, job.summary),
        )


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


    @router.get("/api/runs/{run_id}/timeline")
    def get_run_timeline(
        run_id: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(0, ge=0, le=1000),
        cursor: str | None = Query(default=None),
    ) -> dict[str, object]:
        payload = get_named_output(store, run_id, "timeline")
        return paginate_payload(payload, "events", offset=offset, limit=limit, cursor=cursor)


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
