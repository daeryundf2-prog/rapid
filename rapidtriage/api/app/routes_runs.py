"""Run lifecycle and run-output browsing API routes."""

from __future__ import annotations

import datetime as dt
import json
import re
import zipfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import (
    FileResponse,
    PlainTextResponse,
)

from ...core.columnar_store import query_columnar_artifact_records
from ...core.extract import DEFAULT_EXTRACT_MANIFEST_NAME, ExtractError, run_extract
from ...core.indicators import (
    IndicatorSummaryError,
    build_indicator_ti_enrichment_package,
)
from ...core.jobs import (
    RunJobStore,
    RunRequest,
    run_output_dir,
)
from ...core.visible_capabilities import build_visible_capability_response
from .analyses import run_scope
from .analysis_kinds import cross_case_eligibility
from .artifact_filter import (
    annotate_page_counts,
    files_page_base,
    filter_across_kinds,
    filter_artifact_page,
    filter_files_by_category,
)
from .artifact_sort import SORT_ORDERS, paginate_sorted_artifact_output
from .dashboard import (
    build_run_dashboard,
    notes_output_dir,
    read_case_notes,
    write_case_notes,
)
from .files_ntfs import join_files_page
from .helpers import (
    allowed_source_roots,
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
    RunCaseNotesRequest,
    RunCreateRequest,
    RunExtractRequest,
    RunImportRequest,
)
from .pagination import (
    DOCS_MATCHED_REQUIRES_ALL,
    docs_page,
    paginate_artifact_output,
    paginate_payload,
    with_record_index,
)
from .runops import (
    build_run_output_preview,
    build_run_viewer_workflow_validation,
)
from .timeline_hist import build_timeline_histogram
from .tree import build_run_issues, build_run_tree

ACTIVE_RUN_STATUSES = frozenset({"queued", "running"})
FILTER_LIMIT_MESSAGE = "필터는 limit>0에서만 지원합니다"
EXTRACT_ZIP_MAX_BYTES = 2 * 1024 * 1024 * 1024
EXTRACT_NAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


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
            # Cross-case dialog filter (plan P1 §3.2 cross-case): one stat, no DB open.
            row.update(cross_case_eligibility(job))
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
        job = get_job(store, run_id)
        payload["progress"] = run_progress_payload(job)
        payload.update(cross_case_eligibility(job))
        return payload


    @router.delete("/api/runs/{run_id}", status_code=204)
    def delete_run(run_id: str) -> None:
        try:
            store.remove(run_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="런을 찾을 수 없습니다")


    @router.post("/api/runs/{run_id}/cancel")
    def cancel_run(run_id: str) -> dict[str, Any]:
        try:
            return store.cancel(run_id).to_dict(include_summary=True)
        except KeyError:
            raise HTTPException(status_code=404, detail="런을 찾을 수 없습니다")


    @router.post("/api/runs/{run_id}/retry", status_code=202)
    def retry_run(run_id: str) -> dict[str, Any]:
        try:
            return store.retry(run_id).to_dict(include_summary=True)
        except KeyError:
            raise HTTPException(status_code=404, detail="런을 찾을 수 없습니다")
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc))


    @router.get("/api/runs/{run_id}/summary")
    def get_run_summary(run_id: str) -> dict[str, object]:
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail="완료된 런이 아닙니다")
        try:
            case_path = default_case_path(store, run_id)
        except HTTPException:
            case_path = None
        return enrich_summary_counts(job.summary, case_path=case_path)


    @router.get("/api/runs/{run_id}/capabilities")
    def get_run_capabilities(run_id: str) -> dict[str, object]:
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail="완료된 런이 아닙니다")
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
            raise HTTPException(status_code=409, detail="완료된 런이 아닙니다")
        return build_run_viewer_workflow_validation(store, run_id, job.summary)


    @router.get("/api/runs/{run_id}/outputs/{output_name}")
    def get_run_output(run_id: str, output_name: str) -> dict[str, object]:
        try:
            return store.read_output(run_id, output_name)
        except KeyError:
            raise HTTPException(status_code=404, detail="런 출력을 찾을 수 없습니다")
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
            raise HTTPException(status_code=404, detail="런을 찾을 수 없습니다")
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


    @router.get("/api/runs/{run_id}/dashboard")
    def get_run_dashboard(run_id: str) -> dict[str, object]:
        """접수 dashboard: run profile keywords, evidence source + partitions, export history."""
        return build_run_dashboard(store, run_id, get_job(store, run_id))


    @router.get("/api/runs/{run_id}/case-notes")
    def get_run_case_notes(run_id: str) -> dict[str, object]:
        job = get_job(store, run_id)
        return {"run_id": run_id, **read_case_notes(notes_output_dir(job))}


    @router.put("/api/runs/{run_id}/case-notes")
    def put_run_case_notes(run_id: str, request: RunCaseNotesRequest) -> dict[str, object]:
        job = get_job(store, run_id)
        try:
            saved = write_case_notes(
                notes_output_dir(job),
                examiner=request.examiner.strip(),
                summary=request.summary.strip(),
            )
        except OSError as exc:
            raise HTTPException(status_code=500, detail=str(exc))
        return {"run_id": run_id, **saved}


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
        kind: list[str] = Query(default=[]),
        path_contains: str | None = Query(default=None),
        sort: str | None = Query(default=None),
        order: str | None = Query(default=None),
        locate: int | None = Query(default=None, ge=0),
        artifact_type: list[str] = Query(default=[]),
        after: str | None = Query(default=None),
    ) -> dict[str, object]:
        """Page per-kind artifact rows; every row carries its JSONL ``record_index``.

        ``artifact_type`` (repeatable) keeps only rows of those types: a
        streaming filter (with ``limit > 0``) composable with ``kind``,
        ``sort`` and ``path_contains``; its pagination reports
        ``scanned``/``truncated`` like ``path_contains``. Every kind page
        reports ``record_count`` (unfiltered) and ``matched`` (filtered count,
        exact when the scan reached the end of the kind, else ``null``).

        With ``artifact_type`` and/or ``path_contains`` and zero or several
        ``kind`` (no ``sort``),
        ``offset``/``limit`` page the matches across kinds as one collection
        (kind order: as requested, else alphabetical), scanning at most
        ``CROSS_KIND_SCAN_CAP`` rows per request; the response adds
        ``cross_kind`` = ``{kinds, offset, limit, returned, order, record_count,
        matched, has_more, next_offset, next_after, scanned, truncated}`` and
        each kind page holds only its rows of that window. Pass
        ``after=<next_after>`` to continue behind the last consumed row.

        ``sort`` (``timestamp`` | ``details.<name>``, optionally suffixed
        ``:asc``/``:desc``; an explicit ``order`` wins over the suffix) sorts
        the whole kind through an in-memory index built in the background (see
        ``artifact_sort``); it requires exactly one ``kind``. ``order``
        without ``sort`` is ignored. ``locate=<record_index>`` adds
        ``sort.position`` (that record's 0-based position in the sorted order).
        """
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail="완료된 런이 아닙니다")
        outputs = job.summary.get("outputs")
        if not isinstance(outputs, dict):
            raise HTTPException(status_code=409, detail="run has no outputs")
        wanted_kinds = {item.strip() for item in kind if item.strip()}
        wanted_types = frozenset(item.strip() for item in artifact_type if item.strip()) or None
        needle = path_contains.strip() if path_contains and path_contains.strip() else None
        if (wanted_types or needle) and limit <= 0:
            raise HTTPException(status_code=400, detail=FILTER_LIMIT_MESSAGE)
        sort_key = sort.strip() if sort and sort.strip() else None
        sort_order = (order or "").strip().lower() or None
        if sort_key:
            head, _, suffix = sort_key.rpartition(":")
            if head and suffix.lower() in SORT_ORDERS:
                sort_key = head
                sort_order = sort_order or suffix.lower()
            if len(wanted_kinds) != 1:
                raise HTTPException(status_code=400, detail="sort requires exactly one kind")
            sort_order = sort_order or "asc"
            if sort_order not in SORT_ORDERS:
                raise HTTPException(status_code=400, detail="order must be asc or desc")
        if (wanted_types or needle) and not sort_key and len(wanted_kinds) != 1 and limit > 0:
            return _artifacts_across_kinds(
                run_id,
                outputs,
                kinds=list(dict.fromkeys(item.strip() for item in kind if item.strip())),
                path_contains=needle,
                artifact_types=wanted_types,
                offset=offset,
                limit=limit,
                after=after,
            )
        artifacts = {}
        kind_payloads: dict[str, dict[str, object]] = {}
        for name in sorted(outputs):
            if name.startswith("artifacts_"):
                if wanted_kinds and name.removeprefix("artifacts_") not in wanted_kinds:
                    continue
                try:
                    artifact_payload = store.read_output(run_id, name)
                    kind_payloads[name.removeprefix("artifacts_")] = artifact_payload
                    if sort_key:
                        artifacts[name.removeprefix("artifacts_")] = paginate_sorted_artifact_output(
                            artifact_payload,
                            run_id=run_id,
                            kind=name.removeprefix("artifacts_"),
                            payload_path=get_output_path(store, run_id, name),
                            sort=sort_key,
                            order=sort_order or "asc",
                            offset=offset,
                            limit=limit,
                            cursor=cursor,
                            path_contains=needle,
                            locate=locate,
                            artifact_types=wanted_types,
                        )
                        continue
                    if (needle or wanted_types) and limit > 0:
                        artifacts[name.removeprefix("artifacts_")] = filter_artifact_page(
                            artifact_payload,
                            payload_path=get_output_path(store, run_id, name),
                            path_contains=needle,
                            offset=offset,
                            limit=limit,
                            artifact_types=wanted_types,
                        )
                        continue
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
        for kind_name, page in artifacts.items():
            if isinstance(page, dict) and kind_name in kind_payloads:
                annotate_page_counts(page, kind_payloads[kind_name], filtered=bool(needle or wanted_types) and limit > 0)
        response: dict[str, object] = {"artifacts": artifacts}
        if sort_key:
            statuses = [
                page["sort"].get("status")
                for page in artifacts.values()
                if isinstance(page, dict) and isinstance(page.get("sort"), dict)
            ]
            response["sort_supported"] = bool(statuses) and all(status != "unsupported" for status in statuses)
        return response


    def _artifacts_across_kinds(
        run_id: str,
        outputs: dict[str, object],
        *,
        kinds: list[str],
        path_contains: str | None,
        artifact_types: frozenset[str] | None,
        offset: int,
        limit: int,
        after: str | None,
    ) -> dict[str, object]:
        available = [name.removeprefix("artifacts_") for name in sorted(outputs) if name.startswith("artifacts_")]
        ordered = [item for item in kinds if item in available] if kinds else available
        sources = []
        for item in ordered:
            name = f"artifacts_{item}"
            try:
                sources.append((item, store.read_output(run_id, name), get_output_path(store, run_id, name)))
            except RuntimeError as exc:
                raise HTTPException(status_code=409, detail=str(exc))
            except PermissionError as exc:
                raise HTTPException(status_code=403, detail=str(exc))
            except FileNotFoundError as exc:
                raise HTTPException(status_code=404, detail=str(exc))
        try:
            return filter_across_kinds(
                sources,
                path_contains=path_contains,
                artifact_types=artifact_types,
                offset=offset,
                limit=limit,
                after=after,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))


    @router.post("/api/runs/{run_id}/extract")
    def extract_run_rows(run_id: str, request: RunExtractRequest) -> dict[str, Any]:
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail="완료된 런이 아닙니다")
        roots = allowed_source_roots(job.summary)
        items: list[dict[str, object]] = []
        for row in request.rows:
            try:
                resolved = Path(row.path).expanduser().resolve()
            except OSError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            if not any(resolved.is_relative_to(root) for root in roots):
                raise HTTPException(
                    status_code=403,
                    detail=f"path is outside the run's allowed source roots: {row.path}",
                )
            item: dict[str, object] = {"path": str(resolved)}
            if row.locator:
                item["locator"] = row.locator
            items.append(item)
        name = dt.datetime.now().strftime("%Y%m%dT%H%M%S%f")
        if request.output_name:
            if not EXTRACT_NAME_PATTERN.fullmatch(request.output_name):
                raise HTTPException(
                    status_code=400,
                    detail="output_name may only contain letters, digits, '.', '_' and '-'",
                )
            name = f"{request.output_name}-{name}"
        output_dir = run_output_dir(job.summary)
        target = output_dir / "extract" / name
        run_request = job.request
        try:
            manifest = run_extract(
                output_dir,
                target,
                payload={"command": "files", "candidates": items},
                read_only=bool(run_request and run_request.read_only),
                max_extract_size_bytes=int(run_request.max_extract_size_bytes) if run_request else 0,
                max_file_count=int(run_request.max_file_count) if run_request else 0,
            )
        except ExtractError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except OSError as exc:
            raise HTTPException(status_code=500, detail=str(exc))
        (target / DEFAULT_EXTRACT_MANIFEST_NAME).write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        manifest["name"] = name
        manifest["download_url"] = f"/api/runs/{run_id}/extract/{name}/file"
        return manifest


    @router.get("/api/runs/{run_id}/extract/{name}/file")
    def download_run_extract(run_id: str, name: str) -> FileResponse:
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail="완료된 런이 아닙니다")
        if not EXTRACT_NAME_PATTERN.fullmatch(name):
            raise HTTPException(status_code=400, detail="invalid extract name")
        base = run_output_dir(job.summary) / "extract"
        folder = base / name
        if not folder.is_dir():
            raise HTTPException(status_code=404, detail="extract not found")
        files = [p for p in sorted(folder.rglob("*")) if p.is_file() and not p.is_symlink()]
        if sum(p.stat().st_size for p in files) > EXTRACT_ZIP_MAX_BYTES:
            raise HTTPException(status_code=413, detail="extract is larger than the 2 GB zip limit")
        archive = base / f"{name}.zip"
        if not archive.is_file():
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
                for path in files:
                    bundle.write(path, path.relative_to(folder).as_posix())
        return FileResponse(archive, filename=archive.name, media_type="application/zip")


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
            raise HTTPException(status_code=409, detail="완료된 런이 아닙니다")
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
        category: list[str] = Query(default=[]),
        scope: str = Query("candidates", pattern="^(candidates|inventory)$"),
    ) -> dict[str, object]:
        """Paged file rows joined with the newest ``ntfs-meta`` analysis.

        ``scope`` picks the files-output list: ``candidates`` (default; files
        of the selected categories) or ``inventory`` (every other scanned file,
        incl. ``other``, parser-quality r2). The page holds only that list,
        under its own key, and reports ``scope``, ``candidate_count`` and
        ``inventory_count`` (``null`` when the output has no inventory: run
        before r2 or inventory disabled; ``inventory_note`` then says so).

        Every row gains ``ntfs`` (``entry_number``, ``created_at``,
        ``accessed_at``, ``mft_modified_at``, ``in_use``) or ``null``,
        ``filesystem`` (``"NTFS"`` when joined) and ``source_image``; the page
        reports ``ntfs_join = {analysis_id|null, status: joined|no_analysis|
        no_volume_prefix|too_large|skipped, matched, total, analysis_total|null,
        volume_prefix|null, prefix_method|null, partition|null, reason?}``
        (``matched``/``total`` over this page's rows only; ``analysis_total`` =
        all rows of the joined analysis; ``partition`` = its partition start
        sector; ``reason`` = Korean explanation when not joined). The deletion
        state (``recovery.deletion_state`` of candidates, ``deletion_state`` of
        inventory rows) follows the row's final ``is_deleted``.

        ``category`` (repeatable) keeps rows whose ``categories`` list holds
        any of them (an inventory row without categories counts as
        ``other``); ``offset``/``limit`` then count matches and the page
        reports ``record_count``, ``matched``, ``scanned``, ``truncated``.
        Every row carries ``record_index``: its position in that list of the
        files output (locator ``/candidates/<n>`` or ``/inventory/<n>``),
        filtered or not.
        """
        payload = get_named_output(store, run_id, "files")
        collection = scope
        wanted = frozenset(item.strip() for item in category if item.strip())
        if wanted:
            if limit <= 0:
                raise HTTPException(status_code=400, detail=FILTER_LIMIT_MESSAGE)
            page = filter_files_by_category(payload, wanted, offset=offset, limit=limit, collection=collection)
        else:
            page = dict(paginate_payload(files_page_base(payload, collection), collection, offset=offset, limit=limit, cursor=cursor))
            pagination = page.get("pagination") if limit > 0 and isinstance(page.get("pagination"), dict) else {}
            rows = page.get(collection) if isinstance(page.get(collection), list) else []
            # ``record_index`` = position in that list of rapidtriage-files.json (locator ``/<scope>/<n>``).
            page[collection] = with_record_index(rows, int(pagination.get("offset") or 0))
        candidates = payload.get("candidates") if isinstance(payload.get("candidates"), list) else []
        inventory = payload.get("inventory") if isinstance(payload.get("inventory"), list) else None
        page["scope"] = collection
        page["candidate_count"] = len(candidates)
        page["inventory_count"] = len(inventory) if inventory is not None else None
        if inventory is None:
            page["inventory_note"] = (
                "이 런의 files 출력에 inventory가 없습니다(parser-quality r2 이전 런이거나 inventory 기록 비활성). "
                "선택 범주 밖 파일(기타 포함)은 후보 목록에 없습니다."
            )
        try:
            run = run_scope(store, run_id, require_ready=False)
        except HTTPException:
            run = None  # no usable output dir: serve the rows without the NTFS join
        # Volume-prefix detection samples the scope's own full list.
        return join_files_page(run, page, (inventory or []) if collection == "inventory" else candidates, collection=collection)


    @router.get("/api/runs/{run_id}/docs")
    def get_run_docs(
        run_id: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(0, ge=0, le=1000),
        cursor: str | None = Query(default=None),
        all_candidates: bool = Query(default=False, alias="all"),
        matched: bool | None = Query(default=None),
    ) -> dict[str, object]:
        """Paged document listing.

        Default: pages ``results`` (the keyword hits), exactly the pre-r1
        contract, so shipped clients keep working. ``all=1`` pages
        ``candidates`` instead (every document the docs step saw, each with
        ``record_index``/``matched``/``text_status``…); with ``all=1``,
        ``matched=0``/``matched=1`` filter those candidates. ``matched=0``
        without ``all=1`` is a 400. Every page reports ``candidate_count``
        (all candidates) and ``matched_count`` (keyword hits). ``limit=0``
        returns the whole payload.
        """
        if matched is False and not all_candidates:
            raise HTTPException(status_code=400, detail=DOCS_MATCHED_REQUIRES_ALL)
        payload = get_named_output(store, run_id, "docs")
        return docs_page(
            payload, all_candidates=all_candidates, matched=matched, offset=offset, limit=limit, cursor=cursor
        )


    @router.get("/api/runs/{run_id}/report", response_class=PlainTextResponse)
    def get_run_report(run_id: str) -> str:
        path = get_output_path(store, run_id, "report")
        return path.read_text(encoding="utf-8")

    return router
