"""Run plan (처리 계획표) API: plan view, plan control, and the pre-run group checklist.

Plan P2 §3.4 (``docs/plans/run-model-p2-2026-10-12.md``). The plan lives in
the run's progress file; control requests are appended to the run's
``rapidtriage-run-control.json`` and applied by the run process (within a
second; at once when the run executes in this server process).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response

from ...core.jobs import RunControlConflict, RunJobStore, progress_belongs_to_job
from ...core.run.plan import (
    PlanTargetError,
    build_run_plan,
    parse_utc,
    plan_preview,
    utc_now,
)
from ...core.run.profiles import RUN_PROFILES
from .helpers import get_job, run_progress_payload
from .models import RunPlanControlRequest

LIVE_STATUSES = frozenset({"queued", "running"})


def _elapsed_ms(started_at: object, ended_at: object = None) -> int | None:
    start = parse_utc(started_at)
    if start is None:
        return None
    end = parse_utc(ended_at) or parse_utc(utc_now())
    return max(0, int((end - start).total_seconds() * 1000)) if end else None


def build_plan_response(store: RunJobStore, run_id: str) -> dict[str, Any]:
    """Plan root + ``run_id``/``run_status``/``live``/``stale``/``heartbeat_at``/``elapsed_ms``."""
    job = get_job(store, run_id)
    progress = run_progress_payload(job)
    plan = progress.get("plan") if isinstance(progress, dict) else None
    superseded_by = progress.get("superseded_by") if isinstance(progress, dict) else None
    if superseded_by:
        # A resumed retry took over this run's folder: the plan there is the newer run's.
        plan = {
            "command": "run-plan",
            "version": "run-plan-v1",
            "groups": [],
            "counts": {},
            "outcome": job.status,
            "message": progress.get("message"),
            "updated_at": job.updated_at,
        }
    elif not isinstance(plan, dict) or job.status == "queued" or (
        job.status in LIVE_STATUSES and not progress_belongs_to_job(progress, job)
    ):
        # Before the run wrote its plan (queued; a queued resume's folder still holds the
        # earlier run's plan): a skeleton built from the request. Web runs never carve
        # (RunRequest has no carve option). ``updated_at`` is the job's so the ETag is stable.
        request = job.request
        try:
            plan = build_run_plan(
                mode=request.mode,
                carve=False,
                extract=request.extract,
                case_db=request.case_db,
                skip_groups=request.skip_groups,
                skip_tasks=request.skip_tasks,
                actor="web" if job.origin == "web" else "cli",
            )
        except PlanTargetError:
            plan = {"command": "run-plan", "version": "run-plan-v1", "groups": [], "counts": {}, "outcome": None}
        plan["started_at"] = None
        plan["updated_at"] = job.updated_at
        progress = None
    response = dict(plan)
    run_status = job.status
    if run_status in LIVE_STATUSES and isinstance(progress, dict) and progress.get("status") == "interrupted":
        run_status = "interrupted"
    response["run_id"] = run_id
    response["run_status"] = run_status
    response["superseded_by"] = superseded_by or None
    response["live"] = bool(progress.get("live")) if isinstance(progress, dict) else False
    response["stale"] = bool(progress.get("stale")) if isinstance(progress, dict) else False
    response["heartbeat_at"] = progress.get("heartbeat_at") if isinstance(progress, dict) else None
    started = (progress or {}).get("started_at") if isinstance(progress, dict) else None
    ended = (progress or {}).get("completed_at") if isinstance(progress, dict) else None
    response["elapsed_ms"] = _elapsed_ms(started, ended if run_status not in LIVE_STATUSES else None)
    return response


def _etag(payload: dict[str, Any]) -> str:
    stamp = json.dumps(
        [
            payload.get("updated_at"),
            payload.get("run_status"),
            payload.get("live"),
            payload.get("stale"),
            payload.get("heartbeat_at"),
            payload.get("superseded_by"),
        ],
        sort_keys=True,
        default=str,
    )
    return '"' + hashlib.sha256(stamp.encode("utf-8")).hexdigest()[:32] + '"'


def build_run_plan_router(store: RunJobStore) -> APIRouter:
    router = APIRouter()

    @router.get("/api/run-plan/preview")
    def preview_run_plan(
        mode: str = Query(..., min_length=1, max_length=32),
        carve: bool = Query(False),
        extract: bool = Query(False),
        case_db: bool = Query(True),
        input_kind: str | None = Query(None, max_length=64),
    ) -> dict[str, Any]:
        """Group checklist of the run dialog: ``{mode, groups:[{id, label, default_on, skippable, tasks}]}`` (no file access)."""
        if mode.lower() not in RUN_PROFILES:
            raise HTTPException(status_code=400, detail=f"지원하지 않는 모드입니다: {mode}")
        return plan_preview(mode, carve=carve, extract=extract, case_db=case_db, input_kind=input_kind)

    @router.get("/api/runs/{run_id}/plan")
    def get_run_plan(run_id: str, request: Request) -> Response:
        """The run plan (groups -> tasks) as served; ``If-None-Match`` with the last ``ETag`` answers 304."""
        payload = build_plan_response(store, run_id)
        etag = _etag(payload)
        if request.headers.get("if-none-match") == etag:
            return Response(status_code=304, headers={"ETag": etag})
        return JSONResponse(payload, headers={"ETag": etag, "Cache-Control": "no-cache"})

    @router.post("/api/runs/{run_id}/plan/control", status_code=202)
    def control_run_plan(run_id: str, body: RunPlanControlRequest) -> dict[str, Any]:
        """``cancel``/``skip`` (targets ``[{group}|{task}]``), ``cancel_all``, ``finish`` -> ``{accepted, rejected, plan}``."""
        get_job(store, run_id)
        targets = [target.model_dump(exclude_none=True) for target in body.targets]
        if any(not target for target in targets):
            raise HTTPException(status_code=400, detail="대상은 group 또는 task여야 합니다")
        try:
            result = store.control(run_id, body.action, targets, actor="web")
        except KeyError:
            raise HTTPException(status_code=404, detail="런을 찾을 수 없습니다")
        except RunControlConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        except PlanTargetError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        result["plan"] = build_plan_response(store, run_id)
        return result

    return router
