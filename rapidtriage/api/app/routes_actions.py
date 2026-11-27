"""Action API v1 routes (docs/ai-action-api.md): one contract for the console and an agent.

* ``GET /api/actions`` -- the machine-readable catalog (version, actions, selection forms).
* ``POST /api/runs/{run_id}/actions/select`` -- analyse a selection; read-only.
* ``POST /api/runs/{run_id}/actions/mark`` -- check/tag every row of a selection. ``dry_run``
  defaults to true (preview only); applying goes through ``POST /api/case-db/review-batch`` of
  the run's canonical case DB (created on first use like the console's first mark), so marks,
  tags, history and their Korean errors are the review-batch ones. ``actor.kind = "agent"``
  records the reviewer as ``agent:<name>``, which keeps AI marks apart from people's in the history.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any, Literal

from fastapi import APIRouter, HTTPException
from fastapi.routing import APIRoute
from pydantic import BaseModel, Field

from ...core.jobs import RunJobStore
from .actions import (
    API_VERSION,
    MAX_TARGETS,
    ActionSelection,
    profile,
    resolve_selection,
)
from .helpers import get_named_output, get_output_path, resolve_request_reviewer
from .json_rows import LazyRows, large_output_index
from .models import CaseDbReviewBatchRequest, RunCaseDbEnsureRequest


class ActionActor(BaseModel):
    kind: Literal["human", "agent"] = "human"
    name: str | None = Field(default=None, max_length=120)


AGENT_PREFIX = "agent:"
# The author every other review-tool write records when nobody is named (routes_review_tools).
UNNAMED_HUMAN = "local-user"


def actor_reviewer(actor: ActionActor) -> str:
    """The history author of a mark: ``agent:<name>``, else the person's name, never empty.

    An unnamed person is ``RAPIDTRIAGE_REVIEWER`` or ``local-user`` (as the tag-id path
    records), never the row's previous reviewer. One token serves people and agents, so a
    ``human`` cannot use an ``agent:`` name: that would pass a person's mark off as an AI's.
    """
    name = (actor.name or "").strip()
    if actor.kind == "agent":
        return f"{AGENT_PREFIX}{name or 'unnamed'}"
    if name.casefold().startswith(AGENT_PREFIX):
        raise HTTPException(
            status_code=422,
            detail="사람(actor.kind=human)의 이름은 'agent:'로 시작할 수 없습니다. 에이전트는 actor.kind를 'agent'로 보내세요.",
        )
    return resolve_request_reviewer(name) or UNNAMED_HUMAN


# The console's review statuses (frontend reviewActions); "excluded" also leaves the report.
ReviewStatus = Literal["relevant", "needs-review", "excluded", "unreviewed"]


class ActionMark(BaseModel):
    status: ReviewStatus | None = None
    tag_ids: list[int] | None = None
    add_tags: list[str] | None = None
    include_in_report: bool | None = None
    note: str | None = None


class SelectRequest(BaseModel):
    selection: ActionSelection
    sample: int = Field(5, ge=0, le=50)


class MarkRequest(BaseModel):
    selection: ActionSelection
    mark: ActionMark
    dry_run: bool = True
    actor: ActionActor = Field(default_factory=ActionActor)


ACTION_CATALOG: dict[str, object] = {
    "version": API_VERSION,
    "doc": "docs/ai-action-api.md",
    "limit": MAX_TARGETS,
    "selection_forms": {
        "rows": "[{collection, kind?, locator}] -- 화면의 행 로케이터를 그대로",
        "timeline": "{from?, to?, contains?, event_types?} -- 타임라인 시간 범위·문구·이벤트 유형",
        "related": "{relation: time_window|same_path|same_name, anchor?: {collection:'timeline', locator:'/events/N'}, at?, path?, window_s?}",
    },
    "actions": [
        {
            "id": "select",
            "method": "POST",
            "path": "/api/runs/{run_id}/actions/select",
            "body": "{selection, sample?}",
            "summary": "선택한 행을 분석한다: 건수, 시간 범위, 출처·이벤트 유형별 건수, 상위 경로, 예시 행. 아무것도 바꾸지 않는다.",
        },
        {
            "id": "mark",
            "method": "POST",
            "path": "/api/runs/{run_id}/actions/mark",
            "body": "{selection, mark: {status? | tag_ids? | add_tags? | include_in_report? | note?}, dry_run=true, actor: {kind: human|agent, name?}}",
            "summary": "선택한 행 전부를 체크·태그한다. dry_run=true(기본)는 미리보기만, false일 때 적용한다. tag_ids는 다른 표시와 함께 보낼 수 없다.",
        },
        {"id": "tags", "method": "GET", "path": "/api/cases/{case_id}/tags?run_id={run_id}", "summary": "태그 id 목록(mark.tag_ids에 쓴다)."},
        {"id": "history", "method": "GET", "path": "/api/runs/{run_id}/review-history", "summary": "행별 표시 이력(작성자 agent:<이름> 포함)."},
    ],
}


def _endpoint(router: APIRouter, name: str) -> Callable[..., Any]:
    for route in router.routes:
        if isinstance(route, APIRoute) and route.name == name:
            return route.endpoint
    raise RuntimeError(f"case-db router has no {name} route")


def build_actions_router(store: RunJobStore, case_db_router: APIRouter) -> APIRouter:
    router = APIRouter()
    ensure_case_db = _endpoint(case_db_router, "ensure_run_case_db")
    review_batch = _endpoint(case_db_router, "mark_case_db_reviews_batch")

    def load_events(run_id: str) -> Callable[[], Sequence[object]]:
        def load() -> Sequence[object]:
            index = large_output_index(get_output_path(store, run_id, "timeline"))
            if index is not None and index.count("events") is not None:
                return LazyRows(index, "events")
            events = get_named_output(store, run_id, "timeline").get("events")
            return events if isinstance(events, list) else []

        return load

    @router.get("/api/actions")
    def action_catalog() -> dict[str, object]:
        return ACTION_CATALOG

    @router.post("/api/runs/{run_id}/actions/select")
    def select_rows(run_id: str, request: SelectRequest) -> dict[str, object]:
        resolved = resolve_selection(request.selection, load_events(run_id))
        return {"command": "actions.select", "version": API_VERSION, "run_id": run_id, **profile(resolved, sample=request.sample)}

    @router.post("/api/runs/{run_id}/actions/mark")
    def mark_rows(run_id: str, request: MarkRequest) -> dict[str, object]:
        mark = request.mark.model_dump(exclude_none=True)
        if mark.get("status") == "excluded":
            mark.setdefault("include_in_report", False)
        if not mark:
            raise HTTPException(status_code=422, detail="mark에 적용할 표시(status, tag_ids, add_tags, include_in_report, note)가 없습니다.")
        reviewer = actor_reviewer(request.actor)
        resolved = resolve_selection(request.selection, load_events(run_id))
        summary = profile(resolved, sample=0)
        payload: dict[str, object] = {
            "command": "actions.mark",
            "version": API_VERSION,
            "run_id": run_id,
            "dry_run": request.dry_run,
            "mark": mark,
            "actor": {"kind": request.actor.kind, "reviewer": reviewer},
            **summary,
        }
        if not resolved.targets:
            raise HTTPException(status_code=422, detail="선택한 행이 없습니다. 선택 조건을 확인하세요.")
        if summary["over_limit"]:
            raise HTTPException(
                status_code=422,
                detail=f"선택한 행이 {len(resolved.targets):,}건으로 한 번에 표시할 수 있는 {MAX_TARGETS:,}건을 넘습니다. 범위를 좁히세요.",
            )
        if request.dry_run:
            return payload
        handle = ensure_case_db(run_id, RunCaseDbEnsureRequest())
        result = review_batch(
            CaseDbReviewBatchRequest(
                database=str(handle["database"]),
                case_id=str(handle["case_id"]),
                run_id=run_id,
                targets=resolved.targets,
                reviewer=reviewer,
                **mark,
            )
        )
        payload["case_id"] = handle["case_id"]
        payload["updated_count"] = result.get("updated_count", 0)
        return payload

    return router
