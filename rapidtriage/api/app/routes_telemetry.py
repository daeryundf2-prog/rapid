"""Local telemetry API: console events in, metrics out (``docs/telemetry.md``).

``POST /api/telemetry/events`` takes the five console-side P0 events. The
server, not the browser, fills what it knows (app version, the run's status
and time since it finished, whether a tag is the run's first) and hashes the
raw run/case/tag ids before anything is written. ``GET /api/telemetry/metrics``
returns the metrics and funnels of the local log as numbers.
"""

from __future__ import annotations

import datetime as dt
import threading
from typing import Any, Literal

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field

from ... import __version__
from ...core import telemetry
from ...core.jobs import RunJobStore
from ...core.telemetry.funnels import build_report
from ...core.telemetry.recorder import hid

ClientEventName = Literal[
    "app_session_started", "grid_loaded", "grid_sorted", "review_stage_entered", "review_tag_applied"
]


class ClientEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event: ClientEventName
    props: dict[str, Any] = Field(default_factory=dict, max_length=16)
    run_id: str | None = Field(default=None, max_length=64)
    case_id: str | None = Field(default=None, max_length=64)
    # Raw review tag key: only its salted hash (``tag_hid``) is written.
    tag: str | None = Field(default=None, max_length=200)


class _TaggedRuns:
    """Runs (``install|run`` hashes) with a recorded tag, seeded once from the log."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._runs: set[str] | None = None

    def first_tag(self, run_hid: str) -> bool:
        with self._lock:
            if self._runs is None:
                self._runs = {
                    str(event.get("run_hid"))
                    for event in telemetry.iter_events()
                    if event.get("event") == "review_tag_applied" and event.get("run_hid")
                }
            first = run_hid not in self._runs
            self._runs.add(run_hid)
            return first


TAGGED_RUNS = _TaggedRuns()


def _run_facts(store: RunJobStore, run_id: str) -> dict[str, object]:
    """``run_status`` and ``ms_since_run_finished`` of a known web run (empty for an unknown id)."""
    try:
        job = store.get(run_id)
    except KeyError:
        return {}
    facts: dict[str, object] = {"run_status": job.status}
    if job.completed_at:
        finished = dt.datetime.fromisoformat(job.completed_at)
        facts["ms_since_run_finished"] = int((dt.datetime.now(dt.timezone.utc) - finished).total_seconds() * 1000)
    return facts


def build_telemetry_router(store: RunJobStore) -> APIRouter:
    router = APIRouter()

    @router.post("/api/telemetry/events", status_code=202)
    def post_event(body: ClientEvent) -> dict[str, object]:
        if not telemetry.is_recording():
            return {"recorded": False}
        props = dict(body.props)
        match body.event:
            case "app_session_started":
                props["app_version"] = __version__
            case "review_stage_entered":
                props.update(_run_facts(store, body.run_id) if body.run_id else {})
            case "review_tag_applied":
                if body.run_id:
                    props["is_first_in_run"] = TAGGED_RUNS.first_tag(hid("run", body.run_id))
            case "grid_loaded" | "grid_sorted":
                pass
        recorded = telemetry.record(body.event, props, run_id=body.run_id, case_id=body.case_id, tag=body.tag)
        return {"recorded": recorded}

    @router.get("/api/telemetry/metrics")
    def get_metrics() -> dict[str, Any]:
        return {
            "command": "telemetry.metrics",
            "recording": telemetry.is_recording(),
            "disabled_reason": telemetry.disabled_reason(),
            **build_report(list(telemetry.iter_events())),
        }

    return router
