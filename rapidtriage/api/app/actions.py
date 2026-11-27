"""Action API v1: selections the console and an external agent share (docs/ai-action-api.md).

A *selection* names a set of run rows in one of three ways -- explicit row locators, a
timeline window/text filter, or the rows *related* to an anchor row (same time window, same
path, same file name). :func:`resolve_selection` turns it into review-batch targets
(``{collection, kind, locator}``) plus the timeline rows behind them, and :func:`profile`
summarises those rows (counts by source / event type, time span, top paths) so a caller can
analyse a selection before it marks anything. Nothing here writes; ``routes_actions`` marks.
"""

from __future__ import annotations

import datetime as dt
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field

from ...core.case_db.run_locator import parse_ordinal
from .routes_runs import row_conditions_or_422

API_VERSION = "1"
# Same ceiling as hash propagation (routes_review_tools): above it nothing is applied.
MAX_TARGETS = 10_000
EVENTS_PREFIX = "/events/"


class RowTarget(BaseModel):
    collection: str = Field(..., min_length=1)
    kind: str = ""
    locator: str = Field(..., min_length=1)


class TimelineSelection(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    time_from: str | None = Field(default=None, alias="from")
    time_to: str | None = Field(default=None, alias="to")
    contains: str | None = None
    event_types: list[str] = Field(default_factory=list)


class RelatedSelection(BaseModel):
    relation: Literal["time_window", "same_path", "same_name"]
    anchor: RowTarget | None = None
    at: str | None = None
    path: str | None = None
    window_s: int = Field(300, ge=1, le=7 * 86400)


class ActionSelection(BaseModel):
    rows: list[RowTarget] | None = Field(default=None, min_length=1, max_length=MAX_TARGETS)
    timeline: TimelineSelection | None = None
    related: RelatedSelection | None = None


@dataclass(frozen=True)
class Resolved:
    targets: list[dict[str, str]]
    # (record index, event) of every timeline row in the selection, in timeline order.
    events: list[tuple[int, Mapping[str, object]]]


def event_index(target: RowTarget) -> int | None:
    """``/events/<n>`` of a timeline target; ``None`` for any other row."""
    if target.collection != "timeline" or not target.locator.startswith(EVENTS_PREFIX):
        return None
    return parse_ordinal(target.locator[len(EVENTS_PREFIX) :])


def _norm_path(value: object) -> str:
    return str(value or "").replace("/", "\\").rstrip("\\").casefold()


def _name_of(value: object) -> str:
    return _norm_path(value).rsplit("\\", 1)[-1]


def _parse_instant(value: object) -> dt.datetime | None:
    try:
        parsed = dt.datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=dt.timezone.utc)


def _timeline_predicate(selection: TimelineSelection) -> Callable[[Mapping[str, object]], bool]:
    conditions = row_conditions_or_422(
        time_from=selection.time_from,
        time_to=selection.time_to,
        weekday=[],
        hours=None,
        offhours=None,
        tz=None,
        partial=None,
        content=[],
    )
    in_time = conditions.predicate("timeline") if conditions is not None else None
    needle = (selection.contains or "").strip().casefold()
    types = {item.strip() for item in selection.event_types if item.strip()}

    def keep(event: Mapping[str, object]) -> bool:
        if types and str(event.get("event_type") or "") not in types:
            return False
        if needle and not any(needle in str(event.get(key) or "").casefold() for key in ("summary", "path", "event_type")):
            return False
        return in_time is None or in_time(event)

    return keep


def _anchor_event(related: RelatedSelection, events: Sequence[object]) -> Mapping[str, object]:
    if related.anchor is None:
        return {}
    index = event_index(related.anchor)
    if index is None:
        raise HTTPException(
            status_code=422,
            detail="기준 행(anchor)은 타임라인 행(/events/<번호>)이어야 합니다. 다른 행은 at(시각)이나 path(경로)를 함께 보내세요.",
        )
    if index >= len(events) or not isinstance(events[index], Mapping):
        raise HTTPException(status_code=404, detail=f"타임라인에 기준 행이 없습니다: {related.anchor.locator}")
    return events[index]


def _related_predicate(related: RelatedSelection, events: Sequence[object]) -> Callable[[Mapping[str, object]], bool]:
    anchor = _anchor_event(related, events)
    match related.relation:
        case "time_window":
            at = _parse_instant(related.at or anchor.get("timestamp"))
            if at is None:
                raise HTTPException(status_code=422, detail="기준 시각을 알 수 없습니다. at에 ISO 시각을 보내거나 시각이 있는 기준 행을 고르세요.")
            window = dt.timedelta(seconds=related.window_s)
            return _timeline_predicate(
                TimelineSelection(time_from=(at - window).isoformat(), time_to=(at + window).isoformat())
            )
        case "same_path" | "same_name":
            key = _norm_path if related.relation == "same_path" else _name_of
            wanted = key(related.path or anchor.get("path"))
            if not wanted:
                raise HTTPException(status_code=422, detail="기준 경로를 알 수 없습니다. path를 보내거나 경로가 있는 기준 행을 고르세요.")
            return lambda event: key(event.get("path")) == wanted


def resolve_selection(selection: ActionSelection, load_events: Callable[[], Sequence[object]]) -> Resolved:
    """Targets and timeline rows of ``selection`` (exactly one form; Korean 422 otherwise)."""
    forms = [name for name in ("rows", "timeline", "related") if getattr(selection, name) is not None]
    if len(forms) != 1:
        raise HTTPException(status_code=422, detail="selection에는 rows, timeline, related 중 하나만 보내세요.")
    if selection.rows is not None:
        targets = [row.model_dump() for row in selection.rows]
        indexes: list[int] = []
        for row in selection.rows:
            index = event_index(row)
            if index is not None:
                indexes.append(index)
            elif row.collection == "timeline":
                raise HTTPException(
                    status_code=422,
                    detail=f"타임라인 행 로케이터는 /events/<번호>(ASCII 숫자) 형식이어야 합니다: {row.locator[:80]}",
                )
        if not indexes:
            return Resolved(targets, [])
        events = load_events()
        picked = [(i, events[i]) for i in sorted(set(indexes)) if i < len(events) and isinstance(events[i], Mapping)]
        return Resolved(targets, picked)
    events = load_events()
    if selection.timeline is not None:
        return _timeline_rows(events, _timeline_predicate(selection.timeline))
    if selection.related is not None:
        return _timeline_rows(events, _related_predicate(selection.related, events))
    raise AssertionError("unreachable: exactly one selection form is set")


def _timeline_rows(events: Sequence[object], keep: Callable[[Mapping[str, object]], bool]) -> Resolved:
    picked = [(i, event) for i, event in enumerate(events) if isinstance(event, Mapping) and keep(event)]
    targets = [{"collection": "timeline", "kind": "", "locator": f"{EVENTS_PREFIX}{i}"} for i, _ in picked]
    return Resolved(targets, picked)


def profile(resolved: Resolved, *, sample: int) -> dict[str, object]:
    """What the selection holds: counts, time span, top values and a few sample rows."""
    rows = [event for _, event in resolved.events]
    instants = sorted(t for event in rows if (t := _parse_instant(event.get("timestamp"))) is not None)
    return {
        "total": len(resolved.targets),
        "limit": MAX_TARGETS,
        "over_limit": len(resolved.targets) > MAX_TARGETS,
        "by_collection": dict(Counter(target["collection"] for target in resolved.targets)),
        "timeline_rows": len(rows),
        "time_range": {"first": instants[0].isoformat(), "last": instants[-1].isoformat()} if instants else None,
        "by_source": dict(Counter(str(event.get("source") or "") for event in rows).most_common(10)),
        "by_event_type": dict(Counter(str(event.get("event_type") or "") for event in rows).most_common(10)),
        "top_paths": [
            {"path": path, "count": count}
            for path, count in Counter(str(event.get("path") or "") for event in rows if event.get("path")).most_common(5)
        ],
        "sample": [
            {
                "locator": f"{EVENTS_PREFIX}{index}",
                "timestamp": event.get("timestamp"),
                "event_type": event.get("event_type"),
                "summary": event.get("summary"),
            }
            for index, event in resolved.events[:sample]
        ],
    }
