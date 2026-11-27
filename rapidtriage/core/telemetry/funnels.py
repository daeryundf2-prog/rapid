"""P0 funnels F1 (case -> report, 14 days) and F2 (search -> tag, 10 minutes) from the local log."""

from __future__ import annotations

import datetime as dt
from collections import defaultdict
from collections.abc import Sequence

from .metrics import NOT_COLLECTED, compute_metrics
from .stats import Event, by_name, case_key, prop, ratio, run_cases, ts_of

F1_STEPS = (
    "case_created",
    "run_started",
    "run_finished",
    "review_stage_entered",
    "review_tag_applied",
    "case_report_created",
)
F1_WINDOW = dt.timedelta(days=14)
F2_WINDOW = dt.timedelta(minutes=10)


def funnel_case_to_report(events: Sequence[Event]) -> dict[str, object]:
    """``conv(k)`` = cases reaching step k within 14 days of ``case_created`` / cases created."""
    cases = run_cases(events)
    first: dict[tuple[object, object], dict[str, dt.datetime]] = defaultdict(dict)
    for event in by_name(events, *F1_STEPS):
        key = case_key(event, cases)
        if key is None or (event.get("event") == "case_report_created" and prop(event, "status") != "ok"):
            continue
        first[key].setdefault(str(event["event"]), ts_of(event))
    started = {key: steps for key, steps in first.items() if "case_created" in steps}
    reached = {
        step: sum(1 for steps in started.values() if step in steps and steps[step] <= steps["case_created"] + F1_WINDOW)
        for step in F1_STEPS
    }
    return {
        "window_days": F1_WINDOW.days,
        "steps": [
            {"event": step, "cases": reached[step], "conversion": ratio(reached[step], len(started))} for step in F1_STEPS
        ],
    }


def funnel_search_to_tag(events: Sequence[Event]) -> dict[str, object]:
    """Searches of a console session followed by a search-surface tag within 10 minutes."""
    searches = [event for event in by_name(events, "search_submitted") if event.get("session_id")]
    tags: dict[tuple[object, object], list[dt.datetime]] = defaultdict(list)
    for event in by_name(events, "review_tag_applied"):
        if event.get("session_id") and prop(event, "source_surface") == "search":
            tags[(event.get("install_hid"), event.get("session_id"))].append(ts_of(event))
    tagged = 0
    for search in searches:
        start = ts_of(search)
        times = tags.get((search.get("install_hid"), search.get("session_id")), [])
        tagged += any(start <= moment <= start + F2_WINDOW for moment in times)
    returned = by_name(events, "search_results_returned")
    return {
        "window_minutes": int(F2_WINDOW.total_seconds() // 60),
        "searches": len(searches),
        "results_returned": len(returned),
        "search_success": NOT_COLLECTED,
        "search_to_tag": ratio(tagged, len(searches)),
        "zero_result_rate": ratio(sum(1 for event in returned if prop(event, "zero_result") is True), len(returned)),
    }


def build_report(events: Sequence[Event]) -> dict[str, object]:
    """Metrics + funnels of ``events`` (any order; sorted by time here)."""
    ordered = sorted(events, key=ts_of)
    return {
        "event_count": len(ordered),
        "metrics": compute_metrics(ordered),
        "funnels": {"F1": funnel_case_to_report(ordered), "F2": funnel_search_to_tag(ordered)},
    }
