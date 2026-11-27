"""The 13 approved P0 metrics, computed from the local event log (numbers only).

Formulas follow the product proposal (``metric:*`` items). A metric whose
inputs are P1 events that this build does not record reports
``"not_collected"`` for that part instead of a number.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence

from .stats import (
    Event,
    by_name,
    case_key,
    int_prop,
    iso_week,
    latency_summary,
    prop,
    quantile,
    ratio,
    run_cases,
    run_key,
    ts_of,
)

NOT_COLLECTED = "not_collected"


def _ms_between(later: Event, earlier: Event) -> float:
    return (ts_of(later) - ts_of(earlier)).total_seconds() * 1000


def weekly_reported_cases(events: Sequence[Event], cases: Mapping) -> dict[str, object]:
    weeks: dict[str, set] = defaultdict(set)
    for event in by_name(events, "case_report_created"):
        key = case_key(event, cases)
        if key is not None and prop(event, "status") == "ok":
            weeks[iso_week(event)].add(key)
    return {"by_week": {week: len(keys) for week, keys in sorted(weeks.items())}}


def time_to_value(events: Sequence[Event], cases: Mapping) -> dict[str, object]:
    created: dict = {}
    reported: dict = {}
    for event in events:
        key = case_key(event, cases)
        if key is None:
            continue
        if event.get("event") == "case_created":
            created.setdefault(key, event)
        elif event.get("event") == "case_report_created" and prop(event, "status") == "ok":
            reported.setdefault(key, event)
    spans = [_ms_between(reported[key], created[key]) for key in created.keys() & reported.keys()]
    return {"n": len(spans), "median_ms": quantile(spans, 0.5)}


def time_to_first_review(events: Sequence[Event]) -> dict[str, object]:
    first: dict = {}
    for event in by_name(events, "review_stage_entered"):
        value = int_prop(event, "ms_since_run_finished")
        key = run_key(event)
        if value is not None and key is not None:
            first.setdefault(key, value)
    values = list(first.values())
    return {"n": len(values), "median_ms": quantile(values, 0.5)}


def time_to_first_tag(events: Sequence[Event]) -> dict[str, object]:
    finished: dict = {}
    spans: list[float] = []
    for event in events:
        key = run_key(event)
        if key is None:
            continue
        if event.get("event") == "run_finished":
            finished.setdefault(key, event)
        elif event.get("event") == "review_tag_applied" and prop(event, "is_first_in_run") is True and key in finished:
            spans.append(_ms_between(event, finished[key]))
    return {"n": len(spans), "median_ms": quantile(spans, 0.5)}


def first_result_time(events: Sequence[Event]) -> dict[str, object]:
    groups: dict[str, list[float]] = defaultdict(list)
    loaded = by_name(events, "grid_loaded")
    for event in loaded:
        latency = int_prop(event, "latency_ms")
        if latency is not None:
            groups[f"{prop(event, 'surface')}|{prop(event, 'row_count_bucket')}"].append(latency)
    grid = [value for values in groups.values() for value in values]
    timeline = [v for e in by_name(events, "timeline_entered") if (v := int_prop(e, "latency_ms")) is not None]
    return {
        "grid": latency_summary(grid),
        "grid_by_surface_rows": {key: latency_summary(values) for key, values in sorted(groups.items())},
        "timeline": latency_summary(timeline),
        "viewer": NOT_COLLECTED,
    }


def search_latency(events: Sequence[Event]) -> dict[str, object]:
    """p50/p95 of ``search_results_returned.latency_ms`` by backend and the script of its query,
    with each group's zero-result and truncation rates (H3)."""
    script_of_last: dict = {}
    groups: dict[str, list[Event]] = defaultdict(list)
    for event in by_name(events, "search_submitted", "search_results_returned"):
        key = (event.get("install_hid"), event.get("session_id"), event.get("run_hid"))
        if event.get("event") == "search_submitted":
            script_of_last[key] = prop(event, "script")
        else:
            groups[f"{prop(event, 'backend')}|{script_of_last.get(key, 'unknown')}"].append(event)

    def summary(results: Sequence[Event]) -> dict[str, object]:
        latencies = [value for event in results if (value := int_prop(event, "latency_ms")) is not None]
        return {
            **latency_summary(latencies),
            "zero_result_rate": ratio(sum(1 for e in results if prop(e, "zero_result") is True), len(results)),
            "truncated_rate": ratio(sum(1 for e in results if prop(e, "truncated") is True), len(results)),
        }

    every = [event for results in groups.values() for event in results]
    return {"overall": summary(every), "by_backend_script": {key: summary(value) for key, value in sorted(groups.items())}}


def full_scope_share(events: Sequence[Event]) -> dict[str, object]:
    sorts = by_name(events, "grid_sorted")
    loaded = by_name(events, "grid_loaded")
    return {
        "sort_server_share": ratio(sum(1 for e in sorts if prop(e, "scope") == "server"), len(sorts)),
        "sort_count": len(sorts),
        "filter_server_share": NOT_COLLECTED,
        "total_known_share": ratio(sum(1 for e in loaded if prop(e, "total_known") is True), len(loaded)),
    }


def truncation_rate(events: Sequence[Event]) -> dict[str, object]:
    def avg(name: str) -> tuple[int, int]:
        rows = by_name(events, name)
        return sum(1 for e in rows if prop(e, "truncated") is True), len(rows)

    search, grid = avg("search_results_returned"), avg("grid_loaded")
    return {
        "search": ratio(*search),
        "grid": ratio(*grid),
        "combined": ratio(search[0] + grid[0], search[1] + grid[1]),
    }


def time_to_triage(events: Sequence[Event]) -> dict[str, object]:
    input_kind = {run_key(e): prop(e, "input_kind") for e in by_name(events, "run_started")}
    durations: dict[str, list[float]] = defaultdict(list)
    run_total = 0
    for event in by_name(events, "run_finished"):
        value = int_prop(event, "duration_ms")
        if value is not None:
            durations[str(input_kind.get(run_key(event), "unknown"))].append(value)
            run_total += value
    stage_ms: Counter[str] = Counter()
    for event in by_name(events, "run_stage_completed"):
        stage_ms[str(prop(event, "stage"))] += int_prop(event, "duration_ms") or 0
    every = [value for values in durations.values() for value in values]
    return {
        "median_ms": quantile(every, 0.5),
        "p90_ms": quantile(every, 0.9),
        "by_input_kind": {k: {"n": len(v), "median_ms": quantile(v, 0.5), "p90_ms": quantile(v, 0.9)} for k, v in sorted(durations.items())},
        "by_size_bucket": NOT_COLLECTED,
        "stage_share": {stage: ratio(ms, run_total) for stage, ms in stage_ms.most_common()},
    }


def run_success(events: Sequence[Event]) -> dict[str, object]:
    finished = by_name(events, "run_finished")
    failed = by_name(events, "run_failed")
    completed = sum(1 for e in finished if prop(e, "status") == "completed")
    partial = sum(1 for e in finished if (int_prop(e, "partial_task_count") or 0) > 0)
    return {
        "success_rate": ratio(completed, len(finished) + len(failed)),
        "partial_rate": ratio(partial, len(finished)),
        "runs": len(finished) + len(failed),
    }


def parser_error_rate(events: Sequence[Event]) -> dict[str, object]:
    errors: Counter[str] = Counter()
    providers: Counter[str] = Counter()
    for event in by_name(events, "provider_finished"):
        kind = str(prop(event, "provider_kind"))
        providers[kind] += 1
        errors[kind] += int_prop(event, "parser_error_count") or 0
    return {
        "overall": ratio(sum(errors.values()), sum(providers.values())),
        "by_provider_kind": {kind: ratio(errors[kind], providers[kind]) for kind, _ in errors.most_common()},
    }


def crash_rate(events: Sequence[Event]) -> dict[str, object]:
    crashes = Counter(str(e.get("app_version")) for e in by_name(events, "crash_reported"))
    sessions = Counter(str(e.get("app_version")) for e in by_name(events, "app_session_started"))
    return {
        "overall": ratio(sum(crashes.values()), sum(sessions.values())),
        "by_app_version": {version: ratio(crashes[version], sessions[version]) for version in sorted(crashes | sessions)},
    }


def active_installs(events: Sequence[Event], cases: Mapping) -> dict[str, object]:
    installs: dict[str, set] = defaultdict(set)
    new_cases: dict[str, set] = defaultdict(set)
    for event in by_name(events, "app_session_started"):
        installs[iso_week(event)].add(event.get("install_hid"))
    for event in by_name(events, "case_created"):
        key = case_key(event, cases)
        if key is not None:
            new_cases[iso_week(event)].add(key)
    return {
        "by_week": {
            week: {"installs": len(installs[week]), "cases_per_install": ratio(len(new_cases[week]), len(installs[week]))}
            for week in sorted(installs.keys() | new_cases.keys())
        }
    }


def compute_metrics(events: Sequence[Event]) -> dict[str, object]:
    cases = run_cases(events)
    return {
        "wrc": weekly_reported_cases(events, cases),
        "ttv": time_to_value(events, cases),
        "ttfr": time_to_first_review(events),
        "ttft": time_to_first_tag(events),
        "first_result": first_result_time(events),
        "search_latency": search_latency(events),
        "full_scope_share": full_scope_share(events),
        "truncation_rate": truncation_rate(events),
        "time_to_triage": time_to_triage(events),
        "run_success": run_success(events),
        "parser_error_rate": parser_error_rate(events),
        "crash_rate": crash_rate(events),
        "active_installs": active_installs(events, cases),
    }
