"""Shared helpers of the metric/funnel computation over the local event log."""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterable, Mapping, Sequence

Event = Mapping[str, object]


def ts_of(event: Event) -> dt.datetime:
    return dt.datetime.fromisoformat(str(event["ts"]))


def iso_week(event: Event) -> str:
    year, week, _day = ts_of(event).isocalendar()
    return f"{year}-W{week:02d}"


def prop(event: Event, key: str) -> object:
    props = event.get("props")
    return props.get(key) if isinstance(props, Mapping) else None


def int_prop(event: Event, key: str) -> int | None:
    value = prop(event, key)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def quantile(values: Sequence[float], q: float) -> float | None:
    """Linear-interpolated quantile (DuckDB ``quantile_cont``); ``None`` for no values."""
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * q
    low = int(position)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def ratio(numerator: float, denominator: float) -> float | None:
    return numerator / denominator if denominator else None


def latency_summary(values: Sequence[float]) -> dict[str, object]:
    return {"n": len(values), "p50_ms": quantile(values, 0.5), "p95_ms": quantile(values, 0.95)}


def by_name(events: Iterable[Event], *names: str) -> list[Event]:
    wanted = set(names)
    return [event for event in events if event.get("event") in wanted]


def run_cases(events: Iterable[Event]) -> dict[tuple[object, object], object]:
    """``(install_hid, run_hid) -> case_hid`` from every event that carries both."""
    return {
        (event.get("install_hid"), event.get("run_hid")): event.get("case_hid")
        for event in events
        if event.get("run_hid") and event.get("case_hid")
    }


def case_key(event: Event, cases: Mapping[tuple[object, object], object]) -> tuple[object, object] | None:
    """``(install_hid, case_hid)`` of ``event``, through its run when the event itself has no case."""
    case = event.get("case_hid") or cases.get((event.get("install_hid"), event.get("run_hid")))
    return (event.get("install_hid"), case) if case else None


def run_key(event: Event) -> tuple[object, object] | None:
    return (event.get("install_hid"), event.get("run_hid")) if event.get("run_hid") else None
