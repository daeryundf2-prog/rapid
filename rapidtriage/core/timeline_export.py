from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path

from .filetime import (
    FILETIME_TICKS_PER_SECOND,
    LOCAL_TIMEZONE_LABELS,
    event_timestamp_utc_ticks,
    filetime_to_iso_7,
)
from .search import load_run_summary
from .timeline import event_sort_key, event_utc_ticks

ZONE_UTC_INSTANT = "utc-instant"
ZONE_UNDETERMINED = "wall-clock-zone-undetermined"
# A wall clock of undetermined zone is UTC + offset for some offset in [-12:00, +14:00]:
# it can fall inside a UTC range [start, end] only when it lies in [start - 12 h, end + 14 h].
_MAX_WEST_TICKS = 12 * 3600 * FILETIME_TICKS_PER_SECOND
_MAX_EAST_TICKS = 14 * 3600 * FILETIME_TICKS_PER_SECOND
_OFFSET_RE = re.compile(r"^([+-])(\d{2}):?(\d{2})$")


class TimelineExportError(ValueError):
    """Raised when a unified timeline export cannot be built."""


def build_unified_timeline_export(
    run_output: Path,
    *,
    start: str | None = None,
    end: str | None = None,
    source: str | None = None,
    event_type: str | None = None,
    reviewed_status: str | None = None,
    limit: int = 0,
    assume_local_timezone: str | None = None,
) -> dict[str, object]:
    """Normalized timeline of a completed run.

    ``start``/``end`` are UTC instants compared as integer 100 ns ticks. A wall
    clock whose zone the evidence does not establish (``timezone`` such as
    ``local-unknown``) is never decided against them: it leaves ``events`` and,
    when some UTC offset could put it inside the range, is listed in
    ``zone_undetermined_events``. ``assume_local_timezone`` (``+09:00`` or an
    IANA name) converts such wall clocks under that stated assumption instead;
    the result goes to ``assumed_utc``/``assumed_timezone`` and decides the
    range, and the source ``timestamp`` stays as written.
    """
    summary = load_run_summary(run_output)
    outputs = summary.get("outputs") if isinstance(summary.get("outputs"), Mapping) else {}
    timeline_path = Path(str(outputs.get("timeline") or ""))
    if not timeline_path.is_file():
        raise TimelineExportError("run output does not include a readable timeline JSON")
    timeline_payload = json.loads(timeline_path.read_text(encoding="utf-8"))
    raw_events = timeline_payload.get("events") if isinstance(timeline_payload, Mapping) else None
    if not isinstance(raw_events, list):
        raise TimelineExportError("timeline JSON does not contain events")
    assumed_zone = _assumed_zone(assume_local_timezone)

    filters = {
        "start": start,
        "end": end,
        "source": source,
        "event_type": event_type,
        "reviewed_status": reviewed_status,
        "limit": limit,
        "assume_local_timezone": assume_local_timezone,
    }
    events = [
        normalize_event(event, index=index + 1, assumed_zone=assumed_zone)
        for index, event in enumerate(raw_events)
        if isinstance(event, Mapping)
    ]
    ranged = bool(start or end)
    undetermined: list[dict[str, object]] = []
    kept: list[dict[str, object]] = []
    for event in events:
        if not matches_filters(event, {**filters, "start": None, "end": None}):
            continue
        if ranged and event["zone_status"] == ZONE_UNDETERMINED and "assumed_utc_ticks" not in event:
            if _may_fall_in_range(event, start, end):
                undetermined.append(event)
            continue
        if ranged and not matches_filters(event, {"start": start, "end": end}):
            continue
        kept.append(event)
    events = kept
    # Integer UTC 100 ns ticks decide order (string order of ISO text with
    # different fraction lengths/offsets is not time order).
    events.sort(key=_range_sort_key)
    if limit:
        events = events[:limit]
    for event in (*events, *undetermined):
        event.pop("assumed_utc_ticks", None)

    return {
        "command": "timeline-export",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "run_output": str(Path(run_output).expanduser().resolve()),
        "filters": filters,
        "summary": {
            "event_count": len(events),
            "source_counts": count_by(events, "source"),
            "event_type_counts": count_by(events, "event_type"),
            "earliest_event_at": events[0]["timestamp"] if events else None,
            "latest_event_at": events[-1]["timestamp"] if events else None,
            "range_filter": {
                "applied": ranged,
                "basis": "utc-100ns-ticks",
                "zone_undetermined_policy": (
                    "assumed-timezone" if assumed_zone is not None else "excluded-listed-separately"
                ),
                "assumed_timezone": assumed_zone[1] if assumed_zone is not None else None,
                "zone_undetermined_event_count": len(undetermined),
                "note": (
                    "시간대가 확정되지 않은 현지 시각은 UTC 범위로 판정하지 않습니다. 범위 밖으로 빼고, "
                    "UTC 오프셋 -12:00~+14:00 중 어느 값으로든 범위에 들 수 있는 행은 "
                    "zone_undetermined_events에 따로 둡니다. assume_local_timezone을 주면 그 가정으로 "
                    "환산한 값(assumed_utc)으로 판정합니다."
                ),
            },
        },
        "events": events,
        "zone_undetermined_events": undetermined,
    }


def normalize_event(
    event: Mapping[str, object],
    *,
    index: int,
    assumed_zone: tuple[dt.tzinfo, str] | None = None,
) -> dict[str, object]:
    timestamp = str(event.get("timestamp") or "")
    source = str(event.get("source") or "unknown")
    event_type = str(event.get("event_type") or "observed")
    path = str(event.get("path") or event.get("target") or "")
    summary = str(event.get("summary") or event.get("description") or event_type)
    event_id = stable_event_id(timestamp, source, event_type, path, summary, index)
    timezone = str(event.get("timezone") or "")
    zone_status = ZONE_UNDETERMINED if timezone in LOCAL_TIMEZONE_LABELS else ZONE_UTC_INSTANT
    normalized: dict[str, object] = {
        "event_id": event_id,
        "timestamp": timestamp,
        "timestamp_kind": timestamp_kind(event_type),
        "source_timestamp_kind": str(event.get("timestamp_kind") or ""),
        "timezone": timezone or None,
        "zone_status": zone_status,
        "source": source,
        "event_type": event_type,
        "path": path,
        "summary": summary,
        "review_status": str(event.get("review_status") or "unreviewed"),
        "confidence": event.get("confidence", None),
        "details": event.get("details") if isinstance(event.get("details"), Mapping) else {},
        "raw": dict(event),
    }
    if zone_status == ZONE_UNDETERMINED and assumed_zone is not None:
        ticks = _assumed_utc_ticks(timestamp, assumed_zone[0])
        if ticks is not None:
            normalized["assumed_utc"] = filetime_to_iso_7(ticks)
            normalized["assumed_timezone"] = assumed_zone[1]
            normalized["assumed_utc_ticks"] = ticks
    return normalized


def stable_event_id(timestamp: str, source: str, event_type: str, path: str, summary: str, index: int) -> str:
    digest = hashlib.sha256(f"{timestamp}|{source}|{event_type}|{path}|{summary}|{index}".encode()).hexdigest()
    return f"evt-{digest[:16]}"


def timestamp_kind(event_type: str) -> str:
    lowered = event_type.lower()
    if "visited" in lowered:
        return "visited"
    if "download" in lowered:
        return "downloaded"
    if "created" in lowered:
        return "created"
    if "modified" in lowered:
        return "modified"
    if "access" in lowered:
        return "accessed"
    if "review" in lowered:
        return "reviewed"
    if "eventlog" in lowered:
        return "event-created"
    if "execut" in lowered or "prefetch" in lowered:
        return "executed"
    return "observed"


def matches_filters(event: Mapping[str, object], filters: Mapping[str, object]) -> bool:
    if filters.get("start") and not _not_before(event, str(filters["start"])):
        return False
    if filters.get("end") and _not_before(event, str(filters["end"]), strictly_after=True):
        return False
    if filters.get("source") and str(event.get("source") or "") != str(filters["source"]):
        return False
    if filters.get("event_type") and str(event.get("event_type") or "") != str(filters["event_type"]):
        return False
    if filters.get("reviewed_status") and str(event.get("review_status") or "unreviewed") != str(filters["reviewed_status"]):
        return False
    return True


def _event_ticks(event: Mapping[str, object]) -> int | None:
    """UTC ticks deciding range and order: the assumed conversion of a wall clock, else the event's."""
    assumed = event.get("assumed_utc_ticks")
    return assumed if isinstance(assumed, int) else event_utc_ticks(event)


def _range_sort_key(event: Mapping[str, object]) -> tuple[int, int, str, str, str]:
    if isinstance(event.get("assumed_utc_ticks"), int):
        base = event_sort_key(event)
        return (1, int(event["assumed_utc_ticks"]), *base[2:])
    return event_sort_key(event)


def _not_before(event: Mapping[str, object], bound: str, *, strictly_after: bool = False) -> bool:
    """``event >= bound`` (``event > bound`` with ``strictly_after``), compared as
    integer UTC ticks; text comparison only when either side has no instant."""
    ticks = _event_ticks(event)
    bound_ticks = event_utc_ticks({"timestamp": bound})
    if ticks is None or bound_ticks is None:
        timestamp = str(event.get("timestamp") or "")
        return timestamp > bound if strictly_after else timestamp >= bound
    return ticks > bound_ticks if strictly_after else ticks >= bound_ticks


def _may_fall_in_range(event: Mapping[str, object], start: str | None, end: str | None) -> bool:
    """A wall clock that some UTC offset (-12:00..+14:00) puts inside ``[start, end]``."""
    wall = event_timestamp_utc_ticks(event.get("timestamp"))[0]
    if wall is None:
        return False
    start_ticks = event_utc_ticks({"timestamp": start}) if start else None
    end_ticks = event_utc_ticks({"timestamp": end}) if end else None
    if start_ticks is not None and wall < start_ticks - _MAX_WEST_TICKS:
        return False
    return not (end_ticks is not None and wall > end_ticks + _MAX_EAST_TICKS)


def _assumed_zone(value: str | None) -> tuple[dt.tzinfo, str] | None:
    """``+09:00`` / ``UTC`` / IANA name -> ``(tzinfo, label)``; ``None`` when not given."""
    text = str(value or "").strip()
    if not text:
        return None
    if text.upper() in ("UTC", "Z"):
        return dt.timezone.utc, "UTC"
    match = _OFFSET_RE.match(text)
    if match:
        sign, hours, minutes = match.group(1), int(match.group(2)), int(match.group(3))
        delta = dt.timedelta(hours=hours, minutes=minutes)
        if minutes > 59 or delta > dt.timedelta(hours=14):
            raise TimelineExportError("assume_local_timezone offset must be within -14:00..+14:00")
        label = f"{sign}{hours:02d}:{minutes:02d}"
        return dt.timezone(-delta if sign == "-" else delta, label), label
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(text), text
    except (ValueError, OSError, UnicodeDecodeError, LookupError) as exc:
        raise TimelineExportError(f"assume_local_timezone is not a UTC offset or a readable time zone name: {text!r}") from exc


def _assumed_utc_ticks(timestamp: str, zone: dt.tzinfo) -> int | None:
    """UTC ticks of a wall clock read in ``zone`` (every fraction digit kept)."""
    wall = event_timestamp_utc_ticks(timestamp)
    if wall[0] is None or wall[1] != "iso-no-offset-assumed-utc":
        return None
    seconds = wall[0] // FILETIME_TICKS_PER_SECOND
    moment = dt.datetime(1601, 1, 1) + dt.timedelta(seconds=seconds)
    offset = moment.replace(tzinfo=zone).utcoffset()
    if offset is None:
        return None
    return wall[0] - int(offset.total_seconds()) * FILETIME_TICKS_PER_SECOND


def count_by(events: list[Mapping[str, object]], field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for event in events:
        key = str(event.get(field) or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return counts
