from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Mapping

from .search import load_run_summary


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
) -> dict[str, object]:
    summary = load_run_summary(run_output)
    outputs = summary.get("outputs") if isinstance(summary.get("outputs"), Mapping) else {}
    timeline_path = Path(str(outputs.get("timeline") or ""))
    if not timeline_path.is_file():
        raise TimelineExportError("run output does not include a readable timeline JSON")
    timeline_payload = json.loads(timeline_path.read_text(encoding="utf-8"))
    raw_events = timeline_payload.get("events") if isinstance(timeline_payload, Mapping) else None
    if not isinstance(raw_events, list):
        raise TimelineExportError("timeline JSON does not contain events")

    filters = {
        "start": start,
        "end": end,
        "source": source,
        "event_type": event_type,
        "reviewed_status": reviewed_status,
        "limit": limit,
    }
    events = [normalize_event(event, index=index + 1) for index, event in enumerate(raw_events) if isinstance(event, Mapping)]
    events = [event for event in events if matches_filters(event, filters)]
    events.sort(key=lambda item: str(item.get("timestamp") or ""))
    if limit:
        events = events[:limit]

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
        },
        "events": events,
    }


def normalize_event(event: Mapping[str, object], *, index: int) -> dict[str, object]:
    timestamp = str(event.get("timestamp") or "")
    source = str(event.get("source") or "unknown")
    event_type = str(event.get("event_type") or "observed")
    path = str(event.get("path") or event.get("target") or "")
    summary = str(event.get("summary") or event.get("description") or event_type)
    event_id = stable_event_id(timestamp, source, event_type, path, summary, index)
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "timestamp_kind": timestamp_kind(event_type),
        "source": source,
        "event_type": event_type,
        "path": path,
        "summary": summary,
        "review_status": str(event.get("review_status") or "unreviewed"),
        "confidence": event.get("confidence", None),
        "details": event.get("details") if isinstance(event.get("details"), Mapping) else {},
        "raw": dict(event),
    }


def stable_event_id(timestamp: str, source: str, event_type: str, path: str, summary: str, index: int) -> str:
    digest = hashlib.sha256(f"{timestamp}|{source}|{event_type}|{path}|{summary}|{index}".encode("utf-8")).hexdigest()
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
    timestamp = str(event.get("timestamp") or "")
    if filters.get("start") and timestamp < str(filters["start"]):
        return False
    if filters.get("end") and timestamp > str(filters["end"]):
        return False
    if filters.get("source") and str(event.get("source") or "") != str(filters["source"]):
        return False
    if filters.get("event_type") and str(event.get("event_type") or "") != str(filters["event_type"]):
        return False
    if filters.get("reviewed_status") and str(event.get("review_status") or "unreviewed") != str(filters["reviewed_status"]):
        return False
    return True


def count_by(events: list[Mapping[str, object]], field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for event in events:
        key = str(event.get(field) or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return counts
