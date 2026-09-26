"""Timeline density histogram for the interactive heatmap (R2-4).

Buckets all timeline events (not just the current page) by adaptive time
windows and per-source density so the frontend can render a time x artifact
heatmap without streaming every event to the browser.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping, Sequence

ISO_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
)

HISTOGRAM_VERSION = "timeline-histogram-v1"
MIN_BUCKETS = 24
MAX_BUCKETS = 240
MAX_SOURCE_ROWS = 12


def parse_event_timestamp(value: object) -> dt.datetime | None:
    """Parse a timeline event timestamp into an aware UTC datetime."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    parsed: dt.datetime | None = None
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError:
        for fmt in ISO_FORMATS:
            try:
                parsed = dt.datetime.strptime(normalized, fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def choose_bucket_seconds(span_seconds: float) -> int:
    """Pick an adaptive bucket width so the heatmap stays readable."""
    if span_seconds <= 0:
        return 3600
    for candidate in (300, 900, 1800, 3600, 21600, 86400, 604800, 2592000):
        if span_seconds / candidate <= MAX_BUCKETS:
            return candidate
    return int(span_seconds / MAX_BUCKETS) + 1


def build_timeline_histogram(
    payload: Mapping[str, object],
    *,
    max_source_rows: int = MAX_SOURCE_ROWS,
) -> dict[str, object]:
    """Aggregate timeline events into time x source density buckets."""
    events = payload.get("events")
    if not isinstance(events, Sequence) or isinstance(events, (str, bytes)):
        events = []

    parsed_events: list[tuple[dt.datetime, str]] = []
    unparsed = 0
    for event in events:
        if not isinstance(event, Mapping):
            unparsed += 1
            continue
        timestamp = parse_event_timestamp(event.get("timestamp"))
        if timestamp is None:
            unparsed += 1
            continue
        source = str(event.get("source") or event.get("event_type") or "unknown")
        parsed_events.append((timestamp, source))

    if not parsed_events:
        return {
            "profile_version": HISTOGRAM_VERSION,
            "total_events": len(events),
            "parsed_events": 0,
            "unparsed_events": unparsed,
            "bucket_seconds": None,
            "bucket_count": 0,
            "range_start": None,
            "range_end": None,
            "sources": [],
            "buckets": [],
        }

    start = min(ts for ts, _ in parsed_events)
    end = max(ts for ts, _ in parsed_events)
    span = max((end - start).total_seconds(), 1)
    bucket_seconds = choose_bucket_seconds(span)

    epoch_start = int(start.timestamp())
    # Align buckets to wall-clock boundaries for readability.
    epoch_start -= epoch_start % bucket_seconds
    needed = int((end.timestamp() - epoch_start) // bucket_seconds) + 1
    if needed > MAX_BUCKETS:
        # Widen the bucket so every event index fits within the grid.
        bucket_seconds = int((end.timestamp() - epoch_start) // MAX_BUCKETS) + 1
        epoch_start -= epoch_start % bucket_seconds
        needed = int((end.timestamp() - epoch_start) // bucket_seconds) + 1
    bucket_count = min(max(needed, MIN_BUCKETS), MAX_BUCKETS)

    source_totals: dict[str, int] = {}
    grid: dict[tuple[int, str], int] = {}
    counts = [0] * bucket_count
    for timestamp, source in parsed_events:
        index = int((timestamp.timestamp() - epoch_start) // bucket_seconds)
        if index < 0 or index >= bucket_count:
            continue
        source_totals[source] = source_totals.get(source, 0) + 1
        grid[(index, source)] = grid.get((index, source), 0) + 1
        counts[index] += 1

    top_sources = sorted(source_totals.items(), key=lambda item: (-item[1], item[0]))[:max_source_rows]
    source_names = [name for name, _ in top_sources]

    buckets = []
    for index in range(bucket_count):
        bucket_start = dt.datetime.fromtimestamp(epoch_start + index * bucket_seconds, tz=dt.timezone.utc)
        bucket_end = dt.datetime.fromtimestamp(epoch_start + (index + 1) * bucket_seconds, tz=dt.timezone.utc)
        by_source = {
            source: grid[(index, source)]
            for source in source_names
            if grid.get((index, source))
        }
        other = counts[index] - sum(by_source.values())
        if other > 0:
            by_source["__other__"] = other
        buckets.append(
            {
                "index": index,
                "start": bucket_start.isoformat(),
                "end": bucket_end.isoformat(),
                "count": counts[index],
                "by_source": by_source,
            }
        )

    return {
        "profile_version": HISTOGRAM_VERSION,
        "total_events": len(events),
        "parsed_events": len(parsed_events),
        "unparsed_events": unparsed,
        "bucket_seconds": bucket_seconds,
        "bucket_count": bucket_count,
        "range_start": dt.datetime.fromtimestamp(epoch_start, tz=dt.timezone.utc).isoformat(),
        "range_end": dt.datetime.fromtimestamp(epoch_start + bucket_count * bucket_seconds, tz=dt.timezone.utc).isoformat(),
        "max_bucket_count": max(counts) if counts else 0,
        "sources": [{"name": name, "count": count} for name, count in top_sources],
        "buckets": buckets,
    }
