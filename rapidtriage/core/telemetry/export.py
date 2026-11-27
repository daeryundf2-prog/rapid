"""User-run export bundle of the local telemetry log (nothing is sent anywhere).

``rapidtriage telemetry export --out <folder>`` writes ``events.jsonl`` (every
recorded event, already whitelisted and hashed) and ``manifest.json`` (event
counts, time range, SHA-256 of the events file). The salt is never exported,
so the receiver cannot link ids to this install's raw ids. The user reviews
the bundle and hands it over themselves.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from collections import Counter
from pathlib import Path

from .recorder import iter_events, privacy_violations
from .schema import SCHEMA_VERSION

BUNDLE_EVENTS = "events.jsonl"
BUNDLE_MANIFEST = "manifest.json"


class TelemetryExportError(Exception):
    """The bundle folder is not empty or an event fails the privacy check."""


def export_bundle(out_dir: Path, *, source_dir: Path | None = None) -> dict[str, object]:
    """Write the bundle into the empty (or new) ``out_dir``; returns the manifest."""
    if out_dir.exists() and any(out_dir.iterdir()):
        raise TelemetryExportError(f"export folder is not empty: {out_dir}")
    events = list(iter_events(source_dir))
    for number, event in enumerate(events, start=1):
        problems = privacy_violations(event)
        if problems:
            raise TelemetryExportError(f"event {number} fails the privacy check: {'; '.join(problems)}")
    out_dir.mkdir(parents=True, exist_ok=True)
    body = "".join(json.dumps(event, ensure_ascii=True, separators=(",", ":")) + "\n" for event in events)
    (out_dir / BUNDLE_EVENTS).write_text(body, encoding="utf-8")
    stamps = sorted(str(event.get("ts")) for event in events)
    manifest = {
        "command": "telemetry.export",
        "schema_version": SCHEMA_VERSION,
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "event_count": len(events),
        "events_by_name": dict(sorted(Counter(str(event.get("event")) for event in events).items())),
        "from": stamps[0] if stamps else None,
        "to": stamps[-1] if stamps else None,
        "events_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "salt_included": False,
    }
    (out_dir / BUNDLE_MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest
