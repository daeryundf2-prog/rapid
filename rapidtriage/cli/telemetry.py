"""``rapidtriage telemetry status|metrics|enable|disable|export`` (local telemetry log)."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from ..core import telemetry
from ..core.telemetry.export import TelemetryExportError, export_bundle
from ..core.telemetry.funnels import build_report


def handle_telemetry(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
    directory = telemetry.telemetry_dir()
    match args.action:
        case "status":
            events = Counter(str(event.get("event")) for event in telemetry.iter_events(directory))
            payload: dict[str, object] = {
                "command": "telemetry.status",
                "recording": telemetry.disabled_reason(directory) is None,
                "disabled_reason": telemetry.disabled_reason(directory),
                "directory": str(directory),
                "event_count": sum(events.values()),
                "events_by_name": dict(sorted(events.items())),
                "network_upload": False,
            }
        case "metrics":
            payload = {"command": "telemetry.metrics", **build_report(list(telemetry.iter_events(directory)))}
        case "enable" | "disable":
            path = telemetry.write_settings(enabled=args.action == "enable", directory=directory)
            payload = {"command": f"telemetry.{args.action}", "settings": str(path)}
        case "export":
            if not args.out:
                parser.error("telemetry export needs --out <folder>")
            try:
                payload = export_bundle(Path(args.out).expanduser(), source_dir=directory)
            except TelemetryExportError as exc:
                parser.error(str(exc))
        case unreachable:
            parser.error(f"unknown telemetry action: {unreachable}")
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


HANDLERS = {"telemetry": handle_telemetry}
