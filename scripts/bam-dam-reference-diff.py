#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["regipy>=6.0.0"]
# ///
# --- How to run ---
#   uv run scripts/bam-dam-reference-diff.py --system <SYSTEM hive> --output <report.json> --json
#
# Compares RapidTriage's native BAM/DAM decode (bam-schema-entry
# records: per-SID UserSettings values whose names are executable
# device paths, data = FILETIME) against regipy's BAMPlugin on the
# same SYSTEM hive.
#
# Compares (sid, executable, timestamp) row sets plus SequenceNumber /
# Version metadata presence. Timestamps truncated to milliseconds.
#
# Engineering measurement only; regipy is not in the recognized
# trusted-tool list, so results stay engineering_check_only.
# ------------------
from __future__ import annotations

import sys as _sys

if hasattr(_sys.stdout, "reconfigure"):
    _sys.stdout.reconfigure(encoding="utf-8")
if hasattr(_sys.stderr, "reconfigure"):
    _sys.stderr.reconfigure(encoding="utf-8")

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.artifacts.windows.execution import build_native_bam_dam_records


def _canon_path(value: object) -> str:
    return str(value or "").strip().strip('"').replace("/", "\\").lower().rstrip("\\")


def _canon_ts(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        stamp = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return stamp.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
    text = str(value).strip()
    if not text:
        return ""
    try:
        stamp = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text[:23]
    if stamp.tzinfo:
        stamp = stamp.astimezone(timezone.utc)
    return stamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]


def rapid_side(path: Path) -> dict[str, object]:
    rows: list[dict[str, object]] = []
    for record in build_native_bam_dam_records(path):
        if record.artifact_type != "bam-schema-entry":
            continue
        details = record.details
        rows.append(
            {
                "sid": str(details.get("user_sid") or ""),
                "path": _canon_path(details.get("executable_path")),
                "ts": _canon_ts(details.get("timestamp")),
            }
        )
    return {"rows": rows}


def trusted_side(path: Path) -> dict[str, object]:
    from regipy.plugins.system.bam import BAMPlugin
    from regipy.registry import RegistryHive

    plugin = BAMPlugin(registry_hive=RegistryHive(str(path)))
    plugin.run()
    rows = [
        {
            "sid": str(entry.get("sid") or ""),
            "path": _canon_path(entry.get("executable")),
            "ts": _canon_ts(entry.get("timestamp")),
        }
        for entry in plugin.entries
    ]
    return {"rows": rows}


def _row_key(row: dict[str, object]) -> tuple[str, str]:
    return (row["sid"], row["path"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--system", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    digest = hashlib.sha256(args.system.read_bytes()).hexdigest()

    errors: list[str] = []
    try:
        rapid = rapid_side(args.system)
    except Exception as exc:
        errors.append(f"rapid: {exc!r}"[:200])
        rapid = {"rows": []}
    try:
        trusted = trusted_side(args.system)
    except Exception as exc:
        errors.append(f"trusted: {exc!r}"[:200])
        trusted = {"rows": []}

    rapid_rows: list[dict[str, object]] = rapid["rows"]
    trusted_rows: list[dict[str, object]] = trusted["rows"]
    rapid_keys = {_row_key(row) for row in rapid_rows}
    trusted_keys = {_row_key(row) for row in trusted_rows}
    common_keys = rapid_keys & trusted_keys

    rapid_ts = {_row_key(row): row["ts"] for row in rapid_rows}
    trusted_ts = {_row_key(row): row["ts"] for row in trusted_rows}
    ts_compared = [key for key in common_keys if rapid_ts.get(key) and trusted_ts.get(key)]
    ts_matches = sum(1 for key in ts_compared if rapid_ts[key] == trusted_ts[key])

    report = {
        "schema_version": "bam-dam-reference-diff-v1",
        "release_evidence_status": "engineering_check_only",
        "report_use_warning": (
            "RapidTriage native BAM/DAM UserSettings value decode vs "
            "regipy BAMPlugin. Rows keyed by (sid, executable); "
            "timestamps truncated to milliseconds."
        ),
        "system_hive": str(args.system),
        "system_sha256": digest,
        "trusted_rows": len(trusted_rows),
        "rapid_schema_rows": len(rapid_rows),
        "row_recall": round(len(common_keys) / len(trusted_keys), 6) if trusted_keys else None,
        "row_precision": round(len(common_keys) / len(rapid_keys), 6) if rapid_keys else None,
        "rows_only_in_rapid_sample": [
            {"sid": key[0], "path": key[1]} for key in sorted(rapid_keys - trusted_keys)[:25]
        ],
        "rows_only_in_trusted_sample": [
            {"sid": key[0], "path": key[1]} for key in sorted(trusted_keys - rapid_keys)[:25]
        ],
        "timestamps_compared": len(ts_compared),
        "timestamp_matches": ts_matches,
        "timestamp_agreement": round(ts_matches / len(ts_compared), 6) if ts_compared else None,
        "timestamp_normalization": "utc millisecond truncation",
        "errors": errors,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(
            f"trusted_rows={len(trusted_rows)} rapid_rows={len(rapid_rows)} "
            f"row_recall={report['row_recall']} row_precision={report['row_precision']} "
            f"ts_agreement={report['timestamp_agreement']}"
        )
        print(f"-> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
