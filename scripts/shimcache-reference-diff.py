#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["regipy>=6.0.0"]
# ///
# --- How to run ---
#   uv run scripts/shimcache-reference-diff.py --system <SYSTEM hive> --output <report.json> --json
#
# Compares RapidTriage's native ShimCache binary decode
# (shimcache-schema-entry records from the AppCompatCache value)
# against regipy's ShimCachePlugin on the same SYSTEM hive.
#
# Compares ordered (cache_order, path, last_mod_date) rows: path-set
# recall/precision, per-position row agreement, and timestamp agreement
# on common paths (truncated to milliseconds).
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

from rapidtriage.artifacts.windows.execution import build_native_shimcache_records


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
    for record in build_native_shimcache_records(path):
        if record.artifact_type != "shimcache-schema-entry":
            continue
        details = record.details
        rows.append(
            {
                "order": int(details.get("cache_order") or 0),
                "path": _canon_path(details.get("executable_path")),
                "ts": _canon_ts(details.get("timestamp")),
            }
        )
    rows.sort(key=lambda row: row["order"])
    return {"rows": rows}


def trusted_side(path: Path) -> dict[str, object]:
    from regipy.plugins.system.shimcache import ShimCachePlugin
    from regipy.registry import RegistryHive

    plugin = ShimCachePlugin(registry_hive=RegistryHive(str(path)))
    plugin.run()
    rows = [
        {
            "order": index,
            "path": _canon_path(entry.get("path")),
            "ts": _canon_ts(entry.get("last_mod_date")),
        }
        for index, entry in enumerate(plugin.entries)
    ]
    return {"rows": rows}


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
    rapid_paths = {row["path"] for row in rapid_rows if row["path"]}
    trusted_paths = {row["path"] for row in trusted_rows if row["path"]}
    common_paths = rapid_paths & trusted_paths

    matched_rows = 0
    order_mismatches: list[dict[str, object]] = []
    for index, (rapid_row, trusted_row) in enumerate(zip(rapid_rows, trusted_rows)):
        if rapid_row["path"] == trusted_row["path"] and rapid_row["ts"] == trusted_row["ts"]:
            matched_rows += 1
        elif len(order_mismatches) < 25:
            order_mismatches.append(
                {
                    "index": index,
                    "rapid": {k: v for k, v in rapid_row.items() if v},
                    "trusted": {k: v for k, v in trusted_row.items() if v},
                }
            )

    rapid_ts = {row["path"]: row["ts"] for row in rapid_rows if row["path"]}
    trusted_ts = {row["path"]: row["ts"] for row in trusted_rows if row["path"]}
    ts_compared = [p for p in common_paths if rapid_ts.get(p) and trusted_ts.get(p)]
    ts_matches = sum(1 for p in ts_compared if rapid_ts[p] == trusted_ts[p])

    report = {
        "schema_version": "shimcache-reference-diff-v1",
        "release_evidence_status": "engineering_check_only",
        "report_use_warning": (
            "RapidTriage native AppCompatCache value decode vs regipy "
            "ShimCachePlugin. Row comparison is order-sensitive; "
            "timestamps truncated to milliseconds."
        ),
        "system_hive": str(args.system),
        "system_sha256": digest,
        "trusted_rows": len(trusted_rows),
        "rapid_schema_rows": len(rapid_rows),
        "ordered_row_matches": matched_rows,
        "path_recall": round(len(common_paths) / len(trusted_paths), 6) if trusted_paths else None,
        "path_precision": round(len(common_paths) / len(rapid_paths), 6) if rapid_paths else None,
        "paths_only_in_rapid_sample": sorted(rapid_paths - trusted_paths)[:25],
        "paths_only_in_trusted_sample": sorted(trusted_paths - rapid_paths)[:25],
        "timestamps_compared": len(ts_compared),
        "timestamp_matches": ts_matches,
        "timestamp_agreement": round(ts_matches / len(ts_compared), 6) if ts_compared else None,
        "order_mismatch_sample": order_mismatches,
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
            f"ordered_matches={matched_rows} recall={report['path_recall']} "
            f"precision={report['path_precision']} ts_agreement={report['timestamp_agreement']}"
        )
        print(f"-> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
