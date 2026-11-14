#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["regipy>=6.0.0"]
# ///
# --- How to run ---
#   Export mode (T-206; no extra dependencies):
#     python scripts/shimcache-reference-diff.py --ours <run>/artifacts/<execution per-kind output .json or JSONL> \
#         --reference <AppCompatCacheParser CSV | generic CSV> --output <report.json> --json
#   Hive mode (decoder check):
#     uv run scripts/shimcache-reference-diff.py --system <SYSTEM hive> --output <report.json> --json
#
# Export mode diffs RapidTriage `shimcache-schema-entry` rows against a dedicated
# ShimCache parser's CSV. Key = control set + 0-based cache position + path (case-
# insensitive); a row whose path moved to another position still pairs (by control set +
# path) and reports `cache_order` as a field mismatch. Compares the last-modified time
# (UTC, second precision). The control set leaves the key when either side has none.
# Shared loader/diff/report: rapidtriage/validation/reference_diff.py. Exit 0 clean,
# 1 differences, 2 input error.
#
# Hive mode compares RapidTriage's native ShimCache binary decode
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
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.artifacts.windows.execution import build_native_shimcache_records
from rapidtriage.validation import reference_diff as rd


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


def hive_main(argv: list[str] | None = None) -> int:
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


# ---------------------------------------------------------------------------
# Export mode (T-206)
# ---------------------------------------------------------------------------

SHIMCACHE_ARTIFACT_TYPES = ("shimcache-schema-entry",)
REF_ORDER = ("cacheentryposition", "position", "cacheorder", "order", "entryposition", "index")
REF_PATH = ("path", "executablepath", "filepath", "fullpath", "name")
REF_TIME = ("lastmodifiedtimeutc", "lastmodifiedtime", "lastmodified", "lastmoddate", "modified", "timestamp")
REF_CONTROL_SET = ("controlset", "controlsetnumber")


def control_set_number(value: object) -> str:
    """``ControlSet001`` / ``1`` / ``001`` -> ``"1"``; ``""`` when absent."""
    digits = re.sub(r"\D", "", str(value or ""))
    return str(int(digits)) if digits else ""


def shim_row(control_set: str, order: int, path: object, modified: object) -> rd.KeyedRow:
    canon = rd.normalize_text(str(path or "").strip().strip('"').replace("/", "\\").rstrip("\\"))
    return rd.KeyedRow(
        keys=[f"{control_set}|{order}|{canon}", f"{control_set}|*|{canon}"],
        fields={"cache_order": order, "last_modified": modified},
        label={"control_set": control_set, "cache_order": order, "path": canon, "last_modified": modified},
    )


def build_shimcache_comparison(args: argparse.Namespace, warnings: list[str]) -> rd.Comparison:
    table, header = rd.read_table(args.reference)
    rd.require_columns(header, args.reference, position=REF_ORDER, path=REF_PATH)
    tool = "AppCompatCacheParser (CSV)" if "cacheentryposition" in header else "generic ShimCache CSV"
    reference: list[rd.KeyedRow] = []
    for line, row in enumerate(table, start=2):
        order = rd.parse_int(rd.pick(row, *REF_ORDER))
        path = rd.pick(row, *REF_PATH)
        if order is None or not path:
            rd.add_warning(warnings, f"기준 {line}행에 순번이나 경로가 없어 건너뛰었습니다")
            continue
        stamp = rd.safe_timestamp(rd.pick(row, *REF_TIME), args.reference_tzinfo, warnings, f"기준 {line}행")
        reference.append(shim_row(control_set_number(rd.pick(row, *REF_CONTROL_SET)), order, path, stamp))
    ours: list[rd.KeyedRow] = []
    for row in rd.iter_rapid_rows(args.ours, SHIMCACHE_ARTIFACT_TYPES, warnings):
        order = rd.parse_int(rd.rapid_field(row, "cache_order"))
        path = rd.rapid_field(row, "executable_path", "path")
        if order is None or not path:
            continue
        stamp = rd.safe_timestamp(rd.rapid_field(row, "timestamp", "last_modified"), args.ours_tzinfo, warnings, f"우리 순번 {order}")
        ours.append(shim_row(control_set_number(rd.rapid_field(row, "control_set")), order, path, stamp))
    key_fields = ["control_set", "cache_order", "path"]
    if rd.drop_blank_key_part(ours, reference, 0):
        key_fields = ["cache_order", "path"]
        rd.add_warning(warnings, "한쪽에 ControlSet 값이 없어 키에서 ControlSet을 뺐습니다")
    return rd.Comparison(
        ours=ours,
        reference=reference,
        reference_tool=tool,
        key_fields=key_fields,
        compared_fields=["cache_order", "last_modified"],
    )


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if any(item == "--system" or item.startswith("--system=") for item in argv):
        return hive_main(argv)
    return rd.run_comparison_cli(
        argv,
        comparison="shimcache",
        description="Diff RapidTriage shimcache-schema-entry rows against a ShimCache parser CSV (key = path + position).",
        build=build_shimcache_comparison,
    )


if __name__ == "__main__":
    raise SystemExit(main())
