#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["regipy>=6.0.0"]
# ///
# --- How to run ---
#   Export mode (T-207; no extra dependencies):
#     python scripts/userassist-reference-diff.py --ours <run>/artifacts/<execution per-kind output .json or JSONL> \
#         --reference <RECmd/Registry Explorer UserAssist CSV | generic CSV> --output <report.json> --json
#   Hive mode (decoder check):
#     uv run scripts/userassist-reference-diff.py --ntuser <NTUSER.DAT> --output <report.json> --json
#
# Export mode diffs RapidTriage `userassist-schema-entry` rows against a dedicated
# parser's CSV. Key = account + decoded (ROT13) name, case-insensitive; our row is also
# found by its resolved executable/display path, for tools that expand known-folder
# GUIDs. Compares run count and last-run time (UTC, second precision). The account comes
# from an account/user column or the hive path (Users/<name>/NTUSER.DAT) and leaves the
# key when either side has none. Shared loader/diff/report:
# rapidtriage/validation/reference_diff.py. Exit 0 clean, 1 differences, 2 input error.
#
# Hive mode compares RapidTriage's native UserAssist decode
# (userassist-schema-entry records: ROT13 names + Win7/XP binary
# layouts) against regipy's UserAssistPlugin on the same NTUSER.DAT.
#
# Compares (decoded_name, timestamp) rows plus run_counter /
# focus_count fields. regipy's GUID list contains duplicates so its
# output is deduplicated before comparison (raw_count vs
# deduped_count are both reported).
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

from rapidtriage.artifacts.windows.execution import build_native_userassist_records
from rapidtriage.validation import reference_diff as rd


def _canon_name(value: object) -> str:
    return str(value or "").strip().replace("/", "\\").lower().rstrip("\\")


def _canon_ts(value: object) -> str:
    if value is None:
        # FILETIME zero -> RapidTriage emits null, regipy emits the epoch.
        return "1601-01-01T00:00:00.000"
    if isinstance(value, datetime):
        stamp = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return stamp.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
    text = str(value).strip()
    if not text:
        return "1601-01-01T00:00:00.000"
    try:
        stamp = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text[:23]
    if stamp.tzinfo:
        stamp = stamp.astimezone(timezone.utc)
    return stamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]


def rapid_side(path: Path) -> dict[str, object]:
    rows: dict[str, dict[str, object]] = {}
    for record in build_native_userassist_records(path):
        if record.artifact_type != "userassist-schema-entry":
            continue
        details = record.details
        key = _canon_name(details.get("display_path") or details.get("decoded_name"))
        rows[key] = {
            "ts": _canon_ts(details.get("timestamp")),
            "run_counter": details.get("run_counter"),
            "focus_count": details.get("focus_count"),
            "focus_ms": details.get("total_focus_time_ms"),
            "session_id": details.get("session_id"),
            "layout": details.get("layout"),
        }
    return {"rows": rows}


def trusted_side(path: Path) -> dict[str, object]:
    from regipy.plugins.ntuser.user_assist import UserAssistPlugin
    from regipy.registry import RegistryHive

    plugin = UserAssistPlugin(registry_hive=RegistryHive(str(path)))
    plugin.run()
    rows: dict[str, dict[str, object]] = {}
    for entry in plugin.entries:
        key = _canon_name(entry.get("name"))
        rows[key] = {
            "ts": _canon_ts(entry.get("timestamp")),
            "run_counter": entry.get("run_counter"),
            "focus_count": entry.get("focus_count"),
            "focus_ms": entry.get("total_focus_time_ms"),
            "session_id": entry.get("session_id"),
        }
    return {"rows": rows, "raw_count": len(plugin.entries)}


def hive_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ntuser", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    digest = hashlib.sha256(args.ntuser.read_bytes()).hexdigest()

    errors: list[str] = []
    try:
        rapid = rapid_side(args.ntuser)
    except Exception as exc:
        errors.append(f"rapid: {exc!r}"[:200])
        rapid = {"rows": {}}
    try:
        trusted = trusted_side(args.ntuser)
    except Exception as exc:
        errors.append(f"trusted: {exc!r}"[:200])
        trusted = {"rows": {}, "raw_count": 0}

    rapid_rows: dict[str, dict[str, object]] = rapid["rows"]
    trusted_rows: dict[str, dict[str, object]] = trusted["rows"]
    common = set(rapid_rows) & set(trusted_rows)

    field_mismatches: list[dict[str, object]] = []
    for key in sorted(common):
        rapid_row = rapid_rows[key]
        trusted_row = trusted_rows[key]
        diffs = {
            field: {"rapid": rapid_row.get(field), "trusted": trusted_row.get(field)}
            for field in ("ts", "run_counter", "focus_count", "focus_ms", "session_id")
            if rapid_row.get(field) != trusted_row.get(field)
        }
        if diffs and len(field_mismatches) < 25:
            field_mismatches.append({"name": key, "fields": diffs})
    matched = len(common) - len(field_mismatches) - sum(
        1 for m in field_mismatches if not m["fields"]
    )

    report = {
        "schema_version": "userassist-reference-diff-v1",
        "release_evidence_status": "engineering_check_only",
        "report_use_warning": (
            "RapidTriage native UserAssist decode vs regipy "
            "UserAssistPlugin. regipy's GUID list contains duplicates; "
            "its output is deduplicated by decoded name. Timestamps "
            "truncated to milliseconds."
        ),
        "ntuser": str(args.ntuser),
        "ntuser_sha256": digest,
        "trusted_rows_raw": trusted.get("raw_count", 0),
        "trusted_rows_deduped": len(trusted_rows),
        "rapid_schema_rows": len(rapid_rows),
        "common_names": len(common),
        "row_recall": round(len(common) / len(trusted_rows), 6) if trusted_rows else None,
        "row_precision": round(len(common) / len(rapid_rows), 6) if rapid_rows else None,
        "field_matched_rows": matched,
        "names_only_in_rapid_sample": sorted(set(rapid_rows) - set(trusted_rows))[:25],
        "names_only_in_trusted_sample": sorted(set(trusted_rows) - set(rapid_rows))[:25],
        "field_mismatch_sample": field_mismatches[:25],
        "timestamp_normalization": "utc millisecond truncation",
        "errors": errors,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(
            f"trusted_raw={trusted.get('raw_count', 0)} trusted_deduped={len(trusted_rows)} "
            f"rapid_rows={len(rapid_rows)} recall={report['row_recall']} "
            f"precision={report['row_precision']} field_matched={matched}"
        )
        print(f"-> {args.output}")
    return 0


# ---------------------------------------------------------------------------
# Export mode (T-207)
# ---------------------------------------------------------------------------

USERASSIST_ARTIFACT_TYPES = ("userassist-schema-entry",)
REF_NAME = ("programname", "decodedname", "name", "program", "path")
REF_COUNT = ("runcounter", "runcount", "count", "executioncount")
REF_TIME = ("lastexecuted", "lastrun", "lastruntime", "lastexecution", "lastexecutedutc", "timestamp")
REF_ACCOUNT = ("account", "user", "username", "profile", "usersid", "sid")
REF_HIVE = ("hivepath", "sourcefile", "hive", "source", "sourcepath")
_PROFILE_RE = re.compile(r"(?:^|/)(?:users|documents and settings)/([^/]+)/ntuser\.dat$")


def account_name(explicit: object, hive_path: object) -> str:
    """Explicit account, else the profile folder of ``.../Users/<name>/NTUSER.DAT``; ``""`` when unknown."""
    text = rd.normalize_text(explicit)
    if text:
        return text
    match = _PROFILE_RE.search(rd.normalize_path(hive_path))
    return match.group(1) if match else ""


def program_key(value: object) -> str:
    return rd.normalize_text(str(value or "").strip().strip('"').replace("/", "\\").rstrip("\\"))


def assist_row(account: str, names: list[object], count: int | None, last_run: object) -> rd.KeyedRow:
    canon = [key for key in dict.fromkeys(program_key(name) for name in names) if key]
    return rd.KeyedRow(
        keys=[f"{account}|{name}" for name in canon],
        fields={"run_count": count, "last_run": last_run},
        label={"account": account, "name": canon[0], "run_count": count, "last_run": last_run},
    )


def build_userassist_comparison(args: argparse.Namespace, warnings: list[str]) -> rd.Comparison:
    table, header = rd.read_table(args.reference)
    rd.require_columns(header, args.reference, name=REF_NAME)
    tool = "RECmd / Registry Explorer UserAssist (CSV)" if {"programname", "runcounter"} <= set(header) else "generic UserAssist CSV"
    reference: list[rd.KeyedRow] = []
    for line, row in enumerate(table, start=2):
        name = rd.pick(row, *REF_NAME)
        if not name:
            rd.add_warning(warnings, f"기준 {line}행에 프로그램 이름이 없어 건너뛰었습니다")
            continue
        stamp = rd.safe_timestamp(rd.pick(row, *REF_TIME), args.reference_tzinfo, warnings, f"기준 {line}행")
        account = account_name(rd.pick(row, *REF_ACCOUNT), rd.pick(row, *REF_HIVE))
        reference.append(assist_row(account, [name], rd.parse_int(rd.pick(row, *REF_COUNT)), stamp))
    ours: list[rd.KeyedRow] = []
    for row in rd.iter_rapid_rows(args.ours, USERASSIST_ARTIFACT_TYPES, warnings):
        names = [rd.rapid_field(row, name) for name in ("decoded_name", "executable_path", "display_path", "name")]
        if not any(names):
            continue
        account = account_name(
            rd.rapid_field(row, "account", "user", "user_name", "username"),
            rd.rapid_field(row, "source_path", "path"),
        )
        stamp = rd.safe_timestamp(rd.rapid_field(row, "timestamp", "last_run"), args.ours_tzinfo, warnings, "우리 UserAssist 행")
        count = rd.parse_int(rd.rapid_field(row, "run_counter", "run_count"))
        ours.append(assist_row(account, names, count, stamp))
    key_fields = ["account", "decoded_name"]
    if rd.drop_blank_key_part(ours, reference, 0):
        key_fields = ["decoded_name"]
        rd.add_warning(warnings, "한쪽에 계정 값이 없어 키에서 계정을 뺐습니다")
    return rd.Comparison(
        ours=ours,
        reference=reference,
        reference_tool=tool,
        key_fields=key_fields,
        compared_fields=["run_count", "last_run"],
    )


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if any(item == "--ntuser" or item.startswith("--ntuser=") for item in argv):
        return hive_main(argv)
    return rd.run_comparison_cli(
        argv,
        comparison="userassist",
        description="Diff RapidTriage userassist-schema-entry rows against a UserAssist parser CSV (key = account + name).",
        build=build_userassist_comparison,
    )


if __name__ == "__main__":
    raise SystemExit(main())
