#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["python-evtx>=0.8.0"]
# ///
# --- How to run ---
#   uv run scripts/evtx-reference-diff.py --evtx-root <dir-of-evtx> --output <report.json> --json
#
# Diffs RapidTriage native EVTX collection against python-evtx (an
# independent BinXML decoder) on real .evtx logs. Compares per record:
# record identity (EventRecordID), timestamp, event_id, provider,
# channel, computer. Uses the in-repo build_evtx_trusted_tool_record_diff
# normalizer so results share the trusted-diff schema.
#
# Engineering measurement only; python-evtx is not in the recognized
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
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.artifacts.windows.eventlog import (
    build_evtx_trusted_tool_record_diff,
    collect_native_evtx_events,
)

MAX_FILES_DEFAULT = 25


def _canon_ts(value: str) -> str:
    # Serialize both sides to one format so the diff measures instant
    # agreement, not 'T'-vs-space export formatting. python-evtx converts
    # FILETIME via float(qword)*1e-7 which drifts ~1us at FILETIME
    # magnitude; RapidTriage truncates at //10. Truncate both sides to
    # milliseconds so the diff measures forensic-meaningful agreement;
    # sub-ms deltas are counted in timestamp_sub_ms_deltas for audit.
    text = str(value or "").replace(" ", "T", 1)
    if not text:
        return ""
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return text
    truncated = parsed.replace(microsecond=(parsed.microsecond // 1000) * 1000)
    return truncated.isoformat()


def _sub_ms_delta(a: str, b: str) -> bool:
    try:
        ta = datetime.fromisoformat(str(a).replace(" ", "T", 1))
        tb = datetime.fromisoformat(str(b).replace(" ", "T", 1))
    except ValueError:
        return False
    return ta != tb and abs((ta - tb).total_seconds()) < 0.001


def rapid_records(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for record in collect_native_evtx_events(path):
        details = record.details
        if details.get("evtx_record_offset") is None:
            continue  # chunk headers / unparsed candidates
        system = details.get("binxml_system_fields") or {}
        indicators = details.get("native_indicators") or {}
        precise = str(system.get("TimeCreated") or details.get("timestamp") or "")
        rows.append(
            {
                "record_id": str(details.get("record_id") or ""),
                "event_id": str(system.get("EventID") or details.get("event_id") or ""),
                "provider_name": str(
                    system.get("Provider") or details.get("ProviderName") or indicators.get("provider_name") or ""
                ),
                "channel": str(system.get("Channel") or details.get("channel") or ""),
                "computer": str(system.get("Computer") or details.get("Computer") or ""),
                "timestamp": _canon_ts(precise),
                "timestamp_precise": precise,
                "recovery_status": str(details.get("evtx_recovery_status") or ""),
            }
        )
    return rows


_XMLNS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def trusted_records(path: Path) -> list[dict[str, object]]:
    from Evtx.Evtx import Evtx

    rows: list[dict[str, object]] = []
    with Evtx(str(path)) as log:
        for record in log.records():
            try:
                xml_text = record.xml()
            except Exception:
                continue
            try:
                root = ET.fromstring(xml_text)
            except ET.ParseError:
                continue
            system = root.find(f"{_XMLNS}System")
            if system is None:
                system = root.find("System")
            if system is None:
                continue

            def _text(tag: str, _system=system) -> str:
                node = _system.find(f"{_XMLNS}{tag}")
                if node is None:
                    node = _system.find(tag)
                return (node.text or "") if node is not None else ""

            provider = system.find(f"{_XMLNS}Provider")
            if provider is None:
                provider = system.find("Provider")
            time_node = system.find(f"{_XMLNS}TimeCreated")
            if time_node is None:
                time_node = system.find("TimeCreated")
            precise = time_node.get("SystemTime", "") if time_node is not None else ""
            rows.append(
                {
                    "record_id": _text("EventRecordID"),
                    "event_id": _text("EventID"),
                    "provider_name": provider.get("Name", "") if provider is not None else "",
                    "channel": _text("Channel"),
                    "computer": _text("Computer"),
                    "timestamp": _canon_ts(precise),
                    "timestamp_precise": str(precise),
                }
            )
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evtx-root", required=True, type=Path)
    parser.add_argument("--max-files", type=int, default=MAX_FILES_DEFAULT)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    files = sorted(
        (p for p in args.evtx_root.rglob("*.evtx") if p.is_file() and p.stat().st_size > 0),
        key=lambda p: -p.stat().st_size,
    )[: args.max_files]

    per_file: list[dict[str, object]] = []
    totals = {
        "files": 0,
        "rapid_records": 0,
        "trusted_records": 0,
        "matched": 0,
        "mismatch": 0,
        "missing_in_trusted": 0,
        "extra_in_trusted": 0,
        "errors": [],
    }
    sub_ms_deltas = 0
    for path in files:
        try:
            rapid = rapid_records(path)
            trusted = trusted_records(path)
            rapid_ts = {str(r.get("record_id")): str(r.get("timestamp_precise") or "") for r in rapid}
            trusted_ts = {str(r.get("record_id")): str(r.get("timestamp_precise") or "") for r in trusted}
            for rid, ta in rapid_ts.items():
                tb = trusted_ts.get(rid)
                if tb is not None and _sub_ms_delta(ta, tb):
                    sub_ms_deltas += 1
            rapid_recovery = {
                str(r.get("record_id")): str(r.get("recovery_status") or "") for r in rapid
            }
            diff = build_evtx_trusted_tool_record_diff(rapid, trusted, trusted_tool="python-evtx")
        except Exception as exc:  # keep going; record the failure honestly
            totals["errors"].append({"file": str(path), "error": str(exc)[:200]})
            continue
        totals["files"] += 1
        totals["rapid_records"] += int(diff["rapid_record_count"])
        totals["trusted_records"] += int(diff["trusted_record_count"])
        totals["matched"] += int(diff["matched_count"])
        totals["mismatch"] += int(diff["mismatch_count"])
        totals["missing_in_trusted"] += int(diff["missing_in_trusted_count"])
        totals["extra_in_trusted"] += int(diff["extra_in_trusted_count"])
        field_diff_counts: dict[str, int] = {}
        for mismatch in diff["mismatches"]:
            for fd in mismatch.get("field_diffs", []):
                name = str(fd.get("field") or "?")
                field_diff_counts[name] = field_diff_counts.get(name, 0) + 1
        missing_status_counts: dict[str, int] = {}
        for key in diff["missing_in_trusted"]:
            status = rapid_recovery.get(str(key), "") or "unknown"
            missing_status_counts[status] = missing_status_counts.get(status, 0) + 1
        per_file.append(
            {
                "file": path.name,
                "rapid_records": diff["rapid_record_count"],
                "trusted_records": diff["trusted_record_count"],
                "matched": diff["matched_count"],
                "mismatch": diff["mismatch_count"],
                "missing_in_trusted": diff["missing_in_trusted_count"],
                "extra_in_trusted": diff["extra_in_trusted_count"],
                "status": diff["status"],
                "field_diff_counts": field_diff_counts,
                "missing_in_trusted_recovery_status": missing_status_counts,
                "sample_mismatches": diff["mismatches"][:3],
                "sample_missing_in_trusted": diff["missing_in_trusted"][:5],
                "sample_extra_in_trusted": diff["extra_in_trusted"][:5],
            }
        )

    compared = totals["matched"] + totals["mismatch"]
    field_totals: dict[str, int] = {}
    for item in per_file:
        for name, count in item["field_diff_counts"].items():
            field_totals[name] = field_totals.get(name, 0) + count
    capped_files = [item["file"] for item in per_file if item["rapid_records"] >= 10000]
    report = {
        "schema_version": "evtx-reference-diff-v1",
        "release_evidence_status": "engineering_check_only",
        "report_use_warning": (
            "RapidTriage native EVTX parse vs python-evtx (independent BinXML "
            "decoder) on real logs. python-evtx is not on the recognized "
            "trusted-tool list; results are engineering evidence only."
        ),
        "evtx_root": str(args.evtx_root),
        "evtx_root_sha256_dir_listing": _listing_hash(files),
        "totals": totals,
        "record_coverage": {
            "records_compared": compared,
            "rapid_records_missing_from_trusted": totals["missing_in_trusted"],
            "trusted_records_missed_by_rapid": totals["extra_in_trusted"],
            "record_set_agreement": (
                round(compared / (compared + totals["missing_in_trusted"] + totals["extra_in_trusted"]), 6)
                if compared + totals["missing_in_trusted"] + totals["extra_in_trusted"]
                else None
            ),
            "field_match_rate": round(totals["matched"] / compared, 6) if compared else None,
        },
        "timestamp_normalization": {
            "precision": "milliseconds",
            "timestamp_sub_ms_deltas": sub_ms_deltas,
            "note": (
                "Timestamps truncated to milliseconds on both sides before "
                "field comparison. python-evtx converts FILETIME via "
                "float(qword)*1e-7 which drifts ~1us at FILETIME magnitude; "
                "RapidTriage truncates at //10. Sub-millisecond divergences "
                "are counted here, not hidden."
            ),
        },
        "field_diff_sample_counts": field_totals,
        "field_diff_counts_note": (
            "Counts are aggregated over each file's first 100 mismatched "
            "records (the shared diff caps mismatch rows); they show which "
            "fields diverge, not full divergence frequency."
        ),
        "native_record_cap_observed": {
            "cap": 10000,
            "capped_files": capped_files,
            "note": "RapidTriage native EVTX collection caps at ~10000 records/file; record-set agreement is bounded by that cap.",
        },
        "per_file": per_file,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        t = totals
        print(
            f"files={t['files']} rapid={t['rapid_records']} trusted={t['trusted_records']} "
            f"matched={t['matched']} mismatch={t['mismatch']} "
            f"missing={t['missing_in_trusted']} extra={t['extra_in_trusted']}"
        )
        print(f"-> {args.output}")
    return 0


def _listing_hash(files: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in files:
        digest.update(path.name.encode("utf-8"))
        digest.update(str(path.stat().st_size).encode())
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
