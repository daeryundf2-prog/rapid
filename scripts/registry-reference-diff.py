#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["regipy>=6.0.0"]
# ///
# --- How to run ---
#   uv run scripts/registry-reference-diff.py --hive-root <dir> --output <report.json> --json
#
# Diffs RapidTriage native registry-hive scanning against regipy on real
# hives. Compares per hive: base-block header fields, the decoded key
# path set, and (for common keys) value names + last-write timestamps.
#
# RapidTriage performs a BOUNDED scan (MAX_HIVE_CELL_SCAN_BYTES=16MiB,
# MAX_HIVE_CELL_RECORDS=500): coverage below 100% on large hives is the
# documented triage bound, reported as coverage not correctness.
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
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.artifacts.windows.registry import (
    MAX_HIVE_CELL_RECORDS,
    MAX_HIVE_CELL_SCAN_BYTES,
    collect_registry_hive,
)

HIVE_NAMES = {"NTUSER.DAT", "USRCLASS.DAT", "SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT", "COMPONENTS"}


def _canon_ts(value: object) -> str:
    if isinstance(value, int):
        # FILETIME (100ns ticks since 1601) — regipy header field.
        if value <= 0:
            return ""
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        parsed = epoch + timedelta(microseconds=value // 10)
        truncated = parsed.replace(microsecond=(parsed.microsecond // 1000) * 1000)
        return truncated.isoformat()
    text = str(value or "").replace(" ", "T", 1)
    if not text or text in ("None", "NoneType"):
        return ""
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return text
    truncated = parsed.replace(microsecond=(parsed.microsecond // 1000) * 1000)
    return truncated.isoformat()


def _canon_rapid_key(path: str) -> str:
    # Rapid emits "<HIVE_HINT>\<root key name>\A\B" — strip both the hive
    # hint prefix and the root key's own name so paths are root-relative.
    parts = [p for p in str(path or "").replace("/", "\\").split("\\") if p]
    if not parts:
        return ""
    if parts[0].upper() in {"HKEY_CURRENT_USER", "HKCU"}:
        parts = parts[1:]
    elif parts[0].upper() in {"HKEY_LOCAL_MACHINE", "HKLM"} and len(parts) > 1:
        parts = parts[2:]
    if parts:
        parts = parts[1:]  # root key name
    return "\\".join(parts).lower()


def _canon_ref_key(path: str) -> str:
    # regipy Subkey.path is already root-relative ("\A\B").
    return "\\".join(p for p in str(path or "").replace("/", "\\").split("\\") if p).lower()


def rapid_side(path: Path) -> dict[str, object]:
    keys: dict[str, dict[str, object]] = {}
    header: dict[str, object] = {}
    records = 0
    for record in collect_registry_hive(path):
        records += 1
        if record.artifact_type == "registry-hive":
            header = dict(record.details.get("native_header") or {})
        elif record.artifact_type == "registry-key-tree-node":
            details = record.details
            canon = _canon_rapid_key(str(details.get("key_path") or ""))
            keys[canon] = {
                "key_path": str(details.get("key_path") or ""),
                "last_written_at": _canon_ts(details.get("last_written_at")),
                "value_names": sorted(str(v) for v in (details.get("value_names") or []) if str(v)),
                "subkey_names": sorted(str(v) for v in (details.get("subkey_names") or []) if str(v)),
                "root_reachable": bool(details.get("root_reachable")),
                "allocation_status": str(details.get("allocation_status") or ""),
            }
    return {"header": header, "keys": keys, "record_count": records}


def trusted_side(path: Path) -> dict[str, object]:
    from regipy.registry import RegistryHive

    hive = RegistryHive(str(path))
    header = {
        "sequence_primary": getattr(hive.header, "primary_sequence_num", None),
        "sequence_secondary": getattr(hive.header, "secondary_sequence_num", None),
        "last_written_at": _canon_ts(getattr(hive.header, "last_modification_time", None)),
        "major_version": getattr(hive.header, "major_version", None),
        "minor_version": getattr(hive.header, "minor_version", None),
        "hbin_data_size": getattr(hive.header, "hive_bins_data_size", None),
        "embedded_name": getattr(hive.header, "file_name", None),
    }
    keys: dict[str, dict[str, object]] = {}
    for subkey in hive.recurse_subkeys(as_json=False):
        canon = _canon_ref_key(subkey.path)
        keys[canon] = {
            "key_path": subkey.path,
            "last_written_at": _canon_ts(subkey.timestamp),
            "value_names": sorted(
                str(v.name) for v in (subkey.values or []) if str(v.name)
            ),
        }
    return {"header": header, "keys": keys}


HEADER_COMPARE = (
    "sequence_primary",
    "sequence_secondary",
    "last_written_at",
    "major_version",
    "minor_version",
    "hbin_data_size",
)


def compare_hive(path: Path) -> dict[str, object]:
    rapid = rapid_side(path)
    trusted = trusted_side(path)

    header_diffs = []
    for field in HEADER_COMPARE:
        rv = rapid["header"].get(field)
        tv = trusted["header"].get(field)
        if field == "last_written_at":
            rv, tv = _canon_ts(rv), _canon_ts(tv)
        if rv is not None and tv is not None and rv != tv:
            header_diffs.append({"field": field, "rapid": rv, "trusted": tv})

    rapid_keys: dict = rapid["keys"]
    trusted_keys: dict = trusted["keys"]
    common = sorted(set(rapid_keys) & set(trusted_keys))
    value_name_match = 0
    value_name_consistent = 0  # rapid names ⊆ trusted (bounded scan may decode fewer)
    value_name_conflict = 0
    timestamp_match = 0
    diffs: list[dict[str, object]] = []
    for canon in common:
        rk = rapid_keys[canon]
        tk = trusted_keys[canon]
        rapid_names = set(rk["value_names"])
        trusted_names = set(tk["value_names"])
        if rk["value_names"] == tk["value_names"]:
            value_name_match += 1
            value_name_consistent += 1
        elif rapid_names <= trusted_names:
            value_name_consistent += 1
        else:
            value_name_conflict += 1
            if len(diffs) < 50:
                diffs.append(
                    {
                        "key": rk["key_path"],
                        "kind": "value-names-conflict",
                        "rapid": rk["value_names"][:10],
                        "trusted": tk["value_names"][:10],
                        "root_reachable": rk["root_reachable"],
                    }
                )
        if rk["last_written_at"] == tk["last_written_at"]:
            timestamp_match += 1
        elif len(diffs) < 50:
            diffs.append(
                {
                    "key": rk["key_path"],
                    "kind": "last-written-at",
                    "rapid": rk["last_written_at"],
                    "trusted": tk["last_written_at"],
                    "root_reachable": rk["root_reachable"],
                }
            )

    rapid_only = sorted(set(rapid_keys) - set(trusted_keys))
    # A bounded cell scan also surfaces stale/orphaned nk cells that a
    # live-tree walk skips; split them out instead of counting as false paths.
    rapid_only_reachable = [
        rapid_keys[c]["key_path"] for c in rapid_only if rapid_keys[c]["root_reachable"]
    ]
    rapid_only_stale = [
        rapid_keys[c]["key_path"] for c in rapid_only if not rapid_keys[c]["root_reachable"]
    ]

    ref_total = len(trusted_keys)
    return {
        "hive": path.name,
        "file_size": path.stat().st_size,
        "rapid_records": rapid["record_count"],
        "header_diffs": header_diffs,
        "rapid_keys": len(rapid_keys),
        "trusted_keys": ref_total,
        "common_keys": len(common),
        "key_coverage_vs_reference": round(len(common) / ref_total, 6) if ref_total else None,
        "rapid_only_keys_root_reachable": rapid_only_reachable[:50],
        "rapid_only_keys_stale_or_orphaned": rapid_only_stale[:50],
        "rapid_only_stale_count": len(rapid_only_stale),
        "trusted_only_keys_count": len(set(trusted_keys) - set(rapid_keys)),
        "common_key_value_name_exact_match": value_name_match,
        "common_key_value_name_consistent": value_name_consistent,
        "common_key_value_name_conflicts": value_name_conflict,
        "common_key_timestamp_match": timestamp_match,
        "sample_diffs": diffs,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hive-root", required=True, type=Path)
    parser.add_argument("--max-hives", type=int, default=20)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    hives = sorted(
        p
        for p in args.hive_root.rglob("*")
        if p.is_file() and p.name.upper() in HIVE_NAMES
    )[: args.max_hives]

    digest = hashlib.sha256()
    for hive in hives:
        digest.update(hive.name.encode("utf-8"))
        digest.update(str(hive.stat().st_size).encode())

    results: list[dict[str, object]] = []
    errors: list[dict[str, str]] = []
    for hive in hives:
        try:
            results.append(compare_hive(hive))
        except Exception as exc:  # reference or rapid failure — keep both visible
            errors.append({"hive": str(hive), "error": str(exc)[:200]})

    report = {
        "schema_version": "registry-reference-diff-v1",
        "release_evidence_status": "engineering_check_only",
        "report_use_warning": (
            "RapidTriage native hive scan vs regipy on real hives. regipy is "
            "not on the recognized trusted-tool list; results are engineering "
            "evidence only. RapidTriage scans at most "
            f"{MAX_HIVE_CELL_SCAN_BYTES} bytes / {MAX_HIVE_CELL_RECORDS} cells "
            "per hive, so key coverage below 100% is a documented bound."
        ),
        "hive_root": str(args.hive_root),
        "hive_root_sha256_dir_listing": digest.hexdigest(),
        "rapid_bounds": {
            "max_cell_scan_bytes": MAX_HIVE_CELL_SCAN_BYTES,
            "max_cell_records": MAX_HIVE_CELL_RECORDS,
        },
        "timestamp_normalization": "truncated-to-milliseconds",
        "hives_compared": len(results),
        "errors": errors,
        "results": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        for item in results:
            print(
                f"{item['hive']}: rapid_keys={item['rapid_keys']} trusted_keys={item['trusted_keys']} "
                f"common={item['common_keys']} coverage={item['key_coverage_vs_reference']} "
                f"vals_consistent={item['common_key_value_name_consistent']} "
                f"vals_conflict={item['common_key_value_name_conflicts']} "
                f"ts_match={item['common_key_timestamp_match']} "
                f"rapid_only_reachable={len(item['rapid_only_keys_root_reachable'])} "
                f"header_diffs={len(item['header_diffs'])}"
            )
        print(f"-> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
