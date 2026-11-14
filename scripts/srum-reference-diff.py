#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["dissect.esedb>=3.10"]
# ///
# --- How to run ---
#   uv run scripts/srum-reference-diff.py --srudb <SRUDB.dat> --output <report.json> --json
#   python scripts/srum-reference-diff.py --ours <records.jsonl> --reference <csv folder> --output <report.json> --json
#
# Mode 2 (T-210, --ours/--reference): compares RapidTriage SRUM and
# Windows Search JSONL records against a folder of per-table CSVs written
# by an ESE parser (SrumECmd, an ESE table dump, ...). One CSV per table;
# the table name comes from the file name (``<date>_SrumECmd_`` prefix and
# ``_Output`` suffix dropped; well-known SRUM table GUIDs are mapped to
# their names). Per table: row counts and the multiset of keys
# app id + timestamp (UTC seconds). Report keys: tables[].recall,
# missing_tables, reference_tool (+ recall, matched, missing, mismatched,
# extra_tables). Exit 2 when an input is missing. Needs no dissect.esedb.
#
# Mode 1 (--srudb):
# Compares RapidTriage's native ESE decode (ese_native.py: header,
# catalog, page/tag/node walk, fixed/variable/tagged record fields)
# against dissect.esedb's independent row decode on the same SRUDB.dat.
#
# Metrics: per-table row counts, canonical row-multiset equality
# (field-level agreement per decoded row), and SruDbIdMapTable
# IdIndex -> identity recall. Rows are compared as canonical JSON
# multisets because neither side exposes a stable cross-parser key.
#
# Engineering measurement only; dissect.esedb is not in the
# recognized trusted-tool list, so results stay
# engineering_check_only. A dirty-shutdown database without log
# replay may be missing tail rows on both sides.
# ------------------
from __future__ import annotations

import sys as _sys

if hasattr(_sys.stdout, "reconfigure"):
    _sys.stdout.reconfigure(encoding="utf-8")
if hasattr(_sys.stderr, "reconfigure"):
    _sys.stderr.reconfigure(encoding="utf-8")

import argparse
import datetime
import hashlib
import json
import re
import struct
import sys
from collections import Counter
from datetime import timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.artifacts.windows.ese_native import EseDatabase
from rapidtriage.artifacts.windows.srum_ese import decode_srudb_ese_catalog

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _wc5_helpers as H

MAX_COMPARE_ROWS_PER_TABLE = 250_000


def canon_value(value: object) -> object:
    if isinstance(value, (list, tuple)):
        return [canon_value(item) for item in value]
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        try:
            text = raw.decode("utf-16le").strip("\x00").strip()
            if text and all(ch.isprintable() or ch.isspace() for ch in text):
                return text
        except UnicodeDecodeError:
            pass
        return raw.hex()
    if isinstance(value, datetime.datetime):
        return value.isoformat()
    if isinstance(value, str):
        return value.rstrip("\x00")
    return value


def canon_datetime(value: object) -> object:
    """Normalize JET DateTime representations.

    RapidTriage decodes coltyp 8 to an ISO string; dissect.esedb returns
    the raw little-endian int64 of the OLE Automation double.
    """
    if isinstance(value, int):
        try:
            days = struct.unpack("<d", struct.pack("<q", value))[0]
            return (datetime.datetime(1899, 12, 30) + datetime.timedelta(days=days)).isoformat()
        except (OverflowError, ValueError, struct.error):
            return value
    return value


def canon_row(row: dict[str, object], column_names: list[str], datetime_columns: set[str]) -> str:
    return json.dumps(
        {
            name: canon_datetime(row.get(name)) if name in datetime_columns else canon_value(row.get(name))
            for name in column_names
        },
        sort_keys=True,
        default=str,
    )


def rapid_side(path: Path) -> dict[str, object]:
    blob = path.read_bytes()
    db = EseDatabase(blob)
    tables: dict[str, dict[str, object]] = {}
    idmap: dict[int, str] = {}
    for table in db.tables:
        column_names = [column.name for column in table.columns]
        datetime_columns = {column.name for column in table.columns if column.coltyp == 8}
        rows: Counter[str] = Counter()
        count = 0
        truncated = False
        for node, row, _markers in db.iter_table_rows(table):
            if count >= MAX_COMPARE_ROWS_PER_TABLE:
                truncated = True
                break
            rows[canon_row(row, column_names, datetime_columns)] += 1
            count += 1
            if table.name == "SruDbIdMapTable" and row.get("IdType") == 0:
                blob_value = row.get("IdBlob")
                if isinstance(blob_value, (bytes, bytearray)):
                    text = bytes(blob_value).decode("utf-16le", errors="ignore").strip("\x00").strip()
                    if text:
                        idmap[int(row.get("IdIndex") or 0)] = text
        tables[table.name] = {"rows": rows, "row_count": count, "truncated": truncated}
    return {
        "tables": tables,
        "idmap": idmap,
        "page_size": db.page_size,
        "page_count": db.page_count,
        "limitations": list(db.limitations),
        "errors": list(db.errors),
    }


def trusted_side(path: Path) -> dict[str, object]:
    from dissect.esedb import EseDB

    tables: dict[str, dict[str, object]] = {}
    idmap: dict[int, str] = {}
    table_errors: list[dict[str, str]] = []
    with path.open("rb") as handle:
        db = EseDB(handle)
        for table in db.tables():
            name = table.name
            column_names = list(table.column_names)
            datetime_columns = {
                column.name for column in table.columns if getattr(getattr(column, "type", None), "value", None) == 8
            }
            rows: Counter[str] = Counter()
            count = 0
            truncated = False
            try:
                for record in table.records():
                    if count >= MAX_COMPARE_ROWS_PER_TABLE:
                        truncated = True
                        break
                    row = {column: record.get(column) for column in column_names}
                    rows[canon_row(row, column_names, datetime_columns)] += 1
                    count += 1
                    if name == "SruDbIdMapTable" and record.get("IdType") == 0:
                        blob_value = record.get("IdBlob")
                        if isinstance(blob_value, bytes):
                            text = blob_value.decode("utf-16le", errors="ignore").strip("\x00").strip()
                            if text:
                                idmap[int(record.get("IdIndex") or 0)] = text
            except Exception as exc:
                table_errors.append({"name": name, "error": repr(exc)[:160]})
            tables[name] = {"rows": rows, "row_count": count, "truncated": truncated}
    return {"tables": tables, "idmap": idmap, "table_errors": table_errors}


def ese_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="RapidTriage native ESE decode vs dissect.esedb on one SRUDB.dat")
    parser.add_argument("--srudb", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    digest = hashlib.sha256(args.srudb.read_bytes()).hexdigest()

    errors: list[str] = []
    try:
        catalog = decode_srudb_ese_catalog(args.srudb)
        rapid = rapid_side(args.srudb)
    except Exception as exc:
        errors.append(f"rapid: {exc!r}"[:200])
        catalog, rapid = {}, {"tables": {}, "idmap": {}, "limitations": [], "errors": []}
    try:
        trusted = trusted_side(args.srudb)
    except Exception as exc:
        errors.append(f"trusted: {exc!r}"[:200])
        trusted = {"tables": {}, "idmap": {}, "table_errors": []}

    table_reports: list[dict[str, object]] = []
    matched_rows = 0
    trusted_total = 0
    rapid_total = 0
    for name in sorted(set(trusted["tables"]) | set(rapid["tables"])):
        trusted_entry = trusted["tables"].get(name) or {"rows": Counter(), "row_count": 0}
        rapid_entry = rapid["tables"].get(name) or {"rows": Counter(), "row_count": 0}
        trusted_rows: Counter[str] = trusted_entry["rows"]
        rapid_rows: Counter[str] = rapid_entry["rows"]
        shared = sum((trusted_rows & rapid_rows).values())
        only_trusted = sum((trusted_rows - rapid_rows).values())
        only_rapid = sum((rapid_rows - trusted_rows).values())
        matched_rows += shared
        trusted_total += sum(trusted_rows.values())
        rapid_total += sum(rapid_rows.values())
        table_reports.append(
            {
                "name": name,
                "trusted_rows": sum(trusted_rows.values()),
                "rapid_rows": sum(rapid_rows.values()),
                "matched_rows": shared,
                "only_trusted": only_trusted,
                "only_rapid": only_rapid,
                "truncated": bool(trusted_entry.get("truncated") or rapid_entry.get("truncated")),
            }
        )

    rapid_idmap = rapid["idmap"]
    trusted_idmap = trusted["idmap"]
    idmap_keys = set(trusted_idmap) | set(rapid_idmap)
    idmap_matched = sum(1 for key in idmap_keys if trusted_idmap.get(key) == rapid_idmap.get(key))
    idmap_only_trusted = sorted(key for key in idmap_keys if key in trusted_idmap and key not in rapid_idmap)[:50]
    idmap_only_rapid = sorted(key for key in idmap_keys if key in rapid_idmap and key not in trusted_idmap)[:50]

    report = {
        "schema_version": "srum-reference-diff-v2",
        "release_evidence_status": "engineering_check_only",
        "report_use_warning": (
            "RapidTriage native ESE decode vs dissect.esedb row decode. "
            "Neither side replays ESE transaction logs, so tail rows "
            "written after the last checkpoint may be absent on both sides. "
            "dissect.esedb is an engineering reference, not a recognized trusted tool."
        ),
        "srudb": str(args.srudb),
        "srudb_sha256": digest,
        "file_size": args.srudb.stat().st_size,
        "rapid_decode": {
            "catalog": catalog,
            "limitations": rapid.get("limitations") or [],
            "errors": rapid.get("errors") or [],
        },
        "trusted_table_errors": trusted.get("table_errors") or [],
        "tables": table_reports,
        "table_count_rapid": len(rapid["tables"]),
        "table_count_trusted": len(trusted["tables"]),
        "total_rows_trusted": trusted_total,
        "total_rows_rapid": rapid_total,
        "total_rows_matched": matched_rows,
        "row_field_agreement": round(matched_rows / trusted_total, 6) if trusted_total else None,
        "idmap": {
            "trusted_entries": len(trusted_idmap),
            "rapid_entries": len(rapid_idmap),
            "matched_entries": idmap_matched,
            "recall": round(idmap_matched / len(trusted_idmap), 6) if trusted_idmap else None,
            "precision": round(idmap_matched / len(rapid_idmap), 6) if rapid_idmap else None,
            "only_trusted_idindex_sample": idmap_only_trusted,
            "only_rapid_idindex_sample": idmap_only_rapid,
        },
        "errors": errors,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(
            f"tables={report['table_count_rapid']}/{report['table_count_trusted']} "
            f"rows={rapid_total}/{trusted_total} matched={matched_rows} "
            f"agreement={report['row_field_agreement']} "
            f"idmap_recall={report['idmap']['recall']}"
        )
        print(f"-> {args.output}")
    return 0


# --- mode 2: RapidTriage JSONL vs per-table reference CSV folder (T-210) -----

SRUM_TABLE_NAMES = {
    # Well-known SRUM extension table GUIDs -> canonical names.
    "973f5d5c1d904944be8e24b94231a174": "network_usage",
    "d10ca2fe6fcf4f6d848eb2e99266fa89": "app_resource_usage",
    "dd6636c489294683974e22c046a43763": "network_connectivity",
    "fee4e14f02a94550b5ce5fa2da202e37": "energy_usage",
    "fee4e14f02a94550b5ce5fa2da202e37lt": "energy_usage_long_term",
    "d10ca2fe6fcf4f6d848eb2e99266fa86": "push_notifications",
    "5c8cf1c772574f13b223970ef5939312": "app_timeline",
    "7acbbaa3d0294be49a7a0885927f1d8f": "vfu",
    # Tool / RapidTriage spellings -> canonical names.
    "networkusage": "network_usage",
    "networkusages": "network_usage",
    "networkdatausage": "network_usage",
    "srumnetworkusage": "network_usage",
    "appresourceuseinfo": "app_resource_usage",
    "appresourceusage": "app_resource_usage",
    "applicationresourceusage": "app_resource_usage",
    "srumappresourceusage": "app_resource_usage",
    "networkconnections": "network_connectivity",
    "networkconnectivity": "network_connectivity",
    "energyusage": "energy_usage",
    "energyusages": "energy_usage",
    "energyusagelongterm": "energy_usage_long_term",
    "energyusageslongterm": "energy_usage_long_term",
    "pushnotification": "push_notifications",
    "pushnotifications": "push_notifications",
    "apptimelineprovider": "app_timeline",
    "vfuprov": "vfu",
}
TABLE_OURS = ("table_name", "srum_table", "table", "source_table", "table_family")
APP_OURS = ("app_id", "executable_path", "app_name", "application", "item_path", "work_id")
APP_REF = (
    "ExeInfo", "Exe Info", "Application", "AppName", "App Name", "AppId", "App Id", "app_id",
    "System_ItemPathDisplay", "ItemPathDisplay", "WorkID", "Work Id",
)
TS_OURS = ("timestamp", "srum_timestamp", "time_stamp")
TS_REF = ("Timestamp", "TimeStamp", "Time Stamp", "timestamp", "System_DateModified", "DateModified")
SAMPLE_CAP = 50
# File/summary records, not table rows: never counted against a table.
NON_ROW_TYPES = {
    "srum-database-file",
    "srum-database-pivot",
    "srum-table-candidate",
    "windows-search-edb-file",
    "windows-search-db",
    "windows-search-edb-pivot",
}


def canon_table(name: object) -> str:
    """Canonical table id: file/table name without tool prefix, suffix and punctuation."""
    text = Path(str(name or "")).name
    text = re.sub(r"\.(csv|tsv)$", "", text, flags=re.IGNORECASE)
    text = re.sub(r"^\d+_srumecmd_", "", text, flags=re.IGNORECASE)
    text = re.sub(r"_output$", "", text, flags=re.IGNORECASE)
    token = re.sub(r"[^0-9a-z]", "", text.casefold())
    return SRUM_TABLE_NAMES.get(token, token)


def _row_key(row, app_aliases, ts_aliases, naive_tz, app_basename: bool) -> str:
    app = H.norm_path(H.pick(row, app_aliases))
    if app_basename:
        app = app.rsplit("\\", 1)[-1]
    return f"{app}|{H.norm_ts(H.pick(row, ts_aliases), naive_tz)}"


def load_reference_tables(folder: Path) -> dict[str, list[dict[str, str]]]:
    tables: dict[str, list[dict[str, str]]] = {}
    for path in sorted(folder.iterdir(), key=lambda item: item.name.casefold()):
        if path.is_file() and path.suffix.lower() in {".csv", ".tsv"}:
            tables.setdefault(canon_table(path.name), []).extend(H.load_csv(path))
    if not tables:
        raise H.InputError(f"--reference folder has no .csv/.tsv tables: {folder}")
    return tables


def compare_tables(ours_rows, reference_tables, naive_tz, *, app_basename: bool = False) -> dict[str, object]:
    ours_tables: dict[str, list] = {}
    unassigned = 0
    for row in ours_rows:
        if str(row.get("artifact_type") or "") in NON_ROW_TYPES:
            continue
        table = canon_table(H.pick(row, TABLE_OURS))
        if not table or table == "unknown":
            unassigned += 1
            continue
        ours_tables.setdefault(table, []).append(row)
    table_reports: list[dict[str, object]] = []
    missing: list[dict[str, str]] = []
    mismatched: list[dict[str, object]] = []
    matched_total = 0
    reference_total = 0
    for name in sorted(reference_tables):
        ref_keys = Counter(_row_key(r, APP_REF, TS_REF, naive_tz, app_basename) for r in reference_tables[name])
        ours_keys = Counter(
            _row_key(r, APP_OURS, TS_OURS, timezone.utc, app_basename) for r in ours_tables.get(name, [])
        )
        shared = sum((ref_keys & ours_keys).values())
        only_ref = ref_keys - ours_keys
        only_ours = ours_keys - ref_keys
        ref_rows = sum(ref_keys.values())
        ours_rows_n = sum(ours_keys.values())
        matched_total += shared
        reference_total += ref_rows
        table_reports.append(
            {
                "name": name,
                "present_in_ours": name in ours_tables,
                "reference_rows": ref_rows,
                "ours_rows": ours_rows_n,
                "matched": shared,
                "recall": round(shared / ref_rows, 6) if ref_rows else None,
                "missing_rows": sum(only_ref.values()),
                "extra_rows": sum(only_ours.values()),
                "missing_sample": sorted(only_ref)[:SAMPLE_CAP],
                "extra_sample": sorted(only_ours)[:SAMPLE_CAP],
            }
        )
        missing.extend({"table": name, "key": key} for key in sorted(only_ref.elements()))
        if ref_rows != ours_rows_n:
            mismatched.append({"table": name, "reference_rows": ref_rows, "ours_rows": ours_rows_n})
    return {
        "recall": round(matched_total / reference_total, 6) if reference_total else None,
        "matched": matched_total,
        "missing": missing[: H.LIST_CAP],
        "mismatched": mismatched,
        "missing_tables": sorted(name for name in reference_tables if name not in ours_tables),
        "extra_tables": sorted(name for name in ours_tables if name not in reference_tables),
        "tables": table_reports,
        "counts": {
            "reference_rows": reference_total,
            "ours_rows": sum(len(rows) for rows in ours_tables.values()),
            "matched": matched_total,
            "missing": reference_total - matched_total,
            "mismatched": len(mismatched),
            "ours_rows_without_table": unassigned,
        },
        "key": "app id + timestamp (UTC seconds)" + (", app file name only" if app_basename else ""),
    }


def export_main(argv: list[str] | None = None) -> int:
    parser = H.base_parser(
        "RapidTriage SRUM/Windows Search JSONL vs per-table ESE parser CSVs "
        "(--srudb <SRUDB.dat> runs the native-ESE vs dissect.esedb comparison instead)",
        "ese-parser-csv",
    )
    parser.add_argument(
        "--app-match",
        choices=("path", "basename"),
        default="path",
        help="compare the app id as a full path (default) or as its file name",
    )

    def body() -> int:
        args = parser.parse_args(argv)
        H.require_inputs({"--ours": args.ours, "--reference": args.reference}, directory=("--reference",))
        naive_tz = H.parse_tz(args.reference_tz)
        result = compare_tables(
            H.load_ours(args.ours),
            load_reference_tables(args.reference),
            naive_tz,
            app_basename=args.app_match == "basename",
        )
        report = H.envelope(
            "srum-windows-search", args.reference_tool, {"ours": args.ours, "reference": args.reference}, result
        )
        summary = (
            f"recall={report['recall']} tables={len(result['tables'])} "
            f"missing_tables={result['missing_tables']} reference_tool={report['reference_tool']}"
        )
        return H.emit(report, args.output, args.json, summary)

    return H.run_cli(body)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if any(arg == "--srudb" or arg.startswith("--srudb=") for arg in args):
        return ese_main(args)
    return export_main(args)


if __name__ == "__main__":
    raise SystemExit(main())
