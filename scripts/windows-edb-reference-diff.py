#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["dissect.esedb>=3.10"]
# ///
# --- How to run ---
#   uv run scripts/windows-edb-reference-diff.py --edb <Windows.edb> --output <report.json> --json
#
# Compares RapidTriage's native ESE decode (ese_native.py: header,
# catalog, page/tag/node walk, fixed/variable/tagged record fields)
# against dissect.esedb's independent row decode on the same
# Windows.edb search index.
#
# Metrics: per-table row counts and canonical row-multiset equality
# (field-level agreement per decoded row). Rows are compared as
# canonical JSON multisets because neither side exposes a stable
# cross-parser key.
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
import struct
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.artifacts.windows.ese_native import EseDatabase

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
        tables[table.name] = {"rows": rows, "row_count": count, "truncated": truncated}
    return {
        "tables": tables,
        "page_size": db.page_size,
        "page_count": db.page_count,
        "limitations": list(db.limitations),
        "errors": list(db.errors),
    }


def trusted_side(path: Path) -> dict[str, object]:
    from dissect.esedb import EseDB

    tables: dict[str, dict[str, object]] = {}
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
            except Exception as exc:
                table_errors.append({"name": name, "error": repr(exc)[:160]})
            tables[name] = {"rows": rows, "row_count": count, "truncated": truncated}
    return {"tables": tables, "table_errors": table_errors}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--edb", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    digest = hashlib.sha256()
    with args.edb.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 << 20), b""):
            digest.update(chunk)

    errors: list[str] = []
    try:
        rapid = rapid_side(args.edb)
    except Exception as exc:
        errors.append(f"rapid: {exc!r}"[:200])
        rapid = {"tables": {}, "limitations": [], "errors": []}
    try:
        trusted = trusted_side(args.edb)
    except Exception as exc:
        errors.append(f"trusted: {exc!r}"[:200])
        trusted = {"tables": {}, "table_errors": []}

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

    report = {
        "schema_version": "windows-edb-reference-diff-v1",
        "release_evidence_status": "engineering_check_only",
        "report_use_warning": (
            "RapidTriage native ESE decode vs dissect.esedb row decode. "
            "Neither side replays ESE transaction logs, so tail rows "
            "written after the last checkpoint may be absent on both sides. "
            "dissect.esedb is an engineering reference, not a recognized trusted tool."
        ),
        "edb": str(args.edb),
        "edb_sha256": digest.hexdigest(),
        "file_size": args.edb.stat().st_size,
        "rapid_decode": {
            "limitations": rapid.get("limitations") or [],
            "errors": rapid.get("errors") or [],
            "page_size": rapid.get("page_size"),
            "page_count": rapid.get("page_count"),
        },
        "trusted_table_errors": trusted.get("table_errors") or [],
        "tables": table_reports,
        "table_count_rapid": len(rapid["tables"]),
        "table_count_trusted": len(trusted["tables"]),
        "total_rows_trusted": trusted_total,
        "total_rows_rapid": rapid_total,
        "total_rows_matched": matched_rows,
        "row_field_agreement": round(matched_rows / trusted_total, 6) if trusted_total else None,
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
            f"agreement={report['row_field_agreement']}"
        )
        print(f"-> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
