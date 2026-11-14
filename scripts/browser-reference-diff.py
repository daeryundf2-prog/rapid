#!/usr/bin/env python3
"""Compare RapidTriage browser visits/downloads with a direct SQLite query (T-211).

    python scripts/browser-reference-diff.py --kind visit --ours <run>/artifacts/<per-kind .json or JSONL> \\
        --reference <visits.csv> --output <report.json> --json

The reference is the CSV of a query run directly against the browser
database, e.g. for Chromium ``History``::

    -- --kind visit
    SELECT urls.url, urls.title, visits.visit_time
      FROM visits JOIN urls ON urls.id = visits.url;
    -- --kind download
    SELECT target_path, tab_url, total_bytes, start_time, end_time FROM downloads;

Raw integers are read as WebKit (us since 1601, Chromium), PRTime (us since
1970, Firefox ``visit_date``), unix ms or unix s by magnitude; text goes
through the shared timestamp parser (naive text uses ``--reference-tz``).
All compare in UTC whole seconds.

visit:    key = URL + visit time; compared: title.
download: key = target path (case-insensitive) + start time;
          compared: URL, total bytes, end time.

Ours: ``browser-visit`` / ``browser-download`` rows. Shared loader/diff/report:
rapidtriage/validation/reference_diff.py. Exit 0 clean, 1 differences,
2 input error.
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.validation import reference_diff as rd

UNIX_EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
VISIT_TYPES = ("browser-visit",)
DOWNLOAD_TYPES = ("browser-download",)
REF_URL = ("url",)
REF_TITLE = ("title",)
REF_VISIT_TIME = ("visittime", "visitdate", "visitedon", "visitedat")
REF_TARGET = ("targetpath", "currentpath", "fullpath", "path")
REF_DL_URL = ("taburl", "url", "downloadurl", "sourceurl")
REF_BYTES = ("totalbytes", "size")
REF_START = ("starttime", "startedat")
REF_END = ("endtime", "endedat")


def browser_time(value: object, default_tz: dt.tzinfo, warnings: list[str], context: str) -> dt.datetime | None:
    """Raw WebKit/PRTime/unix ms/unix s integers by magnitude, else the shared text parser."""
    text = str(value if value is not None else "").strip()
    if text.isdigit():
        number = int(text)
        if number <= 0:
            return None
        if number >= 10**17:  # FILETIME (100 ns since 1601)
            return rd.parse_timestamp(number)
        if number >= 10**16:  # WebKit, us since 1601
            return rd.FILETIME_EPOCH + dt.timedelta(microseconds=number)
        if number >= 10**14:  # PRTime, us since 1970
            return UNIX_EPOCH + dt.timedelta(microseconds=number)
        if number >= 10**11:  # unix ms
            return UNIX_EPOCH + dt.timedelta(milliseconds=number)
        return UNIX_EPOCH + dt.timedelta(seconds=number)
    return rd.safe_timestamp(value, default_tz, warnings, context)


def keyed(head: str, stamp: dt.datetime | None, fields: dict[str, object]) -> rd.KeyedRow:
    key = f"{head}|{rd.format_timestamp(stamp)}"
    return rd.KeyedRow(keys=[key], fields=fields, label={"time": stamp, **fields})


def build_visits(args: argparse.Namespace, warnings: list[str]) -> tuple[list[rd.KeyedRow], list[rd.KeyedRow]]:
    table, header = rd.read_table(args.reference)
    rd.require_columns(header, args.reference, url=REF_URL, visit_time=REF_VISIT_TIME)
    reference = []
    for line, row in enumerate(table, start=2):
        url = rd.pick(row, *REF_URL)
        if not url:
            continue
        stamp = browser_time(rd.pick(row, *REF_VISIT_TIME), args.reference_tzinfo, warnings, f"기준 {line}행")
        reference.append(keyed(url, stamp, {"url": url, "title": rd.pick(row, *REF_TITLE)}))
    ours = []
    for row in rd.iter_rapid_rows(args.ours, VISIT_TYPES, warnings):
        url = str(rd.rapid_field(row, "url") or "").strip()
        if not url:
            continue
        raw = rd.rapid_field(row, "visit_time_raw", "timestamp")
        stamp = browser_time(raw, args.ours_tzinfo, warnings, "우리 방문 행")
        ours.append(keyed(url, stamp, {"url": url, "title": str(rd.rapid_field(row, "title") or "").strip()}))
    return ours, reference


def build_downloads(args: argparse.Namespace, warnings: list[str]) -> tuple[list[rd.KeyedRow], list[rd.KeyedRow]]:
    table, header = rd.read_table(args.reference)
    rd.require_columns(header, args.reference, target_path=REF_TARGET, start_time=REF_START)
    reference = []
    for line, row in enumerate(table, start=2):
        target = rd.normalize_text(rd.pick(row, *REF_TARGET).replace("\\", "/"))
        if not target:
            continue
        context = f"기준 {line}행"
        start = browser_time(rd.pick(row, *REF_START), args.reference_tzinfo, warnings, context)
        fields = {
            "url": rd.pick(row, *REF_DL_URL),
            "total_bytes": rd.parse_int(rd.pick(row, *REF_BYTES)),
            "ended": browser_time(rd.pick(row, *REF_END), args.reference_tzinfo, warnings, context),
        }
        reference.append(keyed(target, start, fields))
    ours = []
    for row in rd.iter_rapid_rows(args.ours, DOWNLOAD_TYPES, warnings):
        target = rd.normalize_text(str(rd.rapid_field(row, "target_path", "current_path") or "").replace("\\", "/"))
        if not target:
            continue
        start = browser_time(rd.rapid_field(row, "started_at", "timestamp"), args.ours_tzinfo, warnings, "우리 다운로드 행")
        fields = {
            "url": str(rd.rapid_field(row, "tab_url", "source_url", "url") or "").strip(),
            "total_bytes": rd.parse_int(rd.rapid_field(row, "total_bytes")),
            "ended": browser_time(rd.rapid_field(row, "ended_at"), args.ours_tzinfo, warnings, "우리 다운로드 행"),
        }
        ours.append(keyed(target, start, fields))
    return ours, reference


def build_browser_comparison(args: argparse.Namespace, warnings: list[str]) -> rd.Comparison:
    if args.kind == "visit":
        ours, reference = build_visits(args, warnings)
        return rd.Comparison(
            ours, reference, "sqlite3 direct query: visits (CSV)", ["url", "visit_time"], ["title"],
            extra_sections=lambda _result: {"kind": "visit"},
        )
    ours, reference = build_downloads(args, warnings)
    return rd.Comparison(
        ours, reference, "sqlite3 direct query: downloads (CSV)", ["target_path", "start_time"],
        ["url", "total_bytes", "ended"], extra_sections=lambda _result: {"kind": "download"},
    )


def main(argv: list[str] | None = None) -> int:
    return rd.run_comparison_cli(
        argv,
        comparison="browser",
        description="Diff RapidTriage browser-visit/browser-download rows against a direct SQLite query CSV.",
        build=build_browser_comparison,
        configure=lambda parser: parser.add_argument(
            "--kind", choices=("visit", "download"), default="visit", help="visit (default) or download"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
