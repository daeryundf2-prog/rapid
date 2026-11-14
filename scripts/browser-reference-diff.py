#!/usr/bin/env python3
"""Compare RapidTriage browser visits/downloads with a direct SQLite query (T-211).

    python scripts/browser-reference-diff.py --kind visit --ours <records.jsonl> \\
        --reference <visits.csv> --output <report.json> --json

The reference is the CSV of a query run directly against the browser
database, e.g. for Chromium ``History``::

    -- --kind visit
    SELECT urls.url, urls.title, visits.visit_time
      FROM visits JOIN urls ON urls.id = visits.url;
    -- --kind download
    SELECT target_path, tab_url, total_bytes, start_time, end_time FROM downloads;

Raw WebKit (us since 1601), PRTime (us since 1970), unix ms/s and ISO text
are all normalised to UTC seconds; naive text uses ``--reference-tz``.

visit:    key = URL + visit time; compared: title.
download: key = target path (case-insensitive) + start time;
          compared: URL, total bytes, end time.

Ours: ``browser-visit`` / ``browser-download`` records. Report keys:
recall, matched, missing, mismatched, reference_tool (+ extra, counts).
Exit 2 when an input is missing.
"""

from __future__ import annotations

import sys
from datetime import timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _wc5_helpers as H

KINDS = {
    "visit": {"types": {"browser-visit"}, "tool": "sqlite3-direct-query-visits"},
    "download": {"types": {"browser-download"}, "tool": "sqlite3-direct-query-downloads"},
}
URL_OURS = ("url",)
URL_REF = ("url", "URL")
VISIT_TS_OURS = ("visit_time_raw", "timestamp")
VISIT_TS_REF = ("visit_time", "visit_date", "VisitTime", "Visit Time", "Visited On", "visited_at")
TARGET_OURS = ("target_path", "current_path")
TARGET_REF = ("target_path", "Target Path", "current_path", "Full Path", "Path")
START_OURS = ("started_at", "timestamp")
START_REF = ("start_time", "Start Time", "started_at", "StartTime")


def _url(value: object) -> str:
    return str(value or "").strip()


def _key(url_or_path, ts_aliases, naive_tz, *, path: bool):
    def key(row) -> str:
        head = H.norm_path(H.pick(row, url_or_path)) if path else _url(H.pick(row, url_or_path))
        if not head:
            return ""
        return f"{head}|{H.norm_ts(H.pick(row, ts_aliases), naive_tz)}"

    return key


def compare(kind: str, ours_rows, reference_rows, naive_tz) -> dict[str, object]:
    def ts(value: object) -> str:
        return H.norm_ts(value, naive_tz)

    ours_rows = [row for row in ours_rows if str(row.get("artifact_type") or "") in KINDS[kind]["types"]]
    if kind == "visit":
        return H.diff_keyed(
            ours_rows,
            reference_rows,
            ours_key=_key(URL_OURS, VISIT_TS_OURS, timezone.utc, path=False),
            reference_key=_key(URL_REF, VISIT_TS_REF, naive_tz, path=False),
            fields=[H.FieldSpec("title", ("title",), ("title", "Title"), lambda v: str(v or "").strip())],
        )
    return H.diff_keyed(
        ours_rows,
        reference_rows,
        ours_key=_key(TARGET_OURS, START_OURS, timezone.utc, path=True),
        reference_key=_key(TARGET_REF, START_REF, naive_tz, path=True),
        fields=[
            H.FieldSpec("url", ("tab_url", "source_url", "url"), ("tab_url", "url", "URL", "Download URL"), _url),
            H.FieldSpec("total_bytes", ("total_bytes",), ("total_bytes", "Total Bytes", "Size"), H.norm_int),
            H.FieldSpec("ended", ("ended_at",), ("end_time", "End Time", "ended_at", "EndTime"), ts),
        ],
    )


def main(argv: list[str] | None = None) -> int:
    parser = H.base_parser(__doc__.splitlines()[0], "")
    parser.add_argument("--kind", choices=sorted(KINDS), default="visit", help="visit (default) or download")

    def body() -> int:
        args = parser.parse_args(argv)
        H.require_inputs({"--ours": args.ours, "--reference": args.reference})
        naive_tz = H.parse_tz(args.reference_tz)
        result = compare(args.kind, H.load_ours(args.ours), H.load_csv(args.reference), naive_tz)
        tool = args.reference_tool or KINDS[args.kind]["tool"]
        report = H.envelope(
            f"browser-{args.kind}", tool, {"ours": args.ours, "reference": args.reference}, result
        )
        return H.emit(report, args.output, args.json, H.summary_line(report))

    return H.run_cli(body)


if __name__ == "__main__":
    raise SystemExit(main())
