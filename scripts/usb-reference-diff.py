#!/usr/bin/env python3
"""Compare RapidTriage USB devices with a registry parser's USB export (T-208).

    python scripts/usb-reference-diff.py --ours <records.jsonl> \\
        --reference <usb.csv> --output <report.json> --json

Key = device serial number (case-insensitive; a trailing ``&<n>`` instance
suffix is dropped on both sides). Compared: device name, first connected
(first install) and last connected (last arrival), all in UTC seconds.

Ours: ``windows-usb-device`` records (``serial_number``, ``friendly_name``,
``first_install_at``, ``last_arrival_at``). Reference: CSV/TSV with
``SerialNumber`` + ``FriendlyName``/``DeviceName`` + ``FirstInstalled``/
``FirstConnected`` + ``LastConnected``/``LastArrival`` (Registry Explorer,
RECmd batch or a hand-run reg query; see the alias lists below).

Report keys: recall, matched, missing, mismatched, reference_tool (+ extra,
counts, rows — one row per device). Exit 2 when an input is missing.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _wc5_helpers as H

OURS_TYPES = {"windows-usb-device"}
SERIAL_OURS = ("serial_number", "serial")
SERIAL_REF = ("SerialNumber", "Serial Number", "Serial", "serial_number", "Device Serial")


def _serial(value: object) -> str:
    text = str(value or "").strip().casefold()
    return re.sub(r"&\d+$", "", text)


def fields(naive_tz) -> list[H.FieldSpec]:
    def ts(value: object) -> str:
        return H.norm_ts(value, naive_tz)

    return [
        H.FieldSpec(
            "device_name",
            ("friendly_name", "device_name"),
            ("FriendlyName", "Friendly Name", "DeviceName", "Device Name", "Description", "friendly_name"),
            H.norm_text,
        ),
        H.FieldSpec(
            "first_connected",
            ("first_install_at", "first_connected_at"),
            ("FirstInstalled", "First Installed", "FirstInstallDate", "FirstConnected", "First Connected",
             "first_install_at"),
            ts,
        ),
        H.FieldSpec(
            "last_connected",
            ("last_arrival_at", "last_connected_at"),
            ("LastConnected", "Last Connected", "LastArrival", "Last Arrival", "LastInsertion", "last_arrival_at"),
            ts,
        ),
    ]


def compare(ours_rows, reference_rows, naive_tz) -> dict[str, object]:
    ours_rows = [row for row in ours_rows if str(row.get("artifact_type") or "") in OURS_TYPES]
    return H.diff_keyed(
        ours_rows,
        reference_rows,
        ours_key=lambda row: _serial(H.pick(row, SERIAL_OURS)),
        reference_key=lambda row: _serial(H.pick(row, SERIAL_REF)),
        fields=fields(naive_tz),
        include_rows=True,
    )


def main(argv: list[str] | None = None) -> int:
    parser = H.base_parser(__doc__.splitlines()[0], "registry-usb-parser-csv")

    def body() -> int:
        args = parser.parse_args(argv)
        H.require_inputs({"--ours": args.ours, "--reference": args.reference})
        naive_tz = H.parse_tz(args.reference_tz)
        result = compare(H.load_ours(args.ours), H.load_csv(args.reference), naive_tz)
        report = H.envelope("usb", args.reference_tool, {"ours": args.ours, "reference": args.reference}, result)
        return H.emit(report, args.output, args.json, H.summary_line(report))

    return H.run_cli(body)


if __name__ == "__main__":
    raise SystemExit(main())
