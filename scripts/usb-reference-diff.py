#!/usr/bin/env python3
"""Compare RapidTriage USB devices with a registry parser's USB export (T-208).

    python scripts/usb-reference-diff.py --ours <run>/artifacts/<per-kind .json or JSONL> \\
        --reference <usb.csv> --output <report.json> --json

Key = device serial number (case-insensitive; a trailing ``&<n>`` instance
suffix is dropped on both sides). Compared: device name, first connected
(first install) and last connected (last arrival), UTC whole seconds.

Ours: ``windows-usb-device`` rows (``serial_number``, ``friendly_name``,
``first_install_at``, ``last_arrival_at``). Reference: CSV/TSV with
``SerialNumber`` + ``FriendlyName``/``DeviceName`` + ``FirstInstalled``/
``FirstConnected`` + ``LastConnected``/``LastArrival`` (Registry Explorer,
RECmd batch or a hand-run reg query; see the alias lists below). A device
seen under several control sets is compared once (the row with more values).

Shared loader/diff/report: rapidtriage/validation/reference_diff.py. The
report adds ``rows`` (one line per device with its status). Exit 0 clean,
1 differences, 2 input error.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.validation import reference_diff as rd

USB_ARTIFACT_TYPES = ("windows-usb-device",)
REF_SERIAL = ("serialnumber", "serial", "deviceserial")
REF_NAME = ("friendlyname", "devicename", "description")
REF_FIRST = ("firstinstalled", "firstinstalldate", "firstconnected", "firstinstallat")
REF_LAST = ("lastconnected", "lastarrival", "lastinsertion", "lastarrivalat")


def serial_key(value: object) -> str:
    return re.sub(r"&\d+$", "", rd.normalize_text(value))


def usb_row(serial: str, name: object, first: object, last: object) -> rd.KeyedRow:
    fields = {"device_name": rd.normalize_text(name), "first_connected": first, "last_connected": last}
    return rd.KeyedRow(keys=[serial], fields=fields, label={"serial": serial, **fields})


def build_usb_comparison(args: argparse.Namespace, warnings: list[str]) -> rd.Comparison:
    table, header = rd.read_table(args.reference)
    rd.require_columns(header, args.reference, serial=REF_SERIAL)
    reference: list[rd.KeyedRow] = []
    for line, row in enumerate(table, start=2):
        serial = serial_key(rd.pick(row, *REF_SERIAL))
        if not serial:
            rd.add_warning(warnings, f"기준 {line}행에 일련번호가 없어 건너뛰었습니다")
            continue
        context = f"기준 {line}행"
        reference.append(
            usb_row(
                serial,
                rd.pick(row, *REF_NAME),
                rd.safe_timestamp(rd.pick(row, *REF_FIRST), args.reference_tzinfo, warnings, context),
                rd.safe_timestamp(rd.pick(row, *REF_LAST), args.reference_tzinfo, warnings, context),
            )
        )
    ours: list[rd.KeyedRow] = []
    by_serial: dict[str, rd.KeyedRow] = {}
    for row in rd.iter_rapid_rows(args.ours, USB_ARTIFACT_TYPES, warnings):
        serial = serial_key(rd.rapid_field(row, "serial_number", "serial"))
        if not serial:
            continue
        context = "우리 USB 행"
        candidate = usb_row(
            serial,
            rd.rapid_field(row, "friendly_name", "device_name"),
            rd.safe_timestamp(rd.rapid_field(row, "first_install_at"), args.ours_tzinfo, warnings, context),
            rd.safe_timestamp(rd.rapid_field(row, "last_arrival_at"), args.ours_tzinfo, warnings, context),
        )
        kept = by_serial.get(serial)
        if kept is None:
            by_serial[serial] = candidate
            ours.append(candidate)
            continue
        # The same device under another control set: keep the row with more filled fields.
        rd.add_warning(warnings, "같은 일련번호가 여러 제어 집합에 있어 값이 더 많은 행 하나만 비교했습니다")
        if sum(bool(v) for v in candidate.fields.values()) > sum(bool(v) for v in kept.fields.values()):
            kept.fields, kept.label = candidate.fields, candidate.label
    return rd.Comparison(
        ours=ours,
        reference=reference,
        reference_tool="registry USB parser (CSV)",
        key_fields=["serial_number"],
        compared_fields=["device_name", "first_connected", "last_connected"],
        extra_sections=device_rows,
    )


def device_rows(result: rd.DiffResult) -> dict[str, object]:
    """One line per device (matched / mismatched / missing / extra), sorted by serial."""
    mismatched = {str(item["key"]) for item in result.mismatched}
    rows = [
        {"key": ref.keys[0], "status": "mismatched" if ref.keys[0] in mismatched else "matched"}
        for _mine, ref in result.matched_pairs
    ]
    rows += [{"key": item["key"], "status": "missing"} for item in result.missing]
    rows += [{"key": item["key"], "status": "extra"} for item in result.extra]
    return {"rows": sorted(rows, key=lambda item: str(item["key"]))}


def main(argv: list[str] | None = None) -> int:
    return rd.run_comparison_cli(
        argv,
        comparison="usb",
        description="Diff RapidTriage windows-usb-device rows against a registry USB parser CSV (key = serial).",
        build=build_usb_comparison,
    )


if __name__ == "__main__":
    raise SystemExit(main())
