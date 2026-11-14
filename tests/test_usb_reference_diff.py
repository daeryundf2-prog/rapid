"""scripts/usb-reference-diff.py on synthetic USB records (T-208)."""

from __future__ import annotations

import contextlib
import csv
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "usb-reference-diff.py"


def _load():
    spec = importlib.util.spec_from_file_location("rt_usb_reference_diff_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


usb = _load()

DEVICES = [
    ("AA00000000000001&0", "Example Flash USB Device", "2024-01-02T03:04:05+00:00", "2024-03-01T10:00:00+00:00"),
    ("BB00000000000002&0", "Sample Disk USB Device", "2024-01-05T08:00:00+00:00", "2024-03-02T11:30:00+00:00"),
    ("CC00000000000003&0", "Test Stick USB Device", "2024-02-01T09:15:00+00:00", "2024-03-03T12:45:30+00:00"),
]


def _ours_record(serial, name, first, last):
    return {
        "provider": "windows-registry",
        "artifact_type": "windows-usb-device",
        "path": "C:/synthetic/SYSTEM",
        "supported": True,
        "details": {
            "serial_number": serial,
            "friendly_name": name,
            "first_install_at": first,
            "last_arrival_at": last,
        },
    }


def _reference_row(serial, name, first, last):
    return {"SerialNumber": serial, "FriendlyName": name, "FirstInstalled": first, "LastConnected": last}


class UsbReferenceDiffTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write(self, ours, reference, *, delimiter=","):
        ours_path = self.root / "ours.jsonl"
        ours_path.write_text("".join(json.dumps(row) + "\n" for row in ours), encoding="utf-8")
        ref_path = self.root / "reference.csv"
        with ref_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(reference[0]), delimiter=delimiter)
            writer.writeheader()
            writer.writerows(reference)
        return ours_path, ref_path

    def _run(self, ours, reference, *extra, delimiter=","):
        ours_path, ref_path = self._write(ours, reference, delimiter=delimiter)
        out = self.root / "report.json"
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = usb.main(["--ours", str(ours_path), "--reference", str(ref_path), "--output", str(out), "--json",
                             *extra])
        self.assertEqual(code, 0)
        report = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(report, json.loads(stdout.getvalue()))
        return report

    def test_full_match(self) -> None:
        report = self._run([_ours_record(*d) for d in DEVICES], [_reference_row(*d) for d in DEVICES])
        self.assertEqual(report["recall"], 1.0)
        self.assertEqual(report["matched"], 3)
        self.assertEqual(report["missing"], [])
        self.assertEqual(report["mismatched"], [])
        self.assertEqual(len(report["rows"]), 3)
        for key in ("recall", "matched", "missing", "mismatched", "reference_tool"):
            self.assertIn(key, report)
        self.assertEqual(report["release_evidence_status"], "engineering_check_only")

    def test_one_device_missing(self) -> None:
        report = self._run([_ours_record(*d) for d in DEVICES[:2]], [_reference_row(*d) for d in DEVICES])
        self.assertAlmostEqual(report["recall"], 2 / 3, places=5)
        self.assertEqual(report["missing"], ["cc00000000000003"])
        self.assertEqual([row["status"] for row in report["rows"]], ["matched", "matched", "missing"])

    def test_last_connected_mismatch(self) -> None:
        reference = [_reference_row(*d) for d in DEVICES]
        reference[1]["LastConnected"] = "2024-03-02T11:31:00Z"
        report = self._run([_ours_record(*d) for d in DEVICES], reference)
        self.assertEqual(report["recall"], 1.0)
        self.assertEqual(len(report["mismatched"]), 1)
        item = report["mismatched"][0]
        self.assertEqual(item["key"], "bb00000000000002")
        self.assertEqual(set(item["fields"]), {"last_connected"})
        self.assertEqual(item["fields"]["last_connected"]["ours"], "2024-03-02T11:30:00Z")

    def test_extra_device_and_reference_timezone(self) -> None:
        # Reference in naive KST (+09:00) text and TSV, serial without instance suffix.
        reference = [
            {"Serial Number": serial.split("&")[0], "Device Name": name,
             "First Connected": "2024-01-02 12:04:05", "Last Connected": "2024-03-01 19:00:00"}
            for serial, name, _first, _last in DEVICES[:1]
        ]
        report = self._run([_ours_record(*d) for d in DEVICES[:2]], reference, "--reference-tz", "+09:00",
                           delimiter="\t")
        self.assertEqual(report["recall"], 1.0)
        self.assertEqual(report["mismatched"], [])
        self.assertEqual(report["extra"], ["bb00000000000002"])

    def test_missing_input_exits_2(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            code = usb.main(["--ours", str(self.root / "nope.jsonl"), "--reference", str(self.root / "nope.csv")])
        self.assertEqual(code, 2)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            usb.main(["--ours", str(self.root / "nope.jsonl")])
        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
