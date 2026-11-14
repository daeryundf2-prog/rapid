"""scripts/usb-reference-diff.py on synthetic USB rows (T-208)."""

from __future__ import annotations

import unittest

from tests.reference_diff_helpers import ReferenceDiffCase, write_csv, write_jsonl

DEVICES = [
    ("AA00000000000001&0", "Example Flash USB Device", "2024-01-02T03:04:05+00:00", "2024-03-01T10:00:00+00:00"),
    ("BB00000000000002&0", "Sample Disk USB Device", "2024-01-05T08:00:00+00:00", "2024-03-02T11:30:00+00:00"),
    ("CC00000000000003&0", "Test Stick USB Device", "2024-02-01T09:15:00+00:00", "2024-03-03T12:45:30+00:00"),
]
HEADER = ["SerialNumber", "FriendlyName", "FirstInstalled", "LastConnected"]


def ours_row(serial, name, first, last, control_set="ControlSet001"):
    return {
        "provider": "windows-registry",
        "artifact_type": "windows-usb-device",
        "path": "C:/synthetic/SYSTEM",
        "supported": True,
        "details": {"serial_number": serial, "friendly_name": name, "first_install_at": first,
                    "last_arrival_at": last, "control_set": control_set},
    }


class UsbReferenceDiffTests(ReferenceDiffCase):
    script_name = "usb-reference-diff"

    def _diff(self, ours, reference, *extra, header=HEADER, delimiter=","):
        return self.run_diff(
            write_jsonl(self.tmp / "ours.jsonl", ours),
            write_csv(self.tmp / "usb.csv", header, reference, delimiter=delimiter),
            *extra,
        )

    def test_full_match_one_line_per_device(self) -> None:
        # The same device under a second control set collapses to one row (a warning says so).
        ours = [ours_row(*d) for d in DEVICES] + [ours_row(*DEVICES[0], control_set="ControlSet002")]
        code, report, _ = self._diff(ours, DEVICES)
        self.assertEqual(code, 0)
        self.assert_contract(report)
        self.assertEqual((report["recall"], report["matched"], report["missing"], report["mismatched"]), (1.0, 3, [], []))
        self.assertEqual(report["extra"], [])
        self.assertTrue(any("제어 집합" in warning for warning in report["warnings"]))
        self.assertEqual([row["status"] for row in report["rows"]], ["matched"] * 3)

    def test_one_device_missing(self) -> None:
        code, report, _ = self._diff([ours_row(*d) for d in DEVICES[:2]], DEVICES)
        self.assertEqual(code, 1)
        self.assertAlmostEqual(report["recall"], 2 / 3, places=5)
        self.assertEqual([item["key"] for item in report["missing"]], ["cc00000000000003"])
        self.assertEqual([row["status"] for row in report["rows"]], ["matched", "matched", "missing"])

    def test_last_connected_mismatch(self) -> None:
        reference = [list(d) for d in DEVICES]
        reference[1][3] = "2024-03-02T11:31:00Z"
        code, report, _ = self._diff([ours_row(*d) for d in DEVICES], reference)
        self.assertEqual(code, 1)
        self.assertEqual(report["recall"], 1.0)
        self.assertEqual(len(report["mismatched"]), 1)
        item = report["mismatched"][0]
        self.assertEqual(item["key"], "bb00000000000002")
        self.assertEqual(item["fields"], {"last_connected": {"ours": "2024-03-02T11:30:00Z",
                                                             "reference": "2024-03-02T11:31:00Z"}})
        self.assertEqual(report["field_mismatch_counts"], {"last_connected": 1})
        self.assertEqual(len(report["rows"]), 3)

    def test_extra_device_and_naive_kst_reference(self) -> None:
        header = ["Serial Number", "Device Name", "First Connected", "Last Connected"]
        reference = [["AA00000000000001", DEVICES[0][1], "2024-01-02 12:04:05", "2024-03-01 19:00:00"]]
        code, report, _ = self._diff([ours_row(*d) for d in DEVICES[:2]], reference, "--reference-tz", "+09:00",
                                     header=header, delimiter="\t")
        self.assertEqual(code, 0)
        self.assertEqual((report["recall"], report["mismatched"]), (1.0, []))
        self.assertEqual([item["key"] for item in report["extra"]], ["bb00000000000002"])

    def test_missing_input_exits_2(self) -> None:
        self.assert_missing_input_exit_2(write_csv(self.tmp / "present.csv", HEADER, DEVICES))


if __name__ == "__main__":
    unittest.main()
