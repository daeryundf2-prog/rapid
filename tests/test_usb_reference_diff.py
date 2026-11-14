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

    def test_review_experiment_times_are_read_and_differ(self) -> None:
        # WB-12 review P1-3: these used to be skipped silently (recall 1.0, 0 mismatched, exit 0).
        serial, name = DEVICES[0][0], DEVICES[0][1]
        ours = [ours_row(serial, name, "2024-03-01T00:00:00+00:00", "2024-03-05T10:00:00+00:00")]
        code, report, _ = self._diff(ours, [(serial, name, "2023-01-01 오후 3:04:05", "05-Mar-2019 10:00:00")])
        self.assertEqual(code, 1)
        self.assertEqual(report["unparsed_time_count"], 0)
        self.assertEqual(report["field_mismatch_counts"], {"first_connected": 1, "last_connected": 1})

    def test_unreadable_reference_time_is_counted_and_not_clean(self) -> None:
        serial, name, first, last = DEVICES[0]
        code, report, _ = self._diff([ours_row(*DEVICES[0])], [(serial, name, "어제 오후쯤", last)])
        self.assertEqual(code, 1)
        self.assertEqual(report["status"], "unparsed-time")
        self.assertEqual(report["recall"], 1.0)
        self.assertEqual(report["mismatched"], [])
        self.assertEqual(report["unparsed_time_count"], 1)
        self.assertEqual(report["unparsed_time_fields"], {"reference": {"first_connected": 1}, "ours": {}})
        self.assertEqual(report["unparsed_time_uncompared"], 1)

    def test_ambiguous_slashed_date_warns_and_date_order_decides(self) -> None:
        serial, name = DEVICES[0][0], DEVICES[0][1]
        ours = [ours_row(serial, name, "2024-04-03T10:00:00+00:00", "2024-04-03T10:00:00+00:00")]
        reference = [(serial, name, "03/04/2024 10:00:00", "03/04/2024 10:00:00")]
        code, report, _ = self._diff(ours, reference)
        self.assertEqual(code, 1)  # read as 4 March (tool default mdy)
        self.assertEqual(report["ambiguous_date_count"], 2)
        self.assertEqual(report["settings"]["date_order_source"], "tool-default")
        self.assertTrue(any("--date-order" in item for item in report["warnings"]))
        code, report, _ = self._diff(ours, reference, "--date-order", "dmy")
        self.assertEqual((code, report["status"], report["ambiguous_date_count"]), (0, "clean", 0))
        self.assertEqual(report["settings"]["date_order"], "dmy")

    def test_empty_reference_exits_2(self) -> None:
        code, report, stderr = self._diff([ours_row(*d) for d in DEVICES], [])
        self.assertEqual(code, 2)
        self.assertIn("기준 행 0개 — 비교 불가", stderr)
        self.assertEqual((report["status"], report["recall"]), ("no-reference", None))
        self.assertEqual(report["inputs"]["reference"]["encoding"], "utf-8")

if __name__ == "__main__":
    unittest.main()
