"""T-206: scripts/shimcache-reference-diff.py export mode on synthetic inputs."""

from __future__ import annotations

import unittest
from pathlib import Path

from tests.reference_diff_helpers import ReferenceDiffCase, write_csv, write_jsonl

PARSER_HEADER = ("ControlSet", "CacheEntryPosition", "Path", "LastModifiedTimeUTC", "Executed", "Duplicate", "SourceFile")
ENTRIES = (
    # control set, position, path, last modified (UTC)
    ("ControlSet001", 0, r"C:\Windows\System32\notepad.exe", "2025-11-01T08:00:00+00:00"),
    ("ControlSet001", 1, r"C:\Users\kim\Downloads\Setup.EXE", "2026-01-15T09:30:45.250000+00:00"),
    ("ControlSet001", 2, r"\??\D:\tools\run.bat", "2026-02-01T00:00:01+00:00"),
)


def our_row(control_set: str, order: int, path: str, stamp: str) -> dict[str, object]:
    return {
        "artifact_type": "shimcache-schema-entry",
        "details": {"control_set": control_set, "cache_order": order, "executable_path": path, "timestamp": stamp},
    }


def parser_row(control_set: str, order: int, path: str, stamp: str) -> list[object]:
    number = int(control_set[-3:])
    return [number, order, path.lower() if order == 1 else path, stamp.replace("T", " ").split("+")[0], "NA", "False", "SYSTEM"]


class ShimcacheReferenceDiffTests(ReferenceDiffCase):
    script_name = "shimcache-reference-diff"

    def write_inputs(self, ours=ENTRIES, reference=ENTRIES) -> tuple[Path, Path]:
        rows = [our_row(*item) for item in ours]
        # A string-pivot row of another type must be ignored.
        rows.append({"artifact_type": "shimcache-string-candidate", "details": {"cache_order": 9, "executable_path": "x.exe"}})
        ours_path = write_jsonl(self.tmp / "execution.jsonl", rows)
        return ours_path, write_csv(self.tmp / "appcompat.csv", PARSER_HEADER, [parser_row(*item) for item in reference])

    def test_full_match_recall_one(self) -> None:
        code, report, _ = self.run_diff(*self.write_inputs())
        self.assertEqual(code, 0)
        self.assert_contract(report)
        self.assertEqual((report["recall"], report["matched"]), (1.0, 3))
        self.assertEqual((report["missing"], report["mismatched"], report["extra"]), ([], [], []))
        self.assertEqual(report["reference_tool"], "AppCompatCacheParser (CSV)")
        self.assertEqual(report["key_fields"], ["control_set", "cache_order", "path"])

    def test_one_row_missing(self) -> None:
        code, report, _ = self.run_diff(*self.write_inputs(ours=ENTRIES[:2]))
        self.assertEqual(code, 1)
        self.assertAlmostEqual(report["recall"], 2 / 3, places=5)
        self.assertEqual(len(report["missing"]), 1)
        self.assertEqual(report["missing"][0]["cache_order"], 2)

    def test_time_mismatch_is_one_row(self) -> None:
        shifted = list(ENTRIES)
        shifted[0] = (*ENTRIES[0][:3], "2025-11-01T08:00:02+00:00")
        code, report, _ = self.run_diff(*self.write_inputs(ours=shifted))
        self.assertEqual(code, 1)
        self.assertEqual(report["recall"], 1.0)
        self.assertEqual(len(report["mismatched"]), 1)
        self.assertEqual(report["mismatched"][0]["fields"], {"last_modified": {"ours": "2025-11-01T08:00:02Z", "reference": "2025-11-01T08:00:00Z"}})
        code, report, _ = self.run_diff(*self.write_inputs(ours=shifted), "--time-tolerance", "2")
        self.assertEqual((code, report["mismatched"]), (0, []))

    def test_moved_position_pairs_by_path_and_reports_order(self) -> None:
        swapped = [ENTRIES[0], (ENTRIES[1][0], 2, *ENTRIES[1][2:]), (ENTRIES[2][0], 1, *ENTRIES[2][2:])]
        code, report, _ = self.run_diff(*self.write_inputs(ours=swapped))
        self.assertEqual(code, 1)
        self.assertEqual(report["recall"], 1.0)
        self.assertEqual(report["field_mismatch_counts"], {"cache_order": 2})

    def test_extra_row_and_reference_without_control_set(self) -> None:
        ours_path, _ = self.write_inputs(ours=(*ENTRIES, ("ControlSet001", 3, r"C:\extra.exe", "2026-03-01T00:00:00+00:00")))
        rows = [[order, path, stamp] for _, order, path, stamp in ENTRIES]
        reference = write_csv(self.tmp / "generic.tsv", ("Position", "Path", "Modified"), rows, delimiter="\t")
        code, report, _ = self.run_diff(ours_path, reference)
        self.assertEqual(code, 0)
        self.assertEqual(report["key_fields"], ["cache_order", "path"])
        self.assertEqual(report["reference_tool"], "generic ShimCache CSV")
        self.assertEqual([item["path"] for item in report["extra"]], [r"c:\extra.exe"])

    def test_missing_input_exits_2(self) -> None:
        ours_path, _ = self.write_inputs()
        self.assert_missing_input_exit_2(ours_path)


if __name__ == "__main__":
    unittest.main()
