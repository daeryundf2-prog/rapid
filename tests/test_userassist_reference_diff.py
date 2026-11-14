"""T-207: scripts/userassist-reference-diff.py export mode on synthetic inputs."""

from __future__ import annotations

import unittest
from pathlib import Path

from tests.reference_diff_helpers import ReferenceDiffCase, write_csv, write_jsonl

RECMD_HEADER = ("HivePath", "BatchKeyPath", "ProgramName", "RunCounter", "FocusCount", "FocusTime", "LastExecuted")
HIVE = r"C:\Users\kim\NTUSER.DAT"
ENTRIES = (
    # decoded name, resolved path, run count, last run (UTC)
    (r"{6D809377-6AF0-444B-8957-A3773F02200E}\HNC\Hwp.exe", r"C:\Program Files\HNC\Hwp.exe", 12, "2026-02-03T04:05:06+00:00"),
    (r"C:\Windows\System32\cmd.exe", r"C:\Windows\System32\cmd.exe", 3, "2026-02-04T10:00:00.900000+00:00"),
    ("Microsoft.Windows.Explorer", "", 40, ""),
)


def our_row(name: str, resolved: str, count: int, stamp: str, hive: str = HIVE) -> dict[str, object]:
    return {
        "artifact_type": "userassist-schema-entry",
        "path": hive,
        "details": {"decoded_name": name, "executable_path": resolved, "run_counter": count, "timestamp": stamp, "source_path": hive},
    }


def recmd_row(name: str, count: int, stamp: str, hive: str = HIVE) -> list[object]:
    return [hive, "Software\\...\\UserAssist", name, count, 1, "00:00:01", stamp.replace("T", " ").split("+")[0]]


class UserAssistReferenceDiffTests(ReferenceDiffCase):
    script_name = "userassist-reference-diff"

    def write_inputs(self, ours=ENTRIES, reference=None) -> tuple[Path, Path]:
        ours_path = write_jsonl(self.tmp / "userassist.jsonl", [our_row(*item) for item in ours])
        rows = reference if reference is not None else [recmd_row(item[0], item[2], item[3]) for item in ENTRIES]
        return ours_path, write_csv(self.tmp / "recmd-userassist.csv", RECMD_HEADER, rows)

    def test_full_match_recall_one(self) -> None:
        code, report, _ = self.run_diff(*self.write_inputs())
        self.assertEqual(code, 0)
        self.assert_contract(report)
        self.assertEqual((report["recall"], report["matched"]), (1.0, 3))
        self.assertEqual((report["missing"], report["mismatched"], report["extra"]), ([], [], []))
        self.assertEqual(report["key_fields"], ["account", "decoded_name"])
        self.assertEqual(report["reference_tool"], "RECmd / Registry Explorer UserAssist (CSV)")

    def test_one_row_missing(self) -> None:
        code, report, _ = self.run_diff(*self.write_inputs(ours=ENTRIES[1:]))
        self.assertEqual(code, 1)
        self.assertAlmostEqual(report["recall"], 2 / 3, places=5)
        self.assertEqual(report["missing"][0]["key"], "kim|" + ENTRIES[0][0].lower())

    def test_count_mismatch_is_one_row(self) -> None:
        changed = [ENTRIES[0], (*ENTRIES[1][:2], 4, ENTRIES[1][3]), ENTRIES[2]]
        code, report, _ = self.run_diff(*self.write_inputs(ours=changed))
        self.assertEqual(code, 1)
        self.assertEqual(report["recall"], 1.0)
        self.assertEqual(len(report["mismatched"]), 1)
        self.assertEqual(report["mismatched"][0]["fields"], {"run_count": {"ours": 4, "reference": 3}})

    def test_resolved_path_alias_and_local_time(self) -> None:
        # A tool that expands known-folder GUIDs and prints KST wall-clock times.
        rows = [
            recmd_row(ENTRIES[0][1], 12, "2026-02-03 13:05:06"),
            recmd_row(ENTRIES[1][0], 3, "2026-02-04 19:00:00"),
            recmd_row(ENTRIES[2][0], 40, ""),
        ]
        ours_path, reference = self.write_inputs(reference=rows)
        code, report, _ = self.run_diff(ours_path, reference, "--reference-tz", "+09:00")
        self.assertEqual((code, report["recall"], report["mismatched"]), (0, 1.0, []))
        code, report, _ = self.run_diff(ours_path, reference)
        self.assertEqual(report["field_mismatch_counts"], {"last_run": 2})

    def test_account_separates_users_and_leaves_key_when_absent(self) -> None:
        other = r"C:\Users\lee\NTUSER.DAT"
        ours_path = write_jsonl(
            self.tmp / "two-users.jsonl",
            [our_row(*ENTRIES[1]), our_row(*ENTRIES[1][:2], 9, ENTRIES[1][3], hive=other)],
        )
        reference = write_csv(self.tmp / "ref.csv", RECMD_HEADER, [recmd_row(ENTRIES[1][0], 9, ENTRIES[1][3], hive=other)])
        code, report, _ = self.run_diff(ours_path, reference)
        self.assertEqual((code, report["mismatched"]), (0, []))
        self.assertEqual([item["key"] for item in report["extra"]], ["kim|" + ENTRIES[1][0].lower()])
        generic = write_csv(self.tmp / "generic.csv", ("Name", "Count", "LastRun"), [[ENTRIES[2][0], 40, ""]])
        code, report, _ = self.run_diff(ours_path, generic)
        self.assertEqual(report["key_fields"], ["decoded_name"])
        self.assertEqual(report["recall"], 0.0)

    def test_missing_input_exits_2(self) -> None:
        ours_path, _ = self.write_inputs()
        self.assert_missing_input_exit_2(ours_path)


if __name__ == "__main__":
    unittest.main()
