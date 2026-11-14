"""scripts/shellbags-reference-diff.py on synthetic ShellBags rows (T-209)."""

from __future__ import annotations

import unittest

from tests.reference_diff_helpers import ReferenceDiffCase, write_csv, write_jsonl

HIVE = "D:/extract/C/Users/tester/AppData/Local/Microsoft/Windows/UsrClass.dat"
REF_HIVE = r"C:\Users\tester\AppData\Local\Microsoft\Windows\UsrClass.dat"
FOLDERS = [
    (r"My Computer\C:\Projects", "2024-04-01T01:00:00+00:00", "2024-03-30T05:00:00+00:00"),
    (r"My Computer\C:\Projects\Alpha", "2024-04-02T02:00:00+00:00", "2024-03-31T06:00:00+00:00"),
    (r"My Computer\D:\Exports", "2024-04-03T03:00:00+00:00", "2024-04-01T07:00:00+00:00"),
]
HEADER = ["AbsolutePath", "LastWriteTime", "CreatedOn", "SourceFile"]


def ours_row(path, last, created, *, root=False):
    return {
        "provider": "windows-shellbags",
        "artifact_type": "shellbag-entry",
        "path": HIVE,
        "supported": True,
        "details": {"shell_path": path, "bagmru_root": root, "user_sid": "S-1-5-21-1-2-3-1001", "source_path": HIVE,
                    "key_last_written_at": last, "item_created_at": created, "item_modified_at": "",
                    "item_accessed_at": ""},
    }


def ref_rows(folders=FOLDERS, hive=REF_HIVE):
    return [[path, last, created, hive] for path, last, created in folders]


class ShellbagsReferenceDiffTests(ReferenceDiffCase):
    script_name = "shellbags-reference-diff"

    def _diff(self, ours, reference, *extra, header=HEADER):
        return self.run_diff(
            write_jsonl(self.tmp / "ours.jsonl", ours), write_csv(self.tmp / "bags.csv", header, reference), *extra
        )

    def test_full_match(self) -> None:
        ours = [ours_row("", "2024-04-01T00:00:00+00:00", "", root=True)] + [ours_row(*f) for f in FOLDERS]
        code, report, _ = self._diff(ours, ref_rows())
        self.assertEqual(code, 0)
        self.assert_contract(report)
        self.assertEqual((report["recall"], report["matched"], report["missing"], report["mismatched"]), (1.0, 3, [], []))
        self.assertEqual(report["key_fields"], ["account", "folder_path"])

    def test_one_folder_missing(self) -> None:
        code, report, _ = self._diff([ours_row(*f) for f in FOLDERS[:2]], ref_rows())
        self.assertEqual(code, 1)
        self.assertAlmostEqual(report["recall"], 2 / 3, places=5)
        self.assertEqual([item["key"] for item in report["missing"]], ["tester|my computer/d:/exports"])

    def test_one_time_mismatch(self) -> None:
        reference = ref_rows()
        reference[0][1] = "2024-04-01 01:00:07"
        code, report, _ = self._diff([ours_row(*f) for f in FOLDERS], reference)
        self.assertEqual(code, 1)
        self.assertEqual(report["recall"], 1.0)
        self.assertEqual(len(report["mismatched"]), 1)
        self.assertEqual(report["mismatched"][0]["key"], "tester|my computer/c:/projects")
        self.assertEqual(report["mismatched"][0]["fields"], {
            "last_written": {"ours": "2024-04-01T01:00:00Z", "reference": "2024-04-01T01:00:07Z"}})

    def test_timezone_case_and_desktop_prefix_normalised(self) -> None:
        reference = [["Desktop\\" + FOLDERS[0][0].upper() + "\\", "2024-04-01 10:00:00", "2024-03-30 14:00:00", REF_HIVE]]
        code, report, _ = self._diff([ours_row(*f) for f in FOLDERS[:1]], reference, "--reference-tz", "+09:00")
        self.assertEqual(code, 0)
        self.assertEqual((report["recall"], report["mismatched"]), (1.0, []))

    def test_account_dropped_when_reference_has_none_and_ignore_account(self) -> None:
        code, report, _ = self._diff([ours_row(*f) for f in FOLDERS], ref_rows(hive=r"E:\export\UsrClass.dat"))
        self.assertEqual((code, report["recall"], report["key_fields"]), (0, 1.0, ["folder_path"]))
        other = ref_rows(hive=r"C:\Users\other\AppData\Local\Microsoft\Windows\UsrClass.dat")
        code, report, _ = self._diff([ours_row(*f) for f in FOLDERS], other)
        self.assertEqual((code, report["recall"]), (1, 0.0))
        code, report, _ = self._diff([ours_row(*f) for f in FOLDERS], other, "--ignore-account")
        self.assertEqual((code, report["recall"]), (0, 1.0))

    def test_missing_input_exits_2(self) -> None:
        self.assert_missing_input_exit_2(write_csv(self.tmp / "present.csv", HEADER, ref_rows()))


if __name__ == "__main__":
    unittest.main()
