"""T-205: scripts/usn-reference-diff.py export mode on synthetic inputs."""

from __future__ import annotations

import unittest
from pathlib import Path

from tests.reference_diff_helpers import ReferenceDiffCase, write_csv, write_jsonl

MFTECMD_HEADER = (
    "Name", "Extension", "EntryNumber", "SequenceNumber", "ParentEntryNumber", "ParentSequenceNumber",
    "ParentPath", "UpdateSequenceNumber", "UpdateTimestamp", "UpdateReasons", "FileAttributes",
    "OffsetToData", "SourceFile",
)
RECORDS = (
    # usn, name, entry, iso timestamp (ours), reasons (ours flags), reasons (MFTECmd)
    (1000, "report.docx", 41, "2026-03-02T01:02:03.456789+00:00", ["FILE_CREATE", "CLOSE"], "FileCreate|Close"),
    (1096, "report.docx", 41, "2026-03-02T01:05:00.100000+00:00", ["FILE_DELETE", "CLOSE"], "FileDelete|Close"),
    (1192, "새 문서.txt", 77, "2026-03-02T02:00:00+00:00", ["RENAME_NEW_NAME"], "RenameNewName"),
)


def our_row(usn: int, name: str, entry: int, stamp: str, flags: list[str]) -> dict[str, object]:
    return {
        "artifact_type": "usn-record",
        "path": "C:/case/$J",
        "details": {"usn": usn, "file_path": name, "timestamp": stamp, "reason_flags": flags,
                    "record_number": str(entry | (3 << 48))},
    }


def reference_row(usn: int, name: str, entry: int, stamp: str, reasons: str) -> list[object]:
    # MFTECmd writes "yyyy-MM-dd HH:mm:ss.fffffff" in UTC.
    text = stamp.replace("T", " ").split("+")[0]
    text = text + ("0" if "." in text else "")
    return [name, "", entry, 3, 5, 5, ".", usn, text, reasons, "Archive", 0, "$J"]


class UsnReferenceDiffTests(ReferenceDiffCase):
    script_name = "usn-reference-diff"

    def write_inputs(self, ours=RECORDS, reference=RECORDS) -> tuple[Path, Path]:
        ours_path = write_jsonl(self.tmp / "usn.jsonl", [our_row(*item[:5]) for item in ours])
        rows = [reference_row(item[0], item[1], item[2], item[3], item[5]) for item in reference]
        return ours_path, write_csv(self.tmp / "mftecmd-j.csv", MFTECMD_HEADER, rows)

    def test_full_match_recall_one(self) -> None:
        code, report, _ = self.run_diff(*self.write_inputs())
        self.assertEqual(code, 0)
        self.assert_contract(report)
        self.assertEqual(report["recall"], 1.0)
        self.assertEqual(report["matched"], 3)
        self.assertEqual(report["missing"], [])
        self.assertEqual(report["mismatched"], [])
        self.assertEqual(report["reference_tool"], "MFTECmd ($J CSV)")
        self.assertEqual(report["delete_rename"]["reference_records"], 2)

    def test_one_row_missing(self) -> None:
        code, report, _ = self.run_diff(*self.write_inputs(ours=RECORDS[:2]))
        self.assertEqual(code, 1)
        self.assertAlmostEqual(report["recall"], 2 / 3, places=5)
        self.assertEqual([item["key"] for item in report["missing"]], ["1192"])
        self.assertEqual(report["mismatched"], [])

    def test_extra_row_is_reported_without_lowering_recall(self) -> None:
        code, report, _ = self.run_diff(*self.write_inputs(reference=RECORDS[:2]))
        self.assertEqual(code, 0)
        self.assertEqual(report["recall"], 1.0)
        self.assertEqual([item["key"] for item in report["extra"]], ["1192"])

    def test_delete_time_mismatch_is_one_row(self) -> None:
        shifted = list(RECORDS)
        shifted[1] = (*RECORDS[1][:3], "2026-03-02T01:05:07+00:00", *RECORDS[1][4:])
        code, report, _ = self.run_diff(*self.write_inputs(ours=shifted))
        self.assertEqual(code, 1)
        self.assertEqual(report["recall"], 1.0)
        self.assertEqual(len(report["mismatched"]), 1)
        mismatch = report["mismatched"][0]
        self.assertEqual(mismatch["key"], "1096")
        self.assertEqual(mismatch["fields"]["timestamp"], {"ours": "2026-03-02T01:05:07Z", "reference": "2026-03-02T01:05:00Z"})
        self.assertEqual(report["delete_rename"]["timestamp_mismatched"], 1)

    def test_time_tolerance_and_reference_timezone(self) -> None:
        shifted = list(RECORDS)
        shifted[1] = (*RECORDS[1][:3], "2026-03-02T01:05:01+00:00", *RECORDS[1][4:])
        code, report, _ = self.run_diff(*self.write_inputs(ours=shifted), "--time-tolerance", "1")
        self.assertEqual((code, report["mismatched"]), (0, []))
        # The same instants exported as naive KST wall-clock times match with --reference-tz +09:00.
        ours_path, _ = self.write_inputs()
        kst = [
            [item[1], "", item[2], 3, 5, 5, ".", item[0], kst_text, item[5], "Archive", 0, "$J"]
            for item, kst_text in zip(RECORDS, ("2026-03-02 10:02:03", "2026-03-02 10:05:00", "2026-03-02 11:00:00"))
        ]
        reference = write_csv(self.tmp / "kst.csv", MFTECMD_HEADER, kst)
        code, report, _ = self.run_diff(ours_path, reference, "--reference-tz", "+09:00")
        self.assertEqual((code, report["mismatched"]), (0, []))
        code, report, _ = self.run_diff(ours_path, reference)
        self.assertEqual(len(report["mismatched"]), 3)

    def test_reason_and_name_mismatch_and_generic_pipe_csv(self) -> None:
        rows = [[item[0], item[3], item[1], item[5].replace("|", "+")] for item in RECORDS]
        rows[2][2] = "other.txt"
        reference = write_csv(self.tmp / "generic.csv", ("USN", "Timestamp", "FileName", "Reason"), rows, delimiter="|")
        ours_path, _ = self.write_inputs()
        code, report, _ = self.run_diff(ours_path, reference, "--reference-tool", "UsnTool 1.0")
        self.assertEqual(code, 1)
        self.assertEqual(report["reference_tool"], "UsnTool 1.0")
        self.assertEqual(report["field_mismatch_counts"], {"file_name": 1})

    def test_missing_input_exits_2(self) -> None:
        ours_path, _ = self.write_inputs()
        self.assert_missing_input_exit_2(ours_path)

    def test_reference_without_usn_column_exits_2(self) -> None:
        ours_path, _ = self.write_inputs()
        reference = write_csv(self.tmp / "bad.csv", ("Name", "When"), [["a", "b"]])
        code, _, stderr = self.run_diff(ours_path, reference)
        self.assertEqual(code, 2)
        self.assertIn("필요한 열이 없습니다", stderr)


if __name__ == "__main__":
    unittest.main()
