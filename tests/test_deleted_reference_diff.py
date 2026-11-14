"""T-204: scripts/deleted-reference-diff.py on synthetic fls listings, truth CSVs and recovered files."""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from tests.reference_diff_helpers import ReferenceDiffCase, write_csv

TIMES = "2026-03-01 10:00:00 (KST)\t2026-03-01 10:00:00 (KST)\t2026-03-01 10:00:00 (KST)\t2026-03-01 10:00:00 (KST)"
TRUTH_HEADER = ("path", "inode", "recoverable", "sha256", "content_state", "size")
JPEG = b"\xff\xd8\xff\xe0" + bytes(range(256)) * 4
TEXT = "회의록 초안\n".encode() * 50
ZEROS = bytes(2048)


class DeletedReferenceDiffTests(ReferenceDiffCase):
    script_name = "deleted-reference-diff"

    def setUp(self) -> None:
        super().setUp()
        self.recovered = self.tmp / "recovered"
        self.recovered.mkdir()
        self.files = {
            "Users/kim/Pictures/IMG_0001.jpg": (101, JPEG),
            "Users/kim/Documents/회의록.txt": (102, TEXT),
            "Users/kim/Desktop/wiped.docx": (103, ZEROS),
        }
        for relative, (_, data) in self.files.items():
            (self.recovered / relative.replace("/", "_")).write_bytes(data)

    def files_output(self, names=None, *, allocated_too: bool = True, recoverable_zero: bool = False) -> Path:
        candidates = []
        for relative in names if names is not None else self.files:
            inode, data = self.files[relative]
            candidates.append(
                {
                    "path": f"D:/runs/r1/_e01/fs/{relative}",
                    "size": len(data),
                    "is_deleted": True,
                    "recovery": {
                        "candidate_kind": "deleted-entry",
                        "deletion_state": "deleted",
                        "mft_ref": inode,
                        "content_path": relative.replace("/", "_"),
                        **({"recoverable": True} if recoverable_zero and data == ZEROS else {}),
                    },
                }
            )
        if allocated_too:
            candidates.append({"path": "D:/runs/r1/_e01/fs/Windows/notepad.exe", "size": 10, "is_deleted": False, "recovery": {}})
        path = self.tmp / "rapidtriage-files.json"
        path.write_text(json.dumps({"summary": {}, "candidates": candidates, "inventory": candidates[:1]}), encoding="utf-8")
        return path

    def fls_listing(self, sizes: dict[str, int] | None = None) -> Path:
        lines = ["d/d 5:\tUsers", "r/r 900-128-1:\tWindows/notepad.exe", "d/d * 300:\tUsers/kim/OldFolder"]
        for relative, (inode, data) in self.files.items():
            size = (sizes or {}).get(relative, len(data))
            lines.append(f"r/r * {inode}-128-1:\t{relative}\t{TIMES}\t{size}\t0\t0")
        lines.append("r/r * 101-128-5:\tUsers/kim/Pictures/IMG_0001.jpg:Zone.Identifier")
        path = self.tmp / "fls-rdp.txt"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def truth_csv(self, overrides: dict[str, dict[str, object]] | None = None) -> Path:
        rows = []
        for relative, (inode, data) in self.files.items():
            row = {
                "path": "C:\\" + relative.replace("/", "\\"),
                "inode": inode,
                "recoverable": "false" if data == ZEROS else "true",
                "sha256": hashlib.sha256(data).hexdigest(),
                "content_state": {JPEG: "signature-valid", TEXT: "unclassified", ZEROS: "zero-filled"}[data],
                "size": len(data),
            }
            row.update((overrides or {}).get(relative, {}))
            rows.append([row[name] for name in TRUTH_HEADER])
        return write_csv(self.tmp / "truth.csv", TRUTH_HEADER, rows)

    def run_truth(self, ours: Path, truth: Path) -> tuple[int, dict[str, object], str]:
        return self.run_diff(ours, truth, "--strip-prefix", "_e01/fs", "--content-root", str(self.recovered))

    def test_truth_full_match_recall_one(self) -> None:
        code, report, _ = self.run_truth(self.files_output(), self.truth_csv())
        self.assertEqual(code, 0, report)
        self.assert_contract(report)
        self.assertEqual((report["recall"], report["matched"]), (1.0, 3))
        self.assertEqual((report["missing"], report["mismatched"], report["extra"]), ([], [], []))
        self.assertEqual(report["reference_tool"], "known-answer truth CSV")
        self.assertEqual(report["our_content_state_counts"], {"signature-valid": 1, "unclassified": 1, "zero-filled": 1})
        self.assertEqual(report["zero_filled_claimed_recoverable"], 0)

    def test_truth_one_row_missing(self) -> None:
        names = list(self.files)[:2]
        code, report, _ = self.run_truth(self.files_output(names), self.truth_csv())
        self.assertEqual(code, 1)
        self.assertAlmostEqual(report["recall"], 2 / 3, places=5)
        self.assertEqual([item["path"] for item in report["missing"]], ["users/kim/desktop/wiped.docx"])

    def test_truth_recoverable_hash_mismatch_is_one_row(self) -> None:
        jpeg = "Users/kim/Pictures/IMG_0001.jpg"
        code, report, _ = self.run_truth(self.files_output(), self.truth_csv({jpeg: {"sha256": "0" * 64}}))
        self.assertEqual(code, 1)
        self.assertEqual(report["recall"], 1.0)
        self.assertEqual(len(report["mismatched"]), 1)
        self.assertEqual(set(report["mismatched"][0]["fields"]), {"sha256"})

    def test_unrecoverable_hash_is_not_compared_but_content_state_is(self) -> None:
        wiped = "Users/kim/Desktop/wiped.docx"
        code, report, _ = self.run_truth(self.files_output(), self.truth_csv({wiped: {"sha256": "f" * 64}}))
        self.assertEqual((code, report["mismatched"]), (0, []))
        code, report, _ = self.run_truth(self.files_output(), self.truth_csv({wiped: {"content_state": "high-entropy"}}))
        self.assertEqual(report["field_mismatch_counts"], {"content_state": 1})
        self.assertEqual(report["mismatched"][0]["fields"]["content_state"], {"ours": "zero-filled", "reference": "high-entropy"})

    def test_zero_filled_claimed_recoverable_is_counted(self) -> None:
        code, report, _ = self.run_truth(self.files_output(recoverable_zero=True), self.truth_csv())
        self.assertEqual(code, 0)
        self.assertEqual(report["zero_filled_claimed_recoverable"], 1)
        self.assertEqual(report["zero_filled_claimed_recoverable_keys"], ["users/kim/desktop/wiped.docx"])

    def test_fls_listing_match_missing_and_size_mismatch(self) -> None:
        code, report, _ = self.run_diff(self.files_output(), self.fls_listing(), "--strip-prefix", "_e01/fs")
        self.assertEqual(code, 0, report)
        self.assertEqual(report["reference_tool"], "Sleuth Kit fls (-r -d -p)")
        self.assertEqual(report["reference_stats"]["directories_skipped"], 1)
        self.assertEqual(report["reference_stats"]["ads_skipped"], 1)
        self.assertEqual(report["reference_stats"]["allocated_skipped"], 2)
        code, report, _ = self.run_diff(self.files_output(list(self.files)[1:]), self.fls_listing(), "--strip-prefix", "_e01/fs")
        self.assertAlmostEqual(report["recall"], 2 / 3, places=5)
        code, report, _ = self.run_diff(
            self.files_output(), self.fls_listing({"Users/kim/Documents/회의록.txt": 1}), "--strip-prefix", "_e01/fs"
        )
        self.assertEqual((code, report["field_mismatch_counts"]), (1, {"size": 1}))

    def test_inode_alias_pairs_a_lossy_name(self) -> None:
        listing = self.tmp / "lossy.txt"
        listing.write_text("r/r * 102-128-1:\tUsers/kim/Documents/???.txt\n", encoding="utf-8")
        code, report, _ = self.run_diff(self.files_output(), listing, "--strip-prefix", "_e01/fs")
        self.assertEqual(report["recall"], 1.0)
        self.assertEqual(len(report["extra"]), 2)
        self.assertEqual(code, 0)

    def test_missing_input_exits_2(self) -> None:
        self.assert_missing_input_exit_2(self.files_output())


if __name__ == "__main__":
    unittest.main()
