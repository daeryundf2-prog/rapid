from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "r8-recovery-diff.py"
_spec = importlib.util.spec_from_file_location("r8_recovery_diff", SCRIPT)
assert _spec is not None and _spec.loader is not None
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


class MatchEntriesTest(unittest.TestCase):
    def test_full_recall_and_normalization(self) -> None:
        result = mod.match_entries(["/Users/A.txt", "/b/c.doc"], ["/del/x.bin"], ["users/a.TXT", "B/C.doc", "del/x.bin"])
        self.assertEqual(result["allocated_recall"], 1.0)
        self.assertEqual(result["deleted_recall"], 1.0)
        self.assertEqual(result["rapid_only"], 0)

    def test_missing_file_lowers_recall(self) -> None:
        result = mod.match_entries(["/a", "/b"], ["/d1", "/d2"], ["a", "d1", "extra"])
        self.assertEqual(result["ref_allocated"], 2)
        self.assertEqual(result["rapid_allocated_matched"], 1)
        self.assertEqual(result["allocated_recall"], 0.5)
        self.assertEqual(result["deleted_recall"], 0.5)
        self.assertEqual(result["rapid_only"], 1)

    def test_empty_reference_gives_null_rates(self) -> None:
        result = mod.match_entries([], [], ["x"])
        self.assertIsNone(result["allocated_recall"])
        self.assertIsNone(result["deleted_recall"])
        self.assertEqual(result["rapid_only"], 1)

    def test_deleted_entries_match_by_address(self) -> None:
        rapid = [
            mod.rapid_key("_deleted_mft/42-report.docx"),
            mod.rapid_key("_deleted/Users/7-a.txt"),
            mod.rapid_key("Users/a.txt"),
        ]
        result = mod.match_entries(["/Users/a.txt"], [mod.deleted_key(42), mod.deleted_key(9)], rapid)
        self.assertEqual(result["rapid_deleted_matched"], 1)
        self.assertEqual(result["deleted_recall"], 0.5)
        self.assertEqual(result["allocated_recall"], 1.0)

    def test_partition_keys_stay_within_their_partition(self) -> None:
        by_dir = {"p1": ["a"], "p2": ["b"]}
        self.assertEqual(mod.keys_for_partition(2048, by_dir, {2048: "p1", 9000: "p2"}, None), (["a"], "start-sector"))
        self.assertEqual(mod.keys_for_partition(77, by_dir, {2048: "p1"}, None), ([], "not-extracted"))
        flat = {"": ["x"]}
        self.assertEqual(mod.keys_for_partition(500, flat, {}, 500), (["x"], "selected-partition"))
        self.assertEqual(mod.keys_for_partition(600, flat, {}, 500), ([], "not-extracted"))
        self.assertEqual(mod.keys_for_partition(600, flat, {}, None), (["x"], "unmapped"))
        self.assertEqual(mod.partition_dir_of("_e01/fs/p3/Users/a.txt"), "p3")
        self.assertEqual(mod.partition_dir_of("_e01/fs/Users/a.txt"), "")

    def test_strip_run_prefix(self) -> None:
        self.assertEqual(mod.strip_run_prefix("_e01/fs/Users/a.txt"), "Users/a.txt")
        self.assertEqual(mod.strip_run_prefix("_e01\\filesystem\\Users\\a.txt"), "Users/a.txt")
        self.assertEqual(mod.strip_run_prefix("_e01/fs/p2/Users/a.txt"), "Users/a.txt")
        # Run outputs beside the extracted filesystem are not recovered files.
        self.assertEqual(mod.strip_run_prefix("rapidtriage-run-summary.json"), "")
        self.assertEqual(mod.strip_run_prefix("_e01/rapidtriage-e01-stage-status.json"), "")


if __name__ == "__main__":
    unittest.main()
