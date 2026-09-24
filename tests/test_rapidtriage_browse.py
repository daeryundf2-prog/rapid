"""Contracts for the server-side evidence path picker (core/browse.py)."""

import tempfile
import unittest
from pathlib import Path

from rapidtriage.core.browse import BrowseError, browse_directory


class BrowseDirectoryTest(unittest.TestCase):
    def test_lists_directories_first_and_flags_evidence_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "export-folder").mkdir()
            (root / "case001.E01").write_bytes(b"x")
            (root / "notes.txt").write_bytes(b"x")
            result = browse_directory(str(root))
            kinds = [entry["kind"] for entry in result["entries"]]
            self.assertEqual(kinds[0], "directory")
            by_name = {entry["name"]: entry for entry in result["entries"]}
            self.assertTrue(by_name["case001.E01"]["evidence_candidate"])
            self.assertFalse(by_name["notes.txt"]["evidence_candidate"])
            self.assertEqual(result["path"], str(root.resolve()))

    def test_default_path_falls_back_to_home(self) -> None:
        result = browse_directory(None)
        self.assertEqual(result["path"], str(Path.home()))

    def test_hidden_entries_require_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".hidden").mkdir()
            (root / "visible").mkdir()
            names = {e["name"] for e in browse_directory(str(root))["entries"]}
            self.assertNotIn(".hidden", names)
            names_shown = {e["name"] for e in browse_directory(str(root), show_hidden=True)["entries"]}
            self.assertIn(".hidden", names_shown)

    def test_file_path_browses_its_parent_and_missing_paths_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            file_path = Path(tmp) / "file.txt"
            file_path.write_bytes(b"x")
            # Seeding the picker with a file path opens the containing folder.
            result = browse_directory(str(file_path))
            self.assertEqual(result["path"], str(Path(tmp).resolve()))
            with self.assertRaises(BrowseError):
                browse_directory(str(Path(tmp) / "missing"))

    def test_max_entries_truncates_and_discloses(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index in range(10):
                (root / f"dir-{index:02d}").mkdir()
            result = browse_directory(str(root), limit=5)
            self.assertTrue(result["truncated"])
            self.assertEqual(len(result["entries"]), 5)


if __name__ == "__main__":
    unittest.main()
