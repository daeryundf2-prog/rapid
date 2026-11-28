"""Contracts for the server-side evidence path picker (core/browse.py)."""

import os
import tempfile
import unittest
from pathlib import Path

from rapidtriage.core.browse import BrowseError, browse_directory, foreign_path_message, list_roots


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

    def test_roots_are_returned_so_windows_picker_can_switch_drives(self) -> None:
        # On Windows the picker must expose drive letters — a drive root has
        # no parent so the up button alone can never reach another volume.
        roots = list_roots()
        self.assertTrue(roots)
        with tempfile.TemporaryDirectory() as tmp:
            result = browse_directory(tmp)
            self.assertEqual(result["roots"], roots)

    def test_max_entries_truncates_and_discloses(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index in range(10):
                (root / f"dir-{index:02d}").mkdir()
            result = browse_directory(str(root), limit=5)
            self.assertTrue(result["truncated"])
            self.assertEqual(len(result["entries"]), 5)

    def test_windows_path_on_a_posix_server_says_whose_filesystem_it_is(self) -> None:
        # A remote Windows analyst pastes a drive path into the picker; the POSIX host would
        # otherwise join it to the server's home and report a nonsense "경로가 없습니다".
        if os.sep != "/":
            self.skipTest("POSIX-only message")
        with self.assertRaises(BrowseError) as caught:
            browse_directory("D:\\evidence\\case001")
        message = str(caught.exception)
        self.assertIn("윈도우 경로입니다", message)
        self.assertIn("분석 서버", message)
        self.assertIsNone(foreign_path_message("/Users/analyst/evidence"))
        self.assertIsNone(foreign_path_message(""))

    def test_posix_server_also_catches_quoted_and_drive_relative_pastes(self) -> None:
        # Explorer's "경로로 복사" wraps the path in quotes; "D:data" is drive-relative.
        if os.sep != "/":
            self.skipTest("POSIX-only message")
        for pasted in ('"D:\\evidence\\case001"', "D:evidence", "D:/evidence", "\\\\nas\\share\\case"):
            self.assertIsNotNone(foreign_path_message(pasted), pasted)

    def test_posix_paths_and_relative_names_are_left_alone(self) -> None:
        if os.sep != "/":
            self.skipTest("POSIX-only message")
        for ok in ("/mnt/c/evidence", "~/evidence", "evidence/case001", "C-drive-copy", ""):
            self.assertIsNone(foreign_path_message(ok), ok)


if __name__ == "__main__":
    unittest.main()
