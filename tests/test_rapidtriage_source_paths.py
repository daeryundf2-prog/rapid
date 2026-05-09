from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from rapidtriage.core.source_paths import (
    candidate_source_paths,
    resolve_source_path_in_roots,
    source_path_resolution_diagnostics,
)


class RapidTriageSourcePathTests(unittest.TestCase):
    def test_relative_source_path_resolves_inside_allowed_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "analysis"
            source = root / "Users" / "alice" / "NTUSER.DAT"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"registry")

            resolved = resolve_source_path_in_roots("Users/alice/NTUSER.DAT", [root])

            self.assertEqual(resolved, source.resolve())

    def test_windows_absolute_path_can_map_to_extracted_e01_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "e01-extract"
            source = root / "Users" / "alice" / "AppData" / "Local" / "Microsoft" / "Windows" / "UsrClass.dat"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"hive")

            candidates = candidate_source_paths(
                r"C:\Users\alice\AppData\Local\Microsoft\Windows\UsrClass.dat",
                [root],
            )
            resolved = resolve_source_path_in_roots(
                r"C:\Users\alice\AppData\Local\Microsoft\Windows\UsrClass.dat",
                [root],
            )

            self.assertIn(source.resolve(), candidates)
            self.assertEqual(resolved, source.resolve())

    def test_resolution_diagnostics_lists_tried_allowed_root_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "e01-extract"
            root.mkdir()

            diagnostics = source_path_resolution_diagnostics(
                r"C:\Users\alice\Missing\chatLogs.edb",
                [root],
            )

            self.assertEqual(diagnostics["profile_version"], "source-path-resolution-diagnostics-v1")
            self.assertEqual(diagnostics["status"], "unresolved")
            self.assertGreaterEqual(diagnostics["candidate_count"], 1)
            self.assertGreaterEqual(diagnostics["inside_allowed_root_count"], 1)
            self.assertTrue(any("Users/alice/Missing/chatLogs.edb" in row["path"] for row in diagnostics["candidates"]))
            self.assertFalse(any(row["is_file"] for row in diagnostics["candidates"]))


if __name__ == "__main__":
    unittest.main()
