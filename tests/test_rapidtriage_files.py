from __future__ import annotations

import json
import os
import tempfile
import unittest
import zipfile
from datetime import datetime
from pathlib import Path

from rapidtriage.cli import main


def candidate_categories(candidate: dict[str, object]) -> list[str]:
    if "categories" in candidate:
        return list(candidate["categories"])
    category = candidate.get("category")
    return [category] if category else []


class RapidTriageFilesTests(unittest.TestCase):
    def test_files_command_scans_default_categories_and_writes_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "notes.txt").write_text("incident notes", encoding="utf-8")
            with zipfile.ZipFile(root / "bundle.zip", "w") as archive:
                archive.writestr("evidence.txt", "archive payload")
            (root / "records.sqlite").write_text("SQLite format 3", encoding="utf-8")
            (root / "tool.exe").write_bytes(b"MZ\x90\x00")
            (root / "photo.jpg").write_bytes(b"\xff\xd8\xff")
            output = root / "files.json"

            exit_code = main(["files", str(root), "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["command"], "files")
            self.assertEqual(Path(payload["root"]), root.resolve())
            self.assertEqual(payload["summary"]["candidate_count"], 4)
            category_counts = payload["summary"]["category_counts"]
            self.assertGreaterEqual(category_counts["documents"], 1)
            self.assertGreaterEqual(category_counts["archives"], 1)
            self.assertGreaterEqual(category_counts["databases"], 1)
            self.assertGreaterEqual(category_counts["executables"], 1)

            candidates = {Path(item["path"]).name: item for item in payload["candidates"]}
            self.assertEqual(set(candidates), {"notes.txt", "bundle.zip", "records.sqlite", "tool.exe"})
            self.assertIn("documents", candidate_categories(candidates["notes.txt"]))
            self.assertIn("archives", candidate_categories(candidates["bundle.zip"]))
            self.assertIn("databases", candidate_categories(candidates["records.sqlite"]))
            self.assertIn("executables", candidate_categories(candidates["tool.exe"]))

            for name, candidate in candidates.items():
                self.assertEqual(candidate["name"], name)
                self.assertTrue(candidate["path"].startswith(str(root.resolve())))
                self.assertIn("modified_at", candidate)
                self.assertIn("size", candidate)
                self.assertIn("extension", candidate)

    def test_files_command_records_nested_paths_and_mtime(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            nested = root / "Users" / "alice" / "Desktop"
            nested.mkdir(parents=True)
            candidate_path = nested / "report.docx"
            candidate_path.write_text("placeholder", encoding="utf-8")
            mtime = datetime(2024, 1, 2, 3, 4, 5).timestamp()
            os.utime(candidate_path, (mtime, mtime))
            output = root / "nested.json"

            exit_code = main(["files", str(root), "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["candidate_count"], 1)
            candidate = payload["candidates"][0]
            self.assertIn("documents", candidate_categories(candidate))
            self.assertEqual(candidate["name"], "report.docx")
            self.assertEqual(candidate["extension"], ".docx")
            self.assertEqual(Path(candidate["path"]), candidate_path.resolve())
            self.assertEqual(candidate["modified_at"], datetime.fromtimestamp(mtime).isoformat())


if __name__ == "__main__":
    unittest.main()
