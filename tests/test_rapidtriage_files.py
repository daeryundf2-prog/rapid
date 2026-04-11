from __future__ import annotations

import json
import os
import tempfile
import unittest
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from rapidtriage.cli import main


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
            self.assertEqual(
                set(payload["summary"]["default_categories"]),
                {"documents", "archives", "databases", "executables"},
            )
            self.assertEqual(
                payload["summary"]["category_counts"],
                {
                    "documents": 1,
                    "archives": 1,
                    "databases": 1,
                    "executables": 1,
                },
            )

            candidates = {Path(item["path"]).name: item for item in payload["candidates"]}
            self.assertEqual(set(candidates), {"notes.txt", "bundle.zip", "records.sqlite", "tool.exe"})
            self.assertEqual(candidates["notes.txt"]["category"], "documents")
            self.assertEqual(candidates["bundle.zip"]["category"], "archives")
            self.assertEqual(candidates["records.sqlite"]["category"], "databases")
            self.assertEqual(candidates["tool.exe"]["category"], "executables")

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
            mtime = datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc).timestamp()
            os.utime(candidate_path, (mtime, mtime))
            output = root / "nested.json"

            exit_code = main(["files", str(root), "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["candidate_count"], 1)
            candidate = payload["candidates"][0]
            self.assertEqual(candidate["category"], "documents")
            self.assertEqual(candidate["name"], "report.docx")
            self.assertEqual(candidate["extension"], ".docx")
            self.assertEqual(Path(candidate["path"]), candidate_path.resolve())
            self.assertEqual(candidate["modified_at"], datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat())


if __name__ == "__main__":
    unittest.main()
