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
            (root / "mailbox.pst").write_bytes(b"email archive")
            (root / "case.E01").write_bytes(b"EVF")
            (root / "phone.ufdx").write_bytes(b"cellebrite mobile image")
            (root / "memory.vmem").write_bytes(b"memory dump")
            (root / "route.ivo").write_bytes(b"vehicle export")
            (root / "split.7z001").write_bytes(b"segmented archive")
            (root / "photo.jpg").write_bytes(b"\xff\xd8\xff")
            output = root / "files.json"

            exit_code = main(["files", str(root), "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["command"], "files")
            self.assertEqual(Path(payload["root"]), root.resolve())
            self.assertEqual(payload["summary"]["candidate_count"], 11)
            self.assertIn("duplicate_group_count", payload["summary"])
            self.assertIn("duplicate_content_groups", payload)
            category_counts = payload["summary"]["category_counts"]
            self.assertGreaterEqual(category_counts["documents"], 1)
            self.assertGreaterEqual(category_counts["archives"], 1)
            self.assertGreaterEqual(category_counts["databases"], 1)
            self.assertGreaterEqual(category_counts["executables"], 1)
            self.assertGreaterEqual(category_counts["emails"], 1)
            self.assertGreaterEqual(category_counts["disk-images"], 1)
            self.assertGreaterEqual(category_counts["mobile-images"], 1)
            self.assertGreaterEqual(category_counts["memory-dumps"], 1)
            self.assertGreaterEqual(category_counts["vehicle-images"], 1)
            self.assertGreaterEqual(category_counts["images"], 1)

            candidates = {Path(item["path"]).name: item for item in payload["candidates"]}
            self.assertEqual(
                set(candidates),
                {
                    "notes.txt",
                    "bundle.zip",
                    "records.sqlite",
                    "tool.exe",
                    "mailbox.pst",
                    "case.E01",
                    "phone.ufdx",
                    "memory.vmem",
                    "route.ivo",
                    "split.7z001",
                    "photo.jpg",
                },
            )
            self.assertIn("documents", candidate_categories(candidates["notes.txt"]))
            self.assertIn("archives", candidate_categories(candidates["bundle.zip"]))
            self.assertIn("databases", candidate_categories(candidates["records.sqlite"]))
            self.assertIn("executables", candidate_categories(candidates["tool.exe"]))
            self.assertIn("emails", candidate_categories(candidates["mailbox.pst"]))
            self.assertIn("disk-images", candidate_categories(candidates["case.E01"]))
            self.assertIn("mobile-images", candidate_categories(candidates["phone.ufdx"]))
            self.assertIn("memory-dumps", candidate_categories(candidates["memory.vmem"]))
            self.assertIn("vehicle-images", candidate_categories(candidates["route.ivo"]))
            self.assertIn("archives", candidate_categories(candidates["split.7z001"]))
            self.assertIn("images", candidate_categories(candidates["photo.jpg"]))

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

    def test_files_command_groups_bounded_duplicate_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "copy-a.txt").write_text("same evidence content", encoding="utf-8")
            (root / "copy-b.txt").write_text("same evidence content", encoding="utf-8")
            output = root / "duplicates.json"

            self.assertEqual(main(["files", str(root), "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))

            self.assertEqual(payload["summary"]["duplicate_group_count"], 1)
            self.assertEqual(payload["duplicate_content_groups"][0]["file_count"], 2)


if __name__ == "__main__":
    unittest.main()
