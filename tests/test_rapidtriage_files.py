from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import main


class RapidTriageFilesTests(unittest.TestCase):
    def test_files_command_scans_default_categories_and_writes_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "docs").mkdir()
            (root / "archives").mkdir()
            (root / "db").mkdir()
            (root / "bin").mkdir()
            (root / "docs" / "incident_report.pdf").write_text("not parsed here", encoding="utf-8")
            (root / "archives" / "case-backup.zip").write_text("zip placeholder", encoding="utf-8")
            (root / "db" / "case.sqlite").write_text("sqlite placeholder", encoding="utf-8")
            executable = root / "bin" / "runme.sh"
            executable.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
            executable.chmod(0o755)
            (root / "ignore.tmp").write_text("ignore me", encoding="utf-8")
            output = root / "files.json"

            exit_code = main(["files", str(root), "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["command"], "files")
            self.assertEqual(payload["summary"]["candidate_count"], 4)
            self.assertEqual(payload["summary"]["category_counts"], {
                "documents": 1,
                "archives": 1,
                "databases": 1,
                "executables": 1,
            })
            result_names = {item["name"] for item in payload["candidates"]}
            self.assertEqual(result_names, {"incident_report.pdf", "case-backup.zip", "case.sqlite", "runme.sh"})

        
    def test_files_command_filters_by_name_path_extension_and_modified_time(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            target_dir = root / "evidence_docs"
            target_dir.mkdir()
            recent = target_dir / "incident_report.pdf"
            recent.write_text("pdf placeholder", encoding="utf-8")
            stale = target_dir / "incident_old.pdf"
            stale.write_text("pdf placeholder", encoding="utf-8")
            other = root / "misc" / "incident_report.txt"
            other.parent.mkdir()
            other.write_text("text placeholder", encoding="utf-8")
            os.utime(recent, (1735689600, 1735689600))  # 2025-01-01T00:00:00
            os.utime(stale, (1672531200, 1672531200))  # 2023-01-01T00:00:00
            os.utime(other, (1735689600, 1735689600))
            output = root / "filtered.json"

            exit_code = main(
                [
                    "files",
                    str(root),
                    "--name-contains",
                    "incident",
                    "--path-contains",
                    "evidence_docs",
                    "--ext",
                    "pdf",
                    "--modified-after",
                    "2024-01-01",
                    "--output",
                    str(output),
                ]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["candidate_count"], 1)
            self.assertEqual(payload["candidates"][0]["name"], "incident_report.pdf")
            self.assertEqual(payload["filters"]["extensions"], [".pdf"])
            self.assertEqual(payload["filters"]["modified_after"], "2024-01-01T00:00:00")


if __name__ == "__main__":
    unittest.main()
