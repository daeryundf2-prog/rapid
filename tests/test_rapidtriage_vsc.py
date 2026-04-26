from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import main


class RapidTriageVscCompareTests(unittest.TestCase):
    def test_vsc_compare_reports_deleted_added_and_modified_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            current = root / "current"
            snapshot = root / "snapshot-2024-04-01"
            output = root / "vsc.json"
            current.mkdir()
            snapshot.mkdir()

            (snapshot / "deleted.txt").write_text("snapshot only", encoding="utf-8")
            (snapshot / "modified.txt").write_text("old content", encoding="utf-8")
            (snapshot / "same.txt").write_text("same", encoding="utf-8")
            (current / "modified.txt").write_text("new content", encoding="utf-8")
            (current / "same.txt").write_text("same", encoding="utf-8")
            (current / "added.txt").write_text("current only", encoding="utf-8")

            exit_code = main(["vsc-compare", str(current), str(snapshot), "--hash", "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            records = payload["comparisons"][0]["records"]
            by_path = {record["relative_path"]: record for record in records}

            self.assertEqual(payload["summary"]["snapshot_count"], 1)
            self.assertEqual(payload["summary"]["deleted"], 1)
            self.assertEqual(payload["summary"]["added"], 1)
            self.assertEqual(payload["summary"]["modified"], 1)
            self.assertEqual(by_path["deleted.txt"]["status"], "deleted")
            self.assertEqual(by_path["added.txt"]["status"], "added")
            self.assertEqual(by_path["modified.txt"]["status"], "modified")
            self.assertIn("sha256", by_path["modified.txt"]["current"])
            self.assertTrue(output.with_name("vsc.audit.json").is_file())


if __name__ == "__main__":
    unittest.main()
