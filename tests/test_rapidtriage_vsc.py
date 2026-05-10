from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import main


class RapidTriageVscCompareTests(unittest.TestCase):
    def test_vsc_discover_lists_likely_snapshot_roots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            current = root / "current"
            snapshot = root / "vss" / "snapshot-2024-04-01"
            output = root / "vsc-discovery.json"
            current.mkdir()
            snapshot.mkdir(parents=True)
            (snapshot / "deleted.txt").write_text("snapshot only", encoding="utf-8")

            exit_code = main(["vsc-discover", str(current), "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "rapidforensic-vsc-discovery-v1")
            self.assertEqual(payload["checklist_item"], 8)
            self.assertEqual(payload["qc_gap_id"], "#8")
            self.assertGreaterEqual(payload["snapshot_count"], 1)
            paths = {row["path"] for row in payload["snapshots"]}
            self.assertIn(str(snapshot.resolve()), paths)
            self.assertFalse(payload["direct_image_level_mount_supported"])
            handoff = payload["image_workflow_handoff"]
            self.assertEqual(handoff["profile_version"], "vsc-image-workflow-handoff-v1")
            self.assertEqual(handoff["qc_prep_item"], 3)
            self.assertEqual(handoff["snapshot_count"], payload["snapshot_count"])
            self.assertIn("vsc-compare", handoff["commands"]["compare"])
            self.assertIn("vsc-extract", handoff["commands"]["extract"])
            self.assertFalse(handoff["direct_image_level_mount_supported"])
            self.assertEqual(len(payload["manifest_sha256"]), 64)
            self.assertTrue(output.with_name("vsc-discovery.audit.json").is_file())

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
            self.assertEqual(payload["snapshot_discovery"]["schema"], "rapidforensic-vsc-discovery-v1")
            self.assertEqual(payload["image_workflow_handoff"]["status"], "compare-complete")
            self.assertIn("case-db", payload["image_workflow_handoff"]["commands"]["case_db_import"])
            self.assertFalse(payload["snapshot_discovery"]["direct_image_level_mount_supported"])
            self.assertEqual(payload["summary"]["deleted"], 1)
            self.assertEqual(payload["summary"]["added"], 1)
            self.assertEqual(payload["summary"]["modified"], 1)
            self.assertEqual(by_path["deleted.txt"]["status"], "deleted")
            self.assertEqual(by_path["added.txt"]["status"], "added")
            self.assertEqual(by_path["modified.txt"]["status"], "modified")
            self.assertIn("sha256", by_path["modified.txt"]["current"])
            self.assertTrue(output.with_name("vsc.audit.json").is_file())

    def test_vsc_extract_copies_deleted_and_modified_snapshot_files_with_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            current = root / "current"
            snapshot = root / "snapshot-2024-04-01"
            output_dir = root / "vsc-evidence"
            current.mkdir()
            snapshot.mkdir()

            (snapshot / "deleted.txt").write_text("snapshot only", encoding="utf-8")
            (snapshot / "modified.txt").write_text("old content", encoding="utf-8")
            (current / "modified.txt").write_text("new content", encoding="utf-8")
            (current / "added.txt").write_text("current only", encoding="utf-8")

            exit_code = main(["vsc-extract", str(current), str(snapshot), "--output-dir", str(output_dir)])

            self.assertEqual(exit_code, 0)
            manifest = output_dir / "rapidtriage-vsc-extract.json"
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            copied = {item["relative_path"]: item for item in payload["copied"]}

            self.assertEqual(payload["tool"], "rapidtriage-vsc-extract")
            self.assertEqual(payload["summary"]["selected_count"], 2)
            self.assertEqual(payload["summary"]["copied_count"], 2)
            self.assertEqual(payload["image_workflow_handoff"]["status"], "extract-complete")
            self.assertIn("vsc-discover", payload["image_workflow_handoff"]["commands"]["discover"])
            self.assertEqual(copied["deleted.txt"]["status"], "deleted")
            self.assertEqual(copied["modified.txt"]["status"], "modified")
            self.assertEqual(len(copied["deleted.txt"]["source_sha256"]), 64)
            self.assertEqual(copied["deleted.txt"]["source_sha256"], copied["deleted.txt"]["destination_sha256"])
            self.assertTrue((output_dir / "evidence" / "snapshot-2024-04-01" / "deleted" / "deleted.txt").is_file())
            self.assertTrue((output_dir / "evidence" / "snapshot-2024-04-01" / "modified" / "modified.txt").is_file())
            self.assertTrue(manifest.with_name("rapidtriage-vsc-extract.audit.json").is_file())


if __name__ == "__main__":
    unittest.main()
