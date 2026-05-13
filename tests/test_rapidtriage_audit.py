from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import main
from rapidtriage.core.run import run_triage_mode
from rapidtriage.core.audit import audit_path_for, write_audit_record
from tests.test_rapidtriage_run import build_run_fixture


class RapidTriageAuditTests(unittest.TestCase):
    def test_audit_input_root_inventory_is_bounded_for_large_roots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            root.mkdir(parents=True, exist_ok=True)
            for index in range(6):
                (root / f"item-{index}.txt").write_text(f"artifact {index}", encoding="utf-8")

            audit_path = Path(tmp_dir) / "bounded-audit.json"
            payload = write_audit_record(
                audit_path,
                command="artifacts",
                input_root=root,
                input_root_inventory_max_files=3,
                input_root_inventory_max_dirs=20,
            )

            input_root = payload["provenance"]["input_root"]
            self.assertEqual(input_root["file_count"], 3)
            self.assertEqual(input_root["inventory_scope"], "bounded")
            self.assertTrue(input_root["inventory_truncated"])
            self.assertEqual(input_root["inventory_limits"]["max_files"], 3)

    def test_standalone_commands_write_audit_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)

            manifest_path = root / "manifest.json"
            docs_path = root / "docs.json"
            files_path = root / "files.json"
            artifacts_path = root / "artifacts-browser.json"
            extract_dir = root / "extract-out"
            extract_path = extract_dir / "rapidtriage-extract-manifest.json"

            self.assertEqual(main(["manifest", str(root), "--output", str(manifest_path)]), 0)
            self.assertEqual(main(["docs", str(root), "-k", "fraud", "--output", str(docs_path)]), 0)
            self.assertEqual(main(["files", str(root), "--output", str(files_path)]), 0)
            self.assertEqual(main(["artifacts", str(root), "--kind", "browser", "--output", str(artifacts_path)]), 0)
            self.assertEqual(main(["extract", str(files_path), str(extract_dir)]), 0)

            for command, output_path in (
                ("manifest", manifest_path),
                ("docs", docs_path),
                ("files", files_path),
                ("artifacts", artifacts_path),
                ("extract", extract_path),
            ):
                audit_path = audit_path_for(output_path)
                self.assertTrue(audit_path.is_file(), f"missing audit sidecar for {command}")
                audit_payload = json.loads(audit_path.read_text(encoding="utf-8"))
                self.assertEqual(audit_payload["command"], command)
                self.assertIn("provenance", audit_payload)
                self.assertIn("integrity", audit_payload)
                if command != "extract":
                    self.assertEqual(audit_payload["provenance"]["input_root"]["root_path"], str(root.resolve()))
                self.assertGreaterEqual(len(audit_payload["integrity"]["generated_outputs"]), 1)

            extract_audit = json.loads(audit_path_for(extract_path).read_text(encoding="utf-8"))
            extracted_outputs = extract_audit["integrity"]["generated_outputs"]
            self.assertTrue(any(item["label"] == "extract-manifest" for item in extracted_outputs))
            self.assertTrue(any(item["label"].startswith("extracted:") for item in extracted_outputs))
            self.assertEqual(extract_audit["provenance"]["input_files"][0]["label"], "input-json")

    def test_run_writes_audit_manifest_for_generated_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)

            self.assertEqual(main(["run", str(root), "--mode", "fraud", "--output-dir", str(output_dir)]), 0)

            audit_path = output_dir / "rapidtriage-run-audit.json"
            self.assertTrue(audit_path.is_file())
            audit_payload = json.loads(audit_path.read_text(encoding="utf-8"))

            self.assertEqual(audit_payload["command"], "run")
            self.assertEqual(audit_payload["provenance"]["options"]["mode"], "fraud")
            self.assertEqual(audit_payload["provenance"]["input_root"]["root_path"], str(root.resolve()))

            output_labels = {item["label"] for item in audit_payload["integrity"]["generated_outputs"]}
            self.assertIn("run-summary", output_labels)
            self.assertIn("run-report", output_labels)
            self.assertIn("manifest", output_labels)
            self.assertTrue(any(label.startswith("docs-extract:") for label in output_labels))
            self.assertTrue(any(label.startswith("files-extract:") for label in output_labels))

    def test_run_summary_json_matches_returned_payload_including_audit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)

            payload = run_triage_mode(root, mode="fraud", output_dir=output_dir)

            summary_path = output_dir / "rapidtriage-run-summary.json"
            self.assertTrue(summary_path.is_file())

            summary_payload = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertEqual(summary_payload, payload)
            self.assertEqual(summary_payload["audit"], str((output_dir / "rapidtriage-run-audit.json").resolve()))


if __name__ == "__main__":
    unittest.main()
