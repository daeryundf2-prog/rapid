from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import main
from rapidtriage.core.collect_plan import build_collect_plan, run_collect_export, supported_collect_profiles
from tests.test_rapidtriage_macos_artifacts import build_macos_fixture
from tests.windows_artifact_fixtures import build_windows_artifact_fixture


class RapidTriageCollectPlanTests(unittest.TestCase):
    def test_collect_plan_profiles_are_exposed(self) -> None:
        profiles = supported_collect_profiles()

        self.assertIn("windows-core", profiles)
        self.assertIn("macos-core", profiles)
        self.assertIn("intrusion", profiles)
        self.assertIn("full", profiles)

    def test_windows_collect_plan_finds_high_value_targets_without_copying(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            fixture = build_windows_artifact_fixture(root)

            payload = build_collect_plan(root, profile="windows-core")
            targets = {target["label"]: target for target in payload["targets"]}

            self.assertEqual(payload["command"], "collect-plan")
            self.assertGreater(payload["summary"]["present_count"], 0)
            self.assertTrue(targets["Windows EVTX log directory"]["exists"])
            self.assertTrue(targets["PowerShell PSReadLine history"]["exists"])
            self.assertEqual(targets["PowerShell PSReadLine history"]["match_count"], 1)
            self.assertEqual(targets["Windows EVTX log directory"]["artifact_kind"], "eventlog")
            self.assertFalse((root / "rapidtriage-collect-plan.json").exists())
            self.assertEqual(
                Path(targets["PowerShell PSReadLine history"]["matches"][0]["path"]).resolve(),
                fixture.powershell_history.resolve(),
            )

    def test_macos_collect_plan_finds_browser_quarantine_and_persistence_targets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            build_macos_fixture(root)

            payload = build_collect_plan(root, profile="macos-core")
            targets = {target["label"]: target for target in payload["targets"]}

            self.assertTrue(targets["Safari history databases"]["exists"])
            self.assertTrue(targets["LaunchServices quarantine database"]["exists"])
            self.assertTrue(targets["User LaunchAgents"]["exists"])
            self.assertIn("Persistence", payload["summary"]["category_counts"])
            self.assertIn("macos-system", payload["summary"]["artifact_kind_counts"])

    def test_collect_plan_cli_writes_json_and_lightweight_audit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            build_windows_artifact_fixture(root)
            output = root / "plan.json"
            audit = root / "plan.audit.json"

            self.assertEqual(
                main(["collect-plan", str(root), "--profile", "intrusion", "--output", str(output)]),
                0,
            )

            payload = json.loads(output.read_text(encoding="utf-8"))
            audit_payload = json.loads(audit.read_text(encoding="utf-8"))
            self.assertEqual(payload["profile"], "intrusion")
            self.assertGreater(payload["summary"]["present_count"], 0)
            self.assertIsNone(audit_payload["provenance"]["input_root"])
            self.assertIn("collect-plan intentionally does not hash", audit_payload["provenance"]["notes"][0])

    def test_collect_export_dry_run_selects_files_without_copying(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "evidence"
            output_dir = Path(tmp_dir) / "export"
            fixture = build_windows_artifact_fixture(root)

            payload = run_collect_export(root, output_dir, profile="intrusion", copy_files=False)
            powershell_entry = next(
                entry
                for entry in payload["entries"]
                if Path(entry["source_path"]).resolve() == fixture.powershell_history.resolve()
            )

            self.assertEqual(payload["command"], "collect-export")
            self.assertFalse(powershell_entry["copied"])
            self.assertEqual(len(powershell_entry["sha256"]), 64)
            self.assertFalse((output_dir / "evidence").exists())
            self.assertTrue(any(skip["reason"] == "dry-run" for skip in payload["skipped"]))
            self.assertTrue(any(skip["reason"] == "broad-directory-inventory-only" for skip in payload["skipped"]))

    def test_collect_export_cli_copies_selected_files_with_hash_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "evidence"
            output_dir = Path(tmp_dir) / "export"
            build_macos_fixture(root)

            self.assertEqual(
                main(["collect-export", str(root), str(output_dir), "--profile", "macos-core", "--copy"]),
                0,
            )

            manifest = json.loads((output_dir / "rapidtriage-collect-export.json").read_text(encoding="utf-8"))
            copied = [entry for entry in manifest["entries"] if entry["copied"]]
            self.assertGreaterEqual(len(copied), 3)
            self.assertTrue((output_dir / "evidence" / "Users" / "alice" / "Library" / "Safari" / "History.db").is_file())
            self.assertTrue(all(entry["sha256"] == entry["destination_sha256"] for entry in copied))
            self.assertIn("rapidtriage run", manifest["next_steps"][0])

    def test_collect_plan_rejects_container_files_until_mounted_or_exported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            image = root / "case.E01"
            image.write_bytes(b"E01")
            output = root / "plan.json"

            with self.assertRaises(SystemExit) as error:
                main(["collect-plan", str(image), "--output", str(output)])
            self.assertEqual(error.exception.code, 2)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
