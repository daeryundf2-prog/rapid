from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import main
from rapidtriage.core.collect_plan import build_collect_plan, supported_collect_profiles
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
