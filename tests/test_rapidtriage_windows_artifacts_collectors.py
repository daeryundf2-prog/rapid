from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import main

FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "rapidtriage" / "windows_artifacts"


class RapidTriageWindowsArtifactsCollectorTests(unittest.TestCase):
    def test_manifest_collects_browser_and_recent_file_artifacts_from_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output = Path(tmp_dir) / "manifest.json"

            exit_code = main(["manifest", str(FIXTURE_ROOT), "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            providers = {item["name"]: item for item in payload["providers"]}

            browser_provider = providers["windows-browser-artifacts"]
            self.assertEqual(len(browser_provider["artifacts"]), 3)
            browser_keys = {
                (artifact["details"]["browser"], artifact["details"]["profile"]): artifact
                for artifact in browser_provider["artifacts"]
            }
            chrome = browser_keys[("chrome", "Default")]
            self.assertEqual(chrome["details"]["history_count"], 2)
            self.assertEqual(chrome["details"]["download_count"], 1)
            self.assertEqual(chrome["details"]["downloads"][0]["source_url"], "https://download.example.com/report.zip")
            self.assertEqual(chrome["details"]["downloads"][0]["target_path"], r"C:\Users\alice\Downloads\report.zip")

            firefox = browser_keys[("firefox", "default-release")]
            self.assertEqual(firefox["artifact_type"], "browser-history")
            self.assertEqual(firefox["details"]["history"][0]["url"], "https://support.mozilla.org/kb/download-firefox")
            self.assertEqual(firefox["details"]["download_count"], 0)

            recent_provider = providers["windows-recent-files"]
            recent_types = {artifact["artifact_type"] for artifact in recent_provider["artifacts"]}
            self.assertEqual(recent_types, {"recent-shortcut", "jumplist-automatic", "jumplist-custom"})
            shortcut = next(artifact for artifact in recent_provider["artifacts"] if artifact["artifact_type"] == "recent-shortcut")
            self.assertEqual(shortcut["details"]["entry_name"], "Case Notes.lnk")
            self.assertEqual(shortcut["details"]["user"], "alice")

            event_provider = providers["windows-eventlog"]
            self.assertEqual(event_provider["artifacts"][0]["artifact_type"], "eventlog-event")
            self.assertEqual(event_provider["artifacts"][0]["details"]["event_id"], "4624")
            self.assertEqual(event_provider["artifacts"][0]["details"]["data"]["TargetUserName"], "alice")
            self.assertEqual(event_provider["artifacts"][0]["details"]["source_format"], "xml")

            registry_provider = providers["windows-registry"]
            registry_types = {artifact["artifact_type"] for artifact in registry_provider["artifacts"]}
            self.assertIn("registry-run-key", registry_types)
            self.assertIn("registry-usb", registry_types)
            run_key = next(artifact for artifact in registry_provider["artifacts"] if artifact["artifact_type"] == "registry-run-key")
            self.assertIn("SecurityUpdater", run_key["details"]["values"])

            shellbags_provider = providers["windows-shellbags"]
            self.assertEqual(shellbags_provider["artifacts"][0]["artifact_type"], "shellbag-key")
            self.assertIn("BagMRU", shellbags_provider["artifacts"][0]["details"]["key"])

            prefetch_provider = providers["windows-prefetch"]
            self.assertEqual(prefetch_provider["artifacts"][0]["artifact_type"], "prefetch-file")
            self.assertEqual(prefetch_provider["artifacts"][0]["details"]["executable_hint"], "POWERSHELL.EXE")


if __name__ == "__main__":
    unittest.main()
