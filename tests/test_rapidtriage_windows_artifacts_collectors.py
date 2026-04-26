from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from rapidtriage.cli import main
from tests.windows_artifact_fixtures import build_minimal_registry_hive

FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "rapidtriage" / "windows_artifacts"


class RapidTriageWindowsArtifactsCollectorTests(unittest.TestCase):
    def test_manifest_collects_browser_and_recent_file_artifacts_from_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "windows_artifacts"
            shutil.copytree(FIXTURE_ROOT, root)
            ntuser = root / "Users" / "alice" / "NTUSER.DAT"
            ntuser.write_bytes(
                build_minimal_registry_hive(
                    datetime(2024, 4, 1, 4, 5, 6, tzinfo=timezone.utc),
                    "NTUSER.DAT",
                    [
                        r"Software\Microsoft\Windows\CurrentVersion\Run",
                        r"C:\Users\alice\AppData\Roaming\SecurityUpdater.exe",
                    ],
                )
            )
            usrclass = root / "Users" / "alice" / "AppData" / "Local" / "Microsoft" / "Windows" / "UsrClass.dat"
            usrclass.parent.mkdir(parents=True, exist_ok=True)
            usrclass.write_bytes(
                build_minimal_registry_hive(
                    datetime(2024, 4, 1, 5, 6, 7, tzinfo=timezone.utc),
                    "UsrClass.dat",
                    [r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU"],
                )
            )
            output = Path(tmp_dir) / "manifest.json"

            exit_code = main(["manifest", str(root), "--output", str(output)])

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
            self.assertIn("registry-hive", registry_types)
            self.assertIn("registry-hive-strings", registry_types)
            self.assertIn("registry-run-key", registry_types)
            self.assertIn("registry-usb", registry_types)
            self.assertIn("registry-summary", registry_types)
            hive = next(artifact for artifact in registry_provider["artifacts"] if artifact["artifact_type"] == "registry-hive")
            self.assertEqual(hive["details"]["native_header"]["regf_valid"], True)
            self.assertEqual(hive["details"]["native_header"]["dirty"], False)
            self.assertEqual(hive["details"]["hive_hint"], "HKEY_CURRENT_USER")
            hive_strings = next(
                artifact
                for artifact in registry_provider["artifacts"]
                if artifact["artifact_type"] == "registry-hive-strings" and artifact["details"]["risk_flags"]
            )
            self.assertIn("hive-pivot:currentversion\\run", hive_strings["details"]["risk_flags"])
            self.assertIn(r"C:\Users\alice\AppData\Roaming\SecurityUpdater.exe", hive_strings["details"]["path_candidates"])
            run_key = next(artifact for artifact in registry_provider["artifacts"] if artifact["artifact_type"] == "registry-run-key")
            self.assertIn("SecurityUpdater", run_key["details"]["values"])
            self.assertEqual(run_key["details"]["persistence_values"][0]["value_name"], "SecurityUpdater")
            self.assertIn("suspicious-value:appdata", run_key["details"]["risk_flags"])
            usb_key = next(artifact for artifact in registry_provider["artifacts"] if artifact["artifact_type"] == "registry-usb")
            self.assertEqual(usb_key["details"]["usb_device"]["serial_hint"], "1234567890")
            summary = next(artifact for artifact in registry_provider["artifacts"] if artifact["artifact_type"] == "registry-summary")
            self.assertEqual(summary["details"]["key_count"], 3)
            self.assertEqual(summary["details"]["hive_file_count"], 2)
            self.assertEqual(summary["details"]["hive_string_row_count"], 2)
            self.assertEqual(summary["details"]["persistence_entries"][0]["value_name"], "SecurityUpdater")
            self.assertEqual(summary["details"]["usb_devices"][0]["friendly_name"], "Test USB Device")
            self.assertTrue(summary["details"]["hive_string_hits"])

            shellbags_provider = providers["windows-shellbags"]
            self.assertEqual(shellbags_provider["artifacts"][0]["artifact_type"], "shellbag-key")
            self.assertIn("BagMRU", shellbags_provider["artifacts"][0]["details"]["key"])

            prefetch_provider = providers["windows-prefetch"]
            self.assertEqual(prefetch_provider["artifacts"][0]["artifact_type"], "prefetch-file")
            self.assertEqual(prefetch_provider["artifacts"][0]["details"]["executable_hint"], "POWERSHELL.EXE")
            self.assertEqual(prefetch_provider["artifacts"][0]["details"]["prefetch_hash"], "12345678")
            self.assertEqual(prefetch_provider["artifacts"][0]["details"]["coverage_status"], "detected")
            self.assertEqual(len(prefetch_provider["artifacts"][0]["details"]["source_hashes"]["sha256"]), 64)

            system_provider = providers["windows-system-artifacts"]
            system_types = {artifact["artifact_type"] for artifact in system_provider["artifacts"]}
            self.assertEqual(
                system_types,
                {"task-scheduler-task", "defender-support-log", "firewall-log", "wer-report", "zone-identifier"},
            )
            task = next(artifact for artifact in system_provider["artifacts"] if artifact["artifact_type"] == "task-scheduler-task")
            self.assertEqual(task["details"]["command"], "powershell.exe")
            self.assertIn("Bypass", task["details"]["arguments"])
            defender = next(artifact for artifact in system_provider["artifacts"] if artifact["artifact_type"] == "defender-support-log")
            self.assertEqual(defender["details"]["interesting_entry_count"], 3)
            firewall = next(artifact for artifact in system_provider["artifacts"] if artifact["artifact_type"] == "firewall-log")
            self.assertEqual(firewall["details"]["blocked_count"], 1)
            wer = next(artifact for artifact in system_provider["artifacts"] if artifact["artifact_type"] == "wer-report")
            self.assertEqual(wer["details"]["application"], "powershell.exe")
            zone = next(artifact for artifact in system_provider["artifacts"] if artifact["artifact_type"] == "zone-identifier")
            self.assertEqual(zone["details"]["zone_id"], "3")
            self.assertEqual(zone["details"]["host_url"], "https://download.example.com/report.zip")


if __name__ == "__main__":
    unittest.main()
