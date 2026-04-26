from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path, PureWindowsPath

from rapidtriage.cli import main
from tests.windows_artifact_fixtures import build_windows_artifact_fixture


class RapidTriageWindowsArtifactsTests(unittest.TestCase):
    def test_manifest_surfaces_fixture_browser_history_downloads_and_recent_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            fixture = build_windows_artifact_fixture(root)
            output = root / "manifest.json"

            exit_code = main(["manifest", str(root), "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            serialized_artifacts = [
                json.dumps(artifact, ensure_ascii=False, sort_keys=True)
                for provider in payload["providers"]
                for artifact in provider["artifacts"]
            ]
            manifest_blob = "\n".join(serialized_artifacts)

            self.assertIn(fixture.chrome_visit.url, manifest_blob)
            self.assertIn(fixture.edge_visit.url, manifest_blob)
            self.assertIn(PureWindowsPath(fixture.download.target_path).name, manifest_blob)
            self.assertIn(fixture.recent_shortcut.name, manifest_blob)

    def test_manifest_windows_artifact_rows_point_inside_fixture_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            fixture = build_windows_artifact_fixture(root)
            output = root / "manifest.json"

            self.assertEqual(main(["manifest", str(root), "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            artifact_rows = [artifact for provider in payload["providers"] for artifact in provider["artifacts"]]

            matching = [
                artifact
                for artifact in artifact_rows
                if fixture.chrome_visit.url in json.dumps(artifact, ensure_ascii=False)
                or fixture.edge_visit.url in json.dumps(artifact, ensure_ascii=False)
                or fixture.recent_shortcut.name in json.dumps(artifact, ensure_ascii=False)
            ]

            self.assertTrue(matching)
            for artifact in matching:
                self.assertTrue(Path(artifact["path"]).is_relative_to(root.resolve()))
                self.assertIn("supported", artifact)
                self.assertIsInstance(artifact["details"], dict)

    def test_eventlog_collector_normalizes_exports_detections_and_evtx_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            fixture = build_windows_artifact_fixture(root)
            output = root / "eventlog.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "eventlog", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            artifacts = payload["artifacts"]
            event_rows = [item for item in artifacts if item["artifact_type"] == "eventlog-event"]
            detection_rows = [item for item in artifacts if item["artifact_type"] == "eventlog-detection"]
            inventory_rows = [item for item in artifacts if item["artifact_type"] == "eventlog-file"]
            summary_rows = [item for item in artifacts if item["artifact_type"] == "eventlog-summary"]

            self.assertGreaterEqual(len(event_rows), 2)
            logon = [item for item in event_rows if item["details"]["event_id"] == "4624"][0]
            self.assertEqual(logon["details"]["user_name"], "alice")
            self.assertEqual(logon["details"]["target_user_name"], "alice")
            self.assertEqual(logon["details"]["subject_user_name"], "SYSTEM")
            self.assertEqual(logon["details"]["logon_type"], "10")
            self.assertEqual(logon["details"]["source_ip"], "10.0.0.5")
            powershell = [item for item in event_rows if item["details"]["event_id"] == "4104"][0]
            self.assertEqual(powershell["details"]["event_category"], "powershell-script-block")
            self.assertEqual(powershell["details"]["command_line"], "powershell -enc SQBFAFgA")
            self.assertEqual(powershell["details"]["script_block_text"], "powershell -enc SQBFAFgA")
            self.assertIn("high-value-event-id:4104", powershell["details"]["risk_flags"])
            self.assertIn("suspicious-term:powershell -enc", powershell["details"]["risk_flags"])
            self.assertEqual(detection_rows[0]["details"]["rule"]["title"], "Suspicious Encoded PowerShell")
            self.assertEqual(detection_rows[0]["details"]["coverage_status"], "detected-by-rule")
            self.assertEqual(inventory_rows[0]["details"]["coverage_status"], "detected")
            self.assertEqual(inventory_rows[0]["details"]["source_path"], str(fixture.evtx_file.resolve()))
            summary = summary_rows[0]["details"]
            self.assertEqual(summary["event_count"], 3)
            self.assertEqual(summary["detection_count"], 1)
            self.assertEqual(summary["first_event_at"], "2024-04-01T01:02:03.000000+00:00")
            self.assertIn({"value": "4104", "count": 2}, summary["event_id_counts"])
            self.assertTrue(any(item["event_id"] == "4104" for item in summary["high_risk_events"]))
            self.assertTrue(any(item["channel"] == "Microsoft-Windows-PowerShell/Operational" for item in summary["record_sequence_gaps"]))

    def test_windows_os_account_collector_summarizes_profiles_and_reg_exports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            fixture = build_windows_artifact_fixture(root)
            output = root / "os-account.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "windows-os-account", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            artifacts = payload["artifacts"]
            profiles = [item for item in artifacts if item["artifact_type"] == "windows-user-profile"]
            summaries = [item for item in artifacts if item["artifact_type"] == "windows-os-account-summary"]

            self.assertTrue(profiles)
            self.assertEqual(profiles[0]["details"]["user_name"], "alice")
            self.assertEqual(profiles[0]["details"]["source_path"], str(fixture.user_profile.resolve()))
            self.assertTrue(profiles[0]["details"]["ntuser_dat_present"])
            self.assertTrue(summaries)
            self.assertIn("WIN-FIXTURE", summaries[0]["details"]["computer_names"])
            self.assertIn("Korea Standard Time", summaries[0]["details"]["time_zones"])

    def test_windows_execution_collector_maps_registry_and_powershell_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            fixture = build_windows_artifact_fixture(root)
            output = root / "execution.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "windows-execution", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            artifacts = payload["artifacts"]
            artifact_types = {item["artifact_type"] for item in artifacts}

            self.assertIn("bam-entry", artifact_types)
            self.assertIn("userassist-entry", artifact_types)
            self.assertIn("shimcache-entry", artifact_types)
            self.assertIn("powershell-history-command", artifact_types)
            self.assertIn("srum-network-usage", artifact_types)
            self.assertIn("windows-execution-summary", artifact_types)
            ps_rows = [item for item in artifacts if item["artifact_type"] == "powershell-history-command"]
            srum_rows = [item for item in artifacts if item["artifact_type"] == "srum-network-usage"]
            self.assertTrue(any("suspicious-command:powershell -enc" in row["details"]["risk_flags"] for row in ps_rows))
            self.assertTrue(any("vssadmin delete shadows" in row["details"]["command_line"] for row in ps_rows))
            self.assertEqual(ps_rows[0]["details"]["source_path"], str(fixture.powershell_history.resolve()))
            self.assertEqual(srum_rows[0]["details"]["app_id"], "powershell.exe")
            self.assertEqual(srum_rows[0]["details"]["bytes_received"], 2048)
            self.assertEqual(srum_rows[0]["details"]["source_path"], str(fixture.srum_csv.resolve()))
            summary = next(item for item in artifacts if item["artifact_type"] == "windows-execution-summary")
            groups = {item["display_name"]: item for item in summary["details"]["groups"]}
            self.assertIn("evil.exe", groups)
            self.assertIn("powershell.exe", groups)
            self.assertIn("bam-entry", groups["evil.exe"]["signal_types"])
            self.assertIn("powershell-history-command", groups["powershell.exe"]["signal_types"])
            self.assertIn("srum-network-usage", groups["powershell.exe"]["signal_types"])
            self.assertIn("suspicious-command:powershell -enc", groups["powershell.exe"]["risk_flags"])

    def test_windows_prefetch_collector_is_available_as_dedicated_artifacts_kind(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            output = root / "prefetch.json"
            prefetch = root / "Windows" / "Prefetch" / "POWERSHELL.EXE-12345678.pf"
            prefetch.parent.mkdir(parents=True, exist_ok=True)
            header = bytearray(256)
            header[0:4] = (30).to_bytes(4, "little")
            header[4:8] = b"SCCA"
            header[16 : 16 + len("POWERSHELL.EXE".encode("utf-16le"))] = "POWERSHELL.EXE".encode("utf-16le")
            prefetch.write_bytes(bytes(header))

            self.assertEqual(main(["artifacts", str(root), "--kind", "windows-prefetch", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            artifact = payload["artifacts"][0]

            self.assertEqual(payload["kind"], "windows-prefetch")
            self.assertEqual(artifact["artifact_type"], "prefetch-file")
            self.assertEqual(artifact["details"]["executable_hint"], "POWERSHELL.EXE")
            self.assertEqual(artifact["details"]["executable_hint_source"], "prefetch_header")
            self.assertTrue(artifact["details"]["binary_format_detected"])
            self.assertEqual(artifact["details"]["prefetch_version"], 30)
            self.assertEqual(artifact["details"]["header_executable_name"], "POWERSHELL.EXE")
            self.assertEqual(artifact["details"]["prefetch_hash"], "12345678")
            self.assertEqual(artifact["details"]["evidence_strength"], "execution-indicator")

    def test_windows_filesystem_collector_imports_mft_and_usn_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            fixture = build_windows_artifact_fixture(root)
            output = root / "filesystem.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "windows-filesystem", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            artifacts = payload["artifacts"]
            mft = [item for item in artifacts if item["artifact_type"] == "mft-record"]
            usn = [item for item in artifacts if item["artifact_type"] == "usn-record"]

            self.assertEqual(mft[0]["details"]["record_number"], "42")
            self.assertTrue(mft[0]["details"]["deleted_hint"])
            self.assertEqual(mft[0]["details"]["source_path"], str(fixture.mft_csv.resolve()))
            self.assertEqual(usn[0]["details"]["reason"], "FILE_DELETE")
            self.assertEqual(usn[0]["details"]["source_path"], str(fixture.usn_jsonl.resolve()))


if __name__ == "__main__":
    unittest.main()
