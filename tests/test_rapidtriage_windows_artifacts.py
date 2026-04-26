from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath

from rapidtriage.cli import main
from tests.windows_artifact_fixtures import build_minimal_evtx, build_windows_artifact_fixture


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
            self.assertIn(r"C:\\Users\\alice\\Documents\\Incident Notes.docx", manifest_blob)

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

    def test_recent_shortcut_collector_parses_lnk_header_and_target_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            fixture = build_windows_artifact_fixture(root)
            output = root / "recent.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "recent-files", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            shortcut = next(item for item in payload["artifacts"] if item["artifact_type"] == "recent-shortcut")
            details = shortcut["details"]

            self.assertEqual(details["entry_name"], fixture.recent_shortcut.name)
            self.assertEqual(details["lnk_parse_status"], "parsed")
            self.assertEqual(details["target_path"], r"C:\Users\alice\Documents\Incident Notes.docx")
            self.assertEqual(details["working_dir"], r"C:\Users\alice\Documents")
            self.assertIn("IsUnicode", details["link_flag_names"])
            self.assertIn("ARCHIVE", details["file_attribute_names"])
            self.assertEqual(len(details["source_hashes"]["sha256"]), 64)

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

            self.assertGreaterEqual(len(event_rows), 3)
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
            rules_by_id = {item["details"]["rule"]["id"]: item for item in detection_rows}
            self.assertEqual(rules_by_id["RT-PS-001"]["details"]["rule"]["title"], "Suspicious Encoded PowerShell")
            self.assertEqual(rules_by_id["RT-PS-001"]["details"]["coverage_status"], "detected-by-rule")
            self.assertEqual(rules_by_id["RT-EVTX-PS-ENCODED"]["details"]["parser"], "windows-eventlog-builtin-rulepack")
            self.assertEqual(rules_by_id["RT-EVTX-PS-ENCODED"]["details"]["matched_event"]["record_id"], "202")
            self.assertEqual(rules_by_id["RT-EVTX-RDP-LOGON"]["details"]["logon_type"], "10")
            self.assertEqual(inventory_rows[0]["details"]["coverage_status"], "detected")
            self.assertEqual(inventory_rows[0]["details"]["source_path"], str(fixture.evtx_file.resolve()))
            self.assertEqual(inventory_rows[0]["details"]["native_record_count"], 1)
            native_evtx = [item for item in event_rows if item["details"]["parser"] == "windows-eventlog-evtx-native"][0]
            self.assertEqual(native_evtx["details"]["coverage_status"], "native-binary-partial")
            self.assertEqual(native_evtx["details"]["reportability"], "triage")
            self.assertEqual(native_evtx["details"]["record_id"], "300")
            self.assertEqual(native_evtx["details"]["timestamp"], "2024-04-01T03:04:05+00:00")
            self.assertIn("powershell -enc NativeFixture", native_evtx["details"]["extracted_strings"])
            self.assertIn("suspicious-term:powershell -enc", native_evtx["details"]["risk_flags"])
            summary = summary_rows[0]["details"]
            self.assertEqual(summary["event_count"], 3)
            self.assertEqual(summary["detection_count"], 3)
            self.assertEqual(summary["parsed_row_count"], 6)
            self.assertEqual(summary["first_event_at"], "2024-04-01T01:02:03.000000+00:00")
            self.assertIn({"value": "4104", "count": 1}, summary["event_id_counts"])
            self.assertIn({"value": "RT-EVTX-PS-ENCODED", "count": 1}, summary["detection_rule_counts"])
            self.assertTrue(any(item["event_id"] == "4104" for item in summary["high_risk_events"]))
            self.assertTrue(any(item["channel"] == "Microsoft-Windows-PowerShell/Operational" for item in summary["record_sequence_gaps"]))

    def test_eventlog_collector_discovers_evtx_exports_outside_default_log_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            evtx_path = root / "analysis" / "evtx" / "Collected-System.evtx"
            evtx_path.parent.mkdir(parents=True, exist_ok=True)
            evtx_path.write_bytes(
                build_minimal_evtx(
                    record_id=777,
                    timestamp=datetime(2024, 4, 2, 1, 2, 3, tzinfo=timezone.utc),
                    strings=["Microsoft-Windows-Security-Auditing", "Security", "WIN-EXPORT", "wevtutil cl Security"],
                )
            )
            output = root / "eventlog.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "eventlog", "--output", str(output)]), 0)
            artifacts = json.loads(output.read_text(encoding="utf-8"))["artifacts"]
            native_rows = [
                item
                for item in artifacts
                if item["artifact_type"] == "eventlog-event"
                and item["details"]["parser"] == "windows-eventlog-evtx-native"
            ]

            self.assertEqual(len(native_rows), 1)
            self.assertEqual(native_rows[0]["details"]["record_id"], "777")
            self.assertEqual(native_rows[0]["details"]["source_path"], str(evtx_path.resolve()))

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

    def test_windows_prefetch_fixture_surfaces_run_count_and_last_run_time(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            build_windows_artifact_fixture(root)
            output = root / "prefetch.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "windows-prefetch", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            details = payload["artifacts"][0]["details"]

            self.assertEqual(details["prefetch_parse_status"], "parsed-common-header")
            self.assertEqual(details["run_count"], 3)
            self.assertEqual(details["last_run_at"], "2024-04-01T09:10:11+00:00")
            self.assertIn(details["last_run_at"], details["last_run_times"])
            self.assertTrue(any("POWERSHELL.EXE" in path for path in details["referenced_paths"]))

    def test_windows_prefetch_collector_is_available_as_dedicated_artifacts_kind(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            output = root / "prefetch.json"
            prefetch = root / "Windows" / "Prefetch" / "POWERSHELL.EXE-12345678.pf"
            prefetch.parent.mkdir(parents=True, exist_ok=True)
            header = bytearray(512)
            header[0:4] = (30).to_bytes(4, "little")
            header[4:8] = b"SCCA"
            header[16 : 16 + len("POWERSHELL.EXE".encode("utf-16le"))] = "POWERSHELL.EXE".encode("utf-16le")
            header[0xD0:0xD4] = (7).to_bytes(4, "little")
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
            self.assertEqual(artifact["details"]["run_count"], 7)
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

    def test_windows_search_index_collector_imports_exports_and_inventories_edb(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            fixture = build_windows_artifact_fixture(root)
            output = root / "search-index.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "windows-search-index", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            artifacts = payload["artifacts"]
            entries = [item for item in artifacts if item["artifact_type"] == "windows-search-index-entry"]
            edb_files = [item for item in artifacts if item["artifact_type"] == "windows-search-edb-file"]
            summary = next(item for item in artifacts if item["artifact_type"] == "windows-search-index-summary")

            self.assertEqual(entries[0]["details"]["entry_id"], "7")
            self.assertEqual(entries[0]["details"]["file_name"], "Incident Notes.docx")
            self.assertEqual(entries[0]["details"]["extension"], ".docx")
            self.assertIn("encoded powershell", entries[0]["details"]["content_snippet"])
            self.assertEqual(entries[0]["details"]["source_path"], str(fixture.windows_search_csv.resolve()))
            self.assertEqual(edb_files[0]["details"]["source_path"], str(fixture.windows_edb.resolve()))
            self.assertEqual(summary["details"]["entry_count"], 1)
            self.assertEqual(summary["details"]["inventory_count"], 1)
            self.assertIn({"value": ".docx", "count": 1}, summary["details"]["extension_counts"])

    def test_windows_remote_access_collector_maps_rdp_config_cache_and_destinations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            fixture = build_windows_artifact_fixture(root)
            output = root / "remote-access.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "windows-remote-access", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            artifacts = payload["artifacts"]
            config = next(item for item in artifacts if item["artifact_type"] == "rdp-config")
            cache = next(item for item in artifacts if item["artifact_type"] == "rdp-cache-file")
            destinations = [item for item in artifacts if item["artifact_type"] == "rdp-destination"]

            self.assertEqual(config["details"]["destination"], "10.0.0.50")
            self.assertEqual(config["details"]["username_hint"], r"CORP\alice")
            self.assertEqual(config["details"]["gateway_hostname"], "rd-gateway.example")
            self.assertEqual(config["details"]["source_path"], str(fixture.default_rdp.resolve()))
            self.assertEqual(cache["details"]["source_path"], str(fixture.rdp_cache_file.resolve()))
            self.assertTrue(any(item["details"]["destination"] == "10.0.0.50" for item in destinations))
            self.assertTrue(any(item["details"]["destination"] == "rdp-target.example" for item in destinations))

    def test_windows_system_collector_inventories_wmi_repository_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            fixture = build_windows_artifact_fixture(root)
            output = root / "windows-system.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "windows-system", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            wmi = [item for item in payload["artifacts"] if item["artifact_type"] == "wmi-repository-file"]

            self.assertTrue(wmi)
            self.assertEqual(wmi[0]["details"]["entry_name"], "OBJECTS.DATA")
            self.assertEqual(wmi[0]["details"]["source_path"], str(fixture.wmi_objects.resolve()))
            self.assertEqual(len(wmi[0]["details"]["source_hashes"]["sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
