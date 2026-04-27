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
            self.assertIn(fixture.ai_visit.url, manifest_blob)
            self.assertIn("browser-ai-usage", manifest_blob)
            self.assertIn("browser-ai-conversation", manifest_blob)
            self.assertIn("timeline analysis for evtx", manifest_blob)
            self.assertIn("How do I build an EVTX forensic timeline?", manifest_blob)
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

    def test_browser_collector_detects_internet_and_ai_usage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            fixture = build_windows_artifact_fixture(root)
            output = root / "browser.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "browser", "--output", str(output)]), 0)
            artifacts = json.loads(output.read_text(encoding="utf-8"))["artifacts"]
            chrome = next(
                artifact
                for artifact in artifacts
                if artifact["artifact_type"] == "browser-history-downloads"
                and artifact["details"]["browser"] == "chrome"
            )
            ai_usage = next(artifact for artifact in artifacts if artifact["artifact_type"] == "browser-ai-usage")
            ai_conversation = next(
                artifact for artifact in artifacts if artifact["artifact_type"] == "browser-ai-conversation"
            )

            self.assertEqual(chrome["details"]["history_count"], 2)
            self.assertEqual(chrome["details"]["ai_usage_count"], 1)
            self.assertGreaterEqual(chrome["details"]["ai_conversation_candidate_count"], 2)
            self.assertIn({"value": "ai", "count": 1}, chrome["details"]["internet_category_counts"])
            self.assertEqual(ai_usage["details"]["browser"], "chrome")
            self.assertEqual(ai_usage["details"]["ai_usage_count"], 1)
            self.assertGreaterEqual(ai_usage["details"]["ai_conversation_candidate_count"], 2)
            self.assertEqual(ai_usage["details"]["ai_usage"][0]["ai_service"], "ChatGPT")
            self.assertEqual(ai_usage["details"]["ai_usage"][0]["url"], fixture.ai_visit.url)
            self.assertEqual(ai_usage["details"]["ai_usage"][0]["prompt_hint"], "timeline analysis for evtx")
            self.assertEqual(len(ai_usage["details"]["source_hashes"]["sha256"]), 64)
            self.assertEqual(ai_conversation["details"]["coverage_status"], "candidate")
            self.assertGreaterEqual(ai_conversation["details"]["question_count"], 2)
            self.assertGreaterEqual(ai_conversation["details"]["answer_count"], 2)
            self.assertGreaterEqual(ai_conversation["details"]["complete_pair_count"], 2)
            self.assertGreater(ai_conversation["details"]["transcript_completeness_score"], 0)
            self.assertIn(
                ai_conversation["details"]["transcript_validation_status"],
                {"paired-candidate", "partial-paired-candidate"},
            )
            transcript_pair = ai_conversation["details"]["transcript_pairs"][0]
            self.assertEqual(transcript_pair["ai_service"], "ChatGPT")
            self.assertTrue(transcript_pair["same_source"])
            self.assertEqual(transcript_pair["validation_status"], "paired-candidate")
            candidate_text = "\n".join(
                row["text"] for row in ai_conversation["details"]["conversation_candidates"]
            )
            self.assertIn("How do I build an EVTX forensic timeline?", candidate_text)
            self.assertIn("Correlate EventRecordID", candidate_text)
            self.assertEqual(ai_conversation["details"]["conversation_candidates"][0]["storage_area"], "Local Storage/leveldb")

    def test_recent_shortcut_collector_parses_lnk_header_and_target_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            fixture = build_windows_artifact_fixture(root)
            output = root / "recent.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "recent-files", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            shortcut = next(item for item in payload["artifacts"] if item["artifact_type"] == "recent-shortcut")
            automatic = next(item for item in payload["artifacts"] if item["artifact_type"] == "jumplist-automatic")
            custom = next(item for item in payload["artifacts"] if item["artifact_type"] == "jumplist-custom")
            details = shortcut["details"]

            self.assertEqual(details["entry_name"], fixture.recent_shortcut.name)
            self.assertEqual(details["lnk_parse_status"], "parsed")
            self.assertEqual(details["target_path"], r"C:\Users\alice\Documents\Incident Notes.docx")
            self.assertEqual(details["working_dir"], r"C:\Users\alice\Documents")
            self.assertIn("IsUnicode", details["link_flag_names"])
            self.assertIn("ARCHIVE", details["file_attribute_names"])
            self.assertEqual(len(details["source_hashes"]["sha256"]), 64)
            self.assertEqual(automatic["details"]["jump_list_parse_status"], "parsed-ole-stream-lnk")
            self.assertEqual(automatic["details"]["ole_parse_status"], "parsed")
            self.assertEqual(automatic["details"]["ole_stream_count"], 1)
            self.assertEqual(automatic["details"]["destination_count"], 1)
            self.assertEqual(automatic["details"]["destinations"][0]["target_path"], r"C:\Users\alice\Documents\Incident Notes.docx")
            self.assertEqual(automatic["details"]["destinations"][0]["stream_path"], "1")
            self.assertIn(r"C:\Users\alice\Documents\Incident Notes.docx", automatic["details"]["embedded_paths"])
            self.assertEqual(custom["details"]["destinations"][0]["target_path"], r"C:\Users\alice\Downloads\installer.exe")

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
            self.assertEqual(logon["details"]["event_family"], "authentication")
            self.assertEqual(logon["details"]["channel_family"], "security")
            self.assertIn("event-id:4624", logon["details"]["event_tags"])
            powershell = [item for item in event_rows if item["details"]["event_id"] == "4104"][0]
            self.assertEqual(powershell["details"]["event_category"], "powershell-script-block")
            self.assertEqual(powershell["details"]["event_family"], "execution")
            self.assertEqual(powershell["details"]["command_line"], "powershell -enc SQBFAFgA")
            self.assertEqual(powershell["details"]["script_block_text"], "powershell -enc SQBFAFgA")
            self.assertGreaterEqual(powershell["details"]["parser_confidence"], 0.9)
            self.assertIn("high-value-event-id:4104", powershell["details"]["risk_flags"])
            self.assertIn("suspicious-term:powershell -enc", powershell["details"]["risk_flags"])
            rules_by_id = {item["details"]["rule"]["id"]: item for item in detection_rows}
            self.assertEqual(rules_by_id["RT-PS-001"]["details"]["rule"]["title"], "Suspicious Encoded PowerShell")
            self.assertEqual(rules_by_id["RT-PS-001"]["details"]["coverage_status"], "detected-by-rule")
            self.assertEqual(rules_by_id["RT-EVTX-PS-ENCODED"]["details"]["parser"], "windows-eventlog-builtin-rulepack")
            self.assertEqual(rules_by_id["RT-EVTX-PS-ENCODED"]["details"]["matched_event"]["record_id"], "202")
            self.assertIn("script_block_text", rules_by_id["RT-EVTX-PS-ENCODED"]["details"]["matched_fields"])
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
            self.assertEqual(native_evtx["details"]["command_line"], "powershell -enc NativeFixture")
            self.assertEqual(native_evtx["details"]["native_indicators"]["channel_hint_source"], "record-string")
            self.assertEqual(native_evtx["details"]["evtx_record_integrity"]["declared_size_valid"], True)
            self.assertEqual(native_evtx["details"]["evtx_record_integrity"]["trailing_size_valid"], True)
            self.assertEqual(native_evtx["details"]["evtx_file_header"]["signature_valid"], True)
            self.assertEqual(native_evtx["details"]["evtx_chunk_context"]["chunk_signature_valid"], False)
            self.assertTrue(
                any(item["name"] == "CommandLine" for item in native_evtx["details"]["parameter_candidates"])
            )
            self.assertEqual(native_evtx["details"]["evtx_record_sequence"]["status"], "first-record")
            self.assertEqual(len(native_evtx["details"]["evtx_record_sha256"]), 64)
            self.assertGreaterEqual(native_evtx["details"]["parser_confidence"], 0.75)
            self.assertIn("suspicious-term:powershell -enc", native_evtx["details"]["risk_flags"])
            summary = summary_rows[0]["details"]
            self.assertEqual(summary["event_count"], 3)
            self.assertEqual(summary["detection_count"], 3)
            self.assertEqual(summary["parsed_row_count"], 6)
            self.assertEqual(summary["first_event_at"], "2024-04-01T01:02:03.000000+00:00")
            self.assertIn({"value": "4104", "count": 1}, summary["event_id_counts"])
            self.assertIn({"value": "execution", "count": 2}, summary["event_family_counts"])
            self.assertIn({"value": "powershell -enc", "count": 2}, summary["risk_term_counts"])
            self.assertIn({"value": "RT-EVTX-PS-ENCODED", "count": 1}, summary["detection_rule_counts"])
            self.assertIn({"value": "trailing-size-valid", "count": 1}, summary["native_integrity_counts"])
            self.assertIn({"value": "first-record", "count": 1}, summary["native_sequence_counts"])
            self.assertIn({"value": "record-string", "count": 1}, summary["native_channel_hint_counts"])
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
            self.assertEqual(native_rows[0]["details"]["channel"], "Security")
            self.assertEqual(native_rows[0]["details"]["command_line"], "wevtutil cl Security")

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
            sam_candidates = [item for item in artifacts if item["artifact_type"] == "windows-sam-account-candidate"]

            self.assertTrue(profiles)
            self.assertEqual(profiles[0]["details"]["user_name"], "alice")
            self.assertEqual(profiles[0]["details"]["source_path"], str(fixture.user_profile.resolve()))
            self.assertTrue(profiles[0]["details"]["ntuser_dat_present"])
            self.assertTrue(summaries)
            self.assertIn("WIN-FIXTURE", summaries[0]["details"]["computer_names"])
            self.assertIn("Korea Standard Time", summaries[0]["details"]["time_zones"])
            self.assertIn("2024-04-01T01:02:03+00:00", summaries[0]["details"]["last_boot_times"])
            self.assertIn("2024-04-01T00:55:01+00:00", summaries[0]["details"]["shutdown_times"])
            account_hints = {
                item["user_name"]: item
                for item in summaries[0]["details"]["account_lifecycle_hints"]
                if item.get("user_name")
            }
            self.assertEqual(account_hints["alice"]["created_at"], "2024-03-01T00:00:00+00:00")
            self.assertEqual(account_hints["alice"]["last_logon_at"], "2024-04-01T01:02:03+00:00")
            self.assertEqual(account_hints["alice"]["password_last_set_at"], "2024-03-15T12:34:56+00:00")
            self.assertTrue(account_hints["alice"]["admin_hint"])
            self.assertTrue(sam_candidates)
            alice_sam = next(item for item in sam_candidates if item["details"]["user_name_candidate"] == "alice")
            self.assertEqual(alice_sam["details"]["candidate_role"], "account-name-key")
            self.assertEqual(alice_sam["details"]["rid_hex"], "000003E9")
            self.assertEqual(alice_sam["details"]["rid_decimal"], 1001)
            self.assertTrue(alice_sam["details"]["validation_required"])
            self.assertEqual(len(alice_sam["details"]["source_hashes"]["sha256"]), 64)

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
            self.assertIn("srum-database-file", artifact_types)
            self.assertIn("srum-database-pivot", artifact_types)
            self.assertIn("windows-execution-summary", artifact_types)
            ps_rows = [item for item in artifacts if item["artifact_type"] == "powershell-history-command"]
            srum_rows = [item for item in artifacts if item["artifact_type"] == "srum-network-usage"]
            srum_database_rows = [item for item in artifacts if item["artifact_type"] == "srum-database-file"]
            srum_pivots = [item for item in artifacts if item["artifact_type"] == "srum-database-pivot"]
            self.assertTrue(any("suspicious-command:powershell -enc" in row["details"]["risk_flags"] for row in ps_rows))
            self.assertTrue(any("vssadmin delete shadows" in row["details"]["command_line"] for row in ps_rows))
            self.assertEqual(ps_rows[0]["details"]["source_path"], str(fixture.powershell_history.resolve()))
            self.assertEqual(srum_rows[0]["details"]["app_id"], "powershell.exe")
            self.assertEqual(srum_rows[0]["details"]["bytes_received"], 2048)
            self.assertEqual(srum_rows[0]["details"]["source_path"], str(fixture.srum_csv.resolve()))
            self.assertEqual(srum_database_rows[0]["details"]["source_path"], str(fixture.srum_db.resolve()))
            self.assertTrue(srum_database_rows[0]["details"]["ese_header"]["signature_valid"])
            self.assertTrue(any("powershell.exe" in value.lower() for value in srum_database_rows[0]["details"]["path_candidates"]))
            self.assertTrue(any(item["details"]["app_id"] == "powershell.exe" for item in srum_pivots))
            self.assertTrue(any(item["details"]["url"] == "https://download.example/tools/installer.exe" for item in srum_pivots))
            self.assertTrue(all(item["details"]["validation_required"] for item in srum_pivots))
            summary = next(item for item in artifacts if item["artifact_type"] == "windows-execution-summary")
            groups = {item["display_name"]: item for item in summary["details"]["groups"]}
            self.assertIn("evil.exe", groups)
            self.assertIn("powershell.exe", groups)
            self.assertIn("bam-entry", groups["evil.exe"]["signal_types"])
            self.assertIn("powershell-history-command", groups["powershell.exe"]["signal_types"])
            self.assertIn("srum-network-usage", groups["powershell.exe"]["signal_types"])
            self.assertIn("srum-database-pivot", groups["powershell.exe"]["signal_types"])
            self.assertIn("suspicious-command:powershell -enc", groups["powershell.exe"]["risk_flags"])

    def test_windows_prefetch_fixture_surfaces_run_count_and_last_run_time(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            build_windows_artifact_fixture(root)
            output = root / "prefetch.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "windows-prefetch", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            prefetch_file = next(item for item in payload["artifacts"] if item["artifact_type"] == "prefetch-file")
            references = [item for item in payload["artifacts"] if item["artifact_type"] == "prefetch-reference"]
            details = prefetch_file["details"]

            self.assertEqual(details["prefetch_parse_status"], "parsed-common-header")
            self.assertEqual(details["run_count"], 3)
            self.assertEqual(details["last_run_at"], "2024-04-01T09:10:11+00:00")
            self.assertIn(details["last_run_at"], details["last_run_times"])
            self.assertTrue(any("POWERSHELL.EXE" in path for path in details["referenced_paths"]))
            self.assertTrue(references)
            self.assertEqual(references[0]["details"]["referenced_file_name"], "POWERSHELL.EXE")
            self.assertEqual(references[0]["details"]["last_run_at"], "2024-04-01T09:10:11+00:00")
            self.assertTrue(references[0]["details"]["validation_required"])

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
            mft = [
                item
                for item in artifacts
                if item["artifact_type"] == "mft-record"
                and item["details"]["parser"] == "windows-filesystem-import"
            ]
            native_mft = [
                item
                for item in artifacts
                if item["artifact_type"] == "mft-record"
                and item["details"]["parser"] == "windows-mft-native"
            ]
            usn = [
                item
                for item in artifacts
                if item["artifact_type"] == "usn-record"
                and item["details"]["parser"] == "windows-filesystem-import"
            ]
            native_usn = [
                item
                for item in artifacts
                if item["artifact_type"] == "usn-record"
                and item["details"]["parser"] == "windows-usn-native"
            ]
            mft_files = [item for item in artifacts if item["artifact_type"] == "mft-file"]
            usn_files = [item for item in artifacts if item["artifact_type"] == "usn-journal-file"]

            self.assertEqual(mft[0]["details"]["record_number"], "42")
            self.assertTrue(mft[0]["details"]["deleted_hint"])
            self.assertEqual(mft[0]["details"]["source_path"], str(fixture.mft_csv.resolve()))
            self.assertEqual(usn[0]["details"]["reason"], "FILE_DELETE")
            self.assertEqual(usn[0]["details"]["source_path"], str(fixture.usn_jsonl.resolve()))
            self.assertEqual(mft_files[0]["details"]["source_path"], str(fixture.mft_native.resolve()))
            self.assertEqual(mft_files[0]["details"]["native_record_count"], 1)
            self.assertTrue(mft_files[0]["details"]["record_header_samples"][0]["in_use"])
            self.assertIn(r"C:\Users\alice\Desktop\deleted.txt", mft_files[0]["details"]["path_candidates"])
            self.assertEqual(native_mft[0]["details"]["record_number"], "0")
            self.assertEqual(native_mft[0]["details"]["sequence_number"], 3)
            self.assertTrue(native_mft[0]["details"]["in_use"])
            self.assertIn(r"C:\Users\alice\Desktop\deleted.txt", native_mft[0]["details"]["path_candidates"])
            self.assertTrue(native_mft[0]["details"]["validation_required"])
            self.assertEqual(usn_files[0]["details"]["source_path"], str(fixture.usn_journal.resolve()))
            self.assertEqual(usn_files[0]["details"]["native_record_count"], 2)
            self.assertIn({"value": "2", "count": 1}, usn_files[0]["details"]["record_version_counts"])
            self.assertIn({"value": "3", "count": 1}, usn_files[0]["details"]["record_version_counts"])
            self.assertEqual(native_usn[0]["details"]["file_path"], "deleted.txt")
            self.assertEqual(native_usn[0]["details"]["validation_status"], "valid")
            self.assertEqual(native_usn[0]["details"]["parser_confidence"], 0.85)
            self.assertTrue(native_usn[0]["details"]["deleted_hint"])
            self.assertIn("FILE_DELETE", native_usn[0]["details"]["reason_flags"])
            self.assertIn("ARCHIVE", native_usn[0]["details"]["file_attribute_names"])
            self.assertEqual(native_usn[1]["details"]["major_version"], 3)
            self.assertEqual(native_usn[1]["details"]["file_path"], "renamed.txt")
            self.assertEqual(native_usn[1]["details"]["rename_hint"], "rename-new-name")
            self.assertIn("CLOSE", native_usn[1]["details"]["reason_flags"])

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
            edb_pivots = [item for item in artifacts if item["artifact_type"] == "windows-search-edb-pivot"]
            summary = next(item for item in artifacts if item["artifact_type"] == "windows-search-index-summary")

            self.assertEqual(entries[0]["details"]["entry_id"], "7")
            self.assertEqual(entries[0]["details"]["file_name"], "Incident Notes.docx")
            self.assertEqual(entries[0]["details"]["extension"], ".docx")
            self.assertIn("encoded powershell", entries[0]["details"]["content_snippet"])
            self.assertEqual(entries[0]["details"]["source_path"], str(fixture.windows_search_csv.resolve()))
            self.assertEqual(edb_files[0]["details"]["source_path"], str(fixture.windows_edb.resolve()))
            self.assertTrue(edb_files[0]["details"]["ese_header"]["signature_valid"])
            self.assertIn("ese-string:powershell", edb_files[0]["details"]["risk_flags"])
            self.assertTrue(any("Incident Notes.docx" in value for value in edb_files[0]["details"]["path_candidates"]))
            self.assertTrue(any(item["details"]["file_name"] == "Incident Notes.docx" for item in edb_pivots))
            self.assertTrue(any(item["details"]["url"] == "https://example.com/browser-history" for item in edb_pivots))
            self.assertTrue(all(item["details"]["validation_required"] for item in edb_pivots))
            self.assertEqual(summary["details"]["entry_count"], 1)
            self.assertEqual(summary["details"]["inventory_count"], 1)
            self.assertGreaterEqual(summary["details"]["edb_pivot_count"], 2)
            self.assertGreater(summary["details"]["edb_string_hit_count"], 0)
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
            self.assertEqual(cache["details"]["cache_parse_status"], "image-signature-pivots")
            self.assertEqual(cache["details"]["thumbnail_candidate_count"], 1)
            self.assertEqual(cache["details"]["thumbnail_candidates"][0]["type"], "png")
            self.assertEqual(cache["details"]["thumbnail_candidates"][0]["width"], 320)
            self.assertEqual(cache["details"]["thumbnail_candidates"][0]["height"], 200)
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
            self.assertEqual(wmi[0]["details"]["coverage_status"], "bounded-string-pivot")
            self.assertIn("wmi-string:commandlineeventconsumer", wmi[0]["details"]["risk_flags"])
            self.assertTrue(any("powershell.exe" in value.lower() for value in wmi[0]["details"]["path_candidates"]))
            self.assertIn("https://example.test/wmi-payload", wmi[0]["details"]["url_candidates"])

    def test_windows_system_collector_flags_suspicious_scheduled_tasks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            fixture = build_windows_artifact_fixture(root)
            output = root / "windows-system.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "windows-system", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            task = next(item for item in payload["artifacts"] if item["artifact_type"] == "task-scheduler-task")

            self.assertEqual(task["details"]["source_path"], str(fixture.task_file.resolve()))
            self.assertEqual(task["details"]["task_uri"], r"\Microsoft\Windows\UpdateOrchestrator\SecurityUpdater")
            self.assertTrue(task["details"]["hidden"])
            self.assertIn("task-string:powershell", task["details"]["risk_flags"])
            self.assertIn("task-user-writable-path", task["details"]["risk_flags"])
            self.assertIn("task-microsoft-path-user-payload", task["details"]["risk_flags"])
            self.assertGreater(task["details"]["risk_score"], 0)


if __name__ == "__main__":
    unittest.main()
