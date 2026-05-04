from __future__ import annotations

import json
import tempfile
import unittest
from unittest import mock
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath

from rapidtriage.cli import main
from rapidtriage.artifacts.windows.eventlog import collect_native_evtx_events
from tests.windows_artifact_fixtures import (
    build_corrupt_evtx_record_candidate,
    build_evtx_with_checked_chunk,
    build_evtx_with_slack_record,
    build_minimal_evtx,
    build_template_evtx,
    build_windows_artifact_fixture,
    datetime_to_filetime,
)


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
            storage_inventory = next(
                artifact for artifact in artifacts if artifact["artifact_type"] == "browser-storage-inventory"
            )

            self.assertEqual(chrome["details"]["history_count"], 2)
            self.assertEqual(chrome["details"]["ai_usage_count"], 1)
            self.assertGreaterEqual(chrome["details"]["ai_conversation_candidate_count"], 2)
            self.assertGreaterEqual(chrome["details"]["browser_storage_inventory_count"], 5)
            self.assertGreaterEqual(chrome["details"]["browser_sensitive_inventory_count"], 3)
            self.assertFalse(chrome["details"]["commercial_grade_ready"])
            self.assertIn("cookie-value-decryption-and-legal-opt-in-not-implemented", chrome["details"]["commercial_grade_blockers"])
            self.assertIn("#19", chrome["details"]["browser_report_grade_assessment"]["commercial_gap_ids"])
            self.assertIn("#20", chrome["details"]["browser_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(chrome["details"]["forensic_review"]["gap_id"], "#20")
            self.assertFalse(chrome["details"]["forensic_review"]["report_grade_ready"])
            self.assertFalse(chrome["details"]["browser_native_capabilities"]["full_cache_entry_decode"])
            browser_gates = {gate["gap_id"]: gate for gate in chrome["details"]["core_accuracy_gates"]}
            self.assertIn("profile/source attribution", browser_gates["#19"]["satisfied_checks"])
            self.assertIn("secret/cookie opt-in legal gate", browser_gates["#19"]["satisfied_checks"])
            self.assertIn("timestamp normalization", browser_gates["#20"]["satisfied_checks"])
            self.assertIn("Safari scope limitation disclosure", browser_gates["#20"]["satisfied_checks"])
            browser_uplift = chrome["details"]["commercial_uplift_evidence"]
            self.assertEqual(browser_uplift["batch_id"], "commercial-uplift-016-020")
            self.assertEqual(browser_uplift["item_numbers"], [19, 20])
            self.assertIn("unified-timeline", browser_uplift["passed_validation_matrix_ids"])
            self.assertTrue(browser_uplift["large_data_controls"]["secret_values_redacted_by_default"])
            self.assertEqual(chrome["details"]["unified_timeline_count"], 2)
            self.assertEqual(chrome["details"]["unified_timeline"][0]["timeline_type"], "visit")
            self.assertEqual(chrome["details"]["unified_timeline"][0]["browser"], "chrome")
            self.assertIn("typed_count", chrome["details"]["history"][0])
            self.assertTrue(chrome["details"]["browser_validation_checks"]["typed_url_metadata_present"])
            self.assertIn({"value": "ai", "count": 1}, chrome["details"]["internet_category_counts"])
            self.assertEqual(ai_usage["details"]["browser"], "chrome")
            self.assertEqual(ai_usage["details"]["ai_usage_count"], 1)
            self.assertGreaterEqual(ai_usage["details"]["ai_conversation_candidate_count"], 2)
            self.assertFalse(ai_usage["details"]["commercial_grade_ready"])
            self.assertIn("#20", ai_usage["details"]["browser_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(ai_usage["details"]["forensic_review"]["gap_id"], "#21")
            self.assertEqual(ai_usage["details"]["ai_usage"][0]["ai_service"], "ChatGPT")
            self.assertEqual(ai_usage["details"]["ai_usage"][0]["url"], fixture.ai_visit.url)
            self.assertEqual(ai_usage["details"]["ai_usage"][0]["prompt_hint"], "timeline analysis for evtx")
            self.assertEqual(len(ai_usage["details"]["source_hashes"]["sha256"]), 64)
            self.assertEqual(ai_conversation["details"]["coverage_status"], "candidate")
            self.assertFalse(ai_conversation["details"]["commercial_grade_ready"])
            self.assertGreaterEqual(ai_conversation["details"]["question_count"], 2)
            self.assertGreaterEqual(ai_conversation["details"]["answer_count"], 2)
            self.assertGreaterEqual(ai_conversation["details"]["complete_pair_count"], 2)
            self.assertGreater(ai_conversation["details"]["transcript_completeness_score"], 0)
            self.assertIn("pairing_confidence_summary", ai_conversation["details"])
            self.assertEqual(ai_conversation["details"]["source_storage_summary"]["source_file_count"], 1)
            self.assertTrue(ai_conversation["details"]["transcript_validation_checks"]["has_source_hashes"])
            self.assertFalse(ai_conversation["details"]["transcript_validation_checks"]["service_side_export_validated"])
            self.assertIn("#21", ai_conversation["details"]["browser_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(ai_conversation["details"]["forensic_review"]["gap_id"], "#21")
            self.assertFalse(ai_conversation["details"]["browser_native_capabilities"]["service_side_transcript_export_validation"])
            ai_uplift = ai_conversation["details"]["commercial_uplift_evidence"]
            self.assertEqual(ai_uplift["batch_id"], "commercial-uplift-021-025")
            self.assertEqual(ai_uplift["item_numbers"], [21])
            self.assertIn("has_question_answer_pair", ai_uplift["passed_validation_check_ids"])
            self.assertIn("service_side_export_validated", ai_uplift["failed_validation_check_ids"])
            self.assertGreaterEqual(ai_uplift["candidate_quality"]["complete_pair_count"], 2)
            self.assertEqual(ai_uplift["large_data_controls"]["max_ai_storage_files"], 80)
            ai_gate = ai_conversation["details"]["core_accuracy_gates"][0]
            self.assertEqual(ai_gate["gap_id"], "#21")
            self.assertIn("service/schema version detection", ai_gate["satisfied_checks"])
            self.assertIn("question/answer pairing confidence", ai_gate["satisfied_checks"])
            self.assertIn("orphan prompt/answer tracking", ai_gate["satisfied_checks"])
            self.assertIn("source offset/storage provenance", ai_gate["satisfied_checks"])
            self.assertIn("privacy and completeness warnings", ai_gate["satisfied_checks"])
            self.assertIn(
                ai_conversation["details"]["transcript_validation_status"],
                {"paired-candidate", "partial-paired-candidate"},
            )
            transcript_pair = ai_conversation["details"]["transcript_pairs"][0]
            self.assertEqual(transcript_pair["ai_service"], "ChatGPT")
            self.assertTrue(transcript_pair["same_source"])
            self.assertEqual(transcript_pair["pairing_confidence"], "high-candidate")
            self.assertEqual(transcript_pair["validation_status"], "paired-candidate")
            candidate_text = "\n".join(
                row["text"] for row in ai_conversation["details"]["conversation_candidates"]
            )
            self.assertIn("How do I build an EVTX forensic timeline?", candidate_text)
            self.assertIn("Correlate EventRecordID", candidate_text)
            self.assertEqual(ai_conversation["details"]["conversation_candidates"][0]["storage_area"], "Local Storage/leveldb")
            self.assertEqual(storage_inventory["details"]["coverage_status"], "inventory-candidate")
            self.assertGreaterEqual(storage_inventory["details"]["sensitive_inventory_count"], 3)
            self.assertIn("#19", storage_inventory["details"]["browser_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(storage_inventory["details"]["forensic_review"]["gap_id"], "#19")
            self.assertIn("#42", storage_inventory["details"]["browser_secret_handling_assessment"]["commercial_gap_ids"])
            self.assertEqual(storage_inventory["details"]["secret_handling_forensic_review"]["gap_id"], "#42")
            self.assertFalse(storage_inventory["details"]["browser_native_capabilities"]["cookie_value_decryption"])
            self.assertFalse(storage_inventory["details"]["browser_native_capabilities"]["password_cookie_session_secret_extraction"])
            self.assertFalse(storage_inventory["details"]["validation_checks"]["raw_secret_values_extracted"])
            self.assertFalse(storage_inventory["details"]["secret_handling_validation_checks"]["password_values_decrypted"])
            self.assertFalse(storage_inventory["details"]["secret_handling_validation_checks"]["session_tokens_extracted"])
            self.assertIn("Browser cache, session, sync, cookie", storage_inventory["details"]["privacy_legal_warning"])
            self.assertIn("Password, cookie, and session stores", storage_inventory["details"]["browser_secret_legal_warning"])
            storage_gates = {gate["gap_id"]: gate for gate in storage_inventory["details"]["core_accuracy_gates"]}
            self.assertIn("extension ID/source mapping", storage_gates["#19"]["satisfied_checks"])
            self.assertIn("deleted/synced content warning", storage_gates["#19"]["satisfied_checks"])
            self.assertIn("sensitive artifact inventory", storage_gates["#42"]["satisfied_checks"])
            self.assertIn("secret values redacted by default", storage_gates["#42"]["satisfied_checks"])
            self.assertIn("strict legal warning", storage_gates["#42"]["satisfied_checks"])
            self.assertIn("opt-in reveal workflow warning", storage_gates["#42"]["satisfied_checks"])
            self.assertIn("audit and scope review requirement", storage_gates["#42"]["satisfied_checks"])
            secret_uplift = storage_inventory["details"]["secret_handling_commercial_uplift_evidence"]
            self.assertEqual(secret_uplift["batch_id"], "commercial-uplift-041-045")
            self.assertEqual(secret_uplift["item_numbers"], [42])
            self.assertIn("raw-secret-values-redacted", secret_uplift["passed_control_ids"])
            self.assertIn("strict_legal_warning_present", secret_uplift["passed_control_ids"])
            self.assertTrue(secret_uplift["large_data_controls"]["secret_values_redacted_by_default"])
            self.assertFalse(secret_uplift["large_data_controls"]["dpapi_keychain_integration"])
            storage_uplift = storage_inventory["details"]["commercial_uplift_evidence"]
            self.assertEqual(storage_uplift["batch_id"], "commercial-uplift-016-020")
            self.assertEqual(storage_uplift["item_numbers"], [19, 20])
            self.assertGreaterEqual(storage_uplift["large_data_controls"]["storage_inventory_count"], 5)
            inventory_types = {row["storage_type"] for row in storage_inventory["details"]["storage_inventory"]}
            self.assertIn("cache", inventory_types)
            self.assertIn("cookie", inventory_types)
            self.assertIn("extension", inventory_types)

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
            self.assertFalse(details["commercial_grade_ready"])
            self.assertIn("#17", details["recent_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(details["forensic_review"]["gap_id"], "#17")
            self.assertFalse(details["forensic_review"]["report_grade_ready"])
            self.assertFalse(details["recent_native_capabilities"]["full_shell_item_property_store_decode"])
            self.assertTrue(details["validation_checks"]["has_tracker_data"])
            self.assertEqual(details["validation_checks"]["extra_data_block_count"], 1)
            self.assertEqual(details["extra_data_blocks"][0]["type"], "TrackerDataBlock")
            self.assertEqual(details["tracker_data"]["machine_id"], "ALICE-PC")
            self.assertEqual(details["tracker_data"]["parse_status"], "parsed-candidate")
            self.assertIn("candidate", details["tracker_data"]["validation_status"])
            lnk_gate = details["core_accuracy_gates"][0]
            self.assertEqual(lnk_gate["gap_id"], "#17")
            self.assertIn("header flag consistency", lnk_gate["satisfied_checks"])
            self.assertIn("target/working-dir/arguments extraction", lnk_gate["satisfied_checks"])
            self.assertIn("tracker GUID validation", lnk_gate["satisfied_checks"])
            self.assertIn("timestamp/source field provenance", lnk_gate["satisfied_checks"])
            lnk_uplift = details["commercial_uplift_evidence"]
            self.assertEqual(lnk_uplift["batch_id"], "commercial-uplift-016-020")
            self.assertEqual(lnk_uplift["item_numbers"], [17])
            self.assertIn("has-valid-header", lnk_uplift["passed_validation_matrix_ids"])
            self.assertTrue(lnk_uplift["large_data_controls"]["property_store_decode_required_for_commercial_claims"])
            self.assertEqual(len(details["source_hashes"]["sha256"]), 64)
            self.assertEqual(automatic["details"]["jump_list_parse_status"], "parsed-ole-stream-lnk")
            self.assertEqual(automatic["details"]["ole_parse_status"], "parsed")
            self.assertEqual(automatic["details"]["ole_stream_count"], 2)
            self.assertEqual(automatic["details"]["destlist_parse_status"], "parsed-candidate")
            self.assertEqual(automatic["details"]["destlist_stream_count"], 1)
            self.assertEqual(automatic["details"]["destlist_entry_candidate_count"], 1)
            self.assertTrue(automatic["details"]["destlist_validation_checks"]["declared_count_matches_candidates"])
            self.assertEqual(automatic["details"]["jumplist_evidence"]["container"]["kind"], "automatic")
            self.assertIn("DestList", automatic["details"]["jumplist_evidence"]["container"]["stream_names"])
            self.assertEqual(
                automatic["details"]["jumplist_evidence"]["destlist"]["parse_status"],
                "parsed-candidate",
            )
            self.assertEqual(automatic["details"]["jumplist_evidence"]["destlist"]["candidate_count"], 1)
            self.assertFalse(automatic["details"]["validation_checks"]["destlist_report_grade"])
            self.assertIn(
                "destlist-os-version-specific-field-validation-required",
                automatic["details"]["commercial_grade_blockers"],
            )
            self.assertIn("#14", automatic["details"]["recent_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(automatic["details"]["forensic_review"]["gap_id"], "#14")
            self.assertIn("JumpList", automatic["details"]["forensic_review"]["artifact_goal"])
            self.assertFalse(automatic["details"]["recent_native_capabilities"]["destlist_deleted_entry_recovery"])
            self.assertEqual(automatic["details"]["destination_count"], 1)
            self.assertEqual(automatic["details"]["destinations"][0]["target_path"], r"C:\Users\alice\Documents\Incident Notes.docx")
            self.assertTrue(automatic["details"]["destinations"][0]["has_tracker_data"])
            self.assertEqual(automatic["details"]["destinations"][0]["stream_path"], "1")
            self.assertEqual(automatic["details"]["destinations"][0]["destlist_validation_status"], "candidate-linked-lnk-stream")
            self.assertEqual(
                automatic["details"]["jumplist_evidence"]["destinations"][0]["target_path"],
                r"C:\Users\alice\Documents\Incident Notes.docx",
            )
            self.assertEqual(
                automatic["details"]["jumplist_evidence"]["destinations"][0]["destlist_validation_status"],
                "candidate-linked-lnk-stream",
            )
            jumplist_gate = automatic["details"]["core_accuracy_gates"][0]
            self.assertEqual(jumplist_gate["gap_id"], "#14")
            self.assertIn("CFB stream inventory", jumplist_gate["satisfied_checks"])
            self.assertIn("DestList header/entry layout", jumplist_gate["satisfied_checks"])
            self.assertIn("embedded LNK linkage", jumplist_gate["satisfied_checks"])
            self.assertIn("AppID mapping provenance", jumplist_gate["satisfied_checks"])
            self.assertIn("deleted-entry warning", jumplist_gate["satisfied_checks"])
            jumplist_uplift = automatic["details"]["commercial_uplift_evidence"]
            self.assertEqual(jumplist_uplift["batch_id"], "commercial-uplift-011-015")
            self.assertEqual(jumplist_uplift["item_numbers"], [14])
            self.assertIn("has-destlist-stream", jumplist_uplift["passed_validation_matrix_ids"])
            self.assertTrue(
                jumplist_uplift["large_data_controls"]["deleted_entry_recovery_required_for_commercial_claims"]
            )
            self.assertIn(r"C:\Users\alice\Documents\Incident Notes.docx", automatic["details"]["embedded_paths"])
            self.assertEqual(custom["details"]["destinations"][0]["target_path"], r"C:\Users\alice\Downloads\installer.exe")

    def test_eventlog_collector_uses_provider_message_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            logs = root / "Windows" / "System32" / "winevt" / "Logs"
            logs.mkdir(parents=True)
            event_xml = logs / "CustomProvider.xml"
            event_xml.write_text(
                """<Events><Event>
  <System>
    <Provider Name="Custom-Provider"/>
    <EventID>9001</EventID>
    <EventRecordID>7</EventRecordID>
    <Channel>Custom/Operational</Channel>
    <TimeCreated SystemTime="2026-04-30T01:02:03Z"/>
    <Computer>HOST1</Computer>
  </System>
  <EventData>
    <Data Name="User">alice</Data>
    <Data Name="Action">opened case</Data>
  </EventData>
</Event></Events>""",
                encoding="utf-8",
            )
            catalog = root / "message-catalog.json"
            catalog.write_text(
                json.dumps(
                    {
                        "templates": [
                            {
                                "provider": "Custom-Provider",
                                "event_id": "9001",
                                "message": "Custom provider event. User={User}; action={Action}.",
                                "source": "unit-test-provider-manifest",
                                "source_type": "manifest-export",
                                "locale": "en-US",
                                "message_id": "9001",
                                "extraction_tool": "fixture-manifest-dump",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            output = root / "eventlog.json"

            self.assertEqual(
                main(
                    [
                        "artifacts",
                        str(root),
                        "--kind",
                        "eventlog",
                        "--eventlog-message-catalog",
                        str(catalog),
                        "--output",
                        str(output),
                    ]
                ),
                0,
            )
            payload = json.loads(output.read_text(encoding="utf-8"))
            event = next(item for item in payload["artifacts"] if item["artifact_type"] == "eventlog-event")
            rendering = event["details"]["message_rendering"]
            self.assertEqual(rendering["status"], "rendered-provider-catalog-template")
            self.assertEqual(event["details"]["event_message"], "Custom provider event. User=alice; action=opened case.")
            self.assertTrue(rendering["provenance"]["provider_message_resource_resolved"])
            self.assertEqual(
                rendering["provenance"]["provider_message_resource_source"]["source"],
                "unit-test-provider-manifest",
            )
            self.assertEqual(
                rendering["provenance"]["provider_message_resource_source"]["source_type"],
                "manifest-export",
            )
            self.assertEqual(
                rendering["provenance"]["provider_message_resource_source"]["message_id"],
                "9001",
            )
            self.assertEqual(
                rendering["provenance"]["provider_message_resource_source"]["extraction_tool"],
                "fixture-manifest-dump",
            )
            self.assertEqual(
                len(rendering["provenance"]["provider_message_resource_source"]["template_sha256"]),
                64,
            )

    def test_native_evtx_can_render_from_curated_provider_message_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            evtx_path = root / "Windows" / "System32" / "winevt" / "Logs" / "PowerShell.evtx"
            evtx_path.parent.mkdir(parents=True, exist_ok=True)
            evtx_path.write_bytes(
                build_template_evtx(
                    record_id=901,
                    timestamp=datetime(2024, 4, 4, 1, 2, 3, tzinfo=timezone.utc),
                    command="powershell -enc CatalogNative",
                )
            )
            catalog = root / "message-catalog.json"
            catalog.write_text(
                json.dumps(
                    {
                        "templates": [
                            {
                                "provider": "Microsoft-Windows-PowerShell",
                                "event_id": "4104",
                                "message": "Catalog PowerShell script block: {CommandLine}.",
                                "source": "fixture-provider-resource-table",
                                "source_type": "resource-table-export",
                                "locale": "en-US",
                                "message_id": "4104",
                                "extraction_tool": "fixture-resource-extractor",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            output = root / "eventlog.json"

            self.assertEqual(
                main(
                    [
                        "artifacts",
                        str(root),
                        "--kind",
                        "eventlog",
                        "--eventlog-message-catalog",
                        str(catalog),
                        "--output",
                        str(output),
                    ]
                ),
                0,
            )
            artifacts = json.loads(output.read_text(encoding="utf-8"))["artifacts"]
            native_evtx = next(
                item
                for item in artifacts
                if item["artifact_type"] == "eventlog-event"
                and item["details"]["parser"] == "windows-eventlog-evtx-native"
            )["details"]
            rendering = native_evtx["message_rendering"]
            source = rendering["provenance"]["provider_message_resource_source"]

            self.assertEqual(rendering["status"], "rendered-provider-catalog-template")
            self.assertEqual(native_evtx["event_message"], "Catalog PowerShell script block: powershell -enc CatalogNative.")
            self.assertFalse(rendering["provider_resource_required"])
            self.assertTrue(rendering["provenance"]["provider_message_resource_resolved"])
            self.assertEqual(source["source_type"], "resource-table-export")
            self.assertEqual(source["message_id"], "4104")
            self.assertEqual(source["extraction_tool"], "fixture-resource-extractor")
            self.assertEqual(len(source["template_sha256"]), 64)
            self.assertNotIn(
                "provider-message-resource-rendering-not-implemented",
                native_evtx["evtx_report_grade_assessment"]["blockers"],
            )
            self.assertTrue(native_evtx["evtx_native_capabilities"]["curated_provider_message_catalog"])
            self.assertFalse(native_evtx["commercial_grade_ready"])

    def test_native_evtx_can_render_from_windows_event_manifest_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            evtx_path = root / "Windows" / "System32" / "winevt" / "Logs" / "PowerShell.evtx"
            evtx_path.parent.mkdir(parents=True, exist_ok=True)
            evtx_path.write_bytes(
                build_template_evtx(
                    record_id=902,
                    timestamp=datetime(2024, 4, 4, 1, 2, 3, tzinfo=timezone.utc),
                    command="powershell -enc ManifestNative",
                )
            )
            manifest = root / "powershell-provider.man"
            manifest.write_text(
                """<instrumentationManifest xmlns="http://schemas.microsoft.com/win/2004/08/events">
  <instrumentation>
    <events>
      <provider name="Microsoft-Windows-PowerShell" guid="{a0c1853b-5c40-4b15-8766-3cf1c58f985a}">
        <events>
          <event value="4104" message="$(string.PS.4104.message)" />
        </events>
      </provider>
    </events>
  </instrumentation>
  <localization>
    <resources culture="en-US">
      <stringTable>
        <string id="PS.4104.message" value="Manifest PowerShell script block: {CommandLine}." />
      </stringTable>
    </resources>
  </localization>
</instrumentationManifest>""",
                encoding="utf-8",
            )
            output = root / "eventlog.json"

            self.assertEqual(
                main(
                    [
                        "artifacts",
                        str(root),
                        "--kind",
                        "eventlog",
                        "--eventlog-message-catalog",
                        str(manifest),
                        "--output",
                        str(output),
                    ]
                ),
                0,
            )
            artifacts = json.loads(output.read_text(encoding="utf-8"))["artifacts"]
            native_evtx = next(
                item
                for item in artifacts
                if item["artifact_type"] == "eventlog-event"
                and item["details"]["parser"] == "windows-eventlog-evtx-native"
            )["details"]
            rendering = native_evtx["message_rendering"]
            source = rendering["provenance"]["provider_message_resource_source"]

            self.assertEqual(rendering["status"], "rendered-provider-catalog-template")
            self.assertEqual(native_evtx["event_message"], "Manifest PowerShell script block: powershell -enc ManifestNative.")
            self.assertTrue(rendering["provenance"]["provider_message_resource_resolved"])
            self.assertEqual(source["source"], "windows-event-manifest")
            self.assertEqual(source["source_type"], "windows-event-manifest")
            self.assertEqual(source["locale"], "en-US")
            self.assertEqual(source["message_id"], "$(string.PS.4104.message)")
            self.assertEqual(source["extraction_tool"], "rapidtriage-manifest-loader")
            self.assertEqual(len(source["template_sha256"]), 64)
            self.assertFalse(native_evtx["commercial_grade_ready"])

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
            self.assertEqual(logon["details"]["event_message"], "An account was successfully logged on.")
            self.assertEqual(logon["details"]["message_rendering"]["status"], "external-message")
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
            encoded_powershell_rules = [
                item for item in detection_rows if item["details"]["rule"]["id"] == "RT-EVTX-PS-ENCODED"
            ]
            self.assertEqual(rules_by_id["RT-PS-001"]["details"]["rule"]["title"], "Suspicious Encoded PowerShell")
            self.assertEqual(rules_by_id["RT-PS-001"]["details"]["coverage_status"], "detected-by-rule")
            self.assertTrue(
                any(item["details"]["parser"] == "windows-eventlog-builtin-rulepack" for item in encoded_powershell_rules)
            )
            self.assertTrue(
                any(item["details"]["matched_event"]["record_id"] == "202" for item in encoded_powershell_rules)
            )
            self.assertTrue(
                any("script_block_text" in item["details"]["matched_fields"] for item in encoded_powershell_rules)
            )
            self.assertEqual(rules_by_id["RT-EVTX-RDP-LOGON"]["details"]["logon_type"], "10")
            self.assertEqual(inventory_rows[0]["details"]["coverage_status"], "detected")
            self.assertEqual(inventory_rows[0]["details"]["source_path"], str(fixture.evtx_file.resolve()))
            self.assertEqual(inventory_rows[0]["details"]["native_record_count"], 1)
            native_evtx = [item for item in event_rows if item["details"]["parser"] == "windows-eventlog-evtx-native"][0]
            self.assertEqual(native_evtx["details"]["coverage_status"], "native-binary-partial")
            self.assertEqual(native_evtx["details"]["reportability"], "triage")
            self.assertEqual(native_evtx["details"]["record_id"], "300")
            self.assertEqual(native_evtx["details"]["event_id"], "4104")
            self.assertEqual(native_evtx["details"]["level"], "3")
            self.assertEqual(native_evtx["details"]["timestamp"], "2024-04-01T03:04:05+00:00")
            self.assertIn("powershell -enc NativeFixture", native_evtx["details"]["extracted_strings"])
            self.assertEqual(native_evtx["details"]["command_line"], "powershell -enc NativeFixture")
            self.assertEqual(native_evtx["details"]["provider_name"], "Microsoft-Windows-PowerShell")
            self.assertEqual(native_evtx["details"]["binxml_system_fields"]["EventID"], "4104")
            self.assertEqual(native_evtx["details"]["binxml_system_fields"]["TimeCreated"], "2024-04-01T03:04:05+00:00")
            self.assertEqual(native_evtx["details"]["binxml_system_fields"]["ProcessID"], "4321")
            self.assertEqual(native_evtx["details"]["binxml_system_fields"]["ThreadID"], "8765")
            self.assertEqual(native_evtx["details"]["binxml_system_fields"]["UserID"], "S-1-5-21-111-222-333-1001")
            self.assertEqual(native_evtx["details"]["binxml_event_data_fields"]["CommandLine"], "powershell -enc NativeFixture")
            self.assertEqual(native_evtx["details"]["binxml_event_data_fields"]["SubjectUserSid"], "S-1-5-21-111-222-333-1001")
            self.assertEqual(native_evtx["details"]["binxml_event_data_fields"]["ProcessId"], "4321")
            self.assertEqual(native_evtx["details"]["binxml_event_data_fields"]["IsElevated"], "true")
            self.assertEqual(native_evtx["details"]["binxml_event_data_fields"]["CpuSeconds"], "12.5")
            self.assertEqual(native_evtx["details"]["binxml_event_data_fields"]["RiskRatio"], "0.25")
            self.assertEqual(native_evtx["details"]["binxml_event_data_fields"]["ActivityGuid"], "33221100-5544-7766-8899-aabbccddeeff")
            self.assertEqual(native_evtx["details"]["binxml_event_data_fields"]["PayloadHash"], "feedface")
            self.assertIn(
                {"index": 0, "name": "CommandLine", "value": "powershell -enc NativeFixture", "path": "Event/EventData/CommandLine", "value_type": "StringType", "confidence": "binxml-value-text"},
                native_evtx["details"]["binxml_event_data_sequence"],
            )
            self.assertEqual(
                native_evtx["details"]["binxml_event_data_values_by_name"]["CommandLine"],
                ["powershell -enc NativeFixture"],
            )
            self.assertEqual(native_evtx["details"]["process_id"], "4321")
            self.assertEqual(native_evtx["details"]["thread_id"], "8765")
            self.assertEqual(native_evtx["details"]["user_sid"], "S-1-5-21-111-222-333-1001")
            self.assertEqual(native_evtx["details"]["message_rendering"]["status"], "rendered-builtin-template")
            self.assertTrue(native_evtx["details"]["message_rendering"]["validation_required"])
            self.assertEqual(
                native_evtx["details"]["message_rendering"]["provenance"]["renderer"],
                "rapidtriage-builtin-template",
            )
            self.assertFalse(
                native_evtx["details"]["message_rendering"]["provenance"]["provider_message_resource_resolved"]
            )
            self.assertIn("PowerShell script block", native_evtx["details"]["event_message"])
            self.assertIn(
                {"expression": "ScriptBlockText|CommandLine|Payload", "field": "CommandLine"},
                native_evtx["details"]["message_rendering"]["used_fields"],
            )
            self.assertIn(
                "CommandLine",
                native_evtx["details"]["message_rendering"]["available_field_summary"]["event_data_field_names"],
            )
            self.assertIn(
                "Event/EventData/CommandLine",
                native_evtx["details"]["message_rendering"]["available_field_summary"]["binxml_value_field_paths"],
            )
            self.assertEqual(native_evtx["details"]["native_indicators"]["channel_hint_source"], "record-string")
            self.assertEqual(native_evtx["details"]["evtx_record_integrity"]["declared_size_valid"], True)
            self.assertEqual(native_evtx["details"]["evtx_record_integrity"]["trailing_size_valid"], True)
            self.assertEqual(native_evtx["details"]["evtx_file_header"]["signature_valid"], True)
            self.assertEqual(native_evtx["details"]["evtx_file_header"]["major_version"], 3)
            self.assertEqual(native_evtx["details"]["evtx_file_header"]["next_record_identifier"], 301)
            self.assertEqual(native_evtx["details"]["evtx_chunk_context"]["chunk_signature_valid"], False)
            self.assertEqual(native_evtx["details"]["evtx_chunk_context"]["chunk_validation_status"], "missing-or-not-a-chunk-header")
            self.assertEqual(native_evtx["details"]["evtx_chunk_context"]["chunk_boundary_status"], "no-valid-chunk-header")
            self.assertEqual(native_evtx["details"]["evtx_binxml_status"], "basic-rendered")
            self.assertEqual(native_evtx["details"]["evtx_field_fidelity"], "partial-binxml-token-scan")
            self.assertFalse(native_evtx["details"]["evtx_validation_required"])
            self.assertFalse(native_evtx["details"]["validation_required"])
            self.assertTrue(native_evtx["details"]["evtx_validation_checks"]["passes_basic_record_integrity"])
            self.assertFalse(native_evtx["details"]["evtx_report_grade_assessment"]["report_grade_ready"])
            self.assertEqual(
                native_evtx["details"]["evtx_report_grade_assessment"]["status"],
                "triage-validated-report-grade-blocked",
            )
            self.assertIn(
                "provider-message-resource-rendering-required",
                native_evtx["details"]["evtx_report_grade_assessment"]["blockers"],
            )
            self.assertIn("#1", native_evtx["details"]["evtx_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(native_evtx["details"]["evtx_reader_strategy"], "mmap-bounded-record-scan")
            uplift = native_evtx["details"]["commercial_uplift_evidence"]
            self.assertEqual(uplift["batch_id"], "commercial-uplift-001-005")
            self.assertEqual(uplift["item_numbers"], [1, 2, 3])
            self.assertEqual(uplift["implementation_track"], "native-parser-depth")
            self.assertIn("record-magic", uplift["passed_validation_matrix_ids"])
            self.assertIn("chunk-context", uplift["failed_validation_matrix_ids"])
            self.assertEqual(uplift["large_data_controls"]["current_reader"], "mmap-bounded-record-scan")
            self.assertEqual(uplift["large_data_controls"]["source_hash_strategy"], "streaming-sha256")
            self.assertFalse(uplift["large_data_controls"]["streaming_reader_required_for_tb_claims"])
            self.assertTrue(uplift["large_data_controls"]["remaining_large_data_proof_required"])
            self.assertTrue(native_evtx["details"]["evtx_native_capabilities"]["template_substitution_values"])
            self.assertFalse(native_evtx["details"]["evtx_native_capabilities"]["provider_resource_message_rendering"])
            validation_matrix = {item["id"]: item for item in native_evtx["details"]["evtx_validation_matrix"]}
            self.assertTrue(validation_matrix["record-magic"]["passed"])
            self.assertTrue(validation_matrix["binxml-field-decode"]["passed"])
            self.assertFalse(validation_matrix["chunk-context"]["passed"])
            decoded_type_counts = {
                item["value"]: item["count"]
                for item in native_evtx["details"]["evtx_validation_checks"]["decoded_value_type_counts"]
            }
            self.assertGreaterEqual(decoded_type_counts["Real64Type"], 1)
            self.assertGreaterEqual(decoded_type_counts["Real32Type"], 1)
            self.assertTrue(native_evtx["details"]["evtx_validation_checks"]["value_field_map_present"])
            self.assertEqual(native_evtx["details"]["evtx_validation_checks"]["template_substitution_count"], 0)
            self.assertIn("<Event><System>", native_evtx["details"]["native_message_preview"])
            self.assertIn("powershell -enc NativeFixture", native_evtx["details"]["evtx_binxml"]["rendered_preview"])
            self.assertEqual(
                native_evtx["details"]["evtx_binxml"]["value_field_map"]["Event/EventData/CommandLine"],
                ["powershell -enc NativeFixture"],
            )
            self.assertTrue(
                any(item["name"] == "CommandLine" for item in native_evtx["details"]["evtx_binxml"]["elements"])
            )
            self.assertTrue(
                any(
                    item["element_path"] == "Event/EventData/CommandLine"
                    and item["text"] == "powershell -enc NativeFixture"
                    for item in native_evtx["details"]["evtx_binxml"]["value_fields"]
                )
            )
            self.assertTrue(
                any(
                    item["element_path"] == "Event/EventData/ProcessId"
                    and item["text"] == "4321"
                    and item["value_type"] == "UInt32Type"
                    for item in native_evtx["details"]["evtx_binxml"]["value_fields"]
                )
            )
            self.assertTrue(
                any(item["name"] == "CommandLine" for item in native_evtx["details"]["parameter_candidates"])
            )
            self.assertEqual(native_evtx["details"]["evtx_record_sequence"]["status"], "first-record")
            self.assertEqual(len(native_evtx["details"]["evtx_record_sha256"]), 64)
            self.assertGreaterEqual(native_evtx["details"]["parser_confidence"], 0.75)
            self.assertIn("suspicious-term:powershell -enc", native_evtx["details"]["risk_flags"])
            summary = summary_rows[0]["details"]
            self.assertEqual(summary["event_count"], 3)
            self.assertEqual(summary["detection_count"], 4)
            self.assertEqual(summary["parsed_row_count"], 7)
            self.assertEqual(summary["first_event_at"], "2024-04-01T01:02:03.000000+00:00")
            self.assertIn({"value": "4104", "count": 2}, summary["event_id_counts"])
            self.assertIn({"value": "execution", "count": 2}, summary["event_family_counts"])
            self.assertIn({"value": "powershell -enc", "count": 2}, summary["risk_term_counts"])
            self.assertIn({"value": "RT-EVTX-PS-ENCODED", "count": 2}, summary["detection_rule_counts"])
            self.assertIn({"value": "trailing-size-valid", "count": 1}, summary["native_integrity_counts"])
            self.assertIn({"value": "first-record", "count": 1}, summary["native_sequence_counts"])
            self.assertIn({"value": "record-string", "count": 1}, summary["native_channel_hint_counts"])
            self.assertIn({"value": "basic-rendered", "count": 1}, summary["native_binxml_status_counts"])
            self.assertIn({"value": "no-valid-chunk-header", "count": 1}, summary["native_boundary_status_counts"])
            self.assertIn(
                {"value": "triage-validated-report-grade-blocked", "count": 1},
                summary["native_report_grade_status_counts"],
            )
            self.assertFalse(summary["native_capabilities"]["provider_resource_message_rendering"])
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

    def test_native_evtx_collector_uses_mmap_reader_instead_of_read_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            evtx_path = root / "Security.evtx"
            evtx_path.write_bytes(
                build_minimal_evtx(
                    record_id=778,
                    timestamp=datetime(2024, 4, 2, 2, 3, 4, tzinfo=timezone.utc),
                    strings=["Microsoft-Windows-Security-Auditing", "Security", "WIN-MMAP", "wevtutil gl Security"],
                )
            )

            with mock.patch.object(Path, "read_bytes", side_effect=AssertionError("EVTX collector must not read full files")):
                artifacts = list(collect_native_evtx_events(evtx_path))

            native_evtx = next(
                item
                for item in artifacts
                if item.artifact_type == "eventlog-event"
                and item.details["parser"] == "windows-eventlog-evtx-native"
            )
            self.assertEqual(native_evtx.details["record_id"], "778")
            self.assertEqual(native_evtx.details["evtx_reader_strategy"], "mmap-bounded-record-scan")
            self.assertEqual(native_evtx.details["commercial_uplift_evidence"]["large_data_controls"]["current_reader"], "mmap-bounded-record-scan")

    def test_eventlog_collector_validates_native_evtx_chunk_checksums(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            evtx_path = root / "Windows" / "System32" / "winevt" / "Logs" / "Checked.evtx"
            evtx_path.parent.mkdir(parents=True, exist_ok=True)
            evtx_path.write_bytes(
                build_evtx_with_checked_chunk(
                    record_id=779,
                    timestamp=datetime(2024, 4, 2, 3, 4, 5, tzinfo=timezone.utc),
                    strings=["Microsoft-Windows-Security-Auditing", "Security", "WIN-CRC", "wevtutil gli Security"],
                )
            )
            output = root / "eventlog.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "eventlog", "--output", str(output)]), 0)
            artifacts = json.loads(output.read_text(encoding="utf-8"))["artifacts"]
            chunk = next(item for item in artifacts if item["artifact_type"] == "eventlog-chunk")["details"]
            native_evtx = next(
                item
                for item in artifacts
                if item["artifact_type"] == "eventlog-event"
                and item["details"]["parser"] == "windows-eventlog-evtx-native"
            )["details"]
            summary = next(item for item in artifacts if item["artifact_type"] == "eventlog-summary")["details"]

            self.assertEqual(native_evtx["record_id"], "779")
            self.assertEqual(chunk["evtx_chunk_integrity"]["checksum_status"], "matched")
            self.assertTrue(chunk["evtx_chunk_integrity"]["header_checksum_match"])
            self.assertTrue(chunk["evtx_chunk_integrity"]["events_checksum_match"])
            self.assertIn({"value": "matched", "count": 1}, summary["native_chunk_integrity_counts"])

    def test_eventlog_collector_decodes_native_evtx_template_substitution_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            evtx_path = root / "Windows" / "System32" / "winevt" / "Logs" / "Template.evtx"
            evtx_path.parent.mkdir(parents=True, exist_ok=True)
            evtx_path.write_bytes(
                build_template_evtx(
                    record_id=888,
                    timestamp=datetime(2024, 4, 3, 1, 2, 3, tzinfo=timezone.utc),
                    command="powershell -enc TemplateValue",
                )
            )
            output = root / "eventlog.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "eventlog", "--output", str(output)]), 0)
            artifacts = json.loads(output.read_text(encoding="utf-8"))["artifacts"]
            native_evtx = next(
                item
                for item in artifacts
                if item["artifact_type"] == "eventlog-event"
                and item["details"]["parser"] == "windows-eventlog-evtx-native"
            )

            self.assertEqual(native_evtx["details"]["record_id"], "888")
            self.assertEqual(native_evtx["details"]["event_id"], "4104")
            self.assertEqual(native_evtx["details"]["level"], "3")
            self.assertEqual(native_evtx["details"]["provider_name"], "Microsoft-Windows-PowerShell")
            self.assertEqual(native_evtx["details"]["channel"], "Microsoft-Windows-PowerShell/Operational")
            self.assertEqual(native_evtx["details"]["evtx_binxml_status"], "template-substituted-partial")
            self.assertEqual(native_evtx["details"]["evtx_field_fidelity"], "partial-binxml-template-substitution")
            self.assertIn("powershell -enc TemplateValue", native_evtx["details"]["command_line"])
            self.assertIn("powershell -enc TemplateValue", native_evtx["details"]["evtx_binxml"]["rendered_preview"])
            self.assertIn(
                "33221100-5544-7766-8899-aabbccddeeff",
                native_evtx["details"]["evtx_binxml"]["template_ids"],
            )
            self.assertIn(
                "33221100-5544-7766-8899-aabbccddeeff",
                native_evtx["details"]["message_rendering"]["template_ids"],
            )
            self.assertEqual(native_evtx["details"]["binxml_system_fields"]["EventID"], "4104")
            self.assertEqual(native_evtx["details"]["binxml_event_data_fields"]["CommandLine"], "powershell -enc TemplateValue")
            self.assertEqual(
                native_evtx["details"]["binxml_event_data_sequence"][0]["value"],
                "powershell -enc TemplateValue",
            )
            self.assertEqual(
                native_evtx["details"]["binxml_event_data_values_by_name"]["CommandLine"],
                ["powershell -enc TemplateValue"],
            )
            self.assertEqual(native_evtx["details"]["evtx_binxml"]["template_values"][0]["value_type"], "StringType")
            self.assertEqual(native_evtx["details"]["evtx_binxml"]["template_substitution_count"], 1)
            self.assertEqual(native_evtx["details"]["evtx_validation_checks"]["template_substitution_count"], 1)
            self.assertEqual(native_evtx["details"]["message_rendering"]["provenance"]["template_value_count"], 1)
            self.assertEqual(
                native_evtx["details"]["message_rendering"]["provenance"]["native_binxml_status"],
                "template-substituted-partial",
            )
            self.assertEqual(
                native_evtx["details"]["message_rendering"]["available_field_summary"]["template_substitution_count"],
                1,
            )
            self.assertTrue(
                any(
                    item["confidence"] == "binxml-template-substitution"
                    and item["element_path"] == "Event/EventData/Data"
                    and item["text"] == "powershell -enc TemplateValue"
                    for item in native_evtx["details"]["evtx_binxml"]["value_fields"]
                )
            )

    def test_eventlog_collector_labels_native_evtx_slack_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            evtx_path = root / "Windows" / "System32" / "winevt" / "Logs" / "Slack.evtx"
            evtx_path.parent.mkdir(parents=True, exist_ok=True)
            evtx_path.write_bytes(
                build_evtx_with_slack_record(
                    record_id=889,
                    timestamp=datetime(2024, 4, 3, 2, 3, 4, tzinfo=timezone.utc),
                    strings=[
                        "Microsoft-Windows-Security-Auditing",
                        "Security",
                        "WIN-SLACK",
                        "powershell -enc SlackCandidate",
                    ],
                )
            )
            output = root / "eventlog.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "eventlog", "--output", str(output)]), 0)
            artifacts = json.loads(output.read_text(encoding="utf-8"))["artifacts"]
            native_evtx = next(
                item
                for item in artifacts
                if item["artifact_type"] == "eventlog-event"
                and item["details"]["parser"] == "windows-eventlog-evtx-native"
            )
            chunk = next(item for item in artifacts if item["artifact_type"] == "eventlog-chunk")
            summary = next(item for item in artifacts if item["artifact_type"] == "eventlog-summary")["details"]

            self.assertEqual(native_evtx["details"]["record_id"], "889")
            self.assertEqual(native_evtx["details"]["evtx_recovery_status"], "slack-or-deleted-record-candidate")
            self.assertEqual(native_evtx["details"]["evtx_allocation_status"], "slack-or-deleted-candidate")
            self.assertEqual(native_evtx["details"]["evtx_chunk_context"]["chunk_boundary_status"], "slack-or-deleted-region")
            self.assertTrue(native_evtx["details"]["evtx_validation_required"])
            self.assertTrue(native_evtx["details"]["validation_required"])
            self.assertIn("slack-or-deleted-record-candidate", native_evtx["details"]["evtx_validation_reasons"])
            self.assertTrue(native_evtx["details"]["evtx_recovery_context"]["validation_required"])
            self.assertIn(
                "slack-or-deleted-record-candidate",
                native_evtx["details"]["evtx_recovery_context"]["caution_labels"],
            )
            self.assertEqual(
                native_evtx["details"]["evtx_recovery_evidence"]["allocation_status"],
                "slack-or-deleted-candidate",
            )
            self.assertIn(
                "allocation:slack-or-deleted-candidate",
                native_evtx["details"]["evtx_recovery_evidence"]["evidence_reasons"],
            )
            recovery_profile = native_evtx["details"]["evtx_recovery_validation_profile"]
            self.assertEqual(recovery_profile["candidate_class"], "slack-or-deleted-record")
            self.assertFalse(recovery_profile["reportable_without_secondary_validation"])
            self.assertIn("known-answer-deleted-record-fixture-match", recovery_profile["required_independent_checks"])
            self.assertGreaterEqual(
                native_evtx["details"]["evtx_recovery_evidence"]["record_relative_offset"],
                native_evtx["details"]["evtx_recovery_evidence"]["free_space_offset"],
            )
            self.assertEqual(
                native_evtx["details"]["message_rendering"]["provenance"]["native_recovery_status"],
                "slack-or-deleted-record-candidate",
            )
            self.assertEqual(chunk["details"]["evtx_chunk_header"]["free_space_offset"], 512)
            self.assertTrue(chunk["details"]["evtx_chunk_integrity"]["structure_plausible"])
            self.assertEqual(summary["native_chunk_count"], 1)
            self.assertIn(
                {"value": "structure-plausible", "count": 1},
                summary["native_chunk_integrity_counts"],
            )
            self.assertIn(
                {"value": "slack-or-deleted-record-candidate", "count": 1},
                summary["native_recovery_status_counts"],
            )

    def test_eventlog_collector_reports_corrupt_evtx_record_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            evtx_path = root / "Windows" / "System32" / "winevt" / "Logs" / "Corrupt.evtx"
            evtx_path.parent.mkdir(parents=True, exist_ok=True)
            evtx_path.write_bytes(
                build_corrupt_evtx_record_candidate(
                    record_id=890,
                    timestamp=datetime(2024, 4, 3, 3, 4, 5, tzinfo=timezone.utc),
                    strings=[
                        "Microsoft-Windows-Security-Auditing",
                        "Security",
                        "WIN-CORRUPT",
                        "wevtutil cl Security",
                    ],
                )
            )
            output = root / "eventlog.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "eventlog", "--output", str(output)]), 0)
            artifacts = json.loads(output.read_text(encoding="utf-8"))["artifacts"]
            candidates = [item for item in artifacts if item["artifact_type"] == "eventlog-record-candidate"]
            inventory = next(item for item in artifacts if item["artifact_type"] == "eventlog-file")["details"]
            summary = next(item for item in artifacts if item["artifact_type"] == "eventlog-summary")["details"]

            self.assertEqual(len(candidates), 1)
            candidate = candidates[0]["details"]
            self.assertEqual(candidate["record_id"], "890")
            self.assertEqual(candidate["evtx_recovery_status"], "corrupt-record-candidate")
            self.assertEqual(candidate["evtx_record_integrity"]["candidate_reason"], "record-extends-past-eof")
            self.assertFalse(candidate["evtx_recovery_evidence"]["parseable_record"])
            self.assertEqual(candidate["evtx_recovery_evidence"]["candidate_reason"], "record-extends-past-eof")
            self.assertIn("candidate:record-extends-past-eof", candidate["evtx_recovery_evidence"]["evidence_reasons"])
            self.assertIn("binxml:not-decoded", candidate["evtx_recovery_evidence"]["evidence_reasons"])
            self.assertEqual(
                candidate["evtx_recovery_validation_profile"]["candidate_class"],
                "corrupt-or-truncated-record",
            )
            self.assertIn(
                "known-answer-corrupt-record-fixture-match",
                candidate["evtx_recovery_validation_profile"]["required_independent_checks"],
            )
            self.assertEqual(candidate["evtx_report_grade_assessment"]["status"], "validation-required")
            self.assertEqual(candidate["commercial_uplift_evidence"]["batch_id"], "commercial-uplift-001-005")
            self.assertEqual(candidate["commercial_uplift_evidence"]["item_numbers"], [1, 2, 3])
            self.assertIn("record-magic", candidate["commercial_uplift_evidence"]["passed_validation_matrix_ids"])
            self.assertFalse(
                candidate["commercial_uplift_evidence"]["large_data_controls"][
                    "streaming_reader_required_for_tb_claims"
                ]
            )
            self.assertTrue(
                candidate["commercial_uplift_evidence"]["large_data_controls"][
                    "remaining_large_data_proof_required"
                ]
            )
            self.assertIn("record-integrity-not-proven", candidate["evtx_report_grade_assessment"]["blockers"])
            self.assertTrue(candidate["validation_required"])
            self.assertIn("do-not-report-without-validation", candidate["caution_labels"])
            self.assertLess(candidate["parser_confidence"], 0.6)
            self.assertEqual(inventory["native_record_count"], 0)
            self.assertEqual(inventory["native_record_candidate_count"], 1)
            self.assertEqual(summary["record_candidate_count"], 1)
            self.assertIn(
                {"value": "corrupt-record-candidate", "count": 1},
                summary["native_recovery_status_counts"],
            )

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
            sam_group_candidates = [item for item in artifacts if item["artifact_type"] == "windows-sam-group-candidate"]
            service_rows = [item for item in artifacts if item["artifact_type"] == "windows-service-config"]
            mounted_devices = [item for item in artifacts if item["artifact_type"] == "windows-mounted-device"]
            lsa_locations = [item for item in artifacts if item["artifact_type"] == "windows-lsa-policy-location"]
            privileges = [item for item in artifacts if item["artifact_type"] == "windows-privilege-assignment"]
            group_rows = [item for item in artifacts if item["artifact_type"] == "windows-group-membership"]
            lifecycle_rows = [item for item in artifacts if item["artifact_type"] == "windows-account-lifecycle"]

            self.assertTrue(profiles)
            self.assertEqual(profiles[0]["details"]["user_name"], "alice")
            self.assertEqual(profiles[0]["details"]["source_path"], str(fixture.user_profile.resolve()))
            self.assertTrue(profiles[0]["details"]["ntuser_dat_present"])
            self.assertTrue(summaries)
            self.assertIn("WIN-FIXTURE", summaries[0]["details"]["computer_names"])
            self.assertIn("Korea Standard Time", summaries[0]["details"]["time_zones"])
            self.assertIn("2024-04-01T01:02:03+00:00", summaries[0]["details"]["last_boot_times"])
            self.assertIn("2024-04-01T00:55:01+00:00", summaries[0]["details"]["shutdown_times"])
            self.assertIn("ControlSet001:Current", summaries[0]["details"]["current_control_sets"])
            self.assertGreaterEqual(summaries[0]["details"]["service_count"], 1)
            self.assertGreaterEqual(summaries[0]["details"]["mounted_device_count"], 2)
            self.assertGreaterEqual(summaries[0]["details"]["lsa_secret_count"], 1)
            self.assertGreaterEqual(summaries[0]["details"]["privilege_assignment_count"], 1)
            self.assertGreaterEqual(summaries[0]["details"]["group_membership_hint_count"], 1)
            self.assertEqual(summaries[0]["details"]["group_membership_hints"][0]["group_name"], "Administrators")
            self.assertTrue(summaries[0]["details"]["group_membership_hints"][0]["privileged_group"])
            account_hints = {
                item["user_name"]: item
                for item in summaries[0]["details"]["account_lifecycle_hints"]
                if item.get("user_name")
            }
            self.assertEqual(account_hints["alice"]["created_at"], "2024-03-01T00:00:00+00:00")
            self.assertEqual(account_hints["alice"]["last_logon_at"], "2024-04-01T01:02:03+00:00")
            self.assertEqual(account_hints["alice"]["password_last_set_at"], "2024-03-15T12:34:56+00:00")
            self.assertTrue(account_hints["alice"]["admin_hint"])
            self.assertIn("NORMAL_ACCOUNT", account_hints["alice"]["uac_flags"])
            lifecycle = next(item for item in lifecycle_rows if item["details"]["user_name"] == "alice")
            self.assertEqual(lifecycle["details"]["rid_decimal"], 1001)
            self.assertTrue(lifecycle["details"]["validation_required"])
            self.assertFalse(lifecycle["details"]["commercial_grade_ready"])
            self.assertIn("full-native-sam-fv-layout-validation-required", lifecycle["details"]["commercial_grade_blockers"])
            self.assertEqual(lifecycle["details"]["os_account_report_grade_assessment"]["status"], "validation-required")
            self.assertIn("#6", lifecycle["details"]["os_account_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(lifecycle["details"]["forensic_review"]["gap_id"], "#6")
            self.assertEqual(lifecycle["details"]["forensic_review"]["review_status"], "triage-review")
            self.assertTrue(lifecycle["details"]["forensic_review"]["validation_required"])
            self.assertFalse(lifecycle["details"]["os_account_native_capabilities"]["security_secret_decryption"])
            lifecycle_matrix = {item["id"]: item for item in lifecycle["details"]["os_account_validation_matrix"]}
            self.assertTrue(lifecycle_matrix["has-sam-f-value"]["passed"])
            self.assertTrue(lifecycle_matrix["has-sam-v-value"]["passed"])
            self.assertFalse(lifecycle_matrix["native-sam-fv-report-grade"]["passed"])
            self.assertEqual(lifecycle["details"]["sam_binary_fields"]["F"]["byte_count"], 68)
            self.assertEqual(lifecycle["details"]["sam_binary_fields"]["F"]["decoded_timestamps"]["last_logon_at"], "2024-04-01T01:02:03+00:00")
            self.assertEqual(lifecycle["details"]["sam_binary_fields"]["F"]["rid_decimal_candidate"], 1001)
            self.assertIn("NORMAL_ACCOUNT", lifecycle["details"]["sam_binary_fields"]["F"]["user_account_control_flags"])
            self.assertIn("Alice Example", lifecycle["details"]["sam_binary_fields"]["V"]["string_candidates"])
            self.assertTrue(lifecycle["details"]["validation_checks"]["has_sam_f_value"])
            self.assertTrue(lifecycle["details"]["validation_checks"]["has_sam_v_value"])
            self.assertTrue(lifecycle["details"]["validation_checks"]["native_sam_fv_candidate_decoding_available"])
            self.assertFalse(lifecycle["details"]["validation_checks"]["native_sam_fv_report_grade"])
            self.assertIn("admin-account-hint", lifecycle["details"]["risk_flags"])
            self.assertIn("privileged-group-membership-hint", lifecycle["details"]["risk_flags"])
            self.assertEqual(lifecycle["details"]["group_membership_hints"][0]["group_name"], "Administrators")
            self.assertEqual(lifecycle["details"]["group_membership_hints"][0]["match_types"], ["name", "rid-sid-tail"])
            self.assertEqual(lifecycle["details"]["group_membership_hints"][0]["group_sid_candidates"], ["S-1-5-32-544"])
            self.assertEqual(lifecycle["details"]["account_security_context"]["privileged_group_count"], 1)
            self.assertIn("S-1-5-32-544", lifecycle["details"]["account_security_context"]["group_sid_candidates"])
            self.assertEqual(lifecycle["details"]["account_security_context"]["inherited_privilege_count"], 1)
            account_profile = lifecycle["details"]["account_privilege_deep_parse_profile"]
            self.assertEqual(account_profile["commercial_gap_id"], "#6")
            self.assertEqual(account_profile["target_artifacts"], ["SAM", "SECURITY", "SYSTEM"])
            self.assertTrue(account_profile["decoded_components"]["sam_fv_candidate_fields"])
            self.assertTrue(account_profile["decoded_components"]["privilege_rights_export_mapping"])
            self.assertTrue(account_profile["not_yet_report_grade"]["sam_alias_member_binary_decode"])
            self.assertIn("decode SAM alias/member binary values for actual group membership", account_profile["required_independent_checks"])
            inherited_debug = lifecycle["details"]["account_security_context"]["inherited_privileges"][0]
            self.assertEqual(inherited_debug["privilege"], "SeDebugPrivilege")
            self.assertEqual(inherited_debug["via_groups"], ["Administrators"])
            self.assertIn("high-risk-privilege", inherited_debug["risk_flags"])
            lifecycle_gate = lifecycle["details"]["core_accuracy_gates"][0]
            self.assertEqual(lifecycle_gate["gap_id"], "#6")
            self.assertIn("RID/name/SID consistency", lifecycle_gate["satisfied_checks"])
            self.assertIn("UAC flag decoding", lifecycle_gate["satisfied_checks"])
            self.assertIn("group alias membership reconstruction", lifecycle_gate["satisfied_checks"])
            self.assertIn("privilege assignment attribution", lifecycle_gate["satisfied_checks"])
            self.assertIn("secret-value redaction and authority gate", lifecycle_gate["satisfied_checks"])
            self.assertFalse(lifecycle_gate["commercial_grade_ready"])
            lifecycle_uplift = lifecycle["details"]["commercial_uplift_evidence"]
            self.assertEqual(lifecycle_uplift["batch_id"], "commercial-uplift-006-010")
            self.assertEqual(lifecycle_uplift["item_numbers"], [6])
            self.assertIn("has-sam-f-value", lifecycle_uplift["passed_validation_matrix_ids"])
            self.assertIn("native-sam-fv-report-grade", lifecycle_uplift["failed_validation_matrix_ids"])
            self.assertTrue(lifecycle_uplift["large_data_controls"]["secret_values_redacted"])
            group = next(item for item in group_rows if item["details"]["group_name"] == "Administrators")
            self.assertFalse(group["details"]["commercial_grade_ready"])
            self.assertEqual(group["details"]["member_count"], 1)
            self.assertEqual(group["details"]["member_identifier_count"], 2)
            self.assertIn("not proven", group["details"]["member_count_semantics"])
            self.assertIn("member-sid", group["details"]["membership_source_types"])
            self.assertIn("member-name", group["details"]["membership_source_types"])
            self.assertEqual(group["details"]["group_sid_candidates"], ["S-1-5-32-544"])
            self.assertTrue(group["details"]["validation_checks"]["requires_native_sam_alias_validation"])
            self.assertIn("#6", group["details"]["os_account_report_grade_assessment"]["commercial_gap_ids"])
            self.assertIn("privileged-group-membership-hint", group["details"]["risk_flags"])
            self.assertTrue(sam_candidates)
            alice_sam = next(item for item in sam_candidates if item["details"]["user_name_candidate"] == "alice")
            self.assertEqual(alice_sam["details"]["candidate_role"], "account-name-key")
            self.assertEqual(alice_sam["details"]["rid_hex"], "000003E9")
            self.assertEqual(alice_sam["details"]["rid_decimal"], 1001)
            self.assertTrue(alice_sam["details"]["validation_required"])
            self.assertIn("#6", alice_sam["details"]["os_account_report_grade_assessment"]["commercial_gap_ids"])
            self.assertFalse(alice_sam["details"]["os_account_native_capabilities"]["native_sam_alias_member_binary_decode"])
            self.assertEqual(
                alice_sam["details"]["account_privilege_deep_parse_profile"]["artifact_scope"],
                "native-sam-account-key-candidate",
            )
            self.assertEqual(len(alice_sam["details"]["source_hashes"]["sha256"]), 64)
            admin_group = next(item for item in sam_group_candidates if item["details"]["group_name_candidate"] == "Administrators")
            self.assertFalse(admin_group["details"]["commercial_grade_ready"])
            self.assertEqual(admin_group["details"]["alias_rid_hex"], "00000220")
            self.assertEqual(admin_group["details"]["alias_rid_decimal"], 544)
            self.assertFalse(admin_group["details"]["validation_checks"]["native_membership_reconstruction_available"])
            self.assertIn("privileged-group-candidate", admin_group["details"]["risk_flags"])
            service = next(item for item in service_rows if item["details"]["service_name"] == "SecurityUpdater")
            self.assertEqual(service["details"]["start_type_label"], "automatic")
            self.assertIn("suspicious-service-image-path", service["details"]["risk_flags"])
            self.assertTrue(any(item["details"]["drive_letter"] == r"\DosDevices\E:" for item in mounted_devices))
            lsa_secret = next(item for item in lsa_locations if item["details"]["secret_name"] == "_SC_SecurityUpdater")
            self.assertIn("CurrVal", lsa_secret["details"]["value_names"])
            self.assertEqual(lsa_secret["details"]["secret_value_metadata"]["CurrVal"]["byte_count"], 2)
            self.assertFalse(lsa_secret["details"]["secret_value_metadata"]["CurrVal"]["decrypted"])
            self.assertFalse(lsa_secret["details"]["commercial_grade_ready"])
            self.assertEqual(lsa_secret["details"]["validation_checks"]["exported_value_count"], 3)
            self.assertIn("#6", lsa_secret["details"]["os_account_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(lsa_secret["details"]["secret_value_metadata"]["CupdTime"]["registry_value_type"], "REG_QWORD")
            self.assertEqual(
                lsa_secret["details"]["secret_value_metadata"]["CupdTime"]["timestamp_candidate"],
                "2024-04-01T01:23:45+00:00",
            )
            self.assertTrue(lsa_secret["details"]["secret_value_metadata"]["SecDesc"]["contains_nonzero_bytes"])
            privilege = next(item for item in privileges if item["details"]["privilege"] == "SeDebugPrivilege")
            self.assertIn("S-1-5-32-544", privilege["details"]["assigned_sids"])
            self.assertEqual(
                privilege["details"]["assigned_principal_hints"],
                [{"sid": "S-1-5-32-544", "principal": "Administrators", "principal_type": "builtin-alias"}],
            )
            self.assertIn("high-risk-privilege", privilege["details"]["risk_flags"])

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
            self.assertIn("amcache-hive", artifact_types)
            self.assertIn("amcache-entry", artifact_types)
            self.assertIn("userassist-entry", artifact_types)
            self.assertIn("shimcache-entry", artifact_types)
            self.assertIn("powershell-history-command", artifact_types)
            self.assertIn("srum-network-usage", artifact_types)
            self.assertIn("srum-database-file", artifact_types)
            self.assertIn("srum-database-pivot", artifact_types)
            self.assertIn("srum-table-candidate", artifact_types)
            self.assertIn("srum-row-candidate", artifact_types)
            self.assertIn("windows-execution-summary", artifact_types)
            amcache_rows = [item for item in artifacts if item["artifact_type"] == "amcache-entry"]
            bam = next(item for item in artifacts if item["artifact_type"] == "bam-entry")
            shimcache = next(item for item in artifacts if item["artifact_type"] == "shimcache-entry")
            ps_rows = [item for item in artifacts if item["artifact_type"] == "powershell-history-command"]
            srum_rows = [item for item in artifacts if item["artifact_type"] == "srum-network-usage"]
            srum_database_rows = [item for item in artifacts if item["artifact_type"] == "srum-database-file"]
            srum_pivots = [item for item in artifacts if item["artifact_type"] == "srum-database-pivot"]
            srum_row_candidates = [item for item in artifacts if item["artifact_type"] == "srum-row-candidate"]
            self.assertTrue(any("suspicious-command:powershell -enc" in row["details"]["risk_flags"] for row in ps_rows))
            self.assertTrue(any("vssadmin delete shadows" in row["details"]["command_line"] for row in ps_rows))
            self.assertEqual(ps_rows[0]["details"]["source_path"], str(fixture.powershell_history.resolve()))
            self.assertTrue(any(row["details"]["source_path"] == str(fixture.amcache_hive.resolve()) for row in amcache_rows))
            self.assertTrue(any(row["details"]["executable_path"].endswith(r"Example\app.exe") for row in amcache_rows))
            exported_amcache = next(row for row in amcache_rows if row["details"]["source_format"] == "reg")
            self.assertEqual(exported_amcache["details"]["program_name"], "Example App")
            self.assertEqual(exported_amcache["details"]["publisher"], "Example Publisher")
            self.assertEqual(exported_amcache["details"]["sha1"], "0123456789abcdef0123456789abcdef01234567")
            self.assertEqual(exported_amcache["details"]["file_description"], "Example Application Binary")
            self.assertEqual(exported_amcache["details"]["amcache_evidence"]["file_name"], "app.exe")
            self.assertTrue(exported_amcache["details"]["amcache_evidence"]["path_present"])
            self.assertTrue(exported_amcache["details"]["amcache_evidence"]["hash_present"])
            self.assertEqual(
                exported_amcache["details"]["amcache_evidence"]["sha1_candidates"],
                ["0123456789abcdef0123456789abcdef01234567"],
            )
            self.assertIn("publisher", exported_amcache["details"]["amcache_evidence"]["metadata_fields_present"])
            self.assertEqual(
                exported_amcache["details"]["amcache_evidence"]["execution_caveat"],
                "Amcache supports program presence/install/execution-related pivots but is not standalone proof of execution.",
            )
            self.assertEqual(exported_amcache["details"]["amcache_schema_profile"]["commercial_gap_id"], "#7")
            self.assertEqual(exported_amcache["details"]["amcache_schema_profile"]["source_format"], "reg")
            self.assertFalse(exported_amcache["details"]["amcache_schema_profile"]["standalone_execution_proof"])
            self.assertTrue(exported_amcache["details"]["amcache_schema_profile"]["schema_components"]["root_file_paths"])
            self.assertTrue(exported_amcache["details"]["validation_checks"]["has_hash"])
            self.assertFalse(exported_amcache["details"]["commercial_grade_ready"])
            self.assertIn("native-amcache-schema-decoding-required", exported_amcache["details"]["commercial_grade_blockers"])
            self.assertIn("#7", exported_amcache["details"]["execution_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(exported_amcache["details"]["forensic_review"]["gap_id"], "#7")
            self.assertIn("Amcache", exported_amcache["details"]["forensic_review"]["artifact_goal"])
            self.assertFalse(exported_amcache["details"]["execution_native_capabilities"]["native_amcache_schema_decode"])
            amcache_gate = exported_amcache["details"]["core_accuracy_gates"][0]
            self.assertEqual(amcache_gate["gap_id"], "#7")
            self.assertIn("schema-version detection", amcache_gate["satisfied_checks"])
            self.assertIn("path/hash/publisher extraction", amcache_gate["satisfied_checks"])
            self.assertIn("execution caveat wording", amcache_gate["satisfied_checks"])
            self.assertFalse(amcache_gate["commercial_grade_ready"])
            amcache_uplift = exported_amcache["details"]["commercial_uplift_evidence"]
            self.assertEqual(amcache_uplift["batch_id"], "commercial-uplift-006-010")
            self.assertEqual(amcache_uplift["item_numbers"], [7])
            self.assertIn("has-hash", amcache_uplift["passed_validation_matrix_ids"])
            self.assertTrue(amcache_uplift["large_data_controls"]["schema_version_matrix_required"])
            native_amcache_hive = next(item for item in artifacts if item["artifact_type"] == "amcache-hive")
            self.assertGreaterEqual(native_amcache_hive["details"]["amcache_hive_evidence"]["candidate_path_count"], 1)
            self.assertEqual(
                native_amcache_hive["details"]["amcache_hive_evidence"]["schema_decode_status"],
                "not-implemented-string-pivot-only",
            )
            self.assertEqual(native_amcache_hive["details"]["amcache_schema_profile"]["current_decode_level"], "native-string-pivot-only")
            native_hive_uplift = native_amcache_hive["details"]["commercial_uplift_evidence"]
            self.assertEqual(native_hive_uplift["batch_id"], "commercial-uplift-006-010")
            self.assertEqual(native_hive_uplift["item_numbers"], [7])
            self.assertIn("has-path-candidates", native_hive_uplift["passed_validation_matrix_ids"])
            self.assertTrue(native_hive_uplift["large_data_controls"]["schema_version_matrix_required"])
            self.assertEqual(bam["details"]["user_sid"], "S-1-5-21-1000")
            self.assertEqual(bam["details"]["timestamp"], "2024-04-01T06:07:08+00:00")
            self.assertEqual(bam["details"]["timestamp_source"], "bam_value_filetime")
            self.assertEqual(bam["details"]["bam_dam_evidence"]["user_sid"], "S-1-5-21-1000")
            self.assertEqual(
                bam["details"]["bam_dam_evidence"]["timestamp_semantics"],
                "bam-dam-last-execution-filetime-candidate",
            )
            self.assertTrue(bam["details"]["bam_dam_evidence"]["requires_native_system_hive_validation"])
            self.assertEqual(bam["details"]["bam_dam_decode_profile"]["commercial_gap_id"], "#9")
            self.assertTrue(bam["details"]["bam_dam_decode_profile"]["decoded_components"]["filetime_timestamp"])
            self.assertEqual(
                bam["details"]["bam_dam_decode_profile"]["timestamp_semantics"],
                "bam-dam-last-execution-filetime-candidate",
            )
            self.assertTrue(bam["details"]["validation_checks"]["has_timestamp"])
            self.assertFalse(bam["details"]["commercial_grade_ready"])
            self.assertIn("native-system-hive-bam-decoding-required", bam["details"]["commercial_grade_blockers"])
            self.assertIn("#9", bam["details"]["execution_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(bam["details"]["forensic_review"]["gap_id"], "#9")
            self.assertIn("bam-execution-indicator", bam["details"]["risk_flags"])
            bam_gate = bam["details"]["core_accuracy_gates"][0]
            self.assertEqual(bam_gate["gap_id"], "#9")
            self.assertIn("SID extraction", bam_gate["satisfied_checks"])
            self.assertIn("device path normalization", bam_gate["satisfied_checks"])
            self.assertIn("FILETIME validity", bam_gate["satisfied_checks"])
            self.assertIn("ControlSet attribution", bam_gate["satisfied_checks"])
            bam_uplift = bam["details"]["commercial_uplift_evidence"]
            self.assertEqual(bam_uplift["item_numbers"], [9])
            self.assertTrue(bam_uplift["large_data_controls"]["native_binary_layout_required_for_commercial_claims"])
            self.assertTrue(shimcache["details"]["validation_required"])
            self.assertEqual(shimcache["details"]["execution_caveat"], "Presence in ShimCache is not proof the executable ran.")
            self.assertEqual(
                shimcache["details"]["shimcache_evidence"]["execution_caveat"],
                "ShimCache/AppCompatCache can show program presence/order, but it is not standalone proof of execution.",
            )
            self.assertTrue(shimcache["details"]["shimcache_evidence"]["requires_os_version_layout_validation"])
            self.assertEqual(shimcache["details"]["shimcache_execution_caveat_profile"]["commercial_gap_id"], "#8")
            self.assertFalse(shimcache["details"]["shimcache_execution_caveat_profile"]["standalone_execution_proof"])
            self.assertIn(
                "preserve the UX warning that ShimCache is not proof of execution",
                shimcache["details"]["shimcache_execution_caveat_profile"]["required_independent_checks"],
            )
            self.assertIn("Prefetch", shimcache["details"]["validation_checks"]["correlation_targets"])
            self.assertIn("native-appcompatcache-layout-decoding-required", shimcache["details"]["commercial_grade_blockers"])
            self.assertIn("#8", shimcache["details"]["execution_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(shimcache["details"]["forensic_review"]["gap_id"], "#8")
            shimcache_gate = shimcache["details"]["core_accuracy_gates"][0]
            self.assertEqual(shimcache_gate["gap_id"], "#8")
            self.assertIn("not-proof-of-execution warning", shimcache_gate["satisfied_checks"])
            self.assertIn("malformed binary bounds checks", shimcache_gate["satisfied_checks"])
            shimcache_uplift = shimcache["details"]["commercial_uplift_evidence"]
            self.assertEqual(shimcache_uplift["item_numbers"], [8])
            self.assertTrue(shimcache_uplift["large_data_controls"]["native_binary_layout_required_for_commercial_claims"])
            self.assertEqual(srum_rows[0]["details"]["app_id"], "powershell.exe")
            self.assertEqual(srum_rows[0]["details"]["bytes_received"], 2048)
            self.assertEqual(srum_rows[0]["details"]["bytes_total"], 2560)
            self.assertEqual(srum_rows[0]["details"]["network_profile"], "CorpWiFi")
            self.assertTrue(srum_rows[0]["details"]["validation_checks"]["has_network_counters"])
            self.assertEqual(srum_rows[0]["details"]["srum_usage_evidence"]["table_family"], "network-usage")
            self.assertIn("bytes_received", srum_rows[0]["details"]["srum_usage_evidence"]["counter_fields_present"])
            self.assertEqual(
                srum_rows[0]["details"]["srum_usage_evidence"]["counter_normalization_status"],
                "normalized-from-source-tool-export",
            )
            self.assertEqual(srum_rows[0]["details"]["forensic_review"]["gap_id"], "#10")
            self.assertEqual(srum_rows[0]["details"]["source_path"], str(fixture.srum_csv.resolve()))
            self.assertEqual(srum_database_rows[0]["details"]["source_path"], str(fixture.srum_db.resolve()))
            self.assertTrue(srum_database_rows[0]["details"]["ese_header"]["signature_valid"])
            self.assertTrue(srum_database_rows[0]["details"]["srum_database_evidence"]["ese_signature_valid"])
            self.assertEqual(srum_database_rows[0]["details"]["srum_ese_validation_profile"]["commercial_gap_id"], "#10")
            self.assertEqual(srum_database_rows[0]["details"]["srum_ese_validation_profile"]["artifact_scope"], "database")
            self.assertTrue(srum_database_rows[0]["details"]["srum_ese_validation_profile"]["decoded_components"]["ese_header"])
            self.assertEqual(
                srum_database_rows[0]["details"]["srum_database_evidence"]["schema_decode_status"],
                "not-implemented-header-and-string-pivot-only",
            )
            self.assertTrue(srum_database_rows[0]["details"]["validation_checks"]["ese_signature_valid"])
            self.assertEqual(
                srum_database_rows[0]["details"]["native_srudb_validation"]["validation_status"],
                "header-size-page-aligned",
            )
            self.assertTrue(srum_database_rows[0]["details"]["native_srudb_validation"]["page_size_plausible"])
            self.assertTrue(srum_database_rows[0]["details"]["validation_checks"]["has_native_srum_row_candidates"])
            self.assertFalse(srum_database_rows[0]["details"]["commercial_grade_ready"])
            self.assertIn("native-srum-row-decoding-required", srum_database_rows[0]["details"]["commercial_grade_blockers"])
            self.assertIn("#10", srum_database_rows[0]["details"]["execution_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(srum_database_rows[0]["details"]["forensic_review"]["gap_id"], "#10")
            self.assertFalse(srum_database_rows[0]["details"]["execution_native_capabilities"]["native_srum_page_row_decode"])
            srum_db_gate = srum_database_rows[0]["details"]["core_accuracy_gates"][0]
            self.assertEqual(srum_db_gate["gap_id"], "#10")
            self.assertIn("ESE page checksum validation", srum_db_gate["satisfied_checks"])
            self.assertIn("catalog/table mapping", srum_db_gate["satisfied_checks"])
            self.assertIn("native-row confidence scoring", srum_db_gate["satisfied_checks"])
            srum_uplift = srum_database_rows[0]["details"]["commercial_uplift_evidence"]
            self.assertEqual(srum_uplift["batch_id"], "commercial-uplift-006-010")
            self.assertEqual(srum_uplift["item_numbers"], [10])
            self.assertTrue(srum_uplift["large_data_controls"]["row_level_native_decode_required_for_commercial_claims"])
            self.assertTrue(any("powershell.exe" in value.lower() for value in srum_database_rows[0]["details"]["path_candidates"]))
            self.assertTrue(any(item["details"]["app_id"] == "powershell.exe" for item in srum_pivots))
            self.assertTrue(any(item["details"]["url"] == "https://download.example/tools/installer.exe" for item in srum_pivots))
            self.assertTrue(all(item["details"]["validation_required"] for item in srum_pivots))
            self.assertTrue(all(item["details"]["srum_pivot_evidence"]["pivot_basis"] == "native-ese-string-pivot" for item in srum_pivots))
            self.assertTrue(all(item["details"]["srum_ese_validation_profile"]["artifact_scope"] == "string-pivot" for item in srum_pivots))
            srum_row_candidate = next(item for item in srum_row_candidates if item["details"]["app_id"] == "powershell.exe")
            self.assertEqual(srum_row_candidate["details"]["table_family"], "network-usage")
            self.assertEqual(srum_row_candidate["details"]["bytes_received"], 2048)
            self.assertEqual(srum_row_candidate["details"]["timestamp"], "2024-04-01T05:06:07+00:00")
            self.assertEqual(
                srum_row_candidate["details"]["srum_row_evidence"]["row_level_decode_status"],
                "not-implemented-string-cluster-only",
            )
            self.assertGreaterEqual(srum_row_candidate["details"]["srum_row_evidence"]["counter_candidate_count"], 1)
            self.assertEqual(srum_row_candidate["details"]["srum_ese_validation_profile"]["artifact_scope"], "row-candidate")
            self.assertGreaterEqual(srum_row_candidate["details"]["srum_ese_validation_profile"]["evidence_fields"]["counter_candidate_count"], 1)
            self.assertTrue(srum_row_candidate["details"]["validation_checks"]["requires_srum_parser"])
            self.assertFalse(srum_row_candidate["details"]["commercial_grade_ready"])
            self.assertIn("native-ese-page-row-decoding-required", srum_row_candidate["details"]["commercial_grade_blockers"])
            srum_table = next(item for item in artifacts if item["artifact_type"] == "srum-table-candidate" and item["details"]["table_family"] == "network-usage")
            self.assertGreaterEqual(srum_table["details"]["matched_marker_count"], 1)
            self.assertEqual(srum_table["details"]["srum_ese_validation_profile"]["artifact_scope"], "table-candidate")
            self.assertEqual(srum_table["details"]["srum_ese_validation_profile"]["evidence_fields"]["table_family"], "network-usage")
            self.assertTrue(srum_table["details"]["validation_checks"]["has_source_offsets"])
            self.assertTrue(srum_table["details"]["validation_checks"]["requires_srum_parser"])
            summary = next(item for item in artifacts if item["artifact_type"] == "windows-execution-summary")
            groups = {item["display_name"]: item for item in summary["details"]["groups"]}
            self.assertFalse(summary["details"]["native_capabilities"]["native_ese_catalog_decode"])
            self.assertTrue(summary["details"]["report_grade_status_counts"])
            self.assertIn("evil.exe", groups)
            self.assertIn("powershell.exe", groups)
            self.assertIn("bam-entry", groups["evil.exe"]["signal_types"])
            self.assertIn("powershell-history-command", groups["powershell.exe"]["signal_types"])
            self.assertIn("srum-network-usage", groups["powershell.exe"]["signal_types"])
            self.assertIn("srum-database-pivot", groups["powershell.exe"]["signal_types"])
            self.assertIn("suspicious-command:powershell -enc", groups["powershell.exe"]["risk_flags"])
            self.assertIn("Prefetch", groups["evil.exe"]["correlation_targets"])

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
            self.assertEqual(details["parser_version"], "prefetch-inventory-v7")
            self.assertFalse(details["commercial_grade_ready"])
            self.assertIn("Full file metrics array decoding", details["commercial_readiness_blockers"][0])
            self.assertIn("#16", details["prefetch_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(details["forensic_review"]["gap_id"], "#16")
            self.assertFalse(details["forensic_review"]["report_grade_ready"])
            self.assertFalse(details["prefetch_native_capabilities"]["full_file_metrics_array_decode"])
            self.assertEqual(details["prefetch_version_metadata"]["layout_name"], "windows-10")
            self.assertEqual(details["prefetch_version_metadata"]["run_count_offset_hex"], "0xd0")
            self.assertEqual(details["run_count"], 3)
            self.assertEqual(details["last_run_at"], "2024-04-01T09:10:11+00:00")
            self.assertIn(details["last_run_at"], details["last_run_times"])
            self.assertEqual(details["prefetch_validation_checks"]["file_size_matches_declared"], True)
            self.assertTrue(details["prefetch_validation_checks"]["run_count_plausible"])
            self.assertTrue(details["prefetch_validation_checks"]["last_run_times_not_future"])
            self.assertFalse(details["prefetch_validation_checks"]["full_file_metrics_decoded"])
            prefetch_gate = details["core_accuracy_gates"][0]
            self.assertEqual(prefetch_gate["gap_id"], "#16")
            self.assertIn("SCCA/header validation", prefetch_gate["satisfied_checks"])
            self.assertIn("version-specific section offsets", prefetch_gate["satisfied_checks"])
            self.assertIn("run count and last-run timestamps", prefetch_gate["satisfied_checks"])
            self.assertIn("volume/file metrics", prefetch_gate["satisfied_checks"])
            self.assertIn("compressed PF handling", prefetch_gate["missing_required_checks"])
            prefetch_uplift = details["commercial_uplift_evidence"]
            self.assertEqual(prefetch_uplift["batch_id"], "commercial-uplift-016-020")
            self.assertEqual(prefetch_uplift["item_numbers"], [16])
            self.assertIn("scca-signature", prefetch_uplift["passed_validation_matrix_ids"])
            self.assertTrue(
                prefetch_uplift["large_data_controls"]["full_file_metrics_decode_required_for_commercial_claims"]
            )
            self.assertTrue(any("POWERSHELL.EXE" in path for path in details["referenced_paths"]))
            self.assertEqual(details["volume_candidate_count"], 1)
            self.assertEqual(details["volume_candidates"][0]["volume_device_path"], r"\DEVICE\HARDDISKVOLUME3")
            self.assertEqual(details["file_reference_candidate_count"], 1)
            self.assertEqual(details["file_reference_candidates"][0]["referenced_file_name"], "POWERSHELL.EXE")
            self.assertTrue(references)
            self.assertEqual(references[0]["details"]["referenced_file_name"], "POWERSHELL.EXE")
            self.assertEqual(references[0]["details"]["volume_device_path"], r"\DEVICE\HARDDISKVOLUME3")
            self.assertEqual(references[0]["details"]["last_run_at"], "2024-04-01T09:10:11+00:00")
            self.assertTrue(references[0]["details"]["validation_required"])
            self.assertEqual(references[0]["details"]["commercial_uplift_evidence"]["item_numbers"], [16])
            self.assertFalse(references[0]["details"]["commercial_grade_ready"])
            self.assertIn("#16", references[0]["details"]["prefetch_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(references[0]["details"]["forensic_review"]["gap_id"], "#16")

    def test_windows_prefetch_collector_is_available_as_dedicated_artifacts_kind(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            output = root / "prefetch.json"
            prefetch = root / "Windows" / "Prefetch" / "POWERSHELL.EXE-12345678.pf"
            prefetch.parent.mkdir(parents=True, exist_ok=True)
            header = bytearray(512)
            header[0:4] = (30).to_bytes(4, "little")
            header[4:8] = b"SCCA"
            header[0x0C:0x10] = (len(header)).to_bytes(4, "little")
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
            self.assertTrue(artifact["details"]["prefetch_validation_checks"]["supported_common_layout"])
            self.assertTrue(artifact["details"]["prefetch_validation_checks"]["run_count_present"])
            self.assertEqual(artifact["details"]["prefetch_validation_checks"]["file_size_matches_declared"], True)
            self.assertEqual(artifact["details"]["prefetch_hash"], "12345678")
            self.assertEqual(artifact["details"]["evidence_strength"], "execution-indicator")

    def test_windows_prefetch_common_version_metadata_uses_version_offsets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            output = root / "prefetch.json"
            prefetch = root / "Windows" / "Prefetch" / "NOTEPAD.EXE-ABCDEF12.pf"
            prefetch.parent.mkdir(parents=True, exist_ok=True)
            header = bytearray(512)
            header[0:4] = (23).to_bytes(4, "little")
            header[4:8] = b"SCCA"
            header[0x0C:0x10] = (len(header)).to_bytes(4, "little")
            header[16 : 16 + len("NOTEPAD.EXE".encode("utf-16le"))] = "NOTEPAD.EXE".encode("utf-16le")
            header[0x80:0x88] = datetime_to_filetime(datetime(2024, 2, 3, 4, 5, 6, tzinfo=timezone.utc)).to_bytes(
                8, "little"
            )
            header[0x98:0x9C] = (11).to_bytes(4, "little")
            prefetch.write_bytes(bytes(header))

            self.assertEqual(main(["artifacts", str(root), "--kind", "windows-prefetch", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            details = payload["artifacts"][0]["details"]

            self.assertEqual(details["prefetch_version"], 23)
            self.assertEqual(details["prefetch_version_metadata"]["layout_name"], "windows-vista-7")
            self.assertEqual(details["prefetch_version_metadata"]["run_count_offset_hex"], "0x98")
            self.assertEqual(details["prefetch_version_metadata"]["last_run_time_slots"], 1)
            self.assertEqual(details["run_count"], 11)
            self.assertEqual(details["last_run_times"], ["2024-02-03T04:05:06+00:00"])
            self.assertTrue(details["prefetch_validation_checks"]["supported_common_layout"])

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
            self.assertEqual(native_mft[0]["details"]["coverage_status"], "native-file-record-attributes-partial")
            self.assertEqual(native_mft[0]["details"]["sequence_validation"]["status"], "valid")
            self.assertEqual(native_mft[0]["details"]["timestamp_validation"]["status"], "valid")
            self.assertEqual(native_mft[0]["details"]["timestamp"], "2024-04-01T04:05:06+00:00")
            self.assertIn("$STANDARD_INFORMATION", native_mft[0]["details"]["attribute_types"])
            self.assertIn("$FILE_NAME", native_mft[0]["details"]["attribute_types"])
            self.assertIn("$DATA", native_mft[0]["details"]["attribute_types"])
            self.assertEqual(native_mft[0]["details"]["file_name_entries"][0]["file_name"], "deleted.txt")
            self.assertEqual(native_mft[0]["details"]["parent_reference_decoded"]["record_number"], 5)
            self.assertTrue(native_mft[0]["details"]["data_attributes"][0]["resident"])
            self.assertEqual(native_mft[0]["details"]["mft_record_evidence"]["record_identity"]["sequence_number"], 3)
            self.assertEqual(
                native_mft[0]["details"]["mft_record_evidence"]["path_evidence"]["primary_path"],
                r"C:\Users\alice\Desktop\deleted.txt",
            )
            self.assertEqual(
                native_mft[0]["details"]["mft_record_evidence"]["path_evidence"]["parent_reference_decoded"]["record_number"],
                5,
            )
            self.assertTrue(native_mft[0]["details"]["mft_record_evidence"]["state_evidence"]["in_use"])
            self.assertIn(
                "$STANDARD_INFORMATION",
                native_mft[0]["details"]["mft_record_evidence"]["attribute_evidence"]["attribute_types"],
            )
            self.assertEqual(
                native_mft[0]["details"]["mft_record_evidence"]["validation_evidence"]["sequence_fixup_status"],
                "valid",
            )
            self.assertIn(
                "magic_valid",
                native_mft[0]["details"]["mft_record_evidence"]["validation_evidence"]["critical_checks_passed"],
            )
            self.assertFalse(native_mft[0]["details"]["commercial_grade_ready"])
            self.assertIn(
                "attribute-list-extension-record-resolution-not-implemented",
                native_mft[0]["details"]["commercial_grade_blockers"],
            )
            self.assertIn("#12", native_mft[0]["details"]["ntfs_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(native_mft[0]["details"]["forensic_review"]["gap_id"], "#12")
            mft_gate = native_mft[0]["details"]["core_accuracy_gates"][0]
            self.assertEqual(mft_gate["gap_id"], "#12")
            self.assertIn("USA validation", mft_gate["satisfied_checks"])
            self.assertIn("parent path reconstruction", mft_gate["satisfied_checks"])
            self.assertIn("timestamp/source field provenance", mft_gate["satisfied_checks"])
            self.assertFalse(native_mft[0]["details"]["ntfs_native_capabilities"]["mft_attribute_list_resolution"])
            self.assertTrue(native_mft[0]["details"]["validation_required"])
            mft_uplift = native_mft[0]["details"]["commercial_uplift_evidence"]
            self.assertEqual(mft_uplift["batch_id"], "commercial-uplift-011-015")
            self.assertEqual(mft_uplift["item_numbers"], [12])
            self.assertIn("sequence-fixup-valid", mft_uplift["passed_validation_matrix_ids"])
            self.assertTrue(
                mft_uplift["large_data_controls"]["full_volume_or_journal_validation_required_for_commercial_claims"]
            )
            self.assertIn({"value": "valid", "count": 1}, mft_files[0]["details"]["sequence_validation_counts"])
            self.assertIn({"value": "$FILE_NAME", "count": 1}, mft_files[0]["details"]["native_attribute_type_counts"])
            self.assertEqual(usn_files[0]["details"]["source_path"], str(fixture.usn_journal.resolve()))
            self.assertEqual(usn_files[0]["details"]["native_record_count"], 3)
            self.assertIn({"value": "2", "count": 2}, usn_files[0]["details"]["record_version_counts"])
            self.assertIn({"value": "3", "count": 1}, usn_files[0]["details"]["record_version_counts"])
            self.assertIn({"value": "large", "count": 1}, usn_files[0]["details"]["record_size_class_counts"])
            self.assertIn({"value": "standard", "count": 2}, usn_files[0]["details"]["record_size_class_counts"])
            self.assertEqual(usn_files[0]["details"]["large_record_count"], 1)
            self.assertGreaterEqual(usn_files[0]["details"]["largest_record_length"], 512)
            self.assertEqual(usn_files[0]["details"]["scan_metadata"]["first_record_offset"], 16)
            self.assertEqual(usn_files[0]["details"]["skipped_bytes_before_records"], 16)
            self.assertEqual(usn_files[0]["details"]["skipped_bytes_during_scan"], 16)
            self.assertFalse(usn_files[0]["details"]["next_cursor_available"])
            self.assertIsNone(usn_files[0]["details"]["next_cursor_offset"])
            self.assertEqual(usn_files[0]["details"]["trailing_unparsed_bytes"], 0)
            self.assertEqual(usn_files[0]["details"]["timestamp_range"]["latest"], "2024-04-01T04:08:09+00:00")
            self.assertFalse(usn_files[0]["details"]["commercial_grade_ready"])
            self.assertEqual(native_usn[0]["details"]["file_path"], "deleted.txt")
            self.assertEqual(native_usn[0]["details"]["validation_status"], "valid")
            self.assertEqual(native_usn[0]["details"]["parser_confidence"], 0.85)
            self.assertTrue(native_usn[0]["details"]["deleted_hint"])
            self.assertIn("FILE_DELETE", native_usn[0]["details"]["reason_flags"])
            self.assertIn("ARCHIVE", native_usn[0]["details"]["file_attribute_names"])
            self.assertEqual(native_usn[0]["details"]["record_cursor"], 16)
            self.assertEqual(native_usn[0]["details"]["next_record_cursor"], native_usn[1]["details"]["record_cursor"])
            self.assertEqual(native_usn[0]["details"]["file_reference_number_decoded"]["record_number"], 42)
            self.assertEqual(native_usn[0]["details"]["parent_file_reference_number_decoded"]["record_number"], 5)
            self.assertEqual(
                native_usn[0]["details"]["usn_record_evidence"]["file_reference_evidence"]["file_name"],
                "deleted.txt",
            )
            self.assertIn("FILE_DELETE", native_usn[0]["details"]["usn_record_evidence"]["change_evidence"]["reason_flags"])
            self.assertTrue(native_usn[0]["details"]["usn_record_evidence"]["change_evidence"]["deleted_hint"])
            self.assertEqual(
                native_usn[0]["details"]["usn_record_evidence"]["validation_evidence"]["record_validation_status"],
                "valid",
            )
            self.assertIn(
                "filename_utf16_valid",
                native_usn[0]["details"]["usn_record_evidence"]["validation_evidence"]["critical_checks_passed"],
            )
            self.assertTrue(native_usn[0]["details"]["validation_checks"]["record_cursor_progresses"])
            self.assertTrue(native_usn[0]["details"]["validation_checks"]["filename_utf16_valid"])
            self.assertFalse(native_usn[0]["details"]["commercial_grade_ready"])
            self.assertIn("#13", native_usn[0]["details"]["ntfs_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(native_usn[0]["details"]["forensic_review"]["gap_id"], "#13")
            usn_gate = native_usn[0]["details"]["core_accuracy_gates"][0]
            self.assertEqual(usn_gate["gap_id"], "#13")
            self.assertIn("record-size bounds", usn_gate["satisfied_checks"])
            self.assertIn("reason flag decoding", usn_gate["satisfied_checks"])
            self.assertIn("rename/delete ordering", usn_gate["satisfied_checks"])
            self.assertIn("cursor determinism at scale", usn_gate["satisfied_checks"])
            self.assertFalse(native_usn[0]["details"]["ntfs_native_capabilities"]["usn_full_journal_replay"])
            usn_uplift = native_usn[0]["details"]["commercial_uplift_evidence"]
            self.assertEqual(usn_uplift["item_numbers"], [13])
            self.assertIn("record-cursor-progresses", usn_uplift["passed_validation_matrix_ids"])
            self.assertEqual(usn_uplift["large_data_controls"]["record_cursor"], 16)
            self.assertEqual(native_usn[1]["details"]["major_version"], 3)
            self.assertEqual(native_usn[1]["details"]["file_path"], "renamed.txt")
            self.assertEqual(native_usn[1]["details"]["rename_hint"], "rename-new-name")
            self.assertIn("CLOSE", native_usn[1]["details"]["reason_flags"])
            self.assertEqual(native_usn[1]["details"]["file_reference_number_decoded"]["format"], "file-id-128")
            self.assertEqual(native_usn[2]["details"]["record_size_class"], "large")
            self.assertGreaterEqual(native_usn[2]["details"]["record_length"], 512)
            self.assertGreaterEqual(native_usn[2]["details"]["file_name_length"], 512)
            self.assertEqual(native_usn[2]["details"]["file_name_decode_status"], "valid")
            self.assertTrue(native_usn[2]["details"]["validation_checks"]["large_record"])
            self.assertIn("DATA_EXTEND", native_usn[2]["details"]["reason_flags"])
            self.assertIn("CLOSE", native_usn[2]["details"]["reason_flags"])

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
            edb_page_candidates = [
                item for item in artifacts if item["artifact_type"] == "windows-search-edb-page-candidate"
            ]
            edb_table_candidates = [
                item for item in artifacts if item["artifact_type"] == "windows-search-edb-table-candidate"
            ]
            edb_row_candidates = [
                item for item in artifacts if item["artifact_type"] == "windows-search-edb-row-candidate"
            ]
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
            self.assertTrue(
                any("encoded powershell investigation notes" in value for value in edb_files[0]["details"]["content_candidates"])
            )
            self.assertFalse(edb_files[0]["details"]["commercial_grade_ready"])
            self.assertIn("native-ese-catalog-decoding-required", edb_files[0]["details"]["commercial_grade_blockers"])
            self.assertIn("#11", edb_files[0]["details"]["search_index_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(edb_files[0]["details"]["forensic_review"]["gap_id"], "#11")
            edb_gate = edb_files[0]["details"]["core_accuracy_gates"][0]
            self.assertEqual(edb_gate["gap_id"], "#11")
            self.assertIn("catalog/table/page mapping", edb_gate["satisfied_checks"])
            self.assertIn("path/URL/content correlation", edb_gate["satisfied_checks"])
            self.assertIn("page-level source citation", edb_gate["satisfied_checks"])
            self.assertFalse(edb_files[0]["details"]["search_index_native_capabilities"]["native_row_level_decode"])
            self.assertTrue(edb_files[0]["details"]["search_index_native_capabilities"]["native_page_map_triage"])
            self.assertEqual(
                edb_files[0]["details"]["edb_analysis_method"]["method_id"],
                "ese-page-map-string-correlation-v1",
            )
            self.assertTrue(edb_files[0]["details"]["native_validation"]["page_map_built"])
            self.assertFalse(edb_files[0]["details"]["native_validation"]["row_level_decoding_available"])
            self.assertGreaterEqual(edb_files[0]["details"]["native_candidate_metadata"]["page_count_scanned"], 1)
            self.assertGreaterEqual(edb_files[0]["details"]["native_candidate_metadata"]["page_candidate_count"], 1)
            self.assertGreaterEqual(edb_files[0]["details"]["native_candidate_metadata"]["table_candidate_count"], 3)
            self.assertGreaterEqual(edb_files[0]["details"]["native_candidate_metadata"]["row_candidate_count"], 1)
            edb_uplift = edb_files[0]["details"]["commercial_uplift_evidence"]
            self.assertEqual(edb_uplift["batch_id"], "commercial-uplift-011-015")
            self.assertEqual(edb_uplift["item_numbers"], [11])
            self.assertIn("ese-signature-valid", edb_uplift["passed_validation_matrix_ids"])
            self.assertTrue(edb_uplift["large_data_controls"]["row_level_native_decode_required_for_commercial_claims"])
            self.assertEqual(
                edb_files[0]["details"]["native_validation"]["row_candidate_decode_status"],
                "correlated-native-string-candidates-only",
            )
            self.assertTrue(any(item["details"]["file_name"] == "Incident Notes.docx" for item in edb_pivots))
            self.assertTrue(any(item["details"]["url"] == "https://example.com/browser-history" for item in edb_pivots))
            self.assertTrue(any(item["details"]["candidate_kind"] == "content" for item in edb_pivots))
            self.assertTrue(all(item["details"]["validation_required"] for item in edb_pivots))
            self.assertTrue(all(not item["details"]["commercial_grade_ready"] for item in edb_pivots))
            self.assertTrue(edb_page_candidates)
            page_candidate = edb_page_candidates[0]
            self.assertEqual(page_candidate["details"]["candidate_basis"]["method_id"], "ese-page-map-string-correlation-v1")
            self.assertGreaterEqual(page_candidate["details"]["page_index"], 1)
            self.assertGreaterEqual(page_candidate["details"]["page_offset"], 8192)
            self.assertEqual(len(page_candidate["details"]["page_sha256"]), 64)
            self.assertTrue(page_candidate["details"]["path_candidates"])
            self.assertTrue(page_candidate["details"]["content_candidates"])
            self.assertIn("property-store", page_candidate["details"]["table_marker_hits"])
            self.assertFalse(page_candidate["details"]["commercial_grade_ready"])
            self.assertTrue(any(item["details"]["table_family"] == "property-store" for item in edb_table_candidates))
            self.assertTrue(any(item["details"]["table_family"] == "content-index" for item in edb_table_candidates))
            self.assertTrue(any(item["details"]["table_family"] == "deleted-state" for item in edb_table_candidates))
            self.assertTrue(all(not item["details"]["commercial_grade_ready"] for item in edb_table_candidates))
            self.assertTrue(
                all(not item["details"]["validation_checks"]["row_level_decoding_available"] for item in edb_table_candidates)
            )
            self.assertTrue(any(item["details"]["file_name"] == "Incident Notes.docx" for item in edb_row_candidates))
            row_candidate = next(item for item in edb_row_candidates if item["details"]["file_name"] == "Incident Notes.docx")
            self.assertEqual(row_candidate["details"]["item_path"], r"C:\Users\alice\Documents\Incident Notes.docx")
            self.assertIn("encoded powershell", row_candidate["details"]["content_snippet"])
            self.assertEqual(row_candidate["details"]["deleted_state"], "candidate-marker-present")
            self.assertEqual(row_candidate["details"]["timestamp_source"], "not-decoded-native-edb")
            self.assertEqual(
                row_candidate["details"]["candidate_basis"]["correlation_method"],
                "path-content-url-position-correlation",
            )
            self.assertIn("search-index-suspicious-row-text", row_candidate["details"]["risk_flags"])
            self.assertTrue(row_candidate["details"]["validation_required"])
            self.assertFalse(row_candidate["details"]["commercial_grade_ready"])
            self.assertIn("#11", row_candidate["details"]["search_index_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(row_candidate["details"]["forensic_review"]["gap_id"], "#11")
            row_gate = row_candidate["details"]["core_accuracy_gates"][0]
            self.assertEqual(row_gate["gap_id"], "#11")
            self.assertIn("deleted/index-state validation", row_gate["satisfied_checks"])
            row_uplift = row_candidate["details"]["commercial_uplift_evidence"]
            self.assertIn("row-level-decoding-available", row_uplift["failed_validation_matrix_ids"])
            self.assertEqual(summary["details"]["entry_count"], 1)
            self.assertEqual(summary["details"]["inventory_count"], 1)
            self.assertGreaterEqual(summary["details"]["edb_pivot_count"], 2)
            self.assertGreaterEqual(summary["details"]["edb_page_candidate_count"], 1)
            self.assertGreaterEqual(summary["details"]["edb_table_candidate_count"], 3)
            self.assertGreaterEqual(summary["details"]["edb_row_candidate_count"], 1)
            self.assertGreater(summary["details"]["edb_string_hit_count"], 0)
            self.assertIn({"value": ".docx", "count": 1}, summary["details"]["extension_counts"])
            self.assertIn({"value": "property-store", "count": 1}, summary["details"]["table_family_counts"])
            self.assertFalse(summary["details"]["commercial_grade_ready"])

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
            self.assertIn("#18", wmi[0]["details"]["system_report_grade_assessment"]["commercial_gap_ids"])
            self.assertFalse(wmi[0]["details"]["system_native_capabilities"]["native_wmi_repository_decode"])
            wmi_gate = wmi[0]["details"]["core_accuracy_gates"][0]
            self.assertEqual(wmi_gate["gap_id"], "#18")
            self.assertIn("event semantics and risk rules", wmi_gate["satisfied_checks"])
            self.assertIn("WMI consumer/filter binding validation", wmi_gate["missing_required_checks"])
            wmi_uplift = wmi[0]["details"]["commercial_uplift_evidence"]
            self.assertEqual(wmi_uplift["batch_id"], "commercial-uplift-016-020")
            self.assertEqual(wmi_uplift["item_numbers"], [18])
            self.assertIn("wmi-source-parsed", wmi_uplift["passed_validation_matrix_ids"])
            self.assertTrue(wmi_uplift["large_data_controls"]["native_repository_or_rule_store_decode_required"])
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
            self.assertEqual(task["details"]["coverage_status"], "task-xml-normalized")
            self.assertEqual(task["details"]["executable_name"], "powershell.exe")
            self.assertEqual(task["details"]["normalized_action"]["path_category"], "user-writable")
            self.assertEqual(task["details"]["trigger_details"][0]["trigger_type"], "LogonTrigger")
            self.assertEqual(task["details"]["trigger_details"][0]["start_boundary"], "2024-04-01T09:00:00")
            self.assertTrue(task["details"]["validation_checks"]["has_exec_action"])
            self.assertFalse(task["details"]["validation_checks"]["taskcache_registry_validated"])
            self.assertFalse(task["details"]["commercial_grade_ready"])
            self.assertIn("task-cache-registry-correlation-not-implemented", task["details"]["commercial_grade_blockers"])
            self.assertIn("#18", task["details"]["system_report_grade_assessment"]["commercial_gap_ids"])
            self.assertFalse(task["details"]["system_native_capabilities"]["taskcache_registry_correlation"])
            task_gate = task["details"]["core_accuracy_gates"][0]
            self.assertEqual(task_gate["gap_id"], "#18")
            self.assertIn("event semantics and risk rules", task_gate["satisfied_checks"])
            self.assertIn("Task XML/TaskCache correlation", task_gate["missing_required_checks"])
            task_uplift = task["details"]["commercial_uplift_evidence"]
            self.assertEqual(task_uplift["batch_id"], "commercial-uplift-016-020")
            self.assertEqual(task_uplift["item_numbers"], [18])
            self.assertIn("task-exec-action", task_uplift["passed_validation_matrix_ids"])
            self.assertIn("task-report-grade-correlation", task_uplift["failed_validation_matrix_ids"])
            self.assertEqual(len(task["details"]["source_hashes"]["sha256"]), 64)
            self.assertIn("task-string:powershell", task["details"]["risk_flags"])
            self.assertIn("task-user-writable-path", task["details"]["risk_flags"])
            self.assertIn("task-microsoft-path-user-payload", task["details"]["risk_flags"])
            self.assertGreater(task["details"]["risk_score"], 0)


if __name__ == "__main__":
    unittest.main()
