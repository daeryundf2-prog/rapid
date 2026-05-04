from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from rapidtriage.artifacts.windows.eventlog import (
    binxml_value_field_map,
    native_evtx_commercial_uplift_evidence,
    native_evtx_core_accuracy_gates,
    native_evtx_promoted_fields,
)
from rapidtriage.artifacts.windows.registry import collect_registry_hive
from rapidtriage.artifacts.windows.shellbags import WindowsShellbagsProvider
from rapidtriage.cli import main
from tests.windows_artifact_fixtures import build_minimal_registry_hive, build_minimal_shellbags_registry_hive

FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "rapidtriage" / "windows_artifacts"


class RapidTriageWindowsArtifactsCollectorTests(unittest.TestCase):
    def test_native_evtx_binxml_promotes_duplicate_event_data_without_losing_order(self) -> None:
        value_fields = [
            {
                "element_path": "Event/EventData/Data/@Name",
                "text": "TargetUserName",
                "value_type": "StringType",
                "confidence": "binxml-attribute",
            },
            {
                "element_path": "Event/EventData/Data",
                "text": "alice",
                "value_type": "StringType",
                "confidence": "binxml-template-substitution",
            },
            {
                "element_path": "Event/EventData/Data/@Name",
                "text": "IpAddress",
                "value_type": "StringType",
                "confidence": "binxml-attribute",
            },
            {
                "element_path": "Event/EventData/Data",
                "text": "10.0.0.5",
                "value_type": "StringType",
                "confidence": "binxml-template-substitution",
            },
            {
                "element_path": "Event/EventData/Data/@Name",
                "text": "IpAddress",
                "value_type": "StringType",
                "confidence": "binxml-attribute",
            },
            {
                "element_path": "Event/EventData/Data",
                "text": "10.0.0.6",
                "value_type": "StringType",
                "confidence": "binxml-template-substitution",
            },
        ]

        promoted = native_evtx_promoted_fields({"value_fields": value_fields})

        self.assertEqual(promoted["event_data_fields"]["TargetUserName"], "alice")
        self.assertEqual(promoted["event_data_fields"]["IpAddress"], "10.0.0.5")
        self.assertEqual(promoted["event_data_values_by_name"]["IpAddress"], ["10.0.0.5", "10.0.0.6"])
        self.assertEqual(
            [item["name"] for item in promoted["event_data_sequence"]],
            ["TargetUserName", "IpAddress", "IpAddress"],
        )
        self.assertEqual(
            [item["value"] for item in promoted["event_data_sequence"]],
            ["alice", "10.0.0.5", "10.0.0.6"],
        )
        self.assertEqual(
            binxml_value_field_map(value_fields)["Event/EventData/Data"],
            ["alice", "10.0.0.5", "10.0.0.6"],
        )

    def test_native_evtx_core_accuracy_gates_track_report_grade_blockers(self) -> None:
        gates = native_evtx_core_accuracy_gates(
            {
                "source_path": "Security.evtx",
                "record_id": "42",
                "event_id": "4624",
                "provider_name": "Microsoft-Windows-Security-Auditing",
                "channel": "Security",
                "computer": "host01",
                "evtx_record_offset": 8192,
                "evtx_record_sha256": "a" * 64,
                "binxml_status": "partial-tokenized",
                "binxml_event_data_sequence": [
                    {"name": "TargetUserName", "value": "alice"},
                    {"name": "IpAddress", "value": "10.0.0.5"},
                ],
                "binxml_event_data_values_by_name": {"IpAddress": ["10.0.0.5"]},
                "evtx_validation_checks": {
                    "declared_size_valid": True,
                    "decoded_value_type_counts": {"StringType": 2},
                },
                "evtx_validation_matrix": [
                    {"id": "chunk-context", "passed": True},
                    {"id": "declared-size-and-offset", "passed": True},
                    {"id": "integrity-hash", "passed": True},
                ],
                "evtx_record_integrity": {"record_hash": "a" * 64},
                "evtx_recovery_context": {"validation_required": True},
                "evtx_recovery_evidence": {"caution_labels": ["slack-record-candidate"]},
                "message_rendering": {
                    "event_message": "An account was successfully logged on.",
                    "normalized_template_preview": "%1 logged on from %2",
                    "parameter_candidates": ["alice", "10.0.0.5"],
                    "limitations": ["provider-resource-dll-not-resolved"],
                },
                "evtx_validation_guidance": {"message": "Compare against Event Viewer rendering."},
            }
        )

        by_gap = {gate["gap_id"]: gate for gate in gates}
        self.assertEqual(set(by_gap), {"#1", "#2", "#3"})
        self.assertIn("duplicate EventData order preservation", by_gap["#1"]["satisfied_checks"])
        self.assertIn("message text normalization", by_gap["#2"]["satisfied_checks"])
        self.assertIn("inserted parameter mapping", by_gap["#2"]["satisfied_checks"])
        self.assertIn("provider/template/source provenance", by_gap["#2"]["satisfied_checks"])
        self.assertIn("chunk-boundary containment", by_gap["#3"]["satisfied_checks"])
        self.assertEqual(by_gap["#1"]["missing_required_checks"], [])
        self.assertIn("expected-answer manifest", by_gap["#1"]["minimum_evidence"])
        self.assertFalse(by_gap["#1"]["commercial_grade_ready"])
        uplift = native_evtx_commercial_uplift_evidence(
            {
                "source_path": "Security.evtx",
                "record_id": "42",
                "evtx_record_offset": 8192,
                "evtx_record_sha256": "a" * 64,
                "evtx_report_grade_assessment": {
                    "status": "validation-required",
                    "blockers": [
                        "full-binxml-field-decoding-required",
                        "broad-deleted-corrupt-record-corpus-validation-required",
                    ],
                },
            }
        )
        blocker_categories = {row["blocker"]: row["category"] for row in uplift["commercial_blocker_analysis"]}
        self.assertEqual(blocker_categories["full-binxml-field-decoding-required"], "internal_implementation")
        self.assertEqual(
            blocker_categories["broad-deleted-corrupt-record-corpus-validation-required"],
            "external_validation",
        )

    def test_shellbags_provider_emits_native_hive_candidate_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            hive_path = Path(tmp_dir) / "Users" / "alice" / "UsrClass.dat"
            hive_path.parent.mkdir(parents=True, exist_ok=True)
            hive_path.write_bytes(
                build_minimal_shellbags_registry_hive(
                    datetime(2024, 4, 2, 3, 4, 5, tzinfo=timezone.utc),
                    "UsrClass.dat",
                )
            )

            records = list(WindowsShellbagsProvider().collect(Path(tmp_dir)))
            native = [record for record in records if record.artifact_type == "shellbag-native-candidate"]

            self.assertTrue(native)
            key_tree = next(record for record in native if record.details["candidate_source"] == "native-key-tree")
            self.assertEqual(key_tree.details["shellbag_section"], "bagmru")
            self.assertIn("0", key_tree.details["node_id_candidates"])
            self.assertIn("42", key_tree.details["bag_id_candidates"])
            self.assertTrue(key_tree.details["timestamp_candidates"])
            self.assertEqual(key_tree.details["shellbag_evidence"]["key_evidence"]["shellbag_section"], "bagmru")
            self.assertEqual(
                key_tree.details["shellbag_evidence"]["relationship_evidence"]["bag_node_relationship_status"],
                "candidate-from-key-path-and-values",
            )
            self.assertIn("42", key_tree.details["shellbag_evidence"]["relationship_evidence"]["bag_id_candidates"])
            self.assertIn("0", key_tree.details["shellbag_evidence"]["relationship_evidence"]["node_id_candidates"])
            self.assertEqual(
                key_tree.details["shellbag_evidence"]["activity_evidence"]["primary_timestamp"],
                "2024-04-02T03:04:05+00:00",
            )
            self.assertEqual(key_tree.details["forensic_review"]["gap_id"], "#15")
            self.assertIn("ShellBags", key_tree.details["forensic_review"]["artifact_goal"])
            self.assertTrue(key_tree.details["validation_checks"]["regf_header_valid"])
            self.assertFalse(key_tree.details["validation_checks"]["binary_shell_item_decoding_available"])
            self.assertFalse(key_tree.details["commercial_grade_ready"])
            self.assertIn("#15", key_tree.details["shellbag_report_grade_assessment"]["commercial_gap_ids"])
            self.assertFalse(key_tree.details["shellbag_native_capabilities"]["binary_shell_item_decode"])
            self.assertIn("requires_dedicated_shellbags_parser", key_tree.details["validation_checks"])
            shellbag_gate = key_tree.details["core_accuracy_gates"][0]
            self.assertEqual(shellbag_gate["gap_id"], "#15")
            self.assertIn("BagMRU/Bags relationship", shellbag_gate["satisfied_checks"])
            self.assertIn("timestamp source labeling", shellbag_gate["satisfied_checks"])
            self.assertIn("UsrClass/NTUSER correlation", shellbag_gate["satisfied_checks"])
            self.assertIn("deleted/slack validation warning", shellbag_gate["satisfied_checks"])
            self.assertIn("shell item binary decoding", shellbag_gate["missing_required_checks"])
            shellbag_uplift = key_tree.details["commercial_uplift_evidence"]
            self.assertEqual(shellbag_uplift["batch_id"], "commercial-uplift-011-015")
            self.assertEqual(shellbag_uplift["item_numbers"], [15])
            self.assertIn("regf-header-valid", shellbag_uplift["passed_validation_matrix_ids"])
            self.assertIn("binary-shell-item-decoding-available", shellbag_uplift["failed_validation_matrix_ids"])
            self.assertTrue(
                shellbag_uplift["large_data_controls"]["transaction_log_replay_required_for_commercial_claims"]
            )

    def test_registry_hive_reconstructs_native_key_and_value_links(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            hive_path = Path(tmp_dir) / "NTUSER.DAT"
            hive_path.write_bytes(
                build_minimal_registry_hive(
                    datetime(2024, 4, 1, 4, 5, 6, tzinfo=timezone.utc),
                    "NTUSER.DAT",
                    [
                        r"Software\Microsoft\Windows\CurrentVersion\Run",
                        r"C:\Users\alice\AppData\Roaming\SecurityUpdater.exe",
                    ],
                )
            )
            (hive_path.parent / "NTUSER.DAT.LOG1").write_bytes(b"registry transaction log fixture")

            records = list(collect_registry_hive(hive_path))

            hive_inventory = next(record for record in records if record.artifact_type == "registry-hive")
            key_tree_nodes = [record for record in records if record.artifact_type == "registry-key-tree-node"]
            run_key = next(record for record in key_tree_nodes if record.details["name"] == "Run")
            self.assertEqual(run_key.details["key_path"], "HKEY_CURRENT_USER\\Software\\Run")
            self.assertEqual(run_key.details["key_path_confidence"], "parent-chain")
            self.assertEqual(run_key.details["key_path_components"], ["Software", "Run"])
            self.assertEqual(run_key.details["key_depth"], 2)
            self.assertEqual(run_key.details["key_tree_path_evidence"]["full_path"], "HKEY_CURRENT_USER\\Software\\Run")
            self.assertEqual(run_key.details["key_tree_path_evidence"]["path_confidence"], "parent-chain")
            self.assertTrue(run_key.details["key_tree_path_evidence"]["root_reachable"])
            self.assertTrue(run_key.details["root_reachable"])
            self.assertFalse(run_key.details["is_root_key"])
            self.assertTrue(run_key.details["parent_link_consistency"])
            self.assertEqual(
                run_key.details["registry_key_tree_relationships"]["ancestor_cell_offsets"],
                run_key.details["key_ancestry_cell_offsets"],
            )
            self.assertFalse(run_key.details["key_tree_path_evidence"]["cycle_detected"])
            self.assertEqual(len(run_key.details["key_ancestry_cell_offsets"]), 2)
            self.assertEqual(run_key.details["value_names"], ["SecurityUpdater"])
            self.assertEqual(run_key.details["linked_value_count"], 1)
            self.assertEqual(run_key.details["missing_value_cell_offsets"], [])
            self.assertFalse(run_key.details["validation_required"])
            self.assertFalse(run_key.details["commercial_grade_ready"])
            self.assertEqual(
                run_key.details["registry_report_grade_assessment"]["status"],
                "triage-validated-report-grade-blocked",
            )
            self.assertIn("#4", run_key.details["registry_report_grade_assessment"]["commercial_gap_ids"])
            self.assertTrue(run_key.details["registry_native_capabilities"]["parent_chain_path_reconstruction"])
            self.assertFalse(run_key.details["registry_native_capabilities"]["transaction_log_replay"])
            self.assertEqual(
                hive_inventory.details["registry_transaction_log_evidence"]["status"],
                "present-not-replayed",
            )
            self.assertEqual(run_key.details["registry_transaction_log_evidence"]["present_count"], 1)
            self.assertFalse(run_key.details["registry_transaction_log_evidence"]["transaction_log_replay_applied"])
            self.assertEqual(
                run_key.details["registry_transaction_log_evidence"]["present_logs"][0]["name"],
                "NTUSER.DAT.LOG1",
            )
            validation_matrix = {item["id"]: item for item in run_key.details["registry_validation_matrix"]}
            self.assertTrue(validation_matrix["regf-header"]["passed"])
            self.assertTrue(validation_matrix["parent-chain"]["passed"])
            self.assertTrue(validation_matrix["root-reachability"]["passed"])
            self.assertTrue(validation_matrix["child-parent-backlinks"]["passed"])
            self.assertTrue(validation_matrix["value-list-resolution"]["passed"])
            self.assertTrue(validation_matrix["transaction-log-context-recorded"]["passed"])
            self.assertEqual(validation_matrix["transaction-log-context-recorded"]["detail"], "present-not-replayed")
            key_gate = run_key.details["core_accuracy_gates"][0]
            self.assertEqual(key_gate["gap_id"], "#4")
            self.assertIn("root-cell reachability", key_gate["satisfied_checks"])
            self.assertIn("parent-child backlink consistency", key_gate["satisfied_checks"])
            self.assertIn("transaction-log replay disclosure", key_gate["satisfied_checks"])
            self.assertEqual(key_gate["missing_required_checks"], [])
            self.assertIn("source file or export hash", key_gate["minimum_evidence"])
            self.assertFalse(key_gate["commercial_grade_ready"])
            key_uplift = run_key.details["commercial_uplift_evidence"]
            self.assertEqual(key_uplift["batch_id"], "commercial-uplift-001-005")
            self.assertEqual(key_uplift["item_numbers"], [4])
            self.assertEqual(key_uplift["implementation_track"], "native-parser-depth")
            self.assertIn("root-reachability", key_uplift["passed_validation_matrix_ids"])
            key_blocker_categories = {
                row["blocker"]: row["category"] for row in key_uplift["commercial_blocker_analysis"]
            }
            self.assertEqual(
                key_blocker_categories["transaction-log-replay-not-implemented"],
                "internal_implementation",
            )
            self.assertEqual(
                key_blocker_categories["deleted-cell-known-answer-corpus-validation-required"],
                "external_validation",
            )
            self.assertEqual(key_uplift["large_data_controls"]["reader"], "bounded-hbin-cell-scan")
            self.assertTrue(
                key_uplift["large_data_controls"]["transaction_log_replay_required_for_commercial_claims"]
            )

            value_recovery = next(
                record
                for record in records
                if record.artifact_type == "registry-value-recovery-candidate"
                and record.details["name"] == "SecurityUpdater"
            )
            self.assertEqual(value_recovery.details["parent_key_path_candidate"], "HKEY_CURRENT_USER\\Software\\Run")
            self.assertEqual(value_recovery.details["parent_key_confidence"], "key-value-list")
            self.assertGreater(value_recovery.details["parent_key_cell_offset"], 0)
            self.assertEqual(value_recovery.details["decoded_data_preview"], "1")
            self.assertEqual(
                value_recovery.details["registry_report_grade_assessment"]["status"],
                "recovery-candidate-validation-required",
            )
            self.assertEqual(
                value_recovery.details["registry_recovery_evidence"]["candidate_kind"],
                "deleted-or-free-value-cell",
            )
            self.assertTrue(value_recovery.details["registry_recovery_evidence"]["positive_size_free_cell"])
            self.assertEqual(value_recovery.details["registry_recovery_evidence"]["parent_confidence"], "key-value-list")
            self.assertIn(
                "parent:key-value-list",
                value_recovery.details["registry_recovery_evidence"]["evidence_reasons"],
            )
            self.assertEqual(
                value_recovery.details["registry_recovery_validation_profile"]["candidate_class"],
                "deleted-value-cell",
            )
            self.assertFalse(
                value_recovery.details["registry_recovery_validation_profile"][
                    "reportable_without_secondary_validation"
                ]
            )
            self.assertIn(
                "parent-key-link-confirmation",
                value_recovery.details["registry_recovery_validation_profile"]["required_independent_checks"],
            )
            self.assertIn("#5", value_recovery.details["registry_report_grade_assessment"]["commercial_gap_ids"])
            self.assertIn(
                "deleted-or-free-cell-independent-validation-required",
                value_recovery.details["registry_report_grade_assessment"]["blockers"],
            )
            value_matrix = {item["id"]: item for item in value_recovery.details["registry_validation_matrix"]}
            self.assertTrue(value_matrix["deleted-value-cell"]["passed"])
            self.assertTrue(value_matrix["parent-key-link"]["passed"])
            value_gate = value_recovery.details["core_accuracy_gates"][0]
            self.assertEqual(value_gate["gap_id"], "#5")
            self.assertIn("positive-size free-cell validation", value_gate["satisfied_checks"])
            self.assertIn("parent-key confirmation", value_gate["satisfied_checks"])
            self.assertIn("reportability blocked until independent confirmation", value_gate["satisfied_checks"])
            self.assertEqual(value_gate["missing_required_checks"], [])
            self.assertIn("expected-answer manifest", value_gate["minimum_evidence"])
            self.assertFalse(value_gate["commercial_grade_ready"])
            value_uplift = value_recovery.details["commercial_uplift_evidence"]
            self.assertEqual(value_uplift["batch_id"], "commercial-uplift-001-005")
            self.assertEqual(value_uplift["item_numbers"], [5])
            self.assertIn("deleted-value-cell", value_uplift["passed_validation_matrix_ids"])
            self.assertEqual(
                value_uplift["recovery_profile_version"],
                "registry-deleted-cell-validation-v1",
            )
            self.assertTrue(value_uplift["external_evidence_required"])
            key_recovery = next(
                record
                for record in records
                if record.artifact_type == "registry-key-recovery-candidate"
                and record.details["name"] == "DeletedRun"
            )
            self.assertEqual(
                key_recovery.details["registry_recovery_validation_profile"]["candidate_class"],
                "deleted-key-cell",
            )
            self.assertIn(
                "parent-chain-and-root-reachability-review",
                key_recovery.details["registry_recovery_validation_profile"]["required_independent_checks"],
            )
            self.assertEqual(key_recovery.details["commercial_uplift_evidence"]["item_numbers"], [5])

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
            ntuser_activity = root / "Users" / "alice" / "NTUSER-activity.reg"
            ntuser_activity.write_text(
                """Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count]
"P:\\Hfref\\nyvpr\\NccQngn\\Ebnzvat\\rivy.rkr"=hex:01,00,00,00

[HKEY_CURRENT_USER\\Software\\Microsoft\\Internet Explorer\\TypedURLs]
"url1"="https://example.test/login"

[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths]
"url1"="C:\\\\Users\\\\alice\\\\Documents"

[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce]
"OneShot"="C:\\\\Users\\\\alice\\\\AppData\\\\Roaming\\\\oneshot.exe"
""",
                encoding="utf-16",
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
            self.assertIn("registry-hive-cell", registry_types)
            self.assertIn("registry-key-tree-node", registry_types)
            self.assertIn("registry-key-recovery-candidate", registry_types)
            self.assertIn("registry-deleted-cell-candidate", registry_types)
            self.assertIn("registry-value-recovery-candidate", registry_types)
            self.assertIn("registry-hive-strings", registry_types)
            self.assertIn("registry-run-key", registry_types)
            self.assertIn("registry-usb", registry_types)
            self.assertIn("registry-user-activity", registry_types)
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
            hive_cells = [artifact for artifact in registry_provider["artifacts"] if artifact["artifact_type"] == "registry-hive-cell"]
            self.assertGreaterEqual(len(hive_cells), 4)
            self.assertTrue(any(artifact["details"]["cell_kind"] == "key-node" for artifact in hive_cells))
            updater_value = next(artifact for artifact in hive_cells if artifact["details"]["name"] == "SecurityUpdater")
            self.assertEqual(updater_value["details"]["allocation_status"], "free-or-deleted-candidate")
            self.assertEqual(updater_value["details"]["cell_scan_method"], "hbin-walk")
            self.assertGreater(updater_value["details"]["hbin_offset"], 0)
            self.assertIn("deleted-or-free-cell-candidate", updater_value["details"]["risk_flags"])
            key_tree_nodes = [
                artifact for artifact in registry_provider["artifacts"] if artifact["artifact_type"] == "registry-key-tree-node"
            ]
            self.assertTrue(any(artifact["details"]["key_path"].endswith("\\Run") for artifact in key_tree_nodes))
            self.assertTrue(all("cell_offset" in artifact["details"] for artifact in key_tree_nodes))
            deleted_cells = [
                artifact for artifact in registry_provider["artifacts"] if artifact["artifact_type"] == "registry-deleted-cell-candidate"
            ]
            self.assertGreaterEqual(len(deleted_cells), 2)
            self.assertTrue(all(artifact["details"]["validation_required"] for artifact in deleted_cells))
            self.assertTrue(all(artifact["details"]["registry_recovery_evidence"]["validation_required"] for artifact in deleted_cells))
            self.assertTrue(
                all(
                    not artifact["details"]["registry_recovery_validation_profile"][
                        "reportable_without_secondary_validation"
                    ]
                    for artifact in deleted_cells
                )
            )
            self.assertTrue(any(artifact["details"]["name"] == "SecurityUpdater" for artifact in deleted_cells))
            key_recovery = [
                artifact for artifact in registry_provider["artifacts"] if artifact["artifact_type"] == "registry-key-recovery-candidate"
            ]
            self.assertTrue(any(artifact["details"]["name"] == "DeletedRun" for artifact in key_recovery))
            self.assertTrue(all(artifact["details"]["validation_required"] for artifact in key_recovery))
            self.assertTrue(
                all(
                    artifact["details"]["registry_recovery_validation_profile"]["candidate_class"]
                    == "deleted-key-cell"
                    for artifact in key_recovery
                )
            )
            self.assertTrue(
                any(
                    "allocator:positive-size-free-cell" in artifact["details"]["registry_recovery_evidence"]["evidence_reasons"]
                    for artifact in key_recovery
                )
            )
            value_recovery = [
                artifact for artifact in registry_provider["artifacts"] if artifact["artifact_type"] == "registry-value-recovery-candidate"
            ]
            self.assertTrue(any(artifact["details"]["name"] == "SecurityUpdater" for artifact in value_recovery))
            self.assertTrue(all(artifact["details"]["validation_required"] for artifact in value_recovery))
            self.assertTrue(
                all(
                    artifact["details"]["registry_recovery_validation_profile"]["candidate_class"]
                    == "deleted-value-cell"
                    for artifact in value_recovery
                )
            )
            run_key = next(artifact for artifact in registry_provider["artifacts"] if artifact["artifact_type"] == "registry-run-key")
            self.assertIn("SecurityUpdater", run_key["details"]["values"])
            self.assertEqual(run_key["details"]["persistence_values"][0]["value_name"], "SecurityUpdater")
            self.assertIn("suspicious-value:appdata", run_key["details"]["risk_flags"])
            user_activity = [
                artifact for artifact in registry_provider["artifacts"] if artifact["artifact_type"] == "registry-user-activity"
            ]
            categories = {artifact["details"]["user_activity_category"] for artifact in user_activity}
            self.assertIn("execution", categories)
            self.assertIn("browser-typed-url", categories)
            self.assertIn("typed-path", categories)
            self.assertIn("persistence", categories)
            self.assertIn("shellbag", categories)
            userassist = next(artifact for artifact in user_activity if artifact["details"]["user_activity_category"] == "execution")
            self.assertEqual(
                userassist["details"]["decoded_values"][r"P:\Hfref\nyvpr\NccQngn\Ebnzvat\rivy.rkr"]["decoded_name"],
                r"C:\Users\alice\AppData\Roaming\evil.exe",
            )
            typed_url = next(artifact for artifact in user_activity if artifact["details"]["user_activity_category"] == "browser-typed-url")
            self.assertEqual(typed_url["details"]["decoded_values"]["url1"]["typed_value"], "https://example.test/login")
            hive_shellbag = next(
                artifact
                for artifact in user_activity
                if artifact["details"]["coverage_status"] == "native-hive-string-pivot"
                and artifact["details"]["user_activity_category"] == "shellbag"
            )
            self.assertTrue(hive_shellbag["details"]["validation_required"])
            usb_key = next(artifact for artifact in registry_provider["artifacts"] if artifact["artifact_type"] == "registry-usb")
            self.assertEqual(usb_key["details"]["usb_device"]["serial_hint"], "1234567890")
            summary = next(artifact for artifact in registry_provider["artifacts"] if artifact["artifact_type"] == "registry-summary")
            self.assertEqual(summary["details"]["key_count"], 7)
            self.assertEqual(summary["details"]["hive_file_count"], 2)
            self.assertEqual(summary["details"]["hive_string_row_count"], 2)
            self.assertGreaterEqual(summary["details"]["hive_cell_row_count"], 4)
            self.assertGreaterEqual(summary["details"]["key_tree_node_count"], 2)
            self.assertGreaterEqual(summary["details"]["deleted_cell_candidate_count"], 2)
            self.assertGreaterEqual(summary["details"]["key_recovery_candidate_count"], 2)
            self.assertGreaterEqual(summary["details"]["value_recovery_candidate_count"], 2)
            self.assertGreaterEqual(summary["details"]["user_activity_count"], 5)
            self.assertEqual(summary["details"]["persistence_entries"][0]["value_name"], "SecurityUpdater")
            self.assertEqual(summary["details"]["usb_devices"][0]["friendly_name"], "Test USB Device")
            self.assertTrue(summary["details"]["hive_string_hits"])
            self.assertTrue(summary["details"]["hive_cell_hits"])
            self.assertTrue(summary["details"]["key_tree_nodes"])
            self.assertTrue(summary["details"]["deleted_cell_candidates"])
            self.assertTrue(summary["details"]["key_recovery_candidates"])
            self.assertTrue(summary["details"]["value_recovery_candidates"])
            self.assertTrue(summary["details"]["user_activity_entries"])
            self.assertFalse(summary["details"]["native_capabilities"]["transaction_log_replay"])
            status_counts = {
                item["value"]: item["count"] for item in summary["details"]["native_report_grade_status_counts"]
            }
            self.assertGreaterEqual(
                status_counts["triage-validated-report-grade-blocked"],
                2,
            )
            self.assertIn(
                {"value": "recovery-candidate-validation-required", "count": 4},
                summary["details"]["native_report_grade_status_counts"],
            )

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
            self.assertIn("#18", defender["details"]["system_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(defender["details"]["forensic_review"]["gap_id"], "#18")
            self.assertFalse(defender["details"]["system_native_capabilities"]["defender_event_mpcmdrun_correlation"])
            firewall = next(artifact for artifact in system_provider["artifacts"] if artifact["artifact_type"] == "firewall-log")
            self.assertEqual(firewall["details"]["blocked_count"], 1)
            self.assertIn("#18", firewall["details"]["system_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(firewall["details"]["forensic_review"]["gap_id"], "#18")
            self.assertFalse(firewall["details"]["system_native_capabilities"]["firewall_rule_store_correlation"])
            wer = next(artifact for artifact in system_provider["artifacts"] if artifact["artifact_type"] == "wer-report")
            self.assertEqual(wer["details"]["application"], "powershell.exe")
            self.assertEqual(wer["details"]["coverage_status"], "wer-key-value-normalized")
            self.assertEqual(wer["details"]["application_path"], r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
            self.assertEqual(wer["details"]["fault_module_path"], r"C:\Users\alice\AppData\Roaming\evil.dll")
            self.assertEqual(wer["details"]["exception_code"], "c0000005")
            self.assertEqual(wer["details"]["event_time"], "2026-04-26T01:04:05+00:00")
            self.assertEqual(wer["details"]["report_id"], "11111111-2222-3333-4444-555555555555")
            self.assertTrue(wer["details"]["validation_checks"]["has_exception_code"])
            self.assertFalse(wer["details"]["commercial_grade_ready"])
            self.assertIn("#18", wer["details"]["system_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(wer["details"]["forensic_review"]["gap_id"], "#18")
            self.assertIn("wer-dump-file-correlation-not-implemented", wer["details"]["commercial_grade_blockers"])
            self.assertEqual(len(wer["details"]["source_hashes"]["sha256"]), 64)
            zone = next(artifact for artifact in system_provider["artifacts"] if artifact["artifact_type"] == "zone-identifier")
            self.assertEqual(zone["details"]["zone_id"], "3")
            self.assertEqual(zone["details"]["host_url"], "https://download.example.com/report.zip")


if __name__ == "__main__":
    unittest.main()
