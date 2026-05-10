from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rapidtriage.cli import main
from rapidtriage.core.e01 import build_e01_partition_browser_contract
from rapidtriage.core.evidence import identify_evidence


class RapidTriageEvidenceAdapterTests(unittest.TestCase):
    def test_identifies_folder_as_direct_scan_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            result = identify_evidence(Path(tmp_dir)).to_dict()

            self.assertEqual(result["adapter"], "folder")
            self.assertEqual(result["detected_format"], "folder")
            self.assertEqual(result["supported"], True)
            self.assertEqual(result["can_extract"], False)
            self.assertEqual(result["support_level"], "direct-folder")
            self.assertEqual(result["scan_strategy"], "scan-folder")
            self.assertFalse(result["external_validation_required"])

    def test_identifies_e01_and_reports_external_tool_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            image_path = Path(tmp_dir) / "case.E01"
            image_path.write_bytes(b"EVF\t\r\n\xff\x00")

            result = identify_evidence(image_path).to_dict()

            self.assertEqual(result["adapter"], "ewf")
            self.assertEqual(result["detected_format"], "e01")
            self.assertIn("ewfmount", result["required_tools"])
            self.assertEqual(result["supported"], result["missing_tools"] == [])
            self.assertEqual(result["can_extract"], result["missing_tools"] == [])
            self.assertIn(result["support_level"], {"direct-extract", "tooling-required"})
            self.assertTrue(result["next_actions"])
            self.assertFalse(result["commercial_grade_ready"])
            self.assertEqual(result["source_integrity"]["hash_status"], "computed")
            self.assertIn("sha256", result["source_integrity"])
            self.assertTrue(result["tool_preflight"])
            self.assertTrue(result["preflight_summary"])
            self.assertIn(result["preflight_summary"]["status"], {"ready", "ready-version-unverified", "blocked"})
            self.assertEqual(result["preflight_summary"]["missing_tools"], result["missing_tools"])
            self.assertIn("fallback_strategy", result["preflight_summary"])
            for row in result["tool_preflight"]:
                self.assertIn("purpose", row)
                self.assertIn("install_hint", row)
                self.assertIn("windows_hint", row)
            self.assertIn("#22", result["commercial_gap_ids"])
            self.assertEqual(result["forensic_review"]["gap_id"], "#22")
            self.assertFalse(result["forensic_review"]["report_grade_ready"])
            self.assertFalse(result["native_capabilities"]["native_e01_ex01_parser"])
            e01_gate = result["core_accuracy_gates"][0]
            self.assertEqual(e01_gate["gap_id"], "#22")
            self.assertIn("source hash and segment integrity", e01_gate["satisfied_checks"])
            self.assertIn("EWF segment-set order validation", e01_gate["satisfied_checks"])
            self.assertIn("tool version/command capture", e01_gate["satisfied_checks"])
            self.assertIn("corrupt/encrypted limitation reporting", e01_gate["satisfied_checks"])
            self.assertEqual(result["segment_set_profile"]["segment_count"], 1)
            intake = result["e01_intake_profile"]
            self.assertEqual(intake["profile_version"], "e01-intake-profile-v1")
            self.assertEqual(intake["checklist_item"], 1)
            self.assertEqual(intake["qc_gap_id"], "#1")
            self.assertEqual(intake["source"]["filename"], "case.E01")
            self.assertEqual(intake["source"]["size_bytes"], image_path.stat().st_size)
            self.assertTrue(intake["source"]["supported_extension"])
            self.assertEqual(intake["source_signature"]["segment_count"], 1)
            self.assertEqual(intake["segment_set_profile"]["segment_count"], 1)
            self.assertEqual(intake["hash_feasibility"]["preflight_hash_status"], "computed")
            self.assertTrue(intake["hash_feasibility"]["full_hash_feasible_in_preflight"])
            self.assertFalse(intake["read_only_posture"]["writes_to_source"])
            self.assertTrue(intake["processing_decision"]["can_continue_to_dependency_preflight"])
            self.assertEqual(intake["reportability_decision"]["allowed_use"], "source-selection-and-preflight-context")
            self.assertEqual(len(intake["manifest_sha256"]), 64)
            self.assertEqual(result["ingest_workflow"]["profile_version"], "windows11-e01-single-case-workflow-v1")
            self.assertEqual(result["ingest_workflow"]["qc_prep_item"], 1)
            self.assertEqual(result["ingest_workflow"]["stages"][0]["id"], "select-e01")
            self.assertEqual(result["ingest_workflow"]["stages"][-1]["id"], "search-review-report")
            self.assertIn("#22", result["ingest_workflow"]["commercial_gap_ids"])
            self.assertIn(result["ingest_workflow"]["recommended_input_kind"], {"e01-derived", "mounted-or-exported-folder"})
            self.assertIn("operator_runbook", result["ingest_workflow"])
            self.assertIn("run", result["ingest_workflow"]["recommended_commands"])
            handoff = result["ingest_workflow"]["handoff_contract"]
            self.assertEqual(handoff["profile_version"], "qc-prep-e01-end-to-end-handoff-v1")
            self.assertEqual(handoff["qc_prep_item"], 1)
            self.assertIn("rapidtriage-run-summary.json", handoff["required_output_chain"])
            self.assertIn("source viewer citations", handoff["required_output_chain"])
            self.assertTrue(any(row["id"] == "start-configured-run" for row in handoff["gui_entrypoints"]))
            partition_browser = result["ingest_workflow"]["partition_browser"]
            self.assertEqual(partition_browser["profile_version"], "e01-partition-browser-v1")
            self.assertEqual(partition_browser["qc_prep_item"], 2)
            self.assertEqual(
                partition_browser["status"],
                "pending-mmls" if result["ingest_workflow"]["direct_extract_ready"] else "blocked",
            )
            self.assertIn("partition_number", partition_browser["columns"])
            self.assertIn("start_sector", partition_browser["columns"])
            self.assertIn("size_bytes", partition_browser["columns"])
            self.assertIn("filesystem_guess", partition_browser["columns"])
            self.assertIn("recommendation", partition_browser["columns"])
            self.assertTrue(partition_browser["manual_override"]["enabled"])
            self.assertEqual(partition_browser["manual_override"]["input_id"], "e01PartitionStartSectorInput")
            self.assertEqual(
                result["ingest_workflow"]["operator_runbook"]["profile_version"],
                "windows11-e01-operator-runbook-v1",
            )

            self.assertTrue(result["limitations"])
            self.assertTrue(result["fallback_guidance"])
            e01_review = result["image_analyst_review_profile"]
            self.assertEqual(e01_review["profile_version"], "image-workflow-analyst-review-profile-v1")
            self.assertEqual(e01_review["gap_id"], "#22")
            self.assertEqual(e01_review["artifact_type"], "e01-ex01-workflow")
            self.assertEqual(e01_review["source_field_values"]["detected_format"], "e01")
            self.assertIn("trusted EWF/TSK diff", e01_review["correlation_targets"])
            self.assertIn("native-parser-incomplete", e01_review["risk_tags"])
            e01_uplift = result["commercial_uplift_evidence"]
            self.assertEqual(e01_uplift["batch_id"], "commercial-uplift-021-025")
            self.assertEqual(e01_uplift["item_numbers"], [22])
            self.assertIn("#22-source-integrity", e01_uplift["passed_validation_matrix_ids"])
            self.assertIn("#22-native-commercial-parser", e01_uplift["failed_validation_matrix_ids"])
            self.assertEqual(
                e01_uplift["reportability_decision"]["decision"],
                "do-not-report-e01-ex01-workflow-as-native-complete",
            )
            self.assertEqual(
                e01_uplift["reportability_decision"]["allowed_use"],
                "e01-ex01-extraction-triage-pivot",
            )
            self.assertIn(
                "#22-native-commercial-parser",
                e01_uplift["reportability_decision"]["failed_validation_matrix_ids"],
            )

    def test_e01_partition_browser_marks_recommendation_and_manual_override(self) -> None:
        browser = build_e01_partition_browser_contract(
            partition_selection={
                "selected_start_sector": 4096,
                "recommended_start_sector": 4096,
                "requested_start_sector": None,
            },
            partition_table=[
                {
                    "partition_number": 1,
                    "start_sector": 2048,
                    "size_bytes": 104857600,
                    "filesystem_guess": "fat",
                    "description": "EFI System",
                    "supported_filesystem_hint": False,
                },
                {
                    "partition_number": 2,
                    "start_sector": 4096,
                    "size_bytes": 53687091200,
                    "filesystem_guess": "ntfs",
                    "description": "NTFS / exFAT (0x07)",
                    "supported_filesystem_hint": True,
                },
            ],
            direct_extract_ready=True,
        )

        self.assertEqual(browser["profile_version"], "e01-partition-browser-v1")
        self.assertEqual(browser["status"], "ready")
        self.assertEqual(browser["partition_count"], 2)
        self.assertEqual(browser["supported_partition_count"], 1)
        recommended = browser["partitions"][1]
        self.assertEqual(recommended["start_sector"], 4096)
        self.assertEqual(recommended["recommendation"], "recommended")
        self.assertTrue(recommended["selected_for_recovery"])
        self.assertTrue(recommended["manual_override_allowed"])
        self.assertEqual(browser["manual_override"]["input_id"], "e01PartitionStartSectorInput")

    def test_e01_identify_exposes_failure_guidance_when_tools_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            image_path = Path(tmp_dir) / "case.E01"
            image_path.write_bytes(b"EVF")

            with patch("rapidtriage.core.evidence.missing_e01_tools", return_value=["ewfmount"]):
                result = identify_evidence(image_path).to_dict()

            self.assertEqual(result["supported"], False)
            self.assertEqual(result["failure_guidance"]["category"], "missing-tool")
            self.assertTrue(result["ingest_workflow"]["blocked"])
            self.assertEqual(result["ingest_workflow"]["failure_category"], "missing-tool")
            self.assertEqual(result["ingest_workflow"]["stages"][1]["status"], "blocked")
            self.assertIn("operator_runbook", result["ingest_workflow"])
            self.assertFalse(result["ingest_workflow"]["operator_runbook"]["direct_extract_ready"])
            self.assertIn("WSL2", " ".join(result["failure_guidance"]["next_actions"]))

    def test_identifies_raw_image_as_direct_extract_when_sleuthkit_exists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            image_path = Path(tmp_dir) / "disk.001"
            image_path.write_bytes(b"sample")

            with patch("rapidtriage.core.evidence.missing_raw_image_tools", return_value=[]):
                result = identify_evidence(image_path).to_dict()

            self.assertEqual(result["adapter"], "raw-image")
            self.assertEqual(result["supported"], True)
            self.assertEqual(result["can_extract"], True)
            self.assertEqual(result["support_level"], "direct-extract")
            self.assertEqual(result["scan_strategy"], "auto-extract-then-scan")
            self.assertIn("mmls", result["required_tools"])
            self.assertFalse(result["commercial_grade_ready"])
            self.assertIn("#23", result["commercial_gap_ids"])
            self.assertEqual(result["forensic_review"]["gap_id"], "#23")
            self.assertFalse(result["native_capabilities"]["native_partition_filesystem_parser"])
            self.assertEqual(result["source_integrity"]["split_part_count"], 1)
            raw_gate = result["core_accuracy_gates"][0]
            self.assertEqual(raw_gate["gap_id"], "#23")
            self.assertIn("split-set order and gap validation", raw_gate["satisfied_checks"])
            self.assertIn("split-set provenance profile", raw_gate["satisfied_checks"])
            self.assertIn("encrypted volume limitation warning", raw_gate["satisfied_checks"])
            self.assertEqual(result["split_set_profile"]["part_count"], 1)
            raw_review = result["image_analyst_review_profile"]
            self.assertEqual(raw_review["gap_id"], "#23")
            self.assertEqual(raw_review["artifact_type"], "raw-split-workflow")
            self.assertEqual(raw_review["source_field_values"]["detected_format"], "raw")
            self.assertIn("known-answer file hashes", raw_review["correlation_targets"])
            raw_uplift = result["commercial_uplift_evidence"]
            self.assertEqual(raw_uplift["item_numbers"], [23])
            self.assertIn("#23-source-integrity", raw_uplift["passed_validation_matrix_ids"])
            self.assertIn("#23-native-commercial-parser", raw_uplift["failed_validation_matrix_ids"])
            self.assertEqual(raw_uplift["large_data_controls"]["split_part_count"], 1)
            self.assertEqual(raw_uplift["large_data_controls"]["split_set_contiguous"], True)
            self.assertEqual(
                raw_uplift["reportability_decision"]["decision"],
                "do-not-report-raw-split-workflow-as-native-complete",
            )
            self.assertEqual(
                raw_uplift["reportability_decision"]["allowed_use"],
                "raw-split-extraction-triage-pivot",
            )

    def test_identifies_archive_image_as_direct_extract_when_tool_exists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            image_path = Path(tmp_dir) / "install.iso"
            image_path.write_bytes(b"sample")

            with patch("rapidtriage.core.evidence.missing_archive_image_tools", return_value=[]):
                result = identify_evidence(image_path).to_dict()

            self.assertEqual(result["adapter"], "iso")
            self.assertEqual(result["detected_format"], "iso")
            self.assertEqual(result["supported"], True)
            self.assertEqual(result["can_extract"], True)
            self.assertEqual(result["support_level"], "direct-extract")
            self.assertEqual(result["scan_strategy"], "auto-extract-then-scan")

    def test_identifies_virtual_disk_as_direct_extract_when_tools_exist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            image_path = Path(tmp_dir) / "vm.vmdk"
            image_path.write_bytes(b"sample")

            with patch("rapidtriage.core.evidence.missing_virtual_disk_tools", return_value=[]):
                result = identify_evidence(image_path).to_dict()

            self.assertEqual(result["adapter"], "virtual-disk")
            self.assertEqual(result["detected_format"], "vmdk")
            self.assertEqual(result["supported"], True)
            self.assertEqual(result["can_extract"], True)
            self.assertEqual(result["support_level"], "direct-extract")
            self.assertEqual(result["scan_strategy"], "auto-convert-extract-then-scan")
            self.assertFalse(result["commercial_grade_ready"])
            self.assertIn("#24", result["commercial_gap_ids"])
            self.assertEqual(result["forensic_review"]["gap_id"], "#24")
            self.assertFalse(result["native_capabilities"]["snapshot_chain_validation"])
            self.assertEqual(result["source_integrity"]["hash_status"], "computed")
            vm_gate = result["core_accuracy_gates"][0]
            self.assertEqual(vm_gate["gap_id"], "#24")
            self.assertIn("qemu-img version/command capture", vm_gate["satisfied_checks"])
            self.assertIn("snapshot/differencing-chain detection", vm_gate["satisfied_checks"])
            self.assertIn("virtual disk chain risk profile", vm_gate["satisfied_checks"])
            self.assertIn("unsupported/encrypted VM warning", vm_gate["satisfied_checks"])
            self.assertEqual(result["virtual_disk_chain_profile"]["detected_format"], "vmdk")
            vm_review = result["image_analyst_review_profile"]
            self.assertEqual(vm_review["gap_id"], "#24")
            self.assertEqual(vm_review["artifact_type"], "virtual-disk-workflow")
            self.assertEqual(vm_review["source_field_values"]["detected_format"], "vmdk")
            self.assertIn("qemu-img info", vm_review["correlation_targets"])
            vm_uplift = result["commercial_uplift_evidence"]
            self.assertEqual(vm_uplift["item_numbers"], [24])
            self.assertIn("#24-source-integrity", vm_uplift["passed_validation_matrix_ids"])
            self.assertIn("#24-native-commercial-parser", vm_uplift["failed_validation_matrix_ids"])
            self.assertEqual(
                vm_uplift["reportability_decision"]["decision"],
                "do-not-report-virtual-disk-workflow-as-chain-complete",
            )
            self.assertEqual(
                vm_uplift["reportability_decision"]["allowed_use"],
                "virtual-disk-extraction-triage-pivot",
            )

    def test_identifies_xva_as_export_first_virtual_disk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            image_path = Path(tmp_dir) / "xen-server.xva"
            image_path.write_bytes(b"sample")

            result = identify_evidence(image_path).to_dict()

            self.assertEqual(result["adapter"], "virtual-disk")
            self.assertEqual(result["detected_format"], "xva")
            self.assertEqual(result["supported"], True)
            self.assertEqual(result["can_extract"], False)
            self.assertEqual(result["support_level"], "detected-only")
            self.assertEqual(result["scan_strategy"], "xva-export-or-convert-first")
            self.assertIn("XVA", result["message"])
            self.assertFalse(result["commercial_grade_ready"])
            self.assertIn("#24", result["commercial_gap_ids"])
            self.assertEqual(result["forensic_review"]["gap_id"], "#24")
            self.assertFalse(result["native_capabilities"]["xva_direct_extraction"])
            self.assertEqual(result["source_integrity"]["hash_status"], "computed")
            xva_gate = result["core_accuracy_gates"][0]
            self.assertEqual(xva_gate["gap_id"], "#24")
            self.assertIn("snapshot/differencing-chain detection", xva_gate["satisfied_checks"])
            self.assertIn("unsupported/encrypted VM warning", xva_gate["satisfied_checks"])
            self.assertEqual(result["virtual_disk_chain_profile"]["detected_format"], "xva")
            self.assertTrue(result["fallback_guidance"])
            xva_review = result["image_analyst_review_profile"]
            self.assertEqual(xva_review["source_field_values"]["detected_format"], "xva")
            self.assertIn("XVA direct parsing", xva_review["not_proof_of"])
            xva_uplift = result["commercial_uplift_evidence"]
            self.assertEqual(xva_uplift["item_numbers"], [24])
            self.assertIn("#24-partition-or-container-metadata", xva_uplift["passed_validation_matrix_ids"])
            self.assertIn("xva-direct-extraction-not-implemented", xva_uplift["commercial_blockers"])
            self.assertEqual(
                xva_uplift["reportability_decision"]["allowed_use"],
                "virtual-disk-extraction-triage-pivot",
            )
            self.assertIn(
                "xva-direct-extraction-not-implemented",
                xva_uplift["reportability_decision"]["blockers"],
            )

    def test_identifies_common_image_formats_as_planned_adapters(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            expected = {
                "case.ad1": ("forensic-container", "ad1"),
                "case.l01": ("forensic-container", "l01"),
                "case.lx01": ("forensic-container", "lx01"),
                "case.aff": ("forensic-container", "aff"),
                "case.aff4": ("forensic-container", "aff4"),
                "case.aff4-l": ("forensic-container", "aff4-l"),
            }
            for file_name, (adapter, detected_format) in expected.items():
                image_path = Path(tmp_dir) / file_name
                image_path.write_bytes(b"sample")

                result = identify_evidence(image_path).to_dict()

                self.assertEqual(result["adapter"], adapter)
                self.assertEqual(result["detected_format"], detected_format)
                self.assertEqual(result["supported"], True)
                self.assertEqual(result["can_extract"], False)
                self.assertEqual(result["support_level"], "detected-only")
                self.assertTrue(result["next_actions"])
                self.assertTrue(result["warnings"])
                self.assertFalse(result["commercial_grade_ready"])
                self.assertIn("#25", result["commercial_gap_ids"])
                self.assertEqual(result["forensic_review"]["gap_id"], "#25")
                self.assertFalse(result["native_capabilities"]["direct_ad1_l01_lx01_aff_aff4_parser"])
                self.assertEqual(result["source_integrity"]["hash_status"], "computed")
                container_gate = result["core_accuracy_gates"][0]
                self.assertEqual(container_gate["gap_id"], "#25")
                self.assertIn("container type detection", container_gate["satisfied_checks"])
                self.assertIn("source integrity capture", container_gate["satisfied_checks"])
                self.assertIn("native-vs-export workflow disclosure", container_gate["satisfied_checks"])
                self.assertIn("metadata/deleted-entry validation", container_gate["satisfied_checks"])
                self.assertIn("encrypted/compressed limitation warning", container_gate["satisfied_checks"])
                self.assertEqual(result["container_export_profile"]["workflow"], "vendor-export-first")
                self.assertTrue(result["limitations"])
                container_review = result["image_analyst_review_profile"]
                self.assertEqual(container_review["gap_id"], "#25")
                self.assertEqual(container_review["artifact_type"], "forensic-container-workflow")
                self.assertEqual(container_review["source_field_values"]["detected_format"], detected_format)
                self.assertIn("vendor export manifest", container_review["correlation_targets"])
                self.assertIn("vendor-export-required", container_review["risk_tags"])
                container_uplift = result["commercial_uplift_evidence"]
                self.assertEqual(container_uplift["item_numbers"], [25])
                self.assertTrue(container_uplift["implemented"])
                self.assertTrue(container_uplift["usable"])
                self.assertTrue(container_uplift["validated"])
                self.assertFalse(container_uplift["commercial_grade_ready"])
                self.assertIn("#25-source-integrity", container_uplift["passed_validation_matrix_ids"])
                self.assertIn("#25-native-commercial-parser", container_uplift["failed_validation_matrix_ids"])
                self.assertEqual(
                    container_uplift["reportability_decision"]["decision"],
                    "do-not-report-proprietary-container-as-natively-parsed",
                )
                self.assertEqual(
                    container_uplift["reportability_decision"]["allowed_use"],
                    "vendor-export-container-triage-pivot",
                )
                self.assertFalse(result["verified_export_manifest_profile"]["manifest_present"])
                self.assertEqual(result["verified_export_manifest_profile"]["validation_status"], "missing")
                workflow_manifest = result["forensic_container_workflow_manifest"]
                self.assertEqual(
                    workflow_manifest["profile_version"],
                    "forensic-container-export-workflow-manifest-v1",
                )
                self.assertEqual(workflow_manifest["item_number"], 25)
                self.assertEqual(workflow_manifest["gap_id"], "#25")
                self.assertEqual(len(workflow_manifest["manifest_sha256"]), 64)
                workflow_statuses = {stage["id"]: stage["status"] for stage in workflow_manifest["stages"]}
                self.assertEqual(workflow_statuses["detect-container"], "complete")
                self.assertEqual(workflow_statuses["export-first-guidance"], "complete")
                self.assertEqual(workflow_statuses["verified-export-manifest"], "blocked")
                self.assertEqual(workflow_statuses["scan-derived-export"], "blocked")
                self.assertFalse(workflow_manifest["commercial_grade_ready"])

    def test_forensic_container_reads_verified_export_manifest_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            image_path = Path(tmp_dir) / "case.ad1"
            image_path.write_bytes(b"sample")
            source_hash = hashlib.sha256(b"sample").hexdigest()
            manifest_path = image_path.with_suffix(image_path.suffix + ".export-manifest.json")
            manifest_path.write_text(
                json.dumps(
                    {
                        "vendor_tool": "FTK Imager",
                        "vendor_tool_version": "4.7",
                        "source_sha256": source_hash,
                        "export_root": "case-export",
                        "export_root_sha256": "a" * 64,
                        "files": [{"path": "Users/Alice/evidence.txt", "sha256": "b" * 64, "size": 12}],
                    }
                ),
                encoding="utf-8",
            )

            result = identify_evidence(image_path).to_dict()

            profile = result["verified_export_manifest_profile"]
            self.assertTrue(profile["manifest_present"])
            self.assertEqual(profile["parse_status"], "json-parsed")
            self.assertEqual(profile["validation_status"], "manifest-linked")
            self.assertEqual(profile["vendor_tool"], "FTK Imager")
            self.assertTrue(profile["source_hash_matches_manifest"])
            self.assertEqual(profile["file_count"], 1)
            self.assertEqual(profile["hashed_file_count"], 1)
            self.assertEqual(profile["sample_files"][0]["path"], "Users/Alice/evidence.txt")
            workflow_manifest = result["forensic_container_workflow_manifest"]
            workflow_statuses = {stage["id"]: stage["status"] for stage in workflow_manifest["stages"]}
            self.assertEqual(workflow_statuses["verified-export-manifest"], "complete")
            self.assertEqual(workflow_statuses["scan-derived-export"], "ready-after-export")
            self.assertEqual(
                workflow_manifest["large_data_controls"]["export_manifest_file_count"],
                1,
            )
            self.assertEqual(
                workflow_manifest["verified_export_manifest_profile"]["manifest_sha256"],
                profile["manifest_sha256"],
            )
            self.assertEqual(
                result["commercial_uplift_evidence"]["large_data_controls"]["export_manifest_sha256"],
                profile["manifest_sha256"],
            )

    def test_unknown_format_is_not_supported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            image_path = Path(tmp_dir) / "evidence.unknown"
            image_path.write_text("sample", encoding="utf-8")

            result = identify_evidence(image_path).to_dict()

            self.assertEqual(result["adapter"], "unsupported")
            self.assertEqual(result["supported"], False)
            self.assertEqual(result["support_level"], "unsupported")
            self.assertEqual(result["scan_strategy"], "manual-export-first")

    def test_warns_when_source_name_looks_like_host_folder(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            source = Path(tmp_dir) / "Users"
            source.mkdir()

            result = identify_evidence(source).to_dict()

            self.assertEqual(result["adapter"], "folder")
            self.assertTrue(
                any("common host folder" in warning for warning in result["warnings"]),
                result["warnings"],
            )

    def test_cli_evidence_outputs_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(["evidence", tmp_dir, "--json"])

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["adapter"], "folder")
            self.assertEqual(payload["support_level"], "direct-folder")
            self.assertIn("next_actions", payload)


if __name__ == "__main__":
    unittest.main()
