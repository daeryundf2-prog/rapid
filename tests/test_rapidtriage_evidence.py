from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rapidtriage.cli import main
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
            self.assertIn("#22", result["commercial_gap_ids"])
            self.assertEqual(result["forensic_review"]["gap_id"], "#22")
            self.assertFalse(result["forensic_review"]["report_grade_ready"])
            self.assertFalse(result["native_capabilities"]["native_e01_ex01_parser"])
            e01_gate = result["core_accuracy_gates"][0]
            self.assertEqual(e01_gate["gap_id"], "#22")
            self.assertIn("source hash and segment integrity", e01_gate["satisfied_checks"])
            self.assertIn("tool version/command capture", e01_gate["satisfied_checks"])
            self.assertIn("corrupt/encrypted limitation reporting", e01_gate["satisfied_checks"])
            self.assertTrue(result["limitations"])
            self.assertTrue(result["fallback_guidance"])
            e01_uplift = result["commercial_uplift_evidence"]
            self.assertEqual(e01_uplift["batch_id"], "commercial-uplift-021-025")
            self.assertEqual(e01_uplift["item_numbers"], [22])
            self.assertIn("#22-source-integrity", e01_uplift["passed_validation_matrix_ids"])
            self.assertIn("#22-native-commercial-parser", e01_uplift["failed_validation_matrix_ids"])

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
            self.assertIn("encrypted volume limitation warning", raw_gate["satisfied_checks"])
            raw_uplift = result["commercial_uplift_evidence"]
            self.assertEqual(raw_uplift["item_numbers"], [23])
            self.assertIn("#23-source-integrity", raw_uplift["passed_validation_matrix_ids"])
            self.assertIn("#23-native-commercial-parser", raw_uplift["failed_validation_matrix_ids"])
            self.assertEqual(raw_uplift["large_data_controls"]["split_part_count"], 1)

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
            self.assertIn("unsupported/encrypted VM warning", vm_gate["satisfied_checks"])
            vm_uplift = result["commercial_uplift_evidence"]
            self.assertEqual(vm_uplift["item_numbers"], [24])
            self.assertIn("#24-source-integrity", vm_uplift["passed_validation_matrix_ids"])
            self.assertIn("#24-native-commercial-parser", vm_uplift["failed_validation_matrix_ids"])

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
            self.assertTrue(result["fallback_guidance"])
            xva_uplift = result["commercial_uplift_evidence"]
            self.assertEqual(xva_uplift["item_numbers"], [24])
            self.assertIn("#24-partition-or-container-metadata", xva_uplift["passed_validation_matrix_ids"])
            self.assertIn("xva-direct-extraction-not-implemented", xva_uplift["commercial_blockers"])

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
                self.assertTrue(result["limitations"])
                container_uplift = result["commercial_uplift_evidence"]
                self.assertEqual(container_uplift["item_numbers"], [25])
                self.assertIn("#25-source-integrity", container_uplift["passed_validation_matrix_ids"])
                self.assertIn("#25-native-commercial-parser", container_uplift["failed_validation_matrix_ids"])

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
