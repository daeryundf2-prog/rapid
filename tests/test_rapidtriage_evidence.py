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

    def test_identifies_common_image_formats_as_planned_adapters(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            expected = {
                "case.ad1": ("forensic-container", "ad1"),
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

    def test_unknown_format_is_not_supported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            image_path = Path(tmp_dir) / "evidence.unknown"
            image_path.write_text("sample", encoding="utf-8")

            result = identify_evidence(image_path).to_dict()

            self.assertEqual(result["adapter"], "unsupported")
            self.assertEqual(result["supported"], False)
            self.assertEqual(result["support_level"], "unsupported")
            self.assertEqual(result["scan_strategy"], "manual-export-first")

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
