from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rapidtriage.core.archive_image import ArchiveImageExtractionResult, extract_archive_image_to_directory
from rapidtriage.core.disk_image import (
    DiskImageExtractionResult,
    discover_split_image_parts,
    extract_raw_image_to_directory,
)
from rapidtriage.core.e01 import E01ExtractionError, E01ExtractionResult, extract_e01_to_directory, mmls_first_filesystem
from rapidtriage.core.run import run_triage_mode
from rapidtriage.core.virtual_disk import VirtualDiskExtractionResult, extract_virtual_disk_to_directory
from tests.test_rapidtriage_run import build_run_fixture


class RapidTriageE01Tests(unittest.TestCase):
    def test_mmls_partition_selection_prefers_largest_supported_filesystem(self) -> None:
        text = """
DOS Partition Table
000: 0000000000 0000002047 Unallocated
001: 0000002048 0000010000 NTFS / exFAT (0x07)
002: 0000012048 0000001000 Linux (0x83)
003: 0000013048 0000090000 Basic data partition
"""

        self.assertEqual(mmls_first_filesystem(text), 13048)

    def test_mmls_partition_selection_accepts_linux_xfs_and_ext(self) -> None:
        text = """
DOS Partition Table
000: 0000000000 0000002047 Unallocated
001: 0000002048 0000010000 Linux filesystem
002: 0000012048 0000090000 XFS
003: 0000102048 0000001000 Linux swap
"""

        self.assertEqual(mmls_first_filesystem(text), 12048)

    def test_extract_e01_reports_missing_external_tools(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            e01_path = Path(tmp_dir) / "case.E01"
            e01_path.write_bytes(b"EVF")

            with self.assertRaises(E01ExtractionError) as context:
                extract_e01_to_directory(e01_path, Path(tmp_dir) / "stage", tool_resolver=lambda _: None)

            self.assertIn("requires external tools", str(context.exception))

    def test_extract_e01_runs_mount_partition_and_recover_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            e01_path = root / "case.E01"
            stage_dir = root / "stage"
            e01_path.write_bytes(b"EVF")
            commands: list[list[str]] = []

            def fake_runner(command):
                commands.append(list(command))
                if command[1:] == ["--version"]:
                    return subprocess.CompletedProcess(command, 0, f"{command[0]} 1.0\n", "")
                if command[0] == "ewfmount":
                    (Path(command[2]) / "ewf1").write_bytes(b"raw")
                    return subprocess.CompletedProcess(command, 0, "", "")
                if command[0] == "mmls":
                    return subprocess.CompletedProcess(command, 0, "001: 0000002048 0000020000 NTFS\n", "")
                if command[0] == "tsk_recover":
                    Path(command[-1]).mkdir(parents=True, exist_ok=True)
                    (Path(command[-1]) / "evidence.txt").write_text("fraud invoice", encoding="utf-8")
                    return subprocess.CompletedProcess(command, 0, "", "")
                return subprocess.CompletedProcess(command, 0, "", "")

            result = extract_e01_to_directory(
                e01_path,
                stage_dir,
                runner=fake_runner,
                tool_resolver=lambda name: f"/usr/bin/{name}",
            )

            self.assertEqual(result.partition_start_sector, 2048)
            self.assertTrue((result.extract_dir / "evidence.txt").is_file())
            workflow_commands = [command for command in commands if command[1:] != ["--version"]]
            self.assertEqual(workflow_commands[0][0], "ewfmount")
            self.assertEqual(workflow_commands[1][0], "mmls")
            self.assertEqual(workflow_commands[2][0], "tsk_recover")
            metadata = result.to_dict()
            self.assertFalse(metadata["commercial_grade_ready"])
            self.assertIn("#22", metadata["commercial_gap_ids"])
            self.assertFalse(metadata["native_capabilities"]["native_e01_segment_metadata_decode"])
            self.assertEqual(metadata["source_integrity"]["hash_status"], "computed")
            self.assertTrue(metadata["tool_preflight"])
            self.assertTrue(metadata["partition_table"][0]["selected_for_recovery"])
            self.assertEqual(metadata["command_history"][-1]["purpose"], "read-only-filesystem-recovery")
            e01_gate = metadata["core_accuracy_gates"][0]
            self.assertEqual(e01_gate["gap_id"], "#22")
            self.assertIn("partition offset correctness", e01_gate["satisfied_checks"])
            self.assertIn("read-only extraction provenance", e01_gate["satisfied_checks"])

    def test_raw_split_image_discovery_sorts_numeric_segments(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            for name in ("case.003", "case.001", "case.002", "other.001"):
                (root / name).write_bytes(b"part")

            parts = discover_split_image_parts(root / "case.001")

            self.assertEqual([part.name for part in parts], ["case.001", "case.002", "case.003"])

    def test_raw_split_image_metadata_warns_about_missing_segments(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            image_path = root / "case.001"
            image_path.write_bytes(b"part1")
            (root / "case.003").write_bytes(b"part3")

            def fake_runner(command):
                if command[1:] == ["--version"]:
                    return subprocess.CompletedProcess(command, 0, f"{command[0]} 1.0\n", "")
                if command[0] == "mmls":
                    return subprocess.CompletedProcess(command, 0, "001: 0000002048 0000020000 NTFS\n", "")
                if command[0] == "tsk_recover":
                    Path(command[-1]).mkdir(parents=True, exist_ok=True)
                    return subprocess.CompletedProcess(command, 0, "", "")
                return subprocess.CompletedProcess(command, 0, "", "")

            result = extract_raw_image_to_directory(
                image_path,
                root / "stage",
                runner=fake_runner,
                tool_resolver=lambda name: f"/usr/bin/{name}",
            )

            metadata = result.to_dict()
            self.assertEqual([Path(path).name for path in metadata["image_paths"]], ["case.001", "case.003"])
            self.assertTrue(metadata["split_part_warnings"])
            self.assertIn("missing segment", metadata["split_part_warnings"][0])

    def test_extract_raw_image_runs_mmls_and_tsk_recover(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            image_path = root / "case.001"
            (root / "case.001").write_bytes(b"part1")
            (root / "case.002").write_bytes(b"part2")
            stage_dir = root / "stage"
            commands: list[list[str]] = []

            def fake_runner(command):
                commands.append(list(command))
                if command[1:] == ["--version"]:
                    return subprocess.CompletedProcess(command, 0, f"{command[0]} 1.0\n", "")
                if command[0] == "mmls":
                    return subprocess.CompletedProcess(command, 0, "001: 0000002048 0000020000 NTFS\n", "")
                if command[0] == "tsk_recover":
                    Path(command[-1]).mkdir(parents=True, exist_ok=True)
                    (Path(command[-1]) / "evidence.txt").write_text("raw image invoice", encoding="utf-8")
                    return subprocess.CompletedProcess(command, 0, "", "")
                return subprocess.CompletedProcess(command, 0, "", "")

            result = extract_raw_image_to_directory(
                image_path,
                stage_dir,
                runner=fake_runner,
                tool_resolver=lambda name: f"/usr/bin/{name}",
            )

            self.assertEqual(result.partition_start_sector, 2048)
            self.assertEqual(result.recovery_mode, "partition-offset")
            self.assertEqual([path.name for path in result.image_paths], ["case.001", "case.002"])
            self.assertTrue((result.extract_dir / "evidence.txt").is_file())
            workflow_commands = [command for command in commands if command[1:] != ["--version"]]
            self.assertEqual(workflow_commands[0][0], "mmls")
            self.assertEqual(workflow_commands[1][0], "tsk_recover")
            self.assertIn("-o", workflow_commands[1])
            metadata = result.to_dict()
            self.assertFalse(metadata["commercial_grade_ready"])
            self.assertIn("#23", metadata["commercial_gap_ids"])
            self.assertFalse(metadata["native_capabilities"]["native_partition_filesystem_parser"])
            self.assertEqual(metadata["source_integrity"][0]["hash_status"], "computed")
            self.assertEqual(metadata["partition_table"][0]["selected_for_recovery"], True)
            raw_gate = metadata["core_accuracy_gates"][0]
            self.assertEqual(raw_gate["gap_id"], "#23")
            self.assertIn("partition table parsing", raw_gate["satisfied_checks"])
            self.assertIn("filesystem extraction audit", raw_gate["satisfied_checks"])
            self.assertIn("deleted-file recovery expectations", raw_gate["satisfied_checks"])

    def test_extract_raw_image_falls_back_to_whole_image_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            image_path = root / "filesystem.raw"
            image_path.write_bytes(b"single filesystem")
            commands: list[list[str]] = []

            def fake_runner(command):
                commands.append(list(command))
                if command[1:] == ["--version"]:
                    return subprocess.CompletedProcess(command, 0, f"{command[0]} 1.0\n", "")
                if command[0] == "mmls":
                    return subprocess.CompletedProcess(command, 1, "", "No partition table")
                if command[0] == "tsk_recover":
                    Path(command[-1]).mkdir(parents=True, exist_ok=True)
                    (Path(command[-1]) / "evidence.txt").write_text("whole image", encoding="utf-8")
                    return subprocess.CompletedProcess(command, 0, "", "")
                return subprocess.CompletedProcess(command, 0, "", "")

            result = extract_raw_image_to_directory(
                image_path,
                root / "stage",
                runner=fake_runner,
                tool_resolver=lambda name: f"/usr/bin/{name}",
            )

            self.assertIsNone(result.partition_start_sector)
            self.assertEqual(result.recovery_mode, "whole-image")
            workflow_commands = [command for command in commands if command[1:] != ["--version"]]
            self.assertNotIn("-o", workflow_commands[1])

    def test_extract_archive_image_uses_available_7zip_tool(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            image_path = root / "install.iso"
            image_path.write_bytes(b"iso")
            commands: list[list[str]] = []

            def fake_runner(command):
                commands.append(list(command))
                if command[1:] == ["--version"]:
                    return subprocess.CompletedProcess(command, 0, f"{command[0]} 1.0\n", "")
                Path(command[3][2:] if command[3].startswith("-o") else command[-1]).mkdir(parents=True, exist_ok=True)
                if command[0] in {"7z", "7zz"}:
                    out_dir = Path(command[3][2:])
                    (out_dir / "setup.log").write_text("archive image extracted", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "", "")

            result = extract_archive_image_to_directory(
                image_path,
                root / "stage",
                runner=fake_runner,
                tool_resolver=lambda name: f"/usr/bin/{name}" if name == "7z" else None,
            )

            self.assertEqual(result.tool, "7z")
            workflow_commands = [command for command in commands if command[1:] != ["--version"]]
            self.assertEqual(workflow_commands[0][:3], ["7z", "x", "-y"])
            self.assertTrue((result.extract_dir / "setup.log").is_file())
            self.assertFalse(result.to_dict()["commercial_grade_ready"])

    def test_extract_virtual_disk_converts_to_raw_then_recovers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            image_path = root / "vm.vmdk"
            image_path.write_bytes(b"vmdk")
            commands: list[list[str]] = []

            def fake_runner(command):
                commands.append(list(command))
                if command[1:] == ["--version"]:
                    return subprocess.CompletedProcess(command, 0, f"{command[0]} 1.0\n", "")
                if command[:3] == ["qemu-img", "convert", "-O"]:
                    Path(command[-1]).write_bytes(b"converted raw")
                    return subprocess.CompletedProcess(command, 0, "", "")
                if command[0] == "mmls":
                    return subprocess.CompletedProcess(command, 0, "001: 0000002048 0000020000 NTFS\n", "")
                if command[0] == "tsk_recover":
                    Path(command[-1]).mkdir(parents=True, exist_ok=True)
                    (Path(command[-1]) / "vm-evidence.txt").write_text("virtual disk evidence", encoding="utf-8")
                    return subprocess.CompletedProcess(command, 0, "", "")
                return subprocess.CompletedProcess(command, 0, "", "")

            result = extract_virtual_disk_to_directory(
                image_path,
                root / "stage",
                runner=fake_runner,
                tool_resolver=lambda name: f"/usr/bin/{name}",
            )

            self.assertEqual(result.conversion_tool, "qemu-img")
            workflow_commands = [command for command in commands if command[1:] != ["--version"]]
            self.assertEqual(workflow_commands[0][:4], ["qemu-img", "convert", "-O", "raw"])
            self.assertTrue(result.converted_raw_path.is_file())
            self.assertTrue((result.extract_dir / "vm-evidence.txt").is_file())
            self.assertEqual(result.raw_result.partition_start_sector, 2048)
            metadata = result.to_dict()
            self.assertFalse(metadata["commercial_grade_ready"])
            self.assertIn("#24", metadata["commercial_gap_ids"])
            self.assertFalse(metadata["native_capabilities"]["snapshot_chain_validation"])
            self.assertEqual(metadata["source_integrity"]["hash_status"], "computed")
            self.assertEqual(metadata["converted_raw_integrity"]["hash_status"], "computed")
            vm_gate = metadata["core_accuracy_gates"][0]
            self.assertEqual(vm_gate["gap_id"], "#24")
            self.assertIn("converted raw hash/provenance", vm_gate["satisfied_checks"])
            self.assertIn("nested partition extraction", vm_gate["satisfied_checks"])

    def test_run_triage_accepts_e01_image_and_analyzes_extracted_filesystem(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            e01_path = root / "case.E01"
            output_dir = root / "run-out"
            e01_path.write_bytes(b"EVF")

            def fake_extract(source_path: Path, stage_dir: Path) -> E01ExtractionResult:
                extract_dir = stage_dir / "filesystem"
                extract_dir.mkdir(parents=True, exist_ok=True)
                build_run_fixture(extract_dir)
                return E01ExtractionResult(
                    source_path=source_path,
                    stage_dir=stage_dir,
                    mount_dir=stage_dir / "_ewfmount",
                    raw_image_path=stage_dir / "_ewfmount" / "ewf1",
                    extract_dir=extract_dir,
                    partition_start_sector=2048,
                )

            with patch("rapidtriage.core.run.extract_e01_to_directory", side_effect=fake_extract):
                payload = run_triage_mode(e01_path, mode="fraud", output_dir=output_dir)

            self.assertEqual(payload["source"]["type"], "e01")
            self.assertEqual(Path(payload["source"]["source_path"]), e01_path.resolve())
            self.assertEqual(Path(payload["root"]), (output_dir / "_e01" / "filesystem").resolve())
            self.assertIn("e01", payload["outputs"])
            self.assertTrue((output_dir / "rapidtriage-e01.json").is_file())
            metadata = json.loads((output_dir / "rapidtriage-e01.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["partition_start_sector"], 2048)
            self.assertGreaterEqual(payload["summary"]["document_match_count"], 1)

    def test_run_triage_accepts_raw_image_and_analyzes_extracted_filesystem(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            image_path = root / "case.001"
            output_dir = root / "run-out"
            image_path.write_bytes(b"raw")

            def fake_extract(source_path: Path, stage_dir: Path) -> DiskImageExtractionResult:
                extract_dir = stage_dir / "filesystem"
                extract_dir.mkdir(parents=True, exist_ok=True)
                build_run_fixture(extract_dir)
                return DiskImageExtractionResult(
                    source_path=source_path,
                    stage_dir=stage_dir,
                    extract_dir=extract_dir,
                    image_paths=(source_path,),
                    partition_start_sector=2048,
                    recovery_mode="partition-offset",
                )

            with patch("rapidtriage.core.run.extract_raw_image_to_directory", side_effect=fake_extract):
                payload = run_triage_mode(image_path, mode="fraud", output_dir=output_dir)

            self.assertEqual(payload["source"]["type"], "raw-image")
            self.assertEqual(Path(payload["source"]["source_path"]), image_path.resolve())
            self.assertEqual(Path(payload["root"]), (output_dir / "_disk_image" / "filesystem").resolve())
            self.assertIn("disk_image", payload["outputs"])
            self.assertTrue((output_dir / "rapidtriage-disk-image.json").is_file())
            metadata = json.loads((output_dir / "rapidtriage-disk-image.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["partition_start_sector"], 2048)
            self.assertEqual(metadata["recovery_mode"], "partition-offset")
            self.assertGreaterEqual(payload["summary"]["document_match_count"], 1)

    def test_run_triage_accepts_archive_image_and_analyzes_extracted_filesystem(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            image_path = root / "install.iso"
            output_dir = root / "run-out"
            image_path.write_bytes(b"iso")

            def fake_extract(source_path: Path, stage_dir: Path) -> ArchiveImageExtractionResult:
                extract_dir = stage_dir / "filesystem"
                extract_dir.mkdir(parents=True, exist_ok=True)
                build_run_fixture(extract_dir)
                return ArchiveImageExtractionResult(
                    source_path=source_path,
                    stage_dir=stage_dir,
                    extract_dir=extract_dir,
                    tool="7z",
                    command=("7z", "x", "-y", f"-o{extract_dir}", str(source_path)),
                )

            with patch("rapidtriage.core.run.extract_archive_image_to_directory", side_effect=fake_extract):
                payload = run_triage_mode(image_path, mode="fraud", output_dir=output_dir)

            self.assertEqual(payload["source"]["type"], "archive-image")
            self.assertEqual(Path(payload["source"]["source_path"]), image_path.resolve())
            self.assertEqual(Path(payload["root"]), (output_dir / "_archive_image" / "filesystem").resolve())
            self.assertIn("archive_image", payload["outputs"])
            self.assertTrue((output_dir / "rapidtriage-archive-image.json").is_file())
            metadata = json.loads((output_dir / "rapidtriage-archive-image.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["tool"], "7z")
            self.assertGreaterEqual(payload["summary"]["document_match_count"], 1)

    def test_run_triage_accepts_virtual_disk_and_analyzes_extracted_filesystem(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            image_path = root / "vm.vmdk"
            output_dir = root / "run-out"
            image_path.write_bytes(b"vmdk")

            def fake_extract(source_path: Path, stage_dir: Path) -> VirtualDiskExtractionResult:
                raw_stage = stage_dir / "raw-extract"
                extract_dir = raw_stage / "filesystem"
                extract_dir.mkdir(parents=True, exist_ok=True)
                build_run_fixture(extract_dir)
                raw_result = DiskImageExtractionResult(
                    source_path=stage_dir / "converted" / "vm.raw",
                    stage_dir=raw_stage,
                    extract_dir=extract_dir,
                    image_paths=(stage_dir / "converted" / "vm.raw",),
                    partition_start_sector=2048,
                    recovery_mode="partition-offset",
                )
                return VirtualDiskExtractionResult(
                    source_path=source_path,
                    stage_dir=stage_dir,
                    converted_raw_path=stage_dir / "converted" / "vm.raw",
                    raw_result=raw_result,
                    conversion_tool="qemu-img",
                )

            with patch("rapidtriage.core.run.extract_virtual_disk_to_directory", side_effect=fake_extract):
                payload = run_triage_mode(image_path, mode="fraud", output_dir=output_dir)

            self.assertEqual(payload["source"]["type"], "virtual-disk")
            self.assertEqual(Path(payload["source"]["source_path"]), image_path.resolve())
            self.assertIn("virtual_disk", payload["outputs"])
            self.assertTrue((output_dir / "rapidtriage-virtual-disk.json").is_file())
            metadata = json.loads((output_dir / "rapidtriage-virtual-disk.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["conversion_tool"], "qemu-img")
            self.assertGreaterEqual(payload["summary"]["document_match_count"], 1)


if __name__ == "__main__":
    unittest.main()
