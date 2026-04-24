from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rapidtriage.core.e01 import E01ExtractionError, E01ExtractionResult, extract_e01_to_directory, mmls_first_filesystem
from rapidtriage.core.run import run_triage_mode
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
            self.assertEqual(commands[0][0], "ewfmount")
            self.assertEqual(commands[1][0], "mmls")
            self.assertEqual(commands[2][0], "tsk_recover")

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


if __name__ == "__main__":
    unittest.main()
