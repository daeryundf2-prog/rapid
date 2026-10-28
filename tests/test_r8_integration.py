"""R8 integration: run_mode reaches E01 extraction, the resume fingerprint, unallocated carving
wiring, and single-line manifest JSON. Synthetic inputs and fakes only; no real evidence image."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rapidtriage.core import coverage
from rapidtriage.core import run as run_module
from rapidtriage.core.carving import CarvingError
from rapidtriage.core.e01 import (
    E01_STAGE_CHECKPOINT_VERSION,
    E01ExtractionResult,
    build_recovered_root_manifest,
    build_tsk_recover_recovery_scope,
    e01_checkpoint_resume_ready,
    extract_e01_to_directory,
    recovered_inventory_fingerprint,
)
from rapidtriage.core.input_root import InputRoot
from rapidtriage.core.run import (
    prepare_run_input_root,
    run_triage_mode,
    run_unallocated_carving_stage,
)


class _StopRun(Exception):
    """Raised by a fake extractor once the call arguments are captured."""


def _fake_e01_result(tmp: Path, *, partitions: list[dict[str, object]] | None = None) -> E01ExtractionResult:
    source = tmp / "case.E01"
    source.write_bytes(b"EVF")
    extract_dir = tmp / "stage" / "extract"
    extract_dir.mkdir(parents=True, exist_ok=True)
    (extract_dir / "note.txt").write_text("hello evidence", encoding="utf-8")
    manifest: dict[str, object] = {}
    if partitions is not None:
        manifest["native_extracted_partitions"] = partitions
    return E01ExtractionResult(
        source_path=source,
        stage_dir=tmp / "stage",
        mount_dir=tmp / "stage" / "_ewfmount",
        raw_image_path=source,
        extract_dir=extract_dir,
        partition_start_sector=2048,
        recovered_root_manifest=manifest,
    )


def _fake_carving(calls: list[dict[str, object]], *, fail_sector: int | None = None):
    def fake(image, output_dir, **kwargs):
        calls.append({"image": Path(image), "output_dir": Path(output_dir), **kwargs})
        if kwargs.get("partition_start_sector") == fail_sector:
            raise CarvingError("no NTFS $Bitmap")
        return {"summary": {"candidate_count": 3, "extracted_count": 2, "candidate_cap_reached": False}}

    return fake


class RunModeReachesE01ExtractionTests(unittest.TestCase):
    def _captured_kwargs(self, mode: str) -> dict[str, object]:
        captured: dict[str, object] = {}

        def fake_extract(path, stage_dir, **kwargs):
            captured.update(kwargs)
            raise _StopRun

        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "case.E01"
            image.write_bytes(b"EVF")
            with patch.object(run_module, "extract_e01_to_directory", side_effect=fake_extract), self.assertRaises(_StopRun):
                run_triage_mode(image, mode=mode, output_dir=Path(tmp) / "out", read_only=True, overwrite=True)
        return captured

    def test_recovery_run_passes_recovery_mode(self):
        self.assertEqual(self._captured_kwargs("recovery").get("run_mode"), "recovery")

    def test_bounded_run_keeps_the_default(self):
        for mode in ("seizure", "fraud", "hacking"):
            with self.subTest(mode=mode):
                self.assertNotIn("run_mode", self._captured_kwargs(mode))

    def test_prepare_defaults_to_no_run_mode(self):
        captured: dict[str, object] = {}

        def fake_extract(path, stage_dir, **kwargs):
            captured.update(kwargs)
            raise _StopRun

        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "case.E01"
            image.write_bytes(b"EVF")
            with patch.object(run_module, "extract_e01_to_directory", side_effect=fake_extract), self.assertRaises(_StopRun):
                prepare_run_input_root(image, input_kind=None, output_dir=Path(tmp) / "out")
        self.assertNotIn("run_mode", captured)


class E01ResumeFingerprintRunModeTests(unittest.TestCase):
    def _checkpoint(self, extract_dir: Path, **extra: object) -> dict[str, object]:
        fingerprint = recovered_inventory_fingerprint(build_recovered_root_manifest(extract_dir))
        return {
            "profile_version": E01_STAGE_CHECKPOINT_VERSION,
            "completed": True,
            "resume_ready": True,
            "source_signature": {"size": 3},
            "requested_start_sector": None,
            "partition_selection": {"selected_start_sector": 2048},
            "tool_inputs": {"recovery_tool": "tsk_recover", "recovery_scope": build_tsk_recover_recovery_scope()},
            "recovered_inventory_fingerprint": fingerprint,
            **extra,
        }

    def _ready(self, checkpoint: dict[str, object], extract_dir: Path, run_mode: str | None) -> bool:
        return e01_checkpoint_resume_ready(
            checkpoint,
            source_signature={"size": 3},
            requested_start_sector=None,
            extract_dir=extract_dir,
            run_mode=run_mode,
        )

    def test_bounded_stage_dir_is_not_resumed_by_recovery_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            extract_dir = Path(tmp) / "extract"
            extract_dir.mkdir()
            (extract_dir / "a.txt").write_text("a", encoding="utf-8")
            bounded = self._checkpoint(extract_dir, extraction_mode="bounded")
            legacy = self._checkpoint(extract_dir)
            recovery = self._checkpoint(extract_dir, extraction_mode="recovery")
            self.assertTrue(self._ready(bounded, extract_dir, None))
            self.assertTrue(self._ready(bounded, extract_dir, "seizure"))
            self.assertFalse(self._ready(bounded, extract_dir, "recovery"))
            self.assertFalse(self._ready(legacy, extract_dir, "recovery"))
            self.assertTrue(self._ready(legacy, extract_dir, "fraud"))
            self.assertTrue(self._ready(recovery, extract_dir, "recovery"))
            self.assertFalse(self._ready(recovery, extract_dir, "hacking"))

    def test_extraction_records_mode_and_recovery_run_re_extracts(self):
        with tempfile.TemporaryDirectory() as tmp:
            e01_path = Path(tmp) / "case.E01"
            e01_path.write_bytes(b"EVF")
            stage_dir = Path(tmp) / "stage"
            commands: list[list[str]] = []

            def runner(command):
                commands.append(list(command))
                if command[1:] == ["--version"]:
                    return subprocess.CompletedProcess(command, 0, f"{command[0]} 1.0\n", "")
                if command[0] == "ewfmount":
                    (Path(command[2]) / "ewf1").write_bytes(b"raw")
                if command[0] == "mmls":
                    return subprocess.CompletedProcess(command, 0, "001: 0000002048 0000020000 NTFS\n", "")
                if command[0] == "tsk_recover":
                    Path(command[-1]).mkdir(parents=True, exist_ok=True)
                    (Path(command[-1]) / "evidence.txt").write_text("recovered", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "", "")

            def tools(name):
                return f"/usr/bin/{name}"

            first = extract_e01_to_directory(e01_path, stage_dir, runner=runner, tool_resolver=tools, run_mode="seizure")
            self.assertFalse(first.resume_status["resumed_from_checkpoint"])
            checkpoint = json.loads((stage_dir / "rapidtriage-e01-stage-status.json").read_text(encoding="utf-8"))
            self.assertEqual(checkpoint["extraction_mode"], "bounded")

            def forbidden(command):
                raise AssertionError(f"resume must not run {command}")

            resumed = extract_e01_to_directory(e01_path, stage_dir, runner=forbidden, tool_resolver=lambda _: None, run_mode="fraud")
            self.assertTrue(resumed.resume_status["resumed_from_checkpoint"])

            commands.clear()
            recovered = extract_e01_to_directory(e01_path, stage_dir, runner=runner, tool_resolver=tools, run_mode="recovery")
            self.assertFalse(recovered.resume_status["resumed_from_checkpoint"])
            self.assertIn("tsk_recover", [command[0] for command in commands])
            checkpoint = json.loads((stage_dir / "rapidtriage-e01-stage-status.json").read_text(encoding="utf-8"))
            self.assertEqual(checkpoint["extraction_mode"], "recovery")


class UnallocatedCarvingStageTests(unittest.TestCase):
    def setUp(self):
        coverage.reset_coverage()

    def test_every_ntfs_partition_is_carved_and_counted(self):
        partitions = [
            {"start_sector": 2048, "partition_number": 1, "filesystem": "ntfs"},
            {"start_sector": 206848, "partition_number": 2, "filesystem": "ntfs"},
            {"start_sector": 900000, "partition_number": 3, "filesystem": "fat"},
        ]
        calls: list[dict[str, object]] = []
        with tempfile.TemporaryDirectory() as tmp:
            result = _fake_e01_result(Path(tmp), partitions=partitions)
            carve_dir = Path(tmp) / "out" / "carve-unallocated"
            with patch.object(run_module, "run_unallocated_carving", side_effect=_fake_carving(calls)):
                step = run_unallocated_carving_stage(result, carve_dir, recovery=True, extract=False)
            index = json.loads((carve_dir / "rapidtriage-carve-unallocated.json").read_text(encoding="utf-8"))
        self.assertEqual([call["partition_start_sector"] for call in calls], [2048, 206848])
        self.assertEqual([call["output_dir"].name for call in calls], ["p1", "p2"])
        self.assertTrue(all(call["recovery"] is True and call["image"] == result.source_path for call in calls))
        self.assertEqual((step["status"], step["candidate_count"], step["extracted_count"]), ("completed", 6, 4))
        self.assertEqual(index["name"], "carve-unallocated")
        self.assertEqual(
            coverage.coverage_entries(),
            [
                {
                    "area": "carving.unallocated",
                    "reason_code": "unsupported_filesystem",
                    "limit": None,
                    "observed": 900000,
                    "unit": "start_sector",
                }
            ],
        )

    def test_failed_partition_is_a_partial_step_not_a_failed_run(self):
        partitions = [
            {"start_sector": 2048, "partition_number": 1, "filesystem": "ntfs"},
            {"start_sector": 206848, "partition_number": 2, "filesystem": "ntfs"},
        ]
        calls: list[dict[str, object]] = []
        with tempfile.TemporaryDirectory() as tmp:
            result = _fake_e01_result(Path(tmp), partitions=partitions)
            with patch.object(run_module, "run_unallocated_carving", side_effect=_fake_carving(calls, fail_sector=206848)):
                step = run_unallocated_carving_stage(result, Path(tmp) / "carve", recovery=False, extract=False)
        self.assertEqual(step["status"], "partial")
        self.assertEqual(step["candidate_count"], 3)
        self.assertEqual(step["warning_level"], "warning")
        self.assertFalse(calls[0]["recovery"])

    def test_external_tool_extraction_carves_the_selected_partition(self):
        calls: list[dict[str, object]] = []
        with tempfile.TemporaryDirectory() as tmp:
            result = _fake_e01_result(Path(tmp))
            with patch.object(run_module, "run_unallocated_carving", side_effect=_fake_carving(calls)):
                run_unallocated_carving_stage(result, Path(tmp) / "carve", recovery=True, extract=False)
        self.assertEqual([(call["partition_start_sector"], call["output_dir"].name) for call in calls], [(2048, "carve")])


class RunWiringTests(unittest.TestCase):
    def _run(self, tmp: Path, mode: str, calls: list[dict[str, object]]) -> dict[str, object]:
        result = _fake_e01_result(tmp, partitions=[{"start_sector": 2048, "partition_number": 1, "filesystem": "ntfs"}])
        input_root = InputRoot(source_path=str(result.source_path), root_path=result.extract_dir, kind="e01-derived")
        output_dir = tmp / "out"
        with patch.object(run_module, "prepare_run_input_root", return_value=(input_root, result)), patch.object(
            run_module, "run_unallocated_carving", side_effect=_fake_carving(calls)
        ):
            run_triage_mode(result.source_path, mode=mode, output_dir=output_dir, read_only=True, overwrite=True)
        return json.loads((output_dir / "rapidtriage-run-summary.json").read_text(encoding="utf-8"))

    def test_recovery_run_carves_unallocated_and_reports_counts(self):
        calls: list[dict[str, object]] = []
        with tempfile.TemporaryDirectory() as tmp:
            summary = self._run(Path(tmp), "recovery", calls)
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0]["recovery"])
        self.assertEqual(calls[0]["output_dir"].name, "carve-unallocated")
        self.assertEqual(summary["carving_unallocated"]["summary"], {"candidate_count": 3, "extracted_count": 2})
        step = next(row for row in summary["steps"] if row.get("name") == "carve-unallocated")
        self.assertEqual(step["status"], "completed")
        self.assertIn("carve_unallocated", summary["outputs"])

    def test_bounded_run_writes_single_line_manifest_and_skips_carving(self):
        calls: list[dict[str, object]] = []
        with tempfile.TemporaryDirectory() as tmp:
            summary = self._run(Path(tmp), "seizure", calls)
            output_dir = Path(tmp) / "out"
            manifest_text = (output_dir / "rapidtriage-manifest.json").read_text(encoding="utf-8")
            summary_text = (output_dir / "rapidtriage-run-summary.json").read_text(encoding="utf-8")
        self.assertEqual(calls, [])
        self.assertNotIn("carving_unallocated", summary)
        self.assertNotIn("\n", manifest_text.strip())
        self.assertIsInstance(json.loads(manifest_text), dict)
        self.assertIn("\n  ", summary_text)


if __name__ == "__main__":
    unittest.main()
