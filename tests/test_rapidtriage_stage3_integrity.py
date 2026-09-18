from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from rapidtriage.core.disk_image import extract_raw_image_to_directory
from rapidtriage.core.e01 import extract_e01_to_directory
from rapidtriage.core.e01_hash import run_e01_streaming_hash
from rapidtriage.core.hash_cache import compute_hashes_cached, reset_hash_cache
from rapidtriage.core.submission import build_submission_manifest


def _fake_e01_runner(commands: list[list[str]], recovered_text: str = "recovered once"):
    def runner(command):
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
            (Path(command[-1]) / "evidence.txt").write_text(recovered_text, encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, "", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    return runner


def _fake_raw_runner(commands: list[list[str]], recovered_text: str = "raw image invoice"):
    def runner(command):
        commands.append(list(command))
        if command[1:] == ["--version"]:
            return subprocess.CompletedProcess(command, 0, f"{command[0]} 1.0\n", "")
        if command[0] == "mmls":
            return subprocess.CompletedProcess(command, 0, "001: 0000002048 0000020000 NTFS\n", "")
        if command[0] == "tsk_recover":
            Path(command[-1]).mkdir(parents=True, exist_ok=True)
            (Path(command[-1]) / "evidence.txt").write_text(recovered_text, encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, "", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    return runner


def _workflow_commands(commands: list[list[str]]) -> list[list[str]]:
    return [command for command in commands if command[1:] != ["--version"]]


class Stage3HashScopeTests(unittest.TestCase):
    def test_e01_streaming_hash_covers_every_segment_with_container_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = root / "case.E01"
            second = root / "case.E02"
            first.write_bytes(b"EVF-segment-one-bytes")
            second.write_bytes(b"EVF-segment-two-bytes")

            payload = run_e01_streaming_hash(
                source_path=first,
                output_dir=root / "hash-out",
                algorithms=("sha256",),
                chunk_size=64,
                checkpoint_interval_bytes=128,
            )

            expected_first = hashlib.sha256(first.read_bytes()).hexdigest()
            expected_second = hashlib.sha256(second.read_bytes()).hexdigest()
            expected_aggregate = hashlib.sha256(first.read_bytes() + second.read_bytes()).hexdigest()

            self.assertEqual(payload["digests"]["sha256"], expected_aggregate)
            self.assertEqual(payload["bytes_hashed"], len(first.read_bytes()) + len(second.read_bytes()))
            self.assertEqual(payload["segment_set_size_bytes"], payload["bytes_hashed"])
            self.assertEqual(len(payload["segment_digests"]), 2)
            self.assertEqual(payload["segment_digests"][0]["digests"]["sha256"], expected_first)
            self.assertEqual(payload["segment_digests"][1]["digests"]["sha256"], expected_second)
            self.assertEqual(payload["segment_digests"][1]["segment_number"], 2)

            scope = payload["hash_scope"]
            self.assertEqual(scope["scope"], "ewf-container-segment-bytes")
            self.assertEqual(scope["coverage"], "all-discovered-segments")
            self.assertIs(scope["claims_decoded_media_hash"], False)
            self.assertIs(scope["claims_acquisition_media_hash"], False)
            self.assertIs(payload["reportability_decision"]["not_acquisition_media_hash"], True)
            self.assertNotEqual(payload["reportability_decision"]["allowed_use"], "acquisition/full-image hash evidence")

            checkpoint = json.loads(Path(payload["outputs"]["checkpoint"]).read_text(encoding="utf-8"))
            self.assertEqual(checkpoint["status"], "complete")
            self.assertEqual(checkpoint["segments_completed"], 2)
            self.assertEqual(checkpoint["segment_set_size_bytes"], payload["bytes_hashed"])

            markdown = Path(payload["outputs"]["markdown"]).read_text(encoding="utf-8")
            self.assertIn("## Hash Scope", markdown)
            self.assertIn("## Segment Digests", markdown)

    def test_e01_streaming_hash_single_file_keeps_file_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "case.E01"
            source.write_bytes(b"EVF-single")

            payload = run_e01_streaming_hash(
                source_path=source,
                output_dir=root / "hash-out",
                algorithms=("sha256",),
                chunk_size=64,
            )

            self.assertEqual(payload["digests"]["sha256"], hashlib.sha256(b"EVF-single").hexdigest())
            self.assertEqual(len(payload["segment_digests"]), 1)
            self.assertEqual(payload["hash_scope"]["coverage"], "single-file")
            self.assertIs(payload["hash_scope"]["claims_decoded_media_hash"], False)


class Stage3RecoveryScopeTests(unittest.TestCase):
    def test_e01_recovery_command_drops_contradictory_allocated_flag(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            e01_path = root / "case.E01"
            e01_path.write_bytes(b"EVF")
            commands: list[list[str]] = []

            result = extract_e01_to_directory(
                e01_path,
                root / "stage",
                runner=_fake_e01_runner(commands),
                tool_resolver=lambda name: f"/usr/bin/{name}",
            )

            recover_command = next(
                command for command in _workflow_commands(commands) if command[0] == "tsk_recover"
            )
            self.assertIn("-e", recover_command)
            self.assertNotIn("-a", recover_command)
            scope = result.to_dict()["recovery_scope"]
            self.assertEqual(scope["flags"], ["-e"])
            self.assertEqual(scope["scope"], "all-files-allocated-and-unallocated")
            self.assertTrue(scope["deleted_files_in_scope"])
            self.assertIn("-a", scope["rejected_flags"])

    def test_raw_recovery_command_drops_contradictory_allocated_flag(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            image_path = root / "case.001"
            image_path.write_bytes(b"part1")
            commands: list[list[str]] = []

            result = extract_raw_image_to_directory(
                image_path,
                root / "stage",
                runner=_fake_raw_runner(commands),
                tool_resolver=lambda name: f"/usr/bin/{name}",
            )

            recover_command = next(
                command for command in _workflow_commands(commands) if command[0] == "tsk_recover"
            )
            self.assertIn("-e", recover_command)
            self.assertNotIn("-a", recover_command)
            metadata = result.to_dict()
            self.assertEqual(metadata["recovery_scope"]["flags"], ["-e"])
            plan_commands = metadata["report_grade_validation_plan"]["validation_commands"]
            plan_recover = next(row for row in plan_commands if row["id"] == "read-only-recovery")
            self.assertIn("-e", plan_recover["argv"])
            self.assertNotIn("-a", plan_recover["argv"])


class Stage3E01ResumeIntegrityTests(unittest.TestCase):
    def _run_once(self, e01_path: Path, stage_dir: Path, commands: list[list[str]]):
        return extract_e01_to_directory(
            e01_path,
            stage_dir,
            runner=_fake_e01_runner(commands),
            tool_resolver=lambda name: f"/usr/bin/{name}",
        )

    def test_resume_rejects_changed_secondary_segment(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            e01_path = root / "case.E01"
            e02_path = root / "case.E02"
            e01_path.write_bytes(b"EVF-one")
            e02_path.write_bytes(b"EVF-two")
            stage_dir = root / "stage"
            commands: list[list[str]] = []

            first = self._run_once(e01_path, stage_dir, commands)
            self.assertFalse(first.resume_status["resumed_from_checkpoint"])

            e02_path.write_bytes(b"EVF-two-changed")
            commands.clear()
            second = self._run_once(e01_path, stage_dir, commands)

            self.assertFalse(second.resume_status["resumed_from_checkpoint"])
            self.assertTrue(
                any(command[0] == "tsk_recover" for command in _workflow_commands(commands))
            )

    def test_resume_rejects_recovered_file_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            e01_path = root / "case.E01"
            e01_path.write_bytes(b"EVF")
            stage_dir = root / "stage"
            commands: list[list[str]] = []

            self._run_once(e01_path, stage_dir, commands)
            recovered = stage_dir / "filesystem" / "evidence.txt"
            original = recovered.read_bytes()
            tampered = b"tampered-same!"[: len(original)]
            recovered.write_bytes(tampered)
            commands.clear()

            second = self._run_once(e01_path, stage_dir, commands)

            self.assertFalse(second.resume_status["resumed_from_checkpoint"])
            self.assertTrue(
                any(command[0] == "tsk_recover" for command in _workflow_commands(commands))
            )

    def test_resume_rejects_legacy_checkpoint_version(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            e01_path = root / "case.E01"
            e01_path.write_bytes(b"EVF")
            stage_dir = root / "stage"
            commands: list[list[str]] = []

            self._run_once(e01_path, stage_dir, commands)
            checkpoint_path = stage_dir / "rapidtriage-e01-stage-status.json"
            checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
            checkpoint["profile_version"] = "e01-stage-checkpoint-v1"
            checkpoint_path.write_text(json.dumps(checkpoint), encoding="utf-8")
            commands.clear()

            second = self._run_once(e01_path, stage_dir, commands)

            self.assertFalse(second.resume_status["resumed_from_checkpoint"])
            self.assertTrue(
                any(command[0] == "tsk_recover" for command in _workflow_commands(commands))
            )

    def test_resume_rejects_missing_tool_input_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            e01_path = root / "case.E01"
            e01_path.write_bytes(b"EVF")
            stage_dir = root / "stage"
            commands: list[list[str]] = []

            self._run_once(e01_path, stage_dir, commands)
            checkpoint_path = stage_dir / "rapidtriage-e01-stage-status.json"
            checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
            checkpoint.pop("tool_inputs", None)
            checkpoint_path.write_text(json.dumps(checkpoint), encoding="utf-8")
            commands.clear()

            second = self._run_once(e01_path, stage_dir, commands)

            self.assertFalse(second.resume_status["resumed_from_checkpoint"])

    def test_unchanged_segments_and_inventory_resume(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            e01_path = root / "case.E01"
            e02_path = root / "case.E02"
            e01_path.write_bytes(b"EVF-one")
            e02_path.write_bytes(b"EVF-two")
            stage_dir = root / "stage"
            commands: list[list[str]] = []

            self._run_once(e01_path, stage_dir, commands)
            commands.clear()
            second = self._run_once(e01_path, stage_dir, commands)

            self.assertTrue(second.resume_status["resumed_from_checkpoint"])
            self.assertEqual(_workflow_commands(commands), [])


class Stage3RawResumeIntegrityTests(unittest.TestCase):
    def _run_once(self, image_path: Path, stage_dir: Path, commands: list[list[str]]):
        return extract_raw_image_to_directory(
            image_path,
            stage_dir,
            runner=_fake_raw_runner(commands),
            tool_resolver=lambda name: f"/usr/bin/{name}",
        )

    def test_resume_rejects_changed_secondary_part(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            image_path = root / "case.001"
            second_part = root / "case.002"
            image_path.write_bytes(b"part1")
            second_part.write_bytes(b"part2")
            stage_dir = root / "stage"
            commands: list[list[str]] = []

            self._run_once(image_path, stage_dir, commands)
            second_part.write_bytes(b"part2-changed")
            commands.clear()

            result = self._run_once(image_path, stage_dir, commands)

            self.assertEqual(len(_workflow_commands(commands)), 2)
            self.assertEqual(
                (result.extract_dir / "evidence.txt").read_text(encoding="utf-8"),
                "raw image invoice",
            )

    def test_resume_rejects_recovered_file_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            image_path = root / "case.001"
            image_path.write_bytes(b"part1")
            stage_dir = root / "stage"
            commands: list[list[str]] = []

            self._run_once(image_path, stage_dir, commands)
            recovered = stage_dir / "filesystem" / "evidence.txt"
            recovered.write_bytes(b"x" * recovered.stat().st_size)
            commands.clear()

            self._run_once(image_path, stage_dir, commands)

            self.assertEqual(len(_workflow_commands(commands)), 2)

    def test_resume_rejects_legacy_checkpoint_version(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            image_path = root / "case.001"
            image_path.write_bytes(b"part1")
            stage_dir = root / "stage"
            commands: list[list[str]] = []

            self._run_once(image_path, stage_dir, commands)
            checkpoint_path = stage_dir / "rapidtriage-raw-image-stage-status.json"
            checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
            checkpoint["profile_version"] = "raw-image-stage-checkpoint-v1"
            checkpoint_path.write_text(json.dumps(checkpoint), encoding="utf-8")
            commands.clear()

            self._run_once(image_path, stage_dir, commands)

            self.assertEqual(len(_workflow_commands(commands)), 2)


class Stage3SubmissionHashTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_hash_cache()
        self.addCleanup(reset_hash_cache)

    def test_submission_manifest_bypasses_metadata_cache_for_same_size_modification(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "evidence.bin"
            source.write_bytes(b"AAAA-original")
            case_payload = {
                "case_id": "stage3-submission",
                "bookmarks": [
                    {
                        "bookmark_id": "bm-1",
                        "summary": "evidence",
                        "snapshot": {"path": str(source)},
                        "review": {"include_in_report": True},
                    }
                ],
            }

            primed = compute_hashes_cached(source)["sha256"]
            first = build_submission_manifest(case_payload, allowed_roots=[root], include_all=True)
            first_sha = first["items"][0]["evidence"]["hashes"]["sha256"]
            self.assertEqual(primed, hashlib.sha256(b"AAAA-original").hexdigest())
            self.assertEqual(first_sha, primed)

            stat_result = source.stat()
            source.write_bytes(b"BBBB-modified")
            os.utime(source, ns=(stat_result.st_atime_ns, stat_result.st_mtime_ns))

            stale = compute_hashes_cached(source)["sha256"]
            self.assertEqual(stale, first_sha)

            second = build_submission_manifest(case_payload, allowed_roots=[root], include_all=True)
            second_sha = second["items"][0]["evidence"]["hashes"]["sha256"]

            self.assertEqual(second_sha, hashlib.sha256(b"BBBB-modified").hexdigest())
            self.assertNotEqual(second_sha, first_sha)
            self.assertIs(second["hash_verification"]["metadata_cache_bypassed"], True)
            self.assertEqual(second["items"][0]["evidence"]["hash_source"], "fresh-file-read")


if __name__ == "__main__":
    unittest.main()
