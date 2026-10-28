"""R8 review fixes, run core: per-run coverage, coverage across resumes, no process pool, and
E01 extraction digests reused by the run's hashing. Synthetic files and fakes only."""

from __future__ import annotations

import dataclasses
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from rapidtriage.core import coverage, hash_cache
from rapidtriage.core import run as run_module
from rapidtriage.core.digest_cache import RunDigestCache
from rapidtriage.core.e01 import (
    E01ExtractionResult,
    e01_checkpoint_resume_ready,
    e01_native_file_limit,
    extract_e01_to_directory,
    load_e01_stage_checkpoint,
)
from rapidtriage.core.run import (
    collect_artifact_stages,
    collect_with_coverage,
    run_triage_mode,
)
from rapidtriage.core.submission import compute_hashes

FAKE_DIGESTS = {"md5": "a" * 32, "sha1": "b" * 40, "sha256": "c" * 64}


def _entry(area: str, reason: str = "demo_cap") -> dict[str, object]:
    return {"area": area, "reason_code": reason, "limit": 1, "observed": 2, "unit": "records"}


class PerRunCoverageTests(unittest.TestCase):
    """f1 B2 (b) / f2 MINOR 2: two runs in one process neither wipe nor mix entries."""

    def test_concurrent_runs_keep_their_own_entries(self):
        barrier = threading.Barrier(2, timeout=10)
        results: dict[str, list[dict[str, object]]] = {}

        def run(name: str) -> None:
            collector, token = coverage.start_coverage_run()
            try:
                coverage.reset_coverage()
                barrier.wait()
                coverage.record_coverage(name, "demo_cap", 1, 2, "records")
                barrier.wait()
                if name == "run-b":
                    coverage.reset_coverage()  # a later run start must not wipe run-a
                    coverage.record_coverage(name, "after_reset", 1, 2, "records")
                barrier.wait()
                results[name] = coverage.coverage_entries()
            finally:
                coverage.finish_coverage_run(collector, token)

        threads = [threading.Thread(target=run, args=(name,), daemon=True) for name in ("run-a", "run-b")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(sorted(results), ["run-a", "run-b"])
        self.assertEqual(results["run-a"], [_entry("run-a")])
        self.assertEqual(results["run-b"], [_entry("run-b", "after_reset")])

    def test_provider_thread_entries_reach_its_run_and_kind(self):
        """A provider pump thread (no context) is matched to the run collecting that kind."""
        other_run = coverage.CoverageCollector()
        own_run = coverage.CoverageCollector()
        sink: dict[str, list[dict[str, object]]] = {}

        def fake_collect(*, kind: str) -> str:
            thread = threading.Thread(
                target=coverage.record_coverage,
                args=("eventlog", "demo_cap", 1, 2, "records"),
                name=f"rapidtriage-provider-{kind}",
            )
            thread.start()
            thread.join(timeout=10)
            return "done"

        # Two runs active: the "sole run" fallback cannot apply, only the thread binding can.
        with patch.object(coverage, "_RUNS", [other_run, own_run]):
            outcome = collect_with_coverage(own_run, sink, fake_collect, kind="eventlog")
        self.assertEqual(outcome, "done")
        self.assertEqual(sink["eventlog"], [_entry("eventlog")])
        self.assertEqual(own_run.entries(), [_entry("eventlog")])
        self.assertEqual(other_run.entries(), [])

    def test_run_triage_mode_uses_a_run_scoped_collector(self):
        coverage.reset_coverage()
        seen: list[list[dict[str, object]]] = []

        def fake_stages(*_args, **_kwargs):
            coverage.record_coverage("demo.area", "demo_cap", 1, 2, "records")
            seen.append(coverage.coverage_entries())
            return {}

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "evidence"
            root.mkdir()
            with patch.object(
                run_module, "prepare_run_input_root", return_value=(SimpleNamespace(root_path=root), None)
            ), patch.object(run_module, "_run_triage_stages", side_effect=fake_stages):
                run_triage_mode(root, mode="fraud", output_dir=Path(tmp) / "out")
        self.assertEqual(seen, [[_entry("demo.area")]])
        self.assertEqual(coverage.coverage_entries(), [])  # nothing leaked into the process collector


def _artifact_payload(kind: str) -> dict[str, object]:
    return {
        "command": "artifacts",
        "kind": kind,
        "generated_at": "2026-01-01T00:00:00+00:00",
        "root": "x",
        "provider": {"name": kind, "description": "", "target_platform": "windows", "supported": True},
        "summary": {"artifact_count": 0, "artifact_type_counts": {}},
        "artifacts": [],
    }


class ArtifactCoverageResumeTests(unittest.TestCase):
    """f1 B2 (c) / f2 M4: a reused provider payload replays the coverage it recorded."""

    def test_reused_payload_replays_its_coverage(self):
        def fake_tracked(progress, root, *, kind, **_kwargs):
            coverage.record_coverage("eventlog", "demo_cap", 1, 2, "records")
            return _artifact_payload(kind), "t0", "t1", 1

        with tempfile.TemporaryDirectory() as tmp:
            artifacts_dir = Path(tmp) / "artifacts"
            collector, token = coverage.start_coverage_run()
            try:
                with patch.object(run_module, "tracked_artifact_collection", side_effect=fake_tracked):
                    collect_artifact_stages(
                        SimpleNamespace(root_path=Path(tmp)), ["eventlog"], artifacts_dir=artifacts_dir,
                        resume=False, rule_set=None,
                    )
                first = coverage.coverage_entries()
            finally:
                coverage.finish_coverage_run(collector, token)
            self.assertEqual(first, [_entry("eventlog")])
            stored = json.loads((artifacts_dir / "rapidtriage-coverage-eventlog.json").read_text(encoding="utf-8"))
            self.assertEqual(stored, [_entry("eventlog")])

            collector, token = coverage.start_coverage_run()
            try:
                with patch.object(run_module, "tracked_artifact_collection", side_effect=AssertionError("reused")):
                    results, _manifest = collect_artifact_stages(
                        SimpleNamespace(root_path=Path(tmp)), ["eventlog"], artifacts_dir=artifacts_dir,
                        resume=True, rule_set=None,
                    )
                resumed = coverage.coverage_entries()
            finally:
                coverage.finish_coverage_run(collector, token)
        self.assertTrue(results["eventlog"][2])  # reused, not collected again
        self.assertEqual(resumed, [_entry("eventlog")])


def _external_runner(record_during_recover: bool):
    def runner(command):
        if command[1:] == ["--version"]:
            return subprocess.CompletedProcess(command, 0, f"{command[0]} 1.0\n", "")
        if command[0] == "ewfmount":
            (Path(command[2]) / "ewf1").write_bytes(b"raw")
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[0] == "mmls":
            return subprocess.CompletedProcess(command, 0, "001: 0000002048 0000020000 NTFS\n", "")
        if command[0] == "tsk_recover":
            Path(command[-1]).mkdir(parents=True, exist_ok=True)
            (Path(command[-1]) / "evidence.txt").write_text("recovered once", encoding="utf-8")
            if record_during_recover:
                coverage.record_coverage("e01_native.files", "file-count-cap", 5, 9, "files")
            return subprocess.CompletedProcess(command, 0, "", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    return runner


class E01CheckpointCoverageTests(unittest.TestCase):
    """f1 B2 (c) / f2 M4 and f2 MINOR 4: E01 checkpoint carries coverage and the file cap."""

    def setUp(self):
        coverage.reset_coverage()
        self.addCleanup(coverage.reset_coverage)

    def test_resumed_extraction_replays_coverage(self):
        expected = [{"area": "e01_native.files", "reason_code": "file-count-cap", "limit": 5, "observed": 9, "unit": "files"}]
        with tempfile.TemporaryDirectory() as tmp:
            e01_path = Path(tmp) / "case.E01"
            e01_path.write_bytes(b"EVF")
            stage_dir = Path(tmp) / "stage"
            extract_e01_to_directory(
                e01_path, stage_dir, runner=_external_runner(True), tool_resolver=lambda name: f"/usr/bin/{name}"
            )
            self.assertEqual(coverage.coverage_entries(), expected)
            checkpoint = load_e01_stage_checkpoint(stage_dir / "rapidtriage-e01-stage-status.json")
            self.assertEqual(checkpoint["coverage"], expected)

            coverage.reset_coverage()  # a new run starts with an empty collector

            def forbidden(command):
                raise AssertionError(f"resume must not run {command}")

            resumed = extract_e01_to_directory(e01_path, stage_dir, runner=forbidden, tool_resolver=lambda _: None)
            self.assertTrue(resumed.resume_status["resumed_from_checkpoint"])
            self.assertEqual(coverage.coverage_entries(), expected)
            # Replaying does not duplicate the stored entries.
            checkpoint = load_e01_stage_checkpoint(stage_dir / "rapidtriage-e01-stage-status.json")
            self.assertEqual(checkpoint["coverage"], expected)

    def test_file_limit_is_part_of_the_resume_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            e01_path = Path(tmp) / "case.E01"
            e01_path.write_bytes(b"EVF")
            stage_dir = Path(tmp) / "stage"
            result = extract_e01_to_directory(
                e01_path, stage_dir, runner=_external_runner(False), tool_resolver=lambda name: f"/usr/bin/{name}"
            )
            checkpoint_path = stage_dir / "rapidtriage-e01-stage-status.json"
            checkpoint = load_e01_stage_checkpoint(checkpoint_path)
            signature = checkpoint["source_signature"]
            with patch.dict(os.environ, {"RAPIDTRIAGE_NATIVE_MAX_EXTRACT_FILES": ""}):
                checkpoint["file_limit"] = e01_native_file_limit(None)
                ready_same = e01_checkpoint_resume_ready(
                    checkpoint, source_signature=signature, requested_start_sector=None, extract_dir=result.extract_dir
                )
            with patch.dict(os.environ, {"RAPIDTRIAGE_NATIVE_MAX_EXTRACT_FILES": "50"}):
                ready_capped = e01_checkpoint_resume_ready(
                    checkpoint, source_signature=signature, requested_start_sector=None, extract_dir=result.extract_dir
                )
                self.assertEqual(e01_native_file_limit("recovery"), 50)
            with patch.dict(os.environ, {"RAPIDTRIAGE_NATIVE_MAX_EXTRACT_FILES": ""}):
                self.assertEqual(e01_native_file_limit("recovery"), sys.maxsize)
        self.assertTrue(ready_same)
        self.assertFalse(ready_capped)


class ProcessPoolRemovedTests(unittest.TestCase):
    """f2 M2 / f1 B2 (a) / f1 N2: the never-used parser process pool is gone."""

    def test_procpool_module_is_deleted(self):
        self.assertIsNone(importlib.util.find_spec("rapidtriage.core.run.procpool"))
        self.assertFalse(hasattr(run_module, "pooled_artifact_collection"))


class RunDigestReuseTests(unittest.TestCase):
    """f1 B3 / plan todo 6: extraction digests are reused instead of re-reading the file."""

    def setUp(self):
        hash_cache.reset_hash_cache()
        self.addCleanup(hash_cache.reset_hash_cache)

    def _extracted(self, tmp: str) -> tuple[Path, Path]:
        extract_dir = Path(tmp) / "extract"
        target = extract_dir / "Users" / "a" / "note.txt"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"hello evidence")
        return extract_dir, target

    def test_seeded_file_is_not_opened(self):
        with tempfile.TemporaryDirectory() as tmp:
            extract_dir, target = self._extracted(tmp)
            cache = RunDigestCache()
            seeded = cache.seed_extracted(extract_dir, {"Users/a/note.txt": {"size_bytes": 14, **FAKE_DIGESTS}})
            self.assertEqual(seeded, 1)
            hash_cache.activate_run_digest_cache(cache)
            try:
                with patch.object(hash_cache, "compute_hashes_fresh", side_effect=AssertionError("file was read")):
                    self.assertEqual(compute_hashes(target), FAKE_DIGESTS)
            finally:
                hash_cache.deactivate_run_digest_cache(cache)

    def test_changed_file_is_hashed_again(self):
        with tempfile.TemporaryDirectory() as tmp:
            extract_dir, target = self._extracted(tmp)
            cache = RunDigestCache()
            cache.seed_extracted(extract_dir, {"Users/a/note.txt": {"size_bytes": 14, **FAKE_DIGESTS}})
            stat = target.stat()
            os.utime(target, ns=(stat.st_atime_ns, stat.st_mtime_ns + 10**12))  # modified after the seed
            hash_cache.activate_run_digest_cache(cache)
            try:
                self.assertNotEqual(compute_hashes(target), FAKE_DIGESTS)
            finally:
                hash_cache.deactivate_run_digest_cache(cache)

    def test_run_triage_mode_seeds_from_e01_extraction(self):
        hashed: list[dict[str, str]] = []
        with tempfile.TemporaryDirectory() as tmp:
            extract_dir, target = self._extracted(tmp)
            source = Path(tmp) / "case.E01"
            source.write_bytes(b"EVF")
            image_result = E01ExtractionResult(
                source_path=source,
                stage_dir=Path(tmp),
                mount_dir=Path(tmp) / "_ewfmount",
                raw_image_path=source,
                extract_dir=extract_dir,
                partition_start_sector=2048,
                recovered_root_manifest={"native_file_digests": {"Users/a/note.txt": {"size_bytes": 14, **FAKE_DIGESTS}}},
            )
            self.assertTrue(dataclasses.is_dataclass(image_result))

            def fake_stages(*_args, **_kwargs):
                with patch.object(hash_cache, "compute_hashes_fresh", side_effect=AssertionError("file was read")):
                    hashed.append(compute_hashes(target))
                return {}

            with patch.object(
                run_module, "prepare_run_input_root", return_value=(SimpleNamespace(root_path=extract_dir), image_result)
            ), patch.object(run_module, "_run_triage_stages", side_effect=fake_stages):
                run_triage_mode(source, mode="fraud", output_dir=Path(tmp) / "out")
        self.assertEqual(hashed, [FAKE_DIGESTS])
        self.assertEqual(hash_cache._RUN_DIGEST_CACHES, [])  # deactivated when the run ends


if __name__ == "__main__":
    unittest.main()
