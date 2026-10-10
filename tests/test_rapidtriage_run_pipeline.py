"""Run pipeline robustness: parallel providers, per-provider persistence,
progress file, and the docs.json manifest summary (run-pipeline-mitigations)."""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import rapidtriage.core.run as run_module
from rapidtriage.artifacts import all_providers, clear_collect_cache
from rapidtriage.artifacts.windows.registry import WindowsRegistryProvider
from rapidtriage.core import files as files_module
from rapidtriage.core.docs import (
    build_manifest,
    build_manifest_summary,
    json_default,
    provider_progress_key,
)
from rapidtriage.core.input_root import resolve_input_root
from rapidtriage.core.run import (
    RUN_PROFILES,
    RUN_PROGRESS_FILE_NAME,
    RunModeError,
    RunProgress,
    collect_artifact_stages,
    run_triage_mode,
)
from tests.test_rapidtriage_run import build_run_fixture


def load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def expected_provider_kinds(mode: str) -> set[str]:
    return set(RUN_PROFILES[mode].artifacts_kinds) | {provider_progress_key(item) for item in all_providers()}


class RunPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        clear_collect_cache()

    def tearDown(self) -> None:
        clear_collect_cache()
        self.assertFalse(files_module._EVIDENCE_PATH_CACHE_ENABLED)
        self.assertEqual(files_module._EVIDENCE_PATH_CACHE, {})

    def test_run_writes_progress_file_and_summarized_docs_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            root.mkdir(parents=True)
            build_run_fixture(root)

            summary = run_triage_mode(root, mode="hacking", output_dir=output_dir)

            progress = load_json(output_dir / RUN_PROGRESS_FILE_NAME)
            self.assertEqual(progress["status"], "completed")
            self.assertEqual(progress["stage"], "completed")
            self.assertEqual(progress["run_root"], str(root.resolve()))
            self.assertEqual(progress["completed_count"], progress["total_count"])
            self.assertEqual(set(progress["providers"]), expected_provider_kinds("hacking"))
            self.assertEqual(progress["running"], [])
            self.assertEqual(progress["write_errors"], [])
            for kind, entry in progress["providers"].items():
                self.assertIn(entry["status"], {"completed", "reused"}, kind)
                self.assertIsNotNone(entry["completed_at"], kind)
                self.assertIsInstance(entry["artifact_count"], int, kind)
            completed_stages = [item["stage"] for item in progress["completed_stages"]]
            self.assertLess(completed_stages.index("artifacts"), completed_stages.index("manifest"))
            self.assertIn("indicators", completed_stages)

            manifest = load_json(output_dir / "rapidtriage-manifest.json")
            docs = load_json(output_dir / "rapidtriage-docs.json")
            self.assertEqual(
                [item["name"] for item in manifest["providers"]],
                [item.name for item in all_providers()],
            )
            self.assertEqual(docs["manifest"], build_manifest_summary(manifest))
            for row in docs["manifest"]["providers"]:
                self.assertNotIn("artifacts", row)
                self.assertEqual(
                    set(row),
                    {"name", "description", "target_platform", "supported", "artifact_count"},
                )
            for item in manifest["providers"]:
                # Run manifests carry per-provider summaries, never row arrays.
                self.assertNotIn("artifacts", item)
                self.assertIn("records_path", item)
            manifest_counts = {item["name"]: item["artifact_count"] for item in manifest["providers"]}
            self.assertEqual(
                {item["name"]: item["artifact_count"] for item in docs["manifest"]["providers"]},
                manifest_counts,
            )
            artifact_total = sum(
                int(load_json(Path(path))["summary"]["artifact_count"])
                for name, path in summary["outputs"].items()
                if name.startswith("artifacts_")
            )
            self.assertGreater(artifact_total, 0)
            self.assertEqual(
                artifact_total,
                sum(
                    count
                    for item, count in zip(all_providers(), manifest_counts.values())
                    if provider_progress_key(item) in RUN_PROFILES["hacking"].artifacts_kinds
                ),
            )

    def test_artifact_files_are_written_once_on_completion_with_cache_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            root.mkdir(parents=True)
            build_run_fixture(root)
            writes: dict[str, list[str]] = {}
            cache_states: list[bool] = []
            original_write = run_module.write_result
            original_timed = run_module.timed_artifact_collection

            def recording_write(payload, path):
                original_write(payload, path)
                writes.setdefault(str(path), []).append(
                    json.dumps(payload, ensure_ascii=False, sort_keys=True, default=json_default)
                )

            def spy_timed(input_root, *, kind, rule_set, **kwargs):
                cache_states.append(files_module._EVIDENCE_PATH_CACHE_ENABLED)
                return original_timed(input_root, kind=kind, rule_set=rule_set, **kwargs)

            with mock.patch.object(run_module, "write_result", side_effect=recording_write), mock.patch.object(
                run_module, "timed_artifact_collection", side_effect=spy_timed
            ):
                summary = run_triage_mode(root, mode="fraud", output_dir=output_dir)

            self.assertTrue(cache_states)
            self.assertTrue(all(cache_states))
            artifact_outputs = {
                name: Path(path) for name, path in summary["outputs"].items() if name.startswith("artifacts_")
            }
            self.assertEqual(len(artifact_outputs), len(RUN_PROFILES["fraud"].artifacts_kinds))
            for path in artifact_outputs.values():
                recorded = writes.get(str(path))
                self.assertIsNotNone(recorded, path)
                self.assertEqual(len(recorded), 1, path)
                on_disk = json.dumps(load_json(path), ensure_ascii=False, sort_keys=True)
                self.assertEqual(on_disk, recorded[0])

    def test_failing_provider_is_isolated_and_other_outputs_persist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            root.mkdir(parents=True)
            build_run_fixture(root)
            calls: list[str] = []

            def broken_collect(self, collect_root):
                calls.append(str(collect_root))
                raise RuntimeError("synthetic registry parser crash")

            with mock.patch.object(WindowsRegistryProvider, "collect", broken_collect):
                summary = run_triage_mode(root, mode="hacking", output_dir=output_dir)

            # Collected once: the manifest stage reuses the memoized failure.
            self.assertEqual(len(calls), 1)
            registry_payload = load_json(output_dir / "artifacts" / "rapidtriage-artifacts-windows-registry.json")
            self.assertEqual(registry_payload["summary"]["collection_status"], "failed-isolated")
            for name, path in summary["outputs"].items():
                if name.startswith("artifacts_"):
                    self.assertIsInstance(load_json(Path(path)), dict)
            progress = load_json(output_dir / RUN_PROGRESS_FILE_NAME)
            self.assertEqual(progress["status"], "completed")
            self.assertEqual(progress["providers"]["windows-registry"]["status"], "error")
            self.assertEqual(progress["error_count"], 1)
            self.assertEqual(progress["completed_count"], progress["total_count"])
            manifest = load_json(output_dir / "rapidtriage-manifest.json")
            registry_row = next(item for item in manifest["providers"] if item["name"] == "windows-registry")
            self.assertEqual(registry_row["collection_status"], "failed-isolated")
            self.assertNotIn("artifacts", registry_row)
            self.assertEqual(registry_row["artifact_count"], 0)
            self.assertIn("failed-isolated", json.dumps(summary, default=json_default))

    def test_run_failure_records_failed_stage_and_keeps_artifact_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            root.mkdir(parents=True)
            build_run_fixture(root)

            with mock.patch.object(run_module, "run_files_scan", side_effect=RuntimeError("files stage exploded")):
                with self.assertRaises(RuntimeError):
                    run_triage_mode(root, mode="fraud", output_dir=output_dir)

            progress = load_json(output_dir / RUN_PROGRESS_FILE_NAME)
            self.assertEqual(progress["status"], "failed")
            self.assertEqual(progress["stage"], "files")
            self.assertEqual(progress["error"]["stage"], "files")
            self.assertEqual(progress["error"]["error_type"], "RuntimeError")
            for kind in RUN_PROFILES["fraud"].artifacts_kinds:
                path = output_dir / "artifacts" / f"rapidtriage-artifacts-{kind}.json"
                self.assertEqual(load_json(path)["kind"], kind)
            self.assertTrue((output_dir / "rapidtriage-manifest.json").is_file())

    def test_invalid_mode_writes_no_progress_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir) / "run-out"
            with self.assertRaises(RunModeError):
                run_triage_mode(Path(tmp_dir), mode="not-a-mode", output_dir=output_dir)
            self.assertFalse((output_dir / RUN_PROGRESS_FILE_NAME).exists())

    def test_artifact_stage_runs_providers_concurrently_and_tracks_running_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            root.mkdir(parents=True)
            output_dir.mkdir()
            build_run_fixture(root)
            progress = RunProgress(output_dir)
            progress.start(stage="artifacts")
            kinds = ("windows-registry", "eventlog")
            barrier = threading.Barrier(len(kinds), timeout=30)
            running_seen: list[int] = []
            original_timed = run_module.timed_artifact_collection

            def rendezvous(input_root, *, kind, rule_set, **kwargs):
                barrier.wait()
                running_seen.append(len(load_json(output_dir / RUN_PROGRESS_FILE_NAME)["running"]))
                barrier.wait()
                return original_timed(input_root, kind=kind, rule_set=rule_set, **kwargs)

            with mock.patch.object(run_module, "timed_artifact_collection", side_effect=rendezvous):
                results, scheduler_manifest = collect_artifact_stages(
                    resolve_input_root(root),
                    kinds,
                    artifacts_dir=output_dir / "artifacts",
                    resume=False,
                    rule_set=None,
                    progress=progress,
                )

            self.assertEqual(running_seen, [2, 2])
            self.assertEqual(scheduler_manifest["max_workers"], 2)
            snapshot = progress.snapshot()
            self.assertEqual(snapshot["completed_count"], 2)
            self.assertEqual(snapshot["running"], [])
            for kind in kinds:
                payload, path, reused, delta_merged = results[kind]
                self.assertFalse(reused)
                self.assertEqual(load_json(path), json.loads(json.dumps(payload, default=json_default)))
                self.assertEqual(snapshot["providers"][kind]["status"], "completed")


class RunProgressTests(unittest.TestCase):
    def test_progress_writes_atomically_and_tracks_provider_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir)
            progress = RunProgress(output_dir)
            progress.register_providers(["a", "b", "c"])
            self.assertFalse((output_dir / RUN_PROGRESS_FILE_NAME).exists())
            progress.start(stage="artifacts")
            progress.provider_running("a")
            progress.provider_running("b")
            on_disk = load_json(output_dir / RUN_PROGRESS_FILE_NAME)
            self.assertEqual([item["kind"] for item in on_disk["running"]], ["a", "b"])
            self.assertEqual(on_disk["providers"]["c"]["status"], "queued")
            progress.provider_finished("a", status="completed", artifact_count=3)
            progress.provider_finished("b", status="error", artifact_count=0)
            # A later cache-hit pass must not reopen finished providers.
            progress.provider_running("a")
            progress.provider_finished("a", status="error", artifact_count=0)
            progress.mark_unfinished_reused()
            progress.finish()
            on_disk = load_json(output_dir / RUN_PROGRESS_FILE_NAME)
            self.assertEqual(on_disk["providers"]["a"]["status"], "completed")
            self.assertEqual(on_disk["providers"]["a"]["artifact_count"], 3)
            self.assertIsInstance(on_disk["providers"]["a"]["duration_ms"], int)
            self.assertEqual(on_disk["providers"]["b"]["status"], "error")
            self.assertEqual(on_disk["providers"]["c"]["status"], "reused")
            self.assertEqual((on_disk["completed_count"], on_disk["error_count"], on_disk["total_count"]), (3, 1, 3))
            self.assertEqual(on_disk["status"], "completed")
            self.assertTrue(on_disk["updated_at"].endswith("+00:00"))
            self.assertEqual([path.name for path in output_dir.iterdir()], [RUN_PROGRESS_FILE_NAME])

    def test_progress_write_failures_never_raise(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            progress = RunProgress(Path(tmp_dir) / "missing" / "run-out")
            progress.start(stage="prepare")
            progress.provider_running("a")
            progress.fail(RuntimeError("boom"))
            snapshot = progress.snapshot()
        self.assertEqual(snapshot["status"], "failed")
        self.assertEqual(snapshot["error"]["stage"], "prepare")
        self.assertTrue(snapshot["write_errors"])


class BuildManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        clear_collect_cache()

    def tearDown(self) -> None:
        clear_collect_cache()

    def test_parallel_manifest_keeps_provider_order_and_isolates_failures(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            build_run_fixture(root)

            def broken_collect(self, collect_root):
                raise ValueError("registry boom")

            with mock.patch.object(WindowsRegistryProvider, "collect", broken_collect):
                manifest = build_manifest(root, ["invoice"])

        self.assertEqual([item["name"] for item in manifest["providers"]], [item.name for item in all_providers()])
        registry_row = next(item for item in manifest["providers"] if item["name"] == "windows-registry")
        self.assertEqual(registry_row["collection_status"], "failed-isolated")
        self.assertEqual(registry_row["parser_errors"][0]["error_type"], "ValueError")
        self.assertTrue(any(item["artifacts"] for item in manifest["providers"]))

    def test_manifest_summary_counts_artifacts_without_rows(self) -> None:
        manifest = {
            "generated_at": "2026-10-09T00:00:00",
            "root": "/evidence",
            "platform": "test",
            "keywords": ["a"],
            "providers": [
                {"name": "p1", "description": "d", "target_platform": "any", "supported": True, "artifacts": [{}, {}]},
                {"name": "p2", "description": "d", "target_platform": "any", "supported": False, "artifact_count": 3},
            ],
        }
        summary = build_manifest_summary(manifest)
        self.assertEqual(summary["keywords"], ["a"])
        self.assertEqual([item["artifact_count"] for item in summary["providers"]], [2, 3])
        self.assertTrue(all("artifacts" not in item for item in summary["providers"]))


if __name__ == "__main__":
    unittest.main()
