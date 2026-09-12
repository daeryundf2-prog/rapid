from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import rapidtriage.core.run as run_module
from rapidtriage.cli import main
from rapidtriage.core.incremental import (
    EVIDENCE_DELTA_MANIFEST_NAME,
    EVIDENCE_DELTA_SCOPE_MANIFEST_NAME,
    build_evidence_delta,
)
from tests.windows_artifact_fixtures import build_windows_artifact_fixture


class RapidTriageIncrementalIngestTests(unittest.TestCase):
    def test_build_evidence_delta_sets(self) -> None:
        previous = {
            "fingerprint": "prev",
            "root": "/case/root",
            "summary": {"truncated": False},
            "files": [
                {"relative_path": "a.txt", "size_bytes": 3, "mtime_ns": 1, "sha256": "aaa"},
                {"relative_path": "b.txt", "size_bytes": 3, "mtime_ns": 1, "sha256": "bbb"},
                {"relative_path": "gone.txt", "size_bytes": 1, "mtime_ns": 1, "sha256": "ccc"},
            ],
        }
        current = {
            "fingerprint": "cur",
            "root": "/case/root",
            "summary": {"truncated": False},
            "files": [
                {"relative_path": "a.txt", "size_bytes": 3, "mtime_ns": 1, "sha256": "aaa"},
                {"relative_path": "b.txt", "size_bytes": 5, "mtime_ns": 2, "sha256": "ddd"},
                {"relative_path": "new.txt", "size_bytes": 1, "mtime_ns": 3, "sha256": "eee"},
            ],
        }

        delta = build_evidence_delta(previous, current)

        self.assertTrue(delta["usable"])
        self.assertEqual(delta["counts"]["added"], 1)
        self.assertEqual(delta["counts"]["removed"], 1)
        self.assertEqual(delta["counts"]["changed"], 1)
        self.assertEqual(delta["counts"]["unchanged"], 1)
        self.assertEqual(delta["scope_paths"], ["b.txt", "new.txt"])
        self.assertEqual(delta["unchanged_paths"], ["a.txt"])

    def test_build_evidence_delta_blocks_moved_or_truncated_roots(self) -> None:
        base = {
            "fingerprint": "x",
            "root": "/case/root",
            "summary": {"truncated": False},
            "files": [{"relative_path": "a.txt", "size_bytes": 1, "mtime_ns": 1, "sha256": "a"}],
        }
        moved = {**base, "root": "/other/root"}
        delta = build_evidence_delta(base, moved)
        self.assertFalse(delta["usable"])
        self.assertTrue(any("root" in blocker for blocker in delta["blockers"]))

        truncated = {**base, "summary": {"truncated": True}}
        delta = build_evidence_delta(base, truncated)
        self.assertFalse(delta["usable"])

    def test_run_resume_unchanged_reuses_all_stages_without_delta(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            root.mkdir(parents=True, exist_ok=True)
            build_windows_artifact_fixture(root)
            (root / "note.txt").write_text("invoice evidence note", encoding="utf-8")

            self.assertEqual(
                main(["run", str(root), "--mode", "fraud", "--output-dir", str(output_dir)]),
                0,
            )
            collections: list[str] = []
            original = run_module.timed_artifact_collection

            def spy(input_root, *, kind, rule_set):
                collections.append(str(input_root.root_path))
                return original(input_root, kind=kind, rule_set=rule_set)

            with mock.patch.object(run_module, "timed_artifact_collection", side_effect=spy):
                self.assertEqual(
                    main(
                        [
                            "run",
                            str(root),
                            "--mode",
                            "fraud",
                            "--output-dir",
                            str(output_dir),
                            "--resume",
                        ]
                    ),
                    0,
                )

            self.assertEqual(collections, [])
            self.assertFalse((output_dir / EVIDENCE_DELTA_MANIFEST_NAME).exists())
            summary_payload = json.loads(
                (output_dir / "rapidtriage-run-summary.json").read_text(encoding="utf-8")
            )
            self.assertTrue(summary_payload["safety"]["resume_effective"])
            self.assertEqual(summary_payload["safety"]["delta_applied_outputs"], [])
            checkpoints = json.loads(
                (output_dir / "rapidtriage-run-checkpoints.json").read_text(encoding="utf-8")
            )
            reused = {
                item["stage"]: item
                for item in checkpoints["checkpoints"]
                if item["stage"].startswith("artifacts-")
            }
            self.assertTrue(reused)
            self.assertTrue(all(item["reused"] for item in reused.values()))

    def test_run_resume_changed_file_delta_merges_artifact_stages(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            root.mkdir(parents=True, exist_ok=True)
            build_windows_artifact_fixture(root)
            changed_file = root / "evidence-note.txt"
            changed_file.write_text("invoice evidence v1", encoding="utf-8")
            stable_file = root / "stable-note.txt"
            stable_file.write_text("stable content", encoding="utf-8")

            self.assertEqual(
                main(["run", str(root), "--mode", "fraud", "--output-dir", str(output_dir)]),
                0,
            )
            changed_file.write_text("invoice evidence v2 changed", encoding="utf-8")

            collected_roots: list[str] = []
            original = run_module.timed_artifact_collection

            def spy(input_root, *, kind, rule_set):
                collected_roots.append(str(input_root.root_path))
                return original(input_root, kind=kind, rule_set=rule_set)

            with mock.patch.object(run_module, "timed_artifact_collection", side_effect=spy):
                self.assertEqual(
                    main(
                        [
                            "run",
                            str(root),
                            "--mode",
                            "fraud",
                            "--output-dir",
                            str(output_dir),
                            "--resume",
                        ]
                    ),
                    0,
                )

            delta_manifest_path = output_dir / EVIDENCE_DELTA_MANIFEST_NAME
            self.assertTrue(delta_manifest_path.is_file())
            delta_manifest = json.loads(delta_manifest_path.read_text(encoding="utf-8"))
            self.assertTrue(delta_manifest["usable"])
            self.assertTrue(delta_manifest["artifacts_delta_enabled"])
            self.assertEqual(delta_manifest["delta"]["counts"]["changed"], 1)
            self.assertEqual(delta_manifest["delta"]["counts"]["unchanged"] >= 1, True)

            scope_manifest = json.loads(
                (output_dir / EVIDENCE_DELTA_SCOPE_MANIFEST_NAME).read_text(encoding="utf-8")
            )
            self.assertEqual(scope_manifest["file_count"], 1)
            self.assertEqual(
                [entry["relative_path"] for entry in scope_manifest["entries"]],
                ["evidence-note.txt"],
            )
            scope_root = Path(scope_manifest["scope_root"])
            scope_files = sorted(
                str(path.relative_to(scope_root)) for path in scope_root.rglob("*") if path.is_file()
            )
            self.assertEqual(scope_files, ["evidence-note.txt"])

            # Every artifact collection ran against the one-file delta scope,
            # so only the changed file was reprocessed.
            self.assertTrue(collected_roots)
            self.assertEqual(set(collected_roots), {str(scope_root)})

            checkpoints = json.loads(
                (output_dir / "rapidtriage-run-checkpoints.json").read_text(encoding="utf-8")
            )
            artifact_rows = {
                item["stage"]: item
                for item in checkpoints["checkpoints"]
                if item["stage"].startswith("artifacts-")
            }
            self.assertTrue(artifact_rows)
            self.assertTrue(all(item["delta_merged"] for item in artifact_rows.values()))
            self.assertEqual(
                {item["status"] for item in artifact_rows.values()},
                {"delta-merged"},
            )
            files_checkpoint = next(
                item for item in checkpoints["checkpoints"] if item["stage"] == "files"
            )
            self.assertTrue(files_checkpoint["delta_merged"])

            summary_payload = json.loads(
                (output_dir / "rapidtriage-run-summary.json").read_text(encoding="utf-8")
            )
            self.assertFalse(summary_payload["safety"]["resume_effective"])
            self.assertIn("files", summary_payload["safety"]["delta_applied_outputs"])
            self.assertTrue(
                any(
                    name.startswith("artifacts-")
                    for name in summary_payload["safety"]["delta_applied_outputs"]
                )
            )
            self.assertEqual(
                summary_payload["safety"]["evidence_delta"]["profile_version"],
                "evidence-delta-ingest-v1",
            )

            files_payload = json.loads(
                (output_dir / "rapidtriage-files.json").read_text(encoding="utf-8")
            )
            delta_info = files_payload["incremental_delta"]
            self.assertEqual(delta_info["mode"], "delta-merged")
            self.assertEqual(delta_info["scope_file_count"], 1)
            candidate_paths = {row["path"] for row in files_payload["candidates"]}
            self.assertNotIn(str(scope_root / "evidence-note.txt"), candidate_paths)
            reused_rows = [
                row
                for row in files_payload["candidates"]
                if row.get("incremental_reuse", {}).get("decision") == "reused-unchanged-evidence"
            ]
            self.assertTrue(
                any(row["path"] == str(stable_file.resolve()) for row in reused_rows)
            )

            scheduler = json.loads(
                (output_dir / "rapidtriage-parser-scheduler.json").read_text(encoding="utf-8")
            )
            self.assertGreater(scheduler["delta_merged_count"], 0)
            self.assertTrue(
                any(
                    event["status"] == "delta-merged" and event["delta_merged"]
                    for event in scheduler["events"]
                )
            )

            artifact_outputs = [
                path
                for path in (output_dir / "artifacts").glob("rapidtriage-artifacts-*.json")
            ]
            merged_with_delta = 0
            for artifact_path in artifact_outputs:
                payload = json.loads(artifact_path.read_text(encoding="utf-8"))
                if "incremental_delta" not in payload:
                    continue
                merged_with_delta += 1
                for row in payload["artifacts"]:
                    self.assertNotIn(str(scope_root), json.dumps(row))
            self.assertGreater(merged_with_delta, 0)

    def test_run_resume_removed_file_merges_removal_only_delta(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            root.mkdir(parents=True, exist_ok=True)
            build_windows_artifact_fixture(root)
            removed_file = root / "doomed-note.txt"
            removed_file.write_text("temporary invoice note", encoding="utf-8")

            self.assertEqual(
                main(["run", str(root), "--mode", "fraud", "--output-dir", str(output_dir)]),
                0,
            )
            removed_file.unlink()
            self.assertEqual(
                main(
                    [
                        "run",
                        str(root),
                        "--mode",
                        "fraud",
                        "--output-dir",
                        str(output_dir),
                        "--resume",
                    ]
                ),
                0,
            )

            delta_manifest = json.loads(
                (output_dir / EVIDENCE_DELTA_MANIFEST_NAME).read_text(encoding="utf-8")
            )
            self.assertTrue(delta_manifest["usable"])
            self.assertEqual(delta_manifest["delta"]["counts"]["removed"], 1)
            self.assertEqual(delta_manifest["delta"]["counts"]["changed"], 0)
            scope_manifest = delta_manifest["scope_manifest"]
            self.assertEqual(scope_manifest["file_count"], 0)

            files_payload = json.loads(
                (output_dir / "rapidtriage-files.json").read_text(encoding="utf-8")
            )
            candidate_paths = {row["path"] for row in files_payload["candidates"]}
            self.assertNotIn(str(removed_file.resolve()), candidate_paths)


if __name__ == "__main__":
    unittest.main()
