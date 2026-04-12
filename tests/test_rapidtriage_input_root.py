from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import main
from rapidtriage.core.artifacts import run_artifact_collection
from rapidtriage.core.docs import build_manifest, run_docs_search
from rapidtriage.core.files import run_files_scan
from rapidtriage.core.input_root import InputRoot, derive_child_input_root, resolve_input_root
from rapidtriage.core.run import run_triage_mode
from tests.test_rapidtriage_run import build_run_fixture


class RapidTriageInputRootTests(unittest.TestCase):
    def test_detect_input_root_kinds(self) -> None:
        self.assertEqual(resolve_input_root("/").kind, "live")
        self.assertEqual(resolve_input_root("/Volumes/case-mount").kind, "mounted-image")
        self.assertEqual(resolve_input_root("/Volumes/e01-case-mount").kind, "e01-derived")
        self.assertEqual(resolve_input_root("/tmp/case-root").kind, "folder")

    def test_child_input_root_retains_parent_kind(self) -> None:
        parent = resolve_input_root("/Volumes/e01-case-mount")
        child = derive_child_input_root(parent, "/Volumes/e01-case-mount/Users")

        self.assertEqual(child.kind, parent.kind)
        self.assertEqual(child.source_path, parent.source_path)
        self.assertEqual(child.root_path, Path("/Volumes/e01-case-mount/Users"))

    def test_core_commands_accept_input_root_objects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root_path = Path(tmp_dir) / "case-root"
            root_path.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root_path)
            input_root = InputRoot(source_path=str(root_path), root_path=root_path.resolve(), kind="mounted-image")

            manifest = build_manifest(input_root, ["incident"])
            docs = run_docs_search(input_root, ["fraud"])
            files = run_files_scan(input_root)
            artifacts = run_artifact_collection(input_root, kind="browser")

            self.assertEqual(Path(manifest["root"]), root_path.resolve())
            self.assertEqual(Path(docs["root"]), root_path.resolve())
            self.assertEqual(Path(files["root"]), root_path.resolve())
            self.assertEqual(Path(artifacts["root"]), root_path.resolve())
            self.assertGreaterEqual(files["summary"]["candidate_count"], 1)

    def test_run_pipeline_accepts_input_root_objects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root_path = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            root_path.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root_path)
            input_root = InputRoot(source_path=str(root_path), root_path=root_path.resolve(), kind="e01-derived")

            payload = run_triage_mode(input_root, mode="fraud", output_dir=output_dir)

            self.assertEqual(payload["mode"], "fraud")
            self.assertEqual(Path(payload["root"]), root_path.resolve())
            self.assertTrue((output_dir / "rapidtriage-run-summary.json").is_file())

    def test_cli_accepts_input_kind_overrides_without_breaking_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root_path = Path(tmp_dir) / "case-root"
            output_path = Path(tmp_dir) / "manifest.json"
            root_path.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root_path)

            exit_code = main(
                [
                    "manifest",
                    str(root_path),
                    "--input-kind",
                    "mounted-image",
                    "--output",
                    str(output_path),
                ]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(Path(payload["root"]), root_path.resolve())


if __name__ == "__main__":
    unittest.main()
