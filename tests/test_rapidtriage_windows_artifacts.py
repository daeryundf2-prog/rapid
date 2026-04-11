from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path, PureWindowsPath

from rapidtriage.cli import main
from tests.windows_artifact_fixtures import build_windows_artifact_fixture


class RapidTriageWindowsArtifactsTests(unittest.TestCase):
    def test_manifest_surfaces_fixture_browser_history_downloads_and_recent_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            fixture = build_windows_artifact_fixture(root)
            output = root / "manifest.json"

            exit_code = main(["manifest", str(root), "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            serialized_artifacts = [
                json.dumps(artifact, ensure_ascii=False, sort_keys=True)
                for provider in payload["providers"]
                for artifact in provider["artifacts"]
            ]
            manifest_blob = "\n".join(serialized_artifacts)

            self.assertIn(fixture.chrome_visit.url, manifest_blob)
            self.assertIn(fixture.edge_visit.url, manifest_blob)
            self.assertIn(PureWindowsPath(fixture.download.target_path).name, manifest_blob)
            self.assertIn(fixture.recent_shortcut.name, manifest_blob)

    def test_manifest_windows_artifact_rows_point_inside_fixture_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            fixture = build_windows_artifact_fixture(root)
            output = root / "manifest.json"

            self.assertEqual(main(["manifest", str(root), "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            artifact_rows = [artifact for provider in payload["providers"] for artifact in provider["artifacts"]]

            matching = [
                artifact
                for artifact in artifact_rows
                if fixture.chrome_visit.url in json.dumps(artifact, ensure_ascii=False)
                or fixture.edge_visit.url in json.dumps(artifact, ensure_ascii=False)
                or fixture.recent_shortcut.name in json.dumps(artifact, ensure_ascii=False)
            ]

            self.assertTrue(matching)
            for artifact in matching:
                self.assertTrue(Path(artifact["path"]).is_relative_to(root.resolve()))
                self.assertIn("supported", artifact)
                self.assertIsInstance(artifact["details"], dict)


if __name__ == "__main__":
    unittest.main()
