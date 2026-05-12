from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import main
from rapidtriage.core.macos_live_smoke import (
    MACOS_LIVE_SOURCE_HASH_MAX_BYTES,
    build_redacted_source_profile,
    run_macos_live_smoke,
)
from tests.test_rapidtriage_macos_artifacts import build_macos_fixture


class RapidTriageMacOsLiveSmokeTests(unittest.TestCase):
    def test_macos_live_smoke_writes_redacted_counts_and_benchmarks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "mac-root"
            output_dir = Path(tmp_dir) / "smoke"
            build_macos_fixture(root)

            payload = run_macos_live_smoke(
                output_dir=output_dir,
                root=root,
                home=root / "Users" / "alice",
                benchmark_file_count=5,
                fts_record_count=30,
                keyword="password",
                overwrite=True,
            )

            self.assertEqual(payload["command"], "macos-live-smoke")
            self.assertTrue((output_dir / "macos-live-smoke.json").is_file())
            self.assertTrue((output_dir / "macos-live-smoke.md").is_file())
            self.assertGreaterEqual(payload["macos_artifact_summary"]["record_count"], 1)
            self.assertFalse(payload["macos_artifact_summary"]["redaction"]["raw_paths_included"])
            serialized = json.dumps(payload, ensure_ascii=False)
            self.assertNotIn("https://example.test/mac-download", serialized)
            self.assertIn("triage_benchmark", payload["performance_summary"])
            self.assertIn("sqlite_fts", payload["performance_summary"])

    def test_macos_live_smoke_cli_prints_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "mac-root"
            output_dir = Path(tmp_dir) / "smoke"
            build_macos_fixture(root)

            self.assertEqual(
                main(
                    [
                        "macos-live-smoke",
                        "--root",
                        str(root),
                        "--home",
                        str(root / "Users" / "alice"),
                        "--output-dir",
                        str(output_dir),
                        "--benchmark-file-count",
                        "3",
                        "--fts-record-count",
                        "20",
                        "--overwrite",
                        "--json",
                    ]
                ),
                0,
            )

    def test_source_profile_skips_large_file_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            large_file = Path(tmp_dir) / "large-history.db"
            with large_file.open("wb") as handle:
                handle.truncate(MACOS_LIVE_SOURCE_HASH_MAX_BYTES + 1)

            profile = build_redacted_source_profile(str(large_file), count=1, include_path_details=False)

        self.assertEqual(profile["size"], MACOS_LIVE_SOURCE_HASH_MAX_BYTES + 1)
        self.assertNotIn("sha256", profile)
        self.assertEqual(profile["sha256_skipped_reason"], "source-file-exceeds-live-smoke-hash-cap")
        self.assertFalse(profile.get("source_path"))


if __name__ == "__main__":
    unittest.main()
