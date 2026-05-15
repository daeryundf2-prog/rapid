from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import main
from rapidtriage.core.case_db import CaseDatabase
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
            attachment_script = output_dir / "attach-mac-evidence-to-readiness.sh"
            self.assertTrue(attachment_script.is_file())
            self.assertTrue(attachment_script.stat().st_mode & 0o111)
            self.assertIn("--mac-first-evidence", attachment_script.read_text(encoding="utf-8"))
            self.assertGreaterEqual(payload["macos_artifact_summary"]["record_count"], 1)
            self.assertFalse(payload["macos_artifact_summary"]["redaction"]["raw_paths_included"])
            serialized = json.dumps(payload, ensure_ascii=False)
            self.assertNotIn("https://example.test/mac-download", serialized)
            self.assertIn("triage_benchmark", payload["performance_summary"])
            self.assertIn("sqlite_fts", payload["performance_summary"])
            self.assertTrue((output_dir / "large-case-readiness.json").is_file())
            self.assertEqual(payload["large_case_readiness"]["profile_version"], "large-case-readiness-v1")
            self.assertEqual(payload["large_case_readiness"]["summary"]["largest_benchmark_record_count"], 30)
            self.assertEqual(
                payload["outputs"]["readiness_attachment_script"],
                str(attachment_script.resolve()),
            )
            self.assertEqual(
                payload["outputs"]["large_case_readiness_json"],
                str((output_dir / "large-case-readiness.json").resolve()),
            )
            attachment = payload["readiness_attachment"]
            self.assertEqual(attachment["profile_version"], "macos-live-smoke-readiness-attachment-v1")
            self.assertIn("--mac-first-evidence", attachment["cli_command"])
            self.assertIn("large-case-readiness.json", attachment["cli_command"])
            self.assertIn(66, attachment["supports_backlog_items"])
            report_text = (output_dir / "macos-live-smoke.md").read_text(encoding="utf-8")
            self.assertIn("Large-case readiness", report_text)
            self.assertIn("Readiness Attachment", report_text)
            self.assertIn("preparatory-only", report_text)

    def test_macos_live_smoke_can_profile_case_db_for_large_case_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "mac-root"
            output_dir = Path(tmp_dir) / "smoke"
            db_path = Path(tmp_dir) / "case.db"
            build_macos_fixture(root)
            database = CaseDatabase(db_path)
            database.initialize()
            database.create_case(case_id="CASE-MAC")

            payload = run_macos_live_smoke(
                output_dir=output_dir,
                root=root,
                home=root / "Users" / "alice",
                case_db_path=db_path,
                benchmark_file_count=5,
                fts_record_count=30,
                keyword="password",
                overwrite=True,
            )

            large_case = payload["large_case_readiness"]
            self.assertTrue(large_case["case_db_profile"]["attached"])
            self.assertEqual(large_case["summary"]["case_db_attached"], True)
            self.assertGreaterEqual(large_case["case_db_profile"]["fts_table_count"], 1)
            self.assertEqual(
                payload["inputs"]["case_db_path_hash"],
                build_redacted_source_profile(str(db_path.resolve()), count=1, include_path_details=False)["source_path_hash"],
            )

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
