from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import build_parser, main
from rapidtriage.core.benchmark_fts import (
    build_sqlite_fts_synthetic_manifest,
    expected_sqlite_fts_hit_count,
    run_sqlite_fts_benchmark,
)


class RapidTriageSqliteFtsBenchmarkTests(unittest.TestCase):
    def test_sqlite_fts_synthetic_manifest_is_deterministic(self) -> None:
        first = build_sqlite_fts_synthetic_manifest(record_count=1000, keyword="needle", hit_every=10)
        second = build_sqlite_fts_synthetic_manifest(record_count=1000, keyword="needle", hit_every=10)

        self.assertEqual(first["manifest_hash"], second["manifest_hash"])
        self.assertEqual(first["expected_keyword_count"], 100)
        self.assertEqual(expected_sqlite_fts_hit_count(record_count=1001, hit_every=10), 100)

    def test_sqlite_fts_benchmark_outputs_metrics_and_query_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            payload = run_sqlite_fts_benchmark(
                output_dir=Path(temp),
                record_count=250,
                keyword="needle",
                query_iterations=2,
                hit_every=5,
            )

            self.assertTrue(Path(payload["outputs"]["json"]).is_file())
            self.assertTrue(Path(payload["outputs"]["markdown"]).is_file())
            self.assertTrue(Path(payload["outputs"]["database"]).is_file())

        self.assertEqual(payload["profile_version"], "sqlite-fts-synthetic-benchmark-v1")
        self.assertEqual(payload["metrics"]["record_count"], 250)
        self.assertEqual(payload["metrics"]["expected_hit_count"], 50)
        self.assertEqual(payload["metrics"]["returned_hit_count"], 50)
        self.assertEqual(payload["metrics"]["result_window_count"], 50)
        self.assertFalse(payload["metrics"]["truncated_by_result_window"])
        self.assertTrue(payload["summary"]["expected_counts_match"])
        self.assertEqual(payload["table_counts"]["benchmark_document"], 250)
        self.assertEqual(payload["query_plan_profile"]["profile_version"], "sqlite-fts-query-plan-profile-v1")
        self.assertEqual(payload["checkpoint_profile"]["mode"], "TRUNCATE")
        self.assertEqual(payload["file_sizes"]["profile_version"], "sqlite-fts-benchmark-file-sizes-v1")
        self.assertGreater(payload["file_sizes"]["total_bytes"], 4096)
        self.assertRegex(payload["proof_manifest_hash"], r"^[0-9a-f]{64}$")
        self.assertIn("#53", payload["summary"]["commercial_gap_ids"])
        self.assertIn("#74", payload["summary"]["commercial_gap_ids"])

    def test_sqlite_fts_benchmark_overwrite_removes_stale_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "sqlite-fts-benchmark.db").write_bytes(b"stale database")
            (root / "sqlite-fts-benchmark.db-wal").write_bytes(b"stale wal")
            (root / "sqlite-fts-benchmark.db-shm").write_bytes(b"stale shm")

            payload = run_sqlite_fts_benchmark(
                output_dir=root,
                record_count=100,
                keyword="needle",
                query_iterations=1,
                hit_every=10,
                overwrite=True,
            )

            self.assertEqual(payload["metrics"]["record_count"], 100)
            self.assertNotEqual((root / "sqlite-fts-benchmark.db").read_bytes(), b"stale database")
            if (root / "sqlite-fts-benchmark.db-wal").exists():
                self.assertNotEqual((root / "sqlite-fts-benchmark.db-wal").read_bytes(), b"stale wal")
            if (root / "sqlite-fts-benchmark.db-shm").exists():
                self.assertNotEqual((root / "sqlite-fts-benchmark.db-shm").read_bytes(), b"stale shm")

    def test_sqlite_fts_benchmark_cli_emits_json(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["sqlite-fts-benchmark", "--output-dir", "out"])
        self.assertEqual(args.command, "sqlite-fts-benchmark")

        with tempfile.TemporaryDirectory() as temp:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "sqlite-fts-benchmark",
                        "--output-dir",
                        temp,
                        "--record-count",
                        "200",
                        "--keyword",
                        "needle",
                        "--query-iterations",
                        "1",
                        "--hit-every",
                        "4",
                        "--json",
                    ]
                )
            payload = json.loads(stdout.getvalue())

        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["metrics"]["record_count"], 200)
        self.assertEqual(payload["metrics"]["expected_hit_count"], 50)
        self.assertEqual(payload["metrics"]["returned_hit_count"], 50)

    def test_sqlite_fts_benchmark_separates_total_hits_from_result_window(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            payload = run_sqlite_fts_benchmark(
                output_dir=Path(temp),
                record_count=2000,
                keyword="needle",
                query_iterations=1,
                hit_every=10,
            )

        self.assertEqual(payload["metrics"]["expected_hit_count"], 200)
        self.assertEqual(payload["metrics"]["returned_hit_count"], 200)
        self.assertEqual(payload["metrics"]["result_window_count"], 100)
        self.assertTrue(payload["metrics"]["truncated_by_result_window"])
        self.assertTrue(payload["summary"]["expected_counts_match"])


if __name__ == "__main__":
    unittest.main()
