from __future__ import annotations

import unittest
import tempfile
from pathlib import Path

from rapidtriage.core.columnar_store import (
    ColumnarStoreUnavailable,
    build_columnar_benchmark_plan,
    columnar_capabilities,
    convert_jsonl_to_parquet,
    normalize_artifact_record_for_columnar,
    run_columnar_benchmark,
    write_parquet_artifacts,
)


class RapidTriageColumnarStoreTests(unittest.TestCase):
    def test_columnar_capabilities_are_machine_readable(self) -> None:
        capabilities = columnar_capabilities()

        self.assertIn("pyarrow_available", capabilities)
        self.assertIn("duckdb_available", capabilities)
        self.assertEqual(capabilities["optional_dependency_group"], "columnar")
        self.assertIn("columnar", capabilities["install_hint"])

    def test_write_parquet_artifacts_has_clear_optional_dependency_error(self) -> None:
        capabilities = columnar_capabilities()
        if capabilities["parquet_write_available"]:
            self.skipTest("pyarrow is installed; unavailable-path test is not applicable")

        with self.assertRaisesRegex(ColumnarStoreUnavailable, "pyarrow is required"):
            write_parquet_artifacts([], output_path=Path("artifacts.parquet"))

    def test_columnar_benchmark_plan_is_available_without_optional_dependencies(self) -> None:
        plan = build_columnar_benchmark_plan(record_counts=(10, 100_001), target_row_group_size=100)

        self.assertEqual(plan["component"], "columnar-benchmark-plan")
        self.assertIn("#66", plan["commercial_gap_ids"])
        self.assertEqual(plan["matrix"][0]["target_row_group_count"], 1)
        self.assertEqual(plan["matrix"][1]["target_row_group_count"], 1001)
        self.assertTrue(plan["matrix"][0]["jsonl_baseline_required"])
        self.assertIn("peak_rss_bytes", plan["matrix"][0]["required_metrics"])

    def test_run_columnar_benchmark_writes_jsonl_baseline_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            payload = run_columnar_benchmark(
                output_dir=Path(tmp_dir),
                record_count=25,
                keyword="Needle",
                query_iterations=2,
            )

            self.assertEqual(payload["command"], "columnar-benchmark")
            self.assertEqual(payload["jsonl_baseline"]["record_count"], 25)
            self.assertEqual(payload["jsonl_baseline"]["query_match_count"], 3)
            self.assertIn(payload["duckdb_parquet_query"]["status"], {"skipped", "queried"})
            self.assertIn("python_version", payload["environment"])
            self.assertIn("dependency_versions", payload["environment"])
            self.assertTrue(Path(payload["outputs"]["json"]).is_file())
            self.assertTrue(Path(payload["outputs"]["markdown"]).is_file())
            self.assertTrue(Path(payload["outputs"]["jsonl"]).is_file())

    def test_convert_jsonl_to_parquet_uses_optional_dependency_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            benchmark = run_columnar_benchmark(
                output_dir=Path(tmp_dir) / "benchmark",
                record_count=5,
                query_iterations=1,
            )
            input_jsonl = Path(benchmark["outputs"]["jsonl"])
            output_parquet = Path(tmp_dir) / "converted.parquet"

            if not columnar_capabilities()["parquet_write_available"]:
                with self.assertRaisesRegex(ColumnarStoreUnavailable, "pyarrow is required"):
                    convert_jsonl_to_parquet(input_jsonl=input_jsonl, output_parquet=output_parquet)
                return

            payload = convert_jsonl_to_parquet(
                input_jsonl=input_jsonl,
                output_parquet=output_parquet,
                row_group_size=2,
            )

            self.assertEqual(payload["command"], "columnar-convert")
            self.assertEqual(payload["record_count"], 5)
            self.assertTrue(output_parquet.is_file())
            self.assertTrue(Path(payload["manifest_path"]).is_file())

    def test_columnar_normalization_uses_stable_scalar_columns(self) -> None:
        row = normalize_artifact_record_for_columnar(
            {
                "schema": "ArtifactRecordV1",
                "artifact_id": "A1",
                "artifact_family": "windows-eventlog",
                "artifact_type": "eventlog-event",
                "parser": "test",
                "parser_version": "1",
                "source": {
                    "case_id": "CASE",
                    "source_id": "SRC",
                    "source_path": "Security.evtx",
                    "offset": 128,
                    "length": 64,
                    "hashes": {"sha256": "abc"},
                },
                "confidence": 0.7,
                "validation_required": True,
                "commercial_grade_ready": False,
                "commercial_grade_blockers": ["validation"],
                "legal_limitations": ["test"],
                "fields": {"event_id": "4104"},
            },
            fallback_id="fallback",
        )

        self.assertEqual(row["artifact_id"], "A1")
        self.assertEqual(row["offset"], 128)
        self.assertIn('"event_id": "4104"', row["fields_json"])


if __name__ == "__main__":
    unittest.main()
