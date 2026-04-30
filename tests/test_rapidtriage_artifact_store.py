from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.core.artifact_store import (
    read_jsonl_artifacts,
    validate_artifact_record,
    write_jsonl_artifacts,
)


class RapidTriageArtifactStoreTests(unittest.TestCase):
    def test_write_jsonl_artifacts_streams_records_and_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "artifacts.jsonl"

            result = write_jsonl_artifacts(
                [artifact_record("CASE:SRC:1"), artifact_record("CASE:SRC:2")],
                output_path=output_path,
            )

            self.assertEqual(result.record_count, 2)
            self.assertEqual(result.rejected_count, 0)
            self.assertEqual(len(result.sha256), 64)
            self.assertTrue(Path(result.manifest_path).is_file())
            manifest = json.loads(Path(result.manifest_path).read_text(encoding="utf-8"))
            self.assertTrue(manifest["streaming_safe"])
            self.assertEqual(manifest["storage_role"], "worker-jsonl-staging-before-parquet")
            self.assertEqual(len(list(read_jsonl_artifacts(output_path))), 2)

    def test_invalid_records_are_rejected_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "artifacts.jsonl"

            result = write_jsonl_artifacts(
                [artifact_record("CASE:SRC:1"), {"schema": "wrong"}],
                output_path=output_path,
            )

            self.assertEqual(result.record_count, 1)
            self.assertEqual(result.rejected_count, 1)
            self.assertTrue(result.errors)

    def test_validate_artifact_record_reports_missing_and_type_errors(self) -> None:
        errors = validate_artifact_record(
            {
                "schema": "ArtifactRecordV1",
                "confidence": 2,
                "source": {},
                "validation_required": "yes",
                "commercial_grade_ready": False,
                "commercial_grade_blockers": [],
                "legal_limitations": [],
                "fields": {},
            }
        )

        self.assertIn("confidence-must-be-0-to-1", errors)
        self.assertIn("validation_required-must-be-boolean", errors)
        self.assertIn("source-missing-field:case_id", errors)
        self.assertIn("missing-field:artifact_id", errors)


def artifact_record(artifact_id: str) -> dict[str, object]:
    return {
        "schema": "ArtifactRecordV1",
        "artifact_id": artifact_id,
        "artifact_family": "worker-health",
        "artifact_type": "noop-worker-record",
        "parser": "fake-worker",
        "parser_version": "0.1",
        "source": {
            "case_id": "CASE",
            "source_id": "SRC",
            "source_path": "source.bin",
            "offset": None,
            "length": None,
            "hashes": {},
        },
        "confidence": 1.0,
        "validation_required": False,
        "commercial_grade_ready": False,
        "commercial_grade_blockers": ["contract-test"],
        "legal_limitations": ["not evidence"],
        "fields": {},
    }


if __name__ == "__main__":
    unittest.main()
