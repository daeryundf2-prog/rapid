from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.core.artifact_store import (
    attach_artifact_record_contracts,
    build_artifact_record_v1_from_legacy,
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

    def test_legacy_artifact_rows_are_adapted_to_v1_contract(self) -> None:
        legacy_row = {
            "provider": "windows-browser-artifacts",
            "artifact_type": "browser-history",
            "path": "/case/Users/A/AppData/Local/Chrome/History",
            "supported": True,
            "details": {
                "parser": "browser",
                "parser_version": "browser-v2",
                "parser_confidence": 0.91,
                "source_offset": 128,
                "length": 512,
                "sha256": "abc123",
                "url": "https://example.test",
            },
        }

        record = build_artifact_record_v1_from_legacy(
            legacy_row,
            kind="browser",
            provider_name="windows-browser-artifacts",
            root="/case",
            index=1,
            case_id="CASE-1",
            source_id="SRC-1",
        )

        self.assertEqual(validate_artifact_record(record), [])
        self.assertEqual(record["schema"], "ArtifactRecordV1")
        self.assertEqual(record["artifact_family"], "browser")
        self.assertEqual(record["artifact_type"], "browser-history")
        self.assertEqual(record["parser"], "browser")
        self.assertEqual(record["parser_version"], "browser-v2")
        self.assertEqual(record["source"]["case_id"], "CASE-1")
        self.assertEqual(record["source"]["offset"], 128)
        self.assertEqual(record["source"]["length"], 512)
        self.assertEqual(record["source"]["hashes"]["sha256"], "abc123")
        self.assertEqual(record["confidence"], 0.91)
        self.assertIn("review_contract", record["fields"])
        self.assertIn("gui_contract", record["fields"])

    def test_artifact_payload_gets_contract_manifest_and_rows(self) -> None:
        payload = {
            "command": "artifacts",
            "kind": "browser",
            "provider": {"name": "windows-browser-artifacts"},
            "summary": {"artifact_count": 1, "artifact_type_counts": {"browser-history": 1}},
            "artifacts": [
                {
                    "provider": "windows-browser-artifacts",
                    "artifact_type": "browser-history",
                    "path": "/case/History",
                    "supported": True,
                    "details": {"parser": "browser", "parser_version": "browser-v2"},
                }
            ],
        }

        adapted = attach_artifact_record_contracts(payload, kind="browser", root="/case", case_id="CASE-1")

        self.assertEqual(adapted["artifact_record_contract"]["schema"], "ArtifactRecordV1")
        self.assertEqual(adapted["artifact_record_contract"]["valid_count"], 1)
        self.assertEqual(adapted["artifact_record_contract"]["invalid_count"], 0)
        self.assertTrue(adapted["artifact_record_contract"]["gui_usable"])
        self.assertEqual(adapted["summary"]["artifact_record_contract_valid_count"], 1)
        record = adapted["artifacts"][0]["artifact_record"]
        self.assertEqual(validate_artifact_record(record), [])
        self.assertEqual(record["fields"]["gui_contract"]["primary_tab"], "artifacts")


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
