from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.artifacts.synthetic_media import (
    SYNTHETIC_MEDIA_SCORE_GUIDANCE,
    SYNTHETIC_MEDIA_SCORE_SEMANTICS,
)
from rapidtriage.core.case_db import CaseDatabase, open_case_database
from rapidtriage.core.case_db.reporting import build_synthetic_media_summary
from rapidtriage.core.case_db.search import build_review_priority


def synthetic_media_row(
    *,
    artifact_type: str = "synthetic-media-image",
    source_path: str = "/evidence/suspect.png",
    details: dict[str, object] | None = None,
) -> dict[str, object]:
    merged_details = {
        "parser": "synthetic-media-deepfake-lens",
        "parser_version": "synthetic-media-deepfake-lens-v1",
        "coverage_status": "deepfake-lens-scan",
        "reportability": "triage",
        "source_path": source_path,
        "scan_status": "analyzed",
        "scan_kind": "image",
        "score": 72,
        "band": "high",
        "band_label": "높음",
        "verdict": "stub verdict",
        "signal_count": 1,
        "limitations": ["stub limitation"],
        "next_checks": ["stub next check"],
        "score_semantics": SYNTHETIC_MEDIA_SCORE_SEMANTICS,
        "score_guidance": SYNTHETIC_MEDIA_SCORE_GUIDANCE,
        "validation_required": True,
        "validation_guidance": "Treat score/band as review ordering only.",
    }
    if details:
        merged_details.update(details)
    return {
        "provider": "synthetic-media-artifacts",
        "artifact_type": artifact_type,
        "path": source_path,
        "supported": True,
        "details": merged_details,
    }


def insert_artifact(
    database: CaseDatabase,
    *,
    case_id: str,
    citation_id: str,
    artifact_type: str,
    title: str,
    summary: str,
    row: dict[str, object],
) -> None:
    with database.connect() as connection:
        connection.execute(
            """
            INSERT INTO artifact (
                citation_id, case_id, artifact_type, parser_name,
                parser_version, title, summary, data_json, confidence, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                citation_id,
                case_id,
                artifact_type,
                "synthetic-media-deepfake-lens",
                "synthetic-media-deepfake-lens-v1",
                title,
                summary,
                json.dumps(row, ensure_ascii=False, sort_keys=True),
                None,
                "2026-01-01T00:00:00+00:00",
            ),
        )


class SyntheticMediaReportingTests(unittest.TestCase):
    def _database_with_case(self, tmp_dir: str, case_id: str = "CASE-SM") -> CaseDatabase:
        database = open_case_database(Path(tmp_dir) / "case.db")
        database.create_case(case_id=case_id)
        return database

    def test_search_metadata_surfaces_score_band_and_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            database = self._database_with_case(tmp_dir)
            insert_artifact(
                database,
                case_id="CASE-SM",
                citation_id="CASE-SM-ART-000001",
                artifact_type="synthetic-media-image",
                title="synthetic-media-image: suspect.png",
                summary="deepfake-lens scan of suspect.png",
                row=synthetic_media_row(),
            )

            payload = database.search_case(
                case_id="CASE-SM",
                keywords=["suspect"],
                sources=["artifacts"],
                limit=5,
            )

            self.assertEqual(payload["summary"]["match_count"], 1)
            match = payload["matches"][0]
            metadata = match["metadata"]
            self.assertEqual(metadata["score"], 72)
            self.assertEqual(metadata["band"], "high")
            self.assertEqual(metadata["band_label"], "높음")
            self.assertEqual(metadata["scan_status"], "analyzed")
            self.assertEqual(metadata["scan_kind"], "image")
            self.assertEqual(metadata["score_semantics"], SYNTHETIC_MEDIA_SCORE_SEMANTICS)
            self.assertEqual(metadata["score_guidance"], SYNTHETIC_MEDIA_SCORE_GUIDANCE)
            self.assertTrue(metadata["validation_required"])
            self.assertIn("not an authenticity verdict", metadata["score_guidance"])

    def test_review_priority_boosts_high_band_synthetic_media(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            database = self._database_with_case(tmp_dir)
            insert_artifact(
                database,
                case_id="CASE-SM",
                citation_id="CASE-SM-ART-000001",
                artifact_type="synthetic-media-image",
                title="synthetic-media-image: suspect.png",
                summary="deepfake-lens scan of suspect.png",
                row=synthetic_media_row(),
            )

            payload = database.search_case(
                case_id="CASE-SM",
                keywords=["suspect"],
                sources=["artifacts"],
                limit=5,
            )
            match = payload["matches"][0]
            priority = match["review_priority"]

            self.assertGreaterEqual(priority["score"], 40)
            self.assertIn(priority["level"], {"medium", "high"})
            self.assertIn("high-band synthetic-media screening hit", priority["reasons"])
            self.assertTrue(
                any("not an authenticity verdict" in reason for reason in priority["reasons"]),
                "review priority must keep the prioritization-only caveat",
            )

    def test_review_priority_flags_scan_error_followup(self) -> None:
        match = {
            "source": "artifacts",
            "kind": "synthetic-media-scan-error",
            "title": "synthetic-media-scan-error: broken.png",
            "preview": "scan failed",
            "path": "/evidence/broken.png",
            "metadata": {
                "scan_status": "error",
                "scan_error": "RuntimeError: stub boom",
                "score_semantics": SYNTHETIC_MEDIA_SCORE_SEMANTICS,
                "validation_required": True,
            },
        }

        priority = build_review_priority(match, ["broken"])

        self.assertGreaterEqual(priority["score"], 10)
        self.assertIn(
            "synthetic-media scan error requires examiner follow-up",
            priority["reasons"],
        )

    def test_review_priority_does_not_boost_unavailable_status_record(self) -> None:
        match = {
            "source": "artifacts",
            "kind": "synthetic-media-scan-status",
            "title": "synthetic-media-scan-status",
            "preview": "provider unavailable",
            "path": "/evidence",
            "metadata": {
                "scan_status": "skipped-optional-dependency",
                "score_semantics": SYNTHETIC_MEDIA_SCORE_SEMANTICS,
            },
        }

        priority = build_review_priority(match, ["synthetic"])

        self.assertEqual(priority["level"], "low")
        self.assertNotIn("high-band synthetic-media screening hit", priority["reasons"])
        self.assertTrue(
            any("not an authenticity verdict" in reason for reason in priority["reasons"]),
        )

    def test_synthetic_media_summary_aggregates_scan_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            database = self._database_with_case(tmp_dir)
            insert_artifact(
                database,
                case_id="CASE-SM",
                citation_id="CASE-SM-ART-000001",
                artifact_type="synthetic-media-image",
                title="synthetic-media-image: suspect.png",
                summary="high-band scan",
                row=synthetic_media_row(),
            )
            insert_artifact(
                database,
                case_id="CASE-SM",
                citation_id="CASE-SM-ART-000002",
                artifact_type="synthetic-media-text",
                title="synthetic-media-text: notes.txt",
                summary="medium-band scan",
                row=synthetic_media_row(
                    artifact_type="synthetic-media-text",
                    source_path="/evidence/notes.txt",
                    details={
                        "scan_kind": "text",
                        "score": 41,
                        "band": "medium",
                        "band_label": "중간",
                    },
                ),
            )
            insert_artifact(
                database,
                case_id="CASE-SM",
                citation_id="CASE-SM-ART-000003",
                artifact_type="synthetic-media-scan-error",
                title="synthetic-media-scan-error: broken.png",
                summary="scan error",
                row=synthetic_media_row(
                    artifact_type="synthetic-media-scan-error",
                    source_path="/evidence/broken.png",
                    details={
                        "scan_status": "error",
                        "scan_error": "RuntimeError: stub boom",
                        "score": None,
                        "band": "",
                    },
                ),
            )
            insert_artifact(
                database,
                case_id="CASE-SM",
                citation_id="CASE-SM-ART-000004",
                artifact_type="synthetic-media-scan-summary",
                title="synthetic-media-scan-summary",
                summary="scan summary",
                row=synthetic_media_row(
                    artifact_type="synthetic-media-scan-summary",
                    source_path="/evidence",
                    details={
                        "scan_status": "completed",
                        "scan_file_count": 3,
                        "score": None,
                        "band": "",
                        "limitations": [],
                        "next_checks": [],
                    },
                ),
            )
            insert_artifact(
                database,
                case_id="CASE-SM",
                citation_id="CASE-SM-ART-000005",
                artifact_type="synthetic-media-scan-status",
                title="synthetic-media-scan-status",
                summary="provider unavailable",
                row={
                    "provider": "synthetic-media-artifacts",
                    "artifact_type": "synthetic-media-scan-status",
                    "path": "/evidence",
                    "supported": False,
                    "details": {
                        "parser": "synthetic-media-deepfake-lens",
                        "coverage_status": "provider-unavailable",
                        "scan_status": "skipped-optional-dependency",
                        "score_semantics": SYNTHETIC_MEDIA_SCORE_SEMANTICS,
                        "validation_required": False,
                    },
                },
            )

            with database.connect() as connection:
                summary = build_synthetic_media_summary(connection, "CASE-SM")

            self.assertEqual(summary["profile_version"], "synthetic-media-summary-v1")
            self.assertEqual(summary["artifact_count"], 5)
            self.assertEqual(summary["scanned_file_count"], 2)
            self.assertEqual(summary["scan_error_count"], 1)
            self.assertTrue(summary["provider_unavailable"])
            self.assertEqual(summary["band_counts"], {"high": 1, "medium": 1})
            self.assertEqual(summary["scored_file_count"], 2)
            self.assertEqual(summary["max_score"], 72)
            self.assertEqual(summary["high_band_count"], 1)
            self.assertEqual(summary["high_band_citations"], ["CASE-SM-ART-000001"])
            self.assertEqual(summary["artifact_type_counts"]["synthetic-media-image"], 1)
            self.assertIn("stub limitation", summary["limitations"])
            self.assertIn("stub next check", summary["next_checks"])
            self.assertEqual(summary["score_semantics"], SYNTHETIC_MEDIA_SCORE_SEMANTICS)
            self.assertEqual(summary["score_guidance"], SYNTHETIC_MEDIA_SCORE_GUIDANCE)
            self.assertTrue(summary["validation_required"])
            self.assertFalse(summary["commercial_claim_allowed"])
            self.assertTrue(summary["summary_hash"])

    def test_synthetic_media_summary_handles_case_without_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            database = self._database_with_case(tmp_dir)

            with database.connect() as connection:
                summary = build_synthetic_media_summary(connection, "CASE-SM")

            self.assertEqual(summary["artifact_count"], 0)
            self.assertEqual(summary["scanned_file_count"], 0)
            self.assertFalse(summary["provider_unavailable"])
            self.assertIsNone(summary["max_score"])
            self.assertFalse(summary["validation_required"])
            self.assertEqual(summary["score_semantics"], SYNTHETIC_MEDIA_SCORE_SEMANTICS)

    def test_export_reviewed_items_includes_synthetic_media_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            database = self._database_with_case(tmp_dir)
            insert_artifact(
                database,
                case_id="CASE-SM",
                citation_id="CASE-SM-ART-000001",
                artifact_type="synthetic-media-image",
                title="synthetic-media-image: suspect.png",
                summary="high-band scan",
                row=synthetic_media_row(),
            )

            payload = database.export_reviewed_items(case_id="CASE-SM", include_all=True)

            summary = payload["synthetic_media_summary"]
            self.assertEqual(summary["artifact_count"], 1)
            self.assertEqual(summary["scanned_file_count"], 1)
            self.assertEqual(summary["high_band_count"], 1)
            self.assertEqual(summary["score_semantics"], SYNTHETIC_MEDIA_SCORE_SEMANTICS)
            self.assertIn("not an authenticity verdict", summary["score_guidance"])
            self.assertFalse(summary["commercial_claim_allowed"])
            self.assertEqual(payload["summary"]["synthetic_media_artifact_count"], 1)
            self.assertEqual(payload["summary"]["synthetic_media_high_band_count"], 1)
            self.assertEqual(payload["summary"]["synthetic_media_scan_error_count"], 0)
            package = payload["report_generation_package"]
            self.assertEqual(package["synthetic_media_summary"]["summary_hash"], summary["summary_hash"])
            self.assertIn("## Synthetic-Media Summary", package["markdown_document"])
            self.assertIn(SYNTHETIC_MEDIA_SCORE_SEMANTICS, package["markdown_document"])


if __name__ == "__main__":
    unittest.main()
