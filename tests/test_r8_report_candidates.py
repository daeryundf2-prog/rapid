"""R8 RI-02: one report-candidate count for review counts, case report, manifest and reviewer bundle.

``GET /review-counts`` read a top-level ``include_in_report`` key that case-JSON bookmarks never
carry (``review.include_in_report``), so a bookmark marked for the report was counted 0 there and 1
in the report. All four surfaces now count with ``core.report_candidates.is_report_candidate``
over the same merged review payload, and caps are named instead of silently dropping rows.
"""

from __future__ import annotations

import json
import re
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from rapidtriage.api.app import create_app, review_payload
from rapidtriage.core.jobs import RunJobStore
from rapidtriage.core.sample_case import build_sample_evidence

TOKEN = "r8-candidates-token"


class ReportCandidateCountTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        base = Path(cls._tmp.name)
        evidence = base / "evidence"
        build_sample_evidence(evidence)
        cls.store = RunJobStore()
        cls.client = TestClient(create_app(cls.store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})
        response = cls.client.post(
            "/api/runs",
            json={"root": str(evidence), "mode": "fraud", "output_dir": str(base / "out"), "read_only": True, "wait": True},
        )
        assert response.status_code == 202, response.text
        cls.run_id = response.json()["run_id"]
        run = cls.client.get(f"/api/runs/{cls.run_id}").json()
        cls.output_dir = Path(run["summary"]["output_dir"])
        # Case JSON: 2 bookmarks, 1 marked for the report (``review.include_in_report``).
        for pointer, include in (("/candidates/0", True), ("/candidates/1", False)):
            marked = cls.client.post(
                f"/api/runs/{cls.run_id}/bookmarks",
                json={"source": "files", "pointer": pointer, "include_in_report": include, "review_status": "relevant"},
            )
            assert marked.status_code == 200, marked.text
        # Case DB: 3 marks, 2 marked for the report.
        ensure = cls.client.post(f"/api/runs/{cls.run_id}/case-db/ensure", json={})
        assert ensure.status_code == 200, ensure.text
        cls.database, cls.case_id = ensure.json()["database"], ensure.json()["case_id"]
        for target_id, include in (("a", True), ("b", True), ("c", False)):
            response = cls.client.post(
                "/api/case-db/review",
                json={
                    "database": cls.database,
                    "case_id": cls.case_id,
                    "target_type": "document",
                    "target_id": target_id,
                    "status": "relevant",
                    "include_in_report": include,
                },
            )
            assert response.status_code == 200, response.text

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.close()
        cls._tmp.cleanup()

    def test_all_surfaces_agree(self) -> None:
        counts = self.client.get(f"/api/runs/{self.run_id}/review-counts").json()
        self.assertEqual(counts["report_candidates"], 3)  # was 2: the JSON bookmark was never counted
        self.assertEqual(counts["case_json"]["include_in_report"], 1)
        self.assertEqual(counts["report_candidates_detail"]["case_db"], 2)
        self.assertFalse(counts["truncated"])
        self.assertIsNone(counts["error"])

        manifest = self.client.get(f"/api/runs/{self.run_id}/submission-manifest").json()
        self.assertEqual(manifest["summary"]["report_candidate_count"], 3)
        self.assertEqual(manifest["summary"]["hashed_item_count"] + manifest["summary"]["skipped_count"], 3)
        self.assertFalse(manifest["summary"]["truncated"])

        report = self.client.post(f"/api/runs/{self.run_id}/case-report", json={})
        self.assertEqual(report.status_code, 200, report.text)
        self.assertIn("- 보고서 포함 후보 수: 3", report.json()["markdown"])
        korean = self.client.post(f"/api/runs/{self.run_id}/case-report", json={"template": "korean-expert"})
        self.assertEqual(korean.status_code, 200, korean.text)
        self.assertIn("- 보고서 포함 항목 수: 3", korean.json()["markdown"])

        bundle = self.client.post(f"/api/runs/{self.run_id}/reviewer-bundle", json={})
        self.assertEqual(bundle.status_code, 200, bundle.text)
        with zipfile.ZipFile(self.output_dir / "rapidtriage-reviewer-bundle.zip") as archive:
            bundled = json.loads(archive.read("rapidtriage-submission-manifest.json"))
            bundled_report = archive.read("rapidtriage-case-report.md").decode("utf-8")
        self.assertEqual(bundled["summary"]["report_candidate_count"], 3)
        self.assertIn("- 보고서 포함 후보 수: 3", bundled_report)

    def test_max_items_cap_is_named(self) -> None:
        manifest = self.client.get(f"/api/runs/{self.run_id}/submission-manifest", params={"max_items": 1}).json()
        self.assertTrue(manifest["summary"]["truncated"])
        self.assertEqual(manifest["summary"]["max_items_skipped_count"], 2)
        report = self.client.post(f"/api/runs/{self.run_id}/case-report", json={"max_items": 1}).json()["markdown"]
        self.assertRegex(report, re.compile(r"보고서 포함 후보 3건 중 1건만 해시 산출함"))

    def test_mark_cap_is_named_not_dropped(self) -> None:
        with patch.object(review_payload, "MAX_CASE_DB_MARKS", 2):
            counts = self.client.get(f"/api/runs/{self.run_id}/review-counts").json()
            self.assertTrue(counts["truncated"])
            self.assertEqual(counts["report_candidates_detail"]["case_db_marks_total"], 3)
            report = self.client.post(f"/api/runs/{self.run_id}/case-report", json={}).json()["markdown"]
            self.assertIn("케이스 DB 표시 3건 중 최근 2건만 반영함", report)
            match = re.search(r"- 보고서 포함 후보 수: (\d+)", report)
            self.assertIsNotNone(match)
            self.assertEqual(int(match.group(1)), counts["report_candidates"])

    def test_unreadable_case_db_is_an_error_not_zero(self) -> None:
        def broken(_summary, _run_id):
            return review_payload.CaseDbMarks(error="database disk image is malformed")

        with patch.object(review_payload, "case_db_mark_flags", broken):
            counts = self.client.get(f"/api/runs/{self.run_id}/review-counts").json()
        self.assertIsNone(counts["report_candidates"])
        self.assertEqual(counts["error"]["code"], "CASE_DB_UNREADABLE")
        self.assertIn("케이스 DB", counts["error"]["message"])


if __name__ == "__main__":
    unittest.main()
