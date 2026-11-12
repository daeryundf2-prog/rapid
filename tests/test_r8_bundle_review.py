"""R8 T-028: validation package and reviewer bundle reflect case-DB review; case DB is an audit input.

The console writes marks into the run's case DB (``review_mark``); the validation package's review
status read only the bookmark JSON, so a run reviewed only in the console said "case review file has
not been created" with 0 items. It now reads the same merged review payload (and the one
report-candidate rule) as review counts, manifest, report and bundle. The bundle report gets the run
summary (processing section no longer blank), and the three export audits list the case DB.
"""

from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient

from rapidtriage.api.app import create_app
from rapidtriage.core.jobs import RunJobStore
from rapidtriage.core.sample_case import build_sample_evidence
from rapidtriage.core.submission import compute_hashes

TOKEN = "r8-bundle-review-token"


class CaseDbOnlyReviewTests(unittest.TestCase):
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
        ensure = cls.client.post(f"/api/runs/{cls.run_id}/case-db/ensure", json={})
        assert ensure.status_code == 200, ensure.text
        cls.database, cls.case_id = ensure.json()["database"], ensure.json()["case_id"]
        # Case DB only: 3 marks, 2 marked for the report; no bookmark JSON.
        for target_id, status, include in (("a", "relevant", True), ("b", "relevant", True), ("c", "needs-review", False)):
            marked = cls.client.post(
                "/api/case-db/review",
                json={
                    "database": cls.database,
                    "case_id": cls.case_id,
                    "target_type": "document",
                    "target_id": target_id,
                    "status": status,
                    "include_in_report": include,
                },
            )
            assert marked.status_code == 200, marked.text
        assert not (cls.output_dir / "rapidtriage-case.json").exists()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.close()
        cls._tmp.cleanup()

    def review_counts(self) -> dict[str, object]:
        response = self.client.get(f"/api/runs/{self.run_id}/review-counts")
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_validation_package_counts_case_db_marks(self) -> None:
        counts = self.review_counts()
        self.assertEqual(counts["report_candidates"], 2)
        package = self.client.get(f"/api/runs/{self.run_id}/validation-package").json()
        status = package["review_status"]
        self.assertTrue(status["exists"])
        self.assertTrue(status["case_db_exists"])
        self.assertFalse(status["case_json_exists"])
        self.assertEqual(status["bookmark_count"], 3)
        self.assertEqual(status["report_item_count"], counts["report_candidates"])
        self.assertEqual(status["store_counts"], {"case_json": 0, "case_db": 3})
        self.assertEqual(status["review_status_counts"]["relevant"], 2)
        self.assertEqual(status["review_status_counts"]["needs-review"], 1)
        self.assertEqual(len(status["bookmark_ids"]), 3)
        self.assertTrue(all(bookmark_id.startswith("case-db:") for bookmark_id in status["bookmark_ids"]))
        self.assertEqual(status["limitations"], [])
        text = json.dumps(package, ensure_ascii=False)
        self.assertNotIn("case review file has not been created", text)
        self.assertNotIn("검토 표시가 없습니다", text)

    def test_validation_package_audit_lists_case_db(self) -> None:
        written = self.client.post(f"/api/runs/{self.run_id}/validation-package")
        self.assertEqual(written.status_code, 200, written.text)
        audit = json.loads(Path(written.json()["audit"]).read_text(encoding="utf-8"))
        inputs = {item["label"]: item for item in audit["provenance"]["input_files"]}
        self.assertIn("case-db", inputs)
        database = Path(self.database)
        self.assertEqual(Path(inputs["case-db"]["path"]).resolve(), database.resolve())
        self.assertEqual(json.dumps(inputs["case-db"]).count(compute_hashes(database)["sha256"]), 1)
        saved = json.loads(Path(written.json()["package_path"]).read_text(encoding="utf-8"))
        self.assertEqual(saved["review_status"]["report_item_count"], 2)

    def test_report_and_manifest_audits_list_case_db(self) -> None:
        report = self.client.post(f"/api/runs/{self.run_id}/case-report", json={})
        self.assertEqual(report.status_code, 200, report.text)
        manifest = self.client.post(f"/api/runs/{self.run_id}/submission-manifest")
        self.assertEqual(manifest.status_code, 200, manifest.text)
        for audit_path in (Path(report.json()["audit"]), Path(manifest.json()["audit"])):
            audit = json.loads(audit_path.read_text(encoding="utf-8"))
            labels = [item["label"] for item in audit["provenance"]["input_files"]]
            self.assertIn("case-db", labels, audit_path)
            row = next(item for item in audit["provenance"]["input_files"] if item["label"] == "case-db")
            self.assertIn(compute_hashes(Path(self.database))["sha256"], json.dumps(row))

    def test_reviewer_bundle_reflects_case_db_marks_and_run_summary(self) -> None:
        counts = self.review_counts()
        bundle = self.client.post(f"/api/runs/{self.run_id}/reviewer-bundle", json={})
        self.assertEqual(bundle.status_code, 200, bundle.text)
        with zipfile.ZipFile(self.output_dir / "rapidtriage-reviewer-bundle.zip") as archive:
            manifest = json.loads(archive.read("rapidtriage-submission-manifest.json"))
            report = archive.read("rapidtriage-case-report.md").decode("utf-8")
            reviewer = archive.read("rapidtriage-reviewer.html").decode("utf-8")
        self.assertEqual(manifest["summary"]["report_candidate_count"], counts["report_candidates"])
        self.assertIn(f"- 보고서 포함 후보 수: {counts['report_candidates']}", report)
        # Processing section filled from the run summary (was blank: run_summary={}).
        self.assertIn("- 분석 모드: `fraud`", report)
        self.assertNotIn("- 분석 모드: ``", report)
        self.assertNotIn("- 산출물 디렉터리: ``", report)
        # The reviewer page's report draft carries the same counts (synthetic marks have no source
        # path, so they are listed as hash-skipped rather than as selected evidence rows).
        self.assertIn(f"- 보고서 포함 후보 수: {counts['report_candidates']}", reviewer)
        self.assertIn("- 검토 항목 수: 3", reviewer)


if __name__ == "__main__":
    unittest.main()
