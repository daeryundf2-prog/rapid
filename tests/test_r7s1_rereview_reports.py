"""R7 S1 re-review R-4 (server half): submission manifest written once per request, read back from
``/submission-manifest/saved``; ``POST /case-report`` lists every file it wrote."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

try:
    import fastapi  # noqa: F401

    HAS_FASTAPI = True
except ImportError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

from rapidtriage.core.jobs import RunJobStore


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for API tests")
class ReportWritesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from tests.test_rapidtriage_api import api_test_client
        from tests.test_rapidtriage_run import build_run_fixture

        cls.temp = tempfile.TemporaryDirectory()
        base = Path(cls.temp.name)
        root = base / "case-root"
        cls.output_dir = base / "run-out"
        root.mkdir(parents=True)
        build_run_fixture(root)
        cls.client = api_test_client(RunJobStore())
        response = cls.client.post(
            "/api/runs", json={"root": str(root), "mode": "fraud", "output_dir": str(cls.output_dir), "read_only": True, "wait": True}
        )
        assert response.status_code in (200, 201, 202), response.text
        cls.run_id = response.json()["run_id"]
        bookmark = cls.client.post(
            f"/api/runs/{cls.run_id}/bookmarks",
            json={"source": "files", "pointer": "/candidates/0", "review_status": "relevant", "include_in_report": True},
        )
        assert bookmark.status_code == 200, bookmark.text

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def test_submission_manifest_is_written_once_and_read_from_saved(self) -> None:
        manifest_path = self.output_dir / "rapidtriage-submission-manifest.json"
        audit_path = self.output_dir / "rapidtriage-submission-manifest.audit.json"
        for path in (manifest_path, audit_path):
            path.unlink(missing_ok=True)
        missing = self.client.get(f"/api/runs/{self.run_id}/submission-manifest/saved")
        self.assertEqual(missing.status_code, 404)
        self.assertIn("저장된 제출 매니페스트", missing.json()["detail"])

        written = self.client.post(f"/api/runs/{self.run_id}/submission-manifest", params={"max_items": 100})
        self.assertEqual(written.status_code, 200, written.text)
        body = written.json()
        self.assertEqual(body["written"], [str(manifest_path), str(audit_path)])
        self.assertEqual(body["download_url"], f"/api/runs/{self.run_id}/submission-manifest/saved")
        self.assertEqual(body["manifest"]["command"], "submission-manifest")
        stamps = {path: (path.stat().st_mtime_ns, path.read_bytes()) for path in (manifest_path, audit_path)}

        for _ in range(2):
            saved = self.client.get(body["download_url"])
            self.assertEqual(saved.status_code, 200)
            self.assertEqual(saved.content, stamps[manifest_path][1])
        # Reading the saved manifest never rewrites it or its audit record.
        self.assertEqual({path: (path.stat().st_mtime_ns, path.read_bytes()) for path in stamps}, stamps)

    def test_case_report_lists_every_written_file(self) -> None:
        response = self.client.post(f"/api/runs/{self.run_id}/case-report", json={"title": "R-4"})
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        formats = [item["format"] for item in body["written_files"]]
        self.assertEqual(formats, ["md", "html", "docx", "pdf", "manifest", "audit"])
        self.assertEqual(body["written"], [item["path"] for item in body["written_files"]])
        self.assertEqual(body["written"][-1], body["audit"])
        for item in body["written_files"]:
            self.assertTrue(Path(item["path"]).is_file(), item)
        self.assertEqual(body["written_files"][1]["download_url"], f"/api/runs/{self.run_id}/case-report/file/html")
        self.assertIsNone(body["written_files"][-1]["download_url"])


if __name__ == "__main__":
    unittest.main()
