from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from rapidtriage.api.app import create_app
from rapidtriage.cli import build_web_parser
from rapidtriage.core.jobs import RunJobStore
from tests.schema_validation import validate
from tests.test_rapidtriage_run import build_run_fixture

REPO_ROOT = Path(__file__).resolve().parent.parent


def hash_file(path: Path, algorithm: str) -> str:
    hasher = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


class RapidTriageApiTests(unittest.TestCase):
    def test_web_entrypoint_parser_supports_direct_launch_options(self) -> None:
        args = build_web_parser().parse_args(["--host", "0.0.0.0", "--port", "9000"])

        self.assertEqual(args.host, "0.0.0.0")
        self.assertEqual(args.port, 9000)
        self.assertEqual(args.reload, False)

    def test_health_and_index_are_available(self) -> None:
        client = TestClient(create_app(RunJobStore()))

        self.assertEqual(client.get("/api/health").json(), {"status": "ok"})
        index_response = client.get("/")

        self.assertEqual(index_response.status_code, 200)
        self.assertIn("rapidtriage", index_response.text)

    def test_create_run_waits_and_exposes_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)
            client = TestClient(create_app(RunJobStore()))

            response = client.post(
                "/api/runs",
                json={
                    "root": str(root),
                    "mode": "fraud",
                    "output_dir": str(output_dir),
                    "read_only": True,
                    "wait": True,
                },
            )

            self.assertEqual(response.status_code, 202, response.text)
            run_payload = response.json()
            self.assertEqual(run_payload["status"], "completed")
            self.assertEqual(run_payload["summary"]["mode"], "fraud")

            run_id = run_payload["run_id"]
            summary_response = client.get(f"/api/runs/{run_id}/summary")
            files_response = client.get(f"/api/runs/{run_id}/files")
            timeline_response = client.get(f"/api/runs/{run_id}/timeline")
            search_response = client.get(f"/api/runs/{run_id}/search", params={"keyword": "password", "ocr": "false"})

            self.assertEqual(summary_response.status_code, 200)
            self.assertEqual(files_response.status_code, 200)
            self.assertEqual(timeline_response.status_code, 200)
            self.assertEqual(search_response.status_code, 200)
            self.assertEqual(files_response.json()["command"], "files")
            self.assertEqual(timeline_response.json()["command"], "timeline")
            self.assertEqual(search_response.json()["command"], "search")
            self.assertGreaterEqual(search_response.json()["summary"]["match_count"], 1)
            document_match = next(
                item
                for item in search_response.json()["matches"]
                if item["source"] == "documents" and item["path"].endswith(".txt")
            )
            self.assertIn("metadata", document_match)
            source_response = client.get(f"/api/runs/{run_id}/source-file", params={"path": document_match["path"]})
            self.assertEqual(source_response.status_code, 200)
            self.assertIn("password", source_response.text)
            preview_response = client.get(f"/api/runs/{run_id}/source-preview", params={"path": document_match["path"]})
            self.assertEqual(preview_response.status_code, 200)
            self.assertEqual(preview_response.json()["preview_type"], "text")
            self.assertIn("password", preview_response.json()["text"])
            file_search_response = client.get(
                f"/api/runs/{run_id}/source-search",
                params={"path": document_match["path"], "keyword": "password"},
            )
            self.assertEqual(file_search_response.status_code, 200)
            file_search_payload = file_search_response.json()
            self.assertEqual(file_search_payload["command"], "source-search")
            self.assertEqual(file_search_payload["summary"]["match_count"], 1)
            self.assertEqual(file_search_payload["matches"][0]["keyword"], "password")
            self.assertIn("password", file_search_payload["matches"][0]["snippet"].lower())
            paged_files_response = client.get(f"/api/runs/{run_id}/files", params={"offset": 1, "limit": 2})
            self.assertEqual(paged_files_response.status_code, 200)
            paged_files = paged_files_response.json()
            self.assertEqual(paged_files["pagination"]["collection"], "candidates")
            self.assertEqual(paged_files["pagination"]["offset"], 1)
            self.assertEqual(paged_files["pagination"]["limit"], 2)
            self.assertEqual(len(paged_files["candidates"]), 2)
            self.assertGreaterEqual(paged_files["pagination"]["total"], 2)
            paged_docs_response = client.get(f"/api/runs/{run_id}/docs", params={"offset": 0, "limit": 1})
            self.assertEqual(paged_docs_response.status_code, 200)
            paged_docs = paged_docs_response.json()
            self.assertEqual(paged_docs["pagination"]["collection"], "results")
            self.assertLessEqual(len(paged_docs["results"]), 1)
            self.assertIn("candidates", paged_docs["omitted_fields"])
            self.assertTrue((output_dir / "rapidtriage-run-summary.json").is_file())

            persisted = json.loads((output_dir / "rapidtriage-run-summary.json").read_text(encoding="utf-8"))
            self.assertEqual(persisted["mode"], "fraud")

            report_response = client.get(f"/api/runs/{run_id}/report")
            artifacts_response = client.get(f"/api/runs/{run_id}/artifacts")
            paged_artifacts_response = client.get(f"/api/runs/{run_id}/artifacts", params={"offset": 0, "limit": 1})

            self.assertEqual(report_response.status_code, 200)
            self.assertIn("rapidtriage run report", report_response.text)
            self.assertEqual(artifacts_response.status_code, 200)
            self.assertIn("artifacts", artifacts_response.json())
            self.assertEqual(paged_artifacts_response.status_code, 200)
            paged_artifacts = paged_artifacts_response.json()["artifacts"]
            first_artifact_group = next(iter(paged_artifacts.values()))
            self.assertEqual(first_artifact_group["pagination"]["collection"], "artifacts")
            self.assertLessEqual(len(first_artifact_group["artifacts"]), 1)

    def test_bookmark_api_writes_run_case_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)
            client = TestClient(create_app(RunJobStore()))

            run_response = client.post(
                "/api/runs",
                json={
                    "root": str(root),
                    "mode": "fraud",
                    "output_dir": str(output_dir),
                    "read_only": True,
                    "wait": True,
                },
            )
            run_id = run_response.json()["run_id"]

            bookmark_response = client.post(
                f"/api/runs/{run_id}/bookmarks",
                json={
                    "source": "files",
                    "pointer": "/candidates/0",
                    "tag": "review",
                    "tags": ["credential", "report"],
                    "note": "Check this file.",
                    "review_status": "relevant",
                    "include_in_report": True,
                },
            )

            self.assertEqual(bookmark_response.status_code, 200, bookmark_response.text)
            case_path = output_dir / "rapidtriage-case.json"
            self.assertTrue(case_path.is_file())

            case_response = client.get(f"/api/runs/{run_id}/case")
            self.assertEqual(case_response.status_code, 200)
            payload = case_response.json()
            self.assertEqual(payload["exists"], True)
            self.assertEqual(payload["case"]["summary"]["bookmark_count"], 1)
            self.assertEqual(payload["case"]["summary"]["report_item_count"], 1)
            self.assertEqual(payload["case"]["summary"]["review_status_counts"]["relevant"], 1)
            self.assertEqual(payload["case"]["summary"]["review_revision_count"], 1)
            self.assertEqual(payload["case"]["bookmarks"][0]["tags"], ["review", "credential", "report"])
            self.assertEqual(payload["case"]["bookmarks"][0]["review"]["status"], "relevant")
            self.assertEqual(payload["case"]["bookmarks"][0]["review"]["include_in_report"], True)
            self.assertEqual(payload["case"]["bookmarks"][0]["review_history"][0]["action"], "created")

            manifest_response = client.get(f"/api/runs/{run_id}/submission-manifest")
            self.assertEqual(manifest_response.status_code, 200, manifest_response.text)
            manifest = manifest_response.json()
            self.assertEqual(manifest["command"], "submission-manifest")
            validate(
                manifest,
                json.loads((REPO_ROOT / "rapidtriage" / "schemas" / "submission-manifest.schema.json").read_text(encoding="utf-8")),
            )
            self.assertEqual(manifest["summary"]["hashed_item_count"], 1)
            self.assertEqual(manifest["hash_algorithms"], ["md5", "sha1", "sha256"])
            evidence = manifest["items"][0]["evidence"]
            evidence_path = Path(evidence["path"])
            self.assertEqual(evidence["hashes"]["md5"], hash_file(evidence_path, "md5"))
            self.assertEqual(evidence["hashes"]["sha1"], hash_file(evidence_path, "sha1"))
            self.assertEqual(evidence["hashes"]["sha256"], hash_file(evidence_path, "sha256"))
            self.assertTrue((output_dir / "rapidtriage-submission-manifest.json").is_file())
            self.assertTrue((output_dir / "rapidtriage-submission-manifest.audit.json").is_file())

            manifest_file_response = client.get(f"/api/runs/{run_id}/submission-manifest/file")
            self.assertEqual(manifest_file_response.status_code, 200)
            self.assertIn("submission-manifest", manifest_file_response.text)

            report_response = client.post(
                f"/api/runs/{run_id}/case-report",
                json={
                    "title": "Incident report",
                    "case_number": "CASE-001",
                    "investigator": "Analyst A",
                    "organization": "Forensic Lab",
                    "requester": "Legal Team",
                    "scope": "Review report-candidate evidence and hashes.",
                    "conclusion": "The listed evidence was reviewed and hashed.",
                },
            )
            self.assertEqual(report_response.status_code, 200, report_response.text)
            report_payload = report_response.json()
            self.assertIn("디지털 포렌식 분석 보고서", report_payload["markdown"])
            self.assertIn("CASE-001", report_payload["markdown"])
            self.assertIn(evidence["hashes"]["sha256"], report_payload["markdown"])
            self.assertTrue((output_dir / "rapidtriage-case-report.md").is_file())
            self.assertTrue((output_dir / "rapidtriage-case-report.audit.md").is_file())

            report_file_response = client.get(f"/api/runs/{run_id}/case-report/file")
            self.assertEqual(report_file_response.status_code, 200)
            self.assertIn("디지털 포렌식 분석 보고서", report_file_response.text)

    def test_run_catalog_persists_and_imports_existing_output_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            root = tmp_path / "case-root"
            output_dir = tmp_path / "run-out"
            state_path = tmp_path / "state" / "runs.json"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)

            store = RunJobStore(state_path=state_path)
            client = TestClient(create_app(store))
            run_response = client.post(
                "/api/runs",
                json={
                    "root": str(root),
                    "mode": "fraud",
                    "output_dir": str(output_dir),
                    "read_only": True,
                    "wait": True,
                },
            )
            run_id = run_response.json()["run_id"]

            restored_client = TestClient(create_app(RunJobStore(state_path=state_path)))
            restored_response = restored_client.get(f"/api/runs/{run_id}")

            self.assertEqual(restored_response.status_code, 200)
            self.assertEqual(restored_response.json()["status"], "completed")

            import_response = restored_client.post("/api/runs/import", json={"output_dir": str(output_dir)})
            self.assertEqual(import_response.status_code, 201, import_response.text)
            self.assertEqual(import_response.json()["status"], "completed")
            self.assertEqual(import_response.json()["origin"], "imported")

            output_files_response = restored_client.get(f"/api/runs/{run_id}/output-files")
            self.assertEqual(output_files_response.status_code, 200)
            names = {item["name"] for item in output_files_response.json()["files"]}
            self.assertIn("report", names)
            self.assertIn("summary", names)

            report_download = restored_client.get(f"/api/runs/{run_id}/outputs/report/file")
            self.assertEqual(report_download.status_code, 200)
            self.assertIn("rapidtriage run report", report_download.text)

            delete_response = restored_client.delete(f"/api/runs/{run_id}")
            self.assertEqual(delete_response.status_code, 204)
            self.assertEqual(restored_client.get(f"/api/runs/{run_id}").status_code, 404)

    def test_case_db_api_imports_searches_and_marks_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            db_path = Path(tmp_dir) / "case.db"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)
            client = TestClient(create_app(RunJobStore()))

            run_response = client.post(
                "/api/runs",
                json={
                    "root": str(root),
                    "mode": "fraud",
                    "output_dir": str(output_dir),
                    "read_only": True,
                    "wait": True,
                },
            )
            self.assertEqual(run_response.status_code, 202, run_response.text)

            import_response = client.post(
                "/api/case-db/import-run",
                json={
                    "database": str(db_path),
                    "run_output": str(output_dir),
                    "case_id": "CASE-API-DB",
                    "name": "API Case DB",
                },
            )
            self.assertEqual(import_response.status_code, 200, import_response.text)
            self.assertGreaterEqual(import_response.json()["summary"]["indexed_document_count"], 1)

            search_response = client.post(
                "/api/case-db/search",
                json={
                    "database": str(db_path),
                    "case_id": "CASE-API-DB",
                    "keywords": ["password"],
                    "sources": ["documents"],
                },
            )
            self.assertEqual(search_response.status_code, 200, search_response.text)
            search_payload = search_response.json()
            self.assertGreaterEqual(search_payload["summary"]["match_count"], 1)
            target = search_payload["matches"][0]

            review_response = client.post(
                "/api/case-db/review",
                json={
                    "database": str(db_path),
                    "case_id": "CASE-API-DB",
                    "target_type": target["target_type"],
                    "target_id": target["target_id"],
                    "status": "relevant",
                    "verification_status": "source_opened",
                    "tags": ["credential"],
                    "note": "Opened in viewer.",
                    "reviewer": "api-test",
                    "include_in_report": True,
                },
            )
            self.assertEqual(review_response.status_code, 200, review_response.text)
            self.assertEqual(review_response.json()["verification_status"], "source_opened")

            filtered_response = client.post(
                "/api/case-db/search",
                json={
                    "database": str(db_path),
                    "case_id": "CASE-API-DB",
                    "keywords": ["password"],
                    "sources": ["documents"],
                    "verification_status": "source_opened",
                },
            )
            self.assertEqual(filtered_response.status_code, 200, filtered_response.text)
            filtered_payload = filtered_response.json()
            self.assertGreaterEqual(filtered_payload["summary"]["match_count"], 1)
            self.assertEqual(filtered_payload["matches"][0]["review"]["status"], "relevant")

    def test_imported_summary_cannot_expose_files_outside_output_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            output_dir = tmp_path / "run-out"
            output_dir.mkdir()
            outside_file = tmp_path / "outside.txt"
            outside_file.write_text("do not expose", encoding="utf-8")
            summary_path = output_dir / "rapidtriage-run-summary.json"
            summary_path.write_text(
                json.dumps(
                    {
                        "mode": "fraud",
                        "root": str(tmp_path / "case-root"),
                        "output_dir": str(output_dir),
                        "input_kind": "folder",
                        "summary": {},
                        "outputs": {
                            "summary": str(summary_path),
                            "report": str(outside_file),
                        },
                    }
                ),
                encoding="utf-8",
            )

            client = TestClient(create_app(RunJobStore()))
            import_response = client.post("/api/runs/import", json={"output_dir": str(output_dir)})
            self.assertEqual(import_response.status_code, 201, import_response.text)
            run_id = import_response.json()["run_id"]

            report_response = client.get(f"/api/runs/{run_id}/outputs/report/file")
            self.assertEqual(report_response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
