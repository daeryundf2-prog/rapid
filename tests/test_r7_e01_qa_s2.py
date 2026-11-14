"""E01 QA S2 regressions (fix/r7-e01-qa-s2).

D2 reviewer bundle from case DB marks; further defects append below.
"""

from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from rapidtriage.core.jobs import RunJobStore
from tests import quiet_media_checks
from tests.test_rapidtriage_api import api_test_client
from tests.test_rapidtriage_run import build_run_fixture

setUpModule = quiet_media_checks.setUpModule
tearDownModule = quiet_media_checks.tearDownModule


def _finished_run(client, tmp_dir: str) -> tuple[str, Path]:
    root = Path(tmp_dir) / "case-root"
    output_dir = Path(tmp_dir) / "run-out"
    root.mkdir(parents=True, exist_ok=True)
    build_run_fixture(root)
    response = client.post(
        "/api/runs",
        json={"root": str(root), "mode": "fraud", "output_dir": str(output_dir), "read_only": True, "wait": True},
    )
    assert response.status_code == 202, response.text
    return response.json()["run_id"], output_dir


class ReviewerBundleFromCaseDbTests(unittest.TestCase):
    """D2: console marks/tags (case DB) feed the reviewer bundle; no case JSON needed."""

    def test_empty_review_is_a_korean_404(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            client = api_test_client(RunJobStore(), case_db_roots=[tmp_dir])
            run_id, output_dir = _finished_run(client, tmp_dir)
            response = client.post(f"/api/runs/{run_id}/reviewer-bundle", json={})
            self.assertEqual(response.status_code, 404)
            detail = response.json()["detail"]
            self.assertIn("검토 항목이 없습니다", detail)
            self.assertNotIn("not found", detail)
            self.assertFalse((output_dir / "rapidtriage-case.json").exists())

    def test_bundle_builds_from_case_db_marks_without_case_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            client = api_test_client(RunJobStore(), case_db_roots=[tmp_dir])
            run_id, output_dir = _finished_run(client, tmp_dir)
            handle = client.post(f"/api/runs/{run_id}/case-db/ensure", json={}).json()
            files = client.get(f"/api/runs/{run_id}/files?offset=0&limit=3").json()["candidates"]
            marked = client.post(
                "/api/case-db/review-batch",
                json={
                    "database": handle["database"],
                    "case_id": handle["case_id"],
                    "run_id": run_id,
                    "targets": [{"collection": "files", "locator": "/candidates/1"}],
                    "status": "relevant",
                    "add_tags": ["북마크"],
                    "include_in_report": True,
                },
            )
            self.assertEqual(marked.status_code, 200, marked.text)
            self.assertFalse((output_dir / "rapidtriage-case.json").exists())

            response = client.post(f"/api/runs/{run_id}/reviewer-bundle", json={"max_items": 50})
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["command"], "bundle")
            # The bookmark JSON store is not created or modified by the export.
            self.assertFalse((output_dir / "rapidtriage-case.json").exists())
            snapshot = json.loads(
                (output_dir / "rapidtriage-reviewer-bundle.review-case.json").read_text(encoding="utf-8")
            )
            self.assertEqual(len(snapshot["bookmarks"]), 1)
            bookmark = snapshot["bookmarks"][0]
            self.assertEqual(bookmark["review"]["status"], "relevant")
            self.assertTrue(bookmark["review"]["include_in_report"])
            self.assertEqual(bookmark["tags"], ["북마크"])
            self.assertEqual(bookmark["reference"]["source_command"], "case-db")
            self.assertTrue(bookmark["snapshot"]["path"].endswith(Path(files[1]["path"]).name))
            with zipfile.ZipFile(output_dir / "rapidtriage-reviewer-bundle.zip") as archive:
                selected = json.loads(archive.read("rapidtriage-selected-evidence.json").decode("utf-8"))
            self.assertIn("items", selected)
            manifest = json.loads(
                (output_dir / "rapidtriage-reviewer-bundle" / "rapidtriage-submission-manifest.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(len(manifest["items"]) + len(manifest["skipped"]), 1)

            download = client.get(f"/api/runs/{run_id}/reviewer-bundle/file")
            self.assertEqual(download.status_code, 200)
            self.assertEqual(download.content[:2], b"PK")


class FailedAnalysisDoesNotStaleIndexTests(unittest.TestCase):
    """D3: an analysis that ended without rows (OCR failed: no tesseract) leaves the index fresh."""

    def test_failed_empty_analysis_is_not_a_stale_reason(self) -> None:
        from rapidtriage.core.search_index.build import (
            build_search_index,
            index_meta,
            stale_reasons,
        )
        from rapidtriage.core.search_index.schema import INDEX_FILE_NAME
        from tests.search_index_fixture import build_fixture_run, write_analysis

        with tempfile.TemporaryDirectory() as tmp_dir:
            fixture = build_fixture_run(Path(tmp_dir))
            run_dir, summary = fixture["run_dir"], fixture["summary"]
            build_search_index(run_dir, summary)
            meta = index_meta(run_dir / INDEX_FILE_NAME)
            write_analysis(run_dir, "20251015T000000-cccccccc", "ocr", [], status="failed")
            self.assertEqual(stale_reasons(meta, summary, run_dir), [])
            # An analysis that did produce rows the index lacks is still a stale reason.
            write_analysis(run_dir, "20251016T000000-dddddddd", "ntfs-meta", [{"artifact_type": "x", "path": "C:\\a"}])
            self.assertIn("색인에 없는 분석 결과가 있습니다(1개)", stale_reasons(meta, summary, run_dir))


class NoEvidenceAdjacentOutputTests(unittest.TestCase):
    """D4: a file evidence never gets a default output folder beside it; D5: output pre-check."""

    def test_quick_run_of_a_file_evidence_needs_an_output_folder(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            image = Path(tmp_dir) / "evidence" / "disk.raw"
            image.parent.mkdir()
            image.write_bytes(b"\0" * 1024)
            client = api_test_client(RunJobStore())
            # The image-support gate (Sleuth Kit present or not) is not what this test is about.
            with patch("rapidtriage.api.app.routes_runs.validate_run_evidence_source"):
                response = client.post("/api/runs", json={"root": str(image), "mode": "fraud", "read_only": True})
            self.assertEqual(response.status_code, 422, response.text)
            self.assertIn("출력 폴더를 지정하세요", response.json()["detail"]["message"])
            self.assertEqual(response.json()["detail"]["code"], "OUTPUT_DIR_REQUIRED")
            self.assertEqual(sorted(p.name for p in image.parent.iterdir()), ["disk.raw"])

    def test_output_check_mirrors_the_server_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            client = api_test_client(RunJobStore())
            ok = client.post("/api/cases/output-check", json={"path": str(Path(tmp_dir) / "out")})
            self.assertEqual(ok.status_code, 200, ok.text)
            self.assertTrue(ok.json()["ok"])
            relative = client.post("/api/cases/output-check", json={"path": "relative/out"}).json()
            self.assertFalse(relative["ok"])
            self.assertIn("출력 폴더", relative["problem"])
            as_case = client.post("/api/cases/output-check", json={"path": "relative/out", "kind": "case_root"}).json()
            self.assertIn("케이스 폴더", as_case["problem"])
            blocker = Path(tmp_dir) / "a-file"
            blocker.write_text("x", encoding="utf-8")
            on_file = client.post("/api/cases/output-check", json={"path": str(blocker)}).json()
            self.assertFalse(on_file["ok"])
            self.assertIn("파일이 있습니다", on_file["problem"])
            # The pre-check never creates a case.
            self.assertEqual(client.get("/api/cases").json().get("cases", []), [])


class MftTimelineTargetTests(unittest.TestCase):
    """D6: MFT record events name the file (target) and read in Korean, not "mft-record $MFT"."""

    def _events(self, details: dict[str, object]) -> list[dict[str, object]]:
        from rapidtriage.core.timeline import extract_artifact_events

        payload = {
            "command": "artifacts",
            "kind": "windows-filesystem",
            "artifacts": [
                {
                    "provider": "windows-filesystem",
                    "artifact_type": "mft-record",
                    "path": "C:\\stage\\$MFT",
                    "supported": True,
                    "details": details,
                }
            ],
        }
        return extract_artifact_events(payload, Path("artifacts.json"))

    def test_events_carry_the_record_file_path_and_a_korean_summary(self) -> None:
        details = {
            "record_number": "42",
            "file_path": "\\Users\\kim\\Documents\\report.docx",
            "attributes": [
                {"standard_information": {"timestamps": {"created_at": "2025-01-02T03:04:05+00:00", "modified_at": "2025-01-03T03:04:05+00:00"}}},
                {"file_name": {"timestamps": {"created_at": "2025-01-02T03:04:05+00:00"}}},
            ],
        }
        events = self._events(details)
        self.assertTrue(events)
        by_kind = {event["timestamp_kind"]: event for event in events}
        created = by_kind["si-created"]
        self.assertEqual(created["summary"], "파일 생성(SI): \\Users\\kim\\Documents\\report.docx")
        self.assertEqual(created["details"]["target_path"], "\\Users\\kim\\Documents\\report.docx")
        # The $MFT stays the event path (출처 행) and the event type keeps its stable id.
        self.assertEqual(created["path"], "C:\\stage\\$MFT")
        self.assertEqual(created["event_type"], "artifact-mft-record-si-created")
        self.assertEqual(by_kind["si-modified"]["summary"].split(":")[0], "파일 수정(SI)")
        for event in events:
            self.assertNotIn("mft-record $MFT", event["summary"])

    def test_without_a_path_the_file_name_or_record_number_is_used(self) -> None:
        attributes = [{"standard_information": {"timestamps": {"created_at": "2025-01-02T03:04:05+00:00"}}}]
        named = self._events({"record_number": "7", "file_name_entries": [{"file_name": "a.txt"}], "attributes": attributes})
        self.assertEqual(named[0]["summary"], "파일 생성(SI): a.txt")
        bare = self._events({"record_number": "7", "attributes": attributes})
        self.assertEqual(bare[0]["summary"], "파일 생성(SI): MFT 레코드 #7")
        self.assertNotIn("target_path", bare[0]["details"])


class NativeDeletedSweepTests(unittest.TestCase):
    """D18: files the native E01 engine recovered from unallocated MFT records are flagged deleted."""

    def test_deleted_mft_sweep_rows_are_deleted_and_counted_irregular(self) -> None:
        from rapidtriage.core.files import run_files_scan
        from rapidtriage.core.irregular import files_categories

        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "stage" / "fs"
            (root / "_deleted_mft").mkdir(parents=True)
            (root / "Users" / "kim").mkdir(parents=True)
            (root / "_deleted_mft" / "37-report.docx").write_bytes(b"PK\x03\x04deleted docx body")
            (root / "_deleted_mft" / "38-notes.txt").write_text("deleted notes", encoding="utf-8")
            (root / "Users" / "kim" / "live.txt").write_text("live", encoding="utf-8")
            payload = run_files_scan(root, input_kind="e01-derived", categories=["documents", "other"], inventory_all_files=True)
            rows = {Path(str(row["path"])).name: row for row in [*payload["candidates"], *payload.get("inventory", [])]}
            deleted = rows["37-report.docx"]
            self.assertIs(deleted["is_deleted"], True)
            self.assertEqual(deleted.get("deletion_state") or deleted["recovery"]["deletion_state"], "deleted")
            self.assertEqual(deleted["recovery"]["candidate_kind"], "deleted-entry")
            self.assertEqual(deleted["recovery"]["source_record_id"], "37")
            self.assertIn("deleted", files_categories(deleted, None))
            self.assertIs(rows["38-notes.txt"]["is_deleted"], True)
            # An allocated-tree file of the same extraction keeps its (unknown) state.
            self.assertIsNot(rows["live.txt"].get("is_deleted"), True)
            self.assertNotIn("deleted", files_categories(rows["live.txt"], None))

    def test_a_plain_folder_named_deleted_mft_is_not_flagged(self) -> None:
        from rapidtriage.core.files import run_files_scan

        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "evidence"
            (root / "_deleted_mft").mkdir(parents=True)
            (root / "_deleted_mft" / "1-a.txt").write_text("x", encoding="utf-8")
            payload = run_files_scan(root, categories=["documents", "other"], inventory_all_files=True)
            rows = [*payload["candidates"], *payload.get("inventory", [])]
            self.assertTrue(rows)
            self.assertTrue(all(row.get("is_deleted") is not True for row in rows))


if __name__ == "__main__":
    unittest.main()
