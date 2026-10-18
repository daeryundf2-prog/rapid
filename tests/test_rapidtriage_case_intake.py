"""Case intake (AXIOM adoption E1): workspace case DB, case/evidence/run/note APIs, problems, migration."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import threading
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

HAS_FASTAPI = True
try:
    from fastapi.testclient import TestClient
except ModuleNotFoundError as exc:  # pragma: no cover - optional dependency
    if exc.name == "fastapi":
        HAS_FASTAPI = False
    else:
        raise

from rapidtriage.core.case_db import CaseDatabase
from rapidtriage.core.case_db.constants import SCHEMA_SQL
from rapidtriage.core.case_db.intake import (
    CaseConflictError,
    case_integrity_conflict,
    ensure_intake_schema,
    intake_schema_present,
)
from rapidtriage.core.case_db.schema import register_case_db_functions
from rapidtriage.core.jobs import (
    RunJob,
    RunJobStore,
    RunRequest,
    default_run_output_dir,
)

if HAS_FASTAPI:
    from rapidtriage.api.app import create_app
    from rapidtriage.api.app.case_workspace import CaseWorkspace
    from rapidtriage.api.app.run_problems import classify_warning

TOKEN = "rapidtriage-test-token"


def client_for(temp: Path, store: RunJobStore | None = None) -> tuple[TestClient, RunJobStore]:
    store = store or RunJobStore()
    app = create_app(store, auth_token=TOKEN, cases_db_path=temp / "workspace" / "rapidtriage-cases.db")
    return TestClient(app, headers={"X-RapidTriage-Token": TOKEN}), store


def write_run(run_dir: Path, root: Path, **extra: object) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    summary_path = run_dir / "rapidtriage-run-summary.json"
    payload = {
        "profile_version": "rapidtriage-run-summary-v1",
        "mode": "fraud",
        "root": str(root),
        "output_dir": str(run_dir),
        "outputs": {"summary": str(summary_path)},
        "profile": {"description": "fraud", "keywords": ["invoice"], "artifacts_kinds": ["browser"]},
        "safety": {"read_only": True, "dry_run": False, "memory_cap_bytes": 1024},
        "resource_caps": {"max_file_count": 0},
    }
    payload.update(extra)
    summary_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return summary_path


def fake_execute(request, *, run_id=None, **_kwargs):
    output_dir = Path(request.output_dir) if request.output_dir else Path(request.root).parent / f"out-{run_id}"
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = write_run(output_dir, Path(request.root))
    return json.loads(summary_path.read_text(encoding="utf-8"))


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for RapidTriage API tests")
class CaseIntakeApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.temp = Path(self._temp.name)
        self.evidence_dir = self.temp / "evidence"
        self.evidence_dir.mkdir()
        (self.evidence_dir / "a.txt").write_text("hello", encoding="utf-8")
        self.image = self.temp / "disk.E01"
        self.image.write_bytes(b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 64)
        self.client, self.store = client_for(self.temp)

    def tearDown(self) -> None:
        self.client.app.state.case_workspace.join_hash_jobs()
        self.client.close()
        self._temp.cleanup()

    def create_case(self, **body: object) -> dict:
        payload = {"case_number": "2026-고단-1234", "name": "법인 자금 유출", "case_type": "횡령",
                   "examiner": "홍길동", "requester": "서울중앙지검"}
        payload.update(body)
        response = self.client.post("/api/cases", json=payload)
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()["case"]

    def test_create_list_get_patch_case(self) -> None:
        case = self.create_case()
        self.assertEqual(case["case_number"], "2026-고단-1234")
        self.assertEqual(case["requester"], "서울중앙지검")
        self.assertTrue(case["citation_prefix"].startswith("2026-고단-1234"))
        self.assertEqual(case["evidence"], [])
        listed = self.client.get("/api/cases").json()
        self.assertEqual([item["case_id"] for item in listed["cases"]], [case["case_id"]])
        got = self.client.get(f"/api/cases/{case['case_id']}")
        self.assertEqual(got.status_code, 200)
        patched = self.client.patch(f"/api/cases/{case['case_id']}", json={"requester": "경찰청", "status": "closed"})
        self.assertEqual(patched.status_code, 200, patched.text)
        self.assertEqual(patched.json()["case"]["requester"], "경찰청")
        self.assertEqual(patched.json()["case"]["status"], "closed")
        self.assertEqual(self.client.get("/api/cases/case-missing").status_code, 404)
        self.assertEqual(self.client.get("/api/cases/case-missing").json()["detail"], "케이스를 찾을 수 없습니다")

    def test_case_validation_errors_are_korean(self) -> None:
        missing = self.client.post("/api/cases", json={"name": "x"})
        self.assertEqual(missing.status_code, 422)
        self.assertEqual(missing.json()["detail"][0]["msg"], "사건 번호 값이 필요합니다")
        blank = self.client.post("/api/cases", json={"case_number": "   "})
        self.assertEqual(blank.status_code, 422)
        self.assertEqual(blank.json()["detail"], "사건 번호가 비어 있습니다")
        unknown = self.client.post("/api/cases", json={"case_number": "1", "bogus": 1})
        self.assertEqual(unknown.json()["detail"][0]["msg"], "알 수 없는 필드입니다: bogus")
        rel = self.client.post("/api/cases", json={"case_number": "1", "case_root": "relative/dir"})
        self.assertEqual(rel.status_code, 422)
        self.assertIn("케이스 폴더 경로를 허용하지 않습니다", rel.json()["detail"])
        self.create_case()
        dup = self.client.post("/api/cases", json={"case_number": "2026-고단-1234"})
        self.assertEqual(dup.status_code, 409)
        self.assertIn("같은 사건 번호", dup.json()["detail"])
        other = self.create_case(case_number="2026-2")
        clash = self.client.patch(f"/api/cases/{other['case_id']}", json={"case_number": "2026-고단-1234"})
        self.assertEqual(clash.status_code, 409)
        bad_status = self.client.patch(f"/api/cases/{other['case_id']}", json={"status": "gone"})
        self.assertEqual(bad_status.status_code, 422)
        self.assertEqual(bad_status.json()["detail"][0]["msg"], "상태 값이 허용된 값이 아닙니다")

    def test_evidence_add_list_and_path_rules(self) -> None:
        case = self.create_case()
        url = f"/api/cases/{case['case_id']}/evidence"
        folder = self.client.post(url, json={"evidence_number": "E-01", "source_type": "folder",
                                             "path": str(self.evidence_dir), "verify_hash": True})
        self.assertEqual(folder.status_code, 201, folder.text)
        self.assertEqual(folder.json()["evidence"]["hash_status"], "not-applicable")
        self.assertIn("-EVID-000001", folder.json()["evidence"]["citation_id"])
        dup_number = self.client.post(url, json={"evidence_number": "E-01", "source_type": "e01", "path": str(self.image)})
        self.assertEqual(dup_number.status_code, 409)
        dup_path = self.client.post(url, json={"evidence_number": "E-09", "source_type": "folder",
                                               "path": str(self.evidence_dir)})
        self.assertEqual(dup_path.status_code, 409)
        for body, expected in (
            ({"path": "relative\\x", "source_type": "folder"}, "경로를 허용하지 않습니다"),
            ({"path": "~/x", "source_type": "folder"}, "홈 디렉터리"),
            ({"path": str(self.temp / "nope"), "source_type": "folder"}, "증거 경로가 없습니다"),
            ({"path": str(self.image), "source_type": "folder"}, "폴더 증거는 폴더 경로여야"),
            ({"path": str(self.evidence_dir / "a.txt"), "source_type": "e01"}, "E01 증거는"),
        ):
            response = self.client.post(url, json={"evidence_number": "E-77", **body})
            self.assertEqual(response.status_code, 422, (body, response.text))
            self.assertIn(expected, str(response.json()["detail"]))
        if os.name == "nt":
            for raw in ("\\\\server\\share\\x", "\\\\?\\C:\\x"):
                response = self.client.post(url, json={"evidence_number": "E-78", "source_type": "folder", "path": raw})
                self.assertEqual(response.status_code, 422)
                self.assertIn("UNC", response.json()["detail"])
        bad_type = self.client.post(url, json={"evidence_number": "E-79", "source_type": "tape", "path": str(self.image)})
        self.assertEqual(bad_type.json()["detail"][0]["msg"], "증거 종류 값이 허용된 값이 아닙니다")
        listed = self.client.get(url).json()
        self.assertEqual([item["evidence_number"] for item in listed["evidence"]], ["E-01"])
        self.assertEqual(self.client.get("/api/cases/nope/evidence").status_code, 404)

    def test_analysis_roots_confine_evidence_paths(self) -> None:
        case = self.create_case()
        allowed = self.temp / "allowed"
        allowed.mkdir()
        with patch.dict(os.environ, {"RAPIDTRIAGE_ANALYSIS_ROOTS": str(allowed)}):
            outside = self.client.post(f"/api/cases/{case['case_id']}/evidence", json={
                "evidence_number": "E-01", "source_type": "folder", "path": str(self.evidence_dir)})
            inside = self.client.post(f"/api/cases/{case['case_id']}/evidence", json={
                "evidence_number": "E-02", "source_type": "folder", "path": str(allowed)})
        self.assertEqual(outside.status_code, 422)
        self.assertIn("허용 범위", outside.json()["detail"])
        self.assertEqual(inside.status_code, 201, inside.text)

    def test_evidence_hash_verification_matches_and_mismatches(self) -> None:
        case = self.create_case()
        url = f"/api/cases/{case['case_id']}/evidence"
        export = self.temp / "export.zip"
        export.write_bytes(b"PK export bytes")
        md5 = hashlib.md5(export.read_bytes()).hexdigest()
        # E01: container bytes are not the acquisition (media) hash -> no expected-hash comparison.
        e01_expected = self.client.post(url, json={"evidence_number": "E-09", "source_type": "e01",
                                                   "path": str(self.image), "verify_hash": True, "expected_hash": "0" * 32})
        self.assertEqual(e01_expected.status_code, 422)
        self.assertIn("획득(매체) 해시", e01_expected.json()["detail"])
        match = self.client.post(url, json={"evidence_number": "E-01", "source_type": "export", "path": str(export),
                                            "verify_hash": True, "expected_hash": md5.upper()})
        self.assertEqual(match.status_code, 201, match.text)
        self.assertIn(match.json()["evidence"]["hash_status"], ("hashing", "matched"))
        other = self.temp / "other.E01"
        other.write_bytes(b"different")
        mobile = self.temp / "mobile.tar"
        mobile.write_bytes(b"different")
        mismatch = self.client.post(url, json={"evidence_number": "E-02", "source_type": "mobile", "path": str(mobile),
                                               "verify_hash": True, "expected_hash": "0" * 64})
        self.assertEqual(mismatch.status_code, 201)
        plain = self.client.post(url, json={"evidence_number": "E-03", "source_type": "export",
                                            "path": str(self.evidence_dir / "a.txt"), "verify_hash": True})
        self.client.app.state.case_workspace.join_hash_jobs()
        rows = {item["evidence_number"]: item for item in self.client.get(url).json()["evidence"]}
        self.assertEqual(rows["E-01"]["hash_status"], "matched")
        self.assertEqual(rows["E-01"]["hashes"]["md5"], md5)
        self.assertEqual(rows["E-02"]["hash_status"], "mismatched")
        self.assertEqual(rows["E-03"]["hash_status"], "computed")
        self.assertEqual(plain.status_code, 201)
        bad = self.client.post(url, json={"evidence_number": "E-04", "source_type": "e01", "path": str(other),
                                          "verify_hash": True, "expected_hash": "xyz"})
        self.assertEqual(bad.status_code, 422)
        no_verify = self.client.post(url, json={"evidence_number": "E-05", "source_type": "e01", "path": str(other),
                                                "expected_hash": md5})
        self.assertEqual(no_verify.status_code, 422)

    def test_interrupted_hash_reads_as_interrupted(self) -> None:
        case = self.create_case()
        workspace = self.client.app.state.case_workspace
        evidence = workspace.intake.add_evidence(
            case["case_id"], evidence_number="E-01", display_name="x", source_type="e01", path=str(self.image),
            size_bytes=1, hash_verify=True, hash_expected="", hash_status="hashing", hash_message="", actor="t")
        # Saved by this server and no worker yet: still hashing (no 중단됨 flash before start_hash).
        listed = self.client.get(f"/api/cases/{case['case_id']}/evidence").json()["evidence"]
        self.assertEqual(listed[0]["hash_status"], "hashing")
        # Saved before this server started and no worker: interrupted by a restart.
        workspace._started_at = "9999"
        listed = self.client.get(f"/api/cases/{case['case_id']}/evidence").json()["evidence"]
        self.assertEqual(listed[0]["citation_id"], evidence["citation_id"])
        self.assertEqual(listed[0]["hash_status"], "interrupted")

    def test_case_run_saves_snapshot_to_db_and_output_dir(self) -> None:
        case = self.create_case(case_root=str(self.temp / "case-folder"))
        evidence = self.client.post(f"/api/cases/{case['case_id']}/evidence", json={
            "evidence_number": "E-01", "source_type": "folder", "path": str(self.evidence_dir)}).json()["evidence"]
        with patch("rapidtriage.core.jobs.execute_run_request", side_effect=fake_execute):
            response = self.client.post(f"/api/cases/{case['case_id']}/runs", json={
                "evidence_citation_id": evidence["citation_id"], "mode": "fraud", "read_only": True,
                "max_file_count": 500, "wait": True})
        self.assertEqual(response.status_code, 202, response.text)
        payload = response.json()
        run_id = payload["run"]["run_id"]
        self.assertEqual(payload["run"]["status"], "completed")
        request = payload["snapshot"]["snapshot"]["request"]
        self.assertEqual(request["root"], str(self.evidence_dir))
        self.assertEqual(request["max_file_count"], 500)
        self.assertTrue(request["read_only"])
        output_dir = Path(payload["run"]["request"]["output_dir"])
        self.assertTrue(str(output_dir).startswith(str(self.temp / "case-folder" / "E-01-rapidtriage-run-fraud-")))
        snapshot_file = json.loads((output_dir / "processing-snapshot.json").read_text(encoding="utf-8"))
        self.assertEqual(snapshot_file["evidence"]["evidence_number"], "E-01")
        self.assertEqual(snapshot_file["case"]["case_number"], "2026-고단-1234")
        self.assertEqual(snapshot_file["request"], request)
        got = self.client.get(f"/api/runs/{run_id}/processing-snapshot").json()
        self.assertEqual(got["source"], "case-db")
        self.assertEqual(got["case"]["case_number"], "2026-고단-1234")
        self.assertEqual(got["evidence"]["evidence_number"], "E-01")
        runs = self.client.get(f"/api/cases/{case['case_id']}/runs").json()["runs"]
        self.assertEqual([(item["run_id"], item["evidence_number"], item["status"]) for item in runs],
                         [(run_id, "E-01", "completed")])
        detail = self.client.get(f"/api/cases/{case['case_id']}").json()["case"]
        self.assertEqual(detail["run_count"], 1)
        self.assertEqual(detail["evidence"][0]["runs"][0]["run_id"], run_id)

    def test_case_run_errors(self) -> None:
        case = self.create_case()
        evidence = self.client.post(f"/api/cases/{case['case_id']}/evidence", json={
            "evidence_number": "E-01", "source_type": "folder", "path": str(self.evidence_dir)}).json()["evidence"]
        url = f"/api/cases/{case['case_id']}/runs"
        self.assertEqual(self.client.post(url, json={"evidence_citation_id": "nope", "mode": "fraud"}).status_code, 404)
        self.assertEqual(self.client.post("/api/cases/x/runs", json={"evidence_citation_id": "n", "mode": "fraud"}).status_code, 404)
        bad_mode = self.client.post(url, json={"evidence_citation_id": evidence["citation_id"], "mode": "zzz"})
        self.assertEqual(bad_mode.status_code, 422)
        self.assertIn("알 수 없는 처리 모드", bad_mode.json()["detail"])
        other_root = self.client.post(url, json={"evidence_citation_id": evidence["citation_id"], "mode": "fraud",
                                                 "root": str(self.temp)})
        self.assertEqual(other_root.status_code, 422)
        self.assertEqual(other_root.json()["detail"], "런 경로가 증거 경로와 다릅니다")
        missing = self.client.post(url, json={"mode": "fraud"})
        self.assertEqual(missing.json()["detail"][0]["msg"], "증거 인용 ID 값이 필요합니다")
        bad_out = self.client.post(url, json={"evidence_citation_id": evidence["citation_id"], "mode": "fraud",
                                              "output_dir": "rel"})
        self.assertEqual(bad_out.status_code, 422)

    def test_snapshot_of_caseless_run_and_link_to_case(self) -> None:
        run_dir = self.temp / "old-run"
        write_run(run_dir, self.evidence_dir)
        job = self.store.import_completed_run(run_dir)
        derived = self.client.get(f"/api/runs/{job.run_id}/processing-snapshot")
        self.assertEqual(derived.status_code, 200, derived.text)
        self.assertEqual(derived.json()["source"], "run-request")
        self.assertIsNone(derived.json()["case_id"])
        self.assertEqual(derived.json()["snapshot"]["profile"]["keywords"], ["invoice"])
        self.assertEqual(self.client.get("/api/runs/nope/processing-snapshot").status_code, 404)

        case = self.create_case()
        link_url = f"/api/cases/{case['case_id']}/runs/link"
        needs_number = self.client.post(link_url, json={"run_id": job.run_id})
        self.assertEqual(needs_number.status_code, 422)
        self.assertEqual(needs_number.json()["detail"], "증거 번호 값이 필요합니다")
        linked = self.client.post(link_url, json={"run_id": job.run_id, "evidence_number": "E-07"})
        self.assertEqual(linked.status_code, 201, linked.text)
        self.assertEqual(linked.json()["snapshot"]["snapshot"]["origin"], "linked-run")
        # The finished run's output folder is not written after the fact (review item 5): the
        # snapshot file lives in the workspace and its path is in the audit.
        self.assertFalse((run_dir / "processing-snapshot.json").exists())
        workspace = self.client.app.state.case_workspace
        snapshot_file = Path(linked.json()["snapshot_file"])
        self.assertTrue(snapshot_file.is_file())
        self.assertEqual(snapshot_file.parent, workspace.linked_snapshot_dir(job.run_id))
        with closing(sqlite3.connect(workspace.path())) as connection:
            params = json.loads(connection.execute(
                "SELECT params_json FROM audit_event WHERE action = 'run.linked'").fetchone()[0])
        self.assertEqual(params["snapshot_file"], str(snapshot_file))
        again = self.client.post(link_url, json={"run_id": job.run_id, "evidence_number": "E-08"})
        self.assertEqual(again.status_code, 409)
        self.assertIn("2026-고단-1234", again.json()["detail"])
        self.assertEqual(self.client.post(link_url, json={"run_id": "missing"}).status_code, 404)
        snap = self.client.get(f"/api/runs/{job.run_id}/processing-snapshot").json()
        self.assertEqual(snap["source"], "case-db")
        self.assertEqual(snap["evidence"]["evidence_number"], "E-07")
        self.assertEqual(snap["evidence"]["source_type"], "folder")

    def test_notes_author_soft_delete_and_history(self) -> None:
        case = self.create_case()
        url = f"/api/cases/{case['case_id']}/notes"
        first = self.client.post(url, json={"text": "  압수 목록 확인  "})
        self.assertEqual(first.status_code, 201, first.text)
        self.assertEqual(first.json()["note"]["author"], "홍길동")
        self.assertEqual(first.json()["note"]["text"], "압수 목록 확인")
        second = self.client.post(url, json={"text": "USB 2개", "author": "김분석"}).json()["note"]
        self.assertEqual(second["author"], "김분석")
        self.assertEqual(self.client.post(url, json={"text": "   "}).json()["detail"], "메모 내용이 비어 있습니다")
        self.assertEqual(self.client.post(url, json={}).json()["detail"][0]["msg"], "메모 내용 값이 필요합니다")
        deleted = self.client.delete(f"{url}/{first.json()['note']['id']}", params={"actor": "이감독"})
        self.assertEqual(deleted.status_code, 200, deleted.text)
        self.assertEqual(deleted.json()["note"]["deleted_by"], "이감독")
        self.assertEqual(self.client.delete(f"{url}/{first.json()['note']['id']}").status_code, 409)
        self.assertEqual(self.client.delete(f"{url}/9999").status_code, 404)
        listed = self.client.get(url).json()
        self.assertEqual([note["text"] for note in listed["notes"]], ["USB 2개"])
        self.assertEqual(listed["deleted_count"], 1)
        self.assertEqual([(h["action"], h["actor"]) for h in listed["history"]],
                         [("deleted", "이감독"), ("created", "김분석"), ("created", "홍길동")])
        with_deleted = self.client.get(url, params={"include_deleted": True}).json()
        self.assertEqual(len(with_deleted["notes"]), 2)
        self.assertEqual(self.client.get("/api/cases/nope/notes").status_code, 404)
        database = self.client.app.state.case_workspace.path()
        with closing(sqlite3.connect(database)) as connection:
            with self.assertRaises(sqlite3.DatabaseError):
                connection.execute("UPDATE case_note_history SET actor = 'x'")
            actions = [row[0] for row in connection.execute("SELECT action FROM audit_event ORDER BY id")]
        self.assertIn("note.deleted", actions)
        self.assertIn("case.created", actions)

    def test_problems_grouped_by_reason(self) -> None:
        run_dir = self.temp / "run"
        artifacts = run_dir / "artifacts"
        artifacts.mkdir(parents=True)
        browser = artifacts / "rapidtriage-artifacts-browser.json"
        browser.write_text(json.dumps({"parser_errors": ["History: database disk image is malformed"],
                                       "artifacts": []}), encoding="utf-8")
        warnings = [
            {"step": "docs", "level": "warning", "message": "상한/절단 적용 — 결과가 전수가 아님: x"},
            {"step": "artifacts-recent-files", "level": "warning", "message": "recent-files: 행 단위 절단 10행"},
            {"step": "artifacts-windows-registry", "level": "warning", "message": "windows-registry: 행 단위 절단 5행"},
            {"step": "artifacts-email", "level": "notice", "message": "No email artifact rows were collected."},
        ] + [{"step": f"artifacts-k{i}", "level": "notice", "message": f"No k{i} artifact rows were collected."}
             for i in range(25)]
        write_run(
            run_dir, self.evidence_dir,
            outputs={"summary": str(run_dir / "rapidtriage-run-summary.json"), "artifacts_browser": str(browser)},
            warnings=warnings,
            silent_failure_detection={"checks": [
                {"id": "files-scanned", "level": "pass", "message": "ok"},
                {"id": "eventlog-parsed", "level": "fail", "message": "No event logs parsed", "detail": "n=0"}]},
            steps=[{"name": "docs-extract", "status": "skipped", "disabled_reason": "extraction-disabled"},
                   {"name": "timeline", "status": "failed", "message": "boom"},
                   {"name": "files", "status": "completed"}],
        )
        job = self.store.import_completed_run(run_dir)
        payload = self.client.get(f"/api/runs/{job.run_id}/problems").json()
        groups = {group["reason_id"]: group for group in payload["groups"]}
        self.assertEqual(payload["total"], 4 + 25 + 1 + 1 + 2)
        self.assertEqual(groups["row-truncated"]["count"], 2)
        self.assertEqual(groups["row-truncated"]["label_ko"], "행 단위 절단 (원문 일부만 보존)")
        self.assertEqual(groups["no-rows"]["count"], 26)
        self.assertEqual(len(groups["no-rows"]["items"]), 20)
        self.assertEqual(groups["parser-error"]["items"][0]["step"], "artifacts-browser")
        self.assertEqual(groups["silent-failure"]["count"], 1)
        self.assertEqual(groups["step-failed"]["items"][0]["message"], "boom")
        self.assertEqual(groups["step-skipped"]["items"][0]["message"], "extraction-disabled")
        self.assertEqual(payload["groups"][0]["level"], "error")
        full = self.client.get(f"/api/runs/{job.run_id}/problems", params={"reason_id": "no-rows", "limit": 100}).json()
        self.assertEqual([g["reason_id"] for g in full["groups"]], ["no-rows"])
        self.assertEqual(len(full["groups"][0]["items"]), 26)
        bad = self.client.get(f"/api/runs/{job.run_id}/problems", params={"limit": 0})
        self.assertEqual(bad.status_code, 422)
        self.assertIn("개수(limit)", bad.json()["detail"][0]["msg"])
        self.assertEqual(self.client.get("/api/runs/nope/problems").status_code, 404)

    def test_problems_of_active_run_conflict(self) -> None:
        active = RunJob(run_id="active01", request=RunRequest(root=str(self.evidence_dir), mode="fraud"), status="running")
        self.store._jobs[active.run_id] = active
        response = self.client.get("/api/runs/active01/problems")
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["detail"], "런이 아직 끝나지 않았습니다")

    def test_link_rules_review_followups(self) -> None:
        case = self.create_case()
        # Case numbers are unique regardless of letter case.
        self.assertEqual(self.client.post("/api/cases", json={"case_number": "2026-고단-1234".upper()}).status_code, 409)
        self.create_case(case_number="2026-abc")
        self.assertEqual(self.client.post("/api/cases", json={"case_number": "2026-ABC"}).status_code, 409)
        # A running run cannot be linked (its snapshot would miss the run's recorded options).
        active = RunJob(run_id="active02", request=RunRequest(root=str(self.evidence_dir), mode="fraud"), status="running")
        self.store._jobs[active.run_id] = active
        link_url = f"/api/cases/{case['case_id']}/runs/link"
        busy = self.client.post(link_url, json={"run_id": "active02", "evidence_number": "E-01"})
        self.assertEqual(busy.status_code, 409)
        self.assertIn("실행 중인 런", busy.json()["detail"])
        # Evidence registered with backslashes is found for a run whose root uses forward slashes.
        evidence = self.client.post(f"/api/cases/{case['case_id']}/evidence", json={
            "evidence_number": "E-01", "source_type": "folder", "path": str(self.evidence_dir)}).json()["evidence"]
        run_dir = self.temp / "fwd-run"
        write_run(run_dir, Path(str(self.evidence_dir).replace("\\", "/")))
        job = self.store.import_completed_run(run_dir)
        job.request = RunRequest(root=str(self.evidence_dir).replace("\\", "/").upper() if os.name == "nt"
                                 else str(self.evidence_dir), mode="fraud")
        linked = self.client.post(link_url, json={"run_id": job.run_id, "evidence_citation_id": "   "})
        self.assertEqual(linked.status_code, 201, linked.text)
        self.assertEqual(linked.json()["snapshot"]["evidence_citation_id"], evidence["citation_id"])
        evidence_rows = self.client.get(f"/api/cases/{case['case_id']}/evidence").json()["evidence"]
        self.assertEqual(len(evidence_rows), 1)
        # Same path spelled differently is still a duplicate.
        if os.name == "nt":
            dup = self.client.post(f"/api/cases/{case['case_id']}/evidence", json={
                "evidence_number": "E-02", "source_type": "folder", "path": str(self.evidence_dir).upper()})
            self.assertEqual(dup.status_code, 409)

    # --- adversarial review follow-ups (E1 fixer) ------------------------------------------

    def add_folder_evidence(self, case: dict, number: str = "E-01", path: Path | None = None) -> dict:
        response = self.client.post(f"/api/cases/{case['case_id']}/evidence", json={
            "evidence_number": number, "source_type": "folder", "path": str(path or self.evidence_dir)})
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()["evidence"]

    def wait_for_job(self, run_id: str, timeout: float = 30.0) -> RunJob:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            job = self.store.get(run_id)
            if job.status not in ("queued", "running"):
                return job
            time.sleep(0.05)
        self.fail(f"run {run_id} did not finish")

    def test_review1_explicit_output_dir_used_by_active_run_is_409(self) -> None:
        case = self.create_case()
        first = self.add_folder_evidence(case)
        other_folder = self.temp / "evidence2"
        other_folder.mkdir()
        second = self.add_folder_evidence(case, "E-02", other_folder)
        shared = self.temp / "shared-out"
        busy = RunJob(run_id="busy0001", request=RunRequest(root=str(self.evidence_dir), mode="fraud",
                                                             output_dir=str(shared)), status="running")
        self.store._jobs[busy.run_id] = busy
        url = f"/api/cases/{case['case_id']}/runs"
        spelled = str(shared).upper() if os.name == "nt" else str(shared)
        clash = self.client.post(url, json={"evidence_citation_id": second["citation_id"], "mode": "fraud",
                                            "output_dir": spelled})
        self.assertEqual(clash.status_code, 409, clash.text)
        self.assertIn("같은 출력 폴더를 쓰는 런(busy0001)", clash.json()["detail"])
        # A finished run in that folder does not block (only queued/running ones do).
        busy.status = "completed"
        with patch("rapidtriage.core.jobs.execute_run_request", side_effect=fake_execute):
            ok = self.client.post(url, json={"evidence_citation_id": first["citation_id"], "mode": "fraud",
                                             "output_dir": str(shared), "wait": True})
        self.assertEqual(ok.status_code, 202, ok.text)

    def test_review2_register_only_evidence_is_flagged_and_prechecked(self) -> None:
        case = self.create_case()
        export = self.temp / "export.zip"
        export.write_bytes(b"PK\x03\x04 not really")
        added = self.client.post(f"/api/cases/{case['case_id']}/evidence", json={
            "evidence_number": "E-01", "source_type": "export", "path": str(export)})
        self.assertEqual(added.status_code, 201, added.text)
        self.assertFalse(added.json()["evidence"]["runnable"])
        self.assertIn("등록만", added.json()["evidence"]["run_blocked_reason"])
        folder = self.add_folder_evidence(case, "E-02")
        self.assertTrue(folder["runnable"])
        rows = {item["evidence_number"]: item for item in self.client.get(
            f"/api/cases/{case['case_id']}/evidence").json()["evidence"]}
        self.assertFalse(rows["E-01"]["runnable"])
        self.assertTrue(rows["E-02"]["runnable"])
        run = self.client.post(f"/api/cases/{case['case_id']}/runs", json={
            "evidence_citation_id": rows["E-01"]["citation_id"], "mode": "fraud"})
        self.assertEqual(run.status_code, 422)
        self.assertIn("바로 처리할 수 없습니다", run.json()["detail"])
        # The pre-check the wizard calls before anything is saved.
        check = self.client.post("/api/cases/evidence-check", json={"path": str(export), "source_type": "export"})
        self.assertEqual(check.status_code, 200, check.text)
        self.assertEqual((check.json()["ok"], check.json()["runnable"]), (True, False))
        self.assertIn("등록만", check.json()["run_blocked_reason"])
        folder_check = self.client.post("/api/cases/evidence-check", json={
            "path": str(self.evidence_dir), "source_type": "folder"}).json()
        self.assertEqual((folder_check["ok"], folder_check["runnable"]), (True, True))
        missing = self.client.post("/api/cases/evidence-check", json={
            "path": str(self.temp / "nope"), "source_type": "folder"}).json()
        self.assertFalse(missing["ok"])
        self.assertIn("증거 경로가 없습니다", missing["problem"])
        wrong_kind = self.client.post("/api/cases/evidence-check", json={
            "path": str(export), "source_type": "folder"}).json()
        self.assertIn("폴더 증거는 폴더 경로여야", wrong_kind["problem"])
        relative = self.client.post("/api/cases/evidence-check", json={"path": "rel\\x"}).json()
        self.assertIn("경로를 허용하지 않습니다", relative["problem"])

    def test_review3_link_with_explicit_evidence_requires_same_path_or_audited_force(self) -> None:
        case = self.create_case()
        other_folder = self.temp / "evidence2"
        other_folder.mkdir()
        evidence = self.add_folder_evidence(case, "E-01", other_folder)
        run_dir = self.temp / "old-run"
        write_run(run_dir, self.evidence_dir)
        job = self.store.import_completed_run(run_dir)
        url = f"/api/cases/{case['case_id']}/runs/link"
        wrong = self.client.post(url, json={"run_id": job.run_id, "evidence_citation_id": evidence["citation_id"]})
        self.assertEqual(wrong.status_code, 422, wrong.text)
        self.assertEqual(wrong.json()["detail"], "런 경로가 증거 경로와 다릅니다")
        no_reason = self.client.post(url, json={"run_id": job.run_id, "evidence_citation_id": evidence["citation_id"],
                                                "force": True, "force_reason": "  "})
        self.assertEqual(no_reason.status_code, 422)
        self.assertEqual(no_reason.json()["detail"], "강제 연결 사유를 입력하세요")
        self.assertIsNone(self.client.app.state.case_workspace.intake.get_snapshot(job.run_id))
        forced = self.client.post(url, json={"run_id": job.run_id, "evidence_citation_id": evidence["citation_id"],
                                             "force": True, "force_reason": "증거 사본 경로로 처리함"})
        self.assertEqual(forced.status_code, 201, forced.text)
        self.assertEqual(forced.json()["snapshot"]["snapshot"]["forced_link"]["reason"], "증거 사본 경로로 처리함")
        with closing(sqlite3.connect(self.client.app.state.case_workspace.path())) as connection:
            params = json.loads(connection.execute(
                "SELECT params_json FROM audit_event WHERE action = 'run.linked'").fetchone()[0])
        self.assertTrue(params["forced"])
        self.assertEqual(params["force_reason"], "증거 사본 경로로 처리함")
        self.assertEqual(params["run_root"], str(self.evidence_dir))
        # Same path (spelled differently) links without force.
        run_dir2 = self.temp / "old-run2"
        write_run(run_dir2, other_folder)
        job2 = self.store.import_completed_run(run_dir2)
        if os.name == "nt":
            job2.request = RunRequest(root=str(other_folder).upper(), mode="fraud")
        same = self.client.post(url, json={"run_id": job2.run_id, "evidence_citation_id": evidence["citation_id"]})
        self.assertEqual(same.status_code, 201, same.text)

    def test_review4_concurrent_case_insensitive_creates_yield_one_case(self) -> None:
        intake = self.client.app.state.case_workspace.intake
        for round_index in range(8):
            numbers = (f"2026-ABC-{round_index}", f"2026-abc-{round_index}")
            barrier = threading.Barrier(2)
            outcomes: list[str] = []

            def create(number: str, case_id: str, barrier: threading.Barrier, outcomes: list[str]) -> None:
                barrier.wait()
                try:
                    intake.create_case(case_id=case_id, fields={"case_number": number}, case_root="", actor="t")
                    outcomes.append("created")
                except CaseConflictError as exc:
                    outcomes.append(str(exc))

            threads = [
                threading.Thread(target=create, args=(number, f"case-r{round_index}-{i}", barrier, outcomes))
                for i, number in enumerate(numbers)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(30)
            self.assertEqual(outcomes.count("created"), 1, outcomes)
            self.assertIn("같은 사건 번호의 케이스가 이미 있습니다", [o for o in outcomes if o != "created"][0])
        # Two numbers with one citation prefix (normalized) both succeed, with distinct prefixes.
        barrier = threading.Barrier(2)
        made: list[dict] = []

        def create_prefix(number: str, index: int) -> None:
            barrier.wait()
            made.append(intake.create_case(case_id=f"case-p{index}", fields={"case_number": number},
                                           case_root="", actor="t"))

        threads = [threading.Thread(target=create_prefix, args=(n, i)) for i, n in enumerate(("P 1", "P-1"))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(30)
        self.assertEqual(len(made), 2)
        self.assertEqual(len({item["citation_prefix"] for item in made}), 2)

    def test_review4_unique_indexes_back_the_precheck(self) -> None:
        self.create_case(case_number="2026-XYZ")
        workspace = self.client.app.state.case_workspace
        with closing(sqlite3.connect(workspace.path())) as connection:
            with self.assertRaises(sqlite3.IntegrityError) as number_clash:
                connection.execute(
                    "INSERT INTO case_record (case_id, name, citation_prefix, created_at, updated_at, case_number) "
                    "VALUES ('x1', 'x', 'OTHER', 't', 't', '2026-xyz')")
            prefix = connection.execute("SELECT citation_prefix FROM case_record").fetchone()[0]
            with self.assertRaises(sqlite3.IntegrityError) as prefix_clash:
                connection.execute(
                    "INSERT INTO case_record (case_id, name, citation_prefix, created_at, updated_at, case_number) "
                    "VALUES ('x2', 'x', ?, 't', 't', 'different')", (prefix,))
        self.assertIn("같은 사건 번호", str(case_integrity_conflict(number_clash.exception, "2026-xyz")))
        self.assertIn("인용 ID 접두", str(case_integrity_conflict(prefix_clash.exception, "different")))

    def test_review5_case_run_records_snapshot_file_in_audit(self) -> None:
        case = self.create_case()
        evidence = self.add_folder_evidence(case)
        with patch("rapidtriage.core.jobs.execute_run_request", side_effect=fake_execute):
            response = self.client.post(f"/api/cases/{case['case_id']}/runs", json={
                "evidence_citation_id": evidence["citation_id"], "mode": "fraud", "wait": True})
        self.assertEqual(response.status_code, 202, response.text)
        with closing(sqlite3.connect(self.client.app.state.case_workspace.path())) as connection:
            params = json.loads(connection.execute(
                "SELECT params_json FROM audit_event WHERE action = 'run.created'").fetchone()[0])
        self.assertEqual(params["snapshot_file"], response.json()["snapshot_file"])
        self.assertIsNone(params["snapshot_file_error"])

    def test_review7_restart_marks_hashing_interrupted_in_db_and_rehash_recomputes(self) -> None:
        case = self.create_case()
        export = self.temp / "export.bin"
        export.write_bytes(b"bytes to hash")
        workspace = self.client.app.state.case_workspace
        stuck = workspace.intake.add_evidence(
            case["case_id"], evidence_number="E-01", display_name="x", source_type="export", path=str(export),
            size_bytes=1, hash_verify=True, hash_expected="", hash_status="hashing", hash_message="", actor="t")
        self.client.close()
        # A new server over the same workspace DB (the old hash worker is gone).
        self.client, self.store = client_for(self.temp)
        listed = self.client.get(f"/api/cases/{case['case_id']}/evidence").json()["evidence"]
        self.assertEqual(listed[0]["hash_status"], "interrupted")
        workspace = self.client.app.state.case_workspace
        with closing(sqlite3.connect(workspace.path())) as connection:
            stored = connection.execute("SELECT hash_status FROM evidence_source WHERE citation_id = ?",
                                        (stuck["citation_id"],)).fetchone()[0]
            audit = json.loads(connection.execute(
                "SELECT params_json FROM audit_event WHERE action = 'evidence.hash' ORDER BY id DESC").fetchone()[0])
        self.assertEqual(stored, "interrupted")
        self.assertEqual(audit["status"], "interrupted")
        url = f"/api/cases/{case['case_id']}/evidence/{stuck['citation_id']}/hash"
        again = self.client.post(url, params={"actor": "김분석"})
        self.assertEqual(again.status_code, 202, again.text)
        self.assertEqual(again.json()["evidence"]["hash_status"], "hashing")
        workspace.join_hash_jobs()
        row = self.client.get(f"/api/cases/{case['case_id']}/evidence").json()["evidence"][0]
        self.assertEqual(row["hash_status"], "computed")
        self.assertEqual(row["hashes"]["md5"], hashlib.md5(b"bytes to hash").hexdigest())
        folder = self.add_folder_evidence(case, "E-02")
        not_file = self.client.post(f"/api/cases/{case['case_id']}/evidence/{folder['citation_id']}/hash")
        self.assertEqual(not_file.status_code, 422)
        self.assertEqual(self.client.post(f"/api/cases/{case['case_id']}/evidence/nope/hash").status_code, 404)

    def test_review8_note_history_rejects_delete(self) -> None:
        case = self.create_case()
        self.client.post(f"/api/cases/{case['case_id']}/notes", json={"text": "기록"})
        with closing(sqlite3.connect(self.client.app.state.case_workspace.path())) as connection:
            with self.assertRaises(sqlite3.DatabaseError) as raised:
                connection.execute("DELETE FROM case_note_history")
            self.assertIn("append-only", str(raised.exception))
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM case_note_history").fetchone()[0], 1)

    def test_review9_blank_name_falls_back_to_case_number(self) -> None:
        case = self.create_case()
        blank = self.client.patch(f"/api/cases/{case['case_id']}", json={"name": "   "})
        self.assertEqual(blank.status_code, 200, blank.text)
        self.assertEqual(blank.json()["case"]["name"], "2026-고단-1234")
        both = self.client.patch(f"/api/cases/{case['case_id']}", json={"name": "", "case_number": "2026-새번호"})
        self.assertEqual(both.json()["case"]["name"], "2026-새번호")

    def test_review13_default_wait_false_case_run(self) -> None:
        case = self.create_case(case_root=str(self.temp / "case-folder"))
        evidence = self.add_folder_evidence(case)
        with patch("rapidtriage.core.jobs.execute_run_request", side_effect=fake_execute):
            response = self.client.post(f"/api/cases/{case['case_id']}/runs", json={
                "evidence_citation_id": evidence["citation_id"], "mode": "fraud"})
            self.assertEqual(response.status_code, 202, response.text)
            payload = response.json()
            run_id = payload["run"]["run_id"]
            self.assertIn(payload["run"]["status"], ("queued", "running", "completed"))
            job = self.wait_for_job(run_id)
        self.assertEqual(job.status, "completed", job.error)
        output_dir = Path(job.request.output_dir or "")
        self.assertTrue(output_dir.name.startswith("E-01-rapidtriage-run-fraud-"))
        # The pre-run snapshot file and the run summary share the run's own folder.
        self.assertTrue(os.path.samefile(payload["snapshot_file"], output_dir / "processing-snapshot.json"))
        self.assertTrue((output_dir / "processing-snapshot.json").is_file())
        self.assertTrue((output_dir / "rapidtriage-run-summary.json").is_file())
        runs = self.client.get(f"/api/cases/{case['case_id']}/runs").json()["runs"]
        self.assertEqual([(item["run_id"], item["status"]) for item in runs], [(run_id, "completed")])

    def test_review13_file_evidence_case_run(self) -> None:
        case = self.create_case()
        added = self.client.post(f"/api/cases/{case['case_id']}/evidence", json={
            "evidence_number": "E-01", "source_type": "e01", "path": str(self.image)})
        self.assertEqual(added.status_code, 201, added.text)
        evidence = added.json()["evidence"]
        if not evidence["runnable"]:
            self.skipTest(f"E01 reader unavailable here: {evidence['run_blocked_reason']}")
        def execute_default(request, *, run_id=None, **_kwargs):
            # Like the real run: no output folder given -> the default next to the evidence file.
            output_dir = default_run_output_dir(Path(request.root), request.mode, run_id=run_id)
            output_dir.mkdir(parents=True, exist_ok=True)
            return json.loads(write_run(output_dir, Path(request.root)).read_text(encoding="utf-8"))

        with patch("rapidtriage.core.jobs.execute_run_request", side_effect=execute_default):
            response = self.client.post(f"/api/cases/{case['case_id']}/runs", json={
                "evidence_citation_id": evidence["citation_id"], "mode": "fraud", "wait": True})
        self.assertEqual(response.status_code, 202, response.text)
        run = response.json()["run"]
        self.assertEqual(run["status"], "completed")
        self.assertEqual(run["request"]["root"], str(self.image))
        # No case folder: a file's run output goes next to the file.
        snapshot_file = Path(response.json()["snapshot_file"])
        self.assertTrue(os.path.samefile(snapshot_file.parent.parent, self.image.parent))
        self.assertTrue(snapshot_file.parent.name.startswith("disk-rapidtriage-run-fraud-"))

    def test_review13_recorded_zero_parser_errors_skip_opening_the_output(self) -> None:
        run_dir = self.temp / "run0"
        artifacts = run_dir / "artifacts"
        artifacts.mkdir(parents=True)
        browser = artifacts / "rapidtriage-artifacts-browser.json"
        browser.write_text(json.dumps({"parser_errors": ["would be counted if opened"]}), encoding="utf-8")
        email = artifacts / "rapidtriage-artifacts-email.json"
        email.write_text(json.dumps({"parser_errors": ["email: bad mbox"]}), encoding="utf-8")
        write_run(
            run_dir, self.evidence_dir,
            outputs={"summary": str(run_dir / "rapidtriage-run-summary.json"),
                     "artifacts_browser": str(browser), "artifacts_email": str(email)},
            steps=[{"name": "artifacts-browser", "status": "completed", "parser_error_count": 0},
                   {"name": "artifacts-email", "status": "completed", "parser_error_count": 1}],
        )
        job = self.store.import_completed_run(run_dir)
        from rapidtriage.api.app import run_problems

        with patch.object(run_problems, "read_output_key", wraps=run_problems.read_output_key) as reader:
            payload = self.client.get(f"/api/runs/{job.run_id}/problems").json()
        opened = [Path(call.args[0]).name for call in reader.call_args_list]
        self.assertEqual(opened, ["rapidtriage-artifacts-email.json"])
        groups = {group["reason_id"]: group for group in payload["groups"]}
        self.assertEqual(groups["parser-error"]["count"], 1)
        self.assertEqual(groups["parser-error"]["items"][0]["message"], "email: bad mbox")

    def test_review14_temp_workspace_fallback_logs_warning(self) -> None:
        env = {key: value for key, value in os.environ.items() if key != "RAPIDTRIAGE_CASES_DB"}
        with patch.dict(os.environ, env, clear=True):
            workspace = CaseWorkspace(RunJobStore())
            with self.assertLogs("rapidtriage.api.app.case_workspace", level="WARNING") as logs:
                path = workspace.path()
        self.assertIn("temporary DB", logs.output[0])
        self.assertIn(str(path), logs.output[0])

    def test_routes_require_auth_token(self) -> None:
        bare = TestClient(create_app(RunJobStore(), auth_token=TOKEN, cases_db_path=self.temp / "x.db"))
        for method, path in (("get", "/api/cases"), ("post", "/api/cases"), ("get", "/api/runs/x/problems"),
                             ("delete", "/api/cases/x/notes/1")):
            self.assertEqual(getattr(bare, method)(path).status_code, 401, path)


class ProblemClassificationTests(unittest.TestCase):
    @unittest.skipUnless(HAS_FASTAPI, "fastapi is required")
    def test_run_subset10_messages(self) -> None:
        cases = {
            "상한/절단 적용 — 결과가 전수가 아님: summary.size_caps.truncated": "cap-truncated",
            "문서 8건: 크기 상한 초과로 본문 미추출 (too-large)": "size-cap",
            "문서 80건: 비인쇄 문자 비율 초과로 본문 미색인 (binary-rejected)": "binary-rejected",
            "recent-files: 행 단위 절단 10행 — 원문 일부만 보존됨": "row-truncated",
            "No email artifact rows were collected.": "no-rows",
            "cloud-export: 클라우드 내보내기 루트 없음": "input-missing",
            "mobile-export: 모바일 추출물 없음": "input-missing",
            "synthetic-media: 후보 1104개 중 592개 파일 미선별 (파일 수 상한 512개)": "file-count-cap",
            "eventlog: 표시용 미리보기 절단 33803행 (원본 레코드 값은 보존, 경고 아님)": "preview-truncated",
            "something else": "other-warning",
        }
        for message, reason in cases.items():
            self.assertEqual(classify_warning(message, "warning"), reason, message)
        self.assertEqual(classify_warning("misc", "notice"), "other-notice")


class CaseIntakeMigrationTests(unittest.TestCase):
    def test_existing_case_db_migrates_in_place(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "old.db"
            with closing(sqlite3.connect(path)) as connection:
                register_case_db_functions(connection)
                connection.executescript(SCHEMA_SQL)
                connection.execute("INSERT INTO schema_info (key, value) VALUES ('schema_version', '1')")
                connection.execute(
                    "INSERT INTO case_record (case_id, name, citation_prefix, created_at, updated_at) "
                    "VALUES ('legacy', 'Legacy case', 'LEGACY', 't', 't')"
                )
                connection.execute(
                    "INSERT INTO evidence_source (citation_id, case_id, display_name, source_type, original_path, "
                    "added_at) VALUES ('LEGACY-EVID-000001', 'legacy', 'x', 'folder', '/x', 't')"
                )
                connection.commit()
                self.assertFalse(intake_schema_present(connection))
            database = CaseDatabase(path)
            database.initialize()
            # A current run DB opened by viewers/search is not written to (read-only folders keep working).
            with closing(sqlite3.connect(path)) as connection:
                self.assertFalse(intake_schema_present(connection))
            # The workspace case DB migrates in place when it is opened.
            if HAS_FASTAPI:
                app = create_app(RunJobStore(), auth_token=TOKEN, cases_db_path=path)
                client = TestClient(app, headers={"X-RapidTriage-Token": TOKEN})
                self.assertEqual(client.get("/api/cases").json()["cases"], [])
                made = client.post("/api/cases", json={"case_number": "LEGACY-2"})
                self.assertEqual(made.status_code, 201, made.text)
                client.close()
            else:
                with database.connect() as connection:
                    ensure_intake_schema(connection)
            with closing(sqlite3.connect(path)) as connection:
                connection.row_factory = sqlite3.Row
                self.assertTrue(intake_schema_present(connection))
                row = connection.execute("SELECT * FROM case_record WHERE case_id = 'legacy'").fetchone()
                self.assertEqual(row["name"], "Legacy case")
                self.assertEqual(row["case_number"], "")
                evidence = connection.execute("SELECT * FROM evidence_source").fetchone()
                self.assertEqual(evidence["evidence_number"], "")
                self.assertEqual(evidence["hash_verify"], 0)
            self.assertEqual(database.get_case("legacy").name, "Legacy case")
            self.assertEqual(database.schema_version(), 1)
            # A second open is a no-op (idempotent migration).
            CaseDatabase(path).initialize()


if __name__ == "__main__":
    unittest.main()
