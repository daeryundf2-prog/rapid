"""R8 T-129: evidence hash display honesty (messages and display values only).

Status strings, DB columns and the hash computation are unchanged. The hash worker writes a
display sidecar (per-segment container digests + the acquisition hash recorded in the image,
T-181) and the case API exposes it as ``hash_scope`` / ``hash_segments`` / ``hash_recorded``;
EWF messages say the media (disk) was never re-hashed. Synthetic EWF1 segments only.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from rapidtriage.api.app import create_app
from rapidtriage.api.app.case_workspace import HASH_VIEW_FILE, MEDIA_NOT_REHASHED
from rapidtriage.core.e01_recorded_hash import RecordedHash
from rapidtriage.core.jobs import RunJobStore
from tests.test_e01_recorded_hash import MD5, SHA1, build_ewf1_segment, digest_data

TOKEN = "r8-evidence-hash-display"


class EvidenceHashDisplayTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)
        evidence = self.base / "evidence"
        evidence.mkdir()
        self.image = evidence / "disk.E01"
        self.image.write_bytes(build_ewf1_segment([("header", b"h"), ("next", b"")]))
        self.second = evidence / "disk.E02"
        self.second.write_bytes(
            build_ewf1_segment([("digest", digest_data()), ("done", b"")], segment_number=2)
        )
        self.export = evidence / "export.zip"
        self.export.write_bytes(b"PK synthetic export")
        app = create_app(RunJobStore(), auth_token=TOKEN, cases_db_path=self.base / "ws" / "rapidtriage-cases.db")
        self.client = TestClient(app, headers={"X-RapidTriage-Token": TOKEN})
        self.addCleanup(self.client.close)
        self.workspace = app.state.case_workspace
        created = self.client.post("/api/cases", json={"case_number": "2026-T129", "examiner": "검사관"})
        self.assertEqual(created.status_code, 201, created.text)
        self.case_id = created.json()["case"]["case_id"]

    def add(self, number: str, source_type: str, path: Path, expected: str = "") -> dict:
        response = self.client.post(
            f"/api/cases/{self.case_id}/evidence",
            json={"evidence_number": number, "source_type": source_type, "path": str(path),
                  "verify_hash": True, "expected_hash": expected},
        )
        self.assertEqual(response.status_code, 201, response.text)
        self.workspace.join_hash_jobs()
        rows = self.client.get(f"/api/cases/{self.case_id}/evidence").json()["evidence"]
        return next(row for row in rows if row["evidence_number"] == number)

    def test_e01_rows_expose_segments_and_recorded_hash(self) -> None:
        row = self.add("E-01", "e01", self.image, MD5.hex())
        self.assertEqual(row["hash_status"], "computed")
        self.assertEqual(row["hash_scope"], "ewf-container-segment-bytes")
        segments = row["hash_segments"]
        self.assertEqual([segment["name"] for segment in segments], ["disk.E01", "disk.E02"])
        self.assertEqual(segments[0]["sha256"], hashlib.sha256(self.image.read_bytes()).hexdigest())
        self.assertEqual(segments[1]["sha256"], hashlib.sha256(self.second.read_bytes()).hexdigest())
        self.assertEqual(row["hash_recorded"], {"md5": MD5.hex(), "sha1": SHA1.hex(), "reason": ""})
        # Container columns stay container (aggregate) hashes.
        aggregate = hashlib.sha256(self.image.read_bytes() + self.second.read_bytes()).hexdigest()
        self.assertEqual(row["hashes"]["sha256"], aggregate)
        self.assertIn("매체 재계산은 하지 않음", row["hash_message"])

    def test_container_match_message_says_media_not_rehashed(self) -> None:
        container_md5 = hashlib.md5(self.image.read_bytes() + self.second.read_bytes()).hexdigest()
        row = self.add("E-02", "e01", self.image, container_md5)
        self.assertEqual(row["hash_status"], "matched")
        self.assertTrue(row["hash_message"].endswith(MEDIA_NOT_REHASHED), row["hash_message"])

    def test_file_evidence_keeps_its_message_and_has_no_recorded_hash(self) -> None:
        md5 = hashlib.md5(self.export.read_bytes()).hexdigest()
        row = self.add("E-04", "export", self.export, md5)
        self.assertEqual(row["hash_status"], "matched")
        self.assertEqual(row["hash_message"], f"파일 바이트 MD5 기대값 {md5} / 계산값 {md5}")
        self.assertEqual(row["hash_scope"], "file-bytes")
        self.assertIsNone(row["hash_recorded"])
        self.assertEqual(len(row["hash_segments"]), 1)

    def test_failure_message_and_unfinished_rows_show_no_values(self) -> None:
        with mock.patch(
            "rapidtriage.api.app.case_workspace.run_e01_streaming_hash", side_effect=OSError("읽기 오류")
        ):
            row = self.add("E-05", "export", self.export)
        self.assertEqual(row["hash_status"], "failed")
        self.assertEqual(row["hash_message"], "해시 계산 실패: 읽기 오류")
        self.assertEqual((row["hash_scope"], row["hash_segments"], row["hash_recorded"]), ("", [], None))
        # A corrupt sidecar never breaks the listing.
        other = self.export.with_name("other.zip")
        other.write_bytes(b"PK other synthetic export")
        ok = self.add("E-06", "export", other)
        sidecar = self.workspace.hash_dir(self.case_id, ok["citation_id"]) / HASH_VIEW_FILE
        sidecar.write_text("{not json", encoding="utf-8")
        rows = self.client.get(f"/api/cases/{self.case_id}/evidence").json()["evidence"]
        again = next(item for item in rows if item["evidence_number"] == "E-06")
        self.assertEqual((again["hash_status"], again["hash_scope"]), ("computed", ""))


    def test_not_comparable_e01_input_is_computed_and_raw_error_stays_in_audit(self) -> None:
        """WB-8 P1-1 / P2-10: SHA-256 input or an unreadable recorded hash is never ``mismatched``;
        the raw libewf error goes to the audit params only."""
        sha256 = self.add("E-07", "e01", self.image, "f" * 64)
        self.assertEqual(sha256["hash_status"], "computed")
        self.assertIn("대조 불가", sha256["hash_message"])
        raw = "libewf_handle_open_file_io_pool: unable to read. " * 15
        unreadable = RecordedHash(reason="기록된 취득 해시를 읽는 중 오류가 나 읽지 못했습니다", detail=raw)
        copy = self.image.parent / "copy.E01"
        copy.write_bytes(self.image.read_bytes())
        with mock.patch(
            "rapidtriage.api.app.case_workspace.read_recorded_acquisition_hash", return_value=unreadable
        ):
            row = self.add("E-08", "e01", copy, "f" * 32)
        self.assertEqual(row["hash_status"], "computed")
        self.assertNotIn("libewf", row["hash_message"])
        with closing(sqlite3.connect(self.workspace.path())) as connection:
            params = [
                json.loads(text)
                for (text,) in connection.execute(
                    "SELECT params_json FROM audit_event WHERE action = 'evidence.hash' AND target_id = ?",
                    (row["citation_id"],),
                )
            ]
        self.assertEqual(params[-1]["recorded_error"], raw)
        self.assertEqual(params[-1]["status"], "computed")


if __name__ == "__main__":
    unittest.main()
