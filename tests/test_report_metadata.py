"""R8 T-182: case report audit inputs and report metadata (tool version, evidence records, scope).

Acceptance: the report metadata carries ``tool_version``, ``evidence_records`` (the case evidence
row's hash results, ``[]`` without a case) and ``processing_scope`` (T-023); a run reviewed only in
the case DB lists at least one audit input (the case DB, path + SHA-256). Synthetic data only.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from rapidtriage import __version__
from rapidtriage.api.app import create_app, runops
from rapidtriage.api.app.case_workspace import CaseWorkspace
from rapidtriage.core.jobs import RunJobStore
from rapidtriage.core.sample_case import build_sample_evidence
from rapidtriage.core.submission import compute_hashes
from tests.test_e01_recorded_hash import MD5, SHA1, build_ewf1_segment, digest_data
from tests.test_rapidtriage_case_intake import write_run

TOKEN = "r8-report-metadata-token"
METADATA_KEYS = ("tool_version", "evidence_records", "processing_scope")


class ReportMetadataCaseRunTests(unittest.TestCase):
    """A real run on synthetic evidence, linked to a case, reviewed only in the case DB."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        base = Path(cls._tmp.name)
        evidence = base / "evidence"
        build_sample_evidence(evidence)
        cls.store = RunJobStore()
        app = create_app(cls.store, auth_token=TOKEN, cases_db_path=base / "ws" / "rapidtriage-cases.db")
        cls.client = TestClient(app, headers={"X-RapidTriage-Token": TOKEN})
        response = cls.client.post(
            "/api/runs",
            json={"root": str(evidence), "mode": "fraud", "output_dir": str(base / "out"), "read_only": True, "wait": True},
        )
        assert response.status_code == 202, response.text
        cls.run_id = response.json()["run_id"]
        case = cls.client.post("/api/cases", json={"case_number": "2026-T182", "examiner": "검사관"})
        assert case.status_code == 201, case.text
        cls.case_id = case.json()["case"]["case_id"]
        added = cls.client.post(
            f"/api/cases/{cls.case_id}/evidence",
            json={"evidence_number": "E-01", "source_type": "folder", "path": str(evidence)},
        )
        assert added.status_code == 201, added.text
        cls.citation_id = added.json()["evidence"]["citation_id"]
        linked = cls.client.post(
            f"/api/cases/{cls.case_id}/runs/link",
            json={"run_id": cls.run_id, "evidence_citation_id": cls.citation_id},
        )
        assert linked.status_code == 201, linked.text
        ensure = cls.client.post(f"/api/runs/{cls.run_id}/case-db/ensure", json={})
        assert ensure.status_code == 200, ensure.text
        cls.database = ensure.json()["database"]
        marked = cls.client.post(
            "/api/case-db/review",
            json={"database": cls.database, "case_id": ensure.json()["case_id"], "target_type": "document",
                  "target_id": "a", "status": "relevant", "include_in_report": True},
        )
        assert marked.status_code == 200, marked.text
        output_dir = Path(cls.client.get(f"/api/runs/{cls.run_id}").json()["summary"]["output_dir"])
        assert not (output_dir / "rapidtriage-case.json").exists()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.close()
        cls._tmp.cleanup()

    def export_report(self) -> tuple[dict, dict]:
        with mock.patch.object(runops, "build_case_report_markdown", wraps=runops.build_case_report_markdown) as build:
            response = self.client.post(f"/api/runs/{self.run_id}/case-report", json={})
        self.assertEqual(response.status_code, 200, response.text)
        build.assert_called_once()
        return response.json(), dict(build.call_args.kwargs["metadata"])

    def test_report_metadata_has_the_three_keys(self) -> None:
        _, metadata = self.export_report()
        for key in METADATA_KEYS:
            self.assertIn(key, metadata)
        self.assertEqual(metadata["tool_version"], __version__)
        job = self.store.get(self.run_id)
        self.assertEqual(metadata["processing_scope"], runops.run_report_context(job)["scope"])
        self.assertIsInstance(metadata["processing_scope"], dict)
        records = metadata["evidence_records"]
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual((record["evidence_number"], record["citation_id"]), ("E-01", self.citation_id))
        self.assertEqual(record["hash_status"], "not-requested")
        self.assertEqual((record["segments"], record["recorded_acquisition_hash"]), ([], None))
        json.dumps(metadata, ensure_ascii=False)  # serialisable as written into exports

    def test_case_db_only_review_lists_an_audit_input(self) -> None:
        payload, _ = self.export_report()
        audit = json.loads(Path(payload["audit"]).read_text(encoding="utf-8"))
        inputs = audit["provenance"]["input_files"]
        self.assertGreaterEqual(len(inputs), 1)
        row = next(item for item in inputs if item["label"] == "case-db")
        self.assertEqual(Path(row["path"]).resolve(), Path(self.database).resolve())
        self.assertIn(compute_hashes(Path(self.database))["sha256"], json.dumps(row))
        self.assertEqual(audit["tool_version"], __version__)


class EvidenceRecordsTests(unittest.TestCase):
    """``CaseWorkspace.run_evidence_records`` on a synthetic two-segment E01 with a recorded hash."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name)
        evidence = base / "evidence"
        evidence.mkdir()
        self.image = evidence / "disk.E01"
        self.image.write_bytes(build_ewf1_segment([("header", b"h"), ("next", b"")]))
        self.second = evidence / "disk.E02"
        self.second.write_bytes(build_ewf1_segment([("digest", digest_data()), ("done", b"")], segment_number=2))
        self.store = RunJobStore()
        app = create_app(self.store, auth_token=TOKEN, cases_db_path=base / "ws" / "rapidtriage-cases.db")
        self.client = TestClient(app, headers={"X-RapidTriage-Token": TOKEN})
        self.addCleanup(self.client.close)
        self.workspace: CaseWorkspace = app.state.case_workspace
        run_dir = base / "run"
        write_run(run_dir, self.image)
        self.run_id = self.store.import_completed_run(run_dir).run_id

    def test_records_carry_segments_and_recorded_hash(self) -> None:
        self.assertEqual(self.workspace.run_evidence_records(self.run_id), [])  # no workspace DB yet
        self.assertFalse(self.workspace.path().exists())  # and none was created for the report
        case_id = self.client.post("/api/cases", json={"case_number": "2026-T182-E01"}).json()["case"]["case_id"]
        added = self.client.post(
            f"/api/cases/{case_id}/evidence",
            json={"evidence_number": "E-01", "source_type": "e01", "path": str(self.image),
                  "verify_hash": True, "expected_hash": MD5.hex()},
        )
        self.assertEqual(added.status_code, 201, added.text)
        self.workspace.join_hash_jobs()
        self.assertEqual(self.workspace.run_evidence_records(self.run_id), [])  # run not linked: no case
        linked = self.client.post(
            f"/api/cases/{case_id}/runs/link",
            json={"run_id": self.run_id, "evidence_citation_id": added.json()["evidence"]["citation_id"]},
        )
        self.assertEqual(linked.status_code, 201, linked.text)
        [record] = self.workspace.run_evidence_records(self.run_id)
        self.assertEqual((record["display_name"], record["size_bytes"]), ("disk.E01", self.image.stat().st_size))
        self.assertEqual(record["hash_status"], "computed")
        self.assertEqual(record["hash_scope"], "ewf-container-segment-bytes")
        self.assertEqual(
            [(segment["name"], segment["sha256"]) for segment in record["segments"]],
            [(path.name, hashlib.sha256(path.read_bytes()).hexdigest()) for path in (self.image, self.second)],
        )
        self.assertEqual(
            record["recorded_acquisition_hash"], {"md5": MD5.hex(), "sha1": SHA1.hex(), "reason": "", "incomplete": False}
        )
        metadata = runops.run_report_metadata({"scope": {"axes": []}}, [record])
        self.assertEqual(set(metadata), set(METADATA_KEYS))
        self.assertEqual(runops.run_report_metadata({}, None)["evidence_records"], [])

    def test_unreadable_workspace_gives_no_records(self) -> None:
        self.client.post("/api/cases", json={"case_number": "2026-T182-X"})
        with mock.patch.object(type(self.workspace.intake), "get_snapshot", side_effect=OSError("locked")):
            self.assertEqual(self.workspace.run_evidence_records(self.run_id), [])


if __name__ == "__main__":
    unittest.main()
