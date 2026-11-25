"""D26 practitioner review items 5 and 6 (synthetic D26 selection only).

- Item 5: a row filter a list endpoint does not support is a Korean 422 listing the
  supported filters, never a 200 with the unfiltered rows; responses echo
  ``applied_filters``; ``event_id`` (and the other event-log record fields) really
  filter ``GET /artifacts``; case-search hits name their row kind (``hit_type``).
- Item 6: a raw image the support check accepts registers as ``source_type: raw`` and
  its SHA-256 is verified like an export; the CLI run summary line reports the files
  scanned, the documents indexed / not indexed (with the reason) and the keyword
  matches, matching the run summary.
"""

from __future__ import annotations

import hashlib
import io
import json
import sqlite3
import struct
import tempfile
import unittest
from contextlib import closing, redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

from rapidtriage.cli import main, runops
from rapidtriage.core.run.markdown import apply_report_disclosures
from tests.test_d16_ntfs_usb import HiveWriter, Key, storage, usb
from tests.test_parser_quality_eventlog import Event, EvtxWriter, filetime, u32, wstr
from tests.test_parser_quality_prefetch_lnk import (
    build_lnk,
    build_scca,
    link_info_local,
)

HAS_FASTAPI = True
try:
    from fastapi.testclient import TestClient
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

if HAS_FASTAPI:
    from rapidtriage.api.app import create_app
    from rapidtriage.core.jobs import RunJobStore
    from tests.test_rapidtriage_api import api_test_client

TOKEN = "rapidtriage-test-token"


def _when(minute: int) -> datetime:
    return datetime(2026, 11, 20, 6, minute, tzinfo=timezone.utc)


def _event(record_id: int, minute: int, logon_type: int | None = None) -> Event:
    if logon_type is None:
        data = [("SubjectUserName", wstr("ROLE-A"))]
    else:
        data = [
            ("TargetUserName", wstr("ROLE-A" if logon_type == 2 else "ROLE-B")),
            ("TargetLogonId", wstr("0x21" if logon_type == 2 else "0x22")),
            ("LogonType", u32(logon_type)),
            ("IpAddress", wstr("-" if logon_type == 2 else "192.0.2.26")),
        ]
    return Event(
        record_id=record_id,
        event_id=1102 if logon_type is None else 4624,
        provider="Microsoft-Windows-Eventlog" if logon_type is None else "Microsoft-Windows-Security-Auditing",
        channel="Security",
        computer="SYNTHETIC",
        when=filetime(_when(minute)),
        data=data,
    )


def d26_selection() -> dict[str, bytes]:
    """The review's ten selected files: live 4624 #81/#82, live 1102 #83, slack 4624 #51, USB, Prefetch, LNK, $I/$R."""
    evtx = EvtxWriter()
    evtx.build_chunk([_event(81, 1, 2), _event(82, 8, 10), _event(83, 25)], slack=[_event(51, 0, 10)])
    rows = {"Windows/System32/winevt/Logs/Security.evtx": evtx.file_bytes()}
    hive = Key("ROOT")
    hive.path("Select").value("Current", 4, (1).to_bytes(4, "little"))
    usb(hive, 1, "0026", "UNIT26", 26)
    storage(hive, 1, "Flash26", "UNIT26", 26)
    rows["Windows/System32/config/SYSTEM"] = HiveWriter().build(hive)
    rows["Windows/INF/setupapi.dev.log"] = (
        b">>>  [Device Install - USB\\VID_1234&PID_0026\\UNIT26]\r\n"
        b">>>  2026/11/20 15:10:00.000: Section start\r\n"
        b"<<<  [2026/11/20 15:10:01.000: Section end]\r\n<<<  [Exit Status(0x00000000)]\r\n"
    )
    for name, minute in (("EDITOR", 12), ("VIEWER", 14)):
        exe = name + ".EXE"
        rows[f"Windows/Prefetch/{exe}-00000026.pf"] = build_scca(
            executable=exe, paths=["\\TOOLS\\" + exe], run_times=[_when(minute)], run_count_c8=1
        )
    for name, minute in (("draft.txt", 16), ("ledger.txt", 18)):
        link = link_info_local(26, "D26", "C:\\docs\\" + name, "")
        rows["Users/ROLE-A/AppData/Roaming/Microsoft/Windows/Recent/" + name + ".lnk"] = build_lnk(
            link, created=_when(0), accessed=_when(minute), modified=_when(5)
        )
    recycle = "$Recycle.Bin/S-1-5-21-1-2-3-1001/"
    for code, name, size, minute in (("000026", "draft.txt", 6, 21), ("000027", "missing.txt", 40, 23)):
        original = ("C:\\docs\\" + name + "\0").encode("utf-16le")
        rows[recycle + "$I" + code + ".txt"] = (
            struct.pack("<QQQI", 2, size, filetime(_when(minute)), len(original) // 2) + original
        )
    rows[recycle + "$R000026.txt"] = b"draft\n"
    return rows


def run_d26(base: Path) -> tuple[Path, str]:
    """Write the selection under ``base`` and run ``rapidtriage run --mode fraud``; (output dir, stdout)."""
    selected = base / "selected"
    for relative, data in d26_selection().items():
        target = selected / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    output = base / "run"
    stdout = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
        code = main(["run", str(selected), "--mode", "fraud", "--output-dir", str(output)])
    if code != 0:
        raise AssertionError(f"rapidtriage run exited {code}: {stdout.getvalue()}")
    return output, stdout.getvalue()


class D26RunMixin:
    @classmethod
    def setUpClass(cls) -> None:
        cls._temp = tempfile.TemporaryDirectory()
        cls.base = Path(cls._temp.name)
        cls.output, cls.stdout = run_d26(cls.base)
        cls.summary = json.loads((cls.output / "rapidtriage-run-summary.json").read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temp.cleanup()


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for RapidTriage API tests")
class D26RowFilterTests(D26RunMixin, unittest.TestCase):
    """Item 5: supported filters filter, unsupported ones are a 422, applied filters are echoed."""

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.client = api_test_client(RunJobStore(), case_db_roots=[str(cls.base)])
        imported = cls.client.post("/api/runs/import", json={"output_dir": str(cls.output)})
        if imported.status_code not in (200, 201):
            raise AssertionError(imported.text)
        body = imported.json()
        cls.run_id = body.get("run_id") or body["run"]["run_id"]
        cls.url = f"/api/runs/{cls.run_id}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.close()
        super().tearDownClass()

    def eventlog_rows(self, query: str) -> tuple[list[dict], dict]:
        response = self.client.get(f"{self.url}/artifacts?{query}")
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        return payload["artifacts"]["eventlog"]["artifacts"], payload

    def test_event_id_filter_returns_the_live_1102_record_and_echoes_it(self) -> None:
        baseline, base_payload = self.eventlog_rows("limit=30&kind=eventlog")
        self.assertEqual(len(baseline), 11)
        self.assertEqual(base_payload["applied_filters"], {"kind": ["eventlog"]})

        rows, payload = self.eventlog_rows("limit=30&kind=eventlog&artifact_type=eventlog-event&event_id=1102")
        self.assertEqual(len(rows), 1)
        details = rows[0]["details"]
        self.assertEqual(
            (details["event_id"], details["record_id"], details["evtx_record_state"]), ("1102", "83", "live")
        )
        self.assertEqual(
            payload["applied_filters"],
            {"kind": ["eventlog"], "artifact_type": ["eventlog-event"], "event_id": ["1102"]},
        )
        self.assertEqual(payload["artifacts"]["eventlog"]["pagination"]["fields"], {"event_id": ["1102"]})

        # The review's query: event records only (the live #83); the detection made
        # from it is a derived row, listed only when its artifact_type is asked for.
        rows, payload = self.eventlog_rows("limit=30&kind=eventlog&event_id=1102")
        self.assertEqual([(row["artifact_type"], row["details"]["record_id"]) for row in rows], [("eventlog-event", "83")])
        self.assertEqual(rows[0]["hit_type"], "artifact-record")
        self.assertEqual(
            payload["applied_filters"],
            {"kind": ["eventlog"], "artifact_type": ["eventlog-event"], "event_id": ["1102"]},
        )
        rows, _payload = self.eventlog_rows("limit=30&kind=eventlog&artifact_type=eventlog-detection&event_id=1102")
        self.assertEqual([(row["artifact_type"], row["hit_type"]) for row in rows], [("eventlog-detection", "detection")])
        self.assertTrue(all(row["hit_type"] for row in baseline))

    def test_record_state_filter_separates_the_slack_candidate(self) -> None:
        rows, _payload = self.eventlog_rows(
            "limit=30&kind=eventlog&artifact_type=eventlog-event&event_id=4624&evtx_record_state=live"
        )
        self.assertEqual(sorted(row["details"]["record_id"] for row in rows), ["81", "82"])
        rows, _payload = self.eventlog_rows("limit=30&kind=eventlog&evtx_record_state=slack-recovered")
        self.assertTrue(rows)
        self.assertTrue(all(row["details"]["record_id"] == "51" for row in rows))

    def test_unsupported_filter_is_a_korean_422_listing_supported_fields(self) -> None:
        response = self.client.get(f"{self.url}/artifacts?limit=30&kind=eventlog&eventid=1102")
        self.assertEqual(response.status_code, 422, response.text)
        detail = response.json()["detail"]
        self.assertEqual(detail["unsupported_filters"], ["eventid"])
        self.assertIn("event_id", detail["supported_filters"])
        self.assertIn("artifact_type", detail["supported_filters"])
        self.assertNotIn("limit", detail["supported_filters"])
        self.assertIn("지원하지 않는 조회 조건입니다: eventid", detail["message"])
        self.assertIn("event_id", detail["message"])

    def test_every_run_list_endpoint_rejects_unknown_filters_and_echoes_applied_ones(self) -> None:
        for path, supported in (
            ("timeline", "from"),
            ("files", "category"),
            ("docs", "matched"),
            ("indicators", None),
        ):
            with self.subTest(path=path):
                rejected = self.client.get(f"{self.url}/{path}?limit=5&event_id=1102")
                self.assertEqual(rejected.status_code, 422, rejected.text)
                detail = rejected.json()["detail"]
                self.assertEqual(detail["unsupported_filters"], ["event_id"])
                self.assertIn("지원하지 않는 조회 조건", detail["message"])
                if supported:
                    self.assertIn(supported, detail["supported_filters"])
                else:
                    self.assertEqual(detail["supported_filters"], [])
                plain = self.client.get(f"{self.url}/{path}?limit=5")
                self.assertEqual(plain.status_code, 200, plain.text)
                self.assertEqual(plain.json()["applied_filters"], {})
        filtered = self.client.get(f"{self.url}/files?limit=5&category=documents").json()
        self.assertEqual(filtered["applied_filters"], {"category": ["documents"]})
        docs = self.client.get(f"{self.url}/docs?limit=5&all=1&matched=0").json()
        self.assertEqual(docs["applied_filters"], {"all": ["1"], "matched": ["0"]})
        search = self.client.get(f"{self.url}/search?keyword=1102&event_id=1102")
        self.assertEqual(search.status_code, 422, search.text)
        self.assertIn("keyword", search.json()["detail"]["supported_filters"])


class D26CaseSearchHitTypeTests(D26RunMixin, unittest.TestCase):
    """Item 5: ``case-search -k 1102`` names what each of its hits is (matching unchanged)."""

    def test_case_search_hits_carry_their_row_kind(self) -> None:
        database = self.output / "rapidtriage-case.db"
        with closing(sqlite3.connect(database)) as connection:
            case_id = connection.execute("SELECT case_id FROM case_record ORDER BY case_id LIMIT 1").fetchone()[0]
        stdout = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            code = main(["case-search", str(database), "--case-id", case_id, "-k", "1102", "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(stdout.getvalue())
        matches = payload["matches"]
        by_kind = {match["kind"]: match["hit_type"] for match in matches}
        self.assertEqual(by_kind.get("eventlog-event"), "artifact-record")
        self.assertEqual(by_kind.get("eventlog-detection"), "detection")
        self.assertEqual(by_kind.get("eventlog-summary"), "summary")
        self.assertIn("timeline-event", by_kind.values())
        self.assertTrue(all(match["hit_type_label"] for match in matches))
        counts = payload["summary"]["hit_type_counts"]
        self.assertEqual(sum(counts.values()), payload["summary"]["match_count"])
        self.assertEqual(counts["artifact-record"], 1)


class D26ScanScopeSummaryTests(D26RunMixin, unittest.TestCase):
    """Item 6b: the CLI summary line and the report overview state the real scan scope."""

    def test_cli_summary_line_matches_the_run_summary(self) -> None:
        summary = self.summary["summary"]
        documents = self.summary["disclosures"]["documents"]
        self.assertEqual(summary["scanned_file_count"], 10)
        self.assertEqual(documents["not_indexed_status_counts"], {"binary-rejected": 2})
        expected = (
            f"Files scanned: {summary['scanned_file_count']}  "
            f"Doc candidates: {summary['document_candidate_count']}  "
            f"Docs indexed: {documents['indexed_with_text_count']}  "
            f"Docs not indexed: {summary['document_candidate_count'] - documents['indexed_with_text_count']}"
            " (binary-rejected 2)  "
            f"Docs keyword matches: {summary['document_match_count']}  "
            f"File candidates: {summary['file_candidate_count']}"
        )
        self.assertIn(expected, self.stdout.splitlines())
        self.assertIn("Files scanned: 10  Doc candidates: 4  Docs indexed: 2  Docs not indexed: 2", expected)
        self.assertNotIn("Docs matches:", self.stdout)

    def test_report_overview_states_scanned_files_and_unindexed_documents(self) -> None:
        report = (self.output / "rapidtriage-run-report.md").read_text(encoding="utf-8")
        self.assertIn("- 스캔 파일: 10", report)
        self.assertIn("- 문서 후보: 4 (텍스트 색인 2, 미색인 2 [binary-rejected 2], 암호화 0, 키워드 일치 0)", report)

    def test_summary_line_falls_back_without_per_status_split(self) -> None:
        payload = {
            "summary": {"scanned_file_count": 7, "document_candidate_count": 3, "document_match_count": 1,
                        "file_candidate_count": 2},
            "disclosures": {"documents": {"candidate_count": 3, "indexed_with_text_count": 1,
                                          "text_status_counts": {"ok": 1, "encrypted": 2}}},
        }
        self.assertEqual(
            runops.format_scan_scope_line(payload),
            "Files scanned: 7  Doc candidates: 3  Docs indexed: 1  Docs not indexed: 2 (encrypted 2)  "
            "Docs keyword matches: 1  File candidates: 2",
        )
        markdown = apply_report_disclosures("# r\n\n- Document matches: 1\n", {**payload, "plan": None})
        self.assertIn("- 스캔 파일: 7\n- 문서 후보: 3 (텍스트 색인 1, 미색인 2 [encrypted 2]", markdown)


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for RapidTriage API tests")
class D26RawImageIntakeTests(unittest.TestCase):
    """Item 6a: the raw image the support check accepts registers as ``raw`` and its hash is verified."""

    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.temp = Path(self._temp.name)
        app = create_app(RunJobStore(), auth_token=TOKEN, cases_db_path=self.temp / "workspace" / "rapidtriage-cases.db")
        self.client = TestClient(app, headers={"X-RapidTriage-Token": TOKEN})
        self.image = self.temp / "D26.img"
        self.image.write_bytes(b"\xeb\x3c\x90D26SYNTH" + bytes(range(256)) * 64)
        created = self.client.post("/api/cases", json={"case_number": "D26", "name": "D26 합성 사건"})
        self.assertEqual(created.status_code, 201, created.text)
        self.case_id = created.json()["case"]["case_id"]

    def tearDown(self) -> None:
        self.client.app.state.case_workspace.join_hash_jobs()
        self.client.close()
        self._temp.cleanup()

    def test_raw_image_registers_as_raw_and_hash_matches(self) -> None:
        check = self.client.post("/api/cases/evidence-check", json={"path": str(self.image)})
        self.assertEqual(check.status_code, 200, check.text)
        self.assertTrue(check.json()["ok"])
        self.assertEqual(check.json()["source_type"], "raw")
        typed = self.client.post("/api/cases/evidence-check", json={"path": str(self.image), "source_type": "raw"})
        self.assertTrue(typed.json()["ok"], typed.text)

        sha256 = hashlib.sha256(self.image.read_bytes()).hexdigest()
        url = f"/api/cases/{self.case_id}/evidence"
        added = self.client.post(url, json={"evidence_number": "E01-RAW", "source_type": "raw", "path": str(self.image),
                                            "verify_hash": True, "expected_hash": sha256})
        self.assertEqual(added.status_code, 201, added.text)
        self.assertEqual(added.json()["evidence"]["source_type"], "raw")
        self.client.app.state.case_workspace.join_hash_jobs()
        row = next(item for item in self.client.get(url).json()["evidence"] if item["evidence_number"] == "E01-RAW")
        self.assertEqual(row["hash_status"], "matched", row)
        self.assertEqual(row["hashes"]["sha256"], sha256)

    def test_raw_kind_needs_a_raw_image_and_split_sets_take_no_expected_hash(self) -> None:
        url = f"/api/cases/{self.case_id}/evidence"
        text = self.temp / "notes.txt"
        text.write_text("not an image", encoding="utf-8")
        wrong = self.client.post(url, json={"evidence_number": "E-02", "source_type": "raw", "path": str(text)})
        self.assertEqual(wrong.status_code, 422)
        self.assertIn("RAW 증거는", wrong.json()["detail"])
        first = self.temp / "D26.001"
        first.write_bytes(b"A" * 512)
        (self.temp / "D26.002").write_bytes(b"B" * 512)
        split = self.client.post(url, json={"evidence_number": "E-03", "source_type": "raw", "path": str(first),
                                            "verify_hash": True, "expected_hash": "0" * 64})
        self.assertEqual(split.status_code, 422, split.text)
        self.assertIn("분할 RAW", split.json()["detail"])
        computed = self.client.post(url, json={"evidence_number": "E-04", "source_type": "raw", "path": str(first),
                                               "verify_hash": True})
        self.assertEqual(computed.status_code, 201, computed.text)


if __name__ == "__main__":
    unittest.main()
