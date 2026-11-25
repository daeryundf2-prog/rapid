"""D26 practitioner review: submission of review marks, generated sources and hand-off.

- Item 1: review marks saved through the case-DB review path (the V2 review
  board) with "include in report" reach the default case report (MD, HTML,
  DOCX, PDF), the submission manifest and the reviewer bundle; the review
  counts, the manifest and the report agree. A mark the submission cannot
  carry stops the report and the bundle with a Korean reason naming it,
  never a report with the item silently missing.
- Item 2: the alternate bookmark path (``/bookmarks``) accepts the product's
  own EventLog and timeline JSON, including a run with skipped tasks
  (``inputs_partial``); every generated bookmark source validates against
  its schema.
- Item 3: ``run --replay-audit`` carries the original run's review decisions
  (case-DB marks and case-JSON bookmarks: status, tags, note, report flag)
  into the replay, checking each row's content, and the audit links the
  original image (``--source-image``) by SHA-256.
"""

from __future__ import annotations

import hashlib
import io
import json
import shutil
import sqlite3
import struct
import tempfile
import unittest
import zipfile
from contextlib import closing, redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

from rapidtriage.cli import main
from rapidtriage.core.case import (
    CASE_SOURCE_SCHEMAS,
    CaseBookmarkError,
    load_source_payload,
    source_row_sha256,
)
from rapidtriage.core.schema_validation import load_schema, validate
from rapidtriage.core.submission import build_submission_manifest
from tests.test_d16_ntfs_usb import HiveWriter, Key, storage, usb
from tests.test_parser_quality_eventlog import Event, EvtxWriter, filetime, u32, wstr
from tests.test_parser_quality_prefetch_lnk import (
    build_lnk,
    build_scca,
    link_info_local,
)

HAS_FASTAPI = True
try:
    from fastapi.testclient import TestClient  # noqa: F401
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

if HAS_FASTAPI:
    from rapidtriage.core.jobs import RunJobStore
    from tests.test_rapidtriage_api import api_test_client

# The review skipped the two messenger tasks: the timeline then carries inputs_partial.
RUN_ARGS = ["--mode", "fraud", "--skip-task", "kakaotalk-windows", "--skip-task", "kakaotalk-macos"]

# (artifact kind, row index, note) — the review's ten report items.
NOTES = [
    ("eventlog", 0, "로컬 대화형 로그온. ROLE-A, 15:01 KST, 4624 유형 2, 활성 레코드 81."),
    ("eventlog", 1, "원격 대화형 로그온. ROLE-B, 15:08 KST, 4624 유형 10, 활성 레코드 82."),
    ("eventlog", 3, "복원 후보. ROLE-B 레코드 51은 슬랙에서 검출됐다."),
    ("windows-registry", 11, "USB 저장장치 Flash26, VID 1234, PID 0026, 인스턴스 UNIT26."),
    ("windows-prefetch", 0, "EDITOR.EXE 실행 흔적. Prefetch 카운트 1."),
    ("windows-prefetch", 2, "VIEWER.EXE 실행 흔적. Prefetch 카운트 1."),
    ("recent-files", 0, "최근 바로가기 대상 draft.txt, 대상 접근 필드 15:16 KST."),
    ("windows-filesystem", 0, "draft.txt 휴지통 이동 기록, 대응 본문 6바이트."),
    ("windows-filesystem", 1, "missing.txt 휴지통 이동 기록, 대응 본문 없음."),
    ("eventlog", 2, "보안 감사 로그 지우기 이벤트 1102, 활성 레코드 83."),
]


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
    """The review's ten selected files (synthetic Windows triage set)."""
    writer = EvtxWriter()
    writer.build_chunk([_event(81, 1, 2), _event(82, 8, 10), _event(83, 25)], slack=[_event(51, 0, 10)])
    files = {"Windows/System32/winevt/Logs/Security.evtx": writer.file_bytes()}
    hive = Key("ROOT")
    hive.path("Select").value("Current", 4, (1).to_bytes(4, "little"))
    usb(hive, 1, "0026", "UNIT26", 26)
    storage(hive, 1, "Flash26", "UNIT26", 26)
    files["Windows/System32/config/SYSTEM"] = HiveWriter().build(hive)
    files["Windows/INF/setupapi.dev.log"] = (
        b">>>  [Device Install - USB\\VID_1234&PID_0026\\UNIT26]\r\n"
        b">>>  2026/11/20 15:10:00.000: Section start\r\n"
        b"<<<  [2026/11/20 15:10:01.000: Section end]\r\n<<<  [Exit Status(0x00000000)]\r\n"
    )
    for name, minute in (("EDITOR", 12), ("VIEWER", 14)):
        exe = name + ".EXE"
        files[f"Windows/Prefetch/{exe}-00000026.pf"] = build_scca(
            executable=exe, paths=["\\TOOLS\\" + exe], run_times=[_when(minute)], run_count_c8=1
        )
    for name, minute in (("draft.txt", 16), ("ledger.txt", 18)):
        link = link_info_local(26, "D26", "C:\\docs\\" + name, "")
        files["Users/ROLE-A/AppData/Roaming/Microsoft/Windows/Recent/" + name + ".lnk"] = build_lnk(
            link, created=_when(0), accessed=_when(minute), modified=_when(5)
        )
    recycle = "$Recycle.Bin/S-1-5-21-1-2-3-1001/"
    for code, name, size, minute in (("000026", "draft.txt", 6, 21), ("000027", "missing.txt", 40, 23)):
        original = ("C:\\docs\\" + name + "\0").encode("utf-16le")
        files[recycle + "$I" + code + ".txt"] = struct.pack("<QQQI", 2, size, filetime(_when(minute)), len(original) // 2) + original
    files[recycle + "$R000026.txt"] = b"draft\n"
    return files


def write_selection(root: Path) -> None:
    for relative, blob in d26_selection().items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob)


def run_cli(*args: str) -> int:
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        return main(["run", *args])


def import_and_mark(client, output_dir: Path) -> tuple[str, dict[str, str]]:
    """Import a run and save the ten review marks through the case-DB path."""
    response = client.post("/api/runs/import", json={"output_dir": str(output_dir)})
    assert response.status_code in (200, 201), response.text
    run_id = response.json().get("run_id") or response.json()["run"]["run_id"]
    counts = client.get(f"/api/runs/{run_id}/review-counts").json()
    handle = {"database": counts["database"], "case_id": counts["case_id"]}
    for number, (kind, index, note) in enumerate(NOTES, start=1):
        response = client.post(
            "/api/case-db/review-batch",
            json={
                **handle,
                "run_id": run_id,
                "targets": [{"collection": "artifacts", "kind": kind, "locator": f"/artifacts/{index}"}],
                "add_tags": ["북마크"],
                "note": note,
                "reviewer": "ROLE-EXAMINER",
                "status": "needs-review" if number == 3 else "relevant",
                "include_in_report": True,
            },
        )
        assert response.status_code == 200 and response.json()["updated_count"] == 1, response.text
    return run_id, handle


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for RapidTriage API tests")
class ReviewMarkSubmissionTests(unittest.TestCase):
    """Item 1: the ten marked rows reach every default submission output."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        base = Path(cls.temp.name)
        cls.selected = base / "selected"
        write_selection(cls.selected)
        cls.output_dir = base / "run"
        assert run_cli(str(cls.selected), "--output-dir", str(cls.output_dir), *RUN_ARGS) == 0
        cls.client = api_test_client(RunJobStore(), case_db_roots=[cls.temp.name])
        cls.run_id, cls.handle = import_and_mark(cls.client, cls.output_dir)
        cls.base = f"/api/runs/{cls.run_id}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.close()
        cls.temp.cleanup()

    def test_counts_manifest_report_and_bundle_carry_every_marked_row(self) -> None:
        counts = self.client.get(f"{self.base}/review-counts").json()
        self.assertEqual(counts["report_candidates"], 10)

        manifest = self.client.get(f"{self.base}/submission-manifest").json()
        self.assertEqual(manifest["summary"]["report_candidate_count"], 10)
        self.assertEqual(manifest["summary"]["hashed_item_count"], 10)
        self.assertEqual(manifest["summary"]["missing_count"], 0)
        self.assertEqual(manifest["skipped"], [])
        validate(manifest, load_schema("submission-manifest.schema.json"))
        notes = sorted(item["note"] for item in manifest["items"])
        self.assertEqual(notes, sorted(note for _kind, _index, note in NOTES))
        # Each item cites its case-DB mark and the exact output row.
        for item in manifest["items"]:
            self.assertTrue(item["reference"]["case_db"]["citation_id"])
            self.assertRegex(item["reference"]["row_sha256"], "^[0-9a-f]{64}$")
        evtx = [item for item in manifest["items"] if item["evidence"]["name"] == "Security.evtx"]
        self.assertEqual(len(evtx), 4)

        response = self.client.post(f"{self.base}/case-report", json={"case_number": "D26", "investigator": "ROLE-EXAMINER"})
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        markdown = payload["markdown"]
        self.assertIn("- 검토 항목 수: 10", markdown)
        self.assertIn("- 보고서 포함 후보 수: 10", markdown)
        self.assertIn("- 해시 산출 항목 수: 10", markdown)
        html = Path(payload["exports"]["html"]).read_text(encoding="utf-8")
        with zipfile.ZipFile(payload["exports"]["docx"]) as archive:
            docx = archive.read("word/document.xml").decode("utf-8")
        pdf = Path(payload["exports"]["pdf"]).read_bytes().decode("latin-1")
        for _kind, _index, note in NOTES:
            self.assertEqual(markdown.count(note), 1, note)
            self.assertEqual(html.count(note), 1, note)
            self.assertEqual(docx.count(note), 1, note)
            self.assertIn(note[:8].encode("utf-16-be").hex().upper(), pdf, note)

        bundle = self.client.post(f"{self.base}/reviewer-bundle", json={})
        self.assertEqual(bundle.status_code, 200, bundle.text)
        bundle_manifest = json.loads(Path(bundle.json()["outputs"]["manifest"]).read_text(encoding="utf-8"))
        self.assertEqual(bundle_manifest["summary"]["hashed_item_count"], 10)
        bundle_report = Path(bundle.json()["outputs"]["report"]).read_text(encoding="utf-8")
        for _kind, _index, note in NOTES:
            self.assertEqual(bundle_report.count(note), 1, note)
        self.assertEqual(self.client.get(f"{self.base}/reviewer-bundle/file").status_code, 200)

    def test_mark_without_citable_evidence_file_stops_report_and_bundle(self) -> None:
        # Row 5 of the EventLog output is a logon-session row whose path is the
        # input folder: there is no evidence file to hash for it.
        mark = {
            **self.handle,
            "run_id": self.run_id,
            "targets": [{"collection": "artifacts", "kind": "eventlog", "locator": "/artifacts/5"}],
            "note": "세션 행",
            "status": "relevant",
            "include_in_report": True,
        }
        self.assertEqual(self.client.post("/api/case-db/review-batch", json=mark).status_code, 200)
        try:
            manifest = self.client.get(f"{self.base}/submission-manifest").json()
            self.assertEqual(manifest["summary"]["report_candidate_count"], 11)
            self.assertEqual(manifest["summary"]["missing_count"], 1)
            self.assertEqual(manifest["skipped"][0]["reason"], "missing-or-not-file")
            self.assertEqual(manifest["skipped"][0]["note"], "세션 행")
            report = self.client.post(f"{self.base}/case-report", json={})
            self.assertEqual(report.status_code, 409, report.text)
            detail = report.json()["detail"]
            self.assertIn("11건 중 1건", detail)
            self.assertIn("세션 행", detail)
            self.assertIn("파일이 아니거나 없음", detail)
            bundle = self.client.post(f"{self.base}/reviewer-bundle", json={})
            self.assertEqual(bundle.status_code, 409, bundle.text)
            self.assertIn("세션 행", bundle.json()["detail"])
        finally:
            mark.update(include_in_report=False, note="", status="unreviewed")
            self.assertEqual(self.client.post("/api/case-db/review-batch", json=mark).status_code, 200)
        self.assertEqual(self.client.post(f"{self.base}/case-report", json={}).status_code, 200)

    def test_alternate_bookmark_path_accepts_generated_eventlog_and_timeline_rows(self) -> None:
        # Item 2: the run skipped two tasks, so the timeline carries inputs_partial.
        timeline = json.loads((self.output_dir / "rapidtriage-timeline.json").read_text(encoding="utf-8"))
        self.assertTrue(timeline["inputs_partial"])
        live = self.client.post(
            f"{self.base}/bookmarks",
            json={"source": "artifacts:eventlog", "pointer": "/artifacts/0", "note": "원본 이벤트", "bookmark_id": "D26-EVT"},
        )
        self.assertEqual(live.status_code, 200, live.text)
        recovered_index = next(
            index for index, event in enumerate(timeline["events"]) if event["event_type"] == "eventlog-recovery-candidate"
        )
        recovered = self.client.post(
            f"{self.base}/bookmarks",
            json={"source": "timeline", "pointer": f"/events/{recovered_index}", "note": "복원 후보", "bookmark_id": "D26-TL"},
        )
        self.assertEqual(recovered.status_code, 200, recovered.text)
        bookmarks = {item["bookmark_id"]: item for item in recovered.json()["case"]["bookmarks"]}
        self.assertEqual(bookmarks["D26-EVT"]["snapshot"]["record_state"], "live")
        self.assertEqual(set(bookmarks), {"D26-EVT", "D26-TL"})
        case_path = Path(recovered.json()["case_path"])
        try:
            validate(json.loads(case_path.read_text(encoding="utf-8")), load_schema("case.schema.json"))
        finally:
            case_path.unlink()

    def test_schema_refusal_is_korean_with_row_position_and_reason(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            timeline = json.loads((self.output_dir / "rapidtriage-timeline.json").read_text(encoding="utf-8"))
            timeline["events"][2]["unknown_field"] = 1
            source = Path(temp) / "timeline.json"
            source.write_text(json.dumps(timeline), encoding="utf-8")
            with self.assertRaises(CaseBookmarkError) as refused:
                load_source_payload(source)
        message = str(refused.exception)
        self.assertIn("출력 스키마 검증에 실패해 저장하지 않았습니다", message)
        self.assertIn("events 행 2번 ($.events[2])", message)
        self.assertIn("스키마에 정의되지 않은 필드 — unexpected property 'unknown_field'", message)


class ExtraRowReMatchTests(unittest.TestCase):
    """#34's submission re-check re-matches a moved row in the extra row arrays too."""

    def test_inventory_bookmark_pointer_is_corrected_after_the_output_shifts(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            evidence = base / "evidence.txt"
            evidence.write_text("synthetic", encoding="utf-8")
            row = {"path": str(evidence), "name": "evidence.txt", "size": 9}
            files_json = base / "files.json"
            files_json.write_text(json.dumps({"command": "files", "candidates": [], "inventory": [{"path": "a"}, row]}))
            bookmark = {
                "bookmark_id": "INV-1",
                "summary": "evidence.txt",
                "note": "inventory row",
                "review": {"status": "relevant", "include_in_report": True},
                "reference": {
                    "command": "files",
                    "file": str(files_json),
                    "pointer": "/inventory/1",
                    "stable_key": "k",
                    "row_sha256": source_row_sha256(row),
                },
                "snapshot": {"path": str(evidence)},
            }
            # The output is regenerated with one more inventory row before it.
            files_json.write_text(
                json.dumps({"command": "files", "candidates": [], "inventory": [{"path": "a"}, {"path": "b"}, row]})
            )
            manifest = build_submission_manifest({"bookmarks": [bookmark]}, allowed_roots=[base])
        self.assertEqual(manifest["summary"]["missing_count"], 0)
        reference = manifest["items"][0]["reference"]
        self.assertEqual(reference["pointer"], "/inventory/2")
        self.assertEqual(reference["row_verification"]["status"], "pointer-corrected")


class GeneratedSourceSchemaTests(unittest.TestCase):
    def test_every_generated_bookmark_source_validates_against_its_schema(self) -> None:
        # Skipped provider tasks (inputs_partial), then skipped stage tasks (plan_status).
        stage_skips = ["--skip-task", "docs", "--skip-task", "files", "--skip-task", "timeline", "--skip-task", "indicators"]
        for label, extra in (("provider-skips", []), ("stage-skips", stage_skips)):
            with self.subTest(run=label), tempfile.TemporaryDirectory() as temp:
                base = Path(temp)
                write_selection(base / "selected")
                output_dir = base / "run"
                self.assertEqual(run_cli(str(base / "selected"), "--output-dir", str(output_dir), *RUN_ARGS, *extra), 0)
                checked = set()
                for path in sorted(output_dir.rglob("*.json")):
                    try:
                        payload = json.loads(path.read_text(encoding="utf-8"))
                    except ValueError:
                        continue
                    command = payload.get("command") if isinstance(payload, dict) else None
                    if command in CASE_SOURCE_SCHEMAS:
                        with self.subTest(run=label, output=path.name):
                            validate(payload, load_schema(CASE_SOURCE_SCHEMAS[command]))
                        checked.add(path.name)
                self.assertTrue(
                    {"rapidtriage-artifacts-eventlog.json", "rapidtriage-timeline.json", "rapidtriage-indicators.json"} <= checked
                )
                manifest = json.loads((output_dir / "rapidtriage-manifest.json").read_text(encoding="utf-8"))
                self.assertTrue(manifest["inputs_partial"])
                validate(manifest, load_schema("manifest.schema.json"))
                if extra:
                    timeline = json.loads((output_dir / "rapidtriage-timeline.json").read_text(encoding="utf-8"))
                    self.assertEqual(timeline["plan_status"], "skipped")


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for RapidTriage API tests")
class ReplayHandOffTests(unittest.TestCase):
    """Item 3: a replay from the audit carries the review decisions and the image link."""

    def test_replay_carries_review_decisions_and_verifies_source_image(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            image = base / "D26.img"
            image.write_bytes(b"D26 synthetic container\0" * 512)
            image_sha256 = hashlib.sha256(image.read_bytes()).hexdigest()
            selected = base / "A" / "selected"
            write_selection(selected)
            original = base / "A" / "run"
            self.assertEqual(
                run_cli(str(selected), "--output-dir", str(original), "--source-image", str(image), *RUN_ARGS), 0
            )
            audit_path = original / "rapidtriage-run-audit.json"
            audit = json.loads(audit_path.read_text(encoding="utf-8"))
            self.assertEqual(audit["provenance"]["options"]["source_image"]["sha256"], image_sha256)
            self.assertEqual(audit["provenance"]["options"]["source_image"]["path"], str(image.resolve()))

            client = api_test_client(RunJobStore(), case_db_roots=[temp])
            with client:
                run_id, _handle = import_and_mark(client, original)
                bookmark = client.post(
                    f"/api/runs/{run_id}/bookmarks",
                    json={"source": "timeline", "pointer": "/events/0", "note": "타임라인 첫 행", "include_in_report": True},
                )
                self.assertEqual(bookmark.status_code, 200, bookmark.text)

            # The colleague: another root for the selection, the image moved.
            colleague = base / "colleague"
            shutil.copytree(selected, colleague / "selected")
            moved_image = colleague / "D26.img"
            shutil.copyfile(image, moved_image)
            replay = colleague / "run"
            with self.assertRaises(SystemExit):
                # The recorded image path still exists but a tampered copy must stop the replay.
                tampered = colleague / "tampered.img"
                tampered.write_bytes(image.read_bytes()[:-1] + b"X")
                run_cli(
                    str(colleague / "selected"), "--replay-audit", str(audit_path),
                    "--source-image", str(tampered), "--output-dir", str(replay),
                )
            self.assertFalse(replay.exists())
            self.assertEqual(
                run_cli(
                    str(colleague / "selected"), "--replay-audit", str(audit_path),
                    "--source-image", str(moved_image), "--output-dir", str(replay),
                ),
                0,
            )
            replay_audit = json.loads((replay / "rapidtriage-run-audit.json").read_text(encoding="utf-8"))
            self.assertEqual(replay_audit["provenance"]["options"]["source_image"]["sha256"], image_sha256)
            self.assertEqual(replay_audit["provenance"]["options"]["source_image"]["path"], str(moved_image.resolve()))
            self.assertEqual(replay_audit["provenance"]["options"]["replay_of"]["output_dir"], str(original.resolve()))

            carryover = json.loads((replay / "rapidtriage-review-carryover.json").read_text(encoding="utf-8"))
            self.assertEqual(carryover["summary"]["case_db_marks"], {"found": 10, "carried": 10, "not_carried": 0})
            self.assertEqual(carryover["summary"]["case_bookmarks"], {"found": 1, "carried": 1, "not_carried": 0})

            with closing(sqlite3.connect(replay / "rapidtriage-case.db")) as connection:
                rows = connection.execute(
                    "SELECT note, status, include_in_report, tags_json FROM review_mark WHERE include_in_report = 1"
                ).fetchall()
            self.assertEqual(sorted(row[0] for row in rows), sorted(note for _kind, _index, note in NOTES))
            self.assertEqual(sum(1 for row in rows if row[1] == "needs-review"), 1)
            self.assertTrue(all("북마크" in json.loads(row[3]) for row in rows))
            case_payload = json.loads((replay / "rapidtriage-case.json").read_text(encoding="utf-8"))
            self.assertEqual([item["note"] for item in case_payload["bookmarks"]], ["타임라인 첫 행"])
            self.assertTrue(case_payload["bookmarks"][0]["reference"]["file"].startswith(str(replay.resolve())))

            client = api_test_client(RunJobStore(), case_db_roots=[temp])
            with client:
                response = client.post("/api/runs/import", json={"output_dir": str(replay)})
                replay_id = response.json().get("run_id") or response.json()["run"]["run_id"]
                report = client.post(f"/api/runs/{replay_id}/case-report", json={})
                self.assertEqual(report.status_code, 200, report.text)
                for note in [*(note for _kind, _index, note in NOTES), "타임라인 첫 행"]:
                    self.assertEqual(report.json()["markdown"].count(note), 1, note)

    def test_replay_stops_when_recorded_image_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            image = base / "D26.img"
            image.write_bytes(b"D26 synthetic container")
            write_selection(base / "selected")
            original = base / "run"
            self.assertEqual(
                run_cli(str(base / "selected"), "--output-dir", str(original), "--source-image", str(image), *RUN_ARGS), 0
            )
            image.unlink()
            stderr = io.StringIO()
            with redirect_stderr(stderr), redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
                main(["run", str(base / "selected"), "--replay-audit", str(original / "rapidtriage-run-audit.json"),
                      "--output-dir", str(base / "replay")])
            self.assertIn("--source-image", stderr.getvalue())
            self.assertIn("원본 이미지", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
