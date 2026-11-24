"""D26 item 4: lawyer-facing outputs must not misread activity time, record state or body presence.

Synthetic D26 selected folder: Security.evtx with live 4624 type 2 (#81), live 4624 type 10 (#82),
live 1102 (#83) and a slack-recovered 4624 type 10 (#51); SYSTEM hive with USBSTOR Flash26;
setupapi.dev.log whose section start has no UTC offset; two Prefetch files; two LNK files;
Recycle Bin $I000026 (draft.txt, $R body present) and $I000027 (missing.txt, no $R body).
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import struct
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from rapidtriage.cli import main
from rapidtriage.core.case_report import build_case_report_markdown
from tests.test_d16_ntfs_usb import HiveWriter, Key, storage, usb
from tests.test_parser_quality_eventlog import Event, EvtxWriter, filetime, u32, wstr
from tests.test_parser_quality_prefetch_lnk import (
    build_lnk,
    build_scca,
    link_info_local,
)


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


def write_d26_fixture(root: Path) -> None:
    evtx = EvtxWriter()
    evtx.build_chunk([_event(81, 1, 2), _event(82, 8, 10), _event(83, 25)], slack=[_event(51, 0, 10)])
    rows: dict[str, bytes] = {"Windows/System32/winevt/Logs/Security.evtx": evtx.file_bytes()}
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
        rows[f"Users/ROLE-A/AppData/Roaming/Microsoft/Windows/Recent/{name}.lnk"] = build_lnk(
            link, created=_when(0), accessed=_when(minute), modified=_when(5)
        )
    recycle = "$Recycle.Bin/S-1-5-21-1-2-3-1001/"
    for code, name, size, minute in (("000026", "draft.txt", 6, 21), ("000027", "missing.txt", 40, 23)):
        original = ("C:\\docs\\" + name + "\0").encode("utf-16le")
        rows[f"{recycle}$I{code}.txt"] = struct.pack("<QQQI", 2, size, filetime(_when(minute)), len(original) // 2) + original
    rows[f"{recycle}$R000026.txt"] = b"draft\n"
    for relative, data in rows.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


class D26ReadingRunTests(unittest.TestCase):
    """One CLI run of the D26 fixture; every test reads its outputs."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        base = Path(cls._tmp.name)
        selected = base / "selected"
        write_d26_fixture(selected)
        cls.out = base / "run"
        home = base / "home"
        home.mkdir()
        with mock.patch.dict(os.environ, {"HOME": str(home)}), contextlib.redirect_stdout(io.StringIO()):
            code = main(["run", str(selected), "--mode", "fraud", "--output-dir", str(cls.out)])
        assert code == 0, code
        cls.timeline = json.loads((cls.out / "rapidtriage-timeline.json").read_text(encoding="utf-8"))
        cls.run_report = (cls.out / "rapidtriage-run-report.md").read_text(encoding="utf-8")
        cls.timeline_report = (cls.out / "rapidtriage-timeline-report.md").read_text(encoding="utf-8")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def artifacts(self, kind: str) -> list[dict[str, object]]:
        payload = json.loads((self.out / "artifacts" / f"rapidtriage-artifacts-{kind}.json").read_text(encoding="utf-8"))
        return payload["artifacts"]

    # --- logons ---------------------------------------------------------------

    def test_eventlog_summary_counts_recovered_logon_apart_from_active(self) -> None:
        summary = next(row for row in self.artifacts("eventlog") if row["artifact_type"] == "eventlog-summary")["details"]
        logons = summary["logon_success_counts"]
        self.assertEqual(logons["active_count"], 2)
        self.assertEqual(logons["recovery_candidate_count"], 1)
        self.assertCountEqual(logons["active_logon_type_counts"], [{"value": "2", "count": 1}, {"value": "10", "count": 1}])
        self.assertEqual(logons["recovery_candidate_logon_type_counts"], [{"value": "10", "count": 1}])
        # The recovered type-10 logon's RDP detection is not an active RDP logon.
        self.assertIn({"value": "RT-EVTX-RDP-LOGON", "count": 1}, summary["detection_rule_counts"])
        self.assertEqual(summary["recovery_candidate_detection_rule_counts"], [{"value": "RT-EVTX-RDP-LOGON", "count": 1}])

    def test_reports_state_active_and_recovered_logons_separately(self) -> None:
        expected = "로그온 성공(4624): 활성 2건 (유형 2: 1건, 유형 10: 1건) / 복원 후보 1건 (유형 10: 1건)"
        self.assertIn(expected, self.run_report)
        self.assertIn(expected, self.timeline_report)
        self.assertIn("레코드 상태: 복원 후보(slack-recovered), 시각: 2026-11-20T06:00:00+00:00", self.run_report)
        self.assertIn("레코드 상태: 활성, 시각: 2026-11-20T06:08:00+00:00", self.run_report)

    # --- SetupAPI -------------------------------------------------------------

    def test_setupapi_install_section_is_on_timeline_with_zone_undetermined(self) -> None:
        events = [
            event for event in self.timeline["events"]
            if event["details"].get("artifact_type") == "usb-setupapi-device-install-candidate"
        ]
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["timestamp"], "2026-11-20T15:10:00")
        self.assertEqual(event["timezone"], "local-unknown")
        self.assertNotIn("+", event["timestamp"])
        self.assertIn("원문 현지 시각 2026-11-20T15:10:00.000", event["summary"])
        self.assertIn("시간대 미확정", event["summary"])
        self.assertNotIn(
            "usb-setupapi-device-install-candidate", self.timeline["summary"]["unmapped_artifact_type_counts"]
        )
        self.assertIn("`2026-11-20T15:10:00` (시간대 미확정", self.run_report)
        self.assertIn("timezone=local-unknown (시간대 미확정", self.timeline_report)
        self.assertNotIn("15:10:00+09:00", self.run_report + self.timeline_report)
        self.assertNotIn("15:10:00+00:00", self.run_report + self.timeline_report)

    def test_reports_count_artifact_rows_left_off_the_timeline(self) -> None:
        self.assertIn("- 타임라인 미반영 아티팩트 행: 매핑 없음 2건 (windows-control-set 1, windows-user-profile 1)", self.run_report)
        self.assertIn("- 타임라인 미반영 아티팩트 행: 매핑 없음 2건", self.timeline_report)
        self.assertIn("- 시간대 미확정 이벤트: 1건", self.timeline_report)

    # --- Recycle Bin ----------------------------------------------------------

    def test_recycle_rows_distinguish_body_present_and_missing(self) -> None:
        rows = {Path(row["path"]).name: row["details"] for row in self.artifacts("windows-filesystem")}
        self.assertEqual(rows["$I000026.txt"]["recycle_body_status"], "present")
        self.assertTrue(rows["$I000026.txt"]["paired_payload_path"].endswith("$R000026.txt"))
        self.assertEqual(rows["$I000027.txt"]["recycle_body_status"], "missing")
        self.assertEqual(rows["$I000027.txt"]["paired_payload_path"], "")
        summaries = {
            Path(event["path"]).name: event["summary"]
            for event in self.timeline["events"]
            if event["event_type"] == "artifact-recycle-bin-entry-deleted"
        }
        self.assertIn("C:\\docs\\draft.txt — 대응 $R 본문 있음: $R000026.txt", summaries["$I000026.txt"])
        self.assertIn("C:\\docs\\missing.txt — 대응 본문 없음", summaries["$I000027.txt"])
        for report in (self.run_report, self.timeline_report):
            self.assertIn("휴지통($I) 항목: 2건 — 대응 $R 본문 있음 1건, 대응 본문 없음 1건", report)
        self.assertIn("$I000027.txt` provider=`windows-filesystem` supported=True — 대응 본문 없음", self.run_report)


class D26BookmarkRecordStateTests(unittest.TestCase):
    def test_bookmarked_row_shows_record_state_next_to_its_time(self) -> None:
        def item(bookmark_id: str, timestamp: str, state: str) -> dict[str, object]:
            return {
                "bookmark_id": bookmark_id,
                "summary": f"Security.evtx {bookmark_id}",
                "tags": [],
                "note": "",
                "review": {"status": "relevant", "include_in_report": True},
                "snapshot": {"path": "/evidence/Security.evtx", "timestamp": timestamp, "record_state": state},
                "evidence": {"path": "/evidence/Security.evtx", "name": "Security.evtx", "size": 1, "hashes": {}},
            }

        markdown = build_case_report_markdown(
            run_summary={},
            case_payload={"case_id": "D26"},
            submission_manifest={
                "items": [
                    item("live-82", "2026-11-20T06:08:00+00:00", "live"),
                    item("slack-51", "2026-11-20T06:00:00+00:00", "slack-recovered"),
                ]
            },
        )
        self.assertIn("- 기록 시각: `2026-11-20T06:08:00+00:00` (레코드 상태: 활성)", markdown)
        self.assertIn("- 기록 시각: `2026-11-20T06:00:00+00:00` (레코드 상태: 복원 후보 `slack-recovered`", markdown)


if __name__ == "__main__":
    unittest.main()
