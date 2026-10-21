"""Timeline / grid readability fixes (Fable examiner-experience review, R6 follow-up).

C1 rule 1: a Jump List's container event (``jumplist-automatic`` / ``jumplist-custom``
``destinations[]``) and its DestList entry event (``jumplist-entry``) for the same embedded LNK are
one event (the entry kept). C1 rule 2: ``GET /timeline?group=1`` folds events about the same target
at the same second with the same time-kind family into one row. C2: event-log summaries read as
Korean event name / message + account + computer. C3: ``GET /timeline?q=`` searches on the server
(index column = predicate scan). C5: no "Artifact event: <type>" prefix. Synthetic fixtures only."""

from __future__ import annotations

import json
import random
import tempfile
import unicodedata
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.core.timeline import (
    TimelineBuilder,
    TimelineStats,
    build_artifact_summary,
    build_eventlog_summary,
    extract_artifact_events,
    jumplist_lnk_identity,
)

try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import create_app, timeline_index
    from rapidtriage.api.app.row_conditions import MATCH_CACHE, parse_row_conditions
    from rapidtriage.api.app.timeline_index import (
        TIMELINE_INDEXES,
        event_matches_search,
        kind_family,
        search_column,
        search_needle,
    )
    from rapidtriage.core.jobs import RunJobStore
    from tests.test_r6_s3_timeline_index import COMBOS, random_event

    HAS_FASTAPI = True
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

TOKEN = "r6-grid-readability-token"
AUTO = "C:\\Users\\u\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\abc.automaticDestinations-ms"
CUSTOM = "C:\\Users\\u\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations\\def.customDestinations-ms"
T1 = "2024-03-01T10:00:00+00:00"
T2 = "2024-03-02T11:00:00+00:00"


def lnk(stream: str, target: str, *, offset: int = 0, created: str = T1, modified: str = T2) -> dict[str, object]:
    return {
        "stream_name": stream,
        "lnk_offset": offset,
        "target_path": target,
        "target_created_at": created,
        "target_modified_at": modified,
        "target_file_size": 10,
    }


def entry(stream: str, target: str, *, offset: int = 0, number: int = 1, kind: str = "automatic") -> dict[str, object]:
    return {
        "jumplist_kind": kind,
        "destlist_entry_present": kind == "automatic",
        "destlist_entry_number": number,
        "destlist_entry_offset": 100 + number,
        "destlist_access_count": 3,
        "lnk_stream_name": stream,
        "lnk_offset": offset,
        "target_path": target,
        "target_created_at": T1,
        "target_modified_at": T2,
    }


def recent_files_payload(rows: list[tuple[str, str, dict[str, object]]]) -> dict[str, object]:
    return {
        "command": "artifacts",
        "kind": "recent-files",
        "artifacts": [
            {"artifact_type": artifact_type, "path": path, "provider": "windows-recent-files", "details": details}
            for artifact_type, path, details in rows
        ],
    }


def timeline_events(payload: dict[str, object]) -> tuple[list[dict[str, object]], TimelineStats]:
    stats = TimelineStats()
    builder = TimelineBuilder(stats)
    builder.extend(extract_artifact_events(payload, Path("recent.json"), stats=stats))
    return builder.events(), stats


def keyed(events: list[dict[str, object]]) -> dict[tuple[str, str, str], dict[str, object]]:
    out: dict[tuple[str, str, str], dict[str, object]] = {}
    for event in events:
        details = event["details"]
        assert isinstance(details, dict)
        key = (str(details.get("target_path")), str(event["timestamp"]), str(event["timestamp_kind"]))
        assert key not in out, f"duplicate event {key}"
        out[key] = event
    return out


class JumplistIdentityTests(unittest.TestCase):
    """C1 rule 1: one event per embedded LNK and instant, the DestList entry event kept."""

    def test_automatic_and_entry_events_of_one_lnk_merge(self) -> None:
        payload = recent_files_payload(
            [
                ("jumplist-automatic", AUTO, {"destinations": [lnk("1", "E:\\a.docx"), lnk("2", "E:\\b.docx")]}),
                ("jumplist-entry", AUTO, entry("1", "E:\\a.docx", number=1)),
            ]
        )
        events, stats = timeline_events(payload)
        by_key = keyed(events)
        merged = by_key[("E:\\a.docx", T1, "target-created")]
        self.assertEqual(merged["details"]["artifact_type"], "jumplist-entry")  # type: ignore[index]
        self.assertEqual(merged["details"]["destlist_access_count"], 3)  # type: ignore[index]
        also_in = merged["details"]["also_in"]  # type: ignore[index]
        self.assertEqual([item["artifact_type"] for item in also_in], ["jumplist-automatic"])
        # The stream without a DestList entry keeps the container's event.
        alone = by_key[("E:\\b.docx", T1, "target-created")]
        self.assertEqual(alone["details"]["artifact_type"], "jumplist-automatic")  # type: ignore[index]
        # a.docx created + modified, b.docx created + modified: 4 events (6 before the fix).
        self.assertEqual(len(events), 4)
        self.assertEqual(stats.jumplist_lnk_merges, 2)
        self.assertEqual(stats.as_dict()["jumplist_lnk_merges"], 2)

    def test_entry_first_still_wins_and_order_does_not_matter(self) -> None:
        payload = recent_files_payload(
            [
                ("jumplist-entry", AUTO, entry("1", "E:\\a.docx", number=1)),
                ("jumplist-automatic", AUTO, {"destinations": [lnk("1", "E:\\a.docx")]}),
            ]
        )
        events, _ = timeline_events(payload)
        self.assertEqual(len(events), 2)
        self.assertTrue(all(event["details"]["artifact_type"] == "jumplist-entry" for event in events))  # type: ignore[index]

    def test_two_lnks_with_the_same_target_and_time_stay_two_events(self) -> None:
        payload = recent_files_payload(
            [
                ("jumplist-automatic", AUTO, {"destinations": [lnk("1", "E:\\a.docx"), lnk("5", "E:\\a.docx")]}),
                ("jumplist-entry", AUTO, entry("1", "E:\\a.docx", number=1)),
                ("jumplist-entry", AUTO, entry("5", "E:\\a.docx", number=5)),
            ]
        )
        events, _ = timeline_events(payload)
        created = [event for event in events if event["timestamp_kind"] == "target-created"]
        self.assertEqual(len(created), 2)  # two DestList entries: grouped for display (rule 2), not merged

    def test_other_files_never_merge(self) -> None:
        other = AUTO.replace("abc", "fff")
        payload = recent_files_payload(
            [
                ("jumplist-automatic", AUTO, {"destinations": [lnk("1", "E:\\a.docx")]}),
                ("jumplist-entry", other, entry("1", "E:\\a.docx", number=1)),
            ]
        )
        events, stats = timeline_events(payload)
        self.assertEqual(len(events), 4)
        self.assertEqual(stats.jumplist_lnk_merges, 0)

    def test_custom_destinations_merge_on_the_lnk_offset(self) -> None:
        payload = recent_files_payload(
            [
                (
                    "jumplist-custom",
                    CUSTOM,
                    {
                        "destinations": [
                            lnk("container-scan", "C:\\p\\x.exe", offset=36),
                            lnk("container-scan", "C:\\p\\y.exe", offset=2107),
                        ]
                    },
                ),
                ("jumplist-entry", CUSTOM, entry("container-scan", "C:\\p\\y.exe", offset=2107, kind="custom")),
            ]
        )
        events, stats = timeline_events(payload)
        by_key = keyed(events)
        self.assertEqual(by_key[("C:\\p\\y.exe", T1, "target-created")]["details"]["artifact_type"], "jumplist-entry")  # type: ignore[index]
        self.assertEqual(by_key[("C:\\p\\x.exe", T1, "target-created")]["details"]["artifact_type"], "jumplist-custom")  # type: ignore[index]
        self.assertEqual(stats.jumplist_lnk_merges, 2)

    def test_identity_rules(self) -> None:
        self.assertEqual(jumplist_lnk_identity("jumplist-automatic", {"stream_name": "3e8", "lnk_offset": 0}), "lnk-stream=3e8")
        self.assertEqual(jumplist_lnk_identity("jumplist-entry", {"lnk_stream_name": "3e8", "lnk_offset": 0}), "lnk-stream=3e8")
        self.assertEqual(
            jumplist_lnk_identity("jumplist-entry", {"lnk_stream_name": "container-scan", "lnk_offset": 9, "jumplist_kind": "custom"}),
            "lnk-offset=9",
        )
        self.assertEqual(jumplist_lnk_identity("jumplist-entry", {"destlist_entry_offset": 130}), "destlist-offset=130")
        # Automatic LNKs all start at offset 0 of their stream: an offset alone is no identity there.
        self.assertEqual(jumplist_lnk_identity("jumplist-automatic", {"lnk_offset": 0}), "")
        self.assertEqual(jumplist_lnk_identity("recent-shortcut", {"stream_name": "1"}), "")


class SummaryTests(unittest.TestCase):
    """C2 / C5 / P5 / P6: readable one-line summaries."""

    def eventlog_event(self, details: dict[str, object]) -> dict[str, object]:
        payload = {
            "command": "artifacts",
            "kind": "eventlog",
            "artifacts": [
                {
                    "artifact_type": "eventlog-event",
                    "path": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
                    "provider": "windows-eventlog",
                    "details": {"timestamp": T1, "record_id": "7", "channel": "Security", "event_id": "4624", **details},
                }
            ],
        }
        events = extract_artifact_events(payload, Path("eventlog.json"))
        self.assertEqual(len(events), 1)
        return events[0]

    def test_eventlog_label_account_and_computer(self) -> None:
        event = self.eventlog_event(
            {
                "event_label_ko": "로그온 성공",
                "event_message": "An account was successfully logged on." * 20,
                "subject_user_name": "SYSTEM",
                "target_user_name": "alice",
                "computer": "PC-01",
                "level": "4",
                "event_category": "logon-success",
            }
        )
        self.assertEqual(event["summary"], "로그온 성공 · 계정 SYSTEM → alice · 컴퓨터 PC-01")
        details = event["details"]
        assert isinstance(details, dict)
        self.assertEqual(details["level"], "4")
        self.assertEqual(details["event_label_ko"], "로그온 성공")
        self.assertNotIn("event_message", details)  # the timeline stays bounded

    def test_generic_label_falls_back_to_the_message_capped(self) -> None:
        message = "Provider=InvProv;   Namespace=ROOT\\CIMV2 " + "x" * 300
        event = self.eventlog_event({"event_label_ko": "일반 이벤트", "event_message": message, "user_name": "bob"})
        summary = str(event["summary"])
        self.assertTrue(summary.startswith("Provider=InvProv; Namespace=ROOT\\CIMV2 xxx"))
        head = summary.split(" · ")[0]
        self.assertLessEqual(len(head), 121)  # 120 characters + the ellipsis
        self.assertIn("계정 bob", summary)
        self.assertNotIn("EventLog", summary)

    def test_no_label_no_message_names_provider_and_id(self) -> None:
        event = self.eventlog_event({"provider_name": "Microsoft-Windows-WMI", "event_id": "5615"})
        self.assertEqual(event["summary"], "Microsoft-Windows-WMI 이벤트 5615")

    def test_detection_prefix(self) -> None:
        self.assertEqual(
            build_eventlog_summary("eventlog-detection", {"event_label_ko": "서비스 설치", "computer": "PC"}),
            "[탐지] 서비스 설치 · 컴퓨터 PC",
        )

    def test_artifact_summaries_have_no_type_prefix(self) -> None:
        self.assertEqual(build_artifact_summary("shimcache-schema-entry", "SYSTEM", {"executable_path": "D:\\a\\LiveUpdate.exe"}), "D:\\a\\LiveUpdate.exe")
        self.assertEqual(build_artifact_summary("browser-visit", "History", {"url": "https://a.example/x", "title": "제목"}), "제목 — https://a.example/x")
        self.assertEqual(build_artifact_summary("browser-cookie", "Cookies", {"host": ".a.example", "name": "UID"}), ".a.example · UID")
        self.assertEqual(build_artifact_summary("browser-autofill", "Web Data", {"field_name": "usrId"}), "입력 필드 usrId")
        self.assertEqual(build_artifact_summary("amcache-schema-row", "Amcache.hve", {"program_name": "Setup.exe"}), "Setup.exe")
        self.assertEqual(build_artifact_summary("wer-report", "C:\\x\\Report.wer", {}), "wer-report Report.wer")
        for text in (
            build_artifact_summary("jumplist-entry", AUTO, {"target_path": "E:\\a.docx"}),
            build_artifact_summary("registry-user-activity", "NTUSER.DAT", {"key_path": "HKU\\x"}),
        ):
            self.assertNotIn("Artifact event", text)


def grouped_events() -> list[dict[str, object]]:
    """Events built to exercise display grouping (sorted like a timeline)."""

    def event(timestamp: str, kind: str, artifact_type: str, path: str, target: str | None, summary: str, **extra: object) -> dict[str, object]:
        details: dict[str, object] = {"artifact_type": artifact_type, **extra}
        if target is not None:
            details["target_path"] = target
        return {
            "timestamp": timestamp,
            "timestamp_kind": kind,
            "timezone": "UTC",
            "source": "artifacts",
            "event_type": f"artifact-{artifact_type}-{kind}",
            "path": path,
            "summary": summary,
            "details": details,
        }

    return [
        event("2024-03-01T10:00:00.100000+00:00", "target-created", "jumplist-entry", AUTO, "E:\\A.docx", "E:\\A.docx"),
        event("2024-03-01T10:00:00.900000+00:00", "target-created", "recent-shortcut", "C:\\r\\A.lnk", "e:\\a.docx", "e:\\a.docx"),
        event("2024-03-01T10:00:00.500000+00:00", "created", "shell-shortcut", "C:\\s\\A.lnk", "E:\\a.docx", "E:\\a.docx"),
        # Same instant and target, another kind family: its own row.
        event("2024-03-01T10:00:00.200000+00:00", "target-modified", "recent-shortcut", "C:\\r\\A.lnk", "E:\\a.docx", "E:\\a.docx"),
        # Next second: its own row.
        event("2024-03-01T10:00:01+00:00", "target-created", "jumplist-entry", AUTO, "E:\\a.docx", "E:\\a.docx"),
        # Event-log rows have no target: never grouped.
        event("2024-03-01T10:00:00+00:00", "event", "eventlog-event", "Security.evtx", None, "로그온 성공 · 계정 alice", event_label_ko="로그온 성공"),
        event("2024-03-01T10:00:00+00:00", "event", "eventlog-event", "Security.evtx", None, "로그온 성공 · 계정 alice", event_label_ko="로그온 성공"),
        event("2024-03-02T09:00:00+00:00", "file-last-modified", "shimcache-schema-entry", "SYSTEM", None, "D:\\YSR2000\\Exe\\LiveUpdate.exe", executable_path="D:\\YSR2000\\Exe\\LiveUpdate.exe"),
        event("2024-03-02T09:00:00+00:00", "target-modified", "shell-shortcut", "C:\\s\\L.lnk", "d:\\ysr2000\\exe\\liveupdate.exe", "d:\\ysr2000\\exe\\liveupdate.exe"),
    ]


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for the timeline API tests")
class TimelineApiTests(unittest.TestCase):
    """C1 rule 2 (``group=1``) and C3 (``q``) on ``GET /timeline``."""

    def setUp(self) -> None:
        TIMELINE_INDEXES.clear()
        MATCH_CACHE.clear()
        self.addCleanup(TIMELINE_INDEXES.clear)
        self.addCleanup(MATCH_CACHE.clear)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.client: TestClient | None = None

    def start(self, events: list[object]) -> None:
        base = Path(self.temp.name)
        run_dir = base / f"run{len(list(base.iterdir()))}"
        run_dir.mkdir()
        self.events = events
        timeline = run_dir / "rapidtriage-timeline.json"
        timeline.write_text(json.dumps({"summary": {"event_count": len(events)}, "events": events}), encoding="utf-8")
        summary = run_dir / "rapidtriage-run-summary.json"
        summary.write_text(
            json.dumps(
                {
                    "profile_version": "rapidtriage-run-summary-v1",
                    "mode": "hacking",
                    "root": str(base / "evidence"),
                    "output_dir": str(run_dir),
                    "source": {"type": "directory", "analysis_root": str(base / "evidence")},
                    "outputs": {"timeline": str(timeline), "summary": str(summary)},
                    "summary": {"counts": {}},
                }
            ),
            encoding="utf-8",
        )
        store = RunJobStore()
        self.run_id = store.import_completed_run(run_dir).run_id
        self.client = TestClient(create_app(store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})

    def page(self, query: str) -> dict[str, object]:
        assert self.client is not None
        response = self.client.get(f"/api/runs/{self.run_id}/timeline?{query}")
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def all_rows(self, query: str, limit: int = 1000) -> list[dict[str, object]]:
        out: list[dict[str, object]] = []
        offset = 0
        while True:
            body = self.page(f"{query}&limit={limit}&offset={offset}")
            out.extend(body["events"])  # type: ignore[arg-type]
            pagination = body["pagination"]
            assert isinstance(pagination, dict)
            if not pagination["has_more"]:
                return out
            offset = int(pagination["next_offset"])

    # --- q ------------------------------------------------------------------------------------

    def test_q_is_case_insensitive_over_summary_target_path_and_label(self) -> None:
        self.start(grouped_events())  # type: ignore[arg-type]
        rows = self.all_rows("q=LIVEUPDATE.exe")
        self.assertEqual([row["record_index"] for row in rows], [7, 8])
        body = self.page("limit=10&q=liveupdate.exe")
        self.assertEqual(body["matched"], 2)
        self.assertEqual(body["pagination"]["search"]["q"], "liveupdate.exe")  # type: ignore[index]
        self.assertEqual([row["record_index"] for row in self.all_rows("q=로그온%20성공")], [5, 6])
        self.assertEqual(len(self.all_rows("q=security.evtx")), 2)  # source path
        self.assertEqual(len(self.all_rows("q=shimcache-schema")), 1)  # event type
        self.assertEqual(self.all_rows("q=nothing-like-this"), [])

    def test_q_finds_decomposed_korean_and_ignores_control_characters(self) -> None:
        row = {"summary": unicodedata.normalize("NFD", "D:\\보고서\\한글문서.hwp"), "path": "x", "details": {}}
        self.assertTrue(event_matches_search(row, search_needle("한글문서")))
        self.assertTrue(search_column([row]).positions(search_needle("한글문서")) == [0])
        self.assertEqual(search_needle("  A\tB\x00c  "), "a b c")
        self.assertEqual(search_needle(" \n "), "")

    def test_q_and_conditions_are_anded(self) -> None:
        self.start(grouped_events())  # type: ignore[arg-type]
        rows = self.all_rows("q=a.docx&from=2024-03-01T10:00:01Z")
        self.assertEqual([row["record_index"] for row in rows], [4])

    def test_q_index_equals_the_predicate_on_random_events(self) -> None:
        rng = random.Random(23)
        events = [random_event(rng, position) for position in range(2_000)]
        nfd = unicodedata.normalize("NFD", "한글문서.hwp")
        words = ("Ünïcode", "ＡＢＣ", "로그온", "C:\\X", "report", "e1", ".EXE", "docx", "ß", "", nfd, "İstanbul", "a\x00b", "x\ny")
        for position, event in enumerate(events):
            if isinstance(event, dict) and rng.random() < 0.7:
                event["summary"] = f"{rng.choice(words)} {position} {rng.choice(words)}"
                details = event.get("details")
                if isinstance(details, dict) and rng.random() < 0.3:
                    details["event_label_ko"] = rng.choice(("로그온 성공", "일반 이벤트", "SS"))
        column = search_column(events)
        needles = ("report", "REPORT", "로그온", "c:\\x", "ss", "ß", "abc", "ａｂｃ", ".exe", "e1 ", " 1", "성공", "x\\b")
        for raw in (*needles, "한글", "한글문서.HWP", "i̇stanbul", "istanbul", "a b", "x y", "a\x00b"):
            needle = search_needle(raw)
            expected = [i for i, row in enumerate(events) if event_matches_search(row, needle)]
            self.assertEqual(column.positions(needle), expected, raw)
        self.start(events)  # type: ignore[arg-type]
        cases = (
            ("report", "report", COMBOS[0], "from=2025-01-01T00:00:00Z"),
            ("C%3A%5CX%5C", "C:\\X\\", COMBOS[16], "offhours=1"),
            ("%EB%A1%9C%EA%B7%B8%EC%98%A8", "로그온", COMBOS[27], "content=document"),
            ("e1", "e1", None, ""),
        )
        for encoded, raw, combo, query in cases:
            conditions = parse_row_conditions(**combo) if combo else None  # type: ignore[arg-type]
            predicate = conditions.predicate("timeline") if conditions else None
            needle = search_needle(raw)
            expected = [
                i
                for i, row in enumerate(events)
                if isinstance(row, dict) and (predicate is None or predicate(row)) and event_matches_search(row, needle)
            ]
            self.assertTrue(expected, raw)
            rows = self.all_rows(f"q={encoded}&{query}")
            self.assertEqual([row["record_index"] for row in rows], expected, (raw, combo))

    def test_q_falls_back_to_the_scan_when_the_index_fails(self) -> None:
        self.start(grouped_events())  # type: ignore[arg-type]
        with mock.patch.object(timeline_index, "open_index", side_effect=OSError("disk gone")):
            self.assertEqual([row["record_index"] for row in self.all_rows("q=liveupdate")], [7, 8])

    # --- group --------------------------------------------------------------------------------

    def test_group_folds_one_target_second_and_kind_family(self) -> None:
        self.start(grouped_events())  # type: ignore[arg-type]
        rows = self.all_rows("group=1")
        self.assertEqual([row["record_index"] for row in rows], [0, 3, 4, 5, 6, 7])
        first = rows[0]
        self.assertEqual(first["source_count"], 3)
        self.assertEqual(first["group_members"], [0, 1, 2])
        self.assertEqual(
            sorted(source["artifact_type"] for source in first["sources"]),  # type: ignore[union-attr]
            ["jumplist-entry", "recent-shortcut", "shell-shortcut"],
        )
        self.assertTrue(str(first["group_id"]).startswith("g"))
        # Another kind family at the same second, the next second, event-log rows: single rows.
        for row in rows[1:4]:
            self.assertEqual(row["source_count"], 1)
            self.assertNotIn("group_id", row)
        # ShimCache file-last-modified + a shortcut's target-modified: the same file time.
        self.assertEqual(rows[5]["group_members"], [7, 8])
        body = self.page("group=1&limit=2")
        self.assertEqual(body["matched"], 6)
        self.assertTrue(body["pagination"]["grouped"])  # type: ignore[index]
        self.assertEqual(body["record_count"], len(self.events))
        # Without group=1 every event is a row (the plain listing is unchanged).
        self.assertEqual(len(self.all_rows("from=2000-01-01")), len(self.events))

    def test_group_after_conditions_and_q(self) -> None:
        self.start(grouped_events())  # type: ignore[arg-type]
        rows = self.all_rows("group=1&q=recent-shortcut")
        # Only the recent-shortcut events match: each is its own row now.
        self.assertEqual([row["record_index"] for row in rows], [1, 3])
        self.assertTrue(all(row["source_count"] == 1 for row in rows))
        rows = self.all_rows("group=1&from=2024-03-01T10:00:00.4Z&to=2024-03-01T10:00:00.95Z")
        self.assertEqual([row["record_index"] for row in rows], [1])
        self.assertEqual(rows[0]["group_members"], [1, 2])  # members the time window kept

    def test_group_pages_reuse_the_cached_leaders(self) -> None:
        self.start(grouped_events())  # type: ignore[arg-type]
        first = self.page("group=1&limit=3")
        with mock.patch.object(timeline_index.GroupColumn, "leaders", side_effect=AssertionError("recomputed")):
            second = self.page("group=1&limit=3&offset=3")
        indices = [row["record_index"] for row in first["events"] + second["events"]]  # type: ignore[operator]
        self.assertEqual(indices, [0, 3, 4, 5, 6, 7])

    def test_group_ids_are_saved_in_the_index_file(self) -> None:
        self.start(grouped_events())  # type: ignore[arg-type]
        expected = [row["record_index"] for row in self.all_rows("group=1")]
        index_file = next(Path(self.temp.name).glob(f"run*/{timeline_index.INDEX_FILE_NAME}"))
        self.assertTrue(index_file.exists())  # small timeline: completed and saved in the request
        TIMELINE_INDEXES.clear()
        MATCH_CACHE.clear()
        with (
            mock.patch.object(timeline_index, "group_column", side_effect=AssertionError("rebuilt")),
            mock.patch.object(timeline_index, "time_column", side_effect=AssertionError("rebuilt")),
        ):
            self.assertEqual([row["record_index"] for row in self.all_rows("group=1")], expected)

    def test_locate_gives_the_row_of_an_event_in_the_listing(self) -> None:
        self.start(grouped_events())  # type: ignore[arg-type]

        def where(query: str) -> object:
            return self.page(f"limit=2&{query}")["pagination"]["locate"]["position"]  # type: ignore[index]

        # Grouped rows: [0 (members 0,1,2), 3, 4, 5, 6, 7 (members 7,8)].
        self.assertEqual(where("group=1&locate=2"), 0)
        self.assertEqual(where("group=1&locate=4"), 2)
        self.assertEqual(where("group=1&locate=8"), 5)
        self.assertEqual(where("q=recent-shortcut&group=1&locate=3"), 1)
        self.assertIsNone(where("q=recent-shortcut&group=1&locate=0"))  # left out by q
        self.assertEqual(where("locate=6"), 6)  # plain listing: the position is the index
        self.assertIsNone(where("locate=99"))

    def test_bad_group_value_is_a_korean_422(self) -> None:
        self.start(grouped_events())  # type: ignore[arg-type]
        assert self.client is not None
        response = self.client.get(f"/api/runs/{self.run_id}/timeline?limit=5&group=maybe")
        self.assertEqual(response.status_code, 422)
        self.assertIn("group", response.json()["detail"])

    def test_group_column_equals_the_reference_key_on_random_events(self) -> None:
        rng = random.Random(5)
        events = [random_event(rng, position) for position in range(3_000)]
        kinds = ("created", "target-created", "modified", "file-last-modified", "run-1", None, 3)
        for event in events:
            if isinstance(event, dict):
                event["timestamp_kind"] = rng.choice(kinds)
                details = event.get("details")
                if isinstance(details, dict) and rng.random() < 0.5:
                    details[rng.choice(("target_path", "executable_path", "url"))] = rng.choice(("C:\\A.exe", "c:\\a.EXE", " c:\\a.exe ", "Ünï", "ÜNÏ", ""))
                if rng.random() < 0.5:
                    event["timestamp"] = rng.choice(("2025-01-01T00:00:00Z", "2025-01-01T00:00:00.9Z", "2025-01-01T09:00:00+09:00", "2025-01-01T00:00:00"))
        index = timeline_index.build_timeline_index(events)
        ids = index.group_ids
        assert ids is not None and index.epoch_us is not None
        reference: dict[int, tuple[object, ...]] = {}
        for position, row in enumerate(events):
            epoch = index.epoch_us[position]
            target = timeline_index.event_group_target(row) if isinstance(row, dict) else ""
            if epoch == timeline_index.MISSING or not target:
                self.assertEqual(ids[position], timeline_index.NO_GROUP, position)
                continue
            reference[position] = (epoch // 1_000_000, index.has_offset[position], target, kind_family(row.get("timestamp_kind")))  # type: ignore[index, union-attr]
        positions = list(reference)
        for a in positions[:400]:
            for b in positions:
                self.assertEqual(ids[a] == ids[b], reference[a] == reference[b], (a, b))

    def test_kind_families(self) -> None:
        self.assertEqual(kind_family("target-created"), kind_family("created"))
        self.assertEqual(kind_family("file-last-modified"), kind_family("target-modified"))
        self.assertNotEqual(kind_family("target-created"), kind_family("target-modified"))
        self.assertEqual(kind_family("destlist-last-modified"), "destlist-last-modified")


if __name__ == "__main__":
    unittest.main()
