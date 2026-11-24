"""D16 adversarial review: time, review rows, exports and the shipped console (items 2, 10, 11,
12, 14, 19; remaining parts of D12-5, D14-7, D14-8 and D14-11).

Every fixture is synthetic and built in-test (no case data). Item numbers refer to the D16 review
table "신규·잔존 발견 우선순위"; the console side of items 12 and 13 is pinned by
``frontend/src/features/review/d16Time.test.ts``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import tempfile
import time
import unittest
from html.parser import HTMLParser
from pathlib import Path
from xml.etree import ElementTree
from zipfile import ZipFile

from rapidtriage.api.app.row_conditions import row_time
from rapidtriage.artifacts.windows import recent_files
from rapidtriage.core.case import (
    build_stable_bookmark_key,
    create_or_update_case_payload,
    save_case_payload,
)
from rapidtriage.core.case_db import open_case_database
from rapidtriage.core.case_export import export_case_uco_jsonld
from rapidtriage.core.case_report import (
    build_case_report_markdown,
    write_case_report_exports,
)
from rapidtriage.core.jobs import RunJobStore
from rapidtriage.core.submission import build_submission_manifest
from rapidtriage.core.timeline import (
    TimelineBuilder,
    TimelineStats,
    event_sort_key,
    extract_artifact_events,
    run_timeline,
    write_timeline_result,
)
from rapidtriage.core.timeline_export import build_unified_timeline_export
from tests.test_d12_eventlog import START, collect, finalized, session_event
from tests.test_parser_quality_eventlog import EvtxWriter, filetime
from tests.test_parser_quality_registry import HiveWriter, Key, dword
from tests.test_rapidtriage_case_export import _build_case_db
from tests.windows_artifact_fixtures import (
    LNK_CLSID,
    build_minimal_ole_jumplist_streams,
)

try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import artifact_sort, create_app

    HAS_FASTAPI = True
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

REPO = Path(__file__).resolve().parents[1]
FRONTEND = REPO / "frontend"
TOKEN = "d16-time-test-token"
BASE_TICKS = 133485408000000000  # 2024-01-01T00:00:00Z


class _Text(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def _html_text(path: Path) -> str:
    parser = _Text()
    parser.feed(path.read_text(encoding="utf-8"))
    return "".join(parser.parts)


def _docx_text(path: Path) -> str:
    with ZipFile(path) as archive:
        return "".join(ElementTree.fromstring(archive.read("word/document.xml")).itertext())


def _pdf_text(path: Path) -> str:
    return "".join(
        bytes.fromhex(chunk.decode()).decode("utf-16-be") for chunk in re.findall(rb"<([A-F0-9]+)> Tj", path.read_bytes())
    )


def _write_evtx(root: Path, events: list) -> Path:
    writer = EvtxWriter()
    writer.build_chunk(events)
    path = root / "events.evtx"
    path.write_bytes(finalized(writer))
    return path


class BookmarkRowIdentityTests(unittest.TestCase):
    """#2: two logon rows of one EVTX at the same instant keep their own review notes."""

    def _timeline(self, root: Path) -> Path:
        _write_evtx(
            root,
            [
                session_event(52, 4624, filetime(START, 17), user="Sample<A>&"),
                session_event(53, 4624, filetime(START, 17), user="Sample<B>&"),
            ],
        )
        rows = [row.to_dict() for row in collect(root)]
        artifacts = root / "artifacts.json"
        artifacts.write_text(json.dumps({"command": "artifacts", "kind": "eventlog", "artifacts": rows}), encoding="utf-8")
        files = root / "files.json"
        files.write_text(json.dumps({"command": "files", "candidates": []}), encoding="utf-8")
        docs = root / "docs.json"
        docs.write_text(json.dumps({"command": "docs", "results": []}), encoding="utf-8")
        payload = run_timeline(root=root, files_inputs=[files], docs_inputs=[docs], artifacts_inputs=[artifacts])
        timeline = root / "timeline.json"
        write_timeline_result(payload, timeline)
        return timeline

    @staticmethod
    def _pointers(timeline: Path) -> dict[str, str]:
        events = json.loads(timeline.read_text(encoding="utf-8"))["events"]
        return {str(event["details"].get("record_id")): f"/events/{index}" for index, event in enumerate(events)}

    def test_two_rows_same_instant_keep_separate_bookmarks_through_submission(self) -> None:
        for order in (("52", "53"), ("53", "52")):
            with self.subTest(order=order), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                timeline = self._timeline(root)
                pointers = self._pointers(timeline)
                self.assertIn("52", pointers)
                self.assertIn("53", pointers)
                case_path = root / "case.json"
                for record_id in order:
                    review = (
                        {"note": "checked-record-52", "include_in_report": True}
                        if record_id == "52"
                        else {"tags": ["second-observation"]}
                    )
                    case = create_or_update_case_payload(
                        case_path, source_path=timeline, source_pointer=pointers[record_id], **review
                    )
                    save_case_payload(case_path, case)
                bookmarks = case["bookmarks"]
                self.assertEqual(len(bookmarks), 2)
                by_pointer = {bookmark["reference"]["pointer"]: bookmark for bookmark in bookmarks}
                first, second = by_pointer[pointers["52"]], by_pointer[pointers["53"]]
                self.assertEqual(first["note"], "checked-record-52")
                self.assertIn("user=Sample<A>&", first["summary"])
                self.assertTrue(first["review"]["include_in_report"])
                self.assertEqual(first["tags"], [])
                self.assertEqual(second["note"], "")
                self.assertIn("user=Sample<B>&", second["summary"])
                self.assertEqual(second["tags"], ["second-observation"])
                self.assertFalse(second["review"]["include_in_report"])
                self.assertNotEqual(first["reference"]["row_sha256"], second["reference"]["row_sha256"])

                manifest = build_submission_manifest(case, allowed_roots=[root])
                self.assertEqual(
                    [(item["reference"]["pointer"], item["note"]) for item in manifest["items"]],
                    [(pointers["52"], "checked-record-52")],
                )
                self.assertIn("user=Sample<A>&", manifest["items"][0]["summary"])
                markdown = build_case_report_markdown(run_summary={}, case_payload=case, submission_manifest=manifest)
                outputs = write_case_report_exports(markdown, root / "report.md")
                for name, text in (
                    ("html", _html_text(Path(outputs["html"]))),
                    ("docx", _docx_text(Path(outputs["docx"]))),
                    ("pdf", _pdf_text(Path(outputs["pdf"]))),
                ):
                    with self.subTest(output=name):
                        self.assertIn("checked-record-52", text)
                        self.assertIn("Sample<A>&", text)
                        self.assertNotIn("Sample<B>&", text)

    def test_bookmark_saved_before_row_digests_still_updates_its_own_row_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            timeline = self._timeline(root)
            pointers = self._pointers(timeline)
            case_path = root / "case.json"
            case = create_or_update_case_payload(
                case_path, source_path=timeline, source_pointer=pointers["52"], note="checked-record-52"
            )
            # Rewrite it as an earlier release stored it: legacy key, no row digest.
            legacy = case["bookmarks"][0]
            snapshot = legacy["snapshot"]
            legacy_key = build_stable_bookmark_key(
                source_command="timeline",
                source_file=str(timeline),
                source_path=snapshot["path"],
                source_hash=snapshot["hash"],
                source_timestamp=snapshot["timestamp"],
                artifact_key=snapshot["artifact_key"],
                summary=snapshot["summary"],
            )
            legacy["reference"].pop("row_sha256")
            legacy["reference"]["stable_key"] = legacy_key
            legacy["bookmark_id"] = legacy_key
            save_case_payload(case_path, case)
            # Same row: the legacy bookmark is found and upgraded with the row digest.
            case = create_or_update_case_payload(case_path, source_path=timeline, source_pointer=pointers["52"], tags=["kept"])
            save_case_payload(case_path, case)
            self.assertEqual(len(case["bookmarks"]), 1)
            self.assertEqual(case["bookmarks"][0]["bookmark_id"], legacy_key)
            self.assertEqual(case["bookmarks"][0]["note"], "checked-record-52")
            self.assertIn("row_sha256", case["bookmarks"][0]["reference"])
            # The other row of the same instant never takes it over.
            case = create_or_update_case_payload(case_path, source_path=timeline, source_pointer=pointers["53"], tags=["other"])
            self.assertEqual(len(case["bookmarks"]), 2)
            self.assertEqual(case["bookmarks"][0]["note"], "checked-record-52")
            self.assertEqual(case["bookmarks"][1]["note"], "")


class SameRecordInstantTests(unittest.TestCase):
    """#11 (D14-7): one source row's created/modified times 600 ns apart stay two events."""

    @staticmethod
    def _events(created: str, modified: str) -> list[dict]:
        row = {
            "path": "source.txt",
            "provider": "synthetic",
            "artifact_type": "fixture",
            "details": {
                "timeline_events": [
                    {"timestamp": created, "timestamp_kind": "created"},
                    {"timestamp": modified, "timestamp_kind": "modified"},
                ]
            },
        }
        builder = TimelineBuilder(TimelineStats())
        builder.extend(extract_artifact_events({"kind": "fixture", "artifacts": [row]}, Path("artifacts.json")))
        return [(event["timestamp"], event.get("labels")) for event in sorted(builder.events(), key=event_sort_key)]

    def test_one_and_seven_ticks_are_two_events(self) -> None:
        self.assertEqual(
            self._events("2024-01-01T00:00:00.0000001Z", "2024-01-01T00:00:00.0000007Z"),
            [("2024-01-01T00:00:00.0000001+00:00", None), ("2024-01-01T00:00:00.0000007+00:00", None)],
        )

    def test_same_tick_in_another_notation_is_one_event_with_two_labels(self) -> None:
        events = self._events("2024-01-01T00:00:00.0000007Z", "2024-01-01T09:00:00.00000070+09:00")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0][1], ["created", "modified"])


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for artifact sort API tests")
class ArtifactGridTimeSortTests(unittest.TestCase):
    """#12 (D12-5): the artifact grid "시각" server sort restores EVTX order by 100 ns ticks."""

    def test_server_sort_uses_integer_ticks_of_the_evtx_rows(self) -> None:
        artifact_sort.SORT_INDEX_CACHE.clear()
        self.addCleanup(artifact_sort.SORT_INDEX_CACHE.clear)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "evidence"
            run_dir = Path(tmp) / "run"
            root.mkdir()
            run_dir.mkdir()
            base = filetime(START, 0)
            _write_evtx(root, [session_event(r, 4624, base + d) for r, d in ((50, 7), (51, 1), (52, 10_000_000))])
            rows = [row.to_dict() for row in collect(root)]
            records = run_dir / "records_eventlog.jsonl"
            records.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            payload = run_dir / "artifacts_eventlog.json"
            payload.write_text(json.dumps({"records_path": str(records), "record_count": len(rows), "artifacts": []}), encoding="utf-8")
            summary = run_dir / "rapidtriage-run-summary.json"
            summary.write_text(
                json.dumps(
                    {
                        "profile_version": "rapidtriage-run-summary-v1",
                        "mode": "seizure",
                        "root": str(root),
                        "output_dir": str(run_dir),
                        "outputs": {"artifacts_eventlog": str(payload), "summary": str(summary)},
                    }
                ),
                encoding="utf-8",
            )
            store = RunJobStore()
            run_id = store.import_completed_run(run_dir).run_id
            client = TestClient(create_app(store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})

            def order(direction: str) -> list[str]:
                deadline = time.monotonic() + 10
                while True:
                    response = client.get(
                        f"/api/runs/{run_id}/artifacts",
                        params={"kind": "eventlog", "sort": "timestamp", "order": direction, "limit": 50},
                    )
                    self.assertEqual(response.status_code, 200, response.text)
                    body = response.json()["artifacts"]["eventlog"]
                    if body["sort"]["status"] != "building" or time.monotonic() > deadline:
                        break
                    time.sleep(0.02)
                self.assertEqual(body["sort"]["status"], "ready", body["sort"])
                return [
                    str(row["details"]["record_id"]) for row in body["artifacts"] if row.get("artifact_type") == "eventlog-event"
                ]

            self.assertEqual(order("asc"), ["51", "50", "52"])
            self.assertEqual(order("desc"), ["52", "50", "51"])

    def test_tick_reading_keeps_seven_digits_and_falls_back_for_other_iso_forms(self) -> None:
        self.assertEqual(artifact_sort.as_utc_ticks("2024-01-01T00:00:00.0000007Z"), BASE_TICKS + 7)
        self.assertEqual(artifact_sort.as_utc_ticks("2024-01-01T09:00:00.0000001+09:00"), BASE_TICKS + 1)
        self.assertEqual(artifact_sort.as_utc_ticks("2024-01-01"), BASE_TICKS)
        self.assertIsNone(artifact_sort.as_utc_ticks("not a time"))
        details = {"timestamp": "2024-01-01T00:00:00+00:00", "timestamp_100ns": "2024-01-01T00:00:00.0000007Z"}
        self.assertEqual(artifact_sort.sort_value({"details": details}, "timestamp"), "2024-01-01T00:00:00.0000007Z")
        # A sibling of another instant is ignored.
        details["timestamp_100ns"] = "2024-01-01T00:00:05.0000007Z"
        self.assertEqual(artifact_sort.sort_value({"details": details}, "timestamp"), "2024-01-01T00:00:00+00:00")


class LnkJumpListTicksTests(unittest.TestCase):
    """#14: LNK target times and DestList times keep FILETIME ticks before ordering."""

    @staticmethod
    def _fixture(area: Path, bias: int) -> None:
        hive = Key("ROOT")
        hive.path("Select").value("Current", 4, dword(2))
        hive.path(r"ControlSet002\Control\TimeZoneInformation").value("Bias", 4, dword(bias))
        area.mkdir(parents=True)
        (area / "SYSTEM").write_bytes(HiveWriter().build(hive))
        recent = area.joinpath("Users", "profile-a", *recent_files.RECENT_ROOT)
        recent.mkdir(parents=True)
        for name, tick in (("a", 7), ("b", 1)):
            header = bytearray(0x4C)
            struct.pack_into("<I", header, 0, 0x4C)
            header[4:20] = LNK_CLSID
            struct.pack_into("<IIQQQ", header, 0x14, 0, 0x20, BASE_TICKS + tick, BASE_TICKS + tick, BASE_TICKS + tick)
            (recent / f"{name}.lnk").write_bytes(bytes(header) + bytes(4))
        entries = []
        for number, tick in ((1, 7), (2, 1)):
            entry = bytearray(0x82)
            path = "C:\\" + ("segment" * 20 + "\\") * 8 + f"sample{number}.txt"
            struct.pack_into("<Q", entry, 0x58, number)
            struct.pack_into("<Qi", entry, 0x64, BASE_TICKS + tick, -1)
            struct.pack_into("<H", entry, 0x80, len(path))
            entries.append(bytes(entry) + path.encode("utf-16le") + bytes(4))
        head = bytearray(32)
        struct.pack_into("<IIIII", head, 0, 4, 2, 0, 0, 2)
        jumplists = recent / "AutomaticDestinations"
        jumplists.mkdir()
        (jumplists / "0000000000000001.automaticDestinations-ms").write_bytes(
            build_minimal_ole_jumplist_streams([("DestList", bytes(head) + b"".join(entries))])
        )

    def test_six_hundred_nanoseconds_survive_in_rows_and_timeline_order(self) -> None:
        for bias in (-540, 300):  # +09:00 and -05:00 hives: FILETIMEs are UTC either way
            with self.subTest(bias=bias), tempfile.TemporaryDirectory() as tmp:
                area = Path(tmp) / "area"
                self._fixture(area, bias)
                rows = list(recent_files.WindowsRecentFilesProvider().collect(area))
                lnk = {Path(row.path).name: row.details for row in rows if row.artifact_type == "recent-shortcut"}
                for name, tick in (("a.lnk", 7), ("b.lnk", 1)):
                    for field in ("target_created_at", "target_accessed_at", "target_modified_at"):
                        self.assertEqual(lnk[name][f"{field}_100ns"], f"2024-01-01T00:00:00.000000{tick}Z")
                        self.assertEqual(lnk[name][f"{field}_filetime"], BASE_TICKS + tick)
                jump = [row.details for row in rows if row.artifact_type == "jumplist-entry"]
                self.assertEqual(
                    sorted((entry["destlist_last_modified_filetime"], entry["destlist_last_modified_at_100ns"]) for entry in jump),
                    [(BASE_TICKS + 1, "2024-01-01T00:00:00.0000001Z"), (BASE_TICKS + 7, "2024-01-01T00:00:00.0000007Z")],
                )
                for entry in jump:
                    self.assertEqual(entry["timestamp_100ns"], entry["destlist_last_modified_at_100ns"])
                    self.assertEqual(entry["timestamp_filetime"], entry["destlist_last_modified_filetime"])

                events = sorted(
                    extract_artifact_events({"kind": "recent-files", "artifacts": [row.to_dict() for row in rows]}, area),
                    key=event_sort_key,
                )
                modified = [
                    (Path(str(event.get("path", ""))).name, event["details"]["timestamp_utc_ticks"])
                    for event in events
                    if event["timestamp_kind"] == "target-modified" and event["details"]["artifact_type"] == "recent-shortcut"
                ]
                self.assertEqual(modified, [("b.lnk", str(BASE_TICKS + 1)), ("a.lnk", str(BASE_TICKS + 7))])
                destlist = [event["timestamp"] for event in events if event["timestamp_kind"] == "destlist-last-modified"]
                self.assertEqual(
                    sorted(set(destlist)), ["2024-01-01T00:00:00.0000001+00:00", "2024-01-01T00:00:00.0000007+00:00"]
                )
                self.assertLess(destlist.index("2024-01-01T00:00:00.0000001+00:00"), destlist.index("2024-01-01T00:00:00.0000007+00:00"))


WALL_EVENT = {
    "timestamp": "2024-01-02T09:00:00",
    "timezone": "local-unknown",
    "timestamp_kind": "first-connected",
    "event_type": "artifact-registry-network-profile-first-connected",
    "source": "artifacts",
    "summary": "synthetic network profile",
}
INSTANT_EVENT = {
    "timestamp": "2024-01-02T09:00:00.0000001+00:00",
    "timezone": "UTC",
    "timestamp_kind": "event",
    "event_type": "eventlog-logon-success",
    "source": "artifacts",
    "summary": "synthetic logon",
}


class WallClockRangeTests(unittest.TestCase):
    """#19 (D14-8): a wall clock of undetermined zone is never decided against a UTC range."""

    WALL = WALL_EVENT
    INSTANT = INSTANT_EVENT

    def _summary(self, root: Path) -> Path:
        timeline = root / "timeline.json"
        timeline.write_text(json.dumps({"events": [self.WALL, self.INSTANT]}), encoding="utf-8")
        summary = root / "summary.json"
        summary.write_text(json.dumps({"outputs": {"timeline": str(timeline)}}), encoding="utf-8")
        return summary

    def test_utc_range_excludes_and_lists_the_undetermined_wall_clock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summary = self._summary(Path(tmp))
            export = build_unified_timeline_export(summary, start="2024-01-02T08:59:59Z", end="2024-01-02T09:00:01Z")
            self.assertEqual([event["timestamp"] for event in export["events"]], [self.INSTANT["timestamp"]])
            self.assertEqual(export["events"][0]["zone_status"], "utc-instant")
            listed = export["zone_undetermined_events"]
            self.assertEqual(len(listed), 1)
            self.assertEqual(
                (listed[0]["timestamp"], listed[0]["timezone"], listed[0]["zone_status"], listed[0]["source_timestamp_kind"]),
                ("2024-01-02T09:00:00", "local-unknown", "wall-clock-zone-undetermined", "first-connected"),
            )
            self.assertEqual(export["summary"]["range_filter"]["zone_undetermined_event_count"], 1)
            self.assertEqual(export["summary"]["range_filter"]["zone_undetermined_policy"], "excluded-listed-separately")
            # A range no offset (-12:00..+14:00) can reach does not list it either.
            far = build_unified_timeline_export(summary, start="2024-01-05T00:00:00Z", end="2024-01-05T01:00:00Z")
            self.assertEqual((far["events"], far["zone_undetermined_events"]), ([], []))
            # Without a range nothing is decided: the row stays, flagged.
            whole = build_unified_timeline_export(summary)
            self.assertEqual(
                sorted(event["zone_status"] for event in whole["events"]), ["utc-instant", "wall-clock-zone-undetermined"]
            )

    def test_stated_assumption_converts_into_its_own_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summary = self._summary(Path(tmp))
            for zone in ("+09:00", "Asia/Seoul"):
                with self.subTest(zone=zone):
                    export = build_unified_timeline_export(
                        summary, start="2024-01-01T23:59:59Z", end="2024-01-02T00:00:01Z", assume_local_timezone=zone
                    )
                    self.assertEqual(len(export["events"]), 1)
                    event = export["events"][0]
                    self.assertEqual(event["timestamp"], "2024-01-02T09:00:00")
                    self.assertEqual(event["assumed_utc"], "2024-01-02T00:00:00.0000000Z")
                    self.assertEqual(event["assumed_timezone"], zone)
                    self.assertNotIn("assumed_utc_ticks", event)
                    self.assertEqual(export["summary"]["range_filter"]["zone_undetermined_policy"], "assumed-timezone")
                    # The old wall-clock-as-UTC window no longer catches it.
                    old = build_unified_timeline_export(
                        summary, start="2024-01-02T08:59:59Z", end="2024-01-02T08:59:59.9Z", assume_local_timezone=zone
                    )
                    self.assertEqual(old["events"], [])

    def test_api_time_condition_and_case_uco_keep_the_zone_status(self) -> None:
        self.assertIsNone(row_time(self.WALL, "timeline"))
        self.assertIsNotNone(row_time(self.INSTANT, "timeline"))
        with tempfile.TemporaryDirectory() as tmp:
            database_path = Path(tmp) / "case.db"
            _build_case_db(database_path)
            database = open_case_database(database_path)
            with database.connect() as connection:
                connection.execute(
                    "INSERT INTO event (case_id, citation_id, event_type, timestamp, timestamp_kind, timezone) "
                    "VALUES ('CASE-UCO-1', 'EVT-WALL', 'observed', ?, 'first-connected', 'local-unknown')",
                    (self.WALL["timestamp"],),
                )
            answer = export_case_uco_jsonld(database, case_id="CASE-UCO-1")
            graph = json.loads(Path(answer["output"]).read_text(encoding="utf-8"))["@graph"]
            wall = next(node for node in graph if node.get("rapidtriage:citationId") == "EVT-WALL")
            self.assertEqual(wall["uco-action:startTime"]["@value"], "2024-01-02T09:00:00")
            self.assertEqual(wall["rapidtriage:timezone"], "local-unknown")
            self.assertEqual(wall["rapidtriage:timeZoneStatus"], "wall-clock-zone-undetermined")
            self.assertEqual(wall["rapidtriage:timestampKind"], "first-connected")


def console_source_digest(frontend: Path) -> str:
    """Digest of the console source the bundle must be built from; mirrors
    ``consoleSourceDigest`` in ``frontend/vite.config.ts``."""
    files: list[str] = []
    for directory, _, names in os.walk(frontend / "src"):
        for name in names:
            if name.startswith("."):
                continue
            path = (Path(directory) / name).relative_to(frontend).as_posix()
            if path.startswith("src/schemas/") or re.search(r"\.test\.tsx?$", path) or path == "src/testSetup.ts":
                continue
            files.append(path)
    files.extend(["index.html", "vite.config.ts", "package.json", "package-lock.json"])
    digest = hashlib.sha256()
    for path in sorted(files):
        digest.update(f"{path}\0{hashlib.sha256((frontend / path).read_bytes()).hexdigest()}\n".encode())
    return digest.hexdigest()


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for the served console")
@unittest.skipUnless((FRONTEND / "src").is_dir(), "frontend sources are not part of this checkout")
class ShippedConsoleTests(unittest.TestCase):
    """#10: the console the ASGI root serves is the one built from the current frontend source."""

    def setUp(self) -> None:
        self.client = TestClient(create_app())
        page = self.client.get("/")
        self.assertEqual(page.status_code, 200)
        self.page = page.text

    def test_served_bundle_is_built_from_the_current_frontend_source(self) -> None:
        stamp = re.findall(r'<meta name="rapidtriage-console-source" content="sha256:([0-9a-f]{64})"', self.page)
        self.assertEqual(
            stamp,
            [console_source_digest(FRONTEND)],
            "rapidtriage/web/static/v2 is stale: rebuild it with `cd frontend && npm run build` and commit the bundle",
        )

    def test_console_pages_are_revalidated_but_hashed_assets_are_not(self) -> None:
        # A heuristically cached index.html kept serving the previous bundle after an update.
        self.assertEqual(self.client.get("/").headers.get("cache-control"), "no-cache")
        self.assertEqual(self.client.get("/v2/").headers.get("cache-control"), "no-cache")
        (asset,) = re.findall(r'<script type="module"[^>]* src="([^"]+)"', self.page)
        self.assertIsNone(self.client.get(asset).headers.get("cache-control"))

    def test_served_bundle_carries_the_lossless_time_code(self) -> None:
        (asset,) = re.findall(r'<script type="module"[^>]* src="([^"]+)"', self.page)
        script = self.client.get(asset)
        self.assertEqual(script.status_code, 200)
        for marker in ("시각 UTC 원문", "시간대 상태", "현지 시각(시간대 미확정·환산 안 함)", "FILETIME(환산)", "_100ns`"):
            with self.subTest(marker=marker):
                self.assertIn(marker, script.text)


if __name__ == "__main__":
    unittest.main()
