"""R6 S3 갈래 A: timeline column index (``rapidtriage.api.app.timeline_index``).

Q-S3-1 equivalence (random events x 40 condition combos = the predicate scan), Q-S3-3 index
invalidation (stamp / header / rules), Q-S3-8 read-only output folder (memory only, no 500) and the
API wiring (first page from the index, later pages from ``MATCH_CACHE``). The 500k-event
performance check lives in ``scripts/perf-r6.py --timeline`` (not a unit test)."""

from __future__ import annotations

import json
import random
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import create_app, timeline_index
    from rapidtriage.api.app.row_conditions import MATCH_CACHE, parse_row_conditions
    from rapidtriage.api.app.timeline_index import (
        INDEX_FILE_NAME,
        MISSING,
        TIMELINE_INDEXES,
        build_timeline_index,
        evaluate,
        event_epoch,
        index_path_for,
        load_index,
        open_index,
        write_timeline_index,
    )

    HAS_FASTAPI = True
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

from rapidtriage.core.jobs import RunJobStore

TOKEN = "r6-s3-timeline-index-token"
HANGUL = range(0xAC00, 0xD7A4)

EDGE_TIMES: tuple[object, ...] = (
    "0001-01-01T00:00:00Z",
    "0001-01-01T00:30:00+09:00",  # UTC instant before year 1: never passes a clock condition
    "0001-01-01T05:00:00+09:00",
    "0001-01-01T03:00:00",
    "9999-12-31T23:59:59.9999999Z",  # 7-digit fraction
    "9999-12-31T23:30:00-05:00",  # UTC instant after year 9999
    "9999-12-31T20:00:00Z",  # +09:00 local is year 10000
    "9999-12-31 10:00:00",
    "2025-03-09T06:30:00Z",  # America/New_York DST start (07:00Z)
    "2025-03-09T07:30:00Z",
    "2025-11-02T05:59:59.999999Z",  # America/New_York DST end (06:00Z)
    "2025-11-02T06:00:00Z",
    "2025-04-05T14:45:00Z",  # Australia/Lord_Howe 30-minute DST end (15:00Z)
    "2025-04-05T15:15:00Z",
    "1908-03-31T15:20:00Z",  # Asia/Seoul LMT era
    "1970-01-01T00:00:00Z",
    "1969-12-31T23:59:59.999999Z",
    "2025-05-30",
    "2025-05-30T09:00",
    "2025-05-30t09:00:00z",
    " 2025-05-30T09:00:00+09:00 ",
    "2025-05-30T09:00:00,5Z",
    "2025-05-30T09:00:00.1234567+09:00",
    "20250530T090000Z",
    "2025-13-01T00:00:00Z",
    "not a time",
    "2025",
    "   ",
    "",
    None,
    True,
    0,
    1748595600,
    1748595600.123456,
    -62135596800,
    float("nan"),
    1e30,
    ["2025-05-30T09:00:00Z"],
    {"value": "2025-05-30T09:00:00Z"},
)
ARTIFACT_TYPES: tuple[object, ...] = (
    "recent-shortcut",
    "prefetch-file",
    "eventlog-event",
    "browser-download",
    "media-image",
    "Media-Video",
    "document-pdf",
    "archive-zip-entry",
    "sqlite-row",
    "email",
    "email-attachment",
    "jumplist-entry-invalid",
    "registry-unreadable",
    "lnk-parse-error",
    "media-player-recent",
    "",
    None,
    7,
)
EXTENSIONS = ("docx", "EXE", "jpg", "zip", "mp4", "mp3", "db", "eml", "txt", "x" * 13, "tar-gz", "", "ps1")
STATUSES = ("ok", "parsed", "parsed-no-errors", "truncated-item", "not parsed", "error", "Too Large", "out of range", 3)
DECRYPTS = ("success", "failed", "Unknown", "wrong-key", "", 0)
TRUNCATIONS = ("truncated", "scan_truncated", "event_data_truncated", "message_text_truncated", "parse_truncated")
TARGET_KEYS = ("target_path", "media_path", "file_name", "filename", "attachment_name", "source_path")


def random_time(rng: random.Random) -> object:
    roll = rng.random()
    if roll < 0.25:
        return rng.choice(EDGE_TIMES)
    year = rng.choice((1, 2, 1900, 1969, 1970, 2000, 2024, 2025, 2026, 9998, 9999)) if roll < 0.35 else rng.randint(2023, 2026)
    month, day = rng.randint(1, 12), rng.randint(1, 28)
    clock = f"{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d}"
    fraction = rng.choice(("", ".5", f".{rng.randint(0, 999999):06d}", f".{rng.randint(0, 9999999):07d}"))
    zone = rng.choice(("Z", "+00:00", "+09:00", "-05:00", "+05:30", "-14:00", "+14:00", "", "", "+0900"))
    separator = rng.choice(("T", "T", " "))
    return f"{year:04d}-{month:02d}-{day:02d}{separator}{clock}{fraction}{zone}"


def random_container(rng: random.Random) -> dict[str, object]:
    out: dict[str, object] = {}
    if rng.random() < 0.1:
        out["parser_error"] = rng.choice((True, False, "true"))
    if rng.random() < 0.2:
        out["parse_status"] = rng.choice(STATUSES)
    if rng.random() < 0.1:
        out["decrypt_status"] = rng.choice(DECRYPTS)
    if rng.random() < 0.08:
        out["coverage"] = rng.choice(("partial", "full", {"status": "partial"}, {"status": "full"}))
    if rng.random() < 0.15:
        out[rng.choice(TRUNCATIONS)] = rng.choice((True, False, 1))
    return out


def random_event(rng: random.Random, position: int) -> object:
    if rng.random() < 0.01:
        return rng.choice(("not an event", None, 5, ["x"]))
    details: dict[str, object] = random_container(rng)
    if rng.random() < 0.6:
        details["artifact_type"] = rng.choice(ARTIFACT_TYPES)
    for _ in range(rng.choice((0, 1, 1, 2))):
        name = rng.choice(("a", "report", ".hidden", "dir.d/file", "C:\\Users\\a\\b"))
        extension = rng.choice(EXTENSIONS)
        path = rng.choice((f"C:\\x\\{name}.{extension}", f"/home/u/{name}.{extension}", f" {name}.{extension} ", f"{name}"))
        details[rng.choice(TARGET_KEYS)] = path if rng.random() < 0.9 else 42
    event: dict[str, object] = {"source": "artifacts", "event_type": f"e{position}", "path": "C:\\x", **random_container(rng)}
    if rng.random() < 0.95:
        event["timestamp"] = random_time(rng)
    if rng.random() < 0.3:
        event["artifact_type"] = rng.choice(ARTIFACT_TYPES)
    if rng.random() < 0.97:
        event["details"] = details if rng.random() < 0.98 else "not a mapping"
    return event


COMBOS: tuple[dict[str, object], ...] = (
    {"time_from": "2025-01-01T00:00:00Z"},
    {"time_to": "2025-06-30"},
    {"time_from": "2025-05-30T09:00", "time_to": "2025-05-30T09:00", "tz": "+09:00"},
    {"time_from": "2024-02-29", "time_to": "2025-02-28T23:59:59.5", "tz": "Asia/Seoul"},
    {"time_from": "0001-01-01T00:00:00Z"},
    {"time_from": "0001-01-01T00:00:00", "tz": "+14:00"},
    {"time_to": "9999-12-31"},
    {"time_to": "9999-12-31T23:59:59.999999Z"},
    {"time_to": "0001-01-01T09:00:00+09:00"},
    {"time_from": "9999-12-31T00:00:00-14:00"},
    {"time_from": "1969-12-31T23:59:59.999999Z", "time_to": "1970-01-01"},
    {"weekday": ["sat", "sun"]},
    {"weekday": ["mon,tue"], "tz": "Asia/Seoul"},
    {"hours": "09-18"},
    {"hours": "18-09", "tz": "+09:00"},
    {"hours": "22-02", "tz": "-05:00"},
    {"offhours": True},
    {"offhours": True, "tz": "Asia/Seoul"},
    {"offhours": True, "tz": "+14:00"},
    {"offhours": True, "tz": "-14:00"},
    {"offhours": True, "tz": "America/New_York"},
    {"offhours": True, "hours": "20-06", "weekday": ["sun"], "tz": "+05:30"},
    {"weekday": ["fri"], "hours": "00-03", "tz": "Australia/Lord_Howe"},
    {"hours": "01-02", "tz": "America/New_York"},
    {"weekday": ["sat"], "tz": "UTC"},
    {"weekday": ["mon"], "tz": "+00:00"},
    {"partial": True},
    {"content": ["document"]},
    {"content": ["image", "video"]},
    {"content": ["executable", "archive", "database", "mail", "audio"]},
    {"partial": True, "content": ["document", "image"]},
    {"partial": True, "time_from": "2025-01-01"},
    {"content": ["executable"], "offhours": True, "tz": "Asia/Seoul"},
    {"content": ["document"], "time_to": "2025-05-30T09:00:00+09:00"},
    {"partial": True, "weekday": ["wed"], "hours": "09-18", "tz": "America/New_York"},
    {"time_from": "2025-03-09T01:00:00", "time_to": "2025-03-09T04:00:00", "tz": "America/New_York", "hours": "01-04"},
    {"time_from": "1900-01-01", "time_to": "2100-01-01", "weekday": ["thu"], "tz": "Asia/Seoul"},
    {"time_from": "0001-01-01", "time_to": "9999-12-31", "offhours": True, "tz": "+09:00"},
    {"time_from": "0001-01-01T00:00:00+09:00", "offhours": True, "tz": "UTC"},
    {"content": ["mail"], "partial": True, "weekday": ["sun"], "tz": "Asia/Seoul"},
)


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for timeline index tests")
class TimelineIndexEquivalenceTests(unittest.TestCase):
    """Q-S3-1: index evaluation = ``RowConditions.predicate("timeline")`` on the same events."""

    def test_random_events_match_the_predicate_for_every_combo(self) -> None:
        self.assertEqual(len(COMBOS), 40)
        rng = random.Random(20261019)
        events = [random_event(rng, position) for position in range(20_000)]
        index = build_timeline_index(events)
        for combo in COMBOS:
            conditions = parse_row_conditions(**combo)  # type: ignore[arg-type]
            assert conditions is not None
            predicate = conditions.predicate("timeline")
            expected = [i for i, row in enumerate(events) if isinstance(row, dict) and predicate(row)]
            with self.subTest(combo=combo):
                self.assertEqual(evaluate(index, conditions), expected)
        # The combos exercise both outcomes, not only empty / full sets.
        sizes = {
            json.dumps(combo, sort_keys=True): len(evaluate(index, parse_row_conditions(**combo)))  # type: ignore[arg-type]
            for combo in COMBOS
        }
        self.assertTrue(all(0 < size < len(events) for size in sizes.values()), sizes)

    def test_first_request_subset_path_matches_the_predicate(self) -> None:
        """Several missing columns: one is built, the rest only for its matches -- same set."""
        rng = random.Random(4242)
        events = [random_event(rng, position) for position in range(4_000)]
        with mock.patch.object(timeline_index, "SYNC_COMPLETE_MAX_EVENTS", 0):
            for combo in COMBOS:
                conditions = parse_row_conditions(**combo)  # type: ignore[arg-type]
                assert conditions is not None
                predicate = conditions.predicate("timeline")
                expected = [i for i, row in enumerate(events) if isinstance(row, dict) and predicate(row)]
                for prebuilt in ((), (timeline_index.TIME,), (timeline_index.CONTENT,)):
                    index = timeline_index.TimelineIndex(len(events))
                    index.ensure(events, prebuilt)
                    with self.subTest(combo=combo, prebuilt=prebuilt):
                        self.assertEqual(timeline_index.evaluate_building(index, events, conditions), expected)

    def test_zone_clock_matches_astimezone(self) -> None:
        """Per-day / per-hour offset caches = ``astimezone`` (DST, 30-minute shifts, skipped days)."""
        import datetime as dt
        from zoneinfo import ZoneInfo

        epoch = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
        rng = random.Random(99)
        for name in ("America/New_York", "Australia/Lord_Howe", "Asia/Seoul", "Pacific/Apia", "Europe/London"):
            zone = ZoneInfo(name)
            clock = timeline_index._ZoneClock(zone)
            instants = [rng.randrange(-4_000_000_000, 4_000_000_000) * 1_000_000 for _ in range(3_000)]
            start = int((dt.datetime(2011, 12, 29, tzinfo=dt.timezone.utc) - epoch).total_seconds()) * 1_000_000
            instants += [start + step * 600_000_000 for step in range(600)]  # Apia skipped 2011-12-30
            for instant in instants:
                local = (epoch + dt.timedelta(microseconds=instant)).astimezone(zone)
                with self.subTest(zone=name, instant=instant):
                    self.assertEqual(clock.hour_of_week(instant), local.weekday() * 24 + local.hour)

    def test_edge_times_one_by_one(self) -> None:
        events = [{"timestamp": value, "details": {}} for value in EDGE_TIMES]
        index = build_timeline_index(events)
        for combo in COMBOS:
            conditions = parse_row_conditions(**combo)  # type: ignore[arg-type]
            assert conditions is not None
            predicate = conditions.predicate("timeline")
            with self.subTest(combo=combo):
                self.assertEqual(evaluate(index, conditions), [i for i, row in enumerate(events) if predicate(row)])

    def test_epoch_column_values(self) -> None:
        self.assertEqual(event_epoch("1970-01-01T00:00:00Z"), (0, 1))
        self.assertEqual(event_epoch("1970-01-01T09:00:00+09:00"), (0, 1))
        self.assertEqual(event_epoch("1970-01-01 00:00:01"), (1_000_000, 0))  # naive = UTC
        self.assertEqual(event_epoch("1970-01-01T00:00:00.0000019Z"), (1, 1))  # 7th digit dropped
        self.assertEqual(event_epoch("nope"), (MISSING, 0))
        self.assertEqual(event_epoch(None), (MISSING, 0))
        self.assertEqual(event_epoch(1.5), (1_500_000, 1))
        index = build_timeline_index([{"timestamp": "2025-01-01"}, "x", {"timestamp": "2025-01-01T00:00:00Z"}])
        self.assertEqual(list(index.has_offset or b""), [0, 0, 1])
        self.assertEqual(index.epoch_us[1] if index.epoch_us else None, MISSING)


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for timeline index tests")
class TimelineIndexFileTests(unittest.TestCase):
    """Q-S3-3: the saved index is used only while its header matches the timeline revision."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.timeline = Path(self.temp.name) / "rapidtriage-timeline.json"
        rng = random.Random(7)
        self.events = [random_event(rng, position) for position in range(500)]
        self.timeline.write_text(json.dumps({"events": self.events}), encoding="utf-8")

    def stamp(self) -> tuple[int, int]:
        stat = self.timeline.stat()
        return stat.st_size, stat.st_mtime_ns

    def test_written_index_round_trips(self) -> None:
        written = write_timeline_index(self.events, self.timeline)
        self.assertEqual(written, self.timeline.with_name(INDEX_FILE_NAME))
        loaded = load_index(index_path_for(self.timeline), self.stamp(), len(self.events))
        assert loaded is not None
        built = build_timeline_index(self.events)
        self.assertEqual(loaded.source, "file")
        self.assertEqual(loaded.epoch_us, built.epoch_us)
        self.assertEqual(loaded.has_offset, built.has_offset)
        self.assertEqual(loaded.content_mask, built.content_mask)
        self.assertEqual(loaded.partial, built.partial)
        self.assertEqual(open_index(self.timeline, len(self.events)).source, "file")

    def test_stale_or_damaged_index_is_ignored(self) -> None:
        write_timeline_index(self.events, self.timeline)
        index_file = index_path_for(self.timeline)
        # Rewritten timeline (size / mtime change): the old file no longer applies.
        self.timeline.write_text(json.dumps({"events": self.events[:-1]}), encoding="utf-8")
        self.assertIsNone(load_index(index_file, self.stamp(), len(self.events) - 1))
        reopened = open_index(self.timeline, len(self.events) - 1)
        self.assertEqual((reopened.source, reopened.epoch_us), ("built", None))
        # Restore the matching revision, then damage the file in different ways.
        self.timeline.write_text(json.dumps({"events": self.events}), encoding="utf-8")
        write_timeline_index(self.events, self.timeline)
        good = index_file.read_bytes()
        self.assertIsNotNone(load_index(index_file, self.stamp(), len(self.events)))
        self.assertIsNone(load_index(index_file, self.stamp(), len(self.events) + 1))
        for damaged in (b"", b"XXXXXXXX" + good[8:], good[:-1], good + b"\0", good.replace(b'"rules":"', b'"rules":"0', 1)):
            index_file.write_bytes(damaged)
            with self.subTest(size=len(damaged)):
                self.assertIsNone(load_index(index_file, self.stamp(), len(self.events)))
        index_file.write_bytes(good)
        with mock.patch.object(timeline_index, "RULES_FINGERPRINT", "changed-rules"):
            self.assertIsNone(load_index(index_file, self.stamp(), len(self.events)))

    def test_unwritable_folder_keeps_the_index_in_memory(self) -> None:
        with mock.patch.object(Path, "open", side_effect=PermissionError("read-only")):
            self.assertIsNone(write_timeline_index(self.events, self.timeline))
        self.assertFalse(index_path_for(self.timeline).exists())
        self.assertEqual(list(Path(self.temp.name).glob("*.tmp")), [])


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for timeline index tests")
class TimelineIndexApiTests(unittest.TestCase):
    """``GET /timeline`` with conditions reads the index; results equal the predicate scan."""

    def setUp(self) -> None:
        TIMELINE_INDEXES.clear()
        MATCH_CACHE.clear()
        self.addCleanup(TIMELINE_INDEXES.clear)
        self.addCleanup(MATCH_CACHE.clear)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.run_dir = base / "run"
        self.run_dir.mkdir()
        rng = random.Random(11)
        self.events = [random_event(rng, position) for position in range(3_000)]
        self.timeline = self.run_dir / "rapidtriage-timeline.json"
        self.timeline.write_text(json.dumps({"summary": {"event_count": len(self.events)}, "events": self.events}), encoding="utf-8")
        summary = self.run_dir / "rapidtriage-run-summary.json"
        summary.write_text(
            json.dumps(
                {
                    "profile_version": "rapidtriage-run-summary-v1",
                    "mode": "hacking",
                    "root": str(base / "evidence"),
                    "output_dir": str(self.run_dir),
                    "source": {"type": "directory", "analysis_root": str(base / "evidence")},
                    "outputs": {"timeline": str(self.timeline), "summary": str(summary)},
                    "summary": {"counts": {}},
                }
            ),
            encoding="utf-8",
        )
        self.store = RunJobStore()
        self.run_id = self.store.import_completed_run(self.run_dir).run_id
        self.client = TestClient(create_app(self.store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})

    def page(self, query: str) -> dict[str, object]:
        response = self.client.get(f"/api/runs/{self.run_id}/timeline?{query}")
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def all_matches(self, query: str) -> list[int]:
        out: list[int] = []
        offset = 0
        while True:
            body = self.page(f"{query}&limit=1000&offset={offset}")
            out.extend(int(event["record_index"]) for event in body["events"])  # type: ignore[index, union-attr]
            pagination = body["pagination"]
            assert isinstance(pagination, dict)
            if not pagination["has_more"]:
                return out
            offset = int(pagination["next_offset"])

    def expected(self, **combo: object) -> list[int]:
        conditions = parse_row_conditions(**combo)  # type: ignore[arg-type]
        assert conditions is not None
        predicate = conditions.predicate("timeline")
        return [i for i, row in enumerate(self.events) if isinstance(row, dict) and predicate(row)]

    def test_first_request_builds_and_saves_the_index(self) -> None:
        index_file = self.run_dir / INDEX_FILE_NAME
        self.assertFalse(index_file.exists())
        self.assertEqual(self.all_matches("offhours=1&tz=Asia/Seoul"), self.expected(offhours=True, tz="Asia/Seoul"))
        self.assertTrue(index_file.exists())  # small timeline: completed and saved in the request
        self.assertEqual(self.all_matches("content=document&partial=1"), self.expected(content=["document"], partial=True))
        body = self.page("limit=5&from=2025-01-01&tz=%2B09:00")
        self.assertEqual(body["matched"], len(self.expected(time_from="2025-01-01", tz="+09:00")))
        self.assertEqual(body["record_count"], len(self.events))
        # A fresh process (empty caches) reads the saved file instead of building.
        TIMELINE_INDEXES.clear()
        MATCH_CACHE.clear()
        with mock.patch.object(timeline_index, "time_column", side_effect=AssertionError("rebuilt")):
            self.assertEqual(self.all_matches("weekday=sat,sun"), self.expected(weekday=["sat,sun"]))

    def test_later_pages_reuse_the_matched_positions(self) -> None:
        first = self.page("limit=10&hours=09-18")
        with mock.patch.object(timeline_index, "evaluate", side_effect=AssertionError("re-evaluated")):
            second = self.page("limit=10&offset=10&hours=09-18")
        self.assertEqual(first["matched"], second["matched"])
        indices = [event["record_index"] for event in first["events"] + second["events"]]  # type: ignore[operator]
        self.assertEqual(indices, self.expected(hours="09-18")[:20])

    def test_rewritten_timeline_rebuilds_the_index(self) -> None:
        self.page("limit=10&partial=1")
        index_file = self.run_dir / INDEX_FILE_NAME
        before = index_file.read_bytes()
        self.events = self.events[:1000]
        time.sleep(0.01)
        self.timeline.write_text(json.dumps({"events": self.events}), encoding="utf-8")
        self.assertEqual(self.all_matches("partial=1"), self.expected(partial=True))
        self.assertNotEqual(index_file.read_bytes(), before)
        loaded = load_index(index_file, (self.timeline.stat().st_size, self.timeline.stat().st_mtime_ns), 1000)
        self.assertIsNotNone(loaded)

    def test_read_only_output_folder_answers_from_memory(self) -> None:
        with mock.patch.object(timeline_index, "save_index", return_value=False) as save:
            self.assertEqual(self.all_matches("content=image"), self.expected(content=["image"]))
            self.assertEqual(self.all_matches("weekday=mon"), self.expected(weekday=["mon"]))
        self.assertEqual(save.call_count, 1)  # tried once, then memory only
        self.assertFalse((self.run_dir / INDEX_FILE_NAME).exists())

    def test_index_failure_falls_back_to_the_scan(self) -> None:
        with mock.patch.object(timeline_index, "open_index", side_effect=OSError("disk gone")):
            self.assertEqual(self.all_matches("offhours=1"), self.expected(offhours=True))
        with mock.patch.object(timeline_index, "evaluate", side_effect=RuntimeError("bug")):
            MATCH_CACHE.clear()
            self.assertEqual(self.all_matches("hours=00-06"), self.expected(hours="00-06"))

    def test_large_timeline_completes_in_the_background(self) -> None:
        with mock.patch.object(timeline_index, "SYNC_COMPLETE_MAX_EVENTS", 10):
            self.assertEqual(self.all_matches("from=2025-01-01"), self.expected(time_from="2025-01-01"))
            self.assertTrue(timeline_index.wait_for_background(30))
        self.assertTrue((self.run_dir / INDEX_FILE_NAME).exists())
        TIMELINE_INDEXES.clear()
        MATCH_CACHE.clear()
        self.assertEqual(self.all_matches("content=video"), self.expected(content=["video"]))

    def test_bad_values_stay_korean_422(self) -> None:
        response = self.client.get(f"/api/runs/{self.run_id}/timeline?limit=10&tz=Mars/Base")
        self.assertEqual(response.status_code, 422)
        self.assertTrue(any(ord(char) in HANGUL for char in response.json()["detail"]))


if __name__ == "__main__":
    unittest.main()
