"""R6 S3 step 3 backend: regressions for the adversarial-review findings (synthetic data only).

1. ``/geo-clusters``: every cluster's ``box`` re-queried returns exactly ``count`` rows (edge cells
   clamped at exactly +-90 / +-180, no 1e-9 floor epsilon).
2. A request needing a timeline column never waits behind the throttled background build.
3. ``OutputJsonCache``: two outputs over the byte budget read in turn both stay cached.
4. A planted / corrupt ``rapidtriage-geo-index.json`` is ignored and rebuilt (never a 500).
5. A failed geo-index build is retried after ``GEO_INDEX_RETRY_SECONDS``.
6. Stamps are taken before the data is read (timeline route, geo scan).
7. Saved index files carry a first / last 64 KB digest (a same-size, same-mtime rewrite is noticed).
8. ``RULES_FINGERPRINT`` covers the parse-status negations.
9. ``GeoEntry`` uses slots.
10. ``SingleFlightIndexCache``: an older build finishing late keeps the newer entry.
11. Index writers remove their temporary file on any error; the perf script joins background
    builds before restoring the environment.
"""

from __future__ import annotations

import json
import math
import os
import random
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.core.jobs import OutputJsonCache, RunJobStore

try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import create_app, geo_index, routes_runs, timeline_index
    from rapidtriage.api.app.geo_index import GeoEntry, GeoIndexService, build_clusters
    from rapidtriage.api.app.index_cache import SingleFlightIndexCache, head_tail_digest
    from rapidtriage.api.app.row_conditions import (
        MATCH_CACHE,
        in_geo_box,
        parse_geo,
        parse_row_conditions,
    )

    HAS_FASTAPI = True
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

TOKEN = "r6-s3-backend-review-token"
SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def media(lat: object, lon: object, **details: object) -> dict[str, object]:
    return {"artifact_type": "media-image", "path": r"C:\p\a.jpg", "details": {"gps_latitude": lat, "gps_longitude": lon, **details}}


def write_summary(run_dir: Path, outputs: dict[str, str]) -> None:
    summary = run_dir / "rapidtriage-run-summary.json"
    summary.write_text(
        json.dumps(
            {
                "profile_version": "rapidtriage-run-summary-v1",
                "mode": "hacking",
                "root": str(run_dir / "evidence"),
                "output_dir": str(run_dir),
                "source": {"type": "directory", "analysis_root": str(run_dir / "evidence")},
                "outputs": {**outputs, "summary": str(summary)},
                "summary": {"counts": {}},
            }
        ),
        encoding="utf-8",
    )


def geo_run(run_dir: Path, rows: list[dict[str, object]]) -> tuple[Path, Path, dict[str, object]]:
    """A run with one JSONL kind ``media``: (payload path, records path, payload)."""
    records = run_dir / "media.jsonl"
    records.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8", newline="\n")
    payload: dict[str, object] = {"record_count": len(rows), "records_path": str(records), "artifacts": []}
    payload_path = run_dir / "artifacts_media.json"
    payload_path.write_text(json.dumps(payload), encoding="utf-8")
    return payload_path, records, payload


def timeline_events(count: int) -> list[dict[str, object]]:
    return [
        {
            "timestamp": f"2025-05-{position % 28 + 1:02d}T{position % 24:02d}:00:00Z",
            "artifact_type": "media-image" if position % 3 else "document-x",
            "details": {"path": f"a{position % 50}.jpg", "parse_status": "ok" if position % 7 else "truncated"},
        }
        for position in range(count)
    ]


# --- 1. cluster boxes ------------------------------------------------------------------------------


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required")
class ClusterBoxTests(unittest.TestCase):
    EDGE_POINTS: tuple[tuple[float, float], ...] = (
        (89.9995, 10.0),
        (-89.9995, 10.0),
        (-89.99999999, -179.99999999),
        (10.0, 179.9999),
        (10.0, -179.9999),
        (10.0, 180.0),
        (10.0, -180.0),
        (90.0, 0.5),
        (-90.0, -180.0),
        (90.0, 180.0),
        (0.0099999999995, 1.0),
        (0.0, 0.0099999999995),
        (-0.0099999999995, -0.0),
        (0.03, 0.07),
        (37.48, 126.94),
        (89.995, 1.0),
    )

    def check(self, cell: float, points: list[tuple[float, float]]) -> None:
        """Every cluster's ``box`` re-queried holds exactly its ``count`` rows. Cells are a grid, so
        a row can only fall in its own box or a neighbour's: each row is tested against its own
        cluster's box (no gap) and the up to 8 neighbouring boxes (no overlap)."""
        items = [("k", GeoEntry(number, -1, lat, lon, None, None)) for number, (lat, lon) in enumerate(points)]
        clusters, total = build_clusters(items, cell, max_clusters=10**9)
        self.assertEqual(sum(int(cluster["count"]) for cluster in clusters), len(points))
        self.assertEqual(total, len(clusters))
        boxes: dict[tuple[int, int], tuple[float, float, float, float]] = {}
        inside: dict[tuple[int, int], int] = {}
        for cluster in clusters:
            box = parse_geo(str(cluster["box"]))  # a 422 here would be a box outside the world
            assert box is not None
            lat_cell, lon_cell = (int(part) for part in str(cluster["id"]).split(":"))
            boxes[(lat_cell, lon_cell)] = box
            inside[(lat_cell, lon_cell)] = 0
        for _kind, entry in items:
            lat_cell, lon_cell = geo_index.cell_of(entry.lat, 90, cell), geo_index.cell_of(entry.lon, 180, cell)
            for d_lat in (-1, 0, 1):
                for d_lon in (-1, 0, 1):
                    key = (lat_cell + d_lat, lon_cell + d_lon)
                    if key in boxes and in_geo_box((entry.lat, entry.lon), boxes[key]):
                        inside[key] += 1
            self.assertTrue(in_geo_box((entry.lat, entry.lon), boxes[(lat_cell, lon_cell)]), (cell, entry))
        for cluster in clusters:
            lat_cell, lon_cell = (int(part) for part in str(cluster["id"]).split(":"))
            self.assertEqual(inside[(lat_cell, lon_cell)], cluster["count"], (cell, cluster["box"]))

    def requery(self, cell: float, points: list[tuple[float, float]]) -> None:
        """The literal re-query: every row against every cluster box (small inputs)."""
        items = [("k", GeoEntry(number, -1, lat, lon, None, None)) for number, (lat, lon) in enumerate(points)]
        for cluster in build_clusters(items, cell, max_clusters=10**9)[0]:
            box = parse_geo(str(cluster["box"]))
            assert box is not None
            count = sum(1 for _kind, entry in items if in_geo_box((entry.lat, entry.lon), box))
            self.assertEqual(count, cluster["count"], (cell, cluster["box"]))

    def test_every_cluster_box_requery_returns_its_rows(self) -> None:
        rng = random.Random(1)
        for cell in (0.007, 0.01, 0.003, 0.0013, 0.0067, 0.001, 0.25, 1.0):
            with self.subTest(cell=cell):
                points = list(self.EDGE_POINTS)
                points += [(rng.uniform(-90, 90), rng.uniform(-180, 180)) for _ in range(1500)]
                points += [(round(rng.uniform(-90, 90), 3), round(rng.uniform(-180, 180), 3)) for _ in range(1000)]
                # Values right at / next to cell edges.
                for _ in range(500):
                    edge = rng.randrange(-int(90 / cell), int(90 / cell)) * cell
                    points.append((max(-90.0, min(90.0, edge + rng.choice((0.0, -1e-12, 1e-12, -5e-13)))), edge / 2))
                self.check(cell, points)
                self.requery(cell, list(self.EDGE_POINTS) + points[len(self.EDGE_POINTS) : len(self.EDGE_POINTS) + 200])

    def test_last_cells_end_exactly_at_the_world_edge(self) -> None:
        items = [("k", GeoEntry(0, -1, 89.9995, 179.9995, None, None)), ("k", GeoEntry(1, -1, -89.9995, -179.9995, None, None))]
        boxes = sorted(str(cluster["box"]) for cluster in build_clusters(items, 0.007)[0])
        self.assertEqual(boxes, ["-90,-180,-89.992,-179.991", "89.992,179.991,90,180"])
        self.assertEqual(geo_index.cell_of(37.48, 90, 0.01), 3748)
        self.assertEqual(geo_index.cell_of(0.0099999999995, 90, 0.01), 0)


# --- 2. background throttle --------------------------------------------------------------------------


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required")
class BackgroundThrottleTests(unittest.TestCase):
    def test_request_does_not_wait_behind_the_throttled_build(self) -> None:
        events = timeline_events(120_000)
        started = time.perf_counter()
        expected = timeline_index.TimelineIndex(len(events))
        expected.ensure(events, (timeline_index.TIME,))
        sync_seconds = time.perf_counter() - started
        full = timeline_index.build_timeline_index(events)

        index = timeline_index.TimelineIndex(len(events))
        # 10 ms per 512-row slice: ~2.3 s of pauses for the time column if the request waited on them.
        with mock.patch.object(timeline_index, "BACKGROUND_PAUSE_S", 0.01):
            timeline_index._complete_later(index, events)
            for _ in range(500):
                if index._column_locks[timeline_index.TIME].locked():
                    break
                time.sleep(0.001)
            self.assertTrue(index._column_locks[timeline_index.TIME].locked(), "background build did not start")
            started = time.perf_counter()
            index.ensure(events, (timeline_index.TIME,))
            waited = time.perf_counter() - started
            timeline_index.BACKGROUND_PAUSE_S = 0.0  # finish the rest quickly (restored by the patch)
            self.assertTrue(timeline_index.wait_for_background(60))
        self.assertLess(waited, max(1.2, 4 * sync_seconds), (waited, sync_seconds))
        self.assertEqual(index.epoch_us, full.epoch_us)
        self.assertEqual(index.has_offset, full.has_offset)
        self.assertEqual(index.content_mask, full.content_mask)
        self.assertEqual(index.partial, full.partial)
        self.assertFalse(index.requests_waiting())


# --- 3. OutputJsonCache ----------------------------------------------------------------------------


class OutputJsonCacheLargeSlotsTests(unittest.TestCase):
    def test_two_oversized_outputs_read_in_turn_stay_cached(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            first_path, second_path = Path(temp) / "timeline.json", Path(temp) / "files.json"
            first_path.write_text(json.dumps({"x": "a" * 2000}), encoding="utf-8")
            second_path.write_text(json.dumps({"x": "b" * 2000}), encoding="utf-8")
            cache = OutputJsonCache(max_bytes=1000)
            first, second = cache.read(first_path), cache.read(second_path)
            for _ in range(3):
                self.assertIs(cache.read(first_path), first)
                self.assertIs(cache.read(second_path), second)
            self.assertEqual(cache.stats()["large_entries"], 2)
            third_path = Path(temp) / "other.json"
            third_path.write_text(json.dumps({"x": "c" * 2000}), encoding="utf-8")
            cache.read(third_path)  # LRU: the least recently read oversized payload goes
            self.assertEqual(cache.stats()["large_entries"], 2)
            self.assertIs(cache.read(second_path), second)


# --- 4 / 5 / 6 / 7: geo index file --------------------------------------------------------------------

ROWS = [media(37.4812, 126.9497, timestamp="2025-05-26T01:00:00Z"), media(35.1, 129.04), {"artifact_type": "x", "details": {}}, media(-10.5, 179.995)]


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required")
class GeoIndexFileTests(unittest.TestCase):
    def setUp(self) -> None:
        geo_index.GEO_INDEX_SERVICE.clear()
        self.addCleanup(geo_index.GEO_INDEX_SERVICE.clear)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.run_dir = Path(self.temp.name) / "run"
        self.run_dir.mkdir()
        self.payload_path, self.records, self.payload = geo_run(self.run_dir, ROWS)
        self.sources = [("media", self.payload, self.payload_path)]
        self.index_path = self.run_dir / geo_index.GEO_INDEX_FILE_NAME

    def build(self) -> geo_index.GeoIndex:
        return geo_index.load_or_build(self.sources, self.run_dir)

    def plant(self, mutate) -> None:  # type: ignore[no-untyped-def]
        document = json.loads(self.index_path.read_text(encoding="utf-8"))
        mutate(document)
        self.index_path.write_text(json.dumps(document), encoding="utf-8")

    def test_invalid_stored_rows_are_ignored_and_rebuilt(self) -> None:
        self.assertEqual(self.build().source, "built")
        self.assertEqual(self.build().source, "file")
        good = self.index_path.read_text(encoding="utf-8")

        def row(position: int, value: object):  # type: ignore[no-untyped-def]
            return lambda document: document["rows"][0].__setitem__(position, value)

        planted = {
            "nan lat": row(3, math.nan),
            "inf lon": row(4, math.inf),
            "1e308 lat": row(3, 1e308),
            "lat 90.5": row(3, 90.5),
            "lon -181": row(4, -181),
            "negative record": row(1, -1),
            "offset -2": row(2, -2),
            "kind index": row(0, 5),
            "negative kind": row(0, -1),
            "bool kind": row(0, True),
            "text lat": row(3, "37"),
            "nan epoch": row(6, math.nan),
            "time number": row(5, 12),
            "short row": lambda document: document["rows"].__setitem__(0, [0, 0, 0]),
            "row not list": lambda document: document["rows"].__setitem__(0, {"a": 1}),
            "kinds not str": lambda document: document.__setitem__("kinds", [1]),
        }
        for label, mutate in planted.items():
            with self.subTest(label):
                self.index_path.write_text(good, encoding="utf-8")
                self.plant(mutate)
                self.assertIsNone(geo_index.read_geo_index_file(self.run_dir, geo_index.sources_stamp(self.sources), self.sources))
                rebuilt = self.build()
                self.assertEqual(rebuilt.source, "built")
                self.assertEqual(rebuilt.located, 3)
                self.assertEqual(self.build().source, "file")  # the rebuild replaced the planted file

    def test_deep_nesting_and_row_cap(self) -> None:
        self.build()
        text = self.index_path.read_text(encoding="utf-8")
        self.index_path.write_text(text.replace('"rows":[', '"rows":[' + "[" * 200_000 + "]" * 200_000 + ",", 1), encoding="utf-8")
        self.assertIsNone(geo_index.read_geo_index_file(self.run_dir, geo_index.sources_stamp(self.sources), self.sources))
        self.assertEqual(self.build().source, "built")
        with mock.patch.object(geo_index, "GEO_INDEX_MAX_ROWS", 2):
            self.assertIsNone(geo_index.read_geo_index_file(self.run_dir, geo_index.sources_stamp(self.sources), self.sources))

    def test_planted_file_through_the_api_is_never_a_500(self) -> None:
        write_summary(self.run_dir, {"artifacts_media": str(self.payload_path)})
        store = RunJobStore()
        run_id = store.import_completed_run(self.run_dir).run_id
        client = TestClient(create_app(store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})
        first = client.get(f"/api/runs/{run_id}/geo-clusters?cell=0.007")
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(first.json()["matched"], 3)
        for value in (math.nan, 1e308, -math.inf):
            with self.subTest(value=value):
                self.plant(lambda document, value=value: document["rows"][0].__setitem__(3, value))
                geo_index.GEO_INDEX_SERVICE.clear()
                response = client.get(f"/api/runs/{run_id}/geo-clusters?cell=0.007")
                self.assertEqual(response.status_code, 200, response.text)
                body = response.json()
                self.assertEqual((body["geo_index"], body["geo_index_source"], body["matched"]), ("ready", "built", 3))
                listing = client.get(f"/api/runs/{run_id}/artifacts?geo=-90,-180,90,180&limit=10")
                self.assertEqual(listing.status_code, 200, listing.text)

    def test_same_size_same_mtime_rewrite_is_noticed_by_the_digest(self) -> None:
        self.build()
        stat = self.records.stat()
        body = self.records.read_bytes()
        changed = body.replace(b"126.9497", b"126.9498", 1)
        self.assertEqual(len(changed), len(body))
        self.records.write_bytes(changed)
        os.utime(self.records, ns=(stat.st_atime_ns, stat.st_mtime_ns))
        self.assertEqual(geo_index.sources_stamp(self.sources), geo_index.sources_stamp(self.sources))
        rebuilt = self.build()
        self.assertEqual(rebuilt.source, "built")
        self.assertEqual(rebuilt.by_kind["media"][0].lon, 126.9498)

    def test_stamp_is_taken_before_the_scan_reads(self) -> None:
        before = geo_index.sources_stamp(self.sources)
        real = geo_index._scan_jsonl

        def scan_then_append(*args, **kwargs):  # type: ignore[no-untyped-def]
            found = real(*args, **kwargs)
            time.sleep(0.01)
            with open(self.records, "a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(media(1.5, 2.5)) + "\n")
            return found

        with mock.patch.object(geo_index, "_scan_jsonl", side_effect=scan_then_append):
            index = self.build()
        self.assertEqual(index.stamp, before)
        self.assertEqual(index.source, "memory")  # the source changed during the scan: not written
        self.assertFalse(self.index_path.exists())
        self.assertNotEqual(geo_index.sources_stamp(self.sources), before)
        self.assertEqual(self.build().located, 4)  # the new revision is scanned afresh

    def test_failed_build_is_retried_after_the_retry_window(self) -> None:
        service = GeoIndexService()
        clock = [1000.0]
        calls: list[int] = []
        real = geo_index.load_or_build

        def flaky(sources, output_dir):  # type: ignore[no-untyped-def]
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("disk hiccup")
            return real(sources, output_dir)

        with mock.patch.object(geo_index, "_now", side_effect=lambda: clock[0]), mock.patch.object(
            geo_index, "load_or_build", side_effect=flaky
        ), self.assertLogs(geo_index.LOGGER, "WARNING"):
            self.assertEqual(service.lookup("r", self.sources, self.run_dir, wait=5)[1], "unavailable")
            clock[0] += geo_index.GEO_INDEX_RETRY_SECONDS - 1
            self.assertEqual(service.lookup("r", self.sources, self.run_dir, wait=5)[1], "unavailable")
            self.assertEqual(len(calls), 1)  # inside the window: no new build
            clock[0] += 2
            index, status = service.lookup("r", self.sources, self.run_dir, wait=5)
        self.assertEqual(status, "ready")
        self.assertEqual(len(calls), 2)
        assert index is not None
        self.assertEqual(index.located, 3)

    def test_geo_entry_uses_slots(self) -> None:
        entry = GeoEntry(1, 2, 3.0, 4.0, None, None)
        self.assertFalse(hasattr(entry, "__dict__"))
        self.assertLessEqual(geo_index.GEO_INDEX_CACHE_RUNS, 4)

    def test_writer_removes_its_temp_file_on_any_error(self) -> None:
        index = geo_index.scan_geo_index(self.sources)
        with mock.patch.object(geo_index.json, "dump", side_effect=RuntimeError("encoder bug")):
            with self.assertRaises(RuntimeError):
                geo_index.write_geo_index_file(index, self.run_dir, self.sources)
        self.assertEqual(sorted(path.name for path in self.run_dir.iterdir()), ["artifacts_media.json", "media.jsonl"])


# --- 6 / 7 / 8 / 11: timeline index ------------------------------------------------------------------


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required")
class TimelineStampTests(unittest.TestCase):
    def setUp(self) -> None:
        timeline_index.TIMELINE_INDEXES.clear()
        MATCH_CACHE.clear()
        self.addCleanup(timeline_index.TIMELINE_INDEXES.clear)
        self.addCleanup(MATCH_CACHE.clear)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.run_dir = Path(self.temp.name) / "run"
        self.run_dir.mkdir()
        self.timeline = self.run_dir / "rapidtriage-timeline.json"
        self.events = timeline_events(600)
        self.timeline.write_text(json.dumps({"events": self.events}), encoding="utf-8")

    def expected(self, events: list[dict[str, object]], **combo: object) -> int:
        conditions = parse_row_conditions(**combo)  # type: ignore[arg-type]
        assert conditions is not None
        predicate = conditions.predicate("timeline")
        return sum(1 for row in events if predicate(row))

    def test_rewrite_between_read_and_stamp_never_poisons_the_new_revision(self) -> None:
        write_summary(self.run_dir, {"timeline": str(self.timeline)})
        store = RunJobStore()
        run_id = store.import_completed_run(self.run_dir).run_id
        client = TestClient(create_app(store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})
        newer = self.events[:250]
        real = routes_runs.get_named_output

        def read_then_rewrite(store_, run_id_, name):  # type: ignore[no-untyped-def]
            payload = real(store_, run_id_, name)
            time.sleep(0.01)
            self.timeline.write_text(json.dumps({"events": newer}), encoding="utf-8")
            return payload

        with mock.patch.object(routes_runs, "get_named_output", side_effect=read_then_rewrite):
            first = client.get(f"/api/runs/{run_id}/timeline?partial=1&limit=5")
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(first.json()["matched"], self.expected(self.events, partial=True))
        # Index of the old events: kept in memory, never saved as the new revision's file.
        self.assertFalse((self.run_dir / timeline_index.INDEX_FILE_NAME).exists())
        second = client.get(f"/api/runs/{run_id}/timeline?partial=1&limit=5")
        self.assertEqual(second.json()["matched"], self.expected(newer, partial=True))
        self.assertEqual(second.json()["record_count"], len(newer))
        loaded = timeline_index.load_index(
            timeline_index.index_path_for(self.timeline),
            (self.timeline.stat().st_size, self.timeline.stat().st_mtime_ns),
            len(newer),
            head_tail_digest(self.timeline),
        )
        self.assertIsNotNone(loaded)  # the new revision's own index was saved afterwards

    def test_open_index_with_an_older_stamp_stays_in_memory(self) -> None:
        stamp = (self.timeline.stat().st_size, self.timeline.stat().st_mtime_ns)
        timeline_index.write_timeline_index(self.events, self.timeline)
        time.sleep(0.01)
        self.timeline.write_text(json.dumps({"events": self.events[:10]}), encoding="utf-8")
        opened = timeline_index.open_index(self.timeline, len(self.events), stamp)
        self.assertEqual((opened.source, opened.timeline_path), ("built", None))

    def test_same_size_same_mtime_rewrite_is_noticed_by_the_digest(self) -> None:
        timeline_index.write_timeline_index(self.events, self.timeline)
        self.assertEqual(timeline_index.open_index(self.timeline, len(self.events)).source, "file")
        stat = self.timeline.stat()
        body = self.timeline.read_bytes()
        changed = body.replace(b"2025-05-01T00", b"2025-05-02T00", 1)  # first event, same length
        self.assertNotEqual(changed, body)
        self.timeline.write_bytes(changed)
        os.utime(self.timeline, ns=(stat.st_atime_ns, stat.st_mtime_ns))
        self.assertEqual((self.timeline.stat().st_size, self.timeline.stat().st_mtime_ns), (stat.st_size, stat.st_mtime_ns))
        self.assertEqual(timeline_index.open_index(self.timeline, len(self.events)).source, "built")

    def test_rules_fingerprint_covers_negations(self) -> None:
        base = timeline_index._rules_fingerprint()
        self.assertEqual(base, timeline_index.RULES_FINGERPRINT)
        with mock.patch.object(timeline_index, "_NEGATIONS", frozenset({"no"})):
            self.assertNotEqual(timeline_index._rules_fingerprint(), base)

    def test_save_index_removes_its_temp_file_on_any_error(self) -> None:
        index = timeline_index.build_timeline_index(self.events)

        class Broken:
            def tofile(self, handle: object) -> None:
                raise RuntimeError("encoder bug")

        index.content_mask = Broken()  # type: ignore[assignment]
        target = timeline_index.index_path_for(self.timeline)
        with self.assertLogs(timeline_index.LOGGER, "INFO"):
            self.assertFalse(timeline_index.save_index(index, target, (1, 2), "digest"))
        self.assertEqual([path.name for path in self.run_dir.iterdir()], [self.timeline.name])


# --- 10. single-flight cache ----------------------------------------------------------------------


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required")
class SingleFlightOrderTests(unittest.TestCase):
    def test_older_build_finishing_late_keeps_the_newer_entry(self) -> None:
        cache: SingleFlightIndexCache[str] = SingleFlightIndexCache(max_runs=4)
        old_started, release_old = threading.Event(), threading.Event()
        results: dict[str, str] = {}

        def old_build() -> str:
            old_started.set()
            release_old.wait(10)
            return "old"

        thread = threading.Thread(target=lambda: results.__setitem__("old", cache.get_or_build(("r", 1), old_build)))
        thread.start()
        self.assertTrue(old_started.wait(10))
        self.assertEqual(cache.get_or_build(("r", 2), lambda: "new"), "new")
        release_old.set()
        thread.join(10)
        self.assertEqual(results["old"], "old")  # the late caller still gets its index
        self.assertEqual(cache.get_or_build(("r", 2), lambda: "rebuilt"), "new")  # newer entry kept
        # A newer build still replaces an older entry.
        self.assertEqual(cache.get_or_build(("r", 3), lambda: "newest"), "newest")
        self.assertEqual(cache.get_or_build(("r", 2), lambda: "again"), "again")
        self.assertEqual(cache.pending_builds(), 0)


# --- 11. perf script ------------------------------------------------------------------------------


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required")
class PerfScriptJoinTests(unittest.TestCase):
    def test_no_index_file_restores_the_environment_only_after_the_background_build(self) -> None:
        if str(SCRIPTS) not in sys.path:
            sys.path.insert(0, str(SCRIPTS))
        import perf_r6_timeline

        seen: list[str | None] = []
        answers = iter([False, False, True])

        def join(_timeout: float) -> bool:
            seen.append(os.environ.get("RAPIDTRIAGE_INDEX_PERSIST"))
            return next(answers)

        previous = os.environ.get("RAPIDTRIAGE_INDEX_PERSIST")
        with mock.patch.object(timeline_index, "wait_for_background", side_effect=join), mock.patch.object(
            perf_r6_timeline.sys, "stderr"
        ):
            with perf_r6_timeline.no_index_file():
                pass
        self.assertEqual(seen, ["0", "0", "0"])  # every join ran with persistence still off
        self.assertEqual(os.environ.get("RAPIDTRIAGE_INDEX_PERSIST"), previous)


# --- reviewer fuzz: column indexes == the predicate scan ------------------------------------------

FUZZ_ZONES = (
    "UTC", "+05:45", "-03:30", "+14:00", "-14:00", "Asia/Kathmandu", "Pacific/Chatham", "America/St_Johns",
    "Australia/Lord_Howe", "Antarctica/Troll", "Asia/Seoul", "America/New_York", "Europe/Dublin",
    "Africa/Casablanca", "Pacific/Apia", "Pacific/Kiritimati", "Asia/Pyongyang", "Europe/Moscow",
)  # fmt: skip
FUZZ_SPECIALS: tuple[object, ...] = (
    "２０２５-05-30T10:00:00Z", "2025-05-30T10:00:00+05:30:15", "2025-05-30T10:00:00.5+00:00:01", "٢٠٢٥-05-30",
    "2025-05-30T10:00:00.1234567.8", "2025-05-30T24:00:00", "2025-05-30T10Z", "2025-05-30T10:00:00-00:00",
    math.nan, math.inf, 1e20, -1e20, 253402300799.9999999, -62135596800.0000001, "1e9",
    "0001-01-01T00:00:00-00:01", "9999-12-31T23:59:59.999999-00:00:01", "2025-05-30T10:00:00.000000001Z",
    "2025-W22-5", "2025-150", "2025-05-30T10:00:00 +09:00",
)  # fmt: skip


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required")
class ReviewerFuzzTests(unittest.TestCase):
    """The reviewer's random-time fuzz (r6s3rev_fuzz), smaller: timeline and files column indexes
    give exactly the predicate scan's positions."""

    def random_time(self, rng: random.Random) -> object:
        import datetime as dt

        roll = rng.random()
        if roll < 0.1:
            return rng.choice(FUZZ_SPECIALS)
        seconds = rng.choice([rng.uniform(-62135596800, 253402300799), rng.uniform(1.6e9, 1.8e9), rng.uniform(-2.5e9, 0)])
        if roll < 0.2:
            return seconds
        if roll < 0.25:
            return int(seconds)
        try:
            moment = dt.datetime(1970, 1, 1) + dt.timedelta(seconds=seconds)
        except OverflowError:
            return "x"
        offset = rng.choice([None, "Z", "+09:00", "-05:00", "+05:45", "+14:00", "-12:00", "+00:30"])
        text = moment.isoformat(sep=rng.choice("T "))
        return text if offset is None else text + offset

    def random_bound(self, rng: random.Random) -> str | None:
        import datetime as dt

        if rng.random() < 0.5:
            return None
        seconds = rng.choice([rng.uniform(1.6e9, 1.8e9), rng.uniform(-62135596800, 253402300799)])
        moment = dt.datetime(1970, 1, 1) + dt.timedelta(seconds=seconds)
        text = moment.strftime(rng.choice(["%Y-%m-%d", "%Y-%m-%dT%H", "%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S"]))
        year = text.split("-")[0]
        if len(year) < 4:
            text = "0" * (4 - len(year)) + text
        if rng.random() < 0.3:
            text += rng.choice(["Z", "+09:00", "-03:30"])
        return text

    def test_indexes_equal_the_scan(self) -> None:
        from rapidtriage.api.app.files_index import (
            FILES_INDEX_CACHE,
            files_matched_positions,
        )

        rng = random.Random(7)
        checked = 0
        for trial in range(60):
            events: list[dict[str, object]] = [
                {
                    "timestamp": self.random_time(rng),
                    "artifact_type": rng.choice(["media-image", "document-x", "x-invalid", "", None]),
                    "details": {"path": rng.choice(["a.jpg", "b.PDF", "c", None, "d.tar.gz"])},
                }
                for _ in range(300)
            ]
            low, high = self.random_bound(rng), self.random_bound(rng)
            for bound in (low, high):
                if bound:
                    events.append({"timestamp": bound})
            try:
                conditions = parse_row_conditions(
                    time_from=low,
                    time_to=high,
                    weekday=rng.choice([[], ["sat"], ["mon", "fri"]]),
                    hours=rng.choice([None, "18-09", "9-17", "0-1", "23-24"]),
                    offhours=rng.random() < 0.3,
                    tz=rng.choice(FUZZ_ZONES),
                    partial=rng.random() < 0.2,
                    content=rng.choice([[], ["image"], ["document", "image"]]),
                )
            except ValueError:
                continue
            if conditions is None:
                continue
            checked += 1
            predicate = conditions.predicate("timeline")
            with self.subTest(trial=trial, kind="timeline"):
                self.assertEqual(
                    timeline_index.evaluate(timeline_index.build_timeline_index(events), conditions),
                    [i for i, row in enumerate(events) if predicate(row)],
                )
            rows = [{"fs_modified_at": event["timestamp"], "path": "x.mp4", "categories": ["images"]} for event in events]
            FILES_INDEX_CACHE.clear()
            MATCH_CACHE.clear()
            files_predicate = conditions.predicate("files")
            got = list(files_matched_positions(rows, run_id="r", collection="candidates", files_stamp=(trial,), conditions=conditions))
            with self.subTest(trial=trial, kind="files"):
                self.assertEqual(got, [i for i, row in enumerate(rows) if files_predicate(row)])
        FILES_INDEX_CACHE.clear()
        MATCH_CACHE.clear()
        self.assertGreater(checked, 30)


class ZoneTransitionAssumptionTests(unittest.TestCase):
    """``timeline_index._ZoneClock`` caches a UTC day's offset when the offsets at 00, 06, 12, 18 h
    and the day's last microsecond agree: no zone may leave an offset and come back to it within
    six hours (the reviewer's r6s3rev_zones scan of the installed tz database)."""

    def test_no_zone_changes_offset_and_back_within_six_hours(self) -> None:
        import datetime as dt
        import zoneinfo

        try:
            from zoneinfo._zoneinfo import ZoneInfo as PureZoneInfo
        except ImportError:  # pragma: no cover - interpreter without the pure-Python zoneinfo
            self.skipTest("pure-Python zoneinfo not available")
        epoch = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)

        def offset(zone: dt.tzinfo, seconds: int) -> float | None:
            try:
                return (epoch + dt.timedelta(seconds=seconds)).astimezone(zone).utcoffset().total_seconds()  # type: ignore[union-attr]
            except (OverflowError, ValueError):
                return None

        back: list[tuple[str, int, int]] = []
        for name in sorted(zoneinfo.available_timezones()):
            try:
                transitions = list(getattr(PureZoneInfo.no_cache(name), "_trans_utc", ()) or ())
                zone = zoneinfo.ZoneInfo(name)
            except (OSError, ValueError, zoneinfo.ZoneInfoNotFoundError):
                continue
            for first, second in zip(transitions, transitions[1:]):
                if second - first < 6 * 3600 and offset(zone, first - 1) == offset(zone, second):
                    back.append((name, first, second - first))
        self.assertEqual(back, [])


if __name__ == "__main__":
    unittest.main()
