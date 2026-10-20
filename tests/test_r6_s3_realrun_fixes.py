"""R6 S3 fixes found on real run outputs (run-subset10 / r6-s1-run, 2026-10-20).

* A timeline JSON larger than the ``OutputJsonCache`` byte budget (a real one is ~280 MB, the
  budget 200 MB) was evicted the moment it was inserted, so every ``/timeline`` page re-parsed it
  (~3.5 s per page, first and next alike). Reproduced with a small budget: the payload must be
  parsed once and later pages served from ``MATCH_CACHE`` (also with the >50k background path).
* ~30 ``artifacts_*`` payloads vs. a 4-entry cache: every ``/geo-clusters`` re-parsed all of them.
* ``RAPIDTRIAGE_INDEX_PERSIST=0`` keeps on-demand indexes in memory (no file next to the outputs);
  ``scripts/perf-r6.py --run`` uses it and leaves the run folder byte-identical.
* The located-row scan reads JSONL in blocks; it must find exactly what the line-by-line scan
  found (record indices, byte offsets, budget cut) on awkward streams.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import random
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.core import jobs
from rapidtriage.core.jobs import OutputJsonCache, RunJobStore

try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import create_app, geo_index, timeline_index
    from rapidtriage.api.app.index_cache import INDEX_PERSIST_ENV, index_persist_enabled
    from rapidtriage.api.app.jsonl_records import expand_row, parse_record_line
    from rapidtriage.api.app.row_conditions import MATCH_CACHE, parse_row_conditions

    HAS_FASTAPI = True
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
TOKEN = "r6-s3-realrun-token"


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


def timeline_events(count: int) -> list[dict[str, object]]:
    rng = random.Random(20)
    events: list[dict[str, object]] = []
    for position in range(count):
        day = 1 + rng.randrange(28)
        hour = rng.randrange(24)
        details: dict[str, object] = {"artifact_type": ("prefetch-file", "media-image", "eventlog-event")[position % 3]}
        if position % 3 == 0:
            details["target_path"] = rf"C:\x\{position}.exe"
        if position % 17 == 0:
            details["parse_status"] = "truncated-record"
        events.append({"timestamp": f"2025-05-{day:02d}T{hour:02d}:00:00Z", "source": "artifacts", "details": details})
    return events


class OutputJsonCacheTests(unittest.TestCase):
    def test_payload_over_the_byte_budget_stays_cached(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            big = base / "big.json"
            big.write_text(json.dumps({"events": list(range(500))}), encoding="utf-8")
            small = [base / f"small-{number}.json" for number in range(3)]
            for number, path in enumerate(small):
                path.write_text(json.dumps({"n": number}), encoding="utf-8")
            cache = OutputJsonCache(max_entries=8, max_bytes=100)
            first = cache.read(big)
            for path in small:
                cache.read(path)
            self.assertIs(cache.read(big), first)  # not evicted by its own size nor by later reads
            self.assertEqual(cache.stats()["large_entries"], 1)
            other = base / "other-big.json"
            other.write_text(json.dumps({"events": list(range(600))}), encoding="utf-8")
            cache.read(other)  # one oversized slot: the newer one replaces it
            self.assertIsNot(cache.read(big), first)
            cache.invalidate(big)
            self.assertEqual(cache.stats()["large_entries"], 0)

    def test_byte_budget_and_entry_bound_still_apply(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            paths = [Path(temp) / f"p{number}.json" for number in range(5)]
            for path in paths:
                path.write_text(json.dumps({"pad": "x" * 30}), encoding="utf-8")
            cache = OutputJsonCache(max_entries=3, max_bytes=10_000, max_large_entries=0)
            first = cache.read(paths[0])
            for path in paths[1:]:
                cache.read(path)
            self.assertEqual(cache.stats()["entries"], 3)
            self.assertIsNot(cache.read(paths[0]), first)

    def test_concurrent_readers_parse_once(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "t.json"
            path.write_text(json.dumps({"events": list(range(1000))}), encoding="utf-8")
            cache = OutputJsonCache()
            gate = threading.Event()
            parsed: list[int] = []
            real_store = cache._store

            def slow_store(*args: object) -> None:
                parsed.append(1)
                gate.wait(5)
                real_store(*args)  # type: ignore[arg-type]

            results: list[object] = []
            with mock.patch.object(cache, "_store", side_effect=slow_store):
                threads = [threading.Thread(target=lambda: results.append(cache.read(path))) for _ in range(4)]
                for thread in threads:
                    thread.start()
                threading.Timer(0.3, gate.set).start()
                for thread in threads:
                    thread.join(10)
            self.assertEqual(len(parsed), 1)
            self.assertEqual(len(results), 4)
            self.assertTrue(all(result is results[0] for result in results))

    def test_default_bounds_fit_a_real_run(self) -> None:
        self.assertGreaterEqual(jobs.OUTPUT_JSON_CACHE_MAX_ENTRIES, 64)  # ~30 artifacts_* payloads + others
        self.assertGreaterEqual(jobs.OUTPUT_JSON_CACHE_MAX_LARGE_ENTRIES, 1)


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for API tests")
class RealRunShapeTimelineTests(unittest.TestCase):
    """The real-run failure: timeline file > cache byte budget, > SYNC_COMPLETE_MAX_EVENTS events."""

    def setUp(self) -> None:
        timeline_index.TIMELINE_INDEXES.clear()
        MATCH_CACHE.clear()
        self.addCleanup(timeline_index.TIMELINE_INDEXES.clear)
        self.addCleanup(MATCH_CACHE.clear)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.run_dir = Path(self.temp.name) / "run"
        self.run_dir.mkdir()
        self.events = timeline_events(4_000)
        self.timeline = self.run_dir / "rapidtriage-timeline.json"
        self.timeline.write_text(json.dumps({"events": self.events}), encoding="utf-8")
        write_summary(self.run_dir, {"timeline": str(self.timeline)})
        # Budget below the file size, like 200 MB vs a 280 MB real timeline.
        self.cache = OutputJsonCache(max_bytes=self.timeline.stat().st_size // 2)
        patcher = mock.patch.object(jobs, "_output_json_cache", self.cache)
        patcher.start()
        self.addCleanup(patcher.stop)
        store = RunJobStore()
        self.run_id = store.import_completed_run(self.run_dir).run_id
        self.client = TestClient(create_app(store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})

    def page(self, query: str) -> dict[str, object]:
        response = self.client.get(f"/api/runs/{self.run_id}/timeline?{query}")
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_pages_parse_the_payload_once_and_reuse_the_matches(self) -> None:
        conditions = parse_row_conditions(offhours=True, tz="Asia/Seoul")
        assert conditions is not None
        predicate = conditions.predicate("timeline")
        expected = [i for i, row in enumerate(self.events) if predicate(row)]
        with mock.patch.object(jobs, "json", wraps=json) as parsed, mock.patch.object(
            timeline_index, "SYNC_COMPLETE_MAX_EVENTS", 100
        ):
            first = self.page("offhours=1&tz=Asia/Seoul&limit=100")
            with mock.patch.object(timeline_index, "evaluate", side_effect=AssertionError("re-evaluated")), mock.patch.object(
                timeline_index, "open_index", side_effect=AssertionError("index reopened")
            ):
                second = self.page("offhours=1&tz=Asia/Seoul&limit=100&offset=100")
            self.assertTrue(timeline_index.wait_for_background(30))
            self.page("content=executable&limit=10")
            self.assertEqual(parsed.loads.call_count, 1)  # one parse for every page (was one per request)
        self.assertEqual(len(timeline_index.TIMELINE_INDEXES._items), 1)
        indices = [event["record_index"] for event in first["events"] + second["events"]]  # type: ignore[operator]
        self.assertEqual(indices, expected[:200])
        self.assertEqual(first["matched"], len(expected))
        self.assertTrue((self.run_dir / timeline_index.INDEX_FILE_NAME).exists())

    def test_persist_switch_keeps_the_index_in_memory(self) -> None:
        with mock.patch.dict(os.environ, {INDEX_PERSIST_ENV: "0"}), mock.patch.object(
            timeline_index, "SYNC_COMPLETE_MAX_EVENTS", 100
        ):
            self.assertFalse(index_persist_enabled())
            before = sorted(os.listdir(self.run_dir))
            body = self.page("partial=1&limit=10")
            self.assertTrue(timeline_index.wait_for_background(30))
            self.page("from=2025-05-10&limit=10")
            self.assertEqual(body["matched"], sum(1 for event in self.events if event["details"].get("parse_status")))  # type: ignore[union-attr]
            self.assertEqual(sorted(os.listdir(self.run_dir)), before)
        # An existing index file is still read with persistence off.
        timeline_index.write_timeline_index(self.events, self.timeline)
        timeline_index.TIMELINE_INDEXES.clear()
        MATCH_CACHE.clear()
        with mock.patch.dict(os.environ, {INDEX_PERSIST_ENV: "off"}), mock.patch.object(
            timeline_index, "time_column", side_effect=AssertionError("rebuilt")
        ):
            self.page("hours=09-18&limit=10")


def reference_scan(records_path: Path, profiles: object, budget: int, prefilter: bool) -> tuple[list[object], int, bool]:
    """The line-by-line located-row scan the block scan replaced (geo_index before the fix)."""
    found: list[object] = []
    scanned = index = position = 0
    with open(records_path, "rb") as handle:
        for line_number, line in enumerate(handle, start=1):
            offset = position
            position += len(line)
            stripped = line.strip()
            if not stripped.startswith(b"{"):
                continue
            record_index = index
            index += 1
            scanned += 1
            if prefilter and geo_index._COORDINATE_KEY.search(stripped) is None:
                continue
            row = parse_record_line(stripped, path=records_path, line_number=line_number)
            if row is None:
                continue
            entry = geo_index._entry(record_index, offset, expand_row(row, profiles))  # type: ignore[arg-type]
            if entry is not None:
                if len(found) >= budget:
                    return found, scanned, True
                found.append(entry)
    return found, scanned, False


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for API tests")
class GeoBlockScanTests(unittest.TestCase):
    def stream(self, seed: int) -> bytes:
        rng = random.Random(seed)
        lines: list[bytes] = []
        for number in range(400):
            roll = rng.random()
            if roll < 0.05:
                lines.append(rng.choice([b"", b"   ", b"[1,2]", b"\t{\"lat\": 1, \"lon\": 2}", b"{broken \"lat\""]))
                continue
            details: dict[str, object] = {"note": "translate latest related " * rng.randrange(1, 4)}
            if roll < 0.25:
                details["gps_latitude"], details["gps_longitude"] = round(rng.uniform(-80, 80), 5), round(rng.uniform(-170, 170), 5)
            elif roll < 0.3:
                details["lat"], details["lng"] = None, None
            elif roll < 0.35:
                details["text"] = 'quoted "latitude" inside a value'
            row = json.dumps({"artifact_type": "x", "path": f"C:\\{number}", "details": details}).encode()
            lines.append(row + (b"\r" if rng.random() < 0.1 else b""))
        body = b"\n".join(lines)
        return body if seed % 2 else body + b"\n"

    def test_block_scan_equals_the_line_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            for seed in range(6):
                path = Path(temp) / f"s{seed}.jsonl"
                path.write_bytes(self.stream(seed))
                for block in (64, 333, 4096, 1 << 20):
                    for budget in (10**9, 7):
                        for prefilter in (True, False):
                            with mock.patch.object(geo_index, "SCAN_BLOCK_BYTES", block), self.assertNoLogs(
                                "rapidtriage", "ERROR"
                            ):
                                got = geo_index._scan_jsonl(path, None, budget, prefilter=prefilter)
                            want = reference_scan(path, None, budget, prefilter)
                            self.assertEqual(got, want, (seed, block, budget, prefilter))

    def test_uniform_stream_takes_the_block_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "u.jsonl"
            rows = [{"details": {"v": n}} for n in range(1000)]
            rows[700]["details"] = {"latitude": 37.5, "longitude": 127.0}
            path.write_bytes(b"".join(json.dumps(row).encode() + b"\n" for row in rows))
            calls: list[bytes] = []
            real = geo_index.parse_record_line

            def counting(line: bytes, **kwargs: object) -> object:
                calls.append(line)
                return real(line, **kwargs)  # type: ignore[arg-type]

            with mock.patch.object(geo_index, "parse_record_line", side_effect=counting), mock.patch.object(
                geo_index, "SCAN_BLOCK_BYTES", 4096
            ):
                found, scanned, cut = geo_index._scan_jsonl(path, None, 10, prefilter=True)
            self.assertEqual(len(calls), 1)  # only the key line is parsed
            self.assertEqual((scanned, cut, [entry.record_index for entry in found]), (1000, False, [700]))
            self.assertEqual(found, reference_scan(path, None, 10, True)[0])


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for API tests")
class GeoFixedCostTests(unittest.TestCase):
    def test_clusters_do_not_reparse_thirty_kind_payloads(self) -> None:
        geo_index.GEO_INDEX_SERVICE.clear()
        self.addCleanup(geo_index.GEO_INDEX_SERVICE.clear)
        cache = OutputJsonCache()
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(jobs, "_output_json_cache", cache), mock.patch.dict(
            os.environ, {INDEX_PERSIST_ENV: "0"}
        ):
            run_dir = Path(temp) / "run"
            run_dir.mkdir()
            outputs: dict[str, str] = {}
            for number in range(30):
                kind = f"kind-{number:02d}"
                records = run_dir / f"{kind}.jsonl"
                rows = [{"artifact_type": kind, "details": {"v": n}} for n in range(5)]
                if number == 7:
                    rows[2]["details"] = {"gps_latitude": 37.5, "gps_longitude": 127.0}
                records.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
                payload = run_dir / f"artifacts_{kind}.json"
                payload.write_text(json.dumps({"record_count": 5, "records_path": str(records), "artifacts": []}), encoding="utf-8")
                outputs[f"artifacts_{kind}"] = str(payload)
            write_summary(run_dir, outputs)
            before = sorted(os.listdir(run_dir))
            store = RunJobStore()
            run_id = store.import_completed_run(run_dir).run_id
            client = TestClient(create_app(store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})
            url = f"/api/runs/{run_id}/geo-clusters?cell=0.01"
            body = client.get(url).json()
            for _ in range(50):
                if body["geo_index"] == "ready":
                    break
                body = client.get(url).json()
            self.assertEqual((body["geo_index"], body["geo_index_source"], body["located_total"]), ("ready", "memory", 1))
            with mock.patch.object(jobs, "json", wraps=json) as parsed:
                for _ in range(3):
                    self.assertEqual(client.get(url).status_code, 200)
            self.assertEqual(parsed.loads.call_count, 0)  # was 30 parses per request with a 4-entry cache
            self.assertEqual(sorted(os.listdir(run_dir)), before)  # persistence off: no index file


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for API tests")
class PerfRunReadOnlyTests(unittest.TestCase):
    """``scripts/perf-r6.py --timeline/--geo --run`` leave the run folder byte-identical."""

    def setUp(self) -> None:
        if str(SCRIPTS) not in sys.path:
            sys.path.insert(0, str(SCRIPTS))
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        (self.base / "scratch").mkdir()
        self.addCleanup(timeline_index.TIMELINE_INDEXES.clear)
        self.addCleanup(MATCH_CACHE.clear)
        self.addCleanup(geo_index.GEO_INDEX_SERVICE.clear)

    def run_main(self, module: object, argv: list[str]) -> dict[str, object]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            module.main(argv)  # type: ignore[attr-defined]
        return json.loads(out.getvalue())

    def contents(self, root: Path) -> dict[str, bytes]:
        return {str(path.relative_to(root)): path.read_bytes() for path in sorted(root.rglob("*")) if path.is_file()}

    def test_timeline_run_mode(self) -> None:
        import perf_r6_timeline
        from perf_r6_common import folder_snapshot

        run_dir = perf_r6_timeline.synthetic_timeline_run(self.base / "src", 800)
        before, data = folder_snapshot(run_dir), self.contents(run_dir)
        report = self.run_main(
            perf_r6_timeline, ["--timeline", "--run", str(run_dir), "--repeat", "1", "--scratch", str(self.base / "scratch")]
        )["reports"]["timeline"]
        self.assertEqual(folder_snapshot(run_dir), before)
        self.assertEqual(self.contents(run_dir), data)
        self.assertTrue(report["run_folder_unchanged"])  # type: ignore[index]
        self.assertIn("first_page_s", report["with_file"])  # type: ignore[index, operator]
        self.assertEqual(os.listdir(self.base / "scratch"), [])  # the temporary copy is gone
        self.assertNotIn(INDEX_PERSIST_ENV, os.environ)

    def test_geo_run_mode(self) -> None:
        import perf_r6_geo
        from perf_r6_common import folder_snapshot

        run_dir = perf_r6_geo.synthetic_artifact_run(self.base / "src", rows=600, located=20, kinds=3)
        before, data = folder_snapshot(run_dir), self.contents(run_dir)
        report = self.run_main(
            perf_r6_geo, ["--geo", "--run", str(run_dir), "--repeat", "1", "--scratch", str(self.base / "scratch")]
        )["geo"]
        self.assertEqual(folder_snapshot(run_dir), before)
        self.assertEqual(self.contents(run_dir), data)
        checks = report["checks"]  # type: ignore[index]
        self.assertTrue(checks["run_folder_unchanged"])  # type: ignore[index]
        self.assertTrue(checks["build_in_memory"])  # type: ignore[index]
        self.assertIn("first_display_building_s", checks)  # type: ignore[operator]
        self.assertEqual(report["geo_index_source"], "file")  # type: ignore[index]
        self.assertEqual(report["located_total"], 20)  # type: ignore[index]
        self.assertEqual(os.listdir(self.base / "scratch"), [])
        self.assertNotIn(INDEX_PERSIST_ENV, os.environ)


if __name__ == "__main__":
    unittest.main()
