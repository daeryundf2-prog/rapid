"""위치 행 색인 + 지도 묶음 (plan r6 §3.3 갈래 C, Q-S3-6/7/8): ``rapidtriage-geo-index.json``,
``/artifacts?geo=…`` across kinds from the index, ``GET /geo-clusters``, the building state and a
read-only output folder."""

from __future__ import annotations

import json
import random
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import artifact_sort, create_app, geo_index, tree
    from rapidtriage.api.app.artifact_filter import filter_across_kinds
    from rapidtriage.api.app.row_conditions import in_geo_box, parse_row_conditions

    HAS_FASTAPI = True
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

from rapidtriage.core.jobs import RunJobStore
from rapidtriage.core.run.persist import build_run_geo_index
from rapidtriage.core.triage_rules.stage import run_triage_stage

TOKEN = "geo-index-test-token"
HANGUL = range(0xAC00, 0xD7A4)


def media(lat: object, lon: object, *, path: str = r"C:\p\a.jpg", **details: object) -> dict[str, object]:
    return {"artifact_type": "media-image", "path": path, "details": {"gps_latitude": lat, "gps_longitude": lon, **details}}


# Rows of every coordinate shape row_coordinates reads, and look-alikes without coordinates.
MEDIA = [
    media(37.4812384, 126.9497216, timestamp="2025-05-26T01:00:00Z"),  # 0
    {"artifact_type": "media-image", "path": r"C:\p\b.jpg", "details": {"exif_gps_profile": {"latitude": 37.4851, "longitude": 126.9411, "gps_datetime_utc_candidate": "2025-05-27T02:00:00Z"}}},  # 1
    media(0, 0),  # 2: (0, 0) is none
    media(95, 10),  # 3: out of range
    media("35.1", "129.04", timestamp="2025-05-20T00:00:00Z"),  # 4: numeric strings
    {"artifact_type": "media-video", "path": r"C:\p\v.mp4", "details": {"platform": "translate latest related"}},  # 5
    media(37.48, 126.94),  # 6: exactly on a 0.01° cell edge
    media(90, 180),  # 7: the world corner (last cell, inclusive edge)
    media(-10.5, -179.995, timestamp="2025-06-01T00:00:00Z"),  # 8: west of the antimeridian
    media(-10.5, 179.995),  # 9: east of the antimeridian
]
LOCATIONS = [
    {"artifact_type": "location-fix", "path": r"C:\loc\cache.db", "details": {"latitude": 37.4813, "longitude": 126.9498, "timestamp": "2025-05-26T03:00:00Z"}},
    {"artifact_type": "location-fix", "path": r"C:\loc\cache.db", "details": {"lat": 51.5, "lng": -0.12}},
    {"artifact_type": "location-fix", "path": r"C:\loc\other.db", "details": {"note": "lat 1"}},
    {"artifact_type": "location-fix", "path": r"C:\loc\other.db", "lat": 48.85, "lon": 2.35, "details": {}},
]
EVENTS = [
    {"artifact_type": "eventlog-event", "path": r"C:\Windows\Logs\Security.evtx", "details": {"event_id": "4624", "channel": "Security", "timestamp": "2025-05-26T01:00:00Z"}},
    {"artifact_type": "eventlog-event", "path": r"C:\Windows\Logs\Security.evtx", "details": {"event_id": "1102", "channel": "Security", "provider": "Microsoft-Windows-Eventlog", "timestamp": "2025-05-28T12:00:00Z", "latitude": 37.4814, "longitude": 126.9499}},
]
# A kind whose shared profile carries the coordinates (rows reference it).
PROFILED_ROWS = [
    {"profile_ref": "p1", "artifact_type": "photo", "path": r"C:\profiled.jpg", "details": {"timestamp": "2025-05-29T00:00:00Z"}},
    {"artifact_type": "photo", "path": r"C:\x.jpg", "details": {}},
]
PROFILES = {"p1": {"details": {"gps_latitude": 33.5, "gps_longitude": 126.5}}}

BOXES = [
    "-90,-180,90,180",
    "37.48,126.94,37.49,126.95",
    "37.48,126.94,37.481,126.941",
    "30,120,40,130",
    "-20,170,0,-170",
    "89.99,179.99,90,180",
    "35.1,129.04,36,130",
    "30,120,35.1,129.04",
    "40,-10,60,10",
]


def counts(rows: list[dict[str, object]]) -> dict[str, int]:
    out: dict[str, int] = {}
    for row in rows:
        out[str(row.get("artifact_type"))] = out.get(str(row.get("artifact_type")), 0) + 1
    return out


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for API tests")
class GeoIndexApiTests(unittest.TestCase):
    def setUp(self) -> None:
        artifact_sort.SORT_INDEX_CACHE.clear()
        tree._FACET_CACHE.clear()
        geo_index.GEO_INDEX_SERVICE.clear()
        self.addCleanup(geo_index.GEO_INDEX_SERVICE.clear)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.run_dir = run_dir = base / "run"
        run_dir.mkdir()
        self.artifact_paths: dict[str, Path] = {}
        summary_outputs: dict[str, str] = {}
        kinds = (
            ("media-image", MEDIA, True, None),
            ("location", LOCATIONS, False, None),
            ("eventlog", EVENTS, True, None),
            ("profiled", PROFILED_ROWS, True, PROFILES),
        )
        for kind, rows, jsonl, profiles in kinds:
            payload: dict[str, object] = {"record_count": len(rows), "summary": {"artifact_count": len(rows), "artifact_type_counts": counts(rows)}}
            if profiles:
                payload["artifact_type_profiles"] = profiles
            if jsonl:
                records = run_dir / f"{kind}.jsonl"
                # A blank line and a non-object line consume no record index.
                body = "".join(json.dumps(row) + "\n" for row in rows[:1]) + "\n[1,2]\n" + "".join(json.dumps(row) + "\n" for row in rows[1:])
                records.write_text(body, encoding="utf-8", newline="\n")
                payload.update({"records_path": str(records), "artifacts": []})
            else:
                payload["artifacts"] = rows
            path = run_dir / f"artifacts_{kind}.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            summary_outputs[f"artifacts_{kind}"] = str(path)
            self.artifact_paths[kind] = path
        summary_path = run_dir / "rapidtriage-run-summary.json"
        summary_outputs["summary"] = str(summary_path)
        summary_path.write_text(
            json.dumps(
                {
                    "profile_version": "rapidtriage-run-summary-v1",
                    "mode": "hacking",
                    "root": str(base / "evidence"),
                    "output_dir": str(run_dir),
                    "source": {"type": "directory", "analysis_root": str(base / "evidence")},
                    "outputs": summary_outputs,
                    "summary": {"counts": {"artifacts": 18}},
                }
            ),
            encoding="utf-8",
        )
        self.store = RunJobStore()
        self.run_id = self.store.import_completed_run(run_dir).run_id
        self.client = TestClient(create_app(self.store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})

    # --- helpers -------------------------------------------------------------------------

    def call(self, endpoint: str, query: str, expect: int = 200) -> dict[str, object]:
        response = self.client.get(f"/api/runs/{self.run_id}/{endpoint}?{query}")
        self.assertEqual(response.status_code, expect, response.text)
        return response.json()

    def scan_order(self, query: dict[str, object], kinds: list[str] | None = None) -> list[tuple[str, int]]:
        """The full-scan path (no index) for the same request."""
        names = sorted(self.artifact_paths) if not kinds else kinds
        sources = []
        for name in names:
            payload = json.loads(self.artifact_paths[name].read_text(encoding="utf-8"))
            sources.append((name, payload, self.artifact_paths[name]))
        conditions = parse_row_conditions(**query)  # type: ignore[arg-type]
        result = filter_across_kinds(
            sources,
            path_contains=None,
            artifact_types=None,
            offset=0,
            limit=1000,
            row_filter=conditions.predicate("artifacts") if conditions else None,
        )
        return [(kind, index) for kind, index in result["cross_kind"]["order"]]

    def index_order(self, query: str) -> tuple[list[tuple[str, int]], dict[str, object]]:
        payload = self.call("artifacts", f"limit=1000&{query}")
        cross = payload["cross_kind"]
        return [(kind, index) for kind, index in cross["order"]], cross

    # --- Q-S3-7 equivalence ------------------------------------------------------------------

    def test_index_path_equals_full_scan_for_every_box(self) -> None:
        for box in BOXES:
            with self.subTest(box=box):
                order, cross = self.index_order(f"geo={box}")
                self.assertIs(cross["geo_index"], True)
                self.assertEqual(order, self.scan_order({"geo": box}))
                self.assertEqual(cross["matched"], len(order))
        order, cross = self.index_order("geo=-90,-180,90,180")
        # (0,0), out of range and value-only "lat" rows are not located; profiles and top-level pairs are.
        self.assertEqual(
            order,
            [
                ("eventlog", 1),
                ("location", 0),
                ("location", 1),
                ("location", 3),
                ("media-image", 0),
                ("media-image", 1),
                ("media-image", 4),
                ("media-image", 6),
                ("media-image", 7),
                ("media-image", 8),
                ("media-image", 9),
                ("profiled", 0),
            ],
        )
        self.assertEqual(cross["located_total"], 12)
        page = self.call("artifacts", "limit=1000&geo=-90,-180,90,180")
        rows = page["artifacts"]["media-image"]["artifacts"]
        self.assertEqual([row["record_index"] for row in rows], [0, 1, 4, 6, 7, 8, 9])
        self.assertEqual(rows[1]["path"], r"C:\p\b.jpg")
        # Profile rows come back expanded.
        self.assertEqual(page["artifacts"]["profiled"]["artifacts"][0]["path"], r"C:\profiled.jpg")

    def test_edges_and_antimeridian_rules(self) -> None:
        order, _ = self.index_order("geo=37.47,126.93,37.48,126.94")
        self.assertNotIn(("media-image", 6), order)  # upper edges are exclusive
        order, _ = self.index_order("geo=37.48,126.94,37.49,126.95")
        self.assertIn(("media-image", 6), order)  # lower edges inclusive
        order, _ = self.index_order("geo=89.99,179.99,90,180")
        self.assertEqual(order, [("media-image", 7)])  # 90 / 180 inclusive at the world edge
        order, _ = self.index_order("geo=-20,170,0,-170")
        self.assertEqual(order, [("media-image", 8), ("media-image", 9)])

    def test_random_boxes_and_composed_filters_match_the_scan(self) -> None:
        rng = random.Random(6)
        for _ in range(40):
            lat0 = round(rng.uniform(-90, 89), 3)
            lat1 = round(rng.uniform(lat0 + 0.001, 90), 3)
            lon0, lon1 = round(rng.uniform(-180, 180), 3), round(rng.uniform(-180, 180), 3)
            if lon0 == lon1:
                continue
            box = f"{lat0},{lon0},{lat1},{lon1}"
            with self.subTest(box=box):
                self.assertEqual(self.index_order(f"geo={box}")[0], self.scan_order({"geo": box}))
        # Other conditions run on the box's rows only.
        order, cross = self.index_order("geo=-90,-180,90,180&from=2025-05-26T00:00:00Z&to=2025-05-28")
        self.assertEqual(order, self.scan_order({"geo": "-90,-180,90,180", "time_from": "2025-05-26T00:00:00Z", "time_to": "2025-05-28"}))
        self.assertIs(cross["geo_index"], True)
        self.assertEqual(cross["conditions"]["geo"], [-90.0, -180.0, 90.0, 180.0])
        order, _ = self.index_order("geo=-90,-180,90,180&content=video")
        self.assertEqual(order, [])
        order, cross = self.index_order("geo=-90,-180,90,180&path_contains=cache.db&kind=location&kind=media-image")
        self.assertEqual(order, [("location", 0), ("location", 1)])
        self.assertEqual(cross["kinds"], ["location", "media-image"])
        self.assertEqual(cross["path_contains"], "cache.db")
        order, _ = self.index_order("geo=-90,-180,90,180&artifact_type=location-fix")
        self.assertEqual(order, [("location", 0), ("location", 1), ("location", 3)])
        order, _ = self.index_order("geo=-90,-180,90,180&channel=Security")
        self.assertEqual(order, [("eventlog", 1)])
        # Requested kind order is kept.
        order, _ = self.index_order("geo=37,126,38,127&kind=media-image&kind=location")
        self.assertEqual(order, [("media-image", 0), ("media-image", 1), ("media-image", 6), ("location", 0)])

    def test_paging_offset_and_after_cursor(self) -> None:
        full, _ = self.index_order("geo=-90,-180,90,180")
        collected: list[tuple[str, int]] = []
        after = None
        for _ in range(10):
            query = "limit=5&geo=-90,-180,90,180" + (f"&after={after}" if after else "")
            cross = self.call("artifacts", query)["cross_kind"]
            collected.extend((kind, index) for kind, index in cross["order"])
            self.assertEqual(cross["matched"], len(full))
            after = cross["next_after"]
            if not after:
                self.assertFalse(cross["has_more"])
                break
            self.assertTrue(cross["has_more"])
        self.assertEqual(collected, full)
        cross = self.call("artifacts", "limit=5&offset=10&geo=-90,-180,90,180")["cross_kind"]
        self.assertEqual([(k, i) for k, i in cross["order"]], full[10:15])
        # With another filter the cursor pages the same way.
        filtered_full, _ = self.index_order("geo=-90,-180,90,180&artifact_type=media-image")
        collected, after = [], None
        for _ in range(10):
            query = "limit=2&geo=-90,-180,90,180&artifact_type=media-image" + (f"&after={after}" if after else "")
            cross = self.call("artifacts", query)["cross_kind"]
            collected.extend((kind, index) for kind, index in cross["order"])
            after = cross["next_after"]
            if not after:
                self.assertEqual(cross["matched"], len(filtered_full))
                break
        self.assertEqual(collected, filtered_full)
        self.assertEqual(self.call("artifacts", "limit=5&geo=-90,-180,90,180&after=nope:1:1", expect=400)["detail"][:5], "after")

    def test_flag_filter_on_located_rows(self) -> None:
        step = run_triage_stage(self.run_dir, artifact_outputs=self.artifact_paths)
        self.assertEqual(step["status"], "completed", step)
        order, cross = self.index_order("geo=-90,-180,90,180&flag=eventlog.log_cleared")
        self.assertEqual(order, [("eventlog", 1)])
        self.assertIs(cross["geo_index"], True)
        self.assertEqual(cross["flags"]["flag"], ["eventlog.log_cleared"])
        clusters = self.call("geo-clusters", "flag=eventlog.log_cleared")
        self.assertEqual(clusters["matched"], 1)
        self.assertTrue(clusters["filtered"])

    # --- file / building / read-only (Q-S3-6, Q-S3-8) ------------------------------------------

    def test_index_file_written_reused_and_rebuilt_when_stale(self) -> None:
        index_path = self.run_dir / geo_index.GEO_INDEX_FILE_NAME
        self.assertFalse(index_path.exists())
        first = self.call("geo-clusters", "")
        self.assertEqual((first["geo_index"], first["geo_index_source"]), ("ready", "built"))
        self.assertTrue(index_path.is_file())
        stored = json.loads(index_path.read_text(encoding="utf-8"))
        self.assertEqual(stored["format"], geo_index.GEO_INDEX_FORMAT)
        self.assertEqual(stored["located"], 12)
        self.assertEqual(stored["columns"], ["kind", "record_index", "offset", "lat", "lon", "time", "epoch"])
        geo_index.GEO_INDEX_SERVICE.clear()
        again = self.call("geo-clusters", "")
        self.assertEqual(again["geo_index_source"], "file")
        self.assertEqual(again["clusters"], first["clusters"])
        # A changed output (new stamp) ignores the stored file and rebuilds it.
        records = self.run_dir / "media-image.jsonl"
        with open(records, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(media(10.0, 20.0)) + "\n")
        geo_index.GEO_INDEX_SERVICE.clear()
        rebuilt = self.call("geo-clusters", "")
        self.assertEqual(rebuilt["geo_index_source"], "built")
        self.assertEqual(rebuilt["located_total"], 13)
        order, _ = self.index_order("geo=9,19,11,21")
        self.assertEqual(order, [("media-image", 10)])
        # A corrupt file is ignored too.
        index_path.write_text("{not json", encoding="utf-8")
        geo_index.GEO_INDEX_SERVICE.clear()
        self.assertEqual(self.call("geo-clusters", "")["geo_index_source"], "built")

    def test_read_only_output_folder_keeps_the_index_in_memory(self) -> None:
        with mock.patch.object(geo_index, "write_geo_index_file", side_effect=PermissionError("read-only")):
            payload = self.call("geo-clusters", "")
            self.assertEqual((payload["geo_index"], payload["geo_index_source"]), ("ready", "memory"))
            order, cross = self.index_order("geo=-90,-180,90,180")
        self.assertIs(cross["geo_index"], True)
        self.assertEqual(len(order), 12)
        self.assertFalse((self.run_dir / geo_index.GEO_INDEX_FILE_NAME).exists())

    def test_building_state_falls_back_to_the_scan_then_ready(self) -> None:
        release = threading.Event()
        real = geo_index.load_or_build

        def slow(sources, output_dir):
            release.wait(10)
            return real(sources, output_dir)

        with mock.patch.object(geo_index, "load_or_build", side_effect=slow), mock.patch.object(geo_index, "GEO_INDEX_WAIT_SECONDS", 0.0):
            clusters = self.call("geo-clusters", "")
            self.assertEqual(clusters["geo_index"], "building")
            self.assertEqual(clusters["clusters"], [])
            order, cross = self.index_order("geo=-90,-180,90,180")
            self.assertEqual(cross["geo_index"], "building")
            self.assertEqual(order, self.scan_order({"geo": "-90,-180,90,180"}))
            release.set()
            for _ in range(200):
                clusters = self.call("geo-clusters", "")
                if clusters["geo_index"] == "ready":
                    break
                threading.Event().wait(0.02)
        self.assertEqual(clusters["geo_index"], "ready")
        self.assertEqual(clusters["matched"], 12)

    def test_failed_build_is_unavailable_and_scans(self) -> None:
        with mock.patch.object(geo_index, "load_or_build", side_effect=RuntimeError("boom")), self.assertLogs(geo_index.LOGGER, "WARNING"):
            self.assertEqual(self.call("geo-clusters", "")["geo_index"], "unavailable")
            order, cross = self.index_order("geo=-90,-180,90,180")
        self.assertEqual(cross["geo_index"], "unavailable")
        self.assertEqual(len(order), 12)

    def test_row_cap_truncates_and_the_listing_scans(self) -> None:
        with mock.patch.object(geo_index, "GEO_INDEX_MAX_ROWS", 3):
            clusters = self.call("geo-clusters", "")
            self.assertTrue(clusters["truncated"])
            self.assertEqual(clusters["located_total"], 3)
            order, cross = self.index_order("geo=-90,-180,90,180")
        self.assertEqual(cross["geo_index"], "truncated")
        self.assertEqual(len(order), 12)

    # --- clusters ------------------------------------------------------------------------------

    def test_clusters_cells_times_and_samples(self) -> None:
        payload = self.call("geo-clusters", "cell=0.01")
        self.assertEqual(payload["cell"], 0.01)
        self.assertEqual(payload["located_total"], 12)
        self.assertEqual(payload["matched"], 12)
        self.assertEqual(payload["available_kinds"], ["eventlog", "location", "media-image", "profiled"])
        clusters = {item["id"]: item for item in payload["clusters"]}
        seoul = clusters["3748:12694"]
        # eventlog 1, location 0, media-image 0, 1 (37.4851, 126.9411) and 6 (the cell edge) share 37.48 / 126.94.
        self.assertEqual(seoul["count"], 5)
        self.assertEqual(seoul["box"], "37.48,126.94,37.49,126.95")
        self.assertEqual((seoul["lat"], seoul["lon"]), (37.485, 126.945))
        self.assertEqual(seoul["first_time"], "2025-05-26T01:00:00Z")
        self.assertEqual(seoul["last_time"], "2025-05-28T12:00:00Z")
        self.assertEqual(seoul["sample"]["kind"], "eventlog")
        self.assertEqual(payload["clusters"][0]["id"], "3748:12694")  # most rows first
        self.assertEqual(clusters["8999:17999"]["box"], "89.99,179.99,90,180")
        self.assertEqual(clusters["-1050:-18000"]["box"], "-10.5,-180,-10.49,-179.99")
        # Every row of a cluster lies in its box (the console filters the grid with it).
        for cluster in payload["clusters"]:
            box = tuple(float(part) for part in cluster["box"].split(","))
            self.assertTrue(in_geo_box((cluster["sample"]["lat"], cluster["sample"]["lon"]), box), cluster)
            order, _ = self.index_order(f"geo={cluster['box']}")
            self.assertEqual(len(order), cluster["count"], cluster)
        # GPS time first: media-image 1 carries gps_datetime_utc_candidate only.
        coarse = self.call("geo-clusters", "cell=1&kind=media-image")
        self.assertEqual(coarse["kinds"], ["media-image"])
        self.assertEqual(coarse["matched"], 7)
        seoul = next(item for item in coarse["clusters"] if item["id"] == "37:126")
        self.assertEqual((seoul["first_time"], seoul["last_time"]), ("2025-05-26T01:00:00Z", "2025-05-27T02:00:00Z"))

    def test_clusters_box_and_filters(self) -> None:
        payload = self.call("geo-clusters", "geo=37,126,38,127")
        self.assertEqual(payload["matched"], 5)
        self.assertFalse(payload["filtered"])
        self.assertEqual(payload["conditions"]["geo"], [37.0, 126.0, 38.0, 127.0])
        payload = self.call("geo-clusters", "geo=37,126,38,127&path_contains=b.jpg")
        self.assertEqual(payload["matched"], 1)
        self.assertTrue(payload["filtered"])
        self.assertEqual(payload["scanned"], 5)
        payload = self.call("geo-clusters", "from=2025-05-27")
        self.assertEqual(payload["matched"], 3)  # eventlog 1, media-image 8, profiled 0
        payload = self.call("geo-clusters", "kind=nope")
        self.assertEqual((payload["kinds"], payload["matched"], payload["clusters"]), ([], 0, []))

    def test_clusters_korean_422(self) -> None:
        for query in ("cell=0", "cell=abc", "cell=5", "geo=1,2,3", "weekday=funday"):
            with self.subTest(query=query):
                detail = self.call("geo-clusters", query, expect=422)["detail"]
                self.assertTrue(any(ord(char) in HANGUL for char in str(detail)), detail)


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for API tests")
class GeoIndexUnitTests(unittest.TestCase):
    def test_cell_rule_matches_the_console(self) -> None:
        self.assertEqual(geo_index.cell_of(37.48, 90, 0.01), 3748)
        self.assertEqual(geo_index.cell_of(90, 90, 0.01), 8999)
        self.assertEqual(geo_index.cell_of(-90, 90, 0.01), -9000)
        self.assertEqual(geo_index.cell_of(180, 180, 0.01), 17999)
        self.assertEqual(geo_index.cell_of(-0.001, 180, 0.01), -1)
        self.assertEqual(geo_index._number_text(37.0), "37")
        self.assertEqual(geo_index._number_text(-0.01), "-0.01")
        self.assertEqual(geo_index.parse_cell(None), 0.01)
        with self.assertRaises(ValueError):
            geo_index.parse_cell("2")

    def test_persist_step_writes_the_index(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            records = out / "media.jsonl"
            records.write_text("".join(json.dumps(row) + "\n" for row in MEDIA), encoding="utf-8", newline="\n")
            payload = {"records_path": str(records), "artifacts": [], "record_count": len(MEDIA)}
            payload_path = out / "artifacts_media.json"
            payload_path.write_text(json.dumps(payload), encoding="utf-8")
            record = build_run_geo_index(out, {"media": payload_path}, {"media": payload})
            self.assertEqual(record["status"], "completed", record)
            self.assertEqual(record["located"], 7)
            stored = geo_index.read_geo_index_file(out, geo_index.sources_stamp([("media", payload, payload_path)]))
            self.assertIsNotNone(stored)
            assert stored is not None
            self.assertEqual([entry.record_index for entry in stored.by_kind["media"]], [0, 1, 4, 6, 7, 8, 9])
            # Byte offsets point at the record lines.
            rows = list(geo_index.read_entries(payload, payload_path, stored.by_kind["media"]))
            self.assertEqual([row["path"] for _entry, row in rows][:2], [r"C:\p\a.jpg", r"C:\p\b.jpg"])
            # A read-only folder is a failed record, never an exception.
            with mock.patch.object(geo_index, "write_geo_index_file", side_effect=PermissionError("ro")):
                self.assertEqual(build_run_geo_index(out, {"media": payload_path}, {"media": payload})["status"], "failed")


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for API tests")
class GeoIndexRunCompletionTests(unittest.TestCase):
    def test_run_writes_the_index_and_the_api_reads_it_as_is(self) -> None:
        from rapidtriage.artifacts import clear_collect_cache
        from rapidtriage.core.run import RUN_PROGRESS_FILE_NAME, run_triage_mode
        from tests.test_rapidtriage_run import build_run_fixture

        clear_collect_cache()
        self.addCleanup(clear_collect_cache)
        geo_index.GEO_INDEX_SERVICE.clear()
        self.addCleanup(geo_index.GEO_INDEX_SERVICE.clear)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "case-root"
            output_dir = Path(temp) / "run-out"
            root.mkdir(parents=True)
            build_run_fixture(root)
            run_triage_mode(root, mode="hacking", output_dir=output_dir)
            self.assertTrue((output_dir / geo_index.GEO_INDEX_FILE_NAME).is_file())
            progress = json.loads((output_dir / RUN_PROGRESS_FILE_NAME).read_text(encoding="utf-8"))
            persist = next(item for item in progress["completed_stages"] if item["stage"] == "persist")
            self.assertEqual(persist["geo_index"]["status"], "completed", persist)
            store = RunJobStore()
            run_id = store.import_completed_run(output_dir).run_id
            client = TestClient(create_app(store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})
            payload = client.get(f"/api/runs/{run_id}/geo-clusters").json()
            # The stamp written with the run matches the finished outputs: no rebuild.
            self.assertEqual((payload["geo_index"], payload["geo_index_source"]), ("ready", "file"), payload)


if __name__ == "__main__":
    unittest.main()
