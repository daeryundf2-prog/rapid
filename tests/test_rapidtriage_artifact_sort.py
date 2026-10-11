from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import unittest
from array import array
from pathlib import Path
from unittest.mock import patch

try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import artifact_sort, create_app

    HAS_FASTAPI = True
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

from rapidtriage.core.jobs import RunJobStore

TOKEN = "artifact-sort-test-token"


def _row(index: int, details: dict[str, object], path: str = "C:/logs/a.evtx") -> dict[str, object]:
    return {"artifact_type": "eventlog-event", "path": path, "details": {"source_index": index, **details}}


ROWS = [
    _row(0, {"timestamp": "2024-01-02T00:00:00Z", "run_count": 5, "name": "beta"}),
    _row(1, {"time": "2024-01-05T00:00:00Z", "run_count": 12, "name": "Alpha"}, "C:/user/b.evtx"),
    _row(2, {"timestamp": "", "event_time": "2024-01-03T00:00:00Z", "run_count": None, "name": ""}),
    _row(3, {"last_written_at": "2024-01-01T00:00:00Z", "run_count": 7, "name": "gamma"}, "C:/user/c.evtx"),
    _row(4, {"run_count": 5, "name": "alpha", "tags": ["x"]}),
    _row(5, {"target_modified_at": "2024-01-04T00:00:00Z", "run_count": 30, "name": "Delta"}, "C:/user/d.evtx"),
]


def wait_ready(fetch, *, timeout: float = 10.0):
    deadline = time.monotonic() + timeout
    while True:
        body = fetch()
        if body["sort"]["status"] != "building" or time.monotonic() > deadline:
            return body
        time.sleep(0.02)


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for artifact sort API tests")
class ArtifactSortApiTests(unittest.TestCase):
    def setUp(self) -> None:
        artifact_sort.SORT_INDEX_CACHE.clear()
        self.addCleanup(artifact_sort.SORT_INDEX_CACHE.clear)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name) / "evidence"
        self.run_dir = Path(self.temp.name) / "run"
        root.mkdir()
        self.run_dir.mkdir()
        self.records = self.run_dir / "records_eventlog.jsonl"
        self.records.write_text("\n".join(json.dumps(row) for row in ROWS) + "\n", encoding="utf-8")
        outputs: dict[str, str] = {}
        for kind, payload in (
            ("eventlog", {"records_path": str(self.records), "record_count": len(ROWS), "artifacts": ROWS[:2]}),
            ("browser", {"artifacts": [{"artifact_type": "history", "path": "b.sqlite"}]}),
        ):
            path = self.run_dir / f"artifacts_{kind}.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            outputs[f"artifacts_{kind}"] = str(path)
        summary_path = self.run_dir / "rapidtriage-run-summary.json"
        outputs["summary"] = str(summary_path)
        summary_path.write_text(
            json.dumps(
                {
                    "profile_version": "rapidtriage-run-summary-v1",
                    "mode": "fraud",
                    "root": str(root),
                    "output_dir": str(self.run_dir),
                    "outputs": outputs,
                }
            ),
            encoding="utf-8",
        )
        store = RunJobStore()
        self.run_id = store.import_completed_run(self.run_dir).run_id
        self.client = TestClient(create_app(store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})

    def get(self, **params):
        response = self.client.get(f"/api/runs/{self.run_id}/artifacts", params={"kind": "eventlog", **params})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def sorted_page(self, **params):
        body = wait_ready(lambda: self.get(**params)["artifacts"]["eventlog"])
        self.assertEqual(body["sort"]["status"], "ready", body["sort"])
        return body

    def test_building_response_then_ready_order(self) -> None:
        gate = threading.Event()
        real_build = artifact_sort.build_sort_index

        calls: list[int] = []

        def gated(*args, **kwargs):
            calls.append(1)
            gate.wait(5)
            return real_build(*args, **kwargs)

        with patch.object(artifact_sort, "build_sort_index", gated):
            body = self.get(limit=2, sort="timestamp", order="desc")
            page = body["artifacts"]["eventlog"]
            self.assertEqual(page["sort"]["status"], "building")
            self.assertEqual(page["sort"]["key"], "timestamp")
            self.assertEqual(page["sort"]["order"], "desc")
            self.assertEqual(page["sort"]["progress"], 0.0)  # gated before reading a byte
            self.assertEqual(page["artifacts"], [])
            self.assertEqual(page["pagination"]["total"], len(ROWS))
            self.assertTrue(body["sort_supported"])
            again = self.get(limit=2, sort="timestamp", order="desc", locate=1)["artifacts"]["eventlog"]
            self.assertEqual(again["sort"]["status"], "building")
            self.assertIsNone(again["sort"]["position"])
            self.assertEqual(again["pagination"]["total"], len(ROWS))
            self.assertEqual(calls, [1], "a repeated request must join the in-progress build")
            gate.set()
            page = self.sorted_page(limit=10, sort="timestamp", order="desc")
        self.assertEqual(calls, [1])
        self.assertEqual(page["sort"]["progress"], 1.0)
        # TIME_KEYS first non-empty: 1=01-05, 5=01-04 (target_modified_at), 2=01-03
        # (event_time; empty timestamp skipped), 0=01-02, 3=01-01 (last_written_at); 4 missing.
        self.assertEqual([row["record_index"] for row in page["artifacts"]], [1, 5, 2, 0, 3, 4])
        self.assertEqual(page["artifacts"][0]["details"]["source_index"], 1)
        located = self.sorted_page(limit=2, sort="timestamp", order="desc", locate=2)
        self.assertEqual(located["sort"]["position"], 2)
        self.assertIsNone(self.sorted_page(limit=2, sort="timestamp", order="desc", locate=99)["sort"]["position"])
        self.assertNotIn("position", self.sorted_page(limit=2, sort="timestamp", order="desc")["sort"])
        asc = self.sorted_page(limit=10, sort="timestamp", order="asc")
        self.assertEqual([row["record_index"] for row in asc["artifacts"]], [3, 0, 2, 5, 1, 4])

    def test_numeric_string_and_missing_comparison(self) -> None:
        numbers = self.sorted_page(limit=10, sort="details.run_count", order="asc")
        # 5 (idx 0) and 5 (idx 4) tie -> JSONL order; None last.
        self.assertEqual([row["record_index"] for row in numbers["artifacts"]], [0, 4, 3, 1, 5, 2])
        numbers_desc = self.sorted_page(limit=10, sort="details.run_count:desc")
        self.assertEqual(numbers_desc["sort"]["order"], "desc")
        self.assertEqual([row["record_index"] for row in numbers_desc["artifacts"]], [5, 1, 3, 0, 4, 2])
        names = self.sorted_page(limit=10, sort="details.name", order="asc")
        # casefold: Alpha == alpha (tie keeps JSONL order), "" counts as missing.
        self.assertEqual([row["record_index"] for row in names["artifacts"]], [1, 4, 0, 5, 3, 2])
        names_desc = self.sorted_page(limit=10, sort="details.name", order="desc")
        self.assertEqual([row["record_index"] for row in names_desc["artifacts"]], [3, 5, 0, 1, 4, 2])
        paged = self.sorted_page(limit=2, offset=2, sort="details.name", order="desc")
        self.assertEqual([row["record_index"] for row in paged["artifacts"]], [0, 1])
        self.assertEqual(paged["pagination"]["total"], len(ROWS))
        self.assertTrue(paged["pagination"]["has_more"])

    def test_mixed_values_compare_as_strings(self) -> None:
        values: list[tuple[object, int]] = [(10, 0), ("9", 1), (2, 2), ("abc", 3)]
        ascending, descending = artifact_sort.order_indices(values, array("q", [4]))
        self.assertEqual(list(ascending), [0, 2, 1, 3, 4])
        self.assertEqual(list(descending), [3, 1, 2, 0, 4])

    def test_numeric_strings_compare_numerically(self) -> None:
        values: list[tuple[object, int]] = [("1531", 0), ("9", 1), ("0x1F", 2), (" 4.5 ", 3), (100, 4)]
        ascending, descending = artifact_sort.order_indices(values, array("q", [5]))
        self.assertEqual(list(ascending), [3, 1, 2, 4, 0, 5])
        self.assertEqual(list(descending), [0, 4, 2, 1, 3, 5])
        mixed: list[tuple[object, int]] = [("1531", 0), ("9", 1), ("abc", 2), (True, 3)]
        ascending, _ = artifact_sort.order_indices(mixed, array("q"))
        self.assertEqual(list(ascending), [0, 1, 2, 3])  # text: "1531" < "9" < "abc" < "true"
        booleans: list[tuple[object, int]] = [(True, 0), (False, 1)]
        ascending, _ = artifact_sort.order_indices(booleans, array("q"))
        self.assertEqual(list(ascending), [1, 0])

    def test_timestamps_compare_chronologically(self) -> None:
        values: list[tuple[object, int]] = [
            ("2024-01-01T09:30:00+09:00", 0),  # 00:30Z
            ("2024-01-01T01:00:00+00:00", 1),  # 01:00Z
            ("not a time", 2),
            ("2024-01-01T00:45:00", 3),  # naive = 00:45Z
            ("2024-01-01T00:10:00Z", 4),
            ("garbage", 5),
        ]
        ascending, descending = artifact_sort.order_indices(values, array("q", [6]), chronological=True)
        self.assertEqual(list(ascending), [4, 0, 3, 1, 2, 5, 6])
        self.assertEqual(list(descending), [1, 3, 0, 4, 2, 5, 6])

    def test_non_finite_numbers_sort_as_missing(self) -> None:
        nan = json.loads("NaN")
        for values, expected_asc, expected_desc in (
            ([(nan, 0), (1, 1), (float("inf"), 2), ("1e999", 3), (0, 4)], [4, 1, 0, 2, 3], [1, 4, 0, 2, 3]),
            ([(nan, 0), ("b", 1), ("a", 2)], [2, 1, 0], [1, 2, 0]),
        ):
            ascending, descending = artifact_sort.order_indices(values, array("q"))
            self.assertEqual(list(ascending), expected_asc)
            self.assertEqual(list(descending), expected_desc)
        ascending, _ = artifact_sort.order_indices([(nan, 0), ("2024-01-01", 1)], array("q"), chronological=True)
        self.assertEqual(list(ascending), [1, 0])

    def test_integers_stay_exact_and_huge_hex_falls_back_to_text(self) -> None:
        big = 2**53
        ascending, descending = artifact_sort.order_indices([(big + 1, 0), (big, 1), (str(big + 1), 2)], array("q"))
        self.assertEqual(list(ascending), [1, 0, 2])
        self.assertEqual(list(descending), [0, 2, 1])
        ascending, _ = artifact_sort.order_indices([(big + 1, 0), (float(big), 1)], array("q"))
        self.assertEqual(list(ascending), [1, 0])
        huge = "0x" + "f" * 300
        ascending, _ = artifact_sort.order_indices([("5", 0), (huge, 1), ("3", 2)], array("q"))
        self.assertEqual(list(ascending), [1, 2, 0])  # text: "0xfff…" < "3" < "5"
        self.assertIs(artifact_sort.as_number("9" * 5000), artifact_sort.NOT_NUMERIC)

    def test_one_kind_constraint_and_order_validation(self) -> None:
        url = f"/api/runs/{self.run_id}/artifacts"
        for params in ({"sort": "timestamp", "limit": 5}, {"sort": "timestamp", "limit": 5, "kind": ["eventlog", "browser"]}):
            response = self.client.get(url, params=params)
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.json(), {"detail": "sort requires exactly one kind"})
        bad_order = self.client.get(url, params={"sort": "timestamp", "order": "up", "kind": "eventlog", "limit": 5})
        self.assertEqual(bad_order.status_code, 400)

    def test_unsupported_keys_and_inline_payload(self) -> None:
        listy = self.get(limit=10, sort="details.tags")["artifacts"]["eventlog"]  # probe: no build
        self.assertEqual(listy["sort"]["status"], "unsupported")
        self.assertEqual(listy["sort"]["reason"], "정렬 키 값이 스칼라가 아닙니다: details.tags")
        self.assertEqual([row["record_index"] for row in listy["artifacts"]], list(range(len(ROWS))))
        for bad in ("details.a b", "details.a,b", "details.a:b", "details.", "path", "title"):
            body = self.get(limit=10, sort=bad)
            page = body["artifacts"]["eventlog"]
            self.assertEqual(page["sort"]["status"], "unsupported", bad)
            self.assertIn("지원하지 않는 정렬 키", page["sort"]["reason"])
            self.assertEqual(page["sort"]["progress"], 0.0)
            self.assertFalse(body["sort_supported"])
            self.assertEqual([row["record_index"] for row in page["artifacts"]], list(range(len(ROWS))))
        dotted = wait_ready(lambda: self.get(limit=10, sort="details.a.b")["artifacts"]["eventlog"])
        self.assertEqual(dotted["sort"]["status"], "ready")
        inline = self.client.get(
            f"/api/runs/{self.run_id}/artifacts", params={"kind": "browser", "limit": 5, "sort": "timestamp"}
        ).json()
        self.assertEqual(inline["artifacts"]["browser"]["sort"]["status"], "unsupported")
        self.assertEqual(inline["artifacts"]["browser"]["sort"]["reason"], "인라인 결과는 전체 정렬을 지원하지 않습니다")
        self.assertFalse(inline["sort_supported"])

    def test_sort_with_path_contains(self) -> None:
        page = self.sorted_page(limit=2, sort="details.run_count", order="desc", path_contains="USER")
        self.assertEqual([row["record_index"] for row in page["artifacts"]], [5, 1])
        self.assertTrue(page["pagination"]["filtered"])
        self.assertTrue(page["pagination"]["has_more"])
        rest = self.sorted_page(limit=5, offset=2, sort="details.run_count", order="desc", path_contains="user")
        self.assertEqual([row["record_index"] for row in rest["artifacts"]], [3])
        self.assertEqual(rest["pagination"]["total"], 3)
        self.assertFalse(rest["pagination"]["truncated"])
        self.assertEqual(rest["pagination"]["scanned"], len(ROWS))

    def test_file_change_invalidates_index(self) -> None:
        first = self.sorted_page(limit=1, sort="details.run_count", order="desc")
        self.assertEqual(first["artifacts"][0]["record_index"], 5)
        changed = [dict(row, details=dict(row["details"])) for row in ROWS]
        changed[0]["details"]["run_count"] = 999
        self.records.write_text("\n".join(json.dumps(row) for row in changed) + "\n", encoding="utf-8")
        stat = self.records.stat()
        os.utime(self.records, ns=(stat.st_atime_ns, stat.st_mtime_ns + 5_000_000_000))
        second = self.sorted_page(limit=1, sort="details.run_count", order="desc")
        self.assertEqual(second["artifacts"][0]["record_index"], 0)
        self.assertEqual(second["artifacts"][0]["details"]["run_count"], 999)
        current = self.records.stat()
        revisions = [k for k in artifact_sort.SORT_INDEX_CACHE.cached_keys() if k[2] == "details.run_count"]
        self.assertEqual(revisions, [(self.run_id, "eventlog", "details.run_count", current.st_size, current.st_mtime_ns)])

    def test_same_size_rewrite_answers_409_and_rebuilds(self) -> None:
        self.sorted_page(limit=6, sort="details.run_count", order="desc")
        lines = self.records.read_bytes().splitlines(keepends=True)
        self.assertNotEqual(len(lines[0]), len(lines[1]))
        before = self.records.stat()
        self.records.write_bytes(b"".join([lines[1], lines[0], *lines[2:]]))
        os.utime(self.records, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.assertEqual(self.records.stat().st_size, before.st_size)
        stale = self.client.get(
            f"/api/runs/{self.run_id}/artifacts",
            params={"kind": "eventlog", "limit": 6, "sort": "details.run_count", "order": "desc"},
        )
        self.assertEqual(stale.status_code, 409)
        self.assertEqual(stale.json()["detail"], "정렬 인덱스가 오래되었습니다. 다시 시도하세요")
        self.assertEqual(artifact_sort.SORT_INDEX_CACHE.cached_keys(), [])
        rebuilt = self.sorted_page(limit=6, sort="details.run_count", order="desc")
        self.assertEqual(rebuilt["artifacts"][0]["details"]["run_count"], 30)

    def test_order_casing_suffix_and_order_without_sort(self) -> None:
        upper = self.sorted_page(limit=6, sort="details.run_count", order="DESC")
        self.assertEqual(upper["sort"]["order"], "desc")
        self.assertEqual(upper["artifacts"][0]["record_index"], 5)
        suffix = self.sorted_page(limit=6, sort="details.run_count:DESC")
        self.assertEqual(suffix["sort"]["order"], "desc")
        explicit = self.sorted_page(limit=6, sort="details.run_count:desc", order="asc")
        self.assertEqual(explicit["sort"]["order"], "asc")
        self.assertEqual(explicit["artifacts"][0]["record_index"], 0)
        ignored = self.client.get(
            f"/api/runs/{self.run_id}/artifacts", params={"kind": "eventlog", "limit": 2, "order": "sideways"}
        )
        self.assertEqual(ignored.status_code, 200, ignored.text)
        self.assertNotIn("sort", ignored.json()["artifacts"]["eventlog"])

    def test_sorted_next_cursor_round_trip(self) -> None:
        first = self.sorted_page(limit=2, sort="timestamp", order="desc")
        self.assertEqual([row["record_index"] for row in first["artifacts"]], [1, 5])
        cursor = first["pagination"]["next_cursor"]
        second = self.sorted_page(limit=2, sort="timestamp", order="desc", cursor=cursor)
        self.assertEqual([row["record_index"] for row in second["artifacts"]], [2, 0])
        third = self.sorted_page(limit=2, sort="timestamp", order="desc", cursor=second["pagination"]["next_cursor"])
        self.assertEqual([row["record_index"] for row in third["artifacts"]], [3, 4])
        self.assertIsNone(third["pagination"]["next_cursor"])

    def test_locate_position_is_null_with_path_contains(self) -> None:
        plain = self.sorted_page(limit=2, sort="timestamp", order="desc", locate=5)
        self.assertEqual(plain["sort"]["position"], 1)
        filtered = self.sorted_page(limit=2, sort="timestamp", order="desc", locate=5, path_contains="user")
        self.assertIn("position", filtered["sort"])
        self.assertIsNone(filtered["sort"]["position"])

    def test_sorted_path_contains_scan_cap(self) -> None:
        with patch.object(artifact_sort, "SORTED_FILTER_SCAN_CAP", 2):
            page = self.sorted_page(limit=10, sort="details.run_count", order="desc", path_contains="C:")
        self.assertEqual(page["pagination"]["scanned"], 2)
        self.assertTrue(page["pagination"]["truncated"])
        self.assertIsNone(page["pagination"]["total"])
        self.assertEqual([row["record_index"] for row in page["artifacts"]], [5, 1])

    def test_record_numbering_matches_between_sorted_and_unsorted(self) -> None:
        lines = [
            json.dumps(_row(0, {"name": "b"})),
            "[1, 2]",
            "",
            "   ",
            json.dumps(_row(1, {"name": "a"})),
            '{"details": {"name": broken',
            json.dumps(_row(3, {"name": "c"})),
        ]
        self.records.write_text("\n".join(lines) + "\n", encoding="utf-8")
        stat = self.records.stat()
        os.utime(self.records, ns=(stat.st_atime_ns, stat.st_mtime_ns + 7_000_000_000))
        with self.assertLogs("rapidtriage.api.app.jsonl_records", "WARNING") as logs:
            unsorted = self.get(limit=10)["artifacts"]["eventlog"]
        self.assertTrue(any("line 6" in line for line in logs.output))
        self.assertEqual([row["record_index"] for row in unsorted["artifacts"]], [0, 1, 3])
        by_index = {row["record_index"]: row["details"]["name"] for row in unsorted["artifacts"]}
        page = self.sorted_page(limit=10, sort="details.name", order="asc", locate=3)
        self.assertEqual([row["record_index"] for row in page["artifacts"]], [1, 0, 3])
        self.assertEqual({row["record_index"]: row["details"]["name"] for row in page["artifacts"]}, by_index)
        self.assertEqual(page["sort"]["position"], 2)
        filtered = self.sorted_page(limit=10, sort="details.name", order="desc", path_contains="a.evtx")
        self.assertEqual([row["record_index"] for row in filtered["artifacts"]], [3, 0, 1])
        plain_filter = self.get(limit=10, path_contains="a.evtx")["artifacts"]["eventlog"]
        self.assertEqual([row["record_index"] for row in plain_filter["artifacts"]], [0, 1, 3])

    def test_unsorted_rows_carry_record_index(self) -> None:
        url = f"/api/runs/{self.run_id}/artifacts"
        for params in ({"limit": 3}, {"limit": 3, "kind": ["eventlog", "browser"]}, {}):
            body = self.client.get(url, params=params).json()
            self.assertEqual(sorted(body["artifacts"]), ["browser", "eventlog"])
            for kind_page in body["artifacts"].values():
                self.assertTrue(all("record_index" in row for row in kind_page["artifacts"]), params)
        page = self.get(limit=2, offset=3)["artifacts"]["eventlog"]
        self.assertNotIn("sort", page)
        self.assertEqual([row["record_index"] for row in page["artifacts"]], [3, 4])
        preview = self.get()["artifacts"]["eventlog"]
        self.assertEqual([row["record_index"] for row in preview["artifacts"]], [0, 1])


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for artifact sort tests")
class SortIndexCacheTests(unittest.TestCase):
    def test_lru_bounds_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            records = Path(temp) / "r.jsonl"
            records.write_text("\n".join(json.dumps(row) for row in ROWS) + "\n", encoding="utf-8")
            cache = artifact_sort.SortIndexCache(max_entries=2)
            for kind in ("a", "b", "c"):
                state = cache.lookup(run_id="r", kind=kind, key="timestamp", records_path=records, profiles=None)
                deadline = time.monotonic() + 5
                while state.status == "building" and time.monotonic() < deadline:
                    time.sleep(0.01)
                    state = cache.lookup(run_id="r", kind=kind, key="timestamp", records_path=records, profiles=None)
                self.assertEqual(state.status, "ready")
            self.assertEqual(len(cache._entries), 2)
            self.assertEqual([key[1] for key in cache._entries], ["b", "c"])

    def test_non_scalar_after_probe_window_found_by_build(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            records = Path(temp) / "r.jsonl"
            lines = [{"details": {"v": 1}}, {"details": {"v": 2}}, {"details": {"v": [3]}}]
            records.write_text("\n".join(json.dumps(row) for row in lines) + "\n", encoding="utf-8")
            artifact_sort.probe_sort_key(records, "details.v", None, rows=2)  # list is row 3
            with self.assertRaises(artifact_sort.SortUnsupported):
                artifact_sort.probe_sort_key(records, "details.v", None)
            with self.assertRaises(artifact_sort.SortUnsupported):
                artifact_sort.build_sort_index(records, "details.v", None)

    def test_builds_are_capped_and_queue_with_zero_progress(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            records = Path(temp) / "r.jsonl"
            records.write_text("\n".join(json.dumps(row) for row in ROWS) + "\n", encoding="utf-8")
            gate = threading.Event()
            started: list[str] = []
            lock = threading.Lock()
            real_build = artifact_sort.build_sort_index

            def gated(path, key, profiles, progress=None):
                with lock:
                    started.append(key)
                gate.wait(5)
                return real_build(path, key, profiles, progress)

            cache = artifact_sort.SortIndexCache(max_builds=2)
            keys = ("details.run_count", "details.name", "timestamp")

            def lookup(key):
                return cache.lookup(run_id="r", kind="k", key=key, records_path=records, profiles=None)

            with patch.object(artifact_sort, "build_sort_index", gated):
                states = [lookup(key) for key in keys]
                deadline = time.monotonic() + 5
                while len(started) < 2 and time.monotonic() < deadline:
                    time.sleep(0.01)
                time.sleep(0.1)
                self.assertEqual([state.status for state in states], ["building"] * 3)
                self.assertEqual(len(started), 2, "a third build must wait for a free slot")
                queued = lookup(next(key for key in keys if key not in started))
                self.assertEqual((queued.status, queued.progress), ("building", 0.0))
                gate.set()
                deadline = time.monotonic() + 5
                final = [lookup(key) for key in keys]
                while any(state.status == "building" for state in final) and time.monotonic() < deadline:
                    time.sleep(0.01)
                    final = [lookup(key) for key in keys]
            self.assertEqual([state.status for state in final], ["ready"] * 3)
            self.assertEqual(sorted(started), sorted(keys))

    def test_record_limit_answers_unsupported(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            records = Path(temp) / "r.jsonl"
            records.write_text("\n".join(json.dumps(row) for row in ROWS) + "\n", encoding="utf-8")
            with patch.dict(os.environ, {"RAPIDTRIAGE_SORT_MAX_RECORDS": "4"}):
                with self.assertRaises(artifact_sort.SortUnsupported) as raised:
                    artifact_sort.build_sort_index(records, "timestamp", None)
            self.assertIn("전체 정렬 한도(4건)", str(raised.exception))

    def test_text_keys_are_truncated_and_tie_in_record_order(self) -> None:
        prefix = "x" * artifact_sort.SORT_TEXT_KEY_CHARS
        values: list[tuple[object, int]] = [(prefix + "b", 0), (prefix + "a", 1), ("w", 2)]
        ascending, descending = artifact_sort.order_indices(values, array("q"))
        self.assertEqual(list(ascending), [2, 0, 1])
        self.assertEqual(list(descending), [0, 1, 2])

    def _records(self, temp: str, details: list[dict[str, object]]) -> Path:
        records = Path(temp) / "r.jsonl"
        records.write_text("\n".join(json.dumps({"details": d}) for d in details) + "\n", encoding="utf-8")
        return records

    def _wait(self, cache, key, records, timeout=5.0):
        deadline = time.monotonic() + timeout
        state = cache.lookup(run_id="r", kind="k", key=key, records_path=records, profiles=None)
        while state.status == "building" and time.monotonic() < deadline:
            time.sleep(0.01)
            state = cache.lookup(run_id="r", kind="k", key=key, records_path=records, profiles=None)
        return state

    def test_numeric_scan_restarts_once_in_text_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            records = self._records(temp, [{"v": 3}, {"v": 1}, {"v": "abc"}, {"v": 10}])
            modes: list[str] = []
            real_scan = artifact_sort._scan

            def spy(path, key, profiles, mode, progress):
                modes.append(mode)
                return real_scan(path, key, profiles, mode, progress)

            with patch.object(artifact_sort, "_scan", spy):
                index = artifact_sort.build_sort_index(records, "details.v", None)
            self.assertEqual(modes, ["numeric", "text"])
            self.assertEqual(list(index.ascending), [1, 3, 0, 2])  # "1" < "10" < "3" < "abc"

    def test_text_budget_answers_unsupported(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            records = self._records(temp, [{"v": f"value-{i}"} for i in range(50)])
            with patch.dict(os.environ, {"RAPIDTRIAGE_SORT_MAX_TEXT_BYTES": "500"}):
                with self.assertRaises(artifact_sort.SortUnsupported) as raised:
                    artifact_sort.build_sort_index(records, "details.v", None)
            self.assertIn("정렬 키 텍스트가 메모리 한도", str(raised.exception))
            numeric = self._records(temp, [{"v": i} for i in range(50)])
            with patch.dict(os.environ, {"RAPIDTRIAGE_SORT_MAX_TEXT_BYTES": "500"}):
                self.assertEqual(artifact_sort.build_sort_index(numeric, "details.v", None).total, 50)

    def test_unsupported_reasons_do_not_evict_ready_indices(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            details = {"ok": 1, **{f"l{i}": [i] for i in range(8)}}
            records = self._records(temp, [details, details])
            cache = artifact_sort.SortIndexCache(max_entries=8)
            self.assertEqual(self._wait(cache, "details.ok", records).status, "ready")
            for i in range(8):
                self.assertEqual(self._wait(cache, f"details.l{i}", records).status, "unsupported")
            self.assertEqual([k[2] for k in cache.cached_keys()], ["details.ok"])
            self.assertEqual(self._wait(cache, "details.ok", records).status, "ready")

    def test_failed_build_releases_slot_and_expires(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            records = self._records(temp, [{"v": 1}, {"v": 2}])
            cache = artifact_sort.SortIndexCache(max_builds=1)
            real_build = artifact_sort.build_sort_index

            def flaky(path, key, profiles, progress=None):
                if key == "details.bad":
                    raise OSError("disk went away")
                return real_build(path, key, profiles, progress)

            with patch.object(artifact_sort, "build_sort_index", flaky):
                failed = self._wait(cache, "details.bad", records)
                self.assertEqual(failed.status, "unsupported")
                self.assertTrue(failed.reason.startswith("정렬 인덱스 생성에 실패했습니다"))
                self.assertEqual(self._wait(cache, "details.v", records).status, "ready")  # slot released
                (reason, expires), = [v for k, v in cache._unsupported.items() if k[2] == "details.bad"]
                self.assertIsNotNone(expires)
                with patch.object(artifact_sort.time, "monotonic", return_value=expires + 1):
                    retry = cache.lookup(run_id="r", kind="k", key="details.bad", records_path=records, profiles=None)
                self.assertEqual(retry.status, "building")

    def test_pending_builds_are_capped_without_caching_the_refusal(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            records = self._records(temp, [{"a": 1, "b": 2, "c": 3}])
            cache = artifact_sort.SortIndexCache(max_builds=1, max_pending=1)
            gate = threading.Event()
            real_build = artifact_sort.build_sort_index

            def gated(path, key, profiles, progress=None):
                gate.wait(5)
                return real_build(path, key, profiles, progress)

            def lookup(key):
                return cache.lookup(run_id="r", kind="k", key=key, records_path=records, profiles=None)

            with patch.object(artifact_sort, "build_sort_index", gated):
                self.assertEqual(lookup("details.a").status, "building")
                deadline = time.monotonic() + 5
                while not any(b.running for b in cache._builds.values()) and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertEqual(lookup("details.b").status, "building")  # pending 1
                refused = lookup("details.c")
                self.assertEqual(refused.status, "unsupported")
                self.assertEqual(refused.reason, "대기 중인 정렬 요청이 많습니다. 잠시 후 다시 시도하세요")
                gate.set()
                for key in ("details.a", "details.b", "details.c"):
                    self.assertEqual(self._wait(cache, key, records).status, "ready", key)

    def test_profile_rows_are_expanded_for_sort_values(self) -> None:
        profiles = {"p": {"codes": {"name": ["zulu", "alpha"]}}}
        with tempfile.TemporaryDirectory() as temp:
            records = Path(temp) / "r.jsonl"
            lines = [
                {"profile_ref": "p", "path": "x", "details": {"name": 0}},
                {"profile_ref": "p", "path": "y", "details": {"name": 1}},
            ]
            records.write_text("\n".join(json.dumps(row) for row in lines) + "\n", encoding="utf-8")
            index = artifact_sort.build_sort_index(records, "details.name", profiles)
            self.assertEqual(list(index.ascending), [1, 0])
            rows = list(artifact_sort.read_rows_at(records, index, [1], profiles))
            self.assertEqual(rows[0][1]["details"]["name"], "alpha")


if __name__ == "__main__":
    unittest.main()
