"""R7 search latency: /search defaults, paging, trimmed hits, regex guard, budget, caches, path index."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import create_app
    from rapidtriage.api.app.analyses import ANALYSIS_RUNNER

    HAS_FASTAPI = True
except ImportError:  # pragma: no cover
    HAS_FASTAPI = False

from rapidtriage.api.app.artifact_filter import filter_artifact_page, nfc_fold
from rapidtriage.api.app.artifact_path_index import PATH_INDEX_SERVICE, PathIndexService, build_path_index
from rapidtriage.core.jobs import RunJobStore, read_output_json
from rapidtriage.core.search import (
    COMPACT_METADATA_KEYS,
    SEARCH_DETAIL_KEYS,
    compact_search_metadata,
    run_unified_search,
)
from rapidtriage.core.search_budget import SourceScan
from rapidtriage.core.search_fts import (
    PROGRESS_HANDLER_STEPS,
    OrdinalRows,
    OutputRowCache,
    _BudgetGuard,
    _iter_rows,
    regex_literal_prefix_problem,
)
from tests.search_index_fixture import build_fixture_run, write_kind

TOKEN = "r7-search-latency-token"


def write_needle_run(root: Path, *, events: int, needle_every: int) -> dict[str, object]:
    timeline = {
        "command": "timeline",
        "events": [
            {
                "timestamp": f"2026-01-01T00:00:{index % 60:02d}+00:00",
                "event_type": "file-modified",
                "source": "files",
                "path": f"C:/evidence/file-{index}.txt",
                "summary": "needle event" if index % needle_every == needle_every - 1 else "plain event",
            }
            for index in range(events)
        ],
    }
    (root / "timeline.json").write_text(json.dumps(timeline), encoding="utf-8")
    return {"outputs": {"timeline": str(root / "timeline.json")}}


class UnifiedSearchPagingTests(unittest.TestCase):
    def test_pages_concatenate_to_the_unpaged_result_in_a_stable_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            summary = write_needle_run(Path(tmp_dir), events=400, needle_every=10)
            whole = run_unified_search(summary, ["needle"], limit=100, include_ocr=False, include_analysis=False)
            self.assertEqual(len(whole["matches"]), 40)
            self.assertEqual(whole["pagination"]["total"], 40)
            self.assertFalse(whole["pagination"]["has_more"])
            pointers: list[str] = []
            ids: list[str] = []
            offset = 0
            while True:
                page = run_unified_search(
                    summary, ["needle"], limit=15, offset=offset, include_ocr=False, include_analysis=False
                )
                pointers.extend(match["pointer"] for match in page["matches"])
                ids.extend(match["search_result_id"] for match in page["matches"])
                if not page["pagination"]["has_more"]:
                    self.assertEqual(page["pagination"]["total"], 40)
                    self.assertIsNone(page["pagination"]["next_offset"])
                    break
                self.assertIsNone(page["pagination"]["total"])
                offset = page["pagination"]["next_offset"]
            self.assertEqual(pointers, [match["pointer"] for match in whole["matches"]])
            self.assertEqual(ids, [match["search_result_id"] for match in whole["matches"]])
            self.assertEqual(len(set(ids)), 40)

    def test_detail_off_skips_audit_blocks_and_compact_metadata_drops_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            fixture = build_fixture_run(Path(tmp_dir))
            light = run_unified_search(
                fixture["summary"],
                ["AnyDesk"],
                include_ocr=False,
                include_analysis=False,
                detail=False,
                metadata="compact",
            )
            full = run_unified_search(fixture["summary"], ["AnyDesk"], include_ocr=False, include_analysis=False)
            self.assertTrue(light["matches"])
            self.assertEqual(len(light["matches"]), len(full["matches"]))
            for key in SEARCH_DETAIL_KEYS:
                if not key.startswith("matches[]"):
                    self.assertNotIn(key, light)
                    self.assertIn(key, full)
            self.assertEqual(light["detail_omitted"], list(SEARCH_DETAIL_KEYS))
            for light_hit, full_hit in zip(light["matches"], full["matches"], strict=True):
                self.assertNotIn("advanced_search_hit_manifest", light_hit)
                self.assertNotIn("source_verification_profile", light_hit)
                self.assertIn("advanced_search_hit_manifest", full_hit)
                # finalize_search_hit fields are computed from the whole record before the trim.
                for key in ("title", "display_path", "artifact_type", "timestamp", "snippet", "locator", "path", "kind"):
                    self.assertEqual(light_hit.get(key), full_hit.get(key), key)
                self.assertLessEqual(set(light_hit["metadata"]), set(COMPACT_METADATA_KEYS))
                self.assertNotIn("details", light_hit["metadata"])
            self.assertLess(len(json.dumps(light, ensure_ascii=False)), len(json.dumps(full, ensure_ascii=False)) / 2)

    def test_compact_metadata_keeps_hashes_and_drops_large_values(self) -> None:
        compact = compact_search_metadata(
            {
                "timestamp": "2025-01-01T00:00:00Z",
                "size": 10,
                "hashes": {"sha256": "a" * 64, "nested": {"x": 1}},
                "source_hashes": {"sha256": "b" * 64},
                "details": {"huge": "x" * 10_000},
                "name": "y" * 1000,
            }
        )
        self.assertEqual(
            compact,
            {
                "timestamp": "2025-01-01T00:00:00Z",
                "size": 10,
                "hashes": {"sha256": "a" * 64},
                "source_hashes": {"sha256": "b" * 64},
            },
        )


class RegexGuardTests(unittest.TestCase):
    def test_literal_prefix_required(self) -> None:
        for ok in ("Live.*Update", "LiveUpdate\\w*", "^powershell\\.exe", "\\bcmd\\b", "계약.*서"):
            self.assertIsNone(regex_literal_prefix_problem(ok), ok)
        for bad in (".*Update", "\\d{6}-\\d{7}", "a|b", "[A-Z]+", "x"):
            problem = regex_literal_prefix_problem(bad)
            self.assertIsNotNone(problem, bad)
            self.assertIn("고정된 단어로 시작하지 않아", problem)


class SqliteBudgetTests(unittest.TestCase):
    def test_progress_handler_stops_a_statement_that_yields_no_row(self) -> None:
        connection = sqlite3.connect(":memory:")
        guard = _BudgetGuard()
        connection.set_progress_handler(guard, PROGRESS_HANDLER_STEPS)
        scan = SourceScan("artifacts", time.monotonic() + 0.05)
        guard.deadline = scan.deadline
        started = time.monotonic()
        sql = (
            "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 50000000) "
            "SELECT max(x) FROM c"
        )
        rows = list(_iter_rows(connection, sql, [], scan))
        elapsed = time.monotonic() - started
        self.assertEqual(rows, [])
        self.assertEqual(scan.stopped, "budget")
        self.assertLess(elapsed, 2.0)
        # Without a deadline the same connection still answers.
        guard.deadline = None
        self.assertEqual(connection.execute("SELECT 1").fetchone()[0], 1)
        connection.close()


class OutputRowCacheTests(unittest.TestCase):
    def test_rows_are_cached_per_revision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "files.json"
            path.write_text(json.dumps({"candidates": [{"path": f"C:/f{index}"} for index in range(5)]}), encoding="utf-8")
            cache = OutputRowCache(max_bytes=1 << 20)
            first = cache.rows(path, "candidates")
            self.assertEqual(cache.builds, 1)
            self.assertIs(cache.rows(path, "candidates"), first)
            self.assertEqual(cache.builds, 1)
            self.assertEqual(json.loads(first[3]), {"path": "C:/f3"})
            path.write_text(json.dumps({"candidates": [{"path": "C:/changed"}]}), encoding="utf-8")
            changed = cache.rows(path, "candidates")
            self.assertEqual(cache.builds, 2)
            self.assertEqual([json.loads(row) for row in changed], [{"path": "C:/changed"}])
            self.assertIsNone(OutputRowCache(max_bytes=10).rows(path, "candidates"))

    def test_ordinal_rows_random_access_from_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "docs.json"
            path.write_text(json.dumps({"candidates": [{"i": index} for index in range(4)]}), encoding="utf-8")
            rows = OrdinalRows(path, "candidates")
            self.assertEqual(rows.get(2), {"i": 2})
            self.assertEqual(rows.get(0), {"i": 0})  # cached rows are not forward-only
            self.assertIsNone(rows.get(9))


class PathIndexTests(unittest.TestCase):
    def make_kind(self, root: Path) -> Path:
        rows = []
        for index in range(300):
            row: dict[str, object] = {
                "provider": "p",
                "artifact_type": "eventlog-event",
                "details": {"record_id": index},
            }
            if index % 7 == 0:
                row["source_path"] = f"D:/Logs/Microsoft-Windows-LiveUpdate{index % 3}.evtx"
            elif index % 11 == 0:
                row["profile_ref"] = "with-path"
            else:
                row["path"] = f"D:/Logs/{['Security', 'System', '계약서 로그'][index % 3]}.evtx"
            rows.append(row)
        return write_kind(root, "eventlog", rows, profiles={"with-path": {"path": "D:/Profile/Path.evtx"}})

    def test_index_pages_match_the_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            payload_path = self.make_kind(Path(tmp_dir))
            payload = read_output_json(payload_path)
            index = build_path_index(payload, payload_path)
            self.assertIsNotNone(index)
            self.assertEqual(index.total, 300)
            for needle in ("liveupdate", "SECURITY", "계약", "profile", "evtx", "zzz", "LiveUpdate1"):
                for offset, limit in ((0, 10), (5, 7), (0, 500)):
                    scanned = filter_artifact_page(
                        payload, payload_path=payload_path, path_contains=needle, offset=offset, limit=limit
                    )
                    indexed = filter_artifact_page(
                        payload,
                        payload_path=payload_path,
                        path_contains=needle,
                        offset=offset,
                        limit=limit,
                        rows_source=index.iter_rows(payload, index.matching(nfc_fold(needle))),
                    )
                    self.assertEqual(indexed["artifacts"], scanned["artifacts"], (needle, offset))
                    for key in ("total", "has_more", "next_offset", "truncated"):
                        self.assertEqual(indexed["pagination"][key], scanned["pagination"][key], (needle, key))

    def test_service_reuses_index_and_rebuilds_on_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            payload_path = self.make_kind(Path(tmp_dir))
            payload = read_output_json(payload_path)
            service = PathIndexService(max_kinds=2)
            first = service.get("run1", "eventlog", payload, payload_path)
            self.assertIs(service.get("run1", "eventlog", payload, payload_path), first)
            self.assertEqual(service.builds, 1)
            other = service.get("run1", "other", payload, payload_path)
            self.assertIsNot(other, first)  # one entry per kind, not per run
            self.assertIs(service.get("run1", "eventlog", payload, payload_path), first)
            records = Path(str(payload["records_path"]))
            records.write_text(records.read_text(encoding="utf-8") + json.dumps({"path": "D:/new.evtx", "artifact_type": "x"}) + "\n", encoding="utf-8")
            rebuilt = service.get("run1", "eventlog", payload, payload_path)
            self.assertIsNot(rebuilt, first)
            self.assertEqual(rebuilt.total, 301)

    def test_ready_never_waits_and_builds_in_background(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            payload_path = self.make_kind(Path(tmp_dir))
            payload = read_output_json(payload_path)
            service = PathIndexService()
            self.assertIsNone(service.ready("run1", "eventlog", payload, payload_path))
            deadline = time.monotonic() + 10
            index = None
            while index is None and time.monotonic() < deadline:
                time.sleep(0.02)
                index = service.ready("run1", "eventlog", payload, payload_path)
            self.assertIsNotNone(index)
            self.assertEqual(service.pending(), 0)

    def test_scan_deadline_reports_truncated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            payload_path = self.make_kind(Path(tmp_dir))
            payload = read_output_json(payload_path)
            page = filter_artifact_page(
                payload,
                payload_path=payload_path,
                path_contains="zzz",
                offset=0,
                limit=10,
                deadline=time.monotonic() - 1,
            )
            self.assertTrue(page["pagination"]["truncated"])
            self.assertTrue(page["pagination"]["budget_stopped"])
            self.assertIsNone(page["pagination"]["total"])


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for API tests")
class SearchApiDefaultsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        fixture = build_fixture_run(Path(self.temp.name))
        self.store = RunJobStore()
        self.run_id = self.store.import_completed_run(fixture["run_dir"]).run_id
        self.app = create_app(self.store, auth_token=TOKEN)
        self.client = TestClient(self.app, headers={"X-RapidTriage-Token": TOKEN})
        self.addCleanup(lambda: ANALYSIS_RUNNER.shutdown(owner=self.app.state.analysis_owner))
        self.addCleanup(PATH_INDEX_SERVICE.clear)

    def url(self, suffix: str) -> str:
        return f"/api/runs/{self.run_id}{suffix}"

    def test_defaults_are_light(self) -> None:
        response = self.client.get(self.url("/search"), params={"keyword": "AnyDesk"})
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertTrue(payload["matches"])
        self.assertNotIn("analysis", payload)
        self.assertFalse(payload["options"]["include_ocr"])
        self.assertNotIn("ocr", payload["scanned"])
        self.assertEqual(payload["options"]["limit"], 250)
        self.assertEqual(payload["options"]["metadata"], "compact")
        self.assertFalse(payload["options"]["detail"])
        self.assertNotIn("advanced_search_query_hit_manifest", payload)
        self.assertNotIn("search_result_source_action_profile", payload)
        for hit in payload["matches"]:
            self.assertNotIn("source_viewer_action_profile", hit)
            self.assertNotIn("details", hit["metadata"])
            self.assertIn("snippet", hit)
            self.assertIn("title", hit)
        self.assertEqual(payload["pagination"]["offset"], 0)
        self.assertFalse(payload["pagination"]["has_more"])
        self.assertEqual(payload["pagination"]["total"], len(payload["matches"]))

    def test_flags_restore_the_full_payload(self) -> None:
        response = self.client.get(
            self.url("/search"),
            params={"keyword": "AnyDesk", "analysis": "1", "ocr": "1", "detail": "1", "metadata": "full"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertIn("analysis", payload)
        self.assertTrue(payload["options"]["include_ocr"])
        self.assertIn("advanced_search_query_hit_manifest", payload)
        self.assertIn("search_result_source_action_profile", payload)
        hits = payload["matches"]
        self.assertTrue(all("source_viewer_action_profile" in hit for hit in hits))
        self.assertTrue(any("details" in hit["metadata"] for hit in hits if hit["source"] == "artifacts"))
        # source=ocr alone also turns the OCR source on.
        ocr_only = self.client.get(self.url("/search"), params={"keyword": "AnyDesk", "source": "ocr"}).json()
        self.assertTrue(ocr_only["options"]["include_ocr"])

    def test_offset_pages(self) -> None:
        whole = self.client.get(self.url("/search"), params={"keyword": "AnyDesk"}).json()["matches"]
        self.assertGreaterEqual(len(whole), 3)
        first = self.client.get(self.url("/search"), params={"keyword": "AnyDesk", "limit": 2}).json()
        self.assertTrue(first["pagination"]["has_more"])
        self.assertEqual(first["pagination"]["next_offset"], 2)
        rest = self.client.get(self.url("/search"), params={"keyword": "AnyDesk", "limit": 250, "offset": 2}).json()
        self.assertEqual(
            [hit["pointer"] for hit in first["matches"] + rest["matches"]],
            [hit["pointer"] for hit in whole],
        )

    def test_unanchored_regex_is_a_korean_422(self) -> None:
        response = self.client.get(self.url("/search"), params={"keyword": ".*Desk", "search_mode": "regex"})
        self.assertEqual(response.status_code, 422)
        self.assertIn("고정된 단어로 시작하지 않아", response.json()["detail"])
        ok = self.client.get(self.url("/search"), params={"keyword": "Any.*Desk", "search_mode": "regex"})
        self.assertEqual(ok.status_code, 200, ok.text)
        self.assertTrue(ok.json()["matches"])

    def test_artifacts_path_contains_uses_the_path_index(self) -> None:
        params = {"kind": "eventlog", "limit": 10, "path_contains": "security.EVTX"}
        response = self.client.get(self.url("/artifacts"), params=params)
        self.assertEqual(response.status_code, 200, response.text)
        page = response.json()["artifacts"]["eventlog"]
        self.assertEqual(page["pagination"]["path_index"], "ready")
        self.assertEqual([row["record_index"] for row in page["artifacts"]], [0, 1, 3])
        self.assertEqual(page["matched"], 3)
        none = self.client.get(self.url("/artifacts"), params={**params, "path_contains": "zzqx"}).json()
        self.assertEqual(none["artifacts"]["eventlog"]["matched"], 0)


if __name__ == "__main__":
    unittest.main()
