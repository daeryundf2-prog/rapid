"""R7 P2: the console's global search over the v2 index (``POST /search/query`` with ``keywords``).

Synthetic fixture only (tests/search_index_fixture.py). The v2 hits must have the v1
``GET /search`` hit shape (finalize_search_hit), page by cursor with v1-style numbering, leave
the run folder alone (no search history), and find every v1 hit outside the timeline.
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import create_app
    from rapidtriage.api.app.analyses import ANALYSIS_RUNNER, TERMINAL_STATUSES
    from rapidtriage.api.app.search_index_service import AUTO_INDEX_ENV, SEARCH_HISTORY

    HAS_FASTAPI = True
except ImportError:  # pragma: no cover
    HAS_FASTAPI = False

from rapidtriage.core.jobs import RunJobStore
from rapidtriage.core.search_index.engine import contains_sql
from rapidtriage.core.search_index.hashsets import DATA_DIR_ENV
from rapidtriage.core.search_index.hits import (
    console_keywords,
    console_query,
    index_hit,
    source_path,
)
from rapidtriage.core.search_index.query import parse_query
from tests.search_index_fixture import build_fixture_run

TOKEN = "r7-p2-token"
# Every hit field the console grid, viewer and review marks read (finalize_search_hit).
HIT_FIELDS = {"source", "kind", "pointer", "path", "title", "display_path", "artifact_type", "timestamp", "snippet", "snippet_highlights", "locator", "metadata", "matched_keywords", "preview", "search_result_id"}


class ConsoleQueryTests(unittest.TestCase):
    def test_keywords_become_one_any_keyword_query_over_v1_collections(self) -> None:
        query = console_query(["계약", 'say "hi"', "c:\\temp"])
        self.assertEqual(query, '("계약" OR "say \\"hi\\"" OR "c:\\\\temp") -in:analysis -type:file-inventory')
        parsed = parse_query(query)  # the server grammar accepts it (quotes and backslashes escaped)
        self.assertTrue(parsed.clauses())
        with self.assertRaises(ValueError):
            console_query([])

    def test_keywords_normalized_like_v1_exact_mode(self) -> None:
        import unicodedata

        nfd = unicodedata.normalize("NFD", "계약")
        self.assertEqual(console_keywords([nfd, " 계약 ", "LiveUpdate", "liveupdate", ""]), ["계약", "liveupdate"])

    def test_contains_sql_skips_lower_for_words_without_ascii_letters(self) -> None:
        self.assertEqual(contains_sql("text", "계약"), ("instr(text, ?) > 0", "계약"))
        self.assertEqual(contains_sql("text", "12"), ("instr(text, ?) > 0", "12"))
        self.assertEqual(contains_sql("p.text", "LiveUp계약"), ("instr(lower(p.text), ?) > 0", "liveup계약"))
        connection = sqlite3.connect(":memory:")
        connection.execute("CREATE TABLE doc (text TEXT)")
        connection.executemany("INSERT INTO doc VALUES (?)", [("근로계약서 LiveUpdate",), ("SAMSUNG LIVEUPDATE 계약",), ("계 약",), ("abc",)])
        for literal in ("계약", "liveupdate", "LiveUpdate", "약 l"):
            sql, param = contains_sql("text", literal)
            fast = [row[0] for row in connection.execute(f"SELECT rowid FROM doc WHERE {sql}", (param,))]
            slow = [row[0] for row in connection.execute("SELECT rowid FROM doc WHERE instr(lower(text), ?) > 0", (literal.lower(),))]
            self.assertEqual(fast, slow, literal)

    def test_source_path_puts_the_acquisition_root_back(self) -> None:
        self.assertEqual(source_path("\\Users\\x\\a.doc", "D:\\case\\root\\"), "D:\\case\\root\\Users\\x\\a.doc")
        self.assertEqual(source_path("\\", "D:\\case\\root"), "D:\\case\\root")
        self.assertEqual(source_path("C:\\Windows\\a.exe", "D:\\case\\root"), "C:\\Windows\\a.exe")
        self.assertEqual(source_path("\\\\server\\share\\a", "D:\\root"), "\\\\server\\share\\a")
        self.assertEqual(source_path("\\Users\\x", ""), "\\Users\\x")

    def test_snippet_drops_the_leading_title_and_path_like_v1_body_snippets(self) -> None:
        row = {"collection": "docs", "kind": "", "locator": "/candidates/0", "path": "E:\\a\\계약 안내.hwp", "title": "계약 안내.hwp", "fields": {"kind": "hwp"},
               "snippet": {"text": "계약 안내.hwp E:\\a\\계약 안내.hwp 신규 계약 관련 안내"}}
        self.assertEqual(index_hit(row, root="", keywords=["계약"])["snippet"], "신규 계약 관련 안내")
        only_title = {**row, "snippet": {"text": "계약 안내.hwp E:\\a\\계약 안내.hwp 본문 없음"}}
        # The keyword is only in the title/path: the snippet keeps the path that holds it.
        self.assertEqual(index_hit(only_title, root="", keywords=["계약"])["snippet"], "E:\\a\\계약 안내.hwp 본문 없음")

    def test_index_hit_has_the_v1_hit_shape(self) -> None:
        row = {
            "collection": "artifacts",
            "kind": "windows-execution",
            "locator": "/artifacts/7",
            "artifact_type": "amcache-entry",
            "title": "setup.exe",
            "path": "E:\\root\\Windows\\appcompat\\Programs\\Amcache.hve",
            "ts": "2025-01-02T03:04:05.000Z",
            "ts_kind": "modified",
            "hashes": {"md5": None, "sha1": "a" * 40, "sha256": None},
            "flags": {"deleted": False},
            "snippet": {"text": "…c:\\program files (x86)\\samsungprinterliveupdateinstaller\\setup.exe…", "marks": [[40, 50]]},
            "matched": [{"term": "liveupdate", "field": "kw"}],
            "fields": {"name": "setup.exe"},
        }
        hit = index_hit(row, root="E:\\root", keywords=["liveupdate"])
        self.assertEqual(hit["source"], "artifacts")
        self.assertEqual(hit["pointer"], "/artifacts/7")
        self.assertEqual(hit["display_path"], "Windows\\appcompat\\Programs\\Amcache.hve")
        self.assertEqual(hit["artifact_type"], "amcache-entry")
        self.assertEqual(hit["title"], "setup.exe")
        self.assertEqual(hit["timestamp"], "2025-01-02T03:04:05.000Z")
        self.assertEqual(hit["locator"], {"collection": "artifacts", "kind": "windows-execution", "pointer": "/artifacts/7", "record_index": 7, "output_index": 7, "output_name": "artifacts_windows-execution"})
        self.assertIn("liveupdate", hit["snippet"].casefold())
        start, end = hit["snippet_highlights"][0]
        self.assertEqual(hit["snippet"][start:end].casefold(), "liveupdate")
        self.assertEqual(hit["metadata"]["sha1"], "a" * 40)
        self.assertEqual(hit["matched_keywords"], ["liveupdate"])
        browser = index_hit({**row, "kind": "browser", "locator": "/artifacts/1"}, root="", keywords=["x"])
        self.assertEqual(browser["source"], "web")
        files = index_hit({"collection": "files", "kind": "", "locator": "/candidates/3", "path": "E:\\root\\a\\b.txt", "title": "b.txt", "fields": {"categories": "documents, archives"}, "snippet": {"text": "b.txt"}}, root="E:\\root", keywords=["b.txt"])
        self.assertEqual((files["source"], files["kind"], files["locator"]["collection"]), ("files", "documents,archives", "files"))
        self.assertEqual(files["snippet"], "E:\\root\\a\\b.txt")  # v1: a file hit's snippet is its path
        docs = index_hit({"collection": "docs", "kind": "", "locator": "/candidates/2", "path": "E:\\d.docx", "title": "d.docx", "fields": {"kind": "docx"}, "snippet": {"text": "계약서 본문"}}, root="", keywords=["계약"], docs_results={"E:\\d.docx": 5})
        self.assertEqual((docs["source"], docs["kind"], docs["pointer"]), ("documents", "docx", "/results/5"))
        self.assertEqual(docs["locator"]["pointer"], "/candidates/2")
        indicator = index_hit({"collection": "indicators", "kind": "", "locator": "/indicators/4", "artifact_type": "indicator-url", "title": "url: http://x", "snippet": {"text": "http://x"}}, root="", keywords=["http"])
        self.assertEqual((indicator["source"], indicator["kind"], indicator["locator"]["collection"]), ("indicators", "url", "indicators"))


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for search API tests")
class ConsoleSearchApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(SEARCH_HISTORY.flush)
        base = Path(self.temp.name)
        env = mock.patch.dict(os.environ, {DATA_DIR_ENV: str(base / "data"), AUTO_INDEX_ENV: "0"})
        env.start()
        self.addCleanup(env.stop)
        self.fixture = build_fixture_run(base)
        self.run_dir = Path(self.fixture["run_dir"])
        self.store = RunJobStore()
        self.run_id = self.store.import_completed_run(self.run_dir).run_id
        self.app = create_app(self.store, auth_token=TOKEN)
        self.client = TestClient(self.app, headers={"X-RapidTriage-Token": TOKEN})
        self.addCleanup(lambda: ANALYSIS_RUNNER.shutdown(owner=self.app.state.analysis_owner))

    def url(self, suffix: str) -> str:
        return f"/api/runs/{self.run_id}{suffix}"

    def build_index(self) -> None:
        response = self.client.post(self.url("/search/index/build"), json={"mode": "full"})
        self.assertEqual(response.status_code, 202, response.text)
        analysis_id = response.json()["analysis_id"]
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            state = self.client.get(self.url(f"/analyses/{analysis_id}")).json()
            if state["status"] in TERMINAL_STATUSES:
                self.assertEqual(state["status"], "completed", state)
                return
            time.sleep(0.1)
        self.fail("index build did not finish")

    def console(self, keywords: list[str], **page: object) -> dict:
        response = self.client.post(self.url("/search/query"), json={"keywords": keywords, "page": page, "aggregates": False, "facets": False})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def v1(self, keywords: list[str]) -> dict:
        query = "&".join(f"keyword={word}" for word in keywords)
        response = self.client.get(self.url(f"/search?{query}&limit=1000"))
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    @staticmethod
    def key(hit: dict) -> tuple[str, str, str]:
        locator = hit.get("locator") or {}
        return str(locator.get("collection") or hit.get("source")), str(locator.get("kind") or ""), str(locator.get("pointer") or hit.get("pointer"))

    def test_no_index_is_404_and_bad_bodies_are_400(self) -> None:
        self.assertEqual(self.client.get(self.url("/search/index")).json()["status"], "none")
        self.assertEqual(self.client.post(self.url("/search/query"), json={"keywords": ["급여"]}).status_code, 404)
        self.build_index()
        both = self.client.post(self.url("/search/query"), json={"q": "급여", "keywords": ["급여"]})
        self.assertEqual(both.status_code, 400)
        self.assertEqual(both.json()["detail"], "q와 keywords 중 하나만 주세요")
        empty = self.client.post(self.url("/search/query"), json={"keywords": ["  "]})
        self.assertEqual(empty.status_code, 400)
        too_many = self.client.post(self.url("/search/query"), json={"keywords": [f"x{index}" for index in range(33)]})
        self.assertEqual(too_many.status_code, 422)
        # R7 S3 confirmation: a Korean reason, not pydantic's English list message.
        self.assertEqual(too_many.json()["detail"], "검색어는 32개까지 사용할 수 있습니다 (받은 수: 33)")
        self.assertEqual(self.client.post(self.url("/search/query"), json={"keywords": [f"x{index}" for index in range(32)]}).status_code, 200)

    def test_console_hits_match_v1_shape_and_set(self) -> None:
        self.build_index()
        before = sorted(str(path.relative_to(self.run_dir)) for path in self.run_dir.rglob("*"))
        for keywords in (["급여"], ["AnyDesk"], ["anydesk", "급여"], ["zzqxnotfound"]):
            with self.subTest(keywords=keywords):
                v2 = self.console(keywords, limit=1000)
                v1 = self.v1(keywords)
                self.assertNotIn("rows", v2)
                self.assertEqual(v2["backend"], "index")
                self.assertEqual(v2["keywords"], console_keywords(keywords))
                for hit in v2["matches"]:
                    self.assertLessEqual(HIT_FIELDS, set(hit), hit)
                    self.assertEqual(hit["locator"]["run_id"], self.run_id)
                    self.assertEqual(hit["preview"], hit["snippet"])
                if v1["matches"] and v2["matches"]:
                    self.assertEqual(set(v1["matches"][0]) - {"search_match"}, set(v2["matches"][0]) - {"search_match"})
                v1_keys = {self.key(hit) for hit in v1["matches"] if hit["source"] != "timeline"}
                v2_keys = {self.key(hit) for hit in v2["matches"]}
                self.assertLessEqual(v1_keys, v2_keys, keywords)
                if keywords != ["zzqxnotfound"]:
                    self.assertTrue(v1_keys, keywords)  # the comparison is not vacuous
                # The same row reads alike: source, kind, pointer and the full / displayed path.
                by_key = {self.key(hit): hit for hit in v2["matches"]}
                for hit in v1["matches"]:
                    other = by_key.get(self.key(hit))
                    if other is None:
                        continue
                    for name in ("source", "kind", "pointer", "path", "display_path"):
                        self.assertEqual(hit.get(name), other.get(name), (name, self.key(hit)))
        # The console's search writes nothing into the run folder (no search history).
        SEARCH_HISTORY.flush()
        after = sorted(str(path.relative_to(self.run_dir)) for path in self.run_dir.rglob("*"))
        self.assertEqual(before, after)
        self.assertFalse((self.run_dir / "search").exists())

    def test_cursor_pages_number_hits_like_v1_offsets(self) -> None:
        self.build_index()
        whole = self.console(["bsh"], limit=1000)["matches"]
        self.assertGreater(len(whole), 2)
        first = self.console(["bsh"], limit=2)
        self.assertEqual([hit["search_result_id"] for hit in first["matches"]], ["search-hit-000001", "search-hit-000002"])
        cursor = first["page"]["next_cursor"]
        self.assertTrue(cursor)
        second = self.console(["bsh"], limit=2, cursor=cursor, offset=2)
        self.assertEqual(second["matches"][0]["search_result_id"], "search-hit-000003")
        keys = [self.key(hit) for hit in first["matches"] + second["matches"]]
        self.assertEqual(keys, [self.key(hit) for hit in whole[:4]])
        self.assertEqual(len(set(keys)), len(keys))


if __name__ == "__main__":
    unittest.main()
