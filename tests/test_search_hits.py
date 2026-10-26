"""R7: unified search hits are readable rows with a resolvable review locator.

Artifact hits used to show ``compact_json_preview(record)`` (``{"artifact_record": ...``)
as their text, the raw artifact type as their title, no time, and document hits
outside the docs-index results had no pointer, so review marks from the search
grid failed ("출처 위치를 알 수 없는 행"). Every hit now carries ``title``,
``display_path`` (acquisition root stripped), ``artifact_type``, ``timestamp``,
``snippet`` (<= 200 chars, never the record JSON) and a ``locator`` the case DB
resolves to the source row.
"""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from rapidtriage.api.app.run_review import RunLocatorIndex
from rapidtriage.core.run import run_triage_mode
from rapidtriage.core.run.persist import CASE_DB_FILE_NAME
from rapidtriage.core.search import run_unified_search
from rapidtriage.core.search_hits import (
    SNIPPET_LIMIT,
    display_path,
    finalize_search_hit,
    hit_locator,
    search_snippet,
)
from tests.test_rapidtriage_run import build_run_fixture

REQUIRED = ("title", "path", "display_path", "kind", "artifact_type", "timestamp", "snippet", "locator")


class SearchHitFieldTests(unittest.TestCase):
    def test_display_path_strips_root_case_insensitively(self) -> None:
        root = r"D:\rapid-qa\bsh-subset"
        self.assertEqual(
            display_path(r"d:\RAPID-QA\bsh-subset\Users\user\Desktop\병원문서\a.hwp", root),
            r"Users\user\Desktop\병원문서\a.hwp",
        )
        self.assertEqual(display_path(r"D:\rapid-qa\bsh-subset-2\x.txt", root), r"D:\rapid-qa\bsh-subset-2\x.txt")
        self.assertEqual(display_path("/mnt/case/Users/a.txt", "/mnt/case/"), "Users/a.txt")
        self.assertEqual(display_path("", root), "")

    def test_snippet_is_bounded_and_highlighted(self) -> None:
        text = "가" * 500 + " 병원 기록 " + "나" * 500
        snippet, spans = search_snippet(text, ["병원"])
        self.assertLessEqual(len(snippet), SNIPPET_LIMIT)
        self.assertTrue(snippet.startswith("…") and snippet.endswith("…"))
        self.assertEqual(len(spans), 1)
        start, end = spans[0]
        self.assertEqual(snippet[start:end], "병원")

    def test_artifact_record_snippet_is_evidence_text_not_json(self) -> None:
        record = {
            "artifact_record": {"artifact_id": "artifact-1", "artifact_type": "browser-history", "notes": "chatgpt"},
            "artifact_type": "browser-history",
            "details": {"url": "https://chatgpt.com/c/1", "title": "ChatGPT 대화", "last_visited_at": "2025-05-19T13:31:08Z"},
            "path": r"D:\root\Users\u\History",
            "source_locator": {"output_name": "artifacts_browser", "row_index": 3},
        }
        hit = finalize_search_hit(
            {
                "source": "web",
                "kind": "browser",
                "path": record["path"],
                "title": "browser-history",
                "matched_keywords": ["ChatGPT"],
                "preview": '{"artifact_record": {...}}',
                "pointer": "/artifacts/3",
                "metadata": record,
            },
            root=r"D:\root",
        )
        for key in REQUIRED:
            self.assertIn(key, hit)
        self.assertFalse(hit["snippet"].startswith("{"))
        self.assertNotIn("artifact_record", hit["snippet"])
        self.assertEqual(hit["preview"], hit["snippet"])
        self.assertIn("chatgpt", hit["snippet"].lower())
        self.assertEqual(hit["artifact_type"], "browser-history")
        self.assertEqual(hit["timestamp"], "2025-05-19T13:31:08Z")
        self.assertEqual(hit["display_path"], r"Users\u\History")
        self.assertNotEqual(hit["title"], "browser-history")
        self.assertEqual(
            hit["locator"],
            {
                "collection": "artifacts",
                "kind": "browser",
                "pointer": "/artifacts/3",
                "record_index": 3,
                "output_index": 3,
                "output_name": "artifacts_browser",
                "artifact_id": "artifact-1",
            },
        )

    def test_locator_is_none_without_a_source_row(self) -> None:
        self.assertIsNone(hit_locator({"source": "documents", "kind": "pdf", "pointer": ""}))
        self.assertIsNone(hit_locator({"source": "artifacts", "kind": "", "pointer": "/artifacts/1"}))


class SearchHitRunTests(unittest.TestCase):
    """Artifact, document and file hits of a real (fixture) run, both backends."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        tmp = Path(cls._tmp.name)
        cls.root = tmp / "case-root"
        cls.root.mkdir()
        build_run_fixture(cls.root)
        cls.output_dir = tmp / "run-out"
        cls.summary = run_triage_mode(cls.root, mode="fraud", output_dir=cls.output_dir)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def search(self, **kwargs):
        return run_unified_search(
            self.summary, ["powershell"], include_ocr=False, include_analysis=False, limit=500, **kwargs
        )

    def assert_hits(self, payload) -> None:
        self.assertEqual(Path(payload["root"]), Path(self.summary["scan_scope_root"]))
        sources = {match["source"] for match in payload["matches"]}
        self.assertTrue({"documents", "files", "artifacts"} <= sources, sources)
        db = self.output_dir.resolve() / CASE_DB_FILE_NAME
        connection = sqlite3.connect(db)
        connection.row_factory = sqlite3.Row
        try:
            case_id = connection.execute("SELECT case_id FROM case_record ORDER BY rowid DESC LIMIT 1").fetchone()[0]
            index = RunLocatorIndex(connection, case_id, self.summary["outputs"], output_dir=self.output_dir.resolve())
            for match in payload["matches"]:
                for key in REQUIRED:
                    self.assertIn(key, match)
                self.assertLessEqual(len(match["snippet"]), SNIPPET_LIMIT)
                self.assertFalse(match["snippet"].lstrip().startswith("{"), match["snippet"])
                self.assertFalse(match["preview"].lstrip().startswith("{"), match["preview"])
                self.assertFalse(match["title"].lstrip().startswith("{"), match["title"])
                self.assertFalse(Path(match["display_path"]).is_absolute(), match["display_path"])
                locator = match["locator"]
                self.assertIsInstance(locator, dict, match)
                resolved = index.resolve(locator["collection"], locator["pointer"], locator["kind"])
                self.assertIsNotNone(resolved, locator)
                if match["source"] in {"artifacts", "web"}:
                    self.assertTrue(match["artifact_type"])
                    self.assertTrue(locator.get("artifact_id"))
                if match["source"] in {"files", "documents"}:
                    self.assertTrue(match["timestamp"], match["path"])
        finally:
            connection.close()

    def test_index_backend_hits(self) -> None:
        payload = self.search()
        self.assertEqual(payload["backend"], "fts")
        self.assert_hits(payload)

    def test_scan_backend_hits(self) -> None:
        payload = self.search(use_case_db=False, scan_budget_seconds=0)
        self.assertEqual(payload["backend"], "scan")
        self.assert_hits(payload)


if __name__ == "__main__":
    unittest.main()
