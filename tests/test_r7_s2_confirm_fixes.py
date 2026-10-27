"""R7 stage 2 confirmation pass: regressions found after the review fixes.

Each test class names the confirmation finding it guards.
"""

from __future__ import annotations

import time
import unittest
from typing import ClassVar


class CredentialMaskSpeedTest(unittest.TestCase):
    """S2: credential masking was quadratic on long alphanumeric runs (v1 search 10x slower)."""

    def test_long_alphanumeric_leaf_masks_fast(self) -> None:
        from rapidtriage.core.search_hits import redact_text

        for text in ("a" * 65536 + "=1", "=" + "Ab0_.-" * 11000, "x=" + "a" * 65536, "token" * 13000 + "=v"):
            started = time.perf_counter()
            redact_text(text)
            elapsed = time.perf_counter() - started
            self.assertLess(elapsed, 0.05, (text[:20], elapsed))

    def test_record_with_many_long_leaves_snippet_is_fast(self) -> None:
        from rapidtriage.core.search_hits import search_snippet

        record = {"details": {f"k{index}": "b" * 16000 + "=" for index in range(40)} | {"hit": "근로 token=abc"}}
        started = time.perf_counter()
        snippet, _ = search_snippet(record, ["근로"])
        self.assertLess(time.perf_counter() - started, 0.5)
        self.assertEqual(snippet, "hit: 근로 token=[가림]")

    def test_masking_semantics_kept(self) -> None:
        from rapidtriage.core.search_hits import redact_text

        cases = {
            "…token=abc def": "…token=[가림] def",
            'Version=4.0, PublicKeyToken=b77a5c561934e089"': 'Version=4.0, PublicKeyToken=[가림]"',
            "a&rpctoken=123&b=1": "a&rpctoken=[가림]&b=1",
            "Endpoint=sb://x/;SharedAccessKeyName=k;SharedAccessToken=sasKey99": "Endpoint=sb://x/;SharedAccessKeyName=k;SharedAccessToken=[가림]",
            "db_password=hunter2 next": "db_password=[가림] next",
            "x-api-key=K1 my.secret='s p' API_KEY=\"q\"": "x-api-key=K1 my.secret=[가림] API_KEY=[가림]",
            "user pwd=p1 passwd=p2)": "user pwd=[가림] passwd=[가림])",
            "https://user:pw@host/x": "https://[가림]@host/x",
            ("v" * 200) + "token=abc": ("v" * 200) + "token=[가림]",
            "tokenizer=abc keyword=1": "tokenizer=abc keyword=1",
            "plain text": "plain text",
        }
        for text, expected in cases.items():
            self.assertEqual(redact_text(text), expected, text)

    def test_keyword_only_inside_a_masked_value_does_not_select_the_leaf(self) -> None:
        from rapidtriage.core.search_hits import search_snippet

        record = {"details": {"a": "token=secretword", "b": "the secretword note"}}
        snippet, _ = search_snippet(record, ["secretword"])
        self.assertEqual(snippet, "b: the secretword note")
        snippet, _ = search_snippet({"details": {"a": "token=secretword"}}, ["secretword"])
        self.assertEqual(snippet, "a: token=[가림]")


class IndexHitTitleTest(unittest.TestCase):
    """#10: v2 artifact/web hits get v1's summary title (case DB summary, else compact fields)."""

    ROW: ClassVar[dict[str, object]] = {
        "collection": "artifacts",
        "kind": "browser",
        "locator": "/artifacts/0",
        "artifact_type": "browser-history-downloads",
        "title": "History",
        "path": "\\Users\\u\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History",
        "fields": {"url": "https://example.test/download"},
        "snippet": {"text": "History https://example.test/download"},
    }

    def test_case_db_summary_wins(self) -> None:
        from rapidtriage.core.search_index.hits import index_hit

        hit = index_hit(self.ROW, root="E:", keywords=["example"], summaries={("browser", "/artifacts/0"): "ChatGPT"})
        self.assertEqual(hit["title"], "ChatGPT")
        # A summary that is only the path: the file name, like v1.
        hit = index_hit(self.ROW, root="E:", keywords=["example"], summaries={("browser", "/artifacts/0"): "E:" + str(self.ROW["path"])})
        self.assertEqual(hit["title"], "History")

    def test_bare_file_name_without_case_db_uses_compact_fields(self) -> None:
        from rapidtriage.core.search_index.hits import index_hit

        self.assertEqual(index_hit(self.ROW, root="E:", keywords=["example"])["title"], "https://example.test/download")
        titled = {**self.ROW, "title": "Page title"}
        self.assertEqual(index_hit(titled, root="E:", keywords=["example"])["title"], "Page title")

    def test_archive_entry_keeps_its_entry_name(self) -> None:
        from rapidtriage.core.search_index.hits import artifact_summary_keys, index_hit

        entry = {**self.ROW, "kind": "generic-documents", "artifact_type": "archive-entry", "locator": "/artifacts/3#entry:1",
                 "title": "a.jpg", "fields": {"entry_path": "a.jpg"}}
        hit = index_hit(entry, root="E:", keywords=["example"], summaries={("generic-documents", "/artifacts/3#entry:1"): "x.zip"})
        self.assertEqual(hit["title"], "a.jpg")
        self.assertEqual(artifact_summary_keys([entry, self.ROW]), [("browser", "/artifacts/0")])


class ConsoleTitleApiTest(unittest.TestCase):
    """#10 end to end: same row, same title in v1 GET /search and the v2 console search."""

    def test_v2_titles_equal_v1(self) -> None:
        import json
        import os
        import tempfile
        from pathlib import Path
        from unittest import mock

        try:
            from fastapi.testclient import TestClient

            from rapidtriage.api.app import create_app
            from rapidtriage.api.app.analyses import ANALYSIS_RUNNER, TERMINAL_STATUSES
            from rapidtriage.api.app.search_index_service import (
                AUTO_INDEX_ENV,
                SEARCH_HISTORY,
            )
        except ImportError:  # pragma: no cover
            self.skipTest("fastapi is required")
        from rapidtriage.core.jobs import RunJobStore
        from rapidtriage.core.run.persist import build_run_case_db
        from rapidtriage.core.search_index.hashsets import DATA_DIR_ENV
        from tests.search_index_fixture import build_fixture_run, write_kind

        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.addCleanup(SEARCH_HISTORY.flush)
        base = Path(temp.name)
        env = mock.patch.dict(os.environ, {DATA_DIR_ENV: str(base / "data"), AUTO_INDEX_ENV: "0"})
        env.start()
        self.addCleanup(env.stop)
        fixture = build_fixture_run(base)
        run_dir = Path(fixture["run_dir"])
        evidence = Path(fixture["evidence"])
        history = str(evidence / "Users" / "bsh" / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default" / "History")
        browser_rows = [
            {"provider": "browser", "artifact_type": "browser-history", "path": history,
             "details": {"url": "https://pay.example.test/급여명세", "title": "급여 명세 페이지", "visit_time": "2025-05-01T00:00:00Z"}},
            {"provider": "browser", "artifact_type": "browser-history-downloads", "path": history,
             "details": {"summary": "급여 다운로드 기록", "visit_time": "2025-05-02T00:00:00Z"}},
        ]
        summary = dict(fixture["summary"])  # type: ignore[arg-type]
        summary["outputs"] = {**summary["outputs"], "artifacts_browser": str(write_kind(run_dir, "browser", browser_rows))}
        Path(fixture["summary_path"]).write_text(json.dumps(summary, ensure_ascii=False), encoding="utf-8")
        build_run_case_db(run_dir, summary["outputs"], root=str(evidence))
        store = RunJobStore()
        run_id = store.import_completed_run(run_dir).run_id
        app = create_app(store, auth_token="r7s2c-token")
        self.addCleanup(lambda: ANALYSIS_RUNNER.shutdown(owner=app.state.analysis_owner))
        client = TestClient(app, headers={"X-RapidTriage-Token": "r7s2c-token"})
        response = client.post(f"/api/runs/{run_id}/search/index/build", json={"mode": "full"})
        self.assertEqual(response.status_code, 202, response.text)
        analysis_id = response.json()["analysis_id"]
        deadline = time.monotonic() + 300
        while client.get(f"/api/runs/{run_id}/analyses/{analysis_id}").json()["status"] not in TERMINAL_STATUSES:
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.1)

        def key(hit: dict) -> tuple[str, str, str]:
            locator = hit.get("locator") or {}
            return str(locator.get("collection")), str(locator.get("kind") or ""), str(locator.get("pointer"))

        compared = []
        for keywords in (["급여"], ["bsh"], ["AnyDesk"]):
            v1 = client.get(f"/api/runs/{run_id}/search?" + "&".join(f"keyword={word}" for word in keywords) + "&limit=1000").json()["matches"]
            v2 = client.post(f"/api/runs/{run_id}/search/query", json={"keywords": keywords, "page": {"limit": 250}, "aggregates": False, "facets": False}).json()["matches"]
            by_key = {key(hit): hit for hit in v2}
            for hit in v1:
                other = by_key.get(key(hit))
                if other is not None and hit["source"] in {"artifacts", "web"}:
                    compared.append((key(hit), hit["title"], other["title"]))
        mismatches = [row for row in compared if row[1] != row[2]]
        self.assertEqual(mismatches, [])
        titles = {row[1] for row in compared}
        self.assertIn("https://pay.example.test/급여명세", titles)
        self.assertIn("급여 다운로드 기록", titles)


if __name__ == "__main__":
    unittest.main()
