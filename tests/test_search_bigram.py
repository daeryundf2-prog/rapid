"""R7 S2: 2-character non-ASCII keywords use the ``search_bigram`` table (index v3).

The bigram path must return exactly the rows of the ``instr`` scan it replaces;
a v2 index (no table) stays readable, scans, and is reported stale.
"""

from __future__ import annotations

import contextlib
import json
import random
import shutil
import sqlite3
import tempfile
import unicodedata
import unittest
from pathlib import Path

from rapidtriage.core.search_index.build import (
    build_search_index,
    index_meta,
    stale_reasons,
)
from rapidtriage.core.search_index.engine import Budget, QueryRequest, run_query
from rapidtriage.core.search_index.query import (
    SHORT_ONE_WARNING,
    SHORT_TWO_WARNING,
    parse_query,
)
from rapidtriage.core.search_index.schema import (
    BIGRAM_RULE,
    INDEX_FILE_NAME,
    INDEX_VERSION,
)
from rapidtriage.core.search_index.textutil import bigram_tokens, is_bigram_term
from tests.search_index_fixture import build_fixture_run, write_analysis

SYLLABLES = "계약서근로임금급여대장직원공제퇴직연차휴가보험세금신고"
OLD_INDEX_WARNING = "이전 형식 색인이라 2자 한글 검색어가 전체 본문을 훑습니다(느릴 수 있음). 색인을 다시 만드세요"


def synthetic_run(base: Path, rows: int = 600) -> tuple[Path, dict[str, object]]:
    """A run whose only output is a files list with random Korean/CJK/ASCII names and categories."""
    rng = random.Random(20261027)
    run_dir = base / "synthetic"
    run_dir.mkdir()
    candidates = []
    for index in range(rows):
        words = []
        for _ in range(rng.randint(1, 6)):
            kind = rng.random()
            if kind < 0.6:
                words.append("".join(rng.choice(SYLLABLES) for _ in range(rng.randint(1, 5))))
            elif kind < 0.75:
                words.append(rng.choice(["契約書", "勞動", "東京", "ｶﾀｶﾅ", "é̂", "Ａ１"]))
            else:
                words.append(rng.choice(["LiveUpdate", "report", "ab", "x계y", "2025"]))
        name = rng.choice([" ", "_", "", "-"]).join(words)
        candidates.append({"path": f"C:\\data\\{index}\\{name}.txt", "name": f"{name}.txt", "extension": ".txt", "size": index, "categories": ["documents"]})
    files = run_dir / "rapidtriage-files.json"
    files.write_text(json.dumps({"command": "files", "candidates": candidates, "inventory": []}, ensure_ascii=False), encoding="utf-8")
    return run_dir, {"outputs": {"files": str(files)}}


def locators(index: Path, meta: dict[str, object], q: str, *, collapse: bool = True, aggregates: bool = True) -> tuple[list[str], dict[str, object]]:
    """Every matching locator (paging through all pages)."""
    found: list[str] = []
    cursor: str | None = None
    result: dict[str, object] = {}
    for _page in range(100):
        request = QueryRequest(q=q, cursor=cursor, limit=50, collapse=collapse, aggregates=aggregates, facets=False, histogram=None)
        result = run_query(index, meta, request, budget=Budget(30))
        found.extend(f"{row['collection']}:{row['locator']}" for row in result["rows"])
        cursor = result["page"].get("next_cursor")
        if not cursor:
            break
    return found, result


def scan_meta(meta: dict[str, object]) -> dict[str, object]:
    """The same index read as if it had no bigram table (the scan path)."""
    return {key: value for key, value in meta.items() if key != "bigram"}


class BigramTokenTests(unittest.TestCase):
    def test_pairs(self) -> None:
        self.assertEqual(bigram_tokens("근로계약서"), "계약 근로 로계 약서")
        self.assertEqual(bigram_tokens("a계b 계약 계약"), "계약")  # distinct, ASCII breaks runs
        self.assertEqual(bigram_tokens("plain ascii"), "")
        self.assertEqual(bigram_tokens("가"), "")
        self.assertTrue(is_bigram_term("계약"))
        self.assertFalse(is_bigram_term("계a"))
        self.assertFalse(is_bigram_term("계"))
        self.assertFalse(is_bigram_term("계약서"))

    def test_short_warnings(self) -> None:
        self.assertEqual(parse_query("급여").warnings, [])
        self.assertEqual(parse_query("급").warnings, [SHORT_ONE_WARNING])
        self.assertEqual(parse_query("ab").warnings, [SHORT_TWO_WARNING])
        self.assertEqual(parse_query("a급").warnings, [SHORT_TWO_WARNING])


class BigramEquivalenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        cls.run_dir, cls.summary = synthetic_run(Path(cls.temp.name))
        build_search_index(cls.run_dir, cls.summary, run_id="synthetic")
        cls.index = cls.run_dir / INDEX_FILE_NAME
        cls.meta = index_meta(cls.index)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def queries(self) -> list[str]:
        with contextlib.closing(sqlite3.connect(self.index)) as connection:
            texts = [str(row[0]) for row in connection.execute("SELECT text FROM search_doc WHERE text IS NOT NULL")]
        pairs = sorted({pair for text in texts for pair in bigram_tokens(text).split()})
        rng = random.Random(7)
        chosen = rng.sample(pairs, min(40, len(pairs)))
        return [*chosen, "계약", "근로", "東京", "ｶﾀ", "없음", "뷁뷁", "Ａ１"]

    def test_meta_and_table(self) -> None:
        self.assertEqual(self.meta["index_version"], INDEX_VERSION)
        self.assertEqual(self.meta["bigram"], BIGRAM_RULE)
        self.assertEqual(stale_reasons(self.meta, self.summary, self.run_dir), [])

    def test_bigram_matches_scan(self) -> None:
        old = scan_meta(self.meta)
        nonempty = 0
        for q in self.queries():
            for collapse in (True, False):
                for aggregates in (True, False):  # aggregates=False: the first-page driver path
                    with self.subTest(q=q, collapse=collapse, aggregates=aggregates):
                        fast, result = locators(self.index, self.meta, q, collapse=collapse, aggregates=aggregates)
                        slow, slow_result = locators(self.index, old, q, collapse=collapse, aggregates=aggregates)
                        self.assertEqual(fast, slow)
                        self.assertFalse(result["truncated"])
                        self.assertNotIn(OLD_INDEX_WARNING, result["query"]["parsed"]["warnings"])
                        self.assertIn(OLD_INDEX_WARNING, slow_result["query"]["parsed"]["warnings"])
                        nonempty += bool(fast)
        self.assertGreater(nonempty, 100)

    def test_compound_queries_match_scan(self) -> None:
        old = scan_meta(self.meta)
        for q in ("계약 근로", "계약 OR 東京", "계약 -근로", "word:계약", "계약 LiveUpdate", "(계약 OR 급여) in:files", unicodedata.normalize("NFC", "계약")):
            with self.subTest(q=q):
                self.assertEqual(locators(self.index, self.meta, q)[0], locators(self.index, old, q)[0])

    def test_short_terms_still_scan(self) -> None:
        for q, warning in (("계", SHORT_ONE_WARNING), ("ab", SHORT_TWO_WARNING), ("x계", SHORT_TWO_WARNING)):
            with self.subTest(q=q):
                found, result = locators(self.index, self.meta, q)
                self.assertIn(warning, result["query"]["parsed"]["warnings"])
                self.assertEqual(found, locators(self.index, scan_meta(self.meta), q)[0])
        self.assertGreater(len(locators(self.index, self.meta, "계")[0]), 0)


class BigramMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.fixture = build_fixture_run(Path(self.temp.name))
        self.run_dir = self.fixture["run_dir"]
        self.summary = self.fixture["summary"]
        self.index = self.run_dir / INDEX_FILE_NAME
        build_search_index(self.run_dir, self.summary, run_id="fixture")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def bigram_rows(self, token: str) -> int:
        with contextlib.closing(sqlite3.connect(self.index)) as connection:
            return int(connection.execute("SELECT COUNT(*) FROM search_bigram WHERE search_bigram MATCH ?", (f'"{token}"',)).fetchone()[0])

    def test_v2_index_is_readable_and_stale(self) -> None:
        old = self.run_dir / "old.db"
        shutil.copyfile(self.index, old)
        with contextlib.closing(sqlite3.connect(old)) as connection:
            connection.execute("DROP TABLE search_bigram")
            connection.execute("UPDATE search_meta SET value = 'search-index-v2' WHERE key = 'index_version'")
            connection.execute("DELETE FROM search_meta WHERE key = 'bigram'")
            connection.commit()
        meta = index_meta(old)
        reasons = stale_reasons(meta, self.summary, self.run_dir)
        self.assertEqual(reasons[0], "2자 한글 검색용 색인(bigram)이 없는 이전 형식입니다. 색인을 다시 만드세요")
        result = run_query(old, meta, QueryRequest(q="급여"), budget=Budget(15))
        self.assertEqual(result["page"]["total"], 4)
        self.assertIn(OLD_INDEX_WARNING, result["query"]["parsed"]["warnings"])
        fresh = run_query(self.index, index_meta(self.index), QueryRequest(q="급여"), budget=Budget(15))
        self.assertEqual([row["locator"] for row in fresh["rows"]], [row["locator"] for row in result["rows"]])
        # An incremental update of a v2 index rebuilds it whole (with the bigram table).
        target = self.run_dir / INDEX_FILE_NAME
        shutil.copyfile(old, target)
        built = build_search_index(self.run_dir, self.summary, mode="incremental", analysis_ids=["x"])
        self.assertEqual(built["mode"], "full")
        self.assertEqual(index_meta(target)["bigram"], BIGRAM_RULE)

    def test_incremental_keeps_bigrams_in_step(self) -> None:
        analysis = "20251014T000000-bbbbbbbb"
        write_analysis(self.run_dir, analysis, "ntfs-meta", [
            {"artifact_type": "ntfs-meta-row", "path": "C:\\x\\뷁뷀계약.txt", "details": {"path": "\\x\\뷁뷀계약.txt", "in_use": True}},
        ])
        build_search_index(self.run_dir, self.summary, mode="incremental", analysis_ids=[analysis])
        self.assertEqual(self.bigram_rows("뷁뷀"), 1)
        build_search_index(self.run_dir, self.summary, mode="incremental", analysis_ids=[analysis])
        self.assertEqual(self.bigram_rows("뷁뷀"), 1)  # replaced, not duplicated
        shutil.rmtree(self.run_dir / "analyses" / analysis)
        write_analysis(self.run_dir, analysis, "ntfs-meta", [
            {"artifact_type": "ntfs-meta-row", "path": "C:\\x\\other.txt", "details": {"path": "\\x\\other.txt", "in_use": True}},
        ])
        build_search_index(self.run_dir, self.summary, mode="incremental", analysis_ids=[analysis])
        self.assertEqual(self.bigram_rows("뷁뷀"), 0)  # the old row's pairs were deleted
        meta = index_meta(self.index)
        self.assertEqual(run_query(self.index, meta, QueryRequest(q="뷁뷀"), budget=Budget(15))["page"]["total"], 0)


if __name__ == "__main__":
    unittest.main()
