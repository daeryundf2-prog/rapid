"""R7 stage 2 adversarial review (docs/research/search-adversarial-review-r7s2-2026-10-27.md): backend fixes.

Each test class names the review finding it guards.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unicodedata
import unittest
from pathlib import Path

from rapidtriage.core.search import run_unified_search
from rapidtriage.core.search_index.build import build_search_index, index_meta, stale_reasons
from rapidtriage.core.search_index.engine import Budget, QueryRequest, run_query
from rapidtriage.core.search_index.hits import attach_console_hits, console_keywords, console_query
from rapidtriage.core.search_index.schema import FOLD_RULE, INDEX_VERSION
from rapidtriage.core.search_index.textutil import stored_fold


def NFD(text: str) -> str:
    return unicodedata.normalize("NFD", text)


# The review's synthetic corpus: Korean/CJK/full-width/combining/mixed ASCII file names.
SYNTHETIC_NAMES = [
    "근로계약서_2024.docx", NFD("계약서_NFD.hwp"), "ÉCOLE_upper.txt", "école_lower.txt", "Straße_report.pdf",
    "Ａ１_fullwidth.txt", "ａ１_fullwidth_small.txt", "a계b.txt", "계a.txt", "😀😃_emoji.txt", "😀x😃.txt",
    "가_jamo.txt", "가_syllable.txt", 'quote"inside.txt', "back\\slash.txt", "a.b_dot.txt", "(paren).txt",
    "100%_pct.txt", "under_score.txt", "LiveUpdate.exe", "liveupdate_lower.exe", "契約書_cjk.txt", "ｶﾀｶﾅ_half.txt",
    "Ümlaut_UPPER.txt", "ümlaut_lower.txt", "ΑΒΓ_greek_upper.txt", "αβγ_greek_lower.txt", "ПРИВЕТ_cyr.txt", "привет_cyr.txt",
    "x" * 300 + "_long.txt", "계_single.txt", "ab_two.txt", "계약 근로 둘다.txt", "tab\tname.txt",
]
# Case/fold variants (finding #2): v1 (NFC + casefold) and v2 must return the same rows.
CASE_CASES = [
    ["école"], ["ÉCOLE"], ["ss"], ["straße"], ["STRASSE"], ["Straße"], ["ａ１"], ["Ａ１"], ["ümlaut"], ["ÜMLAUT"],
    ["αβγ"], ["ΑΒΓ"], ["привет"], ["ПРИВЕТ"], ["liveupdate"], ["LIVEUPDATE"], ["LiveUpdate"], ["ｶﾀ"],
    ["계약"], [NFD("계약")], ["계약서"], ["가"], [NFD("가")], ["契約"], ["a계"], ["계a"], ["😀😃"], ["😀"],
]
# Every case of the review's table (52) -- the haystack ones (#15) included.
ALL_CASES = [
    ["계약"], [NFD("계약")], ["계약서"], ["école"], ["ÉCOLE"], ["ss"], ["straße"], ["ａ１"], ["Ａ１"], ["a계"], ["계a"], ["😀😃"], ["😀"],
    ["가"], ["가"], [NFD("가")], ['"'], ['quote"inside'], ["\\"], ["back\\slash"], ["a.b"], ["(paren)"], ["%"], ["100%"], ["_"], ["under_score"],
    ["liveupdate"], ["LIVEUPDATE"], ["契約"], ["ｶﾀ"], ["ümlaut"], ["ÜMLAUT"], ["αβγ"], ["ΑΒΓ"], ["привет"], ["ПРИВЕТ"], ["x" * 300], ["x" * 5000],
    ["계"], ["ab"], ["계약", "근로"], ["zzz"], ["계약", "계약"], ["a b"], ["계약 근로"], ["tab\tname"], ["name.txt"], ["E:\\root"], ["users\\u"],
    ["STRASSE"], ["Straße"], ["LiveUpdate"],
]


class SyntheticRun:
    """The review's synthetic files run, its v4 index, and v1-scan / v2-console searches over it."""

    def __init__(self, base: Path, names: list[str] = SYNTHETIC_NAMES) -> None:
        self.run = base / "run"
        self.run.mkdir()
        candidates = [
            {"path": f"E:\\root\\Users\\u\\{name}", "name": name, "extension": ".txt", "size": index, "categories": ["documents"], "modified_at": "2025-01-01T00:00:00Z"}
            for index, name in enumerate(names)
        ]
        files = self.run / "rapidtriage-files.json"
        files.write_text(json.dumps({"command": "files", "candidates": candidates, "inventory": []}, ensure_ascii=False), encoding="utf-8")
        self.summary = {
            "outputs": {"files": str(files), "summary": str(self.run / "rapidtriage-run-summary.json")},
            "output_dir": str(self.run),
            "root": "E:\\root",
            "scan_scope_root": "E:\\root",
        }
        (self.run / "rapidtriage-run-summary.json").write_text(json.dumps(self.summary, ensure_ascii=False), encoding="utf-8")
        self.index = base / "idx.db"
        build_search_index(self.run, self.summary, index_path=self.index, run_id="syn")
        self.meta = index_meta(self.index)

    def v1(self, keywords: list[str], **options: object) -> list[tuple[str, str]]:
        payload = run_unified_search(
            self.run, keywords, include_ocr=False, limit=1000, detail=False, metadata="compact", use_case_db=False, search_mode="exact", **options
        )
        return sorted((hit["source"], hit["pointer"]) for hit in payload["matches"])

    def v2_hits(self, keywords: list[str]) -> list[dict[str, object]]:
        folded = console_keywords(keywords)
        result = run_query(self.index, self.meta, QueryRequest(q=console_query(folded), limit=1000, aggregates=False, facets=False, histogram=None), budget=Budget(30))
        attach_console_hits(result, folded, summary=self.summary, run_id="syn", offset=0)
        return result["matches"]

    def v2(self, keywords: list[str]) -> list[tuple[str, str]]:
        return sorted((hit["source"], hit["pointer"]) for hit in self.v2_hits(keywords))


class SyntheticCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._previous = os.environ.get("RAPIDTRIAGE_INDEX_PERSIST")
        os.environ["RAPIDTRIAGE_INDEX_PERSIST"] = "0"
        cls.base = Path(tempfile.mkdtemp(prefix="r7s2-review-"))
        cls.syn = SyntheticRun(cls.base)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.base, ignore_errors=True)
        if cls._previous is None:
            os.environ.pop("RAPIDTRIAGE_INDEX_PERSIST", None)
        else:
            os.environ["RAPIDTRIAGE_INDEX_PERSIST"] = cls._previous


class NonAsciiCaseFoldingTest(SyntheticCase):
    """#2: É/Ａ/Greek/Cyrillic capitals and ß~ss match like v1's NFC + casefold."""

    def test_index_is_v4_with_fold_rule(self) -> None:
        self.assertEqual(self.syn.meta["index_version"], INDEX_VERSION)
        self.assertEqual(self.syn.meta["fold"], FOLD_RULE)

    def test_case_variants_equal_v1_scan(self) -> None:
        for keywords in CASE_CASES:
            with self.subTest(keywords=keywords):
                expected = self.syn.v1(keywords)
                self.assertEqual(self.syn.v2(keywords), expected)
        # The variants really find the other case (not two empty sets).
        self.assertEqual(len(self.syn.v2(["ÉCOLE"])), 2)
        self.assertEqual(len(self.syn.v2(["STRASSE"])), 1)
        self.assertEqual(len(self.syn.v2(["Ａ１"])), 2)
        self.assertEqual(len(self.syn.v2(["ΑΒΓ"])), 2)

    def test_snippet_highlights_a_length_changing_fold(self) -> None:
        hits = self.syn.v2_hits(["STRASSE"])
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["title"], "Straße_report.pdf")

    def test_stored_fold_only_where_sqlite_cannot_fold(self) -> None:
        self.assertIsNone(stored_fold("LiveUpdate.exe"))
        self.assertIsNone(stored_fold("근로계약서 ab"))
        self.assertIsNone(stored_fold("école"))
        self.assertEqual(stored_fold("ÉCOLE x"), "école x")
        self.assertEqual(stored_fold("Straße"), "strasse")
        self.assertEqual(stored_fold("Ａ１"), "ａ１")

    def test_v3_index_reported_stale_in_korean(self) -> None:
        meta = dict(self.syn.meta, index_version="search-index-v3")
        reasons = stale_reasons(meta, self.syn.summary, self.syn.run)
        self.assertTrue(any("이전 형식 색인" in reason for reason in reasons), reasons)


if __name__ == "__main__":
    unittest.main()
