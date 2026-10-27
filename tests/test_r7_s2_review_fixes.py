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
from rapidtriage.core.search_index.build import (
    build_search_index,
    index_meta,
    stale_reasons,
)
from rapidtriage.core.search_index.engine import Budget, QueryRequest, run_query
from rapidtriage.core.search_index.hits import (
    attach_console_hits,
    console_keywords,
    console_query,
)
from rapidtriage.core.search_index.schema import FOLD_RULE, INDEX_VERSION
from rapidtriage.core.search_index.textutil import stored_fold
from tests.search_index_fixture import write_kind


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


class SearchRun:
    """A synthetic run, its v4 index, and v1-scan / v2-console searches over it."""

    def __init__(
        self,
        base: Path,
        candidates: list[dict[str, object]],
        *,
        docs: list[dict[str, object]] | None = None,
        kinds: dict[str, list[dict[str, object]]] | None = None,
        root: str = "E:\\root",
    ) -> None:
        self.run = base / "run"
        self.run.mkdir()
        files = self.run / "rapidtriage-files.json"
        files.write_text(json.dumps({"command": "files", "candidates": candidates, "inventory": []}, ensure_ascii=False), encoding="utf-8")
        outputs: dict[str, str] = {"files": str(files), "summary": str(self.run / "rapidtriage-run-summary.json")}
        if docs is not None:
            outputs["docs"] = str(self.run / "rapidtriage-docs.json")
            Path(outputs["docs"]).write_text(json.dumps({"command": "docs", "candidates": docs, "results": []}, ensure_ascii=False), encoding="utf-8")
        for kind, rows in (kinds or {}).items():
            outputs[f"artifacts_{kind}"] = str(write_kind(self.run, kind, rows))
        self.summary = {"outputs": outputs, "output_dir": str(self.run), "root": root, "scan_scope_root": root}
        (self.run / "rapidtriage-run-summary.json").write_text(json.dumps(self.summary, ensure_ascii=False), encoding="utf-8")
        self.index = base / "idx.db"
        self.build = build_search_index(self.run, self.summary, index_path=self.index, run_id="syn")
        self.meta = index_meta(self.index)

    def v1_payload(self, keywords: list[str], **options: object) -> dict[str, object]:
        settings: dict[str, object] = {"include_ocr": False, "limit": 1000, "detail": False, "metadata": "compact", "use_case_db": False, "search_mode": "exact"}
        settings.update(options)
        return run_unified_search(self.run, keywords, **settings)  # type: ignore[arg-type]

    def v1_hits(self, keywords: list[str], **options: object) -> list[dict[str, object]]:
        return self.v1_payload(keywords, **options)["matches"]  # type: ignore[return-value]

    def v1(self, keywords: list[str], **options: object) -> list[tuple[str, str]]:
        return sorted((hit["source"], hit["pointer"]) for hit in self.v1_hits(keywords, **options))

    def v2_result(self, keywords: list[str], limit: int = 1000) -> dict[str, object]:
        folded = console_keywords(keywords)
        result = run_query(self.index, self.meta, QueryRequest(q=console_query(folded), limit=limit, aggregates=False, facets=False, histogram=None), budget=Budget(30))
        attach_console_hits(result, folded, summary=self.summary, run_id="syn", offset=0)
        return result

    def v2_hits(self, keywords: list[str]) -> list[dict[str, object]]:
        return self.v2_result(keywords)["matches"]  # type: ignore[return-value]

    def v2(self, keywords: list[str]) -> list[tuple[str, str]]:
        return sorted((hit["source"], hit["pointer"]) for hit in self.v2_hits(keywords))


def synthetic_candidates(names: list[str] = SYNTHETIC_NAMES) -> list[dict[str, object]]:
    return [
        {"path": f"E:\\root\\Users\\u\\{name}", "name": name, "extension": ".txt", "size": index, "categories": ["documents"], "modified_at": "2025-01-01T00:00:00Z"}
        for index, name in enumerate(names)
    ]


class IsolatedEnv(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._previous = os.environ.get("RAPIDTRIAGE_INDEX_PERSIST")
        os.environ["RAPIDTRIAGE_INDEX_PERSIST"] = "0"
        cls.base = Path(tempfile.mkdtemp(prefix="r7s2-review-"))

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.base, ignore_errors=True)
        if cls._previous is None:
            os.environ.pop("RAPIDTRIAGE_INDEX_PERSIST", None)
        else:
            os.environ["RAPIDTRIAGE_INDEX_PERSIST"] = cls._previous


class SyntheticCase(IsolatedEnv):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.syn = SearchRun(cls.base, synthetic_candidates())


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


class HitTimestampTest(IsolatedEnv):
    """#1: file/document hits carry the record time and artifact hits pick v1's time key."""

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        evidence = cls.base / "evidence"
        evidence.mkdir()
        doc_a = evidence / "zeta-memo.txt"
        doc_a.write_text("zeta 계약 메모", encoding="utf-8")
        doc_b = evidence / "zeta-plan.txt"
        doc_b.write_text("zeta plan", encoding="utf-8")
        root = str(evidence)
        candidates = [
            {"path": f"{root}\\zeta-fs.bin", "name": "zeta-fs.bin", "size": 1, "categories": ["other"],
             "modified_at": "2026-01-01T00:00:00+00:00", "fs_modified_at": "2020-02-02T02:02:02+00:00", "modified_at_origin": "listing"},
            {"path": f"{root}\\zeta-copy.bin", "name": "zeta-copy.bin", "size": 2, "categories": ["other"],
             "modified_at": "2026-01-01T00:00:00.123456+00:00", "modified_at_origin": "acquisition-copy",
             "ntfs": {"si_modified_at": "2019-09-09T09:09:09.1234567+00:00"}},
            {"path": f"{root}\\zeta-plain.bin", "name": "zeta-plain.bin", "size": 3, "categories": ["other"],
             "modified_at": "2024-04-04T04:04:04.427776+00:00", "fs_created_at": "2010-01-01T00:00:00+00:00"},
        ]
        docs = [
            {"path": str(doc_a), "kind": "txt", "size": 10, "text_status": "ok", "modified_at": "2025-05-30T03:35:09.016199+00:00"},
            {"path": str(doc_b), "kind": "txt", "size": 9, "text_status": "ok", "modified_at": "2025-06-01T00:00:00+00:00", "created_at": "2001-01-01T00:00:00+00:00"},
        ]
        kinds = {
            "browser": [
                {"provider": "browser", "artifact_type": "browser-history", "path": f"{root}\\History", "timestamp": "2024-12-31T23:59:59Z",
                 "details": {"url": "https://zeta.example/", "title": "zeta", "last_visited_at": "2025-03-03T03:03:03.000001Z", "created_at": "2000-01-01T00:00:00Z"}},
            ],
            "recent-files": [
                {"provider": "recent", "artifact_type": "lnk-file", "path": f"{root}\\zeta.lnk",
                 "details": {"target_path": "C:\\zeta.docx", "created_at": "2022-02-02T00:00:00Z", "modified_at": "2022-03-03T00:00:00Z"}},
                {"provider": "recent", "artifact_type": "lnk-file", "path": f"{root}\\zeta2.lnk", "modified_at": "2023-07-07T07:07:07Z",
                 "details": {"target_path": "C:\\zeta2.docx"}},
            ],
        }
        cls.syn = SearchRun(cls.base, candidates, docs=docs, kinds=kinds, root=root)

    @staticmethod
    def _key(hit: dict[str, object]) -> str:
        return f"{hit['source']}:{hit.get('kind')}:{hit['pointer']}:{hit['path']}"

    def test_same_row_timestamps_equal_v1(self) -> None:
        v1 = {self._key(hit): hit for hit in self.syn.v1_hits(["zeta"])}
        v2 = {self._key(hit): hit for hit in self.syn.v2_hits(["zeta"])}
        self.assertEqual(set(v1), set(v2))
        self.assertEqual(len(v1), 8)
        for key, hit in v1.items():
            with self.subTest(key=key):
                self.assertTrue(hit["timestamp"], hit)
                self.assertEqual(v2[key]["timestamp"], hit["timestamp"])
        by_title = {hit["title"]: hit["timestamp"] for hit in v2.values()}
        # Files: the grid's 수정 time (fs time > NTFS $SI of an acquisition copy > modified_at).
        self.assertEqual(by_title["zeta-fs.bin"], "2020-02-02T02:02:02+00:00")
        self.assertEqual(by_title["zeta-copy.bin"], "2019-09-09T09:09:09.1234567+00:00")
        self.assertEqual(by_title["zeta-plain.bin"], "2024-04-04T04:04:04.427776+00:00")
        # Documents: their own modified_at, spelled as the record spells it.
        self.assertEqual(by_title["zeta-memo.txt"], "2025-05-30T03:35:09.016199+00:00")

    def test_artifact_time_key_order(self) -> None:
        hits = {hit["display_path"]: hit["timestamp"] for hit in self.syn.v2_hits(["zeta"]) if hit["source"] in {"web", "artifacts"}}
        self.assertEqual(hits["History"], "2025-03-03T03:03:03.000001Z")  # details.last_visited_at before the record's timestamp
        self.assertEqual(hits["zeta.lnk"], "2022-03-03T00:00:00Z")  # modified_at before created_at
        self.assertEqual(hits["zeta2.lnk"], "2023-07-07T07:07:07Z")  # the record's own key without a details time


class LongDocumentTest(IsolatedEnv):
    """#3: document bodies up to 512 K characters are searchable; the warning names cut rows per source."""

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        evidence = cls.base / "evidence"
        evidence.mkdir()
        filler = "가나다라 마바사 " * 4000  # ~36 K characters
        cls.mid = evidence / "mid.txt"
        cls.mid.write_text(filler * 3 + " 등록절차 안내 " + filler, encoding="utf-8")  # keyword at ~108 K
        cls.huge = evidence / "huge.txt"
        cls.huge.write_text(filler * 16 + " 위탁의료기관용 서식 ", encoding="utf-8")  # keyword past 512 K
        docs = [
            {"path": str(cls.mid), "kind": "txt", "size": cls.mid.stat().st_size, "text_status": "ok"},
            {"path": str(cls.huge), "kind": "txt", "size": cls.huge.stat().st_size, "text_status": "ok"},
        ]
        cls.syn = SearchRun(cls.base, [], docs=docs, root=str(evidence))

    def test_keyword_past_64k_found_like_v1(self) -> None:
        self.assertEqual(self.syn.v1(["등록절차"]), [("documents", "")])
        hits = self.syn.v2_hits(["등록절차"])
        self.assertEqual([hit["path"] for hit in hits], [str(self.mid)])
        self.assertIn("등록절차", hits[0]["snippet"])

    def test_cut_rows_named_per_source(self) -> None:
        self.assertEqual(self.syn.build["truncated_by_collection"], {"docs": 1})
        self.assertEqual(self.syn.v1(["위탁의료기관용"]), [("documents", "")])
        self.assertEqual(self.syn.v2(["위탁의료기관용"]), [])  # past the cap: documented
        result = self.syn.v2_result(["가나다라"])
        warnings = result["query"]["parsed"]["warnings"]
        self.assertIn("색인 상한에서 본문 일부가 잘린 행이 있어 잘린 뒷부분은 검색되지 않습니다(본문이 잘린 행: 문서 1건)", warnings)


if __name__ == "__main__":
    unittest.main()
