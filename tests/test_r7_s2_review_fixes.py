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


class ArchiveEntryLocatorTest(IsolatedEnv):
    """#6: archive-entry rows get their own locator (unique row key) that resolves to the archive record."""

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        root = "E:\\root"
        entries = [{"name": f"계약서_{index:02d}.hwp", "uncompressed_size": 100 + index, "crc32": f"{index:08x}"} for index in range(14)]
        kinds = {
            "generic-documents": [
                {"provider": "generic-documents", "artifact_type": "document-archive-inventory", "path": f"{root}\\Users\\u\\계약자료.zip",
                 "details": {"source_path": f"{root}\\Users\\u\\계약자료.zip", "archive_inventory_profile": {"sample_entries": entries}}},
            ],
        }
        cls.syn = SearchRun(cls.base, [], kinds=kinds, root=root)

    def test_fifteen_rows_have_unique_locators(self) -> None:
        hits = self.syn.v2_hits(["계약"])
        self.assertEqual(len(hits), 15)
        pointers = [hit["locator"]["pointer"] for hit in hits]
        self.assertEqual(len(set(pointers)), 15, pointers)
        self.assertEqual(len({hit["search_result_id"] for hit in hits}), 15)
        entries = [hit for hit in hits if hit["artifact_type"] == "archive-entry"]
        self.assertEqual(len(entries), 14)
        for hit in entries:
            locator = hit["locator"]
            self.assertRegex(locator["pointer"], r"^/artifacts/0#entry:\d+$")
            self.assertEqual(locator["record_index"], 0)
            self.assertEqual(hit["entry_path"], locator["entry_path"])
            self.assertEqual(hit["path"], f"E:\\root\\Users\\u\\계약자료.zip!{hit['entry_path']}")
        self.assertEqual(sorted(hit["entry_path"] for hit in entries), [entry["name"] for entry in self._entries()])

    def test_review_filter_sees_the_archive_mark(self) -> None:
        marks = [{"collection": "artifacts", "kind": "generic-documents", "locator": "/artifacts/0", "status": "reviewed"}]
        result = run_query(
            self.syn.index, self.syn.meta, QueryRequest(q="계약 review:reviewed", limit=100, aggregates=False, facets=False),
            budget=Budget(30), review_provider=lambda: marks,
        )
        self.assertEqual(len(result["rows"]), 15)

    def _entries(self) -> list[dict[str, object]]:
        return [{"name": f"계약서_{index:02d}.hwp"} for index in range(14)]

    def test_entry_locator_resolves_to_the_archive_record(self) -> None:
        import sqlite3

        from rapidtriage.api.app.run_review import RunLocatorIndex

        connection = sqlite3.connect(":memory:")
        connection.executescript(
            "CREATE TABLE evidence_source (id INTEGER PRIMARY KEY, case_id TEXT);"
            "CREATE TABLE artifact (id INTEGER PRIMARY KEY, evidence_source_id INTEGER, parser_name TEXT, data_json TEXT);"
        )
        connection.execute("INSERT INTO evidence_source VALUES (1, 'case-1')")
        locator = json.dumps({"source_locator": {"output_name": "artifacts_generic-documents", "row_index": 0}})
        connection.execute("INSERT INTO artifact VALUES (7, 1, 'generic-documents', ?)", (locator,))
        index = RunLocatorIndex(connection, "case-1", {})
        for hit in self.syn.v2_hits(["계약"]):
            with self.subTest(pointer=hit["locator"]["pointer"]):
                self.assertEqual(index.resolve("artifacts", hit["locator"]["pointer"], "generic-documents"), ("artifact", "7"))
        self.assertIsNone(index.resolve("artifacts", "/artifacts/0#entry:x", "generic-documents"))
        connection.close()


class BudgetPrefixTest(IsolatedEnv):
    """#5: a budget-stopped v1 search returns a prefix of the full order and no next page."""

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        candidates = [
            # Every 25th row matches: 1,001 hits need 25,000 rows, far past a 0.05 s budget.
            {"path": f"E:\\root\\data\\{'zz' if index % 25 == 0 else 'yy'}-{index:05d}.bin", "name": f"f-{index:05d}.bin", "extension": ".bin", "size": index,
             "categories": ["other"], "modified_at": "2025-01-01T00:00:00Z", "note": "padding " * 20}
            for index in range(40_000)
        ]
        kinds = {"recent-files": [{"provider": "recent", "artifact_type": "lnk-file", "path": "E:\\root\\zz.lnk", "details": {"target_path": "C:\\zz.txt"}}]}
        cls.syn = SearchRun(cls.base, candidates, kinds=kinds)

    def pointers(self, payload: dict[str, object]) -> list[str]:
        return [f"{hit['source']}{hit['pointer']}" for hit in payload["matches"]]  # type: ignore[index, union-attr]

    def test_budget_stop_is_a_prefix_without_a_next_page(self) -> None:
        full = self.syn.v1_payload(["zz"], limit=1000, scan_budget_seconds=0)
        self.assertFalse(full["truncated"])
        cut = self.syn.v1_payload(["zz"], limit=1000, scan_budget_seconds=0.05)
        self.assertTrue(cut["truncated"])
        self.assertGreater(len(cut["matches"]), 0)  # type: ignore[arg-type]
        self.assertLess(len(cut["matches"]), 1000)  # type: ignore[arg-type]
        self.assertEqual(self.pointers(cut), self.pointers(full)[: len(cut["matches"])])  # type: ignore[arg-type]
        self.assertFalse(cut["has_more"])
        pagination = cut["pagination"]
        self.assertFalse(pagination["has_more"])  # type: ignore[index]
        self.assertIsNone(pagination["next_offset"])  # type: ignore[index]
        self.assertIsNone(pagination["total"])  # type: ignore[index]
        self.assertTrue(pagination["budget_stopped"])  # type: ignore[index]
        self.assertIn("시간 예산", cut["truncated_reason"])
        # Later sources are skipped, never searched after the cut.
        self.assertEqual(cut["scanned"]["files"]["stopped"], "budget")  # type: ignore[index]
        self.assertEqual(cut["scanned"]["artifacts"]["stopped"], "after-budget")  # type: ignore[index]
        # The whole request stays near its budget (summary load and hit finalization included).
        self.assertLess(cut["elapsed_ms"], 3000)

    def test_page_past_the_cut_is_empty_with_a_korean_reason(self) -> None:
        page = self.syn.v1_payload(["zz"], limit=250, offset=20_000, scan_budget_seconds=0.05)
        self.assertTrue(page["truncated"])
        self.assertEqual(page["matches"], [])
        self.assertFalse(page["pagination"]["has_more"])  # type: ignore[index]
        self.assertIn("이 쪽은 비어 있습니다", page["pagination"]["stopped_reason"])  # type: ignore[index]


class V1RegexGuardTest(IsolatedEnv):
    """#7: v1 regex mode runs behind the v2 regex guard (static rejection + bounded per-row matching)."""

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        candidates = [
            {"path": f"E:\\root\\Users\\u\\Live{'a' * 30}b.txt", "name": f"Live{'a' * 30}b.txt", "extension": ".txt", "size": 1, "categories": ["documents"]},
            {"path": "E:\\root\\Users\\u\\LiveUpdate.exe", "name": "LiveUpdate.exe", "extension": ".exe", "size": 2, "categories": ["executables"]},
        ]
        cls.syn = SearchRun(cls.base, candidates)

    def test_catastrophic_pattern_is_refused_in_korean(self) -> None:
        import time

        from rapidtriage.core.search import SearchError, regex_guard_problem

        started = time.monotonic()
        with self.assertRaises(SearchError) as caught:
            self.syn.v1_payload(["Live(a+)+$"], search_mode="regex", scan_budget_seconds=1.0)
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertIn("정규식이 너무 복잡합니다", str(caught.exception))
        self.assertIsNotNone(regex_guard_problem("(\\w+)*x"))
        self.assertIsNone(regex_guard_problem("Live.*Update"))

    def test_guarded_patterns_still_match(self) -> None:
        payload = self.syn.v1_payload(["Live(a|b)+\\.txt"], search_mode="regex")
        self.assertEqual([hit["title"] for hit in payload["matches"]], [f"Live{'a' * 30}b.txt"])
        self.assertEqual(len(self.syn.v1_hits(["liveupdate\\.exe"], search_mode="regex")), 1)  # case-insensitive like before

    def test_row_over_the_time_limit_is_reported_not_dropped(self) -> None:
        from unittest import mock

        from rapidtriage.core.search_index.regex_guard import GuardedRegex, RowTimeout

        def slow(_self: object, _text: str) -> None:
            raise RowTimeout()

        with mock.patch.object(GuardedRegex, "search", slow):
            payload = self.syn.v1_payload(["Live.*Update"], search_mode="regex")
        self.assertEqual(payload["matches"], [])
        self.assertEqual(payload["regex_unchecked_rows"], 2)
        self.assertIn("행당 시간 한도", payload["warnings"][0])


try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import create_app
    from rapidtriage.api.app.analyses import ANALYSIS_RUNNER, TERMINAL_STATUSES
    from rapidtriage.api.app.search_index_service import AUTO_INDEX_ENV, SEARCH_HISTORY

    HAS_FASTAPI = True
except ImportError:  # pragma: no cover
    HAS_FASTAPI = False

TOKEN = "r7-s2-review-token"


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for API tests")
class ReviewApiTests(unittest.TestCase):
    """The HTTP side of #7 (v1 regex 422) and #11 (server-side numbering, offset bound)."""

    def setUp(self) -> None:
        from unittest import mock

        from rapidtriage.core.jobs import RunJobStore
        from rapidtriage.core.search_index.hashsets import DATA_DIR_ENV
        from tests.search_index_fixture import build_fixture_run

        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(SEARCH_HISTORY.flush)
        base = Path(self.temp.name)
        env = mock.patch.dict(os.environ, {DATA_DIR_ENV: str(base / "data"), AUTO_INDEX_ENV: "0"})
        env.start()
        self.addCleanup(env.stop)
        fixture = build_fixture_run(base)
        self.store = RunJobStore()
        self.run_id = self.store.import_completed_run(Path(fixture["run_dir"])).run_id
        self.app = create_app(self.store, auth_token=TOKEN)
        self.client = TestClient(self.app, headers={"X-RapidTriage-Token": TOKEN})
        self.addCleanup(lambda: ANALYSIS_RUNNER.shutdown(owner=self.app.state.analysis_owner))

    def url(self, suffix: str) -> str:
        return f"/api/runs/{self.run_id}{suffix}"

    def build_index(self) -> None:
        import time

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

    def test_v1_regex_guard_is_a_korean_422(self) -> None:
        for pattern in ("Live(a+)+$", "Any(\\w+)*Desk", "Any(.*)(.*)(.*)=Desk"):
            with self.subTest(pattern=pattern):
                response = self.client.get(self.url("/search"), params={"keyword": pattern, "search_mode": "regex"})
                self.assertEqual(response.status_code, 422, response.text)
                self.assertIn("정규식", response.json()["detail"])
        ok = self.client.get(self.url("/search"), params={"keyword": "Any.*Desk", "search_mode": "regex"})
        self.assertEqual(ok.status_code, 200, ok.text)
        self.assertTrue(ok.json()["matches"])


if __name__ == "__main__":
    unittest.main()
