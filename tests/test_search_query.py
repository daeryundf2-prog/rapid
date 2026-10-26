"""Search query grammar (plan §3.1) and engine (§3.2 search/query) on the synthetic run."""

from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.core.search_index import engine
from rapidtriage.core.search_index.build import build_search_index, index_meta
from rapidtriage.core.search_index.engine import (
    Budget,
    QueryRequest,
    SearchOptions,
    run_count,
    run_query,
)
from rapidtriage.core.search_index.query import (
    MAX_CLAUSES,
    Group,
    Not,
    QueryError,
    Term,
    parse_query,
    required_literal,
)
from rapidtriage.core.search_index.schema import INDEX_FILE_NAME
from tests.search_index_fixture import build_fixture_run

try:
    from fastapi import HTTPException

    from rapidtriage.api.app.search_index_service import QueryLimiter

    HAS_FASTAPI = True
except ImportError:  # pragma: no cover
    HAS_FASTAPI = False

S1_QUERIES = [
    "kw:급여대장", "word:급여", "re:/급여\\s*대장/i", "near:(직원, 공제, 5)",
    "time:[2025-05-28 .. 2025-05-30T23:59+09:00]", "time:[-7d .. ref]", "time:2025-05", "around:(artifacts:eventlog/artifacts/0, 5m)",
    "tskind:(event, last_written)", "in:(eventlog, registry)", "type:(eventlog-event)", "actor:bsh", "sid:S-1-5-21-*", "computer:진료실1",
    "afterhours:true", "gap:>=6h", "hash:" + "a" * 64, "md5:" + "b" * 32, "sha1:" + "c" * 40, "sha256:" + "d" * 64,
    "path:*\\Downloads\\*.exe", "ext:(exe, dll)", "extset:(documents, executables)", "size:[1MB .. 10MB]", "size:>=1KB", "deleted:true",
    "mismatch:true", "archive:true", "under:C:\\Users\\bsh\\", "author:김경리", "savedby:박원장", "template:normal*",
    "review:(relevant, needs-review)", "tag:북마크", 'note:"원본 확인"', "bookmark:true", "analysis:20251013T000000-aaaaaaaa",
    "eventid:(4624, 4634, 7045-7050)", "provider:security", "channel:system", "data.LogonType:10", "data.TargetUserName:bs*",
]


class QueryGrammarTests(unittest.TestCase):
    def test_every_s1_field_parses(self) -> None:
        for text in S1_QUERIES:
            with self.subTest(text=text):
                parsed = parse_query(text)
                self.assertEqual(len(parsed.terms), 1)
                clause = parsed.clauses()[0]
                self.assertTrue(clause["chip"])
                self.assertFalse(clause["negated"])

    def test_precedence_parentheses_and_not(self) -> None:
        root = parse_query("a OR b c").root
        assert isinstance(root, Group)
        self.assertEqual(root.op, "OR")
        self.assertIsInstance(root.children[1], Group)
        self.assertEqual(root.children[1].op, "AND")
        root = parse_query("(a OR b) AND NOT c -d").root
        assert isinstance(root, Group)
        self.assertEqual(root.op, "AND")
        self.assertIsInstance(root.children[0], Group)
        self.assertIsInstance(root.children[1], Not)
        self.assertIsInstance(root.children[2], Not)
        clauses = parse_query("x -hashset:hs-0123456789ab").clauses()
        self.assertEqual([(c["field"], c["negated"]) for c in clauses], [("kw", False), ("hashset", True)])

    def test_bare_values_and_unknown_fields_stay_keywords(self) -> None:
        terms = parse_query("C:\\Users\\bsh http://x.example/a").terms
        self.assertEqual([(term.field, term.value.text) for term, _neg in terms], [("kw", "C:\\Users\\bsh"), ("kw", "http://x.example/a")])
        term = parse_query('"급여 대장"').terms[0][0]
        self.assertEqual((term.field, term.value.kind, term.value.text), ("kw", "phrase", "급여 대장"))
        term = parse_query("/급여.*대장/").terms[0][0]
        self.assertEqual((term.field, term.value.kind), ("re", "regex"))
        term = parse_query("data.LogonType:10").terms[0][0]
        self.assertEqual(term.field, "data.LogonType")
        self.assertIsInstance(term, Term)

    def assert_error(self, text: str, position: int, fragment: str) -> None:
        with self.assertRaises(QueryError) as caught:
            parse_query(text)
        self.assertEqual(caught.exception.position, position, caught.exception.detail)
        self.assertIn(fragment, caught.exception.detail)
        if position:
            self.assertTrue(caught.exception.detail.startswith(f"질의 {position}번째 글자: "))

    def test_error_positions(self) -> None:
        self.assert_error("(급여", 1, "닫는 괄호가 없습니다")
        self.assert_error('a kw:"abc', 6, "닫는 따옴표가 없습니다")
        self.assert_error("a AND", 3, "AND 뒤에 조건이 없습니다")
        self.assert_error("a OR", 3, "OR 뒤에 조건이 없습니다")
        self.assert_error("a )", 3, "여는 괄호 없이")
        self.assert_error("time:[2025-05-28", 6, "범위를 닫는 ]")
        self.assert_error("time:[2025]", 6, "[시작 .. 끝]")
        self.assert_error("ext:(exe,,dll)", 10, "빈 항목")
        self.assert_error("kw:", 1, "값이 없습니다")
        self.assert_error("()", 1, "빈 괄호")
        self.assert_error("deleted:maybe", 9, "true 또는 false")
        self.assert_error("", 0, "검색어가 비어 있습니다")

    def test_limits(self) -> None:
        self.assert_error("a" * 4001, 0, "질의가 너무 깁니다(최대 4,000자)")
        many = " ".join(f"t{index}" for index in range(MAX_CLAUSES + 1))
        with self.assertRaises(QueryError) as caught:
            parse_query(many)
        self.assertIn("조건이 너무 많습니다(최대 64개)", caught.exception.detail)
        parse_query(" ".join(f"t{index}" for index in range(MAX_CLAUSES)))
        self.assert_error("re:/" + "a" * 513 + "/", 4, "정규식이 너무 깁니다")
        self.assert_error("re:/(a+)+/", 4, "정규식이 너무 복잡합니다")
        self.assert_error("re:/(\\w*)*x/", 4, "정규식이 너무 복잡합니다")
        self.assert_error("re:/(a)\\1/", 4, "정규식이 너무 복잡합니다")
        self.assert_error("re:/[a/", 4, "정규식이 올바르지 않습니다")
        self.assert_error("-a -b", 0, "제외 조건만으로는")
        self.assert_error("ip:10.0.0.0/8", 1, "S2")
        self.assert_error("list:patients", 1, "S2")
        self.assert_error("geo:near(37.5, 126.9, 3km)", 1, "S3")
        self.assert_error("NOT gap:>=6h x", 5, "NOT·OR 안에")

    def test_two_char_warning_and_required_literal(self) -> None:
        self.assertEqual(parse_query("급여").warnings, [])  # 2 Hangul characters: the bigram table (index v3)
        self.assertEqual(parse_query("ab").warnings, ["영문·숫자·기호가 든 2자 검색어는 색인을 쓰지 못해 전체 본문을 훑습니다(느릴 수 있음)"])
        self.assertEqual(required_literal("급여\\s*대장"), "급여")
        self.assertEqual(required_literal("AnyDesk\\.exe"), "AnyDesk.exe")
        self.assertEqual(required_literal("abcd?ef"), "abc")
        self.assertEqual(required_literal("foo|barbaz"), "")


class QueryEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        cls.fixture = build_fixture_run(Path(cls.temp.name))
        build_search_index(cls.fixture["run_dir"], cls.fixture["summary"], run_id="fixture")
        cls.index = cls.fixture["run_dir"] / INDEX_FILE_NAME
        cls.meta = index_meta(cls.index)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def run_q(self, q: str, **kwargs: object) -> dict:
        budget = kwargs.pop("budget", None) or Budget(15)
        provider = kwargs.pop("review_provider", None)
        resolver = kwargs.pop("hashset_resolver", None)
        return run_query(self.index, self.meta, QueryRequest(q=q, **kwargs), budget=budget, review_provider=provider, hashset_resolver=resolver)

    def total(self, q: str, **kwargs: object) -> int:
        return int(self.run_q(q, **kwargs)["page"]["total"])

    def test_field_totals(self) -> None:
        expected = {
            "급여대장": 4,  # docs, files, generic-documents metadata row, ShellBags path
            "word:급여": 1,
            "re:/급여\\s*대장/": 4,
            "near:(직원, 공제, 5)": 1,
            "SanDisk": 1,
            "AnyDesk.exe": 3,  # file, 7045 ImagePath, indicator URL
            "time:2025-05-28": 4,  # KST day: AnyDesk created, two events, ShellBags access
            "time:[2025-05-28T19:00+09:00 .. 2025-05-28T21:00+09:00]": 4,
            "around:(artifacts:eventlog/artifacts/0, 15m)": 2,
            "around:(artifacts:eventlog/artifacts/0, 1m)": 1,
            "tskind:last_written": 2,
            "tskind:item-accessed": 1,
            "in:docs": 1,
            "in:(eventlog, registry)": 6,
            "type:eventlog-*": 4,
            "actor:bsh": 1,
            "sid:S-1-5-21-*": 2,
            "computer:진료실1": 3,
            "afterhours:true": 1,  # 4624 at 00:00 KST
            "afterhours:false": 6,
            "path:*\\Downloads\\*.exe": 1,
            "under:C:\\Users\\bsh\\Desktop": 5,
            "ext:(txt, exe)": 4,
            "extset:executables": 1,
            "size:[1MB .. 10MB]": 1,
            "size:<100": 1,
            "deleted:true": 1,
            "mismatch:true": 1,
            "archive:true": 0,
            "author:김경리": 2,
            "savedby:박원장": 2,
            "template:normal*": 2,
            "eventid:4624": 3,
            "eventid:(7040-7050)": 1,
            "provider:service": 1,
            "channel:system": 1,
            "eventid:4624 data.LogonType:10": 1,
            "data.TargetUserName:SY*": 1,
            "analysis:20251013T000000-aaaaaaaa": 2,
            "AnyDesk OR SanDisk": 5,
            "NOT SanDisk eventid:4624": 3,
            "eventid:4624 -actor:SYSTEM": 2,
            "(급여대장 OR SanDisk) in:registry": 1,
            "hash:" + self.fixture["exe_hashes"]["sha256"]: 2,
            "md5:" + self.fixture["doc_hashes"]["md5"]: 2,
            "sha256:" + self.fixture["carve_hash"]: 1,
        }
        for q, count in expected.items():
            with self.subTest(q=q):
                self.assertEqual(self.total(q), count)

    def test_rows_shape_snippet_and_collapse(self) -> None:
        result = self.run_q("급여대장", limit=10)
        self.assertEqual(result["query"]["parsed"]["clauses"][0]["field"], "kw")
        row = next(item for item in result["rows"] if item["kind"] == "windows-shellbags")
        self.assertEqual(row["locator"], "/artifacts/0")
        self.assertEqual(row["ts_kinds"], ["item-created", "item-accessed"])
        self.assertEqual(row["matched"], [{"term": "급여대장", "field": "kw"}])
        start, end = row["snippet"]["marks"][0]
        self.assertEqual(row["snippet"]["text"][start:end], "급여대장")
        for key in ("doc_id", "collection", "kind", "locator", "analysis_id", "domain", "artifact_type", "title", "path", "ts", "ts_kind",
                    "ts_kinds", "actor", "computer", "hashes", "snippet", "matched", "fields", "review", "pii", "masked_preview"):
            self.assertIn(key, row)
        self.assertEqual(result["facets"]["domain"][0]["count"] >= 1, True)
        self.assertTrue(result["page"]["total_exact"])
        self.assertEqual(result["index"]["build_id"], self.meta["build_id"])
        expanded = self.run_q("tskind:(item-created, item-accessed)", collapse=False)
        self.assertEqual(expanded["page"]["total"], 2)
        self.assertEqual(self.run_q("tskind:(item-created, item-accessed)")["page"]["total"], 1)

    def test_histogram_gaps_and_after_hours(self) -> None:
        result = self.run_q("time:2025-05-28", collapse=False, view="timeline", histogram="auto")
        histogram = result["histogram"]
        self.assertEqual(sum(bucket["count"] for bucket in histogram["buckets"]), result["page"]["total"])
        self.assertEqual(histogram["tz"], "+09:00")
        self.assertEqual(result["page"]["sort"], "ts")
        times = [row["ts"] for row in result["rows"]]
        self.assertEqual(times, sorted(times))
        gaps = self.run_q("gap:>=6h", collapse=False, histogram="auto")["histogram"]
        self.assertTrue(gaps["gaps"])
        self.assertTrue(all(item["seconds"] >= 6 * 3600 for item in gaps["gaps"]))
        self.assertEqual(gaps["after_hours_count"], 1)
        hourly = self.run_q("time:2025-05-28", collapse=False, histogram="1h")["histogram"]
        self.assertEqual(hourly["bucket_seconds"], 3600)
        self.assertEqual(len(hourly["buckets"]), 24)

    def test_cursor_round_trip_and_previous_page(self) -> None:
        q = "in:(files, docs, artifacts, indicators, analysis)"
        for collapse, sort in ((True, "relevance"), (False, "ts"), (True, "-ts"), (True, "path")):
            seen: list[int] = []
            cursor = None
            pages: list[dict] = []
            while True:
                result = self.run_q(q, cursor=cursor, limit=3, collapse=collapse, sort=sort)
                pages.append(result)
                seen.extend(row["doc_id"] for row in result["rows"])
                cursor = result["page"]["next_cursor"]
                if cursor is None:
                    break
            total = pages[0]["page"]["total"]
            with self.subTest(collapse=collapse, sort=sort):
                self.assertEqual(len(seen), total)
                self.assertEqual(len(set(seen)), total)
                self.assertIsNone(pages[0]["page"]["previous_cursor"])
                back = self.run_q(q, cursor=pages[1]["page"]["previous_cursor"], limit=3, collapse=collapse, sort=sort)
                self.assertEqual([row["doc_id"] for row in back["rows"]], [row["doc_id"] for row in pages[0]["rows"]])
        first = self.run_q(q, limit=3)
        with self.assertRaises(QueryError) as caught:
            self.run_q("SanDisk", cursor=first["page"]["next_cursor"], limit=3)
        self.assertEqual(caught.exception.detail, "커서가 이 질의에 맞지 않습니다")
        with self.assertRaises(QueryError):
            self.run_q(q, cursor=first["page"]["next_cursor"], limit=3, sort="ts")
        with self.assertRaises(QueryError):
            self.run_q(q, cursor="not-base64!", limit=3)

    def test_sort_cap_falls_back_to_relevance(self) -> None:
        with mock.patch.object(engine, "SORT_TS_CAP", 2):
            result = self.run_q("in:artifacts", sort="ts")
        self.assertEqual(result["page"]["sort"], "relevance")
        self.assertTrue(any("시간순 대신" in warning for warning in result["query"]["parsed"]["warnings"]))

    def test_total_cap(self) -> None:
        with mock.patch.object(engine, "TOTAL_CAP", 5):
            result = self.run_q("in:(files, docs, artifacts, indicators, analysis)", limit=3)
            self.assertFalse(result["page"]["total_exact"])
            self.assertFalse(result["facets"]["exact"])
            seen = [row["doc_id"] for row in result["rows"]]
            cursor = result["page"]["next_cursor"]
            while cursor:
                page = self.run_q("in:(files, docs, artifacts, indicators, analysis)", limit=3, cursor=cursor)
                seen.extend(row["doc_id"] for row in page["rows"])
                cursor = page["page"]["next_cursor"]
        self.assertEqual(len(seen), 19)  # paging continues on the live predicate past the cap

    def test_budget_truncation_and_cancellation(self) -> None:
        result = self.run_q("in:artifacts", budget=Budget(0.0))
        self.assertTrue(result["truncated"])
        self.assertIn("시간 예산", result["truncated_reason"])
        cancel = threading.Event()
        cancel.set()
        result = self.run_q("in:artifacts", budget=Budget(15, cancel))
        self.assertTrue(result["truncated"])
        self.assertIn("클라이언트 연결이 끊겨", result["truncated_reason"])
        self.assertEqual(result["rows"], [])

    def test_short_keywords(self) -> None:
        result = self.run_q("급여")
        self.assertEqual(result["page"]["total"], 4)
        self.assertEqual(result["query"]["parsed"]["warnings"], [])  # bigram table, no scan
        self.assertIn("1자 검색어는 색인을 쓰지 못해 전체 본문을 훑습니다(느릴 수 있음)", self.run_q("급")["query"]["parsed"]["warnings"])
        # LIKE metacharacters are literal text, never wildcards.
        self.assertEqual(self.total("kw:%"), 0)
        self.assertEqual(self.total("kw:_Classes"), 1)  # literal underscore (ShellBags key)
        self.assertEqual(self.total("'; DROP TABLE search_doc; --"), 0)
        self.assertEqual(self.total("SanDisk"), 1)

    def test_options(self) -> None:
        self.assertEqual(self.total("anydesk.com"), 1)
        self.assertEqual(self.total("anydesk.com", options=SearchOptions(case_sensitive=True)), 1)
        self.assertEqual(self.total("ANYDESK.COM", options=SearchOptions(case_sensitive=True)), 0)
        self.assertEqual(self.total("급여", options=SearchOptions(whole_word=True)), 1)
        # In UTC the 00:00 KST logon is 15:00 (not after hours) and two early-morning UTC times are.
        self.assertEqual(self.total("afterhours:true", options=SearchOptions(tz="+00:00")), 2)  # 00:10Z, 01:00Z
        with self.assertRaises(QueryError):
            self.run_q("x", options=SearchOptions(tz="Asia/Seoul"))

    def test_around_validates_locators(self) -> None:
        for q in ("around:(artifacts:eventlog/artifacts/../x, 5m)", "around:(/etc/passwd, 5m)", "around:(artifacts:eventlog/artifacts/999, 5m)", "around:(/artifacts/0, 5m)"):
            with self.subTest(q=q):
                with self.assertRaises(QueryError):
                    self.run_q(q)
        self.assertEqual(self.total("around:(7, 15m)"), 2)  # doc_id form

    def test_review_filters_use_marks(self) -> None:
        marks = [
            {"collection": "artifacts", "kind": "eventlog", "locator": "/artifacts/0", "status": "relevant", "tags": ["북마크"], "note": "원본 확인 필요"},
            {"collection": "files", "kind": "", "locator": "/candidates/1", "status": "needs-review", "tags": [], "note": "", "include_in_report": True},
        ]
        provider = lambda: marks
        self.assertEqual(self.total("review:relevant", review_provider=provider), 1)
        self.assertEqual(self.total("review:(relevant, needs-review)", review_provider=provider), 2)
        self.assertEqual(self.total("review:include-in-report", review_provider=provider), 1)
        self.assertEqual(self.total("bookmark:true", review_provider=provider), 1)
        self.assertEqual(self.total('note:"원본 확인"', review_provider=provider), 1)
        self.assertEqual(self.total("tag:북마크 eventid:4624", review_provider=provider), 1)
        self.assertEqual(self.total("review:unreviewed in:eventlog", review_provider=provider), 3)
        result = self.run_q("review:relevant", review_provider=lambda: None)
        self.assertEqual(result["page"]["total"], 0)
        self.assertIn("케이스 DB가 없어 리뷰 조건과 일치하는 행이 없습니다", result["query"]["parsed"]["warnings"])

    def test_count(self) -> None:
        terms = [{"label": "급여", "q": "급여대장"}, {"label": "bad", "q": "(x"}, {"label": "usb", "q": "SanDisk"}]
        result = run_count(self.index, self.meta, terms, SearchOptions(), offset=0, budget=Budget(15))
        self.assertEqual(result["done"], 3)
        self.assertEqual([item["count"] for item in result["items"]], [4, None, 1])
        self.assertIn("닫는 괄호", result["items"][1]["error"])
        self.assertEqual(result["items"][2]["by_domain"], {"devices": 1})
        self.assertEqual(result["items"][2]["first_ts"], "2025-05-26T21:48:04.000+09:00")
        resumed = run_count(self.index, self.meta, terms, SearchOptions(), offset=2, budget=Budget(15))
        self.assertEqual([item["count"] for item in resumed["items"]], [1])
        stopped = run_count(self.index, self.meta, terms, SearchOptions(), offset=0, budget=Budget(0.0))
        self.assertTrue(stopped["truncated"])
        self.assertLess(stopped["done"], 3)

    @unittest.skipUnless(HAS_FASTAPI, "fastapi is required")
    def test_concurrency_limit(self) -> None:
        limiter = QueryLimiter(4)
        with limiter.slot("r"), limiter.slot("r"), limiter.slot("r"), limiter.slot("r"):
            with self.assertRaises(HTTPException) as caught, limiter.slot("r"):
                pass
            self.assertEqual(caught.exception.status_code, 429)
            self.assertEqual(caught.exception.detail, "검색이 너무 많이 실행 중입니다")
            with limiter.slot("other"):
                pass
        with limiter.slot("r"):
            pass


if __name__ == "__main__":
    unittest.main()
