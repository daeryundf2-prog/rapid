"""Search S1 adversarial-review fixes (plan search-2026-10-13 §3.4 "리뷰 반영").

Regex guard (static analysis + bounded matching), histogram caps, parse-tree
FTS literals, payload fields kept whole, histogram/total consistency, no 500s
(fuzz), index replacement on Windows, ``/…/`` keywords, target paths,
review-mark truncation, async history, deleted hide sets, first-page fast
path, slot release on disconnect. Each test fails on the pre-fix code.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.core.search_index import build as build_module
from rapidtriage.core.search_index import engine
from rapidtriage.core.search_index.build import (
    IndexSwapFailed,
    build_search_index,
    index_meta,
    read_index_meta,
    target_path,
)
from rapidtriage.core.search_index.engine import (
    Budget,
    Compiler,
    QueryRequest,
    SearchOptions,
    run_query,
)
from rapidtriage.core.search_index.hashsets import (
    DATA_DIR_ENV,
    create_hash_set,
    delete_hash_set,
    hash_set_path,
)
from rapidtriage.core.search_index.query import (
    QueryError,
    parse_query,
    required_literal,
)
from rapidtriage.core.search_index.regex_guard import (
    GuardedRegex,
    RowTimeout,
    analyze_regex,
)
from rapidtriage.core.search_index.schema import (
    BUILDING_SUFFIX,
    INDEX_FILE_NAME,
    open_writable,
)
from rapidtriage.core.search_index.textutil import target_path_key
from tests.search_index_fixture import build_fixture_run, write_analysis, write_kind

try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import create_app
    from rapidtriage.api.app.analyses import ANALYSIS_RUNNER, TERMINAL_STATUSES
    from rapidtriage.api.app.routes_search_index import run_cancellable
    from rapidtriage.api.app.search_index_service import (
        AUTO_INDEX_ENV,
        SEARCH_HISTORY,
        QueryLimiter,
    )

    HAS_FASTAPI = True
except ImportError:  # pragma: no cover
    HAS_FASTAPI = False

from rapidtriage.core.case_db import open_case_database
from rapidtriage.core.jobs import RunJobStore

DOS_PATTERNS = (r"((a+))+b", r"(a|b|ab)*c", r"(?=(a+))+b", r"[a-z]+[a-z]+[a-z]+=", r"((\w+))+Z")
SLOW_ANALYSIS = "20251016T000000-dddddddd"
SPAN_ANALYSIS = "20251017T000000-eeeeeeee"


def extend_run(fixture: dict) -> dict:
    """Add target-path kinds (LNK, Prefetch, Amcache, download), a 32 KB adversarial row and far-apart times."""
    run_dir: Path = fixture["run_dir"]
    summary = fixture["summary"]
    evidence = fixture["evidence"]
    recent = evidence / "Users" / "bsh" / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent" / "AnyDesk.lnk"
    outputs = summary["outputs"]
    outputs["artifacts_recent-files"] = str(write_kind(run_dir, "recent-files", [
        {"provider": "recent-files", "artifact_type": "recent-shortcut", "path": str(recent),
         "details": {"entry_name": "AnyDesk.lnk", "target_path": "C:\\Users\\bsh\\Downloads\\AnyDesk.exe", "local_base_path": "C:\\Users\\bsh\\Downloads\\AnyDesk.exe"}},
    ]))
    outputs["artifacts_windows-prefetch"] = str(write_kind(run_dir, "windows-prefetch", [
        {"provider": "windows-prefetch", "artifact_type": "prefetch-file", "path": str(evidence / "Windows" / "Prefetch" / "ANYDESK.EXE-12345678.pf"),
         "details": {"header_executable_name": "ANYDESK.EXE", "referenced_paths": [
             "\\VOLUME{01d75b57f6c404f3-a8f6f975}\\WINDOWS\\SYSTEM32\\NTDLL.DLL",
             "\\VOLUME{01d75b57f6c404f3-a8f6f975}\\USERS\\BSH\\DOWNLOADS\\ANYDESK.EXE"]}},
    ]))
    outputs["artifacts_windows-execution"] = str(write_kind(run_dir, "windows-execution", [
        {"provider": "windows-execution", "artifact_type": "amcache-schema-row", "path": str(evidence / "Windows" / "appcompat" / "Programs" / "Amcache.hve"),
         "details": {"executable_path": "c:\\users\\bsh\\downloads\\anydesk.exe"}},
        {"provider": "windows-execution", "artifact_type": "bam-schema-entry", "path": str(evidence / "Windows" / "System32" / "config" / "SYSTEM"),
         "details": {"executable_path": "\\Device\\HarddiskVolume3\\Users\\bsh\\Downloads\\AnyDesk.exe"}},
    ]))
    outputs["artifacts_browser"] = str(write_kind(run_dir, "browser", [
        {"provider": "browser", "artifact_type": "browser-download", "path": str(evidence / "Users" / "bsh" / "AppData" / "Local" / "Edge" / "History"),
         "details": {"url": "https://example.test/tool.exe", "target_path": "C:\\Users\\bsh\\Downloads\\tool.exe"}},
    ]))
    write_analysis(run_dir, SLOW_ANALYSIS, "ocr-batch", [
        {"artifact_type": "ocr-row", "path": "C:\\x\\scan.png", "details": {"text": "ab" * 16000}},
    ])
    write_analysis(run_dir, SPAN_ANALYSIS, "ntfs-meta", [
        {"artifact_type": "ntfs-meta-row", "path": "C:\\x\\old.txt", "details": {"path": "\\x\\old.txt", "created_at": "1700-01-01T00:00:00+00:00"}},
        {"artifact_type": "ntfs-meta-row", "path": "C:\\x\\future.txt", "details": {"path": "\\x\\future.txt", "created_at": "9000-01-01T00:00:00+00:00"}},
    ])
    fixture["summary_path"].write_text(json.dumps(summary, ensure_ascii=False), encoding="utf-8")
    return fixture


PAYLOAD_TERMS = ("IsValuePresent", "LanguagePrimitives")


def build_payload_run(base: Path) -> dict:
    """A large-type 4104 event log output mirroring the real case: script blocks of 1.7–20 KB with the terms deep inside."""
    run_dir = base / "payload-run"
    run_dir.mkdir()
    evtx = "C:\\evidence\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx"
    filler = 'Write-Verbose "step";\n'
    rows: list[dict] = []
    positions = [3, 900, 1500, 3000, 4500, 7000, 12000, 18000]
    for index in range(48):
        term = PAYLOAD_TERMS[index % 2]
        if index % 3 == 2:
            term = "NeitherTerm"
        at = positions[index % len(positions)]
        size = max(at + 400, 1769 + (index * 397) % 18000)
        body = (filler * (size // len(filler) + 1))[:size]
        script = body[:at] + f"[System.Management.Automation.{term}]::Check()\n" + body[at:]
        details = {
            "event_id": "4104", "record_id": str(1000 + index), "channel": "Microsoft-Windows-PowerShell/Operational",
            "provider_name": "Microsoft-Windows-PowerShell", "computer": "진료실1",
            "script_block_text": script, "command_line": script, "event_message": script[:1024], "event_message_truncated": True,
            "event_data": {"MessageNumber": "1", "MessageTotal": "1", "ScriptBlockText": script, "ScriptBlockId": f"{{{index:08d}-aaaa-bbbb-cccc-dddddddddddd}}", "Path": ""},
        }
        rows.append({"provider": "windows-eventlog", "artifact_type": "eventlog-event", "path": evtx, "profile_ref": "eventlog-event", "details": details})
    huge = (filler * 4000)[:70_000] + "TAILMARKER"
    rows.append({"provider": "windows-eventlog", "artifact_type": "eventlog-event", "path": evtx, "profile_ref": "eventlog-event",
                 "details": {"event_id": "4104", "record_id": "9999", "event_data": {"ScriptBlockText": huge, "Junk": "j" * 3000}}})
    profiles = {"eventlog-event": {"details": {"parser": "windows-eventlog-evtx-native"}}}
    head_path = write_kind(run_dir, "eventlog", rows, profiles=profiles)
    head = json.loads(head_path.read_text(encoding="utf-8"))
    head["summary"]["artifact_type_counts"] = {"eventlog-event": 5000}  # a large type, like the real 294k-row output
    head_path.write_text(json.dumps(head, ensure_ascii=False), encoding="utf-8")
    summary = {"output_dir": str(run_dir), "root": "C:\\evidence", "outputs": {"artifacts_eventlog": str(head_path)}}
    (run_dir / "rapidtriage-run-summary.json").write_text(json.dumps(summary, ensure_ascii=False), encoding="utf-8")
    records = run_dir / "artifacts" / "rapidtriage-artifacts-eventlog.jsonl"
    return {"run_dir": run_dir, "summary": summary, "records": records}


def raw_line_count(path: Path, term: str) -> int:
    with open(path, encoding="utf-8") as handle:
        return sum(1 for line in handle if term in line)


class RegexGuardTests(unittest.TestCase):
    def test_static_rejections_on_the_parse_tree(self) -> None:
        for pattern in (*DOS_PATTERNS, r"(\w*)*x", r"(a)\1", r"\w+\s*\w+", r"(?=.*foo)bar", r"(?:\w+\.)+com"):
            with self.subTest(pattern=pattern):
                with self.assertRaises(QueryError) as caught:
                    parse_query(f"re:/{pattern}/")
                self.assertIn("정규식이 너무 복잡합니다", caught.exception.detail)
        for pattern in (r"급여\s*대장", r"\w+\s+\w+", r".*a.*b=", r"(\d{1,3}\.){3}\d{1,3}", r"[0-9a-f]{64}", r"(ab|cd)+", r"\bpowershell\b.*-enc"):
            with self.subTest(pattern=pattern):
                parse_query(f"re:/{pattern}/")

    def test_required_literal_from_the_parse_tree(self) -> None:
        cases = {
            r"Any\x44esk\.exe": "AnyDesk.exe",
            r"\u0041nyDesk": "AnyDesk",
            r"\N{HANGUL SYLLABLE GA}나다": "가나다",
            r"\101BC": "ABC",
            r"a{,3}bcd": "bcd",
            r"(?x) 급여 대장": "급여대장",
            r"[^]]급여대장": "급여대장",
            r"[\]]abc": "]abc",
            r"(?i:abc)defg": "defg",
            r"foo|barbaz": "",
            r"abcd?ef": "abc",
        }
        for pattern, literal in cases.items():
            with self.subTest(pattern=pattern):
                self.assertEqual(required_literal(pattern), literal)
        # IGNORECASE: LIKE folds ASCII only, and Python also matches K/S/I with KELVIN SIGN / LONG S / dotless i.
        self.assertEqual(required_literal("anydesk", "i"), "anyde")
        self.assertEqual(analyze_regex("(?i)급여대장").literal, "급여대장")

    def test_guarded_matcher_bounds_a_hostile_row(self) -> None:
        matcher = GuardedRegex(analyze_regex(r".*a.*b=").compiled)
        started = time.monotonic()
        with self.assertRaises(RowTimeout):
            matcher.search("ab" * 32_000)
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertEqual(GuardedRegex(analyze_regex("needle").compiled).search("x" * 50_000 + "needle"), (50_000, 50_006))


class HardeningEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        cls.data_dir = Path(cls.temp.name) / "data"
        cls.env = mock.patch.dict(os.environ, {DATA_DIR_ENV: str(cls.data_dir)})
        cls.env.start()
        cls.fixture = extend_run(build_fixture_run(Path(cls.temp.name)))
        build_search_index(cls.fixture["run_dir"], cls.fixture["summary"], run_id="hardening")
        cls.index = cls.fixture["run_dir"] / INDEX_FILE_NAME
        cls.meta = index_meta(cls.index)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.env.stop()
        cls.temp.cleanup()

    def run_q(self, q: str, **kwargs: object) -> dict:
        budget = kwargs.pop("budget", None) or Budget(15)
        return run_query(self.index, self.meta, QueryRequest(q=q, **kwargs), budget=budget, hashset_resolver=hash_set_path)

    def total(self, q: str, **kwargs: object) -> int:
        return int(self.run_q(q, **kwargs)["page"]["total"])

    # -- H1 ----------------------------------------------------------------

    def test_dos_patterns_are_400_within_one_second(self) -> None:
        for pattern in DOS_PATTERNS:
            with self.subTest(pattern=pattern):
                started = time.monotonic()
                with self.assertRaises(QueryError) as caught:
                    self.run_q(f"re:/{pattern}/")
                self.assertEqual(caught.exception.status, 400)
                self.assertLess(time.monotonic() - started, 1.0)
        # The 64-hex indicator row exists; the pattern never reaches it.
        self.assertEqual(self.total("type:indicator-sha256"), 1)

    def test_slow_allowed_regex_is_truncated_within_one_second(self) -> None:
        started = time.monotonic()
        result = self.run_q(r"re:/.*a.*b=/")
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertTrue(result["truncated"])
        self.assertTrue(any("행당 시간 한도" in warning for warning in result["query"]["parsed"]["warnings"]))

    def test_regex_snippet_uses_the_guarded_matcher(self) -> None:
        result = self.run_q(r"re:/Any\x44esk\.exe/")
        self.assertEqual(result["page"]["total"], self.total("AnyDesk.exe", options=SearchOptions(case_sensitive=True)))
        row = result["rows"][0]
        self.assertEqual(row["matched"], [{"term": r"Any\x44esk\.exe", "field": "re"}])
        start, end = row["snippet"]["marks"][0]
        self.assertEqual(row["snippet"]["text"][start:end], "AnyDesk.exe")

    # -- H2 ----------------------------------------------------------------

    def test_histogram_buckets_are_capped(self) -> None:
        for q in (f"analysis:{SPAN_ANALYSIS}", "time:[1601-01-01 .. 9999-12-31] analysis:" + SPAN_ANALYSIS):
            with self.subTest(q=q):
                started = time.monotonic()
                result = self.run_q(q, histogram="1m")
                histogram = result["histogram"]
                self.assertLessEqual(len(histogram["buckets"]), engine.MAX_BUCKETS)
                self.assertGreater(histogram["bucket_seconds"], 60)
                self.assertTrue(any("구간을" in warning for warning in result["query"]["parsed"]["warnings"]))
                self.assertEqual(sum(bucket["count"] for bucket in histogram["buckets"]), 2)
                self.assertLess(time.monotonic() - started, 2.0)

    # -- H3 ----------------------------------------------------------------

    def test_regex_prefilter_literals(self) -> None:
        self.assertEqual(self.total(r"re:/(?x) 급여 대장/"), self.total("re:/급여대장/"))
        self.assertEqual(self.total("re:/급여대장/"), 4)
        self.assertEqual(self.total(r"re:/[^]]급여대장/"), 4)
        self.assertEqual(self.total(r"re:/Any\x44esk\.exe/"), self.total(r"re:/AnyDesk\.exe/"))
        self.assertGreater(self.total(r"re:/Any\x44esk\.exe/"), 0)

    # -- M1 ----------------------------------------------------------------

    def test_histogram_counts_groups_and_clips_only_top_level_time(self) -> None:
        # The ShellBags row has two times in the same week: one group, counted once.
        result = self.run_q("tskind:(item-created, item-accessed)", histogram="1w")
        self.assertEqual(result["page"]["total"], 1)
        self.assertEqual(result["histogram"]["counts"], "groups")
        self.assertEqual(sum(bucket["count"] for bucket in result["histogram"]["buckets"]), 1)
        # Under OR the time window does not bound the rows, so it must not bound the axis.
        mixed = self.run_q("SanDisk OR time:2025-05-28", collapse=False, histogram="1h")
        with_time = [row for row in self.run_q("SanDisk OR time:2025-05-28", collapse=False, limit=1000)["rows"] if row["ts"]]
        self.assertEqual(sum(bucket["count"] for bucket in mixed["histogram"]["buckets"]), len(with_time))
        self.assertLessEqual(mixed["histogram"]["range_start"], "2025-05-26T21:48:04.000+09:00")
        clipped = self.run_q("time:2025-05-28 eventid:4624", histogram="1h")["histogram"]
        self.assertEqual(clipped["range_start"], "2025-05-28T00:00:00.000+09:00")

    # -- M2 ----------------------------------------------------------------

    def test_fuzz_inputs_never_escape_as_500(self) -> None:
        inputs = [
            "(" * 40 + "x" + ")" * 40, "NOT " * 40 + "x", "-" * 40 + "x", "x " + " ".join(["OR y"] * 60),
            "around:(99999999999999999999, 5m)", "around:(123456789012345, 5m)", "around:(7, 0s)",
            "size:99999999999999999999999TB", "size:>" + "9" * 400, "time:9999", "time:[0001-01-01 .. 9999-12-31]",
            "time:[2025-01-01T00:00+99:99 .. 2025-01-02]", "foo(", "re:/" + "(" * 200 + "a" + ")" * 200 + "/",
            "re:/(?:a{1,1000}){1,1000}/", "eventid:(1-999999)", "kw:\ud800x", "ext:(" + ", ".join(f"e{i}" for i in range(256)) + ")",
            "path:(" + ", ".join(f"*\\d{i}\\*" for i in range(256)) + ")", "re:/a/b/", "data.:x", "near:(a, b, 101)",
            "hashset:hs-000000000000", "in:nowhere", "tskind:" + "x" * 3000, "\"" + "a" * 3990 + "\"",
        ]
        for q in inputs:
            with self.subTest(q=q[:60]):
                try:
                    result = self.run_q(q)
                except QueryError as exc:
                    self.assertIn(exc.status, {400, 404})
                    self.assertTrue(exc.detail)
                else:
                    self.assertIn("rows", result)

    def test_too_many_hash_sets_is_400(self) -> None:
        ids = [create_hash_set(name=f"set {index}", label="custom", data=(f"{index + 1:032x}\n").encode())["id"] for index in range(11)]
        try:
            with self.assertRaises(QueryError) as caught:
                self.run_q("x", options=SearchOptions(hide_hashsets=ids))
            self.assertEqual(caught.exception.status, 400)
            self.assertIn("최대 8개", caught.exception.detail)
        finally:
            for hash_set_id in ids:
                delete_hash_set(hash_set_id)

    def test_tampered_cursor_with_huge_numbers_is_400(self) -> None:
        qhash = engine.query_hash("AnyDesk", SearchOptions(), True, str(self.meta["build_id"]))
        for last in ([10**30, 1], [1, 10**30], [1, -1], ["x" * 5000, 1]):
            payload = {"v": engine.CURSOR_VERSION, "qhash": qhash, "sort": "relevance", "es": "relevance", "last": last, "dir": "next"}
            cursor = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
            with self.subTest(last=str(last)[:30]):
                with self.assertRaises(QueryError) as caught:
                    self.run_q("AnyDesk", cursor=cursor)
                self.assertEqual(caught.exception.detail, "커서가 이 질의에 맞지 않습니다")

    def test_low_items(self) -> None:
        self.assertIn("소문자 'or'", " ".join(parse_query("AnyDesk or SanDisk").warnings))
        with self.assertRaises(QueryError) as caught:
            parse_query("foo(")
        self.assertEqual(caught.exception.position, 4)
        self.assertIn("기간이 0", " ".join(self.run_q("around:(artifacts:eventlog/artifacts/0, 0s)")["query"]["parsed"]["warnings"]))
        self.assertIn("길이가 0", " ".join(self.run_q("time:[2025-05-28T10:30:00.000Z .. 2025-05-28T10:30:00.000Z]")["query"]["parsed"]["warnings"]))
        with self.assertRaises(QueryError) as caught:
            self.run_q("time:[2025-05-28T00:00+25:00 .. 2025-05-29]")
        self.assertIn("시간대 오프셋", caught.exception.detail)
        self.assertFalse(hasattr(engine, "LOCATOR_RE"))

    def test_cursor_keeps_the_effective_sort(self) -> None:
        q = "in:(files, docs, artifacts, indicators, analysis)"
        with mock.patch.object(engine, "SORT_TS_CAP", 2):
            first = self.run_q(q, sort="ts", limit=4)
        self.assertEqual(first["page"]["sort"], "relevance")
        seen = [row["doc_id"] for row in first["rows"]]
        cursor = first["page"]["next_cursor"]
        while cursor:  # later pages without the fallback: the cursor still pages in relevance order
            page = self.run_q(q, sort="ts", limit=4, cursor=cursor)
            self.assertEqual(page["page"]["sort"], "relevance")
            seen.extend(row["doc_id"] for row in page["rows"])
            cursor = page["page"]["next_cursor"]
        self.assertEqual(len(seen), len(set(seen)))
        self.assertEqual(len(seen), first["page"]["total"])

    # -- M4 / M5 -------------------------------------------------------------

    def test_slash_values_are_keywords_unless_a_bare_regex(self) -> None:
        self.assertEqual([(t.field, t.value.text) for t, _neg in parse_query("/usr/bin/ls").terms], [("kw", "/usr/bin/ls")])
        self.assertEqual([(t.field, t.value.kind) for t, _neg in parse_query("/급여.*대장/").terms], [("re", "regex")])
        self.assertEqual(parse_query("path:/users/bsh/*").terms[0][0].value.kind, "token")
        self.assertEqual(self.total("/usr/bin/ls"), 0)
        self.assertEqual(self.total("/급여.*대장/"), 4)

    def test_path_predicates_match_target_paths(self) -> None:
        result = self.run_q(r"path:*\Downloads\*.exe", limit=50)
        kinds = sorted(row["artifact_type"] for row in result["rows"])
        self.assertEqual(kinds, sorted(["file-candidates", "recent-shortcut", "prefetch-file", "amcache-schema-row", "bam-schema-entry", "browser-download"]))
        shortcut = next(row for row in result["rows"] if row["artifact_type"] == "recent-shortcut")
        self.assertEqual(shortcut["target_path"], "C:\\Users\\bsh\\Downloads\\AnyDesk.exe")
        self.assertEqual(self.total(r"under:C:\Users\bsh\Downloads"), 6)
        self.assertEqual(target_path_key("\\VOLUME{01d7-a8f6}\\USERS\\BSH\\X.EXE"), "/users/bsh/x.exe")
        self.assertEqual(target_path({"destlist_path": "su3client://startbytoast/"}), "")

    # -- M8 / perf ------------------------------------------------------------

    def test_deleted_hide_hashset_warns_and_is_ignored(self) -> None:
        created = create_hash_set(name="gone", label="known-good", data=self.fixture["exe_hashes"]["sha256"].encode())
        delete_hash_set(created["id"])
        result = self.run_q("AnyDesk", options=SearchOptions(hide_hashsets=[created["id"]]))
        self.assertEqual(result["page"]["total"], self.total("AnyDesk"))
        self.assertTrue(any("숨길 해시 세트를 찾을 수 없어" in warning for warning in result["query"]["parsed"]["warnings"]))

    def test_first_page_fast_path_matches_the_aggregate_order(self) -> None:
        queries = ["AnyDesk", "급여대장", "eventid:4624", "AnyDesk -in:files", "진료실1 eventid:4624", "in:(eventlog, registry)", "afterhours:false"]
        for q in queries:
            for collapse in (True, False):
                with self.subTest(q=q, collapse=collapse):
                    reference = self.run_q(q, collapse=collapse, limit=1000)
                    fast_ids: list[int] = []
                    cursor = None
                    while True:
                        page = self.run_q(q, collapse=collapse, limit=2, aggregates=False, cursor=cursor)
                        self.assertIsNone(page["page"]["total"])
                        self.assertIsNone(page["facets"])
                        fast_ids.extend(row["doc_id"] for row in page["rows"])
                        cursor = page["page"]["next_cursor"]
                        if cursor is None:
                            break
                    self.assertEqual(fast_ids, [row["doc_id"] for row in reference["rows"]])
                    first = self.run_q(q, collapse=collapse, limit=2, aggregates=False)
                    if first["page"]["next_cursor"]:
                        second = self.run_q(q, collapse=collapse, limit=2, aggregates=False, cursor=first["page"]["next_cursor"])
                        back = self.run_q(q, collapse=collapse, limit=2, aggregates=False, cursor=second["page"]["previous_cursor"])
                        self.assertEqual([row["doc_id"] for row in back["rows"]], [row["doc_id"] for row in first["rows"]])
        with mock.patch.object(engine, "DRIVER_CHUNK", 1), mock.patch.object(engine, "DRIVER_MAX_CHUNKS", 1):
            fallback = self.run_q("AnyDesk -in:files", aggregates=False, limit=2)
        self.assertEqual([row["doc_id"] for row in fallback["rows"]], [row["doc_id"] for row in self.run_q("AnyDesk -in:files", limit=2)["rows"]])

    def test_aggregates_run_the_predicate_once(self) -> None:
        statements: list[str] = []
        original = engine.open_read_only

        def traced(path: Path) -> sqlite3.Connection:
            connection = original(path)
            connection.set_trace_callback(statements.append)
            return connection

        with mock.patch.object(engine, "open_read_only", traced):
            result = self.run_q("AnyDesk", histogram="auto", collapse=True)
        self.assertIsNotNone(result["histogram"])
        fts = [sql for sql in statements if "search_text WHERE text LIKE" in sql]
        self.assertEqual(len(fts), 1, fts)
        statements.clear()
        with mock.patch.object(engine, "open_read_only", traced):
            fast = self.run_q("AnyDesk", aggregates=False)
        self.assertTrue(fast["rows"])
        self.assertFalse(any("INSERT INTO temp.m" in sql for sql in statements))
        self.assertTrue(all("rowid >" in sql or "ORDER BY rowid" in sql for sql in statements if "search_text WHERE text LIKE" in sql))

    def test_budget_cuts_a_slow_statement(self) -> None:
        slow = "d.doc_id IN (WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 200000000) SELECT x FROM c)"
        with mock.patch.object(Compiler, "field_ext", lambda self, term, value, negated: (slow, [])), mock.patch.object(engine, "GRACE_SECONDS", 0.5):
            started = time.monotonic()
            result = self.run_q("ext:exe", budget=Budget(0.3))
        elapsed = time.monotonic() - started
        self.assertTrue(result["truncated"])
        self.assertIn("시간 예산", result["truncated_reason"])
        self.assertLess(elapsed, 0.3 + 0.5 + 1.5)
        self.assertGreater(elapsed, 0.25)


class PayloadFieldTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        cls.payload = build_payload_run(Path(cls.temp.name))
        cls.summary = build_search_index(cls.payload["run_dir"], cls.payload["summary"], run_id="payload")
        cls.index = cls.payload["run_dir"] / INDEX_FILE_NAME
        cls.meta = index_meta(cls.index)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def run_q(self, q: str) -> dict:
        return run_query(self.index, self.meta, QueryRequest(q=q, limit=1000), budget=Budget(15))

    def test_payload_hits_equal_raw_line_counts(self) -> None:
        for term in PAYLOAD_TERMS:
            with self.subTest(term=term):
                expected = raw_line_count(self.payload["records"], term)
                self.assertGreater(expected, 10)
                self.assertEqual(self.run_q(term)["page"]["total"], expected)

    def test_every_cut_is_counted_and_flagged(self) -> None:
        skipped = self.summary["skipped"]
        fields = self.summary["skipped_fields"]
        self.assertGreaterEqual(skipped.get("text-truncated", 0), 1)
        self.assertGreaterEqual(skipped.get("value-truncated", 0), 1)
        self.assertIn("ScriptBlockText", fields["text-truncated"])
        self.assertEqual(fields["value-truncated"].get("Junk"), 1)
        self.assertNotIn("ScriptBlockText", fields.get("value-truncated", {}))
        self.assertEqual(self.summary["truncated_by_domain"], {"eventlog": 1})
        result = self.run_q("TAILMARKER")
        self.assertEqual(result["page"]["total"], 0)
        self.assertTrue(any("잘린 행" in warning for warning in result["query"]["parsed"]["warnings"]))
        flagged = self.run_q("eventid:4104 Junk")
        self.assertTrue(all(row["truncated"] for row in flagged["rows"]))


class IndexSwapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.fixture = build_fixture_run(Path(self.temp.name))
        self.run_dir = self.fixture["run_dir"]
        self.index = self.run_dir / INDEX_FILE_NAME
        build_search_index(self.run_dir, self.fixture["summary"])
        self.old_build = index_meta(self.index)["build_id"]

    def test_failed_swap_keeps_the_old_index_and_drops_building(self) -> None:
        with mock.patch.object(build_module.os, "replace", side_effect=PermissionError("locked")), mock.patch.object(build_module, "SWAP_WAIT_SECONDS", 0.3):
            with self.assertRaises(IndexSwapFailed) as caught:
                build_search_index(self.run_dir, self.fixture["summary"])
        self.assertEqual(caught.exception.summary["status"], "build-failed-swap")
        self.assertIn("이전 색인을 그대로 씁니다", caught.exception.reason)
        self.assertFalse(self.index.with_name(self.index.name + BUILDING_SUFFIX).exists())
        self.assertEqual(index_meta(self.index)["build_id"], self.old_build)

    @unittest.skipUnless(os.name == "nt", "Windows refuses to replace a file another handle holds")
    def test_swap_with_an_open_reader(self) -> None:
        reader = sqlite3.connect(f"{self.index.resolve().as_uri()}?mode=ro", uri=True)
        cursor = reader.execute("SELECT doc_id FROM search_doc")
        cursor.fetchone()
        try:
            with mock.patch.object(build_module, "SWAP_WAIT_SECONDS", 0.5), self.assertRaises(IndexSwapFailed):
                build_search_index(self.run_dir, self.fixture["summary"])
        finally:
            cursor.close()
            reader.close()
        self.assertEqual(index_meta(self.index)["build_id"], self.old_build)
        # A reader that lets go while the swap waits: the swap succeeds.
        reader = sqlite3.connect(f"{self.index.resolve().as_uri()}?mode=ro", uri=True, check_same_thread=False)
        held = reader.execute("SELECT doc_id FROM search_doc")
        held.fetchone()

        def release() -> None:
            held.close()
            reader.close()

        timer = threading.Timer(0.5, release)
        timer.start()
        try:
            result = build_search_index(self.run_dir, self.fixture["summary"])
        finally:
            timer.join()
        self.assertEqual(result["status"], "ready")
        self.assertNotEqual(index_meta(self.index)["build_id"], self.old_build)

    def test_incremental_writer_waits_for_readers(self) -> None:
        connection = open_writable(self.index, bulk=False)
        try:
            self.assertGreaterEqual(int(connection.execute("PRAGMA busy_timeout").fetchone()[0]), 20_000)
        finally:
            connection.close()

    def test_meta_read_retries_a_short_lock_and_reports_corruption(self) -> None:
        original = build_module.open_read_only
        calls = {"n": 0}

        def flaky(path: Path) -> sqlite3.Connection:
            calls["n"] += 1
            if calls["n"] == 1:
                raise sqlite3.OperationalError("database is locked")
            return original(path)

        with mock.patch.object(build_module, "open_read_only", flaky):
            meta, reason = read_index_meta(self.index)
        self.assertIsNone(reason)
        self.assertEqual(meta["build_id"], self.old_build)
        self.index.write_bytes(b"not a database" * 100)
        meta, reason = read_index_meta(self.index)
        self.assertIsNone(meta)
        self.assertIn("손상", reason)

    def test_incremental_merges_skipped(self) -> None:
        connection = sqlite3.connect(self.index)
        try:
            summary = json.loads(connection.execute("SELECT value FROM search_meta WHERE key = 'summary'").fetchone()[0])
            summary["skipped"] = {"earlier-reason": 7}
            connection.execute("UPDATE search_meta SET value = ? WHERE key = 'summary'", (json.dumps(summary),))
            connection.commit()
        finally:
            connection.close()
        write_analysis(self.run_dir, "20251018T000000-ffffffff", "carve", [{"artifact_type": "carve-row", "path": "C:\\x\\a.bin", "details": {"text": "z" * 40000}}])
        result = build_search_index(self.run_dir, self.fixture["summary"], mode="incremental", analysis_ids=["20251018T000000-ffffffff"])
        self.assertEqual(result["skipped"]["earlier-reason"], 7)
        self.assertGreaterEqual(result["skipped"]["text-truncated"], 1)


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required")
class SlotReleaseTests(unittest.TestCase):
    class FakeRequest:
        def __init__(self, gone: threading.Event) -> None:
            self.gone = gone

        async def is_disconnected(self) -> bool:
            return self.gone.is_set()

    def test_disconnect_cancels_the_worker_and_frees_the_slot(self) -> None:
        limiter = QueryLimiter(1)
        gone = threading.Event()
        gone.set()
        seen: dict[str, bool] = {}

        def work(cancel: threading.Event) -> dict[str, object]:
            seen["cancelled"] = cancel.wait(5)
            return {}

        asyncio.run(run_cancellable(self.FakeRequest(gone), work, limiter.acquire("r")))
        self.assertTrue(seen["cancelled"])
        self.assertEqual(limiter.active("r"), 0)

        def boom(cancel: threading.Event) -> dict[str, object]:
            raise ValueError("bad")

        with self.assertRaises(ValueError):
            asyncio.run(run_cancellable(self.FakeRequest(threading.Event()), boom, limiter.acquire("r")))
        self.assertEqual(limiter.active("r"), 0)

    def test_cancelled_request_holds_the_slot_until_the_worker_ends(self) -> None:
        limiter = QueryLimiter(1)
        state: dict[str, object] = {}
        worker_done = threading.Event()

        def work(cancel: threading.Event) -> dict[str, object]:
            time.sleep(0.6)  # a statement that only checks the budget later
            state["cancel_seen"] = cancel.is_set()
            worker_done.set()
            return {}

        async def scenario() -> None:
            task = asyncio.create_task(run_cancellable(self.FakeRequest(threading.Event()), work, limiter.acquire("r")))
            await asyncio.sleep(0.2)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            state["active_after_cancel"] = limiter.active("r")

        asyncio.run(scenario())
        worker_done.wait(5)
        deadline = time.monotonic() + 5
        while limiter.active("r") and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(state["cancel_seen"])
        self.assertEqual(limiter.active("r"), 0)


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required")
class HardeningApiTests(unittest.TestCase):
    TOKEN = "hardening-token"

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(SEARCH_HISTORY.flush)
        base = Path(self.temp.name)
        env = mock.patch.dict(os.environ, {DATA_DIR_ENV: str(base / "data"), AUTO_INDEX_ENV: "1"})
        env.start()
        self.addCleanup(env.stop)
        self.fixture = build_fixture_run(base)
        self.run_dir = self.fixture["run_dir"]
        self.store = RunJobStore()
        self.run_id = self.store.import_completed_run(self.run_dir).run_id
        self.app = create_app(self.store, auth_token=self.TOKEN)
        self.client = TestClient(self.app, headers={"X-RapidTriage-Token": self.TOKEN})
        self.addCleanup(lambda: ANALYSIS_RUNNER.shutdown(owner=self.app.state.analysis_owner))

    def url(self, suffix: str) -> str:
        return f"/api/runs/{self.run_id}{suffix}"

    def build(self) -> dict:
        state = self.client.post(self.url("/search/index/build"), json={"mode": "full"}).json()
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            current = self.client.get(self.url(f"/analyses/{state['analysis_id']}")).json()
            if current["status"] in TERMINAL_STATUSES:
                return current
            time.sleep(0.1)
        self.fail("build did not finish")

    def test_fuzz_never_returns_500(self) -> None:
        self.build()
        for q in ("(" * 40 + "x" + ")" * 40, "NOT " * 40 + "x", "around:(99999999999999999999, 5m)", "size:" + "9" * 30 + "TB",
                  "time:9999", "foo(", "re:/((a+))+b/", "re:/(a|b|ab)*c/"):
            with self.subTest(q=q[:40]):
                response = self.client.post(self.url("/search/query"), json={"q": q})
                self.assertIn(response.status_code, {200, 400}, response.text)
        # A lone surrogate (a valid JSON escape, invalid text): a 4xx, never a 500.
        response = self.client.post(self.url("/search/query"), content=b'{"q": "kw:\\ud800x"}', headers={"Content-Type": "application/json"})
        self.assertIn(response.status_code, {400, 422}, response.text)
        response = self.client.post(self.url("/search/query"), json={"q": "x", "options": {"tz": "+99:00"}})
        self.assertEqual(response.status_code, 400)
        many = [self.client.post("/api/hash-sets", json={"name": f"s{index}", "label": "custom", "lines": f"{index + 1:032x}"}).json()["id"] for index in range(11)]
        response = self.client.post(self.url("/search/query"), json={"q": "x", "options": {"hide_hashsets": many}})
        self.assertEqual(response.status_code, 400, response.text)

    def test_failed_swap_and_corrupt_status(self) -> None:
        self.build()
        with mock.patch.object(build_module.os, "replace", side_effect=PermissionError("locked")), mock.patch.object(build_module, "SWAP_WAIT_SECONDS", 0.2):
            finished = self.build()
        self.assertEqual(finished["status"], "failed")
        self.assertEqual(finished["summary"]["status"], "build-failed-swap")
        status = self.client.get(self.url("/search/index")).json()
        self.assertEqual(status["status"], "build-failed-swap")
        self.assertIn("이전 색인", status["swap_error"])
        self.assertEqual(self.client.post(self.url("/search/query"), json={"q": "SanDisk"}).json()["page"]["total"], 1)
        (self.run_dir / INDEX_FILE_NAME).write_bytes(b"garbage" * 1000)
        status = self.client.get(self.url("/search/index")).json()
        self.assertEqual(status["status"], "corrupt")
        self.assertTrue(status["corrupt_reason"])
        response = self.client.post(self.url("/search/query"), json={"q": "SanDisk"})
        self.assertEqual(response.status_code, 409)

    def test_review_marks_past_the_limit_are_reported(self) -> None:
        self.build()
        database = open_case_database(self.run_dir / "rapidtriage-case.db")
        database.create_case(case_id=f"run-{self.run_id}", name="hardening")
        marks = [{"collection": "artifacts", "kind": "eventlog", "locator": "/artifacts/0", "status": "relevant", "tags": [], "note": ""}]
        with mock.patch("rapidtriage.api.app.run_review.review_map_entries", return_value=(marks, True)):
            result = self.client.post(self.url("/search/query"), json={"q": "review:relevant"}).json()
            overlay = self.client.post(self.url("/search/query"), json={"q": "SanDisk"}).json()
        self.assertEqual(result["page"]["total"], 1)
        self.assertTrue(result["truncated"])
        self.assertIn("50,000건", result["truncated_reason"])
        self.assertNotIn("uses_review", result)
        self.assertFalse(overlay["truncated"])
        self.assertTrue(any("50,000건" in warning for warning in overlay["query"]["parsed"]["warnings"]))

    def test_history_is_async_capped_and_not_in_audit(self) -> None:
        self.build()
        self.client.post(self.url("/search/query"), json={"q": "SanDisk"})
        history = self.client.get(self.url("/search/history")).json()["history"]
        self.assertEqual([item["q"] for item in history], ["SanDisk"])  # no case DB needed
        output_dir = self.run_dir
        for index in range(505):
            SEARCH_HISTORY.record(output_dir, {"q": f"q{index}"}, truncated=False)
        SEARCH_HISTORY.flush()
        history = self.client.get(self.url("/search/history?limit=500")).json()["history"]
        self.assertEqual(len(history), 500)
        self.assertEqual(history[0]["q"], "q504")
        database = open_case_database(self.run_dir / "rapidtriage-case.db")
        database.create_case(case_id=f"run-{self.run_id}", name="hardening")
        self.client.post(self.url("/search/query"), json={"q": "AnyDesk"})
        self.assertEqual(self.client.post(self.url("/search/saved"), json={"name": "x", "q": "AnyDesk"}).status_code, 201)
        SEARCH_HISTORY.flush()
        connection = sqlite3.connect(self.run_dir / "rapidtriage-case.db")
        try:
            actions = [row[0] for row in connection.execute("SELECT action FROM audit_event")]
        finally:
            connection.close()
        self.assertNotIn("search.run", actions)
        self.assertIn("search.saved.create", actions)

    def test_page_only_request_and_histogram_default(self) -> None:
        self.build()
        default = self.client.post(self.url("/search/query"), json={"q": "AnyDesk"}).json()
        self.assertIsNone(default["histogram"])
        self.assertEqual(default["page"]["total"], 4)
        fast = self.client.post(self.url("/search/query"), json={"q": "AnyDesk", "aggregates": False}).json()
        self.assertIsNone(fast["page"]["total"])
        self.assertEqual([row["doc_id"] for row in fast["rows"]], [row["doc_id"] for row in default["rows"]])
        with_histogram = self.client.post(self.url("/search/query"), json={"q": "AnyDesk", "histogram": {"bucket": "auto"}}).json()
        self.assertIsNotNone(with_histogram["histogram"])


if __name__ == "__main__":
    unittest.main()
