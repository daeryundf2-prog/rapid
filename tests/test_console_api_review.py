"""Console API scale (``view=list``, row index, caches, timeline sort): the guarantees a court
examiner relies on.

* Row index: pages read through :mod:`json_rows` equal the full-parse pages for every page
  boundary, filter, sort and layout (LF / CRLF, multi-byte UTF-8, no final line break); a corrupt
  output fails exactly like the full parse; an output appended to while it is indexed, or
  replaced afterwards (even with the same size and mtime), never serves rows at stale offsets.
* Caches are bounded and keyed by the file revision; concurrent pages build one index.
* ``sort=timestamp`` is the console's own order (shared fixture with the frontend test).
* ``view=list`` names everything it leaves out; examiner fields stay; strict query filters and
  output confinement still hold.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import unittest
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import ClassVar
from unittest import mock
from urllib.parse import quote

try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import (
        artifact_filter,
        create_app,
        fs_tree,
        json_rows,
        routes_runs,
        tree,
    )
    from rapidtriage.api.app.evidence_sort import timeline_order
    from rapidtriage.api.app.json_rows import (
        JsonLayoutError,
        JsonRowIndex,
        StaleIndexError,
        large_output_index,
    )
    from rapidtriage.api.app.list_view import (
        DETAILS_NESTED_KEPT,
        project_artifact_row,
        project_details,
    )
    from rapidtriage.api.app.row_conditions import MATCH_CACHE

    HAS_FASTAPI = True
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

from rapidtriage.core.filetime import LOCAL_TIMEZONE_LABELS
from rapidtriage.core.jobs import RunJobStore, invalidate_output_json_cache

TOKEN = "console-api-review-token"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
KIND = "windows-filesystem"


def make_events(count: int) -> list[object]:
    """Synthetic timeline events: instants, offsets, wall clocks, 7-digit fractions, no time,
    unparseable text, multi-byte text, escaped line breaks, an empty object."""
    events: list[object] = []
    zones = (None, "local-unknown", "UTC", "exif-local")
    for i in range(count):
        day, hour = i * 7 % 28 + 1, i * 5 % 24
        stamp = (
            f"2025-03-{day:02d}T{hour:02d}:00:00Z",
            f"2025-03-{day:02d}T{hour:02d}:30:00+09:00",
            None,
            f"2025-03-{day:02d} {hour:02d}:00:00",
            "시각 미상",
            f"2025-03-{day:02d}T{hour:02d}:00:00.1234567Z",
        )[i % 6]
        events.append(
            {
                "timestamp": stamp,
                "timezone": zones[i % 4],
                "event_type": f"이벤트-{i}",
                "source": "원본😀" if i % 5 == 0 else "mft",
                "path": f"C:\\Users\\사용자\\파일{i}.{('txt', 'jpg', 'exe')[i % 3]}",
                "summary": "줄\r\n바꿈" if i % 9 == 0 else f"요약 {i}",
                "details": {
                    "artifact_type": ("document-text", "media-image", "prefetch")[i % 3],
                    "parse_status": "partial" if i % 11 == 0 else "ok",
                    "nested": {"list": [1, {"k": "값"}], "empty": {}},
                    # The timeline's citation of the artifact row (#69: input_file tells two inputs apart).
                    "source_record": {"output": "artifacts_prefetch", "row_index": i, "input_file": f"C:\\입력\\{i % 2}.pf"},
                    "i": i,
                },
            }
        )
    events[3] = {}
    return events


def make_files(count: int) -> dict[str, object]:
    folders = ("a", "a\\하위", "c", "d e")

    def row(i: int, prefix: str) -> dict[str, object]:
        folder = folders[i % len(folders)]
        name = f"{prefix}{i}{'.docx' if i % 2 == 0 else '.jpg'}"
        return {
            "path": f"C:\\Users\\{folder}\\{name}",
            "name": name,
            "categories": ["documents"] if i % 2 == 0 else ["images"],
            "size": i * 10,
            "fs_modified_at": f"2024-0{1 + i % 9}-1{i % 10}T00:00:00Z",
            "meta": {"nested": [i, {"x": "값"}]},
        }

    return {
        "command": "files",
        "root": "C:\\Users",
        "summary": {"candidate_count": count, "category_counts": {"documents": (count + 1) // 2}},
        "candidates": [row(i, "후보") for i in range(count)],
        "duplicate_content_groups": [{"sha256": "ab", "paths": ["a", "b"], "file_count": 2}],
        "inventory": [row(i, "inv") for i in range(count + 3)],
        "hash_cache_manifest": {"entries": 7},
        "trailer": "끝",
    }


def make_artifact(i: int) -> dict[str, object]:
    return {
        "artifact_type": "mft-entry" if i % 3 else "mft-deleted",
        "path": f"C:\\Evidence\\$MFT#{i}\\파일{i}",
        "details": {
            "file_name": f"file{i}.txt",
            "timestamp": f"2025-04-{i % 28 + 1:02d}T00:00:00Z",
            "mft_full_parser_profile": {"stages": [{"name": "mft"}]},
        },
    }


def encode(payload: object, *, crlf: bool = False, final_break: bool = True) -> bytes:
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    if crlf:
        text = text.replace("\n", "\r\n")
    if final_break:
        text += "\r\n" if crlf else "\n"
    return text.encode("utf-8")


def clear_caches() -> None:
    MATCH_CACHE.clear()
    json_rows.clear_index_cache()
    fs_tree.clear_fs_index_cache()
    artifact_filter._KIND_MATCHES.clear()
    tree._KEY_CACHE.clear()
    invalidate_output_json_cache()


def replace_keeping_size_and_mtime(path: Path, data: bytes) -> None:
    """Atomically replace ``path`` with ``data`` (same length) and give it the old mtime."""
    before = path.stat()
    assert len(data) == before.st_size
    temp = path.with_name(path.name + ".new")
    temp.write_bytes(data)
    os.replace(temp, path)
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    after = path.stat()
    assert (after.st_size, after.st_mtime_ns) == (before.st_size, before.st_mtime_ns)


class ReviewRun:
    """One imported run: timeline, files and one JSONL-backed artifact kind, written as given."""

    def __init__(self, base: Path, *, timeline: bytes, files: bytes, jsonl: bytes | None = None) -> None:
        self.dir = base / "run"
        self.dir.mkdir()
        self.paths = {"timeline": self.dir / "rapidtriage-timeline.json", "files": self.dir / "rapidtriage-files.json"}
        self.paths["timeline"].write_bytes(timeline)
        self.paths["files"].write_bytes(files)
        self.records = self.dir / f"{KIND}.jsonl"
        self.records.write_bytes(jsonl if jsonl is not None else b"".join(json.dumps(make_artifact(i)).encode() + b"\n" for i in range(9)))
        kind_path = self.dir / f"artifacts_{KIND}.json"
        kind_path.write_text(
            json.dumps({"record_count": 9, "records_path": str(self.records), "artifacts": [], "summary": {"artifact_count": 9}}, indent=2),
            encoding="utf-8",
        )
        self.paths[f"artifacts_{KIND}"] = kind_path
        summary_path = self.dir / "rapidtriage-run-summary.json"
        outputs = {name: str(path) for name, path in self.paths.items()}
        outputs["summary"] = str(summary_path)
        summary_path.write_text(
            json.dumps(
                {
                    "profile_version": "rapidtriage-run-summary-v1",
                    "mode": "hacking",
                    "root": str(base / "evidence"),
                    "output_dir": str(self.dir),
                    "source": {"type": "directory", "analysis_root": str(base / "evidence")},
                    "outputs": outputs,
                    "summary": {"counts": {"artifacts": 9}},
                }
            ),
            encoding="utf-8",
        )
        self.store = RunJobStore()
        self.run_id = self.store.import_completed_run(self.dir).run_id
        self.client = TestClient(
            create_app(self.store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN}, raise_server_exceptions=False
        )

    def get(self, endpoint: str, query: str = "") -> tuple[int, object]:
        """``(status, body)``; a server error's body (a unique crash id) is left out."""
        response = self.client.get(f"/api/runs/{self.run_id}/{endpoint}?{query}")
        if response.status_code >= 500:
            return response.status_code, None
        return response.status_code, response.json()


def indexed(enabled: bool) -> mock._patch:  # type: ignore[type-arg]
    """Row index for every output (``True``) or never (``False``: the full-parse path)."""
    return mock.patch.object(json_rows, "OUTPUT_JSON_CACHE_MAX_BYTES", 0 if enabled else 1 << 60)


def timeline_queries(count: int) -> list[str]:
    queries = [f"offset={offset}&limit={limit}" for limit in (1, 2, 5, count - 1, count, count + 5) for offset in range(count + 2)]
    queries += ["cursor=offset:4&limit=3", "offset=2&limit=3&view=list", "limit=0"]
    filters = [
        "from=2025-03-05T00:00:00Z&to=2025-03-20T23:59:59Z",
        "weekday=mon,sat",
        "hours=22-06&tz=%2B09:00",
        "partial=1",
        "content=document",
        "offhours=1",
    ]
    sorts = ["sort=timestamp", "sort=timestamp&order=desc", "sort=timestamp:desc", "sort=timestamp:asc&order=desc"]
    for condition in filters:
        queries += [f"{condition}&offset={offset}&limit={limit}" for limit in (1, 3, 50) for offset in (0, 1, 2, 5, 17, count)]
    for sort in sorts:
        queries += [f"{sort}&offset={offset}&limit={limit}" for limit in (1, 4, 50) for offset in range(0, count + 1, 3)]
        queries += [f"{sort}&limit=5&locate={locate}" for locate in (0, 5, count - 1, 999)]
        queries += [f"{sort}&{condition}&offset={offset}&limit=4&locate=6&view=list" for condition in filters for offset in (0, 4)]
    return queries


def files_queries(count: int) -> list[str]:
    queries: list[str] = []
    for scope in ("", "scope=inventory&"):
        queries += [f"{scope}offset={offset}&limit={limit}" for limit in (1, 3, count) for offset in range(count + 4)]
        queries += [f"{scope}limit=4&view=list", f"{scope}cursor=offset:2&limit=2"]
        for folder in ("a", "a/하위", "c", "d e", ""):
            for recursive in ("", "&recursive=1"):
                prefix = f"{scope}path_prefix={quote(folder)}{recursive}"
                queries += [f"{prefix}&offset={offset}&limit={limit}" for limit in (1, 2, 50) for offset in (0, 1, 3)]
                queries.append(f"{prefix}&limit=3&view=list")
        queries += [f"{scope}category=documents&limit=3&offset=1", f"{scope}from=2024-03-01&limit=5"]
    return queries


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for API tests")
class RowIndexDifferentialTests(unittest.TestCase):
    """New (row index) against old (full parse) over generated outputs."""

    def setUp(self) -> None:
        clear_caches()
        self.addCleanup(clear_caches)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.count = 0

    def make_run(self, timeline: bytes, files: bytes, name: str) -> ReviewRun:
        base = Path(self.temp.name) / name
        base.mkdir()
        return ReviewRun(base, timeline=timeline, files=files)

    def responses(self, run: ReviewRun, endpoint: str, queries: Iterable[str], *, enabled: bool) -> dict[str, tuple[int, object]]:
        clear_caches()
        with indexed(enabled):
            # Twice: the second pass reads the cached index / matches / orders.
            first = {query: run.get(endpoint, query) for query in queries}
            second = {query: run.get(endpoint, query) for query in queries}
        self.assertEqual(first, second, endpoint)
        return first

    def assert_same_pages(self, run: ReviewRun, endpoint: str, queries: list[str]) -> None:
        old = self.responses(run, endpoint, queries, enabled=False)
        new = self.responses(run, endpoint, queries, enabled=True)
        for query in queries:
            self.assertEqual(new[query], old[query], f"{endpoint}?{query}")
        self.assertTrue(any(status == 200 for status, _body in old.values()))

    def test_every_page_filter_and_sort_matches_the_full_parse(self) -> None:
        events, files = make_events(23), make_files(11)
        layouts = [(False, True), (True, True), (False, False), (True, False)]
        for number, (crlf, final_break) in enumerate(layouts):
            with self.subTest(crlf=crlf, final_break=final_break):
                run = self.make_run(
                    encode({"command": "timeline", "events": events, "summary": {"n": 23}}, crlf=crlf, final_break=final_break),
                    encode(files, crlf=crlf, final_break=final_break),
                    f"layout{number}",
                )
                self.assertIsNotNone(JsonRowIndex.build(run.paths["timeline"]))
                self.assertIsNotNone(JsonRowIndex.build(run.paths["files"]))
                self.assert_same_pages(run, "timeline", timeline_queries(len(events)))
                self.assert_same_pages(run, "files", files_queries(11))

    def test_index_path_does_not_parse_the_whole_output(self) -> None:
        run = self.make_run(encode({"command": "timeline", "events": make_events(23)}), encode(make_files(11)), "reads")
        reads: list[str] = []
        original = run.store.read_output

        def tracked(run_id: str, name: str) -> dict[str, object]:
            reads.append(name)
            return original(run_id, name)

        queries = ["limit=3", "offset=7&limit=4&view=list", "sort=timestamp&order=desc&limit=5", "partial=1&limit=2&sort=timestamp"]
        with indexed(True), mock.patch.object(run.store, "read_output", tracked):
            for query in queries:
                self.assertEqual(run.get("timeline", query)[0], 200, query)
            for query in ["limit=3", "scope=inventory&offset=2&limit=2", "path_prefix=a&recursive=1&limit=5"]:
                self.assertEqual(run.get("files", query)[0], 200, query)
        self.assertEqual(reads, [])

    def test_large_member_values_are_bounded_but_still_served(self) -> None:
        run = self.make_run(encode({"command": "timeline", "events": make_events(23)}), encode(make_files(11)), "values")
        expected = run.get("files", "limit=2")
        with mock.patch.object(json_rows, "VALUE_CACHE_MAX_BYTES", 64):
            index = JsonRowIndex.build(run.paths["files"])
            self.assertLessEqual(index._value_bytes, 64)
            self.assertEqual(index.value("duplicate_content_groups"), make_files(11)["duplicate_content_groups"])
            self.assertLessEqual(index._value_bytes, 64)
            clear_caches()
            with indexed(True):
                self.assertEqual(run.get("files", "limit=2"), expected)

    def test_corrupt_outputs_fail_exactly_like_the_full_parse(self) -> None:
        valid = encode({"command": "timeline", "events": [{"timestamp": "2025-01-01T00:00:00Z", "event_type": f"e{i}", "n": "a    b"} for i in range(6)]})
        text = valid.decode()
        # Invalid JSON fails (500) on both paths; valid JSON whose layout the index cannot frame
        # exactly (joined element lines, a blank line) gets no index and is served by the full parse.
        variants = {
            # A raw line break inside a string whose second half looks like an element line.
            "split-line": text.replace('"a    b"', '"a\n    b"', 1),
            "missing-comma": text.replace("},\n    {", "}\n    {", 1),
            "trailing-comma": text.replace("}\n  ]", "},\n  ]", 1),
            "junk-line": text.replace("},\n    {", "},\n      junk\n    {", 1),
            "bad-element": text.replace('"e2"', '"e2', 1),
            "joined-elements": text.replace("},\n    {", "},    {", 1),
            "truncated": text[: len(text) // 2],
            "bad-member-gap": text.replace(',\n  "events"', ',\n\n  "events"', 1),
            "bom": "\ufeff" + text,
        }
        queries = ["limit=2", "offset=4&limit=2", "sort=timestamp&limit=3", "from=2024-01-01&limit=3"]
        for number, (name, broken) in enumerate(variants.items()):
            with self.subTest(variant=name):
                run = self.make_run(broken.encode(), encode(make_files(3)), f"corrupt{number}")
                with self.assertRaises(JsonLayoutError):
                    JsonRowIndex.build(run.paths["timeline"])
                with indexed(True):
                    self.assertIsNone(large_output_index(run.paths["timeline"]))
                old = self.responses(run, "timeline", queries, enabled=False)
                new = self.responses(run, "timeline", queries, enabled=True)
                self.assertEqual(new, old)
                try:
                    json.loads(broken)
                    expected = 200
                except ValueError:
                    expected = 500
                self.assertTrue(all(status == expected for status, _body in old.values()), old)

    def test_output_appended_while_indexed_is_not_cached(self) -> None:
        run = self.make_run(encode({"command": "timeline", "events": make_events(9)}), encode(make_files(3)), "append")
        path = run.paths["timeline"]
        feed = json_rows._LayoutScan.feed
        appended: list[bool] = []

        def feed_and_append(scan: object, region: bytes, base: int) -> None:
            if not appended:
                appended.append(True)
                with path.open("ab") as handle:
                    handle.write(b"\n")  # still valid JSON: trailing whitespace
            feed(scan, region, base)  # type: ignore[arg-type]

        expected = self.responses(run, "timeline", ["limit=4", "sort=timestamp&limit=4"], enabled=False)
        clear_caches()
        with indexed(True), mock.patch.object(json_rows._LayoutScan, "feed", feed_and_append):
            self.assertIsNone(large_output_index(path))
            self.assertEqual(json_rows.INDEX_CACHE._items, {})
            self.assertEqual(run.get("timeline", "limit=4"), expected["limit=4"])
        with indexed(True):
            self.assertIsNotNone(large_output_index(path))
            self.assertEqual(run.get("timeline", "sort=timestamp&limit=4"), expected["sort=timestamp&limit=4"])


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for API tests")
class RevisionTests(unittest.TestCase):
    """Every cache follows the file it was built from: a rewritten output never serves stale rows."""

    def setUp(self) -> None:
        clear_caches()
        self.addCleanup(clear_caches)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.events = make_events(12)
        self.run = ReviewRun(Path(self.temp.name), timeline=encode({"command": "timeline", "events": self.events}), files=encode(make_files(8)))

    def rewritten_events(self) -> bytes:
        """The same byte length, other rows (ASCII letters swapped)."""
        data = self.run.paths["timeline"].read_bytes()
        changed = data.replace(b'"source": "mft"', b'"source": "MFT"').replace(b"T03:00:00Z", b"T23:00:00Z")
        self.assertNotEqual(changed, data)
        return changed

    def test_replaced_output_with_the_same_size_and_mtime_is_reindexed(self) -> None:
        queries = ["limit=4", "sort=timestamp&limit=12", "sort=timestamp&partial=1&limit=5"]
        with indexed(True):
            before = {query: self.run.get("timeline", query) for query in queries}
            replace_keeping_size_and_mtime(self.run.paths["timeline"], self.rewritten_events())
            after = {query: self.run.get("timeline", query) for query in queries}
        clear_caches()
        with indexed(False):
            fresh = {query: self.run.get("timeline", query) for query in queries}
        self.assertEqual(after, fresh)
        self.assertNotEqual(after, before)

    def test_index_reads_check_the_file_revision(self) -> None:
        index = JsonRowIndex.build(self.run.paths["timeline"])
        self.assertEqual(index.rows("events", 0, 2), self.events[:2])
        replace_keeping_size_and_mtime(self.run.paths["timeline"], self.rewritten_events())
        with self.assertRaises(StaleIndexError):
            index.rows("events", 0, 2)
        with self.assertRaises(StaleIndexError):
            JsonRowIndex.build(self.run.paths["timeline"], index.revision)

    def test_an_index_gone_stale_during_a_request_falls_back_to_the_full_parse(self) -> None:
        with indexed(True):
            stale = {name: large_output_index(self.run.paths[name]) for name in ("timeline", "files")}
        self.assertTrue(all(stale.values()))
        replace_keeping_size_and_mtime(self.run.paths["timeline"], self.rewritten_events())
        files = self.run.paths["files"].read_bytes()
        replace_keeping_size_and_mtime(self.run.paths["files"], files.replace("후보".encode(), "后补".encode()))
        queries = {
            "timeline": ["limit=4", "sort=timestamp&order=desc&limit=6", "partial=1&limit=3"],
            "files": ["limit=3", "path_prefix=a&limit=3", "scope=inventory&path_prefix=c&recursive=1&limit=2"],
        }
        clear_caches()
        with indexed(False):
            fresh = {(endpoint, query): self.run.get(endpoint, query) for endpoint, items in queries.items() for query in items}
        clear_caches()

        def stale_index(path: Path) -> JsonRowIndex:
            return stale["timeline" if "timeline" in Path(path).name else "files"]  # type: ignore[return-value]

        with indexed(True), mock.patch.object(routes_runs, "large_output_index", stale_index):
            for (endpoint, query), expected in fresh.items():
                self.assertEqual(self.run.get(endpoint, query), expected, (endpoint, query))

    def test_kind_matches_follow_the_jsonl_revision(self) -> None:
        query = f"kind={KIND}&artifact_type=mft-entry&limit=3&offset=1"
        before = self.run.get("artifacts", query)
        rows = self.run.records.read_bytes()
        replace_keeping_size_and_mtime(self.run.records, rows.replace(b"file", b"FILE"))
        after = self.run.get("artifacts", query)
        with mock.patch.object(artifact_filter, "kind_matches", return_value=None):
            streamed = self.run.get("artifacts", query)
        self.assertEqual(after, streamed)
        self.assertNotEqual(after, before)

    def test_tree_head_scan_cache_follows_the_revision(self) -> None:
        path = self.run.paths["files"]
        self.assertEqual(tree.read_output_key(path, "summary"), make_files(8)["summary"])
        replace_keeping_size_and_mtime(path, path.read_bytes().replace(b'"candidate_count": 8', b'"candidate_count": 9'))
        self.assertEqual(tree.read_output_key(path, "summary")["candidate_count"], 9)


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for API tests")
class CacheBoundTests(unittest.TestCase):
    def setUp(self) -> None:
        clear_caches()
        self.addCleanup(clear_caches)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.run = ReviewRun(Path(self.temp.name), timeline=encode({"command": "timeline", "events": make_events(9)}), files=encode(make_files(5)))

    def test_one_index_per_file_and_at_most_index_cache_size(self) -> None:
        with indexed(True):
            first = large_output_index(self.run.paths["timeline"])
            self.run.paths["timeline"].write_bytes(encode({"command": "timeline", "events": make_events(10)}))
            second = large_output_index(self.run.paths["timeline"])
            self.assertIsNot(first, second)
            self.assertEqual(len(json_rows.INDEX_CACHE._items), 1)  # the new revision replaced the old one
            for number in range(json_rows.INDEX_CACHE_SIZE + 3):
                extra = Path(self.temp.name) / f"extra{number}.json"
                extra.write_bytes(encode({"rows": [number]}))
                self.assertIsNotNone(large_output_index(extra))
            self.assertLessEqual(len(json_rows.INDEX_CACHE._items), json_rows.INDEX_CACHE_SIZE)

    def test_kind_match_cache_is_bounded_and_pages_stay_identical(self) -> None:
        queries = [f"kind={KIND}&path_contains=MFT&limit=2&offset={offset}" for offset in range(10)]
        with mock.patch.object(artifact_filter, "kind_matches", return_value=None):
            streamed = [self.run.get("artifacts", query) for query in queries]
        with mock.patch.object(artifact_filter, "KIND_MATCH_CACHE_MAX_MATCHES", 4):
            self.assertEqual([self.run.get("artifacts", query) for query in queries], streamed)
            self.assertEqual(artifact_filter._KIND_MATCHES, {})  # 9 matches > 4: never cached
            small = [self.run.get("artifacts", f"kind={KIND}&artifact_type=mft-deleted&limit=2&offset={offset}") for offset in range(4)]
            self.assertEqual(sum(len(item.records) for item in artifact_filter._KIND_MATCHES.values() if item), 3)
        with mock.patch.object(artifact_filter, "kind_matches", return_value=None):
            self.assertEqual(small, [self.run.get("artifacts", f"kind={KIND}&artifact_type=mft-deleted&limit=2&offset={offset}") for offset in range(4)])

    def test_tree_key_cache_is_bounded_by_size(self) -> None:
        with mock.patch.object(tree, "KEY_CACHE_MAX_CHARS", 40):
            for name in ("files", "timeline"):
                tree.read_output_key(self.run.paths[name], "command")
            tree.read_output_key(self.run.paths["files"], "summary")  # longer than the whole budget
            self.assertLessEqual(sum(length for _value, length in tree._KEY_CACHE.values()), 40)
            self.assertEqual(tree.read_output_key(self.run.paths["files"], "summary"), make_files(5)["summary"])


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for API tests")
class ConcurrencyTests(unittest.TestCase):
    def setUp(self) -> None:
        clear_caches()
        self.addCleanup(clear_caches)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.run = ReviewRun(Path(self.temp.name), timeline=encode({"command": "timeline", "events": make_events(40)}), files=encode(make_files(20)))

    def test_concurrent_pages_equal_sequential_pages_and_build_each_index_once(self) -> None:
        requests = [("timeline", q) for q in ("limit=5", "offset=13&limit=7", "sort=timestamp&limit=9", "sort=timestamp:desc&partial=1&limit=4")]
        requests += [("files", q) for q in ("limit=4", "path_prefix=a&recursive=1&limit=3", "scope=inventory&offset=5&limit=5")]
        with indexed(False):
            expected = {request: self.run.get(*request) for request in requests}
        clear_caches()
        builds: list[str] = []
        lock = threading.Lock()
        build = JsonRowIndex.build.__func__  # type: ignore[attr-defined]

        def counted(cls: type[JsonRowIndex], path: Path, revision: object = None) -> JsonRowIndex:
            with lock:
                builds.append(Path(path).name)
            return build(cls, path, revision)

        work = requests * 6
        with indexed(True), mock.patch.object(JsonRowIndex, "build", classmethod(counted)), ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda request: (request, self.run.get(*request)), work))
        for request, result in results:
            self.assertEqual(result, expected[request], request)
        self.assertEqual(sorted(builds), sorted({"rapidtriage-timeline.json", "rapidtriage-files.json"}))


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for API tests")
class TimelineSortParityTests(unittest.TestCase):
    """``sort=timestamp`` is the console's former client-side order (frontend/src/api/timelineSortParity.test.ts)."""

    def setUp(self) -> None:
        self.fixture = json.loads((FIXTURES / "timeline-sort-parity.json").read_text(encoding="utf-8"))

    def test_wall_clock_labels_are_the_timelines_and_the_consoles(self) -> None:
        # The timeline keeps these offset-free wall clocks apart from UTC instants (core.timeline);
        # the console sorts them as their own group (utils/time.ts WALL_CLOCK_ZONES).
        source = FIXTURES.parents[1] / "frontend" / "src" / "utils" / "time.ts"
        if not source.is_file():
            self.skipTest("frontend sources are not part of this checkout")
        block = re.search(r"WALL_CLOCK_ZONES[^=]*=\s*\{(.*?)\}", source.read_text(encoding="utf-8"), re.DOTALL)
        assert block is not None
        self.assertEqual(frozenset(re.findall(r'"?([\w-]+)"?\s*:', block.group(1))), LOCAL_TIMEZONE_LABELS)

    def test_order_matches_the_shared_fixture(self) -> None:
        self.assertEqual(list(timeline_order(self.fixture["events"], "asc")), self.fixture["asc"])
        self.assertEqual(list(timeline_order(self.fixture["events"], "desc")), self.fixture["desc"])

    def test_api_pages_follow_that_order_through_both_paths(self) -> None:
        clear_caches()
        self.addCleanup(clear_caches)
        events = [event for event in self.fixture["events"] if isinstance(event, dict)]
        with tempfile.TemporaryDirectory() as temp:
            run = ReviewRun(Path(temp), timeline=encode({"command": "timeline", "events": events}), files=encode(make_files(2)))
            for order in ("asc", "desc"):
                expected = list(timeline_order(events, order))
                for enabled in (False, True):
                    with indexed(enabled):
                        positions = [
                            row["record_index"]
                            for offset in range(0, len(events), 7)
                            for row in run.get("timeline", f"sort=timestamp&order={order}&offset={offset}&limit=7")[1]["events"]
                        ]
                    self.assertEqual(positions, expected, (order, enabled))


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for API tests")
class ListViewDisclosureTests(unittest.TestCase):
    DETAILS: ClassVar[dict[str, object]] = {
        "timestamp": "2025-01-01T00:00:00Z",
        "timestamp_timezone": "local-unknown",
        "timestamp_utc_ticks": "133800000000000000",
        "timestamp_kind": "modified",
        "risk_flags": ["deleted", "timestomp"],
        "parse_status": "partial",
        "recovered": True,
        "source_offset": 4096,
        "record_sha256": "ab" * 32,
        "volumes": [{"volume_device_path": "\\Device\\HarddiskVolume3", "volume_serial_number": "1234"}],
        "attachments": [{"filename": "사진.jpg", "size": 10}, "loose.txt"],
        "recovery": {"status": "recovered", "method": "slack", "blocks": [{"offset": 1, "length": 2}], "source": {"lba": 9}},
        "coverage": {"status": "partial", "missing_ranges": [[0, 10]]},
        "raw": {"sender": "kim", "nested": {"a": 1}},
        "commercial_uplift_evidence": {"source_refs": ["service:Slack"], "grade": "B"},
        "citation_manifest": {"pointer": "/artifacts/3", "hashes": {"sha256": "cd"}},
        "mft_full_parser_profile": {"stages": [{"name": "mft"}]},
        "rows": [[1, 2]],
    }

    def test_every_value_left_out_is_named(self) -> None:
        kept, omitted = project_details(self.DETAILS)
        for key, value in self.DETAILS.items():
            if key not in kept:
                self.assertIn(key, omitted)
                continue
            if isinstance(value, dict) and key in DETAILS_NESTED_KEPT:
                for member, item in value.items():
                    if member in kept[key]:  # type: ignore[operator]
                        self.assertEqual(kept[key][member], item)  # type: ignore[index]
                    else:
                        self.assertIn(f"{key}.{member}", omitted)
            else:
                self.assertEqual(kept[key], value)
        self.assertEqual(
            omitted,
            ["citation_manifest", "commercial_uplift_evidence.grade", "coverage.missing_ranges", "mft_full_parser_profile", "raw.nested", "recovery.source", "rows"],
        )

    def test_examiner_fields_stay_in_the_list_row(self) -> None:
        row = {"artifact_type": "mft-entry", "flags": [{"id": "F1", "grade": "A"}], "artifact_record": {"source": {"hashes": {"sha256": "ef"}}}, "details": self.DETAILS}
        projected = project_artifact_row(row)
        assert isinstance(projected, dict)
        details = projected["details"]
        for key in ("timestamp", "timestamp_timezone", "timestamp_utc_ticks", "timestamp_kind", "risk_flags", "parse_status", "recovered", "source_offset", "record_sha256", "volumes", "attachments"):
            self.assertEqual(details[key], self.DETAILS[key], key)
        self.assertEqual(details["recovery"], {"status": "recovered", "method": "slack", "blocks": [{"offset": 1, "length": 2}]})
        self.assertEqual(details["coverage"], {"status": "partial"})
        self.assertEqual(projected["flags"], row["flags"])
        self.assertEqual(projected["artifact_record"], row["artifact_record"])
        self.assertIn("citation_manifest", projected["details_omitted"])

    def test_files_and_timeline_rows_are_never_cut(self) -> None:
        clear_caches()
        self.addCleanup(clear_caches)
        with tempfile.TemporaryDirectory() as temp:
            run = ReviewRun(Path(temp), timeline=encode({"command": "timeline", "events": make_events(6)}), files=encode(make_files(4)))
            for endpoint, rows_key, query in (("timeline", "events", "limit=6"), ("files", "candidates", "limit=4"), ("timeline", "events", "sort=timestamp&limit=6")):
                full = run.get(endpoint, query)[1]
                lean = run.get(endpoint, f"{query}&view=list")[1]
                self.assertEqual(lean[rows_key], full[rows_key], endpoint)  # type: ignore[index]
                self.assertEqual(lean["view"], "list")  # type: ignore[index]
                omitted = set(lean.get("view_omitted", []))  # type: ignore[union-attr]
                for key in full:  # type: ignore[union-attr]
                    self.assertTrue(key in lean or key in omitted, (endpoint, key))
                for name in full["pagination"]:  # type: ignore[index]
                    self.assertTrue(name in lean["pagination"] or f"pagination.{name}" in omitted, (endpoint, name))  # type: ignore[index]


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for API tests")
class QueryAndConfinementTests(unittest.TestCase):
    def setUp(self) -> None:
        clear_caches()
        self.addCleanup(clear_caches)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.run = ReviewRun(Path(self.temp.name), timeline=encode({"command": "timeline", "events": make_events(6)}), files=encode(make_files(4)))

    def test_unknown_options_are_still_rejected(self) -> None:
        cases = [
            ("timeline", "view=list&bogus=1", "bogus"),
            ("timeline", "sort=timestamp&limit=5&event_idx=1", "event_idx"),
            ("files", "view=list&nope=1", "nope"),
            ("artifacts", f"view=list&kind={KIND}&event_idx=1102", "event_idx"),
            ("docs", "view=list", "view"),
            ("timeline-histogram", "view=list", None),
        ]
        for endpoint, query, unknown in cases:
            with self.subTest(endpoint=endpoint, query=query):
                status, body = self.run.get(endpoint, query)
                if unknown is None:
                    self.assertEqual(status, 200)  # no strict filter on this route (unchanged)
                    continue
                self.assertEqual(status, 422, body)
                self.assertIn(unknown, body["detail"]["unsupported_filters"])  # type: ignore[index]

    def test_paging_sort_and_view_are_never_echoed_as_filters(self) -> None:
        for indexed_path in (False, True):
            with indexed(indexed_path):
                status, body = self.run.get("timeline", "view=list&sort=timestamp&order=desc&locate=1&limit=2&partial=1")
            self.assertEqual(status, 200)
            self.assertEqual(body["applied_filters"], {"partial": ["1"]})  # type: ignore[index]
            status, body = self.run.get("files", "view=list&limit=2&path_prefix=a")
            self.assertEqual(body["applied_filters"], {"path_prefix": ["a"]})  # type: ignore[index]

    def test_run_ids_and_output_names_cannot_escape_the_run(self) -> None:
        client = self.run.client
        for path in ("/api/runs/..%2F..%2Fetc/timeline?limit=1", "/api/runs/%2E%2E/files?limit=1&view=list"):
            self.assertIn(client.get(path).status_code, (404, 422), path)
        for kind in ("../../rapidtriage-timeline", "..%2Ffiles", "/etc/passwd"):
            status, body = self.run.get("artifacts", f"kind={quote(kind, safe='')}&limit=1&view=list")
            self.assertNotEqual(status, 500, body)
            if status == 200:
                self.assertEqual(body["artifacts"], {})  # type: ignore[index]

    def test_an_output_outside_the_run_is_refused_on_the_index_paths(self) -> None:
        outside = Path(self.temp.name) / "outside-timeline.json"
        outside.write_bytes(encode({"command": "timeline", "events": make_events(4)}))
        summary_path = self.run.dir / "rapidtriage-run-summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary["outputs"]["timeline"] = str(outside)
        summary_path.write_text(json.dumps(summary), encoding="utf-8")
        store = RunJobStore()
        run_id = store.import_completed_run(self.run.dir).run_id
        client = TestClient(create_app(store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN}, raise_server_exceptions=False)
        with indexed(True):
            for query in ("limit=2", "limit=2&view=list", "sort=timestamp&limit=2", "partial=1&limit=2"):
                self.assertEqual(client.get(f"/api/runs/{run_id}/timeline?{query}").status_code, 403, query)


if __name__ == "__main__":
    unittest.main()
