"""R6 S3 갈래 B: ``GET /files`` row-condition paging cache (plan r6 §3.3, Q-S3-4 / 5 / 8).

The column index (``files_index``) must select exactly the rows -- in the same order -- that the
per-page scans did before it (reference copies of the old ``filter_files_by_category`` /
``filter_files_rows`` below), for categories × conditions × flags × path restriction, including
acquisition copies whose time comes from the NTFS join.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import random
import stat
import tempfile
import unittest
from collections.abc import Callable, Collection, Mapping, Sequence
from pathlib import Path
from unittest import mock

from rapidtriage.api.app import files_index, files_ntfs
from rapidtriage.api.app.artifact_filter import (
    ARTIFACT_PATH_FILTER_SCAN_CAP,
    file_row_categories,
    files_page_base,
    filter_files_by_category,
)
from rapidtriage.api.app.files_index import (
    fast_path_extension,
    files_matched_positions,
    files_row_time_us,
)
from rapidtriage.api.app.row_conditions import (
    CONTENT_TYPES,
    MATCH_CACHE,
    needs_ntfs_time,
    parse_moment,
    parse_row_conditions,
    path_extension,
    row_time,
)
from rapidtriage.api.app.triage_flags import (
    FLAGS_SORT_KEY,
    FlagQuery,
    filter_files_rows,
)

try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import create_app

    HAS_FASTAPI = True
except ImportError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

from rapidtriage.core.jobs import RunJobStore

TOKEN = "r6-s3-files-cache-token"
_EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)


# --- reference copies of the pre-R6 implementation ------------------------------------------------


def old_filter_files_by_category(
    payload: Mapping[str, object],
    categories: Collection[str],
    *,
    offset: int,
    limit: int,
    collection: str = "candidates",
    scan_cap: int = ARTIFACT_PATH_FILTER_SCAN_CAP,
    row_filter: Callable[[Mapping[str, object]], bool] | None = None,
    rows: Sequence[object] | None = None,
) -> dict[str, object]:
    wanted = frozenset(categories)
    source: Sequence[object] = rows if rows is not None else (payload.get(collection) if isinstance(payload.get(collection), list) else [])  # type: ignore[assignment]
    page_rows: list[object] = []
    matched = 0
    scanned = 0
    exhausted = True
    for record_index, row in enumerate(source):
        if scanned >= scan_cap:
            exhausted = False
            break
        scanned += 1
        if wanted:
            values = file_row_categories(row, collection)
            if not values or wanted.isdisjoint(values):
                continue
        if row_filter is not None and not (isinstance(row, Mapping) and row_filter(row)):
            continue
        if matched >= offset and (limit <= 0 or len(page_rows) < limit):
            page_rows.append({**row, "record_index": record_index})  # type: ignore[dict-item]
        matched += 1
    total = matched if exhausted else None
    has_more = (offset + len(page_rows) < matched) if limit > 0 else False
    page = files_page_base(payload, collection)
    page[collection] = page_rows
    page["record_count"] = len(source)
    page["matched"] = total
    page["pagination"] = {
        "collection": collection,
        "offset": offset,
        "limit": limit,
        "returned": len(page_rows),
        "total": total,
        "matched": total,
        "next_offset": offset + len(page_rows) if has_more else None,
        "previous_offset": max(0, offset - limit) if offset > 0 and limit > 0 else None,
        "has_more": has_more or not exhausted,
        "filtered": True,
        "categories": sorted(wanted) if wanted else None,
        "scanned": scanned,
        "truncated": not exhausted,
    }
    return page


def old_filter_files_rows(
    rows: Sequence[object],
    *,
    collection: str,
    join,
    query: FlagQuery,
    categories: frozenset[str] | None,
    offset: int,
    limit: int,
    restrict: Sequence[int] | None = None,
    row_filter: Callable[[Mapping[str, object]], bool] | None = None,
) -> tuple[list[object], dict[str, object]]:
    kind = f"files:{collection}"
    eligible: set[int] | None = None
    if query.filtered:
        eligible = set(join.require_index().matching(kind, query.rule_ids, query.grade))
    order: list[int] = []
    for record_index in restrict if restrict is not None else range(len(rows)):
        row = rows[record_index]
        if eligible is not None and record_index not in eligible:
            continue
        if categories:
            values = file_row_categories(row, collection)
            if not values or categories.isdisjoint(values):
                continue
        if row_filter is not None and not (isinstance(row, Mapping) and row_filter(row)):
            continue
        order.append(record_index)
    if query.sort and join.index is not None:
        index = join.index
        order.sort(key=lambda item: (index.best_rank(kind, item), item))
    window = order[offset : offset + limit] if limit > 0 else order[offset:]
    page_rows = [{**rows[item], "record_index": item} for item in window if isinstance(rows[item], dict)]  # type: ignore[dict-item]
    has_more = limit > 0 and offset + len(window) < len(order)
    pagination: dict[str, object] = {
        "collection": collection,
        "offset": offset,
        "limit": limit,
        "returned": len(page_rows),
        "total": len(order),
        "matched": len(order),
        "next_offset": offset + len(window) if has_more else None,
        "previous_offset": max(0, offset - limit) if offset > 0 and limit > 0 else None,
        "has_more": has_more,
        "filtered": bool(eligible is not None or categories or restrict is not None or row_filter is not None),
        "categories": sorted(categories) if categories else None,
        "flags": query.descriptor(),
        "scanned": len(restrict) if restrict is not None else len(rows),
        "truncated": False,
    }
    if query.sort:
        pagination["sort"] = FLAGS_SORT_KEY
    return page_rows, pagination


# --- synthetic rows ------------------------------------------------------------------------------

TIME_VALUES: tuple[object, ...] = (
    "2025-05-03T12:00:00Z",
    "2025-05-04T01:30:00Z",
    "2025-05-05T18:59:59Z",
    "2025-05-03 21:00:00",
    "2025-05-03T21:00:00+09:00",
    "2025-05-06T08:15:00-03:30",
    "2025-05-03T21:00:00.1234567Z",
    "2025-05-03T21:00:00.5Z",
    "2025-13-03T21:00:00Z",
    "2025-05-03T21:00Z",
    "２０２５-05-03T12:00:00Z",
    "0001-01-01T00:00:00+09:00",
    "0001-01-01T05:00:00Z",
    "9999-12-31T23:59:59-05:00",
    "9999-12-31T20:00:00Z",
    "2024-03-10T06:30:00Z",
    "2024-03-10T07:30:00Z",
    "2024-11-03T05:30:00Z",
    "2024-11-03T06:30:00Z",
    "2024-04-06T14:45:00Z",
    "2024-04-06T15:15:00Z",
    "2024-10-05T15:45:00Z",
    1716000000,
    1716000000.5,
    True,
    "",
    "   ",
    None,
    "garbage",
    {"x": 1},
    ["2025-05-03T12:00:00Z"],
)
CATEGORY_VALUES: tuple[object, ...] = (
    ["documents"],
    ["images", "archives"],
    [],
    "documents",
    [1],
    [True],
    ["other"],
    [{"a": 1}],
    ["executables", "databases"],
    ["documents", "images"],
    None,
)
PATHS: tuple[object, ...] = (
    r"C:\Users\a\r.docx",
    r"C:\Users\a\clip.MP4",
    "/home/a/b.tar.gz",
    "/home/a/noext",
    r"C:\a\dir.mp3\file",
    "x.mp3 ",
    r"C:\a\b.wav",
    "/a/b.flac",
    "/a/.hidden",
    "/a/b.toolongextension1",
    "/a/b.sqlite-wal",
    "",
    None,
)
PARTIAL_FIELDS: tuple[dict[str, object], ...] = (
    {},
    {},
    {},
    {"parse_status": "ok"},
    {"parse_status": "truncated"},
    {"parse_status": "parsed-no-errors"},
    {"parser_error": True},
    {"details": {"scan_truncated": True}},
    {"artifact_type": "file-invalid"},
    {"coverage": "partial"},
    {"decrypt_status": "failed"},
)
NON_ROWS: tuple[object, ...] = ("text", None, 5, [1, 2])


def ntfs_time_of(row: Mapping[str, object]) -> object:
    """Deterministic NTFS ``$SI`` time of an acquisition copy (None for some paths)."""
    path = str(row.get("path") or row.get("name") or "")
    if len(path) % 3 == 0:
        return None
    return (_EPOCH + dt.timedelta(hours=len(path) * 17 + 480_000)).isoformat()


def random_rows(rng: random.Random, count: int) -> list[object]:
    rows: list[object] = []
    for index in range(count):
        if rng.random() < 0.02:
            rows.append(rng.choice(NON_ROWS))
            continue
        row: dict[str, object] = {"name": f"n{index}.{rng.choice(('jpg', 'mkv', 'ogg', 'docx', 'bin'))}", "size": index}
        path = rng.choice(PATHS)
        if path is not None:
            row["path"] = path
        category = rng.choice(CATEGORY_VALUES)
        if category is not None:
            row["categories"] = list(category) if isinstance(category, list) else category
        if rng.random() < 0.5:
            row["fs_modified_at"] = rng.choice(TIME_VALUES)
        if rng.random() < 0.8:
            row["modified_at"] = rng.choice(TIME_VALUES)
        origin = rng.random()
        if origin < 0.35:
            row["modified_at_origin"] = "acquisition-copy"
            if rng.random() < 0.2:
                row["ntfs"] = {"si_modified_at": rng.choice(TIME_VALUES)} if rng.random() < 0.7 else "not-a-map"
        elif origin < 0.45:
            row["modified_at_origin"] = "scan"
        row.update(rng.choice(PARTIAL_FIELDS))
        rows.append(row)
    return rows


TZ_CHOICES = (None, "UTC", "+09:00", "-03:30", "+05:45", "Asia/Seoul", "America/New_York", "Australia/Lord_Howe")
BOUNDS = (None, "2024-03-10", "2024-11-03T06:00", "2025-05-03", "2025-05-03T21:00:00Z", "2025-05-05T18:59", "0001-01-01", "9999-12-31")


def random_conditions(rng: random.Random):
    while True:
        low, high = rng.choice(BOUNDS), rng.choice(BOUNDS)
        kwargs: dict[str, object] = {
            "time_from": low if rng.random() < 0.4 else None,
            "time_to": high if rng.random() < 0.4 else None,
            "weekday": [",".join(rng.sample(("mon", "tue", "wed", "thu", "fri", "sat", "sun"), rng.randint(1, 3)))] if rng.random() < 0.3 else [],
            "hours": rng.choice(("09-18", "18-09", "00-06", "22-02")) if rng.random() < 0.3 else None,
            "offhours": rng.random() < 0.2,
            "tz": rng.choice(TZ_CHOICES),
            "partial": rng.random() < 0.15,
            "content": [",".join(rng.sample(list(CONTENT_TYPES), rng.randint(1, 3)))] if rng.random() < 0.3 else [],
        }
        try:
            return parse_row_conditions(**kwargs)  # type: ignore[arg-type]
        except ValueError:
            continue  # from > to


def as_us(value: object) -> int:
    moment = parse_moment(value) if value is not None else None
    return -(2**63) if moment is None else (moment - _EPOCH) // dt.timedelta(microseconds=1)


class StubFlagsIndex:
    def __init__(self, flagged: dict[int, int]) -> None:
        self.flagged = flagged  # record index -> rank 0..2

    def matching(self, kind: str, rule_ids, grade) -> list[int]:
        return sorted(index for index, rank in self.flagged.items() if grade is None or rank <= "ABC".index(grade))

    def best_rank(self, kind: str, record_index: int) -> int:
        return self.flagged.get(record_index, 3)


class StubJoin:
    def __init__(self, index: StubFlagsIndex) -> None:
        self.index = index

    def require_index(self) -> StubFlagsIndex:
        return self.index


class FilesIndexEquivalenceTests(unittest.TestCase):
    """Q-S3-5: same rows, same order as the old scans."""

    def setUp(self) -> None:
        MATCH_CACHE.clear()
        files_index.clear_files_index_cache()
        self.addCleanup(MATCH_CACHE.clear)
        self.addCleanup(files_index.clear_files_index_cache)

    def ntfs_join(self, rows: Sequence[object]):
        def resolve(positions: Sequence[int]) -> list[int]:
            return [as_us(ntfs_time_of(rows[position])) for position in positions]  # type: ignore[arg-type]

        return lambda: (("join", 1), resolve)

    def test_row_time_and_extension_helpers_match_the_predicate_helpers(self) -> None:
        rows = random_rows(random.Random(5), 3000)
        for row in rows:
            if not isinstance(row, Mapping):
                self.assertEqual(files_row_time_us(row), files_index.TIME_NONE)
            elif needs_ntfs_time(row):
                self.assertEqual(files_row_time_us(row), files_index.TIME_PENDING_NTFS, row)
            else:
                self.assertEqual(files_row_time_us(row), as_us(row_time(row, "files")), row)
        for value in (*PATHS, "a.", ".b", "dir/x.Y-Z", "x .Jpg", "  /a/b.PNG  ", "a\\b/c.d\\e.txt", 7):
            self.assertEqual(fast_path_extension(value), path_extension(value), value)

    def test_category_and_condition_pages_match_the_old_scan(self) -> None:
        rng = random.Random(20261020)
        rows = random_rows(rng, 2500)
        payload = {"candidates": rows, "inventory": rows, "summary": {"x": 1}}
        for round_number in range(160):
            collection = rng.choice(("candidates", "inventory"))
            wanted = frozenset(rng.sample(("documents", "images", "archives", "other", "executables", "1", "True", "nothing"), rng.randint(0, 2)))
            conditions = random_conditions(rng) if rng.random() < 0.85 else None
            if not wanted and conditions is None:
                continue
            resolver = ntfs_time_of if rng.random() < 0.7 else None
            offset, limit = rng.choice(((0, 50), (30, 20), (0, 0), (2000, 50)))
            expected = old_filter_files_by_category(
                payload,
                wanted,
                offset=offset,
                limit=limit,
                collection=collection,
                row_filter=conditions.predicate("files", resolver) if conditions is not None else None,
                rows=rows,
            )
            positions = files_matched_positions(
                rows,
                run_id="run-a",
                collection=collection,
                files_stamp=("files", 1),
                categories=wanted,
                conditions=conditions,
                ntfs_join=self.ntfs_join(rows) if resolver is not None else (lambda: (("no-join",), None)),
            )
            actual = filter_files_by_category(
                payload, wanted, offset=offset, limit=limit, collection=collection, rows=rows, positions=positions
            )
            self.assertEqual(actual, expected, (round_number, collection, sorted(wanted), conditions and conditions.describe()))

    def test_flag_and_restrict_pages_match_the_old_scan(self) -> None:
        rng = random.Random(77)
        rows = random_rows(rng, 2000)
        join = StubJoin(StubFlagsIndex({index: rng.randint(0, 2) for index in rng.sample(range(len(rows)), 600)}))
        for round_number in range(120):
            collection = rng.choice(("candidates", "inventory"))
            wanted = frozenset(rng.sample(("documents", "images", "archives", "other"), rng.randint(0, 2))) or None
            conditions = random_conditions(rng) if rng.random() < 0.8 else None
            restrict = sorted(rng.sample(range(len(rows)), rng.randint(0, 900))) if rng.random() < 0.6 else None
            query = rng.choice(
                (FlagQuery(), FlagQuery(sort=True), FlagQuery(grade="B"), FlagQuery(rule_ids=frozenset({"r"}), sort=True))
            )
            offset, limit = rng.choice(((0, 40), (25, 25), (500, 40)))
            row_filter = conditions.predicate("files", ntfs_time_of) if conditions is not None else None
            expected = old_filter_files_rows(
                rows,
                collection=collection,
                join=join,
                query=query,
                categories=wanted,
                offset=offset,
                limit=limit,
                restrict=restrict,
                row_filter=row_filter,
            )
            positions = None
            if wanted or conditions is not None:
                positions = files_matched_positions(
                    rows,
                    run_id="run-b",
                    collection=collection,
                    files_stamp=("files", 2),
                    categories=wanted or (),
                    conditions=conditions,
                    restrict=restrict,
                    restrict_key=("folder", round_number) if restrict is not None else None,
                    ntfs_join=self.ntfs_join(rows),
                )
            actual = filter_files_rows(
                rows,
                collection=collection,
                join=join,  # type: ignore[arg-type]
                query=query,
                categories=wanted,
                offset=offset,
                limit=limit,
                restrict=restrict,
                row_filter=row_filter,
                positions=positions,
            )
            self.assertEqual(actual, expected, (round_number, collection, wanted, query))

    def test_cache_key_covers_the_join_state(self) -> None:
        rows = [{"path": "/a/x.txt", "modified_at_origin": "acquisition-copy", "categories": ["documents"]}]
        conditions = parse_row_conditions(time_from="2025-01-01")
        assert conditions is not None
        calls: list[str] = []

        def join(stamp: str, value: object):
            def resolve(positions: Sequence[int]) -> list[int]:
                calls.append(stamp)
                return [as_us(value) for _ in positions]

            return lambda: ((stamp,), resolve)

        def positions(stamp: str, value: object) -> list[int]:
            return list(
                files_matched_positions(rows, run_id="r", collection="candidates", files_stamp=("f",), conditions=conditions, ntfs_join=join(stamp, value))
            )

        self.assertEqual(positions("no_analysis", None), [])
        self.assertEqual(positions("analysis-1", "2025-06-01T00:00:00Z"), [0])
        self.assertEqual(positions("analysis-1", "2025-06-01T00:00:00Z"), [0])  # cached: no new resolve
        self.assertEqual(positions("analysis-2", "2024-06-01T00:00:00Z"), [])
        self.assertEqual(calls, ["no_analysis", "analysis-1", "analysis-2"])


class NtfsVectorTests(unittest.TestCase):
    """The one-pass NTFS time lookup equals the per-row resolver."""

    def test_vector_lookup_matches_resolver(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(os.path.abspath(temp)) / "Vol"
            entries: dict[int, bytes] = {}
            names = ["Users/a.txt", "Users/İstanbul.txt", "Users/straße.doc", "Windows/x.dll", "Users/deep/b.bin", "Users/none.txt"]
            for number, name in enumerate(names):
                times = [files_ntfs._NONE_TIME] * len(files_ntfs.TIME_FIELDS)
                if name != "Users/none.txt":
                    times[files_ntfs.TIME_FIELDS.index("si_modified_at")] = 1_700_000_000_000_000 + number * 3_600_000_000
                entries[files_ntfs._hash_key(files_ntfs.ntfs_path_key(name))] = files_ntfs._PACK.pack(number, *times, 0, True)
            index = files_ntfs.NtfsIndex(key=("r", "a", 0, 0), entries=entries, top_level=frozenset({"users", "windows"}))
            sep = os.sep
            rows: list[object] = [
                {"path": str(root / "Users" / "a.txt")},
                {"path": str(root / "users" / "A.TXT")},
                {"path": str(root) + "/Users/a.txt"},
                {"path": str(root / "Users" / "x" / ".." / "a.txt")},
                {"path": str(root / "Users" / "İstanbul.txt")},
                {"path": str(root / "Users" / "straße.doc")},
                {"path": str(root / "Windows" / "x.dll") + sep},
                {"path": str(root / "Users" / "deep" / "b.bin")},
                {"path": str(root / "Users" / "none.txt")},
                {"path": str(root)},
                {"path": str(root) + "X" + sep + "Users" + sep + "a.txt"},
                {"path": str(root.parent / "elsewhere.txt")},
                {"path": ""},
                {"name": "no-path"},
                "not a row",
            ]
            join = ({}, None, index, str(root))
            with mock.patch.object(files_ntfs, "_join_context", return_value=join):
                resolve = files_ntfs.ntfs_si_modified_resolver(None, rows)
                assert resolve is not None
                vector = files_ntfs.ntfs_si_modified_times(None, rows, range(len(rows)))
            assert vector is not None
            for row, value in zip(rows, vector):
                expected = as_us(resolve(row)) if isinstance(row, Mapping) else -(2**63)
                self.assertEqual(value, expected, row)
            self.assertNotEqual(vector[0], -(2**63))
            with mock.patch.object(files_ntfs, "_join_context", return_value=({}, None, None, None)):
                self.assertIsNone(files_ntfs.ntfs_si_modified_times(None, rows, [0]))


FILES_PAYLOAD_ROWS = 260


def api_rows() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for index in range(FILES_PAYLOAD_ROWS):
        rows.append(
            {
                "path": f"C:\\ev\\Users\\f{index}.{('docx', 'jpg', 'zip')[index % 3]}",
                "name": f"f{index}",
                "categories": [("documents", "images", "archives")[index % 3]],
                "fs_modified_at": f"2025-05-{1 + index % 28:02d}T{index % 24:02d}:00:00Z",
            }
        )
    return rows


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for API tests")
class FilesCacheApiTests(unittest.TestCase):
    """Q-S3-4 / Q-S3-8 through ``GET /files``."""

    def setUp(self) -> None:
        MATCH_CACHE.clear()
        files_index.clear_files_index_cache()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.run_dir = base / "run"
        self.run_dir.mkdir()
        self.files_path = self.run_dir / "rapidtriage-files.json"
        self.files_path.write_text(json.dumps({"candidates": api_rows()}), encoding="utf-8")
        summary_path = self.run_dir / "rapidtriage-run-summary.json"
        summary_path.write_text(
            json.dumps(
                {
                    "profile_version": "rapidtriage-run-summary-v1",
                    "mode": "hacking",
                    "root": str(base / "evidence"),
                    "output_dir": str(self.run_dir),
                    "source": {"type": "directory", "analysis_root": str(base / "evidence")},
                    "outputs": {"files": str(self.files_path), "summary": str(summary_path)},
                    "summary": {"counts": {}},
                }
            ),
            encoding="utf-8",
        )
        self.store = RunJobStore()
        self.run_id = self.store.import_completed_run(self.run_dir).run_id
        self.client = TestClient(create_app(self.store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})

    def page(self, **params: object) -> dict[str, object]:
        response = self.client.get(f"/api/runs/{self.run_id}/files", params=params)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_next_page_slices_cached_positions_and_matched_is_exact(self) -> None:
        query = {"from": "2025-05-10", "content": "document", "limit": 20}
        first = self.page(**query)
        expected = [
            index
            for index, row in enumerate(api_rows())
            if row["categories"] == ["documents"] and str(row["fs_modified_at"]) >= "2025-05-10"
        ]
        self.assertEqual(first["matched"], len(expected))
        self.assertEqual([row["record_index"] for row in first["candidates"]], expected[:20])
        self.assertFalse(first["pagination"]["truncated"])
        original = MATCH_CACHE.get_or_compute

        def no_rescan(key, compute):
            return original(key, lambda: self.fail("the next page rescanned the rows"))

        with mock.patch.object(MATCH_CACHE, "get_or_compute", side_effect=no_rescan):
            second = self.page(**query, offset=20)
        self.assertEqual([row["record_index"] for row in second["candidates"]], expected[20:40])
        self.assertEqual(second["matched"], len(expected))
        self.assertEqual(second["pagination"]["has_more"], len(expected) > 40)
        # A different condition is a different key.
        other = self.page(**{**query, "content": "image"})
        self.assertTrue(all(row["record_index"] % 3 == 1 for row in other["candidates"]))

    def test_rewritten_files_output_invalidates(self) -> None:
        query = {"category": "documents", "limit": 500}
        before = self.page(**query)
        rows = api_rows()
        for row in rows:
            row["categories"] = ["images"]
        self.files_path.write_text(json.dumps({"candidates": rows, "pad": "x" * 64}), encoding="utf-8")
        after = self.page(**query)
        self.assertGreater(before["matched"], 0)
        self.assertEqual(after["matched"], 0)

    def test_read_only_output_folder_uses_memory_only(self) -> None:
        listing = sorted(path.name for path in self.run_dir.iterdir())
        modes = {path: path.stat().st_mode for path in [self.run_dir, *self.run_dir.iterdir()]}
        for path in self.run_dir.iterdir():
            os.chmod(path, stat.S_IREAD)
        os.chmod(self.run_dir, stat.S_IREAD | stat.S_IEXEC)

        def restore() -> None:
            for path, mode in modes.items():
                os.chmod(path, mode)

        self.addCleanup(restore)
        first = self.page(offhours="1", tz="Asia/Seoul", limit=10)
        second = self.page(offhours="1", tz="Asia/Seoul", limit=10, offset=10)
        self.assertGreater(first["matched"], 10)
        self.assertEqual(first["matched"], second["matched"])
        self.assertEqual(sorted(path.name for path in self.run_dir.iterdir()), listing)


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for API tests")
class FilesCacheJoinStateTests(unittest.TestCase):
    """Q-S3-4: an ``ntfs-meta`` analysis completing changes the acquisition copies' times."""

    def setUp(self) -> None:
        from tests.test_rapidtriage_analyses import AnalysisApiTests

        MATCH_CACHE.clear()
        files_index.clear_files_index_cache()
        fixture = AnalysisApiTests("test_files_time_conditions_resolve_acquisition_copies_through_ntfs")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture

    def test_join_state_change_invalidates(self) -> None:
        fixture = self.fixture
        files_path = Path(json.loads((fixture.run_dir / "rapidtriage-run-summary.json").read_text(encoding="utf-8"))["outputs"]["files"])
        payload = json.loads(files_path.read_text(encoding="utf-8"))
        for candidate in payload["candidates"]:
            candidate.pop("fs_modified_at", None)
            candidate.update({"modified_at": "2030-01-01T00:00:00Z", "modified_at_origin": "acquisition-copy"})
        files_path.write_text(json.dumps(payload), encoding="utf-8")
        url = f"/api/runs/{fixture.run_id}/files"
        before = fixture.client.get(url, params={"limit": 10, "from": "2000-01-01"}).json()
        self.assertEqual(before["matched"], 0)  # no join: acquisition copies have no time
        state = fixture.run_ntfs()
        self.assertEqual(state["status"], "completed", state)
        joined = fixture.client.get(url, params={"limit": 10}).json()
        si_modified = joined["candidates"][0]["ntfs"]["si_modified_at"]
        after = fixture.client.get(url, params={"limit": 10, "from": "2000-01-01"}).json()
        self.assertEqual([row["record_index"] for row in after["candidates"]], [0])
        self.assertEqual(after["matched"], 1)
        day = si_modified[:10]
        hit = fixture.client.get(url, params={"limit": 10, "from": day, "to": day}).json()
        self.assertEqual([row["record_index"] for row in hit["candidates"]], [0])


if __name__ == "__main__":
    unittest.main()
