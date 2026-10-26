"""``GET /files`` server sort and text filter from the files column index (plan r7 §3.2 갈래 L2).

``sort=name|path|size|mtime|ctime`` + ``order=asc|desc`` orders the WHOLE list (not the loaded
page), ``q=`` filters name/path, and both compose with category / row conditions / folder / flag
filters. Every check compares against a plain Python sort of the full list."""

from __future__ import annotations

import json
import random
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path

try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import create_app

    HAS_FASTAPI = True
except ImportError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

from rapidtriage.api.app import files_index
from rapidtriage.api.app.files_index import (
    TIME_NONE,
    FilesSort,
    files_display_mtime_us,
    files_ordered_positions,
    files_sort_order,
    files_text_positions,
    parse_files_sort,
)
from rapidtriage.api.app.row_conditions import MATCH_CACHE
from rapidtriage.core.jobs import RunJobStore

TOKEN = "r7-files-sort-token"
NAMES = ("Report.docx", "alpha.txt", "가계부.xlsx", "zeta.PDF", "b.png", "B.PNG", "readme", "계약서.hwp")


def make_rows(rng: random.Random, count: int, root: str = "C:\\ev") -> list[object]:
    rows: list[object] = []
    for index in range(count):
        name = f"{rng.choice(NAMES)}"
        folder = rng.choice(("Users\\kim\\Desktop", "Windows\\Temp", "Users\\lee\\문서", "Data"))
        row: dict[str, object] = {
            "path": f"{root}\\{folder}\\{index:05d}_{name}",
            "name": f"{index:05d}_{name}" if rng.random() > 0.05 else None,
            "size": rng.choice((rng.randint(0, 10_000_000), None, 0, 42)),
            "categories": [rng.choice(("documents", "images", "archives"))],
        }
        kind = rng.random()
        moment = f"20{rng.randint(10, 25):02d}-0{rng.randint(1, 9)}-1{rng.randint(0, 9)}T0{rng.randint(0, 9)}:1{rng.randint(0, 9)}:00Z"
        if kind < 0.5:
            row["fs_modified_at"] = moment
            row["modified_at"] = "2026-10-15T00:00:00+00:00"
        elif kind < 0.8:
            row["fs_modified_at"] = None
            row["modified_at"] = moment
        elif kind < 0.95:
            row["fs_modified_at"] = None
            row["modified_at_origin"] = "acquisition-copy"
            row["modified_at"] = moment
        rows.append(row)
    rows.append("not a row")
    return rows


def expected_order(rows: Sequence[object], key, descending: bool) -> list[int]:
    """Plain sort: rows with a value by value (stable), rows without one last in list order."""
    present = [(position, key(row)) for position, row in enumerate(rows) if key(row) is not None]
    missing = [position for position, row in enumerate(rows) if key(row) is None]
    present.sort(key=lambda item: item[1], reverse=descending)
    return [position for position, _value in present] + missing


def name_key(row: object):
    if not isinstance(row, dict):
        return None
    name = row.get("name") or str(row.get("path") or "").rstrip("\\/").replace("/", "\\").split("\\")[-1]
    return name.casefold() or None


def path_key(row: object):
    return str(row["path"]).casefold() if isinstance(row, dict) and row.get("path") else None


def size_key(row: object):
    if not isinstance(row, dict):
        return None
    value = row.get("size")
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def mtime_key(row: object):
    value = files_display_mtime_us(row)
    if value == files_index.TIME_PENDING_NTFS:
        # No NTFS join in these tests: the copy's own modified_at.
        value = files_index._parse_us(row.get("modified_at"))  # type: ignore[union-attr]
    return None if value == TIME_NONE else value


class FilesSortIndexTests(unittest.TestCase):
    def setUp(self) -> None:
        MATCH_CACHE.clear()
        files_index.clear_files_index_cache()
        self.addCleanup(files_index.clear_files_index_cache)

    def test_parse_sort(self) -> None:
        self.assertEqual(parse_files_sort("size", "desc"), FilesSort("size", True))
        self.assertEqual(parse_files_sort("size:desc", None), FilesSort("size", True))
        self.assertEqual(parse_files_sort("Name", None), FilesSort("name", False))
        self.assertIsNone(parse_files_sort("flags", None))
        self.assertIsNone(parse_files_sort("bogus", "desc"))
        self.assertIsNone(parse_files_sort("", None))

    def test_orders_equal_a_full_python_sort(self) -> None:
        rows = make_rows(random.Random(7), 1500)
        for key, reader in (("name", name_key), ("path", path_key), ("size", size_key), ("mtime", mtime_key)):
            for descending in (False, True):
                order, rank = files_sort_order(rows, run_id="r", collection="candidates", files_stamp=("s",), sort=FilesSort(key, descending))
                self.assertEqual(list(order), expected_order(rows, reader, descending), (key, descending))
                self.assertTrue(all(rank[position] == place for place, position in enumerate(order)))

    def test_ctime_uses_the_ntfs_join_and_is_empty_without_it(self) -> None:
        rows = make_rows(random.Random(3), 200)
        created = {position: 1_000_000 * ((position * 37) % 101) for position in range(len(rows)) if position % 3}

        def join():
            return ("join", 1), lambda field, positions: [created.get(position, TIME_NONE) if field == "created_at" else TIME_NONE for position in positions]

        order, _rank = files_sort_order(rows, run_id="r", collection="candidates", files_stamp=("s",), sort=FilesSort("ctime", True), ntfs_join=join)
        self.assertEqual(list(order), expected_order(list(range(len(rows))), created.get, True))
        files_index.clear_files_index_cache()
        order, _rank = files_sort_order(rows, run_id="r", collection="candidates", files_stamp=("s",), sort=FilesSort("ctime", True))
        self.assertEqual(list(order), list(range(len(rows))))  # nobody has a value: list order

    def test_acquisition_copy_mtime_prefers_the_joined_si_time(self) -> None:
        rows = [
            {"path": "C:\\a", "fs_modified_at": None, "modified_at_origin": "acquisition-copy", "modified_at": "2026-01-01T00:00:00Z"},
            {"path": "C:\\b", "fs_modified_at": "2020-01-01T00:00:00Z"},
            {"path": "C:\\c", "fs_modified_at": None, "modified_at_origin": "acquisition-copy", "modified_at": "2019-01-01T00:00:00Z"},
        ]
        si = {0: files_index._parse_us("2010-01-01T00:00:00Z")}

        def join():
            return ("join", 2), lambda field, positions: [si.get(position, TIME_NONE) for position in positions]

        order, _ = files_sort_order(rows, run_id="r", collection="candidates", files_stamp=("s",), sort=FilesSort("mtime", False), ntfs_join=join)
        # row 0: $SI 2010 (joined); row 2: no $SI -> its copy time 2019; row 1: 2020.
        self.assertEqual(list(order), [0, 2, 1])

    def test_text_filter_and_composition(self) -> None:
        rows = make_rows(random.Random(11), 800)
        positions = files_text_positions(rows, run_id="r", collection="candidates", files_stamp=("s",), needle="  B.png  desktop ")
        expected = [
            position
            for position, row in enumerate(rows)
            if isinstance(row, dict)
            and all(term in f"{name_key(row) or ''}\n{path_key(row) or ''}" for term in ("b.png", "desktop"))
        ]
        self.assertEqual(list(positions), expected)
        self.assertTrue(expected)
        base = [position for position in range(0, len(rows), 3)]
        ordered = files_ordered_positions(
            rows, run_id="r", collection="candidates", files_stamp=("s",), base=base, needle="png", sort=FilesSort("size", True)
        )
        full = expected_order(rows, size_key, True)
        kept = set(base) & set(files_text_positions(rows, run_id="r", collection="candidates", files_stamp=("s",), needle="png"))
        self.assertEqual(list(ordered), [position for position in full if position in kept])
        # A large base walks the full order (same answer).
        big = list(range(len(rows) - 5))
        ordered = files_ordered_positions(rows, run_id="r", collection="candidates", files_stamp=("s",), base=big, sort=FilesSort("name", False))
        self.assertEqual(list(ordered), [position for position in expected_order(rows, name_key, False) if position in set(big)])


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for API tests")
class FilesSortApiTests(unittest.TestCase):
    def setUp(self) -> None:
        MATCH_CACHE.clear()
        files_index.clear_files_index_cache()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.run_dir = base / "run"
        self.run_dir.mkdir()
        self.rows = [row for row in make_rows(random.Random(2026), 900, root=str(base / "evidence")) if isinstance(row, dict)]
        self.files_path = self.run_dir / "rapidtriage-files.json"
        self.files_path.write_text(json.dumps({"candidates": self.rows, "inventory": []}), encoding="utf-8")
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

    def all_pages(self, **params: object) -> list[int]:
        out: list[int] = []
        offset = 0
        while True:
            page = self.page(offset=offset, limit=250, **params)
            rows = page["candidates"]
            out.extend(row["record_index"] for row in rows)
            if not page["pagination"]["has_more"]:
                return out
            offset += 250

    def test_every_sort_key_pages_through_the_whole_order(self) -> None:
        for key, reader in (("name", name_key), ("path", path_key), ("size", size_key), ("mtime", mtime_key)):
            for order in ("asc", "desc"):
                self.assertEqual(self.all_pages(sort=key, order=order), expected_order(self.rows, reader, order == "desc"), (key, order))
        page = self.page(sort="size", order="desc", limit=5)
        self.assertEqual(page["sort"]["status"], "ready")
        self.assertEqual(page["sort"]["key"], "size")
        self.assertEqual(page["sort"]["order"], "desc")
        self.assertEqual(page["matched"], len(self.rows))
        sizes = [row["size"] for row in page["candidates"]]
        self.assertEqual(sizes, sorted((row["size"] for row in self.rows if isinstance(row.get("size"), int)), reverse=True)[:5])

    def test_text_filter_composes_with_category_and_sort(self) -> None:
        page = self.page(q="png", category="images", sort="name", order="asc", limit=1000)
        expected = [
            position
            for position in expected_order(self.rows, name_key, False)
            if "png" in f"{name_key(self.rows[position]) or ''}\n{path_key(self.rows[position])}" and "images" in self.rows[position]["categories"]
        ]
        self.assertEqual([row["record_index"] for row in page["candidates"]], expected)
        self.assertEqual(page["matched"], len(expected))
        self.assertEqual(page["text_filter"], {"q": "png", "fields": ["name", "path"]})
        # Row conditions too.
        page = self.page(q="desktop", **{"from": "2015-01-01"}, sort="mtime", order="desc", limit=1000)
        indexes = [row["record_index"] for row in page["candidates"]]
        self.assertTrue(indexes)
        times = [mtime_key(self.rows[index]) for index in indexes]
        self.assertEqual(times, sorted(times, reverse=True))

    def test_unknown_sort_is_ignored_and_limit_zero_is_refused(self) -> None:
        page = self.page(sort="bogus", limit=3)
        self.assertEqual([row["record_index"] for row in page["candidates"]], [0, 1, 2])
        self.assertNotIn("sort", page)
        self.assertEqual(self.client.get(f"/api/runs/{self.run_id}/files", params={"sort": "size", "limit": 0}).status_code, 400)
        self.assertEqual(self.client.get(f"/api/runs/{self.run_id}/files", params={"q": "x", "limit": 0}).status_code, 400)
        self.assertEqual(self.client.get(f"/api/runs/{self.run_id}/files", params={"sort": "size", "order": "up", "limit": 3}).status_code, 422)


if __name__ == "__main__":
    unittest.main()
