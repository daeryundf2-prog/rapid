"""R7 S1 re-review backend fixes on ``GET /files`` (docs/research/console-adversarial-rereview-r7s1-2026-10-27.md §2).

* R-2: time conditions use the 수정 time the grid shows and ``sort=mtime`` orders by -- an
  acquisition copy without an NTFS ``$SI`` time falls back to its own copy time -- and the page
  reports ``time_basis`` / ``time_basis_counts``; a joined NTFS time wins.
* R-13: placeholder times (1980-01-01 DOS epoch, 1970 / 1601 zero) count as missing: they sort
  last in both orders and never match a time condition.
* R-3: ``q=`` is NFC-folded on both sides.
* R-8: ``order`` and the ``sort=key:dir`` suffix are case-insensitive and ``order`` applies to
  ``sort=flags`` too.
* R-9: the sort descriptor reports ``applied`` / ``values`` / ``empty``; an unknown key answers
  ``applied: false`` with a reason.
"""

from __future__ import annotations

import datetime as dt
import json
import tempfile
import unicodedata
import unittest
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
    files_matched_positions,
    files_sort_order,
    files_time_basis,
    parse_files_sort,
)
from rapidtriage.api.app.row_conditions import (
    MATCH_CACHE,
    parse_row_conditions,
    row_time,
)
from rapidtriage.api.app.triage_flags import FlagQuery, filter_files_rows, is_flags_sort
from rapidtriage.core.jobs import RunJobStore

TOKEN = "r7s1-rereview-files-token"
_EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
NFC_NAME = unicodedata.normalize("NFC", "계약서")
NFD_NAME = unicodedata.normalize("NFD", "계약서")


def us(text: str) -> int:
    return (dt.datetime.fromisoformat(text.replace("Z", "+00:00")) - _EPOCH) // dt.timedelta(microseconds=1)


def folder_rows() -> list[dict[str, object]]:
    """A folder-input run: every row an acquisition copy with no NTFS join."""
    times = (
        "2025-03-03T10:00:00Z",  # Monday
        "2025-06-07T23:30:00Z",  # Saturday
        "2024-12-31T12:00:00Z",
        "1980-01-01T00:00:00Z",  # DOS epoch placeholder
        "2025-08-15T08:00:00Z",  # Friday
        "1970-01-01T00:00:00Z",  # zero placeholder
        None,
    )
    rows: list[dict[str, object]] = []
    for index, moment in enumerate(times):
        name = f"{NFC_NAME}_{index}.docx" if index % 2 == 0 else f"{NFD_NAME}_{index}.txt"
        row: dict[str, object] = {
            "path": f"C:\\case\\{name}",
            "name": name,
            "size": index * 10,
            "categories": ["documents"],
            "fs_modified_at": None,
            "modified_at_origin": "acquisition-copy",
        }
        if moment is not None:
            row["modified_at"] = moment
        rows.append(row)
    return rows


class FilesTimeFallbackUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        MATCH_CACHE.clear()
        files_index.clear_files_index_cache()
        self.addCleanup(MATCH_CACHE.clear)
        self.addCleanup(files_index.clear_files_index_cache)

    def matched(self, rows, join=None, **conditions) -> list[int]:
        parsed = parse_row_conditions(**conditions)
        return list(
            files_matched_positions(rows, run_id="r", collection="candidates", files_stamp=("s",), conditions=parsed, ntfs_join=join)
        )

    def test_copies_without_ntfs_time_match_by_their_copy_time(self) -> None:
        rows = folder_rows()
        self.assertEqual(self.matched(rows, time_from="2025-01-01", time_to="2025-12-31"), [0, 1, 4])
        self.assertEqual(self.matched(rows, weekday=["sat"]), [1])
        # Placeholders never match, even with an open window that covers them.
        self.assertEqual(self.matched(rows, time_from="1960-01-01", time_to="1990-01-01"), [])
        self.assertEqual(self.matched(rows, time_from="1960-01-01"), [0, 1, 2, 4])
        # The generic predicate agrees (row_time is the same fallback).
        conditions = parse_row_conditions(time_from="2025-01-01", time_to="2025-12-31")
        assert conditions is not None
        self.assertEqual([index for index, row in enumerate(rows) if conditions.matches(row, "files")], [0, 1, 4])
        self.assertIsNone(row_time(rows[3], "files"))

    def test_joined_ntfs_time_wins_and_placeholders_fall_back(self) -> None:
        rows = folder_rows()
        si = {0: us("2010-05-05T00:00:00Z"), 1: us("1980-01-01T00:00:00Z")}

        def join():
            return ("join", 1), lambda positions: [si.get(position, TIME_NONE) for position in positions]

        # Row 0's NTFS time (2010) wins over its copy time (2025); row 1's NTFS placeholder falls
        # back to its copy time; the rest keep their copy times.
        self.assertEqual(self.matched(rows, join, time_from="2025-01-01", time_to="2025-12-31"), [1, 4])
        self.assertEqual(self.matched(rows, join, time_from="2010-05-05", time_to="2010-05-05"), [0])
        basis = files_time_basis(rows, run_id="r", collection="candidates", files_stamp=("s",), ntfs_join=join)
        self.assertEqual(basis["time_basis"], "mixed")
        self.assertEqual(basis["time_basis_counts"], {"ntfs": 1, "acquisition_copy": 3, "none": 3})
        files_index.clear_files_index_cache()
        basis = files_time_basis(rows, run_id="r", collection="candidates", files_stamp=("s",))
        self.assertEqual(basis["time_basis"], "acquisition-copy")
        self.assertEqual(basis["time_basis_counts"], {"ntfs": 0, "acquisition_copy": 4, "none": 3})
        image = [{"fs_modified_at": "2025-01-01T00:00:00Z"}, {"fs_modified_at": None}]
        self.assertEqual(files_time_basis(image, run_id="i", collection="candidates", files_stamp=("s",))["time_basis"], "ntfs")

    def test_mtime_sort_puts_placeholders_last_in_both_orders(self) -> None:
        rows = folder_rows()
        for descending, expected in ((False, [2, 0, 1, 4, 3, 5, 6]), (True, [4, 1, 0, 2, 3, 5, 6])):
            order, _rank = files_sort_order(rows, run_id="r", collection="candidates", files_stamp=("s",), sort=FilesSort("mtime", descending))
            self.assertEqual(list(order), expected, descending)

    def test_sort_and_order_parsing_is_case_insensitive(self) -> None:
        self.assertEqual(parse_files_sort("size:DESC", None), FilesSort("size", True))
        self.assertEqual(parse_files_sort("Size", "DESC"), FilesSort("size", True))
        self.assertEqual(parse_files_sort("size:desc", "ASC"), FilesSort("size", False))  # order wins
        self.assertTrue(is_flags_sort("FLAGS:Desc"))

    def test_flags_sort_descending(self) -> None:
        from tests.test_r6_s3_files_cache import StubFlagsIndex, StubJoin

        rows = [{"path": f"/r{index}"} for index in range(6)]
        join = StubJoin(StubFlagsIndex({1: 2, 2: 0, 4: 1, 5: 0}))
        ascending, _ = filter_files_rows(rows, collection="candidates", join=join, query=FlagQuery(sort=True), categories=None, offset=0, limit=10)  # type: ignore[arg-type]
        descending, _ = filter_files_rows(
            rows, collection="candidates", join=join, query=FlagQuery(sort=True, descending=True), categories=None, offset=0, limit=10  # type: ignore[arg-type]
        )
        self.assertEqual([row["record_index"] for row in ascending], [2, 5, 4, 1, 0, 3])
        self.assertEqual([row["record_index"] for row in descending], [1, 4, 2, 5, 0, 3])


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for API tests")
class FilesRereviewApiTests(unittest.TestCase):
    def setUp(self) -> None:
        MATCH_CACHE.clear()
        files_index.clear_files_index_cache()
        self.addCleanup(MATCH_CACHE.clear)
        self.addCleanup(files_index.clear_files_index_cache)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.run_dir = base / "run"
        self.run_dir.mkdir()
        self.rows = folder_rows()
        self.files_path = self.run_dir / "rapidtriage-files.json"
        self.files_path.write_text(json.dumps({"candidates": self.rows, "inventory": []}, ensure_ascii=False), encoding="utf-8")
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
        response = self.client.get(f"/api/runs/{self.run_id}/files", params={"limit": 50, **params})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    @staticmethod
    def indexes(page: dict[str, object]) -> list[int]:
        return [row["record_index"] for row in page["candidates"]]  # type: ignore[index, union-attr]

    def test_time_conditions_on_a_folder_run_match_the_copy_time(self) -> None:
        page = self.page(**{"from": "2025-01-01", "to": "2025-12-31"})
        self.assertEqual(page["matched"], 3)
        self.assertEqual(self.indexes(page), [0, 1, 4])
        self.assertEqual(page["time_basis"], "acquisition-copy")
        self.assertEqual(page["time_basis_counts"], {"ntfs": 0, "acquisition_copy": 4, "none": 3})
        weekday = self.page(weekday="mon,fri", tz="UTC")
        self.assertEqual(self.indexes(weekday), [0, 4])
        self.assertGreater(weekday["matched"], 0)
        # A plain page carries no time basis (computed only for time conditions / mtime sort).
        self.assertNotIn("time_basis", self.page())
        self.assertEqual(self.page(sort="mtime")["time_basis"], "acquisition-copy")

    def test_mtime_sort_and_conditions_agree(self) -> None:
        asc = self.page(sort="mtime", order="asc")
        self.assertEqual(self.indexes(asc), [2, 0, 1, 4, 3, 5, 6])  # 1980 / 1970 placeholders last
        self.assertEqual(asc["sort"]["values"], 4)
        desc = self.page(sort="mtime:DESC")
        self.assertEqual(self.indexes(desc), [4, 1, 0, 2, 3, 5, 6])
        windowed = self.page(sort="mtime", order="desc", **{"from": "2025-01-01"})
        self.assertEqual(self.indexes(windowed), [4, 1, 0])

    def test_order_case_and_unknown_sort(self) -> None:
        upper = self.page(sort="size", order="DESC")
        self.assertEqual(upper["sort"]["order"], "desc")
        self.assertEqual(self.indexes(upper), [6, 5, 4, 3, 2, 1, 0])
        self.assertEqual(self.indexes(self.page(sort="size:DESC")), [6, 5, 4, 3, 2, 1, 0])
        self.assertEqual(self.client.get(f"/api/runs/{self.run_id}/files", params={"sort": "size", "order": "down", "limit": 3}).status_code, 422)
        flags = self.page(sort="flags", order="desc")
        self.assertEqual(flags["sort"]["key"], "flags")
        self.assertEqual(flags["sort"]["order"], "desc")
        bogus = self.page(sort="bogus", order="DESC")
        self.assertEqual(bogus["sort"]["applied"], False)
        self.assertEqual(bogus["sort"]["order"], "desc")
        self.assertEqual(self.indexes(bogus), list(range(7)))

    def test_empty_sort_column_is_reported(self) -> None:
        ctime = self.page(sort="ctime", order="desc")
        self.assertEqual(ctime["sort"]["status"], "ready")
        self.assertTrue(ctime["sort"]["applied"])
        self.assertEqual(ctime["sort"]["values"], 0)
        self.assertTrue(ctime["sort"]["empty"])
        size = self.page(sort="size")
        self.assertEqual(size["sort"]["values"], 7)
        self.assertFalse(size["sort"]["empty"])

    def test_text_filter_folds_nfc_and_nfd(self) -> None:
        for query in (NFC_NAME, NFD_NAME):
            page = self.page(q=query)
            self.assertEqual(page["matched"], 7, ascii(query))
        self.assertEqual(self.indexes(self.page(q=f"{NFD_NAME}_4")), [4])
        self.assertEqual(self.indexes(self.page(q=f"{NFC_NAME}_5")), [5])


if __name__ == "__main__":
    unittest.main()
