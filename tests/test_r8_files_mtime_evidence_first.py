"""R8 T-173 (review P1-2): ``sort=mtime`` puts evidence times before copy times.

On an E01 run every extracted file is an acquisition copy; a recovered file with no NTFS ``$SI``
time kept its copy time (the run date, newer than any evidence time) and so led the default
``mtime desc`` page. Copy times now follow every evidence time in both orders, and rows with the
same evidence time list allocated before recovered. All rows are synthetic.
"""

from __future__ import annotations

import random
import unittest

from rapidtriage.api.app import files_index
from rapidtriage.api.app.files_index import (
    TIME_NONE,
    FilesSort,
    files_row_recovered,
    files_sort_order,
)

COPY_TIME = "2026-11-10T09:00:00Z"  # when the analysis PC wrote the extracted files


def live_row(index: int, moment: str) -> dict[str, object]:
    return {
        "path": f"C:\\ev\\_e01\\fs\\Users\\u\\{index:05d}.docx",
        "name": f"{index:05d}.docx",
        "fs_modified_at": None,
        "modified_at_origin": "acquisition-copy",
        "modified_at": COPY_TIME,
        "is_deleted": False,
        "recovery": {"candidate_kind": "existing"},
        "_si": moment,
    }


def recovered_row(index: int) -> dict[str, object]:
    return {
        "path": f"C:\\ev\\_e01\\fs\\_deleted_mft\\{index}-x.bin",
        "name": f"{index}-x.bin",
        "fs_modified_at": None,
        "modified_at_origin": "acquisition-copy",
        "modified_at": COPY_TIME,
        "is_deleted": True,
        "recovery": {"candidate_kind": "deleted-entry", "subtype": "native-mft-unallocated-record"},
    }


def mixed_rows(seed: int = 5, count: int = 600) -> list[dict[str, object]]:
    rng = random.Random(seed)
    rows: list[dict[str, object]] = []
    for index in range(count):
        if rng.random() < 0.4:
            rows.append(recovered_row(index))
        else:
            rows.append(live_row(index, f"20{rng.randint(15, 24)}-0{rng.randint(1, 9)}-1{rng.randint(0, 9)}T10:00:00Z"))
    return rows


def si_join(rows: list[dict[str, object]]):
    """The NTFS join: live rows have a ``$SI`` time, recovered rows have no index entry."""

    def resolve(field: str, positions):
        out = []
        for position in positions:
            moment = rows[position].get("_si")
            out.append(files_index._time_value_us(moment) if field == "si_modified_at" and moment else TIME_NONE)
        return out

    return lambda: (("join", 1), resolve)


class MtimeEvidenceFirstTests(unittest.TestCase):
    def setUp(self) -> None:
        files_index.clear_files_index_cache()
        self.addCleanup(files_index.clear_files_index_cache)

    def order(self, rows, descending: bool, *, join=None) -> list[int]:
        order, _rank = files_sort_order(
            rows, run_id="r", collection="candidates", files_stamp=("s", descending, join is not None),
            sort=FilesSort("mtime", descending), ntfs_join=join,
        )
        return list(order)

    def test_default_first_page_has_no_recovered_copy_time_rows(self) -> None:
        rows = mixed_rows()
        recovered = {position for position, row in enumerate(rows) if row["is_deleted"]}
        self.assertTrue(recovered and len(recovered) < len(rows) - 50)
        for descending in (True, False):
            order = self.order(rows, descending, join=si_join(rows))
            self.assertEqual([p for p in order[:50] if p in recovered], [], descending)
            # Every evidence-time row precedes every copy-time row.
            live_count = len(rows) - len(recovered)
            self.assertEqual(set(order[:live_count]), set(range(len(rows))) - recovered)
            times = [files_index._time_value_us(rows[p]["_si"]) for p in order[:live_count]]
            self.assertEqual(times, sorted(times, reverse=descending))

    def test_copy_times_follow_rows_with_an_evidence_time_without_a_join(self) -> None:
        rows: list[dict[str, object]] = [recovered_row(0), {"path": "C:\\a", "fs_modified_at": "2020-01-01T00:00:00Z"}]
        rows.append({"path": "C:\\b", "fs_modified_at": "2018-01-01T00:00:00Z"})
        rows.append({"path": "C:\\c"})  # no time at all: last
        for descending, expected in ((True, [1, 2, 0, 3]), (False, [2, 1, 0, 3])):
            self.assertEqual(self.order(rows, descending), expected, descending)

    def test_copy_with_joined_ntfs_block_but_no_si_time_is_a_copy_time(self) -> None:
        rows = [
            {"path": "C:\\x", "fs_modified_at": None, "modified_at_origin": "acquisition-copy", "modified_at": COPY_TIME, "ntfs": {}},
            {"path": "C:\\y", "fs_modified_at": "2019-01-01T00:00:00Z"},
        ]
        self.assertEqual(self.order(rows, True), [1, 0])

    def test_same_evidence_time_lists_allocated_before_recovered_in_both_orders(self) -> None:
        moment = "2021-05-05T05:05:05Z"
        rows = [
            {"path": "C:\\r1", "fs_modified_at": moment, "is_deleted": True},
            {"path": "C:\\a1", "fs_modified_at": moment, "is_deleted": False},
            {"path": "C:\\r2", "fs_modified_at": moment, "recovery": {"candidate_kind": "carved"}},
            {"path": "C:\\a2", "fs_modified_at": moment},
        ]
        for descending in (True, False):
            self.assertEqual(self.order(rows, descending), [1, 3, 0, 2], descending)

    def test_recovered_flag(self) -> None:
        self.assertTrue(files_row_recovered({"is_deleted": True}))
        self.assertTrue(files_row_recovered({"recovery": {"candidate_kind": "orphan"}}))
        self.assertFalse(files_row_recovered({"recovery": {"candidate_kind": "existing"}, "is_deleted": False}))
        self.assertFalse(files_row_recovered("not a row"))


if __name__ == "__main__":
    unittest.main()
