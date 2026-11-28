"""Z (undo) writes in the review history (design viewer-keys re-review P2).

Z puts a row back to its state before a verdict. The stored mark names the examiner who
pressed Z as its writer and verdict setter (forensic: the actor is whoever wrote), and the
history row of that write says it was an undo: ``kind = "undo"``, the ``undone_version`` and
that version's ``undone_reviewer``.
"""

from __future__ import annotations

import contextlib
import sqlite3
import tempfile
import unittest
from pathlib import Path

from rapidtriage.api.app.run_review import review_map_entries, split_batch_targets
from rapidtriage.core.case_db import (
    CaseDatabase,
    CaseDatabaseError,
    review_mark_history_entries,
    verdict_undo,
)
from tests.test_review_mark_conflict import CASE_ID, _history_count, _make_case_db, _row


class ReviewUndoHistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = _make_case_db(Path(self.temp.name))
        self.database = CaseDatabase(self.path)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _batch(self, target: dict[str, object], **fields: object) -> dict[str, object]:
        return self.database.mark_reviews_batch(
            case_id=CASE_ID,
            targets=[{"target_type": "file_record", "target_id": "1", **target}],
            keep_tags=True,
            **fields,
        )

    def _entries(self) -> list[dict[str, object]]:
        with contextlib.closing(sqlite3.connect(self.path)) as connection:
            return review_mark_history_entries(connection, CASE_ID, "file_record", "1")

    def test_undo_by_kim_of_lees_verdict_is_recorded_as_an_undo(self) -> None:
        verdict = self._batch({}, status="relevant", reviewer="lee")["marks"][0]
        lee_version = int(verdict["version"])
        self._batch(
            {"expected_version": lee_version, "undo_of_version": lee_version}, status="unreviewed", reviewer="kim"
        )
        newest, older = self._entries()[:2]
        self.assertEqual(
            (newest["kind"], newest["undone_version"], newest["undone_reviewer"], newest["author"]),
            ("undo", lee_version, "lee", "kim"),
        )
        self.assertEqual((newest["status_before"], newest["status_after"]), ("relevant", "unreviewed"))
        self.assertEqual((older["kind"], older["undone_version"], older["undone_reviewer"]), ("", None, ""))
        # The actor of the undo write is the one who pressed Z.
        row = _row(self.path, "1")
        self.assertEqual((row["reviewer"], row["status_by"]), ("kim", "kim"))

    def test_undo_version_given_as_text_by_the_api_split(self) -> None:
        direct, _ = split_batch_targets(
            [{"target_type": "file_record", "target_id": "1", "expected_version": 1, "undo_of_version": 1}]
        )
        self.assertEqual(direct[0]["undo_of_version"], "1")
        self._batch({}, status="excluded", reviewer="lee")
        self.database.mark_reviews_batch(case_id=CASE_ID, targets=direct, keep_tags=True, status="unreviewed", reviewer="kim")
        self.assertEqual(self._entries()[0]["undone_reviewer"], "lee")

    def test_bad_undo_version_writes_nothing(self) -> None:
        self._batch({}, status="relevant", reviewer="lee")
        before = _history_count(self.path)
        for bad in (0, "x", True):
            with self.assertRaises(CaseDatabaseError):
                self._batch({"undo_of_version": bad}, status="unreviewed", reviewer="kim")
        self.assertEqual(_history_count(self.path), before)
        self.assertEqual(_row(self.path, "1")["status"], "relevant")

    def test_a_db_from_before_the_columns_reads_and_migrates(self) -> None:
        self._batch({}, status="relevant", reviewer="lee")
        with contextlib.closing(sqlite3.connect(self.path)) as connection:
            for column in ("kind", "undone_version", "undone_reviewer"):
                connection.execute(f"ALTER TABLE review_mark_history DROP COLUMN {column}")
            connection.commit()
        with contextlib.closing(sqlite3.connect(f"{self.path.as_uri()}?mode=ro", uri=True)) as connection:
            (entry,) = review_mark_history_entries(connection, CASE_ID, "file_record", "1")
        self.assertEqual((entry["kind"], entry["undone_version"], entry["undone_reviewer"]), ("", None, ""))
        self._batch({"undo_of_version": 1}, status="unreviewed", reviewer="kim")
        self.assertEqual(self._entries()[0]["kind"], "undo")

    def test_the_review_map_names_the_undo_that_set_the_verdict(self) -> None:
        self._batch({}, status="excluded", reviewer="lee")
        mine = self._batch({}, status="relevant", reviewer="kim")["marks"][0]
        version = int(mine["version"])
        self._batch({"expected_version": version, "undo_of_version": version}, status="excluded", reviewer="kim")
        # A note afterwards does not hide it: the verdict is still the undo's.
        self._batch({}, note="메모", reviewer="park")
        with contextlib.closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            entries, _ = review_map_entries(connection, CASE_ID, {}, limit=10)
            self.assertEqual(entries[0]["undo_of"], {"undone_version": version, "undone_reviewer": "kim"})
            self.assertEqual(verdict_undo(connection, CASE_ID, "file_record", "2"), None)
        # A new verdict replaces it.
        self._batch({}, status="needs-review", reviewer="lee")
        with contextlib.closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            entries, _ = review_map_entries(connection, CASE_ID, {}, limit=10)
        self.assertNotIn("undo_of", entries[0])


if __name__ == "__main__":
    unittest.main()
