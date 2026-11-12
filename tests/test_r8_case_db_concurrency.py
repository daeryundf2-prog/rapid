"""R8 T-131 (QA-012): two windows writing review marks to one case DB at the same time.

Two writers (threads, each with its own ``CaseDatabase`` and connections, like two API requests
from two browser windows) cross-mark the same 100 rows: no mark is lost, every write leaves a
history row (200), and each row's current mark is its last write. A lock that outlasts the busy
timeout is retried three times (exponential backoff) before it becomes a Korean error.
Synthetic rows only.
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from rapidtriage.core.case_db import CaseDatabase, apply_schema, write_lock
from rapidtriage.core.case_db.write_lock import (
    BUSY_TIMEOUT_MS,
    CASE_DB_LOCKED_MESSAGE,
    CaseDatabaseLockedError,
    retry_when_locked,
)

CASE = "CASE-T131"
ROWS = 100


def _seed(path: Path) -> list[int]:
    database = CaseDatabase(path)
    database.initialize()
    database.create_case(case_id=CASE, examiner="검사관 A")
    with database.connect() as connection:
        apply_schema(connection)
        ids = []
        for index in range(ROWS):
            cursor = connection.execute(
                "INSERT INTO file_record (citation_id, case_id, path, normalized_path, created_at) "
                "VALUES (?, ?, ?, ?, '2026-11-13T00:00:00+00:00')",
                (f"F-{index}", CASE, f"C:/synthetic/{index}.txt", f"c:/synthetic/{index}.txt"),
            )
            ids.append(int(cursor.lastrowid or 0))
    return ids


class CaseDbConcurrentWriteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "case.db"
        self.ids = _seed(self.path)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_connections_wait_for_the_lock(self) -> None:
        with CaseDatabase(self.path).connect() as connection:
            self.assertEqual(connection.execute("PRAGMA busy_timeout").fetchone()[0], BUSY_TIMEOUT_MS)
            self.assertEqual(BUSY_TIMEOUT_MS, 5000)

    def _cross_mark(self, orders: dict[str, list[int]]) -> list[BaseException]:
        """Run one writer thread per window; each marks its rows in its own order."""
        errors: list[BaseException] = []
        start = threading.Barrier(len(orders))
        statuses = {"A": "relevant", "B": "excluded"}

        def writer(window: str, order: list[int]) -> None:
            database = CaseDatabase(self.path)  # its own handle, like another request
            start.wait()
            try:
                for target in order:
                    database.mark_review(
                        case_id=CASE,
                        target_type="file_record",
                        target_id=str(target),
                        status=statuses[window],
                        reviewer=f"검사관 {window}",
                    )
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(window, order)) for window, order in orders.items()]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=120)
        return errors

    def test_two_writers_cross_marking_the_same_100_rows_lose_nothing(self) -> None:
        # Window A goes top-down, window B bottom-up: every row is written by both, mid-run they cross.
        errors = self._cross_mark({"A": list(self.ids), "B": list(reversed(self.ids))})
        self.assertEqual(errors, [])
        with CaseDatabase(self.path).connect() as connection:
            marks = connection.execute(
                "SELECT target_id, status, reviewer FROM review_mark WHERE case_id = ?", (CASE,)
            ).fetchall()
            self.assertEqual(len(marks), ROWS)  # one mark per row: no duplicate insert, none lost
            history = connection.execute(
                "SELECT COUNT(*) FROM review_mark_history WHERE case_id = ?", (CASE,)
            ).fetchone()[0]
            self.assertEqual(history, 2 * ROWS)
            audit = connection.execute(
                "SELECT COUNT(*) FROM audit_event WHERE case_id = ? AND action = 'review.marked'", (CASE,)
            ).fetchone()[0]
            self.assertEqual(audit, 2 * ROWS)
            for mark in marks:
                versions = connection.execute(
                    "SELECT version, previous_json, current_json FROM review_mark_history "
                    "WHERE case_id = ? AND target_type = 'file_record' AND target_id = ? ORDER BY version",
                    (CASE, mark["target_id"]),
                ).fetchall()
                self.assertEqual([row["version"] for row in versions], [1, 2])
                last = json.loads(versions[-1]["current_json"])
                # The last write is the current value (and its author), the first is its "previous".
                self.assertEqual((mark["status"], mark["reviewer"]), (last["status"], last["reviewer"]))
                first = json.loads(versions[0]["current_json"])
                self.assertNotEqual(first["status"], last["status"])
                self.assertEqual(json.loads(versions[-1]["previous_json"])["status"], first["status"])
            citations = connection.execute(
                "SELECT COUNT(DISTINCT citation_id), COUNT(*) FROM audit_event WHERE case_id = ?", (CASE,)
            ).fetchone()
            self.assertEqual(citations[0], citations[1])  # no citation id handed out twice

    def test_odd_and_even_rows_at_the_same_moment(self) -> None:
        # QA-012 ①: A marks the odd rows, B the even rows, at once → 100 marks, 100 history rows.
        errors = self._cross_mark({"A": self.ids[1::2], "B": self.ids[0::2]})
        self.assertEqual(errors, [])
        with CaseDatabase(self.path).connect() as connection:
            counts = connection.execute(
                "SELECT status, COUNT(*) FROM review_mark WHERE case_id = ? GROUP BY status ORDER BY status", (CASE,)
            ).fetchall()
            self.assertEqual([tuple(row) for row in counts], [("excluded", 50), ("relevant", 50)])
            history = connection.execute("SELECT COUNT(*) FROM review_mark_history WHERE case_id = ?", (CASE,)).fetchone()[0]
            self.assertEqual(history, ROWS)

    def test_a_lock_held_past_the_timeout_errors_only_after_three_retries(self) -> None:
        blocker = sqlite3.connect(self.path)
        blocker.execute("BEGIN IMMEDIATE")  # another window holds the write lock
        sleeps: list[float] = []
        try:
            with (
                patch.object(write_lock, "BUSY_TIMEOUT_MS", 50),
                patch.object(write_lock.time, "sleep", side_effect=sleeps.append),
                self.assertRaises(CaseDatabaseLockedError) as refused,
            ):
                CaseDatabase(self.path).mark_review(
                    case_id=CASE, target_type="file_record", target_id=str(self.ids[0]), status="relevant"
                )
        finally:
            blocker.rollback()
            blocker.close()
        self.assertEqual(str(refused.exception), CASE_DB_LOCKED_MESSAGE)
        self.assertIsInstance(refused.exception.__cause__, sqlite3.OperationalError)
        self.assertEqual(len(sleeps), 3)
        self.assertEqual(sleeps, [sleeps[0], sleeps[0] * 2, sleeps[0] * 4])  # exponential
        with CaseDatabase(self.path).connect() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM review_mark").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM review_mark_history").fetchone()[0], 0)

    def test_a_lock_released_during_the_retries_lets_the_write_land(self) -> None:
        blocker = sqlite3.connect(self.path)
        blocker.execute("BEGIN IMMEDIATE")
        sleeps: list[float] = []

        def release_on_second_wait(seconds: float) -> None:
            sleeps.append(seconds)
            if len(sleeps) == 2:
                blocker.rollback()

        try:
            with (
                patch.object(write_lock, "BUSY_TIMEOUT_MS", 50),
                patch.object(write_lock.time, "sleep", side_effect=release_on_second_wait),
            ):
                mark = CaseDatabase(self.path).mark_review(
                    case_id=CASE, target_type="file_record", target_id=str(self.ids[0]), status="relevant"
                )
        finally:
            blocker.close()
        self.assertEqual(mark["status"], "relevant")
        self.assertEqual(len(sleeps), 2)
        with CaseDatabase(self.path).connect() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM review_mark_history").fetchone()[0], 1)


class RetryWhenLockedTests(unittest.TestCase):
    def test_other_errors_are_not_retried(self) -> None:
        calls: list[int] = []

        def broken() -> None:
            calls.append(1)
            raise sqlite3.OperationalError("no such table: review_mark")

        with patch.object(write_lock.time, "sleep") as sleep, self.assertRaises(sqlite3.OperationalError):
            retry_when_locked(broken)
        self.assertEqual((len(calls), sleep.call_count), (1, 0))

    def test_locked_three_times_then_ok(self) -> None:
        outcomes: list[object] = [
            sqlite3.OperationalError("database is locked"),
            sqlite3.OperationalError("database is locked"),
            sqlite3.OperationalError("database is locked"),
            "ok",
        ]

        def flaky() -> object:
            outcome = outcomes.pop(0)
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome

        with patch.object(write_lock.time, "sleep") as sleep:
            self.assertEqual(retry_when_locked(flaky, backoff_s=0.1), "ok")
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [0.1, 0.2, 0.4])


if __name__ == "__main__":
    unittest.main()
