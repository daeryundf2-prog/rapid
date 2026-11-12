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

from rapidtriage.core.case_db import (
    CaseDatabase,
    CaseDatabaseError,
    apply_schema,
    write_lock,
)
from rapidtriage.core.case_db import database as database_module
from rapidtriage.core.case_db.write_lock import (
    BUSY_TIMEOUT_MS,
    CASE_DB_LOCKED_MESSAGE,
    CaseDatabaseLockedError,
    retry_when_locked,
)

HAS_FASTAPI = True
try:
    from rapidtriage.core.jobs import RunJobStore
    from tests.test_rapidtriage_api import api_test_client
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

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


def _row_tags(path: Path) -> dict[str, list[str]]:
    with CaseDatabase(path).connect() as connection:
        rows = connection.execute("SELECT target_id, tags_json FROM review_mark WHERE case_id = ?", (CASE,)).fetchall()
    return {str(row["target_id"]): json.loads(row["tags_json"]) for row in rows}


def _targets(ids: list[int]) -> list[dict[str, str]]:
    return [{"target_type": "file_record", "target_id": str(i)} for i in ids]


class AddTagsMergeTests(unittest.TestCase):
    """Review P1-7: ``add_tags`` merges with the row's tags inside the write transaction."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "case.db"
        self.ids = _seed(self.path)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _add(self, tag: str, ids: list[int]) -> dict[str, object]:
        return CaseDatabase(self.path).mark_reviews_batch(
            case_id=CASE, targets=_targets(ids), add_tags=[tag], keep_omitted_tags=True
        )

    def test_two_windows_adding_different_tags_to_the_same_rows_keep_both(self) -> None:
        errors: list[BaseException] = []
        start = threading.Barrier(2)

        def window(tag: str, order: list[int]) -> None:
            start.wait()
            try:
                for target in order:  # one request per row, like rapid single-row tagging
                    self._add(tag, [target])
            except BaseException as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=window, args=("X", self.ids[:40])),
            threading.Thread(target=window, args=("북마크", list(reversed(self.ids[:40])))),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=120)
        self.assertEqual(errors, [])
        tags = _row_tags(self.path)
        self.assertEqual(len(tags), 40)
        for target_id, row_tags in tags.items():
            self.assertEqual(sorted(row_tags), sorted(["X", "북마크"]), target_id)

    def test_add_tags_read_happens_under_the_write_lock(self) -> None:
        # Deterministic interleave: window B adds its tag while window A's transaction is open.
        # B must wait for A's commit and then merge onto A's tags (the old route read outside
        # the transaction and wrote ["A0", "B"], losing "A").
        target = self.ids[0]
        self._add("A0", [target])
        original = CaseDatabase._write_review_mark
        b_done = threading.Event()
        b_errors: list[BaseException] = []
        threads: list[threading.Thread] = []

        def window_b() -> None:
            try:
                self._add("B", [target])
            except BaseException as exc:
                b_errors.append(exc)
            b_done.set()

        def a_write(self_, connection, *args, **kwargs):
            if not threads:
                threads.append(threading.Thread(target=window_b))
                threads[0].start()
                self.assertFalse(b_done.wait(0.3))  # B is held by A's BEGIN IMMEDIATE
            return original(self_, connection, *args, **kwargs)

        with patch.object(CaseDatabase, "_write_review_mark", a_write):
            CaseDatabase(self.path).mark_reviews_batch(
                case_id=CASE, targets=_targets([target]), add_tags=["A"], keep_omitted_tags=True
            )
            threads[0].join(timeout=30)
        self.assertEqual(b_errors, [])
        self.assertEqual(_row_tags(self.path)[str(target)], ["A0", "A", "B"])

    def test_omitted_tags_keep_or_clear_by_flag(self) -> None:
        target = self.ids[1]
        self._add("유지", [target])
        database = CaseDatabase(self.path)
        database.mark_reviews_batch(case_id=CASE, targets=_targets([target]), status="relevant", keep_omitted_tags=True)
        self.assertEqual(_row_tags(self.path)[str(target)], ["유지"])
        database.mark_reviews_batch(case_id=CASE, targets=_targets([target]), status="relevant")
        self.assertEqual(_row_tags(self.path)[str(target)], [])  # legacy batch contract: omitted = cleared
        database.mark_review(
            case_id=CASE, target_type="file_record", target_id=str(target), tags=["a"], add_tags=["b", "a"]
        )
        self.assertEqual(_row_tags(self.path)[str(target)], ["a", "b"])


class WriteTransactionScopeTests(unittest.TestCase):
    """Review P2-1 / P2-2 / P2-4: what the retry covers, when the time is taken, batch atomicity."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "case.db"
        self.ids = _seed(self.path)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _count(self, sql: str) -> int:
        with CaseDatabase(self.path).connect() as connection:
            return int(connection.execute(sql).fetchone()[0])

    def test_a_lock_error_in_the_read_back_does_not_write_twice(self) -> None:
        original = CaseDatabase.connect
        failures = [sqlite3.OperationalError("database is locked")]

        def connect(self_, *, write: bool = False):
            if not write and failures:
                raise failures.pop()
            return original(self_, write=write)

        with patch.object(CaseDatabase, "connect", connect), patch.object(write_lock.time, "sleep"):
            with self.assertRaises(sqlite3.OperationalError):
                CaseDatabase(self.path).mark_review(
                    case_id=CASE, target_type="file_record", target_id=str(self.ids[0]), status="relevant"
                )
        self.assertEqual(self._count("SELECT COUNT(*) FROM review_mark_history"), 1)
        self.assertEqual(self._count("SELECT COUNT(*) FROM audit_event WHERE action = 'review.marked'"), 1)

    def test_timestamp_is_taken_after_the_lock_is_acquired(self) -> None:
        blocker = sqlite3.connect(self.path)
        blocker.execute("BEGIN IMMEDIATE")
        released = threading.Event()
        seen: list[bool] = []
        real_now = database_module.now_iso

        def now_iso() -> str:
            seen.append(released.is_set())
            return real_now()

        result: list[dict[str, object]] = []

        def mark() -> None:
            result.append(
                CaseDatabase(self.path).mark_review(
                    case_id=CASE, target_type="file_record", target_id=str(self.ids[0]), status="relevant"
                )
            )

        with patch.object(database_module, "now_iso", now_iso):
            thread = threading.Thread(target=mark)
            thread.start()
            thread.join(0.3)
            released.set()
            blocker.rollback()
            blocker.close()
            thread.join(30)
        self.assertEqual(result[0]["status"], "relevant")
        self.assertTrue(seen)
        self.assertTrue(all(seen), seen)  # no timestamp taken while waiting for the other writer

    def test_a_locked_batch_writes_nothing(self) -> None:
        blocker = sqlite3.connect(self.path)
        blocker.execute("BEGIN IMMEDIATE")
        try:
            with (
                patch.object(write_lock, "BUSY_TIMEOUT_MS", 50),
                patch.object(write_lock.time, "sleep"),
                self.assertRaises(CaseDatabaseLockedError),
            ):
                CaseDatabase(self.path).mark_reviews_batch(case_id=CASE, targets=_targets(self.ids[:3]), status="relevant")
        finally:
            blocker.rollback()
            blocker.close()
        self.assertEqual(self._count("SELECT COUNT(*) FROM review_mark"), 0)

    def test_a_batch_with_a_missing_target_writes_nothing(self) -> None:
        targets = _targets(self.ids[:3]) + [{"target_type": "file_record", "target_id": "999999"}]
        with self.assertRaises(CaseDatabaseError):
            CaseDatabase(self.path).mark_reviews_batch(case_id=CASE, targets=targets, status="relevant")
        self.assertEqual(self._count("SELECT COUNT(*) FROM review_mark"), 0)
        self.assertEqual(self._count("SELECT COUNT(*) FROM review_mark_history"), 0)


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for RapidTriage API tests")
class LockedCaseDbRouteTests(unittest.TestCase):
    """Review P1-7 / P2-3 / P2-4 through the HTTP routes: add_tags from two windows, and a lock is
    409 ``CASE_DB_LOCKED`` (Korean) for marks, tag-id batches and tag edits, never a raw 500."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "case.db"
        self.ids = _seed(self.path)
        self.client = api_test_client(RunJobStore(), case_db_roots=[self.temp.name])

    def tearDown(self) -> None:
        self.client.close()
        self.temp.cleanup()

    def _batch(self, **body: object):
        return self.client.post(
            "/api/case-db/review-batch", json={"database": str(self.path), "case_id": CASE, **body}
        )

    def test_add_tags_from_two_windows_over_http_keep_both(self) -> None:
        errors: list[str] = []
        start = threading.Barrier(2)

        def window(tag: str, order: list[int]) -> None:
            start.wait()
            for target in order:
                response = self._batch(targets=_targets([target]), add_tags=[tag])
                if response.status_code != 200:
                    errors.append(response.text)

        threads = [
            threading.Thread(target=window, args=("X", self.ids[:40])),
            threading.Thread(target=window, args=("북마크", list(reversed(self.ids[:40])))),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=120)
        self.assertEqual(errors, [])
        tags = _row_tags(self.path)
        self.assertEqual(len(tags), 40)
        self.assertTrue(all(sorted(row) == sorted(["X", "북마크"]) for row in tags.values()), tags)

    def _locked(self):
        blocker = sqlite3.connect(self.path)
        blocker.execute("BEGIN IMMEDIATE")
        return blocker

    def assert_locked_409(self, response) -> None:
        self.assertEqual(response.status_code, 409, response.text)
        body = response.json()
        self.assertEqual(body["code"], "CASE_DB_LOCKED")
        self.assertIn("잠겨 있어", body["message"])
        self.assertNotIn("database is locked", response.text)

    def test_locked_writes_are_409_with_a_korean_message(self) -> None:
        tag_id = self.client.get(f"/api/cases/{CASE}/tags", params={"database": str(self.path)}).json()["tags"][0]["id"]
        blocker = self._locked()
        try:
            with patch.object(write_lock, "BUSY_TIMEOUT_MS", 50), patch.object(write_lock.time, "sleep"):
                self.assert_locked_409(self._batch(targets=_targets(self.ids[:3]), add_tags=["X"]))
                self.assert_locked_409(self._batch(targets=_targets(self.ids[:3]), status="relevant"))
                self.assert_locked_409(self._batch(targets=_targets(self.ids[:3]), tag_ids=[tag_id]))
                self.assert_locked_409(
                    self.client.patch(
                        f"/api/cases/{CASE}/tags/{tag_id}", params={"database": str(self.path)}, json={"description": "x"}
                    )
                )
                self.assert_locked_409(
                    self.client.post(f"/api/cases/{CASE}/tags", params={"database": str(self.path)}, json={"name": "새 태그"})
                )
        finally:
            blocker.rollback()
            blocker.close()
        self.assertEqual(_row_tags(self.path), {})  # nothing of the refused batches was applied


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
