"""Review-mark attribution and optimistic concurrency (design review F13/F14).

Two remote examiners used to overwrite each other's decision silently: the last
write won and nobody saw the other decision. A write may now carry, per target,
the ``updated_at`` it last read (``expected_updated_at``; ``""`` = no mark). When
the stored mark changed since, the API answers 409 with the current mark
(status, reviewer, updated_at) and writes nothing; a batch is all-or-nothing.
Writes without an expectation behave as before. The review map names who stored
each mark and when.

Review follow-ups: the token is the mark's history version, not clock text
(P3-1: two writes in one clock tick); who set the verdict (``status_by`` /
``status_at``) is kept apart from the last writer of a note, tag or report flag
(P2-1); a conflict lists what changed since the client's version (P3-4); tag
batches answer the versions they stored (P3-2).
"""

from __future__ import annotations

import contextlib
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.core.case_db import (
    CaseDatabase,
    CaseDatabaseError,
    ReviewConflictError,
    apply_schema,
    apply_tag_ids,
    create_case_tag,
    verdict_select_sql,
)

HAS_FASTAPI = True
try:
    from fastapi.testclient import TestClient  # noqa: F401
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

if HAS_FASTAPI:
    from rapidtriage.core.jobs import RunJobStore
    from tests.test_rapidtriage_api import api_test_client
    from tests.test_rapidtriage_run import build_run_fixture

CASE_ID = "CASE-F14"


def _make_case_db(root: Path, file_count: int = 3) -> Path:
    path = root / "case.db"
    database = CaseDatabase(path)
    database.initialize()
    database.create_case(case_id=CASE_ID, examiner="검사관 A")
    with database.connect() as connection:
        for index in range(1, file_count + 1):
            connection.execute(
                "INSERT INTO file_record (citation_id, case_id, path, normalized_path, created_at) "
                "VALUES (?, ?, ?, ?, '2026-11-28T00:00:00+00:00')",
                (f"F-{index}", CASE_ID, f"C:/synthetic/{index}.txt", f"c:/synthetic/{index}.txt"),
            )
    return path


def _row(path: Path, target_id: str) -> sqlite3.Row | None:
    with contextlib.closing(sqlite3.connect(path)) as connection:
        connection.row_factory = sqlite3.Row
        return connection.execute(
            "SELECT * FROM review_mark WHERE case_id = ? AND target_type = 'file_record' AND target_id = ?",
            (CASE_ID, target_id),
        ).fetchone()


def _history_count(path: Path) -> int:
    with contextlib.closing(sqlite3.connect(path)) as connection:
        return int(connection.execute("SELECT COUNT(*) FROM review_mark_history").fetchone()[0])


class ReviewConflictCoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = _make_case_db(Path(self.temp.name))
        self.database = CaseDatabase(self.path)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _mark(self, target_id: str, **fields: object) -> dict[str, object]:
        return self.database.mark_review(case_id=CASE_ID, target_type="file_record", target_id=target_id, **fields)

    def test_matching_expectation_writes_and_returns_the_new_version(self) -> None:
        first = self._mark("1", status="relevant", reviewer="kim", expected_updated_at="")
        second = self._mark("1", status="excluded", reviewer="lee", expected_updated_at=str(first["updated_at"]))
        self.assertEqual((second["status"], second["reviewer"]), ("excluded", "lee"))
        self.assertNotEqual(second["updated_at"], first["updated_at"])

    def test_stale_expectation_refuses_with_the_current_mark_and_writes_nothing(self) -> None:
        first = self._mark("1", status="relevant", reviewer="kim")
        changed = self._mark("1", status="needs-review", reviewer="lee")
        before = _history_count(self.path)
        with self.assertRaises(ReviewConflictError) as caught:
            self._mark("1", status="excluded", reviewer="park", expected_updated_at=str(first["updated_at"]))
        (conflict,) = caught.exception.conflicts
        self.assertEqual((conflict["target_type"], conflict["target_id"]), ("file_record", "1"))
        self.assertEqual(conflict["expected_updated_at"], first["updated_at"])
        current = conflict["current"]
        self.assertEqual(
            (current["status"], current["reviewer"], current["updated_at"], current["expected_updated_at"]),
            ("needs-review", "lee", changed["updated_at"], changed["updated_at"]),
        )
        row = _row(self.path, "1")
        self.assertEqual((row["status"], row["reviewer"]), ("needs-review", "lee"))
        self.assertEqual(_history_count(self.path), before)

    def test_empty_expectation_means_no_mark_and_a_cleared_mark_counts_as_none(self) -> None:
        self._mark("2", status="relevant", reviewer="kim")
        with self.assertRaises(ReviewConflictError) as caught:
            self._mark("2", status="excluded", expected_updated_at="")
        self.assertTrue(caught.exception.conflicts[0]["current"]["exists"])
        # Toggled off (status back to unreviewed, nothing else): the board has no mark, so "" matches.
        self._mark("2", status="unreviewed", reviewer="kim")
        cleared = self._mark("2", status="excluded", reviewer="lee", expected_updated_at="")
        self.assertEqual(cleared["status"], "excluded")

    def test_no_expectation_keeps_last_write_wins(self) -> None:
        self._mark("3", status="relevant", reviewer="kim")
        self.assertEqual(self._mark("3", status="excluded", reviewer="lee")["status"], "excluded")

    def test_batch_is_all_or_nothing_and_lists_every_conflict(self) -> None:
        one = self._mark("1", status="relevant", reviewer="kim")
        two = self._mark("2", status="relevant", reviewer="kim")
        self._mark("2", status="needs-review", reviewer="lee")
        before = _history_count(self.path)
        targets = [
            {"target_type": "file_record", "target_id": "1", "expected_updated_at": one["updated_at"]},
            {"target_type": "file_record", "target_id": "2", "expected_updated_at": two["updated_at"]},
            {"target_type": "file_record", "target_id": "3", "expected_updated_at": ""},
        ]
        with self.assertRaises(ReviewConflictError) as caught:
            self.database.mark_reviews_batch(case_id=CASE_ID, targets=targets, status="excluded", reviewer="park")
        self.assertEqual([c["target_id"] for c in caught.exception.conflicts], ["2"])
        self.assertEqual(_row(self.path, "1")["status"], "relevant")
        self.assertIsNone(_row(self.path, "3"))
        self.assertEqual(_history_count(self.path), before)

    def test_batch_target_error_midway_writes_nothing(self) -> None:
        targets = [
            {"target_type": "file_record", "target_id": "1"},
            {"target_type": "file_record", "target_id": "999"},
        ]
        with self.assertRaisesRegex(Exception, "review target not found"):
            self.database.mark_reviews_batch(case_id=CASE_ID, targets=targets, status="relevant")
        self.assertIsNone(_row(self.path, "1"))


    def test_version_token_survives_two_writes_in_one_clock_tick(self) -> None:
        # P3-1: on a coarse clock (Windows, 15.6 ms) two writes share an updated_at; the history
        # version still moves, so the stale expectation is refused.
        with mock.patch("rapidtriage.core.case_db.database.now_iso", return_value="2026-11-28T00:00:00+00:00"):
            first = self._mark("1", status="relevant", reviewer="kim", expected_version=0)
            seen = int(first["version"])
            again = self._mark("1", status="excluded", reviewer="kim", expected_version=seen)
            self.assertEqual(again["updated_at"], first["updated_at"])
            self.assertEqual((again["previous_version"], again["version"]), (seen, seen + 1))
            with self.assertRaises(ReviewConflictError) as caught:
                self._mark("1", status="needs-review", reviewer="lee", expected_version=seen)
        (conflict,) = caught.exception.conflicts
        self.assertEqual((conflict["expected_version"], conflict["current"]["version"]), (seen, seen + 1))
        self.assertEqual(_row(self.path, "1")["status"], "excluded")

    def test_write_answers_the_version_it_stored_and_the_one_it_replaced(self) -> None:
        created = self._mark("2", note="메모", reviewer="kim", expected_version=0)
        self.assertEqual((created["previous_version"], created["version"]), (0, 1))
        cleared = self._mark("2", note="", reviewer="kim", expected_version=1)
        # A cleared mark is "no mark": its token is 0 again, and 0 is what a reader of the board sends.
        self.assertEqual((cleared["previous_version"], cleared["version"]), (1, 0))
        remade = self._mark("2", status="relevant", reviewer="lee", expected_version=0)
        self.assertEqual((remade["previous_version"], remade["version"]), (0, 3))

    def test_bad_expected_version_is_refused(self) -> None:
        with self.assertRaisesRegex(CaseDatabaseError, "expected_version"):
            self.database.mark_reviews_batch(
                case_id=CASE_ID,
                targets=[{"target_type": "file_record", "target_id": "1", "expected_version": "v1"}],
                status="relevant",
            )
        self.assertIsNone(_row(self.path, "1"))

    def test_conflict_lists_what_changed_since_the_clients_version(self) -> None:
        seen = self._mark("3", status="relevant", reviewer="kim")
        self._mark("3", note="lee의 메모", reviewer="lee")
        self._mark("3", add_tags=["지갑"], reviewer="park")
        with self.assertRaises(ReviewConflictError) as caught:
            self._mark("3", note="kim의 메모", reviewer="kim", expected_version=int(seen["version"]))
        current = caught.exception.conflicts[0]["current"]
        self.assertEqual(
            [(change["actor"], change["fields"]) for change in current["changes"]],
            [("park", ["tags"]), ("lee", ["note"])],
        )
        # The verdict is still kim's: only the note and the tags moved.
        self.assertEqual((current["status_by"], current["status_at"]), ("kim", seen["status_at"]))
        self.assertEqual(current["reviewer"], "park")

    def test_conflict_from_no_mark_lists_changes_since_the_mark_was_last_cleared(self) -> None:
        self._mark("1", status="relevant", reviewer="kim")
        self._mark("1", status="unreviewed", reviewer="kim")
        self._mark("1", status="excluded", reviewer="lee")
        with self.assertRaises(ReviewConflictError) as caught:
            self._mark("1", status="relevant", reviewer="park", expected_version=0)
        changes = caught.exception.conflicts[0]["current"]["changes"]
        self.assertEqual([(c["version"], c["actor"], c["fields"]) for c in changes], [(3, "lee", ["status"])])

    def test_verdict_actor_and_time_stay_with_the_status_writer(self) -> None:
        # P2-1: lee decides; kim only adds a note and puts the row in the report.
        decided = self._mark("1", status="excluded", reviewer="lee")
        self._mark("1", note="kim의 메모", include_in_report=True, reviewer="kim")
        row = _row(self.path, "1")
        self.assertEqual((row["reviewer"], row["status_by"], row["status_at"]), ("kim", "lee", decided["updated_at"]))
        changed = self._mark("1", status="relevant", reviewer="kim")
        self.assertEqual((changed["status_by"], changed["status_at"]), ("kim", changed["updated_at"]))
        # A mark made with a note only has no verdict yet.
        note_only = self._mark("2", note="메모만", reviewer="park")
        self.assertEqual((note_only["status_by"], note_only["status_at"]), ("", ""))

    def test_tag_writes_do_not_move_the_verdict(self) -> None:
        decided = self._mark("1", status="relevant", reviewer="lee")
        batch = self.database.mark_reviews_batch(
            case_id=CASE_ID,
            targets=[{"target_type": "file_record", "target_id": "1"}],
            add_tags=["메모용"],
            keep_tags=True,
            reviewer="kim",
        )
        self.assertEqual(batch["marks"][0]["status_by"], "lee")
        with self.database.write_transaction() as connection:
            tag_id = int(create_case_tag(connection, CASE_ID, name="지갑", actor="kim")["id"])
            apply_tag_ids(connection, CASE_ID, [{"target_type": "file_record", "target_id": "1"}], add_ids=[tag_id], actor="park")
        row = _row(self.path, "1")
        self.assertEqual((row["reviewer"], row["status_by"], row["status_at"]), ("park", "lee", decided["updated_at"]))


class ReviewVerdictMigrationTests(unittest.TestCase):
    """P2-1 migration: a DB from before ``status_by`` / ``status_at`` gets them from the history."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = _make_case_db(Path(self.temp.name))
        database = CaseDatabase(self.path)

        def mark(target_id: str, **fields: object) -> dict[str, object]:
            return database.mark_review(case_id=CASE_ID, target_type="file_record", target_id=target_id, **fields)

        self.decided = mark("1", status="relevant", reviewer="kim")
        mark("1", note="lee의 메모", include_in_report=True, reviewer="lee")
        mark("2", note="메모만", reviewer="park")
        mark("3", status="excluded", reviewer="kim")
        self.undone = mark("3", status="unreviewed", note="다시 볼 것", reviewer="lee")
        with contextlib.closing(sqlite3.connect(self.path)) as connection:
            connection.execute("ALTER TABLE review_mark DROP COLUMN status_by")
            connection.execute("ALTER TABLE review_mark DROP COLUMN status_at")
            connection.commit()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _expected(self) -> dict[str, tuple[str, str]]:
        return {
            "1": ("kim", str(self.decided["updated_at"])),
            "2": ("", ""),
            # Set back to unreviewed by lee: lee made the current (empty) verdict.
            "3": ("lee", str(self.undone["updated_at"])),
        }

    def test_read_only_db_derives_the_verdict_from_the_history(self) -> None:
        with contextlib.closing(sqlite3.connect(f"{self.path.as_uri()}?mode=ro", uri=True)) as connection:
            rows = connection.execute(
                f"SELECT target_id, {verdict_select_sql(connection)} FROM review_mark ORDER BY target_id"
            ).fetchall()
        self.assertEqual({str(row[0]): (str(row[1]), str(row[2])) for row in rows}, self._expected())

    def test_opening_for_write_adds_and_backfills_the_columns(self) -> None:
        with CaseDatabase(self.path).write_transaction() as connection:
            columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(review_mark)")}
        self.assertLessEqual({"status_by", "status_at"}, columns)
        with contextlib.closing(sqlite3.connect(self.path)) as connection:
            stored = {
                str(row[0]): (str(row[1]), str(row[2]))
                for row in connection.execute("SELECT target_id, status_by, status_at FROM review_mark ORDER BY target_id")
            }
        self.assertEqual(stored, self._expected())


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for RapidTriage API tests")
class ReviewConflictApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.path = _make_case_db(root)
        self.client = api_test_client(case_db_roots=[root])

    def tearDown(self) -> None:
        self.client.close()
        self.temp.cleanup()

    def _review(self, target_id: str, **body: object):
        return self.client.post(
            "/api/case-db/review",
            json={"database": str(self.path), "case_id": CASE_ID, "target_type": "file_record", "target_id": target_id, **body},
        )

    def _batch(self, targets: list[dict[str, str]], **body: object):
        return self.client.post(
            "/api/case-db/review-batch",
            json={"database": str(self.path), "case_id": CASE_ID, "targets": targets, **body},
        )

    def test_single_review_200_then_409_with_the_current_mark(self) -> None:
        created = self._review("1", status="relevant", reviewer="kim", expected_updated_at="")
        self.assertEqual(created.status_code, 200, created.text)
        version = created.json()["updated_at"]
        changed = self._review("1", status="needs-review", reviewer="lee", expected_updated_at=version)
        self.assertEqual(changed.status_code, 200, changed.text)
        stale = self._review("1", status="excluded", reviewer="park", expected_updated_at=version)
        self.assertEqual(stale.status_code, 409, stale.text)
        detail = stale.json()["detail"]
        self.assertEqual(detail["code"], "review-conflict")
        self.assertIn("충돌 1건", detail["message"])
        current = detail["conflicts"][0]["current"]
        self.assertEqual(
            (current["status"], current["reviewer"], current["updated_at"]),
            ("needs-review", "lee", changed.json()["updated_at"]),
        )
        self.assertEqual(_row(self.path, "1")["status"], "needs-review")

    def test_old_clients_without_expectation_still_overwrite(self) -> None:
        self.assertEqual(self._review("2", status="relevant", reviewer="kim").status_code, 200)
        overwrite = self._review("2", status="excluded", reviewer="lee")
        self.assertEqual(overwrite.status_code, 200, overwrite.text)
        batch = self._batch([{"target_type": "file_record", "target_id": "2"}], status="needs-review")
        self.assertEqual(batch.status_code, 200, batch.text)
        self.assertEqual(_row(self.path, "2")["status"], "needs-review")

    def test_batch_409_writes_nothing_then_succeeds_with_the_current_versions(self) -> None:
        one = self._review("1", status="relevant", reviewer="kim").json()
        two = self._review("2", status="relevant", reviewer="kim").json()
        newer = self._review("2", status="needs-review", reviewer="lee").json()
        targets = [
            {"target_type": "file_record", "target_id": "1", "expected_updated_at": one["updated_at"]},
            {"target_type": "file_record", "target_id": "2", "expected_updated_at": two["updated_at"]},
        ]
        # The console path (add_tags keeps tags) and the plain path refuse alike.
        for body in ({"status": "excluded"}, {"status": "excluded", "add_tags": ["검토"]}):
            refused = self._batch(targets, reviewer="park", **body)
            self.assertEqual(refused.status_code, 409, refused.text)
            conflicts = refused.json()["detail"]["conflicts"]
            self.assertEqual([(c["target_id"], c["current"]["reviewer"]) for c in conflicts], [("2", "lee")])
            self.assertEqual(_row(self.path, "1")["status"], "relevant")
            self.assertEqual(_row(self.path, "2")["status"], "needs-review")
        # "내 판정으로 바꾸기": the client resends with the version the conflict reported.
        targets[1]["expected_updated_at"] = conflicts[0]["current"]["expected_updated_at"]
        self.assertEqual(conflicts[0]["current"]["expected_updated_at"], newer["updated_at"])
        applied = self._batch(targets, reviewer="park", status="excluded", add_tags=["검토"])
        self.assertEqual(applied.status_code, 200, applied.text)
        self.assertEqual(applied.json()["updated_count"], 2)
        self.assertEqual(_row(self.path, "1")["status"], "excluded")
        self.assertEqual(_row(self.path, "2")["reviewer"], "park")

    def test_tag_id_batch_checks_expectations_too(self) -> None:
        mark = self._review("3", status="relevant", reviewer="kim").json()
        self._review("3", note="바뀐 메모", reviewer="lee")
        with CaseDatabase(self.path).connect() as connection:
            apply_schema(connection)
            tag_id = int(create_case_tag(connection, CASE_ID, name="충돌 태그", actor="kim")["id"])
        refused = self._batch(
            [{"target_type": "file_record", "target_id": "3", "expected_updated_at": mark["updated_at"]}],
            tag_ids=[tag_id],
        )
        self.assertEqual(refused.status_code, 409, refused.text)
        self.assertNotIn("충돌 태그", _row(self.path, "3")["tags_json"])

    def test_expected_version_over_http_single_and_batch(self) -> None:
        created = self._review("1", status="relevant", reviewer="kim", expected_version=0)
        self.assertEqual(created.status_code, 200, created.text)
        self.assertEqual((created.json()["previous_version"], created.json()["version"]), (0, 1))
        moved = self._batch(
            [{"target_type": "file_record", "target_id": "1", "expected_version": 1}], status="excluded", reviewer="lee"
        )
        self.assertEqual(moved.status_code, 200, moved.text)
        self.assertEqual(moved.json()["marks"][0]["version"], 2)
        stale = self._review("1", status="needs-review", reviewer="park", expected_version=1)
        self.assertEqual(stale.status_code, 409, stale.text)
        (conflict,) = stale.json()["detail"]["conflicts"]
        self.assertEqual(conflict["expected_version"], 1)
        self.assertEqual(
            (conflict["current"]["version"], conflict["current"]["status_by"], conflict["current"]["changes"][0]["fields"]),
            (2, "lee", ["status"]),
        )
        self.assertEqual(self._review("1", status="relevant", expected_version=-1).status_code, 422)

    def test_tag_id_batch_answers_the_versions_it_stored(self) -> None:
        mark = self._review("2", status="relevant", reviewer="kim").json()
        with CaseDatabase(self.path).connect() as connection:
            apply_schema(connection)
            tag_id = int(create_case_tag(connection, CASE_ID, name="버전 태그", actor="kim")["id"])
        tagged = self._batch([{"target_type": "file_record", "target_id": "2"}], tag_ids=[tag_id], reviewer="kim")
        self.assertEqual(tagged.status_code, 200, tagged.text)
        self.assertEqual(
            tagged.json()["marks"],
            [
                {
                    "target_type": "file_record",
                    "target_id": "2",
                    "previous_version": mark["version"],
                    "version": mark["version"] + 1,
                }
            ],
        )


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for RapidTriage API tests")
class ReviewMapAttributionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        base = Path(cls.temp.name)
        root = base / "case-root"
        root.mkdir()
        build_run_fixture(root)
        cls.client = api_test_client(RunJobStore(), case_db_roots=[cls.temp.name])
        response = cls.client.post(
            "/api/runs",
            json={"root": str(root), "mode": "fraud", "output_dir": str(base / "run-out"), "read_only": True, "wait": True},
        )
        assert response.status_code == 202, response.text
        cls.run_id = response.json()["run_id"]
        cls.handle = cls.client.post(f"/api/runs/{cls.run_id}/case-db/ensure", json={}).json()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.close()
        shutil.rmtree(cls.temp.name, ignore_errors=True)

    def _batch(self, targets: list[dict[str, str]], **body: object):
        return self.client.post(
            "/api/case-db/review-batch",
            json={
                "database": self.handle["database"],
                "case_id": self.handle["case_id"],
                "run_id": self.run_id,
                "targets": targets,
                **body,
            },
        )

    def _map_mark(self, locator: str) -> dict[str, object]:
        marks = self.client.get(f"/api/runs/{self.run_id}/review-map").json()["marks"]
        return next(mark for mark in marks if mark["collection"] == "files" and mark["locator"] == locator)

    def test_review_map_names_the_reviewer_times_and_change_count(self) -> None:
        located = [{"collection": "files", "locator": "/candidates/0"}]
        self.assertEqual(self._batch(located, status="relevant", reviewer="검사관 김").status_code, 200)
        first = self._map_mark("/candidates/0")
        self.assertEqual((first["reviewer"], first["change_count"]), ("검사관 김", 1))
        self.assertEqual(first["created_at"], first["updated_at"])
        self.assertEqual(self._batch(located, status="needs-review", reviewer="검사관 이").status_code, 200)
        second = self._map_mark("/candidates/0")
        self.assertEqual((second["status"], second["reviewer"], second["change_count"]), ("needs-review", "검사관 이", 2))
        self.assertEqual(second["created_at"], first["created_at"])
        self.assertNotEqual(second["updated_at"], first["updated_at"])

    def test_locator_conflict_names_the_locator_and_writes_nothing(self) -> None:
        self.assertEqual(
            self._batch([{"collection": "files", "locator": "/candidates/1"}], status="relevant", reviewer="kim").status_code,
            200,
        )
        seen = self._map_mark("/candidates/1")
        self.assertEqual(
            self._batch([{"collection": "files", "locator": "/candidates/1"}], status="needs-review", reviewer="lee").status_code,
            200,
        )
        stale = [
            {"collection": "files", "locator": "/candidates/1", "expected_updated_at": str(seen["updated_at"])},
            {"collection": "files", "locator": "/candidates/2", "expected_updated_at": ""},
        ]
        refused = self._batch(stale, status="excluded", reviewer="park")
        self.assertEqual(refused.status_code, 409, refused.text)
        (conflict,) = refused.json()["detail"]["conflicts"]
        self.assertEqual((conflict["collection"], conflict["locator"]), ("files", "/candidates/1"))
        self.assertEqual((conflict["current"]["status"], conflict["current"]["reviewer"]), ("needs-review", "lee"))
        marks = self.client.get(f"/api/runs/{self.run_id}/review-map").json()["marks"]
        self.assertFalse(any(mark["locator"] == "/candidates/2" and mark["collection"] == "files" for mark in marks))
        self.assertEqual(self._map_mark("/candidates/1")["status"], "needs-review")

    def test_review_map_names_who_set_the_verdict_apart_from_the_last_writer(self) -> None:
        # P2-1: lee decides, kim only puts the row in the report; the verdict stays lee's.
        located = [{"collection": "files", "locator": "/candidates/3"}]
        self.assertEqual(self._batch(located, status="excluded", reviewer="lee").status_code, 200)
        decided = self._map_mark("/candidates/3")
        seen = [{**located[0], "expected_version": decided["version"]}]
        included = self._batch(seen, include_in_report=True, reviewer="kim")
        self.assertEqual(included.status_code, 200, included.text)
        mark = self._map_mark("/candidates/3")
        self.assertEqual((mark["reviewer"], mark["status_by"], mark["status_at"]), ("kim", "lee", decided["status_at"]))
        self.assertEqual((mark["version"], mark["change_count"]), (decided["version"] + 1, decided["change_count"] + 1))
        self.assertEqual(included.json()["marks"][0]["previous_version"], decided["version"])
