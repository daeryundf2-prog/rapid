"""Review marks and tags under concurrent writers (remote-use review R4).

Two examiners tagging the same row at once used to lose tags (the API merged
``add_tags`` with tags read on another connection), and concurrent marks on a
new row created several ``review_mark`` rows (SELECT-then-INSERT outside a
write lock). Marks are now written under ``BEGIN IMMEDIATE`` with a UNIQUE
(case_id, target_type, target_id) index; existing duplicates are merged when
the case DB is opened for writing.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from rapidtriage.core.case_db import CaseDatabase, apply_schema, create_case_tag

HAS_FASTAPI = True
try:
    from fastapi.testclient import TestClient  # noqa: F401
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

if HAS_FASTAPI:
    from tests.test_rapidtriage_api import api_test_client

CASE_ID = "CASE-R4"


def _make_case_db(root: Path, file_count: int) -> Path:
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


def _marks(path: Path, target_id: str) -> list[sqlite3.Row]:
    with contextlib.closing(sqlite3.connect(path)) as connection:
        connection.row_factory = sqlite3.Row
        return connection.execute(
            "SELECT * FROM review_mark WHERE case_id = ? AND target_type = 'file_record' AND target_id = ?",
            (CASE_ID, target_id),
        ).fetchall()


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for RapidTriage API tests")
class ConcurrentReviewBatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.database = _make_case_db(root, file_count=2)
        self.client = api_test_client(case_db_roots=[root])

    def tearDown(self) -> None:
        self.client.close()
        self.temp.cleanup()

    def _post_concurrently(self, bodies: list[dict[str, object]], workers: int) -> list[tuple[int, str]]:
        barrier = threading.Barrier(workers)

        def post(body: dict[str, object]) -> tuple[int, str]:
            with contextlib.suppress(threading.BrokenBarrierError):
                barrier.wait(timeout=0.5)
            response = self.client.post(
                "/api/case-db/review-batch",
                json={"database": str(self.database), "case_id": CASE_ID, **body},
            )
            return response.status_code, response.text

        with ThreadPoolExecutor(workers) as pool:
            return list(pool.map(post, bodies))

    def test_concurrent_add_tags_lose_no_tag(self) -> None:
        # stress2.py: 2 clients x 100 add_tags kept 84 of 100 tags.
        bodies = [
            {
                "targets": [{"target_type": "file_record", "target_id": "1"}],
                "status": "relevant" if index % 2 else "not-relevant",
                "reviewer": "kim" if index % 2 else "lee",
                "add_tags": [f"t{index}"],
            }
            for index in range(100)
        ]
        results = self._post_concurrently(bodies, workers=8)
        self.assertEqual([status for status, _ in results if status != 200], [], results[:3])
        marks = _marks(self.database, "1")
        self.assertEqual(len(marks), 1)
        tags = json.loads(marks[0]["tags_json"])
        self.assertEqual(sorted(tags), sorted(f"t{index}" for index in range(100)))
        self.assertEqual(len(json.loads(marks[0]["tag_ids_json"])), 100)

    def test_concurrent_marks_on_one_row_create_one_mark(self) -> None:
        # stress_marks.py: 32 concurrent marks on one row left 20 review_mark rows.
        bodies = [
            {"targets": [{"target_type": "file_record", "target_id": "2"}], "status": "relevant", "note": f"n{index}"}
            for index in range(20)
        ]
        results = self._post_concurrently(bodies, workers=20)
        self.assertEqual([status for status, _ in results if status != 200], [], results[:3])
        self.assertEqual(len(_marks(self.database, "2")), 1)
        with contextlib.closing(sqlite3.connect(self.database)) as connection:
            history = connection.execute(
                "SELECT review_citation_id, version FROM review_mark_history "
                "WHERE case_id = ? AND target_type = 'file_record' AND target_id = '2' ORDER BY version",
                (CASE_ID,),
            ).fetchall()
        self.assertEqual(len({citation for citation, _ in history}), 1)
        self.assertEqual([version for _, version in history], list(range(1, 21)))

    def test_concurrent_tag_id_batches_lose_no_tag(self) -> None:
        with CaseDatabase(self.database).connect() as connection:
            apply_schema(connection)
            tag_ids = [
                int(create_case_tag(connection, CASE_ID, name=f"id-tag {index}", actor="kim")["id"])
                for index in range(20)
            ]
        bodies = [
            {"targets": [{"target_type": "file_record", "target_id": "2"}], "tag_ids": [tag_id], "reviewer": "kim"}
            for tag_id in tag_ids
        ]
        results = self._post_concurrently(bodies, workers=20)
        self.assertEqual([status for status, _ in results if status != 200], [], results[:3])
        marks = _marks(self.database, "2")
        self.assertEqual(len(marks), 1)
        self.assertEqual(sorted(json.loads(marks[0]["tag_ids_json"])), sorted(tag_ids))


class DuplicateReviewMarkMigrationTests(unittest.TestCase):
    def test_open_merges_existing_duplicates_and_adds_unique_index(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = _make_case_db(Path(tmp), file_count=2)
            database = CaseDatabase(path)
            first = database.mark_review(
                case_id=CASE_ID, target_type="file_record", target_id="1", status="relevant", tags=["a"], reviewer="kim"
            )
            database.mark_review(case_id=CASE_ID, target_type="file_record", target_id="2", status="relevant")
            # A DB written before the fix: no UNIQUE index, two extra rows for file_record:1.
            with contextlib.closing(sqlite3.connect(path)) as connection:
                connection.execute("DROP INDEX idx_review_mark_case_target")
                connection.execute("CREATE INDEX idx_review_mark_case_target ON review_mark(case_id, target_type, target_id)")
                for citation, status, tags, updated in (
                    ("CASE-R4-RV-DUP1", "needs-review", ["b"], "2099-01-01T00:00:00+00:00"),
                    ("CASE-R4-RV-DUP2", "not-relevant", ["a", "c"], "2000-01-01T00:00:00+00:00"),
                ):
                    connection.execute(
                        "INSERT INTO review_mark (citation_id, case_id, target_type, target_id, status, tags_json, "
                        "tag_ids_json, note, reviewer, created_at, updated_at) "
                        "VALUES (?, ?, 'file_record', '1', ?, ?, '[]', ?, 'lee', ?, ?)",
                        (citation, CASE_ID, status, json.dumps(tags), f"note {citation}", updated, updated),
                    )
                connection.commit()
            self.assertEqual(len(_marks(path, "1")), 3)

            database.initialize()

            marks = _marks(path, "1")
            self.assertEqual(len(marks), 1)
            kept = marks[0]
            # The first citation id survives; fields come from the newest row; tags are the union.
            self.assertEqual(kept["citation_id"], first["citation_id"])
            self.assertEqual((kept["status"], kept["note"], kept["reviewer"]), ("needs-review", "note CASE-R4-RV-DUP1", "lee"))
            self.assertEqual(json.loads(kept["tags_json"]), ["a", "b", "c"])
            self.assertEqual(len(json.loads(kept["tag_ids_json"])), 3)
            self.assertEqual(len(_marks(path, "2")), 1)
            with contextlib.closing(sqlite3.connect(path)) as connection:
                unique = {
                    str(row[1]): int(row[2]) for row in connection.execute("PRAGMA index_list(review_mark)")
                }
                self.assertEqual(unique.get("idx_review_mark_case_target"), 1)
                event = connection.execute(
                    "SELECT target_id, params_json FROM audit_event WHERE action = 'review.duplicates-merged'"
                ).fetchall()
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        "INSERT INTO review_mark (citation_id, case_id, target_type, target_id, created_at, updated_at) "
                        "VALUES ('X', ?, 'file_record', '1', '', '')",
                        (CASE_ID,),
                    )
            self.assertEqual(len(event), 1)
            self.assertEqual(event[0][0], "1")
            params = json.loads(event[0][1])
            self.assertEqual(params["kept_citation_id"], first["citation_id"])
            self.assertEqual(params["removed_citation_ids"], ["CASE-R4-RV-DUP1", "CASE-R4-RV-DUP2"])

            # A second open is a no-op.
            database.initialize()
            with contextlib.closing(sqlite3.connect(path)) as connection:
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM audit_event WHERE action = 'review.duplicates-merged'").fetchone()[0],
                    1,
                )


if __name__ == "__main__":
    unittest.main()
