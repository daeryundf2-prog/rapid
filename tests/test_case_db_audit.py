"""R8 T-180: review audit events record the tool version and where the actor name came from.

``audit_event`` schema is unchanged: ``tool_version`` carries ``rapidtriage.__version__`` and
``params_json`` gains ``actor_source`` ("client-supplied" for a reviewer name sent by the client,
"local-default" when it was empty and the actor fell back to ``local-user``).
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import rapidtriage
from rapidtriage.core.case_db import open_case_database

CASE_ID = "CASE-AUDIT"


class ReviewAuditVersionActorTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.database = open_case_database(Path(self._tmp.name) / "case.db")
        self.database.create_case(case_id=CASE_ID)
        self.target_ids: list[str] = []
        with self.database.connect() as connection:
            for index in range(1, 4):
                cursor = connection.execute(
                    "INSERT INTO artifact (citation_id, case_id, artifact_type, parser_name, title, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        f"{CASE_ID}-ART-{index:06d}",
                        CASE_ID,
                        "browser-history-visit",
                        "rapidtriage-browser",
                        f"synthetic visit {index}",
                        "2026-05-16T00:00:00+00:00",
                    ),
                )
                self.target_ids.append(str(cursor.lastrowid))

    def review_audit_rows(self) -> list[dict[str, object]]:
        with self.database.connect() as connection:
            rows = connection.execute(
                "SELECT actor, tool_name, tool_version, params_json FROM audit_event "
                "WHERE case_id = ? AND action = 'review.marked' ORDER BY rowid",
                (CASE_ID,),
            ).fetchall()
        return [
            {"actor": row[0], "tool_name": row[1], "tool_version": row[2], "params": json.loads(row[3])}
            for row in rows
        ]

    def test_three_marks_write_three_audit_rows_with_version_and_actor_source(self) -> None:
        for target_id in self.target_ids:
            self.database.mark_review(
                case_id=CASE_ID,
                target_type="artifact",
                target_id=target_id,
                status="relevant",
                include_in_report=True,
                reviewer="analyst-a",
            )
        rows = self.review_audit_rows()
        self.assertEqual(len(rows), 3)
        for row in rows:
            self.assertEqual(row["tool_name"], "rapidtriage")
            self.assertEqual(row["tool_version"], rapidtriage.__version__)
            self.assertEqual(row["actor"], "analyst-a")
            self.assertEqual(row["params"]["actor_source"], "client-supplied")

    def test_empty_reviewer_stays_local_user(self) -> None:
        self.database.mark_review(case_id=CASE_ID, target_type="artifact", target_id=self.target_ids[0], status="relevant")
        self.database.mark_review(
            case_id=CASE_ID, target_type="artifact", target_id=self.target_ids[1], status="relevant", reviewer=""
        )
        rows = self.review_audit_rows()
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertEqual(row["actor"], "local-user")
            self.assertEqual(row["tool_version"], rapidtriage.__version__)
            self.assertEqual(row["params"]["actor_source"], "local-default")

    def test_audit_event_columns_unchanged(self) -> None:
        with self.database.connect() as connection:
            columns = [row[1] for row in connection.execute("PRAGMA table_info(audit_event)").fetchall()]
        self.assertEqual(
            columns,
            [
                "id",
                "citation_id",
                "case_id",
                "actor",
                "action",
                "target_type",
                "target_id",
                "timestamp",
                "tool_name",
                "tool_version",
                "params_json",
                "result",
                "error",
            ],
        )


if __name__ == "__main__":
    unittest.main()
