"""R8 T-036 + T-180 (review P1-5): an unnamed action is never attributed to the previous reviewer.

The console sends ``reviewer: ""`` when no name is typed. The route turned that into ``None`` and
the case DB then inherited the previous mark's reviewer, writing that person as the actor of the
change with ``actor_source: client-supplied``. Through the HTTP routes now: a typed name is
``client-supplied``, ``RAPIDTRIAGE_REVIEWER`` is ``server-env``, nothing is ``local-user`` /
``local-default`` -- and the earlier reviewer's name is not carried over. Synthetic run only.
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from rapidtriage.api.app import create_app
from rapidtriage.core.jobs import RunJobStore
from rapidtriage.core.sample_case import build_sample_evidence

TOKEN = "r8-review-actor-token"
EXAMINER_A = "examiner-a"


def without_reviewer_env():
    env = {key: value for key, value in os.environ.items() if key != "RAPIDTRIAGE_REVIEWER"}
    return mock.patch.dict(os.environ, env, clear=True)


class ReviewActorRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        base = Path(cls._tmp.name)
        evidence = base / "evidence"
        build_sample_evidence(evidence)
        cls.client = TestClient(create_app(RunJobStore(), auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})
        response = cls.client.post(
            "/api/runs",
            json={"root": str(evidence), "mode": "fraud", "output_dir": str(base / "out"), "read_only": True, "wait": True},
        )
        assert response.status_code == 202, response.text
        run_id = response.json()["run_id"]
        ensure = cls.client.post(f"/api/runs/{run_id}/case-db/ensure", json={})
        assert ensure.status_code == 200, ensure.text
        cls.database, cls.case_id = ensure.json()["database"], ensure.json()["case_id"]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.close()
        cls._tmp.cleanup()

    def mark(self, target_id: str, reviewer: str | None, status: str) -> dict[str, object]:
        body: dict[str, object] = {
            "database": self.database,
            "case_id": self.case_id,
            "target_type": "document",
            "target_id": target_id,
            "status": status,
        }
        if reviewer is not None:
            body["reviewer"] = reviewer
        response = self.client.post("/api/case-db/review", json=body)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def last_audit(self, target_id: str) -> tuple[str, dict[str, object]]:
        with closing(sqlite3.connect(self.database)) as connection:
            actor, params = connection.execute(
                "SELECT actor, params_json FROM audit_event WHERE action = 'review.marked' AND target_id = ? "
                "ORDER BY rowid DESC LIMIT 1",
                (target_id,),
            ).fetchone()
        return str(actor), json.loads(params)

    def last_history_actor(self, target_id: str) -> str:
        with closing(sqlite3.connect(self.database)) as connection:
            (actor,) = connection.execute(
                "SELECT actor FROM review_mark_history WHERE target_id = ? ORDER BY rowid DESC LIMIT 1", (target_id,)
            ).fetchone()
        return str(actor)

    def test_unnamed_change_after_a_named_mark_is_local_user(self) -> None:
        with without_reviewer_env():
            first = self.mark("t1", EXAMINER_A, "relevant")
            self.assertEqual(first["reviewer"], EXAMINER_A)
            actor, params = self.last_audit("t1")
            self.assertEqual((actor, params["actor_source"]), (EXAMINER_A, "client-supplied"))
            for unnamed in ("", "   ", None):
                with self.subTest(reviewer=unnamed):
                    second = self.mark("t1", unnamed, "excluded")
                    actor, params = self.last_audit("t1")
                    self.assertEqual(actor, "local-user")
                    self.assertEqual(params["actor_source"], "local-default")
                    self.assertEqual(self.last_history_actor("t1"), "local-user")
                    self.assertNotEqual(second["reviewer"], EXAMINER_A)
                    self.assertEqual(second["status"], "excluded")

    def test_server_env_reviewer_is_labelled_server_env(self) -> None:
        with mock.patch.dict(os.environ, {"RAPIDTRIAGE_REVIEWER": "env-examiner"}):
            self.mark("t2", "", "relevant")
        actor, params = self.last_audit("t2")
        self.assertEqual(actor, "env-examiner")
        self.assertEqual(params["actor_source"], "server-env")

    def test_batch_route_never_inherits_either(self) -> None:
        with without_reviewer_env():
            self.mark("t3", EXAMINER_A, "relevant")
            response = self.client.post(
                "/api/case-db/review-batch",
                json={
                    "database": self.database,
                    "case_id": self.case_id,
                    "targets": [{"target_type": "document", "target_id": "t3"}],
                    "status": "needs-review",
                    "reviewer": "",
                },
            )
            self.assertEqual(response.status_code, 200, response.text)
        actor, params = self.last_audit("t3")
        self.assertEqual(actor, "local-user")
        self.assertEqual(params["actor_source"], "local-default")
        self.assertNotEqual(response.json()["marks"][0]["reviewer"], EXAMINER_A)


if __name__ == "__main__":
    unittest.main()
