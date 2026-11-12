"""R8 browser check: list reads answer on a read-only server (`rapidtriage web --read-only`).

Every console load called ``POST /api/case-db/saved-searches/list`` and ``GET /api/cases/{case}/tags``
and got 409 ``RUN_READ_ONLY``: the list POST was not on the server's query allowlist, and both routes
opened the case DB for writing (initialisation, system-tag migration). They now read a held case DB
through ``mode=ro`` and the run folder stays byte-identical. Synthetic fixture run only.
"""

from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from rapidtriage.api.app import create_app
from rapidtriage.api.app.factory import READ_ONLY_RUN_QUERY_POSTS
from rapidtriage.api.app.readonly_mode import server_read_only_refusal
from tests import quiet_media_checks
from tests.test_r8_import_readonly import TOKEN, Base, snapshot

setUpModule = quiet_media_checks.setUpModule
tearDownModule = quiet_media_checks.tearDownModule


class ReadOnlyServerListTests(Base):
    def setUp(self) -> None:
        super().setUp()
        self.folder = self.copy_output(self.base / "out-copy")
        response = self.import_folder(self.folder)
        self.assertEqual(response.status_code, 201, response.text)
        self.run_id = response.json()["run_id"]

    def read_only_client(self) -> TestClient:
        app = create_app(self.store, auth_token=TOKEN, read_only=True)
        self.addCleanup(app.state.server_read_only_holds.release)
        client = TestClient(app, headers={"X-RapidTriage-Token": TOKEN})
        self.addCleanup(client.close)
        return client

    def prepare_case_db(self) -> tuple[str, str]:
        """A case DB with one saved search and the system tags, written by a writable server."""
        ensure = self.client.post(f"/api/runs/{self.run_id}/case-db/ensure", json={})
        self.assertEqual(ensure.status_code, 200, ensure.text)
        database, case_id = ensure.json()["database"], ensure.json()["case_id"]
        saved = self.client.post(
            "/api/case-db/saved-searches",
            json={"database": database, "case_id": case_id, "name": "synthetic", "keywords": ["invoice"]},
        )
        self.assertEqual(saved.status_code, 200, saved.text)
        tags = self.client.get(f"/api/cases/{case_id}/tags", params={"run_id": self.run_id})
        self.assertEqual(tags.status_code, 200, tags.text)
        return database, case_id

    def test_gate_allows_the_saved_search_list(self) -> None:
        self.assertIsNone(server_read_only_refusal("POST", "/api/case-db/saved-searches/list", READ_ONLY_RUN_QUERY_POSTS))
        self.assertIsNotNone(server_read_only_refusal("POST", "/api/case-db/saved-searches", READ_ONLY_RUN_QUERY_POSTS))

    def test_lists_read_an_existing_case_db_without_writing(self) -> None:
        database, case_id = self.prepare_case_db()
        writable_tags = self.client.get(f"/api/cases/{case_id}/tags", params={"run_id": self.run_id}).json()["tags"]
        ro = self.read_only_client()
        before = snapshot(self.folder)
        for _ in range(2):
            listed = ro.post("/api/case-db/saved-searches/list", json={"database": database, "case_id": case_id})
            self.assertEqual(listed.status_code, 200, listed.text)
            self.assertEqual([item["name"] for item in listed.json()["saved_searches"]], ["synthetic"])
        tags = ro.get(f"/api/cases/{case_id}/tags", params={"run_id": self.run_id})
        self.assertEqual(tags.status_code, 200, tags.text)
        self.assertTrue(tags.json()["exists"])
        self.assertEqual([tag["name"] for tag in tags.json()["tags"]], [tag["name"] for tag in writable_tags])
        by_path = ro.get(f"/api/cases/{case_id}/tags", params={"database": database})
        self.assertEqual(by_path.status_code, 200, by_path.text)
        # Writes stay refused.
        self.assertEqual(
            ro.post("/api/case-db/saved-searches", json={"database": database, "case_id": case_id, "name": "x", "keywords": ["y"]}).status_code,
            409,
        )
        self.assertEqual(snapshot(self.folder), before)

    def test_lists_without_a_case_db_are_empty_and_create_nothing(self) -> None:
        ro = self.read_only_client()
        before = snapshot(self.folder)
        database = str(self.folder / "rapidtriage-case.db")
        listed = ro.post("/api/case-db/saved-searches/list", json={"database": database, "case_id": "c"})
        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertEqual(listed.json()["saved_searches"], [])
        run = ro.get(f"/api/runs/{self.run_id}").json()
        self.assertEqual(run["status"], "completed")
        self.assertEqual(snapshot(self.folder), before)


if __name__ == "__main__":
    unittest.main()
