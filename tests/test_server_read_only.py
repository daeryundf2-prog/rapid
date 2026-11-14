"""R8 T-112: a read-only server (`rapidtriage web --read-only`) refuses every state-changing request.

* every non-GET route of the OpenAPI schema answers 409 ``RUN_READ_ONLY`` with
  ``readonly_reason: SERVER_READ_ONLY`` and the server's own sentence and hint, except the run query
  POSTs of the T-032 allowlist and the path pre-check POSTs;
* the run folders the server knows are held read-only (the D37 write guard refuses writes into
  them) and released when the app shuts down; GETs and allowed queries leave them unchanged;
* a writable server is not affected.
"""

from __future__ import annotations

import re
import unittest

from fastapi.testclient import TestClient

from rapidtriage.api.app import create_app
from rapidtriage.api.app.factory import READ_ONLY_RUN_QUERY_POSTS
from rapidtriage.api.app.readonly_mode import (
    SERVER_READ_ONLY_CHECK_POSTS,
    SERVER_READ_ONLY_HINT,
    SERVER_READ_ONLY_MESSAGE,
    server_read_only_enabled,
    server_read_only_refusal,
)
from rapidtriage.core.readonly_runs import ReadOnlyRunWriteError, readonly_reason_for
from tests import quiet_media_checks
from tests.test_r8_import_readonly import TOKEN, Base, snapshot

setUpModule = quiet_media_checks.setUpModule
tearDownModule = quiet_media_checks.tearDownModule

PARAM = re.compile(r"{(\w+)}")
ALLOWED = {("post", f"/api/runs/{{run_id}}{rest}") for rest in READ_ONLY_RUN_QUERY_POSTS} | {
    ("post", path) for path in SERVER_READ_ONLY_CHECK_POSTS
}


def fill(path: str, run_id: str) -> str:
    return PARAM.sub(lambda match: run_id if match.group(1) == "run_id" else "1", path)


class GateTests(unittest.TestCase):
    def test_switch(self) -> None:
        self.assertTrue(server_read_only_enabled(True))
        self.assertFalse(server_read_only_enabled(False))

    def test_gate_decisions(self) -> None:
        refused = (
            ("POST", "/api/cases"),
            ("POST", "/api/runs"),
            ("POST", "/api/runs/import"),
            ("DELETE", "/api/runs/r1"),
            ("POST", "/api/runs/r1/bookmarks"),
            ("PUT", "/api/runs/r1/case-notes"),
            ("PATCH", "/api/cases/c1"),
            ("POST", "/api/runs/r1/search/entities/reveal"),
            ("POST", "/api/case-db/search"),
        )
        for method, path in refused:
            with self.subTest(method=method, path=path):
                response = server_read_only_refusal(method, path, READ_ONLY_RUN_QUERY_POSTS)
                self.assertIsNotNone(response)
                self.assertEqual(response.status_code, 409)
        passed = (
            ("GET", "/api/runs/r1/files"),
            ("HEAD", "/api/health"),
            ("OPTIONS", "/api/cases"),
            ("POST", "/api/runs/r1/search/query"),
            ("POST", "/api/cases/output-check"),
            ("POST", "/static/x"),
        )
        for method, path in passed:
            with self.subTest(method=method, path=path):
                self.assertIsNone(server_read_only_refusal(method, path, READ_ONLY_RUN_QUERY_POSTS))


class ReadOnlyServerTests(Base):
    def setUp(self) -> None:
        super().setUp()
        # A writable server imports a finished run (outside the evidence) into the shared store.
        self.folder = self.copy_output(self.base / "out-copy")
        response = self.import_folder(self.folder)
        self.assertEqual(response.status_code, 201, response.text)
        self.assertIsNone(response.json()["readonly_reason"])
        self.run_id = response.json()["run_id"]
        app = create_app(self.store, auth_token=TOKEN, read_only=True)
        self.holds = app.state.server_read_only_holds
        self.addCleanup(self.holds.release)
        self.ro = TestClient(app, headers={"X-RapidTriage-Token": TOKEN})
        self.addCleanup(self.ro.close)

    def assert_server_read_only(self, response, label: str) -> None:
        self.assertEqual(response.status_code, 409, f"{label}: {response.text[:300]}")
        body = response.json()
        self.assertEqual(body["code"], "RUN_READ_ONLY", label)
        self.assertEqual(body["message"], SERVER_READ_ONLY_MESSAGE, label)
        self.assertEqual(body["hint"], SERVER_READ_ONLY_HINT, label)
        self.assertEqual(body["detail"]["readonly_reason"], "SERVER_READ_ONLY", label)

    def test_every_state_changing_route_is_refused(self) -> None:
        before = snapshot(self.folder)
        refused: list[str] = []
        for path, item in self.ro.app.openapi()["paths"].items():
            for method in ("post", "put", "patch", "delete"):
                if method not in item or not path.startswith("/api/") or (method, path) in ALLOWED:
                    continue
                url = fill(path, self.run_id)
                response = self.ro.request(method.upper(), url, json={})
                self.assert_server_read_only(response, f"{method.upper()} {path}")
                refused.append(f"{method} {path}")
        self.assertGreater(len(refused), 40)
        self.assertEqual(snapshot(self.folder), before)
        # The run is still listed: DELETE was refused too.
        self.assertEqual(self.ro.get(f"/api/runs/{self.run_id}").status_code, 200)

    def test_reads_and_allowed_queries_write_nothing(self) -> None:
        before = snapshot(self.folder)
        self.assertEqual(self.ro.get("/api/health").status_code, 200)
        self.assertEqual(self.ro.get(f"/api/runs/{self.run_id}").status_code, 200)
        self.ro.get(f"/api/runs/{self.run_id}/files")
        self.ro.get(f"/api/runs/{self.run_id}/search/index")
        for rest in sorted(READ_ONLY_RUN_QUERY_POSTS):
            response = self.ro.post(f"/api/runs/{self.run_id}{rest}", json={})
            self.assertNotEqual(response.status_code, 500, f"{rest}: {response.text[:300]}")
            if response.status_code == 409:
                self.assertEqual(response.json()["detail"]["readonly_reason"], "SERVER_READ_ONLY", rest)
        response = self.ro.post("/api/cases/output-check", json={"path": str(self.base / "new-out"), "kind": "output_dir"})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(snapshot(self.folder), before)

    def test_run_folders_are_held_read_only_until_shutdown(self) -> None:
        self.ro.get("/api/health")
        self.assertEqual(readonly_reason_for(self.folder / "new.txt"), "SERVER_READ_ONLY")
        with self.assertRaises(ReadOnlyRunWriteError):
            (self.folder / "new.txt").write_text("x", encoding="utf-8")
        self.holds.release()
        self.assertIsNone(readonly_reason_for(self.folder / "new.txt"))

    def test_writable_server_is_not_affected(self) -> None:
        response = self.client.post("/api/cases/output-check", json={"path": str(self.base / "x"), "kind": "output_dir"})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertFalse(self.client.app.state.server_read_only)
        self.assertIsNone(self.client.app.state.server_read_only_holds)
        self.assertIsNone(readonly_reason_for(self.folder / "new.txt"))


if __name__ == "__main__":
    unittest.main()
