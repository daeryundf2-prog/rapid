"""R8 T-032 (D37): the read-only run gate, completed.

* every state-changing route of the OpenAPI schema that names a read-only run — by the
  ``/api/runs/{run_id}/…`` path or by the ``run_id`` query of ``/api/cases/{case_id}/…`` — answers
  ``409 RUN_READ_ONLY`` with the Korean envelope, except the contract D.10 allowlist: the four
  search-query POSTs and removing the run from the list;
* a normal run is not affected by the gate;
* the process write guard also refuses deletes and writes into SQLite databases that already exist
  under a read-only folder (the two gaps of the merged audit hook), follows a link / junction that
  is the last path component, and a SQLite write it refuses answers 409, not 500.
"""

from __future__ import annotations

import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from rapidtriage.api.app.factory import (
    READ_ONLY_RUN_MESSAGES,
    READ_ONLY_RUN_QUERY_POSTS,
    read_only_run_refusal,
)
from rapidtriage.core.readonly_runs import (
    RUN_READ_ONLY_MESSAGE,
    ReadOnlyRunWriteError,
    install_write_guard,
    readonly_reason_for,
    register_readonly_folder,
    unregister_readonly_folder,
)
from tests.test_r8_import_readonly import Base, snapshot

PARAM = re.compile(r"{(\w+)}")
NON_GET = ("post", "put", "patch", "delete")
ALLOWED = {("post", f"/api/runs/{{run_id}}{rest}") for rest in READ_ONLY_RUN_QUERY_POSTS} | {("delete", "/api/runs/{run_id}")}
# Review-tool writes under ``/api/cases/{case_id}`` that find the case DB through ``?run_id=``.
CASE_RUN_QUERY_WRITES = (
    ("post", "/api/cases/{case_id}/tags", {"name": "x", "color_token": "red"}),
    ("patch", "/api/cases/{case_id}/tags/{tag_id}", {"name": "y"}),
    ("delete", "/api/cases/{case_id}/tags/{tag_id}", None),
    ("post", "/api/cases/{case_id}/histogram-baselines", {"name": "b"}),
)


def fill(path: str, run_id: str) -> str:
    return PARAM.sub(lambda match: run_id if match.group(1) == "run_id" else "1", path)


class AllowlistTests(unittest.TestCase):
    def test_allowlist_is_exactly_the_four_search_queries(self) -> None:
        self.assertEqual(READ_ONLY_RUN_QUERY_POSTS, {"/search/count", "/search/query", "/search/entities", "/search/hashes"})

    def test_gate_decisions(self) -> None:
        jobs = {"ro": SimpleNamespace(readonly_reason="OUTPUT_INSIDE_EVIDENCE"), "rw": SimpleNamespace(readonly_reason=None)}

        class Store:
            def get(self, run_id: str):
                return jobs[run_id]

        store = Store()
        refused = (
            ("POST", "/api/runs/ro/bookmarks", None),
            ("PUT", "/api/runs/ro/case-notes", None),
            ("DELETE", "/api/runs/ro/search/lists/1", None),
            ("POST", "/api/runs/ro/search/entities/reveal", None),
            ("POST", "/api/cases/c/tags", "ro"),
            ("DELETE", "/api/cases/c/tags/1", "ro"),
        )
        for method, path, query in refused:
            with self.subTest(method=method, path=path):
                response = read_only_run_refusal(store, method, path, query)  # type: ignore[arg-type]
                self.assertIsNotNone(response)
                self.assertEqual(response.status_code, 409)
        passed = (
            ("GET", "/api/runs/ro/files", None),
            ("HEAD", "/api/runs/ro", None),
            ("DELETE", "/api/runs/ro", None),
            ("POST", "/api/runs/ro/search/query", None),
            ("POST", "/api/runs/rw/bookmarks", None),
            ("POST", "/api/runs/missing/bookmarks", None),
            ("POST", "/api/cases/c/tags", "rw"),
            ("POST", "/api/cases/c/tags", None),
            ("POST", "/api/cases/c/tags", "missing"),
            ("GET", "/api/cases/c/tags", "ro"),
            ("POST", "/static/x", "ro"),
        )
        for method, path, query in passed:
            with self.subTest(method=method, path=path):
                self.assertIsNone(read_only_run_refusal(store, method, path, query))  # type: ignore[arg-type]


class ReadOnlyGateTests(Base):
    def setUp(self) -> None:
        super().setUp()
        self.legacy = self.copy_output(self.evidence / "legacy-out")
        response = self.import_folder(self.legacy)
        self.assertEqual(response.status_code, 201, response.text)
        self.run_id = response.json()["run_id"]
        self.assertEqual(response.json()["readonly_reason"], "OUTPUT_INSIDE_EVIDENCE")

    def assert_read_only(self, response, label: str, message: str = RUN_READ_ONLY_MESSAGE) -> None:
        self.assertEqual(response.status_code, 409, f"{label}: {response.text[:300]}")
        body = response.json()
        self.assertEqual(body["code"], "RUN_READ_ONLY", label)
        self.assertEqual(body["message"], message, label)
        self.assertIn("증거 밖", body["hint"], label)
        self.assertEqual(body["detail"]["code"], "RUN_READ_ONLY", label)
        self.assertEqual(body["detail"]["readonly_reason"], "OUTPUT_INSIDE_EVIDENCE", label)

    def test_every_state_changing_run_route_is_refused(self) -> None:
        before = snapshot(self.evidence)
        schema = self.client.app.openapi()
        refused: list[str] = []
        allowed: list[str] = []
        for path, operations in schema["paths"].items():
            if not path.startswith("/api/runs/{run_id}"):
                continue
            for method in NON_GET:
                if method not in operations:
                    continue
                label = f"{method.upper()} {path}"
                if (method, path) == ("delete", "/api/runs/{run_id}"):
                    allowed.append(label)  # exercised last, below
                    continue
                url = fill(path, self.run_id)
                send = getattr(self.client, method)
                response = send(url) if method == "delete" else send(url, json={})
                if (method, path) in ALLOWED:
                    allowed.append(label)
                    self.assertNotEqual(response.status_code, 500, f"{label}: {response.text[:300]}")
                    self.assertNotEqual(response.json().get("code"), "RUN_READ_ONLY", label)
                else:
                    refused.append(label)
                    rest = path.removeprefix("/api/runs/{run_id}")
                    self.assert_read_only(response, label, READ_ONLY_RUN_MESSAGES.get(rest, RUN_READ_ONLY_MESSAGE))
        self.assertEqual(len(allowed), len(ALLOWED))
        self.assertGreaterEqual(len(refused), 20, refused)
        self.assertEqual(snapshot(self.evidence), before)
        removed = self.client.delete(f"/api/runs/{self.run_id}")
        self.assertEqual(removed.status_code, 204, removed.text)
        self.assertEqual(snapshot(self.evidence), before)

    def test_case_review_tool_writes_naming_the_run_are_refused(self) -> None:
        before = snapshot(self.evidence)
        schema_paths = self.client.app.openapi()["paths"]
        for method, path, body in CASE_RUN_QUERY_WRITES:
            self.assertIn(method, schema_paths[path], path)
            url = fill(path, self.run_id)
            send = getattr(self.client, method)
            params = {"run_id": self.run_id}
            response = send(url, params=params) if body is None else send(url, params=params, json=body)
            self.assert_read_only(response, f"{method.upper()} {path}")
        self.assertEqual(snapshot(self.evidence), before)

    def test_refused_sqlite_write_is_409_not_500(self) -> None:
        database = self.legacy / "guard-probe.db"
        unregister_readonly_folder(self.legacy)
        try:
            with sqlite3.connect(database) as connection:
                connection.execute("CREATE TABLE t (a)")
            connection.close()
        finally:
            register_readonly_folder(self.legacy, "OUTPUT_INSIDE_EVIDENCE")
        before = database.read_bytes()

        @self.client.app.get("/api/runs/{run_id}/_guard-probe")
        def probe(run_id: str) -> dict[str, str]:  # a GET with a lazy write the gate cannot see
            connection = sqlite3.connect(database)
            try:
                connection.execute("INSERT INTO t VALUES (1)")
            finally:
                connection.close()
            return {"run_id": run_id}

        self.assert_read_only(self.client.get(f"/api/runs/{self.run_id}/_guard-probe"), "sqlite probe")
        self.assertEqual(database.read_bytes(), before)

    def test_normal_run_is_not_gated(self) -> None:
        normal = self.copy_output(self.base / "normal-out")
        response = self.import_folder(normal)
        self.assertEqual(response.status_code, 201, response.text)
        self.assertIsNone(response.json()["readonly_reason"])
        normal_id = response.json()["run_id"]
        saved = self.client.put(f"/api/runs/{normal_id}/case-notes", json={"notes": "메모"})
        self.assertEqual(saved.status_code, 200, saved.text)
        tags = self.client.post(
            "/api/cases/x/tags", params={"run_id": normal_id}, json={"name": "x", "color_token": "red"}
        )
        self.assertNotEqual(tags.json().get("code"), "RUN_READ_ONLY", tags.text)


class WriteGuardGapTests(unittest.TestCase):
    def setUp(self) -> None:
        install_write_guard()
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.folder = Path(self._tmp.name).resolve() / "run"
        (self.folder / "sub").mkdir(parents=True)
        self.kept = self.folder / "kept.json"
        self.kept.write_text("{}", encoding="utf-8")
        self.database = self.folder / "index.db"
        with sqlite3.connect(self.database) as connection:
            connection.execute("CREATE TABLE t (a)")
            connection.execute("INSERT INTO t VALUES (1)")
        connection.close()
        register_readonly_folder(self.folder, "OUTPUT_INSIDE_EVIDENCE")
        self.addCleanup(unregister_readonly_folder, self.folder)

    def test_deletes_are_refused(self) -> None:
        for attempt in (
            lambda: self.kept.unlink(),
            lambda: (self.folder / "sub").rmdir(),
            lambda: shutil.rmtree(self.folder / "sub"),
            lambda: shutil.rmtree(self.folder),
        ):
            with self.assertRaises(ReadOnlyRunWriteError):
                attempt()
        self.assertTrue(self.kept.is_file())
        self.assertTrue((self.folder / "sub").is_dir())
        (self.folder / "never-written.tmp").unlink(missing_ok=True)  # nothing to delete: no refusal

    def test_existing_sqlite_database_is_read_only(self) -> None:
        before = self.database.read_bytes()
        connection = sqlite3.connect(self.database)
        try:
            self.assertEqual(connection.execute("SELECT a FROM t").fetchall(), [(1,)])
            for statement in ("INSERT INTO t VALUES (2)", "CREATE TABLE u (b)", "DELETE FROM t"):
                with self.subTest(statement), self.assertRaises(sqlite3.OperationalError):
                    connection.execute(statement)
        finally:
            connection.close()
        uri = sqlite3.connect(f"{self.database.as_uri()}?mode=ro", uri=True)
        try:
            self.assertEqual(uri.execute("SELECT count(*) FROM t").fetchone(), (1,))
        finally:
            uri.close()
        with self.assertRaises(ReadOnlyRunWriteError):
            sqlite3.connect(self.folder / "new.db")
        self.assertFalse((self.folder / "new.db").exists())
        self.assertEqual(self.database.read_bytes(), before)

    def test_last_component_link_into_the_folder_is_followed(self) -> None:
        outside = Path(self._tmp.name).resolve() / "outside"
        outside.mkdir()
        junction = outside / "into-run"
        if os.name == "nt":
            made = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(junction), str(self.folder / "sub")], capture_output=True, check=False
            )
            if made.returncode != 0:
                self.skipTest(f"mklink /J failed: {made.stderr!r}")
        else:
            # The guard refuses creating a link that points into a read-only folder, so make it first.
            reason = readonly_reason_for(self.folder)
            unregister_readonly_folder(self.folder)
            try:
                junction.symlink_to(self.folder / "sub", target_is_directory=True)
            finally:
                register_readonly_folder(self.folder, reason or "OUTPUT_INSIDE_EVIDENCE")
        self.assertEqual(readonly_reason_for(junction), "OUTPUT_INSIDE_EVIDENCE")  # the leaf is the link
        with self.assertRaises(ReadOnlyRunWriteError):
            shutil.copyfile(self.database, junction)  # target is the leaf link itself
        with self.assertRaises(ReadOnlyRunWriteError):
            (junction / "x.json").write_text("x", encoding="utf-8")  # parent is the link
        with self.assertRaises(ReadOnlyRunWriteError):
            os.mkdir(junction / "made")
        self.assertEqual(list((self.folder / "sub").iterdir()), [])
        link = outside / "kept-link.json"
        unregister_readonly_folder(self.folder)  # the guard also refuses creating a link to it
        try:
            link.symlink_to(self.kept)
        except OSError as exc:
            self.skipTest(f"file symlinks need privilege here: {exc}")
        finally:
            register_readonly_folder(self.folder, "OUTPUT_INSIDE_EVIDENCE")
        with self.assertRaises(ReadOnlyRunWriteError):
            link.write_text("changed", encoding="utf-8")  # the leaf itself is the link
        self.assertEqual(self.kept.read_text(encoding="utf-8"), "{}")

    def test_outside_the_folder_is_unaffected(self) -> None:
        beside = Path(self._tmp.name).resolve() / "beside.db"
        with sqlite3.connect(beside) as connection:
            connection.execute("CREATE TABLE t (a)")
            connection.execute("INSERT INTO t VALUES (1)")
        connection.close()
        beside.unlink()
        self.assertFalse(beside.exists())


if __name__ == "__main__":
    unittest.main()
