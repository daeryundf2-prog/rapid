"""R8 T-134 (D37): read-only results — the other lazy writes.

* AST: every file-system write in the seven media / preview / flag / condition / search modules
  is reached only through a persist guard or a state-changing route the read-only gate refuses.
* the search history writer guards itself (not only its caller), and a search-index build on a
  read-only run is refused with its own Korean sentence — by the gate, by the service and by the
  auto build; a query on a read-only run without an index explains why there is none.
* the five screens (similar media, SQLite preview, flags, row conditions, search) plus thumbnails
  and analyses answer on a read-only run and leave the evidence folder byte-identical.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from rapidtriage.api.app import routes_media, search_index_service
from rapidtriage.api.app.analyses import ANALYSIS_RUNNER, TERMINAL_STATUSES
from rapidtriage.api.app.search_index_service import (
    AUTO_INDEX_ENV,
    READ_ONLY_INDEX,
    SEARCH_HISTORY,
    SearchHistory,
    submit_build,
)
from rapidtriage.core.readonly_runs import (
    RUN_READ_ONLY,
    install_write_guard,
    register_readonly_folder,
    unregister_readonly_folder,
)
from rapidtriage.core.search_index.schema import INDEX_FILE_NAME
from tests.lazy_write_ast import API_APP, Package
from tests.test_r8_import_readonly import Base, snapshot

#: T-134 targets (plan appendix F row T-134, v2 file list).
MISC_MODULES = (
    "media_similar.py",
    "media.py",
    "sqlite.py",
    "previews.py",
    "triage_flags.py",
    "row_conditions.py",
    "search_index_service.py",
)
HISTORY = Path("Users") / "alice" / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default" / "History"
IMAGE = Path("Users") / "alice" / "Desktop" / "screen-capture.png"


class MiscWriteAstTests(unittest.TestCase):
    def test_every_misc_module_write_asks_a_persist_guard_or_is_gated(self) -> None:
        package = Package()
        checked = 0
        for name in MISC_MODULES:
            with self.subTest(name):
                _sites, problems = package.unguarded(API_APP / name)
                checked += 1
                self.assertEqual(problems, [])
        self.assertEqual(checked, 7)
        history_writes = [site for site in package.write_sites(API_APP / "search_index_service.py") if site[0].unit == "_write"]
        self.assertTrue(history_writes)


class HistoryWriterGuardTests(unittest.TestCase):
    def test_write_itself_refuses_a_read_only_folder(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir).resolve() / "run"
            folder.mkdir()
            register_readonly_folder(folder, "OUTPUT_INSIDE_EVIDENCE")
            try:
                with mock.patch.object(search_index_service.sqlite3, "connect") as connect:
                    SearchHistory()._write(folder, [("2026-01-01T00:00:00", "q", "{}", "ok")])
                connect.assert_not_called()
            finally:
                unregister_readonly_folder(folder)
            self.assertEqual(list(folder.iterdir()), [])
            history = SearchHistory()
            history._write(folder, [("2026-01-01T00:00:00", "q", "{}", "ok")])  # a normal folder still gets it
            self.assertTrue(SearchHistory.path_for(folder).is_file())
            self.assertEqual(len(history.read(folder, 10)), 1)


class ReadOnlyIndexConnectionTests(unittest.TestCase):
    """The search index reader (``file:…?mode=ro``) keeps its in-memory TEMP tables on a read-only run."""

    def setUp(self) -> None:
        install_write_guard()
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.folder = Path(self._tmp.name).resolve() / "run"
        self.folder.mkdir()
        self.database = self.folder / "index.db"
        with sqlite3.connect(self.database) as connection:
            connection.execute("CREATE TABLE t (a)")
            connection.execute("INSERT INTO t VALUES (1)")
        connection.close()
        register_readonly_folder(self.folder, "OUTPUT_INSIDE_EVIDENCE")
        self.addCleanup(unregister_readonly_folder, self.folder)

    def test_read_only_uri_keeps_temp_tables_and_changes_nothing_else(self) -> None:
        before = self.database.read_bytes()
        connection = sqlite3.connect(f"{self.database.as_uri()}?mode=ro", uri=True)
        try:
            connection.execute("PRAGMA temp_store = MEMORY")
            connection.execute("CREATE TEMP TABLE m (a)")
            connection.execute("INSERT INTO temp.m SELECT a FROM t")
            self.assertEqual(connection.execute("SELECT count(*) FROM temp.m").fetchone(), (1,))
            with self.assertRaises(sqlite3.DatabaseError):
                connection.execute("INSERT INTO t VALUES (2)")  # the file itself stays read-only
            connection.execute("ATTACH DATABASE ? AS w", (str(self.database),))  # opens read-write ...
            for statement in ("INSERT INTO w.t VALUES (3)", "CREATE TABLE w.u (b)", "DELETE FROM w.t"):
                with self.subTest(statement), self.assertRaises(sqlite3.DatabaseError):
                    connection.execute(statement)  # ... but only ``temp`` may change
            with self.assertRaises(sqlite3.DatabaseError):
                connection.execute(f"ATTACH DATABASE '{self.folder / 'new.db'}' AS n")
            self.assertEqual(connection.execute("SELECT count(*) FROM w.t").fetchone(), (1,))
        finally:
            connection.close()
        plain = sqlite3.connect(self.database)  # a plain connection is still query_only
        try:
            with self.assertRaises(sqlite3.OperationalError):
                plain.execute("CREATE TEMP TABLE m (a)")
        finally:
            plain.close()
        self.assertEqual(self.database.read_bytes(), before)
        self.assertEqual(sorted(path.name for path in self.folder.iterdir()), ["index.db"])


class ReadOnlyMiscScreenTests(Base):
    def setUp(self) -> None:
        env = mock.patch.dict(os.environ, {AUTO_INDEX_ENV: "1"})  # the auto build must not write either
        env.start()
        self.addCleanup(env.stop)
        super().setUp()
        self.addCleanup(SEARCH_HISTORY.flush)
        self.addCleanup(lambda: ANALYSIS_RUNNER.shutdown(owner=self.client.app.state.analysis_owner))

    def url(self, run_id: str, rest: str) -> str:
        return f"/api/runs/{run_id}/{rest}"

    def import_read_only(self, folder: Path) -> str:
        # In-process import: this module tests the lazy-write guard, not T-350's root verification
        # (an API import of a copied run cannot prove its evidence root, so source reads would 403).
        run_id = self.store.import_completed_run(folder).run_id
        detail = self.client.get(f"/api/runs/{run_id}")
        self.assertEqual(detail.status_code, 200, detail.text)
        self.assertEqual(detail.json()["readonly_reason"], "OUTPUT_INSIDE_EVIDENCE")
        return run_id

    def wait(self, run_id: str, analysis_id: str) -> dict:
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            state = self.client.get(self.url(run_id, f"analyses/{analysis_id}")).json()
            if state["status"] in TERMINAL_STATUSES:
                return state
            time.sleep(0.1)
        self.fail(f"analysis {analysis_id} did not finish")

    def indexed_read_only_run(self) -> tuple[str, Path, int]:
        """A run indexed (and given a saved search) while normal, then copied into its evidence."""
        normal = self.copy_output(self.base / "normal-out")
        response = self.import_folder(normal)
        self.assertEqual(response.status_code, 201, response.text)
        normal_id = response.json()["run_id"]
        ensured = self.client.post(self.url(normal_id, "case-db/ensure"), json={})
        self.assertEqual(ensured.status_code, 200, ensured.text)
        built = self.client.post(self.url(normal_id, "search/index/build"), json={"mode": "full"})
        if built.status_code == 409:  # the auto build of the import is already running
            latest = search_index_service.latest_build(normal)
            assert latest is not None
            analysis_id = str(latest["analysis_id"])
        else:
            self.assertEqual(built.status_code, 202, built.text)
            analysis_id = built.json()["analysis_id"]
        self.assertEqual(self.wait(normal_id, analysis_id)["status"], "completed")
        saved = self.client.post(self.url(normal_id, "search/saved"), json={"name": "지갑", "q": "wallet"})
        self.assertEqual(saved.status_code, 201, saved.text)
        removed = self.client.delete(self.url(normal_id, ""))
        self.assertEqual(removed.status_code, 204, removed.text)
        legacy = self.evidence / "legacy-indexed"
        shutil.copytree(normal, legacy)
        return self.import_read_only(legacy), legacy, int(saved.json()["id"])

    def assert_unchanged(self, before: dict[str, str]) -> None:
        SEARCH_HISTORY.flush()
        self.assertEqual(snapshot(self.evidence), before)

    def get_ok(self, run_id: str, rest: str, params: dict[str, str], expected: int = 200):  # type: ignore[no-untyped-def]
        response = self.client.get(self.url(run_id, rest), params=params)
        self.assertEqual(response.status_code, expected, f"{rest} {params}: {response.text[:300]}")
        return response

    # -- the five screens + thumbnails + analyses ----------------------------------------------

    def test_media_similar(self) -> None:
        run_id = self.import_read_only(self.copy_output(self.evidence / "legacy-out"))
        before = snapshot(self.evidence)
        groups = self.get_ok(run_id, "media/groups", {"by": "date"}).json()
        self.assertGreaterEqual(groups["index"]["rows"], 1)
        self.get_ok(run_id, "media/groups", {"by": "camera"})
        reference = groups["groups"][0]["sample_paths"][0]  # as the image artifacts recorded it
        similar = self.get_ok(run_id, "media/similar", {"ref": reference}, expected=409)  # the sample image has no pHash
        self.assertIn("pHash", similar.json()["message"])
        self.assert_unchanged(before)

    def test_sqlite_preview(self) -> None:
        run_id = self.import_read_only(self.copy_output(self.evidence / "legacy-out"))
        before = snapshot(self.evidence)
        table = self.get_ok(run_id, "source-sqlite-table", {"path": str(self.evidence / HISTORY), "table": "urls"}).json()
        self.assertTrue(table["sqlite_snapshot"]["files"])
        self.get_ok(run_id, "source-sqlite-wal-preview", {"path": str(self.evidence / HISTORY)})
        self.assert_unchanged(before)

    def test_flags(self) -> None:
        run_id = self.import_read_only(self.copy_output(self.evidence / "legacy-out"))
        before = snapshot(self.evidence)
        self.assertEqual(self.get_ok(run_id, "flags", {}).json()["run_id"], run_id)
        self.get_ok(run_id, "flags/row", {"kind": "files:candidates", "record_index": "0"})
        self.get_ok(run_id, "artifacts", {"kind": "recent-files", "flag_grade": "A", "limit": "20"})
        self.assert_unchanged(before)

    def test_row_conditions(self) -> None:
        run_id = self.import_read_only(self.copy_output(self.evidence / "legacy-out"))
        before = snapshot(self.evidence)
        for rest, params in (
            ("artifacts", {"kind": "recent-files", "from": "2020-01-01", "weekday": "mon", "offhours": "1", "limit": "20"}),
            ("timeline", {"limit": "20", "hours": "9-18", "tz": "+09:00"}),
            ("files", {"limit": "20", "from": "2020-01-01", "partial": "1"}),
        ):
            self.get_ok(run_id, rest, params)
        self.assert_unchanged(before)

    def test_search(self) -> None:
        run_id, legacy, saved_id = self.indexed_read_only_run()
        before = snapshot(self.evidence)
        with mock.patch.object(SearchHistory, "_write", autospec=True, side_effect=SearchHistory._write) as history_write:
            query = self.client.post(self.url(run_id, "search/query"), json={"q": "wallet", "saved_id": saved_id})
            self.assertEqual(query.status_code, 200, query.text)
            self.assertGreater(query.json()["page"]["total"], 0)
            count = self.client.post(self.url(run_id, "search/count"), json={"terms": [{"q": "wallet"}]})
            self.assertEqual(count.status_code, 200, count.text)
            SEARCH_HISTORY.flush()
            history_write.assert_not_called()
        self.assertIn(self.get_ok(run_id, "search/index", {}).json()["status"], {"ready", "stale"})  # copied: may be stale
        self.assertEqual(self.get_ok(run_id, "search/history", {}).json()["history"], [])
        saved = self.get_ok(run_id, "search/saved", {}).json()
        self.assertNotIn("last_count", str(saved))  # the count of the read-only query was not stored
        self.get_ok(run_id, "tree", {})
        self.get_ok(run_id, "search", {"keyword": "wallet"})
        self.assertFalse(SearchHistory.path_for(legacy).exists())
        self.assert_unchanged(before)

    def test_thumbnail_and_analyses(self) -> None:
        run_id = self.import_read_only(self.copy_output(self.evidence / "legacy-out"))
        before = snapshot(self.evidence)
        with mock.patch.object(routes_media, "cached_thumbnail", wraps=routes_media.cached_thumbnail) as thumbnail:
            response = self.client.get(self.url(run_id, "source-thumbnail"), params={"path": str(self.evidence / IMAGE)})
            self.assertIn(response.status_code, {200, 204}, response.text[:300])
        self.assertEqual(thumbnail.call_count, 1)
        self.assertIsNone(thumbnail.call_args.args[2])  # no cache folder: answered from memory
        self.get_ok(run_id, "analyses", {})
        refused = self.client.post(self.url(run_id, "analyses"), json={"kind": "ocr-batch"})
        self.assertEqual(refused.status_code, 409, refused.text)
        self.assertEqual(refused.json()["code"], RUN_READ_ONLY)
        self.assert_unchanged(before)

    # -- the search-index refusal -------------------------------------------------------------

    def test_index_build_is_refused_with_its_own_sentence(self) -> None:
        legacy = self.copy_output(self.evidence / "legacy-out")
        run_id = self.import_read_only(legacy)
        before = snapshot(self.evidence)
        self.assertIsNone(search_index_service.latest_build(legacy))  # the import's auto build did not start
        response = self.client.post(self.url(run_id, "search/index/build"), json={"mode": "full"})
        self.assertEqual(response.status_code, 409, response.text)
        body = response.json()
        self.assertEqual(body["code"], RUN_READ_ONLY)
        self.assertEqual(body["message"], READ_ONLY_INDEX)
        self.assertEqual(body["detail"]["readonly_reason"], "OUTPUT_INSIDE_EVIDENCE")
        with self.assertRaises(HTTPException) as raised:  # the service refuses too (not only the gate)
            submit_build(self.store, run_id, {"mode": "full"}, owner=self.client.app.state.analysis_owner)
        self.assertEqual(raised.exception.status_code, 409)
        self.assertEqual(raised.exception.detail["message"], READ_ONLY_INDEX)  # type: ignore[index]
        for rest, body_json in (("search/query", {"q": "wallet"}), ("search/count", {"terms": [{"q": "wallet"}]})):
            missing = self.client.post(self.url(run_id, rest), json=body_json)
            self.assertEqual(missing.status_code, 404, missing.text)
            self.assertEqual(missing.json()["message"], READ_ONLY_INDEX)
        self.assertEqual(self.get_ok(run_id, "search/index", {}).json()["status"], "none")
        self.assertFalse((legacy / INDEX_FILE_NAME).exists())
        self.assert_unchanged(before)


if __name__ == "__main__":
    unittest.main()
