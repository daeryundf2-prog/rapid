"""R7 stage 1 lane L4 (plan r7-master-2026-10-26 §3.4) backend pieces: the explicit validation
package write (C-G7), the run's ``case_db_ready`` flag (C-G13) and the source viewer's SQLite
detection by magic bytes with a browser-row ``viewer_hint`` and rowid jump (C-W1)."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from rapidtriage.api.app.helpers import is_sqlite_candidate, sqlite_detection
from rapidtriage.api.app.viewer_hint import sqlite_viewer_hint
from rapidtriage.core.jobs import RunJobStore
from tests.test_rapidtriage_api import HAS_FASTAPI, api_test_client


def chromium_history(path: Path, rows: int = 30) -> None:
    connection = sqlite3.connect(path)
    try:
        # More tables than the preview lists (8), "urls" sorted past the limit.
        for name in ("a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "downloads", "keyword_search_terms"):
            connection.execute(f"CREATE TABLE {name}(id INTEGER PRIMARY KEY, v TEXT)")
        connection.execute("CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT)")
        connection.execute("CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER)")
        # Gaps in the ids (deleted rows): the jump must count rows, not trust the id.
        connection.executemany(
            "INSERT INTO urls(id, url, title) VALUES (?, ?, ?)",
            [(index * 3, f"https://example.test/{index}", f"t{index}") for index in range(1, rows + 1)],
        )
        connection.commit()
    finally:
        connection.close()


def imported_run(temp: Path, root: Path) -> tuple[RunJobStore, str, Path]:
    run_dir = temp / "run"
    run_dir.mkdir()
    summary_path = run_dir / "rapidtriage-run-summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "profile_version": "rapidtriage-run-summary-v1",
                "mode": "fraud",
                "root": str(root),
                "output_dir": str(run_dir),
                "source": {"type": "folder", "source_path": str(root), "analysis_root": str(root)},
                "outputs": {"summary": str(summary_path)},
            }
        ),
        encoding="utf-8",
    )
    store = RunJobStore()
    job = store.import_completed_run(run_dir)
    return store, job.run_id, run_dir


class SqliteDetectionTests(unittest.TestCase):
    def test_extensionless_sqlite_is_detected_by_magic_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            history = Path(temp) / "History"
            chromium_history(history)
            named = Path(temp) / "places.sqlite"
            chromium_history(named)
            other = Path(temp) / "notes.db"
            other.write_bytes(b"not a database at all, just text")
            self.assertEqual(sqlite_detection(history), "magic-bytes")
            self.assertEqual(sqlite_detection(named), "extension")
            self.assertIsNone(sqlite_detection(other))
            self.assertTrue(is_sqlite_candidate(history))
            self.assertFalse(is_sqlite_candidate(Path(temp)))

    def test_hint_maps_browser_types_to_present_tables(self) -> None:
        hint = sqlite_viewer_hint("magic-bytes", ["meta", "urls", "visits", "moz_places"])
        self.assertEqual(hint["mode"], "sqlite")
        self.assertEqual(hint["row_tables"]["browser-history"], "urls")
        self.assertEqual(hint["row_tables"]["browser-visit"], "visits")
        self.assertNotIn("browser-cookie", hint["row_tables"])


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for RapidTriage API tests")
class L4ApiTests(unittest.TestCase):
    def test_source_preview_of_history_has_sqlite_hint_and_rowid_jump(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp = Path(tmp)
            root = temp / "evidence"
            profile = root / "Users" / "alice" / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default"
            profile.mkdir(parents=True)
            chromium_history(profile / "History", rows=500)
            store, run_id, _ = imported_run(temp, root)
            client = api_test_client(store)
            path = "Users/alice/AppData/Local/Google/Chrome/User Data/Default/History"

            preview = client.get(f"/api/runs/{run_id}/source-preview", params={"path": path})
            self.assertEqual(preview.status_code, 200, preview.text)
            payload = preview.json()
            self.assertEqual(payload["preview_type"], "sqlite")
            self.assertEqual(payload["mime_type"], "application/octet-stream")
            hint = payload["viewer_hint"]
            self.assertEqual(hint["detected_by"], "magic-bytes")
            self.assertIn("urls", hint["sqlite_tables"])
            self.assertEqual(hint["row_tables"]["browser-history"], "urls")
            # The preview lists 8 tables; "urls" is past that limit but still named.
            self.assertNotIn("urls", [table["name"] for table in payload["sqlite"]["tables"]])

            # id 900 = the 300th row (ids step by 3): page 2 of 200 holds it.
            page = client.get(
                f"/api/runs/{run_id}/source-sqlite-table",
                params={"path": path, "table": "urls", "limit": 200, "locate_rowid": 900},
            )
            self.assertEqual(page.status_code, 200, page.text)
            body = page.json()
            self.assertEqual(body["pagination"]["offset"], 200)
            self.assertEqual(body["pagination"]["located"], {"rowid": 900, "found": True, "row_number": 300})
            self.assertIn(900, [row["rowid"] for row in body["rows"]])

            missing = client.get(
                f"/api/runs/{run_id}/source-sqlite-table",
                params={"path": path, "table": "urls", "limit": 200, "locate_rowid": 901},
            ).json()
            self.assertFalse(missing["pagination"]["located"]["found"])

    def test_validation_package_post_writes_and_names_paths_saved_get_is_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            client = api_test_client(RunJobStore())
            response = client.post(
                "/api/sample-case/run",
                json={"output_dir": str(Path(tmp_dir) / "sample"), "mode": "fraud", "overwrite": True, "read_only": True},
            )
            self.assertEqual(response.status_code, 201, response.text)
            run = response.json()["run"]
            run_id = run["run_id"]
            output_dir = Path(run["summary"]["output_dir"])
            package_path = output_dir / "rapidforensic-run-validation-package.json"

            before = client.get(f"/api/runs/{run_id}/validation-package/saved")
            self.assertEqual(before.status_code, 404)
            self.assertFalse(package_path.exists())

            written = client.post(f"/api/runs/{run_id}/validation-package")
            self.assertEqual(written.status_code, 200, written.text)
            body = written.json()
            self.assertEqual(Path(body["package_path"]), package_path)
            self.assertEqual(
                [Path(item) for item in body["written"]],
                [package_path, output_dir / "rapidforensic-run-validation-package.audit.json"],
            )
            self.assertEqual(body["package"]["command"], "run.validation-package")
            for item in body["written"]:
                self.assertTrue(Path(item).is_file())

            stamp = package_path.stat().st_mtime_ns
            saved = client.get(body["download_url"])
            self.assertEqual(saved.status_code, 200)
            self.assertIn("run.validation-package", saved.text)
            self.assertEqual(package_path.stat().st_mtime_ns, stamp)

    def test_run_reports_case_db_ready_only_after_import(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            client = api_test_client(RunJobStore())
            response = client.post(
                "/api/sample-case/run",
                json={"output_dir": str(Path(tmp_dir) / "sample"), "mode": "fraud", "overwrite": True, "read_only": True},
            )
            self.assertEqual(response.status_code, 201, response.text)
            run_id = response.json()["run"]["run_id"]

            first = client.get(f"/api/runs/{run_id}").json()
            ensured = client.post(f"/api/runs/{run_id}/case-db/ensure", json={})
            self.assertEqual(ensured.status_code, 200, ensured.text)
            handle = ensured.json()
            after = client.get(f"/api/runs/{run_id}").json()

            if not first["case_db_ready"]:
                self.assertIsNone(first["case_db"])
            self.assertTrue(after["case_db_ready"])
            self.assertEqual(after["case_db"]["case_id"], handle["case_id"])
            self.assertEqual(Path(after["case_db"]["database"]).resolve(), Path(handle["database"]).resolve())
            # A second ensure finds the case already imported (the flag predicted it).
            again = client.post(f"/api/runs/{run_id}/case-db/ensure", json={}).json()
            self.assertFalse(again["imported"])


if __name__ == "__main__":
    unittest.main()
