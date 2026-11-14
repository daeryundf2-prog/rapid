"""D37 read-only folder registrations are owned and released (T-032 follow-up).

* a folder held by several owners stays read-only until the last one releases it;
* removing a run from a store (``DELETE /api/runs/{id}``) releases that store's hold;
* ``RunJobStore.close()`` releases every hold of the store, and the app's shutdown calls it;
* while a folder is held, writes and deletes inside it are refused as before.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from rapidtriage.api.app import create_app
from rapidtriage.core.jobs import RunJobStore
from rapidtriage.core.readonly_runs import (
    ReadOnlyRunWriteError,
    install_write_guard,
    may_persist,
    readonly_holders,
    register_readonly_folder,
    unregister_readonly_folder,
)

TOKEN = "r8-registry-token"


def setUpModule() -> None:
    install_write_guard()


class RegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.folder = Path(self._tmp.name) / "run"
        self.folder.mkdir()
        (self.folder / "kept.txt").write_text("kept", encoding="utf-8")
        self.addCleanup(unregister_readonly_folder, self.folder)  # runs before the folder clean-up

    def assert_read_only(self) -> None:
        self.assertFalse(may_persist(self.folder / "x.json"))
        with self.assertRaises(ReadOnlyRunWriteError):
            (self.folder / "new.txt").write_text("x", encoding="utf-8")
        with self.assertRaises(ReadOnlyRunWriteError):
            (self.folder / "kept.txt").unlink()

    def test_folder_stays_read_only_until_last_owner_releases_it(self) -> None:
        register_readonly_folder(self.folder, "OUTPUT_INSIDE_EVIDENCE", owner="a")
        register_readonly_folder(self.folder, "OUTPUT_INSIDE_EVIDENCE", owner="b")
        register_readonly_folder(self.folder, "OUTPUT_INSIDE_EVIDENCE", owner="b")  # same owner: one hold
        self.assertEqual(readonly_holders(self.folder), 2)

        self.assertFalse(unregister_readonly_folder(self.folder, owner="a"))
        self.assert_read_only()
        self.assertFalse(unregister_readonly_folder(self.folder, owner="a"))  # releasing twice changes nothing
        self.assertEqual(readonly_holders(self.folder), 1)

        self.assertTrue(unregister_readonly_folder(self.folder, owner="b"))
        self.assertEqual(readonly_holders(self.folder), 0)
        self.assertTrue(may_persist(self.folder / "x.json"))
        (self.folder / "kept.txt").unlink()

    def test_unregister_without_owner_drops_every_hold(self) -> None:
        register_readonly_folder(self.folder, "OUTPUT_INSIDE_EVIDENCE", owner="a")
        register_readonly_folder(self.folder, "OUTPUT_INSIDE_EVIDENCE")
        self.assertTrue(unregister_readonly_folder(self.folder))
        self.assertTrue(may_persist(self.folder))


class StoreLifecycleTests(unittest.TestCase):
    """Imported runs whose folder is their own evidence root (read-only, D37)."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.folder = self.make_run("run")
        self.addCleanup(unregister_readonly_folder, self.folder)  # safety net if a test fails midway

    def make_run(self, name: str) -> Path:
        folder = Path(self._tmp.name) / name
        folder.mkdir()
        summary_path = folder / "rapidtriage-run-summary.json"
        summary = {
            "profile_version": "rapidtriage-run-summary-v1",
            "mode": "fraud",
            "root": str(folder),
            "output_dir": str(folder),
            "outputs": {"summary": str(summary_path)},
        }
        summary_path.write_text(json.dumps(summary), encoding="utf-8")
        return folder

    def assert_released(self, folder: Path) -> None:
        self.assertEqual(readonly_holders(folder), 0)
        shutil.rmtree(folder)  # deleting is allowed again

    def test_removing_the_run_releases_its_folder(self) -> None:
        store = RunJobStore()
        job = store.import_completed_run(self.folder)
        self.assertEqual(job.readonly_reason, "OUTPUT_INSIDE_EVIDENCE")
        with self.assertRaises(ReadOnlyRunWriteError):
            shutil.rmtree(self.folder)
        store.remove(job.run_id)
        self.assert_released(self.folder)

    def test_folder_held_by_two_stores_stays_read_only_until_both_release_it(self) -> None:
        first, second = RunJobStore(), RunJobStore()
        job = first.import_completed_run(self.folder)
        second.import_completed_run(self.folder)
        self.assertEqual(readonly_holders(self.folder), 2)
        first.remove(job.run_id)
        with self.assertRaises(ReadOnlyRunWriteError):
            (self.folder / "rapidtriage-run-summary.json").unlink()
        second.close()
        self.assert_released(self.folder)

    def test_reimport_holds_the_folder_once(self) -> None:
        store = RunJobStore()
        store.import_completed_run(self.folder)
        store.import_completed_run(self.folder)
        self.assertEqual(readonly_holders(self.folder), 1)
        store.close()
        self.assert_released(self.folder)

    def test_close_releases_every_hold_and_keeps_the_runs_listed(self) -> None:
        other = self.make_run("other")
        self.addCleanup(unregister_readonly_folder, other)
        with RunJobStore() as store:
            store.import_completed_run(self.folder)
            store.import_completed_run(other)
            self.assertFalse(may_persist(other))
        self.assertEqual(len(store.list()), 2)
        store.close()  # idempotent
        self.assert_released(self.folder)
        self.assert_released(other)

    def test_app_shutdown_closes_the_store(self) -> None:
        store = RunJobStore()
        with TestClient(create_app(store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN}) as client:
            response = client.post("/api/runs/import", json={"output_dir": str(self.folder)})
            self.assertEqual(response.status_code, 201, response.text[:200])
            self.assertEqual(response.json()["readonly_reason"], "OUTPUT_INSIDE_EVIDENCE")
            self.assertEqual(client.put(f"/api/runs/{response.json()['run_id']}/case-notes", json={"notes": "x"}).status_code, 409)
        self.assert_released(self.folder)

    def test_delete_run_endpoint_releases_its_folder(self) -> None:
        store = RunJobStore()
        self.addCleanup(store.close)
        client = TestClient(create_app(store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})
        self.addCleanup(client.close)
        run_id = client.post("/api/runs/import", json={"output_dir": str(self.folder)}).json()["run_id"]
        self.assertEqual(readonly_holders(self.folder), 1)
        self.assertIn(client.delete(f"/api/runs/{run_id}").status_code, {200, 204})
        self.assert_released(self.folder)


if __name__ == "__main__":
    unittest.main()
