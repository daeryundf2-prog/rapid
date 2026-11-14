"""R8 T-348: the console learns that a run (or the server) is read-only from the API.

* ``GET /api/health`` carries ``read_only`` (``rapidtriage web --read-only``);
* ``GET /api/runs/{id}`` and ``GET /api/runs/{id}/dashboard`` carry ``readonly_reason``: the run's
  own D37 reason (``OUTPUT_INSIDE_EVIDENCE``), else ``SERVER_READ_ONLY`` on a read-only server,
  else ``null`` (the key is always there);
* the histogram reads (``GET /api/cases/{case}/histogram-baselines``, ``GET /api/runs/{id}/histogram
  ?compare=``) answer on a read-only server through ``mode=ro`` instead of 409, and the run folder
  stays byte-identical. Synthetic fixture run only.
"""

from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from rapidtriage.api.app import create_app
from rapidtriage.api.app.readonly_mode import effective_readonly_reason
from tests import quiet_media_checks
from tests.test_r8_import_readonly import TOKEN, Base, snapshot

setUpModule = quiet_media_checks.setUpModule
tearDownModule = quiet_media_checks.tearDownModule


class EffectiveReasonTests(unittest.TestCase):
    def test_run_reason_wins_then_server(self) -> None:
        self.assertEqual(effective_readonly_reason("OUTPUT_INSIDE_EVIDENCE", True), "OUTPUT_INSIDE_EVIDENCE")
        self.assertEqual(effective_readonly_reason(None, True), "SERVER_READ_ONLY")
        self.assertIsNone(effective_readonly_reason(None, False))


class WritableServerTests(Base):
    def test_fields_are_present_and_empty(self) -> None:
        folder = self.copy_output(self.base / "out-copy")
        run_id = self.import_folder(folder).json()["run_id"]
        self.assertEqual(self.client.get("/api/health").json()["read_only"], False)
        self.assertIsNone(self.client.get(f"/api/runs/{run_id}").json()["readonly_reason"])
        dashboard = self.client.get(f"/api/runs/{run_id}/dashboard")
        self.assertEqual(dashboard.status_code, 200, dashboard.text)
        self.assertIn("readonly_reason", dashboard.json())
        self.assertIsNone(dashboard.json()["readonly_reason"])


class ReadOnlyRunTests(Base):
    def setUp(self) -> None:
        super().setUp()
        self.legacy = self.copy_output(self.evidence / "legacy-out")
        response = self.import_folder(self.legacy)
        self.assertEqual(response.status_code, 201, response.text)
        self.run_id = response.json()["run_id"]

    def test_dashboard_names_the_run_reason(self) -> None:
        before = snapshot(self.legacy)
        self.assertEqual(self.client.get("/api/health").json()["read_only"], False)
        self.assertEqual(self.client.get(f"/api/runs/{self.run_id}").json()["readonly_reason"], "OUTPUT_INSIDE_EVIDENCE")
        dashboard = self.client.get(f"/api/runs/{self.run_id}/dashboard")
        self.assertEqual(dashboard.status_code, 200, dashboard.text)
        self.assertEqual(dashboard.json()["readonly_reason"], "OUTPUT_INSIDE_EVIDENCE")
        self.assertEqual(snapshot(self.legacy), before)

    def test_histogram_reads_without_a_case_db_create_nothing(self) -> None:
        before = snapshot(self.legacy)
        histogram = self.client.get(f"/api/runs/{self.run_id}/histogram")
        self.assertEqual(histogram.status_code, 200, histogram.text)
        case_id = histogram.json()["case_id"]
        listed = self.client.get(f"/api/cases/{case_id}/histogram-baselines", params={"run_id": self.run_id})
        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertEqual(listed.json()["exists"], False)
        self.assertEqual(listed.json()["baselines"], [])
        compared = self.client.get(f"/api/runs/{self.run_id}/histogram", params={"compare": 1})
        self.assertEqual(compared.status_code, 404, compared.text)
        self.assertEqual(snapshot(self.legacy), before)


class ReadOnlyServerTests(Base):
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

    def prepare_baseline(self) -> tuple[str, str, int]:
        """A case DB with one histogram baseline, written by the writable server."""
        ensure = self.client.post(f"/api/runs/{self.run_id}/case-db/ensure", json={})
        self.assertEqual(ensure.status_code, 200, ensure.text)
        database, case_id = ensure.json()["database"], ensure.json()["case_id"]
        created = self.client.post(
            f"/api/cases/{case_id}/histogram-baselines", params={"run_id": self.run_id}, json={"name": "기준"}
        )
        self.assertEqual(created.status_code, 201, created.text)
        return database, case_id, int(created.json()["baseline"]["id"])

    def test_server_fields(self) -> None:
        ro = self.read_only_client()
        self.assertEqual(ro.get("/api/health").json(), {"status": "ok", "read_only": True})
        self.assertEqual(ro.get(f"/api/runs/{self.run_id}").json()["readonly_reason"], "SERVER_READ_ONLY")
        self.assertEqual(ro.get(f"/api/runs/{self.run_id}/dashboard").json()["readonly_reason"], "SERVER_READ_ONLY")

    def test_histogram_reads_answer_without_writing(self) -> None:
        database, case_id, baseline_id = self.prepare_baseline()
        ro = self.read_only_client()
        before = snapshot(self.folder)
        for params in ({"run_id": self.run_id}, {"database": database}):
            listed = ro.get(f"/api/cases/{case_id}/histogram-baselines", params=params)
            self.assertEqual(listed.status_code, 200, listed.text)
            self.assertTrue(listed.json()["exists"])
            self.assertEqual([item["id"] for item in listed.json()["baselines"]], [baseline_id])
        compared = ro.get(f"/api/runs/{self.run_id}/histogram", params={"compare": baseline_id})
        self.assertEqual(compared.status_code, 200, compared.text)
        self.assertEqual(compared.json()["baseline"]["id"], baseline_id)
        self.assertEqual(compared.json()["baseline_total"], compared.json()["total"])
        missing = ro.get(f"/api/runs/{self.run_id}/histogram", params={"compare": baseline_id + 50})
        self.assertEqual(missing.status_code, 404, missing.text)
        unknown_case = ro.get("/api/cases/nope/histogram-baselines", params={"database": database})
        self.assertEqual(unknown_case.status_code, 404, unknown_case.text)
        # Saving a baseline stays refused.
        refused = ro.post(f"/api/cases/{case_id}/histogram-baselines", params={"run_id": self.run_id}, json={"name": "x"})
        self.assertEqual(refused.status_code, 409, refused.text)
        self.assertEqual(snapshot(self.folder), before)

    def test_histogram_reads_without_a_case_db(self) -> None:
        ro = self.read_only_client()
        before = snapshot(self.folder)
        histogram = ro.get(f"/api/runs/{self.run_id}/histogram")
        self.assertEqual(histogram.status_code, 200, histogram.text)
        listed = ro.get(f"/api/cases/{histogram.json()['case_id']}/histogram-baselines", params={"run_id": self.run_id})
        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertFalse(listed.json()["exists"])
        missing_db = ro.get(
            f"/api/cases/{histogram.json()['case_id']}/histogram-baselines",
            params={"database": str(self.folder / "rapidtriage-case.db")},
        )
        self.assertEqual(missing_db.status_code, 404, missing_db.text)
        self.assertEqual(snapshot(self.folder), before)


if __name__ == "__main__":
    unittest.main()
