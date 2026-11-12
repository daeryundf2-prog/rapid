"""R8 T-019: the partial-result contract of list pages.

Every filtered list page reports ``total`` (exact) or ``total: null`` with ``total_lower_bound``,
``budget_stopped`` is always a boolean, and a partial / uncounted page carries a top-level
``notice: {code, message}`` (``SCAN_BUDGET_STOPPED`` / ``TOTAL_NOT_COUNTED``) so a budget stop
never looks like an empty result. Existing pagination fields keep their names and values.
"""

from __future__ import annotations

import importlib.util
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from rapidtriage.api.app import create_app
from rapidtriage.api.app.artifact_filter import (
    filter_across_kinds,
    filter_artifact_page,
    filter_files_by_category,
)
from rapidtriage.api.app.pagination import paginate_payload
from rapidtriage.core.jobs import RunJobStore

REPO = Path(__file__).resolve().parents[1]
TOKEN = "r8-partial-token"
BUDGET_ENV = "RAPIDTRIAGE_SEARCH_SCAN_BUDGET_SECONDS"


def rows(count: int, artifact_type: str = "a") -> list[dict[str, object]]:
    return [{"artifact_type": artifact_type, "path": f"C:/x/{index}.txt"} for index in range(count)]


def inline_payload(items: list[dict[str, object]]) -> dict[str, object]:
    return {"artifacts": items, "record_count": len(items)}


def source(items: list[dict[str, object]]):
    return iter(enumerate(items))


class FilterPageContractTests(unittest.TestCase):
    def page(self, items, **kwargs):
        return filter_artifact_page(
            inline_payload(items), payload_path=Path("unused.json"), path_contains=None,
            rows_source=source(items), **kwargs,
        )

    def test_complete_page_is_counted_without_notice(self) -> None:
        page = self.page(rows(5), offset=0, limit=10, artifact_types={"a"})
        pagination = page["pagination"]
        self.assertEqual(pagination["total"], 5)
        self.assertEqual(pagination["total_lower_bound"], 5)
        self.assertIs(pagination["budget_stopped"], False)
        self.assertIs(pagination["truncated"], False)
        self.assertNotIn("notice", page)

    def test_has_more_page_reports_lower_bound_and_total_not_counted(self) -> None:
        page = self.page(rows(50), offset=10, limit=5, artifact_types={"a"})
        pagination = page["pagination"]
        self.assertIsNone(pagination["total"])
        self.assertTrue(pagination["has_more"])
        self.assertGreaterEqual(pagination["total_lower_bound"], 10 + pagination["returned"] + 1)
        self.assertEqual(pagination["total_lower_bound"], 16)
        self.assertIs(pagination["budget_stopped"], False)
        self.assertEqual(page["notice"]["code"], "TOTAL_NOT_COUNTED")
        self.assertIn("16건 이상", page["notice"]["message"])

    def test_budget_stop_is_not_an_empty_result(self) -> None:
        with mock.patch.dict(os.environ, {BUDGET_ENV: "0.01"}):
            page = self.page(rows(10), offset=0, limit=5, artifact_types={"zzz"}, deadline=time.monotonic() - 1)
        pagination = page["pagination"]
        self.assertEqual(page["artifacts"], [])
        self.assertIs(pagination["budget_stopped"], True)
        self.assertIsNone(pagination["total"])
        self.assertEqual(pagination["total_lower_bound"], 0)
        self.assertEqual(pagination["scanned"], 0)
        self.assertEqual(page["notice"]["code"], "SCAN_BUDGET_STOPPED")
        self.assertIn("0.01초", page["notice"]["message"])

    def test_scan_cap_stop_counts_matches_seen(self) -> None:
        items = rows(3) + rows(10, "b")
        page = self.page(items, offset=0, limit=10, artifact_types={"a"}, scan_cap=5)
        pagination = page["pagination"]
        self.assertTrue(pagination["truncated"])
        self.assertIsNone(pagination["total"])
        self.assertEqual(pagination["total_lower_bound"], 3)
        self.assertEqual(page["notice"]["code"], "TOTAL_NOT_COUNTED")

    def test_cross_kind_contract(self) -> None:
        payload_a, payload_b = inline_payload(rows(4)), inline_payload(rows(4))
        sources = [("a", payload_a, Path("a.json")), ("b", payload_b, Path("b.json"))]

        def rows_for(kind, payload, _path, start):
            return ((index, row) for index, row in enumerate(payload["artifacts"]) if index >= start)

        done = filter_across_kinds(sources, path_contains=None, artifact_types={"a"}, offset=0, limit=20, rows_for=rows_for)
        self.assertEqual(done["cross_kind"]["total"], 8)
        self.assertEqual(done["cross_kind"]["matched"], 8)
        self.assertEqual(done["cross_kind"]["total_lower_bound"], 8)
        self.assertIs(done["cross_kind"]["budget_stopped"], False)
        self.assertNotIn("notice", done)

        more = filter_across_kinds(sources, path_contains=None, artifact_types={"a"}, offset=0, limit=3, rows_for=rows_for)
        self.assertIsNone(more["cross_kind"]["total"])
        self.assertEqual(more["cross_kind"]["total_lower_bound"], 4)
        self.assertEqual(more["notice"]["code"], "TOTAL_NOT_COUNTED")

        stopped = filter_across_kinds(
            sources, path_contains=None, artifact_types={"a"}, offset=0, limit=3, rows_for=rows_for,
            deadline=time.monotonic() - 1,
        )
        self.assertIs(stopped["cross_kind"]["budget_stopped"], True)
        self.assertEqual(stopped["cross_kind"]["order"], [])
        self.assertEqual(stopped["notice"]["code"], "SCAN_BUDGET_STOPPED")

    def test_files_and_unfiltered_pages(self) -> None:
        files = filter_files_by_category({"candidates": [{"categories": ["doc"]}] * 3}, ["doc"], offset=0, limit=10)
        self.assertEqual(files["pagination"]["total_lower_bound"], 3)
        self.assertIs(files["pagination"]["budget_stopped"], False)
        self.assertNotIn("notice", files)
        plain = paginate_payload({"events": list(range(7))}, "events", offset=0, limit=5)
        self.assertEqual(plain["pagination"]["total"], 7)
        self.assertEqual(plain["pagination"]["total_lower_bound"], 7)
        self.assertIs(plain["pagination"]["budget_stopped"], False)
        self.assertIs(plain["pagination"]["truncated"], False)
        self.assertNotIn("notice", plain)


def load_fixture_module():
    spec = importlib.util.spec_from_file_location("make_r8_fixture", REPO / "scripts" / "make-r8-fixture.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class RichFixtureBudgetStopApiTests(unittest.TestCase):
    """The rich fixture's budget-trigger kind with the scan budget at 0.01 s (r8 fixture manifest)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.out = Path(cls._tmp.name).resolve() / "r8-rich"
        cls.manifest = load_fixture_module().generate(cls.out, 8)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def setUp(self) -> None:
        self.client = TestClient(create_app(RunJobStore(), auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})
        self.addCleanup(self.client.close)
        response = self.client.post("/api/runs/import", json={"output_dir": str(self.out)})
        self.assertEqual(response.status_code, 201, response.text[:500])
        self.run_id = response.json()["run_id"]

    def test_budget_stop_reports_notice_not_empty(self) -> None:
        trigger = self.manifest["budget_trigger"]
        with mock.patch.dict(os.environ, trigger["env"]):
            response = self.client.get(
                f"/api/runs/{self.run_id}/artifacts",
                params={"kind": trigger["kind"], "artifact_type": "no-such-type", "limit": 50},
            )
        self.assertEqual(response.status_code, 200, response.text)
        page = response.json()["artifacts"][trigger["kind"]]
        self.assertEqual(page["artifacts"], [])
        self.assertIs(page["pagination"]["budget_stopped"], True)
        self.assertIsNone(page["pagination"]["total"])
        self.assertLess(page["pagination"]["scanned"], trigger["rows"])
        self.assertEqual(page["notice"]["code"], "SCAN_BUDGET_STOPPED")

    def test_cross_kind_type_filter_reports_lower_bound(self) -> None:
        response = self.client.get(
            f"/api/runs/{self.run_id}/artifacts",
            params={"artifact_type": self.manifest["budget_trigger"]["artifact_type"], "limit": 10},
        )
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        cross = body["cross_kind"]
        self.assertTrue(cross["has_more"])
        self.assertIsNone(cross["total"])
        self.assertGreaterEqual(cross["total_lower_bound"], cross["returned"] + 1)
        self.assertIn(body["notice"]["code"], {"TOTAL_NOT_COUNTED", "SCAN_BUDGET_STOPPED"})

    def test_counted_filter_has_exact_total(self) -> None:
        response = self.client.get(
            f"/api/runs/{self.run_id}/artifacts",
            params={"kind": "email", "artifact_type": "email-message", "limit": 100},
        )
        self.assertEqual(response.status_code, 200, response.text)
        page = response.json()["artifacts"]["email"]
        self.assertEqual(page["pagination"]["total"], 18)
        self.assertEqual(page["pagination"]["total_lower_bound"], 18)
        self.assertIs(page["pagination"]["budget_stopped"], False)
        self.assertNotIn("notice", page)


if __name__ == "__main__":
    unittest.main()
