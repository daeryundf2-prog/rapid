"""R7 갈래 A 예외 항목 (Nuix P13): the nine categories from existing fields, the summary and
``irregular=`` on the listings -- every category's count equals its listing's rows (Q-A5)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import create_app
    from rapidtriage.api.app.families import FAMILIES_SERVICE
    from rapidtriage.api.app.row_conditions import MATCH_CACHE, row_is_partial

    HAS_FASTAPI = True
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

from rapidtriage.core.irregular import (
    CATEGORIES,
    CATEGORY_LABELS,
    artifact_categories,
    files_categories,
)
from rapidtriage.core.jobs import RunJobStore
from tests import r7_a_fixtures as fx

TOKEN = "r7-a-irregular-token"
EXPECTED = {
    # category: (files candidates, files inventory, artifacts) record indices
    "bad-extension": ([5], [], []),
    "corrupted": ([], [], [("generic-documents", 4)]),
    "deleted": ([9], [], []),
    "empty": ([6], [], [("mobile-export", 2)]),
    "encrypted": ([4], [], [("generic-documents", 1), ("generic-documents", 2)]),
    "non-searchable-pdf": ([3], [], []),
    "text-stripped": ([7], [], []),
    "unrecognized": ([], [0], []),
    "unsupported": ([8], [], [("generic-documents", 5)]),
}


class CategoryTests(unittest.TestCase):
    def test_every_category_has_a_korean_label(self) -> None:
        self.assertEqual(set(CATEGORY_LABELS), set(CATEGORIES))
        self.assertEqual(len(CATEGORIES), 9)

    def test_rules_are_negation_aware_and_conservative(self) -> None:
        if not HAS_FASTAPI:
            self.skipTest("fastapi is required")
        self.assertEqual(artifact_categories({"artifact_type": "x", "details": {"parse_status": "parsed-no-errors"}}, row_is_partial), [])
        self.assertEqual(artifact_categories({"artifact_type": "x", "details": {"deleted_state": "active"}}, row_is_partial), [])
        self.assertEqual(artifact_categories({"artifact_type": "x", "details": {"deleted_state": "deleted-in-app"}}, row_is_partial), ["deleted"])
        self.assertEqual(
            artifact_categories({"artifact_type": "archive-file-inventory", "details": {"archive_inventory_profile": {"analysis_status": "zip-open-failed"}}}, row_is_partial),
            ["corrupted"],
        )
        self.assertEqual(files_categories({"size": 0, "is_deleted": None, "deletion_state": "unknown"}, None), ["empty"])
        self.assertEqual(files_categories({"size": 3, "file_signature": {"status": "read-error"}}, None), ["corrupted"])
        pdf = {"path": r"C:\a.pdf", "kind": "pdf", "text_status": "encrypted", "text_length": 0, "encrypted": True}
        self.assertEqual(files_categories({"size": 3}, pdf), ["encrypted"])  # an encrypted PDF is not "non-searchable"


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for API tests")
class IrregularApiTests(unittest.TestCase):
    def setUp(self) -> None:
        FAMILIES_SERVICE.clear()
        MATCH_CACHE.clear()
        self.addCleanup(FAMILIES_SERVICE.clear)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.run_dir = Path(self.temp.name) / "run"
        fx.write_run(self.run_dir)
        self.store = RunJobStore()
        self.run_id = self.store.import_completed_run(self.run_dir).run_id
        self.client = TestClient(create_app(self.store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})

    def get(self, url: str, expect: int = 200) -> dict[str, object]:
        response = self.client.get(f"/api/runs/{self.run_id}/{url}")
        self.assertEqual(response.status_code, expect, response.text)
        return response.json()

    def test_q_a5_summary_totals_and_each_category_listing(self) -> None:
        summary = self.get("irregular/summary")
        by_id = {item["id"]: item for item in summary["categories"]}
        self.assertEqual(list(by_id), list(CATEGORIES))
        self.assertEqual(summary["total"], sum(item["count"] for item in summary["categories"]))
        self.assertEqual(summary["total"], 13)
        self.assertEqual(summary["unique_items"], 13)
        for category, (candidates, inventory, artifacts) in EXPECTED.items():
            with self.subTest(category=category):
                item = by_id[category]
                self.assertEqual((item["candidates"], item["inventory"], item["artifacts"]), (len(candidates), len(inventory), len(artifacts)))
                self.assertEqual(item["count"], len(candidates) + len(inventory) + len(artifacts))
                self.assertEqual(item["files"], len(candidates) + len(inventory))
                self.assertTrue(item["label"] and item["help"])
                files = self.get(f"files?limit=500&irregular={category}")
                self.assertEqual([row["record_index"] for row in files["candidates"]], candidates)
                self.assertEqual(files["matched"], len(candidates))
                inv = self.get(f"files?limit=500&scope=inventory&irregular={category}")
                self.assertEqual([row["record_index"] for row in inv["inventory"]], inventory)
                listing = self.get(f"artifacts?limit=500&irregular={category}")
                self.assertEqual([tuple(item) for item in listing["cross_kind"]["order"]], artifacts)
                self.assertEqual(listing["cross_kind"]["matched"], len(artifacts))
        # Q-A5: 암호화 lists the encrypted EGG archive and the encrypted HWP document.
        encrypted = self.get("artifacts?limit=50&irregular=encrypted")
        types = [row["artifact_type"] for page in encrypted["artifacts"].values() for row in page["artifacts"]]
        self.assertEqual(sorted(types), ["archive-file-inventory", "document-metadata-risk"])
        # Several categories OR together; AND with the other conditions.
        both = self.get("artifacts?limit=50&irregular=encrypted,corrupted&kind=generic-documents")
        self.assertEqual([row["record_index"] for row in both["artifacts"]["generic-documents"]["artifacts"]], [1, 2, 4])
        self.assertEqual(both["artifacts"]["generic-documents"]["pagination"]["conditions"]["irregular"], ["corrupted", "encrypted"])
        timeline = self.get("timeline?limit=50&irregular=corrupted")
        self.assertEqual([row["record_index"] for row in timeline["events"]], [4])

    def test_unknown_category_is_korean_422(self) -> None:
        detail = self.get("artifacts?limit=10&irregular=haunted", 422)["detail"]
        self.assertIn("irregular 값", detail)
        self.assertIn("encrypted", detail)


if __name__ == "__main__":
    unittest.main()
