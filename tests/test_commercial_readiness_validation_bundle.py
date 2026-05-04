from __future__ import annotations

import json
import unittest
from pathlib import Path

from rapidtriage.core.commercial_readiness import load_validation_evidence


REPO_ROOT = Path(__file__).resolve().parents[1]
AGGREGATE_MANIFEST = REPO_ROOT / "docs" / "validation" / "rapidtriage-core-forensics-001-120-known-answer.json"


class CommercialReadinessValidationBundleTests(unittest.TestCase):
    def test_aggregate_known_answer_bundle_maps_every_item_once_or_more(self) -> None:
        payload = json.loads(AGGREGATE_MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["item_numbers"], list(range(1, 121)))

        datasets = payload["datasets"]
        self.assertEqual(len(datasets), 120)
        covered = sorted(
            {
                int(str(number).lstrip("#"))
                for dataset in datasets
                for number in dataset.get("backlog_items", [])
            }
        )
        self.assertEqual(covered, list(range(1, 121)))

    def test_aggregate_known_answer_bundle_has_present_evidence_paths(self) -> None:
        evidence = load_validation_evidence(AGGREGATE_MANIFEST)

        self.assertEqual(sorted(evidence), list(range(1, 121)))
        self.assertTrue(all(rows for rows in evidence.values()))
        self.assertTrue(all(row["evidence_paths_present"] for rows in evidence.values() for row in rows))


if __name__ == "__main__":
    unittest.main()
