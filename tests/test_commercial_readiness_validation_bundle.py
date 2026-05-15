from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.core.commercial_readiness import (
    build_commercial_readiness_report,
    load_validation_evidence,
)


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

    def test_commercial_readiness_attaches_mac_first_evidence_without_passing_gates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            evidence_path = Path(tmp_dir) / "macos-live-smoke.json"
            evidence_path.write_text(
                json.dumps(
                    {
                        "command": "macos-live-smoke",
                        "profile_version": "macos-live-smoke-v1",
                        "summary": {
                            "local_smoke_score": 85.71,
                            "passed_count": 6,
                            "failed_count": 1,
                            "failed_check_ids": ["forensic-cross-tool-ready"],
                        },
                        "large_case_readiness": {
                            "status": "limited",
                            "summary": {"largest_benchmark_record_count": 2000},
                        },
                        "commercial_grade_blockers": [
                            "trusted-forensic-cross-tool-output-missing",
                            "windows-e01-real-image-validation-not-run",
                        ],
                        "outputs": {"json": str(evidence_path)},
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            report = build_commercial_readiness_report(mac_first_evidence_paths=[evidence_path])

        mac_first = report["mac_first_evidence_summary"]
        self.assertTrue(mac_first["attached"])
        self.assertEqual(mac_first["evidence_count"], 1)
        self.assertIn(66, mac_first["supports_backlog_items"])
        self.assertIn("preparatory only", mac_first["claim_effect"])
        self.assertIn("trusted-forensic-cross-tool-output-missing", mac_first["blocker_counts"])
        self.assertIn("forensic-cross-tool-ready", mac_first["failed_check_counts"])
        self.assertFalse(report["commercial_claim_allowed"])
        self.assertFalse(report["validation_evidence_summary"]["validation_package_attached"])


if __name__ == "__main__":
    unittest.main()
