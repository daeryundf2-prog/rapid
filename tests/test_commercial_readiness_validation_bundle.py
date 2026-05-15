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

    def test_commercial_readiness_attaches_email_external_mac_first_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            evidence_path = Path(tmp_dir) / "email-external-parser.json"
            evidence_path.write_text(
                json.dumps(
                    {
                        "command": "email-external-parse",
                        "profile_version": "email-external-parser-wrapper-v2",
                        "status": "complete",
                        "selected_tool": {"tool": "readpst", "available": True},
                        "summary": {
                            "export_file_count": 3,
                            "ready_for_trusted_diff": True,
                        },
                        "evidence_manifest": {
                            "manifest_sha256": "m" * 64,
                            "export_inventory_sha256": "e" * 64,
                        },
                        "commercial_uplift_evidence": {
                            "target_items": [36, 55, 81, 85, 90, 95],
                            "failed_or_blocked_checks": ["trusted_parser_diff_missing"],
                            "evidence_manifest_hash": "m" * 64,
                        },
                        "commercial_grade_blockers": [
                            "trusted-libpff-readpst-outlook-diff-required",
                        ],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            report = build_commercial_readiness_report(mac_first_evidence_paths=[evidence_path])

        mac_first = report["mac_first_evidence_summary"]
        self.assertTrue(mac_first["attached"])
        self.assertEqual(mac_first["evidence_count"], 1)
        self.assertIn(36, mac_first["supports_backlog_items"])
        self.assertIn(95, mac_first["supports_backlog_items"])
        self.assertIn("trusted_parser_diff_missing", mac_first["failed_check_counts"])
        self.assertIn("trusted-libpff-readpst-outlook-diff-required", mac_first["blocker_counts"])
        row = mac_first["rows"][0]
        self.assertEqual(row["command"], "email-external-parse")
        self.assertEqual(row["export_file_count"], 3)
        self.assertTrue(row["ready_for_trusted_diff"])
        self.assertEqual(row["evidence_manifest_hash"], "m" * 64)
        self.assertFalse(report["commercial_claim_allowed"])

    def test_commercial_readiness_discovers_mac_first_evidence_from_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "qc"
            smoke_dir = root / "macos-live"
            email_dir = root / "email-external"
            smoke_dir.mkdir(parents=True)
            email_dir.mkdir(parents=True)
            (smoke_dir / "macos-live-smoke.json").write_text(
                json.dumps(
                    {
                        "command": "macos-live-smoke",
                        "profile_version": "macos-live-smoke-v1",
                        "summary": {
                            "local_smoke_score": 85.71,
                            "failed_check_ids": ["forensic-cross-tool-ready"],
                        },
                        "readiness_attachment": {"supported_backlog_items": [66, 68]},
                        "commercial_grade_blockers": ["windows-e01-real-image-validation-not-run"],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            (email_dir / "email-external-parser.json").write_text(
                json.dumps(
                    {
                        "command": "email-external-parse",
                        "profile_version": "email-external-parser-wrapper-v2",
                        "status": "failed",
                        "summary": {"export_file_count": 0, "ready_for_trusted_diff": False},
                        "commercial_uplift_evidence": {
                            "target_items": [36, 55, 90],
                            "failed_or_blocked_checks": ["email_external_tool_available"],
                        },
                        "commercial_grade_blockers": ["trusted-libpff-readpst-outlook-diff-required"],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            report = build_commercial_readiness_report(mac_first_evidence_paths=[root])

        mac_first = report["mac_first_evidence_summary"]
        self.assertTrue(mac_first["attached"])
        self.assertEqual(mac_first["evidence_count"], 2)
        self.assertEqual(
            sorted(row["command"] for row in mac_first["rows"]),
            ["email-external-parse", "macos-live-smoke"],
        )
        self.assertIn(36, mac_first["supports_backlog_items"])
        self.assertIn(66, mac_first["supports_backlog_items"])
        self.assertIn("email_external_tool_available", mac_first["failed_check_counts"])
        self.assertIn("windows-e01-real-image-validation-not-run", mac_first["blocker_counts"])


if __name__ == "__main__":
    unittest.main()
