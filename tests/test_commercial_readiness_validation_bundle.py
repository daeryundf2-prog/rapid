from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.core.commercial_readiness import (
    build_commercial_readiness_report,
    load_validation_evidence,
    trusted_diff_runner_hint,
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
        blocker_package = report["blocker_execution_package"]
        self.assertEqual(blocker_package["profile_version"], "commercial-blocker-execution-package-v1")
        self.assertFalse(blocker_package["commercial_claim_allowed"])
        self.assertTrue(blocker_package["internal_batch"])
        self.assertTrue(blocker_package["external_evidence_batch"])
        self.assertTrue(blocker_package["package_hash"])
        self.assertIn("known-answer-next-batch", " ".join(blocker_package["recommended_commands"]))
        self.assertIn("validation-diff-runners", " ".join(blocker_package["recommended_commands"]))
        evtx_hint = blocker_package["internal_batch"][0]["trusted_diff_runner_hint"]
        self.assertEqual(evtx_hint["artifact_family"], "evtx")
        self.assertIn("EvtxECmd", evtx_hint["trusted_tools"])
        registry_hint = next(
            row["trusted_diff_runner_hint"]
            for row in blocker_package["internal_batch"]
            if row["number"] == 4
        )
        self.assertEqual(registry_hint["artifact_family"], "registry")
        self.assertIn("RECmd", registry_hint["trusted_tools"])

    def test_commercial_readiness_has_second_batch_runner_hints(self) -> None:
        account_hint = trusted_diff_runner_hint(6)
        self.assertEqual(account_hint["artifact_family"], "os-account-execution")
        self.assertEqual(account_hint["validation_diff_runner_group_item"], 82)
        self.assertIn("RECmd", account_hint["trusted_tools"])
        execution_hint = trusted_diff_runner_hint(7)
        self.assertIn("AmcacheParser", execution_hint["trusted_tools"])
        srum_hint = trusted_diff_runner_hint(10)
        self.assertEqual(srum_hint["artifact_family"], "ese")
        self.assertIn("SrumECmd", srum_hint["trusted_tools"])

    def test_commercial_readiness_has_third_batch_runner_hints(self) -> None:
        windows_edb_hint = trusted_diff_runner_hint(11)
        self.assertEqual(windows_edb_hint["artifact_family"], "ese")
        self.assertIn("Windows Search DB Analyzer", windows_edb_hint["trusted_tools"])
        mft_hint = trusted_diff_runner_hint(12)
        self.assertEqual(mft_hint["validation_diff_runner_group_item"], 79)
        self.assertIn("MFTECmd", mft_hint["trusted_tools"])
        usn_hint = trusted_diff_runner_hint(13)
        self.assertIn("UsnJrnl2Csv", usn_hint["trusted_tools"])
        jumplist_hint = trusted_diff_runner_hint(14)
        self.assertEqual(jumplist_hint["artifact_family"], "execution-user-activity")
        self.assertIn("JLECmd", jumplist_hint["trusted_tools"])
        shellbags_hint = trusted_diff_runner_hint(15)
        self.assertIn("ShellBagsExplorer/SBECmd", shellbags_hint["trusted_tools"])

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

    def test_commercial_readiness_attaches_direct_large_case_search_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            evidence_path = Path(tmp_dir) / "large-case-readiness.json"
            evidence_path.write_text(
                json.dumps(
                    {
                        "command": "large-case-readiness",
                        "profile_version": "large-case-readiness-v1",
                        "status": "needs-large-case-evidence",
                        "summary": {
                            "largest_benchmark_record_count": 100000,
                            "case_db_attached": True,
                            "case_db_search_diagnostics_ready": True,
                        },
                        "case_db_profile": {
                            "attached": True,
                            "search_diagnostics": {
                                "profile_version": "case-db-search-diagnostics-v1",
                                "ready": True,
                                "fts_table_count": 2,
                                "profile_hash": "d" * 64,
                            },
                        },
                        "commercial_grade_blockers": [
                            "attach-10m-record-sqlite-fts-benchmark-json",
                        ],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            report = build_commercial_readiness_report(mac_first_evidence_paths=[evidence_path])

        mac_first = report["mac_first_evidence_summary"]
        self.assertTrue(mac_first["attached"])
        self.assertEqual(mac_first["large_case_search_diagnostics_ready_count"], 1)
        self.assertIn(74, mac_first["supports_backlog_items"])
        row = mac_first["rows"][0]
        self.assertEqual(row["command"], "large-case-readiness")
        self.assertEqual(row["large_case_status"], "needs-large-case-evidence")
        self.assertEqual(row["large_case_largest_record_count"], 100000)
        self.assertTrue(row["large_case_search_diagnostics_ready"])
        self.assertEqual(row["large_case_search_diagnostics_hash"], "d" * 64)
        self.assertEqual(row["large_case_search_diagnostics_fts_table_count"], 2)
        self.assertIn("attach-10m-record-sqlite-fts-benchmark-json", mac_first["blocker_counts"])
        self.assertFalse(report["commercial_claim_allowed"])

    def test_commercial_readiness_attaches_source_viewer_handoff_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            source_read_path = Path(tmp_dir) / "source-read.json"
            source_read_path.write_text(
                json.dumps(
                    {
                        "command": "source-read",
                        "profile_version": "source-read-v1",
                        "relative_path": "Users/alice/notes.txt",
                        "source_locator": {"locator_type": "text-preview"},
                        "source_citation_package": {
                            "profile_version": "source-read-citation-package-v1",
                            "package_hash": "c" * 64,
                            "ready_for_review_note": True,
                            "ready_for_court_report": False,
                        },
                        "reportability_decision": {
                            "decision": "source-preview-is-review-aid-not-standalone-proof",
                        },
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            source_search_path = Path(tmp_dir) / "source-search.json"
            source_search_path.write_text(
                json.dumps(
                    {
                        "command": "source-search",
                        "profile_version": "source-search-cli-v1",
                        "relative_path": "Users/alice/notes.txt",
                        "searchable": True,
                        "summary": {"match_count": 3},
                        "source_locator": {"locator_type": "text-preview"},
                        "source_citation_package": {
                            "profile_version": "source-read-citation-package-v1",
                            "package_hash": "s" * 64,
                            "ready_for_review_note": True,
                            "ready_for_court_report": False,
                        },
                        "reportability_decision": {
                            "decision": "source-search-hit-is-review-lead-not-standalone-proof",
                        },
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            report = build_commercial_readiness_report(
                mac_first_evidence_paths=[source_read_path, source_search_path]
            )

        mac_first = report["mac_first_evidence_summary"]
        self.assertTrue(mac_first["attached"])
        self.assertEqual(mac_first["evidence_count"], 2)
        self.assertEqual(mac_first["source_review_handoff_ready_count"], 2)
        self.assertEqual(mac_first["source_court_report_ready_count"], 0)
        self.assertIn(52, mac_first["supports_backlog_items"])
        self.assertIn(61, mac_first["supports_backlog_items"])
        self.assertIn(64, mac_first["supports_backlog_items"])
        self.assertIn(65, mac_first["supports_backlog_items"])
        rows = {row["command"]: row for row in mac_first["rows"]}
        self.assertEqual(rows["source-read"]["source_citation_package_hash"], "c" * 64)
        self.assertTrue(rows["source-read"]["source_ready_for_review_note"])
        self.assertEqual(
            rows["source-read"]["source_reportability_decision"],
            "source-preview-is-review-aid-not-standalone-proof",
        )
        self.assertEqual(rows["source-search"]["source_match_count"], 3)
        self.assertTrue(rows["source-search"]["source_searchable"])
        self.assertEqual(rows["source-search"]["source_citation_package_hash"], "s" * 64)
        self.assertFalse(report["commercial_claim_allowed"])

    def test_commercial_readiness_attaches_cloud_export_parser_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            evidence_path = Path(tmp_dir) / "cloud-export-artifacts.json"
            evidence_path.write_text(
                json.dumps(
                    {
                        "kind": "cloud-export",
                        "provider": {"name": "cloud-export-artifacts"},
                        "summary": {"artifact_count": 4},
                        "artifacts": [
                            {
                                "artifact_type": "cloud-mail",
                                "details": {
                                    "service": "gmail-takeout",
                                    "cloud_family": "google",
                                    "google_takeout_parser_manifest_hash": "g" * 64,
                                    "commercial_grade_blockers": [
                                        "google-takeout-provider-diff-required",
                                    ],
                                },
                            },
                            {
                                "artifact_type": "cloud-audit",
                                "details": {
                                    "service": "microsoft-365",
                                    "cloud_family": "microsoft-365",
                                    "m365_export_parser_manifest_hash": "m" * 64,
                                    "commercial_grade_blockers": [
                                        "m365-ediscovery-provider-diff-required",
                                    ],
                                },
                            },
                            {
                                "artifact_type": "cloud-export-archive",
                                "details": {
                                    "service": "apple-icloud-export",
                                    "cloud_family": "apple-icloud",
                                    "icloud_export_parser_manifest_hash": "i" * 64,
                                    "cloud_archive_manifest_hash": "z" * 64,
                                    "commercial_grade_blockers": [
                                        "icloud-provider-export-diff-required",
                                    ],
                                },
                            },
                            {
                                "artifact_type": "ai-service-export-conversation",
                                "details": {
                                    "service": "chatgpt",
                                    "ai_service_export_parser_manifest_hash": "a" * 64,
                                    "complete_pair_count": 2,
                                    "commercial_grade_blockers": [
                                        "trusted-ai-export-diff-required",
                                    ],
                                },
                            },
                        ],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            report = build_commercial_readiness_report(mac_first_evidence_paths=[evidence_path])

        mac_first = report["mac_first_evidence_summary"]
        self.assertTrue(mac_first["attached"])
        self.assertEqual(mac_first["cloud_export_evidence_count"], 1)
        self.assertEqual(mac_first["cloud_export_artifact_count"], 4)
        self.assertEqual(mac_first["cloud_export_parser_manifest_hash_count"], 4)
        self.assertEqual(mac_first["cloud_export_ai_conversation_count"], 1)
        self.assertIn(21, mac_first["supports_backlog_items"])
        self.assertIn(37, mac_first["supports_backlog_items"])
        self.assertIn(38, mac_first["supports_backlog_items"])
        self.assertIn(39, mac_first["supports_backlog_items"])
        self.assertIn("trusted-ai-export-diff-required", mac_first["blocker_counts"])
        row = mac_first["rows"][0]
        self.assertEqual(row["command"], "cloud-export")
        self.assertEqual(row["cloud_export_artifact_count"], 4)
        self.assertEqual(row["cloud_export_archive_manifest_hash_count"], 1)
        self.assertEqual(row["cloud_export_ai_complete_pair_count"], 2)
        self.assertEqual(row["cloud_export_service_counts"]["gmail-takeout"], 1)
        self.assertFalse(report["commercial_claim_allowed"])

    def test_commercial_readiness_discovers_mac_first_evidence_from_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "qc"
            smoke_dir = root / "macos-live"
            email_dir = root / "email-external"
            cloud_dir = root / "cloud-export"
            smoke_dir.mkdir(parents=True)
            email_dir.mkdir(parents=True)
            cloud_dir.mkdir(parents=True)
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
            (cloud_dir / "cloud-export-artifacts.json").write_text(
                json.dumps(
                    {
                        "kind": "cloud-export",
                        "summary": {"artifact_count": 1},
                        "artifacts": [
                            {
                                "artifact_type": "ai-service-export-conversation",
                                "details": {
                                    "service": "chatgpt",
                                    "ai_service_export_parser_manifest_hash": "a" * 64,
                                    "commercial_grade_blockers": ["trusted-ai-export-diff-required"],
                                },
                            }
                        ],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            report = build_commercial_readiness_report(mac_first_evidence_paths=[root])

        mac_first = report["mac_first_evidence_summary"]
        self.assertTrue(mac_first["attached"])
        self.assertEqual(mac_first["evidence_count"], 3)
        self.assertEqual(
            sorted(row["command"] for row in mac_first["rows"]),
            ["cloud-export", "email-external-parse", "macos-live-smoke"],
        )
        self.assertIn(21, mac_first["supports_backlog_items"])
        self.assertIn(36, mac_first["supports_backlog_items"])
        self.assertIn(66, mac_first["supports_backlog_items"])
        self.assertIn("email_external_tool_available", mac_first["failed_check_counts"])
        self.assertIn("windows-e01-real-image-validation-not-run", mac_first["blocker_counts"])


if __name__ == "__main__":
    unittest.main()
