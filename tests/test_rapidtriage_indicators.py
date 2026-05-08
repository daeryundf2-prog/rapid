from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import build_parser, main
from rapidtriage.core.case_db import open_case_database
from rapidtriage.core.indicators import (
    build_indicator_ti_enrichment_package,
    build_ioc_ti_trusted_diff,
    ioc_ti_core_accuracy_gates,
)
from tests.test_rapidtriage_rule_engine import sha256_hex
from tests.test_rapidtriage_run import build_run_fixture


class RapidTriageIndicatorsTests(unittest.TestCase):
    def test_parser_exposes_indicators_command(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices

        self.assertIn("indicators", commands)
        self.assertIn("--rules", commands["indicators"].format_help())
        self.assertIn("--ti-feed", commands["indicators"].format_help())

    def test_run_writes_indicator_summary_and_cli_matches_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)
            payload_installer = add_indicator_fixture_content(root)
            rules_path = write_indicator_rule_file(Path(tmp_dir), payload_installer)

            self.assertEqual(
                main(["run", str(root), "--mode", "hacking", "--rules", str(rules_path), "--output-dir", str(output_dir)]),
                0,
            )

            summary = json.loads((output_dir / "rapidtriage-run-summary.json").read_text(encoding="utf-8"))
            self.assertIn("indicators", summary["outputs"])
            indicators_path = Path(summary["outputs"]["indicators"])
            self.assertTrue(indicators_path.is_file())

            indicators_payload = json.loads(indicators_path.read_text(encoding="utf-8"))
            self.assertEqual(indicators_payload["command"], "indicators")
            self.assertIndicatorPresent(indicators_payload, "domain", "malicious.example")
            self.assertIndicatorPresent(indicators_payload, "url", "https://malicious.example/login")
            self.assertIndicatorPresent(indicators_payload, "domain", "download.example")
            self.assertIndicatorMatchedRule(indicators_payload, "malicious.example", "credential-url-hit")

            output = Path(tmp_dir) / "indicators-manual.json"
            ti_feed = Path(tmp_dir) / "ti-feed.json"
            ti_feed.write_text(
                json.dumps(
                    {
                        "plugin": {"name": "unit-ti-plugin", "version": "2026.04"},
                        "indicators": [
                            {
                                "type": "domain",
                                "value": "malicious.example",
                                "severity": "high",
                                "source": "unit-feed",
                                "note": "Known credential collection host.",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(
                main(["indicators", str(output_dir), "--rules", str(rules_path), "--ti-feed", str(ti_feed), "--output", str(output)]),
                0,
            )
            manual_payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertIndicatorMatchedRule(manual_payload, "download.example", "browser-download-ioc")
            self.assertIndicatorEnriched(manual_payload, "malicious.example", "unit-feed")
            self.assertEqual(manual_payload["summary"]["ti_feed_count"], 1)
            self.assertIn("#63", manual_payload["summary"]["commercial_gap_ids"])
            self.assertIn("#63", manual_payload["ti_enrichment_assessment"]["commercial_gap_ids"])
            self.assertEqual(manual_payload["core_accuracy_gates"][0]["gap_id"], "#63")
            self.assertIn("offline feed provenance", manual_payload["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("local-only/no-external-call warning", manual_payload["core_accuracy_gates"][0]["satisfied_checks"])
            ioc_uplift = manual_payload["commercial_uplift_evidence"]
            self.assertEqual(ioc_uplift["batch_id"], "commercial-uplift-061-065")
            self.assertEqual(ioc_uplift["item_numbers"], [63])
            self.assertIn("offline feed provenance", ioc_uplift["passed_validation_check_ids"])
            self.assertIn("trusted-ioc-ti-enrichment-diff-missing", ioc_uplift["failed_validation_check_ids"])
            self.assertFalse(ioc_uplift["large_data_controls"]["external_ti_api_calls"])
            self.assertEqual(
                ioc_uplift["reportability_decision"]["decision"],
                "do-not-report-ioc-enrichment-as-live-ti-verdict",
            )
            self.assertEqual(ioc_uplift["reportability_decision"]["allowed_use"], "offline-ioc-ti-triage-pivot")
            self.assertFalse(manual_payload["indicator_native_capabilities"]["external_ti_api_calls"])
            self.assertEqual(manual_payload["ti_feed_sources"][0]["name"], "unit-ti-plugin")
            self.assertEqual(manual_payload["ti_feed_sources"][0]["version"], "2026.04")
            self.assertEqual(manual_payload["ti_feed_sources"][0]["size_bytes"], ti_feed.stat().st_size)
            self.assertEqual(len(manual_payload["ti_feed_sources"][0]["sha256"]), 64)
            self.assertIn("#63", manual_payload["ti_feed_sources"][0]["commercial_gap_ids"])
            self.assertGreaterEqual(manual_payload["summary"]["indicator_count"], 3)
            self.assertGreaterEqual(manual_payload["summary"]["enriched_indicator_count"], 1)
            enrichment_package = build_indicator_ti_enrichment_package(
                manual_payload,
                ti_feeds=[ti_feed],
                include_unmatched=False,
                limit=10,
            )
            self.assertEqual(enrichment_package["command"], "indicator-ti-enrichment")
            self.assertEqual(enrichment_package["profile_version"], "ioc-ti-enrichment-review-package-v1")
            self.assertTrue(enrichment_package["local_only"])
            self.assertTrue(enrichment_package["no_external_calls"])
            self.assertEqual(enrichment_package["summary"]["ti_feed_count"], 1)
            self.assertGreaterEqual(enrichment_package["summary"]["matched_indicator_count"], 1)
            self.assertEqual(enrichment_package["core_accuracy_gates"][0]["gap_id"], "#63")
            self.assertIn("offline feed provenance", enrichment_package["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertEqual(
                enrichment_package["reportability_decision"]["allowed_use"],
                "offline-ioc-ti-triage-pivot",
            )
            self.assertTrue(
                any(item.get("ti_review_status") == "feed-match-review-required" for item in enrichment_package["indicators"])
            )
            trusted_diff = build_ioc_ti_trusted_diff(manual_payload["indicators"], manual_payload["indicators"])
            trusted_gates = ioc_ti_core_accuracy_gates(
                indicators=manual_payload["indicators"],
                ti_feed_sources=manual_payload["ti_feed_sources"],
                trusted_diff=trusted_diff,
            )
            self.assertEqual(trusted_diff["status"], "pass")
            self.assertIn("trusted IOC/TI enrichment diff pass", trusted_gates[0]["satisfied_checks"])

            search_output = Path(tmp_dir) / "search.json"
            self.assertEqual(
                main(["search", str(output_dir), "-k", "malicious.example", "--no-ocr", "--output", str(search_output)]),
                0,
            )
            search_payload = json.loads(search_output.read_text(encoding="utf-8"))
            self.assertTrue(
                any(match["source"] == "indicators" for match in search_payload["matches"]),
                "unified search should include indicator pivot hits",
            )

            database = open_case_database(Path(tmp_dir) / "case.db")
            import_payload = database.import_run_output(output_dir, case_id="CASE-IOC", case_name="IOC Case")
            self.assertGreaterEqual(import_payload["summary"]["indicator_count"], 3)
            case_search = database.search_case(
                case_id="CASE-IOC",
                keywords=["malicious.example"],
                sources=["indicators"],
            )
            self.assertGreaterEqual(case_search["summary"]["match_count"], 1)
            self.assertTrue(all(match["source"] == "indicators" for match in case_search["matches"]))

    def assertIndicatorPresent(self, payload: dict[str, object], indicator_type: str, value: str) -> None:
        for indicator in payload["indicators"]:
            if indicator["type"] == indicator_type and indicator["value"] == value:
                return
        self.fail(f"expected indicator {indicator_type}:{value}")

    def assertIndicatorMatchedRule(self, payload: dict[str, object], value: str, rule_id: str) -> None:
        for indicator in payload["indicators"]:
            if indicator["value"] == value and rule_id in indicator.get("matched_rules", []):
                return
        self.fail(f"expected indicator {value!r} to match rule {rule_id!r}")

    def assertIndicatorEnriched(self, payload: dict[str, object], value: str, source: str) -> None:
        for indicator in payload["indicators"]:
            enrichment = indicator.get("ti_enrichment")
            if indicator["value"] == value and isinstance(enrichment, dict) and enrichment.get("source") == source:
                self.assertEqual(enrichment.get("feed_name"), "unit-ti-plugin")
                self.assertEqual(enrichment.get("feed_version"), "2026.04")
                self.assertIn(enrichment.get("matched_on"), {"exact", "url-host-domain"})
                self.assertIn("#63", indicator["commercial_gap_ids"])
                self.assertIn("#63", enrichment["commercial_gap_ids"])
                self.assertEqual(enrichment["validation_status"], "analyst-feed-provenance-review-required")
                return
        self.fail(f"expected indicator {value!r} to be enriched by {source!r}")


def add_indicator_fixture_content(root: Path) -> Path:
    downloads_dir = root / "Users" / "alice" / "Downloads"
    payload_installer = downloads_dir / "payload-installer.exe"
    docs_dir = root / "Users" / "alice" / "Documents"
    credential_note = docs_dir / "credential-note.txt"
    credential_note.write_text(
        "credential password reset evidence https://malicious.example/login",
        encoding="utf-8",
    )
    return payload_installer


def write_indicator_rule_file(directory: Path, payload_installer: Path) -> Path:
    rule_payload = {
        "rules": [
            {
                "id": "credential-url-hit",
                "description": "Match credential-themed document hits and IOC strings.",
                "keyword": ["credential", "password"],
                "domain": ["malicious.example"],
                "url": ["https://malicious.example/login"],
            },
            {
                "id": "browser-download-ioc",
                "description": "Match browser download artifacts with IOC domains and URLs.",
                "artifact": ["browser-history-downloads"],
                "domain": ["download.example"],
                "url": ["https://download.example/tools/installer.exe"],
            },
            {
                "id": "payload-sha256",
                "description": "Match payload hash.",
                "hash": [sha256_hex(payload_installer)],
            },
        ]
    }
    rules_path = directory / "rapidtriage-indicator-rules.json"
    rules_path.write_text(json.dumps(rule_payload, indent=2), encoding="utf-8")
    return rules_path


if __name__ == "__main__":
    unittest.main()
