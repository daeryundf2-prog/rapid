from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import build_parser, main
from rapidtriage.core.case_db import open_case_database
from tests.test_rapidtriage_rule_engine import sha256_hex
from tests.test_rapidtriage_run import build_run_fixture


class RapidTriageIndicatorsTests(unittest.TestCase):
    def test_parser_exposes_indicators_command(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices

        self.assertIn("indicators", commands)
        self.assertIn("--rules", commands["indicators"].format_help())

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
            self.assertEqual(
                main(["indicators", str(output_dir), "--rules", str(rules_path), "--output", str(output)]),
                0,
            )
            manual_payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertIndicatorMatchedRule(manual_payload, "download.example", "browser-download-ioc")
            self.assertGreaterEqual(manual_payload["summary"]["indicator_count"], 3)

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
