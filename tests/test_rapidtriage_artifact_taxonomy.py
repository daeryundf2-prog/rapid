from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import build_parser, main
from rapidtriage.core.artifact_taxonomy import TAXONOMY_TARGETS, build_taxonomy_audit


REPO_ROOT = Path(__file__).resolve().parents[1]


class RapidTriageArtifactTaxonomyTests(unittest.TestCase):
    def test_taxonomy_has_broad_forensic_targets(self) -> None:
        target_ids = {target.id for target in TAXONOMY_TARGETS}

        self.assertGreaterEqual(len(TAXONOMY_TARGETS), 40)
        self.assertIn("evtx-native-binxml", target_ids)
        self.assertIn("registry-transaction-replay", target_ids)
        self.assertIn("browser-cache-session-extension", target_ids)
        self.assertIn("messenger-matrix", target_ids)
        self.assertIn("taxonomy-audit-guardrail", target_ids)

    def test_taxonomy_audit_reports_missing_and_partial_bindings(self) -> None:
        payload = build_taxonomy_audit(REPO_ROOT)
        summary = payload["summary"]
        targets = {target["id"]: target for target in payload["targets"]}

        self.assertEqual(payload["command"], "taxonomy-audit")
        self.assertGreaterEqual(summary["collector_count"], 20)
        self.assertGreaterEqual(summary["artifact_type_literal_count"], 100)
        self.assertGreater(summary["target_count"], 40)
        self.assertGreaterEqual(summary["covered_count"], 40)
        self.assertEqual(summary["missing_count"], 0)
        self.assertEqual(summary["partial_count"], 0)
        self.assertTrue(summary["strict_pass"])
        self.assertEqual(targets["evtx-native-binxml"]["status"], "covered")
        self.assertEqual(targets["webshell-server-logs"]["status"], "covered")
        self.assertEqual(targets["memory-volatility"]["status"], "covered")
        self.assertEqual(targets["memory-volatility"]["missing_bindings"]["artifact_types"], [])
        self.assertIn("missing_bindings", targets["browser-cache-session-extension"])
        self.assertEqual(targets["registry-transaction-replay"]["present_bindings"]["viewer_markers"], ["registry"])
        self.assertEqual(targets["registry-deleted-recovery"]["present_bindings"]["doc_markers"], ["deleted key"])

    def test_taxonomy_audit_command_writes_json_and_strict_fails_when_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output = Path(tmp_dir) / "taxonomy.json"

            exit_code = main(["taxonomy-audit", "--repo-root", str(REPO_ROOT), "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["command"], "taxonomy-audit")
            self.assertIsInstance(payload["summary"]["strict_pass"], bool)

            strict_code = main(
                ["taxonomy-audit", "--repo-root", str(REPO_ROOT), "--output", str(output), "--strict"]
            )
            self.assertEqual(strict_code, 0 if payload["summary"]["strict_pass"] else 1)

    def test_parser_exposes_taxonomy_audit_command(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices

        self.assertIn("taxonomy-audit", commands)
        help_text = commands["taxonomy-audit"].format_help()
        self.assertIn("--strict", help_text)
        self.assertIn("rapidtriage taxonomy-audit --json", help_text)


if __name__ == "__main__":
    unittest.main()
