from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import build_parser, main
from rapidtriage.core.sample_case import create_sample_case


class RapidTriageSampleCaseTests(unittest.TestCase):
    def test_parser_exposes_sample_subcommand(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices

        self.assertIn("sample", commands)
        self.assertIn("rapidtriage sample --output-dir", commands["sample"].format_help())
        self.assertIn("rapidtriage sample --run", parser.format_help())

    def test_create_sample_case_writes_expected_evidence_layout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            sample_root = Path(tmp_dir) / "sample"

            payload = create_sample_case(sample_root)

            evidence_root = Path(payload["evidence_root"])
            self.assertTrue((evidence_root / "Users" / "alice" / "Documents" / "invoice-wire-transfer.txt").is_file())
            self.assertTrue(
                (
                    evidence_root
                    / "Users"
                    / "alice"
                    / "AppData"
                    / "Local"
                    / "Google"
                    / "Chrome"
                    / "User Data"
                    / "Default"
                    / "History"
                ).is_file()
            )
            expected = json.loads(Path(payload["expected"]).read_text(encoding="utf-8"))
            self.assertEqual(expected["recommended_mode"], "fraud")
            self.assertIn("password", expected["keywords"])

    def test_cli_sample_run_creates_full_smoke_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            sample_root = Path(tmp_dir) / "sample"
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(["sample", "--output-dir", str(sample_root), "--run", "--read-only"])

            self.assertEqual(exit_code, 0)
            self.assertIn("Saved sample run summary JSON", stdout.getvalue())

            run_output = sample_root / "run-output"
            summary = json.loads((run_output / "rapidtriage-run-summary.json").read_text(encoding="utf-8"))
            docs = json.loads((run_output / "rapidtriage-docs.json").read_text(encoding="utf-8"))
            artifacts = json.loads(
                (run_output / "artifacts" / "rapidtriage-artifacts-browser.json").read_text(encoding="utf-8")
            )

            self.assertEqual(summary["mode"], "fraud")
            self.assertGreaterEqual(summary["summary"]["document_match_count"], 1)
            self.assertGreaterEqual(docs["summary"]["match_count"], 1)
            self.assertGreaterEqual(artifacts["summary"]["artifact_count"], 1)
            self.assertTrue((run_output / "rapidtriage-run-report.md").is_file())

    def test_cli_sample_json_output_is_machine_readable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            sample_root = Path(tmp_dir) / "sample"
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(["sample", "--output-dir", str(sample_root), "--json"])

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["command"], "sample")
            self.assertTrue(Path(payload["evidence_root"]).is_dir())
