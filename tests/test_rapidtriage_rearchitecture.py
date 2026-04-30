from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import build_parser, main
from rapidtriage.core.rearchitecture import build_rearchitecture_status


class RapidTriageRearchitectureStatusTests(unittest.TestCase):
    def test_parser_exposes_rearchitecture_status_command(self) -> None:
        commands = build_parser()._subparsers._group_actions[0].choices

        self.assertIn("rearchitecture-status", commands)
        self.assertIn("--json", commands["rearchitecture-status"].format_help())

    def test_rearchitecture_status_reports_foundation_and_blockers(self) -> None:
        payload = build_rearchitecture_status()

        self.assertEqual(payload["command"], "rearchitecture-status")
        check_ids = {item["id"] for item in payload["checks"]}
        self.assertIn("adr-001", check_ids)
        self.assertIn("rust-workspace", check_ids)
        self.assertIn("python-worker-client", check_ids)
        self.assertIn("jsonl-artifact-store", check_ids)
        self.assertIn("rust-evtx-inventory-contract", check_ids)
        self.assertIn("rust-evtx-inventory-worker", check_ids)
        self.assertIn("windows-registry-native-coverage", check_ids)
        self.assertIn("windows-os-account-coverage", check_ids)
        self.assertIn("browser-ai-coverage", check_ids)
        self.assertIn("viewer-review-coverage", check_ids)
        self.assertIn("tool-cargo", check_ids)
        self.assertGreaterEqual(payload["passed_count"], 8)
        self.assertEqual(len(payload["balanced_next_stage_plan"]), 18)
        self.assertTrue(payload["focus_balance"]["evtx_is_not_the_only_lane"])
        self.assertIn("browser-ai", payload["focus_balance"]["lanes"])
        self.assertTrue(payload["next_steps"])

    def test_rearchitecture_status_cli_outputs_json(self) -> None:
        stdout = io.StringIO()

        with contextlib.redirect_stdout(stdout):
            exit_code = main(["rearchitecture-status", "--json"])

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["command"], "rearchitecture-status")
        self.assertIn("columnar_capabilities", payload)
        self.assertIn("balanced_next_stage_plan", payload)

    def test_rearchitecture_status_cli_outputs_balanced_text_plan(self) -> None:
        stdout = io.StringIO()

        with contextlib.redirect_stdout(stdout):
            exit_code = main(["rearchitecture-status"])

        output = stdout.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("Balanced 1-18 plan:", output)
        self.assertIn("Browser unified timeline", output)
        self.assertIn("Mobile/vendor export importers", output)

    def test_rearchitecture_status_requires_worker_parse_cli_wiring(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            cli_path = root / "rapidtriage" / "cli.py"
            cli_path.parent.mkdir(parents=True)
            cli_path.write_text("# CLI exists, but worker-parse is not wired here.\n", encoding="utf-8")

            payload = build_rearchitecture_status(repo_root=root)

        worker_parse_check = next(item for item in payload["checks"] if item["id"] == "worker-parse-cli")
        self.assertEqual(worker_parse_check["status"], "fail")
        self.assertEqual(worker_parse_check["missing_markers"], ["RustWorkerClient", "parse_to_jsonl"])


if __name__ == "__main__":
    unittest.main()
