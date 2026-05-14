from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HAS_FASTAPI = True
try:
    import fastapi  # noqa: F401
except ModuleNotFoundError as exc:
    if exc.name == "fastapi":
        HAS_FASTAPI = False
    else:
        raise

from rapidtriage.cli import build_parser, main
from rapidtriage.core import browser_stress
from rapidtriage.core.browser_stress import build_browser_large_result_stress_plan, run_browser_large_result_stress


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for RapidTriage browser stress contract tests")
class RapidTriageBrowserStressTests(unittest.TestCase):
    def test_browser_large_result_stress_plan_exposes_playwright_contract(self) -> None:
        plan = build_browser_large_result_stress_plan(record_count=100_000)

        self.assertEqual(plan["profile_version"], "browser-large-result-stress-harness-v1")
        self.assertEqual(plan["large_result_evidence_endpoint"], "/api/workbench/large-result-evidence?record_count=100000")
        self.assertEqual(plan["budgets"]["max_dom_rows"], 300)
        self.assertEqual(plan["budgets"]["row_filter_text_limit"], 900)
        self.assertEqual(plan["selectors"]["stress_rows"], "[data-testid='browser-stress-synthetic-window'] tr[data-filter]")
        self.assertIn("console has no browser errors during the stress run", plan["required_assertions"])
        self.assertRegex(str(plan["performance_contract_hash"]), r"^[0-9a-f]{64}$")
        self.assertRegex(str(plan["evidence_manifest_hash"]), r"^[0-9a-f]{64}$")

    def test_browser_large_result_stress_skips_cleanly_without_playwright(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.object(
                browser_stress,
                "load_playwright_sync",
                return_value=browser_stress.PlaywrightImportResult(sync_playwright=None, error="missing playwright"),
            ):
                payload = run_browser_large_result_stress(output_dir=temp, record_count=1000)

            output = Path(temp) / "browser-large-result-stress.json"
            self.assertTrue(output.is_file())
            written = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(payload["status"], "skipped")
        self.assertFalse(payload["playwright_available"])
        self.assertEqual(written["status"], "skipped")
        self.assertIn("Playwright", written["skip_reason"])

    def test_browser_stress_cli_reports_skipped_without_playwright(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["browser-stress", "--output-dir", "out"])
        self.assertEqual(args.command, "browser-stress")

        with tempfile.TemporaryDirectory() as temp:
            stdout = io.StringIO()
            with mock.patch.object(
                browser_stress,
                "load_playwright_sync",
                return_value=browser_stress.PlaywrightImportResult(sync_playwright=None, error="missing playwright"),
            ), contextlib.redirect_stdout(stdout):
                exit_code = main(["browser-stress", "--output-dir", temp, "--record-count", "1000", "--json"])

            payload = json.loads(stdout.getvalue())

        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["status"], "skipped")
        self.assertEqual(payload["record_count"], 1000)


if __name__ == "__main__":
    unittest.main()
