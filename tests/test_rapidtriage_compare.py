from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from rapidtriage.cli import build_parser, main
from rapidtriage.core.case_report import build_case_report_markdown
from rapidtriage.core.submission import build_submission_manifest


def run_cli(*args: str) -> tuple[int, str]:
    stream = io.StringIO()
    with redirect_stdout(stream):
        exit_code = main(list(args))
    return exit_code, stream.getvalue()


class RapidTriageCompareTests(unittest.TestCase):
    def test_parser_exposes_compare_command(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices

        self.assertIn("compare", commands)
        compare_help = commands["compare"].format_help()
        self.assertIn("--left-label", compare_help)
        self.assertIn("--right-label", compare_help)
        self.assertIn("--no-text-diff", compare_help)

    def test_compare_command_outputs_hashes_text_diff_and_case_report_pivot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            left = root / "before.txt"
            right = root / "after.txt"
            output = root / "rapidtriage-compare.json"
            case_json = root / "rapidtriage-case.json"

            left.write_text("alpha\nsecret=old\nomega\n", encoding="utf-8")
            right.write_text("alpha\nsecret=new\nomega\n", encoding="utf-8")

            exit_code, stdout = run_cli(
                "compare",
                str(left),
                str(right),
                "--left-label",
                "baseline",
                "--right-label",
                "suspect",
                "--output",
                str(output),
            )

            self.assertEqual(exit_code, 0, stdout)
            self.assertTrue(output.is_file())
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["command"], "compare")
            self.assertEqual(payload["summary"]["result_count"], 1)
            self.assertEqual(payload["summary"]["status_counts"], {"different": 1})
            result = payload["results"][0]
            self.assertEqual(result["status"], "different")
            self.assertEqual(result["left"]["hashes"].keys(), {"md5", "sha1", "sha256"})
            self.assertTrue(result["diff"]["included"])
            self.assertIn("-secret=old", "\n".join(result["diff"]["preview"]))
            self.assertIn("+secret=new", "\n".join(result["diff"]["preview"]))

            exit_code, stdout = run_cli(
                "case",
                str(case_json),
                "--case-id",
                "case-compare-001",
                "--source",
                str(output),
                "--pointer",
                "/results/0",
                "--tag",
                "compare",
                "--note",
                "Check changed secret value.",
                "--review-status",
                "needs-review",
            )

            self.assertEqual(exit_code, 0, stdout)
            case_payload = json.loads(case_json.read_text(encoding="utf-8"))
            self.assertEqual(case_payload["summary"]["source_command_counts"]["compare"], 1)
            bookmark = case_payload["bookmarks"][0]
            self.assertEqual(bookmark["reference"]["command"], "compare")
            self.assertEqual(bookmark["snapshot"]["path"], str(left.resolve()))
            self.assertEqual(bookmark["snapshot"]["artifact_key"], "different")

            submission = build_submission_manifest(case_payload, allowed_roots=[root], include_all=True)
            report = build_case_report_markdown(
                run_summary={
                    "mode": "compare",
                    "root": str(root),
                    "scan_scope_root": str(root),
                    "output_dir": str(root),
                    "steps": [],
                },
                case_payload=case_payload,
                submission_manifest=submission,
            )
            self.assertIn("A/B compare review pivots", report)
            self.assertIn("Check changed secret value.", report)


if __name__ == "__main__":
    unittest.main()
