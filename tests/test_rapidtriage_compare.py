from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from rapidtriage.cli import build_parser, main
from rapidtriage.core.case_report import build_case_report_markdown
from rapidtriage.core.compare import build_compare_trusted_diff, compare_core_accuracy_gates
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
        self.assertIn("--selection-rationale", compare_help)
        self.assertIn("--review-note", compare_help)

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
                "--selection-rationale",
                "Compare baseline and suspect credential note.",
                "--review-note",
                "Secret value changed and needs source verification.",
            )

            self.assertEqual(exit_code, 0, stdout)
            self.assertTrue(output.is_file())
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["command"], "compare")
            self.assertEqual(payload["summary"]["result_count"], 1)
            self.assertEqual(payload["summary"]["status_counts"], {"different": 1})
            self.assertIn("#52", payload["summary"]["commercial_gap_ids"])
            self.assertFalse(payload["compare_native_capabilities"]["binary_structure_aware_diff"])
            self.assertIn("#52", payload["compare_report_grade_assessment"]["commercial_gap_ids"])
            compare_gate = payload["core_accuracy_gates"][0]
            self.assertEqual(compare_gate["gap_id"], "#52")
            self.assertIn("hash comparison", compare_gate["satisfied_checks"])
            self.assertIn("bounded text diff", compare_gate["satisfied_checks"])
            self.assertIn("compare review profile", compare_gate["satisfied_checks"])
            self.assertIn("comparison review queue", compare_gate["satisfied_checks"])
            self.assertIn("selection rationale captured", compare_gate["satisfied_checks"])
            self.assertIn("bounded compare notes captured", compare_gate["satisfied_checks"])
            self.assertIn("compare citation manifest hash", compare_gate["satisfied_checks"])
            self.assertIn("compare source viewer locators", compare_gate["satisfied_checks"])
            self.assertIn("compare report-grade validation plan", compare_gate["satisfied_checks"])
            self.assertIn("compare report-grade ready slots", compare_gate["satisfied_checks"])
            self.assertIn("specialized diff limitation warning", compare_gate["satisfied_checks"])
            uplift = payload["commercial_uplift_evidence"]
            self.assertEqual(uplift["batch_id"], "commercial-uplift-051-055")
            self.assertEqual(uplift["item_numbers"], [52])
            self.assertIn("bounded text diff", uplift["passed_validation_check_ids"])
            self.assertIn("compare report-grade validation plan", uplift["passed_validation_check_ids"])
            self.assertIn("binary-structure-aware-diff", uplift["failed_validation_check_ids"])
            self.assertEqual(
                uplift["reportability_decision"]["allowed_use"],
                "bounded-file-compare-triage-pivot",
            )
            self.assertIn("check:sqlite-table-aware-diff", uplift["reportability_decision"]["blockers"])
            self.assertTrue(uplift["large_data_controls"]["bounded_text_diff"])
            self.assertTrue(uplift["large_data_controls"]["compare_citation_manifest_present"])
            self.assertEqual(
                uplift["large_data_controls"]["compare_citation_manifest_hash"],
                payload["compare_citation_manifest"]["manifest_hash"],
            )
            self.assertTrue(uplift["large_data_controls"]["compare_report_grade_validation_plan_present"])
            self.assertEqual(
                uplift["large_data_controls"]["compare_report_grade_validation_plan_hash"],
                payload["compare_report_grade_validation_plan"]["validation_plan_sha256"],
            )
            self.assertEqual(uplift["large_data_controls"]["compare_report_grade_ready_slot_count"], 6)
            self.assertEqual(uplift["large_data_controls"]["compare_report_grade_blocking_slot_count"], 6)
            self.assertEqual(uplift["large_data_controls"]["source_viewer_locator_count"], 2)
            self.assertEqual(uplift["large_data_controls"]["diff_locator_count"], 1)
            self.assertTrue(uplift["large_data_controls"]["compare_review_profile_present"])
            self.assertEqual(uplift["large_data_controls"]["review_queue_count"], 1)
            self.assertTrue(uplift["large_data_controls"]["selection_rationale_present"])
            self.assertEqual(uplift["large_data_controls"]["review_note_count"], 1)
            self.assertFalse(uplift["large_data_controls"]["persistent_compare_notes"])
            review_profile = payload["compare_review_profile"]
            self.assertEqual(review_profile["profile_version"], "multi-evidence-compare-review-v1")
            self.assertEqual(review_profile["review_queue_count"], 1)
            self.assertEqual(review_profile["selection_rationale"], "Compare baseline and suspect credential note.")
            self.assertEqual(review_profile["review_note_count"], 1)
            self.assertFalse(review_profile["persistent_compare_notes"])
            self.assertTrue(review_profile["commercial_release_blocked"])
            self.assertEqual(review_profile["review_queue"][0]["report_decision"], "pending")
            validation_plan = payload["compare_report_grade_validation_plan"]
            self.assertEqual(
                validation_plan["profile_version"],
                "multi-evidence-compare-report-grade-validation-plan-v1",
            )
            self.assertEqual(validation_plan["item_number"], 52)
            self.assertEqual(validation_plan["gap_id"], "#52")
            self.assertEqual(payload["summary"]["compare_report_grade_validation_plan_hash"], validation_plan["validation_plan_sha256"])
            self.assertEqual(validation_plan["ready_slot_count"], 6)
            self.assertEqual(validation_plan["blocking_slot_count"], 6)
            self.assertIn("web-three-pane-compare-ui-required", validation_plan["blockers"])
            self.assertIn("compare-trusted-expected-diff-required", validation_plan["blockers"])
            citation_manifest = payload["compare_citation_manifest"]
            self.assertEqual(citation_manifest["manifest_version"], "multi-evidence-compare-citation-manifest-v1")
            self.assertEqual(citation_manifest["comparison_count"], 1)
            self.assertEqual(citation_manifest["source_viewer_locator_count"], 2)
            self.assertEqual(citation_manifest["diff_locator_count"], 1)
            self.assertEqual(citation_manifest["entries"][0]["baseline_locator"]["viewer"], "compare-source")
            self.assertEqual(citation_manifest["entries"][0]["comparison_locator"]["viewer"], "compare-source")
            self.assertEqual(citation_manifest["entries"][0]["diff_locator"]["viewer"], "compare-diff")
            self.assertTrue(citation_manifest["entries"][0]["entry_hash"])
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

    def test_compare_command_supports_three_way_baseline_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            baseline = root / "baseline.txt"
            host_a = root / "host-a.txt"
            host_b = root / "host-b.txt"
            output = root / "rapidtriage-compare.json"

            baseline.write_text("alpha\nshared=true\n", encoding="utf-8")
            host_a.write_text("alpha\nshared=true\n", encoding="utf-8")
            host_b.write_text("alpha\nshared=false\n", encoding="utf-8")

            exit_code, stdout = run_cli(
                "compare",
                str(baseline),
                str(host_a),
                str(host_b),
                "--label",
                "baseline",
                "--label",
                "host-a",
                "--label",
                "host-b",
                "--output",
                str(output),
                "--selection-rationale",
                "Compare same setting across hosts.",
                "--review-note",
                "Host A matches baseline.",
                "--review-note",
                "Host B differs.",
            )

            self.assertEqual(exit_code, 0, stdout)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["command"], "compare")
            self.assertEqual(payload["options"]["mode"], "multi")
            self.assertEqual(payload["summary"]["input_count"], 3)
            self.assertEqual(payload["summary"]["result_count"], 2)
            self.assertIn("#52", payload["summary"]["commercial_gap_ids"])
            self.assertTrue(payload["compare_native_capabilities"]["a_b_c_baseline_compare"])
            self.assertEqual(payload["compare_report_grade_assessment"]["mode"], "multi")
            self.assertEqual(payload["core_accuracy_gates"][0]["gap_id"], "#52")
            self.assertIn("compare review profile", payload["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("selection rationale captured", payload["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("compare report-grade validation plan", payload["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertTrue(payload["commercial_uplift_evidence"]["large_data_controls"]["a_b_c_baseline_compare"])
            self.assertTrue(payload["commercial_uplift_evidence"]["large_data_controls"]["compare_citation_manifest_present"])
            self.assertTrue(
                payload["commercial_uplift_evidence"]["large_data_controls"][
                    "compare_report_grade_validation_plan_present"
                ]
            )
            self.assertEqual(payload["commercial_uplift_evidence"]["large_data_controls"]["review_queue_count"], 2)
            self.assertEqual(payload["compare_citation_manifest"]["comparison_count"], 2)
            self.assertEqual(payload["compare_citation_manifest"]["source_viewer_locator_count"], 4)
            self.assertEqual(payload["summary"]["compare_citation_manifest_hash"], payload["compare_citation_manifest"]["manifest_hash"])
            self.assertEqual(
                payload["summary"]["compare_report_grade_validation_plan_hash"],
                payload["compare_report_grade_validation_plan"]["validation_plan_sha256"],
            )
            self.assertEqual(payload["compare_report_grade_validation_plan"]["ready_slot_count"], 6)
            self.assertEqual(payload["compare_report_grade_validation_plan"]["blocking_slot_count"], 6)
            self.assertEqual(payload["summary"]["review_queue_count"], 2)
            self.assertTrue(payload["summary"]["selection_rationale_present"])
            self.assertEqual(payload["compare_review_profile"]["review_note_count"], 2)
            self.assertEqual(payload["compare_review_profile"]["review_queue"][1]["review_note"], "Host B differs.")
            self.assertEqual(payload["results"][0]["right"]["label"], "host-a")
            self.assertEqual(payload["results"][1]["right"]["label"], "host-b")
            self.assertEqual(payload["summary"]["status_counts"]["same"], 1)
            self.assertEqual(payload["summary"]["status_counts"]["different"], 1)

    def test_compare_trusted_diff_controls_core_accuracy_gate(self) -> None:
        result = {
            "comparison_id": "compare-0001",
            "status": "different",
            "fields": [{"name": "sha256", "status": "different"}],
            "diff": {"included": True, "preview": ["--- baseline", "+++ suspect", "-a", "+b"]},
            "left": {"label": "baseline", "path": "a.txt", "hashes": {"sha256": "left-hash"}},
            "right": {"label": "suspect", "path": "b.txt", "hashes": {"sha256": "right-hash"}},
        }
        diff = build_compare_trusted_diff([result], [dict(result)], trusted_tool="expected-diff-manifest")

        self.assertEqual(diff["status"], "pass")
        gate = compare_core_accuracy_gates(results=[result], mode="pair", trusted_diff=diff)[0]
        self.assertIn("trusted A/B/C comparison expected diff pass", gate["satisfied_checks"])

        mismatch = build_compare_trusted_diff(
            [result],
            [{**result, "status": "same"}],
            trusted_tool="expected-diff-manifest",
        )
        self.assertEqual(mismatch["status"], "fail")
        self.assertEqual(mismatch["blocker_id"], "compare-trusted-expected-diff-required")


if __name__ == "__main__":
    unittest.main()
