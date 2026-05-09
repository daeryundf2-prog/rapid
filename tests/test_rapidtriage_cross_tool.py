from __future__ import annotations

import contextlib
import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import main


class RapidTriageCrossToolTests(unittest.TestCase):
    def test_usn_state_replay_template_command_writes_csv_and_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            output = root / "usn-state-replay-known-answer.csv"

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "usn-state-replay-template",
                        "--output",
                        str(output),
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["profile_version"], "usn-state-replay-known-answer-template-v1")
            self.assertEqual(payload["trusted_tool_name"], "known-answer-state-replay")
            self.assertEqual(payload["row_count"], 4)
            self.assertTrue(output.is_file())
            manifest = Path(payload["manifest_path"])
            self.assertTrue(manifest.is_file())
            self.assertEqual(len(payload["csv_sha256"]), 64)
            self.assertEqual(len(payload["manifest_sha256"]), 64)
            with output.open("r", encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 4)
            self.assertEqual(rows[0]["Transition"], "create")
            self.assertEqual(rows[-1]["Transition"], "delete")
            self.assertIn("cross-tool-validate", payload["cross_tool_command_template"])

    def test_usn_state_replay_template_command_can_write_headers_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output = Path(tmp_dir) / "empty-state-replay.csv"

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["usn-state-replay-template", "--output", str(output), "--empty", "--json"])

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["row_count"], 0)
            with output.open("r", encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))
                self.assertEqual(handle.name, str(output))
            self.assertEqual(rows, [])
            self.assertIn("USN", payload["csv_columns"])

    def test_cross_tool_validate_compares_nested_usn_state_replay_transitions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid-usn.json"
            reference = root / "known-state-replay.csv"
            output = root / "usn-state-replay-cross-tool.json"
            rapid.write_text(
                json.dumps(
                    {
                        "artifacts": [
                            {
                                "artifact_type": "usn-journal-inventory",
                                "details": {
                                    "usn_replay_inventory_profile": {
                                        "bounded_state_replay_preview": {
                                            "transitions": [
                                                {
                                                    "usn": 9004,
                                                    "file_reference_number": 41,
                                                    "record_cursor": 408,
                                                    "transition": "delete",
                                                    "timestamp": "2026-01-02T03:05:00Z",
                                                    "previous_path": r"C:\Users\new.txt",
                                                    "new_path": "",
                                                    "file_name": "new.txt",
                                                    "state_effect": "remove-current-path",
                                                }
                                            ]
                                        }
                                    }
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            reference.write_text(
                "USN,FRN,RecordCursor,Transition,Timestamp,PreviousPath,NewPath,FileName,StateEffect\n"
                r"9004,41,408,delete,2026-01-02T03:05:00Z,C:\Users\new.txt,,new.txt,remove-current-path"
                "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"known-answer-state-replay={reference}",
                        "--backlog-item",
                        "13",
                        "--min-overlap",
                        "1.0",
                        "--output",
                        str(output),
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["status"], "pass")
            comparison = payload["comparisons"][0]
            state_diff = comparison["usn_state_replay_field_comparison"]
            self.assertEqual(state_diff["mode"], "usn-state-replay-field-diff")
            self.assertEqual(state_diff["common_record_count"], 1)
            self.assertEqual(state_diff["mismatch_count"], 0)
            self.assertIn("transition", state_diff["compared_canonical_fields"])
            self.assertIn("previous_path", state_diff["compared_canonical_fields"])
            self.assertIn("state_effect", state_diff["compared_canonical_fields"])
            profile = payload["cross_tool_validation_assessment"]["functional_priority_profile"]
            self.assertIn(
                "usn-state-replay-transition-field-diff-supported",
                profile["passed_validation_check_ids"],
            )
            manifest = payload["cross_tool_validation_assessment"]["trusted_tool_diff_manifest"]
            self.assertEqual(
                manifest["comparison_summaries"][0]["field_diffs"]["usn_state_replay_field_comparison"]["mode"],
                "usn-state-replay-field-diff",
            )
            self.assertTrue(output.is_file())

    def test_cross_tool_validate_fails_on_usn_state_replay_transition_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid-usn.json"
            reference = root / "known-state-replay.csv"
            rapid.write_text(
                json.dumps(
                    {
                        "artifacts": [
                            {
                                "details": {
                                    "usn_replay_inventory_profile": {
                                        "bounded_state_replay_preview": {
                                            "transitions": [
                                                {
                                                    "usn": 9004,
                                                    "file_reference_number": 41,
                                                    "record_cursor": 408,
                                                    "transition": "delete",
                                                    "previous_path": r"C:\Users\new.txt",
                                                }
                                            ]
                                        }
                                    }
                                }
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            reference.write_text(
                "USN,FRN,RecordCursor,Transition,PreviousPath\n"
                r"9004,41,408,rename-new-name,C:\Users\new.txt"
                "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"known-answer-state-replay={reference}",
                        "--backlog-item",
                        "13",
                        "--min-overlap",
                        "1.0",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            comparison = payload["comparisons"][0]
            self.assertEqual(comparison["status"], "failed")
            state_diff = comparison["usn_state_replay_field_comparison"]
            self.assertEqual(state_diff["mismatch_count"], 1)
            self.assertEqual(state_diff["mismatch_samples"][0]["field"], "transition")
            self.assertFalse(payload["cross_tool_validation_assessment"]["ready_for_validated_gate"])

    def test_run_attach_validation_diff_registers_usn_state_replay_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            run_dir = root / "run"
            run_dir.mkdir()
            summary_path = run_dir / "rapidtriage-run-summary.json"
            summary_path.write_text(
                json.dumps(
                    {
                        "profile_version": "rapidtriage-run-summary-v1",
                        "output_dir": str(run_dir),
                        "outputs": {
                            "summary": str(summary_path),
                        },
                    }
                ),
                encoding="utf-8",
            )
            diff_output = root / "usn-state-cross-tool.json"
            diff_output.write_text(
                json.dumps(
                    {
                        "command": "cross-tool-validate",
                        "status": "pass",
                        "comparisons": [
                            {
                                "reference_name": "known-answer-state-replay",
                                "status": "pass",
                                "usn_state_replay_field_comparison": {
                                    "mode": "usn-state-replay-field-diff",
                                    "common_record_count": 2,
                                    "mismatch_count": 0,
                                    "missing_common_field_count": 0,
                                },
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "run-attach-validation-diff",
                        str(run_dir),
                        "--diff-output",
                        f"usn_state={diff_output}",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["command"], "run-attach-validation-diff")
            self.assertEqual(payload["attached_count"], 1)
            self.assertEqual(len(payload["summary_sha256"]), 64)
            attached_path = Path(payload["attached_outputs"][0]["attached_path"])
            self.assertTrue(attached_path.is_file())
            self.assertTrue(Path(payload["manifest_path"]).is_file())

            updated_summary = json.loads(summary_path.read_text(encoding="utf-8"))
            outputs = updated_summary["outputs"]
            self.assertIn("validation_diff_usn_state", outputs)
            self.assertIn("validation_diff_manifest", outputs)
            self.assertEqual(updated_summary["validation_diff_attachments"]["attachment_count"], 1)

    def test_run_attach_validation_diff_rejects_non_json_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            run_dir = root / "run"
            run_dir.mkdir()
            (run_dir / "rapidtriage-run-summary.json").write_text(
                json.dumps({"output_dir": str(run_dir), "outputs": {}}),
                encoding="utf-8",
            )
            not_json = root / "not-json.txt"
            not_json.write_text("not json", encoding="utf-8")

            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit):
                    main(
                        [
                            "run-attach-validation-diff",
                            str(run_dir),
                            "--diff-output",
                            f"bad={not_json}",
                        ]
                    )

            self.assertIn("must be readable JSON", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
