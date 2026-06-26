from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.validation.known_answer_schema import validate_schema_document
from rapidtriage.validation.trusted_diff_result import TrustedDiffResult
from tests.trusted_diff_helpers import (
    RAPID_RESULTS,
    TRUSTED_RESULTS,
    duplicated_manifest_expected_path as _duplicated_manifest_expected_path,
    duplicated_observed_path as _duplicated_observed_path,
    empty_observed_results as _empty_observed_results,
    expected_inconclusive_manifest as _expected_inconclusive_manifest,
    has_diff_message as _has_diff_message,
    has_error_message as _has_error_message,
    int_field as _int_field,
    json_object as _json_object,
    load_trusted_diff_cli as _load_trusted_diff_cli,
    list_field as _list_field,
    make_first_item_id_wrong as _make_first_item_id_wrong,
    make_first_item_inconclusive as _make_first_item_inconclusive,
    manifest_without_required_truth_sha as _manifest_without_required_truth_sha,
    mutated_observed_results as _mutated_observed_results,
    mutated_results as _mutated_results,
    mutated_trusted_results as _mutated_trusted_results,
    object_field as _object_field,
    run_trusted_diff as _run_trusted_diff,
    schema as _schema,
)


class TrustedDiffTests(unittest.TestCase):
    def test_cli_json_passes_schema_when_tier0_matches(self) -> None:
        completed = _run_trusted_diff("--json")
        payload = _json_object(completed.stdout)
        errors = validate_schema_document(payload, _schema())

        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, "")
        self.assertEqual(errors, [])
        self.assertEqual(payload["status"], "PASS")
        self.assertEqual(_int_field(_object_field(payload, "counts"), "match"), 9)
        self.assertEqual(payload["release_evidence_status"], "engineering_check_only")

    def test_cli_json_passes_schema_when_expected_inconclusive_matches(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest_path = _expected_inconclusive_manifest(Path(temp_dir))
            rapid_path = _mutated_observed_results(Path(temp_dir), RAPID_RESULTS, "rapid-expected-inconclusive", _make_first_item_inconclusive)
            trusted_path = _mutated_observed_results(
                Path(temp_dir),
                TRUSTED_RESULTS,
                "trusted-expected-inconclusive",
                _make_first_item_inconclusive,
            )
            completed = _run_trusted_diff(
                "--manifest",
                str(manifest_path),
                "--rapid-results",
                str(rapid_path),
                "--trusted-results",
                str(trusted_path),
                "--json",
            )
            payload = _json_object(completed.stdout)
            errors = validate_schema_document(payload, _schema())

        self.assertEqual(completed.returncode, 0)
        self.assertEqual(errors, [])
        self.assertEqual(payload["status"], "PASS")
        counts = _object_field(payload, "counts")
        self.assertEqual(_int_field(counts, "expected_inconclusive"), 1)
        diffs = _list_field(payload, "diffs")
        self.assertTrue(any(isinstance(diff, dict) and diff.get("category") == "EXPECTED_INCONCLUSIVE" for diff in diffs))

    def test_cli_returns_error_when_generated_pass_result_fails_result_schema(self) -> None:
        cli = _load_trusted_diff_cli()
        invalid_pass = TrustedDiffResult(status="PASS", ok=True, document={"status": "PASS"})
        stdout = io.StringIO()

        with mock.patch.object(cli, "compare", return_value=invalid_pass), contextlib.redirect_stdout(stdout):
            return_code = cli.main(
                [
                    "--manifest",
                    str(_schema()),
                    "--rapid-results",
                    str(RAPID_RESULTS),
                    "--trusted-results",
                    str(TRUSTED_RESULTS),
                    "--json",
                ],
            )
        payload = _json_object(stdout.getvalue())

        self.assertEqual(return_code, 2)
        self.assertEqual(payload["status"], "ERROR")
        self.assertTrue(_has_error_message(payload, "trusted diff result schema"))

    def test_cli_writes_json_and_summary_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            out_path = Path(temp_dir) / "diff.json"
            summary_path = Path(temp_dir) / "summary.md"
            completed = _run_trusted_diff("--out", str(out_path), "--summary", str(summary_path))

            payload = _json_object(out_path.read_text(encoding="utf-8"))
            summary = summary_path.read_text(encoding="utf-8")

        self.assertEqual(completed.returncode, 0)
        self.assertEqual(payload["status"], "PASS")
        self.assertIn("MATCH", summary)

    def test_cli_fails_on_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            trusted_path = _mutated_trusted_results(Path(temp_dir))
            completed = _run_trusted_diff("--trusted-results", str(trusted_path), "--json")
            payload = _json_object(completed.stdout)

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(payload["status"], "FAIL")
        diffs = _list_field(payload, "diffs")
        self.assertTrue(any(isinstance(diff, dict) and diff.get("category") == "HASH_MISMATCH" for diff in diffs))

    def test_cli_fails_when_manifest_expected_items_are_missing_from_both_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            empty_rapid = _empty_observed_results(Path(temp_dir), "rapid-empty")
            empty_trusted = _empty_observed_results(Path(temp_dir), "trusted-empty")
            completed = _run_trusted_diff(
                "--rapid-results",
                str(empty_rapid),
                "--trusted-results",
                str(empty_trusted),
                "--json",
            )
            payload = _json_object(completed.stdout)

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(payload["status"], "FAIL")
        counts = _object_field(payload, "counts")
        self.assertEqual(_int_field(counts, "total"), 9)
        self.assertEqual(_int_field(counts, "critical"), 9)

    def test_cli_fails_when_matching_outputs_disagree_with_manifest_truth(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            rapid_path = _mutated_results(Path(temp_dir), RAPID_RESULTS, "rapid-wrong")
            trusted_path = _mutated_results(Path(temp_dir), TRUSTED_RESULTS, "trusted-wrong")
            completed = _run_trusted_diff(
                "--rapid-results",
                str(rapid_path),
                "--trusted-results",
                str(trusted_path),
                "--json",
            )
            payload = _json_object(completed.stdout)

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(payload["status"], "FAIL")
        diffs = _list_field(payload, "diffs")
        self.assertTrue(any(isinstance(diff, dict) and diff.get("category") == "HASH_MISMATCH" for diff in diffs))

    def test_cli_errors_when_rapid_results_duplicate_normalized_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            rapid_path = _duplicated_observed_path(Path(temp_dir), RAPID_RESULTS, "rapid-duplicate")
            completed = _run_trusted_diff("--rapid-results", str(rapid_path), "--json")
            payload = _json_object(completed.stdout)

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(payload["status"], "ERROR")
        self.assertTrue(_has_error_message(payload, "duplicate normalized_path"))

    def test_cli_errors_when_trusted_results_duplicate_normalized_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            trusted_path = _duplicated_observed_path(Path(temp_dir), TRUSTED_RESULTS, "trusted-duplicate")
            completed = _run_trusted_diff("--trusted-results", str(trusted_path), "--json")
            payload = _json_object(completed.stdout)

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(payload["status"], "ERROR")
        self.assertTrue(_has_error_message(payload, "duplicate normalized_path"))

    def test_cli_errors_when_manifest_has_duplicate_expected_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest_path = _duplicated_manifest_expected_path(Path(temp_dir))
            completed = _run_trusted_diff("--manifest", str(manifest_path), "--json")
            payload = _json_object(completed.stdout)

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(payload["status"], "ERROR")
        self.assertTrue(_has_error_message(payload, "duplicate expected path"))

    def test_cli_fails_when_must_recover_item_is_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            rapid_path = _mutated_observed_results(Path(temp_dir), RAPID_RESULTS, "rapid-inconclusive", _make_first_item_inconclusive)
            trusted_path = _mutated_observed_results(
                Path(temp_dir),
                TRUSTED_RESULTS,
                "trusted-inconclusive",
                _make_first_item_inconclusive,
            )
            completed = _run_trusted_diff(
                "--rapid-results",
                str(rapid_path),
                "--trusted-results",
                str(trusted_path),
                "--json",
            )
            payload = _json_object(completed.stdout)

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(payload["status"], "FAIL")
        self.assertTrue(_has_diff_message(payload, "observed status differs from byte-exact manifest truth"))

    def test_cli_errors_when_manifest_fails_schema_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest_path = _manifest_without_required_truth_sha(Path(temp_dir))
            completed = _run_trusted_diff("--manifest", str(manifest_path), "--json")
            payload = _json_object(completed.stdout)

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(payload["status"], "ERROR")
        self.assertTrue(_has_error_message(payload, "sha256"))

    def test_cli_fails_when_outputs_have_wrong_item_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            rapid_path = _mutated_observed_results(Path(temp_dir), RAPID_RESULTS, "rapid-wrong-id", _make_first_item_id_wrong)
            trusted_path = _mutated_observed_results(
                Path(temp_dir),
                TRUSTED_RESULTS,
                "trusted-wrong-id",
                _make_first_item_id_wrong,
            )
            completed = _run_trusted_diff(
                "--rapid-results",
                str(rapid_path),
                "--trusted-results",
                str(trusted_path),
                "--json",
            )
            payload = _json_object(completed.stdout)

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(payload["status"], "FAIL")
        self.assertTrue(_has_diff_message(payload, "observed item_id differs from manifest truth"))

if __name__ == "__main__":
    _ = unittest.main()
