from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import cast

from rapidtriage.validation.known_answer_schema import load_json_document, validate_schema_document
from rapidtriage.validation.known_answer_types import JsonObject, JsonValue


REPO_ROOT = Path(__file__).resolve().parents[1]
TIER0_ROOT = REPO_ROOT / "tests" / "fixtures" / "known_answer" / "tier0-basic"
MANIFEST = TIER0_ROOT / "manifest.json"
RAPID_RESULTS = TIER0_ROOT / "rapid-results.json"
TRUSTED_RESULTS = TIER0_ROOT / "trusted-results.json"
SCRIPT = REPO_ROOT / "scripts" / "trusted-diff.py"
RESULT_SCHEMA = REPO_ROOT / "docs" / "validation" / "known-answer-corpus" / "trusted-diff-result-schema-v1.schema.json"


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


def _run_trusted_diff(*extra_args: str) -> subprocess.CompletedProcess[str]:
    args = [
        sys.executable,
        str(SCRIPT),
        "--manifest",
        str(MANIFEST),
        "--rapid-results",
        str(RAPID_RESULTS),
        "--trusted-results",
        str(TRUSTED_RESULTS),
        *extra_args,
    ]
    return subprocess.run(args, cwd=REPO_ROOT, check=False, capture_output=True, text=True)


def _schema() -> JsonObject:
    data, error = load_json_document(RESULT_SCHEMA, "trusted diff result schema")
    if error is not None:
        raise AssertionError(error.message)
    if not isinstance(data, dict):
        raise AssertionError("schema must be an object")
    return data


def _json_object(raw_json: str) -> JsonObject:
    value = cast(JsonValue, json.loads(raw_json))
    if not isinstance(value, dict):
        raise AssertionError("JSON output must be an object")
    return value


def _object_field(document: JsonObject, field: str) -> JsonObject:
    value = document.get(field)
    if not isinstance(value, dict):
        raise AssertionError(f"{field} must be an object")
    return value


def _list_field(document: JsonObject, field: str) -> list[JsonValue]:
    value = document.get(field)
    if not isinstance(value, list):
        raise AssertionError(f"{field} must be a list")
    return value


def _int_field(document: JsonObject, field: str) -> int:
    value = document.get(field)
    if not isinstance(value, int) or isinstance(value, bool):
        raise AssertionError(f"{field} must be an integer")
    return value


def _mutated_trusted_results(temp_dir: Path) -> Path:
    return _mutated_results(temp_dir, TRUSTED_RESULTS, "trusted-results")


def _mutated_results(temp_dir: Path, source: Path, stem: str) -> Path:
    payload = _json_object(source.read_text(encoding="utf-8"))
    items = _list_field(payload, "items")
    first_item = items[0] if items else None
    if not isinstance(first_item, dict):
        raise AssertionError("first item must be an object")
    first_item["sha256"] = "f" * 64
    path = temp_dir / f"{stem}.json"
    _ = path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


def _empty_observed_results(temp_dir: Path, stem: str) -> Path:
    payload = _json_object(TRUSTED_RESULTS.read_text(encoding="utf-8"))
    payload["source_run_id"] = stem
    payload["items"] = []
    payload["summary"] = {
        "item_count": 0,
        "recovered_count": 0,
        "error_count": 0,
        "inconclusive_count": 0,
    }
    path = temp_dir / f"{stem}.json"
    _ = path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


if __name__ == "__main__":
    _ = unittest.main()
