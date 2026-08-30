from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rapidtriage.validation.known_answer import validate_manifest
from rapidtriage.validation.known_answer_schema import load_json_document, validate_schema_document
from rapidtriage.validation.known_answer_types import JsonObject, JsonValue, ManifestValidationError


REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "known_answer"
VALID_MANIFEST = FIXTURE_DIR / "valid-t1-minimal-manifest.json"
MISSING_REQUIRED_MANIFEST = FIXTURE_DIR / "invalid-missing-required-manifest.json"
INVALID_SHA256_MANIFEST = FIXTURE_DIR / "invalid-sha256-manifest.json"
TIER0_ROOT = FIXTURE_DIR / "tier0-basic"
TIER0_FILES_ROOT = TIER0_ROOT / "files"
TIER0_MANIFEST = TIER0_ROOT / "manifest.json"
RESULT_SCHEMA = REPO_ROOT / "docs" / "validation" / "known-answer-corpus" / "validation-result-schema-v1.schema.json"
SCRIPT_PATH = REPO_ROOT / "scripts" / "known-answer-qc.py"


class KnownAnswerManifestValidationTests(unittest.TestCase):
    def test_valid_manifest_passes_and_reports_summary_fields(self) -> None:
        result = validate_manifest(VALID_MANIFEST)

        self.assertTrue(result.ok)
        self.assertEqual(result.manifest_path, str(VALID_MANIFEST))
        self.assertTrue(result.schema_path.endswith("truth-manifest-schema-v1.schema.json"))
        self.assertEqual(result.corpus_id, "known-answer-t1-synthetic")
        self.assertEqual(result.case_id, "case-t1-minimal")
        self.assertEqual(result.image_id, "image-t1-folder-baseline-001")
        self.assertEqual(result.expected_item_count, 1)
        self.assertEqual(result.warning_count, 0)
        self.assertEqual(result.errors, [])

    def test_missing_required_manifest_returns_required_error(self) -> None:
        result = validate_manifest(MISSING_REQUIRED_MANIFEST)

        self.assertFalse(result.ok)
        self.assertEqual(result.corpus_id, "known-answer-t1-synthetic")
        self.assertTrue(
            any(error.validator == "required" and "trusted_tool_runs" in error.message for error in result.errors),
        )

    def test_invalid_sha256_reports_item_path(self) -> None:
        result = validate_manifest(INVALID_SHA256_MANIFEST)

        self.assertFalse(result.ok)
        self.assertTrue(
            any(
                error.validator == "pattern" and error.path == "$/expected_items/0/sha256"
                for error in result.errors
            ),
        )

    def test_builtin_schema_fallback_reports_manifest_errors_without_jsonschema(self) -> None:
        dependency_error = ManifestValidationError(path="$", message="jsonschema unavailable", validator="dependency")
        with patch(
            "rapidtriage.validation.known_answer_schema._load_jsonschema_runtime",
            return_value=(None, dependency_error),
        ):
            result = validate_manifest(INVALID_SHA256_MANIFEST)

        self.assertFalse(result.ok)
        self.assertTrue(
            any(
                error.validator == "pattern" and error.path == "$/expected_items/0/sha256"
                for error in result.errors
            ),
        )

    def test_builtin_schema_fallback_rejects_array_form_type_mismatch(self) -> None:
        dependency_error = ManifestValidationError(path="$", message="jsonschema unavailable", validator="dependency")
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest = _manifest_with_accepted_variant(Path(temp_dir), [123])
            with patch(
                "rapidtriage.validation.known_answer_schema._load_jsonschema_runtime",
                return_value=(None, dependency_error),
            ):
                result = validate_manifest(manifest)

        self.assertFalse(result.ok)
        self.assertTrue(
            any(
                error.validator == "type" and error.path == "$/expected_items/0/accepted_variants/0"
                for error in result.errors
            ),
        )

    def test_script_json_output_uses_exit_code_contract(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--manifest",
                str(INVALID_SHA256_MANIFEST),
                "--json",
            ],
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            encoding="utf-8", text=True,
        )

        self.assertEqual(completed.returncode, 1)
        json_tool = subprocess.run(
            [sys.executable, "-m", "json.tool"],
            input=completed.stdout,
            check=False,
            capture_output=True,
            encoding="utf-8", text=True,
        )

        self.assertEqual(json_tool.returncode, 0)
        output = _json_object(completed.stdout)
        self.assertEqual(output["ok"], False)
        self.assertEqual(output["manifest_path"], str(INVALID_SHA256_MANIFEST))
        self.assertIn('"errors": [', completed.stdout)

    def test_tier0_file_check_passes_when_hashes_match(self) -> None:
        result = validate_manifest(TIER0_MANIFEST, check_files=True, fixture_root=TIER0_FILES_ROOT)

        self.assertTrue(result.ok)
        self.assertTrue(result.file_check_enabled)
        self.assertEqual(result.file_checked_count, 9)
        self.assertEqual(result.file_error_count, 0)
        self.assertEqual(result.file_skipped_count, 0)
        self.assertTrue(any(check.relative_path == "zero-byte/empty.txt" for check in result.file_checks))

    def test_tier0_file_check_reports_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest = _mutated_manifest(
                Path(temp_dir),
                '"fixture_relative_path": "hello.txt"',
                '"fixture_relative_path": "same-content-a.txt"',
            )

            result = validate_manifest(manifest, check_files=True, fixture_root=TIER0_FILES_ROOT)

        self.assertFalse(result.ok)
        self.assertEqual(result.file_error_count, 1)
        self.assertTrue(any("sha256 mismatch" in check.message for check in result.file_checks))

    def test_tier0_file_check_reports_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest = _mutated_manifest(
                Path(temp_dir),
                '"fixture_relative_path": "hello.txt"',
                '"fixture_relative_path": "no-such-file.txt"',
            )

            result = validate_manifest(manifest, check_files=True, fixture_root=TIER0_FILES_ROOT)

        self.assertFalse(result.ok)
        self.assertEqual(result.file_error_count, 1)
        self.assertTrue(any("file does not exist" in check.message for check in result.file_checks))

    def test_tier0_file_check_blocks_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest = _mutated_manifest(
                Path(temp_dir),
                '"fixture_relative_path": "hello.txt"',
                '"fixture_relative_path": "../outside.txt"',
            )

            result = validate_manifest(manifest, check_files=True, fixture_root=TIER0_FILES_ROOT)

        self.assertFalse(result.ok)
        self.assertEqual(result.file_error_count, 1)
        self.assertTrue(any("safe relative path" in check.message for check in result.file_checks))

    def test_tier0_file_check_blocks_absolute_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            absolute_path_json = json.dumps(str(TIER0_FILES_ROOT / "hello.txt"))
            manifest = _mutated_manifest(
                Path(temp_dir),
                '"fixture_relative_path": "hello.txt"',
                f'"fixture_relative_path": {absolute_path_json}',
            )

            result = validate_manifest(manifest, check_files=True, fixture_root=TIER0_FILES_ROOT)

        self.assertFalse(result.ok)
        self.assertEqual(result.file_error_count, 1)
        self.assertTrue(any("safe relative path" in check.message for check in result.file_checks))

    def test_script_file_check_options_emit_json_summary(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--manifest",
                str(TIER0_MANIFEST),
                "--check-files",
                "--fixture-root",
                str(TIER0_FILES_ROOT),
                "--json",
            ],
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            encoding="utf-8", text=True,
        )

        self.assertEqual(completed.returncode, 0, msg=f"stdout={completed.stdout!r} stderr={completed.stderr!r}")
        self.assertIn('"file_check_enabled": true', completed.stdout)
        self.assertIn('"file_error_count": 0', completed.stdout)

    def test_script_json_output_matches_result_schema_for_pass_fail_and_error(self) -> None:
        result_schema = _load_result_schema()
        cases = [
            (
                [
                    "--manifest",
                    str(TIER0_MANIFEST),
                    "--check-files",
                    "--fixture-root",
                    str(TIER0_FILES_ROOT),
                    "--json",
                ],
                0,
                "PASS",
            ),
            (["--manifest", str(INVALID_SHA256_MANIFEST), "--json"], 1, "FAIL"),
            (["--manifest", str(FIXTURE_DIR / "missing-manifest.json"), "--json"], 1, "ERROR"),
        ]

        for args, expected_returncode, expected_status in cases:
            with self.subTest(status=expected_status):
                completed = subprocess.run(
                    [sys.executable, str(SCRIPT_PATH), *args],
                    cwd=REPO_ROOT,
                    check=False,
                    capture_output=True,
                    encoding="utf-8", text=True,
                )
                output = _json_object(completed.stdout)
                errors = validate_schema_document(output, result_schema)

                self.assertEqual(completed.returncode, expected_returncode, msg=f"stdout={completed.stdout!r} stderr={completed.stderr!r}")
                self.assertEqual(completed.stderr, "")
                self.assertEqual(output["schema_version"], "rapidforensic-known-answer-validation-result-v1")
                self.assertEqual(output["status"], expected_status)
                self.assertEqual(errors, [])
                self.assertIn("release_evidence_status", output)


def _mutated_manifest(temp_dir: Path, old: str, new: str) -> Path:
    source = TIER0_MANIFEST.read_text(encoding="utf-8")
    if old not in source:
        raise AssertionError(f"manifest mutation target was not found: {old}")
    manifest = temp_dir / "manifest.json"
    _ = manifest.write_text(source.replace(old, new, 1), encoding="utf-8")
    return manifest


def _manifest_with_accepted_variant(temp_dir: Path, variant: JsonValue) -> Path:
    source_data, source_error = load_json_document(TIER0_MANIFEST, "tier0 manifest")
    if source_error is not None or not isinstance(source_data, dict):
        raise AssertionError("tier0 manifest must be an object")
    expected_items = source_data.get("expected_items")
    if not isinstance(expected_items, list) or not expected_items or not isinstance(expected_items[0], dict):
        raise AssertionError("tier0 manifest expected_items[0] must be an object")
    expected_items[0]["accepted_variants"] = [variant]
    manifest = temp_dir / "manifest.json"
    _ = manifest.write_text(json.dumps(source_data), encoding="utf-8")
    return manifest


def _load_result_schema() -> JsonObject:
    schema_data, schema_error = load_json_document(RESULT_SCHEMA, "result schema")
    if schema_error is not None:
        raise AssertionError(schema_error.message)
    if not isinstance(schema_data, dict):
        raise AssertionError("result schema must be a JSON object")
    return schema_data


def _json_object(raw_json: str) -> JsonObject:
    with tempfile.TemporaryDirectory() as temp_dir:
        output_path = Path(temp_dir) / "script-output.json"
        _ = output_path.write_text(raw_json, encoding="utf-8")
        value, parse_error = load_json_document(output_path, "script output")
    if parse_error is not None:
        raise AssertionError(parse_error.message)
    if not isinstance(value, dict):
        raise AssertionError("script JSON output must be an object")
    return value


if __name__ == "__main__":
    _ = unittest.main()
