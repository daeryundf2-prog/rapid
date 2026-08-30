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
TSV_FIXTURE = TIER0_ROOT / "synthetic-trusted-export.tsv"
SCRIPT = REPO_ROOT / "scripts" / "normalize-trusted-export.py"
OBSERVED_SCHEMA = REPO_ROOT / "docs" / "validation" / "known-answer-corpus" / "observed-results-schema-v1.schema.json"


class TrustedExportNormalizerTests(unittest.TestCase):
    def test_synthetic_tsv_stdout_matches_observed_schema(self) -> None:
        completed = _run_normalizer("--json")
        payload = _json_object(completed.stdout)
        errors = validate_schema_document(payload, _schema())

        self.assertEqual(completed.returncode, 0)
        self.assertEqual(errors, [])
        self.assertEqual(payload["source_type"], "synthetic_fixture")
        self.assertEqual(_int_field(_object_field(payload, "summary"), "item_count"), 9)

    def test_synthetic_tsv_writes_output_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            out_path = Path(temp_dir) / "observed.json"
            completed = _run_normalizer("--out", str(out_path))
            payload = _json_object(out_path.read_text(encoding="utf-8"))

        self.assertEqual(completed.returncode, 0)
        self.assertEqual(_int_field(_object_field(payload, "summary"), "recovered_count"), 9)

    def test_unsupported_tool_returns_error_json(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--tool",
                "unknown-tool",
                "--input",
                str(TSV_FIXTURE),
                "--json",
            ],
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            encoding="utf-8", text=True,
        )
        payload = _json_object(completed.stdout)

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(payload["status"], "ERROR")
        self.assertIn("unsupported tool", _str_field(payload, "message"))

    def test_synthetic_tsv_rejects_missing_required_normalized_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            malformed_tsv = Path(temp_dir) / "missing-normalized-path.tsv"
            _ = malformed_tsv.write_text(
                "\t".join(["observed_status", "recovery_mode", "size_bytes", "sha256"])
                + "\n"
                + "\t".join(["recovered", "filesystem", "1", "a" * 64])
                + "\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--tool",
                    "synthetic-tsv",
                    "--input",
                    str(malformed_tsv),
                    "--json",
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                encoding="utf-8", text=True,
            )
            payload = _json_object(completed.stdout)

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(payload["status"], "ERROR")
        self.assertIn("normalized_path", _str_field(payload, "message"))

    def test_synthetic_tsv_rejects_recovered_row_with_invalid_size_bytes(self) -> None:
        completed = _run_normalizer_with_row("recovered", "not-an-int", "a" * 64)
        payload = _json_object(completed.stdout)

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(payload["status"], "ERROR")
        self.assertIn("size_bytes", _str_field(payload, "message"))

    def test_synthetic_tsv_rejects_recovered_row_with_empty_sha256(self) -> None:
        completed = _run_normalizer_with_row("recovered", "1", "")
        payload = _json_object(completed.stdout)

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(payload["status"], "ERROR")
        self.assertIn("sha256", _str_field(payload, "message"))


def _run_normalizer(*extra_args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--tool",
            "synthetic-tsv",
            "--input",
            str(TSV_FIXTURE),
            *extra_args,
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        encoding="utf-8", text=True,
    )


def _run_normalizer_with_row(status: str, size_bytes: str, sha256: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as temp_dir:
        malformed_tsv = Path(temp_dir) / "malformed.tsv"
        _ = malformed_tsv.write_text(
            "\t".join(["normalized_path", "size_bytes", "sha256", "observed_status", "recovery_mode"])
            + "\n"
            + "\t".join(["/recovered.txt", size_bytes, sha256, status, "filesystem"])
            + "\n",
            encoding="utf-8",
        )
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--tool",
                "synthetic-tsv",
                "--input",
                str(malformed_tsv),
                "--json",
            ],
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            encoding="utf-8", text=True,
        )


def _schema() -> JsonObject:
    data, error = load_json_document(OBSERVED_SCHEMA, "observed result schema")
    if error is not None:
        raise AssertionError(error.message)
    if not isinstance(data, dict):
        raise AssertionError("schema must be an object")
    return data


def _json_object(raw_json: str) -> JsonObject:
    try:
        value = cast(JsonValue, json.loads(raw_json))
    except json.JSONDecodeError as exc:
        raise AssertionError(
            f"script stdout was not JSON (chars={len(raw_json)}): {raw_json[:200]!r}"
        ) from exc
    if not isinstance(value, dict):
        raise AssertionError("JSON output must be an object")
    return value


def _object_field(document: JsonObject, field: str) -> JsonObject:
    value = document.get(field)
    if not isinstance(value, dict):
        raise AssertionError(f"{field} must be an object")
    return value


def _int_field(document: JsonObject, field: str) -> int:
    value = document.get(field)
    if not isinstance(value, int) or isinstance(value, bool):
        raise AssertionError(f"{field} must be an integer")
    return value


def _str_field(document: JsonObject, field: str) -> str:
    value = document.get(field)
    if not isinstance(value, str):
        raise AssertionError(f"{field} must be a string")
    return value


if __name__ == "__main__":
    _ = unittest.main()
