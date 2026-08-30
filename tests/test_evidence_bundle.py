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
SCRIPT = REPO_ROOT / "scripts" / "build-evidence-bundle.py"
BUNDLE_SCHEMA = REPO_ROOT / "docs" / "validation" / "release-evidence-bundle-manifest-schema-v1.schema.json"


class EvidenceBundleTests(unittest.TestCase):
    def test_tier0_bundle_json_matches_schema(self) -> None:
        completed = _run_bundle("--json")
        payload = _json_object(completed.stdout)
        errors = validate_schema_document(payload, _schema())

        self.assertEqual(completed.returncode, 0)
        self.assertEqual(errors, [])
        self.assertEqual(payload["release_evidence_status"], "engineering_check_only")
        summary = _object_field(payload, "summary")
        self.assertGreaterEqual(_int_field(summary, "artifact_count"), 1)
        self.assertEqual(_int_field(summary, "blocking_issue_count"), 0)

    def test_bundle_writes_manifest_and_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            out_path = Path(temp_dir) / "bundle.json"
            summary_path = Path(temp_dir) / "bundle.md"
            completed = _run_bundle("--out", str(out_path), "--summary", str(summary_path))
            payload = _json_object(out_path.read_text(encoding="utf-8"))
            summary_text = summary_path.read_text(encoding="utf-8")

        self.assertEqual(completed.returncode, 0)
        self.assertIn("Release Evidence Bundle", summary_text)
        self.assertEqual(_int_field(_object_field(payload, "summary"), "blocking_issue_count"), 0)

    def test_forbidden_evidence_extension_blocks_release(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _ = (root / "sample.E01").write_text("not an image, policy test only", encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, str(SCRIPT), "--root", str(root), "--json"],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            payload = _json_object(completed.stdout)

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(payload["release_evidence_status"], "release_blocked")
        self.assertEqual(_int_field(_object_field(payload, "summary"), "blocking_issue_count"), 1)

    def test_missing_bundle_root_blocks_release(self) -> None:
        missing_root = Path(tempfile.gettempdir()) / "rapid-review-definitely-missing-bundle-root"
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(missing_root), "--json"],
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        payload = _json_object(completed.stdout)

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(payload["release_evidence_status"], "release_blocked")
        self.assertEqual(_int_field(_object_field(payload, "summary"), "artifact_count"), 0)
        self.assertEqual(_int_field(_object_field(payload, "summary"), "blocking_issue_count"), 1)

    def test_file_bundle_root_blocks_release(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            file_root = Path(temp_dir) / "not-a-directory.txt"
            _ = file_root.write_text("bundle root must be a directory", encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, str(SCRIPT), "--root", str(file_root), "--json"],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            payload = _json_object(completed.stdout)

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(payload["release_evidence_status"], "release_blocked")
        self.assertEqual(_int_field(_object_field(payload, "summary"), "artifact_count"), 0)
        self.assertEqual(_int_field(_object_field(payload, "summary"), "blocking_issue_count"), 1)


def _run_bundle(*extra_args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(TIER0_ROOT), *extra_args],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def _schema() -> JsonObject:
    data, error = load_json_document(BUNDLE_SCHEMA, "bundle manifest schema")
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


if __name__ == "__main__":
    _ = unittest.main()
