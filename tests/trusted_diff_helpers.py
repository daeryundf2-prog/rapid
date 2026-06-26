from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import cast

from rapidtriage.validation.known_answer_schema import load_json_document
from rapidtriage.validation.known_answer_types import JsonObject, JsonValue


REPO_ROOT = Path(__file__).resolve().parents[1]
TIER0_ROOT = REPO_ROOT / "tests" / "fixtures" / "known_answer" / "tier0-basic"
MANIFEST = TIER0_ROOT / "manifest.json"
RAPID_RESULTS = TIER0_ROOT / "rapid-results.json"
TRUSTED_RESULTS = TIER0_ROOT / "trusted-results.json"
SCRIPT = REPO_ROOT / "scripts" / "trusted-diff.py"
RESULT_SCHEMA = REPO_ROOT / "docs" / "validation" / "known-answer-corpus" / "trusted-diff-result-schema-v1.schema.json"


def run_trusted_diff(*extra_args: str) -> subprocess.CompletedProcess[str]:
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


def schema() -> JsonObject:
    data, error = load_json_document(RESULT_SCHEMA, "trusted diff result schema")
    if error is not None:
        raise AssertionError(error.message)
    if not isinstance(data, dict):
        raise AssertionError("schema must be an object")
    return data


def json_object(raw_json: str) -> JsonObject:
    value = cast(JsonValue, json.loads(raw_json))
    if not isinstance(value, dict):
        raise AssertionError("JSON output must be an object")
    return value


def object_field(document: JsonObject, field: str) -> JsonObject:
    value = document.get(field)
    if not isinstance(value, dict):
        raise AssertionError(f"{field} must be an object")
    return value


def list_field(document: JsonObject, field: str) -> list[JsonValue]:
    value = document.get(field)
    if not isinstance(value, list):
        raise AssertionError(f"{field} must be a list")
    return value


def int_field(document: JsonObject, field: str) -> int:
    value = document.get(field)
    if not isinstance(value, int) or isinstance(value, bool):
        raise AssertionError(f"{field} must be an integer")
    return value


def mutated_trusted_results(temp_dir: Path) -> Path:
    return mutated_results(temp_dir, TRUSTED_RESULTS, "trusted-results")


def mutated_results(temp_dir: Path, source: Path, stem: str) -> Path:
    return mutated_observed_results(temp_dir, source, stem, make_first_item_hash_wrong)


def mutated_observed_results(temp_dir: Path, source: Path, stem: str, mutator: Callable[[JsonObject], None]) -> Path:
    payload = json_object(source.read_text(encoding="utf-8"))
    items = list_field(payload, "items")
    first_item = items[0] if items else None
    if not isinstance(first_item, dict):
        raise AssertionError("first item must be an object")
    mutator(first_item)
    path = temp_dir / f"{stem}.json"
    _ = path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


def make_first_item_hash_wrong(item: JsonObject) -> None:
    item["sha256"] = "f" * 64


def make_first_item_inconclusive(item: JsonObject) -> None:
    item["observed_status"] = "inconclusive"
    item["recovery_mode"] = "none"
    item["size_bytes"] = None
    item["sha256"] = None


def make_first_item_id_wrong(item: JsonObject) -> None:
    item["item_id"] = "wrong-item-id"


def duplicated_observed_path(temp_dir: Path, source: Path, stem: str) -> Path:
    payload = json_object(source.read_text(encoding="utf-8"))
    items = list_field(payload, "items")
    first_item = items[0] if items else None
    if not isinstance(first_item, dict):
        raise AssertionError("first item must be an object")
    duplicate = dict(first_item)
    duplicate["item_id"] = f"{first_item['item_id']}-duplicate"
    items.append(duplicate)
    payload["summary"] = {
        "item_count": len(items),
        "recovered_count": sum(1 for item in items if isinstance(item, dict) and item.get("observed_status") == "recovered"),
        "error_count": 0,
        "inconclusive_count": 0,
    }
    path = temp_dir / f"{stem}.json"
    _ = path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


def duplicated_manifest_expected_path(temp_dir: Path) -> Path:
    payload = json_object(MANIFEST.read_text(encoding="utf-8"))
    items = list_field(payload, "expected_items")
    first_item = items[0] if items else None
    if not isinstance(first_item, dict):
        raise AssertionError("first expected item must be an object")
    duplicate = dict(first_item)
    duplicate["item_id"] = f"{first_item['item_id']}-duplicate"
    items.append(duplicate)
    path = temp_dir / "manifest-duplicate-path.json"
    _ = path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


def manifest_without_required_truth_sha(temp_dir: Path) -> Path:
    payload = json_object(MANIFEST.read_text(encoding="utf-8"))
    items = list_field(payload, "expected_items")
    first_item = items[0] if items else None
    if not isinstance(first_item, dict):
        raise AssertionError("first expected item must be an object")
    del first_item["sha256"]
    path = temp_dir / "manifest-missing-sha.json"
    _ = path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


def empty_observed_results(temp_dir: Path, stem: str) -> Path:
    payload = json_object(TRUSTED_RESULTS.read_text(encoding="utf-8"))
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


def has_error_message(payload: JsonObject, expected: str) -> bool:
    return any(isinstance(error, dict) and expected in str(error.get("message", "")) for error in list_field(payload, "errors"))


def has_diff_message(payload: JsonObject, expected: str) -> bool:
    return any(isinstance(diff, dict) and expected in str(diff.get("message", "")) for diff in list_field(payload, "diffs"))
