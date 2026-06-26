from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from rapidtriage.validation.known_answer_schema import DEFAULT_SCHEMA_PATH, load_json_document, validate_schema_document
from rapidtriage.validation.known_answer_types import JsonObject, JsonValue, ManifestValidationError


@dataclass(frozen=True, slots=True)
class TruthManifest:
    document: JsonObject
    expected_by_path: dict[str, JsonObject]


def load_truth_manifest(path: Path) -> tuple[TruthManifest | None, list[ManifestValidationError]]:
    data, error = load_json_document(path, "truth manifest")
    if error is not None:
        return None, [error]
    if not isinstance(data, dict):
        return None, [ManifestValidationError(path="$", message="truth manifest must be a JSON object", validator="type")]
    schema_errors = _schema_errors(data)
    if schema_errors:
        return None, schema_errors
    semantic_errors = _semantic_errors(data)
    if semantic_errors:
        return None, semantic_errors
    return TruthManifest(document=data, expected_by_path=_expected_by_path(data)), []


def expected_item_path(item: JsonObject) -> str:
    metadata = item.get("expected_metadata")
    if isinstance(metadata, dict):
        fixture_path = metadata.get("fixture_relative_path")
        if isinstance(fixture_path, str):
            return fixture_path
    normalized_path = item.get("normalized_path")
    return normalized_path if isinstance(normalized_path, str) else ""


def _schema_errors(manifest: JsonObject) -> list[ManifestValidationError]:
    schema, schema_error = load_json_document(DEFAULT_SCHEMA_PATH, "truth manifest schema")
    if schema_error is not None:
        return [schema_error]
    if not isinstance(schema, dict):
        return [ManifestValidationError(path="$", message="truth manifest schema must be a JSON object", validator="type")]
    return validate_schema_document(manifest, schema)


def _expected_by_path(manifest: JsonObject) -> dict[str, JsonObject]:
    expected_items = manifest.get("expected_items")
    if not isinstance(expected_items, list):
        return {}
    expected: dict[str, JsonObject] = {}
    for item in expected_items:
        if isinstance(item, dict):
            path = expected_item_path(item)
            if path:
                expected[path] = item
    return expected


def _semantic_errors(manifest: JsonObject) -> list[ManifestValidationError]:
    expected_items = manifest.get("expected_items")
    if not isinstance(expected_items, list):
        return []
    errors: list[ManifestValidationError] = []
    errors.extend(_duplicate_field_errors(expected_items, "item_id", "duplicate expected item_id"))
    errors.extend(_duplicate_path_errors(expected_items))
    return errors


def _duplicate_field_errors(expected_items: list[JsonValue], field: str, message: str) -> list[ManifestValidationError]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for item in expected_items:
        if not isinstance(item, dict):
            continue
        value = item.get(field)
        if not isinstance(value, str):
            continue
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    return [
        ManifestValidationError(path="$/expected_items", message=f"{message}: {value}", validator="unique")
        for value in sorted(duplicates)
    ]


def _duplicate_path_errors(expected_items: list[JsonValue]) -> list[ManifestValidationError]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    errors: list[ManifestValidationError] = []
    for index, item in enumerate(expected_items):
        if not isinstance(item, dict):
            continue
        path = expected_item_path(item)
        if not path:
            errors.append(
                ManifestValidationError(
                    path=f"$/expected_items/{index}",
                    message="expected item has no comparable path",
                    validator="required",
                ),
            )
            continue
        if path in seen:
            duplicates.add(path)
        seen.add(path)
    errors.extend(
        ManifestValidationError(path="$/expected_items", message=f"duplicate expected path: {path}", validator="unique")
        for path in sorted(duplicates)
    )
    return errors
