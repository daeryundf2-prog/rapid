from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Final

from rapidtriage.validation.known_answer_schema import load_json_document, validate_schema_document
from rapidtriage.validation.known_answer_types import JsonObject, JsonValue, ManifestValidationError


OBSERVED_RESULTS_SCHEMA_PATH: Final[Path] = (
    Path(__file__).resolve().parents[2]
    / "docs"
    / "validation"
    / "known-answer-corpus"
    / "observed-results-schema-v1.schema.json"
)


@dataclass(frozen=True, slots=True)
class ObservedItem:
    item_id: str
    normalized_path: str
    observed_status: str
    recovery_mode: str
    size_bytes: int | None
    sha256: str | None


@dataclass(frozen=True, slots=True)
class ObservedResults:
    path: Path
    document: JsonObject
    items: list[ObservedItem]


def load_observed_results(path: Path) -> tuple[ObservedResults | None, list[ManifestValidationError]]:
    document, load_error = load_json_document(path, "observed results")
    if load_error is not None:
        return None, [load_error]
    if not isinstance(document, dict):
        return None, [ManifestValidationError(path="$", message="observed results must be a JSON object", validator="type")]

    schema, schema_error = _load_schema()
    if schema_error is not None:
        return None, [schema_error]
    errors = validate_schema_document(document, schema)
    if errors:
        return None, errors
    return ObservedResults(path=path, document=document, items=_items(document)), []


def observed_result_document(
    *,
    source_name: str,
    source_run_id: str,
    items: list[ObservedItem],
    generated_at_utc: str,
) -> JsonObject:
    return {
        "schema_version": "rapidforensic-observed-results-v1",
        "source_type": "synthetic_fixture",
        "source_name": source_name,
        "source_run_id": source_run_id,
        "release_evidence_status": "engineering_check_only",
        "generated_at_utc": generated_at_utc,
        "items": [
            {
                "item_id": item.item_id,
                "normalized_path": item.normalized_path,
                "observed_status": item.observed_status,
                "recovery_mode": item.recovery_mode,
                "size_bytes": item.size_bytes,
                "sha256": item.sha256,
                "metadata": {},
                "source_tool_run_id": source_run_id,
                "notes": "Normalized export, not raw evidence.",
            }
            for item in items
        ],
        "summary": {
            "item_count": len(items),
            "recovered_count": sum(1 for item in items if item.observed_status == "recovered"),
            "error_count": sum(1 for item in items if item.observed_status == "error"),
            "inconclusive_count": sum(1 for item in items if item.observed_status == "inconclusive"),
        },
        "notes": "Normalized export, not raw evidence.",
    }


def index_by_path(items: list[ObservedItem]) -> dict[str, ObservedItem]:
    return {item.normalized_path: item for item in items}


def _load_schema() -> tuple[JsonObject, ManifestValidationError | None]:
    schema, schema_error = load_json_document(OBSERVED_RESULTS_SCHEMA_PATH, "observed results schema")
    if schema_error is not None:
        return {}, schema_error
    if not isinstance(schema, dict):
        return {}, ManifestValidationError(path="$", message="observed schema must be a JSON object", validator="type")
    return schema, None


def _items(document: JsonObject) -> list[ObservedItem]:
    raw_items = document.get("items")
    if not isinstance(raw_items, list):
        return []
    items: list[ObservedItem] = []
    for raw_item in raw_items:
        if isinstance(raw_item, dict):
            items.append(_item(raw_item))
    return items


def _item(raw_item: JsonObject) -> ObservedItem:
    return ObservedItem(
        item_id=_string(raw_item, "item_id"),
        normalized_path=_string(raw_item, "normalized_path"),
        observed_status=_string(raw_item, "observed_status"),
        recovery_mode=_string(raw_item, "recovery_mode"),
        size_bytes=_int_or_none(raw_item, "size_bytes"),
        sha256=_string_or_none(raw_item, "sha256"),
    )


def _string(document: JsonObject, field: str) -> str:
    value: JsonValue | None = document.get(field)
    return value if isinstance(value, str) else ""


def _string_or_none(document: JsonObject, field: str) -> str | None:
    value: JsonValue | None = document.get(field)
    return value if isinstance(value, str) else None


def _int_or_none(document: JsonObject, field: str) -> int | None:
    value: JsonValue | None = document.get(field)
    return value if isinstance(value, int) and not isinstance(value, bool) else None
