from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from rapidtriage.validation.known_answer_schema import load_json_document, validate_schema_document
from rapidtriage.validation.known_answer_types import JsonObject, JsonValue, ManifestValidationError
from rapidtriage.validation.observed_results import OBSERVED_RESULTS_SCHEMA_PATH


SUPPORTED_TOOLS: Final = frozenset(
    {
        "synthetic-tsv",
        "manual-json",
        "fls-tsv-placeholder",
        "tsk-recover-manifest-placeholder",
    },
)


@dataclass(frozen=True, slots=True)
class NormalizerResult:
    exit_code: int
    document: JsonObject


def normalize_export(tool: str, input_path: Path) -> NormalizerResult:
    if tool not in SUPPORTED_TOOLS:
        return _error(f"unsupported tool type: {tool}")
    if tool in {"fls-tsv-placeholder", "tsk-recover-manifest-placeholder"}:
        return _error(f"{tool} normalizer is documented placeholder only")
    if tool == "manual-json":
        return _manual_json(input_path)
    return _synthetic_tsv(input_path)


def format_text(result: NormalizerResult) -> str:
    if result.exit_code != 0:
        return f"ERROR normalize trusted export: {result.document['message']}"
    summary = _object(result.document, "summary")
    return "\n".join(
        [
            "PASS normalize trusted export",
            f"items: {_int(summary, 'item_count')}",
            "notes: normalized export, not raw evidence",
        ],
    )


def _manual_json(input_path: Path) -> NormalizerResult:
    document, error = load_json_document(input_path, "manual observed results")
    if error is not None:
        return _error(error.message)
    if not isinstance(document, dict):
        return _error("manual-json input must be a JSON object")
    return _validated_result(document)


def _synthetic_tsv(input_path: Path) -> NormalizerResult:
    if not input_path.exists():
        return _error(f"input file does not exist: {input_path}")
    items: list[JsonValue] = []
    recovered_count = 0
    error_count = 0
    inconclusive_count = 0
    try:
        with input_path.open("r", encoding="utf-8", newline="") as file_obj:
            reader = csv.DictReader(file_obj, delimiter="\t")
            for index, row in enumerate(reader, start=1):
                size_bytes, row_error = _validated_size_bytes(index, row)
                if row_error is not None:
                    return _error(row_error)
                recovered_error = _recovered_row_error(index, row, size_bytes)
                if recovered_error is not None:
                    return _error(recovered_error)
                item = _row_to_item(index, row, size_bytes)
                items.append(item)
                status = row.get("observed_status")
                if status == "recovered":
                    recovered_count += 1
                if status == "error":
                    error_count += 1
                if status == "inconclusive":
                    inconclusive_count += 1
    except OSError as exc:
        return _error(f"input file could not be read: {exc}")

    document: JsonObject = {
        "schema_version": "rapidforensic-observed-results-v1",
        "source_type": "synthetic_fixture",
        "source_name": "synthetic-tsv normalizer",
        "source_run_id": "synthetic-tsv-normalized-001",
        "release_evidence_status": "engineering_check_only",
        "generated_at_utc": "2026-06-17T00:00:00Z",
        "items": items,
        "summary": {
            "item_count": len(items),
            "recovered_count": recovered_count,
            "error_count": error_count,
            "inconclusive_count": inconclusive_count,
        },
        "notes": "Normalized export, not raw evidence.",
    }
    return _validated_result(document)


def _validated_result(document: JsonObject) -> NormalizerResult:
    errors = _observed_schema_errors(document)
    if errors:
        return _error(_error_summary("normalized observed results schema validation failed", errors))
    return NormalizerResult(exit_code=0, document=document)


def _observed_schema_errors(document: JsonObject) -> list[ManifestValidationError]:
    schema, schema_error = load_json_document(OBSERVED_RESULTS_SCHEMA_PATH, "observed results schema")
    if schema_error is not None:
        return [schema_error]
    if not isinstance(schema, dict):
        return [ManifestValidationError(path="$", message="observed results schema must be a JSON object", validator="type")]
    return validate_schema_document(document, schema)


def _error_summary(prefix: str, errors: list[ManifestValidationError]) -> str:
    details = "; ".join(f"{error.path}: {error.message}" for error in errors[:5])
    return f"{prefix}: {details}"


def _row_to_item(index: int, row: dict[str, str | None], size_bytes: int | None) -> JsonObject:
    source_run_id = row.get("source_tool_run_id") or "synthetic-tsv-normalized-001"
    return {
        "item_id": f"synthetic-tsv-{index:03d}",
        "normalized_path": row.get("normalized_path") or "",
        "observed_status": row.get("observed_status") or "inconclusive",
        "recovery_mode": row.get("recovery_mode") or "none",
        "size_bytes": size_bytes,
        "sha256": row.get("sha256") or None,
        "metadata": {},
        "source_tool_run_id": source_run_id,
        "notes": "Normalized export, not raw evidence.",
    }


def _error(message: str) -> NormalizerResult:
    return NormalizerResult(
        exit_code=2,
        document={
            "status": "ERROR",
            "message": message,
            "release_evidence_status": "engineering_check_only",
        },
    )


def _validated_size_bytes(index: int, row: dict[str, str | None]) -> tuple[int | None, str | None]:
    value = row.get("size_bytes")
    if value is None or value == "":
        return None, None
    try:
        return int(value), None
    except ValueError:
        return None, f"row {index} size_bytes must be an integer when provided"


def _recovered_row_error(index: int, row: dict[str, str | None], size_bytes: int | None) -> str | None:
    if row.get("observed_status") != "recovered":
        return None
    if size_bytes is None:
        return f"row {index} recovered item requires size_bytes"
    if not row.get("sha256"):
        return f"row {index} recovered item requires sha256"
    return None


def _object(document: JsonObject, field: str) -> JsonObject:
    value: JsonValue | None = document.get(field)
    return value if isinstance(value, dict) else {}


def _int(document: JsonObject, field: str) -> int:
    value: JsonValue | None = document.get(field)
    return value if isinstance(value, int) and not isinstance(value, bool) else 0
