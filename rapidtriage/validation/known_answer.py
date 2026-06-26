from __future__ import annotations

from pathlib import Path

from rapidtriage.validation.known_answer_files import FileCheckSummary, run_file_checks
from .known_answer_result import (
    build_result,
    format_text_result as _format_text_result,
    new_run_id,
    result_to_dict as _result_to_dict,
    utc_now,
)
from rapidtriage.validation.known_answer_schema import (
    DEFAULT_SCHEMA_PATH,
    load_json_document,
    validate_schema_document,
)
from rapidtriage.validation.known_answer_types import (
    JsonObject,
    JsonValue,
    ManifestValidationError,
    ManifestValidationResult,
)


def validate_manifest(
    manifest_path: str | Path,
    schema_path: str | Path | None = None,
    *,
    check_files: bool = False,
    fixture_root: str | Path | None = None,
) -> ManifestValidationResult:
    run_id = new_run_id()
    started_at_utc = utc_now()
    manifest_file = Path(manifest_path)
    schema_file = Path(schema_path) if schema_path is not None else DEFAULT_SCHEMA_PATH
    effective_fixture_root = Path(fixture_root) if fixture_root is not None else manifest_file.parent

    manifest_data, manifest_error = load_json_document(manifest_file, "manifest")
    schema_data, schema_error = load_json_document(schema_file, "schema")
    manifest_object = _as_object(manifest_data)
    errors: list[ManifestValidationError] = []

    if manifest_error is not None:
        errors.append(manifest_error)
    if schema_error is not None:
        errors.append(schema_error)
    if errors:
        return build_result(
            manifest_file,
            schema_file,
            manifest_object,
            errors,
            run_id=run_id,
            started_at_utc=started_at_utc,
            check_files=check_files,
            fixture_root=effective_fixture_root,
        )

    schema_object = _as_object(schema_data)
    if schema_object is None:
        errors.append(
            ManifestValidationError(
                path="$",
                message="schema document must be a JSON object",
                validator="schema",
            ),
        )
        return build_result(
            manifest_file,
            schema_file,
            manifest_object,
            errors,
            run_id=run_id,
            started_at_utc=started_at_utc,
            check_files=check_files,
            fixture_root=effective_fixture_root,
        )

    errors.extend(validate_schema_document(manifest_data, schema_object))
    file_check_summary = _file_check_summary(check_files, manifest_object, effective_fixture_root, errors)
    return build_result(
        manifest_file,
        schema_file,
        manifest_object,
        errors,
        run_id=run_id,
        started_at_utc=started_at_utc,
        check_files=check_files,
        fixture_root=effective_fixture_root,
        file_check_summary=file_check_summary,
    )


def _file_check_summary(
    check_files: bool,
    manifest_object: JsonObject | None,
    fixture_root: Path,
    errors: list[ManifestValidationError],
) -> FileCheckSummary | None:
    if not check_files or errors:
        return None
    return run_file_checks(manifest_object, fixture_root)


def _as_object(value: JsonValue | None) -> JsonObject | None:
    return value if isinstance(value, dict) else None


def result_to_dict(result: ManifestValidationResult) -> JsonObject:
    return _result_to_dict(result)


def format_text_result(result: ManifestValidationResult) -> str:
    return _format_text_result(result)
