from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Final
from uuid import uuid4

from rapidtriage.validation.known_answer_files import FileCheckSummary
from rapidtriage.validation.known_answer_types import (
    JsonObject,
    ManifestValidationError,
    ManifestValidationResult,
)


RESULT_SCHEMA_VERSION: Final = "rapidforensic-known-answer-validation-result-v1"
RELEASE_EVIDENCE_STATUS: Final = "engineering_check_only"
TOOL_NAME: Final = "known-answer-qc"
TOOL_VERSION: Final = "0.1.0"
RUNTIME_ERROR_VALIDATORS: Final = frozenset({"dependency", "file", "json", "schema"})

__all__ = [
    "build_result",
    "format_text_result",
    "new_run_id",
    "result_to_dict",
    "utc_now",
]


def new_run_id() -> str:
    return f"{TOOL_NAME}-{uuid4()}"


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def build_result(
    manifest_file: Path,
    schema_file: Path,
    manifest_object: JsonObject | None,
    errors: list[ManifestValidationError],
    *,
    run_id: str,
    started_at_utc: str,
    check_files: bool = False,
    fixture_root: Path | None = None,
    file_check_summary: FileCheckSummary | None = None,
) -> ManifestValidationResult:
    file_checks = file_check_summary.checks if file_check_summary is not None else []
    skipped_count = file_check_summary.skipped_count if file_check_summary is not None else 0
    failed_count = sum(1 for check in file_checks if not check.ok)
    ok = not errors and failed_count == 0
    status = _status(ok, errors)
    return ManifestValidationResult(
        schema_version=RESULT_SCHEMA_VERSION,
        run_id=run_id,
        status=status,
        ok=ok,
        release_evidence_status=RELEASE_EVIDENCE_STATUS,
        tool={"name": TOOL_NAME, "version": TOOL_VERSION},
        started_at_utc=started_at_utc,
        finished_at_utc=utc_now(),
        manifest_path=str(manifest_file),
        schema_path=str(schema_file),
        fixture_root=str(fixture_root) if check_files and fixture_root is not None else None,
        check_files=check_files,
        corpus_id=_string_field(manifest_object, "corpus_id"),
        case_id=_string_field(manifest_object, "case_id"),
        image_id=_string_field(manifest_object, "image_id"),
        expected_item_count=_expected_item_count(manifest_object),
        warning_count=0,
        error_count=len(errors) + failed_count,
        errors=errors,
        file_check_enabled=check_files,
        file_checked_count=len(file_checks),
        file_skipped_count=skipped_count,
        file_error_count=failed_count,
        file_checks=file_checks,
        summary=_summary(status, errors, failed_count, check_files, RELEASE_EVIDENCE_STATUS),
    )


def result_to_dict(result: ManifestValidationResult) -> JsonObject:
    return {
        "schema_version": result.schema_version,
        "run_id": result.run_id,
        "status": result.status,
        "ok": result.ok,
        "tool": result.tool,
        "started_at_utc": result.started_at_utc,
        "finished_at_utc": result.finished_at_utc,
        "manifest_path": result.manifest_path,
        "schema_path": result.schema_path,
        "fixture_root": result.fixture_root,
        "check_files": result.check_files,
        "release_evidence_status": result.release_evidence_status,
        "corpus_id": result.corpus_id,
        "case_id": result.case_id,
        "image_id": result.image_id,
        "expected_item_count": result.expected_item_count,
        "warning_count": result.warning_count,
        "error_count": result.error_count,
        "errors": [
            {
                "path": error.path,
                "message": error.message,
                "validator": error.validator,
            }
            for error in result.errors
        ],
        "file_check_enabled": result.file_check_enabled,
        "file_checked_count": result.file_checked_count,
        "file_skipped_count": result.file_skipped_count,
        "file_error_count": result.file_error_count,
        "file_checks": [
            {
                "item_id": check.item_id,
                "relative_path": check.relative_path,
                "status": check.status,
                "ok": check.ok,
                "expected_size": check.expected_size,
                "actual_size": check.actual_size,
                "expected_sha256": check.expected_sha256,
                "actual_sha256": check.actual_sha256,
                "message": check.message,
            }
            for check in result.file_checks
        ],
        "summary": result.summary,
    }


def format_text_result(result: ManifestValidationResult) -> str:
    lines = [
        f"{result.status} known-answer manifest validation",
        f"manifest: {result.manifest_path}",
        f"schema: {result.schema_path}",
        f"corpus_id: {result.corpus_id or '-'}",
        f"case_id: {result.case_id or '-'}",
        f"image_id: {result.image_id or '-'}",
        f"expected_items: {_format_optional_int(result.expected_item_count)}",
        f"warnings: {result.warning_count}",
    ]

    if result.file_check_enabled:
        lines.extend(
            [
                f"fixture_root: {result.fixture_root or '-'}",
                (
                    "file_checks: "
                    f"{result.file_check_passed_count} passed, "
                    f"{result.file_check_failed_count} failed, "
                    f"{result.file_check_skipped_count} skipped"
                ),
            ],
        )

    if result.errors:
        lines.append("errors:")
        lines.extend(
            f"- {error.path}: {error.message} [{error.validator or 'unknown'}]" for error in result.errors
        )
    failed_checks = [check for check in result.file_checks if not check.ok]
    if failed_checks:
        lines.append("file check failures:")
        lines.extend(f"- {check.relative_path}: {check.message}" for check in failed_checks)

    return "\n".join(lines)


def _format_optional_int(value: int | None) -> str:
    return str(value) if value is not None else "-"


def _status(ok: bool, errors: list[ManifestValidationError]) -> str:
    if ok:
        return "PASS"
    if any(error.validator in RUNTIME_ERROR_VALIDATORS for error in errors):
        return "ERROR"
    return "FAIL"


def _summary(
    status: str,
    errors: list[ManifestValidationError],
    failed_count: int,
    check_files: bool,
    release_evidence_status: str,
) -> JsonObject:
    return {
        "schema_valid": not errors,
        "file_checks_valid": not check_files or failed_count == 0,
        "release_evidence_status": release_evidence_status,
        "message": _summary_message(status),
    }


def _summary_message(status: str) -> str:
    if status == "PASS":
        return "known-answer validation passed"
    if status == "ERROR":
        return "known-answer validation could not complete"
    return "known-answer validation failed"


def _string_field(document: JsonObject | None, field_name: str) -> str | None:
    if document is None:
        return None
    value = document.get(field_name)
    return value if isinstance(value, str) else None


def _expected_item_count(document: JsonObject | None) -> int | None:
    if document is None:
        return None
    expected_items = document.get("expected_items")
    return len(expected_items) if isinstance(expected_items, list) else None
