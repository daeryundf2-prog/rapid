from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from rapidtriage.validation.json_fields import int_field, list_field, object_field
from rapidtriage.validation.known_answer_schema import load_json_document, validate_schema_document
from rapidtriage.validation.known_answer_types import JsonObject, ManifestValidationError
from rapidtriage.validation.manifest_truth import expected_truth_issue
from rapidtriage.validation.truth_manifest import expected_item_path, load_truth_manifest
from rapidtriage.validation.trusted_diff_result import (
    DiffEntry,
    TrustedDiffResult,
    diff_counts,
    diff_entry_to_dict,
    diff_message,
)
from .observed_results import ObservedItem, index_by_path, load_observed_results


TRUSTED_DIFF_SCHEMA_PATH: Final[Path] = (
    Path(__file__).resolve().parents[2]
    / "docs"
    / "validation"
    / "known-answer-corpus"
    / "trusted-diff-result-schema-v1.schema.json"
)
TOOL_VERSION: Final = "0.1.0"


@dataclass(frozen=True, slots=True)
class TrustedDiffInputPaths:
    manifest_path: Path
    rapid_results_path: Path
    trusted_results_path: Path


def compare(
    manifest_path: Path,
    rapid_results_path: Path,
    trusted_results_path: Path,
) -> TrustedDiffResult:
    errors = _load_input_errors(manifest_path, rapid_results_path, trusted_results_path)
    if errors:
        return _result("ERROR", manifest_path, rapid_results_path, trusted_results_path, [], errors)

    rapid_results, rapid_errors = load_observed_results(rapid_results_path)
    trusted_results, trusted_errors = load_observed_results(trusted_results_path)
    if rapid_errors or trusted_errors or rapid_results is None or trusted_results is None:
        return _result("ERROR", manifest_path, rapid_results_path, trusted_results_path, [], rapid_errors + trusted_errors)

    manifest, manifest_errors = load_truth_manifest(manifest_path)
    if manifest_errors:
        return _result("ERROR", manifest_path, rapid_results_path, trusted_results_path, [], manifest_errors)

    if manifest is None:
        return _result("ERROR", manifest_path, rapid_results_path, trusted_results_path, [], manifest_errors)
    expected = manifest.expected_by_path
    diffs = _compare_items(index_by_path(rapid_results.items), index_by_path(trusted_results.items), expected)
    status = "FAIL" if any(diff.severity == "critical" for diff in diffs) else "PASS"
    return _result(status, manifest_path, rapid_results_path, trusted_results_path, diffs, [])


def result_to_text(result: TrustedDiffResult) -> str:
    counts = object_field(result.document, "counts")
    lines = [
        f"{result.document['status']} trusted diff",
        f"matches: {int_field(counts, 'match')}",
        f"critical: {int_field(counts, 'critical')}",
    ]
    for diff in list_field(result.document, "diffs"):
        if isinstance(diff, dict) and diff.get("category") != "MATCH":
            lines.append(f"- {diff.get('category')}: {diff.get('normalized_path')} - {diff.get('message')}")
    return "\n".join(lines)


def write_summary(result: TrustedDiffResult, path: Path) -> None:
    counts = object_field(result.document, "counts")
    content = "\n".join(
        [
            "# Trusted Diff Summary",
            "",
            f"- Status: {result.document['status']}",
            f"- MATCH: {int_field(counts, 'match')}",
            f"- Critical: {int_field(counts, 'critical')}",
            "",
            "This is an engineering comparison output, not release approval.",
            "",
        ],
    )
    _ = path.write_text(content, encoding="utf-8")


def validate_result_schema(document: JsonObject) -> list[ManifestValidationError]:
    schema, schema_error = load_json_document(TRUSTED_DIFF_SCHEMA_PATH, "trusted diff result schema")
    if schema_error is not None:
        return [schema_error]
    if not isinstance(schema, dict):
        return [ManifestValidationError(path="$", message="trusted diff schema must be a JSON object", validator="type")]
    return validate_schema_document(document, schema)


def result_schema_error_result(
    inputs: TrustedDiffInputPaths,
    errors: list[ManifestValidationError],
) -> TrustedDiffResult:
    return _result(
        "ERROR",
        inputs.manifest_path,
        inputs.rapid_results_path,
        inputs.trusted_results_path,
        [],
        [_result_schema_error(error) for error in errors],
    )


def _result_schema_error(error: ManifestValidationError) -> ManifestValidationError:
    return ManifestValidationError(
        path=error.path,
        message=f"trusted diff result schema validation failed: {error.message}",
        validator=error.validator,
    )


def _load_input_errors(
    manifest_path: Path,
    rapid_results_path: Path,
    trusted_results_path: Path,
) -> list[ManifestValidationError]:
    return [
        ManifestValidationError(path="$", message=f"input file does not exist: {path}", validator="file")
        for path in (manifest_path, rapid_results_path, trusted_results_path)
        if not path.exists()
    ]


def _compare_items(
    rapid: dict[str, ObservedItem],
    trusted: dict[str, ObservedItem],
    expected: dict[str, JsonObject],
) -> list[DiffEntry]:
    diffs: list[DiffEntry] = []
    for path in sorted(set(rapid) | set(trusted) | set(expected)):
        rapid_item = rapid.get(path)
        trusted_item = trusted.get(path)
        expected_item = expected.get(path, {})
        diffs.append(_diff_for_path(rapid_item, trusted_item, expected_item))
    return diffs


def _diff_for_path(
    rapid_item: ObservedItem | None,
    trusted_item: ObservedItem | None,
    expected_item: JsonObject,
) -> DiffEntry:
    if rapid_item is None and trusted_item is None:
        return _expected_missing_entry(expected_item)
    if rapid_item is None:
        return _entry("TRUSTED_ONLY", "critical", trusted_item, None, "review_required", "trusted reference contains path missing from RapidForensic")
    if trusted_item is None:
        return _entry("RAPID_ONLY", "critical", rapid_item, None, "review_required", "RapidForensic contains path missing from trusted reference")
    if not expected_item:
        return _entry("METADATA_MISMATCH", "critical", rapid_item, trusted_item, "review_required", "output path is not declared in manifest truth")
    if _is_expected_unsupported(expected_item, rapid_item, trusted_item):
        return _entry("EXPECTED_UNSUPPORTED", "info", rapid_item, trusted_item, "none", "both outputs reflect expected unsupported item")
    if _is_expected_unrecoverable(expected_item, rapid_item, trusted_item):
        return _entry("EXPECTED_UNRECOVERABLE", "info", rapid_item, trusted_item, "none", "both outputs reflect expected unrecoverable item")
    if _is_expected_inconclusive(expected_item, rapid_item, trusted_item):
        return _entry("EXPECTED_INCONCLUSIVE", "info", rapid_item, trusted_item, "none", "both outputs reflect expected inconclusive item")
    truth_issue = expected_truth_issue(rapid_item, trusted_item, expected_item)
    if truth_issue is not None:
        return _entry(
            truth_issue.category,
            truth_issue.severity,
            rapid_item,
            trusted_item,
            truth_issue.reviewer_action,
            truth_issue.message,
        )
    if rapid_item.observed_status == "inconclusive" or trusted_item.observed_status == "inconclusive":
        return _entry("INCONCLUSIVE", "critical", rapid_item, trusted_item, "external_review_required", "one or more outputs is inconclusive")
    if rapid_item.sha256 != trusted_item.sha256:
        return _entry("HASH_MISMATCH", "critical", rapid_item, trusted_item, "review_required", "sha256 differs between RapidForensic and trusted reference")
    if rapid_item.size_bytes != trusted_item.size_bytes or rapid_item.observed_status != trusted_item.observed_status:
        return _entry("METADATA_MISMATCH", "critical", rapid_item, trusted_item, "review_required", "status or size differs between outputs")
    return _entry("MATCH", "info", rapid_item, trusted_item, "none", "RapidForensic and trusted reference match")


def _entry(
    category: str,
    severity: str,
    rapid_item: ObservedItem | None,
    trusted_item: ObservedItem | None,
    reviewer_action: str,
    message: str,
) -> DiffEntry:
    item = rapid_item if rapid_item is not None else trusted_item
    return DiffEntry(
        category=category,
        severity=severity,
        item_id=item.item_id if item is not None else None,
        normalized_path=item.normalized_path if item is not None else "<unknown>",
        rapid_status=rapid_item.observed_status if rapid_item is not None else None,
        trusted_status=trusted_item.observed_status if trusted_item is not None else None,
        reviewer_action=reviewer_action,
        message=message,
    )


def _expected_missing_entry(expected_item: JsonObject) -> DiffEntry:
    item_id = expected_item.get("item_id")
    return DiffEntry(
        category="METADATA_MISMATCH",
        severity="critical",
        item_id=item_id if isinstance(item_id, str) else None,
        normalized_path=expected_item_path(expected_item) or "<unknown>",
        rapid_status=None,
        trusted_status=None,
        reviewer_action="rerun_required",
        message="manifest expected path missing from RapidForensic and trusted reference outputs",
    )


def _is_expected_unsupported(expected: JsonObject, rapid: ObservedItem, trusted: ObservedItem) -> bool:
    return expected.get("expected_recovery") == "expected_unsupported" and rapid.observed_status == trusted.observed_status == "unsupported"


def _is_expected_unrecoverable(expected: JsonObject, rapid: ObservedItem, trusted: ObservedItem) -> bool:
    return expected.get("expected_recovery") == "must_not_recover" and rapid.observed_status == trusted.observed_status == "not_found"


def _is_expected_inconclusive(expected: JsonObject, rapid: ObservedItem, trusted: ObservedItem) -> bool:
    return expected.get("expected_recovery") == "expected_inconclusive" and rapid.observed_status == trusted.observed_status == "inconclusive"


def _result(
    status: str,
    manifest_path: Path,
    rapid_results_path: Path,
    trusted_results_path: Path,
    diffs: list[DiffEntry],
    errors: list[ManifestValidationError],
) -> TrustedDiffResult:
    counts = diff_counts(diffs)
    document: JsonObject = {
        "schema_version": "rapidforensic-trusted-diff-result-v1",
        "status": status,
        "ok": status == "PASS",
        "release_evidence_status": "engineering_check_only",
        "tool": {"name": "trusted-diff", "version": TOOL_VERSION},
        "manifest_path": str(manifest_path),
        "rapid_results_path": str(rapid_results_path),
        "trusted_results_path": str(trusted_results_path),
        "compared_at_utc": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "counts": counts,
        "diffs": [diff_entry_to_dict(diff) for diff in diffs],
        "errors": [{"path": error.path, "message": error.message, "validator": error.validator} for error in errors],
        "summary": {"message": diff_message(status, counts), "release_evidence_status": "engineering_check_only"},
    }
    return TrustedDiffResult(status=status, ok=status == "PASS", document=document)
