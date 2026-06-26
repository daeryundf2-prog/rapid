from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from rapidtriage.validation.known_answer_schema import load_json_document, validate_schema_document
from rapidtriage.validation.known_answer_types import JsonObject, JsonValue, ManifestValidationError
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
class DiffEntry:
    category: str
    severity: str
    item_id: str | None
    normalized_path: str
    rapid_status: str | None
    trusted_status: str | None
    reviewer_action: str
    message: str


@dataclass(frozen=True, slots=True)
class TrustedDiffResult:
    status: str
    ok: bool
    document: JsonObject


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

    manifest, manifest_error = _load_manifest(manifest_path)
    if manifest_error is not None:
        return _result("ERROR", manifest_path, rapid_results_path, trusted_results_path, [], [manifest_error])

    expected = _expected_by_path(manifest)
    diffs = _compare_items(index_by_path(rapid_results.items), index_by_path(trusted_results.items), expected)
    status = "FAIL" if any(diff.severity == "critical" for diff in diffs) else "PASS"
    return _result(status, manifest_path, rapid_results_path, trusted_results_path, diffs, [])


def result_to_text(result: TrustedDiffResult) -> str:
    counts = _object(result.document, "counts")
    lines = [
        f"{result.document['status']} trusted diff",
        f"matches: {_int(counts, 'match')}",
        f"critical: {_int(counts, 'critical')}",
    ]
    for diff in _list(result.document, "diffs"):
        if isinstance(diff, dict) and diff.get("category") != "MATCH":
            lines.append(f"- {diff.get('category')}: {diff.get('normalized_path')} - {diff.get('message')}")
    return "\n".join(lines)


def write_summary(result: TrustedDiffResult, path: Path) -> None:
    counts = _object(result.document, "counts")
    content = "\n".join(
        [
            "# Trusted Diff Summary",
            "",
            f"- Status: {result.document['status']}",
            f"- MATCH: {_int(counts, 'match')}",
            f"- Critical: {_int(counts, 'critical')}",
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


def _load_manifest(path: Path) -> tuple[JsonObject, ManifestValidationError | None]:
    data, error = load_json_document(path, "truth manifest")
    if error is not None:
        return {}, error
    if not isinstance(data, dict):
        return {}, ManifestValidationError(path="$", message="truth manifest must be a JSON object", validator="type")
    return data, None


def _expected_by_path(manifest: JsonObject) -> dict[str, JsonObject]:
    expected_items = manifest.get("expected_items")
    if not isinstance(expected_items, list):
        return {}
    expected: dict[str, JsonObject] = {}
    for item in expected_items:
        if isinstance(item, dict):
            path = _expected_path(item)
            if path:
                expected[path] = item
    return expected


def _expected_path(item: JsonObject) -> str:
    metadata = item.get("expected_metadata")
    if isinstance(metadata, dict):
        fixture_path = metadata.get("fixture_relative_path")
        if isinstance(fixture_path, str):
            return fixture_path
    normalized_path = item.get("normalized_path")
    return normalized_path if isinstance(normalized_path, str) else ""


def _compare_items(
    rapid: dict[str, ObservedItem],
    trusted: dict[str, ObservedItem],
    expected: dict[str, JsonObject],
) -> list[DiffEntry]:
    diffs: list[DiffEntry] = []
    for path in sorted(set(rapid) | set(trusted)):
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
    if rapid_item is None:
        return _entry("TRUSTED_ONLY", "critical", trusted_item, None, "review_required", "trusted reference contains path missing from RapidForensic")
    if trusted_item is None:
        return _entry("RAPID_ONLY", "critical", rapid_item, None, "review_required", "RapidForensic contains path missing from trusted reference")
    if _is_expected_unsupported(expected_item, rapid_item, trusted_item):
        return _entry("EXPECTED_UNSUPPORTED", "info", rapid_item, trusted_item, "none", "both outputs reflect expected unsupported item")
    if _is_expected_unrecoverable(expected_item, rapid_item, trusted_item):
        return _entry("EXPECTED_UNRECOVERABLE", "info", rapid_item, trusted_item, "none", "both outputs reflect expected unrecoverable item")
    if rapid_item.observed_status == "inconclusive" or trusted_item.observed_status == "inconclusive":
        return _entry("INCONCLUSIVE", "warning", rapid_item, trusted_item, "external_review_required", "one or more outputs is inconclusive")
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


def _is_expected_unsupported(expected: JsonObject, rapid: ObservedItem, trusted: ObservedItem) -> bool:
    return expected.get("expected_recovery") == "expected_unsupported" and rapid.observed_status == trusted.observed_status == "unsupported"


def _is_expected_unrecoverable(expected: JsonObject, rapid: ObservedItem, trusted: ObservedItem) -> bool:
    return expected.get("expected_recovery") == "must_not_recover" and rapid.observed_status == trusted.observed_status == "not_found"


def _result(
    status: str,
    manifest_path: Path,
    rapid_results_path: Path,
    trusted_results_path: Path,
    diffs: list[DiffEntry],
    errors: list[ManifestValidationError],
) -> TrustedDiffResult:
    counts = _counts(diffs)
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
        "diffs": [_diff_to_dict(diff) for diff in diffs],
        "errors": [{"path": error.path, "message": error.message, "validator": error.validator} for error in errors],
        "summary": {"message": _message(status, counts), "release_evidence_status": "engineering_check_only"},
    }
    return TrustedDiffResult(status=status, ok=status == "PASS", document=document)


def _counts(diffs: list[DiffEntry]) -> JsonObject:
    return {
        "total": len(diffs),
        "match": sum(1 for diff in diffs if diff.category == "MATCH"),
        "rapid_only": sum(1 for diff in diffs if diff.category == "RAPID_ONLY"),
        "trusted_only": sum(1 for diff in diffs if diff.category == "TRUSTED_ONLY"),
        "hash_mismatch": sum(1 for diff in diffs if diff.category == "HASH_MISMATCH"),
        "metadata_mismatch": sum(1 for diff in diffs if diff.category == "METADATA_MISMATCH"),
        "expected_unsupported": sum(1 for diff in diffs if diff.category == "EXPECTED_UNSUPPORTED"),
        "expected_unrecoverable": sum(1 for diff in diffs if diff.category == "EXPECTED_UNRECOVERABLE"),
        "inconclusive": sum(1 for diff in diffs if diff.category == "INCONCLUSIVE"),
        "critical": sum(1 for diff in diffs if diff.severity == "critical"),
    }


def _diff_to_dict(diff: DiffEntry) -> JsonObject:
    return {
        "category": diff.category,
        "severity": diff.severity,
        "item_id": diff.item_id,
        "normalized_path": diff.normalized_path,
        "rapid_status": diff.rapid_status,
        "trusted_status": diff.trusted_status,
        "reviewer_action": diff.reviewer_action,
        "message": diff.message,
    }


def _message(status: str, counts: JsonObject) -> str:
    critical = _int(counts, "critical")
    return "trusted diff passed" if status == "PASS" else f"trusted diff found {critical} critical issue(s)"


def _object(document: JsonObject, field: str) -> JsonObject:
    value: JsonValue | None = document.get(field)
    return value if isinstance(value, dict) else {}


def _list(document: JsonObject, field: str) -> list[JsonValue]:
    value: JsonValue | None = document.get(field)
    return value if isinstance(value, list) else []


def _int(document: JsonObject, field: str) -> int:
    value: JsonValue | None = document.get(field)
    return value if isinstance(value, int) and not isinstance(value, bool) else 0
