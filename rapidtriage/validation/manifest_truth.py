from __future__ import annotations

from dataclasses import dataclass

from rapidtriage.validation.known_answer_types import JsonObject, JsonValue
from rapidtriage.validation.observed_results import ObservedItem


@dataclass(frozen=True, slots=True)
class ExpectedTruthIssue:
    category: str
    severity: str
    reviewer_action: str
    message: str


def expected_truth_issue(
    rapid_item: ObservedItem,
    trusted_item: ObservedItem,
    expected_item: JsonObject,
) -> ExpectedTruthIssue | None:
    expected_recovery = _string_or_none(expected_item, "expected_recovery")
    if expected_recovery != "must_recover_byte_exact":
        return None

    expected_sha256 = _string_or_none(expected_item, "sha256")
    if expected_sha256 is not None and (rapid_item.sha256 != expected_sha256 or trusted_item.sha256 != expected_sha256):
        return _issue("HASH_MISMATCH", "observed sha256 differs from manifest truth")

    expected_size = _int_or_none(expected_item, "size_bytes")
    if expected_size is not None and (rapid_item.size_bytes != expected_size or trusted_item.size_bytes != expected_size):
        return _issue("METADATA_MISMATCH", "observed size differs from manifest truth")

    expected_mode = _string_or_none(expected_item, "expected_recovery_mode")
    if expected_mode is not None and (rapid_item.recovery_mode != expected_mode or trusted_item.recovery_mode != expected_mode):
        return _issue("METADATA_MISMATCH", "observed recovery mode differs from manifest truth")

    if rapid_item.observed_status != "recovered" or trusted_item.observed_status != "recovered":
        return _issue("METADATA_MISMATCH", "observed status differs from byte-exact manifest truth")

    return None


def _issue(category: str, message: str) -> ExpectedTruthIssue:
    return ExpectedTruthIssue(
        category=category,
        severity="critical",
        reviewer_action="review_required",
        message=message,
    )


def _string_or_none(document: JsonObject, field: str) -> str | None:
    value: JsonValue | None = document.get(field)
    return value if isinstance(value, str) else None


def _int_or_none(document: JsonObject, field: str) -> int | None:
    value: JsonValue | None = document.get(field)
    return value if isinstance(value, int) and not isinstance(value, bool) else None
