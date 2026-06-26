from __future__ import annotations

from dataclasses import dataclass

from rapidtriage.validation.json_fields import int_field
from rapidtriage.validation.known_answer_types import JsonObject


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


def diff_counts(diffs: list[DiffEntry]) -> JsonObject:
    category_pairs = (
        ("match", "MATCH"),
        ("rapid_only", "RAPID_ONLY"),
        ("trusted_only", "TRUSTED_ONLY"),
        ("hash_mismatch", "HASH_MISMATCH"),
        ("metadata_mismatch", "METADATA_MISMATCH"),
        ("expected_unsupported", "EXPECTED_UNSUPPORTED"),
        ("expected_unrecoverable", "EXPECTED_UNRECOVERABLE"),
        ("expected_inconclusive", "EXPECTED_INCONCLUSIVE"),
        ("inconclusive", "INCONCLUSIVE"),
    )
    return {
        "total": len(diffs),
        **{key: sum(1 for diff in diffs if diff.category == category) for key, category in category_pairs},
        "critical": sum(1 for diff in diffs if diff.severity == "critical"),
    }


def diff_entry_to_dict(diff: DiffEntry) -> JsonObject:
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


def diff_message(status: str, counts: JsonObject) -> str:
    critical = int_field(counts, "critical")
    return "trusted diff passed" if status == "PASS" else f"trusted diff found {critical} critical issue(s)"
