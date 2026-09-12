"""Performance commercial-uplift evidence helpers."""

from __future__ import annotations

from collections.abc import Sequence

from .constants import PERFORMANCE_BATCH_ID

__all__ = [
    "performance_commercial_uplift_evidence",
    "performance_reportability_decision",
]


def performance_commercial_uplift_evidence(
    *,
    item_number: int,
    validation_ids: Sequence[str],
    large_data_controls: Sequence[str],
    external_validation: Sequence[str],
) -> dict[str, object]:
    return {
        "batch_id": PERFORMANCE_BATCH_ID,
        "item_numbers": [item_number],
        "implemented": True,
        "usable": True,
        "validated": True,
        "commercial_grade_ready": False,
        "reportability_decision": performance_reportability_decision(
            item_number=item_number,
            external_validation=external_validation,
            large_data_controls=large_data_controls,
        ),
        "passed_validation_check_ids": list(validation_ids),
        "large_data_controls": list(large_data_controls),
        "remaining_external_validation": list(external_validation),
    }


def performance_reportability_decision(
    *,
    item_number: int,
    external_validation: Sequence[str],
    large_data_controls: Sequence[str],
) -> dict[str, object]:
    decisions = {
        68: "do-not-report-incremental-indexing-as-content-hash-complete",
        70: "do-not-report-checkpoint-resume-as-mid-parser-complete",
    }
    allowed_uses = {
        68: "bounded-input-fingerprint-triage-pivot",
        70: "stage-checkpoint-resume-triage-pivot",
    }
    return {
        "profile_version": "run-performance-reportability-decision-v1",
        "commercial_gap_ids": [f"#{item_number}"],
        "decision": decisions.get(item_number, "do-not-report-run-performance-output-as-commercial-complete"),
        "allowed_use": allowed_uses.get(item_number, "run-performance-triage-pivot"),
        "blockers": sorted({str(item) for item in external_validation if str(item)}),
        "control_snapshot": list(large_data_controls),
        "ready_for_court_report": False,
        "required_before_report": [
            "validate content-hash reuse, changed-source behavior, and large-case replay before incremental indexing claims",
            "validate failed-stage and mid-parser resume across long-running corpora before checkpoint/resume claims",
        ],
    }
