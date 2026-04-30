from __future__ import annotations

from typing import Mapping, Sequence


def build_forensic_review(
    *,
    gap_id: str,
    artifact_goal: str,
    primary_evidence: Sequence[str],
    validation_required: bool,
    report_grade_assessment: Mapping[str, object] | None = None,
    commercial_grade_ready: bool = False,
    blockers: Sequence[str] | None = None,
    caveats: Sequence[str] | None = None,
) -> dict[str, object]:
    """Return a compact, consistent review summary for validation-gated artifacts."""
    assessment = report_grade_assessment or {}
    assessment_blockers = assessment.get("blockers") if isinstance(assessment.get("blockers"), list) else []
    all_blockers = sorted({str(item) for item in [*assessment_blockers, *list(blockers or [])] if str(item)})
    report_grade_ready = bool(
        assessment.get("report_grade_ready", assessment.get("ready_for_court_report", commercial_grade_ready))
    )
    return {
        "gap_id": gap_id,
        "artifact_goal": artifact_goal,
        "review_status": "commercial-ready" if commercial_grade_ready else "triage-review",
        "report_grade_ready": report_grade_ready,
        "validation_required": validation_required,
        "primary_evidence": [str(item) for item in primary_evidence if str(item)],
        "blockers": all_blockers,
        "caveats": [str(item) for item in (caveats or []) if str(item)],
        "next_validation_step": str(assessment.get("next_validation_step") or ""),
    }
