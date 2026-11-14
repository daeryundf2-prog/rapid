"""Report candidates: one rule, one count (R8 RI-02).

"보고서 포함 후보" was computed three ways (review counts read a top-level ``include_in_report``
key that bookmarks never carry; the report and manifest read ``review.include_in_report``).
Everything now uses :func:`is_report_candidate` over the merged review payload, and every cap that
leaves candidates out is named in the report (:func:`report_scope_notes`).
"""

from __future__ import annotations

from collections.abc import Mapping


def is_report_candidate(bookmark: object) -> bool:
    """The one rule for "보고서 포함 후보" (R8 RI-02): ``review.include_in_report`` is set.

    Review counts, the case report, the submission manifest and the reviewer bundle all count
    candidates with this predicate over the same merged review payload
    (``api/app/review_payload.load_run_review_payload``)."""
    if not isinstance(bookmark, Mapping):
        return False
    review = bookmark.get("review")
    return isinstance(review, Mapping) and bool(review.get("include_in_report"))


def report_scope_notes(case_payload: Mapping[str, object], submission_manifest: Mapping[str, object]) -> list[str]:
    """Report lines naming every cap that left candidates out (never dropped silently)."""
    notes: list[str] = []
    scope = case_payload.get("review_scope")
    if isinstance(scope, Mapping):
        if scope.get("case_db_marks_truncated"):
            total = scope.get("case_db_marks_total")
            limit = scope.get("case_db_mark_limit")
            notes.append(f"- 주의: 케이스 DB 표시 {total}건 중 최근 {limit}건만 반영함(상한).")
        if scope.get("case_db_error"):
            notes.append(f"- 주의: 케이스 DB를 읽지 못해 콘솔 표시가 반영되지 않음({scope.get('case_db_error')}).")
    manifest_summary = submission_manifest.get("summary")
    if isinstance(manifest_summary, Mapping) and int(manifest_summary.get("max_items_skipped_count") or 0) > 0:
        candidates = manifest_summary.get("report_candidate_count")
        options = submission_manifest.get("options")
        max_items = options.get("max_items") if isinstance(options, Mapping) else None
        notes.append(
            f"- 주의: 보고서 포함 후보 {candidates}건 중 {max_items}건만 해시 산출함(상한, "
            f"제외 {manifest_summary.get('max_items_skipped_count')}건은 해시 산출 제외 목록에 '최대 항목 수 초과'로 표기)."
        )
    return notes
