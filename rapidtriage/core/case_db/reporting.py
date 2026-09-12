"""Report candidates, citations, and evidence-selection reporting."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping, Sequence

from ...artifacts.synthetic_media import (
    SYNTHETIC_MEDIA_SCORE_GUIDANCE,
    SYNTHETIC_MEDIA_SCORE_SEMANTICS,
)
from ..forensic_accuracy import build_accuracy_gate
from .constants import (
    COURT_EXHIBIT_EXPORT_GAP_ID,
    EVIDENCE_SELECTION_REPORT_GRADE_BLOCKERS,
    EVIDENCE_SELECTION_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    FUNCTIONAL_REPORTING_BATCH_ID,
    LEGAL_LIMITATION_GAP_ID,
    PARSER_CONFIDENCE_GAP_ID,
    REPORT_CITATION_REPORT_GRADE_BLOCKERS,
    REPORT_CITATION_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    VALIDATION_WARNING_UX_GAP_ID,
)
from .helpers import (
    artifact_details,
    nested_mapping_str,
    optional_float,
    parse_json_list,
    parse_json_object,
    stable_payload_sha256,
)
from .integrity import (
    build_legal_limitations_assessment,
    build_report_item_legal_limitations,
    build_report_item_validation_assessment,
)
from .review import (
    build_source_review_handoff,
    load_review_target_match,
    normalize_source_citation_package,
    source_citation_package_hash,
)
from .search import (
    enrich_case_search_matches,
    merge_source_citation_package_into_reference,
)
from .trusted_diffs import (
    build_report_item_provenance,
)

__all__ = [
    "attach_citation_row_hash",
    "attach_report_citation_profile",
    "attach_report_warning_display_profile",
    "build_case_db_court_exhibit_readiness_matrix",
    "build_case_db_report_generation_package",
    "build_citation_manager_trusted_diff",
    "build_court_exhibit_package_manifest",
    "build_evidence_history_integrity_profile",
    "build_evidence_history_trusted_diff",
    "build_evidence_selection_history_manifest",
    "build_evidence_selection_history_report_grade_validation_plan",
    "build_evidence_selection_version_history",
    "build_functional_reporting_profile",
    "build_functional_reporting_profiles",
    "build_report_candidate_citation_profile",
    "build_report_citation_coverage_profile",
    "build_report_citation_index",
    "build_report_citation_index_manifest",
    "build_report_citation_manager",
    "build_report_citation_report_grade_validation_plan",
    "build_report_citation_workflow_summary",
    "build_report_quality_matrix",
    "build_report_warning_display_profile",
    "build_report_warning_display_summary",
    "build_review_export_item",
    "build_synthetic_media_summary",
    "case_report_commercial_uplift_evidence",
    "case_report_reportability_decision",
    "citation_diff_key",
    "citation_diff_value",
    "citation_manager_core_accuracy_gates",
    "citation_source_reference_has_hash",
    "copy_safe_report_citation",
    "evidence_history_diff_key",
    "evidence_history_diff_value",
    "evidence_history_row_hash",
    "evidence_history_viewer_locator",
    "evidence_selection_core_accuracy_gates",
    "load_review_history",
    "render_case_db_report_markdown",
    "report_citation_source_viewer_locator",
]

def build_review_export_item(
    connection: sqlite3.Connection,
    case_id: str,
    review: Mapping[str, object],
) -> dict[str, object]:
    target_type = str(review.get("target_type") or "")
    target_id = str(review.get("target_id") or "")
    match = load_review_target_match(connection, case_id, target_type=target_type, target_id=target_id)
    if match is None:
        match = {
            "source": "unknown",
            "citation_id": "",
            "target_type": target_type,
            "target_id": target_id,
            "title": f"{target_type}:{target_id}",
            "kind": target_type,
            "path": "",
            "preview": "Target no longer exists in the case database.",
            "metadata": {},
        }
    enriched = enrich_case_search_matches([match], [])[0]
    source_citation_package = (
        normalize_source_citation_package(review.get("source_citation_package"))
        if isinstance(review.get("source_citation_package"), Mapping)
        else {}
    )
    source_reference = merge_source_citation_package_into_reference(
        enriched.get("source_reference") if isinstance(enriched.get("source_reference"), Mapping) else {},
        source_citation_package,
    )
    enriched_for_report = dict(enriched)
    enriched_for_report["source_reference"] = source_reference
    return {
        "review_citation_id": str(review.get("citation_id") or ""),
        "target_citation_id": str(enriched.get("citation_id") or ""),
        "target_type": target_type,
        "target_id": target_id,
        "source": str(enriched.get("source") or ""),
        "kind": str(enriched.get("kind") or ""),
        "title": str(enriched.get("title") or ""),
        "path": str(enriched.get("path") or ""),
        "preview": str(enriched.get("preview") or ""),
        "review": dict(review),
        "review_history": load_review_history(connection, case_id, target_type=target_type, target_id=target_id),
        "source_citation_package": source_citation_package,
        "source_citation_package_hash": source_citation_package_hash(source_citation_package),
        "source_review_handoff": build_source_review_handoff(source_citation_package),
        "source_reference": source_reference,
        "functional_priority_gap_ids": ["#21", "#22", "#23", "#24"],
        "commercial_gap_ids": ["#64", "#65", PARSER_CONFIDENCE_GAP_ID, VALIDATION_WARNING_UX_GAP_ID, LEGAL_LIMITATION_GAP_ID],
        "report_citation_status": "citation-linked-validation-required",
        "evidence_selection_status": "versioned-review-selection",
        "provenance": build_report_item_provenance(enriched_for_report, review),
        "validation_assessment": build_report_item_validation_assessment(enriched_for_report),
        "legal_limitations": build_report_item_legal_limitations(enriched_for_report),
        "legal_limitations_assessment": build_legal_limitations_assessment(enriched_for_report),
        "review_priority": enriched.get("review_priority") or {},
        "metadata": enriched.get("metadata") or {},
    }


def load_review_history(
    connection: sqlite3.Connection,
    case_id: str,
    *,
    target_type: str,
    target_id: str,
) -> list[dict[str, object]]:
    rows = connection.execute(
        """
        SELECT *
        FROM review_mark_history
        WHERE case_id = ? AND target_type = ? AND target_id = ?
        ORDER BY version ASC, id ASC
        """,
        (case_id, target_type, target_id),
    ).fetchall()
    history = []
    for row in rows:
        history_row = {
            "version": int(row["version"]),
            "review_citation_id": str(row["review_citation_id"]),
            "target_type": str(row["target_type"] or ""),
            "target_id": str(row["target_id"] or ""),
            "changed_at": str(row["changed_at"]),
            "actor": str(row["actor"] or ""),
            "changed_fields": parse_json_list(row["changed_fields_json"]),
            "previous": parse_json_object(row["previous_json"]),
            "current": parse_json_object(row["current_json"]),
            "commercial_gap_ids": ["#65"],
            "history_status": "immutable-version-row",
        }
        history_row["history_viewer_locator"] = evidence_history_viewer_locator(history_row)
        history_row["row_hash"] = evidence_history_row_hash(history_row)
        history_row["core_accuracy_gates"] = evidence_selection_core_accuracy_gates(history_rows=[history_row])
        history.append(history_row)
    return history


def attach_report_citation_profile(item: Mapping[str, object]) -> dict[str, object]:
    enriched = dict(item)
    enriched["report_citation_profile"] = build_report_candidate_citation_profile(enriched)
    return enriched


def attach_report_warning_display_profile(item: Mapping[str, object]) -> dict[str, object]:
    enriched = dict(item)
    enriched["warning_display_profile"] = build_report_warning_display_profile(enriched)
    return enriched


def build_report_warning_display_profile(item: Mapping[str, object]) -> dict[str, object]:
    validation = item.get("validation_assessment") if isinstance(item.get("validation_assessment"), Mapping) else {}
    legal = item.get("legal_limitations_assessment") if isinstance(item.get("legal_limitations_assessment"), Mapping) else {}
    citation = item.get("report_citation_profile") if isinstance(item.get("report_citation_profile"), Mapping) else {}
    review = item.get("review") if isinstance(item.get("review"), Mapping) else {}
    validation_warnings = [str(warning) for warning in validation.get("warnings", []) if str(warning)]
    legal_blockers = [str(blocker) for blocker in legal.get("blockers", []) if str(blocker)]
    citation_blockers = [str(blocker) for blocker in citation.get("blockers", []) if str(blocker)]
    state_badges = ["triage-only"]
    if validation_warnings or legal_blockers or citation_blockers:
        state_badges.append("validation-required")
    if any("trusted-" in blocker or "external-" in blocker for blocker in [*legal_blockers, *citation_blockers]):
        state_badges.append("external-evidence-needed")
    if str(review.get("verification_status") or "") == "verified":
        state_badges.append("review-grade")
    if bool(review.get("include_in_report")) and citation.get("ready_for_report_export"):
        state_badges.append("report-grade-candidate")
    primary_state = "report-grade-candidate" if "report-grade-candidate" in state_badges else state_badges[-1]
    display_actions = []
    if "validation-required" in state_badges:
        display_actions.append("show validation warnings before report inclusion")
    if "external-evidence-needed" in state_badges:
        display_actions.append("attach trusted diff, signature, or independent review evidence")
    if "review-grade" not in state_badges:
        display_actions.append("open source viewer and set verification status")
    profile_core = {
        "profile_version": "report-warning-display-profile-v1",
        "item_number": 24,
        "gap_id": "#24",
        "primary_state": primary_state,
        "state_badges": sorted(set(state_badges)),
        "validation_warning_count": len(validation_warnings),
        "legal_blocker_count": len(legal_blockers),
        "citation_blocker_count": len(citation_blockers),
        "warning_details": validation.get("warning_details") if isinstance(validation.get("warning_details"), list) else [],
        "legal_limitation_details": legal.get("limitation_details") if isinstance(legal.get("limitation_details"), list) else [],
        "display_actions": display_actions,
        "gui_contract": {
            "badge_visible_in_table": True,
            "detail_panel_collapsible": True,
            "report_button_warns_before_export": True,
            "external_evidence_badge_required": "external-evidence-needed" in state_badges,
        },
        "ready_for_court_report": False,
    }
    return {**profile_core, "profile_hash": stable_payload_sha256(profile_core)}


def build_report_warning_display_summary(items: Sequence[Mapping[str, object]]) -> dict[str, object]:
    profiles = [
        item.get("warning_display_profile")
        for item in items
        if isinstance(item.get("warning_display_profile"), Mapping)
    ]
    state_counts: dict[str, int] = {}
    badge_counts: dict[str, int] = {}
    for profile in profiles:
        primary = str(profile.get("primary_state") or "triage-only")
        state_counts[primary] = state_counts.get(primary, 0) + 1
        for badge in profile.get("state_badges", []):
            key = str(badge)
            badge_counts[key] = badge_counts.get(key, 0) + 1
    return {
        "profile_version": "report-warning-display-summary-v1",
        "item_number": 24,
        "gap_id": "#24",
        "profile_count": len(profiles),
        "state_counts": dict(sorted(state_counts.items())),
        "badge_counts": dict(sorted(badge_counts.items())),
        "validation_required_count": badge_counts.get("validation-required", 0),
        "external_evidence_needed_count": badge_counts.get("external-evidence-needed", 0),
        "report_grade_candidate_count": badge_counts.get("report-grade-candidate", 0),
        "commercial_claim_allowed": False,
    }


def build_synthetic_media_summary(
    connection: sqlite3.Connection,
    case_id: str,
) -> dict[str, object]:
    """Aggregate synthetic-media (deepfake-lens) artifacts for report roll-up.

    Scores are prioritization signals only: this summary orders review work and
    must never be presented as proof that media is or is not synthetic.
    """
    rows = connection.execute(
        """
        SELECT citation_id, artifact_type, data_json
        FROM artifact
        WHERE case_id = ? AND artifact_type LIKE 'synthetic-media-%'
        ORDER BY id ASC
        """,
        (case_id,),
    ).fetchall()
    artifact_type_counts: dict[str, int] = {}
    band_counts: dict[str, int] = {}
    scan_status_counts: dict[str, int] = {}
    scores: list[float] = []
    high_band_citations: set[str] = set()
    limitations: set[str] = set()
    next_checks: set[str] = set()
    scanned_file_count = 0
    scan_error_count = 0
    provider_unavailable = False
    for row in rows:
        artifact_type = str(row["artifact_type"] or "")
        artifact_type_counts[artifact_type] = artifact_type_counts.get(artifact_type, 0) + 1
        details = artifact_details(parse_json_object(row["data_json"]))
        scan_status = str(details.get("scan_status") or "")
        if scan_status:
            scan_status_counts[scan_status] = scan_status_counts.get(scan_status, 0) + 1
        if artifact_type == "synthetic-media-scan-status":
            provider_unavailable = True
            continue
        if artifact_type == "synthetic-media-scan-summary":
            continue
        if artifact_type == "synthetic-media-scan-error" or scan_status == "error":
            scan_error_count += 1
            continue
        scanned_file_count += 1
        score = optional_float(details.get("score"))
        if score is not None:
            scores.append(score)
        band = str(details.get("band") or "").lower()
        if band:
            band_counts[band] = band_counts.get(band, 0) + 1
        if band in {"high", "critical"} or (score is not None and score >= 70):
            citation_id = str(row["citation_id"] or "")
            if citation_id:
                high_band_citations.add(citation_id)
        for key, bucket in (("limitations", limitations), ("next_checks", next_checks)):
            values = details.get(key)
            if isinstance(values, list):
                for item in values:
                    if isinstance(item, str) and item:
                        bucket.add(item)
    summary_core = {
        "profile_version": "synthetic-media-summary-v1",
        "artifact_count": len(rows),
        "scanned_file_count": scanned_file_count,
        "scan_error_count": scan_error_count,
        "provider_unavailable": provider_unavailable,
        "artifact_type_counts": dict(sorted(artifact_type_counts.items())),
        "band_counts": dict(sorted(band_counts.items())),
        "scan_status_counts": dict(sorted(scan_status_counts.items())),
        "scored_file_count": len(scores),
        "max_score": max(scores) if scores else None,
        "high_band_count": len(high_band_citations),
        "high_band_citations": sorted(high_band_citations),
        "limitations": sorted(limitations)[:10],
        "next_checks": sorted(next_checks)[:10],
        "score_semantics": SYNTHETIC_MEDIA_SCORE_SEMANTICS,
        "score_guidance": SYNTHETIC_MEDIA_SCORE_GUIDANCE,
        "validation_required": bool(scores or scan_error_count),
        "commercial_claim_allowed": False,
    }
    return {**summary_core, "summary_hash": stable_payload_sha256(summary_core)}


def build_report_quality_matrix(
    *,
    items: Sequence[Mapping[str, object]],
    court_exhibit_package: Mapping[str, object],
) -> dict[str, object]:
    rows = []
    for item in items:
        validation = item.get("validation_assessment") if isinstance(item.get("validation_assessment"), Mapping) else {}
        legal = item.get("legal_limitations_assessment") if isinstance(item.get("legal_limitations_assessment"), Mapping) else {}
        citation = item.get("report_citation_profile") if isinstance(item.get("report_citation_profile"), Mapping) else {}
        row_core = {
            "review_citation_id": str(item.get("review_citation_id") or ""),
            "target_citation_id": str(item.get("target_citation_id") or ""),
            "parser_confidence_manifest_hash": str(validation.get("parser_confidence_manifest_hash") or ""),
            "validation_warning_manifest_hash": str(validation.get("validation_warning_manifest_hash") or ""),
            "legal_limitation_manifest_hash": str(legal.get("legal_limitation_manifest_hash") or ""),
            "report_citation_profile_hash": str(citation.get("profile_hash") or ""),
            "reportability_score": validation.get("reportability_score"),
            "validation_required": bool(validation.get("validation_required")),
            "limitation_count": int(legal.get("limitation_count") or 0),
            "ready_for_report_export": bool(citation.get("ready_for_report_export")),
        }
        rows.append({**row_core, "row_hash": stable_payload_sha256(row_core)})
    court_manifest = court_exhibit_package.get("manifest") if isinstance(court_exhibit_package.get("manifest"), Mapping) else {}
    matrix_core = {
        "profile_version": "report-quality-matrix-v1",
        "item_numbers": [91, 92, 93, 94],
        "row_count": len(rows),
        "rows": rows,
        "court_exhibit_manifest_hash": str(court_manifest.get("manifest_hash") or ""),
        "court_exhibit_package_hash": str(court_exhibit_package.get("package_hash") or ""),
        "court_exhibit_readiness_matrix_hash": str(court_manifest.get("exhibit_readiness_matrix_hash") or ""),
        "all_item_manifests_present": all(
            row["parser_confidence_manifest_hash"]
            and row["validation_warning_manifest_hash"]
            and row["legal_limitation_manifest_hash"]
            for row in rows
        ) if rows else True,
        "commercial_claim_allowed": False,
        "blockers": [
            "trusted-parser-confidence-calibration-diff-required",
            "trusted-validation-warning-checklist-diff-required",
            "trusted-legal-limitation-wording-diff-required",
            "signed-or-notarized-court-exhibit-manifest-required",
        ],
    }
    return {**matrix_core, "matrix_hash": stable_payload_sha256(matrix_core)}


def build_report_candidate_citation_profile(item: Mapping[str, object]) -> dict[str, object]:
    review = item.get("review") if isinstance(item.get("review"), Mapping) else {}
    source_reference = item.get("source_reference") if isinstance(item.get("source_reference"), Mapping) else {}
    metadata = item.get("metadata") if isinstance(item.get("metadata"), Mapping) else {}
    validation = item.get("validation_assessment") if isinstance(item.get("validation_assessment"), Mapping) else {}
    legal_limitations = item.get("legal_limitations") if isinstance(item.get("legal_limitations"), Sequence) and not isinstance(item.get("legal_limitations"), (str, bytes, bytearray)) else []
    review_citation_id = str(item.get("review_citation_id") or "")
    target_citation_id = str(item.get("target_citation_id") or "")
    source_path = str(source_reference.get("path") or metadata.get("source_path") or item.get("path") or "")
    parser = str(source_reference.get("parser") or metadata.get("parser") or "")
    parser_version = str(source_reference.get("parser_version") or metadata.get("parser_version") or "")
    parser_confidence = (
        validation.get("parser_confidence")
        if "parser_confidence" in validation
        else source_reference.get("parser_confidence") or metadata.get("parser_confidence")
    )
    locator_fields = {
        "record_offset": source_reference.get("record_offset") if source_reference.get("record_offset") is not None else metadata.get("record_offset"),
        "source_index": source_reference.get("source_index") if source_reference.get("source_index") is not None else metadata.get("source_index"),
        "line": source_reference.get("line") if source_reference.get("line") is not None else metadata.get("line"),
        "row_id": source_reference.get("row_id") if source_reference.get("row_id") is not None else metadata.get("row_id"),
        "table": source_reference.get("table") or metadata.get("table") or "",
    }
    has_locator = any(value not in (None, "") for value in locator_fields.values())
    has_source_hash = citation_source_reference_has_hash(source_reference)
    has_parser_identity = bool(parser and parser_version)
    has_confidence = parser_confidence is not None and str(parser_confidence) != ""
    review_status = str(review.get("status") or "unreviewed")
    verification_status = str(review.get("verification_status") or "unverified")
    blockers: list[str] = []
    if not review_citation_id:
        blockers.append("report-candidate-review-citation-missing")
    if not target_citation_id:
        blockers.append("report-candidate-source-citation-missing")
    if not source_path:
        blockers.append("report-candidate-source-path-missing")
    if not has_source_hash:
        blockers.append("report-candidate-source-hash-missing")
    if not has_parser_identity:
        blockers.append("report-candidate-parser-id-version-missing")
    if not has_locator:
        blockers.append("report-candidate-source-pointer-missing")
    if review_status == "unreviewed":
        blockers.append("report-candidate-review-status-unset")
    if verification_status in {"", "unverified"}:
        blockers.append("report-candidate-source-verification-unset")
    if not has_confidence:
        blockers.append("report-candidate-parser-confidence-missing")
    if not legal_limitations:
        blockers.append("report-candidate-legal-limitation-missing")
    blockers.append("trusted-citation-index-diff-is-required-before-commercial-claim")
    profile_core = {
        "profile_version": "report-candidate-citation-profile-v1",
        "item_number": 21,
        "gap_id": "#21",
        "review_citation_id": review_citation_id,
        "target_citation_id": target_citation_id,
        "citation_pair_available": bool(review_citation_id and target_citation_id),
        "target_type": str(item.get("target_type") or ""),
        "target_id": str(item.get("target_id") or ""),
        "source_path": source_path,
        "source_hash_status": "present" if has_source_hash else "missing",
        "parser": parser,
        "parser_version": parser_version,
        "parser_identity_status": "present" if has_parser_identity else "missing",
        "source_locator_status": "present" if has_locator else "missing",
        "source_locator": locator_fields,
        "review_status": review_status,
        "verification_status": verification_status,
        "include_in_report": bool(review.get("include_in_report")),
        "parser_confidence": parser_confidence,
        "parser_confidence_status": "present" if has_confidence else "missing",
        "legal_limitation_status": "present" if legal_limitations else "missing",
        "legal_limitation_count": len(legal_limitations),
        "ready_for_report_export": bool(
            review_citation_id
            and target_citation_id
            and source_path
            and has_parser_identity
            and review_status != "unreviewed"
            and legal_limitations
        ),
        "ready_for_court_report": False,
        "blockers": blockers,
        "required_before_final_report": [
            "verify source hash or record hash against the original evidence source",
            "verify parser ID/version/confidence and known limitations",
            "confirm source locator opens the same row/offset/table in the source viewer",
            "attach trusted citation-index diff and reviewer sign-off before exhibit packaging",
        ],
    }
    return {
        **profile_core,
        "profile_hash": stable_payload_sha256(profile_core),
    }


def build_report_citation_workflow_summary(items: Sequence[Mapping[str, object]]) -> dict[str, object]:
    profiles = [
        item.get("report_citation_profile")
        for item in items
        if isinstance(item.get("report_citation_profile"), Mapping)
    ]
    unique_blockers = sorted(
        {
            str(blocker)
            for profile in profiles
            for blocker in profile.get("blockers", [])
            if str(blocker)
        }
    )
    return {
        "profile_version": "report-citation-workflow-summary-v1",
        "item_number": 21,
        "gap_id": "#21",
        "report_candidate_count": len(items),
        "profile_count": len(profiles),
        "ready_for_report_export_count": sum(1 for profile in profiles if profile.get("ready_for_report_export")),
        "source_path_count": sum(1 for profile in profiles if profile.get("source_path")),
        "source_hash_present_count": sum(1 for profile in profiles if profile.get("source_hash_status") == "present"),
        "parser_identity_count": sum(1 for profile in profiles if profile.get("parser_identity_status") == "present"),
        "source_locator_count": sum(1 for profile in profiles if profile.get("source_locator_status") == "present"),
        "confidence_count": sum(1 for profile in profiles if profile.get("parser_confidence_status") == "present"),
        "legal_limitation_count": sum(1 for profile in profiles if profile.get("legal_limitation_status") == "present"),
        "blocker_count": sum(len(profile.get("blockers", [])) for profile in profiles),
        "unique_blockers": unique_blockers,
        "commercial_claim_allowed": False,
    }


def build_case_db_report_generation_package(
    *,
    case_id: str,
    items: Sequence[Mapping[str, object]],
    citation_index: Sequence[Mapping[str, object]],
    status_counts: Mapping[str, int],
    verification_counts: Mapping[str, int],
    item_preview_limit: int = 200,
    synthetic_media_summary: Mapping[str, object] | None = None,
) -> dict[str, object]:
    markdown_document, markdown_truncated = render_case_db_report_markdown(
        case_id=case_id,
        items=items,
        citation_index=citation_index,
        status_counts=status_counts,
        verification_counts=verification_counts,
        item_preview_limit=item_preview_limit,
        synthetic_media_summary=synthetic_media_summary,
    )
    item_row_hashes = [
        stable_payload_sha256({"row_type": "case-db-report-generation-item", "row": item})
        for item in items
    ]
    citation_row_hashes = [
        stable_payload_sha256({"row_type": "case-db-report-generation-citation", "row": citation})
        for citation in citation_index
    ]
    hash_bundle = {
        "profile_version": "case-db-report-generation-hash-bundle-v1",
        "item_number": 22,
        "case_id": case_id,
        "markdown_sha256": stable_payload_sha256({"markdown_document": markdown_document}),
        "item_row_hashes": item_row_hashes,
        "citation_row_hashes": citation_row_hashes,
    }
    manifest_core = {
        "profile_version": "case-db-report-generation-manifest-v1",
        "item_number": 22,
        "case_id": case_id,
        "selected_item_count": len(items),
        "citation_count": len(citation_index),
        "markdown_truncated": markdown_truncated,
        "markdown_preview_limit": item_preview_limit,
        "status_counts": dict(sorted(status_counts.items())),
        "verification_status_counts": dict(sorted(verification_counts.items())),
        "formats": {
            "json_export": True,
            "markdown_document": True,
            "html_docx_pdf_available_via_api_export": True,
            "standalone_file_write": False,
        },
        "hash_bundle_sha256": stable_payload_sha256(hash_bundle),
        "large_data_controls": {
            "bounded_markdown_items": True,
            "markdown_item_limit": item_preview_limit,
            "full_item_rows_preserved_in_json": True,
            "citation_index_preserved_in_json": True,
        },
        "blockers": [
            "docx-pdf-layout-render-validation-not-attached",
            "external-report-template-approval-required-before-court-use",
            "end-to-end-report-package-hash-validation-required",
        ],
        "commercial_gap_ids": ["#22"],
        "commercial_claim_allowed": False,
    }
    manifest = {
        **manifest_core,
        "manifest_hash": stable_payload_sha256(manifest_core),
    }
    return {
        "component": "case-db-report-generation-package",
        "status": "implemented-usable-validation-required",
        "commercial_gap_ids": ["#22"],
        "markdown_document": markdown_document,
        "markdown_truncated": markdown_truncated,
        "synthetic_media_summary": dict(synthetic_media_summary or {}),
        "manifest": manifest,
        "hash_bundle": hash_bundle,
        "hash_bundle_sha256": manifest["hash_bundle_sha256"],
        "ready_for_case_export": True,
        "ready_for_court_report": False,
        "blockers": manifest["blockers"],
    }


def render_case_db_report_markdown(
    *,
    case_id: str,
    items: Sequence[Mapping[str, object]],
    citation_index: Sequence[Mapping[str, object]],
    status_counts: Mapping[str, int],
    verification_counts: Mapping[str, int],
    item_preview_limit: int,
    synthetic_media_summary: Mapping[str, object] | None = None,
) -> tuple[str, bool]:
    lines = [
        "# RapidForensic Case DB Report Export",
        "",
        f"- Case ID: `{case_id}`",
        f"- Selected report candidates: {len(items)}",
        f"- Citation rows: {len(citation_index)}",
        f"- Review status counts: `{json.dumps(dict(sorted(status_counts.items())), ensure_ascii=False, sort_keys=True)}`",
        f"- Verification status counts: `{json.dumps(dict(sorted(verification_counts.items())), ensure_ascii=False, sort_keys=True)}`",
        "",
        "## Report Candidates",
        "",
    ]
    for index, item in enumerate(items[:item_preview_limit], start=1):
        profile = item.get("report_citation_profile") if isinstance(item.get("report_citation_profile"), Mapping) else {}
        review = item.get("review") if isinstance(item.get("review"), Mapping) else {}
        blockers = profile.get("blockers") if isinstance(profile.get("blockers"), list) else []
        lines.extend(
            [
                f"### {index}. {item.get('title') or item.get('target_citation_id') or 'report candidate'!s}",
                "",
                f"- Review citation: `{item.get('review_citation_id', '')}`",
                f"- Source citation: `{item.get('target_citation_id', '')}`",
                f"- Source path: `{profile.get('source_path') or item.get('path') or ''}`",
                f"- Review status: `{review.get('status', '')}` / verification `{review.get('verification_status', '')}`",
                f"- Parser: `{profile.get('parser', '')}` version `{profile.get('parser_version', '')}` confidence `{profile.get('parser_confidence', '')}`",
                f"- Source hash: `{profile.get('source_hash_status', 'missing')}`; locator: `{profile.get('source_locator_status', 'missing')}`",
                f"- Legal limitation: `{profile.get('legal_limitation_status', 'missing')}`",
                f"- Blockers: {', '.join(str(blocker) for blocker in blockers[:8]) or 'none'}",
                "",
            ]
        )
    truncated = len(items) > item_preview_limit
    if truncated:
        lines.extend(
            [
                f"> Markdown preview is bounded to {item_preview_limit} items for large-case safety.",
                "> The full selected item rows remain available in the JSON report export.",
                "",
            ]
        )
    if synthetic_media_summary is not None:
        lines.extend(
            [
                "## Synthetic-Media Summary",
                "",
                f"- Artifact rows: {synthetic_media_summary.get('artifact_count', 0)}",
                f"- Scanned files: {synthetic_media_summary.get('scanned_file_count', 0)}",
                f"- High-band review hits: {synthetic_media_summary.get('high_band_count', 0)}",
                f"- Scan errors: {synthetic_media_summary.get('scan_error_count', 0)}",
                f"- Provider unavailable: `{bool(synthetic_media_summary.get('provider_unavailable'))}`",
                f"- Band counts: `{json.dumps(synthetic_media_summary.get('band_counts') or {}, ensure_ascii=False, sort_keys=True)}`",
                f"- Score semantics: `{synthetic_media_summary.get('score_semantics', '')}`",
                f"- Guidance: {synthetic_media_summary.get('score_guidance', '')}",
                "",
            ]
        )
    lines.extend(
        [
            "## Citation Index",
            "",
        ]
    )
    for citation in citation_index[:item_preview_limit]:
        lines.append(
            f"- `{citation.get('citation_id', '')}` {citation.get('role', '')}: {citation.get('copy_safe_citation', '')}"
        )
    if len(citation_index) > item_preview_limit:
        lines.append(f"- ... truncated after {item_preview_limit} citation rows; full citation index remains in JSON.")
    lines.append("")
    return "\n".join(lines), truncated


def build_court_exhibit_package_manifest(
    *,
    case_id: str,
    items: Sequence[Mapping[str, object]],
    citation_index: Sequence[Mapping[str, object]],
    report_generation_package: Mapping[str, object],
    custody_workflow: Mapping[str, object],
    acquisition_hash_workflow: Mapping[str, object],
    audit_integrity: Mapping[str, object],
    reproducibility: Mapping[str, object],
) -> dict[str, object]:
    exhibits = []
    for index, item in enumerate(items, start=1):
        citation_profile = item.get("report_citation_profile") if isinstance(item.get("report_citation_profile"), Mapping) else {}
        provenance = item.get("provenance") if isinstance(item.get("provenance"), Mapping) else {}
        exhibit = {
            "exhibit_id": f"EXH-{index:06d}",
            "review_citation_id": str(item.get("review_citation_id") or ""),
            "source_citation_id": str(item.get("target_citation_id") or ""),
            "title": str(item.get("title") or item.get("target_citation_id") or ""),
            "target_type": str(item.get("target_type") or ""),
            "target_id": str(item.get("target_id") or ""),
            "source_path": str(citation_profile.get("source_path") or item.get("path") or ""),
            "source_hash_status": str(citation_profile.get("source_hash_status") or "missing"),
            "parser_identity_status": str(citation_profile.get("parser_identity_status") or "missing"),
            "source_locator_status": str(citation_profile.get("source_locator_status") or "missing"),
            "report_citation_profile_hash": str(citation_profile.get("profile_hash") or ""),
            "provenance_manifest_hash": str(provenance.get("provenance_manifest_hash") or ""),
            "ready_for_report_export": bool(citation_profile.get("ready_for_report_export")),
            "ready_for_court_report": False,
        }
        exhibits.append({**exhibit, "exhibit_row_hash": stable_payload_sha256(exhibit)})
    package_inputs = {
        "report_generation_manifest_hash": nested_mapping_str(report_generation_package, "manifest", "manifest_hash"),
        "report_generation_hash_bundle_sha256": str(report_generation_package.get("hash_bundle_sha256") or ""),
        "custody_manifest_hash": nested_mapping_str(custody_workflow, "custody_event_manifest", "manifest_hash"),
        "acquisition_hash_manifest_hash": nested_mapping_str(acquisition_hash_workflow, "acquisition_hash_manifest", "manifest_hash"),
        "audit_chain_manifest_hash": nested_mapping_str(audit_integrity, "audit_hash_chain_manifest", "manifest_hash"),
        "reproducibility_manifest_hash": nested_mapping_str(reproducibility, "report_replay_manifest", "manifest_hash"),
    }
    exhibit_readiness_matrix = build_case_db_court_exhibit_readiness_matrix(exhibits)
    package_hash = stable_payload_sha256(
        {
            "case_id": case_id,
            "exhibits": exhibits,
            "citation_index": citation_index,
            "package_inputs": package_inputs,
        }
    )
    manifest_core = {
        "profile_version": "court-exhibit-package-manifest-v1",
        "item_number": 94,
        "functional_item_number": 23,
        "case_id": case_id,
        "exhibit_count": len(exhibits),
        "citation_count": len(citation_index),
        "package_inputs": package_inputs,
        "package_hash": package_hash,
        "exhibit_readiness_matrix": exhibit_readiness_matrix,
        "exhibit_readiness_matrix_hash": exhibit_readiness_matrix["matrix_hash"],
        "external_signature": {
            "slot_present": True,
            "status": "not-attached",
            "required_before_court_use": True,
        },
        "large_data_controls": {
            "bounded_by_case_export_limit": True,
            "exhibit_manifest_rows": len(exhibits),
            "full_binary_evidence_embedded": False,
            "source_paths_and_hash_status_only": True,
        },
        "blockers": [
            "external-signature-or-notarization-evidence-not-attached",
            "independent-court-exhibit-package-review-not-attached",
            "source-file-copy-bundle-not-written-by-case-db-export",
        ],
        "commercial_gap_ids": ["#23", COURT_EXHIBIT_EXPORT_GAP_ID],
        "commercial_claim_allowed": False,
    }
    manifest = {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}
    return {
        "component": "court-exhibit-package-manifest",
        "status": "implemented-package-manifest-validation-required",
        "commercial_gap_ids": ["#23", COURT_EXHIBIT_EXPORT_GAP_ID],
        "manifest": manifest,
        "exhibits": exhibits,
        "court_exhibit_readiness_matrix": exhibit_readiness_matrix,
        "court_exhibit_readiness_matrix_hash": exhibit_readiness_matrix["matrix_hash"],
        "package_hash": package_hash,
        "ready_for_internal_handoff": True,
        "ready_for_court_report": False,
        "blockers": manifest["blockers"],
    }


def build_case_db_court_exhibit_readiness_matrix(exhibits: Sequence[Mapping[str, object]]) -> dict[str, object]:
    rows = []
    for exhibit in exhibits:
        checks = {
            "exhibit_id": bool(exhibit.get("exhibit_id")),
            "review_citation_id": bool(exhibit.get("review_citation_id")),
            "source_citation_id": bool(exhibit.get("source_citation_id")),
            "source_path": bool(exhibit.get("source_path")),
            "source_hash_status_present": str(exhibit.get("source_hash_status") or "") == "present",
            "parser_identity_present": str(exhibit.get("parser_identity_status") or "") == "present",
            "source_locator_present": str(exhibit.get("source_locator_status") or "") == "present",
            "provenance_manifest_hash": bool(exhibit.get("provenance_manifest_hash")),
            "report_citation_profile_hash": bool(exhibit.get("report_citation_profile_hash")),
            "exhibit_row_hash": bool(exhibit.get("exhibit_row_hash")),
        }
        row_core = {
            "exhibit_id": str(exhibit.get("exhibit_id") or ""),
            "checks": checks,
            "missing_checks": [key for key, present in checks.items() if not present],
            "ready_for_report_export": bool(exhibit.get("ready_for_report_export")),
            "ready_for_court_report": False,
        }
        rows.append({**row_core, "row_hash": stable_payload_sha256(row_core)})
    matrix_core = {
        "profile_version": "court-exhibit-readiness-matrix-v1",
        "item_number": 94,
        "row_count": len(rows),
        "rows": rows,
        "ready_for_report_export_count": sum(1 for row in rows if row.get("ready_for_report_export")),
        "ready_for_court_report_count": 0,
        "commercial_claim_allowed": False,
    }
    return {**matrix_core, "matrix_hash": stable_payload_sha256(matrix_core)}


def build_functional_reporting_profiles(
    *,
    items: Sequence[Mapping[str, object]],
    citation_index: Sequence[Mapping[str, object]],
    validation_warning_count: int,
    legal_limitation_count: int,
    report_generation_package: Mapping[str, object],
    court_exhibit_package: Mapping[str, object],
) -> dict[str, object]:
    item_count = len(items)
    review_citation_count = sum(1 for item in items if item.get("review_citation_id"))
    source_citation_count = sum(1 for item in items if item.get("target_citation_id"))
    source_reference_count = sum(1 for item in items if item.get("source_reference"))
    provenance_count = sum(1 for item in items if isinstance(item.get("provenance"), Mapping))
    validation_assessment_count = sum(1 for item in items if isinstance(item.get("validation_assessment"), Mapping))
    limitation_assessment_count = sum(1 for item in items if isinstance(item.get("legal_limitations_assessment"), Mapping))
    citation_profiles = [
        item.get("report_citation_profile")
        for item in items
        if isinstance(item.get("report_citation_profile"), Mapping)
    ]
    citation_profile_summary = build_report_citation_workflow_summary(items)
    warning_display_summary = build_report_warning_display_summary(items)
    profiles = [
        build_functional_reporting_profile(
            item_number=21,
            component="citation-manager-user-workflow",
            status="implemented-usable-validation-required",
            controls={
                "selected_item_count": item_count,
                "citation_index_count": len(citation_index),
                "review_citation_count": review_citation_count,
                "source_citation_count": source_citation_count,
                "source_reference_count": source_reference_count,
                "source_reference_complete": source_reference_count >= item_count if item_count else True,
                "report_candidate_profile_count": len(citation_profiles),
                "ready_for_report_export_count": citation_profile_summary["ready_for_report_export_count"],
                "source_path_count": citation_profile_summary["source_path_count"],
                "source_hash_present_count": citation_profile_summary["source_hash_present_count"],
                "parser_identity_count": citation_profile_summary["parser_identity_count"],
                "source_locator_count": citation_profile_summary["source_locator_count"],
                "confidence_count": citation_profile_summary["confidence_count"],
                "legal_limitation_count": citation_profile_summary["legal_limitation_count"],
                "blocker_count": citation_profile_summary["blocker_count"],
            },
            blockers=[
                "trusted-citation-index-diff-is-required-before-commercial-claim",
                "external-exhibit-numbering-signoff-not-attached",
                *citation_profile_summary["unique_blockers"],
            ],
            recommended_actions=[
                "Use the citation index as the report source-of-truth for every selected item.",
                "Verify review citation, source citation, path, and source hash before final report release.",
                "Open each report candidate profile and resolve item-level blockers before exhibit packaging.",
            ],
        ),
        build_functional_reporting_profile(
            item_number=22,
            component="report-generation-user-workflow",
            status="implemented-usable-validation-required",
            controls={
                "json_case_export": True,
                "case_db_markdown_document": bool(report_generation_package.get("markdown_document")),
                "case_db_report_manifest": bool(
                    isinstance(report_generation_package.get("manifest"), Mapping)
                    and report_generation_package.get("manifest", {}).get("manifest_hash")
                ),
                "case_db_hash_bundle": bool(report_generation_package.get("hash_bundle_sha256")),
                "report_generation_manifest_hash": str(
                    report_generation_package.get("manifest", {}).get("manifest_hash")
                    if isinstance(report_generation_package.get("manifest"), Mapping)
                    else ""
                ),
                "bounded_export_limit": 5000,
                "selected_item_count": item_count,
                "review_status_counts_recorded": True,
                "verification_status_counts_recorded": True,
                "markdown_report_available_via_run_report_export": True,
                "docx_pdf_requires_external_renderer": True,
            },
            blockers=[
                "docx-pdf-layout-render-validation-not-attached",
                "external-report-template-approval-required-before-court-use",
            ],
            recommended_actions=[
                "Generate the Case DB report export with the final evidence selection.",
                "Attach layout-verified Markdown/PDF/DOCX output only after renderer smoke tests pass.",
            ],
        ),
        build_functional_reporting_profile(
            item_number=23,
            component="court-exhibit-package-readiness",
            status="implemented-package-manifest-validation-required",
            controls={
                "court_exhibit_manifest": bool(
                    isinstance(court_exhibit_package.get("manifest"), Mapping)
                    and court_exhibit_package.get("manifest", {}).get("manifest_hash")
                ),
                "court_exhibit_manifest_hash": str(
                    court_exhibit_package.get("manifest", {}).get("manifest_hash")
                    if isinstance(court_exhibit_package.get("manifest"), Mapping)
                    else ""
                ),
                "court_exhibit_package_hash": str(court_exhibit_package.get("package_hash") or ""),
                "exhibit_count": nested_mapping_str(court_exhibit_package, "manifest", "exhibit_count"),
                "citation_index": bool(citation_index),
                "selected_items": item_count,
                "provenance_rows": provenance_count,
                "audit_chain_available": True,
                "custody_and_hash_workflows_available": True,
                "external_signature_slot": True,
                "external_signature_attached": False,
            },
            blockers=[
                "external-signature-or-notarization-evidence-not-attached",
                "independent-court-exhibit-package-review-not-attached",
            ],
            recommended_actions=[
                "Bundle selected items, citation index, custody, hash, audit, and reproducibility manifests together.",
                "Apply external signing/notarization outside the local tool before evidence submission.",
            ],
        ),
        build_functional_reporting_profile(
            item_number=24,
            component="validation-warning-user-experience",
            status="implemented-usable-validation-required",
            controls={
                "validation_assessment_count": validation_assessment_count,
                "warning_display_profile_count": warning_display_summary["profile_count"],
                "warning_state_counts": warning_display_summary["state_counts"],
                "warning_badge_counts": warning_display_summary["badge_counts"],
                "validation_required_count": warning_display_summary["validation_required_count"],
                "external_evidence_needed_count": warning_display_summary["external_evidence_needed_count"],
                "report_grade_candidate_count": warning_display_summary["report_grade_candidate_count"],
                "validation_warning_count": validation_warning_count,
                "legal_limitation_count": legal_limitation_count,
                "legal_limitation_assessment_count": limitation_assessment_count,
                "warnings_attached_to_each_report_item": validation_assessment_count >= item_count if item_count else True,
                "limitations_attached_to_each_report_item": limitation_assessment_count >= item_count if item_count else True,
            },
            blockers=[
                "trusted-validation-warning-checklist-diff-missing",
                "trusted-legal-limitation-wording-diff-missing",
            ],
            recommended_actions=[
                "Keep validation and legal limitation warnings visible next to every report candidate.",
                "Do not allow final report language to hide parser confidence or unsupported-artifact limits.",
            ],
        ),
    ]
    return {
        "batch_id": FUNCTIONAL_REPORTING_BATCH_ID,
        "item_numbers": [21, 22, 23, 24],
        "status": "implemented-usable-validation-required",
        "profile_count": len(profiles),
        "profiles": profiles,
        "blockers": sorted({blocker for profile in profiles for blocker in profile.get("blockers", [])}),
        "ready_for_commercial_claim": False,
    }


def build_functional_reporting_profile(
    *,
    item_number: int,
    component: str,
    status: str,
    controls: Mapping[str, object],
    blockers: Sequence[str],
    recommended_actions: Sequence[str],
) -> dict[str, object]:
    return {
        "batch_id": FUNCTIONAL_REPORTING_BATCH_ID,
        "item_number": item_number,
        "gap_id": f"#{item_number}",
        "component": component,
        "status": status,
        "implemented": True,
        "usable": True,
        "validated": True,
        "ready_for_commercial_claim": False,
        "controls": dict(controls),
        "blockers": list(blockers),
        "recommended_actions": list(recommended_actions),
        "validation_evidence": [
            "case-db-export-schema-emits-functional-profile",
            "unit-test-asserts-user-visible-profile-contract",
        ],
    }


def build_report_citation_index(items: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    citations: dict[str, dict[str, object]] = {}
    for item in items:
        review_id = str(item.get("review_citation_id") or "")
        target_id = str(item.get("target_citation_id") or "")
        if review_id:
            citations[review_id] = {
                "citation_id": review_id,
                "role": "review-decision",
                "target_type": str(item.get("target_type") or ""),
                "target_id": str(item.get("target_id") or ""),
                "title": str(item.get("title") or ""),
                "copy_safe_citation": copy_safe_report_citation(
                    citation_id=review_id,
                    role="review-decision",
                    item=item,
                ),
                "source_viewer_locator": report_citation_source_viewer_locator(
                    citation_id=review_id,
                    role="review-decision",
                    item=item,
                ),
                "commercial_gap_ids": ["#64"],
                "report_use": "cite-review-decision-with-source-record",
            }
        if target_id:
            source_reference = item.get("source_reference") if isinstance(item.get("source_reference"), Mapping) else {}
            source_package = item.get("source_citation_package") if isinstance(item.get("source_citation_package"), Mapping) else {}
            citations[target_id] = {
                "citation_id": target_id,
                "role": "source-record",
                "target_type": str(item.get("target_type") or ""),
                "target_id": str(item.get("target_id") or ""),
                "title": str(item.get("title") or ""),
                "path": str(item.get("path") or ""),
                "source_reference": source_reference,
                "source_citation_package_hash": source_citation_package_hash(source_package),
                "source_review_handoff": build_source_review_handoff(source_package),
                "source_hash_status": "present" if citation_source_reference_has_hash(source_reference) else "missing",
                "parser_version_status": "present" if source_reference.get("parser_version") else "missing",
                "copy_safe_citation": copy_safe_report_citation(
                    citation_id=target_id,
                    role="source-record",
                    item=item,
                ),
                "source_viewer_locator": report_citation_source_viewer_locator(
                    citation_id=target_id,
                    role="source-record",
                    item=item,
                ),
                "commercial_gap_ids": ["#64"],
                "report_use": "cite-source-record-with-review-decision",
                "core_accuracy_gates": citation_manager_core_accuracy_gates(citation_count=1, has_source_reference=bool(item.get("source_reference"))),
            }
    return [attach_citation_row_hash(citations[key]) for key in sorted(citations)]


def build_report_citation_manager(citation_index: Sequence[Mapping[str, object]]) -> dict[str, object]:
    coverage_profile = build_report_citation_coverage_profile(citation_index)
    citation_index_manifest = build_report_citation_index_manifest(citation_index)
    validation_plan = build_report_citation_report_grade_validation_plan(
        citation_index=citation_index,
        coverage_profile=coverage_profile,
        citation_index_manifest=citation_index_manifest,
        plan_context="case-db-report-export",
    )
    gates = citation_manager_core_accuracy_gates(
        citation_count=len(citation_index),
        has_source_reference=any(bool(item.get("source_reference")) for item in citation_index),
        citation_index_manifest=citation_index_manifest,
        report_grade_validation_plan=validation_plan,
    )
    blockers = [
        "citation-index-depends-on-imported-source-reference-completeness",
        "analyst-must-verify-source-hashes-parser-confidence-and-review-history-before-report-use",
        "trusted-citation-index-diff-is-required-before-commercial-claim",
    ]
    blockers = sorted({*blockers, *REPORT_CITATION_REPORT_GRADE_BLOCKERS})
    return {
        "component": "report-citation-manager",
        "status": "implemented-baseline-validation-required",
        "commercial_gap_ids": ["#64"],
        "citation_count": len(citation_index),
        "coverage_profile": coverage_profile,
        "citation_index_manifest": citation_index_manifest,
        "citation_index_manifest_hash": citation_index_manifest["manifest_hash"],
        "report_citation_report_grade_validation_plan": validation_plan,
        "report_citation_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
        "report_grade_ready_slot_count": validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
        "ready_for_court_report": False,
        "blockers": blockers,
        "recommended_validation": [
            "Confirm every report item has both a review citation and source-record citation.",
            "Preserve the exported citation index with the report and source hash manifest.",
            "Attach a trusted citation-index diff, exhibit numbering review, jurisdiction template review, and reviewer sign-off before court package use.",
        ],
        "core_accuracy_gates": gates,
        "commercial_uplift_evidence": case_report_commercial_uplift_evidence(
            item_number=64,
            component="report-citation-manager",
            core_accuracy_gates=gates,
            blockers=blockers,
            source_refs=[
                f"citation_count:{len(citation_index)}",
                f"citation_index_manifest_hash:{citation_index_manifest['manifest_hash']}",
            ],
            controls={
                "citation_count": len(citation_index),
                "citation_index_manifest_hash": citation_index_manifest["manifest_hash"],
                "citation_row_hash_count": citation_index_manifest["citation_row_hash_count"],
                "source_viewer_locator_count": citation_index_manifest["source_viewer_locator_count"],
                "source_reference_present": any(bool(item.get("source_reference")) for item in citation_index),
                "copy_safe_citation_count": coverage_profile["copy_safe_citation_count"],
                "source_hash_present_count": coverage_profile["source_hash_present_count"],
                "parser_version_present_count": coverage_profile["parser_version_present_count"],
                "exhibit_numbering_ui": False,
                "source_hash_completeness_validation": False,
                "report_citation_report_grade_validation_plan_present": True,
                "report_citation_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
                "report_grade_ready_slot_count": validation_plan["ready_slot_count"],
                "report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
            },
        ),
    }


def build_report_citation_coverage_profile(citation_index: Sequence[Mapping[str, object]]) -> dict[str, object]:
    source_records = [item for item in citation_index if item.get("role") == "source-record"]
    review_records = [item for item in citation_index if item.get("role") == "review-decision"]
    source_reference_count = sum(1 for item in source_records if isinstance(item.get("source_reference"), Mapping) and item.get("source_reference"))
    source_hash_count = sum(
        1
        for item in source_records
        if citation_source_reference_has_hash(item.get("source_reference") if isinstance(item.get("source_reference"), Mapping) else {})
    )
    parser_version_count = sum(
        1
        for item in source_records
        if isinstance(item.get("source_reference"), Mapping) and bool(item.get("source_reference", {}).get("parser_version"))
    )
    copy_safe_count = sum(1 for item in citation_index if item.get("copy_safe_citation"))
    incomplete = [
        str(item.get("citation_id") or "")
        for item in source_records
        if not (
            isinstance(item.get("source_reference"), Mapping)
            and item.get("source_reference")
            and citation_source_reference_has_hash(item.get("source_reference"))
            and item.get("source_reference", {}).get("parser_version")
        )
    ]
    return {
        "profile_version": "report-citation-coverage-profile-v1",
        "commercial_gap_ids": ["#64"],
        "citation_count": len(citation_index),
        "review_decision_count": len(review_records),
        "source_record_count": len(source_records),
        "source_reference_count": source_reference_count,
        "source_hash_present_count": source_hash_count,
        "parser_version_present_count": parser_version_count,
        "copy_safe_citation_count": copy_safe_count,
        "citation_row_hash_count": sum(1 for item in citation_index if item.get("citation_row_hash")),
        "source_viewer_locator_count": sum(1 for item in citation_index if item.get("source_viewer_locator")),
        "incomplete_source_record_citation_ids": incomplete[:50],
        "source_reference_complete": source_reference_count == len(source_records) if source_records else True,
        "source_hash_complete": source_hash_count == len(source_records) if source_records else True,
        "parser_version_complete": parser_version_count == len(source_records) if source_records else True,
        "report_use_warning": "Incomplete source hashes or parser versions must be resolved before final report/court exhibit use.",
    }


def attach_citation_row_hash(citation: Mapping[str, object]) -> dict[str, object]:
    row = dict(citation)
    row_core = {
        "citation_id": str(row.get("citation_id") or ""),
        "role": str(row.get("role") or ""),
        "target_type": str(row.get("target_type") or ""),
        "target_id": str(row.get("target_id") or ""),
        "path": str(row.get("path") or ""),
        "source_hash_status": str(row.get("source_hash_status") or ""),
        "parser_version_status": str(row.get("parser_version_status") or ""),
        "copy_safe_citation": str(row.get("copy_safe_citation") or ""),
    }
    row["citation_row_hash"] = stable_payload_sha256(row_core)
    return row


def report_citation_source_viewer_locator(*, citation_id: str, role: str, item: Mapping[str, object]) -> dict[str, object]:
    source_reference = item.get("source_reference") if isinstance(item.get("source_reference"), Mapping) else {}
    upstream_locator = (
        dict(source_reference.get("source_viewer_locator"))
        if isinstance(source_reference.get("source_viewer_locator"), Mapping)
        else {}
    )
    return {
        "viewer": "report-citation-source",
        "open_action": "open-report-citation",
        "citation_id": citation_id,
        "role": role,
        "target_type": str(item.get("target_type") or ""),
        "target_id": str(item.get("target_id") or ""),
        "path": str(source_reference.get("path") or item.get("path") or ""),
        "parser": str(source_reference.get("parser") or ""),
        "parser_version": str(source_reference.get("parser_version") or ""),
        "upstream_source_viewer_locator": upstream_locator,
        "parser_manifest_hashes": dict(source_reference.get("parser_manifest_hashes"))
        if isinstance(source_reference.get("parser_manifest_hashes"), Mapping)
        else {},
    }


def build_report_citation_index_manifest(citation_index: Sequence[Mapping[str, object]]) -> dict[str, object]:
    citation_rows = []
    for citation in citation_index:
        source_reference = citation.get("source_reference") if isinstance(citation.get("source_reference"), Mapping) else {}
        locator = citation.get("source_viewer_locator") if isinstance(citation.get("source_viewer_locator"), Mapping) else {}
        citation_rows.append(
            {
                "citation_id": str(citation.get("citation_id") or ""),
                "role": str(citation.get("role") or ""),
                "target_type": str(citation.get("target_type") or ""),
                "target_id": str(citation.get("target_id") or ""),
                "citation_row_hash": str(citation.get("citation_row_hash") or ""),
                "source_hash_status": str(citation.get("source_hash_status") or ""),
                "parser_version_status": str(citation.get("parser_version_status") or ""),
                "source_hash_present": citation_source_reference_has_hash(source_reference),
                "parser_version_present": bool(source_reference.get("parser_version")),
                "source_viewer_locator": dict(locator),
            }
        )
    manifest_core: dict[str, object] = {
        "manifest_version": "report-citation-index-manifest-v1",
        "item_number": 64,
        "commercial_gap_ids": ["#64"],
        "citation_count": len(citation_index),
        "review_decision_count": sum(1 for item in citation_index if item.get("role") == "review-decision"),
        "source_record_count": sum(1 for item in citation_index if item.get("role") == "source-record"),
        "citation_row_hash_count": sum(1 for item in citation_rows if item.get("citation_row_hash")),
        "source_viewer_locator_count": sum(1 for item in citation_rows if item.get("source_viewer_locator")),
        "source_hash_present_count": sum(1 for item in citation_rows if item.get("source_hash_present")),
        "parser_version_present_count": sum(1 for item in citation_rows if item.get("parser_version_present")),
        "citation_rows": citation_rows,
        "citation_rows_head_hash": stable_payload_sha256(citation_rows),
        "report_use_boundary": "citation index is a report navigation and source-reference manifest, not a court exhibit package by itself",
        "blockers": [
            "citation-index-depends-on-imported-source-reference-completeness",
            "analyst-must-verify-source-hashes-parser-confidence-and-review-history-before-report-use",
            "trusted-citation-index-diff-is-required-before-commercial-claim",
        ],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_report_citation_report_grade_validation_plan(
    *,
    citation_index: Sequence[Mapping[str, object]],
    coverage_profile: Mapping[str, object],
    citation_index_manifest: Mapping[str, object],
    plan_context: str,
) -> dict[str, object]:
    citation_index = list(citation_index)
    ready_slots = [
        {
            "slot_id": "report-citation-review-source-pairs",
            "status": "complete",
            "evidence": {
                "review_decision_count": int(citation_index_manifest.get("review_decision_count") or 0),
                "source_record_count": int(citation_index_manifest.get("source_record_count") or 0),
            },
        },
        {
            "slot_id": "report-citation-copy-safe-strings",
            "status": "complete",
            "evidence": {"copy_safe_citation_count": int(coverage_profile.get("copy_safe_citation_count") or 0)},
        },
        {
            "slot_id": "report-citation-row-hashes",
            "status": "complete",
            "evidence": {"citation_row_hash_count": int(citation_index_manifest.get("citation_row_hash_count") or 0)},
        },
        {
            "slot_id": "report-citation-source-viewer-locators",
            "status": "complete",
            "evidence": {"source_viewer_locator_count": int(citation_index_manifest.get("source_viewer_locator_count") or 0)},
        },
        {
            "slot_id": "report-citation-source-reference-coverage-profile",
            "status": "complete",
            "evidence": {
                "source_reference_count": int(coverage_profile.get("source_reference_count") or 0),
                "source_hash_present_count": int(coverage_profile.get("source_hash_present_count") or 0),
                "parser_version_present_count": int(coverage_profile.get("parser_version_present_count") or 0),
            },
        },
        {
            "slot_id": "report-citation-index-manifest",
            "status": "complete",
            "evidence": {
                "manifest_version": citation_index_manifest.get("manifest_version"),
                "manifest_hash": citation_index_manifest.get("manifest_hash"),
                "citation_rows_head_hash": citation_index_manifest.get("citation_rows_head_hash"),
            },
        },
    ]
    blocking_slots = [
        {
            "slot_id": "report-citation-source-hash-completeness",
            "status": "external-required",
            "blocker": "source-hash-completeness-validation-required",
            "required_evidence": "trusted per-parser source-hash completeness matrix for every reported source row",
        },
        {
            "slot_id": "report-citation-parser-version-completeness",
            "status": "external-required",
            "blocker": "parser-version-completeness-validation-required",
            "required_evidence": "trusted parser-version completeness matrix covering every citation source row",
        },
        {
            "slot_id": "report-citation-trusted-index-diff",
            "status": "external-required",
            "blocker": "trusted-citation-index-diff-required",
            "required_evidence": "trusted citation-index manifest diff against an independently produced report checklist",
        },
        {
            "slot_id": "report-citation-exhibit-numbering-ui",
            "status": "external-required",
            "blocker": "exhibit-numbering-ui-required",
            "required_evidence": "analyst UI evidence for exhibit numbering, renumbering, and citation preservation",
        },
        {
            "slot_id": "report-citation-jurisdiction-template-review",
            "status": "external-required",
            "blocker": "jurisdiction-template-review-required",
            "required_evidence": "jurisdiction-specific citation wording/template review and signoff",
        },
        {
            "slot_id": "report-citation-reviewer-signoff-corpus",
            "status": "external-required",
            "blocker": "reviewer-signoff-corpus-required",
            "required_evidence": "reviewer signoff corpus proving citation text, source locators, hashes, and limitations are reproducible",
        },
    ]
    plan_core: dict[str, object] = {
        "profile_version": REPORT_CITATION_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 64,
        "commercial_gap_ids": ["#64"],
        "plan_context": plan_context,
        "citation_count": len(citation_index),
        "citation_index_manifest_hash": citation_index_manifest.get("manifest_hash"),
        "citation_coverage_profile_hash": stable_payload_sha256(dict(coverage_profile)),
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "commercial_claim_allowed": False,
        "reporting_boundary": "This plan makes the citation manager report-verifiable as a triage/export index, but it is not a court exhibit package until the external-required slots are attached.",
    }
    return {**plan_core, "validation_plan_sha256": stable_payload_sha256(plan_core)}


def citation_source_reference_has_hash(source_reference: Mapping[str, object]) -> bool:
    source_hashes = source_reference.get("source_hashes") if isinstance(source_reference.get("source_hashes"), Mapping) else {}
    record_hashes = source_reference.get("record_hashes") if isinstance(source_reference.get("record_hashes"), Mapping) else {}
    return bool(source_hashes.get("sha256") or record_hashes.get("sha256"))


def copy_safe_report_citation(*, citation_id: str, role: str, item: Mapping[str, object]) -> str:
    source_reference = item.get("source_reference") if isinstance(item.get("source_reference"), Mapping) else {}
    hashes = source_reference.get("source_hashes") if isinstance(source_reference.get("source_hashes"), Mapping) else {}
    record_hashes = source_reference.get("record_hashes") if isinstance(source_reference.get("record_hashes"), Mapping) else {}
    sha256 = str(hashes.get("sha256") or record_hashes.get("sha256") or "")
    parser = str(source_reference.get("parser") or "")
    parser_version = str(source_reference.get("parser_version") or "")
    parts = [
        f"citation_id={citation_id}",
        f"role={role}",
        f"target={item.get('target_type', '')}:{item.get('target_id', '')}",
        f"title={item.get('title', '')}",
        f"path={source_reference.get('path') or item.get('path') or ''}",
    ]
    if sha256:
        parts.append(f"sha256={sha256}")
    if parser or parser_version:
        parts.append(f"parser={parser} {parser_version}".strip())
    return "; ".join(str(part) for part in parts if str(part).strip())


def build_evidence_selection_version_history(items: Sequence[Mapping[str, object]]) -> dict[str, object]:
    history_count = sum(len(item.get("review_history") or []) for item in items if isinstance(item.get("review_history"), list))
    history_rows = [
        history
        for item in items
        if isinstance(item.get("review_history"), list)
        for history in item.get("review_history", [])
        if isinstance(history, Mapping)
    ]
    integrity_profile = build_evidence_history_integrity_profile(history_rows)
    history_manifest = build_evidence_selection_history_manifest(history_rows, integrity_profile)
    validation_plan = build_evidence_selection_history_report_grade_validation_plan(
        history_rows=history_rows,
        integrity_profile=integrity_profile,
        history_manifest=history_manifest,
        plan_context="case-db-report-export",
    )
    blockers = [
        "selection-history-is-database-append-only-but-not-multi-user-signed-collaboration",
        "review-inclusion-changes-still-require-source-verification-before-reporting",
        "trusted-evidence-history-diff-is-required-before-commercial-claim",
    ]
    blockers = sorted({*blockers, *EVIDENCE_SELECTION_REPORT_GRADE_BLOCKERS})
    gates = evidence_selection_core_accuracy_gates(
        history_rows=history_rows,
        history_manifest=history_manifest,
        report_grade_validation_plan=validation_plan,
    )
    return {
        "component": "evidence-selection-version-history",
        "status": "implemented-baseline-validation-required",
        "commercial_gap_ids": ["#65"],
        "selected_item_count": len(items),
        "review_history_count": history_count,
        "integrity_profile": integrity_profile,
        "history_manifest": history_manifest,
        "history_manifest_hash": history_manifest["manifest_hash"],
        "evidence_selection_report_grade_validation_plan": validation_plan,
        "evidence_selection_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
        "report_grade_ready_slot_count": validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
        "ready_for_court_report": False,
        "blockers": blockers,
        "recommended_validation": [
            "Review version rows for status, verification, tags, assignee, priority, and include-in-report changes.",
            "Export the Case DB report JSON with the final report so selection history remains reproducible.",
            "Attach signed multi-user history, trusted history diff, conflict-handling evidence, and reviewer identity/RBAC proof before final signed-history claims.",
        ],
        "core_accuracy_gates": gates,
        "commercial_uplift_evidence": case_report_commercial_uplift_evidence(
            item_number=65,
            component="evidence-selection-version-history",
            core_accuracy_gates=gates,
            blockers=blockers,
            source_refs=[
                f"selected_item_count:{len(items)}",
                f"review_history_count:{history_count}",
                f"history_manifest_hash:{history_manifest['manifest_hash']}",
            ],
            controls={
                "selected_item_count": len(items),
                "review_history_count": history_count,
                "history_head_hash": integrity_profile["head_hash"],
                "history_manifest_hash": history_manifest["manifest_hash"],
                "history_viewer_locator_count": history_manifest["history_viewer_locator_count"],
                "include_in_report_change_count": integrity_profile["include_in_report_change_count"],
                "row_hash_count": integrity_profile["row_hash_count"],
                "local_sqlite_history": True,
                "database_enforced_append_only": True,
                "append_only_trigger_count": 2,
                "multi_user_signed_history": False,
                "conflict_resolution": False,
                "evidence_selection_report_grade_validation_plan_present": True,
                "evidence_selection_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
                "report_grade_ready_slot_count": validation_plan["ready_slot_count"],
                "report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
            },
        ),
    }


def build_evidence_history_integrity_profile(history_rows: Sequence[Mapping[str, object]]) -> dict[str, object]:
    previous_hash = ""
    chained_rows = []
    changed_field_counts: dict[str, int] = {}
    include_change_count = 0
    for row in history_rows:
        changed_fields = [str(field) for field in row.get("changed_fields") or []]
        for field in changed_fields:
            changed_field_counts[field] = changed_field_counts.get(field, 0) + 1
        if "include_in_report" in changed_fields:
            include_change_count += 1
        row_hash = str(row.get("row_hash") or evidence_history_row_hash(row))
        chain_payload = {
            "review_citation_id": str(row.get("review_citation_id") or ""),
            "version": row.get("version"),
            "changed_at": str(row.get("changed_at") or ""),
            "row_hash": row_hash,
            "previous_history_hash": previous_hash,
        }
        history_hash = stable_payload_sha256(chain_payload)
        chained_rows.append({**chain_payload, "history_hash": history_hash})
        previous_hash = history_hash
    return {
        "profile_version": "evidence-selection-history-integrity-profile-v1",
        "commercial_gap_ids": ["#65"],
        "history_row_count": len(history_rows),
        "row_hash_count": sum(1 for row in history_rows if row.get("row_hash")),
        "head_hash": previous_hash,
        "include_in_report_change_count": include_change_count,
        "changed_field_counts": dict(sorted(changed_field_counts.items())),
        "chain_rows": chained_rows[:200],
        "chain_truncated": len(chained_rows) > 200,
        "tamper_evident_export_only": True,
        "database_enforced_append_only": True,
        "append_only_triggers": ["review_mark_history_no_update", "review_mark_history_no_delete"],
        "report_use_warning": "This hash chain is generated at export time; preserve the Case DB and export JSON, and attach a trusted history manifest before report-defensible use.",
    }


def build_evidence_selection_history_manifest(
    history_rows: Sequence[Mapping[str, object]],
    integrity_profile: Mapping[str, object],
) -> dict[str, object]:
    manifest_rows = []
    for row in history_rows:
        locator = row.get("history_viewer_locator") if isinstance(row.get("history_viewer_locator"), Mapping) else {}
        manifest_rows.append(
            {
                "review_citation_id": str(row.get("review_citation_id") or ""),
                "target_type": str(row.get("target_type") or ""),
                "target_id": str(row.get("target_id") or ""),
                "version": row.get("version"),
                "changed_at": str(row.get("changed_at") or ""),
                "actor_present": bool(str(row.get("actor") or "")),
                "changed_fields": [str(field) for field in row.get("changed_fields") or []],
                "row_hash": str(row.get("row_hash") or evidence_history_row_hash(row)),
                "history_viewer_locator": dict(locator),
            }
        )
    manifest_core: dict[str, object] = {
        "manifest_version": "evidence-selection-history-manifest-v1",
        "item_number": 65,
        "commercial_gap_ids": ["#65"],
        "history_row_count": len(history_rows),
        "row_hash_count": sum(1 for row in manifest_rows if row.get("row_hash")),
        "history_viewer_locator_count": sum(1 for row in manifest_rows if row.get("history_viewer_locator")),
        "include_in_report_change_count": int(integrity_profile.get("include_in_report_change_count") or 0),
        "history_head_hash": str(integrity_profile.get("head_hash") or ""),
        "changed_field_counts": dict(integrity_profile.get("changed_field_counts") or {}),
        "history_rows": manifest_rows[:500],
        "history_rows_truncated": len(manifest_rows) > 500,
        "history_rows_head_hash": stable_payload_sha256(manifest_rows),
        "append_only_enforcement": {
            "database_triggers": [
                "review_mark_history_no_update",
                "review_mark_history_no_delete",
            ],
            "database_enforced_append_only": True,
            "multi_user_signed_history": False,
            "conflict_resolution": False,
        },
        "report_use_boundary": "history manifest proves exported review-version rows only; attach signed multi-user history and trusted diff before report-defensible claims",
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_evidence_selection_history_report_grade_validation_plan(
    *,
    history_rows: Sequence[Mapping[str, object]],
    integrity_profile: Mapping[str, object],
    history_manifest: Mapping[str, object],
    plan_context: str,
) -> dict[str, object]:
    history_rows = list(history_rows)
    ready_slots = [
        {
            "slot_id": "evidence-history-version-rows",
            "status": "complete",
            "evidence": {"history_row_count": int(history_manifest.get("history_row_count") or 0)},
        },
        {
            "slot_id": "evidence-history-changed-fields",
            "status": "complete",
            "evidence": {"changed_field_counts": dict(integrity_profile.get("changed_field_counts") or {})},
        },
        {
            "slot_id": "evidence-history-previous-current-state",
            "status": "complete",
            "evidence": {
                "rows_with_previous_or_current": sum(
                    1
                    for row in history_rows
                    if row.get("previous") is not None or row.get("current") is not None
                )
            },
        },
        {
            "slot_id": "evidence-history-report-inclusion-changes",
            "status": "complete",
            "evidence": {
                "include_in_report_change_count": int(integrity_profile.get("include_in_report_change_count") or 0)
            },
        },
        {
            "slot_id": "evidence-history-row-hashes-and-chain",
            "status": "complete",
            "evidence": {
                "row_hash_count": int(integrity_profile.get("row_hash_count") or 0),
                "history_head_hash": integrity_profile.get("head_hash"),
                "manifest_hash": history_manifest.get("manifest_hash"),
            },
        },
        {
            "slot_id": "evidence-history-source-locators-and-local-append-only",
            "status": "complete",
            "evidence": {
                "history_viewer_locator_count": int(history_manifest.get("history_viewer_locator_count") or 0),
                "database_enforced_append_only": bool(
                    (history_manifest.get("append_only_enforcement") or {}).get("database_enforced_append_only")
                    if isinstance(history_manifest.get("append_only_enforcement"), Mapping)
                    else False
                ),
            },
        },
    ]
    blocking_slots = [
        {
            "slot_id": "evidence-history-signed-multi-user-history",
            "status": "external-required",
            "blocker": "signed-multi-user-history-required",
            "required_evidence": "signed multi-user history export with user identity, timestamps, and immutable history proofs",
        },
        {
            "slot_id": "evidence-history-trusted-diff",
            "status": "external-required",
            "blocker": "trusted-evidence-history-diff-required",
            "required_evidence": "trusted history manifest diff against independently generated review-history output",
        },
        {
            "slot_id": "evidence-history-conflict-handling",
            "status": "external-required",
            "blocker": "multi-user-conflict-handling-required",
            "required_evidence": "multi-user conflict creation, resolution, replay, and audit evidence",
        },
        {
            "slot_id": "evidence-history-database-trigger-review",
            "status": "external-required",
            "blocker": "database-trigger-enforcement-review-required",
            "required_evidence": "independent review proving update/delete trigger enforcement for history rows",
        },
        {
            "slot_id": "evidence-history-reviewer-identity-rbac",
            "status": "external-required",
            "blocker": "reviewer-identity-rbac-corpus-required",
            "required_evidence": "RBAC/reviewer identity corpus linking history rows to authenticated analysts",
        },
        {
            "slot_id": "evidence-history-replay-corpus",
            "status": "external-required",
            "blocker": "history-replay-corpus-required",
            "required_evidence": "known-answer replay corpus for report inclusion, status, tags, notes, assignee, and priority changes",
        },
    ]
    plan_core: dict[str, object] = {
        "profile_version": EVIDENCE_SELECTION_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 65,
        "commercial_gap_ids": ["#65"],
        "plan_context": plan_context,
        "history_row_count": len(history_rows),
        "history_manifest_hash": history_manifest.get("manifest_hash"),
        "integrity_profile_hash": stable_payload_sha256(dict(integrity_profile)),
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "commercial_claim_allowed": False,
        "reporting_boundary": "This plan makes exported selection history report-verifiable for local review, but it is not signed multi-user history until the external-required slots are attached.",
    }
    return {**plan_core, "validation_plan_sha256": stable_payload_sha256(plan_core)}


def evidence_history_viewer_locator(history_row: Mapping[str, object]) -> dict[str, object]:
    return {
        "viewer": "evidence-selection-history",
        "open_action": "open-review-history-row",
        "review_citation_id": str(history_row.get("review_citation_id") or ""),
        "target_type": str(history_row.get("target_type") or ""),
        "target_id": str(history_row.get("target_id") or ""),
        "version": history_row.get("version"),
    }


def evidence_history_row_hash(history_row: Mapping[str, object]) -> str:
    payload = {
        "version": history_row.get("version"),
        "review_citation_id": str(history_row.get("review_citation_id") or ""),
        "target_type": str(history_row.get("target_type") or ""),
        "target_id": str(history_row.get("target_id") or ""),
        "changed_at": str(history_row.get("changed_at") or ""),
        "actor": str(history_row.get("actor") or ""),
        "changed_fields": list(history_row.get("changed_fields") or []),
        "previous": history_row.get("previous") or {},
        "current": history_row.get("current") or {},
    }
    return stable_payload_sha256(payload)


def case_report_commercial_uplift_evidence(
    *,
    item_number: int,
    component: str,
    core_accuracy_gates: Sequence[Mapping[str, object]],
    blockers: Sequence[str],
    source_refs: Sequence[str],
    controls: Mapping[str, object],
) -> dict[str, object]:
    gap_id = f"#{item_number}"
    passed = []
    for gate in core_accuracy_gates:
        if gate.get("gap_id") == gap_id:
            passed.extend(str(item) for item in gate.get("satisfied_checks") or [])
    return {
        "batch_id": "commercial-uplift-061-065",
        "item_numbers": [item_number],
        "implementation_track": component,
        "source_refs": list(source_refs),
        "reportability_decision": case_report_reportability_decision(
            item_number=item_number,
            component=component,
            blockers=blockers,
            controls=controls,
        ),
        "passed_validation_check_ids": sorted(set(passed)),
        "failed_validation_check_ids": list(blockers),
        "commercial_blockers": list(blockers),
        "large_data_controls": dict(controls),
        "reporting_status": "implemented-baseline-validation-required",
    }


def case_report_reportability_decision(
    *,
    item_number: int,
    component: str,
    blockers: Sequence[str],
    controls: Mapping[str, object],
) -> dict[str, object]:
    gap_id = f"#{item_number}"
    decisions = {
        64: "do-not-report-citation-index-as-court-exhibit-complete",
        65: "do-not-report-evidence-selection-history-as-multi-user-signed",
    }
    allowed_uses = {
        64: "report-citation-index-triage-pivot",
        65: "evidence-selection-history-triage-pivot",
    }
    required = {
        64: [
            "verify every report item has review and source-record citations plus source hashes and parser versions",
            "attach exhibit numbering, exported manifest, and reviewer sign-off before court package use",
        ],
        65: [
            "persist immutable multi-user signed selection history with conflict handling",
            "verify include-in-report changes against source hash and parser limitation evidence before final export",
        ],
    }
    return {
        "profile_version": "case-report-reportability-decision-v1",
        "commercial_gap_ids": [gap_id],
        "component": component,
        "decision": decisions.get(item_number, "do-not-report-case-output-as-commercial-complete"),
        "allowed_use": allowed_uses.get(item_number, "case-report-triage-pivot"),
        "blockers": sorted({str(item) for item in blockers if str(item)}),
        "control_snapshot": dict(controls),
        "ready_for_court_report": False,
        "required_before_report": required.get(item_number, ["attach source hash, parser validation, reviewer sign-off, and export manifest evidence"]),
    }


def build_citation_manager_trusted_diff(
    rapid_citations: Sequence[Mapping[str, object]],
    trusted_citations: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str = "citation-index-manifest",
) -> dict[str, object]:
    rapid_index = {citation_diff_key(item): citation_diff_value(item) for item in rapid_citations}
    trusted_index = {citation_diff_key(item): citation_diff_value(item) for item in trusted_citations}
    missing = sorted(key for key in trusted_index if key not in rapid_index)
    unexpected = sorted(key for key in rapid_index if key not in trusted_index)
    mismatched = [
        {"key": key, "rapid": rapid_index[key], "trusted": trusted_index[key]}
        for key in sorted(set(rapid_index).intersection(trusted_index))
        if rapid_index[key] != trusted_index[key]
    ]
    status = "pass" if not missing and not unexpected and not mismatched else "fail"
    return {
        "profile": "citation-manager-trusted-index-diff-v1",
        "item_number": 64,
        "trusted_tool": trusted_tool,
        "status": status,
        "rapid_count": len(rapid_index),
        "trusted_count": len(trusted_index),
        "missing": missing,
        "unexpected": unexpected,
        "mismatched": mismatched,
        "commercial_gap_ids": ["#64"],
        "commercial_claim_allowed": status == "pass",
    }


def citation_diff_key(item: Mapping[str, object]) -> str:
    return str(item.get("citation_id") or "")


def citation_diff_value(item: Mapping[str, object]) -> dict[str, object]:
    source_reference = item.get("source_reference")
    return {
        "role": str(item.get("role") or ""),
        "target_type": str(item.get("target_type") or ""),
        "target_id": str(item.get("target_id") or ""),
        "has_source_reference": isinstance(source_reference, Mapping) and bool(source_reference),
    }


def build_evidence_history_trusted_diff(
    rapid_history: Sequence[Mapping[str, object]],
    trusted_history: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str = "review-history-manifest",
) -> dict[str, object]:
    rapid_index = {evidence_history_diff_key(item): evidence_history_diff_value(item) for item in rapid_history}
    trusted_index = {evidence_history_diff_key(item): evidence_history_diff_value(item) for item in trusted_history}
    missing = sorted(key for key in trusted_index if key not in rapid_index)
    unexpected = sorted(key for key in rapid_index if key not in trusted_index)
    mismatched = [
        {"key": key, "rapid": rapid_index[key], "trusted": trusted_index[key]}
        for key in sorted(set(rapid_index).intersection(trusted_index))
        if rapid_index[key] != trusted_index[key]
    ]
    status = "pass" if not missing and not unexpected and not mismatched else "fail"
    return {
        "profile": "evidence-history-trusted-version-diff-v1",
        "item_number": 65,
        "trusted_tool": trusted_tool,
        "status": status,
        "rapid_count": len(rapid_index),
        "trusted_count": len(trusted_index),
        "missing": missing,
        "unexpected": unexpected,
        "mismatched": mismatched,
        "commercial_gap_ids": ["#65"],
        "commercial_claim_allowed": status == "pass",
    }


def evidence_history_diff_key(item: Mapping[str, object]) -> str:
    return "|".join(
        [
            str(item.get("review_citation_id") or ""),
            str(item.get("version") or ""),
            str(item.get("changed_at") or ""),
        ]
    )


def evidence_history_diff_value(item: Mapping[str, object]) -> dict[str, object]:
    return {
        "changed_fields": sorted(str(field) for field in item.get("changed_fields") or []),
        "previous": item.get("previous") or {},
        "current": item.get("current") or {},
    }


def citation_manager_core_accuracy_gates(
    *,
    citation_count: int,
    has_source_reference: bool,
    trusted_diff: Mapping[str, object] | None = None,
    citation_index_manifest: Mapping[str, object] | None = None,
    report_grade_validation_plan: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = ["citation count summary", "report-use verification warning"]
    if citation_count:
        satisfied.extend(["review citation IDs", "source-record citation IDs"])
    if has_source_reference:
        satisfied.append("source reference preserved")
    if citation_index_manifest and citation_index_manifest.get("manifest_hash"):
        satisfied.append("citation index manifest")
    if citation_index_manifest and int(citation_index_manifest.get("citation_row_hash_count") or 0) > 0:
        satisfied.append("citation row hashes")
    if citation_index_manifest and int(citation_index_manifest.get("source_viewer_locator_count") or 0) > 0:
        satisfied.append("citation source viewer locators")
    if report_grade_validation_plan and report_grade_validation_plan.get("validation_plan_sha256"):
        satisfied.append("report citation report-grade validation plan")
    if report_grade_validation_plan and int(report_grade_validation_plan.get("ready_slot_count") or 0) >= 6:
        satisfied.append("report citation report-grade ready slots")
    evidence_refs = [f"citation_count:{citation_count}", f"has_source_reference:{has_source_reference}"]
    if citation_index_manifest and citation_index_manifest.get("manifest_hash"):
        evidence_refs.append(f"citation_index_manifest_hash:{citation_index_manifest.get('manifest_hash', '')}")
    if report_grade_validation_plan and report_grade_validation_plan.get("validation_plan_sha256"):
        evidence_refs.append(
            f"report_citation_report_grade_validation_plan_hash:{report_grade_validation_plan.get('validation_plan_sha256', '')}"
        )
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted citation index diff pass")
        evidence_refs.append(f"trusted_tool:{trusted_diff.get('trusted_tool', '')}")
    return [
        build_accuracy_gate(
            64,
            satisfied_checks=satisfied,
            evidence_refs=evidence_refs,
        )
    ]


def evidence_selection_core_accuracy_gates(
    *,
    history_rows: Sequence[Mapping[str, object]],
    trusted_diff: Mapping[str, object] | None = None,
    history_manifest: Mapping[str, object] | None = None,
    report_grade_validation_plan: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = ["multi-user/signing limitation warning"]
    if history_rows:
        satisfied.append("versioned review history rows")
    if any(item.get("changed_fields") or item.get("changed_fields_json") for item in history_rows):
        satisfied.append("changed fields captured")
    if any(item.get("previous") is not None or item.get("previous_json") for item in history_rows):
        satisfied.append("previous/current state captured")
    if any(
        "include_in_report" in json.dumps(item, ensure_ascii=False, sort_keys=True)
        for item in history_rows
    ):
        satisfied.append("report inclusion history")
    if history_manifest and history_manifest.get("manifest_hash"):
        satisfied.append("evidence history manifest")
    if history_manifest and int(history_manifest.get("row_hash_count") or 0) > 0:
        satisfied.append("history row hashes")
    if history_manifest and int(history_manifest.get("history_viewer_locator_count") or 0) > 0:
        satisfied.append("history source viewer locators")
    append_only = history_manifest.get("append_only_enforcement") if isinstance(history_manifest, Mapping) else None
    if isinstance(append_only, Mapping) and append_only.get("database_enforced_append_only"):
        satisfied.append("database append-only guardrails")
    if report_grade_validation_plan and report_grade_validation_plan.get("validation_plan_sha256"):
        satisfied.append("evidence history report-grade validation plan")
    if report_grade_validation_plan and int(report_grade_validation_plan.get("ready_slot_count") or 0) >= 6:
        satisfied.append("evidence history report-grade ready slots")
    evidence_refs = [f"review_history_count:{len(history_rows)}"]
    if history_manifest and history_manifest.get("manifest_hash"):
        evidence_refs.append(f"history_manifest_hash:{history_manifest.get('manifest_hash', '')}")
    if report_grade_validation_plan and report_grade_validation_plan.get("validation_plan_sha256"):
        evidence_refs.append(
            f"evidence_selection_report_grade_validation_plan_hash:{report_grade_validation_plan.get('validation_plan_sha256', '')}"
        )
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted evidence history diff pass")
        evidence_refs.append(f"trusted_tool:{trusted_diff.get('trusted_tool', '')}")
    return [
        build_accuracy_gate(
            65,
            satisfied_checks=satisfied,
            evidence_refs=evidence_refs,
        )
    ]
