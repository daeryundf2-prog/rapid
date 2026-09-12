"""Immutable audit chains and report defensibility assessments."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Mapping, Sequence

from .constants import (
    FUNCTIONAL_DEFENSIBILITY_BATCH_ID,
    IMMUTABLE_AUDIT_GAP_ID,
    IMMUTABLE_AUDIT_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    IMMUTABLE_AUDIT_TRUSTED_DIFF_BLOCKER_88,
    LEGAL_LIMITATION_GAP_ID,
    LEGAL_LIMITATION_REPORT_GRADE_BLOCKERS,
    LEGAL_LIMITATION_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    LEGAL_LIMITATION_TRUSTED_DIFF_BLOCKER_93,
    PARSER_CONFIDENCE_GAP_ID,
    PARSER_CONFIDENCE_REPORT_GRADE_BLOCKERS,
    PARSER_CONFIDENCE_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    PARSER_CONFIDENCE_TRUSTED_DIFF_BLOCKER_91,
    REPORT_REPRODUCIBILITY_GAP_ID,
    REPORT_REPRODUCIBILITY_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    REPORT_REPRODUCIBILITY_TRUSTED_DIFF_BLOCKER_89,
    VALIDATION_WARNING_REPORT_GRADE_BLOCKERS,
    VALIDATION_WARNING_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    VALIDATION_WARNING_TRUSTED_DIFF_BLOCKER_92,
    VALIDATION_WARNING_UX_GAP_ID,
)
from .helpers import (
    optional_float,
    parse_json_object,
    stable_payload_sha256,
)
from .trusted_diffs import (
    immutable_audit_core_accuracy_gates,
    legal_limitation_core_accuracy_gates,
    missing_integrity_trusted_diff,
    missing_report_quality_trusted_diff,
    parser_confidence_core_accuracy_gates,
    report_reproducibility_core_accuracy_gates,
    validation_warning_ux_core_accuracy_gates,
)

__all__ = [
    "audit_integrity_functional_profile",
    "build_audit_actor_action_matrix",
    "build_audit_hash_chain_manifest",
    "build_audit_integrity_chain",
    "build_audit_replay_manifest",
    "build_immutable_audit_report_grade_validation_plan",
    "build_legal_limitation_manifest",
    "build_legal_limitation_report_grade_validation_plan",
    "build_legal_limitations_assessment",
    "build_parser_confidence_calibration_manifest",
    "build_parser_confidence_report_grade_validation_plan",
    "build_report_item_legal_limitations",
    "build_report_item_validation_assessment",
    "build_report_replay_manifest",
    "build_report_reproducibility_manifest",
    "build_report_reproducibility_report_grade_validation_plan",
    "build_validation_warning_checklist_manifest",
    "build_validation_warning_report_grade_validation_plan",
    "legal_limitation_detail",
    "parser_confidence_band",
    "parser_reportability_score",
    "validation_warning_detail",
]


def build_audit_hash_chain_manifest(events: Sequence[Mapping[str, object]], *, head_hash: str) -> dict[str, object]:
    actor_action_matrix = build_audit_actor_action_matrix(events)
    manifest_core = {
        "profile_version": "audit-hash-chain-manifest-v1",
        "item_number": 88,
        "event_count": len(events),
        "head_hash": head_hash,
        "event_hashes": [str(item.get("event_hash") or "") for item in events],
        "previous_event_hashes": [str(item.get("previous_event_hash") or "") for item in events],
        "citation_ids": sorted(str(item.get("citation_id") or "") for item in events if item.get("citation_id")),
        "actions": sorted({str(item.get("action") or "") for item in events if item.get("action")}),
        "actor_action_matrix": actor_action_matrix,
        "actor_action_matrix_hash": actor_action_matrix["matrix_hash"],
        "commercial_gap_ids": [IMMUTABLE_AUDIT_GAP_ID],
        "commercial_claim_allowed": False,
        "external_notarization_required": True,
    }
    manifest_hash = hashlib.sha256(
        json.dumps(manifest_core, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return {**manifest_core, "manifest_hash": manifest_hash}


def build_audit_actor_action_matrix(events: Sequence[Mapping[str, object]]) -> dict[str, object]:
    rows = []
    for index, item in enumerate(events):
        row = {
            "index": index,
            "citation_id": str(item.get("citation_id") or ""),
            "actor": str(item.get("actor") or ""),
            "action": str(item.get("action") or ""),
            "target_type": str(item.get("target_type") or ""),
            "target_id": str(item.get("target_id") or ""),
            "timestamp_present": bool(item.get("timestamp")),
            "event_hash_present": bool(item.get("event_hash")),
            "previous_event_hash_present": "previous_event_hash" in item,
        }
        rows.append({**row, "row_hash": stable_payload_sha256(row)})
    matrix_core = {
        "profile_version": "audit-actor-action-matrix-v1",
        "item_number": 88,
        "event_count": len(rows),
        "rows": rows,
        "all_rows_actor_action_timestamp": bool(rows) and all(
            bool(row["actor"]) and bool(row["action"]) and bool(row["timestamp_present"]) for row in rows
        ),
    }
    return {**matrix_core, "matrix_hash": stable_payload_sha256(matrix_core)}


def build_audit_replay_manifest(events: Sequence[Mapping[str, object]], *, expected_head_hash: str) -> dict[str, object]:
    previous_hash = ""
    replay_rows = []
    mismatch_indexes = []
    for index, event in enumerate(events):
        replay_core = {
            key: value
            for key, value in event.items()
            if key != "event_hash"
        }
        recomputed_hash = stable_payload_sha256(replay_core)
        stored_hash = str(event.get("event_hash") or "")
        expected_previous = previous_hash
        stored_previous = str(event.get("previous_event_hash") or "")
        matches = stored_hash == recomputed_hash and stored_previous == expected_previous
        if not matches:
            mismatch_indexes.append(index)
        replay_rows.append(
            {
                "index": index,
                "citation_id": str(event.get("citation_id") or ""),
                "stored_event_hash": stored_hash,
                "recomputed_event_hash": recomputed_hash,
                "stored_previous_event_hash": stored_previous,
                "expected_previous_event_hash": expected_previous,
                "chain_link_valid": matches,
            }
        )
        previous_hash = stored_hash
    replay_matrix_hash = stable_payload_sha256({"profile": "audit-replay-row-matrix-v1", "rows": replay_rows})
    manifest_core: dict[str, object] = {
        "profile_version": "audit-replay-manifest-v1",
        "item_number": 44,
        "batch_id": FUNCTIONAL_DEFENSIBILITY_BATCH_ID,
        "gap_id": "#44",
        "commercial_gap_ids": [IMMUTABLE_AUDIT_GAP_ID],
        "event_count": len(events),
        "expected_head_hash": expected_head_hash,
        "recomputed_head_hash": previous_hash,
        "head_hash_matches": previous_hash == expected_head_hash,
        "chain_valid": not mismatch_indexes and previous_hash == expected_head_hash,
        "mismatch_indexes": mismatch_indexes,
        "replay_rows": replay_rows[:100],
        "replay_row_count": len(replay_rows),
        "replay_matrix_hash": replay_matrix_hash,
        "external_notarization_required": True,
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_immutable_audit_report_grade_validation_plan(
    *,
    events: Sequence[Mapping[str, object]],
    head_hash: str,
    audit_hash_chain_manifest: Mapping[str, object],
    audit_replay_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None,
) -> dict[str, object]:
    trusted_status = str(trusted_diff.get("status") or "missing") if trusted_diff else "missing"
    events_with_hash = sum(1 for item in events if item.get("event_hash"))
    events_with_previous = sum(1 for item in events if "previous_event_hash" in item)
    events_with_actor_action_time = sum(
        1
        for item in events
        if item.get("actor") and item.get("action") and item.get("target_type") and item.get("timestamp")
    )
    ready_slots = [
        {
            "slot_id": "audit-event-inventory",
            "status": "complete",
            "evidence": {
                "event_count": len(events),
                "events_with_actor_action_time": events_with_actor_action_time,
            },
        },
        {
            "slot_id": "audit-event-hash-chain",
            "status": "complete",
            "evidence": {
                "events_with_event_hash": events_with_hash,
                "events_with_previous_hash": events_with_previous,
                "head_hash": head_hash,
            },
        },
        {
            "slot_id": "audit-hash-chain-manifest",
            "status": "complete",
            "evidence": {
                "manifest_hash": audit_hash_chain_manifest.get("manifest_hash"),
                "actor_action_matrix_hash": audit_hash_chain_manifest.get("actor_action_matrix_hash"),
            },
        },
        {
            "slot_id": "audit-replay-manifest",
            "status": "complete",
            "evidence": {
                "manifest_hash": audit_replay_manifest.get("manifest_hash"),
                "replay_matrix_hash": audit_replay_manifest.get("replay_matrix_hash"),
                "chain_valid": bool(audit_replay_manifest.get("chain_valid")),
            },
        },
        {
            "slot_id": "audit-replay-head-validation",
            "status": "complete",
            "evidence": {
                "expected_head_hash": audit_replay_manifest.get("expected_head_hash"),
                "recomputed_head_hash": audit_replay_manifest.get("recomputed_head_hash"),
                "head_hash_matches": bool(audit_replay_manifest.get("head_hash_matches")),
            },
        },
        {
            "slot_id": "audit-trusted-diff-disclosure",
            "status": "complete",
            "evidence": {
                "trusted_diff_status": trusted_status,
                "trusted_tool": str((trusted_diff or {}).get("trusted_tool") or ""),
            },
        },
    ]
    blocking_slots: list[dict[str, object]] = []
    if not events:
        blocking_slots.append(
            {
                "slot_id": "audit-events-present",
                "status": "blocked",
                "blocker": "audit-event-chain-required",
                "required_evidence": "append-only audit events for review, export, report, and settings changes",
            }
        )
    if events_with_hash != len(events) or events_with_previous != len(events) or not head_hash:
        blocking_slots.append(
            {
                "slot_id": "audit-hash-chain-completeness",
                "status": "blocked",
                "blocker": "audit-hash-chain-completeness-required",
                "required_evidence": "event_hash, previous_event_hash, and head hash for every audit chain export",
            }
        )
    if events_with_actor_action_time != len(events):
        blocking_slots.append(
            {
                "slot_id": "audit-actor-action-time-completeness",
                "status": "blocked",
                "blocker": "audit-actor-action-time-completeness-required",
                "required_evidence": "actor, action, target, and timestamp on every audit event",
            }
        )
    if not bool(audit_replay_manifest.get("chain_valid")):
        blocking_slots.append(
            {
                "slot_id": "audit-replay-chain-valid",
                "status": "blocked",
                "blocker": "audit-replay-chain-validation-required",
                "required_evidence": "replayed event hash chain must match stored head hash",
            }
        )
    if trusted_status != "pass":
        blocking_slots.append(
            {
                "slot_id": "audit-trusted-hash-chain-manifest-diff",
                "status": "external-required",
                "blocker": IMMUTABLE_AUDIT_TRUSTED_DIFF_BLOCKER_88,
                "required_evidence": "trusted audit hash-chain manifest diff covering chain manifest, replay manifest, actor/action matrix, and replay matrix",
            }
        )
    blocking_slots.extend(
        [
            {
                "slot_id": "database-level-audit-append-only",
                "status": "external-required",
                "blocker": "database-level-audit-append-only-required",
                "required_evidence": "database constraints/triggers or storage policy preventing audit_event update/delete after creation",
            },
            {
                "slot_id": "external-audit-chain-notarization",
                "status": "external-required",
                "blocker": "external-audit-chain-notarization-required",
                "required_evidence": "external timestamp, signing, or notarization proof for the exported audit chain head",
            },
            {
                "slot_id": "signed-audit-export-bundle",
                "status": "external-required",
                "blocker": "signed-audit-export-bundle-required",
                "required_evidence": "signed bundle containing audit export, manifests, hashes, and replay proof",
            },
            {
                "slot_id": "multi-user-identity-binding",
                "status": "external-required",
                "blocker": "multi-user-identity-binding-required",
                "required_evidence": "authenticated user identity mapping and role source for every audit actor",
            },
            {
                "slot_id": "audit-retention-policy",
                "status": "external-required",
                "blocker": "audit-retention-policy-required",
                "required_evidence": "case/lab retention policy for audit logs, export bundles, and notarization proofs",
            },
        ]
    )
    plan_core: dict[str, object] = {
        "profile_version": IMMUTABLE_AUDIT_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 88,
        "commercial_gap_ids": [IMMUTABLE_AUDIT_GAP_ID],
        "plan_context": "case-db-report-export",
        "audit_hash_chain_manifest_hash": audit_hash_chain_manifest.get("manifest_hash"),
        "audit_replay_manifest_hash": audit_replay_manifest.get("manifest_hash"),
        "actor_action_matrix_hash": audit_hash_chain_manifest.get("actor_action_matrix_hash"),
        "replay_matrix_hash": audit_replay_manifest.get("replay_matrix_hash"),
        "trusted_diff_status": trusted_status,
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "blockers": sorted({str(slot.get("blocker") or "") for slot in blocking_slots if slot.get("blocker")}),
        "commercial_claim_allowed": False,
        "reporting_boundary": "This plan makes export-time audit chains reproducible and reviewable, but immutable/court claims require database append-only controls, external notarization/signing, identity binding, retention policy, and trusted-chain evidence.",
    }
    return {**plan_core, "validation_plan_sha256": stable_payload_sha256(plan_core)}


def build_report_replay_manifest(
    *,
    stable_payload_sha256_value: str,
    items: Sequence[Mapping[str, object]],
    citation_index: Sequence[Mapping[str, object]],
    deterministic_sort: str,
    volatile_fields: Sequence[str],
) -> dict[str, object]:
    item_row_hashes = [
        stable_payload_sha256({"row_type": "report_item", "row": item})
        for item in items
    ]
    citation_row_hashes = [
        stable_payload_sha256({"row_type": "citation_index", "row": item})
        for item in citation_index
    ]
    row_hash_set_hash = stable_payload_sha256(
        {
            "item_row_hashes": item_row_hashes,
            "citation_row_hashes": citation_row_hashes,
        }
    )
    replay_contract = {
        "deterministic_sort": deterministic_sort,
        "volatile_fields": list(volatile_fields),
        "stable_item_count": len(items),
        "citation_count": len(citation_index),
        "row_hash_set_hash": row_hash_set_hash,
    }
    manifest_core = {
        "profile_version": "report-replay-manifest-v1",
        "item_number": 89,
        "stable_payload_sha256": stable_payload_sha256_value,
        "stable_item_count": len(items),
        "citation_count": len(citation_index),
        "item_row_hashes": item_row_hashes,
        "citation_row_hashes": citation_row_hashes,
        "row_hash_set_hash": row_hash_set_hash,
        "replay_contract": replay_contract,
        "replay_contract_hash": stable_payload_sha256(replay_contract),
        "deterministic_sort": deterministic_sort,
        "volatile_fields": list(volatile_fields),
        "commercial_gap_ids": [REPORT_REPRODUCIBILITY_GAP_ID],
        "commercial_claim_allowed": False,
        "cross_platform_replay_required": True,
    }
    manifest_hash = hashlib.sha256(
        json.dumps(manifest_core, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return {**manifest_core, "manifest_hash": manifest_hash}


def parser_confidence_band(parser_confidence: object) -> str:
    score = optional_float(parser_confidence)
    if score is None:
        return "missing"
    if score >= 0.85:
        return "high"
    if score >= 0.6:
        return "medium"
    return "low-validation-required"


def parser_reportability_score(
    *,
    parser_confidence: object,
    reportability: str,
    coverage_status: str,
    warnings: Sequence[str],
    evidence_strength: str,
) -> int:
    score = 0
    confidence = optional_float(parser_confidence)
    if confidence is not None:
        score += round(max(0.0, min(1.0, confidence)) * 40)
    if reportability in {"reportable", "reviewed-reportable", "reviewed-report-candidate"}:
        score += 20
    elif reportability:
        score += 8
    if coverage_status in {"implemented", "fixture-backed-baseline", "validated"}:
        score += 15
    elif coverage_status:
        score += 6
    if evidence_strength:
        score += 15
    score += max(0, 10 - min(len(warnings), 10))
    return min(100, score)


def build_parser_confidence_calibration_manifest(
    *,
    parser_confidence: object,
    reportability: str,
    coverage_status: str,
    warnings: Sequence[str],
    evidence_strength: str,
) -> dict[str, object]:
    confidence_score = optional_float(parser_confidence)
    band = parser_confidence_band(parser_confidence)
    reportability_score = parser_reportability_score(
        parser_confidence=parser_confidence,
        reportability=reportability,
        coverage_status=coverage_status,
        warnings=warnings,
        evidence_strength=evidence_strength,
    )
    manifest_core = {
        "profile_version": "parser-confidence-calibration-manifest-v1",
        "item_number": 91,
        "parser_confidence": confidence_score,
        "confidence_band": band,
        "reportability": reportability,
        "coverage_status": coverage_status,
        "warning_count": len(warnings),
        "warnings": list(warnings),
        "evidence_strength": evidence_strength,
        "reportability_score": reportability_score,
        "calibration_basis": [
            "parser-provided-confidence-or-review-default",
            "reportability-state",
            "coverage-status",
            "validation-warning-count",
            "evidence-strength",
        ],
        "commercial_gap_ids": [PARSER_CONFIDENCE_GAP_ID],
        "commercial_claim_allowed": False,
        "trusted_calibration_required": True,
    }
    field_presence = {
        "parser_confidence": confidence_score is not None,
        "confidence_band": bool(band),
        "reportability": bool(reportability),
        "coverage_status": bool(coverage_status),
        "warning_count": True,
        "evidence_strength": bool(evidence_strength),
        "reportability_score": True,
    }
    manifest_core["calibration_field_presence"] = field_presence
    manifest_core["calibration_field_presence_hash"] = stable_payload_sha256(field_presence)
    manifest_hash = hashlib.sha256(
        json.dumps(manifest_core, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return {**manifest_core, "manifest_hash": manifest_hash}


def build_parser_confidence_report_grade_validation_plan(
    *,
    parser_confidence: object,
    reportability: str,
    coverage_status: str,
    warnings: Sequence[str],
    evidence_strength: str,
    confidence_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None,
) -> dict[str, object]:
    trusted_status = str(trusted_diff.get("status") or "missing") if trusted_diff else "missing"
    confidence_score = optional_float(parser_confidence)
    calibration_field_presence = (
        confidence_manifest.get("calibration_field_presence")
        if isinstance(confidence_manifest.get("calibration_field_presence"), Mapping)
        else {}
    )
    ready_slots = [
        {
            "slot_id": "parser-confidence-band-and-score",
            "status": "complete",
            "evidence": {
                "parser_confidence": confidence_score,
                "confidence_band": str(confidence_manifest.get("confidence_band") or ""),
            },
        },
        {
            "slot_id": "reportability-and-score",
            "status": "complete",
            "evidence": {
                "reportability": reportability,
                "reportability_score": confidence_manifest.get("reportability_score"),
            },
        },
        {
            "slot_id": "coverage-warning-evidence-strength",
            "status": "complete",
            "evidence": {
                "coverage_status": coverage_status,
                "warning_count": len(warnings),
                "evidence_strength": evidence_strength,
            },
        },
        {
            "slot_id": "calibration-manifest",
            "status": "complete",
            "evidence": {
                "manifest_hash": str(confidence_manifest.get("manifest_hash") or ""),
                "calibration_field_presence_hash": str(
                    confidence_manifest.get("calibration_field_presence_hash") or ""
                ),
            },
        },
        {
            "slot_id": "calibration-basis",
            "status": "complete",
            "evidence": {
                "basis": list(confidence_manifest.get("calibration_basis") or []),
                "field_presence": dict(calibration_field_presence),
            },
        },
        {
            "slot_id": "trusted-calibration-diff-disclosure",
            "status": "complete",
            "evidence": {
                "trusted_diff_status": trusted_status,
                "trusted_tool": str((trusted_diff or {}).get("trusted_tool") or ""),
            },
        },
    ]
    blocking_slots: list[dict[str, object]] = []
    if confidence_score is None:
        blocking_slots.append(
            {
                "slot_id": "parser-confidence-present",
                "status": "blocked",
                "blocker": "parser-confidence-required",
                "required_evidence": "parser confidence value for every report item",
            }
        )
    if not reportability:
        blocking_slots.append(
            {
                "slot_id": "reportability-state",
                "status": "blocked",
                "blocker": "reportability-state-required",
                "required_evidence": "reportability decision for every report item",
            }
        )
    if not coverage_status:
        blocking_slots.append(
            {
                "slot_id": "coverage-status",
                "status": "blocked",
                "blocker": "coverage-status-required",
                "required_evidence": "parser coverage status for every report item",
            }
        )
    if not evidence_strength:
        blocking_slots.append(
            {
                "slot_id": "evidence-strength",
                "status": "blocked",
                "blocker": "evidence-strength-required",
                "required_evidence": "evidence-strength classification for every report item",
            }
        )
    if not confidence_manifest.get("manifest_hash") or not confidence_manifest.get("calibration_field_presence_hash"):
        blocking_slots.append(
            {
                "slot_id": "confidence-calibration-manifest-complete",
                "status": "blocked",
                "blocker": "parser-confidence-calibration-manifest-required",
                "required_evidence": "calibration manifest hash and field-presence hash",
            }
        )
    missing_fields = [key for key, present in calibration_field_presence.items() if not present]
    if missing_fields:
        blocking_slots.append(
            {
                "slot_id": "calibration-field-completeness",
                "status": "blocked",
                "blocker": "parser-confidence-calibration-field-completeness-required",
                "required_evidence": "all calibration field-presence entries satisfied",
                "missing_fields": missing_fields,
            }
        )
    if trusted_status != "pass":
        blocking_slots.append(
            {
                "slot_id": "trusted-parser-confidence-calibration-diff",
                "status": "external-required",
                "blocker": PARSER_CONFIDENCE_TRUSTED_DIFF_BLOCKER_91,
                "required_evidence": "trusted calibration manifest diff over confidence, band, score, reportability, coverage, warnings, and evidence strength",
            }
        )
    blocking_slots.extend(
        [
            {
                "slot_id": "parser-specific-calibration-table",
                "status": "external-required",
                "blocker": "parser-specific-calibration-table-required",
                "required_evidence": "per-parser confidence calibration table and threshold rationale",
            },
            {
                "slot_id": "cross-tool-confidence-validation",
                "status": "external-required",
                "blocker": "cross-tool-confidence-validation-required",
                "required_evidence": "cross-tool confidence comparison for representative parser families",
            },
            {
                "slot_id": "low-confidence-fp-fn-corpus",
                "status": "external-required",
                "blocker": "low-confidence-fp-fn-corpus-required",
                "required_evidence": "false-positive/false-negative corpus covering low and medium confidence bands",
            },
            {
                "slot_id": "reportability-threshold-review",
                "status": "external-required",
                "blocker": "reportability-threshold-review-required",
                "required_evidence": "reviewed thresholds mapping confidence bands to reportability wording",
            },
            {
                "slot_id": "release-parser-confidence-policy-lock",
                "status": "external-required",
                "blocker": "release-parser-confidence-policy-lock-required",
                "required_evidence": "release-build parser confidence policy/version lock",
            },
        ]
    )
    plan_core: dict[str, object] = {
        "profile_version": PARSER_CONFIDENCE_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 91,
        "commercial_gap_ids": [PARSER_CONFIDENCE_GAP_ID],
        "plan_context": "case-db-report-item-validation-assessment",
        "parser_confidence": confidence_score,
        "confidence_band": str(confidence_manifest.get("confidence_band") or ""),
        "reportability": reportability,
        "coverage_status": coverage_status,
        "warning_count": len(warnings),
        "evidence_strength": evidence_strength,
        "reportability_score": confidence_manifest.get("reportability_score"),
        "calibration_manifest_hash": str(confidence_manifest.get("manifest_hash") or ""),
        "calibration_field_presence_hash": str(confidence_manifest.get("calibration_field_presence_hash") or ""),
        "trusted_diff_status": trusted_status,
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "external_blocker_catalog": list(PARSER_CONFIDENCE_REPORT_GRADE_BLOCKERS),
        "blockers": sorted({str(slot.get("blocker") or "") for slot in blocking_slots if slot.get("blocker")}),
        "commercial_claim_allowed": False,
        "reporting_boundary": "This plan makes one report item confidence-scored and reviewable, but commercial parser-confidence claims require parser-specific calibration tables, cross-tool validation, low-confidence FP/FN corpus, reportability threshold review, release policy locks, and trusted calibration manifests.",
    }
    return {**plan_core, "validation_plan_sha256": stable_payload_sha256(plan_core)}


def validation_warning_detail(warning: str) -> dict[str, object]:
    severity = "medium"
    category = "general-validation"
    action = "Review source evidence and parser limitations before reporting."
    badge = "validation-required"
    if warning == "source-hash-not-present-in-record":
        severity = "high"
        category = "source-integrity"
        action = "Attach or calculate source/record hashes before final report use."
        badge = "hash-missing"
    elif warning == "parser-confidence-not-present":
        severity = "high"
        category = "parser-confidence"
        action = "Attach parser confidence or mark the row as validation-required."
        badge = "confidence-missing"
    elif warning.startswith("reportability-"):
        category = "reportability"
        action = "Confirm reportability wording and analyst review status before inclusion."
        badge = "reportability-review"
    elif warning.startswith("coverage-"):
        category = "coverage"
        action = "Validate parser coverage against fixture/trusted-tool evidence."
        badge = "coverage-review"
    elif warning == "source-parser-validation-required":
        severity = "high"
        category = "parser-validation"
        action = "Resolve parser validation-required state with source evidence or trusted diff."
        badge = "parser-validation"
    elif warning == "commercial-grade-ready-false":
        severity = "high"
        category = "commercial-readiness"
        action = "Keep commercial/report-defensible claims blocked until validation evidence is attached."
        badge = "commercial-blocked"
    return {
        "warning": warning,
        "severity": severity,
        "category": category,
        "badge": badge,
        "recommended_action": action,
    }


def build_validation_warning_checklist_manifest(warnings: Sequence[str]) -> dict[str, object]:
    details = [validation_warning_detail(str(warning)) for warning in warnings]
    severity_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    for item in details:
        severity = str(item["severity"])
        category = str(item["category"])
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        category_counts[category] = category_counts.get(category, 0) + 1
    manifest_core = {
        "profile_version": "validation-warning-checklist-manifest-v1",
        "item_number": 92,
        "warning_count": len(details),
        "warnings": details,
        "severity_counts": severity_counts,
        "category_counts": category_counts,
        "ux_badges": sorted({str(item["badge"]) for item in details}),
        "validation_required": bool(details),
        "commercial_gap_ids": [VALIDATION_WARNING_UX_GAP_ID],
        "commercial_claim_allowed": False,
        "trusted_checklist_required": True,
    }
    action_matrix = [
        {
            "warning": str(item.get("warning") or ""),
            "severity": str(item.get("severity") or ""),
            "category": str(item.get("category") or ""),
            "badge": str(item.get("badge") or ""),
            "recommended_action_hash": stable_payload_sha256(str(item.get("recommended_action") or "")),
        }
        for item in details
    ]
    manifest_core["warning_action_matrix"] = action_matrix
    manifest_core["warning_action_matrix_hash"] = stable_payload_sha256(action_matrix)
    manifest_hash = hashlib.sha256(
        json.dumps(manifest_core, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return {**manifest_core, "manifest_hash": manifest_hash}


def build_validation_warning_report_grade_validation_plan(
    *,
    warnings: Sequence[str],
    warning_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None,
) -> dict[str, object]:
    trusted_status = str(trusted_diff.get("status") or "missing") if trusted_diff else "missing"
    warning_details = (
        warning_manifest.get("warnings")
        if isinstance(warning_manifest.get("warnings"), list)
        else []
    )
    ux_badges = (
        warning_manifest.get("ux_badges")
        if isinstance(warning_manifest.get("ux_badges"), list)
        else []
    )
    severity_counts = (
        warning_manifest.get("severity_counts")
        if isinstance(warning_manifest.get("severity_counts"), Mapping)
        else {}
    )
    category_counts = (
        warning_manifest.get("category_counts")
        if isinstance(warning_manifest.get("category_counts"), Mapping)
        else {}
    )
    action_matrix = (
        warning_manifest.get("warning_action_matrix")
        if isinstance(warning_manifest.get("warning_action_matrix"), list)
        else []
    )
    ready_slots = [
        {
            "slot_id": "warning-reasons-and-details",
            "status": "complete",
            "evidence": {
                "warning_count": len(warnings),
                "detail_count": len(warning_details),
            },
        },
        {
            "slot_id": "severity-and-category-counts",
            "status": "complete",
            "evidence": {
                "severity_counts": dict(severity_counts),
                "category_counts": dict(category_counts),
            },
        },
        {
            "slot_id": "warning-ux-badges",
            "status": "complete",
            "evidence": {
                "ux_badges": list(ux_badges),
                "badge_count": len(ux_badges),
            },
        },
        {
            "slot_id": "warning-action-matrix",
            "status": "complete",
            "evidence": {
                "warning_action_matrix_hash": str(warning_manifest.get("warning_action_matrix_hash") or ""),
                "action_count": len(action_matrix),
            },
        },
        {
            "slot_id": "validation-required-state",
            "status": "complete",
            "evidence": {
                "validation_required": bool(warning_manifest.get("validation_required")),
                "commercial_claim_allowed": bool(warning_manifest.get("commercial_claim_allowed")),
            },
        },
        {
            "slot_id": "warning-checklist-manifest",
            "status": "complete",
            "evidence": {
                "manifest_hash": str(warning_manifest.get("manifest_hash") or ""),
                "trusted_checklist_required": bool(warning_manifest.get("trusted_checklist_required")),
            },
        },
        {
            "slot_id": "trusted-warning-checklist-diff-disclosure",
            "status": "complete",
            "evidence": {
                "trusted_diff_status": trusted_status,
                "trusted_tool": str((trusted_diff or {}).get("trusted_tool") or ""),
            },
        },
    ]
    blocking_slots: list[dict[str, object]] = []
    if len(warning_details) != len(warnings):
        blocking_slots.append(
            {
                "slot_id": "warning-detail-completeness",
                "status": "blocked",
                "blocker": "warning-detail-completeness-required",
                "required_evidence": "warning detail metadata for every warning reason",
            }
        )
    if warnings and not ux_badges:
        blocking_slots.append(
            {
                "slot_id": "warning-badge-presence",
                "status": "blocked",
                "blocker": "warning-badge-presence-required",
                "required_evidence": "UX badge for every validation warning family",
            }
        )
    if not warning_manifest.get("manifest_hash") or not warning_manifest.get("warning_action_matrix_hash"):
        blocking_slots.append(
            {
                "slot_id": "warning-checklist-manifest-complete",
                "status": "blocked",
                "blocker": "validation-warning-checklist-manifest-required",
                "required_evidence": "warning checklist manifest hash and action matrix hash",
            }
        )
    if trusted_status != "pass":
        blocking_slots.append(
            {
                "slot_id": "trusted-validation-warning-checklist-diff",
                "status": "external-required",
                "blocker": VALIDATION_WARNING_TRUSTED_DIFF_BLOCKER_92,
                "required_evidence": "trusted warning checklist diff over warning reasons, badges, actions, and severity/category counts",
            }
        )
    blocking_slots.extend(
        [
            {
                "slot_id": "all-table-warning-badge-coverage",
                "status": "external-required",
                "blocker": "all-table-warning-badge-coverage-required",
                "required_evidence": "warning badges visible in every artifact/search/report table that can expose partial evidence",
            },
            {
                "slot_id": "warning-ux-e2e",
                "status": "external-required",
                "blocker": "warning-ux-e2e-required",
                "required_evidence": "end-to-end UX checks proving warnings persist from table row to detail view to report export",
            },
            {
                "slot_id": "report-template-warning-rendering-review",
                "status": "external-required",
                "blocker": "report-template-warning-rendering-review-required",
                "required_evidence": "final report template review proving warning badges/text are visible and not collapsed away",
            },
            {
                "slot_id": "warning-action-playbook-review",
                "status": "external-required",
                "blocker": "warning-action-playbook-review-required",
                "required_evidence": "forensic lead review of recommended actions and escalation wording per warning family",
            },
            {
                "slot_id": "accessibility-warning-badge-review",
                "status": "external-required",
                "blocker": "accessibility-warning-badge-review-required",
                "required_evidence": "accessibility review for warning badge color, text, and keyboard/screen-reader exposure",
            },
        ]
    )
    plan_core: dict[str, object] = {
        "profile_version": VALIDATION_WARNING_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 92,
        "commercial_gap_ids": [VALIDATION_WARNING_UX_GAP_ID],
        "plan_context": "case-db-report-item-validation-warning-ux",
        "warning_count": len(warnings),
        "warning_manifest_hash": str(warning_manifest.get("manifest_hash") or ""),
        "warning_action_matrix_hash": str(warning_manifest.get("warning_action_matrix_hash") or ""),
        "ux_badges": list(ux_badges),
        "severity_counts": dict(severity_counts),
        "category_counts": dict(category_counts),
        "trusted_diff_status": trusted_status,
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "external_blocker_catalog": list(VALIDATION_WARNING_REPORT_GRADE_BLOCKERS),
        "blockers": sorted({str(slot.get("blocker") or "") for slot in blocking_slots if slot.get("blocker")}),
        "commercial_claim_allowed": False,
        "reporting_boundary": "This plan makes validation warnings visible in the export payload, but commercial UX claims require all-table badge coverage, e2e warning persistence, report-template review, action-playbook review, accessibility review, and trusted checklist manifests.",
    }
    return {**plan_core, "validation_plan_sha256": stable_payload_sha256(plan_core)}


def build_audit_integrity_chain(
    connection: sqlite3.Connection,
    case_id: str,
    *,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    rows = connection.execute(
        """
        SELECT citation_id, actor, action, target_type, target_id, timestamp,
               tool_name, tool_version, params_json, result, error
        FROM audit_event
        WHERE case_id = ?
        ORDER BY timestamp ASC, id ASC
        """,
        (case_id,),
    ).fetchall()
    events = []
    previous_hash = ""
    for row in rows:
        event = {
            "citation_id": str(row["citation_id"]),
            "actor": str(row["actor"] or ""),
            "action": str(row["action"] or ""),
            "target_type": str(row["target_type"] or ""),
            "target_id": str(row["target_id"] or ""),
            "timestamp": str(row["timestamp"] or ""),
            "tool_name": str(row["tool_name"] or ""),
            "tool_version": str(row["tool_version"] or ""),
            "params": parse_json_object(row["params_json"]),
            "result": str(row["result"] or ""),
            "error": str(row["error"] or ""),
            "previous_event_hash": previous_hash,
        }
        event_hash = stable_payload_sha256(event)
        event["event_hash"] = event_hash
        previous_hash = event_hash
        events.append(event)
    audit_chain_manifest = build_audit_hash_chain_manifest(events, head_hash=previous_hash)
    audit_replay_manifest = build_audit_replay_manifest(events, expected_head_hash=previous_hash)
    audit_report_grade_validation_plan = build_immutable_audit_report_grade_validation_plan(
        events=events,
        head_hash=previous_hash,
        audit_hash_chain_manifest=audit_chain_manifest,
        audit_replay_manifest=audit_replay_manifest,
        trusted_diff=trusted_diff,
    )
    blockers = []
    if not trusted_diff or trusted_diff.get("status") != "pass":
        blockers.append(IMMUTABLE_AUDIT_TRUSTED_DIFF_BLOCKER_88)
    blockers = sorted({*blockers, *audit_report_grade_validation_plan["blockers"]})
    return {
        "status": "tamper-evident-export-chain",
        "commercial_gap_ids": [IMMUTABLE_AUDIT_GAP_ID],
        "functional_priority_profile": audit_integrity_functional_profile(
            events=events,
            head_hash=previous_hash,
            audit_hash_chain_manifest=audit_chain_manifest,
            audit_replay_manifest=audit_replay_manifest,
            trusted_diff=trusted_diff,
            report_grade_validation_plan=audit_report_grade_validation_plan,
        ),
        "summary": {
            "event_count": len(events),
            "head_hash": previous_hash,
            "audit_chain_manifest_hash": audit_chain_manifest["manifest_hash"],
            "audit_replay_manifest_hash": audit_replay_manifest["manifest_hash"],
            "commercial_gap_ids": [IMMUTABLE_AUDIT_GAP_ID],
        },
        "events": events,
        "audit_hash_chain_manifest": audit_chain_manifest,
        "audit_replay_manifest": audit_replay_manifest,
        "audit_replay_manifest_hash": audit_replay_manifest["manifest_hash"],
        "immutable_audit_report_grade_validation_plan": audit_report_grade_validation_plan,
        "immutable_audit_report_grade_validation_plan_hash": audit_report_grade_validation_plan["validation_plan_sha256"],
        "report_grade_ready_slot_count": audit_report_grade_validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": audit_report_grade_validation_plan["blocking_slot_count"],
        "trusted_audit_integrity_diff": dict(trusted_diff) if trusted_diff else missing_integrity_trusted_diff(
            IMMUTABLE_AUDIT_GAP_ID,
            IMMUTABLE_AUDIT_TRUSTED_DIFF_BLOCKER_88,
            trusted_tool="audit-hash-chain-manifest",
        ),
        "core_accuracy_gates": immutable_audit_core_accuracy_gates(
            events=events,
            head_hash=previous_hash,
            audit_hash_chain_manifest=audit_chain_manifest,
            audit_replay_manifest=audit_replay_manifest,
            trusted_diff=trusted_diff,
            report_grade_validation_plan=audit_report_grade_validation_plan,
        ),
        "blockers": blockers,
        "limitations": [
            "This hash chain is generated at export time from Case DB audit rows; external notarization/signing is still required for full immutability.",
        ],
    }


def build_report_reproducibility_manifest(
    items: Sequence[Mapping[str, object]],
    citation_index: Sequence[Mapping[str, object]],
    *,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    stable_payload = {
        "items": items,
        "citation_index": citation_index,
    }
    stable_hash = stable_payload_sha256(stable_payload)
    deterministic_sort = "review include flag, updated_at, id; citation index sorted by citation_id"
    volatile_fields = ["generated_at", "database path", "case updated_at"]
    replay_manifest = build_report_replay_manifest(
        stable_payload_sha256_value=stable_hash,
        items=items,
        citation_index=citation_index,
        deterministic_sort=deterministic_sort,
        volatile_fields=volatile_fields,
    )
    reproducibility_report_grade_validation_plan = build_report_reproducibility_report_grade_validation_plan(
        stable_hash=stable_hash,
        item_count=len(items),
        citation_count=len(citation_index),
        deterministic_sort=deterministic_sort,
        volatile_fields=volatile_fields,
        report_replay_manifest=replay_manifest,
        trusted_diff=trusted_diff,
    )
    blockers = []
    if not trusted_diff or trusted_diff.get("status") != "pass":
        blockers.append(REPORT_REPRODUCIBILITY_TRUSTED_DIFF_BLOCKER_89)
    blockers = sorted({*blockers, *reproducibility_report_grade_validation_plan["blockers"]})
    return {
        "status": "deterministic-export-manifest",
        "commercial_gap_ids": [REPORT_REPRODUCIBILITY_GAP_ID],
        "stable_payload_sha256": stable_hash,
        "stable_item_count": len(items),
        "citation_count": len(citation_index),
        "deterministic_sort": deterministic_sort,
        "volatile_fields": volatile_fields,
        "report_replay_manifest": replay_manifest,
        "report_replay_manifest_hash": replay_manifest["manifest_hash"],
        "report_reproducibility_report_grade_validation_plan": reproducibility_report_grade_validation_plan,
        "report_reproducibility_report_grade_validation_plan_hash": reproducibility_report_grade_validation_plan[
            "validation_plan_sha256"
        ],
        "report_grade_ready_slot_count": reproducibility_report_grade_validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": reproducibility_report_grade_validation_plan["blocking_slot_count"],
        "trusted_reproducibility_diff": dict(trusted_diff) if trusted_diff else missing_integrity_trusted_diff(
            REPORT_REPRODUCIBILITY_GAP_ID,
            REPORT_REPRODUCIBILITY_TRUSTED_DIFF_BLOCKER_89,
            trusted_tool="report-replay-manifest",
        ),
        "core_accuracy_gates": report_reproducibility_core_accuracy_gates(
            stable_hash=stable_hash,
            item_count=len(items),
            citation_count=len(citation_index),
            report_replay_manifest=replay_manifest,
            trusted_diff=trusted_diff,
            report_grade_validation_plan=reproducibility_report_grade_validation_plan,
        ),
        "blockers": blockers,
    }


def build_report_reproducibility_report_grade_validation_plan(
    *,
    stable_hash: str,
    item_count: int,
    citation_count: int,
    deterministic_sort: str,
    volatile_fields: Sequence[str],
    report_replay_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None,
) -> dict[str, object]:
    trusted_status = str(trusted_diff.get("status") or "missing") if trusted_diff else "missing"
    ready_slots = [
        {
            "slot_id": "report-stable-payload-hash",
            "status": "complete",
            "evidence": {"stable_payload_sha256": stable_hash},
        },
        {
            "slot_id": "report-deterministic-ordering",
            "status": "complete",
            "evidence": {"deterministic_sort": deterministic_sort},
        },
        {
            "slot_id": "report-item-citation-row-hashes",
            "status": "complete",
            "evidence": {
                "item_count": item_count,
                "citation_count": citation_count,
                "item_row_hash_count": len(report_replay_manifest.get("item_row_hashes") or []),
                "citation_row_hash_count": len(report_replay_manifest.get("citation_row_hashes") or []),
            },
        },
        {
            "slot_id": "report-replay-manifest",
            "status": "complete",
            "evidence": {
                "manifest_hash": report_replay_manifest.get("manifest_hash"),
                "row_hash_set_hash": report_replay_manifest.get("row_hash_set_hash"),
            },
        },
        {
            "slot_id": "report-replay-contract",
            "status": "complete",
            "evidence": {
                "replay_contract_hash": report_replay_manifest.get("replay_contract_hash"),
                "volatile_fields": list(volatile_fields),
            },
        },
        {
            "slot_id": "report-reproducibility-trusted-diff-disclosure",
            "status": "complete",
            "evidence": {
                "trusted_diff_status": trusted_status,
                "trusted_tool": str((trusted_diff or {}).get("trusted_tool") or ""),
            },
        },
    ]
    blocking_slots: list[dict[str, object]] = []
    if not stable_hash:
        blocking_slots.append(
            {
                "slot_id": "report-stable-payload-hash-present",
                "status": "blocked",
                "blocker": "stable-payload-hash-required",
                "required_evidence": "stable payload SHA-256 for the deterministic report export",
            }
        )
    if len(report_replay_manifest.get("item_row_hashes") or []) != item_count:
        blocking_slots.append(
            {
                "slot_id": "report-item-row-hash-completeness",
                "status": "blocked",
                "blocker": "report-item-row-hash-completeness-required",
                "required_evidence": "row hash for every stable report item",
            }
        )
    if len(report_replay_manifest.get("citation_row_hashes") or []) != citation_count:
        blocking_slots.append(
            {
                "slot_id": "report-citation-row-hash-completeness",
                "status": "blocked",
                "blocker": "report-citation-row-hash-completeness-required",
                "required_evidence": "row hash for every citation index row",
            }
        )
    if not report_replay_manifest.get("manifest_hash") or not report_replay_manifest.get("replay_contract_hash"):
        blocking_slots.append(
            {
                "slot_id": "report-replay-manifest-complete",
                "status": "blocked",
                "blocker": "report-replay-manifest-completeness-required",
                "required_evidence": "report replay manifest hash and replay contract hash",
            }
        )
    if trusted_status != "pass":
        blocking_slots.append(
            {
                "slot_id": "report-trusted-replay-manifest-diff",
                "status": "external-required",
                "blocker": REPORT_REPRODUCIBILITY_TRUSTED_DIFF_BLOCKER_89,
                "required_evidence": "trusted report replay manifest diff over stable hash, counts, row hashes, and replay contract",
            }
        )
    blocking_slots.extend(
        [
            {
                "slot_id": "cross-platform-byte-for-byte-replay",
                "status": "external-required",
                "blocker": "cross-platform-byte-for-byte-replay-required",
                "required_evidence": "same input produces byte-equivalent JSON/Markdown/report artifacts on supported OS targets",
            },
            {
                "slot_id": "same-input-repeat-run-log",
                "status": "external-required",
                "blocker": "same-input-repeat-run-log-required",
                "required_evidence": "two or more same-input rerun logs showing identical stable payload/replay manifest hashes",
            },
            {
                "slot_id": "report-template-version-lock",
                "status": "external-required",
                "blocker": "report-template-version-lock-required",
                "required_evidence": "versioned report templates and schema version lock for the shipped build",
            },
            {
                "slot_id": "volatile-field-normalization-review",
                "status": "external-required",
                "blocker": "volatile-field-normalization-review-required",
                "required_evidence": "review of generated_at, path, environment, and case-updated fields excluded or normalized for replay",
            },
            {
                "slot_id": "release-build-replay-evidence",
                "status": "external-required",
                "blocker": "release-build-replay-evidence-required",
                "required_evidence": "release-build replay evidence tied to the final packaged binary/version",
            },
        ]
    )
    plan_core: dict[str, object] = {
        "profile_version": REPORT_REPRODUCIBILITY_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 89,
        "commercial_gap_ids": [REPORT_REPRODUCIBILITY_GAP_ID],
        "plan_context": "case-db-report-export",
        "stable_payload_sha256": stable_hash,
        "report_replay_manifest_hash": report_replay_manifest.get("manifest_hash"),
        "row_hash_set_hash": report_replay_manifest.get("row_hash_set_hash"),
        "replay_contract_hash": report_replay_manifest.get("replay_contract_hash"),
        "trusted_diff_status": trusted_status,
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "blockers": sorted({str(slot.get("blocker") or "") for slot in blocking_slots if slot.get("blocker")}),
        "commercial_claim_allowed": False,
        "reporting_boundary": "This plan makes one Case DB export replay-verifiable, but commercial reproducibility requires cross-platform byte-level replay, repeated run logs, template/schema locks, volatile-field review, release-build evidence, and trusted replay diffs.",
    }
    return {**plan_core, "validation_plan_sha256": stable_payload_sha256(plan_core)}


def build_report_item_validation_assessment(
    enriched: Mapping[str, object],
    *,
    parser_confidence_trusted_diff: Mapping[str, object] | None = None,
    validation_warning_trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    source_reference = enriched.get("source_reference") if isinstance(enriched.get("source_reference"), Mapping) else {}
    metadata = enriched.get("metadata") if isinstance(enriched.get("metadata"), Mapping) else {}
    warnings: list[str] = []
    parser_confidence = source_reference.get("parser_confidence") or metadata.get("parser_confidence")
    reportability = str(source_reference.get("reportability") or metadata.get("reportability") or "")
    coverage_status = str(source_reference.get("coverage_status") or metadata.get("coverage_status") or "")
    if not source_reference.get("source_hashes") and not source_reference.get("record_hashes"):
        warnings.append("source-hash-not-present-in-record")
    if not parser_confidence:
        warnings.append("parser-confidence-not-present")
    if reportability and reportability not in {"reportable", "reviewed-reportable"}:
        warnings.append(f"reportability-{reportability}")
    if coverage_status and coverage_status not in {"implemented", "fixture-backed-baseline"}:
        warnings.append(f"coverage-{coverage_status}")
    if metadata.get("validation_required") is True:
        warnings.append("source-parser-validation-required")
    if metadata.get("commercial_grade_ready") is False:
        warnings.append("commercial-grade-ready-false")
    evidence_strength = str(source_reference.get("evidence_strength") or metadata.get("evidence_strength") or "")
    confidence_manifest = build_parser_confidence_calibration_manifest(
        parser_confidence=parser_confidence,
        reportability=reportability,
        coverage_status=coverage_status,
        warnings=warnings,
        evidence_strength=evidence_strength,
    )
    warning_manifest = build_validation_warning_checklist_manifest(warnings)
    parser_confidence_report_grade_validation_plan = build_parser_confidence_report_grade_validation_plan(
        parser_confidence=parser_confidence,
        reportability=reportability,
        coverage_status=coverage_status,
        warnings=warnings,
        evidence_strength=evidence_strength,
        confidence_manifest=confidence_manifest,
        trusted_diff=parser_confidence_trusted_diff,
    )
    validation_warning_report_grade_validation_plan = build_validation_warning_report_grade_validation_plan(
        warnings=warnings,
        warning_manifest=warning_manifest,
        trusted_diff=validation_warning_trusted_diff,
    )
    blockers = [
        blocker
        for blocker, diff in (
            (PARSER_CONFIDENCE_TRUSTED_DIFF_BLOCKER_91, parser_confidence_trusted_diff),
            (VALIDATION_WARNING_TRUSTED_DIFF_BLOCKER_92, validation_warning_trusted_diff),
        )
        if not diff or diff.get("status") != "pass"
    ]
    blockers = sorted(
        {
            *blockers,
            *parser_confidence_report_grade_validation_plan["blockers"],
            *validation_warning_report_grade_validation_plan["blockers"],
        }
    )
    return {
        "commercial_gap_ids": [PARSER_CONFIDENCE_GAP_ID, VALIDATION_WARNING_UX_GAP_ID],
        "parser_confidence": parser_confidence,
        "confidence_band": confidence_manifest["confidence_band"],
        "reportability_score": confidence_manifest["reportability_score"],
        "reportability": reportability,
        "coverage_status": coverage_status,
        "evidence_strength": evidence_strength,
        "parser_confidence_calibration_manifest": confidence_manifest,
        "parser_confidence_manifest_hash": confidence_manifest["manifest_hash"],
        "calibration_field_presence_hash": confidence_manifest["calibration_field_presence_hash"],
        "parser_confidence_report_grade_validation_plan": parser_confidence_report_grade_validation_plan,
        "parser_confidence_report_grade_validation_plan_hash": parser_confidence_report_grade_validation_plan[
            "validation_plan_sha256"
        ],
        "parser_confidence_report_grade_ready_slot_count": parser_confidence_report_grade_validation_plan[
            "ready_slot_count"
        ],
        "parser_confidence_report_grade_blocking_slot_count": parser_confidence_report_grade_validation_plan[
            "blocking_slot_count"
        ],
        "validation_required": bool(warnings),
        "warnings": warnings,
        "warning_details": warning_manifest["warnings"],
        "warning_severity_counts": warning_manifest["severity_counts"],
        "warning_category_counts": warning_manifest["category_counts"],
        "warning_ux_badges": warning_manifest["ux_badges"],
        "validation_warning_checklist_manifest": warning_manifest,
        "validation_warning_manifest_hash": warning_manifest["manifest_hash"],
        "warning_action_matrix_hash": warning_manifest["warning_action_matrix_hash"],
        "validation_warning_report_grade_validation_plan": validation_warning_report_grade_validation_plan,
        "validation_warning_report_grade_validation_plan_hash": validation_warning_report_grade_validation_plan[
            "validation_plan_sha256"
        ],
        "validation_warning_report_grade_ready_slot_count": validation_warning_report_grade_validation_plan[
            "ready_slot_count"
        ],
        "validation_warning_report_grade_blocking_slot_count": validation_warning_report_grade_validation_plan[
            "blocking_slot_count"
        ],
        "trusted_parser_confidence_diff": dict(parser_confidence_trusted_diff)
        if parser_confidence_trusted_diff
        else missing_report_quality_trusted_diff(
            PARSER_CONFIDENCE_GAP_ID,
            PARSER_CONFIDENCE_TRUSTED_DIFF_BLOCKER_91,
            trusted_tool="parser-confidence-calibration",
        ),
        "trusted_validation_warning_diff": dict(validation_warning_trusted_diff)
        if validation_warning_trusted_diff
        else missing_report_quality_trusted_diff(
            VALIDATION_WARNING_UX_GAP_ID,
            VALIDATION_WARNING_TRUSTED_DIFF_BLOCKER_92,
            trusted_tool="validation-warning-checklist",
        ),
        "blockers": blockers,
        "core_accuracy_gates": [
            *parser_confidence_core_accuracy_gates(
                parser_confidence=parser_confidence,
                reportability=reportability,
                coverage_status=coverage_status,
                warnings=warnings,
                evidence_strength=evidence_strength,
                confidence_manifest=confidence_manifest,
                trusted_diff=parser_confidence_trusted_diff,
                report_grade_validation_plan=parser_confidence_report_grade_validation_plan,
            ),
            *validation_warning_ux_core_accuracy_gates(
                warnings=warnings,
                warning_manifest=warning_manifest,
                trusted_diff=validation_warning_trusted_diff,
                report_grade_validation_plan=validation_warning_report_grade_validation_plan,
            ),
        ],
        "guidance": "Resolve validation warnings and verify source evidence before using this item as a final report conclusion.",
    }


def build_report_item_legal_limitations(enriched: Mapping[str, object]) -> list[str]:
    metadata = enriched.get("metadata") if isinstance(enriched.get("metadata"), Mapping) else {}
    limitations = metadata.get("legal_limitations") or metadata.get("limitations") or metadata.get("commercial_grade_blockers")
    if isinstance(limitations, list):
        return [str(item) for item in limitations if str(item).strip()]
    source = str(enriched.get("source") or "")
    if source in {"artifacts", "indicators"}:
        return ["Artifact parser output should be validated against source evidence before testimony."]
    if source == "documents":
        return ["Indexed text can omit formatting, embedded objects, OCR uncertainty, or unsupported encodings."]
    if source == "files":
        return ["File metadata alone does not prove user intent or execution."]
    if source == "timeline":
        return ["Timeline rows require timezone and source-parser validation before final conclusions."]
    return ["Review source evidence, hashes, and parser limitations before report use."]


def legal_limitation_detail(limitation: str, *, source: str) -> dict[str, object]:
    text = str(limitation)
    lower = text.lower()
    category = "general-caution"
    scope = "report-item"
    wording_source = "rapidtriage-template"
    recommended_report_wording = text
    if "parser" in lower or "validated against source" in lower:
        category = "parser-validation"
        scope = "artifact-parser-output"
    elif "indexed text" in lower or "ocr" in lower or "formatting" in lower:
        category = "indexed-content"
        scope = "document-text-extraction"
    elif "file metadata" in lower or "intent" in lower:
        category = "metadata-interpretation"
        scope = "file-metadata"
    elif "timezone" in lower:
        category = "time-normalization"
        scope = "timeline"
    if source:
        wording_source = f"rapidtriage-{source}-template"
    return {
        "limitation": text,
        "category": category,
        "scope": scope,
        "wording_source": wording_source,
        "recommended_report_wording": recommended_report_wording,
        "requires_analyst_review": True,
        "requires_jurisdiction_review": True,
    }


def build_legal_limitation_manifest(
    *,
    limitations: Sequence[str],
    source: str,
    blockers: Sequence[str],
) -> dict[str, object]:
    details = [legal_limitation_detail(limitation, source=source) for limitation in limitations]
    category_counts: dict[str, int] = {}
    scope_counts: dict[str, int] = {}
    for item in details:
        category = str(item["category"])
        scope = str(item["scope"])
        category_counts[category] = category_counts.get(category, 0) + 1
        scope_counts[scope] = scope_counts.get(scope, 0) + 1
    manifest_core = {
        "profile_version": "legal-limitation-wording-manifest-v1",
        "item_number": 93,
        "limitation_count": len(details),
        "limitations": details,
        "category_counts": category_counts,
        "scope_counts": scope_counts,
        "blockers": list(blockers),
        "jurisdiction_review_required": True,
        "analyst_review_required": True,
        "commercial_gap_ids": [LEGAL_LIMITATION_GAP_ID],
        "commercial_claim_allowed": False,
    }
    wording_matrix = [
        {
            "category": str(item.get("category") or ""),
            "scope": str(item.get("scope") or ""),
            "wording_source": str(item.get("wording_source") or ""),
            "wording_hash": stable_payload_sha256(str(item.get("recommended_report_wording") or "")),
            "requires_analyst_review": bool(item.get("requires_analyst_review")),
            "requires_jurisdiction_review": bool(item.get("requires_jurisdiction_review")),
        }
        for item in details
    ]
    manifest_core["limitation_wording_matrix"] = wording_matrix
    manifest_core["limitation_wording_matrix_hash"] = stable_payload_sha256(wording_matrix)
    manifest_hash = hashlib.sha256(
        json.dumps(manifest_core, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return {**manifest_core, "manifest_hash": manifest_hash}


def build_legal_limitation_report_grade_validation_plan(
    *,
    limitations: Sequence[str],
    limitation_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None,
) -> dict[str, object]:
    trusted_status = str(trusted_diff.get("status") or "missing") if trusted_diff else "missing"
    limitation_details = (
        limitation_manifest.get("limitations")
        if isinstance(limitation_manifest.get("limitations"), list)
        else []
    )
    category_counts = (
        limitation_manifest.get("category_counts")
        if isinstance(limitation_manifest.get("category_counts"), Mapping)
        else {}
    )
    scope_counts = (
        limitation_manifest.get("scope_counts")
        if isinstance(limitation_manifest.get("scope_counts"), Mapping)
        else {}
    )
    wording_matrix = (
        limitation_manifest.get("limitation_wording_matrix")
        if isinstance(limitation_manifest.get("limitation_wording_matrix"), list)
        else []
    )
    ready_slots = [
        {
            "slot_id": "artifact-limitation-text-and-details",
            "status": "complete",
            "evidence": {
                "limitation_count": len(limitations),
                "detail_count": len(limitation_details),
            },
        },
        {
            "slot_id": "category-and-scope-counts",
            "status": "complete",
            "evidence": {
                "category_counts": dict(category_counts),
                "scope_counts": dict(scope_counts),
            },
        },
        {
            "slot_id": "jurisdiction-and-analyst-review-caveats",
            "status": "complete",
            "evidence": {
                "jurisdiction_review_required": bool(limitation_manifest.get("jurisdiction_review_required")),
                "analyst_review_required": bool(limitation_manifest.get("analyst_review_required")),
            },
        },
        {
            "slot_id": "wording-matrix",
            "status": "complete",
            "evidence": {
                "limitation_wording_matrix_hash": str(
                    limitation_manifest.get("limitation_wording_matrix_hash") or ""
                ),
                "wording_count": len(wording_matrix),
            },
        },
        {
            "slot_id": "legal-limitation-manifest",
            "status": "complete",
            "evidence": {
                "manifest_hash": str(limitation_manifest.get("manifest_hash") or ""),
                "profile_version": str(limitation_manifest.get("profile_version") or ""),
            },
        },
        {
            "slot_id": "commercial-claim-boundary",
            "status": "complete",
            "evidence": {
                "commercial_claim_allowed": bool(limitation_manifest.get("commercial_claim_allowed")),
                "commercial_gap_ids": list(limitation_manifest.get("commercial_gap_ids") or []),
            },
        },
        {
            "slot_id": "trusted-legal-wording-diff-disclosure",
            "status": "complete",
            "evidence": {
                "trusted_diff_status": trusted_status,
                "trusted_tool": str((trusted_diff or {}).get("trusted_tool") or ""),
            },
        },
    ]
    blocking_slots: list[dict[str, object]] = []
    if len(limitation_details) != len(limitations):
        blocking_slots.append(
            {
                "slot_id": "limitation-detail-completeness",
                "status": "blocked",
                "blocker": "limitation-detail-completeness-required",
                "required_evidence": "limitation detail metadata for every artifact limitation string",
            }
        )
    if not limitations:
        blocking_slots.append(
            {
                "slot_id": "artifact-limitation-text-present",
                "status": "blocked",
                "blocker": "artifact-limitation-text-required",
                "required_evidence": "at least one artifact-specific legal limitation statement per report item",
            }
        )
    if not limitation_manifest.get("manifest_hash") or not limitation_manifest.get("limitation_wording_matrix_hash"):
        blocking_slots.append(
            {
                "slot_id": "legal-limitation-manifest-complete",
                "status": "blocked",
                "blocker": "legal-limitation-manifest-required",
                "required_evidence": "legal limitation manifest hash and wording matrix hash",
            }
        )
    if trusted_status != "pass":
        blocking_slots.append(
            {
                "slot_id": "trusted-legal-limitation-wording-diff",
                "status": "external-required",
                "blocker": LEGAL_LIMITATION_TRUSTED_DIFF_BLOCKER_93,
                "required_evidence": "trusted legal wording diff over limitation text, categories, scopes, manifest hash, and wording matrix",
            }
        )
    blocking_slots.extend(
        [
            {
                "slot_id": "jurisdiction-approved-wording",
                "status": "external-required",
                "blocker": "jurisdiction-approved-wording-required",
                "required_evidence": "jurisdiction-specific approved limitation wording for shipped report templates",
            },
            {
                "slot_id": "formal-legal-review-signoff",
                "status": "external-required",
                "blocker": "formal-legal-review-signoff-required",
                "required_evidence": "formal legal or forensic lead signoff for wording, scope, and admissibility caveats",
            },
            {
                "slot_id": "artifact-family-limitation-corpus",
                "status": "external-required",
                "blocker": "artifact-family-limitation-corpus-required",
                "required_evidence": "fixture corpus proving every artifact family receives an appropriate limitation statement",
            },
            {
                "slot_id": "report-template-limitation-rendering-review",
                "status": "external-required",
                "blocker": "report-template-limitation-rendering-review-required",
                "required_evidence": "final report template review proving limitation text remains visible next to cited artifacts",
            },
            {
                "slot_id": "analyst-limitation-acknowledgement",
                "status": "external-required",
                "blocker": "analyst-limitation-acknowledgement-required",
                "required_evidence": "analyst workflow evidence requiring acknowledgement before final report export",
            },
        ]
    )
    plan_core: dict[str, object] = {
        "profile_version": LEGAL_LIMITATION_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 93,
        "commercial_gap_ids": [LEGAL_LIMITATION_GAP_ID],
        "plan_context": "case-db-report-item-legal-limitation",
        "limitation_count": len(limitations),
        "legal_limitation_manifest_hash": str(limitation_manifest.get("manifest_hash") or ""),
        "limitation_wording_matrix_hash": str(limitation_manifest.get("limitation_wording_matrix_hash") or ""),
        "category_counts": dict(category_counts),
        "scope_counts": dict(scope_counts),
        "trusted_diff_status": trusted_status,
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "external_blocker_catalog": list(LEGAL_LIMITATION_REPORT_GRADE_BLOCKERS),
        "blockers": sorted({str(slot.get("blocker") or "") for slot in blocking_slots if slot.get("blocker")}),
        "commercial_claim_allowed": False,
        "reporting_boundary": "This plan makes artifact limitation wording auditable in the export payload, but commercial/legal claims require jurisdiction-approved wording, formal legal signoff, artifact-family corpus coverage, report-template rendering review, analyst acknowledgement, and trusted wording manifests.",
    }
    return {**plan_core, "validation_plan_sha256": stable_payload_sha256(plan_core)}


def build_legal_limitations_assessment(
    enriched: Mapping[str, object],
    *,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    limitations = build_report_item_legal_limitations(enriched)
    source = str(enriched.get("source") or "")
    blockers = [
        "limitation-text-is-template-or-parser-provided-and-requires-analyst-review",
        "jurisdiction-specific-admissibility-language-is-operator-owned",
    ]
    if not trusted_diff or trusted_diff.get("status") != "pass":
        blockers.append(LEGAL_LIMITATION_TRUSTED_DIFF_BLOCKER_93)
    limitation_manifest = build_legal_limitation_manifest(
        limitations=limitations,
        source=source,
        blockers=blockers,
    )
    legal_limitation_report_grade_validation_plan = build_legal_limitation_report_grade_validation_plan(
        limitations=limitations,
        limitation_manifest=limitation_manifest,
        trusted_diff=trusted_diff,
    )
    blockers = sorted({*blockers, *legal_limitation_report_grade_validation_plan["blockers"]})
    return {
        "component": "artifact-legal-limitation-statement",
        "status": "present" if limitations else "missing",
        "commercial_gap_ids": [LEGAL_LIMITATION_GAP_ID],
        "limitation_count": len(limitations),
        "limitation_details": limitation_manifest["limitations"],
        "limitation_category_counts": limitation_manifest["category_counts"],
        "limitation_scope_counts": limitation_manifest["scope_counts"],
        "legal_limitation_manifest": limitation_manifest,
        "legal_limitation_manifest_hash": limitation_manifest["manifest_hash"],
        "limitation_wording_matrix_hash": limitation_manifest["limitation_wording_matrix_hash"],
        "legal_limitation_report_grade_validation_plan": legal_limitation_report_grade_validation_plan,
        "legal_limitation_report_grade_validation_plan_hash": legal_limitation_report_grade_validation_plan[
            "validation_plan_sha256"
        ],
        "legal_limitation_report_grade_ready_slot_count": legal_limitation_report_grade_validation_plan[
            "ready_slot_count"
        ],
        "legal_limitation_report_grade_blocking_slot_count": legal_limitation_report_grade_validation_plan[
            "blocking_slot_count"
        ],
        "trusted_legal_limitation_diff": dict(trusted_diff) if trusted_diff else missing_report_quality_trusted_diff(
            LEGAL_LIMITATION_GAP_ID,
            LEGAL_LIMITATION_TRUSTED_DIFF_BLOCKER_93,
            trusted_tool="legal-limitation-wording-review",
        ),
        "core_accuracy_gates": legal_limitation_core_accuracy_gates(
            limitations=limitations,
            limitation_manifest=limitation_manifest,
            trusted_diff=trusted_diff,
            report_grade_validation_plan=legal_limitation_report_grade_validation_plan,
        ),
        "ready_for_court_report": False,
        "blockers": blockers,
    }


def audit_integrity_functional_profile(
    *,
    events: Sequence[Mapping[str, object]],
    head_hash: str,
    audit_hash_chain_manifest: Mapping[str, object],
    audit_replay_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None,
    report_grade_validation_plan: Mapping[str, object] | None = None,
) -> dict[str, object]:
    events_with_hash = sum(1 for item in events if item.get("event_hash"))
    events_with_previous = sum(1 for item in events if "previous_event_hash" in item)
    failed_checks: list[str] = []
    if not events:
        failed_checks.append("audit-event-chain-empty")
    if events_with_hash != len(events):
        failed_checks.append("audit-event-hash-missing")
    if events_with_previous != len(events):
        failed_checks.append("audit-previous-hash-missing")
    if not head_hash:
        failed_checks.append("audit-head-hash-missing")
    if not audit_hash_chain_manifest.get("manifest_hash"):
        failed_checks.append("audit-chain-manifest-hash-missing")
    if not audit_replay_manifest.get("manifest_hash"):
        failed_checks.append("audit-replay-manifest-hash-missing")
    if audit_replay_manifest and not bool(audit_replay_manifest.get("chain_valid")):
        failed_checks.append("audit-replay-chain-invalid")
    if not trusted_diff or trusted_diff.get("status") != "pass":
        failed_checks.append(IMMUTABLE_AUDIT_TRUSTED_DIFF_BLOCKER_88)
    if not report_grade_validation_plan or not report_grade_validation_plan.get("validation_plan_sha256"):
        failed_checks.append("immutable-audit-report-grade-validation-plan-missing")
    else:
        failed_checks.extend(str(blocker) for blocker in report_grade_validation_plan.get("blockers") or [])
    failed_checks = sorted(dict.fromkeys(failed_checks))
    return {
        "item_number": 44,
        "batch_id": FUNCTIONAL_DEFENSIBILITY_BATCH_ID,
        "status": "complete" if not failed_checks else "partial",
        "implemented_controls": {
            "audit_event_count": len(events),
            "events_with_event_hash": events_with_hash,
            "events_with_previous_hash": events_with_previous,
            "head_hash_present": bool(head_hash),
            "audit_chain_manifest_hash": str(audit_hash_chain_manifest.get("manifest_hash") or ""),
            "audit_replay_manifest_hash": str(audit_replay_manifest.get("manifest_hash") or ""),
            "audit_replay_chain_valid": bool(audit_replay_manifest.get("chain_valid")),
            "external_notarization_required": True,
            "trusted_diff_status": str(trusted_diff.get("status")) if trusted_diff else "missing",
            "immutable_audit_report_grade_validation_plan_hash": str(
                (report_grade_validation_plan or {}).get("validation_plan_sha256") or ""
            ),
            "report_grade_ready_slot_count": int((report_grade_validation_plan or {}).get("ready_slot_count") or 0),
            "report_grade_blocking_slot_count": int((report_grade_validation_plan or {}).get("blocking_slot_count") or 0),
        },
        "passed_validation_check_ids": [
            "audit-events-exported",
            "previous-entry-hash-chain-generated",
            "head-hash-recorded",
            "audit-chain-manifest-hash-recorded",
            "audit-replay-manifest-hash-recorded",
            "external-notarization-limitation-disclosed",
            "immutable-audit-report-grade-validation-plan-exported",
        ],
        "failed_validation_check_ids": failed_checks,
        "reportability_decision": {
            "allowed_use": "tamper-evident-case-audit-chain",
            "commercial_claim_allowed": not failed_checks,
            "operator_warning": "External signing/notarization is still required for full tamper-evident release evidence.",
        },
    }
