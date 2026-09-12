"""Custody, acquisition, audit, and forensic-integrity workflows."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import sqlite3
from collections.abc import Mapping, Sequence
from pathlib import Path

from .constants import (
    ACQUISITION_HASH_GAP_ID,
    ACQUISITION_HASH_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    ACQUISITION_HASH_TRUSTED_DIFF_BLOCKER_87,
    ACQUISITION_METADATA_REPORT_GRADE_BLOCKERS,
    ACQUISITION_METADATA_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    ACQUISITION_METADATA_TRUSTED_DIFF_BLOCKER_96,
    CHAIN_OF_CUSTODY_GAP_ID,
    CLOCK_SKEW_ANALYSIS_GAP_ID,
    CLOCK_SKEW_REPORT_GRADE_BLOCKERS,
    CLOCK_SKEW_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    CLOCK_SKEW_TRUSTED_DIFF_BLOCKER_98,
    CONTAMINATION_WARNING_REPORT_GRADE_BLOCKERS,
    CONTAMINATION_WARNING_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    CONTAMINATION_WARNING_TRUSTED_DIFF_BLOCKER_99,
    CUSTODY_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    CUSTODY_TRUSTED_DIFF_BLOCKER_86,
    EVIDENCE_CONTAMINATION_WARNING_GAP_ID,
    FORENSIC_INTEGRITY_BATCH_ID,
    FUNCTIONAL_DEFENSIBILITY_BATCH_ID,
    FUNCTIONAL_VALIDATION_BATCH_ID,
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
    SOURCE_PROVENANCE_REPORT_GRADE_BLOCKERS,
    TIMEZONE_NORMALIZATION_GAP_ID,
    TIMEZONE_REPORT_GRADE_BLOCKERS,
    TIMEZONE_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    TIMEZONE_VALIDATION_TRUSTED_DIFF_BLOCKER_97,
    VALIDATION_WARNING_REPORT_GRADE_BLOCKERS,
    VALIDATION_WARNING_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    VALIDATION_WARNING_TRUSTED_DIFF_BLOCKER_92,
    VALIDATION_WARNING_UX_GAP_ID,
    WRITE_BLOCKER_ACQUISITION_METADATA_GAP_ID,
)
from .helpers import (
    optional_float,
    optional_int,
    parse_json_object,
    stable_payload_sha256,
)
from .review import (
    acquisition_metadata_to_dict,
)
from .trusted_diffs import (
    acquisition_hash_core_accuracy_gates,
    acquisition_metadata_core_accuracy_gates,
    clock_skew_core_accuracy_gates,
    contamination_warning_core_accuracy_gates,
    custody_workflow_core_accuracy_gates,
    immutable_audit_core_accuracy_gates,
    legal_limitation_core_accuracy_gates,
    missing_acquisition_metadata_trusted_diff,
    missing_clock_skew_trusted_diff,
    missing_contamination_warning_trusted_diff,
    missing_integrity_trusted_diff,
    missing_report_quality_trusted_diff,
    missing_timezone_validation_trusted_diff,
    parser_confidence_core_accuracy_gates,
    report_reproducibility_core_accuracy_gates,
    timezone_validation_core_accuracy_gates,
    validation_warning_ux_core_accuracy_gates,
)

__all__ = [
    "acquisition_hash_workflow_functional_profile",
    "acquisition_metadata_functional_profile",
    "attach_acquisition_evidence_source_row_hash",
    "attach_acquisition_hash_row_hash",
    "attach_acquisition_metadata_row_hash",
    "attach_clock_skew_warning_row_hash",
    "attach_contamination_warning_row_hash",
    "attach_custody_row_hash",
    "attach_timezone_sample_row_hash",
    "audit_integrity_functional_profile",
    "build_acquisition_field_completion_matrix",
    "build_acquisition_hash_inventory_matrix",
    "build_acquisition_hash_manifest",
    "build_acquisition_hash_report_grade_validation_plan",
    "build_acquisition_hash_workflow",
    "build_acquisition_metadata_handoff_manifest",
    "build_acquisition_metadata_input_manifest",
    "build_acquisition_metadata_record",
    "build_acquisition_metadata_report_grade_validation_plan",
    "build_audit_actor_action_matrix",
    "build_audit_hash_chain_manifest",
    "build_audit_integrity_chain",
    "build_audit_replay_manifest",
    "build_clock_skew_analysis",
    "build_clock_skew_baseline_manifest",
    "build_clock_skew_range_matrix",
    "build_clock_skew_report_grade_validation_plan",
    "build_contamination_acquisition_context_manifest",
    "build_contamination_checklist_manifest",
    "build_contamination_report_grade_validation_plan",
    "build_contamination_warning_review_matrix",
    "build_custody_chain_manifest",
    "build_custody_completeness_matrix",
    "build_custody_event_manifest",
    "build_custody_report_grade_validation_plan",
    "build_custody_workflow",
    "build_evidence_contamination_warnings",
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
    "build_time_semantics_manifest",
    "build_timezone_normalization_manifest",
    "build_timezone_parser_assumption_matrix",
    "build_timezone_report_grade_validation_plan",
    "build_timezone_validation",
    "build_validation_warning_checklist_manifest",
    "build_validation_warning_report_grade_validation_plan",
    "contamination_warning_functional_profile",
    "custody_event_stage_counts",
    "custody_workflow_functional_profile",
    "is_relative_to",
    "legal_limitation_detail",
    "parse_event_timestamp",
    "parser_confidence_band",
    "parser_reportability_score",
    "timezone_clock_functional_profile",
    "validation_warning_detail",
]

def build_custody_workflow(
    connection: sqlite3.Connection,
    case_id: str,
    *,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    evidence_rows = connection.execute(
        """
        SELECT citation_id, display_name, source_type, original_path, staged_path,
               size_bytes, hash_sha256, status, added_at
        FROM evidence_source
        WHERE case_id = ?
        ORDER BY id ASC
        """,
        (case_id,),
    ).fetchall()
    audit_rows = connection.execute(
        """
        SELECT citation_id, actor, action, target_type, target_id, timestamp, result
        FROM audit_event
        WHERE case_id = ?
        ORDER BY timestamp ASC, id ASC
        """,
        (case_id,),
    ).fetchall()
    evidence_sources = [
        {
            "citation_id": str(row["citation_id"]),
            "display_name": str(row["display_name"] or ""),
            "source_type": str(row["source_type"] or ""),
            "original_path": str(row["original_path"] or ""),
            "staged_path": str(row["staged_path"] or ""),
            "size_bytes": optional_int(row["size_bytes"]),
            "sha256": str(row["hash_sha256"] or ""),
            "status": str(row["status"] or ""),
            "added_at": str(row["added_at"] or ""),
        }
        for row in evidence_rows
    ]
    evidence_sources = [attach_custody_row_hash(item, row_type="evidence_source") for item in evidence_sources]
    custody_events = [
        {
            "citation_id": str(row["citation_id"]),
            "actor": str(row["actor"] or ""),
            "action": str(row["action"] or ""),
            "target_type": str(row["target_type"] or ""),
            "target_id": str(row["target_id"] or ""),
            "timestamp": str(row["timestamp"] or ""),
            "result": str(row["result"] or ""),
        }
        for row in audit_rows
    ]
    custody_events = [attach_custody_row_hash(item, row_type="custody_event") for item in custody_events]
    custody_event_manifest = build_custody_event_manifest(
        evidence_sources=evidence_sources,
        custody_events=custody_events,
    )
    custody_chain_manifest = build_custody_chain_manifest(
        evidence_sources=evidence_sources,
        custody_events=custody_events,
        custody_event_manifest=custody_event_manifest,
        trusted_diff=trusted_diff,
    )
    custody_report_grade_validation_plan = build_custody_report_grade_validation_plan(
        evidence_sources=evidence_sources,
        custody_events=custody_events,
        custody_event_manifest=custody_event_manifest,
        custody_chain_manifest=custody_chain_manifest,
        trusted_diff=trusted_diff,
    )
    blockers = []
    if not trusted_diff or trusted_diff.get("status") != "pass":
        blockers.append(CUSTODY_TRUSTED_DIFF_BLOCKER_86)
    blockers = sorted({*blockers, *custody_report_grade_validation_plan["blockers"]})
    return {
        "status": "case-db-custody-export",
        "commercial_gap_ids": [CHAIN_OF_CUSTODY_GAP_ID],
        "functional_priority_profile": custody_workflow_functional_profile(
            evidence_sources=evidence_sources,
            custody_events=custody_events,
            custody_event_manifest=custody_event_manifest,
            custody_chain_manifest=custody_chain_manifest,
            trusted_diff=trusted_diff,
            report_grade_validation_plan=custody_report_grade_validation_plan,
        ),
            "summary": {
                "evidence_source_count": len(evidence_sources),
                "custody_event_count": len(custody_events),
                "custody_manifest_hash": custody_event_manifest["manifest_hash"],
                "custody_chain_manifest_hash": custody_chain_manifest["manifest_hash"],
                "custody_completeness_matrix_hash": custody_chain_manifest["custody_completeness_matrix_hash"],
                "commercial_gap_ids": [CHAIN_OF_CUSTODY_GAP_ID],
            },
        "evidence_sources": evidence_sources,
        "custody_events": custody_events,
        "custody_event_manifest": custody_event_manifest,
        "custody_chain_manifest": custody_chain_manifest,
        "custody_chain_manifest_hash": custody_chain_manifest["manifest_hash"],
        "custody_completeness_matrix": custody_chain_manifest["custody_completeness_matrix"],
        "custody_completeness_matrix_hash": custody_chain_manifest["custody_completeness_matrix_hash"],
        "custody_manifest_hash": custody_event_manifest["manifest_hash"],
        "custody_report_grade_validation_plan": custody_report_grade_validation_plan,
        "custody_report_grade_validation_plan_hash": custody_report_grade_validation_plan["validation_plan_sha256"],
        "report_grade_ready_slot_count": custody_report_grade_validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": custody_report_grade_validation_plan["blocking_slot_count"],
        "trusted_custody_diff": dict(trusted_diff) if trusted_diff else missing_integrity_trusted_diff(
            CHAIN_OF_CUSTODY_GAP_ID,
            CUSTODY_TRUSTED_DIFF_BLOCKER_86,
            trusted_tool="custody-event-manifest",
        ),
        "core_accuracy_gates": custody_workflow_core_accuracy_gates(
            evidence_sources=evidence_sources,
            custody_events=custody_events,
            custody_event_manifest=custody_event_manifest,
            custody_chain_manifest=custody_chain_manifest,
            trusted_diff=trusted_diff,
            report_grade_validation_plan=custody_report_grade_validation_plan,
        ),
        "blockers": blockers,
        "limitations": [
            "This is a Case DB custody export; acquisition device/write-blocker metadata must be recorded separately when available.",
            "Original evidence images are not copied into report exports.",
        ],
    }


def attach_custody_row_hash(row: Mapping[str, object], *, row_type: str) -> dict[str, object]:
    output = dict(row)
    hash_core = {
        "row_type": row_type,
        "citation_id": str(row.get("citation_id") or ""),
        "actor": str(row.get("actor") or ""),
        "action": str(row.get("action") or ""),
        "target_type": str(row.get("target_type") or ""),
        "target_id": str(row.get("target_id") or ""),
        "timestamp": str(row.get("timestamp") or ""),
        "sha256": str(row.get("sha256") or ""),
        "status": str(row.get("status") or ""),
        "original_path": str(row.get("original_path") or ""),
        "result": str(row.get("result") or ""),
    }
    output["custody_row_hash"] = hashlib.sha256(
        json.dumps(hash_core, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return output


def build_custody_event_manifest(
    *,
    evidence_sources: Sequence[Mapping[str, object]],
    custody_events: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    manifest_core = {
        "profile_version": "custody-event-manifest-v1",
        "item_number": 86,
        "evidence_source_count": len(evidence_sources),
        "custody_event_count": len(custody_events),
        "evidence_source_hashes": [str(item.get("custody_row_hash") or "") for item in evidence_sources],
        "custody_event_hashes": [str(item.get("custody_row_hash") or "") for item in custody_events],
        "citation_ids": sorted(
            str(item.get("citation_id") or "")
            for item in [*evidence_sources, *custody_events]
            if item.get("citation_id")
        ),
        "commercial_gap_ids": [CHAIN_OF_CUSTODY_GAP_ID],
        "commercial_claim_allowed": False,
    }
    manifest_hash = hashlib.sha256(
        json.dumps(manifest_core, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return {**manifest_core, "manifest_hash": manifest_hash}


def build_custody_chain_manifest(
    *,
    evidence_sources: Sequence[Mapping[str, object]],
    custody_events: Sequence[Mapping[str, object]],
    custody_event_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None,
) -> dict[str, object]:
    row_hash_sequence = [
        str(item.get("custody_row_hash") or "")
        for item in [*evidence_sources, *custody_events]
        if item.get("custody_row_hash")
    ]
    chain_head = ""
    for row_hash in row_hash_sequence:
        chain_head = hashlib.sha256(f"{chain_head}:{row_hash}".encode("ascii", errors="ignore")).hexdigest()
    event_stage_counts = custody_event_stage_counts(custody_events)
    required_stages = ["acquisition", "transfer", "review", "export", "report"]
    missing_stages = [stage for stage in required_stages if event_stage_counts.get(stage, 0) == 0]
    source_hash_coverage = sum(1 for item in evidence_sources if item.get("sha256"))
    event_actor_coverage = sum(1 for item in custody_events if item.get("actor"))
    event_timestamp_coverage = sum(1 for item in custody_events if item.get("timestamp"))
    trusted_status = str(trusted_diff.get("status") or "missing") if trusted_diff else "missing"
    completeness_matrix = build_custody_completeness_matrix(
        evidence_sources=evidence_sources,
        custody_events=custody_events,
        event_stage_counts=event_stage_counts,
        missing_stages=missing_stages,
    )
    manifest_core: dict[str, object] = {
        "profile_version": "custody-chain-manifest-v1",
        "item_number": 40,
        "batch_id": FUNCTIONAL_VALIDATION_BATCH_ID,
        "gap_id": "#40",
        "commercial_gap_ids": [CHAIN_OF_CUSTODY_GAP_ID],
        "evidence_source_count": len(evidence_sources),
        "custody_event_count": len(custody_events),
        "source_sha256_coverage_count": source_hash_coverage,
        "event_actor_coverage_count": event_actor_coverage,
        "event_timestamp_coverage_count": event_timestamp_coverage,
        "row_hash_count": len(row_hash_sequence),
        "row_hash_sequence_head": hashlib.sha256("\n".join(row_hash_sequence).encode("ascii")).hexdigest()
        if row_hash_sequence
        else "",
        "hash_chain_head": chain_head,
        "custody_completeness_matrix_hash": completeness_matrix["matrix_hash"],
        "custody_completeness_matrix": completeness_matrix,
        "custody_event_manifest_hash": str(custody_event_manifest.get("manifest_hash") or ""),
        "event_stage_counts": event_stage_counts,
        "missing_stage_names": missing_stages,
        "trusted_diff_status": trusted_status,
        "trusted_diff_hash": hashlib.sha256(
            json.dumps(dict(trusted_diff), ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()
        if trusted_diff
        else "",
        "commercial_claim_allowed": (
            bool(evidence_sources)
            and bool(custody_events)
            and not missing_stages
            and source_hash_coverage == len(evidence_sources)
            and event_actor_coverage == len(custody_events)
            and event_timestamp_coverage == len(custody_events)
            and trusted_status == "pass"
        ),
        "required_external_evidence": [
            "acquisition handoff record",
            "write-blocker or source-protection metadata",
            "transfer/receipt events when evidence changes hands",
            "trusted custody-event manifest diff",
        ],
    }
    return {
        **manifest_core,
        "manifest_hash": hashlib.sha256(
            json.dumps(manifest_core, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest(),
    }


def build_custody_report_grade_validation_plan(
    *,
    evidence_sources: Sequence[Mapping[str, object]],
    custody_events: Sequence[Mapping[str, object]],
    custody_event_manifest: Mapping[str, object],
    custody_chain_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None,
) -> dict[str, object]:
    missing_stages = list(custody_chain_manifest.get("missing_stage_names") or [])
    trusted_status = str(trusted_diff.get("status") or "missing") if trusted_diff else "missing"
    source_hash_coverage = sum(1 for item in evidence_sources if item.get("sha256"))
    source_citation_coverage = sum(1 for item in evidence_sources if item.get("citation_id"))
    event_actor_coverage = sum(1 for item in custody_events if item.get("actor"))
    event_timestamp_coverage = sum(1 for item in custody_events if item.get("timestamp"))
    ready_slots = [
        {
            "slot_id": "custody-evidence-source-inventory",
            "status": "complete",
            "evidence": {
                "evidence_source_count": len(evidence_sources),
                "source_hash_coverage_count": source_hash_coverage,
                "source_citation_coverage_count": source_citation_coverage,
            },
        },
        {
            "slot_id": "custody-event-inventory",
            "status": "complete",
            "evidence": {
                "custody_event_count": len(custody_events),
                "event_actor_coverage_count": event_actor_coverage,
                "event_timestamp_coverage_count": event_timestamp_coverage,
            },
        },
        {
            "slot_id": "custody-event-manifest",
            "status": "complete",
            "evidence": {
                "manifest_hash": custody_event_manifest.get("manifest_hash"),
                "evidence_source_hash_count": len(custody_event_manifest.get("evidence_source_hashes") or []),
                "custody_event_hash_count": len(custody_event_manifest.get("custody_event_hashes") or []),
            },
        },
        {
            "slot_id": "custody-chain-manifest",
            "status": "complete",
            "evidence": {
                "manifest_hash": custody_chain_manifest.get("manifest_hash"),
                "hash_chain_head": custody_chain_manifest.get("hash_chain_head"),
                "row_hash_count": custody_chain_manifest.get("row_hash_count"),
            },
        },
        {
            "slot_id": "custody-completeness-matrix",
            "status": "complete",
            "evidence": {
                "matrix_hash": custody_chain_manifest.get("custody_completeness_matrix_hash"),
                "missing_stage_names": missing_stages,
            },
        },
        {
            "slot_id": "custody-trusted-diff-disclosure",
            "status": "complete",
            "evidence": {
                "trusted_diff_status": trusted_status,
                "trusted_tool": str((trusted_diff or {}).get("trusted_tool") or ""),
            },
        },
    ]
    blocking_slots: list[dict[str, object]] = []
    if not evidence_sources:
        blocking_slots.append(
            {
                "slot_id": "custody-evidence-source-inventory-present",
                "status": "blocked",
                "blocker": "custody-evidence-source-inventory-required",
                "required_evidence": "at least one evidence_source row linked to the exported case",
            }
        )
    if source_hash_coverage != len(evidence_sources):
        blocking_slots.append(
            {
                "slot_id": "custody-source-hash-completeness",
                "status": "blocked",
                "blocker": "custody-source-hash-completeness-required",
                "required_evidence": "SHA-256 or source hash for every evidence source row",
            }
        )
    if source_citation_coverage != len(evidence_sources):
        blocking_slots.append(
            {
                "slot_id": "custody-source-citation-completeness",
                "status": "blocked",
                "blocker": "custody-source-citation-completeness-required",
                "required_evidence": "stable citation_id for every evidence source row",
            }
        )
    if not custody_events:
        blocking_slots.append(
            {
                "slot_id": "custody-event-log-present",
                "status": "blocked",
                "blocker": "custody-event-log-required",
                "required_evidence": "acquisition, transfer, review, export, and report custody events",
            }
        )
    if event_actor_coverage != len(custody_events) or event_timestamp_coverage != len(custody_events):
        blocking_slots.append(
            {
                "slot_id": "custody-event-actor-timestamp-completeness",
                "status": "blocked",
                "blocker": "custody-event-actor-timestamp-completeness-required",
                "required_evidence": "actor and timestamp for every custody event row",
            }
        )
    if missing_stages:
        blocking_slots.append(
            {
                "slot_id": "custody-lifecycle-stage-coverage",
                "status": "blocked",
                "blocker": "custody-lifecycle-stage-coverage-required",
                "required_evidence": ", ".join(missing_stages),
            }
        )
    if trusted_status != "pass":
        blocking_slots.append(
            {
                "slot_id": "custody-trusted-event-manifest-diff",
                "status": "external-required",
                "blocker": CUSTODY_TRUSTED_DIFF_BLOCKER_86,
                "required_evidence": "trusted custody-event manifest diff covering evidence source rows, custody events, manifest hash, and completeness matrix hash",
            }
        )
    blocking_slots.extend(
        [
            {
                "slot_id": "custody-signed-handoff",
                "status": "external-required",
                "blocker": "signed-custody-handoff-required",
                "required_evidence": "signed custody handoff or receipt form for acquisition, transfer, and report delivery",
            },
            {
                "slot_id": "custody-acquisition-device-metadata",
                "status": "external-required",
                "blocker": "acquisition-device-metadata-required",
                "required_evidence": "acquisition workstation/device, examiner, clock, source device, and collection context metadata",
            },
            {
                "slot_id": "custody-write-blocker-metadata",
                "status": "external-required",
                "blocker": "write-blocker-metadata-required",
                "required_evidence": "write-blocker or source-protection device serial, firmware/version, and validation result",
            },
            {
                "slot_id": "custody-lab-policy",
                "status": "external-required",
                "blocker": "lab-custody-policy-required",
                "required_evidence": "lab-approved custody policy or SOP revision used for the case",
            },
        ]
    )
    plan_core: dict[str, object] = {
        "profile_version": CUSTODY_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 86,
        "commercial_gap_ids": [CHAIN_OF_CUSTODY_GAP_ID],
        "plan_context": "case-db-report-export",
        "custody_event_manifest_hash": custody_event_manifest.get("manifest_hash"),
        "custody_chain_manifest_hash": custody_chain_manifest.get("manifest_hash"),
        "custody_completeness_matrix_hash": custody_chain_manifest.get("custody_completeness_matrix_hash"),
        "trusted_diff_status": trusted_status,
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "external_blocker_catalog": list(SOURCE_PROVENANCE_REPORT_GRADE_BLOCKERS),
        "blockers": sorted({str(slot.get("blocker") or "") for slot in blocking_slots if slot.get("blocker")}),
        "commercial_claim_allowed": False,
        "reporting_boundary": "This plan makes Case DB custody exports auditable, but court/commercial custody claims still require external handoff, acquisition-device, write-blocker, policy, and trusted-manifest evidence.",
    }
    return {**plan_core, "validation_plan_sha256": stable_payload_sha256(plan_core)}


def build_custody_completeness_matrix(
    *,
    evidence_sources: Sequence[Mapping[str, object]],
    custody_events: Sequence[Mapping[str, object]],
    event_stage_counts: Mapping[str, int],
    missing_stages: Sequence[str],
) -> dict[str, object]:
    source_rows = []
    for item in evidence_sources:
        row = {
            "citation_id": str(item.get("citation_id") or ""),
            "has_original_path": bool(item.get("original_path")),
            "has_staged_path": bool(item.get("staged_path")),
            "has_size": item.get("size_bytes") is not None,
            "has_sha256": bool(item.get("sha256")),
            "has_status": bool(item.get("status")),
            "has_row_hash": bool(item.get("custody_row_hash")),
        }
        source_rows.append({**row, "row_hash": stable_payload_sha256(row)})
    event_rows = []
    for item in custody_events:
        row = {
            "citation_id": str(item.get("citation_id") or ""),
            "has_actor": bool(item.get("actor")),
            "has_action": bool(item.get("action")),
            "has_target": bool(item.get("target_type") or item.get("target_id")),
            "has_timestamp": bool(item.get("timestamp")),
            "has_result": bool(item.get("result")),
            "has_row_hash": bool(item.get("custody_row_hash")),
        }
        event_rows.append({**row, "row_hash": stable_payload_sha256(row)})
    matrix_core = {
        "profile_version": "custody-completeness-matrix-v1",
        "item_number": 86,
        "evidence_source_count": len(source_rows),
        "custody_event_count": len(event_rows),
        "source_rows": source_rows,
        "event_rows": event_rows,
        "event_stage_counts": dict(event_stage_counts),
        "missing_stage_names": list(missing_stages),
        "all_sources_hash_identified": bool(source_rows) and all(row["has_sha256"] for row in source_rows),
        "all_events_actor_timestamp_identified": bool(event_rows) and all(
            row["has_actor"] and row["has_timestamp"] for row in event_rows
        ),
    }
    return {**matrix_core, "matrix_hash": stable_payload_sha256(matrix_core)}


def custody_event_stage_counts(custody_events: Sequence[Mapping[str, object]]) -> dict[str, int]:
    stages = {"acquisition": 0, "transfer": 0, "review": 0, "export": 0, "report": 0}
    for event in custody_events:
        text = " ".join(
            str(event.get(field) or "").lower()
            for field in ("action", "target_type", "target_id", "result")
        )
        if any(token in text for token in ("acquisition", "acquire", "evidence_source", "import", "ingest")):
            stages["acquisition"] += 1
        if any(token in text for token in ("transfer", "handoff", "receipt", "custody")):
            stages["transfer"] += 1
        if any(token in text for token in ("review", "mark", "tag", "note")):
            stages["review"] += 1
        if any(token in text for token in ("export", "bundle", "exhibit")):
            stages["export"] += 1
        if any(token in text for token in ("report", "citation")):
            stages["report"] += 1
    return stages


def attach_acquisition_hash_row_hash(row: Mapping[str, object]) -> dict[str, object]:
    output = dict(row)
    hash_values = row.get("hashes") if isinstance(row.get("hashes"), Mapping) else {}
    hash_core = {
        "citation_id": str(row.get("citation_id") or ""),
        "target_type": str(row.get("target_type") or ""),
        "target_id": str(row.get("target_id") or ""),
        "hash_scope": str(row.get("hash_scope") or ""),
        "path": str(row.get("path") or ""),
        "display_name": str(row.get("display_name") or ""),
        "size_bytes": row.get("size_bytes"),
        "hashes": {str(key): str(value) for key, value in sorted(hash_values.items())},
        "hash_status": str(row.get("hash_status") or ""),
        "missing_hash_warning": bool(row.get("missing_hash_warning")),
        "calculated_at": str(row.get("calculated_at") or ""),
    }
    output["acquisition_hash_row_hash"] = hashlib.sha256(
        json.dumps(hash_core, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return output


def build_acquisition_hash_manifest(hashes: Sequence[Mapping[str, object]]) -> dict[str, object]:
    algorithm_coverage = {"md5": 0, "sha1": 0, "sha256": 0, "other": 0}
    missing_hash_warning_count = 0
    evidence_source_count = 0
    for item in hashes:
        if item.get("target_type") == "evidence_source":
            evidence_source_count += 1
        values = item.get("hashes") if isinstance(item.get("hashes"), Mapping) else {}
        if not values:
            missing_hash_warning_count += 1
            continue
        normalized_algorithms = {str(key).lower() for key in values}
        if "sha256" not in normalized_algorithms:
            missing_hash_warning_count += 1
        for algorithm in normalized_algorithms:
            if algorithm in algorithm_coverage:
                algorithm_coverage[algorithm] += 1
            else:
                algorithm_coverage["other"] += 1
    inventory_matrix = build_acquisition_hash_inventory_matrix(hashes, algorithm_coverage=algorithm_coverage)
    manifest_core = {
        "profile_version": "acquisition-hash-manifest-v1",
        "item_number": 87,
        "hash_record_count": len(hashes),
        "evidence_source_count": evidence_source_count,
        "hash_row_hashes": [str(item.get("acquisition_hash_row_hash") or "") for item in hashes],
        "citation_ids": sorted(str(item.get("citation_id") or "") for item in hashes if item.get("citation_id")),
        "algorithm_coverage": algorithm_coverage,
        "hash_inventory_matrix": inventory_matrix,
        "hash_inventory_matrix_hash": inventory_matrix["matrix_hash"],
        "missing_hash_warning_count": missing_hash_warning_count,
        "commercial_gap_ids": [ACQUISITION_HASH_GAP_ID],
        "commercial_claim_allowed": False,
    }
    manifest_hash = hashlib.sha256(
        json.dumps(manifest_core, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return {**manifest_core, "manifest_hash": manifest_hash}


def build_acquisition_hash_inventory_matrix(
    hashes: Sequence[Mapping[str, object]],
    *,
    algorithm_coverage: Mapping[str, int],
) -> dict[str, object]:
    rows = []
    for item in hashes:
        hash_values = item.get("hashes") if isinstance(item.get("hashes"), Mapping) else {}
        row = {
            "citation_id": str(item.get("citation_id") or ""),
            "target_type": str(item.get("target_type") or ""),
            "target_id": str(item.get("target_id") or ""),
            "hash_scope": str(item.get("hash_scope") or ""),
            "path_present": bool(item.get("path")),
            "size_present": item.get("size_bytes") is not None,
            "sha256_present": bool(hash_values.get("sha256")),
            "algorithm_count": len(hash_values),
            "hash_status": str(item.get("hash_status") or ""),
            "missing_hash_warning": bool(item.get("missing_hash_warning")),
            "row_hash_present": bool(item.get("acquisition_hash_row_hash")),
        }
        rows.append({**row, "row_hash": stable_payload_sha256(row)})
    matrix_core = {
        "profile_version": "acquisition-hash-inventory-matrix-v1",
        "item_number": 87,
        "hash_record_count": len(rows),
        "algorithm_coverage": dict(algorithm_coverage),
        "rows": rows,
        "all_rows_have_hash_material": bool(rows) and all(row["algorithm_count"] > 0 for row in rows),
        "all_evidence_sources_have_sha256": all(
            row["sha256_present"] for row in rows if row["target_type"] == "evidence_source"
        ),
    }
    return {**matrix_core, "matrix_hash": stable_payload_sha256(matrix_core)}


def build_acquisition_hash_report_grade_validation_plan(
    *,
    hashes: Sequence[Mapping[str, object]],
    acquisition_hash_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None,
) -> dict[str, object]:
    matrix = acquisition_hash_manifest.get("hash_inventory_matrix")
    inventory_matrix = matrix if isinstance(matrix, Mapping) else {}
    algorithm_coverage = acquisition_hash_manifest.get("algorithm_coverage")
    algorithm_coverage = algorithm_coverage if isinstance(algorithm_coverage, Mapping) else {}
    trusted_status = str(trusted_diff.get("status") or "missing") if trusted_diff else "missing"
    evidence_source_hashes = sum(1 for item in hashes if item.get("target_type") == "evidence_source")
    rows_with_hash_values = sum(1 for item in hashes if isinstance(item.get("hashes"), Mapping) and item.get("hashes"))
    rows_with_sha256 = sum(
        1
        for item in hashes
        if isinstance(item.get("hashes"), Mapping)
        and any(str(algorithm).lower() == "sha256" for algorithm in item.get("hashes", {}))
    )
    rows_with_timestamp = sum(1 for item in hashes if item.get("calculated_at"))
    rows_with_row_hash = sum(1 for item in hashes if item.get("acquisition_hash_row_hash"))
    ready_slots = [
        {
            "slot_id": "acquisition-hash-record-inventory",
            "status": "complete",
            "evidence": {
                "hash_record_count": len(hashes),
                "evidence_source_hash_count": evidence_source_hashes,
                "rows_with_hash_values": rows_with_hash_values,
            },
        },
        {
            "slot_id": "acquisition-hash-algorithm-coverage",
            "status": "complete",
            "evidence": dict(algorithm_coverage),
        },
        {
            "slot_id": "acquisition-hash-row-hashes",
            "status": "complete",
            "evidence": {
                "row_hash_count": rows_with_row_hash,
                "hash_row_hash_count": len(acquisition_hash_manifest.get("hash_row_hashes") or []),
            },
        },
        {
            "slot_id": "acquisition-hash-manifest",
            "status": "complete",
            "evidence": {
                "manifest_hash": acquisition_hash_manifest.get("manifest_hash"),
                "missing_hash_warning_count": acquisition_hash_manifest.get("missing_hash_warning_count", 0),
            },
        },
        {
            "slot_id": "acquisition-hash-inventory-matrix",
            "status": "complete",
            "evidence": {
                "matrix_hash": acquisition_hash_manifest.get("hash_inventory_matrix_hash"),
                "all_rows_have_hash_material": bool(inventory_matrix.get("all_rows_have_hash_material")),
                "all_evidence_sources_have_sha256": bool(inventory_matrix.get("all_evidence_sources_have_sha256")),
            },
        },
        {
            "slot_id": "acquisition-hash-trusted-diff-disclosure",
            "status": "complete",
            "evidence": {
                "trusted_diff_status": trusted_status,
                "trusted_tool": str((trusted_diff or {}).get("trusted_tool") or ""),
            },
        },
    ]
    blocking_slots: list[dict[str, object]] = []
    if not hashes:
        blocking_slots.append(
            {
                "slot_id": "acquisition-hash-records-present",
                "status": "blocked",
                "blocker": "acquisition-hash-record-inventory-required",
                "required_evidence": "at least one evidence source or generated-output hash row",
            }
        )
    if rows_with_hash_values != len(hashes):
        blocking_slots.append(
            {
                "slot_id": "acquisition-hash-values-complete",
                "status": "blocked",
                "blocker": "source-hash-completeness-required",
                "required_evidence": "hash values for every acquisition hash row",
            }
        )
    if rows_with_sha256 != len(hashes):
        blocking_slots.append(
            {
                "slot_id": "acquisition-sha256-coverage",
                "status": "blocked",
                "blocker": "source-sha256-completeness-required",
                "required_evidence": "SHA-256 coverage for every acquisition hash row",
            }
        )
    if rows_with_timestamp != len(hashes):
        blocking_slots.append(
            {
                "slot_id": "acquisition-hash-timestamps",
                "status": "blocked",
                "blocker": "hash-calculation-timestamp-required",
                "required_evidence": "calculated_at timestamp for every hash row",
            }
        )
    if rows_with_row_hash != len(hashes):
        blocking_slots.append(
            {
                "slot_id": "acquisition-hash-row-digests",
                "status": "blocked",
                "blocker": "acquisition-hash-row-digest-required",
                "required_evidence": "stable row digest for every hash row",
            }
        )
    if trusted_status != "pass":
        blocking_slots.append(
            {
                "slot_id": "acquisition-trusted-hash-manifest-diff",
                "status": "external-required",
                "blocker": ACQUISITION_HASH_TRUSTED_DIFF_BLOCKER_87,
                "required_evidence": "trusted acquisition hash manifest diff covering rows, manifest hash, and inventory matrix hash",
            }
        )
    blocking_slots.extend(
        [
            {
                "slot_id": "whole-device-acquisition-hash",
                "status": "external-required",
                "blocker": "whole-device-acquisition-hash-required",
                "required_evidence": "source image/device hash captured at acquisition, not only imported file/output hashes",
            },
            {
                "slot_id": "write-blocker-metadata",
                "status": "external-required",
                "blocker": "write-blocker-metadata-required",
                "required_evidence": "write-blocker/source-protection device serial, firmware/version, validation result, and operator",
            },
            {
                "slot_id": "operator-acquisition-log",
                "status": "external-required",
                "blocker": "operator-acquisition-log-required",
                "required_evidence": "operator acquisition log tying source media, time, tool, hash command, and case identifier together",
            },
            {
                "slot_id": "hash-tool-version-capture",
                "status": "external-required",
                "blocker": "hash-tool-version-capture-required",
                "required_evidence": "hashing/imaging tool path, version, command line, and output log for each acquisition hash",
            },
        ]
    )
    plan_core: dict[str, object] = {
        "profile_version": ACQUISITION_HASH_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 87,
        "commercial_gap_ids": [ACQUISITION_HASH_GAP_ID],
        "plan_context": "case-db-report-export",
        "acquisition_hash_manifest_hash": acquisition_hash_manifest.get("manifest_hash"),
        "hash_inventory_matrix_hash": acquisition_hash_manifest.get("hash_inventory_matrix_hash"),
        "trusted_diff_status": trusted_status,
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "blockers": sorted({str(slot.get("blocker") or "") for slot in blocking_slots if slot.get("blocker")}),
        "commercial_claim_allowed": False,
        "reporting_boundary": "This plan makes Case DB acquisition-hash exports auditable, but court/commercial hash claims require original source/device hashes, write-blocker metadata, operator logs, tool-version capture, and trusted-manifest evidence.",
    }
    return {**plan_core, "validation_plan_sha256": stable_payload_sha256(plan_core)}


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


def custody_workflow_functional_profile(
    *,
    evidence_sources: Sequence[Mapping[str, object]],
    custody_events: Sequence[Mapping[str, object]],
    custody_event_manifest: Mapping[str, object],
    custody_chain_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None,
    report_grade_validation_plan: Mapping[str, object] | None = None,
) -> dict[str, object]:
    sources_with_hash = sum(1 for item in evidence_sources if item.get("sha256"))
    sources_with_citation = sum(1 for item in evidence_sources if item.get("citation_id"))
    events_with_actor = sum(1 for item in custody_events if item.get("actor"))
    events_with_timestamp = sum(1 for item in custody_events if item.get("timestamp"))
    sources_with_row_hash = sum(1 for item in evidence_sources if item.get("custody_row_hash"))
    events_with_row_hash = sum(1 for item in custody_events if item.get("custody_row_hash"))
    failed_checks: list[str] = []
    if not evidence_sources:
        failed_checks.append("custody-evidence-source-inventory-empty")
    if sources_with_hash != len(evidence_sources):
        failed_checks.append("custody-source-hash-missing")
    if sources_with_citation != len(evidence_sources):
        failed_checks.append("custody-source-citation-missing")
    if not custody_events:
        failed_checks.append("custody-event-log-empty")
    if events_with_actor != len(custody_events):
        failed_checks.append("custody-event-actor-missing")
    if events_with_timestamp != len(custody_events):
        failed_checks.append("custody-event-timestamp-missing")
    if sources_with_row_hash != len(evidence_sources):
        failed_checks.append("custody-source-row-hash-missing")
    if events_with_row_hash != len(custody_events):
        failed_checks.append("custody-event-row-hash-missing")
    if not custody_event_manifest.get("manifest_hash"):
        failed_checks.append("custody-event-manifest-hash-missing")
    if not custody_chain_manifest.get("manifest_hash"):
        failed_checks.append("custody-chain-manifest-hash-missing")
    if not trusted_diff or trusted_diff.get("status") != "pass":
        failed_checks.append(CUSTODY_TRUSTED_DIFF_BLOCKER_86)
    if not report_grade_validation_plan or not report_grade_validation_plan.get("validation_plan_sha256"):
        failed_checks.append("custody-report-grade-validation-plan-missing")
    else:
        failed_checks.extend(str(blocker) for blocker in report_grade_validation_plan.get("blockers") or [])
    failed_checks = sorted(dict.fromkeys(failed_checks))
    return {
        "item_number": 40,
        "batch_id": FUNCTIONAL_VALIDATION_BATCH_ID,
        "status": "complete" if not failed_checks else "partial",
        "implemented_controls": {
            "evidence_source_count": len(evidence_sources),
            "sources_with_sha256": sources_with_hash,
            "sources_with_citation_id": sources_with_citation,
            "custody_event_count": len(custody_events),
            "events_with_actor": events_with_actor,
            "events_with_timestamp": events_with_timestamp,
            "sources_with_row_hash": sources_with_row_hash,
            "events_with_row_hash": events_with_row_hash,
            "custody_manifest_hash": str(custody_event_manifest.get("manifest_hash") or ""),
            "custody_chain_manifest_hash": str(custody_chain_manifest.get("manifest_hash") or ""),
            "custody_hash_chain_head": str(custody_chain_manifest.get("hash_chain_head") or ""),
            "missing_stage_names": list(custody_chain_manifest.get("missing_stage_names") or []),
            "trusted_diff_status": str(trusted_diff.get("status")) if trusted_diff else "missing",
            "custody_report_grade_validation_plan_hash": str(
                (report_grade_validation_plan or {}).get("validation_plan_sha256") or ""
            ),
            "report_grade_ready_slot_count": int((report_grade_validation_plan or {}).get("ready_slot_count") or 0),
            "report_grade_blocking_slot_count": int((report_grade_validation_plan or {}).get("blocking_slot_count") or 0),
        },
        "passed_validation_check_ids": [
            "case-db-evidence-source-inventory-exported",
            "case-db-custody-event-log-exported",
            "case-db-custody-summary-exported",
            "case-db-custody-row-hashes-exported",
            "case-db-custody-manifest-hash-exported",
            "case-db-custody-chain-manifest-hash-exported",
            "case-db-custody-limitations-disclosed",
            "case-db-custody-report-grade-validation-plan-exported",
        ],
        "failed_validation_check_ids": failed_checks,
        "reportability_decision": {
            "allowed_use": "single-case-chain-of-custody-export",
            "commercial_claim_allowed": not failed_checks,
            "operator_warning": "Attach acquisition/write-blocker metadata and a trusted custody manifest diff before report-defensible use.",
        },
    }


def acquisition_hash_workflow_functional_profile(
    *,
    hashes: Sequence[Mapping[str, object]],
    acquisition_hash_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None,
    report_grade_validation_plan: Mapping[str, object] | None = None,
) -> dict[str, object]:
    evidence_source_hashes = sum(1 for item in hashes if item.get("target_type") == "evidence_source")
    rows_with_hash_values = sum(1 for item in hashes if isinstance(item.get("hashes"), Mapping) and item.get("hashes"))
    rows_with_sha256 = sum(
        1
        for item in hashes
        if isinstance(item.get("hashes"), Mapping)
        and any(str(algorithm).lower() == "sha256" for algorithm in item.get("hashes", {}))
    )
    rows_with_timestamp = sum(1 for item in hashes if item.get("calculated_at"))
    rows_with_row_hash = sum(1 for item in hashes if item.get("acquisition_hash_row_hash"))
    failed_checks: list[str] = []
    if not hashes:
        failed_checks.append("acquisition-hash-record-inventory-empty")
    if rows_with_hash_values != len(hashes):
        failed_checks.append("acquisition-hash-value-missing")
    if rows_with_timestamp != len(hashes):
        failed_checks.append("acquisition-hash-timestamp-missing")
    if rows_with_row_hash != len(hashes):
        failed_checks.append("acquisition-hash-row-hash-missing")
    if not acquisition_hash_manifest.get("manifest_hash"):
        failed_checks.append("acquisition-hash-manifest-hash-missing")
    if rows_with_sha256 != len(hashes):
        failed_checks.append("acquisition-sha256-coverage-incomplete")
    if not trusted_diff or trusted_diff.get("status") != "pass":
        failed_checks.append(ACQUISITION_HASH_TRUSTED_DIFF_BLOCKER_87)
    if not report_grade_validation_plan or not report_grade_validation_plan.get("validation_plan_sha256"):
        failed_checks.append("acquisition-hash-report-grade-validation-plan-missing")
    else:
        failed_checks.extend(str(blocker) for blocker in report_grade_validation_plan.get("blockers") or [])
    failed_checks = sorted(dict.fromkeys(failed_checks))
    return {
        "item_number": 87,
        "batch_id": FORENSIC_INTEGRITY_BATCH_ID,
        "status": "complete" if not failed_checks else "partial",
        "implemented_controls": {
            "hash_record_count": len(hashes),
            "evidence_source_hash_count": evidence_source_hashes,
            "rows_with_hash_values": rows_with_hash_values,
            "rows_with_sha256": rows_with_sha256,
            "rows_with_timestamp": rows_with_timestamp,
            "rows_with_row_hash": rows_with_row_hash,
            "acquisition_hash_manifest_hash": str(acquisition_hash_manifest.get("manifest_hash") or ""),
            "missing_hash_warning_count": acquisition_hash_manifest.get("missing_hash_warning_count", 0),
            "trusted_diff_status": str(trusted_diff.get("status")) if trusted_diff else "missing",
            "acquisition_hash_report_grade_validation_plan_hash": str(
                (report_grade_validation_plan or {}).get("validation_plan_sha256") or ""
            ),
            "report_grade_ready_slot_count": int((report_grade_validation_plan or {}).get("ready_slot_count") or 0),
            "report_grade_blocking_slot_count": int((report_grade_validation_plan or {}).get("blocking_slot_count") or 0),
        },
        "passed_validation_check_ids": [
            "case-db-acquisition-hash-records-exported",
            "case-db-acquisition-hash-algorithms-exported",
            "case-db-acquisition-hash-row-hashes-exported",
            "case-db-acquisition-hash-manifest-hash-exported",
            "case-db-acquisition-hash-limitations-disclosed",
            "case-db-acquisition-hash-report-grade-validation-plan-exported",
        ],
        "failed_validation_check_ids": failed_checks,
        "reportability_decision": {
            "allowed_use": "single-case-acquisition-hash-export",
            "commercial_claim_allowed": not failed_checks,
            "operator_warning": "Attach source acquisition logs, write-blocker metadata, and a trusted acquisition hash manifest diff before report-defensible use.",
        },
    }


def build_acquisition_hash_workflow(
    connection: sqlite3.Connection,
    case_id: str,
    *,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    evidence_rows = connection.execute(
        """
        SELECT citation_id, display_name, original_path, size_bytes, hash_md5, hash_sha1, hash_sha256, added_at
        FROM evidence_source
        WHERE case_id = ?
        ORDER BY id ASC
        """,
        (case_id,),
    ).fetchall()
    hash_rows = connection.execute(
        """
        SELECT citation_id, target_type, target_id, hash_scope, algorithm, value, calculated_at
        FROM hash_record
        WHERE case_id = ?
        ORDER BY id ASC
        """,
        (case_id,),
    ).fetchall()
    hashes = []
    for row in evidence_rows:
        algorithms = {
            "md5": str(row["hash_md5"] or ""),
            "sha1": str(row["hash_sha1"] or ""),
            "sha256": str(row["hash_sha256"] or ""),
        }
        present = {key: value for key, value in algorithms.items() if value}
        hashes.append(
            {
                "citation_id": str(row["citation_id"]),
                "target_type": "evidence_source",
                "target_id": str(row["citation_id"]),
                "path": str(row["original_path"] or ""),
                "display_name": str(row["display_name"] or ""),
                "size_bytes": optional_int(row["size_bytes"]),
                "hashes": present,
                "hash_status": "present" if present else "missing",
                "missing_hash_warning": not present,
                "calculated_at": str(row["added_at"] or ""),
            }
        )
    for row in hash_rows:
        hashes.append(
            {
                "citation_id": str(row["citation_id"]),
                "target_type": str(row["target_type"] or ""),
                "target_id": str(row["target_id"] or ""),
                "hash_scope": str(row["hash_scope"] or ""),
                "hashes": {str(row["algorithm"] or ""): str(row["value"] or "")},
                "calculated_at": str(row["calculated_at"] or ""),
            }
        )
    hashes = [attach_acquisition_hash_row_hash(item) for item in hashes]
    acquisition_manifest = build_acquisition_hash_manifest(hashes)
    acquisition_report_grade_validation_plan = build_acquisition_hash_report_grade_validation_plan(
        hashes=hashes,
        acquisition_hash_manifest=acquisition_manifest,
        trusted_diff=trusted_diff,
    )
    blockers = []
    if not trusted_diff or trusted_diff.get("status") != "pass":
        blockers.append(ACQUISITION_HASH_TRUSTED_DIFF_BLOCKER_87)
    blockers = sorted({*blockers, *acquisition_report_grade_validation_plan["blockers"]})
    return {
        "status": "case-db-hash-export",
        "commercial_gap_ids": [ACQUISITION_HASH_GAP_ID],
        "summary": {
            "hash_count": len(hashes),
            "evidence_source_hash_count": sum(1 for item in hashes if item.get("target_type") == "evidence_source"),
            "acquisition_hash_manifest_hash": acquisition_manifest["manifest_hash"],
            "missing_hash_warning_count": acquisition_manifest["missing_hash_warning_count"],
            "commercial_gap_ids": [ACQUISITION_HASH_GAP_ID],
        },
        "hashes": hashes,
        "acquisition_hash_manifest": acquisition_manifest,
        "acquisition_hash_report_grade_validation_plan": acquisition_report_grade_validation_plan,
        "acquisition_hash_report_grade_validation_plan_hash": acquisition_report_grade_validation_plan["validation_plan_sha256"],
        "report_grade_ready_slot_count": acquisition_report_grade_validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": acquisition_report_grade_validation_plan["blocking_slot_count"],
        "functional_priority_profile": acquisition_hash_workflow_functional_profile(
            hashes=hashes,
            acquisition_hash_manifest=acquisition_manifest,
            trusted_diff=trusted_diff,
            report_grade_validation_plan=acquisition_report_grade_validation_plan,
        ),
        "trusted_acquisition_hash_diff": dict(trusted_diff) if trusted_diff else missing_integrity_trusted_diff(
            ACQUISITION_HASH_GAP_ID,
            ACQUISITION_HASH_TRUSTED_DIFF_BLOCKER_87,
            trusted_tool="acquisition-hash-manifest",
        ),
        "core_accuracy_gates": acquisition_hash_core_accuracy_gates(
            hashes=hashes,
            acquisition_hash_manifest=acquisition_manifest,
            trusted_diff=trusted_diff,
            report_grade_validation_plan=acquisition_report_grade_validation_plan,
        ),
        "blockers": blockers,
        "limitations": [
            "Folder evidence hashes describe imported files/outputs when available; whole-device acquisition hashes require acquisition metadata.",
            "Missing hashes should be resolved before court exhibit export.",
        ],
    }


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


def attach_acquisition_metadata_row_hash(record: Mapping[str, object]) -> dict[str, object]:
    row = dict(record)
    row["acquisition_metadata_row_hash"] = stable_payload_sha256(
        {
            "citation_id": row.get("citation_id"),
            "evidence_source_citation_id": row.get("evidence_source_citation_id"),
            "operator": row.get("operator"),
            "acquisition_started_at": row.get("acquisition_started_at"),
            "acquisition_completed_at": row.get("acquisition_completed_at"),
            "source_identifier": row.get("source_identifier"),
            "write_blocker": row.get("write_blocker"),
            "acquisition_tool": row.get("acquisition_tool"),
            "acquisition_tool_version": row.get("acquisition_tool_version"),
            "whole_source_sha256": row.get("whole_source_sha256"),
        }
    )
    return row


def attach_acquisition_evidence_source_row_hash(source: Mapping[str, object]) -> dict[str, object]:
    row = dict(source)
    row["acquisition_evidence_source_row_hash"] = stable_payload_sha256(
        {
            "citation_id": row.get("citation_id"),
            "original_path": row.get("original_path"),
            "staged_path": row.get("staged_path"),
            "size_bytes": row.get("size_bytes"),
            "sha256": row.get("sha256"),
            "added_at": row.get("added_at"),
        }
    )
    return row


def build_acquisition_metadata_handoff_manifest(
    *,
    records: Sequence[Mapping[str, object]],
    evidence_sources: Sequence[Mapping[str, object]],
    required_fields: Sequence[str],
    missing_required_fields: Sequence[str],
    missing_by_record: Sequence[Mapping[str, object]],
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    field_completion_matrix = build_acquisition_field_completion_matrix(
        records=records,
        evidence_sources=evidence_sources,
        required_fields=required_fields,
    )
    manifest_core = {
        "profile_version": "acquisition-metadata-handoff-manifest-v1",
        "item_number": 96,
        "metadata_record_count": len(records),
        "evidence_source_count": len(evidence_sources),
        "required_fields": list(required_fields),
        "missing_required_fields": list(missing_required_fields),
        "missing_by_record": [dict(item) for item in missing_by_record],
        "field_completion_matrix": field_completion_matrix,
        "field_completion_matrix_hash": field_completion_matrix["matrix_hash"],
        "record_row_hashes": [str(item.get("acquisition_metadata_row_hash") or "") for item in records],
        "evidence_source_row_hashes": [
            str(item.get("acquisition_evidence_source_row_hash") or "") for item in evidence_sources
        ],
        "trusted_diff_status": str(trusted_diff.get("status") or ""),
        "commercial_gap_ids": [WRITE_BLOCKER_ACQUISITION_METADATA_GAP_ID],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_acquisition_field_completion_matrix(
    *,
    records: Sequence[Mapping[str, object]],
    evidence_sources: Sequence[Mapping[str, object]],
    required_fields: Sequence[str],
) -> dict[str, object]:
    rows = []
    for field in required_fields:
        present_count = sum(1 for record in records if str(record.get(field) or "").strip())
        row_core = {
            "field": str(field),
            "present_record_count": present_count,
            "missing_record_count": max(len(records) - present_count, 0),
            "required": True,
        }
        rows.append({**row_core, "row_hash": stable_payload_sha256(row_core)})
    matrix_core = {
        "profile_version": "acquisition-field-completion-matrix-v1",
        "item_number": 96,
        "record_count": len(records),
        "evidence_source_count": len(evidence_sources),
        "required_field_count": len(required_fields),
        "rows": rows,
        "complete_required_fields": all(row["missing_record_count"] == 0 for row in rows) if rows else False,
        "commercial_claim_allowed": False,
    }
    return {**matrix_core, "matrix_hash": stable_payload_sha256(matrix_core)}


def build_acquisition_metadata_report_grade_validation_plan(
    *,
    records: Sequence[Mapping[str, object]],
    evidence_sources: Sequence[Mapping[str, object]],
    required_fields: Sequence[str],
    missing_required_fields: Sequence[str],
    handoff_manifest: Mapping[str, object],
    input_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    trusted_status = str(trusted_diff.get("status") or "missing")
    record_row_hashes = [str(item.get("acquisition_metadata_row_hash") or "") for item in records]
    evidence_source_hashes = [
        str(item.get("acquisition_evidence_source_row_hash") or "") for item in evidence_sources
    ]
    ready_slots = [
        {
            "slot_id": "acquisition-metadata-record-inventory",
            "status": "complete",
            "evidence": {
                "record_count": len(records),
                "record_row_hash_count": sum(1 for value in record_row_hashes if value),
            },
        },
        {
            "slot_id": "evidence-source-linkage-inventory",
            "status": "complete",
            "evidence": {
                "evidence_source_count": len(evidence_sources),
                "evidence_source_row_hash_count": sum(1 for value in evidence_source_hashes if value),
            },
        },
        {
            "slot_id": "acquisition-field-completion-matrix",
            "status": "complete",
            "evidence": {
                "required_field_count": len(required_fields),
                "missing_required_fields": list(missing_required_fields),
                "matrix_hash": str(handoff_manifest.get("field_completion_matrix_hash") or ""),
            },
        },
        {
            "slot_id": "acquisition-handoff-manifest",
            "status": "complete",
            "evidence": {"manifest_hash": str(handoff_manifest.get("manifest_hash") or "")},
        },
        {
            "slot_id": "acquisition-input-manifest",
            "status": "complete",
            "evidence": {
                "manifest_hash": str(input_manifest.get("manifest_hash") or ""),
                "ready_for_submission": bool(input_manifest.get("ready_for_submission")),
            },
        },
        {
            "slot_id": "required-field-gap-disclosure",
            "status": "complete",
            "evidence": {
                "missing_required_field_count": len(missing_required_fields),
                "missing_required_fields": list(missing_required_fields),
            },
        },
        {
            "slot_id": "trusted-acquisition-handoff-diff-disclosure",
            "status": "complete",
            "evidence": {
                "trusted_diff_status": trusted_status,
                "trusted_tool": str(trusted_diff.get("trusted_tool") or ""),
            },
        },
    ]
    blocking_slots: list[dict[str, object]] = []
    if not records:
        blocking_slots.append(
            {
                "slot_id": "acquisition-metadata-record-present",
                "status": "blocked",
                "blocker": "acquisition-metadata-record-not-created",
                "required_evidence": "at least one acquisition metadata record linked to the case",
            }
        )
    if missing_required_fields:
        blocking_slots.append(
            {
                "slot_id": "required-acquisition-fields-complete",
                "status": "blocked",
                "blocker": "acquisition-required-fields-missing",
                "required_evidence": "operator, timestamps, source identifier, write-blocker, and whole-source hash fields",
                "missing_required_fields": list(missing_required_fields),
            }
        )
    if len([value for value in record_row_hashes if value]) != len(records):
        blocking_slots.append(
            {
                "slot_id": "acquisition-metadata-row-hash-completeness",
                "status": "blocked",
                "blocker": "acquisition-metadata-row-hash-completeness-required",
                "required_evidence": "row hash for every acquisition metadata record",
            }
        )
    if len([value for value in evidence_source_hashes if value]) != len(evidence_sources):
        blocking_slots.append(
            {
                "slot_id": "acquisition-evidence-source-row-hash-completeness",
                "status": "blocked",
                "blocker": "acquisition-evidence-source-row-hash-completeness-required",
                "required_evidence": "row hash for every evidence source linked to acquisition metadata",
            }
        )
    if not handoff_manifest.get("manifest_hash") or not handoff_manifest.get("field_completion_matrix_hash"):
        blocking_slots.append(
            {
                "slot_id": "acquisition-handoff-manifest-complete",
                "status": "blocked",
                "blocker": "acquisition-handoff-manifest-required",
                "required_evidence": "handoff manifest hash and field-completion matrix hash",
            }
        )
    if not input_manifest.get("manifest_hash"):
        blocking_slots.append(
            {
                "slot_id": "acquisition-input-manifest-complete",
                "status": "blocked",
                "blocker": "acquisition-input-manifest-required",
                "required_evidence": "input manifest hash for GUI/API acquisition metadata capture",
            }
        )
    if trusted_status != "pass":
        blocking_slots.append(
            {
                "slot_id": "trusted-acquisition-metadata-handoff-diff",
                "status": "external-required",
                "blocker": ACQUISITION_METADATA_TRUSTED_DIFF_BLOCKER_96,
                "required_evidence": "trusted signed handoff/write-blocker log diff covering records, missing fields, and manifest hashes",
            }
        )
    blocking_slots.extend(
        [
            {
                "slot_id": "write-blocker-device-log",
                "status": "external-required",
                "blocker": "write-blocker-device-log-required",
                "required_evidence": "write-blocker device model, serial, firmware/status, and read-only verification log",
            },
            {
                "slot_id": "signed-acquisition-handoff",
                "status": "external-required",
                "blocker": "signed-acquisition-handoff-required",
                "required_evidence": "examiner/operator signed acquisition handoff form",
            },
            {
                "slot_id": "original-acquisition-notes",
                "status": "external-required",
                "blocker": "original-acquisition-notes-required",
                "required_evidence": "operator-preserved acquisition notes and collection timestamps",
            },
            {
                "slot_id": "whole-source-hash-verification-log",
                "status": "external-required",
                "blocker": "whole-source-hash-verification-log-required",
                "required_evidence": "hash verification log proving whole-source hash came from acquisition/imaging output",
            },
            {
                "slot_id": "acquisition-tool-version-linkage",
                "status": "external-required",
                "blocker": "acquisition-tool-version-linkage-required",
                "required_evidence": "linkage between acquisition metadata, external tool-version capture, and source hash manifest",
            },
            {
                "slot_id": "source-read-only-policy-signoff",
                "status": "external-required",
                "blocker": "source-read-only-policy-signoff-required",
                "required_evidence": "lab policy/signoff that the evidence source was handled read-only",
            },
        ]
    )
    plan_core: dict[str, object] = {
        "profile_version": ACQUISITION_METADATA_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 96,
        "commercial_gap_ids": [WRITE_BLOCKER_ACQUISITION_METADATA_GAP_ID],
        "plan_context": "case-db-acquisition-write-blocker-metadata",
        "record_count": len(records),
        "evidence_source_count": len(evidence_sources),
        "required_fields": list(required_fields),
        "missing_required_fields": list(missing_required_fields),
        "acquisition_metadata_handoff_manifest_hash": str(handoff_manifest.get("manifest_hash") or ""),
        "acquisition_field_completion_matrix_hash": str(
            handoff_manifest.get("field_completion_matrix_hash") or ""
        ),
        "acquisition_metadata_input_manifest_hash": str(input_manifest.get("manifest_hash") or ""),
        "trusted_diff_status": trusted_status,
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "external_blocker_catalog": list(ACQUISITION_METADATA_REPORT_GRADE_BLOCKERS),
        "blockers": sorted({str(slot.get("blocker") or "") for slot in blocking_slots if slot.get("blocker")}),
        "commercial_claim_allowed": False,
        "reporting_boundary": "This plan makes acquisition/write-blocker metadata auditable, but commercial claims require signed handoff evidence, write-blocker device logs, original notes, source-hash verification logs, tool-version linkage, read-only policy signoff, and trusted diffs.",
    }
    return {**plan_core, "validation_plan_hash": stable_payload_sha256(plan_core)}


def build_acquisition_metadata_record(
    connection: sqlite3.Connection,
    case_id: str,
    *,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    case = connection.execute("SELECT * FROM case_record WHERE case_id = ?", (case_id,)).fetchone()
    evidence_rows = connection.execute(
        """
        SELECT citation_id, original_path, staged_path, hash_sha256, size_bytes, added_at
        FROM evidence_source
        WHERE case_id = ?
        ORDER BY id ASC
        """,
        (case_id,),
    ).fetchall()
    metadata_rows = connection.execute(
        """
        SELECT * FROM acquisition_metadata
        WHERE case_id = ?
        ORDER BY created_at ASC, id ASC
        """,
        (case_id,),
    ).fetchall()
    required_fields = [
        "operator",
        "acquisition_started_at",
        "acquisition_completed_at",
        "source_identifier",
        "write_blocker",
        "whole_source_sha256",
    ]
    acquisition_records = [
        attach_acquisition_metadata_row_hash(acquisition_metadata_to_dict(row)) for row in metadata_rows
    ]
    missing_by_record = [
        {
            "citation_id": str(record.get("citation_id") or ""),
            "missing_required_fields": [
                field for field in required_fields if not str(record.get(field) or "").strip()
            ],
        }
        for record in acquisition_records
    ]
    if acquisition_records:
        missing = sorted(
            {
                field
                for record in acquisition_records
                for field in required_fields
                if not str(record.get(field) or "").strip()
            }
        )
    else:
        missing = list(required_fields)
    case_metadata = {
        "examiner": str(case["examiner"] or "") if case else "",
        "organization": str(case["organization"] or "") if case else "",
        "case_root": str(case["case_root"] or "") if case else "",
    }
    evidence_sources = [
        attach_acquisition_evidence_source_row_hash(
            {
                "citation_id": str(row["citation_id"]),
                "original_path": str(row["original_path"] or ""),
                "staged_path": str(row["staged_path"] or ""),
                "size_bytes": optional_int(row["size_bytes"]),
                "sha256": str(row["hash_sha256"] or ""),
                "added_at": str(row["added_at"] or ""),
            }
        )
        for row in evidence_rows
    ]
    status = "metadata-recorded" if acquisition_records and not missing else "metadata-check-required"
    if trusted_diff is None:
        trusted_diff = missing_acquisition_metadata_trusted_diff()
    blockers = []
    if trusted_diff.get("status") != "pass":
        blockers.append(ACQUISITION_METADATA_TRUSTED_DIFF_BLOCKER_96)
    handoff_manifest = build_acquisition_metadata_handoff_manifest(
        records=acquisition_records,
        evidence_sources=evidence_sources,
        required_fields=required_fields,
        missing_required_fields=missing,
        missing_by_record=missing_by_record,
        trusted_diff=trusted_diff,
    )
    input_manifest = build_acquisition_metadata_input_manifest(
        records=acquisition_records,
        evidence_sources=evidence_sources,
        required_fields=required_fields,
        missing_required_fields=missing,
        trusted_diff=trusted_diff,
    )
    report_grade_validation_plan = build_acquisition_metadata_report_grade_validation_plan(
        records=acquisition_records,
        evidence_sources=evidence_sources,
        required_fields=required_fields,
        missing_required_fields=missing,
        handoff_manifest=handoff_manifest,
        input_manifest=input_manifest,
        trusted_diff=trusted_diff,
    )
    blockers = sorted({*blockers, *report_grade_validation_plan["blockers"]})
    return {
        "status": status,
        "commercial_gap_ids": [WRITE_BLOCKER_ACQUISITION_METADATA_GAP_ID],
        "functional_priority_profile": acquisition_metadata_functional_profile(
            records=acquisition_records,
            evidence_sources=evidence_sources,
            missing_required_fields=missing,
            input_manifest=input_manifest,
            trusted_diff=trusted_diff,
        ),
        "case_metadata": case_metadata,
        "evidence_sources": evidence_sources,
        "records": acquisition_records,
        "missing_by_record": missing_by_record,
        "required_fields": required_fields,
        "missing_required_fields": missing,
        "trusted_acquisition_metadata_diff": trusted_diff,
        "acquisition_metadata_handoff_manifest": handoff_manifest,
        "acquisition_metadata_handoff_manifest_hash": handoff_manifest["manifest_hash"],
        "acquisition_field_completion_matrix": handoff_manifest["field_completion_matrix"],
        "acquisition_field_completion_matrix_hash": handoff_manifest["field_completion_matrix_hash"],
        "acquisition_metadata_input_manifest": input_manifest,
        "acquisition_metadata_input_manifest_hash": input_manifest["manifest_hash"],
        "acquisition_metadata_report_grade_validation_plan": report_grade_validation_plan,
        "acquisition_metadata_report_grade_validation_plan_hash": report_grade_validation_plan[
            "validation_plan_hash"
        ],
        "acquisition_metadata_report_grade_ready_slot_count": report_grade_validation_plan["ready_slot_count"],
        "acquisition_metadata_report_grade_blocking_slot_count": report_grade_validation_plan["blocking_slot_count"],
        "blockers": blockers,
        "summary": {
            "evidence_source_count": len(evidence_sources),
            "metadata_record_count": len(acquisition_records),
            "missing_required_field_count": len(missing),
            "acquisition_metadata_handoff_manifest_hash": handoff_manifest["manifest_hash"],
            "acquisition_field_completion_matrix_hash": handoff_manifest["field_completion_matrix_hash"],
            "acquisition_metadata_input_manifest_hash": input_manifest["manifest_hash"],
            "acquisition_metadata_report_grade_validation_plan_hash": report_grade_validation_plan[
                "validation_plan_hash"
            ],
            "commercial_gap_ids": [WRITE_BLOCKER_ACQUISITION_METADATA_GAP_ID],
        },
        "validation_assessment": {
            "commercial_gap_ids": [WRITE_BLOCKER_ACQUISITION_METADATA_GAP_ID],
            "write_blocker_recorded": any(str(record.get("write_blocker") or "").strip() for record in acquisition_records),
            "whole_source_hash_recorded": any(
                str(record.get("whole_source_sha256") or "").strip() for record in acquisition_records
            ),
            "ready_for_submission": bool(acquisition_records and not missing),
            "missing_required_fields": missing,
            "acquisition_metadata_handoff_manifest_hash": handoff_manifest["manifest_hash"],
            "acquisition_field_completion_matrix_hash": handoff_manifest["field_completion_matrix_hash"],
            "acquisition_metadata_input_manifest_hash": input_manifest["manifest_hash"],
            "acquisition_metadata_report_grade_validation_plan_hash": report_grade_validation_plan[
                "validation_plan_hash"
            ],
            "acquisition_metadata_report_grade_ready_slot_count": report_grade_validation_plan["ready_slot_count"],
            "acquisition_metadata_report_grade_blocking_slot_count": report_grade_validation_plan[
                "blocking_slot_count"
            ],
            "core_accuracy_gates": acquisition_metadata_core_accuracy_gates(
                records=acquisition_records,
                missing_required_fields=missing,
                handoff_manifest=handoff_manifest,
                input_manifest=input_manifest,
                report_grade_validation_plan=report_grade_validation_plan,
                trusted_diff=trusted_diff,
            ),
            "trusted_acquisition_metadata_diff": trusted_diff,
            "blockers": blockers,
        },
        "guidance": "Record acquisition operator, device/source identifier, write-blocker details, acquisition timestamps, and whole-source hashes before final submission.",
    }


def build_acquisition_metadata_input_manifest(
    *,
    records: Sequence[Mapping[str, object]],
    evidence_sources: Sequence[Mapping[str, object]],
    required_fields: Sequence[str],
    missing_required_fields: Sequence[str],
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    form_fields = [
        ("evidence_source_citation_id", "Evidence source", True),
        ("operator", "Operator / examiner", True),
        ("source_identifier", "Device or source identifier", True),
        ("write_blocker", "Write-blocker / source protection", True),
        ("acquisition_tool", "Acquisition tool", False),
        ("acquisition_tool_version", "Acquisition tool version", False),
        ("acquisition_started_at", "Acquisition started at", True),
        ("acquisition_completed_at", "Acquisition completed at", True),
        ("whole_source_sha256", "Whole-source SHA-256", True),
        ("notes", "Acquisition notes", False),
    ]
    field_rows = []
    for field_name, label, required in form_fields:
        present_count = sum(1 for record in records if str(record.get(field_name) or "").strip())
        field_rows.append(
            {
                "field": field_name,
                "label": label,
                "required": required,
                "present_record_count": present_count,
                "missing_record_count": max(len(records) - present_count, 0),
                "missing_globally": field_name in set(missing_required_fields),
            }
        )
    evidence_source_choices = [
        {
            "citation_id": str(source.get("citation_id") or ""),
            "display": str(source.get("original_path") or source.get("staged_path") or source.get("citation_id") or ""),
            "sha256_present": bool(str(source.get("sha256") or "")),
        }
        for source in evidence_sources
    ]
    manifest_core: dict[str, object] = {
        "profile_version": "acquisition-metadata-input-manifest-v1",
        "item_number": 41,
        "batch_id": FUNCTIONAL_DEFENSIBILITY_BATCH_ID,
        "gap_id": "#41",
        "commercial_gap_ids": [WRITE_BLOCKER_ACQUISITION_METADATA_GAP_ID],
        "record_count": len(records),
        "evidence_source_choice_count": len(evidence_source_choices),
        "required_fields": list(required_fields),
        "missing_required_fields": list(missing_required_fields),
        "form_fields": field_rows,
        "evidence_source_choices": evidence_source_choices,
        "audit_action": "record_acquisition_metadata",
        "audit_required": True,
        "trusted_diff_status": str(trusted_diff.get("status") or ""),
        "ready_for_submission": bool(records and not missing_required_fields),
        "operator_warning": "The GUI must preserve these fields in the audit log and report export before report-defensible use.",
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def attach_timezone_sample_row_hash(sample: Mapping[str, object]) -> dict[str, object]:
    row = dict(sample)
    row["timezone_sample_row_hash"] = stable_payload_sha256(
        {
            "timestamp": row.get("timestamp"),
            "timezone": row.get("timezone"),
            "normalized_utc": row.get("normalized_utc"),
            "parser_assumption": row.get("parser_assumption"),
            "timestamp_kind": row.get("timestamp_kind"),
            "source": row.get("source"),
            "event_type": row.get("event_type"),
        }
    )
    return row


def build_timezone_normalization_manifest(
    *,
    event_count: int,
    missing_timezone_count: int,
    timezone_counts: Mapping[str, int],
    samples: Sequence[Mapping[str, object]],
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    parser_assumption_matrix = build_timezone_parser_assumption_matrix(samples)
    manifest_core = {
        "profile_version": "timezone-normalization-manifest-v1",
        "item_number": 97,
        "event_count": event_count,
        "missing_timezone_count": missing_timezone_count,
        "timezone_counts": dict(timezone_counts),
        "sample_count": len(samples),
        "sample_row_hashes": [str(sample.get("timezone_sample_row_hash") or "") for sample in samples],
        "parser_assumption_matrix": parser_assumption_matrix,
        "parser_assumption_matrix_hash": parser_assumption_matrix["matrix_hash"],
        "utc_assumption": "timestamps are interpreted as UTC when parser/source timezone is absent",
        "trusted_diff_status": str(trusted_diff.get("status") or ""),
        "commercial_gap_ids": [TIMEZONE_NORMALIZATION_GAP_ID],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_timezone_parser_assumption_matrix(samples: Sequence[Mapping[str, object]]) -> dict[str, object]:
    counts: dict[str, int] = {}
    for sample in samples:
        assumption = str(sample.get("parser_assumption") or "unknown")
        counts[assumption] = counts.get(assumption, 0) + 1
    rows = []
    for assumption, count in sorted(counts.items()):
        row_core = {"parser_assumption": assumption, "sample_count": count}
        rows.append({**row_core, "row_hash": stable_payload_sha256(row_core)})
    matrix_core = {
        "profile_version": "timezone-parser-assumption-matrix-v1",
        "item_number": 97,
        "sample_count": len(samples),
        "rows": rows,
        "assumption_count": len(rows),
        "commercial_claim_allowed": False,
    }
    return {**matrix_core, "matrix_hash": stable_payload_sha256(matrix_core)}


def build_time_semantics_manifest(
    *,
    samples: Sequence[Mapping[str, object]],
    timezone_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    semantic_rows = [
        {
            "original_timestamp": str(sample.get("timestamp") or ""),
            "source_timezone": str(sample.get("timezone") or ""),
            "normalized_utc": str(sample.get("normalized_utc") or ""),
            "timestamp_kind": str(sample.get("timestamp_kind") or ""),
            "source": str(sample.get("source") or ""),
            "event_type": str(sample.get("event_type") or ""),
            "parser_assumption": str(sample.get("parser_assumption") or ""),
            "parse_status": str(sample.get("timestamp_parse_status") or ""),
            "sample_row_hash": str(sample.get("timezone_sample_row_hash") or ""),
        }
        for sample in samples
    ]
    manifest_core: dict[str, object] = {
        "profile_version": "time-semantics-manifest-v1",
        "item_number": 42,
        "batch_id": FUNCTIONAL_DEFENSIBILITY_BATCH_ID,
        "gap_id": "#42",
        "commercial_gap_ids": [TIMEZONE_NORMALIZATION_GAP_ID, CLOCK_SKEW_ANALYSIS_GAP_ID],
        "sample_count": len(samples),
        "normalized_utc_sample_count": sum(1 for row in semantic_rows if row["normalized_utc"]),
        "missing_timezone_sample_count": sum(1 for row in semantic_rows if not row["source_timezone"]),
        "parser_assumptions": sorted({row["parser_assumption"] for row in semantic_rows if row["parser_assumption"]}),
        "timezone_normalization_manifest_hash": str(timezone_manifest.get("manifest_hash") or ""),
        "trusted_diff_status": str(trusted_diff.get("status") or ""),
        "samples": semantic_rows,
        "source_viewer_fields": [
            "original_timestamp",
            "source_timezone",
            "normalized_utc",
            "timestamp_kind",
            "source",
            "event_type",
            "parser_assumption",
            "sample_row_hash",
        ],
        "commercial_claim_allowed": False,
        "operator_warning": (
            "Use these rows to cite original and normalized time semantics; parser-specific timezone matrices "
            "and trusted baselines are still required before final conclusions."
        ),
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_timezone_report_grade_validation_plan(
    *,
    event_count: int,
    missing_timezone_count: int,
    samples: Sequence[Mapping[str, object]],
    timezone_manifest: Mapping[str, object],
    time_semantics_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    trusted_status = str(trusted_diff.get("status") or "missing")
    sample_row_hashes = [str(sample.get("timezone_sample_row_hash") or "") for sample in samples]
    parser_assumption_matrix = (
        timezone_manifest.get("parser_assumption_matrix")
        if isinstance(timezone_manifest.get("parser_assumption_matrix"), Mapping)
        else {}
    )
    ready_slots = [
        {
            "slot_id": "event-timezone-inventory",
            "status": "complete",
            "evidence": {
                "event_count": event_count,
                "missing_timezone_count": missing_timezone_count,
                "timezone_counts": dict(timezone_manifest.get("timezone_counts") or {}),
            },
        },
        {
            "slot_id": "timestamp-sample-row-hashes",
            "status": "complete",
            "evidence": {
                "sample_count": len(samples),
                "sample_row_hash_count": sum(1 for value in sample_row_hashes if value),
            },
        },
        {
            "slot_id": "timezone-normalization-manifest",
            "status": "complete",
            "evidence": {"manifest_hash": str(timezone_manifest.get("manifest_hash") or "")},
        },
        {
            "slot_id": "parser-assumption-matrix",
            "status": "complete",
            "evidence": {
                "matrix_hash": str(timezone_manifest.get("parser_assumption_matrix_hash") or ""),
                "assumption_count": int(parser_assumption_matrix.get("assumption_count") or 0),
            },
        },
        {
            "slot_id": "time-semantics-manifest",
            "status": "complete",
            "evidence": {
                "manifest_hash": str(time_semantics_manifest.get("manifest_hash") or ""),
                "normalized_utc_sample_count": int(
                    time_semantics_manifest.get("normalized_utc_sample_count") or 0
                ),
            },
        },
        {
            "slot_id": "utc-assumption-and-review-warning",
            "status": "complete",
            "evidence": {
                "utc_assumption": str(timezone_manifest.get("utc_assumption") or ""),
                "review_required": missing_timezone_count > 0,
            },
        },
        {
            "slot_id": "trusted-timezone-diff-disclosure",
            "status": "complete",
            "evidence": {
                "trusted_diff_status": trusted_status,
                "trusted_tool": str(trusted_diff.get("trusted_tool") or ""),
            },
        },
    ]
    blocking_slots: list[dict[str, object]] = []
    if event_count == 0:
        blocking_slots.append(
            {
                "slot_id": "case-events-present",
                "status": "blocked",
                "blocker": "no-case-events-for-time-validation",
                "required_evidence": "at least one case event with an original timestamp",
            }
        )
    if len([value for value in sample_row_hashes if value]) != len(samples):
        blocking_slots.append(
            {
                "slot_id": "timezone-sample-row-hash-completeness",
                "status": "blocked",
                "blocker": "timezone-sample-row-hash-completeness-required",
                "required_evidence": "row hash for every timezone validation sample",
            }
        )
    if missing_timezone_count:
        blocking_slots.append(
            {
                "slot_id": "source-timezone-completeness",
                "status": "blocked",
                "blocker": "source-timezone-completeness-required",
                "required_evidence": "source timezone or parser-specific timezone assumption for every reportable timestamp",
                "missing_timezone_count": missing_timezone_count,
            }
        )
    if not timezone_manifest.get("manifest_hash") or not timezone_manifest.get("parser_assumption_matrix_hash"):
        blocking_slots.append(
            {
                "slot_id": "timezone-normalization-manifest-complete",
                "status": "blocked",
                "blocker": "timezone-normalization-manifest-required",
                "required_evidence": "timezone normalization manifest hash and parser assumption matrix hash",
            }
        )
    if not time_semantics_manifest.get("manifest_hash"):
        blocking_slots.append(
            {
                "slot_id": "time-semantics-manifest-complete",
                "status": "blocked",
                "blocker": "time-semantics-manifest-required",
                "required_evidence": "time semantics manifest with original/normalized timestamp citation fields",
            }
        )
    if trusted_status != "pass":
        blocking_slots.append(
            {
                "slot_id": "trusted-timezone-normalization-matrix-diff",
                "status": "external-required",
                "blocker": TIMEZONE_VALIDATION_TRUSTED_DIFF_BLOCKER_97,
                "required_evidence": "trusted timezone matrix diff covering summary, samples, parser assumptions, and time semantics manifest",
            }
        )
    blocking_slots.extend(
        [
            {
                "slot_id": "parser-timezone-assumption-matrix",
                "status": "external-required",
                "blocker": "parser-timezone-assumption-matrix-required",
                "required_evidence": "parser-family/version timezone assumption matrix reviewed for all timestamp sources",
            },
            {
                "slot_id": "multi-source-timezone-reconciliation",
                "status": "external-required",
                "blocker": "multi-source-timezone-reconciliation-required",
                "required_evidence": "case-level reconciliation across OS, filesystem, browser, app, cloud, and acquisition timestamps",
            },
            {
                "slot_id": "timezone-known-answer-corpus",
                "status": "external-required",
                "blocker": "timezone-known-answer-corpus-required",
                "required_evidence": "known-answer fixture corpus for UTC, local, offset, missing, and parser-assumed timestamps",
            },
            {
                "slot_id": "daylight-saving-edge-case-corpus",
                "status": "external-required",
                "blocker": "daylight-saving-edge-case-corpus-required",
                "required_evidence": "DST and ambiguous local-time edge-case corpus for supported regions",
            },
            {
                "slot_id": "source-clock-baseline",
                "status": "external-required",
                "blocker": "source-clock-baseline-required",
                "required_evidence": "source clock/acquisition baseline tied to #98 clock-skew analysis",
            },
        ]
    )
    plan_core: dict[str, object] = {
        "profile_version": TIMEZONE_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 97,
        "commercial_gap_ids": [TIMEZONE_NORMALIZATION_GAP_ID],
        "plan_context": "case-db-timezone-normalization-validation",
        "event_count": event_count,
        "missing_timezone_count": missing_timezone_count,
        "sample_count": len(samples),
        "timezone_normalization_manifest_hash": str(timezone_manifest.get("manifest_hash") or ""),
        "parser_assumption_matrix_hash": str(timezone_manifest.get("parser_assumption_matrix_hash") or ""),
        "time_semantics_manifest_hash": str(time_semantics_manifest.get("manifest_hash") or ""),
        "trusted_diff_status": trusted_status,
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "external_blocker_catalog": list(TIMEZONE_REPORT_GRADE_BLOCKERS),
        "blockers": sorted({str(slot.get("blocker") or "") for slot in blocking_slots if slot.get("blocker")}),
        "commercial_claim_allowed": False,
        "reporting_boundary": "This plan makes timezone normalization auditable, but commercial claims require source timezone completeness or validated parser assumptions, trusted timezone matrices, multi-source reconciliation, known-answer/DST corpus, and source clock baselines.",
    }
    return {**plan_core, "validation_plan_hash": stable_payload_sha256(plan_core)}


def build_timezone_validation(
    connection: sqlite3.Connection,
    case_id: str,
    *,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    rows = connection.execute(
        """
        SELECT timestamp, timezone, timestamp_kind, source, event_type
        FROM event
        WHERE case_id = ?
        ORDER BY timestamp ASC, id ASC
        """,
        (case_id,),
    ).fetchall()
    missing = 0
    timezone_counts: dict[str, int] = {}
    samples = []
    for row in rows:
        timestamp = str(row["timestamp"] or "")
        timezone = str(row["timezone"] or "")
        if not timezone:
            missing += 1
        else:
            timezone_counts[timezone] = timezone_counts.get(timezone, 0) + 1
        normalized = parse_event_timestamp(timestamp)
        if len(samples) < 20:
            samples.append(
                attach_timezone_sample_row_hash(
                    {
                        "timestamp": timestamp,
                        "timezone": timezone,
                        "normalized_utc": normalized.isoformat() if normalized else "",
                        "timestamp_parse_status": "parsed" if normalized else "unparsed",
                        "parser_assumption": (
                            "source-timezone-preserved"
                            if timezone
                            else "assume-utc-because-source-timezone-missing"
                        ),
                        "timestamp_kind": str(row["timestamp_kind"] or ""),
                        "source": str(row["source"] or ""),
                        "event_type": str(row["event_type"] or ""),
                    }
                )
            )
    if trusted_diff is None:
        trusted_diff = missing_timezone_validation_trusted_diff()
    blockers = []
    if trusted_diff.get("status") != "pass":
        blockers.append(TIMEZONE_VALIDATION_TRUSTED_DIFF_BLOCKER_97)
    timezone_manifest = build_timezone_normalization_manifest(
        event_count=len(rows),
        missing_timezone_count=missing,
        timezone_counts=timezone_counts,
        samples=samples,
        trusted_diff=trusted_diff,
    )
    time_semantics_manifest = build_time_semantics_manifest(
        samples=samples,
        timezone_manifest=timezone_manifest,
        trusted_diff=trusted_diff,
    )
    report_grade_validation_plan = build_timezone_report_grade_validation_plan(
        event_count=len(rows),
        missing_timezone_count=missing,
        samples=samples,
        timezone_manifest=timezone_manifest,
        time_semantics_manifest=time_semantics_manifest,
        trusted_diff=trusted_diff,
    )
    blockers = sorted({*blockers, *report_grade_validation_plan["blockers"]})
    return {
        "status": "timezone-review-required" if missing else "timezone-fields-present",
        "commercial_gap_ids": [TIMEZONE_NORMALIZATION_GAP_ID],
        "functional_priority_profile": timezone_clock_functional_profile(
            event_count=len(rows),
            missing_timezone_count=missing,
            timezone_counts=timezone_counts,
            sample_count=len(samples),
            clock_warning_count=None,
            time_semantics_manifest=time_semantics_manifest,
            trusted_diff=trusted_diff,
        ),
        "summary": {
            "event_count": len(rows),
            "missing_timezone_count": missing,
            "timezone_counts": timezone_counts,
            "timezone_normalization_manifest_hash": timezone_manifest["manifest_hash"],
            "time_semantics_manifest_hash": time_semantics_manifest["manifest_hash"],
            "timezone_report_grade_validation_plan_hash": report_grade_validation_plan["validation_plan_hash"],
            "commercial_gap_ids": [TIMEZONE_NORMALIZATION_GAP_ID],
        },
        "samples": samples,
        "timezone_normalization_manifest": timezone_manifest,
        "timezone_normalization_manifest_hash": timezone_manifest["manifest_hash"],
        "parser_assumption_matrix_hash": timezone_manifest["parser_assumption_matrix_hash"],
        "time_semantics_manifest": time_semantics_manifest,
        "time_semantics_manifest_hash": time_semantics_manifest["manifest_hash"],
        "timezone_report_grade_validation_plan": report_grade_validation_plan,
        "timezone_report_grade_validation_plan_hash": report_grade_validation_plan["validation_plan_hash"],
        "timezone_report_grade_ready_slot_count": report_grade_validation_plan["ready_slot_count"],
        "timezone_report_grade_blocking_slot_count": report_grade_validation_plan["blocking_slot_count"],
        "trusted_timezone_validation_diff": trusted_diff,
        "blockers": blockers,
        "validation_assessment": {
            "commercial_gap_ids": [TIMEZONE_NORMALIZATION_GAP_ID],
            "original_timestamp_preserved": True,
            "normalized_utc_assumption": "timestamps are interpreted as UTC when parser/source timezone is absent",
            "review_required": bool(missing),
            "timezone_normalization_manifest_hash": timezone_manifest["manifest_hash"],
            "parser_assumption_matrix_hash": timezone_manifest["parser_assumption_matrix_hash"],
            "time_semantics_manifest_hash": time_semantics_manifest["manifest_hash"],
            "timezone_report_grade_validation_plan_hash": report_grade_validation_plan["validation_plan_hash"],
            "timezone_report_grade_ready_slot_count": report_grade_validation_plan["ready_slot_count"],
            "timezone_report_grade_blocking_slot_count": report_grade_validation_plan["blocking_slot_count"],
            "core_accuracy_gates": timezone_validation_core_accuracy_gates(
                event_count=len(rows),
                missing_timezone_count=missing,
                samples=samples,
                timezone_manifest=timezone_manifest,
                time_semantics_manifest=time_semantics_manifest,
                report_grade_validation_plan=report_grade_validation_plan,
                trusted_diff=trusted_diff,
            ),
            "trusted_timezone_validation_diff": trusted_diff,
            "blockers": blockers,
        },
        "guidance": "Preserve original timestamp, source timezone, normalized UTC assumption, and parser-specific timezone notes in final reports.",
    }


def attach_clock_skew_warning_row_hash(warning: Mapping[str, object]) -> dict[str, object]:
    row = dict(warning)
    row["clock_skew_warning_row_hash"] = stable_payload_sha256(
        {
            "type": row.get("type"),
            "timestamp": row.get("timestamp"),
            "source": row.get("source"),
        }
    )
    return row


def build_clock_skew_baseline_manifest(
    *,
    parsed_timestamp_count: int,
    warnings: Sequence[Mapping[str, object]],
    earliest: str,
    latest: str,
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    range_matrix = build_clock_skew_range_matrix(
        parsed_timestamp_count=parsed_timestamp_count,
        warnings=warnings,
        earliest=earliest,
        latest=latest,
    )
    manifest_core = {
        "profile_version": "clock-skew-baseline-manifest-v1",
        "item_number": 98,
        "parsed_timestamp_count": parsed_timestamp_count,
        "warning_count": len(warnings),
        "warning_row_hashes": [str(item.get("clock_skew_warning_row_hash") or "") for item in warnings],
        "earliest_timestamp": earliest,
        "latest_timestamp": latest,
        "clock_skew_range_matrix": range_matrix,
        "clock_skew_range_matrix_hash": range_matrix["matrix_hash"],
        "baseline_required": "Compare host/device time against acquisition notes and trusted external events.",
        "heuristic_only": True,
        "trusted_diff_status": str(trusted_diff.get("status") or ""),
        "commercial_gap_ids": [CLOCK_SKEW_ANALYSIS_GAP_ID],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_clock_skew_range_matrix(
    *,
    parsed_timestamp_count: int,
    warnings: Sequence[Mapping[str, object]],
    earliest: str,
    latest: str,
) -> dict[str, object]:
    warning_type_counts: dict[str, int] = {}
    for warning in warnings:
        warning_type = str(warning.get("type") or "unknown")
        warning_type_counts[warning_type] = warning_type_counts.get(warning_type, 0) + 1
    matrix_core = {
        "profile_version": "clock-skew-range-matrix-v1",
        "item_number": 98,
        "parsed_timestamp_count": parsed_timestamp_count,
        "earliest_timestamp": earliest,
        "latest_timestamp": latest,
        "warning_type_counts": dict(sorted(warning_type_counts.items())),
        "warning_count": len(warnings),
        "baseline_attached": False,
        "commercial_claim_allowed": False,
    }
    return {**matrix_core, "matrix_hash": stable_payload_sha256(matrix_core)}


def build_clock_skew_report_grade_validation_plan(
    *,
    parsed_timestamp_count: int,
    warnings: Sequence[Mapping[str, object]],
    earliest: str,
    latest: str,
    clock_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    trusted_status = str(trusted_diff.get("status") or "missing")
    warning_row_hashes = [str(warning.get("clock_skew_warning_row_hash") or "") for warning in warnings]
    ready_slots = [
        {
            "slot_id": "parsed-timestamp-range",
            "status": "complete",
            "evidence": {
                "parsed_timestamp_count": parsed_timestamp_count,
                "earliest_timestamp": earliest,
                "latest_timestamp": latest,
            },
        },
        {
            "slot_id": "clock-skew-warning-records",
            "status": "complete",
            "evidence": {
                "warning_count": len(warnings),
                "warning_row_hash_count": sum(1 for value in warning_row_hashes if value),
            },
        },
        {
            "slot_id": "clock-skew-range-matrix",
            "status": "complete",
            "evidence": {"matrix_hash": str(clock_manifest.get("clock_skew_range_matrix_hash") or "")},
        },
        {
            "slot_id": "clock-skew-baseline-manifest",
            "status": "complete",
            "evidence": {"manifest_hash": str(clock_manifest.get("manifest_hash") or "")},
        },
        {
            "slot_id": "baseline-and-heuristic-disclosure",
            "status": "complete",
            "evidence": {
                "baseline_required": str(clock_manifest.get("baseline_required") or ""),
                "heuristic_only": bool(clock_manifest.get("heuristic_only")),
            },
        },
        {
            "slot_id": "trusted-clock-skew-diff-disclosure",
            "status": "complete",
            "evidence": {
                "trusted_diff_status": trusted_status,
                "trusted_tool": str(trusted_diff.get("trusted_tool") or ""),
            },
        },
    ]
    blocking_slots: list[dict[str, object]] = []
    if parsed_timestamp_count == 0:
        blocking_slots.append(
            {
                "slot_id": "parsed-timestamps-present",
                "status": "blocked",
                "blocker": "parsed-timestamps-present-required",
                "required_evidence": "at least one parsed case timestamp before clock-skew review",
            }
        )
    if len([value for value in warning_row_hashes if value]) != len(warnings):
        blocking_slots.append(
            {
                "slot_id": "clock-skew-warning-row-hash-completeness",
                "status": "blocked",
                "blocker": "clock-skew-warning-row-hash-completeness-required",
                "required_evidence": "row hash for every exported clock-skew warning record",
            }
        )
    if not clock_manifest.get("manifest_hash") or not clock_manifest.get("clock_skew_range_matrix_hash"):
        blocking_slots.append(
            {
                "slot_id": "clock-skew-baseline-manifest-complete",
                "status": "blocked",
                "blocker": "clock-skew-baseline-manifest-required",
                "required_evidence": "clock-skew baseline manifest hash and range matrix hash",
            }
        )
    if trusted_status != "pass":
        blocking_slots.append(
            {
                "slot_id": "trusted-clock-skew-baseline-diff",
                "status": "external-required",
                "blocker": CLOCK_SKEW_TRUSTED_DIFF_BLOCKER_98,
                "required_evidence": "trusted clock-skew baseline diff covering parsed ranges, warnings, baseline manifest, and range matrix",
            }
        )
    blocking_slots.extend(
        [
            {
                "slot_id": "host-device-clock-baseline",
                "status": "external-required",
                "blocker": "host-device-clock-baseline-required",
                "required_evidence": "host/device clock baseline captured at acquisition and tied to the evidence source",
            },
            {
                "slot_id": "multi-device-skew-model",
                "status": "external-required",
                "blocker": "multi-device-skew-model-required",
                "required_evidence": "case-level model reconciling skew across each host, mobile device, cloud source, and removable media source",
            },
            {
                "slot_id": "trusted-external-timestamp-comparison",
                "status": "external-required",
                "blocker": "trusted-external-timestamp-comparison-required",
                "required_evidence": "comparison against trusted external timestamps such as acquisition logs, server logs, NTP records, or signed communications",
            },
            {
                "slot_id": "acquisition-time-baseline",
                "status": "external-required",
                "blocker": "acquisition-time-baseline-required",
                "required_evidence": "acquisition-start and acquisition-end timestamps with trusted operator/device time source",
            },
            {
                "slot_id": "timezone-normalization-linkage",
                "status": "external-required",
                "blocker": "timezone-normalization-linkage-required",
                "required_evidence": "linkage to #97 timezone normalization output for every reportable skew conclusion",
            },
            {
                "slot_id": "clock-skew-known-answer-corpus",
                "status": "external-required",
                "blocker": "clock-skew-known-answer-corpus-required",
                "required_evidence": "known-answer corpus with normal, skewed, future, pre-epoch, and multi-device timestamp fixtures",
            },
        ]
    )
    plan_core: dict[str, object] = {
        "profile_version": CLOCK_SKEW_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 98,
        "commercial_gap_ids": [CLOCK_SKEW_ANALYSIS_GAP_ID],
        "plan_context": "case-db-clock-skew-analysis-validation",
        "parsed_timestamp_count": parsed_timestamp_count,
        "warning_count": len(warnings),
        "earliest_timestamp": earliest,
        "latest_timestamp": latest,
        "clock_skew_baseline_manifest_hash": str(clock_manifest.get("manifest_hash") or ""),
        "clock_skew_range_matrix_hash": str(clock_manifest.get("clock_skew_range_matrix_hash") or ""),
        "trusted_diff_status": trusted_status,
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "external_blocker_catalog": list(CLOCK_SKEW_REPORT_GRADE_BLOCKERS),
        "blockers": sorted({str(slot.get("blocker") or "") for slot in blocking_slots if slot.get("blocker")}),
        "commercial_claim_allowed": False,
        "reporting_boundary": "This plan makes clock-skew review auditable, but commercial claims require trusted host/device baselines, acquisition-time baselines, external timestamp comparisons, multi-device skew modeling, #97 timezone linkage, and known-answer corpus evidence.",
    }
    return {**plan_core, "validation_plan_hash": stable_payload_sha256(plan_core)}


def build_clock_skew_analysis(
    connection: sqlite3.Connection,
    case_id: str,
    *,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    rows = connection.execute(
        """
        SELECT timestamp, source, event_type, description
        FROM event
        WHERE case_id = ?
        ORDER BY timestamp ASC, id ASC
        """,
        (case_id,),
    ).fetchall()
    warnings = []
    parsed_times: list[dt.datetime] = []
    now = dt.datetime.now(dt.timezone.utc)
    for row in rows:
        parsed = parse_event_timestamp(str(row["timestamp"] or ""))
        if parsed is None:
            continue
        parsed_times.append(parsed)
        if parsed.year < 1980:
            warnings.append(
                attach_clock_skew_warning_row_hash(
                    {"type": "timestamp-before-1980", "timestamp": str(row["timestamp"]), "source": str(row["source"] or "")}
                )
            )
        if parsed > now + dt.timedelta(days=2):
            warnings.append(
                attach_clock_skew_warning_row_hash(
                    {"type": "timestamp-in-future", "timestamp": str(row["timestamp"]), "source": str(row["source"] or "")}
                )
            )
    if trusted_diff is None:
        trusted_diff = missing_clock_skew_trusted_diff()
    blockers = []
    if trusted_diff.get("status") != "pass":
        blockers.append(CLOCK_SKEW_TRUSTED_DIFF_BLOCKER_98)
    earliest = min((value.isoformat() for value in parsed_times), default="")
    latest = max((value.isoformat() for value in parsed_times), default="")
    warnings_for_report = warnings[:100]
    clock_manifest = build_clock_skew_baseline_manifest(
        parsed_timestamp_count=len(parsed_times),
        warnings=warnings_for_report,
        earliest=earliest,
        latest=latest,
        trusted_diff=trusted_diff,
    )
    report_grade_validation_plan = build_clock_skew_report_grade_validation_plan(
        parsed_timestamp_count=len(parsed_times),
        warnings=warnings_for_report,
        earliest=earliest,
        latest=latest,
        clock_manifest=clock_manifest,
        trusted_diff=trusted_diff,
    )
    blockers = sorted({*blockers, *report_grade_validation_plan["blockers"]})
    return {
        "status": "warnings-present" if warnings else "no-obvious-clock-skew",
        "commercial_gap_ids": [CLOCK_SKEW_ANALYSIS_GAP_ID],
        "functional_priority_profile": timezone_clock_functional_profile(
            event_count=len(rows),
            missing_timezone_count=None,
            timezone_counts={},
            sample_count=0,
            clock_warning_count=len(warnings),
            trusted_diff=trusted_diff,
        ),
        "summary": {
            "event_count": len(rows),
            "parsed_timestamp_count": len(parsed_times),
            "warning_count": len(warnings),
            "earliest_timestamp": earliest,
            "latest_timestamp": latest,
            "clock_skew_baseline_manifest_hash": clock_manifest["manifest_hash"],
            "clock_skew_range_matrix_hash": clock_manifest["clock_skew_range_matrix_hash"],
            "clock_skew_report_grade_validation_plan_hash": report_grade_validation_plan["validation_plan_hash"],
            "clock_skew_report_grade_ready_slot_count": report_grade_validation_plan["ready_slot_count"],
            "clock_skew_report_grade_blocking_slot_count": report_grade_validation_plan["blocking_slot_count"],
            "commercial_gap_ids": [CLOCK_SKEW_ANALYSIS_GAP_ID],
        },
        "warnings": warnings_for_report,
        "clock_skew_baseline_manifest": clock_manifest,
        "clock_skew_baseline_manifest_hash": clock_manifest["manifest_hash"],
        "clock_skew_range_matrix_hash": clock_manifest["clock_skew_range_matrix_hash"],
        "clock_skew_report_grade_validation_plan": report_grade_validation_plan,
        "clock_skew_report_grade_validation_plan_hash": report_grade_validation_plan["validation_plan_hash"],
        "clock_skew_report_grade_ready_slot_count": report_grade_validation_plan["ready_slot_count"],
        "clock_skew_report_grade_blocking_slot_count": report_grade_validation_plan["blocking_slot_count"],
        "trusted_clock_skew_diff": trusted_diff,
        "blockers": blockers,
        "validation_assessment": {
            "commercial_gap_ids": [CLOCK_SKEW_ANALYSIS_GAP_ID],
            "heuristic_only": True,
            "baseline_required": "Compare host/device time against acquisition notes and trusted external events.",
            "review_required": bool(warnings),
            "clock_skew_baseline_manifest_hash": clock_manifest["manifest_hash"],
            "clock_skew_range_matrix_hash": clock_manifest["clock_skew_range_matrix_hash"],
            "clock_skew_report_grade_validation_plan_hash": report_grade_validation_plan["validation_plan_hash"],
            "clock_skew_report_grade_ready_slot_count": report_grade_validation_plan["ready_slot_count"],
            "clock_skew_report_grade_blocking_slot_count": report_grade_validation_plan["blocking_slot_count"],
            "core_accuracy_gates": clock_skew_core_accuracy_gates(
                parsed_timestamp_count=len(parsed_times),
                warnings=warnings_for_report,
                earliest=earliest,
                latest=latest,
                clock_manifest=clock_manifest,
                report_grade_validation_plan=report_grade_validation_plan,
                trusted_diff=trusted_diff,
            ),
            "trusted_clock_skew_diff": trusted_diff,
            "blockers": blockers,
        },
        "guidance": "Clock skew detection is heuristic; compare against acquisition notes, system timezone, and trusted external timestamps.",
    }


def attach_contamination_warning_row_hash(warning: Mapping[str, object]) -> dict[str, object]:
    row = dict(warning)
    row["contamination_warning_row_hash"] = stable_payload_sha256(
        {
            "type": row.get("type"),
            "citation_id": row.get("citation_id"),
            "path": row.get("path"),
            "metadata_citation_id": row.get("metadata_citation_id"),
            "write_blocker": row.get("write_blocker"),
        }
    )
    return row


def build_contamination_checklist_manifest(
    *,
    warnings: Sequence[Mapping[str, object]],
    evidence_source_count: int,
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    warning_type_counts: dict[str, int] = {}
    for warning in warnings:
        warning_type = str(warning.get("type") or "")
        warning_type_counts[warning_type] = warning_type_counts.get(warning_type, 0) + 1
    warning_review_matrix = build_contamination_warning_review_matrix(warnings)
    manifest_core = {
        "profile_version": "contamination-checklist-manifest-v1",
        "item_number": 99,
        "evidence_source_count": evidence_source_count,
        "warning_count": len(warnings),
        "warning_type_counts": warning_type_counts,
        "warning_row_hashes": [str(item.get("contamination_warning_row_hash") or "") for item in warnings],
        "warning_review_matrix": warning_review_matrix,
        "warning_review_matrix_hash": warning_review_matrix["matrix_hash"],
        "write_blocker_integration": "not-connected",
        "checks": [
            "rapidtriage-output-inside-evidence-root",
            "staged-output-under-evidence-root",
            "zero-byte-source",
            "source-path-stat-failed",
            "writable-source-permission",
            "acquisition-metadata-missing-for-evidence-source",
            "write-blocker-missing-for-evidence-source",
        ],
        "trusted_diff_status": str(trusted_diff.get("status") or ""),
        "commercial_gap_ids": [EVIDENCE_CONTAMINATION_WARNING_GAP_ID],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_contamination_warning_review_matrix(warnings: Sequence[Mapping[str, object]]) -> dict[str, object]:
    rows = []
    for warning in warnings:
        row_core = {
            "type": str(warning.get("type") or ""),
            "citation_id": str(warning.get("citation_id") or ""),
            "metadata_citation_id": str(warning.get("metadata_citation_id") or ""),
            "path_hash": stable_payload_sha256(str(warning.get("path") or "")),
            "requires_acquisition_review": True,
            "requires_write_blocker_review": str(warning.get("type") or "") in {
                "write-blocker-missing-for-evidence-source",
                "writable-source-permission",
            },
        }
        rows.append({**row_core, "row_hash": stable_payload_sha256(row_core)})
    matrix_core = {
        "profile_version": "contamination-warning-review-matrix-v1",
        "item_number": 99,
        "warning_count": len(warnings),
        "rows": rows,
        "requires_acquisition_review_count": sum(1 for row in rows if row.get("requires_acquisition_review")),
        "requires_write_blocker_review_count": sum(1 for row in rows if row.get("requires_write_blocker_review")),
        "commercial_claim_allowed": False,
    }
    return {**matrix_core, "matrix_hash": stable_payload_sha256(matrix_core)}


def build_contamination_acquisition_context_manifest(
    *,
    evidence_sources: Sequence[Mapping[str, object]],
    metadata_records: Sequence[Mapping[str, object]],
    warnings: Sequence[Mapping[str, object]],
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    metadata_by_source = {
        str(record.get("evidence_source_citation_id") or ""): record
        for record in metadata_records
        if str(record.get("evidence_source_citation_id") or "")
    }
    source_rows = []
    missing_metadata_count = 0
    missing_write_blocker_count = 0
    writable_source_count = 0
    warning_by_source: dict[str, list[str]] = {}
    for warning in warnings:
        citation_id = str(warning.get("citation_id") or "")
        warning_by_source.setdefault(citation_id, []).append(str(warning.get("type") or ""))
    for source in evidence_sources:
        citation_id = str(source.get("citation_id") or "")
        metadata = metadata_by_source.get(citation_id, {})
        write_blocker = str(metadata.get("write_blocker") or "")
        source_warnings = warning_by_source.get(citation_id, [])
        if not metadata:
            missing_metadata_count += 1
        if not write_blocker:
            missing_write_blocker_count += 1
        if "writable-source-permission" in source_warnings:
            writable_source_count += 1
        source_rows.append(
            {
                "citation_id": citation_id,
                "original_path": str(source.get("original_path") or ""),
                "staged_path": str(source.get("staged_path") or ""),
                "metadata_citation_id": str(metadata.get("citation_id") or ""),
                "write_blocker_recorded": bool(write_blocker),
                "write_blocker_hash": stable_payload_sha256({"write_blocker": write_blocker}) if write_blocker else "",
                "source_writable_warning": "writable-source-permission" in source_warnings,
                "warning_types": sorted(set(source_warnings)),
            }
        )
    manifest_core: dict[str, object] = {
        "profile_version": "contamination-acquisition-context-manifest-v1",
        "item_number": 43,
        "batch_id": FUNCTIONAL_DEFENSIBILITY_BATCH_ID,
        "gap_id": "#43",
        "commercial_gap_ids": [EVIDENCE_CONTAMINATION_WARNING_GAP_ID, WRITE_BLOCKER_ACQUISITION_METADATA_GAP_ID],
        "evidence_source_count": len(evidence_sources),
        "acquisition_metadata_record_count": len(metadata_records),
        "missing_acquisition_metadata_count": missing_metadata_count,
        "missing_write_blocker_count": missing_write_blocker_count,
        "writable_source_warning_count": writable_source_count,
        "warning_row_hashes": [str(warning.get("contamination_warning_row_hash") or "") for warning in warnings],
        "source_rows": source_rows,
        "trusted_diff_status": str(trusted_diff.get("status") or ""),
        "commercial_claim_allowed": False,
        "operator_warning": "Writable-source and missing write-blocker findings must be reviewed with acquisition metadata before submission.",
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_contamination_report_grade_validation_plan(
    *,
    warnings: Sequence[Mapping[str, object]],
    evidence_source_count: int,
    contamination_manifest: Mapping[str, object],
    acquisition_context_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    trusted_status = str(trusted_diff.get("status") or "missing")
    warning_row_hashes = [str(warning.get("contamination_warning_row_hash") or "") for warning in warnings]
    ready_slots = [
        {
            "slot_id": "contamination-warning-records",
            "status": "complete",
            "evidence": {
                "warning_count": len(warnings),
                "evidence_source_count": evidence_source_count,
            },
        },
        {
            "slot_id": "contamination-warning-row-hashes",
            "status": "complete",
            "evidence": {
                "warning_row_hash_count": sum(1 for value in warning_row_hashes if value),
                "warning_count": len(warnings),
            },
        },
        {
            "slot_id": "contamination-checklist-manifest",
            "status": "complete",
            "evidence": {"manifest_hash": str(contamination_manifest.get("manifest_hash") or "")},
        },
        {
            "slot_id": "warning-review-matrix",
            "status": "complete",
            "evidence": {
                "matrix_hash": str(contamination_manifest.get("warning_review_matrix_hash") or ""),
                "warning_count": int(
                    (
                        contamination_manifest.get("warning_review_matrix")
                        if isinstance(contamination_manifest.get("warning_review_matrix"), Mapping)
                        else {}
                    ).get("warning_count")
                    or 0
                ),
            },
        },
        {
            "slot_id": "contamination-acquisition-context-manifest",
            "status": "complete",
            "evidence": {
                "manifest_hash": str(acquisition_context_manifest.get("manifest_hash") or ""),
                "missing_write_blocker_count": int(
                    acquisition_context_manifest.get("missing_write_blocker_count") or 0
                ),
            },
        },
        {
            "slot_id": "write-blocker-limitation-disclosure",
            "status": "complete",
            "evidence": {
                "write_blocker_integration": str(contamination_manifest.get("write_blocker_integration") or ""),
                "operator_warning": str(acquisition_context_manifest.get("operator_warning") or ""),
            },
        },
        {
            "slot_id": "trusted-contamination-diff-disclosure",
            "status": "complete",
            "evidence": {
                "trusted_diff_status": trusted_status,
                "trusted_tool": str(trusted_diff.get("trusted_tool") or ""),
            },
        },
    ]
    blocking_slots: list[dict[str, object]] = []
    if evidence_source_count == 0:
        blocking_slots.append(
            {
                "slot_id": "evidence-sources-present",
                "status": "blocked",
                "blocker": "evidence-sources-present-required",
                "required_evidence": "at least one evidence source before contamination review",
            }
        )
    if len([value for value in warning_row_hashes if value]) != len(warnings):
        blocking_slots.append(
            {
                "slot_id": "contamination-warning-row-hash-completeness",
                "status": "blocked",
                "blocker": "contamination-warning-row-hash-completeness-required",
                "required_evidence": "row hash for every exported contamination warning",
            }
        )
    if not contamination_manifest.get("manifest_hash") or not contamination_manifest.get("warning_review_matrix_hash"):
        blocking_slots.append(
            {
                "slot_id": "contamination-checklist-manifest-complete",
                "status": "blocked",
                "blocker": "contamination-checklist-manifest-required",
                "required_evidence": "contamination checklist manifest hash and warning-review matrix hash",
            }
        )
    if not acquisition_context_manifest.get("manifest_hash"):
        blocking_slots.append(
            {
                "slot_id": "contamination-acquisition-context-manifest-complete",
                "status": "blocked",
                "blocker": "contamination-acquisition-context-manifest-required",
                "required_evidence": "acquisition-context manifest linking warnings to acquisition metadata/write-blocker fields",
            }
        )
    if trusted_status != "pass":
        blocking_slots.append(
            {
                "slot_id": "trusted-contamination-checklist-diff",
                "status": "external-required",
                "blocker": CONTAMINATION_WARNING_TRUSTED_DIFF_BLOCKER_99,
                "required_evidence": "trusted contamination checklist diff covering warnings, manifests, review matrix, and acquisition context",
            }
        )
    blocking_slots.extend(
        [
            {
                "slot_id": "acquisition-time-mtime-baseline",
                "status": "external-required",
                "blocker": "acquisition-time-mtime-baseline-required",
                "required_evidence": "acquisition-time source mtime baseline and post-run comparison for each evidence source",
            },
            {
                "slot_id": "write-blocker-integration",
                "status": "external-required",
                "blocker": "write-blocker-integration-required",
                "required_evidence": "write-blocker device/log integration proving source media was not writable during acquisition/review",
            },
            {
                "slot_id": "source-read-only-proof",
                "status": "external-required",
                "blocker": "source-read-only-proof-required",
                "required_evidence": "read-only mount/device policy proof for every original evidence source",
            },
            {
                "slot_id": "output-path-policy-enforcement",
                "status": "external-required",
                "blocker": "output-path-policy-enforcement-required",
                "required_evidence": "enforced output path policy preventing generated files under evidence roots",
            },
            {
                "slot_id": "contamination-known-answer-corpus",
                "status": "external-required",
                "blocker": "contamination-known-answer-corpus-required",
                "required_evidence": "known-answer corpus for writable source, output-under-evidence, zero-byte, stat-failure, mtime-change, and missing write-blocker cases",
            },
            {
                "slot_id": "reviewer-signoff-workflow",
                "status": "external-required",
                "blocker": "reviewer-signoff-workflow-required",
                "required_evidence": "analyst/reviewer signoff on contamination warnings before report submission",
            },
        ]
    )
    plan_core: dict[str, object] = {
        "profile_version": CONTAMINATION_WARNING_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 99,
        "commercial_gap_ids": [EVIDENCE_CONTAMINATION_WARNING_GAP_ID],
        "plan_context": "case-db-evidence-contamination-validation",
        "warning_count": len(warnings),
        "evidence_source_count": evidence_source_count,
        "contamination_checklist_manifest_hash": str(contamination_manifest.get("manifest_hash") or ""),
        "warning_review_matrix_hash": str(contamination_manifest.get("warning_review_matrix_hash") or ""),
        "contamination_acquisition_context_manifest_hash": str(
            acquisition_context_manifest.get("manifest_hash") or ""
        ),
        "trusted_diff_status": trusted_status,
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "external_blocker_catalog": list(CONTAMINATION_WARNING_REPORT_GRADE_BLOCKERS),
        "blockers": sorted({str(slot.get("blocker") or "") for slot in blocking_slots if slot.get("blocker")}),
        "commercial_claim_allowed": False,
        "reporting_boundary": "This plan makes contamination warnings auditable, but commercial claims require acquisition-time mtime baselines, write-blocker integration, source read-only proof, enforced output path policy, trusted checklist diffs, known-answer corpus, and reviewer signoff.",
    }
    return {**plan_core, "validation_plan_hash": stable_payload_sha256(plan_core)}


def build_evidence_contamination_warnings(
    connection: sqlite3.Connection,
    case_id: str,
    *,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    rows = connection.execute(
        """
        SELECT citation_id, original_path, staged_path
        FROM evidence_source
        WHERE case_id = ?
        ORDER BY id ASC
        """,
        (case_id,),
    ).fetchall()
    metadata_rows = connection.execute(
        """
        SELECT * FROM acquisition_metadata
        WHERE case_id = ?
        ORDER BY created_at ASC, id ASC
        """,
        (case_id,),
    ).fetchall()
    metadata_records = [acquisition_metadata_to_dict(row) for row in metadata_rows]
    metadata_by_source = {
        str(record.get("evidence_source_citation_id") or ""): record
        for record in metadata_records
        if str(record.get("evidence_source_citation_id") or "")
    }
    evidence_sources = [
        {
            "citation_id": str(row["citation_id"]),
            "original_path": str(row["original_path"] or ""),
            "staged_path": str(row["staged_path"] or ""),
        }
        for row in rows
    ]
    warnings = []
    for row in rows:
        citation_id = str(row["citation_id"])
        original = Path(str(row["original_path"] or "")).expanduser()
        staged = Path(str(row["staged_path"] or "")).expanduser()
        metadata = metadata_by_source.get(citation_id, {})
        if not metadata:
            warnings.append(
                attach_contamination_warning_row_hash(
                    {
                        "type": "acquisition-metadata-missing-for-evidence-source",
                        "citation_id": citation_id,
                        "path": str(original),
                    }
                )
            )
        elif not str(metadata.get("write_blocker") or "").strip():
            warnings.append(
                attach_contamination_warning_row_hash(
                    {
                        "type": "write-blocker-missing-for-evidence-source",
                        "citation_id": citation_id,
                        "path": str(original),
                        "metadata_citation_id": str(metadata.get("citation_id") or ""),
                    }
                )
            )
        try:
            if original.exists() and os.access(original, os.W_OK):
                warnings.append(
                    attach_contamination_warning_row_hash(
                        {"type": "writable-source-permission", "citation_id": citation_id, "path": str(original)}
                    )
                )
            if original.exists() and original.is_dir() and (original / "rapidtriage-run-summary.json").exists():
                warnings.append(
                    attach_contamination_warning_row_hash(
                        {"type": "rapidtriage-output-inside-evidence-root", "citation_id": citation_id, "path": str(original)}
                    )
                )
            if original.exists() and original.is_dir() and staged.exists() and is_relative_to(staged.resolve(), original.resolve()):
                warnings.append(
                    attach_contamination_warning_row_hash(
                        {"type": "staged-output-under-evidence-root", "citation_id": citation_id, "path": str(staged)}
                    )
                )
            if original.exists() and original.is_file() and original.stat().st_size == 0:
                warnings.append(
                    attach_contamination_warning_row_hash(
                        {"type": "zero-byte-source", "citation_id": citation_id, "path": str(original)}
                    )
                )
        except OSError:
            warnings.append(
                attach_contamination_warning_row_hash(
                    {"type": "source-path-stat-failed", "citation_id": citation_id, "path": str(original)}
                )
            )
    if trusted_diff is None:
        trusted_diff = missing_contamination_warning_trusted_diff()
    blockers = []
    if trusted_diff.get("status") != "pass":
        blockers.append(CONTAMINATION_WARNING_TRUSTED_DIFF_BLOCKER_99)
    contamination_manifest = build_contamination_checklist_manifest(
        warnings=warnings,
        evidence_source_count=len(rows),
        trusted_diff=trusted_diff,
    )
    acquisition_context_manifest = build_contamination_acquisition_context_manifest(
        evidence_sources=evidence_sources,
        metadata_records=metadata_records,
        warnings=warnings,
        trusted_diff=trusted_diff,
    )
    report_grade_validation_plan = build_contamination_report_grade_validation_plan(
        warnings=warnings,
        evidence_source_count=len(rows),
        contamination_manifest=contamination_manifest,
        acquisition_context_manifest=acquisition_context_manifest,
        trusted_diff=trusted_diff,
    )
    blockers = sorted({*blockers, *report_grade_validation_plan["blockers"]})
    return {
        "status": "warnings-present" if warnings else "no-obvious-contamination",
        "commercial_gap_ids": [EVIDENCE_CONTAMINATION_WARNING_GAP_ID],
        "functional_priority_profile": contamination_warning_functional_profile(
            warnings=warnings,
            evidence_source_count=len(rows),
            acquisition_context_manifest=acquisition_context_manifest,
            trusted_diff=trusted_diff,
        ),
        "summary": {
            "warning_count": len(warnings),
            "contamination_checklist_manifest_hash": contamination_manifest["manifest_hash"],
            "warning_review_matrix_hash": contamination_manifest["warning_review_matrix_hash"],
            "contamination_acquisition_context_manifest_hash": acquisition_context_manifest["manifest_hash"],
            "contamination_report_grade_validation_plan_hash": report_grade_validation_plan["validation_plan_hash"],
            "contamination_report_grade_ready_slot_count": report_grade_validation_plan["ready_slot_count"],
            "contamination_report_grade_blocking_slot_count": report_grade_validation_plan["blocking_slot_count"],
            "commercial_gap_ids": [EVIDENCE_CONTAMINATION_WARNING_GAP_ID],
        },
        "warnings": warnings,
        "contamination_checklist_manifest": contamination_manifest,
        "contamination_checklist_manifest_hash": contamination_manifest["manifest_hash"],
        "warning_review_matrix_hash": contamination_manifest["warning_review_matrix_hash"],
        "contamination_acquisition_context_manifest": acquisition_context_manifest,
        "contamination_acquisition_context_manifest_hash": acquisition_context_manifest["manifest_hash"],
        "contamination_report_grade_validation_plan": report_grade_validation_plan,
        "contamination_report_grade_validation_plan_hash": report_grade_validation_plan["validation_plan_hash"],
        "contamination_report_grade_ready_slot_count": report_grade_validation_plan["ready_slot_count"],
        "contamination_report_grade_blocking_slot_count": report_grade_validation_plan["blocking_slot_count"],
        "trusted_contamination_warning_diff": trusted_diff,
        "blockers": blockers,
        "validation_assessment": {
            "commercial_gap_ids": [EVIDENCE_CONTAMINATION_WARNING_GAP_ID],
            "write_blocker_integration": "not-connected",
            "review_required": bool(warnings),
            "checks": [
                "rapidtriage-output-inside-evidence-root",
                "staged-output-under-evidence-root",
                "zero-byte-source",
                "source-path-stat-failed",
            ],
            "contamination_checklist_manifest_hash": contamination_manifest["manifest_hash"],
            "warning_review_matrix_hash": contamination_manifest["warning_review_matrix_hash"],
            "contamination_acquisition_context_manifest_hash": acquisition_context_manifest["manifest_hash"],
            "contamination_report_grade_validation_plan_hash": report_grade_validation_plan["validation_plan_hash"],
            "contamination_report_grade_ready_slot_count": report_grade_validation_plan["ready_slot_count"],
            "contamination_report_grade_blocking_slot_count": report_grade_validation_plan["blocking_slot_count"],
            "core_accuracy_gates": contamination_warning_core_accuracy_gates(
                warnings=warnings,
                contamination_manifest=contamination_manifest,
                acquisition_context_manifest=acquisition_context_manifest,
                report_grade_validation_plan=report_grade_validation_plan,
                trusted_diff=trusted_diff,
            ),
            "trusted_contamination_warning_diff": trusted_diff,
            "blockers": blockers,
        },
        "guidance": "Use write-blocked sources and keep RapidTriage outputs outside evidence roots whenever possible.",
    }


def parse_event_timestamp(value: str) -> dt.datetime | None:
    text = value.strip()
    if not text:
        return None
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def acquisition_metadata_functional_profile(
    *,
    records: Sequence[Mapping[str, object]],
    evidence_sources: Sequence[Mapping[str, object]],
    missing_required_fields: Sequence[str],
    input_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    records_with_operator = sum(1 for item in records if str(item.get("operator") or "").strip())
    records_with_write_blocker = sum(1 for item in records if str(item.get("write_blocker") or "").strip())
    records_with_tool = sum(1 for item in records if str(item.get("acquisition_tool") or "").strip())
    records_with_timestamps = sum(
        1
        for item in records
        if str(item.get("acquisition_started_at") or "").strip()
        and str(item.get("acquisition_completed_at") or "").strip()
    )
    failed_checks: list[str] = []
    if not records:
        failed_checks.append("acquisition-metadata-record-not-created")
    if missing_required_fields:
        failed_checks.append("acquisition-required-fields-missing")
    if records_with_write_blocker == 0:
        failed_checks.append("write-blocker-not-recorded")
    if not input_manifest.get("manifest_hash"):
        failed_checks.append("acquisition-metadata-input-manifest-hash-missing")
    if trusted_diff.get("status") != "pass":
        failed_checks.append(ACQUISITION_METADATA_TRUSTED_DIFF_BLOCKER_96)
    return {
        "item_number": 41,
        "batch_id": FUNCTIONAL_DEFENSIBILITY_BATCH_ID,
        "status": "complete" if not failed_checks else "partial",
        "implemented_controls": {
            "evidence_source_count": len(evidence_sources),
            "metadata_record_count": len(records),
            "records_with_operator": records_with_operator,
            "records_with_write_blocker": records_with_write_blocker,
            "records_with_acquisition_tool": records_with_tool,
            "records_with_start_and_end_timestamps": records_with_timestamps,
            "missing_required_fields": list(missing_required_fields),
            "acquisition_metadata_input_manifest_hash": str(input_manifest.get("manifest_hash") or ""),
            "input_field_count": len(input_manifest.get("form_fields") or []),
            "evidence_source_choice_count": int(input_manifest.get("evidence_source_choice_count") or 0),
            "trusted_diff_status": str(trusted_diff.get("status") or ""),
        },
        "passed_validation_check_ids": [
            "case-db-acquisition-metadata-table-exported",
            "required-field-gap-summary-emitted",
            "gui-input-field-manifest-emitted",
            "audit-backed-acquisition-record-entrypoint-present",
        ],
        "failed_validation_check_ids": failed_checks,
        "reportability_decision": {
            "allowed_use": "acquisition-metadata-review-checklist",
            "commercial_claim_allowed": not failed_checks,
            "operator_warning": "Record write-blocker and acquisition handoff details before relying on custody-grade outputs.",
        },
    }


def timezone_clock_functional_profile(
    *,
    event_count: int,
    missing_timezone_count: int | None,
    timezone_counts: Mapping[str, int],
    sample_count: int,
    clock_warning_count: int | None,
    trusted_diff: Mapping[str, object],
    time_semantics_manifest: Mapping[str, object] | None = None,
) -> dict[str, object]:
    failed_checks: list[str] = []
    if event_count == 0:
        failed_checks.append("no-case-events-for-time-validation")
    if missing_timezone_count is not None and missing_timezone_count > 0:
        failed_checks.append("timezone-missing-on-events")
    if clock_warning_count is not None and clock_warning_count > 0:
        failed_checks.append("clock-skew-warnings-present")
    if time_semantics_manifest is not None and not time_semantics_manifest.get("manifest_hash"):
        failed_checks.append("time-semantics-manifest-hash-missing")
    trusted_blockers = {
        TIMEZONE_VALIDATION_TRUSTED_DIFF_BLOCKER_97,
        CLOCK_SKEW_TRUSTED_DIFF_BLOCKER_98,
    }
    if trusted_diff.get("status") != "pass":
        blocker = str(trusted_diff.get("blocker") or "")
        failed_checks.append(blocker if blocker in trusted_blockers else "trusted-time-validation-diff-missing")
    return {
        "item_number": 42,
        "batch_id": FUNCTIONAL_DEFENSIBILITY_BATCH_ID,
        "status": "complete" if not failed_checks else "partial",
        "implemented_controls": {
            "event_count": event_count,
            "missing_timezone_count": missing_timezone_count,
            "timezone_counts": dict(timezone_counts),
            "sample_count": sample_count,
            "clock_warning_count": clock_warning_count,
            "utc_assumption_disclosed": True,
            "time_semantics_manifest_hash": str((time_semantics_manifest or {}).get("manifest_hash") or ""),
            "normalized_utc_sample_count": int((time_semantics_manifest or {}).get("normalized_utc_sample_count") or 0),
            "trusted_diff_status": str(trusted_diff.get("status") or ""),
        },
        "passed_validation_check_ids": [
            "original-timestamp-samples-preserved",
            "source-timezone-inventory-emitted",
            "utc-normalization-assumption-disclosed",
            "time-semantics-manifest-hash-emitted",
            "clock-skew-baseline-guidance-emitted",
        ],
        "failed_validation_check_ids": failed_checks,
        "reportability_decision": {
            "allowed_use": "timeline-time-semantics-review",
            "commercial_claim_allowed": not failed_checks,
            "operator_warning": "Timezone and skew conclusions require source parser assumptions plus trusted baseline review.",
        },
    }


def contamination_warning_functional_profile(
    *,
    warnings: Sequence[Mapping[str, object]],
    evidence_source_count: int,
    acquisition_context_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    warning_types = sorted({str(item.get("type") or "") for item in warnings if item.get("type")})
    failed_checks = []
    if warnings:
        failed_checks.append("evidence-contamination-warnings-present")
    if not acquisition_context_manifest.get("manifest_hash"):
        failed_checks.append("contamination-acquisition-context-manifest-hash-missing")
    if trusted_diff.get("status") != "pass":
        failed_checks.append(CONTAMINATION_WARNING_TRUSTED_DIFF_BLOCKER_99)
    return {
        "item_number": 43,
        "batch_id": FUNCTIONAL_DEFENSIBILITY_BATCH_ID,
        "status": "complete" if not failed_checks else "partial",
        "implemented_controls": {
            "evidence_source_count": evidence_source_count,
            "warning_count": len(warnings),
            "warning_types": warning_types,
            "contamination_acquisition_context_manifest_hash": str(acquisition_context_manifest.get("manifest_hash") or ""),
            "missing_write_blocker_count": int(acquisition_context_manifest.get("missing_write_blocker_count") or 0),
            "writable_source_warning_count": int(acquisition_context_manifest.get("writable_source_warning_count") or 0),
            "checks": [
                "rapidtriage-output-inside-evidence-root",
                "staged-output-under-evidence-root",
                "zero-byte-source",
                "source-path-stat-failed",
                "writable-source-permission",
                "acquisition-metadata-missing-for-evidence-source",
                "write-blocker-missing-for-evidence-source",
            ],
            "trusted_diff_status": str(trusted_diff.get("status") or ""),
        },
        "passed_validation_check_ids": [
            "evidence-root-output-check",
            "staged-output-location-check",
            "zero-byte-source-check",
            "source-stat-failure-check",
            "writable-source-permission-check",
            "acquisition-metadata-write-blocker-context-check",
        ],
        "failed_validation_check_ids": failed_checks,
        "reportability_decision": {
            "allowed_use": "evidence-contamination-triage-warning",
            "commercial_claim_allowed": not failed_checks,
            "operator_warning": "Warnings must be cleared or explained before final evidence submission.",
        },
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


def is_relative_to(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False
