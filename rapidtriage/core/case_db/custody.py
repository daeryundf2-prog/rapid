"""Chain-of-custody workflows and acquisition-hash sealing."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Mapping, Sequence

from .constants import (
    ACQUISITION_HASH_GAP_ID,
    ACQUISITION_HASH_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    ACQUISITION_HASH_TRUSTED_DIFF_BLOCKER_87,
    CHAIN_OF_CUSTODY_GAP_ID,
    CUSTODY_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    CUSTODY_TRUSTED_DIFF_BLOCKER_86,
    FORENSIC_INTEGRITY_BATCH_ID,
    FUNCTIONAL_VALIDATION_BATCH_ID,
    SOURCE_PROVENANCE_REPORT_GRADE_BLOCKERS,
)
from .helpers import (
    optional_int,
    stable_payload_sha256,
)
from .trusted_diffs import (
    acquisition_hash_core_accuracy_gates,
    custody_workflow_core_accuracy_gates,
    missing_integrity_trusted_diff,
)

__all__ = [
    "acquisition_hash_workflow_functional_profile",
    "attach_acquisition_hash_row_hash",
    "attach_custody_row_hash",
    "build_acquisition_hash_inventory_matrix",
    "build_acquisition_hash_manifest",
    "build_acquisition_hash_report_grade_validation_plan",
    "build_acquisition_hash_workflow",
    "build_custody_chain_manifest",
    "build_custody_completeness_matrix",
    "build_custody_event_manifest",
    "build_custody_report_grade_validation_plan",
    "build_custody_workflow",
    "custody_event_stage_counts",
    "custody_workflow_functional_profile",
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
