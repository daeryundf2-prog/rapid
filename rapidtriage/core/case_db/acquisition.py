"""Acquisition metadata records and evidence-contamination warnings."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Mapping, Sequence
from pathlib import Path

from .constants import (
    ACQUISITION_METADATA_REPORT_GRADE_BLOCKERS,
    ACQUISITION_METADATA_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    ACQUISITION_METADATA_TRUSTED_DIFF_BLOCKER_96,
    CONTAMINATION_WARNING_REPORT_GRADE_BLOCKERS,
    CONTAMINATION_WARNING_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    CONTAMINATION_WARNING_TRUSTED_DIFF_BLOCKER_99,
    EVIDENCE_CONTAMINATION_WARNING_GAP_ID,
    FUNCTIONAL_DEFENSIBILITY_BATCH_ID,
    WRITE_BLOCKER_ACQUISITION_METADATA_GAP_ID,
)
from .helpers import (
    optional_int,
    stable_payload_sha256,
)
from .review import (
    acquisition_metadata_to_dict,
)
from .trusted_diffs import (
    acquisition_metadata_core_accuracy_gates,
    contamination_warning_core_accuracy_gates,
    missing_acquisition_metadata_trusted_diff,
    missing_contamination_warning_trusted_diff,
)

__all__ = [
    "acquisition_metadata_functional_profile",
    "attach_acquisition_evidence_source_row_hash",
    "attach_acquisition_metadata_row_hash",
    "attach_contamination_warning_row_hash",
    "build_acquisition_field_completion_matrix",
    "build_acquisition_metadata_handoff_manifest",
    "build_acquisition_metadata_input_manifest",
    "build_acquisition_metadata_record",
    "build_acquisition_metadata_report_grade_validation_plan",
    "build_contamination_acquisition_context_manifest",
    "build_contamination_checklist_manifest",
    "build_contamination_report_grade_validation_plan",
    "build_contamination_warning_review_matrix",
    "build_evidence_contamination_warnings",
    "contamination_warning_functional_profile",
    "is_relative_to",
]


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


def is_relative_to(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False
