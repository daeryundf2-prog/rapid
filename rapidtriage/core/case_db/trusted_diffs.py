"""Trusted-diff comparisons and core accuracy gates."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence

from ..forensic_accuracy import build_accuracy_gate
from .constants import (
    ACQUISITION_HASH_GAP_ID,
    ACQUISITION_HASH_TRUSTED_DIFF_BLOCKER_87,
    ACQUISITION_METADATA_TRUSTED_DIFF_BLOCKER_96,
    ACQUISITION_QUALITY_TRUSTED_TOOLS,
    CHAIN_OF_CUSTODY_GAP_ID,
    CLOCK_SKEW_ANALYSIS_GAP_ID,
    CLOCK_SKEW_TRUSTED_DIFF_BLOCKER_98,
    CONTAMINATION_WARNING_TRUSTED_DIFF_BLOCKER_99,
    CUSTODY_TRUSTED_DIFF_BLOCKER_86,
    EVIDENCE_CONTAMINATION_WARNING_GAP_ID,
    FORENSIC_INTEGRITY_TRUSTED_TOOLS,
    IMMUTABLE_AUDIT_GAP_ID,
    IMMUTABLE_AUDIT_TRUSTED_DIFF_BLOCKER_88,
    LEGAL_LIMITATION_GAP_ID,
    LEGAL_LIMITATION_TRUSTED_DIFF_BLOCKER_93,
    PARSER_CONFIDENCE_GAP_ID,
    PARSER_CONFIDENCE_TRUSTED_DIFF_BLOCKER_91,
    REPORT_QUALITY_TRUSTED_TOOLS,
    REPORT_REPRODUCIBILITY_GAP_ID,
    REPORT_REPRODUCIBILITY_TRUSTED_DIFF_BLOCKER_89,
    SOURCE_PROVENANCE_GAP_ID,
    SOURCE_PROVENANCE_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    SOURCE_PROVENANCE_TRUSTED_DIFF_BLOCKER_90,
    TIMEZONE_NORMALIZATION_GAP_ID,
    TIMEZONE_VALIDATION_TRUSTED_DIFF_BLOCKER_97,
    VALIDATION_WARNING_TRUSTED_DIFF_BLOCKER_92,
    VALIDATION_WARNING_UX_GAP_ID,
    WRITE_BLOCKER_ACQUISITION_METADATA_GAP_ID,
)
from .helpers import (
    nested_mapping_str,
    optional_float,
    stable_payload_sha256,
)

__all__ = [
    "acquisition_hash_core_accuracy_gates",
    "acquisition_hash_manifest",
    "acquisition_metadata_core_accuracy_gates",
    "acquisition_quality_trusted_diff_result",
    "audit_integrity_manifest",
    "build_acquisition_hash_trusted_diff",
    "build_acquisition_metadata_trusted_diff",
    "build_acquisition_quality_mismatches",
    "build_clock_skew_trusted_diff",
    "build_contamination_warning_trusted_diff",
    "build_custody_workflow_trusted_diff",
    "build_forensic_integrity_matrix",
    "build_immutable_audit_trusted_diff",
    "build_legal_limitation_trusted_diff",
    "build_parser_confidence_trusted_diff",
    "build_report_item_provenance",
    "build_report_provenance_row_manifest",
    "build_report_provenance_trusted_diff",
    "build_report_reproducibility_trusted_diff",
    "build_source_provenance_report_grade_validation_plan",
    "build_timezone_validation_trusted_diff",
    "build_validation_warning_trusted_diff",
    "clock_skew_core_accuracy_gates",
    "compare_indexed_integrity_rows",
    "compare_integrity_manifests",
    "contamination_warning_core_accuracy_gates",
    "custody_manifest",
    "custody_workflow_core_accuracy_gates",
    "immutable_audit_core_accuracy_gates",
    "index_provenance_rows",
    "integrity_trusted_diff_result",
    "legal_limitation_core_accuracy_gates",
    "missing_acquisition_metadata_trusted_diff",
    "missing_acquisition_quality_trusted_diff",
    "missing_clock_skew_trusted_diff",
    "missing_contamination_warning_trusted_diff",
    "missing_integrity_trusted_diff",
    "missing_report_quality_trusted_diff",
    "missing_timezone_validation_trusted_diff",
    "normalize_integrity_value",
    "parser_confidence_core_accuracy_gates",
    "report_item_provenance_core_accuracy_gates",
    "report_quality_trusted_diff_result",
    "report_reproducibility_core_accuracy_gates",
    "reproducibility_manifest",
    "timezone_validation_core_accuracy_gates",
    "validation_warning_ux_core_accuracy_gates",
]

def build_report_provenance_row_manifest(row: Mapping[str, object]) -> dict[str, object]:
    provenance_core = {
        "profile_version": "report-provenance-row-v1",
        "item_number": 90,
        "target_citation_id": str(row.get("target_citation_id") or ""),
        "review_citation_id": str(row.get("review_citation_id") or ""),
        "source_path": str(row.get("source_path") or ""),
        "hashes": row.get("hashes") if isinstance(row.get("hashes"), Mapping) else {},
        "record_hashes": row.get("record_hashes") if isinstance(row.get("record_hashes"), Mapping) else {},
        "parser": str(row.get("parser") or ""),
        "parser_version": str(row.get("parser_version") or ""),
        "parser_confidence": row.get("parser_confidence"),
        "record_offset": row.get("record_offset"),
        "source_index": row.get("source_index"),
        "review_status": str(row.get("review_status") or ""),
        "verification_status": str(row.get("verification_status") or ""),
        "reportability": str(row.get("reportability") or ""),
        "evidence_strength": str(row.get("evidence_strength") or ""),
    }
    provenance_row_hash = stable_payload_sha256(provenance_core)
    field_presence = {
        "source_path": bool(provenance_core["source_path"]),
        "hashes": bool(provenance_core["hashes"]),
        "record_hashes": bool(provenance_core["record_hashes"]),
        "parser": bool(provenance_core["parser"]),
        "parser_version": bool(provenance_core["parser_version"]),
        "parser_confidence": provenance_core["parser_confidence"] is not None,
        "record_offset": provenance_core["record_offset"] is not None,
        "source_index": provenance_core["source_index"] is not None,
        "review_status": bool(provenance_core["review_status"]),
        "reportability": bool(provenance_core["reportability"]),
    }
    required_fields = ["source_path", "hashes", "parser", "parser_version", "review_status", "reportability"]
    completeness_score = round(
        sum(1 for key in required_fields if field_presence.get(key)) / len(required_fields),
        4,
    )
    manifest_core = {
        "profile_version": "report-provenance-row-manifest-v1",
        "item_number": 90,
        "target_citation_id": provenance_core["target_citation_id"],
        "review_citation_id": provenance_core["review_citation_id"],
        "provenance_row_hash": provenance_row_hash,
        "field_presence": field_presence,
        "field_presence_hash": stable_payload_sha256(field_presence),
        "required_fields": required_fields,
        "missing_required_fields": [key for key in required_fields if not field_presence.get(key)],
        "completeness_score": completeness_score,
        "commercial_gap_ids": [SOURCE_PROVENANCE_GAP_ID],
        "commercial_claim_allowed": False,
    }
    manifest_hash = hashlib.sha256(
        json.dumps(manifest_core, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return {**manifest_core, "manifest_hash": manifest_hash}


def build_source_provenance_report_grade_validation_plan(
    provenance: Mapping[str, object],
    provenance_manifest: Mapping[str, object],
    *,
    trusted_diff: Mapping[str, object] | None,
) -> dict[str, object]:
    trusted_status = str(trusted_diff.get("status") or "missing") if trusted_diff else "missing"
    source_locator = provenance.get("source_locator") if isinstance(provenance.get("source_locator"), Mapping) else {}
    source_viewer_locator = (
        provenance.get("source_viewer_locator")
        if isinstance(provenance.get("source_viewer_locator"), Mapping)
        else {}
    )
    hashes = provenance.get("hashes") if isinstance(provenance.get("hashes"), Mapping) else {}
    record_hashes = provenance.get("record_hashes") if isinstance(provenance.get("record_hashes"), Mapping) else {}
    parser_manifest_hashes = (
        provenance.get("parser_manifest_hashes")
        if isinstance(provenance.get("parser_manifest_hashes"), Mapping)
        else {}
    )
    ready_slots = [
        {
            "slot_id": "source-path-and-locator",
            "status": "complete",
            "evidence": {
                "source_path": str(provenance.get("source_path") or ""),
                "source_locator_hash": str(provenance.get("source_locator_hash") or ""),
                "source_locator_present": bool(source_locator),
                "source_viewer_locator_present": bool(source_viewer_locator),
            },
        },
        {
            "slot_id": "source-and-record-hashes",
            "status": "complete",
            "evidence": {
                "source_hash_algorithms": sorted(str(key) for key in hashes.keys()),
                "record_hash_algorithms": sorted(str(key) for key in record_hashes.keys()),
                "row_citation_hash": str(provenance.get("row_citation_hash") or ""),
            },
        },
        {
            "slot_id": "parser-identity-and-confidence",
            "status": "complete",
            "evidence": {
                "parser": str(provenance.get("parser") or ""),
                "parser_version": str(provenance.get("parser_version") or ""),
                "parser_confidence": provenance.get("parser_confidence"),
                "parser_manifest_hash_count": len(parser_manifest_hashes),
            },
        },
        {
            "slot_id": "offset-source-index-and-citation",
            "status": "complete",
            "evidence": {
                "record_offset": provenance.get("record_offset"),
                "source_index": provenance.get("source_index"),
                "source_citation_package_hash": str(provenance.get("source_citation_package_hash") or ""),
                "source_read_citation_id": str(provenance.get("source_read_citation_id") or ""),
            },
        },
        {
            "slot_id": "review-and-reportability-state",
            "status": "complete",
            "evidence": {
                "review_status": str(provenance.get("review_status") or ""),
                "verification_status": str(provenance.get("verification_status") or ""),
                "reportability": str(provenance.get("reportability") or ""),
                "evidence_strength": str(provenance.get("evidence_strength") or ""),
            },
        },
        {
            "slot_id": "provenance-row-and-field-presence-manifest",
            "status": "complete",
            "evidence": {
                "provenance_row_hash": str(provenance_manifest.get("provenance_row_hash") or ""),
                "manifest_hash": str(provenance_manifest.get("manifest_hash") or ""),
                "field_presence_hash": str(provenance_manifest.get("field_presence_hash") or ""),
                "completeness_score": provenance_manifest.get("completeness_score"),
            },
        },
        {
            "slot_id": "trusted-provenance-diff-disclosure",
            "status": "complete",
            "evidence": {
                "trusted_diff_status": trusted_status,
                "trusted_tool": str((trusted_diff or {}).get("trusted_tool") or ""),
            },
        },
    ]
    blocking_slots: list[dict[str, object]] = []
    if not provenance.get("source_path") and not source_locator:
        blocking_slots.append(
            {
                "slot_id": "source-path-or-locator",
                "status": "blocked",
                "blocker": "source-path-or-locator-required",
                "required_evidence": "source path or structured source locator for every report item",
            }
        )
    if not hashes and not record_hashes:
        blocking_slots.append(
            {
                "slot_id": "source-or-record-hash",
                "status": "blocked",
                "blocker": "source-or-record-hash-required",
                "required_evidence": "source SHA-256 or record/content hash for every report item",
            }
        )
    if not provenance.get("parser") or not provenance.get("parser_version"):
        blocking_slots.append(
            {
                "slot_id": "parser-version",
                "status": "blocked",
                "blocker": "parser-version-required",
                "required_evidence": "parser name and parser version for every report item",
            }
        )
    if not provenance.get("review_status") or not provenance.get("reportability"):
        blocking_slots.append(
            {
                "slot_id": "review-reportability",
                "status": "blocked",
                "blocker": "review-reportability-required",
                "required_evidence": "review status and reportability decision for every report item",
            }
        )
    if not provenance_manifest.get("manifest_hash") or not provenance_manifest.get("provenance_row_hash"):
        blocking_slots.append(
            {
                "slot_id": "provenance-manifest-complete",
                "status": "blocked",
                "blocker": "provenance-manifest-completeness-required",
                "required_evidence": "provenance row hash, field-presence hash, and manifest hash",
            }
        )
    if float(provenance_manifest.get("completeness_score") or 0.0) < 1.0:
        blocking_slots.append(
            {
                "slot_id": "required-field-completeness",
                "status": "blocked",
                "blocker": "provenance-required-field-completeness-required",
                "required_evidence": "all required provenance fields present in each row manifest",
            }
        )
    if trusted_status != "pass":
        blocking_slots.append(
            {
                "slot_id": "trusted-report-provenance-manifest-diff",
                "status": "external-required",
                "blocker": SOURCE_PROVENANCE_TRUSTED_DIFF_BLOCKER_90,
                "required_evidence": "trusted provenance manifest diff over source path, hashes, parser, offset, review, and reportability fields",
            }
        )
    blocking_slots.extend(
        [
            {
                "slot_id": "all-parser-provenance-corpus",
                "status": "external-required",
                "blocker": "all-parser-provenance-corpus-required",
                "required_evidence": "fixture corpus proving provenance completeness across every parser family",
            },
            {
                "slot_id": "final-report-template-provenance-review",
                "status": "external-required",
                "blocker": "final-report-template-provenance-review-required",
                "required_evidence": "final report template review proving source provenance is visible for every cited item",
            },
            {
                "slot_id": "source-citation-viewer-roundtrip",
                "status": "external-required",
                "blocker": "source-citation-viewer-roundtrip-required",
                "required_evidence": "source viewer round-trip from report citation back to original source and hash",
            },
            {
                "slot_id": "offset-locator-trusted-diff",
                "status": "external-required",
                "blocker": "offset-locator-trusted-diff-required",
                "required_evidence": "trusted diff for parser offsets, source indexes, and viewer locators",
            },
            {
                "slot_id": "parser-version-release-lock",
                "status": "external-required",
                "blocker": "parser-version-release-lock-required",
                "required_evidence": "release-build parser/version inventory locked to the report export",
            },
        ]
    )
    plan_core: dict[str, object] = {
        "profile_version": SOURCE_PROVENANCE_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 90,
        "commercial_gap_ids": [SOURCE_PROVENANCE_GAP_ID],
        "plan_context": "case-db-report-item-provenance",
        "target_citation_id": str(provenance.get("target_citation_id") or ""),
        "review_citation_id": str(provenance.get("review_citation_id") or ""),
        "provenance_manifest_hash": str(provenance_manifest.get("manifest_hash") or ""),
        "provenance_row_hash": str(provenance_manifest.get("provenance_row_hash") or ""),
        "field_presence_hash": str(provenance_manifest.get("field_presence_hash") or ""),
        "completeness_score": provenance_manifest.get("completeness_score"),
        "trusted_diff_status": trusted_status,
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "blockers": sorted({str(slot.get("blocker") or "") for slot in blocking_slots if slot.get("blocker")}),
        "commercial_claim_allowed": False,
        "reporting_boundary": "This plan makes one report item source-provenance-reviewable, but commercial completeness requires all-parser corpus coverage, final report template review, citation viewer round-trip evidence, offset trusted diffs, parser-version release locks, and trusted provenance manifests.",
    }
    return {**plan_core, "validation_plan_sha256": stable_payload_sha256(plan_core)}


def build_report_item_provenance(
    enriched: Mapping[str, object],
    review: Mapping[str, object],
    *,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    source_reference = enriched.get("source_reference") if isinstance(enriched.get("source_reference"), Mapping) else {}
    metadata = enriched.get("metadata") if isinstance(enriched.get("metadata"), Mapping) else {}
    hashes = source_reference.get("source_hashes") if isinstance(source_reference.get("source_hashes"), Mapping) else {}
    record_hashes = source_reference.get("record_hashes") if isinstance(source_reference.get("record_hashes"), Mapping) else {}
    blockers = []
    if not trusted_diff or trusted_diff.get("status") != "pass":
        blockers.append(SOURCE_PROVENANCE_TRUSTED_DIFF_BLOCKER_90)
    provenance = {
        "commercial_gap_ids": [SOURCE_PROVENANCE_GAP_ID],
        "target_citation_id": str(enriched.get("citation_id") or ""),
        "review_citation_id": str(review.get("citation_id") or ""),
        "source_path": str(source_reference.get("path") or enriched.get("path") or ""),
        "source_citation_package_hash": str(source_reference.get("source_citation_package_hash") or ""),
        "source_read_citation_id": str(source_reference.get("source_read_citation_id") or ""),
        "source_read_citation_text": str(source_reference.get("source_read_citation_text") or ""),
        "source_locator": dict(source_reference.get("source_locator"))
        if isinstance(source_reference.get("source_locator"), Mapping)
        else {},
        "source_viewer_locator": dict(source_reference.get("source_viewer_locator"))
        if isinstance(source_reference.get("source_viewer_locator"), Mapping)
        else {},
        "source_locator_hash": str(source_reference.get("source_locator_hash") or ""),
        "row_citation_hash": str(source_reference.get("row_citation_hash") or ""),
        "parser_manifest_hashes": dict(source_reference.get("parser_manifest_hashes"))
        if isinstance(source_reference.get("parser_manifest_hashes"), Mapping)
        else {},
        "hashes": dict(hashes),
        "record_hashes": dict(record_hashes),
        "parser": str(source_reference.get("parser") or metadata.get("parser") or ""),
        "parser_version": str(source_reference.get("parser_version") or metadata.get("parser_version") or ""),
        "parser_confidence": source_reference.get("parser_confidence") or metadata.get("parser_confidence"),
        "record_offset": source_reference.get("record_offset"),
        "source_index": source_reference.get("source_index"),
        "review_status": str(review.get("status") or ""),
        "verification_status": str(review.get("verification_status") or ""),
        "reportability": str(source_reference.get("reportability") or metadata.get("reportability") or ""),
        "evidence_strength": str(source_reference.get("evidence_strength") or metadata.get("evidence_strength") or ""),
    }
    provenance_manifest = build_report_provenance_row_manifest(provenance)
    source_provenance_report_grade_validation_plan = build_source_provenance_report_grade_validation_plan(
        provenance,
        provenance_manifest,
        trusted_diff=trusted_diff,
    )
    blockers = sorted({*blockers, *source_provenance_report_grade_validation_plan["blockers"]})
    return {
        **provenance,
        "provenance_row_hash": provenance_manifest["provenance_row_hash"],
        "provenance_manifest": provenance_manifest,
        "provenance_manifest_hash": provenance_manifest["manifest_hash"],
        "source_provenance_report_grade_validation_plan": source_provenance_report_grade_validation_plan,
        "source_provenance_report_grade_validation_plan_hash": source_provenance_report_grade_validation_plan[
            "validation_plan_sha256"
        ],
        "report_grade_ready_slot_count": source_provenance_report_grade_validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": source_provenance_report_grade_validation_plan["blocking_slot_count"],
        "trusted_provenance_diff": dict(trusted_diff) if trusted_diff else missing_integrity_trusted_diff(
            SOURCE_PROVENANCE_GAP_ID,
            SOURCE_PROVENANCE_TRUSTED_DIFF_BLOCKER_90,
            trusted_tool="report-provenance-manifest",
        ),
        "blockers": blockers,
        "core_accuracy_gates": report_item_provenance_core_accuracy_gates(
            source_path=str(source_reference.get("path") or enriched.get("path") or ""),
            hashes=hashes,
            record_hashes=record_hashes,
            parser=str(source_reference.get("parser") or metadata.get("parser") or ""),
            parser_version=str(source_reference.get("parser_version") or metadata.get("parser_version") or ""),
            parser_confidence=source_reference.get("parser_confidence") or metadata.get("parser_confidence"),
            record_offset=source_reference.get("record_offset"),
            source_index=source_reference.get("source_index"),
            review_status=str(review.get("status") or ""),
            reportability=str(source_reference.get("reportability") or metadata.get("reportability") or ""),
            provenance_manifest=provenance_manifest,
            trusted_diff=trusted_diff,
            report_grade_validation_plan=source_provenance_report_grade_validation_plan,
        ),
    }


def build_forensic_integrity_matrix(
    *,
    custody_workflow: Mapping[str, object],
    acquisition_hash_workflow: Mapping[str, object],
    audit_integrity: Mapping[str, object],
    reproducibility: Mapping[str, object],
    items: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    provenance_rows = []
    for item in items:
        provenance = item.get("provenance") if isinstance(item.get("provenance"), Mapping) else {}
        manifest = provenance.get("provenance_manifest") if isinstance(provenance.get("provenance_manifest"), Mapping) else {}
        row = {
            "target_citation_id": str(provenance.get("target_citation_id") or ""),
            "review_citation_id": str(provenance.get("review_citation_id") or ""),
            "provenance_manifest_hash": str(provenance.get("provenance_manifest_hash") or ""),
            "source_provenance_report_grade_validation_plan_hash": str(
                provenance.get("source_provenance_report_grade_validation_plan_hash") or ""
            ),
            "field_presence_hash": str(manifest.get("field_presence_hash") or ""),
            "completeness_score": optional_float(manifest.get("completeness_score")) or 0.0,
            "missing_required_fields": list(manifest.get("missing_required_fields") or []),
            "report_grade_ready_slot_count": int(provenance.get("report_grade_ready_slot_count") or 0),
            "report_grade_blocking_slot_count": int(provenance.get("report_grade_blocking_slot_count") or 0),
        }
        provenance_rows.append({**row, "row_hash": stable_payload_sha256(row)})
    source_rows = [
        {
            "item_number": 86,
            "component": "chain-of-custody",
            "primary_hash": nested_mapping_str(custody_workflow, "custody_chain_manifest", "manifest_hash"),
            "secondary_hash": str(custody_workflow.get("custody_completeness_matrix_hash") or ""),
            "record_count": int((custody_workflow.get("summary") or {}).get("custody_event_count") or 0)
            if isinstance(custody_workflow.get("summary"), Mapping)
            else 0,
            "blockers": list(custody_workflow.get("blockers") or []),
        },
        {
            "item_number": 87,
            "component": "acquisition-hash-workflow",
            "primary_hash": nested_mapping_str(acquisition_hash_workflow, "acquisition_hash_manifest", "manifest_hash"),
            "secondary_hash": nested_mapping_str(acquisition_hash_workflow, "acquisition_hash_manifest", "hash_inventory_matrix_hash"),
            "record_count": int((acquisition_hash_workflow.get("summary") or {}).get("hash_count") or 0)
            if isinstance(acquisition_hash_workflow.get("summary"), Mapping)
            else 0,
            "blockers": list(acquisition_hash_workflow.get("blockers") or []),
        },
        {
            "item_number": 88,
            "component": "immutable-audit-log",
            "primary_hash": nested_mapping_str(audit_integrity, "audit_hash_chain_manifest", "manifest_hash"),
            "secondary_hash": nested_mapping_str(audit_integrity, "audit_replay_manifest", "replay_matrix_hash"),
            "record_count": int((audit_integrity.get("summary") or {}).get("event_count") or 0)
            if isinstance(audit_integrity.get("summary"), Mapping)
            else 0,
            "blockers": list(audit_integrity.get("blockers") or []),
        },
        {
            "item_number": 89,
            "component": "report-reproducibility",
            "primary_hash": nested_mapping_str(reproducibility, "report_replay_manifest", "manifest_hash"),
            "secondary_hash": nested_mapping_str(reproducibility, "report_replay_manifest", "row_hash_set_hash"),
            "record_count": int(reproducibility.get("stable_item_count") or 0),
            "blockers": list(reproducibility.get("blockers") or []),
        },
        {
            "item_number": 90,
            "component": "report-provenance",
            "primary_hash": stable_payload_sha256({"provenance_rows": provenance_rows}),
            "secondary_hash": stable_payload_sha256(
                {"field_presence_hashes": [row["field_presence_hash"] for row in provenance_rows]}
            ),
            "record_count": len(provenance_rows),
            "blockers": sorted(
                {
                    blocker
                    for item in items
                    for provenance in [item.get("provenance") if isinstance(item.get("provenance"), Mapping) else {}]
                    for blocker in provenance.get("blockers", [])
                }
            ),
        },
    ]
    rows = [{**row, "row_hash": stable_payload_sha256(row)} for row in source_rows]
    matrix_core = {
        "profile_version": "forensic-integrity-matrix-v1",
        "item_numbers": [86, 87, 88, 89, 90],
        "row_count": len(rows),
        "rows": rows,
        "provenance_rows": provenance_rows,
        "provenance_row_count": len(provenance_rows),
        "all_primary_hashes_present": all(bool(row["primary_hash"]) for row in rows),
        "commercial_claim_allowed": all(not row["blockers"] for row in rows),
    }
    return {**matrix_core, "matrix_hash": stable_payload_sha256(matrix_core)}


def custody_workflow_core_accuracy_gates(
    *,
    evidence_sources: Sequence[Mapping[str, object]],
    custody_events: Sequence[Mapping[str, object]],
    custody_event_manifest: Mapping[str, object] | None = None,
    custody_chain_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
    report_grade_validation_plan: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = ["acquisition metadata limitation warning"]
    if evidence_sources:
        satisfied.append("evidence source inventory")
    if custody_events:
        satisfied.append("custody event inventory")
    if any(item.get("citation_id") for item in [*evidence_sources, *custody_events]):
        satisfied.append("citation IDs preserved")
    if any(item.get("status") or item.get("sha256") for item in evidence_sources):
        satisfied.append("source status/hash fields preserved")
    if any(item.get("custody_row_hash") for item in [*evidence_sources, *custody_events]):
        satisfied.append("custody row hashes emitted")
    if custody_event_manifest and custody_event_manifest.get("manifest_hash"):
        satisfied.append("custody event manifest hash emitted")
    if custody_chain_manifest and custody_chain_manifest.get("manifest_hash"):
        satisfied.append("custody chain manifest hash emitted")
    if custody_chain_manifest and custody_chain_manifest.get("custody_completeness_matrix_hash"):
        satisfied.append("custody completeness matrix hash emitted")
    if report_grade_validation_plan and report_grade_validation_plan.get("validation_plan_sha256"):
        satisfied.append("custody report-grade validation plan")
    if report_grade_validation_plan and int(report_grade_validation_plan.get("ready_slot_count") or 0) >= 6:
        satisfied.append("custody report-grade ready slots")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted custody event manifest diff pass")
    return [
        build_accuracy_gate(
            86,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"evidence_source_count:{len(evidence_sources)}",
                f"custody_event_count:{len(custody_events)}",
                f"custody_manifest_hash:{(custody_event_manifest or {}).get('manifest_hash', '')}",
                f"custody_chain_manifest_hash:{(custody_chain_manifest or {}).get('manifest_hash', '')}",
                f"custody_completeness_matrix_hash:{(custody_chain_manifest or {}).get('custody_completeness_matrix_hash', '')}",
                f"custody_report_grade_validation_plan_hash:{(report_grade_validation_plan or {}).get('validation_plan_sha256', '')}",
            ],
        )
    ]


def acquisition_hash_core_accuracy_gates(
    *,
    hashes: Sequence[Mapping[str, object]],
    acquisition_hash_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
    report_grade_validation_plan: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = ["missing hash limitation warning"]
    if any(item.get("target_type") == "evidence_source" for item in hashes):
        satisfied.append("evidence-source hashes exported")
    if hashes:
        satisfied.append("hash records exported")
    if any(isinstance(item.get("hashes"), Mapping) and item.get("hashes") for item in hashes):
        satisfied.append("hash algorithms preserved")
    if any(item.get("calculated_at") for item in hashes):
        satisfied.append("calculation timestamps preserved")
    if any(item.get("acquisition_hash_row_hash") for item in hashes):
        satisfied.append("acquisition hash row hashes emitted")
    if acquisition_hash_manifest and acquisition_hash_manifest.get("manifest_hash"):
        satisfied.append("acquisition hash manifest hash emitted")
    if acquisition_hash_manifest and acquisition_hash_manifest.get("hash_inventory_matrix_hash"):
        satisfied.append("acquisition hash inventory matrix emitted")
    if report_grade_validation_plan and report_grade_validation_plan.get("validation_plan_sha256"):
        satisfied.append("acquisition hash report-grade validation plan")
    if report_grade_validation_plan and int(report_grade_validation_plan.get("ready_slot_count") or 0) >= 6:
        satisfied.append("acquisition hash report-grade ready slots")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted acquisition hash manifest diff pass")
    return [
        build_accuracy_gate(
            87,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"hash_count:{len(hashes)}",
                f"acquisition_hash_manifest_hash:{(acquisition_hash_manifest or {}).get('manifest_hash', '')}",
                f"hash_inventory_matrix_hash:{(acquisition_hash_manifest or {}).get('hash_inventory_matrix_hash', '')}",
                f"acquisition_hash_report_grade_validation_plan_hash:{(report_grade_validation_plan or {}).get('validation_plan_sha256', '')}",
            ],
        )
    ]


def immutable_audit_core_accuracy_gates(
    *,
    events: Sequence[Mapping[str, object]],
    head_hash: str,
    audit_hash_chain_manifest: Mapping[str, object] | None = None,
    audit_replay_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
    report_grade_validation_plan: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = ["external notarization limitation warning"]
    if events:
        satisfied.append("audit events exported")
    if all(item.get("event_hash") is not None and "previous_event_hash" in item for item in events):
        satisfied.append("previous/event hash chain generated")
    if all(item.get("actor") is not None and item.get("action") and item.get("target_type") is not None and item.get("timestamp") for item in events):
        satisfied.append("actor/action/target/time fields preserved")
    if head_hash:
        satisfied.append("head hash recorded")
    if audit_hash_chain_manifest and audit_hash_chain_manifest.get("manifest_hash"):
        satisfied.append("audit hash-chain manifest hash emitted")
    if audit_hash_chain_manifest and audit_hash_chain_manifest.get("actor_action_matrix_hash"):
        satisfied.append("audit actor/action matrix hash emitted")
    if audit_replay_manifest and audit_replay_manifest.get("manifest_hash"):
        satisfied.append("audit replay manifest hash emitted")
    if audit_replay_manifest and audit_replay_manifest.get("replay_matrix_hash"):
        satisfied.append("audit replay matrix hash emitted")
    if audit_replay_manifest and audit_replay_manifest.get("chain_valid"):
        satisfied.append("audit replay chain validation pass")
    if report_grade_validation_plan and report_grade_validation_plan.get("validation_plan_sha256"):
        satisfied.append("immutable audit report-grade validation plan")
    if report_grade_validation_plan and int(report_grade_validation_plan.get("ready_slot_count") or 0) >= 6:
        satisfied.append("immutable audit report-grade ready slots")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted audit hash-chain manifest diff pass")
    return [
        build_accuracy_gate(
            88,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"event_count:{len(events)}",
                f"head_hash:{head_hash}",
                f"audit_chain_manifest_hash:{(audit_hash_chain_manifest or {}).get('manifest_hash', '')}",
                f"audit_replay_manifest_hash:{(audit_replay_manifest or {}).get('manifest_hash', '')}",
                f"actor_action_matrix_hash:{(audit_hash_chain_manifest or {}).get('actor_action_matrix_hash', '')}",
                f"replay_matrix_hash:{(audit_replay_manifest or {}).get('replay_matrix_hash', '')}",
                f"immutable_audit_report_grade_validation_plan_hash:{(report_grade_validation_plan or {}).get('validation_plan_sha256', '')}",
            ],
        )
    ]


def report_reproducibility_core_accuracy_gates(
    *,
    stable_hash: str,
    item_count: int,
    citation_count: int,
    report_replay_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
    report_grade_validation_plan: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = [
        "stable payload hash generated",
        "deterministic sorting documented",
        "item/citation counts recorded",
        "volatile fields disclosed",
        "cross-platform replay limitation warning",
    ]
    if report_replay_manifest and report_replay_manifest.get("manifest_hash"):
        satisfied.append("report replay manifest hash emitted")
    if report_replay_manifest and (
        report_replay_manifest.get("item_row_hashes") or report_replay_manifest.get("citation_row_hashes")
    ):
        satisfied.append("item/citation row hashes emitted")
    if report_replay_manifest and report_replay_manifest.get("row_hash_set_hash"):
        satisfied.append("row hash set hash emitted")
    if report_replay_manifest and report_replay_manifest.get("replay_contract_hash"):
        satisfied.append("replay contract hash emitted")
    if report_grade_validation_plan and report_grade_validation_plan.get("validation_plan_sha256"):
        satisfied.append("report reproducibility report-grade validation plan")
    if report_grade_validation_plan and int(report_grade_validation_plan.get("ready_slot_count") or 0) >= 6:
        satisfied.append("report reproducibility report-grade ready slots")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted report replay manifest diff pass")
    return [
        build_accuracy_gate(
            89,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"stable_payload_sha256:{stable_hash}",
                f"stable_item_count:{item_count}",
                f"citation_count:{citation_count}",
                f"report_replay_manifest_hash:{(report_replay_manifest or {}).get('manifest_hash', '')}",
                f"row_hash_set_hash:{(report_replay_manifest or {}).get('row_hash_set_hash', '')}",
                f"report_reproducibility_report_grade_validation_plan_hash:{(report_grade_validation_plan or {}).get('validation_plan_sha256', '')}",
            ],
        )
    ]


def report_item_provenance_core_accuracy_gates(
    *,
    source_path: str,
    hashes: Mapping[str, object],
    record_hashes: Mapping[str, object],
    parser: str,
    parser_version: str,
    parser_confidence: object,
    record_offset: object,
    source_index: object,
    review_status: str,
    reportability: str,
    provenance_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
    report_grade_validation_plan: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = []
    if source_path:
        satisfied.append("source path preserved")
    if hashes or record_hashes:
        satisfied.append("source or record hashes preserved")
    if parser or parser_version or parser_confidence:
        satisfied.append("parser/version/confidence preserved")
    if record_offset is not None or source_index is not None:
        satisfied.append("offset or source index preserved when available")
    if review_status or reportability:
        satisfied.append("review/reportability fields preserved")
    if provenance_manifest and provenance_manifest.get("provenance_row_hash"):
        satisfied.append("provenance row hash emitted")
    if provenance_manifest and provenance_manifest.get("manifest_hash"):
        satisfied.append("provenance manifest hash emitted")
    if provenance_manifest and provenance_manifest.get("field_presence_hash"):
        satisfied.append("provenance field-presence hash emitted")
    if report_grade_validation_plan and report_grade_validation_plan.get("validation_plan_sha256"):
        satisfied.append("source provenance report-grade validation plan")
    if report_grade_validation_plan and int(report_grade_validation_plan.get("ready_slot_count") or 0) >= 7:
        satisfied.append("source provenance report-grade ready slots")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted report provenance manifest diff pass")
    return [
        build_accuracy_gate(
            90,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"source_path:{source_path}",
                f"has_hashes:{bool(hashes or record_hashes)}",
                f"parser:{parser}",
                f"review_status:{review_status}",
                f"reportability:{reportability}",
                f"provenance_manifest_hash:{(provenance_manifest or {}).get('manifest_hash', '')}",
                f"source_provenance_report_grade_validation_plan_hash:{(report_grade_validation_plan or {}).get('validation_plan_sha256', '')}",
            ],
        )
    ]


def missing_integrity_trusted_diff(gap_id: str, blocker: str, *, trusted_tool: str) -> dict[str, object]:
    return {
        "status": "missing",
        "trusted_tool": None,
        "commercial_gap_ids": [gap_id],
        "blocker": blocker,
        "required_trusted_tool": trusted_tool,
    }


def build_custody_workflow_trusted_diff(
    rapid_workflow: Mapping[str, object],
    trusted_workflow: Mapping[str, object],
    *,
    trusted_tool: str = "custody-event-manifest",
) -> dict[str, object]:
    mismatches = compare_integrity_manifests(
        custody_manifest(rapid_workflow),
        custody_manifest(trusted_workflow),
        fields=("evidence_sources", "custody_events", "manifest_hash", "custody_completeness_matrix_hash"),
    )
    status = "pass" if not mismatches and trusted_tool in FORENSIC_INTEGRITY_TRUSTED_TOOLS else "fail"
    return integrity_trusted_diff_result(
        status=status,
        gap_id=CHAIN_OF_CUSTODY_GAP_ID,
        blocker=CUSTODY_TRUSTED_DIFF_BLOCKER_86,
        trusted_tool=trusted_tool,
        compared_fields=["evidence_sources", "custody_events", "manifest_hash", "custody_completeness_matrix_hash"],
        mismatches=mismatches,
    )


def build_acquisition_hash_trusted_diff(
    rapid_workflow: Mapping[str, object],
    trusted_workflow: Mapping[str, object],
    *,
    trusted_tool: str = "acquisition-hash-manifest",
) -> dict[str, object]:
    mismatches = compare_integrity_manifests(
        acquisition_hash_manifest(rapid_workflow),
        acquisition_hash_manifest(trusted_workflow),
        fields=("hashes", "manifest_hash", "hash_inventory_matrix_hash"),
    )
    status = "pass" if not mismatches and trusted_tool in FORENSIC_INTEGRITY_TRUSTED_TOOLS else "fail"
    return integrity_trusted_diff_result(
        status=status,
        gap_id=ACQUISITION_HASH_GAP_ID,
        blocker=ACQUISITION_HASH_TRUSTED_DIFF_BLOCKER_87,
        trusted_tool=trusted_tool,
        compared_fields=["hashes", "manifest_hash", "hash_inventory_matrix_hash"],
        mismatches=mismatches,
    )


def build_immutable_audit_trusted_diff(
    rapid_workflow: Mapping[str, object],
    trusted_workflow: Mapping[str, object],
    *,
    trusted_tool: str = "audit-hash-chain-manifest",
) -> dict[str, object]:
    mismatches = compare_integrity_manifests(
        audit_integrity_manifest(rapid_workflow),
        audit_integrity_manifest(trusted_workflow),
        fields=("head_hash", "events", "manifest_hash", "actor_action_matrix_hash", "audit_replay_manifest_hash", "replay_matrix_hash"),
    )
    status = "pass" if not mismatches and trusted_tool in FORENSIC_INTEGRITY_TRUSTED_TOOLS else "fail"
    return integrity_trusted_diff_result(
        status=status,
        gap_id=IMMUTABLE_AUDIT_GAP_ID,
        blocker=IMMUTABLE_AUDIT_TRUSTED_DIFF_BLOCKER_88,
        trusted_tool=trusted_tool,
        compared_fields=[
            "head_hash",
            "events",
            "manifest_hash",
            "actor_action_matrix_hash",
            "audit_replay_manifest_hash",
            "replay_matrix_hash",
        ],
        mismatches=mismatches,
    )


def build_report_reproducibility_trusted_diff(
    rapid_manifest: Mapping[str, object],
    trusted_manifest: Mapping[str, object],
    *,
    trusted_tool: str = "report-replay-manifest",
) -> dict[str, object]:
    mismatches = compare_integrity_manifests(
        reproducibility_manifest(rapid_manifest),
        reproducibility_manifest(trusted_manifest),
        fields=(
            "stable_payload_sha256",
            "stable_item_count",
            "citation_count",
            "manifest_hash",
            "item_row_hashes",
            "citation_row_hashes",
            "row_hash_set_hash",
            "replay_contract_hash",
        ),
    )
    status = "pass" if not mismatches and trusted_tool in FORENSIC_INTEGRITY_TRUSTED_TOOLS else "fail"
    return integrity_trusted_diff_result(
        status=status,
        gap_id=REPORT_REPRODUCIBILITY_GAP_ID,
        blocker=REPORT_REPRODUCIBILITY_TRUSTED_DIFF_BLOCKER_89,
        trusted_tool=trusted_tool,
        compared_fields=[
            "stable_payload_sha256",
            "stable_item_count",
            "citation_count",
            "manifest_hash",
            "item_row_hashes",
            "citation_row_hashes",
            "row_hash_set_hash",
            "replay_contract_hash",
        ],
        mismatches=mismatches,
    )


def build_report_provenance_trusted_diff(
    rapid_rows: Sequence[Mapping[str, object]],
    trusted_rows: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str = "report-provenance-manifest",
) -> dict[str, object]:
    mismatches = compare_indexed_integrity_rows(
        index_provenance_rows(rapid_rows),
        index_provenance_rows(trusted_rows),
        fields=(
            "source_path",
            "hashes",
            "record_hashes",
            "parser",
            "parser_version",
            "review_status",
            "reportability",
            "provenance_row_hash",
            "field_presence_hash",
            "completeness_score",
            "manifest_hash",
        ),
    )
    status = "pass" if not mismatches and trusted_tool in FORENSIC_INTEGRITY_TRUSTED_TOOLS else "fail"
    return integrity_trusted_diff_result(
        status=status,
        gap_id=SOURCE_PROVENANCE_GAP_ID,
        blocker=SOURCE_PROVENANCE_TRUSTED_DIFF_BLOCKER_90,
        trusted_tool=trusted_tool,
        compared_fields=[
            "target_citation_id",
            "source_path",
            "hashes",
            "parser",
            "review_status",
            "reportability",
            "provenance_row_hash",
            "field_presence_hash",
            "completeness_score",
            "manifest_hash",
        ],
        mismatches=mismatches,
    )


def integrity_trusted_diff_result(
    *,
    status: str,
    gap_id: str,
    blocker: str,
    trusted_tool: str,
    compared_fields: Sequence[str],
    mismatches: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    return {
        "status": status,
        "trusted_tool": trusted_tool,
        "commercial_gap_ids": [gap_id],
        "compared_fields": list(compared_fields),
        "mismatches": [dict(item) for item in mismatches],
        "blocker": None if status == "pass" else blocker,
    }


def compare_integrity_manifests(
    rapid: Mapping[str, object],
    trusted: Mapping[str, object],
    *,
    fields: Sequence[str],
) -> list[dict[str, object]]:
    return [
        {"field": field, "rapid": normalize_integrity_value(rapid.get(field)), "trusted": normalize_integrity_value(trusted.get(field))}
        for field in fields
        if normalize_integrity_value(rapid.get(field)) != normalize_integrity_value(trusted.get(field))
    ]


def compare_indexed_integrity_rows(
    rapid_index: Mapping[str, Mapping[str, object]],
    trusted_index: Mapping[str, Mapping[str, object]],
    *,
    fields: Sequence[str],
) -> list[dict[str, object]]:
    mismatches: list[dict[str, object]] = []
    for key, trusted_row in sorted(trusted_index.items()):
        rapid_row = rapid_index.get(key)
        if rapid_row is None:
            mismatches.append({"id": key, "field": "row", "rapid": None, "trusted": "present"})
            continue
        for field in fields:
            rapid_value = normalize_integrity_value(rapid_row.get(field))
            trusted_value = normalize_integrity_value(trusted_row.get(field))
            if rapid_value != trusted_value:
                mismatches.append({"id": key, "field": field, "rapid": rapid_value, "trusted": trusted_value})
    for key in sorted(set(rapid_index) - set(trusted_index)):
        mismatches.append({"id": key, "field": "row", "rapid": "present", "trusted": None})
    return mismatches


def normalize_integrity_value(value: object) -> object:
    if isinstance(value, list):
        return sorted(json.dumps(item, ensure_ascii=False, sort_keys=True, default=str) for item in value)
    if isinstance(value, tuple):
        return sorted(json.dumps(item, ensure_ascii=False, sort_keys=True, default=str) for item in value)
    if isinstance(value, Mapping):
        return json.dumps(dict(value), ensure_ascii=False, sort_keys=True, default=str)
    return value


def custody_manifest(workflow: Mapping[str, object]) -> dict[str, object]:
    event_manifest = workflow.get("custody_event_manifest")
    event_manifest_mapping = event_manifest if isinstance(event_manifest, Mapping) else {}
    chain_manifest = workflow.get("custody_chain_manifest")
    chain_manifest_mapping = chain_manifest if isinstance(chain_manifest, Mapping) else {}
    return {
        "manifest_hash": str(workflow.get("custody_manifest_hash") or event_manifest_mapping.get("manifest_hash") or ""),
        "custody_completeness_matrix_hash": str(
            workflow.get("custody_completeness_matrix_hash")
            or chain_manifest_mapping.get("custody_completeness_matrix_hash")
            or ""
        ),
        "evidence_sources": [
            {
                "citation_id": item.get("citation_id"),
                "sha256": item.get("sha256"),
                "status": item.get("status"),
                "original_path": item.get("original_path"),
                "custody_row_hash": item.get("custody_row_hash"),
            }
            for item in workflow.get("evidence_sources", [])
            if isinstance(item, Mapping)
        ],
        "custody_events": [
            {
                "citation_id": item.get("citation_id"),
                "actor": item.get("actor"),
                "action": item.get("action"),
                "target_type": item.get("target_type"),
                "target_id": item.get("target_id"),
                "timestamp": item.get("timestamp"),
                "result": item.get("result"),
                "custody_row_hash": item.get("custody_row_hash"),
            }
            for item in workflow.get("custody_events", [])
            if isinstance(item, Mapping)
        ],
    }


def acquisition_hash_manifest(workflow: Mapping[str, object]) -> dict[str, object]:
    manifest = workflow.get("acquisition_hash_manifest")
    manifest_hash = ""
    hash_inventory_matrix_hash = ""
    if isinstance(manifest, Mapping):
        manifest_hash = str(manifest.get("manifest_hash") or "")
        hash_inventory_matrix_hash = str(manifest.get("hash_inventory_matrix_hash") or "")
    return {
        "manifest_hash": manifest_hash,
        "hash_inventory_matrix_hash": hash_inventory_matrix_hash,
        "hashes": [
            {
                "citation_id": item.get("citation_id"),
                "target_type": item.get("target_type"),
                "target_id": item.get("target_id"),
                "hash_scope": item.get("hash_scope"),
                "hashes": item.get("hashes"),
                "hash_status": item.get("hash_status"),
                "missing_hash_warning": item.get("missing_hash_warning"),
                "calculated_at": item.get("calculated_at"),
                "acquisition_hash_row_hash": item.get("acquisition_hash_row_hash"),
            }
            for item in workflow.get("hashes", [])
            if isinstance(item, Mapping)
        ],
    }


def audit_integrity_manifest(workflow: Mapping[str, object]) -> dict[str, object]:
    summary = workflow.get("summary") if isinstance(workflow.get("summary"), Mapping) else {}
    manifest = workflow.get("audit_hash_chain_manifest")
    replay_manifest = workflow.get("audit_replay_manifest")
    manifest_hash = ""
    actor_action_matrix_hash = ""
    replay_manifest_hash = ""
    replay_matrix_hash = ""
    if isinstance(manifest, Mapping):
        manifest_hash = str(manifest.get("manifest_hash") or "")
        actor_action_matrix_hash = str(manifest.get("actor_action_matrix_hash") or "")
    if isinstance(replay_manifest, Mapping):
        replay_manifest_hash = str(replay_manifest.get("manifest_hash") or "")
        replay_matrix_hash = str(replay_manifest.get("replay_matrix_hash") or "")
    return {
        "head_hash": summary.get("head_hash"),
        "manifest_hash": manifest_hash,
        "actor_action_matrix_hash": actor_action_matrix_hash,
        "audit_replay_manifest_hash": replay_manifest_hash,
        "replay_matrix_hash": replay_matrix_hash,
        "events": [
            {
                "citation_id": item.get("citation_id"),
                "previous_event_hash": item.get("previous_event_hash"),
                "event_hash": item.get("event_hash"),
                "action": item.get("action"),
                "timestamp": item.get("timestamp"),
            }
            for item in workflow.get("events", [])
            if isinstance(item, Mapping)
        ],
    }


def reproducibility_manifest(manifest: Mapping[str, object]) -> dict[str, object]:
    replay_manifest = manifest.get("report_replay_manifest")
    manifest_hash = ""
    item_row_hashes: list[object] = []
    citation_row_hashes: list[object] = []
    row_hash_set_hash = ""
    replay_contract_hash = ""
    if isinstance(replay_manifest, Mapping):
        manifest_hash = str(replay_manifest.get("manifest_hash") or "")
        row_hash_set_hash = str(replay_manifest.get("row_hash_set_hash") or "")
        replay_contract_hash = str(replay_manifest.get("replay_contract_hash") or "")
        if isinstance(replay_manifest.get("item_row_hashes"), list):
            item_row_hashes = list(replay_manifest["item_row_hashes"])
        if isinstance(replay_manifest.get("citation_row_hashes"), list):
            citation_row_hashes = list(replay_manifest["citation_row_hashes"])
    return {
        "stable_payload_sha256": manifest.get("stable_payload_sha256"),
        "stable_item_count": manifest.get("stable_item_count"),
        "citation_count": manifest.get("citation_count"),
        "manifest_hash": manifest_hash,
        "item_row_hashes": item_row_hashes,
        "citation_row_hashes": citation_row_hashes,
        "row_hash_set_hash": row_hash_set_hash,
        "replay_contract_hash": replay_contract_hash,
    }


def index_provenance_rows(rows: Sequence[Mapping[str, object]]) -> dict[str, Mapping[str, object]]:
    indexed: dict[str, Mapping[str, object]] = {}
    for row in rows:
        key = str(row.get("target_citation_id") or row.get("review_citation_id") or row.get("source_path") or "")
        if not key:
            continue
        indexed[key] = {
            "source_path": row.get("source_path"),
            "hashes": row.get("hashes"),
            "record_hashes": row.get("record_hashes"),
            "parser": row.get("parser"),
            "parser_version": row.get("parser_version"),
            "review_status": row.get("review_status"),
            "reportability": row.get("reportability"),
            "provenance_row_hash": row.get("provenance_row_hash"),
            "field_presence_hash": (row.get("provenance_manifest") or {}).get("field_presence_hash")
            if isinstance(row.get("provenance_manifest"), Mapping)
            else "",
            "completeness_score": (row.get("provenance_manifest") or {}).get("completeness_score")
            if isinstance(row.get("provenance_manifest"), Mapping)
            else None,
            "manifest_hash": row.get("provenance_manifest_hash"),
        }
    return indexed


def missing_report_quality_trusted_diff(gap_id: str, blocker: str, *, trusted_tool: str) -> dict[str, object]:
    return {
        "status": "missing",
        "trusted_tool": None,
        "commercial_gap_ids": [gap_id],
        "blocker": blocker,
        "required_trusted_tool": trusted_tool,
    }


def build_parser_confidence_trusted_diff(
    rapid_assessment: Mapping[str, object],
    trusted_assessment: Mapping[str, object],
    *,
    trusted_tool: str = "parser-confidence-calibration",
) -> dict[str, object]:
    compared_fields = [
        "parser_confidence",
        "confidence_band",
        "reportability_score",
        "reportability",
        "coverage_status",
        "evidence_strength",
        "parser_confidence_manifest_hash",
        "calibration_field_presence_hash",
    ]
    mismatches = [
        {"field": field, "rapid": rapid_assessment.get(field), "trusted": trusted_assessment.get(field)}
        for field in compared_fields
        if rapid_assessment.get(field) != trusted_assessment.get(field)
    ]
    status = "pass" if not mismatches and trusted_tool in REPORT_QUALITY_TRUSTED_TOOLS else "fail"
    return report_quality_trusted_diff_result(
        status=status,
        gap_id=PARSER_CONFIDENCE_GAP_ID,
        blocker=PARSER_CONFIDENCE_TRUSTED_DIFF_BLOCKER_91,
        trusted_tool=trusted_tool,
        compared_fields=compared_fields,
        mismatches=mismatches,
    )


def build_validation_warning_trusted_diff(
    rapid_assessment: Mapping[str, object],
    trusted_assessment: Mapping[str, object],
    *,
    trusted_tool: str = "validation-warning-checklist",
) -> dict[str, object]:
    compared_fields = [
        "validation_required",
        "warnings",
        "warning_severity_counts",
        "warning_category_counts",
        "warning_ux_badges",
        "validation_warning_manifest_hash",
        "warning_action_matrix_hash",
    ]
    mismatches = [
        {"field": field, "rapid": normalize_integrity_value(rapid_assessment.get(field)), "trusted": normalize_integrity_value(trusted_assessment.get(field))}
        for field in compared_fields
        if normalize_integrity_value(rapid_assessment.get(field)) != normalize_integrity_value(trusted_assessment.get(field))
    ]
    status = "pass" if not mismatches and trusted_tool in REPORT_QUALITY_TRUSTED_TOOLS else "fail"
    return report_quality_trusted_diff_result(
        status=status,
        gap_id=VALIDATION_WARNING_UX_GAP_ID,
        blocker=VALIDATION_WARNING_TRUSTED_DIFF_BLOCKER_92,
        trusted_tool=trusted_tool,
        compared_fields=compared_fields,
        mismatches=mismatches,
    )


def build_legal_limitation_trusted_diff(
    rapid_assessment: Mapping[str, object],
    trusted_assessment: Mapping[str, object],
    *,
    trusted_tool: str = "legal-limitation-wording-review",
) -> dict[str, object]:
    compared_fields = [
        "limitation_count",
        "status",
        "limitation_category_counts",
        "limitation_scope_counts",
        "legal_limitation_manifest_hash",
        "limitation_wording_matrix_hash",
    ]
    mismatches = [
        {"field": field, "rapid": rapid_assessment.get(field), "trusted": trusted_assessment.get(field)}
        for field in compared_fields
        if rapid_assessment.get(field) != trusted_assessment.get(field)
    ]
    status = "pass" if not mismatches and trusted_tool in REPORT_QUALITY_TRUSTED_TOOLS else "fail"
    return report_quality_trusted_diff_result(
        status=status,
        gap_id=LEGAL_LIMITATION_GAP_ID,
        blocker=LEGAL_LIMITATION_TRUSTED_DIFF_BLOCKER_93,
        trusted_tool=trusted_tool,
        compared_fields=compared_fields,
        mismatches=mismatches,
    )


def report_quality_trusted_diff_result(
    *,
    status: str,
    gap_id: str,
    blocker: str,
    trusted_tool: str,
    compared_fields: Sequence[str],
    mismatches: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    return {
        "status": status,
        "trusted_tool": trusted_tool,
        "commercial_gap_ids": [gap_id],
        "compared_fields": list(compared_fields),
        "mismatches": [dict(item) for item in mismatches],
        "blocker": None if status == "pass" else blocker,
    }


def missing_acquisition_quality_trusted_diff(gap_id: str, blocker: str, *, trusted_tool: str) -> dict[str, object]:
    return {
        "status": "missing",
        "trusted_tool": None,
        "commercial_gap_ids": [gap_id],
        "blocker": blocker,
        "required_trusted_tool": trusted_tool,
    }


def missing_acquisition_metadata_trusted_diff() -> dict[str, object]:
    return missing_acquisition_quality_trusted_diff(
        WRITE_BLOCKER_ACQUISITION_METADATA_GAP_ID,
        ACQUISITION_METADATA_TRUSTED_DIFF_BLOCKER_96,
        trusted_tool="signed-acquisition-handoff",
    )


def missing_timezone_validation_trusted_diff() -> dict[str, object]:
    return missing_acquisition_quality_trusted_diff(
        TIMEZONE_NORMALIZATION_GAP_ID,
        TIMEZONE_VALIDATION_TRUSTED_DIFF_BLOCKER_97,
        trusted_tool="timezone-normalization-matrix",
    )


def missing_clock_skew_trusted_diff() -> dict[str, object]:
    return missing_acquisition_quality_trusted_diff(
        CLOCK_SKEW_ANALYSIS_GAP_ID,
        CLOCK_SKEW_TRUSTED_DIFF_BLOCKER_98,
        trusted_tool="clock-skew-baseline",
    )


def missing_contamination_warning_trusted_diff() -> dict[str, object]:
    return missing_acquisition_quality_trusted_diff(
        EVIDENCE_CONTAMINATION_WARNING_GAP_ID,
        CONTAMINATION_WARNING_TRUSTED_DIFF_BLOCKER_99,
        trusted_tool="contamination-checklist",
    )


def build_acquisition_metadata_trusted_diff(
    rapid_record: Mapping[str, object],
    trusted_record: Mapping[str, object],
    *,
    trusted_tool: str = "signed-acquisition-handoff",
) -> dict[str, object]:
    compared_fields = [
        "records",
        "missing_required_fields",
        "acquisition_metadata_handoff_manifest_hash",
        "acquisition_field_completion_matrix_hash",
    ]
    mismatches = build_acquisition_quality_mismatches(rapid_record, trusted_record, compared_fields)
    return acquisition_quality_trusted_diff_result(
        status="pass" if not mismatches and trusted_tool in ACQUISITION_QUALITY_TRUSTED_TOOLS else "fail",
        gap_id=WRITE_BLOCKER_ACQUISITION_METADATA_GAP_ID,
        blocker=ACQUISITION_METADATA_TRUSTED_DIFF_BLOCKER_96,
        trusted_tool=trusted_tool,
        compared_fields=compared_fields,
        mismatches=mismatches,
    )


def build_timezone_validation_trusted_diff(
    rapid_validation: Mapping[str, object],
    trusted_validation: Mapping[str, object],
    *,
    trusted_tool: str = "timezone-normalization-matrix",
) -> dict[str, object]:
    compared_fields = [
        "summary",
        "samples",
        "timezone_normalization_manifest_hash",
        "parser_assumption_matrix_hash",
        "time_semantics_manifest_hash",
    ]
    mismatches = build_acquisition_quality_mismatches(rapid_validation, trusted_validation, compared_fields)
    return acquisition_quality_trusted_diff_result(
        status="pass" if not mismatches and trusted_tool in ACQUISITION_QUALITY_TRUSTED_TOOLS else "fail",
        gap_id=TIMEZONE_NORMALIZATION_GAP_ID,
        blocker=TIMEZONE_VALIDATION_TRUSTED_DIFF_BLOCKER_97,
        trusted_tool=trusted_tool,
        compared_fields=compared_fields,
        mismatches=mismatches,
    )


def build_clock_skew_trusted_diff(
    rapid_analysis: Mapping[str, object],
    trusted_analysis: Mapping[str, object],
    *,
    trusted_tool: str = "clock-skew-baseline",
) -> dict[str, object]:
    compared_fields = ["summary", "warnings", "clock_skew_baseline_manifest_hash", "clock_skew_range_matrix_hash"]
    mismatches = build_acquisition_quality_mismatches(rapid_analysis, trusted_analysis, compared_fields)
    return acquisition_quality_trusted_diff_result(
        status="pass" if not mismatches and trusted_tool in ACQUISITION_QUALITY_TRUSTED_TOOLS else "fail",
        gap_id=CLOCK_SKEW_ANALYSIS_GAP_ID,
        blocker=CLOCK_SKEW_TRUSTED_DIFF_BLOCKER_98,
        trusted_tool=trusted_tool,
        compared_fields=compared_fields,
        mismatches=mismatches,
    )


def build_contamination_warning_trusted_diff(
    rapid_warnings: Mapping[str, object],
    trusted_warnings: Mapping[str, object],
    *,
    trusted_tool: str = "contamination-checklist",
) -> dict[str, object]:
    compared_fields = [
        "summary",
        "warnings",
        "contamination_checklist_manifest_hash",
        "warning_review_matrix_hash",
        "contamination_acquisition_context_manifest_hash",
    ]
    mismatches = build_acquisition_quality_mismatches(rapid_warnings, trusted_warnings, compared_fields)
    return acquisition_quality_trusted_diff_result(
        status="pass" if not mismatches and trusted_tool in ACQUISITION_QUALITY_TRUSTED_TOOLS else "fail",
        gap_id=EVIDENCE_CONTAMINATION_WARNING_GAP_ID,
        blocker=CONTAMINATION_WARNING_TRUSTED_DIFF_BLOCKER_99,
        trusted_tool=trusted_tool,
        compared_fields=compared_fields,
        mismatches=mismatches,
    )


def build_acquisition_quality_mismatches(
    rapid_payload: Mapping[str, object],
    trusted_payload: Mapping[str, object],
    compared_fields: Sequence[str],
) -> list[dict[str, object]]:
    mismatches = []
    for field in compared_fields:
        rapid_value = normalize_integrity_value(rapid_payload.get(field))
        trusted_value = normalize_integrity_value(trusted_payload.get(field))
        if rapid_value != trusted_value:
            mismatches.append({"field": field, "rapid": rapid_value, "trusted": trusted_value})
    return mismatches


def acquisition_quality_trusted_diff_result(
    *,
    status: str,
    gap_id: str,
    blocker: str,
    trusted_tool: str,
    compared_fields: Sequence[str],
    mismatches: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    return {
        "status": status,
        "trusted_tool": trusted_tool,
        "commercial_gap_ids": [gap_id],
        "compared_fields": list(compared_fields),
        "mismatches": [dict(item) for item in mismatches],
        "blocker": None if status == "pass" else blocker,
    }


def parser_confidence_core_accuracy_gates(
    *,
    parser_confidence: object,
    reportability: str,
    coverage_status: str,
    warnings: Sequence[str],
    evidence_strength: str,
    confidence_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
    report_grade_validation_plan: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = []
    if parser_confidence not in (None, ""):
        satisfied.append("parser confidence preserved")
    if reportability:
        satisfied.append("reportability state recorded")
    if coverage_status:
        satisfied.append("coverage status recorded")
    if warnings is not None:
        satisfied.append("validation warnings derived")
    if evidence_strength:
        satisfied.append("evidence strength surfaced")
    if confidence_manifest and confidence_manifest.get("confidence_band"):
        satisfied.append("confidence band assigned")
    if confidence_manifest and confidence_manifest.get("reportability_score") is not None:
        satisfied.append("reportability score emitted")
    if confidence_manifest and confidence_manifest.get("manifest_hash"):
        satisfied.append("parser confidence calibration manifest hash emitted")
    if confidence_manifest and confidence_manifest.get("calibration_field_presence_hash"):
        satisfied.append("parser confidence field-presence hash emitted")
    if report_grade_validation_plan and report_grade_validation_plan.get("validation_plan_sha256"):
        satisfied.append("parser confidence report-grade validation plan")
    if report_grade_validation_plan and int(report_grade_validation_plan.get("ready_slot_count") or 0) >= 6:
        satisfied.append("parser confidence report-grade ready slots")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted parser confidence calibration diff pass")
    return [
        build_accuracy_gate(
            91,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"parser_confidence:{parser_confidence}",
                f"reportability:{reportability}",
                f"coverage_status:{coverage_status}",
                f"warning_count:{len(warnings)}",
                f"evidence_strength:{evidence_strength}",
                f"confidence_band:{(confidence_manifest or {}).get('confidence_band', '')}",
                f"reportability_score:{(confidence_manifest or {}).get('reportability_score', '')}",
                f"parser_confidence_manifest_hash:{(confidence_manifest or {}).get('manifest_hash', '')}",
                f"calibration_field_presence_hash:{(confidence_manifest or {}).get('calibration_field_presence_hash', '')}",
                f"parser_confidence_report_grade_validation_plan_hash:{(report_grade_validation_plan or {}).get('validation_plan_sha256', '')}",
            ],
        )
    ]


def validation_warning_ux_core_accuracy_gates(
    *,
    warnings: Sequence[str],
    warning_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
    report_grade_validation_plan: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = [
        "validation warning reasons emitted",
        "summary warning counts emitted",
        "report guidance emitted",
        "validation-required state preserved",
        "warning UX limitation disclosed",
    ]
    if warning_manifest and warning_manifest.get("warnings"):
        satisfied.append("warning detail metadata emitted")
    if warning_manifest and warning_manifest.get("ux_badges"):
        satisfied.append("warning UX badges emitted")
    if warning_manifest and warning_manifest.get("manifest_hash"):
        satisfied.append("validation warning checklist manifest hash emitted")
    if warning_manifest and warning_manifest.get("warning_action_matrix_hash"):
        satisfied.append("warning action matrix hash emitted")
    if report_grade_validation_plan and report_grade_validation_plan.get("validation_plan_sha256"):
        satisfied.append("validation warning report-grade validation plan")
    if report_grade_validation_plan and int(report_grade_validation_plan.get("ready_slot_count") or 0) >= 7:
        satisfied.append("validation warning report-grade ready slots")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted validation warning checklist diff pass")
    return [
        build_accuracy_gate(
            92,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"warning_count:{len(warnings)}",
                f"warning_manifest_hash:{(warning_manifest or {}).get('manifest_hash', '')}",
                f"warning_action_matrix_hash:{(warning_manifest or {}).get('warning_action_matrix_hash', '')}",
                f"ux_badges:{','.join((warning_manifest or {}).get('ux_badges', []) if isinstance((warning_manifest or {}).get('ux_badges'), list) else [])}",
                f"validation_warning_report_grade_validation_plan_hash:{(report_grade_validation_plan or {}).get('validation_plan_sha256', '')}",
            ],
        )
    ]


def legal_limitation_core_accuracy_gates(
    *,
    limitations: Sequence[str],
    limitation_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
    report_grade_validation_plan: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = [
        "artifact limitation text emitted",
        "parser-provided limitations preserved",
        "jurisdiction caveat emitted",
        "analyst review blocker emitted",
        "limitation count summarized",
    ]
    if limitation_manifest and limitation_manifest.get("limitations"):
        satisfied.append("legal limitation detail metadata emitted")
    if limitation_manifest and limitation_manifest.get("category_counts"):
        satisfied.append("limitation category counts emitted")
    if limitation_manifest and limitation_manifest.get("manifest_hash"):
        satisfied.append("legal limitation wording manifest hash emitted")
    if limitation_manifest and limitation_manifest.get("limitation_wording_matrix_hash"):
        satisfied.append("limitation wording matrix hash emitted")
    if report_grade_validation_plan and report_grade_validation_plan.get("validation_plan_sha256"):
        satisfied.append("legal limitation report-grade validation plan")
    if report_grade_validation_plan and int(report_grade_validation_plan.get("ready_slot_count") or 0) >= 7:
        satisfied.append("legal limitation report-grade ready slots")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted legal limitation wording diff pass")
    return [
        build_accuracy_gate(
            93,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"limitation_count:{len(limitations)}",
                f"legal_limitation_manifest_hash:{(limitation_manifest or {}).get('manifest_hash', '')}",
                f"limitation_wording_matrix_hash:{(limitation_manifest or {}).get('limitation_wording_matrix_hash', '')}",
                f"legal_limitation_report_grade_validation_plan_hash:{(report_grade_validation_plan or {}).get('validation_plan_sha256', '')}",
            ],
        )
    ]


def acquisition_metadata_core_accuracy_gates(
    *,
    records: Sequence[Mapping[str, object]],
    missing_required_fields: Sequence[str],
    handoff_manifest: Mapping[str, object] | None = None,
    input_manifest: Mapping[str, object] | None = None,
    report_grade_validation_plan: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = ["missing required fields listed", "submission readiness flag emitted"]
    if any(record.get("operator") or record.get("source_identifier") for record in records):
        satisfied.append("operator/source metadata recorded")
    if any(record.get("write_blocker") for record in records):
        satisfied.append("write-blocker field recorded")
    if any(record.get("whole_source_sha256") for record in records):
        satisfied.append("whole-source hash field recorded")
    if records and all(record.get("acquisition_metadata_row_hash") for record in records):
        satisfied.append("acquisition metadata row hashes emitted")
    if handoff_manifest and handoff_manifest.get("evidence_source_row_hashes"):
        satisfied.append("evidence source row hashes emitted")
    if handoff_manifest and handoff_manifest.get("manifest_hash"):
        satisfied.append("acquisition handoff manifest hash emitted")
    if handoff_manifest and handoff_manifest.get("field_completion_matrix_hash"):
        satisfied.append("acquisition field completion matrix hash emitted")
    if input_manifest and input_manifest.get("manifest_hash"):
        satisfied.append("acquisition metadata input manifest hash emitted")
    if report_grade_validation_plan and report_grade_validation_plan.get("validation_plan_hash"):
        satisfied.append("acquisition metadata report-grade validation plan")
    if report_grade_validation_plan and report_grade_validation_plan.get("ready_slot_count"):
        satisfied.append("acquisition metadata report-grade ready slots")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted acquisition handoff diff pass")
    return [
        build_accuracy_gate(
            96,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"record_count:{len(records)}",
                f"missing_required_field_count:{len(missing_required_fields)}",
                f"acquisition_metadata_handoff_manifest_hash:{(handoff_manifest or {}).get('manifest_hash', '')}",
                f"acquisition_field_completion_matrix_hash:{(handoff_manifest or {}).get('field_completion_matrix_hash', '')}",
                f"acquisition_metadata_input_manifest_hash:{(input_manifest or {}).get('manifest_hash', '')}",
                f"acquisition_metadata_report_grade_validation_plan_hash:{(report_grade_validation_plan or {}).get('validation_plan_hash', '')}",
            ],
        )
    ]


def timezone_validation_core_accuracy_gates(
    *,
    event_count: int,
    missing_timezone_count: int,
    samples: Sequence[Mapping[str, object]],
    timezone_manifest: Mapping[str, object] | None = None,
    time_semantics_manifest: Mapping[str, object] | None = None,
    report_grade_validation_plan: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = [
        "event timezone inventory emitted",
        "missing timezone count emitted",
        "timestamp samples preserved",
        "UTC assumption disclosed",
        "review-required flag emitted",
    ]
    if samples and all(sample.get("timezone_sample_row_hash") for sample in samples):
        satisfied.append("timezone sample row hashes emitted")
    if timezone_manifest and timezone_manifest.get("manifest_hash"):
        satisfied.append("timezone normalization manifest hash emitted")
    if timezone_manifest and timezone_manifest.get("parser_assumption_matrix_hash"):
        satisfied.append("parser assumption matrix hash emitted")
    if time_semantics_manifest and time_semantics_manifest.get("manifest_hash"):
        satisfied.append("time semantics manifest hash emitted")
    if report_grade_validation_plan and report_grade_validation_plan.get("validation_plan_hash"):
        satisfied.append("timezone report-grade validation plan")
    if report_grade_validation_plan and report_grade_validation_plan.get("ready_slot_count"):
        satisfied.append("timezone report-grade ready slots")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted timezone normalization matrix diff pass")
    return [
        build_accuracy_gate(
            97,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"event_count:{event_count}",
                f"missing_timezone_count:{missing_timezone_count}",
                f"sample_count:{len(samples)}",
                f"timezone_normalization_manifest_hash:{(timezone_manifest or {}).get('manifest_hash', '')}",
                f"parser_assumption_matrix_hash:{(timezone_manifest or {}).get('parser_assumption_matrix_hash', '')}",
                f"time_semantics_manifest_hash:{(time_semantics_manifest or {}).get('manifest_hash', '')}",
                f"timezone_report_grade_validation_plan_hash:{(report_grade_validation_plan or {}).get('validation_plan_hash', '')}",
            ],
        )
    ]


def clock_skew_core_accuracy_gates(
    *,
    parsed_timestamp_count: int,
    warnings: Sequence[Mapping[str, object]],
    earliest: str,
    latest: str,
    clock_manifest: Mapping[str, object] | None = None,
    report_grade_validation_plan: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = [
        "parsed timestamp range emitted",
        "skew warning records emitted",
        "warning count summarized",
        "baseline requirement disclosed",
        "heuristic limitation emitted",
    ]
    if warnings and all(warning.get("clock_skew_warning_row_hash") for warning in warnings):
        satisfied.append("clock-skew warning row hashes emitted")
    if clock_manifest and clock_manifest.get("manifest_hash"):
        satisfied.append("clock-skew baseline manifest hash emitted")
    if clock_manifest and clock_manifest.get("clock_skew_range_matrix_hash"):
        satisfied.append("clock skew range matrix hash emitted")
    if report_grade_validation_plan and report_grade_validation_plan.get("validation_plan_hash"):
        satisfied.append("clock skew report-grade validation plan")
    if report_grade_validation_plan and report_grade_validation_plan.get("ready_slot_count"):
        satisfied.append("clock skew report-grade ready slots")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted clock-skew baseline diff pass")
    return [
        build_accuracy_gate(
            98,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"parsed_timestamp_count:{parsed_timestamp_count}",
                f"warning_count:{len(warnings)}",
                f"earliest:{earliest}",
                f"latest:{latest}",
                f"clock_skew_baseline_manifest_hash:{(clock_manifest or {}).get('manifest_hash', '')}",
                f"clock_skew_range_matrix_hash:{(clock_manifest or {}).get('clock_skew_range_matrix_hash', '')}",
                f"clock_skew_report_grade_validation_plan_hash:{(report_grade_validation_plan or {}).get('validation_plan_hash', '')}",
            ],
        )
    ]


def contamination_warning_core_accuracy_gates(
    *,
    warnings: Sequence[Mapping[str, object]],
    contamination_manifest: Mapping[str, object] | None = None,
    acquisition_context_manifest: Mapping[str, object] | None = None,
    report_grade_validation_plan: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = [
        "contamination warning records emitted",
        "warning count summarized",
        "output-under-evidence checks emitted",
        "write-blocker integration limitation emitted",
        "review-required flag emitted",
    ]
    if warnings and all(warning.get("contamination_warning_row_hash") for warning in warnings):
        satisfied.append("contamination warning row hashes emitted")
    if contamination_manifest and contamination_manifest.get("manifest_hash"):
        satisfied.append("contamination checklist manifest hash emitted")
    if contamination_manifest and contamination_manifest.get("warning_review_matrix_hash"):
        satisfied.append("contamination warning review matrix hash emitted")
    if acquisition_context_manifest and acquisition_context_manifest.get("manifest_hash"):
        satisfied.append("contamination acquisition context manifest hash emitted")
    if report_grade_validation_plan and report_grade_validation_plan.get("validation_plan_hash"):
        satisfied.append("contamination report-grade validation plan")
    if report_grade_validation_plan and report_grade_validation_plan.get("ready_slot_count"):
        satisfied.append("contamination report-grade ready slots")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted contamination checklist diff pass")
    return [
        build_accuracy_gate(
            99,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"warning_count:{len(warnings)}",
                f"contamination_checklist_manifest_hash:{(contamination_manifest or {}).get('manifest_hash', '')}",
                f"warning_review_matrix_hash:{(contamination_manifest or {}).get('warning_review_matrix_hash', '')}",
                f"contamination_acquisition_context_manifest_hash:{(acquisition_context_manifest or {}).get('manifest_hash', '')}",
                f"contamination_report_grade_validation_plan_hash:{(report_grade_validation_plan or {}).get('validation_plan_hash', '')}",
            ],
        )
    ]
