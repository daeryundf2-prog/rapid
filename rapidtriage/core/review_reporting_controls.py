from __future__ import annotations

import hashlib
import json
from typing import Mapping, Sequence


def stable_review_qc_sha256(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


def build_evidence_tray_state_contract(*, selected_count: int = 0, pinned_count: int = 0, compared_count: int = 0, report_candidate_count: int = 0) -> dict[str, object]:
    contract_core = {
        "profile_version": "evidence-tray-state-contract-v1",
        "qc_prep_item_number": 61,
        "state_counts": {
            "selected": int(selected_count),
            "pinned": int(pinned_count),
            "compared": int(compared_count),
            "report_candidates": int(report_candidate_count),
        },
        "required_fields": [
            "case_id",
            "target_type",
            "target_id",
            "review_citation_id",
            "source_viewer_locator",
            "report_candidate",
            "pinned",
            "compare_slot",
            "updated_at",
        ],
        "required_behaviors": {
            "selection_survives_navigation": True,
            "source_locator_required_before_report": True,
            "report_candidate_requires_include_in_report": True,
            "compare_slot_is_explicit": True,
        },
        "commercial_claim_allowed": False,
        "commercial_blockers": [
            "browser-e2e-evidence-tray-persistence-required",
            "large-case-tray-virtualization-test-required",
            "multi-user-selection-conflict-test-required",
        ],
    }
    return {**contract_core, "contract_hash": stable_review_qc_sha256(contract_core)}


def build_review_state_contract(*, review_marks: Sequence[Mapping[str, object]] = ()) -> dict[str, object]:
    review_marks = list(review_marks)
    statuses = sorted({str(mark.get("status") or "unreviewed") for mark in review_marks})
    verification_statuses = sorted({str(mark.get("verification_status") or "unverified") for mark in review_marks})
    contract_core = {
        "profile_version": "review-state-contract-v1",
        "qc_prep_item_number": 62,
        "review_mark_count": len(review_marks),
        "observed_statuses": statuses,
        "observed_verification_statuses": verification_statuses,
        "required_statuses": ["unreviewed", "relevant", "needs-review", "excluded", "not-relevant"],
        "required_fields": [
            "status",
            "verification_status",
            "include_in_report",
            "tags",
            "note",
            "reviewer",
            "assignee",
            "priority",
            "due_at",
            "updated_at",
        ],
        "normalization_rules": {
            "tags_deduplicated": True,
            "priority_normalized": True,
            "include_in_report_preserved_until_explicit_change": True,
        },
        "commercial_claim_allowed": False,
        "commercial_blockers": [
            "trusted-review-state-audit-diff-required",
            "role-based-queue-conflict-test-required",
            "review-state-browser-e2e-required",
        ],
    }
    return {**contract_core, "contract_hash": stable_review_qc_sha256(contract_core)}


def build_compare_notes_contract(*, note_count: int = 0, report_candidate_link_count: int = 0) -> dict[str, object]:
    contract_core = {
        "profile_version": "compare-notes-contract-v1",
        "qc_prep_item_number": 63,
        "note_count": int(note_count),
        "report_candidate_link_count": int(report_candidate_link_count),
        "required_compare_slots": ["A", "B", "C"],
        "required_note_fields": [
            "compare_session_id",
            "slot",
            "target_type",
            "target_id",
            "snippet_hash",
            "note",
            "reviewer",
            "linked_report_candidate_id",
        ],
        "required_behaviors": {
            "notes_persist_across_navigation": True,
            "snippet_hash_preserved": True,
            "report_candidate_link_is_explicit": True,
            "source_locator_required_per_slot": True,
        },
        "commercial_claim_allowed": False,
        "commercial_blockers": [
            "persistent-compare-note-table-required",
            "abc-compare-browser-e2e-required",
            "trusted-compare-note-export-diff-required",
        ],
    }
    return {**contract_core, "contract_hash": stable_review_qc_sha256(contract_core)}


def build_report_citation_manager_contract(*, citation_index: Sequence[Mapping[str, object]] = ()) -> dict[str, object]:
    citation_index = list(citation_index)
    source_records = [item for item in citation_index if item.get("role") == "source-record"]
    source_hash_count = sum(1 for item in source_records if str(item.get("source_hash_status") or "") == "present")
    parser_version_count = sum(1 for item in source_records if str(item.get("parser_version_status") or "") == "present")
    locator_count = sum(1 for item in citation_index if isinstance(item.get("source_viewer_locator"), Mapping) and item.get("source_viewer_locator"))
    contract_core = {
        "profile_version": "report-citation-manager-contract-v1",
        "qc_prep_item_number": 64,
        "citation_count": len(citation_index),
        "source_record_count": len(source_records),
        "source_hash_present_count": source_hash_count,
        "parser_version_present_count": parser_version_count,
        "source_viewer_locator_count": locator_count,
        "required_fields": [
            "source_path",
            "source_hash_sha256",
            "parser_name",
            "parser_version",
            "offset_or_row_or_record_locator",
            "confidence",
            "limitation_text",
            "review_status",
        ],
        "required_behaviors": {
            "copy_safe_citation_text": True,
            "citation_row_hash_required": True,
            "source_locator_required": True,
            "limitation_text_required": True,
        },
        "commercial_claim_allowed": False,
        "commercial_blockers": [
            "source-hash-completeness-validation-required",
            "parser-version-completeness-validation-required",
            "trusted-citation-index-diff-required",
        ],
    }
    return {**contract_core, "contract_hash": stable_review_qc_sha256(contract_core)}


def build_selected_evidence_history_contract(*, history_rows: Sequence[Mapping[str, object]] = ()) -> dict[str, object]:
    history_rows = list(history_rows)
    row_hash_count = sum(1 for row in history_rows if row.get("row_hash"))
    include_in_report_changes = sum(
        1
        for row in history_rows
        if "include_in_report" in [str(field) for field in row.get("changed_fields", [])]
    )
    contract_core = {
        "profile_version": "selected-evidence-history-contract-v1",
        "qc_prep_item_number": 65,
        "history_row_count": len(history_rows),
        "row_hash_count": row_hash_count,
        "include_in_report_change_count": include_in_report_changes,
        "required_fields": [
            "version",
            "review_citation_id",
            "target_type",
            "target_id",
            "changed_at",
            "actor",
            "changed_fields",
            "previous",
            "current",
            "row_hash",
        ],
        "required_behaviors": {
            "append_only_history": True,
            "hash_chain_required": True,
            "history_viewer_locator_required": True,
            "export_manifest_required": True,
        },
        "commercial_claim_allowed": False,
        "commercial_blockers": [
            "signed-multi-user-history-required",
            "trusted-evidence-history-diff-required",
            "database-trigger-enforcement-review-required",
        ],
    }
    return {**contract_core, "contract_hash": stable_review_qc_sha256(contract_core)}


def build_review_reporting_contract(
    *,
    review_marks: Sequence[Mapping[str, object]] = (),
    citation_index: Sequence[Mapping[str, object]] = (),
    history_rows: Sequence[Mapping[str, object]] = (),
    compare_note_count: int = 0,
    compare_report_candidate_link_count: int = 0,
) -> dict[str, object]:
    review_marks = list(review_marks)
    citation_index = list(citation_index)
    history_rows = list(history_rows)
    report_candidate_count = sum(1 for mark in review_marks if bool(mark.get("include_in_report")))
    selected_count = len(review_marks)
    contracts = [
        build_evidence_tray_state_contract(
            selected_count=selected_count,
            pinned_count=0,
            compared_count=compare_note_count,
            report_candidate_count=report_candidate_count,
        ),
        build_review_state_contract(review_marks=review_marks),
        build_compare_notes_contract(
            note_count=compare_note_count,
            report_candidate_link_count=compare_report_candidate_link_count,
        ),
        build_report_citation_manager_contract(citation_index=citation_index),
        build_selected_evidence_history_contract(history_rows=history_rows),
    ]
    contract_core: dict[str, object] = {
        "profile_version": "review-reporting-contract-v1",
        "qc_prep_item_numbers": [61, 62, 63, 64, 65],
        "evidence_tray_state_contract": contracts[0],
        "review_state_contract": contracts[1],
        "compare_notes_contract": contracts[2],
        "report_citation_manager_contract": contracts[3],
        "selected_evidence_history_contract": contracts[4],
        "commercial_claim_allowed": False,
        "commercial_blockers": sorted(
            {blocker for contract in contracts for blocker in contract.get("commercial_blockers", [])}
        ),
    }
    return {**contract_core, "contract_hash": stable_review_qc_sha256(contract_core)}
