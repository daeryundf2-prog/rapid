from __future__ import annotations

import hashlib
import json
from typing import Mapping, Sequence


TRUSTED_TOOL_IMPORT_FAMILIES = [
    "EvtxECmd",
    "Hayabusa",
    "RECmd",
    "MFTECmd",
    "JLECmd",
    "PECmd",
    "ShellBagsExplorer",
    "SrumECmd",
    "libesedb",
]


def stable_submission_qc_sha256(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


def build_court_exhibit_bundle_contract(*, court_exhibit_package: Mapping[str, object] | None = None) -> dict[str, object]:
    package = court_exhibit_package if isinstance(court_exhibit_package, Mapping) else {}
    manifest = package.get("manifest") if isinstance(package.get("manifest"), Mapping) else {}
    contract_core = {
        "profile_version": "court-exhibit-bundle-contract-v1",
        "qc_prep_item_number": 66,
        "exhibit_count": int(manifest.get("exhibit_count") or package.get("exhibit_count") or 0),
        "manifest_hash": str(manifest.get("manifest_hash") or package.get("court_exhibit_manifest_hash") or ""),
        "package_hash": str(package.get("package_hash") or ""),
        "signing_slot_present": bool(package.get("external_signature_slot") or package.get("signing_slots")),
        "required_components": [
            "selected evidence",
            "report outputs",
            "court exhibit manifest",
            "output hashes",
            "source provenance",
            "external signing slot",
        ],
        "commercial_claim_allowed": False,
        "commercial_blockers": [
            "external-signature-or-notarization-required",
            "copied-source-file-bundle-validation-required",
            "independent-court-exhibit-review-required",
        ],
    }
    return {**contract_core, "contract_hash": stable_submission_qc_sha256(contract_core)}


def build_custody_acquisition_contract(*, custody_workflow: Mapping[str, object] | None = None, acquisition_metadata: Mapping[str, object] | None = None) -> dict[str, object]:
    custody = custody_workflow if isinstance(custody_workflow, Mapping) else {}
    custody_summary = custody.get("summary") if isinstance(custody.get("summary"), Mapping) else {}
    acquisition = acquisition_metadata if isinstance(acquisition_metadata, Mapping) else {}
    acquisition_summary = acquisition.get("summary") if isinstance(acquisition.get("summary"), Mapping) else {}
    contract_core = {
        "profile_version": "custody-acquisition-contract-v1",
        "qc_prep_item_number": 67,
        "evidence_source_count": int(custody_summary.get("evidence_source_count") or 0),
        "custody_event_count": int(custody_summary.get("custody_event_count") or 0),
        "missing_acquisition_field_count": int(acquisition_summary.get("missing_required_field_count") or 0),
        "custody_manifest_hash": str(custody.get("custody_manifest_hash") or ""),
        "custody_chain_manifest_hash": str(custody.get("custody_chain_manifest_hash") or ""),
        "required_fields": [
            "operator",
            "source identifier",
            "write blocker",
            "acquisition tool/version",
            "whole source hash",
            "handoff timestamps",
        ],
        "commercial_claim_allowed": False,
        "commercial_blockers": [
            "signed-custody-handoff-required",
            "write-blocker-log-required",
            "trusted-custody-event-manifest-diff-required",
        ],
    }
    return {**contract_core, "contract_hash": stable_submission_qc_sha256(contract_core)}


def build_tamper_evident_audit_contract(*, audit_integrity: Mapping[str, object] | None = None) -> dict[str, object]:
    audit = audit_integrity if isinstance(audit_integrity, Mapping) else {}
    summary = audit.get("summary") if isinstance(audit.get("summary"), Mapping) else {}
    manifest = audit.get("audit_chain_manifest") if isinstance(audit.get("audit_chain_manifest"), Mapping) else {}
    contract_core = {
        "profile_version": "tamper-evident-audit-contract-v1",
        "qc_prep_item_number": 68,
        "audit_event_count": int(summary.get("event_count") or 0),
        "audit_manifest_hash": str(manifest.get("manifest_hash") or audit.get("audit_chain_manifest_hash") or ""),
        "hash_chain_head": str(manifest.get("hash_chain_head") or audit.get("hash_chain_head") or ""),
        "required_behaviors": {
            "append_only_audit_rows": True,
            "export_time_hash_chain": True,
            "bundle_manifest_hash": True,
            "external_signature_slot": True,
        },
        "commercial_claim_allowed": False,
        "commercial_blockers": [
            "external-signature-attestation-required",
            "trusted-audit-hash-chain-manifest-diff-required",
            "tamper-evident-bundle-review-required",
        ],
    }
    return {**contract_core, "contract_hash": stable_submission_qc_sha256(contract_core)}


def build_run_validation_package_contract(*, report_generation_package: Mapping[str, object] | None = None, items: Sequence[Mapping[str, object]] = ()) -> dict[str, object]:
    report_package = report_generation_package if isinstance(report_generation_package, Mapping) else {}
    manifest = report_package.get("manifest") if isinstance(report_package.get("manifest"), Mapping) else {}
    item_list = list(items)
    contract_core = {
        "profile_version": "run-validation-package-contract-v1",
        "qc_prep_item_number": 69,
        "selected_item_count": len(item_list),
        "report_generation_manifest_hash": str(manifest.get("manifest_hash") or ""),
        "hash_bundle_sha256": str(report_package.get("hash_bundle_sha256") or ""),
        "required_sections": [
            "commands",
            "tool versions",
            "source hashes",
            "output hashes",
            "parser versions",
            "trusted diffs",
            "warnings",
            "limitations",
            "reviewer status",
        ],
        "item_warning_count": sum(
            len(item.get("legal_limitations") or [])
            for item in item_list
            if isinstance(item.get("legal_limitations"), list)
        ),
        "commercial_claim_allowed": False,
        "commercial_blockers": [
            "operator-attached-command-transcripts-required",
            "trusted-validation-package-manifest-diff-required",
            "independent-reviewer-signoff-required",
        ],
    }
    return {**contract_core, "contract_hash": stable_submission_qc_sha256(contract_core)}


def build_trusted_tool_import_wizard_contract(*, attached_tool_count: int = 0) -> dict[str, object]:
    contract_core = {
        "profile_version": "trusted-tool-import-wizard-contract-v1",
        "qc_prep_item_number": 70,
        "supported_tool_families": TRUSTED_TOOL_IMPORT_FAMILIES,
        "attached_tool_count": int(attached_tool_count),
        "required_wizard_steps": [
            "select tool family",
            "attach export file",
            "capture tool version",
            "capture command line",
            "map artifact family",
            "run row-level diff",
            "review mismatch dashboard",
            "save validation package reference",
        ],
        "required_normalized_outputs": [
            "tool_name",
            "tool_version",
            "tool_command",
            "reference_output_sha256",
            "mapped_backlog_items",
            "diff_manifest_hash",
        ],
        "commercial_claim_allowed": False,
        "commercial_blockers": [
            "gui-import-wizard-e2e-required",
            "trusted-tool-output-schema-fixtures-required",
            "mismatch-dashboard-review-required",
        ],
    }
    return {**contract_core, "contract_hash": stable_submission_qc_sha256(contract_core)}


def build_submission_qc_contract(
    *,
    court_exhibit_package: Mapping[str, object] | None = None,
    custody_workflow: Mapping[str, object] | None = None,
    acquisition_metadata: Mapping[str, object] | None = None,
    audit_integrity: Mapping[str, object] | None = None,
    report_generation_package: Mapping[str, object] | None = None,
    items: Sequence[Mapping[str, object]] = (),
    attached_tool_count: int = 0,
) -> dict[str, object]:
    contracts = [
        build_court_exhibit_bundle_contract(court_exhibit_package=court_exhibit_package),
        build_custody_acquisition_contract(
            custody_workflow=custody_workflow,
            acquisition_metadata=acquisition_metadata,
        ),
        build_tamper_evident_audit_contract(audit_integrity=audit_integrity),
        build_run_validation_package_contract(
            report_generation_package=report_generation_package,
            items=items,
        ),
        build_trusted_tool_import_wizard_contract(attached_tool_count=attached_tool_count),
    ]
    contract_core: dict[str, object] = {
        "profile_version": "submission-qc-contract-v1",
        "qc_prep_item_numbers": [66, 67, 68, 69, 70],
        "court_exhibit_bundle_contract": contracts[0],
        "custody_acquisition_contract": contracts[1],
        "tamper_evident_audit_contract": contracts[2],
        "run_validation_package_contract": contracts[3],
        "trusted_tool_import_wizard_contract": contracts[4],
        "commercial_claim_allowed": False,
        "commercial_blockers": sorted(
            {blocker for contract in contracts for blocker in contract.get("commercial_blockers", [])}
        ),
    }
    return {**contract_core, "contract_hash": stable_submission_qc_sha256(contract_core)}
