from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Mapping

from .forensic_accuracy import build_accuracy_gate

CRASH_REPORTING_GAP_ID = "#105"
LOCAL_ONLY_ENTERPRISE_GAP_ID = "#106"
LICENSE_ACTIVATION_GAP_ID = "#107"
RBAC_GAP_ID = "#108"
MULTI_USER_CASE_SERVER_GAP_ID = "#109"
COLLABORATION_AUDIT_TRAIL_GAP_ID = "#110"
LOCAL_ONLY_TRUSTED_DIFF_BLOCKER_106 = "trusted-local-only-deployment-policy-diff-missing"
LICENSE_TRUSTED_DIFF_BLOCKER_107 = "trusted-license-authority-diff-missing"
RBAC_TRUSTED_DIFF_BLOCKER_108 = "trusted-rbac-enforcement-diff-missing"
MULTI_USER_TRUSTED_DIFF_BLOCKER_109 = "trusted-multi-user-server-review-diff-missing"
COLLABORATION_AUDIT_TRUSTED_DIFF_BLOCKER_110 = "trusted-collaboration-audit-diff-missing"
ENTERPRISE_TRUSTED_TOOLS = {
    "local-only-deployment-policy",
    "license-authority-review",
    "rbac-enforcement-test",
    "multi-user-server-security-review",
    "collaboration-audit-review",
}
SECURITY_HARDENING_REVIEW_GAP_ID = "#118"
MALICIOUS_EVIDENCE_SANDBOXING_GAP_ID = "#119"
SECURITY_HARDENING_TRUSTED_DIFF_BLOCKER_118 = "trusted-security-hardening-review-diff-missing"
MALICIOUS_SANDBOX_TRUSTED_DIFF_BLOCKER_119 = "trusted-malicious-evidence-sandbox-diff-missing"
SECURITY_OPERATIONS_TRUSTED_TOOLS = {
    "independent-appsec-review",
    "malicious-evidence-sandbox-corpus",
}
FUNCTIONAL_OPS_BATCH_ID = "commercial-uplift-061-065"


def build_enterprise_policy() -> dict[str, object]:
    auth_required = bool(os.environ.get("RAPIDTRIAGE_AUTH_TOKEN"))
    configured_role = os.environ.get("RAPIDTRIAGE_USER_ROLE") or "local-analyst"
    license_file = os.environ.get("RAPIDTRIAGE_LICENSE_FILE") or ""
    license_record = build_license_record(license_file)
    roles = {
        "local-analyst": ["read_case", "run_scan", "review", "export_report", "export_evidence_metadata"],
        "viewer": ["read_case", "export_report"],
        "admin": ["read_case", "run_scan", "review", "export_report", "export_evidence_metadata", "configure", "backup_restore"],
    }
    active_permissions = roles.get(configured_role, roles["local-analyst"])
    policy = {
        "command": "enterprise-policy",
        "policy_version": "enterprise-policy-v2",
        "commercial_gap_ids": [
            CRASH_REPORTING_GAP_ID,
            LOCAL_ONLY_ENTERPRISE_GAP_ID,
            LICENSE_ACTIVATION_GAP_ID,
            RBAC_GAP_ID,
            MULTI_USER_CASE_SERVER_GAP_ID,
            COLLABORATION_AUDIT_TRAIL_GAP_ID,
            SECURITY_HARDENING_REVIEW_GAP_ID,
            MALICIOUS_EVIDENCE_SANDBOXING_GAP_ID,
        ],
        "telemetry": {
            "commercial_gap_ids": [LOCAL_ONLY_ENTERPRISE_GAP_ID],
            "core_accuracy_gates": telemetry_core_accuracy_gates(trusted_diff=missing_enterprise_trusted_diff(106)),
            "functional_priority_profile": local_only_enterprise_functional_profile(auth_required=auth_required),
            "enabled": False,
            "default": "local-only",
            "evidence_uploads": False,
            "crash_uploads": False,
            "trusted_local_only_diff": missing_enterprise_trusted_diff(106),
            "blockers": [LOCAL_ONLY_TRUSTED_DIFF_BLOCKER_106],
        },
        "crash_reporting": {
            "commercial_gap_ids": [CRASH_REPORTING_GAP_ID],
            "core_accuracy_gates": crash_reporting_policy_core_accuracy_gates(),
            "status": "local-redacted-files-only",
            "uploads_enabled": False,
            "operator_upload_required": True,
        },
        "network": {
            "commercial_gap_ids": [LOCAL_ONLY_ENTERPRISE_GAP_ID, SECURITY_HARDENING_REVIEW_GAP_ID],
            "default_bind": "127.0.0.1",
            "remote_requires_auth_token": True,
            "auth_token_configured": auth_required,
            "trusted_local_only_diff": missing_enterprise_trusted_diff(106),
            "blockers": [LOCAL_ONLY_TRUSTED_DIFF_BLOCKER_106],
        },
        "license_activation": {
            "commercial_gap_ids": [LICENSE_ACTIVATION_GAP_ID],
            "core_accuracy_gates": license_activation_core_accuracy_gates(
                license_record,
                trusted_diff=missing_enterprise_trusted_diff(107),
            ),
            "required": False,
            "mode": "offline-not-enforced",
            "license_file": license_record.get("path", ""),
            "status": license_record.get("status", "not-required"),
            "license_sha256": license_record.get("sha256", ""),
            "license_size_bytes": license_record.get("size_bytes", 0),
            "validation": license_record.get("validation", "not-required"),
            "evidence_touch": False,
            "network_activation": False,
            "trusted_license_diff": missing_enterprise_trusted_diff(107),
            "blockers": [LICENSE_TRUSTED_DIFF_BLOCKER_107],
            "notes": [
                "No license check reads evidence content.",
                "Offline license files are operator-managed and not enforced by the local-first community build.",
            ],
        },
        "rbac": {
            "commercial_gap_ids": [RBAC_GAP_ID],
            "core_accuracy_gates": rbac_core_accuracy_gates(
                configured_role,
                active_permissions,
                trusted_diff=missing_enterprise_trusted_diff(108),
            ),
            "status": "single-user-local-policy-documented",
            "active_role": configured_role,
            "active_role_supported": configured_role in roles,
            "active_permissions": active_permissions,
            "roles": roles,
            "permission_matrix": build_permission_matrix(roles),
            "export_controls": {
                "viewer_can_export_evidence_metadata": False,
                "viewer_can_export_reports": True,
                "admin_required_for_backup_restore": True,
            },
            "enforcement_scope": "documented local policy; API token gates remote access, per-action RBAC enforcement remains future multi-user work",
            "trusted_rbac_diff": missing_enterprise_trusted_diff(108),
            "blockers": [RBAC_TRUSTED_DIFF_BLOCKER_108],
        },
        "multi_user_case_server": {
            "commercial_gap_ids": [MULTI_USER_CASE_SERVER_GAP_ID],
            "core_accuracy_gates": multi_user_case_server_core_accuracy_gates(
                trusted_diff=missing_enterprise_trusted_diff(109),
            ),
            "enabled": False,
            "status": "not-enabled",
            "reason": "RapidTriage remains local-first; shared case server requires auth, locking, migrations, and security review.",
            "guardrails": [
                "Do not expose the local web server to untrusted networks without RAPIDTRIAGE_AUTH_TOKEN.",
                "Do not claim shared review locking until database-level conflict handling exists.",
                "Use exported reviewer bundles for collaboration until a dedicated case server is built.",
            ],
            "required_before_enablement": [
                "identity provider integration",
                "per-action RBAC enforcement",
                "case locking/conflict resolution",
                "append-only audit storage",
                "database migration/concurrency tests",
                "independent security review",
            ],
            "trusted_multi_user_diff": missing_enterprise_trusted_diff(109),
            "blockers": [MULTI_USER_TRUSTED_DIFF_BLOCKER_109],
        },
        "collaboration_audit_trail": {
            "commercial_gap_ids": [COLLABORATION_AUDIT_TRAIL_GAP_ID],
            "core_accuracy_gates": collaboration_audit_core_accuracy_gates(
                trusted_diff=missing_enterprise_trusted_diff(110),
            ),
            "status": "case-db-audit-events-with-export-hash-chain",
            "scope": "review/search/import/export actions are recorded in Case DB audit_event rows when using Case DB workflows",
            "recorded_fields": ["actor", "action", "target_type", "target_id", "timestamp", "tool_name", "params_json", "result", "error"],
            "tamper_evidence": "Case DB report exports and reviewer bundles include export-time audit hash chains.",
            "identity_model": "single local actor or caller-supplied reviewer until multi-user identity is implemented",
            "multi_user_conflict_handling": "not-enabled",
            "trusted_collaboration_audit_diff": missing_enterprise_trusted_diff(110),
            "blockers": [COLLABORATION_AUDIT_TRUSTED_DIFF_BLOCKER_110],
        },
        "security_hardening": {
            "commercial_gap_ids": [SECURITY_HARDENING_REVIEW_GAP_ID, MALICIOUS_EVIDENCE_SANDBOXING_GAP_ID],
            "core_accuracy_gates": [
                *security_hardening_core_accuracy_gates(trusted_diff=missing_security_operations_trusted_diff(118)),
                *malicious_evidence_sandbox_core_accuracy_gates(
                    trusted_diff=missing_security_operations_trusted_diff(119),
                ),
            ],
            "functional_priority_profile": security_hardening_functional_profile(),
            "status": "documented-local-baseline",
            "preview_sandboxing": "read-only bounded previews with active-content blocking metadata",
            "parser_sandboxing": "parser crash isolation exists; OS-level parser sandbox remains external hardening work",
            "independent_review_required": True,
            "trusted_security_hardening_diff": missing_security_operations_trusted_diff(118),
            "trusted_malicious_sandbox_diff": missing_security_operations_trusted_diff(119),
            "blockers": [SECURITY_HARDENING_TRUSTED_DIFF_BLOCKER_118, MALICIOUS_SANDBOX_TRUSTED_DIFF_BLOCKER_119],
        },
    }
    attach_enterprise_control_manifest(
        policy["telemetry"],
        item_number=106,
        profile_version="local-only-enterprise-evidence-manifest-v1",
        manifest_key="local_only_evidence_manifest",
        hash_key="local_only_evidence_manifest_hash",
        slots_key="local_only_evidence_slots",
        trusted_diff=policy["telemetry"]["trusted_local_only_diff"],
        evidence_slots={
            "network_egress_smoke": "Network egress smoke proving no telemetry/evidence/crash upload paths are active",
            "remote_bind_auth_smoke": "Remote bind smoke proving RAPIDTRIAGE_AUTH_TOKEN is required outside localhost",
            "enterprise_policy_review": "Trusted deployment policy review for local-only enterprise mode",
        },
    )
    policy["telemetry"]["core_accuracy_gates"] = telemetry_core_accuracy_gates(
        trusted_diff=policy["telemetry"]["trusted_local_only_diff"],
        evidence_manifest=policy["telemetry"]["local_only_evidence_manifest"],
    )
    policy["telemetry"]["local_only_deployment_manifest"] = build_local_only_deployment_manifest(policy)
    policy["telemetry"]["local_only_deployment_manifest_hash"] = policy["telemetry"][
        "local_only_deployment_manifest"
    ]["manifest_hash"]
    policy["telemetry"]["functional_priority_profile"] = local_only_enterprise_functional_profile(
        auth_required=auth_required,
        deployment_manifest=policy["telemetry"]["local_only_deployment_manifest"],
    )
    policy["telemetry"]["core_accuracy_gates"] = telemetry_core_accuracy_gates(
        trusted_diff=policy["telemetry"]["trusted_local_only_diff"],
        evidence_manifest=policy["telemetry"]["local_only_evidence_manifest"],
        deployment_manifest=policy["telemetry"]["local_only_deployment_manifest"],
    )
    attach_enterprise_control_manifest(
        policy["license_activation"],
        item_number=107,
        profile_version="license-activation-evidence-manifest-v1",
        manifest_key="license_evidence_manifest",
        hash_key="license_evidence_manifest_hash",
        slots_key="license_evidence_slots",
        trusted_diff=policy["license_activation"]["trusted_license_diff"],
        evidence_slots={
            "license_authority_review": "Trusted license authority review if activation is enabled",
            "offline_activation_smoke": "Offline license activation smoke proving no evidence content is read",
            "paid_flow_review": "Optional paid activation flow review before commercial licensing claims",
        },
    )
    policy["license_activation"]["core_accuracy_gates"] = license_activation_core_accuracy_gates(
        license_record,
        trusted_diff=policy["license_activation"]["trusted_license_diff"],
        evidence_manifest=policy["license_activation"]["license_evidence_manifest"],
    )
    attach_enterprise_control_manifest(
        policy["rbac"],
        item_number=108,
        profile_version="rbac-enforcement-evidence-manifest-v1",
        manifest_key="rbac_evidence_manifest",
        hash_key="rbac_evidence_manifest_hash",
        slots_key="rbac_evidence_slots",
        trusted_diff=policy["rbac"]["trusted_rbac_diff"],
        evidence_slots={
            "per_action_enforcement_test": "Per-action RBAC enforcement test log for run, review, export, admin actions",
            "export_control_review": "Trusted export-control review for viewer/analyst/admin roles",
            "role_matrix_signoff": "Operator role matrix signoff before commercial RBAC claims",
        },
    )
    policy["rbac"]["core_accuracy_gates"] = rbac_core_accuracy_gates(
        configured_role,
        active_permissions,
        trusted_diff=policy["rbac"]["trusted_rbac_diff"],
        evidence_manifest=policy["rbac"]["rbac_evidence_manifest"],
    )
    attach_enterprise_control_manifest(
        policy["multi_user_case_server"],
        item_number=109,
        profile_version="multi-user-server-evidence-manifest-v1",
        manifest_key="multi_user_evidence_manifest",
        hash_key="multi_user_evidence_manifest_hash",
        slots_key="multi_user_evidence_slots",
        trusted_diff=policy["multi_user_case_server"]["trusted_multi_user_diff"],
        evidence_slots={
            "architecture_security_review": "Independent multi-user architecture and security review",
            "locking_conflict_test": "Case locking/conflict/concurrency test log",
            "identity_provider_smoke": "Identity provider integration and auth session smoke log",
        },
    )
    policy["multi_user_case_server"]["core_accuracy_gates"] = multi_user_case_server_core_accuracy_gates(
        trusted_diff=policy["multi_user_case_server"]["trusted_multi_user_diff"],
        evidence_manifest=policy["multi_user_case_server"]["multi_user_evidence_manifest"],
    )
    attach_enterprise_control_manifest(
        policy["collaboration_audit_trail"],
        item_number=110,
        profile_version="collaboration-audit-evidence-manifest-v1",
        manifest_key="collaboration_audit_evidence_manifest",
        hash_key="collaboration_audit_evidence_manifest_hash",
        slots_key="collaboration_audit_evidence_slots",
        trusted_diff=policy["collaboration_audit_trail"]["trusted_collaboration_audit_diff"],
        evidence_slots={
            "audit_append_only_review": "Trusted append-only audit review and tamper-evidence verification",
            "identity_attribution_review": "Reviewer identity attribution and conflict-handling review",
            "collaboration_conflict_test": "Multi-user collaboration conflict test log",
        },
    )
    policy["collaboration_audit_trail"]["core_accuracy_gates"] = collaboration_audit_core_accuracy_gates(
        trusted_diff=policy["collaboration_audit_trail"]["trusted_collaboration_audit_diff"],
        evidence_manifest=policy["collaboration_audit_trail"]["collaboration_audit_evidence_manifest"],
    )
    attach_enterprise_control_manifest(
        policy["security_hardening"],
        item_number=118,
        profile_version="security-hardening-evidence-manifest-v1",
        manifest_key="security_hardening_evidence_manifest",
        hash_key="security_hardening_evidence_manifest_hash",
        slots_key="security_hardening_evidence_slots",
        trusted_diff=policy["security_hardening"]["trusted_security_hardening_diff"],
        evidence_slots={
            "independent_appsec_review": "Independent AppSec review covering auth, paths, export rendering, crash redaction, and parser safety",
            "threat_model_review": "Threat model and abuse-path review for local and remote deployment",
        },
    )
    policy["security_hardening"]["security_hardening_baseline_manifest"] = build_security_hardening_baseline_manifest(
        policy["security_hardening"],
    )
    policy["security_hardening"]["security_hardening_baseline_manifest_hash"] = policy["security_hardening"][
        "security_hardening_baseline_manifest"
    ]["manifest_hash"]
    policy["security_hardening"]["functional_priority_profile"] = security_hardening_functional_profile(
        baseline_manifest=policy["security_hardening"]["security_hardening_baseline_manifest"],
    )
    attach_enterprise_control_manifest(
        policy["security_hardening"],
        item_number=119,
        profile_version="malicious-evidence-sandbox-evidence-manifest-v1",
        manifest_key="malicious_sandbox_evidence_manifest",
        hash_key="malicious_sandbox_evidence_manifest_hash",
        slots_key="malicious_sandbox_evidence_slots",
        trusted_diff=policy["security_hardening"]["trusted_malicious_sandbox_diff"],
        evidence_slots={
            "malicious_corpus_validation": "Trusted malicious corpus validation for parser crash isolation and preview safety",
            "os_sandbox_proof": "OS-level parser and preview sandbox proof",
        },
    )
    policy["security_hardening"]["core_accuracy_gates"] = [
        *security_hardening_core_accuracy_gates(
            trusted_diff=policy["security_hardening"]["trusted_security_hardening_diff"],
            evidence_manifest=policy["security_hardening"]["security_hardening_evidence_manifest"],
            baseline_manifest=policy["security_hardening"]["security_hardening_baseline_manifest"],
        ),
        *malicious_evidence_sandbox_core_accuracy_gates(
            trusted_diff=policy["security_hardening"]["trusted_malicious_sandbox_diff"],
            evidence_manifest=policy["security_hardening"]["malicious_sandbox_evidence_manifest"],
        ),
    ]
    return policy


def build_license_record(raw_path: str) -> dict[str, object]:
    if not raw_path:
        return {"status": "not-required", "validation": "not-run"}
    path = Path(raw_path).expanduser().resolve()
    if not path.is_file():
        return {"path": str(path), "status": "operator-provided-file-missing", "validation": "missing"}
    try:
        data = path.read_bytes()
    except OSError:
        return {"path": str(path), "status": "operator-provided-file-unreadable", "validation": "unreadable"}
    return {
        "path": str(path),
        "status": "operator-provided-file",
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
        "validation": "hash-recorded-no-network-activation",
    }


def build_permission_matrix(roles: dict[str, list[str]]) -> list[dict[str, object]]:
    permissions = sorted({permission for values in roles.values() for permission in values})
    return [
        {
            "permission": permission,
            "roles": [role for role, values in sorted(roles.items()) if permission in values],
        }
        for permission in permissions
    ]


def stable_enterprise_sha256(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def attach_enterprise_control_manifest(
    section: dict[str, object],
    *,
    item_number: int,
    profile_version: str,
    manifest_key: str,
    hash_key: str,
    slots_key: str,
    trusted_diff: Mapping[str, object],
    evidence_slots: Mapping[str, str],
) -> None:
    slots = {
        slot: {
            "status": "not-attached",
            "expected_material": description,
            "required_before_commercial_claim": True,
        }
        for slot, description in evidence_slots.items()
    }
    control_evidence_matrix = build_enterprise_control_evidence_matrix(
        item_number=item_number,
        section=section,
        slots=slots,
    )
    manifest: dict[str, object] = {
        "profile_version": profile_version,
        "item_number": item_number,
        "commercial_gap_ids": [f"#{item_number}"],
        "commercial_claim_allowed": False,
        "section_status": section.get("status", section.get("default", "")),
        "implemented_control_hash": stable_enterprise_sha256(section.get("implemented_controls", {})),
        "policy_snapshot_hash": stable_enterprise_sha256(
            {
                key: value
                for key, value in section.items()
                if key not in {"core_accuracy_gates", manifest_key, hash_key, slots_key}
            }
        ),
        slots_key: slots,
        "control_evidence_matrix": control_evidence_matrix,
        "control_evidence_matrix_hash": control_evidence_matrix["matrix_hash"],
        "trusted_diff_status": trusted_diff.get("status"),
        "trusted_diff_blocker": trusted_diff.get("blocker"),
        "blockers": section.get("blockers", []),
    }
    manifest["manifest_hash"] = stable_enterprise_sha256(manifest)
    section[manifest_key] = manifest
    section[hash_key] = manifest["manifest_hash"]
    section[slots_key] = slots
    section["control_evidence_matrix_hash"] = manifest["control_evidence_matrix_hash"]


def build_enterprise_control_evidence_matrix(
    *,
    item_number: int,
    section: Mapping[str, object],
    slots: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    rows = []
    for slot_name, slot in sorted(slots.items()):
        row_core = {
            "slot": slot_name,
            "status": slot.get("status", ""),
            "attached": slot.get("status") not in {"not-attached", "missing", ""},
            "required_before_commercial_claim": bool(slot.get("required_before_commercial_claim")),
            "expected_material_hash": stable_enterprise_sha256(slot.get("expected_material", "")),
        }
        rows.append({**row_core, "row_hash": stable_enterprise_sha256(row_core)})
    matrix: dict[str, object] = {
        "profile_version": "enterprise-control-evidence-matrix-v1",
        "item_number": item_number,
        "section_status": section.get("status", section.get("default", "")),
        "section_snapshot_hash": stable_enterprise_sha256(
            {
                key: value
                for key, value in section.items()
                if key
                not in {
                    "core_accuracy_gates",
                    "functional_priority_profile",
                    "trusted_local_only_diff",
                    "trusted_license_diff",
                    "trusted_rbac_diff",
                    "trusted_multi_user_diff",
                    "trusted_collaboration_audit_diff",
                }
            }
        ),
        "slot_count": len(rows),
        "required_slot_count": sum(1 for row in rows if row["required_before_commercial_claim"]),
        "attached_slot_count": sum(1 for row in rows if row["attached"]),
        "missing_required_slot_count": sum(
            1 for row in rows if row["required_before_commercial_claim"] and not row["attached"]
        ),
        "rows": rows,
        "commercial_claim_allowed": False,
    }
    matrix["matrix_hash"] = stable_enterprise_sha256(matrix)
    return matrix


def build_local_only_deployment_manifest(policy: Mapping[str, object]) -> dict[str, object]:
    telemetry = policy.get("telemetry") if isinstance(policy.get("telemetry"), Mapping) else {}
    network = policy.get("network") if isinstance(policy.get("network"), Mapping) else {}
    crash_reporting = policy.get("crash_reporting") if isinstance(policy.get("crash_reporting"), Mapping) else {}
    upload_surfaces = [
        {
            "surface": "telemetry",
            "enabled": bool(telemetry.get("enabled")),
            "uploads_enabled": False,
            "egress_endpoint": "",
            "policy_field": "enterprise_policy.telemetry.enabled",
        },
        {
            "surface": "evidence_uploads",
            "enabled": bool(telemetry.get("evidence_uploads")),
            "uploads_enabled": bool(telemetry.get("evidence_uploads")),
            "egress_endpoint": "",
            "policy_field": "enterprise_policy.telemetry.evidence_uploads",
        },
        {
            "surface": "crash_uploads",
            "enabled": bool(telemetry.get("crash_uploads") or crash_reporting.get("uploads_enabled")),
            "uploads_enabled": bool(telemetry.get("crash_uploads") or crash_reporting.get("uploads_enabled")),
            "egress_endpoint": "",
            "policy_field": "enterprise_policy.telemetry.crash_uploads",
        },
    ]
    manifest: dict[str, object] = {
        "profile_version": "local-only-deployment-manifest-v1",
        "item_number": 61,
        "commercial_gap_ids": [LOCAL_ONLY_ENTERPRISE_GAP_ID],
        "commercial_claim_allowed": False,
        "policy_version": policy.get("policy_version", ""),
        "local_only_default": telemetry.get("default") == "local-only",
        "upload_surfaces": upload_surfaces,
        "upload_surface_count": len(upload_surfaces),
        "enabled_upload_surface_count": sum(1 for surface in upload_surfaces if surface["uploads_enabled"]),
        "known_outbound_endpoint_count": 0,
        "known_outbound_endpoints": [],
        "network_boundary": {
            "default_bind": network.get("default_bind", ""),
            "localhost_default": network.get("default_bind") in {"127.0.0.1", "localhost", "::1"},
            "remote_requires_auth_token": bool(network.get("remote_requires_auth_token")),
            "auth_token_configured": bool(network.get("auth_token_configured")),
        },
        "crash_boundary": {
            "status": crash_reporting.get("status", ""),
            "uploads_enabled": bool(crash_reporting.get("uploads_enabled")),
            "operator_upload_required": bool(crash_reporting.get("operator_upload_required")),
        },
        "verification_commands": [
            "rapidtriage enterprise-policy --json",
            "RAPIDTRIAGE_AUTH_TOKEN=token rapidtriage web --host 0.0.0.0 --dry-run-auth-check",
            "network egress smoke with packet/log capture showing no telemetry/evidence/crash upload",
        ],
        "evidence_slots": {
            "network_egress_smoke": "External packet/log capture proving no telemetry/evidence/crash upload endpoints are contacted",
            "remote_bind_auth_smoke": "Remote-bind smoke proving non-local access requires RAPIDTRIAGE_AUTH_TOKEN",
            "deployment_policy_signoff": "Enterprise deployment policy review for local-only operation",
        },
        "commercial_blockers": [
            "network-egress-test-not-attached",
            "remote-bind-auth-smoke-not-attached",
            "trusted-local-only-deployment-policy-diff-required",
        ],
        "validation_status": "implemented-usable-external-egress-smoke-required",
    }
    manifest["manifest_hash"] = stable_enterprise_sha256(manifest)
    return manifest


def local_only_enterprise_functional_profile(
    *,
    auth_required: bool,
    deployment_manifest: Mapping[str, object] | None = None,
) -> dict[str, object]:
    deployment_manifest = deployment_manifest or {}
    return {
        "batch_id": FUNCTIONAL_OPS_BATCH_ID,
        "item_number": 61,
        "implementation_track": "local-only-enterprise-policy",
        "status": "usable-local-policy-external-review-required",
        "implemented_controls": {
            "telemetry_disabled": True,
            "evidence_uploads_disabled": True,
            "crash_uploads_disabled": True,
            "localhost_default_bind": True,
            "remote_bind_requires_auth_token": True,
            "auth_token_configured": auth_required,
            "upload_surface_inventory_emitted": bool(deployment_manifest.get("upload_surfaces")),
            "local_only_deployment_manifest_hash": str(deployment_manifest.get("manifest_hash") or ""),
            "hidden_upload_paths_known": False,
        },
        "passed_validation_check_ids": [
            check
            for check, passed in {
                "local-only-deployment-manifest-emitted": bool(deployment_manifest.get("manifest_hash")),
                "upload-surface-inventory-emitted": bool(deployment_manifest.get("upload_surfaces")),
                "known-outbound-endpoint-inventory-empty": deployment_manifest.get("known_outbound_endpoint_count") == 0,
                "remote-bind-auth-boundary-declared": bool(
                    deployment_manifest.get("network_boundary", {}).get("remote_requires_auth_token")
                    if isinstance(deployment_manifest.get("network_boundary"), Mapping)
                    else False
                ),
            }.items()
            if passed
        ],
        "failed_validation_check_ids": [
            "trusted-local-only-deployment-policy-diff-required",
            "network-egress-test-not-attached",
            "remote-bind-auth-smoke-not-attached",
        ],
        "ready_for_commercial_release": False,
    }


def build_security_hardening_baseline_manifest(section: Mapping[str, object]) -> dict[str, object]:
    controls = [
        {
            "control": "path_traversal_guardrails",
            "status": "documented",
            "scope": "file preview, export, archive handling, case paths",
            "external_validation_required": "path/archive traversal fuzz suite",
        },
        {
            "control": "archive_extraction_safety",
            "status": "documented",
            "scope": "bounded extraction and explicit output paths",
            "external_validation_required": "malicious archive corpus",
        },
        {
            "control": "report_html_escaping",
            "status": "documented",
            "scope": "report and viewer rendering",
            "external_validation_required": "HTML/script injection regression corpus",
        },
        {
            "control": "active_content_preview_blocking",
            "status": "partially-implemented",
            "scope": "source preview metadata and no-exec renderer guidance",
            "external_validation_required": "malicious evidence preview corpus",
        },
        {
            "control": "remote_auth_token_guard",
            "status": "implemented-baseline",
            "scope": "non-local web/API exposure",
            "external_validation_required": "remote bind auth smoke",
        },
        {
            "control": "crash_redaction",
            "status": "documented-local",
            "scope": "local crash files and operator export",
            "external_validation_required": "redaction fixture corpus",
        },
        {
            "control": "parser_crash_isolation",
            "status": "partial",
            "scope": "crash isolation metadata; OS sandbox remains missing",
            "external_validation_required": "hostile parser corpus and OS sandbox proof",
        },
    ]
    manifest: dict[str, object] = {
        "profile_version": "security-hardening-baseline-manifest-v1",
        "item_number": 63,
        "commercial_gap_ids": [SECURITY_HARDENING_REVIEW_GAP_ID, MALICIOUS_EVIDENCE_SANDBOXING_GAP_ID],
        "section_status": section.get("status", ""),
        "control_count": len(controls),
        "controls": controls,
        "preview_sandboxing": section.get("preview_sandboxing", ""),
        "parser_sandboxing": section.get("parser_sandboxing", ""),
        "independent_review_required": bool(section.get("independent_review_required")),
        "commercial_blockers": [
            "independent-appsec-review-not-attached",
            "malicious-evidence-sandbox-corpus-not-attached",
            "os-level-parser-sandbox-not-implemented",
            "full-path-archive-export-fuzz-suite-not-attached",
        ],
        "validation_status": "implemented-baseline-external-appsec-required",
    }
    manifest["manifest_hash"] = stable_enterprise_sha256(manifest)
    return manifest


def security_hardening_functional_profile(
    baseline_manifest: Mapping[str, object] | None = None,
) -> dict[str, object]:
    baseline_manifest = baseline_manifest or {}
    return {
        "batch_id": FUNCTIONAL_OPS_BATCH_ID,
        "item_number": 63,
        "implementation_track": "security-hardening",
        "status": "documented-and-partially-tested-independent-appsec-required",
        "implemented_controls": {
            "path_traversal_guardrails_documented": True,
            "archive_extraction_safety_documented": True,
            "report_html_escaping_documented": True,
            "active_content_preview_blocking_documented": True,
            "auth_token_remote_access_required": True,
            "crash_redaction_documented": True,
            "parser_crash_isolation_documented": True,
            "security_hardening_baseline_manifest_emitted": bool(baseline_manifest.get("manifest_hash")),
            "security_hardening_baseline_manifest_hash": str(baseline_manifest.get("manifest_hash") or ""),
            "os_level_parser_sandbox": False,
        },
        "passed_validation_check_ids": [
            check
            for check, passed in {
                "security-hardening-baseline-manifest-emitted": bool(baseline_manifest.get("manifest_hash")),
                "security-control-inventory-emitted": bool(baseline_manifest.get("controls")),
                "independent-review-required-recorded": bool(baseline_manifest.get("independent_review_required")),
            }.items()
            if passed
        ],
        "failed_validation_check_ids": [
            "independent-appsec-review-not-attached",
            "malicious-evidence-sandbox-corpus-not-attached",
            "os-level-parser-sandbox-not-implemented",
            "full-path-archive-export-fuzz-suite-not-attached",
        ],
        "ready_for_commercial_release": False,
    }


def missing_enterprise_trusted_diff(number: int) -> dict[str, object]:
    gap_ids = {
        106: LOCAL_ONLY_ENTERPRISE_GAP_ID,
        107: LICENSE_ACTIVATION_GAP_ID,
        108: RBAC_GAP_ID,
        109: MULTI_USER_CASE_SERVER_GAP_ID,
        110: COLLABORATION_AUDIT_TRAIL_GAP_ID,
    }
    blockers = {
        106: LOCAL_ONLY_TRUSTED_DIFF_BLOCKER_106,
        107: LICENSE_TRUSTED_DIFF_BLOCKER_107,
        108: RBAC_TRUSTED_DIFF_BLOCKER_108,
        109: MULTI_USER_TRUSTED_DIFF_BLOCKER_109,
        110: COLLABORATION_AUDIT_TRUSTED_DIFF_BLOCKER_110,
    }
    trusted_tools = {
        106: "local-only-deployment-policy",
        107: "license-authority-review",
        108: "rbac-enforcement-test",
        109: "multi-user-server-security-review",
        110: "collaboration-audit-review",
    }
    return {
        "status": "missing",
        "trusted_tool": None,
        "commercial_gap_ids": [gap_ids[number]],
        "blocker": blockers[number],
        "required_trusted_tool": trusted_tools[number],
    }


def build_enterprise_trusted_diff(
    number: int,
    rapid_payload: Mapping[str, object],
    trusted_payload: Mapping[str, object],
    *,
    trusted_tool: str,
) -> dict[str, object]:
    gap_ids = {
        106: LOCAL_ONLY_ENTERPRISE_GAP_ID,
        107: LICENSE_ACTIVATION_GAP_ID,
        108: RBAC_GAP_ID,
        109: MULTI_USER_CASE_SERVER_GAP_ID,
        110: COLLABORATION_AUDIT_TRAIL_GAP_ID,
    }
    blockers = {
        106: LOCAL_ONLY_TRUSTED_DIFF_BLOCKER_106,
        107: LICENSE_TRUSTED_DIFF_BLOCKER_107,
        108: RBAC_TRUSTED_DIFF_BLOCKER_108,
        109: MULTI_USER_TRUSTED_DIFF_BLOCKER_109,
        110: COLLABORATION_AUDIT_TRUSTED_DIFF_BLOCKER_110,
    }
    compared_fields = {
        106: ["enabled", "evidence_uploads", "crash_uploads", "default"],
        107: ["required", "status", "license_sha256", "evidence_touch", "network_activation"],
        108: ["active_role", "active_permissions", "permission_matrix", "export_controls"],
        109: ["enabled", "status", "guardrails", "required_before_enablement"],
        110: ["status", "recorded_fields", "tamper_evidence", "identity_model"],
    }[number]
    optional_manifest_fields = {
        106: [
            "local_only_evidence_manifest_hash",
            "local_only_evidence_slots",
            "local_only_deployment_manifest_hash",
            "control_evidence_matrix_hash",
        ],
        107: ["license_evidence_manifest_hash", "license_evidence_slots", "control_evidence_matrix_hash"],
        108: ["rbac_evidence_manifest_hash", "rbac_evidence_slots", "control_evidence_matrix_hash"],
        109: ["multi_user_evidence_manifest_hash", "multi_user_evidence_slots", "control_evidence_matrix_hash"],
        110: [
            "collaboration_audit_evidence_manifest_hash",
            "collaboration_audit_evidence_slots",
            "control_evidence_matrix_hash",
        ],
    }[number]
    compared_fields = list(compared_fields)
    for field in optional_manifest_fields:
        if field in rapid_payload or field in trusted_payload:
            compared_fields.append(field)
    mismatches = []
    for field in compared_fields:
        rapid_value = normalize_enterprise_trusted_value(rapid_payload.get(field))
        trusted_value = normalize_enterprise_trusted_value(trusted_payload.get(field))
        if rapid_value != trusted_value:
            mismatches.append({"field": field, "rapid": rapid_value, "trusted": trusted_value})
    status = "pass" if not mismatches and trusted_tool in ENTERPRISE_TRUSTED_TOOLS else "fail"
    return {
        "status": status,
        "trusted_tool": trusted_tool,
        "commercial_gap_ids": [gap_ids[number]],
        "compared_fields": compared_fields,
        "mismatches": mismatches,
        "blocker": None if status == "pass" else blockers[number],
    }


def normalize_enterprise_trusted_value(value: object) -> object:
    if isinstance(value, list):
        return sorted(json.dumps(item, ensure_ascii=False, sort_keys=True, default=str) for item in value)
    if isinstance(value, Mapping):
        return json.dumps(dict(value), ensure_ascii=False, sort_keys=True, default=str)
    return value


def crash_reporting_policy_core_accuracy_gates() -> list[dict[str, object]]:
    return [
        build_accuracy_gate(
            105,
            satisfied_checks=[
                "local crash report written",
                "sensitive context redacted",
                "runtime metadata captured",
                "no-upload policy recorded",
                "operator export limitation disclosed",
            ],
            evidence_refs=["enterprise_policy.crash_reporting"],
        )
    ]


def telemetry_core_accuracy_gates(
    trusted_diff: Mapping[str, object] | None = None,
    evidence_manifest: Mapping[str, object] | None = None,
    deployment_manifest: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = [
        "telemetry disabled recorded",
        "evidence/crash upload disabled recorded",
        "localhost default recorded",
        "remote auth token requirement recorded",
        "local-only limitation disclosed",
    ]
    if evidence_manifest:
        if evidence_manifest.get("manifest_hash"):
            satisfied.append("local-only evidence manifest hash emitted")
        if evidence_manifest.get("local_only_evidence_slots"):
            satisfied.append("local-only evidence slots emitted")
        if evidence_manifest.get("control_evidence_matrix_hash"):
            satisfied.append("local-only control evidence matrix hash emitted")
    if deployment_manifest:
        if deployment_manifest.get("manifest_hash"):
            satisfied.append("local-only deployment manifest hash emitted")
        if deployment_manifest.get("upload_surfaces"):
            satisfied.append("local-only upload surface inventory emitted")
        if deployment_manifest.get("known_outbound_endpoint_count") == 0:
            satisfied.append("known outbound endpoint inventory empty")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted local-only deployment policy diff pass")
    evidence_refs = ["enterprise_policy.telemetry", "enterprise_policy.network"]
    if deployment_manifest and deployment_manifest.get("manifest_hash"):
        evidence_refs.append(f"local_only_deployment_manifest_sha256:{deployment_manifest['manifest_hash']}")
    return [
        build_accuracy_gate(
            106,
            satisfied_checks=satisfied,
            evidence_refs=evidence_refs,
        )
    ]


def license_activation_core_accuracy_gates(
    license_record: dict[str, object],
    trusted_diff: Mapping[str, object] | None = None,
    evidence_manifest: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = [
        "license requirement state recorded",
        "network activation disabled recorded",
        "evidence-touch false recorded",
        "paid activation blocker disclosed",
    ]
    if license_record.get("sha256") or license_record.get("status") in {"not-required", "operator-provided-file-missing", "operator-provided-file-unreadable"}:
        satisfied.append("offline license hash captured when present")
    if evidence_manifest:
        if evidence_manifest.get("manifest_hash"):
            satisfied.append("license evidence manifest hash emitted")
        if evidence_manifest.get("license_evidence_slots"):
            satisfied.append("license evidence slots emitted")
        if evidence_manifest.get("control_evidence_matrix_hash"):
            satisfied.append("license control evidence matrix hash emitted")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted license authority diff pass")
    return [
        build_accuracy_gate(
            107,
            satisfied_checks=satisfied,
            evidence_refs=[f"license_status:{license_record.get('status', 'not-required')}"],
        )
    ]


def rbac_core_accuracy_gates(
    active_role: str,
    active_permissions: list[str],
    trusted_diff: Mapping[str, object] | None = None,
    evidence_manifest: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = [
        "role matrix emitted",
        "active role evaluated",
        "active permissions emitted",
        "export controls recorded",
        "per-action enforcement blocker disclosed",
    ]
    if evidence_manifest:
        if evidence_manifest.get("manifest_hash"):
            satisfied.append("rbac evidence manifest hash emitted")
        if evidence_manifest.get("rbac_evidence_slots"):
            satisfied.append("rbac evidence slots emitted")
        if evidence_manifest.get("control_evidence_matrix_hash"):
            satisfied.append("rbac control evidence matrix hash emitted")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted RBAC enforcement diff pass")
    return [
        build_accuracy_gate(
            108,
            satisfied_checks=satisfied,
            evidence_refs=[f"active_role:{active_role}", f"permission_count:{len(active_permissions)}"],
        )
    ]


def multi_user_case_server_core_accuracy_gates(
    trusted_diff: Mapping[str, object] | None = None,
    evidence_manifest: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = [
        "multi-user disabled state recorded",
        "network guardrails emitted",
        "identity provider requirement recorded",
        "locking/conflict requirement recorded",
        "security review blocker disclosed",
    ]
    if evidence_manifest:
        if evidence_manifest.get("manifest_hash"):
            satisfied.append("multi-user evidence manifest hash emitted")
        if evidence_manifest.get("multi_user_evidence_slots"):
            satisfied.append("multi-user evidence slots emitted")
        if evidence_manifest.get("control_evidence_matrix_hash"):
            satisfied.append("multi-user control evidence matrix hash emitted")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted multi-user server review diff pass")
    return [
        build_accuracy_gate(
            109,
            satisfied_checks=satisfied,
            evidence_refs=["enterprise_policy.multi_user_case_server"],
        )
    ]


def collaboration_audit_core_accuracy_gates(
    trusted_diff: Mapping[str, object] | None = None,
    evidence_manifest: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = [
        "audit trail scope recorded",
        "recorded fields listed",
        "tamper evidence linkage recorded",
        "identity model caveat recorded",
        "multi-user conflict blocker disclosed",
    ]
    if evidence_manifest:
        if evidence_manifest.get("manifest_hash"):
            satisfied.append("collaboration audit evidence manifest hash emitted")
        if evidence_manifest.get("collaboration_audit_evidence_slots"):
            satisfied.append("collaboration audit evidence slots emitted")
        if evidence_manifest.get("control_evidence_matrix_hash"):
            satisfied.append("collaboration audit control evidence matrix hash emitted")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted collaboration audit diff pass")
    return [
        build_accuracy_gate(
            110,
            satisfied_checks=satisfied,
            evidence_refs=["enterprise_policy.collaboration_audit_trail"],
        )
    ]


def missing_security_operations_trusted_diff(number: int) -> dict[str, object]:
    gap_ids = {
        118: SECURITY_HARDENING_REVIEW_GAP_ID,
        119: MALICIOUS_EVIDENCE_SANDBOXING_GAP_ID,
    }
    blockers = {
        118: SECURITY_HARDENING_TRUSTED_DIFF_BLOCKER_118,
        119: MALICIOUS_SANDBOX_TRUSTED_DIFF_BLOCKER_119,
    }
    trusted_tools = {
        118: "independent-appsec-review",
        119: "malicious-evidence-sandbox-corpus",
    }
    return {
        "status": "missing",
        "trusted_tool": None,
        "commercial_gap_ids": [gap_ids[number]],
        "blocker": blockers[number],
        "required_trusted_tool": trusted_tools[number],
    }


def build_security_operations_trusted_diff(
    number: int,
    rapid_payload: Mapping[str, object],
    trusted_payload: Mapping[str, object],
    *,
    trusted_tool: str,
) -> dict[str, object]:
    gap_ids = {
        118: SECURITY_HARDENING_REVIEW_GAP_ID,
        119: MALICIOUS_EVIDENCE_SANDBOXING_GAP_ID,
    }
    blockers = {
        118: SECURITY_HARDENING_TRUSTED_DIFF_BLOCKER_118,
        119: MALICIOUS_SANDBOX_TRUSTED_DIFF_BLOCKER_119,
    }
    compared_fields = ["status", "preview_sandboxing", "parser_sandboxing", "independent_review_required"]
    optional_fields = {
        118: [
            "security_hardening_evidence_manifest_hash",
            "security_hardening_evidence_slots",
            "security_hardening_baseline_manifest_hash",
            "control_evidence_matrix_hash",
        ],
        119: ["malicious_sandbox_evidence_manifest_hash", "malicious_sandbox_evidence_slots", "control_evidence_matrix_hash"],
    }[number]
    compared_fields = list(compared_fields)
    for field in optional_fields:
        if field in rapid_payload or field in trusted_payload:
            compared_fields.append(field)
    mismatches = []
    for field in compared_fields:
        rapid_value = normalize_enterprise_trusted_value(rapid_payload.get(field))
        trusted_value = normalize_enterprise_trusted_value(trusted_payload.get(field))
        if rapid_value != trusted_value:
            mismatches.append({"field": field, "rapid": rapid_value, "trusted": trusted_value})
    status = "pass" if not mismatches and trusted_tool in SECURITY_OPERATIONS_TRUSTED_TOOLS else "fail"
    return {
        "status": status,
        "trusted_tool": trusted_tool,
        "commercial_gap_ids": [gap_ids[number]],
        "compared_fields": compared_fields,
        "mismatches": mismatches,
        "blocker": None if status == "pass" else blockers[number],
    }


def security_hardening_core_accuracy_gates(
    trusted_diff: Mapping[str, object] | None = None,
    evidence_manifest: Mapping[str, object] | None = None,
    baseline_manifest: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = [
        "security baseline emitted",
        "auth/network hardening documented",
        "export rendering safety documented",
        "crash redaction documented",
        "independent AppSec blocker disclosed",
    ]
    if evidence_manifest:
        if evidence_manifest.get("manifest_hash"):
            satisfied.append("security hardening evidence manifest hash emitted")
        if evidence_manifest.get("security_hardening_evidence_slots"):
            satisfied.append("security hardening evidence slots emitted")
        if evidence_manifest.get("control_evidence_matrix_hash"):
            satisfied.append("security hardening control evidence matrix hash emitted")
    if baseline_manifest:
        if baseline_manifest.get("manifest_hash"):
            satisfied.append("security hardening baseline manifest hash emitted")
        if baseline_manifest.get("controls"):
            satisfied.append("security hardening control inventory emitted")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted independent AppSec review diff pass")
    evidence_refs = ["enterprise_policy.security_hardening", "docs/rapidtriage-security-policy.md"]
    if baseline_manifest and baseline_manifest.get("manifest_hash"):
        evidence_refs.append(f"security_hardening_baseline_manifest_sha256:{baseline_manifest['manifest_hash']}")
    return [
        build_accuracy_gate(
            118,
            satisfied_checks=satisfied,
            evidence_refs=evidence_refs,
        )
    ]


def malicious_evidence_sandbox_core_accuracy_gates(
    trusted_diff: Mapping[str, object] | None = None,
    evidence_manifest: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = [
        "preview sandboxing documented",
        "active content blocking documented",
        "parser crash isolation documented",
        "hostile evidence guidance documented",
        "OS sandbox blocker disclosed",
    ]
    if evidence_manifest:
        if evidence_manifest.get("manifest_hash"):
            satisfied.append("malicious sandbox evidence manifest hash emitted")
        if evidence_manifest.get("malicious_sandbox_evidence_slots"):
            satisfied.append("malicious sandbox evidence slots emitted")
        if evidence_manifest.get("control_evidence_matrix_hash"):
            satisfied.append("malicious sandbox control evidence matrix hash emitted")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted malicious evidence sandbox corpus diff pass")
    return [
        build_accuracy_gate(
            119,
            satisfied_checks=satisfied,
            evidence_refs=["enterprise_policy.security_hardening", "docs/rapidtriage-admin-deployment-guide.md"],
        )
    ]
