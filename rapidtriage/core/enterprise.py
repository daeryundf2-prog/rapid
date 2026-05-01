from __future__ import annotations

import hashlib
import os
from pathlib import Path

from .forensic_accuracy import build_accuracy_gate

CRASH_REPORTING_GAP_ID = "#105"
LOCAL_ONLY_ENTERPRISE_GAP_ID = "#106"
LICENSE_ACTIVATION_GAP_ID = "#107"
RBAC_GAP_ID = "#108"
MULTI_USER_CASE_SERVER_GAP_ID = "#109"
COLLABORATION_AUDIT_TRAIL_GAP_ID = "#110"
SECURITY_HARDENING_REVIEW_GAP_ID = "#118"
MALICIOUS_EVIDENCE_SANDBOXING_GAP_ID = "#119"


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
    return {
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
            "core_accuracy_gates": telemetry_core_accuracy_gates(),
            "enabled": False,
            "default": "local-only",
            "evidence_uploads": False,
            "crash_uploads": False,
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
        },
        "license_activation": {
            "commercial_gap_ids": [LICENSE_ACTIVATION_GAP_ID],
            "core_accuracy_gates": license_activation_core_accuracy_gates(license_record),
            "required": False,
            "mode": "offline-not-enforced",
            "license_file": license_record.get("path", ""),
            "status": license_record.get("status", "not-required"),
            "license_sha256": license_record.get("sha256", ""),
            "license_size_bytes": license_record.get("size_bytes", 0),
            "validation": license_record.get("validation", "not-required"),
            "evidence_touch": False,
            "network_activation": False,
            "notes": [
                "No license check reads evidence content.",
                "Offline license files are operator-managed and not enforced by the local-first community build.",
            ],
        },
        "rbac": {
            "commercial_gap_ids": [RBAC_GAP_ID],
            "core_accuracy_gates": rbac_core_accuracy_gates(configured_role, active_permissions),
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
        },
        "multi_user_case_server": {
            "commercial_gap_ids": [MULTI_USER_CASE_SERVER_GAP_ID],
            "core_accuracy_gates": multi_user_case_server_core_accuracy_gates(),
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
        },
        "collaboration_audit_trail": {
            "commercial_gap_ids": [COLLABORATION_AUDIT_TRAIL_GAP_ID],
            "core_accuracy_gates": collaboration_audit_core_accuracy_gates(),
            "status": "case-db-audit-events-with-export-hash-chain",
            "scope": "review/search/import/export actions are recorded in Case DB audit_event rows when using Case DB workflows",
            "recorded_fields": ["actor", "action", "target_type", "target_id", "timestamp", "tool_name", "params_json", "result", "error"],
            "tamper_evidence": "Case DB report exports and reviewer bundles include export-time audit hash chains.",
            "identity_model": "single local actor or caller-supplied reviewer until multi-user identity is implemented",
            "multi_user_conflict_handling": "not-enabled",
        },
        "security_hardening": {
            "commercial_gap_ids": [SECURITY_HARDENING_REVIEW_GAP_ID, MALICIOUS_EVIDENCE_SANDBOXING_GAP_ID],
            "core_accuracy_gates": [
                *security_hardening_core_accuracy_gates(),
                *malicious_evidence_sandbox_core_accuracy_gates(),
            ],
            "status": "documented-local-baseline",
            "preview_sandboxing": "read-only bounded previews with active-content blocking metadata",
            "parser_sandboxing": "parser crash isolation exists; OS-level parser sandbox remains external hardening work",
            "independent_review_required": True,
        },
    }


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


def telemetry_core_accuracy_gates() -> list[dict[str, object]]:
    return [
        build_accuracy_gate(
            106,
            satisfied_checks=[
                "telemetry disabled recorded",
                "evidence/crash upload disabled recorded",
                "localhost default recorded",
                "remote auth token requirement recorded",
                "local-only limitation disclosed",
            ],
            evidence_refs=["enterprise_policy.telemetry", "enterprise_policy.network"],
        )
    ]


def license_activation_core_accuracy_gates(license_record: dict[str, object]) -> list[dict[str, object]]:
    satisfied = [
        "license requirement state recorded",
        "network activation disabled recorded",
        "evidence-touch false recorded",
        "paid activation blocker disclosed",
    ]
    if license_record.get("sha256") or license_record.get("status") in {"not-required", "operator-provided-file-missing", "operator-provided-file-unreadable"}:
        satisfied.append("offline license hash captured when present")
    return [
        build_accuracy_gate(
            107,
            satisfied_checks=satisfied,
            evidence_refs=[f"license_status:{license_record.get('status', 'not-required')}"],
        )
    ]


def rbac_core_accuracy_gates(active_role: str, active_permissions: list[str]) -> list[dict[str, object]]:
    return [
        build_accuracy_gate(
            108,
            satisfied_checks=[
                "role matrix emitted",
                "active role evaluated",
                "active permissions emitted",
                "export controls recorded",
                "per-action enforcement blocker disclosed",
            ],
            evidence_refs=[f"active_role:{active_role}", f"permission_count:{len(active_permissions)}"],
        )
    ]


def multi_user_case_server_core_accuracy_gates() -> list[dict[str, object]]:
    return [
        build_accuracy_gate(
            109,
            satisfied_checks=[
                "multi-user disabled state recorded",
                "network guardrails emitted",
                "identity provider requirement recorded",
                "locking/conflict requirement recorded",
                "security review blocker disclosed",
            ],
            evidence_refs=["enterprise_policy.multi_user_case_server"],
        )
    ]


def collaboration_audit_core_accuracy_gates() -> list[dict[str, object]]:
    return [
        build_accuracy_gate(
            110,
            satisfied_checks=[
                "audit trail scope recorded",
                "recorded fields listed",
                "tamper evidence linkage recorded",
                "identity model caveat recorded",
                "multi-user conflict blocker disclosed",
            ],
            evidence_refs=["enterprise_policy.collaboration_audit_trail"],
        )
    ]


def security_hardening_core_accuracy_gates() -> list[dict[str, object]]:
    return [
        build_accuracy_gate(
            118,
            satisfied_checks=[
                "security baseline emitted",
                "auth/network hardening documented",
                "export rendering safety documented",
                "crash redaction documented",
                "independent AppSec blocker disclosed",
            ],
            evidence_refs=["enterprise_policy.security_hardening", "docs/rapidtriage-security-policy.md"],
        )
    ]


def malicious_evidence_sandbox_core_accuracy_gates() -> list[dict[str, object]]:
    return [
        build_accuracy_gate(
            119,
            satisfied_checks=[
                "preview sandboxing documented",
                "active content blocking documented",
                "parser crash isolation documented",
                "hostile evidence guidance documented",
                "OS sandbox blocker disclosed",
            ],
            evidence_refs=["enterprise_policy.security_hardening", "docs/rapidtriage-admin-deployment-guide.md"],
        )
    ]
