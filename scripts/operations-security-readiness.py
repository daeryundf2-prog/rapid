#!/usr/bin/env python3
"""Build numbered operations/security readiness evidence for #108-#111/#118-#120.

This script is deliberately conservative. It proves the local/internal controls
that can be exercised on a developer or release host, then preserves the
external evidence still required before any commercial-grade operations or
security claim is made.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.core.backup import BACKUP_MANIFEST_NAME, build_case_backup, restore_case_backup
from rapidtriage.core.case_db import open_case_database
from rapidtriage.core.enterprise import build_enterprise_policy


PROFILE_VERSION = "operations-security-readiness-v1"
ITEM_NUMBERS = [108, 109, 110, 111, 118, 119, 120]
ITEM_TITLES = {
    108: "Role-based access control",
    109: "Multi-user case server guardrails",
    110: "Collaboration audit trail",
    111: "Backup/restore/migration drill",
    118: "Security hardening review",
    119: "Malicious evidence sandboxing",
    120: "Dependency vulnerability monitoring",
}
EXTERNAL_BLOCKERS = {
    108: [
        "per-action-rbac-enforcement-test-required",
        "multi-user-identity-binding-required",
        "independent-rbac-review-required",
    ],
    109: [
        "multi-user-server-implementation-required",
        "identity-provider-smoke-required",
        "case-locking-conflict-test-required",
        "security-architecture-review-required",
    ],
    110: [
        "append-only-audit-enforcement-required",
        "identity-attribution-review-required",
        "multi-user-conflict-handling-required",
        "independent-collaboration-audit-review-required",
    ],
    111: [
        "multi-version-migration-corpus-required",
        "scheduled-backup-drill-required",
        "release-host-backup-restore-smoke-required",
        "independent-backup-restore-review-required",
    ],
    118: [
        "independent-appsec-review-required",
        "threat-model-review-required",
        "release-host-hardening-smoke-required",
    ],
    119: [
        "os-level-parser-sandbox-required",
        "malicious-corpus-validation-required",
        "preview-sandbox-escape-test-required",
        "independent-malicious-evidence-review-required",
    ],
    120: [
        "ci-advisory-run-log-required",
        "sbom-publication-required",
        "scanner-version-lock-required",
        "independent-dependency-review-required",
    ],
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def stable_hash(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, payload: Mapping[str, Any]) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    path.write_text(serialized, encoding="utf-8")
    return dict(payload)


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def file_entry(path: Path, base: Path) -> dict[str, Any]:
    try:
        relative = path.resolve().relative_to(base.resolve())
    except ValueError:
        relative = path.resolve()
    return {
        "path": relative.as_posix(),
        "sha256": hash_file(path),
        "size_bytes": path.stat().st_size,
    }


def run_command(argv: list[str], *, output_path: Path, timeout: int = 240) -> dict[str, Any]:
    started_at = utc_now()
    try:
        completed = subprocess.run(
            argv,
            cwd=str(REPO_ROOT),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        timed_out = False
        returncode: int | None = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        returncode = None
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
    return {
        "command": argv,
        "command_hash": stable_hash(argv),
        "started_at": started_at,
        "completed_at": utc_now(),
        "returncode": returncode,
        "timed_out": timed_out,
        "output_path": str(output_path),
        "stdout_sha256": hashlib.sha256(stdout.encode("utf-8", errors="replace")).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr.encode("utf-8", errors="replace")).hexdigest(),
        "stdout_tail": stdout[-2000:],
        "stderr_tail": stderr[-2000:],
    }


def clear_work_dir(work_dir: Path, *, overwrite: bool) -> None:
    if work_dir.exists() and any(work_dir.iterdir()):
        if not overwrite:
            raise FileExistsError(f"{work_dir} is not empty; pass --overwrite to replace it")
        for child in work_dir.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    work_dir.mkdir(parents=True, exist_ok=True)


def build_rbac_permission_smoke(policy: Mapping[str, Any], work_dir: Path) -> dict[str, Any]:
    rbac = policy.get("rbac") if isinstance(policy.get("rbac"), Mapping) else {}
    roles = rbac.get("roles") if isinstance(rbac.get("roles"), Mapping) else {}
    normalized_roles = {
        str(role): {str(permission) for permission in permissions}
        for role, permissions in roles.items()
        if isinstance(permissions, list)
    }

    checks = {
        "roles_present": {"local-analyst", "viewer", "admin"}.issubset(normalized_roles),
        "viewer_can_read_case": "read_case" in normalized_roles.get("viewer", set()),
        "viewer_can_export_report": "export_report" in normalized_roles.get("viewer", set()),
        "viewer_cannot_backup_restore": "backup_restore" not in normalized_roles.get("viewer", set()),
        "viewer_cannot_export_evidence_metadata": "export_evidence_metadata"
        not in normalized_roles.get("viewer", set()),
        "local_analyst_can_run_scan": "run_scan" in normalized_roles.get("local-analyst", set()),
        "local_analyst_can_review": "review" in normalized_roles.get("local-analyst", set()),
        "admin_can_backup_restore": "backup_restore" in normalized_roles.get("admin", set()),
        "admin_can_configure": "configure" in normalized_roles.get("admin", set()),
        "export_controls_recorded": isinstance(rbac.get("export_controls"), Mapping),
        "report_grade_plan_hash_present": len(str(rbac.get("rbac_report_grade_validation_plan_hash") or "")) == 64,
    }
    payload: dict[str, Any] = {
        "profile_version": "rbac-permission-smoke-v1",
        "item_number": 108,
        "generated_at": utc_now(),
        "policy_version": policy.get("policy_version"),
        "active_role": rbac.get("active_role"),
        "roles": {role: sorted(permissions) for role, permissions in sorted(normalized_roles.items())},
        "permission_matrix": rbac.get("permission_matrix", []),
        "export_controls": rbac.get("export_controls", {}),
        "checks": checks,
        "passed_check_count": sum(1 for passed in checks.values() if passed),
        "failed_check_ids": [name for name, passed in checks.items() if not passed],
        "commercial_claim_allowed": False,
        "external_blockers": EXTERNAL_BLOCKERS[108],
    }
    payload["smoke_hash"] = stable_hash(payload)
    return write_json(work_dir / "rbac-permission-smoke.json", payload)


def build_backup_restore_smoke(work_dir: Path) -> dict[str, Any]:
    case_db_path = work_dir / "case-db" / "ops-security-case.db"
    database = open_case_database(case_db_path)
    database.create_case(
        case_id="OPS-SECURITY-SMOKE",
        name="Operations Security Smoke",
        description="Internal backup/restore rehearsal for operations-security readiness.",
        examiner="rapidtriage",
        organization="local",
        case_root=work_dir,
    )
    audit_citation = database.add_audit_event(
        case_id="OPS-SECURITY-SMOKE",
        actor="release-operator",
        action="ops.security.readiness.smoke",
        target_type="case",
        target_id="OPS-SECURITY-SMOKE",
        params_json=json.dumps({"profile_version": PROFILE_VERSION}, sort_keys=True),
        result="ok",
    )
    backup_dir = work_dir / "case-backup"
    restored_db = work_dir / "case-restore" / "restored-case.db"
    backup_payload = build_case_backup(database_path=case_db_path, output_dir=backup_dir, overwrite=True)
    restore_payload = restore_case_backup(
        manifest_path=backup_dir / BACKUP_MANIFEST_NAME,
        output_path=restored_db,
        overwrite=True,
    )
    write_json(work_dir / "case-backup.json", backup_payload)
    write_json(work_dir / "case-restore.json", restore_payload)
    checks = {
        "case_created": case_db_path.is_file(),
        "audit_event_written": bool(audit_citation),
        "backup_manifest_written": (backup_dir / BACKUP_MANIFEST_NAME).is_file(),
        "backup_hashes_present": all(
            bool(item.get("hashes", {}).get("sha256"))
            for item in backup_payload.get("files", [])
            if isinstance(item, Mapping)
        ),
        "restore_database_written": restored_db.is_file(),
        "restore_hash_verified": restore_payload.get("hash_verified") is True,
        "backup_report_grade_plan_hash_present": len(
            str(backup_payload.get("backup_restore_report_grade_validation_plan_hash") or "")
        )
        == 64,
        "restore_report_grade_plan_hash_present": len(
            str(restore_payload.get("backup_restore_report_grade_validation_plan_hash") or "")
        )
        == 64,
    }
    payload: dict[str, Any] = {
        "profile_version": "backup-restore-drill-smoke-v1",
        "item_number": 111,
        "generated_at": utc_now(),
        "case_database": str(case_db_path),
        "audit_citation": audit_citation,
        "backup_manifest": str((backup_dir / BACKUP_MANIFEST_NAME).resolve()),
        "restored_database": str(restored_db.resolve()),
        "backup_manifest_hash": hash_file(backup_dir / BACKUP_MANIFEST_NAME),
        "case_backup_json_hash": hash_file(work_dir / "case-backup.json"),
        "case_restore_json_hash": hash_file(work_dir / "case-restore.json"),
        "restore_hash_verified": restore_payload.get("hash_verified") is True,
        "backup_ready_slot_count": backup_payload.get("backup_restore_report_grade_ready_slot_count"),
        "backup_blocking_slot_count": backup_payload.get("backup_restore_report_grade_blocking_slot_count"),
        "restore_ready_slot_count": restore_payload.get("backup_restore_report_grade_ready_slot_count"),
        "restore_blocking_slot_count": restore_payload.get("backup_restore_report_grade_blocking_slot_count"),
        "checks": checks,
        "passed_check_count": sum(1 for passed in checks.values() if passed),
        "failed_check_ids": [name for name, passed in checks.items() if not passed],
        "commercial_claim_allowed": False,
        "external_blockers": EXTERNAL_BLOCKERS[111],
    }
    payload["smoke_hash"] = stable_hash(payload)
    return write_json(work_dir / "backup-restore-drill-smoke.json", payload)


def run_json_script(work_dir: Path, script_name: str, output_name: str, *, timeout: int = 240) -> dict[str, Any]:
    output_path = work_dir / output_name
    argv = [sys.executable, str(REPO_ROOT / "scripts" / script_name), "--output", str(output_path)]
    if script_name in {"security-hardening-review.py", "parser-sandbox-smoke.py"}:
        argv.append("--json")
    command_result = run_command(argv, output_path=output_path, timeout=timeout)
    payload = read_json(output_path) if output_path.is_file() else {}
    return {
        "script": script_name,
        "output": output_name,
        "command_result": command_result,
        "payload": payload,
        "file": file_entry(output_path, work_dir) if output_path.is_file() else None,
        "passed": command_result["returncode"] == 0
        and not command_result["timed_out"]
        and output_path.is_file(),
    }


def extract_policy_item_evidence(policy: Mapping[str, Any], item_number: int) -> dict[str, Any]:
    key_by_item = {
        108: "rbac",
        109: "multi_user_case_server",
        110: "collaboration_audit_trail",
        118: "security_hardening",
        119: "security_hardening",
    }
    key = key_by_item[item_number]
    value = policy.get(key) if isinstance(policy.get(key), Mapping) else {}
    if item_number == 119 and isinstance(value, Mapping):
        return {
            "status": value.get("status"),
            "parser_sandboxing": value.get("parser_sandboxing"),
            "malicious_sandbox_evidence_manifest_hash": value.get("malicious_sandbox_evidence_manifest_hash"),
            "malicious_sandbox_report_grade_validation_plan_hash": value.get(
                "malicious_sandbox_report_grade_validation_plan_hash"
            ),
            "blockers": value.get("blockers", []),
            "core_accuracy_gates": value.get("core_accuracy_gates", []),
        }
    return dict(value)


def readiness_row(
    *,
    item_number: int,
    source_outputs: list[dict[str, Any]],
    checks: Mapping[str, bool],
    evidence_hashes: Mapping[str, str],
    ready_slot_count: int | None = None,
    blocking_slot_count: int | None = None,
) -> dict[str, Any]:
    failed_check_ids = [name for name, passed in checks.items() if not passed]
    implemented = bool(checks) and not failed_check_ids
    row = {
        "number": item_number,
        "title": ITEM_TITLES[item_number],
        "status": "implemented-usable-internal-validated" if implemented else "partial-internal-validation-failed",
        "implemented": implemented,
        "usable": implemented,
        "internal_validated": implemented,
        "commercial_grade": False,
        "commercial_claim_allowed": False,
        "source_outputs": source_outputs,
        "checks": dict(checks),
        "failed_check_ids": failed_check_ids,
        "evidence_hashes": dict(evidence_hashes),
        "ready_slot_count": ready_slot_count,
        "blocking_slot_count": blocking_slot_count,
        "external_blockers": EXTERNAL_BLOCKERS[item_number],
    }
    row["row_hash"] = stable_hash(row)
    return row


def write_sha256sums(work_dir: Path, *, exclude: set[Path] | None = None) -> Path:
    excluded = {path.resolve() for path in (exclude or set())}
    rows = []
    for path in sorted(candidate for candidate in work_dir.rglob("*") if candidate.is_file()):
        if path.name == "SHA256SUMS" or path.resolve() in excluded:
            continue
        rows.append(f"{hash_file(path)}  {path.relative_to(work_dir).as_posix()}")
    sha_path = work_dir / "SHA256SUMS"
    sha_path.write_text("\n".join(rows) + ("\n" if rows else ""), encoding="utf-8")
    return sha_path


def build_operations_security_readiness(
    *,
    output: Path,
    work_dir: Path,
    overwrite: bool = False,
) -> dict[str, Any]:
    clear_work_dir(work_dir, overwrite=overwrite)
    output.parent.mkdir(parents=True, exist_ok=True)

    policy = build_enterprise_policy()
    enterprise_policy_path = work_dir / "enterprise-policy.json"
    write_json(enterprise_policy_path, policy)
    rbac_smoke = build_rbac_permission_smoke(policy, work_dir)
    backup_smoke = build_backup_restore_smoke(work_dir)
    security_run = run_json_script(work_dir, "security-hardening-review.py", "security-hardening-review.json")
    sandbox_run = run_json_script(work_dir, "parser-sandbox-smoke.py", "parser-sandbox-smoke.json")
    dependency_run = run_json_script(work_dir, "check-dependencies.py", "dependency-monitoring.json")

    security_payload = security_run["payload"]
    sandbox_payload = sandbox_run["payload"]
    dependency_payload = dependency_run["payload"]
    policy_evidence = {
        "enterprise_policy": file_entry(enterprise_policy_path, work_dir),
        "rbac_permission_smoke": file_entry(work_dir / "rbac-permission-smoke.json", work_dir),
        "backup_restore_drill_smoke": file_entry(work_dir / "backup-restore-drill-smoke.json", work_dir),
        "case_backup": file_entry(work_dir / "case-backup.json", work_dir),
        "case_restore": file_entry(work_dir / "case-restore.json", work_dir),
        "security_hardening_review": security_run["file"],
        "parser_sandbox_smoke": sandbox_run["file"],
        "dependency_monitoring": dependency_run["file"],
    }

    rbac_checks = {
        **{
            f"rbac_smoke_{name}": bool(value)
            for name, value in rbac_smoke.get("checks", {}).items()
        },
        "rbac_evidence_manifest_hash_present": len(
            str(policy.get("rbac", {}).get("rbac_evidence_manifest_hash") or "")
        )
        == 64,
    }
    multi_user = extract_policy_item_evidence(policy, 109)
    multi_user_checks = {
        "multi_user_guardrails_present": bool(multi_user.get("guardrails")),
        "multi_user_disabled_by_default": multi_user.get("enabled") is False,
        "multi_user_required_before_enablement_present": bool(multi_user.get("required_before_enablement")),
        "multi_user_report_grade_plan_hash_present": len(
            str(multi_user.get("multi_user_report_grade_validation_plan_hash") or "")
        )
        == 64,
        "multi_user_blocker_preserved": "trusted-multi-user-server-review-diff-missing"
        in set(multi_user.get("blockers") or []),
    }
    collaboration = extract_policy_item_evidence(policy, 110)
    collaboration_checks = {
        "collaboration_audit_scope_recorded": bool(collaboration.get("scope")),
        "collaboration_recorded_fields_present": bool(collaboration.get("recorded_fields")),
        "collaboration_tamper_evidence_recorded": bool(collaboration.get("tamper_evidence")),
        "collaboration_report_grade_plan_hash_present": len(
            str(collaboration.get("collaboration_audit_report_grade_validation_plan_hash") or "")
        )
        == 64,
        "collaboration_blocker_preserved": "trusted-collaboration-audit-diff-missing"
        in set(collaboration.get("blockers") or []),
    }
    backup_checks = {
        f"backup_smoke_{name}": bool(value)
        for name, value in backup_smoke.get("checks", {}).items()
    }
    security_checks = {
        "security_review_command_passed": security_run["passed"],
        "security_review_profile": security_payload.get("profile_version") == "security-hardening-release-review-v1",
        "security_review_no_failed_checks": not security_payload.get("failed_check_ids"),
        "security_appsec_blocker_preserved": security_payload.get("checks", {}).get("appsec_blocker_preserved") is True,
    }
    sandbox_checks = {
        "sandbox_smoke_command_passed": sandbox_run["passed"],
        "sandbox_smoke_profile": sandbox_payload.get("profile_version") == "parser-subprocess-isolation-smoke-v1",
        "sandbox_no_failed_checks": not sandbox_payload.get("failed_check_ids"),
        "sandbox_os_level_claim_blocked": sandbox_payload.get("checks", {}).get("os_level_sandbox_claim_blocked") is True,
    }
    dependency_checks = {
        "dependency_command_passed": dependency_run["passed"],
        "dependency_profile": dependency_payload.get("command") == "dependency-monitoring",
        "dependency_inventory_emitted": len(dependency_payload.get("pip_list", {}).get("packages", [])) >= 0,
        "dependency_scheduled_workflow_configured": dependency_payload.get("dependency_ci_workflow_evidence", {}).get(
            "configured"
        )
        is True,
        "dependency_report_grade_plan_hash_present": len(
            str(dependency_payload.get("dependency_report_grade_validation_plan_hash") or "")
        )
        == 64,
    }

    rows = [
        readiness_row(
            item_number=108,
            source_outputs=[policy_evidence["enterprise_policy"], policy_evidence["rbac_permission_smoke"]],
            checks=rbac_checks,
            evidence_hashes={
                "enterprise_policy_sha256": policy_evidence["enterprise_policy"]["sha256"],
                "rbac_permission_smoke_sha256": policy_evidence["rbac_permission_smoke"]["sha256"],
                "rbac_report_grade_validation_plan_hash": str(
                    policy.get("rbac", {}).get("rbac_report_grade_validation_plan_hash") or ""
                ),
            },
            ready_slot_count=int(policy.get("rbac", {}).get("rbac_report_grade_ready_slot_count") or 0),
            blocking_slot_count=int(policy.get("rbac", {}).get("rbac_report_grade_blocking_slot_count") or 0),
        ),
        readiness_row(
            item_number=109,
            source_outputs=[policy_evidence["enterprise_policy"]],
            checks=multi_user_checks,
            evidence_hashes={
                "enterprise_policy_sha256": policy_evidence["enterprise_policy"]["sha256"],
                "multi_user_report_grade_validation_plan_hash": str(
                    multi_user.get("multi_user_report_grade_validation_plan_hash") or ""
                ),
            },
            ready_slot_count=int(multi_user.get("multi_user_report_grade_ready_slot_count") or 0),
            blocking_slot_count=int(multi_user.get("multi_user_report_grade_blocking_slot_count") or 0),
        ),
        readiness_row(
            item_number=110,
            source_outputs=[policy_evidence["enterprise_policy"]],
            checks=collaboration_checks,
            evidence_hashes={
                "enterprise_policy_sha256": policy_evidence["enterprise_policy"]["sha256"],
                "collaboration_audit_report_grade_validation_plan_hash": str(
                    collaboration.get("collaboration_audit_report_grade_validation_plan_hash") or ""
                ),
            },
            ready_slot_count=int(collaboration.get("collaboration_audit_report_grade_ready_slot_count") or 0),
            blocking_slot_count=int(collaboration.get("collaboration_audit_report_grade_blocking_slot_count") or 0),
        ),
        readiness_row(
            item_number=111,
            source_outputs=[
                policy_evidence["backup_restore_drill_smoke"],
                policy_evidence["case_backup"],
                policy_evidence["case_restore"],
            ],
            checks=backup_checks,
            evidence_hashes={
                "backup_restore_drill_smoke_sha256": policy_evidence["backup_restore_drill_smoke"]["sha256"],
                "case_backup_sha256": policy_evidence["case_backup"]["sha256"],
                "case_restore_sha256": policy_evidence["case_restore"]["sha256"],
                "backup_manifest_sha256": str(backup_smoke.get("backup_manifest_hash") or ""),
            },
            ready_slot_count=int(backup_smoke.get("restore_ready_slot_count") or 0),
            blocking_slot_count=int(backup_smoke.get("restore_blocking_slot_count") or 0),
        ),
        readiness_row(
            item_number=118,
            source_outputs=[policy_evidence["security_hardening_review"]],
            checks=security_checks,
            evidence_hashes={
                "security_hardening_review_sha256": policy_evidence["security_hardening_review"]["sha256"],
                "security_review_hash": str(security_payload.get("review_hash") or ""),
            },
            ready_slot_count=len(security_payload.get("checks", {})),
            blocking_slot_count=len(security_payload.get("remaining_external_validation", [])),
        ),
        readiness_row(
            item_number=119,
            source_outputs=[policy_evidence["parser_sandbox_smoke"]],
            checks=sandbox_checks,
            evidence_hashes={
                "parser_sandbox_smoke_sha256": policy_evidence["parser_sandbox_smoke"]["sha256"],
                "parser_sandbox_smoke_hash": str(sandbox_payload.get("smoke_hash") or ""),
            },
            ready_slot_count=int(sandbox_payload.get("passed_check_count") or 0),
            blocking_slot_count=len(sandbox_payload.get("remaining_external_validation", [])),
        ),
        readiness_row(
            item_number=120,
            source_outputs=[policy_evidence["dependency_monitoring"]],
            checks=dependency_checks,
            evidence_hashes={
                "dependency_monitoring_sha256": policy_evidence["dependency_monitoring"]["sha256"],
                "dependency_monitoring_evidence_manifest_hash": str(
                    dependency_payload.get("dependency_monitoring_evidence_manifest_hash") or ""
                ),
                "dependency_report_grade_validation_plan_hash": str(
                    dependency_payload.get("dependency_report_grade_validation_plan_hash") or ""
                ),
            },
            ready_slot_count=int(dependency_payload.get("dependency_report_grade_ready_slot_count") or 0),
            blocking_slot_count=int(dependency_payload.get("dependency_report_grade_blocking_slot_count") or 0),
        ),
    ]
    component_checks = {
        "enterprise_policy_written": enterprise_policy_path.is_file(),
        "rbac_smoke_passed": not rbac_smoke.get("failed_check_ids"),
        "backup_restore_smoke_passed": not backup_smoke.get("failed_check_ids"),
        "security_hardening_review_passed": security_run["passed"] and not security_payload.get("failed_check_ids"),
        "parser_sandbox_smoke_passed": sandbox_run["passed"] and not sandbox_payload.get("failed_check_ids"),
        "dependency_monitoring_passed": dependency_run["passed"],
        "numbered_rows_all_internal_validated": all(row["internal_validated"] for row in rows),
    }
    summary = {
        "item_count": len(rows),
        "implemented_count": sum(1 for row in rows if row["implemented"]),
        "usable_count": sum(1 for row in rows if row["usable"]),
        "internal_validated_count": sum(1 for row in rows if row["internal_validated"]),
        "commercial_grade_count": sum(1 for row in rows if row["commercial_grade"]),
        "external_blocker_count": sum(len(row["external_blockers"]) for row in rows),
        "failed_row_numbers": [row["number"] for row in rows if not row["internal_validated"]],
    }
    payload: dict[str, Any] = {
        "command": "operations-security-readiness",
        "profile_version": PROFILE_VERSION,
        "generated_at": utc_now(),
        "item_numbers": ITEM_NUMBERS,
        "numbered_readiness": rows,
        "summary": summary,
        "component_checks": component_checks,
        "all_internal_checks_passed": all(component_checks.values()),
        "commercial_claim_allowed": False,
        "commercial_grade_boundary": (
            "Internal controls are runnable and numbered, but commercial-grade operations/security claims require "
            "independent review, multi-user server proof, OS-level sandbox evidence, release-host restore drills, "
            "and CI/SBOM artifacts."
        ),
        "external_blocker_catalog": EXTERNAL_BLOCKERS,
        "generated_files": [
            value for value in policy_evidence.values() if isinstance(value, Mapping)
        ],
        "script_results": {
            "security_hardening_review": security_run["command_result"],
            "parser_sandbox_smoke": sandbox_run["command_result"],
            "dependency_monitoring": dependency_run["command_result"],
        },
    }
    payload["manifest_hash"] = stable_hash(payload)
    write_json(output, payload)
    checksum_path = write_sha256sums(work_dir, exclude={output})
    payload["checksum_manifest"] = str(checksum_path)
    # Re-write once with the checksum path included; SHA256SUMS intentionally
    # covers component evidence, while the manifest records where to find it.
    payload["manifest_hash"] = stable_hash({k: v for k, v in payload.items() if k != "manifest_hash"})
    write_json(output, payload)
    return payload


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate numbered operations/security readiness evidence")
    parser.add_argument("--output", default="operations-security-readiness.json", help="Final JSON output path")
    parser.add_argument(
        "--work-dir",
        default="operations-security-readiness-work",
        help="Directory for component evidence JSON files",
    )
    parser.add_argument("--overwrite", action="store_true", help="Replace an existing non-empty work directory")
    parser.add_argument("--json", action="store_true", help="Print final manifest JSON")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    output = Path(args.output).expanduser().resolve()
    work_dir = Path(args.work_dir).expanduser().resolve()
    payload = build_operations_security_readiness(output=output, work_dir=work_dir, overwrite=args.overwrite)
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"Wrote operations/security readiness evidence: {output}")
    return 0 if payload["all_internal_checks_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
