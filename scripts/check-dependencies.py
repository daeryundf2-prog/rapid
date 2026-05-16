#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rapidtriage.core.forensic_accuracy import build_accuracy_gate

DEPENDENCY_VULNERABILITY_MONITORING_GAP_ID = "#120"
DEPENDENCY_MONITORING_TRUSTED_DIFF_BLOCKER_120 = "trusted-dependency-advisory-sbom-diff-missing"
DEPENDENCY_MONITORING_TRUSTED_TOOLS = {"ci-advisory-scan", "sbom-publication-log", "dependency-exception-review"}
DEPENDENCY_MONITORING_REPORT_GRADE_VALIDATION_PLAN_VERSION = "dependency-monitoring-report-grade-validation-plan-v1"
DEPENDENCY_MONITORING_REPORT_GRADE_BLOCKERS = [
    DEPENDENCY_MONITORING_TRUSTED_DIFF_BLOCKER_120,
    "ci-advisory-run-log-required",
    "sbom-publication-required",
    "dependency-exception-review-required",
    "release-host-dependency-smoke-required",
    "scanner-version-lock-required",
    "high-critical-triage-required",
    "artifact-checksum-linkage-required",
    "independent-dependency-review-required",
]
FUNCTIONAL_OPS_BATCH_ID = "commercial-uplift-061-065"
REPO_ROOT = Path(__file__).resolve().parent.parent
DEPENDENCY_MONITORING_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "dependency-monitoring.yml"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write a local dependency vulnerability monitoring baseline")
    parser.add_argument("--output", default="dependency-monitoring.json", help="JSON output path")
    args = parser.parse_args(argv)

    output = Path(args.output).expanduser().resolve()
    workflow_evidence = build_dependency_ci_workflow_evidence(DEPENDENCY_MONITORING_WORKFLOW)
    pip_list = subprocess.run(
        [sys.executable, "-m", "pip", "list", "--format=json"],
        text=True,
        capture_output=True,
        check=False,
    )
    pip_audit = subprocess.run(
        [sys.executable, "-m", "pip_audit", "--format=json"],
        text=True,
        capture_output=True,
        check=False,
    )
    package_count = len(json.loads(pip_list.stdout) if pip_list.returncode == 0 and pip_list.stdout.strip() else [])
    trusted_diff = missing_dependency_monitoring_trusted_diff()
    pip_packages = json.loads(pip_list.stdout) if pip_list.returncode == 0 and pip_list.stdout.strip() else []
    sbom_manifest = build_dependency_sbom_manifest(pip_packages)
    payload = {
        "command": "dependency-monitoring",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "commercial_gap_ids": [DEPENDENCY_VULNERABILITY_MONITORING_GAP_ID],
        "functional_priority_profile": dependency_monitoring_functional_profile(
            package_count=package_count,
            pip_audit_return_code=pip_audit.returncode,
            pip_audit_stdout=pip_audit.stdout,
            pip_audit_stderr=pip_audit.stderr,
            sbom_manifest=sbom_manifest,
            workflow_evidence=workflow_evidence,
            trusted_diff=trusted_diff,
        ),
        "core_accuracy_gates": dependency_monitoring_core_accuracy_gates(
            package_count=package_count,
            scan_attempted=True,
            script_packaged=True,
            workflow_evidence=workflow_evidence,
            trusted_diff=trusted_diff,
        ),
        "python": sys.executable,
        "pip_list": {
            "return_code": pip_list.returncode,
            "packages": pip_packages,
            "error": pip_list.stderr.strip(),
        },
        "dependency_sbom_manifest": sbom_manifest,
        "dependency_sbom_manifest_hash": sbom_manifest["manifest_hash"],
        "dependency_ci_workflow_evidence": workflow_evidence,
        "dependency_ci_workflow_evidence_hash": workflow_evidence["workflow_hash"],
        "vulnerability_scan": {
            "commercial_gap_ids": [DEPENDENCY_VULNERABILITY_MONITORING_GAP_ID],
            "core_accuracy_gates": dependency_monitoring_core_accuracy_gates(
                package_count=package_count,
                scan_attempted=True,
                script_packaged=True,
                workflow_evidence=workflow_evidence,
                trusted_diff=trusted_diff,
            ),
            "tool": "pip-audit",
            "available": pip_audit.returncode != 1 or bool(pip_audit.stdout.strip()),
            "return_code": pip_audit.returncode,
            "raw_output": pip_audit.stdout[:20000],
            "error": pip_audit.stderr[:4000],
            "release_policy": "Block release on known exploitable high/critical dependency issues unless a documented exception is approved.",
        },
        "trusted_dependency_monitoring_diff": trusted_diff,
        "blockers": [DEPENDENCY_MONITORING_TRUSTED_DIFF_BLOCKER_120],
    }
    evidence_manifest = build_dependency_monitoring_evidence_manifest(
        payload,
        trusted_diff=trusted_diff,
        workflow_evidence=workflow_evidence,
    )
    payload["dependency_monitoring_evidence_manifest"] = evidence_manifest
    payload["dependency_monitoring_evidence_manifest_hash"] = evidence_manifest["manifest_hash"]
    payload["dependency_evidence_matrix_hash"] = evidence_manifest["dependency_evidence_matrix_hash"]
    payload["dependency_evidence_slots"] = evidence_manifest["dependency_evidence_slots"]
    report_grade_validation_plan = build_dependency_monitoring_report_grade_validation_plan(
        payload=payload,
        evidence_manifest=evidence_manifest,
        workflow_evidence=workflow_evidence,
        trusted_diff=trusted_diff,
    )
    payload["dependency_report_grade_validation_plan"] = report_grade_validation_plan
    payload["dependency_report_grade_validation_plan_hash"] = report_grade_validation_plan["validation_plan_hash"]
    payload["dependency_report_grade_ready_slot_count"] = report_grade_validation_plan["ready_slot_count"]
    payload["dependency_report_grade_blocking_slot_count"] = report_grade_validation_plan["blocking_slot_count"]
    payload["blockers"] = sorted({*payload.get("blockers", []), *report_grade_validation_plan["blockers"]})
    payload["functional_priority_profile"] = dependency_monitoring_functional_profile(
        package_count=package_count,
        pip_audit_return_code=pip_audit.returncode,
        pip_audit_stdout=pip_audit.stdout,
        pip_audit_stderr=pip_audit.stderr,
        sbom_manifest=sbom_manifest,
        workflow_evidence=workflow_evidence,
        trusted_diff=trusted_diff,
        report_grade_validation_plan=report_grade_validation_plan,
    )
    payload["core_accuracy_gates"] = dependency_monitoring_core_accuracy_gates(
        package_count=package_count,
        scan_attempted=True,
        script_packaged=True,
        workflow_evidence=workflow_evidence,
        trusted_diff=trusted_diff,
        evidence_manifest=evidence_manifest,
        report_grade_validation_plan=report_grade_validation_plan,
    )
    payload["vulnerability_scan"]["core_accuracy_gates"] = payload["core_accuracy_gates"]
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote dependency monitoring baseline: {output}")
    return 0


def dependency_monitoring_core_accuracy_gates(
    *,
    package_count: int,
    scan_attempted: bool,
    script_packaged: bool,
    workflow_evidence: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
    evidence_manifest: Mapping[str, object] | None = None,
    report_grade_validation_plan: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = ["release blocking policy recorded", "CI scheduled scan blocker disclosed"]
    if package_count >= 0:
        satisfied.append("dependency inventory emitted")
    if scan_attempted:
        satisfied.append("vulnerability scan attempted")
    if script_packaged:
        satisfied.append("dependency monitoring script packaged")
    if workflow_evidence and workflow_evidence.get("configured"):
        satisfied.append("CI scheduled advisory scan workflow configured")
    if workflow_evidence and workflow_evidence.get("workflow_hash"):
        satisfied.append("CI dependency workflow hash emitted")
    if evidence_manifest:
        if evidence_manifest.get("manifest_hash"):
            satisfied.append("dependency monitoring evidence manifest hash emitted")
        if evidence_manifest.get("dependency_evidence_slots"):
            satisfied.append("dependency monitoring evidence slots emitted")
        if evidence_manifest.get("sbom_manifest_hash"):
            satisfied.append("dependency SBOM manifest hash emitted")
        if evidence_manifest.get("dependency_evidence_matrix_hash"):
            satisfied.append("dependency evidence matrix hash emitted")
    if report_grade_validation_plan:
        if report_grade_validation_plan.get("validation_plan_hash"):
            satisfied.append("dependency monitoring report-grade validation plan")
        if int(report_grade_validation_plan.get("ready_slot_count") or 0) > 0:
            satisfied.append("dependency monitoring report-grade ready slots")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted dependency advisory/SBOM diff pass")
    evidence_refs = [f"package_count:{package_count}", "tool:pip-audit"]
    if report_grade_validation_plan and report_grade_validation_plan.get("validation_plan_hash"):
        evidence_refs.append(
            f"dependency_report_grade_validation_plan_sha256:{report_grade_validation_plan['validation_plan_hash']}"
        )
        evidence_refs.append(
            f"dependency_report_grade_ready_slots:{report_grade_validation_plan.get('ready_slot_count')}"
        )
        evidence_refs.append(
            f"dependency_report_grade_blocking_slots:{report_grade_validation_plan.get('blocking_slot_count')}"
        )
    return [
        build_accuracy_gate(
            120,
            satisfied_checks=satisfied,
            evidence_refs=evidence_refs,
        )
    ]


def dependency_monitoring_functional_profile(
    *,
    package_count: int,
    pip_audit_return_code: int,
    pip_audit_stdout: str,
    pip_audit_stderr: str,
    sbom_manifest: Mapping[str, object],
    workflow_evidence: Mapping[str, object],
    trusted_diff: Mapping[str, object],
    report_grade_validation_plan: Mapping[str, object] | None = None,
) -> dict[str, object]:
    report_grade_validation_plan = report_grade_validation_plan or {}
    scan_available = pip_audit_return_code != 1 or bool(pip_audit_stdout.strip())
    failed_checks = ["sbom-publication-not-attached"]
    if not workflow_evidence.get("configured"):
        failed_checks.append("ci-scheduled-advisory-scan-not-attached")
    if not scan_available:
        failed_checks.append("pip-audit-not-installed-or-scan-failed")
    if trusted_diff.get("status") != "pass":
        failed_checks.append("trusted-dependency-advisory-sbom-diff-required")
    return {
        "batch_id": FUNCTIONAL_OPS_BATCH_ID,
        "item_number": 64,
        "implementation_track": "dependency-monitoring",
        "status": "usable-local-baseline-ci-sbom-required",
        "implemented_controls": {
            "dependency_inventory_emitted": package_count >= 0,
            "pip_audit_attempted": True,
            "release_blocking_policy_recorded": True,
            "dependency_monitoring_script_packaged": True,
            "dependency_sbom_manifest_emitted": bool(sbom_manifest.get("manifest_hash")),
            "dependency_sbom_manifest_hash": str(sbom_manifest.get("manifest_hash") or ""),
            "scheduled_ci_scan_configured": bool(workflow_evidence.get("configured")),
            "scheduled_ci_workflow_hash": str(workflow_evidence.get("workflow_hash") or ""),
            "sbom_archival_configured": bool(workflow_evidence.get("sbom_archived_in_dependency_artifact")),
            "dependency_report_grade_validation_plan_hash": str(
                report_grade_validation_plan.get("validation_plan_hash") or ""
            ),
            "sbom_published": False,
        },
        "evidence_counts": {
            "package_count": package_count,
            "pip_audit_return_code": pip_audit_return_code,
            "pip_audit_output_bytes": len(pip_audit_stdout.encode("utf-8", errors="replace")),
            "pip_audit_error_bytes": len(pip_audit_stderr.encode("utf-8", errors="replace")),
            "workflow_check_count": len(workflow_evidence.get("passed_checks") or []),
        },
        "failed_validation_check_ids": failed_checks,
        "ready_for_commercial_release": False,
    }


def build_dependency_monitoring_report_grade_validation_plan(
    *,
    payload: Mapping[str, object],
    evidence_manifest: Mapping[str, object],
    workflow_evidence: Mapping[str, object],
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    pip_list = payload.get("pip_list") if isinstance(payload.get("pip_list"), Mapping) else {}
    vulnerability_scan = payload.get("vulnerability_scan") if isinstance(payload.get("vulnerability_scan"), Mapping) else {}
    sbom_manifest = payload.get("dependency_sbom_manifest") if isinstance(payload.get("dependency_sbom_manifest"), Mapping) else {}
    packages = pip_list.get("packages") if isinstance(pip_list.get("packages"), list) else []
    ready_slots = [
        {
            "slot_id": "dependency-monitoring-json",
            "status": "ready",
            "evidence_ref": "scripts/check-dependencies.py --output dependency-monitoring.json",
            "evidence_hash": stable_dependency_sha256("dependency-monitoring command emits JSON"),
        },
        {
            "slot_id": "pip-list-inventory",
            "status": "ready",
            "evidence_ref": "dependency-monitoring.json.pip_list",
            "evidence_hash": stable_dependency_sha256(
                {"return_code": pip_list.get("return_code"), "package_count": len(packages)}
            ),
        },
        {
            "slot_id": "vulnerability-scan-attempt",
            "status": "ready",
            "evidence_ref": "dependency-monitoring.json.vulnerability_scan",
            "evidence_hash": stable_dependency_sha256(
                {
                    "tool": vulnerability_scan.get("tool"),
                    "available": vulnerability_scan.get("available"),
                    "return_code": vulnerability_scan.get("return_code"),
                    "release_policy": vulnerability_scan.get("release_policy"),
                }
            ),
        },
        {
            "slot_id": "dependency-sbom-manifest",
            "status": "ready",
            "evidence_ref": "dependency-monitoring.json.dependency_sbom_manifest_hash",
            "evidence_hash": str(sbom_manifest.get("manifest_hash") or ""),
        },
        {
            "slot_id": "dependency-ci-workflow-evidence",
            "status": "ready" if workflow_evidence.get("configured") else "ready-with-blocker",
            "evidence_ref": "dependency-monitoring.json.dependency_ci_workflow_evidence_hash",
            "evidence_hash": str(workflow_evidence.get("workflow_hash") or ""),
        },
        {
            "slot_id": "dependency-monitoring-evidence-manifest",
            "status": "ready",
            "evidence_ref": "dependency-monitoring.json.dependency_monitoring_evidence_manifest_hash",
            "evidence_hash": str(evidence_manifest.get("manifest_hash") or ""),
        },
        {
            "slot_id": "dependency-evidence-matrix",
            "status": "ready",
            "evidence_ref": "dependency-monitoring.json.dependency_evidence_matrix_hash",
            "evidence_hash": str(evidence_manifest.get("dependency_evidence_matrix_hash") or ""),
        },
        {
            "slot_id": "trusted-dependency-diff-boundary",
            "status": "ready" if trusted_diff.get("status") == "pass" else "ready-with-blocker",
            "evidence_ref": "dependency-monitoring.json.trusted_dependency_monitoring_diff",
            "evidence_hash": stable_dependency_sha256(trusted_diff),
        },
    ]
    blocking_slots = []
    if trusted_diff.get("status") != "pass":
        blocking_slots.append(
            {
                "slot_id": "trusted-dependency-advisory-sbom-diff",
                "status": "blocking",
                "blocker": DEPENDENCY_MONITORING_TRUSTED_DIFF_BLOCKER_120,
                "required_evidence": "trusted CI advisory/SBOM diff proving dependency baseline, SBOM, workflow, and evidence slots are unchanged",
            }
        )
    for slot_id, blocker, required_evidence in (
        (
            "ci-advisory-run-log",
            "ci-advisory-run-log-required",
            "actual scheduled or release CI advisory run log and artifact URL for the release commit",
        ),
        (
            "sbom-publication",
            "sbom-publication-required",
            "published SBOM/dependency baseline with release checksums and retention location",
        ),
        (
            "dependency-exception-review",
            "dependency-exception-review-required",
            "approved exception review for unresolved high/critical dependency findings",
        ),
        (
            "release-host-dependency-smoke",
            "release-host-dependency-smoke-required",
            "release-host smoke proving dependency monitoring command, SBOM manifest, and blockers are packaged",
        ),
        (
            "scanner-version-lock",
            "scanner-version-lock-required",
            "scanner version and vulnerability database timestamp captured for reproducible dependency monitoring",
        ),
        (
            "high-critical-triage",
            "high-critical-triage-required",
            "triage worksheet proving high/critical findings are blocked or have documented exceptions",
        ),
        (
            "artifact-checksum-linkage",
            "artifact-checksum-linkage-required",
            "release artifact checksum linkage between SBOM, dependency-monitoring JSON, and released package set",
        ),
        (
            "independent-dependency-review",
            "independent-dependency-review-required",
            "independent reviewer/lab signoff for advisory scan, SBOM publication, and exception policy",
        ),
    ):
        blocking_slots.append(
            {
                "slot_id": slot_id,
                "status": "blocking",
                "current_attachment_status": "not-attached",
                "blocker": blocker,
                "required_evidence": required_evidence,
            }
        )
    blockers = sorted({str(slot["blocker"]) for slot in blocking_slots if slot.get("blocker")})
    plan: dict[str, object] = {
        "profile_version": DEPENDENCY_MONITORING_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 120,
        "commercial_gap_ids": [DEPENDENCY_VULNERABILITY_MONITORING_GAP_ID],
        "commercial_claim_allowed": False,
        "package_count": len(packages),
        "pip_list_return_code": pip_list.get("return_code"),
        "pip_audit_return_code": vulnerability_scan.get("return_code"),
        "pip_audit_available": bool(vulnerability_scan.get("available")),
        "release_policy": vulnerability_scan.get("release_policy", ""),
        "dependency_sbom_manifest_hash": str(sbom_manifest.get("manifest_hash") or ""),
        "dependency_monitoring_evidence_manifest_hash": str(evidence_manifest.get("manifest_hash") or ""),
        "dependency_evidence_matrix_hash": str(evidence_manifest.get("dependency_evidence_matrix_hash") or ""),
        "dependency_ci_workflow_evidence_hash": str(workflow_evidence.get("workflow_hash") or ""),
        "dependency_ci_workflow_configured": bool(workflow_evidence.get("configured")),
        "trusted_diff_status": str(trusted_diff.get("status") or ""),
        "trusted_diff_blocker": trusted_diff.get("blocker"),
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "external_blocker_catalog": list(DEPENDENCY_MONITORING_REPORT_GRADE_BLOCKERS),
        "blockers": blockers,
        "reporting_boundary": "Dependency inventory, SBOM-like manifest, local pip-audit attempt, and CI workflow contract are usable; commercial monitoring claims require actual CI run evidence, published SBOM/checksum linkage, exception review, scanner version capture, and independent review.",
    }
    plan["validation_plan_hash"] = stable_dependency_sha256(plan)
    return plan


def missing_dependency_monitoring_trusted_diff() -> dict[str, object]:
    return {
        "status": "missing",
        "trusted_tool": None,
        "commercial_gap_ids": [DEPENDENCY_VULNERABILITY_MONITORING_GAP_ID],
        "blocker": DEPENDENCY_MONITORING_TRUSTED_DIFF_BLOCKER_120,
        "required_trusted_tools": sorted(DEPENDENCY_MONITORING_TRUSTED_TOOLS),
    }


def build_dependency_monitoring_trusted_diff(
    rapid_payload: Mapping[str, object],
    trusted_payload: Mapping[str, object],
    *,
    trusted_tool: str = "ci-advisory-scan",
) -> dict[str, object]:
    compared_fields = [
        "pip_list",
        "vulnerability_scan",
        "dependency_sbom_manifest_hash",
        "dependency_monitoring_evidence_manifest_hash",
        "dependency_evidence_matrix_hash",
        "dependency_evidence_slots",
        "dependency_ci_workflow_evidence_hash",
        "dependency_report_grade_validation_plan_hash",
    ]
    mismatches = []
    for field in compared_fields:
        rapid_value = normalize_dependency_monitoring_value(rapid_payload.get(field))
        trusted_value = normalize_dependency_monitoring_value(trusted_payload.get(field))
        if rapid_value != trusted_value:
            mismatches.append({"field": field, "rapid": rapid_value, "trusted": trusted_value})
    status = "pass" if not mismatches and trusted_tool in DEPENDENCY_MONITORING_TRUSTED_TOOLS else "fail"
    return {
        "status": status,
        "trusted_tool": trusted_tool,
        "commercial_gap_ids": [DEPENDENCY_VULNERABILITY_MONITORING_GAP_ID],
        "compared_fields": compared_fields,
        "mismatches": mismatches,
        "blocker": None if status == "pass" else DEPENDENCY_MONITORING_TRUSTED_DIFF_BLOCKER_120,
    }


def normalize_dependency_monitoring_value(value: object) -> object:
    if isinstance(value, list):
        return sorted(json.dumps(item, ensure_ascii=False, sort_keys=True, default=str) for item in value)
    if isinstance(value, Mapping):
        return json.dumps(dict(value), ensure_ascii=False, sort_keys=True, default=str)
    return value


def stable_dependency_sha256(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def build_dependency_sbom_manifest(packages: list[object]) -> dict[str, object]:
    components = []
    for item in packages:
        if not isinstance(item, Mapping):
            continue
        name = str(item.get("name") or "")
        version = str(item.get("version") or "")
        if not name:
            continue
        components.append(
            {
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:pypi/{name}@{version}" if version else f"pkg:pypi/{name}",
            }
        )
    components = sorted(components, key=lambda row: (row["name"].lower(), row["version"]))
    manifest: dict[str, object] = {
        "profile_version": "dependency-sbom-manifest-v1",
        "item_number": 64,
        "commercial_gap_ids": [DEPENDENCY_VULNERABILITY_MONITORING_GAP_ID],
        "sbom_format": "cyclonedx-inspired-internal-json",
        "component_count": len(components),
        "components": components,
        "component_inventory_hash": stable_dependency_sha256(components),
        "publication_status": "not-published",
        "commercial_blockers": [
            "published-sbom-not-attached",
            "scheduled-ci-advisory-scan-not-attached",
            "trusted-dependency-advisory-sbom-diff-required",
        ],
    }
    manifest["manifest_hash"] = stable_dependency_sha256(manifest)
    return manifest


def build_dependency_ci_workflow_evidence(workflow_path: Path = DEPENDENCY_MONITORING_WORKFLOW) -> dict[str, object]:
    text = workflow_path.read_text(encoding="utf-8") if workflow_path.is_file() else ""
    checks = {
        "workflow_file_exists": workflow_path.is_file(),
        "scheduled_trigger": "schedule:" in text and "cron:" in text,
        "manual_trigger": "workflow_dispatch:" in text,
        "pull_request_dependency_paths": "pull_request:" in text and "scripts/check-dependencies.py" in text,
        "check_dependencies_invoked": "python scripts/check-dependencies.py" in text,
        "artifact_upload_configured": "actions/upload-artifact" in text and "dependency-monitoring-ci.json" in text,
        "sbom_archived_in_dependency_artifact": "dependency-monitoring-ci.json" in text,
        "read_only_permissions": "contents: read" in text,
    }
    passed_checks = [name for name, passed in checks.items() if passed]
    failed_checks = [name for name, passed in checks.items() if not passed]
    evidence = {
        "profile_version": "dependency-ci-workflow-evidence-v1",
        "item_number": 120,
        "commercial_gap_ids": [DEPENDENCY_VULNERABILITY_MONITORING_GAP_ID],
        "workflow_path": str(workflow_path),
        "workflow_hash": hashlib.sha256(text.encode("utf-8")).hexdigest() if text else "",
        "configured": not failed_checks,
        "sbom_archived_in_dependency_artifact": checks["sbom_archived_in_dependency_artifact"],
        "checks": checks,
        "passed_checks": passed_checks,
        "failed_checks": failed_checks,
        "commercial_claim_allowed": False,
        "remaining_external_validation": [
            "Attach an actual GitHub Actions run log and artifact URL before claiming commercial scheduled monitoring.",
            "Attach the generated dependency-monitoring-ci.json artifact or publish the SBOM/dependency baseline with release checksums.",
            "Attach a trusted exception review for unresolved high/critical findings.",
        ],
    }
    evidence["evidence_hash"] = stable_dependency_sha256(evidence)
    return evidence


def build_dependency_monitoring_evidence_manifest(
    payload: Mapping[str, object],
    *,
    trusted_diff: Mapping[str, object],
    workflow_evidence: Mapping[str, object] | None = None,
) -> dict[str, object]:
    pip_list = payload.get("pip_list") if isinstance(payload.get("pip_list"), Mapping) else {}
    vulnerability_scan = payload.get("vulnerability_scan") if isinstance(payload.get("vulnerability_scan"), Mapping) else {}
    sbom_manifest = payload.get("dependency_sbom_manifest") if isinstance(payload.get("dependency_sbom_manifest"), Mapping) else {}
    packages = pip_list.get("packages") if isinstance(pip_list.get("packages"), list) else []
    workflow_configured = bool(workflow_evidence and workflow_evidence.get("configured"))
    dependency_evidence_slots = {
        "scheduled_ci_advisory_scan": {
            "status": "configured-no-run-attached" if workflow_configured else "not-attached",
            "expected_material": "Scheduled CI advisory scan log for the release commit",
            "required_before_commercial_claim": True,
            "workflow_hash": workflow_evidence.get("workflow_hash", "") if workflow_evidence else "",
        },
        "sbom_publication": {
            "status": "configured-in-ci-artifact-no-run-attached" if workflow_configured else "not-attached",
            "expected_material": "Published SBOM, dependency-monitoring-ci.json artifact, and checksum for the release artifact set",
            "required_before_commercial_claim": True,
            "workflow_hash": workflow_evidence.get("workflow_hash", "") if workflow_evidence else "",
        },
        "dependency_exception_review": {
            "status": "not-attached",
            "expected_material": "Approved exception review for any unresolved high/critical findings",
            "required_before_commercial_claim": True,
        },
    }
    dependency_evidence_matrix = build_dependency_evidence_matrix(
        package_count=len(packages),
        sbom_manifest=sbom_manifest,
        vulnerability_scan=vulnerability_scan,
        slots=dependency_evidence_slots,
    )
    manifest: dict[str, object] = {
        "profile_version": "dependency-monitoring-evidence-manifest-v1",
        "item_number": 120,
        "commercial_gap_ids": [DEPENDENCY_VULNERABILITY_MONITORING_GAP_ID],
        "commercial_claim_allowed": False,
        "package_count": len(packages),
        "sbom_manifest_hash": sbom_manifest.get("manifest_hash", ""),
        "sbom_component_count": int(sbom_manifest.get("component_count") or 0),
        "pip_list_hash": stable_dependency_sha256(pip_list),
        "vulnerability_scan_hash": stable_dependency_sha256(
            {
                "tool": vulnerability_scan.get("tool"),
                "available": vulnerability_scan.get("available"),
                "return_code": vulnerability_scan.get("return_code"),
                "release_policy": vulnerability_scan.get("release_policy"),
            }
        ),
        "dependency_evidence_slots": dependency_evidence_slots,
        "dependency_evidence_matrix": dependency_evidence_matrix,
        "dependency_evidence_matrix_hash": dependency_evidence_matrix["matrix_hash"],
        "dependency_ci_workflow_evidence_hash": workflow_evidence.get("workflow_hash", "") if workflow_evidence else "",
        "dependency_ci_workflow_configured": workflow_configured,
        "trusted_diff_status": trusted_diff.get("status"),
        "trusted_diff_blocker": trusted_diff.get("blocker"),
        "blockers": [DEPENDENCY_MONITORING_TRUSTED_DIFF_BLOCKER_120],
    }
    manifest["manifest_hash"] = stable_dependency_sha256(manifest)
    return manifest


def build_dependency_evidence_matrix(
    *,
    package_count: int,
    sbom_manifest: Mapping[str, object],
    vulnerability_scan: Mapping[str, object],
    slots: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    rows = []
    for slot_name, slot in sorted(slots.items()):
        row_core = {
            "slot": slot_name,
            "status": slot.get("status", ""),
            "attached": slot.get("status") not in {"not-attached", "missing", ""},
            "required_before_commercial_claim": bool(slot.get("required_before_commercial_claim")),
            "expected_material_hash": stable_dependency_sha256(slot.get("expected_material", "")),
        }
        rows.append({**row_core, "row_hash": stable_dependency_sha256(row_core)})
    matrix: dict[str, object] = {
        "profile_version": "dependency-evidence-matrix-v1",
        "item_number": 120,
        "package_count": package_count,
        "sbom_manifest_hash": sbom_manifest.get("manifest_hash", ""),
        "vulnerability_scan_hash": stable_dependency_sha256(
            {
                "tool": vulnerability_scan.get("tool"),
                "available": vulnerability_scan.get("available"),
                "return_code": vulnerability_scan.get("return_code"),
                "release_policy": vulnerability_scan.get("release_policy"),
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
    matrix["matrix_hash"] = stable_dependency_sha256(matrix)
    return matrix


if __name__ == "__main__":
    raise SystemExit(main())
