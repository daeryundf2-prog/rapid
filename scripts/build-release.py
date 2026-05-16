#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rapidtriage.core.commercial_readiness import build_commercial_readiness_report
from rapidtriage.core.forensic_accuracy import build_accuracy_gate

WINDOWS_SIGNED_INSTALLER_GAP_ID = "#101"
MACOS_NOTARIZED_PACKAGE_GAP_ID = "#102"
LINUX_PACKAGE_GAP_ID = "#103"
AUTO_UPDATE_CHANNEL_GAP_ID = "#104"
WINDOWS_SIGNING_TRUSTED_DIFF_BLOCKER_101 = "trusted-windows-signing-evidence-diff-missing"
WINDOWS_SIGNING_REPORT_GRADE_VALIDATION_PLAN_VERSION = "windows-signing-report-grade-validation-plan-v1"
WINDOWS_SIGNING_REPORT_GRADE_BLOCKERS = [
    WINDOWS_SIGNING_TRUSTED_DIFF_BLOCKER_101,
    "authenticode-signature-required",
    "timestamp-authority-proof-required",
    "fresh-windows-smoke-required",
    "installer-wrapper-build-log-required",
    "certificate-chain-verification-required",
    "windows-defender-smartscreen-review-required",
]
MACOS_NOTARIZATION_TRUSTED_DIFF_BLOCKER_102 = "trusted-macos-notarization-evidence-diff-missing"
MACOS_NOTARIZATION_REPORT_GRADE_VALIDATION_PLAN_VERSION = "macos-notarization-report-grade-validation-plan-v1"
MACOS_NOTARIZATION_REPORT_GRADE_BLOCKERS = [
    MACOS_NOTARIZATION_TRUSTED_DIFF_BLOCKER_102,
    "codesign-verification-required",
    "notarytool-submission-proof-required",
    "notarization-ticket-staple-required",
    "gatekeeper-assessment-required",
    "fresh-macos-smoke-required",
    "pkg-dmg-wrapper-build-log-required",
    "apple-developer-id-certificate-required",
]
LINUX_PACKAGE_TRUSTED_DIFF_BLOCKER_103 = "trusted-linux-package-smoke-diff-missing"
LINUX_PACKAGE_REPORT_GRADE_VALIDATION_PLAN_VERSION = "linux-package-report-grade-validation-plan-v1"
LINUX_PACKAGE_REPORT_GRADE_BLOCKERS = [
    LINUX_PACKAGE_TRUSTED_DIFF_BLOCKER_103,
    "deb-build-log-required",
    "rpm-build-log-required",
    "appimage-build-log-required",
    "clean-container-build-log-required",
    "install-uninstall-smoke-required",
    "dependency-resolution-proof-required",
    "package-signing-policy-required",
]
AUTO_UPDATE_TRUSTED_DIFF_BLOCKER_104 = "trusted-auto-update-channel-diff-missing"
AUTO_UPDATE_REPORT_GRADE_VALIDATION_PLAN_VERSION = "auto-update-report-grade-validation-plan-v1"
AUTO_UPDATE_REPORT_GRADE_BLOCKERS = [
    AUTO_UPDATE_TRUSTED_DIFF_BLOCKER_104,
    "signed-update-manifest-required",
    "hosted-update-channel-required",
    "rollback-test-required",
    "enterprise-disable-smoke-required",
    "update-client-implementation-required",
    "release-artifact-signature-required",
]
RELEASE_PACKAGING_TRUSTED_TOOLS = {
    "authenticode-signature-log",
    "macos-notarization-log",
    "linux-package-smoke-log",
    "signed-update-channel-log",
}
RELEASE_NOTES_CHANGELOG_GAP_ID = "#112"
LTS_HOTFIX_POLICY_GAP_ID = "#113"
SUPPORT_SLA_GAP_ID = "#114"
TRAINING_CURRICULUM_GAP_ID = "#115"
RELEASE_NOTES_REPORT_GRADE_VALIDATION_PLAN_VERSION = "release-notes-report-grade-validation-plan-v1"
LTS_HOTFIX_REPORT_GRADE_VALIDATION_PLAN_VERSION = "lts-hotfix-report-grade-validation-plan-v1"
SUPPORT_SLA_REPORT_GRADE_VALIDATION_PLAN_VERSION = "support-sla-report-grade-validation-plan-v1"
OPERATIONS_DOCUMENT_TRUSTED_DIFF_BLOCKERS = {
    112: "trusted-release-notes-ci-gate-diff-missing",
    113: "trusted-lts-hotfix-policy-diff-missing",
    114: "trusted-support-desk-sla-diff-missing",
    115: "trusted-training-delivery-diff-missing",
    116: "trusted-quickstart-lab-run-diff-missing",
    117: "trusted-admin-deployment-proof-diff-missing",
}
OPERATIONS_DOCUMENT_TRUSTED_TOOLS = {
    "release-notes-ci-gate",
    "lts-hotfix-policy-review",
    "support-desk-sla-attestation",
    "training-delivery-log",
    "quickstart-lab-run-log",
    "admin-deployment-proof",
}
RELEASE_NOTES_REPORT_GRADE_BLOCKERS = [
    OPERATIONS_DOCUMENT_TRUSTED_DIFF_BLOCKERS[112],
    "ci-changelog-gate-required",
    "release-owner-review-required",
    "migration-note-review-required",
    "validation-state-review-required",
    "checksum-publication-review-required",
    "release-host-smoke-log-required",
    "independent-release-notes-review-required",
]
LTS_HOTFIX_REPORT_GRADE_BLOCKERS = [
    OPERATIONS_DOCUMENT_TRUSTED_DIFF_BLOCKERS[113],
    "maintained-branch-proof-required",
    "hotfix-backport-validation-required",
    "emergency-patch-drill-required",
    "release-owner-hotfix-signoff-required",
    "lts-branch-policy-review-required",
    "release-host-hotfix-smoke-required",
    "independent-lts-policy-review-required",
]
SUPPORT_SLA_REPORT_GRADE_BLOCKERS = [
    OPERATIONS_DOCUMENT_TRUSTED_DIFF_BLOCKERS[114],
    "staffed-support-attestation-required",
    "contractual-sla-execution-required",
    "secure-intake-runbook-signoff-required",
    "escalation-rota-required",
    "emergency-parser-hotfix-drill-required",
    "support-ticket-sample-required",
    "release-host-support-flow-smoke-required",
    "independent-support-sla-review-required",
]
ANALYST_QUICKSTART_LAB_GAP_ID = "#116"
ADMIN_DEPLOYMENT_GUIDE_GAP_ID = "#117"
SECURITY_HARDENING_REVIEW_GAP_ID = "#118"
MALICIOUS_EVIDENCE_SANDBOXING_GAP_ID = "#119"
DEPENDENCY_VULNERABILITY_MONITORING_GAP_ID = "#120"
FUNCTIONAL_PACKAGING_BATCH_ID = "commercial-uplift-056-060"
FUNCTIONAL_OPERATIONS_BATCH_ID = "commercial-uplift-066-070"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build RapidTriage release artifacts")
    parser.add_argument("--output-dir", default="release", help="Release artifact directory")
    parser.add_argument("--skip-build", action="store_true", help="Skip wheel/sdist build and only assemble portable zip")
    parser.add_argument("--verify", action="store_true", help="Verify SHA256SUMS in the output directory and exit")
    args = parser.parse_args(argv)

    repo = Path(__file__).resolve().parent.parent
    output_dir = (repo / args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.verify:
        return verify_sha256s(output_dir)

    if not args.skip_build:
        subprocess.run([sys.executable, "-m", "build", "--wheel", "--sdist"], cwd=repo, check=True)
        dist_dir = repo / "dist"
        for artifact in dist_dir.glob("*"):
            shutil.copy2(artifact, output_dir / artifact.name)

    portable_zip = output_dir / "rapidtriage-portable.zip"
    with zipfile.ZipFile(portable_zip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        add_if_exists(archive, repo / "README.md", "README.md")
        add_if_exists(archive, repo / "docs" / "rapidtriage-windows-quickstart.md", "docs/rapidtriage-windows-quickstart.md")
        add_if_exists(archive, repo / "docs" / "rapidtriage-macos-linux-quickstart.md", "docs/rapidtriage-macos-linux-quickstart.md")
        add_if_exists(archive, repo / "docs" / "rapidtriage-fresh-machine-smoke-test.md", "docs/rapidtriage-fresh-machine-smoke-test.md")
        add_if_exists(archive, repo / "docs" / "rapidtriage-e01-workflow.md", "docs/rapidtriage-e01-workflow.md")
        add_if_exists(archive, repo / "docs" / "rapidtriage-user-guide.md", "docs/rapidtriage-user-guide.md")
        add_if_exists(archive, repo / "docs" / "rapidtriage-known-limitations.md", "docs/rapidtriage-known-limitations.md")
        add_if_exists(archive, repo / "docs" / "rapidtriage-parser-coverage.md", "docs/rapidtriage-parser-coverage.md")
        add_if_exists(archive, repo / "docs" / "rapidtriage-sample-case.md", "docs/rapidtriage-sample-case.md")
        add_if_exists(
            archive,
            repo / "docs" / "rapidtriage-commercial-parity-backlog.md",
            "docs/rapidtriage-commercial-parity-backlog.md",
        )
        add_if_exists(archive, repo / "docs" / "rapidtriage-security-policy.md", "docs/rapidtriage-security-policy.md")
        add_if_exists(archive, repo / "docs" / "rapidtriage-release-checklist.md", "docs/rapidtriage-release-checklist.md")
        add_if_exists(archive, repo / "docs" / "rapidtriage-release-notes-template.md", "docs/rapidtriage-release-notes-template.md")
        add_if_exists(archive, repo / "docs" / "rapidtriage-support-sla.md", "docs/rapidtriage-support-sla.md")
        add_if_exists(archive, repo / "docs" / "rapidtriage-lts-hotfix-policy.md", "docs/rapidtriage-lts-hotfix-policy.md")
        add_if_exists(archive, repo / "docs" / "rapidtriage-training-curriculum.md", "docs/rapidtriage-training-curriculum.md")
        add_if_exists(archive, repo / "docs" / "rapidtriage-admin-deployment-guide.md", "docs/rapidtriage-admin-deployment-guide.md")
        add_if_exists(archive, repo / "scripts" / "start-rapidtriage.sh", "scripts/start-rapidtriage.sh")
        add_if_exists(archive, repo / "scripts" / "smoke-test-rapidtriage.sh", "scripts/smoke-test-rapidtriage.sh")
        add_if_exists(archive, repo / "scripts" / "summarize-smoke.py", "scripts/summarize-smoke.py")
        add_if_exists(archive, repo / "scripts" / "verify-release-evidence.py", "scripts/verify-release-evidence.py")
        add_if_exists(archive, repo / "scripts" / "check-dependencies.py", "scripts/check-dependencies.py")
        add_if_exists(archive, repo / "scripts" / "crash-export-smoke.py", "scripts/crash-export-smoke.py")
        add_if_exists(archive, repo / "scripts" / "crash-redaction-review.py", "scripts/crash-redaction-review.py")
        add_if_exists(archive, repo / "scripts" / "parser-sandbox-smoke.py", "scripts/parser-sandbox-smoke.py")
        add_if_exists(archive, repo / "scripts" / "security-hardening-review.py", "scripts/security-hardening-review.py")
        add_if_exists(
            archive,
            repo / "scripts" / "external-release-evidence-template.py",
            "scripts/external-release-evidence-template.py",
        )
        add_if_exists(
            archive,
            repo / "scripts" / "hostile-evidence-containment-template.py",
            "scripts/hostile-evidence-containment-template.py",
        )
        add_if_exists(
            archive,
            repo / "scripts" / "independent-operations-evidence-template.py",
            "scripts/independent-operations-evidence-template.py",
        )
        add_tree(archive, repo / "scripts" / "windows", "scripts/windows")
        archive.writestr("data/.gitkeep", "")
        archive.writestr("cases/.gitkeep", "")
        archive.writestr("logs/.gitkeep", "")
        archive.writestr("tools/.gitkeep", "")

    write_dependency_inventory(output_dir)
    commercial_readiness = build_commercial_readiness_report(output_dir=output_dir)
    write_packaging_plan(output_dir)
    write_update_manifest(output_dir)
    write_release_manifest(output_dir, repo, commercial_readiness)
    write_sha256s(output_dir)

    print(f"Built portable zip: {portable_zip}")
    print(f"Wrote checksums: {output_dir / 'SHA256SUMS'}")
    print(f"Wrote release manifest: {output_dir / 'release-manifest.json'}")
    return 0


def add_if_exists(archive: zipfile.ZipFile, path: Path, arcname: str) -> None:
    if path.is_file():
        archive.write(path, arcname)


def add_tree(archive: zipfile.ZipFile, root: Path, arcroot: str) -> None:
    if not root.is_dir():
        return
    for path in sorted(root.rglob("*")):
        if path.is_file():
            archive.write(path, f"{arcroot}/{path.relative_to(root)}")


def write_dependency_inventory(output_dir: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "pip", "freeze"],
        text=True,
        capture_output=True,
        check=False,
    )
    inventory = output_dir / "dependency-inventory.txt"
    header = [
        "# RapidTriage dependency inventory",
        f"# Python executable: {sys.executable}",
        f"# pip freeze exit code: {result.returncode}",
        "",
    ]
    body = result.stdout if result.stdout.strip() else result.stderr
    inventory.write_text("\n".join(header) + body, encoding="utf-8")


def write_sha256s(output_dir: Path) -> None:
    checksum_path = output_dir / "SHA256SUMS"
    rows: list[str] = []
    for path in sorted(output_dir.iterdir()):
        if not path.is_file() or path.name == checksum_path.name:
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        rows.append(f"{digest}  {path.name}")
    checksum_path.write_text("\n".join(rows) + ("\n" if rows else ""), encoding="utf-8")


def stable_release_sha256(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def build_release_evidence_slot_matrix(
    *,
    item_number: int,
    slots: dict[str, object],
    artifact_hashes: list[dict[str, object]],
) -> dict[str, object]:
    rows = []
    for name, slot in sorted(slots.items()):
        slot_payload = slot if isinstance(slot, dict) else {}
        row_core = {
            "slot_name": name,
            "status": str(slot_payload.get("status") or ""),
            "expected_material_hash": stable_release_sha256(str(slot_payload.get("expected_material") or "")),
            "required_before_commercial_claim": bool(slot_payload.get("required_before_commercial_claim")),
            "attached": str(slot_payload.get("status") or "") not in {"", "not-attached", "operator-owned"},
        }
        rows.append({**row_core, "row_hash": stable_release_sha256(row_core)})
    matrix: dict[str, object] = {
        "profile_version": "release-evidence-slot-matrix-v1",
        "item_number": item_number,
        "slot_count": len(rows),
        "rows": rows,
        "artifact_hash_count": len(artifact_hashes),
        "artifact_hash_set_hash": stable_release_sha256(artifact_hashes),
        "missing_required_slot_count": sum(
            1 for row in rows if row["required_before_commercial_claim"] and not row["attached"]
        ),
        "commercial_claim_allowed": False,
    }
    matrix["matrix_hash"] = stable_release_sha256(matrix)
    return matrix


def build_auto_update_channel_evidence_manifest(
    artifacts: list[dict[str, object]],
    trusted_diff: dict[str, object],
) -> dict[str, object]:
    release_artifact_hashes = [
        {
            "name": artifact.get("name"),
            "size_bytes": artifact.get("size_bytes"),
            "sha256": artifact.get("sha256"),
            "signature_required": artifact.get("signature_required"),
        }
        for artifact in artifacts
        if artifact.get("name")
    ]
    update_evidence_slots = {
        "signed_manifest": {
            "status": "not-attached",
            "expected_material": "Signed update manifest and signature verification transcript",
            "required_before_commercial_claim": True,
        },
        "hosted_channel": {
            "status": "not-attached",
            "expected_material": "Hosted update channel URL, TLS policy, and access-control review",
            "required_before_commercial_claim": True,
        },
        "rollback_test": {
            "status": "not-attached",
            "expected_material": "Rollback test transcript using previous and current release artifacts",
            "required_before_commercial_claim": True,
        },
        "enterprise_disable_smoke": {
            "status": "not-attached",
            "expected_material": "Enterprise policy smoke proving auto-update can be disabled",
            "required_before_commercial_claim": True,
        },
    }
    evidence_slot_matrix = build_release_evidence_slot_matrix(
        item_number=104,
        slots=update_evidence_slots,
        artifact_hashes=release_artifact_hashes,
    )
    manifest: dict[str, object] = {
        "profile_version": "auto-update-channel-evidence-manifest-v1",
        "item_number": 104,
        "commercial_gap_ids": [AUTO_UPDATE_CHANNEL_GAP_ID],
        "commercial_claim_allowed": False,
        "channel": "manual",
        "auto_update_enabled_by_default": False,
        "enterprise_disable": True,
        "release_artifact_hashes": release_artifact_hashes,
        "update_evidence_slots": update_evidence_slots,
        "evidence_slot_matrix": evidence_slot_matrix,
        "evidence_slot_matrix_hash": evidence_slot_matrix["matrix_hash"],
        "trusted_diff_status": trusted_diff.get("status"),
        "trusted_diff_blocker": trusted_diff.get("blocker"),
        "blockers": [AUTO_UPDATE_TRUSTED_DIFF_BLOCKER_104],
    }
    manifest["manifest_hash"] = stable_release_sha256(manifest)
    return manifest


def build_auto_update_report_grade_validation_plan(
    *,
    update_evidence_manifest: dict[str, object],
    artifacts: list[dict[str, object]],
    trusted_diff: dict[str, object],
    channel: str,
    enterprise_disable: bool,
    rollback_guidance: str,
    signature_policy: str,
) -> dict[str, object]:
    release_artifact_hashes = update_evidence_manifest.get("release_artifact_hashes")
    update_evidence_slots = (
        update_evidence_manifest.get("update_evidence_slots")
        if isinstance(update_evidence_manifest.get("update_evidence_slots"), Mapping)
        else {}
    )
    evidence_slot_matrix = (
        update_evidence_manifest.get("evidence_slot_matrix")
        if isinstance(update_evidence_manifest.get("evidence_slot_matrix"), Mapping)
        else {}
    )
    ready_slots: list[dict[str, object]] = []
    blocking_slots: list[dict[str, object]] = []

    def add_ready(slot_id: str, evidence: str, source: str) -> None:
        ready_slots.append(
            {
                "slot_id": slot_id,
                "status": "ready",
                "evidence": evidence,
                "source": source,
                "commercial_claim_material": False,
            }
        )

    def add_blocking(slot_id: str, blocker: str, required_evidence: str, owner: str = "release engineer") -> None:
        blocking_slots.append(
            {
                "slot_id": slot_id,
                "status": "external-evidence-required",
                "blocker": blocker,
                "required_evidence": required_evidence,
                "owner": owner,
                "commercial_claim_material": True,
            }
        )

    if artifacts:
        add_ready("release-artifact-inventory", "Release artifact inventory available for update manifest", "artifacts")
    else:
        add_blocking("release-artifact-inventory", "release-artifact-inventory-missing", "Release artifact inventory")
    if release_artifact_hashes:
        add_ready("release-artifact-hashes", "Update channel artifact hashes captured", "auto-update-evidence-manifest")
    else:
        add_blocking("release-artifact-hashes", "release-artifact-hashes-missing", "Update artifact hash inventory")
    if update_evidence_manifest.get("manifest_hash"):
        add_ready("auto-update-evidence-manifest", "Auto-update evidence manifest hash emitted", "update-manifest")
    else:
        add_blocking(
            "auto-update-evidence-manifest",
            "auto-update-evidence-manifest-hash-missing",
            "auto-update-channel-evidence-manifest-v1 hash",
        )
    if update_evidence_manifest.get("evidence_slot_matrix_hash") and evidence_slot_matrix.get("rows"):
        add_ready("auto-update-evidence-slot-matrix", "Evidence slot matrix rows and hash emitted", "update-manifest")
    else:
        add_blocking(
            "auto-update-evidence-slot-matrix",
            "auto-update-evidence-slot-matrix-missing",
            "release-evidence-slot-matrix-v1 rows and hash",
        )
    if channel == "manual":
        add_ready("manual-channel-boundary", "Manual update channel boundary declared", "update-manifest")
    if enterprise_disable:
        add_ready("enterprise-disable-policy", "Enterprise disable flag declared", "update-manifest")
    if rollback_guidance:
        add_ready("rollback-guidance", "Rollback guidance declared", "update-manifest")
    if signature_policy:
        add_ready("signature-policy", "Signature policy declared", "update-manifest")
    if trusted_diff.get("status"):
        add_ready("trusted-diff-boundary", "Trusted signed update channel diff status recorded", "trusted_auto_update_channel_diff")
    if update_evidence_slots:
        add_ready("update-slot-disclosure", "signed manifest, hosting, rollback, and enterprise-disable slots disclosed", "update_evidence_slots")

    if trusted_diff.get("status") != "pass":
        add_blocking(
            "trusted-auto-update-channel-diff",
            AUTO_UPDATE_TRUSTED_DIFF_BLOCKER_104,
            "Trusted signed update channel diff manifest",
        )
    required_external_slots = {
        "signed_manifest": (
            "signed-update-manifest-required",
            "Signed update manifest and signature verification transcript",
        ),
        "hosted_channel": (
            "hosted-update-channel-required",
            "Hosted update channel URL, TLS policy, and access-control review",
        ),
        "rollback_test": ("rollback-test-required", "Rollback test transcript using previous and current release artifacts"),
        "enterprise_disable_smoke": (
            "enterprise-disable-smoke-required",
            "Enterprise policy smoke proving auto-update can be disabled",
        ),
    }
    for slot_name, (blocker, required_evidence) in required_external_slots.items():
        slot = update_evidence_slots.get(slot_name) if isinstance(update_evidence_slots, Mapping) else {}
        if not isinstance(slot, Mapping) or slot.get("status") != "attached":
            add_blocking(slot_name, blocker, required_evidence)
    add_blocking(
        "update-client-implementation",
        "update-client-implementation-required",
        "Implemented update client/channel resolver or explicit manual-update-only commercial policy",
        owner="product/release engineering",
    )
    add_blocking(
        "release-artifact-signature",
        "release-artifact-signature-required",
        "Signed release artifacts referenced by the update channel",
    )

    blockers = sorted({str(slot.get("blocker")) for slot in blocking_slots if slot.get("blocker")})
    plan_core: dict[str, object] = {
        "profile_version": AUTO_UPDATE_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 104,
        "commercial_gap_ids": [AUTO_UPDATE_CHANNEL_GAP_ID],
        "commercial_claim_allowed": False,
        "reporting_boundary": (
            "Internal update artifacts prove manual-channel manifest readiness and evidence-slot disclosure only; "
            "auto-update claims require the blocking hosted signed-channel, rollback, and client evidence."
        ),
        "channel": channel,
        "auto_update_enabled_by_default": False,
        "enterprise_disable": enterprise_disable,
        "release_artifact_hashes": release_artifact_hashes or [],
        "auto_update_evidence_manifest_hash": update_evidence_manifest.get("manifest_hash"),
        "evidence_slot_matrix_hash": update_evidence_manifest.get("evidence_slot_matrix_hash"),
        "trusted_diff_status": trusted_diff.get("status"),
        "trusted_diff_blocker": trusted_diff.get("blocker"),
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "external_blocker_catalog": AUTO_UPDATE_REPORT_GRADE_BLOCKERS,
        "blockers": blockers,
    }
    plan = dict(plan_core)
    plan["validation_plan_sha256"] = stable_release_sha256(plan_core)
    return plan


def build_windows_signing_evidence_manifest(
    artifacts: list[dict[str, object]],
    trusted_diff: dict[str, object],
) -> dict[str, object]:
    release_artifact_hashes = [
        {
            "name": artifact.get("name"),
            "size_bytes": artifact.get("size_bytes"),
            "sha256": artifact.get("sha256"),
        }
        for artifact in artifacts
        if artifact.get("name")
    ]
    signing_slots = {
        "signature_log": {
            "status": "not-attached",
            "expected_material": "Get-AuthenticodeSignature output for each Windows installer artifact",
            "required_before_commercial_claim": True,
        },
        "timestamp_authority": {
            "status": "not-attached",
            "expected_material": "Trusted timestamp authority proof attached to the Authenticode signature",
            "required_before_commercial_claim": True,
        },
        "fresh_windows_smoke": {
            "status": "not-attached",
            "expected_material": "Fresh Windows 11 install/run smoke output folder and summary log",
            "required_before_commercial_claim": True,
        },
    }
    evidence_slot_matrix = build_release_evidence_slot_matrix(
        item_number=101,
        slots=signing_slots,
        artifact_hashes=release_artifact_hashes,
    )
    manifest: dict[str, object] = {
        "profile_version": "windows-signing-evidence-manifest-v1",
        "item_number": 101,
        "commercial_gap_ids": [WINDOWS_SIGNED_INSTALLER_GAP_ID],
        "commercial_claim_allowed": False,
        "target_outputs": [
            "rapidtriage-portable.zip",
            "future rapidtriage-installer.msi",
            "future rapidtriage-setup.exe",
        ],
        "release_artifact_hashes": release_artifact_hashes,
        "signing_slots": signing_slots,
        "evidence_slot_matrix": evidence_slot_matrix,
        "evidence_slot_matrix_hash": evidence_slot_matrix["matrix_hash"],
        "trusted_diff_status": trusted_diff.get("status"),
        "trusted_diff_blocker": trusted_diff.get("blocker"),
        "blockers": [WINDOWS_SIGNING_TRUSTED_DIFF_BLOCKER_101],
    }
    manifest["manifest_hash"] = stable_release_sha256(manifest)
    return manifest


def build_windows_installer_workflow_manifest(
    artifacts: list[dict[str, object]],
    signing_manifest: dict[str, object],
) -> dict[str, object]:
    payload_hashes = [
        {
            "name": artifact.get("name"),
            "size_bytes": artifact.get("size_bytes"),
            "sha256": artifact.get("sha256"),
        }
        for artifact in artifacts
        if artifact.get("name") in {"rapidtriage-portable.zip", "dependency-inventory.txt", "SHA256SUMS"}
        or str(artifact.get("name") or "").endswith((".whl", ".tar.gz"))
    ]
    manifest: dict[str, object] = {
        "profile_version": "windows-installer-workflow-manifest-v1",
        "item_number": 57,
        "commercial_gap_ids": [WINDOWS_SIGNED_INSTALLER_GAP_ID],
        "commercial_claim_allowed": False,
        "target_outputs": ["rapidtriage-installer.msi", "rapidtriage-setup.exe", "rapidtriage-portable.zip"],
        "payload_hashes": payload_hashes,
        "launcher_entries": [
            "scripts/windows/start-rapidtriage.ps1",
            "scripts/windows/smoke-test-rapidtriage.ps1",
            "scripts/windows/smoke-test-rapidtriage.bat",
        ],
        "installer_workflow_steps": [
            {"step": "assemble portable payload", "status": "implemented", "owner": "build-release.py"},
            {"step": "verify SHA256SUMS", "status": "implemented", "owner": "build-release.py --verify"},
            {"step": "wrap MSI/EXE", "status": "external-tool-required", "owner": "release engineer"},
            {"step": "attach Authenticode signature", "status": "external-evidence-required", "owner": "release engineer"},
            {"step": "attach trusted timestamp", "status": "external-evidence-required", "owner": "release engineer"},
            {"step": "run fresh Windows 11 smoke", "status": "external-evidence-required", "owner": "release QA"},
        ],
        "evidence_slots": {
            "installer_wrapper_log": {
                "status": "not-attached",
                "expected_material": "MSI/EXE wrapper build transcript and installer SHA256 values",
                "required_before_commercial_claim": True,
            },
            "authenticode_signature": signing_manifest.get("signing_slots", {}).get("signature_log", {}),
            "timestamp_authority": signing_manifest.get("signing_slots", {}).get("timestamp_authority", {}),
            "fresh_windows_smoke": signing_manifest.get("signing_slots", {}).get("fresh_windows_smoke", {}),
        },
        "verification_commands": [
            "python scripts/build-release.py --output-dir release --skip-build",
            "python scripts/build-release.py --output-dir release --verify",
            "powershell -ExecutionPolicy Bypass -File scripts/windows/smoke-test-rapidtriage.ps1",
            "Get-AuthenticodeSignature .\\rapidtriage-setup.exe",
        ],
        "blockers": [
            "actual-msi-exe-wrapper-not-attached",
            "authenticode-signature-not-attached",
            "timestamp-authority-not-attached",
            "fresh-windows-11-smoke-not-attached",
            WINDOWS_SIGNING_TRUSTED_DIFF_BLOCKER_101,
        ],
    }
    manifest["manifest_hash"] = stable_release_sha256(manifest)
    return manifest


def build_windows_signing_report_grade_validation_plan(
    *,
    signing_manifest: dict[str, object],
    workflow_manifest: dict[str, object],
    artifacts: list[dict[str, object]],
    trusted_diff: dict[str, object],
) -> dict[str, object]:
    artifact_names = {str(artifact.get("name") or "") for artifact in artifacts if artifact.get("name")}
    release_artifact_hashes = signing_manifest.get("release_artifact_hashes")
    signing_slots = signing_manifest.get("signing_slots") if isinstance(signing_manifest.get("signing_slots"), Mapping) else {}
    evidence_slot_matrix = (
        signing_manifest.get("evidence_slot_matrix")
        if isinstance(signing_manifest.get("evidence_slot_matrix"), Mapping)
        else {}
    )
    ready_slots: list[dict[str, object]] = []
    blocking_slots: list[dict[str, object]] = []

    def add_ready(slot_id: str, evidence: str, source: str) -> None:
        ready_slots.append(
            {
                "slot_id": slot_id,
                "status": "ready",
                "evidence": evidence,
                "source": source,
                "commercial_claim_material": False,
            }
        )

    def add_blocking(slot_id: str, blocker: str, required_evidence: str, owner: str = "release engineer") -> None:
        blocking_slots.append(
            {
                "slot_id": slot_id,
                "status": "external-evidence-required",
                "blocker": blocker,
                "required_evidence": required_evidence,
                "owner": owner,
                "commercial_claim_material": True,
            }
        )

    if "rapidtriage-portable.zip" in artifact_names:
        add_ready("portable-payload-present", "rapidtriage-portable.zip included in release artifacts", "artifacts")
    else:
        add_blocking("portable-payload-present", "portable-payload-missing", "rapidtriage-portable.zip release artifact")
    if release_artifact_hashes:
        add_ready("release-artifact-hashes", "release artifact SHA256 inventory captured", "windows-signing-evidence-manifest")
    else:
        add_blocking("release-artifact-hashes", "release-artifact-hashes-missing", "Release artifact hash inventory")
    if signing_manifest.get("manifest_hash"):
        add_ready("windows-signing-evidence-manifest", "Windows signing evidence manifest hash emitted", "release-manifest")
    else:
        add_blocking(
            "windows-signing-evidence-manifest",
            "windows-signing-evidence-manifest-hash-missing",
            "windows-signing-evidence-manifest-v1 hash",
        )
    if signing_manifest.get("evidence_slot_matrix_hash") and evidence_slot_matrix.get("rows"):
        add_ready("windows-signing-evidence-slot-matrix", "Evidence slot matrix rows and hash emitted", "release-manifest")
    else:
        add_blocking(
            "windows-signing-evidence-slot-matrix",
            "windows-signing-evidence-slot-matrix-missing",
            "release-evidence-slot-matrix-v1 rows and hash",
        )
    if workflow_manifest.get("manifest_hash"):
        add_ready("windows-installer-workflow-manifest", "Installer workflow manifest hash emitted", "release-manifest")
    else:
        add_blocking(
            "windows-installer-workflow-manifest",
            "windows-installer-workflow-manifest-missing",
            "windows-installer-workflow-manifest-v1 hash",
        )
    if workflow_manifest.get("launcher_entries"):
        add_ready("windows-launcher-and-smoke-scripts", "Windows launcher and smoke script entries declared", "workflow-manifest")
    else:
        add_blocking(
            "windows-launcher-and-smoke-scripts",
            "windows-launcher-smoke-scripts-missing",
            "Packaged Windows launcher and smoke scripts",
        )
    if workflow_manifest.get("verification_commands"):
        add_ready("windows-verification-commands", "Windows release verification commands declared", "workflow-manifest")
    else:
        add_blocking(
            "windows-verification-commands",
            "windows-verification-commands-missing",
            "Fresh Windows signing and smoke verification commands",
        )
    if trusted_diff.get("status"):
        add_ready("trusted-diff-boundary", "Trusted Windows signing diff status recorded", "trusted_windows_signing_diff")
    if signing_slots:
        add_ready("signing-slot-disclosure", "Authenticode, timestamp, and Windows smoke slots disclosed", "signing_slots")

    if trusted_diff.get("status") != "pass":
        add_blocking(
            "trusted-windows-signing-diff",
            WINDOWS_SIGNING_TRUSTED_DIFF_BLOCKER_101,
            "Trusted Authenticode signing evidence diff manifest",
        )
    required_external_slots = {
        "signature_log": (
            "authenticode-signature-required",
            "Get-AuthenticodeSignature transcript for every Windows installer artifact",
        ),
        "timestamp_authority": (
            "timestamp-authority-proof-required",
            "Timestamp authority proof bound to each Authenticode signature",
        ),
        "fresh_windows_smoke": (
            "fresh-windows-smoke-required",
            "Fresh Windows 11 install/run smoke summary and logs",
        ),
    }
    for slot_name, (blocker, required_evidence) in required_external_slots.items():
        slot = signing_slots.get(slot_name) if isinstance(signing_slots, Mapping) else {}
        if not isinstance(slot, Mapping) or slot.get("status") != "attached":
            add_blocking(slot_name, blocker, required_evidence)
    workflow_slots = workflow_manifest.get("evidence_slots") if isinstance(workflow_manifest.get("evidence_slots"), Mapping) else {}
    installer_slot = workflow_slots.get("installer_wrapper_log") if isinstance(workflow_slots, Mapping) else {}
    if not isinstance(installer_slot, Mapping) or installer_slot.get("status") != "attached":
        add_blocking(
            "installer-wrapper-log",
            "installer-wrapper-build-log-required",
            "MSI/EXE wrapper build transcript, output hashes, and installer metadata",
        )
    add_blocking(
        "certificate-chain-verification",
        "certificate-chain-verification-required",
        "Certificate chain validation transcript for the Windows signing certificate",
    )
    add_blocking(
        "windows-defender-smartscreen-review",
        "windows-defender-smartscreen-review-required",
        "Windows Defender and SmartScreen reputation/safety review notes for signed artifacts",
        owner="release QA",
    )

    blockers = sorted({str(slot.get("blocker")) for slot in blocking_slots if slot.get("blocker")})
    plan_core: dict[str, object] = {
        "profile_version": WINDOWS_SIGNING_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 101,
        "commercial_gap_ids": [WINDOWS_SIGNED_INSTALLER_GAP_ID],
        "commercial_claim_allowed": False,
        "reporting_boundary": (
            "Internal release artifacts prove payload inventory, evidence-slot disclosure, and workflow readiness only; "
            "a signed Windows installer claim requires the blocking external evidence to be attached."
        ),
        "target_outputs": signing_manifest.get("target_outputs", []),
        "release_artifact_hashes": release_artifact_hashes or [],
        "signing_evidence_manifest_hash": signing_manifest.get("manifest_hash"),
        "installer_workflow_manifest_hash": workflow_manifest.get("manifest_hash"),
        "evidence_slot_matrix_hash": signing_manifest.get("evidence_slot_matrix_hash"),
        "trusted_diff_status": trusted_diff.get("status"),
        "trusted_diff_blocker": trusted_diff.get("blocker"),
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "external_blocker_catalog": WINDOWS_SIGNING_REPORT_GRADE_BLOCKERS,
        "blockers": blockers,
    }
    plan = dict(plan_core)
    plan["validation_plan_sha256"] = stable_release_sha256(plan_core)
    return plan


def build_windows_portable_mode_manifest(output_dir: Path) -> dict[str, object]:
    portable_zip = output_dir / "rapidtriage-portable.zip"
    required_zip_entries = [
        "scripts/windows/start-rapidtriage.ps1",
        "scripts/windows/smoke-test-rapidtriage.ps1",
        "scripts/windows/smoke-test-rapidtriage.bat",
        "scripts/check-dependencies.py",
        "scripts/crash-export-smoke.py",
        "scripts/crash-redaction-review.py",
        "scripts/parser-sandbox-smoke.py",
        "scripts/security-hardening-review.py",
        "scripts/external-release-evidence-template.py",
        "scripts/hostile-evidence-containment-template.py",
        "scripts/independent-operations-evidence-template.py",
        "docs/rapidtriage-windows-quickstart.md",
        "docs/rapidtriage-fresh-machine-smoke-test.md",
    ]
    zip_entries: list[str] = []
    if portable_zip.is_file():
        with zipfile.ZipFile(portable_zip) as archive:
            zip_entries = sorted(archive.namelist())
    missing_entries = [entry for entry in required_zip_entries if entry not in zip_entries]
    manifest: dict[str, object] = {
        "profile_version": "windows-portable-mode-manifest-v1",
        "item_number": 58,
        "batch_id": FUNCTIONAL_PACKAGING_BATCH_ID,
        "target_output": "rapidtriage-portable.zip",
        "portable_zip_present": portable_zip.is_file(),
        "portable_zip_sha256": hashlib.sha256(portable_zip.read_bytes()).hexdigest() if portable_zip.is_file() else "",
        "dependency_inventory_present": (output_dir / "dependency-inventory.txt").is_file(),
        "sha256s_present": (output_dir / "SHA256SUMS").is_file(),
        "release_manifest_present": (output_dir / "release-manifest.json").is_file(),
        "required_zip_entries": required_zip_entries,
        "missing_zip_entries": missing_entries,
        "double_click_entrypoints": [
            "scripts/windows/start-rapidtriage.ps1",
            "scripts/windows/smoke-test-rapidtriage.bat",
        ],
        "preflight_commands": [
            "python scripts/check-dependencies.py --json",
            "python scripts/crash-export-smoke.py --output-dir logs/crash-export-smoke --json",
            "python scripts/crash-redaction-review.py logs/crash-export-smoke/crash-export-smoke.json --json",
            "python scripts/parser-sandbox-smoke.py --output logs/parser-sandbox-smoke.json --json",
            "python scripts/security-hardening-review.py --output logs/security-hardening-review.json --json",
            "python scripts/external-release-evidence-template.py --output logs/external-commercial-evidence.json --json",
            "python scripts/hostile-evidence-containment-template.py --output logs/hostile-evidence-containment.json --json",
            "python scripts/independent-operations-evidence-template.py --output logs/independent-operations-evidence.json --json",
            "python scripts/build-release.py --verify",
            "powershell -ExecutionPolicy Bypass -File scripts/windows/smoke-test-rapidtriage.ps1",
        ],
        "large_data_controls": {
            "evidence_storage_inside_zip": False,
            "cases_directory_placeholder": "cases/.gitkeep" in zip_entries,
            "logs_directory_placeholder": "logs/.gitkeep" in zip_entries,
            "tools_directory_placeholder": "tools/.gitkeep" in zip_entries,
            "optional_forensic_tools_preflighted": True,
        },
        "commercial_blockers": [
            "fresh-windows-portable-smoke-not-attached",
            "clean-windows-no-developer-tools-smoke-not-attached",
        ],
        "validation_status": "implemented-usable-external-smoke-required",
    }
    manifest["manifest_hash"] = stable_release_sha256(manifest)
    return manifest


def build_macos_notarization_evidence_manifest(
    artifacts: list[dict[str, object]],
    trusted_diff: dict[str, object],
) -> dict[str, object]:
    release_artifact_hashes = [
        {
            "name": artifact.get("name"),
            "size_bytes": artifact.get("size_bytes"),
            "sha256": artifact.get("sha256"),
        }
        for artifact in artifacts
        if artifact.get("name")
    ]
    notarization_slots = {
        "codesign_verification": {
            "status": "not-attached",
            "expected_material": "codesign --verify --deep --strict output for each macOS package/app artifact",
            "required_before_commercial_claim": True,
        },
        "notarytool_submission": {
            "status": "not-attached",
            "expected_material": "Apple notarytool submission ID, status, and ticket proof",
            "required_before_commercial_claim": True,
        },
        "gatekeeper_assessment": {
            "status": "not-attached",
            "expected_material": "spctl Gatekeeper assessment output on a clean macOS host",
            "required_before_commercial_claim": True,
        },
        "fresh_macos_smoke": {
            "status": "not-attached",
            "expected_material": "Fresh macOS install/run smoke output folder and summary log",
            "required_before_commercial_claim": True,
        },
    }
    evidence_slot_matrix = build_release_evidence_slot_matrix(
        item_number=102,
        slots=notarization_slots,
        artifact_hashes=release_artifact_hashes,
    )
    manifest: dict[str, object] = {
        "profile_version": "macos-notarization-evidence-manifest-v1",
        "item_number": 102,
        "commercial_gap_ids": [MACOS_NOTARIZED_PACKAGE_GAP_ID],
        "commercial_claim_allowed": False,
        "target_outputs": [
            "future rapidtriage.pkg",
            "future rapidtriage.dmg",
        ],
        "release_artifact_hashes": release_artifact_hashes,
        "notarization_slots": notarization_slots,
        "evidence_slot_matrix": evidence_slot_matrix,
        "evidence_slot_matrix_hash": evidence_slot_matrix["matrix_hash"],
        "trusted_diff_status": trusted_diff.get("status"),
        "trusted_diff_blocker": trusted_diff.get("blocker"),
        "blockers": [MACOS_NOTARIZATION_TRUSTED_DIFF_BLOCKER_102],
    }
    manifest["manifest_hash"] = stable_release_sha256(manifest)
    return manifest


def build_macos_package_workflow_manifest(
    artifacts: list[dict[str, object]],
    notarization_manifest: dict[str, object],
) -> dict[str, object]:
    payload_hashes = [
        {
            "name": artifact.get("name"),
            "size_bytes": artifact.get("size_bytes"),
            "sha256": artifact.get("sha256"),
        }
        for artifact in artifacts
        if artifact.get("name") == "rapidtriage-portable.zip"
        or str(artifact.get("name") or "").endswith((".whl", ".tar.gz"))
    ]
    manifest: dict[str, object] = {
        "profile_version": "macos-package-workflow-manifest-v1",
        "item_number": 59,
        "commercial_gap_ids": [MACOS_NOTARIZED_PACKAGE_GAP_ID],
        "commercial_claim_allowed": False,
        "target_outputs": ["rapidtriage.pkg", "rapidtriage.dmg", "rapidtriage-portable.zip"],
        "payload_hashes": payload_hashes,
        "launcher_entries": [
            "scripts/start-rapidtriage.sh",
            "scripts/smoke-test-rapidtriage.sh",
        ],
        "package_workflow_steps": [
            {"step": "assemble portable payload", "status": "implemented", "owner": "build-release.py"},
            {"step": "wrap pkg/dmg", "status": "external-tool-required", "owner": "release engineer"},
            {"step": "codesign app/package", "status": "external-evidence-required", "owner": "release engineer"},
            {"step": "submit notarization", "status": "external-evidence-required", "owner": "release engineer"},
            {"step": "run Gatekeeper assessment", "status": "external-evidence-required", "owner": "release QA"},
            {"step": "run fresh macOS smoke", "status": "external-evidence-required", "owner": "release QA"},
        ],
        "evidence_slots": {
            "pkg_dmg_build_log": {
                "status": "not-attached",
                "expected_material": "pkg/dmg wrapper build transcript plus package SHA256 values",
                "required_before_commercial_claim": True,
            },
            "codesign_verification": notarization_manifest.get("notarization_slots", {}).get("codesign_verification", {}),
            "notarization_ticket": notarization_manifest.get("notarization_slots", {}).get("notarization_ticket", {}),
            "gatekeeper_assessment": notarization_manifest.get("notarization_slots", {}).get("gatekeeper_assessment", {}),
        },
        "verification_commands": [
            "python scripts/build-release.py --output-dir release --skip-build",
            "pkgutil --check-signature rapidtriage.pkg",
            "codesign --verify --deep --strict rapidtriage.app",
            "spctl --assess --type open --verbose rapidtriage.dmg",
            "xcrun notarytool history",
        ],
        "blockers": [
            "actual-pkg-dmg-wrapper-not-attached",
            "codesign-verification-not-attached",
            "notarization-ticket-not-attached",
            "gatekeeper-assessment-not-attached",
            MACOS_NOTARIZATION_TRUSTED_DIFF_BLOCKER_102,
        ],
    }
    manifest["manifest_hash"] = stable_release_sha256(manifest)
    return manifest


def build_macos_notarization_report_grade_validation_plan(
    *,
    notarization_manifest: dict[str, object],
    workflow_manifest: dict[str, object],
    artifacts: list[dict[str, object]],
    trusted_diff: dict[str, object],
) -> dict[str, object]:
    artifact_names = {str(artifact.get("name") or "") for artifact in artifacts if artifact.get("name")}
    release_artifact_hashes = notarization_manifest.get("release_artifact_hashes")
    notarization_slots = (
        notarization_manifest.get("notarization_slots")
        if isinstance(notarization_manifest.get("notarization_slots"), Mapping)
        else {}
    )
    evidence_slot_matrix = (
        notarization_manifest.get("evidence_slot_matrix")
        if isinstance(notarization_manifest.get("evidence_slot_matrix"), Mapping)
        else {}
    )
    ready_slots: list[dict[str, object]] = []
    blocking_slots: list[dict[str, object]] = []

    def add_ready(slot_id: str, evidence: str, source: str) -> None:
        ready_slots.append(
            {
                "slot_id": slot_id,
                "status": "ready",
                "evidence": evidence,
                "source": source,
                "commercial_claim_material": False,
            }
        )

    def add_blocking(slot_id: str, blocker: str, required_evidence: str, owner: str = "release engineer") -> None:
        blocking_slots.append(
            {
                "slot_id": slot_id,
                "status": "external-evidence-required",
                "blocker": blocker,
                "required_evidence": required_evidence,
                "owner": owner,
                "commercial_claim_material": True,
            }
        )

    if "rapidtriage-portable.zip" in artifact_names:
        add_ready("portable-payload-present", "rapidtriage-portable.zip included in release artifacts", "artifacts")
    else:
        add_blocking("portable-payload-present", "portable-payload-missing", "rapidtriage-portable.zip release artifact")
    if release_artifact_hashes:
        add_ready(
            "release-artifact-hashes",
            "release artifact SHA256 inventory captured",
            "macos-notarization-evidence-manifest",
        )
    else:
        add_blocking("release-artifact-hashes", "release-artifact-hashes-missing", "Release artifact hash inventory")
    if notarization_manifest.get("manifest_hash"):
        add_ready(
            "macos-notarization-evidence-manifest",
            "macOS notarization evidence manifest hash emitted",
            "release-manifest",
        )
    else:
        add_blocking(
            "macos-notarization-evidence-manifest",
            "macos-notarization-evidence-manifest-hash-missing",
            "macos-notarization-evidence-manifest-v1 hash",
        )
    if notarization_manifest.get("evidence_slot_matrix_hash") and evidence_slot_matrix.get("rows"):
        add_ready("macos-notarization-evidence-slot-matrix", "Evidence slot matrix rows and hash emitted", "release-manifest")
    else:
        add_blocking(
            "macos-notarization-evidence-slot-matrix",
            "macos-notarization-evidence-slot-matrix-missing",
            "release-evidence-slot-matrix-v1 rows and hash",
        )
    if workflow_manifest.get("manifest_hash"):
        add_ready("macos-package-workflow-manifest", "macOS package workflow manifest hash emitted", "release-manifest")
    else:
        add_blocking(
            "macos-package-workflow-manifest",
            "macos-package-workflow-manifest-missing",
            "macos-package-workflow-manifest-v1 hash",
        )
    if workflow_manifest.get("launcher_entries"):
        add_ready("macos-launcher-and-smoke-scripts", "macOS launcher and smoke script entries declared", "workflow-manifest")
    else:
        add_blocking(
            "macos-launcher-and-smoke-scripts",
            "macos-launcher-smoke-scripts-missing",
            "Packaged macOS launcher and smoke scripts",
        )
    if workflow_manifest.get("verification_commands"):
        add_ready("macos-verification-commands", "macOS release verification commands declared", "workflow-manifest")
    else:
        add_blocking(
            "macos-verification-commands",
            "macos-verification-commands-missing",
            "codesign, notarytool, Gatekeeper, and smoke verification commands",
        )
    if trusted_diff.get("status"):
        add_ready("trusted-diff-boundary", "Trusted macOS notarization diff status recorded", "trusted_macos_notarization_diff")
    if notarization_slots:
        add_ready("notarization-slot-disclosure", "codesign, notarytool, Gatekeeper, and smoke slots disclosed", "notarization_slots")

    if trusted_diff.get("status") != "pass":
        add_blocking(
            "trusted-macos-notarization-diff",
            MACOS_NOTARIZATION_TRUSTED_DIFF_BLOCKER_102,
            "Trusted macOS notarization evidence diff manifest",
        )
    required_external_slots = {
        "codesign_verification": (
            "codesign-verification-required",
            "codesign --verify --deep --strict transcript for macOS artifacts",
        ),
        "notarytool_submission": (
            "notarytool-submission-proof-required",
            "Apple notarytool submission ID, status, and log transcript",
        ),
        "gatekeeper_assessment": (
            "gatekeeper-assessment-required",
            "spctl Gatekeeper assessment transcript on a clean macOS host",
        ),
        "fresh_macos_smoke": (
            "fresh-macos-smoke-required",
            "Fresh macOS install/run smoke summary and logs",
        ),
    }
    for slot_name, (blocker, required_evidence) in required_external_slots.items():
        slot = notarization_slots.get(slot_name) if isinstance(notarization_slots, Mapping) else {}
        if not isinstance(slot, Mapping) or slot.get("status") != "attached":
            add_blocking(slot_name, blocker, required_evidence)
    workflow_slots = workflow_manifest.get("evidence_slots") if isinstance(workflow_manifest.get("evidence_slots"), Mapping) else {}
    wrapper_slot = workflow_slots.get("pkg_dmg_build_log") if isinstance(workflow_slots, Mapping) else {}
    if not isinstance(wrapper_slot, Mapping) or wrapper_slot.get("status") != "attached":
        add_blocking(
            "pkg-dmg-wrapper-log",
            "pkg-dmg-wrapper-build-log-required",
            "pkg/dmg wrapper build transcript, output hashes, and package metadata",
        )
    add_blocking(
        "notarization-ticket-staple",
        "notarization-ticket-staple-required",
        "Stapled notarization ticket proof or accepted equivalent release policy",
    )
    add_blocking(
        "apple-developer-id-certificate",
        "apple-developer-id-certificate-required",
        "Apple Developer ID certificate identity and chain verification transcript",
    )

    blockers = sorted({str(slot.get("blocker")) for slot in blocking_slots if slot.get("blocker")})
    plan_core: dict[str, object] = {
        "profile_version": MACOS_NOTARIZATION_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 102,
        "commercial_gap_ids": [MACOS_NOTARIZED_PACKAGE_GAP_ID],
        "commercial_claim_allowed": False,
        "reporting_boundary": (
            "Internal release artifacts prove payload inventory, evidence-slot disclosure, and workflow readiness only; "
            "a notarized macOS package claim requires the blocking external Apple signing/notarization evidence."
        ),
        "target_outputs": notarization_manifest.get("target_outputs", []),
        "release_artifact_hashes": release_artifact_hashes or [],
        "notarization_evidence_manifest_hash": notarization_manifest.get("manifest_hash"),
        "package_workflow_manifest_hash": workflow_manifest.get("manifest_hash"),
        "evidence_slot_matrix_hash": notarization_manifest.get("evidence_slot_matrix_hash"),
        "trusted_diff_status": trusted_diff.get("status"),
        "trusted_diff_blocker": trusted_diff.get("blocker"),
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "external_blocker_catalog": MACOS_NOTARIZATION_REPORT_GRADE_BLOCKERS,
        "blockers": blockers,
    }
    plan = dict(plan_core)
    plan["validation_plan_sha256"] = stable_release_sha256(plan_core)
    return plan


def build_linux_package_evidence_manifest(
    artifacts: list[dict[str, object]],
    trusted_diff: dict[str, object],
) -> dict[str, object]:
    release_artifact_hashes = [
        {
            "name": artifact.get("name"),
            "size_bytes": artifact.get("size_bytes"),
            "sha256": artifact.get("sha256"),
        }
        for artifact in artifacts
        if artifact.get("name")
    ]
    package_evidence_slots = {
        "deb_build_log": {
            "status": "not-attached",
            "expected_material": "Clean-container deb build log and generated package SHA256",
            "required_before_commercial_claim": True,
        },
        "rpm_build_log": {
            "status": "not-attached",
            "expected_material": "Clean-container rpm build log and generated package SHA256",
            "required_before_commercial_claim": True,
        },
        "appimage_build_log": {
            "status": "not-attached",
            "expected_material": "Clean-container AppImage build log and generated package SHA256",
            "required_before_commercial_claim": True,
        },
        "install_uninstall_smoke": {
            "status": "not-attached",
            "expected_material": "Fresh distro install, launch, smoke, and uninstall transcript",
            "required_before_commercial_claim": True,
        },
        "dependency_resolution": {
            "status": "not-attached",
            "expected_material": "Package-manager dependency resolution transcript on target distributions",
            "required_before_commercial_claim": True,
        },
    }
    evidence_slot_matrix = build_release_evidence_slot_matrix(
        item_number=103,
        slots=package_evidence_slots,
        artifact_hashes=release_artifact_hashes,
    )
    manifest: dict[str, object] = {
        "profile_version": "linux-package-evidence-manifest-v1",
        "item_number": 103,
        "commercial_gap_ids": [LINUX_PACKAGE_GAP_ID],
        "commercial_claim_allowed": False,
        "supported_outputs": ["rapidtriage-portable.zip", "wheel", "sdist"],
        "target_outputs": [
            "future rapidtriage.deb",
            "future rapidtriage.rpm",
            "future rapidtriage.AppImage",
        ],
        "release_artifact_hashes": release_artifact_hashes,
        "package_evidence_slots": package_evidence_slots,
        "evidence_slot_matrix": evidence_slot_matrix,
        "evidence_slot_matrix_hash": evidence_slot_matrix["matrix_hash"],
        "trusted_diff_status": trusted_diff.get("status"),
        "trusted_diff_blocker": trusted_diff.get("blocker"),
        "blockers": [LINUX_PACKAGE_TRUSTED_DIFF_BLOCKER_103],
    }
    manifest["manifest_hash"] = stable_release_sha256(manifest)
    return manifest


def build_linux_package_workflow_manifest(
    artifacts: list[dict[str, object]],
    package_manifest: dict[str, object],
) -> dict[str, object]:
    payload_hashes = [
        {
            "name": artifact.get("name"),
            "size_bytes": artifact.get("size_bytes"),
            "sha256": artifact.get("sha256"),
        }
        for artifact in artifacts
        if artifact.get("name") == "rapidtriage-portable.zip"
        or str(artifact.get("name") or "").endswith((".whl", ".tar.gz"))
    ]
    manifest: dict[str, object] = {
        "profile_version": "linux-package-workflow-manifest-v1",
        "item_number": 60,
        "commercial_gap_ids": [LINUX_PACKAGE_GAP_ID],
        "commercial_claim_allowed": False,
        "target_outputs": ["rapidtriage.deb", "rapidtriage.rpm", "RapidTriage.AppImage", "rapidtriage-portable.zip"],
        "payload_hashes": payload_hashes,
        "launcher_entries": [
            "scripts/start-rapidtriage.sh",
            "scripts/smoke-test-rapidtriage.sh",
        ],
        "package_workflow_steps": [
            {"step": "assemble portable payload", "status": "implemented", "owner": "build-release.py"},
            {"step": "build wheel/sdist", "status": "implemented-when-build-enabled", "owner": "python -m build"},
            {"step": "build deb", "status": "external-container-required", "owner": "release CI"},
            {"step": "build rpm", "status": "external-container-required", "owner": "release CI"},
            {"step": "build AppImage", "status": "external-container-required", "owner": "release CI"},
            {"step": "run install/uninstall smoke", "status": "external-evidence-required", "owner": "release QA"},
        ],
        "evidence_slots": {
            "deb_build_log": package_manifest.get("package_evidence_slots", {}).get("deb_build_log", {}),
            "rpm_build_log": package_manifest.get("package_evidence_slots", {}).get("rpm_build_log", {}),
            "appimage_build_log": package_manifest.get("package_evidence_slots", {}).get("appimage_build_log", {}),
            "clean_container_smoke": package_manifest.get("package_evidence_slots", {}).get("clean_container_smoke", {}),
            "install_uninstall_log": {
                "status": "not-attached",
                "expected_material": "Install, launch, smoke, and uninstall transcript for each target distribution",
                "required_before_commercial_claim": True,
            },
        },
        "verification_commands": [
            "python scripts/build-release.py --output-dir release --skip-build",
            "python scripts/build-release.py --output-dir release --verify",
            "dpkg -i rapidtriage.deb && rapidtriage --version && dpkg -r rapidtriage",
            "rpm -i rapidtriage.rpm && rapidtriage --version && rpm -e rapidtriage",
            "chmod +x RapidTriage.AppImage && ./RapidTriage.AppImage --version",
        ],
        "blockers": [
            "deb-build-log-not-attached",
            "rpm-build-log-not-attached",
            "appimage-build-log-not-attached",
            "clean-container-install-uninstall-smoke-not-attached",
            LINUX_PACKAGE_TRUSTED_DIFF_BLOCKER_103,
        ],
    }
    manifest["manifest_hash"] = stable_release_sha256(manifest)
    return manifest


def build_linux_package_report_grade_validation_plan(
    *,
    package_manifest: dict[str, object],
    workflow_manifest: dict[str, object],
    artifacts: list[dict[str, object]],
    trusted_diff: dict[str, object],
) -> dict[str, object]:
    artifact_names = {str(artifact.get("name") or "") for artifact in artifacts if artifact.get("name")}
    release_artifact_hashes = package_manifest.get("release_artifact_hashes")
    package_evidence_slots = (
        package_manifest.get("package_evidence_slots")
        if isinstance(package_manifest.get("package_evidence_slots"), Mapping)
        else {}
    )
    evidence_slot_matrix = (
        package_manifest.get("evidence_slot_matrix")
        if isinstance(package_manifest.get("evidence_slot_matrix"), Mapping)
        else {}
    )
    ready_slots: list[dict[str, object]] = []
    blocking_slots: list[dict[str, object]] = []

    def add_ready(slot_id: str, evidence: str, source: str) -> None:
        ready_slots.append(
            {
                "slot_id": slot_id,
                "status": "ready",
                "evidence": evidence,
                "source": source,
                "commercial_claim_material": False,
            }
        )

    def add_blocking(slot_id: str, blocker: str, required_evidence: str, owner: str = "release CI") -> None:
        blocking_slots.append(
            {
                "slot_id": slot_id,
                "status": "external-evidence-required",
                "blocker": blocker,
                "required_evidence": required_evidence,
                "owner": owner,
                "commercial_claim_material": True,
            }
        )

    if "rapidtriage-portable.zip" in artifact_names:
        add_ready("portable-payload-present", "rapidtriage-portable.zip included in release artifacts", "artifacts")
    else:
        add_blocking("portable-payload-present", "portable-payload-missing", "rapidtriage-portable.zip release artifact")
    if release_artifact_hashes:
        add_ready("release-artifact-hashes", "release artifact SHA256 inventory captured", "linux-package-evidence-manifest")
    else:
        add_blocking("release-artifact-hashes", "release-artifact-hashes-missing", "Release artifact hash inventory")
    if package_manifest.get("manifest_hash"):
        add_ready("linux-package-evidence-manifest", "Linux package evidence manifest hash emitted", "release-manifest")
    else:
        add_blocking(
            "linux-package-evidence-manifest",
            "linux-package-evidence-manifest-hash-missing",
            "linux-package-evidence-manifest-v1 hash",
        )
    if package_manifest.get("evidence_slot_matrix_hash") and evidence_slot_matrix.get("rows"):
        add_ready("linux-package-evidence-slot-matrix", "Evidence slot matrix rows and hash emitted", "release-manifest")
    else:
        add_blocking(
            "linux-package-evidence-slot-matrix",
            "linux-package-evidence-slot-matrix-missing",
            "release-evidence-slot-matrix-v1 rows and hash",
        )
    if workflow_manifest.get("manifest_hash"):
        add_ready("linux-package-workflow-manifest", "Linux package workflow manifest hash emitted", "release-manifest")
    else:
        add_blocking(
            "linux-package-workflow-manifest",
            "linux-package-workflow-manifest-missing",
            "linux-package-workflow-manifest-v1 hash",
        )
    if workflow_manifest.get("launcher_entries"):
        add_ready("linux-launcher-and-smoke-scripts", "Linux launcher and smoke script entries declared", "workflow-manifest")
    else:
        add_blocking(
            "linux-launcher-and-smoke-scripts",
            "linux-launcher-smoke-scripts-missing",
            "Packaged Linux launcher and smoke scripts",
        )
    if workflow_manifest.get("verification_commands"):
        add_ready("linux-verification-commands", "Linux package verification commands declared", "workflow-manifest")
    else:
        add_blocking(
            "linux-verification-commands",
            "linux-verification-commands-missing",
            "deb/rpm/AppImage install, launch, and uninstall verification commands",
        )
    if trusted_diff.get("status"):
        add_ready("trusted-diff-boundary", "Trusted Linux package smoke diff status recorded", "trusted_linux_package_diff")
    if package_evidence_slots:
        add_ready("package-slot-disclosure", "deb, rpm, AppImage, dependency, and smoke slots disclosed", "package_evidence_slots")

    if trusted_diff.get("status") != "pass":
        add_blocking(
            "trusted-linux-package-smoke-diff",
            LINUX_PACKAGE_TRUSTED_DIFF_BLOCKER_103,
            "Trusted Linux package build and smoke evidence diff manifest",
        )
    required_external_slots = {
        "deb_build_log": ("deb-build-log-required", "Clean-container deb build log and generated package SHA256"),
        "rpm_build_log": ("rpm-build-log-required", "Clean-container rpm build log and generated package SHA256"),
        "appimage_build_log": (
            "appimage-build-log-required",
            "Clean-container AppImage build log and generated package SHA256",
        ),
        "install_uninstall_smoke": (
            "install-uninstall-smoke-required",
            "Fresh distro install, launch, smoke, and uninstall transcript",
        ),
        "dependency_resolution": (
            "dependency-resolution-proof-required",
            "Package-manager dependency resolution transcript on target distributions",
        ),
    }
    for slot_name, (blocker, required_evidence) in required_external_slots.items():
        slot = package_evidence_slots.get(slot_name) if isinstance(package_evidence_slots, Mapping) else {}
        if not isinstance(slot, Mapping) or slot.get("status") != "attached":
            add_blocking(slot_name, blocker, required_evidence)
    add_blocking(
        "clean-container-build-log",
        "clean-container-build-log-required",
        "Container image digest, build command, and package output hashes for deb/rpm/AppImage builds",
    )
    add_blocking(
        "package-signing-policy",
        "package-signing-policy-required",
        "Distro package signing policy or explicit unsigned-package limitation approved for the release",
        owner="release engineer",
    )

    blockers = sorted({str(slot.get("blocker")) for slot in blocking_slots if slot.get("blocker")})
    plan_core: dict[str, object] = {
        "profile_version": LINUX_PACKAGE_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 103,
        "commercial_gap_ids": [LINUX_PACKAGE_GAP_ID],
        "commercial_claim_allowed": False,
        "reporting_boundary": (
            "Internal release artifacts prove portable payload, package evidence slots, and workflow readiness only; "
            "Linux deb/rpm/AppImage distribution claims require the blocking external build and smoke evidence."
        ),
        "supported_outputs": package_manifest.get("supported_outputs", []),
        "target_outputs": package_manifest.get("target_outputs", []),
        "release_artifact_hashes": release_artifact_hashes or [],
        "package_evidence_manifest_hash": package_manifest.get("manifest_hash"),
        "package_workflow_manifest_hash": workflow_manifest.get("manifest_hash"),
        "evidence_slot_matrix_hash": package_manifest.get("evidence_slot_matrix_hash"),
        "trusted_diff_status": trusted_diff.get("status"),
        "trusted_diff_blocker": trusted_diff.get("blocker"),
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "external_blocker_catalog": LINUX_PACKAGE_REPORT_GRADE_BLOCKERS,
        "blockers": blockers,
    }
    plan = dict(plan_core)
    plan["validation_plan_sha256"] = stable_release_sha256(plan_core)
    return plan


def build_operations_document_evidence_manifests(repo: Path, output_dir: Path) -> dict[str, dict[str, object]]:
    document_specs = {
        112: {
            "profile_version": "release-notes-discipline-evidence-manifest-v1",
            "gap_id": RELEASE_NOTES_CHANGELOG_GAP_ID,
            "documents": ["docs/rapidtriage-release-notes-template.md", "docs/rapidtriage-known-limitations.md"],
            "slots": {
                "ci_changelog_gate": "CI release-note gate proving changes, known limits, validation state, and migration notes are present",
                "release_owner_review": "Release owner review/signoff for changelog completeness",
            },
        },
        113: {
            "profile_version": "lts-hotfix-policy-evidence-manifest-v1",
            "gap_id": LTS_HOTFIX_POLICY_GAP_ID,
            "documents": ["docs/rapidtriage-lts-hotfix-policy.md"],
            "slots": {
                "maintained_branch_proof": "Maintained LTS branch and backport policy proof",
                "hotfix_backport_validation": "Hotfix backport validation transcript",
            },
        },
        114: {
            "profile_version": "support-sla-evidence-manifest-v1",
            "gap_id": SUPPORT_SLA_GAP_ID,
            "documents": ["docs/rapidtriage-support-sla.md"],
            "slots": {
                "staffed_support_attestation": "Staffed support desk attestation and escalation owner list",
                "secure_intake_review": "Secure evidence intake process review",
            },
        },
        115: {
            "profile_version": "training-delivery-evidence-manifest-v1",
            "gap_id": TRAINING_CURRICULUM_GAP_ID,
            "documents": ["docs/rapidtriage-training-curriculum.md"],
            "slots": {
                "training_delivery_log": "Real training delivery log",
                "scoring_rubric_results": "Analyst/admin lab scoring rubric results",
            },
        },
        116: {
            "profile_version": "quickstart-lab-evidence-manifest-v1",
            "gap_id": ANALYST_QUICKSTART_LAB_GAP_ID,
            "documents": [
                "docs/rapidtriage-training-curriculum.md",
                "docs/rapidtriage-windows-quickstart.md",
                "docs/rapidtriage-sample-case.md",
            ],
            "slots": {
                "quickstart_lab_run_log": "Analyst quickstart lab run log from ingest through report export",
                "sample_case_expected_outputs": "Sample case expected-output manifest",
            },
        },
        117: {
            "profile_version": "admin-deployment-evidence-manifest-v1",
            "gap_id": ADMIN_DEPLOYMENT_GUIDE_GAP_ID,
            "documents": ["docs/rapidtriage-admin-deployment-guide.md"],
            "slots": {
                "fresh_deployment_proof": "Fresh admin deployment proof with install/update/auth/backup checks",
                "operator_acceptance_signoff": "Operator acceptance signoff for deployment guide",
            },
        },
        118: {
            "profile_version": "security-hardening-evidence-manifest-v1",
            "gap_id": SECURITY_HARDENING_REVIEW_GAP_ID,
            "documents": ["docs/rapidtriage-security-policy.md", "docs/rapidtriage-admin-deployment-guide.md"],
            "slots": {
                "independent_appsec_review": "Independent AppSec review report",
                "threat_model_review": "Threat model/path/auth/export/parser hardening review",
            },
        },
        119: {
            "profile_version": "malicious-evidence-sandbox-evidence-manifest-v1",
            "gap_id": MALICIOUS_EVIDENCE_SANDBOXING_GAP_ID,
            "documents": ["docs/rapidtriage-admin-deployment-guide.md", "docs/rapidtriage-security-policy.md"],
            "slots": {
                "malicious_corpus_validation": "Trusted malicious evidence corpus validation",
                "os_sandbox_proof": "OS-level parser/preview sandbox proof",
            },
        },
        120: {
            "profile_version": "dependency-monitoring-evidence-manifest-v1",
            "gap_id": DEPENDENCY_VULNERABILITY_MONITORING_GAP_ID,
            "documents": ["scripts/check-dependencies.py", "dependency-inventory.txt"],
            "slots": {
                "scheduled_ci_advisory_scan": "Scheduled CI advisory scan log",
                "sbom_publication": "SBOM publication and release-blocking exception review",
            },
        },
    }
    manifests: dict[str, dict[str, object]] = {}
    for number, spec in document_specs.items():
        document_hashes = []
        for rel_path in spec["documents"]:
            path = repo / rel_path
            if not path.is_file():
                path = output_dir / rel_path
            if path.is_file():
                document_hashes.append({"path": rel_path, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size_bytes": path.stat().st_size})
            else:
                document_hashes.append({"path": rel_path, "status": "missing"})
        slots = {
            slot: {
                "status": "not-attached",
                "expected_material": expected,
                "required_before_commercial_claim": True,
            }
            for slot, expected in spec["slots"].items()
        }
        document_evidence_matrix = build_operations_document_evidence_matrix(
            number=number,
            document_hashes=document_hashes,
            slots=slots,
        )
        manifest: dict[str, object] = {
            "profile_version": spec["profile_version"],
            "item_number": number,
            "commercial_gap_ids": [spec["gap_id"]],
            "commercial_claim_allowed": False,
            "document_hashes": document_hashes,
            "evidence_slots": slots,
            "document_evidence_matrix": document_evidence_matrix,
            "document_evidence_matrix_hash": document_evidence_matrix["matrix_hash"],
            "blockers": [OPERATIONS_DOCUMENT_TRUSTED_DIFF_BLOCKERS[number]] if number in OPERATIONS_DOCUMENT_TRUSTED_DIFF_BLOCKERS else [],
        }
        manifest["manifest_hash"] = stable_release_sha256(manifest)
        manifests[str(number)] = manifest
    return manifests


def build_release_notes_report_grade_validation_plan(
    *,
    evidence_manifest: dict[str, object],
    release_discipline_manifest: dict[str, object],
    trusted_diff: dict[str, object],
) -> dict[str, object]:
    document_hashes = evidence_manifest.get("document_hashes") if isinstance(evidence_manifest.get("document_hashes"), list) else []
    evidence_slots = evidence_manifest.get("evidence_slots") if isinstance(evidence_manifest.get("evidence_slots"), dict) else {}
    section_checks = (
        release_discipline_manifest.get("section_checks")
        if isinstance(release_discipline_manifest.get("section_checks"), dict)
        else {}
    )
    ready_slots = [
        {
            "slot_id": "release-notes-template-document",
            "status": "ready",
            "evidence_ref": "docs/rapidtriage-release-notes-template.md",
            "evidence_hash": stable_release_sha256(
                [item for item in document_hashes if item.get("path") == "docs/rapidtriage-release-notes-template.md"]
            ),
        },
        {
            "slot_id": "known-limitations-document",
            "status": "ready",
            "evidence_ref": "docs/rapidtriage-known-limitations.md",
            "evidence_hash": stable_release_sha256(
                [item for item in document_hashes if item.get("path") == "docs/rapidtriage-known-limitations.md"]
            ),
        },
        {
            "slot_id": "release-notes-evidence-manifest",
            "status": "ready",
            "evidence_ref": "release-manifest.package_readiness.operations_documents.document_evidence_manifest_hashes.112",
            "evidence_hash": str(evidence_manifest.get("manifest_hash") or ""),
        },
        {
            "slot_id": "release-notes-document-evidence-matrix",
            "status": "ready",
            "evidence_ref": "release-manifest.package_readiness.operations_documents.document_evidence_matrix_hashes.112",
            "evidence_hash": str(evidence_manifest.get("document_evidence_matrix_hash") or ""),
        },
        {
            "slot_id": "release-discipline-manifest",
            "status": "ready",
            "evidence_ref": "release-discipline-manifest.json",
            "evidence_hash": str(release_discipline_manifest.get("manifest_hash") or ""),
        },
        {
            "slot_id": "required-release-sections",
            "status": "ready",
            "evidence_ref": "release-discipline-manifest.section_checks",
            "evidence_hash": stable_release_sha256(section_checks),
        },
        {
            "slot_id": "checksum-and-manifest-file-status",
            "status": "ready",
            "evidence_ref": "release-discipline-manifest.required_file_statuses",
            "evidence_hash": stable_release_sha256(release_discipline_manifest.get("required_file_statuses", [])),
        },
        {
            "slot_id": "trusted-release-notes-diff-boundary",
            "status": "ready" if trusted_diff.get("status") == "pass" else "ready-with-blocker",
            "evidence_ref": "release-manifest.package_readiness.operations_documents.trusted_operations_document_diffs.112",
            "evidence_hash": stable_release_sha256(trusted_diff),
        },
    ]
    blocking_slots = []
    if trusted_diff.get("status") != "pass":
        blocking_slots.append(
            {
                "slot_id": "trusted-release-notes-ci-gate-diff",
                "status": "blocking",
                "blocker": OPERATIONS_DOCUMENT_TRUSTED_DIFF_BLOCKERS[112],
                "required_evidence": "trusted CI gate output comparing release notes, known limits, validation state, migration notes, and checksums",
            }
        )
    for slot_id, blocker, required_evidence in (
        (
            "ci-changelog-gate",
            "ci-changelog-gate-required",
            "CI job proving release notes include changes, known limits, validation state, migration notes, and checksum references",
        ),
        (
            "release-owner-review",
            "release-owner-review-required",
            "release owner signoff for changelog completeness and blocked commercial claims",
        ),
        (
            "migration-note-review",
            "migration-note-review-required",
            "review proving migration notes are accurate for Case DB and artifact schema changes",
        ),
        (
            "validation-state-review",
            "validation-state-review-required",
            "review proving validation status and known limitations match attached release evidence",
        ),
        (
            "checksum-publication-review",
            "checksum-publication-review-required",
            "review proving release manifest and SHA256SUMS are published with the release notes",
        ),
        (
            "release-host-smoke-log",
            "release-host-smoke-log-required",
            "release-host smoke log attached to the release notes before report-grade distribution claims",
        ),
        (
            "independent-release-notes-review",
            "independent-release-notes-review-required",
            "independent reviewer confirmation that release notes do not overclaim validation or commercial parity",
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
        "profile_version": RELEASE_NOTES_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 112,
        "commercial_gap_ids": [RELEASE_NOTES_CHANGELOG_GAP_ID],
        "commercial_claim_allowed": False,
        "document_count": len(document_hashes),
        "evidence_slot_count": len(evidence_slots),
        "section_checks_hash": stable_release_sha256(section_checks),
        "release_notes_evidence_manifest_hash": str(evidence_manifest.get("manifest_hash") or ""),
        "operations_document_evidence_matrix_hash": str(evidence_manifest.get("document_evidence_matrix_hash") or ""),
        "release_discipline_manifest_hash": str(release_discipline_manifest.get("manifest_hash") or ""),
        "trusted_diff_status": str(trusted_diff.get("status") or ""),
        "trusted_diff_blocker": trusted_diff.get("blocker"),
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "external_blocker_catalog": list(RELEASE_NOTES_REPORT_GRADE_BLOCKERS),
        "blockers": blockers,
        "reporting_boundary": (
            "Release notes templates and packaged evidence are present; report-grade release claims require an "
            "enforced CI changelog gate, owner review, migration/validation state review, checksum publication, "
            "release-host smoke evidence, and independent wording review."
        ),
    }
    plan["validation_plan_hash"] = stable_release_sha256(plan)
    return plan


def build_lts_hotfix_report_grade_validation_plan(
    *,
    evidence_manifest: dict[str, object],
    trusted_diff: dict[str, object],
) -> dict[str, object]:
    document_hashes = evidence_manifest.get("document_hashes") if isinstance(evidence_manifest.get("document_hashes"), list) else []
    evidence_slots = evidence_manifest.get("evidence_slots") if isinstance(evidence_manifest.get("evidence_slots"), dict) else {}
    ready_slots = [
        {
            "slot_id": "lts-hotfix-policy-document",
            "status": "ready",
            "evidence_ref": "docs/rapidtriage-lts-hotfix-policy.md",
            "evidence_hash": stable_release_sha256(document_hashes),
        },
        {
            "slot_id": "lts-hotfix-evidence-manifest",
            "status": "ready",
            "evidence_ref": "release-manifest.package_readiness.operations_documents.document_evidence_manifest_hashes.113",
            "evidence_hash": str(evidence_manifest.get("manifest_hash") or ""),
        },
        {
            "slot_id": "lts-hotfix-document-evidence-matrix",
            "status": "ready",
            "evidence_ref": "release-manifest.package_readiness.operations_documents.document_evidence_matrix_hashes.113",
            "evidence_hash": str(evidence_manifest.get("document_evidence_matrix_hash") or ""),
        },
        {
            "slot_id": "maintained-branch-proof-boundary",
            "status": "ready-with-blocker",
            "evidence_ref": "release-manifest.package_readiness.operations_documents.document_evidence_slots.113.maintained_branch_proof",
            "evidence_hash": stable_release_sha256(evidence_slots.get("maintained_branch_proof", {})),
        },
        {
            "slot_id": "hotfix-backport-validation-boundary",
            "status": "ready-with-blocker",
            "evidence_ref": "release-manifest.package_readiness.operations_documents.document_evidence_slots.113.hotfix_backport_validation",
            "evidence_hash": stable_release_sha256(evidence_slots.get("hotfix_backport_validation", {})),
        },
        {
            "slot_id": "trusted-lts-hotfix-diff-boundary",
            "status": "ready" if trusted_diff.get("status") == "pass" else "ready-with-blocker",
            "evidence_ref": "release-manifest.package_readiness.operations_documents.trusted_operations_document_diffs.113",
            "evidence_hash": stable_release_sha256(trusted_diff),
        },
    ]
    blocking_slots = []
    if trusted_diff.get("status") != "pass":
        blocking_slots.append(
            {
                "slot_id": "trusted-lts-hotfix-policy-diff",
                "status": "blocking",
                "blocker": OPERATIONS_DOCUMENT_TRUSTED_DIFF_BLOCKERS[113],
                "required_evidence": "trusted LTS/hotfix policy review comparing branch policy, backport validation, and release gating",
            }
        )
    for slot_id, blocker, required_evidence in (
        (
            "maintained-branch-proof",
            "maintained-branch-proof-required",
            "operator-maintained LTS branch proof with branch name, protection status, and supported version window",
        ),
        (
            "hotfix-backport-validation",
            "hotfix-backport-validation-required",
            "hotfix backport validation transcript tying patch, tests, and release notes to affected branches",
        ),
        (
            "emergency-patch-drill",
            "emergency-patch-drill-required",
            "emergency patch drill proving triage, fix, validation, and release timing can meet policy",
        ),
        (
            "release-owner-hotfix-signoff",
            "release-owner-hotfix-signoff-required",
            "release owner signoff for hotfix scope, risk, rollback, and customer notice wording",
        ),
        (
            "lts-branch-policy-review",
            "lts-branch-policy-review-required",
            "review confirming branch rules, support windows, and backport criteria are current for this release",
        ),
        (
            "release-host-hotfix-smoke",
            "release-host-hotfix-smoke-required",
            "release-host smoke log for the hotfix/LTS package path before support claims are made",
        ),
        (
            "independent-lts-policy-review",
            "independent-lts-policy-review-required",
            "independent reviewer confirmation of LTS/hotfix policy operation and evidence completeness",
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
        "profile_version": LTS_HOTFIX_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 113,
        "commercial_gap_ids": [LTS_HOTFIX_POLICY_GAP_ID],
        "commercial_claim_allowed": False,
        "document_count": len(document_hashes),
        "evidence_slot_count": len(evidence_slots),
        "lts_hotfix_evidence_manifest_hash": str(evidence_manifest.get("manifest_hash") or ""),
        "operations_document_evidence_matrix_hash": str(evidence_manifest.get("document_evidence_matrix_hash") or ""),
        "trusted_diff_status": str(trusted_diff.get("status") or ""),
        "trusted_diff_blocker": trusted_diff.get("blocker"),
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "external_blocker_catalog": list(LTS_HOTFIX_REPORT_GRADE_BLOCKERS),
        "blockers": blockers,
        "reporting_boundary": (
            "The LTS/hotfix policy document is packaged; commercial support claims require maintained branch "
            "proof, backport validation, emergency patch drills, release-owner signoff, release-host smoke, "
            "and independent review evidence."
        ),
    }
    plan["validation_plan_hash"] = stable_release_sha256(plan)
    return plan


def build_support_sla_report_grade_validation_plan(
    *,
    evidence_manifest: dict[str, object],
    support_process_readiness_manifest: dict[str, object],
    trusted_diff: dict[str, object],
) -> dict[str, object]:
    document_hashes = evidence_manifest.get("document_hashes") if isinstance(evidence_manifest.get("document_hashes"), list) else []
    evidence_slots = evidence_manifest.get("evidence_slots") if isinstance(evidence_manifest.get("evidence_slots"), dict) else {}
    readiness_checks = (
        support_process_readiness_manifest.get("readiness_checks")
        if isinstance(support_process_readiness_manifest.get("readiness_checks"), dict)
        else {}
    )
    ready_slots = [
        {
            "slot_id": "support-sla-document",
            "status": "ready",
            "evidence_ref": "docs/rapidtriage-support-sla.md",
            "evidence_hash": stable_release_sha256(document_hashes),
        },
        {
            "slot_id": "support-sla-evidence-manifest",
            "status": "ready",
            "evidence_ref": "release-manifest.package_readiness.operations_documents.document_evidence_manifest_hashes.114",
            "evidence_hash": str(evidence_manifest.get("manifest_hash") or ""),
        },
        {
            "slot_id": "support-sla-document-evidence-matrix",
            "status": "ready",
            "evidence_ref": "release-manifest.package_readiness.operations_documents.document_evidence_matrix_hashes.114",
            "evidence_hash": str(evidence_manifest.get("document_evidence_matrix_hash") or ""),
        },
        {
            "slot_id": "support-process-readiness-manifest",
            "status": "ready",
            "evidence_ref": "support-process-readiness-manifest.json",
            "evidence_hash": str(support_process_readiness_manifest.get("manifest_hash") or ""),
        },
        {
            "slot_id": "severity-levels-and-response-targets",
            "status": "ready",
            "evidence_ref": "support-process-readiness-manifest.readiness_checks.severity_levels,response_targets",
            "evidence_hash": stable_release_sha256(
                {
                    "severity_levels": readiness_checks.get("severity_levels", {}),
                    "response_targets": readiness_checks.get("response_targets", {}),
                }
            ),
        },
        {
            "slot_id": "secure-intake-and-escalation",
            "status": "ready",
            "evidence_ref": "support-process-readiness-manifest.readiness_checks.secure_intake,escalation",
            "evidence_hash": stable_release_sha256(
                {
                    "secure_intake": readiness_checks.get("secure_intake", {}),
                    "escalation": readiness_checks.get("escalation", {}),
                }
            ),
        },
        {
            "slot_id": "staffed-support-attestation-boundary",
            "status": "ready-with-blocker",
            "evidence_ref": "release-manifest.package_readiness.operations_documents.document_evidence_slots.114.staffed_support_attestation",
            "evidence_hash": stable_release_sha256(evidence_slots.get("staffed_support_attestation", {})),
        },
        {
            "slot_id": "secure-intake-review-boundary",
            "status": "ready-with-blocker",
            "evidence_ref": "release-manifest.package_readiness.operations_documents.document_evidence_slots.114.secure_intake_review",
            "evidence_hash": stable_release_sha256(evidence_slots.get("secure_intake_review", {})),
        },
        {
            "slot_id": "trusted-support-sla-diff-boundary",
            "status": "ready" if trusted_diff.get("status") == "pass" else "ready-with-blocker",
            "evidence_ref": "release-manifest.package_readiness.operations_documents.trusted_operations_document_diffs.114",
            "evidence_hash": stable_release_sha256(trusted_diff),
        },
    ]
    blocking_slots = []
    if trusted_diff.get("status") != "pass":
        blocking_slots.append(
            {
                "slot_id": "trusted-support-desk-sla-diff",
                "status": "blocking",
                "blocker": OPERATIONS_DOCUMENT_TRUSTED_DIFF_BLOCKERS[114],
                "required_evidence": "trusted support desk SLA attestation comparing staffing, response targets, secure intake, escalation, and hotfix delivery records",
            }
        )
    for slot_id, blocker, required_evidence in (
        (
            "staffed-support-attestation",
            "staffed-support-attestation-required",
            "staffed support desk owner list, coverage window, escalation owners, and on-call acceptance",
        ),
        (
            "contractual-sla-execution",
            "contractual-sla-execution-required",
            "contractual SLA or internal service commitment proving response and patch-delivery targets are operational",
        ),
        (
            "secure-intake-runbook-signoff",
            "secure-intake-runbook-signoff-required",
            "secure evidence intake runbook signoff covering authorization, encryption, custody, and retention",
        ),
        (
            "escalation-rota",
            "escalation-rota-required",
            "support escalation rota tying Sev1-Sev4 triage to forensic, security, and release owners",
        ),
        (
            "emergency-parser-hotfix-drill",
            "emergency-parser-hotfix-drill-required",
            "emergency parser hotfix drill log proving intake, fix, validation, release notes, and rollback timing",
        ),
        (
            "support-ticket-sample",
            "support-ticket-sample-required",
            "redacted support ticket sample showing severity assignment, response target, custody warning, and closure evidence",
        ),
        (
            "release-host-support-flow-smoke",
            "release-host-support-flow-smoke-required",
            "release-host smoke proving support intake links, SLA wording, and evidence-handling warning are present in shipped artifacts",
        ),
        (
            "independent-support-sla-review",
            "independent-support-sla-review-required",
            "independent reviewer confirmation that SLA claims are staffed, enforceable, and do not overclaim commercial support",
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
        "profile_version": SUPPORT_SLA_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 114,
        "commercial_gap_ids": [SUPPORT_SLA_GAP_ID],
        "commercial_claim_allowed": False,
        "document_count": len(document_hashes),
        "evidence_slot_count": len(evidence_slots),
        "support_sla_evidence_manifest_hash": str(evidence_manifest.get("manifest_hash") or ""),
        "operations_document_evidence_matrix_hash": str(evidence_manifest.get("document_evidence_matrix_hash") or ""),
        "support_process_readiness_manifest_hash": str(support_process_readiness_manifest.get("manifest_hash") or ""),
        "readiness_checks_hash": stable_release_sha256(readiness_checks),
        "trusted_diff_status": str(trusted_diff.get("status") or ""),
        "trusted_diff_blocker": trusted_diff.get("blocker"),
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "external_blocker_catalog": list(SUPPORT_SLA_REPORT_GRADE_BLOCKERS),
        "blockers": blockers,
        "reporting_boundary": (
            "The support SLA template and readiness manifest are packaged; commercial support claims require "
            "staffed desk attestation, contractual SLA execution, secure intake signoff, escalation rota, "
            "emergency hotfix drill evidence, support ticket samples, release-host smoke, and independent review."
        ),
    }
    plan["validation_plan_hash"] = stable_release_sha256(plan)
    return plan


def build_operations_document_evidence_matrix(
    *,
    number: int,
    document_hashes: list[dict[str, object]],
    slots: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    slot_rows = []
    for slot_name, slot in sorted(slots.items()):
        row_core = {
            "slot": slot_name,
            "status": slot.get("status", ""),
            "attached": slot.get("status") not in {"not-attached", "missing", ""},
            "required_before_commercial_claim": bool(slot.get("required_before_commercial_claim")),
            "expected_material_hash": stable_release_sha256(slot.get("expected_material", "")),
        }
        slot_rows.append({**row_core, "row_hash": stable_release_sha256(row_core)})
    document_rows = []
    for document in document_hashes:
        row_core = {
            "path": document.get("path", ""),
            "present": bool(document.get("sha256")),
            "sha256": document.get("sha256", ""),
            "size_bytes": document.get("size_bytes", 0),
        }
        document_rows.append({**row_core, "row_hash": stable_release_sha256(row_core)})
    matrix: dict[str, object] = {
        "profile_version": "operations-document-evidence-matrix-v1",
        "item_number": number,
        "document_count": len(document_rows),
        "present_document_count": sum(1 for row in document_rows if row["present"]),
        "slot_count": len(slot_rows),
        "required_slot_count": sum(1 for row in slot_rows if row["required_before_commercial_claim"]),
        "attached_slot_count": sum(1 for row in slot_rows if row["attached"]),
        "missing_required_slot_count": sum(
            1 for row in slot_rows if row["required_before_commercial_claim"] and not row["attached"]
        ),
        "document_rows": document_rows,
        "slot_rows": slot_rows,
        "commercial_claim_allowed": False,
    }
    matrix["matrix_hash"] = stable_release_sha256(matrix)
    return matrix


def build_admin_guide_coverage_manifest(repo: Path, output_dir: Path) -> dict[str, object]:
    document_paths = [
        "docs/rapidtriage-admin-deployment-guide.md",
        "docs/rapidtriage-security-policy.md",
        "docs/rapidtriage-release-checklist.md",
        "docs/rapidtriage-windows-quickstart.md",
        "docs/rapidtriage-macos-linux-quickstart.md",
    ]
    documents: list[dict[str, object]] = []
    corpus_parts: list[str] = []
    for rel_path in document_paths:
        path = repo / rel_path
        if not path.is_file():
            path = output_dir / rel_path
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            corpus_parts.append(text.lower())
            documents.append(
                {
                    "path": rel_path,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "size_bytes": path.stat().st_size,
                }
            )
        else:
            documents.append({"path": rel_path, "status": "missing"})
    corpus = "\n".join(corpus_parts)
    coverage_requirements = {
        "install": ["install", "portable", "wheel"],
        "update": ["update", "reinstall", "upgrade"],
        "auth": ["auth-token", "token"],
        "network": ["localhost", "127.0.0.1", "internet"],
        "backup": ["case-backup", "backup"],
        "restore": ["case-restore", "restore"],
        "logging": ["logs", "crash-log-dir", "smoke-summary"],
        "security": ["security", "telemetry", "hardening"],
        "dependency": ["check-dependencies", "dependency", "sbom"],
        "evidence_handling": ["evidence", "hash", "reviewer bundle"],
    }
    coverage = {
        name: {
            "present": all(keyword in corpus for keyword in keywords),
            "required_keywords": keywords,
        }
        for name, keywords in coverage_requirements.items()
    }
    missing_coverage = sorted(name for name, result in coverage.items() if not result["present"])
    manifest: dict[str, object] = {
        "profile_version": "admin-guide-coverage-manifest-v1",
        "item_number": 66,
        "commercial_gap_ids": [ADMIN_DEPLOYMENT_GUIDE_GAP_ID],
        "commercial_claim_allowed": False,
        "documents": documents,
        "coverage": coverage,
        "missing_coverage": missing_coverage,
        "coverage_passed": not missing_coverage and all("sha256" in document for document in documents),
        "release_evidence_file": "admin-guide-coverage-manifest.json",
        "operator_runbook_sections": [
            "Deployment Checklist",
            "Install And Update Runbook",
            "Authentication And Network Boundary",
            "Backup, Restore, And Logging",
            "Security Hardening",
            "Evidence Handling And Handoff",
        ],
        "verification_commands": [
            "python scripts/build-release.py --output-dir release --skip-build",
            "python scripts/build-release.py --output-dir release --verify",
            "python -m unittest tests.test_rapidtriage_ops.RapidTriageOpsTests.test_build_release_script_can_assemble_portable_zip_without_building_wheel",
        ],
        "blockers": [
            "fresh-admin-deployment-proof-not-attached",
            "operator-acceptance-signoff-not-attached",
            OPERATIONS_DOCUMENT_TRUSTED_DIFF_BLOCKERS[117],
        ],
    }
    manifest["manifest_hash"] = stable_release_sha256(manifest)
    return manifest


def build_support_process_readiness_manifest(repo: Path, output_dir: Path) -> dict[str, object]:
    document_paths = [
        "docs/rapidtriage-support-sla.md",
        "docs/rapidtriage-lts-hotfix-policy.md",
        "docs/rapidtriage-security-policy.md",
        "docs/rapidtriage-release-checklist.md",
    ]
    documents: list[dict[str, object]] = []
    corpus_parts: list[str] = []
    for rel_path in document_paths:
        path = repo / rel_path
        if not path.is_file():
            path = output_dir / rel_path
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            corpus_parts.append(text.lower())
            documents.append(
                {
                    "path": rel_path,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "size_bytes": path.stat().st_size,
                }
            )
        else:
            documents.append({"path": rel_path, "status": "missing"})
    corpus = "\n".join(corpus_parts)
    readiness_checks = {
        "severity_levels": ["sev1", "sev2", "sev3", "sev4"],
        "response_targets": ["4 business hours", "1 business day", "3 business days", "5 business days"],
        "secure_intake": ["secure evidence handling", "written authorization", "encryption", "chain-of-custody"],
        "escalation": ["forensic lead", "security issues", "emergency builds"],
        "hotfix_gates": ["fixture", "known-answer", "rollback guidance", "validation gap"],
        "release_attachments": ["release manifest", "sha256s", "validation package", "smoke test"],
    }
    checks = {
        name: {
            "present": all(keyword in corpus for keyword in keywords),
            "required_keywords": keywords,
        }
        for name, keywords in readiness_checks.items()
    }
    missing_checks = sorted(name for name, result in checks.items() if not result["present"])
    manifest: dict[str, object] = {
        "profile_version": "support-process-readiness-manifest-v1",
        "item_number": 68,
        "commercial_gap_ids": [SUPPORT_SLA_GAP_ID],
        "commercial_claim_allowed": False,
        "documents": documents,
        "readiness_checks": checks,
        "missing_checks": missing_checks,
        "coverage_passed": not missing_checks and all("sha256" in document for document in documents),
        "release_evidence_file": "support-process-readiness-manifest.json",
        "minimum_operator_evidence_before_claim": [
            "staffed support desk owner list",
            "contractual SLA or internal service commitment",
            "secure evidence intake runbook signoff",
            "emergency parser hotfix drill log",
        ],
        "blockers": [
            "staffed-support-desk-not-attached",
            "contractual-sla-evidence-not-attached",
            "secure-intake-runbook-signoff-not-attached",
            OPERATIONS_DOCUMENT_TRUSTED_DIFF_BLOCKERS[114],
        ],
    }
    manifest["manifest_hash"] = stable_release_sha256(manifest)
    return manifest


def build_release_discipline_manifest(repo: Path, output_dir: Path) -> dict[str, object]:
    document_paths = [
        "docs/rapidtriage-release-checklist.md",
        "docs/rapidtriage-release-notes-template.md",
        "docs/rapidtriage-known-limitations.md",
        "docs/rapidtriage-parser-coverage.md",
        "docs/rapidtriage-lts-hotfix-policy.md",
    ]
    documents: list[dict[str, object]] = []
    corpus_parts: list[str] = []
    for rel_path in document_paths:
        path = repo / rel_path
        if not path.is_file():
            path = output_dir / rel_path
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            corpus_parts.append(text.lower())
            documents.append(
                {
                    "path": rel_path,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "size_bytes": path.stat().st_size,
                }
            )
        else:
            documents.append({"path": rel_path, "status": "missing"})
    corpus = "\n".join(corpus_parts)
    required_release_sections = {
        "supported_inputs_and_limits": ["supported evidence inputs", "limitations"],
        "validation_state": ["validation", "known-answer", "independent"],
        "migration_notes": ["migration notes", "migration"],
        "checksums": ["sha256s", "checksums"],
        "smoke_logs": ["smoke-summary", "smoke test"],
        "signing_status": ["signing", "notarization"],
        "hotfix_policy": ["hotfix", "rollback guidance"],
    }
    section_checks = {
        name: {
            "present": all(keyword in corpus for keyword in keywords),
            "required_keywords": keywords,
        }
        for name, keywords in required_release_sections.items()
    }
    required_files = [
        "rapidtriage-portable.zip",
        "dependency-inventory.txt",
        "packaging-plan.json",
        "packaging-plan.md",
        "rapidtriage-commercial-readiness.json",
        "rapidtriage-commercial-readiness.md",
        "update-manifest.json",
        "release-manifest.json",
        "SHA256SUMS",
    ]
    file_statuses = []
    for name in required_files:
        path = output_dir / name
        if path.is_file():
            file_statuses.append(
                {
                    "name": name,
                    "status": "present",
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "size_bytes": path.stat().st_size,
                }
            )
        elif name in {"release-manifest.json", "SHA256SUMS"}:
            file_statuses.append({"name": name, "status": "generated-after-discipline-manifest"})
        else:
            file_statuses.append({"name": name, "status": "missing"})
    missing_sections = sorted(name for name, result in section_checks.items() if not result["present"])
    missing_files = sorted(item["name"] for item in file_statuses if item["status"] == "missing")
    manifest: dict[str, object] = {
        "profile_version": "release-discipline-manifest-v1",
        "item_number": 69,
        "commercial_gap_ids": [RELEASE_NOTES_CHANGELOG_GAP_ID, LTS_HOTFIX_POLICY_GAP_ID],
        "commercial_claim_allowed": False,
        "documents": documents,
        "section_checks": section_checks,
        "required_file_statuses": file_statuses,
        "missing_sections": missing_sections,
        "missing_files": missing_files,
        "coverage_passed": not missing_sections and not missing_files and all("sha256" in document for document in documents),
        "release_evidence_file": "release-discipline-manifest.json",
        "required_external_evidence_before_claim": [
            "CI release-note gate proving migration, limits, validation state, and smoke logs are present",
            "fresh Windows smoke log",
            "fresh macOS/Linux smoke log",
            "release owner signoff",
        ],
        "blockers": [
            OPERATIONS_DOCUMENT_TRUSTED_DIFF_BLOCKERS[112],
            "required-smoke-logs-not-attached",
            "release-owner-signoff-not-attached",
        ],
    }
    manifest["manifest_hash"] = stable_release_sha256(manifest)
    return manifest


def build_external_blocker_ledger_manifest(
    admin_guide_coverage_manifest: dict[str, object],
    support_process_readiness_manifest: dict[str, object],
    release_discipline_manifest: dict[str, object],
) -> dict[str, object]:
    blockers = [
        {
            "blocker_id": "independent-validation-not-attached",
            "category": "validation",
            "required_evidence": "Independent parser validation package, reviewer identity, corpus scope, and signed report hash",
            "owner": "validation lead",
        },
        {
            "blocker_id": "large-hardware-test-evidence-not-attached",
            "category": "performance",
            "required_evidence": "1TB/5TB/10TB benchmark logs, hardware profile, memory/p95 latency, and failure threshold notes",
            "owner": "performance QA",
        },
        {
            "blocker_id": "code-signing-not-attached",
            "category": "windows-release",
            "required_evidence": "Authenticode signature verification, timestamp authority output, and fresh Windows smoke result",
            "owner": "release engineer",
        },
        {
            "blocker_id": "notarization-not-attached",
            "category": "macos-release",
            "required_evidence": "codesign verification, notarization ticket, Gatekeeper assessment, and fresh macOS smoke result",
            "owner": "release engineer",
        },
        {
            "blocker_id": "staffed-support-not-attached",
            "category": "operations",
            "required_evidence": "Staffed support desk owner list, contractual SLA/internal service commitment, and escalation rota",
            "owner": "support lead",
        },
        {
            "blocker_id": "fresh-admin-deployment-proof-not-attached",
            "category": "deployment",
            "required_evidence": "Fresh workstation deployment transcript covering install, update, auth, backup, restore, and smoke",
            "owner": "admin",
        },
        {
            "blocker_id": "required-smoke-logs-not-attached",
            "category": "release-discipline",
            "required_evidence": "Windows and macOS/Linux smoke summaries attached to release evidence",
            "owner": "release QA",
        },
    ]
    for blocker in blockers:
        blocker["commercial_claim_blocker"] = True
    manifest: dict[str, object] = {
        "profile_version": "external-blocker-ledger-manifest-v1",
        "item_number": 70,
        "commercial_gap_ids": [
            "#81-#100",
            WINDOWS_SIGNED_INSTALLER_GAP_ID,
            MACOS_NOTARIZED_PACKAGE_GAP_ID,
            LINUX_PACKAGE_GAP_ID,
            SUPPORT_SLA_GAP_ID,
            ADMIN_DEPLOYMENT_GUIDE_GAP_ID,
        ],
        "commercial_claim_allowed": False,
        "commercial_claim_guard": "Any blocker in this ledger prevents commercial-grade release claims.",
        "source_manifest_hashes": {
            "admin_guide_coverage": admin_guide_coverage_manifest.get("manifest_hash"),
            "support_process_readiness": support_process_readiness_manifest.get("manifest_hash"),
            "release_discipline": release_discipline_manifest.get("manifest_hash"),
        },
        "blocker_count": len(blockers),
        "blockers": blockers,
        "release_evidence_file": "external-blocker-ledger-manifest.json",
    }
    manifest["manifest_hash"] = stable_release_sha256(manifest)
    return manifest


def write_release_manifest(output_dir: Path, repo: Path, commercial_readiness: dict[str, object] | None = None) -> None:
    admin_guide_coverage_manifest = build_admin_guide_coverage_manifest(repo, output_dir)
    (output_dir / "admin-guide-coverage-manifest.json").write_text(
        json.dumps(admin_guide_coverage_manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    support_process_readiness_manifest = build_support_process_readiness_manifest(repo, output_dir)
    (output_dir / "support-process-readiness-manifest.json").write_text(
        json.dumps(support_process_readiness_manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    release_discipline_manifest = build_release_discipline_manifest(repo, output_dir)
    (output_dir / "release-discipline-manifest.json").write_text(
        json.dumps(release_discipline_manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    external_blocker_ledger_manifest = build_external_blocker_ledger_manifest(
        admin_guide_coverage_manifest,
        support_process_readiness_manifest,
        release_discipline_manifest,
    )
    (output_dir / "external-blocker-ledger-manifest.json").write_text(
        json.dumps(external_blocker_ledger_manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    artifacts: list[dict[str, object]] = []
    for path in sorted(output_dir.iterdir()):
        if not path.is_file() or path.name in {"SHA256SUMS", "release-manifest.json"}:
            continue
        artifacts.append(
            {
                "name": path.name,
                "size_bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )

    windows_trusted_diff = missing_release_packaging_trusted_diff(101)
    windows_signing_evidence_manifest = build_windows_signing_evidence_manifest(artifacts, windows_trusted_diff)
    windows_installer_workflow_manifest = build_windows_installer_workflow_manifest(
        artifacts,
        windows_signing_evidence_manifest,
    )
    windows_signing_report_grade_validation_plan = build_windows_signing_report_grade_validation_plan(
        signing_manifest=windows_signing_evidence_manifest,
        workflow_manifest=windows_installer_workflow_manifest,
        artifacts=artifacts,
        trusted_diff=windows_trusted_diff,
    )
    windows_signing_blockers = sorted(
        {
            WINDOWS_SIGNING_TRUSTED_DIFF_BLOCKER_101,
            *[str(blocker) for blocker in windows_signing_report_grade_validation_plan.get("blockers", [])],
        }
    )
    macos_trusted_diff = missing_release_packaging_trusted_diff(102)
    macos_notarization_evidence_manifest = build_macos_notarization_evidence_manifest(artifacts, macos_trusted_diff)
    macos_package_workflow_manifest = build_macos_package_workflow_manifest(
        artifacts,
        macos_notarization_evidence_manifest,
    )
    macos_notarization_report_grade_validation_plan = build_macos_notarization_report_grade_validation_plan(
        notarization_manifest=macos_notarization_evidence_manifest,
        workflow_manifest=macos_package_workflow_manifest,
        artifacts=artifacts,
        trusted_diff=macos_trusted_diff,
    )
    macos_notarization_blockers = sorted(
        {
            MACOS_NOTARIZATION_TRUSTED_DIFF_BLOCKER_102,
            *[str(blocker) for blocker in macos_notarization_report_grade_validation_plan.get("blockers", [])],
        }
    )
    linux_trusted_diff = missing_release_packaging_trusted_diff(103)
    linux_package_evidence_manifest = build_linux_package_evidence_manifest(artifacts, linux_trusted_diff)
    linux_package_workflow_manifest = build_linux_package_workflow_manifest(
        artifacts,
        linux_package_evidence_manifest,
    )
    linux_package_report_grade_validation_plan = build_linux_package_report_grade_validation_plan(
        package_manifest=linux_package_evidence_manifest,
        workflow_manifest=linux_package_workflow_manifest,
        artifacts=artifacts,
        trusted_diff=linux_trusted_diff,
    )
    linux_package_blockers = sorted(
        {
            LINUX_PACKAGE_TRUSTED_DIFF_BLOCKER_103,
            *[str(blocker) for blocker in linux_package_report_grade_validation_plan.get("blockers", [])],
        }
    )
    operations_document_evidence_manifests = build_operations_document_evidence_manifests(repo, output_dir)
    trusted_operations_document_diffs = {
        str(number): missing_operations_document_trusted_diff(number) for number in range(112, 118)
    }
    release_notes_report_grade_validation_plan = build_release_notes_report_grade_validation_plan(
        evidence_manifest=operations_document_evidence_manifests["112"],
        release_discipline_manifest=release_discipline_manifest,
        trusted_diff=trusted_operations_document_diffs["112"],
    )
    lts_hotfix_report_grade_validation_plan = build_lts_hotfix_report_grade_validation_plan(
        evidence_manifest=operations_document_evidence_manifests["113"],
        trusted_diff=trusted_operations_document_diffs["113"],
    )
    support_sla_report_grade_validation_plan = build_support_sla_report_grade_validation_plan(
        evidence_manifest=operations_document_evidence_manifests["114"],
        support_process_readiness_manifest=support_process_readiness_manifest,
        trusted_diff=trusted_operations_document_diffs["114"],
    )
    operations_document_report_grade_validation_plans = {
        "112": release_notes_report_grade_validation_plan,
        "113": lts_hotfix_report_grade_validation_plan,
        "114": support_sla_report_grade_validation_plan,
    }
    operations_document_report_grade_validation_plan_hashes = {
        "112": release_notes_report_grade_validation_plan["validation_plan_hash"],
        "113": lts_hotfix_report_grade_validation_plan["validation_plan_hash"],
        "114": support_sla_report_grade_validation_plan["validation_plan_hash"],
    }
    operations_documents_blockers = sorted(
        {
            *[OPERATIONS_DOCUMENT_TRUSTED_DIFF_BLOCKERS[number] for number in range(112, 118)],
            *[str(blocker) for blocker in release_notes_report_grade_validation_plan.get("blockers", [])],
            *[str(blocker) for blocker in lts_hotfix_report_grade_validation_plan.get("blockers", [])],
            *[str(blocker) for blocker in support_sla_report_grade_validation_plan.get("blockers", [])],
        }
    )
    update_manifest_payload: dict[str, object] = {}
    update_manifest_path = output_dir / "update-manifest.json"
    if update_manifest_path.is_file():
        update_manifest_payload = json.loads(update_manifest_path.read_text(encoding="utf-8"))
    manifest = {
        "name": "rapidtriage-release",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "git_commit": git_value(repo, ["rev-parse", "HEAD"]),
        "git_branch": git_value(repo, ["rev-parse", "--abbrev-ref", "HEAD"]),
        "python": {
            "executable": sys.executable,
            "version": platform.python_version(),
            "platform": platform.platform(),
        },
        "artifacts": artifacts,
        "commercialization_gap_ids": [
            WINDOWS_SIGNED_INSTALLER_GAP_ID,
            MACOS_NOTARIZED_PACKAGE_GAP_ID,
            LINUX_PACKAGE_GAP_ID,
            AUTO_UPDATE_CHANNEL_GAP_ID,
            RELEASE_NOTES_CHANGELOG_GAP_ID,
            LTS_HOTFIX_POLICY_GAP_ID,
            SUPPORT_SLA_GAP_ID,
            TRAINING_CURRICULUM_GAP_ID,
            ANALYST_QUICKSTART_LAB_GAP_ID,
            ADMIN_DEPLOYMENT_GUIDE_GAP_ID,
            SECURITY_HARDENING_REVIEW_GAP_ID,
            MALICIOUS_EVIDENCE_SANDBOXING_GAP_ID,
            DEPENDENCY_VULNERABILITY_MONITORING_GAP_ID,
        ],
        "commercial_readiness": {
            "status": commercial_readiness.get("status") if commercial_readiness else "not-generated",
            "commercial_claim_allowed": commercial_readiness.get("commercial_claim_allowed", False)
            if commercial_readiness
            else False,
            "readiness_score": commercial_readiness.get("readiness_score") if commercial_readiness else None,
            "non_commercial_count": commercial_readiness.get("non_commercial_count") if commercial_readiness else None,
            "report": "rapidtriage-commercial-readiness.json",
            "markdown": "rapidtriage-commercial-readiness.md",
            "release_claim": commercial_readiness.get("release_claim") if commercial_readiness else "",
        },
        "package_readiness": {
            "windows_signed_installer": {
                "status": "external-required",
                "commercial_gap_ids": [WINDOWS_SIGNED_INSTALLER_GAP_ID],
                "core_accuracy_gates": release_packaging_core_accuracy_gate(
                    101,
                    evidence_manifest=windows_signing_evidence_manifest,
                    report_grade_validation_plan=windows_signing_report_grade_validation_plan,
                ),
                "functional_priority_profile": release_packaging_functional_priority_profile("windows"),
                "required_evidence": ["Authenticode signature", "timestamp authority", "fresh Windows smoke test"],
                "windows_signing_evidence_manifest": windows_signing_evidence_manifest,
                "windows_signing_evidence_manifest_hash": windows_signing_evidence_manifest["manifest_hash"],
                "evidence_slot_matrix_hash": windows_signing_evidence_manifest["evidence_slot_matrix_hash"],
                "windows_installer_workflow_manifest": windows_installer_workflow_manifest,
                "windows_installer_workflow_manifest_hash": windows_installer_workflow_manifest["manifest_hash"],
                "windows_signing_report_grade_validation_plan": windows_signing_report_grade_validation_plan,
                "windows_signing_report_grade_validation_plan_hash": windows_signing_report_grade_validation_plan[
                    "validation_plan_sha256"
                ],
                "windows_signing_report_grade_ready_slot_count": windows_signing_report_grade_validation_plan[
                    "ready_slot_count"
                ],
                "windows_signing_report_grade_blocking_slot_count": windows_signing_report_grade_validation_plan[
                    "blocking_slot_count"
                ],
                "signing_slots": windows_signing_evidence_manifest["signing_slots"],
                "trusted_windows_signing_diff": windows_trusted_diff,
                "blockers": windows_signing_blockers,
            },
            "macos_notarized_package": {
                "status": "external-required",
                "commercial_gap_ids": [MACOS_NOTARIZED_PACKAGE_GAP_ID],
                "core_accuracy_gates": release_packaging_core_accuracy_gate(
                    102,
                    evidence_manifest=macos_notarization_evidence_manifest,
                    report_grade_validation_plan=macos_notarization_report_grade_validation_plan,
                ),
                "functional_priority_profile": release_packaging_functional_priority_profile("macos"),
                "required_evidence": ["codesign verification", "notarization ticket", "Gatekeeper assessment"],
                "macos_notarization_evidence_manifest": macos_notarization_evidence_manifest,
                "macos_notarization_evidence_manifest_hash": macos_notarization_evidence_manifest["manifest_hash"],
                "evidence_slot_matrix_hash": macos_notarization_evidence_manifest["evidence_slot_matrix_hash"],
                "macos_package_workflow_manifest": macos_package_workflow_manifest,
                "macos_package_workflow_manifest_hash": macos_package_workflow_manifest["manifest_hash"],
                "macos_notarization_report_grade_validation_plan": macos_notarization_report_grade_validation_plan,
                "macos_notarization_report_grade_validation_plan_hash": macos_notarization_report_grade_validation_plan[
                    "validation_plan_sha256"
                ],
                "macos_notarization_report_grade_ready_slot_count": macos_notarization_report_grade_validation_plan[
                    "ready_slot_count"
                ],
                "macos_notarization_report_grade_blocking_slot_count": macos_notarization_report_grade_validation_plan[
                    "blocking_slot_count"
                ],
                "notarization_slots": macos_notarization_evidence_manifest["notarization_slots"],
                "trusted_macos_notarization_diff": macos_trusted_diff,
                "blockers": macos_notarization_blockers,
            },
            "linux_package": {
                "status": "packaging-plan-ready",
                "commercial_gap_ids": [LINUX_PACKAGE_GAP_ID],
                "core_accuracy_gates": release_packaging_core_accuracy_gate(
                    103,
                    evidence_manifest=linux_package_evidence_manifest,
                    report_grade_validation_plan=linux_package_report_grade_validation_plan,
                ),
                "functional_priority_profile": release_packaging_functional_priority_profile("linux"),
                "supported_outputs": ["portable zip", "wheel", "sdist"],
                "future_outputs": ["deb", "rpm", "AppImage"],
                "plan": "packaging-plan.json",
                "linux_package_evidence_manifest": linux_package_evidence_manifest,
                "linux_package_evidence_manifest_hash": linux_package_evidence_manifest["manifest_hash"],
                "evidence_slot_matrix_hash": linux_package_evidence_manifest["evidence_slot_matrix_hash"],
                "linux_package_workflow_manifest": linux_package_workflow_manifest,
                "linux_package_workflow_manifest_hash": linux_package_workflow_manifest["manifest_hash"],
                "linux_package_report_grade_validation_plan": linux_package_report_grade_validation_plan,
                "linux_package_report_grade_validation_plan_hash": linux_package_report_grade_validation_plan[
                    "validation_plan_sha256"
                ],
                "linux_package_report_grade_ready_slot_count": linux_package_report_grade_validation_plan[
                    "ready_slot_count"
                ],
                "linux_package_report_grade_blocking_slot_count": linux_package_report_grade_validation_plan[
                    "blocking_slot_count"
                ],
                "package_evidence_slots": linux_package_evidence_manifest["package_evidence_slots"],
                "trusted_linux_package_diff": linux_trusted_diff,
                "blockers": linux_package_blockers,
            },
            "auto_update_channel": {
                "status": "manifest-generated",
                "commercial_gap_ids": [AUTO_UPDATE_CHANNEL_GAP_ID],
                "core_accuracy_gates": update_manifest_payload.get(
                    "core_accuracy_gates",
                    release_packaging_core_accuracy_gate(104),
                ),
                "manifest": "update-manifest.json",
                "enterprise_disable_supported": True,
                "auto_update_evidence_manifest_hash": update_manifest_payload.get("auto_update_evidence_manifest_hash"),
                "evidence_slot_matrix_hash": update_manifest_payload.get("evidence_slot_matrix_hash"),
                "auto_update_report_grade_validation_plan": update_manifest_payload.get(
                    "auto_update_report_grade_validation_plan"
                ),
                "auto_update_report_grade_validation_plan_hash": update_manifest_payload.get(
                    "auto_update_report_grade_validation_plan_hash"
                ),
                "auto_update_report_grade_ready_slot_count": update_manifest_payload.get(
                    "auto_update_report_grade_ready_slot_count"
                ),
                "auto_update_report_grade_blocking_slot_count": update_manifest_payload.get(
                    "auto_update_report_grade_blocking_slot_count"
                ),
                "update_evidence_slots": update_manifest_payload.get("update_evidence_slots", {}),
                "trusted_auto_update_channel_diff": update_manifest_payload.get(
                    "trusted_auto_update_channel_diff",
                    missing_release_packaging_trusted_diff(104),
                ),
                "blockers": update_manifest_payload.get("blockers", [AUTO_UPDATE_TRUSTED_DIFF_BLOCKER_104]),
            },
            "operations_documents": {
                "status": "packaged",
                "commercial_gap_ids": [
                    RELEASE_NOTES_CHANGELOG_GAP_ID,
                    LTS_HOTFIX_POLICY_GAP_ID,
                    SUPPORT_SLA_GAP_ID,
                    TRAINING_CURRICULUM_GAP_ID,
                    ANALYST_QUICKSTART_LAB_GAP_ID,
                    ADMIN_DEPLOYMENT_GUIDE_GAP_ID,
                    SECURITY_HARDENING_REVIEW_GAP_ID,
                    MALICIOUS_EVIDENCE_SANDBOXING_GAP_ID,
                    DEPENDENCY_VULNERABILITY_MONITORING_GAP_ID,
                ],
                "core_accuracy_gates": operations_documents_core_accuracy_gates(
                    evidence_manifests=operations_document_evidence_manifests,
                    report_grade_validation_plans=operations_document_report_grade_validation_plans,
                ),
                "functional_priority_profiles": release_operations_functional_priority_profiles(),
                "document_evidence_manifests": operations_document_evidence_manifests,
                "document_evidence_manifest_hashes": {
                    number: manifest["manifest_hash"]
                    for number, manifest in operations_document_evidence_manifests.items()
                },
                "document_evidence_matrix_hashes": {
                    number: manifest["document_evidence_matrix_hash"]
                    for number, manifest in operations_document_evidence_manifests.items()
                },
                "document_report_grade_validation_plans": operations_document_report_grade_validation_plans,
                "document_report_grade_validation_plan_hashes": operations_document_report_grade_validation_plan_hashes,
                "document_report_grade_ready_slot_counts": {
                    "112": release_notes_report_grade_validation_plan["ready_slot_count"],
                    "113": lts_hotfix_report_grade_validation_plan["ready_slot_count"],
                    "114": support_sla_report_grade_validation_plan["ready_slot_count"],
                },
                "document_report_grade_blocking_slot_counts": {
                    "112": release_notes_report_grade_validation_plan["blocking_slot_count"],
                    "113": lts_hotfix_report_grade_validation_plan["blocking_slot_count"],
                    "114": support_sla_report_grade_validation_plan["blocking_slot_count"],
                },
                "admin_guide_coverage_manifest": admin_guide_coverage_manifest,
                "admin_guide_coverage_manifest_hash": admin_guide_coverage_manifest["manifest_hash"],
                "support_process_readiness_manifest": support_process_readiness_manifest,
                "support_process_readiness_manifest_hash": support_process_readiness_manifest["manifest_hash"],
                "release_discipline_manifest": release_discipline_manifest,
                "release_discipline_manifest_hash": release_discipline_manifest["manifest_hash"],
                "external_blocker_ledger_manifest": external_blocker_ledger_manifest,
                "external_blocker_ledger_manifest_hash": external_blocker_ledger_manifest["manifest_hash"],
                "document_evidence_slots": {
                    number: manifest["evidence_slots"]
                    for number, manifest in operations_document_evidence_manifests.items()
                },
                "trusted_operations_document_diffs": trusted_operations_document_diffs,
                "blockers": operations_documents_blockers,
                "documents": [
                    "docs/rapidtriage-release-notes-template.md",
                    "docs/rapidtriage-lts-hotfix-policy.md",
                    "docs/rapidtriage-support-sla.md",
                    "docs/rapidtriage-training-curriculum.md",
                    "docs/rapidtriage-admin-deployment-guide.md",
                    "docs/rapidtriage-security-policy.md",
                ],
            },
        },
        "required_followup_evidence": [
            "Windows smoke output folder",
            "macOS/Linux smoke output folder",
            "Windows Authenticode signature verification when distributing signed binaries",
            "macOS codesign/notarization/Gatekeeper verification when distributing app packages",
        ],
    }
    manifest_path = output_dir / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_packaging_plan(output_dir: Path) -> None:
    windows_portable_mode_manifest = build_windows_portable_mode_manifest(output_dir)
    plan = {
        "name": "rapidtriage-packaging-plan",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "commercial_gap_ids": [
            WINDOWS_SIGNED_INSTALLER_GAP_ID,
            MACOS_NOTARIZED_PACKAGE_GAP_ID,
            LINUX_PACKAGE_GAP_ID,
            AUTO_UPDATE_CHANNEL_GAP_ID,
        ],
        "local_outputs": {
            "portable_zip": {
                "path": "rapidtriage-portable.zip",
                "status": "generated",
                "verification": ["SHA256SUMS", "release-manifest.json", "fresh-machine smoke test"],
                "functional_priority_profile": release_packaging_functional_priority_profile("portable"),
                "windows_portable_mode_manifest": windows_portable_mode_manifest,
                "windows_portable_mode_manifest_hash": windows_portable_mode_manifest["manifest_hash"],
            },
            "python_distribution": {
                "status": "generated-when-build-enabled",
                "outputs": ["wheel", "sdist"],
                "verification": ["pip install smoke test", "dependency-inventory.txt"],
            },
            "update_manifest": {
                "path": "update-manifest.json",
                "status": "manual-channel-generated",
                "commercial_gap_ids": [AUTO_UPDATE_CHANNEL_GAP_ID],
                "enterprise_disable": True,
            },
        },
        "platform_packages": {
            "windows": {
                "commercial_gap_ids": [WINDOWS_SIGNED_INSTALLER_GAP_ID],
                "core_accuracy_gates": release_packaging_core_accuracy_gate(101),
                "functional_priority_profile": release_packaging_functional_priority_profile("windows"),
                "target_outputs": ["msi", "exe"],
                "current_status": "external-signing-required",
                "trusted_packaging_diff": missing_release_packaging_trusted_diff(101),
                "blockers": [WINDOWS_SIGNING_TRUSTED_DIFF_BLOCKER_101],
                "build_steps": [
                    "Build wheel/sdist and portable ZIP with scripts/build-release.py.",
                    "Wrap the release payload with the selected Windows installer tool.",
                    "Sign installer with Authenticode and trusted timestamp authority.",
                    "Run scripts/windows smoke test on a fresh Windows host.",
                ],
                "required_evidence": [
                    "Get-AuthenticodeSignature output",
                    "installer SHA256",
                    "timestamp authority proof",
                    "fresh Windows smoke folder",
                ],
            },
            "macos": {
                "commercial_gap_ids": [MACOS_NOTARIZED_PACKAGE_GAP_ID],
                "core_accuracy_gates": release_packaging_core_accuracy_gate(102),
                "functional_priority_profile": release_packaging_functional_priority_profile("macos"),
                "target_outputs": ["pkg", "dmg"],
                "current_status": "external-codesign-notarization-required",
                "trusted_packaging_diff": missing_release_packaging_trusted_diff(102),
                "blockers": [MACOS_NOTARIZATION_TRUSTED_DIFF_BLOCKER_102],
                "build_steps": [
                    "Build wheel/sdist and portable ZIP with scripts/build-release.py.",
                    "Wrap launcher and payload into pkg/dmg with hardened runtime settings where applicable.",
                    "Codesign package/app and submit for Apple notarization.",
                    "Run Gatekeeper assessment and macOS smoke test on a fresh host.",
                ],
                "required_evidence": [
                    "codesign --verify output",
                    "notarytool submission status",
                    "spctl Gatekeeper assessment",
                    "fresh macOS smoke folder",
                ],
            },
            "linux": {
                "commercial_gap_ids": [LINUX_PACKAGE_GAP_ID],
                "core_accuracy_gates": release_packaging_core_accuracy_gate(103),
                "functional_priority_profile": release_packaging_functional_priority_profile("linux"),
                "target_outputs": ["deb", "rpm", "AppImage"],
                "current_status": "portable-zip-wheel-ready-package-wrapper-pending",
                "trusted_packaging_diff": missing_release_packaging_trusted_diff(103),
                "blockers": [LINUX_PACKAGE_TRUSTED_DIFF_BLOCKER_103],
                "build_steps": [
                    "Build wheel/sdist and portable ZIP with scripts/build-release.py.",
                    "Generate distro package metadata from pyproject and dependency inventory.",
                    "Build deb/rpm/AppImage in clean containers.",
                    "Run install/uninstall and web smoke tests on target distributions.",
                ],
                "required_evidence": [
                    "package manager install logs",
                    "package SHA256",
                    "dependency resolution log",
                    "fresh Linux smoke folder",
                ],
            },
        },
        "release_gates": [
            "Do not claim signed Windows installer until Authenticode evidence is attached.",
            "Do not claim notarized macOS package until notary and Gatekeeper evidence is attached.",
            "Do not claim Linux package support beyond portable ZIP/wheel until deb/rpm/AppImage smoke evidence is attached.",
            "Do not enable public auto-update until artifacts are hosted, signed, and rollback-tested.",
        ],
    }
    (output_dir / "packaging-plan.json").write_text(json.dumps(plan, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (output_dir / "packaging-plan.md").write_text(render_packaging_plan_markdown(plan), encoding="utf-8")


def render_packaging_plan_markdown(plan: dict[str, object]) -> str:
    lines = [
        "# RapidTriage Packaging Plan",
        "",
        f"- Generated at: `{plan.get('generated_at', '')}`",
        "",
        "## Platform Packages",
        "",
    ]
    platform_packages = plan.get("platform_packages")
    if isinstance(platform_packages, dict):
        for name, payload in platform_packages.items():
            if not isinstance(payload, dict):
                continue
            lines.extend(
                [
                    f"### {name}",
                    "",
                    f"- Status: `{payload.get('current_status', '')}`",
                    f"- Targets: `{', '.join(payload.get('target_outputs', []))}`",
                    "- Required evidence:",
                    *[f"  - {item}" for item in payload.get("required_evidence", [])],
                    "",
                ]
            )
    lines.extend(["## Release Gates", ""])
    lines.extend(f"- {item}" for item in plan.get("release_gates", []))
    return "\n".join(lines) + "\n"


def write_update_manifest(output_dir: Path) -> None:
    artifacts = []
    for path in sorted(output_dir.iterdir()):
        if not path.is_file() or path.name in {"SHA256SUMS", "release-manifest.json", "update-manifest.json"}:
            continue
        artifacts.append(
            {
                "name": path.name,
                "size_bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "download_url": "",
                "signature_required": path.suffix.lower() in {".exe", ".msi", ".pkg", ".dmg", ".appimage"},
            }
        )
    trusted_diff = missing_release_packaging_trusted_diff(104)
    update_evidence_manifest = build_auto_update_channel_evidence_manifest(artifacts, trusted_diff)
    channel = "manual"
    enterprise_disable = True
    rollback_guidance = "Keep the previous portable ZIP and SHA256SUMS until the new release smoke tests pass."
    signature_policy = "Public distribution requires signed Windows/macOS artifacts; portable ZIP distribution must verify SHA256SUMS."
    auto_update_report_grade_validation_plan = build_auto_update_report_grade_validation_plan(
        update_evidence_manifest=update_evidence_manifest,
        artifacts=artifacts,
        trusted_diff=trusted_diff,
        channel=channel,
        enterprise_disable=enterprise_disable,
        rollback_guidance=rollback_guidance,
        signature_policy=signature_policy,
    )
    auto_update_blockers = sorted(
        {
            AUTO_UPDATE_TRUSTED_DIFF_BLOCKER_104,
            *[str(blocker) for blocker in auto_update_report_grade_validation_plan.get("blockers", [])],
        }
    )
    manifest = {
        "name": "rapidtriage-update-manifest",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "commercial_gap_ids": [AUTO_UPDATE_CHANNEL_GAP_ID],
        "core_accuracy_gates": release_packaging_core_accuracy_gate(
            104,
            evidence_manifest=update_evidence_manifest,
            report_grade_validation_plan=auto_update_report_grade_validation_plan,
        ),
        "channel": channel,
        "auto_update_enabled_by_default": False,
        "enterprise_disable": enterprise_disable,
        "rollback_guidance": rollback_guidance,
        "artifacts": artifacts,
        "signature_policy": signature_policy,
        "auto_update_evidence_manifest": update_evidence_manifest,
        "auto_update_evidence_manifest_hash": update_evidence_manifest["manifest_hash"],
        "evidence_slot_matrix_hash": update_evidence_manifest["evidence_slot_matrix_hash"],
        "auto_update_report_grade_validation_plan": auto_update_report_grade_validation_plan,
        "auto_update_report_grade_validation_plan_hash": auto_update_report_grade_validation_plan[
            "validation_plan_sha256"
        ],
        "auto_update_report_grade_ready_slot_count": auto_update_report_grade_validation_plan["ready_slot_count"],
        "auto_update_report_grade_blocking_slot_count": auto_update_report_grade_validation_plan["blocking_slot_count"],
        "update_evidence_slots": update_evidence_manifest["update_evidence_slots"],
        "trusted_auto_update_channel_diff": trusted_diff,
        "blockers": auto_update_blockers,
    }
    (output_dir / "update-manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def missing_release_packaging_trusted_diff(number: int) -> dict[str, object]:
    blockers = {
        101: WINDOWS_SIGNING_TRUSTED_DIFF_BLOCKER_101,
        102: MACOS_NOTARIZATION_TRUSTED_DIFF_BLOCKER_102,
        103: LINUX_PACKAGE_TRUSTED_DIFF_BLOCKER_103,
        104: AUTO_UPDATE_TRUSTED_DIFF_BLOCKER_104,
    }
    trusted_tools = {
        101: "authenticode-signature-log",
        102: "macos-notarization-log",
        103: "linux-package-smoke-log",
        104: "signed-update-channel-log",
    }
    gap_ids = {
        101: WINDOWS_SIGNED_INSTALLER_GAP_ID,
        102: MACOS_NOTARIZED_PACKAGE_GAP_ID,
        103: LINUX_PACKAGE_GAP_ID,
        104: AUTO_UPDATE_CHANNEL_GAP_ID,
    }
    return {
        "status": "missing",
        "trusted_tool": None,
        "commercial_gap_ids": [gap_ids[number]],
        "blocker": blockers[number],
        "required_trusted_tool": trusted_tools[number],
    }


def build_release_packaging_trusted_diff(
    number: int,
    rapid_payload: dict[str, object],
    trusted_payload: dict[str, object],
    *,
    trusted_tool: str,
) -> dict[str, object]:
    blockers = {
        101: WINDOWS_SIGNING_TRUSTED_DIFF_BLOCKER_101,
        102: MACOS_NOTARIZATION_TRUSTED_DIFF_BLOCKER_102,
        103: LINUX_PACKAGE_TRUSTED_DIFF_BLOCKER_103,
        104: AUTO_UPDATE_TRUSTED_DIFF_BLOCKER_104,
    }
    gap_ids = {
        101: WINDOWS_SIGNED_INSTALLER_GAP_ID,
        102: MACOS_NOTARIZED_PACKAGE_GAP_ID,
        103: LINUX_PACKAGE_GAP_ID,
        104: AUTO_UPDATE_CHANNEL_GAP_ID,
    }
    compared_fields = ["status", "required_evidence", "target_outputs", "artifacts", "signature_policy"]
    if number == 101:
        compared_fields.extend(
            [
                "windows_signing_evidence_manifest_hash",
                "signing_slots",
                "evidence_slot_matrix_hash",
                "windows_signing_report_grade_validation_plan_hash",
            ]
        )
    if number == 102:
        compared_fields.extend(
            [
                "macos_notarization_evidence_manifest_hash",
                "notarization_slots",
                "evidence_slot_matrix_hash",
                "macos_notarization_report_grade_validation_plan_hash",
            ]
        )
    if number == 103:
        compared_fields.extend(
            [
                "linux_package_evidence_manifest_hash",
                "package_evidence_slots",
                "evidence_slot_matrix_hash",
                "linux_package_report_grade_validation_plan_hash",
            ]
        )
    if number == 104:
        compared_fields.extend(
            [
                "auto_update_evidence_manifest_hash",
                "update_evidence_slots",
                "evidence_slot_matrix_hash",
                "auto_update_report_grade_validation_plan_hash",
            ]
        )
    mismatches = []
    for field in compared_fields:
        rapid_value = normalize_release_packaging_value(rapid_payload.get(field))
        trusted_value = normalize_release_packaging_value(trusted_payload.get(field))
        if rapid_value != trusted_value:
            mismatches.append({"field": field, "rapid": rapid_value, "trusted": trusted_value})
    status = "pass" if not mismatches and trusted_tool in RELEASE_PACKAGING_TRUSTED_TOOLS else "fail"
    return {
        "status": status,
        "trusted_tool": trusted_tool,
        "commercial_gap_ids": [gap_ids[number]],
        "compared_fields": compared_fields,
        "mismatches": mismatches,
        "blocker": None if status == "pass" else blockers[number],
    }


def normalize_release_packaging_value(value: object) -> object:
    if isinstance(value, list):
        return sorted(json.dumps(item, ensure_ascii=False, sort_keys=True, default=str) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return value


def release_packaging_functional_priority_profile(target: str) -> dict[str, object]:
    profiles = {
        "windows": {
            "item_number": 57,
            "implementation_track": "windows-installer",
            "status": "installer-plan-ready-external-signing-required",
            "target_outputs": ["msi", "exe"],
            "implemented_controls": {
                "portable_payload_generated": True,
                "windows_launcher_packaged": True,
                "fresh_windows_smoke_script_packaged": True,
                "installer_workflow_manifest_declared": True,
                "installer_evidence_slots_declared": True,
                "authenticode_signature_attached": False,
                "timestamp_authority_attached": False,
            },
            "failed_validation_check_ids": [
                "actual-msi-exe-build-not-attached",
                "authenticode-signature-not-attached",
                "fresh-windows-11-smoke-not-attached",
            ],
        },
        "portable": {
            "item_number": 58,
            "implementation_track": "windows-portable-mode",
            "status": "portable-zip-generated-smoke-required",
            "target_outputs": ["rapidtriage-portable.zip"],
            "implemented_controls": {
                "double_click_windows_launcher_packaged": True,
                "shell_launcher_packaged": True,
                "dependency_inventory_packaged": True,
                "optional_forensic_tool_preflight_documented": True,
                "windows_portable_mode_manifest_emitted": True,
                "fresh_windows_smoke_attached": False,
            },
            "failed_validation_check_ids": ["fresh-windows-portable-smoke-not-attached"],
        },
        "macos": {
            "item_number": 59,
            "implementation_track": "macos-package",
            "status": "package-plan-ready-external-notarization-required",
            "target_outputs": ["pkg", "dmg"],
            "implemented_controls": {
                "portable_payload_generated": True,
                "macos_linux_launcher_packaged": True,
                "macos_smoke_script_packaged": True,
                "package_workflow_manifest_declared": True,
                "notarization_evidence_slots_declared": True,
                "codesign_attached": False,
                "notarization_ticket_attached": False,
                "gatekeeper_assessment_attached": False,
            },
            "failed_validation_check_ids": [
                "actual-pkg-dmg-build-not-attached",
                "codesign-not-attached",
                "notarization-not-attached",
                "gatekeeper-smoke-not-attached",
            ],
        },
        "linux": {
            "item_number": 60,
            "implementation_track": "linux-packages",
            "status": "portable-wheel-ready-distro-packages-pending",
            "target_outputs": ["deb", "rpm", "AppImage"],
            "implemented_controls": {
                "portable_payload_generated": True,
                "wheel_sdist_supported": True,
                "dependency_inventory_packaged": True,
                "linux_smoke_script_packaged": True,
                "linux_package_workflow_manifest_declared": True,
                "package_evidence_slots_declared": True,
                "deb_build_attached": False,
                "rpm_build_attached": False,
                "appimage_build_attached": False,
            },
            "failed_validation_check_ids": [
                "deb-rpm-appimage-builds-not-attached",
                "clean-container-install-smoke-not-attached",
                "package-manager-uninstall-smoke-not-attached",
            ],
        },
    }
    profile = dict(profiles[target])
    profile["batch_id"] = FUNCTIONAL_PACKAGING_BATCH_ID
    profile["ready_for_commercial_release"] = False
    return profile


def release_packaging_core_accuracy_gate(
    number: int,
    *,
    trusted_diff: dict[str, object] | None = None,
    evidence_manifest: dict[str, object] | None = None,
    report_grade_validation_plan: dict[str, object] | None = None,
) -> list[dict[str, object]]:
    checks = {
        101: [
            "windows installer target declared",
            "authenticode evidence requirement recorded",
            "timestamp authority requirement recorded",
            "windows smoke test requirement recorded",
            "external signing blocker disclosed",
        ],
        102: [
            "macos package target declared",
            "codesign evidence requirement recorded",
            "notarization requirement recorded",
            "gatekeeper smoke requirement recorded",
            "external notarization blocker disclosed",
        ],
        103: [
            "linux package targets declared",
            "portable zip or python distribution generated",
            "dependency inventory generated",
            "linux smoke requirement recorded",
            "package wrapper blocker disclosed",
        ],
        104: [
            "update manifest generated",
            "artifact hashes recorded",
            "enterprise disable recorded",
            "rollback guidance recorded",
            "public hosting/signing blocker disclosed",
        ],
    }
    satisfied_checks = list(checks[number])
    if number == 101 and evidence_manifest:
        if evidence_manifest.get("release_artifact_hashes"):
            satisfied_checks.append("release artifact hashes captured")
        if evidence_manifest.get("manifest_hash"):
            satisfied_checks.append("windows signing evidence manifest hash emitted")
        if evidence_manifest.get("signing_slots"):
            satisfied_checks.append("windows signing evidence slots emitted")
        if evidence_manifest.get("evidence_slot_matrix_hash"):
            satisfied_checks.append("windows evidence slot matrix hash emitted")
    if number == 101 and report_grade_validation_plan:
        if report_grade_validation_plan.get("validation_plan_sha256"):
            satisfied_checks.append("windows signing report-grade validation plan")
        if int(report_grade_validation_plan.get("ready_slot_count") or 0) > 0:
            satisfied_checks.append("windows signing report-grade ready slots")
    if number == 102 and evidence_manifest:
        if evidence_manifest.get("release_artifact_hashes"):
            satisfied_checks.append("release artifact hashes captured")
        if evidence_manifest.get("manifest_hash"):
            satisfied_checks.append("macos notarization evidence manifest hash emitted")
        if evidence_manifest.get("notarization_slots"):
            satisfied_checks.append("macos notarization evidence slots emitted")
        if evidence_manifest.get("evidence_slot_matrix_hash"):
            satisfied_checks.append("macos evidence slot matrix hash emitted")
    if number == 102 and report_grade_validation_plan:
        if report_grade_validation_plan.get("validation_plan_sha256"):
            satisfied_checks.append("macos notarization report-grade validation plan")
        if int(report_grade_validation_plan.get("ready_slot_count") or 0) > 0:
            satisfied_checks.append("macos notarization report-grade ready slots")
    if number == 103 and evidence_manifest:
        if evidence_manifest.get("release_artifact_hashes"):
            satisfied_checks.append("release artifact hashes captured")
        if evidence_manifest.get("manifest_hash"):
            satisfied_checks.append("linux package evidence manifest hash emitted")
        if evidence_manifest.get("package_evidence_slots"):
            satisfied_checks.append("linux package evidence slots emitted")
        if evidence_manifest.get("evidence_slot_matrix_hash"):
            satisfied_checks.append("linux evidence slot matrix hash emitted")
    if number == 103 and report_grade_validation_plan:
        if report_grade_validation_plan.get("validation_plan_sha256"):
            satisfied_checks.append("linux package report-grade validation plan")
        if int(report_grade_validation_plan.get("ready_slot_count") or 0) > 0:
            satisfied_checks.append("linux package report-grade ready slots")
    if number == 104 and evidence_manifest:
        if evidence_manifest.get("release_artifact_hashes"):
            satisfied_checks.append("release artifact hashes captured")
        if evidence_manifest.get("manifest_hash"):
            satisfied_checks.append("auto-update evidence manifest hash emitted")
        if evidence_manifest.get("update_evidence_slots"):
            satisfied_checks.append("auto-update evidence slots emitted")
        if evidence_manifest.get("evidence_slot_matrix_hash"):
            satisfied_checks.append("auto-update evidence slot matrix hash emitted")
    if number == 104 and report_grade_validation_plan:
        if report_grade_validation_plan.get("validation_plan_sha256"):
            satisfied_checks.append("auto-update report-grade validation plan")
        if int(report_grade_validation_plan.get("ready_slot_count") or 0) > 0:
            satisfied_checks.append("auto-update report-grade ready slots")
    if trusted_diff and trusted_diff.get("status") == "pass":
        trusted_checks = {
            101: "trusted Windows Authenticode evidence diff pass",
            102: "trusted macOS notarization evidence diff pass",
            103: "trusted Linux package smoke diff pass",
            104: "trusted signed update channel diff pass",
        }
        satisfied_checks.append(trusted_checks[number])
    return [
        build_accuracy_gate(
            number,
            satisfied_checks=satisfied_checks,
            evidence_refs=["scripts/build-release.py", "release-manifest.json", "packaging-plan.json"],
        )
    ]


def missing_operations_document_trusted_diff(number: int) -> dict[str, object]:
    trusted_tools = {
        112: "release-notes-ci-gate",
        113: "lts-hotfix-policy-review",
        114: "support-desk-sla-attestation",
        115: "training-delivery-log",
        116: "quickstart-lab-run-log",
        117: "admin-deployment-proof",
    }
    gap_ids = {
        112: RELEASE_NOTES_CHANGELOG_GAP_ID,
        113: LTS_HOTFIX_POLICY_GAP_ID,
        114: SUPPORT_SLA_GAP_ID,
        115: TRAINING_CURRICULUM_GAP_ID,
        116: ANALYST_QUICKSTART_LAB_GAP_ID,
        117: ADMIN_DEPLOYMENT_GUIDE_GAP_ID,
    }
    return {
        "status": "missing",
        "trusted_tool": None,
        "commercial_gap_ids": [gap_ids[number]],
        "blocker": OPERATIONS_DOCUMENT_TRUSTED_DIFF_BLOCKERS[number],
        "required_trusted_tool": trusted_tools[number],
    }


def build_operations_document_trusted_diff(
    number: int,
    rapid_payload: dict[str, object],
    trusted_payload: dict[str, object],
    *,
    trusted_tool: str,
) -> dict[str, object]:
    gap_ids = {
        112: RELEASE_NOTES_CHANGELOG_GAP_ID,
        113: LTS_HOTFIX_POLICY_GAP_ID,
        114: SUPPORT_SLA_GAP_ID,
        115: TRAINING_CURRICULUM_GAP_ID,
        116: ANALYST_QUICKSTART_LAB_GAP_ID,
        117: ADMIN_DEPLOYMENT_GUIDE_GAP_ID,
    }
    compared_fields = [
        "status",
        "documents",
        "commercial_gap_ids",
        "document_evidence_manifest_hashes",
        "document_evidence_matrix_hashes",
        "document_report_grade_validation_plan_hashes",
        "document_evidence_slots",
    ]
    mismatches = []
    for field in compared_fields:
        rapid_value = normalize_release_packaging_value(rapid_payload.get(field))
        trusted_value = normalize_release_packaging_value(trusted_payload.get(field))
        if rapid_value != trusted_value:
            mismatches.append({"field": field, "rapid": rapid_value, "trusted": trusted_value})
    status = "pass" if not mismatches and trusted_tool in OPERATIONS_DOCUMENT_TRUSTED_TOOLS else "fail"
    return {
        "status": status,
        "trusted_tool": trusted_tool,
        "commercial_gap_ids": [gap_ids[number]],
        "compared_fields": compared_fields,
        "mismatches": mismatches,
        "blocker": None if status == "pass" else OPERATIONS_DOCUMENT_TRUSTED_DIFF_BLOCKERS[number],
    }


def operations_documents_core_accuracy_gates(
    trusted_diffs: dict[int, dict[str, object]] | None = None,
    evidence_manifests: dict[str, dict[str, object]] | None = None,
    report_grade_validation_plans: dict[str, dict[str, object]] | None = None,
) -> list[dict[str, object]]:
    checks_by_item = {
        112: ["release notes template packaged", "known limits section required", "validation state section required", "migration notes section required", "CI changelog blocker disclosed"],
        113: ["LTS policy document packaged", "hotfix criteria documented", "backport validation documented", "emergency patch gate documented", "operator maintenance blocker disclosed"],
        114: ["support SLA document packaged", "severity levels emitted", "response targets emitted", "secure intake requirement emitted", "staffed support blocker disclosed"],
        115: ["training curriculum packaged", "analyst curriculum documented", "admin curriculum documented", "validation exercise documented", "training delivery blocker disclosed"],
        116: ["quickstart lab documented", "sample workflow command recorded", "ingest/search/review/report steps documented", "bundle verification documented", "real training run blocker disclosed"],
        117: ["admin guide packaged", "install/update guidance documented", "auth/network guidance documented", "backup/restore guidance documented", "admin coverage manifest emitted", "deployment proof blocker disclosed"],
        118: ["security baseline emitted", "auth/network hardening documented", "export rendering safety documented", "crash redaction documented", "independent AppSec blocker disclosed"],
        119: ["preview sandboxing documented", "active content blocking documented", "parser crash isolation documented", "hostile evidence guidance documented", "OS sandbox blocker disclosed"],
        120: ["dependency inventory emitted", "vulnerability scan attempted", "release blocking policy recorded", "dependency monitoring script packaged", "CI scheduled scan blocker disclosed"],
    }
    trusted_checks = {
        112: "trusted release notes CI gate diff pass",
        113: "trusted LTS/hotfix policy diff pass",
        114: "trusted support desk SLA diff pass",
        115: "trusted training delivery diff pass",
        116: "trusted quickstart lab run diff pass",
        117: "trusted admin deployment proof diff pass",
    }
    report_grade_checks = {
        112: (
            "release notes report-grade validation plan",
            "release notes report-grade ready slots",
        ),
        113: (
            "LTS/hotfix report-grade validation plan",
            "LTS/hotfix report-grade ready slots",
        ),
        114: (
            "support SLA report-grade validation plan",
            "support SLA report-grade ready slots",
        ),
    }
    gates = []
    for number, checks in checks_by_item.items():
        satisfied = list(checks)
        evidence_manifest = (evidence_manifests or {}).get(str(number), {})
        report_grade_plan = (report_grade_validation_plans or {}).get(str(number), {})
        if evidence_manifest.get("manifest_hash"):
            satisfied.append("operations evidence manifest hash emitted")
        if evidence_manifest.get("evidence_slots"):
            satisfied.append("operations evidence slots emitted")
        if evidence_manifest.get("document_evidence_matrix_hash"):
            satisfied.append("operations document evidence matrix hash emitted")
        if report_grade_plan and number in report_grade_checks:
            plan_check, ready_check = report_grade_checks[number]
            if report_grade_plan.get("validation_plan_hash"):
                satisfied.append(plan_check)
            if int(report_grade_plan.get("ready_slot_count") or 0) > 0:
                satisfied.append(ready_check)
        if trusted_diffs and trusted_diffs.get(number, {}).get("status") == "pass" and number in trusted_checks:
            satisfied.append(trusted_checks[number])
        evidence_refs = ["rapidtriage-portable.zip", "docs operations package", "scripts/check-dependencies.py"]
        if report_grade_plan.get("validation_plan_hash"):
            evidence_refs.append(
                f"operations_document_{number}_report_grade_validation_plan_sha256:{report_grade_plan['validation_plan_hash']}"
            )
            evidence_refs.append(
                f"operations_document_{number}_report_grade_ready_slots:{report_grade_plan.get('ready_slot_count')}"
            )
            evidence_refs.append(
                f"operations_document_{number}_report_grade_blocking_slots:{report_grade_plan.get('blocking_slot_count')}"
            )
        gates.append(
            build_accuracy_gate(
                number,
                satisfied_checks=satisfied,
                evidence_refs=evidence_refs,
            )
        )
    return gates


def release_operations_functional_priority_profiles() -> list[dict[str, object]]:
    return [
        {
            "batch_id": FUNCTIONAL_OPERATIONS_BATCH_ID,
            "item_number": 66,
            "implementation_track": "admin-guide",
            "status": "packaged-admin-guide-deployment-proof-required",
            "documents": ["docs/rapidtriage-admin-deployment-guide.md"],
            "implemented_controls": {
                "install_guidance_documented": True,
                "update_guidance_documented": True,
                "auth_network_guidance_documented": True,
                "backup_restore_guidance_documented": True,
                "logging_security_dependency_guidance_documented": True,
                "evidence_handling_guidance_documented": True,
                "admin_guide_coverage_manifest_declared": True,
            },
            "failed_validation_check_ids": [
                "fresh-admin-deployment-proof-not-attached",
                "operator-acceptance-signoff-not-attached",
            ],
            "ready_for_commercial_release": False,
        },
        {
            "batch_id": FUNCTIONAL_OPERATIONS_BATCH_ID,
            "item_number": 67,
            "implementation_track": "training-lab",
            "status": "curriculum-packaged-real-lab-run-required",
            "documents": [
                "docs/rapidtriage-training-curriculum.md",
                "docs/rapidtriage-windows-quickstart.md",
                "docs/rapidtriage-macos-linux-quickstart.md",
            ],
            "implemented_controls": {
                "sample_case_workflow_documented": True,
                "ingest_search_viewer_review_report_steps_documented": True,
                "manifest_verification_documented": True,
                "training_lab_workflow_manifest_emitted_by_sample_run": True,
                "analyst_curriculum_documented": True,
                "admin_curriculum_documented": True,
            },
            "failed_validation_check_ids": [
                "real-training-run-log-not-attached",
                "analyst-scoring-rubric-results-not-attached",
            ],
            "ready_for_commercial_release": False,
        },
        {
            "batch_id": FUNCTIONAL_OPERATIONS_BATCH_ID,
            "item_number": 68,
            "implementation_track": "support-process",
            "status": "sla-template-packaged-staffed-desk-required",
            "documents": ["docs/rapidtriage-support-sla.md"],
            "implemented_controls": {
                "support_sla_documented": True,
                "severity_levels_documented": True,
                "response_targets_documented": True,
                "secure_evidence_intake_required": True,
                "emergency_patch_policy_documented": True,
                "support_process_readiness_manifest_declared": True,
            },
            "failed_validation_check_ids": [
                "staffed-support-desk-not-attached",
                "contractual-sla-evidence-not-attached",
                "secure-intake-runbook-signoff-not-attached",
            ],
            "ready_for_commercial_release": False,
        },
        {
            "batch_id": FUNCTIONAL_OPERATIONS_BATCH_ID,
            "item_number": 69,
            "implementation_track": "release-discipline",
            "status": "release-templates-packaged-ci-gates-required",
            "documents": [
                "docs/rapidtriage-release-notes-template.md",
                "docs/rapidtriage-known-limitations.md",
                "docs/rapidtriage-lts-hotfix-policy.md",
            ],
            "implemented_controls": {
                "release_notes_template_packaged": True,
                "known_limits_document_packaged": True,
                "migration_notes_required": True,
                "validation_state_required": True,
                "checksums_generated": True,
                "smoke_logs_required": True,
                "release_discipline_manifest_declared": True,
            },
            "failed_validation_check_ids": [
                "release-notes-ci-gate-not-attached",
                "required-smoke-logs-not-attached",
                "migration-note-review-not-attached",
            ],
            "ready_for_commercial_release": False,
        },
        {
            "batch_id": FUNCTIONAL_OPERATIONS_BATCH_ID,
            "item_number": 70,
            "implementation_track": "external-blocker-ledger",
            "status": "blockers-explicit-not-complete",
            "documents": [
                "release-manifest.json",
                "packaging-plan.json",
                "rapidtriage-commercial-readiness.json",
            ],
            "implemented_controls": {
                "independent_validation_blocker_tracked": True,
                "large_hardware_test_blocker_tracked": True,
                "code_signing_blocker_tracked": True,
                "notarization_blocker_tracked": True,
                "staffed_support_blocker_tracked": True,
                "commercial_claim_guard_present": True,
                "external_blocker_ledger_manifest_declared": True,
            },
            "failed_validation_check_ids": [
                "independent-validation-not-attached",
                "large-hardware-test-evidence-not-attached",
                "code-signing-not-attached",
                "notarization-not-attached",
                "staffed-support-not-attached",
            ],
            "ready_for_commercial_release": False,
        },
    ]


def verify_sha256s(output_dir: Path) -> int:
    checksum_path = output_dir / "SHA256SUMS"
    if not checksum_path.is_file():
        print(f"Missing checksum file: {checksum_path}", file=sys.stderr)
        return 1

    failures: list[str] = []
    checked = 0
    for raw_line in checksum_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            expected, name = line.split(None, 1)
        except ValueError:
            failures.append(f"Malformed checksum row: {raw_line}")
            continue
        path = output_dir / name.strip()
        if not path.is_file():
            failures.append(f"Missing artifact: {name.strip()}")
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        checked += 1
        if actual.lower() != expected.lower():
            failures.append(f"Checksum mismatch: {name.strip()}")

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    print(f"Verified {checked} SHA256 checksums in {checksum_path}")
    return 0


def git_value(repo: Path, args: list[str]) -> str | None:
    result = subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        return None
    return result.stdout.strip()


if __name__ == "__main__":
    raise SystemExit(main())
