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

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rapidtriage.core.commercial_readiness import build_commercial_readiness_report
from rapidtriage.core.forensic_accuracy import build_accuracy_gate

WINDOWS_SIGNED_INSTALLER_GAP_ID = "#101"
MACOS_NOTARIZED_PACKAGE_GAP_ID = "#102"
LINUX_PACKAGE_GAP_ID = "#103"
AUTO_UPDATE_CHANNEL_GAP_ID = "#104"
RELEASE_NOTES_CHANGELOG_GAP_ID = "#112"
LTS_HOTFIX_POLICY_GAP_ID = "#113"
SUPPORT_SLA_GAP_ID = "#114"
TRAINING_CURRICULUM_GAP_ID = "#115"
ANALYST_QUICKSTART_LAB_GAP_ID = "#116"
ADMIN_DEPLOYMENT_GUIDE_GAP_ID = "#117"
SECURITY_HARDENING_REVIEW_GAP_ID = "#118"
MALICIOUS_EVIDENCE_SANDBOXING_GAP_ID = "#119"
DEPENDENCY_VULNERABILITY_MONITORING_GAP_ID = "#120"


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


def write_release_manifest(output_dir: Path, repo: Path, commercial_readiness: dict[str, object] | None = None) -> None:
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
                "core_accuracy_gates": release_packaging_core_accuracy_gate(101),
                "required_evidence": ["Authenticode signature", "timestamp authority", "fresh Windows smoke test"],
            },
            "macos_notarized_package": {
                "status": "external-required",
                "commercial_gap_ids": [MACOS_NOTARIZED_PACKAGE_GAP_ID],
                "core_accuracy_gates": release_packaging_core_accuracy_gate(102),
                "required_evidence": ["codesign verification", "notarization ticket", "Gatekeeper assessment"],
            },
            "linux_package": {
                "status": "packaging-plan-ready",
                "commercial_gap_ids": [LINUX_PACKAGE_GAP_ID],
                "core_accuracy_gates": release_packaging_core_accuracy_gate(103),
                "supported_outputs": ["portable zip", "wheel", "sdist"],
                "future_outputs": ["deb", "rpm", "AppImage"],
                "plan": "packaging-plan.json",
            },
            "auto_update_channel": {
                "status": "manifest-generated",
                "commercial_gap_ids": [AUTO_UPDATE_CHANNEL_GAP_ID],
                "core_accuracy_gates": release_packaging_core_accuracy_gate(104),
                "manifest": "update-manifest.json",
                "enterprise_disable_supported": True,
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
                "core_accuracy_gates": operations_documents_core_accuracy_gates(),
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
                "target_outputs": ["msi", "exe"],
                "current_status": "external-signing-required",
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
                "target_outputs": ["pkg", "dmg"],
                "current_status": "external-codesign-notarization-required",
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
                "target_outputs": ["deb", "rpm", "AppImage"],
                "current_status": "portable-zip-wheel-ready-package-wrapper-pending",
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
    manifest = {
        "name": "rapidtriage-update-manifest",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "commercial_gap_ids": [AUTO_UPDATE_CHANNEL_GAP_ID],
        "core_accuracy_gates": release_packaging_core_accuracy_gate(104),
        "channel": "manual",
        "auto_update_enabled_by_default": False,
        "enterprise_disable": True,
        "rollback_guidance": "Keep the previous portable ZIP and SHA256SUMS until the new release smoke tests pass.",
        "artifacts": artifacts,
        "signature_policy": "Public distribution requires signed Windows/macOS artifacts; portable ZIP distribution must verify SHA256SUMS.",
    }
    (output_dir / "update-manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def release_packaging_core_accuracy_gate(number: int) -> list[dict[str, object]]:
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
    return [
        build_accuracy_gate(
            number,
            satisfied_checks=checks[number],
            evidence_refs=["scripts/build-release.py", "release-manifest.json", "packaging-plan.json"],
        )
    ]


def operations_documents_core_accuracy_gates() -> list[dict[str, object]]:
    checks_by_item = {
        112: ["release notes template packaged", "known limits section required", "validation state section required", "migration notes section required", "CI changelog blocker disclosed"],
        113: ["LTS policy document packaged", "hotfix criteria documented", "backport validation documented", "emergency patch gate documented", "operator maintenance blocker disclosed"],
        114: ["support SLA document packaged", "severity levels emitted", "response targets emitted", "secure intake requirement emitted", "staffed support blocker disclosed"],
        115: ["training curriculum packaged", "analyst curriculum documented", "admin curriculum documented", "validation exercise documented", "training delivery blocker disclosed"],
        116: ["quickstart lab documented", "sample workflow command recorded", "ingest/search/review/report steps documented", "bundle verification documented", "real training run blocker disclosed"],
        117: ["admin guide packaged", "install/update guidance documented", "auth/network guidance documented", "backup/restore guidance documented", "deployment proof blocker disclosed"],
        118: ["security baseline emitted", "auth/network hardening documented", "export rendering safety documented", "crash redaction documented", "independent AppSec blocker disclosed"],
        119: ["preview sandboxing documented", "active content blocking documented", "parser crash isolation documented", "hostile evidence guidance documented", "OS sandbox blocker disclosed"],
        120: ["dependency inventory emitted", "vulnerability scan attempted", "release blocking policy recorded", "dependency monitoring script packaged", "CI scheduled scan blocker disclosed"],
    }
    return [
        build_accuracy_gate(
            number,
            satisfied_checks=checks,
            evidence_refs=["rapidtriage-portable.zip", "docs operations package", "scripts/check-dependencies.py"],
        )
        for number, checks in checks_by_item.items()
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
