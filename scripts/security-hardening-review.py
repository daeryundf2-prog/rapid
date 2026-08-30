#!/usr/bin/env python3
from __future__ import annotations

# Force UTF-8 stdio so JSON output with non-ASCII evidence text (e.g.
# Korean filenames) survives Windows consoles whose default codec is cp1252.
import sys as _sys

if hasattr(_sys.stdout, "reconfigure"):
    _sys.stdout.reconfigure(encoding="utf-8")
if hasattr(_sys.stderr, "reconfigure"):
    _sys.stderr.reconfigure(encoding="utf-8")

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rapidtriage.core.enterprise import build_enterprise_policy


def stable_hash(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate release security hardening self-review evidence")
    parser.add_argument("--output", default="security-hardening-review.json", help="JSON output path")
    parser.add_argument("--json", action="store_true", help="Print the review payload as JSON")
    args = parser.parse_args(argv)

    repo = Path(__file__).resolve().parent.parent
    output = Path(args.output).expanduser().resolve()
    policy = build_enterprise_policy()
    security = policy.get("security_hardening") if isinstance(policy.get("security_hardening"), dict) else {}
    telemetry = policy.get("telemetry") if isinstance(policy.get("telemetry"), dict) else {}
    network = policy.get("network") if isinstance(policy.get("network"), dict) else {}
    crash = policy.get("crash_reporting") if isinstance(policy.get("crash_reporting"), dict) else {}
    baseline = (
        security.get("security_hardening_baseline_manifest")
        if isinstance(security.get("security_hardening_baseline_manifest"), dict)
        else {}
    )
    hardening_manifest = (
        security.get("security_hardening_evidence_manifest")
        if isinstance(security.get("security_hardening_evidence_manifest"), dict)
        else {}
    )
    malicious_manifest = (
        security.get("malicious_sandbox_evidence_manifest")
        if isinstance(security.get("malicious_sandbox_evidence_manifest"), dict)
        else {}
    )
    docs = {
        "admin_deployment_guide": repo / "docs" / "rapidtriage-admin-deployment-guide.md",
        "security_policy": repo / "docs" / "rapidtriage-security-policy.md",
        "release_checklist": repo / "docs" / "rapidtriage-release-checklist.md",
    }
    doc_hashes = {name: file_hash(path) for name, path in docs.items()}
    blockers = security.get("blockers") if isinstance(security.get("blockers"), list) else []
    checks = {
        "security_section_present": bool(security),
        "telemetry_uploads_disabled": telemetry.get("evidence_uploads") is False and telemetry.get("crash_uploads") is False,
        "remote_bind_requires_auth": network.get("remote_requires_auth_token") is True,
        "crash_uploads_disabled": crash.get("uploads_enabled") is False,
        "baseline_manifest_hash_present": isinstance(security.get("security_hardening_baseline_manifest_hash"), str)
        and len(str(security.get("security_hardening_baseline_manifest_hash"))) == 64,
        "hardening_manifest_hash_present": isinstance(security.get("security_hardening_evidence_manifest_hash"), str)
        and len(str(security.get("security_hardening_evidence_manifest_hash"))) == 64,
        "malicious_sandbox_manifest_hash_present": isinstance(security.get("malicious_sandbox_evidence_manifest_hash"), str)
        and len(str(security.get("malicious_sandbox_evidence_manifest_hash"))) == 64,
        "control_matrix_hash_present": isinstance(security.get("control_evidence_matrix_hash"), str)
        and len(str(security.get("control_evidence_matrix_hash"))) == 64,
        "docs_present_and_hashed": all(bool(value) for value in doc_hashes.values()),
        "appsec_blocker_preserved": "trusted-security-hardening-review-diff-missing" in blockers,
        "malicious_corpus_blocker_preserved": "trusted-malicious-evidence-sandbox-diff-missing" in blockers,
        "os_sandbox_limitation_preserved": security.get("parser_sandboxing", "").find("OS-level") >= 0,
    }
    payload: dict[str, Any] = {
        "command": "security-hardening-review",
        "profile_version": "security-hardening-release-review-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "commercial_gap_ids": ["#118", "#119"],
        "policy_version": policy.get("policy_version"),
        "doc_hashes": doc_hashes,
        "baseline_manifest_hash": baseline.get("manifest_hash"),
        "security_hardening_evidence_manifest_hash": hardening_manifest.get("manifest_hash"),
        "malicious_sandbox_evidence_manifest_hash": malicious_manifest.get("manifest_hash"),
        "control_evidence_matrix_hash": security.get("control_evidence_matrix_hash"),
        "trusted_security_hardening_diff": security.get("trusted_security_hardening_diff"),
        "trusted_malicious_sandbox_diff": security.get("trusted_malicious_sandbox_diff"),
        "checks": checks,
        "passed_check_count": sum(1 for passed in checks.values() if passed),
        "failed_check_ids": [name for name, passed in checks.items() if not passed],
        "commercial_claim_allowed": False,
        "remaining_external_validation": [
            "Attach independent AppSec review before claiming commercial security-hardening readiness.",
            "Attach malicious corpus/fuzz validation and OS-level sandbox proof before hostile-evidence containment claims.",
        ],
    }
    payload["review_hash"] = stable_hash(payload)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"Wrote security hardening review evidence: {output}")
    return 0 if not payload["failed_check_ids"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
