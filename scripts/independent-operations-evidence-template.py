#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ITEMS: list[dict[str, Any]] = [
    {
        "number": 14,
        "title": "Independent AppSec review package",
        "status": "external-evidence-required",
        "checks": {
            "architecture_overview_attached": False,
            "threat_model_attached": False,
            "auth_network_boundary_attached": False,
            "export_rendering_policy_attached": False,
            "sandbox_design_attached": False,
            "dependency_report_attached": False,
        },
        "required_files": [],
    },
    {
        "number": 15,
        "title": "Independent AppSec or lab signoff",
        "status": "external-evidence-required",
        "reviewer_identity": "",
        "checks": {
            "signed_report_attached": False,
            "scope_recorded": False,
            "findings_recorded": False,
            "exceptions_recorded": False,
            "residual_risk_recorded": False,
        },
        "required_files": [],
    },
    {
        "number": 16,
        "title": "Support SLA ownership",
        "status": "external-evidence-required",
        "support_contact": "",
        "checks": {
            "support_contact_defined": False,
            "severity_matrix_defined": False,
            "staffed_schedule_defined": False,
            "escalation_owner_defined": False,
            "secure_intake_defined": False,
        },
        "required_files": [],
    },
    {
        "number": 17,
        "title": "Emergency hotfix drill",
        "status": "external-evidence-required",
        "checks": {
            "simulated_issue_recorded": False,
            "patch_branch_recorded": False,
            "validation_run_attached": False,
            "signed_build_attached": False,
            "rollback_note_attached": False,
        },
        "required_files": [],
    },
    {
        "number": 18,
        "title": "Final commercial release evidence gate",
        "status": "external-evidence-required",
        "checks": {
            "release_package_attached": False,
            "platform_smoke_outputs_attached": False,
            "signing_notarization_logs_attached": False,
            "dependency_sbom_attached": False,
            "sandbox_corpus_results_attached": False,
            "appsec_signoff_attached": False,
            "support_evidence_attached": False,
            "remaining_blockers_owner_assigned": False,
        },
        "required_files": [],
    },
]


def stable_hash(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


def build_template() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "profile_version": "independent-operations-evidence-v1",
        "scope": "independent-validation-operations-14-18",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "instructions": [
            "Replace every status with 'pass' only after independent review, support, hotfix, and final release evidence is attached.",
            "Every required_files row must include a local path and SHA256 matching the attached artifact.",
            "Do not mark item 18 pass unless the final release evidence gate references all previous evidence families.",
        ],
        "items": ITEMS,
    }
    payload["evidence_package_hash"] = stable_hash(payload)
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create independent validation and operations 14-18 evidence template")
    parser.add_argument("--output", default="independent-operations-evidence.template.json", help="Template JSON output path")
    parser.add_argument("--json", action="store_true", help="Print template JSON")
    args = parser.parse_args(argv)

    payload = build_template()
    output = Path(args.output).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"Wrote independent operations evidence template: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
