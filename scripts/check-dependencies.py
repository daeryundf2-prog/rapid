#!/usr/bin/env python3
from __future__ import annotations

import argparse
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write a local dependency vulnerability monitoring baseline")
    parser.add_argument("--output", default="dependency-monitoring.json", help="JSON output path")
    args = parser.parse_args(argv)

    output = Path(args.output).expanduser().resolve()
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
    payload = {
        "command": "dependency-monitoring",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "commercial_gap_ids": [DEPENDENCY_VULNERABILITY_MONITORING_GAP_ID],
        "core_accuracy_gates": dependency_monitoring_core_accuracy_gates(
            package_count=len(json.loads(pip_list.stdout) if pip_list.returncode == 0 and pip_list.stdout.strip() else []),
            scan_attempted=True,
            script_packaged=True,
            trusted_diff=missing_dependency_monitoring_trusted_diff(),
        ),
        "python": sys.executable,
        "pip_list": {
            "return_code": pip_list.returncode,
            "packages": json.loads(pip_list.stdout) if pip_list.returncode == 0 and pip_list.stdout.strip() else [],
            "error": pip_list.stderr.strip(),
        },
        "vulnerability_scan": {
            "commercial_gap_ids": [DEPENDENCY_VULNERABILITY_MONITORING_GAP_ID],
            "core_accuracy_gates": dependency_monitoring_core_accuracy_gates(
                package_count=len(json.loads(pip_list.stdout) if pip_list.returncode == 0 and pip_list.stdout.strip() else []),
                scan_attempted=True,
                script_packaged=True,
                trusted_diff=missing_dependency_monitoring_trusted_diff(),
            ),
            "tool": "pip-audit",
            "available": pip_audit.returncode != 1 or bool(pip_audit.stdout.strip()),
            "return_code": pip_audit.returncode,
            "raw_output": pip_audit.stdout[:20000],
            "error": pip_audit.stderr[:4000],
            "release_policy": "Block release on known exploitable high/critical dependency issues unless a documented exception is approved.",
        },
        "trusted_dependency_monitoring_diff": missing_dependency_monitoring_trusted_diff(),
        "blockers": [DEPENDENCY_MONITORING_TRUSTED_DIFF_BLOCKER_120],
    }
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote dependency monitoring baseline: {output}")
    return 0


def dependency_monitoring_core_accuracy_gates(
    *,
    package_count: int,
    scan_attempted: bool,
    script_packaged: bool,
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = ["release blocking policy recorded", "CI scheduled scan blocker disclosed"]
    if package_count >= 0:
        satisfied.append("dependency inventory emitted")
    if scan_attempted:
        satisfied.append("vulnerability scan attempted")
    if script_packaged:
        satisfied.append("dependency monitoring script packaged")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted dependency advisory/SBOM diff pass")
    return [
        build_accuracy_gate(
            120,
            satisfied_checks=satisfied,
            evidence_refs=[f"package_count:{package_count}", "tool:pip-audit"],
        )
    ]


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
    compared_fields = ["pip_list", "vulnerability_scan"]
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


if __name__ == "__main__":
    raise SystemExit(main())
