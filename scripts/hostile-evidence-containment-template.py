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
        "number": 9,
        "title": "Parser sandbox design",
        "status": "external-evidence-required",
        "checks": {
            "threat_model_attached": False,
            "allowed_paths_defined": False,
            "network_policy_defined": False,
            "resource_limits_defined": False,
            "os_matrix_defined": False,
        },
        "required_files": [],
    },
    {
        "number": 10,
        "title": "OS-level parser sandbox implementation",
        "status": "external-evidence-required",
        "checks": {
            "os_level_sandbox_enabled": False,
            "write_escape_blocked": False,
            "network_blocked": False,
            "kill_timeout_supported": False,
        },
        "required_files": [],
    },
    {
        "number": 11,
        "title": "Sandbox escape, timeout, memory, and network tests",
        "status": "external-evidence-required",
        "checks": {
            "path_escape_test_passed": False,
            "network_probe_blocked": False,
            "timeout_test_passed": False,
            "memory_pressure_test_passed": False,
            "active_content_test_passed": False,
        },
        "required_files": [],
    },
    {
        "number": 12,
        "title": "Malicious/corrupt corpus assembly",
        "status": "external-evidence-required",
        "checks": {
            "corpus_manifest_attached": False,
            "license_notes_attached": False,
            "expected_behavior_recorded": False,
            "quarantine_expectations_recorded": False,
            "artifact_families_covered": False,
        },
        "required_files": [],
    },
    {
        "number": 13,
        "title": "Fuzz and crash-quarantine run",
        "status": "external-evidence-required",
        "checks": {
            "fuzz_command_recorded": False,
            "seed_corpus_hash_recorded": False,
            "crash_quarantine_recorded": False,
            "timeout_count_recorded": False,
            "no_silent_corruption": False,
        },
        "required_files": [],
    },
]


def stable_hash(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


def build_template() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "profile_version": "hostile-evidence-containment-v1",
        "scope": "hostile-evidence-containment-9-13",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "instructions": [
            "Replace every status with 'pass' only after real sandbox/corpus/fuzz evidence is attached.",
            "Every required_files row must include a local path and SHA256 matching the attached artifact.",
            "Do not set os_level_sandbox_enabled=true until the platform sandbox proof is attached.",
        ],
        "items": ITEMS,
    }
    payload["evidence_package_hash"] = stable_hash(payload)
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create a hostile evidence containment 9-13 JSON template")
    parser.add_argument("--output", default="hostile-evidence-containment.template.json", help="Template JSON output path")
    parser.add_argument("--json", action="store_true", help="Print template JSON")
    args = parser.parse_args(argv)

    payload = build_template()
    output = Path(args.output).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"Wrote hostile evidence containment template: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
