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
        "number": 1,
        "title": "CI advisory scan artifact",
        "status": "external-evidence-required",
        "ci_run_url": "",
        "checks": {"ci_artifact_attached": False},
        "required_files": [],
    },
    {
        "number": 2,
        "title": "SBOM publication evidence",
        "status": "external-evidence-required",
        "sbom_path": "",
        "sbom_url": "",
        "checks": {"sbom_hash_matches_release": False},
        "required_files": [],
    },
    {
        "number": 3,
        "title": "Windows signed build pipeline",
        "status": "external-evidence-required",
        "certificate_subject": "",
        "checks": {"authenticode_valid": False},
        "required_files": [],
    },
    {
        "number": 4,
        "title": "Windows 11 fresh-machine smoke",
        "status": "external-evidence-required",
        "platform": "Windows 11",
        "checks": {"windows_11_smoke_passed": False},
        "required_files": [],
    },
    {
        "number": 5,
        "title": "macOS signed and notarized build pipeline",
        "status": "external-evidence-required",
        "checks": {
            "codesign_verified": False,
            "notarization_accepted": False,
            "gatekeeper_accepted": False,
        },
        "required_files": [],
    },
    {
        "number": 6,
        "title": "macOS Gatekeeper smoke",
        "status": "external-evidence-required",
        "platform": "macOS",
        "checks": {"gatekeeper_smoke_passed": False},
        "required_files": [],
    },
    {
        "number": 7,
        "title": "Linux package smoke",
        "status": "external-evidence-required",
        "checks": {"install_smoke_passed": False, "uninstall_smoke_passed": False},
        "required_files": [],
    },
    {
        "number": 8,
        "title": "Release evidence verifier schema expansion",
        "status": "external-evidence-required",
        "checks": {
            "verifier_schema_updated": True,
            "missing_evidence_fails": True,
            "attached_hashes_checked": True,
        },
        "required_files": [],
    },
]


def stable_hash(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


def build_template() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "profile_version": "external-commercial-evidence-v1",
        "scope": "release-artifact-evidence-1-8",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "instructions": [
            "Replace every status with 'pass' only after real external evidence is attached.",
            "Every required_files row must include a local path and SHA256 matching the attached artifact.",
            "Do not fabricate signing, notarization, CI, SBOM, smoke, or package evidence.",
        ],
        "items": ITEMS,
    }
    payload["evidence_package_hash"] = stable_hash(payload)
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create an external commercial evidence 1-8 JSON template")
    parser.add_argument("--output", default="external-commercial-evidence.template.json", help="Template JSON output path")
    parser.add_argument("--json", action="store_true", help="Print template JSON")
    args = parser.parse_args(argv)

    payload = build_template()
    output = Path(args.output).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"Wrote external commercial evidence template: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
