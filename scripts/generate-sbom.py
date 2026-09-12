#!/usr/bin/env python3
"""Generate a CycloneDX-style SBOM for the RapidTriage release environment.

Lists installed Python distributions via ``importlib.metadata`` (no new
dependencies) plus tool/runtime versions. Output is CycloneDX-shaped JSON:
``bomFormat``/``specVersion``/``metadata``/``components``, suitable for
dependency-inventory evidence attached to a release.

Usage:
    python scripts/generate-sbom.py --output release/sbom.cyclonedx.json
    python scripts/generate-sbom.py --json
"""
from __future__ import annotations

# Force UTF-8 stdio so JSON output survives Windows consoles (cp1252).
import sys as _sys

if hasattr(_sys.stdout, "reconfigure"):
    _sys.stdout.reconfigure(encoding="utf-8")
if hasattr(_sys.stderr, "reconfigure"):
    _sys.stderr.reconfigure(encoding="utf-8")

import argparse
import importlib.metadata
import json
import platform
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

SBOM_SPEC_VERSION = "1.5"
GENERATOR_NAME = "rapidtriage-generate-sbom"


def _normalized_purl_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _project_version(repo: Path) -> str:
    try:
        return importlib.metadata.version("rapidtriage")
    except importlib.metadata.PackageNotFoundError:
        pass
    pyproject = repo / "pyproject.toml"
    if pyproject.is_file():
        match = re.search(r'(?m)^version\s*=\s*"([^"]+)"', pyproject.read_text(encoding="utf-8"))
        if match:
            return match.group(1)
    return "0.0.0"


def collect_components() -> list[dict[str, object]]:
    components: list[dict[str, object]] = []
    seen: set[str] = set()
    for dist in importlib.metadata.distributions():
        name = str(dist.metadata.get("Name") or dist.metadata.get("Summary") or "").strip()
        version = str(dist.version or "").strip()
        if not name:
            continue
        key = f"{_normalized_purl_name(name)}@{version}"
        if key in seen:
            continue
        seen.add(key)
        normalized = _normalized_purl_name(name)
        components.append(
            {
                "type": "library",
                "bom-ref": f"pkg:pypi/{normalized}@{version}",
                "name": name,
                "version": version,
                "purl": f"pkg:pypi/{normalized}@{version}",
                "scope": "required",
            }
        )
    return sorted(components, key=lambda item: str(item["bom-ref"]))


def build_sbom(repo: Path) -> dict[str, object]:
    components = collect_components()
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SBOM_SPEC_VERSION,
        "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "rapidtriage",
                    "name": GENERATOR_NAME,
                    "version": _project_version(repo),
                }
            ],
            "component": {
                "type": "application",
                "bom-ref": "pkg:pypi/rapidtriage",
                "name": "rapidtriage",
                "version": _project_version(repo),
            },
            "properties": [
                {"name": "rapidtriage:python_version", "value": platform.python_version()},
                {"name": "rapidtriage:python_implementation", "value": platform.python_implementation()},
                {"name": "rapidtriage:platform", "value": platform.platform()},
            ],
        },
        "components": components,
        "dependencies": [
            {
                "ref": "pkg:pypi/rapidtriage",
                "dependsOn": [str(component["bom-ref"]) for component in components],
            }
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a CycloneDX-style SBOM for the RapidTriage environment")
    parser.add_argument("--output", help="Write the SBOM to this path instead of stdout")
    parser.add_argument("--json", action="store_true", help="Print the SBOM JSON to stdout even when --output is given")
    args = parser.parse_args(argv)

    repo = Path(__file__).resolve().parent.parent
    sbom = build_sbom(repo)
    encoded = json.dumps(sbom, indent=2, ensure_ascii=False) + "\n"

    if args.output:
        output_path = Path(args.output).expanduser().resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(encoded, encoding="utf-8")
        print(f"Wrote SBOM ({len(sbom['components'])} components): {output_path}", file=sys.stderr)
    if args.json or not args.output:
        print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
