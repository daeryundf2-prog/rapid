#!/usr/bin/env python3
"""Regenerate the OpenAPI API-contract snapshot fixture.

The snapshot pins the public API surface: every path, HTTP method, and
operationId reported by ``create_app().openapi()``. The contract test
``tests/test_rapidtriage_api_contract.py`` fails when an endpoint is added,
removed, or renamed without regenerating this fixture.

Usage:
    python scripts/update-api-snapshot.py

Equivalent in-test regeneration:
    RAPIDTRIAGE_UPDATE_API_SNAPSHOT=1 python -m unittest tests.test_rapidtriage_api_contract
"""
from __future__ import annotations

# Force UTF-8 stdio so JSON output with non-ASCII evidence text (e.g.
# Korean filenames) survives Windows consoles whose default codec is cp1252.
import sys as _sys

if hasattr(_sys.stdout, "reconfigure"):
    _sys.stdout.reconfigure(encoding="utf-8")
if hasattr(_sys.stderr, "reconfigure"):
    _sys.stderr.reconfigure(encoding="utf-8")

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

SNAPSHOT_PATH = REPO_ROOT / "tests" / "fixtures" / "api_openapi_snapshot.json"
SNAPSHOT_AUTH_TOKEN = "rapidtriage-snapshot-token"


def build_api_snapshot() -> dict:
    """Build a deterministic {path: {method: operationId}} snapshot."""
    from rapidtriage.api.app import create_app

    spec = create_app(auth_token=SNAPSHOT_AUTH_TOKEN).openapi()
    paths: dict[str, dict[str, str]] = {}
    for path in sorted(spec.get("paths", {})):
        operations = spec["paths"][path]
        paths[path] = {
            method: operations[method].get("operationId", "")
            for method in sorted(operations)
            if method in {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
        }
    return {
        "openapi": spec.get("openapi", ""),
        "paths": paths,
    }


def write_snapshot(path: Path) -> dict:
    snapshot = build_api_snapshot()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return snapshot


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Regenerate tests/fixtures/api_openapi_snapshot.json from create_app().openapi()",
    )
    parser.add_argument("--output", default=str(SNAPSHOT_PATH), help="snapshot JSON output path")
    parser.add_argument("--json", action="store_true", help="print a JSON summary")
    args = parser.parse_args(argv)

    output = Path(args.output).expanduser().resolve()
    snapshot = write_snapshot(output)
    method_count = sum(len(methods) for methods in snapshot["paths"].values())
    summary = {
        "snapshot": str(output),
        "path_count": len(snapshot["paths"]),
        "operation_count": method_count,
    }
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(
            f"Wrote {output} ({summary['path_count']} paths, "
            f"{summary['operation_count']} operations)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
