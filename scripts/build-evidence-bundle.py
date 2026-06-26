#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "jsonschema>=4.0",
# ]
# ///
# --- How to run ---
# 1. Install uv (if not installed): curl -LsSf https://astral.sh/uv/install.sh | sh
# 2. Run: uv run scripts/build-evidence-bundle.py --root <bundle-root> --out <manifest.json>
# 3. Emit JSON: uv run scripts/build-evidence-bundle.py --root <bundle-root> --json
# ------------------
from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.validation.evidence_bundle import build_bundle_manifest, format_text, write_summary


@dataclass(frozen=True, slots=True)
class CliArgs:
    root: Path
    out: Path | None
    summary: Path | None
    emit_json: bool


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    result = build_bundle_manifest(args.root)
    if args.out is not None:
        _ = args.out.write_text(json.dumps(result.document, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    if args.summary is not None:
        write_summary(result, args.summary)
    if args.emit_json:
        print(json.dumps(result.document, ensure_ascii=False, indent=2, sort_keys=True))
    elif args.out is None:
        print(format_text(result))
    return result.exit_code


def _parse_args(argv: Sequence[str] | None) -> CliArgs:
    parser = argparse.ArgumentParser(description="Build a release-evidence bundle manifest from small in-repo artifacts.")
    _ = parser.add_argument("--root", required=True, help="Bundle root to inventory.")
    _ = parser.add_argument("--out", help="Optional bundle manifest JSON path.")
    _ = parser.add_argument("--summary", help="Optional Markdown summary path.")
    _ = parser.add_argument("--json", action="store_true", help="Emit JSON to stdout.")
    namespace = parser.parse_args(argv)
    return CliArgs(
        root=Path(_namespace_str(namespace, "root")),
        out=_optional_path(namespace, "out"),
        summary=_optional_path(namespace, "summary"),
        emit_json=_namespace_bool(namespace, "json"),
    )


def _namespace_str(namespace: argparse.Namespace, field: str) -> str:
    value = cast(object, getattr(namespace, field))
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string")
    return value


def _namespace_bool(namespace: argparse.Namespace, field: str) -> bool:
    value = cast(object, getattr(namespace, field))
    if not isinstance(value, bool):
        raise TypeError(f"{field} must be a boolean")
    return value


def _optional_path(namespace: argparse.Namespace, field: str) -> Path | None:
    value = cast(object, getattr(namespace, field))
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string")
    return Path(value)


if __name__ == "__main__":
    raise SystemExit(main())
