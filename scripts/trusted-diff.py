#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "jsonschema>=4.0",
# ]
# ///
# --- How to run ---
# 1. Install uv (if not installed): curl -LsSf https://astral.sh/uv/install.sh | sh
# 2. Run: uv run scripts/trusted-diff.py --manifest <manifest.json> --rapid-results <rapid.json> --trusted-results <trusted.json>
# 3. Emit JSON: uv run scripts/trusted-diff.py --manifest <manifest.json> --rapid-results <rapid.json> --trusted-results <trusted.json> --json
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

from rapidtriage.validation.trusted_diff import compare, result_to_text, write_summary
from rapidtriage.validation.trusted_diff import result_schema_error_result, validate_result_schema, TrustedDiffInputPaths
from rapidtriage.validation.trusted_diff_result import TrustedDiffResult


@dataclass(frozen=True, slots=True)
class CliArgs:
    manifest: Path
    rapid_results: Path
    trusted_results: Path
    emit_json: bool
    out: Path | None
    summary: Path | None


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    inputs = TrustedDiffInputPaths(args.manifest, args.rapid_results, args.trusted_results)
    result = _schema_validated_result(inputs, compare(args.manifest, args.rapid_results, args.trusted_results))

    if args.out is not None:
        _ = args.out.write_text(json.dumps(result.document, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    if args.summary is not None:
        write_summary(result, args.summary)

    if args.emit_json:
        print(json.dumps(result.document, ensure_ascii=False, indent=2, sort_keys=True))
    elif args.out is None:
        print(result_to_text(result))
    return _exit_code(result.status)


def _schema_validated_result(inputs: TrustedDiffInputPaths, result: TrustedDiffResult) -> TrustedDiffResult:
    errors = validate_result_schema(result.document)
    if errors:
        return result_schema_error_result(inputs, errors)
    return result


def _parse_args(argv: Sequence[str] | None) -> CliArgs:
    parser = argparse.ArgumentParser(description="Compare RapidForensic observed results with a normalized trusted reference.")
    _ = parser.add_argument("--manifest", required=True, help="Truth manifest JSON path.")
    _ = parser.add_argument("--rapid-results", required=True, help="RapidForensic normalized observed-results JSON path.")
    _ = parser.add_argument("--trusted-results", required=True, help="Trusted/reference normalized observed-results JSON path.")
    _ = parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON to stdout.")
    _ = parser.add_argument("--out", help="Optional path for trusted-diff result JSON.")
    _ = parser.add_argument("--summary", help="Optional path for Markdown summary.")
    namespace = parser.parse_args(argv)
    return CliArgs(
        manifest=Path(_namespace_str(namespace, "manifest")),
        rapid_results=Path(_namespace_str(namespace, "rapid_results")),
        trusted_results=Path(_namespace_str(namespace, "trusted_results")),
        emit_json=_namespace_bool(namespace, "json"),
        out=_optional_path(namespace, "out"),
        summary=_optional_path(namespace, "summary"),
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


def _exit_code(status: str) -> int:
    if status == "PASS":
        return 0
    if status == "FAIL":
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
