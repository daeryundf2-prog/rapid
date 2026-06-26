#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "jsonschema>=4.0",
# ]
# ///
# --- How to run ---
# 1. Install uv (if not installed): curl -LsSf https://astral.sh/uv/install.sh | sh
# 2. Run: uv run scripts/known-answer-qc.py --manifest <manifest.json>
# 3. With fixture file checks:
#      uv run scripts/known-answer-qc.py --manifest <manifest.json> --check-files --fixture-root <path>
# ------------------
from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.validation.known_answer import format_text_result, result_to_dict, validate_manifest


@dataclass(frozen=True, slots=True)
class CliArgs:
    manifest: str
    schema: str | None
    emit_json: bool
    check_files: bool
    fixture_root: str | None


class CliNamespace(argparse.Namespace):
    manifest: str
    schema: str | None
    json: bool
    check_files: bool
    fixture_root: str | None

    def __init__(self) -> None:
        super().__init__()
        self.manifest = ""
        self.schema = None
        self.json = False
        self.check_files = False
        self.fixture_root = None


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    result = validate_manifest(
        args.manifest,
        args.schema,
        check_files=args.check_files,
        fixture_root=args.fixture_root,
    )
    if args.emit_json:
        print(json.dumps(result_to_dict(result), ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(format_text_result(result))
    return 0 if result.ok else 1


def _parse_args(argv: Sequence[str] | None) -> CliArgs:
    parser = argparse.ArgumentParser(
        description="Validate a RapidForensic known-answer truth manifest against the v1 JSON Schema.",
    )
    _ = parser.add_argument(
        "--manifest",
        required=True,
        help="Path to a known-answer truth manifest JSON file.",
    )
    _ = parser.add_argument(
        "--schema",
        help="Optional schema JSON path. Defaults to docs/validation/known-answer-corpus/truth-manifest-schema-v1.schema.json.",
    )
    _ = parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable validation output.",
    )
    _ = parser.add_argument(
        "--check-files",
        action="store_true",
        help="Also compare eligible manifest expected_items against fixture files.",
    )
    _ = parser.add_argument(
        "--fixture-root",
        help="Fixture root used by --check-files. Defaults to the manifest parent directory.",
    )
    namespace = parser.parse_args(argv, CliNamespace())
    return CliArgs(
        manifest=namespace.manifest,
        schema=namespace.schema,
        emit_json=namespace.json,
        check_files=namespace.check_files,
        fixture_root=namespace.fixture_root,
    )


if __name__ == "__main__":
    raise SystemExit(main())
