#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "jsonschema>=4.0",
# ]
# ///
# --- How to run ---
# 1. Install uv (if not installed): curl -LsSf https://astral.sh/uv/install.sh | sh
# 2. Run: uv run scripts/normalize-trusted-export.py --tool synthetic-tsv --input <export.tsv> --out <observed.json>
# 3. Emit JSON: uv run scripts/normalize-trusted-export.py --tool synthetic-tsv --input <export.tsv> --json
# ------------------
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
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.validation.normalizers import format_text, normalize_export


@dataclass(frozen=True, slots=True)
class CliArgs:
    tool: str
    input_path: Path
    out: Path | None
    emit_json: bool


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    result = normalize_export(args.tool, args.input_path)
    if args.out is not None and result.exit_code == 0:
        _ = args.out.write_text(json.dumps(result.document, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    if args.emit_json:
        print(json.dumps(result.document, ensure_ascii=False, indent=2, sort_keys=True))
    elif args.out is None:
        print(format_text(result))
    return result.exit_code


def _parse_args(argv: Sequence[str] | None) -> CliArgs:
    parser = argparse.ArgumentParser(description="Normalize a trusted/reference export into observed-results JSON.")
    _ = parser.add_argument("--tool", required=True, help="Normalizer type: synthetic-tsv, manual-json, or documented placeholders.")
    _ = parser.add_argument("--input", required=True, help="Input export path.")
    _ = parser.add_argument("--out", help="Optional observed-results JSON output path.")
    _ = parser.add_argument("--json", action="store_true", help="Emit JSON to stdout.")
    namespace = parser.parse_args(argv)
    return CliArgs(
        tool=_namespace_str(namespace, "tool"),
        input_path=Path(_namespace_str(namespace, "input")),
        out=_optional_path(namespace, "out"),
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
