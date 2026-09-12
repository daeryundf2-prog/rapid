"""Compatibility package preserving the original cli.py namespace."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from ..core.rules import RuleConfigError, load_rule_set
from . import analyze, benchmark, case, collect, kakao, readiness, runops, scan
from . import validation as _validation
from .helpers import (
    add_rules_argument,
    add_web_arguments,
    build_source_read_review_note,
    compact_commercial_readiness_payload,
    load_image_workflow_rows,
    load_source_read_review_package,
    parse_named_cli_values,
    write_kakaotalk_message_residue_csv,
)
from .parser import (
    DOCS_EPILOG,
    EXTRACT_EPILOG,
    FILES_EPILOG,
    HELP_FORMATTER,
    MANIFEST_EPILOG,
    TOP_LEVEL_EPILOG,
    build_parser,
)
from .web import build_web_parser, run_web_server, web_main

HANDLERS = {
    **analyze.HANDLERS,
    **benchmark.HANDLERS,
    **case.HANDLERS,
    **collect.HANDLERS,
    **kakao.HANDLERS,
    **readiness.HANDLERS,
    **runops.HANDLERS,
    **scan.HANDLERS,
    **_validation.HANDLERS,
}


def main(argv=None) -> int:
    # Emit UTF-8 regardless of the console codec (cp1252 CI consoles crash on
    # non-ASCII evidence text such as Korean filenames and arrow glyphs).
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = build_parser()
    args = parser.parse_args(argv)
    rule_set = None
    if getattr(args, "rules", None):
        try:
            rule_set = load_rule_set(Path(args.rules).expanduser().resolve())
        except (FileNotFoundError, OSError, json.JSONDecodeError, RuleConfigError) as exc:
            parser.error(f"invalid rules file: {exc}")

    handler = HANDLERS.get(args.command)
    if handler is not None:
        return handler(args, parser, rule_set)
    parser.error(f"unknown command: {args.command}")
    return 2

__all__ = [
    "DOCS_EPILOG",
    "EXTRACT_EPILOG",
    "FILES_EPILOG",
    "HANDLERS",
    "HELP_FORMATTER",
    "MANIFEST_EPILOG",
    "TOP_LEVEL_EPILOG",
    "add_rules_argument",
    "add_web_arguments",
    "build_parser",
    "build_source_read_review_note",
    "build_web_parser",
    "compact_commercial_readiness_payload",
    "load_image_workflow_rows",
    "load_source_read_review_package",
    "main",
    "parse_named_cli_values",
    "run_web_server",
    "web_main",
    "write_kakaotalk_message_residue_csv",
]
