"""Compatibility package preserving the original cli.py namespace.

Command handler modules (and the forensic engine they pull in) are imported
only after argparse has picked a command (T-161): ``rapidtriage --help`` and
``rapidtriage --version`` stay fast and never load ``cv2``/``numpy``. Names that
the old eager namespace re-exported are still reachable as attributes; they are
resolved on first access through ``__getattr__``.
"""

from __future__ import annotations

import importlib
import sys
from types import ModuleType

from .. import __version__

# Command group module (``rapidtriage.cli.<module>``) -> commands it handles.
# Each module's ``HANDLERS`` dict is the authority; this table only decides
# which module to import. A command missing here falls back to loading every
# handler module, so a stale entry costs speed, never correctness.
_COMMAND_MODULES: dict[str, tuple[str, ...]] = {
    "analyze": (
        "evidence", "indicators", "ocr-queue", "search", "search-index",
        "source-read", "source-search", "timeline", "timeline-export",
    ),
    "benchmark": (
        "benchmark", "browser-stress", "columnar-benchmark", "columnar-convert",
        "e01-hash", "e01-known-answer", "e01-smoke", "large-case-readiness",
        "macos-live-smoke", "sqlite-fts-benchmark", "sqlite-wal-preview",
        "stress-plan",
    ),
    "case": (
        "bundle", "case", "case-acquisition", "case-backup", "case-catalog",
        "case-db", "case-db-report", "case-export-uco", "case-restore",
        "case-review", "case-search", "cross-case-correlate", "sample",
    ),
    "collect": (
        "carve", "cloud-collect", "collect-export", "collect-plan", "ntfs-meta",
        "vsc-compare", "vsc-discover", "vsc-extract",
    ),
    "kakao": (
        "kakaotalk-collect-windows", "kakaotalk-decrypt",
        "kakaotalk-key-store-inspect", "kakaotalk-macos-report",
        "kakaotalk-memory-carve", "kakaotalk-sqlcipher-probe",
        "kakaotalk-userdir-bruteforce",
    ),
    "readiness": (
        "commercial-readiness", "confidence-dashboard",
        "forensic-validation-batches", "forensic-validation-batches-assess",
        "forensic-validation-evidence-import", "forensic-validation-pack",
        "forensic-validation-pack-assess", "forensic-validation-plan",
        "forensic-validation-smoke-populate", "parser-explainability",
        "reproducibility-kit",
    ),
    "runops": (
        "artifacts", "doctor", "enterprise-policy", "keyword-packs", "plugins",
        "rearchitecture-status", "run", "run-control", "run-plan", "web",
        "worker-parse",
    ),
    "scan": (
        "compare", "docs", "docs-index-search", "email-external-parse",
        "extract", "files", "known-good-index", "manifest", "normalize",
        "taxonomy-audit",
    ),
    "validation": (
        "cross-tool-validate", "final-qc-report", "image-workflow-validate",
        "known-answer-qc", "run-attach-validation-diff",
        "usn-state-replay-template", "validation", "validation-diff-runners",
    ),
}
_HANDLER_MODULE_BY_COMMAND = {
    command: module for module, commands in _COMMAND_MODULES.items() for command in commands
}

# Re-exported name -> defining submodule, resolved lazily by ``__getattr__``.
_LAZY_EXPORTS = {
    "DOCS_EPILOG": "parser",
    "EXTRACT_EPILOG": "parser",
    "FILES_EPILOG": "parser",
    "HELP_FORMATTER": "parser",
    "MANIFEST_EPILOG": "parser",
    "TOP_LEVEL_EPILOG": "parser",
    "build_parser": "parser",
    "add_rules_argument": "helpers",
    "add_web_arguments": "helpers",
    "build_source_read_review_note": "helpers",
    "compact_commercial_readiness_payload": "helpers",
    "load_image_workflow_rows": "helpers",
    "load_source_read_review_package": "helpers",
    "parse_named_cli_values": "helpers",
    "write_kakaotalk_message_residue_csv": "helpers",
    "build_web_parser": "web",
    "run_web_server": "web",
    "web_main": "web",
}


def _handler_module(name: str) -> ModuleType:
    return importlib.import_module(f"{__name__}.{name}")


def _all_handlers() -> dict:
    handlers: dict = {}
    for module in _COMMAND_MODULES:
        handlers.update(_handler_module(module).HANDLERS)
    return handlers


def _resolve_handler(command: str):
    module = _HANDLER_MODULE_BY_COMMAND.get(command)
    if module is not None:
        handler = _handler_module(module).HANDLERS.get(command)
        if handler is not None:
            return handler
    return _all_handlers().get(command)


def __getattr__(name: str):
    if name == "HANDLERS":
        value = _all_handlers()
    elif name in _LAZY_EXPORTS:
        value = getattr(_handler_module(_LAZY_EXPORTS[name]), name)
    elif name in _COMMAND_MODULES:
        value = _handler_module(name)
    else:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    globals()[name] = value
    return value


def _wants_version(argv: list[str]) -> bool:
    """True when a top-level ``--version`` precedes the subcommand and any help flag.

    The top-level parser takes no valued options, so every token before the
    first positional is a flag; argparse would act on them in this order too.
    """
    for token in argv:
        if token == "--version":
            return True
        if token in {"-h", "--help", "--"} or not token.startswith("-"):
            return False
    return False


def main(argv=None) -> int:
    # Emit UTF-8 regardless of the console codec (cp1252 CI consoles crash on
    # non-ASCII evidence text such as Korean filenames and arrow glyphs).
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    if _wants_version(sys.argv[1:] if argv is None else list(argv)):
        # Answer before building the parser: the parser modules import engine
        # constants and are not cheap to load.
        print(f"rapidtriage {__version__}")
        return 0
    from .parser import build_parser

    parser = build_parser()
    parser.add_argument(
        "--version",
        action="version",
        version=f"rapidtriage {__version__}",
        help="show the rapidtriage version and exit",
    )
    args = parser.parse_args(argv)
    rule_set = None
    if getattr(args, "rules", None):
        import json
        from pathlib import Path

        from ..core.rules import RuleConfigError, load_rule_set

        try:
            rule_set = load_rule_set(Path(args.rules).expanduser().resolve())
        except (FileNotFoundError, OSError, json.JSONDecodeError, RuleConfigError) as exc:
            parser.error(f"invalid rules file: {exc}")

    handler = _resolve_handler(args.command)
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
