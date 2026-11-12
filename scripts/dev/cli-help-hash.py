#!/usr/bin/env python3
"""Hash every rapidtriage CLI command's ``--help`` text and argparse structure (T-159).

For the top-level parser and every subcommand this records two SHA-256 values:

* ``help``   - the exact ``--help`` text (terminal width pinned to 100 columns)
* ``struct`` - the argparse structure: per action its class, option strings,
  dest, default, choices, nargs, required, const, type, metavar and help, plus
  the parser's prog/usage/description/epilog/formatter and its argument and
  mutually exclusive groups

The baseline lives in ``scripts/dev/cli-help-hash.json``. ``--write`` records
it; ``--check`` rebuilds the parser and exits 1 when any command was added,
removed or changed. Paths under the home directory are written as ``~`` so the
baseline does not depend on the machine.

    python scripts/dev/cli-help-hash.py --write
    python scripts/dev/cli-help-hash.py --check [--json]
"""

from __future__ import annotations

import os

os.environ["COLUMNS"] = "100"
os.environ["LINES"] = "50"

import argparse  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import sys  # noqa: E402
from pathlib import Path, PurePath  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
DEFAULT_BASELINE = Path(__file__).resolve().with_name("cli-help-hash.json")
TOP = "(top-level)"


def _normalize(value: object) -> object:
    if isinstance(value, PurePath):
        value = value.as_posix()
    if isinstance(value, str):
        home = str(Path.home())
        for variant in {home, home.replace("\\", "/")}:
            if variant and variant in value:
                value = value.replace(variant, "~")
        return value.replace("\\", "/") if value.startswith("~") else value
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _normalize(item) for key, item in value.items()}
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if callable(value):
        return f"<callable {getattr(value, '__qualname__', type(value).__name__)}>"
    return repr(value)


def _action_struct(action: argparse.Action) -> dict:
    choices = action.choices
    if isinstance(action, argparse._SubParsersAction):
        choices = list(action.choices)
    elif choices is not None:
        choices = list(choices)
    return {
        "class": type(action).__name__,
        "option_strings": list(action.option_strings),
        "dest": action.dest,
        "default": _normalize(action.default),
        "choices": _normalize(choices),
        "nargs": action.nargs,
        "required": action.required,
        "const": _normalize(action.const),
        "type": _normalize(action.type),
        "metavar": _normalize(action.metavar),
        "help": action.help,
    }


def _parser_struct(parser: argparse.ArgumentParser) -> dict:
    return {
        "prog": parser.prog,
        "usage": parser.usage,
        "description": parser.description,
        "epilog": parser.epilog,
        "formatter_class": parser.formatter_class.__name__,
        "add_help": parser.add_help,
        "prefix_chars": parser.prefix_chars,
        "conflict_handler": parser.conflict_handler,
        "argument_default": _normalize(parser.argument_default),
        "defaults": _normalize(parser._defaults),
        "actions": [_action_struct(action) for action in parser._actions],
        "groups": [
            {"title": group.title, "description": group.description, "dests": [a.dest for a in group._group_actions]}
            for group in parser._action_groups
        ],
        "mutually_exclusive": [
            {"required": group.required, "dests": [a.dest for a in group._group_actions]}
            for group in parser._mutually_exclusive_groups
        ],
    }


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _walk(parser: argparse.ArgumentParser, name: str, out: dict[str, dict]) -> None:
    struct = json.dumps(_parser_struct(parser), sort_keys=True, ensure_ascii=False)
    out[name] = {"help": _sha(parser.format_help()), "struct": _sha(struct)}
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for child_name, child in action.choices.items():
                _walk(child, child_name if name == TOP else f"{name} {child_name}", out)


def collect() -> dict[str, dict]:
    sys.path.insert(0, str(REPO))
    from rapidtriage.cli.parser import build_parser

    out: dict[str, dict] = {}
    _walk(build_parser(), TOP, out)
    return out


def main(argv: list[str] | None = None) -> int:
    cli = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = cli.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="Record the baseline")
    mode.add_argument("--check", action="store_true", help="Compare against the baseline; exit 1 on any difference")
    cli.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE, help="Baseline JSON path")
    cli.add_argument("--json", action="store_true", help="Print a JSON summary")
    args = cli.parse_args(argv)

    current = collect()
    commands = [name for name in current if name != TOP]
    python = f"{sys.version_info.major}.{sys.version_info.minor}"
    if args.write:
        payload = {"python": python, "columns": 100, "command_count": len(commands), "commands": current}
        args.baseline.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8", newline="\n")
        print(f"wrote {len(commands)} commands (+ top-level) to {args.baseline}")
        return 0

    baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
    recorded = baseline["commands"]
    errors: list[str] = []
    if baseline.get("python") != python:
        errors.append(f"python {python} differs from baseline python {baseline.get('python')}; argparse help text may differ")
    if list(recorded) != list(current):
        errors.append("command set or order differs")
    for name in sorted(set(recorded) | set(current)):
        if name not in current:
            errors.append(f"{name}: removed")
        elif name not in recorded:
            errors.append(f"{name}: added")
        else:
            for key in ("help", "struct"):
                if recorded[name][key] != current[name][key]:
                    errors.append(f"{name}: {key} hash differs")
    same = sum(1 for name in commands if recorded.get(name) == current[name])
    summary = {"ok": not errors, "identical": same, "total": len(recorded) - (TOP in recorded), "errors": errors}
    if args.json:
        print(json.dumps(summary, indent=2, ensure_ascii=False))
    else:
        for error in errors:
            print(f"DIFF {error}")
        top = "top-level identical" if recorded.get(TOP) == current.get(TOP) else "top-level DIFFERS"
        print(f"{'OK' if not errors else 'FAIL'}: {same}/{summary['total']} commands identical, {top}")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
