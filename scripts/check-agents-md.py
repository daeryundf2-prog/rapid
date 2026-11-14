#!/usr/bin/env python3
"""Check that the commands documented in AGENTS.md still match the repository.

Parses the fenced ``bash`` blocks of the "RapidTriage verification gate" and
"RapidForensic Validation Contract" sections and verifies, per command:

* ``python <script>``   -- the script exists, ``--help`` exits 0 and every flag
  used in the documented command appears in that help text;
* ``python -m <module>`` -- the module is importable;
* ``npm run <name>``    -- the script exists in ``frontend/package.json``;
* path-like arguments    -- the referenced repo file/directory exists.

Inline code spans in those sections that name repo paths (``scripts/...``,
``docs/...``) must exist too. Commands with ``<placeholders>`` (real-evidence
measurements) are only syntax-checked, never executed. ``--run-cheap`` also runs
the cheap fixture commands (Tier 0 known-answer tools, ``git diff --check``...)
and requires exit 0. Any drift exits 1.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SECTIONS = ("RapidTriage verification gate", "RapidForensic Validation Contract")
CHEAP_SCRIPTS = frozenset(
    {
        "scripts/known-answer-qc.py",
        "scripts/trusted-diff.py",
        "scripts/normalize-trusted-export.py",
        "scripts/build-evidence-bundle.py",
    }
)
CHEAP_GIT = frozenset({("git", "diff", "--check"), ("git", "status", "--short")})
PLACEHOLDER_RE = re.compile(r"<[^<>]+>")
INLINE_CODE_RE = re.compile(r"`([^`]+)`")
PATH_PREFIXES = ("scripts/", "docs/", "tests/", "rapidtriage/", "frontend/")
PATH_SUFFIXES = (".py", ".json", ".tsv", ".lock", ".md", ".txt", ".toml")
HELP_TIMEOUT = 60
RUN_TIMEOUT = 300
_HELP_CACHE: dict[tuple[str, str], tuple[int, str]] = {}


@dataclass
class Command:
    section: str
    line: int
    text: str
    status: str = "ok"  # ok | fail | placeholder | ran
    problems: list[str] = field(default_factory=list)


def _sections(text: str) -> dict[str, list[tuple[int, str]]]:
    """Map each wanted section title to its (1-based line number, line) body."""
    found: dict[str, list[tuple[int, str]]] = {}
    current: str | None = None
    for number, line in enumerate(text.splitlines(), start=1):
        if line.startswith("#") or line.strip() == "---":
            title = line.lstrip("#").strip()
            current = title if line.startswith("## ") and title in SECTIONS else None
            if current is not None:
                found[current] = []
            continue
        if current is not None:
            found[current].append((number, line))
    return found


def _fenced_commands(section: str, body: list[tuple[int, str]]) -> list[Command]:
    commands: list[Command] = []
    fence: str | None = None
    for number, line in body:
        stripped = line.strip()
        if stripped.startswith("```"):
            fence = None if fence is not None else stripped[3:].strip()
            continue
        if fence not in ("bash", "sh", "shell") or not stripped:
            continue
        command = re.split(r"\s+#\s", stripped, maxsplit=1)[0].strip()
        if command and not command.startswith("#"):
            commands.append(Command(section=section, line=number, text=command))
    return commands


def _inline_refs(
    section: str, body: list[tuple[int, str]]
) -> tuple[list[tuple[int, str]], list[Command]]:
    """Repo paths and ``npm run``/``python`` commands named in inline code spans."""
    paths: list[tuple[int, str]] = []
    commands: list[Command] = []
    in_fence = False
    for number, line in body:
        if line.strip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for span in INLINE_CODE_RE.findall(line):
            if span.startswith(("npm run ", "python ")):
                commands.append(
                    Command(section=section, line=number, text=span.strip())
                )
                continue
            for token in span.split():
                if token.startswith(PATH_PREFIXES) and not PLACEHOLDER_RE.search(token):
                    paths.append((number, token))
    return paths, commands


def _looks_like_path(token: str) -> bool:
    return not token.startswith("-") and ("/" in token or token.endswith(PATH_SUFFIXES))


class Checker:
    def __init__(self, root: Path, run_cheap: bool) -> None:
        self.root = root
        self.run_cheap = run_cheap
        self._npm: set[str] | None = None

    def _env(self) -> dict[str, str]:
        env = dict(os.environ)
        env.setdefault("RAPIDTRIAGE_NO_BROWSER", "1")
        env.setdefault("PYTHONIOENCODING", "utf-8")
        return env

    def _script_help(self, script: str) -> tuple[int, str]:
        key = (str(self.root), script)
        if key not in _HELP_CACHE:
            try:
                proc = subprocess.run(
                    [sys.executable, script, "--help"],
                    cwd=self.root,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=HELP_TIMEOUT,
                    env=self._env(),
                    check=False,
                )
                _HELP_CACHE[key] = (proc.returncode, proc.stdout + proc.stderr)
            except subprocess.TimeoutExpired:
                _HELP_CACHE[key] = (-1, "")
        return _HELP_CACHE[key]

    def _npm_scripts(self) -> set[str]:
        if self._npm is None:
            package = self.root / "frontend" / "package.json"
            try:
                data = json.loads(package.read_text(encoding="utf-8"))
                self._npm = set(data.get("scripts", {}))
            except (OSError, ValueError):
                self._npm = set()
        return self._npm

    def _check_paths(self, cmd: Command, tokens: list[str]) -> None:
        for token in tokens:
            if _looks_like_path(token) and not (self.root / token).exists():
                cmd.problems.append(f"missing path: {token}")

    def check(self, cmd: Command) -> None:
        placeholder = bool(PLACEHOLDER_RE.search(cmd.text))
        try:
            tokens = shlex.split(PLACEHOLDER_RE.sub("PLACEHOLDER", cmd.text))
        except ValueError as exc:
            cmd.problems.append(f"unparseable: {exc}")
            tokens = []
        if tokens:
            self._dispatch(cmd, tokens, placeholder)
        if cmd.problems:
            cmd.status = "fail"
        elif placeholder:
            cmd.status = "placeholder"

    def _dispatch(self, cmd: Command, tokens: list[str], placeholder: bool) -> None:
        head = tokens[0]
        if head in ("python", "python3", "py"):
            if len(tokens) >= 3 and tokens[1] == "-m":
                self._check_module(cmd, tokens[2])
            elif len(tokens) >= 2:
                self._check_script(cmd, tokens[1], tokens[2:], placeholder)
            else:
                cmd.problems.append("python without a target")
        elif head == "npm":
            if len(tokens) >= 3 and tokens[1] == "run":
                if tokens[2] not in self._npm_scripts():
                    cmd.problems.append(
                        f"npm script not in frontend/package.json: {tokens[2]}"
                    )
            else:
                cmd.problems.append("unsupported npm form (expected 'npm run <name>')")
        elif head == "git":
            if shutil.which("git") is None:
                cmd.problems.append("git not on PATH")
            elif self.run_cheap and tuple(tokens) in CHEAP_GIT:
                self._execute(cmd, tokens)
        else:
            cmd.problems.append(f"unknown command head: {head}")

    def _check_module(self, cmd: Command, module: str) -> None:
        try:
            spec = importlib.util.find_spec(module)
        except (ImportError, ValueError):
            spec = None
        if spec is None:
            cmd.problems.append(f"module not importable: {module}")

    def _check_script(
        self, cmd: Command, script: str, args: list[str], placeholder: bool
    ) -> None:
        if not (self.root / script).is_file():
            cmd.problems.append(f"missing script: {script}")
            return
        self._check_paths(cmd, [a for a in args if a != "PLACEHOLDER"])
        code, help_text = self._script_help(script)
        if code != 0:
            cmd.problems.append(f"{script} --help exited {code}")
            return
        for arg in args:
            if arg.startswith("-") and arg != "-":
                flag = arg.split("=", 1)[0]
                if not re.search(rf"(?<![\w-]){re.escape(flag)}(?![\w-])", help_text):
                    cmd.problems.append(f"flag not in {script} --help: {flag}")
        if (
            self.run_cheap
            and not placeholder
            and not cmd.problems
            and script in CHEAP_SCRIPTS
        ):
            self._execute(cmd, [sys.executable, script, *args])

    def _execute(self, cmd: Command, argv: list[str]) -> None:
        try:
            proc = subprocess.run(
                argv,
                cwd=self.root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=RUN_TIMEOUT,
                env=self._env(),
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            cmd.problems.append(f"run failed: {exc}")
            return
        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or [""]
            cmd.problems.append(f"exited {proc.returncode}: {tail[0][:200]}")
        else:
            cmd.status = "ran"


def check_agents_md(
    agents_md: Path, root: Path, run_cheap: bool = False
) -> dict[str, object]:
    text = agents_md.read_text(encoding="utf-8")
    sections = _sections(text)
    errors: list[str] = [
        f"section missing: ## {title}" for title in SECTIONS if title not in sections
    ]
    checker = Checker(root, run_cheap)
    commands: list[Command] = []
    for title, body in sections.items():
        found = _fenced_commands(title, body)
        if not found:
            errors.append(f"section has no bash commands: ## {title}")
        commands.extend(found)
        paths, inline_commands = _inline_refs(title, body)
        commands.extend(inline_commands)
        for number, path in paths:
            if not (root / path).exists():
                errors.append(f"AGENTS.md:{number}: missing inline path: {path}")
    for cmd in commands:
        checker.check(cmd)
    counts: dict[str, int] = {}
    for cmd in commands:
        counts[cmd.status] = counts.get(cmd.status, 0) + 1
    failed = [c for c in commands if c.status == "fail"]
    return {
        "ok": not errors and not failed,
        "agents_md": str(agents_md),
        "run_cheap": run_cheap,
        "counts": counts,
        "errors": errors,
        "commands": [asdict(c) for c in commands],
    }


def _print_text(report: dict[str, object]) -> None:
    for item in report["commands"]:  # type: ignore[union-attr]
        mark = {"ok": "ok  ", "ran": "RAN ", "placeholder": "SYN ", "fail": "FAIL"}[
            item["status"]
        ]
        print(f"{mark} AGENTS.md:{item['line']}: {item['text']}")
        for problem in item["problems"]:
            print(f"       - {problem}")
    for error in report["errors"]:  # type: ignore[union-attr]
        print(f"FAIL {error}")
    counts = report["counts"]
    summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))  # type: ignore[union-attr]
    verdict = "PASS" if report["ok"] else "FAIL"
    print(f"{verdict}: {summary}; errors={len(report['errors'])}")  # type: ignore[arg-type]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--agents-md",
        type=Path,
        default=None,
        help="AGENTS.md to check (default: <root>/AGENTS.md)",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO,
        help="repository root commands resolve against",
    )
    parser.add_argument(
        "--run-cheap",
        action="store_true",
        help="also execute the cheap Tier 0 fixture and git commands",
    )
    parser.add_argument("--json", action="store_true", help="print a JSON report")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    agents_md = args.agents_md or root / "AGENTS.md"
    if not agents_md.is_file():
        print(f"FAIL: {agents_md} not found", file=sys.stderr)
        return 1
    report = check_agents_md(agents_md, root, run_cheap=args.run_cheap)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_text(report)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
