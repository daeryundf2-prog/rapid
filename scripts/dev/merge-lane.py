#!/usr/bin/env python3
"""Merge one lane branch into the integration branch (coordinator tool, D57).

Steps, in order (any failure stops the run with a non-zero exit; nothing is pushed):

1. the current branch must be the integration branch (``feat/r6-ux`` or ``--into``) and the
   tracked tree must be clean;
2. ``git merge --no-ff -m <message> <branch>`` (a conflict aborts the merge);
3. ``git diff --stat`` of the merge must equal ``git diff --stat --ignore-cr-at-eol`` (no CRLF
   churn came in with the lane);
4. any added/changed shebang file under rapidtriage/, tests/ or scripts/ that is not executable in
   the index gets ``git update-index --chmod=+x``;
5. ``node scripts/extract-ui-contract.mjs --write``, and ``npm run build`` in frontend/ when the
   merge touched frontend/src;
6. the regenerated contract / families fallback / console bundle and the exec-bit fixes go into ONE
   follow-up commit (only those paths are staged; never ``git add -A``);
7. quick gates: ruff, contract ``--check``, ``npm run check:bundle`` (frontend changed) and
   tests/test_script_exec_bits.py.

Examples::

    python scripts/dev/merge-lane.py wa3/t-157-finish -m "Merge branch 'wa3/t-157-finish' into feat/r6-ux"
    python scripts/dev/merge-lane.py wa3/t-157-finish --dry-run
    python scripts/dev/merge-lane.py lane/x --into feat/r7 --skip-gates
"""

from __future__ import annotations

import argparse
import os
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INTO = "feat/r6-ux"
EXEC_SCOPES = ("rapidtriage", "tests", "scripts")
EXEC_SUFFIXES = (".py", ".sh", ".mjs")
CONTRACT_SCRIPT = "scripts/extract-ui-contract.mjs"
# Paths the follow-up commit may contain (besides exec-bit fixes): generated, coordinator-owned.
REGENERATED = (
    "frontend/src/contracts/uiContract.ts",
    "frontend/src/features/flags/families.fallback.json",
    "rapidtriage/web/static/v2",
)
TRAILER = "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"


class LaneError(RuntimeError):
    """A step failed; the message says what to do next."""


@dataclass
class Lane:
    repo: Path
    branch: str
    into: str = DEFAULT_INTO
    message: str | None = None
    dry_run: bool = False
    skip_build: bool = False
    skip_gates: bool = False
    log: list[str] = field(default_factory=list)

    # -- plumbing -----------------------------------------------------------------------------
    def say(self, text: str) -> None:
        self.log.append(text)
        print(text, flush=True)

    def run(
        self,
        args: list[str],
        *,
        cwd: Path | None = None,
        check: bool = True,
        write: bool = True,
    ) -> str:
        """Run a command. ``write`` commands are only printed under --dry-run."""
        where = (
            f" (in {cwd.relative_to(self.repo).as_posix()})"
            if cwd and cwd != self.repo
            else ""
        )
        if write:
            self.say(f"$ {shlex.join(args)}{where}")
            if self.dry_run:
                return ""
        proc = subprocess.run(
            args,
            cwd=cwd or self.repo,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if check and proc.returncode != 0:
            raise LaneError(
                f"{shlex.join(args)} failed ({proc.returncode}):\n{proc.stdout}{proc.stderr}".rstrip()
            )
        return proc.stdout

    def git(self, *args: str, write: bool = False, check: bool = True) -> str:
        return self.run(["git", *args], write=write, check=check)

    # -- steps --------------------------------------------------------------------------------
    def check_start(self) -> None:
        current = self.git("rev-parse", "--abbrev-ref", "HEAD").strip()
        if current != self.into:
            raise LaneError(
                f"current branch is {current!r}, expected {self.into!r} (checkout it or pass --into)"
            )
        self.git("rev-parse", "--verify", "--quiet", f"{self.branch}^{{commit}}")
        dirty = [
            line
            for line in self.git(
                "status", "--porcelain", "--untracked-files=no"
            ).splitlines()
            if line
        ]
        if dirty:
            raise LaneError(
                "tracked changes present - commit or set them aside first:\n"
                + "\n".join(dirty)
            )

    def merge(self) -> None:
        message = self.message or f"Merge branch '{self.branch}' into {self.into}"
        before = self.git("rev-parse", "HEAD").strip()
        try:
            self.run(["git", "merge", "--no-ff", "-m", message, self.branch])
        except LaneError:
            self.git("merge", "--abort", check=False)
            raise
        if not self.dry_run and self.git("rev-parse", "HEAD").strip() == before:
            raise LaneError(
                f"{self.branch} is already merged into {self.into}; nothing to do"
            )

    def check_line_endings(self) -> None:
        if self.dry_run:
            self.say(
                "$ git diff --stat HEAD^1 HEAD  ==  git diff --stat --ignore-cr-at-eol HEAD^1 HEAD"
            )
            return
        plain = self.git("diff", "--stat", "HEAD^1", "HEAD")
        ignoring = self.git("diff", "--stat", "--ignore-cr-at-eol", "HEAD^1", "HEAD")
        if plain != ignoring:
            raise LaneError(
                "the merge carries CR/LF-only changes (diff --stat differs with --ignore-cr-at-eol).\n"
                "Undo with `git reset --hard HEAD^1`, fix the lane's line endings (LF), and retry.\n"
                f"--- diff --stat\n{plain}--- --ignore-cr-at-eol\n{ignoring}"
            )
        self.say("line endings: ok (diff --stat == --ignore-cr-at-eol)")

    def changed(self, *paths: str, diff_filter: str = "ACMR") -> list[str]:
        if self.dry_run:
            return []
        out = self.git(
            "diff",
            "--name-only",
            f"--diff-filter={diff_filter}",
            "HEAD^1",
            "HEAD",
            "--",
            *paths,
        )
        return [line for line in out.splitlines() if line]

    def fix_exec_bits(self) -> list[str]:
        if self.dry_run:
            self.say(
                f"$ git update-index --chmod=+x <new shebang files in {', '.join(EXEC_SCOPES)}>"
            )
            return []
        fixed = []
        for path in self.changed(*EXEC_SCOPES):
            if not path.endswith(EXEC_SUFFIXES):
                continue
            target = self.repo / path
            if not target.is_file() or target.read_bytes()[:2] != b"#!":
                continue
            mode = self.git("ls-files", "-s", "--", path).split(" ", 1)[0]
            if mode == "100644":
                self.git("update-index", "--chmod=+x", "--", path, write=True)
                if os.name != "nt":
                    # Keep the working file in step with the index, or POSIX git reports it modified.
                    target.chmod(target.stat().st_mode | 0o111)
                fixed.append(path)
        if not fixed:
            self.say("exec bits: ok")
        return fixed

    def regenerate(self, frontend_changed: bool) -> None:
        if (self.repo / CONTRACT_SCRIPT).is_file() or self.dry_run:
            self.run(["node", CONTRACT_SCRIPT, "--write"])
        else:
            self.say(f"contract: {CONTRACT_SCRIPT} not present, skipped")
        if frontend_changed and not self.skip_build:
            self.run([npm(), "run", "build"], cwd=self.repo / "frontend")

    def commit_regenerated(self, fixed: list[str]) -> bool:
        present = [
            path for path in REGENERATED if (self.repo / path).exists() or self.dry_run
        ]
        if present:
            # A pathspec `git add` also records deletions inside it (stale bundle chunks).
            self.git("add", "--", *present, write=True)
        if self.dry_run:
            self.say(
                f'$ git commit -m "chore: regenerate contract/bundle after merging {self.branch}" (if staged)'
            )
            return False
        staged = [
            line
            for line in self.git("diff", "--cached", "--name-only").splitlines()
            if line
        ]
        if not staged:
            self.say("follow-up commit: nothing regenerated")
            return False
        subject = f"chore: regenerate contract/bundle after merging {self.branch}"
        body = [
            f"Regenerated by scripts/dev/merge-lane.py: {', '.join(staged[:6])}{' ...' if len(staged) > 6 else ''}."
        ]
        if fixed:
            body.append(f"Executable bit set on: {', '.join(fixed)}.")
        self.git(
            "commit", "-m", subject, "-m", "\n".join(body), "-m", TRAILER, write=True
        )
        stray = [
            line
            for line in self.git(
                "status", "--porcelain", "--untracked-files=no"
            ).splitlines()
            if line
        ]
        if stray:
            self.say(
                "warning: tracked changes left outside the follow-up commit:\n"
                + "\n".join(stray)
            )
        return True

    def gates(self, frontend_changed: bool) -> list[str]:
        failures = []
        for name, args, cwd in gate_commands(self.repo, frontend_changed):
            try:
                self.run(args, cwd=cwd)
                if not self.dry_run:
                    self.say(f"gate {name}: ok")
            except LaneError as error:
                self.say(f"gate {name}: FAILED\n{error}")
                failures.append(name)
        return failures

    def execute(self) -> int:
        self.check_start()
        self.merge()
        self.check_line_endings()
        frontend_changed = (
            bool(self.changed("frontend/src", diff_filter="ACDMR")) or self.dry_run
        )
        fixed = self.fix_exec_bits()
        self.regenerate(frontend_changed)
        self.commit_regenerated(fixed)
        if self.skip_gates:
            self.say("gates: skipped (--skip-gates)")
            return 0
        failures = self.gates(frontend_changed)
        if failures:
            self.say(
                f"gates failed: {', '.join(failures)} - the merge is local only; fix or `git reset` before pushing"
            )
            return 1
        tip = "" if self.dry_run else self.git("log", "--oneline", "-1").strip()
        self.say(
            f"done{' (dry run)' if self.dry_run else ''}{': ' + tip if tip else ''} - not pushed"
        )
        return 0


def npm() -> str:
    return shutil.which("npm") or "npm"


def gate_commands(
    repo: Path, frontend_changed: bool
) -> list[tuple[str, list[str], Path]]:
    """The quick gates: (name, argv, cwd)."""
    gates = [
        ("ruff", [sys.executable, "-m", "ruff", "check", *EXEC_SCOPES], repo),
        ("contract", ["node", CONTRACT_SCRIPT, "--check"], repo),
    ]
    if frontend_changed:
        gates.append(("fe-lint", [npm(), "run", "lint"], repo / "frontend"))
        gates.append(("bundle", [npm(), "run", "check:bundle"], repo / "frontend"))
    gates.append(
        (
            "exec-bits",
            [sys.executable, "-m", "unittest", "tests.test_script_exec_bits"],
            repo,
        )
    )
    return gates


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("branch", help="lane branch to merge")
    parser.add_argument(
        "-m",
        "--message",
        help="merge commit message (default: Merge branch '<branch>' into <into>)",
    )
    parser.add_argument(
        "--into",
        default=DEFAULT_INTO,
        help=f"integration branch (default {DEFAULT_INTO})",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="print the steps; change nothing"
    )
    parser.add_argument(
        "--skip-build", action="store_true", help="do not run npm run build"
    )
    parser.add_argument(
        "--skip-gates", action="store_true", help="do not run the quick gates"
    )
    parser.add_argument("--repo", type=Path, default=REPO_ROOT, help=argparse.SUPPRESS)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    lane = Lane(
        repo=args.repo.resolve(),
        branch=args.branch,
        into=args.into,
        message=args.message,
        dry_run=args.dry_run,
        skip_build=args.skip_build,
        skip_gates=args.skip_gates,
    )
    try:
        return lane.execute()
    except LaneError as error:
        print(f"merge-lane: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
