#!/usr/bin/env python3
"""One-line local gate for RapidTriage (plan task T-152).

Runs the checks every lane needs, in a fixed order, and prints one line per
step (pass / FAIL / skip, seconds) plus the total wall time::

    python scripts/dev/gate.py                      # --tier fast
    python scripts/dev/gate.py --tier static        # L0 only (also: --static)
    python scripts/dev/gate.py --tier full --json   # everything (also: --full)
    python scripts/dev/gate.py --fast --changed     # only test modules touched vs --base

Levels (a failing L0 step stops the run; later levels keep going so one run
shows every failure):

* L0 static   - check-eol, check-staged (size / EOL / bundle path), ruff,
  vulture (80), compileall, tests/test_script_exec_bits, tests/test_architecture
  (import boundaries); frontend tsc, biome and bundle budget when frontend/
  changed (always in ``full``).
* L1 tests    - parallel unit tests via scripts/dev/run-tests.py (tier fast or
  full, ``--changed`` passes through); vitest when frontend/ changed.
* L2 contract - UI contract drift (``node scripts/extract-ui-contract.mjs
  --check``), the RapidForensic Validation Contract Tier 0 scripts
  (known-answer-qc, trusted-diff, normalize-trusted-export,
  build-evidence-bundle) and lock-based pip_audit.
* L3 e2e      - Playwright smoke spec (``full`` only).

Every long step runs under scripts/dev/run.py ``--timeout`` so a hung step only
kills its own process tree.  Step output goes to a log file; the tail is printed
when a step fails.  ``--json`` prints the step table as JSON on stdout (the
human table then goes to stderr).

Exit code: 0 when every step passed or was skipped, 1 otherwise, 2 on usage error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEV = Path(__file__).resolve().parent
FRONTEND = REPO_ROOT / "frontend"
FIXTURE = "tests/fixtures/known_answer/tier0-basic"
DEFAULT_BASE = "feat/r6-ux"
FALLBACK_BASE = "main"
E2E_SMOKE_SPECS = ("case-intake.spec.ts",)
E2E_PORT_RANGE = (8800, 8870)
TAIL_LINES = 30
TIERS = ("static", "fast", "full")


@dataclass
class Step:
    name: str
    level: str
    command: list[str]
    timeout: float
    cwd: Path = REPO_ROOT
    env: dict[str, str] = field(default_factory=dict)
    skip_reason: str | None = None
    needs_node_modules: bool = False


@dataclass
class Result:
    name: str
    level: str
    status: str  # pass | fail | skip | timeout | not-run
    exit_code: int | None
    seconds: float
    command: str
    reason: str = ""
    log: str = ""


# --------------------------------------------------------------------------- #
# git helpers
# --------------------------------------------------------------------------- #


def _git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True,
        encoding="utf-8", errors="replace", check=False,
    )


def resolve_base(base: str | None) -> str | None:
    for candidate in ([base] if base else [DEFAULT_BASE, FALLBACK_BASE]):
        if _git("rev-parse", "--verify", "--quiet", f"{candidate}^{{commit}}").returncode == 0:
            return candidate
    return None


def changed_paths(base: str | None) -> set[str]:
    """Paths changed on this branch (vs merge-base with ``base``), staged, unstaged or untracked."""
    paths: set[str] = set()
    if base:
        mb = _git("merge-base", base, "HEAD")
        if mb.returncode == 0:
            paths.update(_git("diff", "--name-only", mb.stdout.strip(), "HEAD").stdout.splitlines())
    paths.update(_git("diff", "--name-only", "HEAD").stdout.splitlines())
    paths.update(_git("ls-files", "--others", "--exclude-standard").stdout.splitlines())
    return {p.strip() for p in paths if p.strip()}


def frontend_changed(paths: set[str]) -> bool:
    return any(p.startswith("frontend/") for p in paths)


def e2e_port() -> str:
    """Port for the Playwright server: .rt-dev.env (wt.py) or a hash of the checkout path."""
    env_file = REPO_ROOT / ".rt-dev.env"
    if env_file.is_file():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition("=")
            if key.strip() == "RAPIDTRIAGE_E2E_PORT" and value.strip().isdigit():
                return value.strip()
    low, high = E2E_PORT_RANGE
    digest = int(hashlib.sha256(str(REPO_ROOT).lower().encode("utf-8")).hexdigest(), 16)
    return str(low + digest % (high - low))


# --------------------------------------------------------------------------- #
# plan
# --------------------------------------------------------------------------- #


def build_steps(tier: str, changed: bool, base: str | None, fe_changed: bool) -> list[Step]:
    py = sys.executable
    lint_scope = ["rapidtriage", "tests", "scripts"]
    run_fe = tier == "full" or fe_changed
    fe_skip = None if run_fe else "frontend/ unchanged"
    steps = [
        Step("check-eol", "L0", [py, "scripts/dev/check-eol.py"], 60),
        Step("check-staged", "L0", [py, "scripts/dev/check-staged.py"], 60),
        Step("ruff", "L0", [py, "-m", "ruff", "check", *lint_scope], 180),
        Step("vulture", "L0", [py, "-m", "vulture", *lint_scope, "--min-confidence", "80"], 300),
        Step("compileall", "L0", [py, "-m", "compileall", "-q", *lint_scope], 300),
        Step("exec-bits", "L0", [py, "-m", "unittest", "tests.test_script_exec_bits"], 120),
        Step("architecture", "L0", [py, "-m", "unittest", "tests.test_architecture"], 180),
        Step("agents-md", "L0", [py, "scripts/check-agents-md.py"], 300),
        Step("fe-typecheck", "L0", ["npm", "run", "typecheck"], 300, cwd=FRONTEND,
             skip_reason=fe_skip, needs_node_modules=True),
        Step("fe-lint", "L0", ["npm", "run", "lint"], 300, cwd=FRONTEND,
             skip_reason=fe_skip, needs_node_modules=True),
        Step("fe-bundle", "L0", ["npm", "run", "check:bundle"], 600, cwd=FRONTEND,
             skip_reason=fe_skip, needs_node_modules=True),
    ]
    if tier == "static":
        return steps

    test_cmd = [py, "scripts/dev/run-tests.py", "--tier", tier]
    if changed:
        test_cmd += ["--changed"] + (["--base", base] if base else [])
    steps += [
        Step("unit-tests", "L1", test_cmd, 1800 if tier == "full" else 900),
        Step("fe-vitest", "L1", ["npx", "vitest", "run"], 900, cwd=FRONTEND,
             skip_reason=fe_skip, needs_node_modules=True),
        Step("ui-contract", "L2", ["node", "scripts/extract-ui-contract.mjs", "--check"], 120,
             needs_node_modules=True),
        Step("known-answer-qc", "L2", [
            py, "scripts/known-answer-qc.py", "--manifest", f"{FIXTURE}/manifest.json",
            "--check-files", "--fixture-root", f"{FIXTURE}/files", "--json"], 120),
        Step("trusted-diff", "L2", [
            py, "scripts/trusted-diff.py", "--manifest", f"{FIXTURE}/manifest.json",
            "--rapid-results", f"{FIXTURE}/rapid-results.json",
            "--trusted-results", f"{FIXTURE}/trusted-results.json", "--json"], 120),
        Step("normalize-trusted-export", "L2", [
            py, "scripts/normalize-trusted-export.py", "--tool", "synthetic-tsv",
            "--input", f"{FIXTURE}/synthetic-trusted-export.tsv", "--json"], 120),
        Step("build-evidence-bundle", "L2", [
            py, "scripts/build-evidence-bundle.py", "--root", FIXTURE, "--json"], 120),
        Step("pip-audit", "L2", [
            py, "-m", "pip_audit", "-r", "requirements.lock", "-r", "requirements-dev.lock",
            "--require-hashes", "--disable-pip"], 300),
    ]
    if tier == "full":
        steps.append(Step(
            "e2e-smoke", "L3", ["npm", "run", "e2e", "--", *E2E_SMOKE_SPECS], 900, cwd=FRONTEND,
            env={"RAPIDTRIAGE_E2E_PORT": e2e_port()}, needs_node_modules=True,
        ))
    return steps


# --------------------------------------------------------------------------- #
# run
# --------------------------------------------------------------------------- #


def _shown(command: list[str]) -> str:
    return " ".join("python" if part == sys.executable else part for part in command)


def _tail(path: Path, lines: int = TAIL_LINES) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return "\n".join(text.splitlines()[-lines:])


def run_step(step: Step, log_dir: Path) -> Result:
    shown = _shown(step.command)
    if step.skip_reason:
        return Result(step.name, step.level, "skip", None, 0.0, shown, step.skip_reason)
    if step.needs_node_modules and not (FRONTEND / "node_modules").exists():
        return Result(step.name, step.level, "fail", None, 0.0, shown,
                      "frontend/node_modules missing (create worktrees with scripts/dev/wt.py new)")
    log = log_dir / f"{step.name}.log"
    meta = log_dir / f"{step.name}.run.json"
    wrapper = [sys.executable, str(DEV / "run.py"), "--timeout", str(step.timeout),
               "--json-out", str(meta), "--", *step.command]
    env = dict(os.environ, RAPIDTRIAGE_NO_BROWSER="1", PYTHONIOENCODING="utf-8", **step.env)
    started = time.monotonic()
    with log.open("w", encoding="utf-8", newline="\n") as handle:
        proc = subprocess.run(wrapper, cwd=step.cwd, env=env, stdout=handle,
                              stderr=subprocess.STDOUT, check=False)
    seconds = round(time.monotonic() - started, 1)
    info: dict = {}
    try:
        info = json.loads(meta.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    code = proc.returncode
    if info.get("status") == "timeout":
        status, reason = "timeout", f"killed after {step.timeout:.0f}s"
    elif code == 0:
        status, reason = "pass", ""
    else:
        status, reason = "fail", str(info.get("reason", ""))
    return Result(step.name, step.level, status, code, seconds, shown, reason, str(log))


def _line(result: Result) -> str:
    mark = {"pass": "pass", "skip": "skip", "not-run": "----"}.get(result.status, result.status.upper())
    code = "" if result.exit_code is None else f"rc={result.exit_code}"
    extra = f"  {result.reason}" if result.reason else ""
    return f"  {result.level}  {mark:<8} {result.seconds:7.1f}s  {result.name:<26} {code}{extra}"


def default_log_root() -> Path:
    digest = hashlib.sha256(str(REPO_ROOT).lower().encode("utf-8")).hexdigest()[:12]
    return Path(tempfile.gettempdir()) / "rapidtriage-gate" / digest


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--tier", choices=TIERS, help="static | fast (default) | full")
    for tier in TIERS:
        group.add_argument(f"--{tier}", dest="tier", action="store_const", const=tier,
                           help=f"same as --tier {tier}")
    parser.add_argument("--changed", action="store_true",
                        help="unit tests only for modules touched vs --base")
    parser.add_argument("--base", help=f"git base for change detection (default: {DEFAULT_BASE}, then main)")
    parser.add_argument("--json", action="store_true", help="print the result JSON on stdout")
    parser.add_argument("--json-out", type=Path, help="also write the result JSON to this file")
    parser.add_argument("--keep-going", action="store_true", help="do not stop when an L0 step fails")
    parser.add_argument("--list", action="store_true", help="print the planned steps and exit")
    args = parser.parse_args(argv)
    args.tier = args.tier or "fast"
    return args


def main(argv: list[str] | None = None) -> int:
    # Korean Windows consoles default to cp949, which cannot print "—" and crashed the summary.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    args = parse_args(list(sys.argv[1:] if argv is None else argv))
    out = sys.stderr if args.json else sys.stdout
    base = resolve_base(args.base)
    if args.base and base is None:
        print(f"gate: unknown --base {args.base}", file=sys.stderr)
        return 2
    paths = changed_paths(base)
    fe = frontend_changed(paths)
    steps = build_steps(args.tier, args.changed, base, fe)
    if args.list:
        for step in steps:
            print(f"{step.level} {step.name:<26} {_shown(step.command)}"
                  + (f"   [skip: {step.skip_reason}]" if step.skip_reason else ""), file=out)
        return 0

    log_dir = default_log_root() / time.strftime("run-%Y%m%d-%H%M%S")
    log_dir.mkdir(parents=True, exist_ok=True)
    print(f"gate: tier={args.tier} changed={args.changed} base={base} frontend_changed={fe} logs={log_dir}",
          file=out, flush=True)
    started = time.monotonic()
    results: list[Result] = []
    stopped = False
    for step in steps:
        if stopped:
            results.append(Result(step.name, step.level, "not-run", None, 0.0,
                                  _shown(step.command), "L0 failed"))
            print(_line(results[-1]), file=out, flush=True)
            continue
        result = run_step(step, log_dir)
        results.append(result)
        print(_line(result), file=out, flush=True)
        if result.status in ("fail", "timeout"):
            if result.log:
                print(f"    --- last {TAIL_LINES} lines of {result.log} ---", file=out)
                for line in _tail(Path(result.log)).splitlines():
                    print(f"    {line}", file=out)
            if step.level == "L0" and not args.keep_going:
                stopped = True
    total = round(time.monotonic() - started, 1)
    failed = [r.name for r in results if r.status in ("fail", "timeout", "not-run")]
    ok = not failed
    print(f"gate: {'PASS' if ok else 'FAIL'} in {total:.1f}s"
          + (f" - failed: {', '.join(failed)}" if failed else ""), file=out, flush=True)
    payload = {
        "version": 1,
        "tier": args.tier,
        "changed": args.changed,
        "base": base,
        "frontend_changed": fe,
        "ok": ok,
        "total_seconds": total,
        "failed": failed,
        "log_dir": str(log_dir),
        "steps": [asdict(r) for r in results],
    }
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(text + "\n", encoding="utf-8", newline="\n")
    (log_dir / "gate.json").write_text(text + "\n", encoding="utf-8", newline="\n")
    if args.json:
        print(text)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
