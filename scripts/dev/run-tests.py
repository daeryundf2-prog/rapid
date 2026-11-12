#!/usr/bin/env python3
"""Parallel unittest runner for RapidTriage (plan task T-006).

Each worker is one Python process that runs a batch of test modules in turn.
Modules are spread over workers by their recorded durations
(``scripts/dev/test-tiers.json``) so that the batches finish together.

The parent watches every worker through an events file.  When one module runs
past its time limit, the parent kills that worker's process tree, records the
module as ``timeout`` and starts a new worker for the rest of the batch.  The
exit code is non-zero when any module fails, errors, crashes or times out.

Examples::

    python scripts/dev/run-tests.py                       # full suite, 8 workers
    python scripts/dev/run-tests.py --tier fast --workers 8
    python scripts/dev/run-tests.py --only test_rapidtriage_api,test_dev_*
    python scripts/dev/run-tests.py --failed-first --json-out run.json
    python scripts/dev/run-tests.py --changed
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_DIR = REPO_ROOT / "tests"
TIERS_PATH = Path(__file__).resolve().with_name("test-tiers.json")
TIERS = ("full", "fast", "slow", "real-data")
DEFAULT_WORKERS = 8
DEFAULT_DURATION_S = 5.0
POLL_S = 0.25


# --------------------------------------------------------------------------
# worker side
# --------------------------------------------------------------------------


def _emit(events_path: Path, payload: dict) -> None:
    with events_path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def _worker_main(events_path: Path, tests_dir: Path, modules: list[str]) -> int:
    """Run ``modules`` one after another in this process (loaded like ``discover -s tests``)."""
    import unittest

    for path in (str(REPO_ROOT), str(tests_dir)):
        if path not in sys.path:
            sys.path.insert(0, path)
    os.chdir(REPO_ROOT)
    loader = unittest.TestLoader()
    worst = 0
    for module in modules:
        suite = loader.loadTestsFromName(module)
        _emit(
            events_path,
            {
                "event": "start",
                "module": module,
                "t": time.time(),
                "tests": suite.countTestCases(),
            },
        )
        print(f"===== {module} =====", file=sys.stderr, flush=True)
        started = time.monotonic()
        result = unittest.TextTestRunner(stream=sys.stderr, verbosity=1).run(suite)
        problems = [(test, text) for test, text in (*result.failures, *result.errors)]
        problems += [
            (test, "unexpected success") for test in result.unexpectedSuccesses
        ]
        rc = 0 if result.wasSuccessful() else 1
        worst = max(worst, rc)
        _emit(
            events_path,
            {
                "event": "end",
                "module": module,
                "rc": rc,
                "duration_s": round(time.monotonic() - started, 3),
                "tests": result.testsRun,
                "failures": len(result.failures),
                "errors": len(result.errors),
                "skipped": len(result.skipped),
                "failed_tests": [
                    {"id": test.id(), "detail": text[-2000:]} for test, text in problems
                ],
            },
        )
    return worst


# --------------------------------------------------------------------------
# selection and balancing
# --------------------------------------------------------------------------


def discover_modules(tests_dir: Path = TESTS_DIR) -> list[str]:
    return sorted(path.stem for path in tests_dir.glob("test_*.py"))


def load_tiers(path: Path = TIERS_PATH) -> dict:
    if not path.exists():
        return {"durations_s": {}, "slow": [], "real_data": []}
    return json.loads(path.read_text(encoding="utf-8"))


def select_tier(modules: list[str], tiers: dict, tier: str) -> list[str]:
    slow = set(tiers.get("slow", []))
    real = set(tiers.get("real_data", []))
    if tier == "full":
        return list(modules)
    if tier == "slow":
        return [m for m in modules if m in slow]
    if tier == "real-data":
        return [m for m in modules if m in real]
    return [m for m in modules if m not in slow and m not in real]


def normalize_name(name: str) -> str:
    name = name.strip().replace("\\", "/")
    name = name.rsplit("/", 1)[-1]
    name = name.removesuffix(".py")
    name = name.removeprefix("tests.")
    return name


def select_only(modules: list[str], patterns: list[str]) -> tuple[list[str], list[str]]:
    """Return (matched modules, patterns that matched nothing)."""
    wanted: list[str] = []
    unmatched: list[str] = []
    for raw in patterns:
        for item in raw.split(","):
            pattern = normalize_name(item)
            if not pattern:
                continue
            hits = [m for m in modules if fnmatch.fnmatchcase(m, pattern)]
            if not hits:
                unmatched.append(pattern)
            wanted.extend(h for h in hits if h not in wanted)
    return [m for m in modules if m in wanted], unmatched


def _git(*args: str) -> list[str]:
    proc = subprocess.run(
        ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=False
    )
    return (
        [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        if proc.returncode == 0
        else []
    )


def changed_files(base: str) -> list[str]:
    merge_base = _git("merge-base", "HEAD", base)
    names = set(_git("diff", "--name-only", merge_base[0])) if merge_base else set()
    names |= set(_git("diff", "--name-only", "HEAD"))
    names |= set(_git("ls-files", "--others", "--exclude-standard"))
    return sorted(names)


def select_changed(
    modules: list[str], files: list[str], tests_dir: Path = TESTS_DIR
) -> list[str]:
    """Test modules whose file changed, plus modules that mention a changed ``rapidtriage`` module or script."""
    picked = {
        Path(f).stem
        for f in files
        if f.startswith("tests/") and Path(f).stem in modules
    }
    needles: list[str] = []
    for name in files:
        path = Path(name)
        if path.suffix != ".py":
            continue
        if path.parts[:1] == ("rapidtriage",):
            dotted = ".".join(path.with_suffix("").parts)
            needles.append(dotted.removesuffix(".__init__"))
        elif path.parts[:1] == ("scripts",):
            needles.append(path.name)
        elif path.parts[:1] == ("tests",) and path.stem not in modules:
            needles.append("tests." + path.stem)
    if needles:
        for module in modules:
            if module in picked:
                continue
            try:
                text = (tests_dir / f"{module}.py").read_text(
                    encoding="utf-8", errors="replace"
                )
            except OSError:
                continue
            if any(needle in text for needle in needles):
                picked.add(module)
    return [m for m in modules if m in picked]


def balance(
    modules: list[str],
    durations: dict,
    workers: int,
    first: set[str] | frozenset = frozenset(),
) -> list[list[str]]:
    """Longest-processing-time-first split; ``first`` modules lead their batch."""
    workers = max(1, min(workers, len(modules))) if modules else 0
    bins: list[list[str]] = [[] for _ in range(workers)]
    loads = [0.0] * workers

    def cost(module: str) -> float:
        return float(durations.get(module, DEFAULT_DURATION_S))

    for module in sorted(modules, key=lambda m: (-cost(m), m)):
        index = min(range(workers), key=lambda i: (loads[i], i))
        bins[index].append(module)
        loads[index] += cost(module)
    for batch in bins:
        batch.sort(key=lambda m: (m not in first, -cost(m), m))
    return bins


def module_timeout(
    module: str, durations: dict, fixed: float | None, floor: float, factor: float
) -> float:
    if fixed is not None:
        return fixed
    return max(floor, factor * float(durations.get(module, DEFAULT_DURATION_S)))


# --------------------------------------------------------------------------
# parent side
# --------------------------------------------------------------------------


def kill_tree(proc: subprocess.Popen) -> None:
    """Kill ``proc`` and its descendants (only this runner's own children)."""
    if proc.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/T", "/F", "/PID", str(proc.pid)],
            capture_output=True,
            check=False,
        )
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()


@dataclass
class Worker:
    index: int
    pending: list[str]
    run_dir: Path
    proc: subprocess.Popen | None = None
    events: Path | None = None
    log: Path | None = None
    offset: int = 0
    current: str | None = None
    current_started: float = 0.0
    current_tests: int = 0
    spawns: int = 0
    results: list[dict] = field(default_factory=list)


def _spawn(worker: Worker, python: str, tests_dir: Path) -> None:
    worker.spawns += 1
    tag = f"w{worker.index}-{worker.spawns}"
    worker.events = worker.run_dir / f"{tag}.events.jsonl"
    worker.log = worker.run_dir / f"{tag}.log"
    worker.events.write_text("", encoding="utf-8")
    worker.offset = 0
    worker.current = None
    env = dict(os.environ)
    env["RAPIDTRIAGE_NO_BROWSER"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    cmd = [
        python,
        str(Path(__file__).resolve()),
        "--_worker",
        str(worker.events),
        str(tests_dir),
        *worker.pending,
    ]
    log_handle = worker.log.open("w", encoding="utf-8")
    kwargs: dict = {
        "cwd": REPO_ROOT,
        "env": env,
        "stdin": subprocess.DEVNULL,
        "stdout": log_handle,
        "stderr": subprocess.STDOUT,
    }
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    try:
        worker.proc = subprocess.Popen(cmd, **kwargs)
    finally:
        log_handle.close()


def _record(worker: Worker, entry: dict) -> None:
    entry["worker"] = worker.index
    entry["log"] = str(worker.log)
    worker.results.append(entry)
    if entry["module"] in worker.pending:
        worker.pending.remove(entry["module"])
    worker.current = None


def _drain(worker: Worker) -> None:
    assert worker.events is not None
    with worker.events.open("rb") as handle:
        handle.seek(worker.offset)
        data = handle.read()
    complete = data.rsplit(b"\n", 1)[0] + b"\n" if b"\n" in data else b""
    worker.offset += len(complete)
    for line in complete.decode("utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        if event["event"] == "start":
            worker.current = event["module"]
            worker.current_started = time.monotonic()
            worker.current_tests = int(event.get("tests", 0))
        elif event["event"] == "end":
            status = "passed" if event["rc"] == 0 else "failed"
            _record(
                worker,
                {**{k: v for k, v in event.items() if k != "event"}, "status": status},
            )


def _lost(worker: Worker, status: str, rc: int, detail: str) -> None:
    module = worker.current or (worker.pending[0] if worker.pending else None)
    if module is None:
        return
    started = worker.current_started if worker.current else time.monotonic()
    _record(
        worker,
        {
            "module": module,
            "rc": rc,
            "status": status,
            "duration_s": round(time.monotonic() - started, 3),
            "tests": worker.current_tests,
            "failures": 0,
            "errors": worker.current_tests or 1,
            "skipped": 0,
            "failed_tests": [{"id": module, "detail": detail}],
        },
    )


def run_batches(
    batches: list[list[str]], durations: dict, args: argparse.Namespace, run_dir: Path
) -> list[dict]:
    workers = [
        Worker(index=i, pending=list(batch), run_dir=run_dir)
        for i, batch in enumerate(batches)
        if batch
    ]
    for worker in workers:
        _spawn(worker, args.python, args.tests_dir)
    try:
        while any(w.proc is not None for w in workers):
            time.sleep(POLL_S)
            for worker in workers:
                if worker.proc is None:
                    continue
                exited = worker.proc.poll() is not None
                _drain(worker)
                if worker.current is not None:
                    limit = module_timeout(
                        worker.current,
                        durations,
                        args.timeout,
                        args.timeout_floor,
                        args.timeout_factor,
                    )
                    elapsed = time.monotonic() - worker.current_started
                    if not exited and elapsed > limit:
                        name = worker.current
                        kill_tree(worker.proc)
                        _drain(worker)
                        if worker.current == name:
                            _lost(
                                worker,
                                "timeout",
                                124,
                                f"module exceeded time limit of {limit:.0f}s; worker killed",
                            )
                            print(
                                f"[run-tests] TIMEOUT {name} after {elapsed:.0f}s (worker {worker.index})",
                                file=sys.stderr,
                                flush=True,
                            )
                        if worker.pending:
                            _spawn(worker, args.python, args.tests_dir)
                        else:
                            worker.proc = None
                        continue
                if exited:
                    rc = worker.proc.returncode
                    if worker.pending:
                        # Exited before finishing its batch: blame the running (or next) module.
                        _lost(
                            worker,
                            "crashed",
                            rc or 1,
                            f"worker exited with code {rc} before finishing the module; see log",
                        )
                    if worker.pending:
                        _spawn(worker, args.python, args.tests_dir)
                    else:
                        worker.proc = None
    finally:
        for worker in workers:
            if worker.proc is not None:
                kill_tree(worker.proc)
    results = [entry for worker in workers for entry in worker.results]
    return sorted(results, key=lambda e: e["module"])


def default_state_dir() -> Path:
    digest = hashlib.sha1(str(REPO_ROOT).lower().encode("utf-8")).hexdigest()[:10]
    return Path(tempfile.gettempdir()) / "rapidtriage-run-tests" / digest


def previous_failures(path: Path) -> set[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    return {m["module"] for m in data.get("modules", []) if m.get("rc", 0) != 0}


def build_summary(
    results: list[dict],
    args: argparse.Namespace,
    wall: float,
    batches: list[list[str]],
    durations: dict,
) -> dict:
    bad = [r for r in results if r["rc"] != 0]
    totals = {
        "modules": len(results),
        "tests": sum(r["tests"] for r in results),
        "failures": sum(r["failures"] for r in results),
        "errors": sum(r["errors"] for r in results),
        "skipped": sum(r["skipped"] for r in results),
        "failed_modules": sorted(r["module"] for r in bad if r["status"] == "failed"),
        "timed_out_modules": sorted(
            r["module"] for r in bad if r["status"] == "timeout"
        ),
        "crashed_modules": sorted(r["module"] for r in bad if r["status"] == "crashed"),
    }
    return {
        "tool": "run-tests",
        "version": 1,
        "tier": args.tier,
        "workers": len([b for b in batches if b]),
        "wall_s": round(wall, 3),
        "rc": 1 if bad else 0,
        "totals": totals,
        "batches": [
            {
                "worker": i,
                "planned_s": round(
                    sum(float(durations.get(m, DEFAULT_DURATION_S)) for m in b), 1
                ),
                "modules": b,
            }
            for i, b in enumerate(batches)
            if b
        ],
        "modules": results,
    }


def record_durations(results: list[dict], tiers_path: Path) -> None:
    tiers = load_tiers(tiers_path)
    durations = tiers.setdefault("durations_s", {})
    for entry in results:
        if entry["status"] in ("passed", "failed"):
            durations[entry["module"]] = round(float(entry["duration_s"]), 1)
    tiers["durations_s"] = dict(sorted(durations.items()))
    tiers_path.write_text(
        json.dumps(tiers, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--tier",
        choices=TIERS,
        default="full",
        help="module tier from test-tiers.json (default: full)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help="worker processes (default: 8)",
    )
    parser.add_argument(
        "--only",
        action="append",
        default=[],
        help="module names or globs, comma separated (repeatable)",
    )
    parser.add_argument(
        "--changed",
        action="store_true",
        help="only modules touched by changes against --base",
    )
    parser.add_argument(
        "--base", default="main", help="git base for --changed (default: main)"
    )
    parser.add_argument(
        "--failed-first",
        action="store_true",
        help="run modules that failed last time first",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="fixed per-module time limit in seconds",
    )
    parser.add_argument(
        "--timeout-floor",
        type=float,
        default=300.0,
        help="minimum per-module limit (default: 300)",
    )
    parser.add_argument(
        "--timeout-factor",
        type=float,
        default=3.0,
        help="limit = max(floor, factor x recorded duration)",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="summary JSON path (default: <state dir>/last.json)",
    )
    parser.add_argument(
        "--json", action="store_true", help="print the summary JSON to stdout"
    )
    parser.add_argument(
        "--record-durations",
        action="store_true",
        help="write measured durations back to test-tiers.json",
    )
    parser.add_argument(
        "--tiers-file", type=Path, default=TIERS_PATH, help=argparse.SUPPRESS
    )
    parser.add_argument(
        "--tests-dir", type=Path, default=TESTS_DIR, help=argparse.SUPPRESS
    )
    parser.add_argument("--python", default=sys.executable, help=argparse.SUPPRESS)
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=None,
        help="logs and last.json (default: under the temp dir)",
    )
    parser.add_argument(
        "--list", action="store_true", help="print the planned batches and exit"
    )
    args = parser.parse_args(argv)
    if args.workers < 1:
        parser.error("--workers must be >= 1")
    return args


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["--_worker"]:
        return _worker_main(Path(argv[1]), Path(argv[2]), argv[3:])
    args = parse_args(argv)
    tiers = load_tiers(args.tiers_file)
    durations = tiers.get("durations_s", {})
    modules = discover_modules(args.tests_dir)
    if args.only:
        modules, unmatched = select_only(modules, args.only)
        if unmatched:
            print(
                f"[run-tests] --only matched nothing for: {', '.join(unmatched)}",
                file=sys.stderr,
            )
            return 2
    else:
        modules = select_tier(modules, tiers, args.tier)
    if args.changed:
        modules = select_changed(modules, changed_files(args.base), args.tests_dir)
    state_dir = args.state_dir or default_state_dir()
    json_out = args.json_out or state_dir / "last.json"
    first = previous_failures(state_dir / "last.json") if args.failed_first else set()
    batches = balance(modules, durations, args.workers, first)
    if args.list:
        for i, batch in enumerate(batches):
            print(
                f"worker {i}: {sum(float(durations.get(m, DEFAULT_DURATION_S)) for m in batch):.0f}s  {' '.join(batch)}"
            )
        return 0
    if not modules:
        print("[run-tests] no test modules selected", file=sys.stderr)
        return 0
    run_dir = state_dir / time.strftime("run-%Y%m%d-%H%M%S")
    run_dir.mkdir(parents=True, exist_ok=True)
    print(
        f"[run-tests] {len(modules)} modules on {len(batches)} workers; logs in {run_dir}",
        file=sys.stderr,
        flush=True,
    )
    started = time.monotonic()
    results = run_batches(batches, durations, args, run_dir)
    summary = build_summary(
        results, args, time.monotonic() - started, batches, durations
    )
    json_out.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(summary, indent=2, ensure_ascii=False) + "\n"
    json_out.write_text(text, encoding="utf-8", newline="\n")
    if json_out != state_dir / "last.json":
        (state_dir / "last.json").write_text(text, encoding="utf-8", newline="\n")
    if args.record_durations:
        record_durations(results, args.tiers_file)
    totals = summary["totals"]
    for entry in results:
        if entry["rc"] != 0:
            print(
                f"[run-tests] {entry['status'].upper()} {entry['module']} (rc={entry['rc']}, log {entry['log']})",
                file=sys.stderr,
            )
    print(
        f"[run-tests] {totals['tests']} tests in {totals['modules']} modules, wall {summary['wall_s']:.1f}s: "
        f"failures={totals['failures']} errors={totals['errors']} skipped={totals['skipped']} "
        f"timeouts={len(totals['timed_out_modules'])} crashed={len(totals['crashed_modules'])} -> {json_out}",
        file=sys.stderr,
    )
    if args.json:
        print(text, end="")
    return summary["rc"]


if __name__ == "__main__":
    sys.exit(main())
