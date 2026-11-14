#!/usr/bin/env python3
"""R8 task measurements (T-011): run the examiner tasks T1-T5 and summarise them.

Runs the Playwright specs in ``frontend/e2e/tasks`` (``tasks/playwright.config.ts``) and turns the
per-task JSON files they write into one JSON document plus a markdown summary table.

Targets:
  * fixture (default): the isolated e2e fixture server with a SYN sample case.
  * real run: ``--base-url`` / ``--token`` / ``--run-id`` (or ``R8_BASE_URL`` / ``R8_TOKEN`` /
    ``R8_RUN_ID``; ``R8_RUN_C1``..``C6`` / ``R8_RUN_T1``..``T5`` also pass through). Real runs are
    read-only: the specs abort every non-GET request except search/query endpoints.

The measurements are an engineering baseline, not release evidence. A task the console cannot
finish is reported as ``fail``/``partial``; the script exits 0 unless the harness itself breaks.

Examples::

    python scripts/r8-measure.py --out r8-tasks.json --summary r8-tasks.md
    python scripts/r8-measure.py --base-url http://127.0.0.1:8720 --token ... --run-id ... --out real.json
    python scripts/r8-measure.py --results-dir <dir> --out r8-tasks.json   # aggregate only
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"
CONFIG = "e2e/tasks/playwright.config.ts"
TASKS = ("T1", "T2", "T3", "T4", "T5")
SPEC_BY_TASK = {
    "T1": "t1-brief",
    "T2": "t2-search-tag",
    "T3": "t3-day",
    "T4": "t4-ai",
    "T5": "t5-report",
}
RUN_ENV = tuple(
    f"R8_RUN_{suffix}" for suffix in (*TASKS, "C1", "C2", "C3", "C4", "C5", "C6", "S")
)
PASS_THROUGH_ENV = RUN_ENV + (
    "R8_T2_QUERY",
    "R8_T2_ROWS",
    "R8_STEP_TIMEOUT_MS",
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("R8_BASE_URL", ""),
        help="real server (read-only)",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("R8_TOKEN", ""),
        help="API token of the real server",
    )
    parser.add_argument(
        "--run-id",
        default=os.environ.get("R8_RUN_ID", ""),
        help="run to measure (real mode)",
    )
    parser.add_argument(
        "--tasks", default=",".join(TASKS), help="comma-separated subset, e.g. T1,T2"
    )
    parser.add_argument(
        "--port",
        default=os.environ.get("RAPIDTRIAGE_E2E_PORT", "8797"),
        help="fixture port",
    )
    parser.add_argument(
        "--results-dir", help="aggregate an existing results folder instead of running"
    )
    parser.add_argument("--out", help="write the combined JSON here (default: stdout)")
    parser.add_argument(
        "--summary", help="write the markdown summary here (default: stderr)"
    )
    return parser.parse_args(argv)


def run_specs(args: argparse.Namespace, tasks: list[str], out_dir: Path) -> int:
    if args.port == "8710":
        raise SystemExit(
            "port 8710 is the user's server and is never used for measurements"
        )
    npx = shutil.which("npx")
    if not npx:
        raise SystemExit("npx not found: install Node.js and run `npm ci` in frontend/")
    env = {key: value for key, value in os.environ.items() if not key.startswith("R8_")}
    env.update(
        {
            "R8_OUT_DIR": str(out_dir),
            "RAPIDTRIAGE_E2E_PORT": args.port,
            "RAPIDTRIAGE_NO_BROWSER": "1",
        }
    )
    for key in PASS_THROUGH_ENV:
        if os.environ.get(key):
            env[key] = os.environ[key]
    if args.base_url:
        if not (
            args.token and (args.run_id or any(os.environ.get(k) for k in RUN_ENV))
        ):
            raise SystemExit(
                "--base-url needs --token and --run-id (or R8_RUN_* variables)"
            )
        env.update({"R8_BASE_URL": args.base_url, "R8_TOKEN": args.token})
        if args.run_id:
            env["R8_RUN_ID"] = args.run_id
    specs = [f"e2e/tasks/{SPEC_BY_TASK[task]}.spec.ts" for task in tasks]
    command = [npx, "playwright", "test", "--config", CONFIG, "--reporter=line", *specs]
    return subprocess.run(command, cwd=FRONTEND, env=env, check=False).returncode


def load_results(out_dir: Path, tasks: list[str]) -> list[dict[str, Any]]:
    results = []
    for task in tasks:
        path = out_dir / f"{task}.json"
        if path.is_file():
            results.append(json.loads(path.read_text(encoding="utf-8")))
        else:
            results.append(
                {
                    "task": task,
                    "status": "error",
                    "notes": ["harness wrote no result"],
                    "steps": [],
                }
            )
    return results


def _cell(value: Any) -> str:
    if value is None:
        return "-"
    return str(value).replace("|", "\\|")


def summary_markdown(results: list[dict[str, Any]], mode: str) -> str:
    lines = [
        f"## R8 task measurements ({mode}) - engineering baseline, not release evidence",
        "",
        "| Task | Title | Status | Clicks | Keys | Ops | Screens | Wall s | First row ms | Steps ok | Broke at |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for result in results:
        metrics = result.get("metrics") or {}
        steps = result.get("steps") or []
        broke = next((step for step in steps if not step.get("ok")), None)
        broke_text = f"{broke['name']}: {broke.get('note', '')}" if broke else ""
        lines.append(
            "| "
            + " | ".join(
                _cell(value)
                for value in (
                    result.get("task"),
                    result.get("title"),
                    result.get("status"),
                    metrics.get("clicks"),
                    metrics.get("keystrokes"),
                    metrics.get("ops"),
                    metrics.get("screens"),
                    metrics.get("wallSeconds"),
                    metrics.get("firstRowMs"),
                    f"{sum(1 for step in steps if step.get('ok'))}/{len(steps)}",
                    broke_text[:120],
                )
            )
            + " |"
        )
    audit = next(
        (r.get("extra", {}).get("audit") for r in results if r.get("task") == "T1"),
        None,
    )
    if isinstance(audit, dict):
        truncation = audit.get("truncation") or {}
        lines += [
            "",
            "UX-audit numbers (탐색 › 파일, 1280x720): "
            f"tree nodes {_cell(audit.get('treeNodes'))}, "
            f"cell truncation {_cell(truncation.get('truncated'))}/{_cell(truncation.get('cells'))} "
            f"({_cell(truncation.get('ratio'))}), Tab to first grid row {_cell(audit.get('tabsToGrid'))}",
        ]
    blocked = sorted({req for r in results for req in r.get("blockedRequests") or []})
    if blocked:
        lines += ["", "Read-only guard blocked: " + ", ".join(blocked)]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    tasks = [task.strip().upper() for task in args.tasks.split(",") if task.strip()]
    unknown = [task for task in tasks if task not in TASKS]
    if unknown:
        raise SystemExit(f"unknown task(s): {', '.join(unknown)}")
    exit_code = 0
    if args.results_dir:
        out_dir = Path(args.results_dir)
    else:
        out_dir = Path(tempfile.mkdtemp(prefix="r8-measure-"))
        exit_code = run_specs(args, tasks, out_dir)
    results = load_results(out_dir, tasks)
    mode = "real" if args.base_url else "fixture"
    document = {
        "schema": "r8-task-measure/1",
        "mode": mode,
        "evidence": "engineering-baseline",
        "playwrightExit": exit_code,
        "tasks": results,
        "counts": {
            status: sum(1 for r in results if r.get("status") == status)
            for status in ("pass", "partial", "fail", "error")
        },
    }
    text = json.dumps(document, ensure_ascii=False, indent=2) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(text)
    summary = summary_markdown(results, mode)
    if args.summary:
        Path(args.summary).write_text(summary, encoding="utf-8", newline="\n")
    else:
        sys.stderr.write(summary)
    # The specs measure only: a non-zero Playwright exit means the harness broke, not a missed target.
    return 1 if exit_code or any(r.get("status") == "error" for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
