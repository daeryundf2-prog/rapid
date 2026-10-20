#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
# --- How to run ---
#   python scripts/perf-r6.py --synthetic --files 500000 [--repeat 5] [--output <report.json>]
#   python scripts/perf-r6.py --run <run dir> --files [--output <report.json>]
#
# R6 step 3 performance measurements (docs/plans/r6-followups-2026-10-19.md
# section 3.4). Engineering measurement only: not a unit test, not in CI.
# Each mode is one ``bench_<mode>`` function registered in ``MODES``; the
# command line picks modes with their own flags (``--files`` here; other lanes
# add theirs) and the report holds one section per mode.
#
# The API is called in-process through FastAPI's TestClient on a synthetic run
# written to a temporary folder (``--synthetic``) or on an existing run folder
# (``--run``; read-only folders work: caches stay in memory). Timings are the
# median of ``--repeat`` calls. Exit codes: 0 every target met, 1 a target
# missed, 2 input error.
# ------------------
from __future__ import annotations

import sys as _sys

if hasattr(_sys.stdout, "reconfigure"):
    _sys.stdout.reconfigure(encoding="utf-8")
if hasattr(_sys.stderr, "reconfigure"):
    _sys.stderr.reconfigure(encoding="utf-8")

import argparse
import json
import os
import statistics
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

SCHEMA_VERSION = "rapidtriage-perf-r6-v1"
TOKEN = "perf-r6-token"
DEFAULT_FILES = 500_000


# --- shared helpers -----------------------------------------------------------------------------


def make_client(run_dir: Path):
    """``(client, run_id)`` of the run folder imported into a fresh in-memory store."""
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import create_app
    from rapidtriage.core.jobs import RunJobStore

    store = RunJobStore()
    run_id = store.import_completed_run(run_dir).run_id
    client = TestClient(create_app(store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})
    return client, run_id


def timed_get(client, url: str, params: dict[str, object]) -> tuple[float, dict[str, object]]:
    started = time.perf_counter()
    response = client.get(url, params=params)
    elapsed = time.perf_counter() - started
    if response.status_code != 200:
        raise RuntimeError(f"GET {url} {params} -> {response.status_code}: {response.text[:300]}")
    return elapsed, response.json()


def median_of(repeat: int, measure: Callable[[], float]) -> dict[str, object]:
    samples = [measure() for _ in range(max(1, repeat))]
    return {"median_s": round(statistics.median(samples), 4), "samples_s": [round(value, 4) for value in samples]}


def write_summary(run_dir: Path, outputs: dict[str, str], root: Path) -> None:
    summary_path = run_dir / "rapidtriage-run-summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "profile_version": "rapidtriage-run-summary-v1",
                "mode": "hacking",
                "root": str(root),
                "output_dir": str(run_dir),
                "source": {"type": "directory", "analysis_root": str(root)},
                "outputs": {**outputs, "summary": str(summary_path)},
                "summary": {"counts": {}},
            }
        ),
        encoding="utf-8",
    )


# --- files mode (lane B: /files condition paging cache) ------------------------------------------

FILES_CATEGORIES = (["documents"], ["images"], ["archives"], ["executables"], ["other"], ["documents", "archives"], [])
FILES_EXTENSIONS = ("docx", "jpg", "zip", "exe", "dat", "7z", "mp4")
FILES_TARGETS = {"first_page_s": 1.0, "next_page_s": 0.05}


def synthetic_file_rows(count: int, root: Path) -> list[dict[str, object]]:
    """Files rows shaped like ``rapidtriage-files.json`` candidates: mixed categories, times
    (``fs_modified_at`` / ``modified_at`` / acquisition copies) and a few partial rows."""
    rows: list[dict[str, object]] = []
    base = str(root)
    for index in range(count):
        ext = FILES_EXTENSIONS[index % len(FILES_EXTENSIONS)]
        name = f"file{index}.{ext}"
        day = 1 + index % 28
        hour = index % 24
        row: dict[str, object] = {
            "path": os.path.join(base, "Users", f"u{index % 50}", f"dir{index % 997}", name),
            "name": name,
            "extension": f".{ext}",
            "size": index * 7 % 100_000,
            "categories": FILES_CATEGORIES[index % len(FILES_CATEGORIES)],
            "sha256": f"{index:064x}",
        }
        stamp = f"2025-05-{day:02d}T{hour:02d}:{index % 60:02d}:00Z"
        selector = index % 10
        if selector < 3:
            row["fs_modified_at"] = stamp
        elif selector < 5:
            row.update({"modified_at": stamp, "modified_at_origin": "acquisition-copy"})
        else:
            row["modified_at"] = stamp
        if index % 97 == 0:
            row["parse_status"] = "truncated"
        rows.append(row)
    return rows


def synthetic_files_run(base: Path, count: int) -> Path:
    run_dir = base / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    root = base / "evidence"
    files_path = run_dir / "rapidtriage-files.json"
    files_path.write_text(json.dumps({"candidates": synthetic_file_rows(count, root), "inventory": []}), encoding="utf-8")
    write_summary(run_dir, {"files": str(files_path)}, root)
    return run_dir


def clear_files_caches() -> None:
    """Cold start of the /files condition path (matched positions and column indexes)."""
    from rapidtriage.api.app import row_conditions

    row_conditions.MATCH_CACHE.clear()
    try:
        from rapidtriage.api.app import files_index
    except ImportError:  # before lane B
        return
    files_index.clear_files_index_cache()


FILES_SCENARIOS: tuple[tuple[str, dict[str, object]], ...] = (
    ("time_window", {"from": "2025-05-03", "to": "2025-05-20"}),
    ("offhours_seoul_content", {"offhours": "1", "tz": "Asia/Seoul", "content": "document,archive"}),
    ("category_weekday", {"category": ["documents", "images"], "weekday": "sat,sun", "tz": "+09:00"}),
    ("partial", {"partial": "1"}),
)


def bench_files(args: argparse.Namespace) -> dict[str, object]:
    """``GET /files`` with row conditions: first page (cold caches, then warm column index with new
    conditions) and the next page (cached positions); median of ``--repeat``."""
    count = int(args.files or DEFAULT_FILES)
    with tempfile.TemporaryDirectory(prefix="perf-r6-files-") as temp:
        if args.run:
            run_dir = Path(args.run)
        else:
            started = time.perf_counter()
            run_dir = synthetic_files_run(Path(temp), count)
            print(f"[files] synthetic {count:,} rows written in {time.perf_counter() - started:.1f} s", file=sys.stderr)
        client, run_id = make_client(run_dir)
        url = f"/api/runs/{run_id}/files"
        started = time.perf_counter()
        _, plain = timed_get(client, url, {"limit": 100})
        load_s = time.perf_counter() - started
        scenarios: list[dict[str, object]] = []
        missed: list[str] = []
        for name, condition in FILES_SCENARIOS:
            params = {"limit": 100, **condition}

            def cold(params: dict[str, object] = params) -> float:
                clear_files_caches()
                return timed_get(client, url, params)[0]

            def warm_index(params: dict[str, object] = params) -> float:
                from rapidtriage.api.app import row_conditions

                row_conditions.MATCH_CACHE.clear()  # column index stays, positions recomputed
                return timed_get(client, url, params)[0]

            def next_page(params: dict[str, object] = params) -> float:
                return timed_get(client, url, {**params, "offset": 100})[0]

            first = median_of(args.repeat, cold)
            warm = median_of(args.repeat, warm_index)
            timed_get(client, url, params)
            following = median_of(args.repeat, next_page)
            _, page = timed_get(client, url, params)
            pagination = page.get("pagination") or {}
            entry = {
                "scenario": name,
                "params": condition,
                "matched": page.get("matched"),
                "truncated": pagination.get("truncated"),
                "first_page_cold": first,
                "first_page_warm_index": warm,
                "next_page": following,
            }
            if float(first["median_s"]) > FILES_TARGETS["first_page_s"]:
                missed.append(f"{name}: first page {first['median_s']} s > {FILES_TARGETS['first_page_s']} s")
            if float(following["median_s"]) > FILES_TARGETS["next_page_s"]:
                missed.append(f"{name}: next page {following['median_s']} s > {FILES_TARGETS['next_page_s']} s")
            scenarios.append(entry)
            print(
                f"[files] {name}: matched={entry['matched']} cold={first['median_s']} s "
                f"warm-index={warm['median_s']} s next={following['median_s']} s",
                file=sys.stderr,
            )
        return {
            "rows": plain.get("candidate_count"),
            "source": str(args.run) if args.run else "synthetic",
            "initial_load_s": round(load_s, 3),
            "targets": FILES_TARGETS,
            "scenarios": scenarios,
            "missed": missed,
        }


# --- dispatch ----------------------------------------------------------------------------------

MODES: dict[str, Callable[[argparse.Namespace], dict[str, object]]] = {
    "files": bench_files,
}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="R6 step 3 performance measurements (engineering only).")
    parser.add_argument("--synthetic", action="store_true", help="measure on a synthetic run (default without --run)")
    parser.add_argument("--run", help="existing run output folder (read-only is fine)")
    parser.add_argument(
        "--files", nargs="?", type=int, const=DEFAULT_FILES, default=None, metavar="ROWS",
        help=f"measure GET /files row-condition paging (synthetic row count, default {DEFAULT_FILES:,})",
    )
    parser.add_argument("--repeat", type=int, default=5, help="calls per measurement (median)")
    parser.add_argument("--output", help="write the JSON report here")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    selected = [name for name in MODES if getattr(args, name, None) not in (None, False)]
    if not selected:
        print("no mode selected (e.g. --files)", file=sys.stderr)
        return 2
    if args.run and not Path(args.run).is_dir():
        print(f"run folder not found: {args.run}", file=sys.stderr)
        return 2
    report: dict[str, object] = {"schema_version": SCHEMA_VERSION, "python": sys.version.split()[0], "modes": {}}
    missed: list[str] = []
    for name in selected:
        result = MODES[name](args)
        report["modes"][name] = result  # type: ignore[index]
        missed.extend(f"{name}: {item}" for item in result.get("missed") or [])
    report["missed"] = missed
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main())
