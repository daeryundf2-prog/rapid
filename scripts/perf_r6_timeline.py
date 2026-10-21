#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
# --- How to run ---
#   python scripts/perf-r6.py --timeline --synthetic [--events 500000] [--repeat 5] [--output <report.json>]
#   python scripts/perf-r6.py --timeline --run <run output dir> [--repeat 5] [--output <report.json>]
#   (scripts/perf-r6.py dispatches --timeline here with argv unchanged; running this file
#   directly with the same arguments works too.)
#
# R6 S3 timeline mode of the performance measurements (docs/plans/r6-followups-2026-10-19.md
# section 3.4). The API is called in-process through FastAPI's TestClient; times are medians of
# --repeat runs. Engineering measurement only -- not a unit test, not CI.
#
# --timeline (lane A, timeline condition index):
#   * synthetic: a temporary run with N events (default 500,000). "no_file" = an older run without
#     rapidtriage-timeline-index.bin (first conditioned page builds the columns it needs);
#     "with_file" = the index written at run completion; "next_page" = the second page (MATCH_CACHE);
#     "memory_extra_mb" = memory retained by the index + matched positions (tracemalloc, one pass);
#     "baseline_scan_s" = the predicate scan the index replaces (one pass).
#   * --run <dir>: an existing run output folder, read-only -- RAPIDTRIAGE_INDEX_PERSIST=0 keeps every
#     index the API builds in memory ("no_file" = no file read or written; "as_is" = the folder's own
#     index file if present). "with_file" copies the timeline into a temporary folder (--scratch,
#     default the system temp folder), writes the index there and measures that copy. The run folder
#     listing (path, size, mtime) is compared before / after: any change fails the run.
#   Targets (Q-S3-2): no_file first page <= 1.0 s, with_file first page <= 0.3 s, next page <= 0.05 s,
#   memory extra <= 30 MB. "search_group" (q= server search, group=1 display grouping; memory-only
#   columns, timeline/grid readability C1/C3): first page <= 1.0 s, next page <= 0.05 s.
#   Exit code 1 when a target is missed, 2 on input errors.
# ------------------
from __future__ import annotations

import sys as _sys

if hasattr(_sys.stdout, "reconfigure"):
    _sys.stdout.reconfigure(encoding="utf-8")
if hasattr(_sys.stderr, "reconfigure"):
    _sys.stderr.reconfigure(encoding="utf-8")

import argparse
import contextlib
import gc
import json
import random
import shutil
import statistics
import sys
import tempfile
import time
import tracemalloc
from collections.abc import Callable, Iterator
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from perf_r6_common import (
    folder_snapshot,
    index_persist,
    snapshot_changes,
)

TOKEN = "perf-r6-token"
TIMELINE_TARGETS = {
    "no_file_first_page_s": 1.0,
    "with_file_first_page_s": 0.3,
    "next_page_s": 0.05,
    "memory_extra_mb": 30.0,
}
# Conditions measured on the timeline (query string, label).
TIMELINE_QUERIES: tuple[tuple[str, str], ...] = (
    ("from=2025-03-01&to=2025-06-30", "time-range"),
    ("offhours=1&tz=Asia/Seoul", "offhours-iana"),
    ("weekday=sat,sun&hours=09-18&tz=%2B09:00", "weekday-hours-offset"),
    ("content=document,executable", "content"),
    ("partial=1", "partial"),
    ("from=2025-01-01&content=image&partial=1", "combined"),
)
# Server search and display grouping (timeline/grid readability C1/C3): memory-only columns built
# on the first request that needs them, so they have their own targets -- first page <= 1.0 s with
# or without the index file, next page <= 0.05 s.
SEARCH_GROUP_QUERIES: tuple[tuple[str, str], ...] = (
    ("q=liveupdate.exe", "q"),
    ("q=exe&from=2025-01-01&partial=1", "q-combined"),
    ("group=1", "grouped"),
    ("group=1&q=docx&from=2024-06-01", "grouped-q-time"),
)
SEARCH_GROUP_TARGETS = {"search_group_first_page_s": 1.0, "search_group_next_page_s": 0.05}
PAGE = 100
# Seconds per join of a background index build before no_index_file reports it and joins again.
BACKGROUND_JOIN_S = 300.0


# --- shared helpers ----------------------------------------------------------------------------


def median(values: list[float]) -> float:
    return round(statistics.median(values), 4) if values else 0.0


def timed(call: Callable[[], object]) -> tuple[float, object]:
    started = time.perf_counter()
    result = call()
    return time.perf_counter() - started, result


def write_run_summary(run_dir: Path, outputs: dict[str, str]) -> None:
    summary = run_dir / "rapidtriage-run-summary.json"
    summary.write_text(
        json.dumps(
            {
                "profile_version": "rapidtriage-run-summary-v1",
                "mode": "hacking",
                "root": str(run_dir / "evidence"),
                "output_dir": str(run_dir),
                "source": {"type": "directory", "analysis_root": str(run_dir / "evidence")},
                "outputs": {**outputs, "summary": str(summary)},
                "summary": {"counts": {}},
            }
        ),
        encoding="utf-8",
    )


def api_client(run_dir: Path) -> tuple[object, object, str]:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import create_app
    from rapidtriage.core.jobs import RunJobStore

    store = RunJobStore()
    run_id = store.import_completed_run(run_dir).run_id
    client = TestClient(create_app(store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})
    return client, store, run_id


def get_json(client: object, url: str) -> dict[str, object]:
    response = client.get(url)  # type: ignore[attr-defined]
    if response.status_code != 200:
        raise RuntimeError(f"{url} -> {response.status_code}: {response.text[:300]}")
    return response.json()


# --- timeline (lane A) -------------------------------------------------------------------------

SYNTHETIC_TYPES = (
    ("eventlog-event", None),
    ("prefetch-file", "exe"),
    ("recent-shortcut", "docx"),
    ("browser-download", "zip"),
    ("browser-history", None),
    ("media-image", "jpg"),
    ("registry-key", None),
    ("jumplist-entry", "pdf"),
    ("lnk-target", "hwp"),
    ("sqlite-row", None),
)


def synthetic_timeline_events(count: int, seed: int = 6) -> list[dict[str, object]]:
    """Timeline-shaped events (core.timeline output) over 2024-2025, ~5 % 부분 결과."""
    rng = random.Random(seed)
    base = 1_704_067_200  # 2024-01-01T00:00:00Z
    span = 2 * 365 * 86_400
    events: list[dict[str, object]] = []
    for position in range(count):
        seconds = base + rng.randrange(span)
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(seconds))
        roll = rng.random()
        timestamp = f"{stamp}.{rng.randrange(1_000_000):06d}Z" if roll < 0.6 else (f"{stamp}Z" if roll < 0.9 else f"{stamp}+09:00")
        artifact_type, extension = SYNTHETIC_TYPES[position % len(SYNTHETIC_TYPES)]
        details: dict[str, object] = {"artifact_type": artifact_type, "source_path": f"C:\\Users\\u{position % 7}\\NTUSER.DAT"}
        if extension:
            details["target_path"] = f"C:\\Users\\u{position % 7}\\Documents\\file{position}.{extension}"
        if rng.random() < 0.05:
            details["parse_status"] = "truncated-record"
        elif rng.random() < 0.3:
            details["parse_status"] = "parsed"
        events.append(
            {
                "timestamp": timestamp,
                "timestamp_kind": "modified",
                "timezone": "UTC",
                "source": "artifacts",
                "event_type": f"artifact-{artifact_type}-modified",
                "path": f"C:\\Windows\\x\\{position}",
                "summary": f"{artifact_type} {position}",
                "details": details,
            }
        )
    return events


def synthetic_timeline_run(directory: Path, events: int) -> Path:
    from rapidtriage.core.timeline import write_timeline_result

    run_dir = directory / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    timeline = run_dir / "rapidtriage-timeline.json"
    write_timeline_result({"summary": {"event_count": events}, "events": synthetic_timeline_events(events)}, timeline)
    write_run_summary(run_dir, {"timeline": str(timeline)})
    return run_dir


def reset_timeline_caches() -> None:
    from rapidtriage.api.app import timeline_index
    from rapidtriage.api.app.row_conditions import MATCH_CACHE

    timeline_index.wait_for_background(120)
    timeline_index.TIMELINE_INDEXES.clear()
    MATCH_CACHE.clear()
    gc.collect()


@contextlib.contextmanager
def no_index_file() -> Iterator[None]:
    """Memory-only index: no saved file is read or written (read-only folder, older run). The
    background completion of the last request is joined inside the block: patching ``save_index``
    alone let that thread write rapidtriage-timeline-index.bin into the run folder after the block.
    The patches (and RAPIDTRIAGE_INDEX_PERSIST) are restored only once no background build is left:
    a join that times out is reported and joined again, never left running past the block."""
    from rapidtriage.api.app import timeline_index

    with mock.patch.object(timeline_index, "load_index", return_value=None), index_persist(False):
        try:
            yield
        finally:
            while not timeline_index.wait_for_background(BACKGROUND_JOIN_S):
                print(
                    f"perf-r6: timeline index background build still running after {BACKGROUND_JOIN_S:.0f} s; waiting",
                    file=sys.stderr,
                )


def first_and_next(client: object, run_id: str, query: str) -> tuple[float, float, int]:
    url = f"/api/runs/{run_id}/timeline?{query}&limit={PAGE}"
    first, body = timed(lambda: get_json(client, url))
    following, _ = timed(lambda: get_json(client, f"{url}&offset={PAGE}"))
    return first, following, int(body["matched"])  # type: ignore[index, call-overload]


def timeline_scenario(
    client: object,
    run_id: str,
    repeat: int,
    prepare: Callable[[], None],
    queries: tuple[tuple[str, str], ...] = TIMELINE_QUERIES,
) -> dict[str, object]:
    per_query: dict[str, dict[str, object]] = {}
    for query, label in queries:
        firsts: list[float] = []
        nexts: list[float] = []
        matched = 0
        for _ in range(repeat):
            reset_timeline_caches()
            prepare()
            first, following, matched = first_and_next(client, run_id, query)
            firsts.append(first)
            nexts.append(following)
        per_query[label] = {"query": query, "matched": matched, "first_page_s": median(firsts), "next_page_s": median(nexts)}
    return {
        "queries": per_query,
        "first_page_s": max(float(item["first_page_s"]) for item in per_query.values()),  # type: ignore[arg-type]
        "next_page_s": max(float(item["next_page_s"]) for item in per_query.values()),  # type: ignore[arg-type]
    }


def timeline_memory(client: object, run_id: str) -> dict[str, float]:
    """Memory retained after the first conditioned pages (index columns + matched positions)."""
    reset_timeline_caches()
    tracemalloc.start()
    try:
        before = tracemalloc.get_traced_memory()[0]
        with no_index_file():
            for query, _ in TIMELINE_QUERIES:
                get_json(client, f"/api/runs/{run_id}/timeline?{query}&limit={PAGE}")
        from rapidtriage.api.app import timeline_index

        timeline_index.wait_for_background(300)
        gc.collect()
        current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return {"memory_extra_mb": round((current - before) / 2**20, 2), "memory_peak_mb": round((peak - before) / 2**20, 2)}


def timeline_baseline(store_events: list[object]) -> float:
    """The predicate scan the index replaces (time-range query, one pass)."""
    from rapidtriage.api.app.row_conditions import parse_row_conditions

    conditions = parse_row_conditions(time_from="2025-03-01", time_to="2025-06-30")
    assert conditions is not None
    predicate = conditions.predicate("timeline")
    seconds, _ = timed(lambda: [i for i, row in enumerate(store_events) if isinstance(row, dict) and predicate(row)])
    return round(seconds, 3)


def timeline_copy(timeline_path: Path, events: list[object], scratch: Path) -> tuple[Path, float]:
    """A run folder in ``scratch`` holding a copy of the timeline and its index file (written there,
    never next to the original): the "with index file" case of a read-only ``--run``."""
    from rapidtriage.api.app import timeline_index

    run_dir = scratch / "run-copy"
    run_dir.mkdir()
    copy = run_dir / timeline_path.name
    shutil.copyfile(timeline_path, copy)
    write_run_summary(run_dir, {"timeline": str(copy)})
    seconds, written = timed(lambda: timeline_index.write_timeline_index(events, copy))
    if written is None:
        raise RuntimeError(f"timeline index not written to {run_dir}")
    return run_dir, seconds


def measure_timeline(args: argparse.Namespace) -> dict[str, object]:
    from rapidtriage.api.app import timeline_index

    report: dict[str, object] = {"mode": "timeline", "repeat": args.repeat, "page": PAGE}
    before: dict[str, tuple[int, int]] = {}
    with contextlib.ExitStack() as stack:
        if args.run:
            run_dir = Path(args.run)
            report["source"] = {"run": str(run_dir)}
            before = folder_snapshot(run_dir)
            stack.enter_context(index_persist(False))  # --run is read-only: indexes stay in memory
        else:
            temp = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="perf-r6-timeline-")))
            seconds, run_dir = timed(lambda: synthetic_timeline_run(temp, args.events))
            report["source"] = {"synthetic_events": args.events, "generate_s": round(seconds, 2)}
        client, store, run_id = api_client(run_dir)  # type: ignore[arg-type]
        load_s, _ = timed(lambda: get_json(client, f"/api/runs/{run_id}/timeline?limit=1"))
        report["json_load_s"] = round(load_s, 2)  # OutputJsonCache: shared by every later page
        timeline_path = store.output_path(run_id, "timeline")  # type: ignore[attr-defined]
        events = store.read_output(run_id, "timeline").get("events") or []  # type: ignore[attr-defined]
        report["events"] = len(events)  # type: ignore[arg-type]

        with no_index_file():
            report["no_file"] = timeline_scenario(client, run_id, args.repeat, lambda: None)
            report["search_group"] = timeline_scenario(client, run_id, args.repeat, lambda: None, SEARCH_GROUP_QUERIES)
        report.update(timeline_memory(client, run_id))
        report["baseline_scan_s"] = timeline_baseline(events)  # type: ignore[arg-type]
        reset_timeline_caches()
        if args.run:
            # The run folder's own index file when present (read, never written).
            if timeline_index.index_path_for(timeline_path).exists():
                report["as_is"] = timeline_scenario(client, run_id, args.repeat, lambda: None)
            else:
                report["as_is"] = {"skipped": "no index file in the run folder"}
            scratch = Path(
                stack.enter_context(tempfile.TemporaryDirectory(prefix="perf-r6-timeline-copy-", dir=args.scratch))
            )
            copy_dir, persist_s = timeline_copy(timeline_path, events, scratch)  # type: ignore[arg-type]
            report["persist_build_s"] = round(persist_s, 2)
            copy_client, _copy_store, copy_id = api_client(copy_dir)
            copy_load_s, _ = timed(lambda: get_json(copy_client, f"/api/runs/{copy_id}/timeline?limit=1"))
            report["with_file_source"] = {"copy": "temporary folder, deleted afterwards", "json_load_s": round(copy_load_s, 2)}
            report["with_file"] = timeline_scenario(copy_client, copy_id, args.repeat, lambda: None)
        else:
            persist_s, _ = timed(lambda: timeline_index.write_timeline_index(events, timeline_path))  # type: ignore[arg-type]
            report["persist_build_s"] = round(persist_s, 2)
            report["with_file"] = timeline_scenario(client, run_id, args.repeat, lambda: None)
        reset_timeline_caches()
    if args.run:
        changes = snapshot_changes(before, folder_snapshot(Path(args.run)))
        report["run_folder_unchanged"] = not changes
        if changes:
            report["run_folder_changes"] = changes[:50]

    measured = {
        "no_file_first_page_s": report["no_file"]["first_page_s"],  # type: ignore[index]
        "next_page_s": max(report["no_file"]["next_page_s"], (report.get("with_file") or {}).get("next_page_s", 0)),  # type: ignore[index, union-attr]
        "memory_extra_mb": report["memory_extra_mb"],
    }
    if "with_file" in report:
        measured["with_file_first_page_s"] = report["with_file"]["first_page_s"]  # type: ignore[index]
    elif isinstance(report.get("as_is"), dict) and "first_page_s" in report["as_is"]:  # type: ignore[operator]
        measured["with_file_first_page_s"] = report["as_is"]["first_page_s"]  # type: ignore[index]
    measured["search_group_first_page_s"] = report["search_group"]["first_page_s"]  # type: ignore[index]
    measured["search_group_next_page_s"] = report["search_group"]["next_page_s"]  # type: ignore[index]
    targets = {**TIMELINE_TARGETS, **SEARCH_GROUP_TARGETS}
    report["targets"] = {
        key: {"measured": value, "target": targets[key], "ok": float(value) <= targets[key]}  # type: ignore[arg-type]
        for key, value in measured.items()
    }
    report["ok"] = all(item["ok"] for item in report["targets"].values()) and bool(  # type: ignore[union-attr]
        report.get("run_folder_unchanged", True)
    )
    return report


# --- entry -------------------------------------------------------------------------------------

MODES: dict[str, Callable[[argparse.Namespace], dict[str, object]]] = {
    "timeline": measure_timeline,
}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="R6 S3 performance measurements (engineering only).")
    for mode in MODES:
        parser.add_argument(f"--{mode}", action="store_true", help=f"measure the {mode} mode")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--synthetic", action="store_true", help="generate a temporary synthetic run")
    source.add_argument("--run", help="existing run output folder (read-only)")
    parser.add_argument("--events", type=int, default=500_000, help="synthetic timeline events (default 500000)")
    parser.add_argument("--repeat", type=int, default=5, help="runs per measurement, median reported (default 5)")
    parser.add_argument("--output", help="write the JSON report here")
    parser.add_argument("--scratch", help="--run: folder for the temporary timeline copy (default: system temp)")
    args = parser.parse_args(argv)
    if not any(getattr(args, mode) for mode in MODES):
        parser.error("choose at least one mode: " + ", ".join(f"--{mode}" for mode in MODES))
    if args.run and not Path(args.run).is_dir():
        parser.error(f"--run {args.run} is not a folder")
    if args.events <= 0 or args.repeat <= 0:
        parser.error("--events and --repeat must be positive")
    return args


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    reports = {mode: function(args) for mode, function in MODES.items() if getattr(args, mode)}
    out = {"tool": "perf-r6", "reports": reports, "ok": all(report.get("ok", True) for report in reports.values())}
    text = json.dumps(out, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
