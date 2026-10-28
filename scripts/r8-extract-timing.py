#!/usr/bin/env python3
"""Measure native NTFS extraction throughput by job order and worker count on one partition.

Plans the partition once (directory walk, local sequential $MFT copy), keeps only jobs with
non-resident data (resident files never touch the image), then extracts for a fixed wall time per
mode into a scratch directory that is deleted after each mode:

  dir-8   directory order, 8 workers
  lcn-8   first-LCN order, 8 workers
  lcn-2   first-LCN order, 2 workers
  lcn-1   first-LCN order, 1 worker

The modes run back to back so they share the same disk conditions. Each LCN mode starts at a
different slice of the LCN-sorted list so no mode re-reads bytes another mode just cached.
Prints counts, bytes and rates only; output file names never leave the scratch directory
(files are written as numbered names).
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import json
import os
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rapidtriage.core import e01_native
from rapidtriage.core.e01 import discover_e01_segments

# (label, order, workers, start fraction of the sorted list)
MODES = (
    ("dir-8", "dir", 8, 0.0),
    ("lcn-8", "lcn", 8, 0.0),
    ("lcn-2", "lcn", 2, 0.34),
    ("lcn-1", "lcn", 1, 0.67),
)


def plan_jobs(segments: list[Path], offset: int, size: int, plan_limit: int) -> tuple[list[e01_native._ExtractJob], dict]:
    handle = e01_native.open_ewf_segments(segments)
    local_mft: Path | None = None
    stats = e01_native._new_stats()
    t0 = time.monotonic()
    try:
        fs = e01_native.NTFS(e01_native.EwfSectorReader(handle, base=offset, size=size))
        local_mft, _ = e01_native._write_local_mft(fs, None, stats)
        if local_mft is None:
            raise SystemExit("local $MFT copy failed")
        plan_mft = e01_native._LocalMft(local_mft)
        try:
            plan_fs = e01_native.NTFS(e01_native.EwfSectorReader(handle, base=offset, size=size), mft=plan_mft)
            jobs: list[e01_native._ExtractJob] = []
            e01_native._plan_ntfs_dir(plan_fs.mft.get(5), Path("out"), stats, jobs, limit=plan_limit)
        finally:
            plan_mft.close()
    finally:
        with contextlib.suppress(Exception):
            handle.close()
    info = {
        "planned_jobs": len(jobs),
        "resident_or_empty_jobs": sum(1 for job in jobs if job.lcn == 0),
        "plan_seconds": round(time.monotonic() - t0, 1),
        "plan_errors": stats["errors"],
    }
    return jobs, {**info, "_mft": local_mft}


def run_mode(
    label: str,
    jobs: list[e01_native._ExtractJob],
    segments: list[Path],
    offset: int,
    size: int,
    local_mft: Path,
    workers: int,
    seconds: float,
    max_bytes: int,
    scratch: Path,
) -> dict:
    out_root = scratch / label
    out_root.mkdir(parents=True, exist_ok=True)
    contexts = e01_native._WorkerContexts(segments, offset, size, local_mft)
    lock = threading.Lock()
    state = {"next": 0, "files": 0, "bytes": 0, "errors": 0}
    t0 = time.monotonic()
    deadline = t0 + seconds

    def work() -> None:
        while True:
            with lock:
                if time.monotonic() >= deadline or state["bytes"] >= max_bytes or state["next"] >= len(jobs):
                    return
                index = state["next"]
                state["next"] += 1
            job = dataclasses.replace(jobs[index], out_path=out_root / str(index))
            try:
                _, outcome = e01_native._extract_job(contexts, job)
            except Exception:
                outcome = None
            with lock:
                if outcome is None:
                    state["errors"] += 1
                else:
                    state["files"] += 1
                    state["bytes"] += int(outcome[0])

    threads = [threading.Thread(target=work, name=f"timing-{n}", daemon=True) for n in range(workers)]
    try:
        for thread in threads:
            thread.start()
        # Rates are taken at the deadline: a worker inside one multi-GB file would otherwise hold the
        # mode open for an unbounded time. Files still in flight at the deadline are not counted.
        for thread in threads:
            thread.join(max(0.0, deadline - time.monotonic()))
        with lock:
            snapshot = dict(state)
        elapsed = min(time.monotonic(), deadline) - t0
        # Drain the in-flight files before the next mode so modes never overlap on the disk.
        drain_start = time.monotonic()
        for thread in threads:
            thread.join()
        drain = time.monotonic() - drain_start
    finally:
        contexts.close()
        shutil.rmtree(out_root, ignore_errors=True)
    return {
        "mode": label,
        "workers": workers,
        "seconds": round(elapsed, 1),
        "files": snapshot["files"],
        "errors": snapshot["errors"],
        "mb": round(snapshot["bytes"] / 1e6, 1),
        "mb_per_s": round(snapshot["bytes"] / 1e6 / elapsed, 2) if elapsed else None,
        "files_per_s": round(snapshot["files"] / elapsed, 2) if elapsed else None,
        "drain_seconds": round(drain, 1),
        "output_deleted": not out_root.exists(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--start-sector", type=int, required=True)
    parser.add_argument("--scratch", required=True, help="scratch directory for extraction output and the local $MFT copy")
    parser.add_argument("--seconds", type=float, default=180.0, help="wall time per mode")
    parser.add_argument("--max-mb", type=int, default=4096, help="stop a mode after this many MB")
    parser.add_argument("--plan-limit", type=int, default=10**9)
    parser.add_argument("--modes", default=",".join(label for label, *_ in MODES))
    args = parser.parse_args()

    scratch = Path(args.scratch)
    scratch.mkdir(parents=True, exist_ok=True)
    tempfile.tempdir = str(scratch)  # the local $MFT copy lands here too
    segments = discover_e01_segments(Path(args.image))
    handle = e01_native.open_ewf_segments(segments)
    try:
        offset = args.start_sector * e01_native.ewf_sector_size(handle)
        size = int(handle.get_media_size()) - offset
    finally:
        handle.close()

    jobs, info = plan_jobs(segments, offset, size, args.plan_limit)
    local_mft = info.pop("_mft")
    try:
        sample = [job for job in jobs if job.lcn > 0]
        by_lcn = e01_native._order_jobs_by_lcn(sample)
        print(json.dumps({"plan": {**info, "nonresident_jobs": len(sample)}}), flush=True)
        wanted = set(args.modes.split(","))
        for label, order, workers, start in MODES:
            if label not in wanted:
                continue
            ordered = sample if order == "dir" else by_lcn
            begin = int(len(ordered) * start)
            result = run_mode(
                label, ordered[begin:], segments, offset, size, local_mft,
                workers, args.seconds, args.max_mb * 1_000_000, scratch,
            )
            print(json.dumps({**result, "start_index": begin}), flush=True)
    finally:
        with contextlib.suppress(OSError):
            os.unlink(local_mft)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
