#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
# --- How to run ---
#   python scripts/r8-bench.py --image <E01> --label <name> \
#       --out-root <dir> [--mode recovery] [--rapid-root <checkout>] \
#       [--extra-run-args "..."]
#
# One-command benchmark for `rapidtriage run` on one evidence image.
# Writes <out-root>/<label>/<image_set_id>/r8-bench.json (schema r8-bench-v1).
# Output holds counts, stage timings, coverage and host load context only: no
# evidence file names, paths, or content. Exit 3 when any evidence segment changed.
# rapidtriage runs with cwd=<rapid-root> so `python -m rapidtriage` imports that
# checkout. psutil is optional; without it peak_rss_mb and system_cpu_mean are null.
# ------------------
from __future__ import annotations

import sys as _sys

if hasattr(_sys.stdout, "reconfigure"):
    _sys.stdout.reconfigure(encoding="utf-8")
if hasattr(_sys.stderr, "reconfigure"):
    _sys.stderr.reconfigure(encoding="utf-8")

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "r8-bench-v1"
# E01..E99, EAA..EZZ, and the Ex01.. / ExAA.. variants. Letter suffixes are uppercase-only, so
# lowercase ordinary extensions such as .eml or .exe do not match; uppercase three-letter
# extensions such as .EML could still match and are snapshotted as extra (harmless) entries.
SEGMENT_SUFFIX_RE = re.compile(r"[Ee](?:0[1-9]|[1-9][0-9]|[A-Z]{2})|[Ee][Xx](?:0[1-9]|[1-9][0-9]|[A-Z]{2})")
SAMPLE_INTERVAL_S = 2.0
EXIT_SEGMENTS_CHANGED = 3

try:
    import psutil
except ImportError:  # psutil is optional; RSS and CPU load are reported as null without it.
    psutil = None


def image_set_id(image: Path) -> str:
    return hashlib.sha256(str(image).encode("utf-8")).hexdigest()[:12]


def snapshot_segments(image: Path) -> list[list[int]]:
    """Size and mtime (ns) of every EWF segment sharing the image stem, name-sorted."""
    names = {image.name}
    for entry in image.parent.iterdir():
        if (
            entry.is_file()
            and entry.stem.lower() == image.stem.lower()
            and SEGMENT_SUFFIX_RE.fullmatch(entry.suffix[1:])
        ):
            names.add(entry.name)
    entries = []
    for name in sorted(names):
        stat = (image.parent / name).stat()
        entries.append([stat.st_size, stat.st_mtime_ns])
    return entries


def git_short_head(rapid_root: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(rapid_root), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def tree_rss_mb(pid: int) -> float | None:
    try:
        root = psutil.Process(pid)
        total = 0
        for proc in [root, *root.children(recursive=True)]:
            try:
                total += proc.memory_info().rss
            except psutil.Error:
                continue
        return total / (1024 * 1024)
    except psutil.Error:
        return None


def run_sampled(cmd: list[str], log_path: Path, cwd: Path) -> tuple[int, float | None, float | None]:
    """Run cmd in cwd; sample process-tree RSS and system CPU every SAMPLE_INTERVAL_S seconds."""
    peak: float | None = None
    cpu_samples: list[float] = []
    with log_path.open("wb") as log:
        proc = subprocess.Popen(cmd, cwd=cwd, stdout=log, stderr=subprocess.STDOUT)
        if psutil is not None:
            psutil.cpu_percent(interval=None)  # first reading covers no interval; discard it
        while True:
            try:
                proc.wait(timeout=SAMPLE_INTERVAL_S)
                break
            except subprocess.TimeoutExpired:
                if psutil is not None:
                    cpu_samples.append(psutil.cpu_percent(interval=None))
                    sample = tree_rss_mb(proc.pid)
                    if sample is not None:
                        peak = sample if peak is None else max(peak, sample)
    peak_mb = round(peak, 1) if peak is not None else None
    cpu_mean = round(sum(cpu_samples) / len(cpu_samples), 1) if cpu_samples else None
    return proc.returncode, peak_mb, cpu_mean


def read_json_or_empty(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def parse_stages(summary: dict, run_started_epoch: float) -> dict[str, float]:
    """Seconds from run start until each summary step's output file was last written.

    rapidtriage records no per-step durations, so the completion offset of each
    step output (``summary.steps[].output`` mtime) is the observable timing.
    """
    stages: dict[str, float] = {}
    steps = summary.get("steps")
    for step in steps if isinstance(steps, list) else []:
        if not isinstance(step, dict):
            continue
        name = step.get("name")
        output = step.get("output")
        if not name or not isinstance(output, str):
            continue
        try:
            mtime = os.stat(output).st_mtime
        except OSError:
            continue
        stages[str(name)] = round(max(0.0, mtime - run_started_epoch), 3)
    return stages


def parse_provider_ms(summary: dict) -> dict[str, int]:
    """Total provider milliseconds per artifact-scheduler phase (summary.safety.artifact_scheduler)."""
    totals: dict[str, int] = {}
    scheduler = summary.get("safety", {}).get("artifact_scheduler") if isinstance(summary.get("safety"), dict) else None
    for phase, block in scheduler.items() if isinstance(scheduler, dict) else []:
        events = block.get("events") if isinstance(block, dict) else None
        if not isinstance(events, list):
            continue
        totals[str(phase)] = sum(
            e["duration_ms"] for e in events if isinstance(e, dict) and isinstance(e.get("duration_ms"), int)
        )
    return totals


def parse_counts(summary: dict) -> dict:
    inner = summary.get("summary") if isinstance(summary.get("summary"), dict) else {}
    counts = {k: v for k, v in inner.items() if isinstance(v, (int, float)) and k.endswith("_count")}
    if isinstance(inner.get("counts"), dict):
        counts.update({k: v for k, v in inner["counts"].items() if isinstance(v, (int, float))})
    return counts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Benchmark one rapidtriage run on one E01 image (r8-bench-v1).")
    parser.add_argument("--image", required=True, type=Path, help="Evidence image path (E01 first segment)")
    parser.add_argument("--label", required=True, help="Run label, e.g. baseline or after")
    parser.add_argument("--out-root", required=True, type=Path, help="Output root (keep outside Git)")
    parser.add_argument("--mode", default="recovery", help="rapidtriage run mode (default: recovery)")
    parser.add_argument(
        "--rapid-root",
        type=Path,
        default=REPO_ROOT,
        help="rapidtriage checkout to run (subprocess cwd; default: repo root containing this script)",
    )
    parser.add_argument("--extra-run-args", default="", help="Extra arguments passed through to `rapidtriage run`")
    args = parser.parse_args(argv)

    image = Path(os.path.abspath(args.image))
    rapid_root = Path(os.path.abspath(args.rapid_root))
    image_id = image_set_id(image)
    out_dir = Path(os.path.abspath(args.out_root)) / args.label / image_id
    out_dir.mkdir(parents=True, exist_ok=True)

    before = snapshot_segments(image)
    cmd = [
        sys.executable, "-m", "rapidtriage", "run", str(image),
        "--mode", args.mode, "--read-only", "--output-dir", str(out_dir),
        *shlex.split(args.extra_run_args, posix=False),
    ]
    started_epoch = time.time()
    started = time.perf_counter()
    returncode, peak_rss_mb, system_cpu_mean = run_sampled(cmd, out_dir / "r8-bench-run.log", rapid_root)
    wall_s = round(time.perf_counter() - started, 3)
    after = snapshot_segments(image)
    segments_unchanged = before == after

    summary = read_json_or_empty(out_dir / "rapidtriage-run-summary.json")
    result = {
        "schema": SCHEMA,
        "label": args.label,
        "image_set_id": image_id,
        "mode": args.mode,
        "code_rev": git_short_head(rapid_root),
        "run_exit_code": returncode,
        "wall_s": wall_s,
        "peak_rss_mb": peak_rss_mb,
        "cpu_count": os.cpu_count(),
        "system_cpu_mean": system_cpu_mean,
        "stages": parse_stages(summary, started_epoch),
        "provider_ms": parse_provider_ms(summary),
        "counts": parse_counts(summary),
        "coverage": summary.get("coverage") if isinstance(summary.get("coverage"), (dict, list)) else [],
        "segment_count": len(after),
        "segments_unchanged": segments_unchanged,
    }
    (out_dir / "r8-bench.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

    print(
        f"r8-bench {args.label} image_set_id={image_id} run_exit={returncode} "
        f"wall_s={wall_s} segments={len(after)} unchanged={segments_unchanged}"
    )
    print(f"output: {out_dir / 'r8-bench.json'}")
    if not segments_unchanged:
        print("error: evidence segment size or mtime changed", file=sys.stderr)
        return EXIT_SEGMENTS_CHANGED
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
