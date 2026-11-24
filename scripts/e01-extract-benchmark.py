#!/usr/bin/env python3
"""Benchmark the native E01 extraction engines (Python vs Rust) on a synthetic NTFS image.

Builds a synthetic MBR+NTFS disk (``tests/ntfs_volume_gen.py``) in a temporary directory,
optionally wraps it in a multi-segment E01 with ``ewfacquire`` (``--e01``), runs
``extract_e01_native`` with each engine ``--repeat`` times, checks that both engines produced
the same tree and stats, and deletes everything it wrote.

Usage: python scripts/e01-extract-benchmark.py [--files 20000] [--dirs 200] [--repeat 3] [--e01] [--json]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.core import e01_extract_engine, e01_native
from tests.ntfs_volume_gen import build_disk_image


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        digest.update(path.relative_to(root).as_posix().encode())
        if path.is_file():
            digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def run_once(engine: str, source: Path, segments: list[Path], raw: bool, work: Path) -> tuple[float, dict[str, Any], str]:
    out = work / f"out-{engine}"
    shutil.rmtree(out, ignore_errors=True)
    os.environ[e01_extract_engine.E01_EXTRACT_ENGINE_ENV] = engine
    opener = e01_native.open_ewf_segments
    if raw:
        e01_native.open_ewf_segments = lambda segs: e01_native.RawMediaHandle(segs[0])
    try:
        started = time.perf_counter()
        result = e01_native.extract_e01_native(source, segments, out / "tree")
        elapsed = time.perf_counter() - started
    finally:
        e01_native.open_ewf_segments = opener
    digest = tree_digest(out / "tree")
    shutil.rmtree(out, ignore_errors=True)
    return elapsed, result, digest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--files", type=int, default=20_000)
    parser.add_argument("--dirs", type=int, default=200)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--e01", action="store_true", help="wrap the image in an E01 segment set (needs ewfacquire)")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if e01_native.NTFS is None:
        print("dissect.ntfs is not installed", file=sys.stderr)
        return 2
    module, problem = e01_extract_engine.load_extract_extension()
    if module is None:
        print(f"rapid_extract_native unavailable ({problem}); run {e01_extract_engine.E01_EXTRACT_BUILD_HINT}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="e01-extract-bench-") as tmp:
        work = Path(tmp)
        image = work / "disk.raw"
        info = build_disk_image(image, bulk_files=args.files, bulk_dirs=args.dirs)
        source, segments, raw = image, [image], True
        if args.e01:
            ewfacquire = shutil.which("ewfacquire")
            if ewfacquire is None or e01_native.pyewf is None:
                print("--e01 needs ewfacquire and pyewf", file=sys.stderr)
                return 2
            subprocess.run(
                [ewfacquire, "-u", "-q", "-t", str(work / "disk"), "-f", "encase6", "-c", "deflate:fast",
                 "-S", "200MiB", "-C", "synthetic", "-D", "synthetic", "-e", "synthetic", "-E", "1",
                 "-N", "synthetic", str(image)],
                check=True, capture_output=True,
            )
            image.unlink()
            segments = sorted(work.glob("disk.E*"))
            source, raw = segments[0], False

        report: dict[str, object] = {"image": {**info, "container": "e01" if args.e01 else "raw", "segments": len(segments)}}
        digests: dict[str, str] = {}
        stats: dict[str, object] = {}
        best_seconds: dict[str, float] = {}
        for engine in ("python", "rust"):
            runs = [run_once(engine, source, segments, raw, work) for _ in range(max(1, args.repeat))]
            times = [elapsed for elapsed, _result, _digest in runs]
            _elapsed, result, digests[engine] = runs[-1]
            stats[engine] = result["stats"]
            files = int(result["stats"]["files"])
            best = best_seconds[engine] = min(times)
            report[engine] = {
                "wall_seconds": [round(t, 3) for t in times],
                "best_seconds": round(best, 3),
                "median_seconds": round(statistics.median(times), 3),
                "files": files,
                "files_per_second": round(files / best, 1),
                "engine": result.get("extract_engine", {"active": "python"}),
            }
        report["identical_output"] = digests["python"] == digests["rust"] and stats["python"] == stats["rust"]
        report["speedup_best"] = round(best_seconds["python"] / best_seconds["rust"], 2)

    print(json.dumps(report, indent=None if args.json else 2, ensure_ascii=False))
    return 0 if report["identical_output"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
