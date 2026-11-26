#!/usr/bin/env python3
"""Time complete indicator summaries, checking each result against Python."""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rapidtriage.core.indicators import build_indicator_summary


def generate(root: Path, records: int) -> dict:
    """Write one repeatable Windows-shaped JSONL input shared by both engines."""
    header = root / "artifacts.json"
    data = root / "artifacts.jsonl"
    header.write_text(json.dumps({"records_file": data.name}), encoding="utf-8")
    with data.open("w", encoding="ascii") as stream:
        for index in range(records):
            path = rf"C:\fixture\set{index % 89}\item{index:08d}.txt"
            details = {"message": f"Read file {path} and closed the handle."}
            if index % 19 == 0:
                details["message"] += " 경로 확인"
            if index % 47 == 0:
                details["url"] = f"https://node{index % 13}.example/Item{index % 37}"
                details["remote_ip"] = f"192.0.2.{index % 253 + 1}"
            if index % 101 == 0:
                details["sha256"] = "a1b2c3d4" * 8
            row = {"artifact_type": "fixture-file-event", "path": path, "details": details}
            stream.write(json.dumps(row) + "\n")
    return {"outputs": {"artifacts_fixture": str(header)}}


def measure(run, repeats: int) -> dict:
    timings = {"python": [], "rust": []}
    reference = None
    metadata = None
    for iteration in range(repeats):
        order = ("rust", "python") if iteration % 2 else ("python", "rust")
        for engine in order:
            os.environ["RAPIDTRIAGE_RUST_INDICATORS"] = "1" if engine == "rust" else "0"
            start = time.perf_counter()
            result = build_indicator_summary(run, max_indicators=None)
            timings[engine].append(time.perf_counter() - start)
            result.pop("generated_at")
            if engine == "rust":
                metadata = result.pop("indicator_kernel")
                if metadata["fallback_reason"] or not metadata["native_rows"]:
                    raise RuntimeError(f"native comparison unavailable: {metadata}")
            if reference is None:
                reference = result
            elif reference != result:
                raise ValueError("ordered indicator summary differs from reference")
    python_time = statistics.median(timings["python"])
    rust_time = statistics.median(timings["rust"])
    return {
        "seconds": timings, "median_seconds": {"python": python_time, "rust": rust_time},
        "speedup": python_time / rust_time, "indicator_rows": len(reference["indicators"]),
        "scanner_rows": len(reference["ioc_scanner_hits"]), "differences": 0, "kernel": metadata,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--records", type=int, default=50000, help="synthetic input record count")
    source.add_argument("--run-summary", type=Path, help="existing synthetic rapidtriage-run-summary.json")
    parser.add_argument("--repeats", type=int, default=3, help="measurements per engine")
    args = parser.parse_args()
    if args.records < 1 or args.repeats < 1:
        parser.error("records and repeats must be positive")
    with tempfile.TemporaryDirectory() as tmp:
        run = args.run_summary or generate(Path(tmp), args.records)
        print(json.dumps(measure(run, args.repeats), indent=2))


if __name__ == "__main__":
    main()
