#!/usr/bin/env python3
"""Benchmark the Python and Rust registry hive engines on a large generated hive.

Generates a synthetic multi-hbin hive (``tests/registry_hive_gen.py``; nothing real, nothing
committed) in a temporary directory, then for each engine measures:

- reader walk: ``iter_keys`` + ``values`` + ``value_data`` over every key -> keys/s, values/s;
- allocator scan: ``iter_registry_free_cell_candidates`` (whole-hive hbin/cell walk);
- end to end: ``collect_registry_hive`` (key-tree rows, plugins, depth rows, recovery rows).

Each phase reports the best of ``--repeat`` runs. Both engines must also agree on the counts.

Usage: python scripts/registry-engine-benchmark.py [--keys 100000] [--repeat 3] [--json]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.artifacts.windows.registry import (
    NativeRegistryHive,
    RegistryCollectionContext,
    collect_registry_hive,
    iter_registry_free_cell_candidates,
)
from rapidtriage.artifacts.windows.registry_engine import (
    REGISTRY_ENGINE_ENV,
    REGISTRY_NATIVE_BUILD_HINT,
    load_registry_extension,
)
from tests.registry_hive_gen import generate_hive


def best_of(repeat: int, run: Callable[[], object]) -> tuple[float, object]:
    best = float("inf")
    result: object = None
    for _ in range(repeat):
        started = time.perf_counter()
        result = run()
        best = min(best, time.perf_counter() - started)
    return best, result


def walk(path: Path) -> tuple[int, int]:
    hive = NativeRegistryHive.open(path)
    assert hive is not None
    keys = values = 0
    try:
        for _parts, key in hive.iter_keys():
            keys += 1
            for value in hive.values(key):
                hive.value_data(value)
                values += 1
    finally:
        hive.close()
    return keys, values


def free_cells(path: Path) -> int:
    hive = NativeRegistryHive.open(path)
    assert hive is not None
    try:
        return len(iter_registry_free_cell_candidates(hive)[0])
    finally:
        hive.close()


def collect(path: Path) -> int:
    return sum(1 for _ in collect_registry_hive(path, context=RegistryCollectionContext(None)))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--keys", type=int, default=100_000, help="keys in the generated hive")
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument(
        "--deleted",
        type=int,
        default=None,
        help="free (deleted) key/value cells to plant (default: keys/20); end-to-end time grows quadratically with "
        "recovery candidates because of the Python allocator-neighbour context",
    )
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--skip-collect", action="store_true", help="skip the end-to-end collect_registry_hive phase")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if load_registry_extension()[0] is None:
        print(f"rapid_registry_native is not built ({load_registry_extension()[1]}); run {REGISTRY_NATIVE_BUILD_HINT}", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory(prefix="rapid-registry-bench-") as tmp:
        path = Path(tmp) / "SOFTWARE"
        started = time.perf_counter()
        deleted = args.deleted if args.deleted is not None else max(1, args.keys // 20)
        path.write_bytes(generate_hive(args.seed, key_count=args.keys, deleted_count=deleted, minor_version=5))
        report: dict[str, object] = {
            "hive_bytes": path.stat().st_size,
            "generate_seconds": round(time.perf_counter() - started, 3),
            "repeat": args.repeat,
            "engines": {},
        }
        previous = os.environ.get(REGISTRY_ENGINE_ENV)
        try:
            for engine in ("python", "rust"):
                os.environ[REGISTRY_ENGINE_ENV] = engine
                walk_seconds, (keys, values) = best_of(args.repeat, lambda: walk(path))  # type: ignore[misc]
                scan_seconds, free_count = best_of(args.repeat, lambda: free_cells(path))
                result: dict[str, object] = {
                    "keys": keys,
                    "values": values,
                    "walk_seconds": round(walk_seconds, 4),
                    "keys_per_second": round(keys / walk_seconds),
                    "values_per_second": round(values / walk_seconds),
                    "free_cell_scan_seconds": round(scan_seconds, 4),
                    "free_cell_candidates": free_count,
                }
                if not args.skip_collect:
                    collect_seconds, rows = best_of(args.repeat, lambda: collect(path))
                    result.update({"collect_seconds": round(collect_seconds, 4), "collect_rows": rows})
                report["engines"][engine] = result  # type: ignore[index]
        finally:
            if previous is None:
                os.environ.pop(REGISTRY_ENGINE_ENV, None)
            else:
                os.environ[REGISTRY_ENGINE_ENV] = previous
    python_side, rust_side = report["engines"]["python"], report["engines"]["rust"]  # type: ignore[index]
    counted = ("keys", "values", "free_cell_candidates", "collect_rows")
    report["counts_agree"] = all(python_side.get(name) == rust_side.get(name) for name in counted)
    report["speedup"] = {
        phase: round(python_side[phase] / rust_side[phase], 2)
        for phase in ("walk_seconds", "free_cell_scan_seconds", "collect_seconds")
        if phase in python_side and rust_side.get(phase)
    }
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for engine, result in report["engines"].items():  # type: ignore[union-attr]
            print(f"{engine:6} {result}")
        print(f"speedup {report['speedup']} counts_agree={report['counts_agree']}")
    return 0 if report["counts_agree"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
