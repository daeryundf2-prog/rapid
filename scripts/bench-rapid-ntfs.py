#!/usr/bin/env python3
"""Time the Python and Rust (rapid-ntfs) $MFT / $UsnJrnl:$J parsers on synthetic input.

Generates a synthetic $MFT and USN journal in a temporary directory (deleted
afterwards; nothing touches Git), then parses both the way the NTFS-meta
analysis does (2048-record $MFT chunks, 16 MiB USN windows) with each engine.
Requires the extension: python scripts/build-rapid-ntfs.py

Usage: python scripts/bench-rapid-ntfs.py [--mft-records N] [--usn-records N] [--json]
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.api.app.analysis_kinds import (
    MFT_CHUNK_RECORDS,
    USN_WINDOW_BYTES,
    USN_WINDOW_OVERLAP,
)
from rapidtriage.artifacts.windows import filesystem
from rapidtriage.core import ntfs_native
from tests import ntfs_synthetic

RECORD_SIZE = 1024


def time_mft(path: Path, parser: Callable[[bytes], list[dict[str, object]]]) -> tuple[int, float]:
    records = 0
    elapsed = 0.0
    with path.open("rb") as handle:
        while blob := handle.read(MFT_CHUNK_RECORDS * RECORD_SIZE):
            started = time.perf_counter()
            parsed = parser(blob)
            elapsed += time.perf_counter() - started
            records += sum(1 for record in parsed if int(record["record_offset"]) % RECORD_SIZE == 0)
    return records, elapsed


def time_usn(path: Path, parser: Callable[..., dict[str, object]]) -> tuple[int, float]:
    size = path.stat().st_size
    records = 0
    elapsed = 0.0
    position = 0
    with path.open("rb") as handle:
        while position < size:
            handle.seek(position)
            blob = handle.read(USN_WINDOW_BYTES + USN_WINDOW_OVERLAP)
            last_window = position + len(blob) >= size
            started = time.perf_counter()
            scan = parser(blob, record_limit=10_000_000, max_scan_bytes=None if last_window else USN_WINDOW_BYTES)
            elapsed += time.perf_counter() - started
            records += len(scan["records"])  # type: ignore[arg-type]
            if last_window:
                break
            position += max(int(scan["last_scanned_offset"]), 1)  # type: ignore[call-overload]
    return records, elapsed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mft-records", type=int, default=500_000)
    parser.add_argument("--usn-records", type=int, default=500_000)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    extension, reason = ntfs_native.load_native_ntfs_parser()
    if extension is None:
        print(f"rapid_ntfs_native is unusable: {reason}", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="rapid-ntfs-bench-") as tmp:
        mft_path = Path(tmp) / "MFT.bin"
        usn_path = Path(tmp) / "J.bin"
        started = time.perf_counter()
        mft_path.write_bytes(ntfs_synthetic.bench_mft(args.mft_records, size=RECORD_SIZE))
        usn_path.write_bytes(ntfs_synthetic.bench_usn(args.usn_records))
        generated = time.perf_counter() - started

        rows = []
        for artifact, path, timer, python_parser, rust_parser in (
            ("$MFT", mft_path, time_mft, filesystem.parse_mft_record_headers, extension.parse_mft_record_headers),
            ("$UsnJrnl:$J", usn_path, time_usn, filesystem.parse_usn_record_scan, extension.parse_usn_record_scan),
        ):
            python_count, python_seconds = timer(path, python_parser)
            rust_count, rust_seconds = timer(path, rust_parser)
            if python_count != rust_count:
                print(f"{artifact}: record counts differ ({python_count} vs {rust_count})", file=sys.stderr)
                return 1
            rows.append(
                {
                    "artifact": artifact,
                    "records": rust_count,
                    "bytes": path.stat().st_size,
                    "python_seconds": round(python_seconds, 3),
                    "rust_seconds": round(rust_seconds, 3),
                    "python_records_per_second": round(python_count / python_seconds),
                    "rust_records_per_second": round(rust_count / rust_seconds),
                    "speedup": round(python_seconds / rust_seconds, 1),
                }
            )

    result = {"generated_seconds": round(generated, 1), "python": sys.version.split()[0], "results": rows}
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("| artifact | records | Python s | Rust s | Python rec/s | Rust rec/s | speedup |")
        print("|---|---:|---:|---:|---:|---:|---:|")
        for row in rows:
            print(
                f"| {row['artifact']} | {row['records']:,} | {row['python_seconds']} | {row['rust_seconds']} | "
                f"{row['python_records_per_second']:,} | {row['rust_records_per_second']:,} | {row['speedup']}x |"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
