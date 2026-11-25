#!/usr/bin/env python3
"""Benchmark and diff the Python and Rust EVTX decoders on a generated log.

Generates a synthetic EVTX (default 500,000 live records of mixed Security/
System/PowerShell events with Korean text, 7-digit FILETIMEs and slack copies;
``tests/evtx_engine_corpus.py``) into a temporary directory, then reports:

* ``decoder`` — chunk walk + BinXML decode only (``EvtxChunkDecoder`` vs
  ``rapidcore_native.EvtxChunkDecoder``), records/s;
* ``rows`` — full ``collect_native_evtx_events`` row building (pipeline
  defaults: triage detail, no structure rows), records/s for each engine,
  timed while both row streams are compared row by row (every field).

The generated file is deleted afterwards unless ``--keep``. Build the native
module first: ``python scripts/build-native-accel.py``.

Usage: python scripts/evtx-engine-bench.py [--records 500000] [--detail triage|full] [--json OUT]
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import mmap
import platform
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from evtx_engine_corpus import write_mixed_evtx

from rapidtriage.artifacts.windows.eventlog import (
    EVTX_CHUNK_SIGNATURE,
    EVTX_CHUNK_SIZE,
    EVTX_FILE_HEADER_SIZE,
    EvtxChunkDecoder,
    EvtxDecodeError,
    collect_native_evtx_events,
    iter_evtx_chunk_record_slots,
)
from rapidtriage.artifacts.windows.evtx_engine import (
    NativeEvtxChunkDecoder,
    load_native_evtx_decoder,
)


def decode_pass(path: Path, make_decoder) -> tuple[int, float]:
    records = 0
    started = time.process_time()
    with open(path, "rb") as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as blob:
        for offset in range(EVTX_FILE_HEADER_SIZE, len(blob) - 8, EVTX_CHUNK_SIZE):
            if blob[offset : offset + 8] != EVTX_CHUNK_SIGNATURE:
                continue
            chunk = bytes(blob[offset : offset + EVTX_CHUNK_SIZE])
            decoder = make_decoder(chunk)
            for slot in iter_evtx_chunk_record_slots(chunk, active=True):
                if not slot.parseable:
                    continue
                try:
                    decoder.decode_record(slot.relative_offset, slot.declared_size)
                except (EvtxDecodeError, IndexError):
                    pass
                records += 1
    return records, time.process_time() - started


def field_differences(left: dict, right: dict) -> list[str]:
    keys = list(left) + [key for key in right if key not in left]
    return [key for key in keys if left.get(key, "<missing>") != right.get(key, "<missing>")]


def rows_pass(path: Path, native_module, detail: str) -> dict[str, object]:
    """Interleave both row streams: per-engine time + row-by-row, field-by-field comparison."""
    options = {"record_detail": detail, "structure_rows": False}
    python_rows = iter(collect_native_evtx_events(path, **options))
    native_rows = iter(collect_native_evtx_events(path, native_decoder=native_module, **options))
    python_seconds = native_seconds = 0.0
    compared = events = 0
    differing_rows = 0
    examples: list[dict[str, object]] = []
    # Process CPU time: both engines run in this one thread, so other load on
    # the machine does not skew the comparison.
    clock = time.process_time
    while True:
        started = clock()
        expected = next(python_rows, None)
        middle = clock()
        actual = next(native_rows, None)
        python_seconds += middle - started
        native_seconds += clock() - middle
        if expected is None and actual is None:
            break
        compared += 1
        if expected is not None and expected.artifact_type == "eventlog-event":
            events += 1
        if expected != actual:
            differing_rows += 1
            if len(examples) < 5:
                left = dataclasses.asdict(expected) if expected is not None else {}
                right = dataclasses.asdict(actual) if actual is not None else {}
                examples.append({"row": compared - 1, "fields": field_differences(left.get("details", {}), right.get("details", {}))[:20]})
    return {
        "rows_compared": compared,
        "event_rows": events,
        "differing_rows": differing_rows,
        "difference_examples": examples,
        "python": {"cpu_seconds": round(python_seconds, 3), "records_per_second": round(events / python_seconds, 1)},
        "rust": {"cpu_seconds": round(native_seconds, 3), "records_per_second": round(events / native_seconds, 1)},
        "speedup": round(python_seconds / native_seconds, 2),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--records", type=int, default=500_000, help="live records to generate (default 500000)")
    parser.add_argument("--detail", choices=("triage", "full"), default="triage", help="row detail (pipeline default: triage)")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--workdir", type=Path, default=None, help="directory for the generated EVTX (default: temp dir)")
    parser.add_argument("--keep", action="store_true", help="keep the generated EVTX")
    parser.add_argument("--skip-rows", action="store_true", help="decoder layer only")
    parser.add_argument("--json", type=Path, default=None, help="also write the report here")
    args = parser.parse_args()

    native_module, reason = load_native_evtx_decoder()
    if native_module is None:
        print(f"rapidcore_native EVTX decoder unavailable: {reason}", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(dir=args.workdir) as tmp:
        path = Path(tmp) / "bench.evtx"
        started = time.perf_counter()
        write_mixed_evtx(path, args.records, seed=args.seed)
        generated = time.perf_counter() - started
        report: dict[str, object] = {
            "platform": f"{platform.system()} {platform.machine()} / Python {platform.python_version()}",
            "records": args.records,
            "file_bytes": path.stat().st_size,
            "chunks": (path.stat().st_size - EVTX_FILE_HEADER_SIZE) // EVTX_CHUNK_SIZE,
            "generate_seconds": round(generated, 1),
            "detail": args.detail,
        }
        python_records, python_seconds = decode_pass(path, EvtxChunkDecoder)
        native_records, native_seconds = decode_pass(
            path, lambda chunk: NativeEvtxChunkDecoder(native_module, chunk, render_xml=args.detail == "full")
        )
        report["decoder"] = {
            "records": python_records,
            "python": {"cpu_seconds": round(python_seconds, 3), "records_per_second": round(python_records / python_seconds, 1)},
            "rust": {"cpu_seconds": round(native_seconds, 3), "records_per_second": round(native_records / native_seconds, 1)},
            "speedup": round(python_seconds / native_seconds, 2),
        }
        if not args.skip_rows:
            report["rows"] = rows_pass(path, native_module, args.detail)
        if args.keep:
            kept = (args.workdir or Path.cwd()) / f"bench-{args.records}.evtx"
            path.replace(kept)
            report["kept_file"] = str(kept)
    text = json.dumps(report, ensure_ascii=False, indent=2)
    print(text)
    if args.json:
        args.json.write_text(text + "\n", encoding="utf-8")
    rows = report.get("rows")
    return 1 if isinstance(rows, dict) and rows["differing_rows"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
