"""Opt-in, ordered field-by-field parity checks on a known-count corpus.

evtx-scan tests the structural index only. evtx-full compares every complete
collector row (including chunk and candidate rows) to the worker's JSONL.
rows compares complete, unprojected JSONL exports from other stage runners.
Use the same logical source roots/paths for both JSONL exports. Pass expected
counts from the corpus manifest, independent of the two implementations.
For the large generated Application.evtx, run
  python tools/perf/stage_diff.py evtx-scan INPUT --worker BIN --expected 500025 --expected-slack 25
Both current structural scanners count 2525 slack records on that corpus.
Exit 0 means the selected parity and known-count checks passed, 1 indicates
a mismatch, and 2 indicates a run error (including unavailable native code).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from decimal import Decimal
from itertools import zip_longest
from pathlib import Path
from time import perf_counter

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

MISSING = object()


def unique_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate JSON key: {key}")
        obj[key] = value
    return obj


def reject_constant(value):
    raise ValueError(f"non-finite JSON number: {value}")


def load_json(data):
    return json.loads(
        data,
        parse_float=Decimal,
        object_pairs_hook=unique_keys,
        parse_constant=reject_constant,
    )


def read_rows(lines):
    for number, line in enumerate(lines, 1):
        obj = load_json(line)
        if not isinstance(obj, dict) or not obj:
            raise ValueError(f"expected nonempty row object at line {number}")
        yield obj


def first_difference(left, right, path="$"):
    """Return the first mismatching field per row, preserving JSON scalar types."""
    if type(left) is not type(right):
        return path
    if isinstance(left, dict):
        for key in left:
            field = f"{path}.{key}"
            if key not in right:
                return field
            mismatch = first_difference(left[key], right[key], field)
            if mismatch:
                return mismatch
        for key in right:
            if key not in left:
                return f"{path}.{key}"
    elif isinstance(left, list):
        for index, (left_item, right_item) in enumerate(
            zip_longest(left, right, fillvalue=MISSING)
        ):
            mismatch = first_difference(left_item, right_item, f"{path}[{index}]")
            if mismatch:
                return mismatch
    elif left != right:
        return path
    return None


def compare_rows(left, right, expected):
    counts = Counter()
    samples = []
    for index, (python_row, native_row) in enumerate(
        zip_longest(left, right, fillvalue=MISSING)
    ):
        counts["python_rows"] += python_row is not MISSING
        counts["native_rows"] += native_row is not MISSING
        mismatch = first_difference(python_row, native_row)
        if mismatch:
            counts["different_rows"] += 1
            if len(samples) < 10:
                samples.append({"index": index, "field": mismatch})
    return {
        "expected_rows": expected,
        "python_rows": counts["python_rows"],
        "native_rows": counts["native_rows"],
        "different_rows": counts["different_rows"],
        "examples": samples,
        "passed": (
            counts["python_rows"] == counts["native_rows"] == expected
            and counts["different_rows"] == 0
        ),
    }


def scan(args):
    from rapidtriage.core.native_accel import _scan_evtx_python

    limit = args.expected + 1
    start = perf_counter()
    reference = _scan_evtx_python(args.input, limit)
    python_seconds = perf_counter() - start
    start = perf_counter()
    output = subprocess.check_output(
        [
            str(args.worker.resolve()),
            "evtx-scan",
            str(args.input),
            "--max-records",
            str(limit),
        ]
    )
    # Include the ordinary native bridge's subprocess, transfer and JSON decode.
    candidate = json.loads(output)
    native_seconds = perf_counter() - start
    # Reject duplicate JSON keys and nonfinite numbers outside the timed bridge.
    del candidate
    candidate = load_json(output)
    del output
    allocation = Counter(row["allocation_status"] for row in reference["records"])
    expected_slack = args.expected_slack
    records = compare_rows(
        reference.pop("records"), candidate.pop("records"), args.expected
    )
    metadata_diff = first_difference(reference, candidate)
    return {
        "scope": "evtx-structural-index",
        "python_wall_s": python_seconds,
        "worker_wall_s": native_seconds,
        "chunks": len(reference["chunks"]),
        "metadata_difference": metadata_diff,
        "truncated": reference["truncated"] or candidate["truncated"],
        "allocation_counts": dict(allocation),
        "expected_slack": expected_slack,
        **records,
        "passed": bool(
            records["passed"]
            and metadata_diff is None
            and reference["chunks"]
            and reference["file_header"]["signature_valid"]
            and not reference["truncated"]
            and (expected_slack is None or allocation["slack"] == expected_slack)
        ),
    }


def full(args):
    from rapidtriage.artifacts.windows.eventlog import collect_native_evtx_events
    from rapidtriage.core.json_safe import json_default

    reference = collect_native_evtx_events(
        args.input, structure_rows=True, record_detail="full"
    )
    # Compare the JSON representation a consumer sees, including complete
    # source provenance, hashes, recovery flags, precision and citation manifests.
    rows = (
        load_json(json.dumps(row.to_dict(), default=json_default)) for row in reference
    )
    command = [
        str(args.worker.resolve()),
        "parse",
        "--kind",
        "evtx-records",
        "--source",
        str(args.input),
        "--max-records",
        str(args.expected + 1),
    ]
    with subprocess.Popen(command, stdout=subprocess.PIPE) as process:
        try:
            result = compare_rows(rows, read_rows(process.stdout), args.expected)
        except BaseException:
            process.kill()
            raise
        finally:
            process.stdout.close()
        status = process.wait()
        if status:
            raise subprocess.CalledProcessError(status, command)
    return {"scope": "evtx-full-collector", **result}


def positive(value):
    result = int(value)
    if result <= 0:
        raise argparse.ArgumentTypeError("expected a positive known-answer row count")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    stages = parser.add_subparsers(dest="stage", required=True)
    for name in ("evtx-scan", "evtx-full", "rows"):
        stage = stages.add_parser(name)
        stage.add_argument(
            "--expected",
            required=True,
            type=positive,
            help="known record count (evtx-scan) or total emitted rows",
        )
        if name == "evtx-scan":
            stage.add_argument(
                "--expected-slack",
                type=int,
                help="also check slack classification against the corpus manifest",
            )
        if name == "rows":
            stage.add_argument("python_jsonl", type=Path)
            stage.add_argument("native_jsonl", type=Path)
        else:
            stage.add_argument("input", type=Path)
            stage.add_argument(
                "--worker", type=Path, required=True, help="release rapid-worker"
            )
    args = parser.parse_args()
    try:
        if args.stage == "evtx-scan":
            result = scan(args)
        elif args.stage == "evtx-full":
            result = full(args)
        else:
            if args.python_jsonl.samefile(args.native_jsonl):
                raise ValueError("provide independent Python and native exports")
            with (
                args.python_jsonl.open("rb") as left,
                args.native_jsonl.open("rb") as right,
            ):
                result = {
                    "scope": "supplied-jsonl",
                    **compare_rows(read_rows(left), read_rows(right), args.expected),
                }
    except (
        ValueError,
        OSError,
        subprocess.SubprocessError,
        KeyError,
        TypeError,
    ) as error:
        parser.exit(2, f"stage failed: {error}\n")
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
