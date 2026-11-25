"""Compare BinXML decoding to the same six output fields on the generated corpus."""

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from rapidtriage.artifacts.windows import eventlog


def python_events(path):
    with path.open("rb") as stream:
        stream.seek(eventlog.EVTX_FILE_HEADER_SIZE)
        while chunk := stream.read(eventlog.EVTX_CHUNK_SIZE):
            decoder = eventlog.EvtxChunkDecoder(chunk)
            for slot in eventlog.iter_evtx_chunk_record_slots(chunk, active=True):
                row = decoder.decode_record(slot.relative_offset, slot.declared_size)
                system = row["system_fields"]
                yield (
                    int(system["EventRecordID"]),
                    int(system["EventID"]),
                    system["ProviderName"],
                    system["Channel"],
                    system["TimeCreated"],
                    row["event_data"]["Phase"],
                )


def rust_events(path, executable):
    command = [
        executable,
        "--recover-records",
        "--validate-checksums",
        "--stop-after-one-error",
        "-t",
        "1",
        "-o",
        "jsonl",
        path,
    ]
    with subprocess.Popen(command, stdout=subprocess.PIPE) as worker:
        try:
            for line in worker.stdout:
                event = json.loads(line)["Event"]
                system = event["System"]
                yield (
                    system["EventRecordID"],
                    system["EventID"],
                    system["Provider"]["#attributes"]["Name"],
                    system["Channel"],
                    system["TimeCreated"]["#attributes"]["SystemTime"],
                    event["EventData"]["Phase"],
                )
        finally:
            worker.stdout.close()
        if worker.wait():
            raise subprocess.CalledProcessError(worker.returncode, command)


def measure(rows):
    start = time.perf_counter()
    digest = hashlib.sha256()
    count = 0
    for row in rows:
        digest.update((json.dumps(row, separators=(",", ":")) + "\n").encode())
        count += 1
    return {
        "rows": count,
        "sha256": digest.hexdigest(),
        "wall_s": time.perf_counter() - start,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "input", type=Path, help="Application.evtx produced by make_corpus.py"
    )
    parser.add_argument("--evtx-dump", default="evtx_dump", help="evtx 0.15.1 CLI")
    parser.add_argument(
        "--expected",
        required=True,
        type=int,
        help="generated live and slack event count",
    )
    args = parser.parse_args()
    if args.expected < 1:
        parser.error("expected count must be positive")
    native = measure(rust_events(args.input, args.evtx_dump))
    reference = measure(python_events(args.input))
    equal = (
        reference["rows"] == native["rows"] == args.expected
        and reference["sha256"] == native["sha256"]
    )
    print(
        json.dumps(
            {
                "scope": "six synthetic event fields",
                "python": reference,
                "rust": native,
                "equal": equal,
            }
        )
    )
    return 0 if equal else 1


if __name__ == "__main__":
    sys.exit(main())
