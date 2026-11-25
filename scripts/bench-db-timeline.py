"""Generate synthetic run outputs and measure one production stage per process.

Run generate, timeline and persist in that order with the same directory.
Repeat the last two commands in fresh processes for independent RSS peaks.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rapidtriage.core.run.persist import build_run_case_db
from rapidtriage.core.timeline import (
    build_timeline_report,
    run_timeline,
    write_timeline_result,
)


def generate(directory: Path, records: int) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    file_count = min(256, records)
    paths = [f"synthetic/자료/{i}.bin" for i in range(file_count)]
    files = [{"path": path, "size": i + 1, "extension": ".bin"} for i, path in enumerate(paths)]
    for name, candidates in (("files", files), ("docs", [])):
        (directory / f"{name}.json").write_text(json.dumps({"command": name, "candidates": candidates}), encoding="utf-8")
    with (directory / "rows.jsonl").open("w", encoding="utf-8") as stream:
        for i in range(records):
            # Pairs tie exactly; nearby pairs differ below microsecond resolution.
            stamp = f"2024-01-01T01:{i // 120 % 60:02}:{i // 2 % 60:02}.{i // 7200 % 10000000:07}Z"
            details = {"record_id": i + 1, "timestamp": stamp, "entry_name": f"항목{i}\0끝"}
            if i % 4096 == 0:
                details["entry_name"] += "가" * 8192
            artifact_type = "eventlog-event" if i % 3 else "usn-record"
            details["record_state"] = i % 2
            row = {
                "artifact_type": artifact_type, "path": paths[(i // 2) % file_count], "details": details,
                "profile_ref": artifact_type, "context_ref": True,
            }
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")
    # The normal run persists compact JSONL. The two views used by the case
    # index both need the per-file context and the decoded status label.
    contexts = {
        path: {"details": {"source_context": {"path": path, "format": "synthetic"}},
               "artifact_record": {"source": {"path": path, "stream": "generated"}}}
        for path in paths
    }
    profile = {
        "contexts": contexts, "codes": {"record_state": ["allocated", "recovered"]},
        "details": {"parser": "synthetic", "parser_version": "1"},
    }
    head = {
        "command": "artifacts", "kind": "synthetic", "records_file": "rows.jsonl", "record_count": records,
        "artifact_type_profiles": dict.fromkeys(("eventlog-event", "usn-record"), profile),
    }
    (directory / "artifacts.json").write_text(json.dumps(head), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=["generate", "timeline", "persist"])
    parser.add_argument("directory", type=Path, help="dedicated scratch run directory")
    parser.add_argument("--records", type=int, default=100000)
    args = parser.parse_args()
    directory = args.directory.resolve()
    if args.stage != "generate" and sys.platform == "win32":
        parser.error("peak RSS measurement requires a POSIX host")
    if args.stage == "generate":
        if directory.exists() and any(directory.iterdir()):
            parser.error("generate requires an empty directory")
        if args.records <= 0:
            parser.error("--records must be positive")
        generate(directory, args.records)
        return
    outputs = {name: directory / f"{name}.json" for name in ("docs", "files", "timeline")}
    outputs["artifacts_synthetic"] = directory / "artifacts.json"
    head = outputs["artifacts_synthetic"]
    if not head.is_file() or json.loads(head.read_text(encoding="utf-8")).get("kind") != "synthetic":
        parser.error("use a dedicated run directory created by the generate command")
    started = time.perf_counter()
    cpu_started = time.process_time()
    if args.stage == "timeline":
        result = run_timeline(
            root=directory, files_inputs=[outputs["files"]], docs_inputs=[outputs["docs"]],
            artifacts_inputs=[outputs["artifacts_synthetic"]], reference_time=dt.datetime(2025, 1, 1, tzinfo=dt.timezone.utc),
        )
        write_timeline_result(result, outputs["timeline"])
        (directory / "timeline.md").write_text(build_timeline_report(result), encoding="utf-8")
        counts = result["summary"]["event_count"]
    else:
        result = build_run_case_db(directory, outputs, root=str(directory))
        if result["status"] != "completed":
            raise RuntimeError(result)
        counts = result["counts"]
    elapsed = time.perf_counter() - started
    cpu_seconds = time.process_time() - cpu_started
    import resource  # POSIX benchmark hosts

    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    peak_mib = rss / (2**20 if sys.platform == "darwin" else 1024)
    print(json.dumps({"stage": args.stage, "seconds": elapsed, "cpu_seconds": cpu_seconds, "peak_mib": peak_mib, "rows": counts}))


if __name__ == "__main__":
    main()
