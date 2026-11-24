"""Time the default folder triage CLI on Unix. Use --profile on a separate run."""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path


def profiled_cli(profile_path, cli_args):
    # A plain cProfile invocation misses the CLI and provider worker threads.
    import yappi

    from rapidtriage.cli import main

    yappi.set_clock_type("cpu")
    yappi.start(profile_threads=True)
    try:
        return main(cli_args)
    finally:
        yappi.stop()
        yappi.get_func_stats().save(profile_path, type="pstat")


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path, help="fresh directory outside the source")
    parser.add_argument(
        "--mode", choices=["fraud", "hacking", "seizure", "recovery"], default="fraud"
    )
    parser.add_argument(
        "--profile",
        action="store_true",
        help="write thread CPU times to threads.pstats (requires yappi)",
    )
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    if not source.is_dir() or output.is_relative_to(source):
        parser.error("supply a source directory and a separate output directory")
    output.mkdir(parents=True, exist_ok=False)
    cli_args = [
        "run",
        str(source),
        "--mode",
        args.mode,
        "--read-only",
        "--output-dir",
        str(output),
    ]
    command = [sys.executable, "-m", "rapidtriage", *cli_args]
    if args.profile:
        command = [
            sys.executable,
            __file__,
            "_profile",
            str(output / "threads.pstats"),
            *cli_args,
        ]
    start = time.perf_counter()
    with subprocess.Popen(command) as process:
        _, status, usage = os.wait4(process.pid, 0)
        process.returncode = os.waitstatus_to_exitcode(status)
    metrics = {
        "wall_s": time.perf_counter() - start,
        "user_s": usage.ru_utime,
        "system_s": usage.ru_stime,
        "peak_rss_bytes": usage.ru_maxrss
        if sys.platform == "darwin"
        else usage.ru_maxrss * 1024,
        "exit_code": process.returncode,
        "profiled": args.profile,
    }
    (output / "perf.json").write_text(
        json.dumps(metrics, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(metrics))
    return process.returncode


if __name__ == "__main__":
    if sys.argv[1:2] == ["_profile"]:
        sys.exit(profiled_cli(sys.argv[2], sys.argv[3:]))
    sys.exit(run())
