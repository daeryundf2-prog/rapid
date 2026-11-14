#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
# --- How to run ---
#   python scripts/collector-profile.py --root <extracted-tree> --run-dir <run-output-dir> \
#       --output-dir <temp-folder> [--top 12] [--also kind,kind] [--timeout 3600] [--json]
#   python scripts/collector-profile.py --root <tree> --kinds browser,email --output-dir <dir>
#
# Collector profile (R8 T-197, GAP-275/274/285): runs each collector of a finished run
# separately on its extracted evidence tree and splits the time into
#   traversal -- directory walking and per-path handling (pathlib/os/glob frames and
#                core.files.iter_evidence_paths),
#   read      -- file opens, reads and hashing (io / os / hashlib frames),
#   parse     -- every other frame (collector and parser code, json/struct/re/sqlite ...),
#   output    -- rapidtriage.core.artifacts and the artifact record/profile modules
#                (envelope, JSONL streaming).
# The collector code is not touched: the profile is a cProfile run of
# ``run_artifact_collection`` (provider consumed in the profiled thread) grouped by frame
# module, plus counters from wrappers installed at run time (evidence path walks, files
# opened, bytes of the files opened) and an audit hook that BLOCKS every write to the
# evidence root (the input stays read-only). Each collector runs in its own child process;
# the child writes only below --output-dir. The top-N collectors come from the run's
# ``rapidtriage-run-progress.json`` (``providers.<kind>.duration_ms``).
# Reports carry counts, collector names and seconds only; no paths or file contents.
# Engineering measurement; cProfile inflates absolute times (see ``profile_overhead_note``).
# ------------------
from __future__ import annotations

import sys as _sys

if hasattr(_sys.stdout, "reconfigure"):
    _sys.stdout.reconfigure(encoding="utf-8")
if hasattr(_sys.stderr, "reconfigure"):
    _sys.stderr.reconfigure(encoding="utf-8")

import _thread
import argparse
import cProfile
import json
import os
import pstats
import re
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

BUCKETS = ("traversal", "read", "parse", "output")
BIG_FILE_BYTES = 8 * 1024 * 1024
PROFILE_OVERHEAD_NOTE = (
    "cProfile inflates call-heavy code (parse/traversal) more than I/O; compare the bucket shares, "
    "not the absolute seconds, with the run's own duration_ms."
)

_TRAVERSAL_FILES = ("pathlib", "ntpath", "posixpath", "genericpath", "glob.py", "fnmatch.py", "os.py", "stat.py")
_TRAVERSAL_BUILTINS = ("scandir", "listdir", "stat", "lstat", "walk", "fspath", "_path_", "_getfinalpathname", "_findfirstfile", "readlink", "realpath", "abspath", "getfullpathname", "access")
_READ_PATH_FUNCS = {"read_bytes", "read_text", "open"}
_READ_BUILTIN_HINTS = ("_io.", "io.open", "nt.open", "posix.open", "nt.read", "posix.read", "_hashlib", "_md5", "_sha", "_blake2", "mmap", "zlib.decompress", "_lzma", "_bz2", "FileIO", "readinto", "'read'", "'readline'", "'readlines'", "'seek'", "'close'", "'readall'")
_OUTPUT_MODULE_HINTS = (
    "rapidtriage/core/artifacts.py",
    "rapidtriage/core/artifact_",
    "rapidtriage/core/run/",
)
_OUTPUT_FUNC_HINTS = ("_shallow_row", "adapt_artifact_row", "StreamingProfileBuilder", "StreamingArtifactAnnotator")
_COUNTERS: dict[str, Any] = {}
_GUARD: dict[str, Any] = {"active": False, "root": "", "blocked": 0, "sqlite_in_root": 0}


# ---------------------------------------------------------------- classification

def classify_frame(filename: str, funcname: str) -> str:
    """Bucket of one cProfile frame (exclusive time)."""
    name = filename.replace("\\", "/")
    low = name.lower()
    func = funcname
    if name == "~":  # builtin / C function: funcname looks like "<built-in method nt.scandir>"
        text = funcname.lower()
        if any(hint.lower() in text for hint in _READ_BUILTIN_HINTS):
            return "read"
        if any(hint in text for hint in _TRAVERSAL_BUILTINS):
            return "traversal"
        return "parse"
    if low.endswith(("/pathlib.py", "/pathlib/__init__.py", "/pathlib/_local.py", "/pathlib/_abc.py")) or "/pathlib/" in low:
        return "read" if func in _READ_PATH_FUNCS else "traversal"
    if low.endswith(tuple("/" + t for t in _TRAVERSAL_FILES)) and "/site-packages/" not in low:
        return "traversal"
    if low.endswith("/rapidtriage/core/files.py") and func in {
        "iter_evidence_paths",
        "_walk_evidence_paths",
        "_relative_has_tool_output_dir",
        "_cached_evidence_paths",
        "_evidence_pattern_is_cacheable",
        "_evidence_cache_key",
    }:
        return "traversal"
    if low.endswith(("/_pyio.py", "/zipfile.py", "/zipfile/__init__.py")) and func.startswith(("read", "readinto", "open")):
        return "read"
    if any(hint in low for hint in _OUTPUT_MODULE_HINTS) or func in _OUTPUT_FUNC_HINTS:
        return "output"
    return "parse"


def bucket_stats(stats: Mapping[tuple[str, int, str], tuple]) -> tuple[dict[str, float], list[dict[str, Any]]]:
    """Sum exclusive time per bucket and list the heaviest frames (module + function only)."""
    seconds = dict.fromkeys(BUCKETS, 0.0)
    frames: list[tuple[float, str, str, str]] = []
    for (filename, _line, func), values in stats.items():
        tottime = float(values[2])
        bucket = classify_frame(filename, func)
        seconds[bucket] += tottime
        frames.append((tottime, bucket, _module_label(filename), func))
    frames.sort(reverse=True)
    top = [
        {"bucket": bucket, "frame": f"{module}:{func}", "seconds": round(tottime, 3)}
        for tottime, bucket, module, func in frames[:8]
    ]
    return seconds, top


def _module_label(filename: str) -> str:
    if filename == "~":
        return "builtin"
    name = filename.replace("\\", "/")
    if "/rapidtriage/" in name:
        return "rapidtriage/" + name.split("/rapidtriage/", 1)[1]
    return name.rsplit("/", 1)[-1]


def classify_cause(buckets: Mapping[str, float], *, wall: float, opened: Mapping[str, Any] | None = None) -> str:
    """Cause label for the GAP-275 table: traversal / big-file scan / parse / other."""
    total = sum(buckets.get(b, 0.0) for b in BUCKETS)
    if total <= 0 or wall < 1.0:
        return "기타"
    shares = {b: buckets.get(b, 0.0) / total for b in BUCKETS}
    if shares["traversal"] >= 0.5:
        return "전체 순회"
    if shares["read"] >= 0.5:
        return "대용량 훑기"
    if shares["parse"] >= 0.5:
        return "파싱"
    return "기타"


# ---------------------------------------------------------------- run discovery

def top_collectors(run_dir: Path, count: int) -> list[tuple[str, float]]:
    """(kind, run seconds) of the slowest ``count`` collectors from the run progress file."""
    progress = json.loads((run_dir / "rapidtriage-run-progress.json").read_text(encoding="utf-8"))
    providers = progress.get("providers")
    if not isinstance(providers, Mapping):
        raise SystemExit("run progress has no providers table")
    rows = [
        (str(kind), float(info.get("duration_ms") or 0) / 1000.0)
        for kind, info in providers.items()
        if isinstance(info, Mapping)
    ]
    rows.sort(key=lambda row: (-row[1], row[0]))
    return rows[:count]


def run_seconds(run_dir: Path) -> dict[str, float]:
    return dict(top_collectors(run_dir, 10_000))


def tree_stats(root: Path) -> dict[str, int]:
    """File / directory counts and total bytes below ``root`` (one scandir walk, read-only)."""
    files = dirs = size = 0
    stack = [str(root)]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            dirs += 1
                            stack.append(entry.path)
                        else:
                            files += 1
                            size += entry.stat(follow_symlinks=False).st_size
                    except OSError:
                        continue
        except OSError:
            continue
    return {"files": files, "dirs": dirs, "bytes": size}


# ---------------------------------------------------------------- worker side

def _under_root(path: str) -> bool:
    root = _GUARD["root"]
    if not root:
        return False
    try:
        norm = os.path.normcase(os.path.abspath(path))
    except (TypeError, ValueError):
        return False
    return norm == root or norm.startswith(root + os.sep)


def _audit(event: str, args: tuple) -> None:
    if not _GUARD["active"]:
        return
    if event == "open":
        path, mode, flags = args[0], args[1], args[2]
        if not isinstance(path, (str, bytes, os.PathLike)):
            return
        text = os.fsdecode(path)
        writing = (
            (isinstance(mode, str) and any(ch in mode for ch in "wax+"))
            or (isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC))
        )
        if writing:
            if _under_root(text):
                _GUARD["blocked"] += 1
                raise PermissionError("write to the evidence root blocked by collector-profile")
            return
        if _under_root(text):
            counters = _COUNTERS
            counters["files_opened"] += 1
            key = hash(text)
            if key not in counters["_seen"]:
                counters["_seen"].add(key)
                try:
                    size = os.stat(text).st_size
                except OSError:
                    size = 0
                counters["unique_files_opened"] += 1
                counters["bytes_of_files_opened"] += size
                if size >= BIG_FILE_BYTES:
                    counters["big_files_opened"] += 1
                    counters["bytes_of_big_files_opened"] += size
    elif event in {"os.remove", "os.rmdir", "os.mkdir", "os.rename", "os.truncate", "shutil.rmtree", "shutil.move", "os.chmod", "os.utime"}:
        for item in args[:2]:
            if isinstance(item, (str, bytes, os.PathLike)) and _under_root(os.fsdecode(item)):
                _GUARD["blocked"] += 1
                raise PermissionError("modification of the evidence root blocked by collector-profile")
    elif event == "sqlite3.connect":
        target = args[0] if args else None
        if isinstance(target, (str, bytes, os.PathLike)) and _under_root(os.fsdecode(target)):
            _GUARD["sqlite_in_root"] += 1


def _patch_walk_counters() -> int:
    """Wrap ``iter_evidence_paths`` wherever it was imported; returns the number of wrapped names."""
    from rapidtriage.core import files as files_module

    original = files_module.iter_evidence_paths

    def counted(root: Path, pattern: str = "*") -> Iterator[Path]:
        _COUNTERS["walk_calls"] += 1
        started = time.perf_counter()
        entries = 0
        iterator = iter(original(root, pattern))
        try:
            while True:
                tick = time.perf_counter()
                try:
                    item = next(iterator)
                except StopIteration:
                    _COUNTERS["walk_seconds"] += time.perf_counter() - tick
                    break
                _COUNTERS["walk_seconds"] += time.perf_counter() - tick
                entries += 1
                yield item
        finally:
            _COUNTERS["walk_entries"] += entries
            _ = started

    wrapped = 0
    for name, module in list(sys.modules.items()):
        if module is None or not name.startswith("rapidtriage"):
            continue
        if getattr(module, "iter_evidence_paths", None) is original:
            module.iter_evidence_paths = counted  # type: ignore[attr-defined]
            wrapped += 1
    return wrapped


def _sanitize(text: str, root: Path) -> str:
    text = str(text)
    for variant in {str(root), str(root).replace("\\", "/")}:
        text = re.sub(re.escape(variant) + r"[^\s'\"]*", "<path>", text)
    text = re.sub(r"[A-Za-z]:[\\/][^\s'\"]*", "<path>", text)
    text = re.sub(r"(?<![\w.])/(?:[\w.\-]+/)+[\w.\-]*", "<path>", text)
    return text[:160]


def profile_collector(
    kind: str, root: Path, out_dir: Path, *, path_cache: bool = False, plain: bool = False, budget: float = 0.0
) -> dict[str, Any]:
    """Run one collector (child process body) and return its measurement row."""
    from rapidtriage.artifacts import get_artifact_collector
    from rapidtriage.core import files as files_module
    from rapidtriage.core.artifacts import run_artifact_collection
    from rapidtriage.core.input_root import InputRoot

    get_artifact_collector(kind)  # imports the collector modules before the walk wrapper is installed
    _COUNTERS.clear()
    _COUNTERS.update(
        walk_calls=0, walk_entries=0, walk_seconds=0.0, files_opened=0, unique_files_opened=0,
        bytes_of_files_opened=0, big_files_opened=0, bytes_of_big_files_opened=0, _seen=set(),
    )
    wrapped = _patch_walk_counters()
    _GUARD.update(active=True, root=os.path.normcase(os.path.abspath(str(root))), blocked=0, sqlite_in_root=0)
    sys.addaudithook(_audit)
    if path_cache:
        files_module.enable_evidence_path_cache()
    input_root = InputRoot(source_path="IMG-B", root_path=root, kind="directory")
    records = out_dir / f"{kind}.jsonl"
    profiler = None if plain else cProfile.Profile()
    started = time.perf_counter()
    error = None
    payload: dict[str, Any] = {}
    timer = None
    if budget > 0:
        # Past the budget the main thread gets a KeyboardInterrupt: the profile so far is kept.
        timer = threading.Timer(budget, _thread.interrupt_main)
        timer.daemon = True
        timer.start()
    try:
        if profiler is not None:
            profiler.enable()
        try:
            payload = run_artifact_collection(input_root, kind=kind, records_path=records, use_cache=False)
        finally:
            if profiler is not None:
                profiler.disable()
    except KeyboardInterrupt:
        error = f"budget of {int(budget)} s exceeded: partial profile"
    except Exception as exc:
        error = f"{type(exc).__name__}: {_sanitize(str(exc), root)}"
    if timer is not None:
        timer.cancel()
    wall = time.perf_counter() - started
    _GUARD["active"] = False
    if path_cache:
        files_module.disable_evidence_path_cache()

    summary = payload.get("summary") if isinstance(payload.get("summary"), Mapping) else {}
    errors = payload.get("parser_errors") if isinstance(payload.get("parser_errors"), list) else []
    row: dict[str, Any] = {
        "kind": kind,
        "mode": "plain" if plain else "cProfile",
        "path_cache": bool(path_cache),
        "wall_s": round(wall, 2),
        "error": error,
        "partial_by_budget": bool(error and error.startswith("budget")),
        "artifact_count": int(summary.get("artifact_count") or 0),
        "collection_status": summary.get("collection_status"),
        "parser_error_count": int(summary.get("parser_error_count") or 0),
        "parser_errors": [
            {
                "error_type": str(item.get("error_type", ""))[:80],
                "message": _sanitize(str(item.get("message", "")), root),
                "collector": str(item.get("collector", ""))[:80],
            }
            for item in errors[:5]
            if isinstance(item, Mapping)
        ],
        "walk_calls": _COUNTERS["walk_calls"],
        "walk_entries": _COUNTERS["walk_entries"],
        "walk_seconds": round(_COUNTERS["walk_seconds"], 2),
        "walk_wrappers_installed": wrapped,
        "files_opened": _COUNTERS["files_opened"],
        "unique_files_opened": _COUNTERS["unique_files_opened"],
        "bytes_of_files_opened": _COUNTERS["bytes_of_files_opened"],
        "big_files_opened": _COUNTERS["big_files_opened"],
        "bytes_of_big_files_opened": _COUNTERS["bytes_of_big_files_opened"],
        "output_bytes": records.stat().st_size if records.exists() else 0,
        "writes_blocked": _GUARD["blocked"],
        "sqlite_connects_in_root": _GUARD["sqlite_in_root"],
    }
    if profiler is not None:
        profiler.create_stats()
        seconds, top = bucket_stats(pstats.Stats(profiler).stats)  # type: ignore[arg-type]
        profiled = sum(seconds.values())
        row["profiled_s"] = round(profiled, 4)
        row["profiled_share_of_wall"] = round(profiled / wall, 3) if wall > 0 else 0.0
        row["buckets_s"] = {bucket: round(value, 2) for bucket, value in seconds.items()}
        row["bucket_share"] = {bucket: round(value / profiled, 3) if profiled > 0 else 0.0 for bucket, value in seconds.items()}
        row["top_frames"] = top
        row["cause"] = classify_cause(seconds, wall=wall)
    return row


def worker_main(args: argparse.Namespace) -> int:
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    row = profile_collector(args.worker, Path(args.root), out_dir, path_cache=args.path_cache, plain=args.plain, budget=args.budget)
    Path(args.result).write_text(json.dumps(row, ensure_ascii=False), encoding="utf-8")
    return 0


# ---------------------------------------------------------------- parent side

def run_child(kind: str, root: Path, out_dir: Path, *, timeout: float, path_cache: bool, plain: bool, budget: float = 0.0) -> dict[str, Any]:
    work = out_dir / kind
    work.mkdir(parents=True, exist_ok=True)
    tmp = work / "tmp"
    tmp.mkdir(exist_ok=True)
    result = work / "result.json"
    result.unlink(missing_ok=True)
    command = [
        sys.executable, "-X", "utf8", str(Path(__file__).resolve()), "--worker", kind, "--root", str(root),
        "--output-dir", str(work), "--result", str(result),
    ]
    if path_cache:
        command.append("--path-cache")
    if plain:
        command.append("--plain")
    if budget > 0:
        command.extend(["--budget", str(budget)])
    env = dict(os.environ, TMP=str(tmp), TEMP=str(tmp), TMPDIR=str(tmp), RAPIDTRIAGE_NO_BROWSER="1", PYTHONIOENCODING="utf-8")
    started = time.perf_counter()
    try:
        completed = subprocess.run(command, env=env, timeout=timeout, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
        if completed.returncode != 0 or not result.exists():
            row = {"kind": kind, "error": f"worker exit {completed.returncode}: {_sanitize(completed.stderr[-300:], root)}"}
        else:
            row = json.loads(result.read_text(encoding="utf-8"))
    except subprocess.TimeoutExpired:
        row = {"kind": kind, "error": f"timeout after {int(timeout)} s", "wall_s": round(time.perf_counter() - started, 2)}
    shutil.rmtree(work, ignore_errors=True)
    return row


def build_report(rows: list[dict[str, Any]], run_secs: Mapping[str, float], tree: Mapping[str, Any] | None) -> dict[str, Any]:
    for row in rows:
        row["run_s"] = round(run_secs.get(row["kind"], 0.0), 1)
    return {
        "tool": "collector-profile",
        "profile_overhead_note": PROFILE_OVERHEAD_NOTE,
        "tree": dict(tree or {}),
        "collectors": rows,
    }


def markdown_table(report: Mapping[str, Any]) -> str:
    lines = [
        "| 수집기 | 런 s | 단독 s | 순회 s | 읽기 s | 파싱 s | 출력 s | 행 | 전체순회 호출/항목 | 연 파일/대용량 | 원인 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---|---|---|",
    ]
    for row in report["collectors"]:
        if row.get("error") and "walk_calls" not in row:
            lines.append(f"| {row['kind']} | {row.get('run_s', '')} | {row.get('wall_s', '')} | - | - | - | - | - | - | - | 실패: {row['error'][:60]} |")
            continue
        b = row.get("buckets_s") or dict.fromkeys(BUCKETS, "-")  # --plain rows carry no split
        cause = str(row.get("cause", "")) + (" (부분)" if row.get("partial_by_budget") else "")
        lines.append(
            f"| {row['kind']} | {row.get('run_s', '')} | {row['wall_s']} | {b['traversal']} | {b['read']} | {b['parse']} | {b['output']} "
            f"| {row['artifact_count']} | {row['walk_calls']}/{row['walk_entries']} "
            f"| {row['unique_files_opened']}/{row['big_files_opened']} | {cause} |"
        )
    return "\n".join(lines) + "\n"


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Per-collector time split (traversal / read / parse) on an extracted tree.")
    parser.add_argument("--root", help="extracted evidence tree (read-only input)")
    parser.add_argument("--run-dir", help="finished run output dir (reads rapidtriage-run-progress.json for the ranking)")
    parser.add_argument("--output-dir", help="temp folder for collector outputs and the report (never inside --root)")
    parser.add_argument("--top", type=int, default=12, help="number of slowest collectors by run time (default 12)")
    parser.add_argument("--also", default="", help="extra collector kinds to profile, comma separated")
    parser.add_argument("--kinds", default="", help="explicit collector kinds (skips the run ranking)")
    parser.add_argument("--timeout", type=float, default=3600.0, help="per collector seconds (default 3600)")
    parser.add_argument("--budget", type=float, default=0.0, help="per collector seconds before the profile is cut and reported as partial (0 = none; keep below --timeout)")
    parser.add_argument("--path-cache", action="store_true", help="enable the run-scoped evidence path cache like a real run (default off = isolated cost)")
    parser.add_argument("--plain", action="store_true", help="no cProfile: wall time and counters only")
    parser.add_argument("--no-tree-stats", action="store_true", help="skip the before/after tree integrity walk")
    parser.add_argument("--json", action="store_true", help="print the report JSON on stdout")
    parser.add_argument("--json-out", help="also write the report JSON here")
    parser.add_argument("--markdown", help="also write the table as markdown here")
    parser.add_argument("--worker", help=argparse.SUPPRESS)
    parser.add_argument("--result", help=argparse.SUPPRESS)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.worker:
        return worker_main(args)
    if not args.root or not args.output_dir:
        print("--root and --output-dir are required", file=sys.stderr)
        return 2
    root = Path(args.root).resolve()
    out_dir = Path(args.output_dir).resolve()
    if not root.is_dir():
        print("--root is not a directory", file=sys.stderr)
        return 2
    if out_dir == root or root in out_dir.parents:
        print("--output-dir must not be inside the evidence root", file=sys.stderr)
        return 2
    out_dir.mkdir(parents=True, exist_ok=True)

    ranking: dict[str, float] = {}
    if args.run_dir:
        ranking = run_seconds(Path(args.run_dir))
    kinds: list[str]
    if args.kinds:
        kinds = [item.strip() for item in args.kinds.split(",") if item.strip()]
    elif args.run_dir:
        kinds = [kind for kind, _ in top_collectors(Path(args.run_dir), args.top)]
    else:
        print("give --run-dir (ranking) or --kinds", file=sys.stderr)
        return 2
    for extra in (item.strip() for item in args.also.split(",")):
        if extra and extra not in kinds:
            kinds.append(extra)

    before = None if args.no_tree_stats else tree_stats(root)
    rows: list[dict[str, Any]] = []
    for kind in kinds:
        print(f"[collector-profile] {kind} ...", file=sys.stderr, flush=True)
        row = run_child(kind, root, out_dir, timeout=args.timeout, path_cache=args.path_cache, plain=args.plain, budget=args.budget)
        print(f"[collector-profile] {kind} done: {row.get('wall_s')} s {('ERR ' + row['error'][:80]) if row.get('error') else ''}", file=sys.stderr, flush=True)
        rows.append(row)
    tree: dict[str, Any] = {}
    if before is not None:
        after = tree_stats(root)
        tree = {"before": before, "after": after, "unchanged": before == after}
    report = build_report(rows, ranking, tree)
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    if args.markdown:
        Path(args.markdown).write_text(markdown_table(report), encoding="utf-8")
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(markdown_table(report))
        if tree:
            print(f"tree unchanged: {tree['unchanged']} ({tree['before']['files']} files)")
    return 0 if all(not row.get("error") for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
