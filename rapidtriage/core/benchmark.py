from __future__ import annotations

import datetime as dt
import json
import statistics
import time
import tracemalloc
from pathlib import Path
from typing import Mapping

from .docs import write_result
from .run import run_triage_mode
from .search import run_unified_search


DEFAULT_BENCHMARK_FILE_COUNT = 100
DEFAULT_BENCHMARK_KEYWORD = "password"


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def run_benchmark(
    *,
    output_dir: Path,
    root: Path | None = None,
    file_count: int = DEFAULT_BENCHMARK_FILE_COUNT,
    keyword: str = DEFAULT_BENCHMARK_KEYWORD,
    mode: str = "fraud",
    search_iterations: int = 3,
    overwrite: bool = False,
) -> dict[str, object]:
    output_dir = output_dir.expanduser().resolve()
    if output_dir.exists() and any(output_dir.iterdir()) and not overwrite:
        raise BenchmarkError(f"benchmark output directory is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    evidence_root = root.expanduser().resolve() if root is not None else output_dir / "synthetic-evidence"
    if root is None:
        build_synthetic_benchmark_case(evidence_root, file_count=file_count, keyword=keyword, overwrite=overwrite)
    elif not evidence_root.is_dir():
        raise BenchmarkError(f"benchmark root is not a directory: {evidence_root}")

    run_output_dir = output_dir / "run-output"
    tracemalloc.start()
    run_started = time.perf_counter()
    run_payload = run_triage_mode(
        evidence_root,
        mode=mode,
        output_dir=run_output_dir,
        read_only=True,
        overwrite=overwrite,
    )
    ingest_seconds = time.perf_counter() - run_started
    _, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    search_latencies = []
    search_payload: dict[str, object] = {}
    for _ in range(max(1, search_iterations)):
        started = time.perf_counter()
        search_payload = run_unified_search(run_output_dir, [keyword], include_ocr=False, limit=50)
        search_latencies.append(time.perf_counter() - started)

    json_path = output_dir / "rapidtriage-benchmark.json"
    markdown_path = output_dir / "rapidtriage-benchmark.md"
    db_sizes = collect_output_sizes(run_output_dir)
    payload: dict[str, object] = {
        "command": "benchmark",
        "generated_at": now_iso(),
        "root": str(evidence_root),
        "output_dir": str(output_dir),
        "run_output_dir": str(run_output_dir),
        "options": {
            "file_count": file_count,
            "keyword": keyword,
            "mode": mode,
            "search_iterations": max(1, search_iterations),
            "synthetic": root is None,
        },
        "metrics": {
            "ingest_seconds": round(ingest_seconds, 6),
            "memory_peak_bytes": peak_memory,
            "search_p50_seconds": round(statistics.median(search_latencies), 6),
            "search_p95_seconds": round(percentile(search_latencies, 95), 6),
            "run_output_size_bytes": sum(db_sizes.values()),
            "report_generation_seconds": None,
        },
        "summary": {
            "document_match_count": run_payload.get("summary", {}).get("document_match_count", 0)
            if isinstance(run_payload.get("summary"), Mapping)
            else 0,
            "file_candidate_count": run_payload.get("summary", {}).get("file_candidate_count", 0)
            if isinstance(run_payload.get("summary"), Mapping)
            else 0,
            "search_match_count": search_payload.get("summary", {}).get("match_count", 0)
            if isinstance(search_payload.get("summary"), Mapping)
            else 0,
        },
        "outputs": {
            "json": str(json_path),
            "markdown": str(markdown_path),
            "run_summary": str(run_output_dir / "rapidtriage-run-summary.json"),
        },
        "output_sizes": db_sizes,
    }
    write_result(payload, json_path)
    markdown_path.write_text(render_benchmark_markdown(payload), encoding="utf-8")
    return payload


class BenchmarkError(ValueError):
    """Raised when benchmark input or output options are invalid."""


def build_synthetic_benchmark_case(root: Path, *, file_count: int, keyword: str, overwrite: bool = False) -> None:
    if file_count < 1:
        raise BenchmarkError("file_count must be at least 1")
    if root.exists() and any(root.iterdir()) and not overwrite:
        raise BenchmarkError(f"synthetic evidence directory is not empty: {root}")
    root.mkdir(parents=True, exist_ok=True)
    docs = root / "Users" / "analyst" / "Documents"
    logs = root / "Windows" / "Logs"
    downloads = root / "Users" / "analyst" / "Downloads"
    docs.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    downloads.mkdir(parents=True, exist_ok=True)
    for index in range(file_count):
        target_dir = docs if index % 3 == 0 else logs if index % 3 == 1 else downloads
        suffix = ".txt" if target_dir != downloads else ".log"
        token = keyword if index % 10 == 0 else "benign"
        (target_dir / f"bench-{index:06d}{suffix}").write_text(
            f"benchmark row={index} token={token} path={target_dir.name}\n",
            encoding="utf-8",
        )


def collect_output_sizes(root: Path) -> dict[str, int]:
    sizes: dict[str, int] = {}
    if not root.is_dir():
        return sizes
    for path in root.rglob("*"):
        if path.is_file():
            sizes[str(path.relative_to(root))] = path.stat().st_size
    return sizes


def percentile(values: list[float], percent: int) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((percent / 100) * (len(ordered) - 1))))
    return ordered[index]


def render_benchmark_markdown(payload: Mapping[str, object]) -> str:
    metrics = payload.get("metrics") if isinstance(payload.get("metrics"), Mapping) else {}
    summary = payload.get("summary") if isinstance(payload.get("summary"), Mapping) else {}
    return "\n".join(
        [
            "# RapidTriage Benchmark",
            "",
            f"- Generated at: `{payload.get('generated_at', '')}`",
            f"- Root: `{payload.get('root', '')}`",
            f"- Output: `{payload.get('output_dir', '')}`",
            "",
            "## Metrics",
            "",
            f"- Ingest time: `{metrics.get('ingest_seconds', 0)}` seconds",
            f"- Search p50: `{metrics.get('search_p50_seconds', 0)}` seconds",
            f"- Search p95: `{metrics.get('search_p95_seconds', 0)}` seconds",
            f"- Peak memory: `{metrics.get('memory_peak_bytes', 0)}` bytes",
            f"- Output size: `{metrics.get('run_output_size_bytes', 0)}` bytes",
            "",
            "## Summary",
            "",
            f"- Document matches: `{summary.get('document_match_count', 0)}`",
            f"- File candidates: `{summary.get('file_candidate_count', 0)}`",
            f"- Search matches: `{summary.get('search_match_count', 0)}`",
            "",
        ]
    )
