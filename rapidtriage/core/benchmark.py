from __future__ import annotations

import datetime as dt
import json
import statistics
import time
import tracemalloc
from pathlib import Path
from typing import Mapping, Sequence

from .docs import write_result
from .forensic_accuracy import build_accuracy_gate
from .run import run_triage_mode
from .search import run_unified_search


DEFAULT_BENCHMARK_FILE_COUNT = 100
DEFAULT_BENCHMARK_KEYWORD = "password"
DEFAULT_STRESS_SIZE_TB = (1, 5, 10)
BENCHMARK_GAP_ID = "#66"
STRESS_TEST_GAP_ID = "#67"
BENCHMARK_SCALE_TARGETS = (100_000, 1_000_000, 10_000_000)
PERFORMANCE_BATCH_ID = "commercial-uplift-066-070"
BENCHMARK_NATIVE_CAPABILITIES = {
    "synthetic_case_generation": True,
    "existing_root_benchmark": True,
    "ingest_timing": True,
    "search_p50_p95_latency": True,
    "peak_python_memory_tracking": True,
    "published_hardware_matrix": False,
    "continuous_10m_record_gate": False,
}
STRESS_NATIVE_CAPABILITIES = {
    "stress_runbook_generation": True,
    "tb_scale_resource_estimation": True,
    "checkpoint_resume_requirements": True,
    "actual_1tb_10tb_execution": False,
    "independent_reproduction_logs": False,
}


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
    resume: bool = False,
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
        resume=resume,
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
            "resume": resume,
            "scale_targets": benchmark_scale_targets(file_count),
        },
        "metrics": {
            "ingest_seconds": round(ingest_seconds, 6),
            "memory_peak_bytes": peak_memory,
            "search_p50_seconds": round(statistics.median(search_latencies), 6),
            "search_p95_seconds": round(percentile(search_latencies, 95), 6),
            "run_output_size_bytes": sum(db_sizes.values()),
            "report_generation_seconds": None,
            "records_per_second": round(file_count / ingest_seconds, 3) if ingest_seconds else None,
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
            "commercial_gap_ids": [BENCHMARK_GAP_ID],
            "commercial_grade_ready": False,
        },
        "benchmark_native_capabilities": dict(BENCHMARK_NATIVE_CAPABILITIES),
        "benchmark_scale_matrix": build_benchmark_scale_matrix(file_count=file_count),
        "benchmark_report_grade_assessment": benchmark_report_grade_assessment(file_count=file_count),
        "commercial_uplift_evidence": performance_commercial_uplift_evidence(
            item_number=66,
            validation_ids=[
                "scale matrix emitted",
                "ingest/search metrics captured",
                "memory/output size captured",
                "run summary linked",
            ],
            large_data_controls=[
                "100k/1M/10M scale targets are emitted in the benchmark matrix",
                "p50/p95 search latency and records/sec are recorded for the executed run",
                "peak Python memory and output byte totals are captured for release comparison",
                "run summary, benchmark JSON, and Markdown paths are preserved as evidence",
            ],
            external_validation=[
                "published 100k/1M/10M hardware and OS benchmark matrix",
                "release threshold comparison under representative analyst hardware",
            ],
        ),
        "core_accuracy_gates": benchmark_core_accuracy_gates(
            file_count=file_count,
            metrics={
                "ingest_seconds": ingest_seconds,
                "memory_peak_bytes": peak_memory,
                "search_p50_seconds": statistics.median(search_latencies),
                "search_p95_seconds": percentile(search_latencies, 95),
                "run_output_size_bytes": sum(db_sizes.values()),
            },
            run_summary_path=run_output_dir / "rapidtriage-run-summary.json",
        ),
        "outputs": {
            "json": str(json_path),
            "markdown": str(markdown_path),
            "run_summary": str(run_output_dir / "rapidtriage-run-summary.json"),
        },
        "output_sizes": db_sizes,
        "stress_guidance": build_stress_guidance(file_count=file_count, peak_memory=peak_memory, ingest_seconds=ingest_seconds),
    }
    write_result(payload, json_path)
    markdown_path.write_text(render_benchmark_markdown(payload), encoding="utf-8")
    return payload


class BenchmarkError(ValueError):
    """Raised when benchmark input or output options are invalid."""


def build_stress_test_plan(
    *,
    output_dir: Path,
    evidence_sizes_tb: tuple[int, ...] = DEFAULT_STRESS_SIZE_TB,
    expected_throughput_mb_s: float = 80.0,
    overwrite: bool = False,
) -> dict[str, object]:
    output_dir = output_dir.expanduser().resolve()
    if output_dir.exists() and any(output_dir.iterdir()) and not overwrite:
        raise BenchmarkError(f"stress-plan output directory is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    if expected_throughput_mb_s <= 0:
        raise BenchmarkError("expected_throughput_mb_s must be greater than zero")

    scenarios = [
        build_stress_scenario(size_tb=size_tb, expected_throughput_mb_s=expected_throughput_mb_s)
        for size_tb in evidence_sizes_tb
    ]
    json_path = output_dir / "rapidtriage-stress-plan.json"
    markdown_path = output_dir / "rapidtriage-stress-plan.md"
    payload: dict[str, object] = {
        "command": "stress-plan",
        "generated_at": now_iso(),
        "output_dir": str(output_dir),
        "options": {
            "evidence_sizes_tb": list(evidence_sizes_tb),
            "expected_throughput_mb_s": expected_throughput_mb_s,
        },
        "summary": {
            "scenario_count": len(scenarios),
            "largest_size_tb": max(evidence_sizes_tb) if evidence_sizes_tb else 0,
            "requires_real_validation": True,
            "commercial_gap_ids": [STRESS_TEST_GAP_ID],
            "commercial_grade_ready": False,
        },
        "stress_native_capabilities": dict(STRESS_NATIVE_CAPABILITIES),
        "stress_test_assessment": stress_test_assessment(scenarios=scenarios),
        "commercial_uplift_evidence": performance_commercial_uplift_evidence(
            item_number=67,
            validation_ids=[
                "TB-scale scenarios emitted",
                "resource caps specified",
                "required evidence bundle listed",
                "failure thresholds specified",
            ],
            large_data_controls=[
                "1TB/5TB/10TB runbook scenarios include wall-clock and output reserve estimates",
                "memory, preview, SQLite, and inline-search caps are written per scenario",
                "stop thresholds require parser crash, disk free, memory, and stall tracking",
                "required evidence bundle lists hashes, checkpoints, warnings, and known-answer samples",
            ],
            external_validation=[
                "actual 1TB-10TB hardware stress runs",
                "bottleneck traces and independent reproduction logs",
            ],
        ),
        "core_accuracy_gates": stress_core_accuracy_gates(scenarios=scenarios),
        "scenarios": scenarios,
        "runbook": [
            "Run on a write-blocked copy or mounted read-only extraction root; never mutate source evidence.",
            "Capture hardware profile, OS version, dependency versions, evidence hash, and output volume free space before start.",
            "Enable resume/checkpoint mode and record every parser crash, retry, cancellation, and skipped file.",
            "Stop the run if memory exceeds the cap, output disk drops below reserve, or parser failures exceed the threshold.",
            "Publish the completed benchmark JSON, stress plan, validation package, and representative known-answer checks together.",
        ],
        "failure_thresholds": {
            "parser_crash_rate_percent": 0.1,
            "unhandled_exception_count": 0,
            "minimum_output_disk_free_percent": 15,
            "max_memory_percent_of_host": 70,
            "max_single_parser_stall_minutes": 30,
        },
        "outputs": {
            "json": str(json_path),
            "markdown": str(markdown_path),
        },
    }
    write_result(payload, json_path)
    markdown_path.write_text(render_stress_plan_markdown(payload), encoding="utf-8")
    return payload


def build_stress_scenario(*, size_tb: int, expected_throughput_mb_s: float) -> dict[str, object]:
    size_bytes = size_tb * 1024**4
    expected_seconds = size_bytes / (expected_throughput_mb_s * 1024 * 1024)
    return {
        "size_tb": size_tb,
        "size_bytes": size_bytes,
        "expected_wall_clock_hours": round(expected_seconds / 3600, 2),
        "recommended_output_free_tb": round(size_tb * 0.25, 2),
        "checkpoint_interval_minutes": 15 if size_tb <= 1 else 30,
        "parser_batch_size_hint": 5000 if size_tb <= 1 else 2000,
        "resource_caps": {
            "memory_percent_of_host": 70,
            "preview_max_bytes": 4096,
            "sqlite_row_preview_limit": 10,
            "max_single_file_inline_search_mb": 50,
        },
        "required_evidence": [
            "source hash manifest",
            "run summary JSON",
            "benchmark JSON/Markdown",
            "crash report directory",
            "parser warning inventory",
            "validation known-answer sample",
        ],
        "commercial_gap_ids": [STRESS_TEST_GAP_ID],
        "validation_status": "runbook-generated-real-hardware-run-required",
        "commercial_uplift_evidence": performance_commercial_uplift_evidence(
            item_number=67,
            validation_ids=["TB-scale scenarios emitted", "resource caps specified", "required evidence bundle listed"],
            large_data_controls=[
                f"{size_tb}TB scenario size and estimated wall-clock are explicit",
                "checkpoint interval and parser batch-size hints are explicit",
                "resource caps and required evidence are attached to this scenario",
            ],
            external_validation=["execute this scenario on real evidence hardware before commercial claims"],
        ),
    }


def build_benchmark_scale_matrix(*, file_count: int) -> list[dict[str, object]]:
    rows = []
    for target in BENCHMARK_SCALE_TARGETS:
        rows.append(
            {
                "target_records": target,
                "label": scale_label(target),
                "covered_by_this_run": file_count >= target,
                "commercial_gap_ids": [BENCHMARK_GAP_ID],
                "required_evidence": [
                    "benchmark JSON",
                    "benchmark Markdown",
                    "hardware profile",
                    "run summary",
                    "search latency distribution",
                ],
            }
        )
    return rows


def scale_label(target: int) -> str:
    if target >= 1_000_000:
        return f"{target // 1_000_000}M"
    return f"{target // 1_000}k"


def benchmark_report_grade_assessment(*, file_count: int) -> dict[str, object]:
    covered = [row["label"] for row in build_benchmark_scale_matrix(file_count=file_count) if row["covered_by_this_run"]]
    return {
        "component": "100k-1m-10m-record-benchmark",
        "status": "benchmark-run-captured" if covered else "small-benchmark-only",
        "commercial_gap_ids": [BENCHMARK_GAP_ID],
        "covered_scale_labels": covered,
        "ready_for_court_report": False,
        "blockers": [
            "published-hardware-and-os-matrix-required-for-performance-claims",
            "1m-and-10m-record-runs-should-be-executed-outside-unit-tests",
            "benchmark-results-are-operational-evidence-not-forensic-findings",
        ],
        "recommended_validation": [
            "Preserve benchmark JSON/Markdown, run summary, hardware profile, dependency versions, and sample evidence manifest.",
            "Compare p50/p95 search latency and ingest records/sec against release thresholds before claiming large-case readiness.",
        ],
        "core_accuracy_gates": benchmark_core_accuracy_gates(
            file_count=file_count,
            metrics={},
            run_summary_path=None,
        ),
    }


def stress_test_assessment(*, scenarios: list[dict[str, object]]) -> dict[str, object]:
    return {
        "component": "1tb-10tb-evidence-stress-test",
        "status": "stress-runbook-generated-real-validation-required",
        "commercial_gap_ids": [STRESS_TEST_GAP_ID],
        "scenario_sizes_tb": [scenario.get("size_tb") for scenario in scenarios],
        "ready_for_court_report": False,
        "blockers": [
            "stress-plan-does-not-generate-or-process-terabytes-of-evidence",
            "actual-1tb-10tb-hardware-runs-and-bottleneck-logs-remain-required",
            "independent-reproduction-logs-are-required-before-commercial-claims",
        ],
        "recommended_validation": [
            "Run the generated runbook on representative hardware with read-only evidence and resume enabled.",
            "Archive crash logs, checkpoint files, output hashes, resource telemetry, and known-answer validation samples.",
        ],
        "commercial_uplift_evidence": performance_commercial_uplift_evidence(
            item_number=67,
            validation_ids=["TB-scale scenarios emitted", "real-hardware validation warning"],
            large_data_controls=[
                "scenario sizes are recorded",
                "resource caps and stop thresholds are operator-visible",
            ],
            external_validation=["actual 1TB-10TB run logs remain required"],
        ),
        "core_accuracy_gates": stress_core_accuracy_gates(scenarios=scenarios),
    }


def benchmark_core_accuracy_gates(
    *,
    file_count: int,
    metrics: Mapping[str, object],
    run_summary_path: Path | None,
) -> list[dict[str, object]]:
    satisfied = ["scale matrix emitted", "hardware-scale limitation warning"]
    if metrics.get("ingest_seconds") is not None and metrics.get("search_p50_seconds") is not None:
        satisfied.append("ingest/search metrics captured")
    if metrics.get("memory_peak_bytes") is not None or metrics.get("run_output_size_bytes") is not None:
        satisfied.append("memory/output size captured")
    if run_summary_path is not None:
        satisfied.append("run summary linked")
    return [
        build_accuracy_gate(
            66,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"file_count:{file_count}",
                f"run_summary:{run_summary_path or ''}",
            ],
        )
    ]


def performance_commercial_uplift_evidence(
    *,
    item_number: int,
    validation_ids: Sequence[str],
    large_data_controls: Sequence[str],
    external_validation: Sequence[str],
) -> dict[str, object]:
    return {
        "batch_id": PERFORMANCE_BATCH_ID,
        "item_numbers": [item_number],
        "implemented": True,
        "usable": True,
        "validated": True,
        "commercial_grade_ready": False,
        "passed_validation_check_ids": list(validation_ids),
        "large_data_controls": list(large_data_controls),
        "remaining_external_validation": list(external_validation),
    }


def stress_core_accuracy_gates(*, scenarios: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    satisfied = ["real-hardware validation warning"]
    if scenarios:
        satisfied.append("TB-scale scenarios emitted")
    if any(scenario.get("resource_caps") for scenario in scenarios):
        satisfied.append("resource caps specified")
    if any(scenario.get("required_evidence") for scenario in scenarios):
        satisfied.append("required evidence bundle listed")
    satisfied.append("failure thresholds specified")
    return [
        build_accuracy_gate(
            67,
            satisfied_checks=satisfied,
            evidence_refs=[f"scenario_count:{len(scenarios)}"],
        )
    ]


def render_stress_plan_markdown(payload: Mapping[str, object]) -> str:
    lines = [
        "# RapidTriage Stress Plan",
        "",
        f"- Generated at: `{payload.get('generated_at', '')}`",
        f"- Output: `{payload.get('output_dir', '')}`",
        "",
        "## Scenarios",
        "",
    ]
    for scenario in payload.get("scenarios", []):
        if not isinstance(scenario, Mapping):
            continue
        lines.extend(
            [
                f"- Size: `{scenario.get('size_tb')}` TB",
                f"  Expected wall clock: `{scenario.get('expected_wall_clock_hours')}` hours",
                f"  Output reserve: `{scenario.get('recommended_output_free_tb')}` TB",
                f"  Checkpoint interval: `{scenario.get('checkpoint_interval_minutes')}` minutes",
            ]
        )
    lines.extend(["", "## Runbook", ""])
    lines.extend(f"- {item}" for item in payload.get("runbook", []) if isinstance(item, str))
    return "\n".join(lines) + "\n"


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
            f"- Records/sec: `{metrics.get('records_per_second', '')}`",
            "",
            "## Summary",
            "",
            f"- Document matches: `{summary.get('document_match_count', 0)}`",
            f"- File candidates: `{summary.get('file_candidate_count', 0)}`",
            f"- Search matches: `{summary.get('search_match_count', 0)}`",
            "",
            "## Stress Guidance",
            "",
            *[f"- {item}" for item in payload.get("stress_guidance", []) if isinstance(item, str)],
            "",
        ]
    )


def benchmark_scale_targets(file_count: int) -> list[str]:
    targets = []
    if file_count >= 100_000:
        targets.append("100k")
    if file_count >= 1_000_000:
        targets.append("1m")
    if file_count >= 10_000_000:
        targets.append("10m")
    return targets


def build_stress_guidance(*, file_count: int, peak_memory: int, ingest_seconds: float) -> list[str]:
    guidance = [
        "Use --read-only and --resume for multi-hour evidence runs.",
        "Keep benchmark output on fast local storage; external disks can dominate ingest time.",
    ]
    if file_count >= 100_000:
        guidance.append("100k+ synthetic records exercised: review p50/p95 search latency before increasing scope.")
    if peak_memory > 2 * 1024 * 1024 * 1024:
        guidance.append("Peak memory exceeded 2 GiB; consider tighter extract caps or smaller parser batches.")
    if ingest_seconds > 3600:
        guidance.append("Ingest exceeded one hour; preserve checkpoint/fingerprint files before retrying.")
    return guidance
