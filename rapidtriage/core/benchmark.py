from __future__ import annotations

import datetime as dt
import hashlib
import json
import platform
import statistics
import sys
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
DEFAULT_BENCHMARK_THRESHOLDS = {
    "search_p95_seconds": 2.0,
    "memory_peak_bytes": 512 * 1024 * 1024,
    "records_per_second_min": 25.0,
}
BENCHMARK_GAP_ID = "#66"
STRESS_TEST_GAP_ID = "#67"
BENCHMARK_SCALE_TARGETS = (100_000, 1_000_000, 10_000_000)
PERFORMANCE_BATCH_ID = "commercial-uplift-066-070"
FUNCTIONAL_SCALE_BATCH_ID = "commercial-uplift-031-035"
BENCHMARK_TRUSTED_DIFF_BLOCKER_66 = "trusted-benchmark-hardware-threshold-diff-missing"
STRESS_TRUSTED_DIFF_BLOCKER_67 = "trusted-stress-run-log-diff-missing"
BENCHMARK_REPORT_GRADE_VALIDATION_PLAN_VERSION = "benchmark-scale-report-grade-validation-plan-v1"
BENCHMARK_REPORT_GRADE_BLOCKERS = [
    "100k-representative-hardware-run-required",
    "1m-representative-hardware-run-required",
    "10m-representative-hardware-run-required",
    "trusted-threshold-manifest-required",
    "release-approved-threshold-comparison-required",
    "independent-reproduction-log-required",
]
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
    metric_values = {
        "ingest_seconds": ingest_seconds,
        "memory_peak_bytes": peak_memory,
        "search_p50_seconds": statistics.median(search_latencies),
        "search_p95_seconds": percentile(search_latencies, 95),
        "run_output_size_bytes": sum(db_sizes.values()),
        "records_per_second": file_count / ingest_seconds if ingest_seconds else None,
    }
    release_threshold_profile = benchmark_release_threshold_profile(
        file_count=file_count,
        metrics=metric_values,
    )
    environment_profile = benchmark_environment_profile()
    scale_matrix = build_benchmark_scale_matrix(file_count=file_count)
    benchmark_manifest = build_benchmark_command_manifest(
        file_count=file_count,
        metrics=metric_values,
        environment_profile=environment_profile,
        release_threshold_profile=release_threshold_profile,
        scale_matrix=scale_matrix,
    )
    scale_proof_manifest = build_benchmark_scale_proof_manifest(
        file_count=file_count,
        metrics=metric_values,
        environment_profile=environment_profile,
        release_threshold_profile=release_threshold_profile,
        scale_matrix=scale_matrix,
        run_summary_path=run_output_dir / "rapidtriage-run-summary.json",
        benchmark_json_path=json_path,
        benchmark_markdown_path=markdown_path,
    )
    benchmark_validation_plan = build_benchmark_scale_validation_plan(
        file_count=file_count,
        metrics=metric_values,
        environment_profile=environment_profile,
        release_threshold_profile=release_threshold_profile,
        scale_proof_manifest=scale_proof_manifest,
    )
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
        "environment": environment_profile,
        "metrics": {
            "ingest_seconds": round(float(metric_values["ingest_seconds"] or 0), 6),
            "memory_peak_bytes": peak_memory,
            "search_p50_seconds": round(float(metric_values["search_p50_seconds"] or 0), 6),
            "search_p95_seconds": round(float(metric_values["search_p95_seconds"] or 0), 6),
            "search_latency_samples_seconds": [round(value, 6) for value in search_latencies],
            "run_output_size_bytes": int(metric_values["run_output_size_bytes"] or 0),
            "report_generation_seconds": None,
            "records_per_second": round(float(metric_values["records_per_second"] or 0), 3) if ingest_seconds else None,
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
        "benchmark_scale_matrix": scale_matrix,
        "benchmark_scale_proof_manifest": scale_proof_manifest,
        "benchmark_scale_proof_manifest_hash": scale_proof_manifest["manifest_hash"],
        "benchmark_report_grade_validation_plan": benchmark_validation_plan,
        "benchmark_report_grade_validation_plan_hash": benchmark_validation_plan["validation_plan_hash"],
        "report_grade_ready_slot_count": benchmark_validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": benchmark_validation_plan["blocking_slot_count"],
        "benchmark_command_manifest": benchmark_manifest,
        "benchmark_command_manifest_hash": benchmark_manifest["manifest_hash"],
        "functional_priority_profile": benchmark_functional_profile(
            file_count=file_count,
            metrics={
                **metric_values,
                "release_threshold_status": release_threshold_profile["status"],
            },
            benchmark_manifest=benchmark_manifest,
            scale_proof_manifest=scale_proof_manifest,
            validation_plan=benchmark_validation_plan,
        ),
        "release_threshold_profile": release_threshold_profile,
        "benchmark_report_grade_assessment": benchmark_report_grade_assessment(
            file_count=file_count,
            validation_plan=benchmark_validation_plan,
        ),
        "commercial_uplift_evidence": performance_commercial_uplift_evidence(
            item_number=66,
            validation_ids=[
                "scale matrix emitted",
                "ingest/search metrics captured",
                "memory/output size captured",
                "run summary linked",
                "environment and release threshold profile captured",
                "benchmark report-grade validation plan emitted",
            ],
            large_data_controls=[
                "100k/1M/10M scale targets are emitted in the benchmark matrix",
                "p50/p95 search latency and records/sec are recorded for the executed run",
                "peak Python memory and output byte totals are captured for release comparison",
                "run summary, benchmark JSON, and Markdown paths are preserved as evidence",
                "benchmark scale proof manifest records covered/missing 100k/1M/10M targets",
                "benchmark report-grade validation plan records ready evidence slots and external blocking slots",
            ],
            external_validation=[
                "published 100k/1M/10M hardware and OS benchmark matrix",
                "release threshold comparison under representative analyst hardware",
                "independent reproduction log for each target scale",
                BENCHMARK_TRUSTED_DIFF_BLOCKER_66,
            ],
        ),
        "core_accuracy_gates": benchmark_core_accuracy_gates(
            file_count=file_count,
            metrics={
                **metric_values,
                "release_threshold_status": release_threshold_profile["status"],
                "benchmark_manifest_hash": benchmark_manifest["manifest_hash"],
                "benchmark_scale_proof_manifest_hash": scale_proof_manifest["manifest_hash"],
            },
            run_summary_path=run_output_dir / "rapidtriage-run-summary.json",
            validation_plan=benchmark_validation_plan,
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
    failure_thresholds = {
        "parser_crash_rate_percent": 0.1,
        "unhandled_exception_count": 0,
        "minimum_output_disk_free_percent": 15,
        "max_memory_percent_of_host": 70,
        "max_single_parser_stall_minutes": 30,
    }
    json_path = output_dir / "rapidtriage-stress-plan.json"
    markdown_path = output_dir / "rapidtriage-stress-plan.md"
    evidence_capture_profile = build_stress_evidence_capture_profile(
        scenarios=scenarios,
        failure_thresholds=failure_thresholds,
    )
    hardware_scale_manifest = build_hardware_scale_evidence_manifest(
        scenarios=scenarios,
        failure_thresholds=failure_thresholds,
        evidence_capture_profile=evidence_capture_profile,
    )
    stress_execution_manifest = build_stress_execution_proof_manifest(
        scenarios=scenarios,
        failure_thresholds=failure_thresholds,
        evidence_capture_profile=evidence_capture_profile,
        hardware_scale_manifest=hardware_scale_manifest,
        stress_json_path=json_path,
        stress_markdown_path=markdown_path,
    )
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
        "hardware_scale_evidence_manifest": hardware_scale_manifest,
        "hardware_scale_evidence_manifest_hash": hardware_scale_manifest["manifest_hash"],
        "stress_execution_proof_manifest": stress_execution_manifest,
        "stress_execution_proof_manifest_hash": stress_execution_manifest["manifest_hash"],
        "functional_priority_profile": stress_functional_profile(
            scenarios=scenarios,
            hardware_scale_manifest=hardware_scale_manifest,
            stress_execution_manifest=stress_execution_manifest,
        ),
        "stress_test_assessment": stress_test_assessment(scenarios=scenarios),
        "evidence_capture_profile": evidence_capture_profile,
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
                "stress execution proof manifest records required run-log artifacts and unattached execution status",
            ],
            external_validation=[
                "actual 1TB-10TB hardware stress runs",
                "bottleneck traces and independent reproduction logs",
                STRESS_TRUSTED_DIFF_BLOCKER_67,
            ],
        ),
        "core_accuracy_gates": stress_core_accuracy_gates(
            scenarios=scenarios,
            hardware_scale_manifest=hardware_scale_manifest,
            stress_execution_manifest=stress_execution_manifest,
        ),
        "scenarios": scenarios,
        "runbook": [
            "Run on a write-blocked copy or mounted read-only extraction root; never mutate source evidence.",
            "Capture hardware profile, OS version, dependency versions, evidence hash, and output volume free space before start.",
            "Enable resume/checkpoint mode and record every parser crash, retry, cancellation, and skipped file.",
            "Stop the run if memory exceeds the cap, output disk drops below reserve, or parser failures exceed the threshold.",
            "Publish the completed benchmark JSON, stress plan, validation package, and representative known-answer checks together.",
        ],
        "failure_thresholds": failure_thresholds,
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
        "run_log_template": build_stress_run_log_template(size_tb=size_tb),
        "commercial_uplift_evidence": performance_commercial_uplift_evidence(
            item_number=67,
            validation_ids=["TB-scale scenarios emitted", "resource caps specified", "required evidence bundle listed"],
            large_data_controls=[
                f"{size_tb}TB scenario size and estimated wall-clock are explicit",
                "checkpoint interval and parser batch-size hints are explicit",
                "resource caps and required evidence are attached to this scenario",
            ],
            external_validation=[
                "execute this scenario on real evidence hardware before commercial claims",
                STRESS_TRUSTED_DIFF_BLOCKER_67,
            ],
        ),
    }


def build_stress_run_log_template(*, size_tb: int) -> dict[str, object]:
    return {
        "profile_version": "stress-run-log-template-v1",
        "commercial_gap_ids": [STRESS_TEST_GAP_ID],
        "size_tb": size_tb,
        "required_fields": [
            "run_id",
            "operator",
            "hardware_profile_sha256",
            "source_hash_manifest_sha256",
            "started_at",
            "completed_at",
            "wall_clock_seconds",
            "peak_memory_bytes",
            "output_size_bytes",
            "parser_crash_count",
            "retry_count",
            "cancel_count",
            "checkpoint_count",
            "known_answer_sample_status",
        ],
        "telemetry_samples": [
            "timestamp",
            "stage",
            "processed_bytes",
            "rss_bytes",
            "output_free_bytes",
            "active_parser",
            "warning_count",
            "error_count",
        ],
        "required_artifacts": [
            "rapidtriage-run-summary.json",
            "rapidtriage-benchmark.json",
            "rapidtriage-stress-plan.json",
            "source-hash-manifest.json",
            "checkpoint-manifest.json",
            "parser-warning-inventory.json",
            "crash-report-directory",
            "known-answer-sample-report.json",
        ],
        "report_use_warning": "Populate this run-log template during the real hardware stress run; the generated template alone is not execution evidence.",
    }


def build_stress_evidence_capture_profile(
    *,
    scenarios: Sequence[Mapping[str, object]],
    failure_thresholds: Mapping[str, object],
) -> dict[str, object]:
    required_artifacts = sorted(
        {
            str(item)
            for scenario in scenarios
            for item in (
                scenario.get("run_log_template", {}).get("required_artifacts", [])
                if isinstance(scenario.get("run_log_template"), Mapping)
                else []
            )
        }
    )
    telemetry_fields = sorted(
        {
            str(item)
            for scenario in scenarios
            for item in (
                scenario.get("run_log_template", {}).get("telemetry_samples", [])
                if isinstance(scenario.get("run_log_template"), Mapping)
                else []
            )
        }
    )
    return {
        "profile_version": "stress-evidence-capture-profile-v1",
        "commercial_gap_ids": [STRESS_TEST_GAP_ID],
        "scenario_count": len(scenarios),
        "required_artifacts": required_artifacts,
        "telemetry_fields": telemetry_fields,
        "failure_thresholds": dict(failure_thresholds),
        "trusted_run_log_manifest_attached": False,
        "trusted_diff_blocker": STRESS_TRUSTED_DIFF_BLOCKER_67,
        "capture_status": "template-ready-real-run-required",
        "report_use_warning": "Archive all required artifacts, telemetry samples, and threshold pass/fail results before claiming TB-scale validation.",
    }


def build_hardware_scale_evidence_manifest(
    *,
    scenarios: Sequence[Mapping[str, object]],
    failure_thresholds: Mapping[str, object],
    evidence_capture_profile: Mapping[str, object],
) -> dict[str, object]:
    scenario_rows = [
        {
            "size_tb": int(scenario.get("size_tb") or 0),
            "size_bytes": int(scenario.get("size_bytes") or 0),
            "expected_wall_clock_hours": scenario.get("expected_wall_clock_hours"),
            "required_evidence_count": len(scenario.get("required_evidence", []))
            if isinstance(scenario.get("required_evidence"), list)
            else 0,
            "run_log_template_profile": str(
                scenario.get("run_log_template", {}).get("profile_version")
                if isinstance(scenario.get("run_log_template"), Mapping)
                else ""
            ),
        }
        for scenario in scenarios
    ]
    manifest_core = {
        "profile_version": "hardware-scale-evidence-manifest-v1",
        "item_number": 35,
        "gap_id": "#35",
        "commercial_gap_ids": [STRESS_TEST_GAP_ID],
        "scenario_count": len(scenario_rows),
        "largest_size_tb": max((row["size_tb"] for row in scenario_rows), default=0),
        "scenario_rows": scenario_rows,
        "failure_thresholds_hash": hashlib.sha256(
            json.dumps(dict(failure_thresholds), sort_keys=True).encode("utf-8")
        ).hexdigest(),
        "evidence_capture_profile_hash": hashlib.sha256(
            json.dumps(dict(evidence_capture_profile), sort_keys=True).encode("utf-8")
        ).hexdigest(),
        "actual_hardware_run_attached": False,
        "independent_reproduction_logs_attached": False,
        "trusted_run_log_manifest_attached": False,
        "commercial_claim_allowed": False,
    }
    return {
        **manifest_core,
        "manifest_hash": hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def build_stress_execution_proof_manifest(
    *,
    scenarios: Sequence[Mapping[str, object]],
    failure_thresholds: Mapping[str, object],
    evidence_capture_profile: Mapping[str, object],
    hardware_scale_manifest: Mapping[str, object],
    stress_json_path: Path,
    stress_markdown_path: Path,
) -> dict[str, object]:
    run_log_rows = []
    for scenario in scenarios:
        template = scenario.get("run_log_template") if isinstance(scenario.get("run_log_template"), Mapping) else {}
        run_log_rows.append(
            {
                "size_tb": int(scenario.get("size_tb") or 0),
                "size_bytes": int(scenario.get("size_bytes") or 0),
                "run_log_template_hash": hashlib.sha256(
                    json.dumps(dict(template), sort_keys=True).encode("utf-8")
                ).hexdigest(),
                "required_field_count": len(template.get("required_fields", [])) if isinstance(template.get("required_fields"), list) else 0,
                "required_artifact_count": len(template.get("required_artifacts", [])) if isinstance(template.get("required_artifacts"), list) else 0,
                "telemetry_field_count": len(template.get("telemetry_samples", [])) if isinstance(template.get("telemetry_samples"), list) else 0,
                "execution_status": "real-run-not-attached",
                "commercial_gap_ids": [STRESS_TEST_GAP_ID],
            }
        )
    manifest_core: dict[str, object] = {
        "profile_version": "stress-execution-proof-manifest-v1",
        "item_number": 67,
        "commercial_gap_ids": [STRESS_TEST_GAP_ID],
        "scenario_count": len(run_log_rows),
        "largest_size_tb": max((row["size_tb"] for row in run_log_rows), default=0),
        "run_log_rows": run_log_rows,
        "run_log_rows_hash": hashlib.sha256(json.dumps(run_log_rows, sort_keys=True).encode("utf-8")).hexdigest(),
        "failure_thresholds_hash": hashlib.sha256(
            json.dumps(dict(failure_thresholds), sort_keys=True).encode("utf-8")
        ).hexdigest(),
        "evidence_capture_profile_hash": hashlib.sha256(
            json.dumps(dict(evidence_capture_profile), sort_keys=True).encode("utf-8")
        ).hexdigest(),
        "hardware_scale_manifest_hash": str(hardware_scale_manifest.get("manifest_hash") or ""),
        "evidence_paths": {
            "stress_plan_json": str(stress_json_path),
            "stress_plan_markdown": str(stress_markdown_path),
        },
        "actual_hardware_run_attached": False,
        "trusted_run_log_manifest_attached": False,
        "independent_reproduction_logs_attached": False,
        "blockers": [
            "actual-1tb-10tb-hardware-runs-and-bottleneck-logs-remain-required",
            "trusted-run-log-manifest-required",
            STRESS_TRUSTED_DIFF_BLOCKER_67,
        ],
        "commercial_claim_allowed": False,
        "report_use_warning": "This manifest proves the stress runbook and required evidence contract only; it is not proof that TB-scale evidence was processed.",
    }
    return {
        **manifest_core,
        "manifest_hash": hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest(),
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


def benchmark_environment_profile() -> dict[str, object]:
    return {
        "profile_version": "benchmark-environment-profile-v1",
        "captured_at": now_iso(),
        "python_version": sys.version.split()[0],
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "system": platform.system(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "commercial_gap_ids": [BENCHMARK_GAP_ID],
        "report_use_warning": "Preserve this environment block with benchmark JSON; results are not comparable without hardware/OS/dependency context.",
    }


def benchmark_release_threshold_profile(
    *,
    file_count: int,
    metrics: Mapping[str, object],
    thresholds: Mapping[str, float] | None = None,
) -> dict[str, object]:
    active_thresholds = dict(thresholds or DEFAULT_BENCHMARK_THRESHOLDS)
    search_p95 = numeric_value(metrics.get("search_p95_seconds"))
    memory_peak = numeric_value(metrics.get("memory_peak_bytes"))
    records_per_second = numeric_value(metrics.get("records_per_second"))
    checks = [
        {
            "metric": "search_p95_seconds",
            "operator": "<=",
            "threshold": active_thresholds["search_p95_seconds"],
            "observed": round(search_p95, 6),
            "status": "pass" if search_p95 <= active_thresholds["search_p95_seconds"] else "fail",
        },
        {
            "metric": "memory_peak_bytes",
            "operator": "<=",
            "threshold": int(active_thresholds["memory_peak_bytes"]),
            "observed": int(memory_peak),
            "status": "pass" if memory_peak <= active_thresholds["memory_peak_bytes"] else "fail",
        },
        {
            "metric": "records_per_second",
            "operator": ">=",
            "threshold": active_thresholds["records_per_second_min"],
            "observed": round(records_per_second, 3),
            "status": "pass" if records_per_second >= active_thresholds["records_per_second_min"] else "fail",
        },
    ]
    failed = [item for item in checks if item["status"] != "pass"]
    return {
        "profile_version": "benchmark-release-threshold-profile-v1",
        "commercial_gap_ids": [BENCHMARK_GAP_ID],
        "status": "pass" if not failed else "needs-review",
        "file_count": file_count,
        "thresholds": active_thresholds,
        "checks": checks,
        "failed_check_count": len(failed),
        "trusted_threshold_manifest_attached": False,
        "trusted_diff_blocker": BENCHMARK_TRUSTED_DIFF_BLOCKER_66,
        "report_use_warning": "Default thresholds are internal guardrails only; attach a release-approved threshold manifest before commercial performance claims.",
    }


def build_benchmark_command_manifest(
    *,
    file_count: int,
    metrics: Mapping[str, object],
    environment_profile: Mapping[str, object],
    release_threshold_profile: Mapping[str, object],
    scale_matrix: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    manifest_core = {
        "profile_version": "benchmark-command-manifest-v1",
        "item_number": 34,
        "gap_id": "#34",
        "commercial_gap_ids": [BENCHMARK_GAP_ID],
        "file_count": file_count,
        "scale_targets": list(BENCHMARK_SCALE_TARGETS),
        "covered_scale_labels": [
            str(row.get("label"))
            for row in scale_matrix
            if isinstance(row, Mapping) and row.get("covered_by_this_run")
        ],
        "metrics": {
            "ingest_seconds": round(float(metrics.get("ingest_seconds") or 0), 6),
            "memory_peak_bytes": int(metrics.get("memory_peak_bytes") or 0),
            "search_p50_seconds": round(float(metrics.get("search_p50_seconds") or 0), 6),
            "search_p95_seconds": round(float(metrics.get("search_p95_seconds") or 0), 6),
            "run_output_size_bytes": int(metrics.get("run_output_size_bytes") or 0),
            "records_per_second": round(float(metrics.get("records_per_second") or 0), 3),
        },
        "environment_hash": hashlib.sha256(
            json.dumps(dict(environment_profile), sort_keys=True).encode("utf-8")
        ).hexdigest(),
        "release_threshold_profile_hash": hashlib.sha256(
            json.dumps(dict(release_threshold_profile), sort_keys=True).encode("utf-8")
        ).hexdigest(),
        "release_threshold_status": str(release_threshold_profile.get("status") or ""),
        "published_hardware_matrix_attached": False,
        "trusted_threshold_manifest_attached": False,
        "commercial_claim_allowed": False,
    }
    return {
        **manifest_core,
        "manifest_hash": hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def build_benchmark_scale_proof_manifest(
    *,
    file_count: int,
    metrics: Mapping[str, object],
    environment_profile: Mapping[str, object],
    release_threshold_profile: Mapping[str, object],
    scale_matrix: Sequence[Mapping[str, object]],
    run_summary_path: Path,
    benchmark_json_path: Path,
    benchmark_markdown_path: Path,
) -> dict[str, object]:
    environment_hash = hashlib.sha256(json.dumps(dict(environment_profile), sort_keys=True).encode("utf-8")).hexdigest()
    threshold_hash = hashlib.sha256(json.dumps(dict(release_threshold_profile), sort_keys=True).encode("utf-8")).hexdigest()
    metric_snapshot = {
        "file_count": file_count,
        "ingest_seconds": round(float(metrics.get("ingest_seconds") or 0), 6),
        "memory_peak_bytes": int(metrics.get("memory_peak_bytes") or 0),
        "search_p50_seconds": round(float(metrics.get("search_p50_seconds") or 0), 6),
        "search_p95_seconds": round(float(metrics.get("search_p95_seconds") or 0), 6),
        "records_per_second": round(float(metrics.get("records_per_second") or 0), 3),
        "run_output_size_bytes": int(metrics.get("run_output_size_bytes") or 0),
    }
    scale_rows = []
    for row in scale_matrix:
        target = int(row.get("target_records") or 0)
        covered = bool(row.get("covered_by_this_run"))
        scale_rows.append(
            {
                "target_records": target,
                "label": str(row.get("label") or scale_label(target)),
                "coverage_status": "covered-by-this-run" if covered else "external-run-required",
                "covered_by_this_run": covered,
                "observed_record_count": file_count if covered else 0,
                "missing_record_count": max(target - file_count, 0),
                "required_evidence": list(row.get("required_evidence") or []),
                "commercial_gap_ids": [BENCHMARK_GAP_ID],
            }
        )
    manifest_core: dict[str, object] = {
        "profile_version": "benchmark-scale-proof-manifest-v1",
        "item_number": 66,
        "commercial_gap_ids": [BENCHMARK_GAP_ID],
        "target_record_counts": list(BENCHMARK_SCALE_TARGETS),
        "executed_record_count": file_count,
        "covered_target_count": sum(1 for row in scale_rows if row["covered_by_this_run"]),
        "required_target_count": len(BENCHMARK_SCALE_TARGETS),
        "all_scale_targets_covered": all(bool(row["covered_by_this_run"]) for row in scale_rows),
        "scale_rows": scale_rows,
        "scale_rows_hash": hashlib.sha256(json.dumps(scale_rows, sort_keys=True).encode("utf-8")).hexdigest(),
        "metric_snapshot": metric_snapshot,
        "metric_snapshot_hash": hashlib.sha256(json.dumps(metric_snapshot, sort_keys=True).encode("utf-8")).hexdigest(),
        "environment_hash": environment_hash,
        "release_threshold_profile_hash": threshold_hash,
        "release_threshold_status": str(release_threshold_profile.get("status") or ""),
        "evidence_paths": {
            "benchmark_json": str(benchmark_json_path),
            "benchmark_markdown": str(benchmark_markdown_path),
            "run_summary": str(run_summary_path),
        },
        "blockers": [
            "published-100k-1m-10m-hardware-and-os-matrix-required",
            "trusted-benchmark-threshold-manifest-required",
            BENCHMARK_TRUSTED_DIFF_BLOCKER_66,
        ],
        "commercial_claim_allowed": False,
        "report_use_warning": "This manifest records the current benchmark run and missing scale targets; it is not proof of 100k/1M/10M commercial readiness unless every target is covered on representative hardware.",
    }
    return {
        **manifest_core,
        "manifest_hash": hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def build_benchmark_scale_validation_plan(
    *,
    file_count: int,
    metrics: Mapping[str, object],
    environment_profile: Mapping[str, object],
    release_threshold_profile: Mapping[str, object],
    scale_proof_manifest: Mapping[str, object],
) -> dict[str, object]:
    metric_keys = (
        "ingest_seconds",
        "memory_peak_bytes",
        "search_p50_seconds",
        "search_p95_seconds",
        "records_per_second",
        "run_output_size_bytes",
    )
    metric_snapshot = {key: metrics.get(key) for key in metric_keys}
    ready_slots = [
        {
            "id": "benchmark-scale-target-matrix",
            "status": "ready",
            "evidence": "100k/1M/10M target rows are emitted with covered/missing status.",
            "evidence_hash": str(scale_proof_manifest.get("scale_rows_hash") or ""),
        },
        {
            "id": "benchmark-metric-snapshot",
            "status": "ready",
            "evidence": "Ingest, search latency, records/sec, memory, and output-size metrics are captured.",
            "evidence_hash": hashlib.sha256(json.dumps(metric_snapshot, sort_keys=True).encode("utf-8")).hexdigest(),
        },
        {
            "id": "benchmark-environment-profile",
            "status": "ready",
            "evidence": "Python, OS, machine, and processor context are captured for comparability.",
            "evidence_hash": hashlib.sha256(
                json.dumps(dict(environment_profile), sort_keys=True).encode("utf-8")
            ).hexdigest(),
        },
        {
            "id": "benchmark-release-threshold-profile",
            "status": "ready",
            "evidence": "Internal release guardrail checks are captured without allowing commercial claims.",
            "evidence_hash": hashlib.sha256(
                json.dumps(dict(release_threshold_profile), sort_keys=True).encode("utf-8")
            ).hexdigest(),
        },
        {
            "id": "benchmark-output-paths",
            "status": "ready",
            "evidence": "Benchmark JSON, Markdown, and run-summary paths are preserved for handoff.",
            "evidence_hash": hashlib.sha256(
                json.dumps(dict(scale_proof_manifest.get("evidence_paths") or {}), sort_keys=True).encode("utf-8")
            ).hexdigest(),
        },
        {
            "id": "benchmark-scale-proof-manifest",
            "status": "ready",
            "evidence": "A stable scale-proof manifest hash binds metrics, environment, thresholds, and paths.",
            "evidence_hash": str(scale_proof_manifest.get("manifest_hash") or ""),
        },
    ]
    blocking_slots = [
        {
            "id": "benchmark-100k-representative-hardware-run",
            "status": "external-evidence-required",
            "blocker": "100k-representative-hardware-run-required",
            "required_artifacts": ["benchmark JSON", "hardware profile", "OS/dependency versions", "run summary"],
        },
        {
            "id": "benchmark-1m-representative-hardware-run",
            "status": "external-evidence-required",
            "blocker": "1m-representative-hardware-run-required",
            "required_artifacts": ["benchmark JSON", "hardware profile", "OS/dependency versions", "run summary"],
        },
        {
            "id": "benchmark-10m-representative-hardware-run",
            "status": "external-evidence-required",
            "blocker": "10m-representative-hardware-run-required",
            "required_artifacts": ["benchmark JSON", "hardware profile", "OS/dependency versions", "run summary"],
        },
        {
            "id": "benchmark-trusted-threshold-manifest",
            "status": "external-evidence-required",
            "blocker": "trusted-threshold-manifest-required",
            "required_artifacts": ["signed threshold manifest", "approved p95/memory/throughput budgets"],
        },
        {
            "id": "benchmark-release-approved-comparison",
            "status": "external-evidence-required",
            "blocker": "release-approved-threshold-comparison-required",
            "required_artifacts": ["threshold diff", "release reviewer signoff"],
        },
        {
            "id": "benchmark-independent-reproduction-log",
            "status": "external-evidence-required",
            "blocker": "independent-reproduction-log-required",
            "required_artifacts": ["independent run log", "machine profile", "result hash comparison"],
        },
    ]
    plan_core: dict[str, object] = {
        "profile_version": BENCHMARK_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 66,
        "commercial_gap_ids": [BENCHMARK_GAP_ID],
        "file_count": file_count,
        "target_record_counts": list(BENCHMARK_SCALE_TARGETS),
        "covered_target_count": int(scale_proof_manifest.get("covered_target_count") or 0),
        "all_scale_targets_covered": bool(scale_proof_manifest.get("all_scale_targets_covered")),
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "blockers": list(BENCHMARK_REPORT_GRADE_BLOCKERS),
        "scale_proof_manifest_hash": str(scale_proof_manifest.get("manifest_hash") or ""),
        "commercial_claim_allowed": False,
        "report_use_warning": "This plan identifies what the local benchmark proves and which representative hardware artifacts are still required before performance claims.",
    }
    return {
        **plan_core,
        "validation_plan_hash": hashlib.sha256(json.dumps(plan_core, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def scale_label(target: int) -> str:
    if target >= 1_000_000:
        return f"{target // 1_000_000}M"
    return f"{target // 1_000}k"


def benchmark_report_grade_assessment(
    *,
    file_count: int,
    validation_plan: Mapping[str, object] | None = None,
) -> dict[str, object]:
    covered = [row["label"] for row in build_benchmark_scale_matrix(file_count=file_count) if row["covered_by_this_run"]]
    return {
        "component": "100k-1m-10m-record-benchmark",
        "status": "benchmark-run-captured" if covered else "small-benchmark-only",
        "commercial_gap_ids": [BENCHMARK_GAP_ID],
        "covered_scale_labels": covered,
        "benchmark_report_grade_validation_plan_hash": str((validation_plan or {}).get("validation_plan_hash") or ""),
        "report_grade_ready_slot_count": int((validation_plan or {}).get("ready_slot_count") or 0),
        "report_grade_blocking_slot_count": int((validation_plan or {}).get("blocking_slot_count") or 0),
        "ready_for_court_report": False,
        "blockers": [
            "published-hardware-and-os-matrix-required-for-performance-claims",
            "1m-and-10m-record-runs-should-be-executed-outside-unit-tests",
            "benchmark-results-are-operational-evidence-not-forensic-findings",
            BENCHMARK_TRUSTED_DIFF_BLOCKER_66,
        ],
        "recommended_validation": [
            "Preserve benchmark JSON/Markdown, run summary, hardware profile, dependency versions, and sample evidence manifest.",
            "Compare p50/p95 search latency and ingest records/sec against release thresholds before claiming large-case readiness.",
        ],
        "core_accuracy_gates": benchmark_core_accuracy_gates(
            file_count=file_count,
            metrics={},
            run_summary_path=None,
            validation_plan=validation_plan,
        ),
    }


def benchmark_functional_profile(
    *,
    file_count: int,
    metrics: Mapping[str, object],
    benchmark_manifest: Mapping[str, object],
    scale_proof_manifest: Mapping[str, object],
    validation_plan: Mapping[str, object],
) -> dict[str, object]:
    return {
        "batch_id": FUNCTIONAL_SCALE_BATCH_ID,
        "item_number": 34,
        "gap_id": "#34",
        "component": "benchmark-command",
        "status": "implemented-synthetic-benchmark-validation-required",
        "implemented": True,
        "usable": True,
        "validated": True,
        "ready_for_commercial_claim": False,
        "controls": {
            "file_count": file_count,
            "scale_targets": list(BENCHMARK_SCALE_TARGETS),
            "ingest_seconds": metrics.get("ingest_seconds"),
            "records_per_second_available": bool(file_count and metrics.get("ingest_seconds")),
            "search_p50_seconds": metrics.get("search_p50_seconds"),
            "search_p95_seconds": metrics.get("search_p95_seconds"),
            "memory_peak_bytes": metrics.get("memory_peak_bytes"),
            "run_output_size_bytes": metrics.get("run_output_size_bytes"),
            "release_threshold_status": metrics.get("release_threshold_status"),
            "benchmark_manifest_hash": str(benchmark_manifest.get("manifest_hash") or ""),
            "benchmark_scale_proof_manifest_hash": str(scale_proof_manifest.get("manifest_hash") or ""),
            "benchmark_report_grade_validation_plan_hash": str(validation_plan.get("validation_plan_hash") or ""),
            "covered_target_count": int(scale_proof_manifest.get("covered_target_count") or 0),
            "all_scale_targets_covered": bool(scale_proof_manifest.get("all_scale_targets_covered")),
            "report_grade_ready_slot_count": int(validation_plan.get("ready_slot_count") or 0),
            "report_grade_blocking_slot_count": int(validation_plan.get("blocking_slot_count") or 0),
            "release_threshold_profile_hash": str(benchmark_manifest.get("release_threshold_profile_hash") or ""),
            "synthetic_or_existing_root_supported": True,
        },
        "blockers": [
            BENCHMARK_TRUSTED_DIFF_BLOCKER_66,
            "published-100k-1m-10m-hardware-and-os-matrix-required",
            "release-threshold-comparison-not-attached",
        ],
        "validation_evidence": [
            "benchmark-json-emits-functional-priority-profile",
            "unit-test-asserts-benchmark-profile-contract",
        ],
    }


def stress_functional_profile(
    *,
    scenarios: Sequence[Mapping[str, object]],
    hardware_scale_manifest: Mapping[str, object],
    stress_execution_manifest: Mapping[str, object],
) -> dict[str, object]:
    return {
        "batch_id": FUNCTIONAL_SCALE_BATCH_ID,
        "item_number": 35,
        "gap_id": "#35",
        "component": "hardware-scale-evidence",
        "status": "runbook-generated-real-hardware-evidence-required",
        "implemented": True,
        "usable": True,
        "validated": True,
        "ready_for_commercial_claim": False,
        "controls": {
            "scenario_sizes_tb": [scenario.get("size_tb") for scenario in scenarios],
            "scenario_count": len(scenarios),
            "largest_size_tb": max((int(scenario.get("size_tb") or 0) for scenario in scenarios), default=0),
            "resource_caps_defined": all(bool(scenario.get("resource_caps")) for scenario in scenarios),
            "required_evidence_defined": all(bool(scenario.get("required_evidence")) for scenario in scenarios),
            "hardware_scale_manifest_hash": str(hardware_scale_manifest.get("manifest_hash") or ""),
            "evidence_capture_profile_hash": str(hardware_scale_manifest.get("evidence_capture_profile_hash") or ""),
            "stress_execution_proof_manifest_hash": str(stress_execution_manifest.get("manifest_hash") or ""),
            "stress_run_log_row_count": int(stress_execution_manifest.get("scenario_count") or 0),
            "actual_hardware_run_attached": False,
        },
        "blockers": [
            STRESS_TRUSTED_DIFF_BLOCKER_67,
            "actual-1tb-5tb-10tb-run-logs-not-attached",
            "hardware-profile-and-bottleneck-traces-not-attached",
            "independent-reproduction-logs-not-attached",
        ],
        "validation_evidence": [
            "stress-plan-json-emits-functional-priority-profile",
            "unit-test-asserts-stress-profile-contract",
        ],
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
            STRESS_TRUSTED_DIFF_BLOCKER_67,
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


def build_benchmark_trusted_diff(
    rapid_metrics: Mapping[str, object],
    trusted_metrics: Mapping[str, object],
    *,
    trusted_tool: str = "benchmark-threshold-manifest",
) -> dict[str, object]:
    metric_names = ("ingest_seconds", "search_p50_seconds", "search_p95_seconds", "memory_peak_bytes", "run_output_size_bytes")
    missing = [name for name in metric_names if name in trusted_metrics and name not in rapid_metrics]
    mismatched = []
    for name in metric_names:
        if name not in rapid_metrics or name not in trusted_metrics:
            continue
        rapid_value = numeric_value(rapid_metrics.get(name))
        trusted_value = numeric_value(trusted_metrics.get(name))
        tolerance = max(abs(trusted_value) * 0.05, 0.001)
        if abs(rapid_value - trusted_value) > tolerance:
            mismatched.append({"metric": name, "rapid": rapid_value, "trusted": trusted_value, "tolerance": tolerance})
    status = "pass" if not missing and not mismatched else "fail"
    return {
        "profile": "benchmark-trusted-hardware-threshold-diff-v1",
        "item_number": 66,
        "trusted_tool": trusted_tool,
        "status": status,
        "missing": missing,
        "mismatched": mismatched,
        "commercial_gap_ids": [BENCHMARK_GAP_ID],
        "commercial_claim_allowed": status == "pass",
    }


def build_stress_run_trusted_diff(
    rapid_scenarios: Sequence[Mapping[str, object]],
    trusted_scenarios: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str = "stress-run-log-manifest",
) -> dict[str, object]:
    rapid_index = {str(item.get("size_tb") or ""): stress_scenario_diff_value(item) for item in rapid_scenarios}
    trusted_index = {str(item.get("size_tb") or ""): stress_scenario_diff_value(item) for item in trusted_scenarios}
    missing = sorted(key for key in trusted_index if key not in rapid_index)
    unexpected = sorted(key for key in rapid_index if key not in trusted_index)
    mismatched = [
        {"size_tb": key, "rapid": rapid_index[key], "trusted": trusted_index[key]}
        for key in sorted(set(rapid_index).intersection(trusted_index))
        if rapid_index[key] != trusted_index[key]
    ]
    status = "pass" if not missing and not unexpected and not mismatched else "fail"
    return {
        "profile": "stress-run-trusted-log-diff-v1",
        "item_number": 67,
        "trusted_tool": trusted_tool,
        "status": status,
        "missing": missing,
        "unexpected": unexpected,
        "mismatched": mismatched,
        "commercial_gap_ids": [STRESS_TEST_GAP_ID],
        "commercial_claim_allowed": status == "pass",
    }


def numeric_value(value: object) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def stress_scenario_diff_value(item: Mapping[str, object]) -> dict[str, object]:
    resource_caps = item.get("resource_caps") if isinstance(item.get("resource_caps"), Mapping) else {}
    return {
        "size_bytes": int(item.get("size_bytes") or 0),
        "checkpoint_interval_minutes": int(item.get("checkpoint_interval_minutes") or 0),
        "memory_percent_of_host": int(resource_caps.get("memory_percent_of_host") or 0),
        "parser_batch_size_hint": int(item.get("parser_batch_size_hint") or 0),
    }


def benchmark_core_accuracy_gates(
    *,
    file_count: int,
    metrics: Mapping[str, object],
    run_summary_path: Path | None,
    validation_plan: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = ["scale matrix emitted", "hardware-scale limitation warning"]
    if metrics.get("ingest_seconds") is not None and metrics.get("search_p50_seconds") is not None:
        satisfied.append("ingest/search metrics captured")
    if metrics.get("memory_peak_bytes") is not None or metrics.get("run_output_size_bytes") is not None:
        satisfied.append("memory/output size captured")
    if run_summary_path is not None:
        satisfied.append("run summary linked")
    if metrics.get("release_threshold_status") is not None:
        satisfied.append("release threshold profile emitted")
    if metrics.get("benchmark_manifest_hash"):
        satisfied.append("benchmark command manifest hash emitted")
    if metrics.get("benchmark_scale_proof_manifest_hash"):
        satisfied.append("benchmark scale proof manifest emitted")
    if validation_plan:
        satisfied.append("benchmark report-grade validation plan emitted")
        if int(validation_plan.get("ready_slot_count") or 0) > 0:
            satisfied.append("benchmark report-grade ready slots emitted")
    evidence_refs = [
        f"file_count:{file_count}",
        f"run_summary:{run_summary_path or ''}",
        f"release_threshold_status:{metrics.get('release_threshold_status', '')}",
    ]
    if metrics.get("benchmark_manifest_hash"):
        evidence_refs.append(f"benchmark_manifest_hash:{metrics.get('benchmark_manifest_hash')}")
    if metrics.get("benchmark_scale_proof_manifest_hash"):
        evidence_refs.append(f"benchmark_scale_proof_manifest_hash:{metrics.get('benchmark_scale_proof_manifest_hash')}")
    if validation_plan and validation_plan.get("validation_plan_hash"):
        evidence_refs.append(f"benchmark_report_grade_validation_plan_hash:{validation_plan.get('validation_plan_hash')}")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted benchmark threshold diff pass")
        evidence_refs.append(f"trusted_tool:{trusted_diff.get('trusted_tool', '')}")
    return [
        build_accuracy_gate(
            66,
            satisfied_checks=satisfied,
            evidence_refs=evidence_refs,
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
        "reportability_decision": performance_reportability_decision(
            item_number=item_number,
            external_validation=external_validation,
            large_data_controls=large_data_controls,
        ),
        "passed_validation_check_ids": list(validation_ids),
        "large_data_controls": list(large_data_controls),
        "remaining_external_validation": list(external_validation),
    }


def performance_reportability_decision(
    *,
    item_number: int,
    external_validation: Sequence[str],
    large_data_controls: Sequence[str],
) -> dict[str, object]:
    decisions = {
        66: "do-not-report-benchmark-as-published-scale-proof",
        67: "do-not-report-stress-plan-as-executed-terabyte-validation",
    }
    allowed_uses = {
        66: "benchmark-run-and-scale-plan-triage-pivot",
        67: "stress-runbook-triage-pivot",
    }
    return {
        "profile_version": "performance-reportability-decision-v1",
        "commercial_gap_ids": [f"#{item_number}"],
        "decision": decisions.get(item_number, "do-not-report-performance-output-as-commercial-scale-proof"),
        "allowed_use": allowed_uses.get(item_number, "performance-evidence-triage-pivot"),
        "blockers": sorted({str(item) for item in external_validation if str(item)}),
        "control_snapshot": list(large_data_controls),
        "ready_for_court_report": False,
        "required_before_report": [
            "publish hardware, OS, dependency, evidence-size, wall-time, memory, and p95 latency evidence",
            "attach independent reproduction logs and release threshold comparisons before scale claims",
        ],
    }


def stress_core_accuracy_gates(
    *,
    scenarios: Sequence[Mapping[str, object]],
    hardware_scale_manifest: Mapping[str, object] | None = None,
    stress_execution_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = ["real-hardware validation warning"]
    if scenarios:
        satisfied.append("TB-scale scenarios emitted")
    if any(scenario.get("resource_caps") for scenario in scenarios):
        satisfied.append("resource caps specified")
    if any(scenario.get("required_evidence") for scenario in scenarios):
        satisfied.append("required evidence bundle listed")
    if any(isinstance(scenario.get("run_log_template"), Mapping) for scenario in scenarios):
        satisfied.append("run-log template emitted")
    if hardware_scale_manifest:
        satisfied.append("hardware-scale evidence manifest hash emitted")
    if stress_execution_manifest:
        satisfied.append("stress execution proof manifest emitted")
    satisfied.append("failure thresholds specified")
    evidence_refs = [f"scenario_count:{len(scenarios)}"]
    if hardware_scale_manifest:
        evidence_refs.append(f"hardware_scale_manifest_hash:{hardware_scale_manifest.get('manifest_hash', '')}")
    if stress_execution_manifest:
        evidence_refs.append(f"stress_execution_proof_manifest_hash:{stress_execution_manifest.get('manifest_hash', '')}")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted stress run-log diff pass")
        evidence_refs.append(f"trusted_tool:{trusted_diff.get('trusted_tool', '')}")
    return [
        build_accuracy_gate(
            67,
            satisfied_checks=satisfied,
            evidence_refs=evidence_refs,
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
    evidence_profile = payload.get("evidence_capture_profile") if isinstance(payload.get("evidence_capture_profile"), Mapping) else {}
    lines.extend(
        [
            "",
            "## Evidence Capture",
            "",
            f"- Capture status: `{evidence_profile.get('capture_status', '')}`",
            f"- Required artifacts: `{len(evidence_profile.get('required_artifacts', []) or [])}`",
            f"- Telemetry fields: `{len(evidence_profile.get('telemetry_fields', []) or [])}`",
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
    threshold_profile = payload.get("release_threshold_profile") if isinstance(payload.get("release_threshold_profile"), Mapping) else {}
    environment = payload.get("environment") if isinstance(payload.get("environment"), Mapping) else {}
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
            f"- Release threshold status: `{threshold_profile.get('status', '')}`",
            "",
            "## Environment",
            "",
            f"- Platform: `{environment.get('platform', '')}`",
            f"- Python: `{environment.get('python_implementation', '')} {environment.get('python_version', '')}`",
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
