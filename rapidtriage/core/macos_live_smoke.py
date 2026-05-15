from __future__ import annotations

import datetime as dt
import hashlib
import platform
import shutil
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable, Mapping

from ..artifacts.macos import (
    USER_TCC_DB,
    collect_launch_agents,
    collect_macos_browsers,
    collect_quarantine_events,
    collect_tcc_permissions,
)
from .benchmark import DEFAULT_BENCHMARK_KEYWORD, run_benchmark
from .benchmark_fts import run_sqlite_fts_benchmark
from .collect_plan import build_collect_plan
from .docs import write_result
from .large_case_readiness import build_large_case_readiness_report


MACOS_LIVE_SMOKE_VERSION = "macos-live-smoke-v1"
DEFAULT_MACOS_SMOKE_BENCHMARK_FILES = 150
DEFAULT_MACOS_SMOKE_FTS_RECORDS = 2_000
DEFAULT_MACOS_SMOKE_KEYWORD = DEFAULT_BENCHMARK_KEYWORD
MACOS_LIVE_SOURCE_HASH_MAX_BYTES = 256 * 1024 * 1024


class MacOsLiveSmokeError(ValueError):
    """Raised when a macOS live smoke run cannot be executed safely."""


def run_macos_live_smoke(
    *,
    output_dir: Path,
    root: Path = Path("/"),
    home: Path | None = None,
    benchmark_file_count: int = DEFAULT_MACOS_SMOKE_BENCHMARK_FILES,
    fts_record_count: int = DEFAULT_MACOS_SMOKE_FTS_RECORDS,
    keyword: str = DEFAULT_MACOS_SMOKE_KEYWORD,
    overwrite: bool = False,
    include_path_details: bool = False,
) -> dict[str, object]:
    output_dir = output_dir.expanduser().resolve()
    if output_dir.exists() and any(output_dir.iterdir()) and not overwrite:
        raise MacOsLiveSmokeError(f"macOS smoke output directory is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    cleanup_owned_outputs(output_dir, overwrite=overwrite)

    root_path = root.expanduser().resolve()
    home_path = (home or Path.home()).expanduser().resolve()
    normalized_keyword = keyword.strip() or DEFAULT_MACOS_SMOKE_KEYWORD

    collect_plan = build_collect_plan(root_path, profile="macos-core")
    artifact_summary = summarize_live_macos_artifacts(home_path, include_path_details=include_path_details)
    benchmark_payload = run_benchmark(
        output_dir=output_dir / "triage-benchmark",
        file_count=benchmark_file_count,
        keyword=normalized_keyword,
        search_iterations=2,
        overwrite=True,
    )
    fts_payload = run_sqlite_fts_benchmark(
        output_dir=output_dir / "sqlite-fts-benchmark",
        record_count=fts_record_count,
        keyword=normalized_keyword,
        query_iterations=3,
        overwrite=True,
    )
    large_case_readiness = build_large_case_readiness_report(
        benchmark_paths=[Path(str(fts_payload.get("outputs", {}).get("json", "")))],
        keyword=normalized_keyword,
        output=output_dir / "large-case-readiness.json",
    )
    external_tools = external_validation_tool_profile()
    checks = build_macos_smoke_checks(
        collect_plan=collect_plan,
        artifact_summary=artifact_summary,
        benchmark_payload=benchmark_payload,
        fts_payload=fts_payload,
        external_tools=external_tools,
    )
    payload: dict[str, object] = {
        "command": "macos-live-smoke",
        "profile_version": MACOS_LIVE_SMOKE_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "output_dir": str(output_dir),
        "inputs": {
            "root_path_hash": hash_text(str(root_path)),
            "home_path_hash": hash_text(str(home_path)),
            "path_details_included": include_path_details,
            **({"root": str(root_path), "home": str(home_path)} if include_path_details else {}),
        },
        "environment": environment_profile(),
        "collect_plan_summary": collect_plan.get("summary", {}),
        "macos_artifact_summary": artifact_summary,
        "performance_summary": {
            "triage_benchmark": benchmark_payload.get("metrics", {}),
            "sqlite_fts": fts_payload.get("metrics", {}),
        },
        "large_case_readiness": large_case_readiness,
        "external_validation_tools": external_tools,
        "checks": checks,
        "summary": summarize_checks(checks),
        "commercial_grade_blockers": macos_live_commercial_blockers(checks=checks, external_tools=external_tools),
        "outputs": {
            "json": str(output_dir / "macos-live-smoke.json"),
            "markdown": str(output_dir / "macos-live-smoke.md"),
            "triage_benchmark_json": str(benchmark_payload.get("outputs", {}).get("json", "")),
            "sqlite_fts_json": str(fts_payload.get("outputs", {}).get("json", "")),
            "large_case_readiness_json": str(output_dir / "large-case-readiness.json"),
        },
    }
    write_result(payload, output_dir / "macos-live-smoke.json")
    (output_dir / "macos-live-smoke.md").write_text(render_macos_live_smoke_markdown(payload), encoding="utf-8")
    return payload


def cleanup_owned_outputs(output_dir: Path, *, overwrite: bool) -> None:
    if not overwrite:
        return
    for name in (
        "macos-live-smoke.json",
        "macos-live-smoke.md",
        "large-case-readiness.json",
        "triage-benchmark",
        "sqlite-fts-benchmark",
    ):
        path = output_dir / name
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()


def summarize_live_macos_artifacts(home_path: Path, *, include_path_details: bool) -> dict[str, object]:
    records = []
    errors = []
    collectors = (
        ("browser", lambda: collect_macos_browsers(home_path)),
        ("quarantine", lambda: collect_quarantine_events(home_path)),
        ("launch-agent", lambda: collect_launch_agents(home_path)),
        ("tcc-user", lambda: collect_tcc_permissions(home_path.joinpath(*USER_TCC_DB), owner=home_path.name, scope="user")),
    )
    for collector_name, collector in collectors:
        try:
            records.extend(list(collector()))
        except (OSError, PermissionError, RuntimeError, ValueError) as exc:
            errors.append({"collector": collector_name, "error": str(exc)})

    artifact_type_counts = Counter(record.artifact_type for record in records)
    source_counts = Counter(str(record.path) for record in records if record.path)
    source_profiles = [
        build_redacted_source_profile(source_path, count=count, include_path_details=include_path_details)
        for source_path, count in source_counts.most_common(50)
    ]
    return {
        "home_exists": home_path.exists(),
        "home_is_dir": home_path.is_dir(),
        "collector_count": len(collectors),
        "record_count": len(records),
        "artifact_type_counts": dict(sorted(artifact_type_counts.items())),
        "source_count": len(source_counts),
        "source_profiles": source_profiles,
        "row_hints": summarize_record_row_hints(records),
        "errors": errors,
        "redaction": {
            "raw_paths_included": include_path_details,
            "browser_urls_included": False,
            "quarantine_urls_included": False,
            "tcc_clients_included": False,
            "policy": "Live smoke stores counts and source hashes by default; rerun with --include-path-details only for authorized local debugging.",
        },
    }


def summarize_record_row_hints(records: Iterable[object]) -> dict[str, int]:
    hints: Counter[str] = Counter()
    for record in records:
        details = getattr(record, "details", {}) if record else {}
        if not isinstance(details, Mapping):
            continue
        hints["records"] += 1
        if isinstance(details.get("history"), list):
            hints["browser_history_rows"] += len(details["history"])
        if isinstance(details.get("downloads"), list):
            hints["browser_download_rows"] += len(details["downloads"])
        if details.get("parser") == "macos-quarantine-events":
            hints["quarantine_rows"] += 1
        if details.get("parser") == "macos-tcc-db":
            hints["tcc_rows"] += 1
            if details.get("allowed") is True:
                hints["tcc_allowed_rows"] += 1
        if details.get("parser") == "macos-launch-agent-plist":
            hints["launch_agent_rows"] += 1
    return dict(sorted(hints.items()))


def build_redacted_source_profile(source_path: str, *, count: int, include_path_details: bool) -> dict[str, object]:
    path = Path(source_path)
    profile: dict[str, object] = {
        "source_path_hash": hash_text(source_path),
        "basename": path.name,
        "record_count": count,
        "exists": path.exists(),
    }
    if path.is_file():
        try:
            size = path.stat().st_size
            profile["size"] = size
            if size <= MACOS_LIVE_SOURCE_HASH_MAX_BYTES:
                profile["sha256"] = sha256_file(path)
            else:
                profile["sha256_skipped_reason"] = "source-file-exceeds-live-smoke-hash-cap"
                profile["sha256_hash_cap_bytes"] = MACOS_LIVE_SOURCE_HASH_MAX_BYTES
        except OSError:
            profile["stat_error"] = "stat-failed"
    if include_path_details:
        profile["source_path"] = source_path
    return profile


def external_validation_tool_profile() -> dict[str, object]:
    tool_specs = {
        "macos_log": "log",
        "macos_mdfind": "mdfind",
        "sqlite3": "sqlite3",
        "plutil": "plutil",
        "xattr": "xattr",
        "evtxecmd": "EvtxECmd",
        "hayabusa": "hayabusa",
        "recmd": "RECmd",
        "mftecmd": "MFTECmd",
        "srumecmd": "SrumECmd",
    }
    tools = {}
    for name, executable in tool_specs.items():
        resolved = shutil.which(executable)
        tools[name] = {
            "executable": executable,
            "available": bool(resolved),
            "path_hash": hash_text(resolved or ""),
        }
    forensic_keys = {"evtxecmd", "hayabusa", "recmd", "mftecmd", "srumecmd"}
    return {
        "profile_version": "external-validation-tool-availability-v1",
        "tools": tools,
        "available_count": sum(1 for item in tools.values() if item["available"]),
        "forensic_tool_available_count": sum(1 for key, item in tools.items() if key in forensic_keys and item["available"]),
        "disclosure": "Availability alone is not validation; attach tool output and row-level diffs before report-grade claims.",
    }


def build_macos_smoke_checks(
    *,
    collect_plan: Mapping[str, object],
    artifact_summary: Mapping[str, object],
    benchmark_payload: Mapping[str, object],
    fts_payload: Mapping[str, object],
    external_tools: Mapping[str, object],
) -> list[dict[str, object]]:
    collect_summary = collect_plan.get("summary", {}) if isinstance(collect_plan.get("summary"), Mapping) else {}
    benchmark_metrics = benchmark_payload.get("metrics", {}) if isinstance(benchmark_payload.get("metrics"), Mapping) else {}
    fts_summary = fts_payload.get("summary", {}) if isinstance(fts_payload.get("summary"), Mapping) else {}
    return [
        make_check("darwin-platform", platform.system().lower() == "darwin", platform.platform()),
        make_check("macos-collect-plan-present", int(collect_summary.get("present_count") or 0) > 0, str(collect_summary)),
        make_check("macos-live-artifacts-seen", int(artifact_summary.get("record_count") or 0) > 0, str(artifact_summary.get("artifact_type_counts") or {})),
        make_check("triage-benchmark-ran", float(benchmark_metrics.get("ingest_seconds") or 0) > 0, str(benchmark_metrics)),
        make_check("sqlite-fts-returned-hits", bool(fts_summary.get("expected_counts_match")), str(fts_summary)),
        make_check("platform-validation-tools-present", int(external_tools.get("available_count") or 0) >= 3, str(external_tools.get("available_count"))),
        make_check("forensic-cross-tool-ready", int(external_tools.get("forensic_tool_available_count") or 0) > 0, str(external_tools.get("forensic_tool_available_count"))),
    ]


def make_check(check_id: str, passed: bool, detail: str = "") -> dict[str, object]:
    return {"id": check_id, "passed": bool(passed), "detail": detail}


def summarize_checks(checks: list[Mapping[str, object]]) -> dict[str, object]:
    passed = sum(1 for check in checks if check.get("passed") is True)
    failed = len(checks) - passed
    return {
        "check_count": len(checks),
        "passed_count": passed,
        "failed_count": failed,
        "local_smoke_score": round((passed / len(checks)) * 100, 2) if checks else 0,
        "failed_check_ids": [str(check.get("id")) for check in checks if check.get("passed") is not True],
    }


def macos_live_commercial_blockers(*, checks: list[Mapping[str, object]], external_tools: Mapping[str, object]) -> list[str]:
    blockers = [str(check.get("id")) for check in checks if check.get("passed") is not True]
    if int(external_tools.get("forensic_tool_available_count") or 0) == 0:
        blockers.append("trusted-forensic-cross-tool-output-missing")
    blockers.extend(
        [
            "windows-e01-real-image-validation-not-run",
            "large-case-1tb-10tb-hardware-run-not-run",
            "independent-lab-signoff-not-attached",
        ]
    )
    return sorted(set(blockers))


def render_macos_live_smoke_markdown(payload: Mapping[str, object]) -> str:
    summary = payload.get("summary", {}) if isinstance(payload.get("summary"), Mapping) else {}
    artifact_summary = payload.get("macos_artifact_summary", {}) if isinstance(payload.get("macos_artifact_summary"), Mapping) else {}
    large_case = payload.get("large_case_readiness", {}) if isinstance(payload.get("large_case_readiness"), Mapping) else {}
    large_case_summary = large_case.get("summary", {}) if isinstance(large_case.get("summary"), Mapping) else {}
    redaction = artifact_summary.get("redaction", {}) if isinstance(artifact_summary.get("redaction"), Mapping) else {}
    lines = [
        "# RapidTriage macOS Live Smoke",
        "",
        f"- Generated: `{payload.get('generated_at', '')}`",
        f"- Local smoke score: `{summary.get('local_smoke_score', 0)}`",
        f"- Passed checks: `{summary.get('passed_count', 0)}/{summary.get('check_count', 0)}`",
        f"- Live artifact records: `{artifact_summary.get('record_count', 0)}`",
        f"- Large-case readiness: `{large_case.get('status', 'not-run')}`",
        f"- Largest FTS benchmark: `{large_case_summary.get('largest_benchmark_record_count', 0)}` rows",
        f"- Redaction: `{redaction.get('policy', '')}`",
        "",
        "## Failed Checks",
    ]
    failed = summary.get("failed_check_ids") if isinstance(summary.get("failed_check_ids"), list) else []
    if failed:
        lines.extend(f"- `{item}`" for item in failed)
    else:
        lines.append("- None")
    lines.extend(["", "## Commercial Blockers"])
    blockers = payload.get("commercial_grade_blockers") if isinstance(payload.get("commercial_grade_blockers"), list) else []
    lines.extend(f"- `{item}`" for item in blockers)
    return "\n".join(lines) + "\n"


def environment_profile() -> dict[str, object]:
    return {
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": sys.version.split()[0],
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()
