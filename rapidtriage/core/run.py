from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Mapping, Sequence, Union

from .audit import write_audit_record
from .archive_image import (
    ArchiveImageExtractionError,
    ArchiveImageExtractionResult,
    extract_archive_image_to_directory,
    is_archive_image_path,
)
from .artifacts import run_artifact_collection
from .disk_image import (
    DiskImageExtractionError,
    DiskImageExtractionResult,
    extract_raw_image_to_directory,
    is_raw_image_path,
)
from .docs import build_manifest, run_docs_search, write_result
from .e01 import E01ExtractionError, E01ExtractionResult, extract_e01_to_directory, is_e01_path
from .extract import DEFAULT_EXTRACT_MANIFEST_NAME, SUPPORTED_DOC_KINDS, run_extract
from .files import run_files_scan
from .forensic_accuracy import build_accuracy_gate
from .indicators import build_indicator_summary
from .input_root import InputRoot, derive_child_input_root, resolve_input_root
from .reporting import build_run_report_context, render_run_markdown_report
from .rules import RuleSet, summarize_payload_annotations
from .silent_failure import build_silent_failure_report
from .timeline import build_timeline_report, run_timeline
from .virtual_disk import (
    VirtualDiskExtractionError,
    VirtualDiskExtractionResult,
    extract_virtual_disk_to_directory,
    is_virtual_disk_path,
)

SUPPORTED_RUN_MODES: tuple[str, ...] = ("seizure", "fraud", "hacking", "recovery")
IMPLEMENTED_RUN_MODES = set(SUPPORTED_RUN_MODES)
RUN_DOC_EXTRACT_KINDS = SUPPORTED_DOC_KINDS
PARSER_CRASH_ISOLATION_GAP_ID = "#71"
MEMORY_CAP_GAP_ID = "#72"
INCREMENTAL_INDEXING_GAP_ID = "#68"
CHECKPOINT_RESUME_GAP_ID = "#70"
PARALLEL_PARSER_SCHEDULER_GAP_ID = "#75"
MEMORY_CAP_ENV = "RAPIDTRIAGE_MEMORY_CAP_BYTES"


@dataclass(frozen=True)
class RunProfile:
    mode: str
    description: str
    keywords: tuple[str, ...]
    docs_extract_kinds: tuple[str, ...]
    file_extract_categories: tuple[str, ...]
    file_scan_categories: tuple[str, ...]
    file_scan_path_contains: tuple[str, ...] = ()
    scan_root_parts: tuple[str, ...] = ()
    preferred_locations: tuple[str, ...] = ()
    artifacts_kinds: tuple[str, ...] = ()


RUN_PROFILES: Dict[str, RunProfile] = {
    "seizure": RunProfile(
        mode="seizure",
        description="Seizure triage focused on user folders, recent modifications, and high-value documents, archives, and databases.",
        keywords=("seizure", "download", "desktop", "document", "archive", "database", "recent", "evidence"),
        docs_extract_kinds=RUN_DOC_EXTRACT_KINDS,
        file_extract_categories=("documents", "archives", "databases", "emails", "disk-images", "mobile-images", "vehicle-images"),
        file_scan_categories=(
            "documents",
            "archives",
            "databases",
            "emails",
            "disk-images",
            "mobile-images",
            "memory-dumps",
            "vehicle-images",
            "images",
        ),
        scan_root_parts=("Users",),
        preferred_locations=("downloads", "desktop", "documents"),
        artifacts_kinds=(
            "browser",
            "recent-files",
            "windows-os-account",
            "eventlog",
            "windows-search-index",
            "windows-remote-access",
            "windows-execution",
            "windows-prefetch",
            "windows-filesystem",
            "windows-system",
            "linux-system",
            "macos-system",
        ),
    ),
    "fraud": RunProfile(
        mode="fraud",
        description="Document-forward fraud triage focused on payment, account, and invoice evidence.",
        keywords=("fraud", "invoice", "payment", "transfer", "bank", "account", "receipt", "refund"),
        docs_extract_kinds=RUN_DOC_EXTRACT_KINDS,
        file_extract_categories=("documents", "archives", "databases", "emails", "mobile-images"),
        file_scan_categories=("documents", "archives", "databases", "emails", "mobile-images", "images"),
        artifacts_kinds=(
            "browser",
            "recent-files",
            "windows-os-account",
            "eventlog",
            "windows-search-index",
            "windows-remote-access",
            "windows-execution",
            "windows-prefetch",
            "windows-filesystem",
            "windows-system",
            "linux-system",
            "macos-system",
        ),
    ),
    "hacking": RunProfile(
        mode="hacking",
        description="Intrusion triage focused on suspicious binaries, credential theft, persistence, and attacker tooling.",
        keywords=("hacking", "malware", "credential", "powershell", "persistence", "ransomware", "shell", "exfil"),
        docs_extract_kinds=RUN_DOC_EXTRACT_KINDS,
        file_extract_categories=("executables", "archives", "databases", "documents", "emails", "memory-dumps"),
        file_scan_categories=("executables", "archives", "databases", "documents", "emails", "memory-dumps", "images"),
        artifacts_kinds=(
            "browser",
            "recent-files",
            "windows-os-account",
            "eventlog",
            "windows-search-index",
            "windows-remote-access",
            "windows-execution",
            "windows-prefetch",
            "windows-filesystem",
            "windows-system",
            "linux-system",
            "macos-system",
        ),
    ),
    "recovery": RunProfile(
        mode="recovery",
        description="Recovery triage focused on deleted, recycled, or restorable file candidates without doing carving.",
        keywords=("recovery", "deleted", "recycle", "trash", "restore", "backup", "recent"),
        docs_extract_kinds=RUN_DOC_EXTRACT_KINDS,
        file_extract_categories=("documents", "archives", "images", "emails", "disk-images", "mobile-images", "vehicle-images"),
        file_scan_categories=(
            "documents",
            "archives",
            "images",
            "emails",
            "disk-images",
            "mobile-images",
            "memory-dumps",
            "vehicle-images",
        ),
        file_scan_path_contains=("recycle",),
        preferred_locations=("$recycle.bin", "recycle", "trash", "deleted"),
        artifacts_kinds=(
            "recent-files",
            "windows-os-account",
            "eventlog",
            "windows-search-index",
            "windows-remote-access",
            "windows-prefetch",
            "windows-filesystem",
            "linux-system",
            "macos-system",
        ),
    ),
}


class RunModeError(ValueError):
    """Raised when the requested run mode is invalid or unsupported."""


def run_triage_mode(
    root: Union[InputRoot, Path],
    *,
    mode: str,
    output_dir: Path,
    input_kind: str | None = None,
    dry_run: bool = False,
    read_only: bool = False,
    max_extract_size_bytes: int = 0,
    max_file_count: int = 0,
    memory_cap_bytes: int = 0,
    overwrite: bool = False,
    resume: bool = False,
    rule_set: RuleSet | None = None,
) -> Dict[str, object]:
    normalized_mode = mode.lower()
    if normalized_mode not in SUPPORTED_RUN_MODES:
        supported = ", ".join(SUPPORTED_RUN_MODES)
        raise RunModeError(f"unsupported run mode: {mode} (supported: {supported})")
    if normalized_mode not in IMPLEMENTED_RUN_MODES:
        available = ", ".join(sorted(IMPLEMENTED_RUN_MODES))
        raise RunModeError(f"run mode '{normalized_mode}' is not implemented yet (currently available: {available})")

    profile = RUN_PROFILES[normalized_mode]
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    effective_memory_cap = resolve_memory_cap_bytes(memory_cap_bytes)
    enforce_memory_cap("prepare", effective_memory_cap)
    input_root, image_result = prepare_run_input_root(root, input_kind=input_kind, output_dir=output_dir)
    scan_root = resolve_scan_root(input_root.root_path, profile)
    scan_input_root = derive_child_input_root(input_root, scan_root)

    manifest_path = output_dir / "rapidtriage-manifest.json"
    docs_path = output_dir / "rapidtriage-docs.json"
    docs_index_path = output_dir / "rapidtriage-docs-index.json"
    files_path = output_dir / "rapidtriage-files.json"
    artifacts_dir = output_dir / "artifacts"
    docs_extract_dir = output_dir / "docs-extract"
    files_extract_dir = output_dir / "files-extract"
    docs_extract_manifest = docs_extract_dir / DEFAULT_EXTRACT_MANIFEST_NAME
    files_extract_manifest = files_extract_dir / DEFAULT_EXTRACT_MANIFEST_NAME
    timeline_path = output_dir / "rapidtriage-timeline.json"
    timeline_report_path = output_dir / "rapidtriage-timeline-report.md"
    indicators_path = output_dir / "rapidtriage-indicators.json"
    summary_path = output_dir / "rapidtriage-run-summary.json"
    report_path = output_dir / "rapidtriage-run-report.md"
    e01_metadata_path = output_dir / "rapidtriage-e01.json"
    disk_image_metadata_path = output_dir / "rapidtriage-disk-image.json"
    archive_image_metadata_path = output_dir / "rapidtriage-archive-image.json"
    virtual_disk_metadata_path = output_dir / "rapidtriage-virtual-disk.json"
    fingerprint_path = output_dir / "rapidtriage-run-fingerprint.json"
    checkpoint_path = output_dir / "rapidtriage-run-checkpoints.json"

    if isinstance(image_result, E01ExtractionResult):
        write_result(image_result.to_dict(), e01_metadata_path)
    if isinstance(image_result, DiskImageExtractionResult):
        write_result(image_result.to_dict(), disk_image_metadata_path)
    if isinstance(image_result, ArchiveImageExtractionResult):
        write_result(image_result.to_dict(), archive_image_metadata_path)
    if isinstance(image_result, VirtualDiskExtractionResult):
        write_result(image_result.to_dict(), virtual_disk_metadata_path)

    current_fingerprint = build_run_input_fingerprint(scan_root)
    enforce_memory_cap("fingerprint", effective_memory_cap)
    previous_fingerprint = (
        load_reusable_json(
            fingerprint_path,
            expected_command="run-fingerprint",
            required_keys=("fingerprint",),
        )
        if fingerprint_path.is_file()
        else None
    )
    resume_disabled_reason = ""
    effective_resume = resume
    if resume and previous_fingerprint and previous_fingerprint.get("fingerprint") != current_fingerprint.get("fingerprint"):
        effective_resume = False
        resume_disabled_reason = "input fingerprint changed; rebuilding stage outputs"
        current_fingerprint["core_accuracy_gates"] = incremental_indexing_core_accuracy_gates(
            scanned_files=int(current_fingerprint.get("summary", {}).get("scanned_file_count", 0))
            if isinstance(current_fingerprint.get("summary"), Mapping)
            else 0,
            max_files=int(current_fingerprint.get("summary", {}).get("max_files", 0))
            if isinstance(current_fingerprint.get("summary"), Mapping)
            else 0,
            truncated=bool(current_fingerprint.get("summary", {}).get("truncated", False))
            if isinstance(current_fingerprint.get("summary"), Mapping)
            else False,
            fingerprint=str(current_fingerprint.get("fingerprint") or ""),
            reuse_disabled=True,
        )
    write_result(current_fingerprint, fingerprint_path)

    reused_outputs: set[str] = set()
    checkpoint_records: list[dict[str, object]] = []

    manifest_payload, reused = load_or_build_json(
        manifest_path,
        resume=effective_resume,
        required_keys=("providers",),
        producer=lambda: build_manifest(input_root, profile.keywords),
    )
    if reused:
        reused_outputs.add("manifest")
    record_run_checkpoint(checkpoint_records, "manifest", manifest_path, reused=reused)
    enforce_memory_cap("manifest", effective_memory_cap)

    docs_payload, reused = load_or_build_json(
        docs_path,
        resume=effective_resume and docs_index_path.is_file(),
        expected_command="docs",
        required_keys=("summary", "results"),
        producer=lambda: run_docs_search(scan_input_root, profile.keywords, rule_set=rule_set, index_output=docs_index_path),
    )
    if reused:
        reused_outputs.update({"docs", "docs-index"})
    record_run_checkpoint(checkpoint_records, "docs", docs_path, reused=reused)
    docs_payload["manifest"] = manifest_payload
    docs_payload["scan_scope_root"] = str(scan_input_root.root_path)
    enforce_memory_cap("docs", effective_memory_cap)

    files_payload, reused = load_or_build_json(
        files_path,
        resume=effective_resume,
        expected_command="files",
        required_keys=("summary", "candidates"),
        producer=lambda: run_files_scan(
            scan_input_root,
            categories=profile.file_scan_categories,
            path_contains=profile.file_scan_path_contains or None,
            rule_set=rule_set,
        ),
    )
    if reused:
        reused_outputs.add("files")
    record_run_checkpoint(checkpoint_records, "files", files_path, reused=reused)
    files_payload["scan_scope_root"] = str(scan_input_root.root_path)
    enforce_memory_cap("files", effective_memory_cap)

    write_result(manifest_payload, manifest_path)
    write_result(docs_payload, docs_path)
    write_result(files_payload, files_path)

    artifact_outputs: Dict[str, Path] = {}
    artifact_payloads: Dict[str, Dict[str, object]] = {}
    artifact_results = collect_artifact_stages(
        input_root,
        profile.artifacts_kinds,
        artifacts_dir=artifacts_dir,
        resume=effective_resume,
        rule_set=rule_set,
    )
    for kind in profile.artifacts_kinds:
        artifact_payload, artifact_path, reused = artifact_results[kind]
        if reused:
            reused_outputs.add(f"artifacts-{kind}")
        record_run_checkpoint(checkpoint_records, f"artifacts-{kind}", artifact_path, reused=reused)
        artifact_outputs[kind] = artifact_path
        artifact_payloads[kind] = artifact_payload
        write_result(artifact_payload, artifact_path)
    enforce_memory_cap("artifacts", effective_memory_cap)

    docs_extract_payload, reused = load_or_build_json(
        docs_extract_manifest,
        resume=effective_resume,
        expected_command="extract",
        required_keys=("summary", "entries", "skipped"),
        producer=lambda: run_extract(
            docs_path,
            docs_extract_dir,
            kinds=profile.docs_extract_kinds,
            dry_run=dry_run,
            read_only=read_only,
            max_extract_size_bytes=max_extract_size_bytes,
            max_file_count=max_file_count,
            overwrite=overwrite,
        ),
    )
    if reused:
        reused_outputs.add("docs-extract")
    record_run_checkpoint(checkpoint_records, "docs-extract", docs_extract_manifest, reused=reused)
    files_extract_payload, reused = load_or_build_json(
        files_extract_manifest,
        resume=effective_resume,
        expected_command="extract",
        required_keys=("summary", "entries", "skipped"),
        producer=lambda: run_extract(
            files_path,
            files_extract_dir,
            categories=profile.file_extract_categories,
            dry_run=dry_run,
            read_only=read_only,
            max_extract_size_bytes=max_extract_size_bytes,
            max_file_count=max_file_count,
            overwrite=overwrite,
        ),
    )
    if reused:
        reused_outputs.add("files-extract")
    record_run_checkpoint(checkpoint_records, "files-extract", files_extract_manifest, reused=reused)
    write_result(docs_extract_payload, docs_extract_manifest)
    write_result(files_extract_payload, files_extract_manifest)
    enforce_memory_cap("extract", effective_memory_cap)

    timeline_payload, reused = load_or_build_json(
        timeline_path,
        resume=effective_resume,
        expected_command="timeline",
        required_keys=("summary", "events"),
        producer=lambda: run_timeline(
            root=input_root.root_path,
            input_kind=input_root.kind,
            files_inputs=[files_path],
            docs_inputs=[docs_path],
            artifacts_inputs=list(artifact_outputs.values()),
            rule_set=rule_set,
        ),
    )
    if reused:
        reused_outputs.add("timeline")
    record_run_checkpoint(checkpoint_records, "timeline", timeline_path, reused=reused)
    write_result(timeline_payload, timeline_path)
    timeline_report_path.write_text(build_timeline_report(timeline_payload), encoding="utf-8")
    enforce_memory_cap("timeline", effective_memory_cap)

    provisional_outputs = {
        "manifest": manifest_path,
        "docs": docs_path,
        "docs_index": docs_index_path,
        "files": files_path,
        "docs_extract_manifest": docs_extract_manifest,
        "files_extract_manifest": files_extract_manifest,
        "timeline": timeline_path,
        "timeline_report": timeline_report_path,
        **{f"artifacts_{kind}": path for kind, path in artifact_outputs.items()},
    }
    indicators_payload, reused = load_or_build_json(
        indicators_path,
        resume=effective_resume,
        expected_command="indicators",
        required_keys=("summary", "indicators"),
        producer=lambda: build_indicator_summary(
            {"outputs": {key: str(path) for key, path in provisional_outputs.items()}},
            rule_set=rule_set,
        ),
    )
    if reused:
        reused_outputs.add("indicators")
    record_run_checkpoint(checkpoint_records, "indicators", indicators_path, reused=reused)
    write_result(indicators_payload, indicators_path)
    enforce_memory_cap("indicators", effective_memory_cap)
    write_run_checkpoints(
        checkpoint_path,
        output_dir=output_dir,
        input_fingerprint=current_fingerprint,
        resume_requested=resume,
        resume_effective=effective_resume,
        resume_disabled_reason=resume_disabled_reason,
        checkpoints=checkpoint_records,
    )

    outputs = {
        "fingerprint": fingerprint_path,
        "checkpoints": checkpoint_path,
        "manifest": manifest_path,
        "docs": docs_path,
        "docs_index": docs_index_path,
        "files": files_path,
        "docs_extract_manifest": docs_extract_manifest,
        "files_extract_manifest": files_extract_manifest,
        "timeline": timeline_path,
        "timeline_report": timeline_report_path,
        "indicators": indicators_path,
        **{f"artifacts_{kind}": path for kind, path in artifact_outputs.items()},
        "summary": summary_path,
        "report": report_path,
    }
    if isinstance(image_result, E01ExtractionResult):
        outputs = {"e01": e01_metadata_path, **outputs}
    if isinstance(image_result, DiskImageExtractionResult):
        outputs = {"disk_image": disk_image_metadata_path, **outputs}
    if isinstance(image_result, ArchiveImageExtractionResult):
        outputs = {"archive_image": archive_image_metadata_path, **outputs}
    if isinstance(image_result, VirtualDiskExtractionResult):
        outputs = {"virtual_disk": virtual_disk_metadata_path, **outputs}
    summary_payload = build_run_summary(
        root=input_root.root_path,
        output_dir=output_dir,
        profile=profile,
        manifest_payload=manifest_payload,
        docs_payload=docs_payload,
        files_payload=files_payload,
        docs_extract_payload=docs_extract_payload,
        files_extract_payload=files_extract_payload,
        artifact_payloads=artifact_payloads,
        timeline_payload=timeline_payload,
        indicators_payload=indicators_payload,
        outputs=outputs,
        safety={
            "dry_run": dry_run,
            "read_only": read_only,
            "max_extract_size_bytes": max_extract_size_bytes,
            "max_file_count": max_file_count,
            "memory_cap_bytes": effective_memory_cap,
            "memory_cap_source": "argument"
            if memory_cap_bytes
            else ("environment" if os.environ.get(MEMORY_CAP_ENV) else "unset"),
            "overwrite": overwrite,
            "resume": resume,
            "resume_effective": effective_resume,
            "resume_disabled_reason": resume_disabled_reason,
            "reused_outputs": sorted(reused_outputs),
            "artifact_scheduler": {
                "strategy": "parallel-threaded-deterministic-output",
                "max_workers": artifact_scheduler_workers(profile.artifacts_kinds),
                "scheduled_count": len(profile.artifacts_kinds),
                "commercial_gap_ids": [PARALLEL_PARSER_SCHEDULER_GAP_ID],
                "assessment": parallel_parser_scheduler_assessment(profile.artifacts_kinds),
            },
        },
        rule_set=rule_set,
        source=build_run_source_record(input_root, image_result=image_result),
    )
    audit_output = output_dir / "rapidtriage-run-audit.json"
    summary_payload["audit"] = str(audit_output)
    report_path.write_text(
        build_markdown_report(
            summary_payload,
            docs_payload=docs_payload,
            files_payload=files_payload,
            docs_extract_payload=docs_extract_payload,
            files_extract_payload=files_extract_payload,
            artifact_payloads=artifact_payloads,
            timeline_payload=timeline_payload,
            indicators_payload=indicators_payload,
        ),
        encoding="utf-8",
    )
    write_result(summary_payload, summary_path)
    write_audit_record(
        audit_output,
        command="run",
        options={
            "mode": normalized_mode,
            "output_dir": str(output_dir),
            "input_kind": input_root.kind,
            "scan_scope_root": str(scan_input_root.root_path),
            "rules": rule_set.path if rule_set else None,
            "dry_run": dry_run,
            "read_only": read_only,
            "max_extract_size_bytes": max_extract_size_bytes,
            "max_file_count": max_file_count,
            "memory_cap_bytes": effective_memory_cap,
            "overwrite": overwrite,
            "resume": resume,
            "reused_outputs": sorted(reused_outputs),
            "image_source": str(image_result.source_path) if image_result else None,
            "image_extracted_root": str(image_result.extract_dir) if image_result else None,
            "image_extraction_command": str(image_result.to_dict().get("command")) if image_result else None,
        },
        input_root=input_root,
        input_files=[("image-source", image_result.source_path)] if image_result else [],
        output_files=[
            *([("e01-metadata", e01_metadata_path)] if isinstance(image_result, E01ExtractionResult) else []),
            *(
                [("disk-image-metadata", disk_image_metadata_path)]
                if isinstance(image_result, DiskImageExtractionResult)
                else []
            ),
            *(
                [("archive-image-metadata", archive_image_metadata_path)]
                if isinstance(image_result, ArchiveImageExtractionResult)
                else []
            ),
            *(
                [("virtual-disk-metadata", virtual_disk_metadata_path)]
                if isinstance(image_result, VirtualDiskExtractionResult)
                else []
            ),
            ("manifest", manifest_path),
            ("docs", docs_path),
            ("docs-index", docs_index_path),
            ("files", files_path),
            ("docs-extract-manifest", docs_extract_manifest),
            ("files-extract-manifest", files_extract_manifest),
            ("timeline-json", timeline_path),
            ("timeline-report", timeline_report_path),
            *[(f"artifacts-{kind}", path) for kind, path in artifact_outputs.items()],
            ("run-summary", summary_path),
            ("run-report", report_path),
            *[
                (f"docs-extract:{entry['relative_path']}", Path(entry["extracted_path"]).resolve())
                for entry in docs_extract_payload.get("entries", [])
            ],
            *[
                (f"files-extract:{entry['relative_path']}", Path(entry["extracted_path"]).resolve())
                for entry in files_extract_payload.get("entries", [])
            ],
        ],
    )
    return summary_payload


def load_or_build_json(
    path: Path,
    *,
    resume: bool,
    producer,
    expected_command: str | None = None,
    required_keys: Sequence[str] = (),
) -> tuple[Dict[str, object], bool]:
    if resume:
        payload = load_reusable_json(path, expected_command=expected_command, required_keys=required_keys)
        if payload is not None:
            return payload, True
    return producer(), False


def artifact_scheduler_workers(kinds: Sequence[str]) -> int:
    return max(1, min(4, len(tuple(kinds))))


def parallel_parser_scheduler_assessment(kinds: Sequence[str]) -> dict[str, object]:
    scheduled = len(tuple(kinds))
    satisfied = ["distributed scheduler limitation warning"]
    if scheduled:
        satisfied.extend(
            [
                "bounded worker count",
                "deterministic output paths",
                "per-parser result capture",
                "resume-aware scheduling",
            ]
        )
    return {
        "component": "parallel-parser-scheduler",
        "status": "threaded-parser-stage-scheduler-enabled",
        "commercial_gap_ids": [PARALLEL_PARSER_SCHEDULER_GAP_ID],
        "scheduled_count": scheduled,
        "max_workers": artifact_scheduler_workers(kinds),
        "ready_for_court_report": False,
        "core_accuracy_gates": [
            build_accuracy_gate(
                75,
                satisfied_checks=satisfied,
                evidence_refs=[f"scheduled_count:{scheduled}", f"max_workers:{artifact_scheduler_workers(kinds)}"],
            )
        ],
        "supports": [
            "bounded-worker-count",
            "deterministic-output-paths",
            "per-parser-result-capture",
            "resume-aware-skip-of-existing-stage-json",
        ],
        "blockers": [
            "scheduler-is-local-threadpool-not-distributed-priority-queue",
            "parser-resource-telemetry-is-stage-level-not-live-per-worker",
            "fairness-and-backpressure-need-terabyte-scale-validation",
        ],
    }


def resolve_memory_cap_bytes(argument_value: int) -> int:
    if argument_value > 0:
        return argument_value
    raw_value = os.environ.get(MEMORY_CAP_ENV, "")
    if not raw_value:
        return 0
    try:
        return max(0, int(raw_value))
    except ValueError:
        return 0


def current_memory_rss_bytes() -> int:
    try:
        import resource

        rss = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    except Exception:
        return 0
    if sys.platform == "darwin":
        return rss
    return rss * 1024


def enforce_memory_cap(stage: str, memory_cap_bytes: int) -> None:
    if memory_cap_bytes <= 0:
        return
    current = current_memory_rss_bytes()
    if current and current > memory_cap_bytes:
        raise RunModeError(
            f"memory cap exceeded at stage {stage}: current_rss_bytes={current} cap_bytes={memory_cap_bytes}"
        )


def memory_cap_enforcement_assessment(*, memory_cap_bytes: int) -> dict[str, object]:
    current_rss = current_memory_rss_bytes()
    satisfied = [
        "RSS reading captured",
        "stage-boundary enforcement",
        "fail-fast corruption prevention warning",
        "hard OS limit limitation warning",
    ]
    if memory_cap_bytes > 0:
        satisfied.append("memory cap configuration recorded")
    return {
        "component": "memory-cap-enforcement",
        "status": "stage-boundary-enforced" if memory_cap_bytes > 0 else "available-not-configured",
        "commercial_gap_ids": [MEMORY_CAP_GAP_ID],
        "memory_cap_bytes": memory_cap_bytes,
        "current_rss_bytes": current_rss,
        "ready_for_court_report": False,
        "core_accuracy_gates": [
            build_accuracy_gate(
                72,
                satisfied_checks=satisfied,
                evidence_refs=[f"memory_cap_bytes:{memory_cap_bytes}", f"current_rss_bytes:{current_rss}"],
            )
        ],
        "supports": [
            "environment-or-cli-configured-memory-cap",
            "rss-checks-at-run-stage-boundaries",
            "failure-before-output-corruption-when-cap-is-exceeded",
        ],
        "blockers": [
            "not-a-hard-os-cgroup-or-job-object-limit",
            "checks-occur-at-safe-stage-boundaries-not-every-allocation",
            "platform-rss-reporting-differs-across-windows-macos-linux",
        ],
    }


def collect_artifact_stages(
    input_root: InputRoot,
    kinds: Sequence[str],
    *,
    artifacts_dir: Path,
    resume: bool,
    rule_set: RuleSet | None,
) -> Dict[str, tuple[Dict[str, object], Path, bool]]:
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    results: Dict[str, tuple[Dict[str, object], Path, bool]] = {}
    pending: list[tuple[str, Path]] = []
    for kind in kinds:
        artifact_path = artifacts_dir / f"rapidtriage-artifacts-{kind}.json"
        reusable = load_reusable_json(
            artifact_path,
            expected_command="artifacts",
            required_keys=("summary", "artifacts"),
        ) if resume else None
        if reusable is not None:
            results[kind] = (reusable, artifact_path, True)
        else:
            pending.append((kind, artifact_path))

    if pending:
        with ThreadPoolExecutor(max_workers=artifact_scheduler_workers(kinds), thread_name_prefix="rapidtriage-artifact") as executor:
            futures = {
                executor.submit(run_artifact_collection, input_root, kind=kind, rule_set=rule_set): (kind, path)
                for kind, path in pending
            }
            for future in as_completed(futures):
                kind, artifact_path = futures[future]
                try:
                    payload = future.result()
                except Exception as exc:
                    payload = isolated_parser_error_payload(kind, input_root=input_root, exc=exc)
                results[kind] = (payload, artifact_path, False)
    return results


def isolated_parser_error_payload(kind: str, *, input_root: InputRoot, exc: Exception) -> Dict[str, object]:
    message = str(exc) or exc.__class__.__name__
    return {
        "command": "artifacts",
        "kind": kind,
        "root": str(input_root.root_path),
        "input_kind": input_root.kind,
        "generated_at": dt.datetime.now().isoformat(),
        "summary": {
            "artifact_count": 0,
            "artifact_type_counts": {},
            "parser_error_count": 1,
            "commercial_gap_ids": [PARSER_CRASH_ISOLATION_GAP_ID],
            "commercial_grade_ready": False,
        },
        "artifacts": [],
        "parser_errors": [
            {
                "kind": kind,
                "error_type": exc.__class__.__name__,
                "message": message,
                "isolated": True,
                "commercial_gap_ids": [PARSER_CRASH_ISOLATION_GAP_ID],
                "review_hint": "Treat this parser output as incomplete and validate the source with a trusted parser before reporting.",
            }
        ],
        "parser_crash_isolation": parser_crash_isolation_assessment(error_count=1),
    }


def parser_crash_isolation_assessment(*, error_count: int) -> dict[str, object]:
    satisfied = [
        "per-parser exception capture",
        "failed parser JSON output",
        "run continuation after parser error",
        "summary warning surfaced",
        "native sandbox/fuzzing limitation warning",
    ]
    return {
        "component": "parser-crash-isolation",
        "status": "isolated-errors-captured" if error_count else "enabled-no-errors",
        "commercial_gap_ids": [PARSER_CRASH_ISOLATION_GAP_ID],
        "parser_error_count": error_count,
        "ready_for_court_report": error_count == 0,
        "core_accuracy_gates": [
            build_accuracy_gate(
                71,
                satisfied_checks=satisfied,
                evidence_refs=[f"parser_error_count:{error_count}", "run-summary:processing.parser_crash_isolation"],
            )
        ],
        "supports": [
            "per-parser-exception-capture",
            "failed-parser-json-output",
            "run-continues-to-later-stages",
            "warning-surfaced-in-run-summary",
        ],
        "blockers": [
            "native-process-sandboxing-is-not-yet-used-for-every-parser",
            "corrupt-input-fuzzing-and-crash-corpus-validation-remain-required",
        ],
    }


def load_reusable_json(
    path: Path,
    *,
    expected_command: str | None,
    required_keys: Sequence[str],
) -> Dict[str, object] | None:
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    if expected_command is not None and payload.get("command") != expected_command:
        return None
    if any(key not in payload for key in required_keys):
        return None
    return payload


def build_run_input_fingerprint(root: Path, *, max_files: int = 5000) -> Dict[str, object]:
    hasher = hashlib.sha256()
    scanned_files = 0
    total_size = 0
    latest_mtime = 0.0
    truncated = False
    try:
        iterator = root.rglob("*") if root.is_dir() else iter([root])
        for path in iterator:
            if not path.is_file():
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            relative = str(path.relative_to(root)) if root.is_dir() else path.name
            hasher.update(relative.replace("\\", "/").lower().encode("utf-8", errors="replace"))
            hasher.update(str(stat.st_size).encode("ascii"))
            hasher.update(str(int(stat.st_mtime_ns)).encode("ascii"))
            scanned_files += 1
            total_size += stat.st_size
            latest_mtime = max(latest_mtime, stat.st_mtime)
            if max_files and scanned_files >= max_files:
                truncated = True
                break
    except OSError:
        truncated = True
    return {
        "command": "run-fingerprint",
        "generated_at": dt.datetime.now().isoformat(),
        "root": str(root),
        "fingerprint": hasher.hexdigest(),
        "summary": {
            "scanned_file_count": scanned_files,
            "total_size_bytes": total_size,
            "latest_mtime_epoch": latest_mtime,
            "max_files": max_files,
            "truncated": truncated,
            "commercial_gap_ids": [INCREMENTAL_INDEXING_GAP_ID],
            "commercial_grade_ready": False,
        },
        "incremental_indexing_assessment": incremental_indexing_assessment(
            scanned_files=scanned_files,
            max_files=max_files,
            truncated=truncated,
        ),
        "core_accuracy_gates": incremental_indexing_core_accuracy_gates(
            scanned_files=scanned_files,
            max_files=max_files,
            truncated=truncated,
            fingerprint=hasher.hexdigest(),
            reuse_disabled=False,
        ),
    }


def record_run_checkpoint(records: list[dict[str, object]], stage: str, path: Path, *, reused: bool) -> None:
    records.append(
        {
            "stage": stage,
            "status": "reused" if reused else "completed",
            "output": str(path),
            "exists": path.is_file(),
            "size_bytes": path.stat().st_size if path.is_file() else None,
            "reused": reused,
            "recorded_at": dt.datetime.now().isoformat(),
            "commercial_gap_ids": [CHECKPOINT_RESUME_GAP_ID],
            "core_accuracy_gates": checkpoint_resume_core_accuracy_gates(
                checkpoints=[{
                    "stage": stage,
                    "output": str(path),
                    "size_bytes": path.stat().st_size if path.is_file() else None,
                    "reused": reused,
                }],
                resume_requested=False,
                resume_effective=False,
            ),
        }
    )


def write_run_checkpoints(
    path: Path,
    *,
    output_dir: Path,
    input_fingerprint: Mapping[str, object],
    resume_requested: bool,
    resume_effective: bool,
    resume_disabled_reason: str,
    checkpoints: Sequence[Mapping[str, object]],
) -> None:
    status_counts = Counter(str(item.get("status") or "unknown") for item in checkpoints)
    payload = {
        "command": "run-checkpoints",
        "generated_at": dt.datetime.now().isoformat(),
        "output_dir": str(output_dir),
        "resume": {
            "requested": resume_requested,
            "effective": resume_effective,
            "disabled_reason": resume_disabled_reason,
        },
        "input_fingerprint": dict(input_fingerprint),
        "summary": {
            "checkpoint_count": len(checkpoints),
            "status_counts": dict(status_counts),
            "reused_count": sum(1 for item in checkpoints if item.get("reused")),
            "commercial_gap_ids": [CHECKPOINT_RESUME_GAP_ID],
            "commercial_grade_ready": False,
        },
        "checkpoint_resume_assessment": checkpoint_resume_assessment(
            resume_requested=resume_requested,
            resume_effective=resume_effective,
            checkpoints=checkpoints,
        ),
        "core_accuracy_gates": checkpoint_resume_core_accuracy_gates(
            checkpoints=checkpoints,
            resume_requested=resume_requested,
            resume_effective=resume_effective,
        ),
        "checkpoints": [dict(item) for item in checkpoints],
    }
    write_result(payload, path)


def incremental_indexing_assessment(*, scanned_files: int, max_files: int, truncated: bool) -> dict[str, object]:
    return {
        "component": "incremental-indexing",
        "status": "fingerprint-based-reuse-enabled",
        "commercial_gap_ids": [INCREMENTAL_INDEXING_GAP_ID],
        "scanned_file_count": scanned_files,
        "fingerprint_max_files": max_files,
        "fingerprint_truncated": truncated,
        "ready_for_court_report": False,
        "blockers": [
            "fingerprint-is-bounded-path-size-mtime-metadata-not-full-content-index-delta",
            "changed-source-disables-reuse-instead-of-per-file-incremental-reindex",
            "case-db-deduplication-and-reindex-policy-require-large-corpus-validation",
        ],
        "recommended_validation": [
            "Preserve rapidtriage-run-fingerprint.json with resumed run outputs.",
            "Rebuild outputs when the fingerprint changes or when bounded fingerprint truncation is unacceptable.",
        ],
        "core_accuracy_gates": incremental_indexing_core_accuracy_gates(
            scanned_files=scanned_files,
            max_files=max_files,
            truncated=truncated,
            fingerprint="assessment",
            reuse_disabled=False,
        ),
    }


def checkpoint_resume_assessment(
    *,
    resume_requested: bool,
    resume_effective: bool,
    checkpoints: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    return {
        "component": "stage-checkpoint-resume",
        "status": "resume-effective" if resume_effective else ("resume-requested-disabled-or-not-reused" if resume_requested else "fresh-run"),
        "commercial_gap_ids": [CHECKPOINT_RESUME_GAP_ID],
        "checkpoint_count": len(checkpoints),
        "reused_count": sum(1 for item in checkpoints if item.get("reused")),
        "ready_for_court_report": False,
        "blockers": [
            "checkpointing-reuses-complete-json-stage-outputs-not-mid-parser-state",
            "failed-or-partial-stage-resume-requires-rebuild-and-review-of-warning-output",
            "long-running-parser-cooperative-cancellation-remains-limited",
        ],
        "recommended_validation": [
            "Review each checkpoint status, output path, size, and reused flag before relying on resumed results.",
            "Keep checkpoint and fingerprint files together with the run summary for reproducibility.",
        ],
        "core_accuracy_gates": checkpoint_resume_core_accuracy_gates(
            checkpoints=checkpoints,
            resume_requested=resume_requested,
            resume_effective=resume_effective,
        ),
    }


def incremental_indexing_core_accuracy_gates(
    *,
    scanned_files: int,
    max_files: int,
    truncated: bool,
    fingerprint: str,
    reuse_disabled: bool,
) -> list[dict[str, object]]:
    satisfied = ["input fingerprint emitted", "path/size/mtime metadata captured", "per-file reindex limitation warning"]
    if reuse_disabled:
        satisfied.append("changed-source reuse disabled")
    if truncated or max_files:
        satisfied.append("truncation disclosure")
    return [
        build_accuracy_gate(
            68,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"fingerprint:{fingerprint}",
                f"scanned_file_count:{scanned_files}",
                f"max_files:{max_files}",
                f"truncated:{truncated}",
            ],
        )
    ]


def checkpoint_resume_core_accuracy_gates(
    *,
    checkpoints: Sequence[Mapping[str, object]],
    resume_requested: bool,
    resume_effective: bool,
) -> list[dict[str, object]]:
    satisfied = ["partial-stage limitation warning"]
    if checkpoints:
        satisfied.append("stage checkpoints emitted")
    if any(item.get("output") and item.get("size_bytes") is not None for item in checkpoints):
        satisfied.append("output path and size captured")
    if any("reused" in item for item in checkpoints):
        satisfied.append("reused flag captured")
    if resume_requested or resume_effective or checkpoints:
        satisfied.append("resume status summarized")
    return [
        build_accuracy_gate(
            70,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"checkpoint_count:{len(checkpoints)}",
                f"resume_requested:{resume_requested}",
                f"resume_effective:{resume_effective}",
            ],
        )
    ]


def prepare_run_input_root(
    root: Union[InputRoot, Path],
    *,
    input_kind: str | None,
    output_dir: Path,
) -> tuple[
    InputRoot,
    E01ExtractionResult | DiskImageExtractionResult | ArchiveImageExtractionResult | VirtualDiskExtractionResult | None,
]:
    if isinstance(root, InputRoot):
        return resolve_input_root(root, kind=input_kind), None

    root_path = Path(root).expanduser().resolve()
    if is_e01_path(root_path):
        try:
            result = extract_e01_to_directory(root_path, output_dir / "_e01")
        except E01ExtractionError as exc:
            raise RunModeError(str(exc)) from exc
        return InputRoot(source_path=str(root_path), root_path=result.extract_dir, kind="e01-derived"), result
    if is_raw_image_path(root_path):
        try:
            result = extract_raw_image_to_directory(root_path, output_dir / "_disk_image")
        except DiskImageExtractionError as exc:
            raise RunModeError(str(exc)) from exc
        return InputRoot(source_path=str(root_path), root_path=result.extract_dir, kind="disk-image-derived"), result
    if is_archive_image_path(root_path):
        try:
            result = extract_archive_image_to_directory(root_path, output_dir / "_archive_image")
        except ArchiveImageExtractionError as exc:
            raise RunModeError(str(exc)) from exc
        return InputRoot(source_path=str(root_path), root_path=result.extract_dir, kind="archive-image-derived"), result
    if is_virtual_disk_path(root_path):
        try:
            result = extract_virtual_disk_to_directory(root_path, output_dir / "_virtual_disk")
        except VirtualDiskExtractionError as exc:
            raise RunModeError(str(exc)) from exc
        return InputRoot(source_path=str(root_path), root_path=result.extract_dir, kind="disk-image-derived"), result
    return resolve_input_root(root_path, kind=input_kind), None


def build_run_source_record(
    input_root: InputRoot,
    *,
    image_result: E01ExtractionResult
    | DiskImageExtractionResult
    | ArchiveImageExtractionResult
    | VirtualDiskExtractionResult
    | None,
) -> dict[str, object]:
    if image_result is None:
        return {
            "type": input_root.kind,
            "source_path": input_root.source_path,
            "analysis_root": str(input_root.root_path),
        }
    if isinstance(image_result, DiskImageExtractionResult):
        return {
            "type": "raw-image",
            "source_path": str(image_result.source_path),
            "analysis_root": str(image_result.extract_dir),
            "stage_dir": str(image_result.stage_dir),
            "partition_start_sector": image_result.partition_start_sector,
            "recovery_mode": image_result.recovery_mode,
            "image_paths": [str(path) for path in image_result.image_paths],
            "source_integrity": list(image_result.source_integrity),
            "commercial_grade_ready": image_result.commercial_grade_ready,
        }
    if isinstance(image_result, ArchiveImageExtractionResult):
        return {
            "type": "archive-image",
            "source_path": str(image_result.source_path),
            "analysis_root": str(image_result.extract_dir),
            "stage_dir": str(image_result.stage_dir),
            "tool": image_result.tool,
            "source_integrity": image_result.source_integrity,
            "commercial_grade_ready": image_result.commercial_grade_ready,
        }
    if isinstance(image_result, VirtualDiskExtractionResult):
        return {
            "type": "virtual-disk",
            "source_path": str(image_result.source_path),
            "analysis_root": str(image_result.extract_dir),
            "stage_dir": str(image_result.stage_dir),
            "converted_raw_path": str(image_result.converted_raw_path),
            "conversion_tool": image_result.conversion_tool,
            "partition_start_sector": image_result.raw_result.partition_start_sector,
            "recovery_mode": image_result.raw_result.recovery_mode,
            "source_integrity": image_result.source_integrity,
            "converted_raw_integrity": image_result.converted_raw_integrity,
            "commercial_grade_ready": image_result.commercial_grade_ready,
        }
    return {
        "type": "e01",
        "source_path": str(image_result.source_path),
        "analysis_root": str(image_result.extract_dir),
        "stage_dir": str(image_result.stage_dir),
        "partition_start_sector": image_result.partition_start_sector,
        "source_integrity": image_result.source_integrity,
        "commercial_grade_ready": image_result.commercial_grade_ready,
    }


def build_run_summary(
    *,
    root: Path,
    output_dir: Path,
    profile: RunProfile,
    manifest_payload: Mapping[str, object],
    docs_payload: Mapping[str, object],
    files_payload: Mapping[str, object],
    docs_extract_payload: Mapping[str, object],
    files_extract_payload: Mapping[str, object],
    artifact_payloads: Mapping[str, Mapping[str, object]],
    timeline_payload: Mapping[str, object],
    indicators_payload: Mapping[str, object],
    outputs: Mapping[str, Path],
    safety: Mapping[str, object],
    rule_set: RuleSet | None = None,
    source: Mapping[str, object] | None = None,
) -> Dict[str, object]:
    provider_counts = {
        str(provider["name"]): len(provider.get("artifacts", []))
        for provider in manifest_payload.get("providers", [])
        if isinstance(provider, dict) and provider.get("name")
    }
    windows_provider_counts = {
        name: count for name, count in provider_counts.items() if name.startswith("windows-")
    }
    artifact_type_counts = dict(count_artifact_types(manifest_payload.get("providers", [])))
    keyword_counts = dict(count_matched_keywords(docs_payload.get("results", [])))
    file_category_counts = dict(files_payload.get("summary", {}).get("category_counts", {}))
    artifact_summary = {
        kind: {
            "artifact_count": int(payload.get("summary", {}).get("artifact_count", 0)),
            "artifact_type_counts": dict(payload.get("summary", {}).get("artifact_type_counts", {})),
            "output": str(outputs.get(f"artifacts_{kind}", "")),
        }
        for kind, payload in artifact_payloads.items()
    }
    preferred_candidates = collect_preferred_candidates(
        files_payload.get("candidates", []),
        preferred_locations=profile.preferred_locations,
    )
    recent_candidates = summarize_file_candidates(files_payload.get("candidates", []), limit=5)
    large_candidates = summarize_large_file_candidates(files_payload.get("candidates", []), limit=5)

    reused_outputs = {str(item) for item in safety.get("reused_outputs", [])} if isinstance(safety.get("reused_outputs"), list) else set()
    step_rows = build_step_rows(
        manifest_payload=manifest_payload,
        docs_payload=docs_payload,
        files_payload=files_payload,
        docs_extract_payload=docs_extract_payload,
        files_extract_payload=files_extract_payload,
        artifact_payloads=artifact_payloads,
        timeline_payload=timeline_payload,
        indicators_payload=indicators_payload,
        outputs=outputs,
        reused_outputs=reused_outputs,
    )
    silent_failure = build_silent_failure_report(
        root=root,
        docs_payload=docs_payload,
        files_payload=files_payload,
        docs_extract_payload=docs_extract_payload,
        files_extract_payload=files_extract_payload,
        artifact_payloads=artifact_payloads,
        timeline_payload=timeline_payload,
        safety=safety,
    )
    step_rows.append(build_silent_failure_step(silent_failure))
    processing_summary = build_processing_summary(step_rows, safety=safety)

    payload = {
        "command": "run",
        "mode": profile.mode,
        "generated_at": dt.datetime.now().isoformat(),
        "root": str(root),
        "source": dict(source or {}),
        "scan_scope_root": str(files_payload.get("scan_scope_root") or docs_payload.get("scan_scope_root") or root),
        "output_dir": str(output_dir),
        "profile": {
            "description": profile.description,
            "keywords": list(profile.keywords),
            "docs_extract_kinds": list(profile.docs_extract_kinds),
            "file_extract_categories": list(profile.file_extract_categories),
            "file_scan_categories": list(profile.file_scan_categories),
            "file_scan_path_contains": list(profile.file_scan_path_contains),
            "preferred_locations": list(profile.preferred_locations),
            "artifacts_kinds": list(profile.artifacts_kinds),
        },
        "safety": dict(safety),
        "resource_caps": {
            "max_extract_size_bytes": safety.get("max_extract_size_bytes", 0),
            "max_file_count": safety.get("max_file_count", 0),
            "memory_cap_bytes": safety.get("memory_cap_bytes", 0),
            "fingerprint_max_files": 5000,
            "structured_preview_max_bytes": "see API source-preview constants",
            "bounded_outputs": True,
        },
        "outputs": {name: str(path) for name, path in outputs.items()},
        "steps": step_rows,
        "processing": processing_summary,
        "silent_failure_detection": silent_failure,
        "summary": {
            "document_candidate_count": int(docs_payload.get("summary", {}).get("candidate_count", 0)),
            "document_match_count": int(docs_payload.get("summary", {}).get("match_count", 0)),
            "scanned_file_count": int(files_payload.get("summary", {}).get("scanned_file_count", 0)),
            "file_candidate_count": int(files_payload.get("summary", {}).get("candidate_count", 0)),
            "provider_artifact_counts": provider_counts,
            "windows_provider_artifact_counts": windows_provider_counts,
            "artifact_type_counts": artifact_type_counts,
            "matched_keyword_counts": keyword_counts,
            "file_category_counts": file_category_counts,
            "artifacts": artifact_summary,
            "docs_extracted_count": int(docs_extract_payload.get("summary", {}).get("extracted_count", 0)),
            "files_extracted_count": int(files_extract_payload.get("summary", {}).get("extracted_count", 0)),
            "preferred_location_candidate_count": len(preferred_candidates),
            "timeline_event_count": int(timeline_payload.get("summary", {}).get("event_count", 0)),
            "silent_failure_risk": bool(silent_failure.get("silent_failure_risk")),
            "silent_failure_risk_check_count": int(silent_failure.get("risk_check_count", 0)),
        },
        "highlights": {
            "document_hits": summarize_document_hits(docs_payload.get("results", []), limit=5),
            "recent_file_candidates": recent_candidates,
            "large_file_candidates": large_candidates,
            "preferred_location_candidates": preferred_candidates[:5],
        },
    }
    if rule_set is not None:
        annotation_summary = summarize_payload_annotations(files_payload, docs_payload, *artifact_payloads.values())
        payload["rule_set"] = {
            "path": rule_set.path,
            "format": rule_set.format,
            "rule_count": rule_set.rule_count,
        }
        if annotation_summary["matched_rules"]:
            payload["matched_rules"] = annotation_summary["matched_rules"]
        if annotation_summary["ioc_hits"]:
            payload["ioc_hits"] = annotation_summary["ioc_hits"]
        payload["summary"]["matched_rule_count"] = int(annotation_summary["matched_rule_count"])
        payload["summary"]["ioc_hit_count"] = int(annotation_summary["ioc_hit_count"])
    return payload


def build_step_rows(
    *,
    manifest_payload: Mapping[str, object],
    docs_payload: Mapping[str, object],
    files_payload: Mapping[str, object],
    docs_extract_payload: Mapping[str, object],
    files_extract_payload: Mapping[str, object],
    artifact_payloads: Mapping[str, Mapping[str, object]],
    timeline_payload: Mapping[str, object],
    indicators_payload: Mapping[str, object],
    outputs: Mapping[str, Path],
    reused_outputs: set[str] | None = None,
) -> List[Dict[str, object]]:
    reused_outputs = reused_outputs or set()
    provider_count = len(manifest_payload.get("providers", []))
    artifact_count_by_kind = {
        kind: int(payload.get("summary", {}).get("artifact_count", 0))
        for kind, payload in artifact_payloads.items()
    }
    rows: List[Dict[str, object]] = [
        mark_reused_step(
            annotate_step(
            {
                "name": "manifest",
                "status": "completed",
                "output": str(outputs["manifest"]),
                "provider_count": provider_count,
            },
            warning_level="notice" if provider_count == 0 else "none",
            warning_messages=["No manifest providers were collected."] if provider_count == 0 else [],
            ),
            reused_outputs,
        ),
        mark_reused_step(
            annotate_step(
            {
                "name": "docs",
                "status": "completed",
                "output": str(outputs["docs"]),
                "candidate_count": int(docs_payload.get("summary", {}).get("candidate_count", 0)),
                "match_count": int(docs_payload.get("summary", {}).get("match_count", 0)),
            },
            warning_level=docs_warning_level(docs_payload),
            warning_messages=docs_warning_messages(docs_payload),
            ),
            reused_outputs,
        ),
        mark_reused_step(
            annotate_step(
            {
                "name": "docs-index",
                "status": "completed",
                "output": str(outputs["docs_index"]),
                "strategy": str(docs_payload.get("index", {}).get("strategy", "")),
                "document_count": int(docs_payload.get("index", {}).get("document_count", 0)),
                "term_count": int(docs_payload.get("index", {}).get("term_count", 0)),
            },
            warning_level=docs_index_warning_level(docs_payload),
            warning_messages=docs_index_warning_messages(docs_payload),
            ),
            reused_outputs,
        ),
        mark_reused_step(
            annotate_step(
            {
                "name": "files",
                "status": "completed",
                "output": str(outputs["files"]),
                "scanned_file_count": int(files_payload.get("summary", {}).get("scanned_file_count", 0)),
                "candidate_count": int(files_payload.get("summary", {}).get("candidate_count", 0)),
            },
            warning_level=files_warning_level(files_payload),
            warning_messages=files_warning_messages(files_payload),
            ),
            reused_outputs,
        ),
    ]
    for kind, payload in artifact_payloads.items():
        artifact_count = artifact_count_by_kind[kind]
        parser_error_count = int(payload.get("summary", {}).get("parser_error_count", 0))
        rows.append(
            mark_reused_step(
                annotate_step(
                {
                    "name": f"artifacts-{kind}",
                    "status": "failed_isolated" if parser_error_count else "completed",
                    "output": str(outputs[f"artifacts_{kind}"]),
                    "artifact_count": artifact_count,
                    "parser_error_count": parser_error_count,
                },
                warning_level="failed" if parser_error_count else ("notice" if artifact_count == 0 else "none"),
                warning_messages=[f"{kind} parser reported {parser_error_count} isolated error(s)."]
                if parser_error_count
                else ([f"No {kind} artifact rows were collected."] if artifact_count == 0 else []),
                ),
                reused_outputs,
            )
        )
    docs_extract_step = build_extract_step(
        "docs-extract",
        outputs["docs_extract_manifest"],
        docs_extract_payload,
    )
    files_extract_step = build_extract_step(
        "files-extract",
        outputs["files_extract_manifest"],
        files_extract_payload,
    )
    timeline_count = int(timeline_payload.get("summary", {}).get("event_count", 0))
    indicator_count = int(indicators_payload.get("summary", {}).get("indicator_count", 0))
    matched_indicator_count = int(indicators_payload.get("summary", {}).get("matched_indicator_count", 0))
    rows.extend(
        [
            docs_extract_step,
            files_extract_step,
            mark_reused_step(
                annotate_step(
                {
                    "name": "timeline",
                    "status": "completed",
                    "output": str(outputs["timeline"]),
                    "event_count": timeline_count,
                    "report": str(outputs["timeline_report"]),
                },
                warning_level="notice" if timeline_count == 0 else "none",
                warning_messages=[
                    "No timeline events were produced. Confirm the source has supported timestamps/artifacts."
                ]
                if timeline_count == 0
                else [],
                ),
                reused_outputs,
            ),
            mark_reused_step(
                annotate_step(
                {
                    "name": "indicators",
                    "status": "completed",
                    "output": str(outputs["indicators"]),
                    "indicator_count": indicator_count,
                    "matched_indicator_count": matched_indicator_count,
                },
                warning_level="notice" if indicator_count == 0 else "none",
                warning_messages=[
                    "No URL, domain, IP, or hash indicators were summarized from the run outputs."
                ]
                if indicator_count == 0
                else [],
                ),
                reused_outputs,
            ),
        ]
    )
    return [mark_reused_step(row, reused_outputs) for row in rows]


def build_processing_summary(
    steps: List[Dict[str, object]],
    *,
    safety: Mapping[str, object],
) -> Dict[str, object]:
    warnings: List[Dict[str, object]] = []
    for step in steps:
        level = str(step.get("warning_level") or "none")
        messages = step.get("warning_messages", [])
        if level == "none" or not isinstance(messages, list):
            continue
        for message in messages:
            warnings.append(
                {
                    "step": str(step.get("name", "")),
                    "level": level,
                    "message": str(message),
                }
            )

    max_extract_size = int(safety.get("max_extract_size_bytes") or 0)
    max_file_count = int(safety.get("max_file_count") or 0)
    memory_cap_bytes = int(safety.get("memory_cap_bytes") or 0)
    read_only = bool(safety.get("read_only"))
    dry_run = bool(safety.get("dry_run"))
    resume = bool(safety.get("resume"))
    reused_outputs = [str(item) for item in safety.get("reused_outputs", [])] if isinstance(safety.get("reused_outputs"), list) else []
    parser_error_count = sum(int(step.get("parser_error_count") or 0) for step in steps)
    artifact_scheduler = safety.get("artifact_scheduler") if isinstance(safety.get("artifact_scheduler"), Mapping) else {}
    profile_label = infer_processing_profile_label(
        read_only=read_only,
        dry_run=dry_run,
        max_extract_size_bytes=max_extract_size,
        max_file_count=max_file_count,
    )
    return {
        "profile_label": profile_label,
        "dry_run": dry_run,
        "read_only": read_only,
        "overwrite": bool(safety.get("overwrite")),
        "resume": resume,
        "reused_output_count": len(reused_outputs),
        "reused_outputs": reused_outputs,
        "incremental_indexing": {
            "commercial_gap_ids": [INCREMENTAL_INDEXING_GAP_ID],
            "status": "fingerprint-controlled-output-reuse",
            "resume_effective": bool(safety.get("resume_effective")),
            "resume_disabled_reason": str(safety.get("resume_disabled_reason") or ""),
        },
        "checkpoint_resume": {
            "commercial_gap_ids": [CHECKPOINT_RESUME_GAP_ID],
            "status": "stage-checkpoints-written",
            "reused_output_count": len(reused_outputs),
        },
        "parser_crash_isolation": parser_crash_isolation_assessment(error_count=parser_error_count),
        "memory_cap_enforcement": memory_cap_enforcement_assessment(memory_cap_bytes=memory_cap_bytes),
        "parallel_parser_scheduler": artifact_scheduler.get("assessment")
        if isinstance(artifact_scheduler.get("assessment"), Mapping)
        else parallel_parser_scheduler_assessment(()),
        "caps": {
            "max_extract_size_bytes": max_extract_size,
            "max_file_count": max_file_count,
            "memory_cap_bytes": memory_cap_bytes,
        },
        "step_count": len(steps),
        "warning_count": len(warnings),
        "highest_warning_level": highest_warning_level([str(item["level"]) for item in warnings]),
        "warnings": warnings,
    }


def build_silent_failure_step(report: Mapping[str, object]) -> Dict[str, object]:
    status = str(report.get("status") or "unknown")
    risk_count = int(report.get("risk_check_count") or 0)
    check_count = int(report.get("check_count") or 0)
    level = "none"
    if status == "failed":
        level = "failed"
    elif status == "warning":
        level = "warning"
    elif status == "notice":
        level = "notice"
    messages = []
    if level != "none":
        messages.append(
            f"Silent-failure detector found {risk_count} risk check(s) across {check_count} checks."
        )
    return annotate_step(
        {
            "name": "silent-failure-detector",
            "status": status,
            "output": "",
            "check_count": check_count,
            "risk_check_count": risk_count,
            "silent_failure_risk": bool(report.get("silent_failure_risk")),
        },
        warning_level=level,
        warning_messages=messages,
    )


def mark_reused_step(row: Dict[str, object], reused_outputs: set[str]) -> Dict[str, object]:
    name = str(row.get("name") or "")
    if name in reused_outputs:
        row["status"] = "reused"
        row["reused"] = True
    else:
        row["reused"] = False
    return row


def infer_processing_profile_label(
    *,
    read_only: bool,
    dry_run: bool,
    max_extract_size_bytes: int,
    max_file_count: int,
) -> str:
    if dry_run:
        return "Dry run - no extraction"
    if read_only:
        return "Fast first pass - read-only"
    if max_extract_size_bytes or max_file_count:
        return "Standard - bounded extraction"
    return "Deep - uncapped extraction"


def build_extract_step(name: str, output: Path, payload: Mapping[str, object]) -> Dict[str, object]:
    summary = payload.get("summary", {})
    selected_count = int(summary.get("selected_count", 0)) if isinstance(summary, Mapping) else 0
    extracted_count = int(summary.get("extracted_count", 0)) if isinstance(summary, Mapping) else 0
    skipped_count = int(summary.get("skipped_count", 0)) if isinstance(summary, Mapping) else 0
    skip_reason_counts = count_skip_reasons(payload)
    warning_messages = extract_warning_messages(
        selected_count=selected_count,
        extracted_count=extracted_count,
        skipped_count=skipped_count,
        skip_reason_counts=skip_reason_counts,
    )
    warning_level = extract_warning_level(skip_reason_counts, selected_count=selected_count, skipped_count=skipped_count)
    status = "completed"
    if selected_count and skipped_count and not extracted_count:
        status = "skipped"
    elif skipped_count:
        status = "completed_with_warnings"
    return annotate_step(
        {
            "name": name,
            "status": status,
            "output": str(output),
            "selected_count": selected_count,
            "extracted_count": extracted_count,
            "skipped_count": skipped_count,
            "skip_reasons": skip_reason_counts,
        },
        warning_level=warning_level,
        warning_messages=warning_messages,
    )


def annotate_step(
    row: Dict[str, object],
    *,
    warning_level: str,
    warning_messages: List[str],
) -> Dict[str, object]:
    row["warning_level"] = warning_level
    row["warning_messages"] = warning_messages
    return row


def docs_warning_level(payload: Mapping[str, object]) -> str:
    summary = payload.get("summary", {})
    candidate_count = int(summary.get("candidate_count", 0)) if isinstance(summary, Mapping) else 0
    match_count = int(summary.get("match_count", 0)) if isinstance(summary, Mapping) else 0
    if candidate_count == 0:
        return "notice"
    if match_count == 0:
        return "notice"
    return "none"


def docs_warning_messages(payload: Mapping[str, object]) -> List[str]:
    summary = payload.get("summary", {})
    candidate_count = int(summary.get("candidate_count", 0)) if isinstance(summary, Mapping) else 0
    match_count = int(summary.get("match_count", 0)) if isinstance(summary, Mapping) else 0
    if candidate_count == 0:
        return ["No supported document candidates were found."]
    if match_count == 0:
        return ["Documents were scanned, but no configured keywords matched."]
    return []


def docs_index_warning_level(payload: Mapping[str, object]) -> str:
    index = payload.get("index", {})
    document_count = int(index.get("document_count", 0)) if isinstance(index, Mapping) else 0
    return "notice" if document_count == 0 else "none"


def docs_index_warning_messages(payload: Mapping[str, object]) -> List[str]:
    index = payload.get("index", {})
    document_count = int(index.get("document_count", 0)) if isinstance(index, Mapping) else 0
    if document_count == 0:
        return ["No documents were added to the keyword index."]
    return []


def files_warning_level(payload: Mapping[str, object]) -> str:
    summary = payload.get("summary", {})
    scanned_count = int(summary.get("scanned_file_count", 0)) if isinstance(summary, Mapping) else 0
    candidate_count = int(summary.get("candidate_count", 0)) if isinstance(summary, Mapping) else 0
    if scanned_count == 0:
        return "warning"
    if candidate_count == 0:
        return "notice"
    return "none"


def files_warning_messages(payload: Mapping[str, object]) -> List[str]:
    summary = payload.get("summary", {})
    scanned_count = int(summary.get("scanned_file_count", 0)) if isinstance(summary, Mapping) else 0
    candidate_count = int(summary.get("candidate_count", 0)) if isinstance(summary, Mapping) else 0
    if scanned_count == 0:
        return ["No files were scanned. Check the evidence root or mounted-image path."]
    if candidate_count == 0:
        return ["Files were scanned, but no profile-matched candidates were found."]
    return []


def count_skip_reasons(payload: Mapping[str, object]) -> Dict[str, int]:
    skipped = payload.get("skipped", [])
    counts: Counter[str] = Counter()
    if not isinstance(skipped, list):
        return {}
    for item in skipped:
        if not isinstance(item, dict):
            continue
        reason = str(item.get("reason") or "unknown")
        counts[reason] += 1
    return dict(sorted(counts.items()))


def extract_warning_level(
    skip_reason_counts: Mapping[str, int],
    *,
    selected_count: int,
    skipped_count: int,
) -> str:
    if not skipped_count:
        return "notice" if selected_count == 0 else "none"
    if any(reason in skip_reason_counts for reason in {"max-file-count", "max-extract-size", "missing"}):
        return "warning"
    return "notice"


def extract_warning_messages(
    *,
    selected_count: int,
    extracted_count: int,
    skipped_count: int,
    skip_reason_counts: Mapping[str, int],
) -> List[str]:
    messages: List[str] = []
    if selected_count == 0:
        messages.append("No items matched the extraction filters.")
    if skipped_count and not extracted_count:
        messages.append("Selected items were not extracted; review skip reasons before reporting.")
    elif skipped_count:
        messages.append("Some selected items were skipped during extraction.")
    if "read-only" in skip_reason_counts:
        messages.append("Extraction skipped by read-only profile.")
    if "dry-run" in skip_reason_counts:
        messages.append("Extraction skipped because dry run was enabled.")
    if "max-file-count" in skip_reason_counts:
        messages.append("Extraction capped by max file count.")
    if "max-extract-size" in skip_reason_counts:
        messages.append("Extraction capped by max extract size.")
    if "missing" in skip_reason_counts:
        messages.append("Some selected source paths were missing.")
    if "destination-exists" in skip_reason_counts:
        messages.append("Existing destination files were preserved; enable overwrite only when intended.")
    return messages


def highest_warning_level(levels: List[str]) -> str:
    priority = {"none": 0, "notice": 1, "warning": 2, "failed": 3}
    if not levels:
        return "none"
    return max(levels, key=lambda level: priority.get(level, 0))


def resolve_scan_root(root: Path, profile: RunProfile) -> Path:
    if not profile.scan_root_parts:
        return root
    candidate = root.joinpath(*profile.scan_root_parts)
    if candidate.exists():
        return candidate
    return root


def count_artifact_types(providers: object) -> Counter[str]:
    counts: Counter[str] = Counter()
    if not isinstance(providers, list):
        return counts
    for provider in providers:
        if not isinstance(provider, dict):
            continue
        artifacts = provider.get("artifacts", [])
        if not isinstance(artifacts, list):
            continue
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                continue
            artifact_type = artifact.get("artifact_type")
            if artifact_type:
                counts[str(artifact_type)] += 1
    return counts


def count_matched_keywords(results: object) -> Counter[str]:
    counts: Counter[str] = Counter()
    if not isinstance(results, list):
        return counts
    for result in results:
        if not isinstance(result, dict):
            continue
        for keyword in result.get("matched_keywords", []):
            counts[str(keyword)] += 1
    return counts


def summarize_document_hits(results: object, *, limit: int) -> List[Dict[str, object]]:
    if not isinstance(results, list):
        return []
    items: List[Dict[str, object]] = []
    for result in results[:limit]:
        if not isinstance(result, dict):
            continue
        items.append(
            {
                "path": result.get("path"),
                "kind": result.get("kind"),
                "matched_keywords": list(result.get("matched_keywords", [])),
                "preview": result.get("preview"),
            }
        )
    return items


def summarize_file_candidates(candidates: object, *, limit: int) -> List[Dict[str, object]]:
    if not isinstance(candidates, list):
        return []
    items: List[Dict[str, object]] = []
    for candidate in candidates[:limit]:
        if not isinstance(candidate, dict):
            continue
        items.append(
            {
                "path": candidate.get("path"),
                "categories": list(candidate.get("categories", [])),
                "extension": candidate.get("extension"),
                "size": candidate.get("size"),
                "modified_at": candidate.get("modified_at"),
            }
        )
    return items


def summarize_large_file_candidates(candidates: object, *, limit: int) -> List[Dict[str, object]]:
    if not isinstance(candidates, list):
        return []
    sorted_candidates = sorted(
        (candidate for candidate in candidates if isinstance(candidate, dict)),
        key=lambda item: (-int(item.get("size", 0)), str(item.get("path", ""))),
    )
    items: List[Dict[str, object]] = []
    for candidate in sorted_candidates[:limit]:
        items.append(
            {
                "path": candidate.get("path"),
                "categories": list(candidate.get("categories", [])),
                "size": candidate.get("size"),
                "modified_at": candidate.get("modified_at"),
            }
        )
    return items


def collect_preferred_candidates(candidates: object, *, preferred_locations: Sequence[str]) -> List[Dict[str, object]]:
    if not isinstance(candidates, list) or not preferred_locations:
        return []
    normalized_locations = [value.lower() for value in preferred_locations]
    selected = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        path_value = str(candidate.get("path", "")).lower()
        if not any(location in path_value for location in normalized_locations):
            continue
        selected.append(
            {
                "path": candidate.get("path"),
                "categories": list(candidate.get("categories", [])),
                "size": candidate.get("size"),
                "modified_at": candidate.get("modified_at"),
            }
        )
    return selected


def build_markdown_report(
    summary_payload: Mapping[str, object],
    *,
    docs_payload: Mapping[str, object] | None = None,
    files_payload: Mapping[str, object] | None = None,
    docs_extract_payload: Mapping[str, object] | None = None,
    files_extract_payload: Mapping[str, object] | None = None,
    artifact_payloads: Mapping[str, Mapping[str, object]] | None = None,
    timeline_payload: Mapping[str, object] | None = None,
    indicators_payload: Mapping[str, object] | None = None,
) -> str:
    report_context = build_run_report_context(
        summary_payload,
        docs_payload=docs_payload,
        files_payload=files_payload,
        docs_extract_payload=docs_extract_payload,
        files_extract_payload=files_extract_payload,
        artifact_payloads=artifact_payloads,
        timeline_payload=timeline_payload,
        indicators_payload=indicators_payload,
    )
    return render_run_markdown_report(report_context)


def build_key_hit_rows(
    summary_payload: Mapping[str, object],
    *,
    docs_payload: Mapping[str, object],
    files_payload: Mapping[str, object],
    artifact_payloads: Mapping[str, Mapping[str, object]],
    timeline_payload: Mapping[str, object],
) -> List[str]:
    rows: List[str] = []
    matched_rules = summary_payload.get("matched_rules", [])
    if isinstance(matched_rules, list) and matched_rules:
        rows.append(f"Matched rules: {', '.join(str(item) for item in matched_rules[:5])}")

    ioc_hits = summary_payload.get("ioc_hits", [])
    if isinstance(ioc_hits, list):
        for hit in ioc_hits[:3]:
            if not isinstance(hit, dict):
                continue
            rows.append(
                f"IOC `{hit.get('value')}` detected via `{hit.get('type')}`"
                f" (rule `{hit.get('rule_id')}`)"
            )

    for item in docs_payload.get("results", [])[:3]:
        if not isinstance(item, dict):
            continue
        keywords = ", ".join(str(keyword) for keyword in item.get("matched_keywords", []))
        rows.append(f"Document hit `{item.get('path')}` keywords={keywords or 'none'}")

    for item in files_payload.get("candidates", [])[:2]:
        if not isinstance(item, dict):
            continue
        rows.append(
            f"File candidate `{item.get('path')}` categories={', '.join(str(value) for value in item.get('categories', []))}"
        )

    for kind, payload in artifact_payloads.items():
        artifact_count = int(payload.get("summary", {}).get("artifact_count", 0))
        if artifact_count:
            rows.append(f"Artifact collector `{kind}` returned {artifact_count} row(s)")

    for event in timeline_payload.get("events", [])[:2]:
        if not isinstance(event, dict):
            continue
        rows.append(
            f"Timeline `{event.get('timestamp')}` `{event.get('event_type')}` — {event.get('summary')}"
        )

    seen: set[str] = set()
    deduped: List[str] = []
    for row in rows:
        if row in seen:
            continue
        seen.add(row)
        deduped.append(row)
    return deduped[:10]


def append_related_document_rows(lines: List[str], results: object) -> None:
    if not isinstance(results, list) or not results:
        lines.append("- none")
        return
    for item in results[:10]:
        if not isinstance(item, dict):
            continue
        keywords = ", ".join(str(keyword) for keyword in item.get("matched_keywords", [])) or "none"
        lines.append(
            f"- `{item.get('path')}` ({item.get('kind')}) keywords={keywords}: {item.get('preview')}"
        )
        matched_rules = item.get("matched_rules", [])
        if isinstance(matched_rules, list) and matched_rules:
            lines.append(f"  - matched_rules: {', '.join(str(rule_id) for rule_id in matched_rules)}")
        ioc_hits = item.get("ioc_hits", [])
        if isinstance(ioc_hits, list) and ioc_hits:
            values = ", ".join(str(hit.get('value')) for hit in ioc_hits[:5] if isinstance(hit, dict))
            lines.append(f"  - ioc_hits: {values}")


def append_artifact_summary_rows(lines: List[str], artifact_payloads: Mapping[str, Mapping[str, object]]) -> None:
    if not artifact_payloads:
        lines.append("- none")
        return
    for kind, payload in artifact_payloads.items():
        summary = payload.get("summary", {})
        lines.append(
            f"- `{kind}` count={summary.get('artifact_count', 0)}"
            f" types={dict(summary.get('artifact_type_counts', {}))}"
        )
        artifacts = payload.get("artifacts", [])
        if not isinstance(artifacts, list):
            continue
        for artifact in artifacts[:3]:
            if not isinstance(artifact, dict):
                continue
            lines.append(
                f"  - `{artifact.get('artifact_type')}` `{artifact.get('path')}` provider=`{artifact.get('provider')}`"
            )


def append_timeline_rows(lines: List[str], timeline_payload: Mapping[str, object]) -> None:
    summary = timeline_payload.get("summary", {})
    events = timeline_payload.get("events", [])
    if not isinstance(events, list) or not events:
        lines.append("- none")
        return
    lines.extend(
        [
            f"- Event count: {summary.get('event_count', 0)}",
            f"- Earliest event: `{summary.get('earliest_event_at')}`",
            f"- Latest event: `{summary.get('latest_event_at')}`",
        ]
    )
    for event in events[:15]:
        if not isinstance(event, dict):
            continue
        lines.append(
            f"- `{event.get('timestamp')}` `{event.get('source')}` `{event.get('event_type')}`"
            f" `{event.get('path')}` — {event.get('summary')}"
        )
        matched_rules = event.get("matched_rules", [])
        if isinstance(matched_rules, list) and matched_rules:
            lines.append(f"  - matched_rules: {', '.join(str(rule_id) for rule_id in matched_rules)}")
        ioc_hits = event.get("ioc_hits", [])
        if isinstance(ioc_hits, list) and ioc_hits:
            values = ", ".join(str(hit.get('value')) for hit in ioc_hits[:5] if isinstance(hit, dict))
            lines.append(f"  - ioc_hits: {values}")


def append_extract_rows(
    lines: List[str],
    *,
    title: str,
    payload: Mapping[str, object],
    source_label: str,
) -> None:
    lines.extend([title, ""])
    summary = payload.get("summary", {})
    lines.append(
        f"- selected={summary.get('selected_count', 0)} extracted={summary.get('extracted_count', 0)}"
        f" skipped={summary.get('skipped_count', 0)} source={source_label}"
    )
    entries = payload.get("entries", [])
    if isinstance(entries, list) and entries:
        for entry in entries[:10]:
            if not isinstance(entry, dict):
                continue
            lines.append(
                f"  - `{entry.get('original_path')}` -> `{entry.get('extracted_path')}`"
                f" size={entry.get('size')} sha256={entry.get('sha256')}"
            )
    else:
        lines.append("  - none")
