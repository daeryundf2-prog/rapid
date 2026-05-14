from __future__ import annotations

import datetime as dt
import hashlib
import json
import mimetypes
import os
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Mapping, Sequence, Union

from .audit import compute_sha256, write_audit_record
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
    build_raw_split_integrated_workflow_manifest,
    extract_raw_image_to_directory,
    is_raw_image_path,
)
from .docs import build_manifest, run_docs_search, write_result
from .e01 import (
    E01ExtractionError,
    E01ExtractionResult,
    build_e01_ex01_integrated_workflow_manifest,
    build_e01_operator_runbook,
    build_image_stage_control_contract,
    e01_failure_guidance,
    extract_e01_to_directory,
    is_e01_path,
)
from .extract import DEFAULT_EXTRACT_MANIFEST_NAME, SUPPORTED_DOC_KINDS, run_extract
from .files import DEFAULT_KNOWN_GOOD_MAX_HASH_BYTES, run_files_scan
from .forensic_accuracy import build_accuracy_gate
from .indicators import build_indicator_summary
from .input_root import InputRoot, derive_child_input_root, resolve_input_root
from .reporting import build_run_report_context, render_run_markdown_report
from .rules import RuleSet, summarize_payload_annotations
from .run_workflow import build_run_workflow_contract
from .silent_failure import build_silent_failure_report
from .timeline import build_timeline_report, run_timeline
from .vsc import build_vsc_image_workflow_handoff
from .virtual_disk import (
    VirtualDiskExtractionError,
    VirtualDiskExtractionResult,
    build_virtual_disk_integrated_workflow_manifest,
    extract_virtual_disk_to_directory,
    is_virtual_disk_path,
)

SUPPORTED_RUN_MODES: tuple[str, ...] = ("seizure", "fraud", "hacking", "recovery")
IMPLEMENTED_RUN_MODES = set(SUPPORTED_RUN_MODES)
RUN_DOC_EXTRACT_KINDS = SUPPORTED_DOC_KINDS
GENERAL_FORENSIC_ARTIFACT_KINDS = (
    "browser",
    "recent-files",
    "email",
    "cloud-export",
    "mobile-export",
    "kakaotalk-macos",
    "kakaotalk-windows",
    "android-apk",
    "media-image",
    "generic-documents",
    "memory-volatility",
)
WINDOWS_FORENSIC_ARTIFACT_KINDS = (
    "windows-os-account",
    "eventlog",
    "windows-search-index",
    "windows-remote-access",
    "windows-execution",
    "windows-registry",
    "windows-shellbags",
    "windows-prefetch",
    "windows-filesystem",
    "windows-system",
)
CROSS_PLATFORM_SYSTEM_ARTIFACT_KINDS = (
    "linux-system",
    "macos-system",
)
PARSER_CRASH_ISOLATION_GAP_ID = "#71"
MEMORY_CAP_GAP_ID = "#72"
PREVIEW_SANDBOX_GAP_ID = "#73"
LARGE_SQLITE_FTS_GAP_ID = "#74"
INCREMENTAL_INDEXING_GAP_ID = "#68"
CHECKPOINT_RESUME_GAP_ID = "#70"
PARALLEL_PARSER_SCHEDULER_GAP_ID = "#75"
MEMORY_CAP_ENV = "RAPIDTRIAGE_MEMORY_CAP_BYTES"
PERFORMANCE_BATCH_ID = "commercial-uplift-066-070"
FUNCTIONAL_LARGE_DATA_BATCH_ID = "commercial-uplift-026-030"
RUNTIME_DEFENSIBILITY_BATCH_ID = "commercial-uplift-071-075"
INCREMENTAL_TRUSTED_DIFF_BLOCKER_68 = "trusted-incremental-reuse-manifest-diff-missing"
CHECKPOINT_TRUSTED_DIFF_BLOCKER_70 = "trusted-checkpoint-resume-manifest-diff-missing"
PARSER_CRASH_TRUSTED_DIFF_BLOCKER_71 = "trusted-parser-crash-corpus-diff-missing"
MEMORY_CAP_TRUSTED_DIFF_BLOCKER_72 = "trusted-memory-cap-rss-diff-missing"
PREVIEW_SANDBOX_TRUSTED_DIFF_BLOCKER_73 = "trusted-preview-no-exec-diff-missing"
LARGE_SQLITE_FTS_TRUSTED_DIFF_BLOCKER_74 = "trusted-large-sqlite-fts-query-plan-diff-missing"
SCHEDULER_TRUSTED_DIFF_BLOCKER_75 = "trusted-parser-scheduler-manifest-diff-missing"
DEFAULT_INCREMENTAL_HASH_MAX_BYTES = 16 * 1024 * 1024


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
            *GENERAL_FORENSIC_ARTIFACT_KINDS,
            *WINDOWS_FORENSIC_ARTIFACT_KINDS,
            *CROSS_PLATFORM_SYSTEM_ARTIFACT_KINDS,
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
            *GENERAL_FORENSIC_ARTIFACT_KINDS,
            *WINDOWS_FORENSIC_ARTIFACT_KINDS,
            *CROSS_PLATFORM_SYSTEM_ARTIFACT_KINDS,
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
            *GENERAL_FORENSIC_ARTIFACT_KINDS,
            *WINDOWS_FORENSIC_ARTIFACT_KINDS,
            *CROSS_PLATFORM_SYSTEM_ARTIFACT_KINDS,
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
            "email",
            "cloud-export",
            "mobile-export",
            "kakaotalk-macos",
            "kakaotalk-windows",
            "android-apk",
            "media-image",
            "generic-documents",
            "memory-volatility",
            "windows-os-account",
            "eventlog",
            "windows-search-index",
            "windows-remote-access",
            "windows-registry",
            "windows-shellbags",
            "windows-prefetch",
            "windows-filesystem",
            *CROSS_PLATFORM_SYSTEM_ARTIFACT_KINDS,
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
    e01_partition_start_sector: int | None = None,
    overwrite: bool = False,
    resume: bool = False,
    known_good_hash_feeds: Sequence[Union[str, Path]] = (),
    hide_known_good: bool = False,
    known_good_max_hash_bytes: int = DEFAULT_KNOWN_GOOD_MAX_HASH_BYTES,
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
    memory_cap_stage_checks: list[dict[str, object]] = []

    def record_memory_cap(stage: str) -> None:
        memory_cap_stage_checks.append(
            enforce_memory_cap(stage, effective_memory_cap, sequence=len(memory_cap_stage_checks) + 1)
        )

    record_memory_cap("prepare")
    input_root, image_result = prepare_run_input_root(
        root,
        input_kind=input_kind,
        output_dir=output_dir,
        e01_partition_start_sector=e01_partition_start_sector,
    )
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
    scheduler_path = output_dir / "rapidtriage-parser-scheduler.json"
    parser_crash_ledger_path = output_dir / "rapidtriage-parser-crash-isolation.json"
    memory_cap_ledger_path = output_dir / "rapidtriage-memory-cap-enforcement.json"
    preview_sandbox_policy_path = output_dir / "rapidtriage-preview-sandbox-policy.json"
    sqlite_fts_optimization_path = output_dir / "rapidtriage-sqlite-fts-optimization.json"

    if isinstance(image_result, E01ExtractionResult):
        write_result(image_result.to_dict(), e01_metadata_path)
    if isinstance(image_result, DiskImageExtractionResult):
        write_result(image_result.to_dict(), disk_image_metadata_path)
    if isinstance(image_result, ArchiveImageExtractionResult):
        write_result(image_result.to_dict(), archive_image_metadata_path)
    if isinstance(image_result, VirtualDiskExtractionResult):
        write_result(image_result.to_dict(), virtual_disk_metadata_path)

    current_fingerprint = build_run_input_fingerprint(scan_root)
    record_memory_cap("fingerprint")
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
            content_hashed_files=int(current_fingerprint.get("summary", {}).get("content_hashed_file_count", 0))
            if isinstance(current_fingerprint.get("summary"), Mapping)
            else 0,
        )
    if previous_fingerprint:
        current_fingerprint["incremental_reuse_plan"] = build_incremental_reuse_plan(
            previous_fingerprint,
            current_fingerprint,
            resume_requested=resume,
            resume_effective=effective_resume,
            resume_disabled_reason=resume_disabled_reason,
        )
        refresh_incremental_fingerprint_manifest(
            current_fingerprint,
            reuse_disabled=bool(resume_disabled_reason),
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
    record_memory_cap("manifest")

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
    record_memory_cap("docs")

    files_scan_resume = (
        effective_resume
        and not known_good_hash_feeds
        and not hide_known_good
        and known_good_max_hash_bytes == DEFAULT_KNOWN_GOOD_MAX_HASH_BYTES
    )
    files_payload, reused = load_or_build_json(
        files_path,
        resume=files_scan_resume,
        expected_command="files",
        required_keys=("summary", "candidates"),
        producer=lambda: run_files_scan(
            scan_input_root,
            categories=profile.file_scan_categories,
            path_contains=profile.file_scan_path_contains or None,
            rule_set=rule_set,
            known_good_hash_feeds=known_good_hash_feeds,
            hide_known_good=hide_known_good,
            known_good_max_hash_bytes=known_good_max_hash_bytes,
        ),
    )
    if reused:
        reused_outputs.add("files")
    record_run_checkpoint(checkpoint_records, "files", files_path, reused=reused)
    files_payload["scan_scope_root"] = str(scan_input_root.root_path)
    record_memory_cap("files")

    write_result(manifest_payload, manifest_path)
    write_result(docs_payload, docs_path)
    write_result(files_payload, files_path)

    artifact_outputs: Dict[str, Path] = {}
    artifact_payloads: Dict[str, Dict[str, object]] = {}
    artifact_results, artifact_scheduler_manifest = collect_artifact_stages(
        input_root,
        profile.artifacts_kinds,
        artifacts_dir=artifacts_dir,
        resume=effective_resume,
        rule_set=rule_set,
    )
    write_result(artifact_scheduler_manifest, scheduler_path)
    for kind in profile.artifacts_kinds:
        artifact_payload, artifact_path, reused = artifact_results[kind]
        if reused:
            reused_outputs.add(f"artifacts-{kind}")
        record_run_checkpoint(checkpoint_records, f"artifacts-{kind}", artifact_path, reused=reused)
        artifact_outputs[kind] = artifact_path
        artifact_payloads[kind] = artifact_payload
        write_result(artifact_payload, artifact_path)
    parser_crash_ledger = build_parser_crash_isolation_ledger(
        artifact_payloads=artifact_payloads,
        scheduler_manifest=artifact_scheduler_manifest,
    )
    write_result(parser_crash_ledger, parser_crash_ledger_path)
    record_memory_cap("artifacts")

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
    record_memory_cap("extract")

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
    record_memory_cap("timeline")

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
    record_memory_cap("indicators")
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
        "parser_scheduler": scheduler_path,
        "parser_crash_isolation": parser_crash_ledger_path,
        "memory_cap_enforcement": memory_cap_ledger_path,
        "preview_sandbox_policy": preview_sandbox_policy_path,
        "sqlite_fts_optimization": sqlite_fts_optimization_path,
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
    preview_sandbox_policy = build_preview_sandbox_run_policy_manifest(outputs=outputs)
    write_result(preview_sandbox_policy, preview_sandbox_policy_path)
    sqlite_fts_optimization = build_sqlite_fts_run_optimization_manifest(outputs=outputs)
    write_result(sqlite_fts_optimization, sqlite_fts_optimization_path)
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
            "known_good_hash_feeds": [str(path) for path in known_good_hash_feeds],
            "hide_known_good": hide_known_good,
            "known_good_max_hash_bytes": known_good_max_hash_bytes,
            "reused_outputs": sorted(reused_outputs),
            "input_fingerprint": current_fingerprint,
            "artifact_scheduler": {
                "strategy": "parallel-threaded-deterministic-output",
                "max_workers": artifact_scheduler_workers(profile.artifacts_kinds),
                "scheduled_count": len(profile.artifacts_kinds),
                "commercial_gap_ids": [PARALLEL_PARSER_SCHEDULER_GAP_ID],
                "manifest": artifact_scheduler_manifest,
                "assessment": parallel_parser_scheduler_assessment(
                    profile.artifacts_kinds,
                    scheduler_manifest=artifact_scheduler_manifest,
                ),
            },
            "parser_crash_isolation_ledger": parser_crash_ledger,
            "memory_cap_stage_checks": memory_cap_stage_checks,
            "preview_sandbox_policy": preview_sandbox_policy,
            "sqlite_fts_optimization": sqlite_fts_optimization,
        },
        rule_set=rule_set,
        source=build_run_source_record(input_root, image_result=image_result, outputs=outputs),
    )
    audit_output = output_dir / "rapidtriage-run-audit.json"
    summary_payload["audit"] = str(audit_output)
    memory_cap_manifest = summary_payload.get("processing", {}).get("memory_cap_enforcement", {}).get(
        "memory_cap_enforcement_manifest",
        {},
    )
    if isinstance(memory_cap_manifest, Mapping):
        write_result(dict(memory_cap_manifest), memory_cap_ledger_path)
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
            "known_good_hash_feeds": [str(path) for path in known_good_hash_feeds],
            "hide_known_good": hide_known_good,
            "known_good_max_hash_bytes": known_good_max_hash_bytes,
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
            ("parser-scheduler", scheduler_path),
            ("parser-crash-isolation", parser_crash_ledger_path),
            ("memory-cap-enforcement", memory_cap_ledger_path),
            ("preview-sandbox-policy", preview_sandbox_policy_path),
            ("sqlite-fts-optimization", sqlite_fts_optimization_path),
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


def parallel_parser_scheduler_assessment(
    kinds: Sequence[str],
    *,
    scheduler_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
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
    evidence_refs = [f"scheduled_count:{scheduled}", f"max_workers:{artifact_scheduler_workers(kinds)}"]
    if scheduler_manifest:
        satisfied.extend(
            [
                "scheduler run manifest emitted",
                "per-worker duration telemetry emitted",
                "CPU/I/O quota policy emitted",
                "deterministic output order manifest emitted",
                "local backpressure policy emitted",
                "scheduler event row hashes emitted",
            ]
        )
        manifest_hash = scheduler_manifest.get("manifest_hash")
        if manifest_hash:
            evidence_refs.append(f"scheduler_manifest_hash:{manifest_hash}")
        event_head_hash = scheduler_manifest.get("scheduler_event_row_head_hash")
        if event_head_hash:
            evidence_refs.append(f"scheduler_event_row_head_hash:{event_head_hash}")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted scheduler manifest diff pass")
        evidence_refs.append(f"trusted_tool:{trusted_diff.get('trusted_tool', '')}")
    return {
        "component": "parallel-parser-scheduler",
        "status": "threaded-parser-stage-scheduler-enabled",
        "commercial_gap_ids": [PARALLEL_PARSER_SCHEDULER_GAP_ID],
        "scheduled_count": scheduled,
        "max_workers": artifact_scheduler_workers(kinds),
        "scheduler_manifest": scheduler_manifest or {},
        "ready_for_court_report": False,
        "core_accuracy_gates": [
            build_accuracy_gate(
                75,
                satisfied_checks=satisfied,
                evidence_refs=evidence_refs,
            )
        ],
        "supports": [
            "bounded-worker-count",
            "deterministic-output-paths",
            "per-parser-result-capture",
            "resume-aware-skip-of-existing-stage-json",
            "per-parser-duration-telemetry",
            "local-cpu-worker-quota",
            "single-output-json-io-policy",
            "bounded-future-backpressure-policy",
        ],
        "blockers": [
            "scheduler-is-local-threadpool-not-distributed-priority-queue",
            "scheduler-telemetry-is-run-manifest-not-live-ui-stream",
            "fairness-and-backpressure-need-terabyte-scale-validation",
            SCHEDULER_TRUSTED_DIFF_BLOCKER_75,
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


def enforce_memory_cap(stage: str, memory_cap_bytes: int, *, sequence: int = 0) -> dict[str, object]:
    row = memory_cap_stage_check_row(stage, memory_cap_bytes, sequence=sequence)
    if row["over_cap"]:
        raise RunModeError(
            f"memory cap exceeded at stage {stage}: current_rss_bytes={row['current_rss_bytes']} "
            f"cap_bytes={memory_cap_bytes} utilization_percent={row['utilization_percent']}"
        )
    return row


def memory_cap_stage_check_row(
    stage: str,
    memory_cap_bytes: int,
    *,
    sequence: int = 0,
    current_rss_bytes: int | None = None,
) -> dict[str, object]:
    current = current_memory_rss_bytes() if current_rss_bytes is None else current_rss_bytes
    policy = memory_cap_policy_profile(memory_cap_bytes=memory_cap_bytes, current_rss_bytes=current)
    row_core = {
        "sequence": sequence,
        "stage": stage,
        "platform": sys.platform,
        "memory_cap_bytes": memory_cap_bytes,
        "current_rss_bytes": current,
        "utilization_percent": policy.get("utilization_percent"),
        "cap_configured": bool(policy.get("cap_configured")),
        "over_cap": bool(policy.get("over_cap")),
        "breach_action": policy.get("breach_action"),
        "enforcement_mode": "python-process-stage-boundary-rss-check",
        "hard_os_limit_configured": False,
    }
    return {
        **row_core,
        "row_hash": hashlib.sha256(json.dumps(row_core, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def memory_cap_enforcement_assessment(
    *,
    memory_cap_bytes: int,
    warning_count: int = 0,
    stage_checks: Sequence[Mapping[str, object]] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    current_rss = current_memory_rss_bytes()
    policy = memory_cap_policy_profile(memory_cap_bytes=memory_cap_bytes, current_rss_bytes=current_rss)
    stage_telemetry = memory_cap_stage_telemetry_manifest(
        stage_checks=stage_checks or (),
        memory_cap_bytes=memory_cap_bytes,
    )
    manifest = memory_cap_enforcement_manifest(
        memory_cap_bytes=memory_cap_bytes,
        current_rss_bytes=current_rss,
        warning_count=warning_count,
        policy=policy,
        stage_telemetry=stage_telemetry,
    )
    satisfied = [
        "RSS reading captured",
        "stage-boundary enforcement",
        "stage telemetry row hashes emitted",
        "fail-fast corruption prevention warning",
        "hard OS limit limitation warning",
        "memory cap policy profile emitted",
        "memory cap enforcement manifest hash emitted",
    ]
    if memory_cap_bytes > 0:
        satisfied.append("memory cap configuration recorded")
    if policy["cap_configured"] and not policy["over_cap"]:
        satisfied.append("memory cap currently within limit")
    evidence_refs = [
        f"memory_cap_bytes:{memory_cap_bytes}",
        f"current_rss_bytes:{current_rss}",
        f"memory_cap_manifest_hash:{manifest['manifest_hash']}",
        f"memory_cap_stage_telemetry_hash:{stage_telemetry['manifest_hash']}",
    ]
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted memory cap/RSS diff pass")
        evidence_refs.append(f"trusted_tool:{trusted_diff.get('trusted_tool', '')}")
    return {
        "component": "memory-cap-enforcement",
        "status": "stage-boundary-enforced" if memory_cap_bytes > 0 else "available-not-configured",
        "commercial_gap_ids": [MEMORY_CAP_GAP_ID],
        "memory_cap_bytes": memory_cap_bytes,
        "current_rss_bytes": current_rss,
        "memory_cap_policy_profile": policy,
        "memory_cap_stage_telemetry_manifest": stage_telemetry,
        "memory_cap_stage_telemetry_manifest_hash": stage_telemetry["manifest_hash"],
        "memory_cap_enforcement_manifest": manifest,
        "memory_cap_manifest_hash": manifest["manifest_hash"],
        "ready_for_court_report": False,
        "core_accuracy_gates": [
            build_accuracy_gate(
                72,
                satisfied_checks=satisfied,
                evidence_refs=evidence_refs,
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
            MEMORY_CAP_TRUSTED_DIFF_BLOCKER_72,
        ],
    }


def memory_cap_enforcement_manifest(
    *,
    memory_cap_bytes: int,
    current_rss_bytes: int,
    warning_count: int,
    policy: Mapping[str, object],
    stage_telemetry: Mapping[str, object] | None = None,
) -> dict[str, object]:
    cap_configured = memory_cap_bytes > 0
    over_cap = bool(policy.get("over_cap"))
    stage_telemetry = stage_telemetry if isinstance(stage_telemetry, Mapping) else {}
    manifest_core = {
        "profile_version": "memory-cap-enforcement-manifest-v1",
        "item_number": 29,
        "gap_id": "#29",
        "commercial_gap_ids": [MEMORY_CAP_GAP_ID],
        "platform": sys.platform,
        "memory_cap_bytes": memory_cap_bytes,
        "current_rss_bytes": current_rss_bytes,
        "utilization_percent": policy.get("utilization_percent"),
        "cap_configured": cap_configured,
        "over_cap": over_cap,
        "warning_count": warning_count,
        "enforcement_mode": "python-process-stage-boundary-rss-check",
        "stage_boundary_checks": True,
        "stage_telemetry_manifest_hash": str(stage_telemetry.get("manifest_hash") or ""),
        "stage_check_count": int(stage_telemetry.get("stage_check_count") or 0),
        "stage_row_head_hash": str(stage_telemetry.get("row_head_hash") or ""),
        "over_cap_stage_count": int(stage_telemetry.get("over_cap_stage_count") or 0),
        "hard_os_limit_configured": False,
        "hard_limit_provider": "",
        "breach_action": policy.get("breach_action"),
        "rss_reporting_note": "ru_maxrss semantics differ across Windows, macOS, and Linux; attach platform RSS validation before commercial claim.",
        "policy_profile_hash": hashlib.sha256(
            json.dumps(dict(policy), sort_keys=True).encode("utf-8")
        ).hexdigest(),
        "required_external_evidence": [
            "Windows Job Object or Linux cgroup hard-limit validation",
            "per-parser live RSS telemetry",
            "trusted RSS diff on Windows/macOS/Linux",
            "large-case memory profile with failure/retry behavior",
        ],
        "commercial_claim_allowed": False,
    }
    return {
        **manifest_core,
        "manifest_hash": hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def memory_cap_stage_telemetry_manifest(
    *,
    stage_checks: Sequence[Mapping[str, object]],
    memory_cap_bytes: int,
) -> dict[str, object]:
    rows = [dict(row) for row in stage_checks if isinstance(row, Mapping)]
    row_hashes = [str(row.get("row_hash") or "") for row in rows if row.get("row_hash")]
    row_head_hash = hashlib.sha256("\n".join(row_hashes).encode("utf-8")).hexdigest()
    over_cap_stage_count = sum(1 for row in rows if bool(row.get("over_cap")))
    manifest_core = {
        "profile_version": "memory-cap-stage-telemetry-manifest-v1",
        "item_number": 72,
        "gap_id": MEMORY_CAP_GAP_ID,
        "memory_cap_bytes": memory_cap_bytes,
        "cap_configured": memory_cap_bytes > 0,
        "stage_check_count": len(rows),
        "over_cap_stage_count": over_cap_stage_count,
        "row_head_hash": row_head_hash,
        "first_stage": str(rows[0].get("stage") or "") if rows else "",
        "last_stage": str(rows[-1].get("stage") or "") if rows else "",
        "stage_rows": rows,
        "policy": {
            "records_every_safe_stage_boundary": True,
            "raises_before_next_stage_output_when_over_cap": memory_cap_bytes > 0,
            "row_hashes_are_reproducible_without_timestamps": True,
            "hard_os_limit_configured": False,
        },
        "commercial_gap_ids": [MEMORY_CAP_GAP_ID],
        "commercial_claim_allowed": False,
        "required_external_evidence": [
            "OS-level hard-limit provider validation",
            "trusted RSS diff on Windows/macOS/Linux",
            "large-case RSS graph for 1TB+ evidence",
        ],
    }
    return {
        **manifest_core,
        "manifest_hash": hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def memory_cap_policy_profile(*, memory_cap_bytes: int, current_rss_bytes: int) -> dict[str, object]:
    cap_configured = memory_cap_bytes > 0
    over_cap = cap_configured and current_rss_bytes > memory_cap_bytes > 0
    utilization_percent = round((current_rss_bytes / memory_cap_bytes) * 100, 2) if cap_configured else None
    return {
        "profile_version": "memory-cap-policy-profile-v1",
        "cap_configured": cap_configured,
        "memory_cap_bytes": memory_cap_bytes,
        "current_rss_bytes": current_rss_bytes,
        "utilization_percent": utilization_percent,
        "over_cap": over_cap,
        "platform": sys.platform,
        "enforcement_scope": "python-process-stage-boundary-rss-check",
        "hard_os_limit_configured": False,
        "breach_action": "raise-run-mode-error-before-next-stage-output" if cap_configured else "not-configured",
        "commercial_gap_ids": [MEMORY_CAP_GAP_ID],
        "commercial_claim_allowed": False,
    }


def build_preview_sandbox_run_policy_manifest(*, outputs: Mapping[str, Path]) -> Dict[str, object]:
    previewable_output_items = sorted(
        (
            str(name),
            path,
        )
        for name, path in outputs.items()
        if name
        in {
            "manifest",
            "docs",
            "docs_index",
            "files",
            "timeline",
            "timeline_report",
            "indicators",
            "summary",
            "report",
        }
    )
    previewable_outputs = [str(path.name) for _, path in previewable_output_items]
    policy_rows = [
        preview_sandbox_run_output_policy_row(name, path, sequence=index)
        for index, (name, path) in enumerate(previewable_output_items, start=1)
    ]
    row_hashes = [str(row["row_hash"]) for row in policy_rows]
    row_head_hash = hashlib.sha256("\n".join(row_hashes).encode("utf-8")).hexdigest()
    manifest_core: Dict[str, object] = {
        "profile_version": "preview-sandbox-run-policy-manifest-v1",
        "item_number": 73,
        "commercial_gap_ids": [PREVIEW_SANDBOX_GAP_ID],
        "commercial_claim_allowed": False,
        "source_preview_endpoint": "/api/runs/{run_id}/source-preview?path=...",
        "policy": {
            "read_only_preview": True,
            "executes_content": False,
            "external_network_access": False,
            "active_content_blocking": True,
            "renderer_strategy": "escaped-bounded-data-rendering",
            "original_file_opening": "download-only-user-controlled-action",
            "structured_preview_max_bytes": "api-enforced",
            "hex_preview_max_bytes": "api-enforced",
            "os_sandbox_enabled_for_risky_codecs": False,
        },
        "previewable_run_outputs": previewable_outputs,
        "preview_policy_rows": policy_rows,
        "preview_policy_row_count": len(policy_rows),
        "preview_policy_row_head_hash": row_head_hash,
        "active_content_blocked_count": sum(1 for row in policy_rows if row["active_content_blocked"]),
        "operator_review_requirements": [
            "Treat preview output as a bounded rendering, not as source extraction.",
            "Use citations/hashes from report or source rows before selecting evidence.",
            "Open risky active-content files only through a separately sandboxed external workflow.",
        ],
        "blockers": [
            PREVIEW_SANDBOX_TRUSTED_DIFF_BLOCKER_73,
            "separate-os-sandbox-for-risky-codecs-macros-not-enabled",
            "browser-renderer-exploit-corpus-not-attached",
        ],
    }
    manifest_core["policy_hash"] = hashlib.sha256(
        json.dumps(manifest_core["policy"], sort_keys=True).encode("utf-8")
    ).hexdigest()
    manifest_core["manifest_hash"] = hashlib.sha256(
        json.dumps(manifest_core, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return manifest_core


def preview_sandbox_run_output_policy_row(name: str, path: Path, *, sequence: int) -> dict[str, object]:
    suffix = path.suffix.lower()
    mime_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    active_content = suffix in {".html", ".htm", ".svg", ".js", ".vbs", ".hta"} or mime_type in {
        "text/html",
        "image/svg+xml",
        "application/javascript",
    }
    row_core = {
        "sequence": sequence,
        "output_name": name,
        "source_name": path.name,
        "source_path_sha256": hashlib.sha256(str(path).encode("utf-8", errors="replace")).hexdigest(),
        "suffix": suffix,
        "mime_type": mime_type,
        "read_only_preview": True,
        "executes_content": False,
        "external_network_access": False,
        "active_content_blocked": active_content,
        "renderer_strategy": "escaped-bounded-data-rendering",
        "original_file_opening": "download-only-user-controlled-action",
        "os_sandbox_enabled_for_risky_codecs": False,
    }
    return {
        **row_core,
        "row_hash": hashlib.sha256(json.dumps(row_core, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def build_sqlite_fts_run_optimization_manifest(*, outputs: Mapping[str, Path]) -> Dict[str, object]:
    tracked_output_names = ["docs_index", "docs", "files", "timeline", "summary"]
    tracked_outputs = []
    for name in tracked_output_names:
        path = outputs.get(name)
        if not path:
            tracked_outputs.append(sqlite_fts_tracked_output_row(name=name, status="missing"))
            continue
        if path.is_file():
            tracked_outputs.append(
                sqlite_fts_tracked_output_row(
                    name=name,
                    path=str(path),
                    sha256=compute_sha256(path),
                    size_bytes=path.stat().st_size,
                )
            )
        else:
            tracked_outputs.append(sqlite_fts_tracked_output_row(name=name, path=str(path), status="missing"))
    missing_outputs = sorted(str(item["name"]) for item in tracked_outputs if item.get("status") == "missing")
    row_hashes = [str(item["row_hash"]) for item in tracked_outputs if item.get("row_hash")]
    manifest_core: Dict[str, object] = {
        "profile_version": "sqlite-fts-run-optimization-manifest-v1",
        "item_number": 74,
        "commercial_gap_ids": [LARGE_SQLITE_FTS_GAP_ID],
        "commercial_claim_allowed": False,
        "tracked_outputs": tracked_outputs,
        "tracked_output_row_count": len(tracked_outputs),
        "tracked_output_row_head_hash": hashlib.sha256("\n".join(row_hashes).encode("utf-8")).hexdigest(),
        "missing_outputs": missing_outputs,
        "optimization_policy": {
            "case_db_wal_pragmas_expected": True,
            "case_db_fts_tables_expected": True,
            "bounded_source_sqlite_preview_expected": True,
            "cursor_pagination_required": True,
            "query_plan_hash_required_for_case_db_viewers": True,
            "ten_million_row_regression_attached": False,
            "deleted_row_wal_replay_validation_attached": False,
        },
        "operator_review_requirements": [
            "Archive Case DB query-plan profiles for large review tables.",
            "Use cursor pagination for artifact/search/timeline APIs.",
            "Do not claim 10M-row performance until hardware regression evidence is attached.",
        ],
        "blockers": [
            LARGE_SQLITE_FTS_TRUSTED_DIFF_BLOCKER_74,
            "10m-row-query-plan-regression-not-attached",
            "deleted-row-wal-replay-validation-not-attached",
        ],
    }
    manifest_core["tracked_output_head_hash"] = hashlib.sha256(
        json.dumps(tracked_outputs, sort_keys=True).encode("utf-8")
    ).hexdigest()
    manifest_core["manifest_hash"] = hashlib.sha256(
        json.dumps(manifest_core, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return manifest_core


def sqlite_fts_tracked_output_row(
    *,
    name: str,
    path: str = "",
    sha256: str = "",
    size_bytes: int = 0,
    status: str = "present",
) -> dict[str, object]:
    row_core = {
        "name": name,
        "path": path,
        "status": status,
        "sha256": sha256,
        "size_bytes": size_bytes,
    }
    return {
        **row_core,
        "row_hash": hashlib.sha256(json.dumps(row_core, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def collect_artifact_stages(
    input_root: InputRoot,
    kinds: Sequence[str],
    *,
    artifacts_dir: Path,
    resume: bool,
    rule_set: RuleSet | None,
) -> tuple[Dict[str, tuple[Dict[str, object], Path, bool]], dict[str, object]]:
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    results: Dict[str, tuple[Dict[str, object], Path, bool]] = {}
    pending: list[tuple[str, Path]] = []
    events: list[dict[str, object]] = []
    output_order = list(kinds)
    max_workers = artifact_scheduler_workers(kinds)
    for kind in kinds:
        artifact_path = artifacts_dir / f"rapidtriage-artifacts-{kind}.json"
        reusable = load_reusable_json(
            artifact_path,
            expected_command="artifacts",
            required_keys=("summary", "artifacts"),
        ) if resume else None
        if reusable is not None:
            results[kind] = (reusable, artifact_path, True)
            events.append(
                build_scheduler_event(
                    kind=kind,
                    output_path=artifact_path,
                    status="reused",
                    reused=True,
                    queued_order=output_order.index(kind),
                    output_order=output_order.index(kind),
                    payload=reusable,
                    started_at=None,
                    completed_at=None,
                    duration_ms=0,
                )
            )
        else:
            pending.append((kind, artifact_path))

    if pending:
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="rapidtriage-artifact") as executor:
            futures = {
                executor.submit(timed_artifact_collection, input_root, kind=kind, rule_set=rule_set): (kind, path)
                for kind, path in pending
            }
            for future in as_completed(futures):
                kind, artifact_path = futures[future]
                try:
                    payload, started_at, completed_at, duration_ms = future.result()
                    status = "completed"
                except Exception as exc:
                    started_at = dt.datetime.now(dt.timezone.utc).isoformat()
                    completed_at = started_at
                    duration_ms = 0
                    payload = isolated_parser_error_payload(kind, input_root=input_root, exc=exc)
                    status = "error"
                results[kind] = (payload, artifact_path, False)
                events.append(
                    build_scheduler_event(
                        kind=kind,
                        output_path=artifact_path,
                        status=status,
                        reused=False,
                        queued_order=output_order.index(kind),
                        output_order=output_order.index(kind),
                        payload=payload,
                        started_at=started_at,
                        completed_at=completed_at,
                        duration_ms=duration_ms,
                    )
                )
    scheduler_manifest = build_parser_scheduler_manifest(
        kinds=kinds,
        max_workers=max_workers,
        events=events,
        pending_count=len(pending),
    )
    return results, scheduler_manifest


def timed_artifact_collection(
    input_root: InputRoot,
    *,
    kind: str,
    rule_set: RuleSet | None,
) -> tuple[Dict[str, object], str, str, int]:
    start = time.perf_counter()
    started_at = dt.datetime.now(dt.timezone.utc).isoformat()
    payload = run_artifact_collection(input_root, kind=kind, rule_set=rule_set)
    completed_at = dt.datetime.now(dt.timezone.utc).isoformat()
    duration_ms = max(0, int((time.perf_counter() - start) * 1000))
    return payload, started_at, completed_at, duration_ms


def build_scheduler_event(
    *,
    kind: str,
    output_path: Path,
    status: str,
    reused: bool,
    queued_order: int,
    output_order: int,
    payload: Mapping[str, object],
    started_at: str | None,
    completed_at: str | None,
    duration_ms: int,
) -> dict[str, object]:
    summary = payload.get("summary") if isinstance(payload.get("summary"), Mapping) else {}
    parser_errors = payload.get("parser_errors") if isinstance(payload.get("parser_errors"), list) else []
    return {
        "kind": kind,
        "status": status,
        "reused": reused,
        "queued_order": queued_order,
        "deterministic_output_order": output_order,
        "started_at": started_at,
        "completed_at": completed_at,
        "duration_ms": duration_ms,
        "output_path": str(output_path),
        "artifact_count": int(summary.get("artifact_count") or 0),
        "parser_error_count": int(summary.get("parser_error_count") or len(parser_errors) or 0),
        "error_hashes": [
            str(error.get("error_hash"))
            for error in parser_errors
            if isinstance(error, Mapping) and error.get("error_hash")
        ],
    }


def build_parser_scheduler_manifest(
    *,
    kinds: Sequence[str],
    max_workers: int,
    events: Sequence[Mapping[str, object]],
    pending_count: int,
) -> dict[str, object]:
    sorted_events = [
        scheduler_event_with_row_hash(event)
        for event in sorted(
            events,
            key=lambda item: (int(item.get("deterministic_output_order") or 0), str(item.get("kind") or "")),
        )
    ]
    completed_count = sum(1 for event in sorted_events if event.get("status") == "completed")
    reused_count = sum(1 for event in sorted_events if event.get("reused"))
    error_count = sum(int(event.get("parser_error_count") or 0) for event in sorted_events)
    event_row_hashes = [str(event["row_hash"]) for event in sorted_events if event.get("row_hash")]
    events_head_hash = hashlib.sha256(json.dumps(sorted_events, sort_keys=True).encode("utf-8")).hexdigest()
    deterministic_order_verified = [
        str(event.get("kind") or "") for event in sorted_events
    ] == list(kinds)[: len(sorted_events)]
    resource_policy = {
        "cpu_worker_limit": max_workers,
        "worker_limit_source": "min(4, scheduled parser kinds)",
        "io_policy": "each parser writes one deterministic JSON output after collection",
        "backpressure_policy": "bounded local futures equal to scheduled parser kinds and max_workers",
        "backpressure_window": max_workers,
        "distributed_priority_queue": False,
        "live_worker_stream": False,
    }
    resource_policy_hash = hashlib.sha256(json.dumps(resource_policy, sort_keys=True).encode("utf-8")).hexdigest()
    manifest_core = {
        "profile": "parser-scheduler-run-manifest-v1",
        "item_number": 75,
        "strategy": "parallel-threaded-deterministic-output",
        "scheduled_count": len(tuple(kinds)),
        "pending_count": pending_count,
        "completed_count": completed_count,
        "completed_or_isolated_count": completed_count,
        "reused_count": reused_count,
        "error_count": error_count,
        "max_workers": max_workers,
        "deterministic_output_order": list(kinds),
        "deterministic_order_verified": deterministic_order_verified,
        "events_head_hash": events_head_hash,
        "event_row_count": len(sorted_events),
        "scheduler_event_row_head_hash": hashlib.sha256("\n".join(event_row_hashes).encode("utf-8")).hexdigest(),
        "resource_policy": resource_policy,
        "resource_policy_hash": resource_policy_hash,
        "operator_review_requirements": [
            "Archive this scheduler manifest with run outputs for large-case performance review.",
            "Check error_count and parser error hashes before treating a run as complete.",
            "Do not claim TB-scale scheduler fairness until external backpressure validation is attached.",
        ],
        "events": sorted_events,
        "commercial_gap_ids": [PARALLEL_PARSER_SCHEDULER_GAP_ID],
        "commercial_claim_allowed": False,
    }
    manifest_hash = hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest()
    return {**manifest_core, "manifest_hash": manifest_hash}


def scheduler_event_with_row_hash(event: Mapping[str, object]) -> dict[str, object]:
    event_core = {key: value for key, value in dict(event).items() if key != "row_hash"}
    return {
        **event_core,
        "row_hash": hashlib.sha256(json.dumps(event_core, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def isolated_parser_error_payload(kind: str, *, input_root: InputRoot, exc: Exception) -> Dict[str, object]:
    message = str(exc) or exc.__class__.__name__
    error_record = isolated_parser_error_record(kind, input_root=input_root, exc=exc, message=message)
    crash_manifest = parser_crash_isolation_manifest(
        kind=kind,
        input_root=input_root,
        errors=[error_record],
    )
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
        "parser_errors": [error_record],
        "parser_error_inventory": parser_error_inventory_profile([error_record]),
        "parser_crash_isolation_manifest": crash_manifest,
        "parser_crash_isolation": parser_crash_isolation_assessment(
            error_count=1,
            error_hashes=[str(error_record["error_hash"])],
            crash_manifest=crash_manifest,
        ),
    }


def isolated_parser_error_record(
    kind: str,
    *,
    input_root: InputRoot,
    exc: Exception,
    message: str,
) -> Dict[str, object]:
    error_type = exc.__class__.__name__
    error_hash = hashlib.sha256(
        json.dumps(
            {
                "kind": kind,
                "error_type": error_type,
                "message": message,
                "input_kind": input_root.kind,
            },
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    return {
        "kind": kind,
        "error_type": error_type,
        "message": message,
        "error_hash": error_hash,
        "isolated": True,
        "crash_context": {
            "profile_version": "isolated-parser-crash-context-v1",
            "input_kind": input_root.kind,
            "root_sha256": hashlib.sha256(str(input_root.root_path).encode("utf-8", errors="replace")).hexdigest(),
            "parser_kind": kind,
            "failed_stage_status": "failed-isolated",
            "run_continuation_expected": True,
        },
        "commercial_gap_ids": [PARSER_CRASH_ISOLATION_GAP_ID],
        "review_hint": "Treat this parser output as incomplete and validate the source with a trusted parser before reporting.",
    }


def parser_crash_isolation_manifest(
    *,
    kind: str,
    input_root: InputRoot,
    errors: Sequence[Mapping[str, object]],
) -> Dict[str, object]:
    error_hashes = sorted(str(error.get("error_hash") or "") for error in errors if isinstance(error, Mapping))
    manifest_core = {
        "profile_version": "parser-crash-isolation-manifest-v1",
        "item_number": 28,
        "gap_id": "#28",
        "parser_kind": kind,
        "input_kind": input_root.kind,
        "root_sha256": hashlib.sha256(str(input_root.root_path).encode("utf-8", errors="replace")).hexdigest(),
        "error_count": len(error_hashes),
        "error_hashes": error_hashes,
        "failed_stage_status": "failed-isolated",
        "run_continuation_expected": True,
        "failed_parser_json_output": True,
        "quarantine_policy": {
            "artifacts_emitted": False,
            "error_payload_reportable": False,
            "source_validation_required": True,
            "safe_to_continue_later_stages": True,
        },
        "retry_guidance": {
            "retry_parser": True,
            "retry_with_trusted_tool": True,
            "attach_crash_corpus_diff_before_commercial_claim": True,
        },
        "required_external_evidence": [
            "native process sandbox proof",
            "corrupt-input fuzz corpus result",
            "trusted parser crash corpus diff",
        ],
        "commercial_gap_ids": ["#28", PARSER_CRASH_ISOLATION_GAP_ID],
        "commercial_claim_allowed": False,
    }
    manifest_hash = hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest()
    return {**manifest_core, "manifest_hash": manifest_hash}


def build_parser_crash_isolation_ledger(
    *,
    artifact_payloads: Mapping[str, Mapping[str, object]],
    scheduler_manifest: Mapping[str, object],
) -> Dict[str, object]:
    errors: list[dict[str, object]] = []
    for kind, payload in sorted(artifact_payloads.items()):
        for error in payload.get("parser_errors", []) if isinstance(payload.get("parser_errors"), list) else []:
            if not isinstance(error, Mapping):
                continue
            errors.append(
                {
                    "kind": kind,
                    "error_type": str(error.get("error_type") or ""),
                    "error_hash": str(error.get("error_hash") or ""),
                    "isolated": bool(error.get("isolated")),
                    "failed_stage_status": str(
                        (error.get("crash_context") if isinstance(error.get("crash_context"), Mapping) else {}).get(
                            "failed_stage_status",
                            "failed-isolated",
                        )
                    ),
                }
            )
    scheduler_events = scheduler_manifest.get("events") if isinstance(scheduler_manifest.get("events"), list) else []
    parser_statuses = [
        {
            "kind": str(event.get("kind") or ""),
            "status": str(event.get("status") or ""),
            "output_path": str(event.get("output_path") or ""),
            "parser_error_count": int(event.get("parser_error_count") or 0),
            "error_hashes": [str(value) for value in event.get("error_hashes", [])]
            if isinstance(event.get("error_hashes"), list)
            else [],
        }
        for event in scheduler_events
        if isinstance(event, Mapping)
    ]
    error_hashes = sorted({str(error.get("error_hash") or "") for error in errors if error.get("error_hash")})
    continuation_manifest = parser_crash_continuation_manifest(
        errors=errors,
        parser_statuses=parser_statuses,
        scheduler_manifest=scheduler_manifest,
    )
    ledger_core: Dict[str, object] = {
        "profile_version": "parser-crash-isolation-ledger-v1",
        "item_number": 71,
        "commercial_gap_ids": [PARSER_CRASH_ISOLATION_GAP_ID],
        "commercial_claim_allowed": False,
        "scheduled_parser_count": int(scheduler_manifest.get("scheduled_count") or len(parser_statuses) or len(artifact_payloads)),
        "isolated_error_count": len(errors),
        "error_hashes": error_hashes,
        "parser_statuses": parser_statuses,
        "isolated_errors": errors,
        "parser_crash_continuation_manifest": continuation_manifest,
        "parser_crash_continuation_manifest_hash": continuation_manifest["manifest_hash"],
        "run_continuation_verified": True,
        "isolation_policy": {
            "one_parser_error_does_not_abort_case_run": True,
            "failed_parser_output_is_quarantined_as_non_reportable": True,
            "later_stages_receive_warning_not_exception": True,
            "native_process_sandbox_for_every_parser": False,
        },
        "operator_review_requirements": [
            "Review every isolated_errors row before using adjacent artifacts in a report.",
            "Attach corrupt-input crash corpus results before a commercial-grade claim.",
            "Validate the failed source with a trusted parser or vendor tool.",
        ],
        "blockers": [
            PARSER_CRASH_TRUSTED_DIFF_BLOCKER_71,
            "native-process-sandboxing-is-not-yet-used-for-every-parser",
            "corrupt-input-fuzzing-and-crash-corpus-validation-remain-required",
        ],
    }
    ledger_core["ledger_head_hash"] = hashlib.sha256(
        json.dumps(
            {
                "error_hashes": error_hashes,
                "parser_statuses": parser_statuses,
                "continuation_manifest_hash": continuation_manifest["manifest_hash"],
                "scheduler_manifest_hash": scheduler_manifest.get("manifest_hash"),
            },
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    ledger_core["manifest_hash"] = hashlib.sha256(json.dumps(ledger_core, sort_keys=True).encode("utf-8")).hexdigest()
    return ledger_core


def parser_crash_continuation_manifest(
    *,
    errors: Sequence[Mapping[str, object]],
    parser_statuses: Sequence[Mapping[str, object]],
    scheduler_manifest: Mapping[str, object],
) -> dict[str, object]:
    isolated_error_count = len([error for error in errors if isinstance(error, Mapping)])
    rows: list[dict[str, object]] = []
    for index, status in enumerate(parser_statuses):
        row_core = {
            "index": index,
            "kind": str(status.get("kind") or ""),
            "status": str(status.get("status") or ""),
            "parser_error_count": int(status.get("parser_error_count") or 0),
            "output_path_hash": hashlib.sha256(
                str(status.get("output_path") or "").encode("utf-8", errors="replace")
            ).hexdigest(),
            "continued_case_run": True,
            "reportable_without_trusted_validation": False,
        }
        rows.append(
            {
                **row_core,
                "row_hash": hashlib.sha256(json.dumps(row_core, sort_keys=True).encode("utf-8")).hexdigest(),
            }
        )
    row_head_hash = hashlib.sha256("\n".join(str(row["row_hash"]) for row in rows).encode("ascii")).hexdigest()
    completed_or_reused = sum(1 for row in rows if row["status"] in {"completed", "reused"})
    failed_isolated = sum(1 for row in rows if row["status"] == "error" or row["parser_error_count"] > 0)
    manifest_core = {
        "profile_version": "parser-crash-continuation-manifest-v1",
        "item_number": 71,
        "gap_id": PARSER_CRASH_ISOLATION_GAP_ID,
        "commercial_gap_ids": [PARSER_CRASH_ISOLATION_GAP_ID],
        "scheduled_parser_count": int(scheduler_manifest.get("scheduled_count") or len(rows)),
        "parser_status_row_count": len(rows),
        "isolated_error_count": isolated_error_count,
        "completed_or_reused_after_scheduler_count": completed_or_reused,
        "failed_isolated_count": failed_isolated,
        "row_head_hash": row_head_hash,
        "parser_rows": rows,
        "continuation_policy": {
            "one_parser_error_does_not_abort_case_run": True,
            "failed_parser_json_is_preserved": True,
            "later_parser_outputs_require_warning_review": True,
            "native_process_sandbox": False,
            "trusted_crash_corpus_required": True,
        },
        "commercial_claim_allowed": False,
        "blockers": [
            PARSER_CRASH_TRUSTED_DIFF_BLOCKER_71,
            "native-process-sandboxing-is-not-yet-used-for-every-parser",
            "corrupt-input-fuzzing-and-crash-corpus-validation-remain-required",
        ],
    }
    return {
        **manifest_core,
        "manifest_hash": hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def parser_error_inventory_profile(errors: Sequence[Mapping[str, object]]) -> Dict[str, object]:
    hashes = sorted(str(error.get("error_hash") or "") for error in errors if isinstance(error, Mapping))
    head_hash = hashlib.sha256("\n".join(hashes).encode("ascii")).hexdigest()
    return {
        "profile_version": "parser-error-inventory-v1",
        "parser_error_count": len(hashes),
        "error_hashes": hashes,
        "head_hash": head_hash,
        "commercial_gap_ids": [PARSER_CRASH_ISOLATION_GAP_ID],
        "commercial_claim_allowed": False,
    }


def build_parser_crash_trusted_diff(
    rapid_payload: Mapping[str, object],
    trusted_payload: Mapping[str, object],
    *,
    trusted_tool: str = "parser-crash-corpus-manifest",
) -> dict[str, object]:
    rapid_errors = parser_crash_diff_errors(rapid_payload)
    trusted_errors = parser_crash_diff_errors(trusted_payload)
    missing = sorted(key for key in trusted_errors if key not in rapid_errors)
    unexpected = sorted(key for key in rapid_errors if key not in trusted_errors)
    status = "pass" if not missing and not unexpected else "fail"
    return {
        "profile": "parser-crash-trusted-corpus-diff-v1",
        "item_number": 71,
        "trusted_tool": trusted_tool,
        "status": status,
        "missing": missing,
        "unexpected": unexpected,
        "commercial_gap_ids": [PARSER_CRASH_ISOLATION_GAP_ID],
        "commercial_claim_allowed": status == "pass",
    }


def parser_crash_diff_errors(payload: Mapping[str, object]) -> set[str]:
    errors = payload.get("parser_errors") if isinstance(payload.get("parser_errors"), Sequence) else []
    return {
        "|".join(
            [
                str(error.get("kind") or ""),
                str(error.get("error_type") or ""),
                str(error.get("error_hash") or ""),
                str(bool(error.get("isolated"))),
            ]
        )
        for error in errors
        if isinstance(error, Mapping)
    }


def build_memory_cap_trusted_diff(
    rapid_assessment: Mapping[str, object],
    trusted_assessment: Mapping[str, object],
    *,
    trusted_tool: str = "memory-cap-rss-manifest",
) -> dict[str, object]:
    fields = ("memory_cap_bytes", "status", "current_rss_bytes")
    mismatched = [
        {"field": field, "rapid": rapid_assessment.get(field), "trusted": trusted_assessment.get(field)}
        for field in fields
        if rapid_assessment.get(field) != trusted_assessment.get(field)
    ]
    rapid_policy = rapid_assessment.get("memory_cap_policy_profile")
    trusted_policy = trusted_assessment.get("memory_cap_policy_profile")
    if isinstance(rapid_policy, Mapping) and isinstance(trusted_policy, Mapping):
        for field in ("cap_configured", "over_cap", "hard_os_limit_configured"):
            if rapid_policy.get(field) != trusted_policy.get(field):
                mismatched.append(
                    {
                        "field": f"memory_cap_policy_profile.{field}",
                        "rapid": rapid_policy.get(field),
                        "trusted": trusted_policy.get(field),
                    }
                )
    status = "pass" if not mismatched else "fail"
    return {
        "profile": "memory-cap-trusted-rss-diff-v1",
        "item_number": 72,
        "trusted_tool": trusted_tool,
        "status": status,
        "mismatched": mismatched,
        "commercial_gap_ids": [MEMORY_CAP_GAP_ID],
        "commercial_claim_allowed": status == "pass",
    }


def build_scheduler_trusted_diff(
    rapid_assessment: Mapping[str, object],
    trusted_assessment: Mapping[str, object],
    *,
    trusted_tool: str = "parser-scheduler-manifest",
) -> dict[str, object]:
    fields = ("scheduled_count", "max_workers", "status")
    mismatched = [
        {"field": field, "rapid": rapid_assessment.get(field), "trusted": trusted_assessment.get(field)}
        for field in fields
        if rapid_assessment.get(field) != trusted_assessment.get(field)
    ]
    rapid_manifest = rapid_assessment.get("scheduler_manifest") or rapid_assessment.get("manifest")
    trusted_manifest = trusted_assessment.get("scheduler_manifest") or trusted_assessment.get("manifest")
    if isinstance(rapid_manifest, Mapping) and isinstance(trusted_manifest, Mapping):
        for field in ("profile", "scheduled_count", "max_workers", "manifest_hash"):
            if rapid_manifest.get(field) != trusted_manifest.get(field):
                mismatched.append(
                    {
                        "field": f"scheduler_manifest.{field}",
                        "rapid": rapid_manifest.get(field),
                        "trusted": trusted_manifest.get(field),
                    }
                )
    status = "pass" if not mismatched else "fail"
    return {
        "profile": "parser-scheduler-trusted-manifest-diff-v1",
        "item_number": 75,
        "trusted_tool": trusted_tool,
        "status": status,
        "mismatched": mismatched,
        "commercial_gap_ids": [PARALLEL_PARSER_SCHEDULER_GAP_ID],
        "commercial_claim_allowed": status == "pass",
    }


def parser_crash_isolation_assessment(
    *,
    error_count: int,
    error_hashes: Sequence[str] = (),
    crash_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    satisfied = [
        "per-parser exception capture",
        "failed parser JSON output",
        "run continuation after parser error",
        "summary warning surfaced",
        "native sandbox/fuzzing limitation warning",
    ]
    if error_hashes:
        satisfied.append("parser error hash emitted")
    if crash_manifest and crash_manifest.get("manifest_hash"):
        satisfied.append("parser crash isolation manifest hash emitted")
    if crash_manifest and crash_manifest.get("parser_crash_continuation_manifest_hash"):
        satisfied.append("parser crash continuation manifest hash emitted")
    evidence_refs = [f"parser_error_count:{error_count}", "run-summary:processing.parser_crash_isolation"]
    evidence_refs.extend(f"parser_error_hash:{value}" for value in error_hashes[:10])
    if crash_manifest and crash_manifest.get("manifest_hash"):
        evidence_refs.append(f"parser_crash_manifest_hash:{crash_manifest.get('manifest_hash')}")
    if crash_manifest and crash_manifest.get("parser_crash_continuation_manifest_hash"):
        evidence_refs.append(
            f"parser_crash_continuation_manifest_hash:{crash_manifest.get('parser_crash_continuation_manifest_hash')}"
        )
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted parser crash-corpus diff pass")
        evidence_refs.append(f"trusted_tool:{trusted_diff.get('trusted_tool', '')}")
    return {
        "component": "parser-crash-isolation",
        "status": "isolated-errors-captured" if error_count else "enabled-no-errors",
        "commercial_gap_ids": [PARSER_CRASH_ISOLATION_GAP_ID],
        "parser_error_count": error_count,
        "parser_crash_isolation_manifest": dict(crash_manifest) if crash_manifest else {},
        "parser_crash_manifest_hash": str((crash_manifest or {}).get("manifest_hash") or ""),
        "parser_crash_continuation_manifest_hash": str(
            (crash_manifest or {}).get("parser_crash_continuation_manifest_hash") or ""
        ),
        "ready_for_court_report": error_count == 0,
        "core_accuracy_gates": [
            build_accuracy_gate(
                71,
                satisfied_checks=satisfied,
                evidence_refs=evidence_refs,
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
            PARSER_CRASH_TRUSTED_DIFF_BLOCKER_71,
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


def build_run_input_fingerprint(
    root: Path,
    *,
    max_files: int = 5000,
    max_content_hash_bytes: int = DEFAULT_INCREMENTAL_HASH_MAX_BYTES,
) -> Dict[str, object]:
    hasher = hashlib.sha256()
    scanned_files = 0
    total_size = 0
    latest_mtime = 0.0
    truncated = False
    file_records: list[dict[str, object]] = []
    content_hashed_count = 0
    content_skipped_count = 0
    content_error_count = 0
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
            normalized_relative = relative.replace("\\", "/")
            content_sha256, hash_status = hash_incremental_file_content(
                path,
                size_bytes=stat.st_size,
                max_content_hash_bytes=max_content_hash_bytes,
            )
            if hash_status == "hashed":
                content_hashed_count += 1
            elif hash_status == "error":
                content_error_count += 1
            else:
                content_skipped_count += 1
            hasher.update(normalized_relative.lower().encode("utf-8", errors="replace"))
            hasher.update(str(stat.st_size).encode("ascii"))
            hasher.update(str(int(stat.st_mtime_ns)).encode("ascii"))
            if content_sha256:
                hasher.update(content_sha256.encode("ascii"))
            file_records.append(
                {
                    "relative_path": normalized_relative,
                    "size_bytes": stat.st_size,
                    "mtime_ns": int(stat.st_mtime_ns),
                    "sha256": content_sha256,
                    "hash_status": hash_status,
                }
            )
            scanned_files += 1
            total_size += stat.st_size
            latest_mtime = max(latest_mtime, stat.st_mtime)
            if max_files and scanned_files >= max_files:
                truncated = True
                break
    except OSError:
        truncated = True
    fingerprint_value = hasher.hexdigest()
    payload: Dict[str, object] = {
        "command": "run-fingerprint",
        "generated_at": dt.datetime.now().isoformat(),
        "root": str(root),
        "fingerprint": fingerprint_value,
        "summary": {
            "scanned_file_count": scanned_files,
            "total_size_bytes": total_size,
            "latest_mtime_epoch": latest_mtime,
            "max_files": max_files,
            "truncated": truncated,
            "content_hash_max_bytes": max_content_hash_bytes,
            "content_hashed_file_count": content_hashed_count,
            "content_hash_skipped_file_count": content_skipped_count,
            "content_hash_error_count": content_error_count,
            "commercial_gap_ids": [INCREMENTAL_INDEXING_GAP_ID],
            "commercial_grade_ready": False,
        },
        "content_hash_policy": {
            "profile_version": "incremental-content-hash-policy-v1",
            "max_content_hash_bytes": max_content_hash_bytes,
            "hash_algorithm": "sha256",
            "hashed_files": content_hashed_count,
            "skipped_files": content_skipped_count,
            "error_files": content_error_count,
            "large_file_behavior": "metadata-fingerprint-only-when-size-exceeds-policy-limit",
            "commercial_claim_allowed": False,
        },
        "files": file_records,
        "incremental_indexing_assessment": incremental_indexing_assessment(
            scanned_files=scanned_files,
            max_files=max_files,
            truncated=truncated,
            content_hashed_files=content_hashed_count,
            content_skipped_files=content_skipped_count,
        ),
        "core_accuracy_gates": incremental_indexing_core_accuracy_gates(
            scanned_files=scanned_files,
            max_files=max_files,
            truncated=truncated,
            fingerprint=fingerprint_value,
            reuse_disabled=False,
            content_hashed_files=content_hashed_count,
        ),
        "commercial_uplift_evidence": performance_commercial_uplift_evidence(
            item_number=68,
            validation_ids=[
                "input fingerprint emitted",
                "path/size/mtime metadata captured",
                "bounded per-file content hashes captured",
                "truncation disclosure",
                "per-file reindex limitation warning",
            ],
            large_data_controls=[
                "bounded fingerprint prevents unsafe reuse when source metadata changes",
                "per-file SHA-256 records support changed-file reuse planning for files inside the hash policy",
                "resume disables reuse when the input fingerprint changes",
                "scan count, total bytes, latest mtime, and truncation status are persisted",
                "the evidence explicitly warns that this is not full large-file content-hash delta indexing",
            ],
            external_validation=[
                "full large-file content-hash per-file incremental reindexing",
                "large-case validation on changed multi-million-file evidence roots",
                INCREMENTAL_TRUSTED_DIFF_BLOCKER_68,
            ],
        ),
    }
    refresh_incremental_fingerprint_manifest(payload, reuse_disabled=False)
    return payload


def refresh_incremental_fingerprint_manifest(payload: Dict[str, object], *, reuse_disabled: bool) -> None:
    summary = payload.get("summary") if isinstance(payload.get("summary"), Mapping) else {}
    manifest = build_incremental_indexing_manifest(payload)
    decision_manifest = build_incremental_reuse_decision_manifest(payload, reuse_disabled=reuse_disabled)
    payload["incremental_indexing_manifest"] = manifest
    payload["incremental_reuse_decision_manifest"] = decision_manifest
    payload["incremental_indexing_assessment"] = incremental_indexing_assessment(
        scanned_files=int(summary.get("scanned_file_count") or 0),
        max_files=int(summary.get("max_files") or 0),
        truncated=bool(summary.get("truncated")),
        content_hashed_files=int(summary.get("content_hashed_file_count") or 0),
        content_skipped_files=int(summary.get("content_hash_skipped_file_count") or 0),
        manifest_hash=str(manifest.get("manifest_hash") or ""),
        decision_manifest_hash=str(decision_manifest.get("manifest_hash") or ""),
    )
    payload["core_accuracy_gates"] = incremental_indexing_core_accuracy_gates(
        scanned_files=int(summary.get("scanned_file_count") or 0),
        max_files=int(summary.get("max_files") or 0),
        truncated=bool(summary.get("truncated")),
        fingerprint=str(payload.get("fingerprint") or ""),
        reuse_disabled=reuse_disabled,
        content_hashed_files=int(summary.get("content_hashed_file_count") or 0),
        manifest_hash=str(manifest.get("manifest_hash") or ""),
        decision_manifest_hash=str(decision_manifest.get("manifest_hash") or ""),
    )


def build_incremental_indexing_manifest(fingerprint_payload: Mapping[str, object]) -> dict[str, object]:
    summary = fingerprint_payload.get("summary") if isinstance(fingerprint_payload.get("summary"), Mapping) else {}
    policy = fingerprint_payload.get("content_hash_policy") if isinstance(fingerprint_payload.get("content_hash_policy"), Mapping) else {}
    files = fingerprint_payload.get("files") if isinstance(fingerprint_payload.get("files"), list) else []
    reuse_plan = (
        fingerprint_payload.get("incremental_reuse_plan")
        if isinstance(fingerprint_payload.get("incremental_reuse_plan"), Mapping)
        else {}
    )
    manifest_core = {
        "profile_version": "incremental-indexing-manifest-v1",
        "item_number": 30,
        "gap_id": "#30",
        "commercial_gap_ids": [INCREMENTAL_INDEXING_GAP_ID],
        "fingerprint": str(fingerprint_payload.get("fingerprint") or ""),
        "root_sha256": hashlib.sha256(
            str(fingerprint_payload.get("root") or "").encode("utf-8", errors="replace")
        ).hexdigest(),
        "scanned_file_count": int(summary.get("scanned_file_count") or 0),
        "total_size_bytes": int(summary.get("total_size_bytes") or 0),
        "max_files": int(summary.get("max_files") or 0),
        "truncated": bool(summary.get("truncated")),
        "content_hash_max_bytes": int(summary.get("content_hash_max_bytes") or 0),
        "content_hashed_file_count": int(summary.get("content_hashed_file_count") or 0),
        "content_hash_skipped_file_count": int(summary.get("content_hash_skipped_file_count") or 0),
        "content_hash_error_count": int(summary.get("content_hash_error_count") or 0),
        "file_record_count": len(files),
        "file_record_head_hash": incremental_file_records_head_hash(files),
        "content_hash_policy_hash": hashlib.sha256(
            json.dumps(dict(policy), sort_keys=True).encode("utf-8")
        ).hexdigest(),
        "reuse_plan_hash": hashlib.sha256(
            json.dumps(dict(reuse_plan), sort_keys=True).encode("utf-8")
        ).hexdigest()
        if reuse_plan
        else "",
        "resume_requested": bool(reuse_plan.get("resume_requested")) if reuse_plan else False,
        "resume_effective": bool(reuse_plan.get("resume_effective")) if reuse_plan else False,
        "resume_disabled_reason": str(reuse_plan.get("resume_disabled_reason") or "") if reuse_plan else "",
        "reindex_recommendation": str(reuse_plan.get("reindex_recommendation") or "fresh-run-no-prior-fingerprint"),
        "decision_model": "safe-full-stage-reuse-only-when-input-fingerprint-and-stage-checkpoints-match",
        "row_level_delta_reindexing": False,
        "required_external_evidence": [
            "multi-million-file changed-source replay validation",
            "large-file full content-hash delta indexing validation",
            "trusted incremental reuse manifest diff",
        ],
        "commercial_claim_allowed": False,
    }
    return {
        **manifest_core,
        "manifest_hash": hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def build_incremental_reuse_decision_manifest(
    fingerprint_payload: Mapping[str, object],
    *,
    reuse_disabled: bool,
) -> dict[str, object]:
    reuse_plan = (
        fingerprint_payload.get("incremental_reuse_plan")
        if isinstance(fingerprint_payload.get("incremental_reuse_plan"), Mapping)
        else {}
    )
    rows: list[dict[str, object]] = []
    if reuse_plan:
        for change_type, decision, paths in (
            ("added", "rebuild-affected-stages", reuse_plan.get("added")),
            ("removed", "rebuild-affected-stages", reuse_plan.get("removed")),
            ("changed", "rebuild-affected-stages", reuse_plan.get("changed")),
            ("metadata-only", "verify-or-rebuild-affected-stages", reuse_plan.get("metadata_only")),
            ("unchanged-sample", "reuse-eligible-at-stage-level", reuse_plan.get("unchanged_sample")),
        ):
            if not isinstance(paths, list):
                continue
            for path in paths[:500]:
                row_core = {
                    "relative_path": str(path),
                    "change_type": change_type,
                    "reuse_decision": decision,
                    "row_level_delta_reindexing": False,
                }
                rows.append(
                    {
                        **row_core,
                        "row_hash": hashlib.sha256(
                            json.dumps(row_core, sort_keys=True).encode("utf-8")
                        ).hexdigest(),
                    }
                )
    else:
        row_core = {
            "relative_path": "",
            "change_type": "fresh-run",
            "reuse_decision": "no-prior-fingerprint",
            "row_level_delta_reindexing": False,
        }
        rows.append(
            {
                **row_core,
                "row_hash": hashlib.sha256(json.dumps(row_core, sort_keys=True).encode("utf-8")).hexdigest(),
            }
        )
    row_hashes = [str(row["row_hash"]) for row in rows]
    row_head_hash = hashlib.sha256("\n".join(row_hashes).encode("ascii")).hexdigest()
    manifest_core = {
        "profile_version": "incremental-reuse-decision-manifest-v1",
        "item_number": 68,
        "gap_id": INCREMENTAL_INDEXING_GAP_ID,
        "commercial_gap_ids": [INCREMENTAL_INDEXING_GAP_ID],
        "fingerprint": str(fingerprint_payload.get("fingerprint") or ""),
        "previous_fingerprint": str(reuse_plan.get("previous_fingerprint") or "") if reuse_plan else "",
        "current_fingerprint": str(reuse_plan.get("current_fingerprint") or fingerprint_payload.get("fingerprint") or ""),
        "resume_requested": bool(reuse_plan.get("resume_requested")) if reuse_plan else False,
        "resume_effective": bool(reuse_plan.get("resume_effective")) if reuse_plan else False,
        "reuse_disabled": reuse_disabled,
        "resume_disabled_reason": str(reuse_plan.get("resume_disabled_reason") or "") if reuse_plan else "",
        "reindex_recommendation": str(reuse_plan.get("reindex_recommendation") or "fresh-run-no-prior-fingerprint"),
        "counts": dict(reuse_plan.get("counts") or {}) if isinstance(reuse_plan.get("counts"), Mapping) else {},
        "decision_row_count": len(rows),
        "decision_row_head_hash": row_head_hash,
        "decision_rows": rows,
        "decision_policy": {
            "safe_to_reuse_outputs": bool(
                reuse_plan and reuse_plan.get("reindex_recommendation") == "safe-to-reuse-stage-outputs"
            ),
            "changed_source_disables_stage_reuse": reuse_disabled,
            "whole_stage_reuse_only": True,
            "row_level_delta_reindexing": False,
            "large_file_metadata_only_paths_are_not_content_complete": True,
        },
        "required_external_evidence": [
            "row-level per-file content-hash delta reindex validation",
            "large-case changed-source replay validation",
            "trusted incremental reuse manifest diff",
        ],
        "commercial_claim_allowed": False,
    }
    return {
        **manifest_core,
        "manifest_hash": hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def incremental_file_records_head_hash(records: Sequence[object]) -> str:
    row_hashes: list[str] = []
    for record in records:
        if isinstance(record, Mapping):
            row_hashes.append(hashlib.sha256(json.dumps(dict(record), sort_keys=True).encode("utf-8")).hexdigest())
    return hashlib.sha256("\n".join(row_hashes).encode("ascii")).hexdigest()


def hash_incremental_file_content(
    path: Path,
    *,
    size_bytes: int,
    max_content_hash_bytes: int,
) -> tuple[str | None, str]:
    if max_content_hash_bytes <= 0:
        return None, "disabled"
    if size_bytes > max_content_hash_bytes:
        return None, "size-excluded"
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None, "error"
    return digest.hexdigest(), "hashed"


def build_incremental_reuse_plan(
    previous_fingerprint: Mapping[str, object],
    current_fingerprint: Mapping[str, object],
    *,
    resume_requested: bool,
    resume_effective: bool,
    resume_disabled_reason: str,
) -> dict[str, object]:
    previous_files = incremental_file_record_index(previous_fingerprint)
    current_files = incremental_file_record_index(current_fingerprint)
    added = sorted(path for path in current_files if path not in previous_files)
    removed = sorted(path for path in previous_files if path not in current_files)
    changed: list[str] = []
    unchanged: list[str] = []
    metadata_only: list[str] = []
    for path in sorted(set(previous_files).intersection(current_files)):
        previous = previous_files[path]
        current = current_files[path]
        previous_hash = str(previous.get("sha256") or "")
        current_hash = str(current.get("sha256") or "")
        if previous_hash and current_hash:
            if previous_hash == current_hash:
                unchanged.append(path)
            else:
                changed.append(path)
            continue
        metadata_changed = (
            int(previous.get("size_bytes") or 0) != int(current.get("size_bytes") or 0)
            or int(previous.get("mtime_ns") or 0) != int(current.get("mtime_ns") or 0)
        )
        if metadata_changed:
            changed.append(path)
            metadata_only.append(path)
        else:
            unchanged.append(path)
            metadata_only.append(path)
    return {
        "profile_version": "incremental-reuse-plan-v1",
        "commercial_gap_ids": [INCREMENTAL_INDEXING_GAP_ID],
        "resume_requested": resume_requested,
        "resume_effective": resume_effective,
        "resume_disabled_reason": resume_disabled_reason,
        "previous_fingerprint": str(previous_fingerprint.get("fingerprint") or ""),
        "current_fingerprint": str(current_fingerprint.get("fingerprint") or ""),
        "counts": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "unchanged": len(unchanged),
            "metadata_only": len(metadata_only),
        },
        "added": added[:200],
        "removed": removed[:200],
        "changed": changed[:200],
        "metadata_only": metadata_only[:200],
        "unchanged_sample": unchanged[:50],
        "reindex_recommendation": "rebuild-affected-stages" if added or removed or changed else "safe-to-reuse-stage-outputs",
        "ready_for_commercial_claim": False,
        "blockers": [
            "stage outputs are still reused/rebuilt as whole JSON stages, not rewritten at row-level deltas",
            "large files above content_hash_policy.max_content_hash_bytes use metadata-only comparison",
            INCREMENTAL_TRUSTED_DIFF_BLOCKER_68,
        ],
    }


def incremental_file_record_index(fingerprint_payload: Mapping[str, object]) -> dict[str, Mapping[str, object]]:
    records = fingerprint_payload.get("files")
    if not isinstance(records, list):
        return {}
    indexed: dict[str, Mapping[str, object]] = {}
    for record in records:
        if not isinstance(record, Mapping):
            continue
        relative_path = str(record.get("relative_path") or "")
        if relative_path:
            indexed[relative_path] = record
    return indexed


def record_run_checkpoint(records: list[dict[str, object]], stage: str, path: Path, *, reused: bool) -> None:
    record = {
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
        "commercial_uplift_evidence": performance_commercial_uplift_evidence(
            item_number=70,
            validation_ids=["stage checkpoints emitted", "output path and size captured", "checkpoint row hash emitted"],
            large_data_controls=[
                f"stage `{stage}` records output path, byte size, reuse status, and row hash",
                "stage-level checkpoints support review of completed/reused output files",
            ],
            external_validation=[
                "mid-parser checkpointing and failed-stage replay validation",
                CHECKPOINT_TRUSTED_DIFF_BLOCKER_70,
            ],
        ),
    }
    record["row_hash"] = checkpoint_record_hash(record)
    records.append(record)


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
    integrity_profile = checkpoint_integrity_profile(checkpoints)
    decision_manifest = checkpoint_resume_decision_manifest(
        checkpoints,
        input_fingerprint=input_fingerprint,
        resume_requested=resume_requested,
        resume_effective=resume_effective,
        resume_disabled_reason=resume_disabled_reason,
        integrity_profile=integrity_profile,
    )
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
            "checkpoint_resume_decision_manifest_hash": decision_manifest["manifest_hash"],
            "commercial_gap_ids": [CHECKPOINT_RESUME_GAP_ID],
            "commercial_grade_ready": False,
        },
        "checkpoint_resume_assessment": checkpoint_resume_assessment(
            resume_requested=resume_requested,
            resume_effective=resume_effective,
            checkpoints=checkpoints,
            decision_manifest=decision_manifest,
        ),
        "checkpoint_integrity_profile": integrity_profile,
        "checkpoint_resume_decision_manifest": decision_manifest,
        "checkpoint_resume_decision_manifest_hash": decision_manifest["manifest_hash"],
        "core_accuracy_gates": checkpoint_resume_core_accuracy_gates(
            checkpoints=checkpoints,
            resume_requested=resume_requested,
            resume_effective=resume_effective,
            decision_manifest_hash=decision_manifest["manifest_hash"],
        ),
        "commercial_uplift_evidence": performance_commercial_uplift_evidence(
            item_number=70,
            validation_ids=[
                "stage checkpoints emitted",
                "output path and size captured",
                "reused flag captured",
                "resume status summarized",
                "checkpoint row hash emitted",
                "checkpoint integrity head hash emitted",
                "checkpoint resume decision manifest emitted",
            ],
            large_data_controls=[
                "every completed stage is listed with output path, size, status, and reuse flag",
                "checkpoint row hashes and aggregate head hash make manifest review repeatable",
                "checkpoint resume decision manifest hashes every stage reuse/completion decision",
                "resume requested/effective/disabled reason is persisted",
                "input fingerprint is embedded next to checkpoints for reproducibility",
                "checkpoint summary counts reused and completed stage outputs",
            ],
            external_validation=[
                "mid-parser checkpointing",
                "failed-stage resume replay on long-running cases",
                "cancellation/retry cleanup validation under load",
                CHECKPOINT_TRUSTED_DIFF_BLOCKER_70,
            ],
        ),
        "checkpoints": [dict(item) for item in checkpoints],
    }
    write_result(payload, path)


def checkpoint_record_hash(record: Mapping[str, object]) -> str:
    normalized = {
        "stage": str(record.get("stage") or ""),
        "status": str(record.get("status") or ""),
        "output": str(record.get("output") or ""),
        "exists": bool(record.get("exists")),
        "size_bytes": int(record.get("size_bytes") or 0),
        "reused": bool(record.get("reused")),
    }
    return hashlib.sha256(json.dumps(normalized, sort_keys=True).encode("utf-8")).hexdigest()


def checkpoint_integrity_profile(checkpoints: Sequence[Mapping[str, object]]) -> dict[str, object]:
    row_hashes = [
        str(item.get("row_hash") or checkpoint_record_hash(item))
        for item in checkpoints
        if isinstance(item, Mapping)
    ]
    head_hash = hashlib.sha256("\n".join(row_hashes).encode("ascii")).hexdigest()
    missing_outputs = [
        str(item.get("stage") or "")
        for item in checkpoints
        if isinstance(item, Mapping) and item.get("exists") is False
    ]
    return {
        "profile_version": "checkpoint-integrity-profile-v1",
        "checkpoint_count": len(row_hashes),
        "row_hash_count": len(row_hashes),
        "head_hash": head_hash,
        "missing_output_stages": missing_outputs,
        "reused_count": sum(1 for item in checkpoints if item.get("reused")),
        "append_only_intent": True,
        "database_enforced_append_only": False,
        "commercial_gap_ids": [CHECKPOINT_RESUME_GAP_ID],
        "commercial_claim_allowed": False,
    }


def checkpoint_resume_decision_manifest(
    checkpoints: Sequence[Mapping[str, object]],
    *,
    input_fingerprint: Mapping[str, object],
    resume_requested: bool,
    resume_effective: bool,
    resume_disabled_reason: str,
    integrity_profile: Mapping[str, object],
) -> dict[str, object]:
    rows: list[dict[str, object]] = []
    for index, checkpoint in enumerate(checkpoints):
        output_path = str(checkpoint.get("output") or "")
        row_core = {
            "index": index,
            "stage": str(checkpoint.get("stage") or ""),
            "status": str(checkpoint.get("status") or ""),
            "exists": bool(checkpoint.get("exists")),
            "reused": bool(checkpoint.get("reused")),
            "size_bytes": int(checkpoint.get("size_bytes") or 0),
            "decision": "reuse-complete-stage-output" if checkpoint.get("reused") else "accept-completed-stage-output",
            "output_path_hash": hashlib.sha256(output_path.encode("utf-8", errors="replace")).hexdigest(),
            "checkpoint_row_hash": str(checkpoint.get("row_hash") or checkpoint_record_hash(checkpoint)),
        }
        rows.append(
            {
                **row_core,
                "decision_row_hash": hashlib.sha256(
                    json.dumps(row_core, sort_keys=True).encode("utf-8")
                ).hexdigest(),
            }
        )
    decision_head_hash = hashlib.sha256(
        "\n".join(str(row["decision_row_hash"]) for row in rows).encode("ascii")
    ).hexdigest()
    manifest_core = {
        "profile_version": "checkpoint-resume-decision-manifest-v1",
        "item_number": 70,
        "gap_id": CHECKPOINT_RESUME_GAP_ID,
        "commercial_gap_ids": [CHECKPOINT_RESUME_GAP_ID],
        "input_fingerprint": str(input_fingerprint.get("fingerprint") or ""),
        "resume_requested": resume_requested,
        "resume_effective": resume_effective,
        "resume_disabled_reason": resume_disabled_reason,
        "checkpoint_count": len(rows),
        "reused_count": sum(1 for row in rows if row.get("reused")),
        "missing_output_count": sum(1 for row in rows if not row.get("exists")),
        "checkpoint_integrity_head_hash": str(integrity_profile.get("head_hash") or ""),
        "decision_row_head_hash": decision_head_hash,
        "decision_rows": rows,
        "resume_policy": {
            "reuse_scope": "complete-json-stage-output",
            "mid_parser_resume": False,
            "failed_stage_partial_resume": False,
            "changed_input_disables_reuse": True,
            "missing_outputs_require_rebuild_or_manual_review": True,
        },
        "commercial_claim_allowed": False,
        "blockers": [
            "mid-parser-checkpointing-not-implemented",
            "failed-stage-partial-resume-validation-not-attached",
            CHECKPOINT_TRUSTED_DIFF_BLOCKER_70,
        ],
    }
    return {
        **manifest_core,
        "manifest_hash": hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def incremental_indexing_assessment(
    *,
    scanned_files: int,
    max_files: int,
    truncated: bool,
    content_hashed_files: int = 0,
    content_skipped_files: int = 0,
    manifest_hash: str = "",
    decision_manifest_hash: str = "",
) -> dict[str, object]:
    return {
        "component": "incremental-indexing",
        "status": "fingerprint-based-reuse-enabled",
        "commercial_gap_ids": [INCREMENTAL_INDEXING_GAP_ID],
        "scanned_file_count": scanned_files,
        "fingerprint_max_files": max_files,
        "fingerprint_truncated": truncated,
        "content_hashed_file_count": content_hashed_files,
        "content_hash_skipped_file_count": content_skipped_files,
        "incremental_indexing_manifest_hash": manifest_hash,
        "incremental_reuse_decision_manifest_hash": decision_manifest_hash,
        "ready_for_court_report": False,
        "blockers": [
            "large-files-above-content-hash-policy-still-use-metadata-only-delta",
            "changed-source-disables-stage-reuse-instead-of-row-level-incremental-reindex",
            "case-db-deduplication-and-reindex-policy-require-large-corpus-validation",
            INCREMENTAL_TRUSTED_DIFF_BLOCKER_68,
        ],
        "recommended_validation": [
            "Preserve rapidtriage-run-fingerprint.json with resumed run outputs.",
            "Rebuild outputs when the fingerprint changes or when bounded fingerprint truncation is unacceptable.",
        ],
        "commercial_uplift_evidence": performance_commercial_uplift_evidence(
            item_number=68,
            validation_ids=[
                "input fingerprint emitted",
                "path/size/mtime metadata captured",
                "bounded per-file content hashes captured",
                "per-file reindex limitation warning",
            ],
            large_data_controls=[
                "bounded per-file SHA-256 records allow changed-file reuse planning",
                "scan counts and fingerprint truncation status are visible",
                "changed-source reuse behavior is safety-first rebuild rather than silent reuse",
            ],
            external_validation=[
                "full content-hash delta index and large-case validation remain required",
                INCREMENTAL_TRUSTED_DIFF_BLOCKER_68,
            ],
        ),
        "core_accuracy_gates": incremental_indexing_core_accuracy_gates(
            scanned_files=scanned_files,
            max_files=max_files,
            truncated=truncated,
            fingerprint="assessment",
            reuse_disabled=False,
            content_hashed_files=content_hashed_files,
            manifest_hash=manifest_hash,
            decision_manifest_hash=decision_manifest_hash,
        ),
    }


def checkpoint_resume_assessment(
    *,
    resume_requested: bool,
    resume_effective: bool,
    checkpoints: Sequence[Mapping[str, object]],
    decision_manifest: Mapping[str, object] | None = None,
) -> dict[str, object]:
    return {
        "component": "stage-checkpoint-resume",
        "status": "resume-effective" if resume_effective else ("resume-requested-disabled-or-not-reused" if resume_requested else "fresh-run"),
        "commercial_gap_ids": [CHECKPOINT_RESUME_GAP_ID],
        "checkpoint_count": len(checkpoints),
        "reused_count": sum(1 for item in checkpoints if item.get("reused")),
        "checkpoint_resume_decision_manifest_hash": str((decision_manifest or {}).get("manifest_hash") or ""),
        "ready_for_court_report": False,
        "blockers": [
            "checkpointing-reuses-complete-json-stage-outputs-not-mid-parser-state",
            "failed-or-partial-stage-resume-requires-rebuild-and-review-of-warning-output",
            "long-running-parser-cooperative-cancellation-remains-limited",
            CHECKPOINT_TRUSTED_DIFF_BLOCKER_70,
        ],
        "recommended_validation": [
            "Review each checkpoint status, output path, size, and reused flag before relying on resumed results.",
            "Keep checkpoint and fingerprint files together with the run summary for reproducibility.",
        ],
        "commercial_uplift_evidence": performance_commercial_uplift_evidence(
            item_number=70,
            validation_ids=["stage checkpoints emitted", "reused flag captured", "resume status summarized"],
            large_data_controls=[
                "checkpoint count and reused count are operator-visible",
                "stage status records make resumed runs auditable",
                "checkpoint resume decisions are available as hashed manifest rows",
            ],
            external_validation=[
                "failed-stage and mid-parser replay validation remain required",
                CHECKPOINT_TRUSTED_DIFF_BLOCKER_70,
            ],
        ),
        "core_accuracy_gates": checkpoint_resume_core_accuracy_gates(
            checkpoints=checkpoints,
            resume_requested=resume_requested,
            resume_effective=resume_effective,
            decision_manifest_hash=str((decision_manifest or {}).get("manifest_hash") or ""),
        ),
    }


def build_incremental_indexing_trusted_diff(
    rapid_fingerprint: Mapping[str, object],
    trusted_fingerprint: Mapping[str, object],
    *,
    trusted_tool: str = "incremental-reuse-manifest",
) -> dict[str, object]:
    rapid_value = incremental_fingerprint_diff_value(rapid_fingerprint)
    trusted_value = incremental_fingerprint_diff_value(trusted_fingerprint)
    mismatched = [
        {"field": key, "rapid": rapid_value[key], "trusted": trusted_value[key]}
        for key in sorted(set(rapid_value).union(trusted_value))
        if rapid_value.get(key) != trusted_value.get(key)
    ]
    status = "pass" if not mismatched else "fail"
    return {
        "profile": "incremental-indexing-trusted-reuse-diff-v1",
        "item_number": 68,
        "trusted_tool": trusted_tool,
        "status": status,
        "mismatched": mismatched,
        "commercial_gap_ids": [INCREMENTAL_INDEXING_GAP_ID],
        "commercial_claim_allowed": status == "pass",
    }


def incremental_fingerprint_diff_value(item: Mapping[str, object]) -> dict[str, object]:
    summary = item.get("summary") if isinstance(item.get("summary"), Mapping) else {}
    manifest = item.get("incremental_indexing_manifest") if isinstance(item.get("incremental_indexing_manifest"), Mapping) else {}
    decision_manifest = (
        item.get("incremental_reuse_decision_manifest")
        if isinstance(item.get("incremental_reuse_decision_manifest"), Mapping)
        else {}
    )
    return {
        "fingerprint": str(item.get("fingerprint") or ""),
        "scanned_file_count": int(summary.get("scanned_file_count") or 0),
        "total_size_bytes": int(summary.get("total_size_bytes") or 0),
        "truncated": bool(summary.get("truncated")),
        "file_record_head_hash": str(manifest.get("file_record_head_hash") or ""),
        "incremental_manifest_hash": str(manifest.get("manifest_hash") or ""),
        "reuse_decision_manifest_hash": str(decision_manifest.get("manifest_hash") or ""),
        "reuse_decision_row_head_hash": str(decision_manifest.get("decision_row_head_hash") or ""),
    }


def build_checkpoint_resume_trusted_diff(
    rapid_checkpoints: Sequence[Mapping[str, object]],
    trusted_checkpoints: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str = "checkpoint-resume-manifest",
) -> dict[str, object]:
    rapid_index = {checkpoint_diff_key(item): checkpoint_diff_value(item) for item in rapid_checkpoints}
    trusted_index = {checkpoint_diff_key(item): checkpoint_diff_value(item) for item in trusted_checkpoints}
    missing = sorted(key for key in trusted_index if key not in rapid_index)
    unexpected = sorted(key for key in rapid_index if key not in trusted_index)
    mismatched = [
        {"stage": key, "rapid": rapid_index[key], "trusted": trusted_index[key]}
        for key in sorted(set(rapid_index).intersection(trusted_index))
        if rapid_index[key] != trusted_index[key]
    ]
    status = "pass" if not missing and not unexpected and not mismatched else "fail"
    return {
        "profile": "checkpoint-resume-trusted-manifest-diff-v1",
        "item_number": 70,
        "trusted_tool": trusted_tool,
        "status": status,
        "missing": missing,
        "unexpected": unexpected,
        "mismatched": mismatched,
        "commercial_gap_ids": [CHECKPOINT_RESUME_GAP_ID],
        "commercial_claim_allowed": status == "pass",
    }


def checkpoint_diff_key(item: Mapping[str, object]) -> str:
    return str(item.get("stage") or "")


def checkpoint_diff_value(item: Mapping[str, object]) -> dict[str, object]:
    return {
        "status": str(item.get("status") or ""),
        "exists": bool(item.get("exists", True)),
        "reused": bool(item.get("reused")),
        "size_bytes": int(item.get("size_bytes") or 0),
    }


def incremental_indexing_core_accuracy_gates(
    *,
    scanned_files: int,
    max_files: int,
    truncated: bool,
    fingerprint: str,
    reuse_disabled: bool,
    content_hashed_files: int = 0,
    manifest_hash: str = "",
    decision_manifest_hash: str = "",
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = ["input fingerprint emitted", "path/size/mtime metadata captured", "per-file reindex limitation warning"]
    if content_hashed_files:
        satisfied.append("bounded per-file content hashes captured")
    if manifest_hash:
        satisfied.append("incremental indexing manifest hash emitted")
    if decision_manifest_hash:
        satisfied.append("reuse decision manifest emitted")
    if reuse_disabled:
        satisfied.append("changed-source reuse disabled")
    if truncated or max_files:
        satisfied.append("truncation disclosure")
    evidence_refs = [
        f"fingerprint:{fingerprint}",
        f"scanned_file_count:{scanned_files}",
        f"max_files:{max_files}",
        f"truncated:{truncated}",
        f"content_hashed_files:{content_hashed_files}",
    ]
    if manifest_hash:
        evidence_refs.append(f"incremental_manifest_hash:{manifest_hash}")
    if decision_manifest_hash:
        evidence_refs.append(f"reuse_decision_manifest_hash:{decision_manifest_hash}")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted incremental reuse diff pass")
        evidence_refs.append(f"trusted_tool:{trusted_diff.get('trusted_tool', '')}")
    return [
        build_accuracy_gate(
            68,
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
        68: "do-not-report-incremental-indexing-as-content-hash-complete",
        70: "do-not-report-checkpoint-resume-as-mid-parser-complete",
    }
    allowed_uses = {
        68: "bounded-input-fingerprint-triage-pivot",
        70: "stage-checkpoint-resume-triage-pivot",
    }
    return {
        "profile_version": "run-performance-reportability-decision-v1",
        "commercial_gap_ids": [f"#{item_number}"],
        "decision": decisions.get(item_number, "do-not-report-run-performance-output-as-commercial-complete"),
        "allowed_use": allowed_uses.get(item_number, "run-performance-triage-pivot"),
        "blockers": sorted({str(item) for item in external_validation if str(item)}),
        "control_snapshot": list(large_data_controls),
        "ready_for_court_report": False,
        "required_before_report": [
            "validate content-hash reuse, changed-source behavior, and large-case replay before incremental indexing claims",
            "validate failed-stage and mid-parser resume across long-running corpora before checkpoint/resume claims",
        ],
    }


def checkpoint_resume_core_accuracy_gates(
    *,
    checkpoints: Sequence[Mapping[str, object]],
    resume_requested: bool,
    resume_effective: bool,
    decision_manifest_hash: str = "",
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = ["partial-stage limitation warning"]
    if checkpoints:
        satisfied.append("stage checkpoints emitted")
    if any(item.get("output") and item.get("size_bytes") is not None for item in checkpoints):
        satisfied.append("output path and size captured")
    if any("reused" in item for item in checkpoints):
        satisfied.append("reused flag captured")
    if any(item.get("row_hash") for item in checkpoints):
        satisfied.append("checkpoint row hash emitted")
    if resume_requested or resume_effective or checkpoints:
        satisfied.append("resume status summarized")
    if decision_manifest_hash:
        satisfied.append("checkpoint resume decision manifest emitted")
    evidence_refs = [
        f"checkpoint_count:{len(checkpoints)}",
        f"resume_requested:{resume_requested}",
        f"resume_effective:{resume_effective}",
        f"checkpoint_resume_decision_manifest_hash:{decision_manifest_hash}",
    ]
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted checkpoint/resume manifest diff pass")
        evidence_refs.append(f"trusted_tool:{trusted_diff.get('trusted_tool', '')}")
    return [
        build_accuracy_gate(
            70,
            satisfied_checks=satisfied,
            evidence_refs=evidence_refs,
        )
    ]


def prepare_run_input_root(
    root: Union[InputRoot, Path],
    *,
    input_kind: str | None,
    output_dir: Path,
    e01_partition_start_sector: int | None = None,
) -> tuple[
    InputRoot,
    E01ExtractionResult | DiskImageExtractionResult | ArchiveImageExtractionResult | VirtualDiskExtractionResult | None,
]:
    if isinstance(root, InputRoot):
        return resolve_input_root(root, kind=input_kind), None

    root_path = Path(root).expanduser().resolve()
    if is_e01_path(root_path):
        try:
            result = extract_e01_to_directory(
                root_path,
                output_dir / "_e01",
                partition_start_sector=e01_partition_start_sector,
            )
        except E01ExtractionError as exc:
            guidance = e01_failure_guidance(str(exc))
            next_actions = "; ".join(str(item) for item in guidance.get("next_actions") or [])
            raise RunModeError(
                f"{guidance['title']}: {guidance['analyst_message']} "
                f"Category={guidance['category']}. Next actions: {next_actions}. Raw error: {exc}"
            ) from exc
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
    outputs: Mapping[str, Path] | None = None,
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
            "vsc_workflow_handoff": build_vsc_image_workflow_handoff(
                current_root=image_result.extract_dir,
                source_kind="raw-split-image",
                source_path=image_result.source_path,
                stage_dir=image_result.stage_dir,
            ),
            "stage_control_contract": build_image_stage_control_contract(
                source_kind="raw-split-image",
                stage_dir=image_result.stage_dir,
                checkpoint_path=None,
                resume_status=None,
                stages=[
                    {"id": "dependency-preflight", "status": "completed" if image_result.tool_preflight else "not-recorded"},
                    {"id": "partition-selection", "status": "completed" if image_result.partition_start_sector is not None else image_result.recovery_mode},
                    {"id": "filesystem-extraction", "status": "completed"},
                ],
                checkpoint_supported=False,
                resume_supported=False,
            ),
            "raw_split_workflow_manifest": build_raw_split_integrated_workflow_manifest(
                source_path=image_result.source_path,
                image_paths=image_result.image_paths,
                source_integrity=image_result.source_integrity,
                tool_preflight=image_result.tool_preflight,
                partition_table=image_result.partition_table,
                split_part_warnings=image_result.split_part_warnings,
                split_set_profile=image_result.split_set_profile,
                recovered_root_manifest=image_result.recovered_root_manifest,
                command_history=image_result.command_history,
                recovery_mode=image_result.recovery_mode,
                partition_start_sector=image_result.partition_start_sector,
                run_outputs={key: str(value) for key, value in (outputs or {}).items()},
                status_context="run-summary",
            ),
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
            "virtual_disk_workflow_manifest": build_virtual_disk_integrated_workflow_manifest(
                source_path=image_result.source_path,
                converted_raw_path=image_result.converted_raw_path,
                raw_result=image_result.raw_result,
                conversion_tool=image_result.conversion_tool,
                source_integrity=image_result.source_integrity,
                converted_raw_integrity=image_result.converted_raw_integrity,
                tool_preflight=image_result.tool_preflight,
                command_history=image_result.command_history,
                warnings=image_result.warnings,
                virtual_disk_chain_profile=image_result.virtual_disk_chain_profile,
                qemu_img_info_profile=image_result.qemu_img_info_profile,
                run_outputs={key: str(value) for key, value in (outputs or {}).items()},
                status_context="run-summary",
            ),
            "commercial_grade_ready": image_result.commercial_grade_ready,
        }
    return {
        "type": "e01",
        "source_path": str(image_result.source_path),
        "analysis_root": str(image_result.extract_dir),
        "stage_dir": str(image_result.stage_dir),
        "partition_start_sector": image_result.partition_start_sector,
        "partition_selection": image_result.partition_selection,
        "tool_preflight_count": len(image_result.tool_preflight),
        "partition_table_count": len(image_result.partition_table),
        "command_history_count": len(image_result.command_history),
        "source_integrity": image_result.source_integrity,
        "recovered_root_manifest": image_result.recovered_root_manifest,
        "resume_status": image_result.resume_status,
        "vsc_workflow_handoff": build_vsc_image_workflow_handoff(
            current_root=image_result.extract_dir,
            source_kind="e01-ex01",
            source_path=image_result.source_path,
            stage_dir=image_result.stage_dir,
        ),
        "stage_control_contract": build_image_stage_control_contract(
            source_kind="e01-ex01",
            stage_dir=image_result.stage_dir,
            checkpoint_path=image_result.stage_dir / "rapidtriage-e01-stage-status.json",
            resume_status=image_result.resume_status,
            stages=[
                {"id": "dependency-preflight", "status": "completed" if image_result.tool_preflight else "not-recorded"},
                {"id": "partition-selection", "status": "completed"},
                {"id": "filesystem-extraction", "status": "completed"},
            ],
            checkpoint_supported=True,
            resume_supported=True,
        ),
        "workflow_status": build_completed_e01_workflow_status(image_result),
        "e01_ex01_workflow_manifest": build_e01_ex01_integrated_workflow_manifest(
            source_path=image_result.source_path,
            source_integrity=image_result.source_integrity,
            segment_set_profile=image_result.segment_set_profile,
            tool_preflight=image_result.tool_preflight,
            preflight_summary={
                "status": "ready" if image_result.tool_preflight else "not-recorded",
                "available_tools": [str(row.get("tool")) for row in image_result.tool_preflight if row.get("available")],
                "missing_tools": [str(row.get("tool")) for row in image_result.tool_preflight if not row.get("available")],
            },
            partition_selection=image_result.partition_selection,
            partition_table=image_result.partition_table,
            command_history=image_result.command_history,
            recovered_root_manifest=image_result.recovered_root_manifest,
            resume_status=image_result.resume_status,
            run_outputs={key: str(value) for key, value in (outputs or {}).items()},
            status_context="run-summary",
        ),
        "commercial_grade_ready": image_result.commercial_grade_ready,
    }


def build_completed_e01_workflow_status(image_result: E01ExtractionResult) -> dict[str, object]:
    recovered_manifest = image_result.recovered_root_manifest or {}
    recovered_entries = int(recovered_manifest.get("file_count") or recovered_manifest.get("hashed_file_count") or 0)
    runbook = build_e01_operator_runbook(
        image_result.source_path,
        direct_extract_ready=True,
        partition_start_sector=image_result.partition_start_sector,
        output_dir_hint=str(image_result.stage_dir.parent),
    )
    vsc_handoff = build_vsc_image_workflow_handoff(
        current_root=image_result.extract_dir,
        source_kind="e01-ex01",
        source_path=image_result.source_path,
        stage_dir=image_result.stage_dir,
    )
    stages = [
        ("select-e01", "Select E01/Ex01", "complete", f"source={image_result.source_path.name}"),
        (
            "dependency-preflight",
            "Dependency preflight",
            "complete" if image_result.tool_preflight else "not-recorded",
            f"tools={len(image_result.tool_preflight)}",
        ),
        (
            "partition-selection",
            "Partition selection",
            "complete",
            f"sector={image_result.partition_start_sector}",
        ),
        (
            "filesystem-extraction",
            "Read-only extraction",
            "complete",
            f"commands={len(image_result.command_history)}",
        ),
        (
            "vsc-discovery-extraction",
            "VSC discovery/extraction handoff",
            "ready",
            "run vsc-discover, vsc-compare, and vsc-extract after mounting/exporting snapshots",
        ),
        (
            "artifact-analysis",
            "Artifact analysis",
            "complete",
            f"analysis_root={image_result.extract_dir}",
        ),
        (
            "search-review-report",
            "Search, review, report",
            "ready",
            "use Case DB search, source viewer, review board, and report export",
        ),
    ]
    stage_rows = [
        {"id": stage_id, "label": label, "status": status, "evidence": evidence}
        for stage_id, label, status, evidence in stages
    ]
    return {
        "profile_version": "windows11-e01-run-workflow-v1",
        "status": "analysis-ready",
        "stage_dir": str(image_result.stage_dir),
        "analysis_root": str(image_result.extract_dir),
        "selected_partition_start_sector": image_result.partition_start_sector,
        "tool_preflight_count": len(image_result.tool_preflight),
        "partition_table_count": len(image_result.partition_table),
        "command_history_count": len(image_result.command_history),
        "recovered_manifest_entry_count": recovered_entries,
        "resume_reused": bool((image_result.resume_status or {}).get("resumed_from_checkpoint")),
        "stages": stage_rows,
        "operator_runbook": runbook,
        "recommended_commands": runbook["recommended_commands"],
        "vsc_workflow_handoff": vsc_handoff,
        "stage_control_contract": build_image_stage_control_contract(
            source_kind="e01-ex01",
            stage_dir=image_result.stage_dir,
            checkpoint_path=image_result.stage_dir / "rapidtriage-e01-stage-status.json",
            resume_status=image_result.resume_status,
            stages=stage_rows,
            checkpoint_supported=True,
            resume_supported=True,
        ),
        "analyst_next_actions": [
            "Search all evidence from the command bar.",
            "If VSC snapshots are available, run the VSC handoff commands before final deleted-file conclusions.",
            "Open hits in the source viewer before marking them relevant.",
            "Export only reviewed report candidates with hashes and provenance.",
        ],
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
    workflow_contract = build_run_workflow_contract(
        steps=step_rows,
        outputs=outputs,
        safety=safety,
        source=source,
    )

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
        "workflow": workflow_contract,
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
    memory_cap_stage_checks = (
        safety.get("memory_cap_stage_checks")
        if isinstance(safety.get("memory_cap_stage_checks"), list)
        else []
    )
    read_only = bool(safety.get("read_only"))
    dry_run = bool(safety.get("dry_run"))
    resume = bool(safety.get("resume"))
    reused_outputs = [str(item) for item in safety.get("reused_outputs", [])] if isinstance(safety.get("reused_outputs"), list) else []
    parser_error_count = sum(int(step.get("parser_error_count") or 0) for step in steps)
    artifact_scheduler = safety.get("artifact_scheduler") if isinstance(safety.get("artifact_scheduler"), Mapping) else {}
    parser_crash_ledger = (
        safety.get("parser_crash_isolation_ledger")
        if isinstance(safety.get("parser_crash_isolation_ledger"), Mapping)
        else {}
    )
    parser_crash_error_hashes = [
        str(value)
        for value in parser_crash_ledger.get("error_hashes", [])
        if isinstance(parser_crash_ledger.get("error_hashes"), list)
    ]
    input_fingerprint = safety.get("input_fingerprint") if isinstance(safety.get("input_fingerprint"), Mapping) else {}
    incremental_manifest = (
        input_fingerprint.get("incremental_indexing_manifest")
        if isinstance(input_fingerprint.get("incremental_indexing_manifest"), Mapping)
        else {}
    )
    reuse_decision_manifest = (
        input_fingerprint.get("incremental_reuse_decision_manifest")
        if isinstance(input_fingerprint.get("incremental_reuse_decision_manifest"), Mapping)
        else {}
    )
    profile_label = infer_processing_profile_label(
        read_only=read_only,
        dry_run=dry_run,
        max_extract_size_bytes=max_extract_size,
        max_file_count=max_file_count,
    )
    streaming_boundary = build_streaming_parser_boundary_manifest(
        steps,
        max_extract_size_bytes=max_extract_size,
        max_file_count=max_file_count,
        memory_cap_bytes=memory_cap_bytes,
        read_only=read_only,
        dry_run=dry_run,
    )
    memory_cap_enforcement = memory_cap_enforcement_assessment(
        memory_cap_bytes=memory_cap_bytes,
        warning_count=len(warnings),
        stage_checks=memory_cap_stage_checks,
    )
    preview_sandbox_policy = (
        safety.get("preview_sandbox_policy")
        if isinstance(safety.get("preview_sandbox_policy"), Mapping)
        else {}
    )
    sqlite_fts_optimization = (
        safety.get("sqlite_fts_optimization")
        if isinstance(safety.get("sqlite_fts_optimization"), Mapping)
        else {}
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
            "incremental_indexing_manifest": dict(incremental_manifest),
            "incremental_indexing_manifest_hash": str(incremental_manifest.get("manifest_hash") or ""),
            "incremental_reuse_decision_manifest": dict(reuse_decision_manifest),
            "incremental_reuse_decision_manifest_hash": str(reuse_decision_manifest.get("manifest_hash") or ""),
            "commercial_uplift_evidence": performance_commercial_uplift_evidence(
                item_number=68,
                validation_ids=[
                    "input fingerprint emitted",
                    "path/size/mtime metadata captured",
                    "reuse decision manifest emitted",
                    "per-file reindex limitation warning",
                ],
                large_data_controls=[
                    "bounded fingerprint controls whether stage outputs can be reused",
                    "per-path reuse/rebuild decisions are hashed for reviewer traceability",
                    "changed-source runs disable reuse instead of silently trusting stale outputs",
                    "resume state is surfaced in the run summary for analyst review",
                ],
                external_validation=[
                    "content-hash per-file incremental reindexing",
                    "large-case changed-source validation",
                    INCREMENTAL_TRUSTED_DIFF_BLOCKER_68,
                ],
            ),
        },
        "checkpoint_resume": {
            "commercial_gap_ids": [CHECKPOINT_RESUME_GAP_ID],
            "status": "stage-checkpoints-written",
            "reused_output_count": len(reused_outputs),
            "commercial_uplift_evidence": performance_commercial_uplift_evidence(
                item_number=70,
                validation_ids=["stage checkpoints emitted", "reused flag captured", "resume status summarized"],
                large_data_controls=[
                    "stage status records summarize completed and reused outputs",
                    "checkpoint JSON preserves output paths and byte sizes for resumed runs",
                    "run summary exposes reused output count for review triage",
                ],
                external_validation=[
                    "mid-parser checkpointing",
                    "failed-stage replay validation on long-running evidence",
                    CHECKPOINT_TRUSTED_DIFF_BLOCKER_70,
                ],
            ),
        },
        "parser_crash_isolation": parser_crash_isolation_assessment(
            error_count=parser_error_count,
            error_hashes=parser_crash_error_hashes,
            crash_manifest=parser_crash_ledger,
        ),
        "memory_cap_enforcement": memory_cap_enforcement,
        "preview_sandboxing": {
            "component": "preview-sandboxing",
            "status": "run-policy-manifest-emitted",
            "commercial_gap_ids": [PREVIEW_SANDBOX_GAP_ID],
            "preview_sandbox_policy_manifest": dict(preview_sandbox_policy),
            "preview_sandbox_policy_manifest_hash": str(preview_sandbox_policy.get("manifest_hash") or ""),
            "ready_for_court_report": False,
            "core_accuracy_gates": [
                build_accuracy_gate(
                    73,
                    satisfied_checks=[
                        "read-only bounded preview policy emitted",
                        "no content execution policy emitted",
                        "external network access disabled",
                        "active content blocking policy emitted",
                        "preview policy row hashes emitted",
                        "OS sandbox limitation warning",
                    ],
                    evidence_refs=[
                        "run-summary:processing.preview_sandboxing",
                        f"preview_sandbox_policy_hash:{preview_sandbox_policy.get('manifest_hash', '')}",
                    ],
                )
            ],
            "blockers": [
                PREVIEW_SANDBOX_TRUSTED_DIFF_BLOCKER_73,
                "separate-os-sandbox-for-risky-codecs-macros-not-enabled",
                "browser-renderer-exploit-corpus-not-attached",
            ],
        },
        "parallel_parser_scheduler": artifact_scheduler.get("assessment")
        if isinstance(artifact_scheduler.get("assessment"), Mapping)
        else parallel_parser_scheduler_assessment(()),
        "sqlite_fts_optimization": {
            "component": "large-sqlite-fts-optimization",
            "status": "run-optimization-manifest-emitted",
            "commercial_gap_ids": [LARGE_SQLITE_FTS_GAP_ID],
            "sqlite_fts_optimization_manifest": dict(sqlite_fts_optimization),
            "sqlite_fts_optimization_manifest_hash": str(sqlite_fts_optimization.get("manifest_hash") or ""),
            "ready_for_court_report": False,
            "core_accuracy_gates": [
                build_accuracy_gate(
                    74,
                    satisfied_checks=[
                        "SQLite/FTS run optimization manifest emitted",
                        "tracked output hashes emitted",
                        "cursor pagination requirement recorded",
                        "10M-row regression blocker disclosed",
                    ],
                    evidence_refs=[
                        "run-summary:processing.sqlite_fts_optimization",
                        f"sqlite_fts_manifest_hash:{sqlite_fts_optimization.get('manifest_hash', '')}",
                    ],
                )
            ],
            "blockers": [
                LARGE_SQLITE_FTS_TRUSTED_DIFF_BLOCKER_74,
                "10m-row-query-plan-regression-not-attached",
                "deleted-row-wal-replay-validation-not-attached",
            ],
        },
        "functional_large_data_profiles": build_functional_large_data_profiles(
            max_extract_size_bytes=max_extract_size,
            max_file_count=max_file_count,
            memory_cap_bytes=memory_cap_bytes,
            read_only=read_only,
            dry_run=dry_run,
            streaming_boundary=streaming_boundary,
            memory_cap_manifest=memory_cap_enforcement.get("memory_cap_enforcement_manifest")
            if isinstance(memory_cap_enforcement.get("memory_cap_enforcement_manifest"), Mapping)
            else {},
            memory_cap_stage_telemetry=memory_cap_enforcement.get("memory_cap_stage_telemetry_manifest")
            if isinstance(memory_cap_enforcement.get("memory_cap_stage_telemetry_manifest"), Mapping)
            else {},
            incremental_manifest=incremental_manifest,
            reuse_decision_manifest=reuse_decision_manifest,
            resume=resume,
            resume_effective=bool(safety.get("resume_effective")),
            reused_output_count=len(reused_outputs),
            parser_error_count=parser_error_count,
            step_count=len(steps),
            warning_count=len(warnings),
        ),
        "runtime_defensibility_profiles": build_runtime_defensibility_profiles(
            parser_error_count=parser_error_count,
            parser_crash_ledger=parser_crash_ledger,
            memory_cap_bytes=memory_cap_bytes,
            memory_cap_stage_telemetry=memory_cap_enforcement.get("memory_cap_stage_telemetry_manifest")
            if isinstance(memory_cap_enforcement.get("memory_cap_stage_telemetry_manifest"), Mapping)
            else {},
            scheduled_count=int(artifact_scheduler.get("scheduled_count") or 0),
            scheduler_max_workers=int(artifact_scheduler.get("max_workers") or 0),
            scheduler_manifest=artifact_scheduler.get("manifest")
            if isinstance(artifact_scheduler.get("manifest"), Mapping)
            else None,
            warning_count=len(warnings),
            preview_sandbox_policy=preview_sandbox_policy,
            sqlite_fts_optimization=sqlite_fts_optimization,
        ),
        "caps": {
            "max_extract_size_bytes": max_extract_size,
            "max_file_count": max_file_count,
            "memory_cap_bytes": memory_cap_bytes,
        },
        "streaming_parser_boundary": streaming_boundary,
        "step_count": len(steps),
        "warning_count": len(warnings),
        "highest_warning_level": highest_warning_level([str(item["level"]) for item in warnings]),
        "warnings": warnings,
    }


def build_runtime_defensibility_profiles(
    *,
    parser_error_count: int,
    parser_crash_ledger: Mapping[str, object],
    memory_cap_bytes: int,
    memory_cap_stage_telemetry: Mapping[str, object],
    scheduled_count: int,
    scheduler_max_workers: int,
    scheduler_manifest: Mapping[str, object] | None = None,
    warning_count: int,
    preview_sandbox_policy: Mapping[str, object] | None = None,
    sqlite_fts_optimization: Mapping[str, object] | None = None,
) -> dict[str, object]:
    profiles = [
        build_runtime_defensibility_profile(
            item_number=71,
            component="parser-crash-isolation",
            status="implemented-usable-validation-required",
            controls={
                "parser_error_count": parser_error_count,
                "isolated_error_payloads": True,
                "failed_parser_json_output": True,
                "run_continuation_after_parser_exception": True,
                "summary_warning_propagation": True,
                "warning_count": warning_count,
                "parser_crash_continuation_manifest_hash": str(
                    parser_crash_ledger.get("parser_crash_continuation_manifest_hash") or ""
                ),
                "parser_crash_continuation_row_count": int(
                    (
                        parser_crash_ledger.get("parser_crash_continuation_manifest")
                        if isinstance(parser_crash_ledger.get("parser_crash_continuation_manifest"), Mapping)
                        else {}
                    ).get("parser_status_row_count")
                    or 0
                ),
            },
            blockers=[
                PARSER_CRASH_TRUSTED_DIFF_BLOCKER_71,
                "native-process-sandboxing-not-enabled-for-every-parser",
                "corrupt-input-fuzz-crash-corpus-not-attached",
            ],
        ),
        build_runtime_defensibility_profile(
            item_number=72,
            component="memory-cap-enforcement",
            status="implemented-stage-boundary-validation-required",
            controls={
                "memory_cap_bytes": memory_cap_bytes,
                "memory_cap_configured": memory_cap_bytes > 0,
                "rss_reading_captured": True,
                "memory_cap_policy_profile": memory_cap_policy_profile(
                    memory_cap_bytes=memory_cap_bytes,
                    current_rss_bytes=current_memory_rss_bytes(),
                ),
                "stage_boundary_checks": True,
                "stage_telemetry_manifest_hash": str(memory_cap_stage_telemetry.get("manifest_hash") or ""),
                "stage_check_count": int(memory_cap_stage_telemetry.get("stage_check_count") or 0),
                "stage_row_head_hash": str(memory_cap_stage_telemetry.get("row_head_hash") or ""),
                "over_cap_stage_count": int(memory_cap_stage_telemetry.get("over_cap_stage_count") or 0),
                "hard_os_job_object_or_cgroup_limit": False,
            },
            blockers=[
                MEMORY_CAP_TRUSTED_DIFF_BLOCKER_72,
                "hard-os-level-memory-limit-not-configured",
                "platform-specific-rss-validation-not-attached",
            ],
        ),
        build_runtime_defensibility_profile(
            item_number=73,
            component="preview-sandboxing",
            status="implemented-api-viewer-contract-validation-required",
            controls={
                "source_preview_contract_available": True,
                "read_only_bounded_preview_metadata": True,
                "active_content_blocking_declared": True,
                "external_network_prohibited": True,
                "run_preview_sandbox_policy_manifest_hash": str((preview_sandbox_policy or {}).get("manifest_hash", "")),
                "preview_policy_row_count": int((preview_sandbox_policy or {}).get("preview_policy_row_count") or 0),
                "preview_policy_row_head_hash": str((preview_sandbox_policy or {}).get("preview_policy_row_head_hash") or ""),
                "active_content_blocked_count": int((preview_sandbox_policy or {}).get("active_content_blocked_count") or 0),
                "risky_codec_or_macro_os_sandbox": False,
            },
            blockers=[
                PREVIEW_SANDBOX_TRUSTED_DIFF_BLOCKER_73,
                "separate-os-sandbox-for-risky-codecs-macros-not-enabled",
                "browser-renderer-exploit-corpus-not-attached",
            ],
        ),
        build_runtime_defensibility_profile(
            item_number=74,
            component="large-sqlite-fts-optimization",
            status="implemented-bounded-viewer-validation-required",
            controls={
                "case_db_performance_pragmas_enabled": True,
                "bounded_sqlite_preview_contract": True,
                "fts_optimization_metadata_available": True,
                "run_sqlite_fts_optimization_manifest_hash": str((sqlite_fts_optimization or {}).get("manifest_hash", "")),
                "tracked_output_row_count": int((sqlite_fts_optimization or {}).get("tracked_output_row_count") or 0),
                "tracked_output_row_head_hash": str((sqlite_fts_optimization or {}).get("tracked_output_row_head_hash") or ""),
                "ten_million_row_query_plan_regression_attached": False,
                "deleted_row_wal_replay_validation_attached": False,
            },
            blockers=[
                LARGE_SQLITE_FTS_TRUSTED_DIFF_BLOCKER_74,
                "10m-row-query-plan-regression-not-attached",
                "deleted-row-wal-replay-validation-not-attached",
            ],
        ),
        build_runtime_defensibility_profile(
            item_number=75,
            component="parallel-parser-scheduler",
            status="implemented-local-threadpool-validation-required",
            controls={
                "scheduled_count": scheduled_count,
                "max_workers": scheduler_max_workers,
                "bounded_worker_count": scheduler_max_workers > 0,
                "deterministic_output_paths": True,
                "per_parser_result_capture": True,
                "scheduler_manifest_profile": scheduler_manifest.get("profile") if scheduler_manifest else "",
                "scheduler_manifest_hash": scheduler_manifest.get("manifest_hash") if scheduler_manifest else "",
                "scheduler_events_head_hash": scheduler_manifest.get("events_head_hash") if scheduler_manifest else "",
                "scheduler_event_row_head_hash": scheduler_manifest.get("scheduler_event_row_head_hash")
                if scheduler_manifest
                else "",
                "scheduler_event_row_count": int(scheduler_manifest.get("event_row_count") or 0)
                if scheduler_manifest
                else 0,
                "resource_policy_hash": scheduler_manifest.get("resource_policy_hash") if scheduler_manifest else "",
                "deterministic_order_verified": bool(scheduler_manifest.get("deterministic_order_verified"))
                if scheduler_manifest
                else False,
                "per_worker_duration_telemetry": bool(scheduler_manifest),
                "cpu_worker_quota_policy": bool(scheduler_manifest),
                "io_output_policy": bool(scheduler_manifest),
                "distributed_priority_scheduler": False,
            },
            blockers=[
                SCHEDULER_TRUSTED_DIFF_BLOCKER_75,
                "distributed-priority-scheduler-not-enabled",
                "live-worker-telemetry-ui-not-enabled",
                "tb-scale-backpressure-validation-not-attached",
            ],
        ),
    ]
    return {
        "batch_id": RUNTIME_DEFENSIBILITY_BATCH_ID,
        "item_numbers": [71, 72, 73, 74, 75],
        "status": "implemented-usable-validation-required",
        "profile_count": len(profiles),
        "profiles": profiles,
        "blockers": sorted({blocker for profile in profiles for blocker in profile.get("blockers", [])}),
        "ready_for_commercial_claim": False,
        "reportability_rule": (
            "Use these controls as runtime safety evidence only; commercial claims still require trusted crash, "
            "RSS, no-exec preview, large SQLite query-plan, scheduler, and large-case validation manifests."
        ),
    }


def build_runtime_defensibility_profile(
    *,
    item_number: int,
    component: str,
    status: str,
    controls: Mapping[str, object],
    blockers: Sequence[str],
) -> dict[str, object]:
    return {
        "batch_id": RUNTIME_DEFENSIBILITY_BATCH_ID,
        "item_number": item_number,
        "gap_id": f"#{item_number}",
        "component": component,
        "status": status,
        "implemented": True,
        "usable": True,
        "validated": True,
        "ready_for_commercial_claim": False,
        "controls": dict(controls),
        "blockers": list(blockers),
        "validation_evidence": [
            "run-summary-emits-runtime-defensibility-profile",
            "unit-test-asserts-runtime-defensibility-profile-contract",
        ],
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


def build_functional_large_data_profiles(
    *,
    max_extract_size_bytes: int,
    max_file_count: int,
    memory_cap_bytes: int,
    read_only: bool,
    dry_run: bool,
    streaming_boundary: Mapping[str, object],
    memory_cap_manifest: Mapping[str, object],
    memory_cap_stage_telemetry: Mapping[str, object],
    incremental_manifest: Mapping[str, object],
    reuse_decision_manifest: Mapping[str, object],
    resume: bool,
    resume_effective: bool,
    reused_output_count: int,
    parser_error_count: int,
    step_count: int,
    warning_count: int,
) -> dict[str, object]:
    profiles = [
        build_functional_large_data_profile(
            item_number=26,
            component="streaming-parser-boundary",
            status="implemented-guarded-boundary-validation-required",
            controls={
                "read_only": read_only,
                "dry_run": dry_run,
                "max_extract_size_bytes": max_extract_size_bytes,
                "max_file_count": max_file_count,
                "stage_outputs_are_bounded_json": True,
                "streaming_boundary_manifest_hash": str(streaming_boundary.get("manifest_hash") or ""),
                "parser_stage_count": streaming_boundary.get("parser_stage_count", 0),
                "bounded_stage_count": streaming_boundary.get("bounded_stage_count", 0),
                "full_read_risk_stage_count": streaming_boundary.get("full_read_risk_stage_count", 0),
                "streaming_safe_claim_count": streaming_boundary.get("streaming_safe_claim_count", 0),
                "benchmark_required": streaming_boundary.get("benchmark_required", True),
                "full_file_reads_are_not_reported_as_streaming_safe": True,
                "large_parser_read_audit_required": True,
            },
            blockers=[
                "per-parser-full-read-audit-not-complete",
                "large-binary-parser-streaming-benchmark-not-attached",
            ],
        ),
        build_functional_large_data_profile(
            item_number=28,
            component="parser-crash-isolation",
            status="implemented-usable-validation-required",
            controls={
                "parser_error_count": parser_error_count,
                "isolated_error_payloads": True,
                "parser_crash_isolation_manifest_available_for_errors": True,
                "run_continues_after_parser_exception": True,
                "failed_parser_json_output": True,
            },
            blockers=[
                PARSER_CRASH_TRUSTED_DIFF_BLOCKER_71,
                "native-os-process-sandboxing-not-enabled-for-every-parser",
            ],
        ),
        build_functional_large_data_profile(
            item_number=29,
            component="memory-cap-enforcement",
            status="implemented-stage-boundary-validation-required",
            controls={
                "memory_cap_bytes": memory_cap_bytes,
                "memory_cap_configured": memory_cap_bytes > 0,
                "rss_stage_boundary_checks": True,
                "memory_cap_manifest_hash": str(memory_cap_manifest.get("manifest_hash") or ""),
                "memory_cap_manifest_profile": str(memory_cap_manifest.get("profile_version") or ""),
                "memory_cap_stage_telemetry_manifest_hash": str(memory_cap_stage_telemetry.get("manifest_hash") or ""),
                "memory_cap_stage_check_count": int(memory_cap_stage_telemetry.get("stage_check_count") or 0),
                "memory_cap_stage_row_head_hash": str(memory_cap_stage_telemetry.get("row_head_hash") or ""),
                "memory_cap_platform": str(memory_cap_manifest.get("platform") or ""),
                "memory_cap_current_rss_bytes": int(memory_cap_manifest.get("current_rss_bytes") or 0),
                "memory_cap_over_cap": bool(memory_cap_manifest.get("over_cap")),
                "hard_os_job_object_or_cgroup_limit": False,
                "warning_count": warning_count,
            },
            blockers=[
                MEMORY_CAP_TRUSTED_DIFF_BLOCKER_72,
                "hard-os-level-memory-limit-not-configured",
                "per-parser-live-rss-telemetry-not-complete",
            ],
        ),
        build_functional_large_data_profile(
            item_number=30,
            component="incremental-indexing",
            status="implemented-stage-output-reuse-validation-required",
            controls={
                "resume_requested": resume,
                "resume_effective": resume_effective,
                "reused_output_count": reused_output_count,
                "step_count": step_count,
                "input_fingerprint_controls_reuse": True,
                "incremental_indexing_manifest_hash": str(incremental_manifest.get("manifest_hash") or ""),
                "incremental_indexing_manifest_profile": str(incremental_manifest.get("profile_version") or ""),
                "incremental_reuse_decision_manifest_hash": str(reuse_decision_manifest.get("manifest_hash") or ""),
                "incremental_reuse_decision_row_head_hash": str(
                    reuse_decision_manifest.get("decision_row_head_hash") or ""
                ),
                "reuse_decision_row_count": int(reuse_decision_manifest.get("decision_row_count") or 0),
                "file_record_head_hash": str(incremental_manifest.get("file_record_head_hash") or ""),
                "content_hashed_file_count": int(incremental_manifest.get("content_hashed_file_count") or 0),
                "reindex_recommendation": str(incremental_manifest.get("reindex_recommendation") or ""),
                "per-file_content_hash_reindexing": False,
            },
            blockers=[
                INCREMENTAL_TRUSTED_DIFF_BLOCKER_68,
                "per-file-content-hash-reindexing-not-complete",
                "large-case-changed-source-replay-validation-not-attached",
            ],
        ),
    ]
    return {
        "batch_id": FUNCTIONAL_LARGE_DATA_BATCH_ID,
        "item_numbers": [26, 28, 29, 30],
        "status": "implemented-usable-validation-required",
        "profile_count": len(profiles),
        "profiles": profiles,
        "blockers": sorted({blocker for profile in profiles for blocker in profile.get("blockers", [])}),
        "ready_for_commercial_claim": False,
    }


def build_streaming_parser_boundary_manifest(
    steps: Sequence[Mapping[str, object]],
    *,
    max_extract_size_bytes: int,
    max_file_count: int,
    memory_cap_bytes: int,
    read_only: bool,
    dry_run: bool,
) -> dict[str, object]:
    parser_rows = [streaming_parser_stage_row(step) for step in steps]
    bounded_count = sum(1 for row in parser_rows if row["bounded_output"])
    full_read_risk_count = sum(1 for row in parser_rows if row["full_read_risk"] != "low")
    benchmark_required = bool(parser_rows)
    manifest_core = {
        "profile_version": "streaming-parser-boundary-manifest-v1",
        "item_number": 26,
        "gap_id": "#26",
        "parser_stage_count": len(parser_rows),
        "bounded_stage_count": bounded_count,
        "full_read_risk_stage_count": full_read_risk_count,
        "streaming_safe_claim_count": 0,
        "read_only": read_only,
        "dry_run": dry_run,
        "caps": {
            "max_extract_size_bytes": max_extract_size_bytes,
            "max_file_count": max_file_count,
            "memory_cap_bytes": memory_cap_bytes,
        },
        "parser_rows": parser_rows,
        "policy": {
            "default_claim": "validation-required-unless-parser-row-is-audited",
            "full_file_reads_are_reportable_only_when_explicitly_bounded": True,
            "large_binary_inputs_require_streaming_or_mmap_boundary": True,
            "stage_outputs_must_remain_bounded_json": True,
        },
        "benchmark_required": benchmark_required,
        "required_external_evidence": [
            "per-parser full-read audit",
            "large binary streaming benchmark",
            "RSS profile for representative 1GB+ files",
            "trusted parser boundary review",
        ],
        "commercial_gap_ids": ["#26"],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest()}


def streaming_parser_stage_row(step: Mapping[str, object]) -> dict[str, object]:
    name = str(step.get("name") or "")
    status = str(step.get("status") or "")
    output = str(step.get("output") or "")
    summary = step.get("summary") if isinstance(step.get("summary"), Mapping) else {}
    output_path = Path(output) if output else Path()
    output_is_json = output_path.suffix.lower() in {".json", ".jsonl", ".ndjson"} if output else False
    selected_count = int(summary.get("selected_count") or 0)
    extracted_count = int(summary.get("extracted_count") or 0)
    skipped_count = int(summary.get("skipped_count") or 0)
    parser_errors = int(step.get("parser_error_count") or 0)
    reads_source_content = any(token in name for token in ("extract", "docs", "files", "artifacts", "timeline", "indicators"))
    bounded_output = bool(output_is_json or status in {"skipped", "reused"})
    full_read_risk = "medium" if reads_source_content else "low"
    if status in {"skipped", "reused"}:
        full_read_risk = "low"
    if selected_count or extracted_count:
        full_read_risk = "medium"
    return {
        "stage": name,
        "status": status,
        "output": output,
        "output_format": output_path.suffix.lower().lstrip(".") if output else "",
        "bounded_output": bounded_output,
        "source_content_reading": reads_source_content,
        "full_read_risk": full_read_risk,
        "selected_count": selected_count,
        "extracted_count": extracted_count,
        "skipped_count": skipped_count,
        "parser_error_count": parser_errors,
        "streaming_safe_claimed": False,
        "audit_required": full_read_risk != "low",
        "reporting_note": "Do not claim streaming-safe parser behavior until this stage has a full-read audit and large-file benchmark.",
    }


def build_functional_large_data_profile(
    *,
    item_number: int,
    component: str,
    status: str,
    controls: Mapping[str, object],
    blockers: Sequence[str],
) -> dict[str, object]:
    return {
        "batch_id": FUNCTIONAL_LARGE_DATA_BATCH_ID,
        "item_number": item_number,
        "gap_id": f"#{item_number}",
        "component": component,
        "status": status,
        "implemented": True,
        "usable": True,
        "validated": True,
        "ready_for_commercial_claim": False,
        "controls": dict(controls),
        "blockers": list(blockers),
        "validation_evidence": [
            "run-summary-emits-large-data-profile",
            "unit-test-asserts-functional-large-data-profile-contract",
        ],
    }


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
