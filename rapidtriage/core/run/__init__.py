"""Triage run orchestration (split from the former run.py module)."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import mimetypes
import os
import sys
import time
from collections import Counter
from collections.abc import (
    Mapping,
    Sequence,
)
from concurrent.futures import (
    ThreadPoolExecutor,
    as_completed,
)
from dataclasses import dataclass
from pathlib import Path

from ..archive_image import (
    ArchiveImageExtractionError,
    ArchiveImageExtractionResult,
    extract_archive_image_to_directory,
    is_archive_image_path,
)
from ..artifact_store import write_jsonl_artifacts
from ..artifacts import run_artifact_collection
from ..audit import (
    compute_sha256,
    write_audit_record,
)
from ..columnar_store import (
    ColumnarStoreUnavailable,
    convert_jsonl_to_parquet,
)
from ..disk_image import (
    DiskImageExtractionError,
    DiskImageExtractionResult,
    build_raw_split_integrated_workflow_manifest,
    extract_raw_image_to_directory,
    is_raw_image_path,
)
from ..docs import (
    build_manifest,
    run_docs_search,
    write_result,
)
from ..e01 import (
    E01ExtractionError,
    E01ExtractionResult,
    build_e01_ex01_integrated_workflow_manifest,
    build_e01_operator_runbook,
    build_image_stage_control_contract,
    e01_failure_guidance,
    extract_e01_to_directory,
    is_e01_path,
)
from ..extract import (
    DEFAULT_EXTRACT_MANIFEST_NAME,
    SUPPORTED_DOC_KINDS,
    run_extract,
)
from ..files import (
    DEFAULT_KNOWN_GOOD_MAX_HASH_BYTES,
    run_files_scan,
)
from ..forensic_accuracy import build_accuracy_gate
from ..incremental import (
    EVIDENCE_DELTA_MANIFEST_NAME,
    EVIDENCE_DELTA_SCOPE_DIR_NAME,
    EvidenceDeltaContext,
    build_evidence_delta,
    build_evidence_delta_manifest,
    fingerprint_file_index,
    materialize_delta_scope,
    merge_delta_artifact_payload,
    merge_delta_files_payload,
)
from ..indicators import build_indicator_summary
from ..input_root import (
    InputRoot,
    derive_child_input_root,
    resolve_input_root,
)
from ..reporting import (
    build_run_report_context,
    render_run_markdown_report,
)
from ..rules import (
    RuleSet,
    summarize_payload_annotations,
)
from ..run_workflow import build_run_workflow_contract
from ..silent_failure import build_silent_failure_report
from ..timeline import (
    build_timeline_report,
    run_timeline,
)
from ..virtual_disk import (
    VirtualDiskExtractionError,
    VirtualDiskExtractionResult,
    build_virtual_disk_integrated_workflow_manifest,
    extract_virtual_disk_to_directory,
    is_virtual_disk_path,
)
from ..vsc import build_vsc_image_workflow_handoff
from .checkpoints import *
from .constants import *
from .incremental_indexing import *
from .markdown import *
from .memory import *
from .parser_isolation import *
from .performance import *
from .preview_sandbox import *
from .profiles import *
from .scheduler import *
from .source import *
from .sqlite_fts import *
from .steps import *
from .summary import *

__all__ = [
    "CHECKPOINT_RESUME_GAP_ID",
    "CHECKPOINT_RESUME_REPORT_GRADE_BLOCKERS",
    "CHECKPOINT_RESUME_REPORT_GRADE_VALIDATION_PLAN_VERSION",
    "CHECKPOINT_TRUSTED_DIFF_BLOCKER_70",
    "CROSS_PLATFORM_SYSTEM_ARTIFACT_KINDS",
    "DEFAULT_EXTRACT_MANIFEST_NAME",
    "DEFAULT_INCREMENTAL_HASH_MAX_BYTES",
    "DEFAULT_KNOWN_GOOD_MAX_HASH_BYTES",
    "EVIDENCE_DELTA_MANIFEST_NAME",
    "EVIDENCE_DELTA_SCOPE_DIR_NAME",
    "FUNCTIONAL_LARGE_DATA_BATCH_ID",
    "GENERAL_FORENSIC_ARTIFACT_KINDS",
    "IMPLEMENTED_RUN_MODES",
    "INCREMENTAL_INDEXING_GAP_ID",
    "INCREMENTAL_INDEXING_REPORT_GRADE_BLOCKERS",
    "INCREMENTAL_INDEXING_REPORT_GRADE_VALIDATION_PLAN_VERSION",
    "INCREMENTAL_TRUSTED_DIFF_BLOCKER_68",
    "LARGE_SQLITE_FTS_GAP_ID",
    "LARGE_SQLITE_FTS_REPORT_GRADE_BLOCKERS",
    "LARGE_SQLITE_FTS_REPORT_GRADE_VALIDATION_PLAN_VERSION",
    "LARGE_SQLITE_FTS_TRUSTED_DIFF_BLOCKER_74",
    "MEMORY_CAP_ENV",
    "MEMORY_CAP_GAP_ID",
    "MEMORY_CAP_REPORT_GRADE_BLOCKERS",
    "MEMORY_CAP_REPORT_GRADE_VALIDATION_PLAN_VERSION",
    "MEMORY_CAP_TRUSTED_DIFF_BLOCKER_72",
    "PARALLEL_PARSER_SCHEDULER_GAP_ID",
    "PARSER_CRASH_ISOLATION_GAP_ID",
    "PARSER_CRASH_REPORT_GRADE_BLOCKERS",
    "PARSER_CRASH_REPORT_GRADE_VALIDATION_PLAN_VERSION",
    "PARSER_CRASH_TRUSTED_DIFF_BLOCKER_71",
    "PERFORMANCE_BATCH_ID",
    "PREVIEW_SANDBOX_GAP_ID",
    "PREVIEW_SANDBOX_REPORT_GRADE_BLOCKERS",
    "PREVIEW_SANDBOX_REPORT_GRADE_VALIDATION_PLAN_VERSION",
    "PREVIEW_SANDBOX_TRUSTED_DIFF_BLOCKER_73",
    "RUNTIME_DEFENSIBILITY_BATCH_ID",
    "RUN_DOC_EXTRACT_KINDS",
    "RUN_PROFILES",
    "SCHEDULER_REPORT_GRADE_BLOCKERS",
    "SCHEDULER_REPORT_GRADE_VALIDATION_PLAN_VERSION",
    "SCHEDULER_TRUSTED_DIFF_BLOCKER_75",
    "SUPPORTED_DOC_KINDS",
    "SUPPORTED_RUN_MODES",
    "WINDOWS_FORENSIC_ARTIFACT_KINDS",
    "ArchiveImageExtractionError",
    "ArchiveImageExtractionResult",
    "ColumnarStoreUnavailable",
    "Counter",
    "DiskImageExtractionError",
    "DiskImageExtractionResult",
    "E01ExtractionError",
    "E01ExtractionResult",
    "EvidenceDeltaContext",
    "InputRoot",
    "Mapping",
    "Path",
    "RuleSet",
    "RunModeError",
    "RunProfile",
    "Sequence",
    "ThreadPoolExecutor",
    "VirtualDiskExtractionError",
    "VirtualDiskExtractionResult",
    "annotate_step",
    "append_artifact_summary_rows",
    "append_extract_rows",
    "append_related_document_rows",
    "append_timeline_rows",
    "artifact_scheduler_workers",
    "as_completed",
    "build_accuracy_gate",
    "build_checkpoint_resume_trusted_diff",
    "build_columnar_artifacts_sidecar",
    "build_completed_e01_workflow_status",
    "build_e01_ex01_integrated_workflow_manifest",
    "build_e01_operator_runbook",
    "build_evidence_delta",
    "build_evidence_delta_manifest",
    "build_extract_step",
    "build_functional_large_data_profile",
    "build_functional_large_data_profiles",
    "build_image_stage_control_contract",
    "build_incremental_indexing_manifest",
    "build_incremental_indexing_trusted_diff",
    "build_incremental_indexing_validation_plan",
    "build_incremental_reuse_decision_manifest",
    "build_incremental_reuse_plan",
    "build_indicator_summary",
    "build_key_hit_rows",
    "build_manifest",
    "build_markdown_report",
    "build_memory_cap_trusted_diff",
    "build_parser_crash_isolation_ledger",
    "build_parser_crash_trusted_diff",
    "build_parser_scheduler_manifest",
    "build_preview_sandbox_run_policy_manifest",
    "build_processing_summary",
    "build_raw_split_integrated_workflow_manifest",
    "build_run_input_fingerprint",
    "build_run_report_context",
    "build_run_source_record",
    "build_run_summary",
    "build_run_workflow_contract",
    "build_runtime_defensibility_profile",
    "build_runtime_defensibility_profiles",
    "build_scheduler_event",
    "build_scheduler_trusted_diff",
    "build_silent_failure_report",
    "build_silent_failure_step",
    "build_sqlite_fts_run_optimization_manifest",
    "build_step_rows",
    "build_streaming_parser_boundary_manifest",
    "build_timeline_report",
    "build_virtual_disk_integrated_workflow_manifest",
    "build_vsc_image_workflow_handoff",
    "checkpoint_diff_key",
    "checkpoint_diff_value",
    "checkpoint_integrity_profile",
    "checkpoint_record_hash",
    "checkpoint_resume_assessment",
    "checkpoint_resume_core_accuracy_gates",
    "checkpoint_resume_decision_manifest",
    "checkpoint_resume_report_grade_validation_plan",
    "collect_artifact_stages",
    "collect_preferred_candidates",
    "compute_sha256",
    "convert_jsonl_to_parquet",
    "count_artifact_types",
    "count_matched_keywords",
    "count_skip_reasons",
    "current_memory_rss_bytes",
    "dataclass",
    "derive_child_input_root",
    "docs_index_warning_level",
    "docs_index_warning_messages",
    "docs_warning_level",
    "docs_warning_messages",
    "dt",
    "e01_failure_guidance",
    "enforce_memory_cap",
    "extract_archive_image_to_directory",
    "extract_e01_to_directory",
    "extract_raw_image_to_directory",
    "extract_virtual_disk_to_directory",
    "extract_warning_level",
    "extract_warning_messages",
    "files_warning_level",
    "files_warning_messages",
    "fingerprint_file_index",
    "hash_incremental_file_content",
    "hashlib",
    "highest_warning_level",
    "incremental_file_record_index",
    "incremental_file_records_head_hash",
    "incremental_fingerprint_diff_value",
    "incremental_indexing_assessment",
    "incremental_indexing_core_accuracy_gates",
    "infer_processing_profile_label",
    "is_archive_image_path",
    "is_e01_path",
    "is_raw_image_path",
    "is_virtual_disk_path",
    "isolated_parser_error_payload",
    "isolated_parser_error_record",
    "json",
    "load_or_build_json",
    "load_reusable_json",
    "mark_reused_step",
    "materialize_delta_scope",
    "memory_cap_enforcement_assessment",
    "memory_cap_enforcement_manifest",
    "memory_cap_policy_profile",
    "memory_cap_report_grade_validation_plan",
    "memory_cap_stage_check_row",
    "memory_cap_stage_telemetry_manifest",
    "merge_delta_artifact_payload",
    "merge_delta_files_payload",
    "mimetypes",
    "os",
    "parallel_parser_scheduler_assessment",
    "parser_crash_continuation_manifest",
    "parser_crash_diff_errors",
    "parser_crash_isolation_assessment",
    "parser_crash_isolation_manifest",
    "parser_crash_report_grade_validation_plan",
    "parser_error_inventory_profile",
    "parser_scheduler_report_grade_validation_plan",
    "performance_commercial_uplift_evidence",
    "performance_reportability_decision",
    "prepare_run_input_root",
    "preview_sandbox_report_grade_validation_plan",
    "preview_sandbox_run_output_policy_row",
    "record_run_checkpoint",
    "refresh_incremental_fingerprint_manifest",
    "render_run_markdown_report",
    "resolve_input_root",
    "resolve_memory_cap_bytes",
    "resolve_scan_root",
    "run_artifact_collection",
    "run_docs_search",
    "run_extract",
    "run_files_scan",
    "run_timeline",
    "run_triage_mode",
    "scheduler_event_with_row_hash",
    "sqlite_fts_report_grade_validation_plan",
    "sqlite_fts_tracked_output_row",
    "streaming_parser_stage_row",
    "summarize_document_hits",
    "summarize_file_candidates",
    "summarize_large_file_candidates",
    "summarize_payload_annotations",
    "sys",
    "time",
    "timed_artifact_collection",
    "write_audit_record",
    "write_jsonl_artifacts",
    "write_result",
    "write_run_checkpoints",
]


def run_triage_mode(
    root: InputRoot | Path,
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
    known_good_hash_feeds: Sequence[str | Path] = (),
    hide_known_good: bool = False,
    known_good_max_hash_bytes: int = DEFAULT_KNOWN_GOOD_MAX_HASH_BYTES,
    rule_set: RuleSet | None = None,
    columnar_store: bool = False,
) -> dict[str, object]:
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
    run_scan_limit = max(0, max_file_count)

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

    # R-7c: when --resume is requested but the input fingerprint changed,
    # compute a per-file delta so unchanged evidence paths can keep their
    # prior files/artifact stage rows instead of being recollected.
    evidence_delta: dict[str, object] | None = None
    evidence_delta_context: EvidenceDeltaContext | None = None
    if (
        resume
        and previous_fingerprint
        and str(previous_fingerprint.get("fingerprint") or "")
        != str(current_fingerprint.get("fingerprint") or "")
    ):
        evidence_delta = build_evidence_delta(previous_fingerprint, current_fingerprint)
        if evidence_delta.get("usable"):
            blockers = [str(item) for item in evidence_delta.get("blockers") or []]
            scope_manifest = materialize_delta_scope(
                scan_root,
                output_dir / EVIDENCE_DELTA_SCOPE_DIR_NAME,
                evidence_delta.get("scope_paths") or [],
            )
            files_delta_enabled = (
                not known_good_hash_feeds
                and not hide_known_good
                and known_good_max_hash_bytes == DEFAULT_KNOWN_GOOD_MAX_HASH_BYTES
            )
            if not files_delta_enabled:
                blockers.append(
                    "known-good feeds change candidate classification; files stage delta disabled"
                )
            artifacts_delta_enabled = scan_root == input_root.root_path
            if not artifacts_delta_enabled:
                blockers.append(
                    "scan scope narrows the fingerprinted root; artifact stage delta disabled"
                )
            evidence_delta_context = EvidenceDeltaContext(
                scope_root=Path(str(scope_manifest["scope_root"])),
                source_root=scan_root,
                scope_file_count=int(scope_manifest.get("file_count") or 0),
                added=frozenset(str(path) for path in (evidence_delta.get("added") or [])),
                removed=frozenset(str(path) for path in (evidence_delta.get("removed") or [])),
                changed=frozenset(str(path) for path in (evidence_delta.get("changed") or [])),
                unchanged=frozenset(str(path) for path in (evidence_delta.get("unchanged_paths") or [])),
                files_delta_enabled=files_delta_enabled,
                artifacts_delta_enabled=artifacts_delta_enabled,
                blockers=tuple(blockers),
                scope_manifest=scope_manifest,
            )
            if blockers:
                evidence_delta["blockers"] = blockers

    reused_outputs: set[str] = set()
    delta_applied_outputs: set[str] = set()
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
        producer=lambda: run_docs_search(
            scan_input_root,
            profile.keywords,
            limit=run_scan_limit,
            rule_set=rule_set,
            index_output=docs_index_path,
        ),
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
    files_payload: dict[str, object] | None = None
    if evidence_delta_context is not None and evidence_delta_context.files_delta_enabled:
        previous_files_payload = load_reusable_json(
            files_path,
            expected_command="files",
            required_keys=("summary", "candidates"),
        )
        if previous_files_payload is not None:
            delta_files_payload = (
                run_files_scan(
                    derive_child_input_root(input_root, evidence_delta_context.scope_root),
                    categories=profile.file_scan_categories,
                    path_contains=profile.file_scan_path_contains or None,
                    limit=run_scan_limit,
                    rule_set=rule_set,
                )
                if evidence_delta_context.scope_file_count
                else None
            )
            files_payload = merge_delta_files_payload(
                previous_files_payload,
                delta_files_payload,
                delta=evidence_delta_context,
            )
            delta_applied_outputs.add("files")
    if files_payload is None:
        files_payload, reused = load_or_build_json(
            files_path,
            resume=files_scan_resume,
            expected_command="files",
            required_keys=("summary", "candidates"),
            producer=lambda: run_files_scan(
                scan_input_root,
                categories=profile.file_scan_categories,
                path_contains=profile.file_scan_path_contains or None,
                limit=run_scan_limit,
                rule_set=rule_set,
                known_good_hash_feeds=known_good_hash_feeds,
                hide_known_good=hide_known_good,
                known_good_max_hash_bytes=known_good_max_hash_bytes,
            ),
        )
    else:
        reused = False
    if reused:
        reused_outputs.add("files")
    record_run_checkpoint(
        checkpoint_records,
        "files",
        files_path,
        reused=reused,
        delta_merged="files" in delta_applied_outputs,
    )
    files_payload["scan_scope_root"] = str(scan_input_root.root_path)
    record_memory_cap("files")

    write_result(manifest_payload, manifest_path)
    write_result(docs_payload, docs_path)
    write_result(files_payload, files_path)

    artifact_outputs: dict[str, Path] = {}
    artifact_payloads: dict[str, dict[str, object]] = {}
    artifact_results, artifact_scheduler_manifest = collect_artifact_stages(
        input_root,
        profile.artifacts_kinds,
        artifacts_dir=artifacts_dir,
        resume=effective_resume,
        rule_set=rule_set,
        delta=(
            evidence_delta_context
            if evidence_delta_context is not None and evidence_delta_context.artifacts_delta_enabled
            else None
        ),
    )
    write_result(artifact_scheduler_manifest, scheduler_path)
    for kind in profile.artifacts_kinds:
        artifact_payload, artifact_path, reused, delta_merged = artifact_results[kind]
        if reused:
            reused_outputs.add(f"artifacts-{kind}")
        if delta_merged:
            delta_applied_outputs.add(f"artifacts-{kind}")
        record_run_checkpoint(
            checkpoint_records,
            f"artifacts-{kind}",
            artifact_path,
            reused=reused,
            delta_merged=delta_merged,
        )
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
    evidence_delta_manifest: dict[str, object] | None = None
    if evidence_delta is not None:
        evidence_delta_manifest = build_evidence_delta_manifest(
            delta=evidence_delta,
            context=evidence_delta_context,
            output_dir=output_dir,
            files_stage=files_payload,
            artifact_stages=artifact_payloads,
            resume_requested=resume,
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
    if evidence_delta_manifest is not None:
        outputs["evidence_delta"] = output_dir / EVIDENCE_DELTA_MANIFEST_NAME
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
    columnar_artifacts_sidecar: dict[str, object] | None = None
    if columnar_store:
        columnar_artifacts_sidecar = build_columnar_artifacts_sidecar(outputs=outputs, output_dir=output_dir)
        write_result(columnar_artifacts_sidecar, output_dir / "rapidtriage-columnar-artifacts-sidecar.json")
        if columnar_artifacts_sidecar.get("parquet_path"):
            outputs["columnar_artifacts"] = Path(str(columnar_artifacts_sidecar["parquet_path"]))
        if columnar_artifacts_sidecar.get("jsonl_path"):
            outputs["columnar_artifacts_jsonl"] = Path(str(columnar_artifacts_sidecar["jsonl_path"]))
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
            "delta_applied_outputs": sorted(delta_applied_outputs),
            "evidence_delta": evidence_delta_manifest or {},
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


def build_columnar_artifacts_sidecar(
    *,
    outputs: Mapping[str, Path],
    output_dir: Path,
) -> dict[str, object]:
    """Stage run artifact records as JSONL and convert to row-grouped Parquet.

    Opt-in sidecar for the columnar large-case lane: reads each completed
    ``artifacts_{kind}`` JSON payload written by the run, extracts the
    per-row ``artifact_record`` (ArtifactRecordV1) values, stages them into
    one JSONL file, and converts to Parquet when pyarrow is installed.
    JSONL remains the canonical audit format; the Parquet sidecar is a
    derived index for large-case query (DuckDB) use. Failures mark the
    sidecar ``skipped``/``failed`` without failing the run.
    """
    manifest_core: dict[str, object] = {
        "profile_version": "columnar-artifacts-sidecar-manifest-v1",
        "item_number": 140,
        "commercial_gap_ids": [LARGE_SQLITE_FTS_GAP_ID],
        "commercial_claim_allowed": False,
        "source_output_names": [],
        "status": "skipped",
        "record_count": 0,
        "invalid_record_count": 0,
        "jsonl_path": None,
        "jsonl_manifest_path": None,
        "parquet_path": None,
        "row_group_size": None,
        "install_hint": "pip install .[columnar]",
    }
    artifact_outputs = sorted(
        (name, path)
        for name, path in outputs.items()
        if name.startswith("artifacts_") and path is not None and path.is_file()
    )
    manifest_core["source_output_names"] = [name for name, _ in artifact_outputs]
    if not artifact_outputs:
        manifest_core["status"] = "skipped"
        manifest_core["reason"] = "no-artifact-payload-outputs"
        return manifest_core
    records: list[dict[str, object]] = []
    invalid = 0
    for _, path in artifact_outputs:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            invalid += 1
            continue
        rows = payload.get("artifacts") if isinstance(payload.get("artifacts"), list) else []
        for row in rows:
            if not isinstance(row, dict):
                invalid += 1
                continue
            record = row.get("artifact_record")
            if isinstance(record, dict) and record.get("schema") == "ArtifactRecordV1":
                records.append(record)
            elif record is not None:
                invalid += 1
    manifest_core["record_count"] = len(records)
    manifest_core["invalid_record_count"] = invalid
    jsonl_path = output_dir / "rapidtriage-artifacts-records.jsonl"
    jsonl_manifest_path = output_dir / "rapidtriage-artifacts-records.jsonl.manifest.json"
    parquet_path = output_dir / "rapidtriage-artifacts-records.parquet"
    try:
        write_jsonl_artifacts(records, output_path=jsonl_path, manifest_path=jsonl_manifest_path)
    except Exception as exc:
        manifest_core["status"] = "failed"
        manifest_core["reason"] = f"jsonl-stage-write-failed: {exc}"
        return manifest_core
    manifest_core["jsonl_path"] = str(jsonl_path)
    manifest_core["jsonl_manifest_path"] = str(jsonl_manifest_path)
    try:
        parquet_result = convert_jsonl_to_parquet(input_jsonl=jsonl_path, output_parquet=parquet_path)
        manifest_core["status"] = "written"
        manifest_core["parquet_path"] = str(parquet_path)
        manifest_core["row_group_size"] = parquet_result.get("row_group_size")
        manifest_core["parquet_size_bytes"] = parquet_result.get("size_bytes")
        manifest_core["record_count"] = parquet_result.get("record_count", len(records))
        manifest_core["rejected_count"] = parquet_result.get("rejected_count", 0)
    except ColumnarStoreUnavailable as exc:
        manifest_core["status"] = "skipped"
        manifest_core["reason"] = f"columnar-dependency-unavailable: {exc}"
    except Exception as exc:
        manifest_core["status"] = "failed"
        manifest_core["reason"] = f"parquet-convert-failed: {exc}"
    return manifest_core


def collect_artifact_stages(
    input_root: InputRoot,
    kinds: Sequence[str],
    *,
    artifacts_dir: Path,
    resume: bool,
    rule_set: RuleSet | None,
    delta: EvidenceDeltaContext | None = None,
) -> tuple[dict[str, tuple[dict[str, object], Path, bool, bool]], dict[str, object]]:
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    results: dict[str, tuple[dict[str, object], Path, bool, bool]] = {}
    pending: list[tuple[str, Path]] = []
    delta_pending: list[tuple[str, Path, dict[str, object]]] = []
    events: list[dict[str, object]] = []
    output_order = list(kinds)
    max_workers = artifact_scheduler_workers(kinds)
    for kind in kinds:
        artifact_path = artifacts_dir / f"rapidtriage-artifacts-{kind}.json"
        reusable = load_reusable_json(
            artifact_path,
            expected_command="artifacts",
            required_keys=("summary", "artifacts"),
        ) if (resume or delta is not None) else None
        if reusable is not None and resume:
            results[kind] = (reusable, artifact_path, True, False)
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
        elif reusable is not None and delta is not None:
            delta_pending.append((kind, artifact_path, reusable))
        else:
            pending.append((kind, artifact_path))

    def record_delta_merge(
        kind: str,
        artifact_path: Path,
        merged: dict[str, object],
        *,
        started_at: str | None,
        completed_at: str | None,
        duration_ms: int,
    ) -> None:
        results[kind] = (merged, artifact_path, False, True)
        events.append(
            build_scheduler_event(
                kind=kind,
                output_path=artifact_path,
                status="delta-merged",
                reused=False,
                delta_merged=True,
                queued_order=output_order.index(kind),
                output_order=output_order.index(kind),
                payload=merged,
                started_at=started_at,
                completed_at=completed_at,
                duration_ms=duration_ms,
            )
        )

    if pending or delta_pending:
        scope_input_root = (
            derive_child_input_root(input_root, delta.scope_root) if delta else input_root
        )
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="rapidtriage-artifact") as executor:
            futures = {}
            for kind, artifact_path in pending:
                future = executor.submit(
                    timed_artifact_collection, input_root, kind=kind, rule_set=rule_set
                )
                futures[future] = ("full", kind, artifact_path, None)
            if delta is not None:
                for kind, artifact_path, previous in delta_pending:
                    if delta.scope_file_count:
                        future = executor.submit(
                            timed_artifact_collection,
                            scope_input_root,
                            kind=kind,
                            rule_set=rule_set,
                        )
                        futures[future] = ("delta", kind, artifact_path, previous)
                    else:
                        # Removal-only delta: no scope files to recollect.
                        record_delta_merge(
                            kind,
                            artifact_path,
                            merge_delta_artifact_payload(previous, None, delta=delta),
                            started_at=None,
                            completed_at=None,
                            duration_ms=0,
                        )
            for future in as_completed(futures):
                mode, kind, artifact_path, previous = futures[future]
                try:
                    payload, started_at, completed_at, duration_ms = future.result()
                    status = "completed"
                except Exception as exc:
                    started_at = dt.datetime.now(dt.timezone.utc).isoformat()
                    completed_at = started_at
                    duration_ms = 0
                    payload = isolated_parser_error_payload(
                        kind,
                        input_root=scope_input_root if mode == "delta" else input_root,
                        exc=exc,
                    )
                    status = "error"
                if mode == "delta" and status == "completed" and delta is not None:
                    record_delta_merge(
                        kind,
                        artifact_path,
                        merge_delta_artifact_payload(
                            previous if isinstance(previous, dict) else {},
                            payload,
                            delta=delta,
                        ),
                        started_at=started_at,
                        completed_at=completed_at,
                        duration_ms=duration_ms,
                    )
                    continue
                if mode == "delta" and status == "error" and delta is not None:
                    # Delta-scope collection failed; fall back to a full
                    # collection so coverage is preserved (crash isolation).
                    try:
                        payload, started_at, completed_at, duration_ms = timed_artifact_collection(
                            input_root, kind=kind, rule_set=rule_set
                        )
                        status = "completed"
                    except Exception as exc:
                        started_at = dt.datetime.now(dt.timezone.utc).isoformat()
                        completed_at = started_at
                        duration_ms = 0
                        payload = isolated_parser_error_payload(kind, input_root=input_root, exc=exc)
                        status = "error"
                results[kind] = (payload, artifact_path, False, False)
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
) -> tuple[dict[str, object], str, str, int]:
    start = time.perf_counter()
    started_at = dt.datetime.now(dt.timezone.utc).isoformat()
    payload = run_artifact_collection(input_root, kind=kind, rule_set=rule_set)
    completed_at = dt.datetime.now(dt.timezone.utc).isoformat()
    duration_ms = max(0, int((time.perf_counter() - start) * 1000))
    return payload, started_at, completed_at, duration_ms


def prepare_run_input_root(
    root: InputRoot | Path,
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
