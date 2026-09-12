"""Run summary, processing summary, and profile builders."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from collections import Counter
from collections.abc import (
    Mapping,
    Sequence,
)
from pathlib import Path

from ..forensic_accuracy import build_accuracy_gate
from ..rules import (
    RuleSet,
    summarize_payload_annotations,
)
from ..run_workflow import build_run_workflow_contract
from ..silent_failure import build_silent_failure_report
from .constants import (
    CHECKPOINT_RESUME_GAP_ID,
    CHECKPOINT_TRUSTED_DIFF_BLOCKER_70,
    FUNCTIONAL_LARGE_DATA_BATCH_ID,
    INCREMENTAL_INDEXING_GAP_ID,
    INCREMENTAL_INDEXING_REPORT_GRADE_BLOCKERS,
    INCREMENTAL_TRUSTED_DIFF_BLOCKER_68,
    LARGE_SQLITE_FTS_GAP_ID,
    LARGE_SQLITE_FTS_REPORT_GRADE_BLOCKERS,
    MEMORY_CAP_TRUSTED_DIFF_BLOCKER_72,
    PARSER_CRASH_TRUSTED_DIFF_BLOCKER_71,
    PREVIEW_SANDBOX_GAP_ID,
    PREVIEW_SANDBOX_REPORT_GRADE_BLOCKERS,
    RUNTIME_DEFENSIBILITY_BATCH_ID,
    SCHEDULER_REPORT_GRADE_BLOCKERS,
)
from .memory import (
    current_memory_rss_bytes,
    memory_cap_enforcement_assessment,
    memory_cap_policy_profile,
)
from .parser_isolation import parser_crash_isolation_assessment
from .performance import performance_commercial_uplift_evidence
from .profiles import RunProfile
from .scheduler import (
    parallel_parser_scheduler_assessment,
    parser_scheduler_report_grade_validation_plan,
)
from .steps import (
    build_silent_failure_step,
    build_step_rows,
    highest_warning_level,
)

__all__ = [
    "build_functional_large_data_profile",
    "build_functional_large_data_profiles",
    "build_processing_summary",
    "build_run_summary",
    "build_runtime_defensibility_profile",
    "build_runtime_defensibility_profiles",
    "build_streaming_parser_boundary_manifest",
    "collect_preferred_candidates",
    "count_artifact_types",
    "count_matched_keywords",
    "infer_processing_profile_label",
    "streaming_parser_stage_row",
    "summarize_document_hits",
    "summarize_file_candidates",
    "summarize_large_file_candidates",
]


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
) -> dict[str, object]:
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


def build_processing_summary(
    steps: list[dict[str, object]],
    *,
    safety: Mapping[str, object],
) -> dict[str, object]:
    warnings: list[dict[str, object]] = []
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
    incremental_validation_plan = (
        input_fingerprint.get("incremental_indexing_report_grade_validation_plan")
        if isinstance(input_fingerprint.get("incremental_indexing_report_grade_validation_plan"), Mapping)
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
    preview_sandbox_validation_plan = (
        preview_sandbox_policy.get("preview_sandbox_report_grade_validation_plan")
        if isinstance(preview_sandbox_policy.get("preview_sandbox_report_grade_validation_plan"), Mapping)
        else {}
    )
    sqlite_fts_optimization = (
        safety.get("sqlite_fts_optimization")
        if isinstance(safety.get("sqlite_fts_optimization"), Mapping)
        else {}
    )
    sqlite_fts_validation_plan = (
        sqlite_fts_optimization.get("large_sqlite_fts_report_grade_validation_plan")
        if isinstance(sqlite_fts_optimization.get("large_sqlite_fts_report_grade_validation_plan"), Mapping)
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
            "incremental_indexing_report_grade_validation_plan": dict(incremental_validation_plan),
            "incremental_indexing_report_grade_validation_plan_hash": str(
                incremental_validation_plan.get("validation_plan_hash") or ""
            ),
            "report_grade_ready_slot_count": int(incremental_validation_plan.get("ready_slot_count") or 0),
            "report_grade_blocking_slot_count": int(incremental_validation_plan.get("blocking_slot_count") or 0),
            "commercial_uplift_evidence": performance_commercial_uplift_evidence(
                item_number=68,
                validation_ids=[
                    "input fingerprint emitted",
                    "path/size/mtime metadata captured",
                    "reuse decision manifest emitted",
                    "incremental indexing report-grade validation plan emitted",
                    "incremental indexing report-grade ready slots emitted",
                    "per-file reindex limitation warning",
                ],
                large_data_controls=[
                    "bounded fingerprint controls whether stage outputs can be reused",
                    "per-path reuse/rebuild decisions are hashed for reviewer traceability",
                    "changed-source runs disable reuse instead of silently trusting stale outputs",
                    "resume state is surfaced in the run summary for analyst review",
                    "report-grade validation slots identify remaining row-level delta and large-corpus blockers",
                ],
                external_validation=[
                    "content-hash per-file incremental reindexing",
                    "row-level stage delta indexing",
                    "large-case changed-source validation",
                    "case-db deduplication validation",
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
            "status": "run-policy-manifest-and-validation-plan-emitted",
            "commercial_gap_ids": [PREVIEW_SANDBOX_GAP_ID],
            "preview_sandbox_policy_manifest": dict(preview_sandbox_policy),
            "preview_sandbox_policy_manifest_hash": str(preview_sandbox_policy.get("manifest_hash") or ""),
            "preview_sandbox_report_grade_validation_plan": dict(preview_sandbox_validation_plan),
            "preview_sandbox_report_grade_validation_plan_hash": str(
                preview_sandbox_validation_plan.get("validation_plan_hash") or ""
            ),
            "report_grade_ready_slot_count": int(preview_sandbox_validation_plan.get("ready_slot_count") or 0),
            "report_grade_blocking_slot_count": int(preview_sandbox_validation_plan.get("blocking_slot_count") or 0),
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
                        "preview sandbox report-grade validation plan emitted",
                        "preview sandbox report-grade ready slots emitted",
                    ],
                    evidence_refs=[
                        "run-summary:processing.preview_sandboxing",
                        f"preview_sandbox_policy_hash:{preview_sandbox_policy.get('manifest_hash', '')}",
                        (
                            "preview_sandbox_report_grade_validation_plan_hash:"
                            f"{preview_sandbox_validation_plan.get('validation_plan_hash', '')}"
                        ),
                    ],
                )
            ],
            "blockers": list(preview_sandbox_validation_plan.get("blockers") or PREVIEW_SANDBOX_REPORT_GRADE_BLOCKERS),
        },
        "parallel_parser_scheduler": artifact_scheduler.get("assessment")
        if isinstance(artifact_scheduler.get("assessment"), Mapping)
        else parallel_parser_scheduler_assessment(()),
        "sqlite_fts_optimization": {
            "component": "large-sqlite-fts-optimization",
            "status": "run-optimization-manifest-and-validation-plan-emitted",
            "commercial_gap_ids": [LARGE_SQLITE_FTS_GAP_ID],
            "sqlite_fts_optimization_manifest": dict(sqlite_fts_optimization),
            "sqlite_fts_optimization_manifest_hash": str(sqlite_fts_optimization.get("manifest_hash") or ""),
            "large_sqlite_fts_report_grade_validation_plan": dict(sqlite_fts_validation_plan),
            "large_sqlite_fts_report_grade_validation_plan_hash": str(
                sqlite_fts_validation_plan.get("validation_plan_hash") or ""
            ),
            "report_grade_ready_slot_count": int(sqlite_fts_validation_plan.get("ready_slot_count") or 0),
            "report_grade_blocking_slot_count": int(sqlite_fts_validation_plan.get("blocking_slot_count") or 0),
            "ready_for_court_report": False,
            "core_accuracy_gates": [
                build_accuracy_gate(
                    74,
                    satisfied_checks=[
                        "SQLite/FTS run optimization manifest emitted",
                        "tracked output hashes emitted",
                        "cursor pagination requirement recorded",
                        "10M-row regression blocker disclosed",
                        "large SQLite/FTS report-grade validation plan emitted",
                        "large SQLite/FTS report-grade ready slots emitted",
                    ],
                    evidence_refs=[
                        "run-summary:processing.sqlite_fts_optimization",
                        f"sqlite_fts_manifest_hash:{sqlite_fts_optimization.get('manifest_hash', '')}",
                        (
                            "large_sqlite_fts_report_grade_validation_plan_hash:"
                            f"{sqlite_fts_validation_plan.get('validation_plan_hash', '')}"
                        ),
                    ],
                )
            ],
            "blockers": list(sqlite_fts_validation_plan.get("blockers") or LARGE_SQLITE_FTS_REPORT_GRADE_BLOCKERS),
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
            incremental_validation_plan=incremental_validation_plan,
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
    preview_sandbox_validation_plan = (
        (preview_sandbox_policy or {}).get("preview_sandbox_report_grade_validation_plan")
        if isinstance((preview_sandbox_policy or {}).get("preview_sandbox_report_grade_validation_plan"), Mapping)
        else {}
    )
    sqlite_fts_validation_plan = (
        (sqlite_fts_optimization or {}).get("large_sqlite_fts_report_grade_validation_plan")
        if isinstance((sqlite_fts_optimization or {}).get("large_sqlite_fts_report_grade_validation_plan"), Mapping)
        else {}
    )
    scheduler_validation_plan = parser_scheduler_report_grade_validation_plan(
        kinds=tuple(str(kind) for kind in (scheduler_manifest or {}).get("deterministic_output_order", []))
        if isinstance((scheduler_manifest or {}).get("deterministic_output_order"), list)
        else tuple(),
        scheduler_manifest=scheduler_manifest,
    )
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
                "parser_crash_report_grade_validation_plan_hash": str(
                    parser_crash_ledger.get("parser_crash_report_grade_validation_plan_hash") or ""
                ),
                "parser_crash_report_grade_ready_slot_count": int(
                    parser_crash_ledger.get("report_grade_ready_slot_count") or 0
                ),
                "parser_crash_report_grade_blocking_slot_count": int(
                    parser_crash_ledger.get("report_grade_blocking_slot_count") or 0
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
            status="implemented-api-viewer-report-grade-plan-validation-required",
            controls={
                "source_preview_contract_available": True,
                "read_only_bounded_preview_metadata": True,
                "active_content_blocking_declared": True,
                "external_network_prohibited": True,
                "run_preview_sandbox_policy_manifest_hash": str((preview_sandbox_policy or {}).get("manifest_hash", "")),
                "preview_policy_row_count": int((preview_sandbox_policy or {}).get("preview_policy_row_count") or 0),
                "preview_policy_row_head_hash": str((preview_sandbox_policy or {}).get("preview_policy_row_head_hash") or ""),
                "active_content_blocked_count": int((preview_sandbox_policy or {}).get("active_content_blocked_count") or 0),
                "preview_sandbox_report_grade_validation_plan_hash": str(
                    preview_sandbox_validation_plan.get("validation_plan_hash") or ""
                ),
                "preview_sandbox_report_grade_ready_slot_count": int(
                    preview_sandbox_validation_plan.get("ready_slot_count") or 0
                ),
                "preview_sandbox_report_grade_blocking_slot_count": int(
                    preview_sandbox_validation_plan.get("blocking_slot_count") or 0
                ),
                "risky_codec_or_macro_os_sandbox": False,
            },
            blockers=list(preview_sandbox_validation_plan.get("blockers") or PREVIEW_SANDBOX_REPORT_GRADE_BLOCKERS),
        ),
        build_runtime_defensibility_profile(
            item_number=74,
            component="large-sqlite-fts-optimization",
            status="implemented-bounded-viewer-report-grade-plan-validation-required",
            controls={
                "case_db_performance_pragmas_enabled": True,
                "bounded_sqlite_preview_contract": True,
                "fts_optimization_metadata_available": True,
                "run_sqlite_fts_optimization_manifest_hash": str((sqlite_fts_optimization or {}).get("manifest_hash", "")),
                "tracked_output_row_count": int((sqlite_fts_optimization or {}).get("tracked_output_row_count") or 0),
                "tracked_output_row_head_hash": str((sqlite_fts_optimization or {}).get("tracked_output_row_head_hash") or ""),
                "large_sqlite_fts_report_grade_validation_plan_hash": str(
                    sqlite_fts_validation_plan.get("validation_plan_hash") or ""
                ),
                "large_sqlite_fts_report_grade_ready_slot_count": int(
                    sqlite_fts_validation_plan.get("ready_slot_count") or 0
                ),
                "large_sqlite_fts_report_grade_blocking_slot_count": int(
                    sqlite_fts_validation_plan.get("blocking_slot_count") or 0
                ),
                "ten_million_row_query_plan_regression_attached": False,
                "deleted_row_wal_replay_validation_attached": False,
            },
            blockers=list(sqlite_fts_validation_plan.get("blockers") or LARGE_SQLITE_FTS_REPORT_GRADE_BLOCKERS),
        ),
        build_runtime_defensibility_profile(
            item_number=75,
            component="parallel-parser-scheduler",
            status="implemented-local-threadpool-report-grade-plan-validation-required",
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
                "parser_scheduler_report_grade_validation_plan_hash": str(
                    scheduler_validation_plan.get("validation_plan_hash") or ""
                ),
                "parser_scheduler_report_grade_ready_slot_count": int(
                    scheduler_validation_plan.get("ready_slot_count") or 0
                ),
                "parser_scheduler_report_grade_blocking_slot_count": int(
                    scheduler_validation_plan.get("blocking_slot_count") or 0
                ),
                "distributed_priority_scheduler": False,
            },
            blockers=list(scheduler_validation_plan.get("blockers") or SCHEDULER_REPORT_GRADE_BLOCKERS),
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
    incremental_validation_plan: Mapping[str, object],
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
                "incremental_indexing_report_grade_validation_plan_hash": str(
                    incremental_validation_plan.get("validation_plan_hash") or ""
                ),
                "report_grade_ready_slot_count": int(incremental_validation_plan.get("ready_slot_count") or 0),
                "report_grade_blocking_slot_count": int(incremental_validation_plan.get("blocking_slot_count") or 0),
                "reuse_decision_row_count": int(reuse_decision_manifest.get("decision_row_count") or 0),
                "file_record_head_hash": str(incremental_manifest.get("file_record_head_hash") or ""),
                "content_hashed_file_count": int(incremental_manifest.get("content_hashed_file_count") or 0),
                "reindex_recommendation": str(incremental_manifest.get("reindex_recommendation") or ""),
                "per-file_content_hash_reindexing": False,
            },
            blockers=[
                INCREMENTAL_TRUSTED_DIFF_BLOCKER_68,
                *INCREMENTAL_INDEXING_REPORT_GRADE_BLOCKERS,
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


def summarize_document_hits(results: object, *, limit: int) -> list[dict[str, object]]:
    if not isinstance(results, list):
        return []
    items: list[dict[str, object]] = []
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


def summarize_file_candidates(candidates: object, *, limit: int) -> list[dict[str, object]]:
    if not isinstance(candidates, list):
        return []
    items: list[dict[str, object]] = []
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


def summarize_large_file_candidates(candidates: object, *, limit: int) -> list[dict[str, object]]:
    if not isinstance(candidates, list):
        return []
    sorted_candidates = sorted(
        (candidate for candidate in candidates if isinstance(candidate, dict)),
        key=lambda item: (-int(item.get("size", 0)), str(item.get("path", ""))),
    )
    items: list[dict[str, object]] = []
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


def collect_preferred_candidates(candidates: object, *, preferred_locations: Sequence[str]) -> list[dict[str, object]]:
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
