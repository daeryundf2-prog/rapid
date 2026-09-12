"""Parallel parser scheduler assessment, events, and manifests."""

from __future__ import annotations

import hashlib
import json
from collections.abc import (
    Mapping,
    Sequence,
)
from pathlib import Path

from ..forensic_accuracy import build_accuracy_gate
from .constants import (
    PARALLEL_PARSER_SCHEDULER_GAP_ID,
    SCHEDULER_REPORT_GRADE_BLOCKERS,
    SCHEDULER_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    SCHEDULER_TRUSTED_DIFF_BLOCKER_75,
)

__all__ = [
    "artifact_scheduler_workers",
    "build_parser_scheduler_manifest",
    "build_scheduler_event",
    "build_scheduler_trusted_diff",
    "parallel_parser_scheduler_assessment",
    "parser_scheduler_report_grade_validation_plan",
    "scheduler_event_with_row_hash",
]


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
    validation_plan = parser_scheduler_report_grade_validation_plan(
        kinds=kinds,
        scheduler_manifest=scheduler_manifest,
        trusted_diff=trusted_diff,
    )
    if scheduler_manifest:
        satisfied.extend(
            [
                "parser scheduler report-grade validation plan emitted",
                "parser scheduler report-grade ready slots emitted",
            ]
        )
        evidence_refs.extend(
            [
                f"parser_scheduler_report_grade_validation_plan_hash:{validation_plan['validation_plan_hash']}",
                f"parser_scheduler_report_grade_ready_slots:{validation_plan['ready_slot_count']}",
                f"parser_scheduler_report_grade_blocking_slots:{validation_plan['blocking_slot_count']}",
            ]
        )
    return {
        "component": "parallel-parser-scheduler",
        "status": "threaded-parser-stage-scheduler-and-validation-plan-emitted",
        "commercial_gap_ids": [PARALLEL_PARSER_SCHEDULER_GAP_ID],
        "scheduled_count": scheduled,
        "max_workers": artifact_scheduler_workers(kinds),
        "scheduler_manifest": scheduler_manifest or {},
        "parser_scheduler_report_grade_validation_plan": validation_plan,
        "parser_scheduler_report_grade_validation_plan_hash": validation_plan["validation_plan_hash"],
        "report_grade_ready_slot_count": validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
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
        "blockers": list(validation_plan["blockers"]),
    }


def parser_scheduler_report_grade_validation_plan(
    *,
    kinds: Sequence[str],
    scheduler_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    clean_kinds = tuple(str(kind) for kind in kinds)
    manifest = scheduler_manifest if isinstance(scheduler_manifest, Mapping) else {}
    resource_policy = manifest.get("resource_policy") if isinstance(manifest.get("resource_policy"), Mapping) else {}
    event_rows = manifest.get("events") if isinstance(manifest.get("events"), list) else []
    manifest_hash = str(manifest.get("manifest_hash") or "")
    resource_policy_hash = str(manifest.get("resource_policy_hash") or "")
    events_head_hash = str(manifest.get("events_head_hash") or "")
    event_row_head_hash = str(manifest.get("scheduler_event_row_head_hash") or "")
    deterministic_order = [str(value) for value in manifest.get("deterministic_output_order", [])] if isinstance(
        manifest.get("deterministic_output_order"), list
    ) else list(clean_kinds)
    event_status_rows = [
        {
            "kind": str(row.get("kind") or ""),
            "status": str(row.get("status") or ""),
            "queued_order": int(row.get("queued_order") or 0),
            "deterministic_output_order": int(row.get("deterministic_output_order") or 0),
            "duration_ms": int(row.get("duration_ms") or 0),
            "row_hash": str(row.get("row_hash") or ""),
            "reused": bool(row.get("reused")),
            "parser_error_count": int(row.get("parser_error_count") or 0),
        }
        for row in event_rows
        if isinstance(row, Mapping)
    ]
    event_status_head_hash = hashlib.sha256(
        json.dumps(event_status_rows, sort_keys=True).encode("utf-8")
    ).hexdigest()
    local_threadpool_contract = {
        "max_workers": int(manifest.get("max_workers") or artifact_scheduler_workers(clean_kinds)),
        "cpu_worker_limit": int(resource_policy.get("cpu_worker_limit") or 0),
        "backpressure_window": int(resource_policy.get("backpressure_window") or 0),
        "distributed_priority_queue": bool(resource_policy.get("distributed_priority_queue")),
        "live_worker_stream": bool(resource_policy.get("live_worker_stream")),
    }
    local_threadpool_contract_hash = hashlib.sha256(
        json.dumps(local_threadpool_contract, sort_keys=True).encode("utf-8")
    ).hexdigest()
    ready_slots: list[dict[str, object]] = [
        {
            "slot_id": "scheduler-run-manifest",
            "status": "ready",
            "evidence_ref": "scheduler_manifest_hash",
            "evidence_hash": manifest_hash,
            "description": "The run archives a parser scheduler manifest for artifact-stage execution.",
        },
        {
            "slot_id": "bounded-worker-policy",
            "status": "ready",
            "evidence_ref": "resource_policy_hash",
            "evidence_hash": resource_policy_hash,
            "description": "Worker count, CPU quota source, and local backpressure window are hashed.",
        },
        {
            "slot_id": "deterministic-output-order",
            "status": "ready",
            "evidence_ref": "deterministic_output_order_hash",
            "evidence_hash": hashlib.sha256("\n".join(deterministic_order).encode("utf-8")).hexdigest(),
            "description": "Parser outputs are emitted in profile order even when futures complete out of order.",
        },
        {
            "slot_id": "scheduler-event-row-hashes",
            "status": "ready",
            "evidence_ref": "scheduler_event_row_head_hash",
            "evidence_hash": event_row_head_hash,
            "description": "Each queued/completed/reused parser event carries a stable row hash.",
        },
        {
            "slot_id": "per-worker-duration-telemetry",
            "status": "ready",
            "evidence_ref": "event_status_head_hash",
            "evidence_hash": event_status_head_hash,
            "description": "Scheduler rows preserve per-parser duration, status, reuse, and error counts.",
        },
        {
            "slot_id": "local-threadpool-limitation-disclosure",
            "status": "ready",
            "evidence_ref": "local_threadpool_contract_hash",
            "evidence_hash": local_threadpool_contract_hash,
            "description": "The manifest discloses local threadpool execution rather than distributed scheduling.",
        },
    ]
    blocking_slots: list[dict[str, object]] = [
        {
            "slot_id": "trusted-scheduler-manifest",
            "status": "blocked",
            "blocker": SCHEDULER_TRUSTED_DIFF_BLOCKER_75,
            "required_evidence": "independent trusted parser scheduler manifest diff for identical run outputs",
        },
        {
            "slot_id": "distributed-priority-queue",
            "status": "blocked",
            "blocker": "distributed-priority-scheduler-required",
            "required_evidence": "priority queue or distributed worker evidence with deterministic output reconciliation",
        },
        {
            "slot_id": "live-worker-telemetry-stream",
            "status": "blocked",
            "blocker": "live-worker-telemetry-stream-required",
            "required_evidence": "live per-worker progress/CPU/RSS/error telemetry stream captured during long runs",
        },
        {
            "slot_id": "tb-scale-fairness-backpressure",
            "status": "blocked",
            "blocker": "tb-scale-fairness-backpressure-validation-required",
            "required_evidence": "1TB+ evidence run proving fair scheduling, bounded queues, and stable retry behavior",
        },
        {
            "slot_id": "cross-platform-worker-quota",
            "status": "blocked",
            "blocker": "cross-platform-worker-quota-validation-required",
            "required_evidence": "Windows, macOS, and Linux run logs with matching worker quota and output ordering semantics",
        },
        {
            "slot_id": "priority-starvation-regression",
            "status": "blocked",
            "blocker": "priority-starvation-regression-required",
            "required_evidence": "regression corpus proving long parsers do not starve short/high-priority artifact parsers",
        },
    ]
    trusted_status = str((trusted_diff or {}).get("status") or "missing")
    plan_core = {
        "profile_version": SCHEDULER_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 75,
        "gap_id": PARALLEL_PARSER_SCHEDULER_GAP_ID,
        "commercial_gap_ids": [PARALLEL_PARSER_SCHEDULER_GAP_ID],
        "scheduled_count": int(manifest.get("scheduled_count") or len(clean_kinds)),
        "max_workers": int(manifest.get("max_workers") or artifact_scheduler_workers(clean_kinds)),
        "pending_count": int(manifest.get("pending_count") or 0),
        "completed_count": int(manifest.get("completed_count") or 0),
        "reused_count": int(manifest.get("reused_count") or 0),
        "error_count": int(manifest.get("error_count") or 0),
        "event_row_count": int(manifest.get("event_row_count") or len(event_status_rows)),
        "scheduler_manifest_hash": manifest_hash,
        "resource_policy_hash": resource_policy_hash,
        "events_head_hash": events_head_hash,
        "scheduler_event_row_head_hash": event_row_head_hash,
        "event_status_head_hash": event_status_head_hash,
        "local_threadpool_contract_hash": local_threadpool_contract_hash,
        "deterministic_order_verified": bool(manifest.get("deterministic_order_verified")),
        "local_threadpool_scheduler": True,
        "distributed_priority_scheduler": False,
        "live_worker_telemetry_stream": False,
        "trusted_scheduler_diff_status": trusted_status,
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "blockers": list(SCHEDULER_REPORT_GRADE_BLOCKERS),
        "commercial_claim_allowed": False,
        "ready_for_court_report": False,
        "report_use_warning": "Use as local bounded scheduler evidence only; do not claim distributed or TB-scale scheduler fairness until blocker slots are satisfied.",
    }
    validation_plan_hash = hashlib.sha256(json.dumps(plan_core, sort_keys=True).encode("utf-8")).hexdigest()
    return {
        **plan_core,
        "validation_plan_hash": validation_plan_hash,
        "validation_plan_sha256": validation_plan_hash,
    }


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
    delta_merged: bool = False,
) -> dict[str, object]:
    summary = payload.get("summary") if isinstance(payload.get("summary"), Mapping) else {}
    parser_errors = payload.get("parser_errors") if isinstance(payload.get("parser_errors"), list) else []
    return {
        "kind": kind,
        "status": status,
        "reused": reused,
        "delta_merged": delta_merged,
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
        "delta_merged_count": sum(1 for event in sorted_events if event.get("delta_merged")),
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
