"""Run memory-cap resolution, enforcement, and assessment."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from collections.abc import (
    Mapping,
    Sequence,
)

from ..forensic_accuracy import build_accuracy_gate
from .constants import (
    MEMORY_CAP_ENV,
    MEMORY_CAP_GAP_ID,
    MEMORY_CAP_REPORT_GRADE_BLOCKERS,
    MEMORY_CAP_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    MEMORY_CAP_TRUSTED_DIFF_BLOCKER_72,
)
from .profiles import RunModeError

__all__ = [
    "build_memory_cap_trusted_diff",
    "current_memory_rss_bytes",
    "enforce_memory_cap",
    "memory_cap_enforcement_assessment",
    "memory_cap_enforcement_manifest",
    "memory_cap_policy_profile",
    "memory_cap_report_grade_validation_plan",
    "memory_cap_stage_check_row",
    "memory_cap_stage_telemetry_manifest",
    "resolve_memory_cap_bytes",
]


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
    validation_plan = memory_cap_report_grade_validation_plan(
        memory_cap_bytes=memory_cap_bytes,
        current_rss_bytes=current_rss,
        policy=policy,
        stage_telemetry=stage_telemetry,
        warning_count=warning_count,
    )
    manifest = memory_cap_enforcement_manifest(
        memory_cap_bytes=memory_cap_bytes,
        current_rss_bytes=current_rss,
        warning_count=warning_count,
        policy=policy,
        stage_telemetry=stage_telemetry,
        validation_plan=validation_plan,
    )
    satisfied = [
        "RSS reading captured",
        "stage-boundary enforcement",
        "stage telemetry row hashes emitted",
        "fail-fast corruption prevention warning",
        "hard OS limit limitation warning",
        "memory cap policy profile emitted",
        "memory cap enforcement manifest hash emitted",
        "memory cap report-grade validation plan emitted",
        "memory cap report-grade ready slots emitted",
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
        f"memory_cap_report_grade_validation_plan_hash:{validation_plan['validation_plan_hash']}",
        f"memory_cap_report_grade_ready_slots:{validation_plan['ready_slot_count']}",
        f"memory_cap_report_grade_blocking_slots:{validation_plan['blocking_slot_count']}",
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
        "memory_cap_report_grade_validation_plan": validation_plan,
        "memory_cap_report_grade_validation_plan_hash": validation_plan["validation_plan_hash"],
        "report_grade_ready_slot_count": validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
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
            *MEMORY_CAP_REPORT_GRADE_BLOCKERS,
        ],
    }


def memory_cap_enforcement_manifest(
    *,
    memory_cap_bytes: int,
    current_rss_bytes: int,
    warning_count: int,
    policy: Mapping[str, object],
    stage_telemetry: Mapping[str, object] | None = None,
    validation_plan: Mapping[str, object] | None = None,
) -> dict[str, object]:
    cap_configured = memory_cap_bytes > 0
    over_cap = bool(policy.get("over_cap"))
    stage_telemetry = stage_telemetry if isinstance(stage_telemetry, Mapping) else {}
    validation_plan = validation_plan if isinstance(validation_plan, Mapping) else {}
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
        "memory_cap_report_grade_validation_plan": dict(validation_plan),
        "memory_cap_report_grade_validation_plan_hash": str(validation_plan.get("validation_plan_hash") or ""),
        "report_grade_ready_slot_count": int(validation_plan.get("ready_slot_count") or 0),
        "report_grade_blocking_slot_count": int(validation_plan.get("blocking_slot_count") or 0),
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


def memory_cap_report_grade_validation_plan(
    *,
    memory_cap_bytes: int,
    current_rss_bytes: int,
    policy: Mapping[str, object],
    stage_telemetry: Mapping[str, object],
    warning_count: int,
) -> dict[str, object]:
    policy_hash = hashlib.sha256(json.dumps(dict(policy), sort_keys=True).encode("utf-8")).hexdigest()
    rss_context = {
        "memory_cap_bytes": memory_cap_bytes,
        "current_rss_bytes": current_rss_bytes,
        "platform": sys.platform,
        "warning_count": warning_count,
    }
    rss_context_hash = hashlib.sha256(json.dumps(rss_context, sort_keys=True).encode("utf-8")).hexdigest()
    stage_telemetry_hash = str(stage_telemetry.get("manifest_hash") or "")
    stage_row_head_hash = str(stage_telemetry.get("row_head_hash") or "")
    ready_slots: list[dict[str, object]] = [
        {
            "slot_id": "rss-snapshot",
            "status": "ready",
            "evidence_ref": "rss_context_hash",
            "evidence_hash": rss_context_hash,
            "description": "Current process RSS, configured cap, platform, and warning count are preserved.",
        },
        {
            "slot_id": "memory-cap-policy-profile",
            "status": "ready",
            "evidence_ref": "policy_profile_hash",
            "evidence_hash": policy_hash,
            "description": "Memory cap policy records cap configuration, over-cap state, platform, and breach action.",
        },
        {
            "slot_id": "stage-telemetry-manifest",
            "status": "ready",
            "evidence_ref": "memory_cap_stage_telemetry_manifest_hash",
            "evidence_hash": stage_telemetry_hash,
            "description": "Stage-boundary telemetry records checked stages and cap status.",
        },
        {
            "slot_id": "stage-row-hashes",
            "status": "ready",
            "evidence_ref": "stage_row_head_hash",
            "evidence_hash": stage_row_head_hash,
            "description": "Per-stage RSS rows are hashed for reviewer traceability.",
        },
        {
            "slot_id": "breach-action-policy",
            "status": "ready",
            "evidence_ref": "breach_action",
            "evidence_hash": hashlib.sha256(str(policy.get("breach_action") or "").encode("utf-8")).hexdigest(),
            "description": "Configured caps fail before the next stage output when RSS is over the limit.",
        },
        {
            "slot_id": "hard-limit-disclosure",
            "status": "ready",
            "evidence_ref": "hard_os_limit_configured",
            "evidence_hash": hashlib.sha256(str(bool(policy.get("hard_os_limit_configured"))).encode("ascii")).hexdigest(),
            "description": "The manifest explicitly discloses that Python RSS checks are not OS hard limits.",
        },
    ]
    blocking_slots: list[dict[str, object]] = [
        {
            "slot_id": "hard-os-memory-limit",
            "status": "blocked",
            "blocker": "hard-os-memory-limit-required",
            "required_evidence": "Windows Job Object, Linux cgroup, or macOS-equivalent hard memory limit proof",
        },
        {
            "slot_id": "per-parser-live-rss",
            "status": "blocked",
            "blocker": "per-parser-live-rss-telemetry-required",
            "required_evidence": "per-parser live RSS telemetry sampled during long-running parser execution",
        },
        {
            "slot_id": "trusted-rss-manifest",
            "status": "blocked",
            "blocker": "trusted-memory-cap-rss-manifest-required",
            "required_evidence": "trusted RSS manifest diff across cap, over-cap, and no-cap runs",
        },
        {
            "slot_id": "platform-rss-validation",
            "status": "blocked",
            "blocker": "platform-specific-rss-validation-required",
            "required_evidence": "Windows, macOS, and Linux RSS semantic validation logs",
        },
        {
            "slot_id": "large-case-rss-graph",
            "status": "blocked",
            "blocker": "large-case-rss-graph-required",
            "required_evidence": "1TB+ evidence run graph with peak RSS, warnings, and failure/retry behavior",
        },
        {
            "slot_id": "allocation-level-enforcement",
            "status": "blocked",
            "blocker": "allocation-level-enforcement-validation-required",
            "required_evidence": "allocation-level or parser-subprocess enforcement proof instead of stage-boundary-only checks",
        },
    ]
    plan_core = {
        "profile_version": MEMORY_CAP_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 72,
        "gap_id": MEMORY_CAP_GAP_ID,
        "commercial_gap_ids": [MEMORY_CAP_GAP_ID],
        "memory_cap_bytes": memory_cap_bytes,
        "current_rss_bytes": current_rss_bytes,
        "stage_check_count": int(stage_telemetry.get("stage_check_count") or 0),
        "over_cap_stage_count": int(stage_telemetry.get("over_cap_stage_count") or 0),
        "policy_profile_hash": policy_hash,
        "stage_telemetry_manifest_hash": stage_telemetry_hash,
        "stage_row_head_hash": stage_row_head_hash,
        "rss_context_hash": rss_context_hash,
        "stage_boundary_enforcement": True,
        "hard_os_limit_configured": False,
        "per_parser_live_rss_telemetry": False,
        "platform_specific_rss_validation_attached": False,
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "blockers": list(MEMORY_CAP_REPORT_GRADE_BLOCKERS),
        "commercial_claim_allowed": False,
        "ready_for_court_report": False,
        "report_use_warning": "Use as Python process stage-boundary RSS evidence only; do not claim OS hard memory limiting until blocker slots are satisfied.",
    }
    validation_plan_hash = hashlib.sha256(json.dumps(plan_core, sort_keys=True).encode("utf-8")).hexdigest()
    return {**plan_core, "validation_plan_hash": validation_plan_hash}


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
