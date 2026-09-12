"""Run checkpoint recording and resume assessment."""

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

from ..docs import write_result
from ..forensic_accuracy import build_accuracy_gate
from .constants import (
    CHECKPOINT_RESUME_GAP_ID,
    CHECKPOINT_RESUME_REPORT_GRADE_BLOCKERS,
    CHECKPOINT_RESUME_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    CHECKPOINT_TRUSTED_DIFF_BLOCKER_70,
)
from .performance import performance_commercial_uplift_evidence

__all__ = [
    "build_checkpoint_resume_trusted_diff",
    "checkpoint_diff_key",
    "checkpoint_diff_value",
    "checkpoint_integrity_profile",
    "checkpoint_record_hash",
    "checkpoint_resume_assessment",
    "checkpoint_resume_core_accuracy_gates",
    "checkpoint_resume_decision_manifest",
    "checkpoint_resume_report_grade_validation_plan",
    "record_run_checkpoint",
    "write_run_checkpoints",
]


def record_run_checkpoint(
    records: list[dict[str, object]],
    stage: str,
    path: Path,
    *,
    reused: bool,
    delta_merged: bool = False,
) -> None:
    record = {
        "stage": stage,
        "status": "delta-merged" if delta_merged else ("reused" if reused else "completed"),
        "delta_merged": delta_merged,
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
    validation_plan = checkpoint_resume_report_grade_validation_plan(
        checkpoints,
        input_fingerprint=input_fingerprint,
        resume_requested=resume_requested,
        resume_effective=resume_effective,
        resume_disabled_reason=resume_disabled_reason,
        integrity_profile=integrity_profile,
        decision_manifest=decision_manifest,
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
            "checkpoint_resume_report_grade_validation_plan_hash": validation_plan["validation_plan_hash"],
            "report_grade_ready_slot_count": validation_plan["ready_slot_count"],
            "report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
            "commercial_gap_ids": [CHECKPOINT_RESUME_GAP_ID],
            "commercial_grade_ready": False,
        },
        "checkpoint_resume_assessment": checkpoint_resume_assessment(
            resume_requested=resume_requested,
            resume_effective=resume_effective,
            checkpoints=checkpoints,
            decision_manifest=decision_manifest,
            validation_plan=validation_plan,
        ),
        "checkpoint_integrity_profile": integrity_profile,
        "checkpoint_resume_decision_manifest": decision_manifest,
        "checkpoint_resume_decision_manifest_hash": decision_manifest["manifest_hash"],
        "checkpoint_resume_report_grade_validation_plan": validation_plan,
        "checkpoint_resume_report_grade_validation_plan_hash": validation_plan["validation_plan_hash"],
        "report_grade_ready_slot_count": validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
        "core_accuracy_gates": checkpoint_resume_core_accuracy_gates(
            checkpoints=checkpoints,
            resume_requested=resume_requested,
            resume_effective=resume_effective,
            decision_manifest_hash=decision_manifest["manifest_hash"],
            validation_plan=validation_plan,
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
                "checkpoint resume report-grade validation plan emitted",
                "checkpoint resume report-grade ready slots emitted",
            ],
            large_data_controls=[
                "every completed stage is listed with output path, size, status, and reuse flag",
                "checkpoint row hashes and aggregate head hash make manifest review repeatable",
                "checkpoint resume decision manifest hashes every stage reuse/completion decision",
                "resume requested/effective/disabled reason is persisted",
                "input fingerprint is embedded next to checkpoints for reproducibility",
                "checkpoint summary counts reused and completed stage outputs",
                "checkpoint resume report-grade validation plan separates complete-stage reuse evidence from mid-parser blockers",
            ],
            external_validation=[
                "mid-parser checkpointing",
                "failed-stage resume replay on long-running cases",
                "trusted checkpoint/resume manifest diff",
                "cancellation/retry cleanup validation under load",
                "Case DB resume dedup validation",
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


def checkpoint_resume_report_grade_validation_plan(
    checkpoints: Sequence[Mapping[str, object]],
    *,
    input_fingerprint: Mapping[str, object],
    resume_requested: bool,
    resume_effective: bool,
    resume_disabled_reason: str,
    integrity_profile: Mapping[str, object],
    decision_manifest: Mapping[str, object],
) -> dict[str, object]:
    resume_state = {
        "resume_requested": resume_requested,
        "resume_effective": resume_effective,
        "resume_disabled_reason": resume_disabled_reason,
        "reused_count": int(decision_manifest.get("reused_count") or 0),
        "missing_output_count": int(decision_manifest.get("missing_output_count") or 0),
    }
    resume_state_hash = hashlib.sha256(json.dumps(resume_state, sort_keys=True).encode("utf-8")).hexdigest()
    checkpoint_size_rows = [
        {
            "stage": str(item.get("stage") or ""),
            "exists": bool(item.get("exists")),
            "size_bytes": int(item.get("size_bytes") or 0),
            "reused": bool(item.get("reused")),
        }
        for item in checkpoints
        if isinstance(item, Mapping)
    ]
    checkpoint_size_head_hash = hashlib.sha256(
        json.dumps(checkpoint_size_rows, sort_keys=True).encode("utf-8")
    ).hexdigest()
    input_fingerprint_hash = hashlib.sha256(
        str(input_fingerprint.get("fingerprint") or "").encode("utf-8", errors="replace")
    ).hexdigest()
    ready_slots: list[dict[str, object]] = [
        {
            "slot_id": "checkpoint-stage-rows",
            "status": "ready",
            "evidence_ref": "checkpoint_integrity_profile.head_hash",
            "evidence_hash": str(integrity_profile.get("head_hash") or ""),
            "description": "Stage checkpoint rows preserve output path, existence, byte size, and reuse status.",
        },
        {
            "slot_id": "checkpoint-decision-rows",
            "status": "ready",
            "evidence_ref": "checkpoint_resume_decision_manifest.decision_row_head_hash",
            "evidence_hash": str(decision_manifest.get("decision_row_head_hash") or ""),
            "description": "Resume decision rows hash every stage reuse or completion decision.",
        },
        {
            "slot_id": "checkpoint-decision-manifest",
            "status": "ready",
            "evidence_ref": "checkpoint_resume_decision_manifest.manifest_hash",
            "evidence_hash": str(decision_manifest.get("manifest_hash") or ""),
            "description": "Decision manifest ties checkpoint rows to resume policy and input fingerprint.",
        },
        {
            "slot_id": "checkpoint-resume-state",
            "status": "ready",
            "evidence_ref": "resume_state_hash",
            "evidence_hash": resume_state_hash,
            "description": "Resume requested/effective/disabled state is preserved for analyst review.",
        },
        {
            "slot_id": "checkpoint-input-fingerprint",
            "status": "ready",
            "evidence_ref": "input_fingerprint_hash",
            "evidence_hash": input_fingerprint_hash,
            "description": "Input fingerprint links checkpoint reuse to the source evidence state.",
        },
        {
            "slot_id": "checkpoint-output-size-review",
            "status": "ready",
            "evidence_ref": "checkpoint_size_head_hash",
            "evidence_hash": checkpoint_size_head_hash,
            "description": "Output existence, size, and reuse rows support repeatable checkpoint review.",
        },
    ]
    blocking_slots: list[dict[str, object]] = [
        {
            "slot_id": "checkpoint-mid-parser-state",
            "status": "blocked",
            "blocker": "mid-parser-checkpointing-required",
            "required_evidence": "parser-native offsets or cursors that resume inside long-running parser stages",
        },
        {
            "slot_id": "checkpoint-failed-stage-partial-resume",
            "status": "blocked",
            "blocker": "failed-stage-partial-resume-validation-required",
            "required_evidence": "failed-stage replay corpus proving safe partial-output handling and rebuild decisions",
        },
        {
            "slot_id": "checkpoint-trusted-manifest-diff",
            "status": "blocked",
            "blocker": "trusted-checkpoint-resume-manifest-required",
            "required_evidence": "trusted checkpoint/resume manifest diff with matching stage, size, reuse, and decision hashes",
        },
        {
            "slot_id": "checkpoint-long-running-replay",
            "status": "blocked",
            "blocker": "long-running-case-replay-validation-required",
            "required_evidence": "long-running case replay logs proving resume stability across large evidence corpora",
        },
        {
            "slot_id": "checkpoint-partial-output-cleanup",
            "status": "blocked",
            "blocker": "partial-output-cleanup-validation-required",
            "required_evidence": "partial-output cleanup/review validation for canceled or failed stages",
        },
        {
            "slot_id": "checkpoint-case-db-dedup",
            "status": "blocked",
            "blocker": "case-db-resume-dedup-validation-required",
            "required_evidence": "Case DB replay proving resumed imports do not duplicate indexed artifacts",
        },
    ]
    plan_core = {
        "profile_version": CHECKPOINT_RESUME_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 70,
        "gap_id": CHECKPOINT_RESUME_GAP_ID,
        "commercial_gap_ids": [CHECKPOINT_RESUME_GAP_ID],
        "checkpoint_count": len(checkpoints),
        "reused_count": int(decision_manifest.get("reused_count") or 0),
        "missing_output_count": int(decision_manifest.get("missing_output_count") or 0),
        "resume_requested": resume_requested,
        "resume_effective": resume_effective,
        "resume_disabled_reason": resume_disabled_reason,
        "checkpoint_integrity_head_hash": str(integrity_profile.get("head_hash") or ""),
        "checkpoint_resume_decision_manifest_hash": str(decision_manifest.get("manifest_hash") or ""),
        "decision_row_head_hash": str(decision_manifest.get("decision_row_head_hash") or ""),
        "input_fingerprint": str(input_fingerprint.get("fingerprint") or ""),
        "complete_json_stage_reuse_only": True,
        "mid_parser_resume": False,
        "failed_stage_partial_resume": False,
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "blockers": list(CHECKPOINT_RESUME_REPORT_GRADE_BLOCKERS),
        "commercial_claim_allowed": False,
        "ready_for_court_report": False,
        "report_use_warning": "Use as complete-stage checkpoint/reuse triage evidence only; do not claim mid-parser or failed-stage resume until blockers are satisfied.",
    }
    validation_plan_hash = hashlib.sha256(json.dumps(plan_core, sort_keys=True).encode("utf-8")).hexdigest()
    return {**plan_core, "validation_plan_hash": validation_plan_hash}


def checkpoint_resume_assessment(
    *,
    resume_requested: bool,
    resume_effective: bool,
    checkpoints: Sequence[Mapping[str, object]],
    decision_manifest: Mapping[str, object] | None = None,
    validation_plan: Mapping[str, object] | None = None,
) -> dict[str, object]:
    plan = validation_plan or {}
    return {
        "component": "stage-checkpoint-resume",
        "status": "resume-effective" if resume_effective else ("resume-requested-disabled-or-not-reused" if resume_requested else "fresh-run"),
        "commercial_gap_ids": [CHECKPOINT_RESUME_GAP_ID],
        "checkpoint_count": len(checkpoints),
        "reused_count": sum(1 for item in checkpoints if item.get("reused")),
        "checkpoint_resume_decision_manifest_hash": str((decision_manifest or {}).get("manifest_hash") or ""),
        "checkpoint_resume_report_grade_validation_plan": dict(plan) if plan else {},
        "checkpoint_resume_report_grade_validation_plan_hash": str(plan.get("validation_plan_hash") or ""),
        "report_grade_ready_slot_count": int(plan.get("ready_slot_count") or 0),
        "report_grade_blocking_slot_count": int(plan.get("blocking_slot_count") or 0),
        "ready_for_court_report": False,
        "blockers": [
            "checkpointing-reuses-complete-json-stage-outputs-not-mid-parser-state",
            "failed-or-partial-stage-resume-requires-rebuild-and-review-of-warning-output",
            "long-running-parser-cooperative-cancellation-remains-limited",
            CHECKPOINT_TRUSTED_DIFF_BLOCKER_70,
            *CHECKPOINT_RESUME_REPORT_GRADE_BLOCKERS,
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
            validation_plan=plan,
        ),
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


def checkpoint_resume_core_accuracy_gates(
    *,
    checkpoints: Sequence[Mapping[str, object]],
    resume_requested: bool,
    resume_effective: bool,
    decision_manifest_hash: str = "",
    validation_plan: Mapping[str, object] | None = None,
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
    plan = validation_plan or {}
    validation_plan_hash = str(plan.get("validation_plan_hash") or "")
    ready_slot_count = int(plan.get("ready_slot_count") or 0)
    blocking_slot_count = int(plan.get("blocking_slot_count") or 0)
    if validation_plan_hash:
        satisfied.append("checkpoint resume report-grade validation plan emitted")
    if ready_slot_count:
        satisfied.append("checkpoint resume report-grade ready slots emitted")
    evidence_refs = [
        f"checkpoint_count:{len(checkpoints)}",
        f"resume_requested:{resume_requested}",
        f"resume_effective:{resume_effective}",
        f"checkpoint_resume_decision_manifest_hash:{decision_manifest_hash}",
    ]
    if validation_plan_hash:
        evidence_refs.append(f"checkpoint_resume_report_grade_validation_plan_hash:{validation_plan_hash}")
        evidence_refs.append(f"checkpoint_resume_report_grade_ready_slots:{ready_slot_count}")
        evidence_refs.append(f"checkpoint_resume_report_grade_blocking_slots:{blocking_slot_count}")
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
