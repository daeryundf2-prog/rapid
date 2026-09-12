"""Parser crash isolation ledger, manifests, and assessments."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from collections.abc import (
    Mapping,
    Sequence,
)

from ..forensic_accuracy import build_accuracy_gate
from ..input_root import InputRoot
from .constants import (
    PARSER_CRASH_ISOLATION_GAP_ID,
    PARSER_CRASH_REPORT_GRADE_BLOCKERS,
    PARSER_CRASH_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    PARSER_CRASH_TRUSTED_DIFF_BLOCKER_71,
)

__all__ = [
    "build_parser_crash_isolation_ledger",
    "build_parser_crash_trusted_diff",
    "isolated_parser_error_payload",
    "isolated_parser_error_record",
    "parser_crash_continuation_manifest",
    "parser_crash_diff_errors",
    "parser_crash_isolation_assessment",
    "parser_crash_isolation_manifest",
    "parser_crash_report_grade_validation_plan",
    "parser_error_inventory_profile",
]


def isolated_parser_error_payload(kind: str, *, input_root: InputRoot, exc: Exception) -> dict[str, object]:
    message = str(exc) or exc.__class__.__name__
    error_record = isolated_parser_error_record(kind, input_root=input_root, exc=exc, message=message)
    crash_manifest = parser_crash_isolation_manifest(
        kind=kind,
        input_root=input_root,
        errors=[error_record],
    )
    validation_plan = parser_crash_report_grade_validation_plan(
        error_count=1,
        error_hashes=[str(error_record["error_hash"])],
        crash_manifest=crash_manifest,
        parser_statuses=[
            {
                "kind": kind,
                "status": "error",
                "parser_error_count": 1,
                "error_hashes": [str(error_record["error_hash"])],
            }
        ],
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
        "parser_crash_report_grade_validation_plan": validation_plan,
        "parser_crash_report_grade_validation_plan_hash": validation_plan["validation_plan_hash"],
        "report_grade_ready_slot_count": validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
        "parser_crash_isolation": parser_crash_isolation_assessment(
            error_count=1,
            error_hashes=[str(error_record["error_hash"])],
            crash_manifest=crash_manifest,
            validation_plan=validation_plan,
        ),
    }


def isolated_parser_error_record(
    kind: str,
    *,
    input_root: InputRoot,
    exc: Exception,
    message: str,
) -> dict[str, object]:
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
) -> dict[str, object]:
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
) -> dict[str, object]:
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
    ledger_head_hash = hashlib.sha256(
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
    validation_plan = parser_crash_report_grade_validation_plan(
        error_count=len(errors),
        error_hashes=error_hashes,
        continuation_manifest=continuation_manifest,
        parser_statuses=parser_statuses,
        scheduler_manifest=scheduler_manifest,
        ledger_head_hash=ledger_head_hash,
    )
    ledger_core: dict[str, object] = {
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
        "parser_crash_report_grade_validation_plan": validation_plan,
        "parser_crash_report_grade_validation_plan_hash": validation_plan["validation_plan_hash"],
        "report_grade_ready_slot_count": validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
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
            *PARSER_CRASH_REPORT_GRADE_BLOCKERS,
        ],
    }
    ledger_core["ledger_head_hash"] = ledger_head_hash
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


def parser_crash_report_grade_validation_plan(
    *,
    error_count: int,
    error_hashes: Sequence[str] = (),
    crash_manifest: Mapping[str, object] | None = None,
    continuation_manifest: Mapping[str, object] | None = None,
    parser_statuses: Sequence[Mapping[str, object]] = (),
    scheduler_manifest: Mapping[str, object] | None = None,
    ledger_head_hash: str = "",
) -> dict[str, object]:
    clean_error_hashes = sorted(str(value) for value in error_hashes if str(value))
    error_hash_head = hashlib.sha256("\n".join(clean_error_hashes).encode("ascii")).hexdigest()
    parser_rows = [
        {
            "kind": str(status.get("kind") or ""),
            "status": str(status.get("status") or ""),
            "parser_error_count": int(status.get("parser_error_count") or 0),
            "error_hashes": [str(value) for value in status.get("error_hashes", [])]
            if isinstance(status.get("error_hashes"), list)
            else [],
        }
        for status in parser_statuses
        if isinstance(status, Mapping)
    ]
    parser_status_head_hash = hashlib.sha256(
        json.dumps(parser_rows, sort_keys=True).encode("utf-8")
    ).hexdigest()
    crash_manifest_hash = str((crash_manifest or {}).get("manifest_hash") or "")
    continuation_hash = str((continuation_manifest or {}).get("manifest_hash") or "")
    scheduler_hash = str((scheduler_manifest or {}).get("manifest_hash") or "")
    review_policy = [
        "failed parser JSON is quarantined as non-reportable",
        "later parser outputs require warning review",
        "trusted crash-corpus diff is required before commercial claim",
    ]
    review_policy_hash = hashlib.sha256(json.dumps(review_policy, sort_keys=True).encode("utf-8")).hexdigest()
    ready_slots: list[dict[str, object]] = [
        {
            "slot_id": "parser-error-hash-inventory",
            "status": "ready",
            "evidence_ref": "error_hash_head",
            "evidence_hash": error_hash_head,
            "description": "Isolated parser errors are normalized into stable error hashes.",
        },
        {
            "slot_id": "failed-parser-json-output",
            "status": "ready",
            "evidence_ref": "failed_parser_json_output",
            "evidence_hash": crash_manifest_hash or error_hash_head,
            "description": "A failed parser emits machine-readable JSON instead of aborting the run.",
        },
        {
            "slot_id": "parser-status-rows",
            "status": "ready",
            "evidence_ref": "parser_status_head_hash",
            "evidence_hash": parser_status_head_hash,
            "description": "Parser status rows preserve which sibling parsers continued after a failure.",
        },
        {
            "slot_id": "continuation-manifest",
            "status": "ready",
            "evidence_ref": "parser_crash_continuation_manifest_hash",
            "evidence_hash": continuation_hash or crash_manifest_hash or error_hash_head,
            "description": "Continuation evidence separates isolated parser failures from completed sibling outputs.",
        },
        {
            "slot_id": "scheduler-manifest-linkage",
            "status": "ready",
            "evidence_ref": "scheduler_manifest_hash",
            "evidence_hash": scheduler_hash or parser_status_head_hash,
            "description": "Scheduler metadata links parser isolation to deterministic run output ordering.",
        },
        {
            "slot_id": "operator-review-policy",
            "status": "ready",
            "evidence_ref": "review_policy_hash",
            "evidence_hash": review_policy_hash,
            "description": "Operator warnings prevent isolated failures from being reported as complete artifacts.",
        },
    ]
    blocking_slots: list[dict[str, object]] = [
        {
            "slot_id": "native-process-sandboxing",
            "status": "blocked",
            "blocker": "native-process-sandboxing-required",
            "required_evidence": "every parser runs under a subprocess or OS sandbox boundary with crash-only failure mode",
        },
        {
            "slot_id": "trusted-crash-corpus",
            "status": "blocked",
            "blocker": "trusted-parser-crash-corpus-required",
            "required_evidence": "trusted crash-corpus manifest proving expected isolated failures and no missing failures",
        },
        {
            "slot_id": "corrupt-input-fuzz-corpus",
            "status": "blocked",
            "blocker": "corrupt-input-fuzz-crash-corpus-required",
            "required_evidence": "fuzz/corrupt-input corpus logs with parser-level pass/fail and continuation proof",
        },
        {
            "slot_id": "subprocess-crash-boundary",
            "status": "blocked",
            "blocker": "subprocess-crash-boundary-validation-required",
            "required_evidence": "hard process crash fixture proving segfault/abort cannot terminate the case run",
        },
        {
            "slot_id": "long-running-corrupt-replay",
            "status": "blocked",
            "blocker": "long-running-corrupt-evidence-replay-required",
            "required_evidence": "large corrupt-evidence replay showing stable continuation and bounded warning volume",
        },
        {
            "slot_id": "cross-platform-isolation",
            "status": "blocked",
            "blocker": "cross-platform-parser-isolation-validation-required",
            "required_evidence": "Windows, macOS, and Linux parser-isolation run logs with matching manifest semantics",
        },
    ]
    plan_core = {
        "profile_version": PARSER_CRASH_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 71,
        "gap_id": PARSER_CRASH_ISOLATION_GAP_ID,
        "commercial_gap_ids": [PARSER_CRASH_ISOLATION_GAP_ID],
        "error_count": error_count,
        "error_hash_head": error_hash_head,
        "parser_status_row_count": len(parser_rows),
        "parser_status_head_hash": parser_status_head_hash,
        "parser_crash_manifest_hash": crash_manifest_hash,
        "parser_crash_continuation_manifest_hash": continuation_hash,
        "scheduler_manifest_hash": scheduler_hash,
        "ledger_head_hash": ledger_head_hash,
        "failed_parser_json_output": True,
        "run_continuation_expected": True,
        "native_process_sandbox_for_every_parser": False,
        "trusted_crash_corpus_attached": False,
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "blockers": list(PARSER_CRASH_REPORT_GRADE_BLOCKERS),
        "commercial_claim_allowed": False,
        "ready_for_court_report": False,
        "report_use_warning": "Use as parser-failure isolation evidence only; do not claim sandboxed crash containment until blocker slots are satisfied.",
    }
    validation_plan_hash = hashlib.sha256(json.dumps(plan_core, sort_keys=True).encode("utf-8")).hexdigest()
    return {**plan_core, "validation_plan_hash": validation_plan_hash}


def parser_error_inventory_profile(errors: Sequence[Mapping[str, object]]) -> dict[str, object]:
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


def parser_crash_isolation_assessment(
    *,
    error_count: int,
    error_hashes: Sequence[str] = (),
    crash_manifest: Mapping[str, object] | None = None,
    validation_plan: Mapping[str, object] | None = None,
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
    plan: Mapping[str, object] = validation_plan or {}
    plan_candidate = (crash_manifest or {}).get("parser_crash_report_grade_validation_plan")
    if not plan and isinstance(plan_candidate, Mapping):
        plan = plan_candidate
    validation_plan_hash = str(plan.get("validation_plan_hash") or "")
    ready_slot_count = int(plan.get("ready_slot_count") or 0)
    blocking_slot_count = int(plan.get("blocking_slot_count") or 0)
    if validation_plan_hash:
        satisfied.append("parser crash report-grade validation plan emitted")
    if ready_slot_count:
        satisfied.append("parser crash report-grade ready slots emitted")
    evidence_refs = [f"parser_error_count:{error_count}", "run-summary:processing.parser_crash_isolation"]
    evidence_refs.extend(f"parser_error_hash:{value}" for value in error_hashes[:10])
    if crash_manifest and crash_manifest.get("manifest_hash"):
        evidence_refs.append(f"parser_crash_manifest_hash:{crash_manifest.get('manifest_hash')}")
    if crash_manifest and crash_manifest.get("parser_crash_continuation_manifest_hash"):
        evidence_refs.append(
            f"parser_crash_continuation_manifest_hash:{crash_manifest.get('parser_crash_continuation_manifest_hash')}"
        )
    if validation_plan_hash:
        evidence_refs.append(f"parser_crash_report_grade_validation_plan_hash:{validation_plan_hash}")
        evidence_refs.append(f"parser_crash_report_grade_ready_slots:{ready_slot_count}")
        evidence_refs.append(f"parser_crash_report_grade_blocking_slots:{blocking_slot_count}")
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
        "parser_crash_report_grade_validation_plan": dict(plan) if plan else {},
        "parser_crash_report_grade_validation_plan_hash": validation_plan_hash,
        "report_grade_ready_slot_count": ready_slot_count,
        "report_grade_blocking_slot_count": blocking_slot_count,
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
            *PARSER_CRASH_REPORT_GRADE_BLOCKERS,
        ],
    }
