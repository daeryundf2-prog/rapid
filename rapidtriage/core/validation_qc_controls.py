from __future__ import annotations

import hashlib
import json
from typing import Mapping, Sequence


FIELD_DIFF_KEYS = (
    "record_field_comparison",
    "registry_field_comparison",
    "mft_field_comparison",
    "usn_field_comparison",
    "usn_state_replay_field_comparison",
    "ese_field_comparison",
)

DEFAULT_CONFIDENCE_FAMILIES = (
    ("evtx", "medium", "review-required", "provider message rendering and corrupt/deleted recovery require trusted diff evidence"),
    ("registry", "medium", "review-required", "transaction replay and deleted-cell recovery require RECmd/Registry Explorer diff evidence"),
    ("ntfs-mft-usn", "medium", "review-required", "large-volume path reconstruction and replay require known-answer stress evidence"),
    ("ese-srum-windows-edb", "low", "validation-required", "native ESE catalog/page/deleted-row decoding needs external corpus evidence"),
    ("browser-ai-web", "medium", "review-required", "schema drift and deleted history handling require per-version fixtures"),
    ("messenger-email-cloud", "low", "validation-required", "app/cloud schema versions and lawful-key boundaries require fixture matrices"),
)

DEFAULT_LEGAL_LIMITATIONS = {
    "evtx": "Event log records can be missing, provider message text can depend on local manifests/resources, and recovered/corrupt records must be independently validated.",
    "registry": "Registry keys and values can be affected by transaction logs, deleted-cell false positives, profile scope, and hive acquisition timing.",
    "ntfs-mft-usn": "MFT/USN timelines are filesystem metadata evidence; path replay, clock skew, volume snapshots, and journal wraparound must be reviewed.",
    "ese-srum-windows-edb": "ESE-derived rows can reflect cached/indexed state rather than user intent; deleted rows and long values require validation.",
    "browser-ai-web": "Browser and AI-service artifacts can be synced, cached, deleted, or account-shared; Q/A pairing and timestamps need source review.",
    "messenger-email-cloud": "Message, mail, and cloud exports depend on provider version, encryption state, export scope, and lawful authority.",
}


def build_validation_qc_contract(
    *,
    comparisons: Sequence[Mapping[str, object]],
    status: str,
    backlog_items: Sequence[int],
    output_written: bool,
    source_evidence_count: int,
    independent_review_count: int,
    commercial_grade_blockers: Sequence[str],
    tool_versions_attached: bool,
    tool_commands_attached: bool,
    corpus_scope_attached: bool,
) -> dict[str, object]:
    mismatch_dashboard = build_mismatch_dashboard(comparisons)
    fp_fn = build_fp_fn_register(mismatch_dashboard=mismatch_dashboard)
    confidence = build_parser_confidence_matrix(mismatch_dashboard=mismatch_dashboard)
    limitations = build_legal_limitation_guardrails()
    checklist = build_qc_checklist(
        status=status,
        backlog_items=backlog_items,
        output_written=output_written,
        source_evidence_count=source_evidence_count,
        independent_review_count=independent_review_count,
        commercial_grade_blockers=commercial_grade_blockers,
        tool_versions_attached=tool_versions_attached,
        tool_commands_attached=tool_commands_attached,
        corpus_scope_attached=corpus_scope_attached,
        mismatch_dashboard=mismatch_dashboard,
    )
    core = {
        "profile_version": "validation-qc-controls-v1",
        "qc_prep_item_numbers": [71, 72, 73, 74, 75],
        "status": "complete" if checklist["ready_for_validated_review"] else "partial",
        "mismatch_dashboard": mismatch_dashboard,
        "false_positive_false_negative_register": fp_fn,
        "parser_confidence_matrix": confidence,
        "legal_limitation_guardrails": limitations,
        "qc_checklist": checklist,
        "commercial_grade_blockers": list(dict.fromkeys(str(item) for item in commercial_grade_blockers if str(item))),
    }
    return {
        **core,
        "contract_hash": hashlib.sha256(json.dumps(core, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def build_mismatch_dashboard(comparisons: Sequence[Mapping[str, object]]) -> dict[str, object]:
    rows: list[dict[str, object]] = []
    total_missing = 0
    total_extra = 0
    total_field_mismatches = 0
    total_missing_common_fields = 0
    truncation_warnings = 0
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for comparison in comparisons:
        missing = len(_list_value(comparison.get("missing_in_rapid_sample")))
        extra = len(_list_value(comparison.get("only_in_rapid_sample")))
        field_mismatches = 0
        missing_common_fields = 0
        truncated_fields: list[str] = []
        field_summary: dict[str, object] = {}
        for field_key in FIELD_DIFF_KEYS:
            field_diff = comparison.get(field_key)
            if not isinstance(field_diff, Mapping):
                continue
            mismatch_count = int(field_diff.get("mismatch_count") or 0)
            missing_common = int(field_diff.get("missing_common_field_count") or 0)
            truncated = bool(field_diff.get("truncated"))
            field_mismatches += mismatch_count
            missing_common_fields += missing_common
            if truncated:
                truncated_fields.append(field_key)
            field_summary[field_key] = {
                "mode": str(field_diff.get("mode") or ""),
                "mismatch_count": mismatch_count,
                "missing_common_field_count": missing_common,
                "truncated": truncated,
                "sample_count": len(_list_value(field_diff.get("mismatch_samples"))),
            }
        severity = _mismatch_severity(
            status=str(comparison.get("status") or ""),
            missing=missing,
            field_mismatches=field_mismatches,
            missing_common_fields=missing_common_fields,
            truncated=bool(truncated_fields),
        )
        severity_counts[severity] += 1
        total_missing += missing
        total_extra += extra
        total_field_mismatches += field_mismatches
        total_missing_common_fields += missing_common_fields
        truncation_warnings += len(truncated_fields)
        rows.append(
            {
                "reference_name": str(comparison.get("reference_name") or ""),
                "status": str(comparison.get("status") or ""),
                "severity": severity,
                "overlap_ratio": float(comparison.get("overlap_ratio") or 0.0),
                "missing_rows_sample_count": missing,
                "extra_rows_sample_count": extra,
                "field_mismatch_count": field_mismatches,
                "missing_common_field_count": missing_common_fields,
                "truncated_field_diff_count": len(truncated_fields),
                "truncated_field_diffs": truncated_fields,
                "field_diff_summary": field_summary,
                "review_action": _review_action(severity),
            }
        )
    return {
        "profile_version": "trusted-diff-mismatch-dashboard-v1",
        "qc_prep_item_number": 71,
        "comparison_count": len(rows),
        "summary": {
            "missing_rows_sample_count": total_missing,
            "extra_rows_sample_count": total_extra,
            "field_mismatch_count": total_field_mismatches,
            "missing_common_field_count": total_missing_common_fields,
            "truncation_warning_count": truncation_warnings,
            "severity_counts": severity_counts,
        },
        "rows": rows,
        "dashboard_columns": [
            "reference_name",
            "status",
            "severity",
            "overlap_ratio",
            "missing_rows_sample_count",
            "extra_rows_sample_count",
            "field_mismatch_count",
            "truncated_field_diff_count",
            "review_action",
        ],
    }


def build_fp_fn_register(*, mismatch_dashboard: Mapping[str, object]) -> dict[str, object]:
    rows = mismatch_dashboard.get("rows") if isinstance(mismatch_dashboard.get("rows"), list) else []
    unresolved = [
        {
            "reference_name": str(row.get("reference_name") or ""),
            "suggested_record_type": "false-negative" if int(row.get("missing_rows_sample_count") or 0) else "false-positive-or-field-mismatch",
            "severity": str(row.get("severity") or "low"),
            "status": "needs-review",
            "required_fields": [
                "artifact_family",
                "source_record_id_or_offset",
                "analyst_decision",
                "reason",
                "reviewer",
                "created_at",
            ],
        }
        for row in rows
        if str(row.get("severity") or "") in {"critical", "high", "medium"}
    ]
    return {
        "profile_version": "fp-fn-recording-contract-v1",
        "qc_prep_item_number": 72,
        "json_export_required": True,
        "ui_controls_required": ["mark-false-positive", "mark-false-negative", "needs-investigation", "export-json"],
        "unresolved_review_queue": unresolved,
        "export_schema": {
            "artifact_family": "string",
            "source_record_id_or_offset": "string",
            "classification": "false-positive|false-negative|expected-difference|tool-limitation",
            "analyst_note": "string",
            "reviewer": "string",
            "created_at": "ISO-8601",
        },
    }


def build_parser_confidence_matrix(*, mismatch_dashboard: Mapping[str, object]) -> dict[str, object]:
    summary = mismatch_dashboard.get("summary") if isinstance(mismatch_dashboard.get("summary"), Mapping) else {}
    has_mismatch = int(summary.get("field_mismatch_count") or 0) > 0 or int(summary.get("missing_rows_sample_count") or 0) > 0
    rows = []
    for family, baseline, reportability, reason in DEFAULT_CONFIDENCE_FAMILIES:
        confidence = "low" if has_mismatch and baseline == "medium" else baseline
        state = "validation-required" if has_mismatch else reportability
        rows.append(
            {
                "artifact_family": family,
                "confidence": confidence,
                "reportability_state": state,
                "calibration_basis": reason,
                "commercial_claim_allowed": False,
                "required_upgrade_evidence": [
                    "known-answer fixture pass",
                    "trusted-tool row/field diff pass",
                    "parser limitation reviewed",
                ],
            }
        )
    return {
        "profile_version": "parser-confidence-reportability-v1",
        "qc_prep_item_number": 73,
        "confidence_bands": ["low", "medium", "high"],
        "reportability_states": ["validation-required", "review-required", "reportable-with-limitation"],
        "rows": rows,
    }


def build_legal_limitation_guardrails() -> dict[str, object]:
    return {
        "profile_version": "legal-limitation-guardrails-v1",
        "qc_prep_item_number": 74,
        "report_wording_rules": [
            "Do not state that an artifact proves user intent without corroboration.",
            "Always preserve source path/hash/parser version/offset or row identifier when citing extracted evidence.",
            "Recovered, deleted, corrupt, or carved artifacts must carry a validation-required limitation.",
            "Encrypted or authority-gated artifacts must disclose the legal/technical limitation instead of implying completeness.",
        ],
        "artifact_limitations": [
            {"artifact_family": family, "limitation_text": text}
            for family, text in sorted(DEFAULT_LEGAL_LIMITATIONS.items())
        ],
    }


def build_qc_checklist(
    *,
    status: str,
    backlog_items: Sequence[int],
    output_written: bool,
    source_evidence_count: int,
    independent_review_count: int,
    commercial_grade_blockers: Sequence[str],
    tool_versions_attached: bool,
    tool_commands_attached: bool,
    corpus_scope_attached: bool,
    mismatch_dashboard: Mapping[str, object],
) -> dict[str, object]:
    summary = mismatch_dashboard.get("summary") if isinstance(mismatch_dashboard.get("summary"), Mapping) else {}
    severity_counts = summary.get("severity_counts") if isinstance(summary.get("severity_counts"), Mapping) else {}
    checks = [
        _check("mapped-backlog-items", bool(backlog_items), f"{len(backlog_items)} mapped item(s)"),
        _check("cross-tool-output-written", output_written, "cross-tool JSON output path is recorded"),
        _check("cross-tool-status-pass", status == "pass", f"status={status}"),
        _check("source-evidence-hashes", source_evidence_count > 0, f"{source_evidence_count} source evidence file(s) hashed"),
        _check("external-tool-versions", tool_versions_attached, "all external reference versions captured"),
        _check("external-tool-commands", tool_commands_attached, "all external reference commands captured"),
        _check("corpus-scope", corpus_scope_attached, "corpus scope text/hash captured"),
        _check("independent-review", independent_review_count > 0, f"{independent_review_count} independent review file(s) hashed"),
        _check(
            "no-critical-mismatch",
            int(severity_counts.get("critical") or 0) == 0,
            f"critical={int(severity_counts.get('critical') or 0)}",
        ),
        _check(
            "no-high-mismatch",
            int(severity_counts.get("high") or 0) == 0,
            f"high={int(severity_counts.get('high') or 0)}",
        ),
    ]
    blockers = list(dict.fromkeys(str(item) for item in commercial_grade_blockers if str(item)))
    failed = [item["check_id"] for item in checks if not item["passed"]]
    return {
        "profile_version": "auto-qc-checklist-v1",
        "qc_prep_item_number": 75,
        "ready_for_validated_review": not failed,
        "ready_for_commercial_grade_review": not failed and not blockers,
        "checks": checks,
        "failed_check_ids": failed,
        "remaining_blockers": blockers,
    }


def _check(check_id: str, passed: bool, evidence: str) -> dict[str, object]:
    return {"check_id": check_id, "passed": bool(passed), "evidence": evidence}


def _list_value(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def _mismatch_severity(
    *,
    status: str,
    missing: int,
    field_mismatches: int,
    missing_common_fields: int,
    truncated: bool,
) -> str:
    if status == "failed" and (missing or field_mismatches or missing_common_fields):
        return "critical"
    if status == "failed":
        return "high"
    if field_mismatches or missing_common_fields or missing:
        return "high"
    if truncated:
        return "medium"
    return "low"


def _review_action(severity: str) -> str:
    if severity == "critical":
        return "block-reporting-until-triaged"
    if severity == "high":
        return "triage-before-release"
    if severity == "medium":
        return "document-truncation-and-sample"
    return "no-action-required"
