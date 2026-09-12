"""Timezone normalization and clock-skew integrity analysis."""

from __future__ import annotations

import datetime as dt
import sqlite3
from collections.abc import Mapping, Sequence

from .constants import (
    CLOCK_SKEW_ANALYSIS_GAP_ID,
    CLOCK_SKEW_REPORT_GRADE_BLOCKERS,
    CLOCK_SKEW_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    CLOCK_SKEW_TRUSTED_DIFF_BLOCKER_98,
    FUNCTIONAL_DEFENSIBILITY_BATCH_ID,
    TIMEZONE_NORMALIZATION_GAP_ID,
    TIMEZONE_REPORT_GRADE_BLOCKERS,
    TIMEZONE_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    TIMEZONE_VALIDATION_TRUSTED_DIFF_BLOCKER_97,
)
from .helpers import (
    stable_payload_sha256,
)
from .trusted_diffs import (
    clock_skew_core_accuracy_gates,
    missing_clock_skew_trusted_diff,
    missing_timezone_validation_trusted_diff,
    timezone_validation_core_accuracy_gates,
)

__all__ = [
    "attach_clock_skew_warning_row_hash",
    "attach_timezone_sample_row_hash",
    "build_clock_skew_analysis",
    "build_clock_skew_baseline_manifest",
    "build_clock_skew_range_matrix",
    "build_clock_skew_report_grade_validation_plan",
    "build_time_semantics_manifest",
    "build_timezone_normalization_manifest",
    "build_timezone_parser_assumption_matrix",
    "build_timezone_report_grade_validation_plan",
    "build_timezone_validation",
    "parse_event_timestamp",
    "timezone_clock_functional_profile",
]


def attach_timezone_sample_row_hash(sample: Mapping[str, object]) -> dict[str, object]:
    row = dict(sample)
    row["timezone_sample_row_hash"] = stable_payload_sha256(
        {
            "timestamp": row.get("timestamp"),
            "timezone": row.get("timezone"),
            "normalized_utc": row.get("normalized_utc"),
            "parser_assumption": row.get("parser_assumption"),
            "timestamp_kind": row.get("timestamp_kind"),
            "source": row.get("source"),
            "event_type": row.get("event_type"),
        }
    )
    return row


def build_timezone_normalization_manifest(
    *,
    event_count: int,
    missing_timezone_count: int,
    timezone_counts: Mapping[str, int],
    samples: Sequence[Mapping[str, object]],
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    parser_assumption_matrix = build_timezone_parser_assumption_matrix(samples)
    manifest_core = {
        "profile_version": "timezone-normalization-manifest-v1",
        "item_number": 97,
        "event_count": event_count,
        "missing_timezone_count": missing_timezone_count,
        "timezone_counts": dict(timezone_counts),
        "sample_count": len(samples),
        "sample_row_hashes": [str(sample.get("timezone_sample_row_hash") or "") for sample in samples],
        "parser_assumption_matrix": parser_assumption_matrix,
        "parser_assumption_matrix_hash": parser_assumption_matrix["matrix_hash"],
        "utc_assumption": "timestamps are interpreted as UTC when parser/source timezone is absent",
        "trusted_diff_status": str(trusted_diff.get("status") or ""),
        "commercial_gap_ids": [TIMEZONE_NORMALIZATION_GAP_ID],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_timezone_parser_assumption_matrix(samples: Sequence[Mapping[str, object]]) -> dict[str, object]:
    counts: dict[str, int] = {}
    for sample in samples:
        assumption = str(sample.get("parser_assumption") or "unknown")
        counts[assumption] = counts.get(assumption, 0) + 1
    rows = []
    for assumption, count in sorted(counts.items()):
        row_core = {"parser_assumption": assumption, "sample_count": count}
        rows.append({**row_core, "row_hash": stable_payload_sha256(row_core)})
    matrix_core = {
        "profile_version": "timezone-parser-assumption-matrix-v1",
        "item_number": 97,
        "sample_count": len(samples),
        "rows": rows,
        "assumption_count": len(rows),
        "commercial_claim_allowed": False,
    }
    return {**matrix_core, "matrix_hash": stable_payload_sha256(matrix_core)}


def build_time_semantics_manifest(
    *,
    samples: Sequence[Mapping[str, object]],
    timezone_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    semantic_rows = [
        {
            "original_timestamp": str(sample.get("timestamp") or ""),
            "source_timezone": str(sample.get("timezone") or ""),
            "normalized_utc": str(sample.get("normalized_utc") or ""),
            "timestamp_kind": str(sample.get("timestamp_kind") or ""),
            "source": str(sample.get("source") or ""),
            "event_type": str(sample.get("event_type") or ""),
            "parser_assumption": str(sample.get("parser_assumption") or ""),
            "parse_status": str(sample.get("timestamp_parse_status") or ""),
            "sample_row_hash": str(sample.get("timezone_sample_row_hash") or ""),
        }
        for sample in samples
    ]
    manifest_core: dict[str, object] = {
        "profile_version": "time-semantics-manifest-v1",
        "item_number": 42,
        "batch_id": FUNCTIONAL_DEFENSIBILITY_BATCH_ID,
        "gap_id": "#42",
        "commercial_gap_ids": [TIMEZONE_NORMALIZATION_GAP_ID, CLOCK_SKEW_ANALYSIS_GAP_ID],
        "sample_count": len(samples),
        "normalized_utc_sample_count": sum(1 for row in semantic_rows if row["normalized_utc"]),
        "missing_timezone_sample_count": sum(1 for row in semantic_rows if not row["source_timezone"]),
        "parser_assumptions": sorted({row["parser_assumption"] for row in semantic_rows if row["parser_assumption"]}),
        "timezone_normalization_manifest_hash": str(timezone_manifest.get("manifest_hash") or ""),
        "trusted_diff_status": str(trusted_diff.get("status") or ""),
        "samples": semantic_rows,
        "source_viewer_fields": [
            "original_timestamp",
            "source_timezone",
            "normalized_utc",
            "timestamp_kind",
            "source",
            "event_type",
            "parser_assumption",
            "sample_row_hash",
        ],
        "commercial_claim_allowed": False,
        "operator_warning": (
            "Use these rows to cite original and normalized time semantics; parser-specific timezone matrices "
            "and trusted baselines are still required before final conclusions."
        ),
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_timezone_report_grade_validation_plan(
    *,
    event_count: int,
    missing_timezone_count: int,
    samples: Sequence[Mapping[str, object]],
    timezone_manifest: Mapping[str, object],
    time_semantics_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    trusted_status = str(trusted_diff.get("status") or "missing")
    sample_row_hashes = [str(sample.get("timezone_sample_row_hash") or "") for sample in samples]
    parser_assumption_matrix = (
        timezone_manifest.get("parser_assumption_matrix")
        if isinstance(timezone_manifest.get("parser_assumption_matrix"), Mapping)
        else {}
    )
    ready_slots = [
        {
            "slot_id": "event-timezone-inventory",
            "status": "complete",
            "evidence": {
                "event_count": event_count,
                "missing_timezone_count": missing_timezone_count,
                "timezone_counts": dict(timezone_manifest.get("timezone_counts") or {}),
            },
        },
        {
            "slot_id": "timestamp-sample-row-hashes",
            "status": "complete",
            "evidence": {
                "sample_count": len(samples),
                "sample_row_hash_count": sum(1 for value in sample_row_hashes if value),
            },
        },
        {
            "slot_id": "timezone-normalization-manifest",
            "status": "complete",
            "evidence": {"manifest_hash": str(timezone_manifest.get("manifest_hash") or "")},
        },
        {
            "slot_id": "parser-assumption-matrix",
            "status": "complete",
            "evidence": {
                "matrix_hash": str(timezone_manifest.get("parser_assumption_matrix_hash") or ""),
                "assumption_count": int(parser_assumption_matrix.get("assumption_count") or 0),
            },
        },
        {
            "slot_id": "time-semantics-manifest",
            "status": "complete",
            "evidence": {
                "manifest_hash": str(time_semantics_manifest.get("manifest_hash") or ""),
                "normalized_utc_sample_count": int(
                    time_semantics_manifest.get("normalized_utc_sample_count") or 0
                ),
            },
        },
        {
            "slot_id": "utc-assumption-and-review-warning",
            "status": "complete",
            "evidence": {
                "utc_assumption": str(timezone_manifest.get("utc_assumption") or ""),
                "review_required": missing_timezone_count > 0,
            },
        },
        {
            "slot_id": "trusted-timezone-diff-disclosure",
            "status": "complete",
            "evidence": {
                "trusted_diff_status": trusted_status,
                "trusted_tool": str(trusted_diff.get("trusted_tool") or ""),
            },
        },
    ]
    blocking_slots: list[dict[str, object]] = []
    if event_count == 0:
        blocking_slots.append(
            {
                "slot_id": "case-events-present",
                "status": "blocked",
                "blocker": "no-case-events-for-time-validation",
                "required_evidence": "at least one case event with an original timestamp",
            }
        )
    if len([value for value in sample_row_hashes if value]) != len(samples):
        blocking_slots.append(
            {
                "slot_id": "timezone-sample-row-hash-completeness",
                "status": "blocked",
                "blocker": "timezone-sample-row-hash-completeness-required",
                "required_evidence": "row hash for every timezone validation sample",
            }
        )
    if missing_timezone_count:
        blocking_slots.append(
            {
                "slot_id": "source-timezone-completeness",
                "status": "blocked",
                "blocker": "source-timezone-completeness-required",
                "required_evidence": "source timezone or parser-specific timezone assumption for every reportable timestamp",
                "missing_timezone_count": missing_timezone_count,
            }
        )
    if not timezone_manifest.get("manifest_hash") or not timezone_manifest.get("parser_assumption_matrix_hash"):
        blocking_slots.append(
            {
                "slot_id": "timezone-normalization-manifest-complete",
                "status": "blocked",
                "blocker": "timezone-normalization-manifest-required",
                "required_evidence": "timezone normalization manifest hash and parser assumption matrix hash",
            }
        )
    if not time_semantics_manifest.get("manifest_hash"):
        blocking_slots.append(
            {
                "slot_id": "time-semantics-manifest-complete",
                "status": "blocked",
                "blocker": "time-semantics-manifest-required",
                "required_evidence": "time semantics manifest with original/normalized timestamp citation fields",
            }
        )
    if trusted_status != "pass":
        blocking_slots.append(
            {
                "slot_id": "trusted-timezone-normalization-matrix-diff",
                "status": "external-required",
                "blocker": TIMEZONE_VALIDATION_TRUSTED_DIFF_BLOCKER_97,
                "required_evidence": "trusted timezone matrix diff covering summary, samples, parser assumptions, and time semantics manifest",
            }
        )
    blocking_slots.extend(
        [
            {
                "slot_id": "parser-timezone-assumption-matrix",
                "status": "external-required",
                "blocker": "parser-timezone-assumption-matrix-required",
                "required_evidence": "parser-family/version timezone assumption matrix reviewed for all timestamp sources",
            },
            {
                "slot_id": "multi-source-timezone-reconciliation",
                "status": "external-required",
                "blocker": "multi-source-timezone-reconciliation-required",
                "required_evidence": "case-level reconciliation across OS, filesystem, browser, app, cloud, and acquisition timestamps",
            },
            {
                "slot_id": "timezone-known-answer-corpus",
                "status": "external-required",
                "blocker": "timezone-known-answer-corpus-required",
                "required_evidence": "known-answer fixture corpus for UTC, local, offset, missing, and parser-assumed timestamps",
            },
            {
                "slot_id": "daylight-saving-edge-case-corpus",
                "status": "external-required",
                "blocker": "daylight-saving-edge-case-corpus-required",
                "required_evidence": "DST and ambiguous local-time edge-case corpus for supported regions",
            },
            {
                "slot_id": "source-clock-baseline",
                "status": "external-required",
                "blocker": "source-clock-baseline-required",
                "required_evidence": "source clock/acquisition baseline tied to #98 clock-skew analysis",
            },
        ]
    )
    plan_core: dict[str, object] = {
        "profile_version": TIMEZONE_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 97,
        "commercial_gap_ids": [TIMEZONE_NORMALIZATION_GAP_ID],
        "plan_context": "case-db-timezone-normalization-validation",
        "event_count": event_count,
        "missing_timezone_count": missing_timezone_count,
        "sample_count": len(samples),
        "timezone_normalization_manifest_hash": str(timezone_manifest.get("manifest_hash") or ""),
        "parser_assumption_matrix_hash": str(timezone_manifest.get("parser_assumption_matrix_hash") or ""),
        "time_semantics_manifest_hash": str(time_semantics_manifest.get("manifest_hash") or ""),
        "trusted_diff_status": trusted_status,
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "external_blocker_catalog": list(TIMEZONE_REPORT_GRADE_BLOCKERS),
        "blockers": sorted({str(slot.get("blocker") or "") for slot in blocking_slots if slot.get("blocker")}),
        "commercial_claim_allowed": False,
        "reporting_boundary": "This plan makes timezone normalization auditable, but commercial claims require source timezone completeness or validated parser assumptions, trusted timezone matrices, multi-source reconciliation, known-answer/DST corpus, and source clock baselines.",
    }
    return {**plan_core, "validation_plan_hash": stable_payload_sha256(plan_core)}


def build_timezone_validation(
    connection: sqlite3.Connection,
    case_id: str,
    *,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    rows = connection.execute(
        """
        SELECT timestamp, timezone, timestamp_kind, source, event_type
        FROM event
        WHERE case_id = ?
        ORDER BY timestamp ASC, id ASC
        """,
        (case_id,),
    ).fetchall()
    missing = 0
    timezone_counts: dict[str, int] = {}
    samples = []
    for row in rows:
        timestamp = str(row["timestamp"] or "")
        timezone = str(row["timezone"] or "")
        if not timezone:
            missing += 1
        else:
            timezone_counts[timezone] = timezone_counts.get(timezone, 0) + 1
        normalized = parse_event_timestamp(timestamp)
        if len(samples) < 20:
            samples.append(
                attach_timezone_sample_row_hash(
                    {
                        "timestamp": timestamp,
                        "timezone": timezone,
                        "normalized_utc": normalized.isoformat() if normalized else "",
                        "timestamp_parse_status": "parsed" if normalized else "unparsed",
                        "parser_assumption": (
                            "source-timezone-preserved"
                            if timezone
                            else "assume-utc-because-source-timezone-missing"
                        ),
                        "timestamp_kind": str(row["timestamp_kind"] or ""),
                        "source": str(row["source"] or ""),
                        "event_type": str(row["event_type"] or ""),
                    }
                )
            )
    if trusted_diff is None:
        trusted_diff = missing_timezone_validation_trusted_diff()
    blockers = []
    if trusted_diff.get("status") != "pass":
        blockers.append(TIMEZONE_VALIDATION_TRUSTED_DIFF_BLOCKER_97)
    timezone_manifest = build_timezone_normalization_manifest(
        event_count=len(rows),
        missing_timezone_count=missing,
        timezone_counts=timezone_counts,
        samples=samples,
        trusted_diff=trusted_diff,
    )
    time_semantics_manifest = build_time_semantics_manifest(
        samples=samples,
        timezone_manifest=timezone_manifest,
        trusted_diff=trusted_diff,
    )
    report_grade_validation_plan = build_timezone_report_grade_validation_plan(
        event_count=len(rows),
        missing_timezone_count=missing,
        samples=samples,
        timezone_manifest=timezone_manifest,
        time_semantics_manifest=time_semantics_manifest,
        trusted_diff=trusted_diff,
    )
    blockers = sorted({*blockers, *report_grade_validation_plan["blockers"]})
    return {
        "status": "timezone-review-required" if missing else "timezone-fields-present",
        "commercial_gap_ids": [TIMEZONE_NORMALIZATION_GAP_ID],
        "functional_priority_profile": timezone_clock_functional_profile(
            event_count=len(rows),
            missing_timezone_count=missing,
            timezone_counts=timezone_counts,
            sample_count=len(samples),
            clock_warning_count=None,
            time_semantics_manifest=time_semantics_manifest,
            trusted_diff=trusted_diff,
        ),
        "summary": {
            "event_count": len(rows),
            "missing_timezone_count": missing,
            "timezone_counts": timezone_counts,
            "timezone_normalization_manifest_hash": timezone_manifest["manifest_hash"],
            "time_semantics_manifest_hash": time_semantics_manifest["manifest_hash"],
            "timezone_report_grade_validation_plan_hash": report_grade_validation_plan["validation_plan_hash"],
            "commercial_gap_ids": [TIMEZONE_NORMALIZATION_GAP_ID],
        },
        "samples": samples,
        "timezone_normalization_manifest": timezone_manifest,
        "timezone_normalization_manifest_hash": timezone_manifest["manifest_hash"],
        "parser_assumption_matrix_hash": timezone_manifest["parser_assumption_matrix_hash"],
        "time_semantics_manifest": time_semantics_manifest,
        "time_semantics_manifest_hash": time_semantics_manifest["manifest_hash"],
        "timezone_report_grade_validation_plan": report_grade_validation_plan,
        "timezone_report_grade_validation_plan_hash": report_grade_validation_plan["validation_plan_hash"],
        "timezone_report_grade_ready_slot_count": report_grade_validation_plan["ready_slot_count"],
        "timezone_report_grade_blocking_slot_count": report_grade_validation_plan["blocking_slot_count"],
        "trusted_timezone_validation_diff": trusted_diff,
        "blockers": blockers,
        "validation_assessment": {
            "commercial_gap_ids": [TIMEZONE_NORMALIZATION_GAP_ID],
            "original_timestamp_preserved": True,
            "normalized_utc_assumption": "timestamps are interpreted as UTC when parser/source timezone is absent",
            "review_required": bool(missing),
            "timezone_normalization_manifest_hash": timezone_manifest["manifest_hash"],
            "parser_assumption_matrix_hash": timezone_manifest["parser_assumption_matrix_hash"],
            "time_semantics_manifest_hash": time_semantics_manifest["manifest_hash"],
            "timezone_report_grade_validation_plan_hash": report_grade_validation_plan["validation_plan_hash"],
            "timezone_report_grade_ready_slot_count": report_grade_validation_plan["ready_slot_count"],
            "timezone_report_grade_blocking_slot_count": report_grade_validation_plan["blocking_slot_count"],
            "core_accuracy_gates": timezone_validation_core_accuracy_gates(
                event_count=len(rows),
                missing_timezone_count=missing,
                samples=samples,
                timezone_manifest=timezone_manifest,
                time_semantics_manifest=time_semantics_manifest,
                report_grade_validation_plan=report_grade_validation_plan,
                trusted_diff=trusted_diff,
            ),
            "trusted_timezone_validation_diff": trusted_diff,
            "blockers": blockers,
        },
        "guidance": "Preserve original timestamp, source timezone, normalized UTC assumption, and parser-specific timezone notes in final reports.",
    }


def attach_clock_skew_warning_row_hash(warning: Mapping[str, object]) -> dict[str, object]:
    row = dict(warning)
    row["clock_skew_warning_row_hash"] = stable_payload_sha256(
        {
            "type": row.get("type"),
            "timestamp": row.get("timestamp"),
            "source": row.get("source"),
        }
    )
    return row


def build_clock_skew_baseline_manifest(
    *,
    parsed_timestamp_count: int,
    warnings: Sequence[Mapping[str, object]],
    earliest: str,
    latest: str,
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    range_matrix = build_clock_skew_range_matrix(
        parsed_timestamp_count=parsed_timestamp_count,
        warnings=warnings,
        earliest=earliest,
        latest=latest,
    )
    manifest_core = {
        "profile_version": "clock-skew-baseline-manifest-v1",
        "item_number": 98,
        "parsed_timestamp_count": parsed_timestamp_count,
        "warning_count": len(warnings),
        "warning_row_hashes": [str(item.get("clock_skew_warning_row_hash") or "") for item in warnings],
        "earliest_timestamp": earliest,
        "latest_timestamp": latest,
        "clock_skew_range_matrix": range_matrix,
        "clock_skew_range_matrix_hash": range_matrix["matrix_hash"],
        "baseline_required": "Compare host/device time against acquisition notes and trusted external events.",
        "heuristic_only": True,
        "trusted_diff_status": str(trusted_diff.get("status") or ""),
        "commercial_gap_ids": [CLOCK_SKEW_ANALYSIS_GAP_ID],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_clock_skew_range_matrix(
    *,
    parsed_timestamp_count: int,
    warnings: Sequence[Mapping[str, object]],
    earliest: str,
    latest: str,
) -> dict[str, object]:
    warning_type_counts: dict[str, int] = {}
    for warning in warnings:
        warning_type = str(warning.get("type") or "unknown")
        warning_type_counts[warning_type] = warning_type_counts.get(warning_type, 0) + 1
    matrix_core = {
        "profile_version": "clock-skew-range-matrix-v1",
        "item_number": 98,
        "parsed_timestamp_count": parsed_timestamp_count,
        "earliest_timestamp": earliest,
        "latest_timestamp": latest,
        "warning_type_counts": dict(sorted(warning_type_counts.items())),
        "warning_count": len(warnings),
        "baseline_attached": False,
        "commercial_claim_allowed": False,
    }
    return {**matrix_core, "matrix_hash": stable_payload_sha256(matrix_core)}


def build_clock_skew_report_grade_validation_plan(
    *,
    parsed_timestamp_count: int,
    warnings: Sequence[Mapping[str, object]],
    earliest: str,
    latest: str,
    clock_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    trusted_status = str(trusted_diff.get("status") or "missing")
    warning_row_hashes = [str(warning.get("clock_skew_warning_row_hash") or "") for warning in warnings]
    ready_slots = [
        {
            "slot_id": "parsed-timestamp-range",
            "status": "complete",
            "evidence": {
                "parsed_timestamp_count": parsed_timestamp_count,
                "earliest_timestamp": earliest,
                "latest_timestamp": latest,
            },
        },
        {
            "slot_id": "clock-skew-warning-records",
            "status": "complete",
            "evidence": {
                "warning_count": len(warnings),
                "warning_row_hash_count": sum(1 for value in warning_row_hashes if value),
            },
        },
        {
            "slot_id": "clock-skew-range-matrix",
            "status": "complete",
            "evidence": {"matrix_hash": str(clock_manifest.get("clock_skew_range_matrix_hash") or "")},
        },
        {
            "slot_id": "clock-skew-baseline-manifest",
            "status": "complete",
            "evidence": {"manifest_hash": str(clock_manifest.get("manifest_hash") or "")},
        },
        {
            "slot_id": "baseline-and-heuristic-disclosure",
            "status": "complete",
            "evidence": {
                "baseline_required": str(clock_manifest.get("baseline_required") or ""),
                "heuristic_only": bool(clock_manifest.get("heuristic_only")),
            },
        },
        {
            "slot_id": "trusted-clock-skew-diff-disclosure",
            "status": "complete",
            "evidence": {
                "trusted_diff_status": trusted_status,
                "trusted_tool": str(trusted_diff.get("trusted_tool") or ""),
            },
        },
    ]
    blocking_slots: list[dict[str, object]] = []
    if parsed_timestamp_count == 0:
        blocking_slots.append(
            {
                "slot_id": "parsed-timestamps-present",
                "status": "blocked",
                "blocker": "parsed-timestamps-present-required",
                "required_evidence": "at least one parsed case timestamp before clock-skew review",
            }
        )
    if len([value for value in warning_row_hashes if value]) != len(warnings):
        blocking_slots.append(
            {
                "slot_id": "clock-skew-warning-row-hash-completeness",
                "status": "blocked",
                "blocker": "clock-skew-warning-row-hash-completeness-required",
                "required_evidence": "row hash for every exported clock-skew warning record",
            }
        )
    if not clock_manifest.get("manifest_hash") or not clock_manifest.get("clock_skew_range_matrix_hash"):
        blocking_slots.append(
            {
                "slot_id": "clock-skew-baseline-manifest-complete",
                "status": "blocked",
                "blocker": "clock-skew-baseline-manifest-required",
                "required_evidence": "clock-skew baseline manifest hash and range matrix hash",
            }
        )
    if trusted_status != "pass":
        blocking_slots.append(
            {
                "slot_id": "trusted-clock-skew-baseline-diff",
                "status": "external-required",
                "blocker": CLOCK_SKEW_TRUSTED_DIFF_BLOCKER_98,
                "required_evidence": "trusted clock-skew baseline diff covering parsed ranges, warnings, baseline manifest, and range matrix",
            }
        )
    blocking_slots.extend(
        [
            {
                "slot_id": "host-device-clock-baseline",
                "status": "external-required",
                "blocker": "host-device-clock-baseline-required",
                "required_evidence": "host/device clock baseline captured at acquisition and tied to the evidence source",
            },
            {
                "slot_id": "multi-device-skew-model",
                "status": "external-required",
                "blocker": "multi-device-skew-model-required",
                "required_evidence": "case-level model reconciling skew across each host, mobile device, cloud source, and removable media source",
            },
            {
                "slot_id": "trusted-external-timestamp-comparison",
                "status": "external-required",
                "blocker": "trusted-external-timestamp-comparison-required",
                "required_evidence": "comparison against trusted external timestamps such as acquisition logs, server logs, NTP records, or signed communications",
            },
            {
                "slot_id": "acquisition-time-baseline",
                "status": "external-required",
                "blocker": "acquisition-time-baseline-required",
                "required_evidence": "acquisition-start and acquisition-end timestamps with trusted operator/device time source",
            },
            {
                "slot_id": "timezone-normalization-linkage",
                "status": "external-required",
                "blocker": "timezone-normalization-linkage-required",
                "required_evidence": "linkage to #97 timezone normalization output for every reportable skew conclusion",
            },
            {
                "slot_id": "clock-skew-known-answer-corpus",
                "status": "external-required",
                "blocker": "clock-skew-known-answer-corpus-required",
                "required_evidence": "known-answer corpus with normal, skewed, future, pre-epoch, and multi-device timestamp fixtures",
            },
        ]
    )
    plan_core: dict[str, object] = {
        "profile_version": CLOCK_SKEW_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 98,
        "commercial_gap_ids": [CLOCK_SKEW_ANALYSIS_GAP_ID],
        "plan_context": "case-db-clock-skew-analysis-validation",
        "parsed_timestamp_count": parsed_timestamp_count,
        "warning_count": len(warnings),
        "earliest_timestamp": earliest,
        "latest_timestamp": latest,
        "clock_skew_baseline_manifest_hash": str(clock_manifest.get("manifest_hash") or ""),
        "clock_skew_range_matrix_hash": str(clock_manifest.get("clock_skew_range_matrix_hash") or ""),
        "trusted_diff_status": trusted_status,
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "external_blocker_catalog": list(CLOCK_SKEW_REPORT_GRADE_BLOCKERS),
        "blockers": sorted({str(slot.get("blocker") or "") for slot in blocking_slots if slot.get("blocker")}),
        "commercial_claim_allowed": False,
        "reporting_boundary": "This plan makes clock-skew review auditable, but commercial claims require trusted host/device baselines, acquisition-time baselines, external timestamp comparisons, multi-device skew modeling, #97 timezone linkage, and known-answer corpus evidence.",
    }
    return {**plan_core, "validation_plan_hash": stable_payload_sha256(plan_core)}


def build_clock_skew_analysis(
    connection: sqlite3.Connection,
    case_id: str,
    *,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    rows = connection.execute(
        """
        SELECT timestamp, source, event_type, description
        FROM event
        WHERE case_id = ?
        ORDER BY timestamp ASC, id ASC
        """,
        (case_id,),
    ).fetchall()
    warnings = []
    parsed_times: list[dt.datetime] = []
    now = dt.datetime.now(dt.timezone.utc)
    for row in rows:
        parsed = parse_event_timestamp(str(row["timestamp"] or ""))
        if parsed is None:
            continue
        parsed_times.append(parsed)
        if parsed.year < 1980:
            warnings.append(
                attach_clock_skew_warning_row_hash(
                    {"type": "timestamp-before-1980", "timestamp": str(row["timestamp"]), "source": str(row["source"] or "")}
                )
            )
        if parsed > now + dt.timedelta(days=2):
            warnings.append(
                attach_clock_skew_warning_row_hash(
                    {"type": "timestamp-in-future", "timestamp": str(row["timestamp"]), "source": str(row["source"] or "")}
                )
            )
    if trusted_diff is None:
        trusted_diff = missing_clock_skew_trusted_diff()
    blockers = []
    if trusted_diff.get("status") != "pass":
        blockers.append(CLOCK_SKEW_TRUSTED_DIFF_BLOCKER_98)
    earliest = min((value.isoformat() for value in parsed_times), default="")
    latest = max((value.isoformat() for value in parsed_times), default="")
    warnings_for_report = warnings[:100]
    clock_manifest = build_clock_skew_baseline_manifest(
        parsed_timestamp_count=len(parsed_times),
        warnings=warnings_for_report,
        earliest=earliest,
        latest=latest,
        trusted_diff=trusted_diff,
    )
    report_grade_validation_plan = build_clock_skew_report_grade_validation_plan(
        parsed_timestamp_count=len(parsed_times),
        warnings=warnings_for_report,
        earliest=earliest,
        latest=latest,
        clock_manifest=clock_manifest,
        trusted_diff=trusted_diff,
    )
    blockers = sorted({*blockers, *report_grade_validation_plan["blockers"]})
    return {
        "status": "warnings-present" if warnings else "no-obvious-clock-skew",
        "commercial_gap_ids": [CLOCK_SKEW_ANALYSIS_GAP_ID],
        "functional_priority_profile": timezone_clock_functional_profile(
            event_count=len(rows),
            missing_timezone_count=None,
            timezone_counts={},
            sample_count=0,
            clock_warning_count=len(warnings),
            trusted_diff=trusted_diff,
        ),
        "summary": {
            "event_count": len(rows),
            "parsed_timestamp_count": len(parsed_times),
            "warning_count": len(warnings),
            "earliest_timestamp": earliest,
            "latest_timestamp": latest,
            "clock_skew_baseline_manifest_hash": clock_manifest["manifest_hash"],
            "clock_skew_range_matrix_hash": clock_manifest["clock_skew_range_matrix_hash"],
            "clock_skew_report_grade_validation_plan_hash": report_grade_validation_plan["validation_plan_hash"],
            "clock_skew_report_grade_ready_slot_count": report_grade_validation_plan["ready_slot_count"],
            "clock_skew_report_grade_blocking_slot_count": report_grade_validation_plan["blocking_slot_count"],
            "commercial_gap_ids": [CLOCK_SKEW_ANALYSIS_GAP_ID],
        },
        "warnings": warnings_for_report,
        "clock_skew_baseline_manifest": clock_manifest,
        "clock_skew_baseline_manifest_hash": clock_manifest["manifest_hash"],
        "clock_skew_range_matrix_hash": clock_manifest["clock_skew_range_matrix_hash"],
        "clock_skew_report_grade_validation_plan": report_grade_validation_plan,
        "clock_skew_report_grade_validation_plan_hash": report_grade_validation_plan["validation_plan_hash"],
        "clock_skew_report_grade_ready_slot_count": report_grade_validation_plan["ready_slot_count"],
        "clock_skew_report_grade_blocking_slot_count": report_grade_validation_plan["blocking_slot_count"],
        "trusted_clock_skew_diff": trusted_diff,
        "blockers": blockers,
        "validation_assessment": {
            "commercial_gap_ids": [CLOCK_SKEW_ANALYSIS_GAP_ID],
            "heuristic_only": True,
            "baseline_required": "Compare host/device time against acquisition notes and trusted external events.",
            "review_required": bool(warnings),
            "clock_skew_baseline_manifest_hash": clock_manifest["manifest_hash"],
            "clock_skew_range_matrix_hash": clock_manifest["clock_skew_range_matrix_hash"],
            "clock_skew_report_grade_validation_plan_hash": report_grade_validation_plan["validation_plan_hash"],
            "clock_skew_report_grade_ready_slot_count": report_grade_validation_plan["ready_slot_count"],
            "clock_skew_report_grade_blocking_slot_count": report_grade_validation_plan["blocking_slot_count"],
            "core_accuracy_gates": clock_skew_core_accuracy_gates(
                parsed_timestamp_count=len(parsed_times),
                warnings=warnings_for_report,
                earliest=earliest,
                latest=latest,
                clock_manifest=clock_manifest,
                report_grade_validation_plan=report_grade_validation_plan,
                trusted_diff=trusted_diff,
            ),
            "trusted_clock_skew_diff": trusted_diff,
            "blockers": blockers,
        },
        "guidance": "Clock skew detection is heuristic; compare against acquisition notes, system timezone, and trusted external timestamps.",
    }


def parse_event_timestamp(value: str) -> dt.datetime | None:
    text = value.strip()
    if not text:
        return None
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def timezone_clock_functional_profile(
    *,
    event_count: int,
    missing_timezone_count: int | None,
    timezone_counts: Mapping[str, int],
    sample_count: int,
    clock_warning_count: int | None,
    trusted_diff: Mapping[str, object],
    time_semantics_manifest: Mapping[str, object] | None = None,
) -> dict[str, object]:
    failed_checks: list[str] = []
    if event_count == 0:
        failed_checks.append("no-case-events-for-time-validation")
    if missing_timezone_count is not None and missing_timezone_count > 0:
        failed_checks.append("timezone-missing-on-events")
    if clock_warning_count is not None and clock_warning_count > 0:
        failed_checks.append("clock-skew-warnings-present")
    if time_semantics_manifest is not None and not time_semantics_manifest.get("manifest_hash"):
        failed_checks.append("time-semantics-manifest-hash-missing")
    trusted_blockers = {
        TIMEZONE_VALIDATION_TRUSTED_DIFF_BLOCKER_97,
        CLOCK_SKEW_TRUSTED_DIFF_BLOCKER_98,
    }
    if trusted_diff.get("status") != "pass":
        blocker = str(trusted_diff.get("blocker") or "")
        failed_checks.append(blocker if blocker in trusted_blockers else "trusted-time-validation-diff-missing")
    return {
        "item_number": 42,
        "batch_id": FUNCTIONAL_DEFENSIBILITY_BATCH_ID,
        "status": "complete" if not failed_checks else "partial",
        "implemented_controls": {
            "event_count": event_count,
            "missing_timezone_count": missing_timezone_count,
            "timezone_counts": dict(timezone_counts),
            "sample_count": sample_count,
            "clock_warning_count": clock_warning_count,
            "utc_assumption_disclosed": True,
            "time_semantics_manifest_hash": str((time_semantics_manifest or {}).get("manifest_hash") or ""),
            "normalized_utc_sample_count": int((time_semantics_manifest or {}).get("normalized_utc_sample_count") or 0),
            "trusted_diff_status": str(trusted_diff.get("status") or ""),
        },
        "passed_validation_check_ids": [
            "original-timestamp-samples-preserved",
            "source-timezone-inventory-emitted",
            "utc-normalization-assumption-disclosed",
            "time-semantics-manifest-hash-emitted",
            "clock-skew-baseline-guidance-emitted",
        ],
        "failed_validation_check_ids": failed_checks,
        "reportability_decision": {
            "allowed_use": "timeline-time-semantics-review",
            "commercial_claim_allowed": not failed_checks,
            "operator_warning": "Timezone and skew conclusions require source parser assumptions plus trusted baseline review.",
        },
    }
