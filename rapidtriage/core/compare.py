from __future__ import annotations

import datetime as dt
import difflib
import hashlib
import json
from pathlib import Path
from typing import Mapping, Sequence

from .forensic_accuracy import build_accuracy_gate


class CompareError(ValueError):
    """Raised when a compare request cannot be completed."""


def stable_payload_sha256(payload: Mapping[str, object] | Sequence[Mapping[str, object]]) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


HASH_ALGORITHMS = ("md5", "sha1", "sha256")
TEXT_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".conf",
    ".csv",
    ".ini",
    ".json",
    ".log",
    ".md",
    ".ps1",
    ".py",
    ".reg",
    ".sh",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}
COMPARE_GAP_ID = "#52"
COMPARE_NATIVE_CAPABILITIES = {
    "a_b_file_compare": True,
    "a_b_c_baseline_compare": True,
    "hash_compare_md5_sha1_sha256": True,
    "bounded_text_diff": True,
    "case_report_pivot": True,
    "compare_review_profile": True,
    "bounded_compare_notes": True,
    "binary_structure_aware_diff": False,
    "image_visual_diff": False,
    "sqlite_table_aware_diff": False,
    "persistent_compare_notes": False,
}
COMPARE_REPORT_GRADE_BLOCKERS = [
    "binary-structure-aware-diff-not-implemented",
    "visual-and-table-aware-diff-not-implemented",
    "comparison-context-and-analyst-selection-require-review-history",
    "compare-trusted-expected-diff-required",
]
COMPARE_TRUSTED_DIFF_BLOCKER = "compare-trusted-expected-diff-required"
COMPARE_TRUSTED_TOOLS = {
    "expected-diff-manifest",
    "analyst-compare-workbook",
    "beyond-compare-export",
    "git-diff-ground-truth",
    "vendor-compare-export",
}


def compare_paths(
    left: Path,
    right: Path,
    *,
    left_label: str = "left",
    right_label: str = "right",
    hash_files: bool = True,
    include_text_diff: bool = True,
    max_text_bytes: int = 256 * 1024,
    diff_context: int = 3,
    selection_rationale: str = "",
    review_notes: Sequence[str] | None = None,
) -> dict[str, object]:
    left_path = left.expanduser().resolve()
    right_path = right.expanduser().resolve()
    left_record = describe_path(left_path, label=left_label, hash_files=hash_files)
    right_record = describe_path(right_path, label=right_label, hash_files=hash_files)

    fields = build_field_differences(left_record, right_record)
    status = compare_status(left_record, right_record)
    text_diff = (
        build_text_diff(left_path, right_path, left_label=left_label, right_label=right_label, max_text_bytes=max_text_bytes, context=diff_context)
        if include_text_diff and status == "different"
        else {}
    )
    result = {
        "comparison_id": "compare-0001",
        "status": status,
        "timestamp": comparison_timestamp(left_record, right_record),
        "path": str(left_path),
        "left_path": str(left_path),
        "right_path": str(right_path),
        "summary": build_summary(left_record, right_record, status),
        "fields": fields,
        "diff": text_diff,
        "left": left_record,
        "right": right_record,
    }
    review_profile = build_compare_review_profile(
        results=[result],
        mode="pair",
        input_records=[left_record, right_record],
        selection_rationale=selection_rationale,
        review_notes=review_notes,
    )
    citation_manifest = build_compare_citation_manifest(
        results=[result],
        mode="pair",
        input_records=[left_record, right_record],
        review_profile=review_profile,
    )
    report_grade = compare_report_grade_assessment(mode="pair")
    core_accuracy_gates = compare_core_accuracy_gates(
        results=[result],
        mode="pair",
        review_profile=review_profile,
        citation_manifest=citation_manifest,
    )
    return {
        "command": "compare",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "options": {
            "left_label": left_label,
            "right_label": right_label,
            "hash_files": hash_files,
            "include_text_diff": include_text_diff,
            "max_text_bytes": max_text_bytes,
            "diff_context": diff_context,
            "selection_rationale": selection_rationale,
            "review_note_count": int(review_profile.get("review_note_count") or 0),
        },
        "inputs": {
            "left": left_record,
            "right": right_record,
        },
        "summary": {
            "result_count": 1,
            "status_counts": {status: 1},
            "different_field_count": sum(1 for item in fields if item.get("status") == "different"),
            "text_diff_included": bool(text_diff.get("included")) if isinstance(text_diff, Mapping) else False,
            "review_queue_count": int(review_profile.get("review_queue_count") or 0),
            "selection_rationale_present": bool(review_profile.get("selection_rationale")),
            "review_note_count": int(review_profile.get("review_note_count") or 0),
            "compare_citation_manifest_hash": citation_manifest["manifest_hash"],
            "source_viewer_locator_count": citation_manifest["source_viewer_locator_count"],
            "commercial_gap_ids": [COMPARE_GAP_ID],
            "commercial_grade_ready": False,
        },
        "compare_native_capabilities": dict(COMPARE_NATIVE_CAPABILITIES),
        "compare_review_profile": review_profile,
        "compare_citation_manifest": citation_manifest,
        "compare_report_grade_assessment": report_grade,
        "core_accuracy_gates": core_accuracy_gates,
        "commercial_uplift_evidence": compare_commercial_uplift_evidence(
            results=[result],
            mode="pair",
            report_grade=report_grade,
            core_accuracy_gates=core_accuracy_gates,
            max_text_bytes=max_text_bytes,
            diff_context=diff_context,
            review_profile=review_profile,
            citation_manifest=citation_manifest,
        ),
        "results": [result],
    }


def compare_many_paths(
    paths: Sequence[Path],
    *,
    labels: Sequence[str] | None = None,
    hash_files: bool = True,
    include_text_diff: bool = True,
    max_text_bytes: int = 256 * 1024,
    diff_context: int = 3,
    selection_rationale: str = "",
    review_notes: Sequence[str] | None = None,
) -> dict[str, object]:
    if len(paths) < 2:
        raise CompareError("compare requires at least two files")
    normalized_labels = list(labels or [])
    while len(normalized_labels) < len(paths):
        normalized_labels.append(f"item-{len(normalized_labels) + 1}")
    baseline = paths[0]
    comparisons = []
    status_counts: dict[str, int] = {}
    different_field_count = 0
    text_diff_count = 0
    input_records = []
    baseline_record = describe_path(baseline.expanduser().resolve(), label=normalized_labels[0], hash_files=hash_files)
    input_records.append(baseline_record)
    for index, path in enumerate(paths[1:], start=2):
        payload = compare_paths(
            baseline,
            path,
            left_label=normalized_labels[0],
            right_label=normalized_labels[index - 1],
            hash_files=hash_files,
            include_text_diff=include_text_diff,
            max_text_bytes=max_text_bytes,
            diff_context=diff_context,
            selection_rationale=selection_rationale,
            review_notes=review_notes,
        )
        result = dict(payload["results"][0])
        result["comparison_id"] = f"compare-{index - 1:04d}"
        result["baseline_index"] = 1
        result["comparison_index"] = index
        comparisons.append(result)
        status = str(result.get("status") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
        different_field_count += sum(1 for item in result.get("fields", []) if isinstance(item, Mapping) and item.get("status") == "different")
        diff = result.get("diff") if isinstance(result.get("diff"), Mapping) else {}
        if diff.get("included"):
            text_diff_count += 1
        input_records.append(result["right"])
    review_profile = build_compare_review_profile(
        results=comparisons,
        mode="multi",
        input_records=input_records,
        selection_rationale=selection_rationale,
        review_notes=review_notes,
    )
    citation_manifest = build_compare_citation_manifest(
        results=comparisons,
        mode="multi",
        input_records=input_records,
        review_profile=review_profile,
    )
    report_grade = compare_report_grade_assessment(mode="multi")
    core_accuracy_gates = compare_core_accuracy_gates(
        results=comparisons,
        mode="multi",
        review_profile=review_profile,
        citation_manifest=citation_manifest,
    )
    return {
        "command": "compare",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "options": {
            "mode": "multi",
            "baseline_label": normalized_labels[0],
            "labels": normalized_labels[: len(paths)],
            "hash_files": hash_files,
            "include_text_diff": include_text_diff,
            "max_text_bytes": max_text_bytes,
            "diff_context": diff_context,
            "selection_rationale": selection_rationale,
            "review_note_count": int(review_profile.get("review_note_count") or 0),
        },
        "inputs": {
            "baseline": baseline_record,
            "items": input_records,
        },
        "summary": {
            "result_count": len(comparisons),
            "input_count": len(paths),
            "status_counts": status_counts,
            "different_field_count": different_field_count,
            "text_diff_included": text_diff_count > 0,
            "text_diff_count": text_diff_count,
            "review_queue_count": int(review_profile.get("review_queue_count") or 0),
            "selection_rationale_present": bool(review_profile.get("selection_rationale")),
            "review_note_count": int(review_profile.get("review_note_count") or 0),
            "compare_citation_manifest_hash": citation_manifest["manifest_hash"],
            "source_viewer_locator_count": citation_manifest["source_viewer_locator_count"],
            "commercial_gap_ids": [COMPARE_GAP_ID],
            "commercial_grade_ready": False,
        },
        "compare_native_capabilities": dict(COMPARE_NATIVE_CAPABILITIES),
        "compare_review_profile": review_profile,
        "compare_citation_manifest": citation_manifest,
        "compare_report_grade_assessment": report_grade,
        "core_accuracy_gates": core_accuracy_gates,
        "commercial_uplift_evidence": compare_commercial_uplift_evidence(
            results=comparisons,
            mode="multi",
            report_grade=report_grade,
            core_accuracy_gates=core_accuracy_gates,
            max_text_bytes=max_text_bytes,
            diff_context=diff_context,
            review_profile=review_profile,
            citation_manifest=citation_manifest,
        ),
        "results": comparisons,
    }


def compare_core_accuracy_gates(
    *,
    results: Sequence[Mapping[str, object]],
    mode: str,
    trusted_diff: Mapping[str, object] | None = None,
    review_profile: Mapping[str, object] | None = None,
    citation_manifest: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = []
    if mode == "multi" or len(results) >= 1:
        satisfied.append("A/B/C baseline compare")
    if all(result.get("left", {}).get("hashes") and result.get("right", {}).get("hashes") for result in results):
        satisfied.append("hash comparison")
    if any(isinstance(result.get("diff"), Mapping) and result["diff"].get("included") for result in results):
        satisfied.append("bounded text diff")
    if results:
        satisfied.append("status counts")
    review_profile = review_profile if isinstance(review_profile, Mapping) else {}
    if review_profile:
        satisfied.append("compare review profile")
    if int(review_profile.get("review_queue_count") or 0) > 0:
        satisfied.append("comparison review queue")
    if review_profile.get("selection_rationale"):
        satisfied.append("selection rationale captured")
    if int(review_profile.get("review_note_count") or 0) > 0:
        satisfied.append("bounded compare notes captured")
    citation_manifest = citation_manifest if isinstance(citation_manifest, Mapping) else {}
    if citation_manifest.get("manifest_hash"):
        satisfied.append("compare citation manifest hash")
    if int(citation_manifest.get("source_viewer_locator_count") or 0) > 0:
        satisfied.append("compare source viewer locators")
    if not COMPARE_NATIVE_CAPABILITIES["binary_structure_aware_diff"]:
        satisfied.append("specialized diff limitation warning")
    trusted_diff = trusted_diff if isinstance(trusted_diff, Mapping) else {}
    if trusted_diff.get("status") == "pass":
        satisfied.append("trusted A/B/C comparison expected diff pass")
    evidence_refs = [
        f"mode:{mode}",
        f"result_count:{len(results)}",
        f"review_queue_count:{review_profile.get('review_queue_count', 0)}",
        f"review_note_count:{review_profile.get('review_note_count', 0)}",
        f"compare_citation_manifest_hash:{citation_manifest.get('manifest_hash', '')}",
        f"trusted_diff_status:{trusted_diff.get('status', 'missing')}",
    ]
    for result in results[:3]:
        evidence_refs.append(f"comparison_id:{result.get('comparison_id', '')}")
        evidence_refs.append(f"left:{result.get('left_path', '')}")
        evidence_refs.append(f"right:{result.get('right_path', '')}")
    return [build_accuracy_gate(52, satisfied_checks=satisfied, evidence_refs=evidence_refs)]


def build_compare_review_profile(
    *,
    results: Sequence[Mapping[str, object]],
    mode: str,
    input_records: Sequence[Mapping[str, object]],
    selection_rationale: str = "",
    review_notes: Sequence[str] | None = None,
) -> dict[str, object]:
    normalized_notes = [str(note).strip() for note in (review_notes or []) if str(note).strip()]
    review_queue = []
    status_counts: dict[str, int] = {}
    text_diff_count = 0
    for index, result in enumerate(results):
        status = str(result.get("status") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
        fields = result.get("fields") if isinstance(result.get("fields"), Sequence) else []
        diff = result.get("diff") if isinstance(result.get("diff"), Mapping) else {}
        if diff.get("included"):
            text_diff_count += 1
        left = result.get("left") if isinstance(result.get("left"), Mapping) else {}
        right = result.get("right") if isinstance(result.get("right"), Mapping) else {}
        review_queue.append(
            {
                "comparison_id": str(result.get("comparison_id") or f"compare-{index + 1:04d}"),
                "baseline_label": str(left.get("label") or ""),
                "comparison_label": str(right.get("label") or ""),
                "baseline_path": str(left.get("path") or result.get("left_path") or ""),
                "comparison_path": str(right.get("path") or result.get("right_path") or ""),
                "status": status,
                "different_field_count": sum(
                    1 for field in fields if isinstance(field, Mapping) and field.get("status") == "different"
                ),
                "text_diff_included": bool(diff.get("included")),
                "review_status": "unreviewed",
                "report_decision": "pending",
                "selection_rationale": selection_rationale,
                "review_note": normalized_notes[index] if index < len(normalized_notes) else "",
                "required_actions": [
                    "verify source hashes for both compared files",
                    "record why this comparison matters before report inclusion",
                    "use specialized viewers for binary, image, SQLite, mailbox, or timeline-aware differences",
                ],
            }
        )
    input_inventory = [
        {
            "label": str(record.get("label") or ""),
            "path": str(record.get("path") or ""),
            "size": record.get("size"),
            "sha256": str((record.get("hashes") if isinstance(record.get("hashes"), Mapping) else {}).get("sha256") or ""),
        }
        for record in input_records
    ]
    return {
        "profile_version": "multi-evidence-compare-review-v1",
        "selected_track": "bounded-file-compare-review",
        "mode": mode,
        "input_count": len(input_records),
        "result_count": len(results),
        "status_counts": dict(sorted(status_counts.items())),
        "text_diff_count": text_diff_count,
        "selection_rationale": selection_rationale,
        "selection_rationale_required": True,
        "review_notes": normalized_notes,
        "review_note_count": len(normalized_notes),
        "input_inventory": input_inventory,
        "review_queue": review_queue,
        "review_queue_count": len(review_queue),
        "persistent_compare_notes": False,
        "binary_structure_aware_diff": False,
        "image_visual_diff": False,
        "sqlite_table_aware_diff": False,
        "timeline_aware_compare": False,
        "commercial_release_blocked": True,
        "reporting_status": "compare-review-validation-required",
        "required_before_report": [
            "persist compare notes and analyst selection rationale in the Case DB",
            "attach source-row citations and source hashes for every compared item",
            "run specialized semantic diff viewers for non-text evidence before making report-grade claims",
            "attach a trusted expected-diff manifest before claiming compare output is validated",
        ],
    }


def build_compare_citation_manifest(
    *,
    results: Sequence[Mapping[str, object]],
    mode: str,
    input_records: Sequence[Mapping[str, object]],
    review_profile: Mapping[str, object],
) -> dict[str, object]:
    review_queue = review_profile.get("review_queue") if isinstance(review_profile.get("review_queue"), Sequence) else []
    entries: list[dict[str, object]] = []
    source_viewer_locator_count = 0
    diff_locator_count = 0
    for index, result in enumerate(results[:100]):
        left = result.get("left") if isinstance(result.get("left"), Mapping) else {}
        right = result.get("right") if isinstance(result.get("right"), Mapping) else {}
        diff = result.get("diff") if isinstance(result.get("diff"), Mapping) else {}
        review_row = review_queue[index] if index < len(review_queue) and isinstance(review_queue[index], Mapping) else {}
        left_locator = compare_source_locator(left, side="baseline")
        right_locator = compare_source_locator(right, side="comparison")
        if left_locator.get("path"):
            source_viewer_locator_count += 1
        if right_locator.get("path"):
            source_viewer_locator_count += 1
        diff_locator = {
            "viewer": "compare-diff",
            "comparison_id": str(result.get("comparison_id") or f"compare-{index + 1:04d}"),
            "format": str(diff.get("format") or ""),
            "line_count": int(diff.get("line_count") or 0),
            "included": bool(diff.get("included")),
            "preview_line_limit": len(diff.get("preview") or []) if isinstance(diff.get("preview"), Sequence) else 0,
        }
        if diff_locator["included"]:
            diff_locator_count += 1
        entry_core = {
            "comparison_id": str(result.get("comparison_id") or f"compare-{index + 1:04d}"),
            "status": str(result.get("status") or ""),
            "baseline_locator": left_locator,
            "comparison_locator": right_locator,
            "diff_locator": diff_locator,
            "review_status": str(review_row.get("review_status") or "unreviewed"),
            "report_decision": str(review_row.get("report_decision") or "pending"),
            "selection_rationale": str(review_row.get("selection_rationale") or review_profile.get("selection_rationale") or ""),
            "review_note": str(review_row.get("review_note") or ""),
        }
        entries.append({**entry_core, "entry_hash": stable_payload_sha256(entry_core)})
    manifest_core: dict[str, object] = {
        "manifest_version": "multi-evidence-compare-citation-manifest-v1",
        "item_number": 52,
        "commercial_gap_ids": [COMPARE_GAP_ID],
        "mode": mode,
        "input_count": len(input_records),
        "comparison_count": len(results),
        "bounded_entry_count": len(entries),
        "queue_truncated": len(results) > len(entries),
        "source_viewer_locator_count": source_viewer_locator_count,
        "diff_locator_count": diff_locator_count,
        "selection_rationale_present": bool(review_profile.get("selection_rationale")),
        "review_note_count": int(review_profile.get("review_note_count") or 0),
        "entries": entries,
        "blockers": [
            "persistent-compare-notes-not-yet-implemented",
            "semantic-binary-image-sqlite-mailbox-diff-not-complete",
            COMPARE_TRUSTED_DIFF_BLOCKER,
        ],
        "commercial_claim_allowed": False,
        "operator_warning": (
            "Use this manifest to reopen compared sources and bounded text diffs; semantic artifact-specific "
            "comparison still requires specialized viewers and trusted expected-diff validation."
        ),
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def compare_source_locator(record: Mapping[str, object], *, side: str) -> dict[str, object]:
    hashes = record.get("hashes") if isinstance(record.get("hashes"), Mapping) else {}
    return {
        "viewer": "compare-source",
        "side": side,
        "label": str(record.get("label") or ""),
        "path": str(record.get("path") or ""),
        "name": str(record.get("name") or ""),
        "extension": str(record.get("extension") or ""),
        "size": record.get("size"),
        "sha256": str(hashes.get("sha256") or ""),
        "open_action": "open-source-for-compare-verification",
    }


def build_compare_trusted_diff(
    rapid_results: Sequence[Mapping[str, object]],
    trusted_results: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str,
    comparison_id: str = "compare-trusted-expected-diff",
) -> dict[str, object]:
    rapid_index = {_compare_diff_key(row): _compare_diff_values(row) for row in rapid_results}
    trusted_index = {_compare_diff_key(row): _compare_diff_values(row) for row in trusted_results}
    rapid_index.pop("", None)
    trusted_index.pop("", None)
    missing_in_trusted = sorted(key for key in rapid_index if key not in trusted_index)
    unexpected_in_trusted = sorted(key for key in trusted_index if key not in rapid_index)
    mismatches: list[dict[str, object]] = []
    for key in sorted(set(rapid_index) & set(trusted_index)):
        rapid = rapid_index[key]
        trusted = trusted_index[key]
        for field in ("status", "left_sha256", "right_sha256", "diff_sha256", "different_field_count"):
            if rapid.get(field) != trusted.get(field):
                mismatches.append({"row_key": key, "field": field, "rapid": rapid.get(field, ""), "trusted": trusted.get(field, "")})
    tool_accepted = trusted_tool.strip().lower() in COMPARE_TRUSTED_TOOLS
    status = "pass" if tool_accepted and rapid_index and trusted_index and not missing_in_trusted and not unexpected_in_trusted and not mismatches else "fail"
    return {
        "profile_version": "compare-trusted-expected-diff-v1",
        "comparison_id": comparison_id,
        "status": status,
        "blocker_id": "" if status == "pass" else COMPARE_TRUSTED_DIFF_BLOCKER,
        "trusted_tool": trusted_tool,
        "trusted_tool_accepted": tool_accepted,
        "accepted_trusted_tools": sorted(COMPARE_TRUSTED_TOOLS),
        "rapid_row_count": len(rapid_index),
        "trusted_row_count": len(trusted_index),
        "matched_count": len(set(rapid_index) & set(trusted_index)),
        "missing_in_trusted_count": len(missing_in_trusted),
        "unexpected_in_trusted_count": len(unexpected_in_trusted),
        "mismatch_count": len(mismatches),
        "mismatched_fields": mismatches[:50],
        "missing_in_trusted": missing_in_trusted[:50],
        "unexpected_in_trusted": unexpected_in_trusted[:50],
        "commercial_grade_evidence": status == "pass",
    }


def _compare_diff_key(row: Mapping[str, object]) -> str:
    comparison_id = str(row.get("comparison_id") or "").strip()
    if comparison_id:
        return comparison_id
    left = row.get("left") if isinstance(row.get("left"), Mapping) else {}
    right = row.get("right") if isinstance(row.get("right"), Mapping) else {}
    return f"{left.get('label', '')}:{left.get('path', '')}->{right.get('label', '')}:{right.get('path', '')}"


def _compare_diff_values(row: Mapping[str, object]) -> dict[str, object]:
    left = row.get("left") if isinstance(row.get("left"), Mapping) else {}
    right = row.get("right") if isinstance(row.get("right"), Mapping) else {}
    left_hashes = left.get("hashes") if isinstance(left.get("hashes"), Mapping) else {}
    right_hashes = right.get("hashes") if isinstance(right.get("hashes"), Mapping) else {}
    diff = row.get("diff") if isinstance(row.get("diff"), Mapping) else {}
    preview = "\n".join(str(item) for item in diff.get("preview", []) if isinstance(item, str))
    fields = row.get("fields") if isinstance(row.get("fields"), Sequence) else []
    return {
        "status": str(row.get("status") or ""),
        "left_sha256": str(left_hashes.get("sha256") or ""),
        "right_sha256": str(right_hashes.get("sha256") or ""),
        "diff_sha256": hashlib.sha256(preview.encode("utf-8", errors="replace")).hexdigest() if preview else "",
        "different_field_count": sum(1 for field in fields if isinstance(field, Mapping) and field.get("status") == "different"),
    }


def compare_report_grade_assessment(*, mode: str) -> dict[str, object]:
    return {
        "status": "implemented-baseline-validation-required",
        "mode": mode,
        "commercial_gap_ids": [COMPARE_GAP_ID],
        "ready_for_court_report": False,
        "blockers": list(COMPARE_REPORT_GRADE_BLOCKERS),
        "recommended_validation": [
            "Confirm why the compared files were selected and record reviewer status before report inclusion.",
            "Use artifact-specific viewers/parsers for binary, image, SQLite, and mailbox semantic differences.",
        ],
    }


def compare_commercial_uplift_evidence(
    *,
    results: Sequence[Mapping[str, object]],
    mode: str,
    report_grade: Mapping[str, object],
    core_accuracy_gates: Sequence[Mapping[str, object]],
    max_text_bytes: int,
    diff_context: int,
    review_profile: Mapping[str, object] | None = None,
    citation_manifest: Mapping[str, object] | None = None,
) -> dict[str, object]:
    passed = []
    for gate in core_accuracy_gates:
        if gate.get("gap_id") == COMPARE_GAP_ID:
            passed.extend(str(item) for item in gate.get("satisfied_checks") or [])
    failed = [
        "binary-structure-aware-diff",
        "image-visual-diff",
        "sqlite-table-aware-diff",
        "persistent-compare-notes",
        COMPARE_TRUSTED_DIFF_BLOCKER,
    ]
    review_profile = review_profile if isinstance(review_profile, Mapping) else {}
    citation_manifest = citation_manifest if isinstance(citation_manifest, Mapping) else {}
    return {
        "batch_id": "commercial-uplift-051-055",
        "item_numbers": [52],
        "implementation_track": "multi-evidence-compare-gate",
        "source_refs": [
            f"mode:{mode}",
            f"result_count:{len(results)}",
            *[f"comparison_id:{result.get('comparison_id', '')}" for result in results[:5]],
        ],
        "reportability_decision": compare_reportability_decision(
            mode=mode,
            results=results,
            failed_validation_check_ids=failed,
            commercial_blockers=list(report_grade.get("blockers") or []),
        ),
        "passed_validation_check_ids": sorted(set(passed)),
        "failed_validation_check_ids": failed,
        "commercial_blockers": list(report_grade.get("blockers") or []),
        "large_data_controls": {
            "max_text_bytes": max_text_bytes,
            "diff_context": diff_context,
            "result_count": len(results),
            "a_b_c_baseline_compare": mode == "multi",
            "bounded_text_diff": True,
            "compare_citation_manifest_present": bool(citation_manifest.get("manifest_hash")),
            "compare_citation_manifest_hash": str(citation_manifest.get("manifest_hash") or ""),
            "source_viewer_locator_count": int(citation_manifest.get("source_viewer_locator_count") or 0),
            "diff_locator_count": int(citation_manifest.get("diff_locator_count") or 0),
            "compare_review_profile_present": bool(review_profile),
            "review_queue_count": int(review_profile.get("review_queue_count") or 0),
            "selection_rationale_present": bool(review_profile.get("selection_rationale")),
            "review_note_count": int(review_profile.get("review_note_count") or 0),
            "persistent_compare_notes": bool(review_profile.get("persistent_compare_notes")),
            "binary_structure_aware_diff": False,
            "timeline_aware_compare": False,
        },
        "reporting_status": "implemented-baseline-validation-required",
    }


def compare_reportability_decision(
    *,
    mode: str,
    results: Sequence[Mapping[str, object]],
    failed_validation_check_ids: Sequence[str],
    commercial_blockers: Sequence[str],
) -> dict[str, object]:
    blockers = {str(item) for item in commercial_blockers if str(item)}
    blockers.update(f"check:{item}" for item in failed_validation_check_ids)
    return {
        "profile_version": "compare-reportability-decision-v1",
        "commercial_gap_ids": [COMPARE_GAP_ID],
        "decision": "do-not-report-compare-output-as-semantic-diff-complete",
        "allowed_use": "bounded-file-compare-triage-pivot",
        "blockers": sorted(blockers),
        "mode": mode,
        "result_count": len(results),
        "ready_for_court_report": False,
        "required_before_report": [
            "record analyst-selected comparison rationale and persistent compare notes",
            "run semantic binary, image, SQLite, mailbox, or timeline-aware viewers for specialized evidence",
            "attach source hashes and reviewed citations for each compared item",
        ],
    }


def describe_path(path: Path, *, label: str, hash_files: bool) -> dict[str, object]:
    exists = path.exists()
    record: dict[str, object] = {
        "label": label,
        "path": str(path),
        "name": path.name,
        "extension": path.suffix.lower(),
        "exists": exists,
        "is_file": path.is_file() if exists else False,
        "is_dir": path.is_dir() if exists else False,
        "size": None,
        "modified_at": None,
        "hashes": {},
    }
    if not exists:
        return record
    stat_result = path.stat()
    record["size"] = stat_result.st_size
    record["modified_at"] = dt.datetime.fromtimestamp(stat_result.st_mtime, tz=dt.timezone.utc).isoformat()
    if path.is_dir():
        raise CompareError("general compare accepts files only; use vsc-compare for directory tree comparisons")
    if not path.is_file():
        raise CompareError(f"compare input is not a regular file: {path}")
    if hash_files:
        record["hashes"] = compute_hashes(path)
    return record


def compute_hashes(path: Path, *, chunk_size: int = 8 * 1024 * 1024) -> dict[str, str]:
    hashers = {
        "md5": hashlib.md5(usedforsecurity=False),
        "sha1": hashlib.sha1(usedforsecurity=False),
        "sha256": hashlib.sha256(),
    }
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            for hasher in hashers.values():
                hasher.update(chunk)
    return {name: hasher.hexdigest() for name, hasher in hashers.items()}


def build_field_differences(left: Mapping[str, object], right: Mapping[str, object]) -> list[dict[str, object]]:
    fields = ["exists", "is_file", "size", "extension", "modified_at"]
    rows: list[dict[str, object]] = []
    for field in fields:
        left_value = left.get(field)
        right_value = right.get(field)
        rows.append(
            {
                "name": field,
                "left": left_value,
                "right": right_value,
                "status": "same" if left_value == right_value else "different",
            }
        )
    left_hashes = left.get("hashes") if isinstance(left.get("hashes"), Mapping) else {}
    right_hashes = right.get("hashes") if isinstance(right.get("hashes"), Mapping) else {}
    for algorithm in HASH_ALGORITHMS:
        left_hash = left_hashes.get(algorithm)
        right_hash = right_hashes.get(algorithm)
        if left_hash or right_hash:
            rows.append(
                {
                    "name": algorithm,
                    "left": left_hash,
                    "right": right_hash,
                    "status": "same" if left_hash == right_hash else "different",
                }
            )
    return rows


def compare_status(left: Mapping[str, object], right: Mapping[str, object]) -> str:
    if not left.get("exists") and not right.get("exists"):
        return "both-missing"
    if not left.get("exists"):
        return "only-in-right"
    if not right.get("exists"):
        return "only-in-left"
    left_hashes = left.get("hashes") if isinstance(left.get("hashes"), Mapping) else {}
    right_hashes = right.get("hashes") if isinstance(right.get("hashes"), Mapping) else {}
    left_sha256 = left_hashes.get("sha256")
    right_sha256 = right_hashes.get("sha256")
    if left_sha256 and right_sha256:
        return "same" if left_sha256 == right_sha256 else "different"
    return "same" if left.get("size") == right.get("size") else "different"


def comparison_timestamp(left: Mapping[str, object], right: Mapping[str, object]) -> str:
    timestamps = [str(value) for value in (left.get("modified_at"), right.get("modified_at")) if isinstance(value, str) and value]
    if timestamps:
        return max(timestamps)
    return dt.datetime.now(dt.timezone.utc).isoformat()


def build_summary(left: Mapping[str, object], right: Mapping[str, object], status: str) -> str:
    left_name = str(left.get("name") or left.get("path") or "left")
    right_name = str(right.get("name") or right.get("path") or "right")
    if status == "same":
        return f"{left_name} and {right_name} match"
    if status == "only-in-left":
        return f"{left_name} exists only on the left side"
    if status == "only-in-right":
        return f"{right_name} exists only on the right side"
    if status == "both-missing":
        return "Both compare inputs are missing"
    return f"{left_name} differs from {right_name}"


def build_text_diff(
    left: Path,
    right: Path,
    *,
    left_label: str,
    right_label: str,
    max_text_bytes: int,
    context: int,
) -> dict[str, object]:
    if not left.is_file() or not right.is_file():
        return {}
    if left.suffix.lower() not in TEXT_EXTENSIONS and right.suffix.lower() not in TEXT_EXTENSIONS:
        return {"included": False, "reason": "non-text-extension"}
    if left.stat().st_size > max_text_bytes or right.stat().st_size > max_text_bytes:
        return {"included": False, "reason": "text-byte-limit"}
    try:
        left_lines = left.read_text(encoding="utf-8").splitlines()
        right_lines = right.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        return {"included": False, "reason": "utf8-decode-failed"}
    diff_lines = list(
        difflib.unified_diff(
            left_lines,
            right_lines,
            fromfile=left_label,
            tofile=right_label,
            n=max(0, context),
            lineterm="",
        )
    )
    return {
        "included": bool(diff_lines),
        "format": "unified",
        "line_count": len(diff_lines),
        "preview": diff_lines[:200],
    }
