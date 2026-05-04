from __future__ import annotations

import datetime as dt
import difflib
import hashlib
from pathlib import Path
from typing import Mapping, Sequence

from .forensic_accuracy import build_accuracy_gate


class CompareError(ValueError):
    """Raised when a compare request cannot be completed."""


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
    "binary_structure_aware_diff": False,
    "image_visual_diff": False,
    "sqlite_table_aware_diff": False,
}
COMPARE_REPORT_GRADE_BLOCKERS = [
    "binary-structure-aware-diff-not-implemented",
    "visual-and-table-aware-diff-not-implemented",
    "comparison-context-and-analyst-selection-require-review-history",
]


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
    report_grade = compare_report_grade_assessment(mode="pair")
    core_accuracy_gates = compare_core_accuracy_gates(results=[result], mode="pair")
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
            "commercial_gap_ids": [COMPARE_GAP_ID],
            "commercial_grade_ready": False,
        },
        "compare_native_capabilities": dict(COMPARE_NATIVE_CAPABILITIES),
        "compare_report_grade_assessment": report_grade,
        "core_accuracy_gates": core_accuracy_gates,
        "commercial_uplift_evidence": compare_commercial_uplift_evidence(
            results=[result],
            mode="pair",
            report_grade=report_grade,
            core_accuracy_gates=core_accuracy_gates,
            max_text_bytes=max_text_bytes,
            diff_context=diff_context,
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
    report_grade = compare_report_grade_assessment(mode="multi")
    core_accuracy_gates = compare_core_accuracy_gates(results=comparisons, mode="multi")
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
            "commercial_gap_ids": [COMPARE_GAP_ID],
            "commercial_grade_ready": False,
        },
        "compare_native_capabilities": dict(COMPARE_NATIVE_CAPABILITIES),
        "compare_report_grade_assessment": report_grade,
        "core_accuracy_gates": core_accuracy_gates,
        "commercial_uplift_evidence": compare_commercial_uplift_evidence(
            results=comparisons,
            mode="multi",
            report_grade=report_grade,
            core_accuracy_gates=core_accuracy_gates,
            max_text_bytes=max_text_bytes,
            diff_context=diff_context,
        ),
        "results": comparisons,
    }


def compare_core_accuracy_gates(*, results: Sequence[Mapping[str, object]], mode: str) -> list[dict[str, object]]:
    satisfied = []
    if mode == "multi" or len(results) >= 1:
        satisfied.append("A/B/C baseline compare")
    if all(result.get("left", {}).get("hashes") and result.get("right", {}).get("hashes") for result in results):
        satisfied.append("hash comparison")
    if any(isinstance(result.get("diff"), Mapping) and result["diff"].get("included") for result in results):
        satisfied.append("bounded text diff")
    if results:
        satisfied.append("status counts")
    if not COMPARE_NATIVE_CAPABILITIES["binary_structure_aware_diff"]:
        satisfied.append("specialized diff limitation warning")
    evidence_refs = [
        f"mode:{mode}",
        f"result_count:{len(results)}",
    ]
    for result in results[:3]:
        evidence_refs.append(f"comparison_id:{result.get('comparison_id', '')}")
        evidence_refs.append(f"left:{result.get('left_path', '')}")
        evidence_refs.append(f"right:{result.get('right_path', '')}")
    return [build_accuracy_gate(52, satisfied_checks=satisfied, evidence_refs=evidence_refs)]


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
    ]
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
