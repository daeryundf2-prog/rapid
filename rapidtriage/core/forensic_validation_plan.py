from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Iterable, Mapping

from .commercial_readiness import build_commercial_readiness_report, parse_item_range
from .docs import write_result
from .forensic_accuracy import CORE_FORENSIC_ACCURACY_ITEMS, accuracy_profile_for_item


FORENSIC_VALIDATION_PLAN_VERSION = "forensic-validation-plan-v1"
DEFAULT_FORENSIC_VALIDATION_ITEMS = "1-65"


def build_forensic_validation_plan(
    *,
    item_range: str = DEFAULT_FORENSIC_VALIDATION_ITEMS,
    output_dir: Path | None = None,
) -> dict[str, object]:
    numbers = parse_item_range(item_range)
    if not numbers:
        raise ValueError("forensic validation plan item range is empty")
    readiness = build_commercial_readiness_report(output_dir=output_dir)
    readiness_by_number = {
        int(item.get("number") or 0): item
        for item in readiness.get("all_items", [])
        if isinstance(item, Mapping)
    }
    rows = [build_forensic_validation_plan_row(number, readiness_by_number.get(number, {})) for number in numbers]
    summary = summarize_forensic_validation_plan(rows)
    plan_core: dict[str, object] = {
        "command": "forensic-validation-plan",
        "profile_version": FORENSIC_VALIDATION_PLAN_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "item_range": item_range,
        "item_numbers": numbers,
        "item_count": len(rows),
        "summary": summary,
        "sequencing": build_forensic_validation_sequence(rows),
        "rows": rows,
        "commercial_claim_allowed": False,
        "rule": "Items remain non-commercial until required validation, trusted diffs, and remaining blockers are closed.",
    }
    return {**plan_core, "plan_hash": stable_plan_hash(plan_core)}


def build_forensic_validation_plan_row(number: int, readiness_item: Mapping[str, object]) -> dict[str, object]:
    profile = accuracy_profile_for_item(number)
    gates = readiness_item.get("maturity_gates") if isinstance(readiness_item.get("maturity_gates"), Mapping) else {}
    validated_gate = gates.get("validated") if isinstance(gates.get("validated"), Mapping) else {}
    commercial_gate = gates.get("commercial_grade") if isinstance(gates.get("commercial_grade"), Mapping) else {}
    blockers = list(readiness_item.get("commercial_blockers") or []) if isinstance(readiness_item.get("commercial_blockers"), list) else []
    required_checks = [str(item) for item in profile.get("required_checks", []) if str(item)]
    row_core: dict[str, object] = {
        "number": number,
        "title": str(profile.get("title") or readiness_item.get("title") or f"Item {number}"),
        "lane": forensic_lane_for_number(number),
        "priority": forensic_priority_for_number(number),
        "current_maturity": str(readiness_item.get("highest_maturity_stage") or "unknown"),
        "next_required_gate": str(readiness_item.get("next_required_gate") or "validated"),
        "validated": bool(validated_gate.get("passed")),
        "commercial_grade_ready": bool(commercial_gate.get("passed")),
        "surface": str(profile.get("surface") or ""),
        "corpus": str(profile.get("corpus") or ""),
        "oracle": str(profile.get("oracle") or ""),
        "required_checks": required_checks,
        "required_check_count": len(required_checks),
        "remaining_gap": str(
            readiness_item.get("remaining_gap")
            or validated_gate.get("remaining")
            or commercial_gate.get("remaining")
            or "Attach known-answer and trusted diff evidence."
        ),
        "commercial_blockers": blockers,
        "blocker_count": len(blockers),
        "implementation_order": implementation_order_for_number(number),
        "next_internal_work": next_internal_work_for_number(number),
        "external_evidence_required": external_evidence_for_number(number),
        "completion_definition": completion_definition_for_number(number),
    }
    return {**row_core, "row_hash": stable_plan_hash(row_core)}


def summarize_forensic_validation_plan(rows: Iterable[Mapping[str, object]]) -> dict[str, object]:
    row_list = list(rows)
    lane_counts: dict[str, int] = {}
    for row in row_list:
        lane = str(row.get("lane") or "unknown")
        lane_counts[lane] = lane_counts.get(lane, 0) + 1
    return {
        "item_count": len(row_list),
        "validated_count": sum(1 for row in row_list if row.get("validated")),
        "commercial_grade_ready_count": sum(1 for row in row_list if row.get("commercial_grade_ready")),
        "validation_required_count": sum(1 for row in row_list if not row.get("validated")),
        "commercial_blocked_count": sum(1 for row in row_list if not row.get("commercial_grade_ready")),
        "lane_counts": lane_counts,
        "highest_priority_open_items": [
            int(row.get("number") or 0)
            for row in sorted(row_list, key=lambda item: (int(item.get("priority") or 99), int(item.get("number") or 999)))
            if not row.get("commercial_grade_ready")
        ][:10],
    }


def build_forensic_validation_sequence(rows: Iterable[Mapping[str, object]], *, batch_size: int = 5) -> list[dict[str, object]]:
    ordered = sorted(rows, key=lambda item: (int(item.get("implementation_order") or 999), int(item.get("number") or 999)))
    batches = []
    for index in range(0, len(ordered), batch_size):
        batch_rows = ordered[index : index + batch_size]
        batches.append(
            {
                "batch_number": len(batches) + 1,
                "item_numbers": [int(row.get("number") or 0) for row in batch_rows],
                "primary_lane": str(batch_rows[0].get("lane") or "unknown") if batch_rows else "unknown",
                "goal": batch_goal(batch_rows),
                "required_evidence": [
                    "fixture or known-answer input",
                    "RapidTriage output hash",
                    "trusted reference output or expected-result manifest",
                    "record/row/assertion-level diff",
                    "reviewer limitation note",
                ],
            }
        )
    return batches


def forensic_lane_for_number(number: int) -> str:
    if 1 <= number <= 25:
        return "core-windows-forensics"
    if 26 <= number <= 45:
        return "mobile-messenger-mail-cloud"
    if 46 <= number <= 65:
        return "search-viewer-review-report"
    return "other"


def forensic_priority_for_number(number: int) -> int:
    if number in {1, 2, 3, 4, 5, 12, 13, 22}:
        return 1
    if number in {6, 7, 8, 9, 10, 11, 16, 17, 18, 49, 54, 64, 65}:
        return 2
    if 19 <= number <= 21 or 46 <= number <= 63:
        return 3
    if 26 <= number <= 45:
        return 4
    return 5


def implementation_order_for_number(number: int) -> int:
    priority = forensic_priority_for_number(number)
    lane_bias = {"core-windows-forensics": 0, "search-viewer-review-report": 100, "mobile-messenger-mail-cloud": 200}
    return priority * 1000 + lane_bias.get(forensic_lane_for_number(number), 300) + number


def next_internal_work_for_number(number: int) -> str:
    if 1 <= number <= 3:
        return "Add native EVTX parser fixtures, record-offset citations, and trusted EvtxECmd/Hayabusa diff assertions."
    if 4 <= number <= 6 or number == 15:
        return "Add Registry hive transaction/deleted-cell/account fixtures with RECmd/RegRipper/ShellBagsExplorer diff assertions."
    if number in {10, 11}:
        return "Add bounded ESE table/page fixture decoding and source-row citation manifests."
    if number in {12, 13}:
        return "Add NTFS MFT/USN known-answer fixtures for path reconstruction, rename/delete replay, and cursor determinism."
    if 46 <= number <= 65:
        return "Add source citation, reviewer state, large-result, and report evidence fixtures with stable manifest hashes."
    if 26 <= number <= 45:
        return "Add versioned export schema fixtures and legal/secret redaction gates for the service/app family."
    return "Attach known-answer fixtures, trusted reference output, and row-level diff evidence."


def external_evidence_for_number(number: int) -> list[str]:
    evidence = ["reviewer sign-off", "known-answer source hash", "trusted reference output"]
    if 1 <= number <= 25:
        evidence.append("Windows artifact corpus across OS versions")
    if 26 <= number <= 45:
        evidence.append("authorized export/acquisition scope record")
    if 46 <= number <= 65:
        evidence.append("analyst workflow replay or UI/source-citation oracle")
    return evidence


def completion_definition_for_number(number: int) -> str:
    return (
        f"Item #{number} is complete only when implemented and usable evidence remains present, "
        "known-answer/trusted diff validation passes, limitations are emitted in outputs, "
        "and commercial_readiness marks validated without commercial-grade overclaim."
    )


def batch_goal(rows: list[Mapping[str, object]]) -> str:
    if not rows:
        return ""
    numbers = [int(row.get("number") or 0) for row in rows]
    return f"Close validation evidence for #{min(numbers)}-#{max(numbers)} without claiming commercial grade prematurely."


def write_forensic_validation_plan(plan: dict[str, object], output_dir: Path) -> dict[str, str]:
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "rapidtriage-forensic-validation-plan.json"
    md_path = output_dir / "rapidtriage-forensic-validation-plan.md"
    write_result(plan, json_path)
    md_path.write_text(render_forensic_validation_plan_markdown(plan), encoding="utf-8")
    return {"json": str(json_path), "markdown": str(md_path)}


def render_forensic_validation_plan_markdown(plan: Mapping[str, object]) -> str:
    summary = plan.get("summary") if isinstance(plan.get("summary"), Mapping) else {}
    lines = [
        "# RapidTriage Forensic Validation Plan",
        "",
        f"- Profile: `{plan.get('profile_version')}`",
        f"- Items: `{plan.get('item_range')}`",
        f"- Item count: {summary.get('item_count', 0)}",
        f"- Validated: {summary.get('validated_count', 0)}",
        f"- Commercial-ready: {summary.get('commercial_grade_ready_count', 0)}",
        f"- Plan hash: `{plan.get('plan_hash', '')}`",
        "",
        "## Execution Batches",
        "",
    ]
    for batch in plan.get("sequencing", []) if isinstance(plan.get("sequencing"), list) else []:
        if not isinstance(batch, Mapping):
            continue
        lines.append(
            f"- Batch {batch.get('batch_number')}: "
            f"{', '.join(f'#{number}' for number in batch.get('item_numbers', []))} - {batch.get('goal')}"
        )
    lines.extend(["", "## Item Matrix", ""])
    for row in plan.get("rows", []) if isinstance(plan.get("rows"), list) else []:
        if not isinstance(row, Mapping):
            continue
        lines.extend(
            [
                f"### #{row.get('number')} {row.get('title')}",
                "",
                f"- Lane: `{row.get('lane')}`",
                f"- Current maturity: `{row.get('current_maturity')}`",
                f"- Next gate: `{row.get('next_required_gate')}`",
                f"- Validated: `{row.get('validated')}`",
                f"- Commercial-ready: `{row.get('commercial_grade_ready')}`",
                f"- Next internal work: {row.get('next_internal_work')}",
                f"- Remaining gap: {row.get('remaining_gap')}",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def stable_plan_hash(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")).hexdigest()
