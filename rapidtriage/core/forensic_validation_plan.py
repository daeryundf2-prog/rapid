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
FORENSIC_VALIDATION_PACK_VERSION = "forensic-validation-pack-v1"
DEFAULT_FORENSIC_VALIDATION_ITEMS = "1-65"
DEFAULT_FORENSIC_VALIDATION_PACK_ITEMS = "1-5"


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


def build_forensic_validation_pack(
    *,
    item_range: str = DEFAULT_FORENSIC_VALIDATION_PACK_ITEMS,
    output_dir: Path | None = None,
) -> dict[str, object]:
    """Build an executable evidence pack for a focused validation batch.

    The plan command says what remains. The pack command turns a small item
    range into concrete files an examiner can populate and rerun through
    trusted-diff validation without changing the contract by hand.
    """

    plan = build_forensic_validation_plan(item_range=item_range, output_dir=output_dir)
    rows = [row for row in plan.get("rows", []) if isinstance(row, Mapping)]
    if not rows:
        raise ValueError("forensic validation pack item range is empty")
    pack_core: dict[str, object] = {
        "command": "forensic-validation-pack",
        "profile_version": FORENSIC_VALIDATION_PACK_VERSION,
        "plan_profile_version": plan.get("profile_version"),
        "generated_at": plan.get("generated_at"),
        "item_range": item_range,
        "item_numbers": [int(row.get("number") or 0) for row in rows],
        "item_count": len(rows),
        "summary": build_forensic_validation_pack_summary(rows),
        "datasets": [build_validation_dataset_template(row) for row in rows],
        "reference_commands": [build_reference_command_template(row) for row in rows],
        "diff_contract": build_diff_contract(rows),
        "commercial_claim_allowed": False,
        "rule": (
            "This pack is an execution scaffold. Commercial-grade status requires populated "
            "source/reference/diff evidence, passing checks, and a rerun commercial-readiness report."
        ),
    }
    return {**pack_core, "pack_hash": stable_plan_hash(pack_core)}


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


def build_forensic_validation_pack_summary(rows: Iterable[Mapping[str, object]]) -> dict[str, object]:
    row_list = list(rows)
    item_numbers = [int(row.get("number") or 0) for row in row_list]
    tool_families: list[str] = []
    required_checks = 0
    for row in row_list:
        for tool in trusted_reference_tools_for_number(int(row.get("number") or 0)):
            if tool not in tool_families:
                tool_families.append(tool)
        required_checks += int(row.get("required_check_count") or 0)
    return {
        "item_numbers": item_numbers,
        "required_dataset_count": len(row_list),
        "required_check_count": required_checks,
        "required_tool_families": tool_families,
        "ready_to_claim_commercial": False,
        "next_action": "Populate every dataset path, run RapidTriage and trusted references, then attach row-level diffs.",
    }


def build_validation_dataset_template(row: Mapping[str, object]) -> dict[str, object]:
    number = int(row.get("number") or 0)
    dataset_core = {
        "dataset_id": f"forensic-item-{number:03d}",
        "item_number": number,
        "title": str(row.get("title") or f"Item {number}"),
        "status": "not-run",
        "lane": str(row.get("lane") or "unknown"),
        "surface": str(row.get("surface") or ""),
        "corpus_requirement": str(row.get("corpus") or ""),
        "trusted_oracle": str(row.get("oracle") or ""),
        "trusted_reference_tools": trusted_reference_tools_for_number(number),
        "required_checks": list(row.get("required_checks") or []),
        "evidence_paths": {
            "source_evidence": "",
            "rapid_output": "",
            "trusted_reference_output": "",
            "row_level_diff_output": "",
            "reviewer_signoff": "",
        },
        "hash_requirements": {
            "source_sha256": "",
            "rapid_output_sha256": "",
            "trusted_reference_sha256": "",
            "diff_output_sha256": "",
        },
        "pass_fail_contract": [
            "source_evidence path exists and hash matches manifest",
            "rapid_output contains item-specific normalized rows",
            "trusted_reference_output is produced by a recognized independent tool or hand-labeled fixture",
            "row_level_diff_output has zero unexpected missing rows, extra rows, or field mismatches",
            "limitations and reportability blockers remain present when evidence is incomplete",
        ],
        "commercial_blockers": list(row.get("commercial_blockers") or []),
        "remaining_gap": str(row.get("remaining_gap") or ""),
    }
    return {**dataset_core, "dataset_hash": stable_plan_hash(dataset_core)}


def build_reference_command_template(row: Mapping[str, object]) -> dict[str, object]:
    number = int(row.get("number") or 0)
    command_core = {
        "item_number": number,
        "title": str(row.get("title") or f"Item {number}"),
        "rapidtriage_command": rapidtriage_command_hint_for_number(number),
        "trusted_reference_command": trusted_reference_command_hint_for_number(number),
        "diff_command": (
            "rapidtriage cross-tool-validate --rapid-output <rapid.json> "
            "--reference-output reference=<trusted-output> --output <diff.json> --json"
        ),
        "required_output_fields": required_output_fields_for_number(number),
    }
    return {**command_core, "command_hash": stable_plan_hash(command_core)}


def build_diff_contract(rows: Iterable[Mapping[str, object]]) -> dict[str, object]:
    row_list = list(rows)
    contract_core = {
        "version": "row-level-diff-contract-v1",
        "item_numbers": [int(row.get("number") or 0) for row in row_list],
        "minimum_result": {
            "missing_rows": 0,
            "unexpected_rows": 0,
            "field_mismatches": 0,
            "unparsed_source_records": 0,
        },
        "required_diff_fields": sorted(
            {
                field
                for row in row_list
                for field in required_output_fields_for_number(int(row.get("number") or 0))
            }
        ),
        "failure_policy": (
            "Any missing/extra/mismatched row keeps the item at validation-required unless the discrepancy "
            "is documented as a trusted-tool limitation and independently reviewed."
        ),
    }
    return {**contract_core, "contract_hash": stable_plan_hash(contract_core)}


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


def trusted_reference_tools_for_number(number: int) -> list[str]:
    if number in {1, 2, 3}:
        return ["EvtxECmd", "Hayabusa", "Windows Event Viewer or wevtutil"]
    if number in {4, 5}:
        return ["RECmd", "Registry Explorer", "RegRipper"]
    if number == 6:
        return ["RECmd", "RegRipper", "Eric Zimmerman's Registry tools"]
    if 7 <= number <= 10:
        return ["AmcacheParser", "AppCompatCacheParser", "RECmd", "SrumECmd"]
    if number == 11:
        return ["libesedb", "WinSearchDBAnalyzer"]
    if number in {12, 13}:
        return ["MFTECmd", "analyzeMFT", "The Sleuth Kit"]
    if number in {14, 15}:
        return ["JLECmd", "ShellBagsExplorer", "RECmd"]
    return ["trusted external parser", "hand-labeled known-answer fixture"]


def rapidtriage_command_hint_for_number(number: int) -> str:
    if number in {1, 2, 3}:
        return "rapidtriage artifacts <case-root> --windows-event-logs --json --output <rapid-evtx.json>"
    if number in {4, 5}:
        return "rapidtriage artifacts <case-root> --windows-registry --json --output <rapid-registry.json>"
    return "rapidtriage artifacts <case-root> --json --output <rapid-output.json>"


def trusted_reference_command_hint_for_number(number: int) -> str:
    if number == 1:
        return "EvtxECmd -f <source.evtx> --json <reference-dir> plus Hayabusa csv-json export for record cross-check"
    if number == 2:
        return "wevtutil qe <log> /f:RenderedXml or EvtxECmd with maps to verify provider/message rendering"
    if number == 3:
        return "EvtxECmd against corrupt/deleted/slack fixture plus hand-labeled recovered offsets"
    if number == 4:
        return "RECmd -f <hive> --nl plus Registry Explorer export for full key/value tree comparison"
    if number == 5:
        return "Registry Explorer deleted-cell export or hand-labeled free-cell fixture with key/value offsets"
    return "Run the item-specific trusted parser listed in trusted_reference_tools and export JSON/CSV"


def required_output_fields_for_number(number: int) -> list[str]:
    if number in {1, 2, 3}:
        return [
            "source_path",
            "record_id",
            "event_id",
            "provider",
            "channel",
            "timestamp",
            "record_offset",
            "template_id",
            "rendered_message",
            "recovery_status",
        ]
    if number in {4, 5}:
        return [
            "source_path",
            "hive_path",
            "key_path",
            "value_name",
            "value_type",
            "value_data_hash",
            "cell_offset",
            "allocation_state",
            "transaction_replay_status",
        ]
    return ["source_path", "artifact_type", "normalized_identity", "timestamp", "source_offset", "parser_confidence"]


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


def write_forensic_validation_pack(pack: dict[str, object], output_dir: Path) -> dict[str, str]:
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "rapidtriage-forensic-validation-pack.json"
    md_path = output_dir / "rapidtriage-forensic-validation-pack.md"
    dataset_path = output_dir / "known-answer-datasets.template.json"
    commands_path = output_dir / "trusted-reference-commands.md"
    write_result(pack, json_path)
    md_path.write_text(render_forensic_validation_pack_markdown(pack), encoding="utf-8")
    write_result(
        {
            "profile_version": pack.get("profile_version"),
            "item_numbers": pack.get("item_numbers"),
            "datasets": pack.get("datasets", []),
            "diff_contract": pack.get("diff_contract", {}),
        },
        dataset_path,
    )
    commands_path.write_text(render_reference_commands_markdown(pack), encoding="utf-8")
    return {
        "json": str(json_path),
        "markdown": str(md_path),
        "dataset_template": str(dataset_path),
        "reference_commands": str(commands_path),
    }


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


def render_forensic_validation_pack_markdown(pack: Mapping[str, object]) -> str:
    summary = pack.get("summary") if isinstance(pack.get("summary"), Mapping) else {}
    lines = [
        "# RapidTriage Forensic Validation Pack",
        "",
        f"- Profile: `{pack.get('profile_version')}`",
        f"- Items: `{pack.get('item_range')}`",
        f"- Required datasets: {summary.get('required_dataset_count', 0)}",
        f"- Required checks: {summary.get('required_check_count', 0)}",
        f"- Pack hash: `{pack.get('pack_hash', '')}`",
        "",
        "## Required Tool Families",
        "",
    ]
    for tool in summary.get("required_tool_families", []) if isinstance(summary.get("required_tool_families"), list) else []:
        lines.append(f"- {tool}")
    lines.extend(["", "## Dataset Checklist", ""])
    for dataset in pack.get("datasets", []) if isinstance(pack.get("datasets"), list) else []:
        if not isinstance(dataset, Mapping):
            continue
        lines.extend(
            [
                f"### #{dataset.get('item_number')} {dataset.get('title')}",
                "",
                f"- Status: `{dataset.get('status')}`",
                f"- Source evidence: `{dataset.get('evidence_paths', {}).get('source_evidence', '') if isinstance(dataset.get('evidence_paths'), Mapping) else ''}`",
                f"- Trusted oracle: {dataset.get('trusted_oracle')}",
                f"- Remaining gap: {dataset.get('remaining_gap')}",
                "",
            ]
        )
    lines.extend(["## Diff Contract", ""])
    diff = pack.get("diff_contract") if isinstance(pack.get("diff_contract"), Mapping) else {}
    lines.append(f"- Failure policy: {diff.get('failure_policy', '')}")
    return "\n".join(lines).rstrip() + "\n"


def render_reference_commands_markdown(pack: Mapping[str, object]) -> str:
    lines = ["# Trusted Reference Commands", ""]
    for command in pack.get("reference_commands", []) if isinstance(pack.get("reference_commands"), list) else []:
        if not isinstance(command, Mapping):
            continue
        lines.extend(
            [
                f"## #{command.get('item_number')} {command.get('title')}",
                "",
                "```bash",
                str(command.get("rapidtriage_command") or ""),
                str(command.get("trusted_reference_command") or ""),
                str(command.get("diff_command") or ""),
                "```",
                "",
                "Required fields: "
                + ", ".join(str(field) for field in command.get("required_output_fields", []) if str(field)),
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def stable_plan_hash(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")).hexdigest()
