from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import Path
from typing import Iterable, Mapping

from .docs import write_result


COMMERCIAL_READINESS_JSON_NAME = "rapidtriage-commercial-readiness.json"
COMMERCIAL_READINESS_MARKDOWN_NAME = "rapidtriage-commercial-readiness.md"
KNOWN_ANSWER_TEMPLATE_MARKDOWN_SUFFIX = ".md"

BACKLOG_ITEM_RE = re.compile(
    r"^(?P<number>\d+)\.\s+(?P<title>.+?)\.\s+Status:\s+(?P<status>[^.]+)\.\s*(?P<body>.*)$"
)
MATURITY_GATE_ORDER = ("implemented", "usable", "validated", "commercial_grade")
COMMERCIAL_UPLIFT_DEFAULT_TARGET_COUNT = 70
COMMERCIAL_UPLIFT_DEFAULT_BATCH_SIZE = 5
MATURITY_GATE_DEFINITIONS = {
    "implemented": "Code, workflow, import path, or release artifact evidence exists.",
    "usable": "An analyst can reach the feature through CLI/API/UI/docs without custom patching.",
    "validated": "Known-answer, fixture, cross-tool, or release-validation evidence is sufficient for the current claim.",
    "commercial_grade": "No remaining blocker prevents AXIOM/WISDOM-class parity wording for this item.",
}
SEVERITY_PRIORITY = {"critical": 0, "high": 1, "medium": 2, "low": 3}
CATEGORY_PRIORITY = {
    "core-forensics": 0,
    "mobile-cloud-apps": 1,
    "validation-legal": 2,
    "performance-large-scale": 3,
    "search-analysis-ux": 4,
    "deployment-operations": 5,
    "unknown": 9,
}


class CommercialReadinessError(ValueError):
    """Raised when commercial-readiness inputs are invalid."""


def default_backlog_path() -> Path:
    return Path(__file__).resolve().parents[2] / "docs" / "rapidtriage-commercial-parity-backlog.md"


def load_validation_evidence(validation_package_path: Path | None = None) -> dict[int, list[dict[str, object]]]:
    if validation_package_path is None:
        return {}
    resolved = validation_package_path.expanduser().resolve()
    try:
        raw = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CommercialReadinessError(f"failed to read validation evidence: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise CommercialReadinessError("validation evidence must be a JSON object")

    datasets = validation_datasets_from_payload(raw)
    evidence_by_item: dict[int, list[dict[str, object]]] = {}
    for dataset in datasets:
        if not isinstance(dataset, Mapping):
            continue
        status = str(dataset.get("status") or "").lower()
        evidence_paths_present = validation_evidence_paths_present(dataset, manifest_path=resolved)
        if status != "pass" or not evidence_paths_present:
            continue
        for number in validation_target_numbers(dataset):
            evidence_by_item.setdefault(number, []).append(
                {
                    "id": str(dataset.get("id") or ""),
                    "name": str(dataset.get("name") or dataset.get("id") or ""),
                    "source": str(dataset.get("source") or ""),
                    "status": status,
                    "manifest_path": str(resolved),
                    "evidence_paths": list(dataset.get("evidence_paths") or []),
                    "evidence_paths_present": True,
                    "notes": str(dataset.get("notes") or ""),
                }
            )
    return evidence_by_item


def validation_evidence_paths_present(dataset: Mapping[str, object], *, manifest_path: Path) -> bool:
    explicit = dataset.get("evidence_paths_present")
    if explicit is False:
        return False
    raw_paths = dataset.get("evidence_paths")
    if not isinstance(raw_paths, list) or not raw_paths:
        return bool(explicit is True)
    repo_root = Path(__file__).resolve().parents[2]
    for raw_path in raw_paths:
        text = str(raw_path).strip()
        if not text:
            return False
        candidate = Path(text).expanduser()
        candidates = [candidate] if candidate.is_absolute() else [
            Path.cwd() / candidate,
            manifest_path.parent / candidate,
            repo_root / candidate,
        ]
        if not any(path.exists() for path in candidates):
            return False
    return True


def validation_datasets_from_payload(payload: Mapping[str, object]) -> list[object]:
    known_answer = payload.get("known_answer_validation")
    if isinstance(known_answer, Mapping) and isinstance(known_answer.get("datasets"), list):
        return list(known_answer["datasets"])
    datasets = payload.get("datasets")
    if isinstance(datasets, list):
        return list(datasets)
    return []


def validation_target_numbers(dataset: Mapping[str, object]) -> list[int]:
    raw_values = (
        dataset.get("backlog_items")
        or dataset.get("commercial_items")
        or dataset.get("item_numbers")
        or []
    )
    if not raw_values and isinstance(dataset.get("expected"), Mapping):
        expected = dataset["expected"]
        raw_values = (
            expected.get("backlog_items")
            or expected.get("commercial_items")
            or expected.get("item_numbers")
            or []
        )
    if isinstance(raw_values, (str, int)):
        raw_values = [raw_values]
    numbers: list[int] = []
    if isinstance(raw_values, list):
        for value in raw_values:
            try:
                number = int(str(value).lstrip("#"))
            except ValueError:
                continue
            if 1 <= number <= 120 and number not in numbers:
                numbers.append(number)
    return numbers


def attach_validation_evidence(
    items: list[dict[str, object]],
    evidence_by_item: dict[int, list[dict[str, object]]],
) -> dict[str, object]:
    attached_count = 0
    for item in items:
        number = int(item.get("number") or 0)
        evidence_rows = evidence_by_item.get(number, [])
        if not evidence_rows:
            item["validation_evidence"] = []
            continue
        attached_count += 1
        item["validation_evidence"] = evidence_rows
        gates = item.get("maturity_gates")
        if isinstance(gates, dict) and isinstance(gates.get("validated"), dict):
            gates["validated"] = maturity_gate(
                True,
                "attached known-answer validation evidence passed for this backlog item",
                "",
            )
            item["highest_maturity_stage"] = highest_maturity_stage(gates)
            item["next_required_gate"] = next_required_gate(gates)
    return {
        "validation_package_attached": bool(evidence_by_item),
        "items_with_passed_validation_evidence": attached_count,
        "mapped_item_numbers": sorted(evidence_by_item),
        "rule": "Only datasets with status=pass and present evidence paths can satisfy an item's validated gate; commercial_grade still requires blocker removal.",
    }


def build_known_answer_manifest_template(
    items: Iterable[dict[str, object]],
    *,
    next_gate: str = "validated",
    limit: int = 5,
    item_numbers: Iterable[int] | None = None,
) -> dict[str, object]:
    if next_gate not in MATURITY_GATE_ORDER:
        raise CommercialReadinessError(f"unknown maturity gate for known-answer template: {next_gate}")
    item_list = list(items)
    selected_numbers = list(dict.fromkeys(int(number) for number in (item_numbers or []) if 1 <= int(number) <= 120))
    if selected_numbers:
        items_by_number = {int(item.get("number") or 0): item for item in item_list}
        selected = [items_by_number[number] for number in selected_numbers if number in items_by_number]
    else:
        selected = [
            item for item in sorted(item_list, key=priority_sort_key)
            if item.get("next_required_gate") == next_gate
        ][: max(limit, 0)]
    datasets = [known_answer_dataset_template(item) for item in selected]
    return {
        "command": "commercial-readiness-known-answer-template",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": "template-not-run",
        "next_gate": next_gate,
        "item_numbers": [int(item.get("number") or 0) for item in selected],
        "item_count": len(datasets),
        "instructions": [
            "Fill source, evidence_paths, expected assertions, and status after running real known-answer or cross-tool validation.",
            "Keep status as not-run/open/fail until every required assertion is independently verified.",
            "Only status=pass rows with present evidence paths can satisfy the commercial-readiness validated gate.",
        ],
        "datasets": datasets,
    }


def build_known_answer_template_batches(
    items: Iterable[dict[str, object]],
    *,
    item_numbers: Iterable[int],
    batch_size: int = 5,
    next_gate: str = "validated",
) -> dict[str, object]:
    if batch_size <= 0:
        raise CommercialReadinessError("known-answer template batch size must be greater than zero")
    numbers = [number for number in dict.fromkeys(int(value) for value in item_numbers) if 1 <= number <= 120]
    batches: list[dict[str, object]] = []
    for index in range(0, len(numbers), batch_size):
        batch_numbers = numbers[index : index + batch_size]
        template = build_known_answer_manifest_template(
            items,
            next_gate=next_gate,
            limit=batch_size,
            item_numbers=batch_numbers,
        )
        batches.append(
            {
                "batch_number": len(batches) + 1,
                "item_numbers": batch_numbers,
                "item_count": len(batch_numbers),
                "template": template,
            }
        )
    return {
        "command": "commercial-readiness-known-answer-template-batches",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": "templates-not-run",
        "next_gate": next_gate,
        "batch_size": batch_size,
        "batch_count": len(batches),
        "item_count": len(numbers),
        "item_numbers": numbers,
        "batches": batches,
        "rule": "Each batch starts as not-run. Fill evidence and change dataset status to pass only after real validation.",
    }


def known_answer_dataset_template(item: dict[str, object]) -> dict[str, object]:
    number = int(item.get("number") or 0)
    title = str(item.get("title") or f"Backlog item {number}")
    return {
        "id": f"commercial-item-{number:03d}-{slugify(title)}",
        "name": title,
        "source": "",
        "corpus_family": str(item.get("category") or ""),
        "status": "not-run",
        "backlog_items": [number],
        "evidence_paths": [],
        "expected": {
            "backlog_items": [number],
            "required_assertions": required_assertions_for_item(item),
            "reference_tools": reference_tools_for_item(number),
            "minimum_evidence": [
                "source evidence hash and acquisition notes",
                "RapidTriage output JSON/Markdown",
                "trusted reference tool output or known-answer expected-result file",
                "record-level or assertion-level diff",
                "reviewer sign-off with limitations",
            ],
        },
        "notes": gate_remaining_text(item, str(item.get("next_required_gate") or "validated")),
    }


def required_assertions_for_item(item: dict[str, object]) -> list[str]:
    number = int(item.get("number") or 0)
    title = str(item.get("title") or "")
    gap = gate_remaining_text(item, str(item.get("next_required_gate") or "validated"))
    assertions = [
        f"Backlog item #{number} ({title}) has passing known-answer or cross-tool evidence.",
        "RapidTriage output preserves source path, source hash, parser version, and relevant offsets where available.",
        "False-positive and false-negative limitations are documented for this item.",
    ]
    if gap:
        assertions.append(f"Remaining validation gap is specifically addressed: {gap}")
    if 1 <= number <= 3:
        assertions.extend(
            [
                "EVTX record counts, record IDs, timestamps, provider/channel/EventID fields, and recovered/corrupt candidates match expected results within documented tolerance.",
                "Message rendering/template fallback differences are explicitly diffed against the reference output.",
            ]
        )
    elif 4 <= number <= 6:
        assertions.extend(
            [
                "Registry/SAM/SECURITY/SYSTEM key, value, timestamp, deleted-cell, account, group, privilege, and transaction-log claims match expected results within documented tolerance.",
                "Any secret or protected value handling is authorized, redacted where required, and separately audited.",
            ]
        )
    elif 7 <= number <= 18:
        assertions.append(
            "Execution, filesystem, ESE, or system-artifact timestamps and semantic caveats are validated against a trusted parser export."
        )
    return assertions


def reference_tools_for_item(number: int) -> list[str]:
    if 1 <= number <= 3:
        return ["EvtxECmd", "Hayabusa", "Windows Event Viewer/wevtutil export where applicable"]
    if 4 <= number <= 6 or number == 15:
        return ["Registry Explorer/rla", "RegRipper", "Eric Zimmerman RECmd where applicable"]
    if number in {7, 8, 9, 16, 17}:
        return ["AmcacheParser", "AppCompatCacheParser", "PECmd", "LECmd/JLECmd where applicable"]
    if number in {10, 11}:
        return ["SrumECmd", "ESEDatabaseView/esedbexport", "Windows Search parser reference export"]
    if number in {12, 13}:
        return ["MFTECmd", "usn.py/USN Journal parser reference export", "Sleuth Kit where applicable"]
    return ["trusted commercial tool export", "known-answer expected-result manifest"]


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:72] or "validation"


def write_known_answer_manifest_template(template: dict[str, object], output: Path) -> dict[str, str]:
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    write_result(template, output)
    markdown_path = output.with_suffix(KNOWN_ANSWER_TEMPLATE_MARKDOWN_SUFFIX)
    markdown_path.write_text(render_known_answer_template_markdown(template), encoding="utf-8")
    return {"json": str(output), "markdown": str(markdown_path)}


def write_known_answer_template_batches(batch_payload: dict[str, object], output_dir: Path) -> dict[str, object]:
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    written_batches: list[dict[str, object]] = []
    for batch in batch_payload.get("batches", []):
        if not isinstance(batch, dict) or not isinstance(batch.get("template"), dict):
            continue
        item_numbers = [int(number) for number in batch.get("item_numbers", [])]
        if item_numbers:
            stem = f"known-answer-batch-{item_numbers[0]:03d}-{item_numbers[-1]:03d}.template.json"
        else:
            stem = f"known-answer-batch-{int(batch.get('batch_number') or 0):03d}.template.json"
        outputs = write_known_answer_manifest_template(batch["template"], output_dir / stem)
        written_batches.append(
            {
                "batch_number": batch.get("batch_number"),
                "item_numbers": item_numbers,
                "outputs": outputs,
            }
        )
    index_payload = {
        "command": batch_payload.get("command"),
        "generated_at": batch_payload.get("generated_at"),
        "status": batch_payload.get("status"),
        "next_gate": batch_payload.get("next_gate"),
        "batch_size": batch_payload.get("batch_size"),
        "batch_count": len(written_batches),
        "item_count": batch_payload.get("item_count"),
        "item_numbers": batch_payload.get("item_numbers"),
        "batches": written_batches,
        "rule": batch_payload.get("rule"),
    }
    index_json = output_dir / "known-answer-template-batches.index.json"
    index_md = output_dir / "known-answer-template-batches.index.md"
    write_result(index_payload, index_json)
    index_md.write_text(render_known_answer_batch_index_markdown(index_payload), encoding="utf-8")
    return {
        "directory": str(output_dir),
        "index_json": str(index_json),
        "index_markdown": str(index_md),
        "batch_count": len(written_batches),
        "batches": written_batches,
    }


def parse_item_range(value: str) -> list[int]:
    numbers: list[int] = []
    for raw_part in value.split(","):
        part = raw_part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            try:
                start = int(start_text.strip().lstrip("#"))
                end = int(end_text.strip().lstrip("#"))
            except ValueError as exc:
                raise CommercialReadinessError(f"invalid item range: {part}") from exc
            if end < start:
                start, end = end, start
            candidate_numbers = range(start, end + 1)
        else:
            try:
                candidate_numbers = [int(part.lstrip("#"))]
            except ValueError as exc:
                raise CommercialReadinessError(f"invalid item number: {part}") from exc
        for number in candidate_numbers:
            if not 1 <= number <= 120:
                raise CommercialReadinessError(f"item number out of supported range 1-120: {number}")
            if number not in numbers:
                numbers.append(number)
    return numbers


def render_known_answer_template_markdown(template: dict[str, object]) -> str:
    lines = [
        "# RapidTriage Known-Answer Manifest Template",
        "",
        f"- Generated at: `{template.get('generated_at', '')}`",
        f"- Status: `{template.get('status', '')}`",
        f"- Next gate: `{template.get('next_gate', '')}`",
        f"- Dataset templates: `{template.get('item_count', 0)}`",
        "",
        "## Instructions",
        "",
    ]
    for item in template.get("instructions", []):
        lines.append(f"- {item}")
    lines.extend(["", "## Dataset Templates", ""])
    for dataset in template.get("datasets", []):
        if not isinstance(dataset, dict):
            continue
        expected = dataset.get("expected") if isinstance(dataset.get("expected"), dict) else {}
        reference_tools = expected.get("reference_tools") if isinstance(expected.get("reference_tools"), list) else []
        lines.append(f"- `{dataset.get('id', '')}`: {dataset.get('name', '')}")
        if reference_tools:
            lines.append(f"  Reference tools: {', '.join(str(tool) for tool in reference_tools)}")
        notes = str(dataset.get("notes") or "").strip()
        if notes:
            lines.append(f"  Validation focus: {notes}")
    lines.append("")
    return "\n".join(lines)


def render_known_answer_batch_index_markdown(payload: dict[str, object]) -> str:
    lines = [
        "# RapidTriage Known-Answer Template Batch Index",
        "",
        f"- Generated at: `{payload.get('generated_at', '')}`",
        f"- Status: `{payload.get('status', '')}`",
        f"- Next gate: `{payload.get('next_gate', '')}`",
        f"- Batch size: `{payload.get('batch_size', '')}`",
        f"- Batch count: `{payload.get('batch_count', 0)}`",
        f"- Item count: `{payload.get('item_count', 0)}`",
        f"- Rule: {payload.get('rule', '')}",
        "",
        "## Batches",
        "",
    ]
    for batch in payload.get("batches", []):
        if not isinstance(batch, dict):
            continue
        outputs = batch.get("outputs") if isinstance(batch.get("outputs"), dict) else {}
        item_numbers = ", ".join(f"#{number}" for number in batch.get("item_numbers", []))
        lines.append(
            f"- Batch `{batch.get('batch_number')}` ({item_numbers}): `{outputs.get('json', '')}`"
        )
    lines.append("")
    return "\n".join(lines)


def build_commercial_readiness_report(
    *,
    backlog_path: Path | None = None,
    output_dir: Path | None = None,
    validation_package_path: Path | None = None,
    uplift_targets: int = COMMERCIAL_UPLIFT_DEFAULT_TARGET_COUNT,
    uplift_batch_size: int = COMMERCIAL_UPLIFT_DEFAULT_BATCH_SIZE,
) -> dict[str, object]:
    backlog_path = (backlog_path or default_backlog_path()).expanduser().resolve()
    if not backlog_path.is_file():
        raise CommercialReadinessError(f"commercial parity backlog not found: {backlog_path}")

    items = parse_backlog(backlog_path)
    if not items:
        raise CommercialReadinessError(f"no numbered backlog items found in: {backlog_path}")

    validation_evidence_summary = attach_validation_evidence(
        items,
        load_validation_evidence(validation_package_path),
    )
    non_commercial = [item for item in items if not item["commercial_grade_ready"]]
    status_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    for item in items:
        status = str(item["status"])
        severity = str(item["severity"])
        category = str(item["category"])
        status_counts[status] = status_counts.get(status, 0) + 1
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        category_counts[category] = category_counts.get(category, 0) + 1

    commercial_claim_allowed = not non_commercial
    readiness_score = calculate_readiness_score(items)
    maturity_gate_summary = build_maturity_gate_summary(items)
    commercial_uplift_plan = build_commercial_uplift_plan(
        items,
        readiness_score=readiness_score,
        target_count=uplift_targets,
        batch_size=uplift_batch_size,
    )
    payload: dict[str, object] = {
        "command": "commercial-readiness",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "backlog_path": str(backlog_path),
        "status": "commercial-ready" if commercial_claim_allowed else "commercial-gaps-present",
        "commercial_claim_allowed": commercial_claim_allowed,
        "release_claim": (
            "commercial forensic suite parity may be claimed"
            if commercial_claim_allowed
            else "do not claim AXIOM/WISDOM-class commercial parity; disclose triage/validation limits"
        ),
        "readiness_score": readiness_score,
        "item_count": len(items),
        "commercial_ready_count": len(items) - len(non_commercial),
        "non_commercial_count": len(non_commercial),
        "status_counts": status_counts,
        "severity_counts": severity_counts,
        "category_counts": category_counts,
        "maturity_gate_definitions": dict(MATURITY_GATE_DEFINITIONS),
        "maturity_gate_summary": maturity_gate_summary,
        "commercial_uplift_plan": commercial_uplift_plan,
        "validation_evidence_summary": validation_evidence_summary,
        "priority_work_plan": build_priority_work_plan(items),
        "all_items": items,
        "critical_non_commercial_items": [
            item for item in non_commercial if item["severity"] in {"critical", "high"}
        ],
        "non_commercial_items": non_commercial,
        "required_release_evidence": build_required_release_evidence(non_commercial),
        "operator_guidance": build_operator_guidance(non_commercial),
    }

    if output_dir is not None:
        output_dir = output_dir.expanduser().resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        json_path = output_dir / COMMERCIAL_READINESS_JSON_NAME
        markdown_path = output_dir / COMMERCIAL_READINESS_MARKDOWN_NAME
        write_result(payload, json_path)
        markdown_path.write_text(render_commercial_readiness_markdown(payload), encoding="utf-8")
        payload["outputs"] = {
            "json": str(json_path),
            "markdown": str(markdown_path),
        }
    return payload


def parse_backlog(backlog_path: Path) -> list[dict[str, object]]:
    items: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    for raw_line in backlog_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        match = BACKLOG_ITEM_RE.match(line)
        if match:
            if current is not None:
                finalize_backlog_item(current)
                items.append(current)
            number = int(match.group("number"))
            body = match.group("body").strip()
            current = {
                "number": number,
                "title": match.group("title").strip(),
                "status": normalize_status(match.group("status")),
                "category": category_for_number(number),
                "severity": severity_for_number(number),
                "body": body,
                "remaining_gap": extract_remaining_gap(body),
            }
            continue
        if line.startswith("#"):
            continue
        if current is not None and line:
            current["body"] = f"{current.get('body', '')} {line}".strip()
    if current is not None:
        finalize_backlog_item(current)
        items.append(current)
    return items


def finalize_backlog_item(item: dict[str, object]) -> None:
    body = str(item.get("body") or "")
    if not item.get("remaining_gap"):
        item["remaining_gap"] = extract_remaining_gap(body)
    status = str(item.get("status") or "")
    blockers = extract_blockers(body)
    item["commercial_grade_ready"] = status == "Done" and not blockers and not item.get("remaining_gap")
    item["commercial_blockers"] = blockers or fallback_blockers(status, int(item.get("number", 0)))
    item["release_gate"] = release_gate_for_item(item)
    item["maturity_gates"] = build_maturity_gates(item)
    item["highest_maturity_stage"] = highest_maturity_stage(item["maturity_gates"])
    item["next_required_gate"] = next_required_gate(item["maturity_gates"])


def build_maturity_gates(item: dict[str, object]) -> dict[str, dict[str, object]]:
    body = str(item.get("body") or "")
    status = str(item.get("status") or "")
    remaining_gap = str(item.get("remaining_gap") or "")
    blockers = list(item.get("commercial_blockers") or [])
    commercial_ready = bool(item.get("commercial_grade_ready"))

    implemented_passed = status_indicates_implementation(status) or (
        status_can_use_current_evidence(status) and has_current_evidence(body)
    )
    usable_passed = implemented_passed and status_indicates_usability(status, body)
    validated_passed = commercial_ready or has_validation_evidence_without_open_validation_gap(body, remaining_gap, blockers)
    commercial_passed = commercial_ready

    return {
        "implemented": maturity_gate(
            implemented_passed,
            "implementation evidence present in backlog status/body" if implemented_passed else "no implementation evidence",
            "" if implemented_passed else "Add code or verified workflow evidence for this item.",
        ),
        "usable": maturity_gate(
            usable_passed,
            "analyst-facing workflow is documented or exposed" if usable_passed else "analyst-facing workflow not proven",
            "" if usable_passed else "Expose the feature through CLI/API/UI/docs and add smoke coverage.",
        ),
        "validated": maturity_gate(
            validated_passed,
            "validation evidence is sufficient for the current claim" if validated_passed else "validation evidence is incomplete",
            "" if validated_passed else validation_remaining_text(remaining_gap, blockers),
        ),
        "commercial_grade": maturity_gate(
            commercial_passed,
            "no commercial parity blockers remain" if commercial_passed else "commercial parity blockers remain",
            "" if commercial_passed else commercial_remaining_text(item),
        ),
    }


def maturity_gate(passed: bool, evidence: str, remaining: str) -> dict[str, object]:
    return {
        "passed": passed,
        "evidence": evidence,
        "remaining": remaining,
    }


def status_indicates_implementation(status: str) -> bool:
    return status.startswith("Done") or status.startswith("Partial")


def status_can_use_current_evidence(status: str) -> bool:
    return not (status.startswith("Planned") or status.startswith("External"))


def has_current_evidence(body: str) -> bool:
    lowered = body.lower()
    return "current:" in lowered or "current rows" in lowered or "current output" in lowered


def status_indicates_usability(status: str, body: str) -> bool:
    lowered = body.lower()
    if status.startswith("Planned") or status == "External":
        return False
    usable_markers = (
        "cli",
        "api",
        "ui",
        "web",
        "collector",
        "rows",
        "output",
        "imports",
        "emits",
        "records",
        "report",
        "package",
        "workflow",
        "current:",
    )
    return any(marker in lowered for marker in usable_markers)


def has_validation_evidence_without_open_validation_gap(
    body: str,
    remaining_gap: str,
    blockers: list[object],
) -> bool:
    lowered_body = body.lower()
    lowered_gap = remaining_gap.lower()
    blocker_text = " ".join(str(item).lower() for item in blockers)
    validation_markers = (
        "known-answer",
        "fixture-backed",
        "fixture",
        "validation package",
        "cross-tool",
        "independent validation",
        "smoke test",
        "release gate",
    )
    open_validation_terms = (
        "remaining",
        "validation required",
        "known-answer",
        "corpus",
        "broad",
        "independent",
        "external",
        "commercial gap",
    )
    has_marker = any(marker in lowered_body for marker in validation_markers)
    open_gap = any(term in lowered_gap for term in open_validation_terms) or "validation" in blocker_text
    return has_marker and not open_gap


def validation_remaining_text(remaining_gap: str, blockers: list[object]) -> str:
    if remaining_gap:
        return remaining_gap
    if blockers:
        return "Resolve validation blockers: " + ", ".join(str(item) for item in blockers)
    return "Attach fixture, known-answer, cross-tool, or independent validation evidence."


def commercial_remaining_text(item: dict[str, object]) -> str:
    gap = str(item.get("remaining_gap") or "").strip()
    if gap:
        return gap
    blockers = list(item.get("commercial_blockers") or [])
    if blockers:
        return "Resolve commercial blockers: " + ", ".join(str(item) for item in blockers)
    return str(item.get("release_gate") or "Commercial parity evidence is incomplete.")


def highest_maturity_stage(gates: object) -> str:
    if not isinstance(gates, dict):
        return "none"
    highest = "none"
    for gate_name in MATURITY_GATE_ORDER:
        gate = gates.get(gate_name)
        if isinstance(gate, dict) and gate.get("passed"):
            highest = gate_name
        else:
            break
    return highest


def next_required_gate(gates: object) -> str:
    if not isinstance(gates, dict):
        return MATURITY_GATE_ORDER[0]
    for gate_name in MATURITY_GATE_ORDER:
        gate = gates.get(gate_name)
        if not (isinstance(gate, dict) and gate.get("passed")):
            return gate_name
    return ""


def build_maturity_gate_summary(items: Iterable[dict[str, object]]) -> dict[str, object]:
    item_list = list(items)
    gate_counts = {
        gate_name: {
            "passed": sum(
                1
                for item in item_list
                if isinstance(item.get("maturity_gates"), dict)
                and isinstance(item["maturity_gates"].get(gate_name), dict)
                and item["maturity_gates"][gate_name].get("passed")
            ),
            "failed": 0,
        }
        for gate_name in MATURITY_GATE_ORDER
    }
    for gate_name, counts in gate_counts.items():
        counts["failed"] = len(item_list) - int(counts["passed"])

    next_gate_counts: dict[str, int] = {}
    for item in item_list:
        gate_name = str(item.get("next_required_gate") or "complete")
        next_gate_counts[gate_name] = next_gate_counts.get(gate_name, 0) + 1

    maturity_stage_counts: dict[str, int] = {}
    for item in item_list:
        stage_name = str(item.get("highest_maturity_stage") or "none")
        maturity_stage_counts[stage_name] = maturity_stage_counts.get(stage_name, 0) + 1

    next_gate_samples: dict[str, list[dict[str, object]]] = {}
    for gate_name in MATURITY_GATE_ORDER:
        gate_items = [item for item in item_list if item.get("next_required_gate") == gate_name]
        next_gate_samples[gate_name] = [
            {
                "number": item.get("number"),
                "title": item.get("title"),
                "category": item.get("category"),
                "severity": item.get("severity"),
                "remaining": gate_remaining_text(item, gate_name),
            }
            for item in sorted(gate_items, key=priority_sort_key)[:10]
        ]

    return {
        "item_count": len(item_list),
        "gate_counts": gate_counts,
        "next_gate_counts": next_gate_counts,
        "next_gate_samples": next_gate_samples,
        "next_gate_blocker_counts": build_next_gate_blocker_counts(item_list),
        "highest_maturity_stage_counts": maturity_stage_counts,
        "commercial_grade_count": gate_counts["commercial_grade"]["passed"],
        "commercial_grade_missing_count": gate_counts["commercial_grade"]["failed"],
        "rule": "implemented -> usable -> validated -> commercial_grade; do not claim a higher gate until every earlier gate passes.",
    }


def build_priority_work_plan(items: Iterable[dict[str, object]], *, limit: int = 25) -> list[dict[str, object]]:
    actionable = [item for item in items if item.get("next_required_gate")]
    plan: list[dict[str, object]] = []
    for item in sorted(actionable, key=priority_sort_key)[:limit]:
        next_gate = str(item.get("next_required_gate") or "")
        plan.append(
            {
                "number": item.get("number"),
                "title": item.get("title"),
                "category": item.get("category"),
                "severity": item.get("severity"),
                "current_stage": item.get("highest_maturity_stage") or "none",
                "next_gate": next_gate,
                "required_action": gate_remaining_text(item, next_gate),
                "release_gate": item.get("release_gate"),
            }
        )
    return plan


def priority_sort_key(item: dict[str, object]) -> tuple[int, int, int, int]:
    next_gate = str(item.get("next_required_gate") or "complete")
    gate_priority = MATURITY_GATE_ORDER.index(next_gate) if next_gate in MATURITY_GATE_ORDER else len(MATURITY_GATE_ORDER)
    severity_priority = SEVERITY_PRIORITY.get(str(item.get("severity") or "low"), 9)
    category_priority = CATEGORY_PRIORITY.get(str(item.get("category") or "unknown"), 9)
    return (gate_priority, severity_priority, category_priority, int(item.get("number") or 0))


def gate_remaining_text(item: dict[str, object], gate_name: str) -> str:
    gates = item.get("maturity_gates")
    if isinstance(gates, dict):
        gate = gates.get(gate_name)
        if isinstance(gate, dict):
            remaining = str(gate.get("remaining") or "").strip()
            if remaining:
                return remaining
    return str(item.get("remaining_gap") or item.get("release_gate") or "No remaining action recorded.")


def build_next_gate_blocker_counts(items: Iterable[dict[str, object]]) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = {gate_name: {} for gate_name in MATURITY_GATE_ORDER}
    for item in items:
        gate_name = str(item.get("next_required_gate") or "")
        if gate_name not in counts:
            continue
        blocker_ids = list(item.get("commercial_blockers") or [])
        if not blocker_ids:
            blocker_ids = [gate_remaining_text(item, gate_name)]
        for blocker in blocker_ids:
            blocker_key = normalize_blocker_key(str(blocker))
            counts[gate_name][blocker_key] = counts[gate_name].get(blocker_key, 0) + 1
    return counts


def normalize_blocker_key(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9가-힣]+", "-", value.strip().lower()).strip("-")
    return normalized[:96] or "unspecified"


def normalize_status(value: str) -> str:
    return " ".join(value.strip().split())


def extract_remaining_gap(body: str) -> str:
    markers = [
        "Remaining commercial gap:",
        "Remaining:",
        "Blockers:",
    ]
    for marker in markers:
        index = body.find(marker)
        if index >= 0:
            return body[index + len(marker) :].strip()
    return ""


def extract_blockers(body: str) -> list[str]:
    lowered = body.lower()
    blockers: list[str] = []
    keyword_map = {
        "commercial_grade_ready=false": "explicit-commercial-grade-ready-false",
        "remaining commercial gap": "remaining-commercial-gap",
        "external": "external-validation-or-infrastructure-required",
        "validation": "known-answer-or-independent-validation-required",
        "not implemented": "implementation-missing",
        "not-enabled": "feature-not-enabled",
        "planned": "planned-work-remaining",
        "native": "native-parser-depth-required",
        "signing": "platform-signing-required",
        "notarization": "platform-notarization-required",
    }
    for keyword, blocker in keyword_map.items():
        if keyword in lowered and blocker not in blockers:
            blockers.append(blocker)
    return blockers


def fallback_blockers(status: str, number: int) -> list[str]:
    if status.startswith("External"):
        return ["external-operator-evidence-required"]
    if status.startswith("Planned"):
        return ["implementation-not-enabled"]
    if status.startswith("Partial"):
        return ["partial-implementation-requires-validation"]
    if number:
        return ["commercial-readiness-not-proven"]
    return []


def category_for_number(number: int) -> str:
    if 1 <= number <= 25:
        return "core-forensics"
    if 26 <= number <= 45:
        return "mobile-cloud-apps"
    if 46 <= number <= 65:
        return "search-analysis-ux"
    if 66 <= number <= 80:
        return "performance-large-scale"
    if 81 <= number <= 100:
        return "validation-legal"
    if 101 <= number <= 120:
        return "deployment-operations"
    return "unknown"


def severity_for_number(number: int) -> str:
    if 1 <= number <= 25:
        return "critical"
    if 26 <= number <= 45:
        return "high"
    if 81 <= number <= 100:
        return "high"
    if 66 <= number <= 80 or 101 <= number <= 120:
        return "medium"
    if 46 <= number <= 65:
        return "medium"
    return "low"


def release_gate_for_item(item: dict[str, object]) -> str:
    number = int(item.get("number", 0))
    if item.get("commercial_grade_ready"):
        return "claim-allowed"
    if 1 <= number <= 45:
        return "must label as validation-required before report testimony"
    if 81 <= number <= 100:
        return "must attach legal/known-answer validation evidence"
    if 101 <= number <= 120:
        return "must attach platform/operations evidence before commercial distribution"
    return "must disclose partial implementation and UX/performance limits"


def calculate_readiness_score(items: Iterable[dict[str, object]]) -> int:
    total_weight = 0
    earned = 0.0
    status_points = {
        "Done": 1.0,
        "Partial++": 0.88,
        "Partial+": 0.65,
        "Partial": 0.45,
        "External+": 0.35,
        "Planned+": 0.25,
        "External": 0.2,
        "Planned": 0.1,
    }
    severity_weight = {"critical": 3, "high": 2, "medium": 1, "low": 1}
    for item in items:
        weight = severity_weight.get(str(item.get("severity")), 1)
        total_weight += weight
        status = str(item.get("status"))
        base_status = status.split(" with ", 1)[0]
        earned += weight * status_points.get(status, status_points.get(base_status, 0.3))
    if total_weight == 0:
        return 0
    return int(round((earned / total_weight) * 100))


def build_required_release_evidence(non_commercial: list[dict[str, object]]) -> list[dict[str, object]]:
    categories = {str(item["category"]) for item in non_commercial}
    evidence: list[dict[str, object]] = []
    if "core-forensics" in categories:
        evidence.append(
            {
                "id": "core-parser-known-answer-corpus",
                "required_for": "EVTX/Registry/SAM/MFT/USN/SRUM/EDB/native Windows artifact claims",
                "evidence": "known-answer corpus, external parser comparison, source hashes, offset-level diffs, reviewer sign-off",
            }
        )
    if "mobile-cloud-apps" in categories:
        evidence.append(
            {
                "id": "mobile-cloud-schema-validation",
                "required_for": "mobile app, cloud export, mailbox, and messenger claims",
                "evidence": "authorized export samples, app/provider schema versions, deleted/encrypted-store limitations, validation matrix",
            }
        )
    if "performance-large-scale" in categories:
        evidence.append(
            {
                "id": "large-case-stress-results",
                "required_for": "1TB-10TB and million-record usability claims",
                "evidence": "hardware profile, run logs, peak memory, p95 latency, failure thresholds, reproducibility notes",
            }
        )
    if "validation-legal" in categories:
        evidence.append(
            {
                "id": "legal-validation-package",
                "required_for": "court/report-grade evidence handling claims",
                "evidence": "NIST-style known-answer results, chain-of-custody records, audit hash chain, independent validation report",
            }
        )
    if "deployment-operations" in categories:
        evidence.append(
            {
                "id": "commercial-release-operations",
                "required_for": "commercial distribution and support claims",
                "evidence": "signed installers, notarization, CI scans, support SLA, staffed escalation, admin deployment proof",
            }
        )
    return evidence


def build_operator_guidance(non_commercial: list[dict[str, object]]) -> list[str]:
    if not non_commercial:
        return ["Commercial parity gates are satisfied for every tracked backlog item."]
    return [
        "Use RapidTriage as a triage/review accelerator, not as a sole AXIOM/WISDOM replacement.",
        "Any item marked non-commercial must keep validation_required/reportability warnings in artifacts and reports.",
        "For testimony-grade conclusions, attach trusted-tool comparison output and known-answer validation evidence.",
        "Do not advertise signed installer, notarized package, multi-user server, or support SLA until external evidence exists.",
    ]


def build_commercial_uplift_plan(
    items: Iterable[dict[str, object]],
    *,
    readiness_score: int,
    target_count: int = COMMERCIAL_UPLIFT_DEFAULT_TARGET_COUNT,
    batch_size: int = COMMERCIAL_UPLIFT_DEFAULT_BATCH_SIZE,
) -> dict[str, object]:
    """Build a repeatable, prioritized plan for moving strict blockers forward."""

    item_list = list(items)
    safe_target_count = max(0, target_count)
    safe_batch_size = max(1, batch_size)
    candidates = [
        item for item in sorted(item_list, key=priority_sort_key)
        if item.get("next_required_gate")
    ][:safe_target_count]
    goals = [
        build_commercial_uplift_goal(item, priority_rank=index + 1, batch_size=safe_batch_size)
        for index, item in enumerate(candidates)
    ]
    batches: list[dict[str, object]] = []
    for index in range(0, len(goals), safe_batch_size):
        batch_goals = goals[index : index + safe_batch_size]
        batch_numbers = [goal["number"] for goal in batch_goals]
        batches.append(
            {
                "batch_number": len(batches) + 1,
                "item_numbers": batch_numbers,
                "item_count": len(batch_goals),
                "primary_categories": sorted({str(goal["category"]) for goal in batch_goals}),
                "required_outputs": [
                    "code_or_workflow_change",
                    "unit_or_fixture_test",
                    "known_answer_or_cross_tool_artifact",
                    "documentation_update",
                    "commercial_readiness_recalculation",
                    "git_commit",
                ],
                "goals": batch_goals,
            }
        )

    category_counts: dict[str, int] = {}
    for goal in goals:
        category = str(goal["category"])
        category_counts[category] = category_counts.get(category, 0) + 1

    return {
        "version": "commercial-uplift-plan-v1",
        "status": "active" if goals else "complete",
        "current_readiness_score": readiness_score,
        "target_goal_count": safe_target_count,
        "selected_goal_count": len(goals),
        "batch_size": safe_batch_size,
        "batch_count": len(batches),
        "category_counts": category_counts,
        "score_strategy": [
            "Do not raise commercial-grade gates by wording alone.",
            "Prioritize critical parser depth, then validation/legal, then performance and UX bottlenecks.",
            "Attach real corpus, cross-tool diff, benchmark, or operator evidence before claiming commercial parity.",
            "Use five-item batches so every uplift produces code, tests, docs, validation evidence, and a commit.",
        ],
        "large_data_strategy": build_large_data_strategy(),
        "goals": goals,
        "batches": batches,
    }


def build_commercial_uplift_goal(
    item: dict[str, object],
    *,
    priority_rank: int,
    batch_size: int,
) -> dict[str, object]:
    number = int(item.get("number") or 0)
    category = str(item.get("category") or "unknown")
    blockers = [str(blocker) for blocker in item.get("commercial_blockers") or []]
    remaining = gate_remaining_text(item, str(item.get("next_required_gate") or "commercial_grade"))
    return {
        "priority_rank": priority_rank,
        "batch_number": ((priority_rank - 1) // max(1, batch_size)) + 1,
        "number": number,
        "title": str(item.get("title") or ""),
        "category": category,
        "severity": str(item.get("severity") or ""),
        "current_status": str(item.get("status") or ""),
        "current_stage": str(item.get("highest_maturity_stage") or "none"),
        "next_gate": str(item.get("next_required_gate") or ""),
        "objective": uplift_objective_for_item(number, category),
        "implementation_track": uplift_track_for_item(number, category),
        "acceptance_evidence": uplift_acceptance_evidence_for_item(number, category),
        "large_data_strategy": large_data_strategy_for_item(number, category),
        "remaining_gap": remaining,
        "commercial_blockers": blockers,
        "external_evidence_required": external_evidence_required(blockers, remaining),
        "internal_next_step": internal_next_step_for_item(number, category, remaining),
    }


def uplift_objective_for_item(number: int, category: str) -> str:
    if 1 <= number <= 25:
        return "Promote the artifact from validation-required candidate output to report-grade native parsing with source offsets, hashes, confidence, and trusted-tool diff evidence."
    if 26 <= number <= 45:
        return "Turn mobile, messenger, email, or cloud handling into a versioned import/acquisition workflow with redaction, schema tracking, and legal authority gates."
    if 46 <= number <= 65:
        return "Reduce analyst review friction with scalable search, viewer, comparison, citation, and review-state workflows that preserve provenance."
    if 66 <= number <= 80:
        return "Prove large-case behavior through bounded memory, resumable jobs, cursor APIs, deterministic scheduling, and benchmark evidence."
    if 81 <= number <= 100:
        return "Harden court defensibility with known-answer validation, audit chains, provenance completeness, legal warnings, and reproducible exhibit bundles."
    if 101 <= number <= 120:
        return "Produce operator-verifiable release, security, deployment, support, and monitoring evidence without overstating unavailable external services."
    return f"Close the remaining {category} commercial-readiness blocker with measurable implementation and validation evidence."


def uplift_track_for_item(number: int, category: str) -> str:
    if 1 <= number <= 25:
        return "native-parser-depth"
    if 26 <= number <= 45:
        return "schema-import-and-authority-gates"
    if 46 <= number <= 65:
        return "analyst-ux-and-review"
    if 66 <= number <= 80:
        return "large-scale-performance"
    if 81 <= number <= 100:
        return "legal-validation"
    if 101 <= number <= 120:
        return "release-operations"
    return category


def uplift_acceptance_evidence_for_item(number: int, category: str) -> list[str]:
    common = [
        "updated production code or operator workflow",
        "unit/fixture test covering success and limitation behavior",
        "documentation of user-facing behavior and remaining limits",
        "commercial-readiness output showing the next blocker has changed or narrowed",
    ]
    if 1 <= number <= 25:
        return [
            "record/row-level output with source offsets and hashes",
            "trusted-tool or known-answer diff artifact",
            "malformed/deleted/large fixture coverage where relevant",
            *common,
        ]
    if 26 <= number <= 45:
        return [
            "versioned schema matrix or provider export contract",
            "secret/value redaction and authority-gate evidence",
            "sample import fixture with expected rows",
            *common,
        ]
    if 46 <= number <= 65:
        return [
            "cursor-paged API or virtualized UI evidence",
            "review/citation state persisted in Case DB or export",
            "viewer/search smoke test for large result sets",
            *common,
        ]
    if 66 <= number <= 80:
        return [
            "benchmark or stress-plan JSON with hardware/resource assumptions",
            "checkpoint/resume/cancel or bounded-memory evidence",
            "deterministic output and retry behavior test",
            *common,
        ]
    if 81 <= number <= 100:
        return [
            "known-answer, audit, hash-chain, or provenance package evidence",
            "report/export artifact with limitation text",
            "reproducibility or tamper-evidence test",
            *common,
        ]
    return [
        "release/deployment/security evidence artifact",
        "operator smoke or policy check",
        "explicit blocker for external signing, notarization, support, or CI where applicable",
        *common,
    ]


def large_data_strategy_for_item(number: int, category: str) -> str:
    if number in {10, 11, 12, 13, 22, 23, 24}:
        return "Use streaming or mmap-friendly parsing, cursor checkpoints, bounded page/record batches, and never require whole-image or whole-database memory residency."
    if 1 <= number <= 25:
        return "Emit bounded row batches with stable offsets, parser confidence, and per-file checkpoint metadata so corrupt artifacts cannot block the case."
    if 26 <= number <= 45:
        return "Import provider exports in batches, keep raw payloads external or hashed, and maintain schema-version cursors for very large chat/mail/cloud datasets."
    if 46 <= number <= 65:
        return "Route every large table, timeline, graph, and gallery through cursor APIs, server-side filters, dedupe suppression, and virtualized viewers."
    if 66 <= number <= 80:
        return "Measure throughput, peak memory, p95 latency, retry behavior, and checkpoint reuse across 100k/1M/10M-row scenarios before raising claims."
    if 81 <= number <= 100:
        return "Keep validation and report bundles manifest-based with hashes instead of copying large evidence blobs unless explicitly selected."
    if 101 <= number <= 120:
        return "Package and verify release artifacts without embedding evidence data; smoke tests should use small known-answer cases and recorded large-case logs."
    return "Keep processing incremental, bounded, checkpointed, and evidence-hash referenced."


def internal_next_step_for_item(number: int, category: str, remaining: str) -> str:
    if external_evidence_required([], remaining) and 101 <= number <= 120:
        return "Record the external blocker, add an operator evidence slot, and implement the strongest local smoke/policy check available."
    if 1 <= number <= 25:
        return "Add one deeper native parser assertion, a fixture or cross-tool comparator hook, and a reportability warning test."
    if 26 <= number <= 45:
        return "Add a versioned schema/import fixture plus redaction and legal-authority checks."
    if 46 <= number <= 65:
        return "Add a user-facing search/view/review workflow improvement with persisted state and pagination coverage."
    if 66 <= number <= 80:
        return "Add benchmark/checkpoint/resource evidence and enforce bounded processing in the relevant path."
    if 81 <= number <= 100:
        return "Add validation-package, audit, provenance, or report evidence that can be independently reviewed."
    return "Add release-operation evidence and keep external commercial blockers explicit."


def external_evidence_required(blockers: list[str], remaining: str) -> bool:
    text = " ".join([*blockers, remaining]).lower()
    markers = (
        "external",
        "independent",
        "signing",
        "notarization",
        "staffed",
        "hosted",
        "hardware",
        "10tb",
        "third-party",
        "contractual",
    )
    return any(marker in text for marker in markers)


def build_large_data_strategy() -> dict[str, object]:
    return {
        "rule": "Large evidence must be streamed, checkpointed, cursor-paged, and hash-referenced; UI and reports must never require loading all rows.",
        "parser_runtime": "Keep Python as orchestration/API/UI glue; move hot EVTX/Registry/ESE/MFT/USN/hash/OCR workers toward Rust or isolated native subprocesses.",
        "storage": "Use SQLite/PostgreSQL for case metadata, FTS/Tantivy-style indexes for search, and Parquet/DuckDB-style sidecars for large analytical outputs when needed.",
        "api": "Every massive table/search/timeline endpoint should expose cursor tokens, limits, total estimates, and snapshot warnings.",
        "ui": "Use virtualized result tables, lazy previews, dedupe collapse, and explicit loading/progress states.",
        "proof": "Publish benchmark JSON with hardware profile, evidence size, record count, wall time, peak memory, p95 latency, failures, and resume behavior.",
    }


def render_commercial_readiness_markdown(payload: dict[str, object]) -> str:
    lines = [
        "# RapidTriage Commercial Readiness Gate",
        "",
        f"- Generated at: `{payload.get('generated_at', '')}`",
        f"- Backlog: `{payload.get('backlog_path', '')}`",
        f"- Status: `{payload.get('status', '')}`",
        f"- Commercial claim allowed: `{payload.get('commercial_claim_allowed', False)}`",
        f"- Readiness score: `{payload.get('readiness_score', 0)}/100`",
        f"- Non-commercial items: `{payload.get('non_commercial_count', 0)}`/`{payload.get('item_count', 0)}`",
        f"- Release claim: {payload.get('release_claim', '')}",
        "",
        "## Maturity Gate Summary",
        "",
    ]
    maturity_summary = payload.get("maturity_gate_summary") if isinstance(payload.get("maturity_gate_summary"), dict) else {}
    gate_counts = maturity_summary.get("gate_counts") if isinstance(maturity_summary.get("gate_counts"), dict) else {}
    for gate_name in MATURITY_GATE_ORDER:
        counts = gate_counts.get(gate_name) if isinstance(gate_counts.get(gate_name), dict) else {}
        lines.append(
            f"- `{gate_name}`: `{counts.get('passed', 0)}` passed, `{counts.get('failed', 0)}` remaining"
        )
    validation_summary = (
        payload.get("validation_evidence_summary")
        if isinstance(payload.get("validation_evidence_summary"), dict)
        else {}
    )
    if validation_summary.get("validation_package_attached"):
        mapped = ", ".join(f"#{number}" for number in validation_summary.get("mapped_item_numbers", []))
        lines.extend(
            [
                "",
                "## Attached Validation Evidence",
                "",
                f"- Items with passed evidence: `{validation_summary.get('items_with_passed_validation_evidence', 0)}`",
                f"- Mapped items: {mapped or '`none`'}",
                f"- Rule: {validation_summary.get('rule', '')}",
            ]
        )
    lines.extend(["", "## Priority Work Plan", ""])
    for item in payload.get("priority_work_plan", []):
        if not isinstance(item, dict):
            continue
        action = str(item.get("required_action") or "").strip()
        if len(action) > 220:
            action = action[:217].rstrip() + "..."
        lines.append(
            f"- `#{item.get('number')}` {item.get('title', '')} "
            f"({item.get('category', '')}, {item.get('severity', '')}, next `{item.get('next_gate', '')}`): {action}"
        )
    uplift_plan = payload.get("commercial_uplift_plan") if isinstance(payload.get("commercial_uplift_plan"), dict) else {}
    if uplift_plan:
        lines.extend(
            [
                "",
                "## 70-Goal Commercial Uplift Plan",
                "",
                f"- Status: `{uplift_plan.get('status', '')}`",
                f"- Selected goals: `{uplift_plan.get('selected_goal_count', 0)}`/`{uplift_plan.get('target_goal_count', 0)}`",
                f"- Batch size: `{uplift_plan.get('batch_size', 0)}`",
                f"- Batch count: `{uplift_plan.get('batch_count', 0)}`",
                f"- Current readiness score: `{uplift_plan.get('current_readiness_score', 0)}/100`",
                "",
                "### Large Data Strategy",
                "",
            ]
        )
        large_strategy = uplift_plan.get("large_data_strategy")
        if isinstance(large_strategy, dict):
            for key, value in large_strategy.items():
                lines.append(f"- `{key}`: {value}")
        lines.extend(["", "### Five-Item Batches", ""])
        for batch in uplift_plan.get("batches", []):
            if not isinstance(batch, dict):
                continue
            item_numbers = ", ".join(f"#{number}" for number in batch.get("item_numbers", []))
            categories = ", ".join(str(item) for item in batch.get("primary_categories", []))
            lines.append(
                f"- Batch `{batch.get('batch_number')}` ({item_numbers}) categories `{categories}`: "
                f"{batch.get('item_count', 0)} goals"
            )
        lines.extend(["", "### First Goals", ""])
        for goal in uplift_plan.get("goals", [])[:20]:
            if not isinstance(goal, dict):
                continue
            remaining = str(goal.get("remaining_gap") or "")
            if len(remaining) > 160:
                remaining = remaining[:157].rstrip() + "..."
            lines.append(
                f"- Rank `{goal.get('priority_rank')}` batch `{goal.get('batch_number')}` "
                f"`#{goal.get('number')}` {goal.get('title', '')}: {goal.get('objective', '')} "
                f"Remaining: {remaining}"
            )
    lines.extend([
        "",
        "## Required Release Evidence",
        "",
    ])
    for item in payload.get("required_release_evidence", []):
        if isinstance(item, dict):
            lines.append(f"- `{item.get('id', '')}`: {item.get('evidence', '')}")
    lines.extend(["", "## Critical And High Non-Commercial Items", ""])
    for item in payload.get("critical_non_commercial_items", []):
        if not isinstance(item, dict):
            continue
        lines.append(
            f"- `#{item.get('number')}` {item.get('title', '')} "
            f"({item.get('status', '')}, {item.get('severity', '')}): {item.get('release_gate', '')}"
        )
    lines.extend(["", "## All Non-Commercial Items", ""])
    for item in payload.get("non_commercial_items", []):
        if not isinstance(item, dict):
            continue
        gap = str(item.get("remaining_gap") or "").strip()
        if len(gap) > 220:
            gap = gap[:217].rstrip() + "..."
        highest_stage = str(item.get("highest_maturity_stage") or "none")
        next_gate = str(item.get("next_required_gate") or "")
        lines.append(
            f"- `#{item.get('number')}` {item.get('title', '')} "
            f"({item.get('status', '')}, {item.get('category', '')}, highest `{highest_stage}`, next `{next_gate}`): "
            f"{gap or item.get('release_gate', '')}"
        )
    lines.extend(["", "## Operator Guidance", ""])
    for item in payload.get("operator_guidance", []):
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines)
