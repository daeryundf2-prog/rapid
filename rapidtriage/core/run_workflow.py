from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


RUN_WORKFLOW_PROFILE_VERSION = "run-workflow-contract-v1"
RUN_WORKFLOW_STAGE_ORDER = ("ingest", "extract", "parse", "index", "review", "report")


@dataclass(frozen=True)
class RunWorkflowStageDefinition:
    id: str
    label: str
    title: str
    primary_tab: str
    next_action: str
    large_case_note: str


RUN_WORKFLOW_STAGE_DEFINITIONS: Mapping[str, RunWorkflowStageDefinition] = {
    "ingest": RunWorkflowStageDefinition(
        id="ingest",
        label="1. Ingest",
        title="Select evidence and prepare a read-only analysis root",
        primary_tab="summary",
        next_action="Verify source type, hash/provenance, dependencies, and selected analysis root.",
        large_case_note="Image metadata and source fingerprints must be emitted before downstream parsing.",
    ),
    "extract": RunWorkflowStageDefinition(
        id="extract",
        label="2. Extract",
        title="Copy review candidates with bounded size and hash manifests",
        primary_tab="files",
        next_action="Open extraction manifests and confirm skipped/capped files before relying on absence.",
        large_case_note="Extraction is bounded by max file count/size and stays resumable for large evidence.",
    ),
    "parse": RunWorkflowStageDefinition(
        id="parse",
        label="3. Parse",
        title="Run artifact collectors and normalize files, documents, and parsed evidence",
        primary_tab="artifacts",
        next_action="Check zero-row parsers, parser warnings, and artifact rows before search/review.",
        large_case_note="Artifact collectors are isolated per parser so one crash does not hide the rest.",
    ),
    "index": RunWorkflowStageDefinition(
        id="index",
        label="4. Index",
        title="Build searchable documents, timeline, indicators, and FTS-ready outputs",
        primary_tab="search",
        next_action="Run keyword searches and pivot from each hit into the source viewer.",
        large_case_note="Index outputs use cursor/search views rather than loading whole cases into the GUI.",
    ),
    "review": RunWorkflowStageDefinition(
        id="review",
        label="5. Review",
        title="Surface validation warnings, silent-failure risks, and source-viewer handoffs",
        primary_tab="review",
        next_action="Mark relevant/needs-review/excluded and attach notes only after source verification.",
        large_case_note="Review state must stay separate from parser output so large result sets remain immutable.",
    ),
    "report": RunWorkflowStageDefinition(
        id="report",
        label="6. Report",
        title="Generate report and exhibit-ready references with provenance",
        primary_tab="report",
        next_action="Export only reviewed evidence with source hashes, parser version, and limitations.",
        large_case_note="Report bundles reference source rows instead of duplicating all evidence into memory.",
    ),
}


STEP_STAGE_MAP: Mapping[str, str] = {
    "docs-extract": "extract",
    "files-extract": "extract",
    "manifest": "parse",
    "docs": "parse",
    "files": "parse",
    "docs-index": "index",
    "timeline": "index",
    "indicators": "index",
    "silent-failure-detection": "review",
}


OUTPUT_STAGE_MAP: Mapping[str, str] = {
    "e01": "ingest",
    "disk_image": "ingest",
    "archive_image": "ingest",
    "virtual_disk": "ingest",
    "fingerprint": "ingest",
    "checkpoints": "ingest",
    "docs_extract_manifest": "extract",
    "files_extract_manifest": "extract",
    "manifest": "parse",
    "docs": "parse",
    "files": "parse",
    "parser_scheduler": "parse",
    "parser_crash_isolation": "review",
    "memory_cap_enforcement": "review",
    "preview_sandbox_policy": "review",
    "docs_index": "index",
    "timeline": "index",
    "timeline_report": "report",
    "indicators": "index",
    "sqlite_fts_optimization": "index",
    "summary": "report",
    "report": "report",
}


def stage_for_step_name(name: str) -> str | None:
    if name.startswith("artifacts-"):
        return "parse"
    return STEP_STAGE_MAP.get(name)


def stage_for_output_name(name: str) -> str | None:
    if name.startswith("artifacts_"):
        return "parse"
    return OUTPUT_STAGE_MAP.get(name)


def build_run_workflow_contract(
    *,
    steps: Sequence[Mapping[str, object]],
    outputs: Mapping[str, Path],
    safety: Mapping[str, object],
    source: Mapping[str, object] | None = None,
) -> dict[str, object]:
    source = source or {}
    stage_steps: dict[str, list[Mapping[str, object]]] = {stage_id: [] for stage_id in RUN_WORKFLOW_STAGE_ORDER}
    stage_outputs: dict[str, list[str]] = {stage_id: [] for stage_id in RUN_WORKFLOW_STAGE_ORDER}

    for step in steps:
        stage_id = stage_for_step_name(str(step.get("name", "")))
        if stage_id:
            stage_steps[stage_id].append(step)

    for output_name in outputs:
        stage_id = stage_for_output_name(str(output_name))
        if stage_id:
            stage_outputs[stage_id].append(str(output_name))

    stages = [
        build_run_workflow_stage(
            definition=RUN_WORKFLOW_STAGE_DEFINITIONS[stage_id],
            steps=stage_steps[stage_id],
            output_keys=sorted(stage_outputs[stage_id]),
            safety=safety,
            source=source,
        )
        for stage_id in RUN_WORKFLOW_STAGE_ORDER
    ]
    status_counts = {
        status: sum(1 for stage in stages if stage["status"] == status)
        for status in ("completed", "warning", "blocked", "pending")
    }
    warning_stage_count = sum(1 for stage in stages if int(stage.get("warning_count", 0)) > 0)
    stage_hash = hashlib.sha256(
        json.dumps(
            [
                {
                    "id": stage["id"],
                    "status": stage["status"],
                    "step_names": stage["step_names"],
                    "output_keys": stage["output_keys"],
                    "warning_count": stage["warning_count"],
                }
                for stage in stages
            ],
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    return {
        "profile_version": RUN_WORKFLOW_PROFILE_VERSION,
        "stage_order": list(RUN_WORKFLOW_STAGE_ORDER),
        "stage_count": len(stages),
        "completed_stage_count": status_counts["completed"] + status_counts["warning"],
        "warning_stage_count": warning_stage_count,
        "blocked_stage_count": status_counts["blocked"],
        "pending_stage_count": status_counts["pending"],
        "gui_primary_flow": True,
        "source_type": str(source.get("type") or "directory"),
        "source_path": str(source.get("source_path") or source.get("analysis_root") or ""),
        "analysis_root": str(source.get("analysis_root") or ""),
        "read_only": bool(safety.get("read_only")),
        "resume": bool(safety.get("resume")),
        "stage_hash": stage_hash,
        "stage_lookup": {str(stage["id"]): str(stage["status"]) for stage in stages},
        "stages": stages,
    }


def build_run_workflow_stage(
    *,
    definition: RunWorkflowStageDefinition,
    steps: Sequence[Mapping[str, object]],
    output_keys: Sequence[str],
    safety: Mapping[str, object],
    source: Mapping[str, object],
) -> dict[str, object]:
    warning_messages: list[str] = []
    failed = False
    reused = False
    for step in steps:
        if bool(step.get("reused")):
            reused = True
        status = str(step.get("status") or "")
        warning_level = str(step.get("warning_level") or "none")
        if status.startswith("failed") or warning_level == "failed":
            failed = True
        messages = step.get("warning_messages")
        if isinstance(messages, list):
            warning_messages.extend(str(message) for message in messages if str(message))
        elif warning_level != "none":
            warning_messages.append(f"{step.get('name', 'step')} reported {warning_level}")

    has_evidence = bool(steps or output_keys)
    if definition.id == "ingest" and source:
        has_evidence = True
    status = "blocked" if failed else ("warning" if warning_messages else ("completed" if has_evidence else "pending"))

    if definition.id == "extract" and bool(safety.get("read_only")) and status == "warning":
        next_action = "Read-only mode intentionally skipped extraction; review manifests before reporting absence."
    elif definition.id == "ingest" and source.get("type") in {"e01", "raw-image", "virtual-disk", "archive-image"}:
        next_action = "Confirm image workflow provenance, selected partition/root, and downstream handoff outputs."
    else:
        next_action = definition.next_action

    return {
        "id": definition.id,
        "label": definition.label,
        "title": definition.title,
        "status": status,
        "ready": status in {"completed", "warning"},
        "step_names": [str(step.get("name", "")) for step in steps if step.get("name")],
        "output_keys": list(output_keys),
        "reused": reused,
        "warning_count": len(warning_messages),
        "warning_messages": warning_messages[:8],
        "gui": {
            "primary_tab": definition.primary_tab,
            "next_action": next_action,
            "large_case_note": definition.large_case_note,
        },
    }
