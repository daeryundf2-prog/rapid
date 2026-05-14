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


OUTPUT_HANDOFF_ROLES: Mapping[str, tuple[str, str, str, str]] = {
    "fingerprint": (
        "source fingerprint",
        "provenance-viewer",
        "Verify source hash and read-only input identity.",
        "Use as the first citation for source integrity.",
    ),
    "e01": (
        "image workflow evidence",
        "image-workflow-viewer",
        "Verify E01/Ex01 dependency, partition, extraction, and provenance rows.",
        "Report only with source segment/hash and selected partition evidence.",
    ),
    "disk_image": (
        "raw/split image workflow evidence",
        "image-workflow-viewer",
        "Verify split-set order, selected partition, extraction, and recovered root.",
        "Report only with split-set/hash and extraction provenance.",
    ),
    "archive_image": (
        "archive image extraction evidence",
        "image-workflow-viewer",
        "Verify mounted/exported archive image extraction details.",
        "Report with tool/version and extracted-root provenance.",
    ),
    "virtual_disk": (
        "virtual disk workflow evidence",
        "image-workflow-viewer",
        "Verify qemu/chain handling, conversion hash, and recovered root.",
        "Report with source and converted RAW hash provenance.",
    ),
    "checkpoints": (
        "checkpoint/resume state",
        "json-viewer",
        "Confirm which stages can resume without reprocessing evidence.",
        "Use to explain interrupted or resumed large-case processing.",
    ),
    "docs_extract_manifest": (
        "document extraction manifest",
        "manifest-viewer",
        "Review extracted/skipped/capped document candidates.",
        "Absence findings require checking skipped and capped rows.",
    ),
    "files_extract_manifest": (
        "file extraction manifest",
        "manifest-viewer",
        "Review extracted/skipped/capped file candidates.",
        "Absence findings require checking skipped and capped rows.",
    ),
    "manifest": (
        "run manifest",
        "json-viewer",
        "Review source scan inventory and parser inputs.",
        "Use as a high-level inventory citation, not proof of artifact semantics.",
    ),
    "docs": (
        "document text rows",
        "document-viewer",
        "Open matched document text and pivot into source preview.",
        "Report only after source viewer verification.",
    ),
    "files": (
        "file candidate rows",
        "file-table-viewer",
        "Review file metadata, hashes, signatures, and path evidence.",
        "Use source hash/path/timestamp fields for citations.",
    ),
    "parser_scheduler": (
        "parser scheduler manifest",
        "json-viewer",
        "Check parser ordering, quotas, and deterministic scheduling evidence.",
        "Use to explain large-case processing behavior.",
    ),
    "parser_crash_isolation": (
        "parser crash isolation evidence",
        "review-safety-viewer",
        "Confirm parser failures were isolated and downstream stages continued safely.",
        "Report parser gaps as limitations, not negative evidence.",
    ),
    "memory_cap_enforcement": (
        "memory cap evidence",
        "review-safety-viewer",
        "Confirm bounded-memory stage telemetry and cap warnings.",
        "Use to document large-case safety constraints.",
    ),
    "preview_sandbox_policy": (
        "preview sandbox policy",
        "review-safety-viewer",
        "Confirm active content blocking and preview safety controls.",
        "Use to document safe review handling of hostile evidence.",
    ),
    "docs_index": (
        "document search index",
        "search-viewer",
        "Run keyword search and verify hit counts/source handoffs.",
        "A keyword miss is reliable only after index scope and truncation checks.",
    ),
    "timeline": (
        "unified timeline rows",
        "timeline-viewer",
        "Review chronological pivots across files, artifacts, docs, and indicators.",
        "Use row source/provenance fields for timeline citations.",
    ),
    "indicators": (
        "indicator rows",
        "indicator-viewer",
        "Review IOC/domain/IP/hash findings and source locations.",
        "Report only with confidence and source location.",
    ),
    "sqlite_fts_optimization": (
        "FTS optimization manifest",
        "search-diagnostics-viewer",
        "Check FTS/cursor configuration and large-table search safety.",
        "Use to document search completeness limits.",
    ),
    "summary": (
        "run summary contract",
        "json-viewer",
        "Review workflow, warnings, outputs, and readiness fields.",
        "Use as the top-level machine-readable run record.",
    ),
    "report": (
        "analyst report",
        "report-viewer",
        "Open reviewed evidence and limitations for export.",
        "Report is only final after evidence tray/source citation review.",
    ),
    "timeline_report": (
        "timeline report",
        "timeline-report-viewer",
        "Open timeline-focused narrative for time-sequence review.",
        "Use alongside source timeline rows for court-ready citations.",
    ),
}


STAGE_CHECKLIST_DEFINITIONS: Mapping[str, tuple[tuple[str, str, str, tuple[str, ...]], ...]] = {
    "ingest": (
        (
            "source-provenance",
            "Confirm source path, analysis root, and read-only posture.",
            "critical",
            ("fingerprint", "e01", "disk_image", "archive_image", "virtual_disk"),
        ),
        (
            "image-handoff",
            "For image inputs, confirm dependency/partition/extraction provenance.",
            "high",
            ("e01", "disk_image", "archive_image", "virtual_disk"),
        ),
    ),
    "extract": (
        (
            "extract-manifest",
            "Open extraction manifests and review extracted/skipped/capped rows.",
            "high",
            ("docs_extract_manifest", "files_extract_manifest"),
        ),
    ),
    "parse": (
        ("artifact-rows", "Open artifact outputs and verify parser warnings before search/review.", "critical", ()),
        (
            "file-doc-rows",
            "Confirm manifest, document rows, and file candidate rows exist.",
            "high",
            ("manifest", "docs", "files"),
        ),
    ),
    "index": (
        (
            "search-index",
            "Confirm docs index, timeline, indicators, and search diagnostics are ready.",
            "critical",
            ("docs_index", "timeline", "indicators", "sqlite_fts_optimization"),
        ),
    ),
    "review": (
        (
            "review-safety",
            "Check silent-failure, parser-crash, memory-cap, and preview-sandbox evidence.",
            "critical",
            ("parser_crash_isolation", "memory_cap_enforcement", "preview_sandbox_policy"),
        ),
        ("warning-review", "Resolve warning messages before treating absence as evidence.", "high", ()),
    ),
    "report": (
        (
            "report-export",
            "Open report outputs and confirm reviewed evidence/citations before export.",
            "critical",
            ("report", "summary", "timeline_report"),
        ),
    ),
}


def stage_for_step_name(name: str) -> str | None:
    if name.startswith("artifacts-"):
        return "parse"
    return STEP_STAGE_MAP.get(name)


def stage_for_output_name(name: str) -> str | None:
    if name.startswith("artifacts_"):
        return "parse"
    return OUTPUT_STAGE_MAP.get(name)


def output_handoff_for_key(name: str) -> dict[str, str]:
    if name.startswith("artifacts_"):
        artifact_kind = name.removeprefix("artifacts_").replace("_", "-")
        return {
            "name": name,
            "role": f"{artifact_kind} artifact rows",
            "recommended_viewer": "artifact-table-viewer",
            "gui_action": "Open artifact rows, then pivot each finding to the source viewer.",
            "reportability_note": "Report only after row-level source/provenance and validation warnings are checked.",
        }

    role, viewer, action, note = OUTPUT_HANDOFF_ROLES.get(
        name,
        (
            "run output",
            "json-viewer",
            "Open this output and verify contents before relying on stage status.",
            "Reportability depends on source/provenance fields inside the output.",
        ),
    )
    return {
        "name": name,
        "role": role,
        "recommended_viewer": viewer,
        "gui_action": action,
        "reportability_note": note,
    }


def checklist_status_for_outputs(
    *,
    checklist_id: str,
    output_keys: set[str],
    expected_outputs: tuple[str, ...],
    source: Mapping[str, object],
    warning_messages: Sequence[str],
    status: str,
) -> str:
    if status == "blocked":
        return "blocked"
    if checklist_id == "source-provenance":
        return "ready" if source or output_keys.intersection(expected_outputs) else "pending"
    if checklist_id == "image-handoff":
        source_type = str(source.get("type") or "directory")
        if source_type not in {"e01", "raw-image", "virtual-disk", "archive-image"}:
            return "ready"
        return "ready" if output_keys.intersection(expected_outputs) else "warning"
    if checklist_id == "artifact-rows":
        return "ready" if any(key.startswith("artifacts_") for key in output_keys) else "warning"
    if checklist_id == "warning-review":
        return "warning" if warning_messages else "ready"
    if not expected_outputs:
        return "ready" if output_keys else "pending"
    return "ready" if output_keys.intersection(expected_outputs) else "pending"


def build_stage_analyst_checklist(
    *,
    stage_id: str,
    output_keys: Sequence[str],
    source: Mapping[str, object],
    warning_messages: Sequence[str],
    status: str,
) -> list[dict[str, object]]:
    output_key_set = set(output_keys)
    checklist: list[dict[str, object]] = []
    for checklist_id, label, severity, expected_outputs in STAGE_CHECKLIST_DEFINITIONS.get(stage_id, ()):
        item_status = checklist_status_for_outputs(
            checklist_id=checklist_id,
            output_keys=output_key_set,
            expected_outputs=expected_outputs,
            source=source,
            warning_messages=warning_messages,
            status=status,
        )
        matched_outputs = [name for name in output_keys if (not expected_outputs and name) or name in expected_outputs]
        if checklist_id == "artifact-rows":
            matched_outputs = [name for name in output_keys if name.startswith("artifacts_")]
        checklist.append(
            {
                "id": f"{stage_id}:{checklist_id}",
                "label": label,
                "status": item_status,
                "severity": severity,
                "expected_outputs": list(expected_outputs),
                "matched_outputs": matched_outputs[:12],
                "action": analyst_checklist_action(item_status=item_status, stage_id=stage_id, label=label),
            }
        )
    return checklist


def analyst_checklist_action(*, item_status: str, stage_id: str, label: str) -> str:
    if item_status == "ready":
        return "Ready for analyst verification."
    if item_status == "warning":
        return f"Review {stage_id} warnings and open related outputs before relying on this stage."
    if item_status == "blocked":
        return f"Fix blocked {stage_id} step or rerun this stage before continuing."
    return f"Run or import the missing {stage_id} output, then verify: {label}"


def workflow_checklist_summary(stages: Sequence[Mapping[str, object]]) -> dict[str, object]:
    items: list[Mapping[str, object]] = []
    for stage in stages:
        checklist = stage.get("analyst_checklist")
        if isinstance(checklist, list):
            items.extend(item for item in checklist if isinstance(item, Mapping))
    status_counts = {
        status: sum(1 for item in items if str(item.get("status") or "") == status)
        for status in ("ready", "warning", "blocked", "pending")
    }
    severity_counts: dict[str, int] = {}
    for item in items:
        severity = str(item.get("severity") or "unknown")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    next_actions = [
        {
            "stage": str(item.get("id") or "").split(":", 1)[0],
            "status": str(item.get("status") or "pending"),
            "severity": str(item.get("severity") or "unknown"),
            "action": str(item.get("action") or item.get("label") or ""),
        }
        for item in items
        if str(item.get("status") or "") in {"blocked", "warning", "pending"}
    ]
    return {
        "profile_version": "run-workflow-analyst-checklist-summary-v1",
        "item_count": len(items),
        "ready_count": status_counts["ready"],
        "warning_count": status_counts["warning"],
        "blocked_count": status_counts["blocked"],
        "pending_count": status_counts["pending"],
        "severity_counts": severity_counts,
        "next_actions": next_actions[:8],
    }


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
                    "checklist": [
                        {
                            "id": item["id"],
                            "status": item["status"],
                        }
                        for item in stage["analyst_checklist"]
                    ],
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
        "analyst_checklist_summary": workflow_checklist_summary(stages),
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

    checklist = build_stage_analyst_checklist(
        stage_id=definition.id,
        output_keys=output_keys,
        source=source,
        warning_messages=warning_messages,
        status=status,
    )

    return {
        "id": definition.id,
        "label": definition.label,
        "title": definition.title,
        "status": status,
        "ready": status in {"completed", "warning"},
        "step_names": [str(step.get("name", "")) for step in steps if step.get("name")],
        "output_keys": list(output_keys),
        "handoff_outputs": [output_handoff_for_key(output_key) for output_key in output_keys],
        "analyst_checklist": checklist,
        "reused": reused,
        "warning_count": len(warning_messages),
        "warning_messages": warning_messages[:8],
        "gui": {
            "primary_tab": definition.primary_tab,
            "next_action": next_action,
            "large_case_note": definition.large_case_note,
        },
    }
