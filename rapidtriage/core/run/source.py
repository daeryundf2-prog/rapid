"""Run source record and image workflow status builders."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from ..archive_image import ArchiveImageExtractionResult
from ..disk_image import (
    DiskImageExtractionResult,
    build_raw_split_integrated_workflow_manifest,
)
from ..e01 import (
    E01ExtractionResult,
    build_e01_ex01_integrated_workflow_manifest,
    build_e01_operator_runbook,
    build_image_stage_control_contract,
)
from ..input_root import InputRoot
from ..virtual_disk import (
    VirtualDiskExtractionResult,
    build_virtual_disk_integrated_workflow_manifest,
)
from ..vsc import build_vsc_image_workflow_handoff

__all__ = [
    "build_completed_e01_workflow_status",
    "build_run_source_record",
]


def build_run_source_record(
    input_root: InputRoot,
    *,
    image_result: E01ExtractionResult
    | DiskImageExtractionResult
    | ArchiveImageExtractionResult
    | VirtualDiskExtractionResult
    | None,
    outputs: Mapping[str, Path] | None = None,
) -> dict[str, object]:
    if image_result is None:
        return {
            "type": input_root.kind,
            "source_path": input_root.source_path,
            "analysis_root": str(input_root.root_path),
        }
    if isinstance(image_result, DiskImageExtractionResult):
        return {
            "type": "raw-image",
            "source_path": str(image_result.source_path),
            "analysis_root": str(image_result.extract_dir),
            "stage_dir": str(image_result.stage_dir),
            "partition_start_sector": image_result.partition_start_sector,
            "recovery_mode": image_result.recovery_mode,
            "image_paths": [str(path) for path in image_result.image_paths],
            "source_integrity": list(image_result.source_integrity),
            "vsc_workflow_handoff": build_vsc_image_workflow_handoff(
                current_root=image_result.extract_dir,
                source_kind="raw-split-image",
                source_path=image_result.source_path,
                stage_dir=image_result.stage_dir,
            ),
            "stage_control_contract": build_image_stage_control_contract(
                source_kind="raw-split-image",
                stage_dir=image_result.stage_dir,
                checkpoint_path=None,
                resume_status=None,
                stages=[
                    {"id": "dependency-preflight", "status": "completed" if image_result.tool_preflight else "not-recorded"},
                    {"id": "partition-selection", "status": "completed" if image_result.partition_start_sector is not None else image_result.recovery_mode},
                    {"id": "filesystem-extraction", "status": "completed"},
                ],
                checkpoint_supported=False,
                resume_supported=False,
            ),
            "raw_split_workflow_manifest": build_raw_split_integrated_workflow_manifest(
                source_path=image_result.source_path,
                image_paths=image_result.image_paths,
                source_integrity=image_result.source_integrity,
                tool_preflight=image_result.tool_preflight,
                partition_table=image_result.partition_table,
                split_part_warnings=image_result.split_part_warnings,
                split_set_profile=image_result.split_set_profile,
                recovered_root_manifest=image_result.recovered_root_manifest,
                command_history=image_result.command_history,
                recovery_mode=image_result.recovery_mode,
                partition_start_sector=image_result.partition_start_sector,
                run_outputs={key: str(value) for key, value in (outputs or {}).items()},
                status_context="run-summary",
            ),
            "commercial_grade_ready": image_result.commercial_grade_ready,
        }
    if isinstance(image_result, ArchiveImageExtractionResult):
        return {
            "type": "archive-image",
            "source_path": str(image_result.source_path),
            "analysis_root": str(image_result.extract_dir),
            "stage_dir": str(image_result.stage_dir),
            "tool": image_result.tool,
            "source_integrity": image_result.source_integrity,
            "commercial_grade_ready": image_result.commercial_grade_ready,
        }
    if isinstance(image_result, VirtualDiskExtractionResult):
        return {
            "type": "virtual-disk",
            "source_path": str(image_result.source_path),
            "analysis_root": str(image_result.extract_dir),
            "stage_dir": str(image_result.stage_dir),
            "converted_raw_path": str(image_result.converted_raw_path),
            "conversion_tool": image_result.conversion_tool,
            "partition_start_sector": image_result.raw_result.partition_start_sector,
            "recovery_mode": image_result.raw_result.recovery_mode,
            "source_integrity": image_result.source_integrity,
            "converted_raw_integrity": image_result.converted_raw_integrity,
            "virtual_disk_workflow_manifest": build_virtual_disk_integrated_workflow_manifest(
                source_path=image_result.source_path,
                converted_raw_path=image_result.converted_raw_path,
                raw_result=image_result.raw_result,
                conversion_tool=image_result.conversion_tool,
                source_integrity=image_result.source_integrity,
                converted_raw_integrity=image_result.converted_raw_integrity,
                tool_preflight=image_result.tool_preflight,
                command_history=image_result.command_history,
                warnings=image_result.warnings,
                virtual_disk_chain_profile=image_result.virtual_disk_chain_profile,
                qemu_img_info_profile=image_result.qemu_img_info_profile,
                run_outputs={key: str(value) for key, value in (outputs or {}).items()},
                status_context="run-summary",
            ),
            "commercial_grade_ready": image_result.commercial_grade_ready,
        }
    return {
        "type": "e01",
        "source_path": str(image_result.source_path),
        "analysis_root": str(image_result.extract_dir),
        "stage_dir": str(image_result.stage_dir),
        "partition_start_sector": image_result.partition_start_sector,
        "partition_selection": image_result.partition_selection,
        "tool_preflight_count": len(image_result.tool_preflight),
        "partition_table_count": len(image_result.partition_table),
        "command_history_count": len(image_result.command_history),
        "source_integrity": image_result.source_integrity,
        "recovered_root_manifest": image_result.recovered_root_manifest,
        "resume_status": image_result.resume_status,
        "vsc_workflow_handoff": build_vsc_image_workflow_handoff(
            current_root=image_result.extract_dir,
            source_kind="e01-ex01",
            source_path=image_result.source_path,
            stage_dir=image_result.stage_dir,
        ),
        "stage_control_contract": build_image_stage_control_contract(
            source_kind="e01-ex01",
            stage_dir=image_result.stage_dir,
            checkpoint_path=image_result.stage_dir / "rapidtriage-e01-stage-status.json",
            resume_status=image_result.resume_status,
            stages=[
                {"id": "dependency-preflight", "status": "completed" if image_result.tool_preflight else "not-recorded"},
                {"id": "partition-selection", "status": "completed"},
                {"id": "filesystem-extraction", "status": "completed"},
            ],
            checkpoint_supported=True,
            resume_supported=True,
        ),
        "workflow_status": build_completed_e01_workflow_status(image_result),
        "e01_ex01_workflow_manifest": build_e01_ex01_integrated_workflow_manifest(
            source_path=image_result.source_path,
            source_integrity=image_result.source_integrity,
            segment_set_profile=image_result.segment_set_profile,
            tool_preflight=image_result.tool_preflight,
            preflight_summary={
                "status": "ready" if image_result.tool_preflight else "not-recorded",
                "available_tools": [str(row.get("tool")) for row in image_result.tool_preflight if row.get("available")],
                "missing_tools": [str(row.get("tool")) for row in image_result.tool_preflight if not row.get("available")],
            },
            partition_selection=image_result.partition_selection,
            partition_table=image_result.partition_table,
            command_history=image_result.command_history,
            recovered_root_manifest=image_result.recovered_root_manifest,
            resume_status=image_result.resume_status,
            run_outputs={key: str(value) for key, value in (outputs or {}).items()},
            status_context="run-summary",
        ),
        "commercial_grade_ready": image_result.commercial_grade_ready,
    }


def build_completed_e01_workflow_status(image_result: E01ExtractionResult) -> dict[str, object]:
    recovered_manifest = image_result.recovered_root_manifest or {}
    recovered_entries = int(recovered_manifest.get("file_count") or recovered_manifest.get("hashed_file_count") or 0)
    runbook = build_e01_operator_runbook(
        image_result.source_path,
        direct_extract_ready=True,
        partition_start_sector=image_result.partition_start_sector,
        output_dir_hint=str(image_result.stage_dir.parent),
    )
    vsc_handoff = build_vsc_image_workflow_handoff(
        current_root=image_result.extract_dir,
        source_kind="e01-ex01",
        source_path=image_result.source_path,
        stage_dir=image_result.stage_dir,
    )
    stages = [
        ("select-e01", "Select E01/Ex01", "complete", f"source={image_result.source_path.name}"),
        (
            "dependency-preflight",
            "Dependency preflight",
            "complete" if image_result.tool_preflight else "not-recorded",
            f"tools={len(image_result.tool_preflight)}",
        ),
        (
            "partition-selection",
            "Partition selection",
            "complete",
            f"sector={image_result.partition_start_sector}",
        ),
        (
            "filesystem-extraction",
            "Read-only extraction",
            "complete",
            f"commands={len(image_result.command_history)}",
        ),
        (
            "vsc-discovery-extraction",
            "VSC discovery/extraction handoff",
            "ready",
            "run vsc-discover, vsc-compare, and vsc-extract after mounting/exporting snapshots",
        ),
        (
            "artifact-analysis",
            "Artifact analysis",
            "complete",
            f"analysis_root={image_result.extract_dir}",
        ),
        (
            "search-review-report",
            "Search, review, report",
            "ready",
            "use Case DB search, source viewer, review board, and report export",
        ),
    ]
    stage_rows = [
        {"id": stage_id, "label": label, "status": status, "evidence": evidence}
        for stage_id, label, status, evidence in stages
    ]
    return {
        "profile_version": "windows11-e01-run-workflow-v1",
        "status": "analysis-ready",
        "stage_dir": str(image_result.stage_dir),
        "analysis_root": str(image_result.extract_dir),
        "selected_partition_start_sector": image_result.partition_start_sector,
        "tool_preflight_count": len(image_result.tool_preflight),
        "partition_table_count": len(image_result.partition_table),
        "command_history_count": len(image_result.command_history),
        "recovered_manifest_entry_count": recovered_entries,
        "resume_reused": bool((image_result.resume_status or {}).get("resumed_from_checkpoint")),
        "stages": stage_rows,
        "operator_runbook": runbook,
        "recommended_commands": runbook["recommended_commands"],
        "vsc_workflow_handoff": vsc_handoff,
        "stage_control_contract": build_image_stage_control_contract(
            source_kind="e01-ex01",
            stage_dir=image_result.stage_dir,
            checkpoint_path=image_result.stage_dir / "rapidtriage-e01-stage-status.json",
            resume_status=image_result.resume_status,
            stages=stage_rows,
            checkpoint_supported=True,
            resume_supported=True,
        ),
        "analyst_next_actions": [
            "Search all evidence from the command bar.",
            "If VSC snapshots are available, run the VSC handoff commands before final deleted-file conclusions.",
            "Open hits in the source viewer before marking them relevant.",
            "Export only reviewed report candidates with hashes and provenance.",
        ],
    }
