from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional, Sequence

from .e01 import (
    build_image_stage_control_contract,
    build_recovered_root_manifest,
    collect_tool_preflight,
    command_record,
    describe_source_integrity,
    image_commercial_uplift_evidence,
    image_core_accuracy_gates,
    image_report_grade_assessment,
    image_reportability_decision,
    image_validation_matrix,
    mark_selected_partition,
    mmls_first_filesystem,
    parse_mmls_partitions,
    stable_manifest_sha256,
)
from .vsc import build_vsc_image_workflow_handoff


RAW_IMAGE_SUFFIXES = (".dd", ".raw", ".img", ".001", ".000", ".0000", ".0001", ".00001", ".ima")
RAW_IMAGE_REQUIRED_TOOLS = ("mmls", "tsk_recover")
RAW_SPLIT_WORKFLOW_MANIFEST_VERSION = "raw-split-integrated-workflow-manifest-v1"
RAW_IMAGE_NATIVE_CAPABILITIES = {
    "split_segment_discovery": True,
    "split_gap_warning": True,
    "source_integrity_preflight": True,
    "partition_table_enumeration": True,
    "sleuthkit_filesystem_recovery": True,
    "whole_image_fallback": True,
    "native_partition_filesystem_parser": False,
    "encrypted_volume_unlock_workflow": False,
    "volume_shadow_native_handling": False,
    "large_known_answer_validation_corpus": False,
}
RAW_IMAGE_REPORT_GRADE_BLOCKERS = [
    "native-partition-filesystem-parser-not-implemented",
    "split-image-gap-and-damaged-set-known-answer-validation-required",
    "encrypted-volume-unlock-workflow-not-implemented",
    "volume-shadow-native-handling-not-implemented",
    "large-raw-image-known-answer-corpus-required",
]
CommandRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]
ToolResolver = Callable[[str], Optional[str]]


class DiskImageExtractionError(RuntimeError):
    """Raised when a disk image cannot be recovered into a triageable folder."""


@dataclass(frozen=True)
class DiskImageExtractionResult:
    source_path: Path
    stage_dir: Path
    extract_dir: Path
    image_paths: tuple[Path, ...]
    partition_start_sector: int | None
    recovery_mode: str
    source_integrity: tuple[dict[str, object], ...] = ()
    tool_preflight: tuple[dict[str, object], ...] = ()
    partition_table: tuple[dict[str, object], ...] = ()
    split_part_warnings: tuple[str, ...] = ()
    split_set_profile: dict[str, object] = field(default_factory=dict)
    recovered_root_manifest: dict[str, object] = field(default_factory=dict)
    command_history: tuple[dict[str, object], ...] = ()
    warnings: tuple[str, ...] = ()
    commercial_grade_ready: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "command": "disk-image-extract",
            "source_path": str(self.source_path),
            "stage_dir": str(self.stage_dir),
            "extract_dir": str(self.extract_dir),
            "image_paths": [str(path) for path in self.image_paths],
            "partition_start_sector": self.partition_start_sector,
            "recovery_mode": self.recovery_mode,
            "tools": list(RAW_IMAGE_REQUIRED_TOOLS),
            "source_integrity": list(self.source_integrity),
            "tool_preflight": list(self.tool_preflight),
            "partition_table": list(self.partition_table),
            "split_part_warnings": list(self.split_part_warnings),
            "split_set_profile": self.split_set_profile,
            "raw_split_workflow_manifest": build_raw_split_integrated_workflow_manifest(
                source_path=self.source_path,
                image_paths=self.image_paths,
                source_integrity=self.source_integrity,
                tool_preflight=self.tool_preflight,
                partition_table=self.partition_table,
                split_part_warnings=self.split_part_warnings,
                split_set_profile=self.split_set_profile,
                recovered_root_manifest=self.recovered_root_manifest,
                command_history=self.command_history,
                recovery_mode=self.recovery_mode,
                partition_start_sector=self.partition_start_sector,
                run_outputs=None,
                status_context="extraction-result",
            ),
            "vsc_workflow_handoff": build_vsc_image_workflow_handoff(
                current_root=self.extract_dir,
                source_kind="raw-split-image",
                source_path=self.source_path,
                stage_dir=self.stage_dir,
            ),
            "stage_control_contract": build_image_stage_control_contract(
                source_kind="raw-split-image",
                stage_dir=self.stage_dir,
                checkpoint_path=None,
                resume_status=None,
                stages=[
                    {"id": "dependency-preflight", "status": "completed" if self.tool_preflight else "not-recorded"},
                    {"id": "partition-selection", "status": "completed" if self.partition_start_sector is not None else self.recovery_mode},
                    {"id": "filesystem-extraction", "status": "completed"},
                ],
                checkpoint_supported=False,
                resume_supported=False,
            ),
            "recovered_root_manifest": self.recovered_root_manifest,
            "command_history": list(self.command_history),
            "warnings": list(self.warnings),
            "commercial_grade_ready": self.commercial_grade_ready,
            "commercial_gap_ids": ["#23"],
            "validation_matrix": image_validation_matrix(
                gap_id="#23",
                source_integrity=bool(self.source_integrity),
                tool_preflight=bool(self.tool_preflight),
                partition_table=bool(self.partition_table) or self.recovery_mode == "whole-image",
                command_history=bool(self.command_history),
                native_complete=False,
            ),
            "core_accuracy_gates": image_core_accuracy_gates(
                23,
                {
                    "source_path": str(self.source_path),
                    "source_integrity": list(self.source_integrity),
                    "tool_preflight": list(self.tool_preflight),
                    "partition_table": list(self.partition_table),
                    "partition_start_sector": self.partition_start_sector,
                    "split_part_warnings": list(self.split_part_warnings),
                    "split_set_profile": self.split_set_profile,
                    "recovered_root_manifest": self.recovered_root_manifest,
                    "command_history": list(self.command_history),
                    "warnings": list(self.warnings),
                    "recovery_mode": self.recovery_mode,
                    "native_capabilities": dict(RAW_IMAGE_NATIVE_CAPABILITIES),
                    "limitations": RAW_IMAGE_REPORT_GRADE_BLOCKERS,
                },
            ),
            "image_report_grade_assessment": image_report_grade_assessment("#23", RAW_IMAGE_REPORT_GRADE_BLOCKERS),
            "commercial_uplift_evidence": image_commercial_uplift_evidence(
                23,
                {
                    "source_path": str(self.source_path),
                    "source_integrity": list(self.source_integrity),
                    "tool_preflight": list(self.tool_preflight),
                    "partition_table": list(self.partition_table),
                    "partition_start_sector": self.partition_start_sector,
                    "split_part_count": len(self.image_paths),
                    "split_part_warnings": list(self.split_part_warnings),
                    "split_set_profile": self.split_set_profile,
                    "recovered_root_manifest": self.recovered_root_manifest,
                    "command_history": list(self.command_history),
                    "warnings": list(self.warnings),
                    "limitations": RAW_IMAGE_REPORT_GRADE_BLOCKERS,
                },
            ),
            "native_capabilities": dict(RAW_IMAGE_NATIVE_CAPABILITIES),
            "commercial_grade_blockers": [
                "Split-image discovery and Sleuth Kit recovery need larger known-answer validation across damaged/gapped sets.",
                "Filesystem recovery is delegated to installed Sleuth Kit behavior and must be validated per filesystem/version.",
                "Full partition-table, volume-shadow, encrypted-volume, and deleted-file testimony are not native report-grade yet.",
            ],
            "safety": {
                "read_only_source": True,
                "writes_to_stage_dir_only": True,
                "fallback": "Mount/recover the image read-only with a trusted forensic suite, preserve logs, then scan that folder.",
            },
        }


def build_raw_split_integrated_workflow_manifest(
    *,
    source_path: Path,
    image_paths: Sequence[Path],
    source_integrity: Sequence[dict[str, object]] | None,
    tool_preflight: Sequence[dict[str, object]] | None,
    partition_table: Sequence[dict[str, object]] | None,
    split_part_warnings: Sequence[str] | None,
    split_set_profile: dict[str, object] | None,
    recovered_root_manifest: dict[str, object] | None,
    command_history: Sequence[dict[str, object]] | None,
    recovery_mode: str,
    partition_start_sector: int | None,
    run_outputs: dict[str, object] | None = None,
    status_context: str = "extraction-result",
) -> dict[str, object]:
    source_rows = [dict(row) for row in source_integrity or []]
    tool_rows = [dict(row) for row in tool_preflight or []]
    partition_rows = [dict(row) for row in partition_table or []]
    command_rows = [dict(row) for row in command_history or []]
    split_profile = dict(split_set_profile or {})
    recovered_manifest = dict(recovered_root_manifest or {})
    outputs = dict(run_outputs or {})
    output_status = {
        key: {
            "path": str(value),
            "expected": key
            in {
                "disk_image",
                "manifest",
                "docs",
                "docs_index",
                "files",
                "timeline",
                "timeline_report",
                "indicators",
                "summary",
                "report",
            }
            or key.startswith("artifacts_"),
        }
        for key, value in outputs.items()
    }
    analysis_outputs = [
        key
        for key in output_status
        if key
        in {
            "manifest",
            "docs",
            "docs_index",
            "files",
            "timeline",
            "timeline_report",
            "indicators",
        }
        or key.startswith("artifacts_")
    ]
    report_outputs = [key for key in output_status if key in {"summary", "report"}]
    recovered_count = int(
        recovered_manifest.get("visited_file_count")
        or recovered_manifest.get("hashed_file_count")
        or recovered_manifest.get("file_count")
        or 0
    )
    extraction_complete = bool(
        recovered_count
        or any(row.get("purpose") == "read-only-filesystem-recovery" and row.get("returncode") == 0 for row in command_rows)
    )
    vsc_ready = extraction_complete or bool(analysis_outputs) or (status_context == "run-summary" and bool(outputs))
    stage_hint = Path(str(outputs.get("disk_image") or source_path.parent))
    if stage_hint.suffix:
        stage_hint = stage_hint.parent
    vsc_handoff = build_vsc_image_workflow_handoff(
        current_root=str((recovered_manifest or {}).get("root") or "<analysis-root>") if vsc_ready else None,
        source_kind="raw-split-image",
        source_path=source_path,
        stage_dir=stage_hint,
        status="ready-after-extraction" if vsc_ready else "blocked",
    )
    source_hash_statuses = [str(row.get("hash_status") or "not-recorded") for row in source_rows]
    dependency_complete = bool(tool_rows) and all(row.get("available") for row in tool_rows)
    blockers = [
        "native-partition-filesystem-parser-not-implemented",
        "raw-split-trusted-recovery-diff-required",
        "damaged-gapped-split-set-known-answer-corpus-required",
        "encrypted-volume-unlock-workflow-not-implemented",
    ]
    stages = [
        {
            "id": "select-raw-or-split",
            "label": "RAW/split image selection",
            "status": "complete" if source_path.is_file() and image_paths else "blocked",
            "evidence": {
                "source_path": str(source_path),
                "part_count": len(image_paths),
                "hash_statuses": source_hash_statuses,
            },
        },
        {
            "id": "split-set-validation",
            "label": "Split-set order and gap validation",
            "status": "review-required" if split_part_warnings else "complete",
            "evidence": {
                "segment_numbers": list(split_profile.get("segment_numbers") or []),
                "missing_segment_numbers": list(split_profile.get("missing_segment_numbers") or []),
                "contiguous": split_profile.get("contiguous"),
                "warnings": list(split_part_warnings or []),
            },
        },
        {
            "id": "dependency-preflight",
            "label": "Dependency preflight",
            "status": "complete" if dependency_complete else "blocked",
            "evidence": {
                "required_tools": list(RAW_IMAGE_REQUIRED_TOOLS),
                "available_tools": [str(row.get("tool")) for row in tool_rows if row.get("available")],
                "missing_tools": [str(row.get("tool")) for row in tool_rows if not row.get("available")],
            },
        },
        {
            "id": "partition-selection",
            "label": "Partition or whole-image recovery decision",
            "status": "complete" if partition_rows or recovery_mode == "whole-image" else "blocked",
            "evidence": {
                "recovery_mode": recovery_mode,
                "selected_start_sector": partition_start_sector,
                "partition_count": len(partition_rows),
                "whole_image_fallback": recovery_mode == "whole-image",
            },
        },
        {
            "id": "filesystem-extraction",
            "label": "Read-only filesystem extraction",
            "status": "complete" if extraction_complete else "blocked",
            "evidence": {
                "command_history_count": len(command_rows),
                "recovered_file_count": recovered_count,
                "deleted_file_flag": any("-e" in row.get("command", []) for row in command_rows),
            },
        },
        {
            "id": "vsc-discovery-extraction",
            "label": "Volume Shadow Copy discovery/extraction handoff",
            "status": "ready-after-extraction" if vsc_ready else "blocked",
            "evidence": {
                "handoff_profile": vsc_handoff["profile_version"],
                "direct_image_level_mount_supported": vsc_handoff["direct_image_level_mount_supported"],
                "discover_command_available": bool(vsc_handoff["commands"].get("discover")),
                "extract_command_available": bool(vsc_handoff["commands"].get("extract")),
            },
        },
        {
            "id": "artifact-analysis",
            "label": "Artifact analysis",
            "status": "complete" if analysis_outputs else ("ready-after-extraction" if extraction_complete else "blocked"),
            "evidence": {
                "analysis_output_keys": sorted(analysis_outputs),
                "artifact_output_count": sum(1 for key in output_status if key.startswith("artifacts_")),
            },
        },
        {
            "id": "unified-search-indexing",
            "label": "Unified search and indexing",
            "status": "complete" if {"docs", "docs_index", "files"}.issubset(output_status) else ("ready-after-analysis" if analysis_outputs else "blocked"),
            "evidence": {
                "docs_output": "docs" in output_status,
                "docs_index_output": "docs_index" in output_status,
                "files_output": "files" in output_status,
            },
        },
        {
            "id": "review-report",
            "label": "Review and report export",
            "status": "complete" if report_outputs else ("ready-after-review" if analysis_outputs else "blocked"),
            "evidence": {
                "report_output_keys": sorted(report_outputs),
                "source_viewer_required": True,
                "trusted_tool_diff_required": True,
            },
        },
    ]
    stage_control = build_image_stage_control_contract(
        source_kind="raw-split-image",
        stage_dir=stage_hint,
        checkpoint_path=None,
        resume_status=None,
        stages=stages,
        checkpoint_supported=False,
        resume_supported=False,
    )
    payload: dict[str, object] = {
        "profile_version": RAW_SPLIT_WORKFLOW_MANIFEST_VERSION,
        "item_number": 23,
        "gap_id": "#23",
        "status_context": status_context,
        "workflow_goal": "RAW and split images keep part-order evidence, partition/whole-image recovery decisions, read-only extraction provenance, downstream analysis outputs, and report blockers in one contract.",
        "source_ref": {
            "path": str(source_path),
            "image_paths": [str(path) for path in image_paths],
            "hash_statuses": source_hash_statuses,
            "source_sha256s": [row.get("sha256") for row in source_rows if row.get("sha256")],
        },
        "split_set_profile": split_profile,
        "partition_table_row_count": len(partition_rows),
        "recovery_mode": recovery_mode,
        "partition_start_sector": partition_start_sector,
        "command_history_count": len(command_rows),
        "recovered_root_summary": {
            "profile_version": recovered_manifest.get("profile_version"),
            "visited_file_count": recovered_manifest.get("visited_file_count", 0),
            "hashed_file_count": recovered_manifest.get("hashed_file_count", 0),
            "skipped_large_file_count": recovered_manifest.get("skipped_large_file_count", 0),
            "truncated": bool(recovered_manifest.get("truncated", False)),
        },
        "run_output_status": output_status,
        "vsc_workflow_handoff": vsc_handoff,
        "stage_control_contract": stage_control,
        "stages": stages,
        "large_data_controls": {
            "direct_image_hash_limit_bytes": 128 * 1024 * 1024,
            "bounded_recovered_root_manifest": True,
            "split_part_count": len(image_paths),
            "cursor_table_required_for_gui": True,
            "virtualized_table_required_for_gui": True,
        },
        "reportability_decision": image_reportability_decision(
            23,
            blockers=blockers,
            failed_validation_matrix_ids=["#23-native-commercial-parser"],
            details={
                "source_integrity": source_rows,
                "image_trusted_diff": {"status": "not-attached"},
            },
        ),
        "commercial_grade_ready": False,
        "commercial_grade_blockers": blockers,
        "operator_next_steps": [
            "Validate split order/gaps against acquisition notes and a trusted image tool.",
            "Attach mmls/tsk_recover or vendor recovery transcripts with source hashes.",
            "Mount/export any VSC snapshots read-only, then run vsc-discover, vsc-compare, and vsc-extract against the recovered current root.",
            "Use source-viewer citations before reporting recovered filesystem artifacts.",
        ],
    }
    payload["manifest_sha256"] = stable_manifest_sha256(payload)
    return payload


def is_raw_image_path(path: Path) -> bool:
    return path.suffix.lower() in RAW_IMAGE_SUFFIXES


def missing_raw_image_tools(tool_resolver: ToolResolver = shutil.which) -> list[str]:
    return [tool for tool in RAW_IMAGE_REQUIRED_TOOLS if tool_resolver(tool) is None]


def default_runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(command), capture_output=True, text=True)


def extract_raw_image_to_directory(
    image_path: Path,
    stage_dir: Path,
    *,
    runner: CommandRunner = default_runner,
    tool_resolver: ToolResolver = shutil.which,
) -> DiskImageExtractionResult:
    source_path = image_path.expanduser().resolve()
    if not source_path.is_file():
        raise DiskImageExtractionError(f"raw disk image not found: {source_path}")
    if not is_raw_image_path(source_path):
        raise DiskImageExtractionError(f"unsupported raw disk image extension: {source_path.name}")

    missing = missing_raw_image_tools(tool_resolver)
    tool_preflight = collect_tool_preflight(RAW_IMAGE_REQUIRED_TOOLS, runner=runner, tool_resolver=tool_resolver)
    if missing:
        joined = ", ".join(missing)
        raise DiskImageExtractionError(
            f"Raw/split image direct input requires external tools: {joined}. "
            "Install Sleuth Kit, run `rapidtriage evidence IMAGE.001 --json` for preflight, "
            "or mount/recover the image read-only with a trusted forensic tool and scan that folder."
        )

    image_paths = tuple(discover_split_image_parts(source_path))
    split_set_profile = build_split_set_profile(image_paths, selected_path=source_path)
    split_part_warnings = tuple(split_set_profile["warnings"])
    stage = stage_dir.expanduser().resolve()
    extract_dir = stage / "filesystem"
    stage.mkdir(parents=True, exist_ok=True)
    extract_dir.mkdir(parents=True, exist_ok=True)

    mmls_result = runner(["mmls", *[str(path) for path in image_paths]])
    command_history = [command_record("partition-enumeration", ["mmls", *[str(path) for path in image_paths]], mmls_result)]
    start_sector = mmls_first_filesystem(mmls_result.stdout) if mmls_result.returncode == 0 else None
    partition_table = parse_mmls_partitions(mmls_result.stdout) if mmls_result.returncode == 0 else []

    command = ["tsk_recover", "-e", "-a"]
    recovery_mode = "whole-image"
    if start_sector is not None:
        command.extend(["-o", str(start_sector)])
        recovery_mode = "partition-offset"
    command.extend([*[str(path) for path in image_paths], str(extract_dir)])

    recover_result = runner(command)
    command_history.append(command_record("read-only-filesystem-recovery", command, recover_result))
    if recover_result.returncode != 0:
        detail = recover_result.stderr.strip() or recover_result.stdout.strip()
        if start_sector is None and mmls_result.returncode != 0:
            mmls_detail = mmls_result.stderr.strip() or mmls_result.stdout.strip()
            detail = f"{detail}; mmls failed before whole-image fallback: {mmls_detail}".strip("; ")
        raise DiskImageExtractionError(f"tsk_recover failed for raw/split image: {detail}")
    recovered_manifest = build_recovered_root_manifest(extract_dir)

    return DiskImageExtractionResult(
        source_path=source_path,
        stage_dir=stage,
        extract_dir=extract_dir,
        image_paths=image_paths,
        partition_start_sector=start_sector,
        recovery_mode=recovery_mode,
        source_integrity=tuple(describe_source_integrity(path) for path in image_paths),
        tool_preflight=tuple(tool_preflight),
        partition_table=tuple(mark_selected_partition(partition_table, start_sector)),
        split_part_warnings=split_part_warnings,
        split_set_profile=split_set_profile,
        recovered_root_manifest=recovered_manifest,
        command_history=tuple(command_history),
        warnings=(
            "Raw/split direct extraction is an orchestrated Sleuth Kit workflow; validate recovered paths and timestamps before reporting.",
        ),
    )


def discover_split_image_parts(source_path: Path) -> list[Path]:
    suffix = source_path.suffix.lower()
    if not re.fullmatch(r"\.\d+", suffix):
        return [source_path]

    stem = source_path.stem
    candidates: list[Path] = []
    for candidate in source_path.parent.iterdir():
        if candidate.stem != stem:
            continue
        if not re.fullmatch(r"\.\d+", candidate.suffix.lower()):
            continue
        candidates.append(candidate.resolve())

    if not candidates:
        return [source_path]
    return sorted(candidates, key=lambda path: int(path.suffix.lstrip(".")))


def validate_split_image_parts(image_paths: Sequence[Path]) -> list[str]:
    if len(image_paths) <= 1:
        return []
    numbers: list[int] = []
    for path in image_paths:
        if not re.fullmatch(r"\.\d+", path.suffix.lower()):
            return []
        numbers.append(int(path.suffix.lstrip(".")))
    warnings: list[str] = []
    expected = list(range(min(numbers), max(numbers) + 1))
    missing = sorted(set(expected) - set(numbers))
    if missing:
        warnings.append(f"Split image sequence appears to have missing segment numbers: {missing}")
    if numbers and min(numbers) not in {0, 1}:
        warnings.append(f"Split image sequence starts at {min(numbers)}; confirm no earlier segment exists.")
    return warnings


def build_split_set_profile(
    image_paths: Sequence[Path],
    *,
    selected_path: Path | None = None,
) -> dict[str, object]:
    parts = list(image_paths)
    warnings = validate_split_image_parts(parts)
    numbers: list[int] = []
    for path in parts:
        if re.fullmatch(r"\.\d+", path.suffix.lower()):
            numbers.append(int(path.suffix.lstrip(".")))
    selected = selected_path.resolve() if selected_path else (parts[0].resolve() if parts else None)
    first = parts[0].resolve() if parts else None
    if selected and first and selected != first:
        warnings.append(f"Selected split image segment is not the first discovered segment: first={parts[0].name}")
    expected = list(range(min(numbers), max(numbers) + 1)) if numbers else []
    missing = sorted(set(expected) - set(numbers)) if expected else []
    return {
        "profile_version": "raw-split-set-v1",
        "selected_segment": str(selected) if selected else "",
        "selected_is_first_segment": bool(selected and first and selected == first),
        "part_count": len(parts),
        "segment_numbers": numbers,
        "missing_segment_numbers": missing,
        "contiguous": not missing,
        "starts_at_expected_segment": min(numbers) in {0, 1} if numbers else True,
        "total_size_bytes": sum(path.stat().st_size for path in parts if path.is_file()),
        "parts": [
            {
                "path": str(path),
                "name": path.name,
                "segment_number": int(path.suffix.lstrip(".")) if re.fullmatch(r"\.\d+", path.suffix.lower()) else None,
                "size": path.stat().st_size if path.is_file() else 0,
                "mtime_ns": path.stat().st_mtime_ns if path.is_file() else None,
            }
            for path in parts
        ],
        "warnings": warnings,
        "validation_status": "review-required" if warnings else "sequence-contiguous",
        "commercial_note": "This is filename/sequence provenance; partition/filesystem parsing is still delegated to Sleuth Kit.",
    }
