from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional, Sequence

from .disk_image import DiskImageExtractionResult, extract_raw_image_to_directory, missing_raw_image_tools
from .e01 import (
    collect_tool_preflight,
    command_record,
    describe_source_integrity,
    image_commercial_uplift_evidence,
    image_core_accuracy_gates,
    image_report_grade_assessment,
    image_reportability_decision,
    image_validation_matrix,
    stable_manifest_sha256,
)


VIRTUAL_DISK_SUFFIXES = (".vhd", ".vhdx", ".vmdk", ".vdi", ".xva", ".qcow", ".qcow2")
QEMU_CONVERTIBLE_SUFFIXES = (".vhd", ".vhdx", ".vmdk", ".vdi", ".qcow", ".qcow2")
VIRTUAL_DISK_REQUIRED_TOOLS = ("qemu-img", "mmls", "tsk_recover")
VIRTUAL_DISK_WORKFLOW_MANIFEST_VERSION = "virtual-disk-integrated-workflow-manifest-v1"
VIRTUAL_DISK_NATIVE_CAPABILITIES = {
    "qemu_img_raw_conversion": True,
    "source_integrity_preflight": True,
    "converted_raw_integrity_preflight": True,
    "nested_raw_sleuthkit_recovery": True,
    "command_history_capture": True,
    "snapshot_chain_validation": False,
    "differencing_disk_resolution": False,
    "hypervisor_metadata_decode": False,
    "xva_direct_extraction": False,
    "large_known_answer_validation_corpus": False,
}
VIRTUAL_DISK_REPORT_GRADE_BLOCKERS = [
    "snapshot-chain-validation-not-implemented",
    "differencing-disk-resolution-not-implemented",
    "hypervisor-metadata-decoding-not-implemented",
    "xva-direct-extraction-not-implemented",
    "large-virtual-disk-known-answer-corpus-required",
]
CommandRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]
ToolResolver = Callable[[str], Optional[str]]


class VirtualDiskExtractionError(RuntimeError):
    """Raised when a virtual disk cannot be converted and recovered."""


@dataclass(frozen=True)
class VirtualDiskExtractionResult:
    source_path: Path
    stage_dir: Path
    converted_raw_path: Path
    raw_result: DiskImageExtractionResult
    conversion_tool: str
    source_integrity: dict[str, object] = field(default_factory=dict)
    converted_raw_integrity: dict[str, object] = field(default_factory=dict)
    tool_preflight: tuple[dict[str, object], ...] = ()
    command_history: tuple[dict[str, object], ...] = ()
    warnings: tuple[str, ...] = ()
    virtual_disk_chain_profile: dict[str, object] = field(default_factory=dict)
    qemu_img_info_profile: dict[str, object] = field(default_factory=dict)
    commercial_grade_ready: bool = False

    @property
    def extract_dir(self) -> Path:
        return self.raw_result.extract_dir

    def to_dict(self) -> dict[str, object]:
        return {
            "command": "virtual-disk-extract",
            "source_path": str(self.source_path),
            "stage_dir": str(self.stage_dir),
            "converted_raw_path": str(self.converted_raw_path),
            "extract_dir": str(self.extract_dir),
            "conversion_tool": self.conversion_tool,
            "raw_extraction": self.raw_result.to_dict(),
            "tools": list(VIRTUAL_DISK_REQUIRED_TOOLS),
            "source_integrity": self.source_integrity,
            "converted_raw_integrity": self.converted_raw_integrity,
            "tool_preflight": list(self.tool_preflight),
            "command_history": list(self.command_history),
            "warnings": list(self.warnings),
            "virtual_disk_chain_profile": self.virtual_disk_chain_profile,
            "qemu_img_info_profile": self.qemu_img_info_profile,
            "virtual_disk_workflow_manifest": build_virtual_disk_integrated_workflow_manifest(
                source_path=self.source_path,
                converted_raw_path=self.converted_raw_path,
                raw_result=self.raw_result,
                conversion_tool=self.conversion_tool,
                source_integrity=self.source_integrity,
                converted_raw_integrity=self.converted_raw_integrity,
                tool_preflight=self.tool_preflight,
                command_history=self.command_history,
                warnings=self.warnings,
                virtual_disk_chain_profile=self.virtual_disk_chain_profile,
                qemu_img_info_profile=self.qemu_img_info_profile,
                run_outputs=None,
                status_context="extraction-result",
            ),
            "commercial_grade_ready": self.commercial_grade_ready,
            "commercial_gap_ids": ["#24"],
            "validation_matrix": image_validation_matrix(
                gap_id="#24",
                source_integrity=bool(self.source_integrity),
                tool_preflight=bool(self.tool_preflight),
                partition_table=bool(self.raw_result.partition_table),
                command_history=bool(self.command_history) and bool(self.raw_result.command_history),
                native_complete=False,
            ),
            "core_accuracy_gates": image_core_accuracy_gates(
                24,
                {
                    "source_path": str(self.source_path),
                    "source_integrity": self.source_integrity,
                    "converted_raw_path": str(self.converted_raw_path),
                    "converted_raw_integrity": self.converted_raw_integrity,
                    "tool_preflight": list(self.tool_preflight),
                    "partition_table": list(self.raw_result.partition_table),
                    "command_history": [*list(self.command_history), *list(self.raw_result.command_history)],
                    "raw_extraction": self.raw_result.to_dict(),
                    "warnings": list(self.warnings),
                    "virtual_disk_chain_profile": self.virtual_disk_chain_profile,
                    "qemu_img_info_profile": self.qemu_img_info_profile,
                    "native_capabilities": dict(VIRTUAL_DISK_NATIVE_CAPABILITIES),
                    "limitations": VIRTUAL_DISK_REPORT_GRADE_BLOCKERS,
                },
            ),
            "image_report_grade_assessment": image_report_grade_assessment("#24", VIRTUAL_DISK_REPORT_GRADE_BLOCKERS),
            "commercial_uplift_evidence": image_commercial_uplift_evidence(
                24,
                {
                    "source_path": str(self.source_path),
                    "source_integrity": self.source_integrity,
                    "converted_raw_path": str(self.converted_raw_path),
                    "converted_raw_integrity": self.converted_raw_integrity,
                    "tool_preflight": list(self.tool_preflight),
                    "partition_table": list(self.raw_result.partition_table),
                    "command_history": [*list(self.command_history), *list(self.raw_result.command_history)],
                    "raw_extraction": self.raw_result.to_dict(),
                    "warnings": list(self.warnings),
                    "virtual_disk_chain_profile": self.virtual_disk_chain_profile,
                    "qemu_img_info_profile": self.qemu_img_info_profile,
                    "limitations": VIRTUAL_DISK_REPORT_GRADE_BLOCKERS,
                },
            ),
            "native_capabilities": dict(VIRTUAL_DISK_NATIVE_CAPABILITIES),
            "commercial_grade_blockers": [
                "Virtual disk support depends on qemu-img conversion fidelity and installed Sleuth Kit recovery behavior.",
                "Snapshot chains, differencing disks, encryption, and hypervisor metadata are not fully validated natively.",
                "Large cross-format known-answer and corrupted-image validation is still required before commercial-grade claims.",
            ],
            "safety": {
                "read_only_source": True,
                "writes_to_stage_dir_only": True,
                "conversion_output": str(self.converted_raw_path),
            },
        }


def build_virtual_disk_integrated_workflow_manifest(
    *,
    source_path: Path,
    converted_raw_path: Path,
    raw_result: DiskImageExtractionResult,
    conversion_tool: str,
    source_integrity: dict[str, object] | None,
    converted_raw_integrity: dict[str, object] | None,
    tool_preflight: Sequence[dict[str, object]] | None,
    command_history: Sequence[dict[str, object]] | None,
    warnings: Sequence[str] | None,
    virtual_disk_chain_profile: dict[str, object] | None,
    qemu_img_info_profile: dict[str, object] | None,
    run_outputs: dict[str, object] | None = None,
    status_context: str = "extraction-result",
) -> dict[str, object]:
    tool_rows = [dict(row) for row in tool_preflight or []]
    command_rows = [dict(row) for row in command_history or []]
    chain_profile = dict(virtual_disk_chain_profile or {})
    info_profile = dict(qemu_img_info_profile or {})
    raw_payload = raw_result.to_dict()
    outputs = dict(run_outputs or {})
    output_status = {
        key: {
            "path": str(value),
            "expected": key
            in {
                "virtual_disk",
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
    dependency_complete = bool(tool_rows) and all(row.get("available") for row in tool_rows)
    qemu_info_ok = info_profile.get("command_status") == "ok"
    conversion_complete = converted_raw_path.is_file() or bool(converted_raw_integrity)
    raw_extraction_complete = bool((raw_result.recovered_root_manifest or {}).get("visited_file_count")) or bool(raw_result.command_history)
    blockers = [
        "snapshot-chain-validation-not-implemented",
        "differencing-disk-resolution-not-implemented",
        "hypervisor-metadata-decoding-not-implemented",
        "virtual-disk-trusted-conversion-diff-required",
    ]
    stages = [
        {
            "id": "select-virtual-disk",
            "label": "Virtual disk selection",
            "status": "complete" if source_path.is_file() else "blocked",
            "evidence": {
                "source_path": str(source_path),
                "detected_format": chain_profile.get("detected_format") or source_path.suffix.lower().lstrip("."),
                "source_hash_status": (source_integrity or {}).get("hash_status", "not-recorded"),
            },
        },
        {
            "id": "chain-risk-review",
            "label": "Snapshot/differencing chain risk review",
            "status": "review-required" if chain_profile.get("warnings") or chain_profile.get("suspected_snapshot_or_differencing_member") else "complete",
            "evidence": {
                "chain_validation_status": chain_profile.get("chain_validation_status"),
                "suspected_snapshot_or_differencing_member": chain_profile.get("suspected_snapshot_or_differencing_member"),
                "backing_filename_present": info_profile.get("backing_filename_present"),
                "warnings": list(chain_profile.get("warnings") or []),
            },
        },
        {
            "id": "dependency-preflight",
            "label": "Dependency preflight",
            "status": "complete" if dependency_complete else "blocked",
            "evidence": {
                "required_tools": list(VIRTUAL_DISK_REQUIRED_TOOLS),
                "available_tools": [str(row.get("tool")) for row in tool_rows if row.get("available")],
                "missing_tools": [str(row.get("tool")) for row in tool_rows if not row.get("available")],
            },
        },
        {
            "id": "qemu-img-info",
            "label": "qemu-img metadata capture",
            "status": "complete" if qemu_info_ok else "review-required",
            "evidence": {
                "format": info_profile.get("format"),
                "virtual_size": info_profile.get("virtual_size"),
                "actual_size": info_profile.get("actual_size"),
                "parse_status": info_profile.get("parse_status"),
            },
        },
        {
            "id": "raw-conversion",
            "label": "Read-only raw conversion",
            "status": "complete" if conversion_complete else "blocked",
            "evidence": {
                "conversion_tool": conversion_tool,
                "converted_raw_path": str(converted_raw_path),
                "converted_hash_status": (converted_raw_integrity or {}).get("hash_status", "not-recorded"),
                "command_history_count": len(command_rows),
            },
        },
        {
            "id": "nested-raw-recovery",
            "label": "Nested RAW partition/filesystem recovery",
            "status": "complete" if raw_extraction_complete else "blocked",
            "evidence": {
                "raw_recovery_mode": raw_result.recovery_mode,
                "partition_start_sector": raw_result.partition_start_sector,
                "raw_command_history_count": len(raw_result.command_history),
            },
        },
        {
            "id": "artifact-analysis",
            "label": "Artifact analysis",
            "status": "complete" if analysis_outputs else ("ready-after-extraction" if raw_extraction_complete else "blocked"),
            "evidence": {
                "analysis_output_keys": sorted(analysis_outputs),
                "artifact_output_count": sum(1 for key in output_status if key.startswith("artifacts_")),
            },
        },
        {
            "id": "review-report",
            "label": "Review and report export",
            "status": "complete" if report_outputs else ("ready-after-review" if analysis_outputs else "blocked"),
            "evidence": {
                "report_output_keys": sorted(report_outputs),
                "source_viewer_required": True,
                "trusted_conversion_diff_required": True,
            },
        },
    ]
    payload: dict[str, object] = {
        "profile_version": VIRTUAL_DISK_WORKFLOW_MANIFEST_VERSION,
        "item_number": 24,
        "gap_id": "#24",
        "status_context": status_context,
        "workflow_goal": "Virtual disks preserve source/chain risk, qemu-img info, raw conversion provenance, nested RAW recovery, downstream analysis, and report blockers in one contract.",
        "source_ref": {
            "path": str(source_path),
            "sha256": (source_integrity or {}).get("sha256"),
            "hash_status": (source_integrity or {}).get("hash_status"),
        },
        "converted_raw_ref": {
            "path": str(converted_raw_path),
            "sha256": (converted_raw_integrity or {}).get("sha256"),
            "hash_status": (converted_raw_integrity or {}).get("hash_status"),
        },
        "virtual_disk_chain_profile": chain_profile,
        "qemu_img_info_profile": info_profile,
        "raw_extraction_summary": {
            "recovery_mode": raw_result.recovery_mode,
            "partition_start_sector": raw_result.partition_start_sector,
            "partition_table_count": len(raw_result.partition_table),
            "recovered_file_count": (raw_result.recovered_root_manifest or {}).get("visited_file_count", 0),
            "raw_split_workflow_manifest_hash": (raw_payload.get("raw_split_workflow_manifest") or {}).get("manifest_sha256")
            if isinstance(raw_payload.get("raw_split_workflow_manifest"), dict)
            else None,
        },
        "run_output_status": output_status,
        "stages": stages,
        "large_data_controls": {
            "converted_raw_hash_limit_bytes": 128 * 1024 * 1024,
            "qemu_info_captured": bool(info_profile),
            "nested_raw_manifest_linked": bool(raw_payload.get("raw_split_workflow_manifest")),
            "cursor_table_required_for_gui": True,
            "virtualized_table_required_for_gui": True,
        },
        "reportability_decision": image_reportability_decision(
            24,
            blockers=blockers,
            failed_validation_matrix_ids=["#24-native-commercial-parser"],
            details={
                "source_integrity": source_integrity or {},
                "image_trusted_diff": {"status": "not-attached"},
            },
        ),
        "commercial_grade_ready": False,
        "commercial_grade_blockers": blockers,
        "warnings": list(warnings or []),
        "operator_next_steps": [
            "Attach qemu-img info/convert transcripts and trusted conversion diff evidence.",
            "Review backing-file/snapshot/differencing chain risk before reporting.",
            "Validate nested RAW recovery against a trusted virtual-disk workflow.",
        ],
    }
    payload["manifest_sha256"] = stable_manifest_sha256(payload)
    return payload


def is_virtual_disk_path(path: Path) -> bool:
    return path.suffix.lower() in VIRTUAL_DISK_SUFFIXES


def can_convert_virtual_disk_suffix(suffix: str) -> bool:
    return suffix.lower() in QEMU_CONVERTIBLE_SUFFIXES


def build_virtual_disk_chain_profile(source_path: Path) -> dict[str, object]:
    suffix = source_path.suffix.lower()
    name = source_path.name.lower()
    snapshot_tokens = ("snapshot", "delta", "differencing", "-00000", "-s0", ".avhd", ".avhdx")
    suspected_snapshot = any(token in name for token in snapshot_tokens)
    warnings: list[str] = []
    if suspected_snapshot:
        warnings.append("Virtual disk name suggests a snapshot/differencing member; parent chain validation is required.")
    if suffix == ".xva":
        warnings.append("XVA direct extraction is not implemented; export metadata and produced disks must be preserved.")
    elif suffix in {".vmdk", ".vhdx", ".qcow", ".qcow2"}:
        warnings.append("Parent/snapshot chain metadata is not natively resolved; validate qemu-img info and acquisition notes.")
    return {
        "profile_version": "virtual-disk-chain-v1",
        "source_path": str(source_path.resolve()),
        "detected_format": suffix.lstrip(".") or "virtual-disk",
        "qemu_convertible": can_convert_virtual_disk_suffix(suffix),
        "suspected_snapshot_or_differencing_member": suspected_snapshot,
        "chain_validation_status": "review-required" if warnings else "not-detected",
        "parent_chain_resolution": "not-implemented",
        "hypervisor_metadata_decode": "not-implemented",
        "warnings": warnings,
        "recommended_validation": [
            "Capture qemu-img info output and compare virtual size, backing file, and format-specific metadata.",
            "Preserve hypervisor/export logs when snapshots, differencing disks, or converted raw output are used.",
        ],
    }


def build_qemu_img_info_profile(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
    stdout = result.stdout.strip()
    stderr = result.stderr.strip()
    parsed: dict[str, object] = {}
    parse_status = "empty-output"
    if stdout:
        try:
            candidate = json.loads(stdout)
            if isinstance(candidate, dict):
                parsed = candidate
                parse_status = "json-parsed"
            else:
                parse_status = "json-non-object"
        except json.JSONDecodeError:
            parse_status = "text-output"
            for line in stdout.splitlines():
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                parsed[key.strip().lower().replace(" ", "_")] = value.strip()
    return {
        "profile_version": "qemu-img-info-profile-v1",
        "command_status": "ok" if result.returncode == 0 else "failed",
        "parse_status": parse_status,
        "returncode": result.returncode,
        "format": parsed.get("format") or parsed.get("file_format") or "",
        "virtual_size": parsed.get("virtual-size") or parsed.get("virtual_size") or "",
        "actual_size": parsed.get("actual-size") or parsed.get("disk_size") or "",
        "backing_filename": parsed.get("backing-filename") or parsed.get("backing_file") or "",
        "backing_filename_present": bool(parsed.get("backing-filename") or parsed.get("backing_file")),
        "parsed": parsed,
        "stderr_preview": stderr[:500],
    }


def missing_virtual_disk_tools(
    suffix: str,
    *,
    tool_resolver: ToolResolver = shutil.which,
) -> list[str]:
    if not can_convert_virtual_disk_suffix(suffix):
        return ["XVA export/mount tooling"]
    missing = []
    if tool_resolver("qemu-img") is None:
        missing.append("qemu-img")
    missing.extend(missing_raw_image_tools(tool_resolver))
    return missing


def default_runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(command), capture_output=True, text=True)


def extract_virtual_disk_to_directory(
    image_path: Path,
    stage_dir: Path,
    *,
    runner: CommandRunner = default_runner,
    tool_resolver: ToolResolver = shutil.which,
) -> VirtualDiskExtractionResult:
    source_path = image_path.expanduser().resolve()
    if not source_path.is_file():
        raise VirtualDiskExtractionError(f"virtual disk not found: {source_path}")
    if not is_virtual_disk_path(source_path):
        raise VirtualDiskExtractionError(f"unsupported virtual disk extension: {source_path.name}")
    if not can_convert_virtual_disk_suffix(source_path.suffix):
        raise VirtualDiskExtractionError(
            "XVA direct extraction is not implemented yet; export or convert the virtual disk first and preserve the export log."
        )
    chain_profile = build_virtual_disk_chain_profile(source_path)

    missing = missing_virtual_disk_tools(source_path.suffix, tool_resolver=tool_resolver)
    tool_preflight = collect_tool_preflight(VIRTUAL_DISK_REQUIRED_TOOLS, runner=runner, tool_resolver=tool_resolver)
    if missing:
        joined = ", ".join(missing)
        raise VirtualDiskExtractionError(
            f"{source_path.suffix.upper().lstrip('.')} direct input requires external tools: {joined}. "
            "Install qemu-img and Sleuth Kit, run `rapidtriage evidence IMAGE --json` for preflight, "
            "or mount/export the virtual disk read-only first."
        )

    stage = stage_dir.expanduser().resolve()
    convert_dir = stage / "converted"
    convert_dir.mkdir(parents=True, exist_ok=True)
    converted_raw = convert_dir / f"{source_path.stem}.raw"

    info_command = ["qemu-img", "info", "--output=json", str(source_path)]
    info_result = runner(info_command)
    qemu_img_info_profile = build_qemu_img_info_profile(info_result)

    convert_command = ["qemu-img", "convert", "-O", "raw", str(source_path), str(converted_raw)]
    convert_result = runner(convert_command)
    command_history = [
        command_record("qemu-img-info", info_command, info_result),
        command_record("qemu-img-raw-conversion", convert_command, convert_result),
    ]
    if convert_result.returncode != 0:
        detail = convert_result.stderr.strip() or convert_result.stdout.strip()
        raise VirtualDiskExtractionError(f"qemu-img conversion failed: {detail}")
    if not converted_raw.exists():
        raise VirtualDiskExtractionError(f"qemu-img did not create expected raw image: {converted_raw}")

    raw_result = extract_raw_image_to_directory(
        converted_raw,
        stage / "raw-extract",
        runner=runner,
        tool_resolver=tool_resolver,
    )
    return VirtualDiskExtractionResult(
        source_path=source_path,
        stage_dir=stage,
        converted_raw_path=converted_raw,
        raw_result=raw_result,
        conversion_tool="qemu-img",
        source_integrity=describe_source_integrity(source_path),
        converted_raw_integrity=describe_source_integrity(converted_raw),
        tool_preflight=tuple(tool_preflight),
        command_history=tuple(command_history),
        virtual_disk_chain_profile=chain_profile,
        qemu_img_info_profile=qemu_img_info_profile,
        warnings=(
            "Virtual disk direct handling converts to raw before Sleuth Kit recovery; validate conversion logs and source chain metadata.",
        ),
    )
