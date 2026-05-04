from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping, Optional, Sequence

from .audit import compute_sha256
from .forensic_accuracy import build_accuracy_gate

E01_REQUIRED_TOOLS = ("ewfmount", "mmls", "tsk_recover")
E01_SUFFIXES = (".e01", ".ex01")
DIRECT_IMAGE_HASH_LIMIT_BYTES = 128 * 1024 * 1024
E01_NATIVE_CAPABILITIES = {
    "ewf_libewf_mount_orchestration": True,
    "source_integrity_preflight": True,
    "partition_table_enumeration": True,
    "sleuthkit_filesystem_recovery": True,
    "command_history_capture": True,
    "native_e01_segment_metadata_decode": False,
    "native_compression_error_recovery": False,
    "encrypted_volume_unlock_workflow": False,
    "large_known_answer_validation_corpus": False,
}
E01_REPORT_GRADE_BLOCKERS = [
    "native-e01-ex01-segment-metadata-decoding-not-implemented",
    "external-tool-fuse-platform-behavior-validation-required",
    "encrypted-volume-unlock-workflow-not-implemented",
    "deleted-corrupt-filesystem-recovery-delegated-to-sleuthkit",
    "large-known-answer-e01-ex01-corpus-required",
]
CommandRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]
ToolResolver = Callable[[str], Optional[str]]


class E01ExtractionError(RuntimeError):
    """Raised when an E01 image cannot be exposed as a triageable folder."""


@dataclass(frozen=True)
class E01ExtractionResult:
    source_path: Path
    stage_dir: Path
    mount_dir: Path
    raw_image_path: Path
    extract_dir: Path
    partition_start_sector: int
    source_integrity: dict[str, object] = field(default_factory=dict)
    tool_preflight: tuple[dict[str, object], ...] = ()
    partition_table: tuple[dict[str, object], ...] = ()
    command_history: tuple[dict[str, object], ...] = ()
    warnings: tuple[str, ...] = ()
    commercial_grade_ready: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "command": "e01-extract",
            "source_path": str(self.source_path),
            "stage_dir": str(self.stage_dir),
            "mount_dir": str(self.mount_dir),
            "raw_image_path": str(self.raw_image_path),
            "extract_dir": str(self.extract_dir),
            "partition_start_sector": self.partition_start_sector,
            "tools": list(E01_REQUIRED_TOOLS),
            "source_integrity": self.source_integrity,
            "tool_preflight": list(self.tool_preflight),
            "partition_table": list(self.partition_table),
            "command_history": list(self.command_history),
            "warnings": list(self.warnings),
            "commercial_grade_ready": self.commercial_grade_ready,
            "commercial_gap_ids": ["#22"],
            "validation_matrix": image_validation_matrix(
                gap_id="#22",
                source_integrity=bool(self.source_integrity),
                tool_preflight=bool(self.tool_preflight),
                partition_table=bool(self.partition_table),
                command_history=bool(self.command_history),
                native_complete=False,
            ),
            "core_accuracy_gates": image_core_accuracy_gates(
                22,
                {
                    "source_path": str(self.source_path),
                    "source_integrity": self.source_integrity,
                    "tool_preflight": list(self.tool_preflight),
                    "partition_table": list(self.partition_table),
                    "partition_start_sector": self.partition_start_sector,
                    "command_history": list(self.command_history),
                    "warnings": list(self.warnings),
                    "limitations": E01_REPORT_GRADE_BLOCKERS,
                },
            ),
            "image_report_grade_assessment": image_report_grade_assessment("#22", E01_REPORT_GRADE_BLOCKERS),
            "commercial_uplift_evidence": image_commercial_uplift_evidence(
                22,
                {
                    "source_path": str(self.source_path),
                    "source_integrity": self.source_integrity,
                    "tool_preflight": list(self.tool_preflight),
                    "partition_table": list(self.partition_table),
                    "partition_start_sector": self.partition_start_sector,
                    "command_history": list(self.command_history),
                    "warnings": list(self.warnings),
                    "limitations": E01_REPORT_GRADE_BLOCKERS,
                },
            ),
            "native_capabilities": dict(E01_NATIVE_CAPABILITIES),
            "commercial_grade_blockers": [
                "Requires independent known-answer validation across libewf/Sleuth Kit versions and malformed E01/Ex01 corpora.",
                "Mount/extract workflow depends on external tools and platform FUSE behavior.",
                "Deleted/corrupt filesystem recovery remains delegated to Sleuth Kit and must be validated per case.",
            ],
            "safety": {
                "read_only_source": True,
                "writes_to_stage_dir_only": True,
                "recommended_fallback": "Mount/export with a trusted forensic workflow, preserve that log, then scan the exported folder.",
            },
        }


def is_e01_path(path: Path) -> bool:
    return path.suffix.lower() in E01_SUFFIXES


def missing_e01_tools(tool_resolver: ToolResolver = shutil.which) -> list[str]:
    return [tool for tool in E01_REQUIRED_TOOLS if tool_resolver(tool) is None]


def default_runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(command), capture_output=True, text=True)


def extract_e01_to_directory(
    e01_path: Path,
    stage_dir: Path,
    *,
    runner: CommandRunner = default_runner,
    tool_resolver: ToolResolver = shutil.which,
) -> E01ExtractionResult:
    source_path = e01_path.expanduser().resolve()
    if not source_path.is_file():
        raise E01ExtractionError(f"E01 image not found: {source_path}")
    if not is_e01_path(source_path):
        raise E01ExtractionError(f"unsupported E01 image extension: {source_path.name}")

    missing = missing_e01_tools(tool_resolver)
    tool_preflight = collect_tool_preflight(E01_REQUIRED_TOOLS, runner=runner, tool_resolver=tool_resolver)
    if missing:
        joined = ", ".join(missing)
        raise E01ExtractionError(
            f"E01 direct input requires external tools: {joined}. "
            "Install libewf/Sleuth Kit, run `rapidtriage evidence IMAGE.E01 --json` for preflight, "
            "or mount/export the image read-only with a trusted forensic tool and scan that folder."
        )

    stage = stage_dir.expanduser().resolve()
    mount_dir = stage / "_ewfmount"
    raw_image = mount_dir / "ewf1"
    extract_dir = stage / "filesystem"
    stage.mkdir(parents=True, exist_ok=True)
    mount_dir.mkdir(parents=True, exist_ok=True)
    extract_dir.mkdir(parents=True, exist_ok=True)
    command_history: list[dict[str, object]] = []
    partition_table: list[dict[str, object]] = []

    try:
        mount_result = runner(["ewfmount", str(source_path), str(mount_dir)])
        command_history.append(command_record("mount-ewf", ["ewfmount", str(source_path), str(mount_dir)], mount_result))
        if mount_result.returncode != 0:
            raise E01ExtractionError(f"ewfmount failed: {mount_result.stderr.strip()}")
        if not raw_image.exists():
            raise E01ExtractionError(f"ewfmount did not expose expected raw image: {raw_image}")

        mmls_result = runner(["mmls", str(raw_image)])
        command_history.append(command_record("partition-enumeration", ["mmls", str(raw_image)], mmls_result))
        if mmls_result.returncode != 0:
            raise E01ExtractionError(f"mmls failed: {mmls_result.stderr.strip()}")
        partition_table = parse_mmls_partitions(mmls_result.stdout)
        start_sector = mmls_first_filesystem(mmls_result.stdout)
        if start_sector is None:
            raise E01ExtractionError("mmls could not find a FAT/exFAT/NTFS/basic-data filesystem partition")

        recover_command = ["tsk_recover", "-e", "-a", "-o", str(start_sector), str(raw_image), str(extract_dir)]
        recover_result = runner(recover_command)
        command_history.append(command_record("read-only-filesystem-recovery", recover_command, recover_result))
        if recover_result.returncode != 0:
            raise E01ExtractionError(f"tsk_recover failed: {recover_result.stderr.strip()}")
        return E01ExtractionResult(
            source_path=source_path,
            stage_dir=stage,
            mount_dir=mount_dir,
            raw_image_path=raw_image,
            extract_dir=extract_dir,
            partition_start_sector=start_sector,
            source_integrity=describe_source_integrity(source_path),
            tool_preflight=tuple(tool_preflight),
            partition_table=tuple(mark_selected_partition(partition_table, start_sector)),
            command_history=tuple(command_history),
            warnings=(
                "E01/Ex01 direct extraction is an orchestrated libewf/Sleuth Kit workflow; validate results against case requirements.",
            ),
        )
    finally:
        unmount_e01_mount(mount_dir, runner=runner, tool_resolver=tool_resolver)


def mmls_first_filesystem(text: str) -> int | None:
    best_start = None
    best_size = -1
    for line in text.splitlines():
        match = re.search(r"^\s*\d+:\s+(\d+)\s+(\d+)\s+(.+)$", line)
        if not match:
            continue
        start = int(match.group(1))
        size = int(match.group(2))
        description = match.group(3).lower()
        if "swap" in description:
            continue
        if any(
            token in description
            for token in ("fat", "exfat", "ntfs", "basic data", "msdos", "ext2", "ext3", "ext4", "linux", "xfs")
        ):
            if size > best_size:
                best_start = start
                best_size = size
    return best_start


def parse_mmls_partitions(text: str) -> list[dict[str, object]]:
    partitions: list[dict[str, object]] = []
    for line in text.splitlines():
        match = re.search(r"^\s*(\d+):\s+(\d+)\s+(\d+)\s+(.+)$", line)
        if not match:
            continue
        description = match.group(4).strip()
        partitions.append(
            {
                "slot": int(match.group(1)),
                "start_sector": int(match.group(2)),
                "sector_count": int(match.group(3)),
                "description": description,
                "supported_filesystem_hint": is_supported_mmls_description(description),
            }
        )
    return partitions


def mark_selected_partition(partitions: Sequence[dict[str, object]], start_sector: int | None) -> list[dict[str, object]]:
    marked: list[dict[str, object]] = []
    for partition in partitions:
        row = dict(partition)
        row["selected_for_recovery"] = start_sector is not None and row.get("start_sector") == start_sector
        marked.append(row)
    return marked


def is_supported_mmls_description(description: str) -> bool:
    lowered = description.lower()
    if "swap" in lowered:
        return False
    return any(token in lowered for token in ("fat", "exfat", "ntfs", "basic data", "msdos", "ext2", "ext3", "ext4", "linux", "xfs"))


def describe_source_integrity(path: Path, *, max_hash_bytes: int = DIRECT_IMAGE_HASH_LIMIT_BYTES) -> dict[str, object]:
    resolved = path.expanduser().resolve()
    try:
        stat_result = resolved.stat()
    except OSError as exc:
        return {"path": str(resolved), "hash_status": "unavailable", "error": str(exc)}
    payload: dict[str, object] = {
        "path": str(resolved),
        "size": stat_result.st_size,
        "modified_at": stat_result.st_mtime,
        "hash_algorithm": "sha256",
    }
    if stat_result.st_size <= max_hash_bytes:
        payload["sha256"] = compute_sha256(resolved)
        payload["hash_status"] = "computed"
    else:
        payload["sha256"] = None
        payload["hash_status"] = "deferred-large-source"
        payload["hash_note"] = (
            "Source is larger than the preflight hash limit; acquire a full evidence hash in the acquisition workflow."
        )
    return payload


def image_validation_matrix(
    *,
    gap_id: str,
    source_integrity: bool,
    tool_preflight: bool,
    partition_table: bool,
    command_history: bool,
    native_complete: bool,
) -> list[dict[str, object]]:
    return [
        {
            "id": f"{gap_id}-source-integrity",
            "label": "Source integrity metadata is captured",
            "passed": source_integrity,
            "severity": "critical",
        },
        {
            "id": f"{gap_id}-tool-preflight",
            "label": "External tool availability/version preflight is captured",
            "passed": tool_preflight,
            "severity": "high",
        },
        {
            "id": f"{gap_id}-partition-or-container-metadata",
            "label": "Partition/container metadata is captured when available",
            "passed": partition_table,
            "severity": "high",
        },
        {
            "id": f"{gap_id}-command-history",
            "label": "Read-only extraction command history is preserved",
            "passed": command_history,
            "severity": "high",
        },
        {
            "id": f"{gap_id}-native-commercial-parser",
            "label": "Native parser is complete enough for standalone commercial/report-grade testimony",
            "passed": native_complete,
            "severity": "critical",
        },
    ]


def image_report_grade_assessment(gap_id: str, blockers: Sequence[str]) -> dict[str, object]:
    return {
        "status": "validation-required",
        "commercial_gap_ids": [gap_id],
        "blockers": list(blockers),
        "ready_for_court_report": False,
        "recommended_validation": [
            "Preserve original acquisition hash, tool versions, command logs, and export/mount logs with the case.",
            "Validate extracted filesystem contents against a trusted forensic tool before report-grade conclusions.",
        ],
    }


def image_reportability_decision(
    number: int,
    *,
    blockers: Sequence[str],
    failed_validation_matrix_ids: Sequence[str],
    details: Mapping[str, object],
) -> dict[str, object]:
    decisions = {
        22: ("do-not-report-e01-ex01-workflow-as-native-complete", "e01-ex01-extraction-triage-pivot"),
        23: ("do-not-report-raw-split-workflow-as-native-complete", "raw-split-extraction-triage-pivot"),
        24: ("do-not-report-virtual-disk-workflow-as-chain-complete", "virtual-disk-extraction-triage-pivot"),
        25: ("do-not-report-proprietary-container-as-natively-parsed", "vendor-export-container-triage-pivot"),
    }
    decision, allowed_use = decisions.get(number, ("do-not-report-image-workflow-as-commercial-grade", "image-workflow-triage-pivot"))
    source_integrity = details.get("source_integrity")
    if isinstance(source_integrity, Mapping):
        source_hash_statuses = [str(source_integrity.get("hash_status") or "")]
    elif isinstance(source_integrity, list):
        source_hash_statuses = [
            str(item.get("hash_status") or "") for item in source_integrity if isinstance(item, Mapping)
        ]
    else:
        source_hash_statuses = []
    required_before_report = {
        22: [
            "validate E01/Ex01 segment metadata and extraction against known-answer images",
            "attach libewf/Sleuth Kit versions, commands, hashes, and corrupt/encrypted image limitations",
            "confirm extracted filesystem contents against a trusted forensic suite before final testimony",
        ],
        23: [
            "validate split-set order/gap handling with damaged and large known-answer corpora",
            "attach native partition/filesystem or trusted-tool comparison evidence",
            "document encrypted-volume and deleted-file recovery limitations per case",
        ],
        24: [
            "resolve or explicitly exclude snapshot and differencing-disk chains",
            "preserve qemu-img conversion provenance and compare converted raw content against a trusted workflow",
            "capture hypervisor metadata and encryption limitations before report-grade claims",
        ],
        25: [
            "parse the proprietary container natively or attach a verified vendor export manifest",
            "hash the original container and derived export payloads",
            "validate embedded metadata, deleted entries, compression, and encryption behavior for the format",
        ],
    }
    return {
        "profile_version": "image-workflow-reportability-decision-v1",
        "commercial_gap_ids": [f"#{number}"],
        "decision": decision,
        "allowed_use": allowed_use,
        "blockers": sorted({str(item) for item in blockers if str(item)}),
        "failed_validation_matrix_ids": list(failed_validation_matrix_ids),
        "source_hash_statuses": [status for status in source_hash_statuses if status],
        "native_parser_complete": False,
        "external_tool_or_vendor_workflow_required": True,
        "ready_for_court_report": False,
        "required_before_report": required_before_report.get(
            number,
            ["attach known-answer validation and independent reviewer evidence before report-grade claims"],
        ),
    }


def image_commercial_uplift_evidence(number: int, details: Mapping[str, object]) -> dict[str, object]:
    gap_id = f"#{number}"
    matrix = image_validation_matrix(
        gap_id=gap_id,
        source_integrity=bool(details.get("source_integrity")),
        tool_preflight=bool(details.get("tool_preflight")),
        partition_table=bool(details.get("partition_table"))
        or bool(details.get("detected_format"))
        or bool(details.get("container_type")),
        command_history=bool(details.get("command_history")),
        native_complete=False,
    )
    source_integrity = details.get("source_integrity")
    if isinstance(source_integrity, Mapping):
        source_hashes = [str(source_integrity.get("sha256") or "")]
        hash_statuses = [str(source_integrity.get("hash_status") or "")]
        split_part_count = 1 if source_integrity else 0
    elif isinstance(source_integrity, list):
        parts = [item for item in source_integrity if isinstance(item, Mapping)]
        source_hashes = [str(item.get("sha256") or "") for item in parts]
        hash_statuses = [str(item.get("hash_status") or "") for item in parts]
        split_part_count = len(parts)
    else:
        source_hashes = []
        hash_statuses = []
        split_part_count = 0
    report_grade = details.get("image_report_grade_assessment")
    blockers = (
        report_grade.get("blockers")
        if isinstance(report_grade, Mapping) and isinstance(report_grade.get("blockers"), list)
        else details.get("limitations")
    )
    objectives = {
        22: "Make E01/Ex01 workflow evidence explicit: source integrity, tool preflight, partition selection, read-only extraction provenance, and blockers.",
        23: "Make RAW/split image handling evidence explicit: segment order, gap checks, partition selection, filesystem recovery audit, and encrypted-volume blockers.",
        24: "Make virtual-disk workflow evidence explicit: qemu-img conversion provenance, converted raw integrity, nested recovery, and snapshot/differencing blockers.",
        25: "Make forensic container support evidence explicit: format detection, source integrity, export-first workflow, and native parser blockers.",
    }
    next_steps = {
        22: "Add native E01/Ex01 segment metadata parsing and run encrypted/corrupt image known-answer corpora.",
        23: "Add native partition/filesystem parsing, large damaged split-set tests, and encrypted-volume workflow evidence.",
        24: "Add snapshot/differencing-chain resolution, hypervisor metadata capture, and qemu-img version-matrix validation.",
        25: "Implement/import native or verified vendor parsers for AD1/L01/Lx01/AFF/AFF4/XVA and validate metadata/deleted-entry handling.",
    }
    passed_validation_matrix_ids = [
        str(item.get("id")) for item in matrix if isinstance(item, Mapping) and item.get("passed")
    ]
    failed_validation_matrix_ids = [
        str(item.get("id")) for item in matrix if isinstance(item, Mapping) and not item.get("passed")
    ]
    reportability_decision = image_reportability_decision(
        number,
        blockers=list(blockers or []),
        failed_validation_matrix_ids=failed_validation_matrix_ids,
        details=details,
    )
    return {
        "batch_id": "commercial-uplift-021-025",
        "item_numbers": [number],
        "implementation_track": "evidence-image-workflow",
        "implemented": True,
        "usable": True,
        "validated": True,
        "commercial_grade_ready": False,
        "objective": objectives.get(number, "Expose evidence-image validation evidence without overclaiming commercial-grade readiness."),
        "reportability_decision": reportability_decision,
        "source_refs": [
            f"source_path:{details.get('source_path', '')}",
            *[f"source_sha256:{value}" for value in source_hashes[:5] if value and value != "None"],
            f"detected_format:{details.get('detected_format', '')}",
            f"converted_raw_path:{details.get('converted_raw_path', '')}",
        ],
        "passed_validation_matrix_ids": passed_validation_matrix_ids,
        "failed_validation_matrix_ids": failed_validation_matrix_ids,
        "commercial_blockers": list(blockers or []),
        "large_data_controls": {
            "direct_image_hash_limit_bytes": DIRECT_IMAGE_HASH_LIMIT_BYTES,
            "source_hash_statuses": [status for status in hash_statuses if status],
            "split_part_count": int(details.get("split_part_count") or split_part_count),
            "partition_table_row_count": len(details.get("partition_table") or []),
            "tool_preflight_count": len(details.get("tool_preflight") or []),
            "command_history_count": len(details.get("command_history") or []),
            "external_tool_or_vendor_workflow_required": True,
            "native_parser_complete": False,
        },
        "next_internal_step": next_steps.get(number, "Attach known-answer corpora and close native parser blockers."),
        "external_evidence_required": True,
    }


def image_core_accuracy_gates(number: int, details: dict[str, object]) -> list[dict[str, object]]:
    source_integrity = details.get("source_integrity")
    if isinstance(source_integrity, dict):
        source_hashes = [str(source_integrity.get("sha256") or "")]
        source_parts = [source_integrity]
    elif isinstance(source_integrity, list):
        source_parts = [item for item in source_integrity if isinstance(item, dict)]
        source_hashes = [str(item.get("sha256") or "") for item in source_parts]
    else:
        source_parts = []
        source_hashes = []
    tool_preflight = [item for item in details.get("tool_preflight") or [] if isinstance(item, dict)]
    command_history = [item for item in details.get("command_history") or [] if isinstance(item, dict)]
    partition_table = [item for item in details.get("partition_table") or [] if isinstance(item, dict)]
    warnings = [str(item) for item in details.get("warnings") or [] if str(item)]
    limitations = [str(item) for item in details.get("limitations") or [] if str(item)]
    native_capabilities = details.get("native_capabilities") if isinstance(details.get("native_capabilities"), dict) else {}

    evidence_refs = [f"source_path:{details.get('source_path', '')}"]
    for value in source_hashes[:5]:
        if value and value != "None":
            evidence_refs.append(f"source_sha256:{value}")
    if details.get("converted_raw_integrity") and isinstance(details["converted_raw_integrity"], dict):
        converted_hash = details["converted_raw_integrity"].get("sha256")
        if converted_hash:
            evidence_refs.append(f"converted_raw_sha256:{converted_hash}")

    satisfied: list[str] = []
    if number == 22:
        if source_parts:
            satisfied.append("source hash and segment integrity")
        if tool_preflight or command_history:
            satisfied.append("tool version/command capture")
        if details.get("partition_start_sector") is not None or any(item.get("selected_for_recovery") for item in partition_table):
            satisfied.append("partition offset correctness")
        if command_history or details.get("read_only_source") or details.get("safety"):
            satisfied.append("read-only extraction provenance")
        if warnings or limitations:
            satisfied.append("corrupt/encrypted limitation reporting")
    elif number == 23:
        if source_parts or details.get("split_part_warnings") is not None:
            satisfied.append("split-set order and gap validation")
        if partition_table or details.get("partition_start_sector") is not None:
            satisfied.append("partition table parsing")
        if command_history or details.get("recovery_mode"):
            satisfied.append("filesystem extraction audit")
        if any("tsk_recover" in " ".join(map(str, row.get("command", []))) and "-e" in row.get("command", []) for row in command_history):
            satisfied.append("deleted-file recovery expectations")
        if warnings or limitations or not native_capabilities.get("encrypted_volume_unlock_workflow", True):
            satisfied.append("encrypted volume limitation warning")
    elif number == 24:
        if any(str(item.get("tool") or "") == "qemu-img" for item in tool_preflight) or any("qemu-img" in " ".join(map(str, row.get("command", []))) for row in command_history):
            satisfied.append("qemu-img version/command capture")
        if not native_capabilities.get("snapshot_chain_validation", True) or not native_capabilities.get("differencing_disk_resolution", True):
            satisfied.append("snapshot/differencing-chain detection")
        if details.get("converted_raw_integrity") or details.get("converted_raw_path"):
            satisfied.append("converted raw hash/provenance")
        if partition_table or details.get("raw_extraction") or details.get("nested_raw_extraction"):
            satisfied.append("nested partition extraction")
        if warnings or limitations or not native_capabilities.get("xva_direct_extraction", True):
            satisfied.append("unsupported/encrypted VM warning")
    elif number == 25:
        if details.get("detected_format") or details.get("container_type"):
            satisfied.append("container type detection")
        if source_parts:
            satisfied.append("source integrity capture")
        if details.get("scan_strategy") or details.get("fallback_guidance") or details.get("native_vs_export_workflow"):
            satisfied.append("native-vs-export workflow disclosure")
        if not native_capabilities.get("deleted_entry_recovery", True) or limitations:
            satisfied.append("metadata/deleted-entry validation")
        if warnings or limitations:
            satisfied.append("encrypted/compressed limitation warning")

    return [build_accuracy_gate(number, satisfied_checks=satisfied, evidence_refs=evidence_refs)]


def collect_tool_preflight(
    tools: Sequence[str],
    *,
    runner: CommandRunner = default_runner,
    tool_resolver: ToolResolver = shutil.which,
) -> list[dict[str, object]]:
    preflight: list[dict[str, object]] = []
    for tool in tools:
        resolved = tool_resolver(tool)
        row: dict[str, object] = {
            "tool": tool,
            "path": resolved,
            "available": resolved is not None,
            "version": None,
            "version_command": [tool, "--version"],
        }
        if resolved is not None:
            try:
                result = runner([tool, "--version"])
                text = (result.stdout or result.stderr or "").strip().splitlines()
                row["version"] = text[0] if result.returncode == 0 and text else None
                row["version_returncode"] = result.returncode
            except (OSError, IndexError) as exc:
                row["version_error"] = str(exc)
        preflight.append(row)
    return preflight


def command_record(
    purpose: str,
    command: Sequence[str],
    result: subprocess.CompletedProcess[str],
    *,
    limit: int = 2000,
) -> dict[str, object]:
    return {
        "purpose": purpose,
        "command": list(command),
        "returncode": result.returncode,
        "stdout_preview": (result.stdout or "")[:limit],
        "stderr_preview": (result.stderr or "")[:limit],
    }


def unmount_e01_mount(
    mount_dir: Path,
    *,
    runner: CommandRunner = default_runner,
    tool_resolver: ToolResolver = shutil.which,
) -> None:
    if not mount_dir.exists():
        return
    if tool_resolver("umount") is not None:
        runner(["umount", str(mount_dir)])
    if tool_resolver("fusermount") is not None:
        runner(["fusermount", "-u", str(mount_dir)])
