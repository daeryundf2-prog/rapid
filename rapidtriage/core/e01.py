from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional, Sequence

from .audit import compute_sha256

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
            "image_report_grade_assessment": image_report_grade_assessment("#22", E01_REPORT_GRADE_BLOCKERS),
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
