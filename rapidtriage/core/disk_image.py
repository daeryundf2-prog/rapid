from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional, Sequence

from .e01 import (
    collect_tool_preflight,
    command_record,
    describe_source_integrity,
    image_report_grade_assessment,
    image_core_accuracy_gates,
    image_validation_matrix,
    mark_selected_partition,
    mmls_first_filesystem,
    parse_mmls_partitions,
)


RAW_IMAGE_SUFFIXES = (".dd", ".raw", ".img", ".001", ".000", ".0000", ".0001", ".00001", ".ima")
RAW_IMAGE_REQUIRED_TOOLS = ("mmls", "tsk_recover")
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
                    "command_history": list(self.command_history),
                    "warnings": list(self.warnings),
                    "recovery_mode": self.recovery_mode,
                    "native_capabilities": dict(RAW_IMAGE_NATIVE_CAPABILITIES),
                    "limitations": RAW_IMAGE_REPORT_GRADE_BLOCKERS,
                },
            ),
            "image_report_grade_assessment": image_report_grade_assessment("#23", RAW_IMAGE_REPORT_GRADE_BLOCKERS),
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
    split_part_warnings = tuple(validate_split_image_parts(image_paths))
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
