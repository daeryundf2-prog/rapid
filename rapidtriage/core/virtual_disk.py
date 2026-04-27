from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Sequence

from .disk_image import DiskImageExtractionResult, extract_raw_image_to_directory, missing_raw_image_tools


VIRTUAL_DISK_SUFFIXES = (".vhd", ".vhdx", ".vmdk", ".vdi", ".xva", ".qcow", ".qcow2")
QEMU_CONVERTIBLE_SUFFIXES = (".vhd", ".vhdx", ".vmdk", ".vdi", ".qcow", ".qcow2")
VIRTUAL_DISK_REQUIRED_TOOLS = ("qemu-img", "mmls", "tsk_recover")
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
        }


def is_virtual_disk_path(path: Path) -> bool:
    return path.suffix.lower() in VIRTUAL_DISK_SUFFIXES


def can_convert_virtual_disk_suffix(suffix: str) -> bool:
    return suffix.lower() in QEMU_CONVERTIBLE_SUFFIXES


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
        raise VirtualDiskExtractionError("XVA direct extraction is not implemented yet; export or convert the virtual disk first.")

    missing = missing_virtual_disk_tools(source_path.suffix, tool_resolver=tool_resolver)
    if missing:
        joined = ", ".join(missing)
        raise VirtualDiskExtractionError(
            f"{source_path.suffix.upper().lstrip('.')} direct input requires external tools: {joined}. "
            "Install qemu-img and Sleuth Kit or mount/export the virtual disk first."
        )

    stage = stage_dir.expanduser().resolve()
    convert_dir = stage / "converted"
    convert_dir.mkdir(parents=True, exist_ok=True)
    converted_raw = convert_dir / f"{source_path.stem}.raw"

    convert_command = ["qemu-img", "convert", "-O", "raw", str(source_path), str(converted_raw)]
    convert_result = runner(convert_command)
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
    )
