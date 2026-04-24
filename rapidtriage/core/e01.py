from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Sequence


E01_REQUIRED_TOOLS = ("ewfmount", "mmls", "tsk_recover")
E01_SUFFIXES = (".e01", ".ex01")
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
    if missing:
        joined = ", ".join(missing)
        raise E01ExtractionError(
            f"E01 direct input requires external tools: {joined}. "
            "Install libewf/sleuthkit or mount/extract the image first."
        )

    stage = stage_dir.expanduser().resolve()
    mount_dir = stage / "_ewfmount"
    raw_image = mount_dir / "ewf1"
    extract_dir = stage / "filesystem"
    stage.mkdir(parents=True, exist_ok=True)
    mount_dir.mkdir(parents=True, exist_ok=True)
    extract_dir.mkdir(parents=True, exist_ok=True)

    try:
        mount_result = runner(["ewfmount", str(source_path), str(mount_dir)])
        if mount_result.returncode != 0:
            raise E01ExtractionError(f"ewfmount failed: {mount_result.stderr.strip()}")
        if not raw_image.exists():
            raise E01ExtractionError(f"ewfmount did not expose expected raw image: {raw_image}")

        mmls_result = runner(["mmls", str(raw_image)])
        if mmls_result.returncode != 0:
            raise E01ExtractionError(f"mmls failed: {mmls_result.stderr.strip()}")
        start_sector = mmls_first_filesystem(mmls_result.stdout)
        if start_sector is None:
            raise E01ExtractionError("mmls could not find a FAT/exFAT/NTFS/basic-data filesystem partition")

        recover_result = runner(
            ["tsk_recover", "-e", "-a", "-o", str(start_sector), str(raw_image), str(extract_dir)]
        )
        if recover_result.returncode != 0:
            raise E01ExtractionError(f"tsk_recover failed: {recover_result.stderr.strip()}")
        return E01ExtractionResult(
            source_path=source_path,
            stage_dir=stage,
            mount_dir=mount_dir,
            raw_image_path=raw_image,
            extract_dir=extract_dir,
            partition_start_sector=start_sector,
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
        if any(token in description for token in ("fat", "exfat", "ntfs", "basic data", "msdos")):
            if size > best_size:
                best_start = start
                best_size = size
    return best_start


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
