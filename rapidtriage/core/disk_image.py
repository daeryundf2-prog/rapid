from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Sequence

from .e01 import mmls_first_filesystem


RAW_IMAGE_SUFFIXES = (".dd", ".raw", ".img", ".001", ".000", ".0000", ".0001", ".00001", ".ima")
RAW_IMAGE_REQUIRED_TOOLS = ("mmls", "tsk_recover")
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
    if missing:
        joined = ", ".join(missing)
        raise DiskImageExtractionError(
            f"Raw/split image direct input requires external tools: {joined}. "
            "Install Sleuth Kit or mount/export the image first."
        )

    image_paths = tuple(discover_split_image_parts(source_path))
    stage = stage_dir.expanduser().resolve()
    extract_dir = stage / "filesystem"
    stage.mkdir(parents=True, exist_ok=True)
    extract_dir.mkdir(parents=True, exist_ok=True)

    mmls_result = runner(["mmls", *[str(path) for path in image_paths]])
    start_sector = mmls_first_filesystem(mmls_result.stdout) if mmls_result.returncode == 0 else None

    command = ["tsk_recover", "-e", "-a"]
    recovery_mode = "whole-image"
    if start_sector is not None:
        command.extend(["-o", str(start_sector)])
        recovery_mode = "partition-offset"
    command.extend([*[str(path) for path in image_paths], str(extract_dir)])

    recover_result = runner(command)
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
