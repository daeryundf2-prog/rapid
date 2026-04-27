from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Sequence


ARCHIVE_IMAGE_SUFFIXES = (".iso", ".dmg", ".wim", ".swm")
ARCHIVE_IMAGE_TOOLS = ("7zz", "7z", "bsdtar")
CommandRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]
ToolResolver = Callable[[str], Optional[str]]


class ArchiveImageExtractionError(RuntimeError):
    """Raised when an ISO/DMG/WIM-style image cannot be extracted."""


@dataclass(frozen=True)
class ArchiveImageExtractionResult:
    source_path: Path
    stage_dir: Path
    extract_dir: Path
    tool: str
    command: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "command": "archive-image-extract",
            "source_path": str(self.source_path),
            "stage_dir": str(self.stage_dir),
            "extract_dir": str(self.extract_dir),
            "tool": self.tool,
            "extract_command": list(self.command),
            "tools": list(ARCHIVE_IMAGE_TOOLS),
        }


def is_archive_image_path(path: Path) -> bool:
    return path.suffix.lower() in ARCHIVE_IMAGE_SUFFIXES


def resolve_archive_image_tool(
    suffix: str,
    *,
    tool_resolver: ToolResolver = shutil.which,
) -> str | None:
    normalized_suffix = suffix.lower()
    for tool in ("7zz", "7z"):
        if tool_resolver(tool) is not None:
            return tool
    if normalized_suffix == ".iso" and tool_resolver("bsdtar") is not None:
        return "bsdtar"
    return None


def missing_archive_image_tools(
    suffix: str,
    *,
    tool_resolver: ToolResolver = shutil.which,
) -> list[str]:
    if resolve_archive_image_tool(suffix, tool_resolver=tool_resolver):
        return []
    if suffix.lower() == ".iso":
        return ["7zz or 7z or bsdtar"]
    return ["7zz or 7z"]


def default_runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(command), capture_output=True, text=True)


def extract_archive_image_to_directory(
    image_path: Path,
    stage_dir: Path,
    *,
    runner: CommandRunner = default_runner,
    tool_resolver: ToolResolver = shutil.which,
) -> ArchiveImageExtractionResult:
    source_path = image_path.expanduser().resolve()
    if not source_path.is_file():
        raise ArchiveImageExtractionError(f"archive image not found: {source_path}")
    if not is_archive_image_path(source_path):
        raise ArchiveImageExtractionError(f"unsupported archive image extension: {source_path.name}")

    tool = resolve_archive_image_tool(source_path.suffix, tool_resolver=tool_resolver)
    if tool is None:
        joined = ", ".join(missing_archive_image_tools(source_path.suffix, tool_resolver=tool_resolver))
        raise ArchiveImageExtractionError(
            f"{source_path.suffix.upper().lstrip('.')} direct input requires external extraction tools: {joined}. "
            "Install 7-Zip/bsdtar or mount/export the image first."
        )

    stage = stage_dir.expanduser().resolve()
    extract_dir = stage / "filesystem"
    stage.mkdir(parents=True, exist_ok=True)
    extract_dir.mkdir(parents=True, exist_ok=True)

    if tool == "bsdtar":
        command = (tool, "-xf", str(source_path), "-C", str(extract_dir))
    else:
        command = (tool, "x", "-y", f"-o{extract_dir}", str(source_path))

    result = runner(command)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise ArchiveImageExtractionError(f"{tool} failed for archive image: {detail}")

    return ArchiveImageExtractionResult(
        source_path=source_path,
        stage_dir=stage,
        extract_dir=extract_dir,
        tool=tool,
        command=command,
    )
