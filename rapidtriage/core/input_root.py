from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union

SUPPORTED_INPUT_ROOT_KINDS = ("folder", "mounted-image", "e01-derived", "disk-image-derived", "archive-image-derived", "live")
EWF_IMAGE_SUFFIXES = (".e01", ".ex01")
EWF_SEGMENT_SUFFIXES = tuple(f".e{index:02d}" for index in range(1, 100))
DISK_IMAGE_SUFFIXES = (
    ".dd",
    ".raw",
    ".img",
    ".001",
    ".000",
    ".0000",
    ".0001",
    ".00001",
    ".ima",
    ".vhd",
    ".vhdx",
    ".vmdk",
    ".vdi",
    ".xva",
    ".qcow",
    ".qcow2",
)
ARCHIVE_IMAGE_SUFFIXES = (".iso", ".dmg", ".wim", ".swm")
PathLike = Union[Path, str]


@dataclass(frozen=True)
class InputRoot:
    source_path: str
    root_path: Path
    kind: str

    def to_dict(self) -> dict[str, object]:
        return {
            "source_path": self.source_path,
            "root_path": str(self.root_path),
            "kind": self.kind,
        }


class InputRootError(ValueError):
    """Raised when an input root cannot be resolved."""


def resolve_input_root(root: Union[InputRoot, PathLike], *, kind: Optional[str] = None) -> InputRoot:
    if isinstance(root, InputRoot):
        if kind is not None and kind != root.kind:
            return InputRoot(source_path=root.source_path, root_path=root.root_path, kind=normalize_input_root_kind(kind))
        return root

    root_path = Path(root).expanduser().resolve()
    normalized_kind = normalize_input_root_kind(kind) if kind else detect_input_root_kind(root_path)
    return InputRoot(source_path=str(root), root_path=root_path, kind=normalized_kind)


def derive_child_input_root(parent: Union[InputRoot, PathLike], root_path: PathLike) -> InputRoot:
    parent_root = resolve_input_root(parent)
    path = Path(root_path).expanduser().resolve()
    return InputRoot(source_path=parent_root.source_path, root_path=path, kind=parent_root.kind)


def normalize_input_root_kind(kind: str) -> str:
    normalized = kind.strip().lower()
    if normalized not in SUPPORTED_INPUT_ROOT_KINDS:
        supported = ", ".join(SUPPORTED_INPUT_ROOT_KINDS)
        raise InputRootError(f"unsupported input root kind: {kind} (supported: {supported})")
    return normalized


def detect_input_root_kind(root_path: Path) -> str:
    path_text = str(root_path).replace("\\", "/").lower()
    name = root_path.name.lower()
    suffix = root_path.suffix.lower()
    if root_path == Path("/") or (
        os.name == "nt" and root_path.drive and Path(root_path.anchor) == root_path
    ):
        return "live"
    if _looks_like_mounted_path(root_path, path_text):
        if "e01" in path_text or "ewf" in path_text:
            return "e01-derived"
        return "mounted-image"
    if suffix in EWF_IMAGE_SUFFIXES or name.endswith(EWF_SEGMENT_SUFFIXES) or "ewf" in path_text:
        return "e01-derived"
    if suffix in DISK_IMAGE_SUFFIXES:
        return "disk-image-derived"
    if suffix in ARCHIVE_IMAGE_SUFFIXES:
        return "archive-image-derived"
    return "folder"


_MOUNT_DIR_NAMES = {"volumes", "mnt", "media", "mounts"}


def _looks_like_mounted_path(root_path: Path, path_text: str) -> bool:
    if any(marker in path_text for marker in ("/volumes/", "/mnt/", "/media/", "/mounts/")):
        return True
    # Windows mount points live under a drive root; recognize common mount
    # directory names such as C:\Volumes\<case-mount>.
    parts = root_path.parts
    return bool(root_path.drive) and len(parts) >= 2 and parts[1].lower() in _MOUNT_DIR_NAMES
