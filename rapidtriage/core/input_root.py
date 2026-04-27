from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union

SUPPORTED_INPUT_ROOT_KINDS = ("folder", "mounted-image", "e01-derived", "disk-image-derived", "archive-image-derived", "live")
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
    path_text = str(root_path).lower()
    if root_path == Path("/"):
        return "live"
    if "/volumes/" in path_text or "/mnt/" in path_text or "/media/" in path_text:
        if "e01" in path_text or "ewf" in path_text:
            return "e01-derived"
        return "mounted-image"
    if "e01" in path_text or "ewf" in path_text:
        return "e01-derived"
    return "folder"
