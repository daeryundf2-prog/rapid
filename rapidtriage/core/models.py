from __future__ import annotations

import copy
from dataclasses import asdict, dataclass, field, is_dataclass


def _clone_value(value: object) -> object:
    """Deep copy with ``dataclasses.asdict`` results for JSON-like data.

    ``asdict`` walks every nested value through its generic dataclass
    machinery; artifact details are plain dict/list/scalar trees, so this
    specialized copy produces the same value several times faster.
    """
    value_type = type(value)
    if value_type is dict:
        return {key: _clone_value(item) for key, item in value.items()}  # type: ignore[union-attr]
    if value_type is list:
        return [_clone_value(item) for item in value]  # type: ignore[union-attr]
    if value_type in (str, int, float, bool, type(None)):
        return value
    if value_type is tuple:
        return tuple(_clone_value(item) for item in value)  # type: ignore[union-attr]
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    return copy.deepcopy(value)


@dataclass
class ArtifactRecord:
    provider: str
    artifact_type: str
    path: str
    supported: bool
    details: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "artifact_type": self.artifact_type,
            "path": self.path,
            "supported": self.supported,
            "details": _clone_value(self.details),
        }


@dataclass
class DocumentCandidate:
    path: str
    kind: str
    size: int
    modified_at: str
    # Parser-quality r1: extraction outcome per candidate (docs collection
    # lists every candidate; ``matched`` filters the keyword hits).
    text_status: str = ""
    extraction_method: str = ""
    text_length: int = 0
    encrypted: bool = False
    text_reason: str = ""
    matched: bool = False
    matched_keywords: list[str] = field(default_factory=list)
    modified_at_origin: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass
class FileCandidate:
    path: str
    name: str
    extension: str
    size: int
    modified_at: str
    modified_epoch: float
    categories: list[str]
    reasons: dict[str, list[str]]
    recovery: dict[str, object] = field(default_factory=dict)
    # Parser-quality r1 (time provenance): ``modified_at`` is the filesystem
    # time when one is known (``fs_*``), else the host time of the scanned
    # object with ``modified_at_origin`` saying which. Host times of an
    # extracted copy are kept as ``source_file_*`` (``time_origin``
    # "acquisition-copy") and are never timeline events.
    relative_path: str = ""
    time_origin: str = ""
    modified_at_origin: str = ""
    source_file_mtime: str | None = None
    source_file_ctime: str | None = None
    source_file_atime: str | None = None
    fs_modified_at: str | None = None
    fs_created_at: str | None = None
    fs_accessed_at: str | None = None
    fs_changed_at: str | None = None
    attributes: list[str] = field(default_factory=list)
    attributes_origin: str = ""
    is_deleted: bool | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass
class DocumentMatch:
    path: str
    kind: str
    matched_keywords: list[str]
    preview: str
    size: int
    # Set when every keyword occurrence sits in a known noise token
    # (``desktop.ini`` ``[.ShellClassInfo]``/``shell32.dll`` for "shell"):
    # a legitimate substring hit the report groups apart.
    noise_hint: str = ""

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        if not self.noise_hint:
            payload.pop("noise_hint")
        return payload
