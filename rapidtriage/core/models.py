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

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass
class DocumentMatch:
    path: str
    kind: str
    matched_keywords: list[str]
    preview: str
    size: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
