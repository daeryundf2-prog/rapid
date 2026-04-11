from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Dict, List


@dataclass
class ArtifactRecord:
    provider: str
    artifact_type: str
    path: str
    supported: bool
    details: Dict[str, object]

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass
class DocumentCandidate:
    path: str
    kind: str
    size: int
    modified_at: str

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass
class FileCandidate:
    path: str
    name: str
    extension: str
    size: int
    modified_at: str
    modified_epoch: float
    categories: List[str]
    reasons: Dict[str, List[str]]

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass
class DocumentMatch:
    path: str
    kind: str
    matched_keywords: List[str]
    preview: str
    size: int

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)
