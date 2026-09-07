from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Protocol

from .models import ArtifactRecord


class ArtifactProvider(Protocol):
    name: str
    description: str
    target_platform: str

    def supported(self) -> bool:
        ...

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        ...
