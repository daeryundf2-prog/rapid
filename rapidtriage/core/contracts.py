from __future__ import annotations

from pathlib import Path
from typing import Iterable, Protocol

from .models import ArtifactRecord


class ArtifactProvider(Protocol):
    name: str
    description: str
    target_platform: str

    def supported(self) -> bool:
        ...

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        ...
