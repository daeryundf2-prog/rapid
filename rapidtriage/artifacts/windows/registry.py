from __future__ import annotations

import platform
from pathlib import Path
from typing import Iterable

from ...core.models import ArtifactRecord


class WindowsRegistryProvider:
    name = "windows-registry"
    description = "Windows Registry artifacts behind a separate implementation module"
    target_platform = "windows"

    def supported(self) -> bool:
        return platform.system() == "Windows"

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        yield ArtifactRecord(
            provider=self.name,
            artifact_type="registry",
            path=str(root / "artifacts" / "windows" / "registry"),
            supported=self.supported(),
            details={"note": "Windows-specific provider placeholder"},
        )
