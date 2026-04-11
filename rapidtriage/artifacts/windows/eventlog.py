from __future__ import annotations

import platform
from pathlib import Path
from typing import Iterable

from ...core.models import ArtifactRecord


class WindowsEventLogProvider:
    name = "windows-eventlog"
    description = "Windows Event Log artifacts exposed via a dedicated provider boundary"
    target_platform = "windows"

    def supported(self) -> bool:
        return platform.system() == "Windows"

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        yield ArtifactRecord(
            provider=self.name,
            artifact_type="eventlog",
            path=str(root / "artifacts" / "windows" / "eventlog"),
            supported=self.supported(),
            details={"note": "Windows-specific provider placeholder"},
        )
