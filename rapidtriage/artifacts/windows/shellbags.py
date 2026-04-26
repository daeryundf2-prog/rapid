from __future__ import annotations

from pathlib import Path
from typing import Iterable

from ...core.models import ArtifactRecord
from .registry import collect_reg_export


class WindowsShellbagsProvider:
    name = "windows-shellbags"
    description = "Windows Shellbags from Registry .reg exports"
    target_platform = "windows"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        for path in sorted(root.rglob("*.reg"), key=lambda item: str(item).lower()):
            if not path.is_file():
                continue
            for record in collect_reg_export(path):
                key = str(record.details.get("key") or "").lower()
                if "shell\\bagmru" not in key and "shellnoroam\\bagmru" not in key:
                    continue
                details = dict(record.details)
                details["parser"] = "windows-shellbags-reg-export"
                yield ArtifactRecord(
                    provider=self.name,
                    artifact_type="shellbag-key",
                    path=record.path,
                    supported=True,
                    details=details,
                )
