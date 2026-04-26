from __future__ import annotations

from pathlib import Path
from typing import Iterable

from ...core.models import ArtifactRecord
from .common import isoformat_from_timestamp

PREFETCH_ROOT = ("Windows", "Prefetch")
PARSER_VERSION = "prefetch-inventory-v1"


class WindowsPrefetchProvider:
    name = "windows-prefetch"
    description = "Windows Prefetch execution artifact inventory"
    target_platform = "windows"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        prefetch_root = root.joinpath(*PREFETCH_ROOT)
        if not prefetch_root.is_dir():
            return
        for path in sorted(prefetch_root.glob("*.pf"), key=lambda item: item.name.lower()):
            if not path.is_file():
                continue
            stat_result = path.stat()
            yield ArtifactRecord(
                provider=self.name,
                artifact_type="prefetch-file",
                path=str(path.resolve()),
                supported=True,
                details={
                    "parser": "windows-prefetch-inventory",
                    "parser_version": PARSER_VERSION,
                    "source_path": str(path.resolve()),
                    "source_format": "pf",
                    "executable_hint": executable_hint(path.name),
                    "entry_name": path.name,
                    "size": stat_result.st_size,
                    "modified_at": isoformat_from_timestamp(stat_result.st_mtime),
                    "note": "Prefetch binary inventory; full run-count parsing requires a dedicated PF parser.",
                },
            )


def executable_hint(name: str) -> str:
    stem = Path(name).stem
    if "-" not in stem:
        return stem
    return stem.rsplit("-", 1)[0]
