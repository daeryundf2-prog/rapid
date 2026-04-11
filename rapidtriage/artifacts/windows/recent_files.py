from __future__ import annotations

from pathlib import Path
from typing import Iterable, Sequence, Tuple

from ...core.models import ArtifactRecord
from .common import isoformat_from_timestamp, iter_windows_user_homes

RECENT_ROOT = ("AppData", "Roaming", "Microsoft", "Windows", "Recent")
RECENT_PATTERNS: Tuple[Tuple[str, str, Sequence[str]], ...] = (
    ("recent-shortcut", "*.lnk", ()),
    ("jumplist-automatic", "*.automaticDestinations-ms", ("AutomaticDestinations",)),
    ("jumplist-custom", "*.customDestinations-ms", ("CustomDestinations",)),
)


class WindowsRecentFilesProvider:
    name = "windows-recent-files"
    description = "Windows Recent items and Jump Lists collected from per-user profile directories"
    target_platform = "windows"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        for user_root in iter_windows_user_homes(root):
            recent_root = user_root.joinpath(*RECENT_ROOT)
            if not recent_root.is_dir():
                continue
            for artifact_type, pattern, extra_parts in RECENT_PATTERNS:
                scan_root = recent_root.joinpath(*extra_parts)
                if not scan_root.is_dir():
                    continue
                for candidate in sorted(scan_root.glob(pattern), key=lambda item: item.name.lower()):
                    if not candidate.is_file():
                        continue
                    stat_result = candidate.stat()
                    yield ArtifactRecord(
                        provider=self.name,
                        artifact_type=artifact_type,
                        path=str(candidate.resolve()),
                        supported=self.supported(),
                        details={
                            "user": user_root.name,
                            "entry_name": candidate.name,
                            "entry_hint": candidate.stem,
                            "size": stat_result.st_size,
                            "modified_at": isoformat_from_timestamp(stat_result.st_mtime),
                        },
                    )
