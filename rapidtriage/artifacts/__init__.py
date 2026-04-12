from __future__ import annotations

from typing import Dict, List

from .generic import GenericDocumentArtifactProvider
from .windows.browser import WindowsBrowserArtifactsProvider
from .windows.eventlog import WindowsEventLogProvider
from .windows.recent_files import WindowsRecentFilesProvider
from .windows.registry import WindowsRegistryProvider
from .windows.shellbags import WindowsShellbagsProvider


def all_providers() -> List[object]:
    return [
        GenericDocumentArtifactProvider(),
        WindowsBrowserArtifactsProvider(),
        WindowsRecentFilesProvider(),
        WindowsEventLogProvider(),
        WindowsRegistryProvider(),
        WindowsShellbagsProvider(),
    ]


def artifact_collectors() -> Dict[str, object]:
    collectors: Dict[str, object] = {}
    for provider in all_providers():
        collector_kind = getattr(provider, "collector_kind", None)
        if collector_kind:
            collectors[str(collector_kind)] = provider
    return collectors


def get_artifact_collector(kind: str) -> object:
    normalized = kind.strip().lower()
    collectors = artifact_collectors()
    if normalized not in collectors:
        supported = ", ".join(sorted(collectors))
        raise KeyError(f"unsupported artifact collector kind: {kind} (supported: {supported})")
    return collectors[normalized]
