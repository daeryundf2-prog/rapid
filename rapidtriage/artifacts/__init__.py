from __future__ import annotations

from typing import Dict, List

from .android import AndroidApkProvider
from .cloud import CloudExportProvider
from .email import EmailArtifactsProvider
from .generic import GenericDocumentArtifactProvider
from .kakaotalk_windows import KakaoTalkWindowsProvider
from .linux import LinuxSystemArtifactsProvider
from .macos import MacOsSystemArtifactsProvider
from .media import MediaImageProvider
from .memory import MemoryVolatilityProvider
from .mobile import MobileExportProvider
from .windows.browser import WindowsBrowserArtifactsProvider
from .windows.eventlog import WindowsEventLogProvider
from .windows.execution import WindowsExecutionProvider
from .windows.filesystem import WindowsFilesystemProvider
from .windows.os_account import WindowsOsAccountProvider
from .windows.prefetch import WindowsPrefetchProvider
from .windows.recent_files import WindowsRecentFilesProvider
from .windows.registry import WindowsRegistryProvider
from .windows.remote_access import WindowsRemoteAccessProvider
from .windows.search_index import WindowsSearchIndexProvider
from .windows.shellbags import WindowsShellbagsProvider
from .windows.system import WindowsSystemArtifactsProvider


def all_providers() -> List[object]:
    return [
        GenericDocumentArtifactProvider(),
        AndroidApkProvider(),
        CloudExportProvider(),
        EmailArtifactsProvider(),
        LinuxSystemArtifactsProvider(),
        MacOsSystemArtifactsProvider(),
        MediaImageProvider(),
        MemoryVolatilityProvider(),
        MobileExportProvider(),
        KakaoTalkWindowsProvider(),
        WindowsBrowserArtifactsProvider(),
        WindowsRecentFilesProvider(),
        WindowsOsAccountProvider(),
        WindowsExecutionProvider(),
        WindowsFilesystemProvider(),
        WindowsEventLogProvider(),
        WindowsRegistryProvider(),
        WindowsRemoteAccessProvider(),
        WindowsSearchIndexProvider(),
        WindowsShellbagsProvider(),
        WindowsPrefetchProvider(),
        WindowsSystemArtifactsProvider(),
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
