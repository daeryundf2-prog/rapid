from .generic import GenericDocumentArtifactProvider
from .windows.browser import WindowsBrowserArtifactsProvider
from .windows.eventlog import WindowsEventLogProvider
from .windows.recent_files import WindowsRecentFilesProvider
from .windows.registry import WindowsRegistryProvider
from .windows.shellbags import WindowsShellbagsProvider

def all_providers():
    return [
        GenericDocumentArtifactProvider(),
        WindowsBrowserArtifactsProvider(),
        WindowsRecentFilesProvider(),
        WindowsEventLogProvider(),
        WindowsRegistryProvider(),
        WindowsShellbagsProvider(),
    ]
