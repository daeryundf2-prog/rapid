from .generic import GenericDocumentArtifactProvider
from .windows.eventlog import WindowsEventLogProvider
from .windows.registry import WindowsRegistryProvider
from .windows.shellbags import WindowsShellbagsProvider


def all_providers():
    return [
        GenericDocumentArtifactProvider(),
        WindowsEventLogProvider(),
        WindowsRegistryProvider(),
        WindowsShellbagsProvider(),
    ]
