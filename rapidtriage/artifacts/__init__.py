from __future__ import annotations

import importlib.util
import inspect
import os
import threading
import warnings
from collections.abc import Mapping
from pathlib import Path

from .android import AndroidApkProvider
from .cloud import CloudExportProvider
from .email import EmailArtifactsProvider
from .generic import GenericDocumentArtifactProvider
from .kakaotalk_macos import KakaoTalkMacOsProvider
from .kakaotalk_windows import KakaoTalkWindowsProvider
from .linux import LinuxSystemArtifactsProvider
from .macos import MacOsSystemArtifactsProvider
from .media import MediaImageProvider
from .memory import MemoryVolatilityProvider
from .mobile import MobileExportProvider
from .synthetic_media import SyntheticMediaProvider
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

PLUGIN_FILE_PATTERN = "*_provider.py"
PLUGIN_DIRS_ENV = "RAPIDTRIAGE_PLUGIN_DIRS"

# Per-process collect() memo shared by the manifest stage and the artifacts
# stage. A single run asks every provider for the same artifact list twice;
# keying on (collector_kind, root path) lets the second caller reuse the
# first result so each provider walks/parses the tree only once per run.
# A failed collect is memoized as its exception and re-raised to later
# callers for the same (kind, root), so the manifest stage never re-runs a
# provider that already failed (and was isolated) in the artifacts stage.
# The cache is cleared at the start of every run so a long-lived server
# process never serves stale results for a root that changed on disk.
_COLLECT_CACHE_MAX_ENTRIES = 256
_collect_cache: dict[tuple[str, str], list[object]] = {}
_collect_failures: dict[tuple[str, str], Exception] = {}
_collect_cache_lock = threading.Lock()


def collect_cached(provider: object, root_path: Path) -> list[object]:
    """Return ``provider.collect(root_path)`` cached by (kind, root)."""
    kind = str(getattr(provider, "collector_kind", "") or "").strip().lower()
    # Providers configured with non-default collector options (e.g. the
    # eventlog ``structure_rows``/``record_detail`` switches) expose an
    # ``options_key`` so differently-shaped collections never share a slot.
    options_key = str(getattr(provider, "options_key", "") or "")
    key = (f"{kind}|{options_key}" if options_key else kind, str(root_path))
    with _collect_cache_lock:
        cached = _collect_cache.get(key)
        failure = _collect_failures.get(key)
    if cached is not None:
        return cached
    if failure is not None:
        raise failure
    # collect() may return a generator; materialize once so every caller of
    # the cached value sees the full list instead of an exhausted iterator.
    try:
        items = list(provider.collect(root_path))
    except Exception as exc:
        with _collect_cache_lock:
            if len(_collect_failures) >= _COLLECT_CACHE_MAX_ENTRIES:
                _collect_failures.clear()
            _collect_failures[key] = exc
        raise
    with _collect_cache_lock:
        if len(_collect_cache) >= _COLLECT_CACHE_MAX_ENTRIES:
            _collect_cache.clear()
        _collect_cache[key] = items
    return items


def clear_collect_cache() -> None:
    with _collect_cache_lock:
        _collect_cache.clear()
        _collect_failures.clear()


def _builtin_providers() -> list[object]:
    return [
        GenericDocumentArtifactProvider(),
        AndroidApkProvider(),
        CloudExportProvider(),
        EmailArtifactsProvider(),
        LinuxSystemArtifactsProvider(),
        MacOsSystemArtifactsProvider(),
        MediaImageProvider(),
        MemoryVolatilityProvider(),
        SyntheticMediaProvider(),
        MobileExportProvider(),
        KakaoTalkMacOsProvider(),
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


def plugin_search_dirs(env: Mapping[str, str] | None = None) -> list[Path]:
    """Directories scanned for out-of-tree ``*_provider.py`` provider plugins.

    ``RAPIDTRIAGE_PLUGIN_DIRS`` entries (os.pathsep-separated) are scanned first,
    then the user plugin dir ``~/.rapidtriage/plugins/``.
    """
    environ = env if env is not None else os.environ
    dirs: list[Path] = []
    seen: set[str] = set()
    for entry in str(environ.get(PLUGIN_DIRS_ENV, "")).split(os.pathsep):
        entry = entry.strip()
        if entry:
            dirs.append(Path(entry).expanduser())
    dirs.append(Path.home() / ".rapidtriage" / "plugins")
    deduped: list[Path] = []
    for directory in dirs:
        key = str(directory)
        if key not in seen:
            seen.add(key)
            deduped.append(directory)
    return deduped


def _load_plugin_module(path: Path):
    spec = importlib.util.spec_from_file_location(f"rapidtriage_ext_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot build a module spec for {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _is_provider_class(member: object, module_name: str) -> bool:
    return (
        inspect.isclass(member)
        and member.__module__ == module_name
        and isinstance(getattr(member, "collector_kind", None), str)
        and bool(str(member.collector_kind).strip())
        and callable(getattr(member, "supported", None))
        and callable(getattr(member, "collect", None))
    )


def plugin_provider_classes(env: Mapping[str, str] | None = None) -> list[type]:
    """Import ``*_provider.py`` plugin files and return contract-conforming classes.

    A plugin file that fails to import, or that defines no class with a non-empty
    string ``collector_kind`` plus callable ``supported()``/``collect()``, is
    skipped with a RuntimeWarning — provider enumeration never crashes on a bad
    plugin. See docs/rapidtriage-provider-sdk.md for the full contract.
    """
    classes: list[type] = []
    for directory in plugin_search_dirs(env):
        try:
            is_dir = directory.is_dir()
        except OSError:
            is_dir = False
        if not is_dir:
            continue
        for path in sorted(directory.glob(PLUGIN_FILE_PATTERN)):
            try:
                module = _load_plugin_module(path)
            except Exception as exc:
                warnings.warn(
                    f"skipping RapidTriage provider plugin {path}: import failed: {exc}",
                    RuntimeWarning,
                )
                continue
            found = [
                member
                for _, member in inspect.getmembers(module, inspect.isclass)
                if _is_provider_class(member, module.__name__)
            ]
            if not found:
                warnings.warn(
                    f"skipping RapidTriage provider plugin {path}: no class implements the provider contract "
                    "(collector_kind + supported() + collect())",
                    RuntimeWarning,
                )
                continue
            classes.extend(found)
    return classes


def plugin_providers(env: Mapping[str, str] | None = None) -> list[object]:
    """Instantiate plugin provider classes, skipping ones that fail to construct."""
    providers: list[object] = []
    for cls in plugin_provider_classes(env):
        try:
            providers.append(cls())
        except Exception as exc:
            warnings.warn(
                f"skipping RapidTriage provider plugin {cls.__module__}.{cls.__name__}: "
                f"construction failed: {exc}",
                RuntimeWarning,
            )
    return providers


def all_providers() -> list[object]:
    providers = _builtin_providers()
    seen = {str(getattr(provider, "collector_kind", "")).strip().lower() for provider in providers}
    for provider in plugin_providers():
        kind = str(getattr(provider, "collector_kind", "")).strip().lower()
        if not kind:
            continue
        if kind in seen:
            warnings.warn(
                f"skipping RapidTriage provider plugin {type(provider).__module__}.{type(provider).__name__}: "
                f"collector_kind '{kind}' is already registered",
                RuntimeWarning,
            )
            continue
        seen.add(kind)
        providers.append(provider)
    return providers


def artifact_collectors() -> dict[str, object]:
    collectors: dict[str, object] = {}
    for provider in all_providers():
        collector_kind = getattr(provider, "collector_kind", None)
        if collector_kind:
            collectors[str(collector_kind).strip().lower()] = provider
    return collectors


def get_artifact_collector(kind: str) -> object:
    normalized = kind.strip().lower()
    collectors = artifact_collectors()
    if normalized not in collectors:
        supported = ", ".join(sorted(collectors))
        raise KeyError(f"unsupported artifact collector kind: {kind} (supported: {supported})")
    return collectors[normalized]
