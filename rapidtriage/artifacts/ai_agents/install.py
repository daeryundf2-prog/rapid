"""Install traces of catalog AI tools (R7 stage 3.5 §3.4, lane A).

``ai-tool-presence`` rows with ``install_kind``:

``npm-global``        ``<global node_modules>/<package>/package.json`` (version from it)
``pip``               ``<site-packages>/<name>-<version>.dist-info``, pipx / uv tool venvs
``winget``            ``AppData/Local/Microsoft/WinGet/Packages/<Id>_<source>`` (portable installs)
``msix``              ``AppData/Local/Packages/<PackageFamilyName>``, ``Program Files/WindowsApps/<Name>_<ver>_…__<hash>``
``vscode-extension``  ``<editor>/extensions/<publisher.name>-<version>`` for VS Code, Cursor, Windsurf,
                      Antigravity, Kiro, Devin, Trae, VSCodium and remote servers

Package names come from the catalog (``install`` / ``install_artifacts`` notes). Only directory
names and ``package.json`` / ``METADATA``-free dist-info names are read.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterator
from pathlib import Path

from ...core.ai_catalog.catalog import AiCatalog, AiTool, DirCache
from .base import AiRow, EvidenceProfile, mtime_iso, profile_account_key
from .presence import read_manifest_version

__all__ = ["install_rows_for_profile"]

PARSER = "ai-tool-install"
# (relative to the home, glob segments allowed) — global node_modules folders.
_NPM_HOME_DIRS: tuple[tuple[str, ...], ...] = (
    ("AppData", "Roaming", "npm", "node_modules"),
    ("AppData", "Local", "pnpm", "global", "*", "node_modules"),
    (".npm-global", "lib", "node_modules"),
    (".local", "lib", "node_modules"),
    (".nvm", "versions", "node", "*", "lib", "node_modules"),
    (".volta", "tools", "image", "packages"),
    (".bun", "install", "global", "node_modules"),
    ("AppData", "Roaming", "nvm", "*", "node_modules"),
)
_NPM_SYSTEM_DIRS: tuple[tuple[str, ...], ...] = (
    ("usr", "local", "lib", "node_modules"),
    ("usr", "lib", "node_modules"),
    ("opt", "homebrew", "lib", "node_modules"),
    ("Program Files", "nodejs", "node_modules"),
)
_SITE_HOME_DIRS: tuple[tuple[str, ...], ...] = (
    ("AppData", "Local", "Programs", "Python", "*", "Lib", "site-packages"),
    ("AppData", "Roaming", "Python", "*", "site-packages"),
    ("AppData", "Local", "Packages", "PythonSoftwareFoundation.Python.*", "LocalCache", "local-packages", "*", "site-packages"),
    (".local", "lib", "*", "site-packages"),
    ("Library", "Python", "*", "lib", "python", "site-packages"),
    ("miniconda3", "lib", "*", "site-packages"),
    ("anaconda3", "lib", "*", "site-packages"),
    ("miniconda3", "Lib", "site-packages"),
    ("anaconda3", "Lib", "site-packages"),
)
_SITE_SYSTEM_DIRS: tuple[tuple[str, ...], ...] = (
    ("usr", "lib", "*", "site-packages"),
    ("usr", "lib", "*", "dist-packages"),
    ("usr", "local", "lib", "*", "site-packages"),
    ("usr", "local", "lib", "*", "dist-packages"),
    ("Program Files", "Python*", "Lib", "site-packages"),
)
_VENV_HOME_DIRS: tuple[tuple[str, ...], ...] = (
    (".local", "pipx", "venvs"),
    (".local", "share", "pipx", "venvs"),
    ("pipx", "venvs"),
    (".local", "share", "uv", "tools"),
    ("AppData", "Roaming", "uv", "tools"),
)
_EDITOR_EXTENSION_DIRS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("vscode", (".vscode", "extensions")),
    ("vscode-insiders", (".vscode-insiders", "extensions")),
    ("vscodium", (".vscode-oss", "extensions")),
    ("vscode-server", (".vscode-server", "extensions")),
    ("cursor", (".cursor", "extensions")),
    ("windsurf", (".windsurf", "extensions")),
    ("antigravity", (".antigravity", "extensions")),
    ("kiro", (".kiro", "extensions")),
    ("devin", (".devin", "extensions")),
    ("trae", (".trae", "extensions")),
    ("void", (".void-editor", "extensions")),
)
_GLOB = set("*?[")


def _resolve(base: Path, parts: tuple[str, ...], cache: DirCache) -> list[Path]:
    current = [base]
    for part in parts:
        lowered = part.lower()
        following: list[Path] = []
        for folder in current:
            for name, path, is_dir in cache.entries(folder):
                if not is_dir:
                    continue
                if (set(part) & _GLOB and fnmatch.fnmatchcase(name, lowered)) or name == lowered:
                    following.append(path)
        current = following[:64]
        if not current:
            break
    return current


def _row(
    tool: AiTool,
    profile: EvidenceProfile,
    path: Path,
    *,
    install_kind: str,
    package: str,
    version: str,
    extra: dict[str, object] | None = None,
) -> AiRow:
    modified = mtime_iso(path)
    return AiRow(
        artifact_type="ai-tool-presence",
        tool=tool.id,
        tool_label=tool.label,
        account_key=profile_account_key(profile),
        profile_label=profile.label,
        user=profile.user,
        path=str(path),
        timestamp=modified,
        timestamp_kind="modified" if modified else "",
        modified_at=modified,
        coverage_status=tool.coverage_status(),
        parser=PARSER,
        payload={
            "install_kind": install_kind,
            "source": f"install:{install_kind}",
            "category": tool.category,
            "vendor": tool.vendor,
            "package": package,
            "version": version,
            "mtime": modified,
            "retention": tool.retention,
            "retention_auto_delete": tool.retention_auto_delete,
            "catalog_confidence": tool.confidence,
            "os": profile.os,
            **(extra or {}),
        },
    )


def _bases(profile: EvidenceProfile, home_dirs: tuple[tuple[str, ...], ...], system_dirs: tuple[tuple[str, ...], ...], cache: DirCache) -> list[Path]:
    found: list[Path] = []
    for parts in home_dirs:
        found.extend(_resolve(profile.home, parts, cache))
    if profile.system_root is not None:
        for parts in system_dirs:
            found.extend(_resolve(profile.system_root, parts, cache))
    return found


def _npm_rows(catalog: AiCatalog, profile: EvidenceProfile, cache: DirCache) -> Iterator[AiRow]:
    bases = _bases(profile, _NPM_HOME_DIRS, _NPM_SYSTEM_DIRS, cache)
    for tool in catalog.product_tools:
        for package in tool.install.get("npm", ()):
            for base in bases:
                folder = base.joinpath(*package.split("/"))
                if (folder / "package.json").is_file():
                    yield _row(tool, profile, folder, install_kind="npm-global", package=package, version=read_manifest_version(folder))


def _dist_name(name: str) -> str:
    return re.sub(r"[-_.]+", "_", name).lower()


def _pip_rows(catalog: AiCatalog, profile: EvidenceProfile, cache: DirCache) -> Iterator[AiRow]:
    sites = _bases(profile, _SITE_HOME_DIRS, _SITE_SYSTEM_DIRS, cache)
    venv_roots = _bases(profile, _VENV_HOME_DIRS, (), cache)
    for tool in catalog.product_tools:
        for package in tool.install.get("pip", ()):
            wanted = _dist_name(package)
            for site in sites:
                for name, path, is_dir in cache.entries(site):
                    if not is_dir or not name.endswith(".dist-info"):
                        continue
                    stem = name[: -len(".dist-info")]
                    dist, _sep, version = stem.rpartition("-")
                    if _dist_name(dist) == wanted:
                        yield _row(tool, profile, path, install_kind="pip", package=package, version=version, extra={"site_packages": str(site)})
            for root in venv_roots:
                for name, path, is_dir in cache.entries(root):
                    if is_dir and _dist_name(name) == wanted:
                        yield _row(tool, profile, path, install_kind="pip", package=package, version="", extra={"venv": True})


def _winget_rows(catalog: AiCatalog, profile: EvidenceProfile, cache: DirCache) -> Iterator[AiRow]:
    folder = profile.home / "AppData" / "Local" / "Microsoft" / "WinGet" / "Packages"
    entries = cache.entries(folder)
    if not entries:
        return
    for tool in catalog.product_tools:
        for package_id in tool.install.get("winget", ()):
            prefix = package_id.lower() + "_"
            for name, path, is_dir in entries:
                if is_dir and name.startswith(prefix):
                    yield _row(tool, profile, path, install_kind="winget", package=package_id, version="")


def _msix_rows(catalog: AiCatalog, profile: EvidenceProfile, cache: DirCache) -> Iterator[AiRow]:
    packages = cache.entries(profile.home / "AppData" / "Local" / "Packages")
    windows_apps = cache.entries(profile.system_root / "Program Files" / "WindowsApps") if profile.system_root is not None else []
    for tool in catalog.product_tools:
        seen: set[str] = set()
        for family in tool.install.get("msix", ()):
            lowered = family.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            name_part, _sep, publisher = lowered.rpartition("_")
            for name, path, is_dir in packages:
                if is_dir and name == lowered:
                    yield _row(tool, profile, path, install_kind="msix", package=family, version="", extra={"msix_location": "user-packages"})
            for name, path, is_dir in windows_apps:
                if is_dir and name.startswith(name_part + "_") and name.endswith("__" + publisher):
                    version = name[len(name_part) + 1 :].split("_", 1)[0]
                    yield _row(tool, profile, path, install_kind="msix", package=family, version=version, extra={"msix_location": "WindowsApps"})


def _extension_rows(catalog: AiCatalog, profile: EvidenceProfile, cache: DirCache) -> Iterator[AiRow]:
    folders = [(editor, profile.home.joinpath(*parts)) for editor, parts in _EDITOR_EXTENSION_DIRS]
    listings = [(editor, cache.entries(folder)) for editor, folder in folders]
    if not any(entries for _editor, entries in listings):
        return
    emitted: set[str] = set()
    # IDE-agent entries first: an extension listed by both "Cline" and "Cline CLI" belongs to the IDE tool.
    for tool in sorted(catalog.product_tools, key=lambda item: item.category != "ide_agent"):
        for extension_id in tool.install.get("vscode-extension", ()):
            prefix = extension_id.lower() + "-"
            for editor, entries in listings:
                for name, path, is_dir in entries:
                    if not is_dir or not name.startswith(prefix):
                        continue
                    suffix = name[len(prefix) :]
                    if not re.match(r"\d", suffix) or str(path).lower() in emitted:
                        continue  # ``github.copilot-chat-…`` is not ``github.copilot``
                    emitted.add(str(path).lower())
                    version = read_manifest_version(path) or suffix.split("-", 1)[0]
                    yield _row(
                        tool,
                        profile,
                        path,
                        install_kind="vscode-extension",
                        package=extension_id,
                        version=version,
                        extra={"editor": editor},
                    )


def install_rows_for_profile(catalog: AiCatalog, profile: EvidenceProfile, cache: DirCache) -> Iterator[AiRow]:
    """Every install-trace presence row of one profile (npm, pip, winget, msix, editor extensions)."""
    yield from _npm_rows(catalog, profile, cache)
    yield from _pip_rows(catalog, profile, cache)
    if profile.os in ("windows", "unknown"):
        yield from _winget_rows(catalog, profile, cache)
        yield from _msix_rows(catalog, profile, cache)
    yield from _extension_rows(catalog, profile, cache)
