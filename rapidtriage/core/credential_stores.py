"""Well-known credential stores of the machine the server runs on (R8 T-350).

Two consumers:

* remote folder browsing (``/api/browse`` with ``--remote``) never lists these folders / files,
  even with ``show_hidden=true``, and refuses to open them;
* an imported run's evidence root is never accepted when it contains one of them (or lies inside
  one), so a forged run summary cannot turn the examiner's own keys into "evidence".

A path is a credential store when its trailing parts (case-insensitive) match one of
:data:`STORE_DIR_SUFFIXES` — ``.ssh``, ``.gnupg``, ``.aws``, ``.azure``, ``.kube``,
``.config/gcloud``, the Windows credential / DPAPI / vault folders and the registry hive folder
(``System32/config``) — or, for a file, its name is a browser password / cookie store
(Chromium ``Login Data`` / ``Cookies`` / ``Web Data``, Firefox ``logins.json`` / ``key4.db``).
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path, PurePath

__all__ = [
    "BROWSER_STORE_FILE_NAMES",
    "STORE_DIR_SUFFIXES",
    "is_credential_store_path",
    "known_credential_store_dirs",
]

#: Folder suffixes (lower-case path parts) of credential stores.
STORE_DIR_SUFFIXES: tuple[tuple[str, ...], ...] = (
    (".ssh",),
    (".gnupg",),
    (".aws",),
    (".azure",),
    (".kube",),
    (".config", "gcloud"),
    # Windows Credential Manager, DPAPI master keys, vaults, machine keys.
    ("microsoft", "credentials"),
    ("microsoft", "protect"),
    ("microsoft", "vault"),
    ("microsoft", "crypto"),
    # SAM / SECURITY / SYSTEM registry hives of the running system.
    ("system32", "config"),
)

#: File names (lower-case) of browser password / cookie stores.
BROWSER_STORE_FILE_NAMES = frozenset(
    {
        "login data",
        "login data-journal",
        "login data for account",
        "login data for account-journal",
        "cookies",
        "cookies-journal",
        "web data",
        "web data-journal",
        "logins.json",
        "key4.db",
        "key3.db",
    }
)


def _lower_parts(path: PurePath) -> tuple[str, ...]:
    return tuple(part.lower().rstrip("\\/") for part in path.parts)


def is_credential_store_path(path: PurePath | str) -> bool:
    """True when ``path`` is a credential store folder / file or lies inside one."""
    parts = _lower_parts(PurePath(path))
    if parts and parts[-1] in BROWSER_STORE_FILE_NAMES:
        return True
    for suffix in STORE_DIR_SUFFIXES:
        width = len(suffix)
        for index in range(len(parts) - width + 1):
            if parts[index : index + width] == suffix:
                return True
    return False


def known_credential_store_dirs(home: Path | None = None) -> list[Path]:
    """Absolute credential store folders of this machine's user (they need not exist)."""
    home = home if home is not None else Path.home()
    dirs: list[Path] = [home / Path(*suffix) for suffix in STORE_DIR_SUFFIXES if suffix[0].startswith(".")]
    appdata_roots: list[Path] = []
    for env, fallback in (("APPDATA", home / "AppData" / "Roaming"), ("LOCALAPPDATA", home / "AppData" / "Local")):
        value = os.environ.get(env)
        appdata_roots.append(Path(value) if value else fallback)
    for base in _unique(appdata_roots):
        for name in ("Credentials", "Protect", "Vault", "Crypto"):
            dirs.append(base / "Microsoft" / name)
    # Browser profile folders hold the Login Data / Cookies stores.
    dirs.extend(
        [
            home / "AppData" / "Local" / "Google" / "Chrome" / "User Data",
            home / "AppData" / "Local" / "Microsoft" / "Edge" / "User Data",
            home / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles",
            home / "Library" / "Application Support" / "Google" / "Chrome",
            home / "Library" / "Keychains",
            home / ".config" / "google-chrome",
            home / ".mozilla",
        ]
    )
    system_root = os.environ.get("SystemRoot") or os.environ.get("SYSTEMROOT")
    if system_root:
        dirs.append(Path(system_root) / "System32" / "config")
    return _unique(dirs)


def _unique(paths: Iterable[Path]) -> list[Path]:
    result: list[Path] = []
    for path in paths:
        if path not in result:
            result.append(path)
    return result
