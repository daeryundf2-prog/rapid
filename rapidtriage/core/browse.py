"""Bounded local filesystem browsing for the analyst console picker.

The web console is a local tool; analysts need to pick evidence paths without
typing absolute paths by hand. This module lists directories only — it never
reads file contents — and marks known evidence suffixes so images stand out.

Deployment note: browsing enumerates the filesystem of the machine running the
API server. For remote deployments that path is the server's disk, not the
analyst's; a remote-capable picker would need an upload or local-agent flow.
The /api/* token middleware still applies when auth is configured.
"""

from __future__ import annotations

import os
from pathlib import Path

from .evidence import ADAPTERS

BROWSE_ENTRY_LIMIT = 400
BROWSE_PROFILE_VERSION = "fs-browse-v1"

EVIDENCE_FILE_SUFFIXES = frozenset(
    suffix.lower()
    for adapter in ADAPTERS
    for suffix in adapter.supported_suffixes
) | frozenset({
    # Common analyst-visible evidence containers beyond adapter suffixes.
    ".zip", ".7z", ".tar", ".gz", ".sqlite", ".db", ".sqlite3",
})

_EXTRA_EWF_FAMILY = frozenset({".e02", ".e03", ".e04", ".e05", ".ex02", ".ex03", ".ex04", ".ex05"})


class BrowseError(ValueError):
    """Raised when a browse path cannot be listed."""


def list_roots() -> list[str]:
    """Return filesystem roots the picker can jump between.

    Windows needs real drive letters — ``C:\\`` has no parent so the up
    button can never reach ``D:\\`` evidence. POSIX exposes a single root.
    """
    listdrives = getattr(os, "listdrives", None)
    if listdrives is not None:
        try:
            drives = [str(drive) for drive in listdrives()]
            if drives:
                return drives
        except OSError:
            pass
    if os.name == "nt":
        return [
            f"{letter}:\\"
            for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ"
            if Path(f"{letter}:\\").exists()
        ]
    return [os.sep]


def _is_evidence_candidate(path: Path) -> bool:
    suffix = path.suffix.lower()
    return suffix in EVIDENCE_FILE_SUFFIXES or suffix in _EXTRA_EWF_FAMILY


def browse_directory(
    path: Path | str | None,
    *,
    show_hidden: bool = False,
    limit: int = BROWSE_ENTRY_LIMIT,
) -> dict[str, object]:
    """List a directory for the path picker. Directories sort first.

    Only names, kinds, sizes and evidence-suffix flags are returned; file
    contents are never read. ``limit`` bounds entries per directory.
    """
    resolved = Path(path).expanduser() if path else Path.home()
    try:
        resolved = resolved.resolve()
    except OSError as exc:
        raise BrowseError(f"경로를 확인할 수 없습니다: {exc}") from exc
    if not resolved.exists():
        raise BrowseError(f"경로가 없습니다: {resolved}")
    if not resolved.is_dir():
        if resolved.is_file():
            resolved = resolved.parent
        else:
            raise BrowseError(f"폴더가 아닙니다: {resolved}")

    rows: list[dict[str, object]] = []
    truncated = False
    skipped_hidden = 0
    try:
        children = sorted(
            resolved.iterdir(),
            key=lambda child: (not child.is_dir(), child.name.casefold()),
        )
    except OSError as exc:
        raise BrowseError(f"폴더를 읽을 수 없습니다: {exc}") from exc
    for child in children:
        if len(rows) >= limit:
            truncated = True
            break
        if not show_hidden and child.name.startswith("."):
            skipped_hidden += 1
            continue
        try:
            is_dir = child.is_dir()
        except OSError:
            continue
        entry: dict[str, object] = {
            "name": child.name,
            "path": str(child),
            "kind": "directory" if is_dir else "file",
        }
        if is_dir:
            entry["evidence_candidate"] = True
        else:
            try:
                entry["size_bytes"] = child.stat().st_size
            except OSError:
                entry["size_bytes"] = None
            entry["evidence_candidate"] = _is_evidence_candidate(child)
        rows.append(entry)

    parent = resolved.parent
    return {
        "profile_version": BROWSE_PROFILE_VERSION,
        "path": str(resolved),
        "parent": str(parent) if parent != resolved else None,
        "home": str(Path.home()),
        "separator": os.sep,
        "roots": list_roots(),
        "entries": rows,
        "entry_count": len(rows),
        "truncated": truncated,
        "hidden_count": skipped_hidden,
        "limit": limit,
    }
