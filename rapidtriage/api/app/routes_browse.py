"""Local filesystem browse API backing the run-intake file picker.

``GET /api/browse`` lists filesystem roots (drive letters on Windows, ``/`` on
POSIX) and ``GET /api/browse?path=<abs path>`` lists one directory level.
Listings are bounded, non-recursive, and skip hidden entries; the route sits
behind the same token middleware as every other ``/api`` route.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query

BROWSE_ENTRY_LIMIT = 200
_WINDOWS_HIDDEN_ATTRIBUTE = 0x2  # FILE_ATTRIBUTE_HIDDEN


def _is_hidden(entry: os.DirEntry[str]) -> bool:
    if entry.name.startswith("."):
        return True
    try:
        attributes = getattr(entry.stat(follow_symlinks=False), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(attributes & _WINDOWS_HIDDEN_ATTRIBUTE)


def _entry_for(path: Path, *, is_dir: bool | None = None, size: int | None = None) -> dict[str, Any]:
    return {"name": path.name or str(path), "path": str(path), "is_dir": bool(is_dir), "size": size}


def _direntry_payload(entry: os.DirEntry[str]) -> dict[str, Any]:
    try:
        is_dir = entry.is_dir()
    except OSError:
        is_dir = False
    size: int | None = None
    if not is_dir:
        try:
            size = entry.stat().st_size
        except OSError:
            size = None
    return _entry_for(Path(entry.path), is_dir=is_dir, size=size)


def _root_entries() -> list[dict[str, Any]]:
    roots: list[Path] = []
    listdrives = getattr(os, "listdrives", None)  # Windows-only (Python 3.12+)
    if listdrives is not None:
        try:
            roots.extend(Path(drive) for drive in listdrives())
        except OSError:
            pass
    if not roots:
        roots.append(Path("/"))
    userprofile = os.environ.get("USERPROFILE", "").strip()
    if userprofile:
        roots.append(Path(userprofile))
    roots.append(Path.home())
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for root in roots:
        resolved = root.expanduser().resolve()
        key = str(resolved)
        if key in seen or not resolved.is_dir():
            continue
        seen.add(key)
        entries.append(_entry_for(resolved, is_dir=True))
    return entries


def build_browse_router() -> APIRouter:
    router = APIRouter()

    @router.get("/api/browse")
    def browse(path: str | None = Query(default=None, max_length=4096)) -> dict[str, Any]:
        if not path or not path.strip():
            return {"path": None, "parent": None, "entries": _root_entries(), "truncated": False}
        resolved = Path(path).expanduser().resolve()
        if not resolved.exists():
            raise HTTPException(status_code=404, detail=f"path not found: {resolved}")
        parent = resolved.parent
        parent_value = None if parent == resolved else str(parent)
        if not resolved.is_dir():
            try:
                size: int | None = resolved.stat().st_size
            except OSError:
                size = None
            return {
                "path": str(resolved),
                "parent": parent_value,
                "entries": [_entry_for(resolved, is_dir=False, size=size)],
                "truncated": False,
            }
        visible: list[dict[str, Any]] = []
        truncated = False
        try:
            with os.scandir(resolved) as iterator:
                for child in iterator:
                    if _is_hidden(child):
                        continue
                    if len(visible) >= BROWSE_ENTRY_LIMIT:
                        truncated = True
                        break
                    visible.append(_direntry_payload(child))
        except OSError as exc:
            raise HTTPException(status_code=403, detail=f"cannot list directory: {exc}") from exc
        visible.sort(key=lambda item: (not item["is_dir"], str(item["name"]).lower()))
        return {
            "path": str(resolved),
            "parent": parent_value,
            "entries": visible,
            "truncated": truncated,
        }

    return router
