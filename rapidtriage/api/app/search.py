from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path

from fastapi import HTTPException

from .models import (
    BookmarkCreateRequest,
)


def source_search_locator(match: dict[str, object]) -> dict[str, object]:
    locator: dict[str, object] = {
        "line": match.get("line"),
        "offset": match.get("offset"),
        "keyword": match.get("keyword"),
    }
    for key in ("table", "column", "row_number", "rowid", "primary_key_values"):
        if key in match:
            locator[key] = match[key]
    if isinstance(match.get("source_viewer_locator"), Mapping):
        locator["source_viewer_locator"] = dict(match["source_viewer_locator"])
    elif isinstance(match.get("sqlite_row_locator"), Mapping):
        locator["source_viewer_locator"] = dict(match["sqlite_row_locator"])
    for key in ("offset_hex", "byte_length"):
        if key in match:
            locator[key] = match[key]
    return locator


def source_search_citation(source_path: Path, match: dict[str, object], locator: dict[str, object]) -> str:
    if locator.get("table"):
        return (
            f"{source_path.name} table {locator.get('table')} row {locator.get('row_number')} "
            f"column {locator.get('column')} keyword {locator.get('keyword')}"
        )
    if locator.get("offset_hex"):
        return (
            f"{source_path.name} byte offset {locator.get('offset_hex')} "
            f"length {locator.get('byte_length')} keyword {locator.get('keyword')}"
        )
    return f"{source_path.name} line {locator.get('line')} offset {locator.get('offset')} keyword {locator.get('keyword')}"


def source_search_source_digest(source_path: Path) -> str:
    try:
        normalized = str(source_path.resolve())
    except OSError:
        normalized = str(source_path)
    return hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()


def source_search_keywords_digest(keywords: Sequence[str]) -> str:
    normalized = sorted(str(item).strip().lower() for item in keywords if str(item).strip())
    return hashlib.sha256(json.dumps(normalized, ensure_ascii=False).encode("utf-8")).hexdigest()


def snippet_around(text: str, index: int, length: int, *, context: int) -> str:
    start = max(0, index - context)
    end = min(len(text), index + length + context)
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(text) else ""
    return f"{prefix}{text[start:end].strip()}{suffix}"


def normalize_bookmark_source(source: str) -> str:
    normalized = source.strip()
    aliases = {
        "timeline": "timeline",
        "files": "files",
        "docs": "docs",
        "indicators": "indicators",
        "compare": "compare",
    }
    if normalized in aliases:
        return aliases[normalized]
    if normalized.startswith("artifacts:"):
        kind = normalized.split(":", 1)[1].strip()
        if kind:
            return f"artifacts_{kind}"
    if normalized.startswith("artifacts_"):
        return normalized
    raise HTTPException(status_code=400, detail=f"unsupported bookmark source: {source}")


def normalize_bookmark_tags(request: BookmarkCreateRequest) -> list[str]:
    raw_tags: list[str] = []
    if request.tag:
        raw_tags.append(request.tag)
    if request.tags:
        raw_tags.extend(request.tags)
    tags: list[str] = []
    seen: set[str] = set()
    for item in raw_tags:
        tag = str(item).strip()
        if not tag or tag in seen:
            continue
        seen.add(tag)
        tags.append(tag)
    return tags
