"""Non-row sections of ``GET /files`` pages (R6 S3 follow-up: page payload size).

``rapidtriage-files.json`` holds, next to the ``candidates`` / ``inventory`` rows, large non-row
sections (``duplicate_content_groups``, ``duplicate_detection_assessment``, the duplicate and
hash-cache manifests, ``signature_mismatch_candidates`` ...): about 1.9 MB on run-subset10.
Every paged response used to repeat them, and serialising them dominated the next-page time.

A paged response (``limit > 0``) now carries the rows, pagination and the small header fields
only (scalars and :data:`FILES_PAGE_HEADER_KEYS`); every other list/object field of the payload
is a *section*, listed in ``sections_available = [{name, approx_bytes, item_count}]`` and served
on request: ``sections=<name>,<name>`` (or ``sections=all``) on the page, or one section at a
time by ``GET /api/runs/{run_id}/files/sections?name=`` (list sections paged by
``offset``/``limit``). ``limit=0`` (full export) is unchanged.
"""

from __future__ import annotations

import json
import re
import threading
from collections import OrderedDict
from collections.abc import Iterable, Mapping

from fastapi import HTTPException

from .artifact_filter import FILES_COLLECTIONS

# Small header objects every page keeps (each a few KB at most on real runs).
FILES_PAGE_HEADER_KEYS = frozenset(
    {
        "filters",
        "summary",
        "time_provenance",
        "file_exclusions",
        "known_good_suppression_profile",
        "file_signature_profile",
        "core_accuracy_gates",
    }
)
SECTIONS_ALL = "all"
_SECTION_NAME = re.compile(r"^[A-Za-z0-9_]{1,128}$")
_SIZE_CACHE_MAX = 16
_SIZE_CACHE: OrderedDict[tuple[object, ...], list[dict[str, object]]] = OrderedDict()
_SIZE_LOCK = threading.Lock()


def section_names(payload: Mapping[str, object]) -> list[str]:
    """Names of the payload's non-row sections, in payload order."""
    return [
        key
        for key, value in payload.items()
        if key not in FILES_COLLECTIONS and key not in FILES_PAGE_HEADER_KEYS and isinstance(value, (list, dict))
    ]


def _json_bytes(value: object) -> int:
    # Same encoding as the JSON response (starlette: ensure_ascii=False, compact separators).
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8"))


def item_count(value: object) -> int | None:
    """List length or object key count (``None`` for a scalar)."""
    return len(value) if isinstance(value, (list, dict)) else None


def sections_available(payload: Mapping[str, object], stamp: tuple[object, ...]) -> list[dict[str, object]]:
    """``[{name, approx_bytes, item_count}]`` of the payload's sections, sized once per files
    revision (``stamp`` = output path, size, mtime)."""
    with _SIZE_LOCK:
        cached = _SIZE_CACHE.get(stamp)
        if cached is not None:
            _SIZE_CACHE.move_to_end(stamp)
            return [dict(entry) for entry in cached]
    entries = [
        {"name": name, "approx_bytes": _json_bytes(payload[name]), "item_count": item_count(payload[name])}
        for name in section_names(payload)
    ]
    with _SIZE_LOCK:
        _SIZE_CACHE[stamp] = entries
        while len(_SIZE_CACHE) > _SIZE_CACHE_MAX:
            _SIZE_CACHE.popitem(last=False)
    return [dict(entry) for entry in entries]


def clear_sections_cache() -> None:
    with _SIZE_LOCK:
        _SIZE_CACHE.clear()


def parse_sections(values: Iterable[str]) -> tuple[bool, frozenset[str]]:
    """``(all, names)`` of the repeatable, comma-separated ``sections=`` query (Korean 422 on a
    malformed name)."""
    names: set[str] = set()
    for raw in values:
        for item in str(raw).split(","):
            name = item.strip()
            if not name:
                continue
            if not _SECTION_NAME.match(name):
                raise HTTPException(status_code=422, detail=f"sections 값이 올바르지 않습니다: {name[:64]!r}")
            names.add(name)
    return SECTIONS_ALL in names, frozenset(names - {SECTIONS_ALL})


def apply_page_sections(
    page: Mapping[str, object],
    payload: Mapping[str, object],
    stamp: tuple[object, ...],
    sections: Iterable[str],
) -> dict[str, object]:
    """A paged response: ``page`` without the sections that were not requested, plus
    ``sections_available`` (and ``sections_missing`` for requested names this run lacks)."""
    include_all, wanted = parse_sections(sections)
    names = section_names(payload)
    keep = set(names) if include_all else wanted.intersection(names)
    dropped = set(names) - keep
    result = {key: value for key, value in page.items() if key not in dropped}
    for name in keep:
        result[name] = payload[name]
    result["sections_available"] = sections_available(payload, stamp)
    missing = sorted(wanted.difference(names))
    if missing:
        result["sections_missing"] = missing
    return result


def section_response(
    payload: Mapping[str, object],
    stamp: tuple[object, ...],
    run_id: str,
    name: str,
    *,
    offset: int,
    limit: int,
) -> dict[str, object]:
    """``GET /files/sections?name=``: one section; a list section is paged by ``offset``/``limit``
    (``limit=0`` = the whole list), an object section is returned whole."""
    if not _SECTION_NAME.match(name):
        raise HTTPException(status_code=422, detail=f"name 값이 올바르지 않습니다: {name[:64]!r}")
    if name not in section_names(payload):
        raise HTTPException(status_code=404, detail=f"이 런의 files 출력에 '{name}' 섹션이 없습니다")
    value = payload[name]
    size = next((entry for entry in sections_available(payload, stamp) if entry["name"] == name), {})
    response: dict[str, object] = {
        "run_id": run_id,
        "name": name,
        "kind": "list" if isinstance(value, list) else "object",
        "item_count": item_count(value),
        "approx_bytes": size.get("approx_bytes"),
    }
    if isinstance(value, list) and limit > 0:
        end = min(offset + limit, len(value))
        response["value"] = value[offset:end]
        response["pagination"] = {
            "offset": offset,
            "limit": limit,
            "returned": max(0, end - offset),
            "total": len(value),
            "has_more": end < len(value),
        }
    else:
        response["value"] = value
    return response
