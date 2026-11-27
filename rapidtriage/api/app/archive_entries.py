"""``archive.zip::entry`` sources for the file routes: resolution under the run's allowlist and
the entry's bytes as a (ranged) streaming download."""

from __future__ import annotations

import mimetypes
import re
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import quote

from fastapi import HTTPException
from fastapi.responses import StreamingResponse

from ...core.archive_entry import (
    ArchiveEntry,
    ArchiveEntryError,
    SourceFile,
    open_source,
    resolve_archive_entry,
)
from ...core.jobs import RunJobStore
from .helpers import parse_source_preview_archive_request, resolve_allowed_source_file

ENTRY_STREAM_CHUNK_BYTES = 256 * 1024
_RANGE_PATTERN = re.compile(r"bytes=(\d*)-(\d*)")


def resolve_allowed_source_target(
    store: RunJobStore,
    run_id: str,
    raw_path: str,
    *,
    analysis_id: str | None = None,
    locator: str | None = None,
) -> SourceFile:
    """A run source file, or one member of a ZIP that is itself a run source file.

    The container goes through the same allowlist as every file route; the member is then
    looked up by its exact name inside it and refused (Korean reason) when a guard trips.
    """
    archive_request = parse_source_preview_archive_request(raw_path)
    if archive_request is None:
        return resolve_allowed_source_file(store, run_id, raw_path, analysis_id=analysis_id, locator=locator)
    archive_path = resolve_allowed_source_file(
        store, run_id, archive_request["archive_path"], analysis_id=analysis_id, locator=locator
    )
    return resolve_entry_or_raise(archive_path, archive_request["entry_name"])


def resolve_entry_or_raise(archive_path: Path, entry_name: str) -> ArchiveEntry:
    try:
        return resolve_archive_entry(archive_path, entry_name)
    except ArchiveEntryError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc


def parse_byte_range(header: str | None, size: int) -> tuple[int, int] | None:
    """The inclusive ``(start, end)`` of a single ``bytes=`` range, ``None`` for a whole-body answer."""
    if not header:
        return None
    match = _RANGE_PATTERN.fullmatch(header.strip())
    if match is None or match.groups() == ("", ""):
        return None
    first, last = match.groups()
    if first:
        start = int(first)
        end = min(int(last), size - 1) if last else size - 1
    else:
        start, end = max(size - int(last), 0), size - 1
    if start >= size or start > end:
        raise HTTPException(
            status_code=416, detail="요청한 바이트 범위가 항목 밖입니다", headers={"Content-Range": f"bytes */{size}"}
        )
    return start, end


def _iter_entry_bytes(entry: ArchiveEntry, start: int, length: int) -> Iterator[bytes]:
    with open_source(entry) as handle:
        if start:
            handle.seek(start)
        remaining = length
        while remaining > 0:
            chunk = handle.read(min(ENTRY_STREAM_CHUNK_BYTES, remaining))
            if not chunk:
                return
            remaining -= len(chunk)
            yield chunk


def archive_entry_response(entry: ArchiveEntry, range_header: str | None) -> StreamingResponse:
    """The entry's bytes, decompressed while streaming; one ``Range`` is honoured (206)."""
    byte_range = parse_byte_range(range_header, entry.size)
    start, end = byte_range if byte_range else (0, entry.size - 1)
    length = max(end - start + 1, 0)
    headers = {
        "Accept-Ranges": "bytes",
        "Content-Length": str(length),
        "Content-Disposition": f"attachment; filename*=utf-8''{quote(entry.name)}",
    }
    if byte_range:
        headers["Content-Range"] = f"bytes {start}-{end}/{entry.size}"
    return StreamingResponse(
        _iter_entry_bytes(entry, start, length),
        status_code=206 if byte_range else 200,
        media_type=mimetypes.guess_type(entry.name)[0] or "application/octet-stream",
        headers=headers,
    )
