"""One record-numbering rule for JSONL-backed per-kind artifact outputs.

Every API reader of ``records_path`` -- unsorted pages, the ``path_contains``
filter, the sort-index build and sorted pages -- numbers records the same way,
so a row's ``record_index`` (and its ``/artifacts/<record_index>`` locator) is
identical whichever reader produced it:

* blank lines (``bytes.strip()`` empty) are skipped and consume no index;
* lines whose first non-blank byte is not ``{`` (``[1,2]``, scalars) are
  skipped and consume no index -- they can never be artifact rows;
* every ``{``-line consumes exactly one index. When it is not valid JSON
  (or not UTF-8) the record yields ``row=None`` and a warning naming the line
  number is logged; readers keep the index and return no row for it.

Skipping to a start index never parses the skipped lines.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator, Mapping
from pathlib import Path

from ...core.artifact_profiles import (
    PROFILE_REF_KEY,
    PROFILES_PAYLOAD_KEY,
    expand_profile,
    resolve_records_path,
)

LOGGER = logging.getLogger(__name__)


def parse_record_line(line: bytes, *, path: Path | str, line_number: int) -> dict[str, object] | None:
    """Parse one ``{``-line; ``None`` (with a logged warning) when it is not a JSON object."""
    try:
        row = json.loads(line)
    except ValueError as exc:  # JSONDecodeError and UnicodeDecodeError
        LOGGER.warning("skipping invalid JSONL record on line %d of %s: %s", line_number, path, exc)
        return None
    return row if isinstance(row, dict) else None


def iter_jsonl_records(
    path: Path | str,
    *,
    start: int = 0,
) -> Iterator[tuple[int, int, dict[str, object] | None, int]]:
    """Yield ``(record_index, byte_offset, row, line_number)`` from ``start`` on."""
    index = 0
    position = 0
    with open(path, "rb") as handle:
        for line_number, line in enumerate(handle, start=1):
            offset = position
            position += len(line)
            stripped = line.strip()
            if not stripped.startswith(b"{"):
                continue
            if index >= start:
                yield index, offset, parse_record_line(stripped, path=path, line_number=line_number), line_number
            index += 1


def payload_profiles(payload: Mapping[str, object]) -> Mapping[str, Mapping[str, object]] | None:
    profiles = payload.get(PROFILES_PAYLOAD_KEY)
    return profiles if isinstance(profiles, Mapping) else None


def expand_row(
    row: dict[str, object], profiles: Mapping[str, Mapping[str, object]] | None
) -> dict[str, object]:
    if profiles and row.get(PROFILE_REF_KEY):
        return expand_profile(row, profiles, copy_templates=False)
    return row


def jsonl_records_path(payload: Mapping[str, object], payload_path: Path | str | None) -> Path | None:
    """The payload's JSONL stream, or ``None`` for inline payloads."""
    if not (payload.get("records_path") or payload.get("records_file")):
        return None
    return resolve_records_path(payload, payload_path)


def iter_artifact_records(
    payload: Mapping[str, object],
    *,
    payload_path: Path | str | None,
    start: int = 0,
    limit: int | None = None,
) -> Iterator[tuple[int, dict[str, object]]]:
    """``(record_index, expanded row)`` pairs; records without a row are skipped.

    ``limit`` counts record indices (an invalid record still uses one slot).
    Inline payloads number rows by their position in ``artifacts``.
    """
    if limit is not None and limit <= 0:
        return
    records_path = jsonl_records_path(payload, payload_path)
    profiles = payload_profiles(payload)
    end = None if limit is None else start + limit
    if records_path is None:
        inline = payload.get("artifacts")
        inline = inline if isinstance(inline, list) else []
        for index in range(start, len(inline) if end is None else min(end, len(inline))):
            row = inline[index]
            if isinstance(row, dict):
                yield index, expand_row(row, profiles)
        return
    for index, _offset, row, _line in iter_jsonl_records(records_path, start=start):
        if end is not None and index >= end:
            return
        if row is not None:
            yield index, expand_row(row, profiles)
