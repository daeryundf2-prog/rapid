"""Row sources of a triage pass, numbered exactly like the API readers.

Artifact records follow ``api.app.jsonl_records``: blank lines and lines
whose first non-blank byte is not ``{`` consume no index; every ``{``-line
consumes one index, invalid JSON yields no row. Files rows are numbered by
their position in the files output's ``candidates`` / ``inventory`` list;
analysis rows by their line in ``rows.jsonl`` (only the flushed
``row_count`` records).
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from pathlib import Path

from ..artifact_profiles import (
    PROFILE_REF_KEY,
    PROFILES_PAYLOAD_KEY,
    expand_profile,
    resolve_records_path,
)


def iter_jsonl_rows(path: Path, *, limit: int | None = None) -> Iterator[tuple[int, dict[str, object] | None]]:
    """``(record_index, row | None)`` of a JSONL stream (``api.app.jsonl_records`` numbering)."""
    index = 0
    with open(path, "rb") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped.startswith(b"{"):
                continue
            if limit is not None and index >= limit:
                return
            try:
                row = json.loads(stripped)
            except ValueError:
                row = None
            yield index, row if isinstance(row, dict) else None
            index += 1


def iter_artifact_rows(payload: Mapping[str, object], payload_path: Path | None) -> Iterator[tuple[int, dict[str, object]]]:
    """``(record_index, expanded row)`` of a per-kind artifacts payload (JSONL stream or inline)."""
    profiles = payload.get(PROFILES_PAYLOAD_KEY)
    profiles = profiles if isinstance(profiles, Mapping) else None
    records_path = (
        resolve_records_path(payload, payload_path) if payload.get("records_path") or payload.get("records_file") else None
    )
    if records_path is None:
        inline = payload.get("artifacts")
        rows = enumerate(inline if isinstance(inline, list) else [])
    else:
        rows = iter_jsonl_rows(records_path)
    for index, row in rows:
        if not isinstance(row, dict):
            continue
        if profiles and row.get(PROFILE_REF_KEY):
            row = expand_profile(row, profiles, copy_templates=False)
        yield index, row
