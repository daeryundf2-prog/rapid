"""Streaming path filter for per-kind artifact outputs (``GET /api/runs/{id}/artifacts``)."""

from __future__ import annotations

import unicodedata
from pathlib import Path

from ...core.artifact_profiles import iter_payload_records

ARTIFACT_PATH_FILTER_SCAN_CAP = 2_000_000


def nfc_fold(value: object) -> str:
    return unicodedata.normalize("NFC", str(value or "")).casefold()


def filter_artifact_page(
    payload: dict[str, object],
    *,
    payload_path: Path,
    path_contains: str,
    offset: int,
    limit: int,
    scan_cap: int = ARTIFACT_PATH_FILTER_SCAN_CAP,
) -> dict[str, object]:
    """Page only rows whose ``path`` contains ``path_contains`` (NFC, case-insensitive).

    Streams the kind's rows; ``offset`` counts matches. Stops after ``limit``
    matches plus one lookahead row, or after ``scan_cap`` scanned rows
    (``truncated``: the total is then unknown and ``scanned`` reports the cost).
    """
    needle = nfc_fold(path_contains)
    rows: list[object] = []
    matched = 0
    scanned = 0
    has_more = False
    exhausted = True
    for row in iter_payload_records(payload, payload_path=payload_path):
        scanned += 1
        if needle in nfc_fold(row.get("path") or row.get("source_path")):
            if matched >= offset + limit:
                has_more = True
                exhausted = False
                break
            if matched >= offset:
                rows.append(row)
            matched += 1
        if scanned >= scan_cap:
            exhausted = False
            break
    end = offset + len(rows)
    page = dict(payload)
    page["artifacts"] = rows
    page["pagination"] = {
        "collection": "artifacts",
        "offset": offset,
        "limit": limit,
        "returned": len(rows),
        "total": matched if exhausted else None,
        "next_offset": end if has_more else None,
        "previous_offset": max(0, offset - limit) if offset > 0 else None,
        "has_more": has_more,
        "filtered": True,
        "path_contains": path_contains,
        "scanned": scanned,
        "truncated": not exhausted and not has_more,
    }
    return page
