"""Compact console views of heavy run payloads (R7 S1).

Artifact grid rows (``GET /api/runs/{id}/artifacts?compact=1``):

Some parsers attach large nested provenance blocks to every row (the NTFS ``$MFT`` rows of
``windows-filesystem`` carry ~60 KB of ``details``: parser profiles, citation manifests, raw
record dumps). A 250-row grid page of such a kind was 14.8 MB. The grid only renders scalar
cells (and promotes scalar / scalar-array ``details`` keys to columns), so ``compact=1`` drops
the *large nested* ``details`` values from each row and names them in ``details_omitted``; the
viewer fetches the one full row (``kind=<k>&offset=<record_index>&limit=1``) when it opens it.

Never dropped: scalars, scalar arrays (both can be grid columns) and nested values up to
``COMPACT_NESTED_MAX_BYTES`` of JSON (small nested reads such as ``source_hashes.sha256``).

Run summary (``GET /api/runs/{id}/summary?compact=1``): the console reads counts, steps,
warnings, disclosures and outputs, never the per-file lists the summary embeds for the case
report (``source.recovered_root_manifest.files``, ``safety.input_fingerprint.files``: 1.9 of
2.2 MB on a 200k-file E01). ``compact=1`` replaces each list by ``files_omitted`` (its length).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

COMPACT_NESTED_MAX_BYTES = 512


def _is_scalar(value: object) -> bool:
    return value is None or isinstance(value, (str, int, float, bool))


def _keep(value: object) -> bool:
    if _is_scalar(value):
        return True
    if isinstance(value, list) and all(_is_scalar(item) for item in value):
        return True
    try:
        size = len(json.dumps(value, ensure_ascii=False, default=str))
    except (TypeError, ValueError):
        return False
    return size <= COMPACT_NESTED_MAX_BYTES


def compact_artifact_row(row: dict[str, Any]) -> dict[str, Any]:
    """The row with large nested ``details`` values removed (listed in ``details_omitted``)."""
    details = row.get("details")
    if not isinstance(details, Mapping):
        return row
    kept: dict[str, Any] = {}
    omitted: list[str] = []
    for key, value in details.items():
        if _keep(value):
            kept[key] = value
        else:
            omitted.append(str(key))
    if not omitted:
        return row
    return {**row, "details": kept, "details_omitted": sorted(omitted)}


def compact_artifacts_response(response: Mapping[str, Any]) -> None:
    """Compact every row of every kind page of an ``/artifacts`` response in place."""
    pages = response.get("artifacts")
    if not isinstance(pages, Mapping):
        return
    for page in pages.values():
        rows = page.get("artifacts") if isinstance(page, dict) else None
        if isinstance(rows, list):
            page["artifacts"] = [compact_artifact_row(row) if isinstance(row, dict) else row for row in rows]


# (top-level key, nested key) blocks whose ``files`` list the console never reads.
SUMMARY_FILE_LISTS: tuple[tuple[str, str], ...] = (
    ("source", "recovered_root_manifest"),
    ("safety", "input_fingerprint"),
)


def compact_run_summary(payload: Mapping[str, Any]) -> dict[str, Any]:
    """A shallow copy of a run summary without the embedded per-file lists."""
    out = dict(payload)
    for outer_key, inner_key in SUMMARY_FILE_LISTS:
        outer = out.get(outer_key)
        if not isinstance(outer, Mapping):
            continue
        inner = outer.get(inner_key)
        if not isinstance(inner, Mapping) or not isinstance(inner.get("files"), list):
            continue
        slim = {key: value for key, value in inner.items() if key != "files"}
        slim["files_omitted"] = len(inner["files"])
        out[outer_key] = {**outer, inner_key: slim}
    return out
