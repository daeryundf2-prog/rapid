"""Recovered / unallocated files rows (R8 T-173): the ``sort=mtime`` tie-break lists allocated
rows before recovered ones with the same evidence time."""

from __future__ import annotations

from collections.abc import Mapping

from ...core.recovery import CANDIDATE_KIND_EXISTING, normalize_candidate_kind


def files_row_recovered(row: object) -> bool:
    """A recovered / unallocated row (``is_deleted`` or a recovered/deleted ``recovery`` kind)."""
    if not isinstance(row, Mapping):
        return False
    if row.get("is_deleted") is True:
        return True
    recovery = row.get("recovery")
    if isinstance(recovery, Mapping):
        kind = recovery.get("candidate_kind")
        if kind and normalize_candidate_kind(kind) != CANDIDATE_KIND_EXISTING:
            return True
    return False
