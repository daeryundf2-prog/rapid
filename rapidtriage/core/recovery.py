"""Unified recovery candidate-kind model.

All file/recovery outputs classify candidates with the PRD taxonomy:
``existing``, ``deleted-entry``, ``orphan-record``, ``carved``,
``partial-corrupt``. Producers attach a ``recovery`` block built by
``build_recovery_record`` so downstream consumers (case DB, viewer,
report, release gates) see one schema regardless of source.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence

RECOVERY_SCHEMA_VERSION = "candidate-kind-v1"

CANDIDATE_KIND_EXISTING = "existing"
CANDIDATE_KIND_DELETED_ENTRY = "deleted-entry"
CANDIDATE_KIND_ORPHAN_RECORD = "orphan-record"
CANDIDATE_KIND_CARVED = "carved"
CANDIDATE_KIND_PARTIAL_CORRUPT = "partial-corrupt"

CANDIDATE_KINDS: tuple[str, ...] = (
    CANDIDATE_KIND_EXISTING,
    CANDIDATE_KIND_DELETED_ENTRY,
    CANDIDATE_KIND_ORPHAN_RECORD,
    CANDIDATE_KIND_CARVED,
    CANDIDATE_KIND_PARTIAL_CORRUPT,
)

CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"
CONFIDENCE_UNKNOWN = "unknown"
CONFIDENCE_LEVELS: tuple[str, ...] = (
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_LOW,
    CONFIDENCE_UNKNOWN,
)

VALIDATION_UNVERIFIED = "unverified"
VALIDATION_VALIDATED = "validated"
VALIDATION_PARTIAL = "partial"
VALIDATION_REJECTED = "rejected"
VALIDATION_STATES: tuple[str, ...] = (
    VALIDATION_UNVERIFIED,
    VALIDATION_VALIDATED,
    VALIDATION_PARTIAL,
    VALIDATION_REJECTED,
)

# Kinds whose backing object is no longer allocated on the source
# filesystem. Used by case_db import to set is_deleted honestly instead
# of matching "deleted"/"recycle" in the path string.
_DELETED_KINDS = frozenset(
    {
        CANDIDATE_KIND_DELETED_ENTRY,
        CANDIDATE_KIND_ORPHAN_RECORD,
        CANDIDATE_KIND_PARTIAL_CORRUPT,
    }
)

# Kinds where the producer recovered content bytes (carved output or a
# deleted/orphan candidate with recoverable data). `existing` files are
# exported, not recovered.
_RECOVERED_KINDS = frozenset(
    {
        CANDIDATE_KIND_DELETED_ENTRY,
        CANDIDATE_KIND_ORPHAN_RECORD,
        CANDIDATE_KIND_CARVED,
    }
)

# Legacy producer labels mapped onto the unified taxonomy. Keeps
# artifact-specific detail in ``subtype`` while collapsing to the five
# PRD kinds.
_KIND_ALIASES: dict[str, str] = {
    "allocated": CANDIDATE_KIND_EXISTING,
    "deleted": CANDIDATE_KIND_DELETED_ENTRY,
    "deleted-or-free-key-cell": CANDIDATE_KIND_DELETED_ENTRY,
    "deleted-or-free-value-cell": CANDIDATE_KIND_DELETED_ENTRY,
    "recycle-bin-entry": CANDIDATE_KIND_DELETED_ENTRY,
    "orphan": CANDIDATE_KIND_ORPHAN_RECORD,
    "orphaned": CANDIDATE_KIND_ORPHAN_RECORD,
    "signature-carved": CANDIDATE_KIND_CARVED,
    "partial": CANDIDATE_KIND_PARTIAL_CORRUPT,
    "corrupt": CANDIDATE_KIND_PARTIAL_CORRUPT,
    "truncated": CANDIDATE_KIND_PARTIAL_CORRUPT,
}


def normalize_candidate_kind(value: object, *, default: str | None = None) -> str:
    """Map a raw producer label onto the unified taxonomy.

    Unknown values fall back to ``default`` (``existing`` when unset)
    rather than raising so that older outputs and third-party parsers
    degrade gracefully.
    """
    text = str(value or "").strip().lower()
    if text in CANDIDATE_KINDS:
        return text
    if text in _KIND_ALIASES:
        return _KIND_ALIASES[text]
    return default or CANDIDATE_KIND_EXISTING


def is_deleted_candidate_kind(kind: object) -> bool:
    return normalize_candidate_kind(kind) in _DELETED_KINDS


def is_recovered_candidate_kind(kind: object) -> bool:
    return normalize_candidate_kind(kind) in _RECOVERED_KINDS


def build_recovery_record(
    kind: object,
    *,
    confidence: object = CONFIDENCE_UNKNOWN,
    validation_status: object = VALIDATION_UNVERIFIED,
    subtype: object = None,
    deletion_state: object = None,
    source_id: object = None,
    source_path: object = None,
    source_record_id: object = None,
    source_offset: object = None,
    boundary_method: object = None,
    signature_type: object = None,
    limitation: object = None,
    limitations: Sequence[object] = (),
    reportability: object = "triage",
    extra: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Build a normalized ``recovery`` block for a candidate payload.

    ``kind`` must resolve to the unified taxonomy; confidence and
    validation status are normalized to the shared vocabularies.
    ``limitations`` and ``limitation`` are merged into one list so a
    candidate can carry multiple caveats without ad-hoc string
    concatenation at emit sites.
    """
    normalized_kind = normalize_candidate_kind(kind)
    confidence_text = str(confidence or CONFIDENCE_UNKNOWN).strip().lower()
    if confidence_text not in CONFIDENCE_LEVELS:
        confidence_text = CONFIDENCE_UNKNOWN
    validation_text = str(validation_status or VALIDATION_UNVERIFIED).strip().lower()
    if validation_text not in VALIDATION_STATES:
        validation_text = VALIDATION_UNVERIFIED

    all_limitations = [str(item) for item in limitations if str(item or "").strip()]
    if limitation and str(limitation).strip():
        all_limitations.append(str(limitation))

    record: dict[str, object] = {
        "schema": RECOVERY_SCHEMA_VERSION,
        "candidate_kind": normalized_kind,
        "subtype": str(subtype) if subtype else None,
        "confidence": confidence_text,
        "validation_status": validation_text,
        "deletion_state": str(deletion_state) if deletion_state else None,
        "source_id": str(source_id) if source_id else None,
        "source_path": str(source_path) if source_path else None,
        "source_record_id": str(source_record_id) if source_record_id is not None else None,
        "source_offset": _optional_int(source_offset),
        "boundary_method": str(boundary_method) if boundary_method else None,
        "signature_type": str(signature_type) if signature_type else None,
        "limitations": all_limitations,
        "reportability": str(reportability or "triage"),
        "commercial_claim_allowed": False,
    }
    if extra:
        for key, value in extra.items():
            record[str(key)] = value
    return record


def recovery_record_from_payload(row: Mapping[str, object]) -> dict[str, object]:
    """Extract the normalized recovery block from a payload row.

    Rows produced before the unified model (or by external producers)
    get a defaulted ``existing`` record so consumers never see a
    missing key.
    """
    recovery = row.get("recovery")
    if not isinstance(recovery, Mapping):
        return build_recovery_record(CANDIDATE_KIND_EXISTING)
    normalized = dict(recovery)
    normalized["candidate_kind"] = normalize_candidate_kind(recovery.get("candidate_kind"))
    return normalized


def count_candidate_kinds(rows: Sequence[Mapping[str, object]]) -> dict[str, int]:
    counts = {kind: 0 for kind in CANDIDATE_KINDS}
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        kind = normalize_candidate_kind(recovery_record_from_payload(row).get("candidate_kind"))
        counts[kind] = counts.get(kind, 0) + 1
    return {kind: count for kind, count in counts.items() if count}


def _optional_int(value: object) -> int | None:
    try:
        if value is None or str(value) == "":
            return None
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
