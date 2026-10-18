"""NTFS timestamp mismatch rows ($STANDARD_INFORMATION vs $FILE_NAME), plan r3-os-depth §3.3.

One ``ntfs-timestamp-mismatch`` row per MFT record whose eight times
(``si_*`` / ``fn_*`` created, modified, accessed, MFT-modified) disagree in a
way that suggests timestomping (AXIOM "NTFS Timestamp Mismatch" columns):

* ``si_created_before_fn`` -- $SI created earlier than $FN created by more than
  ``SI_BEFORE_FN_MIN_DELTA_SECONDS`` (the ``ntfs.si_before_fn`` rule default);
* ``zero_subsecond`` -- $SI created and modified have zero sub-seconds while
  $FN created has sub-seconds (second-precision tools; ``ntfs.zero_subsecond``);
* ``fn_after_si_modified`` -- a $FN created/modified time later than both $SI
  modified *and* $SI MFT-modified by more than ``FN_AFTER_SI_TOLERANCE_SECONDS``.
  $FN is written on create/rename/move, and the same operation updates the $SI
  entry-modified time; a copy keeps an old $SI modified but a fresh $SI
  MFT-modified, so only a backdated $SI MFT-modified (a timestomping tool that
  sets all four $SI times) trips it. (Comparing with $SI modified alone flagged
  450,699 of 1,421,896 records of the BSH $MFT, almost all ordinary copies.)
* ``future_time`` -- any of the eight times later than the reference time
  (analysis start) plus ``FUTURE_TOLERANCE``.

Inputs are the ISO strings the MFT parser emits (microsecond precision; a
FILETIME whose only sub-second part is below 1 microsecond reads as zero).
Pure functions only: the ntfs-meta analysis calls them per parsed record.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping

PARSER_NAME = "rapidtriage-ntfs-timestamp-mismatch"
PARSER_VERSION = "1"
ROW_SOURCE = "timestamp-mismatch"
ARTIFACT_TYPE = "ntfs-timestamp-mismatch"

TIME_NAMES = ("created_at", "modified_at", "accessed_at", "mft_modified_at")
# Fallback only: the threshold is the ``ntfs.si_before_fn`` rule's ``min_delta_seconds`` from
# the triage catalogue (:func:`si_before_fn_threshold`), so the mismatch rows and the rule agree.
SI_BEFORE_FN_MIN_DELTA_SECONDS = 60
FN_AFTER_SI_TOLERANCE_SECONDS = 60
FUTURE_TOLERANCE = dt.timedelta(days=1)

REASON_LABELS: dict[str, str] = {
    "si_created_before_fn": "$SI 생성이 $FN 생성보다 앞섬",
    "zero_subsecond": "$SI 생성·수정 초 미만 0($FN은 아님)",
    "fn_after_si_modified": "$FN 시각이 $SI 수정·MFT 수정보다 늦음",
    "future_time": "미래 시각",
}
REASON_CODES: tuple[str, ...] = tuple(REASON_LABELS)
# Reasons the triage catalogue also flags on the MFT row itself (cross-link).
REASON_RULES: dict[str, str] = {
    "si_created_before_fn": "ntfs.si_before_fn",
    "zero_subsecond": "ntfs.zero_subsecond",
}


def parse_iso(value: object) -> dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        moment = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=dt.timezone.utc)


def si_before_fn_threshold() -> float:
    """``min_delta_seconds`` of the ``ntfs.si_before_fn`` catalogue rule (single source of truth);
    :data:`SI_BEFORE_FN_MIN_DELTA_SECONDS` when the catalogue cannot be loaded."""
    try:
        from .triage_rules.catalog import load_catalog

        spec = load_catalog().specs.get("ntfs.si_before_fn")
        value = spec.params.get("min_delta_seconds") if spec is not None else None
        return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else float(SI_BEFORE_FN_MIN_DELTA_SECONDS)
    except Exception:
        return float(SI_BEFORE_FN_MIN_DELTA_SECONDS)


def mismatch_reasons(
    si: Mapping[str, object],
    fn: Mapping[str, object],
    *,
    reference: dt.datetime,
    si_before_fn_seconds: float = SI_BEFORE_FN_MIN_DELTA_SECONDS,
) -> tuple[list[str], dict[str, object]]:
    """``(reason codes, evidence)`` for one record's ``si``/``fn`` time maps (keys :data:`TIME_NAMES`)."""
    si_times = {name: parse_iso(si.get(name)) for name in TIME_NAMES}
    fn_times = {name: parse_iso(fn.get(name)) for name in TIME_NAMES}
    reasons: list[str] = []
    evidence: dict[str, object] = {}
    si_created, fn_created = si_times["created_at"], fn_times["created_at"]
    if si_created is not None and fn_created is not None:
        delta = (fn_created - si_created).total_seconds()
        evidence["si_fn_created_delta_seconds"] = int(delta)
        if delta > si_before_fn_seconds:
            reasons.append("si_created_before_fn")
    si_modified = si_times["modified_at"]
    if (
        si_created is not None
        and si_modified is not None
        and fn_created is not None
        and not si_created.microsecond
        and not si_modified.microsecond
        and fn_created.microsecond
    ):
        reasons.append("zero_subsecond")
    si_changed = si_times["mft_modified_at"]
    if si_modified is not None and si_changed is not None:
        later = [moment for moment in (fn_created, fn_times["modified_at"]) if moment is not None]
        if later:
            gap = (max(later) - max(si_modified, si_changed)).total_seconds()
            if gap > FN_AFTER_SI_TOLERANCE_SECONDS:
                reasons.append("fn_after_si_modified")
                evidence["fn_after_si_modified_seconds"] = int(gap)
    limit = reference + FUTURE_TOLERANCE
    future = [
        f"{prefix}_{name}"
        for prefix, times in (("si", si_times), ("fn", fn_times))
        for name in TIME_NAMES
        if times[name] is not None and times[name] > limit  # type: ignore[operator]
    ]
    if future:
        reasons.append("future_time")
        evidence["future_fields"] = future
    return reasons, evidence


def mismatch_row(
    mft_details: Mapping[str, object],
    *,
    reference: dt.datetime,
    mft_row_index: int | None,
    si_before_fn_seconds: float = SI_BEFORE_FN_MIN_DELTA_SECONDS,
) -> dict[str, object] | None:
    """The ``timestamp-mismatch`` row details for one ntfs-meta MFT row, or ``None`` when nothing disagrees."""
    si = {name: mft_details.get(f"si_{name}") for name in TIME_NAMES}
    fn = {name: mft_details.get(f"fn_{name}") for name in TIME_NAMES}
    reasons, evidence = mismatch_reasons(si, fn, reference=reference, si_before_fn_seconds=si_before_fn_seconds)
    if not reasons:
        return None
    labels = [REASON_LABELS[code] for code in reasons]
    row: dict[str, object] = {
        "source": ROW_SOURCE,
        "entry_number": mft_details.get("entry_number"),
        "sequence_number": mft_details.get("sequence_number"),
        "name": mft_details.get("name"),
        "path": mft_details.get("path"),
        "parent_path": mft_details.get("parent_path"),
        "path_status": mft_details.get("path_status"),
        "in_use": mft_details.get("in_use"),
        "directory": mft_details.get("directory"),
        **{f"si_{name}": si[name] or None for name in TIME_NAMES},
        **{f"fn_{name}": fn[name] or None for name in TIME_NAMES},
        "reasons": reasons,
        "reason_labels": labels,
        "reason": " · ".join(labels),
        **evidence,
        "related_rules": [REASON_RULES[code] for code in reasons if code in REASON_RULES],
        "mft_row_index": mft_row_index,
        "record_offset": mft_details.get("record_offset"),
        "reference_time": reference.isoformat(),
        "recovery_method": "parsed",
        "parser": PARSER_NAME,
        "parser_version": PARSER_VERSION,
    }
    return row
