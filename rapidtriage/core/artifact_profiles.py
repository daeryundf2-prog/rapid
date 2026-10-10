"""Per-artifact-type profiles: hoist constant blocks out of artifact records.

Collectors attach the same governance/validation boilerplate (commercial
uplift evidence, accuracy gates, validation matrices, review profiles, ...)
to every record of an ``artifact_type``. Serializing it per record dominated
run output size (``docs/plans/run-pipeline-mitigations-2026-10-09.md`` §5-A,
§7 I11). ``hoist_constant_blocks`` moves the parts of those blocks that are
identical across every record of a type into one profile entry:

- a ``details`` key whose value is identical in every record of the type is
  moved whole into ``profiles[artifact_type]["details"][key]``;
- when the values are all objects (or equal-length arrays of objects) the
  *constant parts* are hoisted recursively and each record keeps only its
  varying residue (e.g. per-record check results, source references);
- the ``artifact_record`` envelope is hoisted the same way into
  ``profiles[artifact_type]["artifact_record"]``.

Records that lost anything carry ``profile_ref: <artifact_type>``.
``expand_profile`` deep-merges the profile template back under the residue
and is the exact inverse (field sets and values round-trip; only key order
may differ). Varying leaves are never hoisted, and identity keys (paths,
hashes, timestamps, counts) are never candidates.

This module also hosts the list-cap helper providers use to bound
per-record candidate lists (§7 I12).
"""

from __future__ import annotations

import copy
import json
from collections.abc import (
    Callable,
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    Sequence,
)
from pathlib import Path
from typing import Any

from .json_safe import json_default
from .json_stream import iter_array_items, iter_jsonl_items, open_json

PROFILE_REF_KEY = "profile_ref"
CONTEXT_REF_KEY = "context_ref"
# Rows of one type that share a source file are context-hoisted only when
# the file contributes at least this many rows.
CONTEXT_MIN_ROWS = 8
# Dictionary encoding of short-vocabulary string labels: applied to types
# with at least CODE_MIN_ROWS rows, for keys with at most CODE_MAX_DISTINCT
# distinct values averaging CODE_MIN_AVERAGE_CHARS characters or more.
CODE_MIN_ROWS = 64
CODE_MAX_DISTINCT = 64
CODE_MIN_AVERAGE_CHARS = 6
PROFILES_PAYLOAD_KEY = "artifact_type_profiles"
ENVELOPE_KEY = "artifact_record"
PROFILE_VERSION = "artifact-type-profiles-v1"

# Governance/validation blocks measured as per-type boilerplate on the BSH
# subset run (scripts/measure-artifact-record-bloat.py --deep-sample): exact
# names here plus the suffix families below are the hoist candidates (e.g.
# commercial_uplift_evidence, core_accuracy_gates, *_validation_matrix,
# *_report_grade_assessment, *_analyst_review_profile, *_native_capabilities,
# *_report_citation_manifest, commercial_grade_blockers).
HOIST_DETAIL_KEYS = frozenset(
    {
        "forensic_review",
        "recommended_parsers",
        "validation_guidance",
        "reportability_decision",
        "triage_recommendation",
        "not_proof_of",
        "source_viewer_locator",
        "message_rendering",
        "record_projection",
        "note",
    }
)
# Suffix families of per-record governance/validation blocks. Within them
# only sub-values identical across every record of a type are hoisted, so a
# block that embeds per-record data keeps that data on the record.
HOIST_DETAIL_KEY_SUFFIXES = (
    "_profile",
    "_manifest",
    "_matrix",
    "_assessment",
    "_evidence",
    "_capabilities",
    "_gates",
    "_checks",
    "_plan",
    "_guidance",
    "_contract",
    "_limitations",
    "_blockers",
)
# Identity/provenance keys stay on every record even if a provider names
# them like a profile block.
NEVER_HOIST_DETAIL_KEYS = frozenset(
    {
        "source_path",
        "source_hashes",
        "source_index",
        "path",
        "timestamp",
        "event_created_at",
        "record_id",
        "event_id",
        "artifact_type",
    }
)
# Scalar ``details`` values identical across every record of a type (labels
# such as parser, parser_version, coverage_status, evidence_strength,
# reportability, validation flags) are hoisted too, except identity-like
# names: paths, hashes, ids, offsets, sizes, counts, and timestamps stay on
# every record even when they happen to be equal.
NEVER_HOIST_SCALAR_SUFFIXES = (
    "_path",
    "_paths",
    "_hash",
    "_hashes",
    "_sha256",
    "_md5",
    "_sha1",
    "_id",
    "_ids",
    "_offset",
    "_size",
    "_index",
    "_count",
    "_total",
    "_at",
    "_time",
    "_timestamp",
    "_name",
)


def is_hoistable_detail_key(key: str) -> bool:
    """True for measured per-type boilerplate keys (never identity keys)."""
    if key in NEVER_HOIST_DETAIL_KEYS:
        return False
    if key in HOIST_DETAIL_KEYS:
        return True
    return key.endswith(HOIST_DETAIL_KEY_SUFFIXES)


def is_hoistable_scalar_key(key: str) -> bool:
    """True when a constant scalar ``details`` value may move to the profile."""
    if key in NEVER_HOIST_DETAIL_KEYS:
        return False
    lowered = key.lower()
    return not (lowered.endswith(NEVER_HOIST_SCALAR_SUFFIXES) or lowered in {"id", "name", "size", "count", "offset"})


_SCALAR_TYPES = (str, int, float, bool, type(None))


class _Missing:
    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<missing>"


_MISSING: Any = _Missing()


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=json_default)


_EXACT_SCALAR_TYPES = (str, type(None))
_NUMERIC_TYPES = (bool, int, float)


def _all_identical(values: Sequence[object]) -> bool:
    first = values[0]
    first_type = type(first)
    if first_type in _EXACT_SCALAR_TYPES or first_type in _NUMERIC_TYPES:
        # Scalars: ``type(...) is`` keeps 1, 1.0 and True apart.
        return all(type(value) is first_type and value == first for value in values[1:])
    if not all(value is first or value == first for value in values[1:]):
        return False
    if len(values) == 1:
        return True
    # ``==`` treats 1 == 1.0 == True inside containers; confirm with JSON
    # identity so a hoisted value always re-expands to the exact original.
    canonical = _canonical(first)
    return all(value is first or _canonical(value) == canonical for value in values[1:])


def _split(values: Sequence[object]) -> tuple[bool, object, list[object]]:
    """Split ``values`` into a shared template and per-value residues.

    Returns ``(hoisted, template, residues)``. A residue of ``_MISSING``
    means the value equals the template exactly. ``hoisted`` is False when
    nothing is shared (the caller keeps the values untouched).
    """
    if _all_identical(values):
        return True, values[0], [_MISSING] * len(values)
    if all(isinstance(value, dict) for value in values):
        first = values[0]
        shared_keys = [key for key in first if all(key in value for value in values[1:])]
        template: dict[str, object] = {}
        residues: list[dict[str, object]] = [dict(value) for value in values]  # type: ignore[arg-type]
        for key in shared_keys:
            hoisted, child_template, child_residues = _split([value[key] for value in values])  # type: ignore[index]
            if not hoisted:
                continue
            template[key] = child_template
            for residue, child in zip(residues, child_residues):
                if child is _MISSING:
                    del residue[key]
                else:
                    residue[key] = child
        if not template:
            return False, None, list(values)
        return True, template, [residue if residue else _MISSING for residue in residues]
    if all(isinstance(value, list) for value in values):
        length = len(values[0])  # type: ignore[arg-type]
        if (
            length
            and all(len(value) == length for value in values)  # type: ignore[arg-type]
            and all(isinstance(item, dict) for value in values for item in value)  # type: ignore[union-attr]
        ):
            list_template: list[object] = []
            list_residues: list[list[object]] = [[None] * length for _ in values]
            any_hoisted = False
            for index in range(length):
                column = [value[index] for value in values]  # type: ignore[index]
                hoisted, child_template, child_residues = _split(column)
                if hoisted:
                    any_hoisted = True
                    list_template.append(child_template)
                    for residue, child in zip(list_residues, child_residues):
                        residue[index] = {} if child is _MISSING else child
                else:
                    # An empty-object template merges back to the full item.
                    list_template.append({})
                    for residue, item in zip(list_residues, column):
                        residue[index] = item
            if not any_hoisted:
                return False, None, list(values)
            return True, list_template, [
                _MISSING if all(item == {} for item in residue) else residue for residue in list_residues
            ]
    return False, None, list(values)


def _merge(template: object, residue: object = _MISSING, *, copy_template: bool = True) -> object:
    """Inverse of ``_split``: deep-merge a residue over its template.

    ``copy_template=False`` shares template sub-objects with the result
    (read-only consumers; avoids a deepcopy per row).
    """
    if residue is _MISSING:
        return copy.deepcopy(template) if copy_template else template
    if isinstance(template, dict) and isinstance(residue, dict):
        merged = {
            key: (
                _merge(value, residue[key], copy_template=copy_template)
                if key in residue
                else (copy.deepcopy(value) if copy_template else value)
            )
            for key, value in template.items()
        }
        for key, value in residue.items():
            if key not in template:
                merged[key] = value
        return merged
    if isinstance(template, list) and isinstance(residue, list) and len(template) == len(residue):
        return [
            _merge(item, residue_item, copy_template=copy_template)
            for item, residue_item in zip(template, residue)
        ]
    return residue


def _key_selector(keys: Iterable[str] | Callable[[str], bool]) -> Callable[[str], bool]:
    if callable(keys):
        return keys
    allowed = frozenset(keys)
    return lambda key: key in allowed and key not in NEVER_HOIST_DETAIL_KEYS


def _hoist_group(
    group: Sequence[MutableMapping[str, object]],
    candidate: Callable[[str, object], bool],
    *,
    hoist_envelope: bool,
) -> dict[str, object]:
    """Hoist the constant parts shared by every row of ``group``; return the templates."""
    first_details = group[0]["details"]
    assert isinstance(first_details, dict)
    candidate_keys = [
        key
        for key, value in first_details.items()
        if candidate(str(key), value) and all(key in record["details"] for record in group[1:])  # type: ignore[operator]
    ]
    detail_templates: dict[str, object] = {}
    for key in candidate_keys:
        hoisted, template, residues = _split([record["details"][key] for record in group])  # type: ignore[index]
        if not hoisted:
            continue
        detail_templates[key] = template
        for record, residue in zip(group, residues):
            details = record["details"]
            assert isinstance(details, dict)
            if residue is _MISSING:
                del details[key]
            else:
                details[key] = residue
    profile: dict[str, object] = {}
    if detail_templates:
        profile["details"] = detail_templates
    if hoist_envelope and all(isinstance(record.get(ENVELOPE_KEY), dict) for record in group):
        hoisted, template, residues = _split([record[ENVELOPE_KEY] for record in group])
        if hoisted and template:
            profile[ENVELOPE_KEY] = template
            for record, residue in zip(group, residues):
                record[ENVELOPE_KEY] = {} if residue is _MISSING else residue
    return profile


def _any_key(_key: str, _value: object) -> bool:
    return True


def hoist_constant_blocks(
    records: list[MutableMapping[str, object]],
    *,
    keys: Iterable[str] | Callable[[str], bool] = is_hoistable_detail_key,
    hoist_envelope: bool = True,
    hoist_scalars: bool = True,
    source_contexts: bool = True,
    context_min_rows: int = CONTEXT_MIN_ROWS,
    encode_values: bool = True,
) -> tuple[list[MutableMapping[str, object]], dict[str, dict[str, object]]]:
    """Hoist per-type constant (parts of) ``details`` blocks into profiles.

    ``records`` are artifact row dicts (``provider``/``artifact_type``/
    ``path``/``details``[/``artifact_record``]); they are updated in place
    and returned. ``keys`` is a key collection or predicate selecting the
    ``details`` keys that may be hoisted; a key is hoisted for a type only
    when every record of that type carries it. ``hoist_scalars`` also
    hoists scalar values that are identical across the type (see
    ``is_hoistable_scalar_key``). Returns ``(records, profiles)`` where
    ``profiles[artifact_type]`` holds ``details`` (and, with
    ``hoist_envelope``, ``artifact_record``) templates.

    With ``source_contexts``, rows of one type that share a source file
    (``path``; at least ``context_min_rows`` of them, e.g. every event of one
    EVTX or every reference of one PF) then hoist whatever is still
    identical across that file into ``profiles[type]["contexts"][path]``
    and carry ``context_ref: true`` (looked up by the row's ``path``):
    per-file context is stored once per
    file instead of once per row. Only exactly-equal values move, so this is
    lossless like the type level.

    With ``encode_values``, short-vocabulary string labels still on the rows
    are dictionary-encoded (``profiles[type]["codes"][key]`` lists the
    values, rows hold the index); ``expand_profile`` decodes them first.
    """
    selector = _key_selector(keys)

    def type_candidate(key: str, value: object) -> bool:
        return selector(key) or (
            hoist_scalars and isinstance(value, _SCALAR_TYPES) and is_hoistable_scalar_key(key)
        )

    by_type: dict[str, list[MutableMapping[str, object]]] = {}
    for record in records:
        if isinstance(record, MutableMapping) and isinstance(record.get("details"), dict):
            by_type.setdefault(str(record.get("artifact_type") or ""), []).append(record)
    profiles: dict[str, dict[str, object]] = {}
    for artifact_type in sorted(by_type):
        group = by_type[artifact_type]
        if len(group) < 2:
            continue
        profile = _hoist_group(group, type_candidate, hoist_envelope=hoist_envelope)
        contexts: dict[str, object] = {}
        if source_contexts:
            by_path: dict[str, list[MutableMapping[str, object]]] = {}
            for record in group:
                by_path.setdefault(str(record.get("path") or ""), []).append(record)
            for path in sorted(by_path):
                rows = by_path[path]
                if not path or len(rows) < max(2, context_min_rows):
                    continue
                context = _hoist_group(rows, _any_key, hoist_envelope=hoist_envelope)
                if context:
                    contexts[path] = context
                    for record in rows:
                        record[CONTEXT_REF_KEY] = True
        if contexts:
            profile["contexts"] = contexts
        if encode_values:
            codes = _encode_low_cardinality(group)
            if codes:
                profile["codes"] = codes
        if profile:
            profiles[artifact_type] = profile
            for record in group:
                record[PROFILE_REF_KEY] = artifact_type
    return records, profiles


def _encode_low_cardinality(group: Sequence[MutableMapping[str, object]]) -> dict[str, list[str]]:
    """Dictionary-encode short-vocabulary string labels left on the rows.

    For a ``details`` key whose remaining string values take at most
    ``CODE_MAX_DISTINCT`` distinct values across the type (status labels,
    categories, fidelity codes), the profile keeps the value list and each
    row keeps the integer index. Only keys every carrying row holds as a
    string are encoded; identity-like names are never encoded.
    """
    if len(group) < CODE_MIN_ROWS:
        return {}
    vocab: dict[str, dict[str, int]] = {}
    rejected: set[str] = set()
    for record in group:
        details = record["details"]
        assert isinstance(details, dict)
        for key, value in details.items():
            if key in rejected:
                continue
            if not isinstance(value, str) or not is_hoistable_scalar_key(str(key)):
                rejected.add(key)
                vocab.pop(key, None)
                continue
            values = vocab.setdefault(key, {})
            if value not in values:
                if len(values) >= CODE_MAX_DISTINCT:
                    rejected.add(key)
                    vocab.pop(key, None)
                    continue
                values[value] = len(values)
    codes: dict[str, list[str]] = {}
    for key in sorted(vocab):
        values = vocab[key]
        if sum(len(value) for value in values) / max(1, len(values)) < CODE_MIN_AVERAGE_CHARS:
            continue
        codes[key] = list(values)
        for record in group:
            details = record["details"]
            assert isinstance(details, dict)
            if key in details:
                details[key] = values[details[key]]
    return codes


def _merge_profile_level(
    expanded: dict[str, object],
    level: Mapping[str, object],
    *,
    copy_templates: bool,
) -> None:
    detail_templates = level.get("details")
    if isinstance(detail_templates, Mapping):
        details = dict(expanded.get("details") or {})
        for key, template in detail_templates.items():
            details[key] = _merge(template, details.get(key, _MISSING), copy_template=copy_templates)
        expanded["details"] = details
    envelope_template = level.get(ENVELOPE_KEY)
    if envelope_template is not None:
        expanded[ENVELOPE_KEY] = _merge(
            envelope_template,
            expanded.get(ENVELOPE_KEY) or {},
            copy_template=copy_templates,
        )


def expand_profile(
    record: Mapping[str, object],
    profiles: Mapping[str, Mapping[str, object]] | None,
    *,
    copy_templates: bool = True,
    include_type_templates: bool = True,
) -> dict[str, object]:
    """Return ``record`` with its profile templates merged back (inverse of hoisting).

    The per-source context (``context_ref``) is merged first, then the
    per-type profile. With ``copy_templates=False`` the expanded row shares
    (read-only) template objects with ``profiles``. With
    ``include_type_templates=False`` only codes and the per-file context are
    restored: the row keeps everything that varies, without the per-type
    boilerplate (``profile_ref`` is kept so the row can still be expanded).
    """
    expanded = dict(record)
    ref = expanded.pop(PROFILE_REF_KEY, None)
    context_ref = expanded.pop(CONTEXT_REF_KEY, None)
    if not ref or not profiles:
        return expanded
    profile = profiles.get(str(ref))
    if not isinstance(profile, Mapping):
        return expanded
    codes = profile.get("codes")
    if isinstance(codes, Mapping) and isinstance(expanded.get("details"), Mapping):
        details = dict(expanded["details"])  # type: ignore[arg-type]
        for key, values in codes.items():
            index = details.get(key)
            if isinstance(index, int) and not isinstance(index, bool) and isinstance(values, list):
                details[key] = values[index]
        expanded["details"] = details
    contexts = profile.get("contexts")
    if context_ref and isinstance(contexts, Mapping):
        # Contexts are keyed by the row's source file (path).
        context = contexts.get(str(expanded.get("path") or ""))
        if isinstance(context, Mapping):
            _merge_profile_level(expanded, context, copy_templates=copy_templates)
    if not include_type_templates:
        expanded[PROFILE_REF_KEY] = ref
        return expanded
    _merge_profile_level(expanded, profile, copy_templates=copy_templates)
    return expanded


def cap_list_field(details: MutableMapping[str, object], key: str, limit: int) -> None:
    """Bound ``details[key]`` to ``limit`` items with truncation markers.

    Adds ``<key>_truncated: true`` and ``<key>_total: n`` only when items
    were dropped, so uncapped records keep their exact field set.
    """
    value = details.get(key)
    if not isinstance(value, list) or len(value) <= limit:
        return
    details[f"{key}_total"] = len(value)
    details[f"{key}_truncated"] = True
    details[key] = value[:limit]


def resolve_records_path(payload: Mapping[str, object], payload_path: Path | str | None = None) -> Path | None:
    """Locate the JSONL record stream of a per-kind artifacts payload.

    Prefers ``records_path``; falls back to ``records_file`` next to the
    payload file so relocated run directories keep working. ``None`` means
    the payload carries its records inline in ``artifacts``.
    """
    raw = payload.get("records_path")
    candidates: list[Path] = []
    if raw:
        candidates.append(Path(str(raw)))
    name = payload.get("records_file")
    if name and payload_path is not None:
        candidates.append(Path(payload_path).expanduser().resolve().parent / str(name))
    if not candidates:
        return None
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return candidates[0]


def iter_payload_records(
    payload: Mapping[str, object],
    *,
    payload_path: Path | str | None = None,
    expand: bool = True,
    offset: int = 0,
    limit: int | None = None,
) -> Iterator[dict[str, object]]:
    """Yield every artifact row of a per-kind payload (streamed when JSONL-backed).

    Run outputs keep only a preview in ``artifacts`` and stream the full
    rows to ``records_path``; standalone payloads keep all rows inline.
    ``expand`` merges ``artifact_type_profiles`` back into each row; the
    expanded rows share profile template objects, so treat them as
    read-only (copy before mutating nested values).
    """
    profiles = payload.get(PROFILES_PAYLOAD_KEY) if expand else None
    profiles = profiles if isinstance(profiles, Mapping) else None
    records_path = resolve_records_path(payload, payload_path)
    if records_path is not None:
        rows: Iterable[object] = iter_jsonl_items(records_path, offset=offset, limit=limit)
    else:
        inline = payload.get("artifacts")
        inline = inline if isinstance(inline, list) else []
        end = None if limit is None else offset + max(0, limit)
        rows = inline[offset:end]
    for row in rows:
        if not isinstance(row, dict):
            continue
        if profiles and row.get(PROFILE_REF_KEY):
            yield expand_profile(row, profiles, copy_templates=False)
        else:
            yield row


def payload_record_count(payload: Mapping[str, object]) -> int:
    """Total artifact rows of a per-kind payload (not just the inline preview)."""
    count = payload.get("record_count")
    if isinstance(count, int) and not isinstance(count, bool):
        return count
    summary = payload.get("summary")
    if isinstance(summary, Mapping) and isinstance(summary.get("artifact_count"), int):
        return int(summary["artifact_count"])
    artifacts = payload.get("artifacts")
    return len(artifacts) if isinstance(artifacts, list) else 0


def read_artifact_output_head(path: Path | str) -> dict[str, object]:
    """Top-level members of a per-kind artifacts output except ``artifacts``.

    The (possibly multi-GB legacy) ``artifacts`` array is skipped without
    being materialized.
    """
    head: dict[str, object] = {}
    with open_json(Path(path)) as root:
        for key, node in root.members():
            if key == "artifacts":
                continue
            head[key] = node.materialize()
    return head


def iter_artifact_output_rows(
    path: Path | str,
    *,
    expand: bool = True,
    offset: int = 0,
    limit: int | None = None,
) -> Iterator[dict[str, object]]:
    """Stream every row of a per-kind artifacts output file.

    JSONL-backed outputs stream ``records_path``; legacy inline outputs
    stream their ``artifacts`` array. Rows are profile-expanded (read-only)
    unless ``expand`` is False.
    """
    path = Path(path).expanduser().resolve()
    if not path.is_file():
        return
    head = read_artifact_output_head(path)
    if head.get("records_path") or head.get("records_file"):
        yield from iter_payload_records(head, payload_path=path, expand=expand, offset=offset, limit=limit)
        return
    profiles = head.get(PROFILES_PAYLOAD_KEY) if expand else None
    profiles = profiles if isinstance(profiles, Mapping) else None
    emitted = 0
    for index, row in enumerate(iter_array_items(path, "artifacts")):
        if index < offset:
            continue
        if limit is not None and emitted >= limit:
            return
        if not isinstance(row, dict):
            continue
        emitted += 1
        if profiles and row.get(PROFILE_REF_KEY):
            yield expand_profile(row, profiles, copy_templates=False)
        else:
            yield row


# ---------------------------------------------------------------------------
# Streaming (bounded-memory) hoisting
# ---------------------------------------------------------------------------


_CanonicalCache = dict[int, tuple[object, str]]


def _same(value: object, template: object, cache: _CanonicalCache | None) -> bool:
    """Strict equality (JSON-identical) with the template's canonical form cached."""
    template_type = type(template)
    if template_type in _EXACT_SCALAR_TYPES or template_type in _NUMERIC_TYPES:
        return type(value) is template_type and value == template
    if value is template:
        return True
    if value != template:
        return False
    canonical = None
    if cache is not None:
        hit = cache.get(id(template))
        if hit is not None and hit[0] is template:
            canonical = hit[1]
    if canonical is None:
        canonical = _canonical(template)
        if cache is not None:
            cache[id(template)] = (template, canonical)
    return _canonical(value) == canonical


def _common(left: object, right: object, cache: _CanonicalCache | None = None) -> tuple[bool, object]:
    """Shared template of a running template and one more value.

    Folding ``_common`` over a column yields the template ``_split`` builds
    from the whole column (keys/elements shared by every value, leaves equal
    in every value), so templates can be built one row at a time. When
    nothing changes the same ``left`` object is returned, so cached
    canonical forms stay valid.
    """
    if _same(right, left, cache):
        return True, left
    if isinstance(left, dict) and isinstance(right, dict):
        template: dict[str, object] = {}
        unchanged = True
        for key, value in left.items():
            if key in right:
                hoisted, child = _common(value, right[key], cache)
                if hoisted:
                    template[key] = child
                    unchanged = unchanged and child is value
                    continue
            unchanged = False
        if unchanged:
            return True, left
        return (True, template) if template else (False, None)
    if (
        isinstance(left, list)
        and isinstance(right, list)
        and left
        and len(left) == len(right)
        and all(isinstance(item, dict) for item in left)
        and all(isinstance(item, dict) for item in right)
    ):
        list_template: list[object] = []
        any_hoisted = False
        unchanged = True
        for left_item, right_item in zip(left, right):
            hoisted, child = _common(left_item, right_item, cache)
            if hoisted:
                any_hoisted = True
                list_template.append(child)
                unchanged = unchanged and child is left_item
            else:
                list_template.append({})
                unchanged = unchanged and left_item == {}
        if unchanged and any_hoisted:
            return True, left
        return (True, list_template) if any_hoisted else (False, None)
    return False, None


def _residue(value: object, template: object, cache: _CanonicalCache | None = None) -> object:
    """What ``value`` keeps after ``template`` is hoisted (``_MISSING`` if nothing)."""
    if _same(value, template, cache):
        return _MISSING
    if isinstance(value, dict) and isinstance(template, dict):
        residue: dict[str, object] = {}
        for key, item in value.items():
            if key in template:
                child = _residue(item, template[key], cache)
                if child is not _MISSING:
                    residue[key] = child
            else:
                residue[key] = item
        return residue if residue else _MISSING
    if isinstance(value, list) and isinstance(template, list) and len(value) == len(template):
        items = [_residue(item, part, cache) for item, part in zip(value, template)]
        if all(item is _MISSING for item in items):
            return _MISSING
        return [{} if item is _MISSING else item for item in items]
    return value


class _TemplateTracker:
    """Running templates of one row group (a type, or one source file of a type)."""

    __slots__ = ("cache", "count", "envelope", "envelope_ok", "templates")

    def __init__(self, first_details: Mapping[str, object], candidate: Callable[[str, object], bool]) -> None:
        self.cache: _CanonicalCache = {}
        self.count = 0
        self.templates: dict[str, object] = {
            key: _MISSING for key, value in first_details.items() if candidate(str(key), value)
        }
        self.envelope: object = _MISSING
        self.envelope_ok = True

    def observe(self, details: Mapping[str, object], envelope: object) -> None:
        self.count += 1
        for key in list(self.templates):
            if key not in details:
                del self.templates[key]
                continue
            current = self.templates[key]
            if current is _MISSING:
                self.templates[key] = details[key]
                continue
            hoisted, template = _common(current, details[key], self.cache)
            if hoisted:
                self.templates[key] = template
            else:
                del self.templates[key]
        if not self.envelope_ok:
            return
        if not isinstance(envelope, dict):
            self.envelope_ok = False
            self.envelope = _MISSING
        elif self.envelope is _MISSING:
            self.envelope = envelope
        else:
            hoisted, template = _common(self.envelope, envelope, self.cache)
            if hoisted:
                self.envelope = template
            else:
                self.envelope_ok = False
                self.envelope = _MISSING

    def profile(self) -> dict[str, object]:
        self.cache = {}
        if self.count < 2:
            return {}
        profile: dict[str, object] = {}
        if self.templates:
            profile["details"] = dict(self.templates)
        if self.envelope_ok and isinstance(self.envelope, dict) and self.envelope:
            profile[ENVELOPE_KEY] = self.envelope
        return profile


def _strip_level(row: dict[str, object], level: Mapping[str, object], cache: _CanonicalCache | None = None) -> None:
    details = row.get("details")
    templates = level.get("details")
    if isinstance(details, dict) and isinstance(templates, Mapping):
        for key, template in templates.items():
            if key in details:
                residue = _residue(details[key], template, cache)
                if residue is _MISSING:
                    del details[key]
                else:
                    details[key] = residue
    envelope_template = level.get(ENVELOPE_KEY)
    if envelope_template is not None and isinstance(row.get(ENVELOPE_KEY), dict):
        residue = _residue(row[ENVELOPE_KEY], envelope_template, cache)
        row[ENVELOPE_KEY] = {} if residue is _MISSING else residue


class StreamingProfileBuilder:
    """Bounded-memory equivalent of ``hoist_constant_blocks`` over a row stream.

    Pass 1 (``observe``) sees every un-hoisted row once and keeps only running
    templates per artifact_type (O(#candidate keys)) plus row counts per
    (type, source file); ``finish_types`` freezes the type templates.
    Pass 2 (``strip_type`` then ``observe_context``) removes the type level
    from each row and builds per-file context templates (only for files with
    at least ``context_min_rows`` rows) and short-vocabulary code tables;
    ``finish_contexts`` freezes them. Pass 3 (``strip_context``) removes the
    file level and dictionary-encodes labels. ``profiles`` has the shape
    ``expand_profile`` reverses.
    """

    def __init__(
        self,
        *,
        keys: Iterable[str] | Callable[[str], bool] = is_hoistable_detail_key,
        hoist_scalars: bool = True,
        context_min_rows: int = CONTEXT_MIN_ROWS,
    ) -> None:
        selector = _key_selector(keys)

        def type_candidate(key: str, value: object) -> bool:
            return selector(key) or (
                hoist_scalars and isinstance(value, _SCALAR_TYPES) and is_hoistable_scalar_key(key)
            )

        self._type_candidate = type_candidate
        self._context_min_rows = max(2, context_min_rows)
        self._types: dict[str, _TemplateTracker] = {}
        self._path_counts: dict[tuple[str, str], int] = {}
        self._contexts: dict[tuple[str, str], _TemplateTracker] = {}
        self._vocab: dict[str, dict[str, dict[str, int]]] = {}
        self._rejected: dict[str, set[str]] = {}
        self._code_index: dict[str, dict[str, dict[str, int]]] = {}
        # Canonical forms of frozen templates (passes 2 and 3).
        self._canonical_cache: _CanonicalCache = {}
        self.profiles: dict[str, dict[str, object]] = {}

    # pass 1 ------------------------------------------------------------
    def observe(self, row: Mapping[str, object]) -> None:
        details = row.get("details")
        if not isinstance(details, dict):
            return
        artifact_type = str(row.get("artifact_type") or "")
        tracker = self._types.get(artifact_type)
        if tracker is None:
            tracker = _TemplateTracker(details, self._type_candidate)
            self._types[artifact_type] = tracker
        tracker.observe(details, row.get(ENVELOPE_KEY))
        path_key = (artifact_type, str(row.get("path") or ""))
        self._path_counts[path_key] = self._path_counts.get(path_key, 0) + 1

    def finish_types(self) -> None:
        for artifact_type in sorted(self._types):
            profile = self._types[artifact_type].profile()
            if profile:
                self.profiles[artifact_type] = profile

    # pass 2 ------------------------------------------------------------
    def strip_type(self, row: dict[str, object]) -> None:
        if not isinstance(row.get("details"), dict):
            return
        profile = self.profiles.get(str(row.get("artifact_type") or ""))
        if profile:
            _strip_level(row, profile, self._canonical_cache)

    def observe_context(self, row: Mapping[str, object]) -> None:
        details = row.get("details")
        if not isinstance(details, dict):
            return
        artifact_type = str(row.get("artifact_type") or "")
        path = str(row.get("path") or "")
        key = (artifact_type, path)
        if path and self._path_counts.get(key, 0) >= self._context_min_rows:
            tracker = self._contexts.get(key)
            if tracker is None:
                tracker = _TemplateTracker(details, _any_key)
                self._contexts[key] = tracker
            tracker.observe(details, row.get(ENVELOPE_KEY))
        type_tracker = self._types.get(artifact_type)
        if type_tracker is None or type_tracker.count < CODE_MIN_ROWS:
            return
        vocab = self._vocab.setdefault(artifact_type, {})
        rejected = self._rejected.setdefault(artifact_type, set())
        for name, value in details.items():
            if name in rejected:
                continue
            if not isinstance(value, str) or not is_hoistable_scalar_key(str(name)):
                rejected.add(name)
                vocab.pop(name, None)
                continue
            values = vocab.setdefault(name, {})
            if value not in values:
                if len(values) >= CODE_MAX_DISTINCT:
                    rejected.add(name)
                    vocab.pop(name, None)
                    continue
                values[value] = len(values)

    def finish_contexts(self) -> None:
        for artifact_type, path in sorted(self._contexts):
            context = self._contexts[(artifact_type, path)].profile()
            if context:
                profile = self.profiles.setdefault(artifact_type, {})
                contexts = profile.setdefault("contexts", {})
                assert isinstance(contexts, dict)
                contexts[path] = context
        self._contexts.clear()
        for artifact_type in sorted(self._vocab):
            codes = {
                name: list(values)
                for name, values in sorted(self._vocab[artifact_type].items())
                if sum(len(value) for value in values) / max(1, len(values)) >= CODE_MIN_AVERAGE_CHARS
            }
            if codes:
                self.profiles.setdefault(artifact_type, {})["codes"] = codes
                self._code_index[artifact_type] = {
                    name: {value: index for index, value in enumerate(values)} for name, values in codes.items()
                }
        self._vocab.clear()

    # pass 3 ------------------------------------------------------------
    def strip_context(self, row: dict[str, object]) -> dict[str, object]:
        details = row.get("details")
        if not isinstance(details, dict):
            return row
        artifact_type = str(row.get("artifact_type") or "")
        profile = self.profiles.get(artifact_type)
        if not profile:
            return row
        contexts = profile.get("contexts")
        if isinstance(contexts, Mapping):
            context = contexts.get(str(row.get("path") or ""))
            if isinstance(context, Mapping):
                _strip_level(row, context, self._canonical_cache)
                row[CONTEXT_REF_KEY] = True
        code_index = self._code_index.get(artifact_type)
        if code_index:
            for name, index in code_index.items():
                value = details.get(name)
                if isinstance(value, str) and value in index:
                    details[name] = index[value]
        row[PROFILE_REF_KEY] = artifact_type
        return row


def iter_artifact_output_row_views(
    path: Path | str,
) -> Iterator[tuple[int, dict[str, object], dict[str, object]]]:
    """Yield ``(row_index, full_row, varying_row)`` for a per-kind artifacts output.

    ``full_row`` is profile-expanded (read-only templates); ``varying_row``
    restores codes and per-file context but leaves the per-type constant
    templates out (``profile_ref`` kept) -- the compact form indexes store.
    Inline (non-hoisted) outputs yield the same row twice.
    """
    path = Path(path).expanduser().resolve()
    if not path.is_file():
        return
    head = read_artifact_output_head(path)
    profiles = head.get(PROFILES_PAYLOAD_KEY)
    profiles = profiles if isinstance(profiles, Mapping) else None
    if head.get("records_path") or head.get("records_file"):
        rows: Iterable[object] = iter_payload_records(head, payload_path=path, expand=False)
    else:
        rows = iter_array_items(path, "artifacts")
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        if profiles and row.get(PROFILE_REF_KEY):
            yield (
                index,
                expand_profile(row, profiles, copy_templates=False),
                expand_profile(row, profiles, copy_templates=False, include_type_templates=False),
            )
        else:
            yield index, row, row
