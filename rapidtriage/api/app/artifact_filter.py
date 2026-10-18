"""Streaming path / artifact_type / channel / record-field filter for per-kind artifact outputs (``GET /api/runs/{id}/artifacts``)."""

from __future__ import annotations

import unicodedata
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from pathlib import Path

from ...core.artifact_profiles import payload_record_count
from ...core.eventlog_channels import GROUP_LABELS, ChannelFilter
from .jsonl_records import iter_artifact_records

ARTIFACT_PATH_FILTER_SCAN_CAP = 2_000_000
# Rows scanned per request by the all-kinds ``artifact_type=`` pager.
CROSS_KIND_SCAN_CAP = 200_000
# ``channel=`` (event-log channel, exact match on ``details.channel``) bounds.
MAX_CHANNEL_VALUES = 256
MAX_CHANNEL_CHARS = 256


def normalize_channel_filter(values: Collection[str], groups: Collection[str] = ()) -> ChannelFilter | None:
    """Validated ``channel=`` / ``channel_group=`` values (``None`` without any); ``ValueError`` with a Korean message.

    A ``channel`` value is one exact channel name (``Security``,
    ``Microsoft-Windows-PowerShell/Operational``): non-empty after trimming,
    at most ``MAX_CHANNEL_CHARS`` characters, no control characters; at most
    ``MAX_CHANNEL_VALUES`` values per request. A ``channel_group`` value is a
    group id of ``core.eventlog_channels`` (``security`` ... ``other``,
    ``none``, ``services``).
    """
    wanted_groups: list[str] = []
    for value in groups:
        text = str(value).strip()
        if text not in GROUP_LABELS:
            known = ", ".join(sorted(GROUP_LABELS))
            raise ValueError(f"channel_group 값 '{text[:64]}'을(를) 알 수 없습니다 — 다음 중 하나: {known}")
        wanted_groups.append(text)
    cleaned: list[str] = []
    for value in values:
        text = str(value).strip()
        if not text:
            raise ValueError("channel 값이 비어 있습니다 — 채널 이름을 정확히 지정하세요(예: Security)")
        if len(text) > MAX_CHANNEL_CHARS:
            raise ValueError(f"channel 값은 {MAX_CHANNEL_CHARS}자 이하여야 합니다")
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in text):
            raise ValueError("channel 값에 제어 문자를 쓸 수 없습니다")
        cleaned.append(text)
    if len(set(cleaned)) > MAX_CHANNEL_VALUES:
        raise ValueError(f"channel 값은 요청당 {MAX_CHANNEL_VALUES}개 이하여야 합니다")
    channel_filter = ChannelFilter(frozenset(cleaned), frozenset(wanted_groups))
    return channel_filter or None


def as_channel_filter(channels: ChannelFilter | Collection[str] | None) -> ChannelFilter | None:
    if isinstance(channels, ChannelFilter):
        return channels or None
    return ChannelFilter(frozenset(channels)) if channels else None


# Exact record-field filters of ``GET /artifacts`` (r2 console fix M2): query
# parameter -> the record field it matches (``details.<field>``, else the row's
# top-level field). ``browser=ie-edge-legacy`` pages the WebCacheV01 rows,
# ``service=teams`` one desktop messenger app.
RECORD_FIELD_FILTERS: tuple[str, ...] = ("browser", "service")
FIELD_FILTER_MAX_VALUES = 32
FIELD_FILTER_MAX_LENGTH = 200
FieldFilters = Mapping[str, frozenset[str]]


def parse_field_filters(values: Mapping[str, Sequence[str]]) -> dict[str, frozenset[str]] | None:
    """``{"browser": [...], "service": [...]}`` query values -> exact-match sets (``None`` when none).

    Raises :class:`ValueError` with a Korean message (the route answers 422)
    for an empty value, a control character, an over-long value or too many values.
    """
    parsed: dict[str, frozenset[str]] = {}
    for field, raw_values in values.items():
        if field not in RECORD_FIELD_FILTERS:
            raise ValueError(f"지원하지 않는 필드 필터입니다: {field}")
        cleaned: list[str] = []
        for raw in raw_values:
            value = str(raw).strip()
            if not value:
                raise ValueError(f"{field} 값이 비어 있습니다 — 정확한 값을 지정하세요")
            if len(value) > FIELD_FILTER_MAX_LENGTH:
                raise ValueError(f"{field} 값이 너무 깁니다(최대 {FIELD_FILTER_MAX_LENGTH}자)")
            if any(ord(char) < 32 for char in value):
                raise ValueError(f"{field} 값에 제어 문자가 있습니다")
            cleaned.append(value)
        if len(cleaned) > FIELD_FILTER_MAX_VALUES:
            raise ValueError(f"{field} 값은 최대 {FIELD_FILTER_MAX_VALUES}개까지 지정할 수 있습니다")
        if cleaned:
            parsed[field] = frozenset(cleaned)
    return parsed or None


def record_field_value(row: Mapping[str, object], field: str) -> str:
    """``details.<field>`` of a row (string form), else its top-level ``field``."""
    details = row.get("details")
    if isinstance(details, Mapping) and details.get(field) not in (None, ""):
        return str(details.get(field))
    value = row.get(field)
    return "" if value is None else str(value)


def field_matching_records(
    payload: dict[str, object],
    *,
    payload_path: Path,
    fields: FieldFilters | None,
    scan_cap: int = ARTIFACT_PATH_FILTER_SCAN_CAP,
    row_filter: Callable[[Mapping[str, object]], bool] | None = None,
) -> set[int]:
    """Record indices whose fields match ``fields`` and ``row_filter`` (the sorted pager narrows to them)."""
    matches = row_matcher("", None, None, fields, row_filter)
    found: set[int] = set()
    for scanned, (record_index, row) in enumerate(iter_artifact_records(payload, payload_path=payload_path)):
        if scanned >= scan_cap:
            break
        if matches(row):
            found.add(record_index)
    return found


def nfc_fold(value: object) -> str:
    return unicodedata.normalize("NFC", str(value or "")).casefold()


def filter_artifact_page(
    payload: dict[str, object],
    *,
    payload_path: Path,
    path_contains: str | None,
    offset: int,
    limit: int,
    scan_cap: int = ARTIFACT_PATH_FILTER_SCAN_CAP,
    rows_source: Iterable[tuple[int, dict[str, object]]] | None = None,
    artifact_types: Collection[str] | None = None,
    record_limit: int | None = None,
    channels: ChannelFilter | Collection[str] | None = None,
    fields: FieldFilters | None = None,
    row_filter: Callable[[Mapping[str, object]], bool] | None = None,
) -> dict[str, object]:
    """Page only rows whose ``path`` contains ``path_contains`` (NFC, case-insensitive),
    when ``artifact_types`` is given, whose ``artifact_type`` is one of them,
    when ``channels`` is given, that match it (exact ``details.channel``
    names and/or channel groups, see :class:`ChannelFilter`), with
    ``fields``, whose record fields equal one of the given values, and, with
    ``row_filter``, that predicate holds (analysis ``details`` filters).
    Filter kinds AND together; values within one kind OR.

    Streams the kind's rows; ``offset`` counts matches. Stops after ``limit``
    matches plus one lookahead row, or after ``scan_cap`` scanned rows
    (``truncated``: the total is then unknown and ``scanned`` reports the cost).
    ``rows_source`` yields ``(record_index, row)`` in another order (server
    sort); by default rows stream in JSONL order, records ``0..record_limit-1``
    only when ``record_limit`` is given. Every returned row carries its
    original ``record_index``.
    """
    needle = nfc_fold(path_contains) if path_contains else ""
    wanted_types = frozenset(artifact_types) if artifact_types else None
    wanted_channels = as_channel_filter(channels)
    matches = row_matcher(needle, wanted_types, wanted_channels, fields, row_filter)
    rows: list[object] = []
    matched = 0
    scanned = 0
    has_more = False
    exhausted = True
    if rows_source is None:
        rows_source = iter_artifact_records(payload, payload_path=payload_path, limit=record_limit)
    for record_index, row in rows_source:
        if scanned >= scan_cap:
            # Checked before scanning the next row (like ``filter_across_kinds``):
            # a scan that ends exactly at the cap is complete, not truncated.
            exhausted = False
            break
        scanned += 1
        if matches(row):
            if matched >= offset + limit:
                has_more = True
                exhausted = False
                break
            if matched >= offset:
                rows.append({**row, "record_index": record_index})
            matched += 1
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
        "path_contains": path_contains or None,
        "artifact_types": sorted(wanted_types) if wanted_types is not None else None,
        **(wanted_channels.describe() if wanted_channels is not None else {}),
        **({"fields": {key: sorted(values) for key, values in fields.items()}} if fields else {}),
        "scanned": scanned,
        "truncated": not exhausted and not has_more,
    }
    return page


def row_matcher(
    needle: str,
    wanted_types: frozenset[str] | None,
    wanted_channels: ChannelFilter | None = None,
    fields: FieldFilters | None = None,
    row_filter: Callable[[Mapping[str, object]], bool] | None = None,
):
    """Predicate for the ``path_contains`` (pre-folded ``needle``), ``artifact_type``, channel and exact field filters,
    and ``row_filter`` (row conditions, analysis ``details`` filters) last.

    ``channel`` names match ``details.channel`` exactly; rows without one
    (other kinds, inventory rows) match only the ``none`` channel group.
    """

    def matches(row: Mapping[str, object]) -> bool:
        if wanted_types is not None and str(row.get("artifact_type") or "") not in wanted_types:
            return False
        if wanted_channels is not None and not wanted_channels.matches(row):
            return False
        if fields:
            for field, values in fields.items():
                if record_field_value(row, field) not in values:
                    return False
        if needle and needle not in nfc_fold(row.get("path") or row.get("source_path")):
            return False
        return row_filter is None or row_filter(row)

    return matches


def annotate_page_counts(page: dict[str, object], payload: Mapping[str, object], *, filtered: bool) -> dict[str, object]:
    """Uniform count fields of one kind / analysis page (``/artifacts`` and ``/analyses/{id}/rows``).

    * ``record_count`` -- unfiltered row total of the kind;
    * ``matched`` -- rows matching ``path_contains``/``artifact_type``: exact
      when the filter scan reached the end of the kind, ``null`` when it
      stopped early (``truncated`` at the scan cap, or ``has_more`` after the
      page's lookahead row); equals ``record_count`` without a filter.

    ``pagination.scanned``/``truncated`` stay as the filter reports them.
    """
    record_count = payload_record_count(payload)
    pagination = page.get("pagination") if isinstance(page.get("pagination"), dict) else None
    if not filtered:
        matched: int | None = record_count
    elif pagination is not None and pagination.get("filtered"):
        total = pagination.get("total")
        matched = int(total) if isinstance(total, int) else None
    else:
        matched = None  # e.g. a sorted page whose index is still building
    page["record_count"] = record_count
    page["matched"] = matched
    if pagination is not None:
        pagination["matched"] = matched
    return page


def parse_cross_kind_after(token: str | None) -> tuple[str, int, int] | None:
    """``<kind>:<record_index>:<matched>`` continuation token -> parts (``None`` when absent)."""
    if not token:
        return None
    parts = token.rsplit(":", 2)
    if len(parts) != 3 or not parts[0] or not parts[1].isdigit() or not parts[2].isdigit():
        raise ValueError("after 값은 <kind>:<record_index>:<matched> 형식(숫자는 0 이상 정수)이어야 합니다")
    return parts[0], int(parts[1]), int(parts[2])


def filter_across_kinds(
    sources: Sequence[tuple[str, dict[str, object], Path]],
    *,
    path_contains: str | None,
    artifact_types: Collection[str] | None,
    offset: int,
    limit: int,
    after: str | None = None,
    scan_cap: int | None = None,
    rows_for: Callable[[str, dict[str, object], Path, int], Iterable[tuple[int, dict[str, object]]]] | None = None,
    extra: Mapping[str, object] | None = None,
    channels: ChannelFilter | Collection[str] | None = None,
    fields: FieldFilters | None = None,
    row_filter: Callable[[Mapping[str, object]], bool] | None = None,
) -> dict[str, object]:
    """Page filtered rows across kinds (``sources`` order) as one collection (``row_filter``: row conditions).

    ``rows_for(kind, payload, path, start)`` yields a kind's candidate rows
    from record ``start`` on (default: every record; the flag filter passes
    only flagged rows); ``extra`` is merged into ``cross_kind``.

    Without ``after`` the first ``offset`` matches are skipped (rescanning
    from the first kind); ``after`` (the previous page's ``next_after``)
    resumes right behind the last consumed row instead, so deep pages stay
    within ``scan_cap`` scanned rows per request. Returns
    ``{"artifacts": {kind: {artifacts, record_count}}, "cross_kind": {...}}``;
    ``cross_kind.order`` lists ``[kind, record_index]`` in page order.
    """
    scan_cap = CROSS_KIND_SCAN_CAP if scan_cap is None else scan_cap
    needle = nfc_fold(path_contains) if path_contains else ""
    wanted_types = frozenset(artifact_types) if artifact_types else None
    wanted_channels = as_channel_filter(channels)
    matches = row_matcher(needle, wanted_types, wanted_channels, fields, row_filter)
    kinds = [kind for kind, _payload, _path in sources]
    resume = parse_cross_kind_after(after)
    start_pos, start_index, matched = 0, 0, 0
    skip_until = offset
    if resume is not None:
        if resume[0] not in kinds:
            raise ValueError(f"after 값이 이 요청에 없는 종류를 가리킵니다: {resume[0]}")
        start_pos, start_index, matched = kinds.index(resume[0]), resume[1] + 1, resume[2]
        skip_until = matched
    base = skip_until
    rows_by_kind: dict[str, list[object]] = {kind: [] for kind in kinds}
    order: list[list[object]] = []
    scanned = 0
    has_more = False
    exhausted = True
    last: tuple[str, int] | None = None
    for position in range(start_pos, len(sources)):
        kind, payload, payload_path = sources[position]
        first = start_index if position == start_pos else 0
        kind_rows = (
            rows_for(kind, payload, payload_path, first)
            if rows_for is not None
            else iter_artifact_records(payload, payload_path=payload_path, start=first)
        )
        for record_index, row in kind_rows:
            if scanned >= scan_cap:
                exhausted = False
                break
            scanned += 1
            if matches(row):
                if len(order) >= limit:
                    has_more, exhausted = True, False
                    break
                if matched >= skip_until:
                    rows_by_kind[kind].append({**row, "record_index": record_index})
                    order.append([kind, record_index])
                matched += 1
            last = (kind, record_index)
        if not exhausted:
            break
    next_after = f"{last[0]}:{last[1]}:{matched}" if not exhausted and last is not None else None
    if not exhausted and last is None and resume is not None:
        next_after = after
    record_count = sum(payload_record_count(payload) for _kind, payload, _path in sources)
    return {
        "artifacts": {
            kind: {"artifacts": rows_by_kind[kind], "record_count": payload_record_count(payload)}
            for kind, payload, _path in sources
        },
        "cross_kind": {
            "collection": "artifacts",
            "kinds": kinds,
            "offset": base,
            "limit": limit,
            "returned": len(order),
            "order": order,
            "record_count": record_count,
            "matched": matched if exhausted else None,
            "has_more": has_more or not exhausted,
            "next_offset": base + len(order) if not exhausted else None,
            "next_after": next_after,
            "path_contains": path_contains or None,
            "artifact_types": sorted(wanted_types) if wanted_types is not None else None,
            **(wanted_channels.describe() if wanted_channels is not None else {}),
            **({"fields": {key: sorted(values) for key, values in fields.items()}} if fields else {}),
            "scanned": scanned,
            "truncated": not exhausted and not has_more,
            **dict(extra or {}),
        },
    }


# Row collections of the files output: ``candidates`` (selected categories)
# and ``inventory`` (every other scanned file, parser-quality r2).
FILES_COLLECTIONS = ("candidates", "inventory")
FILES_OTHER_CATEGORY = "other"


def file_row_categories(row: object, collection: str) -> list[str]:
    """``categories`` of a files row; an inventory row without any counts as ``other``
    (the files summary's ``inventory_category_counts`` uses the same rule)."""
    values = row.get("categories") if isinstance(row, Mapping) else None
    if isinstance(values, list) and values:
        return [str(item) for item in values]
    if collection == "inventory" and isinstance(row, Mapping):
        return [FILES_OTHER_CATEGORY]
    return []


def files_page_base(payload: Mapping[str, object], collection: str) -> dict[str, object]:
    """``payload`` without the row collections, plus ``collection`` (never both lists)."""
    page = {key: value for key, value in payload.items() if key not in FILES_COLLECTIONS}
    rows = payload.get(collection)
    page[collection] = rows if isinstance(rows, list) else []
    return page


def filter_files_by_category(
    payload: Mapping[str, object],
    categories: Collection[str],
    *,
    offset: int,
    limit: int,
    collection: str = "candidates",
    scan_cap: int = ARTIFACT_PATH_FILTER_SCAN_CAP,
    row_filter: Callable[[Mapping[str, object]], bool] | None = None,
    rows: Sequence[object] | None = None,
) -> dict[str, object]:
    """Files page of ``collection`` rows whose ``categories`` intersect ``categories``
    (no ``categories``: every row) and, with ``row_filter``, that pass it (row conditions).
    ``rows`` replaces ``payload[collection]`` (rows already joined with NTFS times).

    ``collection`` is ``candidates`` (default) or ``inventory``. The rows are
    already in memory, so the scan runs to the end (or ``scan_cap``) and
    ``matched`` is exact unless ``truncated``. ``limit=0`` returns every
    match. Rows carry ``record_index`` = their position in that collection of
    the files output (locator ``/<collection>/<record_index>``). The page
    holds only ``collection``'s rows (the other list is dropped).
    """
    wanted = frozenset(categories)
    source: Sequence[object] = rows if rows is not None else (payload.get(collection) if isinstance(payload.get(collection), list) else [])  # type: ignore[assignment]
    page_rows: list[object] = []
    matched = 0
    scanned = 0
    exhausted = True
    for record_index, row in enumerate(source):
        if scanned >= scan_cap:
            exhausted = False
            break
        scanned += 1
        if wanted:
            values = file_row_categories(row, collection)
            if not values or wanted.isdisjoint(values):
                continue
        if row_filter is not None and not (isinstance(row, Mapping) and row_filter(row)):
            continue
        if matched >= offset and (limit <= 0 or len(page_rows) < limit):
            page_rows.append({**row, "record_index": record_index})
        matched += 1
    total = matched if exhausted else None
    has_more = (offset + len(page_rows) < matched) if limit > 0 else False
    page = files_page_base(payload, collection)
    page[collection] = page_rows
    page["record_count"] = len(source)
    page["matched"] = total
    page["pagination"] = {
        "collection": collection,
        "offset": offset,
        "limit": limit,
        "returned": len(page_rows),
        "total": total,
        "matched": total,
        "next_offset": offset + len(page_rows) if has_more else None,
        "previous_offset": max(0, offset - limit) if offset > 0 and limit > 0 else None,
        "has_more": has_more or not exhausted,
        "filtered": True,
        "categories": sorted(wanted) if wanted else None,
        "scanned": scanned,
        "truncated": not exhausted,
    }
    return page
