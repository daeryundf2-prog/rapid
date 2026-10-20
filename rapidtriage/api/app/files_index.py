"""Column index of the files output for ``GET /files`` row conditions (plan r6 §3.3 갈래 B).

``GET /files`` used to run the generic row predicate (:meth:`RowConditions.matches`) over the
whole ``candidates`` / ``inventory`` list on every page. This module keeps, per run, collection
and files-output revision (:func:`row_conditions.output_stamp`), small columns built once and
only for the conditions actually asked for:

* category combination id per row (``categories`` filter and the category part of 콘텐츠 유형),
* row time in epoch microseconds (``fs_modified_at`` / ``modified_at``; an acquisition copy's
  NTFS ``$SI`` modified time comes from a join overlay keyed by the NTFS join state),
* 콘텐츠 유형 bit mask and 부분 결과 flag.

The matching positions of one ``(categories, conditions, path restriction)`` query are kept in
:data:`row_conditions.MATCH_CACHE` under ``("files", run_id, collection, files stamp, join
stamp, categories, conditions, restriction)``, so the next page slices them and ``matched`` is
exact. The answer equals the generic predicate (tests/test_r6_s3_files_cache.py); the rare row
time outside the UTC ``datetime`` range falls back to that predicate per row. Everything lives
in memory: a read-only run output folder works unchanged.
"""

from __future__ import annotations

import datetime as dt
import threading
from array import array
from collections import OrderedDict
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass

from .row_conditions import (
    CONTENT_TYPES,
    DEFAULT_OFFHOURS,
    DEFAULT_WEEKEND,
    MATCH_CACHE,
    PARTIAL_TRUNCATION_KEYS,
    RowConditions,
    _scalar,
    in_hours,
    parse_moment,
    row_is_partial,
    row_time,
)

# Row time sentinels (real times are >= year 1 = about -6.2e16 us).
TIME_NONE = -(2**63)
TIME_PENDING_NTFS = TIME_NONE + 1  # acquisition copy: time from the NTFS join overlay
_EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
_EPOCH_NAIVE = dt.datetime(1970, 1, 1)
_fromisoformat = dt.datetime.fromisoformat
_US = dt.timedelta(microseconds=1)
MIN_US = (dt.datetime(1, 1, 1, tzinfo=dt.timezone.utc) - _EPOCH) // _US
MAX_US = (dt.datetime(9999, 12, 31, 23, 59, 59, 999999, tzinfo=dt.timezone.utc) - _EPOCH) // _US
_HOUR_US = 3_600_000_000
_DAY_US = 86_400_000_000
FILES_INDEX_MAX_ENTRIES = 4
# Keys whose absence means :func:`row_conditions.row_is_partial` is False (it reads nothing else).
PARTIAL_KEYS = frozenset({"artifact_type", "details", "parser_error", "parse_status", "decrypt_status", "coverage"}) | PARTIAL_TRUNCATION_KEYS
CONTENT_IDS: tuple[str, ...] = tuple(CONTENT_TYPES)
# Content types matched by extension only (no scan category): 영상 · 음성.
EXTENSION_CONTENT_BITS = sum(1 << bit for bit, content_id in enumerate(CONTENT_IDS) if not CONTENT_TYPES[content_id].categories)
_NOT_MAPPING = ("X",)


def _combo_key(row: object) -> tuple[object, ...]:
    """Identity of a row's ``categories`` value (``("L", names…)`` for a list, ``("N",)`` otherwise)."""
    if not isinstance(row, Mapping):
        return _NOT_MAPPING
    values = row.get("categories")
    if isinstance(values, list):
        return ("L", *(str(item) for item in values))
    return ("N",)


def _combo_categories(combo: tuple[object, ...], collection: str) -> frozenset[str]:
    """:func:`artifact_filter.file_row_categories` of a combination (non-rows: none)."""
    if combo is _NOT_MAPPING or combo == _NOT_MAPPING:
        return frozenset()
    if combo[0] == "L" and len(combo) > 1:
        return frozenset(str(item) for item in combo[1:])
    return frozenset({"other"}) if collection == "inventory" else frozenset()


def _combo_content_bits(combo: tuple[object, ...]) -> int:
    """Bits of the content types a files row gets from its scan categories alone."""
    names = {str(item) for item in combo[1:]} if combo and combo[0] == "L" else set()
    bits = 0
    for bit, content_id in enumerate(CONTENT_IDS):
        spec = CONTENT_TYPES[content_id]
        if spec.categories and names.intersection(spec.categories):
            bits |= 1 << bit
    return bits


def _extension_content_bits(extension: str) -> int:
    """Bits of the content types without scan categories (영상 · 음성) the extension gives."""
    bits = 0
    for bit, content_id in enumerate(CONTENT_IDS):
        spec = CONTENT_TYPES[content_id]
        if not spec.categories and extension in spec.extensions:
            bits |= 1 << bit
    return bits


def fast_path_extension(value: object) -> str:
    """:func:`row_conditions.path_extension` without the regex split (same answer)."""
    if not isinstance(value, str) or not value:
        return ""
    text = value.strip()
    name = text[max(text.rfind("\\"), text.rfind("/")) + 1 :]
    stem, dot, ext = name.rpartition(".")
    if not dot or not stem or not ext or len(ext) > 12 or not ext.replace("-", "").isalnum():
        return ""
    return ext.lower()


def _moment_us(moment: dt.datetime | None) -> int:
    return TIME_NONE if moment is None else (moment - _EPOCH) // _US


def _fast_utc_us(value: str) -> int | None:
    """``YYYY-MM-DDTHH:MM:SSZ`` (the scan's own format) -> epoch microseconds, as
    :func:`row_conditions.parse_moment` reads it but without its regex; None for other shapes."""
    if len(value) == 20 and value[4::3] == "--T::Z" and value[:4].isdigit():
        try:
            return (_fromisoformat(value[:19]) - _EPOCH_NAIVE) // _US
        except ValueError:
            return TIME_NONE
    return None


def files_row_time_us(row: object) -> int:
    """Epoch microseconds of :func:`row_conditions.row_time` of a files row (``TIME_NONE`` when
    none; ``TIME_PENDING_NTFS`` for an acquisition copy that needs the NTFS join -- the rows
    :func:`row_conditions.needs_ntfs_time` picks)."""
    if not isinstance(row, Mapping):
        return TIME_NONE
    value = row.get("fs_modified_at")
    if value.__class__ is str:
        fast = _fast_utc_us(value)  # type: ignore[arg-type]
        if fast is not None:
            return fast
    if not _scalar(value):
        if row.get("modified_at_origin") == "acquisition-copy":
            if not isinstance(row.get("ntfs"), Mapping):
                return TIME_PENDING_NTFS
            return _moment_us(row_time(row, "files"))  # joined ``ntfs`` already on the row
        value = row.get("modified_at")
        if value.__class__ is str:
            fast = _fast_utc_us(value)  # type: ignore[arg-type]
            if fast is not None:
                return fast
        if not _scalar(value):
            return TIME_NONE
    return _moment_us(parse_moment(value))


@dataclass
class _TimeOverlay:
    stamp: tuple[object, ...]
    times: array


class FilesColumns:
    """Columns of one collection of one files-output revision (built lazily, per condition)."""

    def __init__(self, key: tuple[object, ...], collection: str) -> None:
        self.key = key
        self.collection = collection
        self._lock = threading.Lock()
        self._combo: array | None = None
        self._combos: list[tuple[object, ...]] = []
        self._times: array | None = None
        self._pending: array | None = None
        self._overlay: _TimeOverlay | None = None
        self._content: array | None = None
        self._partial: bytearray | None = None

    # -- columns ------------------------------------------------------------------------------

    def combos(self, rows: Sequence[object]) -> tuple[array, list[tuple[object, ...]]]:
        with self._lock:
            if self._combo is None:
                ids: dict[tuple[object, ...], int] = {}
                combos: list[tuple[object, ...]] = []
                column = array("I")
                append = column.append
                raw_ids: dict[tuple[object, ...], int] = {}  # all-str category tuples, as listed
                for row in rows:
                    if row.__class__ is dict:
                        values = row.get("categories")
                        if values.__class__ is list:
                            raw = tuple(values)
                            try:
                                found = raw_ids.get(raw)
                            except TypeError:  # an unhashable item
                                found = None
                            if found is not None:
                                append(found)
                                continue
                    combo = _combo_key(row)
                    found = ids.get(combo)
                    if found is None:
                        found = ids[combo] = len(combos)
                        combos.append(combo)
                    if combo[0] == "L" and all(item.__class__ is str for item in combo[1:]):
                        raw_ids[combo[1:]] = found
                    append(found)
                self._combo, self._combos = column, combos
            return self._combo, self._combos

    def times(self, rows: Sequence[object]) -> tuple[array, array]:
        """``(time column, positions of acquisition copies waiting for the NTFS join)``."""
        with self._lock:
            if self._times is None:
                column = array("q")
                append = column.append
                for row in rows:
                    if row.__class__ is dict:
                        # Fast path of the common shapes (same answer as files_row_time_us).
                        value = row.get("fs_modified_at")
                        if value is None and row.get("modified_at_origin") is None:
                            value = row.get("modified_at")
                        if value.__class__ is str and len(value) == 20 and value[4::3] == "--T::Z" and value[:4].isdigit():
                            try:
                                append((_fromisoformat(value[:19]) - _EPOCH_NAIVE) // _US)
                            except ValueError:
                                append(TIME_NONE)
                            continue
                    append(files_row_time_us(row))
                self._pending = array("L", (index for index, value in enumerate(column) if value == TIME_PENDING_NTFS))
                self._times = column
            assert self._pending is not None
            return self._times, self._pending

    def joined_times(
        self, rows: Sequence[object], stamp: tuple[object, ...], resolve: Callable[[Sequence[int]], Sequence[int] | None] | None
    ) -> array:
        """The time column with the acquisition copies' NTFS times of join state ``stamp``."""
        base, pending = self.times(rows)
        if not pending:
            return base
        with self._lock:
            overlay = self._overlay
            if overlay is not None and overlay.stamp == stamp:
                return overlay.times
        values = resolve(pending) if resolve is not None else None
        merged = array("q", base)
        if values is None:
            for position in pending:
                merged[position] = TIME_NONE
        else:
            for position, value in zip(pending, values):
                merged[position] = value if MIN_US <= value <= MAX_US else TIME_NONE
        with self._lock:
            self._overlay = _TimeOverlay(stamp, merged)
        return merged

    def extension_bits(self, rows: Sequence[object]) -> array:
        """Content bits each row gets from its path extension (영상 · 음성, no scan category)."""
        with self._lock:
            if self._content is None:
                by_extension: dict[str, int] = {}
                column = array("L")
                append = column.append
                for row in rows:
                    if not isinstance(row, Mapping):
                        append(0)
                        continue
                    extension = fast_path_extension(row.get("path") or row.get("name"))
                    bits = by_extension.get(extension)
                    if bits is None:
                        bits = by_extension[extension] = _extension_content_bits(extension)
                    append(bits)
                self._content = column
            return self._content

    def partial(self, rows: Sequence[object]) -> bytearray:
        with self._lock:
            if self._partial is None:
                keys = PARTIAL_KEYS
                self._partial = bytearray(
                    1 if isinstance(row, Mapping) and not keys.isdisjoint(row.keys()) and row_is_partial(row) else 0 for row in rows
                )
            return self._partial


class FilesIndexCache:
    """LRU of :class:`FilesColumns` per ``(run_id, collection)``; a new files stamp replaces it."""

    def __init__(self, max_entries: int = FILES_INDEX_MAX_ENTRIES) -> None:
        self._lock = threading.Lock()
        self._items: OrderedDict[tuple[str, str], FilesColumns] = OrderedDict()
        self._max_entries = max_entries

    def clear(self) -> None:
        with self._lock:
            self._items.clear()

    def get(self, run_id: str, collection: str, stamp: tuple[object, ...]) -> FilesColumns:
        slot = (run_id, collection)
        with self._lock:
            found = self._items.get(slot)
            if found is None or found.key != stamp:
                found = self._items[slot] = FilesColumns(stamp, collection)
            self._items.move_to_end(slot)
            while len(self._items) > self._max_entries:
                self._items.popitem(last=False)
            return found


FILES_INDEX_CACHE = FilesIndexCache()


def clear_files_index_cache() -> None:
    FILES_INDEX_CACHE.clear()


def _clock_table(conditions: RowConditions) -> list[bool]:
    """``table[weekday * 24 + hour]`` = :meth:`RowConditions._clock_matches` of that local time."""
    table: list[bool] = []
    for weekday in range(7):
        for hour in range(24):
            if conditions.offhours:
                days = conditions.weekdays if conditions.weekdays is not None else DEFAULT_WEEKEND
                window = conditions.hours or DEFAULT_OFFHOURS
                table.append(weekday in days or in_hours(hour, window))
            else:
                table.append(
                    (conditions.weekdays is None or weekday in conditions.weekdays)
                    and (conditions.hours is None or in_hours(hour, conditions.hours))
                )
    return table


def _clock_positions(positions: list[int], times: array, conditions: RowConditions, fallback: Callable[[int], bool]) -> list[int]:
    table = _clock_table(conditions)
    zone = conditions.tz
    if isinstance(zone, dt.timezone):
        offset = zone.utcoffset(None) // _US
        kept: list[int] = []
        for position in positions:
            value = times[position]
            if value < MIN_US or value > MAX_US:
                if fallback(position):
                    kept.append(position)
                continue
            local = value + offset
            if local < MIN_US or local > MAX_US:
                continue  # the zone cannot represent it (year 1 / 9999 edge)
            if table[((local // _DAY_US + 3) % 7) * 24 + (local // _HOUR_US) % 24]:
                kept.append(position)
        return kept
    # A named zone: its UTC offset per UTC hour (constant unless a transition falls inside the
    # hour -- then, and near the year 1 / 9999 edges, each row converts on its own).
    offsets: dict[int, int | None] = {}
    low_edge, high_edge = MIN_US + 2 * _DAY_US, MAX_US - 2 * _DAY_US

    def offset_at(value: int) -> int:
        local = (_EPOCH + dt.timedelta(microseconds=value)).astimezone(zone)
        return local.utcoffset() // _US  # type: ignore[operator]

    kept = []
    for position in positions:
        value = times[position]
        if value < MIN_US or value > MAX_US:
            if fallback(position):
                kept.append(position)
            continue
        if low_edge <= value <= high_edge:
            bucket = value // _HOUR_US
            if bucket in offsets:
                offset = offsets[bucket]
            else:
                start = bucket * _HOUR_US
                first = offset_at(start)
                offset = offsets[bucket] = first if offset_at(start + _HOUR_US - 1) == first else None
            if offset is not None:
                local = value + offset
                if table[((local // _DAY_US + 3) % 7) * 24 + (local // _HOUR_US) % 24]:
                    kept.append(position)
                continue
        try:
            moment = (_EPOCH + dt.timedelta(microseconds=value)).astimezone(zone)
        except (OverflowError, ValueError):
            continue
        if table[moment.weekday() * 24 + moment.hour]:
            kept.append(position)
    return kept


NtfsTimes = Callable[[Sequence[int]], Sequence[int] | None]
# ``() -> (join stamp, resolver | None)``: called only when an acquisition copy needs its time.
NtfsJoinSource = Callable[[], tuple[tuple[object, ...], NtfsTimes | None]]


def files_matched_positions(
    rows: Sequence[object],
    *,
    run_id: str,
    collection: str,
    files_stamp: tuple[object, ...],
    categories: Collection[str] = (),
    conditions: RowConditions | None = None,
    restrict: Sequence[int] | None = None,
    restrict_key: tuple[object, ...] | None = None,
    ntfs_join: NtfsJoinSource | None = None,
) -> array:
    """Ascending positions of ``rows`` (or of ``restrict``, in its order) whose categories meet
    ``categories`` and that pass ``conditions`` -- what the old per-page scans of
    ``filter_files_by_category`` / ``filter_files_rows`` selected. Cached in ``MATCH_CACHE``
    (``restrict`` without ``restrict_key`` is computed but not cached)."""
    wanted = frozenset(categories)
    columns = FILES_INDEX_CACHE.get(run_id, collection, files_stamp)
    join_stamp: tuple[object, ...] | None = None
    resolver: NtfsTimes | None = None
    if conditions is not None and conditions.uses_time:
        _times, pending = columns.times(rows)
        if pending:
            join_stamp, resolver = ntfs_join() if ntfs_join is not None else (("no-join",), None)
    key: tuple[object, ...] | None = (
        "files",
        run_id,
        collection,
        files_stamp,
        join_stamp,
        tuple(sorted(wanted)),
        conditions.cache_key() if conditions is not None else None,
        restrict_key,
    )
    if restrict is not None and restrict_key is None:
        key = None

    def compute() -> list[int]:
        positions: list[int] = list(restrict) if restrict is not None else list(range(len(rows)))
        if wanted:
            combo, combos = columns.combos(rows)
            allowed = [not wanted.isdisjoint(_combo_categories(item, collection)) for item in combos]
            positions = [position for position in positions if allowed[combo[position]]]
        # Without categories, rows that are not objects drop out of every condition below on their
        # own (no time, not partial, no content bits), so no category column is needed.
        if conditions is None:
            return positions
        if conditions.partial:
            flags = columns.partial(rows)
            positions = [position for position in positions if flags[position]]
        if conditions.content is not None:
            want = 0
            for bit, content_id in enumerate(CONTENT_IDS):
                if content_id in conditions.content:
                    want |= 1 << bit
            combo, combos = columns.combos(rows)
            by_combo = [_combo_content_bits(item) & want for item in combos]
            if want & EXTENSION_CONTENT_BITS:
                bits = columns.extension_bits(rows)
                positions = [position for position in positions if by_combo[combo[position]] or bits[position] & want]
            else:
                positions = [position for position in positions if by_combo[combo[position]]]
        if conditions.geo is not None:
            return []  # files rows carry no coordinates (the route answers 422 before this)
        if conditions.uses_time:
            times = columns.joined_times(rows, join_stamp, resolver) if join_stamp is not None else columns.times(rows)[0]

            def fallback(position: int) -> bool:
                row = rows[position]
                return isinstance(row, Mapping) and conditions.matches(row, "files")

            low = (conditions.time_from - _EPOCH) // _US if conditions.time_from is not None else None
            high = (conditions.time_until - _EPOCH) // _US if conditions.time_until is not None else None
            kept: list[int] = []
            for position in positions:
                value = times[position]
                if value <= TIME_PENDING_NTFS:
                    continue
                if (low is not None and value < low) or (high is not None and value >= high):
                    continue
                kept.append(position)
            positions = kept
            if conditions.clock:
                positions = _clock_positions(positions, times, conditions, fallback)
        return positions

    return MATCH_CACHE.get_or_compute(key, compute)
