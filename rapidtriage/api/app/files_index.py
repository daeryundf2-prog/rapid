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

from .artifact_filter import nfc_fold
from .row_conditions import (
    CONTENT_TYPES,
    DEFAULT_OFFHOURS,
    DEFAULT_WEEKEND,
    MATCH_CACHE,
    PARTIAL_TRUNCATION_KEYS,
    PLACEHOLDER_MOMENTS,
    RowConditions,
    _scalar,
    in_hours,
    parse_moment,
    row_is_partial,
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
# :data:`row_conditions.PLACEHOLDER_MOMENTS` in epoch microseconds: no time (R7 S1 re-review R-13).
PLACEHOLDER_US = frozenset((moment - _EPOCH) // _US for moment in PLACEHOLDER_MOMENTS)
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


def _time_value_us(value: object) -> int:
    """:func:`row_conditions.files_moment` of one value in epoch microseconds (``TIME_NONE`` when
    missing, unparseable or a placeholder)."""
    if value.__class__ is str:
        fast = _fast_utc_us(value)  # type: ignore[arg-type]
        if fast is not None:
            return TIME_NONE if fast in PLACEHOLDER_US else fast
    if not _scalar(value):
        return TIME_NONE
    found = _moment_us(parse_moment(value))
    return TIME_NONE if found in PLACEHOLDER_US else found


def files_copy_time_us(row: object) -> int:
    """An acquisition copy's own ``modified_at`` (the fallback when it has no NTFS ``$SI`` time)."""
    return _time_value_us(row.get("modified_at")) if isinstance(row, Mapping) else TIME_NONE


def files_row_time_us(row: object) -> int:
    """Epoch microseconds of :func:`row_conditions.row_time` of a files row (``TIME_NONE`` when
    none; ``TIME_PENDING_NTFS`` for an acquisition copy that needs the NTFS join -- the rows
    :func:`row_conditions.needs_ntfs_time` picks; without an NTFS time it gets
    :func:`files_copy_time_us`). This is also the 수정 column's time (``sort=mtime``)."""
    if not isinstance(row, Mapping):
        return TIME_NONE
    value = _time_value_us(row.get("fs_modified_at"))
    if value != TIME_NONE:
        return value
    if row.get("modified_at_origin") == "acquisition-copy":
        ntfs = row.get("ntfs")
        if not isinstance(ntfs, Mapping):
            return TIME_PENDING_NTFS
        value = _time_value_us(ntfs.get("si_modified_at"))  # joined ``ntfs`` already on the row
        if value != TIME_NONE:
            return value
    return _time_value_us(row.get("modified_at"))


@dataclass
class _TimeOverlay:
    stamp: tuple[object, ...]
    times: array
    # Pending acquisition copies that got their NTFS ``$SI`` time / fell back to their copy time.
    ntfs: int = 0
    copies: int = 0


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
                                found = (_fromisoformat(value[:19]) - _EPOCH_NAIVE) // _US
                            except ValueError:
                                found = TIME_NONE
                            if found != TIME_NONE and found not in PLACEHOLDER_US:
                                append(found)
                                continue
                    append(files_row_time_us(row))
                self._pending = array("L", (index for index, value in enumerate(column) if value == TIME_PENDING_NTFS))
                self._times = column
            assert self._pending is not None
            return self._times, self._pending

    def joined_times(
        self, rows: Sequence[object], stamp: tuple[object, ...], resolve: Callable[[Sequence[int]], Sequence[int] | None] | None
    ) -> array:
        """The time column with the acquisition copies' NTFS times of join state ``stamp`` (a copy
        without an NTFS time -- no join, no entry, a placeholder -- gets its own copy time)."""
        return self._joined(rows, stamp, resolve).times

    def _joined(
        self, rows: Sequence[object], stamp: tuple[object, ...], resolve: Callable[[Sequence[int]], Sequence[int] | None] | None
    ) -> _TimeOverlay:
        base, pending = self.times(rows)
        if not pending:
            return _TimeOverlay(stamp, base)
        with self._lock:
            overlay = self._overlay
            if overlay is not None and overlay.stamp == stamp:
                return overlay
        values = resolve(pending) if resolve is not None else None
        merged = array("q", base)
        joined = copies = 0
        for offset, position in enumerate(pending):
            value = values[offset] if values is not None else TIME_NONE
            if MIN_US <= value <= MAX_US and value not in PLACEHOLDER_US:
                joined += 1
            else:
                value = files_copy_time_us(rows[position])
                copies += value != TIME_NONE
            merged[position] = value
        overlay = _TimeOverlay(stamp, merged, joined, copies)
        with self._lock:
            self._overlay = overlay
        return overlay

    def time_basis(
        self, rows: Sequence[object], stamp: tuple[object, ...] | None, resolve: Callable[[Sequence[int]], Sequence[int] | None] | None
    ) -> dict[str, object]:
        """Where the rows' 수정 times come from (:func:`files_time_basis`)."""
        base, pending = self.times(rows)
        evidence = sum(1 for value in base if value != TIME_NONE and value != TIME_PENDING_NTFS)
        overlay = self._joined(rows, stamp or ("no-join",), resolve) if pending else _TimeOverlay(("none",), base)
        evidence += overlay.ntfs
        copies = overlay.copies
        if evidence and copies:
            basis = "mixed"
        elif copies:
            basis = "acquisition-copy"
        elif evidence:
            basis = "ntfs"
        else:
            basis = "none"
        return {
            "time_basis": basis,
            "time_basis_counts": {"ntfs": evidence, "acquisition_copy": copies, "none": len(rows) - evidence - copies},
        }

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
        if conditions.resolved is not None:
            # 계열·중복·예외 (R7 갈래 A): the lane's rows in the resolved row sets.
            in_sets = conditions.resolved.files(collection)
            positions = [position for position in positions if position in in_sets]
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
                    continue  # no time (a copy without an NTFS time already holds its own)
                if (low is not None and value < low) or (high is not None and value >= high):
                    continue
                kept.append(position)
            positions = kept
            if conditions.clock:
                positions = _clock_positions(positions, times, conditions, fallback)
        return positions

    return MATCH_CACHE.get_or_compute(key, compute)


def files_time_basis(
    rows: Sequence[object], *, run_id: str, collection: str, files_stamp: tuple[object, ...], ntfs_join: NtfsJoinSource | None = None
) -> dict[str, object]:
    """``{time_basis, time_basis_counts}`` of the list's 수정 times (the ``from``/``to``/``weekday``
    and ``sort=mtime`` time): ``"ntfs"`` = every timed row carries an evidence file-system time
    (``fs_modified_at`` or the joined NTFS ``$SI`` time), ``"acquisition-copy"`` = every timed row
    falls back to its acquisition copy's own time (folder input without an NTFS join), ``"mixed"``,
    ``"none"`` = no row has a time. ``time_basis_counts = {ntfs, acquisition_copy, none}``."""
    columns = FILES_INDEX_CACHE.get(run_id, collection, files_stamp)
    _times, pending = columns.times(rows)
    stamp: tuple[object, ...] | None = None
    resolver: NtfsTimes | None = None
    if pending:
        stamp, resolver = ntfs_join() if ntfs_join is not None else (("no-join",), None)
    return columns.time_basis(rows, stamp, resolver)


# -- server sort and text filter (plan r7 §3.2 갈래 L2) -----------------------------------------

# ``sort=`` keys of ``GET /files`` served from these columns (``flags`` stays triage_flags').
FILES_SORT_KEYS: tuple[str, ...] = ("name", "path", "size", "mtime", "ctime")
FILES_SORT_ORDERS = ("asc", "desc")
# Sort key -> the console's 파일 목록 header (이름 · 경로 · 크기 · 수정 · NTFS 생성).
FILES_SORT_LABELS = {"name": "이름", "path": "경로", "size": "크기", "mtime": "수정", "ctime": "NTFS 생성"}
# Text filter (``q=``): the fields every term must occur in (case-insensitive).
FILES_TEXT_FIELDS = ("name", "path")
_MISSING_TEXT = ""
FILES_NEEDLE_CACHE_ENTRIES = 16
# ``(join stamp, resolver(NTFS time field, positions) -> epoch us | None)``: called only when a
# sort needs NTFS times (``mtime`` of acquisition copies, ``ctime``).
NtfsFieldTimes = Callable[[str, Sequence[int]], Sequence[int] | None]
NtfsFieldSource = Callable[[], tuple[tuple[object, ...], NtfsFieldTimes | None]]


@dataclass(frozen=True)
class FilesSort:
    key: str
    descending: bool

    @property
    def order(self) -> str:
        return "desc" if self.descending else "asc"

    def descriptor(self, values: int | None = None) -> dict[str, object]:
        """``sort`` of a sorted page (the shape of ``GET /artifacts``' sort descriptor) plus
        ``applied: true`` and -- given ``values`` (rows of the list with a value of the key) --
        ``values`` and ``empty`` (no row has one: both orders equal list order)."""
        out: dict[str, object] = {
            "key": self.key,
            "order": self.order,
            "status": "ready",
            "progress": 1.0,
            "label": FILES_SORT_LABELS[self.key],
            "applied": True,
        }
        if values is not None:
            out["values"] = values
            out["empty"] = values == 0
        return out


def split_sort_order(sort: str, order: str | None) -> tuple[str, str]:
    """``(key, order)`` of ``sort=key`` / ``sort=key:dir`` and ``order=`` (case-insensitive;
    ``order`` wins over the suffix; default ``asc``)."""
    text = sort.strip()
    head, _, suffix = text.rpartition(":")
    key, suffix_order = (head, suffix.strip().lower()) if head and suffix.strip().lower() in FILES_SORT_ORDERS else (text, None)
    wanted = (order or suffix_order or "asc").strip().lower()
    return key.strip().lower(), wanted if wanted in FILES_SORT_ORDERS else "asc"


def parse_files_sort(sort: str | None, order: str | None) -> FilesSort | None:
    """``sort=size&order=desc`` (or ``sort=size:DESC``; any case) -> :class:`FilesSort`; None for
    no sort, ``flags`` and unknown keys (see :func:`unknown_sort_descriptor`)."""
    if not sort or not sort.strip():
        return None
    key, wanted = split_sort_order(sort, order)
    if key not in FILES_SORT_KEYS:
        return None
    return FilesSort(key, wanted == "desc")


def unknown_sort_descriptor(sort: str, order: str | None) -> dict[str, object]:
    """``sort`` of a page whose ``sort=`` key is not supported (``status: "unsupported"`` like
    ``GET /artifacts``, ``applied: false`` and a Korean ``reason``): the rows stay in list order."""
    key, wanted = split_sort_order(sort[:128], order)
    key = key[:64]
    return {
        "key": key,
        "order": wanted,
        "status": "unsupported",
        "progress": 0.0,
        "applied": False,
        "reason": f"지원하지 않는 정렬 키입니다: {key} (지원: {', '.join((*FILES_SORT_KEYS, 'flags'))}) — 목록 순서로 표시합니다",
    }


def _text_of(value: object) -> str:
    return value.casefold() if isinstance(value, str) else _MISSING_TEXT


def _name_of(row: Mapping[str, object]) -> str:
    name = row.get("name")
    if isinstance(name, str) and name.strip():
        return name.casefold()
    path = row.get("path")
    if not isinstance(path, str):
        return _MISSING_TEXT
    trimmed = path.rstrip("\\/")
    return trimmed[max(trimmed.rfind("\\"), trimmed.rfind("/")) + 1 :].casefold()


# The 수정 cell's time of a files row (console ``modifiedTimeOf``) is the row-condition time:
# sorting and the ``from``/``to``/``weekday`` conditions read the same column (R7 S1 re-review R-2).
files_display_mtime_us = files_row_time_us


class _FilesSortState:
    """Sort orders and text-filter matches of one :class:`FilesColumns` (built lazily)."""

    def __init__(self) -> None:
        self.text: list[str] | None = None
        self.orders: dict[tuple[object, ...], tuple[array, array]] = {}
        # sort cache key -> rows with a value of the key (the descriptor's ``values``).
        self.present: dict[tuple[object, ...], int] = {}
        self.needles: OrderedDict[str, array] = OrderedDict()


_SORT_STATES_LOCK = threading.Lock()


def _sort_state(columns: FilesColumns) -> _FilesSortState:
    with _SORT_STATES_LOCK:
        state = getattr(columns, "sort_state", None)
        if state is None:
            state = _FilesSortState()
            columns.sort_state = state  # type: ignore[attr-defined]
        return state


def _sort_values(
    rows: Sequence[object], key: str, ntfs: NtfsFieldTimes | None, columns: FilesColumns, join_stamp: tuple[object, ...] | None
) -> tuple[Sequence[object], list[bool]]:
    """``(values, present)`` of one sort key over every row."""
    if key in ("name", "path"):
        texts = [(_name_of(row) if key == "name" else _text_of(row.get("path"))) if isinstance(row, Mapping) else _MISSING_TEXT for row in rows]
        return list(texts), [bool(value) for value in texts]
    if key == "size":
        values: list[object] = []
        present: list[bool] = []
        for row in rows:
            size = row.get("size") if isinstance(row, Mapping) else None
            ok = isinstance(size, int | float) and not isinstance(size, bool)
            values.append(size if ok else 0)
            present.append(ok)
        return values, present
    if key == "mtime":
        # The row-condition time column (with the NTFS overlay of ``join_stamp`` when copies wait
        # for it): placeholders and missing times sort last in both orders (R-13).
        if join_stamp is None:
            times = columns.times(rows)[0]
        else:
            resolve = (lambda positions: ntfs("si_modified_at", positions)) if ntfs is not None else None
            times = columns.joined_times(rows, join_stamp, resolve)
        return times, [value != TIME_NONE and value != TIME_PENDING_NTFS for value in times]
    # ctime = the "NTFS 생성" column (the NTFS join's ``created_at``); no join = no values.
    resolved = ntfs("created_at", range(len(rows))) if ntfs is not None and rows else None
    if resolved is None:
        return [0] * len(rows), [False] * len(rows)
    created = [value if MIN_US <= value <= MAX_US and value not in PLACEHOLDER_US else TIME_NONE for value in resolved]
    return list(created), [value != TIME_NONE for value in created]


def files_sort_order(
    rows: Sequence[object],
    *,
    run_id: str,
    collection: str,
    files_stamp: tuple[object, ...],
    sort: FilesSort,
    ntfs_join: NtfsFieldSource | None = None,
) -> tuple[array, array]:
    """``(order, rank)`` of every row under ``sort``: ``order`` = positions in sort order (rows
    without a value last in both orders; ties keep list order), ``rank[position]`` = its place.
    Built once per files revision, collection, key, order and -- for ``mtime`` / ``ctime`` -- NTFS
    join state; later pages slice it."""
    columns = FILES_INDEX_CACHE.get(run_id, collection, files_stamp)
    join_stamp: tuple[object, ...] | None = None
    resolver: NtfsFieldTimes | None = None
    if sort.key == "ctime" or (sort.key == "mtime" and len(columns.times(rows)[1]) > 0):
        join_stamp, resolver = ntfs_join() if ntfs_join is not None else (("no-join",), None)
    cache_key = (sort.key, sort.descending, join_stamp)
    state = _sort_state(columns)
    with _SORT_STATES_LOCK:
        found = state.orders.get(cache_key)
    if found is not None:
        return found
    values, present = _sort_values(rows, sort.key, resolver, columns, join_stamp)
    with_value = [position for position in range(len(rows)) if present[position]]
    # Python's sort is stable with reverse=True too: equal values keep list order.
    with_value.sort(key=values.__getitem__, reverse=sort.descending)
    order = array("L", with_value)
    order.extend(position for position in range(len(rows)) if not present[position])
    rank = array("L", bytes(order.itemsize * len(order)))
    for place, position in enumerate(order):
        rank[position] = place
    with _SORT_STATES_LOCK:
        # A new NTFS join state replaces the older one's order (never served again).
        for stale in [item for item in state.orders if item[:2] == cache_key[:2] and item != cache_key]:
            del state.orders[stale]
            state.present.pop(stale, None)
        state.orders[cache_key] = (order, rank)
        state.present[cache_key] = len(with_value)
    return order, rank


def files_sort_values(rows: Sequence[object], *, run_id: str, collection: str, files_stamp: tuple[object, ...], sort: FilesSort) -> int | None:
    """Rows of the list with a value of ``sort.key`` (after :func:`files_sort_order` built it)."""
    state = _sort_state(FILES_INDEX_CACHE.get(run_id, collection, files_stamp))
    with _SORT_STATES_LOCK:
        for cache_key, count in state.present.items():
            if cache_key[:2] == (sort.key, sort.descending):
                return count
    return None


def files_text_positions(rows: Sequence[object], *, run_id: str, collection: str, files_stamp: tuple[object, ...], needle: str) -> array:
    """Ascending positions of the rows whose name or path holds every whitespace-separated term
    of ``needle`` (case-insensitive, Unicode NFC-folded on both sides like ``/artifacts?path_contains``,
    so an NFD Korean query finds NFC names and vice versa) -- the ``q=`` filter of ``GET /files``."""
    terms = [nfc_fold(term) for term in needle.split() if term]
    state = _sort_state(FILES_INDEX_CACHE.get(run_id, collection, files_stamp))
    cache_key = "\n".join(terms)
    with _SORT_STATES_LOCK:
        found = state.needles.get(cache_key)
        if found is not None:
            state.needles.move_to_end(cache_key)
            return found
        text = state.text
    if text is None:
        text = [nfc_fold(f"{_name_of(row)}\n{_text_of(row.get('path'))}") if isinstance(row, Mapping) else _MISSING_TEXT for row in rows]
    matched = array("L", (position for position, value in enumerate(text) if all(term in value for term in terms)))
    with _SORT_STATES_LOCK:
        state.text = text
        state.needles[cache_key] = matched
        while len(state.needles) > FILES_NEEDLE_CACHE_ENTRIES:
            state.needles.popitem(last=False)
    return matched


def files_ordered_positions(
    rows: Sequence[object],
    *,
    run_id: str,
    collection: str,
    files_stamp: tuple[object, ...],
    base: Sequence[int] | None,
    needle: str = "",
    sort: FilesSort | None = None,
    ntfs_join: NtfsFieldSource | None = None,
) -> Sequence[int]:
    """The rows of a sorted / text-filtered ``GET /files`` query in display order: ``base`` (the
    positions the other filters kept, ascending; None = every row) narrowed by the ``q=`` terms
    and put in ``sort`` order (list order without a sort)."""
    keep: Sequence[int] | None = base
    if needle.strip():
        matched = files_text_positions(rows, run_id=run_id, collection=collection, files_stamp=files_stamp, needle=needle)
        if keep is None:
            keep = matched
        else:
            wanted = set(matched)
            keep = [position for position in keep if position in wanted]
    if sort is None:
        return keep if keep is not None else range(len(rows))
    order, rank = files_sort_order(rows, run_id=run_id, collection=collection, files_stamp=files_stamp, sort=sort, ntfs_join=ntfs_join)
    if keep is None:
        return order
    if len(keep) * 4 >= len(rows):
        # Most rows kept: one linear walk of the full order instead of sorting the subset.
        flags = bytearray(len(rows))
        for position in keep:
            flags[position] = 1
        return array("L", (position for position in order if flags[position]))
    return sorted(keep, key=rank.__getitem__)
