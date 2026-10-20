"""Column index of the timeline events for row conditions (plan R6 §3.3 갈래 A).

``GET /timeline`` with ``from``/``to``/``weekday``/``hours``/``offhours``/``partial``/``content``
used to run :meth:`RowConditions.matches` on every event (ISO parsing, ``details`` walks) -- about
5 s for 500k events. This module keeps one small column index per timeline revision instead:

* ``epoch_us`` (``array('q')``) -- the row time (``row_conditions.row_time``: ``timestamp``) as
  microseconds since 1970-01-01T00:00Z; :data:`MISSING` (INT64_MIN) when absent / unparseable.
  Naive text is UTC (as in ``row_time``), so a condition's ``tz`` never changes a stored value.
* ``has_offset`` (``bytearray``) -- 1 when the timestamp carried an offset (``Z`` / ``±HH:MM``).
* ``content_mask`` (``array('H')``) -- 콘텐츠 유형 bits in ``row_conditions.CONTENT_TYPES`` order.
* ``partial`` (``bytearray``) -- ``row_conditions.row_is_partial``.

Weekday / hour are not stored (they depend on ``tz``): they come from the epoch plus a fixed
offset, or for an IANA zone from a per-UTC-hour offset cache (an hour with a transition inside, or
one the zone cannot represent, is converted event by event). Evaluation yields exactly the
positions of the predicate scan (tests compare both on random events, year 1 / 9999 edges
included) and goes into ``row_conditions.MATCH_CACHE`` as before, so later pages are unchanged.

One index per timeline revision (key ``row_conditions.output_stamp``, single-flight per run),
saved next to the timeline as :data:`INDEX_FILE_NAME` with a header carrying the timeline size /
mtime, the event count and a fingerprint of the content / partial rules. A run writes it when its
timeline stage completes (:func:`write_timeline_index`). An older run gets it on its first
conditioned request: the columns that request needs are built first (a time condition only parses
the timestamps), the rest -- and the file -- follow (in the background for a large timeline). A
header that does not match is ignored and the index rebuilt; a folder that cannot be written -- or
``RAPIDTRIAGE_INDEX_PERSIST=0`` (``index_cache.index_persist_enabled``) -- keeps the index in
memory only. Any index failure falls back to the predicate scan -- never a 500.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
import logging
import os
import struct
import sys
import threading
import time
from array import array
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from pathlib import Path

from .index_cache import SingleFlightIndexCache, index_persist_enabled
from .row_conditions import (
    _FRACTION,
    CONTENT_TYPES,
    DECRYPT_OK,
    DEFAULT_OFFHOURS,
    DEFAULT_WEEKEND,
    PARTIAL_STATUS_PHRASES,
    PARTIAL_STATUS_WORDS,
    PARTIAL_TRUNCATION_KEYS,
    PARTIAL_TYPE_TOKENS,
    TARGET_PATH_KEYS,
    RowConditions,
    _partial_status,
    in_hours,
    parse_moment,
)

LOGGER = logging.getLogger(__name__)

INDEX_FILE_NAME = "rapidtriage-timeline-index.bin"
INDEX_MAGIC = b"RTTLIDX1"
INDEX_VERSION = 1
MISSING = -(2**63)  # INT64_MIN: no parseable row time
US = dt.timedelta(microseconds=1)
HOUR_US = 3_600_000_000
DAY_US = 24 * HOUR_US
_EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
_NAIVE_EPOCH = dt.datetime(1970, 1, 1)
MIN_US = (dt.datetime(1, 1, 1) - _NAIVE_EPOCH) // US
MAX_US = (dt.datetime(9999, 12, 31, 23, 59, 59, 999999) - _NAIVE_EPOCH) // US
_WEEK_SHIFT = 72  # hour 0 since the epoch (1970-01-01) is a Thursday: weekday 3 * 24
CONTENT_IDS: tuple[str, ...] = tuple(CONTENT_TYPES)
CONTENT_BITS: dict[str, int] = {content_id: 1 << bit for bit, content_id in enumerate(CONTENT_IDS)}
# Keys that can make a container 부분 결과 (row_conditions._partial_container): a container with
# none of them is never partial.
_PARTIAL_KEYS = frozenset({"parser_error", "parse_status", "decrypt_status", "coverage", *PARTIAL_TRUNCATION_KEYS})
_TARGET_KEYS = frozenset(TARGET_PATH_KEYS)
_HEADER_LEN = struct.Struct("<I")
TIME, CONTENT, PARTIAL = "time", "content", "partial"
COLUMNS: tuple[str, ...] = (TIME, CONTENT, PARTIAL)
# Timelines up to this many events complete their index (and file) inside the first request;
# larger ones finish the remaining columns and the file in a background thread.
SYNC_COMPLETE_MAX_EVENTS = 50_000
BACKGROUND_PAUSE_S = 0.001


def _rules_fingerprint() -> str:
    """Identity of the rules the stored columns were computed with (a change rebuilds the index)."""
    rules = repr(
        (
            INDEX_VERSION,
            [(key, spec.types, sorted(spec.extensions)) for key, spec in CONTENT_TYPES.items()],
            TARGET_PATH_KEYS,
            sorted(PARTIAL_STATUS_WORDS),
            PARTIAL_STATUS_PHRASES,
            sorted(PARTIAL_TRUNCATION_KEYS),
            PARTIAL_TYPE_TOKENS,
            sorted(DECRYPT_OK),
        )
    )
    return hashlib.sha256(rules.encode("utf-8")).hexdigest()[:16]


RULES_FINGERPRINT = _rules_fingerprint()


# --- column values (exactly row_conditions.row_time / row_content_types / row_is_partial) ---------


def event_epoch(value: object) -> tuple[int, int]:
    """``(epoch_us, has_offset)`` of a ``timestamp`` value; ``(MISSING, 0)`` when it has no time.

    The reading of ``row_time(row, "timeline")`` (``parse_moment``) with a quicker path for text."""
    if isinstance(value, str):
        text = value.strip()
        if len(text) < 10 or not text[:4].isdigit():
            return MISSING, 0
        if len(text) > 10 and text[10] == " ":
            text = f"{text[:10]}T{text[11:]}"
        if text[-1] in "Zz":
            text = text[:-1] + "+00:00"
        if "." in text:
            text = _FRACTION.sub(r"\1", text)
        try:
            moment = dt.datetime.fromisoformat(text)
        except ValueError:
            return MISSING, 0
        if moment.tzinfo is None:
            return (moment - _NAIVE_EPOCH) // US, 0
        return (moment - _EPOCH) // US, 1
    if value is None or isinstance(value, (Mapping, list)):
        return MISSING, 0
    moment = parse_moment(value)
    return (MISSING, 0) if moment is None else ((moment - _EPOCH) // US, 1)


def _extension(value: str) -> str:
    """``row_conditions.path_extension`` of a string (without the regex split)."""
    text = value.strip()
    name = text[max(text.rfind("/"), text.rfind("\\")) + 1 :]
    stem, dot, ext = name.rpartition(".")
    if not dot or not stem or not ext or len(ext) > 12 or not ext.replace("-", "").isalnum():
        return ""
    return ext.lower()


def _is_mapping(row: object) -> bool:
    return type(row) is dict or isinstance(row, Mapping)


def _artifact_type(row: Mapping[str, object], details: Mapping[str, object] | None) -> str:
    raw = row.get("artifact_type") or (details.get("artifact_type") if details else None) or ""
    return (raw if type(raw) is str else str(raw)).lower()


def _details_of(row: Mapping[str, object]) -> Mapping[str, object] | None:
    details = row.get("details")
    return details if type(details) is dict or isinstance(details, Mapping) else None


Pause = Callable[[], None] | None
CHUNK_ROWS = 4096
# Background slices are small: a request thread waits for the GIL until the build pauses, so a
# 4096-row slice (~6 ms) made the next page right after a first page cost ~45 ms on a real
# 330k-event timeline; 512-row slices keep it at ~15-20 ms (the build itself takes ~2x longer).
BACKGROUND_CHUNK_ROWS = 512


def _chunks(events: Sequence[object], pause: Pause) -> Iterator[tuple[int, Sequence[object]]]:
    """``events`` in slices; ``pause`` between slices lets request threads run (background build)."""
    step = CHUNK_ROWS if pause is None else BACKGROUND_CHUNK_ROWS
    for start in range(0, len(events), step):
        if pause is not None and start:
            pause()
        yield start, events[start : start + step]


def time_column(events: Sequence[object], pause: Pause = None) -> tuple[array, bytearray]:
    """``epoch_us`` / ``has_offset``: :func:`event_epoch` with its common text path inlined."""
    epoch = array("q", [MISSING]) * len(events)
    offsets = bytearray(len(events))
    fromisoformat = dt.datetime.fromisoformat
    utc_epoch, naive_epoch, micro = _EPOCH, _NAIVE_EPOCH, US
    previous: object = None
    previous_epoch, previous_offset = MISSING, 0
    for start, chunk in _chunks(events, pause):
        for position, row in enumerate(chunk, start):
            if type(row) is not dict and not isinstance(row, Mapping):
                continue
            value = row.get("timestamp")
            if type(value) is not str:
                if value is not None:
                    epoch[position], offsets[position] = event_epoch(value)
                continue
            if value == previous:  # sorted timelines repeat a timestamp often
                epoch[position], offsets[position] = previous_epoch, previous_offset
                continue
            previous, previous_epoch, previous_offset = value, MISSING, 0
            text = value.strip()
            # parse_moment also rejects a text whose first 4 characters are not digits; so does
            # fromisoformat (an ISO year is 4 ASCII digits), so that check is left to it.
            if len(text) < 10:
                continue
            if text[10:11] == " ":
                text = f"{text[:10]}T{text[11:]}"
            last = text[-1]
            if last == "Z" or last == "z":
                text = text[:-1] + "+00:00"
            if "." in text:
                dot = text.find(".")
                # _FRACTION (a 7th fraction digit) can only match with one there or a second dot.
                if text[dot + 7 : dot + 8].isdigit() or text.count(".") > 1:
                    text = _FRACTION.sub(r"\1", text)
            try:
                moment = fromisoformat(text)
            except ValueError:
                continue
            if moment.tzinfo is None:
                previous_epoch = epoch[position] = (moment - naive_epoch) // micro
            else:
                previous_epoch = epoch[position] = (moment - utc_epoch) // micro
                previous_offset = offsets[position] = 1
    return epoch, offsets


def content_column(events: Sequence[object], pause: Pause = None) -> array:
    """``content_mask``: ``row_content_types(row, "timeline")`` as bits, memoised per (type, ext)."""
    masks = array("H", bytes(2 * len(events)))
    memo: dict[tuple[str, str], int] = {}
    for start, chunk in _chunks(events, pause):
        for position, row in enumerate(chunk, start):
            if not _is_mapping(row):
                continue
            details = _details_of(row)  # type: ignore[arg-type]
            artifact_type = _artifact_type(row, details)  # type: ignore[arg-type]
            target = ""
            if details and not _TARGET_KEYS.isdisjoint(details):
                for key in TARGET_PATH_KEYS:
                    path = details.get(key)
                    if isinstance(path, str):
                        target = _extension(path)
                        if target:
                            break
            key = (artifact_type, target)
            mask = memo.get(key)
            if mask is None:
                mask = 0
                for content_id, spec in CONTENT_TYPES.items():
                    typed = artifact_type and any(artifact_type == p or artifact_type.startswith(p) for p in spec.types)
                    if typed or (target and target in spec.extensions):
                        mask |= CONTENT_BITS[content_id]
                memo[key] = mask
            masks[position] = mask
    return masks


def _container_partial(container: Mapping[str, object], statuses: dict[str, bool]) -> bool:
    """``row_conditions._partial_container`` with the parse-status words memoised."""
    if _PARTIAL_KEYS.isdisjoint(container):
        return False
    if container.get("parser_error") is True:
        return True
    status = container.get("parse_status")
    if isinstance(status, str) and status:
        failing = statuses.get(status)
        if failing is None:
            failing = statuses[status] = _partial_status(status)
        if failing:
            return True
    decrypt = container.get("decrypt_status")
    if isinstance(decrypt, str) and decrypt.lower() not in DECRYPT_OK:
        return True
    coverage = container.get("coverage")
    if coverage == "partial" or (isinstance(coverage, Mapping) and coverage.get("status") == "partial"):
        return True
    return any(container.get(key) is True for key in PARTIAL_TRUNCATION_KEYS)


def partial_column(events: Sequence[object], pause: Pause = None) -> bytearray:
    """``partial``: ``row_is_partial`` with type tokens and parse statuses memoised."""
    flags = bytearray(len(events))
    types: dict[str, bool] = {}
    statuses: dict[str, bool] = {}
    for start, chunk in _chunks(events, pause):
        for position, row in enumerate(chunk, start):
            if not _is_mapping(row):
                continue
            details = _details_of(row)  # type: ignore[arg-type]
            artifact_type = _artifact_type(row, details)  # type: ignore[arg-type]
            typed = types.get(artifact_type)
            if typed is None:
                typed = types[artifact_type] = any(token in artifact_type for token in PARTIAL_TYPE_TOKENS)
            if (
                typed
                or _container_partial(row, statuses)  # type: ignore[arg-type]
                or (details is not None and _container_partial(details, statuses))
            ):
                flags[position] = 1
    return flags


# --- the index ---------------------------------------------------------------------------------------


class TimelineIndex:
    """Columns of one timeline revision; a column is ``None`` until something needs it."""

    def __init__(
        self,
        count: int,
        *,
        stamp: tuple[int, int] | None = None,
        timeline_path: Path | None = None,
        source: str = "built",
    ) -> None:
        self.count = count
        self.stamp = stamp  # timeline (size, mtime_ns) the columns describe
        self.timeline_path = timeline_path
        self.source = source  # built | file
        self.epoch_us: array | None = None
        self.has_offset: bytearray | None = None
        self.content_mask: array | None = None
        self.partial: bytearray | None = None
        self.saved = False
        self._lock = threading.Lock()  # saved / completing flags
        # One lock per column: a request never waits for a column it does not need.
        self._column_locks = {column: threading.Lock() for column in COLUMNS}
        self._completing = False

    def has(self, column: str) -> bool:
        if column == TIME:
            return self.epoch_us is not None
        if column == CONTENT:
            return self.content_mask is not None
        return self.partial is not None

    def complete(self) -> bool:
        return all(self.has(column) for column in COLUMNS)

    def ensure(self, events: Sequence[object], columns: Iterable[str], pause: Pause = None) -> None:
        """Build the missing ``columns`` from ``events`` (one pass per column)."""
        for column in columns:
            if self.has(column):
                continue
            with self._column_locks[column]:
                if self.has(column):
                    continue
                if column == TIME:
                    epoch, offsets = time_column(events, pause)
                    self.has_offset, self.epoch_us = offsets, epoch
                elif column == CONTENT:
                    self.content_mask = content_column(events, pause)
                else:
                    self.partial = partial_column(events, pause)

    def complete_and_save(self, events: Sequence[object], pause: Pause = None) -> None:
        """All columns, then the index file when the timeline is still the indexed revision."""
        self.ensure(events, COLUMNS, pause)
        with self._lock:
            if self.saved or self.timeline_path is None or self.stamp is None or not index_persist_enabled():
                return
            if _file_stamp(self.timeline_path) != self.stamp:
                return
            self.saved = save_index(self, index_path_for(self.timeline_path), self.stamp)


def build_timeline_index(events: Sequence[object]) -> TimelineIndex:
    """All columns of ``events`` (no file)."""
    index = TimelineIndex(len(events))
    index.ensure(events, COLUMNS)
    return index


def _file_stamp(timeline_path: Path) -> tuple[int, int] | None:
    try:
        stat = timeline_path.stat()
    except OSError:
        return None
    return stat.st_size, stat.st_mtime_ns


def index_path_for(timeline_path: Path) -> Path:
    return timeline_path.with_name(INDEX_FILE_NAME)


def _header(count: int, stamp: tuple[int, int]) -> dict[str, object]:
    return {
        "version": INDEX_VERSION,
        "timeline_size": stamp[0],
        "timeline_mtime_ns": stamp[1],
        "count": count,
        "rules": RULES_FINGERPRINT,
        "content_ids": list(CONTENT_IDS),
        "byteorder": sys.byteorder,
    }


def save_index(index: TimelineIndex, index_path: Path, stamp: tuple[int, int]) -> bool:
    """Write a complete index atomically; ``False`` (memory only) when the folder is not writable."""
    if index.epoch_us is None or index.has_offset is None or index.content_mask is None or index.partial is None:
        return False
    header = json.dumps(_header(index.count, stamp), separators=(",", ":")).encode("utf-8")
    temp = index_path.with_name(f"{index_path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        with temp.open("wb") as handle:
            handle.write(INDEX_MAGIC)
            handle.write(_HEADER_LEN.pack(len(header)))
            handle.write(header)
            index.epoch_us.tofile(handle)
            handle.write(index.has_offset)
            index.content_mask.tofile(handle)
            handle.write(index.partial)
        os.replace(temp, index_path)
        return True
    except OSError as exc:
        LOGGER.info("timeline index not saved to %s (memory only): %s", index_path, exc)
        try:
            temp.unlink()
        except OSError:
            pass
        return False


def load_index(index_path: Path, stamp: tuple[int, int] | None, count: int | None = None) -> TimelineIndex | None:
    """The saved index when its header matches ``stamp`` (and ``count``), else ``None``."""
    if stamp is None:
        return None
    try:
        with index_path.open("rb") as handle:
            if handle.read(len(INDEX_MAGIC)) != INDEX_MAGIC:
                return None
            (length,) = _HEADER_LEN.unpack(handle.read(_HEADER_LEN.size))
            if length > 65536:
                return None
            header = json.loads(handle.read(length).decode("utf-8"))
            if not isinstance(header, dict) or not isinstance(header.get("count"), int):
                return None
            total = header["count"]
            if header != _header(total, stamp) or (count is not None and total != count) or total < 0:
                return None
            epoch = array("q")
            epoch.fromfile(handle, total)
            offsets = bytearray(handle.read(total))
            masks = array("H")
            masks.fromfile(handle, total)
            partial = bytearray(handle.read(total))
            if len(offsets) != total or len(partial) != total or handle.read(1):
                return None
    except (OSError, ValueError, EOFError, struct.error, UnicodeDecodeError):
        return None
    index = TimelineIndex(total, stamp=stamp, timeline_path=None, source="file")
    index.epoch_us, index.has_offset, index.content_mask, index.partial = epoch, offsets, masks, partial
    index.saved = True
    return index


def write_timeline_index(events: Sequence[object], timeline_path: Path) -> Path | None:
    """Run completion (timeline stage): build and save the index of a just-written timeline."""
    stamp = _file_stamp(timeline_path)
    if stamp is None:
        return None
    target = index_path_for(timeline_path)
    return target if save_index(build_timeline_index(events), target, stamp) else None


def open_index(timeline_path: Path, count: int) -> TimelineIndex:
    """The saved index when it matches the timeline revision, else an empty one to fill (with no
    ``timeline_path`` -- nothing to save -- when index files must not be written)."""
    stamp = _file_stamp(timeline_path)
    found = load_index(index_path_for(timeline_path), stamp, count)
    if found is not None:
        return found
    return TimelineIndex(count, stamp=stamp, timeline_path=timeline_path if index_persist_enabled() else None)


# --- evaluation ----------------------------------------------------------------------------------


def needed_columns(conditions: RowConditions) -> tuple[str, ...]:
    columns: list[str] = []
    if conditions.uses_time:
        columns.append(TIME)
    if conditions.content is not None:
        columns.append(CONTENT)
    if conditions.partial:
        columns.append(PARTIAL)
    return tuple(columns)


def _bound_us(moment: dt.datetime | None) -> int | None:
    return None if moment is None else (moment - _EPOCH) // US


def hour_of_week_table(conditions: RowConditions) -> bytes:
    """168 flags (``weekday * 24 + hour``) of the local clocks ``_clock_matches`` accepts."""
    table = bytearray(168)
    for weekday in range(7):
        for hour in range(24):
            if conditions.offhours:
                days = conditions.weekdays if conditions.weekdays is not None else DEFAULT_WEEKEND
                ok = weekday in days or in_hours(hour, conditions.hours or DEFAULT_OFFHOURS)
            else:
                ok = (conditions.weekdays is None or weekday in conditions.weekdays) and (
                    conditions.hours is None or in_hours(hour, conditions.hours)
                )
            table[weekday * 24 + hour] = 1 if ok else 0
    return bytes(table)


class _ZoneClock:
    """Local hour-of-week of UTC instants in an IANA zone with the zone's UTC offset cached per
    UTC day (plan: 날짜별 오프셋 캐시). A day is cached when the offset is the same at 00, 06, 12,
    18 h and its last microsecond (zones do not change offset and back within six hours); a day
    with a transition goes per UTC hour (same offset at the hour's first and last microsecond),
    and an hour with a transition inside -- or an edge the zone cannot represent -- converts its
    instants one by one, exactly like ``astimezone``."""

    _MIXED = object()

    def __init__(self, zone: dt.tzinfo) -> None:
        self.zone = zone
        self.days: dict[int, object] = {}
        self._hours: dict[int, int | None] = {}

    def _local(self, utc_us: int) -> dt.datetime | None:
        if not MIN_US <= utc_us <= MAX_US:
            return None
        try:
            return (_EPOCH + dt.timedelta(microseconds=utc_us)).astimezone(self.zone)
        except (OverflowError, ValueError):
            return None

    def _offset(self, utc_us: int) -> int | None:
        local = self._local(utc_us)
        return None if local is None else (local.replace(tzinfo=None) - _NAIVE_EPOCH) // US - utc_us

    def _same_offset(self, points: Iterable[int]) -> int | None:
        found: int | None = None
        for index, point in enumerate(points):
            offset = self._offset(point)
            if offset is None or (index and offset != found):
                return None
            found = offset
        return found

    def day_offset(self, day: int) -> object:
        found = self.days.get(day)
        if found is None:
            start = day * DAY_US
            offset = self._same_offset((start, start + 6 * HOUR_US, start + 12 * HOUR_US, start + 18 * HOUR_US, start + DAY_US - 1))
            found = self._MIXED if offset is None else offset
            self.days[day] = found
        return found

    def _hour_offset(self, hour: int) -> int | None:
        if hour in self._hours:
            return self._hours[hour]
        offset = self._same_offset((hour * HOUR_US, hour * HOUR_US + HOUR_US - 1))
        self._hours[hour] = offset
        return offset

    def hour_of_week(self, utc_us: int) -> int | None:
        offset = self.day_offset(utc_us // DAY_US)
        if offset is self._MIXED:
            offset = self._hour_offset(utc_us // HOUR_US)
        if offset is not None:
            return ((utc_us + offset) // HOUR_US + _WEEK_SHIFT) % 168  # type: ignore[operator]
        local = self._local(utc_us)
        return None if local is None else local.weekday() * 24 + local.hour


def _zone_positions(epoch: array, low: int, high: int, table: bytes, clock: _ZoneClock) -> list[int]:
    """IANA clock condition: per-UTC-day offsets inline (the per-event call only off that path)."""
    days = clock.days
    day_offset = clock.day_offset
    hour_of_week = clock.hour_of_week
    positions: list[int] = []
    append = positions.append
    for i, value in enumerate(epoch):
        if low <= value < high:
            offset = days.get(value // DAY_US)
            if offset is None:
                offset = day_offset(value // DAY_US)
            if type(offset) is int:
                if table[((value + offset) // HOUR_US + _WEEK_SHIFT) % 168]:
                    append(i)
            else:
                how = hour_of_week(value)
                if how is not None and table[how]:
                    append(i)
    return positions


def evaluate(index: TimelineIndex, conditions: RowConditions) -> list[int]:
    """Positions of the events passing ``conditions`` (the set ``conditions.predicate`` passes).

    The index must hold :func:`needed_columns` of ``conditions``."""
    positions: list[int] | None = None
    if conditions.uses_time:
        epoch = index.epoch_us
        assert epoch is not None
        low = _bound_us(conditions.time_from)
        high = _bound_us(conditions.time_until)
        low = MISSING + 1 if low is None else max(low, MISSING + 1)
        high = 2**63 if high is None else high
        if not conditions.clock:
            positions = [i for i, value in enumerate(epoch) if low <= value < high]
        else:
            table = hour_of_week_table(conditions)
            zone = conditions.tz
            if isinstance(zone, dt.timezone):
                offset = zone.utcoffset(None) // US
                # astimezone: the UTC instant and the local wall clock must both be representable.
                low = max(low, MIN_US, MIN_US - offset)
                high = min(high, MAX_US + 1, MAX_US + 1 - offset)
                shift = offset + _WEEK_SHIFT * HOUR_US
                positions = [
                    i for i, value in enumerate(epoch) if low <= value < high and table[(value + shift) // HOUR_US % 168]
                ]
            else:
                positions = _zone_positions(epoch, low, high, table, _ZoneClock(zone))
    if conditions.partial:
        partial = index.partial
        assert partial is not None
        if positions is None:
            positions = [i for i, flag in enumerate(partial) if flag]
        else:
            positions = [i for i in positions if partial[i]]
    if conditions.content is not None:
        masks = index.content_mask
        assert masks is not None
        want = 0
        for content_id in conditions.content:
            want |= CONTENT_BITS[content_id]
        if positions is None:
            positions = [i for i, mask in enumerate(masks) if mask & want]
        else:
            positions = [i for i in positions if masks[i] & want]
    # No condition the index answers (``geo`` is a 422 on /timeline): nothing narrows the list.
    return list(range(index.count)) if positions is None else positions


_ONLY_FIELDS: dict[str, dict[str, object]] = {
    TIME: {"time_from": None, "time_to": None, "time_until": None, "weekdays": None, "hours": None, "offhours": False},
    CONTENT: {"content": None},
    PARTIAL: {"partial": False},
}
# Built first when a request needs several missing columns (the rest is checked on its matches).
FIRST_COLUMN_ORDER: tuple[str, ...] = (PARTIAL, CONTENT, TIME)


def only_columns(conditions: RowConditions, columns: Iterable[str]) -> RowConditions:
    """``conditions`` without the parts answered by other columns (``geo`` dropped too)."""
    keep = set(columns)
    changes: dict[str, object] = {"geo": None}
    for column, cleared in _ONLY_FIELDS.items():
        if column not in keep:
            changes.update(cleared)
    return dataclasses.replace(conditions, **changes)  # type: ignore[arg-type]


def evaluate_building(index: TimelineIndex, events: Sequence[object], conditions: RowConditions) -> list[int]:
    """:func:`evaluate`, building what is missing: with several needed columns missing only one is
    built over all events (:data:`FIRST_COLUMN_ORDER`); the others are computed for its matches
    only (an AND of per-row tests, so the set is the same), and complete later."""
    needed = needed_columns(conditions)
    missing = [column for column in needed if not index.has(column)]
    if len(missing) <= 1 or index.count <= SYNC_COMPLETE_MAX_EVENTS:
        index.ensure(events, needed)
        return evaluate(index, conditions)
    present = [column for column in needed if index.has(column)]
    if not present:
        first = next(column for column in FIRST_COLUMN_ORDER if column in missing)
        index.ensure(events, (first,))
        present, missing = [first], [column for column in missing if column != first]
    candidates = evaluate(index, only_columns(conditions, present))
    subset = TimelineIndex(len(candidates))
    subset.ensure([events[position] for position in candidates], missing)
    return [candidates[position] for position in evaluate(subset, only_columns(conditions, missing))]


# --- API entry -----------------------------------------------------------------------------------

TIMELINE_INDEXES: SingleFlightIndexCache[TimelineIndex] = SingleFlightIndexCache(max_runs=4)
_BACKGROUND: set[threading.Thread] = set()
_BACKGROUND_LOCK = threading.Lock()


def _yield_to_requests() -> None:
    """Background build: give the GIL to request threads between slices."""
    time.sleep(BACKGROUND_PAUSE_S)


def _complete_later(index: TimelineIndex, events: Sequence[object]) -> None:
    """Finish the remaining columns and the file (in a thread for a large timeline)."""
    with index._lock:
        if index._completing or (index.complete() and (index.saved or index.timeline_path is None)):
            return
        index._completing = True

    def run() -> None:
        try:
            index.complete_and_save(events, _yield_to_requests)
        except Exception as exc:  # a background build never takes the server down
            LOGGER.warning("timeline index completion failed: %s", exc)
        finally:
            with _BACKGROUND_LOCK:
                _BACKGROUND.discard(threading.current_thread())

    if index.count <= SYNC_COMPLETE_MAX_EVENTS:
        index.complete_and_save(events)
        return
    thread = threading.Thread(target=run, name="timeline-index", daemon=True)
    with _BACKGROUND_LOCK:
        _BACKGROUND.add(thread)
    thread.start()


def wait_for_background(timeout: float = 30.0) -> bool:
    """Join pending background completions (perf script / tests); ``True`` when none is left."""
    with _BACKGROUND_LOCK:
        threads = list(_BACKGROUND)
    for thread in threads:
        thread.join(timeout)
    with _BACKGROUND_LOCK:
        return not _BACKGROUND


def timeline_positions(
    run_id: str,
    timeline_path: Path,
    events: Sequence[object],
    conditions: RowConditions,
    stamp: tuple[object, ...],
) -> Callable[[], Iterable[int]]:
    """``MATCH_CACHE`` compute of ``GET /timeline``: positions from the run's index, or the
    predicate scan when the index cannot be used (an index problem never fails the request)."""

    def compute() -> Iterable[int]:
        try:
            index = TIMELINE_INDEXES.get_or_build((run_id, stamp), lambda: open_index(timeline_path, len(events)))
            if index.count == len(events):
                positions = evaluate_building(index, events, conditions)
                if not index.complete() or not index.saved:
                    _complete_later(index, events)
                return positions
            LOGGER.warning("timeline index of %s has %d rows for %d events; scanning", run_id, index.count, len(events))
        except Exception as exc:  # the scan below answers instead of a 500
            LOGGER.warning("timeline index of %s failed (%s); scanning", run_id, exc)
        predicate = conditions.predicate("timeline")
        return [i for i, row in enumerate(events) if isinstance(row, Mapping) and predicate(row)]

    return compute
