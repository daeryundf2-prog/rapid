"""Whole-kind server-side sort for ``GET /api/runs/{id}/artifacts``.

A per-kind artifacts output streams its rows from a JSONL file
(``records_path``) that is not ordered by any field. Sorting a page needs the
order of *every* record, so a background thread scans the JSONL per
``(run_id, kind, sort key, file size, mtime_ns)`` and keeps, in process
memory only (nothing is written next to the run, its manifest or evidence
bundle):

* the record indices in ascending and in descending order, as ``array('q')``;
* the byte offset of every record's line, as ``array('q')``, so a page seeks
  straight to its rows instead of re-scanning the file.

Records are numbered by ``jsonl_records`` exactly like unsorted pages and the
``path_contains`` filter, so ``record_index`` never depends on the sort.

Sort keys are ``timestamp`` or ``details.<name>`` (a scalar key directly
under ``details``; ``name`` is taken literally and may not contain
whitespace, ``,`` or ``:``). Unsupported keys and payloads report
``status: "unsupported"`` with a Korean ``reason`` shown to the examiner.
``timestamp`` takes the first non-empty value among ``TIME_KEYS`` -- keep
that tuple aligned with ``TIME_KEYS`` in
``frontend/src/features/grid/columns/artifacts.ts``.

Comparison:

* ``timestamp`` compares chronologically (ISO-8601 with any UTC offset,
  naive values as UTC); unparseable values follow every parsed one in both
  orders, in JSONL order.
* Other keys compare numerically when every non-empty value is a number or a
  numeric string (decimal or ``0x`` hex). Integers stay exact Python ints;
  floats only come from text containing ``.``/``e``/``E`` or JSON floats.
  The first scan stores numbers only; when a non-numeric value (or an int
  that does not fit 64 bits) appears, the scan restarts once in text mode,
  where everything compares as case-folded text cut to ``SORT_TEXT_KEY_CHARS``
  (booleans are text). Text keys are bounded by a byte budget.
* Missing / null / empty values and non-finite numbers (NaN, inf) sort last
  in both orders. Ties keep JSONL order in both orders.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import math
import os
import re
import threading
import time
from array import array
from bisect import bisect_left
from collections import OrderedDict
from collections.abc import Collection, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from ...core.artifact_profiles import payload_record_count
from .artifact_filter import filter_artifact_page
from .jsonl_records import (
    expand_row,
    iter_jsonl_records,
    iter_records_at,
    jsonl_records_path,
    parse_record_line,
    payload_profiles,
)
from .pagination import (
    decode_pagination_cursor,
    paginate_artifact_output,
    paginate_payload,
)

LOGGER = logging.getLogger(__name__)

# Keep aligned with frontend/src/features/grid/columns/artifacts.ts TIME_KEYS.
TIME_KEYS: tuple[str, ...] = (
    "timestamp",
    "time",
    "time_created",
    "last_run_at",
    "last_run_time",
    "last_modified",
    "modified_at",
    "key_last_written_at",
    "last_written_at",
    "event_time",
    "normalized_time",
    "created_at",
    "target_modified_at",
)
SORT_ORDERS = frozenset({"asc", "desc"})
SORT_CACHE_MAX_ENTRIES = 8
SORT_CACHE_MAX_BYTES = 256 * 1024 * 1024
# Unsupported reasons are remembered separately from the index LRU.
SORT_UNSUPPORTED_MAX_ENTRIES = 256
# Generic build failures are retried after this many seconds.
SORT_FAILURE_TTL_SECONDS = 60.0
# Rows checked synchronously for a non-scalar key before a background build.
SORT_PROBE_ROWS = 1000
# Concurrent background builds per process; further builds queue (progress 0).
SORT_MAX_CONCURRENT_BUILDS = 2
# Builds waiting for a slot; beyond this a request answers "unsupported".
SORT_MAX_PENDING_BUILDS = 8
# Kinds with more records answer "unsupported" (env RAPIDTRIAGE_SORT_MAX_RECORDS).
SORT_MAX_RECORDS_DEFAULT = 5_000_000
# Estimated bytes of stored text keys per build (env RAPIDTRIAGE_SORT_MAX_TEXT_BYTES).
SORT_MAX_TEXT_BYTES_DEFAULT = 256 * 1024 * 1024
# Text keys are case-folded and cut to this many characters (ties then fall
# back to JSONL order); distinct values up to SORT_TEXT_INTERN_LIMIT are
# shared so repetitive keys (channel, provider, ...) cost one string each.
SORT_TEXT_KEY_CHARS = 256
SORT_TEXT_INTERN_LIMIT = 65_536
# Rows scanned by ``path_contains`` in sorted order (random seeks) per request.
SORTED_FILTER_SCAN_CAP = 200_000
DETAILS_PREFIX = "details."
FAILED_PREFIX = "정렬 인덱스 생성에 실패했습니다"
STALE_INDEX_MESSAGE = "정렬 인덱스가 오래되었습니다. 다시 시도하세요"
QUEUE_FULL_REASON = "대기 중인 정렬 요청이 많습니다. 잠시 후 다시 시도하세요"
TEXT_BUDGET_REASON = "정렬 키 텍스트가 메모리 한도({limit})를 넘어 전체 정렬을 지원하지 않습니다"
_DECIMAL_INT = re.compile(r"[+-]?\d+")
_DECIMAL = re.compile(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?")
_HEX = re.compile(r"[+-]?0[xX][0-9a-fA-F]+")
_INT64_MIN = -(2**63)
_INT64_MAX = 2**63 - 1


class SortUnsupported(Exception):
    """The requested key cannot be sorted server-side (reason in ``str(exc)``)."""


class StaleSortIndex(RuntimeError):
    """A cached index no longer matches the file it points into (route: 409)."""


class _NeedsText(Exception):
    """A numeric scan met a non-numeric value: restart in text mode."""


def parse_sort_key(sort: str) -> str:
    """Validate a sort key: ``timestamp`` or ``details.<scalar key>``."""
    key = sort.strip()
    if key == "timestamp":
        return key
    if key.startswith(DETAILS_PREFIX):
        name = key[len(DETAILS_PREFIX):]
        if name and not any(char.isspace() or char in ",:" for char in name):
            return key
    raise SortUnsupported(f"지원하지 않는 정렬 키입니다: {key!r} (timestamp 또는 details.<필드명>만 가능)")


def _is_empty(value: object) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


def sort_value(row: Mapping[str, object], key: str) -> object:
    """Raw sort value of an (expanded) row; ``None`` when missing or empty.

    Raises ``SortUnsupported`` for a non-scalar ``details.<name>`` value.
    """
    details = row.get("details")
    if not isinstance(details, Mapping):
        return None
    if key == "timestamp":
        for name in TIME_KEYS:
            value = details.get(name)
            if not _is_empty(value) and not isinstance(value, (Mapping, list)):
                return value
        return None
    value = details.get(key[len(DETAILS_PREFIX):])
    if _is_empty(value):
        return None
    if isinstance(value, (Mapping, list)):
        raise SortUnsupported(f"정렬 키 값이 스칼라가 아닙니다: {key}")
    return value


NOT_NUMERIC = object()
NON_FINITE = object()


def as_number(value: object) -> object:
    """Exact number of a number / numeric string, else ``NOT_NUMERIC`` or ``NON_FINITE``.

    Decimal and ``0x`` hex integers stay Python ints; floats come only from
    JSON floats or text containing ``.``/``e``/``E``. NaN and infinities are
    ``NON_FINITE`` (sorted with missing values); integers too large to parse
    are ``NOT_NUMERIC`` (the key then sorts as text).
    """
    if isinstance(value, bool):
        return NOT_NUMERIC
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else NON_FINITE
    if not isinstance(value, str):
        return NOT_NUMERIC
    text = value.strip()
    try:
        if _HEX.fullmatch(text):
            return int(text, 16)
        if _DECIMAL_INT.fullmatch(text):
            return int(text)
        if _DECIMAL.fullmatch(text):
            number = float(text)
            return number if math.isfinite(number) else NON_FINITE
    except (OverflowError, ValueError):
        return NOT_NUMERIC
    return NOT_NUMERIC


def as_epoch(value: object) -> float | None:
    """Epoch seconds of an ISO-8601 string (naive = UTC), else ``None``."""
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.strip())
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.timestamp()
    except (ValueError, OverflowError, OSError):
        return None


def _text(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value).casefold()


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    try:
        return max(1, int(raw)) if raw else default
    except ValueError:
        return default


def sort_max_records() -> int:
    return _env_int("RAPIDTRIAGE_SORT_MAX_RECORDS", SORT_MAX_RECORDS_DEFAULT)


def sort_max_text_bytes() -> int:
    return _env_int("RAPIDTRIAGE_SORT_MAX_TEXT_BYTES", SORT_MAX_TEXT_BYTES_DEFAULT)


def too_many_records(count: int, limit: int) -> SortUnsupported:
    return SortUnsupported(f"레코드 수({count:,}건)가 전체 정렬 한도({limit:,}건)를 넘어 전체 정렬을 지원하지 않습니다")


def _format_bytes(count: int) -> str:
    return f"{count // (1024 * 1024)} MB" if count >= 1024 * 1024 else f"{count:,} B"


class SortKeyCollector:
    """Compact per-row sort keys gathered in one scan (no raw values kept).

    Modes: ``chronological`` (epoch ``array('d')``), ``numeric`` (exact ints
    in ``array('q')`` plus floats in ``array('d')``; raises ``_NeedsText`` on
    the first non-numeric value or an int beyond 64 bits) and ``text``
    (case-folded keys cut to ``SORT_TEXT_KEY_CHARS``, with an estimated byte
    budget of ``len * 2 + 56`` per distinct stored string).
    """

    def __init__(self, mode: str, *, max_text_bytes: int | None = None) -> None:
        self.mode = mode
        self.indices = array("q")
        self.ints = array("q")
        self.floats = array("d")
        self.is_float = array("b")
        self.texts: list[str] = []
        self.unparsed = array("q")
        self.missing = array("q")
        self.text_bytes = 0
        self.max_text_bytes = max_text_bytes if max_text_bytes is not None else sort_max_text_bytes()
        self._interned: dict[str, str] = {}

    def add_missing(self, index: int) -> None:
        self.missing.append(index)

    def add(self, value: object, index: int) -> None:
        if self.mode == "chronological":
            if isinstance(value, float) and not math.isfinite(value):
                self.missing.append(index)
                return
            epoch = as_epoch(value)
            if epoch is None:
                self.unparsed.append(index)
            else:
                self.indices.append(index)
                self.floats.append(epoch)
            return
        number = as_number(value)
        if number is NON_FINITE:
            self.missing.append(index)
            return
        if self.mode == "numeric":
            if number is NOT_NUMERIC:
                raise _NeedsText
            if isinstance(number, int):
                if not _INT64_MIN <= number <= _INT64_MAX:
                    raise _NeedsText
                self.ints.append(number)
                self.floats.append(0.0)
                self.is_float.append(0)
            else:
                self.ints.append(0)
                self.floats.append(number)  # type: ignore[arg-type]
                self.is_float.append(1)
            self.indices.append(index)
            return
        text = _text(value)[:SORT_TEXT_KEY_CHARS]
        shared = self._interned.get(text)
        if shared is None:
            self.text_bytes += len(text) * 2 + 56
            if len(self._interned) < SORT_TEXT_INTERN_LIMIT:
                self._interned[text] = text
        else:
            text = shared
        self.text_bytes += 8
        if self.text_bytes > self.max_text_bytes:
            raise SortUnsupported(TEXT_BUDGET_REASON.format(limit=_format_bytes(self.max_text_bytes)))
        self.texts.append(text)
        self.indices.append(index)

    def _sort_key(self):
        if self.mode == "text":
            return self.texts.__getitem__
        if self.mode == "chronological" or all(self.is_float):
            return self.floats.__getitem__
        if not any(self.is_float):
            return self.ints.__getitem__
        ints, floats, is_float = self.ints, self.floats, self.is_float
        return lambda i: floats[i] if is_float[i] else ints[i]

    def finish(self) -> tuple[array, array]:
        """Ascending and descending record-index orders.

        Unparseable timestamps, then missing values, follow in both orders.
        Positions are in record order and sorts are stable, so ties keep JSONL
        order in both directions (``reverse=True`` preserves stability).
        """
        self._interned = {}
        positions = range(len(self.indices))
        key = self._sort_key()
        indices = self.indices
        ascending = array("q", (indices[i] for i in sorted(positions, key=key)))
        descending = array("q", (indices[i] for i in sorted(positions, key=key, reverse=True)))
        for tail in (self.unparsed, self.missing):
            ascending.extend(tail)
            descending.extend(tail)
        return ascending, descending


def _first_mode(key: str) -> str:
    return "chronological" if key == "timestamp" else "numeric"


def order_indices(
    values: list[tuple[object, int]], missing: array, *, chronological: bool = False
) -> tuple[array, array]:
    """Ascending and descending orders of ``(value, record_index)`` pairs (missing last)."""
    mode = "chronological" if chronological else "numeric"
    while True:
        collector = SortKeyCollector(mode)
        try:
            for value, index in values:
                collector.add(value, index)
        except _NeedsText:
            mode = "text"
            continue
        for index in missing:
            collector.add_missing(index)
        return collector.finish()


@dataclass
class SortIndex:
    ascending: array
    descending: array
    offsets: array
    size: int = 0
    mtime_ns: int = 0
    # Records that were not valid JSON at build time (ascending; row-less).
    invalid: array = field(default_factory=lambda: array("q"))

    @property
    def total(self) -> int:
        return len(self.offsets)

    @property
    def nbytes(self) -> int:
        return sum(item.itemsize * len(item) for item in (self.ascending, self.descending, self.offsets, self.invalid))

    def order(self, order: str) -> array:
        return self.descending if order == "desc" else self.ascending

    def is_invalid(self, record_index: int) -> bool:
        position = bisect_left(self.invalid, record_index)
        return position < len(self.invalid) and self.invalid[position] == record_index


def probe_sort_key(
    records_path: Path,
    key: str,
    profiles: Mapping[str, Mapping[str, object]] | None,
    rows: int = SORT_PROBE_ROWS,
    *,
    record_limit: int | None = None,
) -> None:
    """Raise ``SortUnsupported`` if one of the first ``rows`` records holds a non-scalar value.

    Cheap (about 1 MB read) so an obviously unsortable key answers
    ``unsupported`` at once; a non-scalar value appearing only later is still
    caught by the full build. ``record_limit`` bounds it like ``build_sort_index``.
    """
    if record_limit is not None:
        rows = min(rows, record_limit)
    for index, _offset, row, _line in iter_jsonl_records(records_path):
        if index >= rows:
            return
        if row is not None:
            sort_value(expand_row(row, profiles), key)


@dataclass
class _Build:
    size: int
    bytes_read: int = 0
    running: bool = False

    @property
    def progress(self) -> float:
        if self.size <= 0:
            return 0.0
        return min(1.0, self.bytes_read / self.size)


def _scan(
    records_path: Path,
    key: str,
    profiles: Mapping[str, Mapping[str, object]] | None,
    mode: str,
    progress: _Build | None,
    *,
    record_limit: int | None = None,
) -> tuple[SortKeyCollector, array, array, os.stat_result]:
    """One pass in ``mode``; numbers records like ``jsonl_records.iter_jsonl_records``.

    ``record_limit`` stops before record ``record_limit`` (rows past it, e.g.
    a running analysis' unflushed tail, are not indexed).
    """
    collector = SortKeyCollector(mode)
    offsets = array("q")
    max_records = sort_max_records()
    invalid = array("q")
    index = 0
    position = 0
    if progress is not None:
        progress.bytes_read = 0
    with open(records_path, "rb") as handle:
        stat = os.fstat(handle.fileno())
        for line_number, line in enumerate(handle, start=1):
            start = position
            position += len(line)
            if progress is not None:
                progress.bytes_read = position
            stripped = line.strip()
            if not stripped.startswith(b"{"):
                continue
            if record_limit is not None and index >= record_limit:
                break
            if index >= max_records:
                raise too_many_records(index + 1, max_records)
            offsets.append(start)
            row = parse_record_line(stripped, path=records_path, line_number=line_number)
            value = None
            if row is None:
                invalid.append(index)
            else:
                value = sort_value(expand_row(row, profiles), key)
            if value is None:
                collector.add_missing(index)
            else:
                collector.add(value, index)
            index += 1
    return collector, offsets, invalid, stat


def build_sort_index(
    records_path: Path,
    key: str,
    profiles: Mapping[str, Mapping[str, object]] | None,
    progress: _Build | None = None,
    *,
    record_limit: int | None = None,
) -> SortIndex:
    """Scan ``records_path`` and return the sorted index for ``key``.

    Numeric keys that turn out to hold text are rescanned once in text mode
    (progress restarts from 0). The index records the ``fstat`` of the handle
    it read, so it is cached under the revision it actually describes.
    ``record_limit`` indexes only records ``0..record_limit-1``.
    """
    mode = _first_mode(key)
    # Passed only when set, so the unbounded call keeps its historical shape.
    bound = {} if record_limit is None else {"record_limit": record_limit}
    try:
        collector, offsets, invalid, stat = _scan(records_path, key, profiles, mode, progress, **bound)
    except _NeedsText:
        LOGGER.info("sort key %s of %s is not numeric; rescanning in text mode", key, records_path)
        collector, offsets, invalid, stat = _scan(records_path, key, profiles, "text", progress, **bound)
    if invalid:
        LOGGER.warning("%d invalid JSONL records in %s sort as missing", len(invalid), records_path)
    ascending, descending = collector.finish()
    return SortIndex(
        ascending=ascending,
        descending=descending,
        offsets=offsets,
        size=stat.st_size,
        mtime_ns=stat.st_mtime_ns,
        invalid=invalid,
    )


@dataclass
class SortState:
    status: str  # "ready" | "building" | "unsupported"
    progress: float
    index: SortIndex | None = None
    reason: str | None = None
    cache_key: tuple[str, str, str, int, int] | None = None


CacheKey = tuple[str, str, str, int, int]


class SortIndexCache:
    """Process-memory LRU of sort indices, unsupported reasons and running builds."""

    def __init__(
        self,
        *,
        max_entries: int = SORT_CACHE_MAX_ENTRIES,
        max_bytes: int = SORT_CACHE_MAX_BYTES,
        max_builds: int = SORT_MAX_CONCURRENT_BUILDS,
        max_pending: int = SORT_MAX_PENDING_BUILDS,
    ) -> None:
        self._max_entries = max_entries
        self._max_bytes = max_bytes
        self._max_pending = max_pending
        # Build threads start at once but scan only while holding a slot, so a
        # queued build reports "building" with progress 0 until a slot frees.
        self._slots = threading.BoundedSemaphore(max_builds)
        self._lock = threading.Lock()
        self._entries: OrderedDict[CacheKey, SortIndex] = OrderedDict()
        # reason, expiry (monotonic seconds) or None for "until the file changes".
        self._unsupported: OrderedDict[CacheKey, tuple[str, float | None]] = OrderedDict()
        self._builds: dict[CacheKey, _Build] = {}

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._unsupported.clear()

    def evict(self, cache_key: CacheKey) -> None:
        with self._lock:
            self._entries.pop(cache_key, None)

    def cached_keys(self) -> list[CacheKey]:
        with self._lock:
            return list(self._entries)

    def _bytes(self) -> int:
        return sum(entry.nbytes for entry in self._entries.values())

    @staticmethod
    def _drop_revisions(table: OrderedDict, cache_key: CacheKey) -> None:
        # A rewritten file (new size/mtime) supersedes older revisions; so does
        # another ``record_limit`` of the same kind (``<kind>#<n>``).
        family = _revision_family(cache_key)
        for stale in [k for k in table if _revision_family(k) == family and k != cache_key]:
            del table[stale]

    def _store_index(self, cache_key: CacheKey, index: SortIndex) -> None:
        self._drop_revisions(self._entries, cache_key)
        self._drop_revisions(self._unsupported, cache_key)
        self._unsupported.pop(cache_key, None)
        self._entries[cache_key] = index
        self._entries.move_to_end(cache_key)
        while len(self._entries) > 1 and (len(self._entries) > self._max_entries or self._bytes() > self._max_bytes):
            self._entries.popitem(last=False)

    def _store_unsupported(self, cache_key: CacheKey, reason: str, ttl: float | None) -> None:
        self._drop_revisions(self._unsupported, cache_key)
        self._unsupported[cache_key] = (reason, None if ttl is None else time.monotonic() + ttl)
        self._unsupported.move_to_end(cache_key)
        while len(self._unsupported) > SORT_UNSUPPORTED_MAX_ENTRIES:
            self._unsupported.popitem(last=False)

    def _cached_state(self, cache_key: CacheKey) -> SortState | None:
        entry = self._entries.get(cache_key)
        if entry is not None:
            self._entries.move_to_end(cache_key)
            return SortState("ready", 1.0, index=entry, cache_key=cache_key)
        negative = self._unsupported.get(cache_key)
        if negative is not None:
            reason, expires = negative
            if expires is None or time.monotonic() < expires:
                return SortState("unsupported", 0.0, reason=reason, cache_key=cache_key)
            del self._unsupported[cache_key]
        build = self._builds.get(cache_key)
        if build is not None:
            return SortState("building", build.progress, cache_key=cache_key)
        return None

    def lookup(
        self,
        *,
        run_id: str,
        kind: str,
        key: str,
        records_path: Path,
        profiles: Mapping[str, Mapping[str, object]] | None,
        record_limit: int | None = None,
    ) -> SortState:
        """Return the cached index, or start / report its background build.

        Repeated requests join the build in progress; it is never restarted.
        ``record_limit`` indexes only the first records (cache kind
        ``<kind>#<record_limit>``), e.g. the flushed rows of a running analysis.
        """
        stat = records_path.stat()
        if record_limit is not None:
            kind = f"{kind}#{record_limit}"
        cache_key: CacheKey = (run_id, kind, key, stat.st_size, stat.st_mtime_ns)
        with self._lock:
            state = self._cached_state(cache_key)
            if state is not None:
                return state
        try:
            probe_sort_key(records_path, key, profiles, record_limit=record_limit)
        except SortUnsupported as exc:
            with self._lock:
                self._store_unsupported(cache_key, str(exc), None)
            return SortState("unsupported", 0.0, reason=str(exc), cache_key=cache_key)
        with self._lock:
            state = self._cached_state(cache_key)
            if state is not None:
                return state
            pending = sum(1 for build in self._builds.values() if not build.running)
            if pending >= self._max_pending:
                return SortState("unsupported", 0.0, reason=QUEUE_FULL_REASON, cache_key=cache_key)
            build = _Build(size=stat.st_size)
            self._builds[cache_key] = build
            thread = threading.Thread(
                target=self._run_build,
                args=(cache_key, build, records_path, key, profiles, record_limit),
                name=f"rapidtriage-sort-{kind}",
                daemon=True,
            )
            try:
                thread.start()
            except RuntimeError as exc:
                self._builds.pop(cache_key, None)
                return SortState("unsupported", 0.0, reason=f"{FAILED_PREFIX}: {exc}", cache_key=cache_key)
            return SortState("building", 0.0, cache_key=cache_key)

    def _run_build(
        self,
        cache_key: CacheKey,
        build: _Build,
        records_path: Path,
        key: str,
        profiles: Mapping[str, Mapping[str, object]] | None,
        record_limit: int | None = None,
    ) -> None:
        index: SortIndex | None = None
        reason: str | None = None
        ttl: float | None = None
        try:
            with self._slots:
                build.running = True
                bound = {} if record_limit is None else {"record_limit": record_limit}
                index = build_sort_index(records_path, key, profiles, build, **bound)
        except SortUnsupported as exc:
            reason = str(exc)
        except Exception as exc:  # a failed build must not stay "building" forever
            LOGGER.warning("sort index build for %s failed: %s", cache_key, exc)
            reason = f"{FAILED_PREFIX}: {exc}"
            ttl = SORT_FAILURE_TTL_SECONDS
        with self._lock:
            self._builds.pop(cache_key, None)
            if index is not None:
                # Store under the revision the build actually read.
                self._store_index((*cache_key[:3], index.size, index.mtime_ns), index)
            elif reason is not None:
                self._store_unsupported(cache_key, reason, ttl)


def _revision_family(cache_key: CacheKey) -> tuple[object, ...]:
    """(run id, kind without ``#<record_limit>``, sort key): revisions of one sorted kind."""
    run_id, kind, key = cache_key[:3]
    return (run_id, str(kind).split("#", 1)[0], key)


SORT_INDEX_CACHE = SortIndexCache()


def read_rows_at(
    records_path: Path,
    index: SortIndex,
    record_indices: list[int],
    profiles: Mapping[str, Mapping[str, object]] | None,
) -> Iterator[tuple[int, dict[str, object]]]:
    """Yield ``(record_index, expanded row)`` by seeking to each record's line.

    Records that were invalid JSON at build time stay row-less. A line that
    no longer parses as an object means the file changed under the index
    (``StaleSortIndex``; the route answers 409).
    """
    with open(records_path, "rb") as handle:
        for record_index in record_indices:
            if index.is_invalid(record_index):
                continue
            handle.seek(index.offsets[record_index])
            line = handle.readline().strip()
            try:
                row = json.loads(line) if line.startswith(b"{") else None
            except ValueError:
                row = None
            if not isinstance(row, dict):
                raise StaleSortIndex(STALE_INDEX_MESSAGE)
            yield record_index, expand_row(row, profiles)


def iter_rows_in_order(
    records_path: Path,
    index: SortIndex,
    ordered: array,
    profiles: Mapping[str, Mapping[str, object]] | None,
    *,
    chunk: int = 512,
) -> Iterator[tuple[int, dict[str, object]]]:
    """The rows of ``ordered`` (record indices in sorted order) in that order (for ``path_contains`` filtering)."""
    for start in range(0, len(ordered), chunk):
        yield from read_rows_at(records_path, index, list(ordered[start:start + chunk]), profiles)


def sort_records_path(payload: Mapping[str, object], payload_path: Path) -> Path | None:
    """JSONL stream to sort, or ``None`` for inline payloads (unsupported)."""
    path = jsonl_records_path(payload, payload_path)
    return path if path is not None and path.is_file() else None


def sort_descriptor(
    key: str,
    order: str,
    state: SortState,
    locate: int | None = None,
    *,
    filtered: bool = False,
) -> dict[str, object]:
    """``{key, order, status, progress, reason?, position?}`` for one kind page.

    ``position`` (only when ``locate`` was requested) is the 0-based position
    of record ``locate`` in the whole-kind sorted order, or ``None`` while not
    ready, when out of range, or when ``path_contains`` filters the page.
    """
    descriptor: dict[str, object] = {
        "key": key,
        "order": order,
        "status": state.status,
        "progress": round(min(1.0, max(0.0, state.progress)), 4),
    }
    if state.reason:
        descriptor["reason"] = state.reason
    if locate is not None:
        position = None
        if not filtered and state.index is not None and 0 <= locate < state.index.total:
            # array.index is a C-level scan: about 1 ms per 200k records.
            position = state.index.order(order).index(locate)
        descriptor["position"] = position
    return descriptor


def paginate_sorted_artifact_output(
    payload: dict[str, object],
    *,
    run_id: str,
    kind: str,
    payload_path: Path,
    sort: str,
    order: str,
    offset: int,
    limit: int,
    cursor: str | None,
    path_contains: str | None,
    locate: int | None = None,
    cache: SortIndexCache | None = None,
    artifact_types: frozenset[str] | None = None,
    record_limit: int | None = None,
    allowed_records: Collection[int] | None = None,
) -> dict[str, object]:
    """One kind's artifacts page in whole-kind sorted order.

    ``allowed_records`` (ascending record indices, e.g. the 특이사항 filter)
    keeps only those records: the sorted order is narrowed before any row is
    read, and the unsorted fallbacks read only those records.

    The page carries ``sort`` = ``{key, order, status, progress, reason?,
    position?}``. ``building`` pages have no rows (the real ``total`` is kept)
    and the client polls; ``unsupported`` pages fall back to JSONL order.
    ``record_limit`` confines every read (index, filter, fallback) to records
    ``0..record_limit-1``.
    """
    cache = cache if cache is not None else SORT_INDEX_CACHE
    profiles = payload_profiles(payload)
    records_path = sort_records_path(payload, payload_path)
    key = sort.strip()
    filtered = bool(path_contains) or bool(artifact_types) or allowed_records is not None
    allowed = None if allowed_records is None else (allowed_records if isinstance(allowed_records, (set, frozenset)) else set(allowed_records))
    try:
        key = parse_sort_key(sort)
        if records_path is None:
            raise SortUnsupported("인라인 결과는 전체 정렬을 지원하지 않습니다")
        if limit <= 0:
            raise SortUnsupported("전체 정렬은 limit > 0 페이지 요청에서만 지원합니다")
        max_records = sort_max_records()
        if payload_record_count(payload) > max_records:
            raise too_many_records(payload_record_count(payload), max_records)
        state = cache.lookup(
            run_id=run_id, kind=kind, key=key, records_path=records_path, profiles=profiles, record_limit=record_limit
        )
    except SortUnsupported as exc:
        state = SortState("unsupported", 0.0, reason=str(exc))

    if state.status != "ready" or state.index is None or records_path is None:
        if state.status == "building":
            if cursor:
                offset = decode_pagination_cursor(cursor)
            page = dict(payload)
            page["artifacts"] = []
            page["pagination"] = {
                "collection": "artifacts",
                "offset": offset,
                "limit": limit,
                "returned": 0,
                "total": payload_record_count(payload),
                "next_offset": None,
                "previous_offset": max(0, offset - limit) if offset > 0 else None,
                "has_more": False,
            }
        elif filtered and limit > 0:
            page = filter_artifact_page(
                payload,
                payload_path=payload_path,
                path_contains=path_contains,
                offset=offset,
                limit=limit,
                artifact_types=artifact_types,
                record_limit=record_limit,
                rows_source=(
                    None
                    if allowed is None
                    else iter_records_at(payload, payload_path, sorted(allowed), record_limit=record_limit)
                ),
            )
        else:
            page = paginate_artifact_output(
                payload, payload_path=payload_path, offset=offset, limit=limit, cursor=cursor
            )
        page["sort"] = sort_descriptor(key, order, state, locate, filtered=filtered)
        return page

    index = state.index

    def guarded(rows: Iterator[tuple[int, dict[str, object]]]) -> Iterator[tuple[int, dict[str, object]]]:
        try:
            yield from rows
        except StaleSortIndex:
            if state.cache_key is not None:
                cache.evict(state.cache_key)
            raise

    ordered_all = index.order(order)
    ordered = ordered_all if allowed is None else array("q", (item for item in ordered_all if item in allowed))
    if filtered and (path_contains or artifact_types):
        page = filter_artifact_page(
            payload,
            payload_path=payload_path,
            path_contains=path_contains,
            offset=offset,
            limit=limit,
            scan_cap=SORTED_FILTER_SCAN_CAP,
            rows_source=guarded(iter_rows_in_order(records_path, index, ordered, profiles)),
            artifact_types=artifact_types,
        )
    else:

        def window(start: int, count: int) -> list[object]:
            wanted = list(ordered[start:start + count])
            rows = guarded(read_rows_at(records_path, index, wanted, profiles))
            return [{**row, "record_index": record_index} for record_index, row in rows]

        page = paginate_payload(
            payload,
            "artifacts",
            offset=offset,
            limit=limit,
            cursor=cursor,
            row_window=window,
            window_total=len(ordered),
        )
        if allowed is not None and isinstance(page.get("pagination"), dict):
            page["pagination"]["filtered"] = True
            page["pagination"]["total"] = len(ordered)
    page["sort"] = sort_descriptor(key, order, state, locate, filtered=filtered)
    return page
