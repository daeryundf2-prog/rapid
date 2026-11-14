"""Path index of a per-kind artifact output for ``GET /artifacts?path_contains=`` (R7 search latency).

``path_contains`` used to stream every JSONL row of the kind and fold its path (about 29 µs per
row: 8-10 s for the 294k event-log rows of a real run, on every keystroke pause of the grid
filter). Rows of a kind share few distinct paths (one per evtx / database / profile file), so the
index keeps:

* ``paths`` -- the distinct paths, NFC + case-folded exactly like
  :func:`artifact_filter.row_matcher` (``row.path`` else ``row.source_path``);
* ``path_ids`` (``array('l')``) -- each record's path id (``-1``: no path / invalid record);
* ``offsets`` (``array('q')``) -- the byte offset of each record's line (JSONL outputs), so the
  rows of a page are read by seeking, never by rescanning.

A ``path_contains`` request then tests the distinct paths (substring, same semantics as the
scan), collects the matching record indices and reads only the rows it pages (and the other
filters, if any, check only those rows). One index per kind revision
(``row_conditions.output_stamp`` of the payload and its JSONL), one build at a time, kept in memory
(LRU over all kinds bounded by bytes, ``RAPIDTRIAGE_PATH_INDEX_MB`` -- default 256 -- and by
:data:`PATH_INDEX_MAX_KINDS` kinds; no file is written; R7 S2 review #12). The first single-kind request
builds it synchronously (one pass over the kind, the cost of the old scan); cross-kind requests
use only ready indexes and start the missing ones in the background (one build at a time), so a
category filter never waits for a whole-run build. Any failure falls back to the scan.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
from array import array
from bisect import bisect_left
from collections import OrderedDict
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from .artifact_filter import nfc_fold
from .jsonl_records import (
    expand_row,
    iter_jsonl_records,
    jsonl_records_path,
    payload_profiles,
)
from .row_conditions import output_stamp

LOGGER = logging.getLogger(__name__)

# Kinds whose index is kept (all runs). An event-log kind of 300k rows costs ~4 MB.
PATH_INDEX_MAX_KINDS = 24
# Bytes all kept indexes may hold together (paths, per-record arrays, matched-record caches).
PATH_INDEX_BUDGET_ENV = "RAPIDTRIAGE_PATH_INDEX_MB"
PATH_INDEX_DEFAULT_MB = 256
# Kinds with more records are not indexed (the scan with its cap and budget answers).
PATH_INDEX_MAX_RECORDS = 20_000_000
# Distinct paths per kind; beyond this the index is useless (every row its own path).
PATH_INDEX_MAX_PATHS = 2_000_000
# Matched record lists remembered per index (needle -> indices).
PATH_INDEX_NEEDLE_CACHE = 32
NO_PATH = -1


def path_index_budget_bytes() -> int:
    """``RAPIDTRIAGE_PATH_INDEX_MB`` (default 256) in bytes; ``0`` keeps no index (every request scans)."""
    raw = os.environ.get(PATH_INDEX_BUDGET_ENV, "").strip()
    try:
        megabytes = float(raw) if raw else PATH_INDEX_DEFAULT_MB
    except ValueError:
        megabytes = PATH_INDEX_DEFAULT_MB
    return max(0, int(megabytes * 1024 * 1024))


@dataclass
class PathIndex:
    paths: list[str]
    path_ids: array
    offsets: array | None
    records_path: Path | None
    needle_cache: OrderedDict[str, array] = field(default_factory=OrderedDict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def total(self) -> int:
        return len(self.path_ids)

    def nbytes(self) -> int:
        """Approximate memory held: the distinct paths, the per-record arrays and the needle cache."""
        size = sum(sys.getsizeof(path) for path in self.paths) + sys.getsizeof(self.paths)
        size += self.path_ids.itemsize * len(self.path_ids)
        if self.offsets is not None:
            size += self.offsets.itemsize * len(self.offsets)
        with self.lock:
            size += sum(len(needle) + found.itemsize * len(found) + 64 for needle, found in self.needle_cache.items())
        return size

    def matching(self, needle: str) -> array:
        """Record indices (ascending) whose folded path contains ``needle`` (pre-folded)."""
        with self.lock:
            cached = self.needle_cache.get(needle)
            if cached is not None:
                self.needle_cache.move_to_end(needle)
                return cached
        wanted = {position for position, path in enumerate(self.paths) if needle in path}
        found = array("q")
        if wanted:
            if len(wanted) == 1:
                only = next(iter(wanted))
                found.extend(index for index, path_id in enumerate(self.path_ids) if path_id == only)
            else:
                found.extend(index for index, path_id in enumerate(self.path_ids) if path_id in wanted)
        with self.lock:
            self.needle_cache[needle] = found
            while len(self.needle_cache) > PATH_INDEX_NEEDLE_CACHE:
                self.needle_cache.popitem(last=False)
        return found

    def iter_rows(
        self,
        payload: Mapping[str, object],
        indices: Sequence[int],
        *,
        start: int = 0,
        record_limit: int | None = None,
    ) -> Iterator[tuple[int, dict[str, object]]]:
        """``(record_index, expanded row)`` of ``indices`` (ascending) from record ``start`` on."""
        profiles = payload_profiles(payload)
        first = bisect_left(indices, start) if start else 0
        if self.records_path is None or self.offsets is None:
            inline = payload.get("artifacts")
            inline = inline if isinstance(inline, list) else []
            for position in range(first, len(indices)):
                index = int(indices[position])
                if record_limit is not None and index >= record_limit:
                    return
                if index < len(inline) and isinstance(inline[index], dict):
                    yield index, expand_row(inline[index], profiles)
            return
        with open(self.records_path, "rb") as handle:
            for position in range(first, len(indices)):
                index = int(indices[position])
                if record_limit is not None and index >= record_limit:
                    return
                handle.seek(self.offsets[index])
                line = handle.readline().strip()
                try:
                    row = json.loads(line) if line.startswith(b"{") else None
                except ValueError:
                    row = None
                if isinstance(row, dict):
                    yield index, expand_row(row, profiles)


def row_path_fold(row: Mapping[str, object]) -> str:
    """The folded path ``row_matcher`` tests (``path`` else ``source_path``)."""
    return nfc_fold(row.get("path") or row.get("source_path"))


def build_path_index(payload: Mapping[str, object], payload_path: Path | None) -> PathIndex | None:
    """One pass over the kind; ``None`` when it is too large to index (caller scans)."""
    profiles = payload_profiles(payload)
    ids: dict[str, int] = {}
    paths: list[str] = []
    path_ids = array("l")
    records_path = jsonl_records_path(payload, payload_path)

    def path_id(row: Mapping[str, object] | None) -> int:
        if row is None:
            return NO_PATH
        folded = row_path_fold(row)
        if not folded and profiles:
            folded = row_path_fold(expand_row(dict(row), profiles))
        found = ids.get(folded)
        if found is None:
            found = ids[folded] = len(paths)
            paths.append(folded)
        return found

    if records_path is None:
        inline = payload.get("artifacts")
        for row in inline if isinstance(inline, list) else []:
            path_ids.append(path_id(row if isinstance(row, dict) else None))
        return PathIndex(paths=paths, path_ids=path_ids, offsets=None, records_path=None)
    if not records_path.is_file():
        return None
    offsets = array("q")
    for record_index, offset, row, _line in iter_jsonl_records(records_path):
        if record_index >= PATH_INDEX_MAX_RECORDS or len(paths) > PATH_INDEX_MAX_PATHS:
            return None
        offsets.append(offset)
        path_ids.append(path_id(row))
    return PathIndex(paths=paths, path_ids=path_ids, offsets=offsets, records_path=records_path)


class PathIndexService:
    """Path indexes per kind revision: LRU of ``max_kinds``, one build per key at a time.

    ``get`` builds a missing index now (single-kind requests); ``ready`` never
    waits: it returns a built index or starts a background build (one at a
    time) and returns ``None`` (cross-kind requests scan that kind meanwhile).
    A kind that cannot be indexed is remembered as ``False`` (no rebuild per request).
    """

    def __init__(self, max_kinds: int = PATH_INDEX_MAX_KINDS, max_bytes: int | None = None) -> None:
        self.max_kinds = max_kinds
        self._max_bytes = max_bytes
        self._lock = threading.Lock()
        self._items: OrderedDict[tuple[object, ...], PathIndex | bool] = OrderedDict()
        self._build_locks: dict[tuple[object, ...], threading.Lock] = {}
        self._queued: set[tuple[object, ...]] = set()
        self._worker_gate = threading.Semaphore(1)
        self.builds = 0

    @property
    def max_bytes(self) -> int:
        return path_index_budget_bytes() if self._max_bytes is None else self._max_bytes

    def clear(self) -> None:
        with self._lock:
            self._items.clear()

    def held_bytes(self) -> int:
        with self._lock:
            items = list(self._items.values())
        return sum(item.nbytes() for item in items if isinstance(item, PathIndex))

    def _evict(self) -> None:
        """Drop least-recently used indexes until the byte budget and the kind count hold (lock held)."""
        budget = self.max_bytes
        sizes = {key: (item.nbytes() if isinstance(item, PathIndex) else 0) for key, item in self._items.items()}
        total = sum(sizes.values())
        while self._items and (total > budget or len(self._items) > self.max_kinds):
            key, _item = self._items.popitem(last=False)
            total -= sizes.pop(key, 0)

    @staticmethod
    def key(run_id: str, kind: str, payload: Mapping[str, object], payload_path: Path | None) -> tuple[object, ...]:
        records_path = jsonl_records_path(payload, payload_path)
        return (run_id, kind, output_stamp(payload_path, records_path))

    def _peek(self, key: tuple[object, ...]) -> PathIndex | bool | None:
        with self._lock:
            found = self._items.get(key)
            if found is not None:
                self._items.move_to_end(key)
            return found

    def _store(self, key: tuple[object, ...], value: PathIndex | bool) -> None:
        with self._lock:
            # A new revision of the kind replaces the old one.
            for stale in [item for item in self._items if item[:2] == key[:2] and item != key]:
                self._items.pop(stale, None)
            if isinstance(value, PathIndex) and value.nbytes() > self.max_bytes:
                return  # larger than the whole budget: used for this request only, never kept
            self._items[key] = value
            self._items.move_to_end(key)
            self._evict()

    def _build(self, payload: Mapping[str, object], payload_path: Path | None) -> PathIndex | bool:
        try:
            index = build_path_index(payload, payload_path)
        except (OSError, ValueError) as exc:
            LOGGER.warning("artifact path index build failed for %s: %s", payload_path, exc)
            index = None
        self.builds += 1
        return index if index is not None else False

    def get(self, run_id: str, kind: str, payload: Mapping[str, object], payload_path: Path | None) -> PathIndex | None:
        """The kind's index, built now when missing."""
        key = self.key(run_id, kind, payload, payload_path)
        found = self._peek(key)
        if found is not None:
            # Its needle cache may have grown since it was stored: re-check the byte budget.
            with self._lock:
                self._evict()
            return found or None
        with self._lock:
            build_lock = self._build_locks.setdefault(key, threading.Lock())
        try:
            with build_lock:
                found = self._peek(key)
                if found is None:
                    found = self._build(payload, payload_path)
                    self._store(key, found)
                return found or None
        finally:
            with self._lock:
                if self._build_locks.get(key) is build_lock:
                    self._build_locks.pop(key, None)

    def ready(self, run_id: str, kind: str, payload: Mapping[str, object], payload_path: Path | None) -> PathIndex | None:
        """The kind's index when already built; else start a background build and return ``None``."""
        key = self.key(run_id, kind, payload, payload_path)
        found = self._peek(key)
        if found is not None:
            return found or None
        with self._lock:
            if key in self._queued:
                return None
            self._queued.add(key)

        def work() -> None:
            try:
                with self._worker_gate:
                    self.get(run_id, kind, payload, payload_path)
            except Exception:  # a background build never takes the server down
                LOGGER.exception("artifact path index background build failed")
            finally:
                with self._lock:
                    self._queued.discard(key)

        threading.Thread(target=work, name=f"artifact-path-index-{kind}", daemon=True).start()
        return None

    def pending(self) -> int:
        with self._lock:
            return len(self._queued)


PATH_INDEX_SERVICE = PathIndexService()
