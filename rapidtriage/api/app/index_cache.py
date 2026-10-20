"""Per-run LRU of explorer indexes, built single-flight per key (fs-tree, registry, media)."""

from __future__ import annotations

import hashlib
import os
import threading
from collections import OrderedDict
from collections.abc import Callable
from pathlib import Path
from typing import Generic, TypeVar

IndexT = TypeVar("IndexT")

# ``0`` / ``false`` / ``no`` / ``off``: the API keeps every index it builds on demand (timeline
# column index, located-row index) in memory only and never writes an index file next to the run
# outputs (benchmarks over a real run folder, read-only review copies). Saved files are still read.
INDEX_PERSIST_ENV = "RAPIDTRIAGE_INDEX_PERSIST"


def index_persist_enabled() -> bool:
    """Whether on-demand index builds may write their file next to the run outputs (default yes)."""
    return os.environ.get(INDEX_PERSIST_ENV, "").strip().lower() not in {"0", "false", "no", "off"}


# Bytes hashed at each end of a file by :func:`head_tail_digest`.
DIGEST_EDGE_BYTES = 64 * 1024


def head_tail_digest(path: Path | str) -> str | None:
    """A cheap content check of a file: SHA-256 of its size and first / last
    :data:`DIGEST_EDGE_BYTES` (``None`` when it cannot be read). Saved index files carry it next
    to ``(size, mtime_ns)`` so a rewrite that keeps both (a copied folder, a coarse mtime) is still
    noticed when it changes either end of the file."""
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(0)
            head = handle.read(DIGEST_EDGE_BYTES)
            tail = b""
            if size > DIGEST_EDGE_BYTES:
                handle.seek(max(DIGEST_EDGE_BYTES, size - DIGEST_EDGE_BYTES))
                tail = handle.read(DIGEST_EDGE_BYTES)
    except OSError:
        return None
    digest = hashlib.sha256(str(size).encode("ascii"))
    digest.update(head)
    digest.update(tail)
    return digest.hexdigest()[:32]


class SingleFlightIndexCache(Generic[IndexT]):
    """LRU of ``max_runs`` indexes keyed by ``(run_id, ...signature)``.

    One build per key at a time (concurrent requests for the same key wait
    for it; other keys build in parallel). A new signature of a run replaces
    that run's older index -- unless that index comes from a build that
    started later (a slow build of an older revision finishing last must not
    evict the newer revision's index: it is returned to its caller but not
    kept). The per-key build lock is dropped whether the build succeeded or
    raised, so failing builds never accumulate locks.
    """

    def __init__(self, max_runs: int) -> None:
        self.max_runs = max_runs
        self._lock = threading.Lock()
        self._build_locks: dict[tuple[object, ...], threading.Lock] = {}
        self._items: OrderedDict[tuple[object, ...], IndexT] = OrderedDict()
        # Start order of the build that produced each kept index (see the class doc).
        self._generations: dict[tuple[object, ...], int] = {}
        self._next_generation = 0

    def clear(self) -> None:
        with self._lock:
            self._items.clear()
            self._generations.clear()

    def pending_builds(self) -> int:
        """Build locks currently held or awaited (``0`` when idle)."""
        with self._lock:
            return len(self._build_locks)

    def get_or_build(self, key: tuple[object, ...], build: Callable[[], IndexT]) -> IndexT:
        with self._lock:
            found = self._items.get(key)
            if found is not None:
                self._items.move_to_end(key)
                return found
            build_lock = self._build_locks.setdefault(key, threading.Lock())
        try:
            with build_lock:
                with self._lock:
                    found = self._items.get(key)
                    if found is not None:
                        return found
                    self._next_generation += 1
                    generation = self._next_generation
                index = build()
                with self._lock:
                    same_run = [item for item in self._items if item[0] == key[0] and item != key]
                    if any(self._generations.get(item, 0) > generation for item in same_run):
                        return index  # a newer revision of the run is already kept
                    for stale in same_run:
                        self._items.pop(stale, None)
                        self._generations.pop(stale, None)
                    self._items[key] = index
                    self._generations[key] = generation
                    while len(self._items) > self.max_runs:
                        evicted, _ = self._items.popitem(last=False)
                        self._generations.pop(evicted, None)
                return index
        finally:
            with self._lock:
                if self._build_locks.get(key) is build_lock:
                    self._build_locks.pop(key, None)
