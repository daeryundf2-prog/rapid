"""Per-run LRU of explorer indexes, built single-flight per key (fs-tree, registry, media)."""

from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Callable
from typing import Generic, TypeVar

IndexT = TypeVar("IndexT")


class SingleFlightIndexCache(Generic[IndexT]):
    """LRU of ``max_runs`` indexes keyed by ``(run_id, ...signature)``.

    One build per key at a time (concurrent requests for the same key wait
    for it; other keys build in parallel). A new signature of a run replaces
    that run's older index. The per-key build lock is dropped whether the
    build succeeded or raised, so failing builds never accumulate locks.
    """

    def __init__(self, max_runs: int) -> None:
        self.max_runs = max_runs
        self._lock = threading.Lock()
        self._build_locks: dict[tuple[object, ...], threading.Lock] = {}
        self._items: OrderedDict[tuple[object, ...], IndexT] = OrderedDict()

    def clear(self) -> None:
        with self._lock:
            self._items.clear()

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
                index = build()
                with self._lock:
                    for stale in [item for item in self._items if item[0] == key[0]]:
                        self._items.pop(stale, None)
                    self._items[key] = index
                    while len(self._items) > self.max_runs:
                        self._items.popitem(last=False)
                return index
        finally:
            with self._lock:
                if self._build_locks.get(key) is build_lock:
                    self._build_locks.pop(key, None)
