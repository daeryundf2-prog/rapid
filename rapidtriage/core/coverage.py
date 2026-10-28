"""Per-run coverage disclosure: every limit that truncated parsing.

Parsers call :func:`record_coverage` when a cap is hit. Each run installs its own
collector (:func:`start_coverage_run`), so two runs in one process (the web job
store runs several at once) never wipe or mix each other's entries; the run
summary writes :func:`coverage_entries` as ``coverage`` in
``rapidtriage-run-summary.json``.

The active collector lives in a :class:`contextvars.ContextVar`. Threads do not
inherit it, so a run hands it to its worker threads explicitly
(:func:`coverage_scope`). Threads the run cannot reach directly (the artifact
provider pump thread started inside ``core/artifacts.py``) are matched by thread
name: :func:`bind_coverage_thread`. Without a run (unit tests, single CLI
commands) a process-wide collector is used, exactly as before.

Entry shape: ``{"area", "reason_code", "limit", "observed", "unit"}`` where
``limit`` and ``observed`` are integers or ``None``. An entry may also carry an
optional ``detail`` mapping of extra integers (for example ``{"start_sector": n}``)
that identifies what was skipped without being rendered as an observed count.
"""

from __future__ import annotations

import contextvars
import copy
import threading
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager

ENTRY_KEYS = ("area", "reason_code", "limit", "observed", "unit")


class CoverageCollector:
    """Thread-safe list of coverage entries; a child forwards every entry to its parent."""

    def __init__(self, parent: CoverageCollector | None = None) -> None:
        self._lock = threading.Lock()
        self._entries: list[dict[str, object]] = []
        self._parent = parent
        self._threads: dict[str, CoverageCollector] = {}

    def record(self, entry: Mapping[str, object]) -> None:
        with self._lock:
            self._entries.append(copy.deepcopy(dict(entry)))
        if self._parent is not None:
            self._parent.record(entry)

    def entries(self) -> list[dict[str, object]]:
        with self._lock:
            return copy.deepcopy(self._entries)

    def reset(self) -> None:
        with self._lock:
            self._entries.clear()

    def bound_thread(self, name: str) -> CoverageCollector | None:
        with self._lock:
            return self._threads.get(name)

    def bind_thread(self, name: str, collector: CoverageCollector | None) -> None:
        with self._lock:
            if collector is None:
                self._threads.pop(name, None)
            else:
                self._threads[name] = collector


_PROCESS = CoverageCollector()
_CURRENT: contextvars.ContextVar[CoverageCollector | None] = contextvars.ContextVar(
    "rapidtriage_coverage_collector", default=None
)
_RUNS_LOCK = threading.Lock()
_RUNS: list[CoverageCollector] = []


def current_coverage_collector() -> CoverageCollector:
    """The collector ``record_coverage`` writes to in this thread/context.

    Order: the context's collector; else a collector bound to this thread's name by
    exactly one active run; else the only active run; else the process collector."""
    collector = _CURRENT.get()
    if collector is not None:
        return collector
    with _RUNS_LOCK:
        runs = list(_RUNS)
    if runs:
        name = threading.current_thread().name
        bound = [child for child in (run.bound_thread(name) for run in runs) if child is not None]
        if len(bound) == 1:
            return bound[0]
        if len(runs) == 1:
            return runs[0]
    return _PROCESS


def start_coverage_run() -> tuple[CoverageCollector, contextvars.Token[CoverageCollector | None]]:
    """Install a fresh collector for the run executing in this context; pair with :func:`finish_coverage_run`."""
    collector = CoverageCollector()
    token = _CURRENT.set(collector)
    with _RUNS_LOCK:
        _RUNS.append(collector)
    return collector, token


def finish_coverage_run(collector: CoverageCollector, token: contextvars.Token[CoverageCollector | None]) -> None:
    with _RUNS_LOCK:
        if collector in _RUNS:
            _RUNS.remove(collector)
    _CURRENT.reset(token)


@contextmanager
def coverage_scope(collector: CoverageCollector) -> Iterator[CoverageCollector]:
    """Make ``collector`` current in this thread (for worker threads a run starts)."""
    token = _CURRENT.set(collector)
    try:
        yield collector
    finally:
        _CURRENT.reset(token)


@contextmanager
def capture_coverage(parent: CoverageCollector | None = None) -> Iterator[CoverageCollector]:
    """Collect the entries recorded inside the block (they still reach ``parent``/the current collector)."""
    child = CoverageCollector(parent if parent is not None else current_coverage_collector())
    with coverage_scope(child):
        yield child


@contextmanager
def bind_coverage_thread(run: CoverageCollector, thread_name: str, collector: CoverageCollector) -> Iterator[None]:
    """Route ``record_coverage`` from a context-less thread named ``thread_name`` to ``collector``."""
    run.bind_thread(thread_name, collector)
    try:
        yield
    finally:
        run.bind_thread(thread_name, None)


def reset_coverage() -> None:
    current_coverage_collector().reset()


def record_coverage(
    area: str,
    reason_code: str,
    limit: int | None,
    observed: int | None,
    unit: str,
    detail: dict[str, int] | None = None,
) -> None:
    entry: dict[str, object] = {
        "area": area,
        "reason_code": reason_code,
        "limit": limit,
        "observed": observed,
        "unit": unit,
    }
    if detail is not None:
        entry["detail"] = dict(detail)
    current_coverage_collector().record(entry)


def replay_coverage(entries: Iterable[object]) -> int:
    """Re-record stored entries (a resumed checkpoint or a reused payload); malformed rows are skipped."""
    count = 0
    for entry in entries:
        if not isinstance(entry, Mapping) or not all(key in entry for key in ENTRY_KEYS):
            continue
        current_coverage_collector().record(entry)
        count += 1
    return count


def coverage_entries() -> list[dict[str, object]]:
    return current_coverage_collector().entries()
