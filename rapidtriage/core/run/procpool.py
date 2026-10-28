"""Process pool for CPU-bound artifact parsers (EVTX, registry, ESE/SRUM).

The artifact stage keeps its bounded thread scheduler. For the CPU-bound kinds in
``PROCESS_KINDS`` the scheduler thread only submits the collection to a
spawn-context ``ProcessPoolExecutor`` and waits, so the parse itself runs outside
the parent's GIL. Only picklable inputs (``InputRoot``, rule set, paths, options)
go in and only the picklable payload comes back; scheduling, ordering and result
handling stay in the parent, so outputs are identical to the thread path.

Limits of the process path: the run plan's cooperative cancel check and live row
counter cannot cross the process boundary, so a cancel of a running process-pool
kind takes effect when the kind finishes. If the pool cannot start (or breaks, or
the inputs cannot be pickled) the collection runs on the calling thread instead.
"""

from __future__ import annotations

import datetime as dt
import multiprocessing
import os
import pickle
import threading
import time
from collections.abc import Callable, Mapping
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..input_root import InputRoot
    from ..rules import RuleSet
    from .progress import RunProgress

__all__ = [
    "PARSE_PROCS_ENV",
    "PROCESS_KINDS",
    "ProcessParsePool",
    "parse_process_count",
    "pooled_artifact_collection",
]

PARSE_PROCS_ENV = "RAPIDTRIAGE_PARSE_PROCS"
# EVTX (eventlog), registry hives (+ shellbags), ESE databases: SRUM (execution) and Windows.edb.
PROCESS_KINDS = frozenset(
    {"eventlog", "windows-registry", "windows-shellbags", "windows-execution", "windows-search-index"}
)

CollectionResult = tuple[dict[str, object], str, str, int]


def parse_process_count() -> int:
    """Worker processes: ``RAPIDTRIAGE_PARSE_PROCS`` or ``max(2, cpu_count // 2)``; ``<= 0`` disables."""
    default = max(2, (os.cpu_count() or 4) // 2)
    raw = os.environ.get(PARSE_PROCS_ENV, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _process_collection(
    input_root: InputRoot,
    kind: str,
    rule_set: RuleSet | None,
    records_path: Path | None,
    collector_options: Mapping[str, object] | None,
) -> CollectionResult:
    """Worker entry point (module level so it is importable under spawn)."""
    from ..artifacts import run_artifact_collection

    start = time.perf_counter()
    started_at = dt.datetime.now(dt.timezone.utc).isoformat()
    payload = run_artifact_collection(
        input_root,
        kind=kind,
        rule_set=rule_set,
        records_path=records_path,
        collector_options=dict(collector_options) if collector_options else None,
        use_cache=False,
    )
    completed_at = dt.datetime.now(dt.timezone.utc).isoformat()
    return payload, started_at, completed_at, max(0, int((time.perf_counter() - start) * 1000))


class ProcessParsePool:
    """Lazily started spawn-context pool; ``run`` returns ``None`` when it cannot be used."""

    def __init__(self, workers: int | None = None) -> None:
        self.workers = parse_process_count() if workers is None else workers
        self._executor: ProcessPoolExecutor | None = None
        self._lock = threading.Lock()
        self.disabled = self.workers <= 0
        self.fallback_reason: str | None = "disabled by configuration" if self.disabled else None

    def _disable(self, reason: str) -> None:
        with self._lock:
            self.disabled = True
            self.fallback_reason = self.fallback_reason or reason

    def _get_executor(self) -> ProcessPoolExecutor | None:
        with self._lock:
            if self.disabled:
                return None
            if self._executor is None:
                self._executor = ProcessPoolExecutor(
                    max_workers=self.workers, mp_context=multiprocessing.get_context("spawn")
                )
            return self._executor

    def run(
        self,
        input_root: InputRoot,
        kind: str,
        rule_set: RuleSet | None,
        records_path: Path | None,
        collector_options: Mapping[str, object] | None,
    ) -> CollectionResult | None:
        """Collect in a worker process, or ``None`` (pool unusable) so the caller runs it in-thread.

        Errors raised by the collector itself propagate like the thread path.
        """
        args = (input_root, kind, rule_set, records_path, dict(collector_options) if collector_options else None)
        try:
            pickle.dumps(args)
        except Exception as exc:  # unpicklable input: this call stays on a thread
            self.fallback_reason = self.fallback_reason or f"unpicklable input: {type(exc).__name__}"
            return None
        try:
            executor = self._get_executor()
            if executor is None:
                return None
            future = executor.submit(_process_collection, *args)
        except Exception as exc:  # pool cannot start / accept work
            self._disable(f"{type(exc).__name__}: {exc}")
            return None
        try:
            return future.result()
        except BrokenProcessPool as exc:
            self._disable(f"BrokenProcessPool: {exc}")
            return None

    def shutdown(self, *, wait: bool = True) -> None:
        with self._lock:
            executor, self._executor = self._executor, None
        if executor is not None:
            executor.shutdown(wait=wait, cancel_futures=True)


def pooled_artifact_collection(
    pool: ProcessParsePool,
    progress: RunProgress | None,
    input_root: InputRoot,
    *,
    kind: str,
    rule_set: RuleSet | None,
    records_path: Path | None,
    collector_options: Mapping[str, object] | None,
    fallback: Callable[..., CollectionResult | None],
) -> CollectionResult | None:
    """Drop-in for ``tracked_artifact_collection`` that prefers the process pool for ``kind``.

    ``fallback`` is the thread implementation, called with the same arguments when
    the pool is unusable (including its cancel/row-count hooks).
    """
    if progress is not None and not progress.task_should_run(kind):
        return None
    if progress is not None:
        progress.provider_running(kind)
    result = pool.run(input_root, kind, rule_set, records_path, collector_options)
    if result is not None:
        return result
    return fallback(
        progress,
        input_root,
        kind=kind,
        rule_set=rule_set,
        records_path=records_path,
        collector_options=collector_options,
    )
