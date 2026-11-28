"""``wait: true`` on run creation: a bounded wait that never holds a request thread.

Runs always go through the store's worker pool (``RAPIDTRIAGE_RUN_WORKERS``).
A ``wait: true`` request awaits the queued run on the event loop for at most
``RAPIDTRIAGE_RUN_WAIT_SECONDS``; past that it answers with the run still
``queued``/``running`` (``wait_timed_out: true``) and the client polls
``GET /api/runs/{run_id}``. Many concurrent ``wait: true`` requests therefore
cannot exhaust the server's thread pool and stall ``/api/health`` or ``/``
(remote-use review R3).

A stop signal (SIGTERM / Ctrl-C) releases every waiting request at once, so the
server does not wait out ``RAPIDTRIAGE_RUN_WAIT_SECONDS`` before it exits (PR #89
review P2): the lifespan chains ``RunWaits.release_all`` in front of the server's
own signal handler (``chain_stop_signals``).
"""

from __future__ import annotations

import asyncio
import os
import signal
import threading
from collections.abc import Callable
from concurrent.futures import Future
from types import FrameType

from ...core.jobs import RunJobStore

RUN_WAIT_SECONDS_ENV = "RAPIDTRIAGE_RUN_WAIT_SECONDS"
DEFAULT_RUN_WAIT_SECONDS = 60.0
STOP_SIGNALS = (signal.SIGINT, signal.SIGTERM)


def run_wait_seconds() -> float:
    """``RAPIDTRIAGE_RUN_WAIT_SECONDS`` (0 or more; unset or not a number -> ``DEFAULT_RUN_WAIT_SECONDS``)."""
    raw = os.environ.get(RUN_WAIT_SECONDS_ENV, "").strip()
    try:
        return max(0.0, float(raw)) if raw else DEFAULT_RUN_WAIT_SECONDS
    except ValueError:
        return DEFAULT_RUN_WAIT_SECONDS


class RunWaits:
    """The app's waiting ``wait: true`` requests; ``release_all()`` (server stopping) ends every wait now."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._waiting: set[tuple[asyncio.AbstractEventLoop, asyncio.Event]] = set()
        self._released = False

    @property
    def released(self) -> bool:
        return self._released

    async def wait(self, store: RunJobStore, run_id: str) -> None:
        """Until the queued run ends, ``run_wait_seconds()`` pass, or the server stops.

        The caller reads the run's status afterwards. A disconnecting client cancels
        only this wait, never the run.
        """
        future = store.completion_future(run_id)
        if future is None:
            return
        loop = asyncio.get_running_loop()
        ended = asyncio.Event()
        entry = (loop, ended)
        with self._lock:
            if self._released:
                return
            self._waiting.add(entry)

        def wake(_future: Future[dict[str, object]]) -> None:
            try:
                loop.call_soon_threadsafe(ended.set)
            except RuntimeError:  # the request's event loop is already closed
                pass

        future.add_done_callback(wake)
        try:
            await asyncio.wait_for(ended.wait(), timeout=run_wait_seconds())
        except asyncio.TimeoutError:
            pass
        finally:
            with self._lock:
                self._waiting.discard(entry)

    def release_all(self) -> None:
        """End every current wait and answer later ones at once (thread-safe, not signal-safe)."""
        with self._lock:
            self._released = True
            waiting = list(self._waiting)
        for loop, ended in waiting:
            try:
                loop.call_soon_threadsafe(ended.set)
            except RuntimeError:
                pass


def chain_stop_signals(on_stop: Callable[[], None]) -> Callable[[], None]:
    """Call ``on_stop`` first whenever SIGINT/SIGTERM reaches the current (server) handler.

    Only from the main thread, and only in front of a Python handler (uvicorn's
    ``handle_exit``), which still runs right after. ``on_stop`` runs inside a signal
    handler: it must only schedule work (``loop.call_soon_threadsafe``). Returns the
    function that puts the previous handlers back.
    """
    if threading.current_thread() is not threading.main_thread():
        return lambda: None
    chained: dict[int, tuple[Callable[[int, FrameType | None], object], Callable[[int, FrameType | None], None]]] = {}
    for sig in STOP_SIGNALS:
        previous = signal.getsignal(sig)
        if not callable(previous):
            continue

        def on_signal(signum: int, frame: FrameType | None, previous=previous) -> None:
            try:
                on_stop()
            except RuntimeError:  # the server's loop is already closed; stopping goes on
                pass
            previous(signum, frame)

        signal.signal(sig, on_signal)
        chained[sig] = (previous, on_signal)

    def restore() -> None:
        for sig, (previous, installed) in chained.items():
            if signal.getsignal(sig) is installed:
                signal.signal(sig, previous)

    return restore
