"""``wait: true`` on run creation: a bounded wait that never holds a request thread.

Runs always go through the store's worker pool (``RAPIDTRIAGE_RUN_WORKERS``).
A ``wait: true`` request awaits the queued run on the event loop for at most
``RAPIDTRIAGE_RUN_WAIT_SECONDS``; past that it answers with the run still
``queued``/``running`` (``wait_timed_out: true``) and the client polls
``GET /api/runs/{run_id}``. Many concurrent ``wait: true`` requests therefore
cannot exhaust the server's thread pool and stall ``/api/health`` or ``/``
(remote-use review R3).
"""

from __future__ import annotations

import asyncio
import os
from concurrent.futures import Future

from ...core.jobs import ACTIVE_JOB_STATUSES, RunJobStore

RUN_WAIT_SECONDS_ENV = "RAPIDTRIAGE_RUN_WAIT_SECONDS"
DEFAULT_RUN_WAIT_SECONDS = 60.0


def run_wait_seconds() -> float:
    """``RAPIDTRIAGE_RUN_WAIT_SECONDS`` (0 or more; unset or not a number -> ``DEFAULT_RUN_WAIT_SECONDS``)."""
    raw = os.environ.get(RUN_WAIT_SECONDS_ENV, "").strip()
    try:
        return max(0.0, float(raw)) if raw else DEFAULT_RUN_WAIT_SECONDS
    except ValueError:
        return DEFAULT_RUN_WAIT_SECONDS


async def wait_for_run(store: RunJobStore, run_id: str) -> bool:
    """Await the queued run up to ``run_wait_seconds()``; ``True`` once it ended, ``False`` on timeout.

    A disconnecting client cancels only this wait, never the run.
    """
    future = store.completion_future(run_id)
    if future is None:
        return store.get(run_id).status not in ACTIVE_JOB_STATUSES
    loop = asyncio.get_running_loop()
    ended = asyncio.Event()

    def wake(_future: Future[dict[str, object]]) -> None:
        try:
            loop.call_soon_threadsafe(ended.set)
        except RuntimeError:  # the request's event loop is already closed
            pass

    future.add_done_callback(wake)
    try:
        await asyncio.wait_for(ended.wait(), timeout=run_wait_seconds())
    except asyncio.TimeoutError:
        return False
    return True
