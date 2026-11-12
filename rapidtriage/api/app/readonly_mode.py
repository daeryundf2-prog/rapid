"""Server-wide read-only mode (`rapidtriage web --read-only`, R8 T-112).

The per-run gate of T-032 (``factory.read_only_run_refusal``) refuses state-changing requests for
one read-only run. A read-only *server* applies the same refusal to every run and every other
``/api`` write: 409 ``RUN_READ_ONLY`` with ``readonly_reason: SERVER_READ_ONLY``. Only requests that
write nothing still answer — the run query POSTs of the T-032 allowlist and the pre-check POSTs
below.

The gate alone does not stop a GET (or an allowed query POST) from writing lazily into a result
folder (search caches, case DB initialisation). So the server also holds every run folder it knows
read-only in ``core.readonly_runs`` with reason ``SERVER_READ_ONLY``: the D37 write guard then
refuses such writes and the lazy writers that ask ``may_persist`` skip them.

``uvicorn`` re-imports ``rapidtriage.api.app:app``, so ``rapidtriage web --read-only`` reaches
``create_app`` only through the ``RAPIDTRIAGE_READ_ONLY`` environment variable.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Iterable

from fastapi.responses import JSONResponse

from ...core.error_codes import ERROR_CODES
from ...core.jobs import ACTIVE_JOB_STATUSES, RunJobStore
from ...core.readonly_runs import (
    RUN_READ_ONLY,
    register_readonly_folder,
    unregister_readonly_folder,
)
from .errors import error_response
from .helpers import truthy_env

SERVER_READ_ONLY = "SERVER_READ_ONLY"
SERVER_READ_ONLY_ENV = "RAPIDTRIAGE_READ_ONLY"
SERVER_READ_ONLY_MESSAGE = ERROR_CODES[SERVER_READ_ONLY].message_ko
SERVER_READ_ONLY_HINT = ERROR_CODES[SERVER_READ_ONLY].hint_ko
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_RUN_SCOPED = re.compile(r"/api/runs/(?P<run_id>[^/]+)(?P<rest>/.*)?")
# Pre-check POSTs that only look at a path and write nothing (case wizard, evidence identify,
# collection plan).
SERVER_READ_ONLY_CHECK_POSTS = frozenset(
    {
        "/api/cases/output-check",
        "/api/cases/evidence-check",
        "/api/evidence/identify",
        "/api/collect/plan",
        # Query POST (a list with a body): served from a ``mode=ro`` connection on a read-only
        # server, never initialising or migrating the case DB.
        "/api/case-db/saved-searches/list",
    }
)


def server_read_only_enabled(explicit: bool | None = None) -> bool:
    """``explicit`` when given, else the ``RAPIDTRIAGE_READ_ONLY`` environment variable."""
    return truthy_env(SERVER_READ_ONLY_ENV) if explicit is None else bool(explicit)


def server_read_only_detail() -> dict[str, str]:
    return {
        "code": RUN_READ_ONLY,
        "message": SERVER_READ_ONLY_MESSAGE,
        "hint": SERVER_READ_ONLY_HINT,
        "readonly_reason": SERVER_READ_ONLY,
    }


def server_read_only_refusal(method: str, path: str, run_query_posts: Iterable[str]) -> JSONResponse | None:
    """409 for a state-changing ``/api`` request on a read-only server, else ``None``.

    ``run_query_posts`` is the T-032 allowlist (``factory.READ_ONLY_RUN_QUERY_POSTS``): the POSTs
    under ``/api/runs/{run_id}`` that are queries. Unlike a read-only run, a read-only server also
    refuses ``DELETE /api/runs/{run_id}`` — removing a run from the list changes the server's state.
    """
    if method in SAFE_METHODS or not path.startswith("/api/"):
        return None
    if method == "POST":
        if path in SERVER_READ_ONLY_CHECK_POSTS:
            return None
        match = _RUN_SCOPED.fullmatch(path)
        if match is not None and (match.group("rest") or "") in frozenset(run_query_posts):
            return None
    return error_response(409, server_read_only_detail())


class ServerReadOnlyHolds:
    """Holds the run folders of ``store`` read-only (reason ``SERVER_READ_ONLY``) for one app."""

    def __init__(self, store: RunJobStore) -> None:
        self._store = store
        self._owner = object()
        self._held: dict[str, str] = {}
        self._lock = threading.Lock()

    def sync(self) -> None:
        """Hold every finished run folder the store knows that is not held yet.

        A run with its own D37 reason keeps it (its store already holds the folder); a queued or
        running run is left alone (a read-only server starts none, and its writer must finish).
        """
        for job in self._store.list():
            if job.run_id in self._held or job.readonly_reason or job.status in ACTIVE_JOB_STATUSES:
                continue
            output_dir = job.output_dir()
            if output_dir is None:
                continue
            with self._lock:
                if job.run_id not in self._held:
                    self._held[job.run_id] = register_readonly_folder(
                        output_dir, SERVER_READ_ONLY, owner=(self._owner, job.run_id)
                    )

    def release(self) -> None:
        with self._lock:
            held, self._held = self._held, {}
        for run_id, folder in held.items():
            unregister_readonly_folder(folder, owner=(self._owner, run_id))

    def held_folders(self) -> list[str]:
        with self._lock:
            return sorted(self._held.values())


__all__ = [
    "SERVER_READ_ONLY",
    "SERVER_READ_ONLY_CHECK_POSTS",
    "SERVER_READ_ONLY_ENV",
    "SERVER_READ_ONLY_HINT",
    "SERVER_READ_ONLY_MESSAGE",
    "ServerReadOnlyHolds",
    "server_read_only_detail",
    "server_read_only_enabled",
    "server_read_only_refusal",
]
