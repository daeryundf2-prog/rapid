"""Concurrent writers on one case DB (R8 T-131: two browser windows marking the same rows).

Every case-DB connection waits ``BUSY_TIMEOUT_MS`` for another writer's lock (``PRAGMA
busy_timeout``). A write still refused with ``database is locked`` is re-run up to
``WRITE_LOCK_RETRIES`` times with exponential backoff (``WRITE_LOCK_BACKOFF_S``, doubled each
time); only then does the caller see an error (:class:`CaseDatabaseLockedError`, Korean).
"""

from __future__ import annotations

import functools
import sqlite3
import time
from collections.abc import Callable, Iterator
from typing import ParamSpec, TypeVar

from .base import CaseDatabaseError

_P = ParamSpec("_P")
_T = TypeVar("_T")

BUSY_TIMEOUT_MS = 5000
WRITE_LOCK_RETRIES = 3
WRITE_LOCK_BACKOFF_S = 0.1
CASE_DB_LOCKED_MESSAGE = (
    "케이스 DB가 다른 창(또는 다른 프로그램)의 쓰기로 잠겨 있어 저장하지 못했습니다. 잠시 뒤 다시 시도하세요."
)


class CaseDatabaseLockedError(CaseDatabaseError):
    """A write still refused by SQLite's lock after every retry (Korean message)."""


def is_lock_error(exc: BaseException) -> bool:
    """SQLite's busy/locked refusal (``database is locked`` / ``database table is locked`` / busy)."""
    if not isinstance(exc, sqlite3.OperationalError):
        return False
    text = str(exc).lower()
    return "locked" in text or "busy" in text


def retry_when_locked(write: Callable[[], _T], *, retries: int | None = None, backoff_s: float | None = None) -> _T:
    """Run ``write`` (one whole transaction); on a lock refusal re-run it up to ``retries`` times.

    The waits are ``backoff_s``, ``2 * backoff_s``, ``4 * backoff_s`` … Only when the last retry is
    still locked does the caller see ``CaseDatabaseLockedError`` (chained to the SQLite error). Any
    other error is raised at once. ``write`` must be re-runnable: ``CaseDatabase.connect`` rolls a
    failed transaction back before the next attempt.
    """
    attempts = WRITE_LOCK_RETRIES if retries is None else retries
    delay = WRITE_LOCK_BACKOFF_S if backoff_s is None else backoff_s
    for attempt in range(attempts + 1):
        try:
            return write()
        except sqlite3.OperationalError as exc:
            if not is_lock_error(exc):
                raise
            if attempt >= attempts:
                raise CaseDatabaseLockedError(CASE_DB_LOCKED_MESSAGE) from exc
            time.sleep(delay * (2**attempt))
    raise AssertionError("unreachable")  # pragma: no cover


def retrying_when_locked(method: Callable[_P, _T]) -> Callable[_P, _T]:
    """Decorate a one-transaction write so it runs under ``retry_when_locked``.

    Iterator arguments (e.g. a tag generator) are read into lists first so a retry sees them again.
    """

    @functools.wraps(method)
    def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> _T:
        frozen = {key: list(value) if isinstance(value, Iterator) else value for key, value in kwargs.items()}
        return retry_when_locked(lambda: method(*args, **frozen))  # type: ignore[arg-type]

    return wrapper
