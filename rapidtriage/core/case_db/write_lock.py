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

#: The back-off wait; tests patch this name (never the global ``time.sleep``, which other
#: threads in the same process use too).
_sleep = time.sleep

_P = ParamSpec("_P")
_T = TypeVar("_T")

BUSY_TIMEOUT_MS = 5000
WRITE_LOCK_RETRIES = 3
WRITE_LOCK_BACKOFF_S = 0.1
CASE_DB_LOCKED_MESSAGE = (
    "케이스 DB가 다른 창(또는 다른 프로그램)의 쓰기로 잠겨 있어 저장하지 못했습니다. 잠시 뒤 다시 시도하세요."
)


#: Error code of a case-DB write refused by another writer's lock (HTTP 409, ``core/error_codes.py``).
CASE_DB_LOCKED = "CASE_DB_LOCKED"


class CaseDatabaseLockedError(CaseDatabaseError):
    """A write still refused by SQLite's lock after every retry (Korean message).

    ``applied_rows`` / ``total_rows`` are set when a chunked batch (WB-9 P2-15) had already committed
    earlier chunks: those rows are saved, the rest are not."""

    applied_rows: int = 0
    total_rows: int = 0


class CaseDatabaseBatchPartialError(CaseDatabaseError):
    """A chunked batch failed (any error but a lasting lock) after earlier chunks were committed
    (review WB-10/11 P2-15): ``applied_rows`` of ``total_rows`` are saved, the rest are not."""

    def __init__(self, cause: BaseException, *, applied_rows: int, total_rows: int) -> None:
        self.applied_rows = applied_rows
        self.total_rows = total_rows
        self.cause_message = str(cause)
        super().__init__(
            f"일괄 표시가 중간에 실패했습니다. 이 요청의 {total_rows:,}행 중 앞의 {applied_rows:,}행은 이미 "
            f"저장되었고 나머지는 저장되지 않았습니다(원인: {cause})."
        )


#: Error code of a chunked batch that failed after earlier chunks were saved (``core/error_codes.py``).
CASE_DB_BATCH_PARTIAL = "CASE_DB_BATCH_PARTIAL"


def case_db_batch_partial_detail(exc: CaseDatabaseBatchPartialError) -> dict[str, object]:
    """HTTP 409 ``detail`` for a partly applied batch: the Korean sentence and both counts."""
    return {
        "code": CASE_DB_BATCH_PARTIAL,
        "message": str(exc),
        "applied_count": exc.applied_rows,
        "total_count": exc.total_rows,
    }


def case_db_locked_detail(exc: BaseException | None = None) -> dict[str, object]:
    """HTTP 409 ``detail`` for a locked case DB. Nothing of the refused transaction was written; for a
    chunked batch the message says how many rows earlier transactions already saved."""
    applied = int(getattr(exc, "applied_rows", 0) or 0)
    if not applied:
        return {"code": CASE_DB_LOCKED, "message": CASE_DB_LOCKED_MESSAGE}
    total = int(getattr(exc, "total_rows", 0) or 0)
    return {
        "code": CASE_DB_LOCKED,
        "message": f"{CASE_DB_LOCKED_MESSAGE} 이 요청의 {total:,}행 중 앞의 {applied:,}행은 이미 저장되었고 나머지는 저장되지 않았습니다.",
        "applied_count": applied,
        "total_count": total,
    }


def raised_in_case_db_code(exc: BaseException) -> bool:
    """The error came through case-DB code (``core/case_db`` or the API's case-DB modules), whatever the URL."""
    tb = exc.__traceback__
    while tb is not None:
        name = tb.tb_frame.f_code.co_filename.replace("\\", "/")
        if "/core/case_db/" in name or name.rsplit("/", 1)[-1] in CASE_DB_API_MODULES:
            return True
        tb = tb.tb_next
    return False


#: API modules whose SQLite work is case-DB work (a lock there is ``CASE_DB_LOCKED`` on any URL).
CASE_DB_API_MODULES = frozenset({"routes_case_db.py", "routes_review_tools.py", "routes_cases.py", "case_workspace.py"})


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
            _sleep(delay * (2**attempt))
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
