from __future__ import annotations

import datetime as dt
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from ...core.sqlite_snapshot import open_sqlite_snapshot as _open_sqlite_snapshot
from ..review import (
    build_forensic_review,  # noqa: F401 - re-exported for Windows artifact modules.
)

WINDOWS_USERS_DIRNAME = "Users"


def iter_windows_user_homes(root: Path) -> Iterator[Path]:
    users_dir = root / WINDOWS_USERS_DIRNAME
    if users_dir.is_dir():
        for candidate in sorted(users_dir.iterdir(), key=lambda item: item.name.lower()):
            if candidate.is_dir():
                yield candidate
        return

    if (root / "AppData").is_dir():
        yield root


@contextmanager
def open_sqlite_snapshot(
    path: Path, *, provenance: dict[str, object] | None = None
) -> Iterator[sqlite3.Connection]:
    with _open_sqlite_snapshot(path, provenance=provenance) as connection:
        yield connection


def isoformat_from_timestamp(timestamp: float | None) -> str | None:
    if timestamp in (None, 0, ""):
        return None
    try:
        return dt.datetime.fromtimestamp(float(timestamp), dt.timezone.utc).isoformat()
    except (OverflowError, OSError, TypeError, ValueError):
        return None


def isoformat_from_unix_micros(value: int | None) -> str | None:
    if value in (None, 0):
        return None
    try:
        timestamp = float(value) / 1_000_000
    except (TypeError, ValueError):
        return None
    return isoformat_from_timestamp(timestamp)


def isoformat_from_webkit_micros(value: int | None) -> str | None:
    if value in (None, 0):
        return None
    try:
        base = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
        moment = base + dt.timedelta(microseconds=int(value))
    except (OverflowError, TypeError, ValueError):
        return None
    return moment.isoformat()
