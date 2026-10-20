"""Shared helpers of the R6 S3 benchmarks (``scripts/perf-r6.py``): ``--run`` must leave the run
folder untouched, so the benchmarks keep on-demand indexes in memory
(``RAPIDTRIAGE_INDEX_PERSIST=0``), measure the "index file present" case on a temporary copy of
the outputs they need, and compare a listing of the run folder (relative path, size, mtime) taken
before and after."""

from __future__ import annotations

import contextlib
import os
from collections.abc import Iterator
from pathlib import Path

INDEX_PERSIST_ENV = "RAPIDTRIAGE_INDEX_PERSIST"  # rapidtriage.api.app.index_cache.INDEX_PERSIST_ENV


def folder_snapshot(root: Path) -> dict[str, tuple[int, int]]:
    """``relative path -> (size, mtime_ns)`` of every file and folder under ``root`` (``root`` too)."""
    listing: dict[str, tuple[int, int]] = {}
    for current, _folders, files in os.walk(root):
        relative = os.path.relpath(current, root)
        listing[relative + os.sep] = (0, os.stat(current).st_mtime_ns)
        for name in files:
            stat = os.stat(os.path.join(current, name))
            listing[os.path.join(relative, name)] = (stat.st_size, stat.st_mtime_ns)
    return listing


def snapshot_changes(before: dict[str, tuple[int, int]], after: dict[str, tuple[int, int]]) -> list[str]:
    """Paths added (``+``), removed (``-``) or changed (``~``) between two snapshots."""
    changes = [f"+{path}" for path in sorted(set(after) - set(before))]
    changes += [f"-{path}" for path in sorted(set(before) - set(after))]
    changes += [f"~{path}" for path in sorted(set(before) & set(after)) if before[path] != after[path]]
    return changes


@contextlib.contextmanager
def index_persist(enabled: bool) -> Iterator[None]:
    """Set ``RAPIDTRIAGE_INDEX_PERSIST`` for the block (restored afterwards)."""
    previous = os.environ.get(INDEX_PERSIST_ENV)
    os.environ[INDEX_PERSIST_ENV] = "1" if enabled else "0"
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(INDEX_PERSIST_ENV, None)
        else:
            os.environ[INDEX_PERSIST_ENV] = previous
