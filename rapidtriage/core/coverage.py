"""Per-run coverage disclosure: every limit that truncated parsing.

Parsers call :func:`record_coverage` when a cap is hit. The run resets the
collector when it starts, and the run summary writes :func:`coverage_entries`
as ``coverage`` in ``rapidtriage-run-summary.json``.

Entry shape: ``{"area", "reason_code", "limit", "observed", "unit"}`` where
``limit`` and ``observed`` are integers or ``None``.
"""

from __future__ import annotations

import threading

_LOCK = threading.Lock()
_ENTRIES: list[dict[str, object]] = []


def reset_coverage() -> None:
    with _LOCK:
        _ENTRIES.clear()


def record_coverage(
    area: str,
    reason_code: str,
    limit: int | None,
    observed: int | None,
    unit: str,
) -> None:
    entry: dict[str, object] = {
        "area": area,
        "reason_code": reason_code,
        "limit": limit,
        "observed": observed,
        "unit": unit,
    }
    with _LOCK:
        _ENTRIES.append(entry)


def coverage_entries() -> list[dict[str, object]]:
    with _LOCK:
        return [dict(entry) for entry in _ENTRIES]
