"""Wall-clock budget for unified search (scan and index backends).

A search never blocks for minutes: every source scan checks a deadline per
row and stops when it passes, and the response then reports
``truncated: true`` with per-source ``scanned`` counters.

Sources run in their fixed order against one deadline (R7 S2 review #5): a
budget stop ends the search at that point of the order (later sources are
skipped as ``after-budget``), so a truncated result is always a prefix of the
full result and paging past it never skips rows.
"""

from __future__ import annotations

import os
import time

SCAN_BUDGET_ENV = "RAPIDTRIAGE_SEARCH_SCAN_BUDGET_SECONDS"
DEFAULT_SCAN_BUDGET_SECONDS = 20.0
FINALIZE_RESERVE_FRACTION = 0.1
FINALIZE_RESERVE_MAX_SECONDS = 2.0


def resolve_scan_budget_seconds(value: float | None = None) -> float:
    """Budget in seconds: explicit value, else the environment, else 20 s.

    ``0`` (or a negative value) disables the budget (unbounded scan).
    """
    if value is None:
        raw = os.environ.get(SCAN_BUDGET_ENV, "").strip()
        try:
            value = float(raw) if raw else DEFAULT_SCAN_BUDGET_SECONDS
        except ValueError:
            value = DEFAULT_SCAN_BUDGET_SECONDS
    return max(0.0, float(value))


class SourceScan:
    """Per-source scan slice: counts rows and enforces the slice deadline."""

    __slots__ = ("deadline", "elapsed", "matches", "rows", "source", "started", "stopped")

    def __init__(self, source: str, deadline: float | None) -> None:
        self.source = source
        self.deadline = deadline
        self.rows = 0
        self.matches = 0
        self.stopped = ""
        self.started = time.monotonic()
        self.elapsed = 0.0

    def tick(self) -> bool:
        """Count one scanned row; False once the slice deadline has passed."""
        if self.deadline is not None and time.monotonic() >= self.deadline:
            self.stopped = "budget"
            return False
        self.rows += 1
        return True

    def finish(self, *, matches: int, limit_reached: bool) -> None:
        self.matches = matches
        if not self.stopped and limit_reached:
            self.stopped = "limit"
        self.elapsed = time.monotonic() - self.started

    def to_dict(self) -> dict[str, object]:
        return {
            "rows": self.rows,
            "matches": self.matches,
            "complete": not self.stopped,
            "stopped": self.stopped or None,
            "elapsed_ms": round(self.elapsed * 1000, 1),
        }


class SearchBudget:
    """One search deadline for every source (they run in order; a stop ends the search there)."""

    def __init__(self, seconds: float, *, started: float | None = None) -> None:
        """``started``: when the request began (a fallback backend keeps the original deadline)."""
        self.seconds = seconds
        self.started = time.monotonic() if started is None else started
        # The budget covers the whole request: source scans stop early enough
        # to leave time for building the response (enrichment, analysis).
        reserve = min(FINALIZE_RESERVE_MAX_SECONDS, seconds * FINALIZE_RESERVE_FRACTION)
        self.deadline = self.started + seconds - reserve if seconds > 0 else None
        self.sources: dict[str, SourceScan] = {}

    def start_source(self, source: str) -> SourceScan:
        """Begin a source scan against the whole remaining budget (sources run in order: a stop
        cuts the result at that point, never in the middle of the order)."""
        scan = SourceScan(source, self.deadline)
        self.sources[source] = scan
        return scan

    def skip_source(self, source: str, reason: str) -> None:
        scan = SourceScan(source, None)
        scan.stopped = reason
        self.sources[source] = scan

    @property
    def truncated(self) -> bool:
        return any(scan.stopped == "budget" for scan in self.sources.values())

    @property
    def stopped_source(self) -> str | None:
        """The source the budget stopped in (later sources were skipped), or ``None``."""
        for source, scan in self.sources.items():
            if scan.stopped == "budget":
                return source
        return None

    def elapsed_ms(self) -> float:
        return round((time.monotonic() - self.started) * 1000, 1)

    def scanned(self) -> dict[str, dict[str, object]]:
        return {source: scan.to_dict() for source, scan in self.sources.items()}
