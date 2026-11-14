"""Wall-clock budgets for tests that scale with the box's load.

A shared CI runner can run a test several times slower than a developer box
(windows-latest ran a 0.55 s check in 5.6 s).  Tests that assert an absolute
wall-clock bound wrap it in :func:`time_budget`, which multiplies it by
``RAPIDTRIAGE_TEST_TIME_SCALE``.  ``scripts/dev/run-tests.py`` exports its load
multiplier there for its workers, and CI sets it to 3.  Unset, invalid or < 1
means 1x, so an idle developer run keeps the original bound.
"""

from __future__ import annotations

import math
import os

TIME_SCALE_ENV = "RAPIDTRIAGE_TEST_TIME_SCALE"


def time_scale() -> float:
    """The current multiplier from ``RAPIDTRIAGE_TEST_TIME_SCALE`` (>= 1; invalid -> 1)."""
    raw = os.environ.get(TIME_SCALE_ENV, "").strip()
    try:
        value = float(raw)
    except ValueError:
        return 1.0
    if not math.isfinite(value):
        return 1.0
    return max(1.0, value)


def time_budget(seconds: float) -> float:
    """``seconds`` x :func:`time_scale` (read at call time)."""
    return seconds * time_scale()
