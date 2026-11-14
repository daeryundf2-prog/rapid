"""One aggregation of a run's processing steps (R8 T-021, GAP-029).

The intake card and the processing screen used to count steps from different sources and with
different rules: the intake card read the collector progress (12 providers, "12/12 완료·오류 0")
while the processing screen read ``summary.steps`` (42 steps, one ``failed_isolated`` browser step
and a failed silent-failure detector). :func:`summarize_steps` is the single server-side rule:
it reads only ``summary["steps"][].status`` and every API payload that reports step counts uses it.

Classes (display layer only; the step status values themselves are owned by ``core/run``):

- completed: ``completed``, ``completed_with_warnings``, ``reused``, ``delta-merged`` and the
  silent-failure detector's ``pass`` / ``notice`` / ``warning`` (the detector ran; its findings
  are reported as warnings, not as a step failure)
- partial: ``failed_isolated`` / ``failed-isolated`` (the step ran, a part of it failed and was
  isolated) and ``cancelled-partial`` / ``partial`` (rows written before a cancel)
- failed: ``failed``, ``error``, ``fail``
- skipped: ``skipped``, ``disabled``
- incomplete: ``queued``, ``pending``, ``running``, ``cancelled``, a missing status and any
  status this table does not know — never counted as completed

The field is named ``steps`` so that it cannot be confused with the collector progress
(``providers``), which counts a different thing.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from typing import Any

STEP_CLASSES: tuple[str, ...] = ("completed", "partial", "failed", "skipped", "incomplete")

_STATUS_CLASS: dict[str, str] = {
    "completed": "completed",
    "completed_with_warnings": "completed",
    "completed-with-warnings": "completed",
    "reused": "completed",
    "delta-merged": "completed",
    "pass": "completed",
    "notice": "completed",
    "warning": "completed",
    "failed_isolated": "partial",
    "failed-isolated": "partial",
    "cancelled-partial": "partial",
    "cancelled_partial": "partial",
    "partial": "partial",
    "failed": "failed",
    "error": "failed",
    "fail": "failed",
    "skipped": "skipped",
    "disabled": "skipped",
}


def classify_step_status(status: object) -> str:
    """Class of one step status; unknown or missing statuses are ``incomplete``, never completed."""
    key = str(status or "").strip().lower()
    return _STATUS_CLASS.get(key, "incomplete")


def summarize_steps(summary: Mapping[str, Any] | None) -> dict[str, Any]:
    """Counts of ``summary["steps"]`` by class.

    ``total`` always equals the sum of the five class counts. Name lists keep the step order of
    the summary so the screen can link each non-completed step.
    """
    steps = summary.get("steps") if isinstance(summary, Mapping) else None
    counts: Counter[str] = Counter()
    by_status: Counter[str] = Counter()
    names: dict[str, list[str]] = {name: [] for name in ("partial", "failed", "skipped", "incomplete")}
    for index, step in enumerate(steps if isinstance(steps, list) else []):
        if not isinstance(step, Mapping):
            continue
        status = str(step.get("status") or "").strip()
        step_class = classify_step_status(status)
        counts[step_class] += 1
        by_status[status or "unknown"] += 1
        if step_class in names:
            names[step_class].append(str(step.get("name") or f"step-{index + 1}"))
    return {
        "total": sum(counts.values()),
        **{name: counts[name] for name in STEP_CLASSES},
        "failed_names": names["failed"],
        "partial_names": names["partial"],
        "skipped_names": names["skipped"],
        "incomplete_names": names["incomplete"],
        "by_status": dict(sorted(by_status.items())),
    }
