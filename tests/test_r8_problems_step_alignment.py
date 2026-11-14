"""The problems list classifies steps exactly like the screens' step counts (T-021/T-022, QA-019)."""

from __future__ import annotations

import unittest
from types import SimpleNamespace

from rapidtriage.api.app import run_problems
from rapidtriage.api.app.run_steps_summary import summarize_steps


def _summary() -> dict:
    return {
        "steps": [
            {"name": "artifacts-browser", "status": "failed_isolated", "message": "1 parser error"},
            {"name": "silent-failure-detector", "status": "failed"},
            {"name": "carving", "status": "skipped", "disabled_reason": "기본 꺼짐"},
            {"name": "files", "status": "completed"},
        ],
        "silent_failure_detection": {
            "checks": [{"id": "eventlog-yield", "level": "failed", "message": "0 rows"}],
        },
    }


class ProblemsStepAlignmentTests(unittest.TestCase):
    def _collect(self) -> list[dict]:
        # No "outputs" in the summary, so the store is never consulted.
        job = SimpleNamespace(summary=_summary(), status="completed", error=None)
        return run_problems.collect_problem_items(None, "run-x", job)  # type: ignore[arg-type]

    def test_failed_isolated_is_partial_not_error(self) -> None:
        items = {item["step"]: item for item in self._collect() if item.get("source") == "step"}
        self.assertEqual(items["artifacts-browser"]["reason_id"], "step-partial")
        self.assertEqual(items["artifacts-browser"]["level"], "warning")
        self.assertEqual(items["silent-failure-detector"]["reason_id"], "step-failed")
        self.assertEqual(items["carving"]["reason_id"], "step-skipped")
        self.assertNotIn("files", items)

    def test_failed_step_count_matches_summarize_steps(self) -> None:
        errors = [i for i in self._collect() if i.get("source") == "step" and i["reason_id"] == "step-failed"]
        self.assertEqual(len(errors), summarize_steps(_summary())["failed"])

    def test_silent_failure_level_failed_is_error(self) -> None:
        silent = [i for i in self._collect() if i.get("source") == "silent_failure"]
        self.assertEqual([i["level"] for i in silent], ["error"])

    def test_partial_reason_has_korean_label(self) -> None:
        self.assertIn("step-partial", run_problems.FIXED_REASONS)


if __name__ == "__main__":
    unittest.main()
