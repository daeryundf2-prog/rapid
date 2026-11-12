"""R8 T-021: one server-side aggregation of ``summary.steps`` (GAP-029 / QA-019).

The IMG-B fixture is synthetic: it only reproduces the shape of the real run (42 steps, one
``failed_isolated`` browser step, a failed silent-failure detector) without any evidence content.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.api.app.run_steps_summary import (
    STEP_CLASSES,
    classify_step_status,
    summarize_steps,
)
from rapidtriage.core.jobs import RunJobStore

TOKEN = "rapidtriage-test-token"


def _steps(*statuses: str) -> dict[str, object]:
    return {"steps": [{"name": f"s{index}", "status": status} for index, status in enumerate(statuses)]}


def _img_b_summary() -> dict[str, object]:
    steps: list[dict[str, object]] = [
        {"name": "source-extraction", "status": "completed"},
        {"name": "files", "status": "completed"},
        {"name": "docs", "status": "completed_with_warnings"},
        {"name": "docs-index", "status": "completed"},
        {"name": "extract", "status": "skipped", "disabled": True},
    ]
    kinds = [
        "registry", "eventlog", "prefetch", "lnk", "jumplist", "shellbags", "srum", "amcache",
        "shimcache", "usb", "email", "cloud", "messenger", "ai-agent", "recycle", "vss",
        "scheduled-tasks", "services", "wmi", "powershell", "rdp", "wifi", "office-mru",
        "thumbcache", "timeline", "notification", "certificates", "defender", "bits", "sru-network",
        "userassist", "mft", "printers",
    ]
    steps.extend({"name": f"artifacts-{kind}", "status": "reused" if index % 7 == 0 else "completed"}
                 for index, kind in enumerate(kinds))
    steps.append({"name": "artifacts-browser", "status": "failed_isolated", "parser_error_count": 1})
    steps.append({"name": "derived", "status": "completed"})
    steps.append({"name": "triage-rules", "status": "completed"})
    steps.append({"name": "silent-failure-detector", "status": "failed", "risk_check_count": 2})
    return {"steps": steps}


class StepStatusClassTests(unittest.TestCase):
    def test_status_table(self) -> None:
        expected = {
            "completed": "completed",
            "completed_with_warnings": "completed",
            "reused": "completed",
            "delta-merged": "completed",
            "pass": "completed",
            "warning": "completed",
            "failed_isolated": "partial",
            "failed-isolated": "partial",
            "cancelled-partial": "partial",
            "failed": "failed",
            "error": "failed",
            "skipped": "skipped",
            "cancelled": "incomplete",
            "running": "incomplete",
            "queued": "incomplete",
            "": "incomplete",
            None: "incomplete",
            "something-new": "incomplete",
            " Failed_Isolated ": "partial",
        }
        for status, step_class in expected.items():
            with self.subTest(status=status):
                self.assertEqual(classify_step_status(status), step_class)

    def test_failed_isolated_is_never_completed(self) -> None:
        result = summarize_steps(_steps("completed", "failed_isolated"))
        self.assertEqual((result["completed"], result["partial"], result["failed"]), (1, 1, 0))
        self.assertEqual(result["partial_names"], ["s1"])


class SummarizeStepsCombinationTests(unittest.TestCase):
    """Twelve status combinations (task card: 상태 조합 12종)."""

    CASES: tuple[tuple[str, tuple[str, ...], dict[str, int]], ...] = (
        ("all-completed", ("completed",) * 3, {"completed": 3}),
        ("with-warnings", ("completed", "completed_with_warnings"), {"completed": 2}),
        ("reused-and-delta", ("reused", "delta-merged", "completed"), {"completed": 3}),
        ("isolated-only", ("failed_isolated",), {"partial": 1}),
        ("failed-and-error", ("failed", "error", "completed"), {"failed": 2, "completed": 1}),
        ("skipped-disabled", ("skipped", "disabled"), {"skipped": 2}),
        ("cancelled-partial", ("cancelled-partial", "completed"), {"partial": 1, "completed": 1}),
        ("cancelled", ("cancelled", "completed"), {"incomplete": 1, "completed": 1}),
        ("in-flight", ("running", "queued", "completed"), {"incomplete": 2, "completed": 1}),
        ("detector-statuses", ("pass", "notice", "warning", "failed"), {"completed": 3, "failed": 1}),
        ("unknown-status", ("brand-new", "", "completed"), {"incomplete": 2, "completed": 1}),
        ("mixed", ("completed", "failed_isolated", "failed", "skipped", "running"),
         {"completed": 1, "partial": 1, "failed": 1, "skipped": 1, "incomplete": 1}),
    )

    def test_combinations(self) -> None:
        self.assertEqual(len(self.CASES), 12)
        for label, statuses, expected in self.CASES:
            with self.subTest(label):
                result = summarize_steps(_steps(*statuses))
                self.assertEqual(result["total"], len(statuses))
                self.assertEqual({name: result[name] for name in STEP_CLASSES},
                                 {name: expected.get(name, 0) for name in STEP_CLASSES})
                self.assertEqual(result["total"], sum(result[name] for name in STEP_CLASSES))

    def test_empty_and_malformed_inputs(self) -> None:
        for summary in (None, {}, {"steps": None}, {"steps": "x"}, {"steps": [None, "row", 3]}):
            with self.subTest(summary=summary):
                result = summarize_steps(summary)  # type: ignore[arg-type]
                self.assertEqual(result["total"], 0)
                self.assertEqual(result["failed_names"], [])

    def test_names_keep_order_and_fall_back_to_position(self) -> None:
        result = summarize_steps({"steps": [{"status": "failed"}, {"name": "b", "status": "error"}]})
        self.assertEqual(result["failed_names"], ["step-1", "b"])
        self.assertEqual(result["by_status"], {"error": 1, "failed": 1})


class ImgBPatternTests(unittest.TestCase):
    def test_img_b_reports_42_steps_one_partial_one_failed(self) -> None:
        result = summarize_steps(_img_b_summary())
        self.assertEqual(result["total"], 42)
        self.assertEqual(result["partial"], 1)
        self.assertEqual(result["failed"], 1)
        self.assertEqual(result["skipped"], 1)
        self.assertEqual(result["completed"], 39)
        self.assertEqual(result["partial_names"], ["artifacts-browser"])
        self.assertEqual(result["failed_names"], ["silent-failure-detector"])

    def test_dashboard_reports_the_same_counts(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            run_dir = Path(temp) / "run"
            run_dir.mkdir()
            summary_path = run_dir / "rapidtriage-run-summary.json"
            summary = {
                "profile_version": "rapidtriage-run-summary-v1",
                "mode": "fraud",
                "root": str(Path(temp) / "evidence"),
                "output_dir": str(run_dir),
                "outputs": {"summary": str(summary_path)},
                **_img_b_summary(),
            }
            summary_path.write_text(json.dumps(summary), encoding="utf-8")
            store = RunJobStore()
            job = store.import_completed_run(run_dir)
            from fastapi.testclient import TestClient

            from rapidtriage.api import create_app

            client = TestClient(create_app(store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})
            response = client.get(f"/api/runs/{job.run_id}/dashboard")
            self.assertEqual(response.status_code, 200, response.text)
            steps = response.json()["steps"]
            self.assertEqual(steps, summarize_steps(_img_b_summary()))
            self.assertEqual((steps["total"], steps["partial"], steps["failed"]), (42, 1, 1))


if __name__ == "__main__":
    unittest.main()
