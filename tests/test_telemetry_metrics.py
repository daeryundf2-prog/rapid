"""P0 metrics/funnels over a synthetic event log, and the telemetry API round trip."""

from __future__ import annotations

import datetime as dt
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from fastapi.testclient import TestClient

from rapidtriage.api.app import create_app
from rapidtriage.api.app.routes_telemetry import _run_facts
from rapidtriage.core import telemetry
from rapidtriage.core.jobs import RunJobStore
from rapidtriage.core.telemetry.funnels import build_report
from rapidtriage.core.telemetry.recorder import ACTIVE_ENV, DIR_ENV, DISABLE_ENV

T0 = dt.datetime(2026, 11, 2, 9, 0, tzinfo=dt.timezone.utc)


def ev(name: str, minutes: float, props: dict[str, object] | None = None, **envelope: object) -> dict[str, object]:
    return {
        "ts": (T0 + dt.timedelta(minutes=minutes)).isoformat(),
        "event": name,
        "install_hid": "i1",
        "app_version": "0.2.0",
        "props": props or {},
        **envelope,
    }


# Case c1 goes all the way to a report (run r1); case c2 stops after its run (r2 fails a provider).
LOG = [
    ev("app_session_started", 0, session_id="s1"),
    ev("case_created", 1, case_hid="c1"),
    ev("case_created", 2, case_hid="c2"),
    ev("run_started", 3, {"input_kind": "e01"}, run_hid="r1"),
    ev("run_stage_completed", 4, {"stage": "artifacts", "duration_ms": 600}, run_hid="r1"),
    ev("provider_finished", 5, {"provider_kind": "evtx", "parser_error_count": 4}, run_hid="r1"),
    ev("provider_finished", 5, {"provider_kind": "evtx", "parser_error_count": 0}, run_hid="r2"),
    ev("run_finished", 10, {"status": "completed", "duration_ms": 1000}, run_hid="r1", case_hid="c1"),
    ev("run_failed", 11, {"stage": "artifacts", "error_class": "OSError"}, run_hid="r2", case_hid="c2"),
    ev("review_stage_entered", 12, {"ms_since_run_finished": 120000}, run_hid="r1"),
    ev("search_submitted", 13, {"script": "hangul"}, session_id="s1", run_hid="r1"),
    ev("search_results_returned", 13, {"latency_ms": 900, "zero_result": False, "truncated": True, "backend": "fts"}, session_id="s1", run_hid="r1"),
    ev("search_submitted", 14, {"script": "latin"}, session_id="s1", run_hid="r1"),
    ev("search_results_returned", 14, {"latency_ms": 100, "zero_result": True, "truncated": False, "backend": "fts"}, session_id="s1", run_hid="r1"),
    ev("review_tag_applied", 15, {"is_first_in_run": True, "source_surface": "search"}, session_id="s1", run_hid="r1"),
    ev("grid_sorted", 16, {"scope": "loaded"}),
    ev("grid_sorted", 17, {"scope": "server"}),
    ev("crash_reported", 18, {"component": "api"}),
    ev("case_report_created", 60 * 24, {"status": "ok"}, run_hid="r1", case_hid="c1"),
]


class MetricsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = build_report(LOG)
        self.metrics = self.report["metrics"]

    def test_value_metrics_follow_the_proposal_formulas(self) -> None:
        self.assertEqual(self.metrics["wrc"]["by_week"], {"2026-W45": 1})
        self.assertEqual(self.metrics["ttv"], {"n": 1, "median_ms": (60 * 24 - 1) * 60000.0})
        self.assertEqual(self.metrics["ttfr"]["median_ms"], 120000)
        self.assertEqual(self.metrics["ttft"]["median_ms"], 5 * 60000.0)
        self.assertEqual(self.metrics["search_latency"]["by_backend_script"]["fts|latin"]["p50_ms"], 100)

    def test_completeness_and_guard_metrics(self) -> None:
        self.assertEqual(self.metrics["full_scope_share"]["sort_server_share"], 0.5)
        self.assertEqual(self.metrics["truncation_rate"]["search"], 0.5)
        self.assertEqual(self.metrics["run_success"]["success_rate"], 0.5)
        self.assertEqual(self.metrics["parser_error_rate"]["by_provider_kind"], {"evtx": 2.0})
        self.assertEqual(self.metrics["crash_rate"]["overall"], 1.0)
        self.assertEqual(self.metrics["time_to_triage"]["by_input_kind"]["e01"]["median_ms"], 1000)
        self.assertEqual(self.metrics["time_to_triage"]["stage_share"], {"artifacts": 0.6})
        self.assertEqual(self.metrics["active_installs"]["by_week"]["2026-W45"], {"installs": 1, "cases_per_install": 2.0})

    def test_f1_counts_each_case_once_per_step_within_14_days(self) -> None:
        steps = {step["event"]: step["cases"] for step in self.report["funnels"]["F1"]["steps"]}
        self.assertEqual(
            steps,
            {"case_created": 2, "run_started": 1, "run_finished": 1, "review_stage_entered": 1, "review_tag_applied": 1, "case_report_created": 1},
        )
        late = [*LOG, ev("case_report_created", 60 * 24 * 15, {"status": "ok"}, case_hid="c2")]
        late_steps = build_report(late)["funnels"]["F1"]["steps"]
        self.assertEqual(late_steps[-1]["cases"], 1)

    def test_f2_search_to_tag_uses_the_10_minute_session_window(self) -> None:
        f2 = self.report["funnels"]["F2"]
        self.assertEqual((f2["searches"], f2["search_to_tag"], f2["zero_result_rate"]), (2, 1.0, 0.5))
        late_tag = [event for event in LOG if event["event"] != "review_tag_applied"]
        late_tag.append(ev("review_tag_applied", 30, {"source_surface": "search"}, session_id="s1"))
        self.assertEqual(build_report(late_tag)["funnels"]["F2"]["search_to_tag"], 0.0)


class TelemetryApiTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.dir = Path(temp.name) / "telemetry"
        env = mock.patch.dict(os.environ, {DIR_ENV: str(self.dir), ACTIVE_ENV: "1"})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop(DISABLE_ENV, None)
        app = create_app(RunJobStore(), auth_token="t", cases_db_path=Path(temp.name) / "cases.db")
        self.client = TestClient(app, headers={"X-RapidTriage-Token": "t", "X-RapidTriage-Session": "sess-0001"})

    def test_console_events_get_server_facts_and_a_session(self) -> None:
        for _ in range(2):
            response = self.client.post(
                "/api/telemetry/events",
                json={"event": "review_tag_applied", "props": {"action": "tag", "row_count": 2}, "run_id": "r9", "tag": "중요"},
            )
            self.assertEqual(response.json(), {"recorded": True})
        lines = list(telemetry.iter_events(self.dir))
        self.assertEqual([line["props"]["is_first_in_run"] for line in lines], [True, False])
        self.assertEqual({line["session_id"] for line in lines}, {"sess-0001"})
        self.assertEqual(len(lines[0]["props"]["tag_hid"]), 16)
        metrics = self.client.get("/api/telemetry/metrics").json()
        self.assertEqual(metrics["event_count"], 2)

    def test_unknown_event_names_are_rejected(self) -> None:
        response = self.client.post("/api/telemetry/events", json={"event": "search_term_typed", "props": {}})
        self.assertEqual(response.status_code, 422)

    def test_run_facts_measure_time_since_the_run_finished(self) -> None:
        finished = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=2)).isoformat()
        store = SimpleNamespace(get=lambda run_id: SimpleNamespace(status="completed", completed_at=finished))
        facts = _run_facts(store, "r1")
        self.assertEqual(facts["run_status"], "completed")
        self.assertGreaterEqual(facts["ms_since_run_finished"], 120000)
