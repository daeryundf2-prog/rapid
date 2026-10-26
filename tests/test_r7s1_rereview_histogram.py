"""R7 S1 re-review C-V2: ``GET /timeline-histogram`` applies ``from``/``to`` server-side."""

from __future__ import annotations

import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path

try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import create_app

    HAS_FASTAPI = True
except ImportError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

from rapidtriage.api.app.timeline_hist import build_timeline_histogram
from rapidtriage.core.jobs import RunJobStore

TOKEN = "r7s1-histogram-token"
EVENTS = [
    {"timestamp": "2023-06-01T00:00:00Z", "source": "files"},
    {"timestamp": "2024-01-01T10:00:00Z", "source": "files"},
    {"timestamp": "2024-01-02T10:00:00Z", "source": "evtx"},
    {"timestamp": "2024-01-31T23:59:59Z", "source": "evtx"},
    {"timestamp": "2024-02-01T00:00:00Z", "source": "lnk"},
    {"timestamp": "1628-03-01T00:00:00Z", "source": "lnk"},
    {"timestamp": "bad", "source": "files"},
]


def utc(text: str) -> dt.datetime:
    return dt.datetime.fromisoformat(text).replace(tzinfo=dt.timezone.utc)


class HistogramRangeUnitTests(unittest.TestCase):
    def test_range_keeps_only_events_inside(self) -> None:
        whole = build_timeline_histogram({"events": EVENTS})
        self.assertEqual(whole["parsed_events"], 5)
        self.assertNotIn("range_excluded_events", whole)
        clipped = build_timeline_histogram({"events": EVENTS}, range_from=utc("2024-01-01T00:00:00"), range_until=utc("2024-02-01T00:00:00"))
        self.assertEqual(clipped["parsed_events"], 3)
        self.assertEqual(sum(bucket["count"] for bucket in clipped["buckets"]), 3)
        self.assertEqual(clipped["range_excluded_events"], 2)
        self.assertEqual(clipped["out_of_range_count"], 1)  # the 1628 value: plausibility window, as before
        self.assertEqual(clipped["unparsed_events"], 1)
        self.assertGreaterEqual(clipped["range_start"], "2024-01-01")
        self.assertLessEqual(clipped["buckets"][-1]["start"], "2024-02-01")
        self.assertEqual(set(whole) - {"range_excluded_events"}, set(clipped) - {"range_excluded_events"})  # same shape
        empty = build_timeline_histogram({"events": EVENTS}, range_from=utc("2030-01-01T00:00:00"))
        self.assertEqual(empty["bucket_count"], 0)
        self.assertEqual(empty["range_excluded_events"], 5)


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for API tests")
class HistogramRangeApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        run_dir = base / "run"
        run_dir.mkdir()
        timeline_path = run_dir / "rapidtriage-timeline.json"
        timeline_path.write_text(json.dumps({"events": EVENTS}), encoding="utf-8")
        summary_path = run_dir / "rapidtriage-run-summary.json"
        summary_path.write_text(
            json.dumps(
                {
                    "profile_version": "rapidtriage-run-summary-v1",
                    "mode": "hacking",
                    "root": str(base / "evidence"),
                    "output_dir": str(run_dir),
                    "source": {"type": "directory", "analysis_root": str(base / "evidence")},
                    "outputs": {"timeline": str(timeline_path), "summary": str(summary_path)},
                    "summary": {"counts": {}},
                }
            ),
            encoding="utf-8",
        )
        store = RunJobStore()
        self.run_id = store.import_completed_run(run_dir).run_id
        self.client = TestClient(create_app(store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})

    def get(self, **params: object):
        return self.client.get(f"/api/runs/{self.run_id}/timeline-histogram", params=params)

    def test_from_to_bucket_only_rows_in_range(self) -> None:
        whole = self.get().json()
        self.assertEqual(whole["parsed_events"], 5)
        self.assertNotIn("range_filter", whole)
        response = self.get(**{"from": "2024-01-01", "to": "2024-01-31"})
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["parsed_events"], 3)  # ``to`` covers the whole day 2024-01-31
        self.assertEqual(body["range_excluded_events"], 2)
        self.assertEqual(body["range_filter"]["from"], "2024-01-01T00:00:00+00:00")
        # Offset-less bounds are read in ``tz``: 2024-01-02 KST starts 2024-01-01T15:00Z.
        seoul = self.get(**{"from": "2024-01-02", "tz": "+09:00"}).json()
        self.assertEqual(seoul["parsed_events"], 3)
        self.assertEqual(self.get(**{"from": "2024-02-01", "to": "2024-01-01"}).status_code, 422)


if __name__ == "__main__":
    unittest.main()
