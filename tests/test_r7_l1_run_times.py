"""R7 L1: run identity times, evidence time zone and the newest evidence time (run responses)."""

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

from rapidtriage.api.app.run_times import (
    evidence_timezone,
    fingerprint_latest,
    run_times,
    timeline_index_max,
)
from rapidtriage.api.app.timeline_index import write_timeline_index
from rapidtriage.core.jobs import RunJob, RunJobStore, RunRequest

TOKEN = "r7-l1-run-times-token"
NOW = dt.datetime(2026, 10, 26, tzinfo=dt.timezone.utc)


def write_run(
    run_dir: Path,
    *,
    progress: dict[str, object] | None = None,
    events: list[dict[str, object]] | None = None,
    latest_mtime: float | None = None,
    timezone: dict[str, object] | None = None,
) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    summary_path = run_dir / "rapidtriage-run-summary.json"
    outputs: dict[str, str] = {"summary": str(summary_path)}
    if events is not None:
        timeline = run_dir / "rapidtriage-timeline.json"
        timeline.write_text(json.dumps({"events": events}), encoding="utf-8")
        outputs["timeline"] = str(timeline)
    summary: dict[str, object] = {
        "mode": "hacking",
        "root": str(run_dir.parent / "evidence"),
        "output_dir": str(run_dir),
        "generated_at": "2026-10-15T21:36:32.628944",  # naive local text: never used as a run time
        "outputs": outputs,
        "summary": {"counts": {}},
    }
    if latest_mtime is not None:
        summary["safety"] = {"input_fingerprint": {"summary": {"latest_mtime_epoch": latest_mtime}}}
    if timezone is not None:
        summary["disclosures"] = {"timezone": {"evidence_timezone": timezone, "evidence_timezone_status": "registry-reported"}}
    summary_path.write_text(json.dumps(summary), encoding="utf-8")
    if progress is not None:
        (run_dir / "rapidtriage-run-progress.json").write_text(json.dumps(progress), encoding="utf-8")
    return run_dir


class RunTimesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def test_imported_run_uses_progress_times_not_the_import_time(self) -> None:
        run_dir = write_run(
            self.base / "run",
            progress={
                "status": "completed",
                "started_at": "2026-10-15T11:54:28+00:00",
                "completed_at": "2026-10-15T12:36:35+00:00",
            },
        )
        job = RunJobStore().import_completed_run(run_dir)
        times = run_times(job)
        self.assertEqual(times["source"], "run-progress")
        self.assertEqual(times["started_at"], "2026-10-15T11:54:28+00:00")
        self.assertEqual(times["completed_at"], "2026-10-15T12:36:35+00:00")
        self.assertEqual(times["imported_at"], job.created_at)

    def test_imported_run_without_progress_has_no_processing_times(self) -> None:
        job = RunJobStore().import_completed_run(write_run(self.base / "run"))
        times = run_times(job)
        self.assertEqual(times, {"started_at": None, "completed_at": None, "source": "none", "imported_at": job.created_at})

    def test_web_run_ignores_an_older_progress_file_in_its_folder(self) -> None:
        run_dir = write_run(self.base / "run", progress={"status": "completed", "started_at": "2020-01-01T00:00:00+00:00"})
        job = RunJob(
            run_id="abc",
            request=RunRequest(root=str(self.base), mode="fraud", output_dir=str(run_dir)),
            status="completed",
            created_at="2026-10-17T11:18:42+00:00",
            started_at="2026-10-17T11:18:43+00:00",
            completed_at="2026-10-17T11:52:54+00:00",
        )
        times = run_times(job)
        self.assertEqual(times["source"], "job")
        self.assertEqual(times["started_at"], "2026-10-17T11:18:43+00:00")
        self.assertEqual(times["completed_at"], "2026-10-17T11:52:54+00:00")
        self.assertIsNone(times["imported_at"])

    def test_web_run_prefers_its_own_progress_file(self) -> None:
        run_dir = write_run(
            self.base / "run",
            progress={"status": "running", "started_at": "2026-10-17T11:18:45+00:00"},
        )
        job = RunJob(
            run_id="abc",
            request=RunRequest(root=str(self.base), mode="fraud", output_dir=str(run_dir)),
            status="running",
            created_at="2026-10-17T11:18:42+00:00",
            started_at="2026-10-17T11:18:43+00:00",
        )
        times = run_times(job)
        self.assertEqual((times["source"], times["started_at"], times["completed_at"]), ("run-progress", "2026-10-17T11:18:45+00:00", None))

    def test_evidence_timezone(self) -> None:
        summary = {"disclosures": {"timezone": {"evidence_timezone": {"name": "Korea Standard Time", "bias_minutes": -540}, "evidence_timezone_status": "registry-reported"}}}
        self.assertEqual(
            evidence_timezone(summary),
            {"name": "Korea Standard Time", "bias_minutes": -540, "status": "registry-reported"},
        )
        self.assertIsNone(evidence_timezone({"disclosures": {"timezone": {"storage": "UTC"}}}))
        self.assertIsNone(evidence_timezone(None))

    def test_timeline_index_max_skips_missing_and_future_times(self) -> None:
        events = [
            {"timestamp": "2025-05-29T23:25:26Z"},
            {"timestamp": "2025-05-30T04:11:48.5Z"},
            {"timestamp": "2099-12-31T00:00:00Z"},  # clock junk past "now"
            {"timestamp": ""},
        ]
        run_dir = write_run(self.base / "run", events=events)
        timeline = run_dir / "rapidtriage-timeline.json"
        self.assertIsNone(timeline_index_max(timeline, now=NOW))  # no index file yet
        self.assertIsNotNone(write_timeline_index(events, timeline))
        self.assertEqual(timeline_index_max(timeline, now=NOW), "2025-05-30T04:11:48.500000+00:00")
        # A timeline rewritten after the index: the header no longer matches, nothing is trusted.
        timeline.write_text(json.dumps({"events": events[:1]}), encoding="utf-8")
        self.assertIsNone(timeline_index_max(timeline, now=NOW))

    def test_fingerprint_latest(self) -> None:
        summary = {"safety": {"input_fingerprint": {"summary": {"latest_mtime_epoch": 1748576113.297231}}}}
        self.assertEqual(fingerprint_latest(summary, now=NOW), "2025-05-30T03:35:13.297231+00:00")
        future = {"safety": {"input_fingerprint": {"summary": {"latest_mtime_epoch": 4_102_444_800}}}}
        self.assertIsNone(fingerprint_latest(future, now=NOW))
        self.assertIsNone(fingerprint_latest({}, now=NOW))


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for API tests")
class RunResponseFieldsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.events = [{"timestamp": "2025-05-28T01:00:00Z"}, {"timestamp": "2025-05-30T04:11:48Z"}]
        run_dir = write_run(
            base / "run",
            progress={"status": "completed", "started_at": "2026-10-15T11:54:28+00:00", "completed_at": "2026-10-15T12:36:35+00:00"},
            events=self.events,
            latest_mtime=1748000000.0,
            timezone={"name": "Korea Standard Time", "bias_minutes": -540},
        )
        self.timeline = run_dir / "rapidtriage-timeline.json"
        self.store = RunJobStore()
        self.run_id = self.store.import_completed_run(run_dir).run_id
        self.client = TestClient(create_app(self.store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})

    def test_run_list_carries_run_times_and_evidence_timezone(self) -> None:
        listing = self.client.get("/api/runs").json()["runs"]
        row = next(item for item in listing if item["run_id"] == self.run_id)
        self.assertEqual(row["origin"], "imported")
        self.assertEqual(row["run_times"]["started_at"], "2026-10-15T11:54:28+00:00")
        self.assertEqual(row["run_times"]["completed_at"], "2026-10-15T12:36:35+00:00")
        self.assertEqual(row["evidence_timezone"]["bias_minutes"], -540)
        self.assertNotIn("timeline_max_ts", row)  # the list never reads an output

    def test_run_detail_timeline_max_from_the_index_else_the_fingerprint(self) -> None:
        detail = self.client.get(f"/api/runs/{self.run_id}").json()
        # No index file: the newest evidence file time of the input fingerprint.
        self.assertEqual(detail["timeline_max_source"], "evidence-mtime")
        self.assertTrue(str(detail["timeline_max_ts"]).startswith("2025-05-23"))
        self.assertEqual(detail["run_times"]["source"], "run-progress")
        write_timeline_index(self.events, self.timeline)
        detail = self.client.get(f"/api/runs/{self.run_id}").json()
        self.assertEqual(detail["timeline_max_source"], "timeline-index")
        self.assertEqual(detail["timeline_max_ts"], "2025-05-30T04:11:48+00:00")


if __name__ == "__main__":
    unittest.main()
