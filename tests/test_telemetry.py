"""Local telemetry: recorder envelope/ids, the privacy guard, run hooks, metrics and funnels."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.core import telemetry
from rapidtriage.core.run.progress import RunProgress
from rapidtriage.core.search_index.query import parse_query
from rapidtriage.core.telemetry.derive import query_shape
from rapidtriage.core.telemetry.export import TelemetryExportError, export_bundle
from rapidtriage.core.telemetry.recorder import (
    ACTIVE_ENV,
    DIR_ENV,
    DISABLE_ENV,
    hid,
    privacy_violations,
)
from rapidtriage.core.telemetry.schema import EVENTS, FORBIDDEN_NAME_WORDS

PATH_VALUE = "C:\\Users\\analyst\\evidence\\secret-report.docx"


class TelemetryCase(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.dir = Path(temp.name) / "telemetry"
        env = mock.patch.dict(os.environ, {DIR_ENV: str(self.dir), ACTIVE_ENV: "1"})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop(DISABLE_ENV, None)

    def lines(self) -> list[dict[str, object]]:
        return list(telemetry.iter_events(self.dir))

    def raw_log(self) -> str:
        return "".join(path.read_text(encoding="utf-8") for path in sorted(self.dir.glob("events-*.jsonl")))


class RecorderTests(TelemetryCase):
    def test_record_writes_envelope_with_salted_ids_and_whitelisted_props(self) -> None:
        self.assertTrue(
            telemetry.record("run_finished", {"status": "completed", "duration_ms": 1200.7, "extra": 1}, run_id="abc123", case_id="case-1")
        )
        [line] = self.lines()
        self.assertEqual(line["event"], "run_finished")
        self.assertEqual(line["props"], {"status": "completed", "duration_ms": 1200})
        self.assertEqual(line["run_hid"], hid("run", "abc123", self.dir))
        self.assertEqual(line["case_hid"], hid("case", "case-1", self.dir))
        self.assertNotIn("abc123", self.raw_log())
        self.assertNotIn("case-1", self.raw_log())

    def test_nothing_is_recorded_without_activation_or_when_turned_off(self) -> None:
        with mock.patch.dict(os.environ, {ACTIVE_ENV: "0"}):
            self.assertFalse(telemetry.record("crash_reported", {"component": "api"}))
        with mock.patch.dict(os.environ, {DISABLE_ENV: "off"}):
            self.assertFalse(telemetry.record("crash_reported", {"component": "api"}))
        telemetry.write_settings(enabled=False, directory=self.dir)
        self.assertFalse(telemetry.record("crash_reported", {"component": "api"}))
        self.assertEqual(self.lines(), [])

    def test_linked_run_events_carry_the_case(self) -> None:
        telemetry.link_run_case("run-linked", "case-9")
        telemetry.record("run_started", {"actor": "web"}, run_id="run-linked")
        self.assertEqual(self.lines()[0]["case_hid"], hid("case", "case-9", self.dir))


class PrivacyGuardTests(TelemetryCase):
    def test_no_whitelisted_property_names_a_forbidden_data_class(self) -> None:
        for event, specs in EVENTS.items():
            for name in specs:
                self.assertFalse(FORBIDDEN_NAME_WORDS & set(name.split("_")), f"{event}.{name}")

    def test_path_like_and_free_text_values_never_reach_the_log(self) -> None:
        for event, specs in EVENTS.items():
            telemetry.record(event, {name: PATH_VALUE for name in specs} | {"path": PATH_VALUE, "query": "홍길동"}, tag=PATH_VALUE)
        log = self.raw_log()
        self.assertEqual(len(self.lines()), len(EVENTS))
        # ensure_ascii=True: any non-ASCII text would show up as a backslash escape.
        for fragment in ("\\", "/", "secret", "analyst", '"path"', '"query"'):
            self.assertNotIn(fragment, log)
        for line in self.lines():
            self.assertEqual(privacy_violations(line), [])

    def test_guard_flags_forbidden_names_paths_and_raw_ids(self) -> None:
        problems = privacy_violations({"props": {"file_name": "x", "artifact_type": "a/b"}, "run_hid": "run-1"})
        self.assertEqual(len(problems), 3)

    def test_export_refuses_a_log_line_that_fails_the_guard(self) -> None:
        telemetry.record("crash_reported", {"component": "api"})
        with (self.dir / "events-20000101.jsonl").open("w", encoding="utf-8") as handle:
            handle.write(json.dumps({"ts": "2000-01-01T00:00:00+00:00", "event": "x", "props": {"path": PATH_VALUE}}) + "\n")
        with self.assertRaises(TelemetryExportError):
            export_bundle(self.dir.parent / "bundle", source_dir=self.dir)

    def test_export_bundle_has_events_and_manifest_without_salt(self) -> None:
        telemetry.record("crash_reported", {"component": "api"})
        manifest = export_bundle(self.dir.parent / "bundle", source_dir=self.dir)
        self.assertEqual(manifest["event_count"], 1)
        self.assertEqual(sorted(p.name for p in (self.dir.parent / "bundle").iterdir()), ["events.jsonl", "manifest.json"])

    def test_query_shape_keeps_only_the_shape_of_a_search(self) -> None:
        self.assertEqual(
            query_shape(parse_query("홍길동 계약서")),
            {"term_count": 2, "term_len_bucket": "1-9", "script": "hangul", "category": "keyword", "scope": "all", "from_keyword_pack": False},
        )
        self.assertEqual(query_shape(parse_query("/ab+c/"))["category"], "regex")
        self.assertEqual(query_shape(parse_query("sha256:" + "a" * 64))["category"], "hash")
        self.assertEqual(query_shape(parse_query("kim@example.com"))["category"], "email")


class RunProgressTelemetryTests(TelemetryCase):
    def test_run_lifecycle_emits_stage_provider_and_finish_events(self) -> None:
        progress = RunProgress(self.dir.parent / "out", heartbeat_interval=0, run_id="job-1")
        progress.start(stage="prepare")
        progress.complete_stage("prepare")
        progress.provider_running("windows.prefetch")
        progress.provider_finished("windows.prefetch", status="error", artifact_count=0, parser_error_count=3)
        progress.finish()
        names = [line["event"] for line in self.lines()]
        self.assertEqual(names, ["run_stage_completed", "provider_finished", "run_finished"])
        provider = self.lines()[1]["props"]
        self.assertEqual((provider["status"], provider["parser_error_count"]), ("failed", 3))
        self.assertEqual(self.lines()[2]["props"]["parser_error_total"], 3)
        self.assertEqual({line["run_hid"] for line in self.lines()}, {hid("run", "job-1", self.dir)})

    def test_failed_run_records_the_error_class_not_its_message(self) -> None:
        progress = RunProgress(self.dir.parent / "out", heartbeat_interval=0, run_id="job-2")
        progress.start(stage="artifacts")
        progress.fail(OSError(f"cannot read {PATH_VALUE}"))
        [line] = self.lines()
        self.assertEqual(line["props"]["error_class"], "OSError")
        self.assertNotIn("secret", self.raw_log())
