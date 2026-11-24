"""F8: output generation/collection times are timezone-aware UTC, like event times."""

from __future__ import annotations

import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.core.artifacts import run_artifact_collection
from rapidtriage.core.docs import run_docs_search
from rapidtriage.core.files import run_files_scan
from rapidtriage.core.run.checkpoints import record_run_checkpoint
from rapidtriage.core.timeline import build_timeline_report, run_timeline


class GeneratedAtUtcTests(unittest.TestCase):
    def assert_utc_now(self, value: object) -> None:
        self.assertIsInstance(value, str)
        parsed = dt.datetime.fromisoformat(str(value))
        self.assertIsNotNone(parsed.tzinfo, f"{value!r} has no UTC offset")
        self.assertEqual(parsed.utcoffset(), dt.timedelta(0), value)
        self.assertLess(abs(dt.datetime.now(dt.timezone.utc) - parsed), dt.timedelta(minutes=5))

    def test_command_payloads_record_utc_generation_time(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "evidence"
            root.mkdir()
            (root / "note.txt").write_text("synthetic keyword", encoding="utf-8")
            artifacts = run_artifact_collection(root, kind="windows-registry", use_cache=False)
            files = run_files_scan(root, categories=["documents"])
            docs = run_docs_search(root, ["keyword"])
            artifacts_path = Path(tmp) / "artifacts.json"
            artifacts_path.write_text(json.dumps(artifacts), encoding="utf-8")
            timeline = run_timeline(root=root, artifacts_inputs=[artifacts_path])

        for payload in (artifacts, files, docs, timeline):
            with self.subTest(command=payload.get("command")):
                self.assert_utc_now(payload["generated_at"])
        report_line = next(line for line in build_timeline_report(timeline).splitlines() if line.startswith("- Generated at:"))
        self.assertTrue(report_line.endswith("+00:00`"), report_line)

    def test_run_checkpoint_records_utc_time(self) -> None:
        records: list[dict[str, object]] = []
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "stage.json"
            output.write_text("{}", encoding="utf-8")
            record_run_checkpoint(records, "files", output, reused=False)

        self.assert_utc_now(records[-1]["recorded_at"])


if __name__ == "__main__":
    unittest.main()
