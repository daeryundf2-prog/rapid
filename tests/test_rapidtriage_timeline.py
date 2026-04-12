from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rapidtriage.cli import build_parser, main
from tests.test_rapidtriage_run import write_minimal_docx, write_minimal_pdf
from tests.windows_artifact_fixtures import build_windows_artifact_fixture


TIMESTAMP_KEYS = ("timestamp", "event_at", "observed_at", "occurred_at", "modified_at")
SOURCE_KEYS = ("source", "source_kind", "event_source", "event_type")
TIMESTAMP_DETAIL_KEYS = ("last_visited_at", "started_at", "ended_at")
PATH_KEYS = ("path", "source_path", "evidence_path", "artifact_path", "target_path")


def set_mtime(path: Path, value: datetime) -> None:
    timestamp = value.timestamp()
    os.utime(path, (timestamp, timestamp))


def build_timeline_fixture(root: Path) -> dict[str, Path]:
    build_windows_artifact_fixture(root)

    user_root = root / "Users" / "alice"
    documents = user_root / "Documents"
    documents.mkdir(parents=True, exist_ok=True)
    note = documents / "incident-notes.txt"
    note.write_text("incident timeline browser history download evidence", encoding="utf-8")
    set_mtime(note, datetime(2024, 1, 1, 9, 0, 0, tzinfo=timezone.utc))

    report = documents / "witness-summary.docx"
    write_minimal_docx(report, "incident browser history and recent files summary")
    set_mtime(report, datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc))

    pdf = documents / "evidence-review.pdf"
    write_minimal_pdf(pdf, "download timeline recent activity artifact review")
    set_mtime(pdf, datetime(2024, 3, 1, 8, 45, 0, tzinfo=timezone.utc))

    downloads = user_root / "Downloads"
    downloads.mkdir(parents=True, exist_ok=True)
    archive = downloads / "evidence-bundle.zip"
    archive.write_bytes(b"PK\x03\x04fixture")
    set_mtime(archive, datetime(2024, 2, 10, 7, 15, 0, tzinfo=timezone.utc))

    executable = downloads / "payload-installer.exe"
    executable.write_bytes(b"MZ\x90\x00")
    set_mtime(executable, datetime(2024, 2, 11, 12, 0, 0, tzinfo=timezone.utc))

    return {
        "note": note,
        "report": report,
        "pdf": pdf,
        "archive": archive,
        "executable": executable,
    }


class RapidTriageTimelineTests(unittest.TestCase):
    def test_parser_exposes_timeline_subcommand(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices

        self.assertIn("timeline", commands)

        timeline_help = commands["timeline"].format_help()
        self.assertIn("--output", timeline_help)
        self.assertIn("--report", timeline_help)

    def test_timeline_command_writes_sorted_json_and_markdown_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output = Path(tmp_dir) / "rapidtriage-timeline.json"
            report = Path(tmp_dir) / "rapidtriage-timeline.md"
            root.mkdir(parents=True, exist_ok=True)
            fixture = build_timeline_fixture(root)

            exit_code = main(["timeline", str(root), "--output", str(output), "--report", str(report)])

            self.assertEqual(exit_code, 0)
            self.assertTrue(output.is_file())
            self.assertTrue(report.is_file())

            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["command"], "timeline")
            self.assertEqual(Path(payload["root"]).resolve(), root.resolve())

            events = payload.get("events")
            self.assertIsInstance(events, list)
            self.assertGreaterEqual(len(events), 5)

            event_times = [self._event_timestamp(event) for event in events]
            self.assertEqual(event_times, sorted(event_times), "timeline events must be chronological")

            event_sources = {self._event_source(event) for event in events}
            self.assertTrue({"files", "docs", "artifacts"}.issubset(event_sources))

            event_paths = {self._event_path(event) for event in events if self._event_path(event)}
            self.assertIn(str(fixture["note"].resolve()), event_paths)
            self.assertTrue(
                any(path.endswith("Incident Notes.docx.lnk") for path in event_paths),
                "expected a recent-files artifact event in the timeline output",
            )

            summary = payload.get("summary")
            self.assertIsInstance(summary, dict)
            self.assertEqual(summary.get("event_count"), len(events))

            report_text = report.read_text(encoding="utf-8").lower()
            self.assertIn("timeline", report_text)
            self.assertIn("incident-notes.txt", report_text)
            self.assertIn("browser", report_text)

    def _event_timestamp(self, event: dict[str, Any]) -> datetime:
        raw = self._event_field(event, TIMESTAMP_KEYS, label="timestamp")
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _event_source(self, event: dict[str, Any]) -> str:
        value = self._event_field(event, SOURCE_KEYS, label="source")
        normalized = value.lower().replace("_", "-")
        if "artifact" in normalized:
            return "artifacts"
        if normalized in {"file", "files"}:
            return "files"
        if normalized in {"doc", "docs", "document", "documents"}:
            return "docs"
        self.fail(f"unexpected event source value: {value!r}")

    def _event_path(self, event: dict[str, Any]) -> str | None:
        for key in PATH_KEYS:
            value = event.get(key)
            if isinstance(value, str) and value:
                return value
        for nested_key in ("source", "details"):
            nested = event.get(nested_key)
            if not isinstance(nested, dict):
                continue
            for key in PATH_KEYS:
                value = nested.get(key)
                if isinstance(value, str) and value:
                    return value
        return None

    def _event_field(self, event: dict[str, Any], keys: tuple[str, ...], *, label: str) -> str:
        for key in keys:
            value = event.get(key)
            if isinstance(value, str) and value:
                return value
        nested_source = event.get("source")
        if isinstance(nested_source, dict):
            for key in keys:
                value = nested_source.get(key)
                if isinstance(value, str) and value:
                    return value
        nested_details = event.get("details")
        if label == "timestamp" and isinstance(nested_details, dict):
            for key in TIMESTAMP_KEYS + TIMESTAMP_DETAIL_KEYS:
                value = nested_details.get(key)
                if isinstance(value, str) and value:
                    return value
        if label == "source":
            for nested_key in ("source", "details"):
                nested = event.get(nested_key)
                if not isinstance(nested, dict):
                    continue
                for key in ("kind", "type", "name", "source"):
                    value = nested.get(key)
                    if isinstance(value, str) and value:
                        return value
        self.fail(f"timeline event missing {label}: {event!r}")


if __name__ == "__main__":
    unittest.main()
