from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from rapidtriage.cli import build_parser, main
from tests.test_rapidtriage_timeline import build_timeline_fixture


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def run_cli(*args: str) -> tuple[int, str]:
    stream = io.StringIO()
    with contextlib.redirect_stdout(stream):
        exit_code = main(list(args))
    return exit_code, stream.getvalue()


class RapidTriageCaseCommandTests(unittest.TestCase):
    def test_parser_exposes_case_subcommand_and_options(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices

        self.assertIn("case", commands)

        case_help = commands["case"].format_help()
        self.assertIn("--source", case_help)
        self.assertIn("--pointer", case_help)
        self.assertIn("--bookmark-id", case_help)
        self.assertIn("--tag", case_help)
        self.assertIn("--note", case_help)
        self.assertIn("--show", case_help)

    def test_case_command_creates_case_file_and_shows_saved_bookmarks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            case_json = root / "case-bookmarks.json"
            timeline_json = root / "timeline.json"
            compare_json = root / "compare.json"

            timeline_event = {
                "timestamp": "2024-03-01T08:45:00+00:00",
                "source": "artifacts",
                "event_type": "browser-download",
                "path": "/cases/case-001/Users/alice/Downloads/evidence.zip",
                "summary": "Browser download: evidence.zip",
                "details": {"provider": "chrome"},
            }
            compare_entry = {
                "timestamp": "2024-03-02T09:10:11+00:00",
                "path": "/cases/case-001/Users/alice/Documents/incident-notes.txt",
                "summary": "Only present in source A",
                "status": "only-in-left",
            }

            write_json(
                timeline_json,
                {
                    "command": "timeline",
                    "generated_at": "2024-03-03T00:00:00+00:00",
                    "root": "/cases/case-001",
                    "summary": {"event_count": 1},
                    "events": [timeline_event],
                },
            )
            write_json(
                compare_json,
                {
                    "command": "compare",
                    "generated_at": "2024-03-03T00:00:00+00:00",
                    "results": [compare_entry],
                },
            )

            exit_code, output = run_cli(
                "case",
                str(case_json),
                "--case-id",
                "case-001",
                "--title",
                "Case 001",
                "--source",
                str(timeline_json),
                "--pointer",
                "/events/0",
                "--bookmark-id",
                "bm-timeline-1",
                "--tag",
                "timeline",
                "--tag",
                "download",
                "--note",
                "Review this artifact first.",
            )

            self.assertEqual(exit_code, 0, output)
            self.assertTrue(case_json.is_file())

            payload = json.loads(case_json.read_text(encoding="utf-8"))
            self.assertEqual(payload["command"], "case")
            self.assertEqual(payload["case_id"], "case-001")
            self.assertEqual(payload["title"], "Case 001")
            self.assertIsInstance(payload["summary"], dict)
            self.assertEqual(len(payload["bookmarks"]), 1)

            first = payload["bookmarks"][0]
            self.assertEqual(first["bookmark_id"], "bm-timeline-1")
            self.assertEqual(first["source_command"], "timeline")
            self.assertEqual(Path(first["source_file"]).resolve(), timeline_json.resolve())
            self.assertEqual(first["source_pointer"], "/events/0")
            self.assertEqual(first["tags"], ["timeline", "download"])
            self.assertEqual(first["note"], "Review this artifact first.")
            self.assertEqual(first["item"], timeline_event)
            self.assertEqual(first["source_path"], timeline_event["path"])
            self.assertEqual(first["source_summary"], timeline_event["summary"])
            self.assertEqual(first["source_timestamp"], timeline_event["timestamp"])

            exit_code, output = run_cli(
                "case",
                str(case_json),
                "--source",
                str(compare_json),
                "--pointer",
                "/results/0",
                "--bookmark-id",
                "bm-compare-1",
                "--tag",
                "compare",
                "--note",
                "Cross-check with timeline.",
            )

            self.assertEqual(exit_code, 0, output)

            payload = json.loads(case_json.read_text(encoding="utf-8"))
            self.assertEqual(len(payload["bookmarks"]), 2)

            second = payload["bookmarks"][1]
            self.assertEqual(second["bookmark_id"], "bm-compare-1")
            self.assertEqual(second["source_command"], "compare")
            self.assertEqual(Path(second["source_file"]).resolve(), compare_json.resolve())
            self.assertEqual(second["source_pointer"], "/results/0")
            self.assertEqual(second["tags"], ["compare"])
            self.assertEqual(second["note"], "Cross-check with timeline.")
            self.assertEqual(second["item"], compare_entry)
            self.assertEqual(second["source_path"], compare_entry["path"])
            self.assertEqual(second["source_summary"], compare_entry["summary"])
            self.assertEqual(second["source_timestamp"], compare_entry["timestamp"])

            exit_code, show_output = run_cli("case", str(case_json), "--show")

            self.assertEqual(exit_code, 0, show_output)
            self.assertIn('"case_id": "case-001"', show_output)
            self.assertIn('"bookmark_id": "bm-timeline-1"', show_output)
            self.assertIn('"bookmark_id": "bm-compare-1"', show_output)

    def test_case_command_saves_and_updates_timeline_bookmark(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            root.mkdir(parents=True, exist_ok=True)
            build_timeline_fixture(root)

            timeline_json = Path(tmp_dir) / "rapidtriage-timeline.json"
            case_json = Path(tmp_dir) / "incident-case.json"

            self.assertEqual(main(["timeline", str(root), "--output", str(timeline_json)]), 0)
            self.assertEqual(
                main(
                    [
                        "case",
                        str(case_json),
                        "--case-id",
                        "incident-001",
                        "--title",
                        "Incident 001",
                        "--source",
                        str(timeline_json),
                        "--pointer",
                        "/events/0",
                        "--tag",
                        "priority",
                        "--tag",
                        "browser",
                        "--note",
                        "Review this event",
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "case",
                        str(case_json),
                        "--source",
                        str(timeline_json),
                        "--pointer",
                        "/events/0",
                        "--tag",
                        "follow-up",
                        "--note",
                        "Updated note",
                    ]
                ),
                0,
            )

            payload = json.loads(case_json.read_text(encoding="utf-8"))
            self.assertEqual(payload["command"], "case")
            self.assertEqual(payload["case_id"], "incident-001")
            self.assertEqual(payload["title"], "Incident 001")
            self.assertEqual(payload["summary"]["bookmark_count"], 1)
            self.assertEqual(payload["summary"]["tagged_bookmark_count"], 1)
            self.assertEqual(payload["summary"]["source_command_counts"], {"timeline": 1})
            self.assertEqual(payload["summary"]["tag_counts"], {"browser": 1, "follow-up": 1, "priority": 1})

            bookmark = payload["bookmarks"][0]
            self.assertEqual(bookmark["source_command"], "timeline")
            self.assertEqual(bookmark["source_pointer"], "/events/0")
            self.assertEqual(bookmark["source_summary"], bookmark["summary"])
            self.assertEqual(bookmark["note"], "Updated note")
            self.assertEqual(bookmark["tags"], ["priority", "browser", "follow-up"])
            self.assertIsInstance(bookmark["item"], dict)
            self.assertTrue(bookmark["summary"])

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(main(["case", str(case_json), "--show"]), 0)
            loaded = json.loads(stdout.getvalue())
            self.assertEqual(loaded, payload)
