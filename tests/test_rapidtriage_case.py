from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import build_parser, main
from tests.test_rapidtriage_timeline import build_timeline_fixture


class RapidTriageCaseBookmarkTests(unittest.TestCase):
    def test_parser_exposes_case_subcommand(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices

        self.assertIn("case", commands)
        help_text = commands["case"].format_help()
        self.assertIn("--source", help_text)
        self.assertIn("--pointer", help_text)
        self.assertIn("--show", help_text)

    def test_case_command_saves_and_loads_bookmarks(self) -> None:
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


if __name__ == "__main__":
    unittest.main()
