from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

from rapidtriage.cli import build_parser, main


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def run_cli(*args: str) -> tuple[int, str]:
    stream = io.StringIO()
    with redirect_stdout(stream):
        exit_code = main(list(args))
    return exit_code, stream.getvalue()


class RapidTriageCaseCommandTests(unittest.TestCase):
    def make_files_payload(self) -> dict[str, Any]:
        return {
            "command": "files",
            "generated_at": "2024-03-03T00:00:00+00:00",
            "root": "/cases/case-001",
            "filters": {
                "categories": [],
                "name_contains": [],
                "path_contains": [],
                "extensions": [],
                "modified_after": None,
                "modified_before": None,
                "limit": 0,
            },
            "summary": {
                "scanned_file_count": 1,
                "candidate_count": 1,
                "category_counts": {"documents": 1},
                "newest_modified_at": "2024-03-02T09:10:11+00:00",
                "oldest_modified_at": "2024-03-02T09:10:11+00:00",
            },
            "candidates": [
                {
                    "modified_at": "2024-03-02T09:10:11+00:00",
                    "path": "/cases/case-001/Users/alice/Documents/incident-notes.txt",
                    "name": "incident-notes.txt",
                    "extension": ".txt",
                    "size": 128,
                    "modified_epoch": 1709370611,
                    "categories": ["documents"],
                    "reasons": {"categories": ["documents"]},
                }
            ],
        }

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
            files_json = root / "files.json"

            timeline_event = {
                "timestamp": "2024-03-01T08:45:00+00:00",
                "source": "artifacts",
                "event_type": "browser-download",
                "path": "/cases/case-001/Users/alice/Downloads/evidence.zip",
                "input_file": "/cases/case-001/rapidtriage-artifacts-browser.json",
                "summary": "Browser download: evidence.zip",
                "details": {"provider": "chrome"},
            }
            file_payload = self.make_files_payload()
            file_candidate = file_payload["candidates"][0]

            write_json(
                timeline_json,
                {
                    "command": "timeline",
                    "generated_at": "2024-03-03T00:00:00+00:00",
                    "root": "/cases/case-001",
                    "inputs": {"files": [], "docs": [], "artifacts": []},
                    "summary": {
                        "input_file_count": 0,
                        "event_count": 1,
                        "source_counts": {"artifacts": 1},
                        "event_type_counts": {"browser-download": 1},
                        "earliest_event_at": "2024-03-01T08:45:00+00:00",
                        "latest_event_at": "2024-03-01T08:45:00+00:00",
                    },
                    "events": [timeline_event],
                },
            )
            write_json(files_json, file_payload)

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
                str(files_json),
                "--pointer",
                "/candidates/0",
                "--bookmark-id",
                "bm-file-1",
                "--tag",
                "files",
                "--note",
                "Review the underlying file.",
            )

            self.assertEqual(exit_code, 0, output)

            payload = json.loads(case_json.read_text(encoding="utf-8"))
            self.assertEqual(len(payload["bookmarks"]), 2)

            second = payload["bookmarks"][1]
            self.assertEqual(second["bookmark_id"], "bm-file-1")
            self.assertEqual(second["source_command"], "files")
            self.assertEqual(Path(second["source_file"]).resolve(), files_json.resolve())
            self.assertEqual(second["source_pointer"], "/candidates/0")
            self.assertEqual(second["tags"], ["files"])
            self.assertEqual(second["note"], "Review the underlying file.")
            self.assertEqual(second["item"], file_candidate)
            self.assertEqual(second["source_path"], file_candidate["path"])
            self.assertEqual(second["source_summary"], file_candidate["name"])
            self.assertEqual(second["source_timestamp"], file_candidate["modified_at"])

            exit_code, show_output = run_cli("case", str(case_json), "--show")

            self.assertEqual(exit_code, 0, show_output)
            self.assertIn('"case_id": "case-001"', show_output)
            self.assertIn('"bookmark_id": "bm-timeline-1"', show_output)
            self.assertIn('"bookmark_id": "bm-file-1"', show_output)

    def test_case_command_rejects_compare_sources_until_compare_command_exists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            case_json = root / "case-bookmarks.json"
            compare_json = root / "compare.json"

            write_json(
                compare_json,
                {
                    "command": "compare",
                    "generated_at": "2024-03-03T00:00:00+00:00",
                    "results": [
                        {
                            "timestamp": "2024-03-02T09:10:11+00:00",
                            "path": "/cases/case-001/Users/alice/Documents/incident-notes.txt",
                            "summary": "Only present in source A",
                            "status": "only-in-left",
                        }
                    ],
                },
            )

            stderr = io.StringIO()
            with redirect_stderr(stderr), self.assertRaises(SystemExit) as exc:
                main(
                    [
                        "case",
                        str(case_json),
                        "--source",
                        str(compare_json),
                        "--pointer",
                        "/results/0",
                    ]
                )

            self.assertEqual(exc.exception.code, 2)
            self.assertIn("bookmark source command 'compare' is not implemented yet", stderr.getvalue())

    def test_case_command_rejects_non_row_pointer_for_source_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            case_json = root / "case-bookmarks.json"
            files_json = root / "files.json"

            write_json(files_json, self.make_files_payload())

            stderr = io.StringIO()
            with redirect_stderr(stderr), self.assertRaises(SystemExit) as exc:
                main(
                    [
                        "case",
                        str(case_json),
                        "--source",
                        str(files_json),
                        "--pointer",
                        "/results/0",
                    ]
                )

            self.assertEqual(exc.exception.code, 2)
            self.assertIn("files bookmarks require a row pointer", stderr.getvalue())

    def test_case_command_rejects_source_payloads_that_fail_schema_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            case_json = root / "case-bookmarks.json"
            files_json = root / "files.json"

            invalid_payload = self.make_files_payload()
            invalid_payload["candidates"][0].pop("reasons")
            write_json(files_json, invalid_payload)

            stderr = io.StringIO()
            with redirect_stderr(stderr), self.assertRaises(SystemExit) as exc:
                main(
                    [
                        "case",
                        str(case_json),
                        "--source",
                        str(files_json),
                        "--pointer",
                        "/candidates/0",
                    ]
                )

            self.assertEqual(exc.exception.code, 2)
            self.assertIn("files source JSON failed schema validation", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
