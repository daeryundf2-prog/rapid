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
        self.assertIn("--review-status", case_help)
        self.assertIn("--include-in-report", case_help)
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
                "--review-status",
                "needs-review",
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
            self.assertEqual(first["reference"]["command"], "timeline")
            self.assertEqual(Path(first["reference"]["file"]).resolve(), timeline_json.resolve())
            self.assertEqual(first["reference"]["pointer"], "/events/0")
            self.assertIsInstance(first["reference"]["stable_key"], str)
            self.assertTrue(first["reference"]["stable_key"].startswith("bookmark-"))
            self.assertEqual(first["tags"], ["timeline", "download"])
            self.assertEqual(first["note"], "Review this artifact first.")
            self.assertEqual(first["review"]["status"], "needs-review")
            self.assertEqual(first["review"]["include_in_report"], False)
            self.assertIsInstance(first["review"]["reviewed_at"], str)
            self.assertEqual(first["review_history"][0]["action"], "created")
            self.assertEqual(first["review_history"][0]["status"], "needs-review")
            self.assertEqual(first["snapshot"]["path"], timeline_event["path"])
            self.assertIsNone(first["snapshot"]["hash"])
            self.assertEqual(first["snapshot"]["artifact_key"], timeline_event["event_type"])
            self.assertEqual(first["snapshot"]["summary"], timeline_event["summary"])
            self.assertEqual(first["snapshot"]["timestamp"], timeline_event["timestamp"])
            self.assertNotIn("item", first)

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
                "--review-status",
                "relevant",
                "--include-in-report",
            )

            self.assertEqual(exit_code, 0, output)

            payload = json.loads(case_json.read_text(encoding="utf-8"))
            self.assertEqual(len(payload["bookmarks"]), 2)

            second = payload["bookmarks"][1]
            self.assertEqual(second["bookmark_id"], "bm-file-1")
            self.assertEqual(second["reference"]["command"], "files")
            self.assertEqual(Path(second["reference"]["file"]).resolve(), files_json.resolve())
            self.assertEqual(second["reference"]["pointer"], "/candidates/0")
            self.assertTrue(second["reference"]["stable_key"].startswith("bookmark-"))
            self.assertEqual(second["tags"], ["files"])
            self.assertEqual(second["note"], "Review the underlying file.")
            self.assertEqual(second["review"]["status"], "relevant")
            self.assertEqual(second["review"]["include_in_report"], True)
            self.assertEqual(second["review_history"][0]["action"], "created")
            self.assertEqual(second["review_history"][0]["include_in_report"], True)
            self.assertEqual(second["snapshot"]["path"], file_candidate["path"])
            self.assertIsNone(second["snapshot"]["hash"])
            self.assertIsNone(second["snapshot"]["artifact_key"])
            self.assertEqual(second["snapshot"]["summary"], file_candidate["name"])
            self.assertEqual(second["snapshot"]["timestamp"], file_candidate["modified_at"])
            self.assertNotIn("item", second)

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
                "escalated",
                "--note",
                "Escalated after second review.",
                "--review-status",
                "needs-review",
            )

            self.assertEqual(exit_code, 0, output)
            payload = json.loads(case_json.read_text(encoding="utf-8"))
            self.assertEqual(len(payload["bookmarks"]), 2)
            updated_second = payload["bookmarks"][1]
            self.assertEqual(updated_second["review"]["status"], "needs-review")
            self.assertEqual(updated_second["review"]["include_in_report"], True)
            self.assertEqual(updated_second["tags"], ["files", "escalated"])
            self.assertEqual(updated_second["note"], "Escalated after second review.")
            self.assertEqual(len(updated_second["review_history"]), 2)
            self.assertEqual(updated_second["review_history"][1]["action"], "updated")
            self.assertIn("review.status", updated_second["review_history"][1]["changed_fields"])
            self.assertIn("tags", updated_second["review_history"][1]["changed_fields"])
            self.assertEqual(payload["summary"]["review_revision_count"], 3)

            exit_code, output = run_cli(
                "case",
                str(case_json),
                "--source",
                str(timeline_json),
                "--pointer",
                "/events/0",
                "--bookmark-id",
                "bm-timeline-1",
                "--review-status",
                "excluded",
            )

            self.assertEqual(exit_code, 0, output)
            payload = json.loads(case_json.read_text(encoding="utf-8"))
            excluded_first = payload["bookmarks"][0]
            self.assertEqual(excluded_first["review"]["status"], "excluded")
            self.assertEqual(excluded_first["review_history"][-1]["status"], "excluded")
            self.assertIn("excluded", payload["summary"]["review_status_counts"])

            exit_code, show_output = run_cli("case", str(case_json), "--show")

            self.assertEqual(exit_code, 0, show_output)
            self.assertIn('"case_id": "case-001"', show_output)
            self.assertIn('"bookmark_id": "bm-timeline-1"', show_output)
            self.assertIn('"bookmark_id": "bm-file-1"', show_output)

    def test_case_command_accepts_compare_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            case_json = root / "case-bookmarks.json"
            compare_json = root / "compare.json"
            left = root / "before.txt"
            left.write_text("before", encoding="utf-8")

            write_json(
                compare_json,
                {
                    "command": "compare",
                    "generated_at": "2024-03-03T00:00:00+00:00",
                    "options": {
                        "left_label": "left",
                        "right_label": "right",
                    },
                    "inputs": {
                        "left": {
                            "label": "left",
                            "path": str(left),
                            "name": left.name,
                            "extension": ".txt",
                            "exists": True,
                            "is_file": True,
                            "is_dir": False,
                            "size": 6,
                            "modified_at": "2024-03-02T09:10:11+00:00",
                            "hashes": {},
                        },
                        "right": {
                            "label": "right",
                            "path": str(root / "after.txt"),
                            "name": "after.txt",
                            "extension": ".txt",
                            "exists": False,
                            "is_file": False,
                            "is_dir": False,
                            "size": None,
                            "modified_at": None,
                            "hashes": {},
                        },
                    },
                    "summary": {
                        "result_count": 1,
                        "status_counts": {"only-in-left": 1},
                    },
                    "results": [
                        {
                            "comparison_id": "compare-0001",
                            "timestamp": "2024-03-02T09:10:11+00:00",
                            "path": str(left),
                            "left_path": str(left),
                            "right_path": str(root / "after.txt"),
                            "summary": "Only present in source A",
                            "status": "only-in-left",
                            "fields": [],
                            "diff": {},
                            "left": {
                                "label": "left",
                                "path": str(left),
                                "name": left.name,
                                "extension": ".txt",
                                "exists": True,
                                "is_file": True,
                                "is_dir": False,
                                "size": 6,
                                "modified_at": "2024-03-02T09:10:11+00:00",
                                "hashes": {},
                            },
                            "right": {
                                "label": "right",
                                "path": str(root / "after.txt"),
                                "name": "after.txt",
                                "extension": ".txt",
                                "exists": False,
                                "is_file": False,
                                "is_dir": False,
                                "size": None,
                                "modified_at": None,
                                "hashes": {},
                            },
                        }
                    ],
                },
            )

            exit_code, output = run_cli(
                "case",
                str(case_json),
                "--source",
                str(compare_json),
                "--pointer",
                "/results/0",
                "--tag",
                "compare",
                "--review-status",
                "needs-review",
            )

            self.assertEqual(exit_code, 0, output)
            payload = json.loads(case_json.read_text(encoding="utf-8"))
            bookmark = payload["bookmarks"][0]
            self.assertEqual(bookmark["reference"]["command"], "compare")
            self.assertEqual(bookmark["snapshot"]["path"], str(left))
            self.assertEqual(bookmark["snapshot"]["artifact_key"], "only-in-left")
            self.assertEqual(payload["summary"]["source_command_counts"]["compare"], 1)

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
