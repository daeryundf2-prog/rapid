from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from rapidtriage.core.case_db.schema import SCHEMA_VERSION, apply_schema
from rapidtriage.core.crash import sanitize_context
from rapidtriage.core.extract import run_extract


def _files_payload(root: Path, *relative_paths: str) -> dict[str, object]:
    return {
        "command": "files",
        "root": str(root),
        "candidates": [{"path": relative} for relative in relative_paths],
    }


class ExtractDestinationSymlinkTests(unittest.TestCase):
    def test_symlinked_destination_parent_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "evidence-root"
            (root / "docs").mkdir(parents=True)
            (root / "docs" / "note.txt").write_text("case note", encoding="utf-8")
            outside = base / "outside"
            outside.mkdir()
            output_dir = base / "extract-out"
            output_dir.mkdir()
            (output_dir / "docs").symlink_to(outside, target_is_directory=True)
            input_json = base / "files.json"
            input_json.write_text(
                json.dumps(_files_payload(root, "docs/note.txt")), encoding="utf-8"
            )

            result = run_extract(input_json, output_dir)

            self.assertFalse((outside / "note.txt").exists())
            skipped = result.get("skipped") or result.get("skipped_entries") or []
            reasons = {entry.get("reason") for entry in skipped}
            self.assertIn("destination-outside-output-dir", reasons)

    def test_symlinked_destination_file_is_not_written_through(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "evidence-root"
            root.mkdir()
            (root / "note.txt").write_text("case note", encoding="utf-8")
            outside_target = base / "outside-target.txt"
            outside_target.write_text("do not overwrite", encoding="utf-8")
            output_dir = base / "extract-out"
            output_dir.mkdir()
            (output_dir / "note.txt").symlink_to(outside_target)
            input_json = base / "files.json"
            input_json.write_text(
                json.dumps(_files_payload(root, "note.txt")), encoding="utf-8"
            )

            result = run_extract(input_json, output_dir, overwrite=True)

            self.assertEqual(outside_target.read_text(encoding="utf-8"), "do not overwrite")
            skipped = result.get("skipped") or result.get("skipped_entries") or []
            reasons = {entry.get("reason") for entry in skipped}
            self.assertIn("destination-outside-output-dir", reasons)


class RecursiveDiagnosticRedactionTests(unittest.TestCase):
    def test_nested_sensitive_keys_are_redacted(self) -> None:
        sanitized = sanitize_context(
            {
                "request": {"api_token": "secret-value", "path": "/tmp/x"},
                "items": [{"session_cookie": "abc"}, {"name": "plain"}],
                "note": "visible",
            }
        )
        self.assertEqual(sanitized["request"]["api_token"], "<redacted>")
        self.assertEqual(sanitized["request"]["path"], "/tmp/x")
        self.assertEqual(sanitized["items"][0]["session_cookie"], "<redacted>")
        self.assertEqual(sanitized["items"][1]["name"], "plain")
        self.assertEqual(sanitized["note"], "visible")

    def test_deeply_nested_context_is_bounded(self) -> None:
        value: object = {"leaf": "x"}
        for _ in range(20):
            value = {"child": value}
        sanitized = sanitize_context({"deep": value})
        self.assertIn("<truncated-depth>", json.dumps(sanitized))

    def test_long_strings_still_truncate(self) -> None:
        sanitized = sanitize_context({"blob": "x" * 900})
        self.assertTrue(str(sanitized["blob"]).endswith("...<truncated>"))


class _CountingConnection:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection
        self.executescript_calls = 0

    def execute(self, *args, **kwargs):
        return self._connection.execute(*args, **kwargs)

    def executescript(self, script: str):
        self.executescript_calls += 1
        return self._connection.executescript(script)


class SchemaInitFastPathTests(unittest.TestCase):
    def test_current_schema_skips_ddl_replay_but_migrates_columns(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            db_path = Path(temp) / "case.db"
            connection = sqlite3.connect(db_path)
            connection.row_factory = sqlite3.Row
            counted = _CountingConnection(connection)

            apply_schema(counted)
            self.assertEqual(counted.executescript_calls, 1)

            apply_schema(counted)
            self.assertEqual(counted.executescript_calls, 1, "DDL replayed for current schema")

            connection.execute("ALTER TABLE review_mark DROP COLUMN assignee")
            apply_schema(counted)
            self.assertEqual(counted.executescript_calls, 2, "missing migration column did not re-run DDL")
            columns = {row["name"] for row in connection.execute("PRAGMA table_info(review_mark)")}
            self.assertIn("assignee", columns)
            version = connection.execute(
                "SELECT value FROM schema_info WHERE key = 'schema_version'"
            ).fetchone()
            self.assertEqual(int(version["value"]), SCHEMA_VERSION)
            connection.close()


if __name__ == "__main__":
    unittest.main()
