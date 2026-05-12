from __future__ import annotations

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from rapidtriage.artifacts.email_external import run_email_external_parse, select_email_external_tool
from rapidtriage.cli import build_parser, main


class RapidTriageEmailExternalParserTests(unittest.TestCase):
    def test_email_external_parse_blocks_when_tool_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "mailbox.pst"
            source.write_bytes(b"pst fixture")

            payload = run_email_external_parse(source_path=source, output_dir=root / "out", tool_resolver=lambda _tool: None)

            self.assertTrue(Path(payload["outputs"]["json"]).is_file())
            self.assertTrue(Path(payload["outputs"]["markdown"]).is_file())

        self.assertEqual(payload["status"], "blocked")
        self.assertFalse(payload["selected_tool"]["available"])
        self.assertFalse(payload["summary"]["native_decode_attempted"])
        self.assertIn("sha256", payload["source"]["hashes"])

    def test_email_external_parse_records_exports_when_tool_runs(self) -> None:
        def fake_runner(command, **_kwargs):
            export_dir = Path(command[command.index("-o") + 1])
            export_dir.mkdir(parents=True, exist_ok=True)
            (export_dir / "message.eml").write_text("Subject: Exported\n\nBody", encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "mailbox.pst"
            source.write_bytes(b"pst fixture")

            payload = run_email_external_parse(
                source_path=source,
                output_dir=root / "out",
                preferred_tool="readpst",
                tool_resolver=lambda tool: f"/usr/bin/{tool}" if tool == "readpst" else None,
                command_runner=fake_runner,
            )

        self.assertEqual(payload["status"], "complete")
        self.assertTrue(payload["selected_tool"]["available"])
        self.assertEqual(payload["summary"]["export_file_count"], 1)
        self.assertTrue(payload["summary"]["ready_for_trusted_diff"])

    def test_email_external_overwrite_removes_stale_exports(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "mailbox.pst"
            source.write_bytes(b"pst fixture")
            output_dir = root / "out"
            stale_export = output_dir / "export" / "stale.eml"
            stale_export.parent.mkdir(parents=True)
            stale_export.write_text("stale", encoding="utf-8")

            payload = run_email_external_parse(
                source_path=source,
                output_dir=output_dir,
                overwrite=True,
                tool_resolver=lambda _tool: None,
            )

            self.assertFalse(stale_export.exists())
            self.assertEqual(payload["status"], "blocked")
            self.assertEqual(payload["summary"]["export_file_count"], 0)

    def test_email_external_cli_emits_json(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["email-external-parse", "mailbox.pst", "--output-dir", "out"])
        self.assertEqual(args.command, "email-external-parse")

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "mailbox.pst"
            source.write_bytes(b"pst fixture")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["email-external-parse", str(source), "--output-dir", str(root / "out"), "--json"])
            payload = json.loads(stdout.getvalue())

        self.assertEqual(exit_code, 0)
        self.assertIn(payload["status"], {"blocked", "failed", "complete"})

    def test_email_external_cli_returns_nonzero_when_selected_tool_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "mailbox.pst"
            source.write_bytes(b"pst fixture")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "email-external-parse",
                        str(source),
                        "--output-dir",
                        str(root / "out"),
                        "--preferred-tool",
                        "false",
                        "--json",
                    ]
                )
            payload = json.loads(stdout.getvalue())

        self.assertEqual(exit_code, 1)
        self.assertEqual(payload["status"], "failed")

    def test_select_email_external_tool_prefers_available_tool(self) -> None:
        selected = select_email_external_tool("pst", preferred_tool="readpst", tool_resolver=lambda tool: f"/bin/{tool}")

        self.assertEqual(selected["tool"], "readpst")
        self.assertTrue(selected["available"])


if __name__ == "__main__":
    unittest.main()
