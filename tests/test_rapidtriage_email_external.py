from __future__ import annotations

import contextlib
import io
import json
import os
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
        self.assertEqual(payload["evidence_manifest"]["manifest_version"], "email-external-parser-evidence-manifest-v1")
        self.assertIn("manifest_sha256", payload["evidence_manifest"])
        self.assertIn("email_external_tool_available", payload["commercial_uplift_evidence"]["failed_or_blocked_checks"])
        self.assertEqual(payload["forensic_review"]["review_profile"], "email_external_parser_review_profile")

    def test_email_external_parse_records_exports_when_tool_runs(self) -> None:
        def fake_runner(command, **_kwargs):
            export_dir = Path(command[command.index("-o") + 1])
            export_dir.mkdir(parents=True, exist_ok=True)
            (export_dir / "Inbox").mkdir()
            (export_dir / "Inbox" / "message.eml").write_text(
                "Message-ID: <exported@example.test>\n"
                "From: alice@example.test\n"
                "To: bob@example.test\n"
                "Subject: Exported\n"
                "\n"
                "Body",
                encoding="utf-8",
            )
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
        self.assertEqual(payload["summary"]["parsed_message_candidate_count"], 1)
        self.assertTrue(payload["summary"]["ready_for_trusted_diff"])
        self.assertIn("command_argv_sha256", payload["execution"])
        self.assertIn("stdout_sha256", payload["execution"])
        self.assertIn("export_inventory_sha256", payload["evidence_manifest"])
        self.assertIn("export_review_profile_sha256", payload["evidence_manifest"])
        self.assertEqual(
            payload["forensic_review"]["export_review_profile_hash"],
            payload["export_review_profile"]["profile_sha256"],
        )
        self.assertEqual(payload["export_review_profile"]["profile_version"], "email-external-export-review-profile-v1")
        self.assertEqual(payload["export_review_profile"]["message_candidate_count"], 1)
        self.assertEqual(payload["export_review_profile"]["folder_candidates"], ["Inbox"])
        self.assertEqual(
            payload["export_review_profile"]["message_samples"][0]["headers"]["message_id"],
            "<exported@example.test>",
        )
        self.assertEqual(
            payload["export_review_profile"]["message_samples"][0]["source_viewer_locator"]["viewer"],
            "external-email-export-file",
        )
        self.assertIn("email_external_trusted_diff_ready", payload["commercial_uplift_evidence"]["passed_checks"])

    def test_email_external_parse_profiles_exported_mbox_messages(self) -> None:
        def fake_runner(command, **_kwargs):
            export_dir = Path(command[command.index("-o") + 1])
            export_dir.mkdir(parents=True, exist_ok=True)
            (export_dir / "mailbox.mbox").write_text(
                "From alice@example.test Mon Apr 01 00:00:00 2024\n"
                "Message-ID: <m1@example.test>\n"
                "From: alice@example.test\n"
                "To: bob@example.test\n"
                "Subject: First\n"
                "\n"
                "Body 1\n"
                "\n"
                "From bob@example.test Mon Apr 01 00:01:00 2024\n"
                "Message-ID: <m2@example.test>\n"
                "From: bob@example.test\n"
                "To: alice@example.test\n"
                "Subject: Re: First\n"
                "\n"
                "Body 2\n",
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "mailbox.ost"
            source.write_bytes(b"!BDNost fixture")

            payload = run_email_external_parse(
                source_path=source,
                output_dir=root / "out",
                preferred_tool="readpst",
                tool_resolver=lambda tool: f"/usr/bin/{tool}" if tool == "readpst" else None,
                command_runner=fake_runner,
            )

        review = payload["export_review_profile"]
        self.assertEqual(review["message_candidate_count"], 2)
        self.assertEqual(review["message_samples"][0]["headers"]["subject"], "First")
        self.assertEqual(review["message_samples"][1]["headers"]["message_id"], "<m2@example.test>")
        self.assertFalse(review["validation"]["commercial_grade"])
        self.assertIn("trusted-libpff-readpst-outlook-diff-required", review["validation"]["blockers"])

    @unittest.skipIf(os.name == "nt", "POSIX shell script cannot stand in for an external parser tool on Windows")
    def test_email_external_parse_supports_absolute_preferred_tool(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "message.msg"
            source.write_bytes(bytes.fromhex("d0cf11e0a1b11ae1") + b"msg fixture")
            tool = root / "fake-msg-tool"
            tool.write_text(
                "#!/bin/sh\n"
                "mkdir -p \"$2\"\n"
                "printf 'Subject: Absolute Tool\\n\\nBody' > \"$2/absolute.eml\"\n",
                encoding="utf-8",
            )
            tool.chmod(0o755)

            payload = run_email_external_parse(
                source_path=source,
                output_dir=root / "out",
                preferred_tool=str(tool),
                tool_resolver=lambda _tool: None,
            )

        self.assertEqual(payload["status"], "complete")
        self.assertEqual(payload["selected_tool"]["path"], str(tool.resolve()))
        self.assertEqual(payload["selected_tool"]["tool"], str(tool))
        self.assertEqual(payload["tool_availability_matrix"][0]["family"], "custom")
        self.assertEqual(payload["summary"]["export_file_count"], 1)

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
