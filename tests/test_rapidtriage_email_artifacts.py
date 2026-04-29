from __future__ import annotations

import json
import tempfile
import unittest
from email.message import EmailMessage
from pathlib import Path

from rapidtriage.cli import build_parser, main


class RapidTriageEmailArtifactsTests(unittest.TestCase):
    def test_parser_exposes_email_collector_kind(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices
        self.assertIn("email", commands["artifacts"].format_help())

    def test_email_collector_parses_eml_mbox_and_mailbox_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            write_email_fixture(root)
            output = root / "email-artifacts.json"

            exit_code = main(["artifacts", str(root), "--kind", "email", "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["kind"], "email")
            artifact_types = {artifact["artifact_type"] for artifact in payload["artifacts"]}
            self.assertEqual(artifact_types, {"email-message", "email-mailbox"})
            messages = [artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "email-message"]
            mailboxes = [artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "email-mailbox"]
            self.assertGreaterEqual(len(messages), 2)
            self.assertGreaterEqual(len(mailboxes), 3)

            eml = next(artifact for artifact in messages if artifact["details"]["source_format"] == "eml")
            self.assertEqual(eml["details"]["subject"], "Password review")
            self.assertEqual(eml["details"]["attachment_count"], 1)
            self.assertIn("sensitive-email-content", eml["details"]["risk_flags"])
            self.assertFalse(eml["details"]["commercial_grade_ready"])
            self.assertIn("#36", eml["details"]["email_report_grade_assessment"]["commercial_gap_ids"])
            self.assertFalse(eml["details"]["email_native_capabilities"]["native_pst_ost_msg_object_decode"])

            pst = next(artifact for artifact in mailboxes if artifact["details"]["source_format"] == "pst")
            self.assertIn("alice@example.test", pst["details"]["email_candidates"])
            self.assertIn("mailbox-container-candidate", pst["details"]["risk_flags"])
            self.assertFalse(pst["details"]["validation_checks"]["native_mailbox_decoding_available"])
            self.assertIn("#36", pst["details"]["commercial_gap_ids"])


def write_email_fixture(root: Path) -> None:
    message = EmailMessage()
    message["From"] = "alice@example.test"
    message["To"] = "bob@example.test"
    message["Subject"] = "Password review"
    message["Date"] = "Mon, 1 Apr 2024 00:00:00 +0000"
    message.set_content("password email body")
    message.add_attachment(b"invoice bytes", maintype="application", subtype="pdf", filename="invoice.pdf")
    (root / "message.eml").write_bytes(message.as_bytes())

    (root / "mailbox.mbox").write_text(
        "From alice@example.test Mon Apr 01 00:00:00 2024\n"
        "From: alice@example.test\n"
        "To: bob@example.test\n"
        "Subject: mbox fixture\n"
        "\n"
        "secret mailbox keyword\n",
        encoding="utf-8",
    )

    for name in ("archive.pst", "offline.ost", "message.msg"):
        (root / name).write_bytes(
            b"Subject: Container Fixture\r\n"
            b"alice@example.test\x00bob@example.test\x00"
            + "secret mailbox keyword".encode("utf-16le")
        )


if __name__ == "__main__":
    unittest.main()
