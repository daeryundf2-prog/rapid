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
            self.assertGreaterEqual(len(messages), 4)
            self.assertGreaterEqual(len(mailboxes), 3)

            eml = next(artifact for artifact in messages if artifact["details"]["source_format"] == "eml")
            self.assertEqual(eml["details"]["subject"], "Password review")
            self.assertEqual(eml["details"]["attachment_count"], 1)
            self.assertIn("sensitive-email-content", eml["details"]["risk_flags"])
            self.assertFalse(eml["details"]["commercial_grade_ready"])
            self.assertIn("#36", eml["details"]["email_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(eml["details"]["forensic_review"]["gap_id"], "#36")
            self.assertFalse(eml["details"]["email_native_capabilities"]["native_pst_ost_msg_object_decode"])
            self.assertEqual(eml["details"]["email_format_profile"]["family"], "internet-message")
            self.assertIn("auth-signature-crypto", {item["id"] for item in eml["details"]["email_issue_matrix"]})

            emlx = next(artifact for artifact in messages if artifact["details"]["source_format"] == "emlx")
            self.assertEqual(emlx["details"]["email_format_profile"]["family"], "apple-mail-message")

            maildir = next(artifact for artifact in messages if artifact["details"]["source_format"] == "maildir")
            self.assertEqual(maildir["details"]["subject"], "maildir fixture")

            pst = next(artifact for artifact in mailboxes if artifact["details"]["source_format"] == "pst")
            self.assertIn("alice@example.test", pst["details"]["email_candidates"])
            self.assertIn("mailbox-container-candidate", pst["details"]["risk_flags"])
            self.assertFalse(pst["details"]["validation_checks"]["native_mailbox_decoding_available"])
            self.assertIn("#36", pst["details"]["commercial_gap_ids"])
            self.assertEqual(pst["details"]["forensic_review"]["gap_id"], "#36")
            self.assertEqual(pst["details"]["email_format_profile"]["support_tier"], "bounded-string-inventory")
            self.assertIn("mapi-native-object-decode", {item["id"] for item in pst["details"]["email_issue_matrix"]})


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

    emlx = EmailMessage()
    emlx["From"] = "apple@example.test"
    emlx["To"] = "bob@example.test"
    emlx["Subject"] = "emlx fixture"
    emlx.set_content("apple mail body")
    emlx_bytes = emlx.as_bytes()
    (root / "message.emlx").write_bytes(str(len(emlx_bytes)).encode("ascii") + b"\n" + emlx_bytes)

    maildir_message = EmailMessage()
    maildir_message["From"] = "maildir@example.test"
    maildir_message["To"] = "bob@example.test"
    maildir_message["Subject"] = "maildir fixture"
    maildir_message.set_content("maildir body")
    maildir_cur = root / "Maildir" / "cur"
    maildir_cur.mkdir(parents=True)
    (maildir_cur / "1714093200.M1P1Q1.host:2,S").write_bytes(maildir_message.as_bytes())

    for name in ("archive.pst", "offline.ost", "message.msg"):
        (root / name).write_bytes(
            b"Subject: Container Fixture\r\n"
            b"alice@example.test\x00bob@example.test\x00"
            + "secret mailbox keyword".encode("utf-16le")
        )


if __name__ == "__main__":
    unittest.main()
