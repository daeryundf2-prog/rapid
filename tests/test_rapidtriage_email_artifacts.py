from __future__ import annotations

import json
import tempfile
import unittest
from email.message import EmailMessage
from pathlib import Path

from rapidtriage.cli import build_parser, main
from rapidtriage.artifacts.email import build_email_trusted_diff, email_core_accuracy_gates


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
            eml_gate = eml["details"]["core_accuracy_gates"][0]
            self.assertEqual(eml_gate["gap_id"], "#36")
            self.assertIn("mailbox/message source profile detection", eml_gate["satisfied_checks"])
            self.assertIn("mailbox strategy profile", eml_gate["satisfied_checks"])
            self.assertIn("email expansion citation manifest", eml_gate["satisfied_checks"])
            self.assertIn("message header/body/attachment inventory", eml_gate["satisfied_checks"])
            self.assertIn("PST/OST native limitation warning", eml_gate["satisfied_checks"])
            self.assertIn("threading/dedup validation warning", eml_gate["satisfied_checks"])
            self.assertIn("legal privilege boundary", eml_gate["satisfied_checks"])
            eml_uplift = eml["details"]["commercial_uplift_evidence"]
            self.assertEqual(eml_uplift["batch_id"], "commercial-uplift-036-040")
            self.assertEqual(eml_uplift["item_numbers"], [36])
            self.assertEqual(eml_uplift["functional_priority_profile"]["item_number"], 49)
            self.assertEqual(eml_uplift["functional_priority_profile"]["batch_id"], "commercial-uplift-046-050")
            eml_manifest = eml["details"]["email_expansion_citation_manifest"]
            self.assertEqual(eml_manifest["manifest_version"], "email-expansion-citation-manifest-v1")
            self.assertEqual(eml_manifest["item_number"], 49)
            self.assertEqual(eml_manifest["gap_id"], "#49")
            self.assertEqual(len(eml_manifest["manifest_sha256"]), 64)
            self.assertEqual(
                eml["details"]["email_expansion_citation_manifest_hash"],
                eml_manifest["manifest_sha256"],
            )
            self.assertEqual(eml_manifest["message_citation_count"], 1)
            self.assertEqual(eml_manifest["attachment_citation_count"], 1)
            self.assertIn("row_hash", eml_manifest["message_citations"][0])
            self.assertEqual(
                eml_uplift["functional_priority_profile"]["implemented_controls"]["citation_manifest_hash"],
                eml_manifest["manifest_sha256"],
            )
            self.assertIn(
                "email-expansion-citation-manifest-emitted",
                eml_uplift["functional_priority_profile"]["passed_validation_check_ids"],
            )
            self.assertEqual(
                eml["details"]["email_mailbox_strategy_profile"]["selected_track"],
                "mime-message-parse-known-answer-validation",
            )
            self.assertEqual(
                eml_uplift["email_mailbox_strategy_profile"]["selected_track"],
                "mime-message-parse-known-answer-validation",
            )
            self.assertIn(
                "email-known-answer-corpus-not-attached",
                eml_uplift["functional_priority_profile"]["failed_validation_check_ids"],
            )
            self.assertIn("source-hash-and-basic-parse", eml_uplift["passed_validation_matrix_ids"])
            self.assertIn("thread-dedup-validation", eml_uplift["failed_validation_matrix_ids"])
            self.assertEqual(
                eml_uplift["reportability_decision"]["decision"],
                "do-not-report-mailbox-as-native-or-deleted-complete",
            )
            self.assertEqual(
                eml_uplift["reportability_decision"]["allowed_use"],
                "email-message-or-mailbox-inventory-triage-pivot",
            )
            self.assertIn(
                "mailbox-known-answer-corpus-not-attached",
                eml_uplift["reportability_decision"]["blockers"],
            )
            self.assertIn(
                "email-mailbox-trusted-diff-required",
                eml_uplift["reportability_decision"]["blockers"],
            )
            self.assertNotIn("trusted email mailbox export diff pass", eml_gate["satisfied_checks"])

            emlx = next(artifact for artifact in messages if artifact["details"]["source_format"] == "emlx")
            self.assertEqual(emlx["details"]["email_format_profile"]["family"], "apple-mail-message")

            maildir = next(artifact for artifact in messages if artifact["details"]["source_format"] == "maildir")
            self.assertEqual(maildir["details"]["subject"], "maildir fixture")

            pst = next(artifact for artifact in mailboxes if artifact["details"]["source_format"] == "pst")
            self.assertIn("alice@example.test", pst["details"]["email_candidates"])
            self.assertIn("mailbox-container-candidate", pst["details"]["risk_flags"])
            self.assertFalse(pst["details"]["validation_checks"]["native_mailbox_decoding_available"])
            self.assertTrue(pst["details"]["validation_checks"]["mapi_container_review_profile_emitted"])
            self.assertTrue(pst["details"]["validation_checks"]["bounded_candidate_inventory_present"])
            self.assertIn("#36", pst["details"]["commercial_gap_ids"])
            self.assertEqual(pst["details"]["forensic_review"]["gap_id"], "#36")
            self.assertEqual(pst["details"]["email_format_profile"]["support_tier"], "bounded-string-inventory")
            self.assertIn("mapi-native-object-decode", {item["id"] for item in pst["details"]["email_issue_matrix"]})
            pst_gate = pst["details"]["core_accuracy_gates"][0]
            self.assertEqual(pst_gate["gap_id"], "#36")
            self.assertIn("MAPI container bounded review profile", pst_gate["satisfied_checks"])
            self.assertIn("bounded mailbox candidate inventory", pst_gate["satisfied_checks"])
            self.assertIn("PST/OST native limitation warning", pst_gate["satisfied_checks"])
            self.assertIn("mailbox strategy profile", pst_gate["satisfied_checks"])
            self.assertIn("email expansion citation manifest", pst_gate["satisfied_checks"])
            mapi_profile = pst["details"]["mapi_container_review_profile"]
            self.assertEqual(mapi_profile["profile_version"], "mapi-container-review-v1")
            self.assertEqual(mapi_profile["native_object_decode_status"], "not-implemented")
            self.assertGreaterEqual(mapi_profile["folder_path_candidate_count"], 1)
            self.assertGreaterEqual(mapi_profile["attachment_name_candidate_count"], 1)
            self.assertEqual(mapi_profile["deleted_item_recovery_status"], "not-performed")
            self.assertEqual(
                pst["details"]["email_mailbox_strategy_profile"]["selected_track"],
                "pst-libpff-or-outlook-export-diff-required",
            )
            self.assertTrue(pst["details"]["email_mailbox_strategy_profile"]["bounded_inventory_only"])
            pst_uplift = pst["details"]["commercial_uplift_evidence"]
            self.assertEqual(pst_uplift["functional_priority_profile"]["item_number"], 49)
            pst_manifest = pst["details"]["email_expansion_citation_manifest"]
            self.assertEqual(pst_manifest["manifest_version"], "email-expansion-citation-manifest-v1")
            self.assertEqual(pst_manifest["item_number"], 49)
            self.assertEqual(len(pst_manifest["manifest_sha256"]), 64)
            self.assertGreaterEqual(pst_manifest["candidate_citation_count"], 3)
            self.assertEqual(pst_manifest["candidate_citations"][0]["source_viewer_locator"]["viewer"], "bounded-container-string")
            self.assertIn(
                "bounded-container-candidate-citations-emitted",
                pst_uplift["functional_priority_profile"]["passed_validation_check_ids"],
            )
            self.assertIn(
                "pst-ost-msg-native-object-decode-not-implemented",
                pst_uplift["functional_priority_profile"]["failed_validation_check_ids"],
            )
            self.assertIn("native-container-object-decode", pst_uplift["failed_validation_matrix_ids"])
            self.assertEqual(pst_uplift["large_data_controls"]["container_scan_limit"], 16 * 1024 * 1024)
            self.assertTrue(pst_uplift["large_data_controls"]["mapi_container_review_profile_present"])
            self.assertIn(
                "native-mapi-container-decoding-not-validated",
                pst_uplift["reportability_decision"]["blockers"],
            )

    def test_email_trusted_diff_controls_core_accuracy_gate(self) -> None:
        rapid = [
            {
                "source_format": "eml",
                "message_id": "<m1@example.test>",
                "subject": "Case mail",
                "from": "alice@example.test",
                "to": "bob@example.test",
                "date": "Mon, 1 Apr 2024 00:00:00 +0000",
                "body_sha256": "abc",
                "attachment_count": 1,
            }
        ]
        trusted = [dict(rapid[0])]

        diff = build_email_trusted_diff(rapid, trusted, trusted_tool="eml-ground-truth")

        self.assertEqual(diff["status"], "pass")
        gate = email_core_accuracy_gates(
            source_format="eml",
            source_hashes={"sha256": "source-hash"},
            details={
                **rapid[0],
                "source_path": "fixture.eml",
                "validation_checks": {"headers_parsed": True},
                "email_trusted_diff": diff,
            },
        )[0]
        self.assertIn("trusted email mailbox export diff pass", gate["satisfied_checks"])

        mismatch = build_email_trusted_diff(
            rapid,
            [{**rapid[0], "subject": "Changed"}],
            trusted_tool="eml-ground-truth",
        )
        self.assertEqual(mismatch["status"], "fail")
        self.assertEqual(mismatch["blocker_id"], "email-mailbox-trusted-diff-required")
        self.assertEqual(mismatch["mismatched_fields"][0]["field"], "subject")


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
            + b"IPM.Note\x00invoice.pdf\x00Inbox\x00Deleted Items\x00"
            + "secret mailbox keyword".encode("utf-16le")
        )


if __name__ == "__main__":
    unittest.main()
