from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path

from rapidtriage.cli import build_parser, main


class RapidTriageGenericDocumentsTests(unittest.TestCase):
    def test_parser_exposes_generic_documents_collector_kind(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices
        help_text = commands["artifacts"].format_help()

        self.assertIn("generic-documents", help_text)

    def test_generic_documents_collects_sticky_notes_and_local_llm_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            sticky_dir = root / "Users" / "Alice" / "Packages" / "Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe"
            sticky_dir.mkdir(parents=True)
            sticky_db = sticky_dir / "plum.sqlite"
            connection = sqlite3.connect(sticky_db)
            with connection:
                connection.execute(
                    "CREATE TABLE Note (Text TEXT, IsDeleted INTEGER, CreatedAt INTEGER, UpdatedAt INTEGER, Account TEXT)"
                )
                connection.execute(
                    "INSERT INTO Note VALUES (?, ?, ?, ?, ?)",
                    ("VPN password review with OTP token", 1, 1710000000, 1710000060, "alice@example.com"),
                )
                connection.execute("CREATE TABLE Fragments (BlobValue BLOB)")
                connection.execute(
                    "INSERT INTO Fragments VALUES (?)",
                    (b"Archived sticky note: deleted seed phrase review for bob@example.com",),
                )

            llm_dir = root / "Users" / "Alice" / ".ollama" / "models"
            llm_dir.mkdir(parents=True)
            (llm_dir / "mistral.gguf").write_bytes(b"GGUF test model bytes")
            chatgpt_dir = root / "Users" / "Alice" / "AppData" / "Roaming" / "OpenAI" / "ChatGPT"
            chatgpt_dir.mkdir(parents=True)
            chatgpt_db = chatgpt_dir / "conversations.sqlite"
            ai_connection = sqlite3.connect(chatgpt_db)
            with ai_connection:
                ai_connection.execute("CREATE TABLE messages (role TEXT, content TEXT, created_at INTEGER)")
                ai_connection.execute("INSERT INTO messages VALUES ('user', 'Summarize incident timeline', 1710000000)")
            suspicious_doc = root / "Users" / "Alice" / "Documents" / "macro-template-report.docx"
            suspicious_doc.parent.mkdir(parents=True)
            write_suspicious_ooxml_document(suspicious_doc)
            output = root / "generic-artifacts.json"

            exit_code = main(["artifacts", str(root), "--kind", "generic-documents", "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            artifact_types = {artifact["artifact_type"] for artifact in payload["artifacts"]}
            self.assertIn("sticky-note", artifact_types)
            self.assertIn("sticky-note-recovery-candidate", artifact_types)
            self.assertIn("local-llm-artifact", artifact_types)
            self.assertIn("desktop-ai-app-artifact", artifact_types)
            self.assertIn("desktop-ai-conversation-candidate", artifact_types)
            self.assertIn("document-metadata-risk", artifact_types)

            doc_risk = next(
                artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "document-metadata-risk"
            )
            self.assertEqual(doc_risk["details"]["document_family"], "docx")
            self.assertIn("Alice Analyst", doc_risk["details"]["author_candidates"])
            self.assertTrue(doc_risk["details"]["macro_profile"]["macro_present"])
            self.assertIn("document-macro-present", doc_risk["details"]["risk_flags"])
            self.assertIn("document-external-reference-candidate", doc_risk["details"]["risk_flags"])
            self.assertEqual(
                doc_risk["details"]["external_reference_candidates"][0]["target"],
                "https://example.invalid/template.dotm",
            )
            self.assertIn("sha256", doc_risk["details"]["source_hashes"])

            sticky = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "sticky-note")
            self.assertEqual(sticky["details"]["source_table"], "Note")
            self.assertTrue(sticky["details"]["is_deleted"])
            self.assertIn("possible-sensitive-note", sticky["details"]["risk_flags"])
            self.assertEqual(sticky["details"]["sticky_note_schema_profile"]["candidate_note_table_count"], 1)
            self.assertEqual(sticky["details"]["sticky_note_review_profile"]["deleted_state"], "deleted-or-recovered-candidate")
            self.assertIn("sticky-note-account-or-email-candidate", sticky["details"]["risk_flags"])
            self.assertIn("sha256", sticky["details"]["source_hashes"])
            self.assertNotIn("VPN password review", json.dumps(sticky["details"]["text_sha256"]))

            recovery_candidates = [
                artifact
                for artifact in payload["artifacts"]
                if artifact["artifact_type"] == "sticky-note-recovery-candidate"
            ]
            recovered = next(
                artifact
                for artifact in recovery_candidates
                if "bob@example.com" in json.dumps(artifact["details"], ensure_ascii=False)
            )
            self.assertEqual(recovered["details"]["recovery_method"], "bounded-sqlite-string-scan")
            self.assertIn("bob@example.com", recovered["details"]["sticky_note_review_profile"]["email_candidates"])
            self.assertIn("possible-sensitive-note", recovered["details"]["risk_flags"])

            llm = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "local-llm-artifact")
            self.assertEqual(llm["details"]["product_hint"], "Ollama")
            self.assertEqual(llm["details"]["artifact_role"], "model-file")
            self.assertIn("local-model-file", llm["details"]["risk_flags"])

            desktop_ai = next(
                artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "desktop-ai-app-artifact"
            )
            self.assertEqual(desktop_ai["details"]["product_hint"], "ChatGPT Desktop")
            self.assertEqual(desktop_ai["details"]["artifact_role"], "application-database")
            self.assertEqual(desktop_ai["details"]["database_profile"]["database_open_status"], "opened")
            self.assertEqual(desktop_ai["details"]["database_profile"]["tables"][0]["name"], "messages")
            self.assertEqual(desktop_ai["details"]["message_table_candidates"][0]["row_count"], 1)
            self.assertIn("ai-message-table-candidate", desktop_ai["details"]["risk_flags"])

            ai_message = next(
                artifact
                for artifact in payload["artifacts"]
                if artifact["artifact_type"] == "desktop-ai-conversation-candidate"
            )
            self.assertEqual(ai_message["details"]["direction"], "user-prompt-candidate")
            self.assertEqual(ai_message["details"]["source_table"], "messages")
            self.assertEqual(
                ai_message["details"]["desktop_ai_conversation_review_profile"]["product_hint"],
                "ChatGPT Desktop",
            )
            self.assertIn("ai-user-prompt-candidate", ai_message["details"]["risk_flags"])


def write_suspicious_ooxml_document(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types />")
        archive.writestr("word/document.xml", "<w:document xmlns:w='urn:test'>Investigation notes</w:document>")
        archive.writestr("word/vbaProject.bin", b"fake-vba-project")
        archive.writestr(
            "docProps/core.xml",
            """
            <cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
                xmlns:dc="http://purl.org/dc/elements/1.1/"
                xmlns:dcterms="http://purl.org/dc/terms/">
                <dc:creator>Alice Analyst</dc:creator>
                <cp:lastModifiedBy>Bob Reviewer</cp:lastModifiedBy>
                <dcterms:created>2026-05-01T10:00:00Z</dcterms:created>
                <dcterms:modified>2026-05-02T11:00:00Z</dcterms:modified>
            </cp:coreProperties>
            """,
        )
        archive.writestr(
            "word/_rels/document.xml.rels",
            """
            <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
              <Relationship Id="rId1"
                Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"
                Target="https://example.invalid/template.dotm"
                TargetMode="External" />
            </Relationships>
            """,
        )


if __name__ == "__main__":
    unittest.main()
