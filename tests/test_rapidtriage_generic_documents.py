from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
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
            output = root / "generic-artifacts.json"

            exit_code = main(["artifacts", str(root), "--kind", "generic-documents", "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            artifact_types = {artifact["artifact_type"] for artifact in payload["artifacts"]}
            self.assertIn("sticky-note", artifact_types)
            self.assertIn("local-llm-artifact", artifact_types)
            self.assertIn("desktop-ai-app-artifact", artifact_types)

            sticky = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "sticky-note")
            self.assertEqual(sticky["details"]["source_table"], "Note")
            self.assertTrue(sticky["details"]["is_deleted"])
            self.assertIn("possible-sensitive-note", sticky["details"]["risk_flags"])
            self.assertIn("sha256", sticky["details"]["source_hashes"])
            self.assertNotIn("VPN password review", json.dumps(sticky["details"]["text_sha256"]))

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


if __name__ == "__main__":
    unittest.main()
