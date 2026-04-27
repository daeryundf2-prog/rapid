from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import build_parser, main


class RapidTriageMobileExportTests(unittest.TestCase):
    def test_parser_exposes_mobile_export_collector_kind(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices
        help_text = commands["artifacts"].format_help()

        self.assertIn("mobile-export", help_text)

    def test_mobile_export_collects_vendor_csv_and_json_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            write_mobile_export_fixtures(root)
            output = root / "mobile-artifacts.json"

            exit_code = main(["artifacts", str(root), "--kind", "mobile-export", "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["kind"], "mobile-export")
            self.assertEqual(payload["provider"]["name"], "mobile-export-artifacts")
            artifact_types = {artifact["artifact_type"] for artifact in payload["artifacts"]}
            self.assertEqual(
                artifact_types,
                {
                    "mobile-message",
                    "mobile-contact",
                    "mobile-call",
                    "mobile-app",
                    "mobile-file",
                    "mobile-export-source",
                },
            )

            message = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "mobile-message")
            self.assertEqual(message["details"]["source_tool"], "cellebrite")
            self.assertEqual(message["details"]["sender"], "+15550100")
            self.assertEqual(message["details"]["recipient"], "+15550200")
            self.assertIn("credential-or-otp", message["details"]["risk_flags"])
            self.assertIn("sha256", message["details"]["source_hashes"])
            self.assertIn("message_text_sha256", message["details"])

            app = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "mobile-app")
            self.assertEqual(app["details"]["source_tool"], "graykey")
            self.assertEqual(app["details"]["package"], "ai.openai.chatgpt")
            self.assertIn("ai-service-app", app["details"]["risk_flags"])

            source_rows = [artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "mobile-export-source"]
            self.assertGreaterEqual(len(source_rows), 3)


def write_mobile_export_fixtures(root: Path) -> None:
    cellebrite = root / "Cellebrite UFED" / "Messages.csv"
    cellebrite.parent.mkdir(parents=True)
    cellebrite.write_text(
        "\n".join(
            [
                "Timestamp,From,To,Body,Direction,Service",
                "2026-04-26T01:02:03Z,+15550100,+15550200,OTP password is 123456,outgoing,SMS",
            ]
        ),
        encoding="utf-8",
    )

    xry = root / "XRY" / "contacts_calls.json"
    xry.parent.mkdir(parents=True)
    xry.write_text(
        json.dumps(
            {
                "contacts": [{"Display Name": "Alice Example", "Phone Number": "+15550100", "Email": "alice@example.com"}],
                "calls": [{"Date": "2026-04-26T02:00:00Z", "Phone Number": "+15550200", "Call Type": "missed"}],
            }
        ),
        encoding="utf-8",
    )

    graykey = root / "GrayKey" / "apps_files.json"
    graykey.parent.mkdir(parents=True)
    graykey.write_text(
        json.dumps(
            [
                {"App Name": "ChatGPT", "Package Name": "ai.openai.chatgpt", "Version": "2.0"},
                {"File Path": "/private/var/mobile/Containers/Data/Application/Documents/export.db", "SHA256": "a" * 64},
            ]
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    unittest.main()
