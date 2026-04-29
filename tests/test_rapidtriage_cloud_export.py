from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import build_parser, main


class RapidTriageCloudExportTests(unittest.TestCase):
    def test_parser_exposes_cloud_export_collector_kind(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices
        help_text = commands["artifacts"].format_help()

        self.assertIn("cloud-export", help_text)

    def test_cloud_export_collects_google_location_activity_and_account_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            write_cloud_export_fixtures(root)
            output = root / "cloud-artifacts.json"

            exit_code = main(["artifacts", str(root), "--kind", "cloud-export", "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["kind"], "cloud-export")
            self.assertEqual(payload["provider"]["name"], "cloud-export-artifacts")
            self.assertEqual(payload["summary"]["artifact_count"], 7)
            artifact_types = {artifact["artifact_type"] for artifact in payload["artifacts"]}
            self.assertEqual(
                artifact_types,
                {"cloud-location", "cloud-activity", "cloud-account", "cloud-mail", "cloud-file", "cloud-message", "cloud-audit"},
            )

            location = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "cloud-location")
            self.assertEqual(location["details"]["latitude"], 37.422)
            self.assertEqual(location["details"]["longitude"], -122.0840575)
            self.assertIn("precise-location", location["details"]["risk_flags"])
            self.assertIn("sha256", location["details"]["source_hashes"])

            activity = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "cloud-activity")
            self.assertEqual(activity["details"]["title"], "Searched for incident response checklist")
            self.assertIn("Search", activity["details"]["products"])
            self.assertIn("user-activity", activity["details"]["risk_flags"])

            account = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "cloud-account")
            self.assertEqual(account["details"]["account_email"], "alice@example.com")
            self.assertIn("account-profile", account["details"]["risk_flags"])

            mail = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "cloud-mail")
            self.assertEqual(mail["details"]["service"], "gmail-takeout")
            self.assertEqual(mail["details"]["subject"], "Invoice password review")
            self.assertIn("sensitive-cloud-content", mail["details"]["risk_flags"])
            self.assertFalse(mail["details"]["commercial_grade_ready"])
            self.assertIn("#37", mail["details"]["cloud_report_grade_assessment"]["commercial_gap_ids"])
            self.assertFalse(mail["details"]["cloud_native_capabilities"]["provider_api_native_acquisition"])

            cloud_file = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "cloud-file")
            self.assertEqual(cloud_file["details"]["service"], "microsoft-onedrive")
            self.assertEqual(cloud_file["details"]["file_name"], "case.zip")
            self.assertIn("reviewable-document-or-archive", cloud_file["details"]["risk_flags"])
            self.assertIn("#39", cloud_file["details"]["commercial_gap_ids"])

            message = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "cloud-message")
            self.assertEqual(message["details"]["service"], "microsoft-teams")
            self.assertEqual(message["details"]["chat_id"], "chat-1")
            self.assertIn("cloud-message", message["details"]["risk_flags"])
            self.assertIn("#39", message["details"]["cloud_report_grade_assessment"]["commercial_gap_ids"])

            audit = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "cloud-audit")
            self.assertEqual(audit["details"]["service"], "microsoft-365")
            self.assertIn("identity-security-event", audit["details"]["risk_flags"])
            self.assertIn("#39", audit["details"]["commercial_gap_ids"])


def write_cloud_export_fixtures(root: Path) -> None:
    location = root / "Takeout" / "Location History" / "Records.json"
    location.parent.mkdir(parents=True)
    location.write_text(
        json.dumps(
            {
                "locations": [
                    {
                        "timestampMs": "1714093200000",
                        "latitudeE7": 374220000,
                        "longitudeE7": -1220840575,
                        "accuracy": 12,
                        "source": "GPS",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    activity = root / "Takeout" / "My Activity" / "Search" / "MyActivity.json"
    activity.parent.mkdir(parents=True)
    activity.write_text(
        json.dumps(
            [
                {
                    "time": "2026-04-26T01:02:03Z",
                    "title": "Searched for incident response checklist",
                    "products": ["Search"],
                    "details": [{"name": "From your device"}],
                }
            ]
        ),
        encoding="utf-8",
    )
    account = root / "Apple" / "Apple ID Account Information.json"
    account.parent.mkdir(parents=True)
    account.write_text(
        json.dumps({"email": "alice@example.com", "name": "Alice Example", "created": "2024-01-02T03:04:05Z"}),
        encoding="utf-8",
    )

    gmail = root / "Takeout" / "Mail" / "gmail-export.json"
    gmail.parent.mkdir(parents=True)
    gmail.write_text(
        json.dumps(
            [
                {
                    "date": "2026-04-26T04:00:00Z",
                    "from": "alice@example.com",
                    "to": "bob@example.com",
                    "subject": "Invoice password review",
                    "snippet": "Please review the invoice password.",
                    "messageId": "gmail-msg-1",
                }
            ]
        ),
        encoding="utf-8",
    )

    onedrive = root / "Microsoft 365" / "OneDrive" / "files.json"
    onedrive.parent.mkdir(parents=True)
    onedrive.write_text(
        json.dumps(
            [
                {
                    "id": "file-1",
                    "name": "case.zip",
                    "webUrl": "https://contoso-my.sharepoint.com/personal/alice/Documents/case.zip",
                    "size": 1234,
                    "lastModifiedDateTime": "2026-04-26T05:00:00Z",
                }
            ]
        ),
        encoding="utf-8",
    )

    teams = root / "Microsoft 365" / "Teams" / "messages.json"
    teams.parent.mkdir(parents=True)
    teams.write_text(
        json.dumps(
            [
                {
                    "createdDateTime": "2026-04-26T06:00:00Z",
                    "chatId": "chat-1",
                    "id": "teams-msg-1",
                    "from": "alice@example.com",
                    "messageText": "Incident response Teams message",
                }
            ]
        ),
        encoding="utf-8",
    )

    audit = root / "Microsoft 365" / "Audit" / "audit.json"
    audit.parent.mkdir(parents=True)
    audit.write_text(
        json.dumps(
            [
                {
                    "creationTime": "2026-04-26T07:00:00Z",
                    "operation": "UserLoggedIn",
                    "userId": "alice@example.com",
                    "ipAddress": "203.0.113.10",
                    "userAgent": "UnitTest",
                }
            ]
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    unittest.main()
