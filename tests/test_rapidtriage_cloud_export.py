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
            self.assertEqual(payload["summary"]["artifact_count"], 3)
            artifact_types = {artifact["artifact_type"] for artifact in payload["artifacts"]}
            self.assertEqual(artifact_types, {"cloud-location", "cloud-activity", "cloud-account"})

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


if __name__ == "__main__":
    unittest.main()
