from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import build_parser, main
from rapidtriage.artifacts.cloud import build_cloud_export_trusted_diff, cloud_core_accuracy_gates


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
            self.assertEqual(payload["summary"]["artifact_count"], 9)
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
            self.assertEqual(mail["details"]["forensic_review"]["gap_id"], "#37")
            self.assertFalse(mail["details"]["cloud_native_capabilities"]["provider_api_native_acquisition"])
            self.assertTrue(mail["details"]["cloud_provider_profile"]["known_profile"])
            self.assertIn("export-scope-captured", {item["id"] for item in mail["details"]["cloud_issue_matrix"]})
            google_gate = mail["details"]["core_accuracy_gates"][0]
            self.assertEqual(google_gate["gap_id"], "#37")
            self.assertIn("Google service/profile detection", google_gate["satisfied_checks"])
            self.assertIn("Google Takeout product matrix strategy", google_gate["satisfied_checks"])
            self.assertIn("Google Takeout product review profile", google_gate["satisfied_checks"])
            self.assertIn("Google Takeout row pivot inventory", google_gate["satisfied_checks"])
            self.assertIn("Gmail/Drive/Activity/Location normalization", google_gate["satisfied_checks"])
            self.assertIn("source hash and export-scope warning", google_gate["satisfied_checks"])
            self.assertIn("provider schema/timezone warning", google_gate["satisfied_checks"])
            self.assertIn("cloud export import manifest", google_gate["satisfied_checks"])
            self.assertIn("cloud export source locator", google_gate["satisfied_checks"])
            google_review = mail["details"]["google_takeout_review_profile"]
            self.assertEqual(google_review["profile_version"], "google-takeout-review-v1")
            self.assertEqual(google_review["product_family"], "gmail")
            self.assertTrue(google_review["primary_pivot_present"])
            self.assertIn("message_id", google_review["present_primary_pivots"])
            self.assertEqual(google_review["sidecar_merge_status"], "not-performed")
            self.assertTrue(mail["details"]["validation_checks"]["google_takeout_review_profile_emitted"])
            self.assertTrue(mail["details"]["validation_checks"]["google_takeout_row_pivot_present"])
            mail_uplift = mail["details"]["commercial_uplift_evidence"]
            cloud_manifest = mail["details"]["cloud_export_import_manifest"]
            self.assertEqual(cloud_manifest["manifest_version"], "cloud-export-import-manifest-v1")
            self.assertEqual(cloud_manifest["item_number"], 55)
            self.assertEqual(cloud_manifest["service"], "gmail-takeout")
            self.assertEqual(cloud_manifest["source_viewer_locator"]["viewer"], "cloud-provider-export-row")
            self.assertEqual(cloud_manifest["provider_review"]["product_or_workload_family"], "gmail")
            self.assertIn("message_id", cloud_manifest["row_pivots"])
            self.assertEqual(len(cloud_manifest["manifest_sha256"]), 64)
            self.assertEqual(mail["details"]["cloud_export_import_manifest_hash"], cloud_manifest["manifest_sha256"])
            self.assertEqual(mail_uplift["batch_id"], "commercial-uplift-036-040")
            self.assertEqual(mail_uplift["item_numbers"], [37])
            mail_profile = mail_uplift["functional_priority_profile"]
            self.assertEqual(mail_profile["item_number"], 55)
            self.assertEqual(mail_profile["batch_id"], "commercial-uplift-051-055")
            self.assertTrue(mail_profile["implemented_controls"]["google_takeout_gmail_drive_photos_location_inventory"])
            self.assertEqual(
                mail_profile["implemented_controls"]["cloud_export_import_manifest_hash"],
                cloud_manifest["manifest_sha256"],
            )
            self.assertIn("cloud-export-import-manifest-emitted", mail_profile["passed_validation_check_ids"])
            self.assertIn("cloud-export-source-locator-emitted", mail_profile["passed_validation_check_ids"])
            self.assertEqual(
                mail["details"]["cloud_provider_strategy_profile"]["selected_track"],
                "google-takeout-product-matrix-validation",
            )
            self.assertIn(
                "Gmail messages/MBOX or JSON exports",
                mail_uplift["cloud_provider_strategy_profile"]["provider_product_matrix"],
            )
            self.assertTrue(mail_uplift["large_data_controls"]["google_takeout_review_profile_present"])
            self.assertEqual(
                mail_uplift["large_data_controls"]["cloud_export_import_manifest_hash"],
                cloud_manifest["manifest_sha256"],
            )
            self.assertTrue(mail_uplift["large_data_controls"]["cloud_export_source_locator_present"])
            self.assertIn("provider-export-scope-not-verified", mail_profile["failed_validation_check_ids"])
            self.assertIn("source-hash-present", mail_uplift["passed_validation_matrix_ids"])
            self.assertIn("provider-scope-verified", mail_uplift["failed_validation_matrix_ids"])
            self.assertEqual(
                mail_uplift["reportability_decision"]["decision"],
                "do-not-report-google-takeout-as-product-matrix-complete",
            )
            self.assertEqual(
                mail_uplift["reportability_decision"]["allowed_use"],
                "google-export-triage-pivot",
            )
            self.assertIn(
                "provider-export-scope-not-verified",
                mail_uplift["reportability_decision"]["blockers"],
            )
            self.assertIn(
                "google-takeout-provider-diff-required",
                mail_uplift["reportability_decision"]["blockers"],
            )
            self.assertNotIn("trusted Google Takeout/provider diff pass", google_gate["satisfied_checks"])

            apple_gate = account["details"]["core_accuracy_gates"][0]
            self.assertEqual(apple_gate["gap_id"], "#38")
            self.assertIn("Apple/iCloud service profile detection", apple_gate["satisfied_checks"])
            self.assertIn("iCloud export scope strategy", apple_gate["satisfied_checks"])
            self.assertIn("iCloud account/file/photo review profile", apple_gate["satisfied_checks"])
            self.assertIn("iCloud row pivot inventory", apple_gate["satisfied_checks"])
            self.assertIn("account/file/photo metadata normalization", apple_gate["satisfied_checks"])
            self.assertIn("ADP/shared-album limitation warning", apple_gate["satisfied_checks"])
            self.assertIn("cloud export import manifest", apple_gate["satisfied_checks"])
            self.assertIn("cloud export source locator", apple_gate["satisfied_checks"])
            icloud_account_profile = account["details"]["icloud_export_review_profile"]
            self.assertEqual(icloud_account_profile["profile_version"], "icloud-export-review-v1")
            self.assertEqual(icloud_account_profile["product_family"], "account")
            self.assertTrue(icloud_account_profile["primary_pivot_present"])
            self.assertEqual(icloud_account_profile["advanced_data_protection_status"], "not-validated")
            self.assertTrue(account["details"]["validation_checks"]["icloud_export_review_profile_emitted"])
            self.assertTrue(account["details"]["validation_checks"]["icloud_row_pivot_present"])
            account_uplift = account["details"]["commercial_uplift_evidence"]
            self.assertEqual(account_uplift["item_numbers"], [38])
            account_manifest = account["details"]["cloud_export_import_manifest"]
            self.assertEqual(account_manifest["provider_review"]["product_or_workload_family"], "account")
            self.assertEqual(account_manifest["source_viewer_locator"]["viewer"], "cloud-provider-export-row")
            self.assertEqual(
                account["details"]["cloud_provider_strategy_profile"]["selected_track"],
                "icloud-export-account-photo-file-scope-validation",
            )
            self.assertIn("icloud-copy-limitations", account_uplift["failed_issue_matrix_ids"])
            self.assertTrue(account_uplift["large_data_controls"]["icloud_export_review_profile_present"])
            self.assertEqual(
                account_uplift["reportability_decision"]["allowed_use"],
                "icloud-export-triage-pivot",
            )

            icloud_photo = next(
                artifact
                for artifact in payload["artifacts"]
                if artifact["artifact_type"] == "cloud-file" and artifact["details"]["service"] == "apple-icloud-export"
            )
            self.assertEqual(icloud_photo["details"]["file_name"], "IMG_0001.JPG")
            self.assertEqual(icloud_photo["details"]["icloud_export_review_profile"]["product_family"], "icloud-photos")
            self.assertIn("file_name", icloud_photo["details"]["icloud_export_review_profile"]["present_primary_pivots"])
            self.assertIn("#38", icloud_photo["details"]["commercial_gap_ids"])

            cloud_file = next(
                artifact
                for artifact in payload["artifacts"]
                if artifact["artifact_type"] == "cloud-file" and artifact["details"]["service"] == "microsoft-onedrive"
            )
            self.assertEqual(cloud_file["details"]["service"], "microsoft-onedrive")
            self.assertEqual(cloud_file["details"]["file_name"], "case.zip")
            self.assertIn("reviewable-document-or-archive", cloud_file["details"]["risk_flags"])
            self.assertIn("#39", cloud_file["details"]["commercial_gap_ids"])
            self.assertEqual(cloud_file["details"]["forensic_review"]["gap_id"], "#39")
            microsoft_file_gate = cloud_file["details"]["core_accuracy_gates"][0]
            self.assertEqual(microsoft_file_gate["gap_id"], "#39")
            self.assertIn("Microsoft 365 service profile detection", microsoft_file_gate["satisfied_checks"])
            self.assertIn("M365/Teams eDiscovery strategy", microsoft_file_gate["satisfied_checks"])
            self.assertIn("M365 workload review profile", microsoft_file_gate["satisfied_checks"])
            self.assertIn("M365 row pivot inventory", microsoft_file_gate["satisfied_checks"])
            self.assertIn("mail/file/message/audit normalization", microsoft_file_gate["satisfied_checks"])
            self.assertIn("source hash and eDiscovery/export warning", microsoft_file_gate["satisfied_checks"])
            self.assertIn("cloud export import manifest", microsoft_file_gate["satisfied_checks"])
            self.assertIn("cloud export source locator", microsoft_file_gate["satisfied_checks"])
            m365_file_profile = cloud_file["details"]["m365_export_review_profile"]
            self.assertEqual(m365_file_profile["profile_version"], "m365-export-review-v1")
            self.assertEqual(m365_file_profile["workload_family"], "onedrive-sharepoint")
            self.assertTrue(m365_file_profile["primary_pivot_present"])
            self.assertIn("file_id", m365_file_profile["present_primary_pivots"])
            self.assertEqual(m365_file_profile["sharepoint_permission_graph_status"], "not-built")
            self.assertTrue(cloud_file["details"]["validation_checks"]["m365_export_review_profile_emitted"])
            self.assertTrue(cloud_file["details"]["validation_checks"]["m365_row_pivot_present"])
            file_uplift = cloud_file["details"]["commercial_uplift_evidence"]
            self.assertEqual(file_uplift["item_numbers"], [39])
            cloud_file_manifest = cloud_file["details"]["cloud_export_import_manifest"]
            self.assertEqual(
                cloud_file_manifest["provider_review"]["product_or_workload_family"],
                "onedrive-sharepoint",
            )
            self.assertEqual(cloud_file_manifest["source_viewer_locator"]["viewer"], "cloud-provider-export-row")
            self.assertEqual(
                cloud_file["details"]["cloud_provider_strategy_profile"]["selected_track"],
                "m365-purview-graph-ediscovery-validation",
            )
            self.assertTrue(
                file_uplift["functional_priority_profile"]["implemented_controls"][
                    "m365_teams_onedrive_sharepoint_inventory"
                ]
            )
            self.assertIn("retention-hold-and-deleted-state", file_uplift["failed_issue_matrix_ids"])
            self.assertTrue(file_uplift["large_data_controls"]["m365_export_review_profile_present"])
            self.assertEqual(
                file_uplift["reportability_decision"]["decision"],
                "do-not-report-m365-export-as-tenant-or-permission-complete",
            )
            self.assertEqual(
                file_uplift["reportability_decision"]["allowed_use"],
                "m365-export-triage-pivot",
            )

            message = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "cloud-message")
            self.assertEqual(message["details"]["service"], "microsoft-teams")
            self.assertEqual(message["details"]["chat_id"], "chat-1")
            self.assertIn("cloud-message", message["details"]["risk_flags"])
            self.assertIn("#39", message["details"]["cloud_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(message["details"]["forensic_review"]["gap_id"], "#39")
            self.assertEqual(message["details"]["m365_export_review_profile"]["workload_family"], "teams")
            self.assertIn("message_id", message["details"]["m365_export_review_profile"]["present_primary_pivots"])
            self.assertIn("teams-cosmosdb-vs-exchange-compliance-records", message["details"]["cloud_provider_profile"]["known_gaps"])

            slack = next(
                artifact
                for artifact in payload["artifacts"]
                if artifact["artifact_type"] == "cloud-message" and artifact["details"]["service"] == "slack"
            )
            self.assertEqual(slack["details"]["cloud_family"], "collaboration-saas")
            self.assertIn("workspace-plan-dependent-export-scope", slack["details"]["cloud_provider_profile"]["known_gaps"])

            audit = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "cloud-audit")
            self.assertEqual(audit["details"]["service"], "microsoft-365")
            self.assertIn("identity-security-event", audit["details"]["risk_flags"])
            self.assertIn("#39", audit["details"]["commercial_gap_ids"])
            self.assertEqual(audit["details"]["forensic_review"]["gap_id"], "#39")
            self.assertEqual(audit["details"]["m365_export_review_profile"]["workload_family"], "audit")

    def test_cloud_trusted_diff_controls_provider_accuracy_gates(self) -> None:
        google_row = {
            "service": "gmail-takeout",
            "event_type": "mail",
            "timestamp": "2026-04-26T04:00:00Z",
            "subject": "Invoice password review",
            "message_id": "gmail-msg-1",
            "body_sha256": "body-hash",
        }
        google_diff = build_cloud_export_trusted_diff(
            37,
            [google_row],
            [dict(google_row)],
            trusted_tool="google-takeout-native",
        )
        self.assertEqual(google_diff["status"], "pass")
        google_gate = cloud_core_accuracy_gates(
            gap_ids=["#37"],
            family="google",
            service="gmail-takeout",
            artifact_type="cloud-mail",
            source_hashes={"sha256": "source-hash"},
            details={
                **google_row,
                "commercial_grade_blockers": ["fixture"],
                "validation_checks": {},
                "cloud_trusted_diff": google_diff,
            },
            source_index=0,
            source_path="gmail-export.json",
        )[0]
        self.assertIn("trusted Google Takeout/provider diff pass", google_gate["satisfied_checks"])

        apple_row = {
            "service": "apple-icloud-export",
            "event_type": "account",
            "timestamp": "2026-04-26T04:00:00Z",
            "account_email": "alice@example.com",
        }
        apple_diff = build_cloud_export_trusted_diff(
            38,
            [apple_row],
            [dict(apple_row)],
            trusted_tool="apple-privacy-export",
        )
        apple_gate = cloud_core_accuracy_gates(
            gap_ids=["#38"],
            family="apple-icloud",
            service="apple-icloud-export",
            artifact_type="cloud-account",
            source_hashes={"sha256": "source-hash"},
            details={
                **apple_row,
                "commercial_grade_blockers": ["fixture"],
                "validation_checks": {},
                "cloud_trusted_diff": apple_diff,
            },
            source_index=0,
            source_path="icloud-export.json",
        )[0]
        self.assertIn("trusted iCloud/provider export diff pass", apple_gate["satisfied_checks"])

        m365_row = {
            "service": "microsoft-teams",
            "event_type": "message",
            "timestamp": "2026-04-26T06:00:00Z",
            "chat_id": "chat-1",
            "message_id": "teams-msg-1",
            "message_text_sha256": "text-hash",
        }
        m365_diff = build_cloud_export_trusted_diff(
            39,
            [m365_row],
            [dict(m365_row)],
            trusted_tool="microsoft-purview-ediscovery",
        )
        m365_gate = cloud_core_accuracy_gates(
            gap_ids=["#39"],
            family="microsoft-365",
            service="microsoft-teams",
            artifact_type="cloud-message",
            source_hashes={"sha256": "source-hash"},
            details={
                **m365_row,
                "commercial_grade_blockers": ["fixture"],
                "validation_checks": {},
                "cloud_trusted_diff": m365_diff,
            },
            source_index=0,
            source_path="teams.json",
        )[0]
        self.assertIn("trusted M365/eDiscovery export diff pass", m365_gate["satisfied_checks"])

        mismatch = build_cloud_export_trusted_diff(
            39,
            [m365_row],
            [{**m365_row, "message_text_sha256": "changed"}],
            trusted_tool="microsoft-purview-ediscovery",
        )
        self.assertEqual(mismatch["status"], "fail")
        self.assertEqual(mismatch["blocker_id"], "m365-ediscovery-provider-diff-required")
        self.assertEqual(mismatch["mismatched_fields"][0]["field"], "message_text_sha256")


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

    icloud_photo = root / "Apple" / "iCloud Photos" / "photos.json"
    icloud_photo.parent.mkdir(parents=True)
    icloud_photo.write_text(
        json.dumps(
            [
                {
                    "id": "icloud-photo-1",
                    "name": "IMG_0001.JPG",
                    "mimeType": "image/jpeg",
                    "webUrl": "https://www.icloud.com/photos/#IMG0001",
                    "createdTime": "2026-04-26T03:30:00Z",
                    "owner": "alice@example.com",
                }
            ]
        ),
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

    slack = root / "Slack" / "messages.json"
    slack.parent.mkdir(parents=True)
    slack.write_text(
        json.dumps(
            [
                {
                    "timestamp": "2026-04-26T08:00:00Z",
                    "channelId": "C123",
                    "id": "slack-msg-1",
                    "user": "alice@example.com",
                    "text": "Slack export message",
                }
            ]
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    unittest.main()
