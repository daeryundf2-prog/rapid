from __future__ import annotations

import json
import plistlib
import sqlite3
import tempfile
import unittest
from pathlib import Path

from rapidtriage.artifacts.mobile import (
    build_chat_app_trusted_diff,
    build_mobile_correlation_trusted_diff,
    build_mobile_trusted_diff,
    chat_app_core_accuracy_gates,
    mobile_core_accuracy_gates,
    mobile_correlation_core_accuracy_gates,
)
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
                    "mobile-account",
                    "mobile-media",
                    "mobile-browser",
                    "mobile-chat-database",
                    "mobile-correlation-summary",
                    "mobile-export-source",
                    "ios-backup-file",
                    "ios-backup-source",
                    "ios-backup-metadata",
                    "ios-keychain-inventory",
                },
            )

            message = next(
                artifact
                for artifact in payload["artifacts"]
                if artifact["artifact_type"] == "mobile-message" and artifact["details"]["source_tool"] == "cellebrite"
            )
            self.assertEqual(message["details"]["source_tool"], "cellebrite")
            self.assertEqual(message["details"]["sender"], "+15550100")
            self.assertEqual(message["details"]["recipient"], "+15550200")
            self.assertIn("credential-or-otp", message["details"]["risk_flags"])
            self.assertIn("sha256", message["details"]["source_hashes"])
            self.assertIn("message_text_sha256", message["details"])
            self.assertIn("#26", message["details"]["mobile_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(message["details"]["forensic_review"]["gap_id"], "#26")
            self.assertFalse(message["details"]["mobile_native_capabilities"]["proprietary_vendor_package_decode"])
            message_gate = message["details"]["core_accuracy_gates"][0]
            self.assertEqual(message_gate["gap_id"], "#26")
            self.assertIn("source tool/version/profile detection", message_gate["satisfied_checks"])
            self.assertIn("row count and source ID preservation", message_gate["satisfied_checks"])
            self.assertIn("duplicate/deleted semantics", message_gate["satisfied_checks"])
            self.assertIn("source hash and acquisition linkage", message_gate["satisfied_checks"])
            self.assertIn("schema version compatibility warning", message_gate["satisfied_checks"])
            message_uplift = message["details"]["commercial_uplift_evidence"]
            self.assertEqual(message_uplift["batch_id"], "commercial-uplift-026-030")
            self.assertEqual(message_uplift["item_numbers"], [26])
            self.assertIn("source-hash-present", message_uplift["passed_validation_matrix_ids"])
            self.assertIn("vendor-settings-verified", message_uplift["failed_validation_matrix_ids"])
            self.assertEqual(message_uplift["large_data_controls"]["max_rows_per_source"], 50000)
            self.assertEqual(
                message_uplift["reportability_decision"]["decision"],
                "do-not-report-vendor-mobile-export-as-source-complete",
            )
            self.assertEqual(
                message_uplift["reportability_decision"]["allowed_use"],
                "vendor-mobile-export-triage-pivot",
            )
            self.assertIn(
                "vendor-export-settings-not-verified",
                message_uplift["reportability_decision"]["blockers"],
            )

            chat_messages = [
                artifact
                for artifact in payload["artifacts"]
                if artifact["artifact_type"] == "mobile-message"
                and artifact["details"]["service_family"]
                in {"kakaotalk", "whatsapp", "telegram", "signal", "line", "discord", "instagram", "facebook-messenger"}
            ]
            self.assertGreaterEqual(len(chat_messages), 8)
            services = {artifact["details"]["service"] for artifact in chat_messages}
            self.assertTrue(
                {"KakaoTalk", "WhatsApp", "Telegram", "Signal", "LINE", "Discord", "Instagram", "Facebook Messenger"}.issubset(
                    services
                )
            )
            kakao = next(artifact for artifact in chat_messages if artifact["details"]["service"] == "KakaoTalk")
            self.assertEqual(kakao["details"]["conversation_title"], "Case Room")
            self.assertEqual(kakao["details"]["reaction"], "👍")
            self.assertTrue(kakao["details"]["validation_checks"]["service_detected"])
            self.assertFalse(kakao["details"]["validation_checks"]["app_schema_validated"])
            self.assertIn("#31", kakao["details"]["chat_app_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(kakao["details"]["chat_app_forensic_review"]["gap_id"], "#31")
            self.assertFalse(kakao["details"]["chat_app_native_capabilities"]["service_specific_native_database_decode"])
            self.assertTrue(kakao["details"]["chat_app_scope_profile"]["known_profile"])
            self.assertIn("schema-version-known-answer", {item["id"] for item in kakao["details"]["chat_app_issue_matrix"]})
            self.assertEqual(
                kakao["details"]["kakaotalk_compatibility_assessment"]["status"],
                "post-bigbang-legacy-method-not-applicable",
            )
            self.assertIn(
                "kakaotalk-post-2025-08-bigbang",
                {item["id"] for item in kakao["details"]["chat_app_issue_matrix"]},
            )
            kakao_gate = {gate["gap_id"]: gate for gate in kakao["details"]["core_accuracy_gates"]}["#31"]
            self.assertIn("KakaoTalk service/profile detection", kakao_gate["satisfied_checks"])
            self.assertIn("chat/message participant/media normalization", kakao_gate["satisfied_checks"])
            self.assertIn("schema/app version and BigBang compatibility tracking", kakao_gate["satisfied_checks"])
            self.assertIn("encrypted/deleted limitation warning", kakao_gate["satisfied_checks"])
            self.assertIn("source hash and legal provenance", kakao_gate["satisfied_checks"])
            kakao_uplift = kakao["details"]["chat_app_commercial_uplift_evidence"]
            self.assertEqual(kakao_uplift["batch_id"], "commercial-uplift-031-035")
            self.assertEqual(kakao_uplift["item_numbers"], [31])
            self.assertIn("service-profile-known", kakao_uplift["passed_issue_matrix_ids"])
            self.assertIn("kakaotalk-post-2025-08-bigbang", kakao_uplift["failed_issue_matrix_ids"])
            self.assertFalse(kakao_uplift["large_data_controls"]["encrypted_store_decryption"])
            self.assertEqual(
                kakao_uplift["reportability_decision"]["decision"],
                "do-not-report-kakaotalk-message-content-as-decrypted-complete",
            )
            self.assertEqual(
                kakao_uplift["reportability_decision"]["allowed_use"],
                "kakaotalk-export-or-inventory-triage-pivot",
            )
            self.assertIn(
                "issue:kakaotalk-post-2025-08-bigbang",
                kakao_uplift["reportability_decision"]["blockers"],
            )
            facebook = next(artifact for artifact in chat_messages if artifact["details"]["service"] == "Facebook Messenger")
            self.assertEqual(facebook["details"]["chat_app_forensic_review"]["gap_id"], "#35")
            self.assertIn(
                "#32",
                next(artifact for artifact in chat_messages if artifact["details"]["service"] == "WhatsApp")["details"][
                    "chat_app_gap_ids"
                ],
            )
            whatsapp = next(artifact for artifact in chat_messages if artifact["details"]["service"] == "WhatsApp")
            whatsapp_gate = {gate["gap_id"]: gate for gate in whatsapp["details"]["core_accuracy_gates"]}["#32"]
            self.assertIn("WhatsApp service/profile detection", whatsapp_gate["satisfied_checks"])
            self.assertIn("chat/contact/media normalization", whatsapp_gate["satisfied_checks"])
            self.assertIn("crypt backup authority workflow warning", whatsapp_gate["satisfied_checks"])
            whatsapp_uplift = whatsapp["details"]["chat_app_commercial_uplift_evidence"]
            self.assertEqual(whatsapp_uplift["item_numbers"], [32])
            self.assertIn("encrypted-store-authority", whatsapp_uplift["failed_issue_matrix_ids"])
            self.assertEqual(
                whatsapp_uplift["reportability_decision"]["decision"],
                "do-not-report-whatsapp-message-content-as-crypt-or-deleted-complete",
            )
            self.assertIn(
                "issue:encrypted-store-authority",
                whatsapp_uplift["reportability_decision"]["blockers"],
            )
            self.assertIn(
                "#33",
                next(artifact for artifact in chat_messages if artifact["details"]["service"] == "Telegram")["details"][
                    "chat_app_gap_ids"
                ],
            )
            telegram = next(artifact for artifact in chat_messages if artifact["details"]["service"] == "Telegram")
            telegram_gate = {gate["gap_id"]: gate for gate in telegram["details"]["core_accuracy_gates"]}["#33"]
            self.assertIn("Telegram service/profile detection", telegram_gate["satisfied_checks"])
            self.assertIn("chat/user/media attribution", telegram_gate["satisfied_checks"])
            self.assertIn("encrypted local store warning", telegram_gate["satisfied_checks"])
            self.assertEqual(telegram["details"]["chat_app_commercial_uplift_evidence"]["item_numbers"], [33])
            self.assertEqual(
                telegram["details"]["chat_app_commercial_uplift_evidence"]["reportability_decision"]["allowed_use"],
                "telegram-export-or-cache-triage-pivot",
            )
            self.assertIn(
                "#34",
                next(artifact for artifact in chat_messages if artifact["details"]["service"] == "Signal")["details"][
                    "chat_app_gap_ids"
                ],
            )
            signal = next(artifact for artifact in chat_messages if artifact["details"]["service"] == "Signal")
            signal_gate = {gate["gap_id"]: gate for gate in signal["details"]["core_accuracy_gates"]}["#34"]
            self.assertIn("Signal service/profile detection", signal_gate["satisfied_checks"])
            self.assertIn("thread/recipient/message inventory", signal_gate["satisfied_checks"])
            self.assertIn("SQLCipher/key authority gate", signal_gate["satisfied_checks"])
            self.assertEqual(signal["details"]["chat_app_commercial_uplift_evidence"]["item_numbers"], [34])
            self.assertEqual(
                signal["details"]["chat_app_commercial_uplift_evidence"]["reportability_decision"]["decision"],
                "do-not-report-signal-message-content-as-sqlcipher-complete",
            )
            self.assertTrue(
                all(
                    "#35" in next(
                        artifact for artifact in chat_messages if artifact["details"]["service"] == service
                    )["details"]["chat_app_gap_ids"]
                    for service in ("LINE", "Discord", "Instagram")
                )
            )
            line = next(artifact for artifact in chat_messages if artifact["details"]["service"] == "LINE")
            line_gate = {gate["gap_id"]: gate for gate in line["details"]["core_accuracy_gates"]}["#35"]
            self.assertIn("extended service/profile detection", line_gate["satisfied_checks"])
            self.assertIn("message/media/reaction normalization", line_gate["satisfied_checks"])
            self.assertIn("schema/app version registry", line_gate["satisfied_checks"])
            line_uplift = line["details"]["chat_app_commercial_uplift_evidence"]
            self.assertEqual(line_uplift["item_numbers"], [35])
            self.assertIn("schema-version-known-answer", line_uplift["failed_issue_matrix_ids"])
            self.assertEqual(
                line_uplift["reportability_decision"]["allowed_use"],
                "extended-messenger-export-triage-pivot",
            )

            app = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "mobile-app")
            self.assertEqual(app["details"]["source_tool"], "graykey")
            self.assertEqual(app["details"]["package"], "ai.openai.chatgpt")
            self.assertIn("ai-service-app", app["details"]["risk_flags"])
            self.assertFalse(app["details"]["commercial_grade_ready"])
            self.assertIn("validation_checks", app["details"])

            browser = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "mobile-browser")
            self.assertEqual(browser["details"]["url"], "https://chatgpt.com/c/example")
            self.assertIn("ai-service-usage", browser["details"]["risk_flags"])

            account = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "mobile-account")
            self.assertEqual(account["details"]["account_identifier"], "alice@example.com")
            self.assertIn("account_identifier_sha256", account["details"])

            ios_file = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "ios-backup-file")
            self.assertEqual(ios_file["details"]["domain"], "AppDomain-com.apple.MobileSMS")
            self.assertIn("message-store-candidate", ios_file["details"]["risk_flags"])
            self.assertIn("#27", ios_file["details"]["mobile_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(ios_file["details"]["forensic_review"]["gap_id"], "#27")
            self.assertFalse(ios_file["details"]["mobile_native_capabilities"]["ios_protected_file_decryption"])
            ios_gate = ios_file["details"]["core_accuracy_gates"][0]
            self.assertEqual(ios_gate["gap_id"], "#27")
            self.assertIn("Manifest.db domain/fileID mapping", ios_gate["satisfied_checks"])
            self.assertIn("encrypted backup authority gate", ios_gate["satisfied_checks"])
            self.assertIn("app database schema detection", ios_gate["satisfied_checks"])
            self.assertIn("deleted-record limitation warning", ios_gate["satisfied_checks"])
            ios_uplift = ios_file["details"]["commercial_uplift_evidence"]
            self.assertEqual(ios_uplift["item_numbers"], [27])
            self.assertIn("protected-data-boundary", ios_uplift["passed_validation_matrix_ids"])
            self.assertIn("known-answer-mobile-validation", ios_uplift["failed_validation_matrix_ids"])
            self.assertEqual(
                ios_uplift["reportability_decision"]["decision"],
                "do-not-report-ios-backup-as-decrypted-complete",
            )
            self.assertEqual(
                ios_uplift["reportability_decision"]["allowed_use"],
                "ios-backup-inventory-triage-pivot",
            )

            ios_metadata = next(
                artifact
                for artifact in payload["artifacts"]
                if artifact["artifact_type"] == "ios-backup-metadata"
                and artifact["details"]["plist_name"] == "Info.plist"
            )
            metadata_gate = ios_metadata["details"]["core_accuracy_gates"][0]
            self.assertEqual(metadata_gate["gap_id"], "#27")
            self.assertIn("Info/Status plist consistency", metadata_gate["satisfied_checks"])

            keychain = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "ios-keychain-inventory")
            self.assertFalse(keychain["details"]["validation_checks"]["secrets_extracted"])
            self.assertTrue(keychain["details"]["validation_checks"]["values_redacted"])
            self.assertIn("sensitive-artifact-redacted", keychain["details"]["risk_flags"])
            self.assertIn("#28", keychain["details"]["mobile_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(keychain["details"]["forensic_review"]["gap_id"], "#28")
            self.assertFalse(keychain["details"]["mobile_native_capabilities"]["ios_keychain_secret_decryption"])
            keychain_gate = keychain["details"]["core_accuracy_gates"][0]
            self.assertEqual(keychain_gate["gap_id"], "#28")
            self.assertIn("secret values redacted by default", keychain_gate["satisfied_checks"])
            self.assertIn("protected-data class labeling", keychain_gate["satisfied_checks"])
            self.assertIn("authority gate before reveal/decrypt", keychain_gate["satisfied_checks"])
            self.assertIn("record count/table inventory", keychain_gate["satisfied_checks"])
            self.assertIn("audit log for any controlled reveal", keychain_gate["satisfied_checks"])
            keychain_uplift = keychain["details"]["commercial_uplift_evidence"]
            self.assertEqual(keychain_uplift["item_numbers"], [28])
            self.assertTrue(keychain_uplift["large_data_controls"]["protected_values_redacted_by_default"])
            self.assertIn("protected-data-boundary", keychain_uplift["passed_validation_matrix_ids"])
            self.assertEqual(
                keychain_uplift["reportability_decision"]["decision"],
                "do-not-report-ios-keychain-secrets-or-access-semantics",
            )
            self.assertEqual(
                keychain_uplift["reportability_decision"]["allowed_use"],
                "ios-keychain-redacted-inventory-pivot",
            )
            self.assertTrue(keychain_uplift["reportability_decision"]["secret_values_redacted_by_default"])

            chat_db = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "mobile-chat-database")
            self.assertEqual(chat_db["details"]["service"], "WhatsApp")
            self.assertTrue(chat_db["details"]["validation_checks"]["opened_readonly"])
            self.assertGreaterEqual(chat_db["details"]["validation_checks"]["message_table_candidate_count"], 1)
            self.assertTrue(chat_db["details"]["validation_checks"]["sample_values_redacted"])
            self.assertIn("mobile-chat-database", chat_db["details"]["risk_flags"])
            self.assertIn("#32", chat_db["details"]["chat_app_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(chat_db["details"]["chat_app_forensic_review"]["gap_id"], "#32")

            summaries = [artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "mobile-correlation-summary"]
            self.assertTrue(any(summary["details"]["message_count"] >= 7 for summary in summaries))
            messenger_summary = next(summary for summary in summaries if summary["details"]["message_count"] >= 7)
            self.assertTrue(messenger_summary["details"]["timeline_correlation_ready"])
            self.assertGreaterEqual(messenger_summary["details"]["participant_count"], 2)
            self.assertIn("#43", messenger_summary["details"]["mobile_correlation_report_grade_assessment"]["commercial_gap_ids"])
            self.assertIn("#44", messenger_summary["details"]["mobile_correlation_report_grade_assessment"]["commercial_gap_ids"])
            self.assertIn("#45", messenger_summary["details"]["mobile_correlation_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(messenger_summary["details"]["forensic_review"]["gap_id"], "#43")
            self.assertFalse(messenger_summary["details"]["forensic_review"]["report_grade_ready"])
            self.assertGreaterEqual(messenger_summary["details"]["media_message_link_count"], 1)
            self.assertEqual(
                messenger_summary["details"]["message_media_links"][0]["validation_status"],
                "unresolved-candidate",
            )
            self.assertGreaterEqual(messenger_summary["details"]["unified_contact_call_sms_view_count"], 2)
            self.assertGreaterEqual(messenger_summary["details"]["schema_version_registry_count"], 1)
            self.assertFalse(
                messenger_summary["details"]["validation_checks"]["schema_version_registry_known_answer_validated"]
            )
            self.assertFalse(
                messenger_summary["details"]["validation_checks"]["correlation_validated_against_known_answer"]
            )
            correlation_gates = {gate["gap_id"]: gate for gate in messenger_summary["details"]["core_accuracy_gates"]}
            self.assertIn("message-media linkage built", correlation_gates["#43"]["satisfied_checks"])
            self.assertIn("message/contact/call/media counts preserved", correlation_gates["#43"]["satisfied_checks"])
            self.assertIn("timeline correlation readiness", correlation_gates["#43"]["satisfied_checks"])
            self.assertIn("known-answer limitation warning", correlation_gates["#43"]["satisfied_checks"])
            self.assertIn("contact/call/SMS actor merge", correlation_gates["#44"]["satisfied_checks"])
            self.assertIn("participant attribution", correlation_gates["#44"]["satisfied_checks"])
            self.assertIn("export-scope limitation warning", correlation_gates["#44"]["satisfied_checks"])
            self.assertIn("app/service schema version registry", correlation_gates["#45"]["satisfied_checks"])
            self.assertIn("source app/version attribution", correlation_gates["#45"]["satisfied_checks"])
            self.assertIn("release-gate limitation disclosure", correlation_gates["#45"]["satisfied_checks"])
            correlation_uplift = messenger_summary["details"]["mobile_correlation_commercial_uplift_evidence"]
            self.assertEqual(correlation_uplift["batch_id"], "commercial-uplift-041-045")
            self.assertEqual(correlation_uplift["item_numbers"], [43, 44, 45])
            self.assertIn("media_message_links_built", correlation_uplift["passed_validation_check_ids"])
            self.assertIn("unified_contact_call_sms_view_built", correlation_uplift["passed_validation_check_ids"])
            self.assertIn("schema_version_registry_built", correlation_uplift["passed_validation_check_ids"])
            self.assertIn(
                "correlation_validated_against_known_answer",
                correlation_uplift["failed_validation_check_ids"],
            )
            self.assertEqual(
                correlation_uplift["reportability_decision"]["decision"],
                "do-not-report-mobile-correlation-as-device-wide-or-identity-complete",
            )
            self.assertEqual(
                correlation_uplift["reportability_decision"]["allowed_use"],
                "mobile-correlation-and-schema-triage-pivot",
            )
            self.assertIn(
                "device-wide-timeline-not-validated",
                correlation_uplift["reportability_decision"]["blockers"],
            )
            self.assertIn(
                "schema-version-registry-known-answer-not-attached",
                correlation_uplift["reportability_decision"]["blockers"],
            )
            self.assertFalse(correlation_uplift["large_data_controls"]["device_wide_timeline_ready"])
            self.assertTrue(correlation_uplift["large_data_controls"]["known_answer_correlation_required"])
            self.assertIn(
                "mobile-correlation-vendor-timeline-diff-required",
                correlation_uplift["reportability_decision"]["blockers"],
            )

            source_rows = [artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "mobile-export-source"]
            self.assertGreaterEqual(len(source_rows), 4)
            self.assertTrue(all("#26" in row["details"]["commercial_gap_ids"] for row in source_rows))

    def test_mobile_correlation_trusted_diff_controls_correlation_actor_and_schema_gates(self) -> None:
        rows = [
            {
                "kind": "message-media",
                "service": "KakaoTalk",
                "message_id": "m-1",
                "media_sha256": "a" * 64,
                "timestamp": "2026-04-26T01:02:03Z",
            },
            {
                "kind": "actor",
                "actor": "+15550100",
                "service": "KakaoTalk",
            },
            {
                "kind": "schema",
                "service": "KakaoTalk",
                "schema_or_app_version": "25.7.2",
            },
        ]
        diff = build_mobile_correlation_trusted_diff(
            rows,
            [dict(row) for row in rows],
            trusted_tool="hand-labeled-known-answer",
        )
        self.assertEqual(diff["status"], "pass")
        gates = {
            gate["gap_id"]: gate
            for gate in mobile_correlation_core_accuracy_gates(
                artifact_type="mobile-correlation-summary",
                source_tool="cellebrite",
                source_format="csv",
                source_index=0,
                source_hashes={"sha256": "d" * 64},
                details={
                    "message_count": 1,
                    "media_count": 1,
                    "contact_count": 1,
                    "call_count": 0,
                    "services": ["KakaoTalk"],
                    "participants": ["+15550100"],
                    "message_media_links": [{"message_id": "m-1"}],
                    "unified_contact_call_sms_view": [{"actor": "+15550100"}],
                    "schema_version_registry": [{"app_identifier": "KakaoTalk", "schema_or_app_version": "25.7.2"}],
                    "timeline_correlation_ready": True,
                    "validation_checks": {
                        "media_message_links_built": True,
                        "unified_contact_call_sms_view_built": True,
                        "schema_version_registry_built": True,
                    },
                    "mobile_correlation_trusted_diff": diff,
                },
            )
        }
        self.assertIn("trusted mobile correlation diff pass", gates["#43"]["satisfied_checks"])
        self.assertIn("trusted mobile actor diff pass", gates["#44"]["satisfied_checks"])
        self.assertIn("trusted app schema migration diff pass", gates["#45"]["satisfied_checks"])

        mismatch = build_mobile_correlation_trusted_diff(
            rows,
            [{**rows[0], "media_sha256": "b" * 64}, rows[1], rows[2]],
            trusted_tool="hand-labeled-known-answer",
        )
        self.assertEqual(mismatch["status"], "diffs-present")
        self.assertIn("mobile-correlation-vendor-timeline-diff-required", mismatch["reportability_decision"]["blockers"])

    def test_mobile_trusted_diffs_gate_vendor_ios_and_keychain_claims(self) -> None:
        vendor_diff = build_mobile_trusted_diff(
            26,
            [
                {
                    "artifact_type": "mobile-message",
                    "source_record_id": "m-1",
                    "timestamp": "2026-04-26T01:02:03Z",
                    "sender": "+15550100",
                    "recipient": "+15550200",
                    "message_text_sha256": "a" * 64,
                }
            ],
            [
                {
                    "Type": "mobile-message",
                    "RecordID": "m-1",
                    "Date": "2026-04-26T01:02:03Z",
                    "From": "+15550100",
                    "To": "+15550200",
                    "BodySHA256": "a" * 64,
                }
            ],
            trusted_tool="Cellebrite",
        )
        ios_diff = build_mobile_trusted_diff(
            27,
            [{"event_type": "ios-backup-file", "file_id": "abc123", "domain": "AppDomain-com.apple.MobileSMS", "logical_path": "AppDomain-com.apple.MobileSMS/Library/SMS/sms.db"}],
            [{"Type": "ios-backup-file", "FileID": "abc123", "Domain": "AppDomain-com.apple.MobileSMS", "Path": "AppDomain-com.apple.MobileSMS/Library/SMS/sms.db"}],
            trusted_tool="iLEAPP",
        )
        keychain_diff = build_mobile_trusted_diff(
            28,
            [{"event_type": "ios-keychain-inventory", "table": "genp", "row_count": 3}],
            [{"Type": "ios-keychain-inventory", "Table": "genp", "Count": 3}],
            trusted_tool="keychain-dumper",
        )

        self.assertEqual(vendor_diff["status"], "pass")
        self.assertEqual(ios_diff["status"], "pass")
        self.assertEqual(keychain_diff["status"], "pass")
        vendor_gate = mobile_core_accuracy_gates(
            artifact_type="mobile-message",
            source_tool="cellebrite",
            source_format="csv",
            source_index=0,
            source_hashes={"sha256": "a" * 64},
            details={
                "source_path": "Messages.csv",
                "message_id": "m-1",
                "deleted_state": "false",
                "mobile_trusted_diff": vendor_diff,
                "commercial_grade_blockers": ["schema-version-required"],
            },
        )[0]
        self.assertIn("trusted vendor mobile export diff pass", vendor_gate["satisfied_checks"])
        ios_gate = mobile_core_accuracy_gates(
            artifact_type="ios-backup-file",
            source_tool="ios-backup",
            source_format="ios-manifest-db",
            source_index=0,
            source_hashes={"sha256": "b" * 64},
            details={
                "file_id": "abc123",
                "domain": "AppDomain-com.apple.MobileSMS",
                "logical_path": "AppDomain-com.apple.MobileSMS/Library/SMS/sms.db",
                "commercial_grade_blockers": ["deleted-record-validation-required"],
                "mobile_trusted_diff": ios_diff,
            },
        )[0]
        self.assertIn("trusted iOS backup manifest diff pass", ios_gate["satisfied_checks"])
        keychain_gate = mobile_core_accuracy_gates(
            artifact_type="ios-keychain-inventory",
            source_tool="ios-backup",
            source_format="ios-keychain-db",
            source_index=0,
            source_hashes={"sha256": "c" * 64},
            details={
                "table_summaries": [{"table": "genp", "row_count": 3}],
                "validation_checks": {"values_redacted": True, "secrets_extracted": False},
                "protected_data_class_handling": {"status": "redacted"},
                "controlled_reveal_audit": {"reveal_performed": False},
                "legal_warning": "redacted",
                "mobile_trusted_diff": keychain_diff,
            },
        )[0]
        self.assertIn("trusted iOS keychain inventory diff pass", keychain_gate["satisfied_checks"])

    def test_mobile_trusted_diff_blocks_unknown_tools_and_mismatches(self) -> None:
        diff = build_mobile_trusted_diff(
            26,
            [{"artifact_type": "mobile-message", "source_record_id": "m-1", "message_text_sha256": "a" * 64}],
            [{"Type": "mobile-message", "RecordID": "m-1", "BodySHA256": "b" * 64}],
            trusted_tool="unknown-tool",
        )

        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["trusted_tool_recognized"])
        self.assertEqual(diff["mismatch_count"], 1)
        self.assertIn("vendor-mobile-export-trusted-diff-required", diff["reportability_decision"]["blockers"])

    def test_chat_app_trusted_diffs_gate_messenger_claims(self) -> None:
        cases = [
            (31, "KakaoTalk", "KakaoTalk export", "trusted KakaoTalk export/native DB diff pass"),
            (32, "WhatsApp", "WhatsApp export", "trusted WhatsApp export/native DB diff pass"),
            (33, "Telegram", "Telegram export", "trusted Telegram export/native DB diff pass"),
            (34, "Signal", "Signal export", "trusted Signal export/native DB diff pass"),
            (35, "LINE", "LINE export", "trusted extended messenger export/native DB diff pass"),
        ]
        for number, service, tool, check in cases:
            with self.subTest(service=service):
                diff = build_chat_app_trusted_diff(
                    number,
                    [
                        {
                            "service": service,
                            "conversation_id": "room-1",
                            "message_id": "msg-1",
                            "timestamp": "2026-04-26T01:02:03Z",
                            "sender": "alice",
                            "recipient": "bob",
                            "message_text_sha256": "a" * 64,
                            "reaction": "ok",
                        }
                    ],
                    [
                        {
                            "Service": service,
                            "ChatID": "room-1",
                            "MsgID": "msg-1",
                            "Date": "2026-04-26T01:02:03Z",
                            "From": "alice",
                            "To": "bob",
                            "BodySHA256": "a" * 64,
                            "Reaction": "ok",
                        }
                    ],
                    trusted_tool=tool,
                )
                self.assertEqual(diff["status"], "pass")
                gate = chat_app_core_accuracy_gates(
                    artifact_type="mobile-message",
                    source_tool="authorized-export",
                    source_format="json",
                    source_index=0,
                    source_hashes={"sha256": "b" * 64},
                    details={
                        "service": service,
                        "conversation_id": "room-1",
                        "message_id": "msg-1",
                        "message_text_sha256": "a" * 64,
                        "reaction": "ok",
                        "app_version": "1.0",
                        "schema_version": "fixture",
                        "chat_app_scope_profile": {"known_profile": True},
                        "chat_app_issue_matrix": [{"id": "service-profile-known", "passed": True}],
                        "kakaotalk_compatibility_assessment": {"report_grade_ready": False, "blockers": ["fixture"]},
                        "commercial_grade_blockers": ["service-specific-validation-required"],
                        "chat_app_trusted_diff": diff,
                    },
                )[0]
                self.assertIn(check, gate["satisfied_checks"])
                self.assertNotIn(check, gate["missing_required_checks"])

    def test_chat_app_trusted_diff_blocks_unknown_tools_and_mismatches(self) -> None:
        diff = build_chat_app_trusted_diff(
            32,
            [{"service": "WhatsApp", "conversation_id": "room-1", "message_id": "msg-1", "message_text_sha256": "a" * 64}],
            [{"Service": "WhatsApp", "ChatID": "room-1", "MsgID": "msg-1", "BodySHA256": "b" * 64}],
            trusted_tool="unknown-tool",
        )

        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["trusted_tool_recognized"])
        self.assertEqual(diff["mismatch_count"], 1)
        self.assertIn("whatsapp-trusted-export-or-native-db-diff-required", diff["reportability_decision"]["blockers"])


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

    axiom = root / "AXIOM" / "accounts_browser_media.json"
    axiom.parent.mkdir(parents=True)
    axiom.write_text(
        json.dumps(
            [
                {
                    "Account ID": "alice@example.com",
                    "Account Name": "Alice Example",
                    "Service": "ChatGPT",
                },
                {
                    "URL": "https://chatgpt.com/c/example",
                    "Title": "ChatGPT conversation",
                    "Browser": "Mobile Safari",
                    "Last Visited": "2026-04-26T03:00:00Z",
                },
                {
                    "Media Path": "/private/var/mobile/Media/DCIM/100APPLE/IMG_0001.JPG",
                    "MIME Type": "image/jpeg",
                    "Width": "3024",
                    "Height": "4032",
                    "SHA256": "b" * 64,
                },
            ]
        ),
        encoding="utf-8",
    )

    chat_exports = root / "AXIOM" / "messenger_exports.jsonl"
    chat_exports.write_text(
        "\n".join(
            json.dumps(row)
            for row in [
                {
                    "Service": "KakaoTalk",
                    "Chat ID": "kakao-room-1",
                    "Chat Name": "Case Room",
                    "Message ID": "kakao-msg-1",
                    "From": "alice",
                    "To": "bob",
                    "Message": "카카오톡 사건 대화",
                    "Reaction": "👍",
                    "Media Path": "/KakaoTalk/Chats/IMG_0001.jpg",
                    "App Version": "25.7.2",
                    "Timestamp": "2026-04-26T05:00:00Z",
                },
                {
                    "Service": "WhatsApp",
                    "Conversation ID": "wa-thread-1",
                    "Message ID": "wa-msg-1",
                    "Sender": "+15550100",
                    "Recipient": "+15550200",
                    "Text": "WhatsApp exported chat",
                    "Timestamp": "2026-04-26T05:01:00Z",
                },
                {
                    "Service": "Telegram",
                    "Chat Title": "Ops",
                    "Message ID": "tg-msg-1",
                    "Author": "alice",
                    "Text": "Telegram desktop export",
                    "Timestamp": "2026-04-26T05:02:00Z",
                },
                {
                    "Service": "Signal",
                    "Thread ID": "signal-thread-1",
                    "Message ID": "signal-msg-1",
                    "From": "alice",
                    "To": "bob",
                    "Body": "Signal backup row",
                    "Timestamp": "2026-04-26T05:03:00Z",
                },
                {
                    "Service": "LINE",
                    "Room ID": "line-room-1",
                    "Message ID": "line-msg-1",
                    "Sender": "alice",
                    "Content": "LINE export row",
                    "Timestamp": "2026-04-26T05:04:00Z",
                },
                {
                    "Service": "Discord",
                    "Channel ID": "discord-channel-1",
                    "Message ID": "discord-msg-1",
                    "Author": "alice",
                    "Message": "Discord data package row",
                    "Timestamp": "2026-04-26T05:05:00Z",
                },
                {
                    "Service": "Instagram",
                    "Thread ID": "instagram-thread-1",
                    "Message ID": "ig-msg-1",
                    "Sender": "alice",
                    "Text": "Instagram direct export row",
                    "Timestamp": "2026-04-26T05:06:00Z",
                },
                {
                    "Service": "Facebook Messenger",
                    "Thread ID": "fb-thread-1",
                    "Message ID": "fb-msg-1",
                    "Sender": "alice",
                    "Text": "Facebook Messenger export row",
                    "Timestamp": "2026-04-26T05:07:00Z",
                },
            ]
        ),
        encoding="utf-8",
    )

    whatsapp_db = root / "WhatsApp" / "msgstore.db"
    whatsapp_db.parent.mkdir()
    with sqlite3.connect(whatsapp_db) as connection:
        connection.execute("CREATE TABLE messages (_id INTEGER, key_remote_jid TEXT, from_me INTEGER, data TEXT, timestamp INTEGER)")
        connection.execute("INSERT INTO messages VALUES (?, ?, ?, ?, ?)", (1, "15550100@s.whatsapp.net", 0, "redacted", 1777180000000))

    ios_backup = root / "iOS Backup"
    ios_backup.mkdir()
    (ios_backup / "Info.plist").write_bytes(
        plistlib.dumps(
            {
                "Device Name": "Alice iPhone",
                "Product Version": "18.4",
                "Last Backup Date": "2026-04-26T04:00:00Z",
                "Unique Identifier": "UDID-EXAMPLE",
            }
        )
    )
    (ios_backup / "Status.plist").write_bytes(plistlib.dumps({"SnapshotState": "finished", "IsFullBackup": True}))

    manifest = ios_backup / "Manifest.db"
    with sqlite3.connect(manifest) as connection:
        connection.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER)")
        connection.execute(
            "INSERT INTO Files VALUES (?, ?, ?, ?)",
            ("abcdef123456", "AppDomain-com.apple.MobileSMS", "Library/SMS/sms.db", 1),
        )

    keychain = ios_backup / "keychain-2.db"
    with sqlite3.connect(keychain) as connection:
        connection.execute("CREATE TABLE genp (agrp TEXT, svce TEXT, acct TEXT, data BLOB)")
        connection.execute("INSERT INTO genp VALUES (?, ?, ?, ?)", ("test", "example", "alice", b"secret-not-exported"))


if __name__ == "__main__":
    unittest.main()
