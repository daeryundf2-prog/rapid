from __future__ import annotations

import hashlib
import json
import plistlib
import sqlite3
import contextlib
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
                    "mobile-location",
                    "mobile-health",
                    "mobile-screen-time",
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
            mobile_review = message["details"]["mobile_analyst_review_profile"]
            self.assertEqual(mobile_review["profile_version"], "mobile-analyst-review-profile-v1")
            self.assertEqual(mobile_review["gap_ids"], ["#26"])
            self.assertEqual(mobile_review["artifact_type"], "mobile-message")
            self.assertIn("vendor/mobile tool row diff", mobile_review["correlation_targets"])
            self.assertIn("complete device extraction", mobile_review["not_proof_of"])
            self.assertFalse(mobile_review["report_grade_ready"])

            location = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "mobile-location")
            self.assertEqual(location["details"]["latitude"], 37.422)
            self.assertEqual(location["details"]["longitude"], -122.0840575)
            self.assertTrue(location["details"]["map_review_profile"]["coordinate_pair_present"])
            self.assertIn("precise-location", location["details"]["risk_flags"])

            health = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "mobile-health")
            self.assertEqual(health["details"]["metric_type"], "steps")
            self.assertEqual(health["details"]["metric_value"], "1234")
            self.assertTrue(health["details"]["health_review_profile"]["metric_value_present"])

            screen_time = next(
                artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "mobile-screen-time"
            )
            self.assertEqual(screen_time["details"]["app_name"], "KakaoTalk")
            self.assertEqual(screen_time["details"]["duration_seconds"], "600")
            self.assertTrue(screen_time["details"]["screen_time_review_profile"]["duration_present"])
            self.assertFalse(message["details"]["mobile_native_capabilities"]["proprietary_vendor_package_decode"])
            message_gate = message["details"]["core_accuracy_gates"][0]
            self.assertEqual(message_gate["gap_id"], "#26")
            self.assertIn("source tool/version/profile detection", message_gate["satisfied_checks"])
            self.assertIn("row count and source ID preservation", message_gate["satisfied_checks"])
            self.assertIn("duplicate/deleted semantics", message_gate["satisfied_checks"])
            self.assertIn("source hash and acquisition linkage", message_gate["satisfied_checks"])
            self.assertIn("schema version compatibility warning", message_gate["satisfied_checks"])
            self.assertIn("mobile vendor import manifest", message_gate["satisfied_checks"])
            self.assertIn("mobile vendor source row locator", message_gate["satisfied_checks"])
            vendor_import_manifest = message["details"]["mobile_vendor_import_manifest"]
            self.assertEqual(vendor_import_manifest["manifest_version"], "mobile-vendor-import-manifest-v1")
            self.assertEqual(vendor_import_manifest["item_number"], 52)
            self.assertEqual(vendor_import_manifest["source_tool"], "cellebrite")
            self.assertEqual(vendor_import_manifest["source_viewer_locator"]["viewer"], "mobile-vendor-export-row")
            self.assertEqual(len(vendor_import_manifest["manifest_sha256"]), 64)
            self.assertEqual(
                message["details"]["mobile_vendor_import_manifest_hash"],
                vendor_import_manifest["manifest_sha256"],
            )
            message_uplift = message["details"]["commercial_uplift_evidence"]
            self.assertEqual(message_uplift["batch_id"], "commercial-uplift-026-030")
            self.assertEqual(message_uplift["item_numbers"], [26])
            self.assertIn("source-hash-present", message_uplift["passed_validation_matrix_ids"])
            self.assertIn("vendor-settings-verified", message_uplift["failed_validation_matrix_ids"])
            self.assertEqual(message_uplift["large_data_controls"]["max_rows_per_source"], 50000)
            vendor_profile = message_uplift["functional_priority_profiles"][0]
            self.assertEqual(vendor_profile["item_number"], 52)
            self.assertEqual(vendor_profile["batch_id"], "commercial-uplift-051-055")
            self.assertEqual(
                vendor_profile["implemented_controls"]["mobile_vendor_import_manifest_hash"],
                vendor_import_manifest["manifest_sha256"],
            )
            self.assertIn("mobile-vendor-import-manifest-emitted", vendor_profile["passed_validation_check_ids"])
            self.assertIn("mobile-vendor-source-row-locator-emitted", vendor_profile["passed_validation_check_ids"])
            self.assertIn("vendor-export-settings-not-verified", vendor_profile["failed_validation_check_ids"])
            self.assertEqual(
                message_uplift["large_data_controls"]["mobile_vendor_import_manifest_hash"],
                vendor_import_manifest["manifest_sha256"],
            )
            self.assertTrue(message_uplift["large_data_controls"]["mobile_vendor_source_row_locator_present"])
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
            source_record = next(
                artifact
                for artifact in payload["artifacts"]
                if artifact["artifact_type"] == "mobile-export-source"
                and artifact["details"]["source_tool"] == "cellebrite"
            )
            source_profile = source_record["details"]["mobile_export_source_profile"]
            self.assertEqual(source_profile["source_tool"], "cellebrite")
            self.assertEqual(source_profile["input_row_count"], source_record["details"]["input_row_count"])
            self.assertEqual(source_profile["emitted_row_count"], source_record["details"]["row_count"])
            self.assertIn("mobile-message", source_profile["detected_artifact_types"])
            self.assertFalse(source_profile["truncated_by_row_cap"])
            self.assertTrue(source_profile["vendor_export_manifest_present"])
            self.assertEqual(source_profile["vendor_tool_version"], "7.66")
            self.assertTrue(source_profile["source_hash_matches_manifest"])
            self.assertTrue(source_profile["original_acquisition_hash_verified"])
            self.assertEqual(source_profile["vendor_schema_registry_profile"]["vendor_family"], "cellebrite-ufed-physical-analyzer")
            self.assertIn("messages", source_profile["vendor_schema_registry_profile"]["observed_artifact_families"])
            manifest_profile = source_record["details"]["vendor_export_manifest_profile"]
            self.assertEqual(manifest_profile["validation_status"], "metadata-linked")
            self.assertTrue(manifest_profile["original_acquisition_hash_present"])
            mapper_manifest = source_record["details"]["mobile_vendor_schema_mapper_manifest"]
            self.assertEqual(mapper_manifest["manifest_version"], "mobile-vendor-schema-mapper-manifest-v1")
            self.assertEqual(mapper_manifest["item_number"], 26)
            self.assertEqual(mapper_manifest["gap_id"], "#26")
            self.assertEqual(mapper_manifest["source_tool"], "cellebrite")
            self.assertEqual(mapper_manifest["vendor_family"], "cellebrite-ufed-physical-analyzer")
            self.assertEqual(len(mapper_manifest["manifest_sha256"]), 64)
            self.assertEqual(
                source_record["details"]["mobile_vendor_schema_mapper_manifest_hash"],
                mapper_manifest["manifest_sha256"],
            )
            self.assertEqual(
                mapper_manifest["source_viewer_locator"]["viewer"],
                "mobile-vendor-export-source",
            )
            self.assertTrue(mapper_manifest["validation"]["source_hash_linked_to_sidecar"])
            self.assertTrue(mapper_manifest["validation"]["original_acquisition_hash_recorded"])
            self.assertFalse(mapper_manifest["validation"]["commercial_grade"])
            self.assertIn("messages", mapper_manifest["schema_registry"]["observed_artifact_families"])
            self.assertGreaterEqual(len(mapper_manifest["supported_vendor_families"]), 4)
            message_mapper = next(
                mapper for mapper in mapper_manifest["artifact_mappers"] if mapper["family"] == "messages"
            )
            self.assertEqual(message_mapper["output_artifact_type"], "mobile-message")
            self.assertTrue(message_mapper["observed"])
            self.assertGreaterEqual(message_mapper["normalized_row_count"], 1)
            self.assertIn("trusted-vendor-mobile-export-diff-required", mapper_manifest["commercial_blockers"])
            self.assertTrue(source_record["details"]["validation_checks"]["vendor_export_settings_verified"])
            self.assertTrue(source_record["details"]["validation_checks"]["original_acquisition_hash_verified"])
            self.assertTrue(source_record["details"]["validation_checks"]["schema_profile_emitted"])
            source_gate = source_record["details"]["core_accuracy_gates"][0]
            self.assertIn("export schema/source profile", source_gate["satisfied_checks"])
            self.assertIn("vendor schema mapper manifest", source_gate["satisfied_checks"])
            self.assertIn("vendor schema mapper source locator", source_gate["satisfied_checks"])
            self.assertTrue(source_record["details"]["commercial_uplift_evidence"]["large_data_controls"]["source_schema_profile_emitted"])
            self.assertTrue(source_record["details"]["commercial_uplift_evidence"]["large_data_controls"]["vendor_export_manifest_present"])
            self.assertEqual(
                source_record["details"]["commercial_uplift_evidence"]["large_data_controls"][
                    "mobile_vendor_schema_mapper_manifest_hash"
                ],
                mapper_manifest["manifest_sha256"],
            )
            self.assertTrue(
                source_record["details"]["commercial_uplift_evidence"]["large_data_controls"][
                    "mobile_vendor_schema_mapper_source_locator_present"
                ]
            )
            source_functional_profile = source_record["details"]["commercial_uplift_evidence"][
                "functional_priority_profiles"
            ][0]
            self.assertEqual(
                source_functional_profile["implemented_controls"]["vendor_schema_mapper_manifest_hash"],
                mapper_manifest["manifest_sha256"],
            )
            self.assertIn(
                "mobile-vendor-schema-mapper-manifest-emitted",
                source_functional_profile["passed_validation_check_ids"],
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
            self.assertTrue(kakao["details"]["validation_checks"]["kakaotalk_review_profile_emitted"])
            self.assertTrue(kakao["details"]["validation_checks"]["kakaotalk_message_hash_present"])
            self.assertTrue(kakao["details"]["validation_checks"]["kakaotalk_attachment_metadata_present"])
            self.assertIn("#31", kakao["details"]["chat_app_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(kakao["details"]["chat_app_forensic_review"]["gap_id"], "#31")
            self.assertFalse(kakao["details"]["chat_app_native_capabilities"]["service_specific_native_database_decode"])
            self.assertTrue(kakao["details"]["chat_app_scope_profile"]["known_profile"])
            kakao_review_profile = kakao["details"]["kakaotalk_message_review_profile"]
            self.assertEqual(kakao_review_profile["attachment_class"], "image")
            self.assertFalse(kakao_review_profile["attachment_local_bytes_verified"])
            self.assertEqual(kakao_review_profile["review_display_mode"], "chat-bubble-row-with-metadata-collapsed")
            self.assertEqual(kakao_review_profile["content_source_status"], "authorized-export-row-not-native-decrypt")
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
            self.assertIn("KakaoTalk message review profile", kakao_gate["satisfied_checks"])
            self.assertIn("KakaoTalk attachment metadata tracking", kakao_gate["satisfied_checks"])
            self.assertIn("schema/app version and BigBang compatibility tracking", kakao_gate["satisfied_checks"])
            self.assertIn("KakaoTalk legacy/post-BigBang strategy profile", kakao_gate["satisfied_checks"])
            self.assertIn("KakaoTalk parser manifest", kakao_gate["satisfied_checks"])
            self.assertIn("KakaoTalk source row citation", kakao_gate["satisfied_checks"])
            self.assertIn("KakaoTalk review viewer controls", kakao_gate["satisfied_checks"])
            self.assertIn("encrypted/deleted limitation warning", kakao_gate["satisfied_checks"])
            self.assertIn("source hash and legal provenance", kakao_gate["satisfied_checks"])
            self.assertEqual(
                kakao["details"]["kakaotalk_compatibility_assessment"]["strategy_profile"]["selected_track"],
                "post-bigbang-memory-key-store-and-export-validation",
            )
            kakao_parser_manifest = kakao["details"]["kakaotalk_parser_manifest"]
            self.assertEqual(kakao_parser_manifest["manifest_version"], "kakaotalk-parser-manifest-v1")
            self.assertEqual(kakao_parser_manifest["item_number"], 31)
            self.assertEqual(kakao_parser_manifest["gap_id"], "#31")
            self.assertEqual(kakao_parser_manifest["qc_prep_item_number"], 37)
            self.assertEqual(kakao_parser_manifest["service"], "KakaoTalk")
            self.assertEqual(kakao_parser_manifest["source_tool"], "axiom")
            self.assertEqual(kakao_parser_manifest["compatibility"]["status"], "post-bigbang-legacy-method-not-applicable")
            self.assertEqual(
                kakao_parser_manifest["compatibility"]["selected_track"],
                "post-bigbang-memory-key-store-and-export-validation",
            )
            self.assertEqual(
                kakao_parser_manifest["row_citation"]["source_viewer_locator"]["viewer"],
                "kakaotalk-message-row",
            )
            self.assertIn("row_hash", kakao_parser_manifest["row_citation"])
            self.assertEqual(kakao_parser_manifest["message_review"]["attachment_class"], "image")
            self.assertTrue(kakao_parser_manifest["message_review"]["message_text_sha256_present"])
            self.assertFalse(kakao_parser_manifest["validation"]["trusted_export_or_native_db_diff_attached"])
            self.assertEqual(
                kakao_parser_manifest["large_data_controls"]["viewer_default"],
                "conversation-grouped-virtualized-chat-review",
            )
            self.assertEqual(len(kakao_parser_manifest["manifest_sha256"]), 64)
            self.assertEqual(
                kakao["details"]["kakaotalk_parser_manifest_hash"],
                kakao_parser_manifest["manifest_sha256"],
            )
            kakao_manifest = kakao["details"]["messenger_export_framework_manifest"]
            self.assertEqual(kakao_manifest["manifest_version"], "messenger-export-framework-manifest-v1")
            self.assertEqual(kakao_manifest["item_number"], 50)
            self.assertEqual(kakao_manifest["gap_id"], "#50")
            self.assertIn("#50", kakao_manifest["commercial_gap_ids"])
            self.assertEqual(kakao_manifest["service"], "KakaoTalk")
            self.assertGreaterEqual(kakao_manifest["supported_service_count"], 20)
            self.assertEqual(len(kakao_manifest["manifest_sha256"]), 64)
            self.assertEqual(
                kakao["details"]["messenger_export_framework_manifest_hash"],
                kakao_manifest["manifest_sha256"],
            )
            self.assertEqual(
                kakao_manifest["row_citation"]["source_viewer_locator"]["viewer"],
                "messenger-export-row",
            )
            self.assertIn("row_hash", kakao_manifest["row_citation"])
            self.assertTrue(kakao_manifest["large_data_controls"]["text_values_hash_only_by_default"])
            self.assertIn("messenger export framework manifest", kakao_gate["satisfied_checks"])
            self.assertIn("messenger source row citation", kakao_gate["satisfied_checks"])
            kakao_uplift = kakao["details"]["chat_app_commercial_uplift_evidence"]
            self.assertEqual(kakao_uplift["batch_id"], "commercial-uplift-031-035")
            self.assertEqual(kakao_uplift["item_numbers"], [31])
            self.assertEqual(kakao_uplift["qc_prep_item_numbers"], [37])
            self.assertEqual(kakao_uplift["functional_priority_profile"]["item_number"], 50)
            self.assertEqual(kakao_uplift["functional_priority_profile"]["qc_prep_item_numbers"], [37])
            self.assertEqual(kakao_uplift["functional_priority_profile"]["batch_id"], "commercial-uplift-046-050")
            self.assertIn(
                "messenger-trusted-export-or-native-db-diff-required",
                kakao_uplift["functional_priority_profile"]["failed_validation_check_ids"],
            )
            self.assertGreaterEqual(
                kakao_uplift["functional_priority_profile"]["implemented_controls"]["supported_service_count"],
                20,
            )
            self.assertEqual(
                kakao_uplift["functional_priority_profile"]["implemented_controls"][
                    "messenger_export_framework_manifest_hash"
                ],
                kakao_manifest["manifest_sha256"],
            )
            self.assertEqual(
                kakao_uplift["functional_priority_profile"]["implemented_controls"][
                    "kakaotalk_parser_manifest_hash"
                ],
                kakao_parser_manifest["manifest_sha256"],
            )
            self.assertIn(
                "messenger-export-framework-manifest-emitted",
                kakao_uplift["functional_priority_profile"]["passed_validation_check_ids"],
            )
            self.assertIn(
                "kakaotalk-parser-manifest-emitted",
                kakao_uplift["functional_priority_profile"]["passed_validation_check_ids"],
            )
            self.assertIn(
                "kakaotalk-source-locator-emitted",
                kakao_uplift["functional_priority_profile"]["passed_validation_check_ids"],
            )
            self.assertIn(
                "messenger-source-locator-emitted",
                kakao_uplift["functional_priority_profile"]["passed_validation_check_ids"],
            )
            self.assertEqual(
                kakao_uplift["large_data_controls"]["messenger_export_framework_manifest_hash"],
                kakao_manifest["manifest_sha256"],
            )
            self.assertEqual(
                kakao_uplift["large_data_controls"]["kakaotalk_parser_manifest_hash"],
                kakao_parser_manifest["manifest_sha256"],
            )
            self.assertTrue(kakao_uplift["large_data_controls"]["messenger_row_citation_present"])
            self.assertTrue(kakao_uplift["large_data_controls"]["kakaotalk_source_row_citation_present"])
            self.assertTrue(kakao_uplift["large_data_controls"]["kakaotalk_review_viewer_controls_present"])
            self.assertIn("service-profile-known", kakao_uplift["passed_issue_matrix_ids"])
            self.assertIn("kakaotalk-post-2025-08-bigbang", kakao_uplift["failed_issue_matrix_ids"])
            self.assertTrue(kakao_uplift["large_data_controls"]["kakaotalk_message_review_profile_present"])
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
            self.assertTrue(whatsapp["details"]["validation_checks"]["whatsapp_review_profile_emitted"])
            self.assertTrue(whatsapp["details"]["validation_checks"]["whatsapp_message_hash_present"])
            self.assertTrue(whatsapp["details"]["validation_checks"]["whatsapp_media_metadata_present"])
            self.assertTrue(whatsapp["details"]["validation_checks"]["whatsapp_jid_attribution_present"])
            whatsapp_review_profile = whatsapp["details"]["whatsapp_message_review_profile"]
            self.assertEqual(whatsapp_review_profile["media_class"], "image")
            self.assertEqual(whatsapp_review_profile["sender_shape"], "user-jid")
            self.assertEqual(whatsapp_review_profile["recipient_shape"], "user-jid")
            self.assertEqual(whatsapp_review_profile["crypt_key_authority_status"], "not-attached")
            self.assertEqual(
                whatsapp_review_profile["review_display_mode"],
                "chat-bubble-row-with-media-and-crypt-metadata-collapsed",
            )
            whatsapp_gate = {gate["gap_id"]: gate for gate in whatsapp["details"]["core_accuracy_gates"]}["#32"]
            self.assertIn("WhatsApp service/profile detection", whatsapp_gate["satisfied_checks"])
            self.assertIn("chat/contact/media normalization", whatsapp_gate["satisfied_checks"])
            self.assertIn("WhatsApp message review profile", whatsapp_gate["satisfied_checks"])
            self.assertIn("WhatsApp JID attribution tracking", whatsapp_gate["satisfied_checks"])
            self.assertIn("WhatsApp media metadata tracking", whatsapp_gate["satisfied_checks"])
            self.assertIn("WhatsApp crypt/export strategy profile", whatsapp_gate["satisfied_checks"])
            self.assertIn("WhatsApp parser manifest", whatsapp_gate["satisfied_checks"])
            self.assertIn("WhatsApp source row citation", whatsapp_gate["satisfied_checks"])
            self.assertIn("WhatsApp review viewer controls", whatsapp_gate["satisfied_checks"])
            self.assertIn("crypt backup authority workflow warning", whatsapp_gate["satisfied_checks"])
            self.assertEqual(
                whatsapp["details"]["chat_app_strategy_profile"]["selected_track"],
                "whatsapp-export-msgstore-crypt-validation",
            )
            self.assertIn(
                "msgstore.db",
                whatsapp["details"]["chat_app_strategy_profile"]["expected_source_pivots"],
            )
            whatsapp_parser_manifest = whatsapp["details"]["whatsapp_parser_manifest"]
            self.assertEqual(whatsapp_parser_manifest["manifest_version"], "whatsapp-parser-manifest-v1")
            self.assertEqual(whatsapp_parser_manifest["item_number"], 32)
            self.assertEqual(whatsapp_parser_manifest["gap_id"], "#32")
            self.assertEqual(whatsapp_parser_manifest["qc_prep_item_number"], 38)
            self.assertEqual(whatsapp_parser_manifest["service"], "WhatsApp")
            self.assertEqual(
                whatsapp_parser_manifest["row_citation"]["source_viewer_locator"]["viewer"],
                "whatsapp-message-row",
            )
            self.assertIn("row_hash", whatsapp_parser_manifest["row_citation"])
            self.assertTrue(whatsapp_parser_manifest["message_review"]["jid_attribution_present"])
            self.assertEqual(whatsapp_parser_manifest["message_review"]["media_class"], "image")
            self.assertEqual(
                whatsapp_parser_manifest["message_review"]["crypt_key_authority_status"],
                "not-attached",
            )
            self.assertFalse(whatsapp_parser_manifest["validation"]["crypt_key_authority_attached"])
            self.assertEqual(
                whatsapp_parser_manifest["large_data_controls"]["viewer_default"],
                "conversation-grouped-virtualized-chat-review",
            )
            self.assertEqual(len(whatsapp_parser_manifest["manifest_sha256"]), 64)
            self.assertEqual(
                whatsapp["details"]["whatsapp_parser_manifest_hash"],
                whatsapp_parser_manifest["manifest_sha256"],
            )
            whatsapp_uplift = whatsapp["details"]["chat_app_commercial_uplift_evidence"]
            self.assertEqual(whatsapp_uplift["item_numbers"], [32])
            self.assertEqual(whatsapp_uplift["qc_prep_item_numbers"], [38])
            self.assertIn("encrypted-store-authority", whatsapp_uplift["failed_issue_matrix_ids"])
            self.assertTrue(whatsapp_uplift["large_data_controls"]["whatsapp_message_review_profile_present"])
            self.assertEqual(
                whatsapp_uplift["large_data_controls"]["whatsapp_parser_manifest_hash"],
                whatsapp_parser_manifest["manifest_sha256"],
            )
            self.assertTrue(whatsapp_uplift["large_data_controls"]["whatsapp_source_row_citation_present"])
            self.assertTrue(whatsapp_uplift["large_data_controls"]["whatsapp_review_viewer_controls_present"])
            self.assertEqual(
                whatsapp_uplift["functional_priority_profile"]["implemented_controls"][
                    "whatsapp_parser_manifest_hash"
                ],
                whatsapp_parser_manifest["manifest_sha256"],
            )
            self.assertIn(
                "whatsapp-parser-manifest-emitted",
                whatsapp_uplift["functional_priority_profile"]["passed_validation_check_ids"],
            )
            self.assertIn(
                "whatsapp-source-locator-emitted",
                whatsapp_uplift["functional_priority_profile"]["passed_validation_check_ids"],
            )
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
            self.assertTrue(telegram["details"]["validation_checks"]["telegram_review_profile_emitted"])
            self.assertTrue(telegram["details"]["validation_checks"]["telegram_message_hash_present"])
            self.assertTrue(telegram["details"]["validation_checks"]["telegram_account_or_dialog_attribution_present"])
            self.assertTrue(telegram["details"]["validation_checks"]["telegram_media_cache_metadata_present"])
            telegram_review_profile = telegram["details"]["telegram_message_review_profile"]
            self.assertEqual(telegram_review_profile["media_class"], "image")
            self.assertTrue(telegram_review_profile["dialog_id_present"])
            self.assertTrue(telegram_review_profile["author_present"])
            self.assertEqual(telegram_review_profile["local_store_decryption_status"], "not-performed")
            self.assertEqual(
                telegram_review_profile["review_display_mode"],
                "chat-bubble-row-with-account-cache-metadata-collapsed",
            )
            telegram_gate = {gate["gap_id"]: gate for gate in telegram["details"]["core_accuracy_gates"]}["#33"]
            self.assertIn("Telegram service/profile detection", telegram_gate["satisfied_checks"])
            self.assertIn("chat/user/media attribution", telegram_gate["satisfied_checks"])
            self.assertIn("Telegram message review profile", telegram_gate["satisfied_checks"])
            self.assertIn("Telegram account/dialog attribution tracking", telegram_gate["satisfied_checks"])
            self.assertIn("Telegram media/cache metadata tracking", telegram_gate["satisfied_checks"])
            self.assertIn("Telegram export/cache strategy profile", telegram_gate["satisfied_checks"])
            self.assertIn("Telegram parser manifest", telegram_gate["satisfied_checks"])
            self.assertIn("Telegram source row citation", telegram_gate["satisfied_checks"])
            self.assertIn("Telegram review viewer controls", telegram_gate["satisfied_checks"])
            self.assertIn("encrypted local store warning", telegram_gate["satisfied_checks"])
            self.assertEqual(
                telegram["details"]["chat_app_strategy_profile"]["selected_track"],
                "telegram-export-cache-account-attribution",
            )
            telegram_parser_manifest = telegram["details"]["telegram_parser_manifest"]
            self.assertEqual(telegram_parser_manifest["manifest_version"], "telegram-parser-manifest-v1")
            self.assertEqual(telegram_parser_manifest["item_number"], 33)
            self.assertEqual(telegram_parser_manifest["gap_id"], "#33")
            self.assertEqual(telegram_parser_manifest["qc_prep_item_number"], 39)
            self.assertEqual(telegram_parser_manifest["service"], "Telegram")
            self.assertEqual(
                telegram_parser_manifest["row_citation"]["source_viewer_locator"]["viewer"],
                "telegram-message-row",
            )
            self.assertIn("row_hash", telegram_parser_manifest["row_citation"])
            self.assertTrue(telegram_parser_manifest["message_review"]["account_or_dialog_attribution_present"])
            self.assertTrue(telegram_parser_manifest["message_review"]["dialog_id_present"])
            self.assertTrue(telegram_parser_manifest["message_review"]["author_present"])
            self.assertEqual(telegram_parser_manifest["message_review"]["media_class"], "image")
            self.assertFalse(telegram_parser_manifest["validation"]["local_store_decryption_complete"])
            self.assertEqual(
                telegram_parser_manifest["large_data_controls"]["viewer_default"],
                "conversation-grouped-virtualized-chat-review",
            )
            self.assertEqual(len(telegram_parser_manifest["manifest_sha256"]), 64)
            self.assertEqual(
                telegram["details"]["telegram_parser_manifest_hash"],
                telegram_parser_manifest["manifest_sha256"],
            )
            self.assertEqual(telegram["details"]["chat_app_commercial_uplift_evidence"]["item_numbers"], [33])
            self.assertEqual(
                telegram["details"]["chat_app_commercial_uplift_evidence"]["qc_prep_item_numbers"],
                [39],
            )
            self.assertEqual(
                telegram["details"]["chat_app_commercial_uplift_evidence"]["large_data_controls"][
                    "telegram_parser_manifest_hash"
                ],
                telegram_parser_manifest["manifest_sha256"],
            )
            self.assertTrue(
                telegram["details"]["chat_app_commercial_uplift_evidence"]["large_data_controls"][
                    "telegram_source_row_citation_present"
                ]
            )
            self.assertTrue(
                telegram["details"]["chat_app_commercial_uplift_evidence"]["large_data_controls"][
                    "telegram_review_viewer_controls_present"
                ]
            )
            self.assertEqual(
                telegram["details"]["chat_app_commercial_uplift_evidence"]["functional_priority_profile"][
                    "implemented_controls"
                ]["telegram_parser_manifest_hash"],
                telegram_parser_manifest["manifest_sha256"],
            )
            self.assertIn(
                "telegram-parser-manifest-emitted",
                telegram["details"]["chat_app_commercial_uplift_evidence"]["functional_priority_profile"][
                    "passed_validation_check_ids"
                ],
            )
            self.assertIn(
                "telegram-source-locator-emitted",
                telegram["details"]["chat_app_commercial_uplift_evidence"]["functional_priority_profile"][
                    "passed_validation_check_ids"
                ],
            )
            self.assertTrue(
                telegram["details"]["chat_app_commercial_uplift_evidence"]["large_data_controls"][
                    "telegram_message_review_profile_present"
                ]
            )
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
            self.assertTrue(signal["details"]["validation_checks"]["signal_review_profile_emitted"])
            self.assertTrue(signal["details"]["validation_checks"]["signal_message_hash_present"])
            self.assertTrue(signal["details"]["validation_checks"]["signal_thread_or_recipient_attribution_present"])
            self.assertTrue(signal["details"]["validation_checks"]["signal_attachment_metadata_present"])
            signal_review_profile = signal["details"]["signal_message_review_profile"]
            self.assertEqual(signal_review_profile["attachment_class"], "audio")
            self.assertTrue(signal_review_profile["thread_id_present"])
            self.assertTrue(signal_review_profile["recipient_id_present"])
            self.assertEqual(signal_review_profile["sqlcipher_key_authority_status"], "not-attached")
            self.assertEqual(
                signal_review_profile["review_display_mode"],
                "chat-bubble-row-with-recipient-sqlcipher-metadata-collapsed",
            )
            signal_gate = {gate["gap_id"]: gate for gate in signal["details"]["core_accuracy_gates"]}["#34"]
            self.assertIn("Signal service/profile detection", signal_gate["satisfied_checks"])
            self.assertIn("thread/recipient/message inventory", signal_gate["satisfied_checks"])
            self.assertIn("Signal message review profile", signal_gate["satisfied_checks"])
            self.assertIn("Signal thread/recipient attribution tracking", signal_gate["satisfied_checks"])
            self.assertIn("Signal attachment metadata tracking", signal_gate["satisfied_checks"])
            self.assertIn("Signal SQLCipher strategy profile", signal_gate["satisfied_checks"])
            self.assertIn("Signal parser manifest", signal_gate["satisfied_checks"])
            self.assertIn("Signal source row citation", signal_gate["satisfied_checks"])
            self.assertIn("Signal review viewer controls", signal_gate["satisfied_checks"])
            self.assertIn("SQLCipher/key authority gate", signal_gate["satisfied_checks"])
            self.assertEqual(
                signal["details"]["chat_app_strategy_profile"]["selected_track"],
                "signal-sqlcipher-authority-gated-inventory",
            )
            signal_parser_manifest = signal["details"]["signal_parser_manifest"]
            self.assertEqual(signal_parser_manifest["manifest_version"], "signal-parser-manifest-v1")
            self.assertEqual(signal_parser_manifest["item_number"], 34)
            self.assertEqual(signal_parser_manifest["gap_id"], "#34")
            self.assertEqual(signal_parser_manifest["qc_prep_item_number"], 40)
            self.assertEqual(signal_parser_manifest["service"], "Signal")
            self.assertEqual(
                signal_parser_manifest["row_citation"]["source_viewer_locator"]["viewer"],
                "signal-message-row",
            )
            self.assertIn("row_hash", signal_parser_manifest["row_citation"])
            self.assertTrue(signal_parser_manifest["message_review"]["thread_or_recipient_attribution_present"])
            self.assertTrue(signal_parser_manifest["message_review"]["thread_id_present"])
            self.assertTrue(signal_parser_manifest["message_review"]["recipient_id_present"])
            self.assertEqual(signal_parser_manifest["message_review"]["attachment_class"], "audio")
            self.assertEqual(signal_parser_manifest["message_review"]["sqlcipher_key_authority_status"], "not-attached")
            self.assertFalse(signal_parser_manifest["validation"]["sqlcipher_key_authority_attached"])
            self.assertEqual(
                signal_parser_manifest["large_data_controls"]["viewer_default"],
                "conversation-grouped-virtualized-chat-review",
            )
            self.assertEqual(len(signal_parser_manifest["manifest_sha256"]), 64)
            self.assertEqual(
                signal["details"]["signal_parser_manifest_hash"],
                signal_parser_manifest["manifest_sha256"],
            )
            self.assertEqual(signal["details"]["chat_app_commercial_uplift_evidence"]["item_numbers"], [34])
            self.assertEqual(
                signal["details"]["chat_app_commercial_uplift_evidence"]["qc_prep_item_numbers"],
                [40],
            )
            self.assertEqual(
                signal["details"]["chat_app_commercial_uplift_evidence"]["large_data_controls"][
                    "signal_parser_manifest_hash"
                ],
                signal_parser_manifest["manifest_sha256"],
            )
            self.assertTrue(
                signal["details"]["chat_app_commercial_uplift_evidence"]["large_data_controls"][
                    "signal_source_row_citation_present"
                ]
            )
            self.assertTrue(
                signal["details"]["chat_app_commercial_uplift_evidence"]["large_data_controls"][
                    "signal_review_viewer_controls_present"
                ]
            )
            self.assertEqual(
                signal["details"]["chat_app_commercial_uplift_evidence"]["functional_priority_profile"][
                    "implemented_controls"
                ]["signal_parser_manifest_hash"],
                signal_parser_manifest["manifest_sha256"],
            )
            self.assertIn(
                "signal-parser-manifest-emitted",
                signal["details"]["chat_app_commercial_uplift_evidence"]["functional_priority_profile"][
                    "passed_validation_check_ids"
                ],
            )
            self.assertIn(
                "signal-source-locator-emitted",
                signal["details"]["chat_app_commercial_uplift_evidence"]["functional_priority_profile"][
                    "passed_validation_check_ids"
                ],
            )
            self.assertTrue(
                signal["details"]["chat_app_commercial_uplift_evidence"]["large_data_controls"][
                    "signal_message_review_profile_present"
                ]
            )
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
            self.assertIn("extended messenger message review profile", line_gate["satisfied_checks"])
            self.assertIn("extended messenger thread/channel attribution tracking", line_gate["satisfied_checks"])
            self.assertIn("extended messenger attachment metadata tracking", line_gate["satisfied_checks"])
            self.assertIn("extended messenger schema/ephemeral strategy profile", line_gate["satisfied_checks"])
            self.assertIn("extended messenger parser manifest", line_gate["satisfied_checks"])
            self.assertIn("extended messenger source row citation", line_gate["satisfied_checks"])
            self.assertIn("extended messenger review viewer controls", line_gate["satisfied_checks"])
            self.assertIn("schema/app version registry", line_gate["satisfied_checks"])
            line_profile = line["details"]["extended_messenger_message_review_profile"]
            self.assertEqual(line_profile["service"], "LINE")
            self.assertEqual(line_profile["source_track"], "line-export-database-schema-review")
            self.assertEqual(line_profile["attachment_class"], "image")
            self.assertTrue(line_profile["thread_or_channel_attribution_present"])
            self.assertTrue(line_profile["account_or_actor_attribution_present"])
            self.assertTrue(line["details"]["validation_checks"]["extended_messenger_review_profile_emitted"])
            self.assertTrue(line["details"]["validation_checks"]["extended_messenger_thread_or_channel_present"])
            self.assertTrue(line["details"]["validation_checks"]["extended_messenger_attachment_metadata_present"])
            self.assertEqual(
                line["details"]["chat_app_strategy_profile"]["selected_track"],
                "extended-service-export-schema-validation",
            )
            line_manifest = line["details"]["extended_messenger_parser_manifest"]
            self.assertEqual(line_manifest["manifest_version"], "extended-messenger-parser-manifest-v1")
            self.assertEqual(line_manifest["item_number"], 35)
            self.assertEqual(line_manifest["gap_id"], "#35")
            self.assertEqual(line_manifest["qc_prep_item_number"], 41)
            self.assertIn("LINE, Discord, Instagram, and WeChat", line_manifest["qc_prep_item_goal"])
            self.assertEqual(line_manifest["service"], "LINE")
            self.assertEqual(line_manifest["row_citation"]["source_viewer_locator"]["viewer"], "extended-messenger-message-row")
            self.assertEqual(len(line_manifest["row_citation"]["row_hash"]), 64)
            self.assertEqual(line_manifest["message_review"]["attachment_class"], "image")
            self.assertTrue(line_manifest["message_review"]["thread_or_channel_attribution_present"])
            self.assertTrue(line_manifest["large_data_controls"]["metadata_collapsed_by_default"])
            self.assertEqual(line_manifest["large_data_controls"]["viewer_default"], "service-grouped-virtualized-chat-review")
            self.assertFalse(line_manifest["validation"]["commercial_grade"])
            self.assertFalse(line_manifest["validation"]["trusted_export_or_native_db_diff_attached"])
            self.assertEqual(
                line["details"]["extended_messenger_parser_manifest_hash"],
                line_manifest["manifest_sha256"],
            )
            line_uplift = line["details"]["chat_app_commercial_uplift_evidence"]
            self.assertEqual(line_uplift["item_numbers"], [35])
            self.assertEqual(line_uplift["qc_prep_item_numbers"], [41])
            self.assertEqual(line_uplift["qc_prep_contracts"][0]["item_number"], 41)
            self.assertEqual(line_uplift["functional_priority_profile"]["item_number"], 50)
            self.assertEqual(line_uplift["functional_priority_profile"]["qc_prep_item_numbers"], [41])
            self.assertIn("schema-version-known-answer", line_uplift["failed_issue_matrix_ids"])
            self.assertEqual(
                line_uplift["reportability_decision"]["allowed_use"],
                "extended-messenger-export-triage-pivot",
            )
            self.assertEqual(line_uplift["reportability_decision"]["qc_prep_item_numbers"], [41])
            self.assertTrue(
                line_uplift["large_data_controls"]["extended_messenger_message_review_profile_present"]
            )
            self.assertEqual(
                line_uplift["large_data_controls"]["extended_messenger_parser_manifest_hash"],
                line_manifest["manifest_sha256"],
            )
            self.assertTrue(line_uplift["large_data_controls"]["extended_messenger_source_row_citation_present"])
            self.assertTrue(line_uplift["large_data_controls"]["extended_messenger_review_viewer_controls_present"])
            self.assertIn(
                "extended-messenger-parser-manifest-emitted",
                line_uplift["functional_priority_profile"]["passed_validation_check_ids"],
            )
            self.assertIn(
                "extended-messenger-source-locator-emitted",
                line_uplift["functional_priority_profile"]["passed_validation_check_ids"],
            )
            self.assertEqual(
                line_uplift["functional_priority_profile"]["implemented_controls"][
                    "extended_messenger_parser_manifest_hash"
                ],
                line_manifest["manifest_sha256"],
            )
            self.assertTrue(
                line_uplift["functional_priority_profile"]["implemented_controls"][
                    "extended_messenger_row_citation_present"
                ]
            )
            for service in ("Discord", "Instagram"):
                artifact = next(artifact for artifact in chat_messages if artifact["details"]["service"] == service)
                profile = artifact["details"]["extended_messenger_message_review_profile"]
                self.assertEqual(profile["service"], service)
                self.assertTrue(profile["thread_or_channel_attribution_present"])
                self.assertTrue(artifact["details"]["validation_checks"]["extended_messenger_review_profile_emitted"])
                manifest = artifact["details"]["extended_messenger_parser_manifest"]
                self.assertEqual(manifest["manifest_version"], "extended-messenger-parser-manifest-v1")
                self.assertEqual(manifest["service"], service)
                self.assertEqual(manifest["gap_id"], "#35")
                self.assertEqual(manifest["qc_prep_item_number"], 41)
                self.assertEqual(manifest["manifest_sha256"], artifact["details"]["extended_messenger_parser_manifest_hash"])

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
            ios_review = ios_file["details"]["mobile_analyst_review_profile"]
            self.assertEqual(ios_review["profile_version"], "mobile-analyst-review-profile-v1")
            self.assertEqual(ios_review["gap_ids"], ["#27"])
            self.assertEqual(ios_review["artifact_type"], "ios-backup-file")
            self.assertIn("decrypted iOS protected file contents", ios_review["not_proof_of"])
            self.assertIn("mobile timeline", ios_review["correlation_targets"])
            self.assertFalse(ios_file["details"]["mobile_native_capabilities"]["ios_protected_file_decryption"])
            ios_gate = ios_file["details"]["core_accuracy_gates"][0]
            self.assertEqual(ios_gate["gap_id"], "#27")
            self.assertIn("Manifest.db domain/fileID mapping", ios_gate["satisfied_checks"])
            self.assertIn("iOS backup scope/file profile", ios_gate["satisfied_checks"])
            self.assertIn("encrypted backup authority gate", ios_gate["satisfied_checks"])
            self.assertIn("app database schema detection", ios_gate["satisfied_checks"])
            self.assertIn("deleted-record limitation warning", ios_gate["satisfied_checks"])
            self.assertIn("iOS backup parser manifest", ios_gate["satisfied_checks"])
            self.assertIn("iOS backup source locator", ios_gate["satisfied_checks"])
            self.assertEqual(ios_file["details"]["ios_backup_file_profile"]["category"], "message-or-chat-store")
            ios_manifest = ios_file["details"]["ios_backup_parser_manifest"]
            self.assertEqual(ios_manifest["manifest_version"], "ios-backup-parser-manifest-v1")
            self.assertEqual(ios_manifest["item_number"], 53)
            self.assertEqual(ios_manifest["qc_prep_item_number"], 46)
            self.assertIn("Manifest.db", ios_manifest["qc_prep_item_goal"])
            self.assertEqual(ios_manifest["source_viewer_locator"]["viewer"], "ios-manifest-file-row")
            self.assertEqual(ios_manifest["manifest_row"]["file_id"], "abcdef123456")
            self.assertEqual(ios_manifest["manifest_row"]["category"], "message-or-chat-store")
            self.assertEqual(len(ios_manifest["manifest_sha256"]), 64)
            self.assertEqual(ios_file["details"]["ios_backup_parser_manifest_hash"], ios_manifest["manifest_sha256"])
            ios_uplift = ios_file["details"]["commercial_uplift_evidence"]
            self.assertEqual(ios_uplift["item_numbers"], [27])
            self.assertEqual(ios_uplift["qc_prep_item_numbers"], [46])
            self.assertEqual(ios_uplift["qc_prep_contracts"][0]["item_number"], 46)
            ios_profiles = {profile["item_number"]: profile for profile in ios_uplift["functional_priority_profiles"]}
            self.assertIn(52, ios_profiles)
            self.assertIn(53, ios_profiles)
            self.assertEqual(ios_profiles[53]["batch_id"], "commercial-uplift-051-055")
            self.assertEqual(ios_profiles[53]["qc_prep_item_numbers"], [46])
            self.assertTrue(ios_profiles[53]["implemented_controls"]["encrypted_backup_lawful_key_workflow_required"])
            self.assertEqual(
                ios_profiles[53]["implemented_controls"]["ios_backup_parser_manifest_hash"],
                ios_manifest["manifest_sha256"],
            )
            self.assertIn("ios-backup-parser-manifest-emitted", ios_profiles[53]["passed_validation_check_ids"])
            self.assertIn("ios-backup-source-locator-emitted", ios_profiles[53]["passed_validation_check_ids"])
            self.assertEqual(
                ios_uplift["large_data_controls"]["ios_backup_parser_manifest_hash"],
                ios_manifest["manifest_sha256"],
            )
            self.assertTrue(ios_uplift["large_data_controls"]["ios_backup_source_locator_present"])
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
            self.assertEqual(ios_uplift["reportability_decision"]["qc_prep_item_numbers"], [46])

            ios_metadata = next(
                artifact
                for artifact in payload["artifacts"]
                if artifact["artifact_type"] == "ios-backup-metadata"
                and artifact["details"]["plist_name"] == "Info.plist"
            )
            metadata_gate = ios_metadata["details"]["core_accuracy_gates"][0]
            self.assertEqual(metadata_gate["gap_id"], "#27")
            self.assertIn("Info/Status plist consistency", metadata_gate["satisfied_checks"])
            ios_source = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "ios-backup-source")
            self.assertEqual(ios_source["details"]["ios_backup_scope_profile"]["manifest_row_count"], 1)
            self.assertEqual(ios_source["details"]["ios_backup_scope_profile"]["domain_count"], 1)
            root_profile = ios_source["details"]["ios_backup_root_profile"]
            self.assertTrue(root_profile["required_files_present"])
            self.assertEqual(root_profile["validation_status"], "inventory-ready")
            self.assertEqual(root_profile["device_name"], "Alice iPhone")
            self.assertEqual(root_profile["product_version"], "18.4")
            self.assertEqual(root_profile["snapshot_state"], "finished")
            self.assertTrue(root_profile["is_full_backup"])
            self.assertTrue(root_profile["required_files"]["Manifest.db"]["sha256"])
            self.assertTrue(root_profile["required_files"]["Info.plist"]["sha256"])
            self.assertTrue(root_profile["keychain_file"]["present"])
            self.assertTrue(ios_source["details"]["validation_checks"]["backup_root_profile_emitted"])
            self.assertTrue(ios_source["details"]["validation_checks"]["required_backup_files_present"])
            source_ios_gate = ios_source["details"]["core_accuracy_gates"][0]
            self.assertIn("backup root integrity/status profile", source_ios_gate["satisfied_checks"])
            source_manifest = ios_source["details"]["ios_backup_parser_manifest"]
            self.assertEqual(source_manifest["source_viewer_locator"]["viewer"], "ios-backup-source-summary")
            self.assertTrue(source_manifest["backup_root"]["required_files_present"])
            deep_manifest = ios_source["details"]["ios_backup_deep_parser_manifest"]
            self.assertEqual(deep_manifest["manifest_version"], "ios-backup-deep-parser-manifest-v1")
            self.assertEqual(deep_manifest["item_number"], 27)
            self.assertEqual(deep_manifest["gap_id"], "#27")
            self.assertEqual(deep_manifest["source_viewer_locator"]["viewer"], "ios-backup-deep-parser-source")
            self.assertEqual(len(deep_manifest["manifest_sha256"]), 64)
            self.assertEqual(
                ios_source["details"]["ios_backup_deep_parser_manifest_hash"],
                deep_manifest["manifest_sha256"],
            )
            self.assertTrue(deep_manifest["root_integrity"]["required_files_present"])
            self.assertEqual(deep_manifest["device_metadata"]["device_name"], "Alice iPhone")
            self.assertEqual(deep_manifest["manifest_db"]["manifest_row_count"], 1)
            self.assertEqual(deep_manifest["app_database_candidates"]["candidate_count"], 1)
            self.assertEqual(deep_manifest["app_database_candidates"]["message_store_candidate_count"], 1)
            self.assertTrue(deep_manifest["capability_statement"]["app_database_candidate_detection"])
            self.assertFalse(deep_manifest["capability_statement"]["file_payload_decode"])
            self.assertFalse(deep_manifest["validation"]["commercial_grade"])
            self.assertIn("trusted-ios-backup-parser-diff-required", deep_manifest["commercial_blockers"])
            self.assertIn("iOS backup deep parser manifest", source_ios_gate["satisfied_checks"])
            self.assertIn("iOS backup deep parser source locator", source_ios_gate["satisfied_checks"])
            source_uplift = ios_source["details"]["commercial_uplift_evidence"]
            self.assertEqual(
                source_uplift["large_data_controls"]["ios_backup_deep_parser_manifest_hash"],
                deep_manifest["manifest_sha256"],
            )
            self.assertTrue(source_uplift["large_data_controls"]["ios_backup_deep_parser_source_locator_present"])
            source_ios_profiles = {
                profile["item_number"]: profile for profile in source_uplift["functional_priority_profiles"]
            }
            self.assertEqual(
                source_ios_profiles[53]["implemented_controls"]["ios_backup_deep_parser_manifest_hash"],
                deep_manifest["manifest_sha256"],
            )
            self.assertIn(
                "ios-backup-deep-parser-manifest-emitted",
                source_ios_profiles[53]["passed_validation_check_ids"],
            )

            keychain = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "ios-keychain-inventory")
            self.assertFalse(keychain["details"]["validation_checks"]["secrets_extracted"])
            self.assertTrue(keychain["details"]["validation_checks"]["values_redacted"])
            self.assertIn("sensitive-artifact-redacted", keychain["details"]["risk_flags"])
            self.assertIn("#28", keychain["details"]["mobile_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(keychain["details"]["forensic_review"]["gap_id"], "#28")
            keychain_review = keychain["details"]["mobile_analyst_review_profile"]
            self.assertEqual(keychain_review["profile_version"], "mobile-analyst-review-profile-v1")
            self.assertEqual(keychain_review["gap_ids"], ["#28"])
            self.assertEqual(keychain_review["artifact_type"], "ios-keychain-inventory")
            self.assertEqual(keychain_review["severity"], "high")
            self.assertIn("keychain secret values or access semantics", keychain_review["not_proof_of"])
            self.assertFalse(keychain["details"]["mobile_native_capabilities"]["ios_keychain_secret_decryption"])
            keychain_gate = keychain["details"]["core_accuracy_gates"][0]
            self.assertEqual(keychain_gate["gap_id"], "#28")
            self.assertIn("secret values redacted by default", keychain_gate["satisfied_checks"])
            self.assertIn("keychain scope/table profile", keychain_gate["satisfied_checks"])
            self.assertIn("protected-data class labeling", keychain_gate["satisfied_checks"])
            self.assertIn("authority gate before reveal/decrypt", keychain_gate["satisfied_checks"])
            self.assertIn("secret reveal authority profile", keychain_gate["satisfied_checks"])
            self.assertIn("record count/table inventory", keychain_gate["satisfied_checks"])
            self.assertIn("iOS backup parser manifest", keychain_gate["satisfied_checks"])
            self.assertIn("iOS keychain source locator", keychain_gate["satisfied_checks"])
            self.assertIn("iOS keychain deep inventory manifest", keychain_gate["satisfied_checks"])
            self.assertIn("iOS keychain deep inventory source locator", keychain_gate["satisfied_checks"])
            self.assertIn("audit log for any controlled reveal", keychain_gate["satisfied_checks"])
            keychain_uplift = keychain["details"]["commercial_uplift_evidence"]
            self.assertEqual(keychain_uplift["item_numbers"], [28])
            keychain_manifest = keychain["details"]["ios_backup_parser_manifest"]
            self.assertEqual(keychain_manifest["source_viewer_locator"]["viewer"], "ios-keychain-table-inventory")
            self.assertFalse(keychain_manifest["keychain_inventory"]["secret_reveal_allowed"])
            self.assertTrue(keychain_manifest["lawful_key_workflow"]["protected_values_redacted_by_default"])
            keychain_deep_manifest = keychain["details"]["ios_keychain_deep_inventory_manifest"]
            self.assertEqual(
                keychain_deep_manifest["manifest_version"],
                "ios-keychain-deep-inventory-manifest-v1",
            )
            self.assertEqual(keychain_deep_manifest["item_number"], 28)
            self.assertEqual(keychain_deep_manifest["gap_id"], "#28")
            self.assertEqual(
                keychain_deep_manifest["source_viewer_locator"]["viewer"],
                "ios-keychain-deep-inventory",
            )
            self.assertEqual(len(keychain_deep_manifest["manifest_sha256"]), 64)
            self.assertEqual(
                keychain["details"]["ios_keychain_deep_inventory_manifest_hash"],
                keychain_deep_manifest["manifest_sha256"],
            )
            self.assertEqual(keychain_deep_manifest["scope"]["table_class_counts"]["generic-password"], 1)
            self.assertGreaterEqual(keychain_deep_manifest["scope"]["protected_value_column_count"], 1)
            self.assertTrue(keychain_deep_manifest["redaction_policy"]["values_redacted"])
            self.assertFalse(keychain_deep_manifest["redaction_policy"]["secrets_extracted"])
            self.assertFalse(keychain_deep_manifest["authority_gate"]["secret_reveal_allowed"])
            self.assertFalse(keychain_deep_manifest["capability_statement"]["secret_value_decryption"])
            self.assertFalse(keychain_deep_manifest["validation"]["commercial_grade"])
            self.assertIn("trusted-keychain-inventory-diff-required", keychain_deep_manifest["commercial_blockers"])
            keychain_scope = keychain["details"]["ios_keychain_scope_profile"]
            self.assertEqual(keychain_scope["sensitive_table_names"], ["genp"])
            self.assertEqual(keychain_scope["table_class_counts"]["generic-password"], 1)
            self.assertIn("data", keychain_scope["sensitive_column_names"])
            self.assertGreaterEqual(keychain_scope["protected_value_column_count"], 1)
            self.assertTrue(keychain_scope["redaction_policy"]["values_redacted"])
            self.assertFalse(keychain_scope["redaction_policy"]["secrets_extracted"])
            self.assertEqual(keychain_scope["table_inventory_validation_status"], "inventory-ready")
            authority_gate = keychain["details"]["ios_keychain_authority_gate"]
            self.assertFalse(authority_gate["secret_reveal_allowed"])
            self.assertTrue(authority_gate["audit_required_before_reveal"])
            self.assertIn("generic-password", authority_gate["blocked_table_classes"])
            self.assertIn("data", authority_gate["blocked_sensitive_columns"])
            keychain_profiles = {
                profile["item_number"]: profile for profile in keychain_uplift["functional_priority_profiles"]
            }
            self.assertIn(53, keychain_profiles)
            self.assertTrue(keychain_profiles[53]["implemented_controls"]["keychain_redacted_inventory"])
            self.assertEqual(
                keychain_profiles[53]["implemented_controls"]["ios_keychain_deep_inventory_manifest_hash"],
                keychain_deep_manifest["manifest_sha256"],
            )
            self.assertIn(
                "ios-keychain-deep-inventory-manifest-emitted",
                keychain_profiles[53]["passed_validation_check_ids"],
            )
            self.assertTrue(keychain_uplift["large_data_controls"]["protected_values_redacted_by_default"])
            self.assertEqual(
                keychain_uplift["large_data_controls"]["ios_keychain_deep_inventory_manifest_hash"],
                keychain_deep_manifest["manifest_sha256"],
            )
            self.assertTrue(
                keychain_uplift["large_data_controls"]["ios_keychain_deep_inventory_source_locator_present"]
            )
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
            whatsapp_db_profile = chat_db["details"]["whatsapp_database_review_profile"]
            self.assertIn("messages", whatsapp_db_profile["message_table_candidates"])
            self.assertTrue(whatsapp_db_profile["msgstore_shape_present"])
            self.assertEqual(whatsapp_db_profile["crypt_key_authority_status"], "not-attached")
            whatsapp_db_parser_manifest = chat_db["details"]["whatsapp_parser_manifest"]
            self.assertEqual(whatsapp_db_parser_manifest["row_citation"]["source_viewer_locator"]["viewer"], "whatsapp-msgstore-inventory")
            self.assertTrue(whatsapp_db_parser_manifest["database_review"]["msgstore_shape_present"])
            self.assertIn("messages", whatsapp_db_parser_manifest["database_review"]["message_table_candidates"])
            self.assertIn("messages", whatsapp_db_parser_manifest["database_review"]["jid_table_candidates"])
            self.assertEqual(
                chat_db["details"]["whatsapp_parser_manifest_hash"],
                whatsapp_db_parser_manifest["manifest_sha256"],
            )
            chat_db_manifest = chat_db["details"]["messenger_export_framework_manifest"]
            self.assertEqual(chat_db_manifest["artifact_type"], "mobile-chat-database")
            self.assertEqual(chat_db_manifest["table_summary_count"], 1)
            self.assertEqual(chat_db_manifest["table_citation_count"], 1)
            self.assertEqual(chat_db_manifest["table_citations"][0]["table_name"], "messages")
            self.assertEqual(
                chat_db_manifest["table_citations"][0]["source_viewer_locator"]["viewer"],
                "sqlite-table-inventory",
            )
            self.assertIn(
                "messenger table citation inventory",
                {gate["gap_id"]: gate for gate in chat_db["details"]["core_accuracy_gates"]}["#32"][
                    "satisfied_checks"
                ],
            )

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
            timeline_profile = messenger_summary["details"]["mobile_timeline_correlation_profile"]
            self.assertEqual(timeline_profile["profile_version"], "mobile-timeline-correlation-v1")
            self.assertGreaterEqual(timeline_profile["event_count"], messenger_summary["details"]["message_count"])
            self.assertGreaterEqual(timeline_profile["message_event_count"], messenger_summary["details"]["message_count"])
            self.assertGreaterEqual(timeline_profile["message_media_link_count"], 1)
            self.assertGreaterEqual(timeline_profile["unresolved_media_link_count"], 1)
            self.assertFalse(timeline_profile["device_wide_timeline_ready"])
            self.assertTrue(timeline_profile["known_answer_correlation_required"])
            self.assertLessEqual(len(timeline_profile["events"]), timeline_profile["event_cap"])
            citation_manifest = messenger_summary["details"]["mobile_correlation_citation_manifest"]
            self.assertEqual(
                citation_manifest["manifest_version"],
                "mobile-correlation-citation-manifest-v1",
            )
            self.assertEqual(citation_manifest["item_number"], 43)
            self.assertEqual(
                messenger_summary["details"]["mobile_correlation_citation_manifest_hash"],
                citation_manifest["manifest_sha256"],
            )
            self.assertGreaterEqual(citation_manifest["row_citation_count"], messenger_summary["details"]["message_count"])
            self.assertGreaterEqual(citation_manifest["timeline_event_citation_count"], 1)
            self.assertGreaterEqual(citation_manifest["message_media_link_citation_count"], 1)
            self.assertEqual(
                citation_manifest["timeline_event_citations"][0]["source_viewer_locator"]["viewer"],
                "mobile-correlation-timeline-event",
            )
            self.assertEqual(
                citation_manifest["message_media_link_citations"][0]["source_viewer_locator"]["viewer"],
                "mobile-message-media-link",
            )
            self.assertIn(
                "mobile-correlation-citation-manifest-emitted",
                citation_manifest["passed_validation_check_ids"],
            )
            self.assertIn("device-wide-timeline-not-validated", citation_manifest["failed_validation_check_ids"])
            self.assertGreaterEqual(messenger_summary["details"]["unified_contact_call_sms_view_count"], 2)
            actor_profile = messenger_summary["details"]["mobile_actor_review_profile"]
            self.assertEqual(actor_profile["profile_version"], "mobile-actor-review-v1")
            self.assertGreaterEqual(actor_profile["actor_count"], 2)
            self.assertGreaterEqual(actor_profile["review_queue_count"], 1)
            self.assertFalse(actor_profile["device_wide_identity_resolution_ready"])
            self.assertTrue(actor_profile["merge_split_review_required"])
            self.assertTrue(actor_profile["known_answer_actor_diff_required"])
            self.assertLessEqual(len(actor_profile["review_queue"]), actor_profile["review_queue_count"])
            actor_citation_manifest = messenger_summary["details"]["mobile_actor_citation_manifest"]
            self.assertEqual(actor_citation_manifest["manifest_version"], "mobile-actor-citation-manifest-v1")
            self.assertEqual(actor_citation_manifest["item_number"], 44)
            self.assertEqual(
                messenger_summary["details"]["mobile_actor_citation_manifest_hash"],
                actor_citation_manifest["manifest_sha256"],
            )
            self.assertGreaterEqual(actor_citation_manifest["actor_entry_count"], 2)
            self.assertFalse(actor_citation_manifest["raw_actor_values_serialized"])
            self.assertIn(
                "actor-values-hashed-in-manifest",
                actor_citation_manifest["passed_validation_check_ids"],
            )
            self.assertEqual(
                actor_citation_manifest["actor_entries"][0]["source_viewer_locator"]["viewer"],
                "mobile-actor-review",
            )
            self.assertIn(
                "mobile-actor-vendor-report-diff-required",
                actor_citation_manifest["failed_validation_check_ids"],
            )
            self.assertGreaterEqual(messenger_summary["details"]["schema_version_registry_count"], 1)
            schema_profile = messenger_summary["details"]["mobile_schema_compatibility_profile"]
            self.assertEqual(schema_profile["profile_version"], "mobile-schema-compatibility-v1")
            self.assertGreaterEqual(schema_profile["entry_count"], 1)
            self.assertGreaterEqual(schema_profile["unvalidated_entry_count"], 1)
            self.assertTrue(schema_profile["known_answer_fixture_required"])
            self.assertTrue(schema_profile["schema_migration_matrix_required"])
            self.assertTrue(schema_profile["commercial_release_blocked"])
            self.assertGreaterEqual(schema_profile["release_gate_entry_count"], 1)
            schema_manifest = messenger_summary["details"]["mobile_schema_version_manifest"]
            self.assertEqual(schema_manifest["manifest_version"], "mobile-schema-version-manifest-v1")
            self.assertEqual(schema_manifest["item_number"], 45)
            self.assertEqual(
                messenger_summary["details"]["mobile_schema_version_manifest_hash"],
                schema_manifest["manifest_sha256"],
            )
            self.assertGreaterEqual(schema_manifest["schema_entry_count"], 1)
            self.assertTrue(schema_manifest["release_gate_blocked"])
            self.assertIn(
                "mobile-schema-version-manifest-emitted",
                schema_manifest["passed_validation_check_ids"],
            )
            self.assertEqual(
                schema_manifest["schema_entries"][0]["source_viewer_locator"]["viewer"],
                "mobile-schema-version-review",
            )
            self.assertIn(
                "schema-version-registry-known-answer-not-attached",
                schema_manifest["failed_validation_check_ids"],
            )
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
            self.assertIn("timeline correlation profile", correlation_gates["#43"]["satisfied_checks"])
            self.assertIn("correlation citation manifest", correlation_gates["#43"]["satisfied_checks"])
            self.assertIn("timeline event source citations", correlation_gates["#43"]["satisfied_checks"])
            self.assertIn("message-media link citations", correlation_gates["#43"]["satisfied_checks"])
            self.assertIn("known-answer limitation warning", correlation_gates["#43"]["satisfied_checks"])
            self.assertIn("contact/call/SMS actor merge", correlation_gates["#44"]["satisfied_checks"])
            self.assertIn("participant attribution", correlation_gates["#44"]["satisfied_checks"])
            self.assertIn("actor review profile", correlation_gates["#44"]["satisfied_checks"])
            self.assertIn("actor citation manifest", correlation_gates["#44"]["satisfied_checks"])
            self.assertIn("actor source viewer locators", correlation_gates["#44"]["satisfied_checks"])
            self.assertIn("actor values hashed in manifest", correlation_gates["#44"]["satisfied_checks"])
            self.assertIn("merge/split review requirement", correlation_gates["#44"]["satisfied_checks"])
            self.assertIn("export-scope limitation warning", correlation_gates["#44"]["satisfied_checks"])
            self.assertIn("app/service schema version registry", correlation_gates["#45"]["satisfied_checks"])
            self.assertIn("schema compatibility profile", correlation_gates["#45"]["satisfied_checks"])
            self.assertIn("schema version manifest", correlation_gates["#45"]["satisfied_checks"])
            self.assertIn("schema source viewer locators", correlation_gates["#45"]["satisfied_checks"])
            self.assertIn("source app/version attribution", correlation_gates["#45"]["satisfied_checks"])
            self.assertIn("schema release gates recorded", correlation_gates["#45"]["satisfied_checks"])
            self.assertIn("release-gate limitation disclosure", correlation_gates["#45"]["satisfied_checks"])
            correlation_uplift = messenger_summary["details"]["mobile_correlation_commercial_uplift_evidence"]
            self.assertEqual(correlation_uplift["batch_id"], "commercial-uplift-041-045")
            self.assertEqual(correlation_uplift["item_numbers"], [43, 44, 45])
            self.assertIn("media_message_links_built", correlation_uplift["passed_validation_check_ids"])
            self.assertIn("unified_contact_call_sms_view_built", correlation_uplift["passed_validation_check_ids"])
            self.assertIn("actor_review_profile_built", correlation_uplift["passed_validation_check_ids"])
            self.assertIn("timeline_correlation_profile_built", correlation_uplift["passed_validation_check_ids"])
            self.assertIn("schema_version_registry_built", correlation_uplift["passed_validation_check_ids"])
            self.assertIn("schema_compatibility_profile_built", correlation_uplift["passed_validation_check_ids"])
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
            self.assertTrue(correlation_uplift["large_data_controls"]["timeline_profile_present"])
            self.assertTrue(correlation_uplift["large_data_controls"]["citation_manifest_present"])
            self.assertEqual(
                correlation_uplift["large_data_controls"]["citation_manifest_hash"],
                citation_manifest["manifest_sha256"],
            )
            self.assertGreaterEqual(correlation_uplift["large_data_controls"]["timeline_event_citation_count"], 1)
            self.assertGreaterEqual(correlation_uplift["large_data_controls"]["message_media_link_citation_count"], 1)
            self.assertGreaterEqual(correlation_uplift["large_data_controls"]["timeline_event_count"], 1)
            self.assertTrue(correlation_uplift["large_data_controls"]["actor_review_profile_present"])
            self.assertTrue(correlation_uplift["large_data_controls"]["actor_citation_manifest_present"])
            self.assertEqual(
                correlation_uplift["large_data_controls"]["actor_citation_manifest_hash"],
                actor_citation_manifest["manifest_sha256"],
            )
            self.assertGreaterEqual(correlation_uplift["large_data_controls"]["actor_citation_entry_count"], 2)
            self.assertFalse(correlation_uplift["large_data_controls"]["raw_actor_values_serialized"])
            self.assertGreaterEqual(correlation_uplift["large_data_controls"]["actor_review_queue_count"], 1)
            self.assertTrue(correlation_uplift["large_data_controls"]["schema_compatibility_profile_present"])
            self.assertGreaterEqual(correlation_uplift["large_data_controls"]["schema_compatibility_entry_count"], 1)
            self.assertTrue(correlation_uplift["large_data_controls"]["schema_release_gate_blocked"])
            self.assertTrue(correlation_uplift["large_data_controls"]["schema_version_manifest_present"])
            self.assertEqual(
                correlation_uplift["large_data_controls"]["schema_version_manifest_hash"],
                schema_manifest["manifest_sha256"],
            )
            self.assertGreaterEqual(correlation_uplift["large_data_controls"]["schema_version_manifest_entry_count"], 1)
            self.assertTrue(correlation_uplift["large_data_controls"]["schema_version_manifest_release_gate_blocked"])
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
    cellebrite_hash = hashlib.sha256(cellebrite.read_bytes()).hexdigest()
    (cellebrite.parent / "export-metadata.json").write_text(
        json.dumps(
            {
                "vendor_tool": "Cellebrite Physical Analyzer",
                "vendor_tool_version": "7.66",
                "parser_version": "PA-7.66-schema",
                "schema_version": "messages-v1",
                "source_sha256": cellebrite_hash,
                "original_acquisition_sha256": "c" * 64,
                "export_settings": {"timezone": "UTC", "include_deleted": True},
            }
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

    behavior = root / "AXIOM" / "location_health_screen_time.json"
    behavior.write_text(
        json.dumps(
            [
                {
                    "Timestamp": "2026-04-26T04:00:00Z",
                    "LatitudeE7": 374220000,
                    "LongitudeE7": -1220840575,
                    "Accuracy": "12",
                    "Source Device": "Alice iPhone",
                },
                {
                    "Timestamp": "2026-04-26T05:00:00Z",
                    "Steps": "1234",
                    "Unit": "count",
                    "Source Device": "Alice Watch",
                },
                {
                    "Timestamp": "2026-04-26T06:00:00Z",
                    "App Name": "KakaoTalk",
                    "Screen Time": "600",
                    "Source Device": "Alice iPhone",
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
                    "Sender": "15550100@s.whatsapp.net",
                    "Recipient": "15550200@s.whatsapp.net",
                    "Text": "WhatsApp exported chat",
                    "Media Path": "/WhatsApp/Media/IMG-0001.jpg",
                    "App Version": "2.26.1",
                    "Timestamp": "2026-04-26T05:01:00Z",
                },
                {
                    "Service": "Telegram",
                    "Conversation ID": "tg-dialog-1",
                    "Chat Title": "Ops",
                    "Message ID": "tg-msg-1",
                    "Author": "alice",
                    "Text": "Telegram desktop export",
                    "Media Path": "/Telegram Desktop/tdata/cache/photo_1.jpg",
                    "Source File": "result.json",
                    "Timestamp": "2026-04-26T05:02:00Z",
                },
                {
                    "Service": "Signal",
                    "Thread ID": "signal-thread-1",
                    "Message ID": "signal-msg-1",
                    "From": "alice",
                    "To": "signal-recipient-1",
                    "Body": "Signal backup row",
                    "Media Path": "/Signal/Attachments/voice-note.ogg",
                    "App Version": "7.45.0",
                    "Timestamp": "2026-04-26T05:03:00Z",
                },
                {
                    "Service": "LINE",
                    "Room ID": "line-room-1",
                    "Message ID": "line-msg-1",
                    "Sender": "alice",
                    "Content": "LINE export row",
                    "Media Path": "/LINE/Images/sticker-1.png",
                    "App Version": "15.1.0",
                    "Timestamp": "2026-04-26T05:04:00Z",
                },
                {
                    "Service": "Discord",
                    "Channel ID": "discord-channel-1",
                    "Message ID": "discord-msg-1",
                    "Author": "alice",
                    "Message": "Discord data package row",
                    "Attachment URL": "https://cdn.discordapp.com/attachments/example/file.pdf",
                    "Edited At": "2026-04-26T05:05:30Z",
                    "Timestamp": "2026-04-26T05:05:00Z",
                },
                {
                    "Service": "Instagram",
                    "Thread ID": "instagram-thread-1",
                    "Message ID": "ig-msg-1",
                    "Sender": "alice",
                    "Text": "Instagram direct export row",
                    "Media Path": "/instagram/messages/inbox/photo.jpg",
                    "Ephemeral": "vanish_mode_possible",
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
    with contextlib.closing(sqlite3.connect(whatsapp_db)) as connection:
        connection.execute("CREATE TABLE messages (_id INTEGER, key_remote_jid TEXT, from_me INTEGER, data TEXT, timestamp INTEGER)")
        connection.execute("INSERT INTO messages VALUES (?, ?, ?, ?, ?)", (1, "15550100@s.whatsapp.net", 0, "redacted", 1777180000000))
        connection.commit()

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
    with contextlib.closing(sqlite3.connect(manifest)) as connection:
        connection.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER)")
        connection.execute(
            "INSERT INTO Files VALUES (?, ?, ?, ?)",
            ("abcdef123456", "AppDomain-com.apple.MobileSMS", "Library/SMS/sms.db", 1),
        )
        connection.commit()

    keychain = ios_backup / "keychain-2.db"
    with contextlib.closing(sqlite3.connect(keychain)) as connection:
        connection.execute("CREATE TABLE genp (agrp TEXT, svce TEXT, acct TEXT, data BLOB)")
        connection.execute("INSERT INTO genp VALUES (?, ?, ?, ?)", ("test", "example", "alice", b"secret-not-exported"))
        connection.commit()


if __name__ == "__main__":
    unittest.main()
