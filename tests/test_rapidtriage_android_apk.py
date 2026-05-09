from __future__ import annotations

import contextlib
import json
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path

from rapidtriage.artifacts.android import build_android_trusted_diff, android_core_accuracy_gates
from rapidtriage.cli import build_parser, main


class RapidTriageAndroidApkTests(unittest.TestCase):
    def test_parser_exposes_android_apk_collector_kind(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices
        help_text = commands["artifacts"].format_help()

        self.assertIn("android-apk", help_text)

    def test_android_apk_artifacts_collect_manifest_permissions_hashes_and_risk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            apk_path = root / "exports" / "suspicious.apk"
            apk_path.parent.mkdir()
            write_apk_fixture(apk_path)
            app_data_path = root / "Android" / "data" / "com.example.spy" / "files" / "browser_messages_media.db"
            app_data_path.parent.mkdir(parents=True)
            with contextlib.closing(sqlite3.connect(app_data_path)) as connection:
                connection.execute("CREATE TABLE sms_messages (id INTEGER PRIMARY KEY, address TEXT, body TEXT, media_url TEXT)")
                connection.execute(
                    "INSERT INTO sms_messages (address, body, media_url) VALUES (?, ?, ?)",
                    ("01000000000", "redacted", "content://media/external/images/1"),
                )
                connection.commit()
            output = root / "apk-artifacts.json"

            exit_code = main(["artifacts", str(root), "--kind", "android-apk", "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["kind"], "android-apk")
            self.assertEqual(payload["provider"]["name"], "android-apk-artifacts")
            self.assertEqual(payload["summary"]["artifact_count"], 2)
            artifact = next(item for item in payload["artifacts"] if item["artifact_type"] == "android-apk")
            details = artifact["details"]
            self.assertEqual(artifact["artifact_type"], "android-apk")
            self.assertEqual(details["package"], "com.example.spy")
            self.assertEqual(details["version_name"], "1.2.3")
            self.assertIn("android.permission.SEND_SMS", details["permissions"])
            self.assertIn("android.permission.SEND_SMS", details["dangerous_permissions"])
            self.assertIn("dangerous-permissions", details["risk_flags"])
            self.assertIn("native-code", details["risk_flags"])
            self.assertIn("suspicious-code-strings", details["risk_flags"])
            self.assertIn("network-indicators", details["risk_flags"])
            self.assertEqual(details["dex_count"], 2)
            self.assertEqual(details["native_library_count"], 1)
            self.assertEqual(details["native_architectures"], ["arm64-v8a"])
            self.assertEqual(details["component_counts"]["service"], 1)
            self.assertEqual(details["component_counts"]["receiver"], 1)
            self.assertEqual(details["apk_analysis_profile"]["dangerous_permission_count"], 2)
            self.assertEqual(details["apk_analysis_profile"]["signature_chain_validation_status"], "signature-entry-inventory-only")
            self.assertEqual(details["apk_analysis_profile"]["signing_block_entry_count"], 3)
            self.assertEqual(details["apk_signing_inventory"]["entry_count"], 3)
            self.assertTrue(details["apk_signing_inventory"]["signature_block_present"])
            self.assertTrue(details["apk_signing_inventory"]["signature_file_present"])
            self.assertTrue(details["apk_signing_inventory"]["jar_manifest_present"])
            self.assertFalse(details["apk_signing_inventory"]["certificate_chain_parsed"])
            self.assertTrue(details["entry_hashes"])
            self.assertFalse(details["commercial_grade_ready"])
            self.assertIn("#30", details["android_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(details["forensic_review"]["gap_id"], "#30")
            self.assertFalse(details["android_native_capabilities"]["binary_manifest_decode"])
            self.assertFalse(details["validation_checks"]["commercial_validation_corpus"])
            self.assertTrue(any(item["value"] == "DexClassLoader" for item in details["string_pivots"]))
            self.assertTrue(any(item["value"] == "https://c2.example.test/payload" for item in details["string_pivots"]))
            self.assertTrue(any(item["value"] == "10.0.0.66" for item in details["string_pivots"]))
            self.assertIn("sha256", details["hashes"])
            self.assertGreater(details["risk_score"], 0)
            apk_gate = details["core_accuracy_gates"][0]
            self.assertEqual(apk_gate["gap_id"], "#30")
            self.assertIn("binary manifest decode or limitation", apk_gate["satisfied_checks"])
            self.assertIn("permission/component normalization", apk_gate["satisfied_checks"])
            self.assertIn("signature chain validation", apk_gate["satisfied_checks"])
            self.assertIn("DEX/native string pivot bounds", apk_gate["satisfied_checks"])
            self.assertIn("APK analysis profile", apk_gate["satisfied_checks"])
            self.assertIn("APK signing entry inventory", apk_gate["satisfied_checks"])
            self.assertIn("app-data schema and secret-handling warnings", apk_gate["satisfied_checks"])
            self.assertIn("Android parser manifest", apk_gate["satisfied_checks"])
            self.assertIn("Android source locator", apk_gate["satisfied_checks"])
            self.assertIn("Android APK deep analysis manifest", apk_gate["satisfied_checks"])
            self.assertIn("Android APK deep analysis source locator", apk_gate["satisfied_checks"])
            android_manifest = details["android_parser_manifest"]
            self.assertEqual(android_manifest["manifest_version"], "android-backup-app-data-parser-manifest-v1")
            self.assertEqual(android_manifest["item_number"], 54)
            self.assertEqual(android_manifest["source_viewer_locator"]["viewer"], "android-apk-inventory")
            self.assertEqual(android_manifest["apk_inventory"]["dex_count"], 2)
            self.assertEqual(android_manifest["apk_inventory"]["dangerous_permission_count"], 2)
            self.assertEqual(len(android_manifest["manifest_sha256"]), 64)
            self.assertEqual(details["android_parser_manifest_hash"], android_manifest["manifest_sha256"])
            apk_deep_manifest = details["android_apk_deep_analysis_manifest"]
            self.assertEqual(apk_deep_manifest["manifest_version"], "android-apk-deep-analysis-manifest-v1")
            self.assertEqual(apk_deep_manifest["item_number"], 30)
            self.assertEqual(apk_deep_manifest["gap_id"], "#30")
            self.assertEqual(apk_deep_manifest["source_viewer_locator"]["viewer"], "android-apk-deep-analysis")
            self.assertEqual(len(apk_deep_manifest["manifest_sha256"]), 64)
            self.assertEqual(
                details["android_apk_deep_analysis_manifest_hash"],
                apk_deep_manifest["manifest_sha256"],
            )
            self.assertEqual(apk_deep_manifest["manifest_inventory"]["dangerous_permission_count"], 2)
            self.assertEqual(apk_deep_manifest["code_inventory"]["dex_count"], 2)
            self.assertEqual(apk_deep_manifest["code_inventory"]["native_library_count"], 1)
            self.assertTrue(apk_deep_manifest["signing_inventory"]["signature_block_present"])
            self.assertFalse(apk_deep_manifest["signing_inventory"]["certificate_chain_parsed"])
            self.assertEqual(apk_deep_manifest["risk_and_reportability"]["malware_verdict"], "not-assessed")
            self.assertFalse(apk_deep_manifest["capability_statement"]["signature_chain_validation"])
            self.assertFalse(apk_deep_manifest["validation"]["commercial_grade"])
            self.assertIn("trusted-aapt-apkanalyzer-mobsf-diff-required", apk_deep_manifest["commercial_blockers"])
            apk_review = details["android_analyst_review_profile"]
            self.assertEqual(apk_review["profile_version"], "android-analyst-review-profile-v1")
            self.assertEqual(apk_review["gap_ids"], ["#30"])
            self.assertEqual(apk_review["artifact_type"], "android-apk")
            self.assertIn("aapt/apkanalyzer/MobSF/ALEAPP diff", apk_review["correlation_targets"])
            self.assertIn("malware verdict", apk_review["not_proof_of"])
            self.assertFalse(apk_review["report_grade_ready"])
            apk_uplift = details["commercial_uplift_evidence"]
            self.assertEqual(apk_uplift["batch_id"], "commercial-uplift-026-030")
            self.assertEqual(apk_uplift["item_numbers"], [30])
            self.assertIn("source-readable", apk_uplift["passed_validation_matrix_ids"])
            self.assertIn("signature-and-binary-manifest", apk_uplift["failed_validation_matrix_ids"])
            self.assertEqual(apk_uplift["large_data_controls"]["apk_string_scan_limit"], 1024 * 1024)
            self.assertTrue(apk_uplift["large_data_controls"]["apk_profile_present"])
            self.assertEqual(
                apk_uplift["large_data_controls"]["android_parser_manifest_hash"],
                android_manifest["manifest_sha256"],
            )
            self.assertEqual(
                apk_uplift["large_data_controls"]["android_apk_deep_analysis_manifest_hash"],
                apk_deep_manifest["manifest_sha256"],
            )
            self.assertTrue(apk_uplift["large_data_controls"]["android_apk_deep_analysis_source_locator_present"])
            self.assertTrue(apk_uplift["large_data_controls"]["android_source_locator_present"])
            apk_profiles = {profile["item_number"]: profile for profile in apk_uplift["functional_priority_profiles"]}
            self.assertEqual(
                apk_profiles[54]["implemented_controls"]["android_apk_deep_analysis_manifest_hash"],
                apk_deep_manifest["manifest_sha256"],
            )
            self.assertIn(
                "android-apk-deep-analysis-manifest-emitted",
                apk_profiles[54]["passed_validation_check_ids"],
            )
            self.assertEqual(
                apk_uplift["reportability_decision"]["decision"],
                "do-not-report-android-apk-as-malware-or-signature-validated",
            )
            self.assertEqual(
                apk_uplift["reportability_decision"]["allowed_use"],
                "android-apk-risk-inventory-triage-pivot",
            )
            self.assertIn(
                "binary-manifest-or-signature-not-validated",
                apk_uplift["reportability_decision"]["blockers"],
            )

            app_data = next(item for item in payload["artifacts"] if item["artifact_type"] == "android-app-data")
            self.assertEqual(app_data["details"]["package"], "com.example.spy")
            self.assertEqual(app_data["details"]["data_category"], "database")
            self.assertIn("communication-store-candidate", app_data["details"]["risk_flags"])
            self.assertIn("browser-store-candidate", app_data["details"]["risk_flags"])
            self.assertIn("media-store-candidate", app_data["details"]["risk_flags"])
            self.assertFalse(app_data["details"]["validation_checks"]["secret_values_extracted"])
            self.assertTrue(app_data["details"]["validation_checks"]["sqlite_schema_inventory_present"])
            self.assertTrue(app_data["details"]["validation_checks"]["sample_values_redacted"])
            self.assertTrue(app_data["details"]["validation_checks"]["android_artifact_matrix_present"])
            self.assertTrue(app_data["details"]["android_app_data_profile"]["sqlite_header_present"])
            self.assertEqual(app_data["details"]["android_app_data_profile"]["candidate_store_family"], "communication")
            app_data_profile = app_data["details"]["android_app_data_profile"]
            sqlite_inventory = app_data_profile["sqlite_schema_inventory"]
            self.assertTrue(sqlite_inventory["opened_readonly"])
            self.assertEqual(sqlite_inventory["table_count"], 1)
            self.assertEqual(sqlite_inventory["tables"][0]["table"], "sms_messages")
            self.assertEqual(sqlite_inventory["tables"][0]["row_count"], 1)
            self.assertEqual(sqlite_inventory["tables"][0]["artifact_family"], "message-or-chat")
            self.assertTrue(sqlite_inventory["values_redacted"])
            self.assertIn("sms", app_data_profile["artifact_family_matrix"]["positive_families"])
            self.assertIn("media", app_data_profile["artifact_family_matrix"]["positive_families"])
            self.assertEqual(app_data_profile["source_layout_profile"]["layout"], "external-app-data")
            self.assertIn("#29", app_data["details"]["android_report_grade_assessment"]["commercial_gap_ids"])
            self.assertIn("#30", app_data["details"]["android_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(app_data["details"]["forensic_review"]["gap_id"], "#29")
            self.assertFalse(app_data["details"]["android_native_capabilities"]["app_specific_database_decode"])
            app_data_gates = {gate["gap_id"]: gate for gate in app_data["details"]["core_accuracy_gates"]}
            self.assertIn("package/path attribution", app_data_gates["#29"]["satisfied_checks"])
            self.assertIn("SMS/call/contact row validation", app_data_gates["#29"]["satisfied_checks"])
            self.assertIn("browser/media source linkage", app_data_gates["#29"]["satisfied_checks"])
            self.assertIn("encrypted-store limitation", app_data_gates["#29"]["satisfied_checks"])
            self.assertIn("app-specific schema version tracking", app_data_gates["#29"]["satisfied_checks"])
            self.assertIn("android app-data profile", app_data_gates["#29"]["satisfied_checks"])
            self.assertIn("SQLite schema inventory without value extraction", app_data_gates["#29"]["satisfied_checks"])
            self.assertIn("Android artifact family matrix", app_data_gates["#29"]["satisfied_checks"])
            self.assertIn("backup/filesystem layout classification", app_data_gates["#29"]["satisfied_checks"])
            self.assertIn("Android parser manifest", app_data_gates["#29"]["satisfied_checks"])
            self.assertIn("Android source locator", app_data_gates["#29"]["satisfied_checks"])
            self.assertIn("Android app-data deep parser manifest", app_data_gates["#29"]["satisfied_checks"])
            self.assertIn("Android app-data deep parser source locator", app_data_gates["#29"]["satisfied_checks"])
            self.assertIn("app-data schema and secret-handling warnings", app_data_gates["#30"]["satisfied_checks"])
            app_data_manifest = app_data["details"]["android_parser_manifest"]
            self.assertEqual(app_data_manifest["source_viewer_locator"]["viewer"], "android-app-data-inventory")
            self.assertEqual(app_data_manifest["app_data_inventory"]["sqlite_table_count"], 1)
            self.assertTrue(app_data_manifest["app_data_inventory"]["values_redacted"])
            self.assertFalse(app_data_manifest["secret_and_schema_boundary"]["secret_values_extracted"])
            app_data_deep_manifest = app_data["details"]["android_app_data_deep_parser_manifest"]
            self.assertEqual(
                app_data_deep_manifest["manifest_version"],
                "android-app-data-deep-parser-manifest-v1",
            )
            self.assertEqual(app_data_deep_manifest["item_number"], 29)
            self.assertEqual(app_data_deep_manifest["gap_id"], "#29")
            self.assertEqual(
                app_data_deep_manifest["source_viewer_locator"]["viewer"],
                "android-app-data-deep-parser",
            )
            self.assertEqual(len(app_data_deep_manifest["manifest_sha256"]), 64)
            self.assertEqual(
                app_data["details"]["android_app_data_deep_parser_manifest_hash"],
                app_data_deep_manifest["manifest_sha256"],
            )
            self.assertEqual(app_data_deep_manifest["source_layout"]["layout"], "external-app-data")
            self.assertTrue(app_data_deep_manifest["sqlite_inventory"]["opened_readonly"])
            self.assertEqual(app_data_deep_manifest["sqlite_inventory"]["table_count"], 1)
            self.assertEqual(
                app_data_deep_manifest["sqlite_inventory"]["table_summaries"][0]["artifact_family"],
                "message-or-chat",
            )
            self.assertIn("sms", app_data_deep_manifest["artifact_family_matrix"]["positive_families"])
            self.assertTrue(app_data_deep_manifest["capability_statement"]["sqlite_schema_inventory"])
            self.assertFalse(app_data_deep_manifest["capability_statement"]["app_specific_database_decode"])
            self.assertFalse(app_data_deep_manifest["redaction_and_secret_boundary"]["secret_values_extracted"])
            self.assertFalse(app_data_deep_manifest["validation"]["commercial_grade"])
            self.assertIn(
                "trusted-aleapp-or-vendor-export-diff-required",
                app_data_deep_manifest["commercial_blockers"],
            )
            app_data_review = app_data["details"]["android_analyst_review_profile"]
            self.assertEqual(app_data_review["profile_version"], "android-analyst-review-profile-v1")
            self.assertEqual(app_data_review["gap_ids"], ["#29", "#30"])
            self.assertEqual(app_data_review["artifact_type"], "android-app-data")
            self.assertIn("decoded app-specific message/account contents", app_data_review["not_proof_of"])
            self.assertIn("mobile timeline", app_data_review["correlation_targets"])
            app_data_uplift = app_data["details"]["commercial_uplift_evidence"]
            self.assertEqual(app_data_uplift["item_numbers"], [29, 30])
            app_data_profiles = {
                profile["item_number"]: profile for profile in app_data_uplift["functional_priority_profiles"]
            }
            self.assertIn(52, app_data_profiles)
            self.assertIn(54, app_data_profiles)
            self.assertEqual(app_data_profiles[54]["batch_id"], "commercial-uplift-051-055")
            self.assertFalse(app_data_profiles[54]["implemented_controls"]["secret_values_extracted"])
            self.assertEqual(
                app_data_profiles[54]["implemented_controls"]["android_parser_manifest_hash"],
                app_data_manifest["manifest_sha256"],
            )
            self.assertEqual(
                app_data_profiles[54]["implemented_controls"]["android_app_data_deep_parser_manifest_hash"],
                app_data_deep_manifest["manifest_sha256"],
            )
            self.assertIn("android-parser-manifest-emitted", app_data_profiles[54]["passed_validation_check_ids"])
            self.assertIn("android-source-locator-emitted", app_data_profiles[54]["passed_validation_check_ids"])
            self.assertIn(
                "android-app-data-deep-parser-manifest-emitted",
                app_data_profiles[54]["passed_validation_check_ids"],
            )
            self.assertIn("manifest-or-package-context", app_data_uplift["passed_validation_matrix_ids"])
            self.assertIn("app-data-report-grade", app_data_uplift["failed_validation_matrix_ids"])
            self.assertFalse(app_data_uplift["large_data_controls"]["secret_values_extracted"])
            self.assertTrue(app_data_uplift["large_data_controls"]["android_app_data_profile_present"])
            self.assertEqual(
                app_data_uplift["reportability_decision"]["decision"],
                "do-not-report-android-app-data-as-decoded-content",
            )
            self.assertEqual(
                app_data_uplift["reportability_decision"]["allowed_use"],
                "android-app-data-inventory-triage-pivot",
            )
            self.assertEqual(
                app_data_uplift["large_data_controls"]["android_app_data_deep_parser_manifest_hash"],
                app_data_deep_manifest["manifest_sha256"],
            )
            self.assertTrue(
                app_data_uplift["large_data_controls"][
                    "android_app_data_deep_parser_source_locator_present"
                ]
            )
            self.assertIn(
                "app-data-schema-or-deleted-record-validation-missing",
                app_data_uplift["reportability_decision"]["blockers"],
            )

    def test_android_trusted_diffs_gate_app_data_and_apk_claims(self) -> None:
        app_data_diff = build_android_trusted_diff(
            29,
            [{"package": "com.example.spy", "source_path": "Android/data/com.example.spy/files/messages.db", "data_category": "database", "source_sha256": "a" * 64}],
            [{"Package": "com.example.spy", "Path": "Android/data/com.example.spy/files/messages.db", "Category": "database", "SHA256": "a" * 64}],
            trusted_tool="ALEAPP",
        )
        apk_diff = build_android_trusted_diff(
            30,
            [{"package": "com.example.spy", "source_path": "suspicious.apk", "manifest_format": "xml", "permission_count": 3, "dex_count": 2, "native_library_count": 1}],
            [{"PackageName": "com.example.spy", "FilePath": "suspicious.apk", "Manifest": "xml", "Permissions": 3, "DexCount": 2, "NativeLibraries": 1}],
            trusted_tool="apkanalyzer",
        )

        self.assertEqual(app_data_diff["status"], "pass")
        self.assertEqual(apk_diff["status"], "pass")
        app_data_gate = android_core_accuracy_gates(
            29,
            {
                "source_path": "Android/data/com.example.spy/files/messages.db",
                "source_format": "android-export-file",
                "package": "com.example.spy",
                "risk_flags": ["communication-store-candidate", "browser-store-candidate", "media-store-candidate"],
                "validation_checks": {"secret_values_extracted": False, "app_specific_schema_version_tracked": True},
                "app_schema_profile": {"schema_version": "unknown"},
                "commercial_grade_blockers": ["app-specific-schema-required"],
                "android_trusted_diff": app_data_diff,
            },
        )[0]
        self.assertIn("trusted Android artifact export diff pass", app_data_gate["satisfied_checks"])
        apk_gate = android_core_accuracy_gates(
            30,
            {
                "source_path": "suspicious.apk",
                "source_format": "apk",
                "package": "com.example.spy",
                "manifest_format": "xml",
                "permissions": ["android.permission.SEND_SMS"],
                "component_counts": {"service": 1},
                "certificate_entries": ["META-INF/CERT.RSA"],
                "dex_count": 2,
                "native_library_count": 1,
                "string_pivots": [{"type": "url", "value": "https://c2.example.test"}],
                "legal_warning": "triage only",
                "commercial_grade_blockers": ["signature-chain-required"],
                "android_trusted_diff": apk_diff,
            },
        )[0]
        self.assertIn("trusted APK/tool analysis diff pass", apk_gate["satisfied_checks"])

    def test_android_trusted_diff_blocks_unknown_tools_and_mismatches(self) -> None:
        diff = build_android_trusted_diff(
            30,
            [{"package": "com.example.spy", "source_path": "suspicious.apk", "manifest_format": "xml", "dex_count": 2}],
            [{"Package": "com.example.spy", "Path": "suspicious.apk", "Manifest": "xml", "DexCount": 3}],
            trusted_tool="unknown-tool",
        )

        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["trusted_tool_recognized"])
        self.assertEqual(diff["mismatch_count"], 1)
        self.assertIn("apk-tool-analysis-trusted-diff-required", diff["reportability_decision"]["blockers"])


def write_apk_fixture(path: Path) -> None:
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.spy"
    android:versionName="1.2.3"
    android:versionCode="12">
  <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35" />
  <uses-permission android:name="android.permission.INTERNET" />
  <uses-permission android:name="android.permission.SEND_SMS" />
  <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
  <application android:label="Spy Sample">
    <service android:name=".SpyService" android:exported="false" />
    <receiver android:name=".BootReceiver" android:exported="true" />
  </application>
</manifest>
"""
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr(
            "classes.dex",
            b"dex\n035\x00"
            b"Ldalvik/system/DexClassLoader;"
            b"Runtime.getRuntime"
            b"https://c2.example.test/payload\x00"
            b"10.0.0.66",
        )
        archive.writestr("classes2.dex", b"dex\n035\x00")
        archive.writestr("lib/arm64-v8a/libpayload.so", b"\x7fELF")
        archive.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")
        archive.writestr("META-INF/CERT.SF", b"Signature-Version: 1.0\n")
        archive.writestr("META-INF/CERT.RSA", b"certificate")


if __name__ == "__main__":
    unittest.main()
