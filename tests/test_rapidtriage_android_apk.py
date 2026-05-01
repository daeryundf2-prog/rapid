from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

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
            app_data_path.write_bytes(b"SQLite format 3\x00message-store")
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
            self.assertIn("app-data schema and secret-handling warnings", apk_gate["satisfied_checks"])
            apk_uplift = details["commercial_uplift_evidence"]
            self.assertEqual(apk_uplift["batch_id"], "commercial-uplift-026-030")
            self.assertEqual(apk_uplift["item_numbers"], [30])
            self.assertIn("source-readable", apk_uplift["passed_validation_matrix_ids"])
            self.assertIn("signature-and-binary-manifest", apk_uplift["failed_validation_matrix_ids"])
            self.assertEqual(apk_uplift["large_data_controls"]["apk_string_scan_limit"], 1024 * 1024)

            app_data = next(item for item in payload["artifacts"] if item["artifact_type"] == "android-app-data")
            self.assertEqual(app_data["details"]["package"], "com.example.spy")
            self.assertEqual(app_data["details"]["data_category"], "database")
            self.assertIn("communication-store-candidate", app_data["details"]["risk_flags"])
            self.assertIn("browser-store-candidate", app_data["details"]["risk_flags"])
            self.assertIn("media-store-candidate", app_data["details"]["risk_flags"])
            self.assertFalse(app_data["details"]["validation_checks"]["secret_values_extracted"])
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
            self.assertIn("app-data schema and secret-handling warnings", app_data_gates["#30"]["satisfied_checks"])
            app_data_uplift = app_data["details"]["commercial_uplift_evidence"]
            self.assertEqual(app_data_uplift["item_numbers"], [29, 30])
            self.assertIn("manifest-or-package-context", app_data_uplift["passed_validation_matrix_ids"])
            self.assertIn("app-data-report-grade", app_data_uplift["failed_validation_matrix_ids"])
            self.assertFalse(app_data_uplift["large_data_controls"]["secret_values_extracted"])


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
        archive.writestr("META-INF/CERT.RSA", b"certificate")


if __name__ == "__main__":
    unittest.main()
