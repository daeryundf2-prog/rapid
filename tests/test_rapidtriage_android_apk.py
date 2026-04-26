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
            output = root / "apk-artifacts.json"

            exit_code = main(["artifacts", str(root), "--kind", "android-apk", "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["kind"], "android-apk")
            self.assertEqual(payload["provider"]["name"], "android-apk-artifacts")
            self.assertEqual(payload["summary"]["artifact_count"], 1)
            artifact = payload["artifacts"][0]
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
            self.assertTrue(any(item["value"] == "DexClassLoader" for item in details["string_pivots"]))
            self.assertTrue(any(item["value"] == "https://c2.example.test/payload" for item in details["string_pivots"]))
            self.assertTrue(any(item["value"] == "10.0.0.66" for item in details["string_pivots"]))
            self.assertIn("sha256", details["hashes"])
            self.assertGreater(details["risk_score"], 0)


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
  <application android:label="Spy Sample" />
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
