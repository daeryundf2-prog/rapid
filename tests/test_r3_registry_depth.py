"""R3 O1: registry depth rows (NetworkList, MountPoints2, WLAN, Office MRU, KnownDLLs, default
browser, PCA, FeatureUsage, install state), PCA text files and BitLocker recovery key files.

Every input is synthetic (``tests.registry_depth_fixtures``); the key value of the BitLocker
fixture must never appear in any output row.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from rapidtriage.artifacts.windows.antiforensics import (
    collect_bitlocker_recovery_key_files,
    mask_recovery_password,
    recovery_password_valid,
)
from rapidtriage.artifacts.windows.execution import WindowsExecutionProvider
from rapidtriage.artifacts.windows.pca import collect_pca_text_files
from rapidtriage.artifacts.windows.registry import WindowsRegistryProvider
from rapidtriage.artifacts.windows.registry_depth import (
    DEPTH_ARTIFACT_TYPES,
    DepthStats,
    ExportKeySource,
    decode_export_value,
    iter_depth_rows,
    systemtime_text,
)
from rapidtriage.artifacts.windows.system import WindowsSystemArtifactsProvider
from rapidtriage.core.artifact_domains import artifact_type_domain
from rapidtriage.core.timeline import TIMELINE_FIELD_MAP
from rapidtriage.core.triage_rules import load_catalog
from tests import registry_depth_fixtures as fx
from tests.test_parser_quality_registry import write_hive


def by_type(records: list, artifact_type: str) -> list[dict]:
    return [record.details for record in records if record.artifact_type == artifact_type]


class RegistryDepthHiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        base = Path(cls.temp.name)
        write_hive(base, "Windows/System32/config/SOFTWARE", fx.software_hive())
        write_hive(base, "Windows/System32/config/SYSTEM", fx.system_hive())
        write_hive(base, "Users/alice/NTUSER.DAT", fx.ntuser_hive())
        cls.records = list(WindowsRegistryProvider().collect(base))
        cls.hive_rows = [r for r in cls.records if r.artifact_type in DEPTH_ARTIFACT_TYPES]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def test_every_type_has_a_hive_row_with_provenance(self) -> None:
        counts = Counter(record.artifact_type for record in self.hive_rows)
        self.assertEqual(set(counts), set(DEPTH_ARTIFACT_TYPES))
        for record in self.hive_rows:
            details = record.details
            self.assertEqual(details["parser"], "windows-registry-depth")
            self.assertEqual(details["recovery_method"], "parsed")
            self.assertTrue(details["source_path"])
            self.assertIsInstance(details["source_offset"], int)
            self.assertEqual(details["source_format"], "registry-hive")

    def test_networklist_profile_joined_with_signature(self) -> None:
        rows = {row["profile_name"]: row for row in by_type(self.records, "registry-network-profile")}
        wired = rows["본사-유선"]
        self.assertEqual(wired["first_connected_at"], "2024-01-02T09:00:00")
        self.assertEqual(wired["last_connected_at"], "2024-05-01T18:30:15")
        self.assertEqual(wired["timestamp_timezone"], "local-unknown")
        self.assertEqual(wired["gateway_mac"], "00:11:22:aa:bb:cc")
        self.assertEqual(wired["dns_suffix"], "corp.example.com")
        self.assertEqual(wired["category_label"], "도메인(Domain)")
        self.assertEqual(wired["name_type_label"], "유선")
        self.assertEqual(wired["signature_scope"], "Managed")
        self.assertEqual(rows["Cafe_WiFi"]["gateway_mac"], "a0:b1:c2:d3:e4:f5")

    def test_wlan_rows_from_wlansvc_and_wireless_networklist(self) -> None:
        rows = {row["ssid"]: row for row in by_type(self.records, "registry-wlan-profile")}
        self.assertEqual(rows["HomeNet-5G"]["source_kind"], "wlansvc-profile")
        self.assertEqual(rows["HomeNet-5G"]["interface_guid"], fx.INTERFACE_GUID)
        self.assertEqual(rows["HomeNet-5G"]["profile_index"], 3)
        self.assertEqual(rows["Cafe_WiFi"]["source_kind"], "networklist-wireless")
        self.assertEqual(rows["Cafe_WiFi"]["last_connected_at"], "2024-04-30T21:05:00")

    def test_mountpoints2_mapped_drive_and_mru(self) -> None:
        rows = by_type(self.records, "registry-network-share")
        kinds = Counter((row["source_kind"], row["share_kind"]) for row in rows)
        self.assertEqual(
            kinds,
            Counter(
                {
                    ("mountpoints2", "network-share"): 1,
                    ("mountpoints2", "volume-guid"): 1,
                    ("map-network-drive-mru", "network-share"): 2,
                    ("network-drive", "network-share"): 1,
                }
            ),
        )
        mount = next(row for row in rows if row["source_kind"] == "mountpoints2" and row["is_network"])
        self.assertEqual(mount["share_path"], "\\\\fileserver\\인사팀")
        self.assertEqual(mount["share_server"], "fileserver")
        self.assertEqual(mount["mount_label"], "인사팀 공유")
        mru = sorted((row for row in rows if row["source_kind"] == "map-network-drive-mru"), key=lambda row: row["mru_position"])
        self.assertEqual([row["share_path"] for row in mru], ["\\\\fileserver\\인사팀", "\\\\nas01\\backup"])
        self.assertTrue(mru[0]["timestamp"])
        self.assertEqual(mru[1]["timestamp"], "")
        drive = next(row for row in rows if row["source_kind"] == "network-drive")
        self.assertEqual((drive["drive_letter"], drive["username"]), ("Z:", "CORP\\alice"))
        self.assertTrue(all(row["key_path"].startswith("HKU\\") or row["key_path"].startswith("HKCU") for row in rows))

    def test_office_mru_filetime_and_user_mru(self) -> None:
        rows = by_type(self.records, "registry-office-mru")
        self.assertEqual(len(rows), 3)  # "Item Metadata" values are not items
        payroll = next(row for row in rows if row["file_name"] == "급여대장.docx")
        self.assertEqual(payroll["last_opened_at"], "2024-03-04T05:06:07+00:00")
        self.assertEqual((payroll["office_version"], payroll["application"], payroll["mru_kind"]), ("16.0", "Word", "file"))
        self.assertEqual(payroll["mru_position"], 0)
        place = next(row for row in rows if row["mru_kind"] == "place")
        self.assertEqual(place["account_id"], "ADAL_ABCDEF")

    def test_known_dlls_baseline(self) -> None:
        rows = {row["value_name"]: row for row in by_type(self.records, "registry-known-dll")}
        self.assertFalse(rows["evilhook"]["in_default_baseline"])
        self.assertIn("known-dll-not-in-baseline", rows["evilhook"]["risk_flags"])
        self.assertTrue(rows["kernel32"]["in_default_baseline"])
        self.assertEqual(rows["DllDirectory"]["entry_kind"], "directory")
        self.assertEqual(rows["kernel32"]["control_set"], "ControlSet001")

    def test_default_browser_pca_feature_usage_install_state(self) -> None:
        browsers = {row["protocol"]: row["browser"] for row in by_type(self.records, "registry-default-browser")}
        self.assertEqual(browsers, {"http": "네이버 웨일", "https": "Google Chrome"})
        pca = by_type(self.records, "execution-pca")
        self.assertEqual(pca[0]["executable_name"], "sdelete64.exe")
        self.assertEqual(pca[0]["source_kind"], "pca-store")
        usage = {row["feature"]: row for row in by_type(self.records, "execution-feature-usage")}
        self.assertEqual(usage["AppSwitched"]["count"], 14)
        self.assertEqual(usage["AppLaunch"]["count"], 52)
        states = {row["state_source"]: row for row in by_type(self.records, "registry-install-state")}
        self.assertEqual(states["app-paths"]["executable_path"], r"C:\Program Files\VeraCrypt\VeraCrypt.exe")
        self.assertEqual(states["msi-product"]["display_version"], "16.0.4266.1001")
        self.assertEqual(states["msi-product"]["installer_sid"], "S-1-5-18")

    def test_hive_record_discloses_depth_summary(self) -> None:
        summaries = [
            record.details["native_walk"]["registry_depth"] for record in self.records if record.artifact_type == "registry-hive"
        ]
        self.assertTrue(summaries)
        self.assertTrue(all(summary["decoder_error_count"] == 0 for summary in summaries))


class RegistryDepthExportTests(unittest.TestCase):
    def test_reg_export_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "export.reg"
            path.write_bytes(fx.reg_export_text().encode("utf-16"))
            records = list(WindowsRegistryProvider().collect(Path(temp)))
        rows = [record.details for record in records if record.artifact_type in DEPTH_ARTIFACT_TYPES]
        self.assertTrue(all(row["source_format"] == "reg" and row["source_offset_unit"] == "line" for row in rows))
        types = Counter(record.artifact_type for record in records if record.artifact_type in DEPTH_ARTIFACT_TYPES)
        self.assertEqual(
            set(types),
            {
                "registry-network-profile",
                "registry-network-share",
                "registry-office-mru",
                "registry-default-browser",
                "execution-feature-usage",
                "execution-pca",
                "registry-known-dll",
                "registry-install-state",
            },
        )
        profile = next(row for row in rows if row.get("profile_name") == "지점-VPN")
        # The DateCreated hex value is continued on a second line ("\\" continuation).
        self.assertEqual(profile["first_connected_at"], "2024-02-03T08:15:00")
        self.assertEqual(profile["last_connected_at"], "2024-05-02T10:00:00")
        self.assertEqual(profile["gateway_mac"], "00:11:22:aa:bb:cc")
        self.assertEqual(profile["name_type_label"], "VPN")
        share = next(row for row in rows if row.get("share_path") == "\\\\nas02\\share")
        self.assertEqual(share["key_path"], "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\##nas02#share")
        office = next(row for row in rows if row.get("file_name") == "매출.xlsx")
        self.assertEqual(office["last_opened_at"], "2024-03-04T05:06:07+00:00")
        pca = next(row for row in rows if "executable_name" in row and row.get("source_kind") == "pca-store")
        self.assertEqual((pca["executable_name"], pca["user_sid"]), ("CCleaner64.exe", "S-1-5-21-9-9-9-1002"))
        app_path = next(row for row in rows if row.get("state_source") == "app-paths")
        self.assertEqual(app_path["executable_path"], r"C:\Tools\sdelete.exe")

    def test_export_value_decoding(self) -> None:
        self.assertEqual(decode_export_value('"a\\\\b \\"q\\""'), 'a\\b "q"')
        self.assertEqual(decode_export_value("dword:0000002a"), 42)
        self.assertEqual(decode_export_value("hex(b):01,00,00,00,00,00,00,00"), 1)
        self.assertEqual(decode_export_value("hex(7):61,00,00,00,62,00,00,00,00,00"), ["a", "b"])
        self.assertEqual(decode_export_value("hex(2):25,00,41,00,00,00"), "%A")
        self.assertEqual(decode_export_value("hex:de,ad"), b"\xde\xad")

    def test_corrupt_values_are_isolated(self) -> None:
        source = ExportKeySource("SOFTWARE", "HKLM\\SOFTWARE", "")
        base = r"Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{X}"
        source.add(base, {"ProfileName": "x", "DateCreated": b"\x01", "DateLastConnected": "not-bytes", "NameType": "zz"}, 1)
        source.add(r"Microsoft\Windows\CurrentVersion\App Paths\a.exe", {"": 7}, 2)
        stats = DepthStats()
        rows = list(iter_depth_rows(source, stats))
        self.assertEqual([row.artifact_type for row in rows], ["registry-network-profile", "registry-install-state"])
        self.assertEqual(rows[0].fields["first_connected_at"], "")
        self.assertEqual(stats.errors, [])
        self.assertEqual(systemtime_text(b"\xff" * 16), "")

    def test_corrupt_hive_does_not_stop_the_provider(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            blob = bytearray(fx.ntuser_hive())
            blob[4096 + 64 : 4096 + 4096] = b"\xa5" * (4096 - 64)  # trash the first hbin page
            write_hive(base, "Users/bob/NTUSER.DAT", bytes(blob))
            write_hive(base, "Windows/System32/config/SYSTEM", fx.system_hive())
            records = list(WindowsRegistryProvider().collect(base))
        self.assertTrue(by_type(records, "registry-known-dll"))


class PcaAndBitLockerFileTests(unittest.TestCase):
    def test_pca_text_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            pca = base / "Windows" / "appcompat" / "pca"
            pca.mkdir(parents=True)
            (pca / "PcaAppLaunchDic.txt").write_bytes(fx.pca_app_launch_dic())
            (pca / "PcaGeneralDb0.txt").write_bytes(fx.pca_general_db())
            (pca / "PcaGeneralDb1.txt").write_bytes(b"\xff\xfe" + "\x00\x01garbage".encode("utf-16-le"))
            rows = [record.details for record in collect_pca_text_files(base, "windows-execution")]
            provider_types = Counter(record.artifact_type for record in WindowsExecutionProvider().collect(base))
        self.assertEqual(provider_types["execution-pca"], 3)
        launch = [row for row in rows if row["source_kind"] == "pca-app-launch-dic"]
        self.assertEqual(len(launch), 2)
        bleach = next(row for row in launch if row["executable_name"] == "bleachbit.exe")
        self.assertEqual(bleach["last_run_at"], "2024-05-02T01:02:03.456+00:00")
        self.assertEqual(bleach["malformed_line_count"], 1)
        self.assertEqual(bleach["source_offset"], 1)
        general = next(row for row in rows if row["source_kind"] == "pca-general-db")
        self.assertEqual((general["executable_name"], general["vendor"], general["record_type"]), ("eraser.exe", "Eraser Project", "2"))
        self.assertEqual(general["event_at"], "2024-05-02T01:05:00.000+00:00")
        self.assertIn("0x1", general["message"])

    def test_bitlocker_key_files_never_store_the_key(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            usb = base / "E" / "keys"
            usb.mkdir(parents=True)
            (usb / f"BitLocker Recovery Key {fx.KEY_ID}.TXT").write_bytes(fx.bitlocker_key_text())
            (usb / f"BitLocker 복구 키 {fx.KEY_ID}.TXT").write_bytes(fx.bitlocker_key_text("ko"))
            (usb / f"{fx.KEY_ID}.BEK").write_bytes(fx.bek_file())
            (usb / "BitLocker Recovery Key broken.txt").write_bytes(b"\x00\x01\x02")
            (usb / "notes.txt").write_text(fx.RECOVERY_PASSWORD, encoding="utf-8")
            records = [r for r in WindowsSystemArtifactsProvider().collect(base) if r.artifact_type == "bitlocker-recovery-key-file"]
            direct = list(collect_bitlocker_recovery_key_files(base, "windows-system-artifacts"))
        self.assertEqual(len(records), 4)
        self.assertEqual(len(direct), 4)
        dumped = json.dumps([record.details for record in records], ensure_ascii=False)
        self.assertNotIn(fx.RECOVERY_PASSWORD, dumped)
        for group in fx.RECOVERY_PASSWORD.split("-")[:-1]:
            self.assertNotIn(f"-{group}-", dumped)
        rows = {record.details["file_name"]: record.details for record in records}
        english = rows[f"BitLocker Recovery Key {fx.KEY_ID}.TXT"]
        self.assertEqual(english["key_identifier"], fx.KEY_ID)
        self.assertTrue(english["identifier_matches_file_name"])
        self.assertEqual(english["key_masked"], "XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXX88")
        self.assertTrue(english["key_format_valid"])
        self.assertEqual(len(english["key_sha256"]), 64)
        self.assertFalse(english["key_value_stored"])
        self.assertEqual(rows[f"BitLocker 복구 키 {fx.KEY_ID}.TXT"]["language"], "ko")
        bek = rows[f"{fx.KEY_ID}.BEK"]
        self.assertEqual((bek["key_identifier"], bek["bek_header_valid"]), (fx.KEY_ID, True))
        self.assertEqual(bek["key_created_at"], "2024-01-10T03:00:00+00:00")
        self.assertNotIn(bytes(range(1, 33)).hex(), dumped)
        broken = rows["BitLocker Recovery Key broken.txt"]
        self.assertFalse(broken["key_present"])

    def test_recovery_password_helpers(self) -> None:
        self.assertTrue(recovery_password_valid(fx.RECOVERY_PASSWORD))
        self.assertFalse(recovery_password_valid("123456-" * 7 + "123457"))
        self.assertEqual(mask_recovery_password("111111-222222"), "XXXXXX-XXXX22")


class RunPipelineTests(unittest.TestCase):
    def test_run_writes_depth_rows_and_antiforensics_flags(self) -> None:
        from rapidtriage.artifacts import clear_collect_cache
        from rapidtriage.core.run import run_triage_mode

        clear_collect_cache()
        self.addCleanup(clear_collect_cache)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "case-root"
            write_hive(root, "Windows/System32/config/SOFTWARE", fx.software_hive())
            write_hive(root, "Windows/System32/config/SYSTEM", fx.system_hive())
            write_hive(root, "Users/alice/NTUSER.DAT", fx.ntuser_hive())
            pca = root / "Windows" / "appcompat" / "pca"
            pca.mkdir(parents=True)
            (pca / "PcaAppLaunchDic.txt").write_bytes(fx.pca_app_launch_dic())
            (root / "Users" / "alice" / "Documents").mkdir(parents=True)
            (root / "Users" / "alice" / "Documents" / f"BitLocker Recovery Key {fx.KEY_ID}.TXT").write_bytes(fx.bitlocker_key_text())
            output_dir = Path(temp) / "run-out"
            summary = run_triage_mode(root, mode="hacking", output_dir=output_dir)
            registry = json.loads(Path(summary["outputs"]["artifacts_windows-registry"]).read_text(encoding="utf-8"))
            counts = registry["summary"]["artifact_type_counts"]
            for artifact_type in DEPTH_ARTIFACT_TYPES:
                self.assertGreaterEqual(counts.get(artifact_type, 0), 1, artifact_type)
            execution = json.loads(Path(summary["outputs"]["artifacts_windows-execution"]).read_text(encoding="utf-8"))
            self.assertEqual(execution["summary"]["artifact_type_counts"]["execution-pca"], 2)
            system_text = Path(summary["outputs"]["artifacts_windows-system"]).read_text(encoding="utf-8")
            self.assertIn("bitlocker-recovery-key-file", system_text)
            self.assertNotIn(fx.RECOVERY_PASSWORD, system_text)
            step = next(item for item in summary["steps"] if item["name"] == "triage-flags")
            self.assertEqual(step["status"], "completed", step)
            flags = (output_dir / "analyses" / str(step["analysis_id"]) / "flags.jsonl").read_text(encoding="utf-8")
            self.assertIn("antiforensics.tool_present", flags)


class RegistrationTests(unittest.TestCase):
    def test_catalog_domains_and_timeline(self) -> None:
        catalog = load_catalog()
        families = {
            "registry-network-profile": "network-profile",
            "registry-network-share": "network-share",
            "registry-wlan-profile": "wlan-profile-registry",
            "registry-office-mru": "office-mru",
            "registry-known-dll": "known-dll",
            "registry-default-browser": "default-browser",
            "registry-install-state": "install-state",
            "execution-pca": "pca",
            "execution-feature-usage": "feature-usage",
            "bitlocker-recovery-key-file": "antiforensics",
        }
        for artifact_type, family in families.items():
            self.assertEqual(catalog.family_for(artifact_type, "windows-registry"), family)
            self.assertIn(artifact_type, TIMELINE_FIELD_MAP)
        self.assertEqual(artifact_type_domain("windows-registry", "execution-pca"), "execution")
        self.assertEqual(artifact_type_domain("windows-registry", "execution-feature-usage"), "execution")
        self.assertEqual(artifact_type_domain("windows-execution", "execution-pca"), "execution")
        self.assertEqual(artifact_type_domain("windows-registry", "registry-office-mru"), "registry")
        self.assertEqual(artifact_type_domain("windows-system", "bitlocker-recovery-key-file"), "anti-forensics")
        signatures = catalog.specs["antiforensics.tool_present"].params["signatures"]
        self.assertGreaterEqual(len(signatures), 14)
        self.assertTrue(all(str(item["source"]).startswith("https://") for item in signatures))
        self.assertEqual(
            catalog.specs["antiforensics.wiper_run_after_incident"].params["signatures"], signatures
        )


if __name__ == "__main__":
    unittest.main()
