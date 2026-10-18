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


class BitLockerKeyDocumentTextTests(unittest.TestCase):
    """R3 follow-up: the 48-digit key of a recognised key file never reaches the document text,
    the docs output, the docs index or the case DB (it is masked like the artifact row)."""

    def test_extract_text_masks_the_key_of_a_recognised_key_file(self) -> None:
        from rapidtriage.core.docs import extract_document_text, extract_text

        with tempfile.TemporaryDirectory() as temp:
            key_file = Path(temp) / f"BitLocker Recovery Key {fx.KEY_ID}.TXT"
            key_file.write_bytes(fx.bitlocker_key_text())
            other = Path(temp) / "notes.txt"
            other.write_text(f"ticket {fx.RECOVERY_PASSWORD}", encoding="utf-8")
            text = extract_text(key_file, "txt")
            document = extract_document_text(key_file, "txt")
            plain = extract_text(other, "txt")
        masked = mask_recovery_password(fx.RECOVERY_PASSWORD)
        for value in (text, document.text):
            self.assertNotIn(fx.RECOVERY_PASSWORD, value)
            self.assertIn(masked, value)
            self.assertIn(fx.KEY_ID, value)  # the identifier is not secret and stays searchable
        # R3 review A3: masking is content-based (checksum-validated), not gated on the file name.
        self.assertNotIn(fx.RECOVERY_PASSWORD, plain)
        self.assertIn(masked, plain)

    def test_run_outputs_never_contain_the_key(self) -> None:
        import sqlite3
        from contextlib import closing

        from rapidtriage.core.run import run_triage_mode

        groups = fx.RECOVERY_PASSWORD.split("-")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "case-root"
            documents = root / "Users" / "alice" / "Documents"
            documents.mkdir(parents=True)
            (documents / f"BitLocker Recovery Key {fx.KEY_ID}.TXT").write_bytes(fx.bitlocker_key_text())
            (documents / f"BitLocker 복구 키 {fx.KEY_ID}.TXT").write_bytes(fx.bitlocker_key_text("ko"))
            (documents / "memo.txt").write_text("password reset memo", encoding="utf-8")
            output_dir = Path(temp) / "run-out"
            # R3 review A2: with --extract the key files are skipped (manifest reason + hash).
            summary = run_triage_mode(root, mode="hacking", output_dir=output_dir, extract_enabled=True)
            manifests = [json.loads(path.read_text(encoding="utf-8")) for path in output_dir.rglob("*extract*manifest*.json")]
            secret_skips = [item for manifest in manifests for item in manifest.get("skipped", []) if item.get("reason") == "secret-redacted"]
            self.assertTrue(secret_skips, [path.name for path in output_dir.rglob("*")][:40])
            self.assertTrue(all(len(item["sha256"]) == 64 for item in secret_skips))

            docs = json.loads((output_dir / "rapidtriage-docs.json").read_text(encoding="utf-8"))
            docs_text = json.dumps(docs, ensure_ascii=False)
            self.assertIn(f"BitLocker Recovery Key {fx.KEY_ID}.TXT", docs_text)
            index = json.loads((output_dir / "rapidtriage-docs-index.json").read_text(encoding="utf-8"))
            key_docs = [item for item in index["documents"] if "BitLocker" in str(item["path"])]
            self.assertEqual(len(key_docs), 2)
            self.assertTrue(all(int(item["text_length"]) > 0 for item in key_docs))  # indexed, masked
            for term in index["terms"]:
                self.assertFalse(any(group in term for group in groups), term)
            self.assertIn(mask_recovery_password(fx.RECOVERY_PASSWORD).casefold(), index["terms"])

            db_path = output_dir / "rapidtriage-case.db"
            self.assertTrue(db_path.is_file(), summary.get("steps"))
            with closing(sqlite3.connect(db_path)) as connection:
                bodies = [
                    str(body)
                    for title, body in connection.execute("SELECT title, body FROM indexed_document")
                    if "BitLocker" in str(title)
                ]
            self.assertEqual(len(bodies), 2)
            for body in bodies:
                self.assertIn(mask_recovery_password(fx.RECOVERY_PASSWORD), body)
                for group in groups:
                    self.assertNotIn(group, body)

            # No output file of the run (JSON, JSONL, SQLite, reports) holds the key in any encoding.
            needles = [fx.RECOVERY_PASSWORD.encode(encoding) for encoding in ("utf-8", "utf-16-le")]
            for path in output_dir.rglob("*"):
                if not path.is_file():
                    continue
                data = path.read_bytes()
                for needle in needles:
                    self.assertNotIn(needle, data, str(path.relative_to(output_dir)))


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


# ---------------------------------------------------------------------------
# R3 adversarial-review regressions (A1-A14)
# ---------------------------------------------------------------------------


class _FakeKey:
    def __init__(self, offset: int, name: str) -> None:
        self.offset = offset
        self.name = name
        self.last_written_at = ""


class _FakeHive:
    """Children by offset; ``lists`` may repeat an offset or point back at an ancestor."""

    def __init__(self, keys: dict[int, str], lists: dict[int, list[int]]) -> None:
        self.keys = {offset: _FakeKey(offset, name) for offset, name in keys.items()}
        self.lists = lists
        self.subkey_calls = 0

    def subkeys(self, key: _FakeKey) -> list[_FakeKey]:
        self.subkey_calls += 1
        return [self.keys[offset] for offset in self.lists.get(key.offset, [])]

    def values_dict(self, key: _FakeKey) -> dict[str, object]:
        return {}

    def open_key(self, rel: str) -> _FakeKey | None:
        return self.keys[1] if rel == "root" else None


class RegistryDepthReviewTests(unittest.TestCase):
    def test_cyclic_and_duplicate_subkey_lists_are_bounded(self) -> None:
        """A1: 2,000 self-referencing ``User MRU``/``Word`` entries used to take minutes (N**4)."""
        import time

        from rapidtriage.artifacts.windows import registry_depth as depth
        from rapidtriage.artifacts.windows.registry import NativeRegistryHive

        for target in ("User MRU", "Word"):
            hive = NativeRegistryHive.from_bytes(fx.cyclic_office_hive(target, 2000))
            self.assertIsNotNone(hive)
            stats = DepthStats()
            started = time.monotonic()
            rows = list(iter_depth_rows(depth.HiveKeySource(hive, "NTUSER"), stats))
            self.assertLess(time.monotonic() - started, 5.0, target)
            self.assertEqual([row for row in rows if row.artifact_type == "registry-office-mru"], [], target)
            self.assertEqual(stats.errors, [], target)

    def test_subkeys_dedupe_and_skip_ancestors(self) -> None:
        from rapidtriage.artifacts.windows import registry_depth as depth

        hive = _FakeHive({1: "root", 2: "a", 3: "b"}, {1: [2, 2, 2, 3, 1], 2: [1, 2, 3], 3: [3]})
        source = depth.HiveKeySource(hive, "NTUSER")
        root = source.key("root")
        children = source.subkeys(root)
        self.assertEqual([child.name for child in children], ["a", "b"])
        # a's list points at root (ancestor) and at itself: only b remains; b lists only itself.
        self.assertEqual([child.name for child in source.subkeys(children[0])], ["b"])
        self.assertEqual(source.subkeys(children[1]), [])

    def test_key_budget_is_recorded_in_depth_stats(self) -> None:
        from unittest import mock

        from rapidtriage.artifacts.windows import registry_depth as depth

        source = ExportKeySource("SOFTWARE", "HKLM\\SOFTWARE", "")
        for index in range(10):
            source.add(rf"Microsoft\Windows\CurrentVersion\App Paths\tool{index}.exe", {"": f"C:\\t\\tool{index}.exe"}, index + 1)
        stats = DepthStats()
        with mock.patch.object(depth, "MAX_DEPTH_KEYS_PER_DECODER", 3):
            rows = [row for row in iter_depth_rows(source, stats) if row.artifact_type == "registry-install-state"]
        self.assertEqual(len(rows), 3)
        self.assertIn("SOFTWARE:install_state_rows", stats.key_budget_exhausted)
        self.assertEqual(stats.summary()["key_budget_exhausted_decoders"], ["SOFTWARE:install_state_rows"])

    def test_type_cap_stops_the_decoder_and_errors_are_isolated(self) -> None:
        """A1/A12: a capped type stops its decoder (no draining); a raising decoder is isolated."""
        from unittest import mock

        from rapidtriage.artifacts.windows import registry_depth as depth

        produced = []

        def flood(_source: object):
            for index in range(1_000_000):
                produced.append(index)
                yield depth.DepthRow("registry-known-dll", "x", depth.KeyView("k", "k", {}), {})

        def broken(_source: object):
            yield depth.DepthRow("registry-network-share", "x", depth.KeyView("k", "k", {}), {})
            raise ValueError("corrupt key")

        def fine(_source: object):
            yield depth.DepthRow("registry-default-browser", "x", depth.KeyView("k", "k", {}), {})

        source = ExportKeySource("SYSTEM", "HKLM\\SYSTEM", "")
        stats = DepthStats()
        with (
            mock.patch.object(depth, "MAX_DEPTH_ROWS_PER_TYPE", 5),
            mock.patch.dict(depth.DECODERS_BY_HIVE, {"SYSTEM": (flood, broken, fine)}),
        ):
            rows = list(iter_depth_rows(source, stats))
        self.assertLessEqual(len(produced), 6)
        self.assertEqual(Counter(row.artifact_type for row in rows), {"registry-known-dll": 5, "registry-network-share": 1, "registry-default-browser": 1})
        self.assertEqual(stats.capped, ["registry-known-dll"])
        self.assertEqual([error["decoder"] for error in stats.errors], ["broken"])
        self.assertIn("ValueError: corrupt key", stats.errors[0]["error"])

    def test_corrupted_ntuser_discloses_depth_summary(self) -> None:
        """A12: a cyclic NTUSER goes through the provider quickly and still gets its depth summary."""
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            write_hive(base, "Users/mallory/NTUSER.DAT", fx.cyclic_office_hive("User MRU", 2000))
            records = list(WindowsRegistryProvider().collect(base))
        summaries = [r.details["native_walk"]["registry_depth"] for r in records if r.artifact_type == "registry-hive"]
        self.assertEqual(len(summaries), 1)
        summary = summaries[0]
        self.assertEqual(summary["decoder_error_count"], 0)
        self.assertIn("key_budget_exhausted_decoders", summary)
        self.assertNotIn("registry-office-mru", summary["row_counts"])

    def test_long_continuation_is_linear_and_capped(self) -> None:
        """A5: a 4 MB ``hex:`` value spread over 160k continuation lines; an oversized value is disclosed."""
        import time
        from unittest import mock

        from rapidtriage.artifacts.windows import registry_depth as depth

        row = "  " + ",".join(["00"] * 25) + ",\\"
        lines = ["[HKEY_CURRENT_USER\\X]", '"Blob"=hex:00,\\', *([row] * 160_000), "  00", '"After"=dword:00000001']
        started = time.monotonic()
        keys = list(depth.iter_export_keys(lines))
        self.assertLess(time.monotonic() - started, 10.0)
        self.assertEqual(len(keys[0][1]["Blob"]), 4_000_002)
        self.assertEqual(keys[0][1]["After"], 1)
        stats = DepthStats()
        with mock.patch.object(depth, "MAX_EXPORT_VALUE_CHARS", 1000):
            keys = list(depth.iter_export_keys(lines, stats))
        self.assertNotIn("Blob", keys[0][1])
        self.assertEqual(keys[0][1]["After"], 1)
        self.assertEqual(len(stats.oversized_values), 1)
        self.assertEqual(stats.summary()["oversized_export_value_count"], 1)

    def test_export_decoding_order(self) -> None:
        """A8: an even-length CP949 ``REGEDIT4`` export is not misread as UTF-16."""
        from rapidtriage.artifacts.windows.registry import collect_reg_export
        from rapidtriage.artifacts.windows.registry_depth import (
            decode_export_bytes,
            export_depth_records,
        )

        text = fx.reg_export_text().replace("Windows Registry Editor Version 5.00", "REGEDIT4")
        cp949 = text.replace("\n", "\r\n").encode("cp949")
        if len(cp949) % 2:
            cp949 += b" "
        self.assertEqual(decode_export_bytes(cp949).rstrip(" "), text.replace("\n", "\r\n").rstrip(" "))
        self.assertIn("회사", decode_export_bytes('"x"="회사"\r\n'.encode("utf-16-le")))
        self.assertIn("회사", decode_export_bytes(b"\xff\xfe" + '"x"="회사"'.encode("utf-16-le")))
        self.assertIn("회사", decode_export_bytes('"x"="회사"'.encode()))
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "ansi.reg"
            path.write_bytes(cp949)
            rows = list(export_depth_records(path, {"sha256": "x"}))
            plain = list(collect_reg_export(path))
            path.write_bytes(fx.reg_export_text().encode("utf-16"))
            utf16_rows = list(export_depth_records(path, {"sha256": "x"}))
        self.assertEqual(len(rows), len(utf16_rows))
        self.assertTrue(plain)
        names = {row.details.get("profile_name") for row in rows} - {None}
        self.assertEqual(names, {row.details.get("profile_name") for row in utf16_rows} - {None})
        self.assertIn("지점-VPN", names)

    def test_systemtime_calendar_validation(self) -> None:
        """A9: February 31st or month 13 is not a date."""
        import struct

        def raw(*fields: int) -> bytes:
            return struct.pack("<8H", *fields)

        self.assertEqual(systemtime_text(raw(2024, 2, 3, 31, 10, 0, 0, 0)), "")
        self.assertEqual(systemtime_text(raw(2024, 13, 3, 1, 10, 0, 0, 0)), "")
        self.assertEqual(systemtime_text(raw(2023, 2, 3, 29, 10, 0, 0, 0)), "")
        self.assertEqual(systemtime_text(raw(2024, 2, 4, 29, 10, 0, 0, 5)), "2024-02-29T10:00:00.005")

    def test_pca_rows_emit_timestamp_kind(self) -> None:
        """A14: registry Store/Persisted rows are key LastWrite, never a run time."""
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            write_hive(base, "Users/alice/NTUSER.DAT", fx.ntuser_hive())
            pca = base / "Windows" / "appcompat" / "pca"
            pca.mkdir(parents=True)
            (pca / "PcaAppLaunchDic.txt").write_bytes(fx.pca_app_launch_dic())
            (pca / "PcaGeneralDb0.txt").write_bytes(fx.pca_general_db())
            registry_rows = by_type(list(WindowsRegistryProvider().collect(base)), "execution-pca")
            text_rows = list(collect_pca_text_files(base, "windows-execution"))
        self.assertTrue(registry_rows)
        self.assertEqual({row["timestamp_kind"] for row in registry_rows}, {"last-written"})
        kinds = {row.details["source_kind"]: row.details["timestamp_kind"] for row in text_rows}
        self.assertEqual(kinds, {"pca-app-launch-dic": "run", "pca-general-db": "pca-event"})

    def test_every_depth_row_maps_timestamp_label_to_kind(self) -> None:
        """A14 (console follow-up): every timestamp_label of a depth row has its timestamp_kind."""
        expected = {
            "last_written": "last-written",
            "last_written_mru_head": "last-written",
            "last_connected": "last-connected",
            "first_connected": "first-connected",
            "last_opened": "last-opened",
        }
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            write_hive(base, "Windows/System32/config/SOFTWARE", fx.software_hive())
            write_hive(base, "Windows/System32/config/SYSTEM", fx.system_hive())
            write_hive(base, "Users/alice/NTUSER.DAT", fx.ntuser_hive())
            (base / "export.reg").write_bytes(fx.reg_export_text().encode("utf-16"))
            rows = [r.details for r in WindowsRegistryProvider().collect(base) if r.artifact_type in DEPTH_ARTIFACT_TYPES]
        seen = set()
        for row in rows:
            label = row.get("timestamp_label") or ""
            if row.get("timestamp"):
                self.assertEqual(row["timestamp_kind"], expected[label], (row.get("label"), label))
                seen.add(label)
            else:
                self.assertEqual(row["timestamp_kind"], "", row.get("label"))
        self.assertTrue({"last_written", "last_connected", "last_opened"} <= seen, seen)


class BitLockerSecretReviewTests(unittest.TestCase):
    """A2-A4: the recovery password is masked by content (checksum-validated) everywhere."""

    def test_content_based_masking_whatever_the_file_name(self) -> None:
        import unicodedata

        from rapidtriage.core.docs import extract_document_text, extract_text

        masked = mask_recovery_password(fx.RECOVERY_PASSWORD)
        body = f"Recovery Key:\r\n\t{fx.RECOVERY_PASSWORD}\r\n"
        names = [
            "notes.md",
            "install.log",
            "BitLockerRecoveryKey.txt",
            "bitlocker_recovery_key.txt",
            "my recovery key.txt",
            unicodedata.normalize("NFD", f"BitLocker 복구 키 {fx.KEY_ID}.TXT"),
            f"BitLocker 복구 키 {fx.KEY_ID}.txt",
        ]
        with tempfile.TemporaryDirectory() as temp:
            for name in names:
                path = Path(temp) / name
                path.write_bytes(b"\xff\xfe" + body.encode("utf-16-le"))
                kind = path.suffix.lstrip(".").lower()
                for value in (extract_text(path, kind), extract_document_text(path, kind).text):
                    self.assertNotIn(fx.RECOVERY_PASSWORD, value, name)
                    self.assertIn(masked, value, name)
            eml = Path(temp) / "key.eml"
            eml.write_bytes(
                f"From: a@example.test\r\nTo: b@example.test\r\nSubject: key\r\n\r\nmy key {fx.RECOVERY_PASSWORD}\r\n".encode()
            )
            self.assertNotIn(fx.RECOVERY_PASSWORD, extract_text(eml, "eml"))

    def test_separators_and_checksum_gate(self) -> None:
        from rapidtriage.artifacts.windows.antiforensics import (
            redact_recovery_key_text,
            redact_recovery_passwords,
        )

        masked = mask_recovery_password(fx.RECOVERY_PASSWORD)
        for variant in (
            fx.RECOVERY_PASSWORD.replace("-", " "),
            fx.RECOVERY_PASSWORD.replace("-", ""),
            fx.RECOVERY_PASSWORD.replace("-", "\u2010"),
            "\uff10" + fx.RECOVERY_PASSWORD[1:],
        ):
            self.assertEqual(redact_recovery_passwords(f"key: {variant}."), f"key: {masked}.", ascii(variant))
        invalid = "123453-234564-345675-456786-567897-678908-111111-222222"  # 678908 % 11 != 0
        self.assertEqual(redact_recovery_passwords(invalid), invalid)
        self.assertEqual(redact_recovery_passwords(fx.RECOVERY_PASSWORD + "9"), fx.RECOVERY_PASSWORD + "9")
        # A recognised key file still masks a key whose checksum fails (name gate kept as a superset).
        self.assertNotIn(invalid, redact_recovery_key_text(f"BitLocker Recovery Key {fx.KEY_ID}.TXT", invalid))

    def test_extract_skips_key_files_with_hash(self) -> None:
        """A2: ``extract`` never copies a key file (or a small text holding a valid key) verbatim."""
        from rapidtriage.core.docs import run_docs_search
        from rapidtriage.core.extract import run_extract

        with tempfile.TemporaryDirectory() as temp:
            evidence = Path(temp) / "evidence"
            evidence.mkdir()
            (evidence / f"BitLocker Recovery Key {fx.KEY_ID}.TXT").write_bytes(fx.bitlocker_key_text())
            (evidence / "recovery notes.txt").write_text(f"recovery {fx.RECOVERY_PASSWORD}", encoding="utf-8")
            (evidence / "recovery plan.txt").write_text("recovery plan without secrets", encoding="utf-8")
            payload = run_docs_search(evidence, ["recovery"])
            output = Path(temp) / "out"
            manifest = run_extract(Path(temp) / "docs.json", output, kinds=["txt"], payload=payload)
            copied = [Path(entry["extracted_path"]).name for entry in manifest["entries"]]
            skipped = {Path(item["original_path"]).name: item for item in manifest["skipped"]}
            files = [path.read_bytes() for path in output.rglob("*") if path.is_file()]
        self.assertEqual(copied, ["recovery plan.txt"])
        for name in (f"BitLocker Recovery Key {fx.KEY_ID}.TXT", "recovery notes.txt"):
            self.assertEqual(skipped[name]["reason"], "secret-redacted")
            self.assertEqual(len(skipped[name]["sha256"]), 64)
        for data in files:
            self.assertNotIn(fx.RECOVERY_PASSWORD.encode("utf-16-le"), data)
            self.assertNotIn(fx.RECOVERY_PASSWORD.encode(), data)

    def test_command_lines_are_masked_at_row_write(self) -> None:
        """A4: PowerShell history and 4688 CommandLine rows never hold the key."""
        from rapidtriage.artifacts.windows.eventlog import WindowsEventLogProvider

        command = f"manage-bde -unlock D: -RecoveryPassword {fx.RECOVERY_PASSWORD}"
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            history = base / "Users" / "alice" / "AppData" / "Roaming" / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine"
            history.mkdir(parents=True)
            (history / "ConsoleHost_history.txt").write_text(f"dir\n{command}\n", encoding="utf-8")
            logs = base / "Windows" / "System32" / "winevt" / "Logs"
            logs.mkdir(parents=True)
            (logs / "Security.xml").write_text(
                '<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
                '<Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4688</EventID>'
                '<TimeCreated SystemTime="2024-05-02T10:00:00.000Z"/><EventRecordID>1</EventRecordID>'
                "<Channel>Security</Channel><Computer>pc</Computer></System><EventData>"
                '<Data Name="NewProcessName">C:\\Windows\\System32\\manage-bde.exe</Data>'
                f'<Data Name="CommandLine">{command}</Data></EventData></Event></Events>',
                encoding="utf-8",
            )
            execution = [r for r in WindowsExecutionProvider().collect(base) if r.artifact_type == "powershell-history-command"]
            events = list(WindowsEventLogProvider().collect(base))
        masked = mask_recovery_password(fx.RECOVERY_PASSWORD)
        self.assertEqual([r.details["command_line"] for r in execution][-1], f"manage-bde -unlock D: -RecoveryPassword {masked}")
        dumped = json.dumps([r.details for r in [*execution, *events]], ensure_ascii=False, default=str)
        self.assertNotIn(fx.RECOVERY_PASSWORD, dumped)
        event = next(r for r in events if r.artifact_type == "eventlog-event")
        self.assertIn(masked, json.dumps(event.details, ensure_ascii=False, default=str))
