"""R5 L2: OS, system and policy-presence rows (plan r5-residual-2026-10-18 §3 L2).

StartupApproved + Startup folders (``startup-item``), logon banner, SSH/PuTTY/WinSCP, Office
identities and Backstage cache, networking event channels, NTFS volume information, LogMeIn,
McAfee logs, VM configs, crypto wallet presence, credential-store presence and wallpaper.

Every input is synthetic (``tests.r5_l2_fixtures``). Q-R5-2: the planted secrets (SSH private
key bodies, PuTTY/WinSCP password values, wallet keys/seeds/xprv, Credentials/Vault/DPAPI
blob bytes) must not appear in any row nor in any file of a full run output.
"""

from __future__ import annotations

import base64
import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from rapidtriage.artifacts.windows.filesystem import WindowsFilesystemProvider
from rapidtriage.artifacts.windows.registry import (
    WindowsRegistryProvider,
    build_registry_record,
)
from rapidtriage.artifacts.windows.registry_depth import (
    R5_DEPTH_ARTIFACT_TYPES,
    DepthStats,
    ExportKeySource,
    export_depth_records,
    iter_depth_rows,
    startup_approved_state,
)
from rapidtriage.artifacts.windows.remote_access import WindowsRemoteAccessProvider
from rapidtriage.artifacts.windows.system import WindowsSystemArtifactsProvider
from rapidtriage.artifacts.windows.system_extras import (
    R5_SYSTEM_EXTRAS_TYPES,
    classify_private_key,
    parse_ntfs_vbr,
    parse_volume_record,
)
from rapidtriage.core.artifact_domains import artifact_type_domain
from rapidtriage.core.timeline import TIMELINE_FIELD_MAP
from rapidtriage.core.triage_rules import load_catalog
from tests import r5_l2_fixtures as fx

NEW_TYPES = sorted({*R5_DEPTH_ARTIFACT_TYPES, *R5_SYSTEM_EXTRAS_TYPES, "ntfs-volume-information"})


def by_type(records: list, artifact_type: str) -> list[dict]:
    return [record.details for record in records if record.artifact_type == artifact_type]


def assert_no_secret(case: unittest.TestCase, text: str, where: str) -> None:
    for secret in fx.SECRETS:
        case.assertNotIn(secret.decode(), text, f"{secret!r} leaked into {where}")
    body = fx.openssh_private_body_b64(6)
    for index in range(0, len(body) - 40, 40):
        case.assertNotIn(body[index : index + 40], text, f"OpenSSH private body leaked into {where}")
    case.assertNotIn(base64.b64encode(fx.PEM_PRIVATE_SECRET * 4).decode()[:40], text, where)


class R5L2ProviderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = fx.build_tree(Path(cls.temp.name) / "case")
        cls.system = list(WindowsSystemArtifactsProvider().collect(cls.root))
        cls.registry = list(WindowsRegistryProvider().collect(cls.root))
        cls.filesystem = list(WindowsFilesystemProvider().collect(cls.root))
        cls.remote = list(WindowsRemoteAccessProvider().collect(cls.root))
        cls.all = [*cls.system, *cls.registry, *cls.filesystem, *cls.remote]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def test_every_new_type_has_rows_with_provenance(self) -> None:
        counts = Counter(record.artifact_type for record in self.all)
        for artifact_type in NEW_TYPES:
            self.assertGreaterEqual(counts[artifact_type], 1, artifact_type)
        for record in self.all:
            if record.artifact_type not in NEW_TYPES:
                continue
            details = record.details
            self.assertIn(details.get("recovery_method"), {"parsed", "inventory"}, record.artifact_type)
            self.assertTrue(details.get("parser_version"), record.artifact_type)
            self.assertTrue(details.get("source_path"), record.artifact_type)

    def test_no_planted_secret_in_any_row(self) -> None:
        assert_no_secret(self, json.dumps([record.to_dict() for record in self.all], default=str, ensure_ascii=False), "rows")
        for record in self.all:
            if record.artifact_type in {"ssh-key-file", "crypto-wallet-presence", "credential-store-presence"}:
                self.assertFalse(record.details.get("secret_values_stored", False) or record.details.get("contents_stored", False))

    # --- startup items --------------------------------------------------------------------

    def test_startup_approved_state_bytes(self) -> None:
        self.assertEqual(startup_approved_state(fx.startup_value(0x02))[:2], (True, "02"))
        self.assertEqual(startup_approved_state(fx.startup_value(0x06))[0], True)
        enabled, state, disabled_at = startup_approved_state(fx.startup_value(0x03, fx.DISABLED_AT))
        self.assertEqual((enabled, state, disabled_at), (False, "03", "2024-05-01T08:30:00+00:00"))
        self.assertEqual(startup_approved_state(fx.startup_value(0x07))[0], False)
        self.assertEqual(startup_approved_state(b"\x09")[0], None)
        self.assertEqual(startup_approved_state(b""), (None, "", ""))

    def test_startup_registry_rows_join_run_values(self) -> None:
        rows = {row["item_name"]: row for row in by_type(self.registry, "startup-item")}
        self.assertEqual(rows["Updater"]["command"], r"C:\Users\alice\AppData\Roaming\upd\upd.exe /silent")
        self.assertTrue(rows["Updater"]["enabled"])
        onedrive = rows["OneDrive"]
        self.assertFalse(onedrive["enabled"])
        self.assertEqual(onedrive["disabled_at"], "2024-05-01T08:30:00+00:00")
        self.assertEqual(onedrive["timestamp"], onedrive["disabled_at"])
        self.assertEqual(onedrive["timestamp_kind"], "disabled")
        self.assertIsNone(rows["Corrupt"]["enabled"])  # unknown state byte: row kept, state unknown
        self.assertEqual(rows["evil.lnk"]["startup_source"], "startup-approved-startup-folder")
        self.assertEqual(rows["SecurityHealth"]["scope"], "machine")
        self.assertEqual(rows["SecurityHealth"]["command"], r"%windir%\system32\SecurityHealthSystray.exe")

    def test_startup_folder_files_through_lnk_parser(self) -> None:
        rows = {row["item_name"]: row for row in by_type(self.system, "startup-item")}
        self.assertNotIn("desktop.ini", rows)
        evil = rows["evil.lnk"]
        self.assertEqual(evil["target_path"], r"C:\Users\alice\AppData\Local\Temp\evil.exe")
        self.assertTrue(evil["target_user_writable"])
        self.assertEqual(evil["timestamp_kind"], "target-modified")
        self.assertEqual(evil["scope"], "user")
        self.assertEqual(evil["volume_serial_number"], fx.VSN_LOW)
        self.assertEqual(rows["run.bat"]["item_kind"], "script")
        vendor = rows["Vendor Agent.lnk"]
        self.assertEqual(vendor["scope"], "machine")
        self.assertFalse(vendor["target_user_writable"])
        self.assertNotEqual(rows["broken.lnk"]["lnk_parse_status"], "parsed")  # corrupt LNK isolated

    # --- logon banner, Office, wallpaper ----------------------------------------------------

    def test_logon_banner_and_office_identities(self) -> None:
        banners = by_type(self.registry, "registry-logon-banner")
        self.assertEqual(len(banners), 1)  # empty Winlogon values are not a banner
        self.assertEqual(banners[0]["banner_caption"], "보안 서약")
        self.assertIn("모니터링", banners[0]["banner_text"])
        identities = {row["email_address"]: row for row in by_type(self.registry, "office-identity")}
        self.assertEqual(identities["alice@corp.example"]["provider_label"], "회사·학교 계정(Entra ID/ADAL)")
        self.assertEqual(identities["alice.personal@example.com"]["provider_label"], "개인 Microsoft 계정(MSA)")
        self.assertEqual(identities["alice@corp.example"]["tenant_id"], "11111111-2222-3333-4444-555555555555")

    def test_office_backstage_items(self) -> None:
        rows = by_type(self.system, "office-backstage-item")
        parsed = {row["item_name"]: row for row in rows if row.get("parse_status") != "error"}
        design = parsed["설계도.docx"]
        self.assertEqual(design["location_kind"], "url")
        self.assertEqual(design["host"], "corp.sharepoint.com")
        self.assertEqual(design["modified_by"], "Bob Lee")
        self.assertEqual(design["timestamp"], "2026-10-02T10:00:00Z")
        self.assertEqual(parsed["Documents"]["local_path"], r"C:\Users\alice\Documents")
        self.assertEqual(sum(1 for row in rows if row.get("parse_status") == "error"), 1)  # broken.json isolated

    def test_wallpaper_rows(self) -> None:
        registry = by_type(self.registry, "desktop-wallpaper")
        current = next(row for row in registry if row["wallpaper_source"] == "control-panel-desktop")
        self.assertEqual(current["original_path"], r"C:\Users\alice\Pictures\beach.jpg")
        history = sorted((row for row in registry if row["wallpaper_source"] == "background-history"), key=lambda row: row["history_position"])
        self.assertEqual([row["original_path"] for row in history], [r"C:\Users\alice\Pictures\beach.jpg", r"C:\Users\alice\Pictures\city.jpg"])
        files = {row["wallpaper_source"]: row for row in by_type(self.system, "desktop-wallpaper")}
        self.assertEqual((files["transcoded"]["image_format"], files["transcoded"]["image_width"], files["transcoded"]["image_height"]), ("jpeg", 1920, 1080))

    # --- SSH ---------------------------------------------------------------------------------

    def test_openssh_known_hosts_authorized_keys_config(self) -> None:
        hosts = by_type(self.system, "ssh-known-host")
        plain = next(row for row in hosts if row.get("host") == "git.example.org")
        self.assertEqual(plain["fingerprint_sha256"], fx.fingerprint(1))
        jump = next(row for row in hosts if row.get("port") == 2200)
        self.assertEqual(jump["fingerprint_sha256"], fx.fingerprint(2))
        hashed = next(row for row in hosts if row.get("host_hashed"))
        self.assertEqual(hashed["host"], "")
        self.assertEqual(sum(1 for row in hosts if row.get("client") == "openssh"), 3)  # garbage line skipped
        keys = by_type(self.system, "ssh-authorized-key")
        forced = next(row for row in keys if "command=" in row["options"])
        self.assertIn("forced-command-key", forced["risk_flags"])
        self.assertEqual(forced["fingerprint_sha256"], fx.fingerprint(4))
        admin = next(row for row in keys if row["scope"] == "machine")
        self.assertIn("administrators-authorized-key", admin["risk_flags"])
        sessions = {row["session_name"]: row for row in by_type(self.system, "ssh-client-session")}
        prod = sessions["prod"]
        self.assertEqual((prod["host_name"], prod["user_name"], prod["port"]), ("203.0.113.10", "deploy", 2022))
        self.assertEqual(prod["port_forwarding"], "5432 db:5432")
        self.assertEqual(sessions["*.internal"]["host_name"], "")
        self.assertEqual(sessions["*.internal"]["proxy_jump"], "bastion")
        server = by_type(self.system, "ssh-server-config")[0]
        self.assertEqual(server["password_authentication"], "yes")
        self.assertEqual(server["allow_users"], "alice deploy")

    def test_key_files_presence_format_and_public_fingerprint_only(self) -> None:
        keys = {row["file_name"]: row for row in by_type(self.system, "ssh-key-file")}
        private = keys["id_ed25519"]
        self.assertEqual((private["key_role"], private["key_format"], private["encrypted"]), ("private", "openssh", False))
        self.assertEqual(private["fingerprint_sha256"], fx.fingerprint(6))
        self.assertEqual(private["fingerprint_sha256"], keys["id_ed25519.pub"]["fingerprint_sha256"])
        self.assertEqual(private["source_hashes"], {})  # no content hash of a private key
        self.assertTrue(keys["id_rsa"]["encrypted"])
        ppk = keys["legacy.ppk"]
        self.assertEqual((ppk["key_format"], ppk["encrypted"], ppk["fingerprint_sha256"]), ("putty-ppk-v3", False, fx.fingerprint(7)))
        self.assertEqual(keys["ssh_host_ed25519_key"]["key_role_label"], "서버 호스트 개인키")
        encrypted = classify_private_key(fx.openssh_private_key(10, cipher=b"aes256-ctr"))
        self.assertEqual((encrypted or {}).get("encrypted"), True)
        self.assertIsNone(classify_private_key(b"not a key"))
        self.assertEqual(classify_private_key(b"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n")["encrypted"], None)

    def test_putty_winscp_sessions_without_password_values(self) -> None:
        sessions = {(row["client"], row["session_name"]): row for row in [*by_type(self.registry, "ssh-client-session"), *by_type(self.system, "ssh-client-session")]}
        putty = sessions[("putty", "prod server")]
        self.assertEqual((putty["host_name"], putty["user_name"], putty["port"], putty["protocol"]), ("203.0.113.5", "root", 2222, "ssh"))
        self.assertTrue(putty["proxy_password_saved"])
        self.assertNotIn(("putty", "Default Settings"), sessions)
        winscp = sessions[("winscp", "backup@files.example.org")]
        self.assertEqual((winscp["protocol"], winscp["port"]), ("SFTP", 22))
        self.assertTrue(winscp["password_saved"])
        self.assertIn("ssh-password-saved", winscp["risk_flags"])
        ini = sessions[("winscp", "nas backup")]
        self.assertTrue(ini["password_saved"])
        self.assertEqual(ini["port"], 2222)
        hosts = {row["host"] for row in by_type(self.registry, "ssh-known-host")}
        self.assertEqual(hosts, {"203.0.113.5", "files.example.org"})

    def test_reg_export_and_hive_strings_drop_password_values(self) -> None:
        record = build_registry_record(
            Path(self.temp.name) / "x.reg",
            r"HKEY_CURRENT_USER\Software\Martin Prikryl\WinSCP 2\Sessions\s1",
            {"HostName": '"h.example"', "Password": f'"{fx.WINSCP_PASSWORD}"'},
            {"sha256": "0"},
        )
        self.assertNotIn(fx.WINSCP_PASSWORD, json.dumps(record.to_dict(), ensure_ascii=False))
        self.assertEqual(record.details["values"]["HostName"], '"h.example"')
        strings = next(row for row in by_type(self.registry, "registry-hive-strings") if "NTUSER" in row["source_path"].upper())
        self.assertIn("files.example.org", strings["extracted_strings"])
        with tempfile.TemporaryDirectory() as temp:
            export = Path(temp) / "sessions.reg"
            export.write_text(
                "Windows Registry Editor Version 5.00\r\n\r\n"
                "[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\exp]\r\n"
                f'"HostName"="192.0.2.1"\r\n"UserName"="op"\r\n"PortNumber"=dword:00000016\r\n"ProxyPassword"="{fx.PUTTY_PROXY_PASSWORD}"\r\n',
                encoding="utf-16",
            )
            rows = [record.details for record in export_depth_records(export, {"sha256": "0"})]
        session = next(row for row in rows if row.get("session_name") == "exp")
        self.assertEqual((session["host_name"], session["port"]), ("192.0.2.1", 22))
        self.assertNotIn(fx.PUTTY_PROXY_PASSWORD, json.dumps(rows, ensure_ascii=False))

    # --- VMs, wallets, credentials, AV ------------------------------------------------------

    def test_vm_configs(self) -> None:
        rows = by_type(self.system, "vm-config")
        vmx = next(row for row in rows if row.get("config_source") == "vmx")
        self.assertEqual((vmx["vm_name"], vmx["guest_os"], vmx["mac_address"]), ("Win10-익명", "windows9-64", "00:0c:29:aa:bb:cc"))
        self.assertEqual(vmx["disk_paths"], ["Win10.vmdk"])
        self.assertEqual(vmx["shared_folders"], [r"C:\Users\alice\Desktop\반출"])
        vbox = next(row for row in rows if row.get("config_source") == "vbox")
        self.assertEqual((vbox["vm_name"], vbox["guest_os"], vbox["mac_address"]), ("Tails", "Debian_64", "08:00:27:ab:cd:ef"))
        self.assertEqual(vbox["timestamp"], "2026-09-30T12:00:00Z")
        self.assertEqual(vbox["snapshot_count"], 1)
        sources = Counter(row["config_source"] for row in rows if row.get("parse_status") != "error")
        self.assertEqual(sources, Counter({"vmx": 1, "vmware-mru": 1, "vmware-inventory": 1, "virtualbox-registry": 1, "vbox": 1, "vmcx": 2}))
        self.assertEqual(sum(1 for row in rows if row.get("parse_status") == "error"), 1)  # Broken.vbox isolated

    def test_wallet_presence_without_keys(self) -> None:
        rows = by_type(self.system, "crypto-wallet-presence")
        products = Counter(row["wallet_product"] for row in rows)
        for product in ("bitcoin-core", "electrum", "exodus", "ledger-live", "ethereum-keystore", "metamask", "phantom", "kaikas", "bitcoin-core-family"):
            self.assertGreaterEqual(products[product], 1, product)
        bitcoin = next(row for row in rows if row["wallet_product"] == "bitcoin-core")
        self.assertEqual((bitcoin["wallet_format"], bitcoin["encrypted"]), ("berkeley-db", True))
        electrum = {Path(row["wallet_path"]).name: row for row in rows if row["wallet_product"] == "electrum"}
        self.assertEqual(electrum["default_wallet"]["public_addresses"], fx.ELECTRUM_ADDRESSES)
        self.assertFalse(electrum["default_wallet"]["encrypted"])
        self.assertEqual(electrum["locked_wallet"]["wallet_format"], "electrum-encrypted")
        self.assertEqual(electrum["broken_wallet"]["parse_status"], "invalid-json")
        keystore = next(row for row in rows if row["wallet_product"] == "ethereum-keystore")
        self.assertEqual(keystore["public_addresses"], ["0x" + fx.ETH_ADDRESS])
        metamask = next(row for row in rows if row["wallet_product"] == "metamask")
        self.assertEqual((metamask["browser_profile"], metamask["file_count"]), ("Default", 1))
        phantom = next(row for row in rows if row["wallet_product"] == "phantom")
        self.assertEqual(phantom["file_count"], 0)
        stray = next(row for row in rows if row["wallet_product"] == "bitcoin-core-family")
        self.assertEqual(stray["wallet_format"], "sqlite")

    def test_credential_store_presence(self) -> None:
        rows = by_type(self.system, "credential-store-presence")
        kinds = Counter(row["store_kind"] for row in rows)
        self.assertEqual(
            kinds,
            Counter({"credential-file": 2, "vault-credential": 1, "vault-policy": 1, "dpapi-master-key": 2, "dpapi-preferred": 1}),
        )
        master = next(row for row in rows if row["store_kind"] == "dpapi-master-key" and row["user"] == "alice")
        self.assertEqual(master["user_sid"], "S-1-5-21-1111-2222-3333-1001")
        self.assertEqual(master["file_guid"], "8a0f1b2c-3d4e-5f60-7182-93a4b5c6d7e8")
        system = next(row for row in rows if row["user"] == "(시스템)")
        self.assertEqual(system["user_sid"], "S-1-5-18")
        self.assertTrue(all(row["contents_stored"] is False and row["dpapi_decrypted"] is False for row in rows))

    def test_mcafee_logs(self) -> None:
        rows = by_type(self.system, "av-detection-log")
        self.assertEqual(len(rows), 2)  # "No threats found" and the garbage line are not detections
        ens = next(row for row in rows if row["av_product"] == "mcafee-ens")
        self.assertEqual(ens["detected_at"], "2026-10-18T09:15:01.123")
        self.assertEqual(ens["object_path"], r"C:\Users\alice\Downloads\invoice.exe")
        self.assertEqual(ens["threat_name"], "Trojan-FRTX!AB12CD34EF56 (Trojan)")
        self.assertEqual(ens["action"], "deleted")
        self.assertEqual(ens["account"], r"NT AUTHORITY\SYSTEM")
        legacy = next(row for row in rows if row["av_product"] == "mcafee-virusscan")
        self.assertEqual(legacy["detected_at"], "2026-10-17T14:05:11")
        self.assertEqual(legacy["object_path"], r"C:\Users\alice\Desktop\keygen.exe")
        self.assertEqual(legacy["threat_name"], "Generic.dx!abc (Trojan)")
        self.assertEqual(legacy["field_extraction"], "tab-separated")

    # --- NTFS volume, LogMeIn -------------------------------------------------------------

    def test_ntfs_volume_information_pivots_with_lnk_vsn(self) -> None:
        rows = by_type(self.filesystem, "ntfs-volume-information")
        self.assertEqual(len(rows), 1)  # the truncated $Boot folder yields nothing
        volume = rows[0]
        self.assertEqual((volume["volume_serial_number"], volume["volume_serial_display"]), (fx.VSN_LOW, "5E6F-7788"))
        self.assertEqual(volume["volume_serial_number_64"], "1A2B3C4D5E6F7788")
        self.assertEqual((volume["bytes_per_sector"], volume["sectors_per_cluster"], volume["cluster_size"]), (512, 8, 4096))
        self.assertEqual((volume["mft_lcn"], volume["mft_record_size"]), (786_432, 1024))
        self.assertEqual((volume["volume_label"], volume["ntfs_version"], volume["volume_dirty"]), ("증거볼륨", "3.1", True))
        lnk = next(row for row in by_type(self.system, "startup-item") if row["item_name"] == "evil.lnk")
        self.assertEqual(lnk["volume_serial_number"], volume["volume_serial_number"])
        self.assertEqual(parse_ntfs_vbr(b"\x00" * 512)["vbr_parse_status"], "not-ntfs")
        self.assertEqual(parse_ntfs_vbr(b"short")["vbr_parse_status"], "truncated")
        self.assertEqual(parse_volume_record(b"FILE" + b"\x00" * 60)["volume_record_status"], "invalid-file-record")
        broken = bytearray(fx.mft_with_volume_record()[3 * 1024 : 4 * 1024])
        broken[510:512] = b"\x00\x00"  # fixup mismatch
        self.assertEqual(parse_volume_record(bytes(broken))["volume_record_status"], "invalid-file-record")

    def test_logmein_remote_control_rows(self) -> None:
        rows = by_type(self.remote, "third-party-remote-control-artifact")
        self.assertEqual([row["product"] for row in rows], ["logmein"])
        self.assertIn("198.51.100.7", rows[0]["ip_candidates"])


class R5L2ContractTests(unittest.TestCase):
    def test_catalog_families_domains_and_timeline(self) -> None:
        catalog = load_catalog()
        expected_domains = {
            ("windows-registry", "startup-item"): "os",
            ("windows-system", "startup-item"): "os",
            ("windows-registry", "registry-logon-banner"): "registry",
            ("windows-registry", "office-identity"): "registry",
            ("windows-system", "office-backstage-item"): "registry",
            ("windows-registry", "ssh-known-host"): "devices",
            ("windows-registry", "ssh-client-session"): "devices",
            ("windows-system", "ssh-known-host"): "devices",
            ("windows-system", "ssh-authorized-key"): "devices",
            ("windows-system", "ssh-client-session"): "devices",
            ("windows-system", "ssh-key-file"): "devices",
            ("windows-system", "ssh-server-config"): "devices",
            ("windows-registry", "desktop-wallpaper"): "os",
            ("windows-system", "desktop-wallpaper"): "os",
            ("windows-system", "credential-store-presence"): "os",
            ("windows-system", "vm-config"): "anti-forensics",
            ("windows-system", "crypto-wallet-presence"): "anti-forensics",
            ("windows-system", "av-detection-log"): "anti-forensics",
            ("windows-filesystem", "ntfs-volume-information"): "filesystem",
        }
        self.assertEqual({artifact_type for _kind, artifact_type in expected_domains}, set(NEW_TYPES))
        for (kind, artifact_type), domain in expected_domains.items():
            self.assertEqual(artifact_type_domain(kind, artifact_type), domain, (kind, artifact_type))
            family_id = catalog.family_for(artifact_type, kind)
            family = next(item for item in catalog.families if item["id"] == family_id)
            self.assertIn(artifact_type, family.get("types") or [], artifact_type)
            if family_id != "logon-banner":  # caption/text only: no person, account, device or path value
                self.assertTrue(any(column.get("semantic") for column in [*family["core_columns"], *(family.get("aux_columns") or [])]), family_id)
        for artifact_type in ("startup-item", "registry-logon-banner", "ssh-client-session", "office-identity", "vm-config", "av-detection-log"):
            self.assertIn(artifact_type, TIMELINE_FIELD_MAP)
        rules = {spec.id: spec for spec in catalog.specs.values()}
        self.assertEqual(rules["execution.startup_user_path"].grade, "B")
        self.assertEqual(rules["antiforensics.crypto_wallet_present"].grade, "C")
        self.assertEqual(rules["antiforensics.vm_present"].grade, "C")

    def test_depth_decoders_isolate_a_corrupt_key(self) -> None:
        source = ExportKeySource("NTUSER", "HKCU", "")
        source.add(r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run", {"A": b"\x02" + b"\x00" * 11}, 1)
        source.add(r"Software\SimonTatham\PuTTY\Sessions\s", {"HostName": "h", "PortNumber": object()}, 2)
        stats = DepthStats()
        rows = list(iter_depth_rows(source, stats))
        self.assertIn("startup-item", {row.artifact_type for row in rows})
        self.assertEqual(stats.summary()["decoder_error_count"], 0)


class R5L2RunTests(unittest.TestCase):
    def test_full_run_output_never_contains_a_planted_secret(self) -> None:
        from rapidtriage.artifacts import clear_collect_cache
        from rapidtriage.core.run import run_triage_mode

        clear_collect_cache()
        self.addCleanup(clear_collect_cache)
        with tempfile.TemporaryDirectory() as temp:
            root = fx.build_tree(Path(temp) / "case-root")
            output_dir = Path(temp) / "run-out"
            summary = run_triage_mode(root, mode="hacking", output_dir=output_dir)
            system = json.loads(Path(summary["outputs"]["artifacts_windows-system"]).read_text(encoding="utf-8"))
            counts = system["summary"]["artifact_type_counts"]
            for artifact_type in ("startup-item", "crypto-wallet-presence", "credential-store-presence", "ssh-key-file", "vm-config"):
                self.assertGreaterEqual(counts.get(artifact_type, 0), 1, artifact_type)
            for path in output_dir.rglob("*"):
                if path.is_file() and path.stat().st_size < 64 * 1024 * 1024:
                    data = path.read_bytes()
                    for secret in fx.SECRETS:
                        self.assertNotIn(secret, data, f"{secret!r} in {path.relative_to(output_dir)}")
                        self.assertNotIn(secret.decode().encode("utf-16-le"), data, f"{secret!r} (UTF-16) in {path.relative_to(output_dir)}")
            step = next(item for item in summary["steps"] if item["name"] == "triage-flags")
            self.assertEqual(step["status"], "completed", step)
            flags = (output_dir / "analyses" / str(step["analysis_id"]) / "flags.jsonl").read_text(encoding="utf-8")
            for rule_id in ("execution.startup_user_path", "antiforensics.crypto_wallet_present", "antiforensics.vm_present"):
                self.assertIn(rule_id, flags)


class R5L2DocumentTextTests(unittest.TestCase):
    """Docs extraction (docs output, docs index, case DB) withholds secret stores and masks secrets."""

    def test_secret_store_paths_and_masking(self) -> None:
        from rapidtriage.artifacts.windows.system_extras import (
            WITHHELD_TEXT,
            is_secret_store_path,
            redact_secret_store_text,
        )
        from rapidtriage.core.docs import extract_text

        home = Path("C:/Users/alice/AppData")
        for path in (
            home / "Local/Google/Chrome/User Data/Default/Local Extension Settings" / fx.METAMASK_ID / "000003.log",
            home / "Local/Google/Chrome/User Data/Default/IndexedDB" / f"chrome-extension_{fx.KAIKAS_ID}_0.indexeddb.leveldb" / "000001.log",
            home / "Roaming/Exodus/exodus.wallet/passphrase.json",
            home / "Roaming/Microsoft/Credentials/DFBE70A7E5CC19A398EBF1B96859CE5D",
            Path("C:/Users/alice/.ssh/id_rsa"),
            Path("D:/keys/legacy.ppk"),
            Path("D:/backup/wallet.dat"),
        ):
            self.assertTrue(is_secret_store_path(path), path)
        for path in (Path("C:/Users/alice/.ssh/id_rsa.pub"), Path("C:/Users/alice/Documents/id_card.pdf"), home / "Local/Google/Chrome/User Data/Default/Local Extension Settings/abcdefghijklmnopabcdefghijklmnop/1.log"):
            self.assertFalse(is_secret_store_path(path), path)
        self.assertEqual(redact_secret_store_text(Path("C:/Users/alice/.ssh/id_rsa"), "x"), WITHHELD_TEXT)
        notes = f"server notes\n{fx.openssh_private_key(6).decode()}\nend\n{fx.ppk_file(7).decode()}"
        masked = redact_secret_store_text(Path("notes.txt"), notes)
        self.assertIn("server notes", masked)
        # Ordinary documents keep "password=" lines (only WinSCP.ini / .reg saved-password values are masked).
        self.assertEqual(redact_secret_store_text(Path("memo.txt"), "password=1234"), "password=1234")
        assert_no_secret(self, masked, "notes")
        self.assertNotIn(base64.b64encode(fx.PPK_PRIVATE_SECRET).decode()[:40], masked)
        with tempfile.TemporaryDirectory() as temp:
            ini = Path(temp) / "WinSCP.ini"
            ini.write_text(f"[Sessions\\s]\nHostName=h\nPassword={fx.WINSCP_INI_PASSWORD}\n", encoding="utf-8")
            text = extract_text(ini, "ini")
            reg = Path(temp) / "putty.reg"
            reg.write_text(f'[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\s]\n"ProxyPassword"="{fx.PUTTY_PROXY_PASSWORD}"\n', encoding="utf-8")
            reg_text = extract_text(reg, "reg")
        self.assertIn("HostName=h", text)
        self.assertNotIn(fx.WINSCP_INI_PASSWORD, text)
        self.assertNotIn(fx.PUTTY_PROXY_PASSWORD, reg_text)

    def test_extract_never_copies_secret_stores(self) -> None:
        from rapidtriage.core.docs import run_docs_search
        from rapidtriage.core.extract import run_extract

        with tempfile.TemporaryDirectory() as temp:
            evidence = Path(temp) / "evidence"
            wallet = fx.write(evidence / "Users/alice/AppData/Roaming/Exodus/exodus.wallet/passphrase.json", b'{"passphrase":"EXODUSSEEDSECRET-r5l2"}')
            plain = fx.write(evidence / "Users/alice/Documents/plan.json", '{"note": "비밀 계획"}')
            payload = run_docs_search(evidence, ["비밀"])
            output = Path(temp) / "out"
            manifest = run_extract(Path(temp) / "docs.json", output, kinds=["json"], payload=payload)
            copied = [Path(entry["extracted_path"]).name for entry in manifest["entries"]]
            skipped = {Path(item["original_path"]).name: item for item in manifest["skipped"]}
            data = b"".join(path.read_bytes() for path in output.rglob("*") if path.is_file())
        self.assertEqual(copied, [plain.name])
        self.assertEqual(skipped[wallet.name]["reason"], "secret-redacted")
        self.assertNotIn(fx.EXODUS_SEED_SECRET, data)


if __name__ == "__main__":
    unittest.main()
