from __future__ import annotations

import contextlib
import json
import sqlite3
import tempfile
import unittest
from unittest import mock
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath

from rapidtriage.cli import main
from rapidtriage.artifacts.windows.browser import build_browser_secret_trusted_diff, browser_core_accuracy_gates
from rapidtriage.artifacts.windows.eventlog import collect_native_evtx_events
from rapidtriage.artifacts.windows.execution import build_execution_artifact_trusted_diff
from rapidtriage.artifacts.windows.os_account import build_os_account_trusted_diff
from rapidtriage.artifacts.windows.system import web_request_basename_sources
from tests.windows_artifact_fixtures import (
    build_corrupt_evtx_record_candidate,
    build_evtx_with_checked_chunk,
    build_evtx_with_slack_record,
    build_minimal_evtx,
    build_minimal_mft,
    build_minimal_registry_hive,
    build_template_evtx,
    build_windows_artifact_fixture,
    datetime_to_filetime,
)


class RapidTriageWindowsArtifactsTests(unittest.TestCase):
    def test_windows_system_collector_maps_bits_qmgr_transfer_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            qmgr = root / "ProgramData" / "Microsoft" / "Network" / "Downloader" / "qmgr0.dat"
            qmgr.parent.mkdir(parents=True)
            qmgr.write_bytes(
                b"BITS job fixture https://exfil.example.test/upload C:\\Users\\alice\\Documents\\case.zip"
            )
            output = root / "windows-system-artifacts.json"

            exit_code = main(["artifacts", str(root), "--kind", "windows-system", "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            bits = next(
                artifact
                for artifact in payload["artifacts"]
                if artifact["artifact_type"] == "bits-qmgr-transfer-candidate"
            )
            self.assertIn("https://exfil.example.test/upload", bits["details"]["url_candidates"])
            self.assertIn("bits-url-candidate", bits["details"]["risk_flags"])
            self.assertFalse(bits["details"]["commercial_grade_ready"])

    def test_windows_system_collector_maps_bits_sqlite_job_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            qmgr = root / "ProgramData" / "Microsoft" / "Network" / "Downloader" / "qmgr.db"
            qmgr.parent.mkdir(parents=True)
            create_sqlite_fixture(
                qmgr,
                "Jobs",
                ["job_id", "remote_url", "local_path", "owner_sid", "state"],
                (
                    "{job-1}",
                    "https://transfer.example.test/drop.zip",
                    r"C:\Users\alice\AppData\Local\Temp\drop.zip",
                    "S-1-5-21-111-222-333-1001",
                    "TRANSFERRING",
                ),
            )
            output = root / "windows-system-artifacts.json"

            exit_code = main(["artifacts", str(root), "--kind", "windows-system", "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            aggregate = next(
                artifact
                for artifact in payload["artifacts"]
                if artifact["artifact_type"] == "bits-qmgr-transfer-candidate"
            )
            row = next(
                artifact
                for artifact in payload["artifacts"]
                if artifact["artifact_type"] == "bits-qmgr-sqlite-job-candidate"
            )
            self.assertTrue(aggregate["details"]["bits_qmgr_sqlite_profile"]["opened_readonly"])
            self.assertEqual(aggregate["details"]["coverage_status"], "bits-qmgr-sqlite-row-inventory")
            self.assertIn("bits-sqlite-transfer-row-candidate", aggregate["details"]["risk_flags"])
            self.assertIn("https://transfer.example.test/drop.zip", row["details"]["url_candidates"])
            self.assertIn(r"C:\Users\alice\AppData\Local\Temp\drop.zip", row["details"]["path_candidates"])
            self.assertIn("S-1-5-21-111-222-333-1001", row["details"]["owner_candidates"])
            self.assertIn("TRANSFERRING", row["details"]["state_candidates"])
            self.assertEqual(row["details"]["bits_qmgr_sqlite_row"]["source_locator"]["table"], "Jobs")
            self.assertFalse(row["details"]["commercial_grade_ready"])

    def test_windows_browser_collector_maps_webcache_and_cloud_sync_db_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            webcache = root / "Users" / "alice" / "AppData" / "Local" / "Microsoft" / "Windows" / "WebCache" / "WebCacheV01.dat"
            webcache.parent.mkdir(parents=True)
            webcache_blob = bytearray(8192)
            webcache_blob[4:8] = bytes.fromhex("efcdab89")
            webcache_blob[0xEC : 0xF0] = (4096).to_bytes(4, "little")
            webcache_blob.extend(b"https://webview.example.test/cache C:\\Users\\alice\\AppData\\Local\\Microsoft")
            webcache.write_bytes(bytes(webcache_blob))

            sync_db = root / "Users" / "alice" / "AppData" / "Local" / "Microsoft" / "OneDrive" / "settings" / "Personal" / "sync_engine.db"
            sync_db.parent.mkdir(parents=True)
            create_sqlite_fixture(
                sync_db,
                "FileMetadata",
                ["resource_id", "local_path", "sync_status", "owner_email", "deleted"],
                ("file-1", "C:\\Users\\alice\\Documents\\secret.docx", "uploaded", "alice@example.com", "0"),
            )
            output = root / "browser-artifacts.json"

            exit_code = main(["artifacts", str(root), "--kind", "browser", "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            artifact_types = {artifact["artifact_type"] for artifact in payload["artifacts"]}
            self.assertIn("webcachev01-ese-file", artifact_types)
            self.assertIn("desktop-cloud-sync-db", artifact_types)
            self.assertIn("desktop-cloud-sync-row-candidate", artifact_types)

            webcache_artifact = next(
                artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "webcachev01-ese-file"
            )
            self.assertTrue(webcache_artifact["details"]["ese_header"]["signature_valid"])
            self.assertIn("https://webview.example.test/cache", webcache_artifact["details"]["url_candidates"])
            self.assertEqual(webcache_artifact["details"]["coverage_status"], "ese-header-string-and-page-map-inventory")
            self.assertIn("webview.example.test", webcache_artifact["details"]["domain_candidates"])
            self.assertTrue(webcache_artifact["details"]["ese_page_map"]["page_map_available"])
            self.assertGreaterEqual(webcache_artifact["details"]["webcachev01_review_profile"]["candidate_page_count"], 1)
            self.assertIn("webcache-url-candidate", webcache_artifact["details"]["risk_flags"])

            sync_artifact = next(
                artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "desktop-cloud-sync-db"
            )
            self.assertEqual(sync_artifact["details"]["sync_provider"], "onedrive")
            self.assertTrue(sync_artifact["details"]["sqlite_schema_inventory"]["opened_readonly"])
            self.assertIn("sync-db-sqlite-opened", sync_artifact["details"]["risk_flags"])

            sync_row = next(
                artifact
                for artifact in payload["artifacts"]
                if artifact["artifact_type"] == "desktop-cloud-sync-row-candidate"
            )
            self.assertEqual(sync_row["details"]["sync_provider"], "onedrive")
            self.assertEqual(sync_row["details"]["local_path_candidate"], "C:\\Users\\alice\\Documents\\secret.docx")
            self.assertEqual(sync_row["details"]["sync_status_candidate"], "uploaded")
            self.assertEqual(sync_row["details"]["owner_or_account_candidate"], "alice@example.com")
            self.assertIn("possible-cloud-upload-or-sync-state", sync_row["details"]["risk_flags"])
            self.assertTrue(sync_row["details"]["cloud_sync_row_review_profile"]["has_path_candidate"])

    def test_windows_filesystem_collector_maps_ntfs_logfile_transaction_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            logfile = root / "$LogFile"
            logfile.write_bytes(
                b"RSTR"
                + b"\x00" * 512
                + b"RCRD FileDelete transaction C:\\Users\\alice\\Documents\\secret.docx"
            )
            output = root / "filesystem.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "windows-filesystem", "--output", str(output)]), 0)

            payload = json.loads(output.read_text(encoding="utf-8"))
            artifact = next(
                item
                for item in payload["artifacts"]
                if item["artifact_type"] == "ntfs-logfile-transaction-candidate"
            )
            self.assertEqual(artifact["details"]["source_format"], "ntfs-logfile")
            self.assertIn("ntfs-logfile-signatures-present", artifact["details"]["risk_flags"])
            self.assertIn("ntfs-logfile-page-map-present", artifact["details"]["risk_flags"])
            self.assertIn("ntfs-logfile-operation-hints-present", artifact["details"]["risk_flags"])
            self.assertIn("C:\\Users\\alice\\Documents\\secret.docx", artifact["details"]["path_candidates"])
            self.assertEqual(
                artifact["details"]["ntfs_logfile_page_profile"]["profile_version"],
                "ntfs-logfile-page-profile-v1",
            )
            self.assertTrue(artifact["details"]["ntfs_logfile_page_profile"]["page_candidates"])
            self.assertEqual(
                artifact["details"]["transaction_operation_profile"]["profile_version"],
                "ntfs-logfile-operation-profile-v1",
            )
            operation_hint = artifact["details"]["transaction_operation_hints"][0]
            self.assertEqual(operation_hint["operation_candidate"], "delete")
            self.assertEqual(operation_hint["path_candidates"], ["C:\\Users\\alice\\Documents\\secret.docx"])
            self.assertEqual(operation_hint["nearest_log_signature"]["signature"], "log_record_page")
            self.assertTrue(artifact["details"]["timeline_join_hints"]["join_ready"])
            self.assertFalse(artifact["details"]["commercial_grade_ready"])

    def test_windows_eventlog_collector_maps_etl_trace_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            etl = root / "Windows" / "System32" / "winevt" / "Logs" / "usb_trace.etl"
            etl.parent.mkdir(parents=True)
            etl.write_bytes(
                b"TRACE Microsoft-Windows-Kernel-PnP USBSTOR C:\\Windows\\System32 https://example.test 10.0.0.5"
            )
            output = root / "eventlog.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "eventlog", "--output", str(output)]), 0)

            payload = json.loads(output.read_text(encoding="utf-8"))
            artifact = next(item for item in payload["artifacts"] if item["artifact_type"] == "etl-trace-file")
            self.assertIn("Microsoft-Windows-Kernel-PnP", artifact["details"]["provider_hints"])
            self.assertIn("usb", artifact["details"]["trace_families"])
            self.assertIn("https://example.test", artifact["details"]["url_candidates"])
            self.assertFalse(artifact["details"]["commercial_grade_ready"])

    def test_windows_eventlog_collector_maps_usb_wlan_print_and_bits_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            events = root / "Windows" / "System32" / "winevt" / "Logs" / "Operational.xml"
            events.parent.mkdir(parents=True)
            events.write_text(
                """<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Kernel-PnP"/>
      <EventID>410</EventID>
      <TimeCreated SystemTime="2026-05-01T08:00:00.0000000Z"/>
      <EventRecordID>4100</EventRecordID>
      <Channel>Microsoft-Windows-Kernel-PnP/Configuration</Channel>
      <Computer>WIN11-CASE</Computer>
    </System>
    <EventData>
      <Data Name="DeviceInstanceId">USBSTOR\\Disk&amp;Ven_Samsung&amp;Prod_Flash_Drive\\123456</Data>
      <Data Name="DriverName">disk.inf</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-WLAN-AutoConfig"/>
      <EventID>8001</EventID>
      <TimeCreated SystemTime="2026-05-01T09:00:00.0000000Z"/>
      <EventRecordID>8001</EventRecordID>
      <Channel>Microsoft-Windows-WLAN-AutoConfig/Operational</Channel>
      <Computer>WIN11-CASE</Computer>
    </System>
    <EventData>
      <Data Name="SSID">CorpWiFi</Data>
      <Data Name="InterfaceGuid">{11111111-2222-3333-4444-555555555555}</Data>
      <Data Name="Reason">connected</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-PrintService"/>
      <EventID>307</EventID>
      <TimeCreated SystemTime="2026-05-01T10:00:00.0000000Z"/>
      <EventRecordID>307</EventRecordID>
      <Channel>Microsoft-Windows-PrintService/Operational</Channel>
      <Computer>WIN11-CASE</Computer>
    </System>
    <EventData>
      <Data Name="DocumentName">secret.docx</Data>
      <Data Name="PrinterName">HP LaserJet</Data>
      <Data Name="UserName">alice</Data>
      <Data Name="Pages">2</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Bits-Client"/>
      <EventID>59</EventID>
      <TimeCreated SystemTime="2026-05-01T11:00:00.0000000Z"/>
      <EventRecordID>59</EventRecordID>
      <Channel>Microsoft-Windows-Bits-Client/Operational</Channel>
      <Computer>WIN11-CASE</Computer>
    </System>
    <EventData>
      <Data Name="JobId">{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}</Data>
      <Data Name="RemoteName">https://example.test/payload.bin</Data>
      <Data Name="LocalFile">C:\\Users\\alice\\AppData\\Local\\Temp\\payload.bin</Data>
      <Data Name="Owner">alice</Data>
      <Data Name="State">Transferred</Data>
    </EventData>
  </Event>
</Events>
""",
                encoding="utf-8",
            )
            output = root / "eventlog.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "eventlog", "--output", str(output)]), 0)

            payload = json.loads(output.read_text(encoding="utf-8"))
            event_rows = [item for item in payload["artifacts"] if item["artifact_type"] == "eventlog-event"]
            detection_rows = [item for item in payload["artifacts"] if item["artifact_type"] == "eventlog-detection"]
            events_by_category = {item["details"]["event_category"]: item["details"] for item in event_rows}
            rules_by_id = {item["details"]["rule"]["id"]: item["details"] for item in detection_rows}

            usb = events_by_category["usb-device-event"]
            self.assertEqual(usb["channel_family"], "device")
            self.assertIn("USBSTOR", usb["device_instance_id"])
            self.assertEqual(usb["event_semantics_profile"]["catalog_key"], "usb-device-event")
            self.assertIn("mounteddevices", usb["event_semantics_profile"]["correlation_targets"])
            self.assertIn("Kernel-PnP recorded device activity", usb["event_message"])

            wlan = events_by_category["wlan-autoconfig-event"]
            self.assertEqual(wlan["channel_family"], "wlan")
            self.assertEqual(wlan["ssid"], "CorpWiFi")
            self.assertEqual(
                wlan["event_semantics_profile"]["source_field_values"]["ssid"],
                "CorpWiFi",
            )
            self.assertIn("WLAN AutoConfig recorded wireless activity", wlan["event_message"])

            printed = events_by_category["print-service-event"]
            self.assertEqual(printed["channel_family"], "print")
            self.assertEqual(printed["document_name"], "secret.docx")
            self.assertEqual(printed["printer_name"], "HP LaserJet")
            self.assertEqual(printed["user_name"], "alice")
            self.assertIn("PrintService recorded document activity", printed["event_message"])

            bits = events_by_category["bits-client-event"]
            self.assertEqual(bits["channel_family"], "bits")
            self.assertEqual(bits["remote_name"], "https://example.test/payload.bin")
            self.assertEqual(bits["local_file"], "C:\\Users\\alice\\AppData\\Local\\Temp\\payload.bin")
            self.assertEqual(bits["event_semantics_profile"]["severity"], "medium")
            self.assertIn("BITS Client recorded transfer activity", bits["event_message"])

            self.assertEqual(rules_by_id["RT-EVTX-USB-PROVIDER"]["device_instance_id"], usb["device_instance_id"])
            self.assertEqual(rules_by_id["RT-EVTX-WLAN-AUTOCONFIG"]["ssid"], "CorpWiFi")
            self.assertEqual(rules_by_id["RT-EVTX-PRINTSERVICE"]["document_name"], "secret.docx")
            self.assertEqual(rules_by_id["RT-EVTX-BITS-CLIENT"]["remote_name"], "https://example.test/payload.bin")

    def test_windows_eventlog_collector_builds_logon_session_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            security = root / "Windows" / "System32" / "winevt" / "Logs" / "Security.xml"
            security.parent.mkdir(parents=True)
            security.write_text(
                """<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing"/>
      <EventID>4624</EventID>
      <TimeCreated SystemTime="2026-05-01T10:00:00.0000000Z"/>
      <EventRecordID>10</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WIN11-CASE</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">alice</Data>
      <Data Name="TargetDomainName">WORKGROUP</Data>
      <Data Name="TargetLogonId">0x12345</Data>
      <Data Name="LogonType">10</Data>
      <Data Name="IpAddress">192.0.2.10</Data>
      <Data Name="WorkstationName">LAPTOP-A</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing"/>
      <EventID>4634</EventID>
      <TimeCreated SystemTime="2026-05-01T10:30:00.0000000Z"/>
      <EventRecordID>11</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WIN11-CASE</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">alice</Data>
      <Data Name="TargetDomainName">WORKGROUP</Data>
      <Data Name="TargetLogonId">0x12345</Data>
      <Data Name="LogonType">10</Data>
    </EventData>
  </Event>
</Events>
""",
                encoding="utf-8",
            )
            output = root / "eventlog.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "eventlog", "--output", str(output)]), 0)

            payload = json.loads(output.read_text(encoding="utf-8"))
            session = next(item for item in payload["artifacts"] if item["artifact_type"] == "eventlog-logon-session")
            self.assertEqual(session["details"]["session_key"], "WIN11-CASE|0x12345")
            self.assertEqual(session["details"]["session_status"], "closed")
            self.assertEqual(session["details"]["user_name"], "alice")
            self.assertEqual(session["details"]["logon_type"], "10")
            self.assertEqual(session["details"]["duration_seconds"], 1800)
            self.assertIn("rdp-logon-session", session["details"]["risk_flags"])
            self.assertFalse(session["details"]["commercial_grade_ready"])

    def test_windows_system_collector_maps_setupapi_usb_and_wifi_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            setupapi = root / "Windows" / "inf" / "setupapi.dev.log"
            setupapi.parent.mkdir(parents=True)
            setupapi.write_text(
                ">>>  Section start 2026/05/01 10:00:00.123\n"
                ">>>  [Device Install - USBSTOR\\Disk&Ven_Samsung&Prod_Flash_Drive\\123456]\n",
                encoding="utf-8",
            )
            wifi = (
                root
                / "ProgramData"
                / "Microsoft"
                / "Wlansvc"
                / "Profiles"
                / "Interfaces"
                / "{GUID}"
                / "corp-wifi.xml"
            )
            wifi.parent.mkdir(parents=True)
            wifi.write_text(
                """<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>CorpWiFi</name>
  <SSIDConfig><SSID><name>CorpWiFi</name></SSID></SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>auto</connectionMode>
  <nonBroadcast>true</nonBroadcast>
  <MSM><security><authEncryption><authentication>WPA2PSK</authentication><encryption>AES</encryption></authEncryption><sharedKey><protected>true</protected><keyMaterial>super-secret-password</keyMaterial></sharedKey></security></MSM>
  <MacRandomization><enableRandomization>true</enableRandomization></MacRandomization>
</WLANProfile>
""",
                encoding="utf-8",
            )
            output = root / "system.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "windows-system", "--output", str(output)]), 0)

            payload = json.loads(output.read_text(encoding="utf-8"))
            setup_artifact = next(
                item
                for item in payload["artifacts"]
                if item["artifact_type"] == "usb-setupapi-device-install-candidate"
            )
            self.assertIn("USBSTOR\\Disk&Ven_Samsung&Prod_Flash_Drive\\123456", setup_artifact["details"]["device_id_candidates"])
            self.assertEqual(setup_artifact["details"]["install_entries"][0]["timestamp_hint"], "2026-05-01T10:00:00.123")
            self.assertEqual(setup_artifact["details"]["usb_device_review_profile"]["storage_device_count"], 1)
            self.assertEqual(
                setup_artifact["details"]["usb_device_review_profile"]["devices"][0]["storage_vendor"],
                "Samsung",
            )
            self.assertEqual(
                setup_artifact["details"]["usb_device_review_profile"]["devices"][0]["serial_number_candidate"],
                "123456",
            )
            self.assertIn("usb-storage-device-candidate", setup_artifact["details"]["risk_flags"])

            wifi_artifact = next(item for item in payload["artifacts"] if item["artifact_type"] == "wifi-profile")
            self.assertEqual(wifi_artifact["details"]["ssid"], "CorpWiFi")
            self.assertEqual(wifi_artifact["details"]["authentication"], "WPA2PSK")
            self.assertTrue(wifi_artifact["details"]["key_material_present"])
            self.assertTrue(wifi_artifact["details"]["key_material_redacted"])
            self.assertNotIn("super-secret-password", json.dumps(wifi_artifact, ensure_ascii=False))
            self.assertEqual(wifi_artifact["details"]["wifi_profile_review_profile"]["interface_guid"], "{GUID}")
            self.assertEqual(wifi_artifact["details"]["wifi_profile_review_profile"]["security_level"], "secured")
            self.assertIn("wifi-mac-randomization-enabled", wifi_artifact["details"]["risk_flags"])
            self.assertIn("hidden-wifi-profile", wifi_artifact["details"]["risk_flags"])
            self.assertIn("wifi-credential-material-present-redacted", wifi_artifact["details"]["risk_flags"])

    def test_windows_system_collector_inventories_thumbnail_activities_uwp_and_webshell_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            explorer = root / "Users" / "alice" / "AppData" / "Local" / "Microsoft" / "Windows" / "Explorer"
            explorer.mkdir(parents=True)
            embedded_jpeg = b"\xff\xd8\xff\xe0JFIF\x00fixture-thumbnail\xff\xd9"
            (explorer / "thumbcache_256.db").write_bytes(b"CMMM thumb cache fixture " + embedded_jpeg)
            (explorer / "iconcache_32.db").write_bytes(b"CMMM icon cache fixture")
            activities = root / "Users" / "alice" / "AppData" / "Local" / "ConnectedDevicesPlatform" / "L.alice"
            activities.mkdir(parents=True)
            create_sqlite_fixture(
                activities / "ActivitiesCache.db",
                "Activity",
                ["Id", "AppId", "DisplayText", "CreatedTime"],
                ("activity-1", "Microsoft.WindowsNotepad_8wekyb3d8bbwe", "Opened case notes", "1767225600000"),
            )
            notifications = root / "Users" / "alice" / "AppData" / "Local" / "Microsoft" / "Windows" / "Notifications"
            notifications.mkdir(parents=True)
            create_sqlite_fixture(
                notifications / "wpndatabase.db",
                "Notification",
                ["Id", "AppId", "Payload", "CreatedTime"],
                (
                    "notification-1",
                    "Microsoft Teams",
                    "<toast><visual><binding><text>Meeting soon</text></binding></visual></toast>",
                    "2026-01-01T00:00:00+00:00",
                ),
            )
            registry_export = root / "registry" / "SOFTWARE_ProfileList.reg"
            registry_export.parent.mkdir()
            registry_export.write_text(
                "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\S-1-5-21-111-222-333-1001]\n"
                '"ProfileImagePath"="C:\\Users\\alice"\n',
                encoding="utf-8",
            )
            native_software = root / "Windows" / "System32" / "config" / "SOFTWARE"
            native_software.parent.mkdir(parents=True)
            native_software.write_bytes(
                (
                    "ProfileList\\S-1-5-21-111-222-333-1002\x00"
                    "ProfileImagePath\x00"
                    "C:\\Users\\alice\x00"
                ).encode("utf-16le")
            )
            uwp = root / "Users" / "alice" / "AppData" / "Local" / "Packages" / "Microsoft.WindowsNotepad_8wekyb3d8bbwe"
            (uwp / "LocalState").mkdir(parents=True)
            webroot = root / "inetpub" / "wwwroot"
            webroot.mkdir(parents=True)
            (webroot / "shell.aspx").write_text("<% eval(Request[\"cmd\"]); %>", encoding="utf-8")
            iis_config = root / "Windows" / "System32" / "inetsrv" / "config" / "applicationHost.config"
            iis_config.parent.mkdir(parents=True)
            iis_config.write_text(
                """<configuration>
  <system.applicationHost>
    <applicationPools>
      <add name="DefaultAppPool"><processModel identityType="ApplicationPoolIdentity" /></add>
    </applicationPools>
    <sites>
      <site name="Default Web Site" id="1">
        <application path="/" applicationPool="DefaultAppPool">
          <virtualDirectory path="/" physicalPath="%SystemDrive%\\inetpub\\wwwroot" />
        </application>
        <bindings><binding protocol="http" bindingInformation="*:80:" /></bindings>
      </site>
    </sites>
  </system.applicationHost>
</configuration>""",
                encoding="utf-8",
            )
            (webroot / "shell.aspx.yara.json").write_text(
                json.dumps(
                    {
                        "matches": [
                            {
                                "rule": "ASP_Eval_Request_Webshell",
                                "tags": ["webshell", "asp"],
                                "meta": {"severity": "high", "source": "fixture-rulepack"},
                                "namespace": "rapidtriage-fixture",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            logs = root / "inetpub" / "logs" / "LogFiles" / "W3SVC1"
            logs.mkdir(parents=True)
            (logs / "u_ex260501.log").write_text("GET /shell.aspx cmd=powershell 200\n", encoding="utf-8")
            (logs / "u_ex260502.log").write_text(
                "#Fields: date time c-ip cs-method cs-uri-stem cs-uri-query sc-status\n"
                "2026-05-01 10:00:00 10.0.0.5 GET /shell.aspx cmd=powershell 200\n",
                encoding="utf-8",
            )
            nginx_logs = root / "var" / "log" / "nginx"
            nginx_logs.mkdir(parents=True)
            (nginx_logs / "access.log").write_text(
                '10.0.0.6 - - [01/May/2026:10:01:00 +0000] "GET /shell.aspx?cmd=whoami HTTP/1.1" 200 123 "-" "curl/8.0"\n'
                '10.0.0.9 - - [01/May/2026:10:01:30 +0000] "GET /shell.aspx?cmd%3D%77%68%6f%61%6d%69 HTTP/1.1" 200 123 "-" "curl/8.0"\n',
                encoding="utf-8",
            )
            (nginx_logs / "json_access.log").write_text(
                json.dumps(
                    {
                        "@timestamp": "2026-05-01T10:02:00+00:00",
                        "remote_addr": "10.0.0.7",
                        "method": "POST",
                        "uri": "/shell.aspx?cmd=powershell",
                        "status": 200,
                        "user_agent": "curl/8.0",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (nginx_logs / "kv_access.log").write_text(
                'ts=2026-05-01T10:03:00Z src=10.0.0.8 method=POST uri="/shell.aspx?cmd=whoami" status=500 ua="curl/8.1"\n',
                encoding="utf-8",
            )
            output = root / "system.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "windows-system", "--output", str(output)]), 0)

            payload = json.loads(output.read_text(encoding="utf-8"))
            type_counts = payload["summary"]["artifact_type_counts"]
            self.assertGreaterEqual(type_counts.get("thumbnail-cache-file", 0), 1)
            self.assertGreaterEqual(type_counts.get("thumbnail-cache-entry-candidate", 0), 1)
            self.assertGreaterEqual(type_counts.get("thumbnail-cache-media-candidate", 0), 1)
            self.assertGreaterEqual(type_counts.get("icon-cache-file", 0), 1)
            self.assertGreaterEqual(type_counts.get("icon-cache-entry-candidate", 0), 1)
            self.assertGreaterEqual(type_counts.get("activities-cache-db", 0), 1)
            self.assertGreaterEqual(type_counts.get("activities-cache-row-candidate", 0), 1)
            self.assertGreaterEqual(type_counts.get("notification-database", 0), 1)
            self.assertGreaterEqual(type_counts.get("notification-row-candidate", 0), 1)
            self.assertGreaterEqual(type_counts.get("uwp-package", 0), 1)
            self.assertGreaterEqual(type_counts.get("webshell-source-candidate", 0), 1)
            self.assertGreaterEqual(type_counts.get("web-server-log", 0), 1)
            webshell = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "webshell-source-candidate")
            self.assertIn("eval(", webshell["details"]["suspicious_terms"])
            self.assertEqual(webshell["details"]["webshell_semantic_profile"]["language_family"], "asp-dotnet")
            self.assertIn("eval", webshell["details"]["webshell_semantic_profile"]["execution_primitives"])
            self.assertEqual(webshell["details"]["webshell_semantic_profile"]["request_parameters"][0]["name"], "cmd")
            self.assertEqual(
                webshell["details"]["webshell_semantic_profile"]["request_parameters"][0]["match_basis"],
                "asp-request-indexer",
            )
            self.assertEqual(webshell["details"]["webshell_semantic_profile"]["review_priority"], "high")
            self.assertGreaterEqual(webshell["details"]["webshell_evidence_span_count"], 2)
            evidence_by_term = {span["term"]: span for span in webshell["details"]["webshell_evidence_spans"]}
            self.assertEqual(evidence_by_term["eval("]["line_number"], 1)
            self.assertEqual(evidence_by_term["request["]["line_number"], 1)
            self.assertIn("Request", evidence_by_term["request["]["line_preview"])
            self.assertIn("line_sha256", evidence_by_term["eval("])
            self.assertEqual(webshell["details"]["webshell_rule_validation_status"], "sidecar-linked")
            self.assertEqual(webshell["details"]["webshell_rule_sidecar_count"], 1)
            rule_match = webshell["details"]["webshell_rule_sidecars"][0]["matches"][0]
            self.assertEqual(rule_match["rule"], "ASP_Eval_Request_Webshell")
            self.assertIn("webshell", rule_match["tags"])
            self.assertEqual(rule_match["severity"], "high")
            self.assertEqual(webshell["details"]["iis_site_correlation"]["status"], "matched")
            iis_match = webshell["details"]["iis_site_correlation"]["matches"][0]
            self.assertEqual(iis_match["site_name"], "Default Web Site")
            self.assertEqual(iis_match["application_pool"], "DefaultAppPool")
            self.assertEqual(iis_match["application_pool_identity"]["identity_type"], "ApplicationPoolIdentity")
            self.assertEqual(iis_match["relative_webshell_path"], "shell.aspx")
            log_correlation = webshell["details"]["webshell_log_correlation"]
            self.assertEqual(log_correlation["status"], "matched")
            self.assertEqual(log_correlation["matched_request_count"], 5)
            self.assertEqual(log_correlation["suspicious_request_count"], 5)
            self.assertIn("10.0.0.5", log_correlation["source_ips"])
            self.assertIn("10.0.0.9", log_correlation["source_ips"])
            self.assertEqual(log_correlation["first_seen"], "2026-05-01T10:00:00+00:00")
            self.assertEqual(log_correlation["last_seen"], "2026-05-01T10:03:00+00:00")
            self.assertIn("cmd", log_correlation["matches"][0]["query_keys"])
            timeline_correlation = webshell["details"]["webshell_timeline_correlation"]
            self.assertEqual(timeline_correlation["profile_version"], "webshell-filesystem-log-timeline-v1")
            self.assertEqual(timeline_correlation["first_log_seen"], "2026-05-01T10:00:00+00:00")
            self.assertEqual(timeline_correlation["last_log_seen"], "2026-05-01T10:03:00+00:00")
            self.assertEqual(timeline_correlation["matched_request_count"], 5)
            self.assertIn(
                timeline_correlation["relation"],
                {
                    "file-modified-before-first-log-hit",
                    "file-modified-after-first-log-hit",
                    "file-modified-at-first-log-hit",
                },
            )
            citation_package = webshell["details"]["webshell_report_citation_package"]
            self.assertEqual(citation_package["manifest_version"], "webshell-report-citation-package-v1")
            self.assertEqual(citation_package["source"]["sha256"], webshell["details"]["source_hashes"]["sha256"])
            self.assertEqual(
                webshell["details"]["webshell_report_citation_package_hash"],
                citation_package["manifest_sha256"],
            )
            self.assertEqual(citation_package["primary_findings"]["language_family"], "asp-dotnet")
            self.assertGreaterEqual(citation_package["evidence_ref_count"], 5)
            citation_kinds = {ref["kind"] for ref in citation_package["evidence_refs"]}
            self.assertIn("source-code-span", citation_kinds)
            self.assertIn("external-rule-sidecar", citation_kinds)
            self.assertIn("iis-site-correlation", citation_kinds)
            self.assertIn("web-log-correlation", citation_kinds)
            self.assertIn("filesystem-log-timeline", citation_kinds)
            source_span = next(
                ref
                for ref in citation_package["evidence_refs"]
                if ref["kind"] == "source-code-span" and ref["term"] == "eval("
            )
            self.assertEqual(source_span["term"], "eval(")
            self.assertEqual(source_span["source_viewer_locator"]["viewer"], "text-line-offset")
            self.assertEqual(
                citation_package["reportability"]["allowed_use"],
                "webshell-triage-correlation-package",
            )
            self.assertFalse(citation_package["reportability"]["ready_for_court_report"])
            self.assertIn("mft-usn-timeline-required", citation_package["reportability"]["blockers"])
            self.assertGreaterEqual(webshell["details"]["risk_score"], 60)
            self.assertFalse(webshell["details"]["commercial_grade_ready"])
            activity = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "activities-cache-db")
            self.assertTrue(activity["details"]["sqlite_schema_inventory"]["opened_readonly"])
            self.assertEqual(activity["details"]["sqlite_schema_inventory"]["tables"][0]["name"], "Activity")
            self.assertEqual(activity["details"]["sqlite_schema_inventory"]["semantic_summary"]["families"]["activity"], 1)
            self.assertEqual(activity["details"]["sqlite_schema_inventory"]["semantic_summary"]["timeline_candidate_count"], 1)
            self.assertEqual(activity["details"]["uwp_package_index_count"], 1)
            self.assertEqual(
                activity["details"]["sqlite_schema_inventory"]["uwp_package_correlation_summary"]["correlation_status"],
                "matched",
            )
            self.assertEqual(activity["details"]["profile_attribution"]["profile_name"], "alice")
            self.assertEqual(activity["details"]["profile_attribution"]["sid"], "S-1-5-21-111-222-333-1001")
            self.assertEqual(activity["details"]["profile_attribution"]["sid_correlation_status"], "profilelist-match")
            self.assertTrue(
                any(
                    candidate["basis"] == "profilelist-profileimagepath-native-string-scan"
                    and candidate["sid"] == "S-1-5-21-111-222-333-1002"
                    and candidate["sid_byte_offset"] is not None
                    and candidate["profile_path_byte_offset"] is not None
                    and candidate["offset_basis"] == "decoded-native-hive-string-offset"
                    for candidate in activity["details"]["profile_attribution"]["sid_candidates"]
                )
            )
            activity_timeline = activity["details"]["sqlite_schema_inventory"]["tables"][0]["normalized_timeline_samples"][0]
            self.assertEqual(activity_timeline["timeline_type"], "activity")
            self.assertEqual(activity_timeline["normalized_time"], "2026-01-01T00:00:00+00:00")
            self.assertEqual(activity_timeline["decoded_text_hint"]["preview"], "Opened case notes")
            self.assertEqual(activity_timeline["profile_attribution"]["profile_name"], "alice")
            self.assertEqual(activity_timeline["profile_attribution"]["sid"], "S-1-5-21-111-222-333-1001")
            self.assertEqual(activity_timeline["uwp_package_correlation"]["status"], "matched")
            self.assertEqual(
                activity_timeline["uwp_package_correlation"]["matched_package"],
                "Microsoft.WindowsNotepad_8wekyb3d8bbwe",
            )
            self.assertEqual(activity_timeline["source_locator"]["viewer"], "sqlite")
            activity_row = next(
                artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "activities-cache-row-candidate"
            )
            self.assertEqual(activity_row["details"]["timeline_type"], "activity")
            self.assertEqual(activity_row["details"]["normalized_time"], "2026-01-01T00:00:00+00:00")
            self.assertEqual(activity_row["details"]["decoded_text_hint"]["preview"], "Opened case notes")
            self.assertEqual(activity_row["details"]["source_locator"]["viewer"], "sqlite")
            self.assertEqual(activity_row["details"]["source_locator"]["parent_artifact_type"], "activities-cache-db")
            self.assertEqual(
                activity_row["details"]["activity_row_review_profile"]["uwp_package_status"],
                "matched",
            )
            self.assertIn("uwp-package-correlated", activity_row["details"]["risk_flags"])
            self.assertFalse(activity_row["details"]["commercial_grade_ready"])
            notification = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "notification-database")
            self.assertEqual(notification["details"]["profile_attribution"]["profile_name"], "alice")
            self.assertEqual(notification["details"]["profile_attribution"]["sid"], "S-1-5-21-111-222-333-1001")
            notification_timeline = notification["details"]["sqlite_schema_inventory"]["tables"][0]["normalized_timeline_samples"][0]
            self.assertEqual(notification_timeline["timeline_type"], "notification")
            self.assertEqual(notification_timeline["time_parse_status"], "iso8601")
            self.assertEqual(notification_timeline["decoded_text_hint"]["format"], "xml-or-html-text")
            self.assertEqual(notification_timeline["decoded_text_hint"]["preview"], "Meeting soon")
            notification_row = next(
                artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "notification-row-candidate"
            )
            self.assertEqual(notification_row["details"]["timeline_type"], "notification")
            self.assertEqual(notification_row["details"]["decoded_text_hint"]["preview"], "Meeting soon")
            self.assertEqual(
                notification_row["details"]["source_locator"]["parent_artifact_type"],
                "notification-database",
            )
            self.assertIn("decoded-text-hint-present", notification_row["details"]["risk_flags"])
            uwp_row = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "uwp-package")
            self.assertEqual(uwp_row["details"]["profile_attribution"]["profile_name"], "alice")
            self.assertEqual(uwp_row["details"]["profile_attribution"]["sid"], "S-1-5-21-111-222-333-1001")
            self.assertEqual(uwp_row["details"]["package_identity"]["name"], "Microsoft.WindowsNotepad")
            thumbnail = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "thumbnail-cache-file")
            self.assertEqual(thumbnail["details"]["cache_signature_profile"]["embedded_media_signature_count"], 1)
            self.assertEqual(thumbnail["details"]["cache_signature_profile"]["embedded_media_candidate_count"], 1)
            self.assertEqual(thumbnail["details"]["cache_signature_profile"]["embedded_media_candidates"][0]["type"], "jpeg")
            self.assertEqual(thumbnail["details"]["cache_signature_profile"]["cache_entry_candidate_count"], 1)
            self.assertEqual(thumbnail["details"]["cache_signature_profile"]["cache_entry_candidates"][0]["signature"], "CMMM")
            self.assertEqual(
                thumbnail["details"]["cache_signature_profile"]["cache_entry_candidates"][0]["nearest_embedded_media"]["type"],
                "jpeg",
            )
            self.assertEqual(thumbnail["details"]["cache_signature_profile"]["entry_decode_status"], "cmmm-entry-candidates")
            thumbnail_entry = next(
                artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "thumbnail-cache-entry-candidate"
            )
            self.assertEqual(thumbnail_entry["details"]["signature"], "CMMM")
            self.assertEqual(thumbnail_entry["details"]["source_locator"]["viewer"], "hex")
            self.assertEqual(thumbnail_entry["details"]["source_locator"]["offset"], 0)
            self.assertEqual(thumbnail_entry["details"]["cache_entry_review_profile"]["nearest_media_type"], "jpeg")
            self.assertIn("embedded-media-near-entry", thumbnail_entry["details"]["risk_flags"])
            self.assertFalse(thumbnail_entry["details"]["commercial_grade_ready"])
            thumbnail_media = next(
                artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "thumbnail-cache-media-candidate"
            )
            self.assertEqual(thumbnail_media["details"]["media_type"], "jpeg")
            self.assertEqual(thumbnail_media["details"]["source_locator"]["viewer"], "embedded-media-range")
            self.assertEqual(len(thumbnail_media["details"]["media_sha256"]), 64)
            self.assertFalse(thumbnail_media["details"]["commercial_grade_ready"])
            icon_entry = next(
                artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "icon-cache-entry-candidate"
            )
            self.assertEqual(icon_entry["details"]["cache_family"], "icon")
            self.assertEqual(icon_entry["details"]["cache_entry_review_profile"]["embedded_media_nearby"], False)
            web_log = next(
                artifact
                for artifact in payload["artifacts"]
                if artifact["artifact_type"] == "web-server-log"
                and artifact["details"]["parsed_log"]["format"] == "iis-w3c"
            )
            self.assertEqual(web_log["details"]["parsed_row_count"], 1)
            self.assertEqual(web_log["details"]["parsed_log"]["status_counts"]["200"], 1)
            self.assertEqual(web_log["details"]["parsed_log"]["timeline_sample_count"], 1)
            self.assertEqual(web_log["details"]["parsed_log"]["timeline_samples"][0]["normalized_time"], "2026-05-01T10:00:00+00:00")
            self.assertEqual(web_log["details"]["parsed_log"]["timeline_samples"][0]["time_parse_status"], "iis-w3c-utc")
            self.assertEqual(web_log["details"]["correlated_source_count"], 1)
            self.assertEqual(
                web_log["details"]["request_file_correlation"]["matches"][0]["request_basename"],
                "shell.aspx",
            )
            combined_log = next(
                artifact
                for artifact in payload["artifacts"]
                if artifact["artifact_type"] == "web-server-log"
                and artifact["details"]["parsed_log"]["format"] == "apache-nginx-combined"
            )
            self.assertEqual(combined_log["details"]["parsed_log"]["suspicious_request_count"], 2)
            combined_request = combined_log["details"]["parsed_log"]["suspicious_requests"][0]
            self.assertIn("cmd=", combined_request["risk_flags"])
            self.assertIn("whoami", combined_request["risk_flags"])
            self.assertEqual(combined_request["query_keys"], ["cmd"])
            self.assertEqual(combined_request["normalized_time"], "2026-05-01T10:01:00+00:00")
            self.assertEqual(combined_request["time_parse_status"], "apache-nginx-offset")
            self.assertEqual(combined_log["details"]["parsed_log"]["timeline_samples"][0]["normalized_time"], "2026-05-01T10:01:00+00:00")
            self.assertTrue(combined_log["details"]["request_file_correlation"]["matches"][0]["webshell_extension"])
            encoded_request = combined_log["details"]["parsed_log"]["suspicious_requests"][1]
            self.assertTrue(encoded_request["url_decode_applied"])
            self.assertEqual(encoded_request["decoded_uri_preview"], "/shell.aspx?cmd=whoami")
            self.assertEqual(encoded_request["query_keys"], ["cmd"])
            self.assertIn("cmd=", encoded_request["risk_flags"])
            self.assertIn("whoami", encoded_request["risk_flags"])
            decoded_basename_sources = web_request_basename_sources(["/%73hell.aspx?cmd=whoami"])
            self.assertEqual(decoded_basename_sources["shell.aspx"]["source"], "decoded")
            self.assertEqual(decoded_basename_sources["shell.aspx"]["decoded_uri"], "/shell.aspx?cmd=whoami")
            json_log = next(
                artifact
                for artifact in payload["artifacts"]
                if artifact["artifact_type"] == "web-server-log"
                and artifact["details"]["parsed_log"]["format"] == "json-lines"
            )
            self.assertEqual(json_log["details"]["parsed_log"]["timeline_samples"][0]["time_parse_status"], "json-iso8601")
            self.assertEqual(json_log["details"]["parsed_log"]["timeline_samples"][0]["source_ip"], "10.0.0.7")
            json_request = json_log["details"]["parsed_log"]["suspicious_requests"][0]
            self.assertIn("powershell", json_request["risk_flags"])
            self.assertEqual(json_request["method"], "POST")
            self.assertEqual(json_log["details"]["parsed_log"]["method_counts"]["POST"], 1)
            key_value_log = next(
                artifact
                for artifact in payload["artifacts"]
                if artifact["artifact_type"] == "web-server-log"
                and artifact["details"]["parsed_log"]["format"] == "key-value"
            )
            self.assertEqual(key_value_log["details"]["parsed_log"]["timeline_samples"][0]["time_parse_status"], "json-iso8601")
            self.assertEqual(key_value_log["details"]["parsed_log"]["timeline_samples"][0]["source_ip"], "10.0.0.8")
            key_value_request = key_value_log["details"]["parsed_log"]["suspicious_requests"][0]
            self.assertIn("cmd=", key_value_request["risk_flags"])
            self.assertIn("whoami", key_value_request["risk_flags"])
            self.assertEqual(key_value_request["method"], "POST")
            self.assertEqual(key_value_request["status"], "500")
            self.assertEqual(key_value_request["query_keys"], ["cmd"])
            self.assertEqual(key_value_log["details"]["parsed_log"]["row_samples"][0]["raw_key_count"], "6")

    def test_manifest_surfaces_fixture_browser_history_downloads_and_recent_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            fixture = build_windows_artifact_fixture(root)
            output = root / "manifest.json"

            exit_code = main(["manifest", str(root), "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            serialized_artifacts = [
                json.dumps(artifact, ensure_ascii=False, sort_keys=True)
                for provider in payload["providers"]
                for artifact in provider["artifacts"]
            ]
            manifest_blob = "\n".join(serialized_artifacts)

            self.assertIn(fixture.chrome_visit.url, manifest_blob)
            self.assertIn(fixture.ai_visit.url, manifest_blob)
            self.assertIn("browser-ai-usage", manifest_blob)
            self.assertIn("browser-ai-conversation", manifest_blob)
            self.assertIn("timeline analysis for evtx", manifest_blob)
            self.assertIn("How do I build an EVTX forensic timeline?", manifest_blob)
            self.assertIn(fixture.edge_visit.url, manifest_blob)
            self.assertIn(PureWindowsPath(fixture.download.target_path).name, manifest_blob)
            self.assertIn(fixture.recent_shortcut.name, manifest_blob)
            self.assertIn(r"C:\\Users\\alice\\Documents\\Incident Notes.docx", manifest_blob)

    def test_manifest_windows_artifact_rows_point_inside_fixture_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            fixture = build_windows_artifact_fixture(root)
            output = root / "manifest.json"

            self.assertEqual(main(["manifest", str(root), "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            artifact_rows = [artifact for provider in payload["providers"] for artifact in provider["artifacts"]]

            matching = [
                artifact
                for artifact in artifact_rows
                if fixture.chrome_visit.url in json.dumps(artifact, ensure_ascii=False)
                or fixture.edge_visit.url in json.dumps(artifact, ensure_ascii=False)
                or fixture.recent_shortcut.name in json.dumps(artifact, ensure_ascii=False)
            ]

            self.assertTrue(matching)
            for artifact in matching:
                self.assertTrue(Path(artifact["path"]).is_relative_to(root.resolve()))
                self.assertIn("supported", artifact)
                self.assertIsInstance(artifact["details"], dict)

    def test_browser_collector_detects_internet_and_ai_usage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            fixture = build_windows_artifact_fixture(root)
            output = root / "browser.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "browser", "--output", str(output)]), 0)
            artifacts = json.loads(output.read_text(encoding="utf-8"))["artifacts"]
            chrome = next(
                artifact
                for artifact in artifacts
                if artifact["artifact_type"] == "browser-history-downloads"
                and artifact["details"]["browser"] == "chrome"
            )
            ai_usage = next(artifact for artifact in artifacts if artifact["artifact_type"] == "browser-ai-usage")
            ai_conversation = next(
                artifact for artifact in artifacts if artifact["artifact_type"] == "browser-ai-conversation"
            )
            storage_inventory = next(
                artifact for artifact in artifacts if artifact["artifact_type"] == "browser-storage-inventory"
            )

            self.assertEqual(chrome["details"]["history_count"], 2)
            self.assertEqual(chrome["details"]["ai_usage_count"], 1)
            self.assertGreaterEqual(chrome["details"]["ai_conversation_candidate_count"], 2)
            self.assertGreaterEqual(chrome["details"]["browser_storage_inventory_count"], 5)
            self.assertGreaterEqual(chrome["details"]["browser_sensitive_inventory_count"], 3)
            self.assertFalse(chrome["details"]["commercial_grade_ready"])
            self.assertIn("cookie-value-decryption-and-legal-opt-in-not-implemented", chrome["details"]["commercial_grade_blockers"])
            self.assertIn("#19", chrome["details"]["browser_report_grade_assessment"]["commercial_gap_ids"])
            self.assertIn("#20", chrome["details"]["browser_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(chrome["details"]["forensic_review"]["gap_id"], "#20")
            self.assertFalse(chrome["details"]["forensic_review"]["report_grade_ready"])
            self.assertFalse(chrome["details"]["browser_native_capabilities"]["full_cache_entry_decode"])
            browser_gates = {gate["gap_id"]: gate for gate in chrome["details"]["core_accuracy_gates"]}
            self.assertIn("profile/source attribution", browser_gates["#19"]["satisfied_checks"])
            self.assertIn("secret/cookie opt-in legal gate", browser_gates["#19"]["satisfied_checks"])
            self.assertIn("timestamp normalization", browser_gates["#20"]["satisfied_checks"])
            self.assertIn("Safari scope limitation disclosure", browser_gates["#20"]["satisfied_checks"])
            self.assertIn("storage review prioritization", browser_gates["#19"]["satisfied_checks"])
            self.assertIn("timeline integrity profile", browser_gates["#20"]["satisfied_checks"])
            browser_uplift = chrome["details"]["commercial_uplift_evidence"]
            self.assertEqual(browser_uplift["batch_id"], "commercial-uplift-016-020")
            self.assertEqual(browser_uplift["item_numbers"], [19, 20])
            self.assertEqual(
                browser_uplift["reportability_decision"]["allowed_use"],
                "browser-storage-and-timeline-triage-pivot",
            )
            self.assertIn("unified-timeline", browser_uplift["passed_validation_matrix_ids"])
            self.assertTrue(browser_uplift["large_data_controls"]["secret_values_redacted_by_default"])
            browser_review_profile = chrome["details"]["browser_analyst_review_profile"]
            self.assertEqual(browser_review_profile["profile_version"], "browser-analyst-review-profile-v1")
            self.assertEqual(browser_review_profile["browser"], "chrome")
            self.assertEqual(browser_review_profile["source_field_values"]["history_count"], 2)
            self.assertEqual(browser_review_profile["source_field_values"]["unified_timeline_count"], 2)
            self.assertIn("Windows Search", browser_review_profile["correlation_targets"])
            self.assertIn("decrypted cookies/passwords/session tokens", browser_review_profile["not_proof_of"])
            self.assertEqual(chrome["details"]["unified_timeline_count"], 2)
            self.assertEqual(chrome["details"]["unified_timeline"][0]["timeline_type"], "visit")
            self.assertEqual(chrome["details"]["unified_timeline"][0]["browser"], "chrome")
            timeline_depth = chrome["details"]["browser_timeline_depth_manifest"]
            self.assertEqual(timeline_depth["manifest_version"], "browser-timeline-depth-manifest-v1")
            self.assertEqual(timeline_depth["gap_id"], "#20")
            self.assertEqual(timeline_depth["timeline_scope"]["history_row_count"], 2)
            self.assertEqual(timeline_depth["timeline_scope"]["timeline_row_count"], 2)
            self.assertTrue(timeline_depth["integrity"]["sorted_descending"])
            self.assertTrue(timeline_depth["integrity"]["source_index_complete"])
            self.assertFalse(timeline_depth["native_depth"]["safari_windows_profile_support"])
            self.assertEqual(
                chrome["details"]["browser_timeline_depth_manifest_hash"],
                timeline_depth["manifest_sha256"],
            )
            self.assertEqual(chrome["details"]["history"][0]["source_table"], "urls")
            self.assertIsInstance(chrome["details"]["history"][0]["source_row_id"], int)
            citation_manifest = chrome["details"]["browser_history_download_citation_manifest"]
            self.assertEqual(citation_manifest["manifest_version"], "browser-history-download-citation-manifest-v1")
            self.assertEqual(citation_manifest["item_number"], 46)
            self.assertEqual(citation_manifest["gap_id"], "#46")
            self.assertEqual(len(citation_manifest["manifest_sha256"]), 64)
            self.assertEqual(
                chrome["details"]["browser_history_download_citation_manifest_hash"],
                citation_manifest["manifest_sha256"],
            )
            self.assertEqual(citation_manifest["citation_row_count"], 2)
            self.assertEqual(citation_manifest["row_locator_count"], 2)
            self.assertEqual(citation_manifest["history_citations"][0]["source_viewer_locator"]["viewer"], "sqlite")
            self.assertIn("row_hash", citation_manifest["history_citations"][0])
            self.assertTrue(chrome["details"]["browser_validation_checks"]["row_level_citation_manifest_present"])
            self.assertTrue(chrome["details"]["browser_validation_checks"]["row_level_source_locators_present"])
            self.assertTrue(chrome["details"]["browser_timeline_integrity_profile"]["sorted_descending"])
            self.assertTrue(chrome["details"]["browser_timeline_integrity_profile"]["source_index_complete"])
            self.assertGreaterEqual(chrome["details"]["browser_storage_review_profile"]["sensitive_inventory_count"], 3)
            self.assertIn("typed_count", chrome["details"]["history"][0])
            self.assertTrue(chrome["details"]["browser_validation_checks"]["typed_url_metadata_present"])
            chrome_storage_depth = chrome["details"]["browser_storage_depth_manifest"]
            self.assertEqual(chrome_storage_depth["manifest_version"], "browser-storage-depth-manifest-v1")
            self.assertEqual(chrome_storage_depth["gap_id"], "#19")
            self.assertEqual(chrome_storage_depth["qc_prep_item_numbers"], [33, 34])
            self.assertEqual(chrome_storage_depth["qc_prep_contracts"][0]["item_number"], 33)
            self.assertEqual(chrome_storage_depth["qc_prep_contracts"][1]["item_number"], 34)
            self.assertTrue(chrome_storage_depth["storage_scope"]["cache_present"])
            self.assertTrue(chrome_storage_depth["storage_scope"]["session_present"])
            self.assertTrue(chrome_storage_depth["storage_scope"]["extension_present"])
            self.assertTrue(chrome_storage_depth["storage_scope"]["sync_present"])
            self.assertFalse(chrome_storage_depth["native_depth"]["full_cache_entry_decode"])
            self.assertFalse(chrome_storage_depth["native_depth"]["sync_engine_state_decode"])
            self.assertEqual(
                chrome["details"]["browser_storage_depth_manifest_hash"],
                chrome_storage_depth["manifest_sha256"],
            )
            storage_review = storage_inventory["details"]["browser_analyst_review_profile"]
            self.assertEqual(storage_review["profile_version"], "browser-analyst-review-profile-v1")
            self.assertEqual(storage_review["artifact_type"], "browser-storage-inventory")
            self.assertGreaterEqual(storage_review["source_field_values"]["sensitive_inventory_count"], 3)
            self.assertIn("secret-scope-warning", storage_review["risk_tags"])
            self.assertIn({"value": "ai", "count": 1}, chrome["details"]["internet_category_counts"])
            self.assertEqual(ai_usage["details"]["browser"], "chrome")
            self.assertEqual(ai_usage["details"]["ai_usage_count"], 1)
            self.assertGreaterEqual(ai_usage["details"]["ai_conversation_candidate_count"], 2)
            self.assertFalse(ai_usage["details"]["commercial_grade_ready"])
            self.assertIn("#20", ai_usage["details"]["browser_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(ai_usage["details"]["forensic_review"]["gap_id"], "#21")
            self.assertEqual(ai_usage["details"]["ai_usage"][0]["ai_service"], "ChatGPT")
            self.assertEqual(ai_usage["details"]["ai_usage"][0]["url"], fixture.ai_visit.url)
            self.assertEqual(ai_usage["details"]["ai_usage"][0]["prompt_hint"], "timeline analysis for evtx")
            self.assertEqual(len(ai_usage["details"]["source_hashes"]["sha256"]), 64)
            ai_usage_review = ai_usage["details"]["ai_transcript_analyst_review_profile"]
            self.assertEqual(ai_usage_review["profile_version"], "ai-transcript-analyst-review-profile-v1")
            self.assertEqual(ai_usage_review["gap_id"], "#21")
            self.assertIn("browser history", ai_usage_review["correlation_targets"])
            self.assertIn("service-export-validation-missing", ai_usage_review["risk_tags"])
            self.assertEqual(ai_conversation["details"]["coverage_status"], "candidate")
            self.assertFalse(ai_conversation["details"]["commercial_grade_ready"])
            self.assertGreaterEqual(ai_conversation["details"]["question_count"], 2)
            self.assertGreaterEqual(ai_conversation["details"]["answer_count"], 2)
            self.assertGreaterEqual(ai_conversation["details"]["complete_pair_count"], 2)
            self.assertGreater(ai_conversation["details"]["transcript_completeness_score"], 0)
            self.assertIn("pairing_confidence_summary", ai_conversation["details"])
            self.assertEqual(ai_conversation["details"]["source_storage_summary"]["source_file_count"], 1)
            self.assertTrue(ai_conversation["details"]["transcript_validation_checks"]["has_source_hashes"])
            self.assertFalse(ai_conversation["details"]["transcript_validation_checks"]["service_side_export_validated"])
            self.assertIn("#21", ai_conversation["details"]["browser_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(ai_conversation["details"]["forensic_review"]["gap_id"], "#21")
            self.assertFalse(ai_conversation["details"]["browser_native_capabilities"]["service_side_transcript_export_validation"])
            ai_review = ai_conversation["details"]["ai_transcript_analyst_review_profile"]
            self.assertEqual(ai_review["profile_version"], "ai-transcript-analyst-review-profile-v1")
            self.assertEqual(ai_review["artifact_type"], "ai-transcript-candidate")
            self.assertGreaterEqual(ai_review["source_field_values"]["complete_pair_count"], 2)
            self.assertIn("complete service-side transcript", ai_review["not_proof_of"])
            self.assertIn("service export", ai_review["correlation_targets"])
            ai_uplift = ai_conversation["details"]["commercial_uplift_evidence"]
            self.assertEqual(ai_uplift["batch_id"], "commercial-uplift-021-025")
            self.assertEqual(ai_uplift["item_numbers"], [21])
            self.assertEqual(ai_uplift["qc_prep_item_numbers"], [36])
            self.assertIn("has_question_answer_pair", ai_uplift["passed_validation_check_ids"])
            self.assertIn("service_side_export_validated", ai_uplift["failed_validation_check_ids"])
            self.assertGreaterEqual(ai_uplift["candidate_quality"]["complete_pair_count"], 2)
            self.assertEqual(ai_uplift["large_data_controls"]["max_ai_storage_files"], 80)
            self.assertEqual(
                ai_uplift["reportability_decision"]["decision"],
                "do-not-report-ai-transcript-as-complete",
            )
            self.assertEqual(
                ai_uplift["reportability_decision"]["allowed_use"],
                "ai-conversation-triage-pivot",
            )
            self.assertIn(
                "service-side-export-not-validated",
                ai_uplift["reportability_decision"]["blockers"],
            )
            ai_gate = ai_conversation["details"]["core_accuracy_gates"][0]
            self.assertEqual(ai_gate["gap_id"], "#21")
            self.assertIn("service/schema version detection", ai_gate["satisfied_checks"])
            self.assertIn("question/answer pairing confidence", ai_gate["satisfied_checks"])
            self.assertIn("AI transcript candidate manifest", ai_gate["satisfied_checks"])
            self.assertIn("candidate source viewer locators", ai_gate["satisfied_checks"])
            self.assertIn("pair source viewer locators", ai_gate["satisfied_checks"])
            self.assertIn("orphan prompt/answer tracking", ai_gate["satisfied_checks"])
            self.assertIn("source offset/storage provenance", ai_gate["satisfied_checks"])
            self.assertIn("privacy and completeness warnings", ai_gate["satisfied_checks"])
            ai_manifest = ai_conversation["details"]["ai_transcript_candidate_manifest"]
            self.assertEqual(ai_manifest["manifest_version"], "ai-transcript-candidate-manifest-v1")
            self.assertEqual(ai_manifest["item_number"], 48)
            self.assertEqual(ai_manifest["gap_id"], "#48")
            self.assertEqual(ai_manifest["qc_prep_item_number"], 36)
            self.assertEqual(len(ai_manifest["manifest_sha256"]), 64)
            self.assertEqual(
                ai_conversation["details"]["ai_transcript_candidate_manifest_hash"],
                ai_manifest["manifest_sha256"],
            )
            self.assertGreaterEqual(ai_manifest["candidate_citation_count"], 4)
            self.assertGreaterEqual(len(ai_manifest["pair_citations"]), 2)
            self.assertIn("text_sha256", ai_manifest["candidate_citations"][0])
            self.assertEqual(ai_manifest["candidate_citations"][0]["source_viewer_locator"]["viewer"], "text-offset")
            ai_schema_manifest = ai_conversation["details"]["ai_transcript_schema_validation_manifest"]
            self.assertEqual(
                ai_schema_manifest["manifest_version"],
                "ai-transcript-schema-validation-manifest-v1",
            )
            self.assertEqual(ai_schema_manifest["item_number"], 21)
            self.assertEqual(ai_schema_manifest["gap_id"], "#21")
            self.assertEqual(ai_schema_manifest["qc_prep_item_number"], 36)
            self.assertEqual(
                ai_schema_manifest["service_schema_validation_status"],
                "service-export-and-schema-validation-required",
            )
            self.assertFalse(ai_schema_manifest["service_schema_matrix"][0]["service_side_export_validated"])
            self.assertFalse(ai_schema_manifest["service_schema_matrix"][0]["schema_version_known"])
            self.assertEqual(
                ai_conversation["details"]["ai_transcript_schema_validation_manifest_hash"],
                ai_schema_manifest["manifest_sha256"],
            )
            self.assertIn(
                "ai-transcript-schema-validation-manifest-emitted",
                ai_uplift["functional_priority_profile"]["passed_validation_check_ids"],
            )
            self.assertIn(
                ai_conversation["details"]["transcript_validation_status"],
                {"paired-candidate", "partial-paired-candidate"},
            )
            transcript_pair = ai_conversation["details"]["transcript_pairs"][0]
            self.assertEqual(transcript_pair["ai_service"], "ChatGPT")
            self.assertTrue(transcript_pair["same_source"])
            self.assertTrue(transcript_pair["pairing_evidence"]["same_source_hash"])
            self.assertEqual(transcript_pair["pairing_evidence"]["source_ordering"], "question-before-answer")
            self.assertEqual(transcript_pair["pairing_confidence"], "high-candidate")
            self.assertEqual(transcript_pair["validation_status"], "paired-candidate")
            candidate_text = "\n".join(
                row["text"] for row in ai_conversation["details"]["conversation_candidates"]
            )
            self.assertIn("How do I build an EVTX forensic timeline?", candidate_text)
            self.assertIn("Correlate EventRecordID", candidate_text)
            self.assertEqual(ai_conversation["details"]["conversation_candidates"][0]["storage_area"], "Local Storage/leveldb")
            self.assertEqual(storage_inventory["details"]["coverage_status"], "inventory-candidate")
            self.assertGreaterEqual(storage_inventory["details"]["sensitive_inventory_count"], 3)
            self.assertEqual(
                storage_inventory["details"]["browser_storage_review_profile"]["review_priority"],
                "legal-scope-review",
            )
            storage_citation_manifest = storage_inventory["details"]["browser_storage_citation_manifest"]
            self.assertEqual(storage_citation_manifest["manifest_version"], "browser-storage-citation-manifest-v1")
            self.assertEqual(storage_citation_manifest["item_number"], 47)
            self.assertEqual(storage_citation_manifest["gap_id"], "#47")
            self.assertEqual(len(storage_citation_manifest["manifest_sha256"]), 64)
            self.assertEqual(
                storage_inventory["details"]["browser_storage_citation_manifest_hash"],
                storage_citation_manifest["manifest_sha256"],
            )
            self.assertGreaterEqual(storage_citation_manifest["citation_row_count"], 5)
            self.assertGreaterEqual(storage_citation_manifest["sensitive_citation_count"], 3)
            self.assertGreaterEqual(storage_citation_manifest["sample_file_hash_count"], 1)
            self.assertEqual(storage_citation_manifest["citations"][0]["raw_values_extracted"], False)
            self.assertIn("source_viewer_locator", storage_citation_manifest["citations"][0])
            self.assertIn("#19", storage_inventory["details"]["browser_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(storage_inventory["details"]["forensic_review"]["gap_id"], "#19")
            storage_depth = storage_inventory["details"]["browser_storage_depth_manifest"]
            self.assertEqual(storage_depth["manifest_version"], "browser-storage-depth-manifest-v1")
            self.assertEqual(storage_depth["item_number"], 19)
            self.assertEqual(storage_depth["qc_prep_item_numbers"], [33, 34])
            self.assertTrue(storage_depth["storage_scope"]["cookie_present"])
            self.assertGreaterEqual(storage_depth["storage_scope"]["sensitive_inventory_count"], 3)
            self.assertEqual(storage_depth["reportability"]["allowed_use"], "browser-storage-inventory-triage-pivot")
            self.assertEqual(
                storage_inventory["details"]["browser_storage_depth_manifest_hash"],
                storage_depth["manifest_sha256"],
            )
            self.assertIn("#42", storage_inventory["details"]["browser_secret_handling_assessment"]["commercial_gap_ids"])
            self.assertEqual(storage_inventory["details"]["secret_handling_forensic_review"]["gap_id"], "#42")
            self.assertFalse(storage_inventory["details"]["browser_native_capabilities"]["cookie_value_decryption"])
            self.assertFalse(storage_inventory["details"]["browser_native_capabilities"]["password_cookie_session_secret_extraction"])
            self.assertFalse(storage_inventory["details"]["validation_checks"]["raw_secret_values_extracted"])
            self.assertFalse(storage_inventory["details"]["secret_handling_validation_checks"]["password_values_decrypted"])
            self.assertFalse(storage_inventory["details"]["secret_handling_validation_checks"]["session_tokens_extracted"])
            self.assertIn("Browser cache, session, sync, cookie", storage_inventory["details"]["privacy_legal_warning"])
            self.assertIn("Password, cookie, and session stores", storage_inventory["details"]["browser_secret_legal_warning"])
            storage_gates = {gate["gap_id"]: gate for gate in storage_inventory["details"]["core_accuracy_gates"]}
            self.assertIn("extension ID/source mapping", storage_gates["#19"]["satisfied_checks"])
            self.assertIn("deleted/synced content warning", storage_gates["#19"]["satisfied_checks"])
            self.assertIn("sensitive artifact inventory", storage_gates["#42"]["satisfied_checks"])
            self.assertIn("secret values redacted by default", storage_gates["#42"]["satisfied_checks"])
            self.assertIn("strict legal warning", storage_gates["#42"]["satisfied_checks"])
            self.assertIn("opt-in reveal workflow warning", storage_gates["#42"]["satisfied_checks"])
            self.assertIn("audit and scope review requirement", storage_gates["#42"]["satisfied_checks"])
            self.assertIn("browser secret authority profile", storage_gates["#42"]["satisfied_checks"])
            self.assertIn("browser secret authority manifest", storage_gates["#42"]["satisfied_checks"])
            self.assertIn("no raw secret serialization", storage_gates["#42"]["satisfied_checks"])
            self.assertIn("controlled reveal disabled by default", storage_gates["#42"]["satisfied_checks"])
            authority_profile = storage_inventory["details"]["browser_secret_authority_profile"]
            self.assertEqual(authority_profile["profile_version"], "browser-secret-authority-v1")
            self.assertEqual(authority_profile["qc_prep_item_number"], 35)
            self.assertEqual(authority_profile["selected_track"], "inventory-only-controlled-reveal-required")
            self.assertFalse(authority_profile["raw_secret_reveal_allowed"])
            self.assertTrue(authority_profile["secret_values_redacted_by_default"])
            self.assertTrue(authority_profile["legal_authority_record_required"])
            self.assertTrue(authority_profile["reveal_audit_log_required"])
            self.assertTrue(authority_profile["trusted_secret_authority_diff_required"])
            authority_manifest = storage_inventory["details"]["browser_secret_authority_manifest"]
            self.assertEqual(authority_manifest["manifest_version"], "browser-secret-authority-manifest-v1")
            self.assertEqual(authority_manifest["item_number"], 42)
            self.assertEqual(authority_manifest["qc_prep_item_number"], 35)
            self.assertGreaterEqual(authority_manifest["sensitive_store_count"], 3)
            self.assertEqual(authority_manifest["controlled_reveal_policy"], "disabled-by-default")
            self.assertFalse(authority_manifest["raw_secret_reveal_allowed"])
            self.assertFalse(authority_manifest["raw_secret_values_serialized"])
            self.assertFalse(authority_manifest["raw_secret_values_extracted"])
            self.assertIn("raw-secret-values-not-serialized", authority_manifest["passed_validation_check_ids"])
            self.assertIn("per-store-source-viewer-locators", authority_manifest["passed_validation_check_ids"])
            self.assertIn("lawful-secret-reveal-authority-not-attached", authority_manifest["failed_validation_check_ids"])
            self.assertEqual(authority_manifest["entries"][0]["controlled_reveal_status"], "blocked-by-default")
            self.assertTrue(authority_manifest["entries"][0]["source_viewer_locator"]["open_requires_authority"])
            secret_uplift = storage_inventory["details"]["secret_handling_commercial_uplift_evidence"]
            self.assertEqual(secret_uplift["batch_id"], "commercial-uplift-041-045")
            self.assertEqual(secret_uplift["item_numbers"], [42])
            self.assertEqual(secret_uplift["qc_prep_item_numbers"], [35])
            self.assertIn("raw-secret-values-redacted", secret_uplift["passed_control_ids"])
            self.assertIn("strict_legal_warning_present", secret_uplift["passed_control_ids"])
            self.assertIn("browser-secret-authority-profile-present", secret_uplift["passed_control_ids"])
            self.assertIn("browser-secret-authority-manifest-present", secret_uplift["passed_control_ids"])
            self.assertIn("raw-secret-values-not-serialized", secret_uplift["passed_control_ids"])
            self.assertIn("controlled-reveal-disabled-by-default", secret_uplift["passed_control_ids"])
            self.assertTrue(secret_uplift["large_data_controls"]["secret_values_redacted_by_default"])
            self.assertFalse(secret_uplift["large_data_controls"]["dpapi_keychain_integration"])
            self.assertTrue(secret_uplift["large_data_controls"]["browser_secret_authority_profile_present"])
            self.assertTrue(secret_uplift["large_data_controls"]["browser_secret_authority_manifest_present"])
            self.assertFalse(secret_uplift["large_data_controls"]["raw_secret_values_serialized"])
            self.assertGreaterEqual(secret_uplift["large_data_controls"]["per_store_reveal_entry_count"], 3)
            self.assertTrue(secret_uplift["large_data_controls"]["controlled_reveal_disabled_by_default"])
            self.assertEqual(
                secret_uplift["reportability_decision"]["decision"],
                "do-not-report-browser-secrets-as-decrypted-or-revealed",
            )
            self.assertEqual(
                secret_uplift["reportability_decision"]["allowed_use"],
                "browser-secret-store-inventory-triage-pivot",
            )
            self.assertTrue(secret_uplift["reportability_decision"]["secret_values_redacted_by_default"])
            self.assertFalse(secret_uplift["reportability_decision"]["dpapi_keychain_integration"])
            self.assertTrue(secret_uplift["reportability_decision"]["browser_secret_authority_profile_present"])
            self.assertTrue(secret_uplift["reportability_decision"]["browser_secret_authority_manifest_present"])
            self.assertEqual(secret_uplift["reportability_decision"]["controlled_reveal_policy"], "disabled-by-default")
            storage_uplift = storage_inventory["details"]["commercial_uplift_evidence"]
            self.assertEqual(storage_uplift["batch_id"], "commercial-uplift-016-020")
            self.assertEqual(storage_uplift["item_numbers"], [19, 20])
            self.assertEqual(storage_uplift["qc_prep_item_numbers"], [33, 34])
            self.assertGreaterEqual(storage_uplift["large_data_controls"]["storage_inventory_count"], 5)
            inventory_types = {row["storage_type"] for row in storage_inventory["details"]["storage_inventory"]}
            self.assertIn("cache", inventory_types)
            self.assertIn("cookie", inventory_types)
            self.assertIn("extension", inventory_types)

    def test_browser_secret_trusted_diff_controls_secret_authority_gate(self) -> None:
        rapid = [
            {
                "browser": "chrome",
                "profile": "Default",
                "storage_type": "credential",
                "storage_name": "Login Data",
                "raw_secret_values_extracted": False,
                "legal_authority_id": "auth-1",
                "audit_event_id": "audit-1",
            }
        ]
        diff = build_browser_secret_trusted_diff(
            rapid,
            [dict(rapid[0])],
            trusted_tool="legal-authority-record",
        )
        self.assertEqual(diff["status"], "pass")
        generated_row = {
            "artifact_type": "browser-storage-inventory",
            "details": {
                "browser": "chrome",
                "profile": "Default",
                "raw_secret_values_extracted": False,
                "legal_authority_id": "auth-1",
                "audit_event_id": "audit-1",
                "storage_inventory": [
                    {
                        "storage_type": "credential",
                        "storage_name": "Login Data",
                        "sensitive": True,
                    },
                    {
                        "storage_type": "cache",
                        "storage_name": "Cache",
                        "sensitive": False,
                    },
                ],
            },
        }
        nested_diff = build_browser_secret_trusted_diff(
            [generated_row],
            [dict(rapid[0])],
            trusted_tool="legal-authority-record",
        )
        self.assertEqual(nested_diff["status"], "pass")
        self.assertEqual(nested_diff["rapid_indexed_count"], 1)
        gate = browser_core_accuracy_gates(
            {
                "source_path": "Login Data",
                "browser": "chrome",
                "profile": "Default",
                "storage_inventory": rapid,
                "secret_validation_checks": {
                    "inventory_only_mode": True,
                    "raw_secret_values_extracted": False,
                    "strict_legal_warning_present": True,
                    "scope_review_required": True,
                },
                "browser_secret_authority_profile": {
                    "profile_version": "browser-secret-authority-v1",
                    "controlled_reveal_policy": "disabled-by-default",
                    "raw_secret_reveal_allowed": False,
                },
                "browser_secret_trusted_diff": diff,
            }
        )[-1]
        self.assertEqual(gate["gap_id"], "#42")
        self.assertIn("browser secret authority profile", gate["satisfied_checks"])
        self.assertIn("controlled reveal disabled by default", gate["satisfied_checks"])
        self.assertIn("trusted browser secret authority diff pass", gate["satisfied_checks"])

        mismatch = build_browser_secret_trusted_diff(
            rapid,
            [{**rapid[0], "audit_event_id": "changed"}],
            trusted_tool="legal-authority-record",
        )
        self.assertEqual(mismatch["status"], "diffs-present")
        self.assertIn("browser-secret-authority-diff-required", mismatch["reportability_decision"]["blockers"])

    def test_recent_shortcut_collector_parses_lnk_header_and_target_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            fixture = build_windows_artifact_fixture(root)
            output = root / "recent.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "recent-files", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            shortcut = next(item for item in payload["artifacts"] if item["artifact_type"] == "recent-shortcut")
            automatic = next(item for item in payload["artifacts"] if item["artifact_type"] == "jumplist-automatic")
            custom = next(item for item in payload["artifacts"] if item["artifact_type"] == "jumplist-custom")
            details = shortcut["details"]

            self.assertEqual(details["entry_name"], fixture.recent_shortcut.name)
            self.assertEqual(details["lnk_parse_status"], "parsed")
            self.assertEqual(details["target_path"], r"C:\Users\alice\Documents\Incident Notes.docx")
            self.assertEqual(details["working_dir"], r"C:\Users\alice\Documents")
            self.assertIn("IsUnicode", details["link_flag_names"])
            self.assertIn("ARCHIVE", details["file_attribute_names"])
            self.assertFalse(details["commercial_grade_ready"])
            self.assertIn("#17", details["recent_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(details["forensic_review"]["gap_id"], "#17")
            self.assertFalse(details["forensic_review"]["report_grade_ready"])
            self.assertFalse(details["recent_native_capabilities"]["full_shell_item_property_store_decode"])
            self.assertTrue(details["validation_checks"]["has_tracker_data"])
            self.assertEqual(details["validation_checks"]["extra_data_block_count"], 1)
            self.assertEqual(details["extra_data_blocks"][0]["type"], "TrackerDataBlock")
            self.assertEqual(details["tracker_data"]["machine_id"], "ALICE-PC")
            self.assertEqual(details["tracker_data"]["parse_status"], "parsed-candidate")
            self.assertIn("candidate", details["tracker_data"]["validation_status"])
            lnk_gate = details["core_accuracy_gates"][0]
            self.assertEqual(lnk_gate["gap_id"], "#17")
            self.assertIn("header flag consistency", lnk_gate["satisfied_checks"])
            self.assertIn("target/working-dir/arguments extraction", lnk_gate["satisfied_checks"])
            self.assertIn("tracker GUID validation", lnk_gate["satisfied_checks"])
            self.assertIn("timestamp/source field provenance", lnk_gate["satisfied_checks"])
            lnk_uplift = details["commercial_uplift_evidence"]
            self.assertEqual(lnk_uplift["batch_id"], "commercial-uplift-016-020")
            self.assertEqual(lnk_uplift["item_numbers"], [17])
            self.assertEqual(lnk_uplift["qc_prep_item_numbers"], [32])
            self.assertEqual(
                lnk_uplift["reportability_decision"]["decision"],
                "do-not-report-target-context-as-complete",
            )
            self.assertIn("has-valid-header", lnk_uplift["passed_validation_matrix_ids"])
            self.assertTrue(lnk_uplift["large_data_controls"]["property_store_decode_required_for_commercial_claims"])
            lnk_review_profile = details["lnk_analyst_review_profile"]
            self.assertEqual(lnk_review_profile["profile_version"], "lnk-analyst-review-profile-v1")
            self.assertEqual(lnk_review_profile["qc_prep_item_number"], 32)
            self.assertEqual(
                lnk_review_profile["source_field_values"]["target_path"],
                r"C:\Users\alice\Documents\Incident Notes.docx",
            )
            self.assertEqual(lnk_review_profile["source_field_values"]["tracker_machine_id"], "ALICE-PC")
            self.assertIn("MFT", lnk_review_profile["correlation_targets"])
            self.assertIn("complete Shell Item semantics", lnk_review_profile["not_proof_of"])
            lnk_manifest = details["lnk_metadata_depth_manifest"]
            self.assertEqual(lnk_manifest["manifest_version"], "lnk-metadata-depth-manifest-v1")
            self.assertEqual(lnk_manifest["gap_id"], "#17")
            self.assertEqual(lnk_manifest["qc_prep_item_number"], 32)
            self.assertEqual(lnk_manifest["source"]["source_format"], "lnk-shell-link")
            self.assertEqual(lnk_manifest["row_identity"]["target_path"], r"C:\Users\alice\Documents\Incident Notes.docx")
            self.assertEqual(lnk_manifest["row_identity"]["tracker_machine_id"], "ALICE-PC")
            self.assertEqual(lnk_manifest["header_validation"]["parse_status"], "parsed")
            self.assertIn("IsUnicode", lnk_manifest["header_validation"]["link_flag_names"])
            self.assertEqual(lnk_manifest["extra_data"]["extra_data_block_types"], ["TrackerDataBlock"])
            self.assertFalse(lnk_manifest["extra_data"]["full_property_store_decode_available"])
            self.assertEqual(
                lnk_manifest["reportability"]["allowed_use"],
                "shortcut-target-and-metadata-triage-pivot",
            )
            self.assertFalse(lnk_manifest["reportability"]["target_context_complete"])
            self.assertEqual(details["lnk_metadata_depth_manifest_hash"], lnk_manifest["manifest_sha256"])
            self.assertEqual(len(details["source_hashes"]["sha256"]), 64)
            self.assertEqual(automatic["details"]["jump_list_parse_status"], "parsed-ole-stream-lnk")
            self.assertEqual(automatic["details"]["ole_parse_status"], "parsed")
            self.assertEqual(automatic["details"]["ole_stream_count"], 2)
            self.assertEqual(automatic["details"]["destlist_parse_status"], "parsed-candidate")
            self.assertEqual(automatic["details"]["destlist_stream_count"], 1)
            self.assertEqual(automatic["details"]["destlist_entry_candidate_count"], 1)
            self.assertTrue(automatic["details"]["destlist_validation_checks"]["declared_count_matches_candidates"])
            self.assertEqual(automatic["details"]["jumplist_evidence"]["container"]["kind"], "automatic")
            self.assertIn("DestList", automatic["details"]["jumplist_evidence"]["container"]["stream_names"])
            self.assertEqual(
                automatic["details"]["jumplist_evidence"]["destlist"]["parse_status"],
                "parsed-candidate",
            )
            self.assertEqual(automatic["details"]["jumplist_evidence"]["destlist"]["candidate_count"], 1)
            self.assertFalse(automatic["details"]["validation_checks"]["destlist_report_grade"])
            self.assertIn(
                "destlist-os-version-specific-field-validation-required",
                automatic["details"]["commercial_grade_blockers"],
            )
            self.assertIn("#14", automatic["details"]["recent_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(automatic["details"]["forensic_review"]["gap_id"], "#14")
            self.assertIn("JumpList", automatic["details"]["forensic_review"]["artifact_goal"])
            self.assertFalse(automatic["details"]["recent_native_capabilities"]["destlist_deleted_entry_recovery"])
            self.assertEqual(automatic["details"]["destination_count"], 1)
            self.assertEqual(automatic["details"]["destinations"][0]["target_path"], r"C:\Users\alice\Documents\Incident Notes.docx")
            self.assertTrue(automatic["details"]["destinations"][0]["has_tracker_data"])
            self.assertEqual(automatic["details"]["destinations"][0]["stream_path"], "1")
            self.assertEqual(automatic["details"]["destinations"][0]["destlist_validation_status"], "candidate-linked-lnk-stream")
            self.assertEqual(
                automatic["details"]["jumplist_evidence"]["destinations"][0]["target_path"],
                r"C:\Users\alice\Documents\Incident Notes.docx",
            )
            self.assertEqual(
                automatic["details"]["jumplist_evidence"]["destinations"][0]["destlist_validation_status"],
                "candidate-linked-lnk-stream",
            )
            jumplist_gate = automatic["details"]["core_accuracy_gates"][0]
            self.assertEqual(jumplist_gate["gap_id"], "#14")
            self.assertIn("CFB stream inventory", jumplist_gate["satisfied_checks"])
            self.assertIn("DestList header/entry layout", jumplist_gate["satisfied_checks"])
            self.assertIn("embedded LNK linkage", jumplist_gate["satisfied_checks"])
            self.assertIn("AppID mapping provenance", jumplist_gate["satisfied_checks"])
            self.assertIn("deleted-entry warning", jumplist_gate["satisfied_checks"])
            jumplist_uplift = automatic["details"]["commercial_uplift_evidence"]
            self.assertEqual(jumplist_uplift["batch_id"], "commercial-uplift-011-015")
            self.assertEqual(jumplist_uplift["item_numbers"], [14])
            self.assertEqual(jumplist_uplift["qc_prep_item_numbers"], [29])
            self.assertEqual(
                jumplist_uplift["reportability_decision"]["decision"],
                "do-not-report-destlist-semantics-as-final",
            )
            self.assertEqual(
                jumplist_uplift["reportability_decision"]["allowed_use"],
                "recent-destination-triage-pivot",
            )
            self.assertIn("has-destlist-stream", jumplist_uplift["passed_validation_matrix_ids"])
            self.assertTrue(
                jumplist_uplift["large_data_controls"]["deleted_entry_recovery_required_for_commercial_claims"]
            )
            jumplist_manifest = automatic["details"]["jumplist_destlist_depth_manifest"]
            self.assertEqual(jumplist_manifest["manifest_version"], "jumplist-destlist-depth-manifest-v1")
            self.assertEqual(jumplist_manifest["gap_id"], "#14")
            self.assertEqual(jumplist_manifest["qc_prep_item_number"], 29)
            self.assertIn("embedded LNK destination extraction and linkage candidates", jumplist_manifest["qc_prep_contract"]["implemented"])
            self.assertEqual(jumplist_manifest["source"]["artifact_type"], "jumplist-automatic")
            self.assertEqual(jumplist_manifest["destlist_decoding"]["parse_status"], "parsed-candidate")
            self.assertEqual(jumplist_manifest["destlist_decoding"]["entry_candidate_count"], 1)
            self.assertFalse(jumplist_manifest["destlist_decoding"]["os_version_semantics_validated"])
            self.assertFalse(jumplist_manifest["destlist_decoding"]["deleted_entry_recovery_validated"])
            self.assertIn(
                r"C:\Users\alice\Documents\Incident Notes.docx",
                jumplist_manifest["destination_linkage"]["target_paths"],
            )
            self.assertEqual(
                jumplist_manifest["reportability"]["allowed_use"],
                "recent-destination-triage-pivot",
            )
            jumplist_review_profile = automatic["details"]["jumplist_analyst_review_profile"]
            self.assertEqual(jumplist_review_profile["profile_version"], "jumplist-analyst-review-profile-v1")
            self.assertEqual(jumplist_review_profile["source_field_values"]["destination_count"], 1)
            self.assertIn(r"C:\Users\alice\Documents\Incident Notes.docx", jumplist_review_profile["source_field_values"]["target_paths"])
            self.assertIn("ShellBags", jumplist_review_profile["correlation_targets"])
            self.assertIn("destlist-os-version-specific-field-validation-required", jumplist_review_profile["commercial_blockers"])
            self.assertFalse(jumplist_manifest["reportability"]["destlist_semantics_final"])
            self.assertEqual(
                automatic["details"]["jumplist_destlist_depth_manifest_hash"],
                jumplist_manifest["manifest_sha256"],
            )
            self.assertIn(r"C:\Users\alice\Documents\Incident Notes.docx", automatic["details"]["embedded_paths"])
            self.assertEqual(custom["details"]["destinations"][0]["target_path"], r"C:\Users\alice\Downloads\installer.exe")

    def test_eventlog_collector_uses_provider_message_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            logs = root / "Windows" / "System32" / "winevt" / "Logs"
            logs.mkdir(parents=True)
            event_xml = logs / "CustomProvider.xml"
            event_xml.write_text(
                """<Events><Event>
  <System>
    <Provider Name="Custom-Provider"/>
    <EventID>9001</EventID>
    <EventRecordID>7</EventRecordID>
    <Channel>Custom/Operational</Channel>
    <TimeCreated SystemTime="2026-04-30T01:02:03Z"/>
    <Computer>HOST1</Computer>
  </System>
  <EventData>
    <Data Name="User">alice</Data>
    <Data Name="Action">opened case</Data>
  </EventData>
</Event></Events>""",
                encoding="utf-8",
            )
            catalog = root / "message-catalog.json"
            catalog.write_text(
                json.dumps(
                    {
                        "templates": [
                            {
                                "provider": "Custom-Provider",
                                "event_id": "9001",
                                "message": "Custom provider event. User={User}; action={Action}.",
                                "source": "unit-test-provider-manifest",
                                "source_type": "manifest-export",
                                "locale": "en-US",
                                "message_id": "9001",
                                "extraction_tool": "fixture-manifest-dump",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            output = root / "eventlog.json"

            self.assertEqual(
                main(
                    [
                        "artifacts",
                        str(root),
                        "--kind",
                        "eventlog",
                        "--eventlog-message-catalog",
                        str(catalog),
                        "--output",
                        str(output),
                    ]
                ),
                0,
            )
            payload = json.loads(output.read_text(encoding="utf-8"))
            event = next(item for item in payload["artifacts"] if item["artifact_type"] == "eventlog-event")
            rendering = event["details"]["message_rendering"]
            self.assertEqual(rendering["status"], "rendered-provider-catalog-template")
            self.assertEqual(event["details"]["event_message"], "Custom provider event. User=alice; action=opened case.")
            self.assertTrue(rendering["provenance"]["provider_message_resource_resolved"])
            self.assertEqual(
                rendering["provenance"]["provider_message_resource_source"]["source"],
                "unit-test-provider-manifest",
            )
            self.assertEqual(
                rendering["provenance"]["provider_message_resource_source"]["source_type"],
                "manifest-export",
            )
            self.assertEqual(
                rendering["provenance"]["provider_message_resource_source"]["message_id"],
                "9001",
            )
            self.assertEqual(
                rendering["provenance"]["provider_message_resource_source"]["extraction_tool"],
                "fixture-manifest-dump",
            )
            self.assertEqual(
                len(rendering["provenance"]["provider_message_resource_source"]["template_sha256"]),
                64,
            )

    def test_native_evtx_can_render_from_curated_provider_message_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            evtx_path = root / "Windows" / "System32" / "winevt" / "Logs" / "PowerShell.evtx"
            evtx_path.parent.mkdir(parents=True, exist_ok=True)
            evtx_path.write_bytes(
                build_template_evtx(
                    record_id=901,
                    timestamp=datetime(2024, 4, 4, 1, 2, 3, tzinfo=timezone.utc),
                    command="powershell -enc CatalogNative",
                )
            )
            catalog = root / "message-catalog.json"
            catalog.write_text(
                json.dumps(
                    {
                        "templates": [
                            {
                                "provider": "Microsoft-Windows-PowerShell",
                                "event_id": "4104",
                                "message": "Catalog PowerShell script block: {CommandLine}.",
                                "source": "fixture-provider-resource-table",
                                "source_type": "resource-table-export",
                                "locale": "en-US",
                                "message_id": "4104",
                                "extraction_tool": "fixture-resource-extractor",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            output = root / "eventlog.json"

            self.assertEqual(
                main(
                    [
                        "artifacts",
                        str(root),
                        "--kind",
                        "eventlog",
                        "--eventlog-message-catalog",
                        str(catalog),
                        "--output",
                        str(output),
                    ]
                ),
                0,
            )
            artifacts = json.loads(output.read_text(encoding="utf-8"))["artifacts"]
            native_evtx = next(
                item
                for item in artifacts
                if item["artifact_type"] == "eventlog-event"
                and item["details"]["parser"] == "windows-eventlog-evtx-native"
            )["details"]
            rendering = native_evtx["message_rendering"]
            source = rendering["provenance"]["provider_message_resource_source"]

            self.assertEqual(rendering["status"], "rendered-provider-catalog-template")
            self.assertEqual(native_evtx["event_message"], "Catalog PowerShell script block: powershell -enc CatalogNative.")
            self.assertFalse(rendering["provider_resource_required"])
            self.assertTrue(rendering["provenance"]["provider_message_resource_resolved"])
            self.assertEqual(source["source_type"], "resource-table-export")
            self.assertEqual(source["message_id"], "4104")
            self.assertEqual(source["extraction_tool"], "fixture-resource-extractor")
            self.assertEqual(len(source["template_sha256"]), 64)
            self.assertNotIn(
                "provider-message-resource-rendering-not-implemented",
                native_evtx["evtx_report_grade_assessment"]["blockers"],
            )
            self.assertTrue(native_evtx["evtx_native_capabilities"]["curated_provider_message_catalog"])
            self.assertFalse(native_evtx["commercial_grade_ready"])

    def test_native_evtx_can_render_from_windows_event_manifest_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            evtx_path = root / "Windows" / "System32" / "winevt" / "Logs" / "PowerShell.evtx"
            evtx_path.parent.mkdir(parents=True, exist_ok=True)
            evtx_path.write_bytes(
                build_template_evtx(
                    record_id=902,
                    timestamp=datetime(2024, 4, 4, 1, 2, 3, tzinfo=timezone.utc),
                    command="powershell -enc ManifestNative",
                )
            )
            manifest = root / "powershell-provider.man"
            manifest.write_text(
                """<instrumentationManifest xmlns="http://schemas.microsoft.com/win/2004/08/events">
  <instrumentation>
    <events>
      <provider name="Microsoft-Windows-PowerShell" guid="{a0c1853b-5c40-4b15-8766-3cf1c58f985a}">
        <templates>
          <template tid="PowerShellScriptBlockTemplate">
            <data name="CommandLine" inType="win:UnicodeString" />
          </template>
        </templates>
        <events>
          <event value="4104" template="PowerShellScriptBlockTemplate" message="$(string.PS.4104.message)" />
        </events>
      </provider>
    </events>
  </instrumentation>
  <localization>
    <resources culture="en-US">
      <stringTable>
        <string id="PS.4104.message" value="Manifest PowerShell script block: %1." />
      </stringTable>
    </resources>
  </localization>
</instrumentationManifest>""",
                encoding="utf-8",
            )
            output = root / "eventlog.json"

            self.assertEqual(
                main(
                    [
                        "artifacts",
                        str(root),
                        "--kind",
                        "eventlog",
                        "--eventlog-message-catalog",
                        str(manifest),
                        "--output",
                        str(output),
                    ]
                ),
                0,
            )
            artifacts = json.loads(output.read_text(encoding="utf-8"))["artifacts"]
            native_evtx = next(
                item
                for item in artifacts
                if item["artifact_type"] == "eventlog-event"
                and item["details"]["parser"] == "windows-eventlog-evtx-native"
            )["details"]
            rendering = native_evtx["message_rendering"]
            source = rendering["provenance"]["provider_message_resource_source"]

            self.assertEqual(rendering["status"], "rendered-provider-catalog-template")
            self.assertEqual(native_evtx["event_message"], "Manifest PowerShell script block: powershell -enc ManifestNative.")
            self.assertTrue(rendering["provenance"]["provider_message_resource_resolved"])
            self.assertEqual(source["source"], "windows-event-manifest")
            self.assertEqual(source["source_type"], "windows-event-manifest")
            self.assertEqual(source["locale"], "en-US")
            self.assertEqual(source["message_id"], "$(string.PS.4104.message)")
            self.assertEqual(source["manifest_template_id"], "PowerShellScriptBlockTemplate")
            self.assertEqual(source["manifest_template_fields"], ["CommandLine"])
            self.assertEqual(source["extraction_tool"], "rapidtriage-manifest-loader")
            self.assertEqual(len(source["template_sha256"]), 64)
            self.assertFalse(native_evtx["commercial_grade_ready"])

    def test_eventlog_auto_discovers_case_local_message_manifest_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            evtx_path = root / "Windows" / "System32" / "winevt" / "Logs" / "PowerShell.evtx"
            evtx_path.parent.mkdir(parents=True, exist_ok=True)
            evtx_path.write_bytes(
                build_template_evtx(
                    record_id=903,
                    timestamp=datetime(2024, 4, 4, 1, 2, 3, tzinfo=timezone.utc),
                    command="powershell -enc AutoManifest",
                )
            )
            manifest = root / "ProviderManifests" / "powershell-provider.man"
            manifest.parent.mkdir(parents=True, exist_ok=True)
            manifest.write_text(
                """<instrumentationManifest xmlns="http://schemas.microsoft.com/win/2004/08/events">
  <instrumentation>
    <events>
      <provider name="Microsoft-Windows-PowerShell">
        <templates>
          <template tid="PowerShellScriptBlockTemplate">
            <data name="CommandLine" inType="win:UnicodeString" />
          </template>
        </templates>
        <events>
          <event value="4104" template="PowerShellScriptBlockTemplate" message="$(string.PS.4104.message)" />
        </events>
      </provider>
    </events>
  </instrumentation>
  <localization>
    <resources culture="en-US">
      <stringTable>
        <string id="PS.4104.message" value="Auto-discovered manifest rendered: %1." />
      </stringTable>
    </resources>
  </localization>
</instrumentationManifest>""",
                encoding="utf-8",
            )
            output = root / "eventlog.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "eventlog", "--output", str(output)]), 0)

            artifacts = json.loads(output.read_text(encoding="utf-8"))["artifacts"]
            native_evtx = next(
                item
                for item in artifacts
                if item["artifact_type"] == "eventlog-event"
                and item["details"]["parser"] == "windows-eventlog-evtx-native"
            )["details"]
            rendering = native_evtx["message_rendering"]
            source = rendering["provenance"]["provider_message_resource_source"]

            self.assertEqual(rendering["status"], "rendered-provider-catalog-template")
            self.assertEqual(native_evtx["event_message"], "Auto-discovered manifest rendered: powershell -enc AutoManifest.")
            self.assertTrue(rendering["provenance"]["provider_message_resource_resolved"])
            self.assertEqual(source["source_type"], "windows-event-manifest")
            self.assertEqual(source["manifest_template_fields"], ["CommandLine"])
            self.assertTrue(source["catalog_path"].endswith("powershell-provider.man"))

    def test_eventlog_collector_normalizes_exports_detections_and_evtx_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            fixture = build_windows_artifact_fixture(root)
            output = root / "eventlog.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "eventlog", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            artifacts = payload["artifacts"]
            event_rows = [item for item in artifacts if item["artifact_type"] == "eventlog-event"]
            detection_rows = [item for item in artifacts if item["artifact_type"] == "eventlog-detection"]
            inventory_rows = [item for item in artifacts if item["artifact_type"] == "eventlog-file"]
            summary_rows = [item for item in artifacts if item["artifact_type"] == "eventlog-summary"]

            self.assertGreaterEqual(len(event_rows), 3)
            logon = [item for item in event_rows if item["details"]["event_id"] == "4624"][0]
            self.assertEqual(logon["details"]["user_name"], "alice")
            self.assertEqual(logon["details"]["target_user_name"], "alice")
            self.assertEqual(logon["details"]["subject_user_name"], "SYSTEM")
            self.assertEqual(logon["details"]["logon_type"], "10")
            self.assertEqual(logon["details"]["source_ip"], "10.0.0.5")
            self.assertEqual(logon["details"]["event_message"], "An account was successfully logged on.")
            self.assertEqual(logon["details"]["message_rendering"]["status"], "external-message")
            self.assertEqual(logon["details"]["event_family"], "authentication")
            self.assertEqual(logon["details"]["channel_family"], "security")
            self.assertIn("event-id:4624", logon["details"]["event_tags"])
            logon_semantics = logon["details"]["event_semantics_profile"]
            self.assertEqual(logon_semantics["profile_version"], "eventlog-analyst-semantics-v1")
            self.assertEqual(logon_semantics["category"], "logon-success")
            self.assertEqual(logon_semantics["source_field_values"]["target_user_name"], "alice")
            self.assertIn("rdp-session-events", logon_semantics["correlation_targets"])
            powershell = [item for item in event_rows if item["details"]["event_id"] == "4104"][0]
            self.assertEqual(powershell["details"]["event_category"], "powershell-script-block")
            self.assertEqual(powershell["details"]["event_family"], "execution")
            self.assertEqual(powershell["details"]["command_line"], "powershell -enc SQBFAFgA")
            self.assertEqual(powershell["details"]["script_block_text"], "powershell -enc SQBFAFgA")
            self.assertGreaterEqual(powershell["details"]["parser_confidence"], 0.9)
            self.assertIn("high-value-event-id:4104", powershell["details"]["risk_flags"])
            self.assertIn("suspicious-term:powershell -enc", powershell["details"]["risk_flags"])
            self.assertIn("script-content", powershell["details"]["event_semantics_profile"]["risk_tags"])
            self.assertIn(
                "defender-events",
                powershell["details"]["event_semantics_profile"]["correlation_targets"],
            )
            rules_by_id = {item["details"]["rule"]["id"]: item for item in detection_rows}
            encoded_powershell_rules = [
                item for item in detection_rows if item["details"]["rule"]["id"] == "RT-EVTX-PS-ENCODED"
            ]
            self.assertEqual(rules_by_id["RT-PS-001"]["details"]["rule"]["title"], "Suspicious Encoded PowerShell")
            self.assertEqual(rules_by_id["RT-PS-001"]["details"]["coverage_status"], "detected-by-rule")
            self.assertTrue(
                any(item["details"]["parser"] == "windows-eventlog-builtin-rulepack" for item in encoded_powershell_rules)
            )
            self.assertTrue(
                any(item["details"]["matched_event"]["record_id"] == "202" for item in encoded_powershell_rules)
            )
            self.assertTrue(
                any("script_block_text" in item["details"]["matched_fields"] for item in encoded_powershell_rules)
            )
            self.assertEqual(rules_by_id["RT-EVTX-RDP-LOGON"]["details"]["logon_type"], "10")
            self.assertEqual(inventory_rows[0]["details"]["coverage_status"], "detected")
            self.assertEqual(inventory_rows[0]["details"]["source_path"], str(fixture.evtx_file.resolve()))
            self.assertEqual(inventory_rows[0]["details"]["native_record_count"], 1)
            native_evtx = [item for item in event_rows if item["details"]["parser"] == "windows-eventlog-evtx-native"][0]
            self.assertEqual(native_evtx["details"]["coverage_status"], "native-binary-partial")
            self.assertEqual(native_evtx["details"]["reportability"], "triage")
            self.assertEqual(native_evtx["details"]["record_id"], "300")
            self.assertEqual(native_evtx["details"]["event_id"], "4104")
            self.assertEqual(native_evtx["details"]["level"], "3")
            self.assertEqual(native_evtx["details"]["timestamp"], "2024-04-01T03:04:05+00:00")
            self.assertIn("powershell -enc NativeFixture", native_evtx["details"]["extracted_strings"])
            self.assertEqual(native_evtx["details"]["command_line"], "powershell -enc NativeFixture")
            self.assertEqual(native_evtx["details"]["provider_name"], "Microsoft-Windows-PowerShell")
            self.assertEqual(native_evtx["details"]["binxml_system_fields"]["EventID"], "4104")
            self.assertEqual(native_evtx["details"]["binxml_system_fields"]["TimeCreated"], "2024-04-01T03:04:05+00:00")
            self.assertEqual(native_evtx["details"]["binxml_system_fields"]["ProcessID"], "4321")
            self.assertEqual(native_evtx["details"]["binxml_system_fields"]["ThreadID"], "8765")
            self.assertEqual(native_evtx["details"]["binxml_system_fields"]["UserID"], "S-1-5-21-111-222-333-1001")
            self.assertEqual(native_evtx["details"]["binxml_event_data_fields"]["CommandLine"], "powershell -enc NativeFixture")
            self.assertEqual(native_evtx["details"]["binxml_event_data_fields"]["SubjectUserSid"], "S-1-5-21-111-222-333-1001")
            self.assertEqual(native_evtx["details"]["binxml_event_data_fields"]["ProcessId"], "4321")
            self.assertEqual(native_evtx["details"]["binxml_event_data_fields"]["IsElevated"], "true")
            self.assertEqual(native_evtx["details"]["binxml_event_data_fields"]["CpuSeconds"], "12.5")
            self.assertEqual(native_evtx["details"]["binxml_event_data_fields"]["RiskRatio"], "0.25")
            self.assertEqual(native_evtx["details"]["binxml_event_data_fields"]["ActivityGuid"], "33221100-5544-7766-8899-aabbccddeeff")
            self.assertEqual(native_evtx["details"]["binxml_event_data_fields"]["PayloadHash"], "feedface")
            self.assertIn(
                {"index": 0, "name": "CommandLine", "value": "powershell -enc NativeFixture", "path": "Event/EventData/CommandLine", "value_type": "StringType", "confidence": "binxml-value-text"},
                native_evtx["details"]["binxml_event_data_sequence"],
            )
            self.assertEqual(
                native_evtx["details"]["binxml_event_data_values_by_name"]["CommandLine"],
                ["powershell -enc NativeFixture"],
            )
            self.assertEqual(native_evtx["details"]["process_id"], "4321")
            self.assertEqual(native_evtx["details"]["thread_id"], "8765")
            self.assertEqual(native_evtx["details"]["user_sid"], "S-1-5-21-111-222-333-1001")
            self.assertEqual(native_evtx["details"]["message_rendering"]["status"], "rendered-builtin-template")
            self.assertTrue(native_evtx["details"]["message_rendering"]["validation_required"])
            self.assertEqual(native_evtx["details"]["event_semantics_profile"]["severity"], "high")
            self.assertIn(
                "attach trusted EVTX parser diff",
                native_evtx["details"]["event_semantics_profile"]["validation_requirements"][0],
            )
            self.assertEqual(
                native_evtx["details"]["message_rendering"]["provenance"]["renderer"],
                "rapidtriage-builtin-template",
            )
            self.assertFalse(
                native_evtx["details"]["message_rendering"]["provenance"]["provider_message_resource_resolved"]
            )
            self.assertIn("PowerShell script block", native_evtx["details"]["event_message"])
            self.assertIn(
                {"expression": "ScriptBlockText|CommandLine|Payload", "field": "CommandLine"},
                native_evtx["details"]["message_rendering"]["used_fields"],
            )
            self.assertIn(
                "CommandLine",
                native_evtx["details"]["message_rendering"]["available_field_summary"]["event_data_field_names"],
            )
            self.assertIn(
                "Event/EventData/CommandLine",
                native_evtx["details"]["message_rendering"]["available_field_summary"]["binxml_value_field_paths"],
            )
            self.assertEqual(native_evtx["details"]["native_indicators"]["channel_hint_source"], "record-string")
            self.assertEqual(native_evtx["details"]["evtx_record_integrity"]["declared_size_valid"], True)
            self.assertEqual(native_evtx["details"]["evtx_record_integrity"]["trailing_size_valid"], True)
            self.assertEqual(native_evtx["details"]["evtx_file_header"]["signature_valid"], True)
            self.assertEqual(native_evtx["details"]["evtx_file_header"]["major_version"], 3)
            self.assertEqual(native_evtx["details"]["evtx_file_header"]["next_record_identifier"], 301)
            self.assertEqual(native_evtx["details"]["evtx_chunk_context"]["chunk_signature_valid"], False)
            self.assertEqual(native_evtx["details"]["evtx_chunk_context"]["chunk_validation_status"], "missing-or-not-a-chunk-header")
            self.assertEqual(native_evtx["details"]["evtx_chunk_context"]["chunk_boundary_status"], "no-valid-chunk-header")
            self.assertEqual(native_evtx["details"]["evtx_binxml_status"], "basic-rendered")
            self.assertEqual(native_evtx["details"]["evtx_field_fidelity"], "partial-binxml-token-scan")
            self.assertFalse(native_evtx["details"]["evtx_validation_required"])
            self.assertFalse(native_evtx["details"]["validation_required"])
            self.assertTrue(native_evtx["details"]["evtx_validation_checks"]["passes_basic_record_integrity"])
            self.assertFalse(native_evtx["details"]["evtx_report_grade_assessment"]["report_grade_ready"])
            self.assertEqual(
                native_evtx["details"]["evtx_report_grade_assessment"]["status"],
                "triage-validated-report-grade-blocked",
            )
            self.assertIn(
                "provider-message-resource-rendering-required",
                native_evtx["details"]["evtx_report_grade_assessment"]["blockers"],
            )
            self.assertIn("#1", native_evtx["details"]["evtx_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(native_evtx["details"]["evtx_reader_strategy"], "mmap-bounded-record-scan")
            provenance = native_evtx["details"]["evtx_record_provenance"]
            self.assertEqual(provenance["profile_version"], "evtx-record-provenance-v1")
            self.assertEqual(provenance["record_id"], "300")
            self.assertEqual(provenance["event_id"], "4104")
            self.assertEqual(provenance["record_offset"], native_evtx["details"]["evtx_record_offset"])
            self.assertEqual(provenance["record_sha256"], native_evtx["details"]["evtx_record_sha256"])
            self.assertIn("record-magic", provenance["validation_matrix_ids"])
            parse_profile = native_evtx["details"]["evtx_native_parse_profile"]
            self.assertEqual(parse_profile["profile_version"], "evtx-native-binxml-parse-profile-v1")
            self.assertEqual(parse_profile["binxml_status"], "basic-rendered")
            self.assertGreaterEqual(parse_profile["scalar_value_count"], 1)
            self.assertIn("EventID", parse_profile["promoted_field_sections"]["system"])
            self.assertIn("CommandLine", parse_profile["promoted_field_sections"]["event_data"])
            self.assertIn("full-binxml-object-model-not-implemented", parse_profile["commercial_blockers"])
            rendering_profile = native_evtx["details"]["evtx_message_rendering_profile"]
            self.assertEqual(rendering_profile["profile_version"], "evtx-message-rendering-profile-v1")
            self.assertEqual(rendering_profile["renderer"], "rapidtriage-builtin-template")
            self.assertFalse(rendering_profile["provider_message_resource_resolved"])
            self.assertIn("provider-message-resource-or-manifest-required", rendering_profile["blockers"])
            readiness_profile = native_evtx["details"]["evtx_commercial_readiness_profile"]
            self.assertEqual(readiness_profile["profile_version"], "evtx-commercial-readiness-v1")
            self.assertFalse(readiness_profile["commercial_grade_ready"])
            self.assertEqual(readiness_profile["allowed_current_use"], "triage-search-timeline-pivot")
            self.assertEqual(readiness_profile["commercial_gap_ids"], ["#1", "#2", "#3"])
            self.assertEqual(readiness_profile["row_identity"]["record_id"], "300")
            self.assertEqual(readiness_profile["native_binxml"]["status"], "basic-rendered")
            self.assertFalse(readiness_profile["message_rendering"]["provider_resource_resolved"])
            self.assertEqual(readiness_profile["trusted_evidence"]["record_diff_status"], "not-attached")
            self.assertGreaterEqual(readiness_profile["blocker_counts"]["total"], 1)
            self.assertIn("Do not quote", readiness_profile["analyst_warning"])
            uplift = native_evtx["details"]["commercial_uplift_evidence"]
            self.assertEqual(uplift["batch_id"], "commercial-uplift-001-005")
            self.assertEqual(uplift["item_numbers"], [1, 2, 3])
            self.assertEqual(uplift["implementation_track"], "native-parser-depth")
            self.assertIn("record-magic", uplift["passed_validation_matrix_ids"])
            self.assertIn("chunk-context", uplift["failed_validation_matrix_ids"])
            self.assertEqual(uplift["large_data_controls"]["current_reader"], "mmap-bounded-record-scan")
            self.assertEqual(uplift["large_data_controls"]["source_hash_strategy"], "streaming-sha256")
            self.assertFalse(uplift["large_data_controls"]["streaming_reader_required_for_tb_claims"])
            self.assertTrue(uplift["large_data_controls"]["remaining_large_data_proof_required"])
            citation_manifest = native_evtx["details"]["evtx_report_citation_manifest"]
            self.assertEqual(citation_manifest["manifest_version"], "evtx-record-report-citation-manifest-v1")
            self.assertEqual(
                native_evtx["details"]["evtx_report_citation_manifest_hash"],
                citation_manifest["manifest_sha256"],
            )
            self.assertEqual(citation_manifest["row_identity"]["record_id"], "300")
            self.assertEqual(citation_manifest["row_identity"]["event_id"], "4104")
            self.assertEqual(
                citation_manifest["row_identity"]["record_sha256"],
                native_evtx["details"]["evtx_record_sha256"],
            )
            self.assertGreaterEqual(citation_manifest["citation_ref_count"], 3)
            citation_kinds = {item["kind"] for item in citation_manifest["citation_refs"]}
            self.assertIn("evtx-record", citation_kinds)
            self.assertIn("evtx-rendered-message", citation_kinds)
            self.assertIn("evtx-event-data-field", citation_kinds)
            record_ref = next(item for item in citation_manifest["citation_refs"] if item["kind"] == "evtx-record")
            self.assertEqual(record_ref["source_viewer_locator"]["viewer"], "evtx-record-offset")
            command_ref = next(
                item
                for item in citation_manifest["citation_refs"]
                if item["kind"] == "evtx-event-data-field" and item["name"] == "CommandLine"
            )
            self.assertEqual(command_ref["source_viewer_locator"]["viewer"], "evtx-binxml-field")
            self.assertEqual(command_ref["value_type"], "StringType")
            self.assertEqual(
                citation_manifest["reportability"]["allowed_use"],
                "native-evtx-triage-search-timeline-pivot",
            )
            self.assertFalse(citation_manifest["reportability"]["ready_for_court_report"])
            self.assertIn("chunk-context", citation_manifest["validation_summary"]["failed_matrix_ids"])
            self.assertTrue(native_evtx["details"]["evtx_native_capabilities"]["template_substitution_values"])
            self.assertFalse(native_evtx["details"]["evtx_native_capabilities"]["provider_resource_message_rendering"])
            validation_matrix = {item["id"]: item for item in native_evtx["details"]["evtx_validation_matrix"]}
            self.assertTrue(validation_matrix["record-magic"]["passed"])
            self.assertTrue(validation_matrix["binxml-field-decode"]["passed"])
            self.assertFalse(validation_matrix["chunk-context"]["passed"])
            decoded_type_counts = {
                item["value"]: item["count"]
                for item in native_evtx["details"]["evtx_validation_checks"]["decoded_value_type_counts"]
            }
            self.assertGreaterEqual(decoded_type_counts["Real64Type"], 1)
            self.assertGreaterEqual(decoded_type_counts["Real32Type"], 1)
            self.assertTrue(native_evtx["details"]["evtx_validation_checks"]["value_field_map_present"])
            self.assertEqual(native_evtx["details"]["evtx_validation_checks"]["template_substitution_count"], 0)
            self.assertIn("<Event><System>", native_evtx["details"]["native_message_preview"])
            self.assertIn("powershell -enc NativeFixture", native_evtx["details"]["evtx_binxml"]["rendered_preview"])
            self.assertEqual(
                native_evtx["details"]["evtx_binxml"]["value_field_map"]["Event/EventData/CommandLine"],
                ["powershell -enc NativeFixture"],
            )
            self.assertTrue(
                any(item["name"] == "CommandLine" for item in native_evtx["details"]["evtx_binxml"]["elements"])
            )
            self.assertTrue(
                any(
                    item["element_path"] == "Event/EventData/CommandLine"
                    and item["text"] == "powershell -enc NativeFixture"
                    for item in native_evtx["details"]["evtx_binxml"]["value_fields"]
                )
            )
            self.assertTrue(
                any(
                    item["element_path"] == "Event/EventData/ProcessId"
                    and item["text"] == "4321"
                    and item["value_type"] == "UInt32Type"
                    for item in native_evtx["details"]["evtx_binxml"]["value_fields"]
                )
            )
            self.assertTrue(
                any(item["name"] == "CommandLine" for item in native_evtx["details"]["parameter_candidates"])
            )
            self.assertEqual(native_evtx["details"]["evtx_record_sequence"]["status"], "first-record")
            self.assertEqual(len(native_evtx["details"]["evtx_record_sha256"]), 64)
            self.assertGreaterEqual(native_evtx["details"]["parser_confidence"], 0.75)
            self.assertIn("suspicious-term:powershell -enc", native_evtx["details"]["risk_flags"])
            summary = summary_rows[0]["details"]
            self.assertEqual(summary["event_count"], 3)
            self.assertEqual(summary["detection_count"], 4)
            self.assertEqual(summary["parsed_row_count"], 7)
            self.assertEqual(summary["first_event_at"], "2024-04-01T01:02:03.000000+00:00")
            self.assertIn({"value": "4104", "count": 2}, summary["event_id_counts"])
            self.assertIn({"value": "execution", "count": 2}, summary["event_family_counts"])
            self.assertIn({"value": "powershell -enc", "count": 2}, summary["risk_term_counts"])
            self.assertIn({"value": "RT-EVTX-PS-ENCODED", "count": 2}, summary["detection_rule_counts"])
            self.assertIn({"value": "trailing-size-valid", "count": 1}, summary["native_integrity_counts"])
            self.assertIn({"value": "first-record", "count": 1}, summary["native_sequence_counts"])
            self.assertIn({"value": "record-string", "count": 1}, summary["native_channel_hint_counts"])
            self.assertIn({"value": "basic-rendered", "count": 1}, summary["native_binxml_status_counts"])
            self.assertIn({"value": "no-valid-chunk-header", "count": 1}, summary["native_boundary_status_counts"])
            self.assertIn(
                {"value": "triage-validated-report-grade-blocked", "count": 1},
                summary["native_report_grade_status_counts"],
            )
            self.assertFalse(summary["native_capabilities"]["provider_resource_message_rendering"])
            self.assertTrue(any(item["event_id"] == "4104" for item in summary["high_risk_events"]))
            self.assertTrue(any(item["channel"] == "Microsoft-Windows-PowerShell/Operational" for item in summary["record_sequence_gaps"]))

    def test_eventlog_collector_discovers_evtx_exports_outside_default_log_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            evtx_path = root / "analysis" / "evtx" / "Collected-System.evtx"
            evtx_path.parent.mkdir(parents=True, exist_ok=True)
            evtx_path.write_bytes(
                build_minimal_evtx(
                    record_id=777,
                    timestamp=datetime(2024, 4, 2, 1, 2, 3, tzinfo=timezone.utc),
                    strings=["Microsoft-Windows-Security-Auditing", "Security", "WIN-EXPORT", "wevtutil cl Security"],
                )
            )
            output = root / "eventlog.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "eventlog", "--output", str(output)]), 0)
            artifacts = json.loads(output.read_text(encoding="utf-8"))["artifacts"]
            native_rows = [
                item
                for item in artifacts
                if item["artifact_type"] == "eventlog-event"
                and item["details"]["parser"] == "windows-eventlog-evtx-native"
            ]

            self.assertEqual(len(native_rows), 1)
            self.assertEqual(native_rows[0]["details"]["record_id"], "777")
            self.assertEqual(native_rows[0]["details"]["source_path"], str(evtx_path.resolve()))
            self.assertEqual(native_rows[0]["details"]["channel"], "Security")
            self.assertEqual(native_rows[0]["details"]["command_line"], "wevtutil cl Security")

    def test_native_evtx_collector_uses_mmap_reader_instead_of_read_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            evtx_path = root / "Security.evtx"
            evtx_path.write_bytes(
                build_minimal_evtx(
                    record_id=778,
                    timestamp=datetime(2024, 4, 2, 2, 3, 4, tzinfo=timezone.utc),
                    strings=["Microsoft-Windows-Security-Auditing", "Security", "WIN-MMAP", "wevtutil gl Security"],
                )
            )

            with mock.patch.object(Path, "read_bytes", side_effect=AssertionError("EVTX collector must not read full files")):
                artifacts = list(collect_native_evtx_events(evtx_path))

            native_evtx = next(
                item
                for item in artifacts
                if item.artifact_type == "eventlog-event"
                and item.details["parser"] == "windows-eventlog-evtx-native"
            )
            self.assertEqual(native_evtx.details["record_id"], "778")
            self.assertEqual(native_evtx.details["evtx_reader_strategy"], "mmap-bounded-record-scan")
            self.assertEqual(native_evtx.details["commercial_uplift_evidence"]["large_data_controls"]["current_reader"], "mmap-bounded-record-scan")

    def test_eventlog_collector_validates_native_evtx_chunk_checksums(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            evtx_path = root / "Windows" / "System32" / "winevt" / "Logs" / "Checked.evtx"
            evtx_path.parent.mkdir(parents=True, exist_ok=True)
            evtx_path.write_bytes(
                build_evtx_with_checked_chunk(
                    record_id=779,
                    timestamp=datetime(2024, 4, 2, 3, 4, 5, tzinfo=timezone.utc),
                    strings=["Microsoft-Windows-Security-Auditing", "Security", "WIN-CRC", "wevtutil gli Security"],
                )
            )
            output = root / "eventlog.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "eventlog", "--output", str(output)]), 0)
            artifacts = json.loads(output.read_text(encoding="utf-8"))["artifacts"]
            chunk = next(item for item in artifacts if item["artifact_type"] == "eventlog-chunk")["details"]
            native_evtx = next(
                item
                for item in artifacts
                if item["artifact_type"] == "eventlog-event"
                and item["details"]["parser"] == "windows-eventlog-evtx-native"
            )["details"]
            summary = next(item for item in artifacts if item["artifact_type"] == "eventlog-summary")["details"]

            self.assertEqual(native_evtx["record_id"], "779")
            self.assertEqual(chunk["evtx_chunk_integrity"]["checksum_status"], "matched")
            self.assertTrue(chunk["evtx_chunk_integrity"]["header_checksum_match"])
            self.assertTrue(chunk["evtx_chunk_integrity"]["events_checksum_match"])
            self.assertIn({"value": "matched", "count": 1}, summary["native_chunk_integrity_counts"])

    def test_eventlog_collector_decodes_native_evtx_template_substitution_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            evtx_path = root / "Windows" / "System32" / "winevt" / "Logs" / "Template.evtx"
            evtx_path.parent.mkdir(parents=True, exist_ok=True)
            evtx_path.write_bytes(
                build_template_evtx(
                    record_id=888,
                    timestamp=datetime(2024, 4, 3, 1, 2, 3, tzinfo=timezone.utc),
                    command="powershell -enc TemplateValue",
                )
            )
            output = root / "eventlog.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "eventlog", "--output", str(output)]), 0)
            artifacts = json.loads(output.read_text(encoding="utf-8"))["artifacts"]
            native_evtx = next(
                item
                for item in artifacts
                if item["artifact_type"] == "eventlog-event"
                and item["details"]["parser"] == "windows-eventlog-evtx-native"
            )

            self.assertEqual(native_evtx["details"]["record_id"], "888")
            self.assertEqual(native_evtx["details"]["event_id"], "4104")
            self.assertEqual(native_evtx["details"]["level"], "3")
            self.assertEqual(native_evtx["details"]["provider_name"], "Microsoft-Windows-PowerShell")
            self.assertEqual(native_evtx["details"]["channel"], "Microsoft-Windows-PowerShell/Operational")
            self.assertEqual(native_evtx["details"]["evtx_binxml_status"], "template-substituted-partial")
            self.assertEqual(native_evtx["details"]["evtx_field_fidelity"], "partial-binxml-template-substitution")
            self.assertIn("powershell -enc TemplateValue", native_evtx["details"]["command_line"])
            self.assertIn("powershell -enc TemplateValue", native_evtx["details"]["evtx_binxml"]["rendered_preview"])
            self.assertIn(
                "33221100-5544-7766-8899-aabbccddeeff",
                native_evtx["details"]["evtx_binxml"]["template_ids"],
            )
            self.assertIn(
                "33221100-5544-7766-8899-aabbccddeeff",
                native_evtx["details"]["message_rendering"]["template_ids"],
            )
            self.assertEqual(native_evtx["details"]["binxml_system_fields"]["EventID"], "4104")
            self.assertEqual(native_evtx["details"]["binxml_event_data_fields"]["CommandLine"], "powershell -enc TemplateValue")
            self.assertEqual(
                native_evtx["details"]["binxml_event_data_sequence"][0]["value"],
                "powershell -enc TemplateValue",
            )
            self.assertEqual(
                native_evtx["details"]["binxml_event_data_values_by_name"]["CommandLine"],
                ["powershell -enc TemplateValue"],
            )
            self.assertEqual(native_evtx["details"]["evtx_binxml"]["template_values"][0]["value_type"], "StringType")
            self.assertEqual(native_evtx["details"]["evtx_binxml"]["template_substitution_count"], 1)
            self.assertEqual(native_evtx["details"]["evtx_validation_checks"]["template_substitution_count"], 1)
            self.assertEqual(native_evtx["details"]["message_rendering"]["provenance"]["template_value_count"], 1)
            self.assertEqual(
                native_evtx["details"]["message_rendering"]["provenance"]["native_binxml_status"],
                "template-substituted-partial",
            )
            self.assertEqual(
                native_evtx["details"]["message_rendering"]["available_field_summary"]["template_substitution_count"],
                1,
            )
            self.assertTrue(
                any(
                    item["confidence"] == "binxml-template-substitution"
                    and item["element_path"] == "Event/EventData/Data"
                    and item["text"] == "powershell -enc TemplateValue"
                    for item in native_evtx["details"]["evtx_binxml"]["value_fields"]
                )
            )

    def test_eventlog_collector_labels_native_evtx_slack_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            evtx_path = root / "Windows" / "System32" / "winevt" / "Logs" / "Slack.evtx"
            evtx_path.parent.mkdir(parents=True, exist_ok=True)
            evtx_path.write_bytes(
                build_evtx_with_slack_record(
                    record_id=889,
                    timestamp=datetime(2024, 4, 3, 2, 3, 4, tzinfo=timezone.utc),
                    strings=[
                        "Microsoft-Windows-Security-Auditing",
                        "Security",
                        "WIN-SLACK",
                        "powershell -enc SlackCandidate",
                    ],
                )
            )
            output = root / "eventlog.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "eventlog", "--output", str(output)]), 0)
            artifacts = json.loads(output.read_text(encoding="utf-8"))["artifacts"]
            native_evtx = next(
                item
                for item in artifacts
                if item["artifact_type"] == "eventlog-event"
                and item["details"]["parser"] == "windows-eventlog-evtx-native"
            )
            chunk = next(item for item in artifacts if item["artifact_type"] == "eventlog-chunk")
            summary = next(item for item in artifacts if item["artifact_type"] == "eventlog-summary")["details"]

            self.assertEqual(native_evtx["details"]["record_id"], "889")
            self.assertEqual(native_evtx["details"]["evtx_recovery_status"], "slack-or-deleted-record-candidate")
            self.assertEqual(native_evtx["details"]["evtx_allocation_status"], "slack-or-deleted-candidate")
            self.assertEqual(native_evtx["details"]["evtx_chunk_context"]["chunk_boundary_status"], "slack-or-deleted-region")
            self.assertTrue(native_evtx["details"]["evtx_validation_required"])
            self.assertTrue(native_evtx["details"]["validation_required"])
            self.assertIn("slack-or-deleted-record-candidate", native_evtx["details"]["evtx_validation_reasons"])
            self.assertTrue(native_evtx["details"]["evtx_recovery_context"]["validation_required"])
            self.assertIn(
                "slack-or-deleted-record-candidate",
                native_evtx["details"]["evtx_recovery_context"]["caution_labels"],
            )
            self.assertEqual(
                native_evtx["details"]["evtx_recovery_evidence"]["allocation_status"],
                "slack-or-deleted-candidate",
            )
            self.assertIn(
                "allocation:slack-or-deleted-candidate",
                native_evtx["details"]["evtx_recovery_evidence"]["evidence_reasons"],
            )
            recovery_profile = native_evtx["details"]["evtx_recovery_validation_profile"]
            self.assertEqual(recovery_profile["candidate_class"], "slack-or-deleted-record")
            self.assertFalse(recovery_profile["reportable_without_secondary_validation"])
            self.assertEqual(recovery_profile["reportability_decision"]["decision"], "do-not-report-as-fact")
            self.assertEqual(recovery_profile["reportability_decision"]["allowed_use"], "triage-pivot-only")
            self.assertIn(
                "secondary-parser-validation-required",
                recovery_profile["reportability_decision"]["blockers"],
            )
            self.assertIn("known-answer-deleted-record-fixture-match", recovery_profile["required_independent_checks"])
            self.assertIn("confidence_band", native_evtx["details"]["evtx_recovery_context"])
            self.assertIn(
                "chunk-signature-valid",
                native_evtx["details"]["evtx_recovery_evidence"]["confidence_factors"],
            )
            self.assertIn(
                "declared-size-plausible",
                native_evtx["details"]["evtx_recovery_evidence"]["confidence_factors"],
            )
            self.assertIn("confidence_penalties", native_evtx["details"]["evtx_recovery_evidence"])
            self.assertGreaterEqual(
                native_evtx["details"]["evtx_recovery_evidence"]["record_relative_offset"],
                native_evtx["details"]["evtx_recovery_evidence"]["free_space_offset"],
            )
            self.assertEqual(
                native_evtx["details"]["message_rendering"]["provenance"]["native_recovery_status"],
                "slack-or-deleted-record-candidate",
            )
            self.assertEqual(
                native_evtx["details"]["evtx_record_provenance"]["chunk_boundary_status"],
                "slack-or-deleted-region",
            )
            recovery_manifest = native_evtx["details"]["evtx_recovery_report_citation_manifest"]
            self.assertEqual(recovery_manifest["artifact_type"], "eventlog-event")
            self.assertEqual(recovery_manifest["row_identity"]["record_offset"], native_evtx["details"]["evtx_record_offset"])
            self.assertEqual(recovery_manifest["row_identity"]["candidate_class"], "slack-or-deleted-record")
            self.assertIn(
                "known-answer-deleted-record-fixture-match",
                recovery_manifest["validation_summary"]["required_independent_checks"],
            )
            self.assertEqual(
                native_evtx["details"]["evtx_recovery_report_citation_manifest_hash"],
                recovery_manifest["manifest_sha256"],
            )
            self.assertEqual(
                native_evtx["details"]["evtx_commercial_readiness_profile"]["recovery_validation"][
                    "citation_manifest_hash"
                ],
                recovery_manifest["manifest_sha256"],
            )
            self.assertEqual(
                recovery_manifest["citation_refs"][0]["source_viewer_locator"]["mode"],
                "evtx-recovery-record-candidate",
            )
            self.assertIn(
                "rendered-message-trusted-diff-required",
                native_evtx["details"]["evtx_message_rendering_profile"]["blockers"],
            )
            self.assertEqual(chunk["details"]["evtx_chunk_header"]["free_space_offset"], 512)
            self.assertTrue(chunk["details"]["evtx_chunk_integrity"]["structure_plausible"])
            self.assertEqual(summary["native_chunk_count"], 1)
            self.assertIn(
                {"value": "structure-plausible", "count": 1},
                summary["native_chunk_integrity_counts"],
            )
            self.assertIn(
                {"value": "slack-or-deleted-record-candidate", "count": 1},
                summary["native_recovery_status_counts"],
            )

    def test_eventlog_collector_reports_corrupt_evtx_record_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            evtx_path = root / "Windows" / "System32" / "winevt" / "Logs" / "Corrupt.evtx"
            evtx_path.parent.mkdir(parents=True, exist_ok=True)
            evtx_path.write_bytes(
                build_corrupt_evtx_record_candidate(
                    record_id=890,
                    timestamp=datetime(2024, 4, 3, 3, 4, 5, tzinfo=timezone.utc),
                    strings=[
                        "Microsoft-Windows-Security-Auditing",
                        "Security",
                        "WIN-CORRUPT",
                        "wevtutil cl Security",
                    ],
                )
            )
            output = root / "eventlog.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "eventlog", "--output", str(output)]), 0)
            artifacts = json.loads(output.read_text(encoding="utf-8"))["artifacts"]
            candidates = [item for item in artifacts if item["artifact_type"] == "eventlog-record-candidate"]
            inventory = next(item for item in artifacts if item["artifact_type"] == "eventlog-file")["details"]
            summary = next(item for item in artifacts if item["artifact_type"] == "eventlog-summary")["details"]

            self.assertEqual(len(candidates), 1)
            candidate = candidates[0]["details"]
            self.assertEqual(candidate["record_id"], "890")
            self.assertEqual(candidate["evtx_recovery_status"], "corrupt-record-candidate")
            self.assertEqual(candidate["evtx_record_integrity"]["candidate_reason"], "record-extends-past-eof")
            self.assertFalse(candidate["evtx_recovery_evidence"]["parseable_record"])
            self.assertEqual(candidate["evtx_recovery_evidence"]["candidate_reason"], "record-extends-past-eof")
            self.assertIn("candidate:record-extends-past-eof", candidate["evtx_recovery_evidence"]["evidence_reasons"])
            self.assertIn("binxml:not-decoded", candidate["evtx_recovery_evidence"]["evidence_reasons"])
            self.assertEqual(
                candidate["evtx_recovery_validation_profile"]["candidate_class"],
                "corrupt-or-truncated-record",
            )
            self.assertIn(
                "known-answer-corrupt-record-fixture-match",
                candidate["evtx_recovery_validation_profile"]["required_independent_checks"],
            )
            self.assertEqual(
                candidate["evtx_recovery_validation_profile"]["reportability_decision"]["decision"],
                "do-not-report-as-fact",
            )
            self.assertIn(
                "candidate-not-live-allocated-record",
                candidate["evtx_recovery_validation_profile"]["reportability_decision"]["blockers"],
            )
            self.assertEqual(candidate["evtx_recovery_context"]["confidence_band"], "low-validation-required")
            self.assertIn("trailing-size-invalid", candidate["evtx_recovery_evidence"]["confidence_penalties"])
            self.assertEqual(candidate["evtx_report_grade_assessment"]["status"], "validation-required")
            self.assertEqual(candidate["commercial_uplift_evidence"]["batch_id"], "commercial-uplift-001-005")
            self.assertEqual(candidate["commercial_uplift_evidence"]["item_numbers"], [1, 2, 3])
            self.assertIn("record-magic", candidate["commercial_uplift_evidence"]["passed_validation_matrix_ids"])
            self.assertFalse(
                candidate["commercial_uplift_evidence"]["large_data_controls"][
                    "streaming_reader_required_for_tb_claims"
                ]
            )
            self.assertTrue(
                candidate["commercial_uplift_evidence"]["large_data_controls"][
                    "remaining_large_data_proof_required"
                ]
            )
            self.assertIn("record-integrity-not-proven", candidate["evtx_report_grade_assessment"]["blockers"])
            self.assertTrue(candidate["validation_required"])
            self.assertIn("do-not-report-without-validation", candidate["caution_labels"])
            self.assertLess(candidate["parser_confidence"], 0.6)
            self.assertEqual(inventory["native_record_count"], 0)
            self.assertEqual(inventory["native_record_candidate_count"], 1)
            self.assertEqual(summary["record_candidate_count"], 1)
            self.assertIn(
                {"value": "corrupt-record-candidate", "count": 1},
                summary["native_recovery_status_counts"],
            )

    def test_windows_os_account_collector_summarizes_profiles_and_reg_exports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            fixture = build_windows_artifact_fixture(root)
            output = root / "os-account.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "windows-os-account", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            artifacts = payload["artifacts"]
            profiles = [item for item in artifacts if item["artifact_type"] == "windows-user-profile"]
            summaries = [item for item in artifacts if item["artifact_type"] == "windows-os-account-summary"]
            sam_candidates = [item for item in artifacts if item["artifact_type"] == "windows-sam-account-candidate"]
            sam_group_candidates = [item for item in artifacts if item["artifact_type"] == "windows-sam-group-candidate"]
            service_rows = [item for item in artifacts if item["artifact_type"] == "windows-service-config"]
            mounted_devices = [item for item in artifacts if item["artifact_type"] == "windows-mounted-device"]
            lsa_locations = [item for item in artifacts if item["artifact_type"] == "windows-lsa-policy-location"]
            privileges = [item for item in artifacts if item["artifact_type"] == "windows-privilege-assignment"]
            group_rows = [item for item in artifacts if item["artifact_type"] == "windows-group-membership"]
            lifecycle_rows = [item for item in artifacts if item["artifact_type"] == "windows-account-lifecycle"]

            self.assertTrue(profiles)
            self.assertEqual(profiles[0]["details"]["user_name"], "alice")
            self.assertEqual(profiles[0]["details"]["source_path"], str(fixture.user_profile.resolve()))
            self.assertTrue(profiles[0]["details"]["ntuser_dat_present"])
            self.assertTrue(summaries)
            self.assertIn("WIN-FIXTURE", summaries[0]["details"]["computer_names"])
            self.assertIn("Korea Standard Time", summaries[0]["details"]["time_zones"])
            self.assertIn("2024-04-01T01:02:03+00:00", summaries[0]["details"]["last_boot_times"])
            self.assertIn("2024-04-01T00:55:01+00:00", summaries[0]["details"]["shutdown_times"])
            self.assertIn("ControlSet001:Current", summaries[0]["details"]["current_control_sets"])
            self.assertGreaterEqual(summaries[0]["details"]["service_count"], 1)
            self.assertGreaterEqual(summaries[0]["details"]["mounted_device_count"], 2)
            self.assertGreaterEqual(summaries[0]["details"]["lsa_secret_count"], 1)
            self.assertGreaterEqual(summaries[0]["details"]["privilege_assignment_count"], 1)
            self.assertGreaterEqual(summaries[0]["details"]["group_membership_hint_count"], 1)
            self.assertEqual(summaries[0]["details"]["group_membership_hints"][0]["group_name"], "Administrators")
            self.assertTrue(summaries[0]["details"]["group_membership_hints"][0]["privileged_group"])
            account_hints = {
                item["user_name"]: item
                for item in summaries[0]["details"]["account_lifecycle_hints"]
                if item.get("user_name")
            }
            self.assertEqual(account_hints["alice"]["created_at"], "2024-03-01T00:00:00+00:00")
            self.assertEqual(account_hints["alice"]["last_logon_at"], "2024-04-01T01:02:03+00:00")
            self.assertEqual(account_hints["alice"]["password_last_set_at"], "2024-03-15T12:34:56+00:00")
            self.assertTrue(account_hints["alice"]["admin_hint"])
            self.assertIn("NORMAL_ACCOUNT", account_hints["alice"]["uac_flags"])
            lifecycle = next(item for item in lifecycle_rows if item["details"]["user_name"] == "alice")
            self.assertEqual(lifecycle["details"]["rid_decimal"], 1001)
            self.assertTrue(lifecycle["details"]["validation_required"])
            self.assertFalse(lifecycle["details"]["commercial_grade_ready"])
            self.assertIn("full-native-sam-fv-layout-validation-required", lifecycle["details"]["commercial_grade_blockers"])
            self.assertEqual(lifecycle["details"]["os_account_report_grade_assessment"]["status"], "validation-required")
            self.assertIn("#6", lifecycle["details"]["os_account_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(lifecycle["details"]["forensic_review"]["gap_id"], "#6")
            self.assertEqual(lifecycle["details"]["forensic_review"]["review_status"], "triage-review")
            self.assertTrue(lifecycle["details"]["forensic_review"]["validation_required"])
            self.assertFalse(lifecycle["details"]["os_account_native_capabilities"]["security_secret_decryption"])
            lifecycle_matrix = {item["id"]: item for item in lifecycle["details"]["os_account_validation_matrix"]}
            self.assertTrue(lifecycle_matrix["has-sam-f-value"]["passed"])
            self.assertTrue(lifecycle_matrix["has-sam-v-value"]["passed"])
            self.assertFalse(lifecycle_matrix["native-sam-fv-report-grade"]["passed"])
            self.assertEqual(lifecycle["details"]["sam_binary_fields"]["F"]["byte_count"], 68)
            self.assertEqual(lifecycle["details"]["sam_binary_fields"]["F"]["decoded_timestamps"]["last_logon_at"], "2024-04-01T01:02:03+00:00")
            self.assertEqual(lifecycle["details"]["sam_binary_fields"]["F"]["rid_decimal_candidate"], 1001)
            self.assertIn("NORMAL_ACCOUNT", lifecycle["details"]["sam_binary_fields"]["F"]["user_account_control_flags"])
            self.assertIn("Alice Example", lifecycle["details"]["sam_binary_fields"]["V"]["string_candidates"])
            self.assertTrue(lifecycle["details"]["validation_checks"]["has_sam_f_value"])
            self.assertTrue(lifecycle["details"]["validation_checks"]["has_sam_v_value"])
            sam_deep_profile = lifecycle["details"]["sam_security_system_deep_parser_profile"]
            self.assertEqual(sam_deep_profile["item_number"], 12)
            self.assertEqual(sam_deep_profile["qc_prep_item_number"], 21)
            self.assertIn("SAM F/V", sam_deep_profile["qc_prep_item_goal"])
            self.assertIn("SAM F/V candidate field decoding", sam_deep_profile["qc_prep_contract"]["validated_by_current_tests"])
            self.assertIn("windows-account-lifecycle", sam_deep_profile["qc_prep_contract"]["usable_outputs"])
            self.assertEqual(sam_deep_profile["target_hives"], ["SAM", "SECURITY", "SYSTEM"])
            self.assertTrue(sam_deep_profile["decoded_components"]["sam_f_value_metadata"])
            self.assertTrue(sam_deep_profile["decoded_components"]["sam_v_value_metadata"])
            self.assertFalse(sam_deep_profile["decoded_components"]["security_secret_decryption"])
            self.assertIn("transaction-log-replay-required", sam_deep_profile["commercial_grade_blockers"])
            self.assertTrue(sam_deep_profile["normalized_security_context_schema"]["safe_for_case_db_indexing"])
            self.assertGreaterEqual(sam_deep_profile["normalized_security_context_schema"]["row_count"], 2)
            self.assertTrue(sam_deep_profile["security_context_manifest_expected"])
            self.assertEqual(
                sam_deep_profile["security_context_manifest_version"],
                "sam-security-context-manifest-v1",
            )
            self.assertTrue(lifecycle["details"]["validation_checks"]["native_sam_fv_candidate_decoding_available"])
            self.assertFalse(lifecycle["details"]["validation_checks"]["native_sam_fv_report_grade"])
            self.assertIn("admin-account-hint", lifecycle["details"]["risk_flags"])
            self.assertIn("privileged-group-membership-hint", lifecycle["details"]["risk_flags"])
            self.assertEqual(lifecycle["details"]["group_membership_hints"][0]["group_name"], "Administrators")
            self.assertEqual(lifecycle["details"]["group_membership_hints"][0]["match_types"], ["name", "rid-sid-tail"])
            self.assertEqual(lifecycle["details"]["group_membership_hints"][0]["group_sid_candidates"], ["S-1-5-32-544"])
            self.assertEqual(lifecycle["details"]["account_security_context"]["privileged_group_count"], 1)
            self.assertIn("S-1-5-32-544", lifecycle["details"]["account_security_context"]["group_sid_candidates"])
            self.assertEqual(lifecycle["details"]["account_security_context"]["inherited_privilege_count"], 1)
            context_rows = lifecycle["details"]["normalized_security_context_rows"]
            self.assertEqual(lifecycle["details"]["normalized_security_context_row_count"], len(context_rows))
            self.assertIn("group-membership-hint", {row["context_type"] for row in context_rows})
            self.assertIn("inherited-privilege-hint", {row["context_type"] for row in context_rows})
            context_manifest = lifecycle["details"]["sam_security_context_manifest"]
            self.assertEqual(context_manifest["manifest_version"], "sam-security-context-manifest-v1")
            self.assertEqual(context_manifest["account_identity"]["user_name"], "alice")
            self.assertEqual(context_manifest["account_identity"]["rid_decimal"], 1001)
            self.assertEqual(context_manifest["context_summary"]["row_count"], len(context_rows))
            self.assertEqual(
                lifecycle["details"]["sam_security_context_manifest_hash"],
                context_manifest["manifest_sha256"],
            )
            self.assertEqual(len(context_manifest["manifest_sha256"]), 64)
            self.assertEqual(len(context_manifest["context_summary"]["row_hash_manifest_sha256"]), 64)
            self.assertIn(
                "group-membership-hint",
                context_manifest["context_summary"]["context_type_counts"],
            )
            self.assertIn("SeDebugPrivilege", context_manifest["context_summary"]["high_risk_privileges"])
            self.assertEqual(context_manifest["reportability"]["allowed_use"], "account-security-triage-pivot")
            self.assertTrue(context_manifest["reportability"]["secret_values_redacted"])
            self.assertFalse(context_manifest["reportability"]["ready_for_court_report"])
            self.assertIn("normalized-security-context-rows", {row["kind"] for row in context_manifest["citation_refs"]})
            row_manifest = lifecycle["details"]["sam_security_system_row_manifest"]
            self.assertEqual(row_manifest["manifest_version"], "sam-security-system-row-manifest-v1")
            self.assertEqual(row_manifest["row_type"], "account")
            self.assertEqual(row_manifest["identity"]["user_name"], "alice")
            self.assertEqual(row_manifest["identity"]["rid"], 1001)
            self.assertEqual(
                row_manifest["evidence_summary"]["sam_security_context_manifest_hash"],
                context_manifest["manifest_sha256"],
            )
            self.assertEqual(lifecycle["details"]["sam_security_system_row_manifest_hash"], row_manifest["manifest_sha256"])
            self.assertEqual(len(row_manifest["row_identity_hash"]), 64)
            self.assertIn("user_name", row_manifest["trusted_diff_contract"]["required_fields_for_row_type"])
            self.assertEqual(row_manifest["trusted_diff_contract"]["missing_identity_fields"], [])
            privilege_row = next(row for row in context_rows if row["context_type"] == "inherited-privilege-hint")
            self.assertEqual(privilege_row["privilege"], "SeDebugPrivilege")
            self.assertEqual(privilege_row["via_groups"], ["Administrators"])
            account_profile = lifecycle["details"]["account_privilege_deep_parse_profile"]
            self.assertEqual(account_profile["commercial_gap_id"], "#6")
            self.assertEqual(account_profile["target_artifacts"], ["SAM", "SECURITY", "SYSTEM"])
            self.assertTrue(account_profile["decoded_components"]["sam_fv_candidate_fields"])
            self.assertTrue(account_profile["decoded_components"]["privilege_rights_export_mapping"])
            self.assertTrue(account_profile["not_yet_report_grade"]["sam_alias_member_binary_decode"])
            self.assertEqual(
                account_profile["reportability_decision"]["decision"],
                "do-not-report-as-final-account-state",
            )
            self.assertEqual(
                lifecycle["details"]["account_reportability_decision"]["allowed_use"],
                "account-security-triage-pivot",
            )
            self.assertIn(
                "sam-security-system-transaction-log-replay-required",
                lifecycle["details"]["account_reportability_decision"]["blockers"],
            )
            self.assertIn("decode SAM alias/member binary values for actual group membership", account_profile["required_independent_checks"])
            inherited_debug = lifecycle["details"]["account_security_context"]["inherited_privileges"][0]
            self.assertEqual(inherited_debug["privilege"], "SeDebugPrivilege")
            self.assertEqual(inherited_debug["via_groups"], ["Administrators"])
            self.assertIn("high-risk-privilege", inherited_debug["risk_flags"])
            lifecycle_gate = lifecycle["details"]["core_accuracy_gates"][0]
            self.assertEqual(lifecycle_gate["gap_id"], "#6")
            self.assertIn("RID/name/SID consistency", lifecycle_gate["satisfied_checks"])
            self.assertIn("UAC flag decoding", lifecycle_gate["satisfied_checks"])
            self.assertIn("group alias membership reconstruction", lifecycle_gate["satisfied_checks"])
            self.assertIn("privilege assignment attribution", lifecycle_gate["satisfied_checks"])
            self.assertIn("secret-value redaction and authority gate", lifecycle_gate["satisfied_checks"])
            self.assertIn("stable SAM/SECURITY/SYSTEM row manifest", lifecycle_gate["satisfied_checks"])
            self.assertFalse(lifecycle_gate["commercial_grade_ready"])
            lifecycle_uplift = lifecycle["details"]["commercial_uplift_evidence"]
            self.assertEqual(lifecycle_uplift["batch_id"], "commercial-uplift-006-010")
            self.assertEqual(lifecycle_uplift["item_numbers"], [6])
            self.assertEqual(lifecycle_uplift["qc_prep_item_numbers"], [21])
            self.assertIn("has-sam-f-value", lifecycle_uplift["passed_validation_matrix_ids"])
            self.assertIn("native-sam-fv-report-grade", lifecycle_uplift["failed_validation_matrix_ids"])
            self.assertEqual(
                lifecycle_uplift["reportability_decision"]["allowed_use"],
                "account-security-triage-pivot",
            )
            self.assertEqual(
                lifecycle_uplift["sam_security_system_row_manifest_hash"],
                row_manifest["manifest_sha256"],
            )
            self.assertEqual(
                lifecycle_uplift["sam_security_context_manifest_hash"],
                context_manifest["manifest_sha256"],
            )
            self.assertTrue(lifecycle_uplift["large_data_controls"]["secret_values_redacted"])
            group = next(item for item in group_rows if item["details"]["group_name"] == "Administrators")
            self.assertFalse(group["details"]["commercial_grade_ready"])
            self.assertEqual(group["details"]["member_count"], 1)
            self.assertEqual(group["details"]["member_identifier_count"], 2)
            self.assertIn("not proven", group["details"]["member_count_semantics"])
            self.assertIn("member-sid", group["details"]["membership_source_types"])
            self.assertIn("member-name", group["details"]["membership_source_types"])
            self.assertEqual(group["details"]["group_sid_candidates"], ["S-1-5-32-544"])
            self.assertTrue(group["details"]["validation_checks"]["requires_native_sam_alias_validation"])
            self.assertIn("#6", group["details"]["os_account_report_grade_assessment"]["commercial_gap_ids"])
            self.assertIn("privileged-group-membership-hint", group["details"]["risk_flags"])
            self.assertEqual(group["details"]["sam_security_system_row_manifest"]["row_type"], "group")
            self.assertEqual(group["details"]["sam_security_system_row_manifest"]["identity"]["group_name"], "Administrators")
            self.assertTrue(sam_candidates)
            alice_sam = next(item for item in sam_candidates if item["details"]["user_name_candidate"] == "alice")
            self.assertEqual(alice_sam["details"]["candidate_role"], "account-name-key")
            self.assertEqual(alice_sam["details"]["rid_hex"], "000003E9")
            self.assertEqual(alice_sam["details"]["rid_decimal"], 1001)
            self.assertTrue(alice_sam["details"]["validation_required"])
            self.assertIn("#6", alice_sam["details"]["os_account_report_grade_assessment"]["commercial_gap_ids"])
            self.assertFalse(alice_sam["details"]["os_account_native_capabilities"]["native_sam_alias_member_binary_decode"])
            self.assertEqual(
                alice_sam["details"]["account_privilege_deep_parse_profile"]["artifact_scope"],
                "native-sam-account-key-candidate",
            )
            self.assertEqual(len(alice_sam["details"]["source_hashes"]["sha256"]), 64)
            self.assertEqual(alice_sam["details"]["sam_security_system_row_manifest"]["row_type"], "account")
            self.assertEqual(alice_sam["details"]["sam_security_system_row_manifest"]["identity"]["user_name"], "alice")
            admin_group = next(item for item in sam_group_candidates if item["details"]["group_name_candidate"] == "Administrators")
            self.assertFalse(admin_group["details"]["commercial_grade_ready"])
            self.assertEqual(admin_group["details"]["alias_rid_hex"], "00000220")
            self.assertEqual(admin_group["details"]["alias_rid_decimal"], 544)
            self.assertFalse(admin_group["details"]["validation_checks"]["native_membership_reconstruction_available"])
            self.assertIn("privileged-group-candidate", admin_group["details"]["risk_flags"])
            self.assertEqual(admin_group["details"]["sam_security_system_row_manifest"]["identity"]["group_name"], "Administrators")
            service = next(item for item in service_rows if item["details"]["service_name"] == "SecurityUpdater")
            self.assertEqual(service["details"]["start_type_label"], "automatic")
            self.assertIn("suspicious-service-image-path", service["details"]["risk_flags"])
            self.assertTrue(any(item["details"]["drive_letter"] == r"\DosDevices\E:" for item in mounted_devices))
            lsa_secret = next(item for item in lsa_locations if item["details"]["secret_name"] == "_SC_SecurityUpdater")
            self.assertIn("CurrVal", lsa_secret["details"]["value_names"])
            self.assertEqual(lsa_secret["details"]["secret_value_metadata"]["CurrVal"]["byte_count"], 2)
            self.assertFalse(lsa_secret["details"]["secret_value_metadata"]["CurrVal"]["decrypted"])
            self.assertEqual(
                lsa_secret["details"]["secret_value_metadata"]["CurrVal"]["secret_handling_decision"]["allowed_use"],
                "metadata-inventory-only",
            )
            self.assertTrue(
                lsa_secret["details"]["secret_value_metadata"]["CurrVal"]["secret_handling_decision"][
                    "protected_value_redacted"
                ]
            )
            self.assertFalse(lsa_secret["details"]["commercial_grade_ready"])
            self.assertEqual(lsa_secret["details"]["validation_checks"]["exported_value_count"], 3)
            self.assertIn("#6", lsa_secret["details"]["os_account_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(lsa_secret["details"]["sam_security_system_row_manifest"]["row_type"], "secret")
            self.assertTrue(lsa_secret["details"]["sam_security_system_row_manifest"]["identity"]["secret_values_redacted"])
            self.assertEqual(lsa_secret["details"]["secret_value_metadata"]["CupdTime"]["registry_value_type"], "REG_QWORD")
            self.assertEqual(
                lsa_secret["details"]["secret_value_metadata"]["CupdTime"]["timestamp_candidate"],
                "2024-04-01T01:23:45+00:00",
            )
            self.assertTrue(lsa_secret["details"]["secret_value_metadata"]["SecDesc"]["contains_nonzero_bytes"])
            privilege = next(item for item in privileges if item["details"]["privilege"] == "SeDebugPrivilege")
            self.assertIn("S-1-5-32-544", privilege["details"]["assigned_sids"])
            self.assertEqual(
                privilege["details"]["assigned_principal_hints"],
                [{"sid": "S-1-5-32-544", "principal": "Administrators", "principal_type": "builtin-alias"}],
            )
            self.assertEqual(privilege["details"]["sam_security_system_row_manifest"]["row_type"], "privilege")
            self.assertEqual(privilege["details"]["sam_security_system_row_manifest"]["identity"]["privilege"], "SeDebugPrivilege")
            self.assertIn("high-risk-privilege", privilege["details"]["risk_flags"])

    def test_os_account_trusted_diff_blocks_unverified_account_state(self) -> None:
        rapid = [
            {
                "user_name": "alice",
                "rid_decimal": 1001,
                "sid": "S-1-5-21-1000-1001",
                "uac_flags": ["NORMAL_ACCOUNT"],
                "group_names": ["Administrators"],
                "privileges": ["SeDebugPrivilege"],
            }
        ]
        trusted = [
            {
                "account_name": "alice",
                "rid": "1001",
                "user_sid": "S-1-5-21-1000-1001",
                "user_account_control_flags": ["NORMAL_ACCOUNT"],
                "groups": ["Administrators"],
                "assigned_privileges": ["SeDebugPrivilege"],
            }
        ]

        diff = build_os_account_trusted_diff(rapid, trusted, trusted_tool="RECmd SAM parser")

        self.assertEqual(diff["status"], "pass")
        self.assertTrue(diff["trusted_tool_recognized"])
        self.assertTrue(diff["commercial_grade_evidence"])
        self.assertEqual(diff["matched_count"], 1)
        self.assertEqual(diff["field_coverage"]["missing_required_fields"], {})
        self.assertIn("secret_values_redacted", diff["compare_fields"])
        self.assertEqual(diff["reportability_decision"]["decision"], "account-diff-passed")

    def test_os_account_trusted_diff_flags_group_mismatches(self) -> None:
        rapid = [{"user_name": "alice", "rid": "1001", "group_names": ["Administrators"]}]
        trusted = [{"user_name": "alice", "rid": "1001", "group_names": ["Users"]}]

        diff = build_os_account_trusted_diff(rapid, trusted, trusted_tool="Registry Explorer")

        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["commercial_grade_evidence"])
        self.assertEqual(diff["mismatch_count"], 1)
        self.assertIn("sam-security-system-trusted-diff-required", diff["reportability_decision"]["blockers"])

    def test_windows_execution_collector_maps_registry_and_powershell_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            fixture = build_windows_artifact_fixture(root)
            system_hive = root / "Windows" / "System32" / "config" / "SYSTEM"
            system_hive.write_bytes(
                build_minimal_registry_hive(
                    datetime(2024, 4, 1, 3, 4, 5, tzinfo=timezone.utc),
                    "SYSTEM",
                    [
                        r"ControlSet001\Control\Session Manager\AppCompatCache",
                        r"C:\Users\alice\AppData\Roaming\legacy.exe",
                        "LastModified=2024-04-01T03:04:05Z",
                        r"C:\Windows\System32\cleanmgr.exe",
                        r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1000",
                        r"\Device\HarddiskVolume3\Users\alice\AppData\Roaming\evil.exe",
                        "LastExecution=2024-04-01T06:07:08Z",
                    ],
                )
            )
            output = root / "execution.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "windows-execution", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            artifacts = payload["artifacts"]
            artifact_types = {item["artifact_type"] for item in artifacts}

            self.assertIn("bam-entry", artifact_types)
            self.assertIn("amcache-hive", artifact_types)
            self.assertIn("amcache-entry", artifact_types)
            self.assertIn("userassist-entry", artifact_types)
            self.assertIn("shimcache-entry", artifact_types)
            self.assertIn("powershell-history-command", artifact_types)
            self.assertIn("srum-network-usage", artifact_types)
            self.assertIn("srum-database-file", artifact_types)
            self.assertIn("srum-database-pivot", artifact_types)
            self.assertIn("srum-table-candidate", artifact_types)
            self.assertIn("srum-row-candidate", artifact_types)
            self.assertIn("windows-execution-summary", artifact_types)
            amcache_rows = [item for item in artifacts if item["artifact_type"] == "amcache-entry"]
            bam = next(item for item in artifacts if item["artifact_type"] == "bam-entry")
            native_bam = next(
                item
                for item in artifacts
                if item["artifact_type"] == "bam-entry"
                and item["details"].get("source_format") == "system-hive-native-bam-dam-scan"
                and item["details"].get("executable_path", "").endswith("evil.exe")
            )
            shimcache = next(item for item in artifacts if item["artifact_type"] == "shimcache-entry")
            native_shimcache = next(
                item
                for item in artifacts
                if item["artifact_type"] == "shimcache-entry"
                and item["details"].get("source_format") == "system-hive-native-shimcache-scan"
            )
            ps_rows = [item for item in artifacts if item["artifact_type"] == "powershell-history-command"]
            srum_rows = [item for item in artifacts if item["artifact_type"] == "srum-network-usage"]
            srum_database_rows = [item for item in artifacts if item["artifact_type"] == "srum-database-file"]
            srum_pivots = [item for item in artifacts if item["artifact_type"] == "srum-database-pivot"]
            srum_row_candidates = [item for item in artifacts if item["artifact_type"] == "srum-row-candidate"]
            self.assertTrue(any("suspicious-command:powershell -enc" in row["details"]["risk_flags"] for row in ps_rows))
            self.assertTrue(any("vssadmin delete shadows" in row["details"]["command_line"] for row in ps_rows))
            self.assertEqual(ps_rows[0]["details"]["source_path"], str(fixture.powershell_history.resolve()))
            self.assertTrue(any(row["details"]["source_path"] == str(fixture.amcache_hive.resolve()) for row in amcache_rows))
            self.assertTrue(any(row["details"]["executable_path"].endswith(r"Example\app.exe") for row in amcache_rows))
            exported_amcache = next(row for row in amcache_rows if row["details"]["source_format"] == "reg")
            self.assertEqual(exported_amcache["details"]["program_name"], "Example App")
            self.assertEqual(exported_amcache["details"]["publisher"], "Example Publisher")
            self.assertEqual(exported_amcache["details"]["sha1"], "0123456789abcdef0123456789abcdef01234567")
            self.assertEqual(exported_amcache["details"]["file_description"], "Example Application Binary")
            self.assertEqual(exported_amcache["details"]["amcache_evidence"]["file_name"], "app.exe")
            self.assertTrue(exported_amcache["details"]["amcache_evidence"]["path_present"])
            self.assertTrue(exported_amcache["details"]["amcache_evidence"]["hash_present"])
            self.assertEqual(
                exported_amcache["details"]["amcache_evidence"]["sha1_candidates"],
                ["0123456789abcdef0123456789abcdef01234567"],
            )
            self.assertIn("publisher", exported_amcache["details"]["amcache_evidence"]["metadata_fields_present"])
            self.assertEqual(
                exported_amcache["details"]["amcache_evidence"]["execution_caveat"],
                "Amcache supports program presence/install/execution-related pivots but is not standalone proof of execution.",
            )
            self.assertEqual(exported_amcache["details"]["amcache_schema_profile"]["commercial_gap_id"], "#7")
            self.assertEqual(exported_amcache["details"]["amcache_schema_profile"]["readiness_item_number"], 15)
            self.assertEqual(exported_amcache["details"]["amcache_schema_profile"]["qc_prep_item_number"], 22)
            self.assertIn(
                "reg-export Amcache row mapping",
                exported_amcache["details"]["amcache_schema_profile"]["qc_prep_contract"]["implemented"],
            )
            self.assertEqual(
                exported_amcache["details"]["amcache_schema_profile"]["execution_artifact_validation_profile"]["item_number"],
                15,
            )
            self.assertEqual(exported_amcache["details"]["amcache_schema_profile"]["source_format"], "reg")
            self.assertFalse(exported_amcache["details"]["amcache_schema_profile"]["standalone_execution_proof"])
            self.assertEqual(
                exported_amcache["details"]["amcache_schema_profile"]["reportability_decision"]["decision"],
                "do-not-report-as-standalone-execution",
            )
            self.assertTrue(exported_amcache["details"]["amcache_schema_profile"]["schema_components"]["root_file_paths"])
            self.assertTrue(exported_amcache["details"]["validation_checks"]["has_hash"])
            self.assertFalse(exported_amcache["details"]["commercial_grade_ready"])
            self.assertIn("native-amcache-schema-decoding-required", exported_amcache["details"]["commercial_grade_blockers"])
            self.assertIn("#7", exported_amcache["details"]["execution_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(exported_amcache["details"]["forensic_review"]["gap_id"], "#7")
            self.assertIn("Amcache", exported_amcache["details"]["forensic_review"]["artifact_goal"])
            self.assertFalse(exported_amcache["details"]["execution_native_capabilities"]["native_amcache_schema_decode"])
            exported_amcache_manifest = exported_amcache["details"]["amcache_report_citation_manifest"]
            self.assertEqual(
                exported_amcache_manifest["manifest_version"],
                "amcache-report-citation-manifest-v1",
            )
            self.assertEqual(exported_amcache_manifest["source"]["format"], "reg")
            self.assertEqual(
                exported_amcache_manifest["row_identity"]["sha1_candidates"],
                ["0123456789abcdef0123456789abcdef01234567"],
            )
            self.assertFalse(exported_amcache_manifest["reportability"]["standalone_execution_proof"])
            self.assertEqual(
                exported_amcache_manifest["reportability"]["allowed_use"],
                "program-presence-install-execution-related-pivot",
            )
            self.assertEqual(len(exported_amcache_manifest["manifest_sha256"]), 64)
            amcache_review_profile = exported_amcache["details"]["execution_analyst_review_profile"]
            self.assertEqual(amcache_review_profile["profile_version"], "execution-analyst-review-profile-v1")
            self.assertEqual(amcache_review_profile["artifact_type"], "amcache-entry")
            self.assertIn("standalone execution", amcache_review_profile["not_proof_of"])
            self.assertEqual(
                amcache_review_profile["source_field_values"]["sha1"],
                "0123456789abcdef0123456789abcdef01234567",
            )
            self.assertIn("Prefetch", amcache_review_profile["correlation_targets"])
            self.assertIn("execution-artifact-trusted-diff-required", amcache_review_profile["commercial_blockers"])
            amcache_gate = exported_amcache["details"]["core_accuracy_gates"][0]
            self.assertEqual(amcache_gate["gap_id"], "#7")
            self.assertIn("schema-version detection", amcache_gate["satisfied_checks"])
            self.assertIn("path/hash/publisher extraction", amcache_gate["satisfied_checks"])
            self.assertIn("execution caveat wording", amcache_gate["satisfied_checks"])
            self.assertFalse(amcache_gate["commercial_grade_ready"])
            amcache_uplift = exported_amcache["details"]["commercial_uplift_evidence"]
            self.assertEqual(amcache_uplift["batch_id"], "commercial-uplift-006-010")
            self.assertEqual(amcache_uplift["item_numbers"], [7])
            self.assertEqual(amcache_uplift["qc_prep_item_numbers"], [22])
            self.assertEqual(
                amcache_uplift["reportability_decision"]["allowed_use"],
                "program-presence-install-execution-related-pivot",
            )
            self.assertIn("has-hash", amcache_uplift["passed_validation_matrix_ids"])
            self.assertTrue(amcache_uplift["large_data_controls"]["schema_version_matrix_required"])
            native_amcache_hive = next(item for item in artifacts if item["artifact_type"] == "amcache-hive")
            self.assertGreaterEqual(native_amcache_hive["details"]["amcache_hive_evidence"]["candidate_path_count"], 1)
            self.assertEqual(
                native_amcache_hive["details"]["amcache_hive_evidence"]["schema_decode_status"],
                "not-implemented-string-pivot-only",
            )
            self.assertEqual(native_amcache_hive["details"]["amcache_schema_profile"]["current_decode_level"], "native-string-pivot-only")
            self.assertEqual(
                native_amcache_hive["details"]["amcache_report_citation_manifest"]["source"]["format"],
                "amcache-hive",
            )
            native_amcache_entry = next(
                item
                for item in amcache_rows
                if item["details"]["source_format"] == "amcache-hive"
                and item["details"]["executable_path"].endswith(r"Example\app.exe")
            )
            native_manifest = native_amcache_entry["details"]["amcache_report_citation_manifest"]
            self.assertEqual(native_manifest["source"]["format"], "amcache-hive")
            self.assertIn(
                native_manifest["row_identity"]["timestamp_source"],
                {"native-amcache-nearby-string-timestamp-candidate", "not_available_native_string_pivot"},
            )
            self.assertIn("amcache-timestamp-semantics", {row["kind"] for row in native_manifest["citation_refs"]})
            self.assertFalse(native_manifest["reportability"]["standalone_execution_proof"])
            native_hive_uplift = native_amcache_hive["details"]["commercial_uplift_evidence"]
            self.assertEqual(native_hive_uplift["batch_id"], "commercial-uplift-006-010")
            self.assertEqual(native_hive_uplift["item_numbers"], [7])
            self.assertIn("has-path-candidates", native_hive_uplift["passed_validation_matrix_ids"])
            self.assertTrue(native_hive_uplift["large_data_controls"]["schema_version_matrix_required"])
            self.assertEqual(bam["details"]["user_sid"], "S-1-5-21-1000")
            self.assertEqual(bam["details"]["timestamp"], "2024-04-01T06:07:08+00:00")
            self.assertEqual(bam["details"]["timestamp_source"], "bam_value_filetime")
            self.assertEqual(bam["details"]["bam_dam_evidence"]["user_sid"], "S-1-5-21-1000")
            self.assertEqual(
                bam["details"]["bam_dam_evidence"]["timestamp_semantics"],
                "bam-dam-last-execution-filetime-candidate",
            )
            self.assertTrue(bam["details"]["bam_dam_evidence"]["requires_native_system_hive_validation"])
            self.assertEqual(bam["details"]["bam_dam_decode_profile"]["commercial_gap_id"], "#9")
            self.assertEqual(bam["details"]["bam_dam_decode_profile"]["qc_prep_item_number"], 24)
            self.assertIn(
                "native cluster SID/path/timestamp/source extraction",
                bam["details"]["bam_dam_decode_profile"]["qc_prep_contract"]["validated_by_current_tests"],
            )
            self.assertEqual(
                bam["details"]["bam_dam_decode_profile"]["execution_artifact_validation_profile"]["artifact_family"],
                "bam-dam",
            )
            self.assertTrue(bam["details"]["bam_dam_decode_profile"]["decoded_components"]["filetime_timestamp"])
            self.assertEqual(
                bam["details"]["bam_dam_decode_profile"]["timestamp_semantics"],
                "bam-dam-last-execution-filetime-candidate",
            )
            self.assertEqual(
                bam["details"]["bam_dam_decode_profile"]["reportability_decision"]["decision"],
                "report-only-with-correlation",
            )
            self.assertFalse(bam["details"]["bam_dam_decode_profile"]["standalone_execution_proof"])
            self.assertTrue(bam["details"]["validation_checks"]["has_timestamp"])
            self.assertFalse(bam["details"]["commercial_grade_ready"])
            self.assertIn("native-system-hive-bam-decoding-required", bam["details"]["commercial_grade_blockers"])
            self.assertIn("#9", bam["details"]["execution_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(bam["details"]["forensic_review"]["gap_id"], "#9")
            self.assertIn("bam-execution-indicator", bam["details"]["risk_flags"])
            bam_gate = bam["details"]["core_accuracy_gates"][0]
            self.assertEqual(bam_gate["gap_id"], "#9")
            self.assertIn("SID extraction", bam_gate["satisfied_checks"])
            self.assertIn("device path normalization", bam_gate["satisfied_checks"])
            self.assertIn("FILETIME validity", bam_gate["satisfied_checks"])
            self.assertIn("ControlSet attribution", bam_gate["satisfied_checks"])
            self.assertIn("stable BAM/DAM row manifest", bam_gate["satisfied_checks"])
            bam_row_manifest = bam["details"]["bam_dam_row_manifest"]
            self.assertEqual(bam_row_manifest["manifest_version"], "bam-dam-row-manifest-v1")
            self.assertEqual(bam_row_manifest["row_identity"]["control_set"], "CurrentControlSet")
            self.assertFalse(bam_row_manifest["row_identity"]["standalone_execution_proof"])
            self.assertIn("source_key", bam_row_manifest["trusted_diff_contract"]["required_fields"])
            self.assertEqual(bam["details"]["bam_dam_row_manifest_hash"], bam_row_manifest["manifest_sha256"])
            bam_manifest = bam["details"]["bam_dam_report_citation_manifest"]
            self.assertEqual(
                bam_manifest["manifest_version"],
                "bam-dam-report-citation-manifest-v1",
            )
            self.assertEqual(bam_manifest["source"]["format"], "reg")
            self.assertEqual(bam_manifest["row_identity"]["user_sid"], "S-1-5-21-1000")
            self.assertEqual(
                bam_manifest["reportability"]["allowed_use"],
                "recent-execution-pivot-corroborate-before-testimony",
            )
            self.assertFalse(bam_manifest["reportability"]["standalone_execution_proof"])
            self.assertIn(
                "bam-dam-timestamp",
                {row["kind"] for row in bam_manifest["citation_refs"]},
            )
            self.assertEqual(len(bam_manifest["manifest_sha256"]), 64)
            bam_review_profile = bam["details"]["execution_analyst_review_profile"]
            self.assertEqual(bam_review_profile["severity"], "high")
            self.assertEqual(bam_review_profile["source_field_values"]["user_sid"], "S-1-5-21-1000")
            self.assertIn("SRUM", bam_review_profile["correlation_targets"])
            self.assertIn("bam-execution-indicator", bam_review_profile["risk_tags"])
            self.assertIn("native-system-hive-bam-decoding-required", bam_review_profile["commercial_blockers"])
            bam_uplift = bam["details"]["commercial_uplift_evidence"]
            self.assertEqual(bam_uplift["item_numbers"], [9])
            self.assertEqual(bam_uplift["qc_prep_item_numbers"], [24])
            self.assertEqual(
                bam_uplift["reportability_decision"]["allowed_use"],
                "recent-execution-pivot-corroborate-before-testimony",
            )
            self.assertTrue(bam_uplift["large_data_controls"]["native_binary_layout_required_for_commercial_claims"])
            self.assertTrue(native_bam["details"]["executable_path"].endswith("evil.exe"))
            self.assertEqual(native_bam["details"]["user_sid"], "S-1-5-21-1000")
            self.assertEqual(native_bam["details"]["timestamp"], "2024-04-01T06:07:08+00:00")
            self.assertEqual(
                native_bam["details"]["bam_dam_evidence"]["native_scan_status"],
                "bounded-path-sid-cluster",
            )
            self.assertEqual(
                native_bam["details"]["bam_dam_decode_profile"]["current_decode_level"],
                "native-system-hive-string-pivot",
            )
            native_bam_manifest = native_bam["details"]["bam_dam_report_citation_manifest"]
            self.assertEqual(native_bam_manifest["source"]["format"], "system-hive-native-bam-dam-scan")
            self.assertEqual(native_bam_manifest["row_identity"]["user_sid"], "S-1-5-21-1000")
            self.assertFalse(native_bam_manifest["reportability"]["standalone_execution_proof"])
            native_bam_row_manifest = native_bam["details"]["bam_dam_row_manifest"]
            self.assertEqual(native_bam_row_manifest["source"]["format"], "system-hive-native-bam-dam-scan")
            self.assertEqual(native_bam_row_manifest["row_identity"]["artifact_scope"], "bam")
            self.assertEqual(native_bam["details"]["bam_dam_row_manifest_hash"], native_bam_row_manifest["manifest_sha256"])
            self.assertEqual(
                native_bam["details"]["bam_dam_report_citation_manifest_hash"],
                native_bam_manifest["manifest_sha256"],
            )
            self.assertIn(
                "bam-dam-row-cluster",
                {row["kind"] for row in native_bam_manifest["citation_refs"]},
            )
            self.assertIn(
                "bounded native BAM/DAM path provenance",
                native_bam["details"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertTrue(shimcache["details"]["validation_required"])
            self.assertEqual(shimcache["details"]["execution_caveat"], "Presence in ShimCache is not proof the executable ran.")
            self.assertEqual(
                shimcache["details"]["shimcache_evidence"]["execution_caveat"],
                "ShimCache/AppCompatCache can show program presence/order, but it is not standalone proof of execution.",
            )
            self.assertTrue(shimcache["details"]["shimcache_evidence"]["requires_os_version_layout_validation"])
            self.assertEqual(shimcache["details"]["shimcache_execution_caveat_profile"]["commercial_gap_id"], "#8")
            self.assertEqual(
                shimcache["details"]["shimcache_execution_caveat_profile"]["execution_artifact_validation_profile"]["normalized_row_contract"]["execution_caveat_required"],
                True,
            )
            self.assertEqual(shimcache["details"]["shimcache_execution_caveat_profile"]["qc_prep_item_number"], 23)
            self.assertIn(
                "not-proof-of-execution UX wording",
                shimcache["details"]["shimcache_execution_caveat_profile"]["qc_prep_contract"]["validated_by_current_tests"],
            )
            self.assertFalse(shimcache["details"]["shimcache_execution_caveat_profile"]["standalone_execution_proof"])
            self.assertEqual(
                shimcache["details"]["shimcache_execution_caveat_profile"]["reportability_decision"]["decision"],
                "do-not-report-as-execution-proof",
            )
            self.assertIn(
                "preserve the UX warning that ShimCache is not proof of execution",
                shimcache["details"]["shimcache_execution_caveat_profile"]["required_independent_checks"],
            )
            self.assertIn("Prefetch", shimcache["details"]["validation_checks"]["correlation_targets"])
            self.assertIn("native-appcompatcache-layout-decoding-required", shimcache["details"]["commercial_grade_blockers"])
            self.assertIn("#8", shimcache["details"]["execution_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(shimcache["details"]["forensic_review"]["gap_id"], "#8")
            shimcache_manifest = shimcache["details"]["shimcache_report_citation_manifest"]
            self.assertEqual(
                shimcache_manifest["manifest_version"],
                "shimcache-report-citation-manifest-v1",
            )
            self.assertEqual(shimcache_manifest["source"]["format"], "reg")
            self.assertEqual(
                shimcache_manifest["reportability"]["allowed_use"],
                "program-presence-cache-order-pivot",
            )
            self.assertFalse(shimcache_manifest["reportability"]["standalone_execution_proof"])
            self.assertIn("shimcache-not-proof-of-execution", shimcache_manifest["reportability"]["blockers"])
            self.assertIn(
                "shimcache-cache-order-or-timestamp",
                {row["kind"] for row in shimcache_manifest["citation_refs"]},
            )
            self.assertEqual(len(shimcache_manifest["manifest_sha256"]), 64)
            shimcache_review_profile = shimcache["details"]["execution_analyst_review_profile"]
            self.assertIn("program execution", shimcache_review_profile["not_proof_of"])
            self.assertIn("not-execution-proof", shimcache_review_profile["risk_tags"])
            self.assertIn("Prefetch", shimcache_review_profile["correlation_targets"])
            self.assertIn(
                "native-appcompatcache-layout-decoding-required",
                shimcache_review_profile["commercial_blockers"],
            )
            shimcache_gate = shimcache["details"]["core_accuracy_gates"][0]
            self.assertEqual(shimcache_gate["gap_id"], "#8")
            self.assertIn("not-proof-of-execution warning", shimcache_gate["satisfied_checks"])
            self.assertIn("malformed binary bounds checks", shimcache_gate["satisfied_checks"])
            shimcache_uplift = shimcache["details"]["commercial_uplift_evidence"]
            self.assertEqual(shimcache_uplift["item_numbers"], [8])
            self.assertEqual(shimcache_uplift["qc_prep_item_numbers"], [23])
            self.assertEqual(
                shimcache_uplift["reportability_decision"]["allowed_use"],
                "program-presence-cache-order-pivot",
            )
            self.assertTrue(shimcache_uplift["large_data_controls"]["native_binary_layout_required_for_commercial_claims"])
            self.assertTrue(native_shimcache["details"]["executable_path"].endswith("legacy.exe"))
            self.assertEqual(native_shimcache["details"]["cache_order"], 0)
            self.assertGreaterEqual(native_shimcache["details"]["source_offset"], 0)
            self.assertEqual(native_shimcache["details"]["timestamp"], "2024-04-01T03:04:05+00:00")
            self.assertEqual(
                native_shimcache["details"]["shimcache_evidence"]["native_scan_status"],
                "bounded-path-cluster",
            )
            self.assertEqual(
                native_shimcache["details"]["shimcache_execution_caveat_profile"]["current_decode_level"],
                "native-system-hive-string-pivot",
            )
            native_shimcache_manifest = native_shimcache["details"]["shimcache_report_citation_manifest"]
            self.assertEqual(native_shimcache_manifest["source"]["format"], "system-hive-native-shimcache-scan")
            self.assertEqual(native_shimcache_manifest["row_identity"]["cache_order"], 0)
            self.assertFalse(native_shimcache_manifest["reportability"]["standalone_execution_proof"])
            self.assertEqual(
                native_shimcache["details"]["shimcache_report_citation_manifest_hash"],
                native_shimcache_manifest["manifest_sha256"],
            )
            self.assertIn(
                "shimcache-row-cluster",
                {row["kind"] for row in native_shimcache_manifest["citation_refs"]},
            )
            self.assertIn(
                "bounded native AppCompatCache path provenance",
                native_shimcache["details"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "cache order preservation",
                native_shimcache["details"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertEqual(srum_rows[0]["details"]["app_id"], "powershell.exe")
            self.assertEqual(srum_rows[0]["details"]["bytes_received"], 2048)
            self.assertEqual(srum_rows[0]["details"]["bytes_total"], 2560)
            self.assertEqual(srum_rows[0]["details"]["network_profile"], "CorpWiFi")
            self.assertTrue(srum_rows[0]["details"]["validation_checks"]["has_network_counters"])
            self.assertEqual(srum_rows[0]["details"]["srum_usage_evidence"]["table_family"], "network-usage")
            self.assertIn("bytes_received", srum_rows[0]["details"]["srum_usage_evidence"]["counter_fields_present"])
            self.assertEqual(
                srum_rows[0]["details"]["srum_usage_evidence"]["counter_normalization_status"],
                "normalized-from-source-tool-export",
            )
            self.assertEqual(srum_rows[0]["details"]["forensic_review"]["gap_id"], "#10")
            self.assertEqual(srum_rows[0]["details"]["source_path"], str(fixture.srum_csv.resolve()))
            srum_import_manifest = srum_rows[0]["details"]["srum_report_citation_manifest"]
            self.assertEqual(srum_import_manifest["manifest_version"], "srum-report-citation-manifest-v1")
            self.assertEqual(srum_import_manifest["row_identity"]["artifact_scope"], "source-tool-export")
            self.assertEqual(srum_import_manifest["row_identity"]["table_family"], "network-usage")
            self.assertEqual(srum_import_manifest["row_identity"]["network_profile"], "CorpWiFi")
            self.assertEqual(
                srum_rows[0]["details"]["srum_report_citation_manifest_hash"],
                srum_import_manifest["manifest_sha256"],
            )
            self.assertIn("semantics_warning", srum_import_manifest["trusted_diff_contract"]["required_fields"])
            self.assertEqual(srum_import_manifest["reportability"]["allowed_use"], "srum-usage-triage-pivot")
            self.assertFalse(srum_import_manifest["reportability"]["standalone_execution_proof"])
            self.assertIn("triage pivots", srum_import_manifest["reportability"]["semantics_warning"])
            self.assertIn("srum-counter-semantics", {row["kind"] for row in srum_import_manifest["citation_refs"]})
            srum_import_review_profile = srum_rows[0]["details"]["execution_analyst_review_profile"]
            self.assertEqual(srum_import_review_profile["artifact_type"], "srum-network-usage")
            self.assertEqual(srum_import_review_profile["source_field_values"]["bytes_total"], 2560)
            self.assertIn("DNS", srum_import_review_profile["correlation_targets"])
            self.assertTrue(srum_import_review_profile["validation_required"])
            self.assertIn("execution-artifact-trusted-diff-required", srum_import_review_profile["commercial_blockers"])
            self.assertEqual(srum_database_rows[0]["details"]["source_path"], str(fixture.srum_db.resolve()))
            self.assertTrue(srum_database_rows[0]["details"]["ese_header"]["signature_valid"])
            self.assertTrue(srum_database_rows[0]["details"]["srum_database_evidence"]["ese_signature_valid"])
            self.assertEqual(srum_database_rows[0]["details"]["srum_ese_validation_profile"]["commercial_gap_id"], "#10")
            self.assertEqual(srum_database_rows[0]["details"]["srum_ese_validation_profile"]["qc_prep_item_number"], 25)
            self.assertIn(
                "native SRUDB.dat ESE header probe",
                srum_database_rows[0]["details"]["srum_ese_validation_profile"]["qc_prep_contract"]["implemented"],
            )
            self.assertEqual(srum_database_rows[0]["details"]["srum_ese_validation_profile"]["artifact_scope"], "database")
            self.assertTrue(srum_database_rows[0]["details"]["srum_ese_validation_profile"]["decoded_components"]["ese_header"])
            self.assertEqual(
                srum_database_rows[0]["details"]["srum_ese_validation_profile"]["reportability_decision"]["decision"],
                "do-not-report-native-row-as-decoded-fact",
            )
            self.assertEqual(
                srum_database_rows[0]["details"]["srum_database_evidence"]["schema_decode_status"],
                "not-implemented-header-and-string-pivot-only",
            )
            srum_database_manifest = srum_database_rows[0]["details"]["srum_report_citation_manifest"]
            self.assertEqual(srum_database_manifest["row_identity"]["artifact_scope"], "database")
            self.assertEqual(
                srum_database_rows[0]["details"]["srum_report_citation_manifest_hash"],
                srum_database_manifest["manifest_sha256"],
            )
            self.assertFalse(srum_database_manifest["validation_summary"]["native_srum_page_row_decode_available"])
            self.assertIn("trusted-srum-parser-diff-required", srum_database_manifest["reportability"]["blockers"])
            self.assertTrue(srum_database_rows[0]["details"]["validation_checks"]["ese_signature_valid"])
            self.assertEqual(
                srum_database_rows[0]["details"]["native_srudb_validation"]["validation_status"],
                "header-size-page-aligned",
            )
            self.assertTrue(srum_database_rows[0]["details"]["native_srudb_validation"]["page_size_plausible"])
            self.assertTrue(srum_database_rows[0]["details"]["validation_checks"]["has_native_srum_row_candidates"])
            self.assertFalse(srum_database_rows[0]["details"]["commercial_grade_ready"])
            self.assertIn("native-srum-row-decoding-required", srum_database_rows[0]["details"]["commercial_grade_blockers"])
            self.assertIn("#10", srum_database_rows[0]["details"]["execution_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(srum_database_rows[0]["details"]["forensic_review"]["gap_id"], "#10")
            self.assertFalse(srum_database_rows[0]["details"]["execution_native_capabilities"]["native_srum_page_row_decode"])
            srum_db_gate = srum_database_rows[0]["details"]["core_accuracy_gates"][0]
            self.assertEqual(srum_db_gate["gap_id"], "#10")
            self.assertIn("ESE header/page-size validation", srum_db_gate["satisfied_checks"])
            self.assertIn("catalog/table mapping", srum_db_gate["satisfied_checks"])
            self.assertIn("native-row confidence scoring", srum_db_gate["satisfied_checks"])
            self.assertIn("stable SRUM citation manifest", srum_db_gate["satisfied_checks"])
            srum_uplift = srum_database_rows[0]["details"]["commercial_uplift_evidence"]
            self.assertEqual(srum_uplift["batch_id"], "commercial-uplift-006-010")
            self.assertEqual(srum_uplift["item_numbers"], [10])
            self.assertEqual(srum_uplift["qc_prep_item_numbers"], [25])
            self.assertEqual(srum_uplift["reportability_decision"]["allowed_use"], "srum-usage-triage-pivot")
            self.assertTrue(srum_uplift["large_data_controls"]["row_level_native_decode_required_for_commercial_claims"])
            self.assertTrue(any("powershell.exe" in value.lower() for value in srum_database_rows[0]["details"]["path_candidates"]))
            self.assertTrue(any(item["details"]["app_id"] == "powershell.exe" for item in srum_pivots))
            self.assertTrue(any(item["details"]["url"] == "https://download.example/tools/installer.exe" for item in srum_pivots))
            self.assertTrue(all(item["details"]["validation_required"] for item in srum_pivots))
            self.assertTrue(all(item["details"]["srum_pivot_evidence"]["pivot_basis"] == "native-ese-string-pivot" for item in srum_pivots))
            self.assertTrue(all(item["details"]["srum_ese_validation_profile"]["artifact_scope"] == "string-pivot" for item in srum_pivots))
            srum_row_candidate = next(item for item in srum_row_candidates if item["details"]["app_id"] == "powershell.exe")
            self.assertEqual(srum_row_candidate["details"]["table_family"], "network-usage")
            self.assertEqual(srum_row_candidate["details"]["bytes_received"], 2048)
            self.assertEqual(srum_row_candidate["details"]["timestamp"], "2024-04-01T05:06:07+00:00")
            self.assertEqual(
                srum_row_candidate["details"]["srum_row_evidence"]["row_level_decode_status"],
                "not-implemented-string-cluster-only",
            )
            self.assertGreaterEqual(srum_row_candidate["details"]["srum_row_evidence"]["counter_candidate_count"], 1)
            self.assertGreaterEqual(srum_row_candidate["details"]["srum_row_evidence"]["nearby_string_count"], 1)
            self.assertIn(
                "SRUM field presence profile",
                srum_row_candidate["details"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertTrue(srum_row_candidate["details"]["field_presence_profile"]["network_counters"])
            self.assertEqual(srum_row_candidate["details"]["srum_ese_validation_profile"]["artifact_scope"], "row-candidate")
            self.assertGreaterEqual(srum_row_candidate["details"]["srum_ese_validation_profile"]["evidence_fields"]["counter_candidate_count"], 1)
            srum_row_manifest = srum_row_candidate["details"]["srum_report_citation_manifest"]
            self.assertEqual(srum_row_manifest["row_identity"]["artifact_scope"], "row-candidate")
            self.assertIn("bytes_received", srum_row_manifest["row_identity"]["counter_names"])
            self.assertEqual(srum_row_manifest["row_identity"]["network_profile"], "CorpWiFi")
            self.assertEqual(
                srum_row_candidate["details"]["srum_report_citation_manifest_hash"],
                srum_row_manifest["manifest_sha256"],
            )
            self.assertIn("srum-row-cluster", {row["kind"] for row in srum_row_manifest["citation_refs"]})
            self.assertFalse(srum_row_manifest["reportability"]["standalone_execution_proof"])
            self.assertIn("trusted-srum-parser-diff-required", srum_row_manifest["reportability"]["blockers"])
            srum_row_review_profile = srum_row_candidate["details"]["execution_analyst_review_profile"]
            self.assertEqual(srum_row_review_profile["artifact_type"], "srum-row-candidate")
            self.assertEqual(srum_row_review_profile["source_field_values"]["app_id"], "powershell.exe")
            self.assertGreaterEqual(srum_row_review_profile["source_field_values"]["source_offset"], 0)
            self.assertIn("native-ese-page-row-decoding-required", srum_row_review_profile["commercial_blockers"])
            self.assertTrue(srum_row_candidate["details"]["validation_checks"]["requires_srum_parser"])
            self.assertFalse(srum_row_candidate["details"]["commercial_grade_ready"])
            self.assertIn("native-ese-page-row-decoding-required", srum_row_candidate["details"]["commercial_grade_blockers"])
            srum_table = next(item for item in artifacts if item["artifact_type"] == "srum-table-candidate" and item["details"]["table_family"] == "network-usage")
            self.assertGreaterEqual(srum_table["details"]["matched_marker_count"], 1)
            self.assertEqual(srum_table["details"]["srum_ese_validation_profile"]["artifact_scope"], "table-candidate")
            self.assertEqual(srum_table["details"]["srum_ese_validation_profile"]["evidence_fields"]["table_family"], "network-usage")
            self.assertEqual(srum_table["details"]["srum_report_citation_manifest"]["row_identity"]["artifact_scope"], "table-candidate")
            self.assertTrue(srum_table["details"]["validation_checks"]["has_source_offsets"])
            self.assertTrue(srum_table["details"]["validation_checks"]["requires_srum_parser"])
            summary = next(item for item in artifacts if item["artifact_type"] == "windows-execution-summary")
            groups = {item["display_name"]: item for item in summary["details"]["groups"]}
            self.assertFalse(summary["details"]["native_capabilities"]["native_ese_catalog_decode"])
            self.assertTrue(summary["details"]["report_grade_status_counts"])
            self.assertEqual(
                summary["details"]["execution_correlation_profile"]["profile_version"],
                "execution-summary-correlation-v1",
            )
            self.assertEqual(summary["details"]["execution_correlation_profile"]["reportable_candidate_count"], 0)
            self.assertIn("powershell.exe", summary["details"]["execution_correlation_profile"]["review_required"])
            self.assertIn("evil.exe", summary["details"]["execution_correlation_profile"]["review_required"])
            self.assertIn("evil.exe", groups)
            self.assertIn("powershell.exe", groups)
            self.assertIn("bam-entry", groups["evil.exe"]["signal_types"])
            self.assertIn("powershell-history-command", groups["powershell.exe"]["signal_types"])
            self.assertIn("srum-network-usage", groups["powershell.exe"]["signal_types"])
            self.assertIn("srum-database-pivot", groups["powershell.exe"]["signal_types"])
            self.assertEqual(groups["powershell.exe"]["correlation_profile"]["status"], "multi-signal-corroborated")
            self.assertEqual(groups["evil.exe"]["correlation_profile"]["status"], "multi-signal-corroborated")
            self.assertIn(
                "source-artifact-validation-required",
                groups["evil.exe"]["correlation_profile"]["blockers"],
            )
            self.assertTrue(groups["powershell.exe"]["source_artifact_refs"])
            self.assertIn("suspicious-command:powershell -enc", groups["powershell.exe"]["risk_flags"])
            self.assertIn("Prefetch", groups["evil.exe"]["correlation_targets"])

    def test_execution_artifact_trusted_diff_passes_matching_rows(self) -> None:
        rapid = [
            {
                "executable_path": r"C:\Program Files\Example\app.exe",
                "timestamp": "2024-04-01T06:07:08Z",
                "sha1": "0123456789abcdef0123456789abcdef01234567",
                "execution_caveat": "Amcache supports program presence/install/execution-related pivots but is not standalone proof of execution.",
            }
        ]
        trusted = [
            {
                "path": r"C:\Program Files\Example\app.exe",
                "last_execution": "2024-04-01T06:07:08+00:00",
                "hash": "0123456789abcdef0123456789abcdef01234567",
                "warning": "Amcache supports program presence/install/execution-related pivots but is not standalone proof of execution.",
            }
        ]

        diff = build_execution_artifact_trusted_diff(
            rapid,
            trusted,
            trusted_tool="AmcacheParser",
            artifact_family="amcache",
        )

        self.assertEqual(diff["status"], "pass")
        self.assertTrue(diff["trusted_tool_recognized"])
        self.assertTrue(diff["commercial_grade_evidence"])
        self.assertEqual(diff["matched_count"], 1)
        self.assertEqual(diff["reportability_decision"]["decision"], "execution-artifact-diff-passed")

    def test_execution_artifact_trusted_diff_blocks_srum_counter_mismatch(self) -> None:
        rapid = [{"app_id": "powershell.exe", "timestamp": "2024-04-01T05:06:07+00:00", "bytes_received": 2048}]
        trusted = [{"app_id": "powershell.exe", "timestamp": "2024-04-01T05:06:07+00:00", "bytes_received": 1024}]

        diff = build_execution_artifact_trusted_diff(
            rapid,
            trusted,
            trusted_tool="SrumECmd",
            artifact_family="srum",
        )

        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["commercial_grade_evidence"])
        self.assertEqual(diff["mismatch_count"], 1)
        self.assertIn("execution-artifact-trusted-diff-required", diff["reportability_decision"]["blockers"])

    def test_windows_prefetch_fixture_surfaces_run_count_and_last_run_time(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            build_windows_artifact_fixture(root)
            output = root / "prefetch.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "windows-prefetch", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            prefetch_file = next(item for item in payload["artifacts"] if item["artifact_type"] == "prefetch-file")
            references = [item for item in payload["artifacts"] if item["artifact_type"] == "prefetch-reference"]
            details = prefetch_file["details"]

            self.assertEqual(details["prefetch_parse_status"], "parsed-common-header")
            self.assertEqual(details["parser_version"], "prefetch-inventory-v8")
            self.assertFalse(details["commercial_grade_ready"])
            self.assertIn("Full file metrics array decoding", details["commercial_readiness_blockers"][0])
            self.assertIn("#16", details["prefetch_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(details["forensic_review"]["gap_id"], "#16")
            self.assertFalse(details["forensic_review"]["report_grade_ready"])
            self.assertFalse(details["prefetch_native_capabilities"]["full_file_metrics_array_decode"])
            self.assertEqual(details["prefetch_version_metadata"]["layout_name"], "windows-10")
            self.assertEqual(details["prefetch_version_metadata"]["run_count_offset_hex"], "0xd0")
            self.assertEqual(details["run_count"], 3)
            self.assertEqual(details["last_run_at"], "2024-04-01T09:10:11+00:00")
            self.assertIn(details["last_run_at"], details["last_run_times"])
            self.assertEqual(details["prefetch_validation_checks"]["file_size_matches_declared"], True)
            self.assertTrue(details["prefetch_validation_checks"]["run_count_plausible"])
            self.assertTrue(details["prefetch_validation_checks"]["last_run_times_not_future"])
            self.assertFalse(details["prefetch_validation_checks"]["full_file_metrics_decoded"])
            prefetch_gate = details["core_accuracy_gates"][0]
            self.assertEqual(prefetch_gate["gap_id"], "#16")
            self.assertIn("SCCA/header validation", prefetch_gate["satisfied_checks"])
            self.assertIn("version-specific section offsets", prefetch_gate["satisfied_checks"])
            self.assertIn("run count and last-run timestamps", prefetch_gate["satisfied_checks"])
            self.assertIn("volume/file metrics", prefetch_gate["satisfied_checks"])
            self.assertIn("compressed PF handling", prefetch_gate["satisfied_checks"])
            prefetch_uplift = details["commercial_uplift_evidence"]
            self.assertEqual(prefetch_uplift["batch_id"], "commercial-uplift-016-020")
            self.assertEqual(prefetch_uplift["item_numbers"], [16])
            self.assertEqual(prefetch_uplift["qc_prep_item_numbers"], [31])
            self.assertEqual(
                prefetch_uplift["reportability_decision"]["allowed_use"],
                "prefetch-execution-triage-pivot",
            )
            self.assertIn("scca-signature", prefetch_uplift["passed_validation_matrix_ids"])
            self.assertTrue(
                prefetch_uplift["large_data_controls"]["full_file_metrics_decode_required_for_commercial_claims"]
            )
            prefetch_review_profile = details["prefetch_analyst_review_profile"]
            self.assertEqual(prefetch_review_profile["profile_version"], "prefetch-analyst-review-profile-v1")
            self.assertEqual(prefetch_review_profile["qc_prep_item_number"], 31)
            self.assertEqual(prefetch_review_profile["source_field_values"]["executable_hint"], "POWERSHELL.EXE")
            self.assertEqual(prefetch_review_profile["source_field_values"]["run_count"], 3)
            self.assertIn("Amcache", prefetch_review_profile["correlation_targets"])
            self.assertIn("standalone execution attribution", prefetch_review_profile["not_proof_of"])
            prefetch_manifest = details["prefetch_execution_depth_manifest"]
            self.assertEqual(prefetch_manifest["manifest_version"], "prefetch-execution-depth-manifest-v1")
            self.assertEqual(prefetch_manifest["gap_id"], "#16")
            self.assertEqual(prefetch_manifest["qc_prep_item_number"], 31)
            self.assertEqual(prefetch_manifest["format_validation"]["layout_name"], "windows-10")
            self.assertTrue(prefetch_manifest["format_validation"]["supported_common_layout"])
            self.assertEqual(prefetch_manifest["execution_counters"]["run_count"], 3)
            self.assertEqual(
                prefetch_manifest["execution_counters"]["last_run_at"],
                "2024-04-01T09:10:11+00:00",
            )
            self.assertFalse(prefetch_manifest["referenced_file_metrics"]["full_file_metrics_decoded"])
            self.assertFalse(prefetch_manifest["referenced_file_metrics"]["mft_file_reference_decode_available"])
            self.assertEqual(
                prefetch_manifest["reportability"]["allowed_use"],
                "prefetch-execution-triage-pivot",
            )
            self.assertTrue(prefetch_manifest["reportability"]["execution_claim_requires_correlation"])
            self.assertEqual(
                details["prefetch_execution_depth_manifest_hash"],
                prefetch_manifest["manifest_sha256"],
            )
            self.assertTrue(any("POWERSHELL.EXE" in path for path in details["referenced_paths"]))
            self.assertEqual(details["volume_candidate_count"], 1)
            self.assertEqual(details["volume_candidates"][0]["volume_device_path"], r"\DEVICE\HARDDISKVOLUME3")
            self.assertEqual(details["file_reference_candidate_count"], 1)
            self.assertEqual(details["file_reference_candidates"][0]["referenced_file_name"], "POWERSHELL.EXE")
            self.assertTrue(references)
            self.assertEqual(references[0]["details"]["referenced_file_name"], "POWERSHELL.EXE")
            self.assertEqual(references[0]["details"]["volume_device_path"], r"\DEVICE\HARDDISKVOLUME3")
            self.assertEqual(references[0]["details"]["last_run_at"], "2024-04-01T09:10:11+00:00")
            self.assertTrue(references[0]["details"]["validation_required"])
            self.assertEqual(references[0]["details"]["commercial_uplift_evidence"]["item_numbers"], [16])
            self.assertEqual(references[0]["details"]["commercial_uplift_evidence"]["qc_prep_item_numbers"], [31])
            self.assertFalse(references[0]["details"]["commercial_grade_ready"])
            self.assertIn("#16", references[0]["details"]["prefetch_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(references[0]["details"]["forensic_review"]["gap_id"], "#16")
            self.assertEqual(
                references[0]["details"]["prefetch_execution_depth_manifest"]["artifact_type"],
                "prefetch-reference",
            )

    def test_windows_prefetch_collector_is_available_as_dedicated_artifacts_kind(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            output = root / "prefetch.json"
            prefetch = root / "Windows" / "Prefetch" / "POWERSHELL.EXE-12345678.pf"
            prefetch.parent.mkdir(parents=True, exist_ok=True)
            header = bytearray(512)
            header[0:4] = (30).to_bytes(4, "little")
            header[4:8] = b"SCCA"
            header[0x0C:0x10] = (len(header)).to_bytes(4, "little")
            header[16 : 16 + len("POWERSHELL.EXE".encode("utf-16le"))] = "POWERSHELL.EXE".encode("utf-16le")
            header[0xD0:0xD4] = (7).to_bytes(4, "little")
            prefetch.write_bytes(bytes(header))

            self.assertEqual(main(["artifacts", str(root), "--kind", "windows-prefetch", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            artifact = payload["artifacts"][0]

            self.assertEqual(payload["kind"], "windows-prefetch")
            self.assertEqual(artifact["artifact_type"], "prefetch-file")
            self.assertEqual(artifact["details"]["executable_hint"], "POWERSHELL.EXE")
            self.assertEqual(artifact["details"]["executable_hint_source"], "prefetch_header")
            self.assertTrue(artifact["details"]["binary_format_detected"])
            self.assertEqual(artifact["details"]["prefetch_version"], 30)
            self.assertEqual(artifact["details"]["header_executable_name"], "POWERSHELL.EXE")
            self.assertEqual(artifact["details"]["run_count"], 7)
            self.assertTrue(artifact["details"]["prefetch_validation_checks"]["supported_common_layout"])
            self.assertTrue(artifact["details"]["prefetch_validation_checks"]["run_count_present"])
            self.assertEqual(artifact["details"]["prefetch_validation_checks"]["file_size_matches_declared"], True)
            self.assertEqual(artifact["details"]["prefetch_hash"], "12345678")
            self.assertEqual(artifact["details"]["evidence_strength"], "execution-indicator")

    def test_windows_prefetch_common_version_metadata_uses_version_offsets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            output = root / "prefetch.json"
            prefetch = root / "Windows" / "Prefetch" / "NOTEPAD.EXE-ABCDEF12.pf"
            prefetch.parent.mkdir(parents=True, exist_ok=True)
            header = bytearray(512)
            header[0:4] = (23).to_bytes(4, "little")
            header[4:8] = b"SCCA"
            header[0x0C:0x10] = (len(header)).to_bytes(4, "little")
            header[16 : 16 + len("NOTEPAD.EXE".encode("utf-16le"))] = "NOTEPAD.EXE".encode("utf-16le")
            header[0x80:0x88] = datetime_to_filetime(datetime(2024, 2, 3, 4, 5, 6, tzinfo=timezone.utc)).to_bytes(
                8, "little"
            )
            header[0x98:0x9C] = (11).to_bytes(4, "little")
            prefetch.write_bytes(bytes(header))

            self.assertEqual(main(["artifacts", str(root), "--kind", "windows-prefetch", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            details = payload["artifacts"][0]["details"]

            self.assertEqual(details["prefetch_version"], 23)
            self.assertEqual(details["prefetch_version_metadata"]["layout_name"], "windows-vista-7")
            self.assertEqual(details["prefetch_version_metadata"]["run_count_offset_hex"], "0x98")
            self.assertEqual(details["prefetch_version_metadata"]["last_run_time_slots"], 1)
            self.assertEqual(details["run_count"], 11)
            self.assertEqual(details["last_run_times"], ["2024-02-03T04:05:06+00:00"])
            self.assertTrue(details["prefetch_validation_checks"]["supported_common_layout"])

    def test_windows_filesystem_collector_imports_mft_and_usn_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            fixture = build_windows_artifact_fixture(root)
            output = root / "filesystem.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "windows-filesystem", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            artifacts = payload["artifacts"]
            mft = [
                item
                for item in artifacts
                if item["artifact_type"] == "mft-record"
                and item["details"]["parser"] == "windows-filesystem-import"
            ]
            native_mft = [
                item
                for item in artifacts
                if item["artifact_type"] == "mft-record"
                and item["details"]["parser"] == "windows-mft-native"
            ]
            usn = [
                item
                for item in artifacts
                if item["artifact_type"] == "usn-record"
                and item["details"]["parser"] == "windows-filesystem-import"
            ]
            native_usn = [
                item
                for item in artifacts
                if item["artifact_type"] == "usn-record"
                and item["details"]["parser"] == "windows-usn-native"
            ]
            mft_files = [item for item in artifacts if item["artifact_type"] == "mft-file"]
            usn_files = [item for item in artifacts if item["artifact_type"] == "usn-journal-file"]

            self.assertEqual(mft[0]["details"]["record_number"], "42")
            self.assertTrue(mft[0]["details"]["deleted_hint"])
            self.assertEqual(mft[0]["details"]["source_path"], str(fixture.mft_csv.resolve()))
            self.assertEqual(usn[0]["details"]["reason"], "FILE_DELETE")
            self.assertEqual(usn[0]["details"]["source_path"], str(fixture.usn_jsonl.resolve()))
            self.assertEqual(mft_files[0]["details"]["source_path"], str(fixture.mft_native.resolve()))
            self.assertEqual(mft_files[0]["details"]["native_record_count"], 1)
            self.assertTrue(mft_files[0]["details"]["record_header_samples"][0]["in_use"])
            self.assertIn(r"C:\Users\alice\Desktop\deleted.txt", mft_files[0]["details"]["path_candidates"])
            self.assertEqual(native_mft[0]["details"]["record_number"], "0")
            self.assertEqual(native_mft[0]["details"]["sequence_number"], 3)
            self.assertTrue(native_mft[0]["details"]["in_use"])
            self.assertIn(r"C:\Users\alice\Desktop\deleted.txt", native_mft[0]["details"]["path_candidates"])
            self.assertEqual(native_mft[0]["details"]["coverage_status"], "native-file-record-attributes-partial")
            self.assertEqual(native_mft[0]["details"]["sequence_validation"]["status"], "valid")
            self.assertEqual(native_mft[0]["details"]["timestamp_validation"]["status"], "valid")
            self.assertEqual(native_mft[0]["details"]["timestamp"], "2024-04-01T04:05:06+00:00")
            self.assertFalse(native_mft[0]["details"]["time_stomping_suspected"])
            self.assertEqual(
                native_mft[0]["details"]["timestamp_stomping_analysis"]["coverage_status"],
                "sia-fna-compared",
            )
            self.assertIn("$STANDARD_INFORMATION", native_mft[0]["details"]["attribute_types"])
            self.assertIn("$FILE_NAME", native_mft[0]["details"]["attribute_types"])
            self.assertIn("$DATA", native_mft[0]["details"]["attribute_types"])
            self.assertEqual(native_mft[0]["details"]["file_name_entries"][0]["file_name"], "deleted.txt")
            self.assertEqual(native_mft[0]["details"]["parent_reference_decoded"]["record_number"], 5)
            self.assertTrue(native_mft[0]["details"]["data_attributes"][0]["resident"])
            self.assertEqual(native_mft[0]["details"]["mft_record_evidence"]["record_identity"]["sequence_number"], 3)
            self.assertEqual(
                native_mft[0]["details"]["mft_record_evidence"]["path_evidence"]["primary_path"],
                r"C:\Users\alice\Desktop\deleted.txt",
            )
            self.assertEqual(
                native_mft[0]["details"]["mft_record_evidence"]["path_evidence"]["parent_reference_decoded"]["record_number"],
                5,
            )
            self.assertEqual(
                native_mft[0]["details"]["mft_path_reconstruction_profile"]["parent_record_number"],
                5,
            )
            self.assertFalse(native_mft[0]["details"]["mft_path_reconstruction_profile"]["full_volume_path_cache_used"])
            self.assertIn(
                "mft-full-volume-parent-cache-required",
                native_mft[0]["details"]["mft_path_reconstruction_profile"]["blockers"],
            )
            self.assertTrue(native_mft[0]["details"]["mft_record_evidence"]["state_evidence"]["in_use"])
            self.assertIn(
                "$STANDARD_INFORMATION",
                native_mft[0]["details"]["mft_record_evidence"]["attribute_evidence"]["attribute_types"],
            )
            self.assertEqual(
                native_mft[0]["details"]["mft_attribute_list_profile"]["resolution_status"],
                "not-present-in-record",
            )
            self.assertEqual(native_mft[0]["details"]["mft_data_run_summary"]["resident_data_attribute_count"], 1)
            self.assertEqual(native_mft[0]["details"]["mft_data_run_summary"]["nonresident_data_attribute_count"], 0)
            self.assertEqual(
                native_mft[0]["details"]["mft_record_evidence"]["validation_evidence"]["sequence_fixup_status"],
                "valid",
            )
            self.assertIn(
                "magic_valid",
                native_mft[0]["details"]["mft_record_evidence"]["validation_evidence"]["critical_checks_passed"],
            )
            self.assertFalse(native_mft[0]["details"]["commercial_grade_ready"])
            self.assertIn(
                "attribute-list-extension-record-resolution-not-implemented",
                native_mft[0]["details"]["commercial_grade_blockers"],
            )
            self.assertIn("#12", native_mft[0]["details"]["ntfs_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(native_mft[0]["details"]["forensic_review"]["gap_id"], "#12")
            mft_gate = native_mft[0]["details"]["core_accuracy_gates"][0]
            self.assertEqual(mft_gate["gap_id"], "#12")
            self.assertIn("USA validation", mft_gate["satisfied_checks"])
            self.assertIn("parent path reconstruction", mft_gate["satisfied_checks"])
            self.assertIn("timestamp/source field provenance", mft_gate["satisfied_checks"])
            self.assertFalse(native_mft[0]["details"]["ntfs_native_capabilities"]["mft_attribute_list_resolution"])
            self.assertTrue(native_mft[0]["details"]["validation_required"])
            mft_depth = native_mft[0]["details"]["ntfs_native_depth_readiness_profile"]
            self.assertEqual(mft_depth["profile_version"], "ntfs-native-depth-readiness-v1")
            self.assertEqual(mft_depth["family"], "mft")
            self.assertEqual(mft_depth["artifact_scope"], "record")
            self.assertFalse(mft_depth["commercial_grade_ready"])
            self.assertTrue(mft_depth["decoded_components"]["usa_sequence_fixup"])
            self.assertTrue(mft_depth["decoded_components"]["file_name_attribute"])
            self.assertFalse(mft_depth["decoded_components"]["attribute_list_resolution"])
            self.assertIn("source_sha256", mft_depth["source_citation_requirements"])
            self.assertIn("attribute-list-extension-record-resolution-not-implemented", mft_depth["blockers"])
            mft_parser_manifest = native_mft[0]["details"]["mft_parser_depth_manifest"]
            self.assertEqual(mft_parser_manifest["manifest_version"], "mft-parser-depth-manifest-v1")
            self.assertEqual(mft_parser_manifest["gap_id"], "#12")
            self.assertEqual(mft_parser_manifest["record_identity"]["record_number"], "0")
            self.assertTrue(mft_parser_manifest["usa_validation"]["sequence_fixup_valid"])
            self.assertTrue(mft_parser_manifest["attribute_decoding"]["has_file_name"])
            self.assertTrue(mft_parser_manifest["attribute_decoding"]["has_data"])
            self.assertFalse(mft_parser_manifest["attribute_decoding"]["attribute_list_resolution_available"])
            self.assertEqual(
                mft_parser_manifest["data_run_decoding"]["resident_data_attribute_count"],
                1,
            )
            self.assertFalse(
                mft_parser_manifest["path_reconstruction"]["full_volume_path_reconstruction_complete"],
            )
            self.assertEqual(
                mft_parser_manifest["reportability"]["allowed_use"],
                "mft-record-structure-and-timestamp-pivot",
            )
            self.assertEqual(
                native_mft[0]["details"]["mft_parser_depth_manifest_hash"],
                mft_parser_manifest["manifest_sha256"],
            )
            self.assertEqual(native_mft[0]["details"]["mft_full_parser_profile"]["item_number"], 12)
            self.assertEqual(native_mft[0]["details"]["mft_full_parser_profile"]["qc_prep_item_number"], 27)
            self.assertIn(
                "native FILE record header and USA sequence fixup validation",
                native_mft[0]["details"]["mft_full_parser_profile"]["qc_prep_contract"]["implemented"],
            )
            self.assertEqual(native_mft[0]["details"]["mft_full_parser_profile"]["artifact_scope"], "record")
            self.assertTrue(native_mft[0]["details"]["mft_full_parser_profile"]["decoded_components"]["usa_sequence_fixup"])
            self.assertTrue(native_mft[0]["details"]["mft_full_parser_profile"]["decoded_components"]["file_name_attributes"])
            self.assertTrue(native_mft[0]["details"]["mft_full_parser_profile"]["decoded_components"]["parent_reference_decode"])
            self.assertFalse(native_mft[0]["details"]["mft_full_parser_profile"]["decoded_components"]["attribute_list_resolution"])
            self.assertEqual(
                native_mft[0]["details"]["mft_full_parser_profile"]["path_reconstruction_profile"]["source_mode"],
                "full-path-string-candidate",
            )
            self.assertIn(
                "mft-full-volume-path-cache-required",
                native_mft[0]["details"]["mft_full_parser_profile"]["commercial_grade_blockers"],
            )
            mft_uplift = native_mft[0]["details"]["commercial_uplift_evidence"]
            self.assertEqual(mft_uplift["batch_id"], "commercial-uplift-011-015")
            self.assertEqual(mft_uplift["item_numbers"], [12])
            self.assertEqual(mft_uplift["qc_prep_item_numbers"], [27])
            self.assertEqual(
                mft_uplift["reportability_decision"]["decision"],
                "do-not-report-full-path-or-file-content-as-complete",
            )
            self.assertEqual(
                mft_uplift["reportability_decision"]["allowed_use"],
                "mft-record-structure-and-timestamp-pivot",
            )
            self.assertIn("sequence-fixup-valid", mft_uplift["passed_validation_matrix_ids"])
            self.assertTrue(
                mft_uplift["large_data_controls"]["full_volume_or_journal_validation_required_for_commercial_claims"]
            )
            mft_review_profile = native_mft[0]["details"]["ntfs_analyst_review_profile"]
            self.assertEqual(mft_review_profile["profile_version"], "ntfs-analyst-review-profile-v1")
            self.assertEqual(mft_review_profile["family"], "mft")
            self.assertEqual(mft_review_profile["source_field_values"]["record_number"], "0")
            self.assertIn("USN", mft_review_profile["correlation_targets"])
            self.assertIn("full path reconstruction without volume-wide parent cache", mft_review_profile["not_proof_of"])
            self.assertIn("mft-trusted-parser-diff-required", mft_review_profile["commercial_blockers"])
            mft_locator = native_mft[0]["details"]["ntfs_record_locator_profile"]
            self.assertEqual(mft_locator["profile_version"], "ntfs-record-source-viewer-locator-v1")
            self.assertEqual(mft_locator["qc_prep_item"], 9)
            self.assertEqual(mft_locator["viewer"], "ntfs-mft-record")
            self.assertEqual(mft_locator["record_locator_type"], "mft-file-record")
            self.assertEqual(mft_locator["record_number"], "0")
            self.assertEqual(mft_locator["frn"], "0")
            self.assertEqual(mft_locator["parent_frn_record_number"], 5)
            self.assertEqual(mft_locator["sequence"], 3)
            self.assertEqual(mft_locator["record_offset"], 0)
            self.assertEqual(mft_locator["path_confidence"], "full-path-string-candidate")
            self.assertIn("$MFT record 0", mft_locator["source_citation"])
            self.assertEqual(len(mft_locator["source_sha256"]), 64)
            self.assertEqual(native_mft[0]["details"]["source_viewer_locator"], mft_locator)
            self.assertIn({"value": "valid", "count": 1}, mft_files[0]["details"]["sequence_validation_counts"])
            self.assertIn({"value": "$FILE_NAME", "count": 1}, mft_files[0]["details"]["native_attribute_type_counts"])
            self.assertEqual(usn_files[0]["details"]["source_path"], str(fixture.usn_journal.resolve()))
            self.assertEqual(usn_files[0]["details"]["native_record_count"], 3)
            self.assertIn({"value": "2", "count": 2}, usn_files[0]["details"]["record_version_counts"])
            self.assertIn({"value": "3", "count": 1}, usn_files[0]["details"]["record_version_counts"])
            self.assertIn({"value": "large", "count": 1}, usn_files[0]["details"]["record_size_class_counts"])
            self.assertIn({"value": "standard", "count": 2}, usn_files[0]["details"]["record_size_class_counts"])
            self.assertEqual(usn_files[0]["details"]["large_record_count"], 1)
            self.assertGreaterEqual(usn_files[0]["details"]["largest_record_length"], 512)
            self.assertEqual(usn_files[0]["details"]["scan_metadata"]["first_record_offset"], 16)
            self.assertEqual(usn_files[0]["details"]["skipped_bytes_before_records"], 16)
            self.assertEqual(usn_files[0]["details"]["skipped_bytes_during_scan"], 16)
            self.assertFalse(usn_files[0]["details"]["next_cursor_available"])
            self.assertIsNone(usn_files[0]["details"]["next_cursor_offset"])
            self.assertEqual(usn_files[0]["details"]["trailing_unparsed_bytes"], 0)
            self.assertEqual(usn_files[0]["details"]["timestamp_range"]["latest"], "2024-04-01T04:08:09+00:00")
            self.assertEqual(usn_files[0]["details"]["usn_replay_inventory_profile"]["delete_count"], 1)
            self.assertEqual(
                usn_files[0]["details"]["usn_replay_inventory_profile"]["cursor_window"]["first_record_offset"],
                16,
            )
            self.assertFalse(usn_files[0]["details"]["usn_replay_inventory_profile"]["full_frn_path_cache_replay_done"])
            self.assertEqual(usn_files[0]["details"]["usn_journal_replay_profile"]["item_number"], 14)
            self.assertEqual(usn_files[0]["details"]["usn_journal_replay_profile"]["qc_prep_item_number"], 28)
            self.assertIn(
                "native USN v2/v3 record scan and v4 extent preview",
                usn_files[0]["details"]["usn_journal_replay_profile"]["qc_prep_contract"]["implemented"],
            )
            self.assertEqual(usn_files[0]["details"]["usn_journal_replay_profile"]["artifact_scope"], "inventory")
            self.assertEqual(
                usn_files[0]["details"]["usn_journal_replay_profile"]["inventory_replay_profile"]["delete_count"],
                1,
            )
            self.assertFalse(
                usn_files[0]["details"]["usn_journal_replay_profile"]["decoded_components"][
                    "full_frn_path_cache_replay"
                ]
            )
            self.assertFalse(usn_files[0]["details"]["commercial_grade_ready"])
            self.assertEqual(native_usn[0]["details"]["file_path"], "deleted.txt")
            self.assertEqual(native_usn[0]["details"]["validation_status"], "valid")
            self.assertEqual(native_usn[0]["details"]["parser_confidence"], 0.85)
            self.assertTrue(native_usn[0]["details"]["deleted_hint"])
            self.assertIn("FILE_DELETE", native_usn[0]["details"]["reason_flags"])
            self.assertIn("ARCHIVE", native_usn[0]["details"]["file_attribute_names"])
            self.assertEqual(native_usn[0]["details"]["record_cursor"], 16)
            self.assertEqual(native_usn[0]["details"]["next_record_cursor"], native_usn[1]["details"]["record_cursor"])
            self.assertEqual(native_usn[0]["details"]["usn_replay_transition_profile"]["transition_class"], "delete")
            self.assertTrue(native_usn[0]["details"]["usn_replay_transition_profile"]["requires_previous_state"])
            self.assertTrue(native_usn[0]["details"]["usn_cursor_pagination_profile"]["safe_for_cursor_api"])
            self.assertEqual(
                native_usn[0]["details"]["usn_journal_replay_profile"]["transition_profile"]["transition_class"],
                "delete",
            )
            self.assertEqual(native_usn[0]["details"]["file_reference_number_decoded"]["record_number"], 42)
            self.assertEqual(native_usn[0]["details"]["parent_file_reference_number_decoded"]["record_number"], 5)
            self.assertEqual(
                native_usn[0]["details"]["usn_record_evidence"]["file_reference_evidence"]["file_name"],
                "deleted.txt",
            )
            self.assertIn("FILE_DELETE", native_usn[0]["details"]["usn_record_evidence"]["change_evidence"]["reason_flags"])
            self.assertTrue(native_usn[0]["details"]["usn_record_evidence"]["change_evidence"]["deleted_hint"])
            self.assertEqual(
                native_usn[0]["details"]["usn_record_evidence"]["validation_evidence"]["record_validation_status"],
                "valid",
            )
            self.assertIn(
                "filename_utf16_valid",
                native_usn[0]["details"]["usn_record_evidence"]["validation_evidence"]["critical_checks_passed"],
            )
            self.assertTrue(native_usn[0]["details"]["validation_checks"]["record_cursor_progresses"])
            self.assertTrue(native_usn[0]["details"]["validation_checks"]["filename_utf16_valid"])
            self.assertFalse(native_usn[0]["details"]["commercial_grade_ready"])
            self.assertIn("#13", native_usn[0]["details"]["ntfs_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(native_usn[0]["details"]["forensic_review"]["gap_id"], "#13")
            usn_depth = native_usn[0]["details"]["ntfs_native_depth_readiness_profile"]
            self.assertEqual(usn_depth["profile_version"], "ntfs-native-depth-readiness-v1")
            self.assertEqual(usn_depth["family"], "usn")
            self.assertEqual(usn_depth["artifact_scope"], "record")
            self.assertFalse(usn_depth["commercial_grade_ready"])
            self.assertTrue(usn_depth["decoded_components"]["cursor_progression"])
            self.assertTrue(usn_depth["decoded_components"]["reason_flags"])
            self.assertFalse(usn_depth["decoded_components"]["full_frn_path_cache_replay"])
            self.assertEqual(usn_depth["validation_summary"]["trusted_diff_status"], "not-attached")
            self.assertIn("record_offset_or_cursor", usn_depth["source_citation_requirements"])
            usn_gate = native_usn[0]["details"]["core_accuracy_gates"][0]
            self.assertEqual(usn_gate["gap_id"], "#13")
            self.assertIn("record-size bounds", usn_gate["satisfied_checks"])
            self.assertIn("reason flag decoding", usn_gate["satisfied_checks"])
            self.assertIn("rename/delete ordering", usn_gate["satisfied_checks"])
            self.assertIn("cursor determinism at scale", usn_gate["satisfied_checks"])
            self.assertFalse(native_usn[0]["details"]["ntfs_native_capabilities"]["usn_full_journal_replay"])
            self.assertEqual(native_usn[0]["details"]["usn_journal_replay_profile"]["artifact_scope"], "record")
            self.assertTrue(native_usn[0]["details"]["usn_journal_replay_profile"]["decoded_components"]["reason_flags"])
            self.assertTrue(native_usn[0]["details"]["usn_journal_replay_profile"]["decoded_components"]["cursor_pagination"])
            self.assertEqual(native_usn[0]["details"]["commercial_uplift_evidence"]["qc_prep_item_numbers"], [28])
            self.assertIn(
                "usn-frn-path-cache-replay-required",
                native_usn[0]["details"]["usn_journal_replay_profile"]["commercial_grade_blockers"],
            )
            usn_manifest = native_usn[0]["details"]["usn_timeline_depth_manifest"]
            self.assertEqual(usn_manifest["manifest_version"], "usn-timeline-depth-manifest-v1")
            self.assertEqual(usn_manifest["gap_id"], "#13")
            self.assertEqual(usn_manifest["record_identity"]["file_name"], "deleted.txt")
            self.assertTrue(usn_manifest["record_layout_validation"]["record_cursor_progresses"])
            self.assertTrue(usn_manifest["record_layout_validation"]["filename_utf16_valid"])
            self.assertIn("FILE_DELETE", usn_manifest["change_semantics"]["reason_flags"])
            self.assertEqual(usn_manifest["change_semantics"]["transition_class"], "delete")
            self.assertEqual(usn_manifest["path_correlation"]["path_candidate"], "")
            self.assertIn(
                "usn-full-frn-path-cache-required",
                usn_manifest["path_correlation"]["blockers"],
            )
            self.assertFalse(usn_manifest["path_correlation"]["full_frn_path_cache_replay_done"])
            self.assertTrue(usn_manifest["cursor_pagination"]["safe_for_cursor_api"])
            self.assertFalse(usn_manifest["replay_state"]["full_journal_replay_available"])
            self.assertFalse(usn_manifest["reportability"]["full_timeline_replayed"])
            self.assertEqual(
                native_usn[0]["details"]["usn_timeline_depth_manifest_hash"],
                usn_manifest["manifest_sha256"],
            )
            usn_uplift = native_usn[0]["details"]["commercial_uplift_evidence"]
            self.assertEqual(usn_uplift["item_numbers"], [13])
            self.assertEqual(usn_uplift["reportability_decision"]["decision"], "do-not-report-full-timeline-as-replayed")
            self.assertEqual(usn_uplift["reportability_decision"]["allowed_use"], "usn-change-record-triage-pivot")
            self.assertIn("record-cursor-progresses", usn_uplift["passed_validation_matrix_ids"])
            self.assertEqual(usn_uplift["large_data_controls"]["record_cursor"], 16)
            usn_review_profile = native_usn[0]["details"]["ntfs_analyst_review_profile"]
            self.assertEqual(usn_review_profile["profile_version"], "ntfs-analyst-review-profile-v1")
            self.assertEqual(usn_review_profile["family"], "usn")
            self.assertEqual(usn_review_profile["source_field_values"]["usn"], 9001)
            self.assertIn("MFT", usn_review_profile["correlation_targets"])
            self.assertIn("complete timeline replay", usn_review_profile["not_proof_of"])
            self.assertIn("usn-trusted-parser-diff-required", usn_review_profile["commercial_blockers"])
            usn_locator = native_usn[0]["details"]["ntfs_record_locator_profile"]
            self.assertEqual(usn_locator["profile_version"], "ntfs-record-source-viewer-locator-v1")
            self.assertEqual(usn_locator["qc_prep_item"], 9)
            self.assertEqual(usn_locator["viewer"], "ntfs-usn-record")
            self.assertEqual(usn_locator["record_locator_type"], "usn-change-record")
            self.assertEqual(usn_locator["frn_record_number"], 42)
            self.assertEqual(usn_locator["parent_frn_record_number"], 5)
            self.assertEqual(usn_locator["sequence"], 0)
            self.assertEqual(usn_locator["usn"], 9001)
            self.assertIn("FILE_DELETE", usn_locator["reason_flags"])
            self.assertEqual(usn_locator["record_cursor"], 16)
            self.assertEqual(usn_locator["path_confidence"], "no-matching-frn-in-bounded-mft-cache")
            self.assertIn("USN 9001", usn_locator["source_citation"])
            self.assertEqual(len(usn_locator["source_sha256"]), 64)
            self.assertEqual(native_usn[0]["details"]["source_viewer_locator"], usn_locator)
            self.assertEqual(native_usn[1]["details"]["major_version"], 3)
            self.assertEqual(native_usn[1]["details"]["file_path"], "renamed.txt")
            self.assertEqual(native_usn[1]["details"]["rename_hint"], "rename-new-name")
            self.assertIn("CLOSE", native_usn[1]["details"]["reason_flags"])
            self.assertEqual(native_usn[1]["details"]["file_reference_number_decoded"]["format"], "file-id-128")
            self.assertEqual(native_usn[2]["details"]["record_size_class"], "large")
            self.assertGreaterEqual(native_usn[2]["details"]["record_length"], 512)
            self.assertGreaterEqual(native_usn[2]["details"]["file_name_length"], 512)
            self.assertEqual(native_usn[2]["details"]["file_name_decode_status"], "valid")
            self.assertTrue(native_usn[2]["details"]["validation_checks"]["large_record"])
            self.assertIn("DATA_EXTEND", native_usn[2]["details"]["reason_flags"])
            self.assertIn("CLOSE", native_usn[2]["details"]["reason_flags"])

    def test_windows_filesystem_collector_flags_mft_sia_fna_timestamp_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            mft = root / "$MFT"
            mft.write_bytes(
                build_minimal_mft(file_name_timestamp=datetime(2024, 3, 31, 1, 2, 3, tzinfo=timezone.utc))
            )
            output = root / "filesystem.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "windows-filesystem", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            artifact = next(item for item in payload["artifacts"] if item["artifact_type"] == "mft-record")
            analysis = artifact["details"]["timestamp_stomping_analysis"]

            self.assertTrue(artifact["details"]["time_stomping_suspected"])
            self.assertEqual(analysis["coverage_status"], "sia-fna-mismatch-detected")
            self.assertEqual(analysis["mismatch_count"], 4)
            self.assertIn("mft-sia-fna-timestamp-mismatch", artifact["details"]["risk_flags"])
            self.assertEqual(analysis["mismatches"][0]["field"], "created_at")
            self.assertEqual(analysis["mismatches"][0]["file_name_value"], "deleted.txt")

    def test_windows_filesystem_collector_maps_recycle_bin_and_signature_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            recycle_dir = root / "$Recycle.Bin" / "S-1-5-21-111-222-333-1001"
            recycle_dir.mkdir(parents=True)
            original_path = r"C:\Users\alice\Desktop\SecretPlan.docx"
            deleted_at = datetime(2024, 5, 6, 7, 8, 9, tzinfo=timezone.utc)
            i_blob = (
                (2).to_bytes(8, "little")
                + (12345).to_bytes(8, "little")
                + datetime_to_filetime(deleted_at).to_bytes(8, "little")
                + len(original_path).to_bytes(4, "little")
                + original_path.encode("utf-16le")
            )
            (recycle_dir / "$IABC123").write_bytes(i_blob)
            (recycle_dir / "$RABC123").write_bytes(b"recovered document bytes")
            disguised = root / "Users" / "alice" / "Pictures" / "holiday.jpg"
            disguised.parent.mkdir(parents=True)
            disguised.write_bytes(b"MZ" + b"\x00" * 64 + b"hidden pe payload")
            host_doc = root / "Users" / "alice" / "Downloads" / "report.docx"
            host_doc.parent.mkdir(parents=True, exist_ok=True)
            host_doc.write_bytes(b"PK\x03\x04docx fixture")
            (host_doc.parent / "report.docx:Zone.Identifier").write_text(
                "[ZoneTransfer]\n"
                "ZoneId=3\n"
                "ReferrerUrl=https://referrer.example/download\n"
                "HostUrl=https://download.example/report.docx\n",
                encoding="utf-8",
            )
            (host_doc.parent / "report.docx:hidden.ps1:$DATA").write_text(
                "powershell -EncodedCommand SQBFAFgA",
                encoding="utf-8",
            )
            output = root / "filesystem.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "windows-filesystem", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            artifacts = payload["artifacts"]
            recycle = next(item for item in artifacts if item["artifact_type"] == "recycle-bin-entry")
            mismatch = next(item for item in artifacts if item["artifact_type"] == "file-signature-mismatch")
            ads_rows = [item for item in artifacts if item["artifact_type"] == "ads-stream-candidate"]
            ads_by_stream = {item["details"]["stream_name"]: item["details"] for item in ads_rows}

            self.assertEqual(recycle["details"]["original_path"], original_path)
            self.assertEqual(recycle["details"]["deleted_file_size"], 12345)
            self.assertEqual(recycle["details"]["deleted_at"], deleted_at.isoformat())
            self.assertEqual(recycle["details"]["coverage_status"], "i-r-pair-mapped")
            self.assertTrue(recycle["details"]["paired_payload_path"].endswith("$RABC123"))
            self.assertEqual(len(recycle["details"]["paired_payload_hashes"]["sha256"]), 64)
            self.assertEqual(mismatch["details"]["actual_extension"], ".jpg")
            self.assertEqual(mismatch["details"]["detected_signature_kind"], "windows-pe")
            self.assertIn("signature-extension-mismatch", mismatch["details"]["risk_flags"])
            self.assertIn("Zone.Identifier", ads_by_stream)
            self.assertIn("hidden.ps1", ads_by_stream)
            zone_ads = ads_by_stream["Zone.Identifier"]
            self.assertEqual(zone_ads["zone_id"], "3")
            self.assertEqual(zone_ads["host_url"], "https://download.example/report.docx")
            self.assertEqual(zone_ads["stream_family"], "download-provenance")
            self.assertTrue(zone_ads["host_file_present"])
            self.assertIn("ads-zone-identifier-download-provenance", zone_ads["risk_flags"])
            self.assertEqual(zone_ads["ads_review_profile"]["review_priority"], "review-download-provenance")
            script_ads = ads_by_stream["hidden.ps1"]
            self.assertEqual(script_ads["stream_type"], "$DATA")
            self.assertEqual(script_ads["stream_family"], "executable-or-script-stream")
            self.assertIn("ads-suspicious-stream-extension", script_ads["risk_flags"])
            self.assertIn("ads-script-payload-candidate", script_ads["risk_flags"])
            self.assertEqual(script_ads["source_locator"]["viewer"], "source-hex-range")
            self.assertIn("native-ntfs-ads-enumeration-required", script_ads["commercial_grade_blockers"])

    def test_windows_search_index_collector_imports_exports_and_inventories_edb(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            fixture = build_windows_artifact_fixture(root)
            output = root / "search-index.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "windows-search-index", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            artifacts = payload["artifacts"]
            entries = [item for item in artifacts if item["artifact_type"] == "windows-search-index-entry"]
            edb_files = [item for item in artifacts if item["artifact_type"] == "windows-search-edb-file"]
            edb_pivots = [item for item in artifacts if item["artifact_type"] == "windows-search-edb-pivot"]
            edb_page_candidates = [
                item for item in artifacts if item["artifact_type"] == "windows-search-edb-page-candidate"
            ]
            edb_table_candidates = [
                item for item in artifacts if item["artifact_type"] == "windows-search-edb-table-candidate"
            ]
            edb_row_candidates = [
                item for item in artifacts if item["artifact_type"] == "windows-search-edb-row-candidate"
            ]
            summary = next(item for item in artifacts if item["artifact_type"] == "windows-search-index-summary")

            self.assertEqual(entries[0]["details"]["entry_id"], "7")
            self.assertEqual(entries[0]["details"]["file_name"], "Incident Notes.docx")
            self.assertEqual(entries[0]["details"]["extension"], ".docx")
            self.assertIn("encoded powershell", entries[0]["details"]["content_snippet"])
            self.assertEqual(entries[0]["details"]["source_path"], str(fixture.windows_search_csv.resolve()))
            entry_manifest = entries[0]["details"]["windows_edb_report_citation_manifest"]
            self.assertEqual(entry_manifest["manifest_version"], "windows-edb-report-citation-manifest-v1")
            self.assertEqual(entry_manifest["row_identity"]["artifact_scope"], "source-tool-export")
            self.assertEqual(entry_manifest["reportability"]["allowed_use"], "search-index-triage-pivot")
            self.assertFalse(entry_manifest["reportability"]["standalone_decoded_row_fact"])
            self.assertIn("windows-edb-path-url-content", {row["kind"] for row in entry_manifest["citation_refs"]})
            entry_review_profile = entries[0]["details"]["windows_search_analyst_review_profile"]
            self.assertEqual(entry_review_profile["profile_version"], "windows-search-analyst-review-profile-v1")
            self.assertEqual(entry_review_profile["source_field_values"]["file_name"], "Incident Notes.docx")
            self.assertIn("MFT", entry_review_profile["correlation_targets"])
            self.assertEqual(edb_files[0]["details"]["source_path"], str(fixture.windows_edb.resolve()))
            self.assertTrue(edb_files[0]["details"]["ese_header"]["signature_valid"])
            self.assertIn("ese-string:powershell", edb_files[0]["details"]["risk_flags"])
            self.assertTrue(any("Incident Notes.docx" in value for value in edb_files[0]["details"]["path_candidates"]))
            self.assertTrue(
                any("encoded powershell investigation notes" in value for value in edb_files[0]["details"]["content_candidates"])
            )
            self.assertFalse(edb_files[0]["details"]["commercial_grade_ready"])
            self.assertIn("native-ese-catalog-decoding-required", edb_files[0]["details"]["commercial_grade_blockers"])
            self.assertIn("#11", edb_files[0]["details"]["search_index_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(edb_files[0]["details"]["forensic_review"]["gap_id"], "#11")
            edb_gate = edb_files[0]["details"]["core_accuracy_gates"][0]
            self.assertEqual(edb_gate["gap_id"], "#11")
            self.assertIn("catalog/table/page mapping", edb_gate["satisfied_checks"])
            self.assertIn("path/URL/content correlation", edb_gate["satisfied_checks"])
            self.assertIn("page-level source citation", edb_gate["satisfied_checks"])
            self.assertFalse(edb_files[0]["details"]["search_index_native_capabilities"]["native_row_level_decode"])
            self.assertTrue(edb_files[0]["details"]["search_index_native_capabilities"]["native_page_map_triage"])
            self.assertEqual(
                edb_files[0]["details"]["edb_analysis_method"]["method_id"],
                "ese-page-map-string-correlation-v1",
            )
            self.assertTrue(edb_files[0]["details"]["native_validation"]["page_map_built"])
            self.assertFalse(edb_files[0]["details"]["native_validation"]["row_level_decoding_available"])
            self.assertGreaterEqual(edb_files[0]["details"]["native_candidate_metadata"]["page_count_scanned"], 1)
            self.assertGreaterEqual(edb_files[0]["details"]["native_candidate_metadata"]["page_candidate_count"], 1)
            self.assertGreaterEqual(edb_files[0]["details"]["native_candidate_metadata"]["table_candidate_count"], 3)
            self.assertGreaterEqual(edb_files[0]["details"]["native_candidate_metadata"]["row_candidate_count"], 1)
            edb_manifest = edb_files[0]["details"]["windows_edb_report_citation_manifest"]
            self.assertEqual(edb_manifest["row_identity"]["artifact_scope"], "database")
            self.assertEqual(edb_manifest["qc_prep_item_number"], 26)
            self.assertIn("native Windows.edb ESE header and page-map triage", edb_manifest["qc_prep_contract"]["implemented"])
            self.assertFalse(edb_manifest["validation_summary"]["native_row_level_decode_available"])
            self.assertFalse(edb_manifest["validation_summary"]["native_deleted_state_decode_available"])
            self.assertIn(
                "windows-edb-native-row-decoder-validation-required",
                edb_manifest["reportability"]["blockers"],
            )
            edb_uplift = edb_files[0]["details"]["commercial_uplift_evidence"]
            self.assertEqual(edb_uplift["batch_id"], "commercial-uplift-011-015")
            self.assertEqual(edb_uplift["item_numbers"], [11])
            self.assertEqual(edb_uplift["qc_prep_item_numbers"], [26])
            self.assertEqual(
                edb_uplift["reportability_decision"]["decision"],
                "do-not-report-native-row-as-decoded-fact",
            )
            self.assertEqual(edb_uplift["reportability_decision"]["allowed_use"], "search-index-triage-pivot")
            self.assertIn("ese-signature-valid", edb_uplift["passed_validation_matrix_ids"])
            self.assertTrue(edb_uplift["large_data_controls"]["row_level_native_decode_required_for_commercial_claims"])
            edb_review_profile = edb_files[0]["details"]["windows_search_analyst_review_profile"]
            self.assertEqual(edb_review_profile["artifact_type"], "windows-search-edb-file")
            self.assertGreaterEqual(edb_review_profile["source_field_values"]["row_candidate_count"], 1)
            self.assertIn("decoded ESE row facts", edb_review_profile["not_proof_of"])
            self.assertIn("libesedb/esedbexport", edb_review_profile["correlation_targets"])
            self.assertIn("windows-edb-trusted-parser-diff-required", edb_review_profile["commercial_blockers"])
            self.assertEqual(
                edb_files[0]["details"]["native_validation"]["row_candidate_decode_status"],
                "correlated-native-string-candidates-only",
            )
            self.assertTrue(any(item["details"]["file_name"] == "Incident Notes.docx" for item in edb_pivots))
            self.assertTrue(any(item["details"]["url"] == "https://example.com/browser-history" for item in edb_pivots))
            self.assertTrue(any(item["details"]["candidate_kind"] == "content" for item in edb_pivots))
            self.assertTrue(all(item["details"]["validation_required"] for item in edb_pivots))
            self.assertTrue(all(not item["details"]["commercial_grade_ready"] for item in edb_pivots))
            self.assertTrue(edb_page_candidates)
            page_candidate = edb_page_candidates[0]
            self.assertEqual(page_candidate["details"]["candidate_basis"]["method_id"], "ese-page-map-string-correlation-v1")
            self.assertGreaterEqual(page_candidate["details"]["page_index"], 1)
            self.assertGreaterEqual(page_candidate["details"]["page_offset"], 8192)
            self.assertEqual(len(page_candidate["details"]["page_sha256"]), 64)
            self.assertTrue(page_candidate["details"]["path_candidates"])
            self.assertTrue(page_candidate["details"]["content_candidates"])
            self.assertIn("property-store", page_candidate["details"]["table_marker_hits"])
            self.assertFalse(page_candidate["details"]["commercial_grade_ready"])
            page_manifest = page_candidate["details"]["windows_edb_report_citation_manifest"]
            self.assertEqual(page_manifest["row_identity"]["artifact_scope"], "page-candidate")
            self.assertIn("windows-edb-page-locator", {row["kind"] for row in page_manifest["citation_refs"]})
            self.assertFalse(page_manifest["reportability"]["standalone_decoded_row_fact"])
            self.assertTrue(any(item["details"]["table_family"] == "property-store" for item in edb_table_candidates))
            self.assertTrue(any(item["details"]["table_family"] == "content-index" for item in edb_table_candidates))
            self.assertTrue(any(item["details"]["table_family"] == "deleted-state" for item in edb_table_candidates))
            self.assertTrue(all(not item["details"]["commercial_grade_ready"] for item in edb_table_candidates))
            self.assertTrue(
                all(not item["details"]["validation_checks"]["row_level_decoding_available"] for item in edb_table_candidates)
            )
            table_candidate = next(item for item in edb_table_candidates if item["details"]["table_family"] == "deleted-state")
            self.assertEqual(
                table_candidate["details"]["windows_edb_report_citation_manifest"]["row_identity"]["deleted_state"],
                "candidate-marker-present",
            )
            self.assertTrue(any(item["details"]["file_name"] == "Incident Notes.docx" for item in edb_row_candidates))
            row_candidate = next(item for item in edb_row_candidates if item["details"]["file_name"] == "Incident Notes.docx")
            self.assertEqual(row_candidate["details"]["item_path"], r"C:\Users\alice\Documents\Incident Notes.docx")
            self.assertIn("encoded powershell", row_candidate["details"]["content_snippet"])
            self.assertTrue(row_candidate["details"]["page_local_correlation"])
            self.assertGreaterEqual(row_candidate["details"]["page_offset"], 0)
            self.assertEqual(len(row_candidate["details"]["page_sha256"]), 64)
            self.assertTrue(row_candidate["details"]["field_presence_profile"]["item_path"])
            self.assertTrue(row_candidate["details"]["field_presence_profile"]["content_snippet"])
            self.assertEqual(row_candidate["details"]["deleted_state"], "candidate-marker-present")
            self.assertEqual(row_candidate["details"]["timestamp_source"], "not-decoded-native-edb")
            self.assertEqual(
                row_candidate["details"]["candidate_basis"]["correlation_method"],
                "page-local-path-url-content-correlation",
            )
            self.assertIn("search-index-suspicious-row-text", row_candidate["details"]["risk_flags"])
            self.assertTrue(row_candidate["details"]["validation_required"])
            self.assertFalse(row_candidate["details"]["commercial_grade_ready"])
            self.assertIn("#11", row_candidate["details"]["search_index_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(row_candidate["details"]["forensic_review"]["gap_id"], "#11")
            row_gate = row_candidate["details"]["core_accuracy_gates"][0]
            self.assertEqual(row_gate["gap_id"], "#11")
            self.assertIn("deleted/index-state validation", row_gate["satisfied_checks"])
            self.assertIn("field presence profile", row_gate["satisfied_checks"])
            self.assertIn("page-local table marker correlation", row_gate["satisfied_checks"])
            row_manifest = row_candidate["details"]["windows_edb_report_citation_manifest"]
            self.assertEqual(row_manifest["row_identity"]["artifact_scope"], "row-candidate")
            self.assertEqual(row_manifest["row_identity"]["deleted_state"], "candidate-marker-present")
            self.assertIn("windows-edb-row-cluster", {row["kind"] for row in row_manifest["citation_refs"]})
            self.assertEqual(len(row_manifest["manifest_sha256"]), 64)
            self.assertFalse(row_manifest["reportability"]["standalone_decoded_row_fact"])
            row_uplift = row_candidate["details"]["commercial_uplift_evidence"]
            self.assertIn("row-level-decoding-available", row_uplift["failed_validation_matrix_ids"])
            self.assertEqual(row_uplift["reportability_decision"]["allowed_use"], "search-index-triage-pivot")
            row_review_profile = row_candidate["details"]["windows_search_analyst_review_profile"]
            self.assertEqual(row_review_profile["severity"], "high")
            self.assertEqual(row_review_profile["source_field_values"]["file_name"], "Incident Notes.docx")
            self.assertEqual(row_review_profile["source_field_values"]["deleted_state"], "candidate-marker-present")
            self.assertIn("Document viewer", row_review_profile["correlation_targets"])
            self.assertIn("final deleted state", row_review_profile["not_proof_of"])
            self.assertEqual(summary["details"]["entry_count"], 1)
            self.assertEqual(summary["details"]["inventory_count"], 1)
            self.assertGreaterEqual(summary["details"]["edb_pivot_count"], 2)
            self.assertGreaterEqual(summary["details"]["edb_page_candidate_count"], 1)
            self.assertGreaterEqual(summary["details"]["edb_table_candidate_count"], 3)
            self.assertGreaterEqual(summary["details"]["edb_row_candidate_count"], 1)
            self.assertGreater(summary["details"]["edb_string_hit_count"], 0)
            self.assertIn({"value": ".docx", "count": 1}, summary["details"]["extension_counts"])
            self.assertIn({"value": "property-store", "count": 1}, summary["details"]["table_family_counts"])
            self.assertFalse(summary["details"]["commercial_grade_ready"])

    def test_windows_remote_access_collector_maps_rdp_config_cache_and_destinations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            fixture = build_windows_artifact_fixture(root)
            anydesk = root / "ProgramData" / "AnyDesk" / "service.trace"
            anydesk.parent.mkdir(parents=True, exist_ok=True)
            anydesk.write_text(
                "2026-05-14 10:15:20 AnyDesk session remote id 123 456 789 from 203.0.113.10 "
                "https://relay.anydesk.com file transfer upload SecretPlan.docx",
                encoding="utf-8",
            )
            teamviewer = root / "ProgramData" / "TeamViewer" / "Connections_incoming.txt"
            teamviewer.parent.mkdir(parents=True, exist_ok=True)
            teamviewer.write_text(
                "2026-05-14 10:18:44 TeamViewer incoming connection Partner ID: 222 333 444 "
                "from 198.51.100.20 transferred file Budget.xlsx",
                encoding="utf-8",
            )
            rustdesk = root / "Users" / "alice" / "AppData" / "Roaming" / "RustDesk" / "log" / "rustdesk.log"
            rustdesk.parent.mkdir(parents=True, exist_ok=True)
            rustdesk.write_text(
                "2026-05-14 10:20:00 RustDesk connected peer id 555666777 from 203.0.113.20",
                encoding="utf-8",
            )
            chrome_remote = (
                root
                / "Users"
                / "alice"
                / "AppData"
                / "Local"
                / "Google"
                / "Chrome Remote Desktop"
                / "chromoting.log"
            )
            chrome_remote.parent.mkdir(parents=True, exist_ok=True)
            chrome_remote.write_text(
                "2026-05-14 10:22:00 chromoting remoting_host session client id abc123xyz from 192.0.2.44",
                encoding="utf-8",
            )
            output = root / "remote-access.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "windows-remote-access", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            artifacts = payload["artifacts"]
            config = next(item for item in artifacts if item["artifact_type"] == "rdp-config")
            cache = next(item for item in artifacts if item["artifact_type"] == "rdp-cache-file")
            destinations = [item for item in artifacts if item["artifact_type"] == "rdp-destination"]
            remotes = [
                item for item in artifacts if item["artifact_type"] == "third-party-remote-control-artifact"
            ]
            remotes_by_product = {item["details"]["product"]: item for item in remotes}

            self.assertEqual(config["details"]["destination"], "10.0.0.50")
            self.assertEqual(config["details"]["username_hint"], r"CORP\alice")
            self.assertEqual(config["details"]["gateway_hostname"], "rd-gateway.example")
            self.assertEqual(config["details"]["source_path"], str(fixture.default_rdp.resolve()))
            self.assertEqual(cache["details"]["source_path"], str(fixture.rdp_cache_file.resolve()))
            self.assertEqual(cache["details"]["cache_parse_status"], "image-signature-pivots")
            self.assertEqual(cache["details"]["thumbnail_candidate_count"], 1)
            self.assertEqual(cache["details"]["thumbnail_candidates"][0]["type"], "png")
            self.assertEqual(cache["details"]["thumbnail_candidates"][0]["width"], 320)
            self.assertEqual(cache["details"]["thumbnail_candidates"][0]["height"], 200)
            self.assertTrue(any(item["details"]["destination"] == "10.0.0.50" for item in destinations))
            self.assertTrue(any(item["details"]["destination"] == "rdp-target.example" for item in destinations))
            self.assertEqual(
                set(remotes_by_product),
                {"anydesk", "teamviewer", "rustdesk", "chrome-remote-desktop"},
            )
            remote = remotes_by_product["anydesk"]
            self.assertEqual(remote["provider"], "windows-remote-access")
            self.assertEqual(remote["details"]["product"], "anydesk")
            self.assertEqual(remote["details"]["ip_candidates"], ["203.0.113.10"])
            self.assertIn("https://relay.anydesk.com", remote["details"]["url_candidates"])
            self.assertEqual(remote["details"]["coverage_status"], "remote-control-session-pivot-inventory")
            self.assertTrue(remote["details"]["remote_control_session_profile"]["session_candidates"])
            self.assertIn("123 456 789", remote["details"]["remote_id_candidates"])
            self.assertTrue(remote["details"]["file_transfer_indicators"])
            self.assertIn("remote-control:anydesk", remote["details"]["risk_flags"])
            self.assertIn("remote-control-file-transfer-candidate", remote["details"]["risk_flags"])
            self.assertEqual(
                remotes_by_product["teamviewer"]["details"]["ip_candidates"],
                ["198.51.100.20"],
            )
            self.assertIn(
                "222 333 444",
                remotes_by_product["teamviewer"]["details"]["remote_id_candidates"],
            )
            self.assertEqual(
                remotes_by_product["rustdesk"]["details"]["ip_candidates"],
                ["203.0.113.20"],
            )
            self.assertIn(
                "555666777",
                remotes_by_product["rustdesk"]["details"]["remote_id_candidates"],
            )
            self.assertEqual(
                remotes_by_product["chrome-remote-desktop"]["details"]["ip_candidates"],
                ["192.0.2.44"],
            )
            self.assertIn(
                "abc123xyz",
                remotes_by_product["chrome-remote-desktop"]["details"]["remote_id_candidates"],
            )

    def test_windows_system_collector_maps_print_spooler_and_remote_control_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            spool = root / "Windows" / "System32" / "spool" / "PRINTERS" / "00001.SHD"
            spool.parent.mkdir(parents=True)
            spool.write_bytes(
                "SecretPlan.docx\x00Office Printer\x00alice\x00C:\\Users\\alice\\SecretPlan.docx".encode("utf-16le")
            )
            spool.with_suffix(".SPL").write_bytes(b"\x1b%-12345X SecretPlan payload")
            anydesk = root / "ProgramData" / "AnyDesk" / "service.trace"
            anydesk.parent.mkdir(parents=True)
            anydesk.write_text(
                "2026-05-14 10:15:20 AnyDesk session remote id 123 456 789 from 203.0.113.10 "
                "https://relay.anydesk.com file transfer upload SecretPlan.docx",
                encoding="utf-8",
            )
            output = root / "windows-system.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "windows-system", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            artifacts = payload["artifacts"]
            spooler = next(item for item in artifacts if item["artifact_type"] == "print-spooler-job")
            remote = next(item for item in artifacts if item["artifact_type"] == "third-party-remote-control-artifact")

            self.assertEqual(spooler["details"]["spooler_file_kind"], "shd")
            self.assertEqual(spooler["details"]["coverage_status"], "spooler-metadata-pivot-inventory")
            self.assertIn(r"C:\Users\alice\SecretPlan.docx", spooler["details"]["path_candidates"])
            self.assertIn("SecretPlan.docx", spooler["details"]["document_name_candidates"])
            self.assertIn("Office Printer", spooler["details"]["printer_name_candidates"])
            self.assertIn("alice", spooler["details"]["user_name_candidates"])
            self.assertIn("possible-printed-document", spooler["details"]["risk_flags"])
            self.assertIn("printed-document-name-candidate", spooler["details"]["risk_flags"])
            self.assertEqual(
                spooler["details"]["print_spooler_companion_profile"]["pair_status"],
                "complete-shd-spl-pair",
            )
            self.assertIn("complete-shd-spl-pair", spooler["details"]["risk_flags"])
            self.assertEqual(remote["details"]["product"], "anydesk")
            self.assertEqual(remote["details"]["ip_candidates"], ["203.0.113.10"])
            self.assertIn("https://relay.anydesk.com", remote["details"]["url_candidates"])
            self.assertEqual(remote["details"]["coverage_status"], "remote-control-session-pivot-inventory")
            self.assertTrue(remote["details"]["session_candidates"])
            self.assertIn("123 456 789", remote["details"]["remote_id_candidates"])
            self.assertTrue(remote["details"]["file_transfer_indicators"])
            self.assertIn("remote-control:anydesk", remote["details"]["risk_flags"])
            self.assertIn("remote-control-file-transfer-candidate", remote["details"]["risk_flags"])

    def test_windows_system_collector_maps_defender_policy_tamper_exports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            policy = root / "Windows" / "System32" / "config" / "Windows Defender policy.reg"
            policy.parent.mkdir(parents=True, exist_ok=True)
            policy.write_text(
                """Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths]
"C:\\Temp"=dword:00000000

[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection]
"DisableRealtimeMonitoring"=dword:00000001

[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Features]
"TamperProtection"=dword:00000000
""",
                encoding="utf-16",
            )
            output = root / "windows-system.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "windows-system", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            artifact = next(item for item in payload["artifacts"] if item["artifact_type"] == "defender-policy-artifact")
            details = artifact["details"]
            profile = details["defender_policy_profile"]

            self.assertEqual(details["coverage_status"], "defender-policy-tamper-pivot")
            self.assertEqual(profile["profile_version"], "defender-policy-profile-v1")
            self.assertEqual(profile["policy_entry_count"], 3)
            self.assertTrue(details["exclusion_entries"])
            self.assertTrue(details["disabled_protection_entries"])
            self.assertTrue(details["tamper_entries"])
            self.assertIn("defender-exclusion-candidate", details["risk_flags"])
            self.assertIn("defender-protection-disabled-candidate", details["risk_flags"])
            self.assertIn("defender-tamper-setting-candidate", details["risk_flags"])
            self.assertIn("defender-event-policy-and-quarantine-correlation-required", details["commercial_grade_blockers"])

    def test_windows_system_collector_inventories_windows_recall_pivots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            recall_root = (
                root
                / "Users"
                / "alice"
                / "AppData"
                / "Local"
                / "CoreAIPlatform.00"
                / "UKP"
                / "S-1-5-21-1000"
            )
            recall_root.mkdir(parents=True)
            db_path = recall_root / "ukg.db"
            with contextlib.closing(sqlite3.connect(db_path)) as connection:
                connection.execute(
                    "CREATE TABLE WindowCaptureText (AppName TEXT, WindowTitle TEXT, OCRText TEXT, Timestamp INTEGER)"
                )
                connection.execute(
                    "INSERT INTO WindowCaptureText VALUES ('Edge', 'ChatGPT - Work', 'redacted prompt text', 133589952000000000)"
                )
                connection.commit()
            snapshot = recall_root / "ImageStore" / "frame_0001.jpg"
            snapshot.parent.mkdir(parents=True)
            snapshot.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 32 + b"\xff\xd9")
            output = root / "windows-system.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "windows-system", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            artifacts = payload["artifacts"]
            recall_db = next(item for item in artifacts if item["artifact_type"] == "windows-recall-database")
            recall_snapshot = next(
                item for item in artifacts if item["artifact_type"] == "windows-recall-snapshot-file"
            )

            self.assertEqual(recall_db["details"]["source_path"], str(db_path.resolve()))
            self.assertEqual(recall_db["details"]["sqlite_schema_inventory"]["open_status"], "opened")
            self.assertEqual(recall_db["details"]["sqlite_schema_inventory"]["total_row_count"], 1)
            self.assertEqual(
                recall_db["details"]["recall_evidence_profile"]["semantic_table_candidates"][0]["table"],
                "WindowCaptureText",
            )
            self.assertIn("recall-ocr-text-store-candidate", recall_db["details"]["risk_flags"])
            self.assertIn("recall-app-window-attribution-candidate", recall_db["details"]["risk_flags"])
            self.assertIn("legal_privacy_warning", recall_db["details"]["recall_evidence_profile"])
            self.assertFalse(recall_db["details"]["commercial_grade_ready"])
            self.assertEqual(recall_snapshot["details"]["source_path"], str(snapshot.resolve()))
            self.assertEqual(recall_snapshot["details"]["image_signature"]["format"], "jpeg")
            self.assertIn("windows-recall-snapshot-file", recall_snapshot["details"]["risk_flags"])

    def test_windows_system_collector_inventories_wmi_repository_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            fixture = build_windows_artifact_fixture(root)
            output = root / "windows-system.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "windows-system", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            wmi = [item for item in payload["artifacts"] if item["artifact_type"] == "wmi-repository-file"]

            self.assertTrue(wmi)
            self.assertEqual(wmi[0]["details"]["entry_name"], "OBJECTS.DATA")
            self.assertEqual(wmi[0]["details"]["source_path"], str(fixture.wmi_objects.resolve()))
            self.assertEqual(len(wmi[0]["details"]["source_hashes"]["sha256"]), 64)
            self.assertEqual(wmi[0]["details"]["coverage_status"], "bounded-string-pivot")
            self.assertIn("#18", wmi[0]["details"]["system_report_grade_assessment"]["commercial_gap_ids"])
            self.assertFalse(wmi[0]["details"]["system_native_capabilities"]["native_wmi_repository_decode"])
            wmi_gate = wmi[0]["details"]["core_accuracy_gates"][0]
            self.assertEqual(wmi_gate["gap_id"], "#18")
            self.assertIn("event semantics and risk rules", wmi_gate["satisfied_checks"])
            self.assertIn("WMI consumer/filter binding validation", wmi_gate["missing_required_checks"])
            wmi_uplift = wmi[0]["details"]["commercial_uplift_evidence"]
            self.assertEqual(wmi_uplift["batch_id"], "commercial-uplift-016-020")
            self.assertEqual(wmi_uplift["item_numbers"], [18])
            self.assertEqual(
                wmi_uplift["reportability_decision"]["allowed_use"],
                "windows-system-artifact-triage-pivot",
            )
            self.assertIn("wmi-source-parsed", wmi_uplift["passed_validation_matrix_ids"])
            self.assertTrue(wmi_uplift["large_data_controls"]["native_repository_or_rule_store_decode_required"])
            self.assertIn("wmi-string:commandlineeventconsumer", wmi[0]["details"]["risk_flags"])
            self.assertTrue(any("powershell.exe" in value.lower() for value in wmi[0]["details"]["path_candidates"]))
            self.assertIn("https://example.test/wmi-payload", wmi[0]["details"]["url_candidates"])
            wmi_manifest = wmi[0]["details"]["system_deep_parser_manifest"]
            self.assertEqual(wmi_manifest["manifest_version"], "windows-system-deep-parser-manifest-v1")
            self.assertEqual(wmi_manifest["gap_id"], "#18")
            self.assertEqual(wmi_manifest["artifact_family"], "wmi")
            self.assertEqual(wmi_manifest["normalized_semantics"]["entry_name"], "OBJECTS.DATA")
            self.assertFalse(wmi_manifest["native_depth"]["native_wmi_repository_decode"])
            self.assertIn("wmi-native-report-grade", wmi_manifest["validation"]["failed_validation_matrix_ids"])
            self.assertEqual(wmi[0]["details"]["system_deep_parser_manifest_hash"], wmi_manifest["manifest_sha256"])

    def test_windows_system_collector_flags_suspicious_scheduled_tasks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            fixture = build_windows_artifact_fixture(root)
            output = root / "windows-system.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "windows-system", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            task = next(item for item in payload["artifacts"] if item["artifact_type"] == "task-scheduler-task")

            self.assertEqual(task["details"]["source_path"], str(fixture.task_file.resolve()))
            self.assertEqual(task["details"]["task_uri"], r"\Microsoft\Windows\UpdateOrchestrator\SecurityUpdater")
            self.assertTrue(task["details"]["hidden"])
            self.assertEqual(task["details"]["coverage_status"], "task-xml-normalized")
            self.assertEqual(task["details"]["executable_name"], "powershell.exe")
            self.assertEqual(task["details"]["normalized_action"]["path_category"], "user-writable")
            self.assertEqual(task["details"]["trigger_details"][0]["trigger_type"], "LogonTrigger")
            self.assertEqual(task["details"]["trigger_details"][0]["start_boundary"], "2024-04-01T09:00:00")
            self.assertEqual(task["details"]["task_temporal_profile"]["start_boundaries"], ["2024-04-01T09:00:00"])
            self.assertIn("task_file_modified_at", task["details"]["task_temporal_profile"]["timestamp_sources"])
            self.assertTrue(task["details"]["validation_checks"]["has_exec_action"])
            self.assertTrue(task["details"]["validation_checks"]["has_task_temporal_metadata"])
            self.assertFalse(task["details"]["validation_checks"]["taskcache_registry_validated"])
            self.assertFalse(task["details"]["commercial_grade_ready"])
            self.assertIn("task-cache-registry-correlation-not-implemented", task["details"]["commercial_grade_blockers"])
            self.assertIn("#18", task["details"]["system_report_grade_assessment"]["commercial_gap_ids"])
            self.assertFalse(task["details"]["system_native_capabilities"]["taskcache_registry_correlation"])
            task_gate = task["details"]["core_accuracy_gates"][0]
            self.assertEqual(task_gate["gap_id"], "#18")
            self.assertIn("event semantics and risk rules", task_gate["satisfied_checks"])
            self.assertIn("task temporal metadata provenance", task_gate["satisfied_checks"])
            self.assertIn("Task XML/TaskCache correlation", task_gate["missing_required_checks"])
            task_uplift = task["details"]["commercial_uplift_evidence"]
            self.assertEqual(task_uplift["batch_id"], "commercial-uplift-016-020")
            self.assertEqual(task_uplift["item_numbers"], [18])
            self.assertEqual(
                task_uplift["reportability_decision"]["decision"],
                "do-not-report-system-artifact-as-fully-correlated",
            )
            self.assertIn("task-exec-action", task_uplift["passed_validation_matrix_ids"])
            self.assertIn("task-temporal-metadata", task_uplift["passed_validation_matrix_ids"])
            self.assertIn("task-report-grade-correlation", task_uplift["failed_validation_matrix_ids"])
            self.assertEqual(len(task["details"]["source_hashes"]["sha256"]), 64)
            self.assertIn("task-string:powershell", task["details"]["risk_flags"])
            self.assertIn("task-user-writable-path", task["details"]["risk_flags"])
            self.assertIn("task-microsoft-path-user-payload", task["details"]["risk_flags"])
            self.assertGreater(task["details"]["risk_score"], 0)
            task_manifest = task["details"]["system_deep_parser_manifest"]
            self.assertEqual(task_manifest["manifest_version"], "windows-system-deep-parser-manifest-v1")
            self.assertEqual(task_manifest["artifact_family"], "task-scheduler")
            self.assertEqual(task_manifest["normalized_semantics"]["executable_name"], "powershell.exe")
            self.assertTrue(task_manifest["native_depth"]["task_xml_normalization"])
            self.assertFalse(task_manifest["native_depth"]["taskcache_registry_correlation"])
            self.assertIn("task-report-grade-correlation", task_manifest["validation"]["failed_validation_matrix_ids"])
            self.assertEqual(task["details"]["system_deep_parser_manifest_hash"], task_manifest["manifest_sha256"])


def create_sqlite_fixture(path: Path, table: str, columns: list[str], values: tuple[str, ...] | None = None) -> None:
    connection = sqlite3.connect(path)
    try:
        quoted_columns = ", ".join(f'"{column}" TEXT' for column in columns)
        connection.execute(f'CREATE TABLE "{table}" ({quoted_columns})')
        placeholders = ", ".join("?" for _ in columns)
        connection.execute(f'INSERT INTO "{table}" VALUES ({placeholders})', values or tuple(f"{column}-value" for column in columns))
        connection.commit()
    finally:
        connection.close()


if __name__ == "__main__":
    unittest.main()
