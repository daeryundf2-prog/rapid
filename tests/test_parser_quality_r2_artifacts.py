"""Parser-quality round 2 (artifact providers): each test fails on the pre-r2 code.

Synthetic fixtures only (no evidence): memory dump strings, regf hives built with the
``tests.test_parser_quality_registry`` writer, LNK/IDList bytes, EVTX triage projections,
browser autofill/extension stores, a minimal HEIC container and a notification SQLite DB.
"""

from __future__ import annotations

import json
import math
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from rapidtriage.artifacts import kakaotalk_windows as kakao
from rapidtriage.artifacts import media, memory
from rapidtriage.artifacts.windows import browser, eventlog, recent_files, system
from rapidtriage.artifacts.windows.execution import build_native_amcache_records
from rapidtriage.artifacts.windows.registry import WindowsRegistryProvider
from rapidtriage.core.models import ArtifactRecord
from tests.test_parser_quality_registry import (
    REG_BINARY,
    REG_SZ,
    HiveWriter,
    Key,
    shell_directory,
    shell_root,
    shell_volume,
    sz,
    write_hive,
)

MY_COMPUTER = "20d04fe0-3aea-1069-a2d8-08002b30309d"


class MemoryIndicatorTests(unittest.TestCase):
    def test_environment_entry_with_header_byte_is_not_an_ioc(self) -> None:
        text = "\x00\x00\x8cComSpec=C:\\WINDOWS\\system32\\cmd.exe\x00"
        self.assertTrue(memory.is_environment_block_value(text, text.index("cmd.exe")))
        data = b"\x00" * 32 + b"\x84\x00B\x00\x8cComSpec=C:\\WINDOWS\\system32\\cmd.exe\x00\x00" + b"\x00" * 32
        pivots: list[dict[str, object]] = []
        memory.collect_memory_pivots(data, 0, pivots, set())
        memory.collect_memory_process_candidates(data, 0, pivots, set())
        self.assertFalse([pivot for pivot in pivots if "cmd.exe" in json.dumps(pivot.get("value"))])

    def test_ansi_header_byte_does_not_fuse_into_a_cp949_syllable(self) -> None:
        decoded = memory.decode_ansi_memory_text(b"\x8cComSpec=C:\\WINDOWS\x00")
        self.assertIn("ComSpec=C:\\WINDOWS", decoded)
        self.assertNotIn("\ub602", decoded)  # "똂"

    def test_utf16_offsets_are_byte_exact_after_lone_surrogates(self) -> None:
        prefix = b"\x00\xd8" * 3 + b" \x00"  # three lone high surrogates, then a space
        value = "COMPUTERNAME=PC1\x00".encode("utf-16le")
        data = prefix + value + b"\x00" * 8
        pivots: list[dict[str, object]] = []
        memory.collect_utf16_memory_pivots(data, 4096, pivots, set())
        env = [pivot for pivot in pivots if pivot["type"] == "environment-variable"]
        self.assertEqual(len(env), 1)
        self.assertEqual(env[0]["offset"], 4096 + len(prefix))

    def test_suspicious_term_offset_survives_length_changing_lowercase(self) -> None:
        # "İ".lower() is two characters: an index found on text.lower() would drift.
        text = "\u0130" * 10 + " mimikatz "
        data = text.encode("utf-16le")
        pivots: list[dict[str, object]] = []
        memory.collect_utf16_memory_pivots(data, 0, pivots, set())
        hit = next(pivot for pivot in pivots if pivot.get("value") == "mimikatz")
        self.assertEqual(hit["offset"], data.index("mimikatz".encode("utf-16le")))

    def test_version_strings_are_not_ip_indicators(self) -> None:
        for value in ("2.25.0.24", "2.24.0.31", "2.0.0.0"):
            self.assertEqual(memory.ipv4_indicator_strength(value, "\x00", "\x00"), "", value)
        self.assertEqual(memory.ipv4_indicator_strength("1.2.3.4", " ", " ", context="ProductVersion "), "")
        self.assertEqual(memory.ipv4_indicator_strength("192.168.0.100", " ", " "), "triage")
        data = b"\x00\x00\x00\x002.25.0.24\x00\x00\x00 SeqList[0] 2.0.0.0?k"
        pivots: list[dict[str, object]] = []
        memory.collect_memory_pivots(data, 0, pivots, set())
        self.assertFalse([pivot for pivot in pivots if pivot["type"] == "ip"])

    def test_minidump_stream_type_names(self) -> None:
        names = memory.MINIDUMP_STREAM_NAMES
        self.assertEqual(names[12], "HandleData")
        self.assertEqual(names[13], "FunctionTable")
        self.assertEqual(names[14], "UnloadedModuleList")
        self.assertEqual(names[19], "Token")
        self.assertEqual(names[24], "ThreadNames")


def usb_system_hive() -> bytes:
    root = Key("ROOT")
    root.path("Select").value("Current", 4, (1).to_bytes(4, "little"))
    enum = "ControlSet001\\Enum"
    # 1) OS-generated serial: joined through the USB instance's ParentIdPrefix.
    flash = root.path(f"{enum}\\USB\\VID_090C&PID_1000\\6&2b51a475&0&1")
    flash.value("ParentIdPrefix", REG_SZ, sz("7&2502771e&0")).value("Service", REG_SZ, sz("USBSTOR"))
    flash.value("ContainerID", REG_SZ, sz("{edc52298-33e1-11f0-90ec-8cb0e992a14a}"))
    root.path(f"{enum}\\USBSTOR\\Disk&Ven_USB&Prod_Flash_Disk&Rev_1100\\7&2502771e&0").value(
        "ContainerID", REG_SZ, sz("{edc52298-33e1-11f0-90ec-8cb0e992a14a}")
    )
    # 2) USBSTOR clips a long serial: joined by prefix.
    long_serial = "0101998493edc5f87f4295b74595152d37d4a6f9bbf9019204f615b8588f1430e8c6000000000000"
    root.path(f"{enum}\\USB\\VID_0781&PID_55A3\\{long_serial}").value("Service", REG_SZ, sz("USBSTOR"))
    root.path(f"{enum}\\USBSTOR\\Disk&Ven__USB&Prod__SanDisk_3.2Gen1&Rev_1.00\\{long_serial[:63]}&0")
    # 3) Different serial spelling, same ContainerID.
    root.path(f"{enum}\\USB\\VID_0781&PID_5591\\AA11BB22").value("Service", REG_SZ, sz("USBSTOR")).value(
        "ContainerID", REG_SZ, sz("{3b4274ad-4fe5-551e-85fb-fdcb2f0172db}")
    )
    root.path(f"{enum}\\USBSTOR\\Disk&Ven_SanDisk&Prod_X&Rev_1\\ZZ99&0").value(
        "ContainerID", REG_SZ, sz("{3b4274ad-4fe5-551e-85fb-fdcb2f0172db}")
    )
    return HiveWriter().build(root)


class UsbJoinTests(unittest.TestCase):
    def test_usbstor_joins_by_parent_id_prefix_serial_prefix_and_container_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_hive(root, "Windows/System32/config/SYSTEM", usb_system_hive())
            usb = {
                record.details["serial_number"][:8]: record.details
                for record in WindowsRegistryProvider().collect(root)
                if record.artifact_type == "windows-usb-device"
            }
        self.assertEqual((usb["7&250277"]["vid"], usb["7&250277"]["pid"]), ("090C", "1000"))
        self.assertEqual(usb["7&250277"]["usb_join_method"], "parent-id-prefix")
        self.assertEqual((usb["01019984"]["vid"], usb["01019984"]["pid"]), ("0781", "55A3"))
        self.assertEqual(usb["01019984"]["usb_join_method"], "serial-prefix")
        self.assertEqual((usb["ZZ99&0"]["vid"], usb["ZZ99&0"]["pid"]), ("0781", "5591"))
        self.assertEqual(usb["ZZ99&0"]["usb_join_method"], "container-id")


def amcache_hive() -> bytes:
    root = Key("{11517B7C-E79D-4e20-961B-75A811715ADD}")
    inventory = root.path("Root")
    inventory.path("InventoryApplicationFile\\evil.exe|0000").value("LowerCaseLongPath", REG_SZ, sz("c:\\evil.exe"))
    inventory.path("InventoryDriverBinary\\c:/windows/system32/drivers/x.sys").value(
        "DriverName", REG_SZ, sz("x.sys")
    ).value("DriverTimeStamp", REG_SZ, sz("1690268978")).value("DriverLastWriteTime", REG_SZ, sz("07/25/2023 08:28:00"))
    inventory.path("InventoryDevicePnp\\usb/vid_090c&pid_1000/x").value("Model", REG_SZ, sz("USB Flash Disk")).value(
        "FirstInstallDate", REG_SZ, sz("02-23-2025")
    )
    inventory.path("InventoryApplicationShortcut\\access.lnk|1").value(
        "ShortcutPath", REG_SZ, sz("C:\\ProgramData\\Access.lnk")
    ).value("ShortcutTargetPath", REG_SZ, sz("C:\\Office\\MSACCESS.EXE"))
    census = inventory.path("DeviceCensus")
    census.value("lastFullSync", REG_SZ, sz("133923443475884436"))
    census.path("OS").value("OSEdition", REG_SZ, sz("Core")).value("OA3xOriginalProductKey", REG_SZ, sz("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE"))
    inventory.path("InventoryDevicePci").value("WritePermissionsCheck", REG_SZ, sz("1"))
    return HiveWriter().build(root)


class AmcacheInventoryTests(unittest.TestCase):
    def test_extended_inventories_are_rows_with_labelled_timestamps(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_hive(Path(tmp), "Windows/appcompat/Programs/Amcache.hve", amcache_hive())
            records = list(build_native_amcache_records(path))
        by_type: dict[str, list[ArtifactRecord]] = {}
        for record in records:
            by_type.setdefault(record.artifact_type, []).append(record)
        self.assertEqual(len(by_type["amcache-schema-row"]), 1)
        driver = by_type["amcache-driver-binary"][0].details
        self.assertEqual(driver["driver_name"], "x.sys")
        self.assertEqual(driver["driver_link_time"], "2023-07-25T07:09:38+00:00")
        self.assertEqual(driver["timestamp_label"], "last_written")
        self.assertTrue(driver["timestamp"])
        pnp = by_type["amcache-device-pnp"][0].details
        self.assertEqual(pnp["first_install_date"], "2025-02-23")
        shortcut = by_type["amcache-application-shortcut"][0].details
        self.assertEqual(shortcut["shortcut_target_path"], "C:\\Office\\MSACCESS.EXE")
        census = {record.details["census_category"]: record.details for record in by_type["amcache-device-census"]}
        self.assertEqual(census["(root)"]["last_full_sync_at"], "2025-05-21T23:39:07.5884436+00:00")
        self.assertNotIn("BBBBB", json.dumps(census["OS"]["decoded_values"]))
        self.assertNotIn("amcache-inventory-row", by_type)  # empty provider-version keys are skipped


def lnk_with_id_list(items: list[bytes], tail: bytes = b"") -> bytes:
    id_list = b"".join(items) + b"\x00\x00"
    header = bytearray(recent_files.LNK_HEADER_SIZE)
    header[0:4] = b"\x4c\x00\x00\x00"
    header[4:20] = recent_files.LNK_CLSID
    header[0x14:0x18] = (0x01 | 0x10 | 0x80).to_bytes(4, "little")  # IDList, WorkingDir, Unicode
    working_dir = "D:\\YSR2000\\exe\\"
    strings = len(working_dir).to_bytes(2, "little") + working_dir.encode("utf-16le")
    return bytes(header) + len(id_list).to_bytes(2, "little") + id_list + strings + tail


class LnkTests(unittest.TestCase):
    def test_tracker_machine_id_is_decoded_as_cp949(self) -> None:
        block = bytearray(0x60)
        block[0x10 : 0x10 + 7] = "진료실1".encode("cp949")
        tracker = recent_files.parse_lnk_tracker_data_block(bytes(block))
        self.assertEqual(tracker["machine_id"], "진료실1")
        self.assertEqual(tracker["machine_id_encoding"], "cp949")

    def test_embedded_path_scan_stops_at_control_characters(self) -> None:
        data = "D:\\YSR2000\\exe\\\x1aD:\\YSR2000\\Exe\\YSR2012.exe\x00".encode("utf-16le")
        data += b"\x00\x00C:\\Tools\\a.exe\x1aC:\\b.exe\x00"
        paths = recent_files.extract_windows_paths(data)
        self.assertTrue(paths)
        self.assertFalse([path for path in paths if any(ord(ch) < 0x20 for ch in path)])
        self.assertIn("D:\\YSR2000\\Exe\\YSR2012.exe", paths)

    def test_target_is_rebuilt_from_the_id_list_without_link_info(self) -> None:
        moment = datetime(2024, 1, 2, 3, 4, 6, tzinfo=timezone.utc)
        items = [
            shell_root(MY_COMPUTER),
            shell_volume("D"),
            shell_directory("YSR2000", modified=moment, created=moment, accessed=moment),
            shell_directory("YSR2012.exe", modified=moment, created=moment, accessed=moment),
        ]
        details = recent_files.parse_lnk_metadata_from_bytes(lnk_with_id_list(items))
        self.assertEqual(details["target_path"], "D:\\YSR2000\\YSR2012.exe")
        self.assertEqual(details["target_path_source"], "link-target-id-list")


class KakaoRegistryNoiseTests(unittest.TestCase):
    def test_bare_deviceinfo_is_not_a_kakao_term(self) -> None:
        self.assertEqual(kakao.matched_kakao_terms("SetupDiEnumDeviceInfo"), [])
        self.assertTrue(kakao.matched_kakao_terms("Software\\Kakao\\KakaoTalk\\DeviceInfo"))

    def test_binary_value_noise_is_not_decoded_as_text(self) -> None:
        noise = b"\x01\x02" + b"Um%" + "情".encode("cp949") + b"\x00\x00\x07" + "絶".encode("cp949") + b"YTGdYTGd\x00\x00"
        text = "KakaoTalk".encode("utf-16le") + b"\x00\x00"
        strings = [value for value, _encoding in kakao.decode_registry_value_strings(REG_BINARY, noise + text)]
        self.assertIn("KakaoTalk", strings)
        self.assertFalse([value for value in strings if "情" in value or "絶" in value])

    def test_kakaotalk_deviceinfo_key_is_still_a_candidate(self) -> None:
        root = Key("ROOT")
        root.path("Software\\Kakao\\KakaoTalk\\DeviceInfo\\20250101").value("hdd_model", REG_SZ, sz("X"))
        with tempfile.TemporaryDirectory() as tmp:
            path = write_hive(Path(tmp), "Users/u/NTUSER.DAT", HiveWriter().build(root))
            records = kakao.collect_native_hive_kakao_traces(path, {}) or []
        values = [str(record.details.get("candidate_value") or "") for record in records]
        self.assertTrue([value for value in values if value.lower().endswith("kakaotalk\\deviceinfo")])
        self.assertFalse([value for value in values if "setupdi" in value.lower()])


def native_details(event_data: dict[str, object], **extra: object) -> dict[str, object]:
    return {
        "parser": "windows-eventlog-evtx-native",
        "event_id": "4104",
        "binxml_event_data_fields": event_data,
        **extra,
    }


class EventlogTriageTests(unittest.TestCase):
    def test_script_block_text_is_kept_in_full_up_to_the_payload_cap(self) -> None:
        script = "Write-Host 'x'\n" * 1300  # ~19.5k chars, like the longest real 4104 block
        slim = eventlog.triage_eventlog_details(native_details({"ScriptBlockText": script, "Path": "p" * 600}))
        self.assertEqual(slim["event_data"]["ScriptBlockText"], script)
        self.assertEqual(slim["event_data_truncated_fields"], ["Path"])
        huge = "A" * (eventlog.EVENTLOG_TRIAGE_PAYLOAD_MAX_CHARS + 10)
        slim = eventlog.triage_eventlog_details(native_details({"ScriptBlockText": huge}))
        self.assertEqual(len(slim["event_data"]["ScriptBlockText"]), eventlog.EVENTLOG_TRIAGE_PAYLOAD_MAX_CHARS)
        self.assertEqual(slim["event_data_truncated_fields"], ["ScriptBlockText"])

    def test_command_line_is_not_cut_at_512_and_cuts_are_flagged(self) -> None:
        command = "cmd.exe /c " + "x" * 2000
        slim = eventlog.triage_eventlog_details(native_details({}, command_line=command, raw_preview=""))
        self.assertEqual(slim["command_line"], command)
        self.assertNotIn("command_line_truncated", slim)
        huge = "y" * (eventlog.EVENTLOG_TRIAGE_PAYLOAD_MAX_CHARS + 1)
        slim = eventlog.triage_eventlog_details(native_details({}, command_line=huge, raw_preview=""))
        self.assertTrue(slim["command_line_truncated"])

    def test_truncation_counts_reach_the_file_row_and_summary(self) -> None:
        counter: eventlog.Counter[str] = eventlog.Counter()
        eventlog.count_triage_truncation(counter, {"event_message_truncated": True})
        eventlog.count_triage_truncation(
            counter, {"event_data_truncated": True, "event_data_truncated_fields": ["ScriptBlockText"]}
        )
        eventlog.count_triage_truncation(counter, {"event_id": "1"})
        fields = eventlog.triage_truncation_fields(counter)
        self.assertEqual(fields["text_truncated_rows"], 2)
        self.assertEqual(fields["payload_truncated_rows"], 1)
        accumulator = eventlog.EventlogSummaryAccumulator()
        accumulator.add(
            ArtifactRecord(
                provider="windows-eventlog",
                artifact_type="eventlog-file",
                path="C:\\x\\Security.evtx",
                supported=True,
                details={"source_path": "C:\\x\\Security.evtx", "stale_below_first_record_count": 39, **fields},
            )
        )
        summary = accumulator.build(Path(".")).details
        self.assertEqual(summary["text_truncated_rows"], 2)
        self.assertEqual(summary["payload_truncated_rows"], 1)
        self.assertEqual(summary["stale_below_first_record_count"], 39)
        self.assertEqual(summary["text_truncated_files"][0]["text_truncated_rows"], 2)

    def test_stale_records_below_the_first_live_id_are_labelled(self) -> None:
        self.assertEqual(eventlog.evtx_record_id_position(639703, 639742, 673724), "stale-below-first")
        self.assertEqual(eventlog.evtx_record_id_position(650000, 639742, 673724), "within-live-range")
        self.assertEqual(eventlog.evtx_record_id_position(5, 0, 0), "no-live-records")
        self.assertIn("evtx_record_id_position", eventlog.EVENTLOG_TRIAGE_IDENTITY_KEYS)

    def test_binary_junk_event_data_keys_become_data_n(self) -> None:
        parts = eventlog.native_evtx_decoded_parts(
            {
                "event_data": {"Error Code": "0x0", "ageIdentifier\x00\u0d02junk": "x", "\x01\x00\x00\x00v": "y"},
                "event_data_sequence": [{"name": "ageIdentifier\x00\u0d02junk", "value": "x"}],
            },
            render_xml=False,
        )
        fields = parts["promoted"]["event_data_fields"]
        self.assertEqual(list(fields), ["Error Code", "data_1", "data_2"])
        self.assertEqual(parts["promoted"]["event_data_invalid_keys"], ["data_1", "data_2"])
        self.assertEqual(parts["promoted"]["event_data_sequence"][0]["name"], "data_1")

    def test_local_session_manager_is_not_remote_access(self) -> None:
        channel = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
        self.assertEqual(eventlog.channel_family(channel), "session")
        self.assertEqual(eventlog.inferred_event_family("event", "session"), "session")
        self.assertEqual(
            eventlog.channel_family("Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"),
            "remote-access",
        )


class BrowserTests(unittest.TestCase):
    def test_personal_autofill_fields_and_values_are_masked(self) -> None:
        for name, value in (
            ("edtPtntRrn1", "900101"),
            ("phone2", "1234"),
            ("우편번호", "06236"),
            ("이름", "홍길동"),
            ("접종자명", "홍길동"),
            ("edtMtno1", "010"),
            ("comment", "010-1234-5678"),
            ("memo", "900101-1234567"),
            ("x", "someone@example.com"),
        ):
            result = browser.browser_pii_value(name, value)
            self.assertTrue(result["value_masked"], name)
            self.assertEqual(result["value_preview"], "[마스킹됨]")
            self.assertTrue(result["value_sha256"])
        kept = browser.browser_pii_value("검색어", "날씨")
        self.assertFalse(kept["value_masked"])
        self.assertEqual(kept["value_preview"], "날씨")

    def test_preferences_manifest_is_used_when_secure_preferences_holds_a_stub(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            profile = Path(tmp)
            stub = {"extensions": {"settings": {"abcdefghijklmnopabcdefghijklmnop": {"state": 1, "active_bit": True}}}}
            full = {
                "extensions": {
                    "settings": {
                        "abcdefghijklmnopabcdefghijklmnop": {"manifest": {"name": "Helper", "version": "1.2.3"}, "state": 1}
                    }
                }
            }
            (profile / "Secure Preferences").write_text(json.dumps(stub), encoding="utf-8")
            (profile / "Preferences").write_text(json.dumps(full), encoding="utf-8")
            context = browser.BrowserRowContext(provider="windows-browser", user="u", browser="edge", profile="Default")
            rows = browser.chromium_extension_rows(context, profile, [])
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0].details["name"], rows[0].details["version"]), ("Helper", "1.2.3"))
        self.assertEqual(rows[0].details["name_source"], "preferences-embedded-manifest")


def bmff_box(kind: bytes, payload: bytes) -> bytes:
    return (8 + len(payload)).to_bytes(4, "big") + kind + payload


def ispe(width: int, height: int) -> bytes:
    return bmff_box(b"ispe", b"\x00\x00\x00\x00" + width.to_bytes(4, "big") + height.to_bytes(4, "big"))


class MediaAndNotificationTests(unittest.TestCase):
    def test_heic_dimensions_come_from_ispe(self) -> None:
        ftyp = bmff_box(b"ftyp", b"heic" + b"\x00\x00\x00\x00" + b"mif1heic")
        ipco = bmff_box(b"ipco", ispe(512, 512) + ispe(4032, 3024) + ispe(320, 240))
        meta = bmff_box(b"meta", b"\x00\x00\x00\x00" + bmff_box(b"iprp", ipco))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "photo.heic"
            path.write_bytes(ftyp + meta + bmff_box(b"mdat", b"\x00" * 64))
            record = media.build_image_record(path)
        self.assertEqual((record.details["width"], record.details["height"]), (4032, 3024))
        self.assertEqual(record.details["dimension_source"], "heif-ispe")
        self.assertEqual(record.details["coverage_status"], "container-metadata-only")

    def test_counter_entropy_matches_the_former_per_byte_loop(self) -> None:
        def reference(blob: bytes) -> float:  # pre-r2 implementation
            if not blob:
                return 0.0
            counts = [0] * 256
            for byte in blob:
                counts[byte] += 1
            length = len(blob)
            return round(-sum((count / length) * math.log2(count / length) for count in counts if count), 4)

        random = bytes((index * 2654435761 >> 7) & 0xFF for index in range(300_000))
        jpeg_like = b"\xff\xd8\xff\xe0" + bytes(range(256)) * 40 + b"\x00" * 5000 + b"\xff\xd9"
        for blob in (b"", b"\x00" * 1000, b"ab", "진료실1 KakaoTalk".encode() * 99, random, jpeg_like, bytes(range(256))):
            self.assertAlmostEqual(media.shannon_entropy(blob), reference(blob), delta=1e-9)

    def test_notification_event_time_is_arrival_not_expiry(self) -> None:
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        connection.execute("CREATE TABLE Notification (Id INTEGER, Payload TEXT, ExpiryTime INTEGER, ArrivalTime INTEGER)")
        arrival = 133923443475884436  # 2025-05-21 FILETIME
        expiry = arrival + 3 * 86400 * 10_000_000
        connection.execute("INSERT INTO Notification VALUES (1, '<toast/>', ?, ?)", (expiry, arrival))
        columns = ["Id", "Payload", "ExpiryTime", "ArrivalTime"]
        sample = system.sqlite_normalized_timeline_samples(connection, "Notification", columns)[0]
        self.assertEqual(sample["time_column"], "ArrivalTime")
        self.assertTrue(str(sample["normalized_time"]).startswith("2025-05-21"))
        self.assertIn("ExpiryTime", sample["secondary_times"])
        self.assertEqual(sample["secondary_times"]["ExpiryTime"]["label"], "expiry")


if __name__ == "__main__":
    unittest.main()
