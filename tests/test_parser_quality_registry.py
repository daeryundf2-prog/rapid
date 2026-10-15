"""Parser-quality round 1, W2: registry, SAM accounts, ShellBags, execution.

Every hive here is synthesized in-test by a minimal regf writer (base block,
one hbin, nk/vk/lf/li/ri/db cells) so the ground-truth numbers from the
real-data review can be reproduced without shipping evidence files.
"""

from __future__ import annotations

import tempfile
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path

from rapidtriage.artifacts.windows.execution import WindowsExecutionProvider
from rapidtriage.artifacts.windows.os_account import WindowsOsAccountProvider
from rapidtriage.artifacts.windows.registry import (
    NativeRegistryHive,
    RegistryCollectionContext,
    WindowsRegistryProvider,
    collect_registry_hive,
    filetime_to_iso_ticks,
    parse_registry_nk_cell,
)
from rapidtriage.artifacts.windows.shellbags import (
    WindowsShellbagsProvider,
    collect_native_shellbag_hive,
    decode_shell_item_entry,
)

REG_SZ = 1
REG_BINARY = 3
REG_DWORD = 4
REG_MULTI_SZ = 7
REG_QWORD = 11
BIG_DATA_SEGMENT = 16344
EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)


def filetime(moment: datetime, extra_ticks: int = 0) -> int:
    delta = moment - EPOCH_1601
    return (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10 + extra_ticks


def sz(text: str) -> bytes:
    return text.encode("utf-16-le") + b"\x00\x00"


def dword(value: int) -> bytes:
    return (value & 0xFFFFFFFF).to_bytes(4, "little")


class Key:
    def __init__(self, name: str, *, stamp: int = 0, compressed: bool | None = None) -> None:
        self.name = name
        self.stamp = stamp or filetime(datetime(2025, 5, 30, 3, 27, 49, tzinfo=timezone.utc))
        self.compressed = compressed
        self.values: list[tuple[str, int, bytes]] = []
        self.children: list[Key] = []

    def key(self, name: str, **kwargs: object) -> Key:
        child = Key(name, **kwargs)  # type: ignore[arg-type]
        self.children.append(child)
        return child

    def path(self, relative: str, **kwargs: object) -> Key:
        node = self
        for part in relative.split("\\"):
            match = next((child for child in node.children if child.name == part), None)
            node = match if match is not None else node.key(part, **kwargs)
        return node

    def value(self, name: str, value_type: int, data: bytes) -> Key:
        self.values.append((name, value_type, data))
        return self


class HiveWriter:
    """Minimal regf writer: everything lives in one (possibly large) hbin."""

    def __init__(self, *, minor_version: int = 5, ri_threshold: int = 0) -> None:
        self.cells = bytearray()
        self.minor_version = minor_version
        self.ri_threshold = ri_threshold

    def alloc(self, payload: bytes, *, free: bool = False) -> int:
        size = 4 + len(payload)
        size += (-size) % 8
        offset = 32 + len(self.cells)
        raw = size if free else -size
        self.cells += raw.to_bytes(4, "little", signed=True) + payload + b"\x00" * (size - 4 - len(payload))
        return offset

    def patch_u32(self, cell_offset: int, field: int, value: int) -> None:
        position = cell_offset - 32 + 4 + field
        self.cells[position : position + 4] = value.to_bytes(4, "little")

    @staticmethod
    def encode_name(name: str, compressed: bool | None) -> tuple[bytes, bool]:
        if compressed is None:
            try:
                return name.encode("ascii"), True
            except UnicodeEncodeError:
                return name.encode("utf-16-le"), False
        return (name.encode("latin-1"), True) if compressed else (name.encode("utf-16-le"), False)

    def nk_payload(self, key: Key, *, root: bool) -> bytes:
        raw_name, compressed = self.encode_name(key.name, key.compressed)
        body = bytearray(0x4C + len(raw_name))
        body[0:2] = b"nk"
        flags = (0x0020 if compressed else 0) | (0x0004 | 0x0008 if root else 0)
        body[2:4] = flags.to_bytes(2, "little")
        body[4:12] = key.stamp.to_bytes(8, "little")
        body[0x1C:0x20] = (0xFFFFFFFF).to_bytes(4, "little")
        body[0x20:0x24] = (0xFFFFFFFF).to_bytes(4, "little")
        body[0x28:0x2C] = (0xFFFFFFFF).to_bytes(4, "little")
        body[0x48:0x4A] = len(raw_name).to_bytes(2, "little")
        body[0x4C:] = raw_name
        return bytes(body)

    def write_value(self, name: str, value_type: int, data: bytes) -> int:
        raw_name, compressed = self.encode_name(name, None)
        if len(data) <= 4:
            size_field = 0x80000000 | len(data)
            data_field = int.from_bytes(data.ljust(4, b"\x00"), "little")
        elif len(data) > BIG_DATA_SEGMENT and self.minor_version >= 4:
            segments = [
                self.alloc(data[index : index + BIG_DATA_SEGMENT]) for index in range(0, len(data), BIG_DATA_SEGMENT)
            ]
            segment_list = self.alloc(b"".join(offset.to_bytes(4, "little") for offset in segments))
            db = b"db" + len(segments).to_bytes(2, "little") + segment_list.to_bytes(4, "little") + b"\x00" * 4
            size_field, data_field = len(data), self.alloc(db)
        else:
            size_field, data_field = len(data), self.alloc(data)
        body = bytearray(20 + len(raw_name))
        body[0:2] = b"vk"
        body[2:4] = len(raw_name).to_bytes(2, "little")
        body[4:8] = size_field.to_bytes(4, "little")
        body[8:12] = data_field.to_bytes(4, "little")
        body[12:16] = value_type.to_bytes(4, "little")
        body[16:18] = (1 if compressed and raw_name else 0).to_bytes(2, "little")
        body[20:] = raw_name
        return self.alloc(bytes(body))

    def subkey_list(self, offsets: list[int]) -> int:
        if self.ri_threshold and len(offsets) > self.ri_threshold:
            chunks = [offsets[i : i + self.ri_threshold] for i in range(0, len(offsets), self.ri_threshold)]
            lists = []
            for chunk in chunks:
                payload = b"li" + len(chunk).to_bytes(2, "little") + b"".join(o.to_bytes(4, "little") for o in chunk)
                lists.append(self.alloc(payload))
            return self.alloc(b"ri" + len(lists).to_bytes(2, "little") + b"".join(o.to_bytes(4, "little") for o in lists))
        payload = b"lh" + len(offsets).to_bytes(2, "little") + b"".join(
            offset.to_bytes(4, "little") + b"\x00" * 4 for offset in offsets
        )
        return self.alloc(payload)

    def serialize(self, key: Key, parent: int, *, root: bool = False) -> int:
        offset = self.alloc(self.nk_payload(key, root=root))
        self.patch_u32(offset, 0x10, parent)
        if key.values:
            value_offsets = [self.write_value(*value) for value in key.values]
            value_list = self.alloc(b"".join(item.to_bytes(4, "little") for item in value_offsets))
            self.patch_u32(offset, 0x24, len(value_offsets))
            self.patch_u32(offset, 0x28, value_list)
        if key.children:
            ordered = sorted(key.children, key=lambda child: child.name.upper())
            child_offsets = [self.serialize(child, offset) for child in ordered]
            self.patch_u32(offset, 0x14, len(child_offsets))
            self.patch_u32(offset, 0x1C, self.subkey_list(child_offsets))
        return offset

    def build(self, root: Key, *, sequence: tuple[int, int] = (7, 7), free_payloads: tuple[bytes, ...] = ()) -> bytes:
        root_offset = self.serialize(root, 0, root=True)
        for payload in free_payloads:
            self.alloc(payload, free=True)
        hbin_size = 32 + len(self.cells)
        hbin_size += (-hbin_size) % 4096
        hbin = bytearray(hbin_size)
        hbin[0:4] = b"hbin"
        hbin[8:12] = hbin_size.to_bytes(4, "little")
        hbin[32 : 32 + len(self.cells)] = self.cells
        base = bytearray(4096)
        base[0:4] = b"regf"
        base[4:8] = sequence[0].to_bytes(4, "little")
        base[8:12] = sequence[1].to_bytes(4, "little")
        base[12:20] = filetime(datetime(2025, 5, 30, tzinfo=timezone.utc)).to_bytes(8, "little")
        base[20:24] = (1).to_bytes(4, "little")
        base[24:28] = self.minor_version.to_bytes(4, "little")
        base[32:36] = (1).to_bytes(4, "little")
        base[36:40] = root_offset.to_bytes(4, "little")
        base[40:44] = hbin_size.to_bytes(4, "little")
        base[44:48] = (1).to_bytes(4, "little")
        checksum = 0
        for index in range(0, 508, 4):
            checksum ^= int.from_bytes(base[index : index + 4], "little")
        base[508:512] = checksum.to_bytes(4, "little")
        return bytes(base) + bytes(hbin)


def guid_le(text: str) -> bytes:
    return uuid.UUID(text).bytes_le


def dos_datetime(moment: datetime) -> bytes:
    date = ((moment.year - 1980) << 9) | (moment.month << 5) | moment.day
    time = (moment.hour << 11) | (moment.minute << 5) | (moment.second // 2)
    return date.to_bytes(2, "little") + time.to_bytes(2, "little")


def shell_root(guid: str) -> bytes:
    return (20).to_bytes(2, "little") + b"\x1f\x50" + guid_le(guid)


def shell_volume(letter: str) -> bytes:
    body = b"\x2f" + f"{letter}:\\".encode("ascii")
    body = body.ljust(23, b"\x00")
    return (len(body) + 2).to_bytes(2, "little") + body


def shell_directory(long_name: str, *, modified: datetime, created: datetime, accessed: datetime) -> bytes:
    short = b"DIR~1\x00"
    fixed = b"\x31\x00" + (0).to_bytes(4, "little") + dos_datetime(modified) + (0x10).to_bytes(2, "little") + short
    if len(fixed) % 2:
        fixed += b"\x00"
    name = long_name.encode("utf-16-le") + b"\x00\x00"
    block = bytearray(0x2E)
    block[2:4] = (9).to_bytes(2, "little")
    block[4:8] = b"\x04\x00\xef\xbe"
    block[8:12] = dos_datetime(created)
    block[12:16] = dos_datetime(accessed)
    block[16:18] = (0x2E).to_bytes(2, "little")
    block[0x14:0x1C] = ((3 << 48) | 0x1234).to_bytes(8, "little")
    block += name + (0x14).to_bytes(2, "little")
    block[0:2] = len(block).to_bytes(2, "little")
    item = fixed + bytes(block)
    return (len(item) + 2).to_bytes(2, "little") + item


def mru_list_ex(order: list[int]) -> bytes:
    return b"".join(index.to_bytes(4, "little") for index in order) + b"\xff\xff\xff\xff"


def write_hive(directory: Path, relative: str, blob: bytes) -> Path:
    path = directory.joinpath(*relative.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(blob)
    return path


SANDISK_CLASS = "Disk&Ven_SanDisk&Prod_Portable_SSD&Rev_6004"
SANDISK_SERIAL = "323431313535343030343036&0"
CONNECT_TICKS = filetime(datetime(2025, 5, 30, 3, 27, 49, 165523, tzinfo=timezone.utc), 7)
DEVICE_PROPERTY_GUID = "{83da6326-97a6-4088-9453-a1923f573b29}"
FILETIME_PROPERTY_TYPE = 0xFFFF0010


def build_system_hive() -> bytes:
    root = Key("ROOT")
    root.path("Select").value("Current", REG_DWORD, dword(1)).value("Default", REG_DWORD, dword(1))
    control = root.path("ControlSet001\\Control")
    control.path("ComputerName\\ComputerName").value("ComputerName", REG_SZ, sz("진료실1"))
    control.path("TimeZoneInformation").value("Bias", REG_DWORD, dword(-540)).value(
        "ActiveTimeBias", REG_DWORD, dword(-540)
    ).value("StandardName", REG_SZ, sz("@tzres.dll,-622")).value(
        "TimeZoneKeyName", REG_SZ, sz("Korea Standard Time")
    )
    control.path("Windows").value(
        "ShutdownTime", REG_BINARY, filetime(datetime(2025, 5, 29, 8, 50, 47, tzinfo=timezone.utc)).to_bytes(8, "little")
    )
    instance = root.path(f"ControlSet001\\Enum\\USBSTOR\\{SANDISK_CLASS}\\{SANDISK_SERIAL}")
    instance.value("FriendlyName", REG_SZ, sz("SanDisk Portable SSD USB Device"))
    for code, ticks in (("0064", CONNECT_TICKS - 10_000_000), ("0066", CONNECT_TICKS), ("0067", CONNECT_TICKS + 4_220_000_000)):
        instance.path(f"Properties\\{DEVICE_PROPERTY_GUID}\\{code}").value("", FILETIME_PROPERTY_TYPE, ticks.to_bytes(8, "little"))
    root.path("ControlSet001\\Enum\\USB\\VID_0781&PID_55BB\\323431313535343030343036")
    device_path = f"_??_USBSTOR#{SANDISK_CLASS}#{SANDISK_SERIAL}#{{53f56307-b6bf-11d0-94f2-00a0c91efb8b}}"
    root.path("MountedDevices").value("\\DosDevices\\F:", REG_BINARY, sz(device_path)[:-2]).value(
        "\\??\\Volume{a03fc990-3c72-11f0-90f3-8cb0e992a14a}", REG_BINARY, sz(device_path)[:-2]
    ).value("\\DosDevices\\C:", REG_BINARY, b"DMIO:ID:" + guid_le("ce84fdf4-f1d3-4775-a8cc-840362427056"))
    services = root.path("ControlSet001\\Services")
    services.path("EvilSvc").value("ImagePath", REG_SZ, sz("C:\\Users\\Public\\evil.exe")).value(
        "Start", REG_DWORD, dword(2)
    ).value("Type", REG_DWORD, dword(0x10))
    services.path("Tcpip\\Parameters\\Interfaces\\{5d95f948-da87-455c-8c05-43e84ddeda07}").value(
        "IPAddress", REG_MULTI_SZ, "192.168.0.100\x00\x00".encode("utf-16-le")
    ).value("EnableDHCP", REG_DWORD, dword(0))
    sid = "S-1-5-21-1-2-3-1001"
    services.path(f"bam\\State\\UserSettings\\{sid}").value(
        "\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe",
        REG_BINARY,
        filetime(datetime(2025, 5, 29, 23, 30, 0, tzinfo=timezone.utc), 3).to_bytes(8, "little") + b"\x00" * 16,
    ).value("SequenceNumber", REG_DWORD, dword(9))
    control.path("Session Manager\\AppCompatCache").value("AppCompatCache", REG_BINARY, appcompat_win10())
    return HiveWriter().build(root, sequence=(53344, 53343))


def appcompat_win10() -> bytes:
    header = bytearray(0x34)
    header[0:4] = (0x34).to_bytes(4, "little")
    entries = b""
    for path, ticks in (("C:\\Tools\\a.exe", filetime(datetime(2024, 1, 2, tzinfo=timezone.utc), 5)),):
        encoded = path.encode("utf-16-le")
        body = len(encoded).to_bytes(2, "little") + encoded + ticks.to_bytes(8, "little") + (0).to_bytes(4, "little")
        entries += b"10ts" + (0).to_bytes(4, "little") + len(body).to_bytes(4, "little") + body
    return bytes(header) + entries


class FiletimeTests(unittest.TestCase):
    def test_filetime_keeps_100ns_and_whole_second_format(self) -> None:
        moment = datetime(2025, 5, 29, 23, 25, 26, 427664, tzinfo=timezone.utc)
        self.assertEqual(filetime_to_iso_ticks(filetime(moment, 7)), "2025-05-29T23:25:26.4276647+00:00")
        self.assertEqual(
            filetime_to_iso_ticks(filetime(datetime(2024, 4, 1, 6, 7, 8, tzinfo=timezone.utc))),
            "2024-04-01T06:07:08+00:00",
        )
        self.assertEqual(filetime_to_iso_ticks(0), "")
        self.assertEqual(filetime_to_iso_ticks(0x7FFFFFFFFFFFFFFF), "")


class NativeHiveWalkTests(unittest.TestCase):
    def test_walk_covers_hive_larger_than_16mb_with_big_data_and_ri_lists(self) -> None:
        root = Key("ROOT")
        payload = bytes(range(256)) * ((17 * 1024 * 1024) // 256)
        root.path("Big").value("Blob", REG_BINARY, payload)
        late = root.path("Software\\Late")
        for index in range(40):
            late.key(f"Child{index:02d}").value("Index", REG_DWORD, dword(index))
        blob = HiveWriter(ri_threshold=8).build(root)
        self.assertGreater(len(blob), 16 * 1024 * 1024)
        with tempfile.TemporaryDirectory() as tmp:
            path = write_hive(Path(tmp), "Windows/System32/config/DRIVERS", blob)
            hive = NativeRegistryHive.open(path)
            assert hive is not None
            try:
                big = hive.open_key("Big")
                assert big is not None
                self.assertEqual(hive.value_bytes(hive.values(big)[0]), payload)
                self.assertEqual(len(hive.subkeys(hive.open_key("Software\\Late"))), 40)  # type: ignore[arg-type]
            finally:
                hive.close()
            records = list(collect_registry_hive(path))
        nodes = [record for record in records if record.artifact_type == "registry-key-tree-node"]
        inventory = next(record for record in records if record.artifact_type == "registry-hive")
        self.assertEqual(len(nodes), 1 + 1 + 2 + 40)
        self.assertEqual(inventory.details["key_count"], 44)
        self.assertEqual(inventory.details["native_walk"]["read_cap_bytes"], None)
        paths = {record.details["key_path"] for record in nodes}
        self.assertIn("HKLM\\DRIVERS\\Software\\Late\\Child39", paths)
        self.assertIn("HKLM\\DRIVERS", paths)
        self.assertFalse(any("ROOT" in path for path in paths))

    def test_korean_key_names_with_and_without_comp_name_flag(self) -> None:
        root = Key("ROOT")
        root.key("진료실 자료")
        root.key("Café", compressed=True)
        root.key("Plain")
        blob = HiveWriter().build(root)
        hive = NativeRegistryHive.from_bytes(blob)
        assert hive is not None
        names = {key.name: key.name_encoding for _parts, key in hive.iter_keys()}
        self.assertEqual(names["진료실 자료"], "utf-16le")
        self.assertEqual(names["Café"], "latin-1")
        self.assertEqual(names["Plain"], "latin-1")
        korean = hive.open_key("진료실 자료")
        assert korean is not None
        cell = blob[4096 + int(korean.offset) : 4096 + int(korean.offset) + 200]
        candidate = parse_registry_nk_cell(cell, 0, 4, len(cell), -len(cell))
        assert candidate is not None
        self.assertEqual(candidate["name"], "진료실 자료")

    def test_free_cell_recovery_uses_mount_path(self) -> None:
        root = Key("ROOT")
        run = root.path("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
        run.value("OneDrive", REG_SZ, sz("C:\\OneDrive.exe"))
        writer = HiveWriter()
        blob = writer.build(root)
        hive = NativeRegistryHive.from_bytes(blob)
        assert hive is not None
        run_key = hive.open_key("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
        assert run_key is not None
        deleted = bytearray(writer.nk_payload(Key("DeletedRun"), root=False))
        deleted[0x10:0x14] = int(run_key.offset).to_bytes(4, "little")
        blob = HiveWriter().build(root, free_payloads=(bytes(deleted),))
        with tempfile.TemporaryDirectory() as tmp:
            path = write_hive(Path(tmp), "Users/alice/NTUSER.DAT", blob)
            records = list(collect_registry_hive(path))
        recovered = next(record for record in records if record.artifact_type == "registry-key-recovery-candidate")
        self.assertEqual(
            recovered.details["key_path_candidate"], "HKU\\alice\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\DeletedRun"
        )
        persistence = next(record for record in records if record.artifact_type == "registry-persistence-entry")
        self.assertEqual(persistence.details["value_name"], "OneDrive")
        self.assertEqual(persistence.details["key_path"], "HKU\\alice\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")


class SystemHivePluginTests(unittest.TestCase):
    def collect(self) -> tuple[list[object], Path]:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        write_hive(root, "Windows/System32/config/SYSTEM", build_system_hive())
        return list(WindowsRegistryProvider().collect(root)), root

    def test_usbstor_mounted_devices_and_usb_vid_pid_join(self) -> None:
        records, _root = self.collect()
        usb = [record for record in records if record.artifact_type == "windows-usb-device"]
        self.assertEqual(len(usb), 1)
        details = usb[0].details
        self.assertEqual(details["vendor"], "SanDisk")
        self.assertEqual(details["product"], "Portable SSD")
        self.assertEqual(details["serial_number"], SANDISK_SERIAL)
        self.assertEqual((details["vid"], details["pid"]), ("0781", "55BB"))
        self.assertEqual(details["last_arrival_at"], "2025-05-30T03:27:49.1655237+00:00")
        self.assertEqual(details["timestamp"], details["last_arrival_at"])
        self.assertEqual(details["drive_letters"], ["F:"])
        self.assertEqual(details["volume_guids"], ["{a03fc990-3c72-11f0-90f3-8cb0e992a14a}"])
        self.assertEqual(
            details["key_path"], f"HKLM\\SYSTEM\\ControlSet001\\Enum\\USBSTOR\\{SANDISK_CLASS}\\{SANDISK_SERIAL}"
        )
        mounted = {record.details["mount_name"]: record.details for record in records if record.artifact_type == "windows-mounted-device"}
        self.assertEqual(mounted["\\DosDevices\\F:"]["usb_serial_number"], SANDISK_SERIAL)
        self.assertTrue(mounted["\\DosDevices\\F:"]["removable_usb"])
        self.assertEqual(mounted["\\DosDevices\\C:"]["data_kind"], "gpt-partition-guid")
        summary = next(record for record in records if record.artifact_type == "registry-summary")
        self.assertEqual(summary.details["usb_devices"][0]["serial_number"], SANDISK_SERIAL)

    def test_timezone_computer_name_control_set_and_services(self) -> None:
        records, _root = self.collect()
        timezone_row = next(record for record in records if record.artifact_type == "windows-timezone")
        self.assertEqual(timezone_row.details["bias_minutes"], -540)
        self.assertEqual(timezone_row.details["utc_offset"], "+09:00")
        self.assertEqual(timezone_row.details["time_zone_label_ko"], "대한민국 표준시(KST)")
        self.assertEqual(timezone_row.details["key_path"], "HKLM\\SYSTEM\\ControlSet001\\Control\\TimeZoneInformation")
        name_row = next(record for record in records if record.artifact_type == "windows-computer-name")
        self.assertEqual(name_row.details["computer_name"], "진료실1")
        service = next(
            record for record in records if record.artifact_type == "windows-service-config" and record.details["service_name"] == "EvilSvc"
        )
        self.assertEqual(service.details["start_label"], "자동(Auto)")
        self.assertIn("autostart-service-outside-system-dirs", service.details["risk_flags"])
        network = next(record for record in records if record.artifact_type == "windows-network-interface")
        self.assertEqual(network.details["ip_address"], "192.168.0.100")
        summary = next(record for record in records if record.artifact_type == "registry-summary")
        self.assertEqual(summary.details["computer_name"], "진료실1")
        self.assertEqual(summary.details["timezone"]["utc_offset"], "+09:00")
        self.assertEqual(summary.details["current_control_set"], "ControlSet001")
        self.assertEqual(summary.details["last_shutdown_at"], "2025-05-29T08:50:47+00:00")
        self.assertTrue(any(entry["category"] == "service" for entry in summary.details["persistence_entries"]))
        self.assertGreater(summary.details["native_key_count"], 20)

    def test_newer_transaction_log_sequence_is_disclosed_not_replayed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_hive(Path(tmp), "Windows/System32/config/SYSTEM", build_system_hive())
            log = bytearray(512 + 512 * 2)
            log[0:4] = b"regf"
            log[4:8] = (53475).to_bytes(4, "little")
            log[8:12] = (53475).to_bytes(4, "little")
            log[28:32] = (6).to_bytes(4, "little")
            for index, sequence in enumerate((53475, 53476)):
                start = 512 + index * 512
                log[start : start + 4] = b"HvLE"
                log[start + 4 : start + 8] = (512).to_bytes(4, "little")
                log[start + 12 : start + 16] = sequence.to_bytes(4, "little")
            (path.parent / "SYSTEM.LOG1").write_bytes(bytes(log))
            records = list(collect_registry_hive(path, context=RegistryCollectionContext(Path(tmp))))
        inventory = next(record for record in records if record.artifact_type == "registry-hive")
        self.assertEqual(inventory.details["transaction_log_disclosure_status"], "newer-sequence-not-replayed")
        self.assertIn("2개(53475–53476)", inventory.details["transaction_log_disclosure"])
        evidence = inventory.details["registry_transaction_log_evidence"]
        self.assertFalse(evidence["transaction_log_replay_applied"])
        self.assertEqual(evidence["present_logs"][0]["header"]["log_format"], "new-hvle")


class UserHivePluginTests(unittest.TestCase):
    def test_wordwheel_mru_order_run_keys_and_sid_mount(self) -> None:
        root = Key("ROOT")
        explorer = root.path("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer")
        wordwheel = explorer.path("WordWheelQuery")
        wordwheel.value("MRUListEx", REG_BINARY, mru_list_ex([1, 0]))
        wordwheel.value("0", REG_BINARY, sz("급여대장"))
        wordwheel.value("1", REG_BINARY, sz("계약서"))
        root.path("Software\\Microsoft\\Windows\\CurrentVersion\\Run").value(
            "의사랑 모바일 서버", REG_SZ, sz("D:\\YSR2000\\Ysr.Server.EmbedIO.exe")
        )
        classes = Key("S-1-5-21-1-2-3-1001_Classes")
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            write_hive(base, "Users/user/NTUSER.DAT", HiveWriter().build(root))
            write_hive(base, "Users/user/AppData/Local/Microsoft/Windows/UsrClass.dat", HiveWriter().build(classes))
            records = list(WindowsRegistryProvider().collect(base))
        activity = [
            record.details for record in records if record.artifact_type == "registry-user-activity"
        ]
        wordwheel_rows = sorted(
            (row for row in activity if row["user_activity_category"] == "wordwheel-query"), key=lambda row: row["mru_position"]
        )
        self.assertEqual([row["activity_value"] for row in wordwheel_rows], ["계약서", "급여대장"])
        self.assertEqual(wordwheel_rows[0]["timestamp_label"], "last_written_mru_head")
        self.assertEqual(wordwheel_rows[1]["timestamp"], "")
        run = next(record for record in records if record.artifact_type == "registry-persistence-entry")
        self.assertEqual(run.details["value_name"], "의사랑 모바일 서버")
        self.assertEqual(
            run.details["key_path"], "HKU\\S-1-5-21-1-2-3-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        )
        hives = {
            record.details["hive_name"]: record.details["hive_mount"] for record in records if record.artifact_type == "registry-hive"
        }
        self.assertEqual(hives["UsrClass.dat"], "HKU\\S-1-5-21-1-2-3-1001_Classes")
        self.assertFalse(any(record.details.get("coverage_status") == "native-hive-string-pivot" for record in records))


def build_sam_hive() -> bytes:
    domain_sid = b"\x01\x04\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00" + b"".join(
        value.to_bytes(4, "little") for value in (2266883812, 3902313356, 1106336633)
    )
    root = Key("ROOT")
    account = root.path("SAM\\Domains\\Account")
    account.value("V", REG_BINARY, b"\x00" * 64 + domain_sid)
    users = account.path("Users")
    f_value = bytearray(0x50)
    f_value[0x08:0x10] = filetime(datetime(2025, 5, 29, 23, 25, 26, 427664, tzinfo=timezone.utc), 7).to_bytes(8, "little")
    f_value[0x18:0x20] = filetime(datetime(2021, 12, 9, 9, 42, 15, tzinfo=timezone.utc)).to_bytes(8, "little")
    f_value[0x20:0x28] = (0x7FFFFFFFFFFFFFFF).to_bytes(8, "little")
    f_value[0x28:0x30] = filetime(datetime(2025, 5, 29, 23, 25, 26, 952279, tzinfo=timezone.utc)).to_bytes(8, "little")
    f_value[0x30:0x34] = (1001).to_bytes(4, "little")
    f_value[0x38:0x3A] = (0x214).to_bytes(2, "little")
    f_value[0x40:0x42] = (1).to_bytes(2, "little")
    f_value[0x42:0x44] = (1974).to_bytes(2, "little")
    strings = {0x0C: "user", 0x18: "홍길동", 0x24: "진료실 계정"}
    v_value = bytearray(0xCC)
    data = bytearray()
    for descriptor, text in strings.items():
        encoded = text.encode("utf-16-le")
        v_value[descriptor : descriptor + 4] = len(data).to_bytes(4, "little")
        v_value[descriptor + 4 : descriptor + 8] = len(encoded).to_bytes(4, "little")
        data += encoded + b"\x00" * ((-len(encoded)) % 4)
    users.path("000003E9").value("F", REG_BINARY, bytes(f_value)).value("V", REG_BINARY, bytes(v_value + data))
    users.path("Names\\user").value("", 0x3E9, b"")
    member = domain_sid[:1] + b"\x05" + domain_sid[2:] + (1001).to_bytes(4, "little")
    name = "Administrators".encode("utf-16-le")
    alias = bytearray(0x34)
    alias[0:4] = (0x220).to_bytes(4, "little")
    alias[0x10:0x14] = (0).to_bytes(4, "little")
    alias[0x14:0x18] = len(name).to_bytes(4, "little")
    alias[0x28:0x2C] = len(name).to_bytes(4, "little")
    alias[0x2C:0x30] = len(member).to_bytes(4, "little")
    alias[0x30:0x34] = (1).to_bytes(4, "little")
    root.path("SAM\\Domains\\Builtin\\Aliases\\00000220").value("C", REG_BINARY, bytes(alias) + name + member)
    return HiveWriter().build(root)


class SamDecodeTests(unittest.TestCase):
    def test_sam_f_v_decode_with_korean_full_name_and_groups(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            write_hive(Path(tmp), "Windows/System32/config/SAM", build_sam_hive())
            records = list(WindowsOsAccountProvider().collect(Path(tmp)))
        types = {record.artifact_type for record in records}
        self.assertNotIn("windows-sam-account-candidate", types)
        self.assertNotIn("windows-sam-group-candidate", types)
        account = next(record.details for record in records if record.artifact_type == "windows-sam-account")
        self.assertEqual(account["user_name"], "user")
        self.assertEqual(account["full_name"], "홍길동")
        self.assertEqual(account["comment"], "진료실 계정")
        self.assertEqual(account["rid"], 1001)
        self.assertEqual(account["sid"], "S-1-5-21-2266883812-3902313356-1106336633-1001")
        self.assertEqual(account["last_logon_at"], "2025-05-29T23:25:26.4276647+00:00")
        self.assertEqual(account["password_last_set_at"], "2021-12-09T09:42:15+00:00")
        self.assertEqual(account["account_expires_at"], "")
        self.assertEqual(account["last_failed_logon_at"], "2025-05-29T23:25:26.9522790+00:00")
        self.assertEqual((account["logon_count"], account["failed_logon_count"]), (1974, 1))
        self.assertIn("일반 사용자 계정", account["acb_flag_labels_ko"])
        self.assertEqual(account["group_memberships"], ["Administrators"])
        self.assertTrue(account["admin_member"])
        self.assertEqual(account["names_key_name"], "user")
        group = next(record.details for record in records if record.artifact_type == "windows-sam-group")
        self.assertEqual(group["group_scope"], "builtin-alias")
        self.assertEqual(group["group_sid"], "S-1-5-32-544")
        self.assertEqual(group["member_names"], ["user"])


def build_usrclass_shellbags() -> bytes:
    root = Key("S-1-5-21-1-2-3-1001_Classes")
    shell = root.path("Local Settings\\Software\\Microsoft\\Windows\\Shell")
    bagmru = shell.path("BagMRU")
    bagmru.value("0", REG_BINARY, shell_root("20d04fe0-3aea-1069-a2d8-08002b30309d") + b"\x00\x00")
    bagmru.value("MRUListEx", REG_BINARY, mru_list_ex([0]))
    computer = bagmru.key("0")
    computer.value("NodeSlot", REG_DWORD, dword(2))
    computer.value("0", REG_BINARY, shell_volume("F") + b"\x00\x00")
    volume = computer.key("0")
    stamp = datetime(2024, 1, 31, 3, 32, 24, tzinfo=timezone.utc)
    volume.value("0", REG_BINARY, shell_directory("마음의원(new)", modified=stamp, created=stamp, accessed=stamp) + b"\x00\x00")
    volume.value("1", REG_BINARY, shell_directory("기타", modified=stamp, created=stamp, accessed=stamp) + b"\x00\x00")
    volume.value("MRUListEx", REG_BINARY, mru_list_ex([1, 0]))
    clinic = volume.key("0")
    volume.key("1")
    clinic.value("0", REG_BINARY, shell_directory("급여대장", modified=stamp, created=datetime(2023, 9, 5, 4, 28, 2, tzinfo=timezone.utc), accessed=stamp) + b"\x00\x00")
    payroll = clinic.key("0")
    payroll.value("0", REG_BINARY, shell_directory("2024", modified=stamp, created=stamp, accessed=stamp) + b"\x00\x00")
    payroll.key("0").value("NodeSlot", REG_DWORD, dword(686))
    shell.path("Bags\\686\\Shell").value("FFlags", REG_DWORD, dword(1))
    return HiveWriter().build(root)


class ShellbagTests(unittest.TestCase):
    def test_bagmru_path_reconstruction_mru_order_and_bags_exclusion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            write_hive(Path(tmp), "Users/user/AppData/Local/Microsoft/Windows/UsrClass.dat", build_usrclass_shellbags())
            records = list(WindowsShellbagsProvider().collect(Path(tmp)))
        entries = [record.details for record in records if record.artifact_type == "shellbag-entry" and not record.details["bagmru_root"]]
        by_path = {entry["shell_path"]: entry for entry in entries}
        self.assertEqual(len(entries), 6)
        deepest = by_path["My Computer\\F:\\마음의원(new)\\급여대장\\2024"]
        self.assertEqual(deepest["node_slot"], 686)
        self.assertEqual(deepest["volume"], "F:\\")
        self.assertEqual(deepest["item_kind"], "directory")
        payroll = by_path["My Computer\\F:\\마음의원(new)\\급여대장"]
        self.assertEqual(payroll["item_created_at"], "2023-09-05T04:28:02+00:00")
        self.assertEqual(payroll["shellitem"]["mft_entry"], 0x1234)
        self.assertEqual(payroll["shellitem"]["mft_sequence"], 3)
        self.assertEqual(by_path["My Computer\\F:\\기타"]["mru_position"], 0)
        self.assertEqual(by_path["My Computer\\F:\\마음의원(new)"]["mru_position"], 1)
        self.assertEqual(by_path["My Computer"]["key_path"], "HKU\\S-1-5-21-1-2-3-1001_Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU\\0")
        self.assertFalse(any("Bags" in str(entry["node_key_path"]).split("\\") for entry in entries))
        summary = next(record.details for record in records if record.artifact_type == "shellbag-hive-summary")
        self.assertEqual(summary["shellbag_entry_count"], 6)
        self.assertEqual(summary["bags_view_settings_key_count_excluded"], 2)
        self.assertIsNone(summary["row_cap"])
        self.assertNotIn("shellbag-native-candidate", {record.artifact_type for record in records})

    def test_ntuser_shell_bagmru_is_walked_and_unc_paths_are_absolute(self) -> None:
        root = Key("ROOT")
        bagmru = root.path("Software\\Microsoft\\Windows\\Shell\\BagMRU")
        network = b"\xc3\x01\x00" + b"\\\\192.168.0.100\\Users\x00" + b"\x00\x00"
        item = (len(network) + 2).to_bytes(2, "little") + network
        bagmru.value("0", REG_BINARY, item + b"\x00\x00")
        bagmru.key("0")
        with tempfile.TemporaryDirectory() as tmp:
            path = write_hive(Path(tmp), "Users/user/NTUSER.DAT", HiveWriter().build(root))
            records = list(collect_native_shellbag_hive(path))
        entry = next(record.details for record in records if record.artifact_type == "shellbag-entry" and not record.details["bagmru_root"])
        self.assertEqual(entry["item_kind"], "network")
        self.assertEqual(entry["shell_path"], "\\\\192.168.0.100\\Users")

    def test_shell_item_root_and_volume_decode(self) -> None:
        self.assertEqual(decode_shell_item_entry(shell_root("679f85cb-0220-4080-b29b-5540cc05aab6"))["name"], "Quick Access")
        self.assertEqual(decode_shell_item_entry(shell_volume("E"))["name"], "E:\\")


class ExecutionTypeTests(unittest.TestCase):
    def test_string_pivot_types_absent_and_decoded_rows_carry_timeline_fields(self) -> None:
        user = Key("ROOT")
        count = user.path("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count")
        record = bytearray(72)
        record[4:8] = (12).to_bytes(4, "little")
        record[60:68] = filetime(datetime(2025, 5, 30, 1, 11, 47, 413000, tzinfo=timezone.utc)).to_bytes(8, "little")
        import codecs

        count.value(codecs.encode("{6D809377-6AF0-444B-8957-A3773F02200E}\\Tool\\tool.exe", "rot_13"), REG_BINARY, bytes(record))
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            write_hive(base, "Windows/System32/config/SYSTEM", build_system_hive())
            write_hive(base, "Users/user/NTUSER.DAT", HiveWriter().build(user))
            records = list(WindowsExecutionProvider().collect(base))
        types = {record.artifact_type for record in records}
        for junk in ("amcache-entry", "shimcache-entry", "bam-entry", "shimcache-string-candidate", "bam-string-candidate"):
            self.assertNotIn(junk, types)
        shim = next(record.details for record in records if record.artifact_type == "shimcache-schema-entry")
        self.assertEqual(shim["executable_path"], "C:\\Tools\\a.exe")
        self.assertEqual(shim["timestamp"], "2024-01-02T00:00:00.0000005+00:00")
        self.assertEqual(shim["timestamp_label"], "file_last_modified")
        bam = next(record.details for record in records if record.artifact_type == "bam-schema-entry")
        self.assertEqual(bam["user_sid"], "S-1-5-21-1-2-3-1001")
        self.assertEqual(bam["timestamp"], "2025-05-29T23:30:00.0000003+00:00")
        self.assertEqual(bam["timestamp_label"], "last_execution")
        assist = next(record.details for record in records if record.artifact_type == "userassist-schema-entry")
        self.assertEqual(assist["layout"], "win7-plus")
        self.assertTrue(assist["known_folder_resolved"])
        self.assertTrue(assist["display_path"].startswith("%PROGRAMFILES%\\Tool"))
        self.assertEqual(assist["run_counter"], 12)
        self.assertEqual(assist["timestamp"], "2025-05-30T01:11:47.4130000+00:00")


if __name__ == "__main__":
    unittest.main()
