"""Parser-quality round 1 (W3): Prefetch, LNK, Jump Lists, signature scan,
WER, minidump and remote-access timestamps.

Every fixture is synthetic and built in-test from the documented binary
layouts; the expected values mirror the ground truth measured on the
reviewed evidence set (e.g. run count at 0xC8 for metrics offset 0x128,
DestList v3 entry layout with a 4-byte trailer, cp949 NetBIOS names).
"""

from __future__ import annotations

import os
import struct
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from rapidtriage.artifacts.windows.filesystem import (
    collect_signature_mismatch_artifacts,
    sniff_content_kind,
)
from rapidtriage.artifacts.windows.prefetch import (
    WindowsPrefetchProvider,
    prefetch_header_hints,
)
from rapidtriage.artifacts.windows.recent_files import (
    WindowsRecentFilesProvider,
    parse_cfb_directory_entries,
    parse_destlist_metadata,
    parse_lnk_metadata_from_bytes,
    windows_filetime_to_iso,
)
from rapidtriage.artifacts.windows.remote_access import WindowsRemoteAccessProvider
from rapidtriage.artifacts.windows.system import (
    WindowsSystemArtifactsProvider,
    normalize_sqlite_time_value,
    parse_minidump_header,
    wer_time_to_iso,
)
from tests.windows_artifact_fixtures import build_minimal_ole_jumplist_streams

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
LNK_CLSID = bytes.fromhex("0114020000000000c000000000000046")


def to_filetime(moment: datetime) -> int:
    delta = moment - FILETIME_EPOCH
    return (delta.days * 86_400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


def utf16z(text: str) -> bytes:
    return text.encode("utf-16le") + b"\x00\x00"


# --------------------------------------------------------------------------
# Prefetch (SCCA) builders
# --------------------------------------------------------------------------


def build_scca(
    *,
    version: int = 31,
    metrics_offset: int = 0x128,
    executable: str = "CMD.EXE",
    paths: list[str],
    run_times: list[datetime],
    run_count_c8: int = 0,
    run_count_d0: int = 0,
    volume_device: str = "\\VOLUME{01d75b57f6c404f3-a8f6f975}",
    volume_serial: int = 0xA8F6F975,
    volume_created: datetime | None = None,
    directories: list[str] | None = None,
) -> bytes:
    """Decompressed SCCA v30/31 layout: header, file information, metrics, strings, volumes."""
    filename_blob = b""
    name_offsets: list[tuple[int, int]] = []
    for path in paths:
        name_offsets.append((len(filename_blob), len(path)))
        filename_blob += utf16z(path)
    metrics = bytearray()
    for index, (offset, chars) in enumerate(name_offsets):
        entry = bytearray(32)
        struct.pack_into("<IIIIII", entry, 0, index, 1, 1, offset, chars, 0x200)
        struct.pack_into("<Q", entry, 24, (7 << 48) | (1000 + index))
        metrics += entry
    filename_offset = metrics_offset + len(metrics)
    volume_offset = filename_offset + len(filename_blob)
    volume_offset += (-volume_offset) % 8
    directories = directories or []
    volume_entry = bytearray(96)
    device_rel = 96
    device_blob = utf16z(volume_device)
    dirs_rel = device_rel + len(device_blob)
    dirs_blob = b"".join(struct.pack("<H", len(item)) + utf16z(item) for item in directories)
    struct.pack_into(
        "<IIQIIIII",
        volume_entry,
        0,
        device_rel,
        len(volume_device),
        to_filetime(volume_created) if volume_created else 0,
        volume_serial,
        0,
        0,
        dirs_rel,
        len(directories),
    )
    volume_blob = bytes(volume_entry) + device_blob + dirs_blob
    total = volume_offset + len(volume_blob)
    blob = bytearray(total)
    struct.pack_into("<I4s", blob, 0, version, b"SCCA")
    struct.pack_into("<I", blob, 0x0C, total)
    name = executable.encode("utf-16le")[:58]
    blob[0x10 : 0x10 + len(name)] = name
    struct.pack_into("<I", blob, 0x4C, 0x6D6290C5)
    struct.pack_into(
        "<9I",
        blob,
        0x54,
        metrics_offset,
        len(paths),
        0,
        0,
        filename_offset,
        len(filename_blob),
        volume_offset,
        1,
        len(volume_blob),
    )
    for index, moment in enumerate(run_times[:8]):
        struct.pack_into("<Q", blob, 0x80 + index * 8, to_filetime(moment))
    struct.pack_into("<I", blob, 0xC8, run_count_c8)
    struct.pack_into("<I", blob, 0xD0, run_count_d0)
    blob[metrics_offset : metrics_offset + len(metrics)] = metrics
    blob[filename_offset : filename_offset + len(filename_blob)] = filename_blob
    blob[volume_offset : volume_offset + len(volume_blob)] = volume_blob
    return bytes(blob)


RUN_TIMES = [datetime(2025, 5, 29, 23, 26, 25, 428203, tzinfo=timezone.utc) - timedelta(days=index) for index in range(8)]
KOREAN_PATHS = [
    "\\VOLUME{01d75b57f6c404f3-a8f6f975}\\WINDOWS\\SYSTEM32\\NTDLL.DLL",
    "\\VOLUME{01d75b57f6c404f3-a8f6f975}\\USERS\\USER\\DESKTOP\\진료 기록.HWP",
    "\\VOLUME{01d75b57f6c404f3-a8f6f975}\\WINDOWS\\SYSTEM32\\CMD.EXE",
    "\\VOLUME{01d75b57f6c404f3-a8f6f975}\\WINDOWS\\SYSTEM32\\KERNEL32.DLL",
]


class PrefetchParserQualityTests(unittest.TestCase):
    def collect(self, files: dict[str, bytes]) -> list:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        prefetch_dir = root / "Windows" / "Prefetch"
        prefetch_dir.mkdir(parents=True)
        for name, data in files.items():
            (prefetch_dir / name).write_bytes(data)
        return list(WindowsPrefetchProvider().collect(root))

    def test_v31_metrics_offset_0x128_reads_run_count_at_0xc8(self) -> None:
        blob = build_scca(
            paths=KOREAN_PATHS,
            run_times=RUN_TIMES,
            run_count_c8=23,
            run_count_d0=0x11,
            volume_created=datetime(2021, 6, 7, 4, 45, 39, 104280, tzinfo=timezone.utc),
            directories=["\\VOLUME{01d75b57f6c404f3-a8f6f975}\\USERS", "\\VOLUME{01d75b57f6c404f3-a8f6f975}\\USERS\\USER\\바탕 화면"],
        )
        rows = self.collect({"CMD.EXE-6D6290C5.pf": blob})
        file_row = next(row for row in rows if row.artifact_type == "prefetch-file")
        details = file_row.details
        self.assertEqual(details["run_count"], 23)
        self.assertEqual(details["run_count_offset"], 0xC8)
        self.assertEqual(details["prefetch_version_metadata"]["run_count_offset_hex"], "0xc8")
        self.assertTrue(details["run_count_cross_check"]["consistent"])
        self.assertEqual(details["file_information_layout"], "v31-file-information-212-bytes")
        self.assertEqual(len(details["last_run_times"]), 8)
        self.assertEqual(details["run_time_1"], "2025-05-29T23:26:25.428203+00:00")
        self.assertEqual(details["run_time_8"], RUN_TIMES[7].isoformat())
        self.assertEqual(details["timestamp"], details["last_run_at"])
        self.assertEqual(details["timestamp_kind"], "run")
        self.assertNotIn("modified_at", details)
        self.assertTrue(details["source_file_mtime"])
        self.assertEqual(details["header_executable_name"], "CMD.EXE")
        self.assertEqual(details["header_prefetch_hash"], "6D6290C5")
        # Load order preserved, no sort/dedup, Korean decoded, no length-prefix char.
        self.assertEqual(details["referenced_paths"], KOREAN_PATHS)
        self.assertEqual(details["referenced_path_source"], "file-metrics-filename-strings")
        self.assertEqual(details["file_reference_candidates"][1]["mft_entry"], 1001)
        self.assertEqual(details["file_reference_candidates"][1]["mft_sequence"], 7)
        volume = details["volumes"][0]
        self.assertEqual(volume["volume_device_path"], "\\VOLUME{01d75b57f6c404f3-a8f6f975}")
        self.assertEqual(volume["volume_serial_number"], "A8F6F975")
        self.assertEqual(volume["volume_created_at"], "2021-06-07T04:45:39.104280+00:00")
        self.assertEqual(volume["directory_strings"][1], "\\VOLUME{01d75b57f6c404f3-a8f6f975}\\USERS\\USER\\바탕 화면")
        self.assertEqual(details["volume_candidates"][0]["volume_serial_number"], "A8F6F975")
        references = [row for row in rows if row.artifact_type == "prefetch-reference"]
        self.assertEqual([row.details["referenced_path"] for row in references], KOREAN_PATHS)
        self.assertEqual(references[1].details["volume_device_path"], "\\VOLUME{01d75b57f6c404f3-a8f6f975}")
        self.assertEqual(references[0].details["timestamp"], "")

    def test_v30_metrics_offset_0x130_reads_run_count_at_0xd0(self) -> None:
        blob = build_scca(version=30, metrics_offset=0x130, paths=KOREAN_PATHS[:1], run_times=RUN_TIMES[:2], run_count_c8=0, run_count_d0=2)
        hints = self.hints(blob)
        self.assertEqual(hints["run_count"], 2)
        self.assertEqual(hints["run_count_offset"], 0xD0)
        self.assertEqual(hints["last_run_times"], [RUN_TIMES[0].isoformat(), RUN_TIMES[1].isoformat()])

    def test_unrecognized_metrics_offset_cross_checks_run_times(self) -> None:
        blob = build_scca(metrics_offset=0x140, paths=KOREAN_PATHS[:1], run_times=RUN_TIMES[:3], run_count_c8=3, run_count_d0=0)
        hints = self.hints(blob)
        self.assertEqual(hints["run_count"], 3)
        self.assertEqual(hints["run_count_offset"], 0xC8)
        self.assertTrue(hints["run_count_cross_check"]["switched_to_alternate"])

    def test_header_name_is_the_29_character_field_not_a_path(self) -> None:
        long_name = "AM_DELTA_PATCH_1.429.176.0.EX"  # 29 characters, truncated by Windows
        blob = build_scca(
            executable=long_name,
            paths=["\\VOLUME{X}\\WINDOWS\\SOFTWAREDISTRIBUTION\\DOWNLOAD\\INSTALL\\AM_DELTA_PATCH_1.429.176.0.EXE"],
            run_times=RUN_TIMES[:1],
            run_count_c8=1,
        )
        hints = self.hints(blob)
        self.assertEqual(hints["header_executable_name"], long_name)
        self.assertTrue(hints["header_executable_name_may_be_truncated"])

    def test_more_than_200_references_are_all_emitted_and_inline_cap_is_disclosed(self) -> None:
        paths = [f"\\VOLUME{{X}}\\DIR\\FILE{index:03d}.DLL" for index in range(250)]
        rows = self.collect({"BIG.EXE-00000001.pf": build_scca(executable="BIG.EXE", paths=paths, run_times=RUN_TIMES[:1], run_count_c8=1)})
        file_row = next(row for row in rows if row.artifact_type == "prefetch-file")
        self.assertEqual(file_row.details["referenced_path_count"], 250)
        self.assertTrue(file_row.details["referenced_paths_truncated"])
        self.assertEqual(len([row for row in rows if row.artifact_type == "prefetch-reference"]), 250)

    def test_legacy_layouts_v17_v23_v26_keep_their_offsets(self) -> None:
        for version, run_offset, time_offset, slots in ((17, 0x90, 0x78, 1), (23, 0x98, 0x80, 1), (26, 0xD0, 0x80, 8)):
            blob = bytearray(0x200)
            struct.pack_into("<I4s", blob, 0, version, b"SCCA")
            struct.pack_into("<I", blob, 0x0C, len(blob))
            blob[0x10:0x20] = "NOTEPAD.EXE".encode("utf-16le")[:16]
            struct.pack_into("<I", blob, run_offset, 11)
            for index in range(slots):
                struct.pack_into("<Q", blob, time_offset + index * 8, to_filetime(RUN_TIMES[index]))
            hints = self.hints(bytes(blob))
            self.assertEqual(hints["run_count"], 11, version)
            self.assertEqual(len(hints["last_run_times"]), slots, version)

    def test_non_scca_content_becomes_prefetch_invalid_content(self) -> None:
        jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00" + os.urandom(2048)
        rows = self.collect(
            {
                "APPLICATIONFRAMEHOST.EXE-8CE9A1EE.pf": jpeg,
                "CVTRES.EXE-CB8485B0.pf": b"\x00" * 3929,
                "CMD.EXE-6D6290C5.pf": build_scca(paths=KOREAN_PATHS[:1], run_times=RUN_TIMES[:1], run_count_c8=1),
            }
        )
        invalid = {Path(row.path).name: row.details for row in rows if row.artifact_type == "prefetch-invalid-content"}
        self.assertEqual(invalid["APPLICATIONFRAMEHOST.EXE-8CE9A1EE.pf"]["detected_content_kind"], "jpeg")
        self.assertEqual(invalid["CVTRES.EXE-CB8485B0.pf"]["detected_content_kind"], "zero-filled")
        for details in invalid.values():
            self.assertNotIn("executable_hint", details)
            self.assertNotIn("run_count", details)
            self.assertFalse(details["execution_evidence"])
            self.assertIn("실행 근거", details["note"])
        self.assertEqual([Path(row.path).name for row in rows if row.artifact_type == "prefetch-file"], ["CMD.EXE-6D6290C5.pf"])
        self.assertFalse(any(Path(row.path).name.startswith(("APPLICATION", "CVTRES")) for row in rows if row.artifact_type == "prefetch-reference"))

    @unittest.skipUnless(os.name == "nt", "MAM compression uses ntdll RtlCompressBuffer")
    def test_mam_compressed_v31_0x128_layout(self) -> None:
        import ctypes

        inner = build_scca(paths=KOREAN_PATHS, run_times=RUN_TIMES[:5], run_count_c8=5, run_count_d0=0x99)
        ntdll = ctypes.windll.ntdll
        workspace_compress, workspace_fragment = ctypes.c_uint32(), ctypes.c_uint32()
        self.assertEqual(ntdll.RtlGetCompressionWorkSpaceSize(ctypes.c_uint16(4), ctypes.byref(workspace_compress), ctypes.byref(workspace_fragment)), 0)
        source = (ctypes.c_ubyte * len(inner)).from_buffer_copy(inner)
        target = (ctypes.c_ubyte * (len(inner) + 4096))()
        produced = ctypes.c_uint32()
        workspace = (ctypes.c_ubyte * workspace_compress.value)()
        rc = ntdll.RtlCompressBuffer(
            ctypes.c_uint16(4), ctypes.byref(source), ctypes.c_uint32(len(inner)), ctypes.byref(target),
            ctypes.c_uint32(len(inner) + 4096), ctypes.c_uint32(4096), ctypes.byref(produced), ctypes.byref(workspace),
        )
        self.assertEqual(rc, 0)
        mam = (0x044D414D).to_bytes(4, "little") + len(inner).to_bytes(4, "little") + bytes(target[: produced.value])
        hints = self.hints(mam)
        self.assertEqual(hints["prefetch_decompression"]["status"], "decompressed")
        self.assertEqual(hints["run_count"], 5)
        self.assertEqual(hints["referenced_paths"], KOREAN_PATHS)

    def test_corrupt_mam_is_invalid_content(self) -> None:
        rows = self.collect({"DLLHOST.EXE-7D5CE0CA.pf": b"MAM\x04" + (0x663A).to_bytes(4, "little") + os.urandom(512)})
        self.assertEqual(rows[0].artifact_type, "prefetch-invalid-content")
        self.assertEqual(rows[0].details["detected_content_kind"], "mam-decompression-failed")

    def hints(self, blob: bytes) -> dict:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "TEST.EXE-00000000.pf"
            path.write_bytes(blob)
            return prefetch_header_hints(path)


# --------------------------------------------------------------------------
# Shell Link builders
# --------------------------------------------------------------------------


def lnk_header(flags: int, *, created: datetime, accessed: datetime, modified: datetime, size: int = 1234) -> bytearray:
    header = bytearray(0x4C)
    struct.pack_into("<I16sII", header, 0, 0x4C, LNK_CLSID, flags, 0x20)
    struct.pack_into("<QQQI", header, 0x1C, to_filetime(created), to_filetime(accessed), to_filetime(modified), size)
    struct.pack_into("<I", header, 0x3C, 1)
    return header


def link_info_local(serial: int, label: str, base: str, suffix: str) -> bytes:
    """LinkInfo with VolumeID (unicode label) and unicode LocalBasePath/CommonPathSuffix."""
    volume = bytearray(0x14)
    label_blob = utf16z(label)
    struct.pack_into("<IIIII", volume, 0, 0x14 + len(label_blob), 3, serial, 0x14, 0x14)
    volume_blob = bytes(volume) + label_blob
    header_size = 0x24
    volume_offset = header_size
    ansi_base_offset = volume_offset + len(volume_blob)
    ansi_base = b"?\x00"
    ansi_suffix_offset = ansi_base_offset + len(ansi_base)
    ansi_suffix = b"\x00"
    unicode_base_offset = ansi_suffix_offset + len(ansi_suffix)
    unicode_base = utf16z(base)
    unicode_suffix_offset = unicode_base_offset + len(unicode_base)
    unicode_suffix = utf16z(suffix)
    total = unicode_suffix_offset + len(unicode_suffix)
    block = bytearray(header_size)
    struct.pack_into("<IIIIIIIII", block, 0, total, header_size, 0x1, volume_offset, ansi_base_offset, 0, ansi_suffix_offset, unicode_base_offset, unicode_suffix_offset)
    return bytes(block) + volume_blob + ansi_base + ansi_suffix + unicode_base + unicode_suffix


def link_info_network(net_name: str, suffix: str) -> bytes:
    """LinkInfo with only a CommonNetworkRelativeLink (ANSI cp949 NetName and suffix)."""
    net_blob = net_name.encode("cp949") + b"\x00"
    network = bytearray(0x14)
    struct.pack_into("<IIIII", network, 0, 0x14 + len(net_blob), 0x2, 0x14, 0, 0x00020000)
    network_blob = bytes(network) + net_blob
    header_size = 0x1C
    suffix_blob = suffix.encode("cp949") + b"\x00"
    total = header_size + len(network_blob) + len(suffix_blob)
    block = bytearray(header_size)
    struct.pack_into("<IIIIIII", block, 0, total, header_size, 0x2, 0, 0, header_size, header_size + len(network_blob))
    return bytes(block) + network_blob + suffix_blob


def tracker_block(machine: str) -> bytes:
    block = bytearray(0x60)
    struct.pack_into("<IIII", block, 0, 0x60, 0xA0000003, 0x58, 0)
    block[0x10:0x20] = machine.encode("ascii").ljust(16, b"\x00")
    file_droid = uuid.UUID("2c4c5e46-3c0d-11ec-b0c8-a4bb6d5a1f20")  # version 1, node a4:bb:6d:5a:1f:20
    block[0x20:0x30] = uuid.uuid4().bytes_le
    block[0x30:0x40] = file_droid.bytes_le
    block[0x40:0x50] = uuid.uuid4().bytes_le
    block[0x50:0x60] = file_droid.bytes_le
    return bytes(block)


def property_store_block(name_display: str) -> bytes:
    value = utf16z(name_display)
    typed = struct.pack("<HHI", 0x1F, 0, len(value) // 2) + value
    serialized = struct.pack("<IIB", 9 + len(typed), 10, 0) + typed
    storage = struct.pack("<I4s", 24 + len(serialized) + 4, b"1SPS") + uuid.UUID("b725f130-47ef-101a-a5f1-02608c9eebac").bytes_le
    storage += serialized + b"\x00\x00\x00\x00"
    payload = storage + b"\x00\x00\x00\x00"
    return struct.pack("<II", 8 + len(payload), 0xA0000009) + payload


def known_folder_block(folder_id: str) -> bytes:
    return struct.pack("<II", 0x1C, 0xA000000B) + uuid.UUID(folder_id).bytes_le + struct.pack("<I", 0)


def build_lnk(link_info: bytes, *, extra: bytes = b"", created: datetime, accessed: datetime, modified: datetime) -> bytes:
    flags = 0x2 | 0x10 | 0x80
    header = lnk_header(flags, created=created, accessed=accessed, modified=modified)
    working_dir = "C:\\Users\\user\\Downloads"
    strings = struct.pack("<H", len(working_dir)) + working_dir.encode("utf-16le")
    return bytes(header) + link_info + strings + extra + b"\x00\x00\x00\x00"


TARGET_TIMES = {
    "created": datetime(2025, 5, 19, 12, 49, 0, 503712, tzinfo=timezone.utc),
    "accessed": datetime(2025, 5, 19, 12, 49, 2, 604936, tzinfo=timezone.utc),
    "modified": datetime(2025, 5, 19, 12, 48, 57, 428945, tzinfo=timezone.utc),
}


class ShellLinkParserQualityTests(unittest.TestCase):
    def test_volume_id_unicode_paths_tracker_property_store_known_folder(self) -> None:
        data = build_lnk(
            link_info_local(0xA8F6F975, "로컬 디스크", "C:\\Users\\user\\Downloads\\", "출고 내역.jpg"),
            extra=tracker_block("desktop-8g0u3vi")
            + property_store_block("출고 내역.jpg")
            + known_folder_block("374de290-123f-4565-9164-39c4925e467b"),
            **TARGET_TIMES,
        )
        details = parse_lnk_metadata_from_bytes(data)
        self.assertEqual(details["lnk_parse_status"], "parsed")
        self.assertEqual(details["target_path"], "C:\\Users\\user\\Downloads\\출고 내역.jpg")
        self.assertEqual(details["volume_serial_number"], "A8F6F975")
        self.assertEqual(details["drive_type_name"], "fixed")
        self.assertEqual(details["volume_label"], "로컬 디스크")
        self.assertEqual(details["working_dir"], "C:\\Users\\user\\Downloads")
        self.assertEqual(details["tracker_machine_id"], "desktop-8g0u3vi")
        self.assertEqual(details["tracker_droid_file_mac_address"], "a4:bb:6d:5a:1f:20")
        self.assertEqual(details["target_created_at"], "2025-05-19T12:49:00.503712+00:00")
        self.assertEqual(details["target_accessed_at"], "2025-05-19T12:49:02.604936+00:00")
        self.assertEqual(details["target_modified_at"], "2025-05-19T12:48:57.428945+00:00")
        properties = details["property_store_blocks"][0]["properties"]
        self.assertEqual(properties[0]["name"], "System.ItemNameDisplay")
        self.assertEqual(properties[0]["value"], "출고 내역.jpg")
        self.assertEqual(details["known_folder_ids"][0]["name"], "Downloads")

    def test_network_link_rebuilds_unc_target_from_netname(self) -> None:
        data = build_lnk(link_info_network("\\\\192.168.0.100\\USERS", "Public\\병원문서\\진료부\\가정의학과"), **TARGET_TIMES)
        details = parse_lnk_metadata_from_bytes(data)
        self.assertEqual(details["net_name"], "\\\\192.168.0.100\\USERS")
        self.assertEqual(details["target_path"], "\\\\192.168.0.100\\USERS\\Public\\병원문서\\진료부\\가정의학과")
        self.assertEqual(details["link_info"]["full_path_source"], "net-name+common-path-suffix")

    def test_filetime_conversion_is_integer_and_pre_1970_safe(self) -> None:
        self.assertEqual(windows_filetime_to_iso(to_filetime(datetime(1960, 1, 2, 3, 4, 5, 123456, tzinfo=timezone.utc))), "1960-01-02T03:04:05.123456+00:00")
        # 100 ns remainder truncates, never rounds up (float conversion produced ...937 for ...936).
        self.assertEqual(windows_filetime_to_iso(to_filetime(TARGET_TIMES["accessed"]) + 9), "2025-05-19T12:49:02.604936+00:00")

    def test_recent_scope_location_labels_and_invalid_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            recent = root / "Users" / "user" / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent"
            recent.mkdir(parents=True)
            good = build_lnk(link_info_local(0x06D53E29, "", "D:\\", "병원 관련 서류\\위례마음병원사인시안-최종.ai"), **TARGET_TIMES)
            (recent / "위례마음병원사인시안-최종.ai.lnk").write_bytes(good)
            (recent / "20250401.txt.lnk").write_bytes("2025-04-01 진료 메모\r\n".encode() * 20)
            desktop = root / "Users" / "user" / "Desktop"
            desktop.mkdir(parents=True)
            (desktop / "eGhis.lnk").write_bytes(good)
            sendto = root / "Users" / "Default" / "AppData" / "Roaming" / "Microsoft" / "Windows" / "SendTo"
            sendto.mkdir(parents=True)
            (sendto / "TeamViewer.lnk").write_bytes(good)
            rows = list(WindowsRecentFilesProvider().collect(root))
        by_name = {Path(row.path).name + "|" + row.details["user"]: row for row in rows}
        recent_row = by_name["위례마음병원사인시안-최종.ai.lnk|user"]
        self.assertEqual(recent_row.artifact_type, "recent-shortcut")
        self.assertEqual(recent_row.details["location"], "recent")
        self.assertEqual(recent_row.details["target_path"], "D:\\병원 관련 서류\\위례마음병원사인시안-최종.ai")
        self.assertEqual(recent_row.details["timestamp"], "2025-05-19T12:49:02.604936+00:00")
        self.assertEqual(recent_row.details["timestamp_source"], "target_accessed_at")
        self.assertNotIn("modified_at", recent_row.details)
        invalid = by_name["20250401.txt.lnk|user"]
        self.assertEqual(invalid.artifact_type, "recent-shortcut-invalid-content")
        self.assertEqual(invalid.details["detected_content_kind"], "text")
        self.assertEqual(invalid.details["target_path"], "")
        self.assertEqual(by_name["eGhis.lnk|user"].artifact_type, "shell-shortcut")
        self.assertEqual(by_name["eGhis.lnk|user"].details["location"], "desktop")
        template = by_name["TeamViewer.lnk|Default"]
        self.assertEqual(template.details["location"], "sendto")
        self.assertTrue(template.details["profile_template"])


# --------------------------------------------------------------------------
# DestList builders
# --------------------------------------------------------------------------


def destlist_v3_entry(*, number: int, host: bytes, path: str, modified: datetime, pin: int, access_count: int) -> bytes:
    entry = bytearray(0x82)
    struct.pack_into("<Q", entry, 0, 0x1122334455667788)
    entry[0x08:0x18] = uuid.uuid4().bytes_le
    entry[0x18:0x28] = uuid.UUID("2c4c5e46-3c0d-11ec-b0c8-a4bb6d5a1f20").bytes_le
    entry[0x28:0x38] = uuid.uuid4().bytes_le
    entry[0x38:0x48] = uuid.uuid4().bytes_le
    entry[0x48 : 0x48 + len(host)] = host
    struct.pack_into("<I", entry, 0x58, number)
    struct.pack_into("<Q", entry, 0x64, to_filetime(modified))
    struct.pack_into("<i", entry, 0x6C, pin)
    struct.pack_into("<I", entry, 0x70, 0xFFFFFFFF)
    struct.pack_into("<I", entry, 0x74, access_count)
    struct.pack_into("<H", entry, 0x80, len(path))
    return bytes(entry) + path.encode("utf-16le") + b"\x00\x00\x00\x00"


DESTLIST_ENTRIES = [
    {"number": 1, "host": "진료실1".encode("cp949"), "path": "D:\\병원 관련 서류\\위례마음병원사인시안-최종.ai",
     "modified": datetime(2021, 12, 13, 6, 40, 22, 536886, tzinfo=timezone.utc), "pin": -1, "access_count": 1},
    {"number": 10, "host": b"desktop-8g0u3vi", "path": "C:\\Users\\user\\Documents\\사업자등록증.jpg",
     "modified": datetime(2021, 12, 10, 7, 11, 51, 955008, tzinfo=timezone.utc), "pin": 0, "access_count": 7},
    {"number": 11, "host": b"", "path": "knownfolder:{4BD8D571-6D19-48D3-BE97-422220080E43}",
     "modified": datetime(2022, 8, 12, 5, 0, 52, 581435, tzinfo=timezone.utc), "pin": -1, "access_count": 2},
]


def build_destlist_v3(entries: list[dict]) -> bytes:
    header = bytearray(32)
    struct.pack_into("<IIiIII", header, 0, 4, len(entries), 1, 0, max(item["number"] for item in entries), 0)
    return bytes(header) + b"".join(destlist_v3_entry(**item) for item in entries)


class JumpListParserQualityTests(unittest.TestCase):
    def test_destlist_v3_entries_hostname_cp949_access_count_and_stream_join(self) -> None:
        lnk_a = build_lnk(link_info_local(0x06D53E29, "", "D:\\", "병원 관련 서류\\위례마음병원사인시안-최종.ai"), **TARGET_TIMES)
        lnk_b = build_lnk(link_info_local(0xA8F6F975, "", "C:\\Users\\user\\Documents\\", "사업자등록증.jpg"), **TARGET_TIMES)
        container = build_minimal_ole_jumplist_streams([("DestList", build_destlist_v3(DESTLIST_ENTRIES)), ("1", lnk_a), ("a", lnk_b)])
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            automatic = root / "Users" / "user" / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent" / "AutomaticDestinations"
            automatic.mkdir(parents=True)
            (automatic / "12dc1ea8e34b5a6.automaticDestinations-ms").write_bytes(container)
            rows = list(WindowsRecentFilesProvider().collect(root))
        container_row = next(row for row in rows if row.artifact_type == "jumplist-automatic")
        self.assertEqual(container_row.details["destlist_layout_status"], "decoded-destlist-v4")
        self.assertEqual(container_row.details["destlist_entry_candidate_count"], 3)
        self.assertEqual(container_row.details["destinations_total"], 2)
        entries = [row.details for row in rows if row.artifact_type == "jumplist-entry"]
        self.assertEqual(len(entries), 3)
        first, second, third = entries
        self.assertEqual(first["destlist_hostname"], "진료실1")
        self.assertEqual(first["destlist_hostname_encoding"], "cp949")
        self.assertEqual(first["destlist_path"], "D:\\병원 관련 서류\\위례마음병원사인시안-최종.ai")
        self.assertEqual(first["destlist_last_modified_at"], "2021-12-13T06:40:22.536886+00:00")
        self.assertEqual(first["timestamp"], first["destlist_last_modified_at"])
        self.assertEqual(first["destlist_access_count"], 1)
        self.assertFalse(first["destlist_pinned"])
        self.assertEqual(first["target_path"], "D:\\병원 관련 서류\\위례마음병원사인시안-최종.ai")
        self.assertEqual(first["volume_serial_number"], "06D53E29")
        self.assertEqual(second["destlist_entry_number"], 10)
        self.assertEqual(second["lnk_stream_name"], "a")
        self.assertTrue(second["lnk_stream_present"])
        self.assertEqual(second["destlist_hostname"], "desktop-8g0u3vi")
        self.assertEqual(second["destlist_access_count"], 7)
        self.assertTrue(second["destlist_pinned"])
        self.assertEqual(second["destlist_file_droid_mac_address"], "a4:bb:6d:5a:1f:20")
        self.assertEqual(second["target_path"], "C:\\Users\\user\\Documents\\사업자등록증.jpg")
        self.assertEqual(third["lnk_stream_name"], "b")
        self.assertFalse(third["lnk_stream_present"])
        self.assertNotIn("target_path", third)

    def test_destlist_v1_layout(self) -> None:
        path = "C:\\Users\\alice\\보고서.docx"
        entry = bytearray(0x72)
        entry[0x48:0x50] = b"ALICEPC\x00"
        struct.pack_into("<I", entry, 0x58, 2)
        struct.pack_into("<f", entry, 0x60, 3.0)
        struct.pack_into("<Q", entry, 0x64, to_filetime(datetime(2014, 1, 2, tzinfo=timezone.utc)))
        struct.pack_into("<i", entry, 0x6C, -1)
        struct.pack_into("<H", entry, 0x70, len(path))
        header = bytearray(32)
        struct.pack_into("<II", header, 0, 1, 1)
        data = bytes(header) + bytes(entry) + path.encode("utf-16le")
        metadata = parse_destlist_metadata([{"name": "DestList", "path": "DestList", "index": 1, "size": len(data), "start_sector": 0, "data": data}])
        candidate = metadata["destlist_entry_candidates"][0]
        self.assertEqual(metadata["destlist_layout_status"], "decoded-destlist-v1")
        self.assertEqual(candidate["path"], path)
        self.assertEqual(candidate["entry_number"], 2)
        self.assertEqual(candidate["hostname"], "ALICEPC")
        self.assertEqual(candidate["access_count_float_v1"], 3.0)
        self.assertEqual(candidate["last_modified_at"], "2014-01-02T00:00:00+00:00")

    def test_cfb_directory_ids_survive_unused_slots(self) -> None:
        def entry(name: str, object_type: int, right: int = 0xFFFFFFFF) -> bytes:
            raw = bytearray(128)
            encoded = utf16z(name)
            raw[: len(encoded)] = encoded
            struct.pack_into("<HB", raw, 64, len(encoded), object_type)
            struct.pack_into("<III", raw, 68, 0xFFFFFFFF, right, 0xFFFFFFFF)
            return bytes(raw)

        directory = entry("Root Entry", 5) + bytes(128) + entry("DestList", 2)
        entries = parse_cfb_directory_entries(directory)
        self.assertEqual(len(entries), 3)
        self.assertEqual(entries[2]["name"], "DestList")
        self.assertEqual(entries[1]["type"], 0)


# --------------------------------------------------------------------------
# Signature scan, WER, minidump, naive times, remote access
# --------------------------------------------------------------------------


class SignatureScanParserQualityTests(unittest.TestCase):
    def test_full_scan_flags_true_mismatches_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "Windows" / "Prefetch").mkdir(parents=True)
            (root / "Windows" / "Prefetch" / "A.EXE-00000001.pf").write_bytes(b"\xff\xd8\xff\xe0" + b"\x01" * 600)
            (root / "Windows" / "Prefetch" / "B.EXE-00000002.pf").write_bytes(b"\x00" * 600)
            (root / "Windows" / "Prefetch" / "C.EXE-00000003.pf").write_bytes(build_scca(paths=["\\V\\X"], run_times=RUN_TIMES[:1], run_count_c8=1))
            (root / "notes.lnk").write_bytes("메모".encode() * 100)
            (root / "thumbcache_idx").write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 64)  # extensionless: skipped
            (root / "~$보고서.docx").write_bytes(b"\x0cuser" + b"\x00" * 100)  # Office lock file: skipped
            (root / "photo.jpg").write_bytes(b"\xff\xd8\xff\xe0" + b"\x01" * 64)
            rows = list(collect_signature_mismatch_artifacts(root))
        mismatches = {Path(row.path).name: row.details for row in rows if row.artifact_type == "file-signature-mismatch"}
        self.assertEqual({row.artifact_type for row in rows}, {"file-signature-mismatch"})
        summary = mismatches["notes.lnk"]["signature_scan_summary"]
        self.assertEqual(set(mismatches), {"A.EXE-00000001.pf", "B.EXE-00000002.pf", "notes.lnk"})
        self.assertEqual(mismatches["A.EXE-00000001.pf"]["detected_signature_kind"], "jpeg")
        self.assertEqual(mismatches["A.EXE-00000001.pf"]["mismatch_direction"], "magic-not-expected-for-extension")
        self.assertEqual(mismatches["B.EXE-00000002.pf"]["detected_signature_kind"], "zero-filled")
        self.assertEqual(mismatches["notes.lnk"]["mismatch_direction"], "extension-expected-signature-missing")
        self.assertEqual(summary["skipped_extensionless"], 1)
        self.assertEqual(summary["skipped_office_owner_lock_files"], 1)
        self.assertIsNone(summary["file_count_cap"])
        self.assertEqual(summary["mismatch_count"], 3)
        with tempfile.TemporaryDirectory() as tmp_dir:
            clean = Path(tmp_dir)
            (clean / "photo.jpg").write_bytes(b"\xff\xd8\xff\xe0" + b"\x01" * 64)
            self.assertEqual(list(collect_signature_mismatch_artifacts(clean)), [])

    def test_content_kinds_are_names(self) -> None:
        self.assertEqual(sniff_content_kind(b"MZ\x90\x00")["kind"], "windows-pe")
        self.assertEqual(sniff_content_kind(b"\n\n%PDF-1.4\r")["kind"], "pdf")
        self.assertEqual(sniff_content_kind(os.urandom(4096))["kind"], "high-entropy-binary")


def build_wer_report(event_time: int) -> bytes:
    lines = [
        "Version=1",
        "EventType=APPCRASH",
        f"EventTime={event_time}",
        "ReportType=2",
        "Sig[0].Name=패키지 전체 이름",
        "Sig[0].Value=Microsoft.Photos_2025.1.0.0_x64",
        "Sig[1].Name=응용 프로그램 이름",
        "Sig[1].Value=Photos.exe",
        "Sig[4].Name=오류 모듈 이름",
        "Sig[4].Value=KERNELBASE.dll",
        "Sig[7].Name=예외 코드",
        "Sig[7].Value=c000027b",
        "Sig[8].Name=예외 오프셋",
        "Sig[8].Value=00000000000d8b4c",
    ]
    lines += [f"LoadedModule[{index}]=C:\\Windows\\System32\\module{index}.dll" for index in range(320)]
    lines += ["FriendlyEventName=작동이 중지됨", "AppName=Microsoft 사진", "AppPath=C:\\Program Files\\WindowsApps\\Photos.exe"]
    return "\ufeff".encode("utf-16le") + "\r\n".join(lines).encode("utf-16le")


class SystemParserQualityTests(unittest.TestCase):
    def test_wer_utf16_report_event_time_and_late_app_fields(self) -> None:
        event_time = to_filetime(datetime(2025, 5, 28, 23, 35, 57, 123456, tzinfo=timezone.utc))
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            report = root / "ProgramData" / "Microsoft" / "Windows" / "WER" / "ReportArchive" / "AppCrash_Photos" / "Report.wer"
            report.parent.mkdir(parents=True)
            report.write_bytes(build_wer_report(event_time))
            rows = [row for row in WindowsSystemArtifactsProvider().collect(root) if row.artifact_type == "wer-report"]
        details = rows[0].details
        self.assertEqual(details["event_time"], "2025-05-28T23:35:57.123456+00:00")
        self.assertEqual(details["timestamp"], details["event_time"])
        self.assertEqual(details["timestamp_kind"], "event")
        self.assertEqual(details["application_name"], "Microsoft 사진")
        self.assertEqual(details["application_path"], "C:\\Program Files\\WindowsApps\\Photos.exe")
        self.assertEqual(details["fault_module_name"], "KERNELBASE.dll")
        self.assertEqual(details["exception_code"], "c000027b")
        self.assertEqual(details["exception_offset"], "00000000000d8b4c")
        self.assertEqual(details["loaded_module_count"], 320)
        self.assertNotIn("modified_at", details)

    def test_naive_text_times_are_not_shifted_by_host_timezone(self) -> None:
        parsed = normalize_sqlite_time_value("2024-01-02 03:04:05")
        self.assertEqual(parsed["iso8601"], "2024-01-02T03:04:05")
        self.assertEqual(parsed["timezone"], "unknown")
        self.assertEqual(normalize_sqlite_time_value("2024-01-02T03:04:05+09:00")["iso8601"], "2024-01-01T18:04:05+00:00")
        self.assertEqual(wer_time_to_iso("2024-01-02T03:04:05"), "2024-01-02T03:04:05")

    def test_minidump_header_and_streams(self) -> None:
        streams: list[tuple[int, bytes]] = []
        system_info = bytearray(56)
        struct.pack_into("<HHHBBIIII", system_info, 0, 9, 6, 0, 8, 1, 10, 0, 26100, 2)
        streams.append((7, bytes(system_info)))
        misc = struct.pack("<IIIIII", 24, 0x3, 4536, 1748474093, 1, 2)
        streams.append((15, misc))
        exception = bytearray(168)
        struct.pack_into("<IIII", exception, 0, 7792, 0, 0xC0000374, 1)
        struct.pack_into("<Q", exception, 24, 0x00007FFBEB03E0E5)
        streams.append((6, bytes(exception)))
        streams.append((3, struct.pack("<I", 68)))
        module_count_blob = struct.pack("<I", 1)
        module = bytearray(108)
        struct.pack_into("<QIII", module, 0, 0x00007FF727740000, 4317184, 4359541, 1723083492)
        struct.pack_into("<IIII", module, 24, 0xFEEF04BD, 0x10000, (2 << 16) | 5, (0 << 16) | 261)
        streams.append((4, module_count_blob + bytes(module)))
        directory_rva = 32
        data_rva = directory_rva + 12 * len(streams)
        directory = b""
        body = b""
        name_rvas = []
        for stream_type, payload in streams:
            directory += struct.pack("<III", stream_type, len(payload), data_rva + len(body))
            if stream_type == 4:
                name_rvas.append(data_rva + len(body) + 4 + 20)
            body += payload
        name = "C:\\Program Files\\AhnLab\\ASDSvc.exe".encode("utf-16le")
        name_rva = data_rva + len(body)
        body += struct.pack("<I", len(name)) + name
        blob = bytearray(struct.pack("<4sIIIII", b"MDMP", 0xA793, len(streams), directory_rva, 0, 1748475357) + b"\x00" * 8 + directory + body)
        struct.pack_into("<I", blob, name_rvas[0], name_rva)
        header = parse_minidump_header(bytes(blob))
        self.assertEqual(header["minidump_parse_status"], "parsed")
        self.assertEqual(header["minidump_stream_count"], 5)
        self.assertEqual(header["minidump_created_at"], "2025-05-28T23:35:57+00:00")
        self.assertEqual(header["minidump_process_id"], 4536)
        self.assertEqual(header["minidump_process_create_time"], "2025-05-28T23:14:53+00:00")
        self.assertEqual(header["minidump_exception_code"], "0xC0000374")
        self.assertEqual(header["minidump_exception_address"], "0x00007FFBEB03E0E5")
        self.assertEqual(header["minidump_exception_thread_id"], 7792)
        self.assertEqual(header["minidump_os_version"], "10.0.26100")
        self.assertEqual(header["minidump_processor_architecture"], "x64")
        self.assertEqual(header["minidump_thread_count"], 68)
        self.assertEqual(header["minidump_modules"][0]["name"], "C:\\Program Files\\AhnLab\\ASDSvc.exe")
        self.assertEqual(header["minidump_modules"][0]["file_version"], "2.5.0.261")
        self.assertEqual(parse_minidump_header(b"PAGEDU64")["minidump_parse_status"], "not-minidump")


class RemoteAccessParserQualityTests(unittest.TestCase):
    def test_remote_control_rows_use_artifact_times_and_have_one_owner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            prefetch = root / "Windows" / "Prefetch"
            prefetch.mkdir(parents=True)
            (prefetch / "TEAMVIEWER.EXE-15FF374D.pf").write_bytes(
                build_scca(executable="TEAMVIEWER.EXE", paths=["\\V\\PROGRAM FILES\\TEAMVIEWER\\TEAMVIEWER.EXE"], run_times=RUN_TIMES, run_count_c8=9)
            )
            sendto = root / "Users" / "Default" / "AppData" / "Roaming" / "Microsoft" / "Windows" / "SendTo"
            sendto.mkdir(parents=True)
            (sendto / "TeamViewer.lnk").write_bytes(
                build_lnk(link_info_local(0xA8F6F975, "", "C:\\Program Files\\TeamViewer\\", "TeamViewer.exe"), **TARGET_TIMES)
            )
            remote_rows = list(WindowsRemoteAccessProvider().collect(root))
            system_rows = list(WindowsSystemArtifactsProvider().collect(root))
        by_name = {Path(row.path).name: row.details for row in remote_rows if row.artifact_type == "third-party-remote-control-artifact"}
        pf = by_name["TEAMVIEWER.EXE-15FF374D.pf"]
        self.assertEqual(pf["run_count"], 9)
        self.assertEqual(pf["timestamp"], RUN_TIMES[0].isoformat())
        self.assertEqual(pf["timestamp_source"], "prefetch_last_run_time")
        lnk = by_name["TeamViewer.lnk"]
        self.assertEqual(lnk["timestamp"], "2025-05-19T12:49:02.604936+00:00")
        self.assertTrue(lnk["profile_template"])
        self.assertEqual(lnk["session_candidates"], [])
        self.assertNotIn("remote-control-session-candidate", lnk["risk_flags"])
        self.assertIn("default-profile-template", lnk["risk_flags"])
        self.assertFalse(any(row.artifact_type == "third-party-remote-control-artifact" for row in system_rows))


if __name__ == "__main__":
    unittest.main()
