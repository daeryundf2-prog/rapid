"""R3 O2: pure-Python MAM (XPRESS Huffman) decompression and full Prefetch decoding.

Every fixture is synthetic: SCCA streams are built in-test from the
documented v23/v30/v31 layouts and compressed with the tiny test encoder in
``tests.xpress_huffman_encoder`` (no OS API), so the suite runs on any host.
"""

from __future__ import annotations

import os
import struct
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from rapidtriage.artifacts.windows import xpress_huffman
from rapidtriage.artifacts.windows.prefetch import (
    MAX_REFERENCED_FILES,
    WindowsPrefetchProvider,
    decompress_mam_prefetch,
    prefetch_header_hints,
)
from rapidtriage.artifacts.windows.xpress_huffman import XpressHuffmanError, decompress
from rapidtriage.core.triage_rules.base import FlagContext, RowView
from rapidtriage.core.triage_rules.execution import (
    RunCountSpike,
    SuspiciousPath,
    prefetch_executable_path,
)
from tests.xpress_huffman_encoder import compress, mam

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
VOLUME = "\\VOLUME{01d75b57f6c404f3-a8f6f975}"
BURST = [datetime(2024, 5, 1, 10, 40, tzinfo=timezone.utc) - timedelta(minutes=5 * index) for index in range(8)]
VOLUME_CREATED = datetime(2021, 6, 7, 4, 45, 39, 104280, tzinfo=timezone.utc)


def to_filetime(moment: datetime) -> int:
    delta = moment - FILETIME_EPOCH
    return (delta.days * 86_400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


def utf16z(text: str) -> bytes:
    return text.encode("utf-16le") + b"\x00\x00"


# Per-version layout: (file information end = metrics offset, run count offset,
# run-time slots, metrics entry size, trace entry size, volume entry size).
LAYOUTS = {
    23: (0xF0, 0x98, 1, 32, 12, 104),
    30: (0x130, 0xD0, 8, 32, 8, 96),
    31: (0x128, 0xC8, 8, 32, 8, 96),
}


def build_pf(
    *,
    version: int,
    executable: str,
    paths: list[str],
    run_times: list[datetime],
    run_count: int,
    volumes: list[tuple[str, int, datetime, list[str]]],
    trace_chains: int = 6,
) -> bytes:
    """Decompressed SCCA stream with metrics, trace chains, strings and volume entries."""
    metrics_offset, run_count_offset, slots, metric_size, trace_size, volume_size = LAYOUTS[version]
    filename_blob = b""
    names: list[tuple[int, int]] = []
    for path in paths:
        names.append((len(filename_blob), len(path)))
        filename_blob += utf16z(path)
    metrics = bytearray()
    for index, (offset, chars) in enumerate(names):
        entry = bytearray(metric_size)
        # trace start, trace count, unknown, name offset, name chars, flags, MFT reference
        struct.pack_into("<IIIIII", entry, 0, index, 1, 0, offset, chars, 0x200)
        struct.pack_into("<Q", entry, 24, (5 << 48) | (2000 + index))
        metrics += entry
    trace_offset = metrics_offset + len(metrics)
    trace_blob = bytes(trace_chains * trace_size)
    filename_offset = trace_offset + len(trace_blob)
    volume_offset = filename_offset + len(filename_blob)
    volume_offset += (-volume_offset) % 8
    entries = bytearray(volume_size * len(volumes))
    strings = b""
    base = volume_size * len(volumes)
    for index, (device, serial, created, directories) in enumerate(volumes):
        device_rel = base + len(strings)
        strings += utf16z(device)
        dirs_rel = base + len(strings)
        strings += b"".join(struct.pack("<H", len(item)) + utf16z(item) for item in directories)
        struct.pack_into(
            "<IIQIIIII", entries, index * volume_size,
            device_rel, len(device), to_filetime(created), serial, 0, 0, dirs_rel, len(directories),
        )
    volume_blob = bytes(entries) + strings
    total = volume_offset + len(volume_blob)
    blob = bytearray(total)
    struct.pack_into("<I4s", blob, 0, version, b"SCCA")
    struct.pack_into("<I", blob, 0x0C, total)
    name = executable.encode("utf-16le")[:58]
    blob[0x10 : 0x10 + len(name)] = name
    struct.pack_into("<I", blob, 0x4C, 0x1A2B3C4D)
    struct.pack_into(
        "<9I", blob, 0x54,
        metrics_offset, len(paths), trace_offset, trace_chains,
        filename_offset, len(filename_blob), volume_offset, len(volumes), len(volume_blob),
    )
    for index, moment in enumerate(run_times[:slots]):
        struct.pack_into("<Q", blob, 0x80 + index * 8, to_filetime(moment))
    struct.pack_into("<I", blob, run_count_offset, run_count)
    blob[metrics_offset : metrics_offset + len(metrics)] = metrics
    blob[trace_offset : trace_offset + len(trace_blob)] = trace_blob
    blob[filename_offset : filename_offset + len(filename_blob)] = filename_blob
    blob[volume_offset : volume_offset + len(volume_blob)] = volume_blob
    return bytes(blob)


def tool_paths(executable: str, folder: str = "USERS\\KIM\\DOWNLOADS") -> list[str]:
    return [
        f"{VOLUME}\\WINDOWS\\SYSTEM32\\NTDLL.DLL",
        f"{VOLUME}\\WINDOWS\\SYSTEM32\\KERNEL32.DLL",
        f"{VOLUME}\\{folder}\\{executable}",
        f"{VOLUME}\\USERS\\KIM\\DESKTOP\\고객 명단.XLSX",
    ]


def two_volumes() -> list[tuple[str, int, datetime, list[str]]]:
    return [
        (VOLUME, 0xA8F6F975, VOLUME_CREATED, [f"{VOLUME}\\USERS", f"{VOLUME}\\USERS\\KIM\\바탕 화면"]),
        ("\\VOLUME{01d9aa00aa00aa00-5e5e5e5e}", 0x5E5E5E5E, datetime(2023, 1, 2, 3, 4, 5, tzinfo=timezone.utc), ["\\VOLUME{01d9aa00aa00aa00-5e5e5e5e}\\TOOLS"]),
    ]


class XpressHuffmanTests(unittest.TestCase):
    def test_round_trip_literals_matches_and_multiple_blocks(self) -> None:
        samples = [
            b"a",
            b"SCCA" * 5000,
            bytes(range(256)) * 600,  # > 2 blocks of 64 KiB
            os.urandom(4096),
            b"x" * 300 + os.urandom(64) + b"y" * 70000,  # long matches: 1-byte and u16 length extensions
        ]
        for data in samples:
            for flat in (False, True):
                with self.subTest(size=len(data), flat=flat):
                    self.assertEqual(decompress(compress(data, flat=flat), len(data)), data)

    def test_u32_length_extension(self) -> None:
        data = b"z" * 5000
        self.assertEqual(decompress(compress(data, force_u32_lengths=True), len(data)), data)

    def test_declared_size_is_checked_before_allocation(self) -> None:
        with self.assertRaises(XpressHuffmanError):
            decompress(b"\x00" * 300, xpress_huffman.MAX_OUTPUT_BYTES + 1)
        status = decompress_mam_prefetch(b"MAM\x04" + struct.pack("<I", 0xFFFFFFF0) + b"\x00" * 300)[1]
        self.assertEqual(status["status"], "declared-size-out-of-bounds")

    def test_corrupt_huffman_tables_are_rejected(self) -> None:
        data = b"hello prefetch " * 50
        stream = bytearray(compress(data))
        cases = {
            "empty table": bytes(256) + stream[256:],
            # every symbol 1 bit long: 512 codes for a 2-code space
            "over-subscribed": bytes([0x11]) * 256 + stream[256:],
            "short table": stream[:100],
        }
        for label, blob in cases.items():
            with self.subTest(label), self.assertRaises(XpressHuffmanError):
                decompress(bytes(blob), len(data))

    def test_incomplete_table_code_and_bad_offsets_never_loop(self) -> None:
        # Only symbol 'A' (length 1): code "1" is not in the table.
        table = bytearray(256)
        table[ord("A") // 2] = 0x01 if ord("A") % 2 == 0 else 0x10
        with self.assertRaises(XpressHuffmanError):
            decompress(bytes(table) + b"\xff\xff\xff\xff", 10)
        # Only a match symbol (offset bits 4) as the very first symbol: points before the output.
        table = bytearray(256)
        symbol = 256 + (4 << 4)
        table[symbol // 2] = 0x01 if symbol % 2 == 0 else 0x10
        with self.assertRaises(XpressHuffmanError):
            decompress(bytes(table) + bytes(8), 10)

    def test_truncated_stream_raises_instead_of_padding_forever(self) -> None:
        data = os.urandom(2000)
        stream = compress(data)
        with self.assertRaises(XpressHuffmanError):
            decompress(stream[: len(stream) // 2], len(data))

    def test_random_garbage_terminates(self) -> None:
        for _ in range(20):
            blob = os.urandom(600)
            try:
                decompress(blob, 4096)
            except XpressHuffmanError:
                pass

    @unittest.skipUnless(os.name == "nt", "cross-check against ntdll RtlDecompressBufferEx")
    def test_encoder_output_is_accepted_by_windows(self) -> None:
        import ctypes

        data = b"abc" * 4000 + os.urandom(500) + b"q" * 3000
        stream = compress(data)
        ntdll = ctypes.windll.ntdll
        compress_ws, fragment_ws = ctypes.c_uint32(), ctypes.c_uint32()
        ntdll.RtlGetCompressionWorkSpaceSize(ctypes.c_uint16(4), ctypes.byref(compress_ws), ctypes.byref(fragment_ws))
        source = (ctypes.c_ubyte * len(stream)).from_buffer_copy(stream)
        target = (ctypes.c_ubyte * len(data))()
        final = ctypes.c_uint32()
        workspace = (ctypes.c_ubyte * fragment_ws.value)()
        rc = ntdll.RtlDecompressBufferEx(
            ctypes.c_uint16(4), ctypes.byref(target), ctypes.c_uint32(len(data)), ctypes.byref(source),
            ctypes.c_uint32(len(stream)), ctypes.byref(final), ctypes.byref(workspace),
        )
        self.assertEqual(rc, 0)
        self.assertEqual(bytes(target[: final.value]), data)


class PrefetchFullDecodeTests(unittest.TestCase):
    def collect(self, files: dict[str, bytes]) -> list:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        prefetch_dir = Path(tmp.name) / "Windows" / "Prefetch"
        prefetch_dir.mkdir(parents=True)
        for name, data in files.items():
            (prefetch_dir / name).write_bytes(data)
        return list(WindowsPrefetchProvider().collect(Path(tmp.name)))

    def file_row(self, rows: list):
        return next(row for row in rows if row.artifact_type == "prefetch-file").details

    def test_compressed_v30_decodes_run_count_times_volumes_files_and_traces(self) -> None:
        paths = tool_paths("MIMIKATZ.EXE")
        inner = build_pf(version=30, executable="MIMIKATZ.EXE", paths=paths, run_times=BURST, run_count=42, volumes=two_volumes())
        rows = self.collect({"MIMIKATZ.EXE-1A2B3C4D.pf": mam(inner)})
        details = self.file_row(rows)
        self.assertEqual(details["prefetch_decompression"]["status"], "decompressed")
        self.assertEqual(details["prefetch_decompression"]["method"], "pure-python-xpress-huffman")
        self.assertEqual(details["prefetch_version"], 30)
        self.assertEqual(details["run_count"], 42)
        self.assertEqual(details["last_run_times"], [moment.isoformat() for moment in BURST])
        self.assertEqual(details["last_run_at"], BURST[0].isoformat())
        self.assertEqual([volume["volume_serial_number"] for volume in details["volumes"]], ["A8F6F975", "5E5E5E5E"])
        self.assertEqual(details["volumes"][0]["volume_created_at"], VOLUME_CREATED.isoformat())
        self.assertEqual(details["volumes"][0]["volume_device_path"], VOLUME)
        self.assertEqual(details["volumes"][0]["directory_strings"][1], f"{VOLUME}\\USERS\\KIM\\바탕 화면")
        self.assertEqual(details["volumes"][1]["directory_strings"], ["\\VOLUME{01d9aa00aa00aa00-5e5e5e5e}\\TOOLS"])
        self.assertEqual([item["path"] for item in details["referenced_files"]], paths)
        self.assertEqual(details["referenced_files"][2]["mft_entry"], 2002)
        self.assertEqual(details["referenced_files"][2]["mft_sequence"], 5)
        self.assertEqual(details["referenced_file_count"], 4)
        self.assertEqual(details["trace_chain_count"], 6)
        self.assertEqual(details["trace_chain_status"], "counted")
        self.assertEqual(details["source_offset"], 0)
        self.assertEqual(details["source_offset_space"], "decompressed-scca")
        # source_offset of a referenced file points at its UTF-16 name in the decompressed stream.
        first = details["referenced_files"][0]
        decompressed = inner
        self.assertEqual(decompressed[first["source_offset"] : first["source_offset"] + len(paths[0]) * 2].decode("utf-16le"), paths[0])
        checks = details["prefetch_validation_checks"]
        self.assertTrue(checks["full_file_metrics_decoded"])
        self.assertTrue(checks["full_volume_table_decoded"])
        self.assertTrue(checks["trace_chains_counted"])
        self.assertTrue(checks["compressed_prefetch_decompressed"])
        self.assertTrue(details["prefetch_native_capabilities"]["compressed_prefetch_decompression"])
        self.assertEqual(details["prefetch_native_capabilities"]["compressed_prefetch_decompression_platform"], "pure-python-any-host")
        self.assertNotIn("compressed-not-decompressed", str(details["prefetch_section_bounds_profile"]))
        references = [row.details for row in rows if row.artifact_type == "prefetch-reference"]
        self.assertEqual([item["referenced_path"] for item in references], paths)
        self.assertEqual(references[3]["source_offset"], details["referenced_files"][3]["source_offset"])
        self.assertEqual(references[3]["source_offset_space"], "decompressed-scca")

    def test_compressed_v31_0x128_layout(self) -> None:
        paths = tool_paths("PSEXEC.EXE", folder="USERS\\PUBLIC")
        inner = build_pf(version=31, executable="PSEXEC.EXE", paths=paths, run_times=BURST[:3], run_count=3, volumes=two_volumes()[:1])
        hints = self.hint(mam(inner))
        self.assertEqual(hints["prefetch_version"], 31)
        self.assertEqual(hints["run_count"], 3)
        self.assertEqual(hints["run_count_offset"], 0xC8)
        self.assertEqual(len(hints["last_run_times"]), 3)
        self.assertEqual(hints["volume_count"], 1)
        self.assertEqual(hints["referenced_file_count"], 4)

    def test_uncompressed_v23_decodes_metrics_volumes_and_12_byte_traces(self) -> None:
        paths = tool_paths("NOTEPAD.EXE", folder="WINDOWS\\SYSTEM32")
        inner = build_pf(version=23, executable="NOTEPAD.EXE", paths=paths, run_times=BURST[:1], run_count=17, volumes=two_volumes(), trace_chains=4)
        hints = self.hint(inner)
        self.assertEqual(hints["prefetch_decompression"]["status"], "not-mam")
        self.assertEqual(hints["run_count"], 17)
        self.assertEqual(hints["last_run_times"], [BURST[0].isoformat()])
        self.assertEqual(hints["source_offset_space"], "file")
        self.assertEqual([item["path"] for item in hints["referenced_files"]], paths)
        self.assertEqual([volume["volume_serial_number"] for volume in hints["volumes"]], ["A8F6F975", "5E5E5E5E"])
        self.assertEqual(hints["trace_chain_count"], 4)
        self.assertEqual(hints["trace_chain_status"], "counted")

    def test_trace_chain_out_of_bounds_is_disclosed(self) -> None:
        inner = bytearray(build_pf(version=30, executable="A.EXE", paths=tool_paths("A.EXE"), run_times=BURST[:1], run_count=1, volumes=two_volumes()))
        struct.pack_into("<I", inner, 0x60, 0x0FFFFFFF)
        hints = self.hint(bytes(inner))
        self.assertEqual(hints["trace_chain_status"], "declared-out-of-bounds")
        self.assertFalse(hints["prefetch_validation_checks"]["trace_chains_counted"])

    def test_referenced_files_are_capped_at_1000_with_markers(self) -> None:
        paths = [f"{VOLUME}\\DIR\\FILE{index:04d}.DLL" for index in range(MAX_REFERENCED_FILES + 50)]
        inner = build_pf(version=30, executable="BIG.EXE", paths=paths, run_times=BURST[:1], run_count=1, volumes=two_volumes()[:1])
        rows = self.collect({"BIG.EXE-00000001.pf": mam(inner)})
        details = self.file_row(rows)
        self.assertEqual(len(details["referenced_files"]), MAX_REFERENCED_FILES)
        self.assertTrue(details["referenced_files_truncated"])
        self.assertEqual(details["referenced_files_total"], MAX_REFERENCED_FILES + 50)
        self.assertEqual(details["referenced_file_count"], MAX_REFERENCED_FILES + 50)
        # Every referenced path still becomes a reference row with its offset.
        references = [row for row in rows if row.artifact_type == "prefetch-reference"]
        self.assertEqual(len(references), MAX_REFERENCED_FILES + 50)
        self.assertIsInstance(references[-1].details["source_offset"], int)

    def test_corrupt_mam_is_invalid_content_with_decompression_error(self) -> None:
        inner = build_pf(version=30, executable="A.EXE", paths=tool_paths("A.EXE"), run_times=BURST[:1], run_count=1, volumes=two_volumes())
        broken = bytearray(mam(inner))
        broken[8:8 + 256] = bytes([0x11]) * 256  # over-subscribed code lengths
        rows = self.collect({"A.EXE-00000002.pf": bytes(broken)})
        self.assertEqual(rows[0].artifact_type, "prefetch-invalid-content")
        self.assertEqual(rows[0].details["detected_content_kind"], "mam-decompression-failed")
        self.assertEqual(rows[0].details["prefetch_decompression"]["status"], "decompress-error")

    def test_unsupported_mam_algorithm_is_reported(self) -> None:
        status = decompress_mam_prefetch(b"MAM\x03" + struct.pack("<I", 64) + bytes(64))[1]
        self.assertEqual(status["status"], "unsupported-algorithm-3")

    def hint(self, blob: bytes) -> dict:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "X.EXE-00000000.pf"
            path.write_bytes(blob)
            return prefetch_header_hints(path)


class PrefetchRulesReadDecodedFieldsTests(unittest.TestCase):
    def row(self, details: dict) -> RowView:
        return RowView(
            kind="windows-prefetch", collection="artifacts", source_kind="windows-prefetch", index=0,
            row={"artifact_type": "prefetch-file", "path": "C:\\Windows\\Prefetch\\X.pf", "details": details},
        )

    def decoded_row(self, executable: str, folder: str, run_times: list[datetime]) -> RowView:
        paths = tool_paths(executable, folder)
        inner = build_pf(version=30, executable=executable, paths=paths, run_times=run_times, run_count=len(run_times), volumes=two_volumes())
        with tempfile.TemporaryDirectory() as tmp_dir:
            prefetch_dir = Path(tmp_dir) / "Windows" / "Prefetch"
            prefetch_dir.mkdir(parents=True)
            (prefetch_dir / f"{executable}-1A2B3C4D.pf").write_bytes(mam(inner))
            record = next(row for row in WindowsPrefetchProvider().collect(Path(tmp_dir)) if row.artifact_type == "prefetch-file")
        return self.row(record.to_dict()["details"])

    def test_runcount_spike_fires_on_a_decoded_compressed_pf(self) -> None:
        result = RunCountSpike().apply(self.decoded_row("TOOL.EXE", "USERS\\KIM\\DESKTOP", BURST), FlagContext())
        self.assertIsNotNone(result)
        daily = [BURST[0] - timedelta(days=index) for index in range(8)]
        self.assertIsNone(RunCountSpike().apply(self.decoded_row("TOOL.EXE", "USERS\\KIM\\DESKTOP", daily), FlagContext()))

    def test_suspicious_path_reads_referenced_files(self) -> None:
        row = self.decoded_row("DROPPER.EXE", "USERS\\KIM\\DOWNLOADS", BURST[:1])
        self.assertIsNotNone(SuspiciousPath().apply(row, FlagContext()))
        only_decoded = self.row({"executable_hint": "DROPPER.EXE", "referenced_files": [{"path": f"{VOLUME}\\USERS\\KIM\\DOWNLOADS\\DROPPER.EXE"}]})
        self.assertTrue(prefetch_executable_path(only_decoded).endswith("DOWNLOADS\\DROPPER.EXE"))

    def test_legacy_rows_and_truncated_header_names_still_resolve(self) -> None:
        legacy = self.row({"executable_hint": "CMD.EXE", "referenced_paths": [f"{VOLUME}\\WINDOWS\\SYSTEM32\\CMD.EXE"]})
        self.assertEqual(prefetch_executable_path(legacy), f"{VOLUME}\\WINDOWS\\SYSTEM32\\CMD.EXE")
        long_name = "AM_DELTA_PATCH_1.429.176.0.EX"  # 29-character header field
        truncated = self.row({"executable_hint": long_name, "referenced_files": [{"path": f"{VOLUME}\\TEMP\\AM_DELTA_PATCH_1.429.176.0.EXE"}]})
        self.assertTrue(prefetch_executable_path(truncated).endswith("AM_DELTA_PATCH_1.429.176.0.EXE"))


if __name__ == "__main__":
    unittest.main()
