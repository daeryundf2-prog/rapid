"""Tests for the macOS KakaoTalk live-collection workflow and Mach-O core analysis.

All fixtures are synthetic: Mach-O core files are generated in-process and the
collector's subprocess seams are mocked. No real process is ever attached,
dumped, or read, and no lldb/csrutil/sw_vers command is executed.
"""

from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rapidtriage.cli import main
from rapidtriage.core.kakaotalk import (
    KAKAOTALK_MACOS_COLLECT_VERSION,
    build_memory_address_ranges,
    describe_memory_region_for_offset,
    detect_memory_dump_format,
    mapped_offset_to_va,
    mapped_va_to_offset,
    parse_macho_core_segments,
    run_kakaotalk_macos_collect,
    run_kakaotalk_memory_carve,
)

MACHO_MAGIC_64_LE = 0xFEEDFACF
MACHO_FILETYPE_CORE = 4
MACHO_LC_SEGMENT_64 = 0x19


def _sqlite_header(page_size: int = 512, page_count: int = 1) -> bytes:
    header = bytearray(100)
    header[0:16] = b"SQLite format 3\x00"
    struct.pack_into(">H", header, 16, page_size)
    struct.pack_into(">I", header, 28, page_count)
    return bytes(header)


def build_synthetic_macho_core(segments: list[tuple[str, int, bytes]]) -> bytes:
    """Build a minimal 64-bit Mach-O core (MH_CORE) with LC_SEGMENT_64 segments."""

    ncmds = len(segments)
    seg_cmd_size = 72
    sizeofcmds = seg_cmd_size * ncmds
    data_start = 32 + sizeofcmds

    load_commands = bytearray()
    payload = bytearray()
    file_offset = data_start
    for segname, vmaddr, data in segments:
        filesize = len(data)
        load_commands += struct.pack(
            "<II16sQQQQiiII",
            MACHO_LC_SEGMENT_64,
            seg_cmd_size,
            segname.encode("ascii")[:16],
            vmaddr,
            filesize,
            file_offset,
            filesize,
            7,
            7,
            0,
            0,
        )
        payload += data
        file_offset += filesize

    header = struct.pack(
        "<IIIIIIII",
        MACHO_MAGIC_64_LE,
        0x0100000C,
        0,
        MACHO_FILETYPE_CORE,
        ncmds,
        sizeofcmds,
        0,
        0,
    )
    return bytes(header) + bytes(load_commands) + bytes(payload)


class MachoCoreParsingTests(unittest.TestCase):
    def test_detect_formats(self) -> None:
        core = build_synthetic_macho_core([("__DATA", 0x100000000, b"\x00" * 64)])
        self.assertEqual(detect_memory_dump_format(core), "macho-core")
        self.assertEqual(detect_memory_dump_format(b"MDMP" + b"\x00" * 60), "minidump")
        self.assertEqual(detect_memory_dump_format(b"not a dump at all"), "raw")

    def test_segment_ranges_and_va_round_trip(self) -> None:
        seg_a = b"A" * 0x40
        seg_b = b"B" * 0x80
        core = build_synthetic_macho_core(
            [("__TEXT", 0x100000000, seg_a), ("__DATA", 0x200000000, seg_b)]
        )
        segments = parse_macho_core_segments(core)
        self.assertEqual([s["segname"] for s in segments], ["__TEXT", "__DATA"])

        ranges = build_memory_address_ranges(core)
        self.assertEqual(len(ranges), 2)
        data_fileoff = int(segments[1]["fileoff"])
        va = mapped_offset_to_va(data_fileoff, ranges)
        self.assertEqual(va, 0x200000000)
        self.assertEqual(mapped_va_to_offset(0x200000000, ranges), data_fileoff)

    def test_region_provenance_for_offset(self) -> None:
        core = build_synthetic_macho_core(
            [("__TEXT", 0x100000000, b"\x11" * 0x30), ("__DATA", 0x200000000, b"\x22" * 0x30)]
        )
        segments = parse_macho_core_segments(core)
        data_fileoff = int(segments[1]["fileoff"])
        provenance = describe_memory_region_for_offset(data_fileoff + 4, segments)
        assert provenance is not None
        self.assertEqual(provenance["segment_name"], "__DATA")
        self.assertEqual(provenance["segment_vmaddr"], 0x200000000)
        self.assertEqual(provenance["mapped_virtual_address"], 0x200000004)


class MachoCoreCarveTests(unittest.TestCase):
    def test_memory_carve_reads_macho_core_with_region_provenance(self) -> None:
        key_literal = b"x'" + (b"ab" * 32) + b"'"
        data_segment = b"\x00" * 64 + _sqlite_header() + b"\x00" * 64 + key_literal + b"\x00" * 16
        core = build_synthetic_macho_core(
            [("__TEXT", 0x100000000, b"\x00" * 32), ("__DATA", 0x200000000, data_segment)]
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "KakaoTalkMac_4242.core").write_bytes(core)
            out = root / "carve.json"
            payload = run_kakaotalk_memory_carve(root, output=out)

        self.assertGreaterEqual(payload["summary"]["sqlite_header_count"], 1)
        self.assertEqual(payload["summary"]["memory_source_count"], 1)
        self.assertGreaterEqual(payload["summary"]["sqlcipher_key_residue_count"], 1)

        entry = payload["entries"][0]
        self.assertEqual(entry["memory_dump_format"], "macho-core")
        provenance = entry["region_provenance"]
        assert provenance is not None
        self.assertEqual(provenance["segment_name"], "__DATA")


class MacosCollectorTests(unittest.TestCase):
    def test_successful_collection_writes_manifest_with_consent_and_hashes(self) -> None:
        def fake_save_core(pid, output_core, **_kwargs):
            output_core.write_bytes(b"synthetic-core-bytes")
            return {"pid": pid, "status": "saved", "core_path": str(output_core), "returncode": 0}

        preflight = {
            "checks": {"platform_is_macos": True, "running_as_root": True, "effective_uid": 0},
            "tool_versions": {"lldb_version": "lldb-1600.0.0", "macos_product_version": "15.0"},
            "blockers": [],
            "advisories": ["advisory"],
            "can_attempt": True,
        }
        with tempfile.TemporaryDirectory() as tmp, patch(
            "rapidtriage.core.kakaotalk.macos_collect_preflight", return_value=preflight
        ), patch(
            "rapidtriage.core.kakaotalk.find_running_kakaotalk_macos_pids", return_value=[4242]
        ), patch(
            "rapidtriage.core.kakaotalk.run_lldb_process_save_core", side_effect=fake_save_core
        ):
            payload = run_kakaotalk_macos_collect(
                output_root=Path(tmp),
                operator="Investigator A",
                consent_statement="Holder consented on site",
                authority_reference="Case 42",
            )
            manifest_path = Path(str(payload["summary"]["manifest_path"]))
            manifest = json.loads(manifest_path.read_text())

        self.assertEqual(payload["summary"]["status"], "collected")
        self.assertEqual(payload["summary"]["core_dump_saved_count"], 1)
        self.assertEqual(manifest["parser"], KAKAOTALK_MACOS_COLLECT_VERSION)
        self.assertEqual(manifest["user_consent"]["operator"], "Investigator A")
        self.assertEqual(manifest["user_consent"]["consent_statement"], "Holder consented on site")
        self.assertTrue(manifest["user_consent"]["consent_obtained"])
        self.assertEqual(manifest["tool_versions"]["lldb_version"], "lldb-1600.0.0")
        # The collected core is hashed in the manifest file list.
        self.assertTrue(manifest["files"])
        self.assertEqual(manifest["core_dumps"][0]["status"], "saved")
        self.assertTrue(all(len(item["sha256"]) == 64 for item in manifest["files"]))

    def test_preflight_blocker_skips_any_dump_attempt(self) -> None:
        blocked = {
            "checks": {"running_as_root": False, "effective_uid": 501},
            "tool_versions": {},
            "blockers": ["Not running as root"],
            "advisories": [],
            "can_attempt": False,
        }
        with tempfile.TemporaryDirectory() as tmp, patch(
            "rapidtriage.core.kakaotalk.macos_collect_preflight", return_value=blocked
        ), patch(
            "rapidtriage.core.kakaotalk.find_running_kakaotalk_macos_pids"
        ) as find_pids, patch(
            "rapidtriage.core.kakaotalk.run_lldb_process_save_core"
        ) as save_core:
            payload = run_kakaotalk_macos_collect(
                output_root=Path(tmp),
                operator="Investigator A",
                consent_statement="Holder consented on site",
            )

        self.assertEqual(payload["summary"]["status"], "blocked-by-preflight")
        self.assertEqual(payload["summary"]["core_dump_count"], 0)
        find_pids.assert_not_called()
        save_core.assert_not_called()

    def test_preflight_only_runs_no_tool_and_records_posture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch(
            "rapidtriage.core.kakaotalk._run_macos_command",
            side_effect=FileNotFoundError("no such tool"),
        ), patch(
            "rapidtriage.core.kakaotalk.find_running_kakaotalk_macos_pids"
        ) as find_pids:
            payload = run_kakaotalk_macos_collect(
                output_root=Path(tmp),
                operator="Investigator A",
                consent_statement="",
                preflight_only=True,
            )

        self.assertEqual(payload["summary"]["status"], "preflight-only")
        self.assertEqual(payload["summary"]["core_dump_count"], 0)
        find_pids.assert_not_called()
        self.assertIn("advisories", payload["preflight"])

    def test_cli_preflight_only_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch(
            "rapidtriage.core.kakaotalk._run_macos_command",
            side_effect=FileNotFoundError("no such tool"),
        ):
            exit_code = main(
                [
                    "kakaotalk-collect-macos",
                    "--output-root",
                    tmp,
                    "--operator",
                    "Investigator A",
                    "--preflight-only",
                    "--json",
                ]
            )
        self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
