from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.core.ntfs_metadata import (
    NTFSMetadataError,
    extract_ntfs_metadata,
    find_usn_journal_attribute,
    missing_ntfs_metadata_tools,
)

MMLS_OUTPUT = """GUID Partition Table (EFI)
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Safety Table
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000       0000567296   0457496575   0456929280   Basic data partition
"""

FLS_EXTEND_OUTPUT = """d/d 27-144-2:	$RmMetadata
r/r 138837-128-685:	$UsnJrnl:$Max
r/r 138837-128-686:	$UsnJrnl:$J
"""

MOJIBAKE_MMLS_OUTPUT = MMLS_OUTPUT.replace("Basic data partition", "???s")

EWF_MAGIC = b"EVF\x09\x0d\x0a\xff\x00"


def _fake_runner(command):
    argv = [str(part) for part in command]
    if argv[0] == "mmls":
        return subprocess.CompletedProcess(argv, 0, MMLS_OUTPUT, "")
    if argv[0] == "fls":
        return subprocess.CompletedProcess(argv, 0, FLS_EXTEND_OUTPUT, "")
    raise AssertionError(f"unexpected command: {argv}")


def _fake_stream_runner(command, output_path: Path):
    argv = [str(part) for part in command]
    assert argv[0] == "icat", argv
    if argv[-1] == "0":
        output_path.write_bytes(b"FILE" + b"\x00" * 1020)
    else:
        output_path.write_bytes(b"USN-RECORD-BYTES")
    return subprocess.CompletedProcess(argv, 0, b"", b"")


def _all_tools(_name: str):
    return "/usr/bin/tool"


class NTFSMetadataExtractTests(unittest.TestCase):
    def test_find_usn_journal_attribute_parses_fls(self) -> None:
        entry = find_usn_journal_attribute(FLS_EXTEND_OUTPUT)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["inode"], 138837)
        self.assertEqual(entry["attribute"], "138837-128-686")

    def test_find_usn_journal_attribute_missing(self) -> None:
        self.assertIsNone(find_usn_journal_attribute("d/d 27-144-2:\t$RmMetadata\n"))

    def test_missing_tools_blocks_extraction(self) -> None:
        self.assertEqual(missing_ntfs_metadata_tools(lambda name: None), ["mmls", "fls", "icat"])
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "case.raw"
            image.write_bytes(b"img")
            with self.assertRaises(NTFSMetadataError):
                extract_ntfs_metadata(image, Path(tmp) / "out", tool_resolver=lambda name: None)

    def test_extracts_mft_and_journal_with_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "case.raw"
            image.write_bytes(b"fake-image")
            out = Path(tmp) / "meta"

            payload = extract_ntfs_metadata(
                image,
                out,
                runner=_fake_runner,
                stream_runner=_fake_stream_runner,
                tool_resolver=_all_tools,
            )

            self.assertEqual(payload["extraction_status"], "complete")
            self.assertEqual(payload["partition"]["start_sector"], 567296)
            self.assertEqual(payload["partition"]["byte_offset"], 567296 * 512)
            mft = payload["outputs"]["mft"]
            self.assertEqual(mft["inode"], 0)
            self.assertEqual(mft["extraction_mode"], "full-stream")
            self.assertTrue(mft["sha256"])
            journal = payload["outputs"]["usn_journal"]
            self.assertEqual(journal["inode"], 138837)
            self.assertEqual(journal["extraction_mode"], "sparse-holes-omitted")
            self.assertIn("-h", journal["command"])
            self.assertTrue(journal["limitations"])
            self.assertTrue((out / "rapidtriage-ntfs-meta.json").is_file())

    def test_full_journal_mode_omits_h_flag(self) -> None:
        commands: list[list[str]] = []

        def recording_stream(command, output_path: Path):
            commands.append([str(part) for part in command])
            return _fake_stream_runner(command, output_path)

        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "case.raw"
            image.write_bytes(b"fake-image")
            payload = extract_ntfs_metadata(
                image,
                Path(tmp) / "meta",
                sparse_journal=False,
                runner=_fake_runner,
                stream_runner=recording_stream,
                tool_resolver=_all_tools,
            )
            journal_cmd = next(c for c in commands if c[-1] != "0")
            self.assertNotIn("-h", journal_cmd)
            self.assertEqual(payload["outputs"]["usn_journal"]["extraction_mode"], "full-stream")

    def test_explicit_partition_offset_must_exist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "case.raw"
            image.write_bytes(b"fake-image")
            with self.assertRaises(NTFSMetadataError):
                extract_ntfs_metadata(
                    image,
                    Path(tmp) / "meta",
                    partition_start_sector=999999,
                    runner=_fake_runner,
                    stream_runner=_fake_stream_runner,
                    tool_resolver=_all_tools,
                )

    def test_garbled_description_resolves_via_mmls_fallback(self) -> None:
        # Garbled description still resolves through select_mmls_filesystem's
        # largest-data-partition fallback, so the fsstat probe is not reached.
        def runner(command):
            argv = [str(part) for part in command]
            if argv[0] == "mmls":
                return subprocess.CompletedProcess(argv, 0, MOJIBAKE_MMLS_OUTPUT, "")
            if argv[0] == "fsstat":
                return subprocess.CompletedProcess(argv, 0, "File System Type: NTFS\n", "")
            if argv[0] == "fls":
                return subprocess.CompletedProcess(argv, 0, FLS_EXTEND_OUTPUT, "")
            raise AssertionError(argv)

        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "case.raw"
            image.write_bytes(b"raw-image-not-ewf")
            payload = extract_ntfs_metadata(
                image,
                Path(tmp) / "meta",
                runner=runner,
                stream_runner=_fake_stream_runner,
                tool_resolver=_all_tools,
            )
            self.assertEqual(payload["partition"]["start_sector"], 567296)
            self.assertEqual(payload["partition"]["selection_method"], "mmls-description")
            self.assertEqual(payload["extraction_status"], "complete")

    def test_ewf_image_reports_mmls_selection_with_verified_filesystem(self) -> None:
        def runner(command):
            argv = [str(part) for part in command]
            if argv[0] == "mmls":
                return subprocess.CompletedProcess(argv, 0, MOJIBAKE_MMLS_OUTPUT, "")
            if argv[0] == "fsstat":
                return subprocess.CompletedProcess(argv, 0, "File System Type: NTFS\n", "")
            if argv[0] == "fls":
                return subprocess.CompletedProcess(argv, 0, FLS_EXTEND_OUTPUT, "")
            raise AssertionError(argv)

        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "case.E01"
            image.write_bytes(EWF_MAGIC + b"container-bytes")
            payload = extract_ntfs_metadata(
                image,
                Path(tmp) / "meta",
                runner=runner,
                stream_runner=_fake_stream_runner,
                tool_resolver=_all_tools,
            )
            self.assertEqual(payload["partition"]["start_sector"], 567296)
            self.assertEqual(payload["partition"]["selection_method"], "mmls-description")
            self.assertTrue(payload["partition"]["filesystem_verified"])

    def test_no_mmls_selection_probes_candidates_with_fsstat(self) -> None:
        # select_mmls_filesystem only returns None when every data row is swap,
        # which is not a realistic listing, so it is patched to None here to
        # reach the fsstat-probe branch. Two garbled data partitions: the larger
        # one (probed first) is not NTFS; only the smaller one at sector 2048 is.
        two_partition_mmls = """GUID Partition Table (EFI)
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Safety Table
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000       0000002048   0000004095   0000002048   ???s
003:  001       0000567296   0457496575   0456929280   ???s
"""
        fsstat_offsets: list[str] = []

        def runner(command):
            argv = [str(part) for part in command]
            if argv[0] == "mmls":
                return subprocess.CompletedProcess(argv, 0, two_partition_mmls, "")
            if argv[0] == "fsstat":
                offset = argv[argv.index("-o") + 1]
                fsstat_offsets.append(offset)
                fs_type = "NTFS" if offset == "2048" else "Unknown"
                return subprocess.CompletedProcess(argv, 0, f"File System Type: {fs_type}\n", "")
            if argv[0] == "fls":
                return subprocess.CompletedProcess(argv, 0, FLS_EXTEND_OUTPUT, "")
            raise AssertionError(argv)

        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "case.E01"
            image.write_bytes(EWF_MAGIC + b"container-bytes")
            with mock.patch(
                "rapidtriage.core.ntfs_metadata.select_mmls_filesystem", return_value=None
            ):
                payload = extract_ntfs_metadata(
                    image,
                    Path(tmp) / "meta",
                    runner=runner,
                    stream_runner=_fake_stream_runner,
                    tool_resolver=_all_tools,
                )
            self.assertEqual(fsstat_offsets[:2], ["567296", "2048"])
            self.assertEqual(payload["partition"]["start_sector"], 2048)
            self.assertEqual(payload["partition"]["selection_method"], "fsstat-probe")
            self.assertTrue(payload["partition"]["filesystem_verified"])
            self.assertEqual(payload["extraction_status"], "complete")

    def test_journal_not_found_records_skip(self) -> None:
        def no_journal_runner(command):
            argv = [str(part) for part in command]
            if argv[0] == "mmls":
                return subprocess.CompletedProcess(argv, 0, MMLS_OUTPUT, "")
            if argv[0] == "fls":
                return subprocess.CompletedProcess(argv, 0, "d/d 27-144-2:\t$RmMetadata\n", "")
            raise AssertionError(argv)

        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "case.raw"
            image.write_bytes(b"fake-image")
            payload = extract_ntfs_metadata(
                image,
                Path(tmp) / "meta",
                runner=no_journal_runner,
                stream_runner=_fake_stream_runner,
                tool_resolver=_all_tools,
            )
            self.assertEqual(payload["extraction_status"], "partial")
            self.assertIn("mft", payload["outputs"])
            self.assertEqual(payload["skipped"][0]["target"], "usn_journal")


if __name__ == "__main__":
    unittest.main()
