"""D12 adversarial review: Prefetch truncation, CFB v4 Jump Lists, UNC LNK targets, Recent siblings.

Every fixture is synthetic and built in-test. Core assertions use only Rapid; the
olefile / LnkParse3 / windowsprefetch cross-checks skip when those readers are absent.
"""

from __future__ import annotations

import hashlib
import io
import struct
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from rapidtriage.artifacts.windows.prefetch import WindowsPrefetchProvider
from rapidtriage.artifacts.windows.recent_files import (
    RECENT_ROOT,
    WindowsRecentFilesProvider,
    join_lnk_base_suffix,
    parse_lnk_metadata_from_bytes,
    parse_ole_compound_streams,
)
from rapidtriage.core.artifacts import run_artifact_collection
from tests.test_parser_quality_prefetch_lnk import link_info_network, lnk_header
from tests.test_r3_prefetch_decoding import build_pf
from tests.windows_artifact_fixtures import cfb_directory_entry
from tests.xpress_huffman_encoder import mam

MOMENT = datetime(2024, 2, 3, 1, 2, 4, tzinfo=timezone.utc)
DEVICE = r"\VOLUME{SAMPLE}"
TARGET = DEVICE + r"\DIR\SAMPLE.EXE"
SHARE = r"\\example.invalid\metadata"
CFB_END = 0xFFFFFFFE


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def v23_prefetch() -> bytes:
    return build_pf(
        version=23,
        executable="SAMPLE.EXE",
        paths=[TARGET],
        run_times=[MOMENT],
        run_count=1,
        volumes=[(DEVICE, 123, MOMENT, [DEVICE])],
    )


def destlist(count: int = 32) -> tuple[int, bytes]:
    """DestList v4 header plus ``count`` entries (each a distinct path)."""
    header = bytearray(32)
    struct.pack_into("<IIIII", header, 0, 4, count, 0, 0, count)
    entries = []
    for index in range(1, count + 1):
        path = rf"C:\sample\item-{index:02}.txt"
        entry = bytearray(0x82)
        struct.pack_into("<Q", entry, 0x58, index)
        struct.pack_into("<Qi", entry, 0x64, 133513093240000000, -1)
        struct.pack_into("<H", entry, 0x80, len(path))
        entries.append(bytes(entry) + path.encode("utf-16le") + bytes(4))
    return count, bytes(header) + b"".join(entries)


def compound(major: int, payload: bytes) -> bytes:
    """CFB v3 (512-byte sectors) or v4 (4096-byte sectors) holding one regular ``DestList`` stream."""
    size = {3: 512, 4: 4096}[major]
    assert len(payload) >= 4096  # at the mini-stream cutoff: stored in regular sectors
    header = bytearray(size)
    header[:8] = bytes.fromhex("d0cf11e0a1b11ae1")
    struct.pack_into("<5H", header, 24, 0x3E, major, 0xFFFE, size.bit_length() - 1, 6)
    struct.pack_into("<9I", header, 40, int(major == 4), 1, 1, 0, 4096, CFB_END, 0, CFB_END, 0)
    struct.pack_into("<109I", header, 76, 0, *([0xFFFFFFFF] * 108))
    sectors = (len(payload) + size - 1) // size
    fat = bytearray(b"\xff" * size)
    struct.pack_into(f"<{2 + sectors}I", fat, 0, 0xFFFFFFFD, CFB_END, *range(3, 2 + sectors), CFB_END)
    directory = cfb_directory_entry("Root Entry", 5, child_id=1, start_sector=CFB_END)
    directory += cfb_directory_entry("DestList", 2, start_sector=2, stream_size=len(payload))
    return bytes(header) + bytes(fat) + directory.ljust(size, b"\0") + payload.ljust(sectors * size, b"\0")


def network_lnk(suffix: str) -> bytes:
    header = lnk_header(2, created=MOMENT, accessed=MOMENT, modified=MOMENT)
    return bytes(header) + link_info_network(SHARE, suffix) + bytes(4)


class TruncatedPrefetchTests(unittest.TestCase):
    """Item 6: an SCCA stream cut before its file information is not an execution indicator."""

    def collect_dir(self, files: dict[str, bytes]) -> tuple[Path, tempfile.TemporaryDirectory]:
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        directory = Path(holder.name) / "Windows" / "Prefetch"
        directory.mkdir(parents=True)
        for name, blob in files.items():
            (directory / name).write_bytes(blob)
        return Path(holder.name), holder

    def test_eight_byte_v23_is_one_incomplete_input_row_counted_as_parser_error(self) -> None:
        full = v23_prefetch()
        root, _ = self.collect_dir({"SAMPLE.EXE-1A2B3C4D.pf": full, "OTHER.EXE-00000000.pf": full[:8]})
        rows = list(WindowsPrefetchProvider().collect(root))

        cut = [row for row in rows if Path(row.path).name == "OTHER.EXE-00000000.pf"]
        self.assertEqual(len(cut), 1)
        row = cut[0]
        self.assertEqual(row.artifact_type, "prefetch-invalid-content")
        details = row.details
        self.assertEqual(details["prefetch_parse_status"], "incomplete-input")
        self.assertEqual(details["coverage_status"], "incomplete-input")
        self.assertEqual(details["detected_content_kind"], "incomplete-prefetch")
        self.assertTrue(details["parser_error"])
        self.assertFalse(details["execution_evidence"])
        self.assertEqual(
            details["prefetch_incomplete_input"],
            {
                "scca_signature_detected": True,
                "prefetch_version": 23,
                "required_bytes": 0xF0,
                "available_bytes": 8,
                "required_structure": "file-header+v23-file-information-156-bytes",
                "space": "file",
            },
        )
        for absent in ("evidence_strength", "executable_hint", "executable_hint_source", "prefetch_decode_coverage", "run_count"):
            self.assertNotIn(absent, details)
        self.assertEqual(details["source_hashes"]["sha256"], sha256(full[:8]))

        # The intact v23 control keeps its execution indicator with name, time, run count and path.
        control = next(row.details for row in rows if row.artifact_type == "prefetch-file")
        self.assertEqual(control["entry_name"], "SAMPLE.EXE-1A2B3C4D.pf")
        self.assertEqual(control["evidence_strength"], "execution-indicator")
        self.assertEqual(control["executable_hint"], "SAMPLE.EXE")
        self.assertEqual(control["executable_hint_source"], "prefetch_header")
        self.assertEqual(control["prefetch_decode_coverage"]["file_information"], "decoded")
        self.assertEqual((control["run_count"], control["timestamp"]), (1, MOMENT.isoformat()))
        self.assertEqual(control["referenced_paths"], [TARGET])
        self.assertEqual(control["source_hashes"]["sha256"], sha256(full))
        self.assertEqual([row.artifact_type for row in rows].count("prefetch-file"), 1)

        payload = run_artifact_collection(root, kind="windows-prefetch", use_cache=False)
        self.assertEqual(payload["summary"]["parser_error_count"], 1)
        self.assertEqual(payload["parser_errors"][0]["error_type"], "prefetch-incomplete-input")
        self.assertEqual(Path(payload["parser_errors"][0]["path"]).name, "OTHER.EXE-00000000.pf")

    def test_cut_inside_file_information_is_incomplete_for_each_version(self) -> None:
        full = v23_prefetch()
        # One byte short of the v23 file information end (0xF0): the run count at 0x98 is present
        # but the section is not, so nothing may be marked decoded.
        root, _ = self.collect_dir({"SAMPLE.EXE-1A2B3C4D.pf": full[: 0xF0 - 1]})
        rows = list(WindowsPrefetchProvider().collect(root))
        self.assertEqual([row.artifact_type for row in rows], ["prefetch-invalid-content"])
        self.assertEqual(rows[0].details["prefetch_incomplete_input"]["available_bytes"], 0xEF)
        for version, end in ((30, 0x130), (31, 0x128)):
            blob = build_pf(version=version, executable="SAMPLE.EXE", paths=[TARGET], run_times=[MOMENT], run_count=1, volumes=[])
            with self.subTest(version=version):
                root, _ = self.collect_dir({"SAMPLE.EXE-1A2B3C4D.pf": blob[: end - 4]})
                rows = list(WindowsPrefetchProvider().collect(root))
                self.assertEqual([row.artifact_type for row in rows], ["prefetch-invalid-content"])
                self.assertEqual(rows[0].details["prefetch_incomplete_input"]["required_bytes"], end)

    def test_truncated_decompressed_mam_stream_is_incomplete(self) -> None:
        root, _ = self.collect_dir({"SAMPLE.EXE-1A2B3C4D.pf": mam(v23_prefetch()[:0x60])})
        rows = list(WindowsPrefetchProvider().collect(root))
        self.assertEqual([row.artifact_type for row in rows], ["prefetch-invalid-content"])
        self.assertEqual(rows[0].details["prefetch_incomplete_input"]["space"], "decompressed-scca")

    def test_independent_windowsprefetch_rejects_the_cut_file(self) -> None:
        try:
            from windowsprefetch import Prefetch
        except ImportError as exc:
            raise unittest.SkipTest("windowsprefetch comparison reader unavailable") from exc
        full = v23_prefetch()
        root, _ = self.collect_dir({"SAMPLE.EXE-1A2B3C4D.pf": full, "OTHER.EXE-00000000.pf": full[:8]})
        directory = root / "Windows" / "Prefetch"
        reference = Prefetch(str(directory / "SAMPLE.EXE-1A2B3C4D.pf"))
        self.assertEqual((reference.executableName, reference.runCount, reference.resources), ("SAMPLE.EXE", 1, [TARGET]))
        with self.assertRaises(struct.error):
            Prefetch(str(directory / "OTHER.EXE-00000000.pf"))


class CompoundFileSectorSizeTests(unittest.TestCase):
    """Item 9a: CFB sector N starts at (N + 1) * sector size, for v3 and v4 alike."""

    def test_v3_and_v4_containers_yield_the_same_destlist_stream(self) -> None:
        _, payload = destlist()
        for major in (3, 4):
            with self.subTest(major=major):
                streams = parse_ole_compound_streams(compound(major, payload))
                self.assertEqual([stream["name"] for stream in streams], ["DestList"])
                self.assertEqual(streams[0]["data"], payload)
                self.assertEqual(streams[0]["sha256"], sha256(payload))

    def test_v3_and_v4_jump_lists_give_the_same_32_entries(self) -> None:
        count, payload = destlist()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root.joinpath("Users", "sample", *RECENT_ROOT, "AutomaticDestinations")
            folder.mkdir(parents=True)
            for major in (3, 4):
                (folder / f"{major:016x}.automaticDestinations-ms").write_bytes(compound(major, payload))
            rows = list(WindowsRecentFilesProvider().collect(root))
        entries: dict[int, list[tuple[object, ...]]] = {}
        for major in (3, 4):
            group = [row for row in rows if Path(row.path).name.startswith(f"{major:016x}.")]
            header = next(row.details for row in group if row.artifact_type == "jumplist-automatic")
            self.assertEqual(header["ole_parse_status"], "parsed", major)
            self.assertEqual(header["ole_stream_count"], 1, major)
            children = [row.details for row in group if row.artifact_type == "jumplist-entry"]
            self.assertEqual(len(children), count, major)
            entries[major] = [
                (child["destlist_entry_number"], child["destlist_path"], child["destlist_entry_sha256"], child["destlist_last_modified_at"])
                for child in children
            ]
        self.assertEqual(entries[3], entries[4])
        self.assertEqual([entry[:2] for entry in entries[3][:2]], [(1, r"C:\sample\item-01.txt"), (2, r"C:\sample\item-02.txt")])

    def test_independent_olefile_reads_the_same_stream(self) -> None:
        try:
            import olefile
        except ImportError as exc:
            raise unittest.SkipTest("olefile comparison reader unavailable") from exc
        _, payload = destlist()
        for major in (3, 4):
            blob = compound(major, payload)
            with self.subTest(major=major), olefile.OleFileIO(io.BytesIO(blob), raise_defects=olefile.DEFECT_INCORRECT) as source:
                truth = source.openstream("DestList").read()
                self.assertEqual(parse_ole_compound_streams(blob)[0]["sha256"], sha256(truth))


class UncLinkTargetTests(unittest.TestCase):
    """Item 9b: NetName and CommonPathSuffix are joined by path components."""

    def test_share_root_and_suffix_are_joined(self) -> None:
        metadata = parse_lnk_metadata_from_bytes(network_lnk("data"))
        self.assertEqual(metadata["target_path"], SHARE + r"\data")

    def test_empty_suffix_returns_the_share(self) -> None:
        metadata = parse_lnk_metadata_from_bytes(network_lnk(""))
        self.assertEqual(metadata["target_path"], SHARE)

    def test_join_rules(self) -> None:
        self.assertEqual(join_lnk_base_suffix(SHARE, "data"), SHARE + r"\data")
        # A suffix equal to the share name is still a child of the share root.
        self.assertEqual(join_lnk_base_suffix(r"\\srv\data", "data"), r"\\srv\data\data")
        self.assertEqual(join_lnk_base_suffix(r"\\srv\data", ""), r"\\srv\data")
        self.assertEqual(join_lnk_base_suffix("C:\\Users\\", r"user\file.pdf"), r"C:\Users\user\file.pdf")
        # Only a whole trailing component sequence counts as already embedded.
        self.assertEqual(join_lnk_base_suffix(r"C:\docs\user\file.pdf", r"user\file.pdf"), r"C:\docs\user\file.pdf")
        self.assertEqual(join_lnk_base_suffix(r"C:\docs\profile.pdf", "file.pdf"), r"C:\docs\profile.pdf\file.pdf")
        self.assertEqual(join_lnk_base_suffix(r"\\srv\share\dir\file.txt", "file.txt"), r"\\srv\share\dir\file.txt")

    def test_independent_lnkparse3_matches(self) -> None:
        try:
            from LnkParse3.lnk_file import LnkFile
        except ImportError as exc:
            raise unittest.SkipTest("LnkParse3 comparison reader unavailable") from exc
        blob = network_lnk("data")
        reference = LnkFile(indata=blob, cp="cp949")
        expected = reference.info.net_name() + "\\" + reference.info.common_path_suffix()
        self.assertEqual(parse_lnk_metadata_from_bytes(blob)["target_path"], expected)


class RecentSiblingFolderTests(unittest.TestCase):
    """Item 13b: Recent containment is decided per path component."""

    def test_recent_and_recent_archive_are_each_collected_once(self) -> None:
        blob = network_lnk("data")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            recent = root.joinpath("Users", "sample", *RECENT_ROOT)
            recent.mkdir(parents=True)
            archive = recent.with_name("Recent-Archive")
            archive.mkdir()
            (recent / "sample.lnk").write_bytes(blob)
            (archive / "copy.lnk").write_bytes(blob)
            rows = list(WindowsRecentFilesProvider().collect(root))
        by_name = {Path(row.path).name: row for row in rows}
        self.assertEqual(sorted(Path(row.path).name for row in rows), ["copy.lnk", "sample.lnk"])
        self.assertEqual((by_name["sample.lnk"].artifact_type, by_name["sample.lnk"].details["location"]), ("recent-shortcut", "recent"))
        self.assertEqual((by_name["copy.lnk"].artifact_type, by_name["copy.lnk"].details["location"]), ("shell-shortcut", "other-profile"))
        self.assertEqual(by_name["copy.lnk"].details["source_hashes"]["sha256"], sha256(blob))


if __name__ == "__main__":
    unittest.main()
