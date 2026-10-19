"""R6 S2 갈래 C: ``$Boot`` extraction and the ``ntfs-volume-information`` analysis row (Q-S2-5).

Sleuth Kit is faked (``icat`` stream runner, ``NTFS_EXTRACTOR`` hook, pattern of
``tests/test_rapidtriage_analyses.py``); the native fallback reads a synthetic raw image.
"""

from __future__ import annotations

import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from rapidtriage.api.app import analyses, analysis_kinds, create_app
from rapidtriage.artifacts.windows import system_extras
from rapidtriage.artifacts.windows.system_extras import collect_ntfs_volume_information
from rapidtriage.core import e01_native, ntfs_volume
from rapidtriage.core.e01_native import NativeImageError, dump_boot_sector
from rapidtriage.core.jobs import RunJobStore
from rapidtriage.core.ntfs_metadata import NTFSMetadataError, extract_ntfs_metadata
from tests import r5_l2_fixtures as fx
from tests.test_r6_s2_unalloc_carve import PARTITION_SECTOR, VSN, build_ntfs_image
from tests.test_rapidtriage_analyses import write_run

TOKEN = "r6-s2-boot-token"

MMLS_OUTPUT = """DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0001026047   0001024000   NTFS / exFAT (0x07)
"""
FLS_EXTEND = "r/r 38-128-1:\t$UsnJrnl:$J\n"


def raw_mft() -> bytes:
    """``fx.mft_with_volume_record`` with the FILE allocated size set, so it is detected as a raw $MFT."""
    data = bytearray(fx.mft_with_volume_record())
    for start in range(0, len(data), 1024):
        data[start + 0x1C : start + 0x20] = (1024).to_bytes(4, "little")
    return bytes(data)


def fake_runner(command):
    argv = [str(part) for part in command]
    if argv[0] == "mmls":
        return subprocess.CompletedProcess(argv, 0, MMLS_OUTPUT, "")
    if argv[0] == "fls":
        return subprocess.CompletedProcess(argv, 0, FLS_EXTEND, "")
    raise AssertionError(argv)


def stream_runner_with_boot(boot: bytes, *, boot_exit: int = 0):
    commands: list[list[str]] = []

    def run(command, output_path: Path):
        argv = [str(part) for part in command]
        commands.append(argv)
        if argv[-1] == "7":
            output_path.write_bytes(boot)
            return subprocess.CompletedProcess(argv, boot_exit, b"", b"icat: bad inode" if boot_exit else b"")
        output_path.write_bytes(fx.mft_with_volume_record() if argv[-1] == "0" else b"USN-BYTES")
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    run.commands = commands  # type: ignore[attr-defined]
    return run


class BootExtractionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.image = self.base / "case.raw"
        self.image.write_bytes(b"fake-image")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def extract(self, runner):
        return extract_ntfs_metadata(
            self.image, self.base / "meta", runner=fake_runner, stream_runner=runner, tool_resolver=lambda name: f"/bin/{name}"
        )

    def test_icat_inode_7_to_boot_capped_at_8k(self) -> None:
        runner = stream_runner_with_boot(fx.boot_sector() + b"\x00" * 9000)
        manifest = self.extract(runner)
        boot = manifest["outputs"]["boot"]
        self.assertEqual(boot["inode"], 7)
        self.assertEqual(boot["command"], ["icat", "-o", "2048", str(self.image.resolve()), "7"])
        self.assertEqual(Path(boot["path"]).name, "$Boot")
        self.assertEqual(boot["size_bytes"], 8192)
        self.assertEqual((boot["extraction_mode"], boot["stream_size_bytes"]), ("first-8KiB", 512 + 9000))
        self.assertEqual(Path(boot["path"]).read_bytes()[:512], fx.boot_sector())
        self.assertEqual(manifest["extraction_status"], "complete")
        self.assertIn(["icat", "-o", "2048", str(self.image.resolve()), "7"], runner.commands)

    def test_short_or_failed_boot_is_skipped_and_extraction_goes_on(self) -> None:
        manifest = self.extract(stream_runner_with_boot(b"\x00" * 100))
        self.assertNotIn("boot", manifest["outputs"])
        self.assertEqual(manifest["extraction_status"], "complete")
        skip = next(item for item in manifest["skipped"] if item["target"] == "boot")
        self.assertIn("100 bytes", skip["reason"])
        self.assertFalse((self.base / "meta" / "$Boot").exists())
        failed = self.extract(stream_runner_with_boot(b"", boot_exit=1))
        self.assertIn("icat exit 1", next(item for item in failed["skipped"] if item["target"] == "boot")["reason"])

    def test_missing_tools_still_raise(self) -> None:
        with self.assertRaises(NTFSMetadataError):
            extract_ntfs_metadata(self.image, self.base / "m", tool_resolver=lambda name: None)


class NativeBootSectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_dump_boot_sector_raw_disk_and_volume(self) -> None:
        image = build_ntfs_image(self.base / "disk.raw")
        entry = dump_boot_sector(image.path, self.base / "out" / "$Boot")
        self.assertEqual(entry["partition"]["start_sector"], PARTITION_SECTOR)
        self.assertEqual(entry["extraction_mode"], "native-boot-sector-raw")
        self.assertEqual(entry["size_bytes"], 512)
        parsed = ntfs_volume.parse_ntfs_vbr((self.base / "out" / "$Boot").read_bytes())
        self.assertEqual(parsed["volume_serial_number"], f"{VSN & 0xFFFFFFFF:08X}")
        volume = build_ntfs_image(self.base / "vol.raw", with_mbr=False)
        self.assertEqual(dump_boot_sector(volume.path, self.base / "v" / "$Boot")["partition"]["selection_method"], "volume-image")

    def test_dump_boot_sector_korean_errors(self) -> None:
        image = build_ntfs_image(self.base / "disk.raw")
        with self.assertRaisesRegex(NativeImageError, "섹터 1에 NTFS 부트 섹터가 없습니다"):
            dump_boot_sector(image.path, self.base / "x", partition_start_sector=1)
        ewf = self.base / "a.E01"
        ewf.write_bytes(b"EVF\x09\x0d\x0a\xff\x00" + bytes(64))
        with patch.object(e01_native, "pyewf", None), self.assertRaisesRegex(NativeImageError, "pyewf"):
            dump_boot_sector(ewf, self.base / "y")

    def test_cluster_size_from_extracted_boot_for_ewf(self) -> None:
        # ntfs_cluster_size cannot read an EWF container at the partition offset; the $Boot that
        # ntfs-meta now extracts next to LogFile.bin gives the cluster size instead.
        ewf = self.base / "case.E01"
        ewf.write_bytes(b"EVF\x09\x0d\x0a\xff\x00" + bytes(1024))
        folder = self.base / "ntfs"
        folder.mkdir()
        (folder / "LogFile.bin").write_bytes(b"RSTR")
        partition = {"start_sector": 0}
        self.assertIsNone(analysis_kinds.ntfs_cluster_size(ewf, partition, [folder / "LogFile.bin"]))
        (folder / "$Boot").write_bytes(fx.boot_sector() + bytes(7680))
        self.assertEqual(analysis_kinds.ntfs_cluster_size(ewf, partition, [folder / "LogFile.bin"]), 4096)


class VolumeRowAnalysisTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.evidence = self.base / "evidence"
        (self.evidence / "export").mkdir(parents=True)
        (self.evidence / "disk.E01").write_bytes(b"EVF\x09\x0d\x0a\xff\x00" + bytes(64))
        self.run_dir = write_run(self.base, "run", self.evidence)
        self.store = RunJobStore()
        self.run_id = self.store.import_completed_run(self.run_dir).run_id
        self.client = TestClient(create_app(self.store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})

    def tearDown(self) -> None:
        self.client.close()
        self.temp.cleanup()

    def run_analysis(self, options: dict[str, object] | None = None) -> dict[str, object]:
        created = self.client.post(f"/api/runs/{self.run_id}/analyses", json={"kind": "ntfs-meta", "options": options or {}})
        self.assertEqual(created.status_code, 202, created.text)
        deadline = time.monotonic() + 30
        while True:
            state = self.client.get(f"/api/runs/{self.run_id}/analyses/{created.json()['analysis_id']}").json()
            if state["status"] in analyses.TERMINAL_STATUSES and state.get("finished_at"):
                return state
            self.assertLess(time.monotonic(), deadline, state)
            time.sleep(0.03)

    def volume_rows(self, state: dict[str, object]) -> list[dict[str, object]]:
        page = self.client.get(f"/api/runs/{self.run_id}/analyses/{state['analysis_id']}/rows", params={"limit": 200}).json()
        return [row for row in page["rows"] if row["artifact_type"] == "ntfs-volume-information"]

    def assert_volume_row(self, state: dict[str, object]) -> dict[str, object]:
        self.assertEqual(state["status"], "completed", state)
        rows = self.volume_rows(state)
        self.assertEqual(len(rows), 1)
        details = rows[0]["details"]
        self.assertEqual((details["volume_serial_number"], details["volume_serial_display"]), (fx.VSN_LOW, "5E6F-7788"))
        self.assertEqual((details["cluster_size"], details["volume_label"], details["ntfs_version"]), (4096, "증거볼륨", "3.1"))
        self.assertEqual(details["source"], "volume-information")
        self.assertEqual(details["risk_flags"], ["ntfs-volume-dirty"])
        summary = state["summary"]
        self.assertEqual((summary["volume_serial_number"], summary["cluster_size"]), (fx.VSN_LOW, 4096))
        self.assertEqual((summary["volume_label"], summary["volume_information_status"]), ("증거볼륨", "parsed"))
        return details

    def test_image_extraction_writes_one_volume_row(self) -> None:
        def fake_extract(image, output_dir, *, partition_start_sector=None, sparse_journal=True):
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / "MFT.bin").write_bytes(fx.mft_with_volume_record())
            (output_dir / "$Boot").write_bytes(fx.boot_sector() + bytes(7680))
            outputs = {
                "mft": {"path": str(output_dir / "MFT.bin"), "size_bytes": 4096, "sha256": "m"},
                "boot": {"path": str(output_dir / "$Boot"), "size_bytes": 8192, "sha256": "b"},
            }
            return {"outputs": outputs, "extraction_status": "partial", "partition": {"start_sector": 2048}, "skipped": []}

        with patch.object(analysis_kinds, "NTFS_EXTRACTOR", fake_extract):
            state = self.run_analysis()
        details = self.assert_volume_row(state)
        self.assertTrue(details["boot_source_path"].endswith("$Boot"))
        self.assertEqual(details["volume_record_number"], 3)
        self.assertIn("boot", state["summary"]["outputs"])
        # the MFT rows' source ranges are untouched by the trailing volume row
        mft_range = state["summary"]["source_row_ranges"]["mft"]
        self.assertEqual(mft_range["start"], 0)
        self.assertEqual(state["row_count"], mft_range["end"] + 1)
        title = analysis_kinds.analysis_row_title("ntfs-meta", self.volume_rows(state)[0], 0)
        self.assertEqual(title, "NTFS 볼륨 정보 · VSN 5E6F-7788 · 증거볼륨")
        # console review #4: the volume row has its own source range / count and row filter
        self.assertEqual(state["summary"]["source_row_ranges"]["volume-information"]["start"], mft_range["end"])
        self.assertEqual(state["summary"]["source_row_ranges"]["volume-information"]["end"], mft_range["end"] + 1)
        self.assertEqual(state["summary"]["source_counts"]["volume-information"], 1)
        self.assert_source_filter(state)

    def assert_source_filter(self, state: dict[str, object]) -> None:
        page = self.client.get(
            f"/api/runs/{self.run_id}/analyses/{state['analysis_id']}/rows",
            params={"limit": 50, "source": "volume-information"},
        )
        self.assertEqual(page.status_code, 200, page.text)
        rows = page.json()["rows"]
        self.assertEqual([row["artifact_type"] for row in rows], ["ntfs-volume-information"])

    def test_raw_mft_input_with_sibling_boot(self) -> None:
        mft = self.evidence / "export" / "$MFT"
        mft.write_bytes(raw_mft())
        (self.evidence / "export" / "Boot.bin").write_bytes(fx.boot_sector())
        details = self.assert_volume_row(self.run_analysis({"image_path": str(mft)}))
        self.assertTrue(details["boot_source_path"].endswith("Boot.bin"))

    def test_raw_mft_without_boot_records_skip_and_continues(self) -> None:
        mft = self.evidence / "export" / "$MFT"
        mft.write_bytes(raw_mft())
        state = self.run_analysis({"image_path": str(mft)})
        self.assertEqual(state["status"], "completed", state)
        self.assertEqual(state["summary"]["skipped"], [{"target": "boot", "reason": "$MFT 옆에 $Boot 파일이 없습니다"}])
        rows = self.volume_rows(state)  # the $Volume record alone still names the volume (no VSN)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["details"]["volume_label"], "증거볼륨")
        self.assertNotIn("volume_serial_number", rows[0]["details"])
        self.assertEqual(state["summary"]["mft_record_count"], 4)

    def test_native_fallback_without_sleuthkit(self) -> None:
        image = build_ntfs_image(self.evidence / "disk.dd")

        def no_tools(*_args, **_kwargs):
            raise NTFSMetadataError("missing Sleuth Kit tools: mmls, fls, icat")

        with patch.object(analysis_kinds, "NTFS_EXTRACTOR", no_tools):
            state = self.run_analysis({"image_path": str(image.path)})
            failed = self.run_analysis()  # the run's disk.E01 is not a readable image
        self.assertEqual(state["status"], "completed", state)
        self.assertEqual(state["summary"]["extraction_status"], "boot-only-native")
        self.assertEqual({item["target"] for item in state["summary"]["skipped"]}, {"mft", "usn_journal", "logfile"})
        rows = self.volume_rows(state)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["details"]["volume_serial_number"], f"{VSN & 0xFFFFFFFF:08X}")
        self.assertEqual(state["summary"]["cluster_size"], 1024)
        self.assertEqual(state["summary"]["source_counts"]["volume-information"], 1)
        self.assertEqual(state["summary"]["source_row_ranges"]["volume-information"]["end"], 1)
        self.assert_source_filter(state)
        self.assertEqual(failed["status"], "failed")
        self.assertIn("Sleuth Kit 도구가 없습니다", failed["error"])
        self.assertIn("부트 섹터 직접 읽기도 실패", failed["error"])


class CollectorReadsAnalysisFoldersTests(unittest.TestCase):
    def test_run_analysis_ntfs_folders_feed_the_volume_row(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "evidence"
            (root / "Users").mkdir(parents=True)
            for analysis_id in ("20261019T000000-aaaa", "20261019T000001-bbbb"):  # same volume twice: one row
                folder = root / "rapidtriage-run-hacking" / "analyses" / analysis_id / "ntfs"
                folder.mkdir(parents=True)
                (folder / "$Boot").write_bytes(fx.boot_sector() + bytes(7680))
                (folder / "MFT.bin").write_bytes(fx.mft_with_volume_record())
            rows = list(collect_ntfs_volume_information(root, "windows-filesystem"))
            self.assertEqual(len(rows), 1)
            details = rows[0].details
            self.assertEqual(details["volume_serial_number"], fx.VSN_LOW)
            self.assertEqual((details["volume_source"], details["analysis_id"]), ("ntfs-meta-analysis", "20261019T000000-aaaa"))
            self.assertEqual(details["volume_label"], "증거볼륨")
            # an evidence-tree $Boot of the same volume wins: the analysis copy adds nothing
            (root / "Users" / "$Boot").write_bytes(fx.boot_sector())
            rows = list(collect_ntfs_volume_information(root, "windows-filesystem"))
            self.assertEqual(len(rows), 1)
            self.assertNotIn("volume_source", rows[0].details)

    def test_e01_extraction_root_inside_the_run_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "out"
            root = output / "e01-stage" / "fs"
            (root / "Windows").mkdir(parents=True)
            (output / "rapidtriage-run-summary.json").write_text("{}", encoding="utf-8")
            folder = output / "analyses" / "20261019T000000-cccc" / "ntfs"
            folder.mkdir(parents=True)
            (folder / "$Boot").write_bytes(fx.boot_sector())
            rows = list(collect_ntfs_volume_information(root, "windows-filesystem"))
            self.assertEqual([row.details["volume_serial_number"] for row in rows], [fx.VSN_LOW])
            self.assertEqual(rows[0].details["volume_source"], "ntfs-meta-analysis")
            # MFT-only analysis folders (no VSN) add nothing
            (folder / "$Boot").unlink()
            (folder / "MFT.bin").write_bytes(fx.mft_with_volume_record())
            self.assertEqual(list(collect_ntfs_volume_information(root, "windows-filesystem")), [])

    def test_reexports_point_at_core(self) -> None:
        self.assertIs(system_extras.parse_ntfs_vbr, ntfs_volume.parse_ntfs_vbr)
        self.assertIs(system_extras.parse_volume_record, ntfs_volume.parse_volume_record)


if __name__ == "__main__":
    unittest.main()
