"""R6 S2 갈래 C: unallocated clusters of an NTFS image and the ``image-unallocated`` URL-carve source.

Q-S2-6 (runs from a hand-made ``$Boot`` + ``$Bitmap``, a URL across a chunk boundary, absolute
image offsets) and Q-S2-7 (options, Korean failures, ``source_truncated``). Every image here is
synthetic: an MBR, an NTFS boot sector, MFT record 6 (``$Bitmap``) with a one-run ``$DATA``,
the bitmap itself, and URL bytes placed in free and in allocated clusters.
"""

from __future__ import annotations

import struct
import subprocess
import tempfile
import time
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from rapidtriage.api.app import analyses, create_app
from rapidtriage.api.app.analysis_kinds import UrlCarveOptions
from rapidtriage.core import e01_native
from rapidtriage.core.jobs import RunJobStore
from rapidtriage.core.ntfs_unalloc import (
    ScanStats,
    bitmap_unallocated_runs,
    decode_runlist,
    iter_unallocated_chunks,
    open_unallocated_image,
)
from rapidtriage.core.url_carving import UrlCarveState, scan_url_windows
from tests.test_rapidtriage_analyses import write_run

TOKEN = "r6-s2-unalloc-token"
VSN = 0x0123456789ABCDEF
PARTITION_SECTOR = 64
MFT_LCN = 4
BITMAP_LCN = 12
MFT_RECORD = 1024


@dataclass
class SyntheticImage:
    path: Path
    cluster_size: int
    total_clusters: int
    allocated: set[int]
    partition_offset: int

    def offset_of(self, cluster: int, within: int = 0) -> int:
        return self.partition_offset + cluster * self.cluster_size + within


def _mft_record(number: int, attributes: bytes) -> bytes:
    record = bytearray(MFT_RECORD)
    record[0:4] = b"FILE"
    struct.pack_into("<HH", record, 4, 0x30, 3)
    struct.pack_into("<H", record, 0x14, 0x38)
    struct.pack_into("<I", record, 0x1C, MFT_RECORD)
    struct.pack_into("<I", record, 0x2C, number)
    record[0x38 : 0x38 + len(attributes)] = attributes
    struct.pack_into("<I", record, 0x38 + len(attributes), 0xFFFFFFFF)
    usn = b"\x05\x00"
    record[0x30:0x32] = usn
    for sector in (1, 2):
        end = sector * 512
        record[0x30 + sector * 2 : 0x32 + sector * 2] = record[end - 2 : end]
        record[end - 2 : end] = usn
    return bytes(record)


def _nonresident_data(lcn: int, clusters: int, data_size: int) -> bytes:
    runlist = bytes([0x11 if lcn < 0x80 else 0x21, clusters]) + (
        lcn.to_bytes(1, "little") if lcn < 0x80 else lcn.to_bytes(2, "little", signed=True)
    ) + b"\x00"
    attr = bytearray(0x40 + len(runlist))
    struct.pack_into("<IIBB", attr, 0, 0x80, 0, 1, 0)
    struct.pack_into("<QQ", attr, 0x10, 0, clusters - 1)
    struct.pack_into("<H", attr, 0x20, 0x40)
    struct.pack_into("<QQQ", attr, 0x28, clusters * 4096, data_size, data_size)
    attr[0x40:] = runlist
    attr += b"\x00" * ((-len(attr)) % 8)
    struct.pack_into("<I", attr, 4, len(attr))
    return bytes(attr)


def boot_sector(*, sectors_per_cluster: int, total_sectors: int, vsn: int = VSN) -> bytes:
    boot = bytearray(512)
    boot[0:3] = b"\xeb\x52\x90"
    boot[3:11] = b"NTFS    "
    struct.pack_into("<HB", boot, 0x0B, 512, sectors_per_cluster)
    boot[0x15] = 0xF8
    struct.pack_into("<I", boot, 0x1C, PARTITION_SECTOR)
    struct.pack_into("<QQQ", boot, 0x28, total_sectors, MFT_LCN, 2)
    boot[0x40] = 0xF6  # 1024-byte MFT records
    boot[0x44] = 0x01
    struct.pack_into("<Q", boot, 0x48, vsn)
    boot[510:512] = b"\x55\xaa"
    return bytes(boot)


def build_ntfs_image(
    path: Path,
    *,
    cluster_size: int = 1024,
    total_clusters: int = 600,
    allocated_ranges: tuple[tuple[int, int], ...] = ((100, 150),),
    payloads: dict[int, bytes] | None = None,
    with_mbr: bool = True,
) -> SyntheticImage:
    """A raw disk image: MBR (one type-0x07 partition at sector 64) + an NTFS-like volume whose
    clusters 0..BITMAP_LCN and ``allocated_ranges`` are allocated in ``$Bitmap``. ``payloads`` maps
    absolute image offsets to bytes written there (after the metadata)."""
    spc = cluster_size // 512
    partition_offset = PARTITION_SECTOR * 512 if with_mbr else 0
    total_sectors = total_clusters * spc
    allocated = set(range(BITMAP_LCN + 1))
    for start, end in allocated_ranges:
        allocated.update(range(start, end))
    bitmap = bytearray((total_clusters + 7) // 8)
    for cluster in allocated:
        bitmap[cluster // 8] |= 1 << (cluster % 8)
    image = bytearray(partition_offset + total_clusters * cluster_size)
    if with_mbr:
        entry = bytearray(16)
        entry[4] = 0x07
        struct.pack_into("<II", entry, 8, PARTITION_SECTOR, total_sectors)
        image[0x1BE:0x1CE] = entry
        image[510:512] = b"\x55\xaa"
    image[partition_offset : partition_offset + 512] = boot_sector(sectors_per_cluster=spc, total_sectors=total_sectors)
    bitmap_clusters = (len(bitmap) + cluster_size - 1) // cluster_size
    mft_offset = partition_offset + MFT_LCN * cluster_size
    record6 = _mft_record(6, _nonresident_data(BITMAP_LCN, bitmap_clusters, len(bitmap)))
    image[mft_offset + 6 * MFT_RECORD : mft_offset + 7 * MFT_RECORD] = record6
    bitmap_offset = partition_offset + BITMAP_LCN * cluster_size
    image[bitmap_offset : bitmap_offset + len(bitmap)] = bitmap
    for offset, data in (payloads or {}).items():
        image[offset : offset + len(data)] = data
    path.write_bytes(bytes(image))
    return SyntheticImage(path, cluster_size, total_clusters, allocated, partition_offset)


def expected_runs(image: SyntheticImage) -> list[tuple[int, int]]:
    runs: list[tuple[int, int]] = []
    for cluster in range(image.total_clusters):
        if cluster in image.allocated:
            continue
        if runs and runs[-1][0] + runs[-1][1] == cluster:
            runs[-1] = (runs[-1][0], runs[-1][1] + 1)
        else:
            runs.append((cluster, 1))
    return runs


class BitmapRunTests(unittest.TestCase):
    def test_runs_merge_across_bytes_and_stop_at_total_clusters(self) -> None:
        # clusters 0-3 allocated, 4-19 free (crosses two byte boundaries), 20 allocated, 21-29 free;
        # bits past total_clusters=30 are clear but are not clusters.
        bits = [1] * 4 + [0] * 16 + [1] + [0] * 9 + [0] * 10
        bitmap = bytearray(5)
        for index, bit in enumerate(bits):
            if bit:
                bitmap[index // 8] |= 1 << (index % 8)
        result = bitmap_unallocated_runs(bytes(bitmap), 30)
        self.assertEqual(result.runs, [(4, 16), (21, 9)])
        self.assertEqual(result.free_clusters, 25)
        self.assertFalse(result.truncated)

    def test_all_free_bytes_and_cap(self) -> None:
        result = bitmap_unallocated_runs(b"\x00" * 4, 32)
        self.assertEqual(result.runs, [(0, 32)])
        # alternating bits -> 16 one-cluster runs; a cap of 3 keeps 3 and says so (free still counted)
        capped = bitmap_unallocated_runs(b"\x55\x55\x55\x55", 32, max_runs=3)
        self.assertEqual(capped.runs, [(1, 1), (3, 1), (5, 1)])
        self.assertTrue(capped.truncated)
        self.assertEqual(capped.free_clusters, 16)
        self.assertEqual(bitmap_unallocated_runs(b"\xff" * 4, 32).runs, [])

    def test_runlist_decoding(self) -> None:
        # 0x21: 1-byte length, 2-byte signed delta; second run goes backwards; 0x01: sparse
        self.assertEqual(decode_runlist(bytes([0x21, 4, 0x00, 0x01, 0x11, 2, 0xF0, 0x01, 5, 0x00])), [(256, 4), (240, 2), (None, 5)])


class UnallocatedImageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_native_runs_match_bitmap_and_offsets_are_absolute(self) -> None:
        image = build_ntfs_image(self.base / "disk.raw")
        with open_unallocated_image(image.path, work_dir=self.base / "work", tool_resolver=lambda _name: None) as source:
            self.assertEqual(source.bitmap_method, "native-mft-record-6")
            self.assertEqual(source.partition["start_sector"], PARTITION_SECTOR)
            self.assertEqual(source.partition["selection_method"], "ntfs-oem-id-probe")
            self.assertEqual((source.cluster_size, source.total_clusters), (1024, 600))
            self.assertEqual(source.runs.runs, expected_runs(image))
            self.assertEqual(source.runs.runs, [(13, 87), (150, 450)])
            self.assertEqual(source.unallocated_bytes, (87 + 450) * 1024)
            self.assertEqual(source.cluster_at(image.offset_of(150, 10)), 150)

    def test_volume_image_and_operator_partition(self) -> None:
        image = build_ntfs_image(self.base / "volume.raw", with_mbr=False)
        with open_unallocated_image(image.path, work_dir=self.base / "w", tool_resolver=lambda _name: None) as source:
            self.assertEqual((source.partition["selection_method"], source.partition_offset), ("volume-image", 0))
        disk = build_ntfs_image(self.base / "disk.raw")
        with open_unallocated_image(disk.path, partition_start_sector=PARTITION_SECTOR, work_dir=self.base / "w2") as source:
            self.assertEqual(source.partition["selection_method"], "operator-specified")

    def test_icat_bitmap_when_sleuthkit_is_present(self) -> None:
        image = build_ntfs_image(self.base / "disk.raw")
        bitmap = bytearray(75)
        for cluster in range(600):
            if cluster < 300:
                bitmap[cluster // 8] |= 1 << (cluster % 8)
        commands: list[list[str]] = []

        def fake_icat(command, output_path: Path):
            argv = [str(part) for part in command]
            commands.append(argv)
            output_path.write_bytes(bytes(bitmap))
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        work = self.base / "work"
        with open_unallocated_image(
            image.path, work_dir=work, stream_runner=fake_icat, tool_resolver=lambda name: f"/usr/bin/{name}"
        ) as source:
            self.assertEqual(source.bitmap_method, "sleuthkit-icat")
            self.assertEqual(source.runs.runs, [(300, 300)])
        self.assertEqual(commands, [["icat", "-o", str(PARTITION_SECTOR), str(image.path), "6"]])
        self.assertEqual(list(work.iterdir()), [])  # the extracted $Bitmap copy is removed

    def test_url_across_chunk_boundary_found_once_with_absolute_offset(self) -> None:
        url = b"https://boundary.example.com/path/across/the/chunk"
        # free run 150..599: chunk 4096 bytes from cluster 150 -> boundary at cluster 154
        boundary = (150 * 1024) + 4096
        straddle = 64 * 512 + boundary - 20
        allocated_url = b"https://allocated.example.com/never"
        free_utf16 = "https://wide.example.org/u16".encode("utf-16-le")
        image = build_ntfs_image(
            self.base / "disk.raw",
            payloads={
                straddle: url,
                64 * 512 + 120 * 1024: allocated_url,  # cluster 120: allocated
                64 * 512 + 20 * 1024 + 7: free_utf16,  # cluster 20: free
            },
        )
        data = image.path.read_bytes()
        self.assertEqual(data[straddle : straddle + len(url)], url)
        with open_unallocated_image(image.path, work_dir=self.base / "w", tool_resolver=lambda _name: None) as source:
            stats = ScanStats()
            windows = list(
                iter_unallocated_chunks(
                    source.reader, source.partition_offset, source.cluster_size, source.runs.runs, 1 << 30,
                    stats=stats, chunk_bytes=4096, overlap_bytes=1024,
                )
            )
            # a window boundary falls inside the URL: the first window's new bytes end at `boundary`
            self.assertTrue(any(w.image_offset + len(w.data) == image.partition_offset + boundary for w in windows))
            self.assertEqual(stats.bytes_read, source.unallocated_bytes)
            state = UrlCarveState(None, 100)
            found = scan_url_windows(((w.data, w.image_offset, w.cutoff) for w in windows), state=state)
        by_url = {entry["url"]: entry for entry in found}
        self.assertEqual(set(by_url), {url.decode(), "https://wide.example.org/u16"})
        self.assertEqual(by_url[url.decode()]["offset"], straddle)
        self.assertEqual(by_url[url.decode()]["hit_count"], 1)
        wide = by_url["https://wide.example.org/u16"]
        self.assertEqual((wide["offset"], wide["encoding"]), (64 * 512 + 20 * 1024 + 7, "utf-16le"))
        self.assertEqual(data[wide["offset"] : wide["offset"] + len(free_utf16)], free_utf16)

    def test_read_limit_truncates(self) -> None:
        image = build_ntfs_image(self.base / "disk.raw")
        with open_unallocated_image(image.path, work_dir=self.base / "w", tool_resolver=lambda _name: None) as source:
            stats = ScanStats()
            list(source.windows(5000, stats=stats))
            self.assertEqual(stats.bytes_read, 5000)

    def test_korean_failures(self) -> None:
        from rapidtriage.core.ntfs_unalloc import NtfsUnallocError

        junk = self.base / "junk.raw"
        junk.write_bytes(b"\x11" * 8192)
        with self.assertRaisesRegex(NtfsUnallocError, "NTFS 파티션을 찾지 못했습니다"):
            with open_unallocated_image(junk, work_dir=self.base / "w"):
                pass
        image = build_ntfs_image(self.base / "disk.raw")
        with self.assertRaisesRegex(NtfsUnallocError, "섹터 63에 NTFS 부트 섹터가 없습니다"):
            with open_unallocated_image(image.path, partition_start_sector=63, work_dir=self.base / "w"):
                pass
        ewf = self.base / "fake.E01"
        ewf.write_bytes(b"EVF\x09\x0d\x0a\xff\x00" + bytes(64))
        with patch.object(e01_native, "pyewf", None):
            with self.assertRaisesRegex(NtfsUnallocError, "pyewf"):
                with open_unallocated_image(ewf, work_dir=self.base / "w"):
                    pass


class ImageUnallocatedAnalysisTests(unittest.TestCase):
    BIG_URL = b"https://big-boundary.example.net/a/b/c?q=1"

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.evidence = self.base / "evidence"
        self.evidence.mkdir()
        # 4 KiB clusters, 3,000 clusters (~12 MiB): the free run 13..2999 is longer than one 8 MiB
        # chunk, so the URL placed at the first 8 MiB boundary crosses a real window edge.
        boundary = 64 * 512 + 13 * 4096 + 8 * 1024 * 1024
        self.big_offset = boundary - 17
        self.image = build_ntfs_image(
            self.evidence / "disk.dd",
            cluster_size=4096,
            total_clusters=3000,
            allocated_ranges=((5, 13),),
            payloads={
                self.big_offset: self.BIG_URL,
                64 * 512 + 8 * 4096 + 100: b"https://in-allocated.example.com/x",
            },
        )
        (self.evidence / "pagefile.sys").write_bytes(b"\x00" * 32 + b"https://pagefile.example.com/p " + b"\x00" * 32)
        (self.evidence / "MFT.raw").write_bytes(_mft_record(0, b""))
        run_dir = write_run(self.base, "run", self.evidence)
        self.store = RunJobStore()
        self.run_id = self.store.import_completed_run(run_dir).run_id
        self.client = TestClient(create_app(self.store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})

    def tearDown(self) -> None:
        self.client.close()
        self.temp.cleanup()

    def submit(self, options: dict[str, object]):
        return self.client.post(f"/api/runs/{self.run_id}/analyses", json={"kind": "url-carve", "options": options})

    def wait(self, analysis_id: str) -> dict[str, object]:
        deadline = time.monotonic() + 60
        while True:
            state = self.client.get(f"/api/runs/{self.run_id}/analyses/{analysis_id}").json()
            if state["status"] in analyses.TERMINAL_STATUSES and state.get("finished_at"):
                return state
            self.assertLess(time.monotonic(), deadline, state)
            time.sleep(0.05)

    def rows(self, analysis_id: str) -> list[dict[str, object]]:
        page = self.client.get(f"/api/runs/{self.run_id}/analyses/{analysis_id}/rows", params={"limit": 100}).json()
        return page["rows"]

    def test_default_sources_unchanged(self) -> None:
        self.assertEqual(UrlCarveOptions().sources, ["pagefile", "unallocated"])

    def test_image_unallocated_rows(self) -> None:
        created = self.submit({"sources": ["image-unallocated"], "image_path": str(self.image.path)})
        self.assertEqual(created.status_code, 202, created.text)
        state = self.wait(created.json()["analysis_id"])
        self.assertEqual(state["status"], "completed", state)
        summary = state["summary"]
        self.assertEqual(summary["image_unallocated_status"], "scanned")
        self.assertEqual(summary["image_bitmap_method"], "native-mft-record-6")
        self.assertEqual(summary["image_unallocated_run_count"], 1)
        self.assertEqual(summary["image_unallocated_bytes"], (3000 - 13) * 4096)
        self.assertEqual(summary["image_unallocated_scanned_bytes"], (3000 - 13) * 4096)
        self.assertFalse(summary["image_unallocated_truncated"])
        self.assertEqual(summary["source_file_count"], 0)  # the pagefile is not a requested source
        rows = self.rows(state["analysis_id"])
        self.assertEqual(len(rows), 1, rows)
        details = rows[0]["details"]
        self.assertEqual(rows[0]["artifact_type"], "carved-url-candidate")
        self.assertEqual(details["url"], self.BIG_URL.decode())
        self.assertEqual(
            (details["source_kind"], details["source_kind_label"], details["source_path"]),
            ("image-unallocated", "이미지 미할당 영역", str(self.image.path.resolve())),
        )
        self.assertEqual((details["offset"], details["source_offset"]), (self.big_offset, self.big_offset))
        self.assertEqual(details["cluster"], (self.big_offset - 64 * 512) // 4096)
        self.assertEqual(details["partition_start_sector"], PARTITION_SECTOR)
        self.assertFalse(details["source_truncated"])
        data = self.image.path.read_bytes()
        self.assertEqual(data[details["offset"] : details["offset"] + len(self.BIG_URL)], self.BIG_URL)

    def test_scan_cap_marks_source_truncated_and_mixed_sources(self) -> None:
        created = self.submit(
            {"sources": ["pagefile", "image-unallocated"], "image_path": str(self.image.path), "max_scan_bytes": 1024 * 1024}
        )
        state = self.wait(created.json()["analysis_id"])
        self.assertEqual(state["status"], "completed", state)
        self.assertTrue(state["summary"]["image_unallocated_truncated"])
        self.assertEqual(state["summary"]["image_unallocated_scanned_bytes"], 1024 * 1024)
        self.assertEqual(state["summary"]["kind_counts"], {"pagefile": 1})  # the URL lies past the first MiB
        self.assertEqual(state["progress"]["total"], 2)

    def test_option_validation_in_korean(self) -> None:
        stray = self.submit({"sources": ["pagefile"], "image_path": str(self.image.path)})
        self.assertEqual(stray.status_code, 422)
        self.assertIn("image-unallocated", stray.text)
        self.assertIn("고를 때만 씁니다", stray.text)
        missing = self.submit({"sources": ["image-unallocated"], "image_path": str(self.evidence / "nope.dd")})
        self.assertEqual(missing.status_code, 400)
        self.assertIn("파일이 아닙니다", missing.json()["detail"])
        folder_source = self.submit({"sources": ["image-unallocated"]})  # the run's source is a folder
        self.assertEqual(folder_source.status_code, 400)
        self.assertIn("디스크 이미지(E01/raw)가 필요합니다", folder_source.json()["detail"])
        mft = self.submit({"sources": ["image-unallocated"], "image_path": str(self.evidence / "MFT.raw")})
        self.assertEqual(mft.status_code, 400)
        self.assertIn("$MFT 파일은 디스크 이미지가 아닙니다", mft.json()["detail"])
        negative = self.submit({"sources": ["image-unallocated"], "image_path": str(self.image.path), "partition_start_sector": -1})
        self.assertEqual(negative.status_code, 422)

    def test_runtime_failures_in_korean(self) -> None:
        junk = self.evidence / "junk.dd"
        junk.write_bytes(b"\x22" * 16384)
        state = self.wait(self.submit({"sources": ["image-unallocated"], "image_path": str(junk)}).json()["analysis_id"])
        self.assertEqual(state["status"], "failed")
        self.assertIn("NTFS 파티션을 찾지 못했습니다", state["error"])
        self.assertIn("blkls", state["error"])
        wrong = self.wait(
            self.submit({"sources": ["image-unallocated"], "image_path": str(self.image.path), "partition_start_sector": 2}).json()["analysis_id"]
        )
        self.assertEqual(wrong.get("status"), "failed")
        self.assertIn("NTFS 부트 섹터가 없습니다", wrong["error"])
        ewf = self.evidence / "disk.E01"
        ewf.write_bytes(b"EVF\x09\x0d\x0a\xff\x00" + bytes(64))
        with patch.object(e01_native, "pyewf", None):
            no_tool = self.wait(self.submit({"sources": ["image-unallocated"], "image_path": str(ewf)}).json()["analysis_id"])
            mixed = self.wait(
                self.submit({"sources": ["pagefile", "image-unallocated"], "image_path": str(ewf)}).json()["analysis_id"]
            )
        self.assertEqual(no_tool["status"], "failed")
        self.assertIn("pyewf", no_tool["error"])
        self.assertEqual(mixed["status"], "completed", mixed)  # the file source still yields its rows
        self.assertEqual(mixed["summary"]["image_unallocated_status"], "failed")
        self.assertIn("pyewf", mixed["summary"]["image_unallocated_error"])
        self.assertEqual(mixed["summary"]["candidate_count"], 1)


if __name__ == "__main__":
    unittest.main()
