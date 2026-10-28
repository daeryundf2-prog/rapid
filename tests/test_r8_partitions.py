"""Native E01 engine extracts every partition (synthetic MBR + FAT16 volumes, real pytsk3)."""

from __future__ import annotations

import hashlib
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.core import coverage, e01_native

SECTOR = 512
FAT16_SECTORS = 4200  # 4133 data clusters -> TSK classifies the volume as FAT16
FAT_SECTORS = 17
ROOT_SECTORS = 32
DATA_START = 1 + 2 * FAT_SECTORS + ROOT_SECTORS


def _dir_entry(name: bytes, attr: int, cluster: int, size: int) -> bytes:
    return name.ljust(11) + bytes([attr]) + b"\x00" * 14 + struct.pack("<HI", cluster, size)


def build_fat16(hidden: int, files: dict[bytes, bytes], subdir_file: tuple[bytes, bytes]) -> bytes:
    """A FAT16 volume: ``files`` in the root, ``SUB/<subdir_file>``; every file fits one cluster."""
    boot = bytearray(SECTOR)
    boot[0:3] = b"\xeb\x3c\x90"
    boot[3:11] = b"MSDOS5.0"
    struct.pack_into("<HBHBHHBHHHI", boot, 11, SECTOR, 1, 1, 2, 512, FAT16_SECTORS, 0xF8, FAT_SECTORS, 32, 2, hidden)
    boot[36:38] = b"\x80\x00"
    boot[38] = 0x29
    boot[39:43] = b"\x01\x02\x03\x04"
    boot[43:54] = b"TESTVOL    "
    boot[54:62] = b"FAT16   "
    boot[510:512] = b"\x55\xaa"

    image = bytearray(FAT16_SECTORS * SECTOR)
    image[:SECTOR] = boot
    fat = bytearray(FAT_SECTORS * SECTOR)
    struct.pack_into("<HH", fat, 0, 0xFFF8, 0xFFFF)
    root = bytearray()
    next_cluster = 2

    def put_cluster(data: bytes) -> int:
        nonlocal next_cluster
        cluster = next_cluster
        next_cluster += 1
        struct.pack_into("<H", fat, cluster * 2, 0xFFFF)
        offset = (DATA_START + cluster - 2) * SECTOR
        image[offset : offset + len(data)] = data
        return cluster

    for name, content in files.items():
        root += _dir_entry(name, 0x20, put_cluster(content), len(content))
    sub_name, sub_content = subdir_file
    sub_cluster = next_cluster
    deep_cluster = sub_cluster + 1
    sub = _dir_entry(b".", 0x10, sub_cluster, 0) + _dir_entry(b"..", 0x10, 0, 0)
    sub += _dir_entry(sub_name, 0x20, deep_cluster, len(sub_content))
    assert put_cluster(sub) == sub_cluster
    assert put_cluster(sub_content) == deep_cluster
    root += _dir_entry(b"SUB", 0x10, sub_cluster, 0)

    image[SECTOR : SECTOR + len(fat)] = fat
    image[SECTOR + len(fat) : SECTOR + 2 * len(fat)] = fat
    root_offset = (1 + 2 * FAT_SECTORS) * SECTOR
    image[root_offset : root_offset + len(root)] = root
    return bytes(image)


def mbr_entry(ptype: int, start: int, count: int) -> bytes:
    return b"\x00\x00\x00\x00" + bytes([ptype]) + b"\x00\x00\x00" + struct.pack("<II", start, count)


def build_disk(partitions: list[tuple[int, int, bytes]]) -> bytes:
    """MBR disk from ``(type, start_sector, volume_bytes)`` rows."""
    end = max(start * SECTOR + len(volume) for _, start, volume in partitions)
    disk = bytearray(end)
    for slot, (ptype, start, volume) in enumerate(partitions):
        disk[0x1BE + slot * 16 : 0x1BE + (slot + 1) * 16] = mbr_entry(ptype, start, len(volume) // SECTOR)
        disk[start * SECTOR : start * SECTOR + len(volume)] = volume
    disk[510:512] = b"\x55\xaa"
    return bytes(disk)


class _RawHandle:
    """pyewf-handle-shaped view over in-memory bytes."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def get_media_size(self) -> int:
        return len(self._data)

    def seek(self, offset: int, whence: int = 0) -> None:
        self._pos = offset

    def read(self, size: int) -> bytes:
        out = self._data[self._pos : self._pos + size]
        self._pos += len(out)
        return out

    def close(self) -> None:
        pass


HELLO = b"hello from partition one\n"
DEEP = b"deep file one " * 20
WORLD = b"world from partition two\n"
DEEP2 = b"deep file two " * 15
START_A = 64
START_B = START_A + FAT16_SECTORS + 8
START_C = START_B + FAT16_SECTORS + 8


def _volume_a() -> bytes:
    return build_fat16(START_A, {b"HELLO   TXT": HELLO}, (b"DEEP    BIN", DEEP))


def _volume_b() -> bytes:
    return build_fat16(START_B, {b"WORLD   TXT": WORLD}, (b"DEEP2   BIN", DEEP2))


class AllPartitionsTests(unittest.TestCase):
    def setUp(self) -> None:
        coverage.reset_coverage()

    def _extract(self, disk: bytes, out: Path, **kwargs):
        with mock.patch.object(e01_native, "open_ewf_segments", lambda _segs: _RawHandle(disk)):
            return e01_native.extract_e01_native(Path("x.E01"), [Path("x.E01")], out, **kwargs)

    def test_two_partitions_extracted_and_unknown_type_in_coverage(self) -> None:
        disk = build_disk(
            [(0x06, START_A, _volume_a()), (0x06, START_B, _volume_b()), (0xA5, START_C, b"\x00" * (100 * SECTOR))]
        )
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "fs"
            result = self._extract(disk, out)
            self.assertEqual((out / "p0" / "HELLO.TXT").read_bytes(), HELLO)
            self.assertEqual((out / "p0" / "SUB" / "DEEP.BIN").read_bytes(), DEEP)
            self.assertEqual((out / "p1" / "WORLD.TXT").read_bytes(), WORLD)
            self.assertEqual((out / "p1" / "SUB" / "DEEP2.BIN").read_bytes(), DEEP2)
            self.assertFalse((out / "HELLO.TXT").exists())
            digests = result["file_digests"]
            self.assertEqual(
                sorted(digests), ["p0/HELLO.TXT", "p0/SUB/DEEP.BIN", "p1/SUB/DEEP2.BIN", "p1/WORLD.TXT"]
            )
            for rel, entry in digests.items():
                data = (out / rel).read_bytes()
                self.assertEqual(entry["size_bytes"], len(data))
                self.assertEqual(entry["md5"], hashlib.md5(data).hexdigest())
                self.assertEqual(entry["sha1"], hashlib.sha1(data).hexdigest())
                self.assertEqual(entry["sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(result["stats"]["files"], 4)
            self.assertEqual(
                [(p["partition_number"], p["filesystem"], p["directory"]) for p in result["extracted_partitions"]],
                [(0, "fat", "p0"), (1, "fat", "p1")],
            )
        self.assertEqual(
            coverage.coverage_entries(),
            [
                {
                    "area": "partition",
                    "reason_code": "unsupported-filesystem",
                    "limit": None,
                    "observed": START_C,
                    "unit": "start_sector",
                }
            ],
        )

    def test_single_extractable_partition_keeps_flat_layout(self) -> None:
        disk = build_disk([(0x06, START_A, _volume_a()), (0xA5, START_B, b"\x00" * (100 * SECTOR))])
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "fs"
            result = self._extract(disk, out)
            self.assertEqual((out / "HELLO.TXT").read_bytes(), HELLO)
            self.assertEqual((out / "SUB" / "DEEP.BIN").read_bytes(), DEEP)
            self.assertFalse((out / "p0").exists())
            self.assertEqual(sorted(result["file_digests"]), ["HELLO.TXT", "SUB/DEEP.BIN"])
        self.assertEqual([e["reason_code"] for e in coverage.coverage_entries()], ["unsupported-filesystem"])

    def test_explicit_start_sector_selects_only_that_partition(self) -> None:
        disk = build_disk([(0x06, START_A, _volume_a()), (0x06, START_B, _volume_b())])
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "fs"
            result = self._extract(disk, out, partition_start_sector=START_B)
            self.assertEqual((out / "WORLD.TXT").read_bytes(), WORLD)
            self.assertFalse((out / "HELLO.TXT").exists())
            self.assertEqual(result["selected_start_sector"], START_B)
            self.assertEqual(len(result["extracted_partitions"]), 1)
        self.assertEqual(coverage.coverage_entries(), [])

    def test_no_supported_partition_raises_with_coverage(self) -> None:
        disk = build_disk([(0xA5, START_A, b"\x00" * (100 * SECTOR))])
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                self._extract(disk, Path(tmp) / "fs")
        self.assertEqual([e["area"] for e in coverage.coverage_entries()], ["e01_native.filesystem"])


if __name__ == "__main__":
    unittest.main()
