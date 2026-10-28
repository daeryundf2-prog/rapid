"""Recovery-mode deleted-entry parity: unbounded MFT sweep, partial entries flagged, pytsk3 _deleted/."""

from __future__ import annotations

import hashlib
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.core import coverage, e01_native
from tests.test_r8_extract import _Dir, _File, _Handle, _make_ntfs
from tests.test_r8_partitions import (
    FAT_SECTORS,
    HELLO,
    SECTOR,
    START_A,
    _RawHandle,
    build_disk,
    build_fat16,
)


class _BrokenStream:
    """Returns ``head`` once, then fails like a read of an unreadable data run."""

    def __init__(self, head: bytes) -> None:
        self._head = head

    def read(self, n: int) -> bytes:
        if self._head:
            out, self._head = self._head, b""
            return out
        raise OSError("unreadable cluster run")


class _PartlyUnreadable(_File):
    def __init__(self, segment: int, head: bytes, size: int) -> None:
        super().__init__(segment, b"", deleted=True)
        self._head = head
        self._size = size

    def size(self) -> int:
        return self._size

    def open(self):
        return _BrokenStream(self._head)


class _Reused(_File):
    def dataruns(self):
        return [(10, 2)]


class _Bitmap(_File):
    def __init__(self, bitmap: bytes) -> None:
        super().__init__(6, bitmap)


def _deleted_files(count: int, first: int = 30) -> dict[int, _File]:
    return {seg: _File(seg, f"deleted-{seg}".encode() * 7, deleted=True) for seg in range(first, first + count)}


class DeletedMftSweepTests(unittest.TestCase):
    def setUp(self) -> None:
        coverage.reset_coverage()

    def _run(self, files: dict[int, _File], out: Path, *, run_mode: str | None, cap: int = 3):
        root = _Dir({"kept.txt": files[20]})
        env = {e01_native.NATIVE_E01_WORKERS_ENV: "2", e01_native.NATIVE_MAX_EXTRACT_FILES_ENV: str(cap)}
        with (
            mock.patch.object(e01_native, "open_ewf_segments", lambda _segs: _Handle()),
            mock.patch.object(e01_native, "NTFS", _make_ntfs(files, root)),
            mock.patch.dict("os.environ", env),
        ):
            return e01_native.extract_e01_native(Path("x.E01"), [Path("x.E01")], out, run_mode=run_mode)

    def _cap_entries(self) -> list[dict[str, object]]:
        return [e for e in coverage.coverage_entries() if e["reason_code"] == "deleted-sweep-cap"]

    def test_default_mode_is_bounded_and_discloses_the_cap(self) -> None:
        files = {20: _File(20, b"live"), **_deleted_files(8)}
        with tempfile.TemporaryDirectory() as tmp:
            result = self._run(files, Path(tmp), run_mode=None)
        self.assertEqual(result["stats"]["deleted_files"], 2)
        self.assertEqual(result["stats"]["truncated"], 6)
        self.assertEqual(
            self._cap_entries(),
            [{"area": "e01_native.deleted_mft", "reason_code": "deleted-sweep-cap", "limit": 3, "observed": 8, "unit": "files"}],
        )

    def test_recovery_mode_sweeps_beyond_the_old_cap(self) -> None:
        files = {20: _File(20, b"live"), **_deleted_files(8)}
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            result = self._run(files, out, run_mode="recovery")
            swept = sorted(p.name for p in (out / "_deleted_mft").iterdir())
            self.assertEqual(len(swept), 8)
            for seg in range(30, 38):
                rel = f"_deleted_mft/{seg}-gone{seg}.bin"
                self.assertEqual((out / rel).read_bytes(), files[seg].content)
                self.assertNotIn("partial", result["file_digests"][rel])
        self.assertEqual(result["stats"]["deleted_files"], 8)
        self.assertEqual(result["stats"]["truncated"], 0)
        self.assertEqual(self._cap_entries(), [])

    def test_partly_unreadable_record_is_written_and_flagged_partial(self) -> None:
        head = b"readable-prefix"
        files = {20: _File(20, b"live"), 50: _PartlyUnreadable(50, head, 4096)}
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            result = self._run(files, out, run_mode="recovery")
            rel = "_deleted_mft/50-gone50.bin"
            self.assertEqual((out / rel).read_bytes(), head)
            entry = result["file_digests"][rel]
        self.assertIs(entry["partial"], True)
        self.assertEqual(entry["partial_reasons"], ["unreadable"])
        self.assertEqual(entry["expected_size_bytes"], 4096)
        self.assertEqual(entry["size_bytes"], len(head))
        self.assertEqual(entry["sha256"], hashlib.sha256(head).hexdigest())
        self.assertEqual(result["stats"]["deleted_partial"], 1)
        self.assertEqual(result["stats"]["deleted_files"], 1)

    def test_default_mode_never_presents_the_damaged_record_as_intact(self) -> None:
        files = {20: _File(20, b"live"), 50: _PartlyUnreadable(50, b"readable-prefix", 4096)}
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            result = self._run(files, out, run_mode=None)
            self.assertFalse((out / "_deleted_mft" / "50-gone50.bin").exists())
        self.assertNotIn("_deleted_mft/50-gone50.bin", result["file_digests"])
        self.assertEqual(result["stats"]["deleted_read_errors"], 1)

    def test_reallocated_runs_are_flagged_partial(self) -> None:
        bitmap = bytearray(16)
        bitmap[1] = 0b0000_0100  # cluster 10 is allocated again
        files = {
            20: _File(20, b"live"),
            6: _Bitmap(bytes(bitmap)),
            60: _Reused(60, b"overwritten?" * 4, deleted=True),
            61: _File(61, b"resident deleted", deleted=True),
        }
        with tempfile.TemporaryDirectory() as tmp:
            result = self._run(files, Path(tmp), run_mode="recovery")
        reused = result["file_digests"]["_deleted_mft/60-gone60.bin"]
        self.assertIs(reused["partial"], True)
        self.assertEqual(reused["partial_reasons"], ["reallocated"])
        self.assertNotIn("partial", result["file_digests"]["_deleted_mft/61-gone61.bin"])

    def test_cluster_bitmap_probe(self) -> None:
        bitmap = bytes([0, 0, 0b1000_0000, 0])
        self.assertTrue(e01_native._any_cluster_allocated(bitmap, 23, 1))
        self.assertTrue(e01_native._any_cluster_allocated(bitmap, 0, 32))
        self.assertFalse(e01_native._any_cluster_allocated(bitmap, 0, 23))
        self.assertFalse(e01_native._any_cluster_allocated(bitmap, 24, 8))
        self.assertTrue(e01_native._any_cluster_allocated(bitmap, 30, 4))  # runs past the volume


def _fat_with_deleted_file(content: bytes) -> bytes:
    """FAT16 volume holding HELLO.TXT plus a deleted GONE.BIN whose cluster is free again."""
    volume = bytearray(build_fat16(START_A, {b"HELLO   TXT": HELLO, b"GONE    BIN": content}, (b"DEEP    BIN", b"d")))
    at = volume.index(b"GONE    BIN")
    cluster = struct.unpack_from("<H", volume, at + 26)[0]
    volume[at] = 0xE5
    for fat in range(2):
        struct.pack_into("<H", volume, SECTOR + fat * FAT_SECTORS * SECTOR + cluster * 2, 0)
    return bytes(volume)


class TskDeletedTests(unittest.TestCase):
    def setUp(self) -> None:
        coverage.reset_coverage()

    def _extract(self, disk: bytes, out: Path, run_mode: str | None):
        with mock.patch.object(e01_native, "open_ewf_segments", lambda _segs: _RawHandle(disk)):
            return e01_native.extract_e01_native(Path("x.E01"), [Path("x.E01")], out, run_mode=run_mode)

    def test_recovery_mode_extracts_unallocated_entries_into_deleted(self) -> None:
        gone = b"deleted fat payload\n"
        disk = build_disk([(0x06, START_A, _fat_with_deleted_file(gone))])
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "fs"
            result = self._extract(disk, out, "recovery")
            self.assertEqual((out / "HELLO.TXT").read_bytes(), HELLO)
            recovered = [p for p in (out / "_deleted").rglob("*") if p.is_file()]
            self.assertEqual(len(recovered), 1)
            self.assertEqual(recovered[0].read_bytes(), gone)
            rel = recovered[0].relative_to(out).as_posix()
            self.assertNotIn("partial", result["file_digests"][rel])
            self.assertEqual(result["file_digests"][rel]["md5"], hashlib.md5(gone).hexdigest())
        self.assertEqual(result["stats"]["deleted_files"], 1)
        self.assertEqual(coverage.coverage_entries(), [])

    def test_default_mode_skips_deleted_entries_with_coverage(self) -> None:
        disk = build_disk([(0x06, START_A, _fat_with_deleted_file(b"deleted fat payload\n"))])
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "fs"
            result = self._extract(disk, out, None)
            self.assertFalse((out / "_deleted").exists())
        self.assertEqual(result["stats"]["deleted_files"], 0)
        self.assertEqual(
            coverage.coverage_entries(),
            [{"area": "e01_native.deleted_tsk", "reason_code": "deleted-sweep-cap", "limit": 0, "observed": 1, "unit": "files"}],
        )

    def test_unreadable_tsk_entry_is_flagged_partial(self) -> None:
        class _Meta:
            size = 100

        class _Info:
            meta = _Meta()

        class _Entry:
            info = _Info()

            def read_random(self, offset: int, n: int) -> bytes:
                if offset == 0:
                    return b"x" * 10
                raise OSError("unreadable")

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "_deleted" / "7-gone"
            size, _, partial = e01_native._dump_hashed_salvage(e01_native._TskFile(_Entry()), target)
            self.assertEqual(target.read_bytes(), b"x" * 10)
        self.assertEqual(size, 10)
        self.assertEqual(partial, {"partial": True, "partial_reasons": ["unreadable"], "expected_size_bytes": 100})


if __name__ == "__main__":
    unittest.main()
