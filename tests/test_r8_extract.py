from __future__ import annotations

import hashlib
import io
import tempfile
import threading
import unittest
from pathlib import Path
from typing import ClassVar
from unittest import mock

from rapidtriage.core import e01_native


class _Handle:
    opened: ClassVar[list[_Handle]] = []

    def __init__(self) -> None:
        mbr = bytearray(512)
        mbr[0x1BE + 4] = 0x07
        mbr[0x1BE + 8 : 0x1BE + 16] = (1).to_bytes(4, "little") + (4).to_bytes(4, "little")
        mbr[510:512] = b"\x55\xaa"
        self._data = bytes(mbr) + b"\x00\x00\x00NTFS    " + b"\x00" * 2036
        self._pos = 0
        self.closed = False
        self.owner = threading.get_ident()
        _Handle.opened.append(self)

    def get_media_size(self) -> int:
        return len(self._data)

    def seek(self, offset: int, whence: int = 0) -> None:
        self._pos = offset

    def read(self, size: int) -> bytes:
        out = self._data[self._pos : self._pos + size]
        self._pos += len(out)
        return out

    def close(self) -> None:
        self.closed = True


class _File:
    def __init__(self, segment: int, content: bytes, *, deleted: bool = False) -> None:
        self.segment = segment
        self.content = content
        self.filename = f"gone{segment}.bin"
        self.header = mock.Mock(Flags=0 if deleted else 1)

    def is_dir(self) -> bool:
        return False

    def is_file(self) -> bool:
        return True

    def size(self) -> int:
        return len(self.content)

    def open(self):
        return io.BytesIO(self.content)


class _Dir:
    segment = 5

    def __init__(self, children: dict) -> None:
        self._children = children

    def is_dir(self) -> bool:
        return True

    def is_file(self) -> bool:
        return False

    def listdir(self, ignore_dos: bool = False):
        return list(self._children)

    def get(self, name):
        return self._children.get(name)


def _make_ntfs(files: dict[int, _File], root: _Dir):
    class _Mft:
        fh = mock.Mock(size=1024 * 64)

        def get(self, index):
            if index == 5:
                return root
            if index in files:
                return files[index]
            raise KeyError(index)

    class _Fs:
        boot_sector = mock.Mock(clusters_per_file_record=-10)
        cluster_size = 4096
        volume_name = "VOL"
        serial = 1

        def __init__(self, reader) -> None:
            self.mft = _Mft()

    return _Fs


class ParallelExtractTests(unittest.TestCase):
    def _fixture(self):
        payloads = {20 + i: (f"payload-{i}-".encode() * (50 + i)) for i in range(12)}
        files = {seg: _File(seg, data) for seg, data in payloads.items()}
        files[40] = _File(40, b"deleted-bytes" * 10, deleted=True)
        root = _Dir(
            {
                **{f"f{seg}.txt": files[seg] for seg in list(payloads)[:6]},
                "sub": _Dir({f"g{seg}.txt": files[seg] for seg in list(payloads)[6:]}),
            }
        )
        return files, payloads, root

    def _run(self, workers: int, files, root, out: Path):
        _Handle.opened = []
        with (
            mock.patch.object(e01_native, "open_ewf_segments", lambda _segs: _Handle()),
            mock.patch.object(e01_native, "NTFS", _make_ntfs(files, root)),
            mock.patch.dict("os.environ", {e01_native.NATIVE_E01_WORKERS_ENV: str(workers)}),
        ):
            return e01_native.extract_e01_native(Path("x.E01"), [Path("x.E01")], out)

    def test_digests_match_extracted_bytes_and_layout_is_stable(self) -> None:
        files, payloads, root = self._fixture()
        trees = []
        for workers in (1, 4):
            with tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp)
                result = self._run(workers, files, root, out)
                digests = result["file_digests"]
                on_disk = sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file())
                self.assertEqual(sorted(digests), on_disk)
                self.assertEqual(result["stats"]["files"], len(on_disk))
                self.assertEqual(result["stats"]["deleted_files"], 1)
                self.assertEqual(result["stats"]["errors"], 0)
                for rel, entry in digests.items():
                    data = (out / rel).read_bytes()
                    self.assertEqual(entry["size_bytes"], len(data))
                    self.assertEqual(entry["md5"], hashlib.md5(data).hexdigest())
                    self.assertEqual(entry["sha1"], hashlib.sha1(data).hexdigest())
                    self.assertEqual(entry["sha256"], hashlib.sha256(data).hexdigest())
                trees.append({rel: (out / rel).read_bytes() for rel in on_disk})
        self.assertEqual(trees[0], trees[1])
        self.assertIn("_deleted_mft/40-gone40.bin", trees[0])
        self.assertIn("sub/g26.txt", trees[0])

    def test_each_worker_owns_its_handle_and_all_are_closed(self) -> None:
        files, _, root = self._fixture()
        with tempfile.TemporaryDirectory() as tmp:
            self._run(4, files, root, Path(tmp))
        # main-thread handle + worker handles, each used by a single thread, all closed
        self.assertGreaterEqual(len(_Handle.opened), 2)
        self.assertEqual(len({h.owner for h in _Handle.opened}), len(_Handle.opened))
        self.assertTrue(all(h.closed for h in _Handle.opened))

    def test_worker_exception_fails_the_run(self) -> None:
        files, _, root = self._fixture()
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(e01_native, "_dump_hashed", side_effect=RuntimeError("worker boom")):
                with self.assertRaisesRegex(RuntimeError, "worker boom"):
                    self._run(3, files, root, Path(tmp))
        self.assertTrue(all(h.closed for h in _Handle.opened))

    def test_worker_count_env(self) -> None:
        with mock.patch.dict("os.environ", {e01_native.NATIVE_E01_WORKERS_ENV: "3"}):
            self.assertEqual(e01_native.native_extract_worker_count(), 3)
        with mock.patch.dict("os.environ", {e01_native.NATIVE_E01_WORKERS_ENV: "junk"}):
            self.assertTrue(1 <= e01_native.native_extract_worker_count() <= 8)


if __name__ == "__main__":
    unittest.main()
