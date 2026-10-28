from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.core import compare
from rapidtriage.core.digest_cache import RunDigestCache, hash_file_digests


def _expected(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


class _OpenCounter:
    """Counts Path.open calls on real files while still performing them."""

    def __init__(self) -> None:
        self.count = 0
        self._original = Path.open

    def __call__(self, path_self: Path, *args: object, **kwargs: object):
        self.count += 1
        return self._original(path_self, *args, **kwargs)


class HashCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="r8-hashcache-")
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.payload = b"synthetic-r8-payload\n" * 4096

    def _file(self, name: str, data: bytes) -> Path:
        path = self.root / name
        path.write_bytes(data)
        return path

    def test_single_pass_digests_match_hashlib_across_chunks(self) -> None:
        path = self._file("a.bin", self.payload)
        self.assertEqual(hash_file_digests(path, chunk_size=1000), _expected(self.payload))
        self.assertEqual(compare.compute_hashes(path, chunk_size=1000), _expected(self.payload))

    def test_second_call_does_not_reopen_the_file(self) -> None:
        path = self._file("b.bin", self.payload)
        cache = RunDigestCache()
        counter = _OpenCounter()
        with mock.patch.object(Path, "open", autospec=True, side_effect=counter):
            first = cache.compute(path)
            second = cache.compute(path)
        self.assertEqual(first, _expected(self.payload))
        self.assertEqual(second, first)
        self.assertEqual(counter.count, 1)

    def test_mtime_change_invalidates_cache_entry(self) -> None:
        path = self._file("c.bin", self.payload)
        cache = RunDigestCache()
        counter = _OpenCounter()
        with mock.patch.object(Path, "open", autospec=True, side_effect=counter):
            cache.compute(path)
        updated = b"x" * len(self.payload)
        path.write_bytes(updated)
        st = path.stat()
        os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 2_000_000_000))
        with mock.patch.object(Path, "open", autospec=True, side_effect=counter):
            after = cache.compute(path)
        self.assertEqual(counter.count, 2)
        self.assertEqual(after, _expected(updated))

    def test_seeded_digest_is_served_without_reading(self) -> None:
        path = self._file("d.bin", self.payload)
        st = path.stat()
        cache = RunDigestCache()
        seeded = _expected(self.payload)
        cache.seed(path, size=st.st_size, mtime_ns=st.st_mtime_ns, digests=seeded)
        counter = _OpenCounter()
        with mock.patch.object(Path, "open", autospec=True, side_effect=counter):
            result = cache.compute(path)
        self.assertEqual(result, seeded)
        self.assertEqual(counter.count, 0)


if __name__ == "__main__":
    unittest.main()
