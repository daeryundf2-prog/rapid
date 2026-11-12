"""R8 T-179: the run validation package recomputes integrity values instead of trusting a cache.

The package's source hash was served from the metadata-keyed hash cache (path + size + mtime), so
a 1-byte change that kept size and mtime reported the old digest. It is now re-read from disk; an
E01/Ex01 source lists every discovered segment (name, size, SHA-256) with
``scope: container-segments``. All fixtures are synthetic bytes written to a temp directory.
"""

from __future__ import annotations

import hashlib
import inspect
import os
import tempfile
import unittest
from pathlib import Path

from rapidtriage.api.app import runops
from rapidtriage.api.app.viewer_core import (
    build_run_validation_output_hashes,
    build_run_validation_source_integrity,
)
from rapidtriage.core.hash_cache import compute_hashes_cached


def tamper_one_byte_keep_metadata(path: Path) -> None:
    stat = path.stat()
    data = bytearray(path.read_bytes())
    data[0] ^= 0xFF
    path.write_bytes(bytes(data))
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    after = path.stat()
    assert after.st_size == stat.st_size and after.st_mtime_ns == stat.st_mtime_ns


class ValidationPackageFreshHashTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name).resolve()
        self.addCleanup(self._tmp.cleanup)

    def test_tampered_copy_with_same_size_and_mtime_changes_source_hash(self) -> None:
        source = self.base / "evidence.bin"
        source.write_bytes(b"synthetic evidence bytes" * 64)
        # Warm the metadata cache the old code read from.
        cached_before = compute_hashes_cached(source)
        before = build_run_validation_source_integrity({"root": str(source)})
        tamper_one_byte_keep_metadata(source)
        after = build_run_validation_source_integrity({"root": str(source)})

        self.assertEqual(before["hash_source"], "fresh-file-read")
        self.assertEqual(before["hashes"]["sha256"], cached_before["sha256"])
        self.assertNotEqual(after["hashes"]["sha256"], before["hashes"]["sha256"])
        self.assertEqual(after["hashes"]["sha256"], hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertEqual(after["size"], before["size"])
        self.assertNotIn("segments", after)

    def test_tampered_output_with_same_size_and_mtime_changes_output_hash(self) -> None:
        output_dir = self.base / "out"
        output_dir.mkdir()
        output = output_dir / "files.json"
        output.write_bytes(b'{"items": []}' * 10)
        summary = {"outputs": {"files": str(output)}}
        before = build_run_validation_output_hashes(summary, output_dir=output_dir)
        tamper_one_byte_keep_metadata(output)
        after = build_run_validation_output_hashes(summary, output_dir=output_dir)
        self.assertEqual(after["hash_source"], "fresh-file-read")
        self.assertNotEqual(after["items"][0]["hashes"]["sha256"], before["items"][0]["hashes"]["sha256"])

    def test_three_segment_e01_lists_every_segment(self) -> None:
        payloads = {f"disk.E0{n}": bytes([n]) * (100 * n) for n in (1, 2, 3)}
        for name, data in payloads.items():
            (self.base / name).write_bytes(data)
        (self.base / "other.E01").write_bytes(b"not part of the set")

        result = build_run_validation_source_integrity({"root": str(self.base / "disk.E01")})

        self.assertEqual(result["kind"], "e01")
        self.assertEqual(result["scope"], "container-segments")
        segments = result["segments"]
        self.assertEqual([segment["name"] for segment in segments], ["disk.E01", "disk.E02", "disk.E03"])
        for segment in segments:
            data = payloads[segment["name"]]
            self.assertEqual(segment["size"], len(data))
            self.assertEqual(segment["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(result["hashes"]["sha256"], segments[0]["sha256"])

    def test_tampered_later_segment_is_visible(self) -> None:
        for n in (1, 2, 3):
            (self.base / f"disk.E0{n}").write_bytes(bytes([n]) * 256)
        before = build_run_validation_source_integrity({"root": str(self.base / "disk.E01")})
        tamper_one_byte_keep_metadata(self.base / "disk.E03")
        after = build_run_validation_source_integrity({"root": str(self.base / "disk.E01")})
        self.assertEqual(before["segments"][:2], after["segments"][:2])
        self.assertNotEqual(before["segments"][2]["sha256"], after["segments"][2]["sha256"])

    def test_ex01_family_uses_container_segments(self) -> None:
        for n in (1, 2):
            (self.base / f"disk.Ex0{n}").write_bytes(b"ex" * n)
        result = build_run_validation_source_integrity({"root": str(self.base / "disk.Ex01")})
        self.assertEqual(result["scope"], "container-segments")
        self.assertEqual([segment["name"] for segment in result["segments"]], ["disk.Ex01", "disk.Ex02"])

    def test_review_status_uses_the_t028_merged_review_payload(self) -> None:
        # Same function T-028 wired in: the merged bookmark JSON + case DB payload.
        source = inspect.getsource(runops.build_run_validation_package)
        self.assertIn("_validation_review_payload(store, run_id, summary)", source)
        self.assertIn("load_run_review_payload", inspect.getsource(runops._run_review_payload))


if __name__ == "__main__":
    unittest.main()
