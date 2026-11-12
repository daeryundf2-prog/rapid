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
from unittest import mock

from rapidtriage.api.app import routes_reports, runops
from rapidtriage.api.app.validation_source import build_run_validation_source_integrity
from rapidtriage.api.app.viewer_core import build_run_validation_output_hashes
from rapidtriage.core.hash_cache import compute_hashes_cached
from rapidtriage.core.input_root import InputRoot
from rapidtriage.core.run.source import build_run_source_record


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

    def e01_run_summary(self, *, source_type: str = "e01") -> dict[str, object]:
        """The summary shape an E01 run writes: ``root`` is the extraction folder
        (``core/run/__init__.py`` ``build_run_summary(root=input_root.root_path)``), the image is
        ``source.source_path`` (``core/run/source.py``)."""
        for n in (1, 2, 3):
            (self.base / f"disk.E0{n}").write_bytes(bytes([n]) * (64 * n))
        extract_dir = self.base / "out" / "_e01" / "fs"
        extract_dir.mkdir(parents=True)
        (extract_dir / "Windows").mkdir()
        input_root = InputRoot(source_path=str(self.base / "disk.E01"), root_path=extract_dir, kind="e01-derived")
        source = build_run_source_record(input_root, image_result=None)
        if source_type == "e01":
            source = {**source, "type": "e01", "stage_dir": str(self.base / "out" / "_e01")}
        return {
            "root": str(input_root.root_path),
            "scan_scope_root": str(input_root.root_path),
            "source": source,
        }

    def test_e01_run_summary_hashes_the_image_not_the_extraction_folder(self) -> None:
        for source_type in ("e01", "e01-derived"):
            with self.subTest(source_type=source_type):
                self.base = Path(self._tmp.name).resolve() / source_type
                self.base.mkdir()
                summary = self.e01_run_summary(source_type=source_type)
                result = build_run_validation_source_integrity(summary)
                self.assertEqual(result["kind"], "e01")
                self.assertEqual(result["path"], str(self.base / "disk.E01"))
                self.assertEqual(result["path_origin"], "source.source_path")
                self.assertEqual(result["scope"], "container-segments")
                self.assertEqual(
                    [segment["name"] for segment in result["segments"]], ["disk.E01", "disk.E02", "disk.E03"]
                )
                self.assertEqual(
                    result["segments"][2]["sha256"], hashlib.sha256((self.base / "disk.E03").read_bytes()).hexdigest()
                )
                self.assertNotIn("fs", Path(str(result["path"])).parts[-1:])
                self.assertEqual(result["source_metadata"]["analysis_root"], summary["root"])
                self.assertEqual(result["limitations"], [])

    def test_e01_run_tampered_segment_visible_through_run_summary(self) -> None:
        summary = self.e01_run_summary()
        before = build_run_validation_source_integrity(summary)
        tamper_one_byte_keep_metadata(self.base / "disk.E02")
        after = build_run_validation_source_integrity(summary)
        self.assertNotEqual(before["segments"][1]["sha256"], after["segments"][1]["sha256"])
        self.assertEqual(before["segments"][0], after["segments"][0])

    def test_read_only_build_defers_every_digest(self) -> None:
        summary = self.e01_run_summary()
        with mock.patch("rapidtriage.api.app.validation_source.compute_hashes_fresh") as fresh, mock.patch(
            "rapidtriage.api.app.validation_source.sha256_fresh"
        ) as segment_fresh:
            result = build_run_validation_source_integrity(summary, compute_hashes=False)
        fresh.assert_not_called()
        segment_fresh.assert_not_called()
        self.assertEqual(result["hash_status"], "deferred-to-generation")
        self.assertEqual(result["hashes"], {})
        self.assertEqual([segment["hash_status"] for segment in result["segments"]], ["deferred-to-generation"] * 3)
        self.assertEqual([segment["size"] for segment in result["segments"]], [64, 128, 192])

    def test_get_route_defers_and_post_route_hashes(self) -> None:
        source = inspect.getsource(routes_reports.build_reports_router)
        get_body = source.split('@router.get("/api/runs/{run_id}/validation-package")')[1].split("@router")[0]
        post_body = source.split('@router.post("/api/runs/{run_id}/validation-package")')[1].split("@router")[0]
        self.assertIn("compute_source_hashes=False", get_body)
        self.assertNotIn("compute_source_hashes=False", post_body)

    def test_segment_gap_and_undiscovered_siblings_are_named(self) -> None:
        for name in ("disk.E01", "disk.E03", "disk.EAA", "DISK.E02"):
            (self.base / name).write_bytes(b"seg")
        result = build_run_validation_source_integrity({"root": str(self.base / "disk.E01")})
        warnings = result["segment_warnings"]
        self.assertTrue(any("missing" in warning and "[2]" in warning for warning in warnings), warnings)
        undiscovered = [warning for warning in warnings if "not included" in warning]
        self.assertEqual(len(undiscovered), 1)
        self.assertIn("disk.EAA", undiscovered[0])
        self.assertIn("DISK.E02", undiscovered[0])
        for warning in warnings:
            self.assertIn(warning, result["limitations"])

    def test_review_status_uses_the_t028_merged_review_payload(self) -> None:
        # Same function T-028 wired in: the merged bookmark JSON + case DB payload.
        source = inspect.getsource(runops.build_run_validation_package)
        self.assertIn("_validation_review_payload(store, run_id, summary)", source)
        self.assertIn("load_run_review_payload", inspect.getsource(runops._run_review_payload))


if __name__ == "__main__":
    unittest.main()
