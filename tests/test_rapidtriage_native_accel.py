"""R4-1: native acceleration bridge tests.

Covers the PyO3 extension (when built), the pure-Python fallback scanner, and
result parity between the two paths on a synthetic EVTX blob.
"""
from __future__ import annotations

import struct
import subprocess
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from rapidtriage.core import native_accel

FILE_HEADER = 4096
CHUNK = 65536


def _write_sample_evtx(path: Path) -> None:
    blob = bytearray(FILE_HEADER + CHUNK)
    blob[0:8] = native_accel.EVTX_FILE_SIGNATURE
    struct.pack_into("<Q", blob, 24, 3)
    chunk = FILE_HEADER
    blob[chunk : chunk + 8] = native_accel.EVTX_CHUNK_SIGNATURE
    struct.pack_into("<Q", blob, chunk + 8, 1)
    struct.pack_into("<Q", blob, chunk + 16, 2)
    struct.pack_into("<I", blob, chunk + 44, 2048)
    rec = chunk + 64
    blob[rec : rec + 4] = native_accel.EVTX_RECORD_MAGIC
    struct.pack_into("<I", blob, rec + 4, 48)
    struct.pack_into("<Q", blob, rec + 8, 7)
    struct.pack_into("<Q", blob, rec + 16, 0xDEADBEEF)
    struct.pack_into("<I", blob, rec + 44, 48)
    # slack record beyond free_space_offset
    rec2 = chunk + 4096
    blob[rec2 : rec2 + 4] = native_accel.EVTX_RECORD_MAGIC
    struct.pack_into("<I", blob, rec2 + 4, 48)
    struct.pack_into("<Q", blob, rec2 + 8, 9)
    struct.pack_into("<Q", blob, rec2 + 16, 0xCAFE)
    struct.pack_into("<I", blob, rec2 + 44, 48)
    path.write_bytes(bytes(blob))


class NativeAccelTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.evtx = Path(self._tmp.name) / "sample.evtx"
        _write_sample_evtx(self.evtx)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_python_fallback_scans_chunk_and_records(self) -> None:
        result = native_accel._scan_evtx_python(self.evtx, 1024)
        self.assertTrue(result["file_header"]["signature_valid"])
        self.assertEqual(result["file_header"]["next_record_identifier"], 3)
        self.assertEqual(len(result["chunks"]), 1)
        self.assertEqual(len(result["records"]), 2)
        allocated, slack = result["records"]
        self.assertEqual(allocated["record_id"], 7)
        self.assertEqual(allocated["timestamp_filetime"], 0xDEADBEEF)
        self.assertEqual(allocated["allocation_status"], "allocated")
        self.assertEqual(slack["record_id"], 9)
        self.assertEqual(slack["allocation_status"], "slack")
        self.assertTrue(allocated["trailing_size_valid"])

    def test_scan_evtx_dispatches_available_engine(self) -> None:
        result = native_accel.scan_evtx(self.evtx)
        self.assertIn(native_accel.engine(), ("pyo3-rapidcore", "rapid-worker-subprocess", "python-fallback"))
        self.assertEqual(len(result["records"]), 2)

    def test_extension_and_fallback_parity(self) -> None:
        if native_accel._EXTENSION is None:
            self.skipTest("rapidcore_native extension not built")
        native = native_accel.scan_evtx(self.evtx)
        fallback = native_accel._scan_evtx_python(self.evtx, 1024)
        self.assertEqual(native["file_header"], fallback["file_header"])
        self.assertEqual(native["chunks"], fallback["chunks"])
        self.assertEqual(native["records"], fallback["records"])
        self.assertFalse(native["truncated"])

    def test_truncation_flag_on_bounded_scan(self) -> None:
        result = native_accel._scan_evtx_python(self.evtx, 1)
        self.assertTrue(result["truncated"])
        self.assertEqual(len(result["records"]), 1)

    def test_short_file_returns_empty_scan(self) -> None:
        tiny = Path(self._tmp.name) / "tiny.evtx"
        tiny.write_bytes(b"tiny")
        result = native_accel.scan_evtx(tiny)
        self.assertEqual(result["chunks"], [])
        self.assertEqual(result["records"], [])

    def test_failed_worker_falls_back_to_python(self) -> None:
        # A degraded worker lane (non-zero exit) must not take the scan down —
        # the documented contract is a fallback chain.
        with unittest.mock.patch.object(
            native_accel, "_EXTENSION", None
        ), unittest.mock.patch.object(
            native_accel, "_worker_binary", return_value=Path("fake-worker")
        ), unittest.mock.patch.object(
            native_accel.subprocess,
            "run",
            side_effect=subprocess.CalledProcessError(1, ["fake-worker"]),
        ):
            result = native_accel.scan_evtx(self.evtx)
        self.assertEqual(len(result["records"]), 2)

    def test_worker_bad_output_falls_back_to_python(self) -> None:
        class _Completed:
            stdout = "not json"

        with unittest.mock.patch.object(
            native_accel, "_EXTENSION", None
        ), unittest.mock.patch.object(
            native_accel, "_worker_binary", return_value=Path("fake-worker")
        ), unittest.mock.patch.object(
            native_accel.subprocess, "run", return_value=_Completed()
        ):
            result = native_accel.scan_evtx(self.evtx)
        self.assertEqual(len(result["records"]), 2)

    def test_engine_info_reports_shape(self) -> None:
        info = native_accel.engine_info()
        self.assertIn(info["engine"], ("pyo3-rapidcore", "rapid-worker-subprocess", "python-fallback"))
        self.assertIsInstance(info["available"], bool)


if __name__ == "__main__":
    unittest.main()
