from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import ClassVar
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from rapidtriage.api.app import create_app
from rapidtriage.core import coverage, e01_native
from rapidtriage.core.jobs import RunJobStore

TEST_API_TOKEN = "rapidtriage-test-token"


class _FakeSectorReader:
    """Stands in for EwfSectorReader: the boot sector carries no filesystem signature at all.

    exFAT/FAT/ext/NTFS are all extractable now, so the fixture is a genuinely unknown volume
    (no OEM id, no 0x55AA boot signature, no ext superblock magic)."""

    def __init__(self, handle, base=0, size=None):
        pass

    def seek(self, offset, whence=0):
        return 0

    def read(self, size=-1):
        return b"\x00" * 3 + b"UNKNOWN!" + b"\x00" * (size - 11)


class CoverageCollectorTests(unittest.TestCase):
    def setUp(self):
        coverage.reset_coverage()

    def test_no_caps_hit_yields_empty_list(self):
        self.assertEqual(coverage.coverage_entries(), [])

    def test_record_appends_entry_with_fixed_shape(self):
        coverage.record_coverage("demo.area", "demo_cap", 10, 12, "records")
        self.assertEqual(
            coverage.coverage_entries(),
            [
                {
                    "area": "demo.area",
                    "reason_code": "demo_cap",
                    "limit": 10,
                    "observed": 12,
                    "unit": "records",
                }
            ],
        )

    def test_returned_entries_are_copies(self):
        coverage.record_coverage("demo.area", "demo_cap", None, None, "bytes")
        coverage.coverage_entries()[0]["reason_code"] = "mutated"
        self.assertEqual(coverage.coverage_entries()[0]["reason_code"], "demo_cap")

    def test_reset_clears_entries(self):
        coverage.record_coverage("demo.area", "demo_cap", 1, 2, "bytes")
        coverage.reset_coverage()
        self.assertEqual(coverage.coverage_entries(), [])


class NativeE01CoverageTests(unittest.TestCase):
    def setUp(self):
        coverage.reset_coverage()

    def test_requested_unsupported_partition_records_entry(self):
        partitions = [
            {
                "start_sector": 2048,
                "sector_count": 1000,
                "description": "Microsoft reserved partition",
            }
        ]
        with self.assertRaises(ValueError):
            e01_native.select_native_partition(partitions, preferred_start_sector=2048)
        self.assertEqual(
            coverage.coverage_entries(),
            [
                {
                    "area": "e01_native.partition",
                    "reason_code": "partition_not_supported",
                    "limit": None,
                    "observed": None,
                    "unit": "partition",
                }
            ],
        )

    def test_unsupported_filesystem_records_entry(self):
        row = {
            "start_sector": 2048,
            "sector_count": 1000,
            "byte_offset": 2048 * 512,
            "size_bytes": 512000,
            "description": "Unknown partition type 0x7f",
            "partition_number": 1,
        }
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            e01_native, "open_ewf_segments", MagicMock()
        ), patch.object(
            e01_native, "native_partition_table", return_value=([row], 512)
        ), patch.object(
            e01_native, "EwfSectorReader", _FakeSectorReader
        ):
            with self.assertRaisesRegex(ValueError, "filesystem signature 'unknown'"):
                e01_native.extract_e01_native(
                    Path(tmp) / "image.E01",
                    [Path(tmp) / "image.E01"],
                    Path(tmp) / "extract",
                    partition_start_sector=None,
                    system_dir=Path(tmp) / "system",
                )
        self.assertEqual(
            coverage.coverage_entries(),
            [
                {
                    "area": "e01_native.filesystem",
                    "reason_code": "unsupported_filesystem",
                    "limit": None,
                    "observed": None,
                    "unit": "filesystem",
                }
            ],
        )


class CoverageApiTests(unittest.TestCase):
    ENTRY: ClassVar[dict[str, object]] = {
        "area": "e01_native.partition",
        "reason_code": "partition_not_supported",
        "limit": None,
        "observed": None,
        "unit": "partition",
    }

    def _client_for_summary(self, tmp: Path, summary: dict) -> TestClient:
        root = tmp / "run"
        root.mkdir()
        summary = {"root": str(root), "mode": "fraud", "output_dir": str(root), "outputs": {}, **summary}
        path = root / "rapidtriage-run-summary.json"
        path.write_text(json.dumps(summary), encoding="utf-8")
        store = RunJobStore()
        self.run_id = store.import_completed_run(path).run_id
        return TestClient(
            create_app(store, auth_token=TEST_API_TOKEN),
            headers={"X-RapidTriage-Token": TEST_API_TOKEN},
        )

    def test_summary_route_returns_recorded_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = self._client_for_summary(Path(tmp), {"coverage": [self.ENTRY]})
            response = client.get(f"/api/runs/{self.run_id}/summary")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["coverage"], [self.ENTRY])

    def test_summary_without_coverage_key_returns_empty_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = self._client_for_summary(Path(tmp), {})
            response = client.get(f"/api/runs/{self.run_id}/summary")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["coverage"], [])


if __name__ == "__main__":
    unittest.main()
