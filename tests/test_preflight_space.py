"""R8 T-186: disk free-space check before a run (synthetic data only)."""

from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from rapidtriage.api.app.preflight_space import (
    DISK_SPACE_INSUFFICIENT,
    DISK_SPACE_LOW,
    ESTIMATE_MARGIN,
    check_output_space,
    estimate_from_sizes,
    space_verdict,
)

GB = 1_000_000_000


def _usage(free: int):
    return lambda _path: SimpleNamespace(total=free * 2, used=free, free=free)


def _raw_image(path: Path, *, start: int, count: int, size: int = 1024 * 1024) -> None:
    """A sparse raw disk with one MBR NTFS partition (type 0x07)."""
    sector0 = bytearray(512)
    entry = bytes([0x80, 0, 0, 0, 0x07, 0, 0, 0]) + struct.pack("<II", start, count)
    sector0[0x1BE : 0x1BE + 16] = entry
    sector0[510:512] = b"\x55\xaa"
    with path.open("wb") as handle:
        handle.write(sector0)
        handle.truncate(size)


class EstimateModelTests(unittest.TestCase):
    def test_img_b_estimate_within_30_percent_of_measured(self) -> None:
        # IMG-B (R8 QA, outside Git): 3 EWF segments 18,533,691,556 bytes, 240 GB media, the processed
        # NTFS partition is nearly the whole disk (approximated here), measured output 71.6 GB.
        estimated, method = estimate_from_sizes("ewf", evidence_bytes=18_533_691_556, media_bytes=240 * GB, partition_bytes=239 * GB)
        self.assertEqual(method, "ewf-compressed-segments")
        self.assertLessEqual(abs(estimated - 71.6 * GB) / (71.6 * GB), 0.30, estimated)

    def test_ewf_estimate_is_capped_by_partition_and_scaled_by_share(self) -> None:
        capped, _ = estimate_from_sizes("ewf", evidence_bytes=100 * GB, media_bytes=200 * GB, partition_bytes=50 * GB)
        self.assertEqual(capped, int(50 * GB * 1.12))
        half, _ = estimate_from_sizes("ewf", evidence_bytes=10 * GB, media_bytes=200 * GB, partition_bytes=100 * GB)
        whole, _ = estimate_from_sizes("ewf", evidence_bytes=10 * GB, media_bytes=200 * GB, partition_bytes=200 * GB)
        self.assertAlmostEqual(half / whole, 0.5, places=3)
        _, method = estimate_from_sizes("ewf", evidence_bytes=10 * GB)
        self.assertEqual(method, "ewf-compressed-segments-no-partition")

    def test_raw_folder_and_file_methods(self) -> None:
        raw, method = estimate_from_sizes("raw", evidence_bytes=500 * GB, media_bytes=500 * GB, partition_bytes=100 * GB)
        self.assertEqual((raw, method), (int(100 * GB * 1.12), "raw-partition-upper-bound"))
        folder, method = estimate_from_sizes("folder", evidence_bytes=10 * GB)
        self.assertEqual((folder, method), (int(10 * GB * 0.12), "folder-derived-rows"))
        file_estimate, method = estimate_from_sizes("file", evidence_bytes=GB)
        self.assertEqual((file_estimate, method), (int(GB * 1.12), "evidence-file-size"))


class VerdictTests(unittest.TestCase):
    def test_levels_and_korean_messages(self) -> None:
        estimated = 100 * GB
        ok = space_verdict(estimated, int(estimated * (1 + ESTIMATE_MARGIN)) + 1)
        self.assertEqual((ok["ok"], ok["level"], ok["code"]), (True, "ok", None))
        warn = space_verdict(estimated, estimated + 1)
        self.assertEqual((warn["ok"], warn["level"], warn["code"]), (True, "warn", DISK_SPACE_LOW))
        self.assertIn("빠듯합니다", str(warn["message"]))
        block = space_verdict(estimated, estimated - 1)
        self.assertEqual((block["ok"], block["level"], block["code"]), (False, "block", DISK_SPACE_INSUFFICIENT))
        self.assertIn("여유 공간", str(block["message"]))
        self.assertIn("100.0 GB", str(block["message"]))
        unknown = space_verdict(None, 5)
        self.assertEqual((unknown["ok"], unknown["level"]), (True, "unknown"))
        self.assertIn("확인하지 못해", str(unknown["message"]))


class CheckOutputSpaceTests(unittest.TestCase):
    def test_response_shape_for_raw_image_and_missing_output_folder(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            image = Path(temp) / "disk.dd"
            _raw_image(image, start=2048, count=4096)
            out = Path(temp) / "not" / "yet" / "made"
            result = check_output_space(image, out, disk_usage=_usage(10 * GB))
            self.assertTrue({"estimated_bytes", "free_bytes", "ok", "message"} <= set(result))
            self.assertEqual(result["estimated_bytes"], int(4096 * 512 * 1.12))
            self.assertEqual(result["free_bytes"], 10 * GB)
            self.assertEqual(result["level"], "ok")
            basis = result["basis"]
            self.assertEqual((basis["evidence_kind"], basis["partition_bytes"]), ("raw", 4096 * 512))  # type: ignore[index]
            self.assertEqual(Path(str(basis["output_volume_probe"])), Path(temp))  # type: ignore[index]
            self.assertFalse(out.exists())  # nothing is created

    def test_low_space_blocks_with_korean_warning(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            image = Path(temp) / "disk.dd"
            _raw_image(image, start=2048, count=4096)
            result = check_output_space(image, temp, disk_usage=_usage(1000))
            self.assertFalse(result["ok"])
            self.assertEqual(result["code"], DISK_SPACE_INSUFFICIENT)
            self.assertIn("예상 출력 크기", str(result["message"]))

    def test_folder_evidence_and_unchosen_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            evidence = Path(temp) / "evidence"
            (evidence / "sub").mkdir(parents=True)
            (evidence / "sub" / "a.bin").write_bytes(b"x" * 10_000)
            result = check_output_space(evidence, Path(temp) / "out", disk_usage=_usage(GB))
            self.assertEqual(result["estimated_bytes"], int(10_000 * 0.12))
            self.assertTrue(result["basis"]["folder_walk_complete"])  # type: ignore[index]
            unchosen = check_output_space(evidence, "", disk_usage=_usage(GB))
            self.assertEqual((unchosen["free_bytes"], unchosen["level"]), (None, "unknown"))

    def test_missing_evidence_is_unknown_not_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            result = check_output_space(Path(temp) / "missing.E01", temp, disk_usage=_usage(GB))
            self.assertEqual((result["estimated_bytes"], result["ok"], result["level"]), (None, True, "unknown"))


class RunStartWiringTests(unittest.TestCase):
    def setUp(self) -> None:
        try:
            from fastapi.testclient import TestClient

            from rapidtriage.api.app import create_app
        except ImportError:  # pragma: no cover - API extras absent
            self.skipTest("fastapi not installed")
        from rapidtriage.core.jobs import RunJobStore

        self.store = RunJobStore()
        self.client = TestClient(create_app(self.store, auth_token="space-token"), headers={"X-RapidTriage-Token": "space-token"})
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.evidence = Path(self.temp.name) / "evidence"
        self.evidence.mkdir()
        (self.evidence / "a.txt").write_bytes(b"x" * 50_000)
        self.body = {"root": str(self.evidence), "mode": "seizure", "output_dir": str(Path(self.temp.name) / "out")}

    def test_preview_endpoint(self) -> None:
        with mock.patch("rapidtriage.api.app.preflight_space.shutil.disk_usage", _usage(10)):
            response = self.client.post("/api/run-plan/space", json=self.body)
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual((body["ok"], body["level"], body["code"], body["free_bytes"]), (False, "block", DISK_SPACE_INSUFFICIENT, 10))
        self.assertGreater(body["estimated_bytes"], 0)

    def test_run_start_refuses_then_allows_override(self) -> None:
        submitted: list[object] = []

        def fake_submit(request):
            submitted.append(request)
            return SimpleNamespace(to_dict=lambda include_summary=False: {"run_id": "fake", "status": "queued"})

        with mock.patch("rapidtriage.api.app.preflight_space.shutil.disk_usage", _usage(10)), mock.patch.object(self.store, "submit", fake_submit):
            refused = self.client.post("/api/runs", json=self.body)
            self.assertEqual(refused.status_code, 507, refused.text)
            self.assertEqual(refused.json()["code"], DISK_SPACE_INSUFFICIENT)
            self.assertIn("여유 공간", refused.json()["message"])
            self.assertEqual(submitted, [])
            allowed = self.client.post("/api/runs", json={**self.body, "allow_low_disk_space": True})
            self.assertEqual(allowed.status_code, 202, allowed.text)
            self.assertEqual(allowed.json()["preflight_space"]["level"], "block")
            self.assertEqual(len(submitted), 1)
        with mock.patch("rapidtriage.api.app.preflight_space.shutil.disk_usage", _usage(100 * GB)), mock.patch.object(self.store, "submit", fake_submit):
            fine = self.client.post("/api/runs", json=self.body)
            self.assertEqual(fine.status_code, 202, fine.text)
            self.assertEqual(fine.json()["preflight_space"]["level"], "ok")


if __name__ == "__main__":
    unittest.main()
