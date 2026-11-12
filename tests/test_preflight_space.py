"""R8 T-186 / WB-9 P1-1·P1-2: disk free-space check before a run (synthetic data only).

The check is advice only (no 507), names its basis and says "추정"; ``block`` is reserved for a reliable
upper bound (a raw image's partition size). Counterexamples of the WB-9 review are pinned here.
"""

from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from rapidtriage.api.app import preflight_space
from rapidtriage.api.app.preflight_space import (
    DISK_SPACE_INSUFFICIENT,
    DISK_SPACE_LOW,
    ESTIMATE_MARGIN,
    EWF_EXPANSION,
    FOLDER_BYTES_PER_ENTRY,
    FOLDER_CONTENT_SHARE,
    check_output_space,
    estimate_from_sizes,
    estimate_output_bytes,
    space_verdict,
)

GB = 1_000_000_000
MB = 1_000_000
TB = 1000 * GB


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


def setUpModule() -> None:
    preflight_space._cache.clear()


class EstimateModelTests(unittest.TestCase):
    def test_img_b_estimate_within_30_percent_of_measured(self) -> None:
        # IMG-B (R8 QA, outside Git): 3 EWF segments 18,533,691,556 bytes, 240 GB media, the processed
        # NTFS partition is nearly the whole disk (approximated here), measured output 71.6 GB.
        # This is the point EWF_EXPANSION was fitted on: it pins the constant, it does not validate it.
        estimated, method = estimate_from_sizes("ewf", evidence_bytes=18_533_691_556, media_bytes=240 * GB, partition_bytes=239 * GB)
        self.assertEqual(method, "ewf-compressed-segments")
        self.assertLessEqual(abs(estimated - 71.6 * GB) / (71.6 * GB), 0.30, estimated)

    def test_ewf_cap_and_missing_partition_are_their_own_methods(self) -> None:
        capped, method = estimate_from_sizes("ewf", evidence_bytes=100 * GB, media_bytes=200 * GB, partition_bytes=50 * GB)
        self.assertEqual((capped, method), (int(50 * GB * 1.12), "ewf-partition-cap"))
        half, _ = estimate_from_sizes("ewf", evidence_bytes=10 * GB, media_bytes=200 * GB, partition_bytes=100 * GB)
        whole, _ = estimate_from_sizes("ewf", evidence_bytes=10 * GB, media_bytes=200 * GB, partition_bytes=200 * GB)
        self.assertAlmostEqual(half / whole, 0.5, places=3)
        # P2-4: no partition -> no ratio, capped at the media size.
        no_part, method = estimate_from_sizes("ewf", evidence_bytes=600 * GB, media_bytes=500 * GB)
        self.assertEqual((no_part, method), (int(500 * GB * 1.12), "ewf-no-partition"))

    def test_raw_file_and_folder_methods(self) -> None:
        raw, method = estimate_from_sizes("raw", evidence_bytes=500 * GB, media_bytes=500 * GB, partition_bytes=100 * GB)
        self.assertEqual((raw, method), (int(100 * GB * 1.12), "raw-partition-upper-bound"))
        file_estimate, method = estimate_from_sizes("file", evidence_bytes=GB)
        self.assertEqual((file_estimate, method), (int(GB * 1.12), "evidence-file-size"))
        folder, method = estimate_from_sizes("folder", evidence_bytes=10 * GB, entry_count=1000)
        self.assertEqual(method, "folder-entries")
        self.assertEqual(folder, int(1000 * FOLDER_BYTES_PER_ENTRY + 10 * GB * FOLDER_CONTENT_SHARE))
        with_extract, _ = estimate_from_sizes("folder", evidence_bytes=10 * GB, entry_count=1000, extract_bytes=GB)
        self.assertEqual(with_extract, folder + int(GB * 1.12))


class VerdictTests(unittest.TestCase):
    def test_levels_say_estimate_and_basis(self) -> None:
        estimated = 100 * GB
        ok = space_verdict(estimated, int(estimated * (1 + ESTIMATE_MARGIN)) + 1, "folder-entries")
        self.assertEqual((ok["ok"], ok["level"], ok["code"]), (True, "ok", None))
        self.assertIn("추정", str(ok["message"]))
        self.assertIn("폴더 항목 수", str(ok["message"]))
        warn = space_verdict(estimated, estimated - 1, "ewf-compressed-segments")
        self.assertEqual((warn["ok"], warn["level"], warn["code"]), (True, "warn", DISK_SPACE_LOW))
        self.assertIn(f"× {EWF_EXPANSION}", str(warn["message"]))
        self.assertIn("런은 시작됩니다", str(warn["message"]))
        block = space_verdict(estimated, estimated - 1, "raw-partition-upper-bound")
        self.assertEqual((block["ok"], block["level"], block["code"]), (False, "block", DISK_SPACE_INSUFFICIENT))
        self.assertIn("최대 출력 크기(100.0 GB", str(block["message"]))
        self.assertIn("더 작을 수 있지만", str(block["message"]))
        unknown = space_verdict(None, 5)
        self.assertEqual((unknown["ok"], unknown["level"]), (True, "unknown"))
        self.assertIn("확인하지 못해", str(unknown["message"]))

    def test_only_a_reliable_upper_bound_blocks(self) -> None:
        for method in ("ewf-compressed-segments", "ewf-partition-cap", "ewf-no-partition", "evidence-file-size", "folder-entries"):
            with self.subTest(method=method):
                self.assertNotEqual(space_verdict(100 * GB, GB, method)["level"], "block")

    def test_uncompressed_e01_1tb_disk_60gb_data_is_not_block(self) -> None:
        # Review counterexample: segments ≈ media size, so × 3.5 hits the partition cap (1.1 TB estimate).
        estimated, method = estimate_from_sizes("ewf", evidence_bytes=TB, media_bytes=TB, partition_bytes=TB - GB)
        self.assertEqual(method, "ewf-partition-cap")
        verdict = space_verdict(estimated, 100 * GB, method)
        self.assertEqual(verdict["level"], "unknown")
        self.assertTrue(verdict["ok"])
        self.assertIn("실제 출력 크기를 알 수 없습니다", str(verdict["message"]))


class CheckOutputSpaceTests(unittest.TestCase):
    def setUp(self) -> None:
        preflight_space._cache.clear()

    def test_response_shape_for_raw_image_and_missing_output_folder(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            image = Path(temp) / "disk.dd"
            _raw_image(image, start=2048, count=4096)
            out = Path(temp) / "not" / "yet" / "made"
            result = check_output_space(image, out, disk_usage=_usage(10 * GB))
            self.assertTrue({"estimated_bytes", "free_bytes", "ok", "message"} <= set(result))
            self.assertEqual(result["estimated_bytes"], int(4096 * 512 * 1.12))
            self.assertEqual((result["free_bytes"], result["level"]), (10 * GB, "ok"))
            basis = result["basis"]
            self.assertEqual((basis["evidence_kind"], basis["partition_bytes"]), ("raw", 4096 * 512))  # type: ignore[index]
            self.assertTrue(basis["estimate_is_upper_bound"])  # type: ignore[index]
            self.assertEqual(Path(str(basis["output_volume_probe"])), Path(temp))  # type: ignore[index]
            self.assertFalse(out.exists())  # nothing is created

    def test_raw_upper_bound_blocks_but_resume_or_overwrite_warns(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            image = Path(temp) / "disk.dd"
            _raw_image(image, start=2048, count=4096)
            result = check_output_space(image, temp, disk_usage=_usage(1000))
            self.assertEqual((result["ok"], result["level"], result["code"]), (False, "block", DISK_SPACE_INSUFFICIENT))
            self.assertIn("엔진은 이미지당 파일", str(result["message"]))  # native file cap disclosed
            resumed = check_output_space(image, temp, disk_usage=_usage(1000), resume=True)
            self.assertEqual((resumed["ok"], resumed["level"]), (True, "warn"))
            self.assertIn("이어서 실행·덮어쓰기", str(resumed["message"]))

    def test_folder_with_one_3gb_file_and_100mb_free_is_not_presented_as_certain(self) -> None:
        # Review counterexample: 12 % of bytes said "block, 360 MB needed". Rows grow with entries, not bytes.
        with tempfile.TemporaryDirectory() as temp:
            evidence = Path(temp) / "evidence"
            evidence.mkdir()
            with (evidence / "big.bin").open("wb") as handle:
                handle.truncate(3 * GB)  # sparse
            result = check_output_space(evidence, Path(temp) / "out", disk_usage=_usage(100 * MB))
            self.assertNotEqual(result["level"], "block")
            self.assertTrue(result["ok"])
            self.assertIn("추정", str(result["message"]))
            self.assertEqual(result["basis"]["entry_count"], 1)  # type: ignore[index]
            self.assertEqual(result["estimated_bytes"], int(FOLDER_BYTES_PER_ENTRY + 3 * GB * FOLDER_CONTENT_SHARE))

    def test_folder_caps_extract_and_walk_limits(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            evidence = Path(temp) / "evidence"
            (evidence / "sub").mkdir(parents=True)
            for index in range(10):
                (evidence / "sub" / f"{index}.bin").write_bytes(b"x" * 1000)
            capped = estimate_output_bytes(evidence, max_file_count=4)
            self.assertEqual(capped["entry_count"], 4)
            self.assertTrue(capped["folder_walk_complete"])
            self.assertIn("파일 수 상한(4개)", " ".join(capped["notes"]))  # type: ignore[arg-type]
            extracted = estimate_output_bytes(evidence, extract=True, max_extract_size_bytes=2000)
            plain = estimate_output_bytes(evidence)
            self.assertEqual(int(extracted["estimated_bytes"]) - int(plain["estimated_bytes"]), int(2000 * 1.12))  # type: ignore[call-overload]
            preflight_space._cache.clear()
            with mock.patch.object(preflight_space, "FOLDER_WALK_SECONDS", -1.0), mock.patch.object(preflight_space, "FOLDER_WALK_LIMIT", 5):
                cut = estimate_output_bytes(evidence)
            self.assertFalse(cut["folder_walk_complete"])
            self.assertIn("하한", " ".join(cut["notes"]))  # type: ignore[arg-type]

    def test_estimate_is_cached_for_the_preview_and_start_pair(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            evidence = Path(temp) / "evidence"
            evidence.mkdir()
            (evidence / "a.txt").write_bytes(b"x")
            with mock.patch.object(preflight_space, "_folder_walk", wraps=preflight_space._folder_walk) as walk:
                first = check_output_space(evidence, temp, disk_usage=_usage(GB))
                second = check_output_space(evidence, temp, disk_usage=_usage(GB))
            self.assertEqual(walk.call_count, 1)
            self.assertTrue(second["basis"]["cached"])  # type: ignore[index]
            self.assertEqual(first["estimated_bytes"], second["estimated_bytes"])

    def test_ewf_path_counts_segments_past_e99_and_ex01(self) -> None:
        # Synthetic EWF1 signatures only: libewf cannot open them, so the partition read fails into a note.
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            names = [f"big.E{n:02d}" for n in range(1, 100)] + ["big.EAA"]
            for name in names:
                (folder / name).write_bytes(b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 92)
            basis = estimate_output_bytes(folder / "big.E01")
            self.assertEqual((basis["evidence_kind"], basis["segment_count"], basis["evidence_bytes"]), ("ewf", 100, 100 * 100))
            self.assertEqual(basis["method"], "ewf-no-partition")
            self.assertTrue(any("파티션" in note for note in basis["notes"]))  # type: ignore[union-attr]
            ex01 = folder / "v2.Ex01"
            ex01.write_bytes(b"EVF2\r\n\x81\x00" + b"\x00" * 64)
            self.assertEqual(estimate_output_bytes(ex01)["evidence_kind"], "ewf")
            verdict = check_output_space(folder / "big.E01", temp, disk_usage=_usage(10))
            self.assertNotEqual(verdict["level"], "block")

    def test_missing_evidence_is_unknown_not_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            result = check_output_space(Path(temp) / "missing.E01", temp, disk_usage=_usage(GB))
            self.assertEqual((result["estimated_bytes"], result["ok"], result["level"]), (None, True, "unknown"))
            unchosen = check_output_space(Path(temp), "", disk_usage=_usage(GB))
            self.assertEqual((unchosen["free_bytes"], unchosen["level"]), (None, "unknown"))


class RunStartWiringTests(unittest.TestCase):
    def setUp(self) -> None:
        try:
            from fastapi.testclient import TestClient

            from rapidtriage.api.app import create_app
        except ImportError:  # pragma: no cover - API extras absent
            self.skipTest("fastapi not installed")
        from rapidtriage.core.jobs import RunJobStore

        preflight_space._cache.clear()
        self.store = RunJobStore()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        app = create_app(self.store, auth_token="space-token", cases_db_path=base / "ws" / "rapidtriage-cases.db")
        self.client = TestClient(app, headers={"X-RapidTriage-Token": "space-token"})
        self.addCleanup(self.client.close)
        self.image = base / "disk.dd"
        _raw_image(self.image, start=2048, count=4096)
        self.body = {"root": str(self.image), "mode": "seizure", "output_dir": str(base / "out")}
        self.submitted: list[object] = []
        # The raw image needs Sleuth Kit to be accepted as a run source; the check under test does not.
        for target in ("rapidtriage.api.app.routes_runs.validate_run_evidence_source",
                       "rapidtriage.api.app.routes_run_plan.validate_run_evidence_source"):
            patcher = mock.patch(target, lambda _root: None)
            patcher.start()
            self.addCleanup(patcher.stop)

    def fake_submit(self, request):
        self.submitted.append(request)
        return SimpleNamespace(run_id="fake", to_dict=lambda include_summary=False: {"run_id": "fake", "status": "queued"})

    def test_preview_endpoint(self) -> None:
        with mock.patch("rapidtriage.api.app.preflight_space.shutil.disk_usage", _usage(10)):
            response = self.client.post("/api/run-plan/space", json=self.body)
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual((body["ok"], body["level"], body["code"], body["free_bytes"]), (False, "block", DISK_SPACE_INSUFFICIENT, 10))

    def test_run_start_never_refuses_and_attaches_the_advice(self) -> None:
        with mock.patch("rapidtriage.api.app.preflight_space.shutil.disk_usage", _usage(10)), mock.patch.object(self.store, "submit", self.fake_submit):
            for extra in ({}, {"allow_low_disk_space": True}):
                response = self.client.post("/api/runs", json={**self.body, **extra})
                self.assertEqual(response.status_code, 202, response.text)
                self.assertEqual(response.json()["preflight_space"]["level"], "block")
        self.assertEqual(len(self.submitted), 2)

    def test_retry_attaches_the_advice(self) -> None:
        from rapidtriage.core.jobs import RunRequest

        previous = SimpleNamespace(
            request=RunRequest(root=str(self.image), mode="seizure", output_dir=self.body["output_dir"]), readonly_reason=None
        )
        retried = SimpleNamespace(to_dict=lambda include_summary=False: {"run_id": "r2", "status": "queued"})
        with mock.patch("rapidtriage.api.app.preflight_space.shutil.disk_usage", _usage(10)), \
                mock.patch.object(self.store, "get", return_value=previous), \
                mock.patch.object(self.store, "retry", return_value=retried):
            fresh = self.client.post("/api/runs/r1/retry", json={})
            resumed = self.client.post("/api/runs/r1/retry", json={"resume": True})
        self.assertEqual(fresh.status_code, 202, fresh.text)
        self.assertEqual(fresh.json()["preflight_space"]["level"], "block")
        self.assertEqual(resumed.json()["preflight_space"]["level"], "warn")  # resume reuses written output

    def test_case_run_route_attaches_the_advice(self) -> None:
        base = Path(self.temp.name)
        created = self.client.post("/api/cases", json={"case_number": "2026-SPACE", "examiner": "검사관", "case_root": str(base / "case")})
        self.assertEqual(created.status_code, 201, created.text)
        case_id = created.json()["case"]["case_id"]
        evidence = base / "evidence"
        evidence.mkdir()
        (evidence / "a.txt").write_bytes(b"x" * 100)
        added = self.client.post(f"/api/cases/{case_id}/evidence", json={"evidence_number": "E-01", "source_type": "folder", "path": str(evidence)})
        self.assertEqual(added.status_code, 201, added.text)
        citation = added.json()["evidence"]["citation_id"]
        from tests.test_rapidtriage_case_intake import fake_execute

        with mock.patch("rapidtriage.api.app.preflight_space.shutil.disk_usage", _usage(10)), \
                mock.patch("rapidtriage.core.jobs.execute_run_request", side_effect=fake_execute):
            response = self.client.post(f"/api/cases/{case_id}/runs", json={"evidence_citation_id": citation, "mode": "seizure", "wait": True})
        self.assertEqual(response.status_code, 202, response.text)
        space = response.json()["preflight_space"]
        self.assertEqual((space["level"], space["basis"]["method"]), ("warn", "folder-entries"))


if __name__ == "__main__":
    unittest.main()
