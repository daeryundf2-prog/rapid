"""R8 review fixes for unallocated carving: per-run cap, cancel, worker errors, coverage wording."""

from __future__ import annotations

import tempfile
import unittest
from concurrent import futures
from concurrent.futures.process import BrokenProcessPool
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar
from unittest import mock

from rapidtriage.core import carving
from rapidtriage.core.coverage import coverage_entries, reset_coverage
from rapidtriage.core.run import (
    run_unallocated_carving_stage,
    unallocated_carve_targets,
)
from tests.test_r6_s2_unalloc_carve import build_ntfs_image

PART = 64 * 512
CLUSTER = 1024


def jpeg(tag: int) -> bytes:
    return b"\xff\xd8\xff\xe0" + b"JFIF\x00" + bytes([tag]) * 40 + b"\xff\xd9"


def at(cluster: int, within: int = 0) -> int:
    return PART + cluster * CLUSTER + within


class FakeProcessPool(futures.ThreadPoolExecutor):
    """Thread pool standing in for the spawn process pool (accepts ``mp_context``)."""

    def __init__(self, max_workers: int | None = None, **_spawn_options: object) -> None:
        super().__init__(max_workers=max_workers)


class RecordingPool(FakeProcessPool):
    """Records ``shutdown`` calls."""

    shutdowns: ClassVar[list[dict[str, object]]] = []

    def shutdown(self, wait: bool = True, *, cancel_futures: bool = False) -> None:
        type(self).shutdowns.append({"wait": wait, "cancel_futures": cancel_futures})
        super().shutdown(wait=wait, cancel_futures=cancel_futures)


class BrokenSubmitPool(FakeProcessPool):
    def submit(self, *_args, **_kwargs):  # type: ignore[no-untyped-def]
        raise BrokenProcessPool("pool died")


class PerRunCapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        reset_coverage()

    def tearDown(self) -> None:
        self.temp.cleanup()
        reset_coverage()

    def test_batch_cap_spans_chunks(self) -> None:
        image = build_ntfs_image(self.base / "d.raw", payloads={at(150 + n * 8): jpeg(n) for n in range(10)})
        common = (str(image.path), None, str(self.base / "carved"), False, 1 << 20, 3, PART, CLUSTER)
        run_tasks = [(at(150), at(600), at(150) + index * 4096, at(150) + (index + 1) * 4096) for index in range(100)]
        entries, error = carving._scan_unallocated_batch(common[0], common[1], run_tasks, *common[2:])
        self.assertIsNone(error)
        self.assertEqual(len(entries), 3)  # per-chunk counting would return all 10

    def test_merge_stops_submitting_batches_at_cap(self) -> None:
        batches = [[(0, 1, 0, 1)], [(0, 1, 1, 2)], [(0, 1, 2, 3)]]
        with mock.patch.object(carving, "_scan_unallocated_batch", return_value=([], None)) as scan:
            carving._run_batches(batches, 1, ("img", None), None, lambda _result: True)
        self.assertEqual(scan.call_count, 1)

    def test_run_records_cap_and_prunes_claims(self) -> None:
        image = build_ntfs_image(self.base / "d.raw", payloads={at(20 + n * 2): jpeg(n) for n in range(6)})
        with mock.patch.object(carving._Claims, "prune", autospec=True, side_effect=carving._Claims.prune) as prune:
            payload = carving.run_unallocated_carving(
                image.path, self.base / "out", workers=1, max_candidates=4, extract=True
            )
        self.assertEqual(len(payload["entries"]), 4)
        self.assertTrue(payload["summary"]["candidate_cap_reached"])
        self.assertEqual(len(list((self.base / "out" / "carved").iterdir())), 4)
        self.assertGreaterEqual(prune.call_count, 4)
        self.assertTrue(any(entry["reason_code"] == "candidate_cap" for entry in coverage_entries()))


class CancelAndFailureTests(unittest.TestCase):
    def setUp(self) -> None:
        RecordingPool.shutdowns = []
        reset_coverage()

    def tearDown(self) -> None:
        reset_coverage()

    def test_cancel_shuts_pool_down_with_cancel_futures(self) -> None:
        batches = [[(0, 1, index, index + 1)] for index in range(4)]

        def cancel() -> None:
            raise carving.CarvingCancelled("stop")

        with (
            mock.patch.object(futures, "ProcessPoolExecutor", RecordingPool),
            mock.patch.object(carving, "_scan_unallocated_batch", return_value=([], None)),
            self.assertRaises(carving.CarvingCancelled),
        ):
            carving._run_batches(batches, 2, ("img", None), cancel, lambda _result: False)
        self.assertEqual(RecordingPool.shutdowns, [{"wait": False, "cancel_futures": True}])

    def test_worker_exception_propagates_without_rerun(self) -> None:
        batches = [[(0, 1, index, index + 1)] for index in range(2)]
        with (
            mock.patch.object(futures, "ProcessPoolExecutor", RecordingPool),
            mock.patch.object(carving, "_scan_unallocated_batch", side_effect=RuntimeError("worker bug")),
            self.assertRaisesRegex(RuntimeError, "worker bug"),
        ):
            carving._run_batches(batches, 2, ("img", None), None, lambda _result: False)

    def test_broken_pool_falls_back_to_threads(self) -> None:
        batches = [[(0, 1, index, index + 1)] for index in range(3)]
        seen: list[object] = []
        with (
            mock.patch.object(futures, "ProcessPoolExecutor", BrokenSubmitPool),
            mock.patch.object(carving, "_scan_unallocated_batch", return_value=([], None)),
        ):
            carving._run_batches(batches, 2, ("img", None), None, lambda result: seen.append(result) or False)
        self.assertEqual(len(seen), 3)

    @staticmethod
    def image_result() -> SimpleNamespace:
        return SimpleNamespace(
            raw_image_path="missing.raw",
            source_path="missing.E01",
            partition_start_sector=63,
            recovered_root_manifest={
                "native_extracted_partitions": [
                    {"start_sector": 63, "partition_number": 1, "filesystem": "ntfs"},
                    {"start_sector": 9999, "partition_number": 2, "filesystem": "ntfs"},
                ]
            },
        )

    def test_stage_cancel_fails_remaining_partitions(self) -> None:
        def fake_carving(*_args, check_cancel=None, **_kwargs):
            check_cancel()
            raise AssertionError("cancel was not raised")

        with tempfile.TemporaryDirectory() as tmp, mock.patch(
            "rapidtriage.core.run.run_unallocated_carving", side_effect=fake_carving
        ) as carve:
            step = run_unallocated_carving_stage(
                self.image_result(), Path(tmp) / "carve", recovery=True, extract=False, check_cancel=lambda: True
            )
        self.assertEqual(carve.call_count, 1)
        self.assertEqual([row["error"] for row in step["partitions"]], ["cancelled", "cancelled"])
        self.assertEqual(step["status"], "failed")

    def test_stage_turns_unexpected_error_into_failed_partition(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch(
            "rapidtriage.core.run.run_unallocated_carving", side_effect=ValueError("walker bug")
        ):
            step = run_unallocated_carving_stage(self.image_result(), Path(tmp) / "carve", recovery=False, extract=False)
        self.assertEqual([row["status"] for row in step["partitions"]], ["failed", "failed"])
        self.assertIn("walker bug", step["partitions"][0]["error"])

    def test_unsupported_filesystem_coverage_does_not_claim_observed_sectors(self) -> None:
        result = SimpleNamespace(
            partition_start_sector=0,
            recovered_root_manifest={
                "native_extracted_partitions": [{"start_sector": 567296, "partition_number": 1, "filesystem": "ext4"}]
            },
        )
        self.assertEqual(unallocated_carve_targets(result), [])  # type: ignore[arg-type]
        entry = next(item for item in coverage_entries() if item["reason_code"] == "unsupported_filesystem")
        self.assertIsNone(entry["observed"])
        self.assertEqual(entry["detail"], {"start_sector": 567296})


if __name__ == "__main__":
    unittest.main()
