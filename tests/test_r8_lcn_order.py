from __future__ import annotations

import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.core import e01_native
from rapidtriage.core.e01_native import _ExtractJob


class _Rec:
    def __init__(self, runs=None, error: Exception | None = None) -> None:
        self._runs = runs
        self._error = error

    def dataruns(self):
        if self._error is not None:
            raise self._error
        return self._runs


class FirstLcnTests(unittest.TestCase):
    def test_first_non_sparse_run_wins(self) -> None:
        self.assertEqual(e01_native._first_lcn(_Rec([(None, 8), (900, 4), (10, 2)])), 900)

    def test_resident_empty_or_missing_stream_is_zero(self) -> None:
        self.assertEqual(e01_native._first_lcn(_Rec([])), 0)
        self.assertEqual(e01_native._first_lcn(_Rec([(None, 8)])), 0)
        self.assertEqual(e01_native._first_lcn(_Rec(error=FileNotFoundError())), 0)


class OrderTests(unittest.TestCase):
    def test_sort_is_ascending_and_stable(self) -> None:
        jobs = [_ExtractJob(i, Path(f"o{i}"), lcn=lcn) for i, lcn in enumerate([50, 0, 7, 50, 0, 3])]
        ordered = e01_native._order_jobs_by_lcn(jobs)
        self.assertEqual([job.lcn for job in ordered], [0, 0, 3, 7, 50, 50])
        self.assertEqual([job.segment for job in ordered], [1, 4, 5, 2, 0, 3])  # ties keep planning order
        self.assertEqual(ordered, e01_native._order_jobs_by_lcn(jobs))  # deterministic


class DispatchTests(unittest.TestCase):
    def _run(self, workers: int):
        jobs = [_ExtractJob(i, Path(f"o{i}"), lcn=lcn) for i, lcn in enumerate([90, 10, 0, 70, 30, 50])]
        seen: list[int] = []
        lock = threading.Lock()

        def fake_extract(_contexts, job):
            with lock:
                seen.append(job.lcn)
            return job, (job.segment + 1, {"md5": f"m{job.segment}", "sha1": "s", "sha256": "h"})

        stats = e01_native._new_stats()
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(e01_native, "_extract_job", fake_extract):
            root = Path(tmp)
            real = [_ExtractJob(j.segment, root / j.out_path, lcn=j.lcn) for j in jobs]
            digests = e01_native._run_extract_jobs(mock.Mock(), real, root, stats, workers)
        return seen, digests, stats

    def test_single_worker_consumes_ascending_offsets(self) -> None:
        seen, digests, _ = self._run(1)
        self.assertEqual(seen, [0, 10, 30, 50, 70, 90])
        self.assertEqual(list(digests), ["o2", "o1", "o4", "o5", "o3", "o0"])

    def test_digest_order_and_totals_do_not_depend_on_worker_count(self) -> None:
        _, one, one_stats = self._run(1)
        _, many, many_stats = self._run(4)
        self.assertEqual(list(one), list(many))
        self.assertEqual(one, many)
        self.assertEqual((one_stats["files"], one_stats["bytes"]), (many_stats["files"], many_stats["bytes"]))


class WorkerDefaultTests(unittest.TestCase):
    def test_default_is_two_and_env_overrides(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(e01_native.NATIVE_E01_WORKERS_ENV, None)
            self.assertEqual(e01_native.native_extract_worker_count(), 2)
            os.environ[e01_native.NATIVE_E01_WORKERS_ENV] = "5"
            self.assertEqual(e01_native.native_extract_worker_count(), 5)


if __name__ == "__main__":
    unittest.main()
