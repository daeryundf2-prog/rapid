"""Tests for the CPU-bound artifact process pool (rapidtriage/core/run/procpool.py)."""

from __future__ import annotations

import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.core.artifacts import run_artifact_collection
from rapidtriage.core.input_root import InputRoot
from rapidtriage.core.run.procpool import (
    PARSE_PROCS_ENV,
    PROCESS_KINDS,
    ProcessParsePool,
    parse_process_count,
    pooled_artifact_collection,
)

PROCPOOL = "rapidtriage.core.run.procpool"


def _thread_collection(progress, input_root, *, kind, rule_set, records_path, collector_options):
    """Thread-path stand-in: runs the real collector on the calling thread."""
    payload = run_artifact_collection(
        input_root,
        kind=kind,
        rule_set=rule_set,
        records_path=records_path,
        collector_options=dict(collector_options) if collector_options else None,
        use_cache=False,
    )
    return payload, "started", "completed", 0


def _sentinel_fallback(progress, input_root, *, kind, rule_set, records_path, collector_options):
    return ({"sentinel": kind}, "started", "completed", 0)


class ProcessPoolParityTests(unittest.TestCase):
    def test_process_kind_payload_matches_thread_fallback(self) -> None:
        kind = "eventlog"
        self.assertIn(kind, PROCESS_KINDS)
        with tempfile.TemporaryDirectory() as tmp:
            root = InputRoot(source_path=tmp, root_path=Path(tmp), kind="directory")
            pool = ProcessParsePool(workers=1)
            self.addCleanup(pool.shutdown)

            pooled = pooled_artifact_collection(
                pool,
                None,
                root,
                kind=kind,
                rule_set=None,
                records_path=None,
                collector_options=None,
                fallback=_thread_collection,
            )
            threaded = _thread_collection(
                None,
                root,
                kind=kind,
                rule_set=None,
                records_path=None,
                collector_options=None,
            )

        self.assertFalse(pool.disabled, pool.fallback_reason)
        self.assertIsNotNone(pooled)
        # ``generated_at`` is a per-run wall-clock stamp; everything else must match exactly.
        pooled_payload = {k: v for k, v in pooled[0].items() if k != "generated_at"}
        threaded_payload = {k: v for k, v in threaded[0].items() if k != "generated_at"}
        self.assertEqual(pooled_payload, threaded_payload)


class ProcessPoolFailureTests(unittest.TestCase):
    def test_executor_construction_failure_falls_back_and_disables_pool(self) -> None:
        root = InputRoot(source_path="x", root_path=Path("x"), kind="directory")
        pool = ProcessParsePool(workers=2)
        with mock.patch(f"{PROCPOOL}.ProcessPoolExecutor", side_effect=OSError("no spawn")):
            result = pooled_artifact_collection(
                pool,
                None,
                root,
                kind="eventlog",
                rule_set=None,
                records_path=None,
                collector_options=None,
                fallback=_sentinel_fallback,
            )

        self.assertEqual(result, ({"sentinel": "eventlog"}, "started", "completed", 0))
        self.assertTrue(pool.disabled)
        self.assertIn("OSError", pool.fallback_reason or "")

    def test_unpicklable_input_falls_back_without_starting_pool(self) -> None:
        root = InputRoot(source_path="x", root_path=Path("x"), kind="directory")
        pool = ProcessParsePool(workers=2)
        options = {"guard": threading.Lock()}
        with mock.patch(f"{PROCPOOL}.ProcessPoolExecutor") as executor_cls:
            result = pooled_artifact_collection(
                pool,
                None,
                root,
                kind="eventlog",
                rule_set=None,
                records_path=None,
                collector_options=options,
                fallback=_sentinel_fallback,
            )

        executor_cls.assert_not_called()
        self.assertEqual(result, ({"sentinel": "eventlog"}, "started", "completed", 0))
        self.assertFalse(pool.disabled)
        self.assertTrue((pool.fallback_reason or "").startswith("unpicklable input"))

    def test_zero_workers_disables_pool_and_uses_fallback(self) -> None:
        root = InputRoot(source_path="x", root_path=Path("x"), kind="directory")
        pool = ProcessParsePool(workers=0)
        self.assertTrue(pool.disabled)
        result = pool.run(root, "eventlog", None, None, None)
        self.assertIsNone(result)
        self.assertEqual(pool.fallback_reason, "disabled by configuration")


class ParseProcessCountTests(unittest.TestCase):
    def test_env_overrides_default(self) -> None:
        with mock.patch.dict(os.environ, {PARSE_PROCS_ENV: " 3 "}):
            self.assertEqual(parse_process_count(), 3)
        with mock.patch.dict(os.environ, {PARSE_PROCS_ENV: "0"}):
            self.assertEqual(parse_process_count(), 0)

    def test_invalid_env_falls_back_to_default(self) -> None:
        with mock.patch.dict(os.environ, {PARSE_PROCS_ENV: "many"}), mock.patch(f"{PROCPOOL}.os.cpu_count", return_value=16):
            self.assertEqual(parse_process_count(), 8)

    def test_default_is_half_cpus_with_floor_of_two(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != PARSE_PROCS_ENV}
        with mock.patch.dict(os.environ, env, clear=True):
            with mock.patch(f"{PROCPOOL}.os.cpu_count", return_value=16):
                self.assertEqual(parse_process_count(), 8)
            with mock.patch(f"{PROCPOOL}.os.cpu_count", return_value=2):
                self.assertEqual(parse_process_count(), 2)
            with mock.patch(f"{PROCPOOL}.os.cpu_count", return_value=None):
                self.assertEqual(parse_process_count(), 2)


if __name__ == "__main__":
    unittest.main()
