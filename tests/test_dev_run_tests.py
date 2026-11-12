"""Tests for scripts/dev/run-tests.py (T-006 parallel test runner)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "dev" / "run-tests.py"
TIERS = ROOT / "scripts" / "dev" / "test-tiers.json"


def _load():
    spec = importlib.util.spec_from_file_location("dev_run_tests", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


rt = _load()

PASS = """
import unittest
class T(unittest.TestCase):
    def test_a(self): pass
    def test_b(self): pass
    @unittest.skip("x")
    def test_c(self): pass
"""
FAIL = """
import unittest
class T(unittest.TestCase):
    def test_ok(self): pass
    def test_bad(self): self.assertEqual(1, 2)
"""
HANG = """
import time, unittest
class T(unittest.TestCase):
    def test_hang(self): time.sleep(120)
"""
CRASH = """
import os, unittest
class T(unittest.TestCase):
    def test_exit(self): os._exit(3)
"""


class SelectionTests(unittest.TestCase):
    def test_tiers_file_lists_the_four_slow_modules(self):
        tiers = json.loads(TIERS.read_text(encoding="utf-8"))
        self.assertEqual(
            sorted(tiers["slow"]),
            [
                "test_rapidtriage_api",
                "test_rapidtriage_core_forensics_accuracy",
                "test_rapidtriage_ops",
                "test_rapidtriage_run",
            ],
        )
        modules = rt.discover_modules()
        self.assertTrue(set(tiers["slow"]) <= set(modules))
        self.assertGreater(len(tiers["durations_s"]), 200)

    def test_tiers_partition_full_suite(self):
        modules = rt.discover_modules()
        tiers = rt.load_tiers()
        fast = rt.select_tier(modules, tiers, "fast")
        slow = rt.select_tier(modules, tiers, "slow")
        real = rt.select_tier(modules, tiers, "real-data")
        self.assertEqual(
            sorted(fast + slow + real), rt.select_tier(modules, tiers, "full")
        )
        self.assertIn("test_dev_run_tests", fast)
        self.assertNotIn("test_rapidtriage_ops", fast)

    def test_only_accepts_names_paths_and_globs(self):
        modules = ["test_a", "test_b1", "test_b2", "test_c"]
        picked, missing = rt.select_only(
            modules, ["tests/test_a.py,tests.test_c", "test_b*", "test_zz"]
        )
        self.assertEqual(picked, ["test_a", "test_b1", "test_b2", "test_c"])
        self.assertEqual(missing, ["test_zz"])

    def test_changed_picks_touched_tests_and_importers(self):
        with tempfile.TemporaryDirectory() as tmp:
            tdir = Path(tmp)
            (tdir / "test_x.py").write_text(
                "import rapidtriage.web.api\n", encoding="utf-8"
            )
            (tdir / "test_y.py").write_text(
                "import rapidtriage.cli\n", encoding="utf-8"
            )
            (tdir / "test_z.py").write_text("pass\n", encoding="utf-8")
            files = ["rapidtriage/web/api.py", "tests/test_z.py", "docs/a.md"]
            self.assertEqual(
                rt.select_changed(["test_x", "test_y", "test_z"], files, tdir),
                ["test_x", "test_z"],
            )

    def test_balance_spreads_by_duration_and_puts_failed_first(self):
        durations = {"big": 100, "m1": 50, "m2": 50, "s1": 1, "s2": 1}
        batches = rt.balance(list(durations), durations, 2, first={"s2"})
        loads = sorted(sum(durations[m] for m in b) for b in batches)
        self.assertEqual(loads, [101, 101])
        self.assertEqual(sorted(m for b in batches for m in b), sorted(durations))
        holder = next(b for b in batches if "s2" in b)
        self.assertEqual(holder[0], "s2")
        self.assertEqual(len(rt.balance(["a"], {}, 8)), 1)
        self.assertEqual(rt.balance([], {}, 8), [])

    def test_module_timeout(self):
        self.assertEqual(rt.module_timeout("m", {"m": 200}, None, 300, 3), 600)
        self.assertEqual(rt.module_timeout("m", {}, None, 300, 3), 300)
        self.assertEqual(rt.module_timeout("m", {"m": 200}, 7, 300, 3), 7)

    def test_module_timeout_scales_with_load_but_not_a_fixed_limit(self):
        # T-148: under load modules ran 3-5x their recorded time; the limit stretches with it.
        self.assertEqual(rt.module_timeout("m", {"m": 200}, None, 300, 3, 2.5), 1500)
        self.assertEqual(rt.module_timeout("m", {}, None, 300, 3, 2.0), 600)
        self.assertEqual(rt.module_timeout("m", {"m": 200}, None, 300, 3, 0.5), 600)
        self.assertEqual(rt.module_timeout("m", {"m": 200}, 7, 300, 3, 4.0), 7)

    def test_load_multiplier_mapping(self):
        self.assertEqual(rt.load_multiplier(None), 1.0)
        self.assertEqual(rt.load_multiplier(float("nan")), 1.0)
        self.assertEqual(rt.load_multiplier(0.0), 1.0)
        self.assertEqual(rt.load_multiplier(rt.LOAD_IDLE_RATIO), 1.0)
        self.assertEqual(rt.load_multiplier(1.0), rt.LOAD_FULL_MULTIPLIER)
        self.assertEqual(rt.load_multiplier(50.0), rt.LOAD_MAX_MULTIPLIER)
        mid = rt.load_multiplier(0.6)
        self.assertTrue(1.0 < mid < rt.LOAD_FULL_MULTIPLIER, mid)
        self.assertLess(rt.load_multiplier(0.5), rt.load_multiplier(0.9))

    def test_measure_load_reports_a_source_and_a_sane_multiplier(self):
        info = rt.measure_load(sample_s=0.1, workers=4)
        self.assertIn(info["source"], {"loadavg", "cpu-sample", "unavailable"})
        if sys.platform == "win32":
            self.assertEqual(info["source"], "cpu-sample", info)
            self.assertTrue(0.0 <= info["box_ratio"] <= 1.0, info)
        if info["box_ratio"] is not None:
            # the run's own workers count as load they are about to add
            self.assertAlmostEqual(info["ratio"], info["box_ratio"] + 4 / info["cpus"], places=2)
        self.assertEqual(info["own_workers"], 4)
        self.assertGreaterEqual(info["multiplier"], 1.0)
        self.assertLessEqual(info["multiplier"], rt.LOAD_MAX_MULTIPLIER)
        self.assertEqual(info["multiplier"], rt.load_multiplier(info["ratio"]))

    def test_default_workers_is_half_the_cpus_capped_at_8(self):
        self.assertEqual(rt.default_workers(16), 8)
        self.assertEqual(rt.default_workers(32), 8)
        self.assertEqual(rt.default_workers(6), 3)
        self.assertEqual(rt.default_workers(1), 1)
        self.assertEqual(rt.default_workers(None), rt.DEFAULT_WORKERS)
        self.assertEqual(rt.parse_args([]).workers, rt.DEFAULT_WORKERS)


class EndToEndTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.tests = self.tmp / "tests"
        self.tests.mkdir()
        self.tiers = self.tmp / "tiers.json"
        self.tiers.write_text(
            json.dumps({"slow": ["test_slow"], "real_data": [], "durations_s": {}}),
            encoding="utf-8",
        )
        self.out = self.tmp / "out.json"

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, name, body):
        (self.tests / f"{name}.py").write_text(textwrap.dedent(body), encoding="utf-8")

    def run_cli(self, *extra, timeout=120):
        cmd = [
            sys.executable,
            str(SCRIPT),
            "--tests-dir",
            str(self.tests),
            "--tiers-file",
            str(self.tiers),
            "--state-dir",
            str(self.tmp / "state"),
            "--json-out",
            str(self.out),
            *extra,
        ]
        proc = subprocess.run(
            cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout, check=False
        )
        summary = (
            json.loads(self.out.read_text(encoding="utf-8"))
            if self.out.exists()
            else None
        )
        return proc, summary

    def test_all_pass_counts_match_and_exit_zero(self):
        for name in ("test_p1", "test_p2", "test_p3", "test_slow"):
            self.write(name, PASS)
        proc, summary = self.run_cli("--workers", "2")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(summary["rc"], 0)
        self.assertEqual(summary["workers"], 2)
        self.assertEqual(summary["totals"]["tests"], 12)
        self.assertEqual(summary["totals"]["skipped"], 4)
        self.assertEqual(
            [m["module"] for m in summary["modules"]],
            ["test_p1", "test_p2", "test_p3", "test_slow"],
        )
        for entry in summary["modules"]:
            self.assertEqual((entry["rc"], entry["status"]), (0, "passed"))
            self.assertIn("duration_s", entry)
        self.assertIn(summary["load"]["source"], {"loadavg", "cpu-sample", "unavailable"})
        self.assertGreaterEqual(summary["timeout_multiplier"], 1.0)
        self.assertEqual(summary["timeout_multiplier"], summary["load"]["multiplier"])
        self.assertIn("time limits x", proc.stderr)

    def test_load_multiplier_argument_is_reported(self):
        self.write("test_p1", PASS)
        proc, summary = self.run_cli("--load-multiplier", "3")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(summary["load"], {"source": "argument", "ratio": None, "multiplier": 3.0})
        self.assertEqual(summary["timeout_multiplier"], 3.0)
        proc, _ = self.run_cli("--load-multiplier", "0.5")
        self.assertEqual(proc.returncode, 2)

    def test_fast_tier_excludes_slow(self):
        self.write("test_p1", PASS)
        self.write("test_slow", PASS)
        proc, summary = self.run_cli("--tier", "fast")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual([m["module"] for m in summary["modules"]], ["test_p1"])

    def test_failure_hang_and_crash_are_reported_and_rest_still_runs(self):
        self.write("test_a_hang", HANG)
        self.write("test_b_after", PASS)
        self.write("test_c_fail", FAIL)
        self.write("test_d_crash", CRASH)
        self.write("test_e_after", PASS)
        started = time.monotonic()
        proc, summary = self.run_cli(
            "--workers",
            "1",
            "--timeout",
            "5",
            "--only",
            "test_a_hang,test_b_after,test_c_fail,test_d_crash,test_e_after",
        )
        self.assertLess(time.monotonic() - started, 60)
        self.assertNotEqual(proc.returncode, 0)
        by_name = {m["module"]: m for m in summary["modules"]}
        self.assertEqual(by_name["test_a_hang"]["status"], "timeout")
        self.assertEqual(by_name["test_c_fail"]["status"], "failed")
        self.assertEqual(
            by_name["test_c_fail"]["failed_tests"][0]["id"], "test_c_fail.T.test_bad"
        )
        self.assertEqual(by_name["test_d_crash"]["status"], "crashed")
        self.assertEqual(by_name["test_b_after"]["status"], "passed")
        self.assertEqual(by_name["test_e_after"]["status"], "passed")
        self.assertEqual(summary["totals"]["timed_out_modules"], ["test_a_hang"])
        self.assertEqual(summary["totals"]["failed_modules"], ["test_c_fail"])
        self.assertEqual(summary["totals"]["crashed_modules"], ["test_d_crash"])
        self.assertIn("TIMEOUT test_a_hang", proc.stderr)

    def test_failed_first_reorders_from_last_run(self):
        self.write("test_a", PASS)
        self.write("test_z", FAIL)
        self.run_cli("--workers", "1")
        proc = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--tests-dir",
                str(self.tests),
                "--tiers-file",
                str(self.tiers),
                "--state-dir",
                str(self.tmp / "state"),
                "--workers",
                "1",
                "--failed-first",
                "--list",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertRegex(proc.stdout, r"worker 0: \d+s  test_z test_a")

    def test_only_unknown_module_is_an_error(self):
        self.write("test_a", PASS)
        proc, _ = self.run_cli("--only", "test_nope")
        self.assertEqual(proc.returncode, 2)


if __name__ == "__main__":
    unittest.main()
