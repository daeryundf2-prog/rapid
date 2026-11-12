"""Tests for scripts/dev/run.py (plan task T-151): time limit, own-tree kill, port guard, cleanup."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RUN_PY = REPO / "scripts" / "dev" / "run.py"

_spec = importlib.util.spec_from_file_location("dev_run", RUN_PY)
dev_run = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(dev_run)

# Child records its PID, starts a grandchild that records its PID, then both sleep 60 s.
GRANDCHILD = (
    "import os, sys, time; p = sys.argv[1]; open(p + '.tmp', 'w').write(str(os.getpid())); "
    "os.replace(p + '.tmp', p); time.sleep(60)"
)
CHILD = textwrap.dedent(
    """
    import os, subprocess, sys, time
    out = sys.argv[1]
    open(os.path.join(out, "child.pid"), "w").write(str(os.getpid()))
    subprocess.Popen([sys.executable, "-c", sys.argv[2], os.path.join(out, "grand.pid")])
    time.sleep(60)
    """
)

def _wait_for(path: Path, seconds: float = 20.0) -> None:
    deadline = time.monotonic() + seconds
    while not path.exists():
        if time.monotonic() > deadline:
            raise AssertionError(f"{path} never appeared")
        time.sleep(0.05)


def _sleeper() -> subprocess.Popen:
    return subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])


class DevRunTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="dev-run-test-"))
        self.state_dir = self.tmp / "state"
        self.extra: list[subprocess.Popen] = []

    def tearDown(self) -> None:
        for proc in self.extra:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, *args: str, timeout: float = 60) -> tuple[subprocess.CompletedProcess, dict]:
        out = self.tmp / "result.json"
        proc = subprocess.run(
            [sys.executable, str(RUN_PY), "--state-dir", str(self.state_dir), "--json-out", str(out), *args],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        result = json.loads(out.read_text(encoding="utf-8")) if out.exists() else {}
        return proc, result

    def test_timeout_kills_child_and_grandchild_only(self) -> None:
        bystander = _sleeper()
        self.extra.append(bystander)
        started = time.monotonic()
        proc, result = self._run(
            "--timeout", "5", "--", sys.executable, "-c", CHILD, str(self.tmp), GRANDCHILD,
        )
        elapsed = time.monotonic() - started
        self.assertEqual(proc.returncode, dev_run.EXIT_TIMEOUT, proc.stderr)
        self.assertEqual(result["status"], "timeout")
        self.assertEqual(result["exit_code"], dev_run.EXIT_TIMEOUT)
        self.assertGreaterEqual(result["seconds"], 5)
        self.assertLess(elapsed, 30)
        self.assertEqual(result["remaining"], [])

        _wait_for(self.tmp / "grand.pid", 1)
        child_pid = int((self.tmp / "child.pid").read_text())
        grand_pid = int((self.tmp / "grand.pid").read_text())
        self.assertIn(child_pid, result["tree"])
        self.assertIn(grand_pid, result["tree"])
        self.assertFalse(dev_run.is_alive(child_pid))
        self.assertFalse(dev_run.is_alive(grand_pid))
        self.assertIsNone(bystander.poll(), "an unrelated python process was killed")
        self.assertEqual(list(self.state_dir.glob("run-*.json")), [])

    def test_normal_exit_kills_orphaned_grandchild(self) -> None:
        code = textwrap.dedent(
            """
            import os, subprocess, sys
            subprocess.Popen([sys.executable, "-c", sys.argv[2], os.path.join(sys.argv[1], "grand.pid")])
            while not os.path.exists(os.path.join(sys.argv[1], "grand.pid")):
                pass
            sys.exit(3)
            """
        )
        proc, result = self._run("--timeout", "30", "--", sys.executable, "-c", code, str(self.tmp), GRANDCHILD)
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assertEqual(result["remaining"], [])
        grand_pid = int((self.tmp / "grand.pid").read_text())
        self.assertFalse(dev_run.is_alive(grand_pid))

    def test_exit_code_passthrough_and_no_browser_env(self) -> None:
        marker = self.tmp / "env.txt"
        code = (
            "import os, sys; from pathlib import Path; "
            f"Path({str(marker)!r}).write_text(os.environ.get('RAPIDTRIAGE_NO_BROWSER', '')); sys.exit(7)"
        )
        proc, result = self._run("--timeout", "30", "--", sys.executable, "-c", code)
        self.assertEqual(proc.returncode, 7, proc.stderr)
        self.assertEqual(result["status"], "exited")
        self.assertEqual(result["exit_code"], 7)
        self.assertIn("seconds", result)
        self.assertEqual(marker.read_text(), "1")

        proc, result = self._run("--timeout", "30", "--", sys.executable, "-c", "pass")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(result["exit_code"], 0)

    def test_refuses_protected_port_without_running(self) -> None:
        marker = self.tmp / "ran.txt"
        code = f"from pathlib import Path; Path({str(marker)!r}).write_text('1')"
        proc, result = self._run("--timeout", "10", "--port", "8710", "--", sys.executable, "-c", code)
        self.assertEqual(proc.returncode, dev_run.EXIT_REFUSED)
        self.assertEqual(result["status"], "refused")
        self.assertFalse(marker.exists())

        proc, result = self._run("--timeout", "10", "--", sys.executable, "-c", code, "--port=8710")
        self.assertEqual(proc.returncode, dev_run.EXIT_REFUSED)
        self.assertFalse(marker.exists())

    def test_refuses_busy_port(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            self.assertNotEqual(port, dev_run.PROTECTED_PORT)
            proc, result = self._run("--timeout", "10", "--port", str(port), "--", sys.executable, "-c", "pass")
        self.assertEqual(proc.returncode, dev_run.EXIT_REFUSED)
        self.assertIn("in use", result["reason"])

    def test_cleanup_kills_only_recorded_pids(self) -> None:
        leftover = _sleeper()
        unrelated = _sleeper()
        reused = _sleeper()  # recorded with a wrong start time: simulates PID reuse
        self.extra += [leftover, unrelated, reused]
        deadline = time.monotonic() + 10
        while dev_run.process_start(leftover.pid) is None and time.monotonic() < deadline:
            time.sleep(0.05)

        self.state_dir.mkdir(parents=True)
        dead = subprocess.run([sys.executable, "-c", "import os; print(os.getpid())"],
                              capture_output=True, text=True, check=True)
        state = {
            "version": 1,
            "wrapper": {"pid": int(dead.stdout), "start": "dead-wrapper"},
            "root": leftover.pid,
            "pgid": None,
            "command": ["sleeper"],
            "processes": [
                {"pid": leftover.pid, "start": dev_run.process_start(leftover.pid)},
                {"pid": reused.pid, "start": "not-the-real-start-time"},
            ],
        }
        (self.state_dir / "run-1-dead.json").write_text(json.dumps(state), encoding="utf-8")

        live_state = dict(state)
        live_state["wrapper"] = {"pid": os.getpid(), "start": dev_run.process_start(os.getpid())}
        live_state["processes"] = [{"pid": unrelated.pid, "start": dev_run.process_start(unrelated.pid)}]
        (self.state_dir / "run-2-live.json").write_text(json.dumps(live_state), encoding="utf-8")

        proc = subprocess.run(
            [sys.executable, str(RUN_PY), "--cleanup", "--state-dir", str(self.state_dir)],
            capture_output=True, text=True, timeout=60, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        report = json.loads(proc.stdout)
        self.assertEqual(report["killed"], [leftover.pid])
        self.assertEqual(len(report["skipped_active"]), 1)
        leftover.wait(timeout=10)
        self.assertIsNone(unrelated.poll(), "process of a live wrapper was killed")
        self.assertIsNone(reused.poll(), "PID with a different start time was killed")
        self.assertFalse((self.state_dir / "run-1-dead.json").exists())
        self.assertTrue((self.state_dir / "run-2-live.json").exists())


if __name__ == "__main__":
    unittest.main()
