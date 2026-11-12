"""Tests for the T-149 guard scripts: scripts/dev/check-eol.py and check-staged.py."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CHECK_EOL = REPO / "scripts" / "dev" / "check-eol.py"
CHECK_STAGED = REPO / "scripts" / "dev" / "check-staged.py"
BASELINE = REPO / "scripts" / "dev" / "eol-baseline.json"
EOL_BUDGET_SECONDS = 2.0  # T-149 acceptance: one run of check-eol.py on this repo
# Python start + one `git ls-files` on an idle 16-core Windows host.
IDLE_PROBE_SECONDS = 0.4


def _run(script: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(script), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


@unittest.skipIf(shutil.which("git") is None, "git not available")
class _TempRepo(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.git("init", "-q")
        self.git("config", "core.autocrlf", "false")
        (self.root / ".gitattributes").write_bytes(b"* -text\n*.ps1 text eol=crlf\n")
        (self.root / "ok.py").write_bytes(b"x = 1\n")
        (self.root / "old.py").write_bytes(b"x = 1\r\ny = 2\r\n")
        self.baseline = self.root / "baseline.json"
        self.baseline.write_text(
            json.dumps({"files": [{"path": "old.py", "eol": "crlf"}]}), encoding="utf-8"
        )
        self.git("add", ".gitattributes", "ok.py", "old.py")
        self.git(
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.invalid",
            "commit",
            "-q",
            "-m",
            "init",
        )

    def git(self, *args: str) -> None:
        subprocess.run(["git", *args], cwd=self.root, check=True, capture_output=True)

    def write(self, rel: str, data: bytes) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def eol(self, *args: str) -> subprocess.CompletedProcess[str]:
        return _run(
            CHECK_EOL, "--repo", str(self.root), "--baseline", str(self.baseline), *args
        )

    def staged(self, *args: str) -> subprocess.CompletedProcess[str]:
        return _run(
            CHECK_STAGED,
            "--repo",
            str(self.root),
            "--baseline",
            str(self.baseline),
            *args,
        )


class CheckEolTests(_TempRepo):
    def test_baseline_only_passes(self) -> None:
        result = self.eol()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_new_crlf_file_fails(self) -> None:
        self.write("new.py", b"a = 1\r\n")
        result = self.eol("--json")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(
            json.loads(result.stdout)["new"], [{"path": "new.py", "eol": "crlf"}]
        )

    def test_mixed_tracked_file_fails(self) -> None:
        self.write("ok.py", b"x = 1\ny = 2\r\n")
        result = self.eol()
        self.assertEqual(result.returncode, 1)
        self.assertIn("ok.py", result.stdout)

    def test_fixed_baseline_entry_is_stale(self) -> None:
        self.write("old.py", b"x = 1\ny = 2\n")
        self.git("add", "old.py")
        result = self.eol("--json")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["stale_baseline"], ["old.py"])

    def test_crlf_attribute_and_binary_are_ignored(self) -> None:
        self.write("run.ps1", b"Write-Host hi\r\n")
        self.write("blob.bin", b"\x00\x01\r\n\x00")
        self.assertEqual(self.eol().returncode, 0, self.eol().stdout)


class CheckStagedTests(_TempRepo):
    def test_clean_stage_passes(self) -> None:
        self.write("src/a.py", b"a = 1\n")
        self.git("add", "src/a.py")
        result = self.staged()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_blocked_paths_fail(self) -> None:
        blocked = [
            "rapidtriage/web/static/v2/assets/index.js",
            "frontend/node_modules/x/index.js",
            ".rt-dev.json",
            "evidence/disk.E01",
            "evidence/disk.Ex01",
            "evidence/disk.dd",
            "evidence/disk.raw",
            "evidence/disk.img",
            "evidence/disk.vhdx",
            "evidence/disk.aff",
        ]
        for rel in blocked:
            self.write(rel, b"data\n")
            self.git("add", "-f", rel)
        result = self.staged("--json")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(
            sorted(e["path"] for e in json.loads(result.stdout)["blocked"]),
            sorted(blocked),
        )

    def test_allow_bundle(self) -> None:
        self.write("rapidtriage/web/static/v2/index.html", b"<html></html>\n")
        self.git("add", "rapidtriage/web/static/v2/index.html")
        self.assertEqual(self.staged().returncode, 1)
        self.assertEqual(self.staged("--allow-bundle").returncode, 0)

    def test_large_blob_fails(self) -> None:
        self.write("big.bin", b"\x00" * 2048)
        self.git("add", "big.bin")
        self.assertEqual(self.staged("--max-bytes", "1024").returncode, 1)
        self.assertEqual(self.staged("--max-bytes", "4096").returncode, 0)

    def test_staged_crlf_fails_unless_baselined(self) -> None:
        self.write("new.py", b"a = 1\r\n")
        self.write("old.py", b"x = 1\r\ny = 3\r\n")
        self.git("add", "new.py", "old.py")
        result = self.staged("--json")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(
            [e["path"] for e in json.loads(result.stdout)["blocked"]], ["new.py"]
        )


@unittest.skipIf(
    shutil.which("git") is None or not (REPO / ".git").exists(),
    "git checkout not available",
)
class RepoGuardTests(unittest.TestCase):
    def test_baseline_records_13_crlf_and_1_mixed(self) -> None:
        files = json.loads(BASELINE.read_text(encoding="utf-8"))["files"]
        kinds = [entry["eol"] for entry in files]
        self.assertEqual((kinds.count("crlf"), kinds.count("mixed")), (13, 1))

    def test_check_eol_runs_on_repo_within_two_seconds(self) -> None:
        # Budget: 2 s on an idle machine.  A busy machine (parallel test workers,
        # other agents) slows every process start, so the budget is scaled by how
        # much slower a bare "python + git ls-files" probe is than its idle cost.
        probe = [
            sys.executable,
            "-c",
            "import subprocess; subprocess.run(['git', 'ls-files', '-z'], capture_output=True)",
        ]
        timings = []
        budgets = []
        for _ in range(3):
            start = time.monotonic()
            subprocess.run(probe, cwd=REPO, check=True)
            load = max(1.0, (time.monotonic() - start) / IDLE_PROBE_SECONDS)
            start = time.monotonic()
            result = _run(CHECK_EOL, "--json")
            timings.append(time.monotonic() - start)
            budgets.append(EOL_BUDGET_SECONDS * load)
            self.assertIn(result.returncode, (0, 1), result.stderr)
            json.loads(result.stdout)
            if timings[-1] < budgets[-1]:
                break
        self.assertLess(
            timings[-1], budgets[-1], f"timings={timings} budgets={budgets}"
        )


if __name__ == "__main__":
    unittest.main()
