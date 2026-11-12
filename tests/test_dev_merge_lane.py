"""Tests for scripts/dev/merge-lane.py (coordinator lane merge, D57).

Each test builds a throwaway git repository; npm (build, check:bundle) and the quick gates are
skipped there, so only the git/contract plumbing is exercised.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "dev" / "merge-lane.py"


def _load():
    spec = importlib.util.spec_from_file_location("dev_merge_lane", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ml = _load()

FAKE_CONTRACT = """\
import { mkdirSync, writeFileSync } from "node:fs";
mkdirSync("frontend/src/contracts", { recursive: true });
writeFileSync("frontend/src/contracts/uiContract.ts", "export const GENERATED = true;\\n");
"""


@unittest.skipIf(shutil.which("git") is None, "git not available")
class MergeLaneTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmp.name)
        self.git("init", "-q", "-b", "feat/r6-ux")
        for key, value in (
            ("user.name", "Lane Test"),
            ("user.email", "lane@example.invalid"),
            ("core.autocrlf", "false"),
            ("commit.gpgsign", "false"),
        ):
            self.git("config", key, value)
        self.write("README.md", "base\n")
        self.write("notes.txt", "one\ntwo\n")
        self.commit("base", "README.md", "notes.txt")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    # -- helpers ------------------------------------------------------------------------------
    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", *args],
            cwd=self.repo,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        ).stdout

    def write(self, path: str, text: str, newline: str = "\n") -> None:
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(text.replace("\n", newline).encode("utf-8"))

    def commit(self, message: str, *paths: str) -> None:
        self.git("add", "--", *paths)
        self.git("commit", "-q", "-m", message)

    def lane(
        self, files: dict[str, str], newline: str = "\n", name: str = "lane/x"
    ) -> None:
        self.git("checkout", "-q", "-b", name)
        for path, text in files.items():
            self.write(path, text, newline)
        self.commit("lane work", *files)
        self.git("checkout", "-q", "feat/r6-ux")

    def run_lane(self, **kwargs) -> tuple[int, str]:
        lane = ml.Lane(
            repo=self.repo,
            branch=kwargs.pop("branch", "lane/x"),
            skip_build=True,
            skip_gates=True,
            **kwargs,
        )
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = lane.execute()
        return code, out.getvalue()

    def parents(self, rev: str) -> list[str]:
        return self.git("rev-list", "--parents", "-n", "1", rev).split()[1:]

    # -- tests --------------------------------------------------------------------------------
    def test_merges_no_ff_and_commits_exec_bit_fix(self) -> None:
        self.lane(
            {
                "scripts/tool.py": "#!/usr/bin/env python3\nprint('x')\n",
                "scripts/lib.py": "X = 1\n",
            }
        )
        code, out = self.run_lane(message="Merge lane/x for the test")
        self.assertEqual(code, 0, out)
        self.assertEqual(
            len(self.parents("HEAD^")), 2, "HEAD^ must be the --no-ff merge commit"
        )
        self.assertEqual(
            self.git("log", "-1", "--format=%s", "HEAD^").strip(),
            "Merge lane/x for the test",
        )
        body = self.git("log", "-1", "--format=%B", "HEAD")
        self.assertIn("Executable bit set on: scripts/tool.py", body)
        self.assertIn(ml.TRAILER, body)
        self.assertTrue(
            self.git("ls-tree", "HEAD", "scripts/tool.py").startswith("100755")
        )
        self.assertTrue(
            self.git("ls-tree", "HEAD", "scripts/lib.py").startswith("100644")
        )
        self.assertEqual(self.git("status", "--porcelain", "--untracked-files=no"), "")

    def test_no_follow_up_commit_when_nothing_regenerated(self) -> None:
        self.lane({"docs/a.md": "a\n"})
        code, out = self.run_lane()
        self.assertEqual(code, 0, out)
        self.assertEqual(len(self.parents("HEAD")), 2, "the merge commit stays the tip")
        self.assertIn("nothing regenerated", out)

    @unittest.skipIf(shutil.which("node") is None, "node not available")
    def test_regenerated_contract_goes_into_one_follow_up_commit(self) -> None:
        self.write(ml.CONTRACT_SCRIPT, FAKE_CONTRACT)
        self.write(
            "frontend/src/contracts/uiContract.ts", "export const GENERATED = false;\n"
        )
        self.commit(
            "contract", ml.CONTRACT_SCRIPT, "frontend/src/contracts/uiContract.ts"
        )
        self.lane({"frontend/src/app.ts": "export {};\n"})
        code, out = self.run_lane()
        self.assertEqual(code, 0, out)
        self.assertEqual(
            self.git("show", "--name-only", "--format=", "HEAD").split(),
            ["frontend/src/contracts/uiContract.ts"],
        )
        self.assertIn(
            "GENERATED = true",
            self.git("show", "HEAD:frontend/src/contracts/uiContract.ts"),
        )

    def test_refuses_other_branch(self) -> None:
        self.lane({"a.txt": "a\n"})
        self.git("checkout", "-q", "lane/x")
        with self.assertRaisesRegex(ml.LaneError, "expected 'feat/r6-ux'"):
            self.run_lane()

    def test_into_selects_integration_branch(self) -> None:
        self.git("branch", "feat/other")
        self.lane({"a.txt": "a\n"})
        self.git("checkout", "-q", "feat/other")
        code, out = self.run_lane(into="feat/other")
        self.assertEqual(code, 0, out)
        self.assertIn("into feat/other", self.git("log", "-1", "--format=%s"))

    def test_refuses_dirty_tree(self) -> None:
        self.lane({"a.txt": "a\n"})
        self.write("README.md", "changed\n")
        with self.assertRaisesRegex(ml.LaneError, "tracked changes"):
            self.run_lane()

    def test_rejects_crlf_only_churn(self) -> None:
        self.lane({"notes.txt": "one\ntwo\n"}, newline="\r\n")
        with self.assertRaisesRegex(ml.LaneError, "CR/LF"):
            self.run_lane()

    def test_conflict_aborts_merge(self) -> None:
        self.lane({"notes.txt": "lane\n"})
        self.write("notes.txt", "base side\n")
        self.commit("base change", "notes.txt")
        head = self.git("rev-parse", "HEAD")
        with self.assertRaises(ml.LaneError):
            self.run_lane()
        self.assertEqual(self.git("rev-parse", "HEAD"), head)
        self.assertFalse((self.repo / ".git" / "MERGE_HEAD").exists())

    def test_already_merged(self) -> None:
        self.lane({"a.txt": "a\n"})
        self.assertEqual(self.run_lane()[0], 0)
        with self.assertRaisesRegex(ml.LaneError, "already merged"):
            self.run_lane()

    def test_dry_run_changes_nothing(self) -> None:
        self.lane({"scripts/tool.py": "#!/usr/bin/env python3\n"})
        head = self.git("rev-parse", "HEAD")
        lane = ml.Lane(repo=self.repo, branch="lane/x", dry_run=True)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(lane.execute(), 0)
        self.assertEqual(self.git("rev-parse", "HEAD"), head)
        text = out.getvalue()
        for step in (
            "git merge --no-ff",
            "--ignore-cr-at-eol",
            "--chmod=+x",
            "--write",
            "run build",
            "check:bundle",
        ):
            self.assertIn(step, text)
        self.assertIn("not pushed", text)

    def test_main_reports_errors(self) -> None:
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = ml.main(["lane/missing", "--repo", str(self.repo), "--skip-gates"])
        self.assertEqual(code, 1)
        self.assertIn("merge-lane:", err.getvalue())


class GateCommandTests(unittest.TestCase):
    def test_bundle_gate_only_when_frontend_changed(self) -> None:
        names = [
            name for name, _args, _cwd in ml.gate_commands(ROOT, frontend_changed=False)
        ]
        self.assertEqual(names, ["ruff", "contract", "exec-bits"])
        names = [
            name for name, _args, _cwd in ml.gate_commands(ROOT, frontend_changed=True)
        ]
        self.assertEqual(names, ["ruff", "contract", "bundle", "exec-bits"])


if __name__ == "__main__":
    unittest.main()
