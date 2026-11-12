"""Tests for scripts/dev/wt.py (plan task T-150) against a throwaway git repo."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "dev" / "wt.py"

_spec = importlib.util.spec_from_file_location("rt_dev_wt", SCRIPT)
assert _spec is not None and _spec.loader is not None
wt = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = wt
_spec.loader.exec_module(wt)


def run_git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    ).stdout


def count_files(path: Path) -> int:
    return sum(len(files) for _, _, files in os.walk(path))


@unittest.skipIf(shutil.which("git") is None, "git not available")
class WtToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name).resolve() / "repo"
        self.root.mkdir()
        run_git(self.root, "init", "-q", "-b", "main")
        run_git(self.root, "config", "user.email", "t@example.invalid")
        run_git(self.root, "config", "user.name", "t")
        run_git(self.root, "config", "core.autocrlf", "false")
        (self.root / "README.txt").write_text("x\n", encoding="utf-8")
        (self.root / ".gitignore").write_text(
            ".claude/worktrees/\nfrontend/node_modules/\n", encoding="utf-8"
        )
        run_git(self.root, "add", "README.txt", ".gitignore")
        run_git(self.root, "commit", "-q", "-m", "init")
        nm = self.root / "frontend" / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        for i in range(5):
            (nm / f"f{i}.js").write_text("module.exports = 1;\n", encoding="utf-8")
        self.nm_root = self.root / "frontend" / "node_modules"
        self._cwd = os.getcwd()
        os.chdir(self.root)

    def tearDown(self) -> None:
        os.chdir(self._cwd)
        # Unlink any junctions first so cleanup can never recurse into the real node_modules.
        base = self.root / ".claude" / "worktrees"
        if base.is_dir():
            for child in base.iterdir():
                link = child / "frontend" / "node_modules"
                if os.path.lexists(link) and wt.is_link(link):
                    wt.remove_link(link)
        self._tmp.cleanup()

    def wt(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = wt.main(["-C", str(self.root), *argv])
        return code, out.getvalue(), err.getvalue()

    # ------------------------------------------------------------------ ports

    def test_port_ranges_and_reserved(self) -> None:
        for name in ("a", "b", "feat-x", "wa4-t-150"):
            api, vite, e2e = wt.allocate_ports(name, set())
            self.assertTrue(8720 <= api <= 8789)
            self.assertTrue(5200 <= vite <= 5269)
            self.assertTrue(8800 <= e2e <= 8869)
            self.assertNotIn(8710, (api, vite, e2e))
            self.assertNotIn(8791, (api, vite, e2e))

    def test_allocate_skips_used_slot(self) -> None:
        first = wt.allocate_ports("same", set())
        second = wt.allocate_ports("same", {first[0] - wt.API_BASE})
        self.assertNotEqual(first, second)
        with self.assertRaises(wt.WtError):
            wt.allocate_ports("x", set(range(wt.PORT_SLOTS)))

    # -------------------------------------------------------------------- new

    def test_new_twice_gives_distinct_ports_and_env(self) -> None:
        code1, _, err1 = self.wt("new", "feat/one")
        code2, _, err2 = self.wt("new", "feat/two", "--from", "main")
        self.assertEqual((code1, code2), (0, 0), err1 + err2)
        envs = [
            wt.read_env(self.root / ".claude" / "worktrees" / n / ".rt-dev.env")
            for n in ("feat-one", "feat-two")
        ]
        triples = [tuple(int(e[k]) for k in wt.PORT_KEYS) for e in envs]
        self.assertNotEqual(triples[0], triples[1])
        for a, b in zip(*triples, strict=True):
            self.assertNotEqual(a, b)
        self.assertEqual(envs[0]["RT_WT_BRANCH"], "feat/one")
        raw = (
            self.root / ".claude" / "worktrees" / "feat-one" / ".rt-dev.env"
        ).read_bytes()
        self.assertNotIn(b"\r\n", raw)

    def test_new_refuses_existing_dir(self) -> None:
        self.assertEqual(self.wt("new", "dup")[0], 0)
        code, _, err = self.wt("new", "dup")
        self.assertEqual(code, 1)
        self.assertIn("already exists", err)

    # --------------------------------------------------------------------- rm

    def test_rm_refuses_main_checkout_and_outside_paths(self) -> None:
        code, _, err = self.wt("rm", str(self.root))
        self.assertEqual(code, 1)
        self.assertIn("main checkout", err)
        outside = self.root.parent / "elsewhere"
        outside.mkdir()
        code, _, err = self.wt("rm", str(outside))
        self.assertEqual(code, 1)
        self.assertIn("not under", err)
        self.assertTrue((self.root / "README.txt").exists())

    def test_rm_refuses_dirty_unless_force(self) -> None:
        self.wt("new", "dirty")
        path = self.root / ".claude" / "worktrees" / "dirty"
        (path / "README.txt").write_text("changed\n", encoding="utf-8")
        code, _, err = self.wt("rm", "dirty")
        self.assertEqual(code, 1)
        self.assertIn("uncommitted", err)
        self.assertTrue(path.is_dir())
        code, _, err = self.wt("rm", "dirty", "--force")
        self.assertEqual(code, 0, err)
        self.assertFalse(path.exists())

    def test_rm_clean_ignores_own_files(self) -> None:
        self.wt("new", "clean")
        path = self.root / ".claude" / "worktrees" / "clean"
        (path / ".rt-dev.pids").write_text("", encoding="utf-8")
        code, _, err = self.wt("rm", "clean")
        self.assertEqual(code, 0, err)
        self.assertFalse(path.exists())
        self.assertNotIn(str(path), run_git(self.root, "worktree", "list"))

    def test_rm_refuses_locked_unless_force(self) -> None:
        self.wt("new", "locked")
        path = self.root / ".claude" / "worktrees" / "locked"
        run_git(self.root, "worktree", "lock", str(path))
        code, _, err = self.wt("rm", "locked")
        self.assertEqual(code, 1)
        self.assertIn("locked", err)
        self.assertEqual(self.wt("rm", "locked", "--force")[0], 0)
        self.assertFalse(path.exists())

    @unittest.skipUnless(os.name == "nt", "junctions are Windows-only")
    def test_junction_created_and_rm_keeps_real_node_modules(self) -> None:
        before = count_files(self.nm_root)
        self.assertEqual(self.wt("new", "jn")[0], 0)
        link = self.root / ".claude" / "worktrees" / "jn" / "frontend" / "node_modules"
        self.assertTrue(os.path.isjunction(link))
        self.assertTrue((link / "pkg" / "f0.js").is_file())
        code, _, err = self.wt("rm", "jn")
        self.assertEqual(code, 0, err)
        self.assertFalse(os.path.lexists(link))
        self.assertEqual(count_files(self.nm_root), before)

    @unittest.skipUnless(os.name == "nt", "junctions are Windows-only")
    def test_force_rm_dirty_with_junction_keeps_real_node_modules(self) -> None:
        before = count_files(self.nm_root)
        self.wt("new", "jd")
        path = self.root / ".claude" / "worktrees" / "jd"
        (path / "untracked.txt").write_text("u\n", encoding="utf-8")
        self.assertEqual(self.wt("rm", "jd", "--force")[0], 0)
        self.assertFalse(path.exists())
        self.assertEqual(count_files(self.nm_root), before)

    @unittest.skipUnless(os.name == "nt", "junctions are Windows-only")
    def test_rm_refuses_unknown_extra_junction(self) -> None:
        self.wt("new", "extra")
        path = self.root / ".claude" / "worktrees" / "extra"
        wt.make_link(path / "frontend" / "nm2", self.nm_root)
        code, _, err = self.wt("rm", "extra", "--force")
        self.assertEqual(code, 1)
        self.assertIn("other junctions", err)
        wt.remove_link(path / "frontend" / "nm2")
        self.assertEqual(count_files(self.nm_root), 5)

    def test_remove_link_refuses_real_directory(self) -> None:
        with self.assertRaises(wt.WtError):
            wt.remove_link(self.nm_root)
        self.assertEqual(count_files(self.nm_root), 5)

    # ------------------------------------------------------------------ prune

    def _merged_setup(self) -> None:
        run_git(self.root, "branch", "integ")
        self.wt("new", "done", "--from", "integ")
        self.wt("new", "wip", "--from", "integ")
        wip = self.root / ".claude" / "worktrees" / "wip"
        (wip / "new.txt").write_text("n\n", encoding="utf-8")
        run_git(wip, "add", "new.txt")
        run_git(wip, "commit", "-q", "-m", "wip")
        run_git(self.root, "branch", "old-merged", "integ")
        self.wt("new", "busy", "--from", "integ")
        run_git(
            self.root,
            "worktree",
            "lock",
            str(self.root / ".claude" / "worktrees" / "busy"),
        )

    def test_prune_dry_run_lists_without_deleting(self) -> None:
        self._merged_setup()
        code, out, err = self.wt(
            "prune", "--merged-into", "integ", "--dry-run", "--json"
        )
        self.assertEqual(code, 0, err)
        report = json.loads(out)
        paths = [Path(item["path"]).name for item in report["worktrees"]]
        self.assertEqual(paths, ["done"])
        self.assertEqual(sorted(report["branches"]), ["done", "old-merged"])
        self.assertEqual(report["skipped_locked"], 1)
        self.assertEqual(report["skipped_unmerged"], 1)
        self.assertFalse(report["applied"])
        self.assertTrue((self.root / ".claude" / "worktrees" / "done").is_dir())
        self.assertIn("old-merged", run_git(self.root, "branch"))

    def test_prune_apply_removes_only_merged(self) -> None:
        self._merged_setup()
        code, _, err = self.wt("prune", "--merged-into", "integ", "--apply")
        self.assertEqual(code, 0, err)
        base = self.root / ".claude" / "worktrees"
        self.assertFalse((base / "done").exists())
        self.assertTrue((base / "wip").is_dir())
        self.assertTrue((base / "busy").is_dir())
        branches = run_git(self.root, "branch", "--format=%(refname:short)").split()
        self.assertNotIn("old-merged", branches)
        self.assertNotIn("done", branches)
        for keep in ("main", "integ", "wip", "busy"):
            self.assertIn(keep, branches)
        self.assertEqual(count_files(self.nm_root), 5)

    def test_prune_flags_are_exclusive(self) -> None:
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            wt.main(["-C", str(self.root), "prune", "--dry-run", "--apply"])


if __name__ == "__main__":
    unittest.main()
