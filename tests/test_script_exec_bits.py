"""Shebang scripts in the ruff scope must be committed executable (ruff EXE001 on POSIX CI).

Windows checkouts never set the executable bit, so files created there land as 100644 and
only the Linux CI job notices. This test reads the git index, so it fails on Windows too.
"""

from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCOPES = ("rapidtriage", "tests", "scripts")


class ScriptExecBitTests(unittest.TestCase):
    def test_shebang_files_are_executable_in_git(self) -> None:
        if shutil.which("git") is None or not (REPO / ".git").exists():
            self.skipTest("git checkout not available")
        listing = subprocess.run(
            ["git", "ls-files", "-s", "--", *SCOPES],
            cwd=REPO,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        ).stdout
        missing = []
        for line in listing.splitlines():
            meta, _, path = line.partition("\t")
            mode = meta.split(" ", 1)[0]
            if mode != "100644" or not path.endswith((".py", ".sh", ".mjs")):
                continue
            target = REPO / path
            if target.is_file() and target.read_bytes()[:2] == b"#!":
                missing.append(path)
        self.assertEqual(missing, [], "run: git update-index --chmod=+x " + " ".join(missing))


if __name__ == "__main__":
    unittest.main()
