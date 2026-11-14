"""Tests for scripts/check-agents-md.py (AGENTS.md command drift check)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "check-agents-md.py"

_spec = importlib.util.spec_from_file_location("check_agents_md", SCRIPT)
assert _spec is not None and _spec.loader is not None
check_agents_md = importlib.util.module_from_spec(_spec)
sys.modules["check_agents_md"] = check_agents_md
_spec.loader.exec_module(check_agents_md)

GOOD = """# Title

## RapidTriage verification gate

```bash
python scripts/dev/gate.py --tier fast             # comment
```

Inline `npm run check:bundle` and `docs/rapidtriage-quality-checks.md`.

## RapidForensic Validation Contract

```bash
python -m json.tool --help
python scripts/build-evidence-bundle.py --root tests/fixtures/known_answer/tier0-basic --json
git status --short
```

```bash
python scripts/carve-known-answer.py --output-dir <dir> --extract --json
```

---

## Other

```bash
python scripts/does-not-exist.py
```
"""


class CheckAgentsMdTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _check(self, text: str, run_cheap: bool = False) -> dict:
        path = self.tmp / "AGENTS.md"
        path.write_text(text, encoding="utf-8", newline="\n")
        return check_agents_md.check_agents_md(path, REPO, run_cheap=run_cheap)

    def _problems(self, report: dict) -> list[str]:
        return [p for c in report["commands"] for p in c["problems"]] + report["errors"]

    def test_good_document_passes_and_ignores_other_sections(self) -> None:
        report = self._check(GOOD)
        self.assertTrue(report["ok"], self._problems(report))
        texts = [c["text"] for c in report["commands"]]
        self.assertIn(
            "python scripts/dev/gate.py --tier fast", texts
        )  # comment stripped
        self.assertIn("npm run check:bundle", texts)  # inline command picked up
        self.assertNotIn("python scripts/does-not-exist.py", texts)
        self.assertEqual(report["counts"].get("placeholder"), 1)

    def test_run_cheap_executes_fixture_commands(self) -> None:
        report = self._check(GOOD, run_cheap=True)
        self.assertTrue(report["ok"], self._problems(report))
        ran = {c["text"] for c in report["commands"] if c["status"] == "ran"}
        self.assertIn(
            "python scripts/build-evidence-bundle.py --root tests/fixtures/known_answer/tier0-basic --json",
            ran,
        )
        self.assertIn("git status --short", ran)

    def _assert_drift(self, old: str, new: str, needle: str) -> None:
        report = self._check(GOOD.replace(old, new, 1))
        self.assertFalse(report["ok"])
        self.assertTrue(
            any(needle in p for p in self._problems(report)), self._problems(report)
        )

    def test_missing_script(self) -> None:
        self._assert_drift(
            "scripts/dev/gate.py", "scripts/dev/gone.py", "missing script"
        )

    def test_unknown_flag(self) -> None:
        self._assert_drift("--tier fast", "--tier fast --no-such-flag", "flag not in")

    def test_missing_module(self) -> None:
        self._assert_drift("json.tool", "no_such_module_xyz", "module not importable")

    def test_missing_npm_script(self) -> None:
        self._assert_drift("check:bundle", "check:nope", "npm script")

    def test_missing_path_argument(self) -> None:
        self._assert_drift(
            "known_answer/tier0-basic --json",
            "known_answer/nope --json",
            "missing path",
        )

    def test_missing_inline_path(self) -> None:
        self._assert_drift(
            "docs/rapidtriage-quality-checks.md", "docs/gone.md", "missing inline path"
        )

    def test_placeholder_command_still_syntax_checked(self) -> None:
        self._assert_drift("--extract --json", "--extract --bogus", "flag not in")

    def test_missing_section(self) -> None:
        self._assert_drift(
            "## RapidTriage verification gate", "## Renamed", "section missing"
        )

    def test_unknown_command_head(self) -> None:
        self._assert_drift("git status --short", "make all", "unknown command head")

    def test_cli_on_synthetic_broken_document_exits_one(self) -> None:
        path = self.tmp / "AGENTS.md"
        path.write_text(
            GOOD.replace("scripts/dev/gate.py", "scripts/dev/gone.py"),
            encoding="utf-8",
            newline="\n",
        )
        proc = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--agents-md",
                str(path),
                "--root",
                str(REPO),
                "--json",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=300,
            check=False,
        )
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertFalse(json.loads(proc.stdout)["ok"])

    def test_repository_agents_md_passes(self) -> None:
        report = check_agents_md.check_agents_md(REPO / "AGENTS.md", REPO)
        self.assertTrue(report["ok"], self._problems(report))


if __name__ == "__main__":
    unittest.main()
