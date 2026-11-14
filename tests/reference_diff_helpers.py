"""Synthetic-fixture helpers for the ``scripts/*-reference-diff.py`` export-mode tests (T-204..T-207)."""

from __future__ import annotations

import contextlib
import csv
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str) -> ModuleType:
    """Import ``scripts/<name>.py`` (hyphenated file names are not importable by ``import``)."""
    path = REPO_ROOT / "scripts" / f"{name}.py"
    module_name = name.replace("-", "_") + "_under_test"
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def write_jsonl(path: Path, rows: Iterable[Mapping[str, object]]) -> Path:
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")
    return path


def write_csv(path: Path, header: Sequence[str], rows: Iterable[Sequence[object]], delimiter: str = ",") -> Path:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle, delimiter=delimiter)
        writer.writerow(header)
        writer.writerows(rows)
    return path


class ReferenceDiffCase(unittest.TestCase):
    """Runs a script's ``main`` in-process against files in a fresh temp dir."""

    script_name = ""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.module = load_script(self.script_name)

    def run_diff(self, ours: Path, reference: Path, *extra: str) -> tuple[int, dict[str, object], str]:
        output = self.tmp / "report.json"
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = self.module.main(["--ours", str(ours), "--reference", str(reference), "--output", str(output), *extra])
        report = json.loads(output.read_text(encoding="utf-8")) if output.is_file() else {}
        return code, report, stderr.getvalue()

    def assert_contract(self, report: Mapping[str, object]) -> None:
        for key in ("recall", "matched", "missing", "mismatched", "reference_tool"):
            self.assertIn(key, report)
        self.assertEqual(report["release_evidence_status"], "engineering_check_only")

    def assert_missing_input_exit_2(self, present: Path) -> None:
        absent = self.tmp / "no-such-file.csv"
        for ours, reference in ((absent, present), (present, absent)):
            code, report, stderr = self.run_diff(ours, reference)
            self.assertEqual(code, 2)
            self.assertEqual(report, {})
            self.assertIn("입력 파일이 없습니다", stderr)
