"""R8 T-352: a full output volume during processing is recorded as a failure (``OUTPUT_DISK_FULL``).

ENOSPC is injected while a stage output is half written (synthetic fixture only). The step fails
with the Korean status "실패 — 결과 폴더 여유 부족(여유 m · 쓰다 만 파일 k개 지움)", the half-written files are
removed, the problem list has one line, the evidence is untouched and a resume after space is
freed produces the same per-kind row counts as an uninterrupted run.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.core import run as run_module
from rapidtriage.core.jobs import RunJob, RunJobStore, RunRequest
from rapidtriage.core.run import run_triage_mode
from rapidtriage.core.run.progress import RUN_PROGRESS_FILE_NAME
from rapidtriage.core.run.steps import (
    OUTPUT_DISK_FULL,
    OutputDiskFull,
    classify_step_exception,
    extraction_disk_full_error,
    is_disk_full_error,
    remove_partial_outputs,
)
from tests import quiet_media_checks
from tests.test_rapidtriage_run import build_run_fixture

setUpModule = quiet_media_checks.setUpModule
tearDownModule = quiet_media_checks.tearDownModule

try:
    from rapidtriage.api.app.run_problems import build_run_problems

    HAS_FASTAPI = True
except ImportError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

FAILING_OUTPUT = "rapidtriage-indicators.json"
STATUS_RE = r"^실패 — 결과 폴더 여유 부족\(여유 [^)]+\)"


def _tree_snapshot(root: Path) -> dict[str, str]:
    """Path -> SHA-256 of every evidence file (the evidence snapshot)."""
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _disk_full_write_result(real_write):
    """``write_result`` that half-writes ``FAILING_OUTPUT`` (plus a temp file) and raises ENOSPC."""

    def fake(payload, output, *args, **kwargs):
        if Path(output).name == FAILING_OUTPUT:
            text = json.dumps(payload, ensure_ascii=False, default=str)
            Path(output).write_text(text[: max(1, len(text) // 2)], encoding="utf-8")
            Path(str(output) + ".tmp").write_text("{", encoding="utf-8")
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_write(payload, output, *args, **kwargs)

    return fake


def _kind_row_counts(summary: dict) -> dict[str, int]:
    return {
        str(step["name"]): int(step.get("artifact_count") or 0)
        for step in summary["steps"]
        if str(step.get("name") or "").startswith("artifacts-")
    }


class DiskFullClassificationTests(unittest.TestCase):
    def test_enospc_and_windows_112_are_disk_full(self) -> None:
        self.assertTrue(is_disk_full_error(OSError(errno.ENOSPC, "full")))
        windows = OSError(errno.EIO, "full")
        windows.winerror = 112  # type: ignore[attr-defined]
        self.assertTrue(is_disk_full_error(windows))
        self.assertFalse(is_disk_full_error(OSError(errno.EACCES, "denied")))
        self.assertFalse(is_disk_full_error(ValueError("x")))

    def test_other_errors_pass_through_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            error = PermissionError(errno.EACCES, "denied")
            self.assertIs(classify_step_exception(error, stage="docs", output_dir=Path(tmp), since_epoch=0), error)

    def test_sqlite_full_is_disk_full(self) -> None:
        self.assertTrue(is_disk_full_error(sqlite3.OperationalError("database or disk is full")))
        self.assertFalse(is_disk_full_error(sqlite3.OperationalError("database is locked")))
        with tempfile.TemporaryDirectory() as tmp:
            failure = classify_step_exception(
                sqlite3.OperationalError("database or disk is full"), stage="case-db", output_dir=Path(tmp), since_epoch=0
            )
        self.assertIsInstance(failure, OutputDiskFull)

    def test_classified_error_carries_code_and_korean_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "rapidtriage-half.json").write_text('{"a": [1, 2', encoding="utf-8")
            (out / "rapidtriage-done.json").write_text('{"a": 1}\n', encoding="utf-8")
            (out / "rapidtriage-rows.jsonl").write_text('{"a": 1}\n{"b"', encoding="utf-8")
            failure = classify_step_exception(OSError(errno.ENOSPC, "full"), stage="timeline", output_dir=out, since_epoch=0)
            self.assertIsInstance(failure, OutputDiskFull)
            self.assertEqual(failure.code, OUTPUT_DISK_FULL)
            self.assertEqual(failure.errno, errno.ENOSPC)
            self.assertRegex(str(failure), STATUS_RE)
            self.assertNotIn("필요", str(failure))
            self.assertIn("쓰다 만 파일 2개 지움", str(failure))
            self.assertEqual(failure.removed_files, ["rapidtriage-half.json", "rapidtriage-rows.jsonl"])
            self.assertIn("지운 파일(결과 폴더 기준): rapidtriage-half.json, rapidtriage-rows.jsonl", str(failure))
            self.assertTrue((out / "rapidtriage-done.json").exists())

    def test_free_space_is_measured_before_cleanup(self) -> None:
        calls: list[str] = []

        def usage(_folder):
            calls.append("usage")
            return mock.Mock(free=123)

        def remove(*_args, **_kwargs):
            calls.append("remove")
            return ["rapidtriage-x.tmp"], 4096

        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch("rapidtriage.core.run.disk_full.shutil.disk_usage", usage),
            mock.patch("rapidtriage.core.run.disk_full.remove_partial_outputs", remove),
        ):
            failure = classify_step_exception(OSError(errno.ENOSPC, "full"), stage="docs", output_dir=Path(tmp), since_epoch=0)
        self.assertEqual(calls, ["usage", "remove"])
        self.assertIn("여유 123 B", str(failure))

    def test_extracted_trees_and_evidence_named_files_survive(self) -> None:
        """Review P1-1: only this run's own temp / unclosed outputs go; extracted copies never do."""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            evidence = []
            trees = (
                "_e01/filesystem/Users/u/AppData/Local/Temp",
                "_disk_image/fs",
                "_archive_image",
                "_virtual_disk",
                "docs-extract",
                "files-extract",
                "mobile-inner",
            )
            for tree in trees:
                folder = out / tree
                folder.mkdir(parents=True)
                for name in ("a.tmp", "~WRL0001.tmp", "dl.partial", "x.json", "s.jsonl", "rapidtriage-y.tmp"):
                    path = folder / name
                    path.write_text('{"a": 1' if name.endswith(".json") else "row", encoding="utf-8")
                    evidence.append(path)
                (folder / "empty.json").write_text("", encoding="utf-8")
                evidence.append(folder / "empty.json")
            # User-named temp / json files at the top level are not this tool's outputs either.
            for name in ("notes.tmp", "user.json"):
                (out / name).write_text("{", encoding="utf-8")
                evidence.append(out / name)
            (out / "artifacts").mkdir()
            own = [
                out / "rapidtriage-run-progress.json.tmp",
                out / "rapidtriage-artifacts-records.jsonl.raw.tmp",
                out / "rapidtriage-indicators.json",
                out / "artifacts" / "rapidtriage-artifacts-browser.json.123.456.tmp",
                out / "artifacts" / "rapidtriage-artifacts-ai.json",
            ]
            for path in own:
                path.write_text("{", encoding="utf-8")
            named = out / "_e01" / "filesystem" / "big.bin"
            named.write_bytes(b"x")
            evidence.append(named)
            error = OSError(errno.ENOSPC, "full", str(named))
            failure = classify_step_exception(error, stage="files", output_dir=out, since_epoch=0)
            for path in evidence:
                self.assertTrue(path.exists(), f"evidence copy removed: {path.relative_to(out)}")
            for path in own:
                self.assertFalse(path.exists(), f"own temp left: {path.relative_to(out)}")
            self.assertEqual(failure.removed_files, sorted(path.relative_to(out).as_posix() for path in own))

    def test_extraction_errors_on_a_full_volume_are_disk_full(self) -> None:
        result = {"command_history": [{"stage": "native-filesystem-recovery", "errors": 7}]}
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            with mock.patch("rapidtriage.core.run.disk_full.shutil.disk_usage", return_value=mock.Mock(free=1024)):
                error = extraction_disk_full_error(out, result)
                self.assertIsNotNone(error)
                failure = classify_step_exception(error, stage="prepare", output_dir=out, since_epoch=0)
            self.assertIn("추출하지 못한 파일 7개", str(failure))
            self.assertIn("새 결과 폴더", str(failure))
            with mock.patch("rapidtriage.core.run.disk_full.shutil.disk_usage", return_value=mock.Mock(free=10 << 30)):
                self.assertIsNone(extraction_disk_full_error(out, result))
            self.assertIsNone(extraction_disk_full_error(out, {"command_history": [{"errors": 0}]}))

    def test_old_outputs_are_kept_and_named_file_is_removed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            old = out / "rapidtriage-old.json"
            old.write_text('{"a": 1', encoding="utf-8")
            os.utime(old, (1000, 1000))
            named = out / "report.md"
            named.write_text("# half", encoding="utf-8")
            error = OSError(errno.ENOSPC, "full", str(named))
            removed, removed_bytes = remove_partial_outputs(out, error, since_epoch=10_000)
            self.assertEqual(removed, ["report.md"])
            self.assertEqual(removed_bytes, len("# half"))
            self.assertTrue(old.exists())


class DiskFullRunTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name)
        self.root = base / "case-root"
        self.root.mkdir()
        build_run_fixture(self.root)
        self.output_dir = base / "run-out"
        self.reference_dir = base / "run-reference"

    @unittest.skipUnless(HAS_FASTAPI, "web extra not installed")
    def test_injected_enospc_fails_step_removes_half_files_and_resume_matches(self) -> None:
        evidence_before = _tree_snapshot(self.root)
        store = RunJobStore()
        request = RunRequest(root=str(self.root), mode="hacking", output_dir=str(self.output_dir))
        store._jobs["full"] = RunJob(run_id="full", request=request)
        with mock.patch.object(run_module, "write_result", _disk_full_write_result(run_module.write_result)):
            with self.assertRaises(OutputDiskFull) as caught:
                store._execute("full")
        failure = caught.exception
        self.assertRegex(str(failure), STATUS_RE)
        self.assertIsInstance(failure.__cause__, OSError)

        # The job and the step record the failure; the problem list has one line.
        job = store._jobs["full"]
        self.assertEqual(job.status, "failed")
        self.assertEqual(job.error_type, "OutputDiskFull")
        self.assertRegex(job.error or "", STATUS_RE)
        triage = next(step for step in job.steps if step.get("name") == "triage")
        self.assertEqual(triage["status"], "failed")
        problems = build_run_problems(store, "full")
        self.assertEqual(problems["total"], 1)
        self.assertEqual([group["reason_id"] for group in problems["groups"]], ["output-disk-full"])
        self.assertRegex(problems["groups"][0]["items"][0]["message"], STATUS_RE)

        progress = json.loads((self.output_dir / RUN_PROGRESS_FILE_NAME).read_text(encoding="utf-8"))
        self.assertEqual(progress["status"], "failed")
        self.assertEqual(progress["error"]["code"], OUTPUT_DISK_FULL)
        self.assertEqual(progress["error"]["error_type"], "OutputDiskFull")
        # Every removed path is recorded (relative to the result folder) in progress and the problem line.
        self.assertEqual(
            progress["error"]["removed_files"], [FAILING_OUTPUT, FAILING_OUTPUT + ".tmp"]
        )
        self.assertIn(FAILING_OUTPUT, problems["groups"][0]["items"][0]["message"])
        self.assertEqual(progress["plan"]["outcome"], "failed")
        tasks = [task for group in progress["plan"]["groups"] for task in group["tasks"]]
        self.assertEqual([task["id"] for task in tasks if task.get("status") == "running"], [])
        failed = [task for task in tasks if task.get("status") == "failed"]
        self.assertTrue(failed, "the step that was writing is failed")
        for task in failed:
            self.assertEqual(int(task.get("rows_so_far") or 0), 0)

        # 0 half-written files: no temp leftovers, the failing output is gone, every JSON parses.
        self.assertFalse((self.output_dir / FAILING_OUTPUT).exists())
        leftovers = [p.name for p in self.output_dir.rglob("*") if p.name.endswith((".tmp", ".partial"))]
        self.assertEqual(leftovers, [])
        for path in self.output_dir.rglob("*.json"):
            json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(_tree_snapshot(self.root), evidence_before, "evidence snapshot changed")

        # Space freed: the resumed run matches an uninterrupted run kind by kind.
        resumed = run_triage_mode(self.root, mode="hacking", output_dir=self.output_dir, resume=True)
        self.assertEqual(resumed["plan"]["outcome"], "complete")
        reference = run_triage_mode(self.root, mode="hacking", output_dir=self.reference_dir)
        self.assertTrue(_kind_row_counts(reference))
        self.assertEqual(_kind_row_counts(resumed), _kind_row_counts(reference))
        self.assertTrue((self.output_dir / FAILING_OUTPUT).exists())
        self.assertEqual(_tree_snapshot(self.root), evidence_before, "evidence snapshot changed")


if __name__ == "__main__":
    unittest.main()
