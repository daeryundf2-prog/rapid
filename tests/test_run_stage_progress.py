"""Live progress of the long run stages (windows-filesystem, docs, persist).

On a full Windows volume the windows-filesystem task sat at the same row count
for close to an hour (its signature scan buffers mismatch rows until the scan totals are
known) and docs/persist showed 0 rows for minutes: these stages now report
rows and a Korean phase message through RunProgress.task_progress.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.artifacts.windows import filesystem
from rapidtriage.core import docs as docs_module
from rapidtriage.core.artifacts import run_artifact_collection
from rapidtriage.core.case_db import database as database_module
from rapidtriage.core.docs import run_docs_search
from rapidtriage.core.run import RunProgress
from rapidtriage.core.run.persist import build_run_case_db
from rapidtriage.core.run.plan import build_run_plan
from tests.test_parser_quality_r2_perf import sample_outputs


def make_signature_tree(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for index in range(5):
        # Text behind an image extension: a signature mismatch row (buffered until the scan ends).
        (root / f"photo{index}.jpg").write_text("not a jpeg", encoding="utf-8")


class RunProgressTaskProgressTests(unittest.TestCase):
    def test_rows_and_message_reach_the_running_task_and_the_message_ends_with_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            progress = RunProgress(Path(tmp_dir), heartbeat_interval=0)
            progress.start(stage="docs")
            progress.set_plan(build_run_plan(mode="fraud"))
            progress.task_progress("docs", rows=3, message="문서 텍스트 추출 중 · 3/10개")
            running = dict(progress.task_record("docs") or {})
            progress.task_progress("persist", message="케이스 DB 적재 중")  # still queued: ignored
            queued = dict(progress.task_record("persist") or {})
            progress.complete_stage("docs")
            finished = dict(progress.task_record("docs") or {})
            progress.finish(status="completed")
        self.assertEqual(running["status"], "running")
        self.assertEqual(running["rows_so_far"], 3)
        self.assertEqual(running["message"], "문서 텍스트 추출 중 · 3/10개")
        self.assertEqual(queued["message"], "")
        self.assertEqual(finished["status"], "completed")
        self.assertEqual(finished["message"], "")  # a "... 중" phase text must not outlive the task


class WindowsFilesystemProgressTests(unittest.TestCase):
    def collect_messages(self, *, threaded: bool) -> tuple[list[str], dict]:
        messages: list[str] = []
        with tempfile.TemporaryDirectory() as tmp_dir, mock.patch.object(filesystem, "PROVIDER_SCAN_REPORT_EVERY", 2):
            root = Path(tmp_dir) / "evidence"
            make_signature_tree(root)
            payload = run_artifact_collection(
                root,
                kind="windows-filesystem",
                records_path=Path(tmp_dir) / "out" / "wfs.jsonl",
                use_cache=False,
                check_cancel=(lambda: False) if threaded else None,
                on_message=messages.append,
            )
        return messages, dict(payload.get("summary") or {})

    def test_signature_scan_reports_files_checked_while_its_rows_are_buffered(self) -> None:
        for threaded in (True, False):  # provider thread (run plan) and inline generator
            with self.subTest(threaded=threaded):
                messages, summary = self.collect_messages(threaded=threaded)
                self.assertEqual(summary.get("artifact_type_counts", {}).get("file-signature-mismatch"), 5)
                self.assertEqual(messages[0], "$MFT·$UsnJrnl 원본 검사 중")
                self.assertIn("파일 서명 검사 중 · 2/5개 확인 · 불일치 2개", messages)
                self.assertIn("파일 서명 검사 중 · 4/5개 확인 · 불일치 4개", messages)
                self.assertEqual(messages[-1], "MFT·USN 내보내기 파일(CSV/JSON) 검사 중")


class DocsProgressTests(unittest.TestCase):
    def test_docs_search_reports_walk_extraction_and_index_phases(self) -> None:
        calls: list[tuple[int, str]] = []
        with tempfile.TemporaryDirectory() as tmp_dir, mock.patch.object(docs_module, "PROVIDER_SCAN_REPORT_EVERY", 1):
            root = Path(tmp_dir) / "evidence"
            root.mkdir()
            for index in range(3):
                (root / f"memo{index}.txt").write_text(f"memo {index}", encoding="utf-8")
            (root / "image.bin").write_bytes(b"\x00" * 8)
            payload = run_docs_search(
                root,
                ["memo"],
                index_output=Path(tmp_dir) / "docs-index.json",
                manifest={},
                on_progress=lambda rows, message: calls.append((rows, message)),
            )
        self.assertEqual(payload["summary"]["candidate_count"], 3)
        messages = [message for _rows, message in calls]
        self.assertTrue(any(message.startswith("문서 후보 찾는 중 · 파일 ") for message in messages))
        self.assertIn((0, "문서 텍스트 추출 중 · 0/3개"), calls)
        self.assertIn((2, "문서 텍스트 추출 중 · 2/3개"), calls)
        self.assertEqual(calls[-1], (3, "문서 검색 색인 만드는 중 · 문서 3개"))


class PersistProgressTests(unittest.TestCase):
    def test_case_db_import_reports_each_phase_and_the_running_row_total(self) -> None:
        calls: list[tuple[int, str]] = []
        with tempfile.TemporaryDirectory() as tmp_dir, mock.patch.object(database_module, "IMPORT_PROGRESS_INTERVAL", 1):
            root = Path(tmp_dir)
            outputs = sample_outputs(root, artifact_count=10)
            out_dir = root / "run-progress"
            out_dir.mkdir()
            record = build_run_case_db(
                out_dir,
                outputs,
                root=str(root / "evidence"),
                on_progress=lambda rows, message: calls.append((rows, message)),
            )
        self.assertEqual(record["status"], "completed", record.get("error"))
        labels = []
        for _rows, message in calls:
            self.assertTrue(message.startswith("케이스 DB 적재 중 · "), message)
            label = message.removeprefix("케이스 DB 적재 중 · ").rsplit(" ", 1)[0]
            if not labels or labels[-1] != label:
                labels.append(label)
        self.assertEqual(labels, ["파일 목록", "문서 본문", "아티팩트", "지표", "타임라인 이벤트"])
        totals = [rows for rows, _message in calls]
        self.assertEqual(totals, sorted(totals))
        counts = record["counts"]
        self.assertEqual(
            totals[-1],
            counts["file_record_count"] + counts["indexed_document_count"] + counts["artifact_count"]
            + counts["indicator_count"] + counts["event_count"],
        )


if __name__ == "__main__":
    unittest.main()
