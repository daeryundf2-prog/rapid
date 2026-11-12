"""Processing problems list engine and parser limits in Korean (R8 T-184, GAP-271/262/263/264).

Acceptance: an IMG-B-shaped run gains at least five Korean limitation items (E01 truncation per
axis, read errors, ``$MFT`` / USN record caps, the ``$LogFile`` window, undisclosed caps); no cap
number is a fixed string -- with every cap set to 50 the sentences say 50 and never 200,000.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

from rapidtriage.api.app import run_problem_limits, run_problems

REPO = Path(__file__).resolve().parents[1]
MIB = 1024 * 1024
IMG_B_STATS = {
    "files": 200_000,
    "bytes": 1,
    "errors": 2_175,
    "depth_skips": 3,
    "truncated": 430_052,
    "deleted_files": 54_693,
    "deleted_read_errors": 2_170,
    "alias_skips": 41_937,
    "file_limit": 200_000,
}
HANGUL = re.compile(r"[가-힣]")
ENGLISH_PHRASE = re.compile(r"\b[A-Za-z]{3,}\s+[A-Za-z]{3,}\b")


class _Store:
    """Just enough of ``RunJobStore`` for ``get_output_path``: outputs come from the summary."""

    def __init__(self, summary: dict[str, Any]) -> None:
        self.summary = summary

    def output_path(self, _run_id: str, name: str) -> Path:
        return Path(self.summary["outputs"][name])


def _sparse(path: Path, size: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.truncate(size)


class RunProblemLimitsTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name)
        self.run_dir = base / "run"
        self.root = base / "run" / "_e01" / "recovered"
        _sparse(self.root / "$MFT", 20 * MIB)
        _sparse(self.root / "$LogFile", 9 * MIB)
        _sparse(self.root / "$Extend" / "$UsnJrnl", 1 * MIB)
        fs_output = self.run_dir / "artifacts" / "rapidtriage-artifacts-windows-filesystem.json"
        fs_output.parent.mkdir(parents=True, exist_ok=True)
        fs_output.write_text(
            json.dumps(
                {
                    "command": "artifacts",
                    "summary": {
                        "artifact_count": 10_013,
                        "artifact_type_counts": {
                            "mft-file": 1,
                            "mft-record": 5000,
                            "usn-journal-file": 1,
                            "usn-record": 5000,
                            "ntfs-logfile-transaction-candidate": 1,
                        },
                        "parser_error_count": 0,
                    },
                    "parser_errors": [],
                    "artifacts": [],
                }
            ),
            encoding="utf-8",
        )
        self.summary: dict[str, Any] = {
            "output_dir": str(self.run_dir),
            "root": str(self.root),
            "outputs": {"artifacts_windows-filesystem": str(fs_output)},
            "source": {
                "partition_selection": {"selected_start_sector": 2048, "partition_count": 4, "supported_partition_count": 2},
                "recovered_root_manifest": {"native_extraction_stats": dict(IMG_B_STATS)},
            },
            "steps": [
                {"name": "artifacts-windows-filesystem", "status": "completed", "parser_error_count": 0},
                {"name": "artifacts-windows-execution", "status": "completed", "parser_error_count": 0},
                {"name": "artifacts-eventlog", "status": "failed_isolated", "parser_error_count": 0},
                {"name": "artifacts-email", "status": "skipped"},
            ],
            "silent_failure_detection": {
                "checks": [
                    {
                        "id": "artifact-yield-windows-prefetch",
                        "level": "warning",
                        "detail": "target_count=212, artifact_count=0",
                        "message": "Prefetch files exist but no prefetch artifacts were parsed.",
                    },
                    {
                        "id": "timeline-yield",
                        "level": "warning",
                        "detail": "timeline_event_count=0, file_candidate_count=4, document_match_count=2",
                        "message": "Candidate evidence exists but no timeline events were produced.",
                    },
                ]
            },
            "warnings": [{"step": "artifacts-email", "level": "notice", "message": "No email artifact rows were collected."}],
        }

    def collect(self) -> list[dict[str, Any]]:
        job = SimpleNamespace(summary=self.summary, status="completed", error=None)
        return run_problems.collect_problem_items(_Store(self.summary), "run-b", job)  # type: ignore[arg-type]

    def limits(self) -> list[dict[str, Any]]:
        return [item for item in self.collect() if item["source"] == "engine_limit"]

    def test_img_b_shape_adds_at_least_five_korean_limits(self) -> None:
        items = self.limits()
        self.assertGreaterEqual(len(items), 5)
        reasons = {item["reason_id"] for item in items}
        self.assertTrue({"e01-extract-cap", "e01-read-error", "e01-depth-cap", "ntfs-parse-cap", "undisclosed-cap"} <= reasons)
        for item in items:
            with self.subTest(message=item["message"]):
                self.assertRegex(item["message"], HANGUL)
                self.assertNotRegex(item["message"], ENGLISH_PHRASE)
                self.assertIn(item["reason_id"], run_problems.ALL_REASON_LABELS)

    def test_e01_truncation_and_read_errors_name_the_axis(self) -> None:
        messages = [item["message"] for item in self.limits() if item["reason_id"].startswith("e01-")]
        joined = "\n".join(messages)
        self.assertIn("E01 추출 상한(파일 200,000개)에 닿아 삭제 파일 레코드 430,052건", joined)
        self.assertIn("(삭제 영역 축)", joined)
        self.assertIn("E01 할당 영역 읽기 오류 5건", joined)
        self.assertIn("E01 삭제 레코드 읽기 오류 2,170건", joined)
        self.assertIn("폴더 깊이 상한(64단계)보다 깊은 폴더 3개", joined)

    def test_truncated_walk_without_sweep_says_allocated_axis(self) -> None:
        stats = self.summary["source"]["recovered_root_manifest"]["native_extraction_stats"]
        stats.update({"deleted_files": 0, "deleted_read_errors": 0, "truncated": 12})
        cap = [item["message"] for item in self.limits() if item["reason_id"] == "e01-extract-cap"]
        self.assertEqual(len(cap), 1)
        self.assertIn("할당 영역 축", cap[0])

    def test_ntfs_caps_mft_usn_logfile(self) -> None:
        messages = [item["message"] for item in self.limits() if item["reason_id"] == "ntfs-parse-cap"]
        self.assertEqual(len(messages), 3)
        self.assertIn("$MFT 레코드 분석 상한(5,000건)", messages[0])
        self.assertIn("파일 앞 16 MiB만 읽음", messages[0])
        self.assertIn("USN 저널 레코드 분석 상한(5,000건)", messages[1])
        self.assertIn("$LogFile 9 MiB 중 앞 8 MiB만 훑었습니다", messages[2])

    def _set_counts(self, **counts: int) -> None:
        output = Path(self.summary["outputs"]["artifacts_windows-filesystem"])
        payload = json.loads(output.read_text(encoding="utf-8"))
        payload["summary"]["artifact_type_counts"].update(counts)
        output.write_text(json.dumps(payload), encoding="utf-8")

    def test_read_window_without_the_record_cap_is_worded_as_the_window(self) -> None:
        # Review P2-16: 3,000 $MFT rows from a 20 MiB $MFT never reached the 5,000-record cap.
        self._set_counts(**{"mft-record": 3000, "usn-record": 40})
        _sparse(self.root / "$Extend" / "$UsnJrnl", 40 * MIB)
        messages = [item["message"] for item in self.limits() if item["reason_id"] == "ntfs-parse-cap"]
        mft = next(message for message in messages if message.startswith("$MFT"))
        self.assertIn("$MFT 20 MiB 중 앞 16 MiB만 읽어 3,000건을", mft)
        self.assertIn("레코드 상한 5,000건에는 닿지 않음", mft)
        self.assertNotIn("에 닿아", mft)
        usn = next(message for message in messages if message.startswith("USN"))
        self.assertIn("USN 저널 40 MiB 중 앞 16 MiB만 읽어 40건을 반영했습니다(레코드 상한 5,000건에는 닿지 않음)", usn)
        self.assertNotIn("에 닿아", usn)

    def test_large_usn_and_logfile_with_zero_rows_still_get_an_item(self) -> None:
        # Review P2-16: a large $UsnJrnl / $LogFile that produced 0 rows used to give no item at all.
        self._set_counts(**{"usn-record": 0, "ntfs-logfile-transaction-candidate": 0})
        _sparse(self.root / "$Extend" / "$UsnJrnl", 40 * MIB)
        messages = [item["message"] for item in self.limits() if item["reason_id"] == "ntfs-parse-cap"]
        usn = next(message for message in messages if message.startswith("USN"))
        self.assertIn("USN 저널 40 MiB 중 앞 16 MiB만 읽어 반영한 레코드가 0건입니다", usn)
        self.assertIn("기록이 없다는 뜻이 아님", usn)
        logfile = next(message for message in messages if message.startswith("$LogFile"))
        self.assertIn("$LogFile 9 MiB 중 앞 8 MiB만 훑었습니다(부분). 그 구간에서 찾은 트랜잭션 후보는 0건입니다.", logfile)

    def test_no_ntfs_items_below_the_caps(self) -> None:
        output = Path(self.summary["outputs"]["artifacts_windows-filesystem"])
        payload = json.loads(output.read_text(encoding="utf-8"))
        payload["summary"]["artifact_type_counts"].update({"mft-record": 120, "usn-record": 40})
        output.write_text(json.dumps(payload), encoding="utf-8")
        _sparse(self.root / "$MFT", 1 * MIB)
        _sparse(self.root / "$LogFile", 2 * MIB)
        self.assertEqual([i for i in self.limits() if i["reason_id"] == "ntfs-parse-cap"], [])

    def test_undisclosed_caps_only_for_collectors_that_ran(self) -> None:
        steps = {item["step"] for item in self.limits() if item["reason_id"] == "undisclosed-cap"}
        self.assertEqual(steps, {"artifacts-windows-execution", "artifacts-eventlog"})
        messages = "\n".join(item["message"] for item in self.limits() if item["reason_id"] == "undisclosed-cap")
        self.assertIn("ShimCache 항목 상한 8,192건", messages)
        self.assertIn("ETL 로그 검사 범위(파일당) 상한 4 MiB", messages)

    def test_cap_numbers_come_from_settings_not_fixed_strings(self) -> None:
        stats = self.summary["source"]["recovered_root_manifest"]["native_extraction_stats"]
        stats["file_limit"] = 50
        output = Path(self.summary["outputs"]["artifacts_windows-filesystem"])
        payload = json.loads(output.read_text(encoding="utf-8"))
        payload["summary"]["artifact_type_counts"].update({"mft-record": 50, "usn-record": 50})
        output.write_text(json.dumps(payload), encoding="utf-8")
        with mock.patch.multiple(
            run_problem_limits,
            MFT_RECORD_SCAN_LIMIT=50,
            USN_RECORD_SCAN_LIMIT=50,
            NATIVE_SCAN_LIMIT=50 * MIB,
            NTFS_LOGFILE_SCAN_LIMIT=50,
            E01_WALK_MAX_DEPTH=50,
        ):
            messages = "\n".join(item["message"] for item in self.limits())
        self.assertIn("E01 추출 상한(파일 50개)", messages)
        self.assertIn("$MFT 레코드 분석 상한(50건)", messages)
        self.assertIn("USN 저널 레코드 분석 상한(50건)", messages)
        self.assertIn("중 앞 50바이트만 훑었습니다", messages)
        self.assertIn("폴더 깊이 상한(50단계)", messages)
        for fixed in ("200,000", "5,000건", "8 MiB", "64단계"):
            self.assertNotIn(fixed, messages)

    def test_english_yield_warnings_are_replaced(self) -> None:
        items = self.collect()
        silent = [item["message"] for item in items if item["source"] == "silent_failure"]
        self.assertEqual(
            silent[0],
            "windows-prefetch: 대상 파일 212개가 있으나 수집된 행 0건 — 분석기 오류·원본 경로·이미지 완전성을 확인해야 합니다.",
        )
        self.assertIn("타임라인 이벤트가 0건", silent[1])
        warning = [item for item in items if item["source"] == "warning"][0]
        self.assertEqual(warning["message"], "email: 수집된 행 없음")
        self.assertEqual(warning["reason_id"], "no-rows")
        for message in silent + [warning["message"]]:
            self.assertNotRegex(message, ENGLISH_PHRASE)

    def test_folder_evidence_has_no_engine_items(self) -> None:
        self.summary.pop("source")
        self.summary["outputs"] = {}
        self.summary["steps"] = []
        self.assertEqual(self.limits(), [])

    def test_mirrored_engine_literals_match_the_engine(self) -> None:
        spec = importlib.util.spec_from_file_location("check_collector_caps_t184", REPO / "scripts" / "check-collector-caps.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        caps = {cap["id"]: cap["value"] for cap in module.build_inventory(REPO)["caps"]}
        mft_id = "rapidtriage/artifacts/windows/filesystem.py::parse_mft_record_headers:len>=5000"
        self.assertEqual(caps[mft_id], run_problem_limits.MFT_RECORD_SCAN_LIMIT)
        source = (REPO / "rapidtriage" / "core" / "e01_native.py").read_text(encoding="utf-8")
        depths = re.findall(r"if depth > (\d+):", source)
        self.assertEqual(depths, [str(run_problem_limits.E01_WALK_MAX_DEPTH)])


if __name__ == "__main__":
    unittest.main()
