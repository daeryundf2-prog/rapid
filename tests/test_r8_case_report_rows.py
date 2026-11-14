"""Case report: Korean only, defensive fields, row info for files and artifact rows (R8 T-027).

Acceptance fixture: 12 report marks (6 files + 6 artifact rows) -> all 12 in section 5, each with
its evidence time (display time zone + UTC), preview, path inside the evidence and source location.
"""

from __future__ import annotations

import importlib.util
import re
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

from rapidtriage import PRODUCT_NAME, __version__
from rapidtriage.api.app.run_scope import build_run_scope
from rapidtriage.api.app.run_steps_summary import summarize_steps
from rapidtriage.core.case_report import (
    build_case_report_markdown,
    render_case_report_html,
    write_case_report_exports,
)
from rapidtriage.core.submission import (
    build_submission_manifest,
    evidence_relative_roots,
)

REPO = Path(__file__).resolve().parents[1]
AUDIT_SCRIPT = REPO / "scripts" / "r8-report-audit.py"
#: ASCII words allowed in headings and field labels (proper nouns, hash algorithm names).
ALLOWED_ASCII = {"RapidTriage", "Windows", "SHA", "MD5"}


def _load_audit():
    spec = importlib.util.spec_from_file_location("r8_report_audit", AUDIT_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def file_mark(index: int, path: Path) -> dict[str, Any]:
    return {
        "bookmark_id": f"file-{index}",
        "summary": f"문서 파일 {index}",
        "tags": ["유출"],
        "note": f"파일 메모 {index}",
        "review": {"status": "relevant", "include_in_report": True, "reviewer": "web-ui"},
        "reference": {"command": "files", "pointer": f"/candidates/{index}"},
        "snapshot": {"path": str(path), "timestamp": f"2025-05-29T14:2{index}:00Z", "summary": f"파일 미리보기 {index}"},
    }


def artifact_mark(index: int, source: Path | None) -> dict[str, Any]:
    return {
        "bookmark_id": f"row-{index}",
        "summary": f"USB 연결 {index}",
        "tags": [],
        "note": "",
        "review": {"status": "needs-review", "include_in_report": True},
        "reference": {
            "source_command": "case-db",
            "citation_id": f"cit-{index}",
            "target_type": "artifact",
            "target_id": str(100 + index),
            "collection": "windows-registry",
            "kind": "usb-device",
            "locator": f"SYSTEM\\USBSTOR\\Disk&Ven_{index}",
        },
        "snapshot": {
            "path": str(source) if source else "",
            "timestamp": f"2025-05-30T01:0{index}:00+00:00",
            "summary": f"USB 저장 장치 일련번호 SN-{index}",
        },
    }


class CaseReportRowsTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name)
        self.root = base / "evidence"
        (self.root / "Users" / "kim" / "Documents").mkdir(parents=True)
        (self.root / "Windows" / "System32" / "config").mkdir(parents=True)
        files = []
        for index in range(1, 7):
            path = self.root / "Users" / "kim" / "Documents" / f"report-{index}.txt"
            path.write_text(f"synthetic text {index}\n", encoding="utf-8")
            files.append(path)
        hive = self.root / "Windows" / "System32" / "config" / "SYSTEM"
        hive.write_bytes(b"regf" + bytes(60))
        # 6 files + 6 artifact rows (three cite the hive, three carry no path).
        bookmarks = [file_mark(i, path) for i, path in enumerate(files, start=1)]
        bookmarks += [artifact_mark(i, hive if i <= 3 else None) for i in range(1, 7)]
        bookmarks.append({"bookmark_id": "not-in-report", "summary": "보고서 제외 표시", "review": {"include_in_report": False}})
        self.case_payload = {"case_id": "CASE-27", "bookmarks": bookmarks, "summary": {"bookmark_count": 13, "report_item_count": 12}}
        self.output_dir = base / "run"
        self.output_dir.mkdir()
        self.summary: dict[str, Any] = {
            "mode": "seizure",
            "root": str(self.root),
            "scan_scope_root": str(self.root),
            "output_dir": str(self.output_dir),
            "disclosures": {"timezone": {"evidence_timezone": {"name": "Korea Standard Time", "bias_minutes": -540}}},
            "steps": [
                {"name": "files", "status": "completed", "output": "rapidtriage-files.json"},
                {"name": "artifacts-windows-registry", "status": "failed_isolated"},
                {"name": "triage-flags", "status": "completed", "catalog_version": "2026.11.1"},
            ],
            "source": {
                "partition_selection": {"selected_start_sector": 2048, "partition_count": 2, "supported_partition_count": 1},
                "recovered_root_manifest": {
                    "native_extraction_stats": {
                        "files": 50, "errors": 3, "truncated": 40, "deleted_files": 10,
                        "deleted_read_errors": 1, "file_limit": 50,
                    }
                },
            },
        }
        self.manifest = build_submission_manifest(
            self.case_payload, allowed_roots=[self.root], evidence_roots=evidence_relative_roots(self.summary)
        )
        self.context = {"scope": build_run_scope(self.summary, self.output_dir), "steps": summarize_steps(self.summary)}

    def report(self, template: str = "legal-handoff", **kwargs: Any) -> str:
        return build_case_report_markdown(
            run_summary=self.summary,
            case_payload=self.case_payload,
            submission_manifest=self.manifest,
            metadata={"template": template, "title": "사건 27"},
            report_context=kwargs.get("context", self.context),
        )

    def section(self, markdown: str, start: str, end: str) -> str:
        return markdown.split(start, 1)[1].split(end, 1)[0]

    def test_all_twelve_marks_are_in_section_five(self) -> None:
        markdown = self.report()
        body = self.section(markdown, "## 5.", "## 6.")
        self.assertEqual(len(re.findall(r"^### 5\.\d+\. ", body, flags=re.MULTILINE)), 12)
        for index in range(1, 7):
            self.assertIn(f"### 5.{index}. 문서 파일 {index}", body)
            self.assertIn(f"USB 연결 {index}", body)
        self.assertNotIn("보고서 제외 표시", body)
        self.assertEqual(body.count("- 구분: 파일"), 6)
        self.assertEqual(body.count("- 구분: 아티팩트 행"), 6)

    def test_each_item_carries_row_info(self) -> None:
        body = self.section(self.report(), "## 5.", "## 6.")
        # Display time zone (evidence system, offset = -Bias) and UTC side by side.
        self.assertIn("- 증거 시각: 2025-05-29 23:21:00 (UTC+09:00) · UTC 2025-05-29 14:21:00", body)
        self.assertIn("- 증거 시각: 2025-05-30 10:06:00 (UTC+09:00) · UTC 2025-05-30 01:06:00", body)
        self.assertIn("- 내용 미리보기: 파일 미리보기 3", body)
        self.assertIn("- 내용 미리보기: USB 저장 장치 일련번호 SN-6", body)
        self.assertIn("- 증거 안 경로: `Users/kim/Documents/report-2.txt`", body)
        self.assertIn("- 증거 안 경로: `Windows/System32/config/SYSTEM`", body)
        self.assertIn("- 증거 안 경로: 경로 없음(아티팩트 행)", body)
        self.assertIn("수집 원천 `windows-registry` · 유형 `usb-device` · 위치 `SYSTEM\\USBSTOR\\Disk&Ven_4` · 인용 ID `cit-4`", body)
        # The analysis PC's copy path is technical information, not the item body.
        self.assertNotIn(str(self.root), body)
        self.assertIn("- 검토자: (작성자 미지정)", body)
        self.assertIn("- 판단: 추가 검토 필요", body)

    def test_skip_reasons_are_korean(self) -> None:
        markdown = self.report()
        self.assertIn("- 해시: 산출하지 않음 — 원본 파일 경로가 없어 해시할 수 없습니다", markdown)
        skipped = self.section(markdown, "## 6.", "## 7.")
        self.assertIn("USB 연결 5: 원본 파일 경로가 없어 해시할 수 없습니다", skipped)
        self.assertNotIn("no-source-path", markdown)

    def test_defensive_fields_and_four_axis_scope(self) -> None:
        markdown = self.report()
        self.assertIn(f"- 도구 버전: {PRODUCT_NAME} {__version__}", markdown)
        self.assertIn("- 규칙·분류 카탈로그 버전: 특이사항: `2026.11.1`", markdown)
        self.assertNotIn("triage-flags", markdown)
        self.assertIn("- 표시 시간대: UTC+09:00 (증거 시스템 시간대, Korea Standard Time)", markdown)
        self.assertIn("- 부분 단계: 아티팩트 수집: 레지스트리", markdown)
        self.assertIn("- 처리 범위(추정): 파티션 2개 중 지원 파일시스템 1개, 처리 1개 · 할당 파일 목록화 100%", markdown)
        self.assertIn("비할당 영역은 측정하지 않음", markdown)
        self.assertIn("추출 상한(50개)", markdown)
        self.assertIn("- 적용 조건: 보고서 포함으로 표시한 항목, 해시 산출 최대 500건", markdown)

    def test_without_context_says_not_recorded(self) -> None:
        markdown = self.report(context=None)
        self.assertIn("- 처리 범위: 기록 없음", markdown)
        self.assertIn("- 실패·부분 단계: 기록 없음", markdown)

    def test_default_display_zone_when_evidence_zone_unknown(self) -> None:
        self.summary.pop("disclosures")
        body = self.section(self.report(), "## 5.", "## 6.")
        self.assertIn("2025-05-29 23:21:00 (UTC+09:00) · UTC 2025-05-29 14:21:00", body)
        self.assertIn("기본값 사용", self.report())

    def test_no_english_in_titles_or_labels(self) -> None:
        for template in ("legal-handoff", "executive-summary", "technical-appendix", "hash-only"):
            markdown = self.report(template)
            in_skip_list = False
            for line in markdown.splitlines():
                if line.startswith("## "):
                    in_skip_list = "해시 산출 제외" in line
                if re.match(r"^### [25]\.\d+\. ", line) or (in_skip_list and line.startswith("- ")):
                    continue  # item titles / skip lines start with the analyst's own text
                if line.startswith("#"):
                    label = line
                elif re.match(r"^\s*- [^`:]+:", line) or line.startswith(">"):
                    label = line.split(":", 1)[0]
                else:
                    continue
                label = re.sub(r"`[^`]*`", "", label)
                words = set(re.findall(r"[A-Za-z]{3,}", label)) - ALLOWED_ASCII
                self.assertFalse(words, f"{template}: {line}")
            self.assertNotIn("status=", markdown)
            self.assertNotIn("SHA256", markdown)

    def test_html_docx_titles_are_korean_and_audit_passes(self) -> None:
        markdown = self.report()
        self.assertIn("<title>디지털 포렌식 분석 보고서</title>", render_case_report_html(markdown))
        self.assertNotIn("Case Report", render_case_report_html(markdown))
        exports = write_case_report_exports(markdown, self.output_dir / "rapidtriage-case-report.md")
        audit = _load_audit()
        for key in ("md", "html", "docx"):
            result = audit.audit_file(Path(exports[key]))
            self.assertTrue(result["ok"], f"{key}: {result}")

    def test_hash_only_uses_evidence_relative_paths(self) -> None:
        markdown = self.report("hash-only")
        self.assertIn("- 증거 안 경로: `Users/kim/Documents/report-1.txt`", markdown)
        self.assertIn("- SHA-256: `", markdown)
        self.assertNotIn(str(self.root), markdown)


if __name__ == "__main__":
    unittest.main()
