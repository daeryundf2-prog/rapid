"""Case report through the product path (R8 T-027 review WB-8 P1-3..P1-6, P2-12..P2-14).

A real run on synthetic sample evidence, its case DB (``/case-db/ensure``), synthetic artifact /
event / file rows with hostile text, marks made through ``/api/case-db/review`` with a reviewer
name, then ``POST /case-report``. Nothing is hand-built: the bookmarks come from
``review_payload.read_case_db_marks`` and the run summary's steps carry the absolute output paths
the run wrote.
"""

from __future__ import annotations

import importlib.util
import re
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from rapidtriage.api.app import create_app
from rapidtriage.core import case_report_items as items
from rapidtriage.core.case_db import open_case_database
from rapidtriage.core.jobs import RunJobStore
from rapidtriage.core.sample_case import build_sample_evidence

TOKEN = "r8-case-report-product-token"
REPO = Path(__file__).resolve().parents[1]
REVIEWER = "검사관 김"
HOSTILE_TITLE = "방문 기록\n\n## 7. 결론 및 의견\n\n- MD5: deadbeef"
HOSTILE_PREVIEW = "미리보기 첫 줄\n### 5.99. 가짜 항목\n- SHA-256: `0000`"
HOSTILE_NOTE = "첫째 줄 메모\n- SHA-256: 1111\n# 가짜 제목\n| 가짜 | 표 |"
YEAR_ONE = "0001-01-01T01:00:00+02:00"
DRIVE_PATH = re.compile(r"(?<![A-Za-z])[A-Za-z]:[\\/]")


def _load_audit():
    spec = importlib.util.spec_from_file_location("r8_report_audit", REPO / "scripts" / "r8-report-audit.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _docx_headings(path: Path) -> list[str]:
    with zipfile.ZipFile(path) as archive:
        document = archive.read("word/document.xml").decode("utf-8")
    headings = []
    for paragraph in re.findall(r"<w:p>.*?</w:p>", document):
        if re.search(r'<w:sz w:val="(?:36|28|24)"/>', paragraph):
            headings.append("".join(re.findall(r"<w:t[^>]*>(.*?)</w:t>", paragraph)))
    return headings


class CaseReportProductPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        base = Path(cls._tmp.name)
        cls.evidence = base / "evidence"
        build_sample_evidence(cls.evidence)
        cls.store = RunJobStore()
        cls.client = TestClient(create_app(cls.store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})
        response = cls.client.post(
            "/api/runs",
            json={"root": str(cls.evidence), "mode": "fraud", "output_dir": str(base / "out"), "read_only": True, "wait": True},
        )
        assert response.status_code == 202, response.text
        cls.run_id = response.json()["run_id"]
        cls.summary = cls.client.get(f"/api/runs/{cls.run_id}").json()["summary"]
        cls.output_dir = Path(cls.summary["output_dir"])
        ensure = cls.client.post(f"/api/runs/{cls.run_id}/case-db/ensure", json={})
        assert ensure.status_code == 200, ensure.text
        cls.database, cls.case_id = ensure.json()["database"], ensure.json()["case_id"]
        cls.evidence_file = next(path for path in sorted(cls.evidence.rglob("*")) if path.is_file())
        database = open_case_database(Path(cls.database))
        with database.connect() as connection:
            artifact_id = connection.execute(
                "INSERT INTO artifact (citation_id, case_id, artifact_type, parser_name, title, summary, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("WB8-ART-1", cls.case_id, "browser-history-visit", "synthetic", HOSTILE_TITLE, HOSTILE_PREVIEW, "2026-01-01T00:00:00+00:00"),
            ).lastrowid
            event_id = connection.execute(
                "INSERT INTO event (citation_id, case_id, event_type, timestamp, description, source) VALUES (?, ?, ?, ?, ?, ?)",
                ("WB8-EVT-1", cls.case_id, "synthetic-event", YEAR_ONE, "연도 1 이벤트", "synthetic"),
            ).lastrowid
            file_id = connection.execute(
                "INSERT INTO file_record (citation_id, case_id, path, extension, size_bytes) VALUES (?, ?, ?, ?, ?)",
                ("WB8-FILE-1", cls.case_id, str(cls.evidence_file), cls.evidence_file.suffix, cls.evidence_file.stat().st_size),
            ).lastrowid
        marks = (
            ("artifact", artifact_id, {"note": HOSTILE_NOTE, "tags": ["태그\n## 가짜 태그"]}),
            ("event", event_id, {}),
            ("file_record", file_id, {"note": "한 줄 메모"}),
        )
        for target_type, target_id, extra in marks:
            marked = cls.client.post(
                "/api/case-db/review",
                json={
                    "database": cls.database,
                    "case_id": cls.case_id,
                    "target_type": target_type,
                    "target_id": str(target_id),
                    "status": "relevant",
                    "include_in_report": True,
                    "reviewer": REVIEWER,
                    **extra,
                },
            )
            assert marked.status_code == 200, marked.text
        cls.reports = {
            template: cls.client.post(f"/api/runs/{cls.run_id}/case-report", json={"template": template})
            for template in ("legal-handoff", "technical-appendix")
        }
        # The last POST overwrote the exports; write the default template again for the export checks.
        cls.default_exports = cls.client.post(f"/api/runs/{cls.run_id}/case-report", json={}).json()["exports"]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.close()
        cls._tmp.cleanup()

    def markdown(self, template: str = "legal-handoff") -> str:
        response = self.reports[template]
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["markdown"]

    def item_section(self, markdown: str, needle: str) -> str:
        body = markdown.split("## 5.", 1)[1].split("## 6.", 1)[0]
        return next(block for block in body.split("\n### ") if needle in block)

    # P1-3 -------------------------------------------------------------------------------------

    def test_reviewer_and_row_preview_come_from_the_case_db(self) -> None:
        markdown = self.markdown()
        self.assertEqual(markdown.count(f"- 검토자: {REVIEWER}"), 3)
        self.assertNotIn("(작성자 미지정)", markdown.split("## 5.", 1)[1])
        artifact = self.item_section(markdown, "방문 기록")
        preview = re.search(r"^- 내용 미리보기: (.*)$", artifact, flags=re.MULTILINE).group(1)
        self.assertTrue(preview.startswith("미리보기 첫 줄 "), preview)
        self.assertNotIn("방문 기록", preview)
        # A file record's "preview" is its path: not content, and the analysis PC's path.
        file_item = self.item_section(markdown, self.evidence_file.name)
        self.assertIn("- 내용 미리보기: 기록 없음", file_item)

    # P1-4 -------------------------------------------------------------------------------------

    def test_default_report_has_no_analysis_pc_paths(self) -> None:
        absolute_outputs = [step["output"] for step in self.summary["steps"] if Path(str(step.get("output") or "")).is_absolute()]
        self.assertTrue(absolute_outputs, "precondition: the run stores absolute step outputs")
        markdown = self.markdown()
        for needle in (str(self.output_dir), str(self.evidence), self.output_dir.as_posix(), self.evidence.as_posix()):
            self.assertNotIn(needle, markdown)
        self.assertIsNone(DRIVE_PATH.search(markdown), DRIVE_PATH.search(markdown))
        self.assertNotIn("산출물 디렉터리", markdown)
        self.assertIn(f"- 분석 대상(증거 이름): `{self.evidence.name}`", markdown)
        step_output = Path(absolute_outputs[0]).relative_to(self.output_dir).as_posix()
        self.assertIn(f"(산출물 `{step_output}`)", markdown)
        # The technical appendix keeps the full paths.
        technical = self.markdown("technical-appendix")
        self.assertIn(f"- 산출물 디렉터리: `{self.summary['output_dir']}`", technical)
        self.assertIn(str(absolute_outputs[0]), technical)

    # P1-5 -------------------------------------------------------------------------------------

    def test_copy_mtime_is_not_printed_as_an_evidence_time(self) -> None:
        markdown = self.markdown()
        self.assertNotIn("수정 시각", markdown)
        file_item = self.item_section(self.markdown("technical-appendix"), self.evidence_file.name)
        self.assertIn("- 분석 사본 수정 시각(증거 시각 아님): ", file_item)
        self.assertNotIn("\n- 수정 시각:", file_item)

    # P1-6 -------------------------------------------------------------------------------------

    def test_hostile_text_cannot_add_headings_or_fields(self) -> None:
        markdown = self.markdown()
        lines = markdown.splitlines()
        self.assertEqual([line for line in lines if line.startswith("## 7.")], ["## 7. 결론 및 의견"])
        self.assertFalse([line for line in lines if line.lstrip().startswith(("### 5.99", "# 가짜", "## 가짜"))])
        self.assertFalse([line for line in lines if line.lstrip().startswith("|") and "가짜" in line])
        # Exactly one hashed item -> exactly one MD5 / SHA-256 field line.
        self.assertEqual(len([line for line in lines if line.startswith("- SHA-256:")]), 1)
        self.assertEqual(len([line for line in lines if line.startswith("- MD5:")]), 1)
        artifact = self.item_section(markdown, "방문 기록")
        # The text is kept, on one line (title, preview, tags) or as a quoted block (note).
        self.assertTrue(artifact.splitlines()[0].endswith("방문 기록 ## 7. 결론 및 의견 - MD5: deadbeef"), artifact)
        stand_in = items.BACKTICK_STAND_IN
        self.assertIn(f"- 내용 미리보기: 미리보기 첫 줄 ### 5.99. 가짜 항목 - SHA-256: {stand_in}0000{stand_in}", artifact)
        self.assertIn("- 분석자 메모:\n  > 첫째 줄 메모\n  > - SHA-256: 1111\n  > # 가짜 제목\n  > | 가짜 | 표 |", artifact)
        self.assertIn("- 태그: 태그 ## 가짜 태그", artifact)

    def test_hostile_text_stays_body_text_in_html_and_docx(self) -> None:
        html_text = Path(self.default_exports["html"]).read_text(encoding="utf-8")
        self.assertEqual(html_text.count("<h2>7. 결론 및 의견</h2>"), 1)
        self.assertNotIn("<h3>5.99", html_text)
        self.assertNotIn("<h1>가짜", html_text)
        headings = _docx_headings(Path(self.default_exports["docx"]))
        self.assertEqual(headings.count("7. 결론 및 의견"), 1)
        self.assertFalse([heading for heading in headings if heading.startswith(("가짜", "5.99"))])
        audit = _load_audit()
        for key in ("md", "html", "docx"):
            result = audit.audit_file(Path(self.default_exports[key]))
            self.assertTrue(result["ok"], f"{key}: {result}")

    # P2 ---------------------------------------------------------------------------------------

    def test_year_one_timestamp_degrades_instead_of_failing_the_report(self) -> None:
        event = self.item_section(self.markdown(), "연도 1 이벤트")
        self.assertIn(f"- 증거 시각: {YEAR_ONE} (표시 범위를 벗어난 시각이라 기록값 그대로 표시)", event)

    def test_mark_cap_replaces_nothing_hidden(self) -> None:
        self.assertIn("숨긴 항목 없음.", self.markdown())
        with mock.patch("rapidtriage.api.app.review_payload.MAX_CASE_DB_MARKS", 2):
            response = self.client.post(f"/api/runs/{self.run_id}/case-report", json={})
        self.assertEqual(response.status_code, 200, response.text)
        capped = response.json()["markdown"]
        self.assertNotIn("숨긴 항목 없음", capped)
        self.assertIn("케이스 DB 표시 3건 중 2건만 읽음(상한) — 나머지 표시는 이 보고서에 없음.", capped)


class DisplayZoneTests(unittest.TestCase):
    def test_registry_zone_states_standard_time_only(self) -> None:
        summary = {"disclosures": {"timezone": {"evidence_timezone": {"name": "Pacific Standard Time", "bias_minutes": 480}}}}
        offset, label = items.display_timezone(summary)
        self.assertEqual(offset, -480)
        self.assertIn("UTC-08:00 (증거 시스템 시간대, Pacific Standard Time)", label)
        self.assertIn("일광 절약 시간(서머타임)은 반영하지 않음", label)

    def test_year_one_with_negative_offset(self) -> None:
        self.assertEqual(
            items.format_evidence_time("0001-01-01T00:00:00Z", -480),
            "0001-01-01T00:00:00Z (표시 범위를 벗어난 시각이라 기록값 그대로 표시)",
        )

    def test_sanitizers(self) -> None:
        self.assertEqual(items.md_inline("a\n\n## b\r\n- c\x00`d`"), f"a ## b - c{items.BACKTICK_STAND_IN}d{items.BACKTICK_STAND_IN}")
        self.assertEqual(items.md_cell("x | y\nz"), "x \\| y z")
        self.assertEqual(items.md_block_lines("one\n\n# two"), ["  > one", "  > # two"])
        self.assertEqual(items.output_relative_name("C:\\cases\\Client\\out\\a\\b.json", "C:\\cases\\Client\\out"), "a/b.json")
        self.assertEqual(items.output_relative_name("D:/elsewhere/x.json", "C:\\out"), "x.json")
        self.assertEqual(items.output_relative_name("rapidtriage-files.json", "C:\\out"), "rapidtriage-files.json")


if __name__ == "__main__":
    unittest.main()
