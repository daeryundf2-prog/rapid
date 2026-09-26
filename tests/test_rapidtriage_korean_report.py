"""R4-3: Korean expert-opinion (감정서) report template tests."""

from __future__ import annotations

import unittest

from rapidtriage.core.case_report import (
    build_case_report_markdown,
    template_noise_policy,
)
from rapidtriage.core.korean_report import build_korean_expert_report


def _run_summary() -> dict[str, object]:
    return {
        "root": "D:/evidence/BSH.E01",
        "mode": "image",
        "output_dir": "D:/work/run-001",
        "steps": [
            {"name": "intake", "status": "completed", "output": "stage/intake.json"},
            {"name": "parse", "status": "completed", "output": "stage/parse.json"},
        ],
        "validation": {"commercial_grade_ready": False, "validation_required": True},
    }


def _case_payload() -> dict[str, object]:
    return {
        "case_id": "2026고합123",
        "title": "피의자 PC 압수물 감정",
        "bookmarks": [
            {
                "bookmark_id": "b1",
                "summary": "삭제된 문서 복구",
                "reference": {"command": "artifact"},
                "review": {"status": "confirmed", "include_in_report": True},
                "tags": ["삭제복구"],
                "note": "사건 연관 문서",
            },
            {
                "bookmark_id": "b2",
                "summary": "무관한 캐시 파일",
                "reference": {"command": "artifact"},
                "review": {"status": "reviewed", "include_in_report": False},
                "tags": [],
                "note": "",
            },
        ],
        "summary": {"bookmark_count": 2, "report_item_count": 1},
    }


def _manifest() -> dict[str, object]:
    return {
        "generated_at": "2026-09-26T00:00:00+00:00",
        "summary": {"hashed_item_count": 1, "skipped_count": 0},
        "items": [
            {"path": "evidence/image.e01", "sha256": "ab" * 32},
        ],
    }


class KoreanExpertReportTests(unittest.TestCase):
    def test_template_dispatch_produces_expert_report(self) -> None:
        markdown = build_case_report_markdown(
            run_summary=_run_summary(),
            case_payload=_case_payload(),
            submission_manifest=_manifest(),
            metadata={"template": "korean-expert"},
        )
        for section in (
            "# 감 정 서",
            "## 1. 감정의 취지",
            "## 2. 감정물의 내역 및 인계·인수",
            "## 3. 감정 방법 및 사용 도구",
            "## 4. 감정 결과",
            "## 5. 법적 검토 대조표",
            "## 6. 제한사항",
            "## 7. 결론",
            "## 부록. 증거 해시 목록",
        ):
            self.assertIn(section, markdown, section)

    def test_metadata_fields_rendered(self) -> None:
        markdown = build_korean_expert_report(
            run_summary=_run_summary(),
            case_payload=_case_payload(),
            submission_manifest=_manifest(),
            metadata={
                "case_number": "2026고합999",
                "investigator": "홍길동",
                "organization": "국립과학수사연구원",
                "requester": "서울중앙지방법원",
                "scope": "삭제 파일 복구 여부 감정",
                "conclusion": "복구된 문서가 확인됨.",
            },
        )
        self.assertIn("사건번호: 2026고합999", markdown)
        self.assertIn("감정인: 홍길동", markdown)
        self.assertIn("감정기관: 국립과학수사연구원", markdown)
        self.assertIn("의뢰기관: 서울중앙지방법원", markdown)
        self.assertIn("삭제 파일 복구 여부 감정", markdown)
        self.assertIn("복구된 문서가 확인됨.", markdown)

    def test_draft_notice_and_validation_flags(self) -> None:
        markdown = build_korean_expert_report(
            run_summary=_run_summary(),
            case_payload=_case_payload(),
            submission_manifest=_manifest(),
            metadata={},
        )
        self.assertIn("초안", markdown)
        self.assertIn("commercial_grade_ready=False", markdown)
        self.assertIn("validation_required=True", markdown)

    def test_only_report_included_bookmarks_listed(self) -> None:
        markdown = build_korean_expert_report(
            run_summary=_run_summary(),
            case_payload=_case_payload(),
            submission_manifest=_manifest(),
            metadata={},
        )
        self.assertIn("삭제된 문서 복구", markdown)
        self.assertIn("삭제복구", markdown)
        self.assertNotIn("무관한 캐시 파일", markdown)

    def test_manifest_hash_rows_in_appendix(self) -> None:
        markdown = build_korean_expert_report(
            run_summary=_run_summary(),
            case_payload=_case_payload(),
            submission_manifest=_manifest(),
            metadata={},
        )
        self.assertIn("`evidence/image.e01`", markdown)
        self.assertIn("`" + "ab" * 32 + "`", markdown)

    def test_noise_policy_describes_template(self) -> None:
        self.assertIn("감정서", template_noise_policy("korean-expert"))

    def test_other_templates_unchanged(self) -> None:
        markdown = build_case_report_markdown(
            run_summary=_run_summary(),
            case_payload=_case_payload(),
            submission_manifest=_manifest(),
            metadata={"template": "legal-handoff"},
        )
        self.assertIn("# 디지털 포렌식 분석 보고서", markdown)
        self.assertNotIn("# 감 정 서", markdown)


if __name__ == "__main__":
    unittest.main()
