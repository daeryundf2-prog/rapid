"""R4-3 / R8 T-026: Korean expert-opinion (감정서) report template tests (synthetic data)."""

from __future__ import annotations

import re
import unittest

from rapidtriage import __version__
from rapidtriage.core.case_report import (
    build_case_report_markdown,
    template_noise_policy,
)
from rapidtriage.core.case_report_items import BACKTICK_STAND_IN
from rapidtriage.core.korean_report import (
    EVIDENCE_HASH_NOT_RECORDED,
    build_korean_expert_report,
)

DRIVE_PATH = re.compile(r"(?<![A-Za-z])[A-Za-z]:[\\/]")
SEGMENT_SHA = ("11" * 32, "22" * 32)
ITEM_SHA = "ab" * 32


def _run_summary() -> dict[str, object]:
    return {
        "root": "D:/evidence/BSH.E01",
        "mode": "fraud",
        "output_dir": "D:/work/Client-Kim/run-001",
        "steps": [
            {"name": "manifest", "status": "completed", "output": "D:/work/Client-Kim/run-001/stage/intake.json"},
            {"name": "artifacts-browser", "status": "failed", "output": "stage/browser.json"},
            {"name": "custom-step", "status": "completed", "output": ""},
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
                "review": {"status": "relevant", "include_in_report": True},
                "tags": ["삭제복구"],
                "note": "사건 연관 문서",
            },
            {
                "bookmark_id": "b2",
                "summary": "무관한 캐시 파일",
                "reference": {"command": "artifact"},
                "review": {"status": "not-relevant", "include_in_report": False},
                "tags": [],
                "note": "",
            },
            {
                "bookmark_id": "b3",
                "summary": "아직 보지 않은 항목",
                "review": {"status": "unreviewed"},
            },
        ],
        "summary": {"bookmark_count": 3, "report_item_count": 1},
    }


def _manifest() -> dict[str, object]:
    return {
        "generated_at": "2026-09-26T00:00:00+00:00",
        "summary": {"hashed_item_count": 1, "skipped_count": 0},
        "items": [
            {
                "bookmark_id": "b1",
                "evidence": {
                    "path": "D:/evidence/BSH.E01/Users/kim/doc.docx",
                    "relative_path": "Users/kim/doc.docx",
                    "name": "doc.docx",
                    "hashes": {"md5": "cd" * 16, "sha256": ITEM_SHA},
                },
            }
        ],
        "skipped": [],
    }


def _e01_record() -> dict[str, object]:
    return {
        "evidence_number": "E-01",
        "citation_id": "EV-1",
        "display_name": "disk.E01",
        "path": "D:/evidence/disk.E01",
        "size_bytes": 2048,
        "hash_status": "computed",
        "hashes": {"sha256": "99" * 32},
        "hash_scope": "ewf-container-segment-bytes",
        "segments": [
            {"name": "disk.E01", "segment_number": 1, "size_bytes": 1024, "sha256": SEGMENT_SHA[0]},
            {"name": "disk.E02", "segment_number": 2, "size_bytes": 1024, "sha256": SEGMENT_SHA[1]},
        ],
        "recorded_acquisition_hash": {"md5": "aa" * 16, "sha1": "bb" * 20, "reason": ""},
    }


def _report(**metadata: object) -> str:
    return build_korean_expert_report(
        run_summary=_run_summary(),
        case_payload=_case_payload(),
        submission_manifest=_manifest(),
        metadata=metadata,
    )


def _section(markdown: str, start: str, end: str) -> str:
    return markdown.split(start, 1)[1].split(end, 1)[0]


def _table_cells(block: str) -> list[str]:
    cells: list[str] = []
    for line in block.splitlines():
        if line.startswith("|") and not line.startswith("|---"):
            cells += [cell.strip() for cell in line.strip("|").split(" | ")]
    return cells


class KoreanExpertReportTests(unittest.TestCase):
    def test_template_dispatch_produces_expert_report(self) -> None:
        markdown = build_case_report_markdown(
            run_summary=_run_summary(),
            case_payload=_case_payload(),
            submission_manifest=_manifest(),
            metadata={"template": "korean-expert"},
            report_context={"steps": {"total": 2, "completed": 2, "failed_names": [], "partial_names": []}},
        )
        for section in (
            "# 감 정 서",
            "## 1. 감정의 취지",
            "## 2. 감정물의 내역 및 인계·인수",
            "### 2.1 감정 대상 증거",
            "### 2.2 제출 항목(보고서 포함 파일의 분석 사본)",
            "## 3. 감정 방법 및 사용 도구",
            "## 4. 감정 결과",
            "## 5. 법적 검토 대조표",
            "## 6. 제한사항",
            "## 7. 결론",
            "## 부록. 제출 항목 해시 목록",
        ):
            self.assertIn(section, markdown, section)
        self.assertIn("- 처리 단계: 전체 2 · 완료 2", markdown)  # report_context reaches the template

    def test_metadata_fields_rendered(self) -> None:
        markdown = _report(
            case_number="2026고합999",
            investigator="홍길동",
            organization="국립과학수사연구원",
            requester="서울중앙지방법원",
            scope="삭제 파일 복구 여부 감정",
            conclusion="복구된 문서가 확인됨.",
        )
        self.assertIn("사건번호: 2026고합999", markdown)
        self.assertIn("감정인: 홍길동", markdown)
        self.assertIn("감정기관: 국립과학수사연구원", markdown)
        self.assertIn("의뢰기관: 서울중앙지방법원", markdown)
        self.assertIn("> 삭제 파일 복구 여부 감정", markdown)
        self.assertIn("> 복구된 문서가 확인됨.", markdown)

    def test_validation_state_is_korean(self) -> None:
        markdown = _report()
        self.assertIn("초안", markdown)
        self.assertIn("- 검증 상태: 상용 수준 검증 완료 아니오, 추가 검증 필요 예", markdown)
        for token in ("commercial_grade_ready", "validation_required", "output=", "max-items", "status="):
            self.assertNotIn(token, markdown)
        self.assertIn("- 분석 모드: 문서·부정 조사", markdown)

    def test_only_report_included_bookmarks_listed(self) -> None:
        markdown = _report()
        self.assertIn("| 삭제된 문서 복구 | 아티팩트 | 관련 있음 | (작성자 미지정) | 삭제복구 | 사건 연관 문서 |", markdown)
        self.assertNotIn("무관한 캐시 파일", markdown)

    # T-026 ① two tables ------------------------------------------------------------------------

    def test_without_evidence_records_one_not_recorded_line(self) -> None:
        markdown = _report()
        evidence = _section(markdown, "### 2.1 감정 대상 증거", "### 2.2")
        self.assertEqual(evidence.strip(), f"- {EVIDENCE_HASH_NOT_RECORDED}")

    def test_evidence_records_list_segments_and_recorded_hash(self) -> None:
        markdown = _report(evidence_records=[_e01_record()])
        evidence = _section(markdown, "### 2.1 감정 대상 증거", "### 2.2")
        self.assertIn(f"| E-01 | `disk.E01` | 1,024 바이트 | `{SEGMENT_SHA[0]}` |", evidence)
        self.assertIn(f"| E-01 | `disk.E02` | 1,024 바이트 | `{SEGMENT_SHA[1]}` |", evidence)
        self.assertIn("- E-01 해시 대상: E01 컨테이너 세그먼트 파일의 바이트(디스크 매체 내용의 해시가 아님)", evidence)
        self.assertIn(f"- E-01 기록된 취득 해시: MD5 `{'aa' * 16}`, SHA-1 `{'bb' * 20}`", evidence)
        self.assertNotIn(EVIDENCE_HASH_NOT_RECORDED, evidence)
        # The submission item's hash is in the other table only.
        self.assertNotIn(ITEM_SHA, evidence)
        submitted = _section(markdown, "### 2.2", "## 3.")
        self.assertIn(f"| 1 | `Users/kim/doc.docx` | `{ITEM_SHA}` |", submitted)
        self.assertNotIn(SEGMENT_SHA[0], submitted)

    def test_incomplete_segment_set_is_never_plain_computed(self) -> None:
        """Review WB-10/11 P1-4: the incomplete-set facts the server computes reach section 2.1."""
        record = {**_e01_record(), "segment_set_incomplete": True, "segment_count": 2, "segment_gaps": [3, 5],
                  "hash_message": "세그먼트 집합 불완전 — 컨테이너 해시는 있는 세그먼트만"}
        evidence = _section(_report(evidence_records=[record]), "### 2.1 감정 대상 증거", "### 2.2")
        self.assertIn(
            "- E-01 해시 결과: 세그먼트 집합 불완전 — 있는 세그먼트 2개만 해시함(컨테이너 전체의 해시 아님), "
            "빠진 세그먼트 번호 3, 5",
            evidence,
        )
        self.assertNotIn("해시 결과: 계산 완료", evidence)
        self.assertIn("- E-01 세그먼트 수: 2개", evidence)
        self.assertIn("- E-01 해시 처리 메시지: 세그먼트 집합 불완전 — 컨테이너 해시는 있는 세그먼트만", evidence)
        no_gap = {**record, "segment_gaps": []}
        evidence = _section(_report(evidence_records=[no_gap]), "### 2.1 감정 대상 증거", "### 2.2")
        self.assertIn("마지막 세그먼트 없음 또는 번호 미상", evidence)

    def test_recorded_compare_and_container_hash_are_printed(self) -> None:
        for compare, text in (
            ("equals", "입력한 기대 해시가 이미지에 기록된 취득 해시와 같음"),
            ("differs", "입력한 기대 해시가 이미지에 기록된 취득 해시와 다름 — 취득 기록·이미지 확인 필요"),
            ("not-comparable", "이미지에 같은 종류의 취득 해시가 없어 비교하지 못함"),
        ):
            record = {**_e01_record(), "hash_status": "matched", "recorded_compare": compare}
            evidence = _section(_report(evidence_records=[record]), "### 2.1 감정 대상 증거", "### 2.2")
            self.assertIn(f"- E-01 기록된 취득 해시 대조: {text}", evidence)
        self.assertIn(f"- E-01 컨테이너 SHA-256(세그먼트 파일을 순서대로 이은 바이트): `{'99' * 32}`", evidence)
        self.assertIn("- E-01 해시 결과: 계산 완료 — 입력한 기대 해시와 일치", evidence)

    def test_many_segments_table_is_bounded(self) -> None:
        segments = [
            {"name": f"disk.E{index:02d}", "segment_number": index, "size_bytes": 10, "sha256": f"{index:064x}"}
            for index in range(1, 61)
        ]
        record = {**_e01_record(), "segments": segments, "segment_count": 60}
        evidence = _section(_report(evidence_records=[record]), "### 2.1 감정 대상 증거", "### 2.2")
        self.assertEqual(len([line for line in evidence.splitlines() if line.startswith("| E-01 |")]), 20)
        self.assertIn("- E-01 세그먼트 수: 60개 (표에는 앞 20개만 적음)", evidence)

    def test_no_raw_identifiers_in_body(self) -> None:
        """Acceptance ⑥: no English id tokens outside code spans anywhere in the 감정서."""
        summary = {
            **_run_summary(),
            "steps": [
                *_run_summary()["steps"],
                {"name": "triage-flags", "status": "completed", "catalog_version": "2026.11.1"},
                {"name": "artifacts-ai-agent", "status": "completed", "catalog_version": "ai-catalog-3"},
            ],
        }
        case = _case_payload()
        case["bookmarks"][0]["reference"] = {"command": "artifacts"}
        case["bookmarks"].append({"bookmark_id": "b4", "summary": "USB 기록", "source": "artifacts_windows-registry",
                                  "review": {"status": "relevant", "include_in_report": True}})
        record = {**_e01_record(), "hash_scope": "some-new-scope", "segment_set_incomplete": True,
                  "segment_gaps": [2], "recorded_compare": "not-comparable"}
        markdown = build_korean_expert_report(
            run_summary=summary, case_payload=case, submission_manifest=_manifest(),
            metadata={"evidence_records": [record]},
        )
        body = re.sub(r"`[^`\n]*`", "", markdown)
        self.assertEqual(re.findall(r"[a-z]+(?:[-_][a-z]+)+", body), [])
        self.assertIn("- 규칙·분류 카탈로그 버전: 특이사항: `2026.11.1`", markdown)
        self.assertIn("| USB 기록 | 아티팩트: ", markdown)

    def test_single_file_record_and_unhashed_records(self) -> None:
        single = {**_e01_record(), "evidence_number": "E-02", "display_name": "usb.dd", "segments": [],
                  "hash_scope": "file-bytes", "recorded_acquisition_hash": None, "size_bytes": 4096}
        unhashed = {**_e01_record(), "evidence_number": "E-03", "display_name": "phone.zip",
                    "hash_status": "not-requested", "hashes": {}, "segments": []}
        folder = {**unhashed, "evidence_number": "E-04", "display_name": "share", "hash_status": "not-applicable",
                  "hash_message": "폴더 증거는 해시를 계산하지 않습니다"}
        markdown = _report(evidence_records=[single, unhashed, folder])
        evidence = _section(markdown, "### 2.1 감정 대상 증거", "### 2.2")
        self.assertIn(f"| E-02 | `usb.dd` | 4,096 바이트 | `{'99' * 32}` |", evidence)
        self.assertIn("- E-02 해시 대상: 증거 파일의 바이트", evidence)
        self.assertIn("- E-02 기록된 취득 해시: 증거 파일에 기록된 취득 해시 없음", evidence)
        self.assertIn(f"- E-03 `phone.zip`: {EVIDENCE_HASH_NOT_RECORDED}", evidence)
        self.assertIn("- E-04 `share`: 폴더 증거는 해시를 계산하지 않습니다", evidence)

    def test_value_cells_never_say_not_entered(self) -> None:
        markdown = _report(evidence_records=[_e01_record()])
        tables = _section(markdown, "## 2.", "## 3.") + _section(markdown, "### 4.1", "## 5.")
        cells = _table_cells(tables)
        self.assertTrue(cells)
        self.assertFalse([cell for cell in cells if cell in {"-", "미기재", "`-`", "`미기재`"}], cells)

    def test_item_outside_evidence_root_is_named_not_pathed(self) -> None:
        manifest = _manifest()
        manifest["items"][0]["evidence"].update(relative_path="", path="D:/work/Client-Kim/run-001/carved/x.bin", name="x.bin")
        markdown = build_korean_expert_report(
            run_summary=_run_summary(), case_payload=_case_payload(), submission_manifest=manifest, metadata={}
        )
        self.assertIn("| 1 | `x.bin` (분석 결과 폴더의 파일 — 증거 안 경로 없음) |", markdown)
        self.assertIn(f"1. `x.bin` (분석 결과 폴더의 파일 — 증거 안 경로 없음) — SHA-256 `{ITEM_SHA}`", markdown)

    # T-026 ② hand-over vs hash time ------------------------------------------------------------

    def test_hand_over_time_only_from_metadata(self) -> None:
        markdown = _report()
        self.assertIn("- 인계 인수 시각: 미기재", markdown)
        self.assertIn("- 제출 항목 해시 산출 시각: 2026-09-26 09:00:00 (UTC+09:00) · UTC 2026-09-26 00:00:00", markdown)
        self.assertNotIn("매니페스트 생성", markdown)
        received = _report(received_at="2026-09-20 14:00 인수(봉인 확인)")
        self.assertIn("- 인계 인수 시각: 2026-09-20 14:00 인수(봉인 확인)", received)

    # T-026 ③ tool version ④ reviewed count ⑤ wording ------------------------------------------

    def test_tool_version_and_reviewed_count(self) -> None:
        markdown = _report(tool_version="9.9.9-test")
        self.assertIn("- 도구 버전: 9.9.9-test", markdown)
        self.assertIn(f"- 도구 버전: {__version__}", _report())
        self.assertIn("- 검토 완료 항목 수(미검토 제외): 2", markdown)
        self.assertIn("- 전체 표시 항목 수: 3", markdown)

    def test_no_read_only_assertion(self) -> None:
        markdown = _report()
        self.assertNotIn("읽기 전용으로 처리하였으며", markdown)
        self.assertIn("분석은 추출 사본에 대해 수행하였다. 처리 전후 원본 상태 기록: 미기록", markdown)
        recorded = _report(source_state_record="처리 전후 SHA-256 동일(기록지 3쪽)")
        self.assertIn("처리 전후 원본 상태 기록: 처리 전후 SHA-256 동일(기록지 3쪽)", recorded)

    # WB-8 follow-up: no analysis-PC paths, sanitised text --------------------------------------

    def test_no_analysis_pc_paths(self) -> None:
        markdown = _report(evidence_records=[_e01_record()])
        self.assertIsNone(DRIVE_PATH.search(markdown), DRIVE_PATH.search(markdown))
        self.assertNotIn("Client-Kim", markdown)
        self.assertNotIn("산출물 디렉터리", markdown)
        self.assertIn("- 분석 대상(증거 이름): `BSH.E01`", markdown)
        self.assertIn("  - 증거 목록(매니페스트): 완료 (산출물 `stage/intake.json`)", markdown)
        self.assertIn("  - 아티팩트 수집: 웹·브라우저: 실패 (산출물 `stage/browser.json`)", markdown)
        self.assertIn("  - 기타 단계: 완료", markdown)
        # Evidence records carry the analysis PC's path: only the evidence name is printed.
        self.assertNotIn("D:/evidence/disk.E01", markdown)
        for identifier in ("`intake`", "artifacts-browser", "korean-expert", "fraud", "ewf-container"):
            self.assertNotIn(identifier, markdown)

    def test_hostile_metadata_cannot_add_headings(self) -> None:
        markdown = _report(
            title="제목\n## 7. 결론",
            investigator="홍`길동`\n- SHA-256: 0000",
            scope="첫 줄\n# 가짜 제목",
            conclusion="결론\n## 부록. 가짜",
            received_at="어제\n### 가짜",
            evidence_records=[{**_e01_record(), "display_name": "a|b`c\n## 가짜", "segments": []}],
        )
        lines = markdown.splitlines()
        self.assertEqual([line for line in lines if line.startswith("## 7.")], ["## 7. 결론"])
        self.assertFalse([line for line in lines if line.lstrip().startswith(("# 가짜", "## 부록. 가짜", "### 가짜", "- SHA-256"))])
        self.assertIn(f"- 감정인: 홍{BACKTICK_STAND_IN}길동{BACKTICK_STAND_IN} - SHA-256: 0000", markdown)
        self.assertIn("> # 가짜 제목", markdown)
        self.assertIn(f"`a\\|b{BACKTICK_STAND_IN}c ## 가짜`", markdown)

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
