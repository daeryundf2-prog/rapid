from __future__ import annotations

from typing import Mapping


def build_case_report_markdown(
    *,
    run_summary: Mapping[str, object],
    case_payload: Mapping[str, object],
    submission_manifest: Mapping[str, object],
    metadata: Mapping[str, object] | None = None,
) -> str:
    metadata = metadata or {}
    case_title = str(metadata.get("title") or case_payload.get("title") or "rapidtriage case report")
    case_id = str(metadata.get("case_number") or case_payload.get("case_id") or "")
    investigator = str(metadata.get("investigator") or "")
    organization = str(metadata.get("organization") or "")
    requester = str(metadata.get("requester") or "")
    scope = str(metadata.get("scope") or "검토 대상으로 지정된 증거 파일과 rapidtriage 분석 산출물을 기준으로 작성함.")
    conclusion = str(metadata.get("conclusion") or "검토 결과 및 증거 해시는 아래 항목과 같음.")

    lines = [
        "# 디지털 포렌식 분석 보고서",
        "",
        "## 1. 사건 정보",
        "",
        f"- 보고서 제목: {case_title}",
        f"- 사건 번호: {case_id or '미기재'}",
        f"- 분석자: {investigator or '미기재'}",
        f"- 소속/기관: {organization or '미기재'}",
        f"- 의뢰자/의뢰기관: {requester or '미기재'}",
        f"- 생성 시각: `{submission_manifest.get('generated_at', '')}`",
        "",
        "## 2. 분석 대상 및 범위",
        "",
        f"- 분석 모드: `{run_summary.get('mode', '')}`",
        f"- 원본/분석 루트: `{run_summary.get('root', '')}`",
        f"- 분석 범위 루트: `{run_summary.get('scan_scope_root', '')}`",
        f"- 산출물 디렉터리: `{run_summary.get('output_dir', '')}`",
        "",
        scope,
        "",
        "## 3. 분석 절차 요약",
        "",
    ]

    for step in run_summary.get("steps", []):
        if not isinstance(step, Mapping):
            continue
        lines.append(
            f"- `{step.get('name')}`: {step.get('status')} "
            f"(output=`{step.get('output', '')}`)"
        )
    if not any(line.startswith("- `") for line in lines[-20:]):
        lines.append("- 절차 정보 없음")

    lines.extend(
        [
            "",
            "## 4. 주요 검토 결과",
            "",
        ]
    )
    case_summary = case_payload.get("summary") if isinstance(case_payload.get("summary"), Mapping) else {}
    lines.extend(
        [
            f"- 검토 항목 수: {case_summary.get('bookmark_count', 0)}",
            f"- 보고서 포함 후보 수: {case_summary.get('report_item_count', 0)}",
            f"- 해시 산출 항목 수: {submission_manifest.get('summary', {}).get('hashed_item_count', 0)}",
            f"- 해시 산출 제외 항목 수: {submission_manifest.get('summary', {}).get('skipped_count', 0)}",
            "",
        ]
    )

    lines.extend(["## 5. 제출 증거 및 해시값", ""])
    items = submission_manifest.get("items")
    if isinstance(items, list) and items:
        for index, item in enumerate(items, start=1):
            if not isinstance(item, Mapping):
                continue
            evidence = item.get("evidence") if isinstance(item.get("evidence"), Mapping) else {}
            hashes = evidence.get("hashes") if isinstance(evidence.get("hashes"), Mapping) else {}
            review = item.get("review") if isinstance(item.get("review"), Mapping) else {}
            lines.extend(
                [
                    f"### 5.{index}. {item.get('summary') or evidence.get('name') or 'Evidence'}",
                    "",
                    f"- 북마크 ID: `{item.get('bookmark_id', '')}`",
                    f"- 파일명: `{evidence.get('name', '')}`",
                    f"- 경로: `{evidence.get('path', '')}`",
                    f"- 크기: {evidence.get('size', 0)} bytes",
                    f"- 수정 시각: `{evidence.get('modified_at', '')}`",
                    f"- 검토 상태: `{review.get('status', '')}`",
                    f"- 태그: {', '.join(str(tag) for tag in item.get('tags', [])) or '없음'}",
                    f"- 분석자 메모: {item.get('note') or '없음'}",
                    f"- MD5: `{hashes.get('md5', '')}`",
                    f"- SHA1: `{hashes.get('sha1', '')}`",
                    f"- SHA256: `{hashes.get('sha256', '')}`",
                    "",
                ]
            )
    else:
        lines.append("- 제출 후보로 지정되어 해시 산출된 증거가 없음.")
        lines.append("")

    skipped = submission_manifest.get("skipped")
    lines.extend(["## 6. 해시 산출 제외 항목", ""])
    if isinstance(skipped, list) and skipped:
        for item in skipped:
            if isinstance(item, Mapping):
                lines.append(f"- `{item.get('path', '')}`: {item.get('reason', '')}")
    else:
        lines.append("- 없음")

    lines.extend(
        [
            "",
            "## 7. 결론 및 의견",
            "",
            conclusion,
            "",
            "## 8. 첨부 산출물",
            "",
            "- `rapidtriage-case.json`: 검토/북마크/분류 기록",
            "- `rapidtriage-submission-manifest.json`: 제출 후보 증거 해시 목록",
            "- `rapidtriage-submission-manifest.audit.json`: 제출 해시 매니페스트 생성 감사 기록",
            "- `rapidtriage-run-report.md`: 자동 분석 요약 보고서",
            "",
        ]
    )
    return "\n".join(lines)
