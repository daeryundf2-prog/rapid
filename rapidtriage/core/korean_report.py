"""Korean expert-opinion (감정서) report template (R4-3).

Produces a court-submission-oriented markdown draft following domestic
디지털포렌식 감정서 conventions: 사건 개요, 감정물 인계·인수(CoC), 분석 도구와
검증 상태, 감정 결과, 법적 검토 대조표, 제한사항, 해시 부록.

The draft is a *review candidate* — 감정인의 최종 검토·서명 전까지 법적 효력이
없다는 점을 본문에 명시한다.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone

TEMPLATE_ID = "korean-expert"


def _text(value: object, default: str = "미기재") -> str:
    text = str(value or "").strip()
    return text or default


def _bookmark_rows(case_payload: Mapping[str, object], *, limit: int = 50) -> list[dict[str, object]]:
    bookmarks = case_payload.get("bookmarks")
    rows: list[dict[str, object]] = []
    if not isinstance(bookmarks, list):
        return rows
    for bookmark in bookmarks:
        if not isinstance(bookmark, Mapping):
            continue
        review = bookmark.get("review") if isinstance(bookmark.get("review"), Mapping) else {}
        if not review.get("include_in_report"):
            continue
        reference = bookmark.get("reference") if isinstance(bookmark.get("reference"), Mapping) else {}
        rows.append(
            {
                "summary": str(bookmark.get("summary") or bookmark.get("bookmark_id") or "항목"),
                "source": str(reference.get("command") or bookmark.get("source") or ""),
                "status": str(review.get("status") or "unreviewed"),
                "tags": ", ".join(str(tag) for tag in bookmark.get("tags", []) if tag),
                "note": str(bookmark.get("note") or ""),
            }
        )
        if len(rows) >= limit:
            break
    return rows


def _validation_flags(run_summary: Mapping[str, object]) -> list[str]:
    flags: list[str] = []
    validation = run_summary.get("validation")
    if isinstance(validation, Mapping):
        for key in ("commercial_grade_ready", "validation_required"):
            if validation.get(key) is not None:
                flags.append(f"{key}={validation.get(key)}")
    issues = run_summary.get("validation_issues") or run_summary.get("issues")
    if isinstance(issues, int) and issues:
        flags.append(f"validation_issues={issues}")
    return flags


def build_korean_expert_report(
    *,
    run_summary: Mapping[str, object],
    case_payload: Mapping[str, object],
    submission_manifest: Mapping[str, object],
    metadata: Mapping[str, object] | None = None,
) -> str:
    """Render the 감정서 draft markdown for a completed run."""
    metadata = metadata or {}
    generated_at = str(submission_manifest.get("generated_at") or datetime.now(timezone.utc).isoformat())
    case_number = _text(metadata.get("case_number") or case_payload.get("case_id"))
    case_title = _text(metadata.get("title") or case_payload.get("title"), "디지털 증거 감정")
    examiner = _text(metadata.get("investigator"))
    organization = _text(metadata.get("organization"))
    requester = _text(metadata.get("requester"))
    scope = _text(
        metadata.get("scope"),
        "감정 대상 디지털 증거에서 지정 아티팩트를 추출·분석하고 관련 행위 흔적을 감정함.",
    )
    conclusion = _text(metadata.get("conclusion"), "감정 결과는 제5장 및 부록과 같음.")

    manifest_items = submission_manifest.get("items") if isinstance(submission_manifest.get("items"), list) else []
    manifest_summary = submission_manifest.get("summary") if isinstance(submission_manifest.get("summary"), Mapping) else {}
    steps = [step for step in run_summary.get("steps", []) if isinstance(step, Mapping)]
    flags = _validation_flags(run_summary)
    bookmark_rows = _bookmark_rows(case_payload)
    case_summary = case_payload.get("summary") if isinstance(case_payload.get("summary"), Mapping) else {}

    lines: list[str] = [
        "# 감 정 서",
        "",
        f"- 사건번호: {case_number}",
        f"- 사건명: {case_title}",
        f"- 감정인: {examiner}",
        f"- 감정기관: {organization}",
        f"- 의뢰기관: {requester}",
        f"- 작성일시: {generated_at}",
        "",
        "> 본 문서는 분석 도구 산출물을 바탕으로 한 감정서 **초안**이다. "
        "감정인의 최종 검토와 서명이 있기 전까지 법적 감정서로서의 효력이 없다.",
        "",
        "## 1. 감정의 취지",
        "",
        scope,
        "",
        "## 2. 감정물의 내역 및 인계·인수",
        "",
        f"- 분석 대상 루트: `{_text(run_summary.get('root'), '미기재')}`",
        f"- 분석 모드: `{_text(run_summary.get('mode'), '미기재')}`",
        f"- 산출물 디렉터리: `{_text(run_summary.get('output_dir'), '미기재')}`",
        f"- 인계 증거 항목 수: {manifest_summary.get('hashed_item_count', 0)}",
        f"- 인계 인수 시각(매니페스트 생성): {generated_at}",
        "",
        "| 순번 | 증거물 | SHA-256 |",
        "|---|---|---|",
    ]
    for index, item in enumerate(manifest_items[:50], start=1):
        if not isinstance(item, Mapping):
            continue
        name = _text(item.get("path") or item.get("name") or item.get("source"))
        sha = _text(item.get("sha256") or item.get("hash"), "-")
        lines.append(f"| {index} | `{name}` | `{sha}` |")
    if not manifest_items:
        lines.append("| - | 인계 해시 목록 없음 | - |")

    lines += [
        "",
        "> 인계·인수 기록은 위 해시와 매니페스트 생성 시각으로 동일성을 확인한다. "
        "원본 매체는 읽기 전용으로 처리하였으며, 분석은 추출 사본에 대해 수행하였다.",
        "",
        "## 3. 감정 방법 및 사용 도구",
        "",
        "- 분석 도구: RapidTriage (로컬 우선 triage/아티팩트 분석 플랫폼)",
        "- 처리 절차:",
    ]
    if steps:
        for step in steps:
            lines.append(
                f"  - `{_text(step.get('name'))}`: {_text(step.get('status'))} "
                f"(output=`{_text(step.get('output'), '-')}`)"
            )
    else:
        lines.append("  - 절차 정보 없음")
    lines += [
        "- 검증 상태: " + (", ".join(flags) if flags else "검증 플래그 미기록"),
        "",
        "> 도구 검증은 알려진-답 픽스처와 신뢰 도구 대조 기록에 근거한다. "
        "실증거 검증 기록이 없는 파서 결과는 제5장에서 별도 표기한다.",
        "",
        "## 4. 감정 결과",
        "",
        f"- 검토 완료 항목 수: {case_summary.get('bookmark_count', 0)}",
        f"- 보고서 포함 항목 수: {case_summary.get('report_item_count', 0)}",
        "",
        "### 4.1 보고 포함 심사 항목",
        "",
    ]
    if bookmark_rows:
        lines += ["| 항목 | 출처 | 상태 | 태그 | 비고 |", "|---|---|---|---|---|"]
        for row in bookmark_rows:
            lines.append(
                f"| {row['summary']} | `{row['source']}` | {row['status']} "
                f"| {row['tags'] or '-'} | {row['note'] or '-'} |"
            )
    else:
        lines.append("- 보고서 포함으로 지정된 심사 항목 없음.")

    lines += [
        "",
        "## 5. 법적 검토 대조표",
        "",
        "| 요건 | 관련 근거 | 본 감정의 대응 |",
        "|---|---|---|",
        "| 증거 동일성 | 형사소송법상 증거의 동일성·무결성 확보 필요 | 인계 해시(SHA-256)를 제2장에 기재하고 매니페스트에 보존 |",
        "| 적법 절차 | 압수·수색 영장 및 절차 적법성 | 본 도구는 수집 이후 분석 단계만 수행 — 수집 적법성은 별도 확인 필요 |",
        "| 개인정보 | 개인정보 보호법·정보통신망법상 최소 처리 | 로컬 처리 원칙, 외부 전송 없음; 보고 포함 항목은 심사 지정분만 |",
        "| 재현 가능성 | 감정 결과의 검증 가능성 | 처리 절차·도구·버전·해시를 제3장과 부록에 기재 |",
        "",
        "## 6. 제한사항",
        "",
        "- 일부 파서 결과는 검증 대조 기록이 없어 `validation_required`로 표기된다.",
        "- 복호화되지 않은 메신저 후보는 증언 가치 없는 인벤토리로 취급하였다.",
        "- 상용 도구(EnCase/AXIOM 등)와의 교차 검증 기록이 없는 항목은 보고 전 추가 대조가 필요하다.",
        "",
        "## 7. 결론",
        "",
        conclusion,
        "",
        "## 부록. 증거 해시 목록",
        "",
    ]
    if manifest_items:
        for index, item in enumerate(manifest_items, start=1):
            if not isinstance(item, Mapping):
                continue
            name = _text(item.get("path") or item.get("name") or item.get("source"))
            sha = _text(item.get("sha256") or item.get("hash"), "-")
            lines.append(f"{index}. `{name}` — `{sha}`")
    else:
        lines.append("- 해시 목록 없음")

    return "\n".join(lines) + "\n"
