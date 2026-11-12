"""Korean expert-opinion (감정서) report template (R4-3, corrected R8 T-026).

Produces a court-submission-oriented markdown draft following domestic
디지털포렌식 감정서 conventions: 사건 개요, 감정물 인계·인수(CoC), 분석 도구와
검증 상태, 감정 결과, 법적 검토 대조표, 제한사항, 해시 부록.

R8 T-026: section 2 keeps two tables apart -- "감정 대상 증거" (the case evidence row's own hash
results from ``metadata.evidence_records``: name, size, per-segment SHA-256, recorded acquisition
hash) and "제출 항목" (the report candidates' analysis copies hashed by the submission manifest,
``item.evidence.relative_path`` / ``hashes.sha256``). The manifest time is the hash time, never the
hand-over time (``metadata.received_at``). The draft names the evidence only: the analysis PC's
folders (analysed root, output folder, absolute step outputs) belong to the technical appendix
template. Every interpolated value goes through the ``case_report_items`` markdown helpers.

The draft is a *review candidate* — 감정인의 최종 검토·서명 전까지 법적 효력이
없다는 점을 본문에 명시한다.
"""

from __future__ import annotations

from collections.abc import Mapping

from .. import PRODUCT_NAME, __version__
from .case_report_items import (
    NOT_RECORDED,
    author_label,
    catalog_versions,
    conditions_line,
    display_timezone,
    format_evidence_time,
    md_block_lines,
    md_cell,
    md_code,
    md_inline,
    path_name,
    review_status_label,
    roots_for,
    scope_lines,
    skipped_lines,
    step_lines,
    subject_lines,
)
from .report_candidates import is_report_candidate, report_scope_notes
from .step_labels import run_mode_ko, step_name_ko

TEMPLATE_ID = "korean-expert"
NOT_ENTERED = "미기재"
#: Shown for a case evidence row without a hash result (QA-175).
EVIDENCE_HASH_NOT_RECORDED = "원본 증거 해시 미기록 — 사건 화면에서 해시 계산 후 다시 내보내기"
#: Rows of the section 2 tables; the rest is listed in the appendix.
TABLE_LIMIT = 50

#: What an evidence hash covers (``core.e01_hash`` ``hash_scope.scope``).
HASH_SCOPE_KO = {
    "ewf-container-segment-bytes": "E01 컨테이너 세그먼트 파일의 바이트(디스크 매체 내용의 해시가 아님)",
    "file-bytes": "증거 파일의 바이트",
}
#: Case evidence hash outcome (``routes_cases`` / ``case_db.intake``).
HASH_STATUS_KO = {
    "computed": "계산 완료",
    "matched": "계산 완료 — 입력한 기대 해시와 일치",
    "mismatched": "계산 완료 — 입력한 기대 해시와 불일치",
}
HASHED_STATUSES = frozenset(HASH_STATUS_KO)


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _text(value: object, default: str = NOT_ENTERED) -> str:
    """One-line examiner / evidence text (``md_inline``), ``default`` when empty."""
    return md_inline(value) or default


def _paragraph_lines(value: object, default: str) -> list[str]:
    """Free text typed by the examiner (scope, conclusion) as quoted lines: a newline in it can
    never start a heading, a list item or a look-alike field."""
    return md_block_lines(value, indent="") or [default]


def _size_text(value: object) -> str:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return f"{value:,} 바이트"
    return NOT_RECORDED


def _review_rows(
    case_payload: Mapping[str, object], *, limit: int = TABLE_LIMIT
) -> tuple[list[dict[str, object]], int]:
    """Up to ``limit`` report-candidate rows and the total count (``review_rows_total``); the table
    states the cut when ``review_rows_truncated`` (table 상한, rest 잘림)."""
    bookmarks = case_payload.get("bookmarks")
    rows: list[dict[str, object]] = []
    for bookmark in bookmarks if isinstance(bookmarks, list) else []:
        if not isinstance(bookmark, Mapping) or not is_report_candidate(bookmark):
            continue
        review = _mapping(bookmark.get("review"))
        reference = _mapping(bookmark.get("reference"))
        rows.append(
            {
                "summary": str(bookmark.get("summary") or bookmark.get("bookmark_id") or "항목"),
                "source": str(reference.get("command") or bookmark.get("source") or ""),
                "status": review_status_label(review.get("status")),
                # Same reviewer source as the per-item "검토자" line of the other templates.
                "reviewer": author_label(review.get("reviewer") or review.get("reviewed_by") or bookmark.get("created_by")),
                "tags": ", ".join(str(tag) for tag in bookmark.get("tags") or [] if tag),
                "note": str(bookmark.get("note") or ""),
            }
        )
    review_rows_total = len(rows)
    review_rows_truncated = review_rows_total > limit
    return (rows[:limit] if review_rows_truncated else rows), review_rows_total


def reviewed_count(case_payload: Mapping[str, object]) -> int:
    """Marks whose review status is set (anything but 미검토) -- "검토 완료" (T-026 ④)."""
    bookmarks = case_payload.get("bookmarks")
    count = 0
    for bookmark in bookmarks if isinstance(bookmarks, list) else []:
        if isinstance(bookmark, Mapping):
            status = str(_mapping(bookmark.get("review")).get("status") or "unreviewed")
            count += int(status != "unreviewed")
    return count


def _step_lines(run_summary: Mapping[str, object]) -> list[str]:
    """Processing steps with Korean names and outputs relative to the result folder."""
    return step_lines(run_summary, technical=False)


def _validation_text(run_summary: Mapping[str, object]) -> str:
    parts: list[str] = []
    validation = _mapping(run_summary.get("validation"))
    for key, label in (("commercial_grade_ready", "상용 수준 검증 완료"), ("validation_required", "추가 검증 필요")):
        value = validation.get(key)
        if isinstance(value, bool):
            parts.append(f"{label} {'예' if value else '아니오'}")
    issues = run_summary.get("validation_issues") or run_summary.get("issues")
    if isinstance(issues, int) and not isinstance(issues, bool) and issues:
        parts.append(f"검증 문제 {issues:,}건")
    return ", ".join(parts) if parts else "검증 상태 기록 없음"


def _evidence_records(metadata: Mapping[str, object]) -> list[Mapping[str, object]]:
    records = metadata.get("evidence_records")
    return [record for record in records if isinstance(record, Mapping)] if isinstance(records, list) else []


def _recorded_hash_text(record: Mapping[str, object]) -> str:
    recorded = record.get("recorded_acquisition_hash")
    if not isinstance(recorded, Mapping):
        return "증거 파일에 기록된 취득 해시 없음(읽지 않았거나 형식에 기록 칸이 없음)"
    values = [
        f"{label} {md_code(recorded.get(key))}"
        for key, label in (("md5", "MD5"), ("sha1", "SHA-1"))
        if md_inline(recorded.get(key))
    ]
    if values:
        return ", ".join(values) + " (이미지에 기록된 값을 읽은 것이며 다시 계산한 값이 아님)"
    return f"읽지 못함 — {_text(recorded.get('reason'), '사유 기록 없음')}"


def evidence_record_lines(metadata: Mapping[str, object]) -> list[str]:
    """Section 2.1 "감정 대상 증거": the case evidence rows' own hash results (T-182 records)."""
    records = _evidence_records(metadata)
    if not records:
        return [f"- {EVIDENCE_HASH_NOT_RECORDED}"]
    lines: list[str] = []
    rows: list[str] = []
    for record in records:
        number = _text(record.get("evidence_number"), "번호 없음")
        name = _text(record.get("display_name") or path_name(record.get("path")), "이름 없음")
        status = str(record.get("hash_status") or "")
        segments = [row for row in record.get("segments") or [] if isinstance(row, Mapping)]
        container_sha = md_inline(_mapping(record.get("hashes")).get("sha256"))
        if status not in HASHED_STATUSES or not (container_sha or any(md_inline(row.get("sha256")) for row in segments)):
            message = md_inline(record.get("hash_message"))
            why = message if status == "not-applicable" and message else EVIDENCE_HASH_NOT_RECORDED
            lines.append(f"- {number} {md_code(name)}: {why}")
            continue
        if segments:
            for segment in segments:
                sha = md_inline(segment.get("sha256"))
                rows.append(
                    f"| {md_cell(number)} | `{md_cell(segment.get('name') or name)}` "
                    f"| {_size_text(segment.get('size_bytes'))} "
                    f"| {f'`{md_cell(sha)}`' if sha else '해시 미기록'} |"
                )
        else:
            rows.append(f"| {md_cell(number)} | `{md_cell(name)}` | {_size_text(record.get('size_bytes'))} | `{md_cell(container_sha)}` |")
        scope = str(record.get("hash_scope") or "")
        scope_text = HASH_SCOPE_KO.get(scope) or (md_inline(scope) and f"기록값 {md_code(scope)}") or NOT_RECORDED
        lines += [
            f"- {number} 해시 결과: {HASH_STATUS_KO[status]}",
            f"- {number} 해시 대상: {scope_text}",
            f"- {number} 기록된 취득 해시: {_recorded_hash_text(record)}",
        ]
    table = ["| 증거 번호 | 증거 파일 | 크기 | SHA-256 |", "|---|---|---|---|", *rows, ""] if rows else []
    return table + lines


def submission_item_lines(submission_manifest: Mapping[str, object]) -> list[str]:
    """Section 2.2 "제출 항목": report candidates hashed by the submission manifest."""
    items = [item for item in submission_manifest.get("items") or [] if isinstance(item, Mapping)]
    if not items:
        return ["- 해시를 산출한 제출 항목 없음."]
    lines = ["| 순번 | 증거 안 경로 | SHA-256 |", "|---|---|---|"]
    for index, item in enumerate(items[:TABLE_LIMIT], start=1):
        lines.append(f"| {index} | {_item_name(item)} | `{md_cell(_item_sha(item))}` |")
    if len(items) > TABLE_LIMIT:
        lines += ["", f"- 표 상한 {TABLE_LIMIT}건까지만 적음(나머지는 표에서 잘림). 전체 {len(items):,}건은 부록에 있음."]
    return lines


def _item_name(item: Mapping[str, object]) -> str:
    evidence = _mapping(item.get("evidence"))
    relative = md_inline(evidence.get("relative_path"))
    if relative:
        return f"`{md_cell(relative)}`"
    name = md_inline(evidence.get("name")) or path_name(evidence.get("path")) or "이름 없음"
    return f"`{md_cell(name)}` (분석 결과 폴더의 파일 — 증거 안 경로 없음)"


def _item_sha(item: Mapping[str, object]) -> str:
    return md_inline(_mapping(_mapping(item.get("evidence")).get("hashes")).get("sha256")) or "해시 미기록"


def method_lines(
    run_summary: Mapping[str, object],
    metadata: Mapping[str, object],
    report_context: Mapping[str, object],
    *,
    display_label: str,
) -> list[str]:
    """Section 3: tool and catalog versions, display zone, step counts, the four-axis scope."""
    versions = catalog_versions(run_summary)
    steps = _mapping(report_context.get("steps"))
    scope = _mapping(metadata.get("processing_scope")) or _mapping(report_context.get("scope"))
    lines = [
        f"- 분석 도구: {PRODUCT_NAME} (로컬 분석 프로그램)",
        f"- 도구 버전: {_text(metadata.get('tool_version'), __version__)}",
        f"- 규칙·분류 카탈로그 버전: {', '.join(versions) if versions else NOT_RECORDED}",
        f"- 표시 시간대: {display_label}. 모든 시각은 UTC 값을 함께 적음.",
    ]
    if steps:
        failed = ", ".join(step_name_ko(name) for name in steps.get("failed_names") or []) or "없음"
        partial = ", ".join(step_name_ko(name) for name in steps.get("partial_names") or []) or "없음"
        lines += [
            f"- 처리 단계: 전체 {steps.get('total', 0)} · 완료 {steps.get('completed', 0)} · "
            f"부분 {steps.get('partial', 0)} · 실패 {steps.get('failed', 0)} · 건너뜀 {steps.get('skipped', 0)}",
            f"- 실패한 단계: {failed}",
            f"- 부분 단계: {partial}",
        ]
    else:
        lines.append(f"- 실패·부분 단계: {NOT_RECORDED}")
    lines += scope_lines(scope or None)
    lines.append(f"- 검증 상태: {_validation_text(run_summary)}")
    lines += ["- 처리 절차:", *(f"  {line}" for line in _step_lines(run_summary) or ["- 절차 정보 없음"])]
    return lines


def build_korean_expert_report(
    *,
    run_summary: Mapping[str, object],
    case_payload: Mapping[str, object],
    submission_manifest: Mapping[str, object],
    metadata: Mapping[str, object] | None = None,
    report_context: Mapping[str, object] | None = None,
) -> str:
    """Render the 감정서 draft markdown for a completed run.

    ``metadata``: request fields plus the run's ``tool_version`` / ``evidence_records`` /
    ``processing_scope`` (T-182); optional ``received_at`` (hand-over time, T-279) and
    ``source_state_record`` (the original's state before and after processing)."""
    metadata = metadata or {}
    report_context = report_context or {}
    offset_minutes, display_label = display_timezone(run_summary)
    hashed_at = format_evidence_time(submission_manifest.get("generated_at"), offset_minutes)
    case_number = _text(metadata.get("case_number") or case_payload.get("case_id"))
    case_title = _text(metadata.get("title") or case_payload.get("title"), "디지털 증거 감정")
    mode = str(run_summary.get("mode") or "")
    manifest_summary = _mapping(submission_manifest.get("summary"))
    case_summary = _mapping(case_payload.get("summary"))
    review_rows, review_rows_total = _review_rows(case_payload)
    roots = roots_for(run_summary)

    lines: list[str] = [
        "# 감 정 서",
        "",
        f"- 사건번호: {case_number}",
        f"- 사건명: {case_title}",
        f"- 감정인: {_text(metadata.get('investigator'))}",
        f"- 감정기관: {_text(metadata.get('organization'))}",
        f"- 의뢰기관: {_text(metadata.get('requester'))}",
        f"- 작성일시: {hashed_at}",
        "",
        "> 본 문서는 분석 도구 산출물을 바탕으로 한 감정서 **초안**이다. "
        "감정인의 최종 검토와 서명이 있기 전까지 법적 감정서로서의 효력이 없다.",
        "",
        "## 1. 감정의 취지",
        "",
        *_paragraph_lines(
            metadata.get("scope"),
            "감정 대상 디지털 증거에서 지정 아티팩트를 추출·분석하고 관련 행위 흔적을 감정함.",
        ),
        "",
        "## 2. 감정물의 내역 및 인계·인수",
        "",
        *subject_lines(run_summary, technical=False),
        f"- 분석 모드: {run_mode_ko(mode)}",
        f"- 인계 인수 시각: {_text(metadata.get('received_at'))}",
        f"- 제출 항목 해시 산출 시각: {hashed_at}",
        f"- 제출 항목 수(해시 산출): {manifest_summary.get('hashed_item_count', 0)}",
        "",
        "### 2.1 감정 대상 증거",
        "",
        *evidence_record_lines(metadata),
        "",
        "### 2.2 제출 항목(보고서 포함 파일의 분석 사본)",
        "",
        *submission_item_lines(submission_manifest),
        "",
        "해시 산출에서 제외한 항목:",
        "",
        *skipped_lines(submission_manifest, roots),
        "",
        "> 제출 항목 해시는 위 산출 시각에 분석 사본을 다시 읽어 계산한 값이며 원본 증거 매체의 해시가 아니다. "
        "분석은 추출 사본에 대해 수행하였다. "
        f"처리 전후 원본 상태 기록: {_text(metadata.get('source_state_record'), '미기록')}",
        "",
        "## 3. 감정 방법 및 사용 도구",
        "",
        *method_lines(run_summary, metadata, report_context, display_label=display_label),
        conditions_line(submission_manifest, case_payload),
        "",
        "> 도구 검증은 알려진-답 픽스처와 신뢰 도구 대조 기록에 근거한다. "
        "실증거 검증 기록이 없는 파서 결과는 제6장에서 별도 표기한다.",
        "",
        "## 4. 감정 결과",
        "",
        f"- 전체 표시 항목 수: {case_summary.get('bookmark_count', 0)}",
        f"- 검토 완료 항목 수(미검토 제외): {reviewed_count(case_payload)}",
        f"- 보고서 포함 항목 수: {case_summary.get('report_item_count', 0)}",
        *report_scope_notes(case_payload, submission_manifest),
        "",
        "### 4.1 보고 포함 심사 항목",
        "",
    ]
    if review_rows:
        lines += ["| 항목 | 출처 | 상태 | 검토자 | 태그 | 비고 |", "|---|---|---|---|---|---|"]
        for row in review_rows:
            # Evidence / examiner text: one line per cell, ``|`` and backticks neutralised (R8 T-027).
            lines.append(
                f"| {md_cell(row['summary'])} | {md_cell(row['source']) or '출처 기록 없음'} | {md_cell(row['status'])} "
                f"| {md_cell(row['reviewer'])} | {md_cell(row['tags']) or '없음'} | {md_cell(row['note']) or '없음'} |"
            )
        if review_rows_total > len(review_rows):
            lines += ["", f"- 표 상한 {TABLE_LIMIT}건까지만 적음(전체 {review_rows_total:,}건, 나머지는 표에서 잘림)."]
    else:
        lines.append("- 보고서 포함으로 지정된 심사 항목 없음.")

    lines += [
        "",
        "## 5. 법적 검토 대조표",
        "",
        "| 요건 | 관련 근거 | 본 감정의 대응 |",
        "|---|---|---|",
        "| 증거 동일성 | 형사소송법상 증거의 동일성·무결성 확보 필요 | 원본 증거 해시(계산한 경우)와 제출 항목 해시를 제2장에 나누어 기재 |",
        "| 적법 절차 | 압수·수색 영장 및 절차 적법성 | 본 도구는 수집 이후 분석 단계만 수행 — 수집 적법성은 별도 확인 필요 |",
        "| 개인정보 | 개인정보 보호법·정보통신망법상 최소 처리 | 로컬 처리 원칙, 외부 전송 없음; 보고 포함 항목은 심사 지정분만 |",
        "| 재현 가능성 | 감정 결과의 검증 가능성 | 처리 절차·도구 버전·카탈로그 버전·처리 범위·해시를 제2장·제3장과 부록에 기재 |",
        "",
        "## 6. 제한사항",
        "",
        "- 일부 파서 결과는 검증 대조 기록이 없어 '추가 검증 필요'로 표기된다.",
        "- 원본 증거 해시가 '미기록'이면 이 문서만으로 원본 동일성을 확인할 수 없다. 사건 화면에서 해시를 계산한 뒤 다시 내보낸다.",
        "- 처리 전후 원본 상태를 도구가 기록하지 않았으면 원본 매체가 변경되지 않았다는 점은 이 문서로 확인되지 않는다.",
        "- 복호화되지 않은 메신저 후보는 증언 가치 없는 인벤토리로 취급하였다.",
        "- 상용 도구(EnCase/AXIOM 등)와의 교차 검증 기록이 없는 항목은 보고 전 추가 대조가 필요하다.",
        "",
        "## 7. 결론",
        "",
        *_paragraph_lines(metadata.get("conclusion"), "감정 결과는 제4장 및 부록과 같음."),
        "",
        "## 부록. 제출 항목 해시 목록",
        "",
    ]
    items = [item for item in submission_manifest.get("items") or [] if isinstance(item, Mapping)]
    for index, item in enumerate(items, start=1):
        lines.append(f"{index}. {_item_name(item)} — SHA-256 `{md_inline(_item_sha(item))}`")
    if not items:
        lines.append("- 해시를 산출한 제출 항목 없음.")

    return "\n".join(lines) + "\n"
