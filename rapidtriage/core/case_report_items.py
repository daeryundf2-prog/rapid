"""Korean building blocks of the case report (R8 T-027).

Section 5 lists every report candidate -- files *and* artifact rows (USB 연결, 로그온, 방문 기록 ...)
-- with the row the mark cites: its evidence time in the display time zone and in UTC, a preview,
the path inside the evidence and where the row came from (T-178 ``row`` info). Hashes come from the
submission manifest when the candidate is a file that was hashed; otherwise the Korean skip reason
is shown. Nothing a candidate carries is dropped because it has no file.

The processing scope is told on four axes (T-023 ``scope``), never as one number. The core layer
does not import the API package, so the caller passes the computed scope and step counts in
``report_context`` (``{"scope": ..., "steps": ...}``); without them the report says "기록 없음".
"""

from __future__ import annotations

import datetime as dt
from collections import deque
from collections.abc import Mapping, Sequence
from pathlib import Path

from .. import PRODUCT_NAME, __version__
from .report_candidates import is_report_candidate
from .submission import (
    SKIP_REASON_KO,
    build_row_info,
    evidence_relative_roots,
    is_relative_to,
)

#: Korean review-status labels (``core.cli_constants.REVIEW_STATUSES``).
REVIEW_STATUS_KO = {
    "unreviewed": "미검토",
    "relevant": "관련 있음",
    "needs-review": "추가 검토 필요",
    "not-relevant": "관련 없음",
    "excluded": "제외",
}
STEP_STATUS_KO = {
    "completed": "완료",
    "completed_with_warnings": "완료(경고 있음)",
    "completed-with-warnings": "완료(경고 있음)",
    "reused": "완료(이전 결과 재사용)",
    "delta-merged": "완료(증분 병합)",
    "failed_isolated": "일부 완료(일부 실패 격리)",
    "failed-isolated": "일부 완료(일부 실패 격리)",
    "cancelled-partial": "일부 완료(취소 전까지)",
    "partial": "일부 완료",
    "failed": "실패",
    "error": "실패",
    "skipped": "건너뜀",
    "disabled": "건너뜀(꺼짐)",
    "cancelled": "취소됨",
    "running": "실행 중",
    "queued": "대기",
    "pass": "완료",
    "notice": "완료(알림 있음)",
    "warning": "완료(경고 있음)",
}
TEMPLATE_LABEL_KO = {
    "legal-handoff": "법률 인계용",
    "executive-summary": "의사결정자 요약",
    "technical-appendix": "기술 부록 포함",
    "hash-only": "해시 목록만",
    "korean-expert": "감정서",
}
TEMPLATE_POLICY_KO = {
    "executive-summary": "의사결정자용. 분석기 경로와 단계별 산출물은 요약해 생략함.",
    "legal-handoff": "균형 인계용. 절차와 증거 해시를 싣고 원시 JSON은 싣지 않음.",
    "technical-appendix": "기술 부록 포함. 처리 상한·경고·원본 경로·분석기 정보를 함께 실음.",
    "hash-only": "해시 부록만. 서술 분석과 대부분의 메타데이터를 생략함.",
    "korean-expert": "법원 제출용 초안. 감정서 구조(증거 연속성·도구 검증·법적 점검·한계)를 따름.",
}
#: Author placeholders that name no person (the console writes ``web-ui``).
ANONYMOUS_AUTHORS = {"", "web-ui", "web", "api", "cli", "unknown"}
NO_AUTHOR = "(작성자 미지정)"
NOT_RECORDED = "기록 없음"
#: Display time zone when the evidence system's zone was not recorded: Korea Standard Time.
DEFAULT_DISPLAY_OFFSET_MINUTES = 9 * 60
SOURCE_HIT_LABELS = (
    ("source_type", "출처 유형"),
    ("structured_citation", "구조화 인용"),
    ("source_locator", "출처 위치"),
    ("matched_terms", "일치 검색어"),
    ("result_hash", "결과 해시"),
    ("snippet", "내용 일부"),
    ("review_hint", "검토 안내"),
)
SOURCE_TYPE_KO = {"source-search": "현재 파일 출처 검색", "docs-index": "문서 색인"}


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def template_label(template: str) -> str:
    return TEMPLATE_LABEL_KO.get(template, template)


def template_policy(template: str) -> str:
    return TEMPLATE_POLICY_KO.get(template, TEMPLATE_POLICY_KO["legal-handoff"])


def review_status_label(status: object) -> str:
    key = str(status or "unreviewed")
    return REVIEW_STATUS_KO.get(key, key)


def step_status_label(status: object) -> str:
    key = str(status or "").strip()
    return STEP_STATUS_KO.get(key.lower(), f"상태 미상({key or '없음'})")


def author_label(value: object) -> str:
    text = str(value or "").strip()
    return NO_AUTHOR if text.lower() in ANONYMOUS_AUTHORS else text


# --- time -----------------------------------------------------------------------------------


def _offset_text(minutes: int) -> str:
    sign = "+" if minutes >= 0 else "-"
    hours, rest = divmod(abs(minutes), 60)
    return f"UTC{sign}{hours:02d}:{rest:02d}"


def display_timezone(run_summary: Mapping[str, object]) -> tuple[int, str]:
    """``(offset minutes, Korean label)``: the evidence system's zone when the run read it from the
    registry (offset = -Bias), else Korea Standard Time, said so."""
    timezone = _mapping(_mapping(run_summary.get("disclosures")).get("timezone"))
    evidence = _mapping(timezone.get("evidence_timezone"))
    bias = evidence.get("bias_minutes")
    if isinstance(bias, int) and not isinstance(bias, bool) and abs(bias) <= 14 * 60:
        name = str(evidence.get("label") or evidence.get("name") or "").strip()
        offset = -bias
        suffix = f", {name}" if name else ""
        return offset, f"{_offset_text(offset)} (증거 시스템 시간대{suffix})"
    offset = DEFAULT_DISPLAY_OFFSET_MINUTES
    return offset, f"{_offset_text(offset)} (한국 표준시 — 증거 시스템 시간대가 기록되지 않아 기본값 사용)"


def format_evidence_time(value: object, offset_minutes: int) -> str:
    """``2025-05-29 23:25:26 (UTC+09:00) · UTC 2025-05-29 14:25:26``; unparsable values as recorded."""
    text = str(value or "").strip()
    if not text:
        return NOT_RECORDED
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return f"{text} (형식을 해석하지 못해 기록값 그대로 표시)"
    note = ""
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
        note = " (시간대 표기 없음 — UTC로 간주)"
    utc = parsed.astimezone(dt.timezone.utc)
    local = utc.astimezone(dt.timezone(dt.timedelta(minutes=offset_minutes)))
    return (
        f"{local:%Y-%m-%d %H:%M:%S} ({_offset_text(offset_minutes)}) · UTC {utc:%Y-%m-%d %H:%M:%S}{note}"
    )


# --- processing scope -----------------------------------------------------------------------


def _pct_text(value: object) -> str:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return "확인 불가"
    return f"{value:g}%"


def _num_text(value: object) -> str:
    if not isinstance(value, int) or isinstance(value, bool):
        return "확인 불가"
    return f"{value:,}"


def scope_lines(scope: Mapping[str, object] | None) -> list[str]:
    """The four-axis processing scope as report lines (T-023 ``build_run_scope``)."""
    if not isinstance(scope, Mapping) or not scope:
        return ["- 처리 범위: 기록 없음(이 보고서를 만든 경로가 처리 범위를 넘기지 않음)."]
    notes = [str(note) for note in scope.get("notes") or [] if str(note).strip()]
    if scope.get("basis") == "unavailable":
        lines = ["- 처리 범위: 추출 통계가 없어 네 축 처리 범위를 계산하지 않음."]
        return lines + [f"  - {note}" for note in notes]
    partitions = _mapping(scope.get("partitions"))
    allocated = _mapping(scope.get("allocated"))
    deleted = _mapping(scope.get("deleted"))
    unallocated = _mapping(scope.get("unallocated"))
    basis = "추정" if scope.get("basis") == "inferred" else "측정"
    unallocated_text = (
        f"비할당 영역 {_pct_text(unallocated.get('scanned_pct'))} 검사"
        if unallocated.get("measured")
        else "비할당 영역은 측정하지 않음"
    )
    sentence = (
        f"- 처리 범위({basis}): 파티션 {_num_text(partitions.get('total'))}개 중 지원 파일시스템 "
        f"{_num_text(partitions.get('supported'))}개, 처리 {_num_text(partitions.get('processed'))}개 · "
        f"할당 파일 목록화 {_pct_text(allocated.get('listed_pct'))}, 내용 읽기 {_pct_text(allocated.get('content_pct'))} · "
        f"삭제 파일 레코드 {_num_text(deleted.get('records'))}건 중 추출 시도 {_pct_text(deleted.get('attempted_pct'))}, "
        f"목록화 {_pct_text(deleted.get('listed_pct'))} · {unallocated_text}."
    )
    return [sentence, *(f"  - {note}" for note in notes)]


# --- reproducibility ------------------------------------------------------------------------


def catalog_versions(run_summary: Mapping[str, object]) -> list[str]:
    found: list[str] = []
    for step in run_summary.get("steps") or []:
        if isinstance(step, Mapping) and step.get("catalog_version") not in (None, ""):
            text = f"{step.get('name')}: {step.get('catalog_version')}"
            if text not in found:
                found.append(text)
    return found


def reproducibility_lines(
    run_summary: Mapping[str, object],
    report_context: Mapping[str, object],
    *,
    display_label: str,
) -> list[str]:
    versions = catalog_versions(run_summary)
    steps = _mapping(report_context.get("steps"))
    lines = [
        f"- 도구 버전: {PRODUCT_NAME} {__version__}",
        f"- 규칙·분류 카탈로그 버전: {', '.join(versions) if versions else NOT_RECORDED}",
        f"- 표시 시간대: {display_label}. 모든 시각은 UTC 값을 함께 적음.",
    ]
    if steps:
        failed = ", ".join(str(name) for name in steps.get("failed_names") or []) or "없음"
        partial = ", ".join(str(name) for name in steps.get("partial_names") or []) or "없음"
        lines.append(
            f"- 처리 단계: 전체 {steps.get('total', 0)} · 완료 {steps.get('completed', 0)} · "
            f"부분 {steps.get('partial', 0)} · 실패 {steps.get('failed', 0)} · 건너뜀 {steps.get('skipped', 0)}"
        )
        lines.append(f"- 실패한 단계: {failed}")
        lines.append(f"- 부분 단계: {partial}")
    else:
        lines.append(f"- 실패·부분 단계: {NOT_RECORDED}")
    lines.extend(scope_lines(_mapping(report_context.get("scope")) or None))
    return lines


# --- section 5 entries ----------------------------------------------------------------------


def report_entries(
    case_payload: Mapping[str, object],
    submission_manifest: Mapping[str, object],
) -> list[dict[str, object]]:
    """Every report candidate with its manifest outcome: ``{bookmark, item, skip}``.

    Candidates are the case payload's bookmarks the manifest selected (``include_all`` or
    :func:`is_report_candidate`), joined to the manifest's ``items`` / ``skipped`` by bookmark id
    in order. Manifest entries no candidate claimed are appended so nothing is dropped."""
    options = _mapping(submission_manifest.get("options"))
    include_all = bool(options.get("include_all"))
    bookmarks = case_payload.get("bookmarks")
    candidates = [
        bookmark
        for bookmark in (bookmarks if isinstance(bookmarks, list) else [])
        if isinstance(bookmark, Mapping) and (include_all or is_report_candidate(bookmark))
    ]
    outcomes: dict[str, deque[tuple[str, Mapping[str, object]]]] = {}
    for key in ("items", "skipped"):
        values = submission_manifest.get(key)
        for value in values if isinstance(values, list) else []:
            if isinstance(value, Mapping):
                outcomes.setdefault(str(value.get("bookmark_id") or ""), deque()).append((key, value))
    entries: list[dict[str, object]] = []
    for bookmark in candidates:
        queue = outcomes.get(str(bookmark.get("bookmark_id") or ""))
        kind, outcome = queue.popleft() if queue else ("", {})
        entries.append(
            {
                "bookmark": bookmark,
                "item": outcome if kind == "items" else None,
                "skip": outcome if kind == "skipped" else None,
            }
        )
    for queue in outcomes.values():
        while queue:
            kind, outcome = queue.popleft()
            entries.append(
                {
                    "bookmark": outcome,
                    "item": outcome if kind == "items" else None,
                    "skip": outcome if kind == "skipped" else None,
                }
            )
    return entries


def evidence_relative_path(raw_path: object, roots: Sequence[Path]) -> str:
    """Path inside the evidence (relative to an analysed root), or ``""`` when it is not under one."""
    text = str(raw_path or "").strip()
    if not text:
        return ""
    try:
        path = Path(text).expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        return ""
    for root in roots:
        if is_relative_to(path, root):
            return path.relative_to(root).as_posix() or "."
    return ""


def skip_reason_label(skip: Mapping[str, object]) -> str:
    reason = str(skip.get("reason") or "")
    return str(skip.get("reason_ko") or SKIP_REASON_KO.get(reason, reason or "사유 기록 없음"))


def _source_location(row: Mapping[str, object]) -> str:
    parts = []
    for key, label in (("collection", "수집 원천"), ("kind", "유형"), ("locator", "위치"), ("citation_id", "인용 ID")):
        value = str(row.get(key) or "").strip()
        if value:
            parts.append(f"{label} `{value}`")
    return " · ".join(parts) or NOT_RECORDED


def source_hit_lines(hits: Sequence[Mapping[str, str]]) -> list[str]:
    if not hits:
        return []
    lines = ["- 출처 검색 인용:"]
    for hit in hits:
        lines.append(f"  - 인용: {hit.get('citation', '')}")
        for key, label in SOURCE_HIT_LABELS:
            value = hit.get(key)
            if not value:
                continue
            if key == "source_type":
                value = f"{SOURCE_TYPE_KO.get(value, value)} (`{value}`)"
            elif key in ("source_locator", "result_hash"):
                value = f"`{value}`"
            lines.append(f"    - {label}: {value}")
    return lines


#: Case DB target types / bookmark sources that cite a file rather than an artifact row.
FILE_TARGET_TYPES = {"file_record", "indexed_document", "file"}
ARTIFACT_TARGET_TYPES = {"artifact", "event"}
FILE_SOURCE_COMMANDS = {"files", "docs", "files-extract", "docs-extract", "compare"}


def is_file_entry(bookmark: Mapping[str, object], evidence: Mapping[str, object]) -> bool:
    """A case DB file/document mark, a bookmark taken from a file list, or a hashed file that is not
    an artifact row (an artifact row whose source file was hashed is still an artifact row)."""
    reference = _mapping(bookmark.get("reference"))
    target_type = str(reference.get("target_type") or "")
    if target_type in ARTIFACT_TARGET_TYPES:
        return False
    if evidence or target_type in FILE_TARGET_TYPES:
        return True
    return str(reference.get("command") or reference.get("source_command") or "") in FILE_SOURCE_COMMANDS


def entry_lines(
    index: int,
    entry: Mapping[str, object],
    *,
    roots: Sequence[Path],
    offset_minutes: int,
    source_hits: Sequence[Mapping[str, str]],
    show_copy_path: bool,
) -> list[str]:
    bookmark = _mapping(entry.get("bookmark"))
    item = _mapping(entry.get("item"))
    skip = _mapping(entry.get("skip"))
    evidence = _mapping(item.get("evidence"))
    hashes = _mapping(evidence.get("hashes"))
    review = _mapping(bookmark.get("review")) or _mapping(item.get("review"))
    row = _mapping(item.get("row")) or build_row_info(bookmark)
    snapshot = _mapping(bookmark.get("snapshot"))
    raw_path = evidence.get("path") or snapshot.get("path") or skip.get("path")
    relative = str(evidence.get("relative_path") or "") or evidence_relative_path(raw_path, roots)
    is_file = is_file_entry(bookmark, evidence)
    title = (
        bookmark.get("summary") or item.get("summary") or skip.get("summary") or evidence.get("name")
        or row.get("preview") or "제목 없는 항목"
    )
    tags = bookmark.get("tags") if isinstance(bookmark.get("tags"), list) else item.get("tags")
    note = str(bookmark.get("note") or item.get("note") or "")
    if relative:
        location = f"`{relative}`"
    elif raw_path:
        location = "원래 위치 알 수 없음(복구·추출 사본 또는 증거 루트 밖)"
    else:
        location = "경로 없음(아티팩트 행)"
    lines = [
        f"### 5.{index}. {title}",
        "",
        f"- 항목 ID: `{bookmark.get('bookmark_id') or item.get('bookmark_id') or ''}`",
        f"- 구분: {'파일' if is_file else '아티팩트 행'}",
        f"- 증거 시각: {format_evidence_time(row.get('timestamp'), offset_minutes)}",
        f"- 내용 미리보기: {row.get('preview') or NOT_RECORDED}"
        + (f" (전체 {row.get('preview_total')}자 중 앞부분)" if row.get("preview_truncated") else ""),
        f"- 증거 안 경로: {location}",
        f"- 출처 위치: {_source_location(row)}",
    ]
    if evidence:
        lines.extend(
            [
                f"- 파일명: `{evidence.get('name', '')}`",
                f"- 크기: {int(evidence.get('size') or 0):,}바이트",
                f"- 수정 시각: {format_evidence_time(evidence.get('modified_at'), offset_minutes)}",
            ]
        )
        if show_copy_path:
            lines.append(f"- 분석 사본 위치(기술 정보): `{evidence.get('path', '')}`")
    lines.extend(
        [
            f"- 판단: {review_status_label(review.get('status'))}",
            f"- 검토자: {author_label(review.get('reviewer') or review.get('reviewed_by') or bookmark.get('created_by'))}",
            f"- 태그: {', '.join(str(tag) for tag in tags or []) or '없음'}",
            f"- 분석자 메모: {note or '없음'}",
            *source_hit_lines(source_hits),
        ]
    )
    if evidence:
        lines.extend(
            [
                f"- MD5: `{hashes.get('md5', '')}`",
                f"- SHA-1: `{hashes.get('sha1', '')}`",
                f"- SHA-256: `{hashes.get('sha256', '')}`",
            ]
        )
    elif skip:
        lines.append(f"- 해시: 산출하지 않음 — {skip_reason_label(skip)}")
    else:
        lines.append("- 해시: 산출하지 않음 — 제출 해시 목록에 없는 항목")
    lines.append("")
    return lines


def skipped_lines(submission_manifest: Mapping[str, object], roots: Sequence[Path]) -> list[str]:
    skipped = submission_manifest.get("skipped")
    lines: list[str] = []
    for skip in skipped if isinstance(skipped, list) else []:
        if not isinstance(skip, Mapping):
            continue
        relative = evidence_relative_path(skip.get("path"), roots)
        label = str(skip.get("summary") or "") or (f"`{relative}`" if relative else "제목 없는 항목")
        where = f" (증거 안 경로 `{relative}`)" if relative and skip.get("summary") else ""
        lines.append(f"- {label}{where}: {skip_reason_label(skip)}")
    return lines or ["- 없음"]


def roots_for(run_summary: Mapping[str, object]) -> list[Path]:
    return evidence_relative_roots(run_summary) if run_summary else []


def conditions_line(submission_manifest: Mapping[str, object]) -> str:
    options = _mapping(submission_manifest.get("options"))
    include_all = " (표시한 항목 전부 포함 옵션 사용)" if options.get("include_all") else ""
    max_items = options.get("max_items")
    cap = f"{max_items:,}건" if isinstance(max_items, int) and max_items > 0 else "제한 없음"
    return f"- 적용 조건: 보고서 포함으로 표시한 항목{include_all}, 해시 산출 최대 {cap}. 숨긴 항목 없음."


def _cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def review_table(heading: str, rows: Sequence[Mapping[str, object]], empty: str) -> list[str]:
    """Indicator / compare review rows as a table: 항목 · 판단 · 보고서 포함 · 태그 · 메모."""
    if not rows:
        return [heading, "", empty, ""]
    lines = [heading, "", "| 항목 | 판단 | 보고서 포함 | 태그 | 메모 |", "|---|---|---|---|---|"]
    for row in rows:
        cells = (
            f"`{row.get('summary')}`",
            review_status_label(row.get("status")),
            "포함" if row.get("include_in_report") else "제외",
            row.get("tags") or "없음",
            row.get("note") or "없음",
        )
        lines.append("| " + " | ".join(_cell(cell) for cell in cells) + " |")
    return [*lines, ""]


def technical_appendix_lines(run_summary: Mapping[str, object]) -> list[str]:
    processing = _mapping(run_summary.get("processing"))
    source = _mapping(run_summary.get("source"))
    warnings = processing.get("warnings") if isinstance(processing.get("warnings"), list) else []
    caps = _mapping(processing.get("caps"))
    lines = [
        "## 9. 기술 부록",
        "",
        f"- 처리 프로파일: `{processing.get('profile_label', '')}`",
        f"- 처리 경고 수: {processing.get('warning_count', 0)}",
        f"- 가장 높은 경고 수준: `{processing.get('highest_warning_level', 'none')}`",
        f"- 추출 최대 바이트: {int(caps.get('max_extract_size_bytes') or 0):,}",
        f"- 추출 최대 파일 수: {int(caps.get('max_file_count') or 0):,}",
        f"- 원본 종류: `{source.get('kind', '')}`",
        f"- 원본 경로: `{source.get('source_path', '')}`",
        f"- 분석 범위 루트: `{run_summary.get('scan_scope_root', '')}`",
        "",
    ]
    if warnings:
        lines.extend(["### 9.1 처리 경고", ""])
        for item in warnings[:20]:
            if isinstance(item, Mapping):
                lines.append(f"- `{item.get('step', '')}` [{item.get('level', '')}]: {item.get('message', '')}")
        lines.append("")
    return lines


def hash_only_lines(submission_manifest: Mapping[str, object], roots: Sequence[Path]) -> list[str]:
    lines = ["## 2. 제출 증거 해시 목록", ""]
    values = submission_manifest.get("items")
    hashed = [item for item in values if isinstance(item, Mapping)] if isinstance(values, list) else []
    for index, item in enumerate(hashed, start=1):
        evidence = _mapping(item.get("evidence"))
        hashes = _mapping(evidence.get("hashes"))
        relative = str(evidence.get("relative_path") or "") or evidence_relative_path(evidence.get("path"), roots)
        where = f"`{relative}`" if relative else "원래 위치 알 수 없음(복구·추출 사본 또는 증거 루트 밖)"
        lines.extend(
            [
                f"### 2.{index}. {item.get('summary') or evidence.get('name') or '제목 없는 항목'}",
                "",
                f"- 증거 안 경로: {where}",
                f"- MD5: `{hashes.get('md5', '')}`",
                f"- SHA-1: `{hashes.get('sha1', '')}`",
                f"- SHA-256: `{hashes.get('sha256', '')}`",
                "",
            ]
        )
    if not hashed:
        lines.extend(["- 해시 산출된 제출 증거가 없음.", ""])
    return [*lines, "## 3. 해시 산출 제외 항목", "", *skipped_lines(submission_manifest, roots), ""]
