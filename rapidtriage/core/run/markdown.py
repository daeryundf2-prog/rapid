"""Run markdown report assembly helpers."""

from __future__ import annotations

import re
from collections.abc import Mapping

from ..reporting import (
    build_run_report_context,
    render_run_markdown_report,
)

__all__ = [
    "append_artifact_summary_rows",
    "append_extract_rows",
    "append_related_document_rows",
    "append_timeline_rows",
    "apply_report_disclosures",
    "build_disclosure_section",
    "build_key_hit_rows",
    "build_markdown_report",
]


def build_markdown_report(
    summary_payload: Mapping[str, object],
    *,
    docs_payload: Mapping[str, object] | None = None,
    files_payload: Mapping[str, object] | None = None,
    docs_extract_payload: Mapping[str, object] | None = None,
    files_extract_payload: Mapping[str, object] | None = None,
    artifact_payloads: Mapping[str, Mapping[str, object]] | None = None,
    timeline_payload: Mapping[str, object] | None = None,
    indicators_payload: Mapping[str, object] | None = None,
) -> str:
    report_context = build_run_report_context(
        summary_payload,
        docs_payload=docs_payload,
        files_payload=files_payload,
        docs_extract_payload=docs_extract_payload,
        files_extract_payload=files_extract_payload,
        artifact_payloads=artifact_payloads,
        timeline_payload=timeline_payload,
        indicators_payload=indicators_payload,
    )
    return apply_report_disclosures(render_run_markdown_report(report_context), summary_payload)


_DOC_MATCH_LINE_RE = re.compile(r"^- Document matches: (\d+)$", re.MULTILINE)


def apply_report_disclosures(markdown: str, summary_payload: Mapping[str, object]) -> str:
    """Insert the parser-quality disclosure section and demote "Document matches".

    The keyword-hit count is not a headline: the overview shows document
    candidates and how many had text, with matches as a detail.
    """
    disclosures = summary_payload.get("disclosures") if isinstance(summary_payload.get("disclosures"), Mapping) else {}
    documents = disclosures.get("documents") if isinstance(disclosures.get("documents"), Mapping) else {}

    def doc_line(match: re.Match[str]) -> str:
        return (
            f"- 문서 후보: {documents.get('candidate_count', '?')}"
            f" (텍스트 추출 {documents.get('indexed_with_text_count', '?')}, 암호화 {documents.get('encrypted_count', '?')},"
            f" 키워드 일치 {match.group(1)})"
        )

    markdown = _DOC_MATCH_LINE_RE.sub(doc_line, markdown, count=1)
    markdown = _DOC_MATCH_LINE_RE.sub(lambda match: f"- 문서 키워드 일치(후보 중): {match.group(1)}", markdown)
    markdown = markdown.replace("Deep - uncapped extraction", "Deep - extraction without size limits")
    section = build_disclosure_section(disclosures)
    anchor = "\n## Mode profile"
    if anchor in markdown:
        return markdown.replace(anchor, "\n" + section + anchor, 1)
    return markdown.rstrip("\n") + "\n\n" + section


def build_disclosure_section(disclosures: Mapping[str, object]) -> str:
    lines = ["## 처리 한계·공개 사항 / Disclosures", ""]
    timezone = disclosures.get("timezone") if isinstance(disclosures.get("timezone"), Mapping) else {}
    evidence_tz = timezone.get("evidence_timezone") if isinstance(timezone, Mapping) else None
    lines.append("- 시각 저장 기준: UTC (ISO 8601, +00:00)")
    if isinstance(evidence_tz, Mapping) and evidence_tz:
        lines.append(
            f"- 증거 시스템 시간대: `{evidence_tz.get('name') or evidence_tz.get('label')}`"
            f" (UTC 오프셋 {evidence_tz.get('utc_offset') or evidence_tz.get('bias_minutes')}, 레지스트리 TimeZoneInformation)"
        )
    else:
        lines.append("- 증거 시스템 시간대: 레지스트리에서 확인되지 않음")
    note = str(disclosures.get("acquisition_copy_note") or "")
    if note:
        lines.append(f"- 취득 사본 시각: {note}")
    registry = disclosures.get("registry_context") if isinstance(disclosures.get("registry_context"), Mapping) else {}
    labels = {
        "computer_name": "컴퓨터 이름",
        "os_version": "OS 버전",
        "current_control_set": "현재 ControlSet",
        "last_shutdown_at": "마지막 종료 시각",
        "transaction_log_disclosures": "하이브 트랜잭션 로그",
        "cap_disclosure": "레지스트리 상한",
    }
    for key, label in labels.items():
        if registry.get(key) not in (None, "", [], {}):
            lines.append(f"- {label}: `{registry.get(key)}`")
    tools = disclosures.get("missing_tools") if isinstance(disclosures.get("missing_tools"), Mapping) else {}
    missing = [f"{name} — {info.get('note')}" for name, info in tools.items() if isinstance(info, Mapping) and not info.get("available")]
    lines.append("- 누락 도구: " + ("; ".join(missing) if missing else "없음"))
    caps = disclosures.get("caps") if isinstance(disclosures.get("caps"), Mapping) else {}
    if caps:
        lines.append("- 상한/절단 적용 단계 (결과가 전수가 아님):")
        for step, flags in caps.items():
            shown = ", ".join(str(item) for item in list(flags)[:8])
            lines.append(f"  - `{step}`: {shown}")
    else:
        lines.append("- 상한/절단 적용 단계: 없음")
    excluded = disclosures.get("timeline_excluded") if isinstance(disclosures.get("timeline_excluded"), Mapping) else {}
    if excluded:
        lines.append(
            f"- 타임라인 제외: 범위 밖 시각 {excluded.get('out_of_range', 0)}건, 중복 {excluded.get('duplicates', 0)}건,"
            f" 사본 시각만 있는 파일 {excluded.get('copy_time_candidates', 0)}건"
        )
    indicators = disclosures.get("indicators") if isinstance(disclosures.get("indicators"), Mapping) else {}
    if indicators:
        lines.append(
            f"- {indicators.get('display_label') or '지표'}: {indicators.get('rule_status_message') or ''}"
            f" (상한 전 {indicators.get('total_before_cap')}건, 절단 {bool(indicators.get('truncated'))})"
        )
    files = disclosures.get("files") if isinstance(disclosures.get("files"), Mapping) else {}
    if files.get("excluded_file_count"):
        lines.append(
            f"- 파일 후보 제외: {files.get('excluded_file_count')}건 (사유 {dict(files.get('exclusion_reason_counts') or {})},"
            f" 범주 {dict(files.get('excluded_category_counts') or {})})"
        )
    documents = disclosures.get("documents") if isinstance(disclosures.get("documents"), Mapping) else {}
    if documents.get("text_status_counts"):
        lines.append(f"- 문서 텍스트 추출 상태: {dict(documents.get('text_status_counts') or {})}")
    notes = disclosures.get("collection_notes") if isinstance(disclosures.get("collection_notes"), Mapping) else {}
    for kind, items in notes.items():
        lines.append(f"- `{kind}` 수집 메모: {'; '.join(str(item) for item in items)}")
    lines.append("")
    return "\n".join(lines)


def build_key_hit_rows(
    summary_payload: Mapping[str, object],
    *,
    docs_payload: Mapping[str, object],
    files_payload: Mapping[str, object],
    artifact_payloads: Mapping[str, Mapping[str, object]],
    timeline_payload: Mapping[str, object],
) -> list[str]:
    rows: list[str] = []
    matched_rules = summary_payload.get("matched_rules", [])
    if isinstance(matched_rules, list) and matched_rules:
        rows.append(f"Matched rules: {', '.join(str(item) for item in matched_rules[:5])}")

    ioc_hits = summary_payload.get("ioc_hits", [])
    if isinstance(ioc_hits, list):
        for hit in ioc_hits[:3]:
            if not isinstance(hit, dict):
                continue
            rows.append(
                f"IOC `{hit.get('value')}` detected via `{hit.get('type')}`"
                f" (rule `{hit.get('rule_id')}`)"
            )

    for item in docs_payload.get("results", [])[:3]:
        if not isinstance(item, dict):
            continue
        keywords = ", ".join(str(keyword) for keyword in item.get("matched_keywords", []))
        rows.append(f"Document hit `{item.get('path')}` keywords={keywords or 'none'}")

    for item in files_payload.get("candidates", [])[:2]:
        if not isinstance(item, dict):
            continue
        rows.append(
            f"File candidate `{item.get('path')}` categories={', '.join(str(value) for value in item.get('categories', []))}"
        )

    for kind, payload in artifact_payloads.items():
        artifact_count = int(payload.get("summary", {}).get("artifact_count", 0))
        if artifact_count:
            rows.append(f"Artifact collector `{kind}` returned {artifact_count} row(s)")

    for event in timeline_payload.get("events", [])[:2]:
        if not isinstance(event, dict):
            continue
        rows.append(
            f"Timeline `{event.get('timestamp')}` `{event.get('event_type')}` — {event.get('summary')}"
        )

    seen: set[str] = set()
    deduped: list[str] = []
    for row in rows:
        if row in seen:
            continue
        seen.add(row)
        deduped.append(row)
    return deduped[:10]


def append_related_document_rows(lines: list[str], results: object) -> None:
    if not isinstance(results, list) or not results:
        lines.append("- none")
        return
    for item in results[:10]:
        if not isinstance(item, dict):
            continue
        keywords = ", ".join(str(keyword) for keyword in item.get("matched_keywords", [])) or "none"
        lines.append(
            f"- `{item.get('path')}` ({item.get('kind')}) keywords={keywords}: {item.get('preview')}"
        )
        matched_rules = item.get("matched_rules", [])
        if isinstance(matched_rules, list) and matched_rules:
            lines.append(f"  - matched_rules: {', '.join(str(rule_id) for rule_id in matched_rules)}")
        ioc_hits = item.get("ioc_hits", [])
        if isinstance(ioc_hits, list) and ioc_hits:
            values = ", ".join(str(hit.get('value')) for hit in ioc_hits[:5] if isinstance(hit, dict))
            lines.append(f"  - ioc_hits: {values}")


def append_artifact_summary_rows(lines: list[str], artifact_payloads: Mapping[str, Mapping[str, object]]) -> None:
    if not artifact_payloads:
        lines.append("- none")
        return
    for kind, payload in artifact_payloads.items():
        summary = payload.get("summary", {})
        lines.append(
            f"- `{kind}` count={summary.get('artifact_count', 0)}"
            f" types={dict(summary.get('artifact_type_counts', {}))}"
        )
        artifacts = payload.get("artifacts", [])
        if not isinstance(artifacts, list):
            continue
        for artifact in artifacts[:3]:
            if not isinstance(artifact, dict):
                continue
            lines.append(
                f"  - `{artifact.get('artifact_type')}` `{artifact.get('path')}` provider=`{artifact.get('provider')}`"
            )


def append_timeline_rows(lines: list[str], timeline_payload: Mapping[str, object]) -> None:
    summary = timeline_payload.get("summary", {})
    events = timeline_payload.get("events", [])
    if not isinstance(events, list) or not events:
        lines.append("- none")
        return
    lines.extend(
        [
            f"- Event count: {summary.get('event_count', 0)}",
            f"- Earliest event: `{summary.get('earliest_event_at')}`",
            f"- Latest event: `{summary.get('latest_event_at')}`",
        ]
    )
    for event in events[:15]:
        if not isinstance(event, dict):
            continue
        lines.append(
            f"- `{event.get('timestamp')}` `{event.get('source')}` `{event.get('event_type')}`"
            f" `{event.get('path')}` — {event.get('summary')}"
        )
        matched_rules = event.get("matched_rules", [])
        if isinstance(matched_rules, list) and matched_rules:
            lines.append(f"  - matched_rules: {', '.join(str(rule_id) for rule_id in matched_rules)}")
        ioc_hits = event.get("ioc_hits", [])
        if isinstance(ioc_hits, list) and ioc_hits:
            values = ", ".join(str(hit.get('value')) for hit in ioc_hits[:5] if isinstance(hit, dict))
            lines.append(f"  - ioc_hits: {values}")


def append_extract_rows(
    lines: list[str],
    *,
    title: str,
    payload: Mapping[str, object],
    source_label: str,
) -> None:
    lines.extend([title, ""])
    summary = payload.get("summary", {})
    lines.append(
        f"- selected={summary.get('selected_count', 0)} extracted={summary.get('extracted_count', 0)}"
        f" skipped={summary.get('skipped_count', 0)} source={source_label}"
    )
    entries = payload.get("entries", [])
    if isinstance(entries, list) and entries:
        for entry in entries[:10]:
            if not isinstance(entry, dict):
                continue
            lines.append(
                f"  - `{entry.get('original_path')}` -> `{entry.get('extracted_path')}`"
                f" size={entry.get('size')} sha256={entry.get('sha256')}"
            )
    else:
        lines.append("  - none")
