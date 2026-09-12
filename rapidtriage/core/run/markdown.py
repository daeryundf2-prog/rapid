"""Run markdown report assembly helpers."""

from __future__ import annotations

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
    return render_run_markdown_report(report_context)


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
