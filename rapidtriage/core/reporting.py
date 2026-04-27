from __future__ import annotations

from typing import Dict, List, Mapping


def build_run_report_context(
    summary_payload: Mapping[str, object],
    *,
    docs_payload: Mapping[str, object] | None = None,
    files_payload: Mapping[str, object] | None = None,
    docs_extract_payload: Mapping[str, object] | None = None,
    files_extract_payload: Mapping[str, object] | None = None,
    artifact_payloads: Mapping[str, Mapping[str, object]] | None = None,
    timeline_payload: Mapping[str, object] | None = None,
    indicators_payload: Mapping[str, object] | None = None,
) -> dict[str, object]:
    profile = summary_payload["profile"]
    outputs = summary_payload["outputs"]
    summary = summary_payload["summary"]
    steps = summary_payload["steps"]
    processing = summary_payload.get("processing", {})
    highlights = summary_payload["highlights"]
    docs_payload = docs_payload or {}
    files_payload = files_payload or {}
    docs_extract_payload = docs_extract_payload or {}
    files_extract_payload = files_extract_payload or {}
    artifact_payloads = artifact_payloads or {}
    timeline_payload = timeline_payload or {}
    indicators_payload = indicators_payload or {}
    ordered_artifact_payloads = order_artifact_payloads(artifact_payloads, summary_payload)

    windows_counts = summary.get("windows_provider_artifact_counts", {})
    artifact_outputs = summary.get("artifacts", {})
    keyword_counts = summary.get("matched_keyword_counts", {})
    file_category_counts = summary.get("file_category_counts", {})

    return {
        "overview": {
            "mode": summary_payload["mode"],
            "root": summary_payload["root"],
            "scan_scope_root": summary_payload["scan_scope_root"],
            "generated_at": summary_payload["generated_at"],
            "output_dir": summary_payload["output_dir"],
            "document_match_count": summary["document_match_count"],
            "file_candidate_count": summary["file_candidate_count"],
            "timeline_event_count": summary.get("timeline_event_count", 0),
        },
        "profile": {
            "description": profile["description"],
            "keywords": list(profile["keywords"]),
            "docs_extract_kinds": list(profile["docs_extract_kinds"]),
            "file_extract_categories": list(profile["file_extract_categories"]),
            "file_scan_categories": list(profile["file_scan_categories"]),
        },
        "steps": [
            {
                "name": step["name"],
                "status": step["status"],
                "output": step["output"],
                "details": {key: value for key, value in step.items() if key not in {"name", "status", "output"}},
            }
            for step in steps
        ],
        "processing": {
            "profile_label": processing.get("profile_label", "unknown") if isinstance(processing, Mapping) else "unknown",
            "dry_run": processing.get("dry_run", False) if isinstance(processing, Mapping) else False,
            "read_only": processing.get("read_only", False) if isinstance(processing, Mapping) else False,
            "overwrite": processing.get("overwrite", False) if isinstance(processing, Mapping) else False,
            "caps": processing.get("caps", {}) if isinstance(processing, Mapping) else {},
            "warning_count": processing.get("warning_count", 0) if isinstance(processing, Mapping) else 0,
            "highest_warning_level": processing.get("highest_warning_level", "none") if isinstance(processing, Mapping) else "none",
            "warnings": list(processing.get("warnings", [])) if isinstance(processing, Mapping) and isinstance(processing.get("warnings", []), list) else [],
        },
        "summary": {
            "document_candidate_count": summary["document_candidate_count"],
            "document_match_count": summary["document_match_count"],
            "scanned_file_count": summary["scanned_file_count"],
            "file_candidate_count": summary["file_candidate_count"],
            "docs_extracted_count": summary["docs_extracted_count"],
            "files_extracted_count": summary["files_extracted_count"],
            "preferred_location_candidate_count": summary["preferred_location_candidate_count"],
            "timeline_event_count": summary.get("timeline_event_count", 0),
            "windows_provider_artifact_counts": [
                {"name": name, "count": count}
                for name, count in sorted(windows_counts.items())
            ],
            "artifact_outputs": [
                {
                    "kind": kind,
                    "artifact_count": details["artifact_count"],
                    "output": details["output"],
                }
                for kind, details in artifact_outputs.items()
            ],
            "matched_keyword_counts": [
                {"keyword": keyword, "count": count}
                for keyword, count in keyword_counts.items()
            ],
            "file_category_counts": [
                {"category": category, "count": count}
                for category, count in file_category_counts.items()
            ],
        },
        "key_hits": build_key_hit_rows(
            summary_payload,
            docs_payload=docs_payload,
            files_payload=files_payload,
            artifact_payloads=ordered_artifact_payloads,
            timeline_payload=timeline_payload,
        ),
        "matched_rules": [str(item) for item in summary_payload.get("matched_rules", [])],
        "ioc_hits": [
            {
                "type": hit.get("type"),
                "value": hit.get("value"),
                "rule_id": hit.get("rule_id"),
                "count": hit.get("count", 1),
            }
            for hit in summary_payload.get("ioc_hits", [])
            if isinstance(hit, dict)
        ],
        "indicator_summary": build_indicator_summary_rows(indicators_payload),
        "related_documents": summarize_document_hits(docs_payload.get("results", []), limit=10),
        "recent_file_candidates": list(highlights.get("recent_file_candidates", [])),
        "large_file_candidates": list(highlights.get("large_file_candidates", [])),
        "preferred_location_candidates": list(highlights.get("preferred_location_candidates", [])),
        "artifact_summary": build_artifact_summary_rows(ordered_artifact_payloads),
        "timeline": build_timeline_rows(timeline_payload),
        "extracts": [
            build_extract_context("### Docs extract", docs_extract_payload),
            build_extract_context("### Files extract", files_extract_payload),
        ],
        "compare_results": build_compare_rows(summary_payload.get("compare_results")),
        "outputs": [{"name": name, "path": path} for name, path in outputs.items()],
    }


def order_artifact_payloads(
    artifact_payloads: Mapping[str, Mapping[str, object]],
    summary_payload: Mapping[str, object],
) -> Dict[str, Mapping[str, object]]:
    profile = summary_payload.get("profile", {})
    preferred: list[str] = []
    if isinstance(profile, Mapping):
        preferred = [str(kind) for kind in profile.get("artifacts_kinds", [])]
    ordered: Dict[str, Mapping[str, object]] = {}
    for kind in preferred:
        if kind in artifact_payloads:
            ordered[kind] = artifact_payloads[kind]
    for kind in sorted(str(kind) for kind in artifact_payloads):
        if kind not in ordered:
            ordered[kind] = artifact_payloads[kind]
    return ordered


def build_indicator_summary_rows(payload: Mapping[str, object], *, limit: int = 15) -> list[dict[str, object]]:
    indicators = payload.get("indicators")
    if not isinstance(indicators, list):
        return []
    rows: list[dict[str, object]] = []
    for item in indicators[:limit]:
        if not isinstance(item, Mapping):
            continue
        risk_flags = item.get("risk_flags")
        matched_rules = item.get("matched_rules")
        rows.append(
            {
                "type": str(item.get("type") or ""),
                "value": str(item.get("value") or ""),
                "count": int(item.get("count") or 0),
                "classification": str(item.get("classification") or ""),
                "risk_flags": [str(flag) for flag in risk_flags] if isinstance(risk_flags, list) else [],
                "matched_rules": [str(rule) for rule in matched_rules] if isinstance(matched_rules, list) else [],
            }
        )
    return rows


def render_run_markdown_report(report_context: Mapping[str, object]) -> str:
    overview = report_context["overview"]
    profile = report_context["profile"]
    steps = report_context["steps"]
    processing = report_context["processing"]
    summary = report_context["summary"]

    lines = [
        "# rapidtriage run report",
        "",
        "> Submission-ready markdown template generated from rapidtriage run results.",
        "",
        "## 사건 개요 / Case overview",
        "",
        f"- Mode: `{overview['mode']}`",
        f"- Root: `{overview['root']}`",
        f"- Scan scope root: `{overview['scan_scope_root']}`",
        f"- Generated at: `{overview['generated_at']}`",
        f"- Output directory: `{overview['output_dir']}`",
        f"- Document matches: {overview['document_match_count']}",
        f"- File candidates: {overview['file_candidate_count']}",
        f"- Timeline events: {overview['timeline_event_count']}",
        "",
        "## Mode profile",
        "",
        f"- Description: {profile['description']}",
        f"- Keywords: {', '.join(profile['keywords'])}",
        f"- Docs extract kinds: {', '.join(profile['docs_extract_kinds'])}",
        f"- File extract categories: {', '.join(profile['file_extract_categories'])}",
        f"- File scan categories: {', '.join(profile['file_scan_categories'])}",
        "",
        "## Processing transparency",
        "",
        f"- Profile: {processing['profile_label']}",
        f"- Read-only: {processing['read_only']}",
        f"- Dry run: {processing['dry_run']}",
        f"- Overwrite extracts: {processing['overwrite']}",
        f"- Max extract bytes: {processing['caps'].get('max_extract_size_bytes', 0)}",
        f"- Max files: {processing['caps'].get('max_file_count', 0)}",
        f"- Warning level: {processing['highest_warning_level']} ({processing['warning_count']} warning/notice item(s))",
        "",
        "### Processing warnings",
        "",
    ]
    if processing["warnings"]:
        for item in processing["warnings"][:20]:
            if not isinstance(item, dict):
                continue
            lines.append(f"- `{item.get('step')}` [{item.get('level')}]: {item.get('message')}")
    else:
        lines.append("- none")

    lines.extend(
        [
            "",
            "## Step outputs",
            "",
        ]
    )
    for step in steps:
        detail_parts = [f"{key}={value}" for key, value in step["details"].items()]
        detail_text = ", ".join(detail_parts) if detail_parts else "no metrics"
        lines.append(f"- `{step['name']}` ({step['status']}): `{step['output']}` — {detail_text}")

    lines.extend(
        [
            "",
            "## Summary",
            "",
            f"- Document candidates: {summary['document_candidate_count']}",
            f"- Document matches: {summary['document_match_count']}",
            f"- Scanned files: {summary['scanned_file_count']}",
            f"- File candidates: {summary['file_candidate_count']}",
            f"- Docs extracted: {summary['docs_extracted_count']}",
            f"- Files extracted: {summary['files_extracted_count']}",
            f"- Preferred-location candidates: {summary['preferred_location_candidate_count']}",
            f"- Timeline events: {summary['timeline_event_count']}",
            "",
            "### Windows provider artifact counts",
            "",
        ]
    )

    if summary["windows_provider_artifact_counts"]:
        for row in summary["windows_provider_artifact_counts"]:
            lines.append(f"- `{row['name']}`: {row['count']}")
    else:
        lines.append("- none")

    lines.extend(["", "### Dedicated artifact outputs", ""])
    if summary["artifact_outputs"]:
        for row in summary["artifact_outputs"]:
            lines.append(f"- `{row['kind']}`: count={row['artifact_count']} output=`{row['output']}`")
    else:
        lines.append("- none")

    lines.extend(["", "### Matched keyword counts", ""])
    if summary["matched_keyword_counts"]:
        for row in summary["matched_keyword_counts"]:
            lines.append(f"- `{row['keyword']}`: {row['count']}")
    else:
        lines.append("- none")

    lines.extend(["", "### File category counts", ""])
    if summary["file_category_counts"]:
        for row in summary["file_category_counts"]:
            lines.append(f"- `{row['category']}`: {row['count']}")
    else:
        lines.append("- none")

    lines.extend(["", "## 핵심 hit / Key hits", ""])
    if report_context["key_hits"]:
        lines.extend([f"- {row}" for row in report_context["key_hits"]])
    else:
        lines.append("- none")

    lines.extend(["", "## Matched rules", ""])
    if report_context["matched_rules"]:
        for rule_id in report_context["matched_rules"]:
            lines.append(f"- `{rule_id}`")
    else:
        lines.append("- none")

    lines.extend(["", "## IOC hits", ""])
    if report_context["ioc_hits"]:
        for hit in report_context["ioc_hits"][:10]:
            lines.append(
                f"- `{hit.get('type')}` `{hit.get('value')}`"
                f" (rule=`{hit.get('rule_id')}`, count={hit.get('count', 1)})"
            )
    else:
        lines.append("- none")

    lines.extend(["", "## Indicator pivots", ""])
    if report_context["indicator_summary"]:
        for item in report_context["indicator_summary"]:
            lines.append(
                f"- `{item.get('type')}` `{item.get('value')}`"
                f" count={item.get('count', 0)} classification=`{item.get('classification', '')}`"
                f" flags={', '.join(str(flag) for flag in item.get('risk_flags', [])) or 'none'}"
                f" rules={', '.join(str(rule) for rule in item.get('matched_rules', [])) or 'none'}"
            )
    else:
        lines.append("- none")

    lines.extend(["", "## 관련 문서 / Related documents", ""])
    append_related_document_rows(lines, report_context["related_documents"])

    lines.extend(["", "## Recent file candidates", ""])
    append_candidate_rows(lines, report_context["recent_file_candidates"])

    lines.extend(["", "## Largest file candidates", ""])
    append_candidate_rows(lines, report_context["large_file_candidates"])

    lines.extend(["", "## Preferred location candidates", ""])
    append_candidate_rows(lines, report_context["preferred_location_candidates"])

    lines.extend(["", "## Artifact summary", ""])
    append_artifact_rows(lines, report_context["artifact_summary"])

    lines.extend(["", "## Timeline", ""])
    append_timeline_section_rows(lines, report_context["timeline"])

    lines.extend(["", "## Extract results", ""])
    for extract in report_context["extracts"]:
        append_extract_section(lines, extract)

    lines.extend(["", "## Compare results", ""])
    if report_context["compare_results"]:
        for item in report_context["compare_results"][:10]:
            lines.append(
                f"- `{item.get('timestamp')}` `{item.get('status')}` `{item.get('path')}` — {item.get('summary')}"
            )
    else:
        lines.append("- none provided (attach compare JSON findings here when available).")

    lines.extend(["", "## Output paths", ""])
    for item in report_context["outputs"]:
        lines.append(f"- `{item['name']}`: `{item['path']}`")
    return "\n".join(lines) + "\n"


def summarize_document_hits(results: object, *, limit: int) -> List[Dict[str, object]]:
    if not isinstance(results, list):
        return []
    items: List[Dict[str, object]] = []
    for row in results[:limit]:
        if not isinstance(row, dict):
            continue
        items.append(
            {
                "path": row.get("path"),
                "kind": row.get("kind"),
                "matched_keywords": list(row.get("matched_keywords", [])),
                "preview": row.get("preview"),
            }
        )
    return items


def build_key_hit_rows(
    summary_payload: Mapping[str, object],
    *,
    docs_payload: Mapping[str, object],
    files_payload: Mapping[str, object],
    artifact_payloads: Mapping[str, Mapping[str, object]],
    timeline_payload: Mapping[str, object],
) -> List[str]:
    rows: List[str] = []
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
        rows.append(f"Artifact collector `{kind}` found {artifact_count} artifacts")

    events = timeline_payload.get("events", [])
    if isinstance(events, list):
        for event in events[:2]:
            if not isinstance(event, dict):
                continue
            rows.append(
                f"Timeline event `{event.get('timestamp')}` `{event.get('event_type')}` at `{event.get('path')}`"
            )
    return rows[:12]


def build_artifact_summary_rows(artifact_payloads: Mapping[str, Mapping[str, object]]) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    for kind, payload in artifact_payloads.items():
        for item in payload.get("artifacts", [])[:10]:
            if not isinstance(item, dict):
                continue
            rows.append(
                {
                    "kind": kind,
                    "artifact_type": item.get("artifact_type"),
                    "path": item.get("path"),
                    "provider": item.get("provider"),
                    "supported": item.get("supported"),
                }
            )
    return rows


def build_timeline_rows(timeline_payload: Mapping[str, object]) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    for item in timeline_payload.get("events", [])[:20]:
        if not isinstance(item, dict):
            continue
        rows.append(
            {
                "timestamp": item.get("timestamp"),
                "source": item.get("source"),
                "event_type": item.get("event_type"),
                "path": item.get("path"),
                "summary": item.get("summary"),
            }
        )
    return rows


def build_extract_context(title: str, payload: Mapping[str, object]) -> Dict[str, object]:
    summary = payload.get("summary", {}) if isinstance(payload, Mapping) else {}
    return {
        "title": title,
        "source_command": payload.get("source_command"),
        "output_dir": payload.get("output_dir"),
        "selected_count": summary.get("selected_count", 0),
        "extracted_count": summary.get("extracted_count", 0),
        "skipped_count": summary.get("skipped_count", 0),
        "entries": list(payload.get("entries", [])) if isinstance(payload, Mapping) else [],
        "skipped": list(payload.get("skipped", [])) if isinstance(payload, Mapping) else [],
    }


def build_compare_rows(compare_results: object) -> List[Dict[str, object]]:
    if not isinstance(compare_results, list):
        return []
    return [item for item in compare_results if isinstance(item, dict)]


def append_related_document_rows(lines: List[str], rows: object) -> None:
    if isinstance(rows, list) and rows:
        for item in rows:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"- `{item['path']}` kind={item['kind']} keywords={', '.join(item['matched_keywords']) or 'none'}"
            )
            lines.append(f"  - preview: {item['preview']}")
    else:
        lines.append("- none")


def append_candidate_rows(lines: List[str], rows: object) -> None:
    if isinstance(rows, list) and rows:
        for item in rows:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"- `{item['path']}` categories={', '.join(item['categories'])} size={item['size']} modified={item['modified_at']}"
            )
    else:
        lines.append("- none")


def append_artifact_rows(lines: List[str], rows: object) -> None:
    if isinstance(rows, list) and rows:
        for item in rows:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"- [{item['kind']}] `{item['artifact_type']}` `{item['path']}`"
                f" provider=`{item['provider']}` supported={item['supported']}"
            )
    else:
        lines.append("- none")


def append_timeline_section_rows(lines: List[str], rows: object) -> None:
    if isinstance(rows, list) and rows:
        for item in rows:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"- `{item['timestamp']}` `{item['source']}` `{item['event_type']}` `{item['path']}` — {item['summary']}"
            )
    else:
        lines.append("- none")


def append_extract_section(lines: List[str], section: Mapping[str, object]) -> None:
    lines.extend(
        [
            section["title"],
            "",
            f"- Source command: `{section['source_command']}`",
            f"- Output dir: `{section['output_dir']}`",
            f"- Selected: {section['selected_count']}",
            f"- Extracted: {section['extracted_count']}",
            f"- Skipped: {section['skipped_count']}",
        ]
    )

    entries = section.get("entries", [])
    if isinstance(entries, list) and entries:
        lines.append("- Entries:")
        for item in entries[:10]:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"  - `{item.get('original_path')}` -> `{item.get('extracted_path')}` sha256=`{item.get('sha256')}`"
            )
    else:
        lines.append("- Entries: none")

    skipped = section.get("skipped", [])
    if isinstance(skipped, list) and skipped:
        lines.append("- Skipped:")
        for item in skipped[:10]:
            if not isinstance(item, dict):
                continue
            lines.append(f"  - `{item.get('original_path')}` reason={item.get('reason')}")
    lines.append("")
