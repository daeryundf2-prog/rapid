"""Run step rows and warning-level helpers."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from pathlib import Path

__all__ = [
    "annotate_step",
    "build_extract_step",
    "build_silent_failure_step",
    "build_step_rows",
    "count_skip_reasons",
    "docs_index_warning_level",
    "docs_index_warning_messages",
    "docs_warning_level",
    "docs_warning_messages",
    "extract_warning_level",
    "extract_warning_messages",
    "files_warning_level",
    "files_warning_messages",
    "highest_warning_level",
    "mark_reused_step",
]


def build_step_rows(
    *,
    manifest_payload: Mapping[str, object],
    docs_payload: Mapping[str, object],
    files_payload: Mapping[str, object],
    docs_extract_payload: Mapping[str, object],
    files_extract_payload: Mapping[str, object],
    artifact_payloads: Mapping[str, Mapping[str, object]],
    timeline_payload: Mapping[str, object],
    indicators_payload: Mapping[str, object],
    outputs: Mapping[str, Path],
    reused_outputs: set[str] | None = None,
) -> list[dict[str, object]]:
    reused_outputs = reused_outputs or set()
    provider_count = len(manifest_payload.get("providers", []))
    artifact_count_by_kind = {
        kind: int(payload.get("summary", {}).get("artifact_count", 0))
        for kind, payload in artifact_payloads.items()
    }
    rows: list[dict[str, object]] = [
        mark_reused_step(
            annotate_step(
            {
                "name": "manifest",
                "status": "completed",
                "output": str(outputs["manifest"]),
                "provider_count": provider_count,
            },
            warning_level="notice" if provider_count == 0 else "none",
            warning_messages=["No manifest providers were collected."] if provider_count == 0 else [],
            ),
            reused_outputs,
        ),
        mark_reused_step(
            annotate_step(
            {
                "name": "docs",
                "status": "completed",
                "output": str(outputs["docs"]),
                "candidate_count": int(docs_payload.get("summary", {}).get("candidate_count", 0)),
                "match_count": int(docs_payload.get("summary", {}).get("match_count", 0)),
            },
            warning_level=docs_warning_level(docs_payload),
            warning_messages=docs_warning_messages(docs_payload),
            ),
            reused_outputs,
        ),
        mark_reused_step(
            annotate_step(
            {
                "name": "docs-index",
                "status": "completed",
                "output": str(outputs["docs_index"]),
                "strategy": str(docs_payload.get("index", {}).get("strategy", "")),
                "document_count": int(docs_payload.get("index", {}).get("document_count", 0)),
                "term_count": int(docs_payload.get("index", {}).get("term_count", 0)),
            },
            warning_level=docs_index_warning_level(docs_payload),
            warning_messages=docs_index_warning_messages(docs_payload),
            ),
            reused_outputs,
        ),
        mark_reused_step(
            annotate_step(
            {
                "name": "files",
                "status": "completed",
                "output": str(outputs["files"]),
                "scanned_file_count": int(files_payload.get("summary", {}).get("scanned_file_count", 0)),
                "candidate_count": int(files_payload.get("summary", {}).get("candidate_count", 0)),
            },
            warning_level=files_warning_level(files_payload),
            warning_messages=files_warning_messages(files_payload),
            ),
            reused_outputs,
        ),
    ]
    for kind, payload in artifact_payloads.items():
        artifact_count = artifact_count_by_kind[kind]
        parser_error_count = int(payload.get("summary", {}).get("parser_error_count", 0))
        rows.append(
            mark_reused_step(
                annotate_step(
                {
                    "name": f"artifacts-{kind}",
                    "status": "failed_isolated" if parser_error_count else "completed",
                    "output": str(outputs[f"artifacts_{kind}"]),
                    "artifact_count": artifact_count,
                    "parser_error_count": parser_error_count,
                },
                warning_level="failed" if parser_error_count else ("notice" if artifact_count == 0 else "none"),
                warning_messages=[f"{kind} parser reported {parser_error_count} isolated error(s)."]
                if parser_error_count
                else ([f"No {kind} artifact rows were collected."] if artifact_count == 0 else []),
                ),
                reused_outputs,
            )
        )
    docs_extract_step = build_extract_step(
        "docs-extract",
        outputs["docs_extract_manifest"],
        docs_extract_payload,
    )
    files_extract_step = build_extract_step(
        "files-extract",
        outputs["files_extract_manifest"],
        files_extract_payload,
    )
    timeline_count = int(timeline_payload.get("summary", {}).get("event_count", 0))
    indicator_count = int(indicators_payload.get("summary", {}).get("indicator_count", 0))
    matched_indicator_count = int(indicators_payload.get("summary", {}).get("matched_indicator_count", 0))
    rows.extend(
        [
            docs_extract_step,
            files_extract_step,
            mark_reused_step(
                annotate_step(
                {
                    "name": "timeline",
                    "status": "completed",
                    "output": str(outputs["timeline"]),
                    "event_count": timeline_count,
                    "report": str(outputs["timeline_report"]),
                },
                warning_level="notice" if timeline_count == 0 else "none",
                warning_messages=[
                    "No timeline events were produced. Confirm the source has supported timestamps/artifacts."
                ]
                if timeline_count == 0
                else [],
                ),
                reused_outputs,
            ),
            mark_reused_step(
                annotate_step(
                {
                    "name": "indicators",
                    "status": "completed",
                    "output": str(outputs["indicators"]),
                    "indicator_count": indicator_count,
                    "matched_indicator_count": matched_indicator_count,
                },
                warning_level="notice" if indicator_count == 0 else "none",
                warning_messages=[
                    "No URL, domain, IP, or hash indicators were summarized from the run outputs."
                ]
                if indicator_count == 0
                else [],
                ),
                reused_outputs,
            ),
        ]
    )
    return [mark_reused_step(row, reused_outputs) for row in rows]


def build_silent_failure_step(report: Mapping[str, object]) -> dict[str, object]:
    status = str(report.get("status") or "unknown")
    risk_count = int(report.get("risk_check_count") or 0)
    check_count = int(report.get("check_count") or 0)
    level = "none"
    if status == "failed":
        level = "failed"
    elif status == "warning":
        level = "warning"
    elif status == "notice":
        level = "notice"
    messages = []
    if level != "none":
        messages.append(
            f"Silent-failure detector found {risk_count} risk check(s) across {check_count} checks."
        )
    return annotate_step(
        {
            "name": "silent-failure-detector",
            "status": status,
            "output": "",
            "check_count": check_count,
            "risk_check_count": risk_count,
            "silent_failure_risk": bool(report.get("silent_failure_risk")),
        },
        warning_level=level,
        warning_messages=messages,
    )


def mark_reused_step(row: dict[str, object], reused_outputs: set[str]) -> dict[str, object]:
    name = str(row.get("name") or "")
    if name in reused_outputs:
        row["status"] = "reused"
        row["reused"] = True
    else:
        row["reused"] = False
    return row


def build_extract_step(name: str, output: Path, payload: Mapping[str, object]) -> dict[str, object]:
    summary = payload.get("summary", {})
    selected_count = int(summary.get("selected_count", 0)) if isinstance(summary, Mapping) else 0
    extracted_count = int(summary.get("extracted_count", 0)) if isinstance(summary, Mapping) else 0
    skipped_count = int(summary.get("skipped_count", 0)) if isinstance(summary, Mapping) else 0
    skip_reason_counts = count_skip_reasons(payload)
    warning_messages = extract_warning_messages(
        selected_count=selected_count,
        extracted_count=extracted_count,
        skipped_count=skipped_count,
        skip_reason_counts=skip_reason_counts,
    )
    warning_level = extract_warning_level(skip_reason_counts, selected_count=selected_count, skipped_count=skipped_count)
    status = "completed"
    if selected_count and skipped_count and not extracted_count:
        status = "skipped"
    elif skipped_count:
        status = "completed_with_warnings"
    return annotate_step(
        {
            "name": name,
            "status": status,
            "output": str(output),
            "selected_count": selected_count,
            "extracted_count": extracted_count,
            "skipped_count": skipped_count,
            "skip_reasons": skip_reason_counts,
        },
        warning_level=warning_level,
        warning_messages=warning_messages,
    )


def annotate_step(
    row: dict[str, object],
    *,
    warning_level: str,
    warning_messages: list[str],
) -> dict[str, object]:
    row["warning_level"] = warning_level
    row["warning_messages"] = warning_messages
    return row


def docs_warning_level(payload: Mapping[str, object]) -> str:
    summary = payload.get("summary", {})
    candidate_count = int(summary.get("candidate_count", 0)) if isinstance(summary, Mapping) else 0
    match_count = int(summary.get("match_count", 0)) if isinstance(summary, Mapping) else 0
    if candidate_count == 0:
        return "notice"
    if match_count == 0:
        return "notice"
    return "none"


def docs_warning_messages(payload: Mapping[str, object]) -> list[str]:
    summary = payload.get("summary", {})
    candidate_count = int(summary.get("candidate_count", 0)) if isinstance(summary, Mapping) else 0
    match_count = int(summary.get("match_count", 0)) if isinstance(summary, Mapping) else 0
    if candidate_count == 0:
        return ["No supported document candidates were found."]
    if match_count == 0:
        return ["Documents were scanned, but no configured keywords matched."]
    return []


def docs_index_warning_level(payload: Mapping[str, object]) -> str:
    index = payload.get("index", {})
    document_count = int(index.get("document_count", 0)) if isinstance(index, Mapping) else 0
    return "notice" if document_count == 0 else "none"


def docs_index_warning_messages(payload: Mapping[str, object]) -> list[str]:
    index = payload.get("index", {})
    document_count = int(index.get("document_count", 0)) if isinstance(index, Mapping) else 0
    if document_count == 0:
        return ["No documents were added to the keyword index."]
    return []


def files_warning_level(payload: Mapping[str, object]) -> str:
    summary = payload.get("summary", {})
    scanned_count = int(summary.get("scanned_file_count", 0)) if isinstance(summary, Mapping) else 0
    candidate_count = int(summary.get("candidate_count", 0)) if isinstance(summary, Mapping) else 0
    if scanned_count == 0:
        return "warning"
    if candidate_count == 0:
        return "notice"
    return "none"


def files_warning_messages(payload: Mapping[str, object]) -> list[str]:
    summary = payload.get("summary", {})
    scanned_count = int(summary.get("scanned_file_count", 0)) if isinstance(summary, Mapping) else 0
    candidate_count = int(summary.get("candidate_count", 0)) if isinstance(summary, Mapping) else 0
    if scanned_count == 0:
        return ["No files were scanned. Check the evidence root or mounted-image path."]
    if candidate_count == 0:
        return ["Files were scanned, but no profile-matched candidates were found."]
    return []


def count_skip_reasons(payload: Mapping[str, object]) -> dict[str, int]:
    skipped = payload.get("skipped", [])
    counts: Counter[str] = Counter()
    if not isinstance(skipped, list):
        return {}
    for item in skipped:
        if not isinstance(item, dict):
            continue
        reason = str(item.get("reason") or "unknown")
        counts[reason] += 1
    return dict(sorted(counts.items()))


def extract_warning_level(
    skip_reason_counts: Mapping[str, int],
    *,
    selected_count: int,
    skipped_count: int,
) -> str:
    if not skipped_count:
        return "notice" if selected_count == 0 else "none"
    if any(reason in skip_reason_counts for reason in ("max-file-count", "max-extract-size", "missing")):
        return "warning"
    return "notice"


def extract_warning_messages(
    *,
    selected_count: int,
    extracted_count: int,
    skipped_count: int,
    skip_reason_counts: Mapping[str, int],
) -> list[str]:
    messages: list[str] = []
    if selected_count == 0:
        messages.append("No items matched the extraction filters.")
    if skipped_count and not extracted_count:
        messages.append("Selected items were not extracted; review skip reasons before reporting.")
    elif skipped_count:
        messages.append("Some selected items were skipped during extraction.")
    if "read-only" in skip_reason_counts:
        messages.append("Extraction skipped by read-only profile.")
    if "dry-run" in skip_reason_counts:
        messages.append("Extraction skipped because dry run was enabled.")
    if "max-file-count" in skip_reason_counts:
        messages.append("Extraction capped by max file count.")
    if "max-extract-size" in skip_reason_counts:
        messages.append("Extraction capped by max extract size.")
    if "missing" in skip_reason_counts:
        messages.append("Some selected source paths were missing.")
    if "destination-exists" in skip_reason_counts:
        messages.append("Existing destination files were preserved; enable overwrite only when intended.")
    return messages


def highest_warning_level(levels: list[str]) -> str:
    priority = {"none": 0, "notice": 1, "warning": 2, "failed": 3}
    if not levels:
        return "none"
    return max(levels, key=lambda level: priority.get(level, 0))
