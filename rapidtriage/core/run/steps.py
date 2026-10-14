"""Run step rows and warning-level helpers."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from pathlib import Path

from ..extract import extract_manifest_disabled

__all__ = [
    "annotate_step",
    "apply_cap_disclosures",
    "apply_row_truncation_warnings",
    "apply_silent_failure_verdicts",
    "build_extract_step",
    "build_silent_failure_step",
    "build_step_rows",
    "collect_cap_disclosures",
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
        kind_summary = payload.get("summary", {}) if isinstance(payload.get("summary"), Mapping) else {}
        parser_error_count = int(kind_summary.get("parser_error_count", 0))
        skipped = str(kind_summary.get("collection_status") or "") == "skipped"
        notes = [str(item) for item in kind_summary.get("collection_notes") or [] if str(item)]
        skip_reasons = kind_summary.get("skip_reasons") if isinstance(kind_summary.get("skip_reasons"), Mapping) else {}
        messages: list[str]
        if parser_error_count:
            level = "failed"
            messages = [f"{kind} parser reported {parser_error_count} isolated error(s)."]
        elif skipped:
            level = "notice"
            reasons = ", ".join(f"{reason} ({count})" for reason, count in skip_reasons.items()) or "의존성 없음"
            messages = [f"{kind} 수집 건너뜀: {reasons}"]
        elif artifact_count == 0:
            level = "notice"
            messages = [f"No {kind} artifact rows were collected."]
        else:
            level = "none"
            messages = []
        messages.extend(f"{kind}: {note}" for note in notes)
        if notes and level == "none":
            level = "notice"
        row = {
            "name": f"artifacts-{kind}",
            "status": "failed_isolated" if parser_error_count else ("skipped" if skipped else "completed"),
            "output": str(outputs[f"artifacts_{kind}"]),
            "artifact_count": artifact_count,
            "parser_error_count": parser_error_count,
        }
        if notes:
            row["collection_notes"] = notes
        if skip_reasons:
            row["skip_reasons"] = dict(skip_reasons)
        rows.append(mark_reused_step(annotate_step(row, warning_level=level, warning_messages=messages), reused_outputs))
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
    rows = [mark_reused_step(row, reused_outputs) for row in rows]
    payload_by_step: dict[str, Mapping[str, object]] = {
        "docs": docs_payload,
        "files": files_payload,
        "timeline": timeline_payload,
        "indicators": indicators_payload,
        **{f"artifacts-{kind}": payload for kind, payload in artifact_payloads.items()},
    }
    apply_cap_disclosures(rows, payload_by_step)
    apply_row_truncation_warnings(rows, timeline_payload=timeline_payload, docs_payload=docs_payload)
    return rows


# --- row-level truncation (parser-quality r2) --------------------------------

# Document text statuses that leave a document (partly) unindexed.
DOCS_WARNING_TEXT_STATUSES: dict[str, str] = {
    "too-large": "크기 상한 초과로 본문 미추출",
    "binary-rejected": "비인쇄 문자 비율 초과로 본문 미색인",
}


def _row_truncation_message(kind: str, disclosure: Mapping[str, object]) -> str:
    flags = disclosure.get("flag_counts") if isinstance(disclosure.get("flag_counts"), Mapping) else {}
    counts = disclosure.get("count_fields") if isinstance(disclosure.get("count_fields"), Mapping) else {}
    parts = [f"{name} {count}행" for name, count in list(flags.items())[:6]]
    parts.extend(f"{name}={count}" for name, count in list(counts.items())[:4])
    rows = int(disclosure.get("rows_with_truncation") or 0)
    return f"{kind}: 행 단위 절단 {rows}행 — 원문 일부만 보존됨 ({', '.join(parts)})"


SCAN_CAP_FLAGS = frozenset({"scan_capped", "capped"})


def _scan_coverage_message(kind: str, coverage: Mapping[str, object]) -> str:
    unscanned = int(coverage.get("unscanned") or 0)
    total = int(coverage.get("candidates") or 0)
    if coverage.get("reason") == "cpu-time-budget":
        budget = coverage.get("cpu_budget_seconds")
        reason = f"CPU 시간 예산{f' {budget:g}초' if isinstance(budget, (int, float)) else ''} 소진"
    else:
        reason = f"파일 수 상한 {coverage.get('max_files')}개" if coverage.get("max_files") else "스캔 상한"
    return f"{kind}: 후보 {total}개 중 {unscanned}개 파일 미선별 ({reason})"


def _without_scan_cap_flags(disclosure: Mapping[str, object]) -> dict[str, object]:
    flags = disclosure.get("flag_counts") if isinstance(disclosure.get("flag_counts"), Mapping) else {}
    kept = {name: count for name, count in flags.items() if str(name).rsplit(".", 1)[-1] not in SCAN_CAP_FLAGS}
    rows = int(disclosure.get("rows_with_truncation") or 0)
    if not kept:
        rows = 0
    return {**disclosure, "flag_counts": kept, "rows_with_truncation": rows}


def apply_row_truncation_warnings(
    rows: list[dict[str, object]],
    *,
    timeline_payload: Mapping[str, object],
    docs_payload: Mapping[str, object],
) -> None:
    """Promote row-level truncation to ``warning_level=warning`` on its step.

    Artifact rows disclose cuts with ``<field>_truncated: true`` (eventlog
    text/event_data/script block/command line, prefetch inline reference
    lists, jumplist streams), ``scan_capped`` (synthetic-media) or numeric
    ``*_truncated_rows``/``*_truncated_count`` (eventlog-file rows); the
    timeline pass counts them per kind (``input_row_truncation``). Documents
    with ``too-large``/``binary-rejected`` text status are disclosed on the
    docs step.
    """
    by_name = {str(row.get("name") or ""): row for row in rows}
    timeline_summary = timeline_payload.get("summary") if isinstance(timeline_payload.get("summary"), Mapping) else {}
    truncation = timeline_summary.get("input_row_truncation") if isinstance(timeline_summary, Mapping) else None
    for kind, disclosure in (truncation.items() if isinstance(truncation, Mapping) else ()):
        row = by_name.get(f"artifacts-{kind}")
        if row is None or not isinstance(disclosure, Mapping):
            continue
        row["row_truncation"] = dict(disclosure)
        coverage = disclosure.get("scan_coverage") if isinstance(disclosure.get("scan_coverage"), Mapping) else None
        if coverage:
            # A capped scan is "N of M files not scanned", not a truncated row.
            _add_step_warning(row, _scan_coverage_message(str(kind), coverage), cap=f"scan-coverage:{kind}")
            disclosure = _without_scan_cap_flags(disclosure)
        if int(disclosure.get("rows_with_truncation") or 0) or disclosure.get("count_fields"):
            _add_step_warning(row, _row_truncation_message(str(kind), disclosure), cap=f"row-truncation:{kind}")
        elif int(disclosure.get("preview_only_rows") or 0) or disclosure.get("preview_count_fields"):
            # Display previews only (EVTX message preview): disclosed, no warning.
            message = (
                f"{kind}: 표시용 미리보기 절단 {int(disclosure.get('preview_only_rows') or 0)}행 "
                "(원본 레코드 값은 보존, 경고 아님)"
            )
            messages = row.setdefault("warning_messages", [])
            if isinstance(messages, list) and message not in messages:
                messages.append(message)
            row["warning_level"] = highest_warning_level([str(row.get("warning_level") or "none"), "notice"])
    docs_row = by_name.get("docs")
    summary = docs_payload.get("summary") if isinstance(docs_payload.get("summary"), Mapping) else {}
    status_counts = summary.get("text_status_counts") if isinstance(summary, Mapping) else None
    if docs_row is not None and isinstance(status_counts, Mapping):
        for status, label in DOCS_WARNING_TEXT_STATUSES.items():
            count = int(status_counts.get(status) or 0)
            if count:
                _add_step_warning(docs_row, f"문서 {count}건: {label} ({status})", cap=f"docs:{status}")


def _add_step_warning(row: dict[str, object], message: str, *, cap: str) -> None:
    messages = row.setdefault("warning_messages", [])
    if isinstance(messages, list) and message not in messages:
        messages.append(message)
    caps = row.setdefault("cap_disclosures", [])
    if isinstance(caps, list) and cap not in caps:
        caps.append(cap)
    row["truncated"] = True
    row["warning_level"] = highest_warning_level([str(row.get("warning_level") or "none"), "warning"])


# --- cap / truncation disclosure (parser-quality r1) -------------------------

_CAP_SCAN_MAX_DEPTH = 4
# Keys that are row arrays (large) or per-row data: never walked for flags.
_CAP_SCAN_SKIP_KEYS = frozenset(
    {"artifacts", "candidates", "results", "events", "indicators", "entries", "skipped", "ioc_scanner_hits", "artifact_type_profiles"}
)


def collect_cap_disclosures(payload: Mapping[str, object]) -> list[str]:
    """Dotted paths of every ``*_truncated``/``truncated`` flag set, partial
    collection status and disclosed cap in a stage payload (not its rows)."""
    found: list[str] = []

    def walk(value: object, path: str, depth: int) -> None:
        if depth > _CAP_SCAN_MAX_DEPTH or not isinstance(value, Mapping):
            return
        for key, item in value.items():
            name = str(key)
            if name in _CAP_SCAN_SKIP_KEYS:
                continue
            dotted = f"{path}.{name}" if path else name
            if (name == "truncated" or name.endswith("_truncated") or name == "limit_reached") and item is True:
                found.append(dotted)
            elif name == "collection_status" and item == "partial":
                found.append(f"{dotted}=partial")
            elif isinstance(item, Mapping):
                walk(item, dotted, depth + 1)

    walk(payload, "", 0)
    return sorted(set(found))


def apply_cap_disclosures(rows: list[dict[str, object]], payload_by_step: Mapping[str, Mapping[str, object]]) -> None:
    """Promote every disclosed cap/truncation to ``warning_level=warning``."""
    for row in rows:
        payload = payload_by_step.get(str(row.get("name") or ""))
        if not isinstance(payload, Mapping):
            continue
        caps = collect_cap_disclosures(payload)
        if not caps:
            continue
        row["cap_disclosures"] = caps
        row["truncated"] = True
        messages = row.setdefault("warning_messages", [])
        if isinstance(messages, list):
            shown = ", ".join(caps[:6]) + (f" 외 {len(caps) - 6}건" if len(caps) > 6 else "")
            messages.append(f"상한/절단 적용 — 결과가 전수가 아님: {shown}")
        row["warning_level"] = highest_warning_level([str(row.get("warning_level") or "none"), "warning"])


_SILENT_CHECK_STEPS: tuple[tuple[str, str], ...] = (
    ("artifact-yield-", "artifacts-"),
    ("parser-errors-", "artifacts-"),
    ("files-scanned", "files"),
    ("documents-indexed", "docs"),
    ("keyword-search-yield", "docs"),
    ("timeline-yield", "timeline"),
    ("docs-extract-yield", "docs-extract"),
    ("files-extract-yield", "files-extract"),
    ("target-inventory-truncated", "silent-failure-detector"),
)


def apply_silent_failure_verdicts(rows: list[dict[str, object]], report: Mapping[str, object]) -> None:
    """Copy warning/failed silent-failure checks onto the step they concern."""
    by_name = {str(row.get("name") or ""): row for row in rows}
    checks = report.get("checks") if isinstance(report.get("checks"), list) else []
    for check in checks:
        if not isinstance(check, Mapping) or check.get("level") not in {"warning", "failed"}:
            continue
        check_id = str(check.get("id") or "")
        step_name = ""
        for prefix, target in _SILENT_CHECK_STEPS:
            if check_id.startswith(prefix):
                step_name = target + check_id[len(prefix) :] if target.endswith("-") else target
                break
        row = by_name.get(step_name)
        if row is None:
            continue
        message = f"무응답 실패 점검 {check_id} [{check.get('level')}]: {check.get('message')} ({check.get('detail')})"
        messages = row.setdefault("warning_messages", [])
        if isinstance(messages, list) and message not in messages:
            messages.append(message)
        row.setdefault("silent_failure_checks", []).append(check_id)  # type: ignore[union-attr]
        row["warning_level"] = highest_warning_level([str(row.get("warning_level") or "none"), str(check.get("level"))])


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
    if extract_manifest_disabled(payload):
        return annotate_step(
            {
                "name": name,
                "status": "skipped",
                "output": str(output),
                "disabled": True,
                "disabled_reason": str(payload.get("disabled_reason") or "extraction-disabled"),
                "selected_count": 0,
                "extracted_count": 0,
                "skipped_count": 0,
                "skip_reasons": {},
            },
            warning_level="none",
            warning_messages=[],
        )
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
