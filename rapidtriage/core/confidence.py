from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Iterable, Mapping

from .docs import write_result


VOLATILE_KEYS = {
    "generated_at",
    "audit",
    "output_dir",
    "root",
    "scan_scope_root",
    "path",
    "source_path",
    "analysis_root",
    "output",
    "outputs",
}


class ConfidenceDashboardError(ValueError):
    """Raised when confidence/explainability inputs are invalid."""


def build_confidence_dashboard(
    run_output: Path,
    *,
    output: Path | None = None,
) -> dict[str, object]:
    summary_path, summary = load_run_summary(run_output)
    records = list(iter_run_records(summary))
    counts: dict[str, int] = {"report-grade": 0, "needs-validation": 0, "triage": 0, "unsupported": 0}
    source_counts: dict[str, dict[str, int]] = {}
    samples: dict[str, list[dict[str, object]]] = {key: [] for key in counts}
    for record in records:
        level = classify_record(record)
        counts[level] += 1
        source = str(record.get("source") or "unknown")
        source_counts.setdefault(source, {key: 0 for key in counts})
        source_counts[source][level] += 1
        if len(samples[level]) < 10:
            samples[level].append(summarize_record(record, level=level))
    total = max(len(records), 1)
    payload = {
        "command": "confidence-dashboard",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "run_summary": str(summary_path),
        "status": "validation-required" if counts["needs-validation"] or counts["unsupported"] else "review-ready",
        "summary": {
            "record_count": len(records),
            "confidence_counts": counts,
            "confidence_percentages": {
                key: round((value / total) * 100, 2) for key, value in counts.items()
            },
            "source_counts": source_counts,
        },
        "samples": samples,
        "operator_guidance": build_confidence_guidance(counts),
    }
    if output is not None:
        write_result(payload, output.expanduser().resolve())
        payload["output"] = str(output.expanduser().resolve())
    return payload


def build_parser_explainability(
    run_output: Path,
    *,
    output: Path | None = None,
    markdown_output: Path | None = None,
    limit: int = 500,
) -> dict[str, object]:
    summary_path, summary = load_run_summary(run_output)
    entries = [build_explainability_entry(record) for record in iter_run_records(summary)]
    if limit:
        entries = entries[:limit]
    status_counts: dict[str, int] = {}
    for entry in entries:
        status = str(entry["explanation_status"])
        status_counts[status] = status_counts.get(status, 0) + 1
    payload = {
        "command": "parser-explainability",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "run_summary": str(summary_path),
        "limit": limit,
        "summary": {
            "entry_count": len(entries),
            "status_counts": status_counts,
            "incomplete_count": status_counts.get("partial", 0) + status_counts.get("missing-source", 0),
        },
        "entries": entries,
        "operator_guidance": [
            "Report-grade findings should include source path/hash, parser name/version, confidence, and offset/index when available.",
            "Rows marked partial or missing-source should be validated against source evidence before final reporting.",
        ],
    }
    if output is not None:
        write_result(payload, output.expanduser().resolve())
        payload["output"] = str(output.expanduser().resolve())
    if markdown_output is not None:
        resolved = markdown_output.expanduser().resolve()
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(render_explainability_markdown(payload), encoding="utf-8")
        payload["markdown_output"] = str(resolved)
    return payload


def build_reproducibility_kit(
    *,
    baseline_run: Path,
    candidate_run: Path,
    output_dir: Path,
) -> dict[str, object]:
    baseline_path, baseline = load_run_summary(baseline_run)
    candidate_path, candidate = load_run_summary(candidate_run)
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    baseline_hashes = build_output_hashes(baseline)
    candidate_hashes = build_output_hashes(candidate)
    output_names = sorted(set(baseline_hashes) | set(candidate_hashes))
    comparisons = []
    for name in output_names:
        base = baseline_hashes.get(name)
        cand = candidate_hashes.get(name)
        comparisons.append(
            {
                "name": name,
                "status": "match" if base and cand and base["sha256"] == cand["sha256"] else "diff",
                "baseline_sha256": base.get("sha256", "") if base else "",
                "candidate_sha256": cand.get("sha256", "") if cand else "",
                "baseline_record_count": base.get("record_count", 0) if base else 0,
                "candidate_record_count": cand.get("record_count", 0) if cand else 0,
            }
        )
    diff_count = sum(1 for item in comparisons if item["status"] != "match")
    payload = {
        "command": "reproducibility-kit",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": "reproducible" if diff_count == 0 else "differences-detected",
        "baseline_run_summary": str(baseline_path),
        "candidate_run_summary": str(candidate_path),
        "summary": {
            "compared_output_count": len(comparisons),
            "diff_count": diff_count,
            "match_count": len(comparisons) - diff_count,
        },
        "comparisons": comparisons,
        "operator_guidance": [
            "Differences can be caused by parser changes, external tool versions, timestamps, or evidence path changes.",
            "Attach this kit when claiming same-input/same-output reproducibility across releases or workstations.",
        ],
    }
    json_path = output_dir / "rapidtriage-reproducibility-kit.json"
    markdown_path = output_dir / "rapidtriage-reproducibility-kit.md"
    write_result(payload, json_path)
    markdown_path.write_text(render_reproducibility_markdown(payload), encoding="utf-8")
    payload["outputs"] = {"json": str(json_path), "markdown": str(markdown_path)}
    return payload


def load_run_summary(run_output: Path) -> tuple[Path, Mapping[str, object]]:
    path = run_output.expanduser().resolve()
    if path.is_dir():
        path = path / "rapidtriage-run-summary.json"
    if not path.is_file():
        raise ConfidenceDashboardError(f"run summary not found: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfidenceDashboardError(f"invalid run summary JSON: {path}") from exc
    if not isinstance(payload, Mapping) or payload.get("command") != "run":
        raise ConfidenceDashboardError(f"not a RapidTriage run summary: {path}")
    return path, payload


def iter_run_records(summary: Mapping[str, object]) -> Iterable[dict[str, object]]:
    outputs = summary.get("outputs")
    if not isinstance(outputs, Mapping):
        return
    for output_name, raw_path in sorted(outputs.items()):
        payload = read_json_path(Path(str(raw_path)))
        if not isinstance(payload, Mapping):
            continue
        source = source_for_output(str(output_name))
        for pointer, row in rows_from_payload(payload):
            yield {
                "source": source,
                "output_name": str(output_name),
                "output_path": str(raw_path),
                "pointer": pointer,
                "row": row,
            }


def rows_from_payload(payload: Mapping[str, object]) -> Iterable[tuple[str, Mapping[str, object]]]:
    for key in ("artifacts", "events", "results", "candidates", "indicators", "entries"):
        value = payload.get(key)
        if isinstance(value, list):
            for index, row in enumerate(value):
                if isinstance(row, Mapping):
                    yield f"/{key}/{index}", row


def source_for_output(output_name: str) -> str:
    if output_name.startswith("artifacts_"):
        return output_name.removeprefix("artifacts_")
    if output_name in {"docs", "files", "timeline", "indicators"}:
        return output_name
    return "other"


def classify_record(record: Mapping[str, object]) -> str:
    row = record.get("row")
    if not isinstance(row, Mapping):
        return "unsupported"
    details = row.get("details") if isinstance(row.get("details"), Mapping) else {}
    if row.get("supported") is False or details.get("supported") is False:
        return "unsupported"
    if details.get("commercial_grade_ready") is False or details.get("validation_required") is True:
        return "needs-validation"
    reportability = str(details.get("reportability") or row.get("reportability") or "").lower()
    confidence = confidence_float(details.get("parser_confidence") or row.get("parser_confidence"))
    if reportability in {"report-grade", "reportable"} and confidence >= 0.85:
        return "report-grade"
    if confidence >= 0.9 and not details.get("validation_required"):
        return "report-grade"
    if reportability == "triage" or confidence < 0.75:
        return "triage"
    return "triage"


def confidence_float(value: object) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value or "").lower()
    return {"high": 0.9, "medium": 0.7, "low": 0.4}.get(text, 0.6)


def summarize_record(record: Mapping[str, object], *, level: str) -> dict[str, object]:
    row = record.get("row") if isinstance(record.get("row"), Mapping) else {}
    details = row.get("details") if isinstance(row.get("details"), Mapping) else {}
    return {
        "level": level,
        "source": record.get("source", ""),
        "pointer": record.get("pointer", ""),
        "artifact_type": row.get("artifact_type") or row.get("event_type") or row.get("kind") or "",
        "path": row.get("path") or details.get("source_path") or details.get("path") or "",
        "parser": details.get("parser") or row.get("provider") or "",
        "parser_confidence": details.get("parser_confidence") or row.get("parser_confidence") or "",
        "validation_required": bool(details.get("validation_required")),
        "commercial_grade_ready": details.get("commercial_grade_ready", ""),
    }


def build_explainability_entry(record: Mapping[str, object]) -> dict[str, object]:
    row = record.get("row") if isinstance(record.get("row"), Mapping) else {}
    details = row.get("details") if isinstance(row.get("details"), Mapping) else {}
    source_path = str(details.get("source_path") or row.get("path") or details.get("path") or "")
    parser = str(details.get("parser") or row.get("provider") or "")
    parser_version = str(details.get("parser_version") or details.get("version") or "")
    offsets = collect_offset_fields(row)
    hashes = collect_hash_fields(row)
    status = "complete" if source_path and parser else "partial"
    if not source_path:
        status = "missing-source"
    return {
        "source": record.get("source", ""),
        "output_name": record.get("output_name", ""),
        "output_path": record.get("output_path", ""),
        "pointer": record.get("pointer", ""),
        "artifact_type": row.get("artifact_type") or row.get("event_type") or row.get("kind") or "",
        "source_path": source_path,
        "parser": parser,
        "parser_version": parser_version,
        "parser_confidence": details.get("parser_confidence") or row.get("parser_confidence") or "",
        "reportability": details.get("reportability") or row.get("reportability") or "",
        "validation_required": bool(details.get("validation_required")),
        "commercial_grade_ready": details.get("commercial_grade_ready", ""),
        "hashes": hashes,
        "offsets": offsets,
        "explanation_status": status,
    }


def collect_offset_fields(value: object, *, prefix: str = "") -> dict[str, object]:
    found: dict[str, object] = {}
    if isinstance(value, Mapping):
        for key, item in value.items():
            full_key = f"{prefix}.{key}" if prefix else str(key)
            lowered = str(key).lower()
            if "offset" in lowered or lowered in {"record_number", "record_id", "index"}:
                if isinstance(item, (str, int, float, bool)) or item is None:
                    found[full_key] = item
            found.update(collect_offset_fields(item, prefix=full_key))
    return found


def collect_hash_fields(value: object, *, prefix: str = "") -> dict[str, object]:
    found: dict[str, object] = {}
    if isinstance(value, Mapping):
        for key, item in value.items():
            full_key = f"{prefix}.{key}" if prefix else str(key)
            lowered = str(key).lower()
            if lowered in {"md5", "sha1", "sha256"} or "hash" in lowered:
                if isinstance(item, (str, int, float, bool)) or item is None:
                    found[full_key] = item
            found.update(collect_hash_fields(item, prefix=full_key))
    return found


def build_output_hashes(summary: Mapping[str, object]) -> dict[str, dict[str, object]]:
    outputs = summary.get("outputs")
    if not isinstance(outputs, Mapping):
        return {}
    hashes: dict[str, dict[str, object]] = {}
    for name, raw_path in sorted(outputs.items()):
        payload = read_json_path(Path(str(raw_path)))
        if payload is None:
            continue
        canonical = canonicalize(payload)
        encoded = json.dumps(canonical, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        hashes[str(name)] = {
            "sha256": hashlib.sha256(encoded).hexdigest(),
            "record_count": count_records(payload),
        }
    return hashes


def canonicalize(value: object) -> object:
    if isinstance(value, Mapping):
        return {
            str(key): canonicalize(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            if str(key) not in VOLATILE_KEYS
        }
    if isinstance(value, list):
        return [canonicalize(item) for item in value]
    return value


def count_records(payload: object) -> int:
    if not isinstance(payload, Mapping):
        return 0
    return sum(1 for _pointer, _row in rows_from_payload(payload))


def read_json_path(path: Path) -> object | None:
    try:
        if not path.is_file() or path.suffix.lower() not in {".json", ""}:
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def build_confidence_guidance(counts: Mapping[str, int]) -> list[str]:
    guidance = []
    if counts.get("needs-validation", 0):
        guidance.append("Rows marked needs-validation require cross-tool or known-answer validation before report testimony.")
    if counts.get("unsupported", 0):
        guidance.append("Unsupported rows indicate parser gaps or intentionally blocked/sensitive artifact handling.")
    if counts.get("report-grade", 0) == 0:
        guidance.append("No rows met report-grade criteria; treat this run as triage-only.")
    return guidance or ["Confidence distribution is review-ready."]


def render_explainability_markdown(payload: Mapping[str, object]) -> str:
    lines = [
        "# RapidTriage Parser Explainability",
        "",
        f"- Generated at: `{payload.get('generated_at', '')}`",
        f"- Run summary: `{payload.get('run_summary', '')}`",
        f"- Entries: `{payload.get('summary', {}).get('entry_count', 0)}`",
        f"- Incomplete: `{payload.get('summary', {}).get('incomplete_count', 0)}`",
        "",
        "| Source | Type | Status | Parser | Path | Pointer |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for entry in payload.get("entries", [])[:100]:
        if isinstance(entry, Mapping):
            lines.append(
                f"| {entry.get('source', '')} | {entry.get('artifact_type', '')} | "
                f"{entry.get('explanation_status', '')} | {entry.get('parser', '')} | "
                f"`{entry.get('source_path', '')}` | `{entry.get('pointer', '')}` |"
            )
    lines.append("")
    return "\n".join(lines)


def render_reproducibility_markdown(payload: Mapping[str, object]) -> str:
    lines = [
        "# RapidTriage Reproducibility Kit",
        "",
        f"- Status: `{payload.get('status', '')}`",
        f"- Baseline: `{payload.get('baseline_run_summary', '')}`",
        f"- Candidate: `{payload.get('candidate_run_summary', '')}`",
        f"- Diff count: `{payload.get('summary', {}).get('diff_count', 0)}`",
        "",
        "| Output | Status | Baseline records | Candidate records |",
        "| --- | --- | ---: | ---: |",
    ]
    for item in payload.get("comparisons", []):
        if isinstance(item, Mapping):
            lines.append(
                f"| {item.get('name', '')} | {item.get('status', '')} | "
                f"{item.get('baseline_record_count', 0)} | {item.get('candidate_record_count', 0)} |"
            )
    lines.append("")
    return "\n".join(lines)
