from __future__ import annotations

import datetime as dt
import json
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Sequence

from .artifacts import SUPPORTED_ARTIFACT_KINDS, run_artifact_collection
from .docs import scan_document_candidates
from .files import run_files_scan
from .input_root import resolve_input_root
from .rules import RuleSet, annotate_timeline_payload


class TimelineError(ValueError):
    """Raised when timeline inputs are missing or invalid."""


TIMESTAMP_EVENT_NAMES: Dict[str, str] = {
    "accessed_at": "accessed",
    "created_at": "created",
    "ended_at": "ended",
    "last_visited_at": "last-visited",
    "modified_at": "modified",
    "started_at": "started",
    "timestamp": "observed",
    "visited_at": "visited",
}


def run_timeline(
    *,
    root: Path | None = None,
    input_kind: str | None = None,
    files_inputs: Sequence[Path] | None = None,
    docs_inputs: Sequence[Path] | None = None,
    artifacts_inputs: Sequence[Path] | None = None,
    rule_set: RuleSet | None = None,
) -> Dict[str, object]:
    input_root = resolve_input_root(root or Path.cwd(), kind=input_kind)
    normalized_files = normalize_input_paths(files_inputs)
    normalized_docs = normalize_input_paths(docs_inputs)
    normalized_artifacts = normalize_input_paths(artifacts_inputs)

    if root is None and not normalized_files and not normalized_docs and not normalized_artifacts:
        raise TimelineError("timeline requires a ROOT or at least one --files, --docs, or --artifacts input")

    events: List[Dict[str, object]] = []
    if normalized_files:
        for input_path in normalized_files:
            payload = load_input_payload(input_path, expected_command="files")
            events.extend(extract_file_events(payload, input_path))
    else:
        payload = run_files_scan(input_root, rule_set=rule_set)
        events.extend(extract_file_events(payload, Path("generated:files")))

    if normalized_docs:
        for input_path in normalized_docs:
            payload = load_input_payload(input_path, expected_command="docs")
            events.extend(extract_docs_events(payload, input_path))
    else:
        events.extend(extract_document_candidate_events(scan_document_candidates(input_root), Path("generated:docs")))

    if normalized_artifacts:
        for input_path in normalized_artifacts:
            payload = load_input_payload(input_path, expected_command="artifacts")
            events.extend(extract_artifact_events(payload, input_path))
    else:
        for kind in SUPPORTED_ARTIFACT_KINDS:
            payload = run_artifact_collection(input_root, kind=kind, rule_set=rule_set)
            events.extend(extract_artifact_events(payload, Path(f"generated:artifacts:{kind}")))

    events.sort(key=event_sort_key)
    event_type_counts = Counter(str(event["event_type"]) for event in events)
    source_counts = Counter(str(event["source"]) for event in events)
    timestamps = [str(event["timestamp"]) for event in events]

    payload = {
        "command": "timeline",
        "generated_at": dt.datetime.now().isoformat(),
        "root": str(input_root.root_path),
        "inputs": {
            "files": [str(path) for path in normalized_files],
            "docs": [str(path) for path in normalized_docs],
            "artifacts": [str(path) for path in normalized_artifacts],
        },
        "summary": {
            "input_file_count": len(normalized_files) + len(normalized_docs) + len(normalized_artifacts),
            "event_count": len(events),
            "source_counts": dict(source_counts),
            "event_type_counts": dict(event_type_counts),
            "earliest_event_at": timestamps[0] if timestamps else None,
            "latest_event_at": timestamps[-1] if timestamps else None,
        },
        "events": events,
    }
    if rule_set is not None:
        annotate_timeline_payload(payload, rule_set)
    return payload


def normalize_input_paths(paths: Sequence[Path] | None) -> List[Path]:
    normalized: List[Path] = []
    seen: set[str] = set()
    for raw_path in paths or ():
        resolved = Path(raw_path).expanduser().resolve()
        key = str(resolved)
        if key in seen:
            continue
        seen.add(key)
        normalized.append(resolved)
    return normalized


def load_input_payload(path: Path, *, expected_command: str) -> Dict[str, object]:
    if not path.is_file():
        raise TimelineError(f"timeline input does not exist: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise TimelineError(f"timeline input is not valid JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise TimelineError(f"timeline input must be a JSON object: {path}")
    if payload.get("command") != expected_command:
        actual = payload.get("command")
        raise TimelineError(f"timeline input {path} must have command={expected_command!r} (got {actual!r})")
    return payload


def extract_file_events(payload: Mapping[str, object], input_path: Path) -> List[Dict[str, object]]:
    events: List[Dict[str, object]] = []
    for candidate in payload.get("candidates", []):
        if not isinstance(candidate, dict):
            continue
        timestamp = coerce_utc_timestamp(
            candidate.get("modified_epoch"),
            fallback=candidate.get("modified_at"),
        )
        if timestamp is None:
            continue
        path = str(candidate.get("path", ""))
        name = str(candidate.get("name") or Path(path).name)
        events.append(
            {
                "timestamp": timestamp,
                "source": "files",
                "event_type": "file-modified",
                "path": path,
                "input_file": str(input_path),
                "summary": f"File candidate modified: {name}",
                "details": {
                    "name": candidate.get("name"),
                    "extension": candidate.get("extension"),
                    "size": candidate.get("size"),
                    "categories": list(candidate.get("categories", [])),
                    "reasons": dict(candidate.get("reasons", {})),
                },
            }
        )
    return events


def extract_document_candidate_events(candidates: Sequence[object], input_path: Path) -> List[Dict[str, object]]:
    events: List[Dict[str, object]] = []
    for candidate in candidates:
        if not hasattr(candidate, "path"):
            continue
        path = str(getattr(candidate, "path", ""))
        if not path:
            continue
        timestamp = path_timestamp_to_utc(path, fallback=getattr(candidate, "modified_at", None))
        if timestamp is None:
            continue
        kind = str(getattr(candidate, "kind", ""))
        events.append(
            {
                "timestamp": timestamp,
                "source": "docs",
                "event_type": "document-modified",
                "path": path,
                "input_file": str(input_path),
                "summary": f"Document candidate modified: {Path(path).name}",
                "details": {
                    "kind": kind,
                    "size": getattr(candidate, "size", None),
                },
            }
        )
    return events


def extract_docs_events(payload: Mapping[str, object], input_path: Path) -> List[Dict[str, object]]:
    events: List[Dict[str, object]] = []
    candidates_by_path = {
        str(candidate.get("path")): candidate
        for candidate in payload.get("candidates", [])
        if isinstance(candidate, dict) and candidate.get("path")
    }
    for result in payload.get("results", []):
        if not isinstance(result, dict):
            continue
        path = str(result.get("path", ""))
        candidate = candidates_by_path.get(path, {})
        timestamp = path_timestamp_to_utc(path, fallback=candidate.get("modified_at"))
        if timestamp is None:
            continue
        matched_keywords = [str(keyword) for keyword in result.get("matched_keywords", [])]
        kind = str(result.get("kind", candidate.get("kind", "")))
        events.append(
            {
                "timestamp": timestamp,
                "source": "docs",
                "event_type": "document-keyword-hit",
                "path": path,
                "input_file": str(input_path),
                "summary": build_document_summary(path, matched_keywords),
                "details": {
                    "kind": kind,
                    "matched_keywords": matched_keywords,
                    "preview": result.get("preview"),
                    "size": result.get("size", candidate.get("size")),
                },
            }
        )
    return events


def build_document_summary(path: str, matched_keywords: Sequence[str]) -> str:
    label = Path(path).name or path
    if matched_keywords:
        return f"Document keyword hit: {label} ({', '.join(matched_keywords)})"
    return f"Document keyword hit: {label}"


def extract_artifact_events(payload: Mapping[str, object], input_path: Path) -> List[Dict[str, object]]:
    events: List[Dict[str, object]] = []
    kind = str(payload.get("kind", ""))
    for artifact in payload.get("artifacts", []):
        if not isinstance(artifact, dict):
            continue
        artifact_type = str(artifact.get("artifact_type", "artifact"))
        artifact_path = str(artifact.get("path", ""))
        provider = str(artifact.get("provider", ""))
        details = artifact.get("details")
        if not isinstance(details, dict):
            continue
        for detail_event in iter_artifact_detail_events(artifact_type, details):
            events.append(
                {
                    "timestamp": detail_event["timestamp"],
                    "source": "artifacts",
                    "event_type": detail_event["event_type"],
                    "path": artifact_path,
                    "input_file": str(input_path),
                    "summary": build_artifact_summary(artifact_type, artifact_path, detail_event["context"]),
                    "details": {
                        "kind": kind,
                        "provider": provider,
                        "artifact_type": artifact_type,
                        "field_path": detail_event["field_path"],
                        **detail_event["context"],
                    },
                }
            )
    return events


def iter_artifact_detail_events(artifact_type: str, details: Mapping[str, object]) -> Iterable[Dict[str, object]]:
    if artifact_type in {"eventlog-event", "eventlog-detection"}:
        event = eventlog_detail_event(artifact_type, details)
        if event is not None:
            yield event
            return
    yield from _walk_artifact_detail_values(
        artifact_type=artifact_type,
        value=details,
        path_parts=("details",),
    )


def eventlog_detail_event(artifact_type: str, details: Mapping[str, object]) -> Dict[str, object] | None:
    timestamp = str(details.get("event_created_at") or details.get("timestamp") or "")
    if not timestamp:
        return None
    category = str(details.get("event_category") or "event")
    family = str(details.get("event_family") or "")
    context = collect_selected_context(
        details,
        (
            "parser",
            "coverage_status",
            "reportability",
            "source_path",
            "source_hashes",
            "record_id",
            "event_id",
            "event_category",
            "event_family",
            "event_tags",
            "channel",
            "channel_family",
            "provider_name",
            "computer",
            "user_name",
            "target_user_name",
            "subject_user_name",
            "source_ip",
            "destination_ip",
            "process_name",
            "command_line",
            "script_block_text",
            "risk_score",
            "risk_flags",
            "rule",
        ),
    )
    return {
        "timestamp": timestamp,
        "event_type": f"eventlog-{category}" if artifact_type == "eventlog-event" else "eventlog-detection",
        "field_path": "details.event_created_at",
        "context": {
            **context,
            "timestamp_kind": "event-created",
            "timeline_family": family or category,
        },
    }


def _walk_artifact_detail_values(
    *,
    artifact_type: str,
    value: object,
    path_parts: Sequence[str],
) -> Iterable[Dict[str, object]]:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in TIMESTAMP_EVENT_NAMES and isinstance(item, str) and item:
                context = collect_scalar_context(value, skip_keys={key})
                yield {
                    "timestamp": item,
                    "event_type": build_artifact_event_type(artifact_type, path_parts, key),
                    "field_path": ".".join((*path_parts, key)),
                    "context": context,
                }
            else:
                yield from _walk_artifact_detail_values(
                    artifact_type=artifact_type,
                    value=item,
                    path_parts=(*path_parts, key),
                )
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            yield from _walk_artifact_detail_values(
                artifact_type=artifact_type,
                value=item,
                path_parts=(*path_parts, f"[{index}]"),
            )


def collect_scalar_context(value: Mapping[str, object], *, skip_keys: set[str]) -> Dict[str, object]:
    context: Dict[str, object] = {}
    for key, item in value.items():
        if key in skip_keys or isinstance(item, (dict, list)):
            continue
        context[key] = item
    return context


def collect_selected_context(value: Mapping[str, object], keys: Sequence[str]) -> Dict[str, object]:
    context: Dict[str, object] = {}
    for key in keys:
        item = value.get(key)
        if item in (None, "", []):
            continue
        context[key] = item
    return context


def build_artifact_event_type(artifact_type: str, path_parts: Sequence[str], timestamp_key: str) -> str:
    section = ""
    for part in reversed(path_parts):
        if part in {"details"} or part.startswith("["):
            continue
        section = singularize(part)
        break
    if "bounded_state_replay_preview" in path_parts and section == "transitions":
        section = "usn-state-transition"
    parts = ["artifact", artifact_type]
    if section and section not in {"artifact", artifact_type}:
        parts.append(section)
    parts.append(TIMESTAMP_EVENT_NAMES.get(timestamp_key, normalize_token(timestamp_key)))
    return "-".join(parts)


def singularize(value: str) -> str:
    overrides = {
        "ai_usage": "ai-usage",
        "downloads": "download",
        "internet_usage": "internet-usage",
        "timeline_review_candidates": "timeline-review-candidate",
    }
    return overrides.get(value, value)


def normalize_token(value: str) -> str:
    return value.strip().lower().replace("_", "-")


def field_label(name: str, value: object) -> str:
    return f"{name}={value}" if value not in (None, "") else ""


def build_artifact_summary(artifact_type: str, artifact_path: str, context: Mapping[str, object]) -> str:
    if artifact_type in {"eventlog-event", "eventlog-detection"}:
        label = "EventLog detection" if artifact_type == "eventlog-detection" else "EventLog event"
        bits = [
            field_label("id", context.get("event_id")),
            str(context.get("event_category") or ""),
            field_label("channel", context.get("channel")),
            field_label("user", context.get("user_name") or context.get("target_user_name") or context.get("subject_user_name")),
            field_label("src", context.get("source_ip")),
            field_label("cmd", context.get("command_line") or context.get("script_block_text")),
        ]
        return f"{label}: {' '.join(bit for bit in bits if bit)}".strip()
    if "ai_service" in context:
        bits = [
            str(context.get("ai_service") or "AI service"),
            str(context.get("query_hint") or context.get("prompt_hint") or context.get("title") or context.get("url") or ""),
        ]
        return f"AI usage: {' '.join(bit for bit in bits if bit)}".strip()
    if "url" in context:
        return f"Artifact event: {artifact_type} {context['url']}"
    if "source_url" in context:
        return f"Artifact event: {artifact_type} {context['source_url']}"
    if "target_path" in context and context["target_path"]:
        return f"Artifact event: {artifact_type} {context['target_path']}"
    if "entry_name" in context:
        return f"Artifact event: {artifact_type} {context['entry_name']}"
    if "timeline_type" in context and str(context.get("timeline_type") or "").startswith("usn-"):
        label = str(context.get("event_label") or context.get("timeline_type") or "USN timeline candidate")
        path = str(context.get("path_candidate") or context.get("file_name") or "")
        return f"{label} {path}".strip()
    label = Path(artifact_path).name or artifact_path or artifact_type
    return f"Artifact event: {artifact_type} {label}"


def event_sort_key(event: Mapping[str, object]) -> tuple[float, str, str, str]:
    timestamp_text = str(event.get("timestamp", ""))
    return (
        timestamp_to_epoch(timestamp_text),
        timestamp_text,
        str(event.get("source", "")),
        str(event.get("path", "")),
    )


def timestamp_to_epoch(value: str) -> float:
    if not value:
        return float("-inf")
    try:
        parsed = dt.datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.timestamp()
    except ValueError:
        return float("-inf")


def coerce_utc_timestamp(value: object, *, fallback: object = None) -> str | None:
    if isinstance(value, (float, int)):
        return dt.datetime.fromtimestamp(float(value), dt.timezone.utc).isoformat()
    if isinstance(fallback, str) and fallback:
        try:
            parsed = dt.datetime.fromisoformat(fallback)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.astimezone(dt.timezone.utc).isoformat()
    return None


def path_timestamp_to_utc(path: str, *, fallback: object = None) -> str | None:
    try:
        stat_result = Path(path).stat()
    except (FileNotFoundError, PermissionError, OSError):
        return coerce_utc_timestamp(None, fallback=fallback)
    return dt.datetime.fromtimestamp(stat_result.st_mtime, dt.timezone.utc).isoformat()


def build_timeline_report(payload: Mapping[str, object]) -> str:
    inputs = payload.get("inputs", {})
    summary = payload.get("summary", {})
    events = payload.get("events", [])

    lines = [
        "# rapidtriage timeline report",
        "",
        f"- Generated at: `{payload.get('generated_at', '')}`",
        f"- Events: {summary.get('event_count', 0)}",
        f"- Earliest event: `{summary.get('earliest_event_at')}`",
        f"- Latest event: `{summary.get('latest_event_at')}`",
        "",
        "## Inputs",
        "",
    ]

    if isinstance(inputs, dict):
        for key in ("files", "docs", "artifacts"):
            rows = inputs.get(key, [])
            lines.append(f"### {key}")
            if isinstance(rows, list) and rows:
                for row in rows:
                    lines.append(f"- `{row}`")
            else:
                lines.append("- none")
            lines.append("")

    lines.extend(["## Event type counts", ""])
    event_type_counts = summary.get("event_type_counts", {})
    if isinstance(event_type_counts, dict) and event_type_counts:
        for name, count in sorted(event_type_counts.items()):
            lines.append(f"- `{name}`: {count}")
    else:
        lines.append("- none")

    lines.extend(["", "## Timeline", ""])
    if isinstance(events, list) and events:
        for event in events:
            if not isinstance(event, dict):
                continue
            caveat = timeline_report_caveat(event)
            suffix = f" — {caveat}" if caveat else ""
            lines.append(
                f"- `{event.get('timestamp')}` `{event.get('source')}` `{event.get('event_type')}` "
                f"`{event.get('path')}` — {event.get('summary')}{suffix}"
            )
    else:
        lines.append("- none")

    return "\n".join(lines) + "\n"


def timeline_report_caveat(event: Mapping[str, object]) -> str:
    details = event.get("details")
    if not isinstance(details, Mapping):
        return ""
    bits: List[str] = []
    if details.get("validation_required") is True:
        bits.append("validation required")
    reportability = details.get("reportability")
    if isinstance(reportability, str) and reportability:
        bits.append(f"reportability={reportability}")
    blockers = details.get("blockers")
    if isinstance(blockers, list):
        visible = [str(item) for item in blockers[:3] if item]
        if visible:
            bits.append(f"blockers={', '.join(visible)}")
    if not bits:
        return ""
    return "Caveat: " + "; ".join(bits)
