"""Row serialization and generic helpers."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from ..docs import extract_text
from ..submission import compute_hashes
from .base import (
    CaseDatabaseError,
)
from .schema import (
    list_tables,
)

__all__ = [
    "artifact_details",
    "artifact_match_source",
    "artifact_nested_preview",
    "artifact_parser_manifest_hashes",
    "artifact_row_citation",
    "artifact_search_metadata",
    "artifact_source_manifest_keys",
    "artifact_source_path",
    "artifact_source_viewer_locator",
    "artifact_summary",
    "artifact_title",
    "build_fts_query",
    "compact_text",
    "count_rows",
    "field_label",
    "hash_existing_file",
    "indicator_artifact_row",
    "ioc_scanner_artifact_row",
    "matched_keywords",
    "metadata_matches",
    "nested_mapping_str",
    "normalize_path_for_db",
    "optional_float",
    "optional_int",
    "optional_str",
    "parse_json_list",
    "parse_json_object",
    "parse_metadata_filters",
    "path_size",
    "quote_fts_token",
    "read_json_path",
    "read_output",
    "require_tables",
    "row_to_dict",
    "safe_extract_text",
    "stable_payload_sha256",
    "vsc_artifact_row",
    "worker_artifact_row",
    "worker_record_index_text",
]

def count_rows(connection: sqlite3.Connection, table_name: str, case_id: str) -> int:
    row = connection.execute(f"SELECT COUNT(*) AS count FROM {table_name} WHERE case_id = ?", (case_id,)).fetchone()
    return int(row["count"]) if row is not None else 0


def require_tables(connection: sqlite3.Connection, table_names: Iterable[str]) -> None:
    existing = set(list_tables(connection))
    missing = sorted(set(table_names) - existing)
    if missing:
        raise CaseDatabaseError(f"case DB is missing required tables: {', '.join(missing)}")


def row_to_dict(row: Mapping[str, object]) -> dict[str, object]:
    return {key: row[key] for key in row.keys()}


def read_output(outputs: Mapping[str, object], name: str) -> dict[str, object]:
    raw_path = outputs.get(name)
    if not raw_path:
        return {}
    return read_json_path(Path(str(raw_path)))


def read_json_path(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.expanduser().resolve().read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def safe_extract_text(path: Path, kind: str) -> tuple[str, str]:
    try:
        return extract_text(path, kind), ""
    except Exception as exc:
        return "", f"{type(exc).__name__}: {exc}"


def hash_existing_file(path: str) -> dict[str, str]:
    if not path:
        return {}
    resolved = Path(path).expanduser()
    try:
        if not resolved.is_file():
            return {}
        return compute_hashes(resolved)
    except OSError:
        return {}


def path_size(path: str) -> int | None:
    if not path:
        return None
    try:
        resolved = Path(path).expanduser()
        return resolved.stat().st_size if resolved.is_file() else None
    except OSError:
        return None


def normalize_path_for_db(path: str) -> str:
    return path.replace("\\", "/").lower()


def optional_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def optional_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def optional_str(value: Any) -> str | None:
    return str(value) if value not in (None, "") else None


def parse_metadata_filters(filters: Iterable[str]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for item in filters:
        text = str(item or "").strip()
        if not text:
            continue
        if "=" not in text:
            raise CaseDatabaseError(f"metadata filter must be KEY=VALUE: {text}")
        key, value = text.split("=", 1)
        key = key.strip()
        if not key:
            raise CaseDatabaseError(f"metadata filter key is empty: {text}")
        parsed[key] = value.strip()
    return parsed


def metadata_matches(metadata: object, filters: Mapping[str, str]) -> bool:
    if not isinstance(metadata, Mapping):
        return False
    for key, expected in filters.items():
        value = metadata.get(key)
        if isinstance(value, list):
            haystack = " ".join(str(item) for item in value)
        else:
            haystack = str(value or "")
        if expected.lower() not in haystack.lower():
            return False
    return True


def artifact_details(row: Mapping[str, object]) -> Mapping[str, object]:
    details = row.get("details")
    return details if isinstance(details, Mapping) else {}


def artifact_summary(row: Mapping[str, object]) -> str:
    details_payload = artifact_details(row)
    indicator_value = details_payload.get("indicator_value")
    if indicator_value:
        return " ".join(
            str(part)
            for part in (
                details_payload.get("indicator_type"),
                indicator_value,
                details_payload.get("classification"),
            )
            if part
        )
    event_id = details_payload.get("event_id")
    if event_id:
        parts = [
            f"event_id={event_id}",
            str(details_payload.get("event_category") or ""),
            field_label("user", details_payload.get("user_name") or details_payload.get("target_user_name")),
            field_label("ip", details_payload.get("source_ip")),
            field_label("cmd", details_payload.get("command_line") or details_payload.get("script_block_text")),
        ]
        summary = " ".join(part for part in parts if part)
        if summary:
            return summary

    for key in (
        "relative_path",
        "current_path",
        "snapshot_path",
        "command_line",
        "script_block_text",
        "file_path",
        "executable_path",
        "data_url",
        "origin_url",
        "url",
        "source_url",
        "target_path",
        "label",
        "program",
        "home_path",
        "entry_name",
        "service_name",
        "process_name",
        "summary",
    ):
        value = details_payload.get(key) or row.get(key)
        if value:
            return str(value)
    nested = artifact_nested_preview(details_payload)
    if nested:
        return nested
    return str(row.get("path") or row.get("artifact_type") or "artifact")


def artifact_title(row: Mapping[str, object]) -> str:
    artifact_type = str(row.get("artifact_type") or "artifact")
    details = artifact_details(row)
    indicator_value = details.get("indicator_value")
    if indicator_value:
        return f"{artifact_type}: {compact_text(str(indicator_value), 80)}"
    event_id = details.get("event_id")
    if event_id:
        category = details.get("event_category") or "event"
        return f"{artifact_type} {event_id} {category}"
    if "browser" in artifact_type:
        nested = artifact_nested_preview(details)
        if nested:
            return f"{artifact_type}: {compact_text(nested, 80)}"
    for key in (
        "relative_path",
        "current_path",
        "snapshot_path",
        "command_line",
        "file_path",
        "executable_path",
        "data_url",
        "origin_url",
        "label",
        "program",
        "entry_name",
        "source_path",
    ):
        value = details.get(key)
        if value:
            return f"{artifact_type}: {compact_text(str(value), 80)}"
    nested = artifact_nested_preview(details)
    if nested:
        return f"{artifact_type}: {compact_text(nested, 80)}"
    return artifact_type


def artifact_source_path(row: Mapping[str, object]) -> str:
    details = artifact_details(row)
    for value in (
        row.get("path"),
        details.get("source_path"),
        details.get("current_path"),
        details.get("snapshot_path"),
        details.get("target_path"),
        details.get("file_path"),
        details.get("source_path"),
    ):
        if value:
            return str(value)
    return ""


def artifact_search_metadata(row: Mapping[str, object]) -> dict[str, object]:
    details = artifact_details(row)
    keys = (
        "parser",
        "parser_version",
        "coverage_status",
        "reportability",
        "status",
        "relative_path",
        "snapshot_label",
        "snapshot_path",
        "current_path",
        "snapshot_modified_at",
        "current_modified_at",
        "snapshot_sha256",
        "current_sha256",
        "event_id",
        "event_category",
        "event_family",
        "event_tags",
        "event_description",
        "channel",
        "channel_family",
        "computer",
        "user_name",
        "subject_user_name",
        "target_user_name",
        "target_domain_name",
        "logon_type",
        "source_ip",
        "source_port",
        "destination_ip",
        "destination_hostname",
        "destination_port",
        "service_name",
        "service_file_name",
        "process_name",
        "new_process_name",
        "parent_process_name",
        "parent_command_line",
        "command_line",
        "script_block_text",
        "query_name",
        "target_object",
        "image_loaded",
        "task_name",
        "workstation_name",
        "logon_process_name",
        "authentication_package_name",
        "status_code",
        "failure_reason",
        "share_name",
        "relative_target_name",
        "triage_recommendation",
        "matched_fields",
        "false_positive_note",
        "file_path",
        "executable_path",
        "reason",
        "timestamp",
        "risk_score",
        "risk_flags",
        "evidence_strength",
        "user",
        "browser",
        "profile",
        "history_count",
        "download_count",
        "internet_usage_count",
        "ai_usage_count",
        "ai_conversation_candidate_count",
        "question_count",
        "answer_count",
        "ai_service",
        "domain",
        "query_hint",
        "prompt_hint",
        "first_seen_at",
        "last_seen_at",
        "ai_service_counts",
        "internet_category_counts",
        "top_domains",
        "agent_name",
        "data_url",
        "origin_url",
        "sender_name",
        "home_path",
        "label",
        "program",
        "program_arguments",
        "run_at_load",
        "modified_at",
        "indicator_type",
        "indicator_value",
        "classification",
        "count",
        "source_hashes",
        "record_hashes",
        "source_viewer_locator",
        "source_locator",
        "row_citation_hash",
        "parser_manifest_hashes",
        "source_path",
        "source_format",
        "source_index",
        "record_offset",
        "file_offset",
        "raw_record_preview",
        "extraction_method",
        "parser_confidence",
        "matched_rules",
        "score",
        "band",
        "band_label",
        "verdict",
        "scan_status",
        "scan_kind",
        "scan_error",
        "signal_count",
        "score_semantics",
        "score_guidance",
        "validation_required",
        "validation_guidance",
        "limitations",
        "next_checks",
        "commercial_grade_ready",
    )
    metadata = {key: details[key] for key in keys if details.get(key) not in (None, "", [])}
    source_viewer_locator = artifact_source_viewer_locator(details)
    if source_viewer_locator:
        metadata["source_viewer_locator"] = source_viewer_locator
        metadata.setdefault("source_locator", source_viewer_locator)
        metadata["source_locator_hash"] = stable_payload_sha256(source_viewer_locator)
    row_citation = artifact_row_citation(details)
    if row_citation:
        metadata["row_citation"] = row_citation
        if row_citation.get("row_hash"):
            metadata["row_citation_hash"] = str(row_citation["row_hash"])
    parser_manifest_hashes = artifact_parser_manifest_hashes(details)
    if parser_manifest_hashes:
        metadata["parser_manifest_hashes"] = parser_manifest_hashes
    nested = artifact_nested_preview(details)
    if nested:
        metadata["preview_value"] = nested
    return metadata


def artifact_parser_manifest_hashes(details: Mapping[str, object]) -> dict[str, str]:
    manifest_fields = {
        "cloud_export_import_manifest_hash": "cloud_export_import",
        "cloud_archive_manifest_hash": "cloud_archive",
        "google_takeout_parser_manifest_hash": "google_takeout",
        "icloud_export_parser_manifest_hash": "icloud_export",
        "m365_export_parser_manifest_hash": "m365_export",
        "email_mailbox_parser_manifest_hash": "email_mailbox",
        "email_expansion_citation_manifest_hash": "email_expansion",
        "ai_transcript_parser_manifest_hash": "ai_transcript",
    }
    hashes: dict[str, str] = {}
    for field, label in manifest_fields.items():
        value = str(details.get(field) or "").strip()
        if value:
            hashes[label] = value
    return hashes


def artifact_row_citation(details: Mapping[str, object]) -> dict[str, object]:
    for manifest_key in artifact_source_manifest_keys():
        manifest = details.get(manifest_key)
        if not isinstance(manifest, Mapping):
            continue
        row_citation = manifest.get("row_citation")
        if isinstance(row_citation, Mapping):
            return dict(row_citation)
    return {}


def artifact_source_viewer_locator(details: Mapping[str, object]) -> dict[str, object]:
    direct = details.get("source_viewer_locator")
    if isinstance(direct, Mapping):
        return dict(direct)
    for manifest_key in artifact_source_manifest_keys():
        manifest = details.get(manifest_key)
        if not isinstance(manifest, Mapping):
            continue
        row_citation = manifest.get("row_citation")
        if isinstance(row_citation, Mapping) and isinstance(row_citation.get("source_viewer_locator"), Mapping):
            return dict(row_citation["source_viewer_locator"])
    import_manifest = details.get("cloud_export_import_manifest")
    if isinstance(import_manifest, Mapping) and isinstance(import_manifest.get("source_viewer_locator"), Mapping):
        return dict(import_manifest["source_viewer_locator"])
    attachments = details.get("attachments")
    if isinstance(attachments, list):
        for attachment in attachments:
            if isinstance(attachment, Mapping) and isinstance(attachment.get("source_viewer_locator"), Mapping):
                return dict(attachment["source_viewer_locator"])
    return {}


def artifact_source_manifest_keys() -> tuple[str, ...]:
    return (
        "google_takeout_parser_manifest",
        "icloud_export_parser_manifest",
        "m365_export_parser_manifest",
        "email_mailbox_parser_manifest",
        "email_expansion_citation_manifest",
        "ai_transcript_parser_manifest",
    )


def artifact_nested_preview(details: Mapping[str, object]) -> str:
    for key in ("conversation_candidates", "ai_conversation_candidates", "ai_usage", "internet_usage", "downloads", "history"):
        rows = details.get(key)
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            for value_key in ("text", "ai_service", "query_hint", "prompt_hint", "source_url", "url", "target_path", "title", "domain"):
                value = row.get(value_key)
                if value:
                    return str(value)
    return ""


def vsc_artifact_row(
    record: Mapping[str, object],
    *,
    snapshot_label: str,
    snapshot_root: str,
    index: int,
) -> dict[str, object]:
    status = str(record.get("status") or "change")
    relative_path = str(record.get("relative_path") or "")
    snapshot = record.get("snapshot") if isinstance(record.get("snapshot"), Mapping) else {}
    current = record.get("current") if isinstance(record.get("current"), Mapping) else {}
    snapshot_path = str(snapshot.get("path") or "") if isinstance(snapshot, Mapping) else ""
    current_path = str(current.get("path") or "") if isinstance(current, Mapping) else ""
    review_path = current_path or snapshot_path or relative_path
    details = {
        "parser": "rapidtriage-vsc-compare-import",
        "parser_version": "1",
        "coverage_status": "mapped",
        "reportability": "triage",
        "source_format": "vsc-compare-json",
        "source_index": index,
        "status": status,
        "relative_path": relative_path,
        "snapshot_label": snapshot_label,
        "snapshot_root": snapshot_root,
        "snapshot_path": snapshot_path,
        "current_path": current_path,
        "snapshot_size": snapshot.get("size") if isinstance(snapshot, Mapping) else None,
        "current_size": current.get("size") if isinstance(current, Mapping) else None,
        "snapshot_modified_at": snapshot.get("modified_at") if isinstance(snapshot, Mapping) else "",
        "current_modified_at": current.get("modified_at") if isinstance(current, Mapping) else "",
        "snapshot_sha256": snapshot.get("sha256") if isinstance(snapshot, Mapping) else "",
        "current_sha256": current.get("sha256") if isinstance(current, Mapping) else "",
        "evidence_strength": "snapshot-file-delta",
        "raw": dict(record),
    }
    return {
        "provider": "rapidtriage-vsc-compare",
        "artifact_type": f"vsc-{status}-file",
        "path": review_path,
        "supported": True,
        "details": details,
    }


def indicator_artifact_row(row: Mapping[str, object], *, index: int) -> dict[str, object]:
    indicator_type = str(row.get("type") or "indicator")
    indicator_value = str(row.get("value") or "")
    sources = row.get("sources") if isinstance(row.get("sources"), list) else []
    first_source = sources[0] if sources and isinstance(sources[0], Mapping) else {}
    source_path = str(first_source.get("path") or first_source.get("source_path") or "")
    output_path = str(first_source.get("output_path") or "")
    details = {
        "parser": "rapidtriage-indicators",
        "parser_version": "1",
        "coverage_status": "run-output-summary",
        "reportability": "triage",
        "source_format": "rapidtriage-indicators-json",
        "source_index": index,
        "source_path": source_path,
        "output_path": output_path,
        "indicator_type": indicator_type,
        "indicator_value": indicator_value,
        "count": optional_int(row.get("count")) or 0,
        "classification": str(row.get("classification") or ""),
        "risk_flags": list(row.get("risk_flags", [])) if isinstance(row.get("risk_flags"), list) else [],
        "matched_rules": list(row.get("matched_rules", [])) if isinstance(row.get("matched_rules"), list) else [],
        "sources": sources,
        "evidence_strength": "indicator-pivot",
        "raw": dict(row),
    }
    return {
        "provider": "rapidtriage-indicators",
        "artifact_type": f"indicator-{indicator_type}",
        "path": source_path or output_path,
        "supported": True,
        "details": details,
    }


def ioc_scanner_artifact_row(row: Mapping[str, object], *, index: int) -> dict[str, object]:
    hit_type = str(row.get("type") or "ioc")
    hit_value = str(row.get("value") or "")
    rule_id = str(row.get("rule_id") or "")
    sources = row.get("sources") if isinstance(row.get("sources"), list) else []
    first_source = sources[0] if sources and isinstance(sources[0], Mapping) else {}
    source_path = str(first_source.get("path") or first_source.get("source_path") or "")
    output_path = str(first_source.get("output_path") or "")
    title = f"IOC scanner hit: {rule_id} {hit_type}:{hit_value}".strip()
    details = {
        "parser": "rapidtriage-indicators",
        "parser_version": "1",
        "coverage_status": "local-rule-ioc-scanner",
        "reportability": "triage",
        "source_format": "rapidtriage-indicators-json",
        "source_index": index,
        "source_path": source_path,
        "output_path": output_path,
        "rule_id": rule_id,
        "ioc_type": hit_type,
        "ioc_value": hit_value,
        "count": optional_int(row.get("count")) or 0,
        "classification": str(row.get("classification") or ""),
        "risk_flags": list(row.get("risk_flags", [])) if isinstance(row.get("risk_flags"), list) else [],
        "sources": sources,
        "source_viewer_locator": dict(row.get("source_viewer_locator", {})) if isinstance(row.get("source_viewer_locator"), Mapping) else {},
        "evidence_strength": "local-rule-ioc-hit",
        "report_use_boundary": str(row.get("report_use_boundary") or ""),
        "raw": dict(row),
    }
    return {
        "provider": "rapidtriage-indicators",
        "artifact_type": "indicator-ioc-scanner-hit",
        "path": source_path or output_path,
        "title": title,
        "summary": f"{rule_id} matched {hit_type}:{hit_value}" if rule_id or hit_value else "IOC scanner hit",
        "supported": True,
        "details": details,
    }


def worker_artifact_row(record: Mapping[str, object], *, source_jsonl: str, index: int) -> dict[str, object]:
    source = record.get("source") if isinstance(record.get("source"), Mapping) else {}
    fields = record.get("fields") if isinstance(record.get("fields"), Mapping) else {}
    artifact_type = str(record.get("artifact_type") or "worker-artifact")
    artifact_family = str(record.get("artifact_family") or "")
    source_path = str(source.get("source_path") or "") if isinstance(source, Mapping) else ""
    details = {
        "parser": str(record.get("parser") or "rapid-worker"),
        "parser_version": str(record.get("parser_version") or ""),
        "coverage_status": "worker-jsonl-import",
        "reportability": "triage",
        "source_format": "ArtifactRecordV1-jsonl",
        "source_index": index,
        "source_jsonl": source_jsonl,
        "artifact_id": str(record.get("artifact_id") or ""),
        "artifact_family": artifact_family,
        "source_case_id": str(source.get("case_id") or "") if isinstance(source, Mapping) else "",
        "source_id": str(source.get("source_id") or "") if isinstance(source, Mapping) else "",
        "source_path": source_path,
        "source_offset": source.get("offset") if isinstance(source, Mapping) else None,
        "source_length": source.get("length") if isinstance(source, Mapping) else None,
        "source_hashes": source.get("hashes") if isinstance(source.get("hashes"), Mapping) else {},
        "confidence": optional_float(record.get("confidence")),
        "validation_required": bool(record.get("validation_required")),
        "commercial_grade_ready": bool(record.get("commercial_grade_ready")),
        "commercial_grade_blockers": list(record.get("commercial_grade_blockers", []))
        if isinstance(record.get("commercial_grade_blockers"), list)
        else [],
        "legal_limitations": list(record.get("legal_limitations", []))
        if isinstance(record.get("legal_limitations"), list)
        else [],
        "fields": dict(fields),
        "raw": dict(record),
    }
    for key, value in fields.items():
        if key not in details and value not in (None, "", []):
            details[str(key)] = value
    return {
        "provider": "rapid-worker",
        "artifact_type": artifact_type,
        "path": source_path,
        "supported": True,
        "details": details,
    }


def worker_record_index_text(artifact: Mapping[str, object]) -> str:
    details = artifact_details(artifact)
    raw = details.get("raw") if isinstance(details.get("raw"), Mapping) else {}
    fields = details.get("fields") if isinstance(details.get("fields"), Mapping) else {}
    searchable = {
        "provider": artifact.get("provider"),
        "artifact_type": artifact.get("artifact_type"),
        "path": artifact.get("path"),
        "title": artifact_title(artifact),
        "summary": artifact_summary(artifact),
        "details": details,
        "fields": fields,
        "raw": raw,
        "metadata": artifact_search_metadata(artifact),
    }
    return json.dumps(searchable, ensure_ascii=False, sort_keys=True)


def parse_json_object(value: object) -> dict[str, object]:
    if isinstance(value, Mapping):
        return dict(value)
    try:
        payload = json.loads(str(value or "{}"))
    except json.JSONDecodeError:
        return {}
    return dict(payload) if isinstance(payload, Mapping) else {}


def parse_json_list(value: object) -> list[object]:
    if isinstance(value, list):
        return list(value)
    try:
        payload = json.loads(str(value or "[]"))
    except json.JSONDecodeError:
        return []
    return list(payload) if isinstance(payload, list) else []


def field_label(name: str, value: object) -> str:
    return f"{name}={value}" if value not in (None, "") else ""


def compact_text(value: str, limit: int) -> str:
    text = " ".join(value.split())
    return text if len(text) <= limit else f"{text[: limit - 1]}..."


def artifact_match_source(artifact_type: str) -> str:
    return "indicators" if artifact_type.startswith("indicator-") else "artifacts"


def nested_mapping_str(mapping: Mapping[str, object], *keys: str) -> str:
    current: object = mapping
    for key in keys:
        if not isinstance(current, Mapping):
            return ""
        current = current.get(key)
    return str(current or "")


def stable_payload_sha256(payload: Mapping[str, object] | Sequence[Mapping[str, object]]) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_fts_query(keywords: list[str]) -> str:
    return " OR ".join(quote_fts_token(keyword) for keyword in keywords)


def quote_fts_token(keyword: str) -> str:
    escaped = keyword.replace('"', '""')
    return f'"{escaped}"'


def matched_keywords(text: str, keywords: Iterable[str]) -> list[str]:
    haystack = text.lower()
    return [keyword for keyword in keywords if keyword.lower() in haystack]
