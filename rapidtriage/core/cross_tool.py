from __future__ import annotations

import csv
import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Iterable, Mapping

from .docs import write_result


MAX_ROWS_PER_TOOL = 100_000
MAX_RECORD_FIELD_DIFF_ROWS = 5_000
MAX_FIELD_MISMATCH_SAMPLES = 50
KEY_FIELDS = (
    "event_record_id",
    "EventRecordID",
    "record_id",
    "RecordNumber",
    "record_number",
    "event_id",
    "EventID",
    "provider_name",
    "Provider",
    "channel",
    "Channel",
    "key_path",
    "KeyPath",
    "registry_path",
    "RegistryPath",
    "value_name",
    "ValueName",
    "cell_offset",
    "CellOffset",
    "source_offset",
    "SourceOffset",
    "path",
    "Path",
    "source_path",
    "TargetFilename",
    "FileName",
    "filename",
    "sha256",
    "SHA256",
    "hash",
)
EVTX_FIELD_ALIASES = {
    "event_record_id": ("event_record_id", "EventRecordID", "record_id", "RecordNumber", "record_number"),
    "event_id": ("event_id", "EventID"),
    "provider_name": ("provider_name", "Provider", "ProviderName"),
    "channel": ("channel", "Channel"),
    "computer": ("computer", "Computer"),
    "event_created_at": ("event_created_at", "TimeCreated", "timestamp", "Timestamp", "DateTime"),
}


class CrossToolValidationError(ValueError):
    """Raised when cross-tool validation inputs are invalid."""


def build_cross_tool_validation_report(
    *,
    rapid_output: Path,
    reference_outputs: Mapping[str, Path],
    output: Path | None = None,
    min_overlap: float = 0.8,
    backlog_items: Iterable[int] | None = None,
    tool_versions: Mapping[str, str] | None = None,
    tool_commands: Mapping[str, str] | None = None,
    source_evidence: Iterable[Path] | None = None,
    independent_reports: Iterable[Path] | None = None,
    corpus_scope: str = "",
) -> dict[str, object]:
    if not reference_outputs:
        raise CrossToolValidationError("at least one --reference-output NAME=PATH is required")
    if not 0 <= min_overlap <= 1:
        raise CrossToolValidationError("--min-overlap must be between 0 and 1")

    rapid_dataset = load_tool_dataset("rapidtriage", rapid_output)
    reference_datasets = {
        name: load_tool_dataset(name, path)
        for name, path in sorted(reference_outputs.items())
    }
    comparisons = [
        compare_datasets(rapid_dataset, dataset, min_overlap=min_overlap)
        for dataset in reference_datasets.values()
    ]
    mapped_items = list(dict.fromkeys(int(item) for item in (backlog_items or [])))
    source_evidence_integrity = [file_integrity(path) for path in (source_evidence or [])]
    independent_review_integrity = [file_integrity(path) for path in (independent_reports or [])]
    tool_metadata = build_tool_metadata(
        rapid_dataset=rapid_dataset,
        reference_datasets=list(reference_datasets.values()),
        tool_versions=tool_versions or {},
        tool_commands=tool_commands or {},
    )
    status = "pass"
    if any(item["status"] == "failed" for item in comparisons):
        status = "failed"
    elif any(item["status"] == "warning" for item in comparisons):
        status = "warning"
    payload = {
        "command": "cross-tool-validate",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": status,
        "min_overlap": min_overlap,
        "rapid_output": rapid_dataset,
        "reference_outputs": list(reference_datasets.values()),
        "backlog_items": mapped_items,
        "source_evidence_integrity": source_evidence_integrity,
        "independent_review_integrity": independent_review_integrity,
        "corpus_scope": corpus_scope.strip(),
        "tool_metadata": tool_metadata,
        "comparisons": comparisons,
        "cross_tool_validation_assessment": cross_tool_validation_assessment(
            status=status,
            comparisons=comparisons,
            backlog_items=mapped_items,
            output=output,
            source_evidence_integrity=source_evidence_integrity,
            independent_review_integrity=independent_review_integrity,
            corpus_scope=corpus_scope,
            tool_metadata=tool_metadata,
        ),
        "operator_guidance": build_operator_guidance(comparisons),
    }
    if mapped_items:
        payload["datasets"] = build_validation_datasets(
            status=status,
            backlog_items=mapped_items,
            comparisons=comparisons,
            output=output,
            rapid_output=rapid_output,
            reference_outputs=reference_outputs,
            source_evidence=source_evidence or [],
            independent_reports=independent_reports or [],
            corpus_scope=corpus_scope,
        )
    if output is not None:
        write_result(payload, output.expanduser().resolve())
        payload["output"] = str(output.expanduser().resolve())
    return payload


def load_tool_dataset(name: str, path: Path) -> dict[str, object]:
    path = path.expanduser().resolve()
    if not path.is_file():
        raise CrossToolValidationError(f"{name} output not found: {path}")
    rows = list(iter_rows(path, max_rows=MAX_ROWS_PER_TOOL))
    keys = sorted({key for row in rows for key in candidate_keys(row)})
    return {
        "name": name,
        "path": str(path),
        "format": infer_format(path),
        "file_integrity": file_integrity(path),
        "row_count": len(rows),
        "truncated": len(rows) >= MAX_ROWS_PER_TOOL,
        "key_count": len(keys),
        "keys": keys[:5000],
        "sample_rows": rows[:5],
        "record_field_index": record_field_index(rows),
    }


def iter_rows(path: Path, *, max_rows: int) -> Iterable[dict[str, object]]:
    file_format = infer_format(path)
    if file_format == "json":
        raw = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        yield from rows_from_json(raw, max_rows=max_rows)
        return
    if file_format == "jsonl":
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for index, line in enumerate(handle):
                if index >= max_rows:
                    break
                line = line.strip()
                if not line:
                    continue
                item = json.loads(line)
                if isinstance(item, Mapping):
                    yield flatten_mapping(item)
        return
    if file_format == "csv":
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            reader = csv.DictReader(handle)
            for index, row in enumerate(reader):
                if index >= max_rows:
                    break
                yield {str(key): value for key, value in row.items() if key is not None}
        return
    raise CrossToolValidationError(f"unsupported output format for {path}: use JSON, JSONL, or CSV")


def rows_from_json(raw: object, *, max_rows: int) -> Iterable[dict[str, object]]:
    candidates: list[object] = []
    if isinstance(raw, list):
        candidates = raw
    elif isinstance(raw, Mapping):
        for key in ("artifacts", "events", "results", "records", "rows", "indicators", "candidates"):
            value = raw.get(key)
            if isinstance(value, list):
                candidates = value
                break
        if not candidates:
            candidates = [raw]
    for item in candidates[:max_rows]:
        if isinstance(item, Mapping):
            yield flatten_mapping(item)


def flatten_mapping(value: Mapping[str, object], *, prefix: str = "") -> dict[str, object]:
    row: dict[str, object] = {}
    for key, item in value.items():
        full_key = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(item, Mapping):
            row.update(flatten_mapping(item, prefix=full_key))
        elif isinstance(item, (str, int, float, bool)) or item is None:
            row[full_key] = item
    return row


def candidate_keys(row: Mapping[str, object]) -> list[str]:
    keys: list[str] = []
    keys.extend(composite_candidate_keys(row))
    for field in KEY_FIELDS:
        value = value_for_key(row, field)
        if value is not None and str(value).strip():
            keys.append(normalize_key(value))
    if not keys:
        joined = "|".join(f"{key}={row[key]}" for key in sorted(row)[:8])
        if joined:
            keys.append(normalize_key(joined))
    return keys


def composite_candidate_keys(row: Mapping[str, object]) -> list[str]:
    composites: list[str] = []
    event_record_id = first_value(row, ("event_record_id", "EventRecordID", "record_id", "RecordNumber", "record_number"))
    event_id = first_value(row, ("event_id", "EventID"))
    provider = first_value(row, ("provider_name", "Provider"))
    channel = first_value(row, ("channel", "Channel"))
    if event_record_id is not None:
        composites.append(normalize_key(f"evtx-record:{event_record_id}"))
    if event_record_id is not None and channel is not None:
        composites.append(normalize_key(f"evtx-record:{channel}:{event_record_id}"))
    if event_id is not None and provider is not None:
        composites.append(normalize_key(f"evtx-event:{provider}:{event_id}"))

    key_path = first_value(row, ("key_path", "KeyPath", "registry_path", "RegistryPath", "path", "Path"))
    value_name = first_value(row, ("value_name", "ValueName"))
    cell_offset = first_value(row, ("cell_offset", "CellOffset", "source_offset", "SourceOffset"))
    if key_path is not None:
        composites.append(normalize_key(f"registry-key:{key_path}"))
    if key_path is not None and value_name is not None:
        composites.append(normalize_key(f"registry-value:{key_path}:{value_name}"))
    if cell_offset is not None:
        composites.append(normalize_key(f"registry-cell:{cell_offset}"))
    return composites


def first_value(row: Mapping[str, object], fields: Iterable[str]) -> object | None:
    for field in fields:
        value = value_for_key(row, field)
        if value is not None and str(value).strip():
            return value
    return None


def compare_datasets(
    rapid_dataset: Mapping[str, object],
    reference_dataset: Mapping[str, object],
    *,
    min_overlap: float,
) -> dict[str, object]:
    rapid_keys = set(str(item) for item in rapid_dataset.get("keys", []) if str(item))
    reference_keys = set(str(item) for item in reference_dataset.get("keys", []) if str(item))
    overlap = sorted(rapid_keys & reference_keys)
    missing_in_rapid = sorted(reference_keys - rapid_keys)
    only_in_rapid = sorted(rapid_keys - reference_keys)
    denominator = max(len(reference_keys), 1)
    overlap_ratio = round(len(overlap) / denominator, 4)
    row_count_delta = int(rapid_dataset.get("row_count", 0)) - int(reference_dataset.get("row_count", 0))
    status = "pass"
    if reference_keys and overlap_ratio < min_overlap:
        status = "failed"
    elif abs(row_count_delta) > max(int(reference_dataset.get("row_count", 0)) * 0.25, 10):
        status = "warning"
    field_comparison = compare_record_fields(rapid_dataset, reference_dataset)
    if field_comparison["mismatch_count"] or field_comparison["missing_common_field_count"]:
        status = "failed"
    return {
        "reference_name": reference_dataset.get("name", ""),
        "status": status,
        "rapid_row_count": rapid_dataset.get("row_count", 0),
        "reference_row_count": reference_dataset.get("row_count", 0),
        "row_count_delta": row_count_delta,
        "rapid_key_count": len(rapid_keys),
        "reference_key_count": len(reference_keys),
        "overlap_count": len(overlap),
        "overlap_ratio": overlap_ratio,
        "missing_in_rapid_sample": missing_in_rapid[:50],
        "only_in_rapid_sample": only_in_rapid[:50],
        "record_field_comparison": field_comparison,
        "release_gate": "review-required" if status != "pass" else "comparison-passed",
    }


def record_field_index(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    index: dict[str, dict[str, str]] = {}
    for row in rows[:MAX_RECORD_FIELD_DIFF_ROWS]:
        record_id = first_value(row, EVTX_FIELD_ALIASES["event_record_id"])
        if record_id is None:
            continue
        channel = first_value(row, EVTX_FIELD_ALIASES["channel"])
        key = normalize_key(f"evtx-record:{channel}:{record_id}" if channel is not None else f"evtx-record:{record_id}")
        fields: dict[str, str] = {}
        for canonical, aliases in EVTX_FIELD_ALIASES.items():
            value = first_value(row, aliases)
            if value is not None and str(value).strip():
                fields[canonical] = normalize_field_value(value)
        if fields:
            index[key] = fields
    return index


def compare_record_fields(
    rapid_dataset: Mapping[str, object],
    reference_dataset: Mapping[str, object],
) -> dict[str, object]:
    rapid_index = rapid_dataset.get("record_field_index") if isinstance(rapid_dataset.get("record_field_index"), Mapping) else {}
    reference_index = (
        reference_dataset.get("record_field_index")
        if isinstance(reference_dataset.get("record_field_index"), Mapping)
        else {}
    )
    common_keys = sorted(set(rapid_index) & set(reference_index))
    compared_field_count = 0
    mismatch_count = 0
    missing_common_field_count = 0
    mismatch_samples: list[dict[str, object]] = []
    for key in common_keys[:MAX_RECORD_FIELD_DIFF_ROWS]:
        rapid_fields = rapid_index.get(key) if isinstance(rapid_index.get(key), Mapping) else {}
        reference_fields = reference_index.get(key) if isinstance(reference_index.get(key), Mapping) else {}
        field_names = sorted(set(rapid_fields) | set(reference_fields))
        for field_name in field_names:
            rapid_value = str(rapid_fields.get(field_name) or "")
            reference_value = str(reference_fields.get(field_name) or "")
            if not rapid_value or not reference_value:
                missing_common_field_count += 1
                if len(mismatch_samples) < MAX_FIELD_MISMATCH_SAMPLES:
                    mismatch_samples.append(
                        {
                            "record_key": key,
                            "field": field_name,
                            "rapid_value": rapid_value,
                            "reference_value": reference_value,
                            "status": "missing-field",
                        }
                    )
                continue
            compared_field_count += 1
            if rapid_value != reference_value:
                mismatch_count += 1
                if len(mismatch_samples) < MAX_FIELD_MISMATCH_SAMPLES:
                    mismatch_samples.append(
                        {
                            "record_key": key,
                            "field": field_name,
                            "rapid_value": rapid_value,
                            "reference_value": reference_value,
                            "status": "mismatch",
                        }
                    )
    match_count = max(compared_field_count - mismatch_count, 0)
    field_match_ratio = round(match_count / compared_field_count, 4) if compared_field_count else 0.0
    return {
        "mode": "evtx-record-field-diff",
        "rapid_indexed_record_count": len(rapid_index),
        "reference_indexed_record_count": len(reference_index),
        "common_record_count": len(common_keys),
        "compared_field_count": compared_field_count,
        "field_match_count": match_count,
        "mismatch_count": mismatch_count,
        "missing_common_field_count": missing_common_field_count,
        "field_match_ratio": field_match_ratio,
        "mismatch_samples": mismatch_samples,
        "truncated": len(common_keys) > MAX_RECORD_FIELD_DIFF_ROWS,
    }


def build_operator_guidance(comparisons: list[Mapping[str, object]]) -> list[str]:
    if all(item.get("status") == "pass" for item in comparisons):
        return ["Cross-tool row/key overlap met the configured threshold."]
    return [
        "Review missing_in_rapid samples before treating parser output as report-grade.",
        "Low overlap can indicate parser loss, schema mismatch, wrong evidence root, or incompatible external-tool export settings.",
        "Attach this report with parser version, external tool version, and source evidence hash when validating high-value artifacts.",
    ]


def build_validation_datasets(
    *,
    status: str,
    backlog_items: list[int],
    comparisons: list[Mapping[str, object]],
    output: Path | None,
    rapid_output: Path,
    reference_outputs: Mapping[str, Path],
    source_evidence: Iterable[Path],
    independent_reports: Iterable[Path],
    corpus_scope: str,
) -> list[dict[str, object]]:
    evidence_paths = [str(output.expanduser().resolve())] if output is not None else [
        str(rapid_output.expanduser().resolve()),
        *[str(path.expanduser().resolve()) for path in reference_outputs.values()],
        *[str(path.expanduser().resolve()) for path in source_evidence],
        *[str(path.expanduser().resolve()) for path in independent_reports],
    ]
    reference_names = [str(item.get("reference_name") or "") for item in comparisons]
    return [
        {
            "id": f"cross-tool-items-{'-'.join(str(item) for item in backlog_items)}",
            "name": "Cross-tool validation for RapidTriage core forensic parser claims",
            "source": ", ".join(name for name in reference_names if name),
            "corpus_family": "core-forensics-cross-tool",
            "status": "pass" if status == "pass" else "fail",
            "backlog_items": backlog_items,
            "evidence_paths": evidence_paths,
            "evidence_paths_present": True,
            "expected": {
                "backlog_items": backlog_items,
                "required_assertions": [
                    "RapidTriage output and trusted reference output share record/cell keys above the configured overlap threshold.",
                    "Missing reference keys are bounded in missing_in_rapid_sample for reviewer triage.",
                    "Reference tool names, row counts, key counts, and overlap ratio are preserved.",
                    "Cross-tool report preserves source/reference output hashes plus operator-provided tool version/command metadata when supplied.",
                    "Independent review report hash and corpus scope are preserved when supplied.",
                ],
                "reference_tools": reference_names,
                "corpus_scope": corpus_scope.strip(),
                "minimum_overlap": min(
                    [float(item.get("overlap_ratio") or 0.0) for item in comparisons] or [0.0]
                ),
            },
            "notes": "Cross-tool validation evidence. Passing overlap can satisfy the validated gate, but commercial-grade still requires corpus scope review and independent sign-off.",
        }
    ]


def cross_tool_validation_assessment(
    *,
    status: str,
    comparisons: list[Mapping[str, object]],
    backlog_items: list[int],
    output: Path | None,
    source_evidence_integrity: list[dict[str, object]],
    independent_review_integrity: list[dict[str, object]],
    corpus_scope: str,
    tool_metadata: Mapping[str, object],
) -> dict[str, object]:
    tool_rows = tool_metadata.get("tools") if isinstance(tool_metadata.get("tools"), list) else []
    external_tool_rows = [
        item for item in tool_rows
        if isinstance(item, Mapping) and item.get("name") and item.get("name") != "rapidtriage"
    ]
    tools_with_version = sum(1 for item in external_tool_rows if item.get("version"))
    tools_with_command = sum(1 for item in external_tool_rows if item.get("command"))
    source_hashes_attached = bool(source_evidence_integrity)
    independent_review_attached = bool(independent_review_integrity)
    corpus_scope_attached = bool(corpus_scope.strip())
    versions_attached = bool(external_tool_rows) and tools_with_version == len(external_tool_rows)
    commands_attached = bool(external_tool_rows) and tools_with_command == len(external_tool_rows)
    blockers: list[str] = []
    if not source_hashes_attached or not corpus_scope_attached:
        blockers.append("corpus-scope-and-source-hash-review-required")
    if not versions_attached or not commands_attached:
        blockers.append("external-tool-version-and-command-capture-required")
    if not independent_review_attached:
        blockers.append("independent-reviewer-signoff-required")
    ready_for_commercial_grade = (
        bool(backlog_items)
        and status == "pass"
        and output is not None
        and source_hashes_attached
        and corpus_scope_attached
        and versions_attached
        and commands_attached
        and independent_review_attached
    )
    return {
        "status": status,
        "backlog_items": backlog_items,
        "comparison_count": len(comparisons),
        "output": str(output.expanduser().resolve()) if output is not None else "",
        "ready_for_validated_gate": bool(backlog_items) and status == "pass" and output is not None,
        "ready_for_commercial_grade": ready_for_commercial_grade,
        "source_evidence_count": len(source_evidence_integrity),
        "independent_review_count": len(independent_review_integrity),
        "tools_with_version_count": tools_with_version,
        "tools_with_command_count": tools_with_command,
        "commercial_grade_readiness_checks": {
            "source_evidence_hashes_attached": source_hashes_attached,
            "corpus_scope_attached": corpus_scope_attached,
            "external_tool_versions_attached": versions_attached,
            "external_tool_commands_attached": commands_attached,
            "independent_reviewer_signoff_attached": independent_review_attached,
        },
        "commercial_grade_blockers": blockers,
    }


def build_tool_metadata(
    *,
    rapid_dataset: Mapping[str, object],
    reference_datasets: list[Mapping[str, object]],
    tool_versions: Mapping[str, str],
    tool_commands: Mapping[str, str],
) -> dict[str, object]:
    rows: list[dict[str, object]] = []
    for dataset in [rapid_dataset, *reference_datasets]:
        name = str(dataset.get("name") or "")
        rows.append(
            {
                "name": name,
                "output_path": str(dataset.get("path") or ""),
                "output_sha256": (
                    dataset.get("file_integrity", {}).get("sha256")
                    if isinstance(dataset.get("file_integrity"), Mapping)
                    else ""
                ),
                "version": str(tool_versions.get(name) or ""),
                "command": str(tool_commands.get(name) or ""),
                "version_required_for_commercial_grade": name != "rapidtriage" and not tool_versions.get(name),
                "command_required_for_commercial_grade": name != "rapidtriage" and not tool_commands.get(name),
            }
        )
    return {
        "tools": rows,
        "version_count": sum(1 for item in rows if item.get("version")),
        "command_count": sum(1 for item in rows if item.get("command")),
        "commercial_grade_note": "Capture external tool version and command lines before relying on cross-tool output as commercial-grade evidence.",
    }


def file_integrity(path: Path) -> dict[str, object]:
    resolved = path.expanduser().resolve()
    stat = resolved.stat()
    hasher = hashlib.sha256()
    with resolved.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return {
        "path": str(resolved),
        "size_bytes": stat.st_size,
        "sha256": hasher.hexdigest(),
        "mtime_epoch": stat.st_mtime,
    }


def infer_format(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return "json"
    if suffix in {".jsonl", ".ndjson"}:
        return "jsonl"
    if suffix == ".csv":
        return "csv"
    return ""


def value_for_key(row: Mapping[str, object], wanted: str) -> object | None:
    wanted_lower = wanted.lower()
    for key, value in row.items():
        if key.lower() == wanted_lower or key.lower().endswith(f".{wanted_lower}"):
            return value
    return None


def normalize_key(value: object) -> str:
    return str(value).strip().replace("\\", "/").lower()


def normalize_field_value(value: object) -> str:
    text = str(value).strip()
    if text.endswith(".0") and text[:-2].isdigit():
        text = text[:-2]
    return text.replace("\\", "/").lower()
