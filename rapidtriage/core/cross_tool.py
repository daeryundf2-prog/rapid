from __future__ import annotations

import csv
import datetime as dt
import json
from pathlib import Path
from typing import Iterable, Mapping

from .docs import write_result


MAX_ROWS_PER_TOOL = 100_000
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


class CrossToolValidationError(ValueError):
    """Raised when cross-tool validation inputs are invalid."""


def build_cross_tool_validation_report(
    *,
    rapid_output: Path,
    reference_outputs: Mapping[str, Path],
    output: Path | None = None,
    min_overlap: float = 0.8,
    backlog_items: Iterable[int] | None = None,
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
        "comparisons": comparisons,
        "cross_tool_validation_assessment": cross_tool_validation_assessment(
            status=status,
            comparisons=comparisons,
            backlog_items=mapped_items,
            output=output,
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
        "row_count": len(rows),
        "truncated": len(rows) >= MAX_ROWS_PER_TOOL,
        "key_count": len(keys),
        "keys": keys[:5000],
        "sample_rows": rows[:5],
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
        "release_gate": "review-required" if status != "pass" else "comparison-passed",
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
) -> list[dict[str, object]]:
    evidence_paths = [str(output.expanduser().resolve())] if output is not None else [
        str(rapid_output.expanduser().resolve()),
        *[str(path.expanduser().resolve()) for path in reference_outputs.values()],
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
                ],
                "reference_tools": reference_names,
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
) -> dict[str, object]:
    return {
        "status": status,
        "backlog_items": backlog_items,
        "comparison_count": len(comparisons),
        "output": str(output.expanduser().resolve()) if output is not None else "",
        "ready_for_validated_gate": bool(backlog_items) and status == "pass" and output is not None,
        "ready_for_commercial_grade": False,
        "commercial_grade_blockers": [
            "corpus-scope-and-source-hash-review-required",
            "independent-reviewer-signoff-required",
            "external-tool-version-and-command-capture-required",
        ],
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
