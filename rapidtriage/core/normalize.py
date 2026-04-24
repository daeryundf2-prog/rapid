from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Mapping

from .search import load_run_summary


class NormalizationError(ValueError):
    """Raised when run outputs cannot be normalized."""


def build_normalized_case(run_output: Path, *, case_id: str | None = None) -> dict[str, object]:
    summary = load_run_summary(run_output)
    outputs = summary.get("outputs") if isinstance(summary.get("outputs"), Mapping) else {}
    normalized_case_id = case_id or Path(str(summary.get("output_dir") or run_output)).name or "case"
    files = normalize_files(read_json_output(outputs, "files"))
    artifacts = normalize_artifacts(outputs)
    events = normalize_events(read_json_output(outputs, "timeline"))
    documents = normalize_documents(read_json_output(outputs, "docs"))
    return {
        "command": "normalize",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "case": {
            "case_id": normalized_case_id,
            "name": normalized_case_id,
            "source_root": str(summary.get("root") or ""),
            "run_output": str(Path(run_output).expanduser().resolve()),
        },
        "summary": {
            "file_record_count": len(files),
            "artifact_count": len(artifacts),
            "event_count": len(events),
            "indexed_document_count": len(documents),
        },
        "models": {
            "file_records": files,
            "artifacts": artifacts,
            "events": events,
            "indexed_documents": documents,
        },
    }


def read_json_output(outputs: Mapping[str, object], name: str) -> dict[str, object]:
    raw = outputs.get(name)
    if not raw:
        return {}
    try:
        payload = json.loads(Path(str(raw)).expanduser().resolve().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def normalize_files(payload: Mapping[str, object]) -> list[dict[str, object]]:
    rows = payload.get("candidates") if isinstance(payload.get("candidates"), list) else []
    output = []
    for index, row in enumerate(rows, start=1):
        if not isinstance(row, Mapping):
            continue
        path = str(row.get("path") or "")
        output.append(
            {
                "id": stable_id("file", path, index),
                "model": "FileRecord",
                "path": path,
                "name": str(row.get("name") or Path(path).name),
                "extension": str(row.get("extension") or ""),
                "size": row.get("size"),
                "modified_at": row.get("modified_at"),
                "categories": list(row.get("categories") or []),
                "parser": "rapidtriage.files",
                "parser_version": "1",
            }
        )
    return output


def normalize_artifacts(outputs: Mapping[str, object]) -> list[dict[str, object]]:
    output = []
    index = 0
    for name, raw_path in sorted(outputs.items()):
        if not str(name).startswith("artifacts_"):
            continue
        try:
            payload = json.loads(Path(str(raw_path)).expanduser().resolve().read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        rows = payload.get("artifacts") if isinstance(payload, Mapping) else None
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            index += 1
            artifact_type = str(row.get("artifact_type") or str(name).removeprefix("artifacts_"))
            output.append(
                {
                    "id": stable_id("artifact", artifact_type, index),
                    "model": "Artifact",
                    "artifact_type": artifact_type,
                    "title": artifact_type,
                    "summary": artifact_summary(row),
                    "source": str(name),
                    "parser": str(row.get("provider") or name),
                    "parser_version": "1",
                    "confidence": row.get("confidence"),
                    "data": dict(row),
                }
            )
    return output


def normalize_events(payload: Mapping[str, object]) -> list[dict[str, object]]:
    rows = payload.get("events") if isinstance(payload.get("events"), list) else []
    output = []
    for index, row in enumerate(rows, start=1):
        if not isinstance(row, Mapping):
            continue
        output.append(
            {
                "id": stable_id("event", str(row.get("timestamp") or ""), index),
                "model": "Event",
                "timestamp": str(row.get("timestamp") or ""),
                "timestamp_kind": str(row.get("timestamp_kind") or "observed"),
                "event_type": str(row.get("event_type") or "observed"),
                "source": str(row.get("source") or ""),
                "summary": str(row.get("summary") or ""),
                "path": str(row.get("path") or ""),
                "parser": "rapidtriage.timeline",
                "parser_version": "1",
            }
        )
    return output


def normalize_documents(payload: Mapping[str, object]) -> list[dict[str, object]]:
    rows = payload.get("candidates") if isinstance(payload.get("candidates"), list) else []
    output = []
    for index, row in enumerate(rows, start=1):
        if not isinstance(row, Mapping):
            continue
        path = str(row.get("path") or "")
        output.append(
            {
                "id": stable_id("doc", path, index),
                "model": "IndexedDocument",
                "path": path,
                "title": Path(path).name,
                "kind": str(row.get("kind") or ""),
                "matched": bool(row.get("matches")),
                "parser": "rapidtriage.docs",
                "parser_version": "1",
            }
        )
    return output


def artifact_summary(row: Mapping[str, object]) -> str:
    details = row.get("details") if isinstance(row.get("details"), Mapping) else {}
    for key in ("url", "source_url", "target_path", "entry_name", "summary", "path"):
        value = details.get(key) or row.get(key)
        if value:
            return str(value)
    return str(row.get("artifact_type") or "artifact")


def stable_id(prefix: str, value: str, index: int) -> str:
    digest = hashlib.sha256(f"{prefix}|{value}|{index}".encode("utf-8")).hexdigest()
    return f"{prefix}-{digest[:16]}"
