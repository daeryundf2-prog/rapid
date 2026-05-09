from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Mapping


RUN_SUMMARY_NAME = "rapidtriage-run-summary.json"


class RunValidationAttachmentError(ValueError):
    """Raised when a validation diff cannot be attached to a completed run."""


def attach_validation_diff_outputs(
    run_output: Path,
    diff_outputs: Mapping[str, Path],
    *,
    overwrite: bool = False,
) -> dict[str, object]:
    if not diff_outputs:
        raise RunValidationAttachmentError("at least one validation diff output is required")
    summary_path = resolve_run_summary_path(run_output)
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    if not isinstance(summary, dict):
        raise RunValidationAttachmentError("run summary must be a JSON object")
    outputs = summary.get("outputs")
    if not isinstance(outputs, dict):
        raise RunValidationAttachmentError("run summary does not include outputs")
    output_dir = Path(str(summary.get("output_dir") or summary_path.parent)).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    attachment_dir = output_dir / "validation-diffs"
    attachment_dir.mkdir(parents=True, exist_ok=True)

    attached_at = dt.datetime.now(dt.timezone.utc).isoformat()
    rows: list[dict[str, object]] = []
    for name, source in sorted(diff_outputs.items()):
        safe_name = safe_output_name(name)
        source = source.expanduser().resolve()
        if not source.is_file():
            raise RunValidationAttachmentError(f"validation diff output not found: {source}")
        key = f"validation_diff_{safe_name}"
        if key in outputs and not overwrite:
            raise RunValidationAttachmentError(f"run summary already has output {key}; use --overwrite to replace")
        destination = attachment_dir / f"{safe_name}{source.suffix or '.json'}"
        if destination.exists() and not overwrite:
            raise RunValidationAttachmentError(f"validation diff attachment already exists: {destination}")
        try:
            source_payload = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise RunValidationAttachmentError(f"validation diff output must be readable JSON: {source}") from exc
        shutil.copy2(source, destination)
        row = {
            "name": safe_name,
            "output_key": key,
            "source_path": str(source),
            "attached_path": str(destination),
            "attached_at": attached_at,
            "source_sha256": file_sha256(source),
            "attached_sha256": file_sha256(destination),
            "size_bytes": destination.stat().st_size,
            "attachment_status": "copied-into-run-output",
            "source_command": source_payload.get("command") if isinstance(source_payload, Mapping) else "",
            "source_status": source_payload.get("status") if isinstance(source_payload, Mapping) else "",
        }
        outputs[key] = str(destination)
        rows.append(row)

    prior = summary.get("validation_diff_attachments")
    previous_rows = []
    if isinstance(prior, Mapping) and isinstance(prior.get("items"), list):
        previous_rows = [item for item in prior["items"] if isinstance(item, Mapping)]
    attachment_manifest = {
        "profile_version": "run-validation-diff-attachments-v1",
        "attached_at": attached_at,
        "attachment_count": len(previous_rows) + len(rows),
        "items": [*previous_rows, *rows],
        "reportability": "validation-diff-attachment-inventory",
        "commercial_grade_ready": False,
        "blockers": [
            "attached-diff-must-pass-cross-tool-validation",
            "independent-reviewer-signoff-required",
            "source-evidence-hash-and-tool-command-required",
        ],
    }
    attachment_manifest["manifest_hash"] = hashlib.sha256(
        json.dumps(attachment_manifest, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    manifest_path = attachment_dir / "validation-diff-attachments.json"
    manifest_path.write_text(json.dumps(attachment_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    outputs["validation_diff_manifest"] = str(manifest_path)
    summary["outputs"] = outputs
    summary["validation_diff_attachments"] = attachment_manifest
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    summary_sha256 = file_sha256(summary_path)
    audit_path = summary_path.with_name("rapidtriage-run-validation-diff-attachments.audit.json")
    audit_payload = {
        "command": "run-attach-validation-diff",
        "profile_version": "run-validation-diff-attachment-audit-v1",
        "summary_path": str(summary_path),
        "output_dir": str(output_dir),
        "attached_count": len(rows),
        "attached_outputs": rows,
        "manifest_path": str(manifest_path),
        "manifest_hash": attachment_manifest["manifest_hash"],
        "summary_sha256": summary_sha256,
    }
    audit_path.write_text(json.dumps(audit_payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {
        "command": "run-attach-validation-diff",
        "summary_path": str(summary_path),
        "output_dir": str(output_dir),
        "attached_count": len(rows),
        "attached_outputs": rows,
        "validation_diff_attachments": attachment_manifest,
        "manifest_path": str(manifest_path),
        "summary_sha256": summary_sha256,
        "audit_path": str(audit_path),
    }


def resolve_run_summary_path(run_output: Path) -> Path:
    resolved = run_output.expanduser().resolve()
    if resolved.is_dir():
        resolved = resolved / RUN_SUMMARY_NAME
    if not resolved.is_file():
        raise RunValidationAttachmentError(f"run summary not found: {resolved}")
    return resolved


def safe_output_name(name: str) -> str:
    text = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(name).strip()).strip("-._").lower()
    if not text:
        raise RunValidationAttachmentError("validation diff output name cannot be empty")
    return text[:80]


def file_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()
