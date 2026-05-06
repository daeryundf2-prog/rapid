from __future__ import annotations

import datetime as dt
import json
import os
import platform
import traceback
import uuid
from pathlib import Path
from typing import Mapping

from .forensic_accuracy import build_accuracy_gate


DEFAULT_CRASH_DIR = Path.home() / ".rapidtriage" / "crash-reports"
CRASH_REPORTING_GAP_ID = "#105"
CRASH_REPORT_TRUSTED_DIFF_BLOCKER_105 = "trusted-crash-redaction-export-diff-missing"
CRASH_REPORT_TRUSTED_TOOLS = {"crash-redaction-checklist", "local-crash-export-log", "enterprise-no-upload-review"}


def crash_log_dir() -> Path:
    return Path(os.environ.get("RAPIDTRIAGE_CRASH_LOG_DIR") or DEFAULT_CRASH_DIR).expanduser().resolve()


def write_crash_report(
    exc: BaseException,
    *,
    context: Mapping[str, object] | None = None,
    output_dir: Path | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    directory = (output_dir or crash_log_dir()).expanduser().resolve()
    directory.mkdir(parents=True, exist_ok=True)
    crash_id = f"crash-{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
    report_path = directory / f"{crash_id}.json"
    if trusted_diff is None:
        trusted_diff = missing_crash_report_trusted_diff()
    blockers = []
    if trusted_diff.get("status") != "pass":
        blockers.append(CRASH_REPORT_TRUSTED_DIFF_BLOCKER_105)
    payload = {
        "command": "crash-report",
        "crash_id": crash_id,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "commercial_gap_ids": [CRASH_REPORTING_GAP_ID],
        "core_accuracy_gates": crash_report_core_accuracy_gates(
            crash_id=crash_id,
            report_path=report_path,
            trusted_diff=trusted_diff,
        ),
        "local_only": True,
        "privacy_note": "Crash reports are written locally and are never uploaded by RapidTriage.",
        "trusted_crash_report_diff": trusted_diff,
        "blockers": blockers,
        "exception": {
            "type": type(exc).__name__,
            "message": str(exc)[:1000],
            "traceback": traceback.format_exception(type(exc), exc, exc.__traceback__)[-20:],
        },
        "runtime": {
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "context": sanitize_context(context or {}),
    }
    report_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"crash_id": crash_id, "path": str(report_path), "payload": payload}


def missing_crash_report_trusted_diff() -> dict[str, object]:
    return {
        "status": "missing",
        "trusted_tool": None,
        "commercial_gap_ids": [CRASH_REPORTING_GAP_ID],
        "blocker": CRASH_REPORT_TRUSTED_DIFF_BLOCKER_105,
        "required_trusted_tools": sorted(CRASH_REPORT_TRUSTED_TOOLS),
    }


def build_crash_report_trusted_diff(
    rapid_report: Mapping[str, object],
    trusted_report: Mapping[str, object],
    *,
    trusted_tool: str = "crash-redaction-checklist",
) -> dict[str, object]:
    compared_fields = ["local_only", "privacy_note", "context"]
    mismatches = []
    for field in compared_fields:
        rapid_value = normalize_crash_report_value(rapid_report.get(field))
        trusted_value = normalize_crash_report_value(trusted_report.get(field))
        if rapid_value != trusted_value:
            mismatches.append({"field": field, "rapid": rapid_value, "trusted": trusted_value})
    status = "pass" if not mismatches and trusted_tool in CRASH_REPORT_TRUSTED_TOOLS else "fail"
    return {
        "status": status,
        "trusted_tool": trusted_tool,
        "commercial_gap_ids": [CRASH_REPORTING_GAP_ID],
        "compared_fields": compared_fields,
        "mismatches": mismatches,
        "blocker": None if status == "pass" else CRASH_REPORT_TRUSTED_DIFF_BLOCKER_105,
    }


def crash_report_core_accuracy_gates(
    *,
    crash_id: str,
    report_path: Path,
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = [
        "local crash report written",
        "sensitive context redacted",
        "runtime metadata captured",
        "no-upload policy recorded",
        "operator export limitation disclosed",
    ]
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted crash redaction/export diff pass")
    return [
        build_accuracy_gate(
            105,
            satisfied_checks=satisfied,
            evidence_refs=[f"crash_id:{crash_id}", f"path:{report_path}"],
        )
    ]


def normalize_crash_report_value(value: object) -> object:
    if isinstance(value, list):
        return sorted(json.dumps(item, ensure_ascii=False, sort_keys=True, default=str) for item in value)
    if isinstance(value, Mapping):
        return json.dumps(dict(value), ensure_ascii=False, sort_keys=True, default=str)
    return value


def sanitize_context(context: Mapping[str, object]) -> dict[str, object]:
    sanitized: dict[str, object] = {}
    for key, value in context.items():
        text = str(value)
        lowered = key.lower()
        if any(token in lowered for token in ("token", "secret", "password", "credential", "cookie")):
            sanitized[key] = "<redacted>"
        elif len(text) > 500:
            sanitized[key] = text[:500] + "...<truncated>"
        else:
            sanitized[key] = value
    return sanitized
