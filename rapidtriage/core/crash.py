from __future__ import annotations

import datetime as dt
import json
import os
import platform
import traceback
import uuid
from pathlib import Path
from typing import Mapping


DEFAULT_CRASH_DIR = Path.home() / ".rapidtriage" / "crash-reports"


def crash_log_dir() -> Path:
    return Path(os.environ.get("RAPIDTRIAGE_CRASH_LOG_DIR") or DEFAULT_CRASH_DIR).expanduser().resolve()


def write_crash_report(
    exc: BaseException,
    *,
    context: Mapping[str, object] | None = None,
    output_dir: Path | None = None,
) -> dict[str, object]:
    directory = (output_dir or crash_log_dir()).expanduser().resolve()
    directory.mkdir(parents=True, exist_ok=True)
    crash_id = f"crash-{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
    report_path = directory / f"{crash_id}.json"
    payload = {
        "command": "crash-report",
        "crash_id": crash_id,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "local_only": True,
        "privacy_note": "Crash reports are written locally and are never uploaded by RapidTriage.",
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
