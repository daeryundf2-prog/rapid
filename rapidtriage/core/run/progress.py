"""Live per-provider run progress (``rapidtriage-run-progress.json``).

The progress file lets an analyst (and the web API) tell a slow run from a
dead one: it records the current stage, which providers are queued, running,
completed, failed, or reused, and when each one started and finished. It is
rewritten atomically (temp file + ``os.replace``) on every state change.
Progress bookkeeping must never fail a run, so write errors are captured in
the payload's ``write_errors`` list instead of being raised.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import threading
import time
from collections.abc import Iterable, Mapping
from pathlib import Path

from ..json_safe import json_default

RUN_PROGRESS_FILE_NAME = "rapidtriage-run-progress.json"
RUN_PROGRESS_VERSION = "run-progress-v1"
PROVIDER_TERMINAL_STATUSES = frozenset({"completed", "error", "reused"})
MAX_PROGRESS_WRITE_ERRORS = 20
REPLACE_ATTEMPTS = 3

__all__ = [
    "RUN_PROGRESS_FILE_NAME",
    "RunProgress",
    "read_run_progress",
]


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


class RunProgress:
    """Thread-safe recorder for ``rapidtriage-run-progress.json``.

    Nothing is written until :meth:`start` is called, so a run rejected
    before its output directory exists leaves no progress file behind.
    """

    def __init__(self, output_dir: Path) -> None:
        self.path = Path(output_dir) / RUN_PROGRESS_FILE_NAME
        self._lock = threading.Lock()
        self._active = False
        self._started_clock: dict[str, float] = {}
        self._providers: dict[str, dict[str, object]] = {}
        self._completed_stages: list[dict[str, object]] = []
        self._write_errors: list[dict[str, object]] = []
        self._payload: dict[str, object] = {
            "command": "run-progress",
            "version": RUN_PROGRESS_VERSION,
            "status": "pending",
            "run_root": "",
            "stage": "",
            "stage_started_at": None,
            "completed_stages": self._completed_stages,
            "started_at": None,
            "updated_at": None,
            "completed_at": None,
            "providers": self._providers,
            "running": [],
            "completed_count": 0,
            "error_count": 0,
            "total_count": 0,
            "error": None,
            "write_errors": self._write_errors,
        }

    # -- run lifecycle -------------------------------------------------

    def start(self, *, stage: str) -> None:
        with self._lock:
            now = _utc_now()
            self._active = True
            self._payload["status"] = "running"
            self._payload["started_at"] = now
            self._set_stage_locked(stage, now)
            self._write_locked()

    def set_run_root(self, run_root: str) -> None:
        with self._lock:
            self._payload["run_root"] = str(run_root)
            self._write_locked()

    def begin_stage(self, stage: str) -> None:
        with self._lock:
            self._set_stage_locked(stage, _utc_now())
            self._write_locked()

    def complete_stage(self, stage: str, details: Mapping[str, object] | None = None) -> None:
        """Record ``stage`` as completed; ``details`` (e.g. the persist step's
        started_at and row counts) are merged into its entry."""
        with self._lock:
            entry: dict[str, object] = {"stage": stage, "completed_at": _utc_now()}
            if details:
                entry.update({key: value for key, value in details.items() if key not in entry})
            self._completed_stages.append(entry)
            self._write_locked()

    def finish(self) -> None:
        with self._lock:
            now = _utc_now()
            self._payload["status"] = "completed"
            self._payload["completed_at"] = now
            self._set_stage_locked("completed", now)
            self._write_locked()

    def fail(self, exc: BaseException) -> None:
        with self._lock:
            self._payload["status"] = "failed"
            self._payload["completed_at"] = _utc_now()
            error: dict[str, object] = {
                "stage": self._payload.get("stage"),
                "error_type": type(exc).__name__,
                "message": str(exc),
            }
            code = getattr(exc, "code", None)
            if isinstance(code, str) and code:
                # e.g. ``memory-cap`` for MemoryCapExceeded (fail-fast cap breach).
                error["code"] = code
            self._payload["error"] = error
            self._write_locked()

    # -- providers -----------------------------------------------------

    def register_providers(self, kinds: Iterable[str]) -> None:
        with self._lock:
            providers = self._providers
            for kind in kinds:
                providers.setdefault(str(kind), self._new_entry())
            self._refresh_counts_locked()
            self._write_locked()

    def provider_running(self, kind: str) -> None:
        """Mark ``kind`` running; providers already finished are left alone."""
        with self._lock:
            entry = self._providers.setdefault(str(kind), self._new_entry())
            if entry["status"] in PROVIDER_TERMINAL_STATUSES:
                return
            entry["status"] = "running"
            entry["started_at"] = _utc_now()
            self._started_clock[str(kind)] = time.perf_counter()
            self._refresh_counts_locked()
            self._write_locked()

    def provider_finished(self, kind: str, *, status: str, artifact_count: int) -> None:
        """Record a terminal ``completed``/``error`` state for ``kind``."""
        with self._lock:
            entry = self._providers.setdefault(str(kind), self._new_entry())
            if entry["status"] in PROVIDER_TERMINAL_STATUSES:
                return
            now = _utc_now()
            started = self._started_clock.pop(str(kind), None)
            entry["status"] = status
            entry["started_at"] = entry["started_at"] or now
            entry["completed_at"] = now
            entry["duration_ms"] = max(0, int((time.perf_counter() - started) * 1000)) if started is not None else 0
            entry["artifact_count"] = int(artifact_count)
            self._refresh_counts_locked()
            self._write_locked()

    def provider_reused(self, kind: str, *, artifact_count: int) -> None:
        with self._lock:
            entry = self._providers.setdefault(str(kind), self._new_entry())
            if entry["status"] in PROVIDER_TERMINAL_STATUSES:
                return
            entry["status"] = "reused"
            entry["completed_at"] = _utc_now()
            entry["duration_ms"] = 0
            entry["artifact_count"] = int(artifact_count)
            self._refresh_counts_locked()
            self._write_locked()

    def mark_unfinished_reused(self) -> None:
        """Mark every provider not yet finished as reused (resumed manifest)."""
        with self._lock:
            now = _utc_now()
            for entry in self._providers.values():
                if entry["status"] in PROVIDER_TERMINAL_STATUSES:
                    continue
                entry["status"] = "reused"
                entry["completed_at"] = now
                entry["duration_ms"] = 0
            self._refresh_counts_locked()
            self._write_locked()

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return json.loads(json.dumps(self._payload, default=json_default))

    # -- internals -----------------------------------------------------

    @staticmethod
    def _new_entry() -> dict[str, object]:
        return {
            "status": "queued",
            "started_at": None,
            "completed_at": None,
            "duration_ms": None,
            "artifact_count": None,
        }

    def _set_stage_locked(self, stage: str, now: str) -> None:
        self._payload["stage"] = stage
        self._payload["stage_started_at"] = now

    def _refresh_counts_locked(self) -> None:
        providers = self._providers
        self._payload["total_count"] = len(providers)
        self._payload["completed_count"] = sum(
            1 for entry in providers.values() if entry["status"] in PROVIDER_TERMINAL_STATUSES
        )
        self._payload["error_count"] = sum(1 for entry in providers.values() if entry["status"] == "error")
        self._payload["running"] = [
            {"kind": kind, "started_at": entry["started_at"]}
            for kind, entry in providers.items()
            if entry["status"] == "running"
        ]

    def _write_locked(self) -> None:
        self._payload["updated_at"] = _utc_now()
        if not self._active:
            return
        tmp_path = self.path.with_name(self.path.name + ".tmp")
        try:
            text = json.dumps(self._payload, ensure_ascii=False, indent=2, default=json_default)
            tmp_path.write_text(text + "\n", encoding="utf-8")
            for attempt in range(REPLACE_ATTEMPTS):
                try:
                    os.replace(tmp_path, self.path)
                    break
                except PermissionError:
                    # Windows refuses to replace a file another process (the
                    # web API) has open for reading; retry briefly.
                    if attempt == REPLACE_ATTEMPTS - 1:
                        raise
                    time.sleep(0.05)
        except Exception as exc:  # progress must never fail the run
            if len(self._write_errors) < MAX_PROGRESS_WRITE_ERRORS:
                self._write_errors.append({"at": self._payload["updated_at"], "error_type": type(exc).__name__, "message": str(exc)})


def read_run_progress(output_dir: Path) -> dict[str, object] | None:
    """Return the parsed progress file for ``output_dir`` or ``None``."""
    path = Path(output_dir) / RUN_PROGRESS_FILE_NAME
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None
