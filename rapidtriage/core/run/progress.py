"""Live per-provider run progress (``rapidtriage-run-progress.json``).

The progress file lets an analyst (and the web API) tell a slow run from a
dead one: it records the current stage, which providers are queued, running,
completed, failed, or reused, and when each one started and finished. It is
rewritten atomically (temp file + ``os.replace``) on every state change.
Progress bookkeeping must never fail a run, so write errors are captured in
the payload's ``write_errors`` list instead of being raised.

``run-progress-v2`` (plan P2 §3.2) keeps every v1 key and adds the run plan
(``plan``: groups -> tasks, see ``core/run/plan.py``), a 15-second
``heartbeat_at`` and ``_owner`` (``{pid, boot_id, heartbeat_at}``) so a reader
can tell a run whose process died (server restart) from a slow one. The plan
is copied to ``rapidtriage-run-plan.json`` when the run ends.
"""

from __future__ import annotations

import copy
import datetime as dt
import json
import os
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path

from ..json_safe import json_default
from .plan import (
    HEARTBEAT_INTERVAL_SECONDS,
    HEARTBEAT_STALE_SECONDS,
    PLAN_FILE_NAME,
    REASON_BEFORE_START,
    REASON_CANCEL_ALL,
    REASON_EXAMINER,
    REASON_FINISH,
    REASON_INTERRUPTED,
    REASON_RUNNING_CANCEL,
    STAGE_TASKS,
    TERMINAL_TASK_STATUSES,
    evaluate_control,
    find_task,
    interrupted_plan_view,
    iter_tasks,
    orphan_reason,
    owner_record,
    plan_outcome,
    refresh_plan,
)

RUN_PROGRESS_FILE_NAME = "rapidtriage-run-progress.json"
RUN_PROGRESS_VERSION = "run-progress-v2"
PROVIDER_TERMINAL_STATUSES = frozenset({"completed", "error", "reused", "partial", "cancelled", "skipped"})
MAX_PROGRESS_WRITE_ERRORS = 20
REPLACE_ATTEMPTS = 3
ROWS_WRITE_INTERVAL_SECONDS = 1.0
CANCEL_REQUESTED_MESSAGE = "취소 요청됨 · 지금까지의 행을 남기고 멈춥니다"

__all__ = [
    "RUN_PROGRESS_FILE_NAME",
    "RunProgress",
    "active_run_progress",
    "load_run_progress_view",
    "read_run_progress",
]

# Resolved output dir -> RunProgress of runs executing in this process.
_ACTIVE_RUNS: dict[str, RunProgress] = {}
_ACTIVE_LOCK = threading.Lock()


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _active_key(output_dir: Path) -> str:
    try:
        return str(Path(output_dir).expanduser().resolve())
    except OSError:
        return str(output_dir)


def active_run_progress(output_dir: Path) -> RunProgress | None:
    """The live recorder of a run executing in this process for ``output_dir``."""
    with _ACTIVE_LOCK:
        return _ACTIVE_RUNS.get(_active_key(output_dir))


class RunProgress:
    """Thread-safe recorder for ``rapidtriage-run-progress.json``.

    Nothing is written until :meth:`start` is called, so a run rejected
    before its output directory exists leaves no progress file behind.
    """

    def __init__(self, output_dir: Path, *, heartbeat_interval: float = HEARTBEAT_INTERVAL_SECONDS) -> None:
        self.output_dir = Path(output_dir)
        self.path = self.output_dir / RUN_PROGRESS_FILE_NAME
        self._lock = threading.Lock()
        self._active = False
        self._started_clock: dict[str, float] = {}
        self._task_clock: dict[str, float] = {}
        self._providers: dict[str, dict[str, object]] = {}
        self._completed_stages: list[dict[str, object]] = []
        self._write_errors: list[dict[str, object]] = []
        self._heartbeat_interval = heartbeat_interval
        self._heartbeat_stop = threading.Event()
        self._heartbeat_thread: threading.Thread | None = None
        self._last_rows_write = 0.0
        self._plan: dict[str, object] | None = None
        # RunControlWatcher of this run (set by run_triage_mode; polled by in-process writers).
        self.control_watcher: object | None = None
        # Cooperative cancel state, set from control requests.
        self._cancel_events: set[str] = set()
        self.cancel_all_requested = threading.Event()
        self.finish_requested = threading.Event()
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
            "heartbeat_at": None,
            "plan": None,
        }

    # -- run lifecycle -------------------------------------------------

    def start(self, *, stage: str) -> None:
        with self._lock:
            now = _utc_now()
            self._active = True
            self._payload["status"] = "running"
            self._payload["started_at"] = now
            self._payload["heartbeat_at"] = now
            self._payload["_owner"] = owner_record()
            self._set_stage_locked(stage, now)
            self._write_locked()
        with _ACTIVE_LOCK:
            _ACTIVE_RUNS[_active_key(self.output_dir)] = self
        self._heartbeat_stop.clear()
        if self._heartbeat_interval > 0:
            self._heartbeat_thread = threading.Thread(target=self._beat, name="rapidtriage-run-heartbeat", daemon=True)
            self._heartbeat_thread.start()

    def heartbeat(self) -> None:
        """Refresh ``heartbeat_at`` and ``_owner.heartbeat_at`` (every 15 s from a daemon thread)."""
        with self._lock:
            if not self._active or self._payload.get("status") != "running":
                return
            self._payload["heartbeat_at"] = _utc_now()
            self._payload["_owner"] = owner_record()
            self._write_locked()

    def set_run_root(self, run_root: str) -> None:
        with self._lock:
            self._payload["run_root"] = str(run_root)
            if self._plan is not None:
                self._plan["run_root"] = str(run_root)
            self._write_locked()

    def begin_stage(self, stage: str) -> None:
        with self._lock:
            now = _utc_now()
            self._set_stage_locked(stage, now)
            for task_id in STAGE_TASKS.get(stage, ()):
                self._task_running_locked(task_id, now)
            self._write_locked()

    def complete_stage(self, stage: str, details: Mapping[str, object] | None = None) -> None:
        """Record ``stage`` as completed; ``details`` (e.g. the persist step's
        started_at and row counts) are merged into its entry."""
        with self._lock:
            entry: dict[str, object] = {"stage": stage, "completed_at": _utc_now()}
            if details:
                entry.update({key: value for key, value in details.items() if key not in entry})
            self._completed_stages.append(entry)
            failed = str((details or {}).get("status") or "") == "failed"
            for task_id in STAGE_TASKS.get(stage, ()):
                self._task_finished_locked(task_id, status="failed" if failed else "completed")
            self._write_locked()

    def finish(self, *, status: str = "completed") -> None:
        """End the run (``completed`` or ``cancelled``) and write ``rapidtriage-run-plan.json``."""
        self._stop_heartbeat()
        with self._lock:
            now = _utc_now()
            self._payload["status"] = status
            self._payload["completed_at"] = now
            self._set_stage_locked("completed", now)
            if self._plan is not None:
                for task_id in STAGE_TASKS["report"]:
                    self._task_finished_locked(task_id, status="completed")
                refresh_plan(self._plan)
                if not self._plan.get("outcome"):
                    self._plan["outcome"] = plan_outcome(self._plan)
            self._write_locked()
            self._write_plan_file_locked()

    def fail(self, exc: BaseException) -> None:
        self._stop_heartbeat()
        with self._lock:
            now = _utc_now()
            self._payload["status"] = "failed"
            self._payload["completed_at"] = now
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
            if self._plan is not None:
                for task in iter_tasks(self._plan):
                    if task.get("status") == "running":
                        rows = int(task.get("rows_so_far") or 0)
                        task.update(
                            status="partial" if rows else "failed",
                            finished_at=now,
                            message=str(exc)[:300],
                        )
                refresh_plan(self._plan)
                self._plan["outcome"] = "failed"
            self._write_locked()
            self._write_plan_file_locked()

    # -- plan ------------------------------------------------------------

    def set_plan(self, plan: dict[str, object]) -> None:
        """Attach the run plan (``core/run/plan.py``); stage/provider events then update its tasks."""
        with self._lock:
            self._plan = plan
            self._payload["plan"] = plan
            stage = str(self._payload.get("stage") or "")
            if self._active and stage:
                started = str(self._payload.get("stage_started_at") or _utc_now())
                for task_id in STAGE_TASKS.get(stage, ()):
                    self._task_running_locked(task_id, started)
            refresh_plan(plan)
            self._write_locked()

    def plan_snapshot(self) -> dict[str, object] | None:
        with self._lock:
            if self._plan is None:
                return None
            refresh_plan(self._plan)
            return json.loads(json.dumps(self._plan, default=json_default))

    def task_status(self, task_id: str) -> str | None:
        with self._lock:
            task = find_task(self._plan, task_id) if self._plan is not None else None
            return str(task.get("status")) if task is not None else None

    def task_record(self, task_id: str) -> dict[str, object] | None:
        """Copy of one plan task (``None`` without a plan or for an unknown id)."""
        with self._lock:
            task = find_task(self._plan, task_id) if self._plan is not None else None
            return copy.deepcopy(task) if task is not None else None

    def task_order(self, task_id: str) -> int:
        """Plan execution order of ``task_id`` (unknown ids sort last)."""
        with self._lock:
            task = find_task(self._plan, task_id) if self._plan is not None else None
            return int(task.get("queued_order") or 0) if task is not None else 1_000_000

    def task_should_run(self, task_id: str) -> bool:
        """``False`` when the plan says ``task_id`` was skipped/cancelled before it started."""
        with self._lock:
            task = find_task(self._plan, task_id) if self._plan is not None else None
            return task is None or task.get("status") in {"queued", "running"}

    def task_cancel_requested(self, task_id: str) -> bool:
        """Cooperative cancel check of a running task (provider row loops)."""
        return task_id in self._cancel_events or self.cancel_all_requested.is_set()

    def cancel_checker(self, task_id: str) -> Callable[[], bool]:
        return lambda: self.task_cancel_requested(task_id)

    def rows_reporter(self, task_id: str) -> Callable[[int], None]:
        return lambda rows: self.task_rows(task_id, rows)

    def task_rows(self, task_id: str, rows: int) -> None:
        """Rows written so far by a running task (file write throttled to once a second)."""
        with self._lock:
            task = find_task(self._plan, task_id) if self._plan is not None else None
            if task is None:
                return
            task["rows_so_far"] = int(rows)
            now = time.monotonic()
            if now - self._last_rows_write < ROWS_WRITE_INTERVAL_SECONDS:
                return
            self._last_rows_write = now
            self._write_locked()

    def task_finished(
        self,
        task_id: str,
        *,
        status: str = "completed",
        artifact_count: int | None = None,
        output: Mapping[str, object] | None = None,
        message: str = "",
        reason: str | None = None,
    ) -> None:
        with self._lock:
            self._task_finished_locked(
                task_id, status=status, artifact_count=artifact_count, output=output, message=message, reason=reason
            )
            self._write_locked()

    def task_set_message(self, task_id: str, message: str) -> None:
        with self._lock:
            task = find_task(self._plan, task_id) if self._plan is not None else None
            if task is not None:
                task["message"] = message
                self._write_locked()

    def stage_tasks_finished(self, stage: str, *, status: str, reason: str | None = None) -> None:
        """Mark the plan tasks of a progress stage terminal (unless already terminal)."""
        with self._lock:
            for task_id in STAGE_TASKS.get(stage, ()):
                self._task_finished_locked(task_id, status=status, reason=reason)
            self._write_locked()

    def apply_control(self, request: Mapping[str, object]) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
        """Apply one control request to the plan; returns ``(accepted, rejected)``."""
        action = str(request.get("action") or "")
        targets = [dict(item) for item in request.get("targets") or [] if isinstance(item, Mapping)]
        actor = str(request.get("actor") or "cli")
        at = str(request.get("at") or _utc_now())
        with self._lock:
            if self._plan is None:
                return [], []
            accepted, rejected, effects = evaluate_control(self._plan, action, targets)
            control = self._plan.setdefault("control", {"cancel_all_at": None, "finish_at": None, "requests": []})
            control.setdefault("requests", []).append(
                {
                    "seq": request.get("seq"),
                    "action": action,
                    "targets": targets,
                    "actor": actor,
                    "at": at,
                    "accepted": accepted,
                    "rejected": rejected,
                    "effects": dict(effects),
                }
            )
            if action == "cancel_all":
                control["cancel_all_at"] = control.get("cancel_all_at") or at
                self.cancel_all_requested.set()
            if action == "finish":
                control["finish_at"] = control.get("finish_at") or at
                self.finish_requested.set()
            reason = {"cancel_all": REASON_CANCEL_ALL, "finish": REASON_FINISH}.get(action, REASON_EXAMINER)
            requested_by = {"actor": actor, "at": at}
            now = _utc_now()
            for task_id, effect in effects.items():
                task = find_task(self._plan, task_id)
                if task is None:
                    continue
                task["requested_by"] = dict(requested_by)
                if effect == "skip":
                    task.update(status="skipped", reason=reason, finished_at=now)
                    self._mirror_provider_locked(task_id, "skipped")
                elif effect == "cancel-queued":
                    task.update(
                        status="cancelled",
                        reason=REASON_BEFORE_START if action == "cancel" else reason,
                        finished_at=now,
                    )
                    self._mirror_provider_locked(task_id, "cancelled")
                elif effect == "cancel-running":
                    task["reason"] = REASON_RUNNING_CANCEL if action == "cancel" else reason
                    task["message"] = CANCEL_REQUESTED_MESSAGE
                    self._cancel_events.add(task_id)
            refresh_plan(self._plan)
            self._write_locked()
            return accepted, rejected

    def request_cancel_all(self, *, actor: str = "cli") -> None:
        """In-process "모두 취소" (CLI Ctrl+C)."""
        self.apply_control({"action": "cancel_all", "targets": [], "actor": actor, "at": _utc_now(), "seq": None})

    def finalize_plan(self) -> dict[str, object] | None:
        """Close the plan before the summary is built: report task done, ``outcome`` recorded."""
        with self._lock:
            if self._plan is None:
                return None
            for task_id in STAGE_TASKS["report"]:
                self._task_finished_locked(task_id, status="completed")
            refresh_plan(self._plan)
            self._plan["outcome"] = plan_outcome(self._plan)
            self._write_locked()
            return json.loads(json.dumps(self._plan, default=json_default))

    # -- providers -----------------------------------------------------

    def register_providers(self, kinds: Iterable[str]) -> None:
        with self._lock:
            providers = self._providers
            for kind in kinds:
                entry = providers.setdefault(str(kind), self._new_entry())
                task = find_task(self._plan, str(kind)) if self._plan is not None else None
                if task is not None and task.get("status") in {"skipped", "cancelled"} and entry["status"] == "queued":
                    # Left out by the run plan before the run: terminal in the v1 view too.
                    entry["status"] = task["status"]
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
            self._task_running_locked(str(kind), str(entry["started_at"]))
            self._refresh_counts_locked()
            self._write_locked()

    def provider_finished(
        self,
        kind: str,
        *,
        status: str,
        artifact_count: int,
        output: Mapping[str, object] | None = None,
        parser_error_count: int = 0,
        message: str = "",
    ) -> None:
        """Record a terminal state for ``kind``: ``completed``/``error``/``partial``/``cancelled``."""
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
            task_status = "failed" if status == "error" else status
            if task_status == "failed" and int(artifact_count) > 0:
                task_status = "partial"
            self._task_finished_locked(
                str(kind),
                status=task_status,
                artifact_count=int(artifact_count),
                output=output,
                message=message,
                parser_error_count=parser_error_count,
            )
            self._refresh_counts_locked()
            self._write_locked()

    def provider_reused(self, kind: str, *, artifact_count: int, output: Mapping[str, object] | None = None) -> None:
        with self._lock:
            entry = self._providers.setdefault(str(kind), self._new_entry())
            if entry["status"] in PROVIDER_TERMINAL_STATUSES:
                return
            entry["status"] = "reused"
            entry["completed_at"] = _utc_now()
            entry["duration_ms"] = 0
            entry["artifact_count"] = int(artifact_count)
            self._task_finished_locked(
                str(kind),
                status="completed",
                artifact_count=int(artifact_count),
                output=output,
                reused=True,
                message="이전 런 출력 재사용",
            )
            self._refresh_counts_locked()
            self._write_locked()

    def mark_unfinished_reused(self) -> None:
        """Mark every provider not yet finished as reused (resumed manifest)."""
        with self._lock:
            now = _utc_now()
            for kind, entry in self._providers.items():
                if entry["status"] in PROVIDER_TERMINAL_STATUSES:
                    continue
                entry["status"] = "reused"
                entry["completed_at"] = now
                entry["duration_ms"] = 0
                self._task_finished_locked(kind, status="completed", reused=True, message="이전 런 출력 재사용")
            self._refresh_counts_locked()
            self._write_locked()

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return json.loads(json.dumps(self._payload, default=json_default))

    # -- internals -----------------------------------------------------

    def _beat(self) -> None:
        while not self._heartbeat_stop.wait(self._heartbeat_interval):
            self.heartbeat()

    def _stop_heartbeat(self) -> None:
        self._heartbeat_stop.set()
        thread = self._heartbeat_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)
        self._heartbeat_thread = None
        with _ACTIVE_LOCK:
            key = _active_key(self.output_dir)
            if _ACTIVE_RUNS.get(key) is self:
                _ACTIVE_RUNS.pop(key, None)

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

    def _mirror_provider_locked(self, kind: str, status: str) -> None:
        entry = self._providers.get(kind)
        if entry is not None and entry["status"] not in PROVIDER_TERMINAL_STATUSES:
            entry["status"] = status
            entry["completed_at"] = _utc_now()
            self._refresh_counts_locked()

    def _task_running_locked(self, task_id: str, now: str) -> None:
        task = find_task(self._plan, task_id) if self._plan is not None else None
        if task is None or task.get("status") != "queued":
            return
        task["status"] = "running"
        task["started_at"] = now
        task["rows_so_far"] = 0
        self._task_clock[task_id] = time.perf_counter()

    def _task_finished_locked(
        self,
        task_id: str,
        *,
        status: str,
        artifact_count: int | None = None,
        output: Mapping[str, object] | None = None,
        message: str = "",
        reason: str | None = None,
        reused: bool = False,
        parser_error_count: int = 0,
    ) -> None:
        task = find_task(self._plan, task_id) if self._plan is not None else None
        if task is None or task.get("status") in TERMINAL_TASK_STATUSES:
            return
        now = _utc_now()
        started = self._task_clock.pop(task_id, None)
        task["status"] = status
        task["reused"] = bool(reused)
        if not reused:
            task["started_at"] = task.get("started_at") or now
        task["finished_at"] = now
        if started is not None:
            task["duration_ms"] = max(0, int((time.perf_counter() - started) * 1000))
        elif reused:
            task["duration_ms"] = 0
        if artifact_count is not None:
            task["artifact_count"] = int(artifact_count)
            task["rows_so_far"] = int(artifact_count)
        if output is not None:
            task["output"] = dict(output)
        if message:
            task["message"] = message
        elif task.get("message") == CANCEL_REQUESTED_MESSAGE and status == "completed":
            task["message"] = "취소 요청 시점에 실행 중이어서 단계 끝까지 마침"
        if reason is not None:
            task["reason"] = reason
        if parser_error_count:
            task["parser_error_count"] = int(parser_error_count)
        self._cancel_events.discard(task_id)

    def _write_locked(self) -> None:
        self._payload["updated_at"] = _utc_now()
        if self._plan is not None:
            refresh_plan(self._plan)
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

    def _write_plan_file_locked(self) -> None:
        if self._plan is None or not self._active:
            return
        path = self.output_dir / PLAN_FILE_NAME
        tmp_path = path.with_name(path.name + ".tmp")
        try:
            tmp_path.write_text(
                json.dumps(self._plan, ensure_ascii=False, indent=2, default=json_default) + "\n",
                encoding="utf-8",
            )
            os.replace(tmp_path, path)
        except Exception as exc:  # the plan file must never fail the run
            if len(self._write_errors) < MAX_PROGRESS_WRITE_ERRORS:
                self._write_errors.append({"at": _utc_now(), "error_type": type(exc).__name__, "message": str(exc)})


def read_run_progress(output_dir: Path) -> dict[str, object] | None:
    """Return the parsed progress file for ``output_dir`` or ``None``."""
    path = Path(output_dir) / RUN_PROGRESS_FILE_NAME
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _epoch(value: object) -> float | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.timestamp()


def load_run_progress_view(output_dir: Path, *, now: float | None = None) -> dict[str, object] | None:
    """Progress as served to readers: live when running here, ``interrupted`` when its process died.

    Adds ``live`` (the run process is alive) and ``stale`` (running but no
    heartbeat for 90 s) and drops ``_owner``. An orphaned ``running`` file is
    shown as ``interrupted`` with its running tasks ``partial``/``cancelled``;
    the file itself is never rewritten (same rule as analyses ``load_state``).
    """
    active = active_run_progress(output_dir)
    payload = active.snapshot() if active is not None else read_run_progress(output_dir)
    if payload is None:
        return None
    view = copy.deepcopy(payload)
    owner = view.pop("_owner", None)
    now = time.time() if now is None else now
    view["live"] = False
    view["stale"] = False
    if view.get("status") != "running":
        return view
    reason = orphan_reason(owner, now=now, active_here=active is not None)
    if reason is None:
        view["live"] = True
        heartbeat = _epoch(view.get("heartbeat_at") or view.get("updated_at"))
        view["stale"] = heartbeat is not None and now - heartbeat > HEARTBEAT_STALE_SECONDS
        return view
    heartbeat_at = owner.get("heartbeat_at") if isinstance(owner, Mapping) else None
    at = (
        dt.datetime.fromtimestamp(float(heartbeat_at), dt.timezone.utc).isoformat()
        if isinstance(heartbeat_at, (int, float))
        else str(view.get("updated_at") or "")
    )
    view["status"] = "interrupted"
    view["interrupted_reason"] = reason
    view["error"] = view.get("error") or {"stage": view.get("stage"), "message": REASON_INTERRUPTED}
    if isinstance(view.get("plan"), Mapping):
        view["plan"] = interrupted_plan_view(view["plan"], at=at or None)
    return view
