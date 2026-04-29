from __future__ import annotations

import datetime as dt
import json
import os
import threading
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Mapping

from .rules import RuleConfigError, load_rule_set
from .run import RunModeError, run_triage_mode


RUN_STATUSES = ("queued", "running", "completed", "failed", "canceled")
JOB_STEP_NAMES = ("prepare", "triage", "persist", "finalize")


def now_iso() -> str:
    return dt.datetime.now().isoformat()


@dataclass(frozen=True)
class RunRequest:
    root: str
    mode: str
    output_dir: str | None = None
    input_kind: str | None = None
    rules: str | None = None
    dry_run: bool = False
    read_only: bool = False
    max_extract_size_bytes: int = 0
    max_file_count: int = 0
    overwrite: bool = False
    resume: bool = False

    def to_dict(self) -> Dict[str, object]:
        return {
            "root": self.root,
            "mode": self.mode,
            "output_dir": self.output_dir,
            "input_kind": self.input_kind,
            "rules": self.rules,
            "dry_run": self.dry_run,
            "read_only": self.read_only,
            "max_extract_size_bytes": self.max_extract_size_bytes,
            "max_file_count": self.max_file_count,
            "overwrite": self.overwrite,
            "resume": self.resume,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "RunRequest":
        return cls(
            root=str(payload.get("root") or ""),
            mode=str(payload.get("mode") or ""),
            output_dir=str(payload["output_dir"]) if payload.get("output_dir") else None,
            input_kind=str(payload["input_kind"]) if payload.get("input_kind") else None,
            rules=str(payload["rules"]) if payload.get("rules") else None,
            dry_run=bool(payload.get("dry_run", False)),
            read_only=bool(payload.get("read_only", False)),
            max_extract_size_bytes=int(payload.get("max_extract_size_bytes") or 0),
            max_file_count=int(payload.get("max_file_count") or 0),
            overwrite=bool(payload.get("overwrite", False)),
            resume=bool(payload.get("resume", False)),
        )


@dataclass
class RunJob:
    run_id: str
    request: RunRequest
    status: str = "queued"
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)
    started_at: str | None = None
    completed_at: str | None = None
    error: str | None = None
    summary: Dict[str, object] | None = None
    origin: str = "web"
    steps: List[Dict[str, object]] = field(default_factory=list)
    cancellation_requested: bool = False

    def __post_init__(self) -> None:
        if not self.steps:
            self.steps = default_job_steps()

    def to_dict(self, *, include_summary: bool = False) -> Dict[str, object]:
        payload: Dict[str, object] = {
            "run_id": self.run_id,
            "status": self.status,
            "origin": self.origin,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "error": self.error,
            "request": self.request.to_dict(),
            "steps": self.steps,
            "cancellation_requested": self.cancellation_requested,
        }
        if self.summary:
            outputs = self.summary.get("outputs", {})
            if isinstance(outputs, dict):
                payload["outputs"] = outputs
            payload["summary_path"] = outputs.get("summary") if isinstance(outputs, dict) else None
        if include_summary and self.summary is not None:
            payload["summary"] = self.summary
        return payload

    def to_record(self) -> Dict[str, object]:
        payload = self.to_dict(include_summary=True)
        return payload

    @classmethod
    def from_record(cls, payload: Mapping[str, object]) -> "RunJob":
        request_payload = payload.get("request")
        request = RunRequest.from_dict(request_payload if isinstance(request_payload, Mapping) else {})
        summary_payload = payload.get("summary")
        return cls(
            run_id=str(payload.get("run_id") or uuid.uuid4().hex[:12]),
            request=request,
            status=str(payload.get("status") or "failed"),
            origin=str(payload.get("origin") or "web"),
            created_at=str(payload.get("created_at") or now_iso()),
            updated_at=str(payload.get("updated_at") or now_iso()),
            started_at=str(payload["started_at"]) if payload.get("started_at") else None,
            completed_at=str(payload["completed_at"]) if payload.get("completed_at") else None,
            error=str(payload["error"]) if payload.get("error") else None,
            summary=dict(summary_payload) if isinstance(summary_payload, Mapping) else None,
            steps=[dict(step) for step in payload.get("steps", [])] if isinstance(payload.get("steps"), list) else [],
            cancellation_requested=bool(payload.get("cancellation_requested", False)),
        )


class RunJobStore:
    def __init__(self, *, max_workers: int = 2, state_path: Path | None = None) -> None:
        self._jobs: Dict[str, RunJob] = {}
        self._futures: Dict[str, Future[Dict[str, object]]] = {}
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="rapidtriage-run")
        self._lock = threading.Lock()
        self._state_path = state_path.expanduser().resolve() if state_path is not None else None
        self._load_state()

    def submit(self, request: RunRequest) -> RunJob:
        run_id = uuid.uuid4().hex[:12]
        job = RunJob(run_id=run_id, request=request)
        with self._lock:
            self._jobs[run_id] = job
            self._write_state_locked()
        future = self._executor.submit(self._execute, run_id)
        with self._lock:
            self._futures[run_id] = future
        return job

    def run_sync(self, request: RunRequest) -> RunJob:
        job = RunJob(run_id=uuid.uuid4().hex[:12], request=request)
        with self._lock:
            self._jobs[job.run_id] = job
            self._write_state_locked()
        try:
            self._execute(job.run_id)
        except Exception:
            pass
        return self.get(job.run_id)

    def list(self) -> List[RunJob]:
        with self._lock:
            return sorted(self._jobs.values(), key=lambda item: item.created_at, reverse=True)

    def get(self, run_id: str) -> RunJob:
        with self._lock:
            if run_id not in self._jobs:
                raise KeyError(run_id)
            return self._jobs[run_id]

    def read_output(self, run_id: str, output_name: str) -> Dict[str, object]:
        output_path = self.output_path(run_id, output_name)
        return json.loads(output_path.read_text(encoding="utf-8"))

    def output_path(self, run_id: str, output_name: str) -> Path:
        job = self.get(run_id)
        if job.summary is None:
            raise RuntimeError("run has no summary yet")
        outputs = job.summary.get("outputs")
        if not isinstance(outputs, Mapping):
            raise RuntimeError("run summary does not include outputs")
        if output_name not in outputs:
            raise KeyError(output_name)
        output_path = Path(str(outputs[output_name])).expanduser().resolve()
        output_dir = run_output_dir(job.summary)
        if not is_relative_to(output_path, output_dir):
            raise PermissionError(f"run output is outside output_dir: {output_path}")
        if not output_path.is_file():
            raise FileNotFoundError(str(output_path))
        return output_path

    def output_files(self, run_id: str) -> List[Dict[str, object]]:
        job = self.get(run_id)
        if job.summary is None:
            raise RuntimeError("run has no summary yet")
        outputs = job.summary.get("outputs")
        if not isinstance(outputs, Mapping):
            raise RuntimeError("run summary does not include outputs")
        output_dir = run_output_dir(job.summary)
        files: List[Dict[str, object]] = []
        for name, raw_path in sorted(outputs.items()):
            path = Path(str(raw_path)).expanduser().resolve()
            if not is_relative_to(path, output_dir):
                raise PermissionError(f"run output is outside output_dir: {path}")
            files.append(
                {
                    "name": name,
                    "path": str(path),
                    "exists": path.is_file(),
                    "size": path.stat().st_size if path.is_file() else None,
                    "download_url": f"/api/runs/{run_id}/outputs/{name}/file",
                }
            )
        return files

    def import_completed_run(self, output_dir_or_summary: str | Path) -> RunJob:
        summary_path = resolve_run_summary_path(Path(output_dir_or_summary).expanduser())
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        if not isinstance(summary, dict):
            raise ValueError("run summary must be a JSON object")
        outputs = summary.get("outputs")
        if not isinstance(outputs, Mapping):
            raise ValueError("run summary does not include outputs")

        run_id = uuid.uuid5(uuid.NAMESPACE_URL, str(summary_path.resolve())).hex[:12]
        safety = summary.get("safety")
        safety_options = safety if isinstance(safety, Mapping) else {}
        request = RunRequest(
            root=str(summary.get("root") or ""),
            mode=str(summary.get("mode") or ""),
            output_dir=str(summary.get("output_dir") or summary_path.parent),
            input_kind=str(summary["input_kind"]) if summary.get("input_kind") else None,
            dry_run=bool(safety_options.get("dry_run", False)),
            read_only=bool(safety_options.get("read_only", False)),
            max_extract_size_bytes=int(safety_options.get("max_extract_size_bytes") or 0),
            max_file_count=int(safety_options.get("max_file_count") or 0),
            overwrite=bool(safety_options.get("overwrite", False)),
        )
        imported_at = now_iso()
        job = RunJob(
            run_id=run_id,
            request=request,
            status="completed",
            origin="imported",
            created_at=imported_at,
            updated_at=imported_at,
            started_at=imported_at,
            completed_at=imported_at,
            summary=summary,
        )
        with self._lock:
            existing = self._jobs.get(run_id)
            if existing is not None:
                job.created_at = existing.created_at
                job.started_at = existing.started_at
                job.completed_at = existing.completed_at
            self._jobs[run_id] = job
            self._write_state_locked()
        return job

    def remove(self, run_id: str) -> None:
        with self._lock:
            if run_id not in self._jobs:
                raise KeyError(run_id)
            del self._jobs[run_id]
            self._futures.pop(run_id, None)
            self._write_state_locked()

    def cancel(self, run_id: str) -> RunJob:
        with self._lock:
            if run_id not in self._jobs:
                raise KeyError(run_id)
            job = self._jobs[run_id]
            future = self._futures.get(run_id)
            job.cancellation_requested = True
            if job.status == "queued":
                if future is not None:
                    future.cancel()
                job.status = "canceled"
                job.completed_at = now_iso()
                job.steps = update_step(job.steps, "prepare", "canceled", message="Canceled before execution")
            elif job.status == "running":
                job.steps = update_step(
                    job.steps,
                    "triage",
                    "running",
                    message="Cancellation requested; current stage will finish safely before state changes.",
                )
            job.updated_at = now_iso()
            self._write_state_locked()
            return job

    def retry(self, run_id: str) -> RunJob:
        with self._lock:
            if run_id not in self._jobs:
                raise KeyError(run_id)
            previous = self._jobs[run_id]
            if previous.status not in {"failed", "canceled"}:
                raise ValueError("only failed or canceled runs can be retried")
        return self.submit(previous.request)

    def _execute(self, run_id: str) -> Dict[str, object]:
        with self._lock:
            job = self._jobs[run_id]
            job.status = "running"
            job.started_at = now_iso()
            job.updated_at = job.started_at
            self._write_state_locked()
            if job.cancellation_requested:
                job.status = "canceled"
                job.completed_at = now_iso()
                job.updated_at = job.completed_at
                job.steps = update_step(job.steps, "prepare", "canceled", message="Canceled before execution")
                self._write_state_locked()
                return {}
        try:
            self._mark_step(run_id, "prepare", "completed", message="Run request accepted")
            self._mark_step(run_id, "triage", "running", message="Executing triage workflow")
            summary = execute_run_request(job.request, run_id=run_id)
        except Exception as exc:
            with self._lock:
                job.status = "failed"
                job.error = str(exc)
                job.completed_at = now_iso()
                job.updated_at = job.completed_at
                job.steps = update_step(job.steps, "triage", "failed", message=str(exc))
                job.steps = update_step(job.steps, "finalize", "skipped", message="Run failed before finalize")
                self._write_state_locked()
            raise
        with self._lock:
            job.steps = update_step(job.steps, "triage", "completed", message="Triage workflow completed")
            job.steps = update_step(job.steps, "persist", "completed", message="Run summary persisted")
            job.steps = update_step(job.steps, "finalize", "completed", message="Run completed")
            job.status = "completed"
            job.summary = summary
            job.completed_at = now_iso()
            job.updated_at = job.completed_at
            self._write_state_locked()
        return summary

    def _mark_step(self, run_id: str, name: str, status: str, *, message: str = "") -> None:
        with self._lock:
            job = self._jobs[run_id]
            job.steps = update_step(job.steps, name, status, message=message)
            job.updated_at = now_iso()
            self._write_state_locked()

    def _load_state(self) -> None:
        if self._state_path is None or not self._state_path.is_file():
            return
        try:
            payload = json.loads(self._state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        records = payload.get("runs") if isinstance(payload, Mapping) else None
        if not isinstance(records, list):
            return
        changed = False
        for record in records:
            if not isinstance(record, Mapping):
                continue
            job = RunJob.from_record(record)
            if job.status in {"queued", "running"}:
                job.status = "failed"
                job.error = "server restarted before this run completed"
                job.completed_at = now_iso()
                job.updated_at = job.completed_at
                changed = True
            self._jobs[job.run_id] = job
        if changed:
            with self._lock:
                self._write_state_locked()

    def _write_state_locked(self) -> None:
        if self._state_path is None:
            return
        payload = {
            "version": 1,
            "updated_at": now_iso(),
            "runs": [job.to_record() for job in self.list_locked()],
        }
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = self._state_path.with_name(f"{self._state_path.name}.tmp")
        temporary_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temporary_path.replace(self._state_path)

    def list_locked(self) -> List[RunJob]:
        return sorted(self._jobs.values(), key=lambda item: item.created_at, reverse=True)


def default_job_steps() -> List[Dict[str, object]]:
    return [
        {
            "name": name,
            "status": "pending",
            "retry_count": 0,
            "started_at": None,
            "completed_at": None,
            "message": "",
        }
        for name in JOB_STEP_NAMES
    ]


def update_step(steps: List[Dict[str, object]], name: str, status: str, *, message: str = "") -> List[Dict[str, object]]:
    output = [dict(step) for step in (steps or default_job_steps())]
    existing_names = {str(step.get("name")) for step in output}
    for missing in JOB_STEP_NAMES:
        if missing not in existing_names:
            output.append(
                {
                    "name": missing,
                    "status": "pending",
                    "retry_count": 0,
                    "started_at": None,
                    "completed_at": None,
                    "message": "",
                }
            )
    timestamp = now_iso()
    for step in output:
        if step.get("name") != name:
            continue
        previous_status = str(step.get("status") or "pending")
        if status == "running" and previous_status == "failed":
            step["retry_count"] = int(step.get("retry_count") or 0) + 1
        step["status"] = status
        step["message"] = message
        if status == "running" and not step.get("started_at"):
            step["started_at"] = timestamp
        if status in {"completed", "failed", "skipped", "canceled"}:
            step["completed_at"] = timestamp
        break
    return output


def execute_run_request(request: RunRequest, *, run_id: str | None = None) -> Dict[str, object]:
    root = Path(request.root).expanduser().resolve()
    output_dir = (
        Path(request.output_dir).expanduser().resolve()
        if request.output_dir
        else default_run_output_dir(root, request.mode, run_id=run_id)
    )
    rule_set = None
    if request.rules:
        rule_set = load_rule_set(Path(request.rules).expanduser().resolve())
    try:
        return run_triage_mode(
            root,
            mode=request.mode,
            output_dir=output_dir,
            input_kind=request.input_kind,
            dry_run=request.dry_run,
            read_only=request.read_only,
            max_extract_size_bytes=request.max_extract_size_bytes,
            max_file_count=request.max_file_count,
            overwrite=request.overwrite,
            resume=request.resume,
            rule_set=rule_set,
        )
    except (FileNotFoundError, OSError, RuleConfigError, RunModeError, ValueError):
        raise


def default_run_output_dir(root: Path, mode: str, *, run_id: str | None = None) -> Path:
    suffix = f"rapidtriage-run-{mode.lower()}"
    if run_id:
        suffix = f"{suffix}-{run_id}"
    return root / suffix


def resolve_run_summary_path(output_dir_or_summary: Path) -> Path:
    candidate = output_dir_or_summary.expanduser().resolve()
    if candidate.is_dir():
        candidate = candidate / "rapidtriage-run-summary.json"
    if not candidate.is_file():
        raise FileNotFoundError(str(candidate))
    return candidate


def run_output_dir(summary: Mapping[str, object]) -> Path:
    output_dir = summary.get("output_dir")
    if not isinstance(output_dir, str) or not output_dir:
        raise RuntimeError("run summary does not include output_dir")
    return Path(output_dir).expanduser().resolve()


def is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def default_state_path() -> Path:
    explicit = os.environ.get("RAPIDTRIAGE_STATE_PATH")
    if explicit:
        return Path(explicit).expanduser()
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        return base / "rapidtriage" / "runs.json"
    base = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
    return base / "rapidtriage" / "runs.json"


default_job_store = RunJobStore(state_path=default_state_path())
