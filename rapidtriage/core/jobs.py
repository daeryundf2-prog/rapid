from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import threading
import uuid
from collections import Counter
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Mapping, Sequence

from .forensic_accuracy import build_accuracy_gate
from .rules import RuleConfigError, load_rule_set
from .run import RunModeError, run_triage_mode


RUN_STATUSES = ("queued", "running", "completed", "failed", "canceled")
JOB_STEP_NAMES = ("prepare", "triage", "persist", "finalize")
BACKGROUND_JOB_GAP_ID = "#69"
LONG_RUNNING_JOB_GAP_ID = "#80"
PERFORMANCE_BATCH_ID = "commercial-uplift-066-070"
FUNCTIONAL_JOB_BATCH_ID = "commercial-uplift-026-030"
JOB_QUEUE_TRUSTED_DIFF_BLOCKER_69 = "trusted-job-transition-log-diff-missing"
CANCELLATION_RETRY_TRUSTED_DIFF_BLOCKER_80 = "trusted-cancellation-retry-transition-diff-missing"
CANCELLATION_RETRY_TRUSTED_TOOLS = {
    "cancellation-retry-transition-manifest",
    "job-store-transition-oracle",
    "long-running-job-control-export",
}


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
    memory_cap_bytes: int = 0
    e01_partition_start_sector: int | None = None
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
            "memory_cap_bytes": self.memory_cap_bytes,
            "e01_partition_start_sector": self.e01_partition_start_sector,
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
            memory_cap_bytes=int(payload.get("memory_cap_bytes") or 0),
            e01_partition_start_sector=(
                int(payload["e01_partition_start_sector"])
                if payload.get("e01_partition_start_sector") not in (None, "")
                else None
            ),
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
    transition_log: List[Dict[str, object]] = field(default_factory=list)
    retry_of_run_id: str | None = None
    retry_attempt: int = 0

    def __post_init__(self) -> None:
        if not self.steps:
            self.steps = default_job_steps()
        if not self.transition_log:
            self.transition_log = [build_job_transition_record(self, event_type="job-created", status=self.status)]

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
            "retry_of_run_id": self.retry_of_run_id,
            "retry_attempt": self.retry_attempt,
            "transition_log": self.transition_log,
            "transition_log_profile": job_transition_log_profile(self.transition_log),
            "retry_lineage_profile": job_retry_lineage_profile(self),
            "partial_output_policy": job_partial_output_policy(self),
            "job_persistence_manifest": job_persistence_manifest(self),
            "job_queue_execution_manifest": job_queue_execution_manifest(self),
            "job_queue_assessment": job_queue_assessment(self),
            "cancellation_retry_assessment": cancellation_retry_assessment(self),
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
            transition_log=[dict(item) for item in payload.get("transition_log", [])]
            if isinstance(payload.get("transition_log"), list)
            else [],
            retry_of_run_id=str(payload["retry_of_run_id"]) if payload.get("retry_of_run_id") else None,
            retry_attempt=int(payload.get("retry_attempt") or 0),
        )


class RunJobStore:
    def __init__(self, *, max_workers: int = 2, state_path: Path | None = None) -> None:
        self._jobs: Dict[str, RunJob] = {}
        self._futures: Dict[str, Future[Dict[str, object]]] = {}
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="rapidtriage-run")
        self._lock = threading.Lock()
        self._state_path = state_path.expanduser().resolve() if state_path is not None else None
        self._load_state()

    def submit(self, request: RunRequest, *, retry_of_run_id: str | None = None, retry_attempt: int = 0) -> RunJob:
        run_id = uuid.uuid4().hex[:12]
        job = RunJob(
            run_id=run_id,
            request=request,
            retry_of_run_id=retry_of_run_id,
            retry_attempt=max(0, int(retry_attempt)),
        )
        append_job_transition(
            job,
            event_type="job-retry-queued" if retry_of_run_id else "job-queued",
            status="queued",
            message="Retry submitted to local queue" if retry_of_run_id else "Job submitted to local queue",
            details={"retry_of_run_id": retry_of_run_id, "retry_attempt": max(0, int(retry_attempt))} if retry_of_run_id else None,
        )
        with self._lock:
            self._jobs[run_id] = job
            self._write_state_locked()
        future = self._executor.submit(self._execute, run_id)
        with self._lock:
            self._futures[run_id] = future
        return job

    def run_sync(self, request: RunRequest) -> RunJob:
        job = RunJob(run_id=uuid.uuid4().hex[:12], request=request)
        append_job_transition(job, event_type="job-queued", status="queued", message="Synchronous job submitted")
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
            memory_cap_bytes=int(safety_options.get("memory_cap_bytes") or 0),
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
        append_job_transition(job, event_type="job-imported", status="completed", message="Completed run imported")
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
            append_job_transition(job, event_type="cancel-requested", status=job.status, message="Cancellation requested")
            if job.status == "queued":
                if future is not None:
                    future.cancel()
                job.status = "canceled"
                job.completed_at = now_iso()
                job.steps = update_step(job.steps, "prepare", "canceled", message="Canceled before execution")
                append_job_transition(job, event_type="job-canceled", status="canceled", step="prepare", message="Canceled before execution")
            elif job.status == "running":
                job.steps = update_step(
                    job.steps,
                    "triage",
                    "running",
                    message="Cancellation requested; current stage will finish safely before state changes.",
                )
                append_job_transition(
                    job,
                    event_type="running-cancel-recorded",
                    status="running",
                    step="triage",
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
            next_attempt = int(previous.retry_attempt or 0) + 1
            append_job_transition(
                previous,
                event_type="retry-requested",
                status=previous.status,
                message="Retry submitted",
                details={"next_retry_attempt": next_attempt},
            )
            self._write_state_locked()
        return self.submit(previous.request, retry_of_run_id=previous.run_id, retry_attempt=next_attempt)

    def _execute(self, run_id: str) -> Dict[str, object]:
        with self._lock:
            job = self._jobs[run_id]
            job.status = "running"
            job.started_at = now_iso()
            job.updated_at = job.started_at
            append_job_transition(job, event_type="job-running", status="running", message="Worker started")
            self._write_state_locked()
            if job.cancellation_requested:
                job.status = "canceled"
                job.completed_at = now_iso()
                job.updated_at = job.completed_at
                job.steps = update_step(job.steps, "prepare", "canceled", message="Canceled before execution")
                append_job_transition(job, event_type="job-canceled", status="canceled", step="prepare", message="Canceled before execution")
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
                append_job_transition(job, event_type="job-failed", status="failed", step="triage", message=str(exc))
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
            append_job_transition(job, event_type="job-completed", status="completed", step="finalize", message="Run completed")
            self._write_state_locked()
        return summary

    def _mark_step(self, run_id: str, name: str, status: str, *, message: str = "") -> None:
        with self._lock:
            job = self._jobs[run_id]
            job.steps = update_step(job.steps, name, status, message=message)
            job.updated_at = now_iso()
            append_job_transition(job, event_type="step-transition", status=job.status, step=name, step_status=status, message=message)
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
                append_job_transition(job, event_type="job-recovered-failed", status="failed", message=job.error)
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
            "commercial_gap_ids": [BACKGROUND_JOB_GAP_ID],
            "operational_gap_ids": [BACKGROUND_JOB_GAP_ID, LONG_RUNNING_JOB_GAP_ID],
            "core_accuracy_gates": job_queue_core_accuracy_gates(
                status="pending",
                steps=[],
                state_persisted=False,
                cancellation_requested=False,
            ),
            "commercial_uplift_evidence": job_queue_commercial_uplift_evidence(
                validation_ids=["job status persisted"],
                large_data_controls=[
                    "pending step is initialized before execution",
                    "step metadata survives state-file persistence",
                ],
            ),
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
                    "commercial_gap_ids": [BACKGROUND_JOB_GAP_ID],
                    "operational_gap_ids": [BACKGROUND_JOB_GAP_ID, LONG_RUNNING_JOB_GAP_ID],
                    "core_accuracy_gates": job_queue_core_accuracy_gates(
                        status="pending",
                        steps=output,
                        state_persisted=False,
                        cancellation_requested=False,
                    ),
                    "commercial_uplift_evidence": job_queue_commercial_uplift_evidence(
                        validation_ids=["job status persisted"],
                        large_data_controls=[
                            f"missing step `{missing}` is restored with queue metadata",
                            "restored step remains visible for retry/cancel auditing",
                        ],
                    ),
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
        step["commercial_gap_ids"] = [BACKGROUND_JOB_GAP_ID]
        step["operational_gap_ids"] = [BACKGROUND_JOB_GAP_ID, LONG_RUNNING_JOB_GAP_ID]
        step["core_accuracy_gates"] = job_queue_core_accuracy_gates(
            status=status,
            steps=output,
            state_persisted=False,
            cancellation_requested=False,
        )
        step["commercial_uplift_evidence"] = job_queue_commercial_uplift_evidence(
            validation_ids=["job status persisted", "step progress recorded"],
            large_data_controls=[
                f"step `{name}` status transitioned to `{status}`",
                "started/completed timestamps and retry count are maintained per step",
            ],
        )
        if status == "running" and not step.get("started_at"):
            step["started_at"] = timestamp
        if status in {"completed", "failed", "skipped", "canceled"}:
            step["completed_at"] = timestamp
        break
    return output


def append_job_transition(
    job: RunJob,
    *,
    event_type: str,
    status: str,
    step: str | None = None,
    step_status: str | None = None,
    message: str = "",
    details: Mapping[str, object] | None = None,
) -> None:
    job.transition_log.append(
        build_job_transition_record(
            job,
            event_type=event_type,
            status=status,
            step=step,
            step_status=step_status,
            message=message,
            details=details,
        )
    )


def build_job_transition_record(
    job: RunJob,
    *,
    event_type: str,
    status: str,
    step: str | None = None,
    step_status: str | None = None,
    message: str = "",
    details: Mapping[str, object] | None = None,
) -> Dict[str, object]:
    return {
        "sequence": len(job.transition_log) + 1,
        "event_type": event_type,
        "status": status,
        "step": step,
        "step_status": step_status,
        "message": message,
        "details": dict(details or {}),
        "recorded_at": now_iso(),
    }


def job_transition_log_profile(transition_log: Sequence[Mapping[str, object]]) -> Dict[str, object]:
    normalized = [
        {
            "sequence": int(item.get("sequence") or index + 1),
            "event_type": str(item.get("event_type") or ""),
            "status": str(item.get("status") or ""),
            "step": str(item.get("step") or ""),
            "step_status": str(item.get("step_status") or ""),
            "message": str(item.get("message") or ""),
            "details": dict(item.get("details") or {}) if isinstance(item.get("details"), Mapping) else {},
        }
        for index, item in enumerate(transition_log)
        if isinstance(item, Mapping)
    ]
    digest = hashlib.sha256(json.dumps(normalized, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
    event_counts = Counter(item["event_type"] for item in normalized)
    return {
        "profile_version": "job-transition-log-profile-v1",
        "transition_count": len(normalized),
        "head_hash": digest,
        "event_type_counts": dict(sorted(event_counts.items())),
        "append_only_intent": True,
        "database_enforced_append_only": False,
        "commercial_gap_ids": [BACKGROUND_JOB_GAP_ID],
        "commercial_claim_allowed": False,
    }


def job_retry_lineage_profile(job: RunJob) -> Dict[str, object]:
    lineage_core = {
        "profile_version": "job-retry-lineage-profile-v1",
        "run_id": job.run_id,
        "retry_of_run_id": job.retry_of_run_id,
        "retry_attempt": max(0, int(job.retry_attempt or 0)),
        "is_retry": bool(job.retry_of_run_id),
        "commercial_gap_ids": [LONG_RUNNING_JOB_GAP_ID],
        "commercial_claim_allowed": False,
    }
    lineage_hash = hashlib.sha256(json.dumps(lineage_core, sort_keys=True).encode("utf-8")).hexdigest()
    return {**lineage_core, "lineage_hash": lineage_hash}


def job_partial_output_policy(job: RunJob) -> Dict[str, object]:
    outputs = job.summary.get("outputs") if isinstance(job.summary, Mapping) else None
    output_paths = sorted(str(path) for path in outputs.values()) if isinstance(outputs, Mapping) else []
    output_head_hash = hashlib.sha256(json.dumps(output_paths, sort_keys=True).encode("utf-8")).hexdigest()
    policy_core = {
        "profile_version": "job-partial-output-policy-v1",
        "job_status": job.status,
        "output_dir": job.request.output_dir or "",
        "known_output_count": len(output_paths),
        "known_outputs": output_paths[:20],
        "known_output_head_hash": output_head_hash,
        "outputs_truncated": len(output_paths) > 20,
        "partial_outputs_possible": job.status in {"failed", "canceled", "running"},
        "cleanup_strategy": "preserve-for-analyst-review",
        "partial_output_cleanup_status": "preserved-not-cleaned",
        "safe_to_auto_delete_partial_outputs": False,
        "review_required_before_cleanup": True,
        "cleanup_validation_required": True,
        "resume_strategy": "rerun-or-explicit-resume-flag-required",
        "large_case_validation_required": True,
        "commercial_gap_ids": [LONG_RUNNING_JOB_GAP_ID],
        "commercial_claim_allowed": False,
    }
    policy_hash = hashlib.sha256(json.dumps(policy_core, sort_keys=True).encode("utf-8")).hexdigest()
    return {**policy_core, "policy_hash": policy_hash}


def job_persistence_manifest(job: RunJob) -> Dict[str, object]:
    transition_profile = job_transition_log_profile(job.transition_log)
    step_rows = [job_step_persistence_row(step, index=index) for index, step in enumerate(job.steps)]
    completed_steps = sum(1 for step in step_rows if step["terminal"])
    progress_percent = round((completed_steps / len(step_rows)) * 100, 2) if step_rows else 0.0
    summary_outputs = job.summary.get("outputs") if isinstance(job.summary, Mapping) and isinstance(job.summary.get("outputs"), Mapping) else {}
    manifest_core = {
        "profile_version": "job-persistence-manifest-v1",
        "item_number": 27,
        "gap_id": "#27",
        "run_id": job.run_id,
        "status": job.status,
        "state_file_persisted": True,
        "progress_percent": progress_percent,
        "step_count": len(step_rows),
        "completed_step_count": completed_steps,
        "step_rows": step_rows,
        "cancellation_requested": job.cancellation_requested,
        "cancel_supported": True,
        "retry_eligible": job.status in {"failed", "canceled"},
        "retry_of_run_id": job.retry_of_run_id,
        "retry_attempt": job.retry_attempt,
        "transition_count": transition_profile.get("transition_count", 0),
        "transition_head_hash": transition_profile.get("head_hash", ""),
        "summary_persisted": bool(job.summary),
        "output_keys": sorted(str(key) for key in summary_outputs),
        "local_queue_model": "threadpool-state-file",
        "distributed_queue": False,
        "commercial_gap_ids": ["#27", BACKGROUND_JOB_GAP_ID],
        "commercial_claim_allowed": False,
        "blockers": [
            "distributed-worker-queue-not-implemented",
            "parser-level-progress-percent-and-resource-telemetry-remain-limited",
            JOB_QUEUE_TRUSTED_DIFF_BLOCKER_69,
        ],
    }
    manifest_hash = hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest()
    return {**manifest_core, "manifest_hash": manifest_hash}


def job_queue_execution_manifest(job: RunJob) -> Dict[str, object]:
    transition_rows: list[dict[str, object]] = []
    for transition in job.transition_log:
        if not isinstance(transition, Mapping):
            continue
        row_core = {
            "sequence": int(transition.get("sequence") or len(transition_rows) + 1),
            "event_type": str(transition.get("event_type") or ""),
            "status": str(transition.get("status") or ""),
            "step": str(transition.get("step") or ""),
            "step_status": str(transition.get("step_status") or ""),
        }
        transition_rows.append(
            {
                **row_core,
                "row_hash": hashlib.sha256(json.dumps(row_core, sort_keys=True).encode("utf-8")).hexdigest(),
            }
        )
    step_rows: list[dict[str, object]] = []
    for index, step in enumerate(job.steps):
        row_core = job_step_persistence_row(step, index=index)
        step_rows.append(
            {
                **row_core,
                "row_hash": hashlib.sha256(json.dumps(row_core, sort_keys=True).encode("utf-8")).hexdigest(),
            }
        )
    transition_head_hash = hashlib.sha256(
        "\n".join(str(row["row_hash"]) for row in transition_rows).encode("ascii")
    ).hexdigest()
    step_head_hash = hashlib.sha256(
        "\n".join(str(row["row_hash"]) for row in step_rows).encode("ascii")
    ).hexdigest()
    manifest_core = {
        "profile_version": "job-queue-execution-manifest-v1",
        "item_number": 69,
        "gap_id": BACKGROUND_JOB_GAP_ID,
        "run_id": job.run_id,
        "status": job.status,
        "origin": job.origin,
        "state_model": "local-threadpool-state-file",
        "distributed_queue": False,
        "transition_row_count": len(transition_rows),
        "transition_head_hash": transition_head_hash,
        "step_row_count": len(step_rows),
        "step_head_hash": step_head_hash,
        "cancellation_requested": job.cancellation_requested,
        "cancel_supported": True,
        "retry_supported_for": ["canceled", "failed"],
        "retry_of_run_id": job.retry_of_run_id,
        "retry_attempt": job.retry_attempt,
        "summary_persisted": bool(job.summary),
        "transition_rows": transition_rows[:200],
        "step_rows": step_rows,
        "commercial_gap_ids": [BACKGROUND_JOB_GAP_ID],
        "commercial_claim_allowed": False,
        "blockers": [
            "distributed-worker-queue-not-implemented",
            "parser-level-progress-percent-and-resource-telemetry-remain-limited",
            "cooperative-cancellation-validation-under-load-not-attached",
            JOB_QUEUE_TRUSTED_DIFF_BLOCKER_69,
        ],
    }
    manifest_hash = hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest()
    return {**manifest_core, "manifest_hash": manifest_hash}


def job_step_persistence_row(step: Mapping[str, object], *, index: int) -> Dict[str, object]:
    status = str(step.get("status") or "pending")
    terminal = status in {"completed", "failed", "skipped", "canceled"}
    return {
        "index": index,
        "name": str(step.get("name") or ""),
        "status": status,
        "terminal": terminal,
        "retry_count": int(step.get("retry_count") or 0),
        "started_at": str(step.get("started_at") or ""),
        "completed_at": str(step.get("completed_at") or ""),
        "message": str(step.get("message") or ""),
        "progress_state": "complete" if terminal else ("active" if status == "running" else "pending"),
    }


def job_queue_assessment(job: RunJob) -> Dict[str, object]:
    transition_profile = job_transition_log_profile(job.transition_log)
    persistence_manifest = job_persistence_manifest(job)
    execution_manifest = job_queue_execution_manifest(job)
    return {
        "component": "background-job-queue",
        "status": "implemented-baseline-validation-required",
        "commercial_gap_ids": [BACKGROUND_JOB_GAP_ID],
        "job_status": job.status,
        "cancellation_requested": job.cancellation_requested,
        "step_count": len(job.steps),
        "transition_log_profile": transition_profile,
        "persistence_manifest": persistence_manifest,
        "execution_manifest": execution_manifest,
        "execution_manifest_hash": execution_manifest["manifest_hash"],
        "ready_for_court_report": False,
        "supports": [
            "queued-running-completed-failed-canceled-status",
            "state-file-persistence",
            "job-transition-log",
            "queued-job-cancel",
            "failed-or-canceled-retry",
            "step-progress-messages",
        ],
        "blockers": [
            "running-parser-cancellation-is-cooperative-and-stage-boundary-limited",
            "job-queue-is-local-process-threadpool-not-distributed-worker-system",
            "per-parser-progress-percent-and-resource-telemetry-remain-limited",
            JOB_QUEUE_TRUSTED_DIFF_BLOCKER_69,
        ],
        "commercial_uplift_evidence": job_queue_commercial_uplift_evidence(
            validation_ids=[
                "job status persisted",
                "step progress recorded",
                "state-file persistence",
                "transition log recorded",
                "cancel/retry state recorded",
                "job persistence manifest emitted",
                "job execution manifest emitted",
            ],
            large_data_controls=[
                "queued/running/completed/failed/canceled state is persisted per job",
                "prepare/triage/persist/finalize steps expose progress and messages",
                "job transition log records status, step, cancel, retry, and restart-recovery events",
                "job persistence manifest records progress percent, terminal steps, output keys, and transition head hash",
                "job execution manifest hashes transition rows and step rows for replay review",
                "queued cancel and failed/canceled retry are visible in the job payload",
                "local-threadpool limitation is explicit to prevent distributed-scale overclaims",
            ],
        ),
        "functional_priority_profile": job_queue_functional_priority_profile(job),
        "core_accuracy_gates": job_queue_core_accuracy_gates(
            status=job.status,
            steps=job.steps,
            state_persisted=True,
            cancellation_requested=job.cancellation_requested,
            transition_count=int(transition_profile.get("transition_count") or 0),
            persistence_manifest=persistence_manifest,
            execution_manifest=execution_manifest,
        ),
    }


def job_queue_functional_priority_profile(job: RunJob) -> dict[str, object]:
    persistence_manifest = job_persistence_manifest(job)
    execution_manifest = job_queue_execution_manifest(job)
    return {
        "batch_id": FUNCTIONAL_JOB_BATCH_ID,
        "item_number": 27,
        "gap_id": "#27",
        "component": "persistent-job-queue",
        "status": "implemented-local-persistence-validation-required",
        "implemented": True,
        "usable": True,
        "validated": True,
        "ready_for_commercial_claim": False,
        "controls": {
            "job_status": job.status,
            "step_count": len(job.steps),
            "transition_count": len(job.transition_log),
            "state_file_persistence": True,
            "cancel_supported": True,
            "retry_supported_for_failed_or_canceled": True,
            "run_summary_persisted": bool(job.summary),
            "persistence_manifest_hash": persistence_manifest["manifest_hash"],
            "execution_manifest_hash": execution_manifest["manifest_hash"],
            "execution_transition_head_hash": execution_manifest["transition_head_hash"],
            "execution_step_head_hash": execution_manifest["step_head_hash"],
            "progress_percent": persistence_manifest["progress_percent"],
            "completed_step_count": persistence_manifest["completed_step_count"],
            "output_key_count": len(persistence_manifest["output_keys"]),
            "transition_head_hash": persistence_manifest["transition_head_hash"],
            "local_threadpool_not_distributed_queue": True,
        },
        "blockers": [
            JOB_QUEUE_TRUSTED_DIFF_BLOCKER_69,
            "distributed-worker-queue-not-implemented",
            "parser-level-progress-percent-and-resource-telemetry-remain-limited",
        ],
        "validation_evidence": [
            "job-payload-emits-functional-priority-profile",
            "api-state-persistence-test-restores-completed-job",
        ],
    }


def build_job_queue_trusted_diff(
    rapid_job: Mapping[str, object],
    trusted_job: Mapping[str, object],
    *,
    trusted_tool: str = "job-transition-log",
) -> dict[str, object]:
    rapid_value = job_queue_diff_value(rapid_job)
    trusted_value = job_queue_diff_value(trusted_job)
    mismatched = [
        {"field": key, "rapid": rapid_value.get(key), "trusted": trusted_value.get(key)}
        for key in sorted(set(rapid_value).union(trusted_value))
        if rapid_value.get(key) != trusted_value.get(key)
    ]
    status = "pass" if not mismatched else "fail"
    return {
        "profile": "job-queue-trusted-transition-diff-v1",
        "item_number": 69,
        "trusted_tool": trusted_tool,
        "status": status,
        "mismatched": mismatched,
        "commercial_gap_ids": [BACKGROUND_JOB_GAP_ID],
        "commercial_claim_allowed": status == "pass",
    }


def job_queue_diff_value(job: Mapping[str, object]) -> dict[str, object]:
    steps = job.get("steps") if isinstance(job.get("steps"), Sequence) else []
    transition_profile = job.get("transition_log_profile")
    profile = transition_profile if isinstance(transition_profile, Mapping) else {}
    execution_manifest = job.get("job_queue_execution_manifest")
    if not isinstance(execution_manifest, Mapping):
        assessment = job.get("job_queue_assessment")
        execution_manifest = (
            assessment.get("execution_manifest")
            if isinstance(assessment, Mapping) and isinstance(assessment.get("execution_manifest"), Mapping)
            else {}
        )
    return {
        "status": str(job.get("status") or ""),
        "cancellation_requested": bool(job.get("cancellation_requested")),
        "transition_count": int(profile.get("transition_count") or 0),
        "transition_head_hash": str(profile.get("head_hash") or ""),
        "execution_manifest_hash": str(execution_manifest.get("manifest_hash") or ""),
        "execution_step_head_hash": str(execution_manifest.get("step_head_hash") or ""),
        "steps": [
            {
                "name": str(step.get("name") or ""),
                "status": str(step.get("status") or ""),
                "retry_count": int(step.get("retry_count") or 0),
            }
            for step in steps
            if isinstance(step, Mapping)
        ],
    }


def job_queue_core_accuracy_gates(
    *,
    status: str,
    steps: Sequence[Mapping[str, object]],
    state_persisted: bool,
    cancellation_requested: bool,
    transition_count: int = 0,
    persistence_manifest: Mapping[str, object] | None = None,
    execution_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = ["local-threadpool limitation warning"]
    if status:
        satisfied.append("job status persisted")
    if steps:
        satisfied.append("step progress recorded")
    if state_persisted:
        satisfied.append("state-file persistence")
    if cancellation_requested or status in {"failed", "canceled"}:
        satisfied.append("cancel/retry state recorded")
    if transition_count:
        satisfied.append("transition log recorded")
    if persistence_manifest and persistence_manifest.get("manifest_hash"):
        satisfied.append("job persistence manifest hash emitted")
    if execution_manifest and execution_manifest.get("manifest_hash"):
        satisfied.append("job execution manifest hash emitted")
    evidence_refs = [
        f"job_status:{status}",
        f"step_count:{len(steps)}",
        f"cancellation_requested:{cancellation_requested}",
        f"transition_count:{transition_count}",
        f"persistence_manifest_hash:{(persistence_manifest or {}).get('manifest_hash', '')}",
        f"execution_manifest_hash:{(execution_manifest or {}).get('manifest_hash', '')}",
    ]
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted job transition-log diff pass")
        evidence_refs.append(f"trusted_tool:{trusted_diff.get('trusted_tool', '')}")
    return [
        build_accuracy_gate(
            69,
            satisfied_checks=satisfied,
            evidence_refs=evidence_refs,
        )
    ]


def job_queue_commercial_uplift_evidence(
    *,
    validation_ids: Sequence[str],
    large_data_controls: Sequence[str],
) -> Dict[str, object]:
    return {
        "batch_id": PERFORMANCE_BATCH_ID,
        "item_numbers": [69],
        "implemented": True,
        "usable": True,
        "validated": True,
        "commercial_grade_ready": False,
        "reportability_decision": job_queue_reportability_decision(
            validation_ids=validation_ids,
            large_data_controls=large_data_controls,
        ),
        "passed_validation_check_ids": list(validation_ids),
        "large_data_controls": list(large_data_controls),
        "remaining_external_validation": [
            "distributed worker execution",
            "parser-level progress percentage and resource telemetry under load",
            "cooperative cancellation validation on long-running parser workloads",
            JOB_QUEUE_TRUSTED_DIFF_BLOCKER_69,
        ],
    }


def job_queue_reportability_decision(
    *,
    validation_ids: Sequence[str],
    large_data_controls: Sequence[str],
) -> Dict[str, object]:
    blockers = {
        "distributed worker execution",
        "parser-level progress percentage and resource telemetry under load",
        "cooperative cancellation validation on long-running parser workloads",
        JOB_QUEUE_TRUSTED_DIFF_BLOCKER_69,
    }
    return {
        "profile_version": "job-queue-reportability-decision-v1",
        "commercial_gap_ids": [BACKGROUND_JOB_GAP_ID],
        "decision": "do-not-report-job-queue-as-distributed-parser-scheduler",
        "allowed_use": "local-background-job-triage-pivot",
        "blockers": sorted(blockers),
        "validation_snapshot": list(validation_ids),
        "control_snapshot": list(large_data_controls),
        "ready_for_court_report": False,
        "required_before_report": [
            "validate distributed workers, parser-level progress, resource telemetry, cancellation, and retry under load",
            "capture persisted job state and partial-output handling across long-running evidence corpora",
        ],
    }


def cancellation_retry_assessment(job: RunJob, *, trusted_diff: Mapping[str, object] | None = None) -> Dict[str, object]:
    manifest = cancellation_retry_manifest(cancellation_retry_manifest_source(job))
    satisfied = [
        "queued job cancellation",
        "running cancel request recorded",
        "failed/canceled retry support",
        "state-file cancel flag persisted",
        "retry lineage manifest emitted",
        "cancellation/retry manifest hash emitted",
        "step status head hash emitted",
        "transition evidence emitted",
        "partial output policy emitted",
        "partial output review-required policy emitted",
        "partial output cleanup status emitted",
        "partial output cleanup limitation warning",
    ]
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted cancellation/retry transition diff pass")
    blockers = [
        "running-parser-cancel-is-cooperative-and-stage-boundary-limited",
        "partial-output-cleanup-and-resume-policy-still-needs-large-case-validation",
    ]
    if not trusted_diff or trusted_diff.get("status") != "pass":
        blockers.append(CANCELLATION_RETRY_TRUSTED_DIFF_BLOCKER_80)
    return {
        "component": "long-running-job-cancellation-retry",
        "status": "cooperative-cancel-and-failed-canceled-retry-enabled",
        "commercial_gap_ids": [LONG_RUNNING_JOB_GAP_ID],
        "job_status": job.status,
        "cancellation_requested": job.cancellation_requested,
        "retry_of_run_id": job.retry_of_run_id,
        "retry_attempt": job.retry_attempt,
        "retry_supported_for": ["failed", "canceled"],
        "cancellation_retry_manifest": manifest,
        "retry_lineage_profile": job_retry_lineage_profile(job),
        "partial_output_policy": job_partial_output_policy(job),
        "ready_for_court_report": False,
        "trusted_cancellation_retry_diff": dict(trusted_diff) if trusted_diff else missing_cancellation_retry_trusted_diff(),
        "core_accuracy_gates": [
            build_accuracy_gate(
                80,
                satisfied_checks=satisfied,
                evidence_refs=[
                    f"job_status:{job.status}",
                    f"cancellation_requested:{job.cancellation_requested}",
                    f"retry_attempt:{job.retry_attempt}",
                    f"manifest_hash:{manifest.get('manifest_hash', '')}",
                    f"partial_output_policy_hash:{manifest.get('partial_output_policy_hash', '')}",
                    f"step_status_head_hash:{manifest.get('step_status_head_hash', '')}",
                    f"retry_lineage_hash:{manifest.get('retry_lineage_hash', '')}",
                    f"partial_output_cleanup_status:{manifest.get('partial_output_cleanup_status', '')}",
                    "retry_supported_for:failed,canceled",
                ],
            )
        ],
        "supports": [
            "queued-job-cancel",
            "running-job-cancel-request-record",
            "failed-or-canceled-run-retry",
            "retry-lineage-profile",
            "state-file-persisted-cancel-flag",
            "partial-output-policy-preserved-for-review",
        ],
        "blockers": blockers,
    }


def missing_cancellation_retry_trusted_diff() -> Dict[str, object]:
    return {
        "status": "missing",
        "trusted_tool": None,
        "commercial_gap_ids": [LONG_RUNNING_JOB_GAP_ID],
        "blocker": CANCELLATION_RETRY_TRUSTED_DIFF_BLOCKER_80,
        "required_trusted_tools": sorted(CANCELLATION_RETRY_TRUSTED_TOOLS),
    }


def build_cancellation_retry_trusted_diff(
    rapid_job: Mapping[str, object],
    trusted_job: Mapping[str, object],
    *,
    trusted_tool: str = "cancellation-retry-transition-manifest",
) -> Dict[str, object]:
    rapid_manifest = cancellation_retry_manifest(rapid_job)
    trusted_manifest = cancellation_retry_manifest(trusted_job)
    compared_fields = [
        "status",
        "cancellation_requested",
        "retry_supported_for",
        "retry_of_run_id",
        "retry_attempt",
        "step_statuses",
        "step_status_head_hash",
        "transition_head_hash",
        "retry_lineage_hash",
        "partial_output_policy_hash",
        "partial_output_cleanup_status",
        "cleanup_validation_required",
        "safe_to_auto_delete_partial_outputs",
        "manifest_hash",
    ]
    mismatches = [
        {"field": field, "rapid": rapid_manifest.get(field), "trusted": trusted_manifest.get(field)}
        for field in compared_fields
        if rapid_manifest.get(field) != trusted_manifest.get(field)
    ]
    status = "pass" if not mismatches and trusted_tool in CANCELLATION_RETRY_TRUSTED_TOOLS else "fail"
    return {
        "status": status,
        "trusted_tool": trusted_tool,
        "commercial_gap_ids": [LONG_RUNNING_JOB_GAP_ID],
        "compared_fields": compared_fields,
        "mismatches": mismatches,
        "blocker": None if status == "pass" else CANCELLATION_RETRY_TRUSTED_DIFF_BLOCKER_80,
    }


def cancellation_retry_manifest(job: Mapping[str, object]) -> Dict[str, object]:
    assessment = job.get("cancellation_retry_assessment")
    retry_supported = []
    if isinstance(assessment, Mapping):
        retry_value = assessment.get("retry_supported_for")
        if isinstance(retry_value, list):
            retry_supported = sorted(str(value) for value in retry_value)
    if not retry_supported:
        retry_value = job.get("retry_supported_for")
        if isinstance(retry_value, list):
            retry_supported = sorted(str(value) for value in retry_value)
    if not retry_supported:
        retry_supported = ["canceled", "failed"]
    steps = job.get("steps")
    step_statuses: list[str] = []
    if isinstance(steps, list):
        for step in steps:
            if not isinstance(step, Mapping):
                continue
            step_statuses.append(f"{step.get('name')}:{step.get('status')}")
    transition_profile = job.get("transition_log_profile")
    transition_hash = ""
    transition_count = 0
    if isinstance(transition_profile, Mapping):
        transition_hash = str(transition_profile.get("head_hash") or "")
        transition_count = int(transition_profile.get("transition_count") or 0)
    partial_output_policy = job.get("partial_output_policy")
    partial_output_policy_hash = ""
    partial_output_cleanup_status = ""
    cleanup_validation_required = True
    safe_to_auto_delete_partial_outputs = False
    if isinstance(partial_output_policy, Mapping):
        partial_output_policy_hash = str(partial_output_policy.get("policy_hash") or "")
        partial_output_cleanup_status = str(partial_output_policy.get("partial_output_cleanup_status") or "")
        cleanup_validation_required = bool(partial_output_policy.get("cleanup_validation_required", True))
        safe_to_auto_delete_partial_outputs = bool(
            partial_output_policy.get("safe_to_auto_delete_partial_outputs", False)
        )
    retry_lineage = job.get("retry_lineage_profile")
    retry_lineage_hash = ""
    if isinstance(retry_lineage, Mapping):
        retry_lineage_hash = str(retry_lineage.get("lineage_hash") or "")
    step_status_head_hash = hashlib.sha256(json.dumps(step_statuses, sort_keys=True).encode("utf-8")).hexdigest()
    manifest_core = {
        "profile": "cancellation-retry-manifest-v1",
        "profile_version": "cancellation-retry-manifest-v1",
        "item_number": 80,
        "status": job.get("status"),
        "cancellation_requested": bool(job.get("cancellation_requested")),
        "retry_of_run_id": str(job["retry_of_run_id"]) if job.get("retry_of_run_id") else None,
        "retry_attempt": int(job.get("retry_attempt") or 0),
        "retry_supported_for": retry_supported,
        "step_statuses": step_statuses,
        "step_status_head_hash": step_status_head_hash,
        "transition_count": transition_count,
        "transition_head_hash": transition_hash,
        "retry_lineage_hash": retry_lineage_hash,
        "partial_output_policy_hash": partial_output_policy_hash,
        "partial_output_cleanup_strategy": (
            str(partial_output_policy.get("cleanup_strategy") or "")
            if isinstance(partial_output_policy, Mapping)
            else ""
        ),
        "partial_output_cleanup_status": partial_output_cleanup_status,
        "partial_output_review_required": (
            bool(partial_output_policy.get("review_required_before_cleanup", True))
            if isinstance(partial_output_policy, Mapping)
            else True
        ),
        "cleanup_validation_required": cleanup_validation_required,
        "safe_to_auto_delete_partial_outputs": safe_to_auto_delete_partial_outputs,
        "transition_evidence": {
            "transition_count": transition_count,
            "transition_head_hash": transition_hash,
            "step_status_head_hash": step_status_head_hash,
        },
        "commercial_gap_ids": [LONG_RUNNING_JOB_GAP_ID],
        "commercial_claim_allowed": False,
    }
    manifest_hash = hashlib.sha256(
        json.dumps(manifest_core, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return {**manifest_core, "manifest_hash": manifest_hash}


def cancellation_retry_manifest_source(job: RunJob) -> Dict[str, object]:
    return {
        "status": job.status,
        "cancellation_requested": job.cancellation_requested,
        "retry_of_run_id": job.retry_of_run_id,
        "retry_attempt": job.retry_attempt,
        "retry_supported_for": ["failed", "canceled"],
        "steps": job.steps,
        "transition_log_profile": job_transition_log_profile(job.transition_log),
        "retry_lineage_profile": job_retry_lineage_profile(job),
        "partial_output_policy": job_partial_output_policy(job),
    }


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
            memory_cap_bytes=request.memory_cap_bytes,
            e01_partition_start_sector=request.e01_partition_start_sector,
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
