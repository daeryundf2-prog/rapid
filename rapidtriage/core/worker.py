from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Callable, Mapping, Sequence

from .artifact_store import JsonlArtifactStreamWriter, JsonlArtifactWriteResult, write_jsonl_artifact_manifest, write_jsonl_artifacts


DEFAULT_WORKER_TIMEOUT_SECONDS = 30.0
MAX_CAPTURED_STDERR_CHARS = 4000


class WorkerError(RuntimeError):
    """Raised when an isolated parser worker fails before producing usable output."""


@dataclass(frozen=True)
class WorkerResult:
    command: list[str]
    return_code: int
    records: list[dict[str, object]]
    errors: list[dict[str, object]]
    stderr: str = ""
    timed_out: bool = False
    streamed_record_count: int | None = None

    @property
    def ok(self) -> bool:
        return self.return_code == 0 and not self.timed_out and not self.errors

    @property
    def record_count(self) -> int:
        return self.streamed_record_count if self.streamed_record_count is not None else len(self.records)


@dataclass(frozen=True)
class RustWorkerClient:
    executable: Path | None = None
    timeout_seconds: float = DEFAULT_WORKER_TIMEOUT_SECONDS
    extra_env: Mapping[str, str] = field(default_factory=dict)

    @classmethod
    def from_environment(cls) -> "RustWorkerClient":
        raw = os.environ.get("RAPIDTRIAGE_RUST_WORKER") or ""
        executable = Path(raw).expanduser().resolve() if raw else None
        return cls(executable=executable)

    def resolve_executable(self) -> str:
        if self.executable is not None:
            return str(self.executable)
        found = shutil.which("rapid-worker")
        if found:
            return found
        raise WorkerError(
            "rapid-worker executable not found; set RAPIDTRIAGE_RUST_WORKER or add rapid-worker to PATH"
        )

    def parse(
        self,
        *,
        kind: str,
        source: Path,
        case_id: str = "CASE",
        source_id: str = "SOURCE",
        extra_args: Sequence[str] = (),
    ) -> WorkerResult:
        records: list[dict[str, object]] = []
        return self._run_worker(
            kind=kind,
            source=source,
            case_id=case_id,
            source_id=source_id,
            extra_args=extra_args,
            collect_records=records,
        )

    def _build_command(
        self,
        *,
        kind: str,
        source: Path,
        case_id: str,
        source_id: str,
        extra_args: Sequence[str],
    ) -> list[str]:
        return [
            self.resolve_executable(),
            "parse",
            "--kind",
            kind,
            "--source",
            str(source),
            "--case-id",
            case_id,
            "--source-id",
            source_id,
            *extra_args,
        ]

    def _run_worker(
        self,
        *,
        kind: str,
        source: Path,
        case_id: str,
        source_id: str,
        extra_args: Sequence[str],
        on_record: Callable[[dict[str, object]], None] | None = None,
        collect_records: list[dict[str, object]] | None = None,
    ) -> WorkerResult:
        command = self._build_command(
            kind=kind,
            source=source,
            case_id=case_id,
            source_id=source_id,
            extra_args=extra_args,
        )
        env = os.environ.copy()
        env.update(self.extra_env)
        records = collect_records if collect_records is not None else []
        errors: list[dict[str, object]] = []
        stderr_parts: list[str] = []
        stderr_len = 0
        streamed_record_count = 0
        try:
            process = subprocess.Popen(
                command,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
        except OSError as exc:
            raise WorkerError(f"failed to execute rapid-worker: {exc}") from exc

        events: queue.Queue[tuple[str, str | None]] = queue.Queue()
        threads = [
            threading.Thread(target=_pump_stream, args=("stdout", process.stdout, events), daemon=True),
            threading.Thread(target=_pump_stream, args=("stderr", process.stderr, events), daemon=True),
        ]
        for thread in threads:
            thread.start()

        stdout_done = False
        stderr_done = False
        timed_out = False
        deadline = time.monotonic() + self.timeout_seconds
        line_number = 0
        while not (stdout_done and stderr_done):
            if not timed_out and time.monotonic() > deadline:
                timed_out = True
                process.kill()
                errors.append(
                    {
                        "type": "worker-timeout",
                        "message": f"worker exceeded {self.timeout_seconds:.3f}s timeout",
                    }
                )
            try:
                stream_name, line = events.get(timeout=0.05)
            except queue.Empty:
                continue
            if stream_name == "stdout":
                if line is None:
                    stdout_done = True
                    continue
                line_number += 1
                record, error = parse_jsonl_record_line(line, line_number)
                if error is not None:
                    errors.append(error)
                    continue
                if record is None:
                    continue
                streamed_record_count += 1
                if collect_records is not None:
                    records.append(record)
                if on_record is not None:
                    on_record(record)
                continue
            if line is None:
                stderr_done = True
                continue
            if stderr_len < MAX_CAPTURED_STDERR_CHARS:
                remaining = MAX_CAPTURED_STDERR_CHARS - stderr_len
                stderr_parts.append(line[:remaining])
                stderr_len += min(len(line), remaining)

        return_code = process.wait()
        for thread in threads:
            thread.join(timeout=1)
        stderr = "".join(stderr_parts)
        if return_code != 0 and not timed_out:
            errors.append(
                {
                    "type": "worker-nonzero-exit",
                    "return_code": return_code,
                    "stderr": stderr,
                }
            )
        return WorkerResult(
            command=command,
            return_code=return_code,
            records=records,
            errors=errors,
            stderr=stderr,
            timed_out=timed_out,
            streamed_record_count=streamed_record_count,
        )

    def parse_to_jsonl(
        self,
        *,
        kind: str,
        source: Path,
        output_path: Path,
        case_id: str = "CASE",
        source_id: str = "SOURCE",
        extra_args: Sequence[str] = (),
        reject_invalid: bool = True,
    ) -> dict[str, object]:
        output_path = output_path.expanduser().resolve()
        partial_path = output_path.with_name(output_path.name + ".partial")
        partial_manifest_path = partial_path.with_suffix(partial_path.suffix + ".manifest.json")
        with JsonlArtifactStreamWriter(
            output_path=partial_path,
            manifest_path=partial_manifest_path,
            reject_invalid=reject_invalid,
        ) as writer:
            result = self._run_worker(
                kind=kind,
                source=source,
                case_id=case_id,
                source_id=source_id,
                extra_args=extra_args,
                on_record=writer.write,
            )
            write_result = writer.close()
        if result.ok and write_result.rejected_count == 0:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            partial_path.replace(output_path)
            final_manifest_path = output_path.with_suffix(output_path.suffix + ".manifest.json")
            write_result = write_jsonl_artifact_manifest(
                output_path=output_path,
                manifest_path=final_manifest_path,
                record_count=write_result.record_count,
                rejected_count=write_result.rejected_count,
                errors=write_result.errors,
            )
            partial_manifest_path.unlink(missing_ok=True)
        return build_worker_jsonl_pipeline_result(result, write_result)


def parse_jsonl_records(text: str) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    records: list[dict[str, object]] = []
    errors: list[dict[str, object]] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        record, error = parse_jsonl_record_line(raw_line, line_number)
        if error is not None:
            errors.append(error)
            continue
        if record is None:
            continue
        records.append(record)
    return records, errors


def parse_jsonl_record_line(raw_line: str, line_number: int) -> tuple[dict[str, object] | None, dict[str, object] | None]:
    line = raw_line.strip()
    if not line:
        return None, None
    try:
        payload = json.loads(line)
    except json.JSONDecodeError as exc:
        return None, {
            "type": "malformed-jsonl",
            "line_number": line_number,
            "message": str(exc),
            "line_preview": line[:500],
        }
    if not isinstance(payload, dict):
        return None, {
            "type": "non-object-jsonl",
            "line_number": line_number,
            "line_preview": line[:500],
        }
    return payload, None


def _pump_stream(name: str, stream: IO[str] | None, events: queue.Queue[tuple[str, str | None]]) -> None:
    if stream is None:
        events.put((name, None))
        return
    try:
        for line in stream:
            events.put((name, line))
    finally:
        stream.close()
        events.put((name, None))


def build_worker_jsonl_pipeline_result(
    worker_result: WorkerResult,
    write_result: JsonlArtifactWriteResult,
) -> dict[str, object]:
    return {
        "command": "worker-parse-to-jsonl",
        "worker": {
            "command": worker_result.command,
            "return_code": worker_result.return_code,
            "ok": worker_result.ok,
            "timed_out": worker_result.timed_out,
            "stderr": worker_result.stderr[:4000],
            "record_count": worker_result.record_count,
            "error_count": len(worker_result.errors),
            "errors": worker_result.errors[:100],
        },
        "artifact_store": write_result.to_dict(),
        "pipeline_status": "ok" if worker_result.ok and write_result.rejected_count == 0 else "review-required",
    }
