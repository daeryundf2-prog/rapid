from __future__ import annotations

import datetime as dt
from collections.abc import Mapping
from pathlib import Path
from typing import Sequence

from .audit import compute_sha256
from .docs import write_result
from .e01 import build_windows11_e01_known_answer_manifest, e01_failure_guidance, is_e01_path
from .evidence import identify_evidence
from .run import RunModeError, run_triage_mode

E01_SMOKE_PROFILE_VERSION = "windows11-e01-end-to-end-smoke-v1"
E01_SMOKE_OUTPUT_NAME = "rapidforensic-e01-smoke.json"
E01_KNOWN_ANSWER_OUTPUT_NAME = "windows11-e01-known-answer.json"
E01_EVIDENCE_PREFLIGHT_OUTPUT_NAME = "rapidtriage-evidence-preflight.json"


def _output_status(path: Path) -> dict[str, object]:
    status: dict[str, object] = {
        "path": str(path),
        "exists": path.is_file(),
    }
    if path.is_file():
        stat = path.stat()
        status.update(
            {
                "size_bytes": stat.st_size,
                "sha256": compute_sha256(path),
            }
        )
    return status


def _stage(
    stage_id: str,
    name: str,
    status: str,
    *,
    output_path: Path | None = None,
    details: Mapping[str, object] | None = None,
) -> dict[str, object]:
    row: dict[str, object] = {
        "id": stage_id,
        "name": name,
        "status": status,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    if output_path is not None:
        row["output"] = _output_status(output_path)
    if details:
        row["details"] = dict(details)
    return row


def _run_output_statuses(outputs: Mapping[str, object]) -> dict[str, object]:
    rows: dict[str, object] = {}
    for key, value in outputs.items():
        if isinstance(value, str):
            rows[key] = _output_status(Path(value))
    return rows


def run_windows11_e01_smoke(
    source: Path,
    *,
    output_dir: Path,
    case_id: str = "windows11-e01-smoke",
    mode: str = "hacking",
    input_kind: str | None = None,
    expected_partition_start_sector: int | None = None,
    expected_artifacts: Sequence[str] | None = None,
    validation_commands: Sequence[str] | None = None,
    execute: bool = True,
    read_only: bool = True,
    resume: bool = False,
    max_file_count: int = 0,
    max_extract_size_bytes: int = 0,
    memory_cap_bytes: int = 0,
) -> dict[str, object]:
    """Build a single-case E01 workflow smoke report with honest blockers.

    The smoke report is intentionally broader than extraction: it preserves the
    known-answer draft, evidence adapter preflight, attempted end-to-end run, and
    report/checkpoint outputs so an analyst can see where the workflow breaks.
    """

    source = source.expanduser().resolve()
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    known_answer_path = output_dir / E01_KNOWN_ANSWER_OUTPUT_NAME
    evidence_path = output_dir / E01_EVIDENCE_PREFLIGHT_OUTPUT_NAME
    smoke_path = output_dir / E01_SMOKE_OUTPUT_NAME
    run_dir = output_dir / "run"

    expected_artifacts = list(expected_artifacts or [])
    validation_commands = list(validation_commands or [])
    stages: list[dict[str, object]] = []

    known_answer = build_windows11_e01_known_answer_manifest(
        source,
        case_id=case_id,
        expected_partition_start_sector=expected_partition_start_sector,
        expected_artifacts=expected_artifacts,
        validation_commands=validation_commands,
    )
    write_result(known_answer, known_answer_path)
    stages.append(
        _stage(
            "known-answer-manifest",
            "Windows 11 E01 known-answer manifest",
            "complete",
            output_path=known_answer_path,
            details={
                "manifest_sha256": known_answer.get("manifest_sha256"),
                "commercial_grade_ready": known_answer.get("commercial_grade_ready"),
            },
        )
    )

    evidence = identify_evidence(source).to_dict()
    write_result(evidence, evidence_path)
    stages.append(
        _stage(
            "evidence-preflight",
            "Evidence adapter and dependency preflight",
            "complete" if evidence.get("supported") else "blocked",
            output_path=evidence_path,
            details={
                "adapter": evidence.get("adapter"),
                "detected_format": evidence.get("detected_format"),
                "missing_tools": evidence.get("missing_tools") or [],
                "support_level": evidence.get("support_level"),
            },
        )
    )

    run_payload: dict[str, object] | None = None
    run_error: dict[str, object] | None = None
    if execute:
        try:
            run_payload = run_triage_mode(
                source,
                mode=mode,
                output_dir=run_dir,
                input_kind=input_kind,
                read_only=read_only,
                max_extract_size_bytes=max_extract_size_bytes,
                max_file_count=max_file_count,
                memory_cap_bytes=memory_cap_bytes,
                e01_partition_start_sector=expected_partition_start_sector,
                resume=resume,
            )
            stages.append(
                _stage(
                    "triage-run",
                    "E01 extraction, artifact analysis, search indexes, and report",
                    "complete",
                    details={
                        "summary": run_payload.get("summary", {}),
                        "outputs": _run_output_statuses(run_payload.get("outputs", {})),
                    },
                )
            )
        except (RunModeError, OSError, ValueError) as exc:
            raw_error = str(exc)
            guidance = e01_failure_guidance(raw_error) if is_e01_path(source) else {"raw_error": raw_error}
            run_error = {
                "error": raw_error,
                "failure_guidance": guidance,
                "run_dir": str(run_dir),
            }
            stages.append(
                _stage(
                    "triage-run",
                    "E01 extraction, artifact analysis, search indexes, and report",
                    "blocked",
                    details=run_error,
                )
            )
    else:
        stages.append(
            _stage(
                "triage-run",
                "E01 extraction, artifact analysis, search indexes, and report",
                "skipped",
                details={"reason": "plan-only"},
            )
        )

    completed = run_payload is not None
    blocked = any(stage.get("status") == "blocked" for stage in stages)
    status = "complete" if completed else "blocked" if blocked else "planned"
    outputs: dict[str, object] = {
        "known_answer_manifest": _output_status(known_answer_path),
        "evidence_preflight": _output_status(evidence_path),
    }
    if run_payload and isinstance(run_payload.get("outputs"), Mapping):
        outputs["run"] = _run_output_statuses(run_payload["outputs"])

    payload: dict[str, object] = {
        "schema": "rapidforensic-e01-smoke-report-v1",
        "profile_version": E01_SMOKE_PROFILE_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "case_id": case_id,
        "source_path": str(source),
        "mode": mode,
        "input_kind": input_kind,
        "status": status,
        "stages": stages,
        "known_answer_manifest": known_answer,
        "evidence_preflight": evidence,
        "run_summary": run_payload.get("summary", {}) if run_payload else {},
        "run_error": run_error,
        "outputs": outputs,
        "commercial_gap_ids": ["#22", "#64", "#85", "#90"],
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "Known-answer assertions must be executed against a real Windows 11 E01 and trusted-tool outputs.",
            "Direct E01 extraction depends on libewf/Sleuth Kit availability and platform mount behavior.",
            "Report citations still require reviewer validation against original source paths, offsets, and hashes.",
        ],
        "operator_next_steps": [
            "Run this command against the real Windows 11 E01 on the target workstation.",
            "If triage-run is blocked, follow failure_guidance and rerun with --resume.",
            "Attach trusted-tool diff output before claiming commercial-grade E01 support.",
        ],
    }
    payload["outputs"]["smoke_report"] = {
        "path": str(smoke_path),
        "exists": True,
        "sha256": None,
        "hash_note": "Self-referential smoke report hash is omitted; hash the saved file externally when packaging evidence.",
    }
    write_result(payload, smoke_path)
    return payload
