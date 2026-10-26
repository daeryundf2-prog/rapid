"""The ``triage-flags`` run step (plan viewer-families §3.1 "실행 지점" ①).

At the end of a new run (after ``persist``) the rule engine runs over the
run's own outputs and writes a fresh generation directory
``analyses/run-triage-flags-<UTC time>/`` inside the run output directory --
``flags.jsonl`` + ``summary.json`` first, the ``analysis.json`` state of kind
``triage-flags`` last -- so the API joins it exactly like a manually run
``triage-flags`` analysis and the analysis workbench lists it. A new
generation never writes over files an API reader may hold open (Windows); older
run-stage generations are removed afterwards (best effort). Nothing is written
outside the output directory.

A failure never fails the run: the step row reports ``failed_isolated`` with a
Korean warning and the generation keeps no ``analysis.json`` (no half result is
ever joined). A ``partial`` set (a source could not be read to its end) is
joined but the step reports a warning.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import shutil
import time
import uuid
from collections.abc import Mapping
from pathlib import Path

from ..json_safe import json_default
from .engine import (
    FLAGS_FILE_NAME,
    Progress,
    TriageInputs,
    replace_with_retry,
    run_triage_flags,
)

LOGGER = logging.getLogger(__name__)

TRIAGE_ANALYSIS_KIND = "triage-flags"
TRIAGE_ANALYSIS_LABEL = "특이사항"
TRIAGE_ANALYSIS_UNIT = "행 소스"
RUN_STAGE_ANALYSIS_PREFIX = "run-triage-flags"
STEP_NAME = "triage-flags"
# Mirrors api.app.analyses (the core layer does not import the API package).
ANALYSES_DIR_NAME = "analyses"
STATE_FILE_NAME = "analysis.json"
ROWS_FILE_NAME = "rows.jsonl"
ANALYSIS_STATE_VERSION = "analysis-state-v1"
SUMMARY_STATE_KEYS = (
    "status",
    "coverage",
    "catalog_version",
    "rule_set",
    "flagged_rows",
    "flag_count",
    "rows_by_best_grade",
    "flags_by_grade",
    "by_rule",
    "rows_scanned",
    "skipped_sources",
    "suppressed",
    "rule_errors",
    "elapsed_s",
    "limitation",
)


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def new_run_stage_analysis_id(prefix: str) -> str:
    """``<prefix>-<UTC µs time>-<8 hex>``: unique even when two stage runs share a clock tick.

    The Windows clock can return the same microsecond value for consecutive calls, so a
    timestamp alone collided (``FileExistsError`` on the generation directory). The random
    suffix keeps the id inside ``[A-Za-z0-9_-]{1,64}`` and the ``<prefix>-`` start that
    generation cleanup and readers match on; nothing parses the time part.
    """
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    return f"{prefix}-{stamp}-{uuid.uuid4().hex[:8]}"


def _write_state(path: Path, state: Mapping[str, object]) -> None:
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    try:
        tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2, default=json_default) + "\n", encoding="utf-8")
        replace_with_retry(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _remove_older_generations(root: Path, *, keep: str) -> None:
    """Delete earlier run-stage generations (best effort: one an API reader holds open stays until next time)."""
    try:
        children = [child for child in root.iterdir() if child.is_dir()]
    except OSError:
        return
    for child in children:
        if child.name != keep and (child.name == RUN_STAGE_ANALYSIS_PREFIX or child.name.startswith(f"{RUN_STAGE_ANALYSIS_PREFIX}-")):
            shutil.rmtree(child, ignore_errors=True)


def run_triage_stage(
    output_dir: Path,
    *,
    artifact_outputs: Mapping[str, Path],
    artifact_payloads: Mapping[str, Mapping[str, object]] | None = None,
    files_path: Path | None = None,
    files_payload: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Run the engine over a run's outputs into a new ``analyses/run-triage-flags-<time>/``; returns the run-summary step row."""
    root = Path(output_dir) / ANALYSES_DIR_NAME
    analysis_id = f"{RUN_STAGE_ANALYSIS_PREFIX}-{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%f')}"
    directory = root / analysis_id
    state_path = directory / STATE_FILE_NAME
    started_at = _utc_now()
    started = time.monotonic()
    step: dict[str, object] = {"name": STEP_NAME, "analysis_id": analysis_id, "output": str(directory / FLAGS_FILE_NAME)}
    try:
        directory.mkdir(parents=True, exist_ok=False)
        (directory / ROWS_FILE_NAME).touch()
        sources: list[str] = []
        summary = run_triage_flags(
            TriageInputs(
                output_dir=Path(output_dir),
                artifact_payloads=dict(artifact_outputs),
                files_path=files_path,
                artifact_payload_objects=dict(artifact_payloads or {}),
                files_payload=files_payload,
            ),
            directory,
            source_label="run-stage",
            progress=Progress(begin=lambda kind, _index, _count: sources.append(kind)),
        )
    except Exception as exc:  # the run never fails on the triage pass
        LOGGER.exception("triage-flags run step failed")
        step.update(
            {
                "status": "failed_isolated",
                "warning_level": "warning",
                "warning_messages": [f"특이사항 단계 실패: {type(exc).__name__}: {exc}"[:300]],
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "reused": False,
            }
        )
        return step
    finished_at = _utc_now()
    elapsed = round(time.monotonic() - started, 3)
    state: dict[str, object] = {
        "version": ANALYSIS_STATE_VERSION,
        "analysis_id": analysis_id,
        "run_id": None,
        "kind": TRIAGE_ANALYSIS_KIND,
        "label": TRIAGE_ANALYSIS_LABEL,
        "status": "completed",
        "options": {"source": "run-stage"},
        "created_at": started_at,
        "started_at": started_at,
        "finished_at": finished_at,
        "elapsed_s": elapsed,
        "cancel_requested_at": None,
        "progress": {"done": len(sources), "total": len(sources), "unit": TRIAGE_ANALYSIS_UNIT, "message": "완료", "percent": 100.0},
        "row_count": 0,
        "output_dir": str(directory),
        "rows_path": str(directory / ROWS_FILE_NAME),
        "summary": {"source": "run-stage", **{key: summary.get(key) for key in SUMMARY_STATE_KEYS}},
        "error": None,
    }
    errors = summary.get("rule_errors") if isinstance(summary.get("rule_errors"), Mapping) else {}
    messages = [f"특이사항 규칙 오류 {len(errors)}종(요약의 rule_errors 참조)"] if errors else []
    coverage = summary.get("coverage") if isinstance(summary.get("coverage"), Mapping) else {}
    if summary.get("status") == "partial":
        incomplete = ", ".join(str(kind) for kind in coverage.get("incomplete") or [])
        messages.append(f"특이사항 일부만 계산됨: 끝까지 읽지 못한 소스({incomplete})의 나머지 행에는 특이사항이 없습니다")
    state_written = True
    try:
        _write_state(state_path, state)
    except OSError as exc:
        state_written = False
        messages.append(f"특이사항 상태 파일을 쓰지 못했습니다: {exc}"[:300])
    if state_written:
        _remove_older_generations(root, keep=analysis_id)
    step.update(
        {
            "status": "completed" if state_written else "failed_isolated",
            "coverage": "complete" if summary.get("status") != "partial" else "partial",
            "flagged_rows": summary.get("flagged_rows"),
            "flag_count": summary.get("flag_count"),
            "rows_by_best_grade": summary.get("rows_by_best_grade"),
            "catalog_version": summary.get("catalog_version"),
            "elapsed_seconds": elapsed,
            "warning_level": "warning" if messages else "none",
            "warning_messages": messages,
            "reused": False,
        }
    )
    return step
