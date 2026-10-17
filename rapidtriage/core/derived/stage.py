"""The ``derived`` run step (통합 보기, plan axiom-adoption §3.2 "실행").

Right after ``triage-flags`` the derived engine runs over the run's own outputs
into a fresh generation directory ``analyses/run-derived-<UTC time>/`` inside the
run output directory -- the six ``<table>.jsonl`` files and ``summary.json`` first,
the ``analysis.json`` state of kind ``derived`` last -- so the API reads it exactly
like a manually run ``derived`` analysis. Older run-stage generations are removed
afterwards (best effort; one an API reader holds open stays until next time).

A failure never fails the run: the step row reports ``failed_isolated`` with a
Korean warning and the generation keeps no ``analysis.json``. A ``partial`` set is
kept and the step reports a warning.
"""

from __future__ import annotations

import datetime as dt
import logging
import shutil
import time
from collections.abc import Mapping
from pathlib import Path

from ..triage_rules.engine import Progress, TriageInputs
from ..triage_rules.stage import (
    ANALYSES_DIR_NAME,
    ANALYSIS_STATE_VERSION,
    ROWS_FILE_NAME,
    STATE_FILE_NAME,
    _write_state,
)
from .engine import TABLES, run_derived

LOGGER = logging.getLogger(__name__)

DERIVED_ANALYSIS_KIND = "derived"
DERIVED_ANALYSIS_LABEL = "통합 보기"
DERIVED_ANALYSIS_UNIT = "행 소스"
RUN_STAGE_ANALYSIS_PREFIX = "run-derived"
STEP_NAME = "derived"
SUMMARY_STATE_KEYS = ("status", "coverage", "catalog_version", "url_classes", "tables", "rows_scanned", "errors", "caps", "elapsed_s", "limitation")


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _remove_older_generations(root: Path, *, keep: str) -> None:
    try:
        children = [child for child in root.iterdir() if child.is_dir()]
    except OSError:
        return
    for child in children:
        if child.name != keep and child.name.startswith(f"{RUN_STAGE_ANALYSIS_PREFIX}-"):
            shutil.rmtree(child, ignore_errors=True)


def table_counts(summary: Mapping[str, object]) -> dict[str, int]:
    tables = summary.get("tables") if isinstance(summary.get("tables"), Mapping) else {}
    counts: dict[str, int] = {}
    for table in TABLES:
        entry = tables.get(table)
        counts[table] = int(entry.get("rows") or 0) if isinstance(entry, Mapping) else 0
    return counts


def run_derived_stage(
    output_dir: Path,
    *,
    artifact_outputs: Mapping[str, Path],
    artifact_payloads: Mapping[str, Mapping[str, object]] | None = None,
    files_path: Path | None = None,
    files_payload: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Run the derived engine into a new ``analyses/run-derived-<time>/``; returns the run-summary step row."""
    root = Path(output_dir) / ANALYSES_DIR_NAME
    analysis_id = f"{RUN_STAGE_ANALYSIS_PREFIX}-{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%f')}"
    directory = root / analysis_id
    started_at = _utc_now()
    started = time.monotonic()
    step: dict[str, object] = {"name": STEP_NAME, "analysis_id": analysis_id, "output": str(directory)}
    sources: list[str] = []
    try:
        directory.mkdir(parents=True, exist_ok=False)
        (directory / ROWS_FILE_NAME).touch()
        summary = run_derived(
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
    except Exception as exc:  # the run never fails on the derived pass
        LOGGER.exception("derived run step failed")
        step.update(
            {
                "status": "failed_isolated",
                "warning_level": "warning",
                # Type + first 100 chars only: the full text can carry evidence paths or row fragments
                # (the traceback is in the log).
                "warning_messages": [f"통합 보기 단계 실패: {type(exc).__name__}: {str(exc)[:100]}"],
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "reused": False,
            }
        )
        return step
    elapsed = round(time.monotonic() - started, 3)
    state: dict[str, object] = {
        "version": ANALYSIS_STATE_VERSION,
        "analysis_id": analysis_id,
        "run_id": None,
        "kind": DERIVED_ANALYSIS_KIND,
        "label": DERIVED_ANALYSIS_LABEL,
        "status": "completed",
        "options": {"source": "run-stage"},
        "created_at": started_at,
        "started_at": started_at,
        "finished_at": _utc_now(),
        "elapsed_s": elapsed,
        "cancel_requested_at": None,
        "progress": {"done": len(sources), "total": len(sources), "unit": DERIVED_ANALYSIS_UNIT, "message": "완료", "percent": 100.0},
        "row_count": 0,
        "output_dir": str(directory),
        "rows_path": str(directory / ROWS_FILE_NAME),
        "summary": {"source": "run-stage", **{key: summary.get(key) for key in SUMMARY_STATE_KEYS}},
        "error": None,
    }
    messages: list[str] = []
    errors = summary.get("errors") if isinstance(summary.get("errors"), Mapping) else {}
    if errors:
        messages.append(f"통합 보기 소스 읽기 오류 {len(errors)}건(요약의 errors 참조)")
    coverage = summary.get("coverage") if isinstance(summary.get("coverage"), Mapping) else {}
    if summary.get("status") == "partial":
        incomplete = ", ".join(str(kind) for kind in coverage.get("incomplete") or [])
        messages.append(f"통합 보기 일부만 계산됨: 끝까지 읽지 못한 소스({incomplete})의 나머지 행은 빠졌습니다")
    tables = summary.get("tables") if isinstance(summary.get("tables"), Mapping) else {}
    capped = [str(name) for name, entry in tables.items() if isinstance(entry, Mapping) and entry.get("capped")]
    if capped:
        messages.append(f"통합 보기 상한 도달: {', '.join(capped)} (새 값은 더 추가하지 않음)")
    state_written = True
    try:
        _write_state(directory / STATE_FILE_NAME, state)
    except OSError as exc:
        state_written = False
        messages.append(f"통합 보기 상태 파일을 쓰지 못했습니다: {exc}"[:300])
    if state_written:
        _remove_older_generations(root, keep=analysis_id)
    step.update(
        {
            "status": "completed" if state_written else "failed_isolated",
            "coverage": "complete" if summary.get("status") != "partial" else "partial",
            "table_rows": table_counts(summary),
            "elapsed_seconds": elapsed,
            "warning_level": "warning" if messages else "none",
            "warning_messages": messages,
            "reused": False,
        }
    )
    return step
