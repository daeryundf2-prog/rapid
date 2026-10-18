"""Stage outputs for run-plan tasks that were skipped or cancelled (plan P2 §3.3).

A skipped or cancelled stage still leaves an output of the usual shape so the
summary, report, and readers keep their contract: the payload is produced by
the real stage function over an empty input (zero rows) and is marked with
``plan_status`` (``skipped``/``cancelled``) and the Korean ``plan_reason``.
Stage outputs built from partial provider inputs (``finish``, a cancelled or
skipped provider) carry ``inputs_partial: true`` and ``partial_kinds``.
"""

from __future__ import annotations

import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path

from ..docs import run_docs_search
from ..files import run_files_scan
from ..indicators import build_indicator_summary
from ..input_root import InputRoot, derive_child_input_root
from ..timeline import run_timeline
from .plan import TASK_LABELS, iter_tasks
from .steps import annotate_step

__all__ = [
    "apply_plan_to_steps",
    "mark_inputs_partial",
    "partial_provider_kinds",
    "plan_step_rows",
    "planned_out_docs_payload",
    "planned_out_files_payload",
    "planned_out_indicators_payload",
    "planned_out_step",
    "planned_out_timeline_payload",
]

PLAN_STATUS_LABELS = {"skipped": "건너뜀", "cancelled": "취소", "partial": "일부 완료"}


def _mark(payload: dict[str, object], status: str, reason: str | None) -> dict[str, object]:
    payload["plan_status"] = status
    payload["plan_reason"] = reason or ""
    summary = payload.get("summary")
    if isinstance(summary, dict):
        summary["plan_status"] = status
        summary["plan_reason"] = reason or ""
    return payload


def planned_out_docs_payload(
    scan_input_root: InputRoot,
    keywords: Sequence[str],
    *,
    index_output: Path,
    manifest: Mapping[str, object],
    status: str,
    reason: str | None,
) -> dict[str, object]:
    """Zero-candidate docs payload (and an empty docs index at ``index_output``)."""
    with tempfile.TemporaryDirectory(prefix="rapidtriage-planned-out-") as empty:
        payload = run_docs_search(
            derive_child_input_root(scan_input_root, Path(empty)),
            keywords,
            index_output=index_output,
            manifest=manifest,
        )
    payload["root"] = str(scan_input_root.root_path)
    return _mark(payload, status, reason)


def planned_out_files_payload(scan_input_root: InputRoot, *, status: str, reason: str | None) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="rapidtriage-planned-out-") as empty:
        payload = run_files_scan(derive_child_input_root(scan_input_root, Path(empty)))
    payload["root"] = str(scan_input_root.root_path)
    return _mark(payload, status, reason)


def planned_out_timeline_payload(input_root: InputRoot, *, status: str, reason: str | None) -> dict[str, object]:
    # run_timeline collects from its root for a missing input kind: hand it empty
    # in-memory inputs (and an empty root) so nothing is read from the evidence.
    with tempfile.TemporaryDirectory(prefix="rapidtriage-planned-out-") as empty:
        base = Path(empty)
        inputs = {
            str((base / "files.json").resolve()): {"command": "files", "summary": {}, "candidates": [], "inventory": []},
            str((base / "docs.json").resolve()): {"command": "docs", "summary": {}, "results": [], "candidates": []},
            str((base / "artifacts.json").resolve()): {"command": "artifacts", "summary": {}, "artifacts": []},
        }
        payload = run_timeline(
            root=base,
            input_kind=input_root.kind,
            files_inputs=[base / "files.json"],
            docs_inputs=[base / "docs.json"],
            artifacts_inputs=[base / "artifacts.json"],
            input_payloads=inputs,
        )
        payload["inputs"] = []
    payload["root"] = str(input_root.root_path)
    return _mark(payload, status, reason)


def planned_out_indicators_payload(*, status: str, reason: str | None) -> dict[str, object]:
    return _mark(build_indicator_summary({"outputs": {}}), status, reason)


def planned_out_step(name: str, *, status: str, reason: str | None, requested_by: Mapping[str, object] | None = None) -> dict[str, object]:
    """Summary step row of a stage task that did not run."""
    who = ""
    if isinstance(requested_by, Mapping) and requested_by.get("actor"):
        who = f" ({requested_by.get('actor')}, {requested_by.get('at') or ''})"
    label = PLAN_STATUS_LABELS.get(status, status)
    return annotate_step(
        {
            "name": name,
            "status": status,
            "output": "",
            "plan_reason": reason or "",
            "requested_by": dict(requested_by or {}) or None,
        },
        warning_level="warning",
        warning_messages=[f"{TASK_LABELS.get(name, name)} {label}: {reason or '사유 없음'}{who}"],
    )


def partial_provider_kinds(plan: Mapping[str, object] | None) -> list[str]:
    """Provider kinds whose rows are missing or incomplete (partial/cancelled/skipped/failed)."""
    if not isinstance(plan, Mapping):
        return []
    return [
        str(task.get("id"))
        for task in iter_tasks(plan)
        if task.get("type") == "provider" and task.get("status") in {"partial", "cancelled", "skipped", "failed"}
    ]


def mark_inputs_partial(payload: dict[str, object], partial_kinds: Sequence[str]) -> dict[str, object]:
    """``inputs_partial`` / ``partial_kinds`` on a stage payload built from incomplete provider inputs."""
    if not partial_kinds:
        return payload
    payload["inputs_partial"] = True
    payload["partial_kinds"] = list(partial_kinds)
    summary = payload.get("summary")
    if isinstance(summary, dict):
        summary["inputs_partial"] = True
        summary["partial_kinds"] = list(partial_kinds)
    return payload


def plan_step_rows(plan: Mapping[str, object] | None, existing_names: set[str]) -> list[dict[str, object]]:
    """Step rows for plan tasks absent from the summary steps (skipped/cancelled providers and stages)."""
    if not isinstance(plan, Mapping):
        return []
    rows: list[dict[str, object]] = []
    for task in iter_tasks(plan):
        status = str(task.get("status") or "")
        if status not in {"skipped", "cancelled"}:
            continue
        if task.get("reason") in OPTION_REASONS:
            # Switched-off options are not examiner actions; the plan file records them.
            continue
        task_id = str(task.get("id"))
        name = f"artifacts-{task_id}" if task.get("type") == "provider" else task_id
        if name in existing_names:
            continue
        requested_by = task.get("requested_by") if isinstance(task.get("requested_by"), Mapping) else None
        row = planned_out_step(task_id, status=status, reason=str(task.get("reason") or ""), requested_by=requested_by)
        row["name"] = name
        row["plan_group"] = task.get("group")
        rows.append(row)
    return rows


OPTION_REASONS = frozenset({"옵션 꺼짐", "케이스 DB 꺼짐", "폴더 입력"})
# Summary step row name -> plan task id (stage rows built by steps.build_step_rows).
STEP_TASKS = {
    "docs": "docs",
    "docs-index": "docs",
    "files": "files",
    "docs-extract": "docs-extract",
    "files-extract": "files-extract",
    "timeline": "timeline",
    "indicators": "indicators",
    "triage-flags": "triage-flags",
    "derived": "derived",
}


def apply_plan_to_steps(step_rows: list[dict[str, object]], plan: Mapping[str, object] | None) -> None:
    """Set ``status`` and a Korean warning on step rows whose plan task was skipped, cancelled or partial."""
    if not isinstance(plan, Mapping):
        return
    tasks = {str(task.get("id")): task for task in iter_tasks(plan)}
    for row in step_rows:
        name = str(row.get("name") or "")
        task_id = name.removeprefix("artifacts-") if name.startswith("artifacts-") else STEP_TASKS.get(name)
        task = tasks.get(task_id or "")
        if task is None:
            continue
        status = str(task.get("status") or "")
        if status not in {"skipped", "cancelled", "partial"} or task.get("reason") in OPTION_REASONS:
            continue
        if status == "partial" and task.get("type") != "provider":
            continue
        requested_by = task.get("requested_by") if isinstance(task.get("requested_by"), Mapping) else None
        who = f" ({requested_by.get('actor')}, {requested_by.get('at') or ''})" if requested_by else ""
        label = PLAN_STATUS_LABELS.get(status, status)
        rows = int(task.get("artifact_count") or 0)
        detail = f" · 남은 행 {rows:,}" if status == "partial" else ""
        row["status"] = status
        row["plan_reason"] = str(task.get("reason") or "")
        row["requested_by"] = dict(requested_by) if requested_by else None
        row["warning_level"] = "warning"
        messages = [str(item) for item in row.get("warning_messages") or [] if str(item)]
        messages.insert(0, f"{TASK_LABELS.get(str(task_id), str(task_id))} {label}: {task.get('reason') or '사유 없음'}{who}{detail}")
        row["warning_messages"] = messages
