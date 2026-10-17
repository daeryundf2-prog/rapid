"""Processing problems of a run, grouped by reason (AXIOM ``scan_problem`` adoption, plan E1).

``GET /api/runs/{id}/problems`` reads the run summary's ``warnings``, each
artifacts output's ``parser_errors``, the silent-failure detector's failing
checks and the failed/skipped ``steps`` and groups them by a stable
``reason_id`` with a Korean label, so the 접수 card shows "행 단위 절단 3" instead
of 19 loose lines.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from fastapi import HTTPException

from ...core.jobs import RunJob, RunJobStore
from .helpers import get_job, get_output_path
from .tree import read_output_key

PROBLEM_PREVIEW_LIMIT = 20
PROBLEM_MAX_LIMIT = 5000

LEVEL_RANK = {"error": 0, "warning": 1, "notice": 2}

#: (reason_id, label_ko, pattern) — first match wins; order matters.
WARNING_REASONS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("row-truncated", "행 단위 절단 (원문 일부만 보존)", re.compile(r"행 단위 절단")),
    ("preview-truncated", "표시용 미리보기 절단 (원본 보존)", re.compile(r"미리보기 절단")),
    ("cap-truncated", "상한·절단 적용 (전수 아님)", re.compile(r"상한/절단 적용|truncat", re.IGNORECASE)),
    ("size-cap", "크기 상한 초과로 본문 미추출", re.compile(r"크기 상한 초과|too-large")),
    ("binary-rejected", "비인쇄 문자 비율 초과로 미색인", re.compile(r"비인쇄 문자|binary-rejected")),
    ("file-count-cap", "파일 수 상한으로 미선별", re.compile(r"파일 수 상한|미선별")),
    ("no-rows", "수집된 행 없음", re.compile(r"No [\w-]+ artifact rows were collected|수집된 행 없음")),
    ("input-missing", "입력 없음 (해당 증거 없음)", re.compile(r"루트 없음|추출물 없음|not found|찾을 수 없")),
)
FIXED_REASONS = {
    "parser-error": "파서 오류",
    "step-failed": "실패한 단계",
    "step-skipped": "건너뛴 단계",
    "silent-failure": "조용한 실패 위험",
    "run-failed": "런 실패",
    "run-cancelled": "런 취소됨",
    "other-warning": "기타 경고",
    "other-notice": "기타 알림",
}
ALL_REASON_LABELS = {**{rid: label for rid, label, _ in WARNING_REASONS}, **FIXED_REASONS}


def classify_warning(message: str, level: str) -> str:
    for reason_id, _label, pattern in WARNING_REASONS:
        if pattern.search(message):
            return reason_id
    return "other-notice" if level == "notice" else "other-warning"


def _warnings(summary: Mapping[str, object]) -> list[Mapping[str, object]]:
    warnings = summary.get("warnings")
    if not isinstance(warnings, list):
        processing = summary.get("processing")
        warnings = processing.get("warnings") if isinstance(processing, Mapping) else None
    return [item for item in warnings or [] if isinstance(item, Mapping)]


def collect_problem_items(store: RunJobStore, run_id: str, job: RunJob) -> list[dict[str, Any]]:
    """Every problem item ``{reason_id, source, step, level, message}`` in summary order."""
    items: list[dict[str, Any]] = []
    summary = job.summary
    if summary is None:
        if job.status in ("failed", "cancelled", "canceled"):
            reason = "run-failed" if job.status == "failed" else "run-cancelled"
            items.append({"reason_id": reason, "source": "run", "step": "", "level": "error",
                          "message": job.error or ("런이 실패했습니다" if reason == "run-failed" else "런이 취소되었습니다")})
        return items
    for warning in _warnings(summary):
        message = str(warning.get("message") or "")
        level = str(warning.get("level") or "warning")
        items.append({"reason_id": classify_warning(message, level), "source": "warning",
                      "step": str(warning.get("step") or ""), "level": level, "message": message})
    # Steps already count each provider's parser errors: outputs with a recorded 0 are not opened
    # (24 artifact JSONs, some tens of MB, on a real run).
    recorded_errors = {
        str(step.get("name")): step.get("parser_error_count")
        for step in summary.get("steps") or []
        if isinstance(step, Mapping)
    }
    outputs = summary.get("outputs")
    if isinstance(outputs, Mapping):
        for name in sorted(outputs):
            if not str(name).startswith("artifacts_"):
                continue
            if recorded_errors.get(f"artifacts-{str(name).removeprefix('artifacts_')}") == 0:
                continue
            try:
                path = get_output_path(store, run_id, str(name))
            except HTTPException:
                continue
            errors = read_output_key(path, "parser_errors")
            if not isinstance(errors, list):
                continue
            kind = str(name).removeprefix("artifacts_")
            for error in errors:
                message = error if isinstance(error, str) else json.dumps(error, ensure_ascii=False)
                items.append({"reason_id": "parser-error", "source": "parser_error", "step": f"artifacts-{kind}",
                              "level": "error", "message": message})
    silent = summary.get("silent_failure_detection")
    if isinstance(silent, Mapping) and isinstance(silent.get("checks"), list):
        for check in silent["checks"]:
            if not isinstance(check, Mapping):
                continue
            level = str(check.get("level") or "")
            if level in ("pass", "") and not check.get("requires_review"):
                continue
            detail = str(check.get("detail") or "")
            message = f"{check.get('id') or ''}: {check.get('message') or ''}" + (f" ({detail})" if detail else "")
            items.append({"reason_id": "silent-failure", "source": "silent_failure",
                          "step": "silent-failure-detector", "level": "error" if level == "fail" else "warning",
                          "message": message})
    steps = summary.get("steps")
    if isinstance(steps, list):
        for step in steps:
            if not isinstance(step, Mapping):
                continue
            status = str(step.get("status") or "")
            if status == "skipped":
                reason, level = "step-skipped", "notice"
                message = str(step.get("disabled_reason") or step.get("message") or "건너뜀")
            elif "fail" in status:
                reason, level = "step-failed", "error"
                message = str(step.get("error") or step.get("message") or status)
            else:
                continue
            items.append({"reason_id": reason, "source": "step", "step": str(step.get("name") or ""),
                          "level": level, "message": message})
    return items


def group_problems(items: list[dict[str, Any]], *, limit: int) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for item in items:
        reason_id = str(item["reason_id"])
        group = groups.setdefault(
            reason_id,
            {"reason_id": reason_id, "label_ko": ALL_REASON_LABELS.get(reason_id, reason_id), "level": item["level"],
             "count": 0, "steps": [], "items": []},
        )
        group["count"] += 1
        if LEVEL_RANK.get(str(item["level"]), 3) < LEVEL_RANK.get(str(group["level"]), 3):
            group["level"] = item["level"]
        if item["step"] and item["step"] not in group["steps"]:
            group["steps"].append(item["step"])
        if len(group["items"]) < limit:
            group["items"].append({key: item[key] for key in ("source", "step", "level", "message")})
    return sorted(
        groups.values(),
        key=lambda g: (LEVEL_RANK.get(str(g["level"]), 3), -int(g["count"]), str(g["reason_id"])),
    )


def build_run_problems(store: RunJobStore, run_id: str, *, reason_id: str | None = None,
                       limit: int = PROBLEM_PREVIEW_LIMIT) -> dict[str, Any]:
    job = get_job(store, run_id)
    if job.summary is None and job.status in ("queued", "running"):
        raise HTTPException(status_code=409, detail="런이 아직 끝나지 않았습니다")
    items = collect_problem_items(store, run_id, job)
    if reason_id:
        items = [item for item in items if item["reason_id"] == reason_id]
    groups = group_problems(items, limit=limit)
    by_level: dict[str, int] = {}
    for item in items:
        by_level[str(item["level"])] = by_level.get(str(item["level"]), 0) + 1
    return {
        "command": "run.problems",
        "run_id": run_id,
        "total": len(items),
        "by_level": by_level,
        "limit": limit,
        "groups": groups,
    }
