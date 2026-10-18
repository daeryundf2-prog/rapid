"""Run plan: groups -> tasks, run-process ownership, and the run control file.

Plan P2 (``docs/plans/run-model-p2-2026-10-12.md`` §3.1-3.3), updated for the
R2/R3 providers. A run is planned as a fixed, ordered catalog of groups; a
group holds tasks (one per artifact provider kind or pipeline stage). The plan
lives in ``rapidtriage-run-progress.json`` (``plan`` block) while the run is
going and is written to ``rapidtriage-run-plan.json`` when the run ends.

Provider -> group mapping (every built-in collector kind has a domain group;
features added in R2/R3 ride inside their provider task):

* ``os-account``: ``windows-os-account``, ``windows-registry`` (registry depth
  keys, anti-forensics registry traces), ``windows-shellbags``
* ``execution``: ``windows-execution`` (PCA, BAM, Amcache), ``windows-prefetch``
  (prefetch decoding), ``recent-files``
* ``eventlog``: ``eventlog`` (channel counts)
* ``filesystem``: ``windows-filesystem`` (anti-forensics, $UsnJrnl/MFT
  inventory), ``windows-search-index``
* ``web``: ``browser`` (cache, WebCache, upload candidates, map-URL locations), ``p2p``
  (BitTorrent clients, ``.torrent``, eMule; R5 L3)
* ``messaging``: ``email`` (PST/ICS), ``kakaotalk-windows`` (messages and
  pictures), ``kakaotalk-macos``, ``windows-messenger``, ``mobile-export``
* ``cloud``: ``cloud-export``, ``cloud-sync``
* ``media-docs``: ``media-image``, ``generic-documents``, ``synthetic-media``
* ``remote-system``: ``windows-remote-access``, ``windows-system``
* ``memory``: ``memory-volatility``; ``mobile``: ``android-apk``;
  ``cross-platform``: ``linux-system``, ``macos-system``

Kinds outside the run profile (and plugin providers) are collected by the
manifest stage and are tasks of the ``manifest`` group. The stage groups
follow: ``docs``, ``files``, ``carve``, ``extract``, ``timeline``,
``indicators``, ``persist``, ``triage-flags``, ``derived`` and ``report``.

The control file ``rapidtriage-run-control.json`` carries requests from a
reader (web API, ``rapidtriage run-control``) to the run process, which
polls it once per second. Cancelling or skipping never deletes or rewrites
bytes already written.
"""

from __future__ import annotations

import contextlib
import copy
import datetime as dt
import json
import os
import socket
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from pathlib import Path

from ..json_safe import json_default

__all__ = [
    "CONTROL_ACTIONS",
    "CONTROL_FILE_NAME",
    "GROUP_CATALOG",
    "HEARTBEAT_INTERVAL_SECONDS",
    "HEARTBEAT_STALE_SECONDS",
    "PLAN_FILE_NAME",
    "PLAN_VERSION",
    "TASK_STATUSES",
    "ControlFileError",
    "PlanTargetError",
    "RunControlWatcher",
    "append_control_request",
    "build_run_plan",
    "evaluate_control",
    "interrupted_plan_view",
    "orphan_reason",
    "owner_record",
    "plan_counts_brief",
    "plan_preview",
    "read_control_requests",
    "refresh_plan",
    "validate_skip_targets",
]

PLAN_FILE_NAME = "rapidtriage-run-plan.json"
CONTROL_FILE_NAME = "rapidtriage-run-control.json"
PLAN_VERSION = "run-plan-v1"
CONTROL_VERSION = "run-control-v1"
TASK_STATUSES = ("queued", "running", "completed", "partial", "failed", "skipped", "cancelled")
TERMINAL_TASK_STATUSES = frozenset({"completed", "partial", "failed", "skipped", "cancelled"})
CONTROL_ACTIONS = ("cancel", "skip", "cancel_all", "finish")
CONTROL_ACTORS = ("web", "cli")
HEARTBEAT_INTERVAL_SECONDS = 15.0
HEARTBEAT_STALE_SECONDS = 90.0
BOOT_ID_TOLERANCE_SECONDS = 120
CONTROL_POLL_SECONDS = 1.0
REPLACE_ATTEMPTS = 20
CONTROL_LOCK_TIMEOUT_SECONDS = 5.0
CONTROL_LOCK_STALE_SECONDS = 30.0

REASON_PRE_RUN = "실행 전 제외"
REASON_EXAMINER = "검사관 요청"
REASON_FOLDER_INPUT = "폴더 입력"
REASON_OPTION_OFF = "옵션 꺼짐"
REASON_CASE_DB_OFF = "케이스 DB 꺼짐"
REASON_FINISH = "마치기 요청"
REASON_CANCEL_ALL = "모두 취소 요청"
REASON_BEFORE_START = "시작 전 취소"
REASON_RUNNING_CANCEL = "실행 중 취소"
REASON_INTERRUPTED = "서버 재시작으로 중단"

MESSAGE_UNKNOWN_GROUP = "알 수 없는 그룹입니다: {}"
MESSAGE_UNKNOWN_TASK = "알 수 없는 태스크입니다: {}"
MESSAGE_UNSKIPPABLE_GROUP = "건너뛸 수 없는 그룹입니다: {}"
MESSAGE_UNSKIPPABLE_TASK = "건너뛸 수 없는 태스크입니다: {}"
MESSAGE_ALREADY_STARTED = "이미 시작된 태스크는 건너뛸 수 없습니다. 취소를 사용하세요"
MESSAGE_ALREADY_FINISHED = "이미 끝난 태스크입니다"
MESSAGE_NOT_CANCELLABLE = "취소할 수 없는 태스크입니다: {}"
MESSAGE_NO_QUEUED = "대기 중인 태스크가 없습니다"
MESSAGE_REPORT_STARTED = "이미 끝난 태스크입니다: 요약·보고서 단계가 시작되어 {} 요청을 적용할 수 없습니다"
MESSAGE_CONTROL_UNREADABLE = "실행 제어 파일을 읽을 수 없어 요청을 기록하지 않았습니다: {}"
MESSAGE_CONTROL_BUSY = "실행 제어 파일이 다른 요청에 잠겨 있습니다. 잠시 후 다시 시도하세요"

# (group id, Korean label, task ids in execution order). Provider groups list
# collector kinds; a kind absent from the run profile moves to ``manifest``.
GROUP_CATALOG: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("prepare", "증거 준비", ("image-extract",)),
    ("fingerprint", "입력 지문", ("fingerprint",)),
    ("os-account", "운영체제·계정·레지스트리", ("windows-os-account", "windows-registry", "windows-shellbags")),
    ("execution", "실행 흔적", ("windows-execution", "windows-prefetch", "recent-files")),
    ("eventlog", "이벤트 로그", ("eventlog",)),
    ("filesystem", "파일시스템·검색 색인", ("windows-filesystem", "windows-search-index")),
    ("web", "웹·브라우저", ("browser", "p2p")),
    (
        "messaging",
        "메신저·메일",
        ("email", "kakaotalk-windows", "kakaotalk-macos", "windows-messenger", "mobile-export", "email-clients"),
    ),
    ("cloud", "클라우드", ("cloud-export", "cloud-sync")),
    ("media-docs", "미디어·문서", ("media-image", "generic-documents", "synthetic-media", "media-player")),
    ("remote-system", "원격 접속·시스템", ("windows-remote-access", "windows-system")),
    ("memory", "메모리", ("memory-volatility",)),
    ("mobile", "모바일 앱", ("android-apk", "windows-phone-link")),
    ("cross-platform", "리눅스·macOS", ("linux-system", "macos-system")),
    ("manifest", "매니페스트(프로필 밖 공급자)", ("manifest",)),
    ("docs", "문서 검색·색인", ("docs",)),
    ("files", "파일 인벤토리", ("files",)),
    ("carve", "카빙(선택)", ("carve",)),
    ("extract", "추출(선택)", ("docs-extract", "files-extract")),
    ("timeline", "타임라인", ("timeline",)),
    ("indicators", "지표", ("indicators",)),
    ("persist", "케이스 DB", ("persist",)),
    ("triage-flags", "특이사항 규칙", ("triage-flags",)),
    ("derived", "통합 보기", ("derived",)),
    ("report", "요약·보고서·감사", ("report",)),
)
GROUP_LABELS: dict[str, str] = {group_id: label for group_id, label, _ in GROUP_CATALOG}
STAGE_TASK_IDS: frozenset[str] = frozenset(
    {
        "image-extract",
        "fingerprint",
        "manifest",
        "docs",
        "files",
        "carve",
        "docs-extract",
        "files-extract",
        "timeline",
        "indicators",
        "persist",
        "triage-flags",
        "derived",
        "report",
    }
)
PROVIDER_GROUPS: dict[str, str] = {
    task_id: group_id
    for group_id, _label, task_ids in GROUP_CATALOG
    for task_id in task_ids
    if task_id not in STAGE_TASK_IDS
}
# Progress stage name -> plan stage task ids (core/run/__init__.py stages).
STAGE_TASKS: dict[str, tuple[str, ...]] = {
    "prepare": ("image-extract",),
    "fingerprint": ("fingerprint",),
    "manifest": ("manifest",),
    "docs": ("docs",),
    "files": ("files",),
    "carve": ("carve",),
    "extract": ("docs-extract", "files-extract"),
    "timeline": ("timeline",),
    "indicators": ("indicators",),
    "persist": ("persist",),
    "triage-flags": ("triage-flags",),
    "derived": ("derived",),
    "report": ("report",),
}
UNSKIPPABLE_GROUPS = frozenset({"prepare", "fingerprint", "report"})
UNSKIPPABLE_TASKS = frozenset({"image-extract", "fingerprint", "manifest", "report"})
TASK_LABELS: dict[str, str] = {
    "image-extract": "증거 이미지 추출",
    "fingerprint": "입력 지문",
    "manifest": "매니페스트 조립",
    "docs": "문서 검색·색인",
    "files": "파일 인벤토리",
    "carve": "카빙",
    "docs-extract": "문서 추출",
    "files-extract": "파일 추출",
    "timeline": "타임라인",
    "indicators": "지표",
    "persist": "케이스 DB",
    "triage-flags": "특이사항 규칙",
    "derived": "통합 보기",
    "report": "요약·보고서·감사",
    "windows-os-account": "OS 계정",
    "windows-registry": "레지스트리",
    "windows-shellbags": "ShellBags",
    "windows-execution": "실행 흔적(PCA·BAM·Amcache)",
    "windows-prefetch": "Prefetch",
    "recent-files": "최근 파일·LNK",
    "eventlog": "이벤트 로그",
    "windows-filesystem": "파일시스템 기록",
    "windows-search-index": "Windows 검색 색인",
    "browser": "브라우저(캐시·WebCache 포함)",
    "p2p": "P2P·토렌트(eMule 포함)",
    "email": "이메일(PST·ICS 포함)",
    "kakaotalk-windows": "카카오톡 (Windows)",
    "kakaotalk-macos": "카카오톡 (macOS)",
    "windows-messenger": "데스크톱 메신저 (Windows)",
    "mobile-export": "모바일 내보내기",
    "cloud-export": "클라우드 내보내기",
    "cloud-sync": "클라우드 동기화 클라이언트",
    "media-image": "미디어 이미지",
    "generic-documents": "문서",
    "synthetic-media": "합성 미디어",
    "windows-remote-access": "원격 접속",
    "windows-system": "Windows 시스템",
    "memory-volatility": "메모리 (Volatility)",
    "android-apk": "Android APK",
    "linux-system": "Linux 시스템",
    "macos-system": "macOS 시스템",
    # R5 L1
    "email-clients": "메일 클라이언트(Thunderbird·Windows 메일)",
    "media-player": "미디어 플레이어 재생 기록",
    "windows-phone-link": "휴대폰과 연결(Phone Link)",
}


class PlanTargetError(ValueError):
    """An unknown or unskippable group/task id (``str(exc)`` is Korean)."""


class ControlFileError(RuntimeError):
    """The control file could not be read or locked; nothing was appended (``str(exc)`` is Korean)."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def parse_utc(value: object) -> dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


# --- catalog -------------------------------------------------------------------


def builtin_provider_kinds() -> list[str]:
    """Every registered collector kind (built-in + plugin) in registry order."""
    from ...artifacts import all_providers
    from ..docs import provider_progress_key

    return [provider_progress_key(provider) for provider in all_providers()]


def plan_groups(profile_kinds: Sequence[str], provider_kinds: Sequence[str] | None = None) -> list[tuple[str, str, list[str]]]:
    """``(group id, label, task ids)`` for a run whose profile schedules ``profile_kinds``."""
    in_profile = [str(kind) for kind in profile_kinds]
    profile_set = set(in_profile)
    registered = list(provider_kinds) if provider_kinds is not None else builtin_provider_kinds()
    outside = [kind for kind in registered if kind not in profile_set]
    groups: list[tuple[str, str, list[str]]] = []
    placed: set[str] = set()
    for group_id, label, task_ids in GROUP_CATALOG:
        if group_id == "manifest":
            unplaced = [kind for kind in in_profile if kind not in PROVIDER_GROUPS and kind not in placed]
            tasks = [*unplaced, *outside, "manifest"]
            placed.update(unplaced)
        else:
            tasks = [task for task in task_ids if task in STAGE_TASK_IDS or task in profile_set]
            placed.update(task for task in tasks if task not in STAGE_TASK_IDS)
        groups.append((group_id, label, tasks))
    return groups


def _profile_kinds(mode: str) -> tuple[str, ...]:
    from .profiles import RUN_PROFILES

    profile = RUN_PROFILES.get(str(mode).lower())
    if profile is None:
        raise PlanTargetError(f"지원하지 않는 모드입니다: {mode}")
    return profile.artifacts_kinds


def validate_skip_targets(
    mode: str,
    skip_groups: Iterable[str] = (),
    skip_tasks: Iterable[str] = (),
    *,
    provider_kinds: Sequence[str] | None = None,
) -> tuple[list[str], list[str]]:
    """Normalized ``(skip_groups, skip_tasks)``; raises :class:`PlanTargetError` (Korean)."""
    groups = plan_groups(_profile_kinds(mode), provider_kinds)
    group_ids = {group_id for group_id, _label, _tasks in groups}
    task_ids = {task for _group, _label, tasks in groups for task in tasks}
    normalized_groups: list[str] = []
    for raw in skip_groups:
        group_id = str(raw).strip()
        if not group_id:
            continue
        if group_id not in group_ids:
            raise PlanTargetError(MESSAGE_UNKNOWN_GROUP.format(group_id))
        if group_id in UNSKIPPABLE_GROUPS:
            raise PlanTargetError(MESSAGE_UNSKIPPABLE_GROUP.format(group_id))
        if group_id not in normalized_groups:
            normalized_groups.append(group_id)
    normalized_tasks: list[str] = []
    for raw in skip_tasks:
        task_id = str(raw).strip()
        if not task_id:
            continue
        if task_id not in task_ids:
            raise PlanTargetError(MESSAGE_UNKNOWN_TASK.format(task_id))
        if task_id in UNSKIPPABLE_TASKS:
            raise PlanTargetError(MESSAGE_UNSKIPPABLE_TASK.format(task_id))
        if task_id not in normalized_tasks:
            normalized_tasks.append(task_id)
    return normalized_groups, normalized_tasks


def _new_task(task_id: str, group_id: str, order: int) -> dict[str, object]:
    return {
        "id": task_id,
        "group": group_id,
        "label": TASK_LABELS.get(task_id, task_id),
        "type": "stage" if task_id in STAGE_TASK_IDS else "provider",
        "status": "queued",
        "reused": False,
        "queued_order": order,
        "started_at": None,
        "finished_at": None,
        "duration_ms": None,
        "artifact_count": None,
        "rows_so_far": 0,
        "output": None,
        "message": "",
        "reason": None,
        "requested_by": None,
        "parser_error_count": 0,
        "skippable": task_id not in UNSKIPPABLE_TASKS and group_id not in UNSKIPPABLE_GROUPS,
    }


def build_run_plan(
    *,
    mode: str,
    run_root: str = "",
    carve: bool = False,
    extract: bool = False,
    case_db: bool = True,
    skip_groups: Iterable[str] = (),
    skip_tasks: Iterable[str] = (),
    provider_kinds: Sequence[str] | None = None,
    actor: str = "cli",
    profile_kinds: Sequence[str] | None = None,
) -> dict[str, object]:
    """A fresh plan (every task ``queued``; pre-run skips and switched-off options ``skipped``)."""
    kinds = tuple(profile_kinds) if profile_kinds is not None else _profile_kinds(mode)
    groups_spec = plan_groups(kinds, provider_kinds)
    if profile_kinds is None:
        normalized_groups, normalized_tasks = validate_skip_targets(
            mode, skip_groups, skip_tasks, provider_kinds=provider_kinds
        )
    else:
        normalized_groups = [str(item) for item in skip_groups if str(item)]
        normalized_tasks = [str(item) for item in skip_tasks if str(item)]
    now = utc_now()
    requested = {"actor": actor if actor in CONTROL_ACTORS else "cli", "at": now}
    groups: list[dict[str, object]] = []
    order = 0
    for group_id, label, task_ids in groups_spec:
        tasks: list[dict[str, object]] = []
        for task_id in task_ids:
            task = _new_task(task_id, group_id, order)
            order += 1
            if group_id in normalized_groups or task_id in normalized_tasks:
                if task["skippable"]:
                    task.update(status="skipped", reason=REASON_PRE_RUN, requested_by=dict(requested))
            elif task_id == "carve" and not carve or task_id in {"docs-extract", "files-extract"} and not extract:
                task.update(status="skipped", reason=REASON_OPTION_OFF)
            elif task_id == "persist" and not case_db:
                task.update(status="skipped", reason=REASON_CASE_DB_OFF)
            tasks.append(task)
        groups.append(
            {
                "id": group_id,
                "label": label,
                "status": "queued",
                "skippable": group_id not in UNSKIPPABLE_GROUPS,
                "counts": {},
                "started_at": None,
                "finished_at": None,
                "duration_ms": None,
                "artifact_count": None,
                "tasks": tasks,
            }
        )
    plan: dict[str, object] = {
        "command": "run-plan",
        "version": PLAN_VERSION,
        "run_root": str(run_root),
        "mode": str(mode).lower(),
        "options": {
            "carve": bool(carve),
            "extract": bool(extract),
            "case_db": bool(case_db),
            "skip_groups": normalized_groups,
            "skip_tasks": normalized_tasks,
        },
        "outcome": None,
        "control": {"cancel_all_at": None, "finish_at": None, "requests": []},
        "counts": {},
        "groups": groups,
        "started_at": now,
        "updated_at": now,
    }
    refresh_plan(plan)
    return plan


def plan_preview(
    mode: str,
    *,
    carve: bool = False,
    extract: bool = False,
    case_db: bool = True,
    input_kind: str | None = None,
    provider_kinds: Sequence[str] | None = None,
) -> dict[str, object]:
    """Group checklist for the run dialog (no file access beyond the provider registry)."""
    groups = plan_groups(_profile_kinds(mode), provider_kinds)
    rows: list[dict[str, object]] = []
    for group_id, label, task_ids in groups:
        default_on = True
        if group_id == "carve":
            default_on = bool(carve)
        elif group_id == "extract":
            default_on = bool(extract)
        elif group_id == "persist":
            default_on = bool(case_db)
        elif group_id == "manifest" and task_ids == ["manifest"]:
            default_on = True
        rows.append(
            {
                "id": group_id,
                "label": label,
                "default_on": default_on,
                "skippable": group_id not in UNSKIPPABLE_GROUPS,
                "tasks": [{"id": task_id, "label": TASK_LABELS.get(task_id, task_id)} for task_id in task_ids],
            }
        )
    return {"mode": str(mode).lower(), "input_kind": input_kind or None, "groups": rows}


# --- derivation ----------------------------------------------------------------


def iter_tasks(plan: Mapping[str, object]) -> Iterator[dict[str, object]]:
    for group in plan.get("groups") or []:
        if isinstance(group, dict):
            for task in group.get("tasks") or []:
                if isinstance(task, dict):
                    yield task


def find_task(plan: Mapping[str, object], task_id: str) -> dict[str, object] | None:
    for task in iter_tasks(plan):
        if task.get("id") == task_id:
            return task
    return None


def find_group(plan: Mapping[str, object], group_id: str) -> dict[str, object] | None:
    for group in plan.get("groups") or []:
        if isinstance(group, dict) and group.get("id") == group_id:
            return group
    return None


def empty_counts() -> dict[str, int]:
    return {"total": 0, **{status: 0 for status in TASK_STATUSES}}


def derive_group_status(statuses: Sequence[str]) -> str:
    """Group status from its task statuses (plan P2 §3.1 precedence)."""
    if not statuses:
        return "completed"
    if any(status == "running" for status in statuses):
        return "running"
    if all(status == "queued" for status in statuses):
        return "queued"
    if all(status == "completed" for status in statuses):
        return "completed"
    if all(status == "skipped" for status in statuses):
        return "skipped"
    completed = sum(1 for status in statuses if status == "completed")
    if any(status == "queued" for status in statuses) and not any(
        status in {"partial", "failed", "cancelled"} for status in statuses
    ):
        # Some tasks done (or skipped), others still waiting: in progress.
        return "running" if completed else "queued"
    if completed == 0 and any(status == "cancelled" for status in statuses) and not any(
        status in {"partial", "failed"} for status in statuses
    ):
        return "cancelled"
    if completed == 0 and all(status in {"failed", "skipped"} for status in statuses):
        return "failed"
    return "partial"


def refresh_plan(plan: dict[str, object]) -> dict[str, object]:
    """Recompute group statuses, counts, timings and the root ``counts`` in place."""
    group_counts = empty_counts()
    task_counts = empty_counts()
    for group in plan.get("groups") or []:
        if not isinstance(group, dict):
            continue
        tasks = [task for task in group.get("tasks") or [] if isinstance(task, dict)]
        counts = empty_counts()
        started: list[str] = []
        finished: list[str] = []
        artifact_total = 0
        artifact_known = False
        for task in tasks:
            status = str(task.get("status") or "queued")
            counts["total"] += 1
            counts[status] = counts.get(status, 0) + 1
            task_counts["total"] += 1
            task_counts[status] = task_counts.get(status, 0) + 1
            if task.get("started_at"):
                started.append(str(task["started_at"]))
            if task.get("finished_at"):
                finished.append(str(task["finished_at"]))
            if isinstance(task.get("artifact_count"), int):
                artifact_total += int(task["artifact_count"])
                artifact_known = True
        status = derive_group_status([str(task.get("status") or "queued") for task in tasks])
        group["status"] = status
        group["counts"] = counts
        group["started_at"] = min(started) if started else None
        all_terminal = all(str(task.get("status")) in TERMINAL_TASK_STATUSES for task in tasks)
        group["finished_at"] = max(finished) if finished and all_terminal else None
        start_at = parse_utc(group["started_at"])
        end_at = parse_utc(group["finished_at"])
        group["duration_ms"] = (
            max(0, int((end_at - start_at).total_seconds() * 1000)) if start_at and end_at else None
        )
        group["artifact_count"] = artifact_total if artifact_known else None
        group_counts["total"] += 1
        group_counts[status] = group_counts.get(status, 0) + 1
    plan["counts"] = {"groups": group_counts, "tasks": task_counts}
    plan["updated_at"] = utc_now()
    return plan


def plan_counts_brief(plan: Mapping[str, object] | None) -> dict[str, int] | None:
    """``{groups, tasks, completed, partial, failed, skipped, cancelled, running, queued}`` (task counts)."""
    if not isinstance(plan, Mapping):
        return None
    counts = plan.get("counts") if isinstance(plan.get("counts"), Mapping) else {}
    groups = counts.get("groups") if isinstance(counts.get("groups"), Mapping) else {}
    tasks = counts.get("tasks") if isinstance(counts.get("tasks"), Mapping) else {}
    brief = {"groups": int(groups.get("total") or 0), "tasks": int(tasks.get("total") or 0)}
    for status in ("completed", "partial", "failed", "skipped", "cancelled", "running", "queued"):
        brief[status] = int(tasks.get(status) or 0)
    brief["groups_done"] = sum(
        int(groups.get(status) or 0) for status in ("completed", "partial", "failed", "skipped", "cancelled")
    )
    return brief


def plan_outcome(plan: Mapping[str, object]) -> str:
    """``complete`` when nothing was cancelled/partial/runtime-skipped, else ``partial``."""
    control = plan.get("control") if isinstance(plan.get("control"), Mapping) else {}
    if control.get("cancel_all_at"):
        return "cancelled"
    for task in iter_tasks(plan):
        status = task.get("status")
        if status in {"partial", "cancelled"}:
            return "partial"
        if status == "skipped" and task.get("requested_by") is not None and task.get("reason") != REASON_PRE_RUN:
            return "partial"
    return "complete"


def interrupted_plan_view(plan: Mapping[str, object], *, at: str | None = None) -> dict[str, object]:
    """Copy of ``plan`` as served after its run process died (the file is not rewritten)."""
    view = copy.deepcopy(dict(plan))
    for task in iter_tasks(view):
        if task.get("status") == "running":
            rows = int(task.get("rows_so_far") or 0)
            task["status"] = "partial" if rows > 0 else "cancelled"
            task["reason"] = REASON_INTERRUPTED
            task["finished_at"] = task.get("finished_at") or at
    view["outcome"] = "interrupted"
    refresh_plan(view)
    if at:
        view["updated_at"] = at
    return view


def control_targets(
    plan: Mapping[str, object], targets: Sequence[Mapping[str, object]]
) -> tuple[list[tuple[dict[str, object], list[dict[str, object]]]], list[dict[str, object]]]:
    """Resolve ``[{group}|{task}]`` targets to plan tasks; unknown targets are rejected."""
    resolved: list[tuple[dict[str, object], list[dict[str, object]]]] = []
    rejected: list[dict[str, object]] = []
    for raw in targets:
        target = {key: str(value) for key, value in dict(raw).items() if key in {"group", "task"} and value}
        if "task" in target:
            task = find_task(plan, target["task"])
            if task is None:
                rejected.append({"target": target, "reason": MESSAGE_UNKNOWN_TASK.format(target["task"])})
                continue
            resolved.append((target, [task]))
        elif "group" in target:
            group = find_group(plan, target["group"])
            if group is None:
                rejected.append({"target": target, "reason": MESSAGE_UNKNOWN_GROUP.format(target["group"])})
                continue
            resolved.append((target, [task for task in group.get("tasks") or [] if isinstance(task, dict)]))
        else:
            rejected.append({"target": dict(raw), "reason": "대상은 group 또는 task여야 합니다"})
    return resolved, rejected


def report_started(plan: Mapping[str, object]) -> bool:
    """``True`` once the ``report`` task left ``queued`` (summary/report/audit being written)."""
    task = find_task(plan, "report")
    return task is not None and str(task.get("status") or "queued") != "queued"


def evaluate_control(
    plan: Mapping[str, object], action: str, targets: Sequence[Mapping[str, object]] = ()
) -> tuple[list[dict[str, object]], list[dict[str, object]], dict[str, str]]:
    """``(accepted targets, rejected [{target, reason}], {task id: effect})`` without mutating ``plan``.

    ``effect`` is ``skip`` (queued -> skipped), ``cancel-queued`` (queued ->
    cancelled) or ``cancel-running`` (cancel event for a running task).
    ``cancel_all``/``finish`` take no targets and are accepted until the
    ``report`` task starts; after that they are rejected (``이미 끝난 태스크``)
    so the plan outcome and the progress status never disagree.
    """
    effects: dict[str, str] = {}
    if action in {"cancel_all", "finish"} and report_started(plan):
        # The summary/report/audit are being written: the run outcome is settled.
        return [], [{"target": {}, "reason": MESSAGE_REPORT_STARTED.format(action)}], effects
    if action == "cancel_all":
        for task in iter_tasks(plan):
            if task.get("id") == "report":
                continue
            if task.get("status") == "queued":
                effects[str(task["id"])] = "cancel-queued"
            elif task.get("status") == "running":
                effects[str(task["id"])] = "cancel-running"
        return [], [], effects
    if action == "finish":
        for task in iter_tasks(plan):
            if task.get("type") == "provider" and task.get("status") == "queued":
                effects[str(task["id"])] = "cancel-queued"
        return [], [], effects
    resolved, rejected = control_targets(plan, targets)
    accepted: list[dict[str, object]] = []
    for target, tasks in resolved:
        target_effects: dict[str, str] = {}
        reason = MESSAGE_ALREADY_FINISHED
        for task in tasks:
            task_id = str(task.get("id"))
            status = str(task.get("status") or "")
            if not task.get("skippable", True):
                if "task" in target:
                    reason = MESSAGE_NOT_CANCELLABLE.format(task_id)
                continue
            if action == "skip":
                if status == "queued":
                    target_effects[task_id] = "skip"
                elif status == "running":
                    reason = MESSAGE_ALREADY_STARTED
            elif action == "cancel":
                if status == "queued":
                    target_effects[task_id] = "cancel-queued"
                elif status == "running":
                    target_effects[task_id] = "cancel-running"
        if target_effects:
            accepted.append(target)
            effects.update(target_effects)
        else:
            if "group" in target and reason == MESSAGE_ALREADY_FINISHED and action == "skip":
                reason = MESSAGE_NO_QUEUED if any(task.get("status") == "running" for task in tasks) else reason
            rejected.append({"target": target, "reason": reason})
    return accepted, rejected, effects


# --- process ownership (same shape as api/app/analyses.py ``_owner``) ----------


def boot_id() -> int:
    """Approximate boot time (epoch seconds); changes across reboots."""
    return int(time.time() - time.monotonic())


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if pid == os.getpid():
        return True
    if os.name == "nt":
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return kernel32.GetLastError() == 5  # access denied: the process exists
        try:
            code = ctypes.c_ulong()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return True
            return code.value == 259  # STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def owner_record() -> dict[str, object]:
    return {"pid": os.getpid(), "boot_id": boot_id(), "heartbeat_at": time.time()}


def orphan_reason(owner: object, *, now: float | None = None, active_here: bool = False) -> str | None:
    """Why a running progress file's owner can no longer finish it (``None``: still owned)."""
    if active_here:
        return None
    if not isinstance(owner, Mapping):
        return "owner-missing"
    now = time.time() if now is None else now
    try:
        pid = int(owner.get("pid") or 0)
        owner_boot = int(owner.get("boot_id") or 0)
        heartbeat = float(owner.get("heartbeat_at") or 0.0)
    except (TypeError, ValueError):
        return "owner-invalid"
    if abs(owner_boot - boot_id()) > BOOT_ID_TOLERANCE_SECONDS:
        return "rebooted"
    if pid == os.getpid():
        return "not-active-in-owner"
    if not pid_alive(pid):
        return "owner-dead"
    if now - heartbeat > HEARTBEAT_STALE_SECONDS * 4:
        # Alive pid but silent for 6 minutes: the pid was reused or the run hung.
        return "heartbeat-stale"
    return None


# --- control file ----------------------------------------------------------------


def control_path(output_dir: Path) -> Path:
    return Path(output_dir) / CONTROL_FILE_NAME


def read_control_requests(output_dir: Path) -> list[dict[str, object]]:
    """Requests in the control file (``[]`` when it is missing or unreadable)."""
    try:
        return read_control_requests_strict(output_dir)
    except ControlFileError:
        return []


def read_control_requests_strict(output_dir: Path) -> list[dict[str, object]]:
    """Requests in the control file: ``[]`` when it does not exist, :class:`ControlFileError` when unreadable."""
    path = control_path(output_dir)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    except (OSError, UnicodeDecodeError) as exc:
        raise ControlFileError(MESSAGE_CONTROL_UNREADABLE.format(exc)) from exc
    try:
        payload = json.loads(text)
    except ValueError as exc:
        raise ControlFileError(MESSAGE_CONTROL_UNREADABLE.format(exc)) from exc
    requests = payload.get("requests") if isinstance(payload, Mapping) else None
    if not isinstance(requests, list):
        raise ControlFileError(MESSAGE_CONTROL_UNREADABLE.format("requests 목록이 없습니다"))
    return [dict(item) for item in requests if isinstance(item, Mapping)]


_CONTROL_WRITE_LOCK = threading.Lock()


@contextlib.contextmanager
def control_file_lock(output_dir: Path, *, timeout: float = CONTROL_LOCK_TIMEOUT_SECONDS) -> Iterator[None]:
    """Cross-process lock (``O_EXCL`` lock file) around the control file's read-modify-write.

    A lock file older than ``CONTROL_LOCK_STALE_SECONDS`` (its writer died)
    is removed. Raises :class:`ControlFileError` when the lock is not
    obtained within ``timeout`` seconds.
    """
    lock_path = control_path(output_dir).with_name(CONTROL_FILE_NAME + ".lock")
    deadline = time.monotonic() + timeout
    while True:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            break
        except FileExistsError:
            try:
                age = time.time() - lock_path.stat().st_mtime
            except OSError:
                age = 0.0
            if age > CONTROL_LOCK_STALE_SECONDS:
                with contextlib.suppress(OSError):
                    lock_path.unlink()
                continue
        except PermissionError:
            # Windows: the holder is deleting the lock file right now.
            pass
        if time.monotonic() >= deadline:
            raise ControlFileError(MESSAGE_CONTROL_BUSY)
        time.sleep(0.02)
    try:
        with contextlib.suppress(OSError):
            os.write(fd, f"{os.getpid()} {socket.gethostname()}".encode("utf-8", "replace"))
        os.close(fd)
        yield
    finally:
        with contextlib.suppress(OSError):
            lock_path.unlink()


def append_control_request(
    output_dir: Path,
    action: str,
    targets: Sequence[Mapping[str, object]] = (),
    *,
    actor: str = "cli",
) -> dict[str, object]:
    """Append one request to ``rapidtriage-run-control.json`` (atomic replace) and return it.

    The read-modify-write runs under :func:`control_file_lock` (other
    processes: CLI ``run-control``, a second server). An unreadable existing
    file raises :class:`ControlFileError` instead of being rewritten, so the
    request history and its ``seq`` numbering are never reset.
    """
    if action not in CONTROL_ACTIONS:
        raise PlanTargetError(f"알 수 없는 동작입니다: {action}")
    path = control_path(output_dir)
    with _CONTROL_WRITE_LOCK, control_file_lock(output_dir):
        requests = read_control_requests_strict(output_dir)
        request = {
            "seq": (max((int(item.get("seq") or 0) for item in requests), default=0) + 1),
            "action": action,
            "targets": [
                {key: str(value) for key, value in dict(target).items() if key in {"group", "task"} and value}
                for target in targets
            ],
            "actor": actor if actor in CONTROL_ACTORS else "cli",
            "host": socket.gethostname(),
            "at": utc_now(),
        }
        requests.append(request)
        payload = {"version": CONTROL_VERSION, "requests": requests}
        tmp = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=json_default) + "\n", encoding="utf-8")
        for attempt in range(REPLACE_ATTEMPTS):
            try:
                os.replace(tmp, path)
                break
            except PermissionError:
                if attempt == REPLACE_ATTEMPTS - 1:
                    tmp.unlink(missing_ok=True)
                    raise
                time.sleep(0.05)
    return request


class RunControlWatcher:
    """Polls the control file once per second and hands new requests to ``handler``.

    Requests already in the file when the watcher starts belong to an earlier
    run in the same output directory (resume) and are not replayed. With
    ``since`` (ISO time, e.g. when the run was submitted) only requests written
    before ``since`` count as earlier: a request written after the run was
    submitted but before the watcher started (a quick "모두 취소") is applied.
    """

    def __init__(
        self,
        output_dir: Path,
        handler: Callable[[dict[str, object]], None],
        *,
        poll_seconds: float = CONTROL_POLL_SECONDS,
        since: str | None = None,
    ) -> None:
        self.output_dir = Path(output_dir)
        self._handler = handler
        self._poll_seconds = poll_seconds
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        since_at = parse_utc(since)
        existing = read_control_requests(self.output_dir)
        if since_at is not None:
            existing = [item for item in existing if (parse_utc(item.get("at")) or since_at) < since_at]
        self._last_seq = max((int(item.get("seq") or 0) for item in existing), default=0)
        self._last_stamp: tuple[int, int] | None = None

    def start(self) -> None:
        # Apply requests already waiting (e.g. a cancel_all sent while the run was queued) before
        # the first stage: the loop below only polls after one interval, and a short run can end first.
        self.poll()
        self._thread = threading.Thread(target=self._loop, name="rapidtriage-run-control", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=2.0)

    def poll(self) -> None:
        """Apply any unseen requests now (also called by in-process writers)."""
        with self._lock:
            try:
                stat = control_path(self.output_dir).stat()
            except OSError:
                return
            stamp = (stat.st_mtime_ns, stat.st_size)
            if stamp == self._last_stamp:
                return
            try:
                requests = read_control_requests_strict(self.output_dir)
            except ControlFileError:
                # Unreadable right now: the stamp stays unset so the next poll reads again.
                return
            self._last_stamp = stamp
            for request in requests:
                seq = int(request.get("seq") or 0)
                if seq <= self._last_seq:
                    continue
                self._last_seq = seq
                try:
                    self._handler(request)
                except Exception:  # a bad request never kills the run
                    continue

    def _loop(self) -> None:
        while not self._stop.wait(self._poll_seconds):
            self.poll()
