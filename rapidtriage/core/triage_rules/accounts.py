"""OS / account indicators: SAM, tasks, services, profiles, WER (catalogue: Windows §5)."""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping

from .base import (
    EVENTLOG,
    PERSISTENCE_MARKERS,
    FlagContext,
    RowRef,
    RowView,
    Rule,
    RuleResult,
    as_list,
    evidence,
    register,
    select,
    split_windows_path,
    suspicious_command,
    under_system_dir,
    user_writable_marker,
)
from .eventlog import target_user

ADMIN_GROUP_SIDS = frozenset({"S-1-5-32-544"})
ADMIN_GROUP_NAMES = frozenset({"administrators", "관리자", "domain admins", "enterprise admins"})
TASK = select(types={"task-scheduler-task"})
_MINUTE_REPETITION = re.compile(r"PT(\d+)M\b", re.IGNORECASE)


@register("accounts.new_account")
class NewAccount(Rule):
    """4720 account creation (inside the incident window when one is set), or a local SAM account ending in ``$``."""

    selector = select(types={"eventlog-event", "eventlog-detection", "windows-sam-account", "windows-sam-account-candidate"})

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if row.source_kind == "eventlog":
            if row.event_id() != "4720" or row.is_duplicate():
                return None
            moment = row.time("timestamp", "time_created")
            if ctx.has_incident_window and not ctx.in_incident(moment):
                return None
            return RuleResult(
                evidence(event_id="4720", account=target_user(row), sid=row.ev_text("TargetSid"), created_by=row.ev_text("SubjectUserName"))
            )
        name = row.text("user_name", "user_name_candidate", "account_name")
        if name.endswith("$"):
            return RuleResult(evidence(account=name, rid=row.get("rid", "rid_decimal")), note="이름이 $로 끝나는 로컬 계정(숨김 계정 기법)")
        return None


@register("accounts.admin_added")
class AdminAdded(Rule):
    """4732/4728/4756: a member added to Administrators (S-1-5-32-544) or an *Admins group."""

    selector = EVENTLOG

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if row.event_id() not in {"4732", "4728", "4756"}:
            return None
        group_sid = row.ev_text("TargetSid").upper()
        group = (row.ev_text("TargetUserName") or target_user(row)).lower()
        if group_sid not in ADMIN_GROUP_SIDS and group not in ADMIN_GROUP_NAMES and not group.endswith(" admins"):
            return None
        return RuleResult(
            evidence(
                event_id=row.event_id(),
                group=group,
                group_sid=group_sid,
                member=row.ev_text("MemberName", "MemberSid"),
                subject_user_name=row.ev_text("SubjectUserName"),
            )
        )


@register("accounts.task_suspicious")
class TaskSuspicious(Rule):
    """Scheduled task running a user-writable/LOLBin/encoded command, or a hidden task with a minute-level trigger or SYSTEM."""

    selector = TASK

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        command = " ".join(
            part for part in (row.text("command", "executable_name"), row.text("arguments")) if part
        ) or row.text("command_line", "action_preview")
        reasons = suspicious_command(command) if command else []
        hidden = row.flag("hidden") is True
        minutes = [int(value) for value in _MINUTE_REPETITION.findall(_repetition_text(row.get("trigger_details", "trigger_types")))]
        minute_trigger = any(value <= int(self.param("max_repeat_minutes", 5)) for value in minutes)
        account = row.text("user_id", "run_as", "principals").upper()
        system = account in {"S-1-5-18", "SYSTEM", "NT AUTHORITY\\SYSTEM"}
        if not reasons and not (hidden and (minute_trigger or system)):
            return None
        if not reasons and _builtin_task(row.text("task_uri"), command):
            return None  # Windows' own hidden SYSTEM tasks (system binary or COM handler action)
        conditions = list(reasons)
        if hidden:
            conditions.append("숨김")
        if minute_trigger:
            conditions.append("분 단위 반복 트리거")
        if system:
            conditions.append("SYSTEM 실행")
        return RuleResult(evidence(task=row.text("task_uri"), command=command, conditions=conditions))


def _repetition_text(value: object) -> str:
    """Repetition intervals of a task's triggers (a trigger's ``Delay`` is not a repetition)."""
    parts: list[str] = []
    for item in as_list(value):
        if isinstance(item, Mapping):
            parts.extend(str(item.get(key) or "") for key in ("repetition_interval", "interval"))
        else:
            parts.append(str(item))
    return " ".join(parts)


def _builtin_task(uri: str, command: str) -> bool:
    """A task under ``\\Microsoft\\Windows\\`` running a Windows/Program Files binary (or a COM handler)."""
    if not uri.replace("/", "\\").lower().startswith("\\microsoft\\windows\\"):
        return False
    return not command or under_system_dir(command)


def _task_key(value: str) -> str:
    return value.replace("/", "\\").strip("\\").casefold()


@register("accounts.task_mismatch")
class TaskMismatch(Rule):
    """TaskCache Tree key without its task file (or without the ``SD`` value: hidden task), or a task file without a TaskCache key."""

    selector = select(types={"task-scheduler-task", "registry-key-tree-node"}, kinds={"windows-system", "windows-registry"})

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.files: dict[str, RowRef] = {}
        self.tree: dict[str, tuple[RowRef, bool]] = {}

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if row.type == "task-scheduler-task":
            uri = _task_key(row.text("task_uri"))
            if uri:
                self.files[uri] = row.ref
            return None
        key = row.text("key_path")
        marker = key.lower().find("\\schedule\\taskcache\\tree\\")
        if marker < 0:
            return None
        names = {str(name).lower() for name in as_list(row.get("value_names"))}
        if "id" not in names:
            return None  # a folder node, not a task
        self.tree[_task_key(key[marker + len("\\schedule\\taskcache\\tree\\") :])] = (row.ref, "sd" in names)
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        if not self.files or not self.tree:
            return  # one side was not collected: no comparison
        for uri, (ref, has_sd) in self.tree.items():
            if not has_sd:
                yield ref, RuleResult(evidence(task=uri), note="TaskCache 키에 SD 값이 없음(숨김 작업 기법)")
            elif uri not in self.files:
                yield ref, RuleResult(evidence(task=uri), note="TaskCache에는 있으나 작업 파일이 없음")
        for uri, ref in self.files.items():
            if uri not in self.tree:
                yield ref, RuleResult(evidence(task=uri), note="작업 파일은 있으나 TaskCache 키가 없음")


@register("accounts.service_suspicious")
class ServiceSuspicious(Rule):
    """Service with a ServiceDll outside System32/SysWOW64, or a user-writable ServiceDll."""

    selector = select(types={"windows-service-config"})

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        dll = row.text("service_dll")
        if not dll:
            return None
        _drive, rest = split_windows_path(dll)
        if rest.startswith(("windows\\system32\\", "windows\\syswow64\\")):
            return None
        reasons = suspicious_command(dll, PERSISTENCE_MARKERS) or ["System32 밖 ServiceDll"]
        return RuleResult(evidence(service_name=row.text("service_name", "name"), service_dll=dll, reasons=reasons))


@register("accounts.profile_anomaly")
class ProfileAnomaly(Rule):
    """ProfileList entry whose profile path is outside Users / service profiles."""

    selector = select(types={"windows-profile-list-entry"})

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        path = row.text("profile_image_path", "profile_path")
        if not path:
            return None
        _drive, rest = split_windows_path(path)
        normal = ("users\\", "documents and settings\\", "windows\\serviceprofiles\\", "windows\\system32\\config\\systemprofile")
        if rest.startswith(normal) or rest in {"windows\\system32\\config\\systemprofile"}:
            return None
        return RuleResult(evidence(sid=row.text("sid"), profile_image_path=path))


@register("accounts.wer_anomaly")
class WerAnomaly(Rule):
    """WER report of an application in a user-writable path, or whose executable is gone from the file listing."""

    selector = select(types={"wer-report"})

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        path = row.text("application_path")
        if not path:
            return None
        marker = user_writable_marker(path, ("\\temp\\", "\\tmp\\", "\\downloads\\", "\\users\\public\\", "\\appdata\\local\\temp\\"))
        missing = ctx.file_missing(path) is True
        if not marker and not missing:
            return None
        reasons = [reason for reason in (marker and f"사용자 쓰기 경로({marker})", missing and "실행 파일이 목록에 없음") if reason]
        return RuleResult(evidence(application_path=path, event_time=row.text("event_time", "timestamp"), reasons=reasons))
