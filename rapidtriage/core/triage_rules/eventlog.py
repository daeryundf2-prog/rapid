"""Event log indicators (catalogue: Windows §1)."""

from __future__ import annotations

import datetime as dt
import re
from collections import Counter, defaultdict
from collections.abc import Iterator

from .base import (
    ENCODED_POWERSHELL,
    EVENTLOG,
    FlagContext,
    RowRef,
    RowView,
    Rule,
    RuleResult,
    base_name,
    clean_ip,
    evidence,
    hour_of,
    is_public_ip,
    register,
    split_windows_path,
    suspicious_command,
    under_system_dir,
    window_groups,
)

SYSMON_CHANNEL = "microsoft-windows-sysmon/operational"
POWERSHELL_OPERATIONAL = "microsoft-windows-powershell/operational"
INTERACTIVE_LOGON_TYPES = frozenset({"2", "10", "11"})


def logon_type(row: RowView) -> str:
    return row.text("logon_type") or row.ev_text("LogonType")


def logon_ip(row: RowView) -> str:
    return clean_ip(row.text("source_ip", "ip_address") or row.ev_text("IpAddress", "SourceAddress", "ClientAddress"))


def target_user(row: RowView) -> str:
    return (row.text("target_user_name") or row.ev_text("TargetUserName")).strip()


def is_security(row: RowView) -> bool:
    return row.channel() == "security" or "security-auditing" in row.provider()


def is_sysmon(row: RowView) -> bool:
    return row.channel() == SYSMON_CHANNEL or "sysmon" in row.provider()


def is_service_account(name: str) -> bool:
    lowered = name.lower()
    return (
        not lowered
        or lowered.endswith("$")
        or lowered in {"system", "local service", "network service", "anonymous logon", "-"}
        or lowered.startswith(("dwm-", "umfd-", "font driver host"))
    )


@register("eventlog.rdp_external_ip")
class RdpExternalLogon(Rule):
    """4624 LogonType 10 from a public (non-RFC1918/loopback/link-local) address."""

    selector = EVENTLOG

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if row.event_id() != "4624" or logon_type(row) != "10":
            return None
        ip = logon_ip(row)
        if not is_public_ip(ip):
            return None
        return RuleResult(evidence(event_id="4624", logon_type="10", source_ip=ip, target_user_name=target_user(row)))


def _failed_logons(rows: list[tuple[dt.datetime, RowRef, str, str]], window: dt.timedelta, minimum: int):
    """Bursts of 4625 per source IP (or per target user when the IP is empty): ``[(key, group)]``."""
    buckets: dict[str, list[tuple[dt.datetime, RowRef]]] = defaultdict(list)
    for moment, ref, ip, user in rows:
        key = f"ip:{ip}" if ip else f"user:{user.lower()}"
        if key in {"ip:", "user:"}:
            continue
        buckets[key].append((moment, ref))
    for key, items in buckets.items():
        for group in window_groups(items, window, minimum):
            yield key, group


@register("eventlog.failed_logon_burst")
class FailedLogonBurst(Rule):
    """≥ ``min_count`` 4625 from one source IP (or for one account) within ``window_minutes``."""

    selector = EVENTLOG

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.rows: list[tuple[dt.datetime, RowRef, str, str]] = []

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if row.event_id() == "4625" and not row.is_duplicate():
            moment = row.time("timestamp", "time_created", "event_created_at")
            if moment is not None:
                self.rows.append((moment, row.ref, logon_ip(row), target_user(row)))
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        window = dt.timedelta(minutes=float(self.param("window_minutes", 5)))
        for key, group in _failed_logons(self.rows, window, int(self.param("min_count", 10))):
            first, last = group[0][0], group[-1][0]
            for _moment, ref in group:
                yield ref, RuleResult(
                    evidence(bucket=key, burst_count=len(group), burst_start=first, burst_end=last),
                    note=f"{len(group)}건 실패가 {int((last - first).total_seconds())}초 안에 발생",
                )


@register("eventlog.burst_then_success")
class BurstThenSuccess(Rule):
    """A 4624 from the source IP (or account) of a 4625 burst within ``success_within_minutes`` after it."""

    selector = EVENTLOG

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.failed: list[tuple[dt.datetime, RowRef, str, str]] = []
        self.success: list[tuple[dt.datetime, RowRef, str, str, str]] = []

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        event_id = row.event_id()
        if event_id not in {"4624", "4625"} or row.is_duplicate():
            return None
        moment = row.time("timestamp", "time_created", "event_created_at")
        if moment is None:
            return None
        if event_id == "4625":
            self.failed.append((moment, row.ref, logon_ip(row), target_user(row)))
        else:
            self.success.append((moment, row.ref, logon_ip(row), target_user(row), logon_type(row)))
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        window = dt.timedelta(minutes=float(self.param("window_minutes", 5)))
        after = dt.timedelta(minutes=float(self.param("success_within_minutes", 60)))
        bursts: dict[str, list[tuple[dt.datetime, dt.datetime, int]]] = defaultdict(list)
        for key, group in _failed_logons(self.failed, window, int(self.param("min_count", 10))):
            bursts[key].append((group[0][0], group[-1][0], len(group)))
        if not bursts:
            return
        for moment, ref, ip, user, kind in self.success:
            keys = [f"ip:{ip}"] if ip else []
            keys.append(f"user:{user.lower()}")
            for key in keys:
                for start, end, count in bursts.get(key, ()):
                    if start <= moment <= end + after:
                        yield ref, RuleResult(
                            evidence(bucket=key, logon_type=kind, burst_count=count, burst_start=start, burst_end=end),
                            note="실패 폭주 뒤(또는 도중) 같은 출처의 로그온 성공",
                        )
                        break
                else:
                    continue
                break


@register("eventlog.log_cleared")
class LogCleared(Rule):
    """Security 1102 / System 104 (Eventlog provider): an event log was cleared."""

    selector = EVENTLOG

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        event_id = row.event_id()
        provider = row.provider()
        if event_id == "1102":
            cleared = is_security(row) or "eventlog" in provider
        elif event_id == "104":
            cleared = "eventlog" in provider or (not provider and row.channel() == "system")
        else:
            cleared = False
        if not cleared:
            return None
        return RuleResult(
            evidence(
                event_id=event_id,
                channel=row.text("channel"),
                subject_user_name=row.text("subject_user_name") or row.ev_text("SubjectUserName"),
                cleared_channel=row.ev_text("Channel"),
                backup_path=row.ev_text("BackupPath"),
                timestamp=row.text("timestamp"),
            )
        )


@register("eventlog.record_id_gap")
class RecordIdGap(Rule):
    """A jump of more than ``min_gap`` EventRecordIDs between consecutive live records of one .evtx file."""

    selector = EVENTLOG

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.records: dict[str, list[tuple[int, RowRef]]] = defaultdict(list)

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        state = row.text("evtx_record_state")
        if state and state != "live":
            return None
        record_id = row.number("record_id", "event_record_id")
        if record_id is None:
            return None
        self.records[row.text("source_path") or row.path()].append((int(record_id), row.ref))
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        min_gap = int(self.param("min_gap", 10))
        for source, items in self.records.items():
            items.sort()
            for (previous, _), (current, ref) in zip(items, items[1:]):
                missing = current - previous - 1
                if missing >= min_gap:
                    yield ref, RuleResult(
                        evidence(source=base_name(source), previous_record_id=previous, record_id=current, missing=missing),
                        note=f"앞 레코드와 {missing:,}개 번호 차이",
                    )


@register("eventlog.new_service")
class NewService(Rule):
    """7045/4697 service install whose ImagePath is user-writable, UNC, cmd or PowerShell."""

    selector = EVENTLOG

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if row.event_id() not in {"7045", "4697"}:
            return None
        image = row.text("service_file_name", "service_image_path", "image_path") or row.ev_text("ImagePath", "ServiceFileName")
        if not image:
            return None
        reasons = suspicious_command(image)
        _drive, rest = split_windows_path(image)
        allowed = tuple(str(prefix).casefold().replace("/", "\\") for prefix in self.param("allowed_path_prefixes", []))
        if allowed and rest.startswith(allowed):
            # A vetted vendor folder (Defender platform / definition updates): only its location is excused.
            reasons = [reason for reason in reasons if not reason.startswith("사용자 쓰기 경로")]
        lowered = image.lower()
        if "powershell" in lowered and "인코딩/다운로드 PowerShell" not in reasons:
            reasons.append("PowerShell")
        if "%comspec%" in lowered:
            reasons.append("%COMSPEC%")
        if not reasons:
            return None
        return RuleResult(
            evidence(
                event_id=row.event_id(),
                service_name=row.text("service_name") or row.ev_text("ServiceName"),
                image_path=image,
                reasons=reasons,
                account=row.text("service_account_name") or row.ev_text("AccountName", "ServiceAccount"),
            )
        )


_CHAR_OBFUSCATION = re.compile(r"\[char\]\s*\d+", re.IGNORECASE)


@register("eventlog.encoded_powershell")
class EncodedPowerShell(Rule):
    """4688/Sysmon 1 command line or 4104 script block with -enc/IEX/FromBase64String/[char] obfuscation."""

    selector = EVENTLOG

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        event_id = row.event_id()
        if event_id == "4104":
            text = row.text("script_block_text") or row.ev_text("ScriptBlockText")
        elif event_id == "4688" or (event_id == "1" and is_sysmon(row)):
            text = row.text("command_line") or row.ev_text("CommandLine", "ProcessCommandLine")
        else:
            return None
        if not text:
            return None
        match = ENCODED_POWERSHELL.search(text)
        obfuscation = len(_CHAR_OBFUSCATION.findall(text)) >= int(self.param("min_char_casts", 10))
        if match is None and not obfuscation:
            return None
        return RuleResult(
            evidence(
                event_id=event_id,
                matched=match.group(0).strip() if match else "[char] 난독화",
                command=text,
                process=row.text("process_name", "new_process_name") or row.ev_text("NewProcessName", "Image"),
            )
        )


_TASK_COMMAND = re.compile(r"<Command>(.*?)</Command>(?:\s*<Arguments>(.*?)</Arguments>)?", re.IGNORECASE | re.DOTALL)


@register("eventlog.task_created")
class TaskCreated(Rule):
    """4698/4702 scheduled task whose action runs from a user-writable path or a LOLBin/encoded PowerShell."""

    selector = EVENTLOG

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        event_id = row.event_id()
        if event_id not in {"4698", "4702"}:
            return None
        content = row.ev_text("TaskContent", "TaskContentNew") or row.text("task_content")
        commands = [" ".join(part for part in match if part).strip() for match in _TASK_COMMAND.findall(content)]
        if not commands and row.text("command_line"):
            commands = [row.text("command_line")]
        for command in commands:
            reasons = suspicious_command(command)
            if reasons:
                return RuleResult(
                    evidence(
                        event_id=event_id,
                        task_name=row.text("task_name") or row.ev_text("TaskName"),
                        command=command,
                        reasons=reasons,
                        subject_user_name=row.text("subject_user_name") or row.ev_text("SubjectUserName"),
                    )
                )
        return None


@register("eventlog.account_manipulation")
class AccountManipulation(Rule):
    """4720 followed by a 4732 for the same SID within ``window_minutes``; 4724 reset by another account."""

    selector = EVENTLOG

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.created: list[tuple[dt.datetime, RowRef, str, str]] = []
        self.added: list[tuple[dt.datetime, RowRef, str, str]] = []

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        event_id = row.event_id()
        if event_id not in {"4720", "4732", "4724"} or row.is_duplicate():
            return None
        if event_id == "4724":
            subject = (row.text("subject_user_name") or row.ev_text("SubjectUserName")).lower()
            target = target_user(row).lower()
            if subject and target and subject != target and not subject.endswith("$"):
                return RuleResult(evidence(event_id="4724", subject_user_name=subject, target_user_name=target), note="다른 계정이 암호를 재설정")
            return None
        moment = row.time("timestamp", "time_created")
        if moment is None:
            return None
        if event_id == "4720":
            sid = row.ev_text("TargetSid") or row.text("user_sid")
            self.created.append((moment, row.ref, sid.upper(), target_user(row)))
        else:
            member = (row.ev_text("MemberSid") or "").upper()
            group = row.ev_text("TargetUserName", "TargetSid") or target_user(row)
            self.added.append((moment, row.ref, member, group))
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        window = dt.timedelta(minutes=float(self.param("window_minutes", 60)))
        added_by_sid: dict[str, list[tuple[dt.datetime, RowRef, str]]] = defaultdict(list)
        for moment, ref, member, group in self.added:
            if member:
                added_by_sid[member].append((moment, ref, group))
        for moment, ref, sid, name in self.created:
            for added_at, added_ref, group in added_by_sid.get(sid, ()):
                if moment <= added_at <= moment + window:
                    details = evidence(account=name, sid=sid, created_at=moment, added_at=added_at, group=group)
                    yield ref, RuleResult(details, note="계정 생성 직후 로컬 그룹에 추가")
                    yield added_ref, RuleResult(details, note="생성 직후 계정을 그룹에 추가")
                    break


@register("eventlog.explicit_credentials")
class ExplicitCredentials(Rule):
    """4648 to a remote target server by a process outside ``allowed_processes``."""

    selector = EVENTLOG

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if row.event_id() != "4648":
            return None
        server = row.ev_text("TargetServerName").lower()
        computer = row.text("computer").lower()
        local = {"", "-", "localhost", "127.0.0.1", "::1", computer, computer.split(".")[0]}
        if server in local or server.split(".")[0] in local:
            return None
        process = row.text("process_name") or row.ev_text("ProcessName")
        allowed = {str(name).lower() for name in self.param("allowed_processes", [])}
        if base_name(process) in allowed:
            return None
        return RuleResult(
            evidence(
                target_server=server,
                process=process,
                subject_user_name=row.text("subject_user_name") or row.ev_text("SubjectUserName"),
                target_user_name=target_user(row),
            )
        )


@register("eventlog.off_hours_logon")
class OffHoursLogon(Rule):
    """Interactive/remote 4624 at an hour that is rare for that account (share < ``rare_share``)."""

    selector = EVENTLOG

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.logons: dict[str, list[tuple[int, RowRef, dt.datetime]]] = defaultdict(list)

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if row.event_id() != "4624" or logon_type(row) not in INTERACTIVE_LOGON_TYPES or row.is_duplicate():
            return None
        user = target_user(row)
        if is_service_account(user):
            return None
        moment = row.time("timestamp", "time_created")
        if moment is None:
            return None
        self.logons[user.lower()].append((hour_of(moment, float(self.param("tz_offset_hours", 9))), row.ref, moment))
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        min_events = int(self.param("min_events", 20))
        rare = float(self.param("rare_share", 0.03))
        for user, items in self.logons.items():
            if len(items) < min_events:
                continue
            counts = Counter(hour for hour, _ref, _moment in items)
            for hour, ref, _moment in items:
                share = counts[hour] / len(items)
                if share < rare:
                    yield ref, RuleResult(
                        evidence(account=user, local_hour=hour, hour_share=round(share, 4), account_logons=len(items)),
                        note=f"이 계정 로그온 {len(items)}건 중 {hour}시대 비율 {share:.1%}",
                    )


@register("eventlog.sysmon_injection")
class SysmonInjection(Rule):
    """Sysmon 8 (CreateRemoteThread) / 10 (ProcessAccess to lsass) from an image outside Windows/Program Files."""

    selector = EVENTLOG

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        event_id = row.event_id()
        if event_id not in {"8", "10"} or not is_sysmon(row):
            return None
        source = row.ev_text("SourceImage")
        target = row.ev_text("TargetImage")
        if not source or under_system_dir(source):
            return None
        allowed = {str(name).lower() for name in self.param("allowed_sources", [])}
        if base_name(source) in allowed:
            return None
        if event_id == "10":
            if base_name(target) != "lsass.exe":
                return None
            access = row.ev_text("GrantedAccess").lower()
            masks = {str(mask).lower() for mask in self.param("lsass_access_masks", [])}
            if masks and access not in masks:
                return None
        return RuleResult(
            evidence(event_id=event_id, source_image=source, target_image=target, granted_access=row.ev_text("GrantedAccess"))
        )


@register("eventlog.audit_gap")
class AuditGap(Rule):
    """Security log without any 4688 / PowerShell Operational log without 4104: auditing likely off (absence ≠ non-occurrence)."""

    selector = EVENTLOG

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.first: dict[str, RowRef] = {}
        self.counts: Counter[str] = Counter()
        self.seen: set[tuple[str, str]] = set()

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        channel = "security" if is_security(row) else row.channel()
        if channel not in {"security", POWERSHELL_OPERATIONAL}:
            return None
        self.first.setdefault(channel, row.ref)
        self.counts[channel] += 1
        self.seen.add((channel, row.event_id()))
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        minimum = int(self.param("min_channel_events", 100))
        for channel, expected in (("security", "4688"), (POWERSHELL_OPERATIONAL, "4104")):
            if self.counts[channel] >= minimum and (channel, expected) not in self.seen:
                yield self.first[channel], RuleResult(
                    evidence(channel=channel, channel_events=self.counts[channel], missing_event_id=expected),
                    note=f"{channel} 이벤트 {self.counts[channel]:,}건 중 {expected} 없음: 감사 정책 미설정 가능(부재 ≠ 미발생)",
                )
