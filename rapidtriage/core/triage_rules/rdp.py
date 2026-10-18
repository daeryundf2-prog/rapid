"""RDP / remote access indicators (catalogue: Windows §1-b)."""

from __future__ import annotations

import datetime as dt
from collections import defaultdict
from collections.abc import Iterator

from .base import (
    EVENTLOG,
    FlagContext,
    RowRef,
    RowView,
    Rule,
    RuleResult,
    clean_ip,
    evidence,
    is_public_ip,
    register,
    select,
)
from .eventlog import logon_ip, logon_type, target_user

RCM_CHANNEL = "microsoft-windows-terminalservices-remoteconnectionmanager/operational"
LSM_CHANNEL = "microsoft-windows-terminalservices-localsessionmanager/operational"
RDPCORE_CHANNEL = "microsoft-windows-remotedesktopservices-rdpcorets/operational"
CLIENT_CHANNEL = "microsoft-windows-terminalservices-rdpclient/operational"


def _user_part(value: str) -> str:
    return value.replace("/", "\\").rsplit("\\", 1)[-1].strip().lower()


def rdp_ip(row: RowView) -> str:
    """Client address of an RDP event (1149 Param3, 21/24/25 Address, 131 ClientIP, 4778 ClientAddress)."""
    return clean_ip(
        row.ev_text("Param3", "ClientIP", "Address", "ClientAddress", "IpAddress") or row.text("source_ip", "ip_address")
    )


def rdp_user(row: RowView) -> str:
    return _user_part(row.ev_text("Param1", "User", "AccountName", "TargetUserName") or row.text("target_user_name", "user_name"))


@register("rdp.external_ip")
class RdpExternalAddress(Rule):
    """1149 (RemoteConnectionManager) / 131 (RdpCoreTS) from a public address."""

    selector = EVENTLOG

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        event_id = row.event_id()
        channel = row.channel()
        if not ((event_id == "1149" and channel in {RCM_CHANNEL, ""}) or (event_id == "131" and channel in {RDPCORE_CHANNEL, ""})):
            return None
        ip = rdp_ip(row)
        if not is_public_ip(ip):
            return None
        return RuleResult(evidence(event_id=event_id, channel=channel, client_ip=ip, user=rdp_user(row)))


@register("rdp.pairing_mismatch")
class PairingMismatch(Rule):
    """1149 (network authentication) without a session 21 for the user within ``window_seconds``, or 21 without 1149."""

    selector = EVENTLOG

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.auth: list[tuple[dt.datetime, RowRef, str, str]] = []
        self.sessions: list[tuple[dt.datetime, RowRef, str, str]] = []

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        event_id = row.event_id()
        channel = row.channel()
        if event_id == "1149" and channel == RCM_CHANNEL:
            bucket = self.auth
        elif event_id == "21" and channel == LSM_CHANNEL:
            ip = rdp_ip(row)
            if not ip:
                return None  # console (LOCAL) session: no network authentication expected
            bucket = self.sessions
        else:
            return None
        moment = row.time("timestamp", "time_created")
        if moment is not None and not row.is_duplicate():
            bucket.append((moment, row.ref, rdp_user(row), rdp_ip(row)))
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        if not self.auth or not self.sessions:
            return  # one side's log is missing entirely: not a pairing question
        window = dt.timedelta(seconds=float(self.param("window_seconds", 120)))
        sessions_by_user: dict[str, list[dt.datetime]] = defaultdict(list)
        auth_by_user: dict[str, list[dt.datetime]] = defaultdict(list)
        for moment, _ref, user, _ip in self.sessions:
            sessions_by_user[user].append(moment)
        for moment, _ref, user, _ip in self.auth:
            auth_by_user[user].append(moment)
        for moment, ref, user, ip in self.auth:
            if not any(abs(other - moment) <= window for other in sessions_by_user.get(user, ())):
                yield ref, RuleResult(evidence(event_id="1149", user=user, client_ip=ip), note="인증(1149) 뒤 세션 로그온(21)이 없음")
        for moment, ref, user, ip in self.sessions:
            if not any(abs(other - moment) <= window for other in auth_by_user.get(user, ())):
                yield ref, RuleResult(evidence(event_id="21", user=user, client_ip=ip), note="세션 로그온(21) 앞에 인증(1149)이 없음")


@register("rdp.session_hijack")
class SessionHijack(Rule):
    """4778 / LSM 25 reconnect from an address other than the account's preceding RDP logon."""

    selector = EVENTLOG

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.logons: dict[str, list[tuple[dt.datetime, str]]] = defaultdict(list)
        self.reconnects: list[tuple[dt.datetime, RowRef, str, str, str]] = []

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        event_id = row.event_id()
        channel = row.channel()
        moment = row.time("timestamp", "time_created")
        if moment is None or row.is_duplicate():
            return None
        if (event_id == "4624" and logon_type(row) == "10") or (event_id == "1149" and channel == RCM_CHANNEL):
            ip = logon_ip(row) if event_id == "4624" else rdp_ip(row)
            user = _user_part(target_user(row)) if event_id == "4624" else rdp_user(row)
            if ip and user:
                self.logons[user].append((moment, ip))
        elif event_id == "4778" or (event_id == "25" and channel == LSM_CHANNEL):
            ip = rdp_ip(row)
            user = rdp_user(row)
            if ip and user:
                self.reconnects.append((moment, row.ref, user, ip, event_id))
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        for items in self.logons.values():
            items.sort()
        for moment, ref, user, ip, event_id in self.reconnects:
            previous = [item for item in self.logons.get(user, ()) if item[0] <= moment]
            if previous and previous[-1][1] != ip:
                yield ref, RuleResult(
                    evidence(event_id=event_id, user=user, reconnect_ip=ip, previous_logon_ip=previous[-1][1], previous_logon_at=previous[-1][0]),
                    note="재연결 주소가 직전 RDP 로그온 주소와 다름",
                )


@register("rdp.outbound")
class OutboundRdp(Rule):
    """Source-side RDPClient 1024 with a 4648 (explicit credentials) within ``window_minutes``."""

    selector = EVENTLOG

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.clients: list[tuple[dt.datetime, RowRef, str]] = []
        self.explicit: list[tuple[dt.datetime, str]] = []

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        event_id = row.event_id()
        moment = row.time("timestamp", "time_created")
        if moment is None:
            return None
        if event_id == "1024" and row.channel() == CLIENT_CHANNEL:
            self.clients.append((moment, row.ref, row.ev_text("Value", "ServerName") or row.text("destination_hostname")))
        elif event_id == "4648":
            self.explicit.append((moment, row.ev_text("TargetServerName")))
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        window = dt.timedelta(minutes=float(self.param("window_minutes", 5)))
        for moment, ref, server in self.clients:
            match = next(((at, target) for at, target in self.explicit if abs(at - moment) <= window), None)
            if match is not None:
                yield ref, RuleResult(evidence(rdp_target=server, explicit_credential_at=match[0], explicit_target_server=match[1]))


@register("rdp.enabled")
class RdpEnabled(Rule):
    """fDenyTSConnections set to 0 (Sysmon 13 registry value set, or a registry value row)."""

    selector = select(kinds={"eventlog", "windows-registry"})

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if row.source_kind == "eventlog":
            if row.event_id() != "13":
                return None
            target = row.ev_text("TargetObject")
            data = row.ev_text("Details")
        else:
            target = row.text("name", "value_name")
            if target.lower() != "fdenytsconnections":
                return None
            data = row.text("activity_value", "value_data", "decoded_data_preview", "value_data_inline")
        if not target.lower().endswith("fdenytsconnections"):
            return None
        normalized = data.lower().replace(" ", "")
        if normalized not in {"0", "dword(0x00000000)", "0x00000000", "0x0"}:
            return None
        return RuleResult(evidence(target_object=target, value=data))


@register("rdp.multi_host")
class MultiHost(Rule):
    """One account with type-10 logons on ≥ ``min_hosts`` computers within ``window_minutes``."""

    selector = EVENTLOG

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.logons: dict[str, list[tuple[dt.datetime, RowRef, str]]] = defaultdict(list)

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if row.event_id() != "4624" or logon_type(row) != "10" or row.is_duplicate():
            return None
        moment = row.time("timestamp", "time_created")
        computer = row.text("computer").lower()
        user = _user_part(target_user(row))
        if moment is not None and computer and user:
            self.logons[user].append((moment, row.ref, computer))
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        window = dt.timedelta(minutes=float(self.param("window_minutes", 60)))
        minimum = int(self.param("min_hosts", 3))
        for user, items in self.logons.items():
            items.sort(key=lambda item: item[0])
            flagged: set[int] = set()
            start = 0
            for end in range(len(items)):
                while items[end][0] - items[start][0] > window:
                    start += 1
                hosts = {item[2] for item in items[start : end + 1]}
                if len(hosts) >= minimum:
                    flagged.update(range(start, end + 1))
            for position in sorted(flagged):
                moment, ref, computer = items[position]
                yield ref, RuleResult(evidence(account=user, computer=computer, window_minutes=int(window.total_seconds() // 60)))
