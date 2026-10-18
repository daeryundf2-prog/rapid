"""Event-log channel groups of the evidence tree (plan r3-os-depth §3.2 O2, Q-R3-4).

Every ``eventlog`` row falls into exactly one *partition* group by its
``details.channel`` (exact names first, then prefixes, case-insensitive):
보안, 시스템, 응용 프로그램, PowerShell, Windows Defender, 방화벽, 작업 스케줄러,
스토리지, 사용자 PNP, Office Alerts, 원격 데스크톱 (TerminalServices-*), then
기타 채널 (any other channel) and 채널 없음 (inventory/summary rows, records
without a channel). The partition counts therefore sum to the kind's row
total. 서비스(SCM) is a *view* inside 시스템 (System channel rows whose
provider is the Service Control Manager) and is not part of the partition.

The kind output summary records the raw ``channel_counts`` (written by
``core.artifacts``); ``/tree`` turns them into group nodes with the exact
channel names each group matched, which the console sends back as the
server ``channel=`` filter (exact match on ``details.channel``).
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping

EVENTLOG_KIND = "eventlog"
# Kind output summary keys.
CHANNEL_COUNTS_KEY = "channel_counts"
SCM_COUNT_KEY = "channel_service_control_manager_count"
NO_CHANNEL = ""
SCM_PROVIDERS = frozenset({"service control manager", "microsoft-windows-service control manager"})
SCM_GROUP = "services"
OTHER_GROUP = "other"
NONE_GROUP = "none"

# (group id, Korean label, exact channel names, channel-name prefixes); casefolded matching.
CHANNEL_GROUPS: tuple[tuple[str, str, tuple[str, ...], tuple[str, ...]], ...] = (
    ("security", "보안", ("security",), ()),
    ("system", "시스템", ("system",), ()),
    ("application", "응용 프로그램", ("application",), ()),
    (
        "powershell",
        "PowerShell",
        ("windows powershell",),
        ("microsoft-windows-powershell/", "powershellcore/"),
    ),
    ("defender", "Windows Defender", (), ("microsoft-windows-windows defender/",)),
    ("firewall", "방화벽", (), ("microsoft-windows-windows firewall with advanced security/",)),
    ("task-scheduler", "작업 스케줄러", (), ("microsoft-windows-taskscheduler/",)),
    (
        "storage",
        "스토리지",
        (),
        (
            "microsoft-windows-storage-",
            "microsoft-windows-ntfs/",
            "microsoft-windows-storagespaces-",
            "microsoft-windows-partition/",
            "microsoft-windows-storsvc/",
        ),
    ),
    ("user-pnp", "사용자 PNP", (), ("microsoft-windows-userpnp/",)),
    ("office-alerts", "Office Alerts", ("oalerts",), ()),
    (
        "rdp",
        "원격 데스크톱",
        (),
        ("microsoft-windows-terminalservices-", "microsoft-windows-remotedesktopservices-"),
    ),
)
GROUP_LABELS: dict[str, str] = {
    **{group: label for group, label, _exact, _prefixes in CHANNEL_GROUPS},
    SCM_GROUP: "서비스(SCM)",
    OTHER_GROUP: "기타 채널",
    NONE_GROUP: "채널 없음",
}
# Canonical channel of a group (filter value when the run has no row of it).
CANONICAL_CHANNELS: dict[str, tuple[str, ...]] = {
    "security": ("Security",),
    "system": ("System",),
    "application": ("Application",),
    "powershell": ("Microsoft-Windows-PowerShell/Operational", "Windows PowerShell"),
    "defender": ("Microsoft-Windows-Windows Defender/Operational",),
    "firewall": ("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",),
    "task-scheduler": ("Microsoft-Windows-TaskScheduler/Operational",),
    "storage": ("Microsoft-Windows-Ntfs/Operational",),
    "user-pnp": ("Microsoft-Windows-UserPnp/DeviceInstall",),
    "office-alerts": ("OAlerts",),
    "rdp": ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",),
    SCM_GROUP: ("System",),
}


def channel_group(channel: str) -> str:
    """Partition group id of one channel name."""
    folded = channel.strip().casefold()
    if not folded:
        return NONE_GROUP
    for group, _label, exact, prefixes in CHANNEL_GROUPS:
        if folded in exact or folded.startswith(prefixes):
            return group
    return OTHER_GROUP


def row_channel(row: Mapping[str, object]) -> str:
    """``details.channel`` of an artifact row (``""`` when absent)."""
    details = row.get("details")
    value = details.get("channel") if isinstance(details, Mapping) else None
    return value if isinstance(value, str) else ""


def is_scm_row(row: Mapping[str, object]) -> bool:
    details = row.get("details")
    if not isinstance(details, Mapping) or channel_group(row_channel(row)) != "system":
        return False
    provider = details.get("provider_name") or details.get("provider")
    return isinstance(provider, str) and provider.strip().casefold() in SCM_PROVIDERS


class ChannelCounter:
    """Streaming ``channel_counts`` / SCM count of one eventlog kind output."""

    def __init__(self) -> None:
        self.counts: Counter[str] = Counter()
        self.scm = 0

    def observe(self, row: Mapping[str, object]) -> None:
        self.counts[row_channel(row)] += 1
        if is_scm_row(row):
            self.scm += 1

    def summary(self) -> dict[str, object]:
        return {CHANNEL_COUNTS_KEY: dict(sorted(self.counts.items())), SCM_COUNT_KEY: self.scm}


def channel_group_nodes(channel_counts: Mapping[str, object], scm_count: object = None) -> list[dict[str, object]]:
    """Tree entries ``{id, label, count, channels, partition}`` sorted by Korean label.

    ``channels`` are the exact channel names of the run in that group (the
    server ``channel=`` values); a group with no row lists its canonical
    channel so its filter still selects nothing else. ``partition`` is
    False for the 서비스(SCM) view (a subset of 시스템).
    """
    totals: Counter[str] = Counter()
    members: dict[str, list[str]] = {}
    for channel, count in channel_counts.items():
        if not isinstance(count, int) or isinstance(count, bool):
            continue
        group = channel_group(str(channel))
        totals[group] += count
        if group != NONE_GROUP:
            members.setdefault(group, []).append(str(channel))
    nodes: list[dict[str, object]] = []
    for group, label in GROUP_LABELS.items():
        if group == SCM_GROUP:
            count = scm_count if isinstance(scm_count, int) and not isinstance(scm_count, bool) else None
            channels = sorted(members.get("system") or CANONICAL_CHANNELS[SCM_GROUP])
        else:
            count = totals.get(group, 0)
            channels = sorted(members.get(group) or CANONICAL_CHANNELS.get(group, ()))
        node: dict[str, object] = {
            "id": group,
            "label": label,
            "count": count,
            "channels": channels,
            "partition": group != SCM_GROUP,
        }
        if group == SCM_GROUP:
            node["provider"] = "Service Control Manager"
        nodes.append(node)
    return sorted(nodes, key=lambda item: korean_sort_key(str(item["label"])))


def korean_sort_key(label: str) -> tuple[int, str]:
    """Hangul labels first (가나다), then Latin (case-insensitive), like the console's ko collation."""
    first = label[:1]
    hangul = "가" <= first <= "힣"
    return (0 if hangul else 1, label.casefold())
