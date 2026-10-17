"""LNK / Jump List indicators (catalogue: Windows §4)."""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterator, Mapping

from .base import (
    FlagContext,
    RowRef,
    RowView,
    Rule,
    RuleResult,
    evidence,
    extension,
    fix_mojibake,
    parse_time,
    register,
    select,
    split_windows_path,
    under_system_dir,
    user_writable_marker,
)
from .registry import removable_letters

SHORTCUT = select(types={"recent-shortcut", "shell-shortcut"}, kinds={"recent-files", "windows-system", "windows-filesystem"})
EXECUTABLE_EXTENSIONS = frozenset({"exe", "scr", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "hta", "msi", "com", "pif", "wsf", "dll", "cpl"})


def _link_info(row: RowView) -> Mapping[str, object]:
    value = row.get("link_info")
    return value if isinstance(value, Mapping) else {}


def _tracker(row: RowView) -> Mapping[str, object]:
    value = row.get("tracker_data")
    return value if isinstance(value, Mapping) else {}


def lnk_target(row: RowView) -> str:
    info = _link_info(row)
    return row.text("target_path", "local_base_path") or str(info.get("full_path") or info.get("local_base_path") or "")


def drive_type(row: RowView) -> str:
    info = _link_info(row)
    value = row.get("drive_type_name", "drive_type") or info.get("drive_type_name") or info.get("drive_type") or ""
    text = str(value).strip().lower()
    # Numeric DriveType codes and the parser's names (``LNK_DRIVE_TYPES``: 4 = "remote").
    return {"2": "removable", "3": "fixed", "4": "network", "5": "cdrom", "remote": "network"}.get(text, text)


def volume_serial(row: RowView) -> str:
    info = _link_info(row)
    value = row.get("volume_serial_number") or info.get("volume_serial_number") or info.get("drive_serial_number")
    return normalize_vsn(value)


def normalize_vsn(value: object) -> str:
    """``1234-ABCD`` / ``0x1234abcd`` / int -> ``1234ABCD`` (``""`` when not a VSN)."""
    if value is None or value == "":
        return ""
    if isinstance(value, int) and not isinstance(value, bool):
        return f"{value & 0xFFFFFFFF:08X}"
    text = str(value).strip().upper().removeprefix("0X").replace("-", "")
    if not text or len(text) > 8 or any(char not in "0123456789ABCDEF" for char in text):
        return ""
    return text.rjust(8, "0")


def machine_id(row: RowView) -> str:
    tracker = _tracker(row)
    value = row.text("tracker_machine_id", "machine_id") or str(tracker.get("machine_id") or "")
    return fix_mojibake(value.strip().strip("\x00")).strip()


@register("lnk.removable_target")
class RemovableTarget(Rule):
    """Shortcut target on a removable drive (LinkInfo DriveType, a known removable letter, or a removable volume serial)."""

    selector = SHORTCUT

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.removable_vsns: set[str] = set()
        self.pending: list[tuple[RowRef, str, str]] = []

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        target = lnk_target(row)
        vsn = volume_serial(row)
        kind = drive_type(row)
        if kind in {"removable", "drive_removable"}:
            if vsn:
                self.removable_vsns.add(vsn)
            return RuleResult(evidence(target=target, drive_type=kind, volume_serial=vsn))
        drive, _rest = split_windows_path(target)
        if len(drive) == 1 and drive != "c" and drive in removable_letters(ctx):
            return RuleResult(evidence(target=target, drive_letter=drive.upper(), reason="MountedDevices 이동식 드라이브 문자"))
        if vsn and kind not in {"network", "drive_remote"}:
            self.pending.append((row.ref, target, vsn))
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        known = self.removable_vsns | set(ctx.shared.get("usb_vsns", {}))
        for ref, target, vsn in self.pending:
            if vsn in known:
                yield ref, RuleResult(evidence(target=target, volume_serial=vsn, reason="이동식 볼륨 시리얼과 일치"))


def share_host_of(path: str) -> str:
    """Casefolded host (first DNS label) of a UNC NetName / path (``""`` when not UNC)."""
    drive, rest = split_windows_path(path)
    return rest.split("\\", 1)[0].split(".")[0] if drive == "unc" else ""


@register("lnk.network_target")
class NetworkTarget(Rule):
    """Shortcut target on a network share (DriveType network, UNC path or LinkInfo NetName).

    A share served by the examined computer itself (NetName host = one of its host names, e.g. the
    loopback ``Users`` share) is not a network access."""

    selector = SHORTCUT

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        target = lnk_target(row)
        info = _link_info(row)
        net = row.text("net_name") or str(info.get("net_name") or info.get("network_share_name") or "")
        drive, _rest = split_windows_path(target)
        share_host = share_host_of(net) or share_host_of(target)
        if share_host and share_host in {name.casefold().split(".")[0] for name in ctx.hostnames if name}:
            return None
        if drive_type(row) in {"network", "drive_remote"} or drive == "unc" or net:
            return RuleResult(evidence(target=target, net_name=net, drive_type=drive_type(row)))
        return None


@register("lnk.target_missing")
class TargetMissing(Rule):
    """Shortcut target on the system volume absent from the file listing although its folder was listed."""

    selector = SHORTCUT

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        target = lnk_target(row)
        if not target or ctx.file_missing(target) is not True:
            return None
        return RuleResult(evidence(target=target, target_accessed_at=row.text("target_accessed_at")))


@register("lnk.user_path_exec")
class UserPathExec(Rule):
    """Shortcut to an executable/script in Temp, Downloads, AppData or Public."""

    selector = SHORTCUT

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        target = lnk_target(row)
        if extension(target) not in EXECUTABLE_EXTENSIONS:
            return None
        marker = user_writable_marker(target, ("\\temp\\", "\\tmp\\", "\\downloads\\", "\\appdata\\", "\\users\\public\\"))
        if not marker:
            return None
        return RuleResult(evidence(target=target, marker=marker, arguments=row.text("command_line_arguments", "arguments")))


@register("lnk.foreign_machine")
class ForeignMachine(Rule):
    """Tracker MachineID (NetBIOS name) differs from every host name of this evidence.

    Targets under the Windows directory are skipped: stock OS shortcuts (Windows PowerShell in the
    Start menu …) carry the MachineID of the Microsoft build machine."""

    selector = SHORTCUT

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.machines: list[tuple[RowRef, str, str]] = []

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        machine = machine_id(row)
        target = lnk_target(row)
        if machine and not under_system_dir(target):
            self.machines.append((row.ref, machine, target))
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        hosts = {name.casefold() for name in ctx.hostnames if name}
        if not hosts:
            return  # host name unknown: nothing to compare against
        for ref, machine, target in self.machines:
            if machine.casefold() not in hosts:
                yield ref, RuleResult(evidence(machine_id=machine, host_names=sorted(ctx.hostnames), target=target))


@register("lnk.timestamp_anomaly")
class TimestampAnomaly(Rule):
    """Target created after the shortcut file was last written, or LinkInfo target without any target time."""

    selector = SHORTCUT

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        created = parse_time(row.get("target_created_at"))
        modified = parse_time(row.get("target_modified_at"))
        accessed = parse_time(row.get("target_accessed_at"))
        link_written = parse_time(row.get("modified_at"))
        tolerance = dt.timedelta(minutes=float(self.param("tolerance_minutes", 1)))
        if created is not None and link_written is not None and created > link_written + tolerance:
            return RuleResult(evidence(target_created_at=created, shortcut_modified_at=link_written, target=lnk_target(row)), note="대상 생성 시각이 바로 가기 기록 시각보다 늦음")
        has_link_info = bool(_link_info(row).get("local_base_path"))
        if has_link_info and created is None and modified is None and accessed is None:
            return RuleResult(evidence(target=lnk_target(row)), note="대상 시각 3종이 모두 0(비어 있음)")
        return None
