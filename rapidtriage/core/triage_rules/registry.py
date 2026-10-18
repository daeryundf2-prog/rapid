"""Registry indicators (catalogue: Windows §2)."""

from __future__ import annotations

import re
from collections.abc import Iterator

from .base import (
    PERSISTENCE_MARKERS,
    USER_WRITABLE_MARKERS,
    FlagContext,
    RowRef,
    RowView,
    Rule,
    RuleResult,
    as_list,
    evidence,
    extension,
    register,
    select,
    split_windows_path,
    suspicious_command,
    under_system_dir,
    user_writable_marker,
)

PERSISTENCE = select(types={"registry-persistence-entry", "registry-run-key"})
SERVICE = select(types={"windows-service-config"})
USB_DEVICE = select(types={"windows-usb-device", "registry-usb"})
MOUNTED = select(types={"windows-mounted-device"})


def normalize_serial(value: object) -> str:
    """USBSTOR instance serial without the ``&0`` LUN suffix, upper-cased."""
    text = str(value or "").strip().upper()
    if "&" in text and text.rsplit("&", 1)[-1].isdigit():
        text = text.rsplit("&", 1)[0]
    return text


def removable_or_network(path: str, removable_letters: set[str]) -> str:
    """Why ``path`` points off the system volume: ``"UNC"``, ``"이동식 드라이브 X:"`` or ``""``."""
    drive, _rest = split_windows_path(path)
    if drive == "unc":
        return "UNC"
    if len(drive) == 1 and drive != "c" and (not removable_letters or drive in removable_letters):
        return f"이동식/외부 드라이브 {drive.upper()}:"
    return ""


# Squirrel (Electron) per-user install: ``<LocalAppData>\<app>\<app>.exe`` directly under the app folder.
_SQUIRREL_EXE = re.compile(r"\\(?:appdata\\local|%localappdata%)\\(?!temp\\|tmp\\)[^\\]+\\[^\\]+\.exe$")
_EXE_PREFIX = re.compile(r"^\s*\"?([^\"]*?\.exe)", re.IGNORECASE)


def squirrel_autostart(value_name: str, command: str, prefixes: list[str]) -> bool:
    """A Squirrel-style per-user autostart (``com.squirrel.<app>`` value -> exe directly under ``AppData/Local/<app>``)."""
    if not any(value_name.lower().startswith(str(prefix).lower()) for prefix in prefixes):
        return False
    match = _EXE_PREFIX.match(command)
    if not match:
        return False
    return bool(_SQUIRREL_EXE.search("\\" + split_windows_path(match.group(1))[1]))


def removable_letters(ctx: FlagContext) -> set[str]:
    letters = ctx.shared.get("removable_letters")
    return letters if isinstance(letters, set) else set()


@register("registry.run_user_path")
class RunUserPath(Rule):
    """Run/RunOnce (and other autostart) command in a user-writable path or using encoded PowerShell/LOLBins."""

    selector = PERSISTENCE

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        command = row.text("command", "value_data", "data", "image_path")
        if not command:
            return None
        probe = "\\" + split_windows_path(command.strip('"').split('"')[0])[1]
        if any(str(marker).lower() in probe for marker in self.param("exclude_markers", [])):
            return None
        reasons = suspicious_command(command, PERSISTENCE_MARKERS)
        if not reasons:
            return None
        value_name = row.text("value_name", "name")
        if all(reason.startswith("사용자 쓰기 경로") for reason in reasons) and squirrel_autostart(
            value_name, command, list(self.param("squirrel_value_prefixes", []))
        ):
            return None  # e.g. com.squirrel.slack.slack -> %LOCALAPPDATA%\slack\slack.exe --process-start-args --startup
        return RuleResult(
            evidence(
                key_path=row.text("key_path", "key"),
                value_name=row.text("value_name", "name"),
                command=command,
                category=row.text("persistence_category"),
                reasons=reasons,
            )
        )


@register("registry.service_anomaly")
class ServiceAnomaly(Rule):
    """Service ImagePath in a user-writable path, ``cmd /c``, PowerShell or LOLBin (Start=2 noted)."""

    selector = SERVICE

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        image = row.text("image_path", "image_path_hint")
        if not image:
            return None
        reasons = suspicious_command(image, PERSISTENCE_MARKERS)
        if under_system_dir(image.strip('"')) and "http" not in image.lower():
            reasons = [reason for reason in reasons if not reason.startswith("LOLBin")]  # msiexec /V etc.
        if "powershell" in image.lower() and not any("PowerShell" in reason for reason in reasons):
            reasons.append("PowerShell")
        if not reasons:
            return None
        return RuleResult(
            evidence(
                service_name=row.text("service_name", "name", "key_name"),
                image_path=image,
                start=row.text("start_label", "start_type_label", "start"),
                reasons=reasons,
            )
        )


@register("registry.persistence_lastwrite_window")
class PersistenceLastWrite(Rule):
    """Autostart/service key last written inside the incident window (needs ``incident_start``/``incident_end``)."""

    selector = select(types={"registry-persistence-entry", "registry-run-key", "windows-service-config"})

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if not ctx.has_incident_window:
            return None
        moment = row.time("key_last_written_at", "last_written_at")
        if not ctx.in_incident(moment):
            return None
        return RuleResult(evidence(key_path=row.text("key_path", "key"), key_last_written_at=moment))


@register("registry.usb_serial_cross")
class UsbSerialCross(Rule):
    """USBSTOR device whose serial (or volume GUID) also appears in MountedDevices: device ↔ drive letter link."""

    selector = select(types={"windows-usb-device", "registry-usb", "windows-mounted-device"})

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.devices: list[tuple[RowRef, str, set[str], str]] = []
        self.mounted_serials: dict[str, list[str]] = {}
        self.mounted_guids: dict[str, list[str]] = {}

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if row.type == "windows-mounted-device":
            label = row.text("drive_letter", "mount_name", "value_name")
            serial = normalize_serial(row.get("usb_serial_number"))
            if serial:
                self.mounted_serials.setdefault(serial, []).append(label)
            guid = row.text("volume_guid").lower()
            if guid:
                self.mounted_guids.setdefault(guid, []).append(label)
            return None
        serial = normalize_serial(row.get("serial_number", "serial", "usb_serial_number"))
        guids = {str(item).lower() for item in as_list(row.get("volume_guids", "volume_guid")) if item}
        if serial or guids:
            self.devices.append((row.ref, serial, guids, row.text("friendly_name", "product")))
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        for ref, serial, guids, name in self.devices:
            mounts = list(self.mounted_serials.get(serial, [])) if serial else []
            matched_guids = sorted(guid for guid in guids if guid in self.mounted_guids)
            for guid in matched_guids:
                mounts.extend(self.mounted_guids[guid])
            if mounts:
                yield ref, RuleResult(evidence(device=name, serial=serial, mounted_devices=sorted(set(mounts)), volume_guids=matched_guids))


@register("registry.userassist_path")
class UserAssistPath(Rule):
    """UserAssist program path in Temp/user-writable folders, on UNC or on a non-system drive.

    Shortcuts (``.lnk``) and the Desktop / Public markers are ignored: double-clicking an ordinary
    desktop shortcut is recorded the same way (``ignore_extensions`` / ``ignore_markers``)."""

    selector = select(prefixes=("userassist-",))

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        path = row.text("decoded_name", "executable_path", "display_path", "name")
        if not path:
            return None
        if extension(path) in {str(item).lower().lstrip(".") for item in self.param("ignore_extensions", [])}:
            return None
        ignored = {str(item).lower().strip("\\") for item in self.param("ignore_markers", [])}
        markers = tuple(marker for marker in USER_WRITABLE_MARKERS if marker.strip("\\") not in ignored)
        reasons = [reason for reason in (user_writable_marker(path, markers), removable_or_network(path, removable_letters(ctx))) if reason]
        if not reasons:
            return None
        return RuleResult(evidence(path=path, run_count=row.get("run_counter", "run_count"), reasons=reasons))


@register("registry.shellbag_removable_network")
class ShellbagRemovableNetwork(Rule):
    """ShellBag folder on a UNC share or a non-system (removable) drive."""

    selector = select(prefixes=("shellbag",), kinds={"windows-shellbags", "windows-registry"})

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        candidates = as_list(row.get("shell_path", "folder_path", "shellbag_path_candidates", "path_candidates"))
        letters = removable_letters(ctx)
        for candidate in candidates:
            reason = removable_or_network(str(candidate), letters)
            if reason:
                return RuleResult(evidence(folder=str(candidate), reason=reason, key_path=row.text("key_path", "node_key_path")))
        network = row.text("network_location")
        if network:
            return RuleResult(evidence(folder=network, reason="네트워크 위치"))
        return None


@register("registry.typedpaths_unc")
class TypedPathsUnc(Rule):
    """TypedPaths / RunMRU entry with a UNC path or an administrative share (C$, ADMIN$)."""

    selector = select(types={"registry-user-activity"}, kinds={"windows-registry"})

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        key = row.text("key_path", "key").lower()
        if not key.endswith(("\\typedpaths", "\\runmru")):
            return None
        value = row.text("activity_value", "value_data")
        lowered = value.lower()
        if not (lowered.startswith("\\\\") or "\\c$" in lowered or "admin$" in lowered):
            return None
        return RuleResult(evidence(key_path=row.text("key_path"), value_name=row.text("value_name"), value=value))
