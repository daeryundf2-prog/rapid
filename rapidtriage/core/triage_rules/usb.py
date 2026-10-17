"""USB / removable device indicators (catalogue: Windows §7)."""

from __future__ import annotations

import bisect
import datetime as dt
from collections import Counter, defaultdict
from collections.abc import Iterator

from .base import (
    FlagContext,
    RowRef,
    RowView,
    Rule,
    RuleResult,
    evidence,
    parse_time,
    register,
    select,
)
from .lnk import normalize_vsn, volume_serial
from .registry import normalize_serial

USB_DEVICE = select(types={"windows-usb-device", "registry-usb", "usb-setupapi-device-install-candidate"})
PARTITION_CHANNEL = "microsoft-windows-partition/diagnostic"
DRIVER_FRAMEWORKS_CHANNEL = "microsoft-windows-driverframeworks-usermode/operational"
KEYBOARD_CLASS_GUID = "{4d36e96b-e325-11ce-bfc1-08002be10318}"
HID_CLASS_GUID = "{745a17a0-74d3-11d0-b6fe-00a0c90f57da}"


def vbr_serial(vbr_hex: str) -> str:
    """Volume serial number from a volume boot record (Partition/Diagnostic 1006 ``Vbr0``): NTFS, FAT32, exFAT, FAT12/16."""
    try:
        data = bytes.fromhex(vbr_hex.strip().replace(" ", ""))
    except ValueError:
        return ""
    if len(data) < 0x70:
        return ""
    if data[3:11] == b"NTFS    ":
        return normalize_vsn(int.from_bytes(data[0x48:0x4C], "little"))
    if data[3:11] == b"EXFAT   ":
        return normalize_vsn(int.from_bytes(data[0x64:0x68], "little"))
    if data[0x52:0x5A] == b"FAT32   ":
        return normalize_vsn(int.from_bytes(data[0x43:0x47], "little"))
    if data[0x36:0x3B] in {b"FAT12", b"FAT16"}:
        return normalize_vsn(int.from_bytes(data[0x27:0x2B], "little"))
    return ""


def device_serial(row: RowView) -> str:
    return normalize_serial(row.get("serial_number", "serial", "usb_serial_number"))


def is_usbstor(row: RowView) -> bool:
    key = row.text("key_path", "key").lower()
    return "\\usbstor\\" in key or "usbstor" in row.text("device_class_id").lower() or row.text("device_class_id").lower().startswith("disk&")


@register("usb.new_device")
class NewDevice(Rule):
    """USB device first installed/connected inside the incident window (needs ``incident_start``/``incident_end``)."""

    selector = USB_DEVICE

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if not ctx.has_incident_window:
            return None
        moment = row.time("first_install_at", "install_at", "timestamp")
        if not ctx.in_incident(moment):
            return None
        return RuleResult(evidence(device=row.text("friendly_name", "product"), serial=device_serial(row), first_install_at=moment))


GENERIC_SERIALS = frozenset({"", "0", "00000000", "0000000000000000", "000000000000", "123456789", "12345678", "AAAAAAAAAAAA"})


@register("usb.serial_missing")
class SerialMissing(Rule):
    """No usable serial: OS-generated (``&`` at position 2), empty, a generic value, or shared by different VID/PID."""

    selector = USB_DEVICE

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.by_serial: dict[str, list[tuple[RowRef, str]]] = defaultdict(list)

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        serial = device_serial(row)
        name = row.text("friendly_name", "product")
        if row.flag("serial_is_os_generated") is True:
            return RuleResult(evidence(device=name, serial=serial), note="OS가 만든 인스턴스 ID(장치 고유 시리얼 아님)")
        if serial in GENERIC_SERIALS or len(set(serial)) == 1:
            return RuleResult(evidence(device=name, serial=serial), note="시리얼이 없거나 일반값")
        self.by_serial[serial].append((row.ref, f"{row.text('vid')}:{row.text('pid')}"))
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        for serial, items in self.by_serial.items():
            ids = {vid_pid for _ref, vid_pid in items if vid_pid != ":"}
            if len(ids) > 1:
                for ref, vid_pid in items:
                    yield ref, RuleResult(evidence(serial=serial, vid_pid=vid_pid, other_vid_pids=sorted(ids)), note="서로 다른 VID/PID가 같은 시리얼 사용")


@register("usb.mass_storage_activity")
class MassStorageActivity(Rule):
    """USB mass storage connected while ≥ ``min_items`` LNK/ShellBag records were written within ``window_minutes``."""

    selector = select(types={"windows-usb-device", "registry-usb", "recent-shortcut", "shell-shortcut"}, prefixes=("shellbag",))

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.devices: list[tuple[RowRef, str, list[dt.datetime]]] = []
        self.activity: list[dt.datetime] = []

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if row.type in {"windows-usb-device", "registry-usb"}:
            if is_usbstor(row):
                moments = [moment for moment in (parse_time(row.get(key)) for key in ("last_arrival_at", "first_install_at", "install_at")) if moment]
                if moments:
                    self.devices.append((row.ref, row.text("friendly_name", "product"), moments))
            return None
        moment = row.time("modified_at", "key_last_written_at", "last_written_at")
        if moment is not None:
            self.activity.append(moment)
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        if not self.devices or not self.activity:
            return
        window = dt.timedelta(minutes=float(self.param("window_minutes", 60)))
        minimum = int(self.param("min_items", 20))
        self.activity.sort()
        for ref, name, moments in self.devices:
            for moment in moments:
                low = bisect.bisect_left(self.activity, moment - window)
                high = bisect.bisect_right(self.activity, moment + window)
                if high - low >= minimum:
                    yield ref, RuleResult(evidence(device=name, connected_at=moment, nearby_lnk_shellbag=high - low))
                    break


@register("usb.non_storage_hid")
class NonStorageHid(Rule):
    """A keyboard/HID class USB device (BadUSB candidate; inside the incident window when one is set).

    Not flagged: PS/2 / ACPI-enumerated keyboards (not USB; ``exclude_terms`` / ``exclude_enumerators``) and
    a HID installed in the same minute as ≥ ``batch_min_others`` other devices (OS install / driver
    enumeration batch)."""

    selector = select(
        types={"windows-usb-device", "registry-usb", "usb-setupapi-device-install-candidate", "amcache-device-pnp"},
    )

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.installs_per_minute: Counter[dt.datetime] = Counter()
        self.candidates: list[tuple[RowRef, dt.datetime | None, RuleResult]] = []

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        # Amcache InventoryDevicePnp rows carry ``first_install_date`` / ``install_date``.
        moment = row.time("first_install_at", "install_at", "first_install_date", "install_date", "timestamp")
        minute = moment.replace(second=0, microsecond=0) if moment is not None else None
        if minute is not None:
            self.installs_per_minute[minute] += 1
        text = " ".join(
            row.text(key)
            for key in ("device_class_id", "device_type", "class", "device_class", "class_guid", "friendly_name", "description", "driver")
        ).lower()
        if "keyboard" not in text and KEYBOARD_CLASS_GUID not in text and "hid" not in text.split() and HID_CLASS_GUID not in text:
            return None
        if any(str(term).lower() in text for term in self.param("exclude_terms", [])):
            return None
        enumerator = (row.text("enumerator") or row.text("device_instance_id").split("\\", 1)[0]).lower()
        if enumerator and enumerator in {str(item).lower() for item in self.param("exclude_enumerators", [])}:
            return None
        if ctx.has_incident_window and not ctx.in_incident(moment):
            return None
        result = RuleResult(evidence(device=row.text("friendly_name", "description", "product"), first_install_at=moment, class_hint=text[:120]))
        self.candidates.append((row.ref, minute, result))
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        batch = int(self.param("batch_min_others", 3))
        for ref, minute, result in self.candidates:
            if batch > 0 and minute is not None and self.installs_per_minute[minute] - 1 >= batch:
                continue  # installed together with many other devices: OS setup / driver enumeration
            yield ref, result


@register("usb.cross_match")
class CrossMatch(Rule):
    """Volume serial of a USB device (Partition/Diagnostic 1006 VBR) seen in a shortcut's LinkInfo: user ↔ device ↔ file."""

    selector = select(types={"eventlog-event", "recent-shortcut", "shell-shortcut", "windows-usb-device", "registry-usb"})

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.usb_vsns: dict[str, str] = {}
        self.shortcuts: list[tuple[RowRef, str, str]] = []
        self.devices: list[tuple[RowRef, str, str]] = []
        self.serial_vsns: dict[str, set[str]] = defaultdict(set)

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if row.type == "eventlog-event":
            if row.event_id() == "1006" and row.channel() == PARTITION_CHANNEL:
                serial = normalize_serial(row.ev_text("SerialNumber"))
                for name in ("Vbr0", "Vbr1", "Vbr2", "Vbr3"):
                    vsn = vbr_serial(row.ev_text(name))
                    if vsn:
                        self.usb_vsns[vsn] = serial
                        if serial:
                            self.serial_vsns[serial].add(vsn)
            return None
        if row.type in {"windows-usb-device", "registry-usb"}:
            self.devices.append((row.ref, device_serial(row), row.text("friendly_name", "product")))
            return None
        vsn = volume_serial(row)
        if vsn:
            self.shortcuts.append((row.ref, vsn, row.text("target_path")))
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        linked: set[str] = set()
        for ref, vsn, target in self.shortcuts:
            if vsn in self.usb_vsns:
                linked.add(vsn)
                yield ref, RuleResult(evidence(volume_serial=vsn, usb_serial=self.usb_vsns[vsn], target=target))
        for ref, serial, name in self.devices:
            vsns = sorted(self.serial_vsns.get(serial, set()) & linked)
            if vsns:
                yield ref, RuleResult(evidence(device=name, serial=serial, volume_serials=vsns), note="이 장치 볼륨을 가리키는 바로 가기 있음")


@register("usb.logging_disabled")
class LoggingDisabled(Rule):
    """USB devices in the registry but no DriverFrameworks/Partition events: device event logs off (absence ≠ non-occurrence)."""

    selector = select(types={"eventlog-event", "windows-usb-device", "registry-usb"})

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.first_device: RowRef | None = None
        self.device_count = 0
        self.eventlog_rows = 0
        self.device_log_rows = 0

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if row.type == "eventlog-event":
            self.eventlog_rows += 1
            if row.channel() in {PARTITION_CHANNEL, DRIVER_FRAMEWORKS_CHANNEL}:
                self.device_log_rows += 1
            return None
        self.device_count += 1
        if self.first_device is None:
            self.first_device = row.ref
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        if self.first_device is None or self.eventlog_rows < int(self.param("min_eventlog_rows", 100)) or self.device_log_rows:
            return
        yield self.first_device, RuleResult(
            evidence(usb_devices=self.device_count, eventlog_rows=self.eventlog_rows, device_log_rows=0),
            note="DriverFrameworks/Partition 로그가 없어 연결 이력은 레지스트리(최신 값)에만 의존",
        )
