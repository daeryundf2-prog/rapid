"""Offline Unified Log clock and string indexes, scoped to one acquired archive."""
from __future__ import annotations

import datetime as dt
import struct
from bisect import bisect_right
from dataclasses import dataclass, field
from operator import itemgetter

MAX_DESCRIPTORS = 65_536
MAX_CLOCK_RECORDS = 65_536
MAX_STRING_BYTES = 4096
_EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
_START = itemgetter(0)


class SidecarError(ValueError):
    """A malformed or unsupported field at a byte offset in a sidecar."""

    def __init__(self, reason: str, offset: int):
        super().__init__(reason)
        self.offset = offset


def _cstring(data: bytes, start: int, end: int) -> str:
    stop = data.find(b"\0", start, min(end, start + MAX_STRING_BYTES + 1))
    if stop < 0:
        return ""
    try:
        return data[start:stop].decode("utf-8")
    except UnicodeDecodeError:
        return ""


# Virtual start, length, physical start, image path offset. The DSC can contain
# many images, while every UUIDText range belongs to the same image.
_Range = tuple[int, int, int, int]


@dataclass
class _Strings:
    data: bytes
    ranges: list[_Range]
    default_path: str

    def lookup(self, address: int) -> tuple[str, str]:
        pos = bisect_right(self.ranges, address, key=_START) - 1
        if pos >= 0:
            start, size, payload, path = self.ranges[pos]
            if address < start + size:
                text = _cstring(self.data, payload + address - start, payload + size)
                return text, self.default_path or _cstring(self.data, path, len(self.data))
        return "", self.default_path


def _uuidtext(data: bytes, budget: int) -> tuple[_Strings, int]:
    magic, major, minor, count = struct.unpack_from("<4I", data)
    if magic != 0x66778899:
        raise SidecarError("invalid-uuidtext-signature", 0)
    if (major, minor) != (2, 1):
        raise SidecarError("unsupported-uuidtext-version", 4)
    if count > budget:
        raise SidecarError("string-index-limit", 12)
    payload = 16 + count * 8
    if payload > len(data):
        raise SidecarError("truncated-uuidtext-index", 16)
    ranges = []
    for pos in range(16, payload, 8):
        start, size = struct.unpack_from("<II", data, pos)
        if payload + size > len(data):
            raise SidecarError("truncated-uuidtext-range", pos)
        if size:
            ranges.append((start, size, payload, 0))
        payload += size
    path = _cstring(data, payload, len(data))
    if not path:
        raise SidecarError("invalid-uuidtext-image-path", payload)
    return _Strings(data, ranges, path), count


def _dsc(data: bytes, budget: int) -> tuple[_Strings, int]:
    magic, major, minor, count, images = struct.unpack_from("<IHHII", data)
    if magic != 0x64736368:
        raise SidecarError("invalid-dsc-signature", 0)
    if major not in (1, 2) or minor != 0:
        raise SidecarError("unsupported-dsc-version", 4)
    if count + images > budget:
        raise SidecarError("string-index-limit", 8)
    stride, image_stride = (16, 28) if major == 1 else (24, 32)
    images_start = 16 + count * stride
    tables_end = images_start + images * image_stride
    if tables_end > len(data):
        raise SidecarError("truncated-dsc-index", 16)
    paths = []
    for pos in range(images_start, tables_end, image_stride):
        path_pos = pos + image_stride - 4
        path, = struct.unpack_from("<I", data, path_pos)
        if path < tables_end or not _cstring(data, path, len(data)):
            raise SidecarError("invalid-dsc-image-path", path_pos)
        paths.append(path)
    ranges = []
    for pos in range(16, images_start, stride):
        if major == 1:
            image, start, payload, size = struct.unpack_from("<4I", data, pos)
        else:
            start, payload, size, image = struct.unpack_from("<QIIQ", data, pos)
        if image >= images or payload < tables_end or payload + size > len(data):
            raise SidecarError("invalid-dsc-range", pos)
        if size:
            ranges.append((start, size, payload, paths[image]))
    return _Strings(data, ranges, ""), count + images


@dataclass(frozen=True, slots=True)
class _Anchor:
    ticks: int
    wall_ns: int
    source_path: str
    offset: int


@dataclass
class _Boot:
    numerator: int
    denominator: int
    # The boot record dates continuous time zero. It only applies before the
    # first clock record: a record at the same tick may carry a different
    # wall time, and the record is the measured calibration.
    origin: _Anchor
    # Clock adjustments establish new origins. Keep every anchor so that a
    # later correction cannot change the time assigned to an earlier event.
    anchors: dict[int, _Anchor] = field(default_factory=dict)
    ordered_ticks: list[int] | None = None

    def preceding_anchor(self, ticks: int) -> _Anchor:
        if self.ordered_ticks is None:
            self.ordered_ticks = sorted(self.anchors)
        pos = bisect_right(self.ordered_ticks, ticks) - 1
        return self.anchors[self.ordered_ticks[pos]] if pos >= 0 else self.origin

    def timestamp(self, ticks: int) -> str:
        anchor = self.preceding_anchor(ticks)
        ns = anchor.wall_ns + (ticks - anchor.ticks) * self.numerator // self.denominator
        seconds, fraction = divmod(ns, 1_000_000_000)
        try:
            whole = (_EPOCH + dt.timedelta(seconds=seconds)).replace(tzinfo=None)
        except OverflowError:
            return ""
        return f"{whole.isoformat()}.{fraction:09d}Z"


def _key(uuid: str) -> str:
    return uuid.replace("-", "").lower()


class Sidecars:
    """Build once per evidence tree. The caller bounds source files and bytes."""

    def __init__(self):
        self._strings: dict[tuple[str, str], _Strings] = {}
        self._boots: dict[str, _Boot] = {}
        self._descriptor_count = 0
        self._clock_count = 0

    def add_strings(self, kind: str, uuid_hex: str, data: bytes) -> None:
        if len(data) < 16:
            raise SidecarError("truncated-string-header", 0)
        key = (kind, _key(uuid_hex))
        if key in self._strings:
            raise SidecarError("duplicate-string-sidecar", 0)
        remaining = MAX_DESCRIPTORS - self._descriptor_count
        if kind == "uuidtext":
            table, used = _uuidtext(data, remaining)
        elif kind == "dsc":
            table, used = _dsc(data, remaining)
        else:
            raise SidecarError("unknown-string-sidecar", 0)
        table.ranges.sort(key=_START)
        end = 0
        for start, size, payload, _path in table.ranges:
            if start < end:
                raise SidecarError("overlapping-string-ranges", payload)
            end = start + size
        self._strings[key] = table
        self._descriptor_count += used

    def resolve(self, kind: str, uuid_hex: str, address: int) -> tuple[str, str]:
        table = self._strings.get((kind, _key(uuid_hex)))
        return table.lookup(address) if table else ("", "")

    def add_timesync(self, data: bytes, source_path: str = "") -> None:
        """Index complete calibrations, even when a later record is damaged."""
        if not data:
            raise SidecarError("empty-timesync", 0)
        pos = 0
        boot = None
        while pos < len(data):
            if self._clock_count >= MAX_CLOCK_RECORDS:
                raise SidecarError("clock-record-limit", pos)
            tag = data[pos:pos + 4]
            if tag[:2] == b"\xb0\xbb":
                if tag != b"\xb0\xbb\x30\x00" or pos + 48 > len(data):
                    raise SidecarError("invalid-timesync-boot-header", pos)
                uuid = data[pos + 8:pos + 24].hex()
                num, den, wall = struct.unpack_from("<IIq", data, pos + 24)
                if not num or not den:
                    raise SidecarError("invalid-timesync-timebase", pos + 24)
                origin = _Anchor(0, wall, source_path, pos)
                boot = self._boots.get(uuid)
                if boot is None:
                    boot = self._boots[uuid] = _Boot(num, den, origin)
                elif (num, den) != (boot.numerator, boot.denominator):
                    raise SidecarError("conflicting-timesync-timebase", pos + 24)
                elif wall != boot.origin.wall_ns:
                    raise SidecarError("conflicting-timesync-boot-time", pos + 32)
                size = 48
            elif tag == b"Ts\x20\x00" and boot is not None:
                if pos + 32 > len(data):
                    raise SidecarError("truncated-timesync-record", pos)
                ticks, wall = struct.unpack_from("<Qq", data, pos + 8)
                existing = boot.anchors.get(ticks)
                if existing is None:
                    boot.anchors[ticks] = _Anchor(ticks, wall, source_path, pos)
                    boot.ordered_ticks = None
                elif existing.wall_ns != wall:
                    raise SidecarError("conflicting-timesync-anchor", pos)
                size = 32
            else:
                raise SidecarError("invalid-timesync-record", pos)
            self._clock_count += 1
            pos += size

    def wall_time(self, boot_uuid_hex: str, ticks: int) -> str:
        boot = self._boots.get(_key(boot_uuid_hex))
        return boot.timestamp(ticks) if boot else ""

    def clock_source(self, boot_uuid_hex: str, ticks: int) -> tuple[str, int]:
        boot = self._boots.get(_key(boot_uuid_hex))
        anchor = boot.preceding_anchor(ticks) if boot else None
        return (anchor.source_path, anchor.offset) if anchor and anchor.source_path else ("", 0)
