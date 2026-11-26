"""Linux login accounting, using the LSB x86 ABI shared by i386 and x86-64."""

from __future__ import annotations

import datetime as dt
import errno
import hashlib
import ipaddress
import os
import re
import struct
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

from ..core.files import path_is_within
from ..core.models import ArtifactRecord

PROVIDER = "linux-system-artifacts"
SUMMARY = "linux-login-accounting-summary"
UTMP_SIZE = 384
LASTLOG_SIZE = 292
MAX_RECORDS_READ = 100_000
MAX_LOGIN_ROWS = 10_000
MAX_PASSWD_BYTES = 4 * 1024 * 1024
TYPES = ("EMPTY", "RUN_LVL", "BOOT_TIME", "NEW_TIME", "OLD_TIME",
         "INIT_PROCESS", "LOGIN_PROCESS", "USER_PROCESS", "DEAD_PROCESS", "ACCOUNTING")
# Rotations: numbered (logrotate default) and dated (dateext). Compressed copies are disclosed, not read.
ROTATED_LOG = re.compile(r"(wtmp|btmp)(\.[0-9]{1,4}|-[0-9]{8})?(\.(?:gz|bz2|xz|zst|lz4|Z))?")
MAX_ROTATED_FILES = 64


def _passwd_names(root: Path) -> dict[int, str]:
    path = root / "etc/passwd"
    if not path_is_within(path, root) or not path.is_file():
        return {}
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_PASSWD_BYTES + 1)
    except OSError:
        return {}
    if len(data) > MAX_PASSWD_BYTES:
        data = data[:MAX_PASSWD_BYTES].rpartition(b"\n")[0]
    names = {}
    for line in data.splitlines():
        fields = line.split(b":")
        if len(fields) == 7 and fields[2].isdigit() and len(fields[2]) <= 10:
            uid = int(fields[2])
            name = fields[0].decode("utf-8", "replace")
            names[uid] = name if names.get(uid, name) == name else ""
    return names


def _slot_ranges(handle: BinaryIO, slots: int, width: int, sparse: bool) -> Iterator[range]:
    """Visit records touching an allocated extent, including records straddling its edges."""
    index = 0
    if sparse and hasattr(os, "SEEK_DATA") and hasattr(os, "SEEK_HOLE"):
        while index < slots:
            try:
                data = handle.seek(index * width, os.SEEK_DATA)
                hole = handle.seek(data, os.SEEK_HOLE)
            except OSError as exc:
                if exc.errno == errno.ENXIO:  # the remaining bytes are a hole
                    return
                if exc.errno not in {errno.EINVAL, errno.ENOTSUP, errno.ENOSYS}:
                    raise
                break
            start = max(index, data // width)
            stop = min(slots, (hole + width - 1) // width)
            if stop <= start:
                break
            yield range(start, stop)
            index = stop
    if index < slots:
        yield range(index, slots)


def _string(field: bytes) -> str:
    return field.partition(b"\0")[0].decode("utf-8", "replace")


def _timestamp(seconds: int, usec: int) -> str:
    # All supported seconds are signed 32-bit. Adding to the epoch also handles
    # pre-1970 values on platforms with a restricted fromtimestamp() range.
    epoch = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
    return (epoch + dt.timedelta(seconds=seconds, microseconds=usec)).isoformat()


def _address(raw: bytes) -> str:
    """``ut_addr_v6``: IPv4 in the first word (network order) and zeros after it, or IPv6."""
    if not any(raw):
        return ""
    if not any(raw[4:]):
        return str(ipaddress.IPv4Address(raw[:4]))
    return str(ipaddress.IPv6Address(raw))


def _utmp(data: bytes) -> dict[str, object] | None:
    kind, pid = struct.unpack_from("<h2xi", data)
    termination, exit_code, session, seconds, usec = struct.unpack_from("<hhiii", data, 332)
    if not 0 < kind < len(TYPES) or not 0 <= usec < 1_000_000:
        return None
    return {
        "user": _string(data[44:76]), "tty": _string(data[8:40]), "host": _string(data[76:332]),
        "id": _string(data[40:44]), "address": _address(data[348:364]),
        "exit_termination": termination, "exit_status": exit_code,
        "uid": None, "pid": pid, "type": kind, "type_name": TYPES[kind], "session": session,
        "timestamp_sec": seconds, "timestamp_usec": usec, "timestamp": _timestamp(seconds, usec),
    }


def _lastlog(data: bytes, uid: int, names: dict[int, str]) -> dict[str, object] | None:
    seconds, = struct.unpack_from("<i", data)
    if seconds == 0:
        return None
    return {
        "user": names.get(uid, ""), "tty": _string(data[4:36]), "host": _string(data[36:292]),
        "id": "", "address": "", "exit_termination": None, "exit_status": None,
        "uid": uid, "pid": None, "type": None, "type_name": "", "session": None,
        "timestamp_sec": seconds, "timestamp_usec": None, "timestamp": _timestamp(seconds, 0),
    }


def _alignment_score(handle: BinaryIO, size: int, width: int, lastlog: bool) -> tuple[int, int, int]:
    """Check a bounded sample on each candidate boundary, skipping sparse holes."""
    total = size // width
    indices: set[int] = set()
    for slots in _slot_ranges(handle, total, width, lastlog):
        indices.update(slots[:64 - len(indices)])
        if len(indices) == 64:
            break
    indices.update(range(max(0, total - 64), total))
    valid = invalid = 0
    for index in sorted(indices):
        handle.seek(index * width)
        data = handle.read(width)
        if len(data) != width or not any(data):
            continue
        if lastlog:
            stamp_width = width - 288
            sec = int.from_bytes(data[:stamp_width], "little", signed=True)
            line = _string(data[stamp_width:stamp_width + 32])
            plausible = sec != 0 and abs(sec) < 2**32 and bool(line) and line.isprintable()
        else:
            kind = int.from_bytes(data[:2], "little", signed=True)
            if width == UTMP_SIZE:
                usec = struct.unpack_from("<i", data, 344)[0]
            else:
                usec = struct.unpack_from("<q", data, 352)[0]
            plausible = 0 < kind < len(TYPES) and 0 <= usec < 1_000_000
        if plausible:
            valid += 1
        else:
            invalid += 1
    # With equally many recognizable records, prefer the shorter partial tail.
    # Otherwise a damaged final slot on the right boundaries can be mistaken for
    # almost an entire record of trailing bytes on the wrong boundaries.
    return valid, -(size % width), -invalid


def _parse_file(path: Path, kind: str, names: dict[int, str]) -> Iterator[ArtifactRecord]:
    lastlog = kind == "lastlog"
    width = LASTLOG_SIZE if lastlog else UTMP_SIZE
    alternate = 296 if lastlog else 400
    base = {
        "parser": "linux-login-accounting", "parser_version": "1", "reportability": "triage",
        "log_kind": kind, "source_path": str(path), "layout": f"glibc-le-{width}",
    }
    examined = emitted = damaged = truncated = tail = 0
    size = 0
    capped = False
    status = "parsed"
    try:
        with path.open("rb", buffering=0) as handle:
            size = os.fstat(handle.fileno()).st_size
            slots, tail = divmod(size, width)
            if size >= alternate and (tail or size % alternate == 0) and (
                _alignment_score(handle, size, width, lastlog)
                <= _alignment_score(handle, size, alternate, lastlog)
            ):
                # A known incompatible stride (or two equally plausible strides).
                # Do not assign shifted timestamps, paths or UIDs.
                status = base["layout"] = "unknown-layout"
                base["candidate_record_size"] = alternate
                slots = 0
                tail = size % alternate
            truncated = int(bool(tail))
            for indices in _slot_ranges(handle, slots, width, lastlog):
                handle.seek(indices.start * width)
                for index in indices:
                    if examined >= MAX_RECORDS_READ or emitted >= MAX_LOGIN_ROWS:
                        capped = True
                        break
                    data = handle.read(width)
                    if len(data) < width:
                        truncated += 1
                        break
                    examined += 1
                    if not any(data):
                        continue
                    fields = _lastlog(data, index, names) if lastlog else _utmp(data)
                    if fields is None:
                        damaged += 1
                        continue
                    emitted += 1
                    yield ArtifactRecord(PROVIDER, f"linux-{kind}", str(path), True, {
                        **base, **fields, "coverage_status": "parsed", "timestamp_timezone": "UTC",
                        "source_index": index, "source_offset": index * width, "source_length": width,
                        "length": width, "record_sha256": hashlib.sha256(data).hexdigest(),
                    })
                if capped:
                    break
    except OSError as exc:
        status = "read-error"
        base["read_errno"] = exc.errno
    if status == "parsed" and (damaged or truncated or capped):
        status = "partial"
        if not emitted and not capped:
            base["layout"] = "unknown-layout"
    yield ArtifactRecord(PROVIDER, SUMMARY, str(path), True, {
        **base, "coverage_status": status, "file_size": size, "records_examined": examined,
        "rows_emitted": emitted, "damaged_records": damaged, "truncated_records": truncated,
        "trailing_bytes": tail, "capped": capped, "row_cap": MAX_LOGIN_ROWS,
        "scan_record_cap": MAX_RECORDS_READ,
    })


def _unread_summary(path: Path, kind: str, layout: str, status: str) -> ArtifactRecord:
    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    return ArtifactRecord(PROVIDER, SUMMARY, str(path), True, {
        "parser": "linux-login-accounting", "parser_version": "1", "reportability": "triage",
        "log_kind": kind, "source_path": str(path), "layout": layout,
        "coverage_status": status, "file_size": size, "records_examined": 0,
        "rows_emitted": 0, "damaged_records": 0, "truncated_records": 0, "trailing_bytes": 0,
        "capped": status == "skipped-file-cap", "row_cap": MAX_LOGIN_ROWS, "scan_record_cap": MAX_RECORDS_READ,
    })


def _log_candidates(root: Path) -> Iterator[tuple[Path, str, str]]:
    """``(path, kind, status)``: an empty status is read; any other names why the file is only disclosed."""
    yield root / "run/utmp", "utmp", ""
    yield root / "var/run/utmp", "utmp", ""
    logs = root / "var/log"
    try:
        with os.scandir(logs) as entries:
            matches = [match for entry in entries if (match := ROTATED_LOG.fullmatch(entry.name))]
    except OSError:
        matches = []
    files = {"wtmp": 0, "btmp": 0}
    for match in sorted(matches, key=lambda match: (match[1] != "wtmp", len(match[0]), match[0])):
        kind = match[1]
        files[kind] += 1
        if files[kind] > MAX_ROTATED_FILES + 1:  # the live file plus its rotations
            yield logs / match[0], kind, "skipped-file-cap"
        elif match[3]:
            yield logs / match[0], kind, "unsupported-compression"
        else:
            yield logs / match[0], kind, ""
    yield logs / "lastlog", "lastlog", ""


def collect_login_accounting(root: Path) -> Iterator[ArtifactRecord]:
    seen: set[Path] = set()
    for candidate, kind, status in _log_candidates(root):
        if not path_is_within(candidate, root) or not candidate.is_file():
            continue
        path = candidate.resolve()
        if path in seen:  # commonly var/run is a symlink to run
            continue
        seen.add(path)
        if status:
            yield _unread_summary(path, kind, "compressed" if status == "unsupported-compression" else "", status)
        else:
            yield from _parse_file(path, kind, _passwd_names(root) if kind == "lastlog" else {})
