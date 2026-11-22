"""Active EVENTLOGRECORDs in the pre-Vista circular log format."""

from __future__ import annotations

import datetime as dt
import mmap
import struct
from collections.abc import Iterator

from ...core.filetime import plausibility

HEADER_SIZE = 48
RECORD_HEADER_SIZE = 56
EOF_MAGIC = struct.pack("<5I", 40, 0x11111111, 0x22222222, 0x33333333, 0x44444444)
MAX_RECORD_SIZE = 1024 * 1024
MAX_DIRTY_SCAN = 64 * 1024 * 1024


class EvtFormatError(ValueError):
    """Reason the active record walk could not finish."""


def _ring_bytes(blob: mmap.mmap | bytes, offset: int, size: int) -> bytes:
    tail = blob[offset : offset + size]
    return tail + blob[HEADER_SIZE : HEADER_SIZE + size - len(tail)]


def _bounds(blob: mmap.mmap | bytes) -> tuple[int, int, int, int]:
    if len(blob) < HEADER_SIZE + 40 or len(blob) % 4 or (
        blob[:16] != struct.pack("<I4sII", HEADER_SIZE, b"LfLe", 1, 1)
        or struct.unpack_from("<I", blob, 44)[0] != HEADER_SIZE
    ):
        raise EvtFormatError("invalid-file-header")

    def eof_at(offset: int) -> tuple[int, int, int, int] | None:
        if not HEADER_SIZE <= offset < len(blob) or offset % 4:
            return None
        marker = _ring_bytes(blob, offset, 40)
        if not marker.startswith(EOF_MAGIC) or marker[-4:] != struct.pack("<I", 40):
            return None
        start, end, following, oldest = struct.unpack_from("<4I", marker, 20)
        if end != offset or not HEADER_SIZE <= start < len(blob) or start % 4:
            return None
        return start, end, following, oldest

    header_bounds = struct.unpack_from("<4I", blob, 16)
    dirty = struct.unpack_from("<I", blob, 36)[0] & 1
    if not dirty:
        footer = eof_at(header_bounds[1])
        # A fresh XP log uses zero as the header's oldest record number,
        # while its empty EOF uses one. Both offsets must agree on emptiness.
        if header_bounds == (HEADER_SIZE, HEADER_SIZE, 1, 0) and footer == (HEADER_SIZE, HEADER_SIZE, 1, 1):
            return footer
        if footer != header_bounds:
            raise EvtFormatError("header-eof-disagreement")
        return header_bounds

    # An unflushed header may still point to the original empty log. Accept
    # one self-locating EOF only. Multiple surviving markers are ambiguous.
    if len(blob) > MAX_DIRTY_SCAN:
        raise EvtFormatError("dirty-header-scan-limit")
    found = None
    offset = HEADER_SIZE
    while (offset := blob.find(EOF_MAGIC, offset)) >= 0:
        candidate = eof_at(offset)
        if candidate is not None:
            if found is not None:
                raise EvtFormatError("ambiguous-dirty-eof")
            found = candidate
        offset += len(EOF_MAGIC)
    # The signature itself may cross the ring boundary.
    for offset in range(max(HEADER_SIZE, len(blob) - 16), len(blob), 4):
        candidate = eof_at(offset)
        if candidate is not None:
            if found is not None:
                raise EvtFormatError("ambiguous-dirty-eof")
            found = candidate
    if found is None:
        raise EvtFormatError("missing-dirty-eof")
    return found


def _strings(record: bytes, offset: int, end: int, count: int) -> list[str]:
    if offset % 2:
        raise EvtFormatError("unaligned-string")
    result = []
    for _ in range(count):
        terminator = offset
        while terminator + 2 <= end and record[terminator : terminator + 2] != b"\0\0":
            terminator += 2
        if terminator + 2 > end:
            raise EvtFormatError("unterminated-string")
        try:
            result.append(record[offset:terminator].decode("utf-16-le"))
        except UnicodeDecodeError as exc:
            raise EvtFormatError("invalid-utf16") from exc
        offset = terminator + 2
    return result


def _decode(record: bytes) -> dict[str, object]:
    number, created, written, event = struct.unpack_from("<4I", record, 8)
    event_type, count, category = struct.unpack_from("<3H", record, 24)
    strings, sid_len, sid, data_len, data = struct.unpack_from("<5I", record, 36)
    end = len(record) - 4
    # Offsets for omitted fields can contain arbitrary values.
    next_field = end
    if data_len:
        if data < RECORD_HEADER_SIZE or data + data_len > end:
            raise EvtFormatError("invalid-data-range")
        next_field = data
    insertions = []
    if count:
        if not RECORD_HEADER_SIZE <= strings < next_field:
            raise EvtFormatError("invalid-strings-range")
        insertions = _strings(record, strings, next_field, count)
        next_field = strings
    if sid_len:
        if sid < RECORD_HEADER_SIZE or sid + sid_len > next_field:
            raise EvtFormatError("invalid-sid-range")
        next_field = sid
    source, computer = _strings(record, RECORD_HEADER_SIZE, next_field, 2)
    generated = dt.datetime.fromtimestamp(created, dt.timezone.utc)
    timestamp = generated.isoformat()
    time_status = plausibility(generated)
    return {
        "record_id": str(number),
        "event_id": str(event & 0xFFFF),
        "event_id_qualifiers": event >> 16,
        "evt_event_type": event_type,
        "evt_event_category": category,
        "event_created_at": timestamp,
        "timestamp": timestamp,
        "timestamp_status": {"before-min": "out-of-range-before-1980", "future": "out-of-range-future"}.get(
            time_status, time_status
        ),
        "evt_time_written": dt.datetime.fromtimestamp(written, dt.timezone.utc).isoformat(),
        "provider_name": source,
        "computer": computer,
        "data": {f"Insertion{i}": s for i, s in enumerate(insertions, 1)},
    }


def iter_evt_records(blob: mmap.mmap | bytes) -> Iterator[dict[str, object]]:
    start, end, following, expected = _bounds(blob)
    offset = start
    span = len(blob) - HEADER_SIZE
    remaining = (end - offset) % span
    if remaining > span - 40:
        raise EvtFormatError("record-range-overlaps-eof")
    while remaining:
        tail = len(blob) - offset
        if tail < RECORD_HEADER_SIZE:
            if tail > remaining or blob[offset:] != struct.pack("<I", 0x27) * (tail // 4):
                raise EvtFormatError("invalid-wrap-padding")
            remaining -= tail
            offset = HEADER_SIZE
            continue
        size, magic, number = struct.unpack_from("<I4sI", blob, offset)
        if magic != b"LfLe" or size % 4 or not RECORD_HEADER_SIZE + 4 <= size <= min(remaining, MAX_RECORD_SIZE):
            raise EvtFormatError("invalid-record-header")
        record = _ring_bytes(blob, offset, size)
        if struct.unpack_from("<I", record, size - 4)[0] != size or number != expected:
            raise EvtFormatError("invalid-record-trailer-or-number")
        yield {**_decode(record), "evt_record_offset": offset, "evt_record_size": size}
        offset = HEADER_SIZE + (offset - HEADER_SIZE + size) % span
        remaining -= size
        expected = (expected + 1) & 0xFFFFFFFF
    if expected != following and not (expected == 0 and following == 1 and start == end == HEADER_SIZE):
        raise EvtFormatError("record-count-disagreement")
