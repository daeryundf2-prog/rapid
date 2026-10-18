"""Synthetic NTFS fixtures for R3 (plan r3-os-depth §3.3, Q-R3-5).

* :func:`mft_record_times` -- one FILE record whose $STANDARD_INFORMATION and
  $FILE_NAME carry *different* times (timestomping shapes);
* :func:`logfile` -- a $LogFile with two RSTR restart pages, RCRD record pages
  (InitializeFileRecordSegment / AddIndexEntryAllocation / DeallocateFileRecordSegment
  with $FILE_NAME redo data) and optional empty / bad-fixup pages.

Generated from the on-disk layouts; no real evidence.
"""

from __future__ import annotations

import datetime as dt
import struct

PAGE = 4096
SEQ_BITS = 44
DATA_OFFSET = 0x40


def filetime(value: str) -> int:
    moment = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    delta = moment - dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


def _fixup(page: bytearray, usa_offset: int, usn: int = 1, *, sector: int = 512) -> bytearray:
    count = len(page) // sector + 1
    struct.pack_into("<HH", page, 4, usa_offset, count)
    struct.pack_into("<H", page, usa_offset, usn)
    for index in range(1, count):
        tail = sector * index - 2
        page[usa_offset + 2 * index : usa_offset + 2 * index + 2] = page[tail : tail + 2]
        struct.pack_into("<H", page, tail, usn)
    return page


def mft_record_times(
    *,
    name: str,
    parent: int,
    si: tuple[str, str, str, str],
    fn: tuple[str, str, str, str],
    in_use: bool = True,
    record_size: int = 1024,
) -> bytes:
    """FILE record; ``si`` / ``fn`` = (created, modified, mft_modified, accessed)."""
    record = bytearray(record_size)
    record[0:4] = b"FILE"
    sectors = record_size // 512
    first_attribute = (0x30 + 2 * (sectors + 1) + 7) // 8 * 8
    struct.pack_into("<H", record, 0x10, 1)
    struct.pack_into("<H", record, 0x12, 1)
    struct.pack_into("<H", record, 0x14, first_attribute)
    struct.pack_into("<H", record, 0x16, 1 if in_use else 0)
    struct.pack_into("<I", record, 0x1C, record_size)
    si_value = struct.pack("<QQQQ", *(filetime(value) for value in si)) + struct.pack("<I", 0x20) + bytes(36)
    offset = first_attribute
    struct.pack_into("<IIBBHHHIHBB", record, offset, 0x10, 24 + len(si_value), 0, 0, 0x18, 0, 0, len(si_value), 0x18, 0, 0)
    record[offset + 24 : offset + 24 + len(si_value)] = si_value
    offset += 24 + len(si_value)
    encoded = name.encode("utf-16le")
    fn_value = (
        struct.pack("<Q", parent | (1 << 48))
        + struct.pack("<QQQQ", *(filetime(value) for value in fn))
        + struct.pack("<QQII", 0, 0, 0x20, 0)
        + struct.pack("<BB", len(name), 1)
        + encoded
    )
    attr_len = (24 + len(fn_value) + 7) // 8 * 8
    struct.pack_into("<IIBBHHHIHBB", record, offset, 0x30, attr_len, 0, 0, 0x18, 0, 1, len(fn_value), 0x18, 0, 0)
    record[offset + 24 : offset + 24 + len(fn_value)] = fn_value
    offset += attr_len
    struct.pack_into("<I", record, offset, 0xFFFFFFFF)
    struct.pack_into("<I", record, 0x18, offset + 8)
    return bytes(_fixup(record, 0x30))


def file_name_value(name: str, *, parent: int, created: str) -> bytes:
    stamp = filetime(created)
    encoded = name.encode("utf-16le")
    return (
        struct.pack("<Q", parent | (1 << 48))
        + struct.pack("<QQQQ", stamp, stamp, stamp, stamp)
        + struct.pack("<QQII", 0, 0, 0x20, 0)
        + struct.pack("<BB", len(name), 1)
        + encoded
    )


def lsn_for(file_offset: int, sequence: int = 3) -> int:
    return (sequence << (64 - SEQ_BITS)) | (file_offset >> 3)


def log_record(
    *,
    lsn: int,
    redo_op: int,
    undo_op: int,
    redo: bytes = b"",
    undo: bytes = b"",
    target_vcn: int = 0,
    cluster_block_offset: int = 0,
    transaction_id: int = 0x18,
    previous_lsn: int = 0,
) -> bytes:
    lcns = 1
    header = 0x20 + 8 * lcns
    redo_offset = header
    undo_offset = (redo_offset + len(redo) + 7) // 8 * 8
    client = bytearray(undo_offset + len(undo))
    struct.pack_into(
        "<HHHHHHHHHHHH",
        client,
        0,
        redo_op,
        undo_op,
        redo_offset,
        len(redo),
        undo_offset,
        len(undo),
        1,  # target attribute (open attribute table index)
        lcns,
        0,
        0,
        cluster_block_offset,
        0,
    )
    struct.pack_into("<QQ", client, 0x18, target_vcn, 0x1234)
    client[redo_offset : redo_offset + len(redo)] = redo
    client[undo_offset : undo_offset + len(undo)] = undo
    lfs = struct.pack("<QQQIIIIH", lsn, previous_lsn, 0, len(client), 0, 1, transaction_id, 0) + bytes(6)
    body = lfs + bytes(client)
    return body + bytes((-len(body)) % 8)


def rstr_page(current_lsn: int) -> bytes:
    page = bytearray(PAGE)
    page[0:4] = b"RSTR"
    struct.pack_into("<QIIHhh", page, 8, 0, PAGE, PAGE, 0x30, 1, 1)
    area = 0x30
    struct.pack_into("<QHHHH", page, area, current_lsn, 1, 0xFFFF, 0, 0)
    struct.pack_into("<IHH", page, area + 0x10, SEQ_BITS, 0x40, 0x40)
    struct.pack_into("<QIHH", page, area + 0x18, 64 * PAGE, 0x40, 0x30, DATA_OFFSET)
    return bytes(_fixup(page, 0x1E))


def rcrd_page(page_offset: int, records: list[bytes]) -> bytes:
    page = bytearray(PAGE)
    page[0:4] = b"RCRD"
    position = DATA_OFFSET
    for record in records:
        page[position : position + len(record)] = record
        position += len(record)
    last_lsn = struct.unpack_from("<Q", records[-1], 0)[0] if records else 0
    struct.pack_into("<QIHHH", page, 8, last_lsn, 0, 1, 1, position)
    struct.pack_into("<Q", page, 0x20, last_lsn)
    return bytes(_fixup(page, 0x28))


def page_records() -> list[list[bytes]]:
    """Records of the three RCRD pages (page index 2, 3, 4 of the file)."""
    pages: list[list[bytes]] = []
    page2 = 2 * PAGE
    pages.append(
        [
            log_record(
                lsn=lsn_for(page2 + DATA_OFFSET),
                redo_op=0x02,  # InitializeFileRecordSegment (file created)
                undo_op=0x00,
                redo=b"FILE" + bytes(60) + file_name_value("secret.docx", parent=5, created="2024-05-01T10:00:00Z"),
                target_vcn=16,
                cluster_block_offset=0,
            )
        ]
    )
    page3 = 3 * PAGE
    entry = struct.pack("<QHHI", 64 | (1 << 48), 0x68, 0x50, 0)
    pages.append(
        [
            log_record(
                lsn=lsn_for(page3 + DATA_OFFSET),
                redo_op=0x0E,  # AddIndexEntryAllocation (name added to the directory)
                undo_op=0x0F,
                redo=entry + file_name_value("secret.docx", parent=5, created="2024-05-01T10:00:00Z"),
                undo=entry + file_name_value("secret.docx", parent=5, created="2024-05-01T10:00:00Z"),
                target_vcn=2,
            )
        ]
    )
    page4 = 4 * PAGE
    first = log_record(
        lsn=lsn_for(page4 + DATA_OFFSET),
        redo_op=0x03,  # DeallocateFileRecordSegment (file deleted)
        undo_op=0x02,
        undo=b"FILE" + bytes(60) + file_name_value("wiped.log", parent=5, created="2024-05-02T08:30:00Z"),
        target_vcn=16,
        cluster_block_offset=2,
    )
    second = log_record(
        lsn=lsn_for(page4 + DATA_OFFSET + len(first)),
        redo_op=0x1B,  # ForgetTransaction
        undo_op=0x00,
        previous_lsn=lsn_for(page4 + DATA_OFFSET),
    )
    pages.append([first, second])
    return pages


def logfile(*, bad_fixup_page: bool = True, empty_page: bool = True) -> bytes:
    """RSTR ×2, RCRD ×3 (4 records), then an 0xFF empty page and a page with a broken fixup."""
    parts = [rstr_page(lsn_for(4 * PAGE)), rstr_page(lsn_for(4 * PAGE))]
    for index, records in enumerate(page_records()):
        parts.append(rcrd_page((2 + index) * PAGE, records))
    if empty_page:
        parts.append(b"\xff" * PAGE)
    if bad_fixup_page:
        broken = bytearray(rcrd_page(6 * PAGE, page_records()[0]))
        broken[1022:1024] = b"\x99\x99"  # sector 1 tail no longer equals the update sequence number
        parts.append(bytes(broken))
    return b"".join(parts)
