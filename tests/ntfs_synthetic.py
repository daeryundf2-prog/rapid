"""Synthetic $MFT / $UsnJrnl:$J builders for the rapid-ntfs parity test and benchmark.

Everything is generated from code: no real volume or evidence. FILETIMEs use
odd 100 ns ticks so a parser that rounds to microseconds is caught.
"""

from __future__ import annotations

import random
import struct
from dataclasses import dataclass, field

BASE_FILETIME = 133_485_408_000_000_000  # 2024-01-01T00:00:00Z
OUT_OF_RANGE_FILETIME = 0x7FFF_FFFF_FFFF_FFFF
WIN32, DOS, POSIX, WIN32_AND_DOS = 1, 2, 0, 3


def reference(record: int, sequence: int) -> int:
    return (sequence << 48) | record


def ticks(index: int, salt: int = 0) -> int:
    return BASE_FILETIME + index * 10_000_017 + salt * 1_234_567 + 7


def _align8(value: int) -> int:
    return (value + 7) & ~7


def _resident(attribute_type: int, value: bytes, *, attribute_id: int, name: str = "") -> bytes:
    encoded = name.encode("utf-16le")
    value_offset = _align8(24 + len(encoded))
    length = _align8(value_offset + len(value))
    blob = bytearray(length)
    struct.pack_into("<IIBBHHH", blob, 0, attribute_type, length, 0, len(name), 24, 0, attribute_id)
    struct.pack_into("<IHBB", blob, 16, len(value), value_offset, 0, 0)
    blob[24 : 24 + len(encoded)] = encoded
    blob[value_offset : value_offset + len(value)] = value
    return bytes(blob)


def _nonresident(
    attribute_type: int,
    runlist: bytes,
    *,
    attribute_id: int,
    real_size: int,
    name: str = "",
    highest_vcn: int = 0,
) -> bytes:
    encoded = name.encode("utf-16le")
    runlist_offset = _align8(64 + len(encoded))
    length = _align8(runlist_offset + len(runlist))
    blob = bytearray(length)
    struct.pack_into("<IIBBHHH", blob, 0, attribute_type, length, 1, len(name), 64, 0, attribute_id)
    allocated = _align8(real_size) + 4096
    struct.pack_into("<QQHHIQQQ", blob, 16, 0, highest_vcn, runlist_offset, 0, 0, allocated, real_size, real_size)
    blob[64 : 64 + len(encoded)] = encoded
    blob[runlist_offset : runlist_offset + len(runlist)] = runlist
    return bytes(blob)


def standard_information(times: tuple[int, int, int, int], attributes: int = 0x20) -> bytes:
    return struct.pack("<QQQQI", *times, attributes) + bytes(36)


def file_name(name: str, parent: int, times: tuple[int, int, int, int], *, namespace: int = WIN32, size: int = 0) -> bytes:
    encoded = name.encode("utf-16le", errors="surrogatepass")
    return (
        struct.pack("<Q", parent)
        + struct.pack("<QQQQ", *times)
        + struct.pack("<QQII", _align8(size), size, 0x20, 0)
        + struct.pack("<BB", len(encoded) // 2, namespace)
        + encoded
    )


def attribute_list(entries: list[tuple[int, int, int]]) -> bytes:
    blob = bytearray()
    for attribute_type, extension_reference, attribute_id in entries:
        entry = bytearray(32)
        struct.pack_into("<IHBBQQH", entry, 0, attribute_type, 32, 0, 26, 0, extension_reference, attribute_id)
        blob.extend(entry)
    return bytes(blob)


@dataclass
class MftSpec:
    number: int
    sequence: int = 1
    in_use: bool = True
    directory: bool = False
    names: list[tuple[str, int, int]] = field(default_factory=list)  # (name, namespace, parent reference)
    si_times: tuple[int, int, int, int] | None = None
    fn_times: tuple[int, int, int, int] | None = None
    resident_data: bytes | None = None
    nonresident_runlist: bytes | None = None
    nonresident_name: str = ""
    attribute_list_entries: list[tuple[int, int, int]] | None = None
    extra_attribute: bytes | None = None
    header_number: int | None = None
    allocated_size: int | None = None
    usa: bool = True
    corrupt_trailer_sector: int | None = None


def mft_record(spec: MftSpec, *, size: int = 1024) -> bytes:
    """One FILE record with update-sequence fixups applied (sector tails replaced)."""
    record = bytearray(size)
    record[0:4] = b"FILE"
    sectors = size // 512
    first_attribute = _align8(0x30 + 2 * (sectors + 1))
    struct.pack_into("<HH", record, 0x04, 0x30 if spec.usa else 0, sectors + 1 if spec.usa else 0)
    struct.pack_into("<Q", record, 0x08, 0x1000 + spec.number)
    struct.pack_into("<HH", record, 0x10, spec.sequence, max(1, len(spec.names)))
    struct.pack_into("<HH", record, 0x14, first_attribute, (1 if spec.in_use else 0) | (2 if spec.directory else 0))
    struct.pack_into("<I", record, 0x1C, spec.allocated_size if spec.allocated_size is not None else size)
    struct.pack_into("<I", record, 0x2C, spec.number if spec.header_number is None else spec.header_number)
    si_times = spec.si_times or (ticks(spec.number, 1), ticks(spec.number, 2), ticks(spec.number, 3), ticks(spec.number, 4))
    fn_times = spec.fn_times or (ticks(spec.number, 5), ticks(spec.number, 6), ticks(spec.number, 7), ticks(spec.number, 8))
    attributes = [_resident(0x10, standard_information(si_times), attribute_id=0)]
    if spec.attribute_list_entries is not None:
        attributes.append(_resident(0x20, attribute_list(spec.attribute_list_entries), attribute_id=5))
    for index, (name, namespace, parent) in enumerate(spec.names):
        size_hint = len(spec.resident_data or b"")
        attributes.append(
            _resident(0x30, file_name(name, parent, fn_times, namespace=namespace, size=size_hint), attribute_id=1 + index)
        )
    if spec.resident_data is not None:
        attributes.append(_resident(0x80, spec.resident_data, attribute_id=3))
    if spec.nonresident_runlist is not None:
        attributes.append(
            _nonresident(
                0x80,
                spec.nonresident_runlist,
                attribute_id=4,
                real_size=123_457,
                name=spec.nonresident_name,
                highest_vcn=30,
            )
        )
    if spec.extra_attribute is not None:
        attributes.append(spec.extra_attribute)
    offset = first_attribute
    for attribute in attributes:
        record[offset : offset + len(attribute)] = attribute
        offset += len(attribute)
    struct.pack_into("<I", record, offset, 0xFFFFFFFF)
    struct.pack_into("<I", record, 0x18, offset + 8)
    if spec.usa:
        update_number = 0x0100 + (spec.number & 0xFF) + 1
        struct.pack_into("<H", record, 0x30, update_number)
        for sector in range(1, sectors + 1):
            tail = sector * 512 - 2
            record[0x30 + 2 * sector : 0x32 + 2 * sector] = record[tail : tail + 2]
            stamp = update_number ^ 0xFFFF if sector == spec.corrupt_trailer_sector else update_number
            struct.pack_into("<H", record, tail, stamp)
    return bytes(record)


def build_mft(specs: list[MftSpec], *, size: int = 1024) -> bytes:
    by_number = {spec.number: spec for spec in specs}
    return b"".join(
        mft_record(by_number[number], size=size) if number in by_number else bytes(size)
        for number in range(max(by_number) + 1)
    )


RUNLIST_MIXED = bytes([0x21, 0x10, 0x00, 0x01, 0x11, 0x05, 0xF0, 0x01, 0x04, 0x31, 0x02, 0x00, 0x00, 0x80, 0x00])
RUNLIST_NO_TERMINATOR = bytes([0x11, 0x01, 0x02, 0x11, 0x01, 0x03])
RUNLIST_OVERSIZED = bytes([0x91, 0x01, 0x02])


def parity_mft_specs() -> list[MftSpec]:
    root = reference(5, 5)
    users = reference(64, 2)
    return [
        MftSpec(0, names=[("$MFT", WIN32_AND_DOS, root)], nonresident_runlist=RUNLIST_MIXED),
        MftSpec(5, sequence=5, directory=True, names=[(".", WIN32_AND_DOS, root)]),
        MftSpec(64, sequence=2, directory=True, names=[("Users", WIN32_AND_DOS, root)]),
        MftSpec(
            65,
            sequence=7,
            names=[("ALICE~1.TXT", DOS, users), ("alice report.txt", WIN32, users)],
            resident_data=b"hello world",
        ),
        MftSpec(66, sequence=3, in_use=False, names=[("deleted.bin", WIN32, users)], nonresident_runlist=RUNLIST_MIXED),
        MftSpec(67, sequence=9, names=[("trailer.bin", WIN32, users)], corrupt_trailer_sector=2),
        MftSpec(68, names=[("no-usa.bin", WIN32, users)], usa=False),
        MftSpec(69, names=[("header.bin", WIN32, users)], header_number=4242),
        MftSpec(70, names=[("mis-sized.bin", WIN32, users)], allocated_size=4096),
        MftSpec(
            72,
            names=[("times.bin", POSIX, users)],
            si_times=(OUT_OF_RANGE_FILETIME, 0, ticks(72), 1),
            fn_times=(0, 0, 0, 0),
        ),
        MftSpec(
            73,
            names=[("listed.bin", WIN32, users)],
            attribute_list_entries=[(0x80, reference(74, 1), 4), (0x80, reference(9_000, 1), 6), (0x30, reference(73, 2), 1)],
        ),
        MftSpec(74, sequence=1, nonresident_runlist=RUNLIST_NO_TERMINATOR, nonresident_name="stream"),
        MftSpec(75, names=[("FILE-in-content.txt", WIN32, users)], resident_data=b"xxxxFILE" + bytes(48) + b"tail"),
        MftSpec(76, names=[("보고서\ud800.hwp", WIN32, users)], nonresident_runlist=RUNLIST_OVERSIZED),
        MftSpec(77, names=[("bad-attr.bin", WIN32, users)], extra_attribute=struct.pack("<II", 0x40, 8) + bytes(16)),
        MftSpec(78, directory=True, names=[("deep", WIN32, reference(77, 1))]),
        MftSpec(79, resident_data="C:\\Windows\\System32\\cmd.exe), \\\\server\\share\\x.txt;".encode("utf-16le")),
    ]


def rename_volume() -> tuple[bytes, bytes]:
    """PR #33's rename case: one file renamed old.txt -> new.txt under \\records."""
    root = reference(5, 1)
    specs = [
        MftSpec(5, sequence=1, directory=True, names=[(".", WIN32, root)]),
        MftSpec(11, sequence=4, directory=True, names=[("records", WIN32, root)]),
        MftSpec(42, sequence=3, names=[("new.txt", WIN32, reference(11, 4))]),
    ]
    journal = b"".join(
        usn_v2(name, reason, reference(42, 3), reference(11, 4), usn, ticks(usn))
        for usn, (name, reason) in enumerate([("old.txt", 0x1000), ("new.txt", 0x2000), ("other.txt", 0x100)])
    )
    stale_parent = usn_v2("stale.txt", 0x100, reference(43, 1), reference(11, 3), 9, ticks(9))
    return build_mft(specs), journal + stale_parent


def fuzz(blob: bytes, *, seed: int, flips: int) -> bytes:
    rng = random.Random(seed)
    mutated = bytearray(blob)
    for _ in range(flips):
        position = rng.randrange(len(mutated))
        mutated[position] = rng.randrange(256)
    return bytes(mutated)


def usn_v2(name: str, reason: int, frn: int, parent: int, usn: int, filetime: int, *, attributes: int = 0x20) -> bytes:
    encoded = name.encode("utf-16le", errors="surrogatepass")
    length = _align8(60 + len(encoded))
    head = struct.pack("<IHHQQQQIIIIHH", length, 2, 0, frn, parent, usn, filetime, reason, 0, 0, attributes, len(encoded), 60)
    return head + encoded + bytes(length - 60 - len(encoded))


def usn_v3(name: str, reason: int, frn: int, parent: int, usn: int, filetime: int) -> bytes:
    encoded = name.encode("utf-16le")
    length = _align8(76 + len(encoded))
    head = struct.pack("<IHH", length, 3, 0) + frn.to_bytes(16, "little") + parent.to_bytes(16, "little")
    head += struct.pack("<QQIIIIHH", usn, filetime, reason, 2, 7, 0x20, len(encoded), 76)
    return head + encoded + bytes(length - 76 - len(encoded))


def usn_v4(frn: int, parent: int, usn: int, reason: int, extents: list[tuple[int, int]], *, extent_count: int | None = None) -> bytes:
    count = len(extents) if extent_count is None else extent_count
    length = 64 + 16 * len(extents)
    head = struct.pack("<IHH", length, 4, 0) + frn.to_bytes(16, "little") + parent.to_bytes(16, "little")
    head += struct.pack("<QIIIHH", usn, reason, 1, 0, count, 16)
    return head + b"".join(struct.pack("<QQ", offset, size) for offset, size in extents)


def parity_usn_journal() -> tuple[bytes, list[int]]:
    """A journal exercising every record shape; returns the blob and the v2/v3 FILETIMEs in order."""
    users = reference(64, 2)
    alice = reference(65, 7)
    chunks: list[bytes] = [bytes(40)]
    filetimes: list[int] = []

    def add(record: bytes, filetime: int | None = None) -> None:
        chunks.append(record)
        if filetime is not None:
            filetimes.append(filetime)

    for index, (name, reason) in enumerate(
        [
            ("draft.txt", 0x0000_0100),
            ("draft.txt", 0x0000_1000),
            ("alice report.txt", 0x0000_2000),
            ("alice report.txt", 0x8000_2000),
            ("alice report.txt", 0x0000_3000),
            ("gone.tmp", 0x8000_0200),
            ("odd-bits.dat", 0x0040_0008),
            ("empty-reason.dat", 0),
        ]
    ):
        add(usn_v2(name, reason, alice, users, 1000 + index, ticks(index, 9)), ticks(index, 9))
    chunks.append(bytes(4096))
    add(usn_v2("lone\ud800.txt", 0x100, reference(80, 1), users, 2000, ticks(20)), ticks(20))
    odd = bytearray(usn_v2("oddlen.txt", 0x100, reference(81, 1), users, 2001, ticks(21)))
    struct.pack_into("<H", odd, 56, 19)
    add(bytes(odd), ticks(21))
    add(usn_v2("far-future.txt", 0x100, reference(82, 1), users, 2002, OUT_OF_RANGE_FILETIME), OUT_OF_RANGE_FILETIME)
    add(usn_v2("no-time.txt", 0x100, reference(83, 1), users, 2003, 0), 0)
    chunks.append(b"\x01garbage\xff" * 3)
    add(usn_v3("v3-file.txt", 0x2000, (0xABCDEF << 64) | reference(90, 3), (1 << 127) | users, 3000, ticks(30)), ticks(30))
    add(usn_v4(reference(91, 1), users, 4000, 0x0000_0002, [(0, 4096), (8192, 512)]))
    add(usn_v4(reference(92, 1), users, 4001, 0x0000_0001, [(0, 4096)], extent_count=99))
    chunks.append(bytes(13))
    add(usn_v2("tail.txt", 0x100, reference(93, 1), users, 5000, ticks(40)), ticks(40))
    tail = usn_v2("partial.txt", 0x100, reference(94, 1), users, 5001, ticks(41))
    chunks.append(tail[:-8])
    return b"".join(chunks), filetimes


def bench_mft(record_count: int, *, size: int = 1024) -> bytes:
    """``record_count`` FILE records shaped like a populated volume (patched from templates)."""
    users = reference(64, 2)
    templates = [
        mft_record(MftSpec(0, names=[("file-name-template.txt", WIN32, users)], resident_data=b"x" * 40), size=size),
        mft_record(
            MftSpec(0, names=[("LONGNA~1.DOC", DOS, users), ("long document name.docx", WIN32, users)], nonresident_runlist=RUNLIST_MIXED),
            size=size,
        ),
        mft_record(MftSpec(0, directory=True, names=[("Directory Entry", WIN32_AND_DOS, users)]), size=size),
        mft_record(MftSpec(0, in_use=False, names=[("deleted.tmp", WIN32, users)], resident_data=b"temp"), size=size),
    ]
    out = bytearray(size * record_count)
    for number in range(record_count):
        record = bytearray(templates[number % len(templates)])
        struct.pack_into("<I", record, 0x2C, number)
        struct.pack_into("<H", record, 0x10, 1 + number % 31)
        out[number * size : (number + 1) * size] = record
    return bytes(out)


def bench_usn(record_count: int) -> bytes:
    users = reference(64, 2)
    templates = [
        usn_v2(f"document-{index:02d}.docx", reason, reference(100 + index, 1), users, 0, ticks(index))
        for index, reason in enumerate([0x100, 0x1000, 0x2000, 0x8000_0002, 0x8000_0200, 0x8000])
    ]
    out = bytearray()
    for number in range(record_count):
        record = bytearray(templates[number % len(templates)])
        struct.pack_into("<Q", record, 24, number)
        struct.pack_into("<Q", record, 8, reference(100 + number, 1 + number % 7))
        out.extend(record)
    return bytes(out)
