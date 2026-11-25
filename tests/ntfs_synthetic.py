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


# --- Adversarial generators (seeded): structurally plausible records with hostile fields. ---

_LAST_FILETIME = 2_650_467_743_999_999_990  # 9999-12-31T23:59:59.999999, the last ISO-representable tick
_EDGE_FILETIMES = (1, 9, 10, _LAST_FILETIME, _LAST_FILETIME + 1, _LAST_FILETIME + 9, OUT_OF_RANGE_FILETIME, 2**64 - 1)


def _random_filetime(rng: random.Random) -> int:
    roll = rng.random()
    if roll < 0.1:
        return 0
    if roll < 0.2:
        return rng.getrandbits(64)
    if roll < 0.25:
        return rng.choice(_EDGE_FILETIMES)
    return rng.randrange(1, _LAST_FILETIME)


def _random_utf16(rng: random.Random, units: int | None = None) -> bytes:
    """UTF-16LE with printable ASCII, Hangul, lone surrogates, surrogate pairs and arbitrary units."""
    out: list[int] = []
    for _ in range(rng.randrange(0, 20) if units is None else units):
        roll = rng.random()
        if roll < 0.6:
            out.append(rng.randrange(32, 127))
        elif roll < 0.7:
            out.append(rng.choice([0xD800, 0xDBFF, 0xDC00, 0xDFFF]))
        elif roll < 0.8:
            out.append(rng.randrange(0xAC00, 0xD7A4))
        elif roll < 0.85:
            out += [0xD83D, 0xDE00]
        else:
            out.append(rng.randrange(0x10000))
    return b"".join(struct.pack("<H", unit) for unit in out)


def _random_runlist(rng: random.Random) -> bytes:
    if rng.random() < 0.3:
        return rng.randbytes(rng.randrange(0, 40))
    out = bytearray()
    for _ in range(rng.randrange(0, 80)):
        length_size = rng.choice([1, 1, 2, 3, 4, 8, 0, 9])
        delta_size = rng.choice([0, 1, 2, 3, 8, 9])
        out.append((delta_size << 4) | length_size)
        out += rng.randbytes(length_size + delta_size)
    if rng.random() < 0.7:
        out.append(0)
    return bytes(out)


def _random_resident_value(rng: random.Random, attribute_type: int) -> bytes:
    if attribute_type == 0x10:
        value = struct.pack("<QQQQI", *(_random_filetime(rng) for _ in range(4)), rng.getrandbits(32)) + bytes(rng.choice([0, 0, 12, 36]))
        return value[: rng.choice([len(value), len(value), 35, 36, 20, 0])]
    if attribute_type == 0x30:
        name = _random_utf16(rng)
        value = struct.pack("<QQQQQQQII", rng.getrandbits(64), *(_random_filetime(rng) for _ in range(4)), rng.getrandbits(64), rng.getrandbits(64), rng.getrandbits(32), 0)
        name_length = rng.choice([len(name) // 2, len(name) // 2, rng.getrandbits(8)])
        value += struct.pack("<BB", name_length, rng.choice([0, 1, 2, 3, rng.getrandbits(8)])) + name
        return value[: rng.randrange(0, len(value) + 1)] if rng.random() < 0.1 else value
    if attribute_type == 0x20:
        value = bytearray()
        for _ in range(rng.randrange(0, 8)):
            name = _random_utf16(rng, rng.choice([0, 2, 5]))
            entry = bytearray(max(32, 26 + len(name)))
            struct.pack_into(
                "<IHBBQQH",
                entry,
                0,
                rng.choice([0x80, 0x30, 0x10, 0, rng.getrandbits(32)]),
                rng.choice([32, 32, 26, 40, 0, 20, rng.getrandbits(16)]),
                len(name) // 2 if rng.random() < 0.8 else rng.getrandbits(8),
                rng.choice([26, 26, 0, rng.getrandbits(8)]),
                rng.getrandbits(64),
                rng.getrandbits(64),
                rng.getrandbits(16),
            )
            entry[26 : 26 + len(name)] = name
            value += entry
        return bytes(value)
    if rng.random() < 0.2:  # a resident $DATA / other value holding UTF-16 path text
        return _random_utf16(rng, 30) + "C:\\Users\\x\\file.txt".encode("utf-16le")
    return rng.randbytes(rng.randrange(0, 64))


def _random_attribute(rng: random.Random) -> bytes:
    attribute_type = rng.choice([0x10, 0x10, 0x20, 0x30, 0x30, 0x40, 0x80, 0x80, 0x90, 0xA0, 0x100, rng.getrandbits(32), 0xFFFFFFFF])
    name = _random_utf16(rng, rng.choice([0, 0, 0, 1, 3, 6]))  # a named $DATA is an ADS
    if rng.random() < 0.3:
        runlist = _random_runlist(rng)
        runlist_offset = _align8(64 + len(name)) if rng.random() < 0.9 else rng.randrange(0, 600)
        length = _align8(max(runlist_offset, 64 + len(name)) + len(runlist))
        blob = bytearray(max(length, 72))
        struct.pack_into("<IIBBHHH", blob, 0, attribute_type, length, 1, len(name) // 2, 64, rng.getrandbits(16), rng.getrandbits(16))
        struct.pack_into("<QQHHIQQQ", blob, 16, rng.getrandbits(64), rng.getrandbits(64), runlist_offset, rng.getrandbits(16), 0, rng.getrandbits(64), rng.getrandbits(64), rng.getrandbits(64))
        blob[64 : 64 + len(name)] = name
        if runlist_offset < len(blob):
            blob[runlist_offset : runlist_offset + len(runlist)] = runlist[: len(blob) - runlist_offset]
    else:
        value = _random_resident_value(rng, attribute_type)
        value_offset = _align8(24 + len(name))
        length = _align8(value_offset + len(value))
        blob = bytearray(max(length, 24))
        declared_length = rng.getrandbits(32) if rng.random() < 0.1 else len(value)
        declared_offset = rng.getrandbits(16) if rng.random() < 0.05 else value_offset
        struct.pack_into("<IIBBHHH", blob, 0, attribute_type, length, 0, len(name) // 2, 24, rng.getrandbits(16), rng.getrandbits(16))
        struct.pack_into("<IHBB", blob, 16, declared_length, declared_offset, rng.getrandbits(8), 0)
        blob[24 : 24 + len(name)] = name
        blob[value_offset : value_offset + len(value)] = value
    if rng.random() < 0.05:
        struct.pack_into("<I", blob, 4, rng.choice([0, 8, 23, 24, len(blob) + 8, rng.getrandbits(32)]))
    if rng.random() < 0.03:
        blob[9] = rng.getrandbits(8)
        struct.pack_into("<H", blob, 10, rng.getrandbits(16))
    return bytes(blob)


def _adversarial_mft_record(rng: random.Random, size: int, number: int) -> bytes:
    """A FILE record with hostile header, update-sequence, attribute and slack fields."""
    record = bytearray(size)
    record[0:4] = b"FILE"
    sectors = size // 512
    usa_offset = rng.choice([0x30, 0x30, 0x30, 0x28, 0, rng.getrandbits(16), size - 2])
    usa_count = rng.choice([sectors + 1] * 4 + [0, 1, sectors, sectors + 2, rng.getrandbits(16)])
    first = rng.choice([_align8(0x30 + 2 * (sectors + 1))] * 5 + [0, 0x30, 0x3A, size, size + 8, rng.getrandbits(16)])
    struct.pack_into("<HHQ", record, 0x04, usa_offset, usa_count, rng.getrandbits(64))
    struct.pack_into("<HHHH", record, 0x10, rng.getrandbits(16), rng.getrandbits(4), first, rng.choice([0, 1, 2, 3, rng.getrandbits(16)]))
    struct.pack_into("<I", record, 0x1C, rng.choice([size] * 6 + [1024, 2048, 4096, 0, 47, 48, 4097, rng.getrandbits(32)]))
    struct.pack_into("<Q", record, 0x20, rng.choice([0, 0, rng.getrandbits(64)]))
    struct.pack_into("<I", record, 0x2C, rng.choice([number] * 4 + [number + 1, 0, rng.getrandbits(32)]))
    offset = first if 0x30 <= first < size else _align8(0x30 + 2 * (sectors + 1))
    for _ in range(rng.randrange(0, 9)):
        attribute = _random_attribute(rng)
        if offset + len(attribute) > size:
            break
        record[offset : offset + len(attribute)] = attribute
        offset += len(attribute)
    if offset + 8 <= size and rng.random() < 0.85:
        struct.pack_into("<I", record, offset, 0xFFFFFFFF)
        offset += 8
    struct.pack_into("<I", record, 0x18, rng.choice([offset] * 5 + [0, size, size + 1, first, rng.getrandbits(32)]))
    if rng.random() < 0.15:  # slack past the used size: stale UTF-16 path text and a stray FILE magic
        tail = _random_utf16(rng, 20) + "C:\\Users\\x\\slack.txt".encode("utf-16le") + b"FILE" + bytes(60)
        position = rng.randrange(min(offset, size - 1), size)
        record[position : position + len(tail)] = tail[: size - position]
    if 0 < usa_offset and usa_offset + 2 <= size and rng.random() < 0.9:
        stamp = rng.getrandbits(16)
        struct.pack_into("<H", record, usa_offset, stamp)
        for sector in range(1, sectors + 1):
            trailer = sector * 512 - 2
            if usa_offset + 2 * sector + 2 <= size:
                record[usa_offset + 2 * sector : usa_offset + 2 * sector + 2] = record[trailer : trailer + 2]
            if rng.random() < 0.95:  # else: a torn sector (fixup trailer mismatch)
                struct.pack_into("<H", record, trailer, stamp)
    return bytes(record[:size])


def adversarial_mft(seed: int) -> bytes:
    """A $MFT blob of hostile records, zero/garbage slots, mixed strides, clipping and byte flips."""
    rng = random.Random(seed)
    size = rng.choice([1024, 1024, 4096, 2048])
    out = bytearray()
    for _ in range(rng.randrange(1, 10)):
        roll = rng.random()
        if roll < 0.1:
            out += bytes(size)
        elif roll < 0.15:
            out += rng.randbytes(rng.randrange(0, 300))
        elif roll < 0.2:
            out += _adversarial_mft_record(rng, rng.choice([1024, 2048, 4096]), len(out) // size)
        else:
            out += _adversarial_mft_record(rng, size, len(out) // size)
    if rng.random() < 0.3:
        out = out[: rng.randrange(0, len(out) + 1)]
    if rng.random() < 0.3 and out:
        for _ in range(rng.randrange(1, 40)):
            out[rng.randrange(len(out))] = rng.getrandbits(8)
    if rng.random() < 0.1:
        out += b"FILE" + rng.randbytes(rng.randrange(0, 60))
    return bytes(out)


def _adversarial_usn_record(rng: random.Random) -> bytes:
    major = rng.choice([2, 2, 2, 3, 3, 4, 4, 1, 5, 0])
    if major == 4:
        count = rng.choice([0, 1, 2, 3, 64, 65, 100, rng.getrandbits(16)])
        extent_size = rng.choice([16, 16, 16, 24, 15, 0, rng.getrandbits(16)])
        extents = rng.randbytes(16 * min(count, rng.choice([count, 2, 70]), 80))
        record = bytearray(64 + len(extents))
        length = rng.choice([len(record)] * 4 + [60, 63, 64, rng.randrange(60, 70000)])
        struct.pack_into("<IHH", record, 0, length, 4, rng.getrandbits(16))
        record[8:40] = rng.randbytes(32)
        reason = rng.choice([0, 0x100, 0x200, 0x80000000, 0x3000, rng.getrandbits(32)])
        struct.pack_into("<QIIIHH", record, 40, rng.getrandbits(64), reason, rng.getrandbits(4), rng.getrandbits(32), count, extent_size)
        record[64:] = extents
        return bytes(record)
    name = _random_utf16(rng)
    minimum = 76 if major == 3 else 60
    name_length = rng.choice([len(name)] * 6 + [0, len(name) + 1, 1, rng.getrandbits(16)])
    name_offset = rng.choice([minimum] * 6 + [minimum + 1, minimum - 2, 0, rng.getrandbits(16)])
    length = rng.choice([_align8(minimum + len(name))] * 6 + [minimum + len(name), 59, 65536, 65537, rng.getrandbits(32)])
    reason = rng.choice([0x100, 0x200, 0x1000, 0x2000, 0x3000, 0x80000200, 0, 0x00400008, rng.getrandbits(32)])
    record = bytearray(_align8(minimum + len(name)))
    fields = (_random_filetime(rng), reason, rng.getrandbits(5), rng.getrandbits(32), rng.getrandbits(32), name_length, name_offset)
    if major == 3:
        struct.pack_into("<IHH", record, 0, length, 3, rng.getrandbits(16))
        record[8:40] = rng.randbytes(32)
        struct.pack_into("<QQIIIIHH", record, 40, rng.getrandbits(64), *fields)
    else:
        struct.pack_into("<IHHQQQ", record, 0, length, major, rng.getrandbits(16), rng.getrandbits(64), rng.getrandbits(64), rng.getrandbits(64))
        struct.pack_into("<QIIIIHH", record, 32, *fields)
    record[minimum : minimum + len(name)] = name
    return bytes(record)


def adversarial_usn(seed: int) -> tuple[bytes, dict[str, object]]:
    """A journal of hostile v2/v3/v4 records, zero gaps, garbage and byte flips, plus a scan window."""
    rng = random.Random(seed)
    out = bytearray()
    for _ in range(rng.randrange(1, 25)):
        roll = rng.random()
        if roll < 0.2:
            out += bytes(rng.choice([1, 2, 3, 4, 5, 7, 8, 13, 60, 61, 512, 4096]))
        elif roll < 0.27:
            out += rng.randbytes(rng.randrange(1, 30))
        elif roll < 0.3:
            out += b"\x00\x00\x00" + bytes([rng.getrandbits(8)])
        else:
            out += _adversarial_usn_record(rng)
    if rng.random() < 0.3 and out:
        out = out[: rng.randrange(len(out))]
    if rng.random() < 0.3 and out:
        for _ in range(rng.randrange(1, 20)):
            out[rng.randrange(len(out))] = rng.getrandbits(8)
    window: dict[str, object] = {}
    if rng.random() < 0.4:
        window["record_limit"] = rng.choice([-3, -1, 0, 1, 2, 3, 5000, 10**6])
    if rng.random() < 0.4:
        window["start_offset"] = rng.choice([-10, 0, 1, 7, rng.randrange(0, len(out) + 20)])
    if rng.random() < 0.4:
        window["max_scan_bytes"] = rng.choice([None, -5, 0, 59, 60, 61, rng.randrange(0, len(out) + 20)])
    return bytes(out), window
