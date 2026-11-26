"""Deterministic synthetic NTFS volume/disk images for the native extraction engines.

Pure Python (no mkntfs, no real evidence): an MBR disk with one NTFS partition whose
volume holds system records 0-23, a directory tree with small (resident-index) and large
(``$INDEX_ALLOCATION`` B-tree) directories, and files covering every data layout the
extraction walk meets on real volumes:

- resident, contiguous, fragmented (forward and backward run deltas), sparse,
  LZNT1-compressed and ``$ATTRIBUTE_LIST``-split (two ``$DATA`` extents in extension
  records) default streams; empty files; streams whose runs end past the volume;
- alternate data streams (resident and non-resident), Win32+DOS name pairs, hard links,
  POSIX-namespace case twins, names ``_safe_component`` rewrites, Korean names;
- deleted file/directory records (content still on disk), a stale index entry that points
  at a deleted record, a record with a broken fixup, reserved FILE records with no
  attributes, and non-FILE slots in the MFT;
- a junction (absolute mount point) under ``Users`` and the Windows paths the priority
  pass recovers first.

Used by ``tests/test_e01_extract_rust_parity.py`` and ``scripts/e01-extract-benchmark.py``.
"""

from __future__ import annotations

import random
import struct
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

CLUSTER = 4096
RECORD = 1024
INDEX_BUFFER = 4096
SECTOR = 512
PARTITION_SECTOR = 2048
FIRST_USER_RECORD = 24
SPARE_RECORDS = 64

NS_POSIX, NS_WIN32, NS_DOS, NS_WIN32_AND_DOS = 0, 1, 2, 3
FILE_NAME_INDEX_PRESENT = 0x10000000
BASE_TIME = 132_500_000_000_000_000  # 2020-11 in FILETIME units (100 ns)


def _align8(value: int) -> int:
    return (value + 7) & ~7


def _signed(value: int) -> bytes:
    size = 1
    while not -(1 << (8 * size - 1)) <= value < (1 << (8 * size - 1)):
        size += 1
    return value.to_bytes(size, "little", signed=True)


def encode_runs(runs: Sequence[tuple[int | None, int]]) -> bytes:
    out = bytearray()
    previous = 0
    for lcn, count in runs:
        length = _signed(count)
        if lcn is None:
            out += bytes([len(length)]) + length
            continue
        delta = _signed(lcn - previous)
        previous = lcn
        out += bytes([(len(delta) << 4) | len(length)]) + length + delta
    out.append(0)
    return bytes(out)


def apply_usa(buf: bytearray, usa_offset: int, usn: int = 1) -> None:
    usn_bytes = usn.to_bytes(2, "little")
    for index in range(len(buf) // SECTOR):
        end = (index + 1) * SECTOR
        slot = usa_offset + 2 + 2 * index
        buf[slot : slot + 2] = buf[end - 2 : end]
        buf[end - 2 : end] = usn_bytes
    buf[usa_offset : usa_offset + 2] = usn_bytes


def resident_attr(type_code: int, value: bytes, *, name: str = "", instance: int = 0, indexed: bool = False) -> bytes:
    name_bytes = name.encode("utf-16-le")
    value_offset = _align8(0x18 + len(name_bytes))
    length = _align8(value_offset + len(value))
    attr = bytearray(length)
    struct.pack_into("<IIBBHHH", attr, 0, type_code, length, 0, len(name), 0x18, 0, instance)
    struct.pack_into("<IHBB", attr, 0x10, len(value), value_offset, 1 if indexed else 0, 0)
    attr[0x18 : 0x18 + len(name_bytes)] = name_bytes
    attr[value_offset : value_offset + len(value)] = value
    return bytes(attr)


def nonresident_attr(
    type_code: int,
    runs: Sequence[tuple[int | None, int]],
    size: int,
    *,
    name: str = "",
    instance: int = 0,
    lowest_vcn: int = 0,
    allocated: int | None = None,
    compression_unit: int = 0,
    flags: int = 0,
) -> bytes:
    name_bytes = name.encode("utf-16-le")
    name_offset = 0x48 if compression_unit else 0x40
    mapping = encode_runs(runs)
    mapping_offset = _align8(name_offset + len(name_bytes))
    length = _align8(mapping_offset + len(mapping))
    clusters = sum(count for _lcn, count in runs)
    attr = bytearray(length)
    struct.pack_into("<IIBBHHH", attr, 0, type_code, length, 1, len(name), name_offset, flags, instance)
    struct.pack_into("<QQHB", attr, 0x10, lowest_vcn, lowest_vcn + clusters - 1, mapping_offset, compression_unit)
    allocated = clusters * CLUSTER if allocated is None else allocated
    struct.pack_into("<qqq", attr, 0x28, allocated, size, size)
    attr[name_offset : name_offset + len(name_bytes)] = name_bytes
    attr[mapping_offset : mapping_offset + len(mapping)] = mapping
    return bytes(attr)


def standard_information(times: tuple[int, int, int, int], attributes: int = 0x20) -> bytes:
    return struct.pack("<qqqqIIIIIIQQ", *times, attributes, 0, 0, 0, 0, 0, 0, 0)


def file_name_value(
    parent: int, name: str, namespace: int, times: tuple[int, int, int, int], *, size: int = 0, attributes: int = 0x20
) -> bytes:
    encoded = name.encode("utf-16-le")
    return struct.pack("<Qqqqqqq", parent, *times, _align_cluster(size), size) + struct.pack(
        "<IIBB", attributes, 0, len(encoded) // 2, namespace
    ) + encoded


def _align_cluster(size: int) -> int:
    return (size + CLUSTER - 1) // CLUSTER * CLUSTER


def file_ref(record: int, sequence: int = 1) -> int:
    return record | (sequence << 48)


def mft_record(
    number: int, attrs: list[bytes], *, flags: int, sequence: int = 1, base: int = 0, links: int = 1
) -> bytes:
    record = bytearray(RECORD)
    record[0:4] = b"FILE"
    position = 0x38
    for attr in attrs:
        record[position : position + len(attr)] = attr
        position += len(attr)
    if position + 8 > RECORD:
        raise ValueError(f"record {number} overflows ({position} bytes)")
    struct.pack_into("<I", record, position, 0xFFFFFFFF)
    used = position + 8
    struct.pack_into("<HHQHHHHII", record, 4, 0x30, 3, 0, sequence, links, 0x38, flags, used, RECORD)
    struct.pack_into("<QHHI", record, 0x20, base, len(attrs), 0, number)
    apply_usa(record, 0x30)
    return bytes(record)


def lznt1_compress(data: bytes) -> bytes:
    """Greedy LZNT1 (4 KiB chunks); a chunk that does not shrink is stored raw."""
    out = bytearray()
    for start in range(0, len(data), 4096):
        chunk = data[start : start + 4096]
        body = bytearray()
        pos = 0
        while pos < len(chunk):
            flags = 0
            group = bytearray()
            for bit in range(8):
                if pos >= len(chunk):
                    break
                best_len, best_disp = 0, 0
                if pos:
                    disp_bits = max(4, (pos - 1).bit_length())
                    max_len = (1 << (16 - disp_bits)) + 2
                    for disp in range(1, min(pos, 1 << disp_bits, 64) + 1):
                        length = 0
                        while length < max_len and pos + length < len(chunk) and chunk[pos + length - disp] == chunk[pos + length]:
                            length += 1
                        if length > best_len:
                            best_len, best_disp = length, disp
                if best_len >= 3:
                    disp_bits = max(4, (pos - 1).bit_length())
                    token = ((best_disp - 1) << (16 - disp_bits)) | (best_len - 3)
                    group += struct.pack("<H", token)
                    flags |= 1 << bit
                    pos += best_len
                else:
                    group.append(chunk[pos])
                    pos += 1
            body.append(flags)
            body += group
        if len(body) < len(chunk):
            out += struct.pack("<H", 0xB000 | (len(body) + 2 - 3)) + body
        else:
            out += struct.pack("<H", 0x3000 | (len(chunk) + 2 - 3)) + chunk.ljust(4096, b"\x00")
    return bytes(out)


@dataclass
class Link:
    parent: int
    name: str
    namespace: int = NS_WIN32


@dataclass
class Entry:
    record: int
    is_dir: bool
    links: list[Link]
    times: tuple[int, int, int, int]
    data: bytes = b""
    layout: str = "auto"
    ads: dict[str, bytes] = field(default_factory=dict)
    deleted: bool = False
    sequence: int = 1
    indexed: bool = True


class VolumeBuilder:
    def __init__(self, seed: int = 1):
        self.rng = random.Random(seed)
        self.volume = bytearray(CLUSTER * 16)
        self.next_cluster = 16
        self.entries: dict[int, Entry] = {}
        self.next_record = FIRST_USER_RECORD
        self.extra_records: dict[int, bytes] = {}
        self.stale_index: list[tuple[int, Link]] = []
        self.broken_fixup: set[int] = set()
        self._children: dict[int, list[tuple[str, int, bytes]]] | None = None
        self.root = 5
        self.entries[5] = Entry(5, True, [Link(5, ".", NS_WIN32_AND_DOS)], self._times(5))

    def alloc(self, clusters: int) -> int:
        lcn = self.next_cluster
        self.next_cluster += clusters
        need = self.next_cluster * CLUSTER
        if len(self.volume) < need:
            self.volume.extend(self.rng.randbytes(need - len(self.volume)))
        return lcn

    def write_runs(self, runs: Sequence[tuple[int | None, int]], data: bytes) -> None:
        offset = 0
        for lcn, count in runs:
            size = count * CLUSTER
            if lcn is not None:
                piece = data[offset : offset + size]
                self.volume[lcn * CLUSTER : lcn * CLUSTER + len(piece)] = piece
            offset += size

    def _times(self, salt: int) -> tuple[int, int, int, int]:
        base = BASE_TIME + salt * 10_000_019
        return (base, base + 1_234_567, base + 2_345_678 + 3, base + 9_999_999 + 7)

    def new_record(self) -> int:
        number = self.next_record
        self.next_record += 1
        return number

    def add_dir(self, parent: int, name: str, *, deleted: bool = False) -> int:
        number = self.new_record()
        self.entries[number] = Entry(number, True, [Link(parent, name)], self._times(number), deleted=deleted)
        return number

    def add_file(
        self,
        parent: int,
        name: str,
        data: bytes,
        *,
        layout: str = "auto",
        ads: dict[str, bytes] | None = None,
        dos_name: str | None = None,
        namespace: int = NS_WIN32,
        deleted: bool = False,
        links: list[Link] | None = None,
    ) -> int:
        number = self.new_record()
        all_links = [Link(parent, name, namespace)]
        if dos_name:
            all_links.append(Link(parent, dos_name, NS_DOS))
        all_links += links or []
        self.entries[number] = Entry(
            number, False, all_links, self._times(number), data, layout, dict(ads or {}), deleted=deleted
        )
        return number

    def path(self, *parts: str) -> int:
        node = self.root
        for part in parts:
            node = next(
                e.record
                for e in self.entries.values()
                if e.is_dir and not e.deleted and any(link.parent == node and link.name == part for link in e.links)
            )
        return node

    def makedirs(self, *parts: str) -> int:
        node = self.root
        for part in parts:
            found = [
                e.record
                for e in self.entries.values()
                if e.is_dir and not e.deleted and any(link.parent == node and link.name == part for link in e.links)
            ]
            node = found[0] if found else self.add_dir(node, part)
        return node

    def _stream_attrs(self, entry: Entry, name: str, data: bytes, layout: str, instance: int) -> list[bytes]:
        size = len(data)
        clusters = max(1, (size + CLUSTER - 1) // CLUSTER)
        if layout == "auto":
            layout = "resident" if size <= 400 else "contiguous"
        if layout == "resident":
            return [resident_attr(0x80, data, name=name, instance=instance)]
        if layout == "contiguous":
            lcn = self.alloc(clusters)
            runs: list[tuple[int | None, int]] = [(lcn, clusters)]
        elif layout in ("fragmented", "backward"):
            sizes = []
            remaining = clusters
            while remaining:
                sizes.append(min(remaining, self.rng.randint(1, 3)))
                remaining -= sizes[-1]
            # ``backward`` places later pieces at lower LCNs: negative run deltas
            order = range(len(sizes) - 1, -1, -1) if layout == "backward" else range(len(sizes))
            lcns: dict[int, int] = {}
            for index in order:
                lcns[index] = self.alloc(sizes[index])
                self.alloc(self.rng.randint(1, 2))
            runs = [(lcns[index], size) for index, size in enumerate(sizes)]
        elif layout == "sparse":
            head = max(1, clusters // 3)
            hole = max(1, clusters // 3)
            tail = max(1, clusters - head - hole)
            runs = [(self.alloc(head), head), (None, hole), (self.alloc(tail), tail)]
            data = (data[: head * CLUSTER] + bytes(hole * CLUSTER) + data[(head + hole) * CLUSTER :])[:size]
        elif layout == "past-end":
            runs = [(10_000_000, clusters)]  # beyond the volume end: reads come back short
        elif layout == "compressed":
            return [self._compressed_attr(data, name, instance)]
        else:
            raise ValueError(layout)
        if layout != "past-end":
            self.write_runs(runs, data)
        return [nonresident_attr(0x80, runs, size, name=name, instance=instance)]

    def _compressed_attr(self, data: bytes, name: str, instance: int) -> bytes:
        unit = 16 * CLUSTER
        runs: list[tuple[int | None, int]] = []
        for start in range(0, len(data), unit):
            block = data[start : start + unit].ljust(unit, b"\x00")
            if block.count(0) == unit:
                runs.append((None, 16))
                continue
            packed = lznt1_compress(block)
            used = (len(packed) + CLUSTER - 1) // CLUSTER
            if used >= 16:
                lcn = self.alloc(16)
                self.write_runs([(lcn, 16)], block)
                runs.append((lcn, 16))
            else:
                lcn = self.alloc(used)
                self.write_runs([(lcn, used)], packed)
                runs += [(lcn, used), (None, 16 - used)]
        merged: list[tuple[int | None, int]] = []
        for lcn, count in runs:
            if merged and lcn is None and merged[-1][0] is None:
                merged[-1] = (None, merged[-1][1] + count)
            else:
                merged.append((lcn, count))
        return nonresident_attr(0x80, merged, len(data), name=name, instance=instance, compression_unit=4, flags=0x0001)

    def _fn_values(self, entry: Entry) -> list[tuple[Link, bytes]]:
        attributes = 0x20 | (FILE_NAME_INDEX_PRESENT if entry.is_dir else 0)
        return [
            (
                link,
                file_name_value(
                    file_ref(link.parent, self.entries[link.parent].sequence if link.parent in self.entries else 1),
                    link.name,
                    link.namespace,
                    (entry.times[0] + 11, entry.times[1] + 11, entry.times[2] + 11, entry.times[3] + 11),
                    size=0 if entry.is_dir else len(entry.data),
                    attributes=attributes,
                ),
            )
            for link in entry.links
        ]

    def _index_entry(self, ref: int, key: bytes, *, vcn: int | None = None) -> bytes:
        length = _align8(0x10 + len(key)) + (8 if vcn is not None else 0)
        out = bytearray(length)
        struct.pack_into("<QHHHH", out, 0, ref, length, len(key), 1 if vcn is not None else 0, 0)
        out[0x10 : 0x10 + len(key)] = key
        if vcn is not None:
            struct.pack_into("<Q", out, length - 8, vcn)
        return bytes(out)

    def _end_entry(self, vcn: int | None = None) -> bytes:
        if vcn is None:
            return struct.pack("<QHHHH", 0, 0x10, 0, 2, 0)
        return struct.pack("<QHHHHQ", 0, 0x18, 0, 3, 0, vcn)

    def _index_root_value(self, entries: bytes, large: bool) -> bytes:
        header = struct.pack("<IIIB3x", 0x10, 0x10 + len(entries), 0x10 + len(entries), 1 if large else 0)
        return struct.pack("<IIIB3x", 0x30, 1, INDEX_BUFFER, 1) + header + entries

    def _directory_index(self, number: int) -> tuple[list[bytes], int]:
        if self._children is None:
            self._children = {}
            for child in self.entries.values():
                if child.deleted or not child.indexed:
                    continue
                for link, value in self._fn_values(child):
                    if child.record != link.parent:
                        self._children.setdefault(link.parent, []).append((link.name, file_ref(child.record, child.sequence), value))
        children = list(self._children.get(number, []))
        for stale_record, link in self.stale_index:
            if link.parent == number:
                stale = self.entries[stale_record]
                value = {lnk.name: v for lnk, v in self._fn_values(stale)}[link.name]
                children.append((link.name, file_ref(stale_record, stale.sequence), value))
        children.sort(key=lambda item: item[0].upper())
        raw = [self._index_entry(ref, key) for _name, ref, key in children]
        small = b"".join(raw) + self._end_entry()
        if 0x38 + 0x60 + 0x80 + 0x20 + 0x20 + len(small) + 0x40 < RECORD:
            return [resident_attr(0x90, self._index_root_value(small, False), name="$I30", instance=3)], 0
        # Two-level B-tree: leaves in INDX buffers; each root entry is the separator after its leaf.
        capacity = INDEX_BUFFER - 0x40 - 0x10
        leaves: list[list[int]] = [[]]
        separators: list[int] = []
        used = 0
        for index, entry in enumerate(raw):
            if used + len(entry) > capacity:
                separators.append(index)
                leaves.append([])
                used = 0
                continue
            leaves[-1].append(index)
            used += len(entry)
        root = b"".join(
            self._index_entry(children[sep][1], children[sep][2], vcn=leaf) for leaf, sep in enumerate(separators)
        ) + self._end_entry(len(leaves) - 1)
        lcn = self.alloc(len(leaves))
        for vcn, leaf in enumerate(leaves):
            body = b"".join(raw[i] for i in leaf) + self._end_entry()
            buf = bytearray(INDEX_BUFFER)
            buf[0:4] = b"INDX"
            struct.pack_into("<HHQQ", buf, 4, 0x28, 9, 0, vcn)
            struct.pack_into("<IIIB", buf, 0x18, 0x28, 0x28 + len(body), INDEX_BUFFER - 0x18, 0)
            buf[0x40 : 0x40 + len(body)] = body
            apply_usa(buf, 0x28)
            self.volume[(lcn + vcn) * CLUSTER : (lcn + vcn + 1) * CLUSTER] = buf
        bitmap = bytearray(_align8((len(leaves) + 7) // 8))
        for vcn in range(len(leaves)):
            bitmap[vcn // 8] |= 1 << (vcn % 8)
        attrs = [
            resident_attr(0x90, self._index_root_value(root, True), name="$I30", instance=3),
            nonresident_attr(0xA0, [(lcn, len(leaves))], len(leaves) * INDEX_BUFFER, name="$I30", instance=4),
            resident_attr(0xB0, bytes(bitmap), name="$I30", instance=5),
        ]
        return attrs, len(leaves)

    def _file_record(self, entry: Entry) -> bytes:
        flags = (0 if entry.deleted else 1) | (2 if entry.is_dir else 0)
        attrs = [resident_attr(0x10, standard_information(entry.times), instance=0)]
        fn_attrs = [resident_attr(0x30, value, instance=1 + i, indexed=True) for i, (_l, value) in enumerate(self._fn_values(entry))]
        if entry.layout == "junction":
            attrs[0] = resident_attr(0x10, standard_information(entry.times, 0x416), instance=0)
            return mft_record(entry.record, [*attrs, *fn_attrs, junction_attr()], flags=flags, sequence=entry.sequence)
        if entry.is_dir:
            index_attrs, _ = self._directory_index(entry.record)
            return mft_record(entry.record, attrs + fn_attrs + index_attrs, flags=flags, sequence=entry.sequence, links=len(entry.links))
        if entry.layout == "attrlist":
            return self._attribute_list_record(entry, attrs[0], fn_attrs, flags)
        data_attrs = self._stream_attrs(entry, "", entry.data, entry.layout, 8)
        for i, (stream, payload) in enumerate(entry.ads.items()):
            data_attrs += self._stream_attrs(entry, stream, payload, "resident" if len(payload) < 200 else "fragmented", 9 + i)
        return mft_record(entry.record, attrs + fn_attrs + data_attrs, flags=flags, sequence=entry.sequence, links=len(entry.links))

    def _attribute_list_record(self, entry: Entry, si: bytes, fn_attrs: list[bytes], flags: int) -> bytes:
        clusters = (len(entry.data) + CLUSTER - 1) // CLUSTER
        half = clusters // 2
        first = [(self.alloc(1), 1) for _ in range(half)]
        self.alloc(1)
        second = [(self.alloc(1), 1) for _ in range(clusters - half)]
        self.write_runs(first + second, entry.data)
        ext_a, ext_b = self.new_record(), self.new_record()
        base_ref = file_ref(entry.record, entry.sequence)
        # the list names the second extent first: readers must order extents by lowest VCN
        self.extra_records[ext_b] = mft_record(
            ext_b, [nonresident_attr(0x80, second, 0, lowest_vcn=half, allocated=0, instance=0)], flags=1, base=base_ref
        )
        self.extra_records[ext_a] = mft_record(
            ext_a, [nonresident_attr(0x80, first, len(entry.data), instance=0)], flags=1, base=base_ref
        )

        def list_entry(type_code: int, lowest: int, record: int, instance: int) -> bytes:
            return struct.pack("<IHBBQQH", type_code, 0x20, 0, 0x1A, lowest, file_ref(record), instance) + b"\x00" * 6

        listing = list_entry(0x10, 0, entry.record, 0) + list_entry(0x30, 0, entry.record, 1)
        listing += list_entry(0x80, half, ext_b, 0) + list_entry(0x80, 0, ext_a, 0)
        attrs = [si, resident_attr(0x20, listing, instance=7), *fn_attrs]
        return mft_record(entry.record, attrs, flags=flags, sequence=entry.sequence, links=len(entry.links))

    def build_volume(self, label: str = "SYNTHETIC") -> bytes:
        system = {
            0: "$MFT", 1: "$MFTMirr", 2: "$LogFile", 3: "$Volume", 4: "$AttrDef", 6: "$Bitmap",
            7: "$Boot", 8: "$BadClus", 9: "$Secure", 10: "$UpCase", 11: "$Extend",
        }  # fmt: skip
        indexed_system = {0, 1, 2, 3, 4, 6, 7, 8, 11}
        records: dict[int, bytes] = {}
        logfile = self.rng.randbytes(64 * 1024)
        log_lcn = self.alloc(16)
        self.write_runs([(log_lcn, 16)], logfile)
        attrdef = self.rng.randbytes(2560)
        attrdef_lcn = self.alloc(1)
        self.write_runs([(attrdef_lcn, 1)], attrdef)
        mirr_lcn = self.alloc(1)
        self.entries[11] = Entry(11, True, [Link(5, "$Extend")], self._times(11))
        for number, name in system.items():
            if number == 11:
                continue
            self.entries[number] = Entry(number, False, [Link(5, name)], self._times(number), indexed=number in indexed_system)
        for number in sorted(self.entries):
            entry = self.entries[number]
            if number < FIRST_USER_RECORD and number not in (5, 11):
                continue
            records[number] = self._file_record(entry)
        total_records = max(max(self.entries), max(self.extra_records, default=0), self.next_record) + 1 + SPARE_RECORDS
        mft_clusters = (total_records * RECORD + CLUSTER - 1) // CLUSTER
        first_part = max(1, mft_clusters // 3)
        mft_runs = [(self.alloc(first_part), first_part)]
        self.alloc(2)
        mft_runs.append((self.alloc(mft_clusters - first_part), mft_clusters - first_part))
        bitmap_lcn = self.alloc(4)
        total_clusters = self.next_cluster + 8
        self.alloc(8)
        volume_bitmap = bytearray(4 * CLUSTER)
        for cluster in range(total_clusters):
            volume_bitmap[cluster // 8] |= 1 << (cluster % 8)
        self.write_runs([(bitmap_lcn, 4)], bytes(volume_bitmap))
        mft_size = mft_clusters * CLUSTER

        def system_record(number: int, data_attrs: list[bytes], extra: list[bytes] | None = None) -> bytes:
            entry = self.entries[number]
            fn = [resident_attr(0x30, v, instance=1, indexed=True) for _l, v in self._fn_values(entry)]
            return mft_record(
                number,
                [resident_attr(0x10, standard_information(entry.times, 0x06), instance=0), *fn, *(extra or []), *data_attrs],
                flags=1,
            )

        records[0] = system_record(0, [nonresident_attr(0x80, mft_runs, mft_size, instance=2)])
        records[1] = system_record(1, [nonresident_attr(0x80, [(mirr_lcn, 1)], 4 * RECORD, instance=2)])
        records[2] = system_record(2, [nonresident_attr(0x80, [(log_lcn, 16)], len(logfile), instance=2)])
        volume_info = struct.pack("<QBBH", 0, 3, 1, 0)
        records[3] = system_record(
            3,
            [resident_attr(0x80, b"", instance=4)],
            [resident_attr(0x60, label.encode("utf-16-le"), instance=2), resident_attr(0x70, volume_info, instance=3)],
        )
        records[4] = system_record(4, [nonresident_attr(0x80, [(attrdef_lcn, 1)], len(attrdef), instance=2)])
        records[6] = system_record(6, [nonresident_attr(0x80, [(bitmap_lcn, 4)], (total_clusters + 7) // 8, instance=2)])
        records[7] = system_record(7, [nonresident_attr(0x80, [(0, 2)], 8192, instance=2)])
        records[8] = system_record(
            8,
            [resident_attr(0x80, b"", instance=2), nonresident_attr(0x80, [(None, total_clusters)], total_clusters * CLUSTER, name="$Bad", instance=3)],
        )
        records[9] = system_record(9, [])
        records[10] = system_record(10, [resident_attr(0x80, bytes(range(256)), instance=2)])
        # 12-15: never initialised (no FILE signature); 16-23: reserved FILE records, no attributes.
        for number in range(16, FIRST_USER_RECORD):
            records[number] = mft_record(number, [], flags=0)
        records.update(self.extra_records)
        mft = bytearray(mft_size)
        for number, raw in records.items():
            mft[number * RECORD : (number + 1) * RECORD] = raw
        for number in self.broken_fixup:
            mft[number * RECORD + SECTOR - 2] ^= 0xFF  # sector trailer no longer matches the update sequence number
        self.write_runs(mft_runs, bytes(mft))
        self.volume[mirr_lcn * CLUSTER : mirr_lcn * CLUSTER + 4 * RECORD] = mft[: 4 * RECORD]
        boot = bytearray(SECTOR)
        boot[0:3] = b"\xeb\x52\x90"
        boot[3:11] = b"NTFS    "
        struct.pack_into("<HB", boot, 0x0B, SECTOR, CLUSTER // SECTOR)
        boot[0x15] = 0xF8
        struct.pack_into("<I", boot, 0x1C, PARTITION_SECTOR)
        struct.pack_into("<QQQ", boot, 0x28, total_clusters * (CLUSTER // SECTOR) - 1, mft_runs[0][0], mirr_lcn)
        boot[0x40] = 0xF6  # 1024-byte FILE records
        boot[0x44] = 0x01  # one-cluster index buffers
        struct.pack_into("<Q", boot, 0x48, 0x1234_5678_9ABC_DEF0)
        boot[510:512] = b"\x55\xaa"
        self.volume[0:SECTOR] = boot
        del self.volume[total_clusters * CLUSTER :]
        return bytes(self.volume)


def populate(
    builder: VolumeBuilder, *, bulk_files: int = 400, bulk_dirs: int = 8, seed: int = 1, payload: str = "random"
) -> dict[str, int]:
    """Add the edge-case tree plus ``bulk_files`` files over ``bulk_dirs`` directories.

    ``payload="text"`` fills bulk files with word text (compresses ~3x in an E01, like real
    documents); ``"random"`` keeps them incompressible."""
    rng = random.Random(seed)
    text_rng = random.Random(seed + 1)
    words = [text_rng.randbytes(text_rng.randint(2, 9)).hex().encode() for _ in range(512)]

    def blob(size: int) -> bytes:
        if payload == "random":
            return rng.randbytes(size)
        out = bytearray()
        while len(out) < size:
            out += b" ".join(text_rng.choices(words, k=64)) + b"\n"
        return bytes(out[:size])

    b = builder
    config = b.makedirs("Windows", "System32", "config")
    for hive in ("SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"):
        b.add_file(config, hive, rng.randbytes(rng.randint(20_000, 90_000)), layout="fragmented")
    logs = b.makedirs("Windows", "System32", "winevt", "Logs")
    for index in range(40):
        b.add_file(logs, f"Microsoft-Windows-Channel{index:02d}%4Operational.evtx", rng.randbytes(69_632))
    prefetch = b.makedirs("Windows", "Prefetch")
    for index in range(12):
        b.add_file(prefetch, f"APP{index:02d}.EXE-{index:08X}.pf", rng.randbytes(rng.randint(500, 30_000)))
    b.add_file(b.makedirs("Windows", "inf"), "setupapi.dev.log", rng.randbytes(12_000))
    users = b.makedirs("Users")
    for user in ("alice", "bob"):
        home = b.add_dir(users, user)
        b.add_file(home, "NTUSER.DAT", rng.randbytes(262_144), layout="backward")
        b.add_file(home, "NTUSER.DAT.LOG1", rng.randbytes(8192))
        recent = b.makedirs("Users", user, "AppData", "Roaming", "Microsoft", "Windows", "Recent")
        for index in range(5):
            b.add_file(recent, f"doc{index}.lnk", rng.randbytes(rng.randint(300, 1500)))
    # absolute mount point like "All Users" -> C:\ProgramData; it has no $I30 index
    junction = b.add_dir(users, "All Users")
    b.entries[junction].layout = "junction"
    docs = b.makedirs("Users", "alice", "Documents")
    b.add_file(docs, "Quarterly Report Final Version.docx", rng.randbytes(45_000), dos_name="QUARTE~1.DOC")
    b.add_file(docs, "notes.txt", b"resident body " * 10, ads={"Zone.Identifier": b"[ZoneTransfer]\r\nZoneId=3\r\n", "big": rng.randbytes(20_000)})
    b.add_file(docs, "sparse.bin", rng.randbytes(40_000), layout="sparse")
    b.add_file(docs, "compressed.log", (b"compressible line of text 0123456789\n" * 6000) + bytes(70_000) + rng.randbytes(5000), layout="compressed")
    b.add_file(docs, "attrlist.bin", rng.randbytes(9 * CLUSTER + 123), layout="attrlist")
    b.add_file(docs, "empty.txt", b"")
    b.add_file(docs, "truncated.bin", rng.randbytes(3 * CLUSTER), layout="past-end")
    b.add_file(docs, "보고서.hwp", rng.randbytes(5000))
    b.add_file(docs, "weird:name?.txt", b"rewritten by _safe_component", namespace=NS_POSIX)
    b.add_file(docs, "trailing dot. ", b"trailing", namespace=NS_POSIX)
    b.add_file(docs, "x" * 200 + ".txt", b"long name")
    b.add_file(docs, "readme", b"lower posix twin", namespace=NS_POSIX)
    b.add_file(docs, "README", b"upper posix twin", namespace=NS_POSIX)
    shared = b.add_file(docs, "hardlink-a.txt", b"hard linked content" * 40)
    b.entries[shared].links.append(Link(b.makedirs("Users", "bob", "Documents"), "hardlink-b.txt"))
    broken = b.add_file(docs, "broken-fixup.bin", rng.randbytes(3000))
    b.broken_fixup.add(broken)
    stale = b.add_file(docs, "stale-entry.tmp", rng.randbytes(7000), deleted=True)
    b.stale_index.append((stale, Link(docs, "stale-entry.tmp")))
    recycle = b.makedirs("$Recycle.Bin")
    b.add_file(recycle, "$IABC123.txt", rng.randbytes(544))
    b.add_file(docs, "deleted-report.pdf", rng.randbytes(33_333), deleted=True)
    b.add_file(docs, "deleted-small.txt", b"gone but resident", deleted=True)
    b.add_dir(docs, "deleted-folder", deleted=True)
    nameless = b.add_file(docs, "nameless", rng.randbytes(5000), deleted=True)
    b.entries[nameless].links = []
    layouts = ("auto", "auto", "auto", "fragmented", "backward", "sparse", "auto")
    for d in range(bulk_dirs):
        folder = b.add_dir(b.makedirs("data", f"group{d // 40:02d}"), f"dir{d:03d}")
        for f in range(bulk_files // bulk_dirs):
            size = rng.choice((0, 80, 300, 700, 3000, 9000, 20_000, 60_000))
            layout = rng.choice(layouts) if size > 400 else "auto"
            name = f"file{f:05d}.{rng.choice(('txt', 'dat', 'jpg', 'log'))}"
            deleted = rng.random() < 0.05
            b.add_file(folder, name, blob(size), layout=layout, deleted=deleted)
    return {"records": b.next_record}


def junction_attr() -> bytes:
    target = "\\??\\C:\\ProgramData"
    print_name = "C:\\ProgramData"
    sub = target.encode("utf-16-le")
    prn = print_name.encode("utf-16-le")
    body = struct.pack("<HHHH", 0, len(sub), len(sub) + 2, len(prn)) + sub + b"\x00\x00" + prn + b"\x00\x00"
    value = struct.pack("<IHH", 0xA0000003, len(body), 0) + body
    return resident_attr(0xC0, value, instance=6)


def add_name_collisions(b: VolumeBuilder) -> None:
    """Names that reach the same output file or directory only after ``_safe_component`` or the
    output file system's folding (case, Unicode normalization), plus Win32 device names."""
    root = b.makedirs("Collide")
    trailing_dot = b.add_dir(root, "x.")  # written as directory "x", where the file "x" goes too
    b.add_file(trailing_dot, "child.txt", b"in directory x.")
    b.add_file(root, "x", b"file x " * 300, namespace=NS_POSIX)
    upper = b.add_dir(root, "Foo")
    b.add_file(upper, "inside.txt", b"inside Foo")
    b.add_file(root, "foo", b"file foo " * 500, namespace=NS_POSIX)
    for form, body in (("NFC", b"nfc " * 3000), ("NFD", b"NFD " * 5000)):
        b.add_file(root, unicodedata.normalize(form, "caf\u00e9.txt"), body, namespace=NS_POSIX)
    b.add_file(root, "\u03b1\u03c2.txt", b"final sigma " * 2000, namespace=NS_POSIX)
    b.add_file(root, "\u03b1\u03c3.txt", b"sigma " * 1000, namespace=NS_POSIX)
    b.add_file(root, "\u212a.txt", b"kelvin " * 900, namespace=NS_POSIX)
    b.add_file(root, "k.txt", b"ascii k " * 700, namespace=NS_POSIX)
    for device in ("CON", "aux.txt", "NUL", "com1.log", "LPT9 .txt"):
        b.add_file(root, device, f"device name {device}".encode() * 20, namespace=NS_POSIX)


def build_disk_image(
    path: Path,
    *,
    bulk_files: int = 400,
    bulk_dirs: int = 8,
    seed: int = 1,
    payload: str = "random",
    collisions: bool = False,
    builder: VolumeBuilder | None = None,
) -> dict[str, int]:
    """Write an MBR disk (one 0x07 partition at sector 2048) holding the synthetic volume."""
    builder = builder or VolumeBuilder(seed)
    info = populate(builder, bulk_files=bulk_files, bulk_dirs=bulk_dirs, seed=seed, payload=payload)
    if collisions:
        add_name_collisions(builder)
    volume = builder.build_volume()
    sectors = len(volume) // SECTOR
    mbr = bytearray(PARTITION_SECTOR * SECTOR)
    entry = bytearray(16)
    entry[4] = 0x07
    struct.pack_into("<II", entry, 8, PARTITION_SECTOR, sectors)
    mbr[0x1BE:0x1CE] = entry
    mbr[510:512] = b"\x55\xaa"
    with Path(path).open("wb") as handle:
        handle.write(mbr)
        handle.write(volume)
    return {**info, "volume_bytes": len(volume), "image_bytes": len(mbr) + len(volume)}


if __name__ == "__main__":  # pragma: no cover - manual corpus generation
    import argparse
    import json

    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--files", type=int, default=400)
    parser.add_argument("--dirs", type=int, default=8)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--payload", choices=("random", "text"), default="random")
    args = parser.parse_args()
    print(json.dumps(build_disk_image(args.output, bulk_files=args.files, bulk_dirs=args.dirs, seed=args.seed, payload=args.payload)))
