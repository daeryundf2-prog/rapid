"""Deterministic synthetic regf hives for the registry-engine differential tests and benchmark.

Unlike the single-hbin ``HiveWriter`` of ``tests.test_parser_quality_registry``, this writer
lays cells out over many 4 KiB-aligned hbins (closing each with a free padding cell), mixes
lf/lh/li/ri subkey lists, inline / ordinary / big-data (``db``) values, Latin-1 and UTF-16LE
names (Korean, case-folding edge cases, surrogate pairs and lone surrogates), deleted (free)
key and value cells, and offers structural corruptions (truncated hbins, signature gaps,
invalid sizes, cycles, misaligned or dangling references, random byte damage). Everything is
generated from a seed: no real evidence is involved.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

REG_NONE = 0
REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_DWORD_BIG_ENDIAN = 5
REG_LINK = 6
REG_MULTI_SZ = 7
REG_QWORD = 11
BIG_DATA_SEGMENT = 16344
HBIN_ALIGNMENT = 4096
FILETIME_2025 = 133_930_492_691_655_237

ASCII_WORDS = (
    "Software", "Microsoft", "Windows", "CurrentVersion", "Run", "Explorer", "UserAssist", "Count",
    "Services", "Select", "Control", "Shell", "BagMRU", "Bags", "TypedPaths", "RecentDocs", "Policies",
    "App Paths", "Uninstall", "{6F0B2B4E-8C1D-4E7A-9A51-0123456789AB}", "S-1-5-21-1004-1001", "0", "1",
)
UNICODE_WORDS = (
    "레지스트리", "사용자설정", "진료실1", "café", "naïve", "Ärger", "Straße", "STRASSE", "Ωmega", "ΣΊΣΥΦΟΣ",
    "İstanbul", "ſtate", "\u212aelvin", "ﬁle", "📁폴더", "日本語キー", "émigré",
)
VALUE_NAMES = ("", "Path", "ImagePath", "Start", "Type", "DisplayName", "MRUListEx", "Current", "값", "Größe")


@dataclass
class GenValue:
    name: str
    value_type: int
    data: bytes
    raw_name: bytes | None = None
    compressed: bool | None = None
    force_cell: bool = False


@dataclass
class GenKey:
    name: str
    stamp: int = FILETIME_2025
    raw_name: bytes | None = None
    compressed: bool | None = None
    list_kind: str = "lh"
    values: list[GenValue] = field(default_factory=list)
    children: list[GenKey] = field(default_factory=list)


class HbinWriter:
    """Cell allocator over 4 KiB-aligned hbins; offsets are relative to the first hbin."""

    def __init__(self) -> None:
        self.body = bytearray()
        self.cursor = 0
        self.bin_end = 0

    def _close_bin(self) -> None:
        remaining = self.bin_end - self.cursor
        if remaining >= 8:
            self.body[self.cursor : self.cursor + 4] = remaining.to_bytes(4, "little", signed=True)
        self.cursor = self.bin_end

    def _open_bin(self, cell_size: int) -> None:
        self._close_bin()
        size = 32 + cell_size
        size += (-size) % HBIN_ALIGNMENT
        start = len(self.body)
        self.body += bytearray(size)
        self.body[start : start + 4] = b"hbin"
        self.body[start + 4 : start + 8] = start.to_bytes(4, "little")
        self.body[start + 8 : start + 12] = size.to_bytes(4, "little")
        self.cursor = start + 32
        self.bin_end = start + size

    def alloc(self, payload: bytes, *, free: bool = False) -> int:
        size = 4 + len(payload)
        size += (-size) % 8
        if self.bin_end - self.cursor < size:
            self._open_bin(size)
        offset = self.cursor
        raw = size if free else -size
        self.body[offset : offset + 4] = raw.to_bytes(4, "little", signed=True)
        self.body[offset + 4 : offset + 4 + len(payload)] = payload
        self.cursor += size
        return offset

    def patch_u32(self, cell: int, field_offset: int, value: int) -> None:
        position = cell + 4 + field_offset
        self.body[position : position + 4] = (value & 0xFFFFFFFF).to_bytes(4, "little")

    def finish(self) -> bytes:
        self._close_bin()
        return bytes(self.body)


def encode_name(name: str, raw_name: bytes | None, compressed: bool | None) -> tuple[bytes, bool]:
    if raw_name is not None:
        return raw_name, bool(compressed)
    if compressed is None:
        compressed = all(ord(char) < 256 for char in name)
    if compressed:
        return name.encode("latin-1"), True
    return name.encode("utf-16-le", errors="surrogatepass"), False


class RegfBuilder:
    def __init__(self, *, minor_version: int = 5) -> None:
        self.minor_version = minor_version
        self.cells = HbinWriter()
        self.key_offsets: list[int] = []
        self.value_offsets: list[int] = []
        self.list_offsets: list[int] = []
        self.segment_lists: list[int] = []

    def nk(self, key: GenKey, parent: int, *, root: bool = False, free: bool = False) -> int:
        raw_name, compressed = encode_name(key.name, key.raw_name, key.compressed)
        body = bytearray(0x4C + len(raw_name))
        body[0:2] = b"nk"
        flags = (0x0020 if compressed else 0) | (0x000C if root else 0)
        body[2:4] = flags.to_bytes(2, "little")
        body[4:12] = (key.stamp & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        body[0x10:0x14] = parent.to_bytes(4, "little")
        body[0x1C:0x20] = (0xFFFFFFFF).to_bytes(4, "little")
        body[0x20:0x24] = (0xFFFFFFFF).to_bytes(4, "little")
        body[0x28:0x2C] = (0xFFFFFFFF).to_bytes(4, "little")
        body[0x48:0x4A] = len(raw_name).to_bytes(2, "little")
        body[0x4C:] = raw_name
        return self.cells.alloc(bytes(body), free=free)

    def vk(self, value: GenValue, *, free: bool = False) -> int:
        raw_name, compressed = encode_name(value.name, value.raw_name, value.compressed)
        data = value.data
        if len(data) <= 4 and not value.force_cell:
            size_field = 0x80000000 | len(data)
            data_field = int.from_bytes(data.ljust(4, b"\x00"), "little")
        elif len(data) > BIG_DATA_SEGMENT and self.minor_version >= 4:
            segments = [
                self.cells.alloc(data[index : index + BIG_DATA_SEGMENT], free=free)
                for index in range(0, len(data), BIG_DATA_SEGMENT)
            ]
            segment_list = self.cells.alloc(b"".join(offset.to_bytes(4, "little") for offset in segments), free=free)
            if not free:
                self.segment_lists.append(segment_list)
            db = b"db" + len(segments).to_bytes(2, "little") + segment_list.to_bytes(4, "little") + b"\x00" * 4
            size_field, data_field = len(data), self.cells.alloc(db, free=free)
        else:
            size_field, data_field = len(data), self.cells.alloc(data, free=free)
        body = bytearray(20 + len(raw_name))
        body[0:2] = b"vk"
        body[2:4] = len(raw_name).to_bytes(2, "little")
        body[4:8] = size_field.to_bytes(4, "little")
        body[8:12] = data_field.to_bytes(4, "little")
        body[12:16] = (value.value_type & 0xFFFFFFFF).to_bytes(4, "little")
        body[16:18] = (1 if compressed and raw_name else 0).to_bytes(2, "little")
        body[20:] = raw_name
        offset = self.cells.alloc(bytes(body), free=free)
        if not free:
            self.value_offsets.append(offset)
        return offset

    def subkey_list(self, kind: str, offsets: list[int]) -> int:
        def leaf(signature: bytes, chunk: list[int]) -> int:
            if signature == b"li":
                entries = b"".join(offset.to_bytes(4, "little") for offset in chunk)
            else:
                entries = b"".join(offset.to_bytes(4, "little") + b"\x00" * 4 for offset in chunk)
            return self.cells.alloc(signature + len(chunk).to_bytes(2, "little") + entries)

        if kind == "ri" and len(offsets) > 1:
            middle = len(offsets) // 2
            leaves = [leaf(b"li", offsets[:middle]), leaf(b"lh", offsets[middle:])]
            list_offset = self.cells.alloc(b"ri" + len(leaves).to_bytes(2, "little") + b"".join(o.to_bytes(4, "little") for o in leaves))
        else:
            list_offset = leaf(kind.encode("ascii") if kind in ("lf", "lh", "li") else b"lh", offsets)
        self.list_offsets.append(list_offset)
        return list_offset

    def serialize(self, key: GenKey, parent: int, *, root: bool = False) -> int:
        offset = self.nk(key, parent, root=root)
        self.key_offsets.append(offset)
        if key.values:
            value_offsets = [self.vk(value) for value in key.values]
            value_list = self.cells.alloc(b"".join(item.to_bytes(4, "little") for item in value_offsets))
            self.cells.patch_u32(offset, 0x24, len(value_offsets))
            self.cells.patch_u32(offset, 0x28, value_list)
        if key.children:
            ordered = sorted(key.children, key=lambda child: child.name.upper())
            child_offsets = [self.serialize(child, offset) for child in ordered]
            self.cells.patch_u32(offset, 0x14, len(child_offsets))
            self.cells.patch_u32(offset, 0x1C, self.subkey_list(key.list_kind, child_offsets))
        return offset

    def build(self, root: GenKey, *, deleted: list[tuple[GenKey | GenValue, int]] = ()) -> bytes:
        root_offset = self.serialize(root, 0, root=True)
        for item, parent_index in deleted:
            if isinstance(item, GenKey):
                parent = self.key_offsets[parent_index % len(self.key_offsets)]
                self.nk(item, parent, free=True)
            else:
                self.vk(item, free=True)
            self.cells.alloc(b"\x00" * 8, free=True)
        body = self.cells.finish()
        base = bytearray(4096)
        base[0:4] = b"regf"
        base[4:8] = (11).to_bytes(4, "little")
        base[8:12] = (11).to_bytes(4, "little")
        base[12:20] = FILETIME_2025.to_bytes(8, "little")
        base[20:24] = (1).to_bytes(4, "little")
        base[24:28] = self.minor_version.to_bytes(4, "little")
        base[32:36] = (1).to_bytes(4, "little")
        base[36:40] = root_offset.to_bytes(4, "little")
        base[40:44] = len(body).to_bytes(4, "little")
        base[44:48] = (1).to_bytes(4, "little")
        base[48:112] = "\\??\\C:\\Synthetic\\SOFTWARE".encode("utf-16-le")[:64].ljust(64, b"\x00")
        checksum = 0
        for index in range(0, 508, 4):
            checksum ^= int.from_bytes(base[index : index + 4], "little")
        base[508:512] = checksum.to_bytes(4, "little")
        return bytes(base) + body


def random_name(rng: random.Random, *, unicode_ratio: float = 0.25) -> str:
    if rng.random() < unicode_ratio:
        return rng.choice(UNICODE_WORDS) + (str(rng.randrange(100)) if rng.random() < 0.5 else "")
    return rng.choice(ASCII_WORDS) + (f"_{rng.randrange(1000)}" if rng.random() < 0.6 else "")


def random_stamp(rng: random.Random) -> int:
    roll = rng.random()
    if roll < 0.03:
        return 0
    if roll < 0.05:
        return 0xFFFFFFFFFFFFFFFF
    if roll < 0.08:
        return rng.randrange(1, 10_000_000)
    return FILETIME_2025 + rng.randrange(-10**15, 10**15)


def utf16z(text: str) -> bytes:
    return text.encode("utf-16-le", errors="surrogatepass") + b"\x00\x00"


def random_value(rng: random.Random, *, big_ratio: float = 0.02) -> GenValue:
    name = rng.choice(VALUE_NAMES) if rng.random() < 0.5 else random_name(rng)
    roll = rng.random()
    if roll < big_ratio:
        size = rng.choice((BIG_DATA_SEGMENT + 1, BIG_DATA_SEGMENT * 2 + 17, BIG_DATA_SEGMENT * 3))
        return GenValue(name, rng.choice((REG_BINARY, REG_SZ, REG_MULTI_SZ)), bytes(rng.randrange(256) for _ in range(64)) * (size // 64 + 1))
    kind = rng.randrange(14)
    if kind == 0:
        return GenValue(name, REG_SZ, utf16z(f"C:\\Users\\사용자\\AppData\\{random_name(rng)}.exe"))
    if kind == 1:
        return GenValue(name, REG_EXPAND_SZ, utf16z("%SystemRoot%\\System32\\svchost.exe -k netsvcs"))
    if kind == 2:
        return GenValue(name, REG_MULTI_SZ, b"".join(utf16z(random_name(rng)) for _ in range(rng.randrange(4))) + b"\x00\x00")
    if kind == 3:
        return GenValue(name, REG_DWORD, rng.randrange(2**32).to_bytes(4, "little"))
    if kind == 4:
        return GenValue(name, REG_DWORD_BIG_ENDIAN, rng.randrange(2**32).to_bytes(4, "big"))
    if kind == 5:
        return GenValue(name, REG_QWORD, rng.randrange(2**64).to_bytes(8, "little"))
    if kind == 6:
        return GenValue(name, REG_BINARY, bytes(rng.randrange(256) for _ in range(rng.randrange(0, 300))))
    if kind == 7:
        return GenValue(name, REG_NONE, b"")
    if kind == 8:  # odd length, unterminated, lone surrogates
        return GenValue(name, REG_SZ, "A\ud800B".encode("utf-16-le", errors="surrogatepass") + b"\x00\xd8Z")
    if kind == 9:
        return GenValue(name, REG_SZ, rng.randbytes(rng.randrange(1, 4)))
    if kind == 10:
        return GenValue(name, REG_DWORD, rng.randbytes(rng.randrange(0, 4)), force_cell=rng.random() < 0.5)
    if kind == 11:
        return GenValue(name, 0xFFFF0010, rng.randrange(2**64).to_bytes(8, "little"))
    if kind == 12:
        return GenValue(name, REG_LINK, utf16z("\\Registry\\Machine\\System\\ControlSet001"))
    return GenValue(
        name,
        REG_SZ,
        utf16z("x"),
        raw_name=b"N\x00\x00\xdc\x3d\xd8\x01\xdcZ" if rng.random() < 0.5 else bytes(rng.randrange(1, 256) for _ in range(5)),
        compressed=rng.random() < 0.5,
    )


def random_tree(rng: random.Random, *, key_count: int, max_children: int = 12, max_values: int = 6, big_ratio: float = 0.02) -> GenKey:
    root = GenKey("ROOT" if rng.random() < 0.5 else "CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}")
    frontier = [root]
    made = 1
    while made < key_count and frontier:
        parent = frontier.pop(rng.randrange(len(frontier)))
        parent.list_kind = rng.choice(("lh", "lh", "lf", "li", "ri"))
        names_seen: set[str] = set()
        for _ in range(rng.randrange(1, max_children + 1)):
            if made >= key_count:
                break
            name = random_name(rng)
            if name.upper() in names_seen:
                continue
            names_seen.add(name.upper())
            child = GenKey(name, stamp=random_stamp(rng))
            if rng.random() < 0.02:
                child.raw_name = b"K\x00\x00\xd8"  # lone high surrogate at the end
                child.compressed = False
            for _ in range(rng.randrange(max_values + 1)):
                child.values.append(random_value(rng, big_ratio=big_ratio))
            parent.children.append(child)
            frontier.append(child)
            made += 1
    root.values.append(GenValue("", REG_SZ, utf16z("(root default)")))
    return root


def random_deleted(rng: random.Random, count: int) -> list[tuple[GenKey | GenValue, int]]:
    deleted: list[tuple[GenKey | GenValue, int]] = []
    for _ in range(count):
        if rng.random() < 0.5:
            key = GenKey(random_name(rng), stamp=random_stamp(rng))
            if rng.random() < 0.1:
                key.raw_name = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 12)))
                key.compressed = rng.random() < 0.5
            deleted.append((key, rng.randrange(1 << 30)))
        else:
            deleted.append((random_value(rng, big_ratio=0.05), 0))
    return deleted


def generate_hive_with_layout(
    seed: int,
    *,
    key_count: int = 300,
    deleted_count: int = 40,
    minor_version: int | None = None,
    big_ratio: float = 0.02,
) -> tuple[bytes, RegfBuilder]:
    """(hive bytes, builder holding the key/value/list cell offsets) for ``seed``."""
    rng = random.Random(seed)
    builder = RegfBuilder(minor_version=minor_version if minor_version is not None else rng.choice((3, 4, 5, 5, 6)))
    root = random_tree(rng, key_count=key_count, big_ratio=big_ratio)
    return builder.build(root, deleted=random_deleted(rng, deleted_count)), builder


def generate_hive(seed: int, **options: float | None) -> bytes:
    return generate_hive_with_layout(seed, **options)[0]  # type: ignore[arg-type]


def _set_u32(blob: bytearray, position: int, value: int) -> None:
    if 0 <= position <= len(blob) - 4:
        blob[position : position + 4] = (value & 0xFFFFFFFF).to_bytes(4, "little")


def corrupted_variants(seed: int) -> list[tuple[str, bytes]]:
    """Structural damage applied to one generated hive, one variant per kind."""
    rng = random.Random(seed ^ 0x5EED)
    blob, builder = generate_hive_with_layout(seed)
    base = 4096
    keys = builder.key_offsets
    variants: list[tuple[str, bytes]] = [("intact", blob)]

    cut = rng.randrange(base + 64, len(blob))
    variants.append(("truncated-hbin-data", blob[:cut]))
    variants.append(("truncated-mid-cell", blob[: base + keys[len(keys) // 2] + 10]))

    damaged = bytearray(blob)
    bins = [offset for offset in range(base, len(blob), HBIN_ALIGNMENT) if blob[offset : offset + 4] == b"hbin"]
    damaged[bins[len(bins) // 2] : bins[len(bins) // 2] + 4] = b"\x00\x00\x00\x00"
    variants.append(("hbin-signature-gap", bytes(damaged)))

    damaged = bytearray(blob)
    _set_u32(damaged, bins[-1] + 8, 123)
    variants.append(("hbin-size-invalid", bytes(damaged)))

    damaged = bytearray(blob)
    _set_u32(damaged, 40, len(blob) * 2)
    variants.append(("declared-size-beyond-file", bytes(damaged)))

    damaged = bytearray(blob)
    _set_u32(damaged, 40, 0)
    variants.append(("declared-size-zero", bytes(damaged)))

    damaged = bytearray(blob)
    child = keys[rng.randrange(1, len(keys))]
    _set_u32(damaged, base + child + 4 + 0x14, 7)
    variants.append(("subkey-count-mismatch", bytes(damaged)))

    damaged = bytearray(blob)
    for list_offset in builder.list_offsets[:3]:
        signature = bytes(damaged[base + list_offset + 4 : base + list_offset + 6])
        if signature in (b"lh", b"lf"):
            _set_u32(damaged, base + list_offset + 8, keys[0])  # first child -> root: cycle
        elif signature == b"li":
            _set_u32(damaged, base + list_offset + 8, keys[0])
    variants.append(("subkey-cycle-to-root", bytes(damaged)))

    damaged = bytearray(blob)
    for list_offset in builder.list_offsets[:2]:
        _set_u32(damaged, base + list_offset + 8, keys[1] + 3)
    variants.append(("misaligned-subkey-pointer", bytes(damaged)))

    damaged = bytearray(blob)
    for list_offset in builder.list_offsets[2:4]:
        damaged[base + list_offset + 4 : base + list_offset + 6] = b"zz"
    variants.append(("unknown-list-signature", bytes(damaged)))

    damaged = bytearray(blob)
    for value in builder.value_offsets[:: max(1, len(builder.value_offsets) // 5)]:
        size = int.from_bytes(damaged[base + value : base + value + 4], "little", signed=True)
        damaged[base + value : base + value + 4] = abs(size).to_bytes(4, "little", signed=True)
    variants.append(("free-cell-referenced", bytes(damaged)))

    damaged = bytearray(blob)
    for value in builder.value_offsets[:: max(1, len(builder.value_offsets) // 7)]:
        _set_u32(damaged, base + value + 4 + 8, rng.choice((0, 0xFFFFFFFF, 0x7FFFFFF8, 13, keys[0])))
    variants.append(("dangling-value-data", bytes(damaged)))

    damaged = bytearray(blob)
    for value in builder.value_offsets[:: max(1, len(builder.value_offsets) // 7)]:
        _set_u32(damaged, base + value + 4 + 4, rng.choice((0x80000004, 0x7FFFFFFF, 0x80000000, 0x00010000)))
    variants.append(("value-size-damage", bytes(damaged)))

    damaged = bytearray(blob)
    for segment_list in builder.segment_lists:
        _set_u32(damaged, base + segment_list + 4 + 4, 0x7FFFFFF8)  # second segment -> out of bounds
    variants.append(("big-data-segment-missing", bytes(damaged)))

    damaged = bytearray(blob)
    for value in builder.value_offsets[:: max(1, len(builder.value_offsets) // 9)]:
        damaged[base + value + 4 : base + value + 6] = b"nk"  # vk-signature-mismatch
    for key in keys[1 :: max(1, len(keys) // 9)]:
        damaged[base + key + 4 : base + key + 6] = b"vk"  # nk-signature-mismatch
    variants.append(("cell-signature-damage", bytes(damaged)))

    damaged = bytearray(blob)
    _set_u32(damaged, 36, 0x7FFFFFF8)
    variants.append(("root-unresolved", bytes(damaged)))

    # Deep ri nesting (> REGF_MAX_SUBKEY_LIST_DEPTH): an appended hbin holds a chain of ri lists
    # ending in an li, and the root's subkey list points at the head of the chain.
    damaged = bytearray(blob)
    hbin_start = len(damaged) - base
    depth = 11
    cells = bytearray()
    for index in range(depth):
        cell = hbin_start + 32 + index * 16
        target = cell + 16 if index < depth - 1 else keys[1]
        payload = (b"ri" if index < depth - 1 else b"li") + (1).to_bytes(2, "little") + target.to_bytes(4, "little")
        cells += (-16).to_bytes(4, "little", signed=True) + payload.ljust(12, b"\x00")
    hbin_size = 32 + len(cells)
    hbin_size += (-hbin_size) % HBIN_ALIGNMENT
    hbin = bytearray(hbin_size)
    hbin[0:4] = b"hbin"
    hbin[4:8] = hbin_start.to_bytes(4, "little")
    hbin[8:12] = hbin_size.to_bytes(4, "little")
    hbin[32 : 32 + len(cells)] = cells
    damaged += hbin
    _set_u32(damaged, 40, len(damaged) - base)
    _set_u32(damaged, base + keys[0] + 4 + 0x1C, hbin_start + 32)
    variants.append(("ri-depth-exceeded", bytes(damaged)))

    for round_index in range(4):
        damaged = bytearray(blob)
        for _ in range(rng.randrange(5, 60)):
            position = rng.randrange(base, len(damaged))
            damaged[position] = rng.randrange(256)
        variants.append((f"random-byte-damage-{round_index}", bytes(damaged)))
    return variants
